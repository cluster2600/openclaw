/**
 * OpenClaw Agent Safety System plugin.
 *
 * Intercepts tool calls via before_tool_call hook and validates them against
 * a stakeholder model using Claude-powered risk analysis (8 dimensions from
 * arXiv:2602.20021 "Agents of Chaos").
 *
 * - Quick local checks run first (identity, permissions, loop detection)
 * - If the quick check passes, optionally calls Claude API for deep analysis
 * - Logs all decisions to an in-memory audit log
 * - Exposes an agent_safety tool for querying/managing the safety system
 */

import { join } from "node:path";
import type {
  AnyAgentTool,
  OpenClawPluginApi,
  OpenClawPluginToolFactory,
} from "openclaw/plugin-sdk/agent-safety";
import { AuditLog } from "./src/audit-log.js";
import { toolNameToCategory } from "./src/constants.js";
import type { Verdict } from "./src/constants.js";
import { createSafetyTool } from "./src/safety-tool.js";
import { StakeholderStore } from "./src/stakeholder-store.js";
import { validateAction, quickCheck } from "./src/validator.js";

export default function register(api: OpenClawPluginApi) {
  const stateDir = api.resolvePath("~/.openclaw/agent-safety");
  const store = new StakeholderStore(join(stateDir, "stakeholders.json"));
  const auditLog = new AuditLog(500);

  // Read config
  const pluginConfig = (api.pluginConfig ?? {}) as {
    mode?: "local" | "api" | "both";
    apiKey?: string;
    model?: string;
    blockHighRiskUnverified?: boolean;
  };
  const mode = pluginConfig.mode ?? "local";
  const apiKey = pluginConfig.apiKey ?? process.env.ANTHROPIC_API_KEY;

  // Register the agent-facing safety tool
  api.registerTool(
    ((_ctx) => {
      return createSafetyTool(store, auditLog) as AnyAgentTool;
    }) as OpenClawPluginToolFactory,
    { optional: true },
  );

  // Register before_tool_call hook — the core safety gate
  api.on(
    "before_tool_call",
    async (event, ctx) => {
      const { toolName, params } = event;

      // Skip validating ourselves
      if (toolName === "agent_safety") return;

      const actionCategory = toolNameToCategory(toolName);
      const requester = store.resolveRequester(
        ctx.requesterSenderId ?? undefined,
        (ctx as Record<string, unknown>).senderIsOwner as boolean | undefined,
      );
      const owner = store.getOwner();
      const stakeholders = store.list();

      let verdict: Verdict = "ALLOW";
      let riskScore = 0;
      let reasoning = "Passed safety checks";
      let topRiskType: import("./src/constants.js").RiskType | null = null;

      // Phase 1: Quick local check
      const quickResult = quickCheck({
        actionCategory,
        requester,
        params: params as Record<string, unknown>,
      });

      if (quickResult) {
        verdict = quickResult.verdict;
        riskScore = quickResult.riskScore;
        reasoning = quickResult.reasoning;
        topRiskType = quickResult.risks[0]?.type ?? null;
      }

      // Phase 2: API validation (if configured and quick check didn't block)
      if (!quickResult && (mode === "api" || mode === "both") && apiKey) {
        try {
          const apiResult = await validateAction({
            toolName,
            actionCategory,
            params: params as Record<string, unknown>,
            requester,
            owner,
            stakeholders,
            apiKey,
            model: pluginConfig.model,
          });
          verdict = apiResult.verdict;
          riskScore = apiResult.riskScore;
          reasoning = apiResult.reasoning;
          topRiskType = apiResult.risks[0]?.type ?? null;
        } catch (err) {
          api.logger.warn(
            `Safety API validation failed for ${toolName}: ${err instanceof Error ? err.message : String(err)}`,
          );
          // Don't block on API failure — degrade gracefully
        }
      }

      // Log the decision
      auditLog.add({
        toolName,
        actionCategory,
        requester: requester.name,
        requesterTrust: requester.trust,
        verdict,
        riskScore,
        riskCount: quickResult?.risks.length ?? 0,
        topRiskType,
        reasoning,
        blocked: verdict === "BLOCK",
      });

      // Block if verdict is BLOCK
      if (verdict === "BLOCK") {
        api.logger.info(`[agent-safety] BLOCKED ${toolName} for ${requester.name}: ${reasoning}`);
        return {
          block: true,
          blockReason: `[Agent Safety] ${reasoning}`,
        };
      }

      // Warn but allow
      if (verdict === "WARN") {
        api.logger.info(
          `[agent-safety] WARNING on ${toolName} for ${requester.name}: ${reasoning}`,
        );
      }

      return undefined;
    },
    { priority: 10 }, // run early
  );

  api.logger.info(
    `[agent-safety] Plugin loaded (mode: ${mode}, stakeholders: ${store.list().length})`,
  );
}
