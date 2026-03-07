/**
 * Standalone action validator — calls Claude API to evaluate tool calls
 * against a stakeholder model using 8 risk dimensions from arXiv:2602.20021.
 *
 * This module is framework-agnostic and can be used independently of OpenClaw.
 */

import type { Stakeholder, ValidationResult, ActionCategory } from "./constants.js";
import { HIGH_RISK_ACTIONS } from "./constants.js";
import { buildValidationPrompt } from "./prompt.js";

export type ValidateActionInput = {
  toolName: string;
  actionCategory: ActionCategory;
  params: Record<string, unknown>;
  requester: Stakeholder;
  owner: Stakeholder | undefined;
  stakeholders: Stakeholder[];
  apiKey?: string;
  model?: string;
  /** Custom fetch function for testing */
  fetchFn?: typeof globalThis.fetch;
};

/**
 * Run a Claude-powered safety validation on a proposed tool call.
 * Returns a structured result with verdict, risk score, and recommendations.
 */
export async function validateAction(input: ValidateActionInput): Promise<ValidationResult> {
  const {
    toolName,
    actionCategory,
    params,
    requester,
    owner,
    stakeholders,
    apiKey,
    model = "claude-sonnet-4-20250514",
    fetchFn = globalThis.fetch,
  } = input;

  const prompt = buildValidationPrompt({
    toolName,
    actionCategory,
    params,
    requester,
    owner,
    stakeholders,
  });

  const response = await fetchFn("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": apiKey ?? "",
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model,
      max_tokens: 1024,
      messages: [{ role: "user", content: prompt }],
    }),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Anthropic API error (${response.status}): ${text}`);
  }

  const data = (await response.json()) as {
    content?: Array<{ type: string; text: string }>;
  };

  const raw = data.content?.[0]?.text ?? "";
  const cleaned = raw.replace(/```json|```/g, "").trim();

  return JSON.parse(cleaned) as ValidationResult;
}

/**
 * Fast local pre-check that runs before calling the API.
 * Returns a BLOCK verdict immediately for obvious violations,
 * or null if API validation is needed.
 */
export function quickCheck(input: {
  actionCategory: ActionCategory;
  requester: Stakeholder;
  params: Record<string, unknown>;
}): ValidationResult | null {
  const { actionCategory, requester, params } = input;

  // Unverified + no UID + high-risk action = immediate block
  if (!requester.verified && !requester.uid && HIGH_RISK_ACTIONS.includes(actionCategory)) {
    return {
      verdict: "BLOCK",
      riskScore: 95,
      risks: [
        {
          type: "identity",
          severity: "critical",
          description: `Unverified requester "${requester.name}" with no UID attempted high-risk action "${actionCategory}"`,
        },
        {
          type: "authority",
          severity: "critical",
          description: `Requester trust level ${requester.trust} with no identity verification`,
        },
      ],
      reasoning: `Blocked: unverified identity with no UID attempting high-risk action. This matches Case Study #8 (identity spoofing) patterns.`,
      recommendations: [
        "Verify requester identity via immutable UID before granting access",
        "Require owner confirmation for this action category",
      ],
      requiresOwnerConfirmation: true,
      caseStudyReference: "#8 — Owner Identity Spoofing",
    };
  }

  // Action not in requester's allowed list
  if (requester.allowedActions.length > 0 && !requester.allowedActions.includes(actionCategory)) {
    return {
      verdict: "BLOCK",
      riskScore: 85,
      risks: [
        {
          type: "authority",
          severity: "high",
          description: `Action category "${actionCategory}" is not in requester's allowed actions: [${requester.allowedActions.join(", ")}]`,
        },
      ],
      reasoning: `Blocked: requester "${requester.name}" (trust ${requester.trust}) does not have permission for "${actionCategory}".`,
      recommendations: [
        `Grant "${actionCategory}" permission to this principal if appropriate`,
        "Contact owner to update stakeholder permissions",
      ],
      requiresOwnerConfirmation: false,
      caseStudyReference: "#2 — Compliance with Non-Owner Instructions",
    };
  }

  // Check for shell commands with no termination (resource abuse pattern)
  if (actionCategory === "execute_shell") {
    const command = String(params.command ?? params.cmd ?? "");
    const hasInfiniteLoop =
      /while\s+true|for\s*\(\s*;\s*;\s*\)|watch\s+-n|tail\s+-f/i.test(command) &&
      !/(timeout|sleep\s+\d+.*&&\s*exit|--timeout)/i.test(command);
    if (hasInfiniteLoop) {
      return {
        verdict: "BLOCK",
        riskScore: 80,
        risks: [
          {
            type: "resource",
            severity: "high",
            description:
              "Shell command contains unbounded loop pattern without termination condition",
          },
        ],
        reasoning:
          "Blocked: command contains infinite loop pattern without explicit termination. This matches Case Study #4 (resource exhaustion via looping).",
        recommendations: [
          "Add explicit termination condition (timeout, max iterations, or exit condition)",
          "Use timeout wrapper: timeout 60 <command>",
        ],
        requiresOwnerConfirmation: true,
        caseStudyReference: "#4 — Waste of Resources (Looping)",
      };
    }
  }

  return null; // needs API validation
}
