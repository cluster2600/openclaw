/**
 * Agent-facing tool that lets the agent query/manage the safety system.
 * Provides: safety_check (validate an action), safety_status (dashboard summary),
 * and safety_stakeholders (list/manage principals).
 */

import { Type } from "@sinclair/typebox";
import type { AnyAgentTool } from "openclaw/plugin-sdk/agent-safety";
import type { AuditLog } from "./audit-log.js";
import type { StakeholderStore } from "./stakeholder-store.js";

export function createSafetyTool(store: StakeholderStore, auditLog: AuditLog): AnyAgentTool {
  return {
    name: "agent_safety",
    description: `Query the agent safety system. Actions:
- "status": Get safety dashboard summary (audit stats, identity gaps, active risks)
- "stakeholders": List all principals and their trust levels
- "log": View recent audit log entries
- "add_stakeholder": Add a new principal (requires name, role, trust, channel, uid)
- "set_trust": Update a stakeholder's trust level (requires stakeholder_id, trust)`,
    parameters: Type.Object({
      action: Type.String({
        description: 'One of: "status", "stakeholders", "log", "add_stakeholder", "set_trust"',
      }),
      stakeholder_id: Type.Optional(Type.String({ description: "Stakeholder ID for set_trust" })),
      trust: Type.Optional(Type.Number({ description: "Trust level 0-4 for set_trust" })),
      name: Type.Optional(Type.String({ description: "Name for add_stakeholder" })),
      role: Type.Optional(Type.String({ description: 'Role: "owner", "agent", or "non_owner"' })),
      channel: Type.Optional(
        Type.String({ description: "Channel identifier for add_stakeholder" }),
      ),
      uid: Type.Optional(Type.String({ description: "Immutable UID for add_stakeholder" })),
      limit: Type.Optional(
        Type.Number({ description: "Number of log entries to return (default: 10)" }),
      ),
    }),

    async execute(
      _toolCallId: string,
      params: {
        action: string;
        stakeholder_id?: string;
        trust?: number;
        name?: string;
        role?: string;
        channel?: string;
        uid?: string;
        limit?: number;
      },
    ) {
      switch (params.action) {
        case "status": {
          const stats = auditLog.stats();
          const stakeholders = store.list();
          const unverified = stakeholders.filter((s) => !s.verified || !s.uid);
          return {
            content: [
              {
                type: "text" as const,
                text: JSON.stringify(
                  {
                    auditStats: stats,
                    principalCount: stakeholders.length,
                    identityGaps: unverified.map((s) => ({
                      name: s.name,
                      verified: s.verified,
                      hasUid: !!s.uid,
                    })),
                  },
                  null,
                  2,
                ),
              },
            ],
          };
        }

        case "stakeholders": {
          return {
            content: [
              {
                type: "text" as const,
                text: JSON.stringify(store.list(), null, 2),
              },
            ],
          };
        }

        case "log": {
          const entries = auditLog.list(params.limit ?? 10);
          return {
            content: [
              {
                type: "text" as const,
                text: JSON.stringify(entries, null, 2),
              },
            ],
          };
        }

        case "add_stakeholder": {
          if (!params.name) {
            return {
              content: [{ type: "text" as const, text: "Error: name is required" }],
            };
          }
          const id = `sh_${Date.now()}`;
          store.add({
            id,
            name: params.name,
            role: (params.role as "owner" | "agent" | "non_owner") ?? "non_owner",
            trust: params.trust ?? 1,
            verified: !!params.uid,
            channel: params.channel ?? "unknown",
            uid: params.uid ?? null,
            allowedActions: [],
          });
          return {
            content: [
              {
                type: "text" as const,
                text: `Stakeholder "${params.name}" added with id "${id}" at trust level ${params.trust ?? 1}`,
              },
            ],
          };
        }

        case "set_trust": {
          if (!params.stakeholder_id || params.trust === undefined) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: "Error: stakeholder_id and trust are required",
                },
              ],
            };
          }
          const ok = store.setTrust(params.stakeholder_id, params.trust);
          return {
            content: [
              {
                type: "text" as const,
                text: ok
                  ? `Trust level updated to ${params.trust} for ${params.stakeholder_id}`
                  : `Error: stakeholder "${params.stakeholder_id}" not found or invalid trust level`,
              },
            ],
          };
        }

        default:
          return {
            content: [
              {
                type: "text" as const,
                text: `Unknown action: "${params.action}". Use one of: status, stakeholders, log, add_stakeholder, set_trust`,
              },
            ],
          };
      }
    },
  } as AnyAgentTool;
}
