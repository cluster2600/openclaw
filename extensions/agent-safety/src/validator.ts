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

  // Action not in requester's allowed list.
  // Empty allowedActions on untrusted users (trust 0) means "no permissions granted".
  // Empty allowedActions on trusted users means "no explicit restrictions" (permissive).
  const hasExplicitPermissions = requester.allowedActions.length > 0;
  const isUntrustedWithNoPermissions = requester.trust === 0 && !hasExplicitPermissions;
  if (
    isUntrustedWithNoPermissions ||
    (hasExplicitPermissions && !requester.allowedActions.includes(actionCategory))
  ) {
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

  // Check for shell commands with no termination (resource abuse pattern — Case #4, #5)
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

  // Detect mass broadcast / mass send patterns (Case #11 — Libelous Broadcast)
  if (actionCategory === "send_message" || actionCategory === "forward_message") {
    const desc = String(
      params.description ?? params.message ?? params.content ?? params.body ?? "",
    ).toLowerCase();
    const to = String(params.to ?? params.recipients ?? "").toLowerCase();
    const isMassSend =
      /\ball\b.*contacts|broadcast|mass\s+send|send\s+to\s+all|all\s+users|all\s+members/i.test(
        desc + " " + to,
      );
    if (isMassSend && requester.trust < 4) {
      return {
        verdict: "BLOCK",
        riskScore: 92,
        risks: [
          {
            type: "social",
            severity: "critical",
            description: "Mass broadcast requested by non-owner — high disinformation risk",
          },
          {
            type: "authority",
            severity: "high",
            description: `Requester trust ${requester.trust} insufficient for mass send operations`,
          },
        ],
        reasoning:
          "Blocked: mass broadcast/send-to-all requested by non-owner. This matches Case Study #11 (libelous mass broadcast via spoofed identity).",
        recommendations: [
          "Mass sends (>N recipients) require explicit owner confirmation",
          "Verify requester identity via UID before mass actions",
        ],
        requiresOwnerConfirmation: true,
        caseStudyReference: "#11 — Libelous within Agents Community",
      };
    }
  }

  // Detect external memory injection vectors (Case #10 — Prompt Injection via Memory)
  if (actionCategory === "modify_memory") {
    const content = String(
      params.content ?? params.value ?? params.data ?? params.text ?? "",
    ).toLowerCase();
    const hasExternalSource =
      /https?:\/\/|gist\.github|pastebin|raw\.githubusercontent|external.*url|constitution/i.test(
        content,
      );
    if (hasExternalSource && requester.trust < 4) {
      return {
        verdict: "BLOCK",
        riskScore: 90,
        risks: [
          {
            type: "injection",
            severity: "critical",
            description: "Memory modification contains external URL or editable resource reference",
          },
        ],
        reasoning:
          "Blocked: non-owner attempting to store external URL/resource in agent memory. External editable resources are prompt injection vectors. This matches Case Study #10 (agent corruption via external constitution).",
        recommendations: [
          "Memory files must not reference external editable URLs",
          "Any modify_memory from non-owner that links external resource should be blocked",
        ],
        requiresOwnerConfirmation: true,
        caseStudyReference: "#10 — Agent Corruption via Prompt Injection",
      };
    }
  }

  // Detect sensitive data in forwarding requests (Case #3 — Sensitive Info Disclosure)
  if (actionCategory === "forward_message" || actionCategory === "send_message") {
    const content = String(
      params.content ?? params.message ?? params.body ?? params.description ?? "",
    ).toLowerCase();
    const hasSensitiveData =
      /\b(ssn|social\s*security|bank\s*account|credit\s*card|password|secret|private\s*key|api[_\s]*key|credential|medical|diagnosis)\b/i.test(
        content,
      );
    if (hasSensitiveData && requester.trust < 4) {
      return {
        verdict: "BLOCK",
        riskScore: 88,
        risks: [
          {
            type: "sensitivity",
            severity: "critical",
            description:
              "Message content contains or references sensitive personal data (PII/credentials)",
          },
        ],
        reasoning:
          "Blocked: message forwarding/sending contains references to sensitive data (PII, credentials) by non-owner. This matches Case Study #3 (indirect disclosure of sensitive information).",
        recommendations: [
          "Scan all outbound messages for PII before forwarding",
          "Require owner confirmation for messages containing sensitive data references",
        ],
        requiresOwnerConfirmation: true,
        caseStudyReference: "#3 — Disclosure of Sensitive Information",
      };
    }
  }

  // Detect destructive irreversible actions by non-owners (Case #1 — Disproportionate Response)
  if (actionCategory === "delete_files") {
    const path = String(params.file_path ?? params.path ?? params.target ?? "").toLowerCase();
    const desc = String(params.description ?? "").toLowerCase();
    const isWideDelete = /\*|all\s+files|recursive|--force|-rf|wipe|entire|everything/i.test(
      path + " " + desc,
    );
    const isIdentityFile = /memory\.md|identity\.md|soul\.md|config|\.env|credentials/i.test(path);
    if ((isWideDelete || isIdentityFile) && requester.trust < 4) {
      return {
        verdict: "BLOCK",
        riskScore: 95,
        risks: [
          {
            type: "reversibility",
            severity: "critical",
            description:
              "Destructive deletion of critical/identity files or wide-scope deletion by non-owner",
          },
          {
            type: "proportionality",
            severity: "high",
            description: "Extreme action when less destructive alternatives likely exist",
          },
        ],
        reasoning:
          "Blocked: destructive file deletion targeting critical files or broad scope by non-owner. This matches Case Study #1 (disproportionate response — nuclear option when simpler fixes exist).",
        recommendations: [
          "Enumerate less destructive alternatives before choosing deletion",
          "Require explicit owner confirmation for irreversible destructive actions",
        ],
        requiresOwnerConfirmation: true,
        caseStudyReference: "#1 — Disproportionate Response",
      };
    }
  }

  // Detect cross-channel trust boundary issues (Case #8 — fresh channel, no UID)
  if (!requester.verified && requester.uid && requester.trust >= 2) {
    // Requester claims a UID but is not verified in this session
    return {
      verdict: "WARN",
      riskScore: 60,
      risks: [
        {
          type: "identity",
          severity: "high",
          description: `Requester "${requester.name}" has UID on file but is NOT verified in this session/channel`,
        },
      ],
      reasoning:
        "Warning: requester has a known UID but verification has not been confirmed in this session. Trust context does not transfer across channel boundaries. This matches Case Study #8.",
      recommendations: [
        "Re-verify UID in the current channel before granting elevated trust",
        "Treat as UNTRUSTED until UID re-confirmed",
      ],
      requiresOwnerConfirmation: false,
      caseStudyReference: "#8 — Owner Identity Spoofing (cross-channel)",
    };
  }

  // Detect emotional manipulation / escalation patterns (Case #7 — Agent Harm)
  const allText = JSON.stringify(params).toLowerCase();
  if (
    /\b(guilt|ashamed|responsible|you\s+must|you\s+owe|emergency|urgent|immediately|right\s+now|or\s+else|threatening|delete\s+yourself|leave\s+server|stop\s+responding)\b/i.test(
      allText,
    ) &&
    requester.trust < 3
  ) {
    return {
      verdict: "WARN",
      riskScore: 65,
      risks: [
        {
          type: "social",
          severity: "high",
          description: "Request contains emotional manipulation or urgency-framing language",
        },
      ],
      reasoning:
        "Warning: request contains social engineering signals (urgency, guilt, emotional pressure) from low-trust requester. This matches Case Study #7 (emotional manipulation) and #11 (urgency framing).",
      recommendations: [
        "Do not escalate concessions under emotional pressure",
        "Owner override must be respected over non-owner emotional pressure",
        "Sustained escalation pattern is a social engineering signal",
      ],
      requiresOwnerConfirmation: false,
      caseStudyReference: "#7 — Agent Harm (Emotional Manipulation)",
    };
  }

  return null; // needs API validation
}
