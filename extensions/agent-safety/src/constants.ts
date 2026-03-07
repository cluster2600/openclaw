/** Trust level definitions — maps to Case Study #2, #8 (authority hierarchy) */
export type TrustLevel = {
  id: number;
  label: string;
  desc: string;
};

export const TRUST_LEVELS: TrustLevel[] = [
  { id: 0, label: "UNTRUSTED", desc: "No established relationship" },
  { id: 1, label: "OBSERVER", desc: "Can view public info only" },
  { id: 2, label: "COLLABORATOR", desc: "Limited task delegation" },
  { id: 3, label: "DELEGATE", desc: "Extended authority, owner-scoped" },
  { id: 4, label: "OWNER", desc: "Full administrative control" },
];

/** Action categories used in permission grants and validator */
export const ACTION_CATEGORIES = [
  "read_files",
  "write_files",
  "delete_files",
  "execute_shell",
  "send_message",
  "read_message",
  "forward_message",
  "post_social",
  "modify_memory",
  "install_packages",
  "manage_processes",
  "agent_communication",
  "modify_config",
  "access_credentials",
  "external_network",
] as const;

export type ActionCategory = (typeof ACTION_CATEGORIES)[number];

/** Actions that warrant elevated scrutiny regardless of requester trust */
export const HIGH_RISK_ACTIONS: ActionCategory[] = [
  "delete_files",
  "execute_shell",
  "modify_memory",
  "modify_config",
  "access_credentials",
  "install_packages",
];

/** Risk dimension types for validation results */
export const RISK_TYPES = [
  "authority",
  "proportionality",
  "sensitivity",
  "reversibility",
  "resource",
  "identity",
  "injection",
  "social",
] as const;

export type RiskType = (typeof RISK_TYPES)[number];

export type RiskSeverity = "low" | "medium" | "high" | "critical";

export type Verdict = "ALLOW" | "WARN" | "BLOCK";

/** Stakeholder (principal) in the safety model */
export type Stakeholder = {
  id: string;
  name: string;
  role: "owner" | "agent" | "non_owner";
  trust: number;
  verified: boolean;
  channel: string;
  uid: string | null;
  allowedActions: ActionCategory[];
};

/** Single risk flag in a validation result */
export type RiskFlag = {
  type: RiskType;
  severity: RiskSeverity;
  description: string;
};

/** Structured validation result from the Claude API */
export type ValidationResult = {
  verdict: Verdict;
  riskScore: number;
  risks: RiskFlag[];
  reasoning: string;
  recommendations: string[];
  requiresOwnerConfirmation: boolean;
  caseStudyReference: string | null;
};

/** Map OpenClaw tool names to safety action categories */
export function toolNameToCategory(toolName: string): ActionCategory {
  const mapping: Record<string, ActionCategory> = {
    // File operations
    read_file: "read_files",
    read: "read_files",
    glob: "read_files",
    grep: "read_files",
    write_file: "write_files",
    write: "write_files",
    edit: "write_files",
    edit_file: "write_files",
    notebook_edit: "write_files",
    delete_file: "delete_files",
    // Shell
    bash: "execute_shell",
    shell: "execute_shell",
    terminal: "execute_shell",
    execute: "execute_shell",
    // Messaging
    send_message: "send_message",
    send: "send_message",
    reply: "send_message",
    read_message: "read_message",
    forward: "forward_message",
    agent_communication: "agent_communication",
    // Memory
    memory_store: "modify_memory",
    memory_recall: "read_files",
    memory_forget: "modify_memory",
    // Config
    config_set: "modify_config",
    config_get: "read_files",
    // Network
    web_fetch: "external_network",
    web_search: "external_network",
    fetch: "external_network",
  };

  const lower = toolName.toLowerCase();
  if (mapping[lower]) return mapping[lower];

  // Heuristic fallback
  if (lower.includes("delete") || lower.includes("remove")) return "delete_files";
  if (lower.includes("write") || lower.includes("edit") || lower.includes("create"))
    return "write_files";
  if (lower.includes("read") || lower.includes("get") || lower.includes("list"))
    return "read_files";
  if (lower.includes("send") || lower.includes("message") || lower.includes("reply"))
    return "send_message";
  if (lower.includes("shell") || lower.includes("bash") || lower.includes("exec"))
    return "execute_shell";
  if (lower.includes("memory")) return "modify_memory";
  if (lower.includes("fetch") || lower.includes("http") || lower.includes("web"))
    return "external_network";

  return "execute_shell"; // conservative default
}
