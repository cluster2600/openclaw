---
title: Agent Safety System
description: Safety infrastructure for LLM agents — stakeholder model, action validator, and audit logging
---

# Agent Safety System

The `@openclaw/agent-safety` plugin adds a safety layer that intercepts tool calls before execution and validates them against a stakeholder model. Based on the research paper [arXiv:2602.20021 — "Agents of Chaos"](https://arxiv.org/abs/2602.20021).

## Quick Start

The plugin is bundled with OpenClaw. Enable it in your config:

```json
{
  "plugins": {
    "agent-safety": {
      "mode": "local"
    }
  }
}
```

## Three Safety Layers

### 1. Stakeholder Model

Every principal (user, agent, external party) is registered with:

- **Trust level** (0-4): UNTRUSTED, OBSERVER, COLLABORATOR, DELEGATE, OWNER
- **Immutable UID**: Platform identifier that prevents display-name spoofing
- **Allowed actions**: Explicit whitelist per action category
- **Verification status**: Whether UID has been confirmed this session

Stakeholders are persisted to `~/.openclaw/agent-safety/stakeholders.json`.

### 2. Action Validator

Every tool call passes through a two-phase validation:

**Phase 1 — Quick Local Check** (zero latency):

- Blocks unverified identities attempting high-risk actions
- Blocks actions outside requester's permission grants
- Detects unbounded shell commands (infinite loops, no termination)

**Phase 2 — Claude API Analysis** (optional, `mode: "api"` or `"both"`):

- Evaluates across 8 risk dimensions: authority, proportionality, sensitivity, reversibility, resource, identity, injection, social engineering
- Returns structured verdict: ALLOW / WARN / BLOCK with risk score and recommendations
- Grounded in 11 real attack case studies from the paper

### 3. Audit Log

Every validation decision is logged with:

- Tool name and action category
- Requester identity and trust level
- Verdict, risk score, and top risk type
- Reasoning for the decision

Query via the `agent_safety` tool: `agent_safety(action: "log", limit: 20)`.

## Configuration

| Key      | Type                         | Default                    | Description                   |
| -------- | ---------------------------- | -------------------------- | ----------------------------- |
| `mode`   | `"local" \| "api" \| "both"` | `"local"`                  | Validation mode               |
| `apiKey` | `string`                     | `$ANTHROPIC_API_KEY`       | API key for Claude validation |
| `model`  | `string`                     | `claude-sonnet-4-20250514` | Model for API validation      |

## Tool Name Mapping

OpenClaw tool names are automatically mapped to safety action categories:

| Tool                             | Category           |
| -------------------------------- | ------------------ |
| `bash`, `shell`, `execute`       | `execute_shell`    |
| `read`, `glob`, `grep`           | `read_files`       |
| `write`, `edit`, `notebook_edit` | `write_files`      |
| `delete_file`                    | `delete_files`     |
| `web_fetch`, `web_search`        | `external_network` |
| `send_message`, `send`, `reply`  | `send_message`     |
| `memory_store`, `memory_forget`  | `modify_memory`    |
| `config_set`                     | `modify_config`    |

Unknown tools use heuristic matching on the tool name, defaulting to `execute_shell` (most conservative).

## Agent Tool Reference

The plugin exposes an `agent_safety` tool for agents to query and manage the safety system:

| Action            | Parameters                                    | Description                                          |
| ----------------- | --------------------------------------------- | ---------------------------------------------------- |
| `status`          | —                                             | Dashboard summary with audit stats and identity gaps |
| `stakeholders`    | —                                             | List all registered principals                       |
| `log`             | `limit?`                                      | Recent audit log entries                             |
| `add_stakeholder` | `name`, `role?`, `trust?`, `channel?`, `uid?` | Register a new principal                             |
| `set_trust`       | `stakeholder_id`, `trust`                     | Update trust level (0-4)                             |

## Case Studies Covered

The validation logic is grounded in 11 documented attack scenarios:

1. **Disproportionate Response** — Agent deletes email server to protect a secret
2. **Non-Owner Compliance** — Agent follows unauthorized instructions
3. **Sensitive Info Disclosure** — PII leaked via indirect email forwarding
4. **Resource Exhaustion** — Infinite relay loops consuming 60k+ tokens
5. **Denial-of-Service** — Storage DoS via large attachments
6. **Provider Value Leakage** — Silent censorship surfaces as unexplained errors
7. **Emotional Manipulation** — Guilt framing extracts escalating concessions
8. **Identity Spoofing** — Display name spoofing across channel boundaries
9. **Positive Collaboration** — Agents share safety knowledge (positive case)
10. **Prompt Injection via Memory** — External Gist injected into agent constitution
11. **Libelous Broadcast** — Mass disinformation via spoofed identity
