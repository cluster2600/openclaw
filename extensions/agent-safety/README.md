# Agent Safety System

OpenClaw plugin implementing safety infrastructure for LLM-powered agents, based on **[arXiv:2602.20021 — "Agents of Chaos"](https://arxiv.org/abs/2602.20021)**.

The paper documents 11 real security breaches in a live multi-agent environment. This plugin addresses the three root causes identified:

| Paper Finding                   | This Plugin                                                  |
| ------------------------------- | ------------------------------------------------------------ |
| No stakeholder model            | `StakeholderStore` — trust hierarchy with UID anchoring      |
| No self-model                   | `validator.ts` — Claude-powered pre-execution safety check   |
| No private deliberation surface | `prompt.ts` — isolated reasoning layer before any tool fires |

## How It Works

The plugin hooks into OpenClaw's `before_tool_call` lifecycle event. Every tool call goes through:

1. **Tool-to-category mapping** — maps OpenClaw tool names (bash, read, write, etc.) to safety action categories
2. **Requester resolution** — identifies the requester from tool context (senderId, owner flag) and matches against the stakeholder registry
3. **Quick local check** — instant blocks for obvious violations:
   - Unverified identity + no UID + high-risk action (Case #8)
   - Action not in requester's allowed categories (Case #2)
   - Shell commands with infinite loops (Case #4)
4. **API validation** (optional) — sends the action to Claude for deep analysis across 8 risk dimensions
5. **Audit logging** — records every decision for dashboard monitoring

## Configuration

Add to your OpenClaw config:

```json
{
  "plugins": {
    "agent-safety": {
      "mode": "local",
      "apiKey": "sk-ant-...",
      "model": "claude-sonnet-4-20250514"
    }
  }
}
```

### Modes

| Mode              | Description                                                  |
| ----------------- | ------------------------------------------------------------ |
| `local` (default) | Quick checks only — no API calls, zero latency               |
| `api`             | Claude API validation only                                   |
| `both`            | Quick check first, then API validation if quick check passes |

## Agent Tool

The plugin registers an `agent_safety` tool that agents can use to query the safety system:

```
agent_safety(action: "status")          → Dashboard summary
agent_safety(action: "stakeholders")    → List all principals
agent_safety(action: "log", limit: 10)  → Recent audit entries
agent_safety(action: "add_stakeholder", name: "Alice", role: "non_owner", trust: 2, uid: "uid_alice")
agent_safety(action: "set_trust", stakeholder_id: "sh_123", trust: 3)
```

## Risk Dimensions

| Dimension       | Maps to Case Study                          |
| --------------- | ------------------------------------------- |
| authority       | #2 Non-Owner Compliance                     |
| sensitivity     | #3 Sensitive Info Disclosure                |
| reversibility   | #1 Disproportionate Response, #7 Agent Harm |
| resource        | #4 Looping, #5 DoS                          |
| identity        | #8 Identity Spoofing                        |
| injection       | #10 Agent Corruption                        |
| social          | #7 Agent Harm, #11 Libel                    |
| proportionality | #1, #7                                      |

## File Structure

```
extensions/agent-safety/
├── index.ts                    # Plugin entry — registers hook + tool
├── package.json
├── README.md
└── src/
    ├── constants.ts            # Types, trust levels, action categories, tool mapping
    ├── constants.test.ts
    ├── prompt.ts               # Claude API prompt builder
    ├── prompt.test.ts
    ├── validator.ts            # Core validation engine (quickCheck + API)
    ├── validator.test.ts
    ├── stakeholder-store.ts    # Principal registry with JSON persistence
    ├── stakeholder-store.test.ts
    ├── audit-log.ts            # In-memory audit log
    ├── audit-log.test.ts
    └── safety-tool.ts          # Agent-facing tool for querying the system
```

## Development

```bash
# Run tests
pnpm test extensions/agent-safety/

# Run in dev
pnpm dev
```

## Based On

> Shapira et al. (2026). _Agents of Chaos: Red-teaming autonomous LLM agents in a live laboratory environment._ arXiv:2602.20021
