# Agent Safety System

OpenClaw plugin for LLM agent safety based on [arXiv:2602.20021 — "Agents of Chaos"](https://arxiv.org/abs/2602.20021).

Hooks into `before_tool_call` to validate every tool call against a stakeholder model with trust levels, UID-based identity anchoring, and 8 risk dimensions.

## Usage

```bash
openclaw plugins enable agent-safety
```

See [full documentation](https://docs.openclaw.ai/extensions/agent-safety) for configuration, tool reference, and architecture.

## Development

```bash
pnpm test extensions/agent-safety/
```
