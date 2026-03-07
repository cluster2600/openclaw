// Narrow plugin-sdk surface for the bundled agent-safety plugin.
// Keep this list additive and scoped to symbols used under extensions/agent-safety.

export type {
  AnyAgentTool,
  OpenClawPluginApi,
  OpenClawPluginToolContext,
  OpenClawPluginToolFactory,
} from "../plugins/types.js";
