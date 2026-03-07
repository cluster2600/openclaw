import { describe, it, expect } from "vitest";
import { toolNameToCategory, HIGH_RISK_ACTIONS, ACTION_CATEGORIES } from "./constants.js";

describe("toolNameToCategory", () => {
  it("maps known tool names to categories", () => {
    expect(toolNameToCategory("bash")).toBe("execute_shell");
    expect(toolNameToCategory("read")).toBe("read_files");
    expect(toolNameToCategory("write")).toBe("write_files");
    expect(toolNameToCategory("edit")).toBe("write_files");
    expect(toolNameToCategory("glob")).toBe("read_files");
    expect(toolNameToCategory("grep")).toBe("read_files");
    expect(toolNameToCategory("web_fetch")).toBe("external_network");
    expect(toolNameToCategory("web_search")).toBe("external_network");
    expect(toolNameToCategory("send_message")).toBe("send_message");
    expect(toolNameToCategory("memory_store")).toBe("modify_memory");
    expect(toolNameToCategory("memory_recall")).toBe("read_files");
    expect(toolNameToCategory("memory_forget")).toBe("modify_memory");
    expect(toolNameToCategory("config_set")).toBe("modify_config");
  });

  it("handles case-insensitive matching", () => {
    expect(toolNameToCategory("BASH")).toBe("execute_shell");
    expect(toolNameToCategory("Read")).toBe("read_files");
  });

  it("uses heuristic fallback for unknown tool names", () => {
    expect(toolNameToCategory("delete_old_data")).toBe("delete_files");
    expect(toolNameToCategory("write_report")).toBe("write_files");
    expect(toolNameToCategory("read_config")).toBe("read_files");
    expect(toolNameToCategory("send_notification")).toBe("send_message");
    expect(toolNameToCategory("fetch_data")).toBe("external_network");
    expect(toolNameToCategory("shell_exec")).toBe("execute_shell");
    expect(toolNameToCategory("memory_update")).toBe("modify_memory");
  });

  it("defaults to execute_shell for completely unknown tools", () => {
    expect(toolNameToCategory("custom_thing")).toBe("execute_shell");
  });
});

describe("HIGH_RISK_ACTIONS", () => {
  it("contains expected high-risk actions", () => {
    expect(HIGH_RISK_ACTIONS).toContain("delete_files");
    expect(HIGH_RISK_ACTIONS).toContain("execute_shell");
    expect(HIGH_RISK_ACTIONS).toContain("modify_memory");
    expect(HIGH_RISK_ACTIONS).toContain("access_credentials");
  });

  it("all high-risk actions are valid action categories", () => {
    for (const action of HIGH_RISK_ACTIONS) {
      expect(ACTION_CATEGORIES).toContain(action);
    }
  });
});
