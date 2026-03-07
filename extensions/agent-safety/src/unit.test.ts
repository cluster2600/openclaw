/**
 * Unit tests for constants, audit-log, stakeholder-store, prompt, and safety-tool modules.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { AuditLog } from "./audit-log.js";
import { toolNameToCategory, HIGH_RISK_ACTIONS, ACTION_CATEGORIES } from "./constants.js";
import type { Stakeholder } from "./constants.js";
import { buildValidationPrompt } from "./prompt.js";
import { createSafetyTool } from "./safety-tool.js";
import { StakeholderStore } from "./stakeholder-store.js";

// ── Audit log helper ────────────────────────────────────────────────────────

const entry = (overrides: Partial<Parameters<AuditLog["add"]>[0]> = {}) => ({
  toolName: "bash",
  actionCategory: "execute_shell" as const,
  requester: "u",
  requesterTrust: 1,
  verdict: "ALLOW" as const,
  riskScore: 0,
  riskCount: 0,
  topRiskType: null,
  reasoning: "",
  blocked: false,
  ...overrides,
});

// ── Constants ───────────────────────────────────────────────────────────────

describe("toolNameToCategory", () => {
  it("maps known tool names", () => {
    expect(toolNameToCategory("bash")).toBe("execute_shell");
    expect(toolNameToCategory("read")).toBe("read_files");
    expect(toolNameToCategory("write")).toBe("write_files");
    expect(toolNameToCategory("glob")).toBe("read_files");
    expect(toolNameToCategory("web_fetch")).toBe("external_network");
    expect(toolNameToCategory("send_message")).toBe("send_message");
    expect(toolNameToCategory("memory_store")).toBe("modify_memory");
    expect(toolNameToCategory("agent_communication")).toBe("agent_communication");
  });

  it("case-insensitive", () => {
    expect(toolNameToCategory("BASH")).toBe("execute_shell");
  });

  it("heuristic fallback", () => {
    expect(toolNameToCategory("delete_old_data")).toBe("delete_files");
    expect(toolNameToCategory("write_report")).toBe("write_files");
    expect(toolNameToCategory("read_config")).toBe("read_files");
    expect(toolNameToCategory("send_notification")).toBe("send_message");
    expect(toolNameToCategory("fetch_data")).toBe("external_network");
  });

  it("defaults to execute_shell for unknown", () => {
    expect(toolNameToCategory("custom_thing")).toBe("execute_shell");
  });
});

describe("HIGH_RISK_ACTIONS", () => {
  it("contains expected actions and all are valid categories", () => {
    for (const a of ["delete_files", "execute_shell", "modify_memory", "access_credentials"]) {
      expect(HIGH_RISK_ACTIONS).toContain(a);
    }
    for (const a of HIGH_RISK_ACTIONS) expect(ACTION_CATEGORIES).toContain(a);
  });
});

// ── AuditLog ────────────────────────────────────────────────────────────────

describe("AuditLog", () => {
  it("auto-incrementing ids + reverse-chronological", () => {
    const log = new AuditLog();
    const e1 = log.add(entry({ toolName: "a" }));
    const e2 = log.add(entry({ toolName: "b" }));
    expect(e1.id).toBe(1);
    expect(e2.id).toBe(2);
    expect(log.list()[0].toolName).toBe("b");
  });

  it("respects limit and maxEntries", () => {
    const log = new AuditLog(5);
    for (let i = 0; i < 10; i++) log.add(entry({ toolName: `t${i}` }));
    expect(log.list()).toHaveLength(5);
    expect(log.list(2)).toHaveLength(2);
    expect(log.list()[0].toolName).toBe("t9");
  });

  it("computes correct stats", () => {
    const log = new AuditLog();
    log.add(entry({ verdict: "ALLOW", riskScore: 10 }));
    log.add(entry({ verdict: "WARN", riskScore: 40 }));
    log.add(entry({ verdict: "BLOCK", riskScore: 90, blocked: true }));
    log.add(entry({ verdict: "BLOCK", riskScore: 80, blocked: true }));
    const s = log.stats();
    expect(s).toEqual({ total: 4, allowed: 1, warned: 1, blocked: 2, averageRisk: 55 });
  });

  it("empty stats and clear", () => {
    const log = new AuditLog();
    expect(log.stats().total).toBe(0);
    log.add(entry());
    log.clear();
    expect(log.list()).toHaveLength(0);
    expect(log.add(entry()).id).toBe(1);
  });
});

// ── StakeholderStore ────────────────────────────────────────────────────────

describe("StakeholderStore", () => {
  let tempDir: string;
  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "agent-safety-test-"));
  });
  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  it("initializes with default owner", () => {
    const s = new StakeholderStore();
    expect(s.list()).toHaveLength(1);
    expect(s.list()[0].role).toBe("owner");
  });

  it("add, get, persist, reload", () => {
    const fp = join(tempDir, "s.json");
    const s1 = new StakeholderStore(fp);
    s1.add({
      id: "u1",
      name: "Bob",
      role: "agent",
      trust: 3,
      verified: true,
      channel: "Internal",
      uid: "uid_bob",
      allowedActions: ["read_files"],
    });
    const s2 = new StakeholderStore(fp);
    expect(s2.list()).toHaveLength(2);
    expect(s2.get("u1")!.name).toBe("Bob");
  });

  it("update, remove, setTrust, grant/revoke", () => {
    const s = new StakeholderStore();
    s.add({
      id: "u1",
      name: "A",
      role: "non_owner",
      trust: 1,
      verified: false,
      channel: "E",
      uid: null,
      allowedActions: [],
    });
    expect(s.update("u1", { verified: true })).toBe(true);
    expect(s.get("u1")!.verified).toBe(true);
    expect(s.update("nope", { trust: 3 })).toBe(false);
    expect(s.setTrust("u1", 3)).toBe(true);
    expect(s.setTrust("u1", 5)).toBe(false);
    s.grantAction("u1", "read_files");
    expect(s.get("u1")!.allowedActions).toContain("read_files");
    s.revokeAction("u1", "read_files");
    expect(s.get("u1")!.allowedActions).not.toContain("read_files");
    expect(s.remove("u1")).toBe(true);
    expect(s.remove("owner_default")).toBe(false);
  });

  it("resolveRequester: owner flag, UID, unknown", () => {
    const s = new StakeholderStore();
    s.add({
      id: "u1",
      name: "Grace",
      role: "non_owner",
      trust: 2,
      verified: true,
      channel: "Discord",
      uid: "uid_g",
      allowedActions: ["read_files"],
    });
    expect(s.resolveRequester(undefined, true).role).toBe("owner");
    expect(s.resolveRequester("uid_g").name).toBe("Grace");
    const unknown = s.resolveRequester("nope");
    expect(unknown.trust).toBe(0);
    expect(unknown.verified).toBe(false);
  });

  it("getOwner", () => {
    expect(new StakeholderStore().getOwner()!.role).toBe("owner");
  });
});

// ── Prompt builder ──────────────────────────────────────────────────────────

describe("buildValidationPrompt", () => {
  const owner: Stakeholder = {
    id: "o",
    name: "Owner",
    role: "owner",
    trust: 4,
    verified: true,
    channel: "local",
    uid: "uid_o",
    allowedActions: ["read_files"],
  };
  const req: Stakeholder = {
    id: "u",
    name: "Test",
    role: "non_owner",
    trust: 2,
    verified: true,
    channel: "Discord",
    uid: "uid_t",
    allowedActions: ["read_files"],
  };

  it("includes tool info, stakeholder context, criteria, and schema", () => {
    const p = buildValidationPrompt({
      toolName: "bash",
      actionCategory: "execute_shell",
      params: { command: "ls" },
      requester: req,
      owner,
      stakeholders: [owner, req],
    });
    expect(p).toContain("Tool: bash");
    expect(p).toContain("Owner: Owner");
    expect(p).toContain("AUTHORITY");
    expect(p).toContain('"verdict"');
  });

  it("truncates long params", () => {
    const p = buildValidationPrompt({
      toolName: "write",
      actionCategory: "write_files",
      params: { content: "x".repeat(1000) },
      requester: req,
      owner,
      stakeholders: [owner],
    });
    expect(p).toContain("[truncated]");
  });

  it("handles missing owner and no-UID requester", () => {
    const noUid = { ...req, uid: null };
    const p = buildValidationPrompt({
      toolName: "read",
      actionCategory: "read_files",
      params: {},
      requester: noUid,
      owner: undefined,
      stakeholders: [],
    });
    expect(p).toContain("Unknown / Not configured");
    expect(p).toContain("UID: NOT PROVIDED");
  });
});

// ── Safety tool ─────────────────────────────────────────────────────────────

describe("agent_safety tool", () => {
  let store: StakeholderStore;
  let auditLog: AuditLog;
  let exec: (p: Record<string, unknown>) => Promise<{ content: Array<{ text: string }> }>;

  beforeEach(() => {
    store = new StakeholderStore();
    auditLog = new AuditLog();
    const tool = createSafetyTool(store, auditLog);
    exec = (p) =>
      (
        tool as {
          execute: (
            id: string,
            p: Record<string, unknown>,
          ) => Promise<{ content: Array<{ text: string }> }>;
        }
      ).execute("c", p);
  });

  it("status returns dashboard", async () => {
    auditLog.add(entry({ verdict: "ALLOW" }));
    auditLog.add(entry({ verdict: "BLOCK", blocked: true }));
    const d = JSON.parse((await exec({ action: "status" })).content[0].text);
    expect(d.auditStats.total).toBe(2);
    expect(d.auditStats.blocked).toBe(1);
  });

  it("stakeholders lists principals", async () => {
    const d = JSON.parse((await exec({ action: "stakeholders" })).content[0].text);
    expect(d).toHaveLength(1);
    expect(d[0].role).toBe("owner");
  });

  it("log returns entries with limit", async () => {
    for (let i = 0; i < 15; i++) auditLog.add(entry({ toolName: `t${i}` }));
    expect(JSON.parse((await exec({ action: "log", limit: 5 })).content[0].text)).toHaveLength(5);
    expect(JSON.parse((await exec({ action: "log" })).content[0].text)).toHaveLength(10);
  });

  it("add_stakeholder with and without UID", async () => {
    await exec({ action: "add_stakeholder", name: "A", uid: "uid_a" });
    const a = store.list().find((s) => s.name === "A");
    expect(a!.verified).toBe(true);

    await exec({ action: "add_stakeholder", name: "B" });
    const b = store.list().find((s) => s.name === "B");
    expect(b!.verified).toBe(false);
    expect(b!.trust).toBe(1);
    expect(b!.allowedActions).toEqual([]);
  });

  it("add_stakeholder errors on missing name", async () => {
    expect((await exec({ action: "add_stakeholder" })).content[0].text).toContain("Error");
  });

  it("set_trust updates and validates", async () => {
    store.add({
      id: "u1",
      name: "D",
      role: "non_owner",
      trust: 1,
      verified: true,
      channel: "D",
      uid: "uid_d",
      allowedActions: [],
    });
    await exec({ action: "set_trust", stakeholder_id: "u1", trust: 3 });
    expect(store.get("u1")!.trust).toBe(3);
    expect((await exec({ action: "set_trust" })).content[0].text).toContain("Error");
    expect(
      (await exec({ action: "set_trust", stakeholder_id: "u1", trust: 5 })).content[0].text,
    ).toContain("Error");
  });

  it("unknown action", async () => {
    const r = (await exec({ action: "nope" })).content[0].text;
    expect(r).toContain("Unknown action");
  });
});
