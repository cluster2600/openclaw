/**
 * Tests for the agent-facing safety tool (agent_safety).
 * Verifies that agents cannot abuse the tool to bypass safety controls.
 */
import { describe, it, expect, beforeEach } from "vitest";
import { AuditLog } from "./audit-log.js";
import { createSafetyTool } from "./safety-tool.js";
import { StakeholderStore } from "./stakeholder-store.js";

describe("agent_safety tool", () => {
  let store: StakeholderStore;
  let auditLog: AuditLog;
  let tool: ReturnType<typeof createSafetyTool>;

  beforeEach(() => {
    store = new StakeholderStore();
    auditLog = new AuditLog();
    tool = createSafetyTool(store, auditLog);
  });

  const exec = (params: Record<string, unknown>) =>
    (
      tool as {
        execute: (
          id: string,
          p: Record<string, unknown>,
        ) => Promise<{ content: Array<{ text: string }> }>;
      }
    ).execute("call_1", params);

  // ── status action ─────────────────────────────────────────────────────

  describe("status", () => {
    it("returns dashboard summary with audit stats", async () => {
      auditLog.add({
        toolName: "bash",
        actionCategory: "execute_shell",
        requester: "Owner",
        requesterTrust: 4,
        verdict: "ALLOW",
        riskScore: 5,
        riskCount: 0,
        topRiskType: null,
        reasoning: "ok",
        blocked: false,
      });
      auditLog.add({
        toolName: "delete_file",
        actionCategory: "delete_files",
        requester: "Attacker",
        requesterTrust: 0,
        verdict: "BLOCK",
        riskScore: 95,
        riskCount: 2,
        topRiskType: "identity",
        reasoning: "blocked",
        blocked: true,
      });

      const result = await exec({ action: "status" });
      const data = JSON.parse(result.content[0].text);

      expect(data.auditStats.total).toBe(2);
      expect(data.auditStats.allowed).toBe(1);
      expect(data.auditStats.blocked).toBe(1);
      expect(data.principalCount).toBe(1); // default owner
    });

    it("reports identity gaps", async () => {
      store.add({
        id: "unverified_1",
        name: "Sketchy",
        role: "non_owner",
        trust: 0,
        verified: false,
        channel: "Email",
        uid: null,
        allowedActions: [],
      });

      const result = await exec({ action: "status" });
      const data = JSON.parse(result.content[0].text);

      expect(data.identityGaps.length).toBeGreaterThanOrEqual(1);
      expect(data.identityGaps.some((g: { name: string }) => g.name === "Sketchy")).toBe(true);
    });
  });

  // ── stakeholders action ───────────────────────────────────────────────

  describe("stakeholders", () => {
    it("lists all registered principals", async () => {
      const result = await exec({ action: "stakeholders" });
      const data = JSON.parse(result.content[0].text);

      expect(data).toHaveLength(1); // default owner
      expect(data[0].role).toBe("owner");
    });
  });

  // ── log action ────────────────────────────────────────────────────────

  describe("log", () => {
    it("returns recent audit entries", async () => {
      for (let i = 0; i < 15; i++) {
        auditLog.add({
          toolName: `tool_${i}`,
          actionCategory: "read_files",
          requester: "u",
          requesterTrust: 1,
          verdict: "ALLOW",
          riskScore: 0,
          riskCount: 0,
          topRiskType: null,
          reasoning: "",
          blocked: false,
        });
      }

      const result = await exec({ action: "log", limit: 5 });
      const data = JSON.parse(result.content[0].text);
      expect(data).toHaveLength(5);
    });

    it("defaults to 10 entries", async () => {
      for (let i = 0; i < 20; i++) {
        auditLog.add({
          toolName: `tool_${i}`,
          actionCategory: "read_files",
          requester: "u",
          requesterTrust: 1,
          verdict: "ALLOW",
          riskScore: 0,
          riskCount: 0,
          topRiskType: null,
          reasoning: "",
          blocked: false,
        });
      }

      const result = await exec({ action: "log" });
      const data = JSON.parse(result.content[0].text);
      expect(data).toHaveLength(10);
    });
  });

  // ── add_stakeholder action ────────────────────────────────────────────

  describe("add_stakeholder", () => {
    it("adds a new principal", async () => {
      const result = await exec({
        action: "add_stakeholder",
        name: "Alice",
        role: "non_owner",
        trust: 2,
        channel: "Discord",
        uid: "uid_alice",
      });

      expect(result.content[0].text).toContain("Alice");
      expect(result.content[0].text).toContain("added");

      const all = store.list();
      expect(all.some((s) => s.name === "Alice")).toBe(true);
    });

    it("sets verified=true when UID is provided", async () => {
      await exec({
        action: "add_stakeholder",
        name: "Bob",
        uid: "uid_bob",
      });

      const bob = store.list().find((s) => s.name === "Bob");
      expect(bob).toBeDefined();
      expect(bob!.verified).toBe(true);
    });

    it("sets verified=false when no UID", async () => {
      await exec({
        action: "add_stakeholder",
        name: "Charlie",
      });

      const charlie = store.list().find((s) => s.name === "Charlie");
      expect(charlie).toBeDefined();
      expect(charlie!.verified).toBe(false);
      expect(charlie!.uid).toBeNull();
    });

    it("returns error when name is missing", async () => {
      const result = await exec({ action: "add_stakeholder" });
      expect(result.content[0].text).toContain("Error");
    });

    it("defaults to non_owner role and trust 1", async () => {
      await exec({ action: "add_stakeholder", name: "Default" });

      const d = store.list().find((s) => s.name === "Default");
      expect(d!.role).toBe("non_owner");
      expect(d!.trust).toBe(1);
    });

    it("starts with empty allowedActions", async () => {
      await exec({ action: "add_stakeholder", name: "NewUser" });
      const u = store.list().find((s) => s.name === "NewUser");
      expect(u!.allowedActions).toEqual([]);
    });
  });

  // ── set_trust action ──────────────────────────────────────────────────

  describe("set_trust", () => {
    it("updates trust level", async () => {
      store.add({
        id: "user_1",
        name: "Diana",
        role: "non_owner",
        trust: 1,
        verified: true,
        channel: "Discord",
        uid: "uid_diana",
        allowedActions: ["read_message"],
      });

      const result = await exec({
        action: "set_trust",
        stakeholder_id: "user_1",
        trust: 3,
      });

      expect(result.content[0].text).toContain("updated");
      expect(store.get("user_1")!.trust).toBe(3);
    });

    it("returns error for missing params", async () => {
      const result = await exec({ action: "set_trust" });
      expect(result.content[0].text).toContain("Error");
    });

    it("returns error for non-existent stakeholder", async () => {
      const result = await exec({
        action: "set_trust",
        stakeholder_id: "nonexistent",
        trust: 2,
      });
      expect(result.content[0].text).toContain("Error");
    });

    it("rejects invalid trust levels", async () => {
      store.add({
        id: "user_2",
        name: "Eve",
        role: "non_owner",
        trust: 2,
        verified: true,
        channel: "Discord",
        uid: "uid_eve",
        allowedActions: [],
      });

      const result = await exec({
        action: "set_trust",
        stakeholder_id: "user_2",
        trust: 5,
      });
      expect(result.content[0].text).toContain("Error");
      expect(store.get("user_2")!.trust).toBe(2); // unchanged
    });
  });

  // ── unknown action ────────────────────────────────────────────────────

  describe("unknown action", () => {
    it("returns helpful error message", async () => {
      const result = await exec({ action: "hack_everything" });
      expect(result.content[0].text).toContain("Unknown action");
      expect(result.content[0].text).toContain("status");
    });
  });
});
