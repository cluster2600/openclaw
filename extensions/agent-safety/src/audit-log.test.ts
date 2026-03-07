import { describe, it, expect } from "vitest";
import { AuditLog } from "./audit-log.js";

describe("AuditLog", () => {
  it("adds entries and assigns auto-incrementing ids", () => {
    const log = new AuditLog();
    const entry = log.add({
      toolName: "bash",
      actionCategory: "execute_shell",
      requester: "TestUser",
      requesterTrust: 2,
      verdict: "ALLOW",
      riskScore: 10,
      riskCount: 0,
      topRiskType: null,
      reasoning: "Low risk action",
      blocked: false,
    });
    expect(entry.id).toBe(1);
    expect(entry.timestamp).toBeTruthy();
    expect(entry.toolName).toBe("bash");

    const entry2 = log.add({
      toolName: "read",
      actionCategory: "read_files",
      requester: "TestUser",
      requesterTrust: 2,
      verdict: "WARN",
      riskScore: 40,
      riskCount: 1,
      topRiskType: "sensitivity",
      reasoning: "May expose sensitive data",
      blocked: false,
    });
    expect(entry2.id).toBe(2);
  });

  it("returns entries in reverse chronological order", () => {
    const log = new AuditLog();
    log.add({
      toolName: "a",
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
    log.add({
      toolName: "b",
      actionCategory: "write_files",
      requester: "u",
      requesterTrust: 1,
      verdict: "WARN",
      riskScore: 30,
      riskCount: 1,
      topRiskType: "sensitivity",
      reasoning: "",
      blocked: false,
    });
    log.add({
      toolName: "c",
      actionCategory: "delete_files",
      requester: "u",
      requesterTrust: 1,
      verdict: "BLOCK",
      riskScore: 90,
      riskCount: 3,
      topRiskType: "authority",
      reasoning: "",
      blocked: true,
    });

    const entries = log.list();
    expect(entries[0].toolName).toBe("c");
    expect(entries[1].toolName).toBe("b");
    expect(entries[2].toolName).toBe("a");
  });

  it("respects limit parameter", () => {
    const log = new AuditLog();
    for (let i = 0; i < 10; i++) {
      log.add({
        toolName: `t${i}`,
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
    expect(log.list(3)).toHaveLength(3);
    expect(log.list()).toHaveLength(10);
  });

  it("enforces maxEntries", () => {
    const log = new AuditLog(5);
    for (let i = 0; i < 10; i++) {
      log.add({
        toolName: `t${i}`,
        actionCategory: "read_files",
        requester: "u",
        requesterTrust: 1,
        verdict: "ALLOW",
        riskScore: i * 10,
        riskCount: 0,
        topRiskType: null,
        reasoning: "",
        blocked: false,
      });
    }
    const entries = log.list();
    expect(entries).toHaveLength(5);
    // Most recent should be first
    expect(entries[0].toolName).toBe("t9");
  });

  it("computes correct stats", () => {
    const log = new AuditLog();
    log.add({
      toolName: "a",
      actionCategory: "read_files",
      requester: "u",
      requesterTrust: 1,
      verdict: "ALLOW",
      riskScore: 10,
      riskCount: 0,
      topRiskType: null,
      reasoning: "",
      blocked: false,
    });
    log.add({
      toolName: "b",
      actionCategory: "write_files",
      requester: "u",
      requesterTrust: 1,
      verdict: "WARN",
      riskScore: 40,
      riskCount: 1,
      topRiskType: "sensitivity",
      reasoning: "",
      blocked: false,
    });
    log.add({
      toolName: "c",
      actionCategory: "delete_files",
      requester: "u",
      requesterTrust: 1,
      verdict: "BLOCK",
      riskScore: 90,
      riskCount: 3,
      topRiskType: "authority",
      reasoning: "",
      blocked: true,
    });
    log.add({
      toolName: "d",
      actionCategory: "read_files",
      requester: "u",
      requesterTrust: 1,
      verdict: "BLOCK",
      riskScore: 80,
      riskCount: 2,
      topRiskType: "identity",
      reasoning: "",
      blocked: true,
    });

    const stats = log.stats();
    expect(stats.total).toBe(4);
    expect(stats.allowed).toBe(1);
    expect(stats.warned).toBe(1);
    expect(stats.blocked).toBe(2);
    expect(stats.averageRisk).toBe(55); // (10+40+90+80)/4 = 55
  });

  it("returns zero stats for empty log", () => {
    const log = new AuditLog();
    const stats = log.stats();
    expect(stats).toEqual({
      total: 0,
      allowed: 0,
      warned: 0,
      blocked: 0,
      averageRisk: 0,
    });
  });

  it("clears all entries", () => {
    const log = new AuditLog();
    log.add({
      toolName: "a",
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
    log.clear();
    expect(log.list()).toHaveLength(0);
    // IDs should reset
    const entry = log.add({
      toolName: "b",
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
    expect(entry.id).toBe(1);
  });
});
