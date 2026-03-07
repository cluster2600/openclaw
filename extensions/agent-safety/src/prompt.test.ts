import { describe, it, expect } from "vitest";
import type { Stakeholder } from "./constants.js";
import { buildValidationPrompt } from "./prompt.js";

describe("buildValidationPrompt", () => {
  const owner: Stakeholder = {
    id: "owner_1",
    name: "Owner",
    role: "owner",
    trust: 4,
    verified: true,
    channel: "local",
    uid: "uid_owner",
    allowedActions: ["read_files", "write_files", "execute_shell"],
  };

  const requester: Stakeholder = {
    id: "user_1",
    name: "TestUser",
    role: "non_owner",
    trust: 2,
    verified: true,
    channel: "Discord",
    uid: "uid_test_123",
    allowedActions: ["read_files"],
  };

  it("includes tool name and action category", () => {
    const prompt = buildValidationPrompt({
      toolName: "bash",
      actionCategory: "execute_shell",
      params: { command: "ls -la" },
      requester,
      owner,
      stakeholders: [owner, requester],
    });

    expect(prompt).toContain("Tool: bash");
    expect(prompt).toContain("Action Category: execute_shell");
  });

  it("includes stakeholder context", () => {
    const prompt = buildValidationPrompt({
      toolName: "read",
      actionCategory: "read_files",
      params: {},
      requester,
      owner,
      stakeholders: [owner, requester],
    });

    expect(prompt).toContain("Owner: Owner");
    expect(prompt).toContain("Name: TestUser");
    expect(prompt).toContain("Trust Level: 2/4");
    expect(prompt).toContain("Total principals in system: 2");
  });

  it("includes evaluation criteria and case study knowledge", () => {
    const prompt = buildValidationPrompt({
      toolName: "read",
      actionCategory: "read_files",
      params: {},
      requester,
      owner,
      stakeholders: [owner],
    });

    expect(prompt).toContain("AUTHORITY");
    expect(prompt).toContain("PROPORTIONALITY");
    expect(prompt).toContain("SENSITIVITY");
    expect(prompt).toContain("REVERSIBILITY");
    expect(prompt).toContain("RESOURCE");
    expect(prompt).toContain("IDENTITY");
    expect(prompt).toContain("INJECTION");
    expect(prompt).toContain("SOCIAL_ENGINEERING");
    expect(prompt).toContain("Case #2");
    expect(prompt).toContain("Case #8");
  });

  it("truncates long parameter values", () => {
    const longValue = "x".repeat(1000);
    const prompt = buildValidationPrompt({
      toolName: "write",
      actionCategory: "write_files",
      params: { content: longValue },
      requester,
      owner,
      stakeholders: [owner],
    });

    expect(prompt).toContain("[truncated]");
    expect(prompt).not.toContain("x".repeat(1000));
  });

  it("handles missing owner", () => {
    const prompt = buildValidationPrompt({
      toolName: "read",
      actionCategory: "read_files",
      params: {},
      requester,
      owner: undefined,
      stakeholders: [requester],
    });

    expect(prompt).toContain("Unknown / Not configured");
  });

  it("handles requester with no UID", () => {
    const noUidRequester = { ...requester, uid: null };
    const prompt = buildValidationPrompt({
      toolName: "read",
      actionCategory: "read_files",
      params: {},
      requester: noUidRequester,
      owner,
      stakeholders: [owner],
    });

    expect(prompt).toContain("UID: NOT PROVIDED");
  });

  it("includes response schema", () => {
    const prompt = buildValidationPrompt({
      toolName: "read",
      actionCategory: "read_files",
      params: {},
      requester,
      owner,
      stakeholders: [owner],
    });

    expect(prompt).toContain('"verdict"');
    expect(prompt).toContain('"riskScore"');
    expect(prompt).toContain('"risks"');
    expect(prompt).toContain('"recommendations"');
    expect(prompt).toContain("ALLOW");
    expect(prompt).toContain("WARN");
    expect(prompt).toContain("BLOCK");
  });
});
