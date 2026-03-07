import { describe, it, expect, vi } from "vitest";
import type { Stakeholder } from "./constants.js";
import { quickCheck, validateAction } from "./validator.js";

const makeStakeholder = (overrides: Partial<Stakeholder> = {}): Stakeholder => ({
  id: "test_user",
  name: "Test User",
  role: "non_owner",
  trust: 2,
  verified: true,
  channel: "Discord",
  uid: "uid_test_123",
  allowedActions: ["read_files", "write_files"],
  ...overrides,
});

const owner: Stakeholder = {
  id: "owner_1",
  name: "Owner",
  role: "owner",
  trust: 4,
  verified: true,
  channel: "local",
  uid: "uid_owner",
  allowedActions: [
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
  ],
};

describe("quickCheck", () => {
  it("returns null for normal allowed actions", () => {
    const result = quickCheck({
      actionCategory: "read_files",
      requester: makeStakeholder(),
      params: {},
    });
    expect(result).toBeNull();
  });

  it("blocks unverified users with no UID on high-risk actions", () => {
    const result = quickCheck({
      actionCategory: "execute_shell",
      requester: makeStakeholder({
        verified: false,
        uid: null,
        allowedActions: ["execute_shell"],
      }),
      params: {},
    });
    expect(result).not.toBeNull();
    expect(result!.verdict).toBe("BLOCK");
    expect(result!.risks[0].type).toBe("identity");
    expect(result!.caseStudyReference).toContain("#8");
  });

  it("blocks actions not in requester's allowed list", () => {
    const result = quickCheck({
      actionCategory: "delete_files",
      requester: makeStakeholder({ allowedActions: ["read_files"] }),
      params: {},
    });
    expect(result).not.toBeNull();
    expect(result!.verdict).toBe("BLOCK");
    expect(result!.risks[0].type).toBe("authority");
    expect(result!.caseStudyReference).toContain("#2");
  });

  it("does not block if allowedActions is empty (no restrictions defined)", () => {
    const result = quickCheck({
      actionCategory: "delete_files",
      requester: makeStakeholder({ allowedActions: [] }),
      params: {},
    });
    // Empty allowedActions = no restrictions set, not "no permissions"
    // The length check is > 0 so this passes through
    expect(result).toBeNull();
  });

  it("blocks shell commands with infinite loops", () => {
    const result = quickCheck({
      actionCategory: "execute_shell",
      requester: makeStakeholder({ allowedActions: ["execute_shell"] }),
      params: { command: "while true; do echo running; done" },
    });
    expect(result).not.toBeNull();
    expect(result!.verdict).toBe("BLOCK");
    expect(result!.risks[0].type).toBe("resource");
    expect(result!.caseStudyReference).toContain("#4");
  });

  it("allows shell commands with timeout wrappers", () => {
    const result = quickCheck({
      actionCategory: "execute_shell",
      requester: makeStakeholder({ allowedActions: ["execute_shell"] }),
      params: { command: "timeout 60 watch -n 1 df -h" },
    });
    expect(result).toBeNull();
  });

  it("blocks tail -f without timeout", () => {
    const result = quickCheck({
      actionCategory: "execute_shell",
      requester: makeStakeholder({ allowedActions: ["execute_shell"] }),
      params: { command: "tail -f /var/log/syslog" },
    });
    expect(result).not.toBeNull();
    expect(result!.verdict).toBe("BLOCK");
  });

  it("allows tail -f with timeout", () => {
    const result = quickCheck({
      actionCategory: "execute_shell",
      requester: makeStakeholder({ allowedActions: ["execute_shell"] }),
      params: { command: "timeout 30 tail -f /var/log/syslog" },
    });
    expect(result).toBeNull();
  });
});

describe("validateAction", () => {
  it("calls the Anthropic API and returns parsed result", async () => {
    const mockResult = {
      verdict: "WARN",
      riskScore: 45,
      risks: [
        {
          type: "sensitivity",
          severity: "medium",
          description: "May expose file contents",
        },
      ],
      reasoning: "The action involves reading files which may contain sensitive data.",
      recommendations: ["Review file contents before sharing"],
      requiresOwnerConfirmation: false,
      caseStudyReference: null,
    };

    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        content: [{ type: "text", text: JSON.stringify(mockResult) }],
      }),
    });

    const result = await validateAction({
      toolName: "read",
      actionCategory: "read_files",
      params: { file_path: "/etc/passwd" },
      requester: makeStakeholder(),
      owner,
      stakeholders: [owner, makeStakeholder()],
      apiKey: "test-key",
      fetchFn: mockFetch as unknown as typeof globalThis.fetch,
    });

    expect(result.verdict).toBe("WARN");
    expect(result.riskScore).toBe(45);
    expect(result.risks).toHaveLength(1);

    // Verify API was called correctly
    expect(mockFetch).toHaveBeenCalledOnce();
    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe("https://api.anthropic.com/v1/messages");
    expect(opts.method).toBe("POST");
    expect(JSON.parse(opts.body).model).toBe("claude-sonnet-4-20250514");
  });

  it("throws on API error", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      text: async () => "Unauthorized",
    });

    await expect(
      validateAction({
        toolName: "bash",
        actionCategory: "execute_shell",
        params: { command: "ls" },
        requester: makeStakeholder(),
        owner,
        stakeholders: [owner],
        apiKey: "bad-key",
        fetchFn: mockFetch as unknown as typeof globalThis.fetch,
      }),
    ).rejects.toThrow("Anthropic API error (401)");
  });

  it("handles JSON wrapped in markdown code blocks", async () => {
    const mockResult = {
      verdict: "ALLOW",
      riskScore: 5,
      risks: [],
      reasoning: "Safe action",
      recommendations: [],
      requiresOwnerConfirmation: false,
      caseStudyReference: null,
    };

    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        content: [
          {
            type: "text",
            text: "```json\n" + JSON.stringify(mockResult) + "\n```",
          },
        ],
      }),
    });

    const result = await validateAction({
      toolName: "read",
      actionCategory: "read_files",
      params: {},
      requester: makeStakeholder(),
      owner,
      stakeholders: [owner],
      apiKey: "test-key",
      fetchFn: mockFetch as unknown as typeof globalThis.fetch,
    });

    expect(result.verdict).toBe("ALLOW");
    expect(result.riskScore).toBe(5);
  });
});
