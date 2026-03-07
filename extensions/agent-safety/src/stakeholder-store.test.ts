import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { StakeholderStore } from "./stakeholder-store.js";

describe("StakeholderStore", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "agent-safety-test-"));
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  it("initializes with default owner", () => {
    const store = new StakeholderStore();
    const stakeholders = store.list();
    expect(stakeholders).toHaveLength(1);
    expect(stakeholders[0].role).toBe("owner");
    expect(stakeholders[0].trust).toBe(4);
  });

  it("adds and retrieves stakeholders", () => {
    const store = new StakeholderStore();
    store.add({
      id: "user_1",
      name: "Alice",
      role: "non_owner",
      trust: 2,
      verified: true,
      channel: "Discord",
      uid: "uid_alice_123",
      allowedActions: ["read_files"],
    });

    const alice = store.get("user_1");
    expect(alice).toBeDefined();
    expect(alice!.name).toBe("Alice");
    expect(alice!.trust).toBe(2);
  });

  it("persists to file and reloads", () => {
    const filePath = join(tempDir, "stakeholders.json");
    const store1 = new StakeholderStore(filePath);
    store1.add({
      id: "user_1",
      name: "Bob",
      role: "agent",
      trust: 3,
      verified: true,
      channel: "Internal",
      uid: "uid_bob_456",
      allowedActions: ["read_files", "write_files"],
    });

    // Create new store from same file
    const store2 = new StakeholderStore(filePath);
    expect(store2.list()).toHaveLength(2); // owner + Bob
    expect(store2.get("user_1")!.name).toBe("Bob");
  });

  it("updates stakeholder fields", () => {
    const store = new StakeholderStore();
    store.add({
      id: "user_1",
      name: "Charlie",
      role: "non_owner",
      trust: 1,
      verified: false,
      channel: "Email",
      uid: null,
      allowedActions: [],
    });

    const result = store.update("user_1", { verified: true, uid: "uid_charlie" });
    expect(result).toBe(true);
    expect(store.get("user_1")!.verified).toBe(true);
    expect(store.get("user_1")!.uid).toBe("uid_charlie");
  });

  it("returns false for updating non-existent stakeholder", () => {
    const store = new StakeholderStore();
    expect(store.update("nonexistent", { trust: 3 })).toBe(false);
  });

  it("removes non-owner stakeholders", () => {
    const store = new StakeholderStore();
    store.add({
      id: "user_1",
      name: "Diana",
      role: "non_owner",
      trust: 1,
      verified: false,
      channel: "Discord",
      uid: null,
      allowedActions: [],
    });

    expect(store.remove("user_1")).toBe(true);
    expect(store.get("user_1")).toBeUndefined();
  });

  it("refuses to remove the owner", () => {
    const store = new StakeholderStore();
    expect(store.remove("owner_default")).toBe(false);
    expect(store.get("owner_default")).toBeDefined();
  });

  it("sets trust level within valid range", () => {
    const store = new StakeholderStore();
    store.add({
      id: "user_1",
      name: "Eve",
      role: "non_owner",
      trust: 1,
      verified: true,
      channel: "Discord",
      uid: "uid_eve",
      allowedActions: [],
    });

    expect(store.setTrust("user_1", 3)).toBe(true);
    expect(store.get("user_1")!.trust).toBe(3);

    expect(store.setTrust("user_1", -1)).toBe(false);
    expect(store.setTrust("user_1", 5)).toBe(false);
    expect(store.get("user_1")!.trust).toBe(3); // unchanged
  });

  it("grants and revokes action permissions", () => {
    const store = new StakeholderStore();
    store.add({
      id: "user_1",
      name: "Frank",
      role: "non_owner",
      trust: 2,
      verified: true,
      channel: "Discord",
      uid: "uid_frank",
      allowedActions: ["read_files"],
    });

    store.grantAction("user_1", "write_files");
    expect(store.get("user_1")!.allowedActions).toContain("write_files");

    store.revokeAction("user_1", "read_files");
    expect(store.get("user_1")!.allowedActions).not.toContain("read_files");
  });

  it("resolves requester by owner flag", () => {
    const store = new StakeholderStore();
    const resolved = store.resolveRequester(undefined, true);
    expect(resolved.role).toBe("owner");
    expect(resolved.trust).toBe(4);
  });

  it("resolves requester by UID", () => {
    const store = new StakeholderStore();
    store.add({
      id: "user_1",
      name: "Grace",
      role: "non_owner",
      trust: 2,
      verified: true,
      channel: "Discord",
      uid: "uid_grace_789",
      allowedActions: ["read_files"],
    });

    const resolved = store.resolveRequester("uid_grace_789");
    expect(resolved.name).toBe("Grace");
    expect(resolved.trust).toBe(2);
  });

  it("returns untrusted default for unknown senders", () => {
    const store = new StakeholderStore();
    const resolved = store.resolveRequester("unknown_uid");
    expect(resolved.trust).toBe(0);
    expect(resolved.verified).toBe(false);
    expect(resolved.role).toBe("non_owner");
  });

  it("returns untrusted default with sender name when no UID match", () => {
    const store = new StakeholderStore();
    const resolved = store.resolveRequester("some_sender_id");
    expect(resolved.name).toBe("some_sender_id");
  });

  it("getOwner returns the owner stakeholder", () => {
    const store = new StakeholderStore();
    const owner = store.getOwner();
    expect(owner).toBeDefined();
    expect(owner!.role).toBe("owner");
  });
});
