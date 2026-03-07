/**
 * In-memory stakeholder store with JSON file persistence.
 * Manages the principal registry for the safety system.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import type { Stakeholder, ActionCategory } from "./constants.js";
import { ACTION_CATEGORIES } from "./constants.js";

const DEFAULT_STAKEHOLDERS: Stakeholder[] = [
  {
    id: "owner_default",
    name: "Owner",
    role: "owner",
    trust: 4,
    verified: true,
    channel: "local",
    uid: "owner",
    allowedActions: [...ACTION_CATEGORIES],
  },
];

export class StakeholderStore {
  private stakeholders: Map<string, Stakeholder>;
  private filePath: string | null;

  constructor(filePath?: string) {
    this.filePath = filePath ?? null;
    this.stakeholders = new Map();
    this.load();
  }

  private load(): void {
    if (this.filePath && existsSync(this.filePath)) {
      try {
        const data = JSON.parse(readFileSync(this.filePath, "utf-8")) as Stakeholder[];
        for (const s of data) {
          this.stakeholders.set(s.id, s);
        }
        return;
      } catch {
        // fall through to defaults
      }
    }
    for (const s of DEFAULT_STAKEHOLDERS) {
      this.stakeholders.set(s.id, s);
    }
  }

  private persist(): void {
    if (!this.filePath) return;
    const dir = dirname(this.filePath);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(this.filePath, JSON.stringify(this.list(), null, 2));
  }

  list(): Stakeholder[] {
    return Array.from(this.stakeholders.values());
  }

  get(id: string): Stakeholder | undefined {
    return this.stakeholders.get(id);
  }

  getOwner(): Stakeholder | undefined {
    return this.list().find((s) => s.role === "owner");
  }

  /** Resolve a requester from tool context (senderId, channel info) */
  resolveRequester(senderId?: string, isOwner?: boolean): Stakeholder {
    // If sender is explicitly the owner
    if (isOwner) {
      return this.getOwner() ?? DEFAULT_STAKEHOLDERS[0];
    }

    // Try to match by UID
    if (senderId) {
      const match = this.list().find((s) => s.uid === senderId);
      if (match) return match;
    }

    // Return untrusted default for unknown senders
    return {
      id: "unknown",
      name: senderId ?? "Unknown",
      role: "non_owner",
      trust: 0,
      verified: false,
      channel: "unknown",
      uid: null,
      allowedActions: [],
    };
  }

  add(stakeholder: Stakeholder): void {
    this.stakeholders.set(stakeholder.id, stakeholder);
    this.persist();
  }

  update(id: string, updates: Partial<Stakeholder>): boolean {
    const existing = this.stakeholders.get(id);
    if (!existing) return false;
    this.stakeholders.set(id, { ...existing, ...updates });
    this.persist();
    return true;
  }

  remove(id: string): boolean {
    const existing = this.stakeholders.get(id);
    if (!existing || existing.role === "owner") return false;
    this.stakeholders.delete(id);
    this.persist();
    return true;
  }

  setTrust(id: string, trust: number): boolean {
    if (trust < 0 || trust > 4) return false;
    return this.update(id, { trust });
  }

  grantAction(id: string, action: ActionCategory): boolean {
    const s = this.stakeholders.get(id);
    if (!s) return false;
    if (s.allowedActions.includes(action)) return true;
    return this.update(id, { allowedActions: [...s.allowedActions, action] });
  }

  revokeAction(id: string, action: ActionCategory): boolean {
    const s = this.stakeholders.get(id);
    if (!s) return false;
    return this.update(id, {
      allowedActions: s.allowedActions.filter((a) => a !== action),
    });
  }
}
