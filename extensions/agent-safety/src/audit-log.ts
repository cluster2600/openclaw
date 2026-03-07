/**
 * In-memory audit log for validated actions.
 * Provides the data backbone for the safety dashboard.
 */

import type { Verdict, RiskType } from "./constants.js";

export type AuditEntry = {
  id: number;
  timestamp: string;
  toolName: string;
  actionCategory: string;
  requester: string;
  requesterTrust: number;
  verdict: Verdict;
  riskScore: number;
  riskCount: number;
  topRiskType: RiskType | null;
  reasoning: string;
  blocked: boolean;
};

export class AuditLog {
  private entries: AuditEntry[] = [];
  private maxEntries: number;
  private nextId = 1;

  constructor(maxEntries = 500) {
    this.maxEntries = maxEntries;
  }

  add(entry: Omit<AuditEntry, "id" | "timestamp">): AuditEntry {
    const full: AuditEntry = {
      ...entry,
      id: this.nextId++,
      timestamp: new Date().toISOString(),
    };
    this.entries.unshift(full);
    if (this.entries.length > this.maxEntries) {
      this.entries = this.entries.slice(0, this.maxEntries);
    }
    return full;
  }

  list(limit?: number): AuditEntry[] {
    return limit ? this.entries.slice(0, limit) : [...this.entries];
  }

  stats(): {
    total: number;
    allowed: number;
    warned: number;
    blocked: number;
    averageRisk: number;
  } {
    const total = this.entries.length;
    if (total === 0) {
      return { total: 0, allowed: 0, warned: 0, blocked: 0, averageRisk: 0 };
    }
    const allowed = this.entries.filter((e) => e.verdict === "ALLOW").length;
    const warned = this.entries.filter((e) => e.verdict === "WARN").length;
    const blocked = this.entries.filter((e) => e.verdict === "BLOCK").length;
    const averageRisk = Math.round(this.entries.reduce((sum, e) => sum + e.riskScore, 0) / total);
    return { total, allowed, warned, blocked, averageRisk };
  }

  clear(): void {
    this.entries = [];
    this.nextId = 1;
  }
}
