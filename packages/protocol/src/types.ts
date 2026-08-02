export const PROTOCOL_VERSION = "1-alpha" as const;

export type IntegrityStatus = "PASS" | "REVIEW" | "BLOCKED";
export type FindingSeverity = "review" | "blocked";

export interface IntegrityFinding {
  readonly code: string;
  readonly severity: FindingSeverity;
  readonly message: string;
  readonly path?: string;
}

export interface IntegrityResult {
  readonly protocolVersion: typeof PROTOCOL_VERSION;
  readonly status: IntegrityStatus;
  readonly findings: readonly IntegrityFinding[];
}
