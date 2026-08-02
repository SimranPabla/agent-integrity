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

export type DecisionAction = "activate" | "reject" | "supersede";

export interface DecisionEvent {
  readonly eventId: string;
  readonly decisionId: string;
  readonly revision: number;
  readonly action: DecisionAction;
  readonly supersededBy?: string;
}

export type DecisionStatus = "active" | "rejected" | "superseded";

export interface DecisionState {
  readonly decisionId: string;
  readonly status: DecisionStatus;
  readonly revision: number;
  readonly supersededBy?: string;
}

export type ClaimKind = "factual" | "recommendation" | "inference";
export type EvidenceRole = "supporting" | "contradictory" | "contextual";
export type EvidenceSupport = "direct" | "ambiguous";

export interface ResponseSection {
  readonly sectionId: string;
  readonly substantive: boolean;
}

export interface EvidenceItem {
  readonly evidenceId: string;
  readonly sourceId: string;
}

export interface ClaimEvidence {
  readonly evidenceId: string;
  readonly role: EvidenceRole;
  readonly support?: EvidenceSupport;
  readonly disclosed?: boolean;
}

export interface IntegrityClaim {
  readonly claimId: string;
  readonly sectionId: string;
  readonly kind: ClaimKind;
  readonly evidence: readonly ClaimEvidence[];
}
