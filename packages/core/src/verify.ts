import {
  PROTOCOL_VERSION,
  type EnvelopeVerificationResult,
  type IntegrityEnvelope,
  type IntegrityFinding,
  type SourceRecord,
} from "@agent-integrity/protocol";
import { validateClaims } from "./claims/coverage.js";
import { reduceDecisions } from "./decisions/reduce-decisions.js";
import { sha256Canonical } from "./hash.js";
import { calculateOutcome, checkerFailure } from "./outcome.js";

const SHA256 = /^[a-f0-9]{64}$/u;

function validateSources(sources: readonly SourceRecord[]): void {
  const sourceIds = new Set<string>();
  const paths = new Set<string>();
  for (const [index, source] of sources.entries()) {
    if (typeof source.sourceId !== "string" || source.sourceId.trim() === "") {
      throw new Error(`sources[${index}].sourceId must be a non-empty string`);
    }
    if (sourceIds.has(source.sourceId)) throw new Error(`duplicate source ID: ${source.sourceId}`);
    sourceIds.add(source.sourceId);
    if (typeof source.path !== "string" || source.path.trim() === "") {
      throw new Error(`sources[${index}].path must be a non-empty string`);
    }
    if (paths.has(source.path)) throw new Error(`duplicate source path: ${source.path}`);
    paths.add(source.path);
    if (!SHA256.test(source.sha256)) throw new Error(`sources[${index}].sha256 is invalid`);
    if (!Number.isSafeInteger(source.size) || source.size < 0) {
      throw new Error(`sources[${index}].size must be a non-negative safe integer`);
    }
  }
}

function decisionFindings(envelope: IntegrityEnvelope): IntegrityFinding[] {
  const states = reduceDecisions(envelope.decisions);
  return states
    .filter((state) => state.status !== "active")
    .map((state) => ({
      code: `decision.${state.status}`,
      severity: "blocked" as const,
      message: `Decision ${state.decisionId} is ${state.status}`,
      path: "decisions",
    }));
}

function verifyUnsafe(envelope: IntegrityEnvelope): EnvelopeVerificationResult {
  if (envelope === null || typeof envelope !== "object") throw new Error("envelope must be an object");
  if (envelope.protocolVersion !== PROTOCOL_VERSION) throw new Error("unsupported protocol version");
  if (typeof envelope.response?.content !== "string") throw new Error("response.content must be a string");
  if (!Array.isArray(envelope.response.sections)) throw new Error("response.sections must be a list");
  if (!Array.isArray(envelope.sources) || !Array.isArray(envelope.decisions) ||
      !Array.isArray(envelope.evidence) || !Array.isArray(envelope.claims)) {
    throw new Error("sources, decisions, evidence, and claims must be lists");
  }
  validateSources(envelope.sources);
  const sourceIds = new Set(envelope.sources.map((source) => source.sourceId));
  for (const [index, evidence] of envelope.evidence.entries()) {
    if (!sourceIds.has(evidence.sourceId)) {
      throw new Error(`evidence[${index}] references unknown source: ${evidence.sourceId}`);
    }
  }

  const findings = [
    ...decisionFindings(envelope),
    ...validateClaims({
      sections: envelope.response.sections,
      claims: envelope.claims,
      evidence: envelope.evidence,
      requiredEvidenceFor: envelope.policy.rules.requireEvidenceFor,
      contradictions: envelope.policy.rules.contradictions,
    }),
  ];
  return { ...calculateOutcome(findings), envelopeDigest: sha256Canonical(envelope) };
}

export function verifyEnvelope(envelope: IntegrityEnvelope): EnvelopeVerificationResult {
  try {
    return verifyUnsafe(envelope);
  } catch (error) {
    return checkerFailure(error);
  }
}
