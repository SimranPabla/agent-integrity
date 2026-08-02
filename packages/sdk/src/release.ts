import { sha256Canonical, verifyEnvelope } from "@agent-integrity/core";
import {
  PROTOCOL_VERSION,
  type EnvelopeVerificationResult,
  type IntegrityEnvelope,
  type IntegrityResult,
} from "@agent-integrity/protocol";

export interface ReleaseVerifiedResponseOptions {
  readonly envelope: IntegrityEnvelope;
  readonly verification: EnvelopeVerificationResult;
}

export interface ReleasedResponse {
  readonly status: "PASS";
  readonly response: string;
  readonly verification: EnvelopeVerificationResult;
}

export interface HeldResponse {
  readonly status: "REVIEW" | "BLOCKED";
  readonly verification: EnvelopeVerificationResult;
}

export type ReleaseResult = ReleasedResponse | HeldResponse;

function mismatchResult(message: string): EnvelopeVerificationResult {
  const result: IntegrityResult = {
    protocolVersion: PROTOCOL_VERSION,
    status: "BLOCKED",
    findings: [{ code: "release.verification_mismatch", severity: "blocked", message }],
  };
  return result;
}

/** Rechecks all bound input and releases only the exact response verified as PASS. */
export function releaseVerifiedResponse(options: ReleaseVerifiedResponseOptions): ReleaseResult {
  try {
    const live = verifyEnvelope(options.envelope);
    if (live.envelopeDigest === undefined) {
      return { status: "BLOCKED", verification: live };
    }
    if (sha256Canonical(live) !== sha256Canonical(options.verification)) {
      return {
        status: "BLOCKED",
        verification: mismatchResult("The envelope or verification changed after checking"),
      };
    }
    if (live.status !== "PASS") return { status: live.status, verification: live };
    return { status: "PASS", response: options.envelope.response.content, verification: live };
  } catch {
    return {
      status: "BLOCKED",
      verification: mismatchResult("Release verification failed closed"),
    };
  }
}
