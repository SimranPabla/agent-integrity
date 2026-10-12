import { captureJsonData, captureTrustedContext, FileReceiptStore, recheckTrustedReceipt, sha256Canonical, verifyTrustedEnvelope, type RecheckReceiptOptions, type TrustedVerificationContext } from "@agent-integrity/core";
import {
  PROTOCOL_VERSION,
  type EnvelopeVerificationResult,
  type IntegrityEnvelope,
  type IntegrityResult,
  type AlphaIntegrityReceipt,
} from "@agent-integrity/protocol";

export interface ReleaseVerifiedResponseOptions {
  readonly envelope: IntegrityEnvelope;
  readonly verification: EnvelopeVerificationResult;
  readonly context: TrustedVerificationContext;
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

export interface ReleaseVerifiedReceiptOptions extends ReleaseVerifiedResponseOptions {
  readonly receipt: AlphaIntegrityReceipt;
  readonly receiptStore: FileReceiptStore;
  readonly now: Date;
  readonly trust: RecheckReceiptOptions["trust"];
}

function mismatchResult(message: string): EnvelopeVerificationResult {
  const result: IntegrityResult = {
    protocolVersion: PROTOCOL_VERSION,
    status: "BLOCKED",
    findings: [{ code: "release.verification_mismatch", severity: "blocked", message }],
  };
  return result;
}

/** Rechecks all bound input and releases only the exact response verified as PASS. */
export async function releaseVerifiedResponse(options: ReleaseVerifiedResponseOptions): Promise<ReleaseResult> {
  try {
    // Select only the plain fields: signed options also contain Date/store capabilities.
    const select = <K extends keyof ReleaseVerifiedResponseOptions>(key: K): ReleaseVerifiedResponseOptions[K] => {
      const descriptor = Object.getOwnPropertyDescriptor(options, key);
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
        throw new TypeError("Release options require own enumerable data fields");
      }
      return descriptor.value as ReleaseVerifiedResponseOptions[K];
    };
    const envelope = captureJsonData(select("envelope"));
    const verification = captureJsonData(select("verification"));
    const context = captureTrustedContext(select("context"));
    const live = await verifyTrustedEnvelope(envelope, context);
    if (live.envelopeDigest === undefined) {
      return { status: "BLOCKED", verification: live };
    }
    if (sha256Canonical(live) !== sha256Canonical(verification)) {
      return {
        status: "BLOCKED",
        verification: mismatchResult("The envelope or verification changed after checking"),
      };
    }
    if (live.status !== "PASS") return { status: live.status, verification: live };
    return { status: "PASS", response: envelope.response.content, verification: live };
  } catch {
    return {
      status: "BLOCKED",
      verification: mismatchResult("Release verification failed closed"),
    };
  }
}

/** Authenticates and atomically consumes a signed receipt before releasing its exact response. */
export async function releaseVerifiedReceipt(options: ReleaseVerifiedReceiptOptions): Promise<ReleaseResult> {
  const release = await releaseVerifiedResponse(options);
  if (release.status !== "PASS") return release;
  const consumed = await recheckTrustedReceipt({ receipt: options.receipt, envelope: options.envelope, context: options.context, receiptStore: options.receiptStore, now: options.now, trust: options.trust });
  if (consumed.status !== "PASS") return { status: consumed.status, verification: consumed };
  return release;
}
