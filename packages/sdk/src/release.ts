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

function selectDataField<T extends object, K extends keyof T>(options: T, key: K): T[K] {
  const descriptor = Object.getOwnPropertyDescriptor(options, key);
  if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
    throw new TypeError("Release options require own enumerable data fields");
  }
  return descriptor.value as T[K];
}

function captureReceiptTrust(value: RecheckReceiptOptions["trust"]): RecheckReceiptOptions["trust"] {
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError("Expected plain receipt trust");
  const normalized: Record<string, unknown> = Object.create(null);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (typeof key !== "string" || !descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new TypeError("Receipt trust requires enumerable data properties");
    }
    // Preserve the recheck API's defaults without admitting other undefined data.
    if (descriptor.value === undefined &&
        (key === "maxClockSkewMs" || key === "maxLifetimeMs" || key === "revokedKeyIds")) continue;
    normalized[key] = descriptor.value;
  }
  return captureJsonData(normalized) as unknown as RecheckReceiptOptions["trust"];
}

/** Rechecks all bound input and releases only the exact response verified as PASS. */
export async function releaseVerifiedResponse(options: ReleaseVerifiedResponseOptions): Promise<ReleaseResult> {
  try {
    // Select only the plain fields: signed options also contain Date/store capabilities.
    const envelope = captureJsonData(selectDataField(options, "envelope"));
    const verification = captureJsonData(selectDataField(options, "verification"));
    const context = captureTrustedContext(selectDataField(options, "context"));
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
  try {
    // Own the entire transaction before either verification stage can yield.
    // Store identity is selected once; its methods/state remain trusted-host capabilities.
    const envelope = captureJsonData(selectDataField(options, "envelope"));
    const verification = captureJsonData(selectDataField(options, "verification"));
    const context = captureTrustedContext(selectDataField(options, "context"));
    const receipt = captureJsonData(selectDataField(options, "receipt"));
    const trust = captureReceiptTrust(selectDataField(options, "trust"));
    const time = Date.prototype.getTime.call(selectDataField(options, "now"));
    if (!Number.isFinite(time)) throw new TypeError("now must be a valid Date");
    const now = new Date(time);
    const receiptStore = selectDataField(options, "receiptStore");
    const release = await releaseVerifiedResponse({ envelope, verification, context });
    if (release.status !== "PASS") return release;
    const consumed = await recheckTrustedReceipt({ receipt, envelope, context, receiptStore, now, trust });
    if (consumed.status !== "PASS") return { status: consumed.status, verification: consumed };
    return release;
  } catch {
    return { status: "BLOCKED", verification: mismatchResult("Signed release verification failed closed") };
  }
}
