import {
  PROTOCOL_VERSION,
  type AlphaIntegrityReceipt,
  type IntegrityEnvelope,
  type IntegrityFinding,
  type ReceiptRecheckResult,
} from "@agent-integrity/protocol";
import { sha256Canonical } from "../hash.js";
import { calculateOutcome, checkerFailure } from "../outcome.js";
import { verifyEnvelope } from "../verify.js";

export interface RecheckReceiptOptions {
  readonly receipt: AlphaIntegrityReceipt;
  readonly envelope: IntegrityEnvelope;
  readonly now: Date;
}

function receiptBody(receipt: AlphaIntegrityReceipt): Omit<AlphaIntegrityReceipt, "receiptDigest"> {
  const { receiptDigest: _receiptDigest, ...body } = receipt;
  return body;
}

function blocked(code: string, message: string): IntegrityFinding {
  return { code, severity: "blocked", message, path: "receipt" };
}

function recheckUnsafe(options: RecheckReceiptOptions): ReceiptRecheckResult {
  const { receipt, envelope, now } = options;
  if (receipt === null || typeof receipt !== "object") throw new Error("receipt must be an object");
  if (receipt.protocolVersion !== PROTOCOL_VERSION || receipt.receiptVersion !== "1-alpha") {
    throw new Error("unsupported receipt version");
  }
  if (receipt.signature?.status !== "unsigned") throw new Error("invalid alpha receipt signature status");
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) throw new Error("now must be a valid Date");

  const findings: IntegrityFinding[] = [];
  const calculatedReceiptDigest = sha256Canonical(receiptBody(receipt));
  if (calculatedReceiptDigest !== receipt.receiptDigest) {
    findings.push(blocked("receipt.mutated", "Receipt content changed after creation"));
  }
  const expiresAt = Date.parse(receipt.expiresAt);
  const createdAt = Date.parse(receipt.createdAt);
  if (!Number.isFinite(expiresAt) || !Number.isFinite(createdAt) || expiresAt <= createdAt) {
    findings.push(blocked("receipt.invalid_time", "Receipt timestamps are invalid"));
  } else if (now.getTime() >= expiresAt) {
    findings.push(blocked("receipt.expired", "Receipt has expired"));
  }

  const liveVerification = verifyEnvelope(envelope);
  if (liveVerification.envelopeDigest === undefined) {
    findings.push(blocked("receipt.live_check_failed", "Live envelope could not be verified"));
  } else if (liveVerification.envelopeDigest !== receipt.envelopeDigest) {
    findings.push(blocked("receipt.subject_changed", "Response or another bound subject changed"));
  }
  if (liveVerification.envelopeDigest === receipt.envelopeDigest &&
      (liveVerification.status !== receipt.verification.status ||
       sha256Canonical(liveVerification.findings) !== sha256Canonical(receipt.verification.findings))) {
    findings.push(blocked("receipt.outcome_changed", "Verification outcome no longer matches the receipt"));
  }

  const outcome = calculateOutcome([...receipt.verification.findings, ...findings]);
  return {
    ...outcome,
    receiptDigest: calculatedReceiptDigest,
    ...(liveVerification.envelopeDigest === undefined
      ? {}
      : { envelopeDigest: liveVerification.envelopeDigest }),
  };
}

export function recheckReceipt(options: RecheckReceiptOptions): ReceiptRecheckResult {
  try {
    return recheckUnsafe(options);
  } catch (error) {
    return checkerFailure(error);
  }
}
