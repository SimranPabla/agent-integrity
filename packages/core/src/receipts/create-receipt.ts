import { join } from "node:path";
import {
  type AlphaIntegrityReceipt,
  type EnvelopeVerificationResult,
  type IntegrityEnvelope,
} from "@agent-integrity/protocol";
import { sha256Canonical } from "../hash.js";
import { verifyTrustedEnvelope, type TrustedVerificationContext } from "../verify-trusted.js";
import { buildReceipt } from "./build-receipt.js";
import { FileReceiptStore } from "./file-receipt-store.js";
import { ReceiptOutputBoundary } from "./receipt-output-boundary.js";

export interface CreateReceiptOptions {
  readonly runId: string;
  readonly transactionId: string;
  readonly outputBoundary: ReceiptOutputBoundary;
  readonly outputName: string;
  readonly envelope: IntegrityEnvelope;
  readonly verification: EnvelopeVerificationResult;
  readonly context: TrustedVerificationContext;
  readonly createdAt: Date;
  readonly expiresAt: Date;
  readonly runRegistryDirectory?: string;
  readonly receiptStore?: FileReceiptStore;
  readonly signer: {
    readonly keyId: string;
    readonly privateKey: string;
    readonly issuer: string;
  };
  readonly audience: string;
  readonly purpose: string;
  readonly nonce: string;
  readonly engineVersion: string;
  readonly maxLifetimeMs?: number;
}

export async function createReceipt(options: CreateReceiptOptions): Promise<AlphaIntegrityReceipt> {
  const liveVerification = await verifyTrustedEnvelope(options.envelope, options.context);
  if (liveVerification.envelopeDigest === undefined) {
    throw new Error("cannot create a receipt for a malformed envelope");
  }
  if (sha256Canonical(liveVerification) !== sha256Canonical(options.verification)) {
    throw new Error("verification does not match the supplied envelope");
  }

  const receipt = buildReceipt({
    runId: options.runId,
    envelope: options.envelope,
    verification: liveVerification,
    createdAt: options.createdAt,
    expiresAt: options.expiresAt,
    signer: options.signer,
    audience: options.audience,
    purpose: options.purpose,
    nonce: options.nonce,
    engineVersion: options.engineVersion,
    ...(options.maxLifetimeMs === undefined ? {} : { maxLifetimeMs: options.maxLifetimeMs }),
  });

  const registryDirectory = options.runRegistryDirectory ?? join(options.outputBoundary.root, ".integrity-receipts");
  const store = options.receiptStore ?? new FileReceiptStore(registryDirectory);
  await store.issue(receipt, { transactionId: options.transactionId });

  try {
    await store.completeReceiptFile(receipt.receiptDigest, options.outputBoundary, options.outputName);
  } catch (error) {
    throw new Error(`receipt was issued but output completion failed; recover it with completeReceiptFile: ${error instanceof Error ? error.message : "unknown failure"}`);
  }
  return receipt;
}
