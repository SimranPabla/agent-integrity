import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import {
  PROTOCOL_VERSION,
  type AlphaIntegrityReceipt,
  type EnvelopeVerificationResult,
  type IntegrityEnvelope,
} from "@agent-integrity/protocol";
import { canonicalJson } from "../canonical-json.js";
import { sha256Canonical } from "../hash.js";
import { verifyTrustedEnvelope, type TrustedVerificationContext } from "../verify-trusted.js";

const RUN_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;

export interface CreateReceiptOptions {
  readonly runId: string;
  readonly path: string;
  readonly envelope: IntegrityEnvelope;
  readonly verification: EnvelopeVerificationResult;
  readonly context: TrustedVerificationContext;
  readonly createdAt: Date;
  readonly expiresAt: Date;
  readonly runRegistryDirectory?: string;
}

function isoDate(value: Date, name: string): string {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw new Error(`${name} must be a valid Date`);
  }
  return value.toISOString();
}

export async function createReceipt(options: CreateReceiptOptions): Promise<AlphaIntegrityReceipt> {
  if (!RUN_ID.test(options.runId)) {
    throw new Error("runId must be 1-128 safe identifier characters");
  }
  const createdAt = isoDate(options.createdAt, "createdAt");
  const expiresAt = isoDate(options.expiresAt, "expiresAt");
  if (options.expiresAt.getTime() <= options.createdAt.getTime()) {
    throw new Error("expiresAt must be later than createdAt");
  }

  const liveVerification = await verifyTrustedEnvelope(options.envelope, options.context);
  if (liveVerification.envelopeDigest === undefined) {
    throw new Error("cannot create a receipt for a malformed envelope");
  }
  if (sha256Canonical(liveVerification) !== sha256Canonical(options.verification)) {
    throw new Error("verification does not match the supplied envelope");
  }

  const body = {
    protocolVersion: PROTOCOL_VERSION,
    receiptVersion: "1-alpha" as const,
    signature: { status: "unsigned" as const },
    runId: options.runId,
    createdAt,
    expiresAt,
    envelopeDigest: liveVerification.envelopeDigest,
    verification: {
      protocolVersion: liveVerification.protocolVersion,
      status: liveVerification.status,
      findings: liveVerification.findings,
    },
  };
  const receipt: AlphaIntegrityReceipt = { ...body, receiptDigest: sha256Canonical(body) };

  const registryDirectory = options.runRegistryDirectory ?? join(dirname(options.path), ".integrity-run-ids");
  await mkdir(registryDirectory, { recursive: true });
  const markerPath = join(registryDirectory, options.runId);
  try {
    await writeFile(markerPath, `${receipt.receiptDigest}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new Error(`run ID already exists: ${options.runId}`);
    }
    throw error;
  }

  await mkdir(dirname(options.path), { recursive: true });
  try {
    await writeFile(options.path, `${canonicalJson(receipt)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new Error(`receipt already exists: ${options.path}`);
    }
    throw error;
  }
  return receipt;
}
