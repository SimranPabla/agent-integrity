import { sign } from "node:crypto";
import {
  PROTOCOL_VERSION,
  type AlphaIntegrityReceipt,
  type EnvelopeVerificationResult,
  type IntegrityEnvelope,
} from "@agent-integrity/protocol";
import { canonicalJson } from "../canonical-json.js";
import { sha256Canonical } from "../hash.js";

const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;

export interface BuildReceiptOptions {
  readonly runId: string;
  readonly envelope: IntegrityEnvelope;
  readonly verification: EnvelopeVerificationResult;
  readonly createdAt: Date;
  readonly expiresAt: Date;
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

function isoDate(value: Date, name: string): string {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) throw new Error(`${name} must be a valid Date`);
  return value.toISOString();
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

/** Pure receipt construction from already-live-verified, explicit inputs. */
export function buildReceipt(options: BuildReceiptOptions): AlphaIntegrityReceipt {
  if (!SAFE_IDENTIFIER.test(options.runId)) throw new Error("runId must be 1-128 safe identifier characters");
  const createdAt = isoDate(options.createdAt, "createdAt");
  const expiresAt = isoDate(options.expiresAt, "expiresAt");
  if (options.expiresAt.getTime() <= options.createdAt.getTime()) throw new Error("expiresAt must be later than createdAt");
  const maxLifetimeMs = options.maxLifetimeMs ?? 3_600_000;
  if (!Number.isSafeInteger(maxLifetimeMs) || maxLifetimeMs < 1) throw new Error("maxLifetimeMs must be a positive safe integer");
  if (options.expiresAt.getTime() - options.createdAt.getTime() > maxLifetimeMs) throw new Error("receipt lifetime exceeds configured maximum");
  for (const [name, value] of Object.entries({
    keyId: options.signer.keyId,
    issuer: options.signer.issuer,
    audience: options.audience,
    purpose: options.purpose,
    nonce: options.nonce,
    engineVersion: options.engineVersion,
  })) {
    if (typeof value !== "string" || value.length < 1 || value.length > 256) throw new Error(`${name} must be 1-256 characters`);
  }
  if (options.verification.envelopeDigest === undefined) throw new Error("cannot build a receipt for a malformed envelope");

  const body = {
    protocolVersion: PROTOCOL_VERSION,
    receiptVersion: "2-alpha" as const,
    engineVersion: options.engineVersion,
    issuer: options.signer.issuer,
    audience: options.audience,
    purpose: options.purpose,
    nonce: options.nonce,
    runId: options.runId,
    createdAt,
    expiresAt,
    policyDigest: sha256Canonical(options.envelope.policy),
    envelopeDigest: options.verification.envelopeDigest,
    verification: {
      protocolVersion: options.verification.protocolVersion,
      status: options.verification.status,
      findings: structuredClone(options.verification.findings),
    },
  };
  const protectedSignature = { algorithm: "Ed25519" as const, keyId: options.signer.keyId };
  const signature = {
    ...protectedSignature,
    value: sign(null, Buffer.from(canonicalJson({ protected: protectedSignature, body }), "utf8"), options.signer.privateKey).toString("base64"),
  };
  const signed = { ...body, signature };
  return deepFreeze({ ...signed, receiptDigest: sha256Canonical(signed) });
}
