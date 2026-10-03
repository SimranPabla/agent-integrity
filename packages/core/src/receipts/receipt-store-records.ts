import { PROTOCOL_VERSION, type AlphaIntegrityReceipt } from "@agent-integrity/protocol";
import { sha256Canonical } from "../hash.js";

const SHA256 = /^[a-f0-9]{64}$/u;
const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const REASON_CODE = /^[A-Z][A-Z0-9_]{0,127}$/u;

export type ReceiptRecordKind = "transaction" | "quota" | "run" | "nonce" | "issued" | "consumed" | "closed" | "cleanup";

export interface StoredReceiptRecord {
  readonly version: 3;
  readonly runId: string;
  readonly nonce: string;
  readonly receiptDigest: string;
  readonly quotaSlot: number;
  readonly transactionId: string;
  readonly receipt?: AlphaIntegrityReceipt;
  readonly consumedAt?: string;
  readonly closedAt?: string;
  readonly reasonCode?: string;
  readonly cleanupPaths?: readonly string[];
}

export interface ConsumedReceiptRecord {
  readonly receiptDigest: string;
  readonly runId: string;
  readonly nonce: string;
  readonly transactionId: string;
  readonly consumedAt: string;
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new Error(`invalid ${label}`);
  return value as Record<string, unknown>;
}

function exact(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) throw new Error(`invalid ${label}`);
}

function boundedString(value: unknown, maximum: number): value is string {
  return typeof value === "string" && value.length > 0 && Buffer.byteLength(value, "utf8") <= maximum;
}

function iso(value: unknown): value is string {
  return boundedString(value, 64) && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
}

export function parseAlphaIntegrityReceipt(value: unknown): AlphaIntegrityReceipt {
  const receipt = record(value, "embedded receipt");
  exact(receipt, ["audience", "createdAt", "engineVersion", "envelopeDigest", "expiresAt", "issuer", "nonce", "policyDigest", "protocolVersion", "purpose", "receiptDigest", "receiptVersion", "runId", "signature", "verification"], "embedded receipt");
  if (receipt.protocolVersion !== PROTOCOL_VERSION || receipt.receiptVersion !== "2-alpha") throw new Error("invalid embedded receipt");
  for (const field of ["engineVersion", "issuer", "audience", "purpose", "nonce"] as const)
    if (!boundedString(receipt[field], 256)) throw new Error("invalid embedded receipt");
  if (!boundedString(receipt.runId, 128) || !SAFE_IDENTIFIER.test(receipt.runId as string)) throw new Error("invalid embedded receipt");
  if (!iso(receipt.createdAt) || !iso(receipt.expiresAt) || !SHA256.test(String(receipt.policyDigest)) || !SHA256.test(String(receipt.envelopeDigest)) || !SHA256.test(String(receipt.receiptDigest))) throw new Error("invalid embedded receipt");
  const signature = record(receipt.signature, "receipt signature");
  exact(signature, ["algorithm", "keyId", "value"], "receipt signature");
  if (signature.algorithm !== "Ed25519" || !boundedString(signature.keyId, 256) || !/^[A-Za-z0-9+/]{86}==$/u.test(String(signature.value))) throw new Error("invalid receipt signature");
  const verification = record(receipt.verification, "receipt verification");
  exact(verification, ["findings", "protocolVersion", "status"], "receipt verification");
  if (verification.protocolVersion !== PROTOCOL_VERSION || !["PASS", "REVIEW", "BLOCKED"].includes(String(verification.status)) || !Array.isArray(verification.findings) || verification.findings.length > 10_000) throw new Error("invalid receipt verification");
  for (const findingValue of verification.findings) {
    const finding = record(findingValue, "receipt finding");
    exact(finding, finding.path === undefined ? ["code", "message", "severity"] : ["code", "message", "path", "severity"], "receipt finding");
    if (!boundedString(finding.code, 1024) || !boundedString(finding.message, 16 * 1024) || !["review", "blocked"].includes(String(finding.severity)) || (finding.path !== undefined && !boundedString(finding.path, 4096))) throw new Error("invalid receipt finding");
  }
  const typed = receipt as unknown as AlphaIntegrityReceipt;
  const { receiptDigest, ...signed } = typed;
  if (sha256Canonical(signed) !== receiptDigest) throw new Error("embedded receipt digest mismatch");
  return typed;
}

export function parseStoredReceiptRecord(value: unknown, kind: ReceiptRecordKind): StoredReceiptRecord {
  const stored = record(value, `${kind} receipt store record`);
  const base = ["nonce", "quotaSlot", "receiptDigest", "runId", "transactionId", "version"];
  const extra = kind === "issued" ? ["receipt"]
    : kind === "consumed" ? ["consumedAt", "receipt"]
      : kind === "closed" ? ["closedAt", "reasonCode", "receipt"]
        : kind === "cleanup" ? ["cleanupPaths"] : [];
  exact(stored, [...base, ...extra], `${kind} receipt store record`);
  if (stored.version !== 3 || !boundedString(stored.runId, 128) || !SAFE_IDENTIFIER.test(stored.runId as string) || !boundedString(stored.nonce, 256) || !SHA256.test(String(stored.receiptDigest)) || !Number.isSafeInteger(stored.quotaSlot) || (stored.quotaSlot as number) < -1 || !boundedString(stored.transactionId, 128) || !SAFE_IDENTIFIER.test(stored.transactionId as string)) throw new Error(`invalid ${kind} receipt store record`);
  if (kind === "issued" || kind === "consumed" || kind === "closed") {
    const receipt = parseAlphaIntegrityReceipt(stored.receipt);
    if (receipt.receiptDigest !== stored.receiptDigest || receipt.runId !== stored.runId || receipt.nonce !== stored.nonce) throw new Error(`${kind} receipt store binding mismatch`);
  }
  if (kind === "consumed" && !iso(stored.consumedAt)) throw new Error("invalid consumed receipt store record");
  if (kind === "closed" && (!iso(stored.closedAt) || typeof stored.reasonCode !== "string" || !REASON_CODE.test(stored.reasonCode))) throw new Error("invalid closed receipt store record");
  if (kind === "cleanup" && (!Array.isArray(stored.cleanupPaths) || stored.cleanupPaths.length > 16 || !stored.cleanupPaths.every((entry) => boundedString(entry, 4096)))) throw new Error("invalid cleanup receipt store record");
  return stored as unknown as StoredReceiptRecord;
}

export function freezeValidated<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) freezeValidated(child);
    Object.freeze(value);
  }
  return value;
}

export function consumedView(record: StoredReceiptRecord): ConsumedReceiptRecord {
  if (record.consumedAt === undefined) throw new Error("consumed receipt time is missing");
  return freezeValidated({ receiptDigest: record.receiptDigest, runId: record.runId, nonce: record.nonce, transactionId: record.transactionId, consumedAt: record.consumedAt });
}
