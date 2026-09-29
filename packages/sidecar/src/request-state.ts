import { canonicalJson, parseAlphaIntegrityReceipt } from "@agent-integrity/core";
import type { AlphaIntegrityReceipt, IntegrityResult } from "@agent-integrity/protocol";
import { SERVICE_ERROR_CODES, type ServiceResponse } from "./protocol.js";
import { createHash } from "node:crypto";

const SAFE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const DIGEST = /^[a-f0-9]{64}$/u;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;

interface RequestIdentity {
  readonly version: 1; readonly clientId: string; readonly storeGeneration: string;
  readonly idempotencyKeyHash: string; readonly requestDigest: string; readonly requestId: string;
  readonly transactionId: string; readonly requestObjectId: string;
}
interface VerificationFields {
  readonly snapshotId: string; readonly envelopeDigest: string;
  readonly verificationDigest: string; readonly verification: IntegrityResult;
}
interface PreparedFields {
  readonly signingTime: string; readonly trustSnapshotObjectId: string;
  readonly trustSnapshotDigest: string; readonly keyId: string; readonly publicKeyDigest: string;
  readonly runId: string; readonly receiptNonce: string; readonly createdAt: string; readonly expiresAt: string;
  readonly audience: string; readonly purpose: string; readonly engineVersion: string; readonly maxLifetimeMs: number;
  readonly receiptOutputName: string; readonly receiptOutputRootIdentity: string; readonly trustedContextDigest: string;
  readonly preparedResponse?: Readonly<{ bytes: string; sha256: string }>;
}
interface IssuedFields { readonly receiptDigest: string; readonly receipt: AlphaIntegrityReceipt }
export interface ReservedState extends RequestIdentity { readonly phase: "reserved" }
export interface VerifiedState extends RequestIdentity, VerificationFields { readonly phase: "verified" }
export interface ReceiptPreparedState extends RequestIdentity, VerificationFields, PreparedFields { readonly phase: "receipt-prepared" }
export interface ReceiptIssuedState extends RequestIdentity, VerificationFields, PreparedFields, IssuedFields {
  readonly phase: "receipt-issued"; readonly receiptDigest: string; readonly receipt: AlphaIntegrityReceipt;
}
export interface PassConsumedState extends RequestIdentity, VerificationFields, PreparedFields, IssuedFields {
  readonly phase: "pass-consumed"; readonly consumedMarkerDigest: string; readonly consumedAt: string;
}
export interface ReleaseRefusedState extends RequestIdentity, VerificationFields, PreparedFields, IssuedFields {
  readonly phase: "release-refused"; readonly closedMarkerDigest: string; readonly response: ServiceResponse;
}
export interface ResultCommittedState extends RequestIdentity {
  readonly phase: "result-committed"; readonly response: ServiceResponse; readonly outcome: "PASS" | "REVIEW" | "BLOCKED" | "RELEASE_REFUSED";
  readonly receiptExpiresAt: string; readonly deliveryDeadline: string; readonly responseBytesRetained: boolean;
}
export interface TombstoneState {
  readonly version: 1; readonly phase: "tombstone"; readonly clientId: string; readonly storeGeneration: string;
  readonly idempotencyKeyHash: string; readonly requestDigest: string; readonly requestId: string;
  readonly transactionId: string; readonly terminalOutcome: string; readonly expiredAt: string;
}
export type RequestState = ReservedState | VerifiedState | ReceiptPreparedState | ReceiptIssuedState | PassConsumedState | ReleaseRefusedState | ResultCommittedState | TombstoneState;
export type ActiveRequestState = Exclude<RequestState, TombstoneState>;

const COMMON = ["clientId", "idempotencyKeyHash", "phase", "requestDigest", "requestId", "requestObjectId", "storeGeneration", "transactionId", "version"];
const VERIFIED = ["envelopeDigest", "snapshotId", "verification", "verificationDigest"];
const PREPARED = ["audience", "createdAt", "engineVersion", "expiresAt", "keyId", "maxLifetimeMs", "publicKeyDigest", "purpose", "receiptNonce", "receiptOutputName", "receiptOutputRootIdentity", "runId", "signingTime", "trustSnapshotDigest", "trustSnapshotObjectId", "trustedContextDigest"];

function plain(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new Error(`${label} is invalid`);
  return value as Record<string, unknown>;
}
function exact(value: Record<string, unknown>, fields: readonly string[], label: string): void {
  const actual = Object.keys(value).sort(); const expected = [...fields].sort();
  if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index])) throw new Error(`${label} contains unknown or missing fields`);
}
function safe(value: unknown, label: string): asserts value is string { if (typeof value !== "string" || !SAFE.test(value)) throw new Error(`${label} is invalid`); }
function digest(value: unknown, label: string): asserts value is string { if (typeof value !== "string" || !DIGEST.test(value)) throw new Error(`${label} is invalid`); }
function iso(value: unknown, label: string): asserts value is string { if (typeof value !== "string" || !ISO.test(value) || new Date(value).toISOString() !== value) throw new Error(`${label} is invalid`); }
function verification(value: unknown): void {
  const result = plain(value, "verification"); exact(result, ["findings", "protocolVersion", "status"], "verification");
  if (result.protocolVersion !== "1-alpha" || !["PASS", "REVIEW", "BLOCKED"].includes(String(result.status)) || !Array.isArray(result.findings) || result.findings.length > 10_000) throw new Error("verification is invalid");
  for (const entry of result.findings) {
    const finding = plain(entry, "verification finding");
    exact(finding, finding.path === undefined ? ["code", "message", "severity"] : ["code", "message", "path", "severity"], "verification finding");
    if (typeof finding.code !== "string" || finding.code.length === 0 || Buffer.byteLength(finding.code, "utf8") > 1024 || typeof finding.message !== "string" || finding.message.length === 0 || Buffer.byteLength(finding.message, "utf8") > 16 * 1024 || !["review", "blocked"].includes(String(finding.severity)) || (finding.path !== undefined && (typeof finding.path !== "string" || finding.path.length === 0 || Buffer.byteLength(finding.path, "utf8") > 4096))) throw new Error("verification finding is invalid");
  }
}
function freeze<T>(value: T): T { if (value !== null && typeof value === "object" && !Object.isFrozen(value)) { for (const child of Object.values(value as Record<string, unknown>)) freeze(child); Object.freeze(value); } return value; }
function serviceResponse(value: unknown, requestId: string): void {
  const response = plain(value, "service response");
  if (response.serviceProtocolVersion !== "1") throw new Error("service response is invalid");
  if (Object.prototype.hasOwnProperty.call(response, "error")) {
    exact(response, response.requestId === undefined ? ["error", "serviceProtocolVersion"] : ["error", "requestId", "serviceProtocolVersion"], "service response");
    if (response.requestId !== undefined && response.requestId !== requestId) throw new Error("service response request ID mismatch");
    const error = plain(response.error, "service error"); exact(error, ["code", "retryable"], "service error");
    if (typeof error.code !== "string" || !(SERVICE_ERROR_CODES as readonly string[]).includes(error.code) || typeof error.retryable !== "boolean") throw new Error("service error is invalid");
    return;
  }
  if (response.requestId !== requestId || typeof response.status !== "string") throw new Error("service response request ID or status is invalid");
  if (response.status === "PASS") {
    exact(response, ["receipt", "releasedResponse", "requestId", "serviceProtocolVersion", "status", "verification"], "service response");
    verification(response.verification); const receipt = parseAlphaIntegrityReceipt(response.receipt);
    if ((response.verification as { status?: unknown }).status !== "PASS" || canonicalJson(response.verification) !== canonicalJson(receipt.verification)) throw new Error("PASS response verification is invalid");
    const released = plain(response.releasedResponse, "released response"); exact(released, ["bytes", "encoding", "sha256"], "released response");
    if (released.encoding !== "base64" || typeof released.bytes !== "string" || typeof released.sha256 !== "string" || !DIGEST.test(released.sha256)) throw new Error("released response is invalid");
    const bytes = Buffer.from(released.bytes, "base64");
    if (bytes.toString("base64") !== released.bytes || createHash("sha256").update(bytes).digest("hex") !== released.sha256) throw new Error("released response digest is invalid");
    return;
  }
  if (response.status === "REVIEW" || response.status === "BLOCKED") {
    exact(response, ["receipt", "requestId", "serviceProtocolVersion", "status", "verification"], "service response");
    verification(response.verification); const receipt = parseAlphaIntegrityReceipt(response.receipt);
    if ((response.verification as { status?: unknown }).status !== response.status || canonicalJson(response.verification) !== canonicalJson(receipt.verification)) throw new Error("refusal response verification is invalid");
    return;
  }
  if (response.status === "RELEASE_REFUSED") {
    exact(response, ["receipt", "release", "requestId", "serviceProtocolVersion", "status", "verification"], "service response");
    verification(response.verification); const receipt = parseAlphaIntegrityReceipt(response.receipt);
    if ((response.verification as { status?: unknown }).status !== "PASS" || canonicalJson(response.verification) !== canonicalJson(receipt.verification)) throw new Error("release-refused response verification is invalid");
    const release = plain(response.release, "release refusal"); exact(release, ["code", "retryable", "status"], "release refusal");
    if (!["REVIEW", "BLOCKED"].includes(String(release.status)) || release.code !== "RECEIPT_RECHECK_REFUSED" || release.retryable !== false) throw new Error("release refusal is invalid");
    return;
  }
  throw new Error("service response status is invalid");
}

export function parseRequestState(value: unknown): RequestState {
  const state = plain(value, "request state");
  if (state.version !== 1 || typeof state.phase !== "string") throw new Error("request state is invalid");
  let fields: string[];
  switch (state.phase) {
    case "reserved": fields = [...COMMON]; break;
    case "verified": fields = [...COMMON, ...VERIFIED]; break;
    case "receipt-prepared": fields = [...COMMON, ...VERIFIED, ...PREPARED, ...(state.preparedResponse === undefined ? [] : ["preparedResponse"])]; break;
    case "receipt-issued": fields = [...COMMON, ...VERIFIED, ...PREPARED, ...(state.preparedResponse === undefined ? [] : ["preparedResponse"]), "receipt", "receiptDigest"]; break;
    case "pass-consumed": fields = [...COMMON, ...VERIFIED, ...PREPARED, ...(state.preparedResponse === undefined ? [] : ["preparedResponse"]), "consumedAt", "consumedMarkerDigest", "receipt", "receiptDigest"]; break;
    case "release-refused": fields = [...COMMON, ...VERIFIED, ...PREPARED, ...(state.preparedResponse === undefined ? [] : ["preparedResponse"]), "closedMarkerDigest", "receipt", "receiptDigest", "response"]; break;
    case "result-committed": fields = [...COMMON, "deliveryDeadline", "outcome", "receiptExpiresAt", "response", "responseBytesRetained"]; break;
    case "tombstone": fields = ["clientId", "expiredAt", "idempotencyKeyHash", "phase", "requestDigest", "requestId", "storeGeneration", "terminalOutcome", "transactionId", "version"]; break;
    default: throw new Error("request state phase is invalid");
  }
  exact(state, fields, "request state");
  for (const field of ["clientId", "storeGeneration", "requestId", "transactionId"] as const) safe(state[field], field);
  digest(state.idempotencyKeyHash, "idempotencyKeyHash"); digest(state.requestDigest, "requestDigest");
  if (state.phase === "tombstone") { safe(state.terminalOutcome, "terminalOutcome"); iso(state.expiredAt, "expiredAt"); return freeze(structuredClone(state) as unknown as TombstoneState); }
  digest(state.requestObjectId, "requestObjectId");
  if (["verified", "receipt-prepared", "receipt-issued", "pass-consumed", "release-refused"].includes(state.phase)) {
    digest(state.snapshotId, "snapshotId"); digest(state.envelopeDigest, "envelopeDigest"); digest(state.verificationDigest, "verificationDigest"); verification(state.verification);
  }
  if (["receipt-prepared", "receipt-issued", "pass-consumed", "release-refused"].includes(state.phase)) {
    for (const field of ["signingTime", "createdAt", "expiresAt"] as const) iso(state[field], field);
    for (const field of ["trustSnapshotObjectId", "trustSnapshotDigest", "publicKeyDigest", "receiptOutputRootIdentity", "trustedContextDigest"] as const) digest(state[field], field);
    for (const field of ["keyId", "runId", "receiptNonce", "audience", "purpose", "engineVersion", "receiptOutputName"] as const) safe(state[field], field);
    if (!Number.isSafeInteger(state.maxLifetimeMs) || (state.maxLifetimeMs as number) < 1) throw new Error("maxLifetimeMs is invalid");
    if (state.preparedResponse !== undefined) { const prepared = plain(state.preparedResponse, "preparedResponse"); exact(prepared, ["bytes", "sha256"], "preparedResponse"); if (typeof prepared.bytes !== "string") throw new Error("preparedResponse is invalid"); digest(prepared.sha256, "preparedResponse.sha256"); }
  }
  if (["receipt-issued", "pass-consumed", "release-refused"].includes(state.phase)) { digest(state.receiptDigest, "receiptDigest"); const receipt = parseAlphaIntegrityReceipt(state.receipt); if (receipt.receiptDigest !== state.receiptDigest) throw new Error("receipt digest binding is invalid"); }
  if (state.phase === "pass-consumed") { digest(state.consumedMarkerDigest, "consumedMarkerDigest"); iso(state.consumedAt, "consumedAt"); }
  if (state.phase === "release-refused") { digest(state.closedMarkerDigest, "closedMarkerDigest"); serviceResponse(state.response, state.requestId as string); if ((state.response as { status?: unknown }).status !== "RELEASE_REFUSED") throw new Error("release-refused phase response is invalid"); }
  if (state.phase === "result-committed") { if (!["PASS", "REVIEW", "BLOCKED", "RELEASE_REFUSED"].includes(String(state.outcome))) throw new Error("outcome is invalid"); iso(state.receiptExpiresAt, "receiptExpiresAt"); iso(state.deliveryDeadline, "deliveryDeadline"); if (typeof state.responseBytesRetained !== "boolean") throw new Error("responseBytesRetained is invalid"); serviceResponse(state.response, state.requestId as string); const responseStatus = (state.response as { status?: unknown }).status; if (responseStatus !== undefined && responseStatus !== state.outcome) throw new Error("terminal response outcome mismatch"); }
  return freeze(structuredClone(state) as unknown as RequestState);
}

export function requestStateDigest(state: RequestState): string { return createHash("sha256").update(canonicalJson(parseRequestState(state)), "utf8").digest("hex"); }

export function assertTransition(previous: ActiveRequestState, next: ActiveRequestState): void {
  const allowed: Readonly<Record<string, readonly string[]>> = {
    reserved: ["verified"], verified: ["receipt-prepared"], "receipt-prepared": ["receipt-issued"],
    "receipt-issued": previous.phase === "receipt-issued" && previous.verification.status === "PASS" ? ["pass-consumed", "release-refused"] : ["result-committed"],
    "pass-consumed": ["result-committed"], "release-refused": ["result-committed"], "result-committed": [],
  };
  if (!allowed[previous.phase]?.includes(next.phase)) throw new Error(`invalid request-state transition: ${previous.phase} -> ${next.phase}`);
  for (const field of ["clientId", "storeGeneration", "idempotencyKeyHash", "requestDigest", "requestId", "transactionId", "requestObjectId"] as const)
    if (previous[field] !== next[field]) throw new Error(`request-state owner changed: ${field}`);
}
