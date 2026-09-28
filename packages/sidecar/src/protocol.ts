import { createHash } from "node:crypto";
import { assertIntegrityEnvelope, calculateOutcome, canonicalJson, sha256Canonical } from "@agent-integrity/core";
import type { AlphaIntegrityReceipt, IntegrityEnvelope, IntegrityResult } from "@agent-integrity/protocol";

export const SIDECAR_PROTOCOL_VERSION = "1" as const;

export interface ServiceRequest {
  serviceProtocolVersion: "1";
  requestId: string;
  idempotencyKey: string;
  bundleId: string;
  envelope: IntegrityEnvelope;
}

type DeepReadonly<T> = T extends (...args: never[]) => unknown
  ? T
  : T extends readonly (infer Entry)[]
    ? readonly DeepReadonly<Entry>[]
    : T extends object
      ? { readonly [Key in keyof T]: DeepReadonly<T[Key]> }
      : T;

declare const PARSED_SERVICE_REQUEST: unique symbol;

export type ParsedServiceRequest = DeepReadonly<ServiceRequest> & {
  readonly [PARSED_SERVICE_REQUEST]: true;
};

export interface PassResponse {
  readonly serviceProtocolVersion: "1";
  readonly requestId: string;
  readonly status: "PASS";
  readonly verification: IntegrityResult & { readonly status: "PASS" };
  readonly receipt: AlphaIntegrityReceipt;
  readonly releasedResponse: Readonly<{ readonly encoding: "base64"; readonly sha256: string; readonly bytes: string }>;
}

export interface RefusalResponse {
  readonly serviceProtocolVersion: "1";
  readonly requestId: string;
  readonly status: "REVIEW" | "BLOCKED";
  readonly verification: IntegrityResult;
  readonly receipt: AlphaIntegrityReceipt;
}

export interface ReleaseRefusedResponse {
  readonly serviceProtocolVersion: "1";
  readonly requestId: string;
  readonly status: "RELEASE_REFUSED";
  readonly verification: IntegrityResult & { readonly status: "PASS" };
  readonly receipt: AlphaIntegrityReceipt;
  readonly release: Readonly<{
    readonly status: "REVIEW" | "BLOCKED";
    readonly code: "RECEIPT_RECHECK_REFUSED";
    readonly retryable: false;
  }>;
}

export const SERVICE_ERROR_CODES = [
  "INVALID_REQUEST", "UNSUPPORTED_PROTOCOL", "AUTHENTICATION_FAILED", "REPLAY_DETECTED",
  "BUNDLE_UNAVAILABLE", "BUNDLE_INVALID", "IDEMPOTENCY_CONFLICT", "PAYLOAD_TOO_LARGE",
  "RESOURCE_LIMIT", "RESULT_EXPIRED", "STORAGE_UNAVAILABLE", "SIGNING_UNAVAILABLE",
  "VERIFIER_FAILURE", "SERVICE_UNAVAILABLE", "INTERNAL_FAILURE",
] as const;

export type ServiceErrorCode = typeof SERVICE_ERROR_CODES[number];

export interface TechnicalErrorResponse {
  readonly serviceProtocolVersion: "1";
  readonly requestId?: string;
  readonly error: Readonly<{ readonly code: ServiceErrorCode; readonly retryable: boolean }>;
}

export type ServiceResponse = PassResponse | RefusalResponse | ReleaseRefusedResponse | TechnicalErrorResponse;
export type ParsedServiceResponse = DeepReadonly<ServiceResponse>;

export interface ResponseLimits {
  readonly request: ParsedServiceRequest;
  readonly maxBodyBytes: number;
  readonly maxFindings: number;
  readonly maxFindingBytes: number;
  readonly maxReleasedResponseBytes: number;
}

const REQUEST_KEYS = [
  "serviceProtocolVersion",
  "requestId",
  "idempotencyKey",
  "bundleId",
  "envelope",
] as const;
const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const MAX_JSON_DEPTH = 65;
const MAX_JSON_NODES = 100_000;
const MAX_CANONICAL_ENVELOPE_BYTES = 16 * 1024 * 1024;
const admittedRequestDigests = new WeakMap<object, string>();

class DuplicateKeyScanner {
  private index = 0;
  private nodes = 0;

  constructor(private readonly text: string) {}

  scan(): void {
    this.whitespace();
    this.value(0);
    this.whitespace();
    if (this.index !== this.text.length) throw new SyntaxError("invalid JSON after root value");
  }

  private value(depth: number): void {
    if (depth > MAX_JSON_DEPTH) throw new SyntaxError("maximum JSON depth exceeded");
    this.nodes += 1;
    if (this.nodes > MAX_JSON_NODES) throw new SyntaxError("maximum JSON node count exceeded");
    const token = this.text[this.index];
    if (token === "{") return this.object(depth + 1);
    if (token === "[") return this.array(depth + 1);
    if (token === '"') return void this.string();
    if (token === "t") return this.literal("true");
    if (token === "f") return this.literal("false");
    if (token === "n") return this.literal("null");
    if (token === "-" || (token !== undefined && token >= "0" && token <= "9")) return this.number();
    throw new SyntaxError(`invalid JSON token at code-unit offset ${this.index}`);
  }

  private object(depth: number): void {
    this.index += 1;
    this.whitespace();
    const keys = new Set<string>();
    if (this.text[this.index] === "}") {
      this.index += 1;
      return;
    }
    while (true) {
      if (this.text[this.index] !== '"') throw new SyntaxError(`invalid JSON object key at code-unit offset ${this.index}`);
      const key = this.string();
      if (keys.has(key)) throw new SyntaxError("duplicate JSON key");
      keys.add(key);
      this.whitespace();
      if (this.text[this.index] !== ":") throw new SyntaxError(`missing JSON colon at code-unit offset ${this.index}`);
      this.index += 1;
      this.whitespace();
      this.value(depth);
      this.whitespace();
      const next = this.text[this.index];
      if (next === "}") {
        this.index += 1;
        return;
      }
      if (next !== ",") throw new SyntaxError(`invalid JSON object separator at code-unit offset ${this.index}`);
      this.index += 1;
      this.whitespace();
    }
  }

  private array(depth: number): void {
    this.index += 1;
    this.whitespace();
    if (this.text[this.index] === "]") {
      this.index += 1;
      return;
    }
    while (true) {
      this.value(depth);
      this.whitespace();
      const next = this.text[this.index];
      if (next === "]") {
        this.index += 1;
        return;
      }
      if (next !== ",") throw new SyntaxError(`invalid JSON array separator at code-unit offset ${this.index}`);
      this.index += 1;
      this.whitespace();
    }
  }

  private string(): string {
    const start = this.index;
    this.index += 1;
    while (this.index < this.text.length) {
      const character = this.text[this.index];
      if (character === '"') {
        this.index += 1;
        return JSON.parse(this.text.slice(start, this.index)) as string;
      }
      if (character === "\\") {
        this.index += 1;
        const escape = this.text[this.index];
        if (escape === "u") {
          const digits = this.text.slice(this.index + 1, this.index + 5);
          if (!/^[0-9a-fA-F]{4}$/u.test(digits)) throw new SyntaxError(`invalid JSON Unicode escape at code-unit offset ${this.index}`);
          this.index += 5;
          continue;
        }
        if (escape === undefined || !'"\\/bfnrt'.includes(escape)) {
          throw new SyntaxError(`invalid JSON escape at code-unit offset ${this.index}`);
        }
        this.index += 1;
        continue;
      }
      if (character === undefined || character.charCodeAt(0) <= 0x1f) {
        throw new SyntaxError(`invalid JSON string at code-unit offset ${this.index}`);
      }
      this.index += 1;
    }
    throw new SyntaxError("unterminated JSON string");
  }

  private literal(expected: string): void {
    if (!this.text.startsWith(expected, this.index)) throw new SyntaxError(`invalid JSON literal at code-unit offset ${this.index}`);
    this.index += expected.length;
  }

  private number(): void {
    const remaining = this.text.slice(this.index);
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(remaining);
    if (!match) throw new SyntaxError(`invalid JSON number at code-unit offset ${this.index}`);
    if (!Number.isFinite(Number(match[0]))) throw new TypeError("Non-finite JSON number is forbidden");
    this.index += match[0].length;
  }

  private whitespace(): void {
    while (this.text[this.index] === " " || this.text[this.index] === "\t" ||
           this.text[this.index] === "\n" || this.text[this.index] === "\r") {
      this.index += 1;
    }
  }
}

function plainRecord(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError("service request must be a plain object");
  }
  return value as Record<string, unknown>;
}

function requireExactKeys(value: Record<string, unknown>): void {
  const expected = [...REQUEST_KEYS].sort();
  const actual = Object.keys(value).sort();
  const unknown = actual.filter((key) => !expected.includes(key as typeof REQUEST_KEYS[number]));
  if (unknown.length > 0) throw new TypeError("service request contains unknown keys");
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new TypeError(`service request must contain exactly: ${expected.join(", ")}`);
  }
}

function requireIdentifier(value: unknown, name: string): asserts value is string {
  if (typeof value !== "string" || !SAFE_IDENTIFIER.test(value)) {
    throw new TypeError(`${name} must match ${SAFE_IDENTIFIER.source}`);
  }
}

function rejectLoneSurrogates(root: unknown): void {
  const pending: unknown[] = [root];
  let nodes = 0;
  while (pending.length > 0) {
    const value = pending.pop();
    nodes += 1;
    if (nodes > MAX_JSON_NODES) throw new SyntaxError("maximum JSON node count exceeded");
    if (typeof value === "string") {
      for (let index = 0; index < value.length; index += 1) {
        const code = value.charCodeAt(index);
        if (code >= 0xd800 && code <= 0xdbff) {
          const next = value.charCodeAt(index + 1);
          if (!(next >= 0xdc00 && next <= 0xdfff)) throw new TypeError("lone UTF-16 surrogate is forbidden");
          index += 1;
        } else if (code >= 0xdc00 && code <= 0xdfff) {
          throw new TypeError("lone UTF-16 surrogate is forbidden");
        }
      }
      continue;
    }
    if (Array.isArray(value)) {
      for (let index = value.length - 1; index >= 0; index -= 1) pending.push(value[index]);
      continue;
    }
    if (value !== null && typeof value === "object") {
      for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
        for (let index = 0; index < key.length; index += 1) {
          const code = key.charCodeAt(index);
          if (code >= 0xd800 && code <= 0xdbff) {
            const next = key.charCodeAt(index + 1);
            if (!(next >= 0xdc00 && next <= 0xdfff)) throw new TypeError("lone UTF-16 surrogate is forbidden");
            index += 1;
          } else if (code >= 0xdc00 && code <= 0xdfff) {
            throw new TypeError("lone UTF-16 surrogate is forbidden");
          }
        }
        pending.push(entry);
      }
    }
  }
}

function deepFreeze<T>(root: T): T {
  const pending: object[] = [];
  if (root !== null && typeof root === "object") pending.push(root);
  while (pending.length > 0) {
    const value = pending.pop()!;
    for (const entry of Object.values(value)) {
      if (entry !== null && typeof entry === "object" && !Object.isFrozen(entry)) pending.push(entry);
    }
    Object.freeze(value);
  }
  return root;
}

export function parseCanonicalServiceRequest(raw: Uint8Array, maxBytes: number): ParsedServiceRequest {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) throw new TypeError("maximum body bytes must be a positive safe integer");
  if (raw.byteLength > maxBytes) throw new TypeError("request body exceeds maximum body bytes");

  const acceptedBytes = Uint8Array.from(raw);

  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(acceptedBytes);
  } catch {
    throw new TypeError("request body must contain valid UTF-8");
  }
  new DuplicateKeyScanner(text).scan();

  const parsed: unknown = JSON.parse(text);
  rejectLoneSurrogates(parsed);
  if (canonicalJson(parsed) !== text) throw new TypeError("request body must use canonical JSON encoding");

  const request = plainRecord(parsed);
  requireExactKeys(request);
  if (request.serviceProtocolVersion !== SIDECAR_PROTOCOL_VERSION) throw new TypeError("unsupported service protocol version");
  requireIdentifier(request.requestId, "requestId");
  requireIdentifier(request.idempotencyKey, "idempotencyKey");
  requireIdentifier(request.bundleId, "bundleId");
  if (Buffer.byteLength(canonicalJson(request.envelope), "utf8") > MAX_CANONICAL_ENVELOPE_BYTES) {
    throw new TypeError("canonical envelope exceeds maximum envelope bytes");
  }
  assertIntegrityEnvelope(request.envelope);

  const parsedRequest = deepFreeze(request as unknown as ServiceRequest) as ParsedServiceRequest;
  admittedRequestDigests.set(parsedRequest, createHash("sha256").update(acceptedBytes).digest("hex"));
  return parsedRequest;
}

export function serviceRequestDigest(request: ParsedServiceRequest): string {
  const digest = admittedRequestDigests.get(request);
  if (digest === undefined) throw new TypeError("service request is not an admitted request identity");
  return digest;
}

const SHA256 = /^[a-f0-9]{64}$/u;
const RECEIPT_SIGNATURE = /^[A-Za-z0-9+/]{86}==$/u;
const SERVICE_ERROR_CODE_SET = new Set<string>(SERVICE_ERROR_CODES);

function exactObject(value: unknown, required: readonly string[], label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError(`${label} must be a plain object`);
  }
  const record = value as Record<string, unknown>;
  const actual = Object.keys(record).sort();
  const expected = [...required].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new TypeError(`${label} must contain exactly the required fields`);
  }
  return record;
}

function boundedString(value: unknown, label: string, maximumBytes: number, allowEmpty = false): string {
  if (typeof value !== "string" || (!allowEmpty && value.length === 0) || Buffer.byteLength(value, "utf8") > maximumBytes) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

function assertSha256(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || !SHA256.test(value)) throw new TypeError(`${label} is invalid`);
}

function validateFinding(value: unknown, limits: ResponseLimits): void {
  if (Buffer.byteLength(canonicalJson(value), "utf8") > limits.maxFindingBytes) throw new TypeError("finding exceeds configured limit");
  const candidate = value as Record<string, unknown> | null;
  const hasPath = candidate !== null && typeof candidate === "object" && !Array.isArray(candidate) && Object.prototype.hasOwnProperty.call(candidate, "path");
  const finding = exactObject(value, hasPath ? ["code", "severity", "message", "path"] : ["code", "severity", "message"], "finding");
  boundedString(finding.code, "finding code", limits.maxFindingBytes);
  boundedString(finding.message, "finding message", limits.maxFindingBytes);
  if (finding.severity !== "review" && finding.severity !== "blocked") throw new TypeError("finding severity is invalid");
  if (hasPath) boundedString(finding.path, "finding path", limits.maxFindingBytes, true);
}

function validateVerification(value: unknown, limits: ResponseLimits): IntegrityResult {
  const verification = exactObject(value, ["protocolVersion", "status", "findings"], "verification");
  if (verification.protocolVersion !== "1-alpha") throw new TypeError("verification protocol version is invalid");
  if (verification.status !== "PASS" && verification.status !== "REVIEW" && verification.status !== "BLOCKED") throw new TypeError("verification status is invalid");
  if (!Array.isArray(verification.findings) || verification.findings.length > limits.maxFindings) throw new TypeError("verification findings exceed configured limit");
  for (const finding of verification.findings) validateFinding(finding, limits);
  if (calculateOutcome(verification.findings as unknown as IntegrityResult["findings"]).status !== verification.status) throw new TypeError("verification status is inconsistent with findings");
  return verification as unknown as IntegrityResult;
}

function validateTimestamp(value: unknown, label: string): number {
  const timestamp = boundedString(value, label, 64);
  if (!/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/u.test(timestamp)) throw new TypeError(`${label} is invalid`);
  const milliseconds = Date.parse(timestamp);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== timestamp) throw new TypeError(`${label} is invalid`);
  return milliseconds;
}

function validateReceipt(value: unknown, limits: ResponseLimits): AlphaIntegrityReceipt {
  const receipt = exactObject(value, [
    "protocolVersion", "receiptVersion", "engineVersion", "issuer", "audience", "purpose",
    "nonce", "runId", "createdAt", "expiresAt", "policyDigest", "envelopeDigest",
    "verification", "signature", "receiptDigest",
  ], "receipt");
  if (receipt.protocolVersion !== "1-alpha" || receipt.receiptVersion !== "2-alpha") throw new TypeError("receipt version is invalid");
  for (const field of ["engineVersion", "issuer", "audience", "purpose", "nonce"] as const) boundedString(receipt[field], `receipt ${field}`, 256);
  if (typeof receipt.runId !== "string" || !SAFE_IDENTIFIER.test(receipt.runId)) throw new TypeError("receipt runId is invalid");
  const createdAt = validateTimestamp(receipt.createdAt, "receipt createdAt");
  const expiresAt = validateTimestamp(receipt.expiresAt, "receipt expiresAt");
  if (expiresAt <= createdAt) throw new TypeError("receipt validity interval is invalid");
  assertSha256(receipt.policyDigest, "receipt policyDigest");
  assertSha256(receipt.envelopeDigest, "receipt envelopeDigest");
  assertSha256(receipt.receiptDigest, "receipt receiptDigest");
  validateVerification(receipt.verification, limits);
  const signature = exactObject(receipt.signature, ["algorithm", "keyId", "value"], "receipt signature");
  if (signature.algorithm !== "Ed25519") throw new TypeError("receipt signature algorithm is invalid");
  boundedString(signature.keyId, "receipt signature keyId", 256);
  if (typeof signature.value !== "string" || !RECEIPT_SIGNATURE.test(signature.value)) throw new TypeError("receipt signature value is invalid");
  const decoded = Buffer.from(signature.value, "base64");
  if (decoded.byteLength !== 64 || decoded.toString("base64") !== signature.value) throw new TypeError("receipt signature value is invalid");
  const { receiptDigest: _receiptDigest, ...receiptBody } = receipt;
  if (sha256Canonical(receiptBody) !== receipt.receiptDigest) throw new TypeError("receipt digest does not match receipt body");
  return receipt as unknown as AlphaIntegrityReceipt;
}

function validateLimits(limits: ResponseLimits): void {
  serviceRequestDigest(limits.request);
  const integers = [limits.maxBodyBytes, limits.maxFindings, limits.maxFindingBytes, limits.maxReleasedResponseBytes];
  if (!integers.every((value) => Number.isSafeInteger(value) && value > 0)) throw new TypeError("response limits are invalid");
  if (limits.maxBodyBytes > 32 * 1024 * 1024 || limits.maxFindings > 10_000 || limits.maxFindingBytes > 1024 * 1024 || limits.maxReleasedResponseBytes > 16 * 1024 * 1024) {
    throw new TypeError("response limits exceed hard ceilings");
  }
}

function validateRequestId(value: unknown, limits: ResponseLimits): void {
  if (typeof value !== "string" || !SAFE_IDENTIFIER.test(value) || value !== limits.request.requestId) throw new TypeError("service response requestId is invalid");
}

function validateReceiptBindings(wrapper: Record<string, unknown>, limits: ResponseLimits, status: "PASS" | "REVIEW" | "BLOCKED" | "RELEASE_REFUSED"): void {
  const verification = validateVerification(wrapper.verification, limits);
  const receipt = validateReceipt(wrapper.receipt, limits);
  if (canonicalJson(verification) !== canonicalJson(receipt.verification)) throw new TypeError("service response verification does not match signed receipt verification");
  if (receipt.envelopeDigest !== sha256Canonical(limits.request.envelope)) throw new TypeError("service response receipt envelope digest does not match request");
  if (status === "RELEASE_REFUSED") {
    if (verification.status !== "PASS" || receipt.verification.status !== "PASS") throw new TypeError("release-refused response must preserve a PASS receipt");
  } else if (verification.status !== status || receipt.verification.status !== status) {
    throw new TypeError("service response status does not match verification");
  }
}

function validateReleasedResponse(value: unknown, limits: ResponseLimits): void {
  const released = exactObject(value, ["encoding", "sha256", "bytes"], "released response");
  if (released.encoding !== "base64" || typeof released.bytes !== "string") throw new TypeError("released response encoding is invalid");
  assertSha256(released.sha256, "released response digest");
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(released.bytes)) throw new TypeError("released response bytes are not canonical base64");
  const decoded = Buffer.from(released.bytes, "base64");
  if (decoded.byteLength > limits.maxReleasedResponseBytes || decoded.toString("base64") !== released.bytes) throw new TypeError("released response exceeds configured limit or is noncanonical");
  if (createHash("sha256").update(decoded).digest("hex") !== released.sha256) throw new TypeError("released response digest mismatch");
  if (!decoded.equals(Buffer.from(limits.request.envelope.response.content, "utf8"))) throw new TypeError("released response bytes do not match admitted request");
}

function validateTechnicalError(value: Record<string, unknown>, limits: ResponseLimits): TechnicalErrorResponse {
  const hasRequestId = Object.prototype.hasOwnProperty.call(value, "requestId");
  const response = exactObject(value, hasRequestId ? ["serviceProtocolVersion", "requestId", "error"] : ["serviceProtocolVersion", "error"], "technical error response");
  if (response.serviceProtocolVersion !== SIDECAR_PROTOCOL_VERSION) throw new TypeError("unsupported service response protocol version");
  if (hasRequestId) validateRequestId(response.requestId, limits);
  const error = exactObject(response.error, ["code", "retryable"], "technical error");
  if (typeof error.code !== "string" || !SERVICE_ERROR_CODE_SET.has(error.code) || typeof error.retryable !== "boolean") throw new TypeError("technical error code or retryability is invalid");
  return response as unknown as TechnicalErrorResponse;
}

function validateServiceResponse(value: unknown, limits: ResponseLimits): ServiceResponse {
  const root = plainRecord(value);
  if (Object.prototype.hasOwnProperty.call(root, "error")) return validateTechnicalError(root, limits);
  if (root.serviceProtocolVersion !== SIDECAR_PROTOCOL_VERSION) throw new TypeError("unsupported service response protocol version");
  validateRequestId(root.requestId, limits);
  if (root.status === "PASS") {
    const response = exactObject(root, ["serviceProtocolVersion", "requestId", "status", "verification", "receipt", "releasedResponse"], "PASS response");
    validateReceiptBindings(response, limits, "PASS");
    validateReleasedResponse(response.releasedResponse, limits);
    return response as unknown as PassResponse;
  }
  if (root.status === "REVIEW" || root.status === "BLOCKED") {
    const response = exactObject(root, ["serviceProtocolVersion", "requestId", "status", "verification", "receipt"], "refusal response");
    validateReceiptBindings(response, limits, root.status);
    return response as unknown as RefusalResponse;
  }
  if (root.status === "RELEASE_REFUSED") {
    const response = exactObject(root, ["serviceProtocolVersion", "requestId", "status", "verification", "receipt", "release"], "release-refused response");
    validateReceiptBindings(response, limits, "RELEASE_REFUSED");
    const release = exactObject(response.release, ["status", "code", "retryable"], "release refusal");
    if ((release.status !== "REVIEW" && release.status !== "BLOCKED") || release.code !== "RECEIPT_RECHECK_REFUSED" || release.retryable !== false) throw new TypeError("release refusal is invalid");
    return response as unknown as ReleaseRefusedResponse;
  }
  throw new TypeError("service response status is invalid");
}

export function parseCanonicalServiceResponse(raw: Uint8Array, limits: ResponseLimits): ParsedServiceResponse {
  validateLimits(limits);
  if (raw.byteLength > limits.maxBodyBytes) throw new TypeError("service response exceeds maximum body bytes");
  const acceptedBytes = Uint8Array.from(raw);
  let text: string;
  try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(acceptedBytes); }
  catch { throw new TypeError("service response must contain valid UTF-8"); }
  new DuplicateKeyScanner(text).scan();
  const parsed: unknown = JSON.parse(text);
  rejectLoneSurrogates(parsed);
  if (canonicalJson(parsed) !== text) throw new TypeError("service response must use canonical JSON encoding");
  return deepFreeze(validateServiceResponse(parsed, limits)) as ParsedServiceResponse;
}

export function serializeCanonicalServiceResponse(response: ServiceResponse, limits: ResponseLimits): Uint8Array {
  const bytes = Buffer.from(canonicalJson(response), "utf8");
  const parsed = parseCanonicalServiceResponse(bytes, limits);
  return Buffer.from(canonicalJson(parsed), "utf8");
}
