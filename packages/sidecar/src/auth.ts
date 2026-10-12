import { createHmac, timingSafeEqual } from "node:crypto";
import { serviceRequestDigest, type ParsedServiceRequest } from "./protocol.js";

const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const TIMESTAMP = /^[0-9]{13}$/u;
const DIGEST = /^[a-f0-9]{64}$/u;
const MAC = /^[A-Za-z0-9_-]{43}$/u;
const DOMAIN = Buffer.from("agent-integrity-sidecar-auth-v1", "ascii");

export interface AuthHeaders {
  readonly clientId: string;
  readonly keyId: string;
  readonly timestampMs: string;
  readonly nonce: string;
  readonly mac: string;
}
export interface HmacKeyRecord {
  readonly secret: Uint8Array;
  readonly validFromMs: number;
  readonly validUntilMs: number;
  readonly revokedAtMs?: number;
}
export interface HmacRegistry {
  readonly clients: Readonly<Record<string, { readonly keys: Readonly<Record<string, HmacKeyRecord>> }>>;
}
export interface AuthenticateRequestOptions {
  readonly request: ParsedServiceRequest;
  readonly method: string;
  readonly path: string;
  readonly headers: AuthHeaders;
  readonly nowMs: number;
  readonly maximumSkewMs: number;
  readonly registry: HmacRegistry;
}
export interface AuthenticatedRequest {
  readonly request: ParsedServiceRequest;
  readonly clientId: string;
  readonly keyId: string;
  readonly timestampMs: number;
  readonly nonce: string;
  readonly bodyDigest: string;
}

function dataRecord(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new TypeError(`${label} is invalid`);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).some((key) => typeof key !== "string") || Object.values(descriptors).some((descriptor) => descriptor.get !== undefined || descriptor.set !== undefined || descriptor.enumerable !== true || !("value" in descriptor))) throw new TypeError(`${label} is invalid`);
  return Object.fromEntries(Object.entries(descriptors).map(([key, descriptor]) => [key, descriptor.value]));
}
function exactKeys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) throw new TypeError(`${label} is invalid`);
}
function snapshotRegistry(input: HmacRegistry): HmacRegistry {
  try {
    const root = dataRecord(input, "HMAC registry");
    exactKeys(root, ["clients"], "HMAC registry");
    const clientsInput = dataRecord(root.clients, "HMAC registry");
    const clients = Object.create(null) as Record<string, { keys: Record<string, HmacKeyRecord> }>;
    for (const [clientId, rawClient] of Object.entries(clientsInput)) {
      if (!SAFE_IDENTIFIER.test(clientId)) throw new TypeError("HMAC registry is invalid");
      const client = dataRecord(rawClient, "HMAC registry");
      exactKeys(client, ["keys"], "HMAC registry");
      const keyInputs = dataRecord(client.keys, "HMAC registry");
      const keys = Object.create(null) as Record<string, HmacKeyRecord>;
      for (const [keyId, rawKey] of Object.entries(keyInputs)) {
        if (!SAFE_IDENTIFIER.test(keyId)) throw new TypeError("HMAC registry is invalid");
        const key = dataRecord(rawKey, "HMAC registry");
        const allowed = key.revokedAtMs === undefined ? ["secret", "validFromMs", "validUntilMs"] : ["secret", "validFromMs", "validUntilMs", "revokedAtMs"];
        exactKeys(key, allowed, "HMAC registry");
        if (!(key.secret instanceof Uint8Array) || key.secret.byteLength < 32 || key.secret.byteLength > 1024 || !Number.isSafeInteger(key.validFromMs) || !Number.isSafeInteger(key.validUntilMs) || (key.validFromMs as number) > (key.validUntilMs as number) || (key.revokedAtMs !== undefined && !Number.isSafeInteger(key.revokedAtMs))) throw new TypeError("HMAC registry is invalid");
        keys[keyId] = Object.freeze({ secret: Uint8Array.from(key.secret), validFromMs: key.validFromMs as number, validUntilMs: key.validUntilMs as number, ...(key.revokedAtMs === undefined ? {} : { revokedAtMs: key.revokedAtMs as number }) });
      }
      clients[clientId] = Object.freeze({ keys: Object.freeze(keys) });
    }
    return Object.freeze({ clients: Object.freeze(clients) });
  } catch (error) {
    if (error instanceof TypeError && /HMAC registry/u.test(error.message)) throw error;
    throw new TypeError("HMAC registry is invalid", { cause: error });
  }
}
function encode(fields: readonly string[]): Buffer {
  const parts: Buffer[] = [DOMAIN];
  for (const field of fields) {
    const bytes = Buffer.from(field, "utf8");
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.byteLength);
    parts.push(length, bytes);
  }
  return Buffer.concat(parts);
}
function fail(message = "request authentication failed"): never { throw new Error(message); }

export function authenticateRequest(options: AuthenticateRequestOptions): AuthenticatedRequest {
  const captured = dataRecord(options, "authentication options");
  exactKeys(captured, ["headers", "maximumSkewMs", "method", "nowMs", "path", "registry", "request"], "authentication options");
  const rawHeaders = dataRecord(captured.headers, "authentication headers");
  exactKeys(rawHeaders, ["clientId", "keyId", "mac", "nonce", "timestampMs"], "authentication headers");
  if (!Object.values(rawHeaders).every((value) => typeof value === "string")) throw new TypeError("authentication headers are invalid");
  const headers = Object.freeze({ ...(rawHeaders as unknown as AuthHeaders) });
  const request = captured.request as ParsedServiceRequest;
  const method = captured.method;
  const path = captured.path;
  const nowMs = captured.nowMs;
  const maximumSkewMs = captured.maximumSkewMs;
  if (typeof method !== "string" || method.length < 1 || Buffer.byteLength(method, "utf8") > 32 || typeof path !== "string" || path.length < 1 || Buffer.byteLength(path, "utf8") > 2048) throw new TypeError("authentication target is invalid");
  const registry = snapshotRegistry(captured.registry as HmacRegistry);
  if (!Number.isSafeInteger(nowMs) || !Number.isSafeInteger(maximumSkewMs) || (maximumSkewMs as number) < 0 || (maximumSkewMs as number) > 24 * 60 * 60 * 1000) throw new TypeError("authentication time configuration is invalid");
  if (![headers.clientId, headers.keyId, headers.nonce].every((value) => SAFE_IDENTIFIER.test(value))) fail();
  if (!TIMESTAMP.test(headers.timestampMs)) fail("authentication timestamp is invalid");
  const timestampMs = Number(headers.timestampMs);
  if (!Number.isSafeInteger(timestampMs) || Math.abs((nowMs as number) - timestampMs) > (maximumSkewMs as number)) fail("authentication timestamp is outside the allowed skew");
  const key = registry.clients[headers.clientId]?.keys[headers.keyId];
  if (key === undefined || (nowMs as number) < key.validFromMs || (nowMs as number) >= key.validUntilMs || (key.revokedAtMs !== undefined && (nowMs as number) >= key.revokedAtMs)) fail("authentication key is inactive");
  if (!MAC.test(headers.mac)) fail();
  let received: Buffer;
  try { received = Buffer.from(headers.mac, "base64url"); } catch { fail(); }
  if (received.byteLength !== 32 || received.toString("base64url") !== headers.mac) fail();
  const bodyDigest = serviceRequestDigest(request);
  if (!DIGEST.test(bodyDigest)) fail();
  const expected = createHmac("sha256", key.secret).update(encode([
    method, path, request.serviceProtocolVersion, headers.clientId, headers.keyId,
    headers.timestampMs, headers.nonce, bodyDigest,
  ])).digest();
  if (!timingSafeEqual(expected, received)) fail();
  return Object.freeze({ request, clientId: headers.clientId, keyId: headers.keyId, timestampMs, nonce: headers.nonce, bodyDigest });
}
