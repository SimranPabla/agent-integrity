import { createHmac } from "node:crypto";
import { canonicalJson } from "@agent-integrity/core";
import type { IntegrityEnvelope } from "@agent-integrity/protocol";
import { describe, expect, it } from "vitest";
import {
  SIDECAR_PROTOCOL_VERSION,
  authenticateRequest,
  parseCanonicalServiceRequest,
  serviceRequestDigest,
  type AuthHeaders,
  type HmacRegistry,
} from "../src/index.js";

const NOW = 1_800_000_000_000;
const SECRET = Buffer.from("0123456789abcdef0123456789abcdef", "utf8");
const METHOD = "POST";
const PATH = "/v1/verify-release";

function envelope(): IntegrityEnvelope {
  return {
    protocolVersion: "1-alpha",
    policy: {
      version: 1,
      sources: { allowedRoots: ["docs"] },
      decisions: { path: "integrity/decisions.yaml" },
      rules: {
        requireEvidenceFor: ["factual", "recommendation"], contradictions: "review",
        rejectedDecisions: "block", responseMutation: "block", replay: "block",
      },
    },
    response: { content: "ok", sections: [{ sectionId: "s", substantive: false, byteStart: 0, byteEnd: 2, sha256: "2689367b205c16ce32ed4200942b8b1ef0a8f2e857d9aefecf9e5c0c4f9f5d3d" }] },
    sources: [], decisionRegistryDigest: "a".repeat(64), decisions: [], evidence: [], claims: [],
  };
}

function request(content = "ok") {
  const value = { serviceProtocolVersion: SIDECAR_PROTOCOL_VERSION, requestId: "req-1", idempotencyKey: "idem-1", bundleId: "bundle-1", envelope: envelope() };
  value.envelope.response.content = content;
  const raw = Buffer.from(canonicalJson(value));
  return { raw, parsed: parseCanonicalServiceRequest(raw, 1024 * 1024) };
}

function registry(...keys: Array<{ keyId: string; validFromMs: number; validUntilMs: number; revokedAtMs?: number }>): HmacRegistry {
  return { clients: { cage: { keys: Object.fromEntries(keys.map(({ keyId, ...key }) => [keyId, { ...key, secret: SECRET }])) } } };
}

function preimage(fields: readonly string[]): Buffer {
  const parts: Buffer[] = [Buffer.from("agent-integrity-sidecar-auth-v1", "ascii")];
  for (const field of fields) {
    const bytes = Buffer.from(field, "utf8");
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length);
    parts.push(length, bytes);
  }
  return Buffer.concat(parts);
}

function signedHeaders(bodyDigest: string, overrides: Partial<AuthHeaders> = {}, protocolVersion = SIDECAR_PROTOCOL_VERSION, secret = SECRET): AuthHeaders {
  const base = { clientId: "cage", keyId: "key-new", timestampMs: String(NOW), nonce: "nonce-123" };
  const values = { ...base, ...overrides };
  const mac = createHmac("sha256", secret).update(preimage([
    METHOD, PATH, protocolVersion, values.clientId, values.keyId,
    values.timestampMs, values.nonce, bodyDigest,
  ])).digest("base64url");
  return { ...values, mac, ...overrides };
}

function authenticate(overrides: Record<string, unknown> = {}) {
  const admitted = request();
  return authenticateRequest({
    request: admitted.parsed,
    method: METHOD,
    path: PATH,
    headers: signedHeaders(serviceRequestDigest(admitted.parsed)),
    nowMs: NOW,
    maximumSkewMs: 30_000,
    registry: registry(
      { keyId: "key-old", validFromMs: NOW - 100_000, validUntilMs: NOW + 1_000 },
      { keyId: "key-new", validFromMs: NOW - 1_000, validUntilMs: NOW + 100_000 },
    ),
    ...overrides,
  });
}

describe("sidecar HMAC authentication", () => {
  it("freezes the exact length-delimited golden vector", () => {
    const digest = "ab".repeat(32);
    const input = preimage([METHOD, PATH, "1", "cage", "key-new", String(NOW), "nonce-123", digest]);
    expect(input.toString("hex")).toBe("6167656e742d696e746567726974792d736964656361722d617574682d763100000004504f5354000000122f76312f7665726966792d72656c6561736500000001310000000463616765000000076b65792d6e65770000000d31383030303030303030303030000000096e6f6e63652d3132330000004061626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162");
    expect(createHmac("sha256", SECRET).update(input).digest("base64url")).toBe("ybIw6r6VoERPBtUYUkch2e8ex56uUc8TUkzVnOZ9g7w");
  });

  it("authenticates an admitted request without claiming nonce admission", () => {
    const authenticated = authenticate();
    expect(authenticated).toMatchObject({ clientId: "cage", keyId: "key-new", nonce: "nonce-123", bodyDigest: expect.stringMatching(/^[a-f0-9]{64}$/u) });
    expect(Object.isFrozen(authenticated)).toBe(true);
    expect(authenticated).not.toHaveProperty("admitted");
    expect(authenticated).not.toHaveProperty("nonceConsumed");
  });

  it.each([["method", { method: "GET" }], ["path", { path: "/v1/other" }]])("rejects a changed %s", (_name, changed) => {
    expect(() => authenticate(changed)).toThrow(/authentication/u);
  });

  it("takes the protocol version only from the admitted body", () => {
    const admitted = request();
    expect(() => authenticateRequest({
      request: admitted.parsed, method: METHOD, path: PATH,
      headers: signedHeaders(serviceRequestDigest(admitted.parsed), {}, "2"),
      nowMs: NOW, maximumSkewMs: 30_000,
      registry: registry({ keyId: "key-new", validFromMs: NOW - 1, validUntilMs: NOW + 1 }),
    })).toThrow(/authentication/u);
    expect(() => authenticate({ serviceProtocolVersion: "2" })).toThrow(/options.*invalid/u);
  });

  it.each([["client", { clientId: "other" }], ["key", { keyId: "key-old" }], ["nonce", { nonce: "nonce-other" }]])("rejects a changed %s header", (_name, changed) => {
    const admitted = request();
    expect(() => authenticate({ headers: { ...signedHeaders(serviceRequestDigest(admitted.parsed)), ...changed } })).toThrow(/authentication/u);
  });

  it("rejects a signature for another admitted body", () => {
    const first = request();
    const second = request("different");
    expect(() => authenticateRequest({
      request: second.parsed, method: METHOD, path: PATH,
      headers: signedHeaders(serviceRequestDigest(first.parsed)), nowMs: NOW, maximumSkewMs: 30_000,
      registry: registry({ keyId: "key-new", validFromMs: NOW - 1, validUntilMs: NOW + 1 }),
    })).toThrow(/authentication/u);
  });

  it.each([NOW - 30_001, NOW + 30_001])("rejects timestamp outside skew: %s", (timestamp) => {
    const admitted = request();
    expect(() => authenticate({ headers: signedHeaders(serviceRequestDigest(admitted.parsed), { timestampMs: String(timestamp) }) })).toThrow(/timestamp/u);
  });

  it("binds an independently changed in-window timestamp to the MAC", () => {
    const admitted = request();
    const headers = signedHeaders(serviceRequestDigest(admitted.parsed));
    expect(() => authenticate({ headers: { ...headers, timestampMs: String(NOW + 1) } })).toThrow(/authentication/u);
  });

  it("rejects malformed, padded, or independently mutated MAC encodings", () => {
    expect(() => authenticate({ headers: { ...signedHeaders("a".repeat(64)), mac: "A".repeat(43) } })).toThrow(/authentication/u);
    expect(() => authenticate({ headers: { ...signedHeaders("a".repeat(64)), mac: `${"A".repeat(43)}=` } })).toThrow(/authentication/u);
    expect(() => authenticate({ headers: { ...signedHeaders("a".repeat(64)), mac: `${"A".repeat(42)}B` } })).toThrow(/authentication/u);
    const admitted = request();
    const headers = signedHeaders(serviceRequestDigest(admitted.parsed));
    const replacement = headers.mac[0] === "A" ? "B" : "A";
    expect(() => authenticate({ headers: { ...headers, mac: `${replacement}${headers.mac.slice(1)}` } })).toThrow(/authentication/u);
  });

  it("accepts old and new keys only during their explicit overlap", () => {
    const admitted = request();
    const common = { request: admitted.parsed, method: METHOD, path: PATH, nowMs: NOW, maximumSkewMs: 30_000 } as const;
    const overlap = registry(
      { keyId: "key-old", validFromMs: NOW - 100, validUntilMs: NOW + 100 },
      { keyId: "key-new", validFromMs: NOW - 100, validUntilMs: NOW + 100 },
    );
    expect(authenticateRequest({ ...common, registry: overlap, headers: signedHeaders(serviceRequestDigest(admitted.parsed), { keyId: "key-old" }) }).keyId).toBe("key-old");
    expect(authenticateRequest({ ...common, registry: overlap, headers: signedHeaders(serviceRequestDigest(admitted.parsed), { keyId: "key-new" }) }).keyId).toBe("key-new");
    expect(() => authenticateRequest({ ...common, nowMs: NOW + 101, registry: overlap, headers: signedHeaders(serviceRequestDigest(admitted.parsed), { keyId: "key-old", timestampMs: String(NOW + 101) }) })).toThrow(/key/u);
  });

  it("rejects revoked keys and accessor-backed inputs without executing them", () => {
    expect(() => authenticate({ registry: registry({ keyId: "key-new", validFromMs: NOW - 1, validUntilMs: NOW + 1, revokedAtMs: NOW }) })).toThrow(/key/u);
    const admitted = request();
    let accessed = false;
    const headers = { ...signedHeaders(serviceRequestDigest(admitted.parsed)) };
    Object.defineProperty(headers, "nonce", { enumerable: true, get() { accessed = true; return "nonce-123"; } });
    expect(() => authenticate({ headers })).toThrow(/authentication.*invalid/u);
    expect(accessed).toBe(false);
  });

  it("rejects unknown and expired key IDs using captured host time", () => {
    const admitted = request();
    const digest = serviceRequestDigest(admitted.parsed);
    expect(() => authenticate({ headers: signedHeaders(digest, { keyId: "key-unknown" }) })).toThrow(/key/u);
    expect(() => authenticate({
      headers: signedHeaders(digest),
      registry: registry({ keyId: "key-new", validFromMs: NOW - 100, validUntilMs: NOW - 1 }),
    })).toThrow(/key/u);
    expect(() => authenticate({
      headers: signedHeaders(digest),
      registry: registry({ keyId: "key-new", validFromMs: NOW - 100, validUntilMs: NOW }),
    })).toThrow(/key/u);
  });
});
