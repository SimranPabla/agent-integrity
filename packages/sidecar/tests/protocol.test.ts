import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { canonicalJson, sha256Canonical } from "@agent-integrity/core";
import type { AlphaIntegrityReceipt, IntegrityEnvelope, IntegrityResult } from "@agent-integrity/protocol";
import {
  SIDECAR_PROTOCOL_VERSION,
  type ParsedServiceRequest,
  type ServiceResponse,
  type ServiceRequest,
  parseCanonicalServiceRequest,
  parseCanonicalServiceResponse,
  serializeCanonicalServiceResponse,
  serviceRequestDigest,
} from "../src/index.js";

const MAX_BODY_BYTES = 20 * 1024 * 1024;
const MAX_ENVELOPE_BYTES = 16 * 1024 * 1024;
const MAX_JSON_NODES = 100_000;
const RESPONSE_LIMITS = {
  maxBodyBytes: 2 * 1024 * 1024,
  maxFindings: 100,
  maxFindingBytes: 4096,
  maxReleasedResponseBytes: 16 * 1024 * 1024,
} as const;

function validEnvelope(): IntegrityEnvelope {
  return {
    protocolVersion: "1-alpha",
    policy: {
      version: 1,
      sources: { allowedRoots: ["docs"] },
      decisions: { path: "integrity/decisions.yaml" },
      rules: {
        requireEvidenceFor: ["factual", "recommendation"],
        contradictions: "review",
        rejectedDecisions: "block",
        responseMutation: "block",
        replay: "block",
      },
    },
    response: {
      content: "Supported response",
      sections: [{
        sectionId: "answer",
        substantive: true,
        byteStart: 0,
        byteEnd: 18,
        sha256: "a31069ff26ded3cd55c0d40ebaa3430097950a210b8caaece07b27dedbb92766",
      }],
    },
    sources: [{ sourceId: "source-1", path: "docs/source.md", sha256: "a".repeat(64), size: 10 }],
    decisionRegistryDigest: "b".repeat(64),
    decisions: [],
    evidence: [{ evidenceId: "evidence-1", sourceId: "source-1" }],
    claims: [{
      claimId: "claim-1",
      sectionId: "answer",
      kind: "factual",
      decisionIds: [],
      evidence: [{ evidenceId: "evidence-1", role: "supporting", support: "direct" }],
    }],
  };
}

function validRequest() {
  return {
    serviceProtocolVersion: SIDECAR_PROTOCOL_VERSION,
    requestId: "req-123",
    idempotencyKey: "idem-123",
    bundleId: "bundle-123",
    envelope: validEnvelope(),
  };
}

function encoded(value: unknown): Buffer {
  return Buffer.from(canonicalJson(value), "utf8");
}

function admittedRequest(): ParsedServiceRequest {
  return parseCanonicalServiceRequest(encoded(validRequest()), MAX_BODY_BYTES);
}

function verification(status: "PASS" | "REVIEW" | "BLOCKED" = "PASS"): IntegrityResult {
  return {
    protocolVersion: "1-alpha",
    status,
    findings: status === "PASS" ? [] : [{ code: `test.${status.toLowerCase()}`, severity: status === "BLOCKED" ? "blocked" : "review", message: "Bounded finding" }],
  };
}

function receipt(request: ParsedServiceRequest, result = verification()): AlphaIntegrityReceipt {
  const body = {
    protocolVersion: "1-alpha",
    receiptVersion: "2-alpha",
    engineVersion: "0.1.0-alpha.2",
    issuer: "agent-integrity-sidecar",
    audience: "cage",
    purpose: "verified-release",
    nonce: "receipt-nonce",
    runId: "run-123",
    createdAt: "2026-09-28T19:00:00.000Z",
    expiresAt: "2026-09-28T20:00:00.000Z",
    policyDigest: "a".repeat(64),
    envelopeDigest: sha256Canonical(request.envelope),
    verification: result,
    signature: { algorithm: "Ed25519", keyId: "receipt-key-1", value: `${"A".repeat(86)}==` },
  };
  return { ...body, receiptDigest: sha256Canonical(body) };
}

function responseContext(request = admittedRequest()) {
  return { ...RESPONSE_LIMITS, request };
}

function passResponse(request = admittedRequest()) {
  const result = verification("PASS");
  const bytes = Buffer.from(request.envelope.response.content, "utf8");
  return {
    serviceProtocolVersion: "1" as const,
    requestId: request.requestId,
    status: "PASS" as const,
    verification: result,
    receipt: receipt(request, result),
    releasedResponse: {
      encoding: "base64" as const,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      bytes: bytes.toString("base64"),
    },
  };
}

function requestWithEnvelopeBytes(targetBytes: number) {
  const request = validRequest();
  const envelope = request.envelope;
  const baseBytes = Buffer.byteLength(canonicalJson(envelope), "utf8");
  const baseRoot = envelope.policy.sources.allowedRoots[0]!;
  envelope.policy.sources.allowedRoots[0] = "a".repeat(targetBytes - baseBytes + Buffer.byteLength(baseRoot, "utf8"));
  expect(Buffer.byteLength(canonicalJson(envelope), "utf8")).toBe(targetBytes);
  expect(Buffer.byteLength(envelope.response.content, "utf8")).toBeLessThan(MAX_ENVELOPE_BYTES);
  return request;
}

function jsonNodeCount(root: unknown): number {
  const pending: unknown[] = [root];
  let count = 0;
  while (pending.length > 0) {
    const value = pending.pop();
    count += 1;
    if (Array.isArray(value)) {
      for (let index = value.length - 1; index >= 0; index -= 1) pending.push(value[index]);
    } else if (value !== null && typeof value === "object") {
      const values = Object.values(value as Record<string, unknown>);
      for (let index = values.length - 1; index >= 0; index -= 1) pending.push(values[index]);
    }
  }
  return count;
}

function requestWithJsonNodes(targetNodes: number) {
  const request = validRequest();
  request.envelope.policy.sources.allowedRoots = Array.from({ length: 10_000 }, (_, index) => `root-${index}`);
  request.envelope.sources = Array.from({ length: 10_000 }, (_, index) => ({
    sourceId: `source-${index}`,
    path: `docs/source-${index}.md`,
    sha256: "a".repeat(64),
    size: index,
  }));
  request.envelope.evidence = Array.from({ length: 10_000 }, (_, index) => ({
    evidenceId: `evidence-${index}`,
    sourceId: `source-${index}`,
  }));
  request.envelope.claims = Array.from({ length: 1_500 }, (_, index) => ({
    claimId: `claim-${index}`,
    sectionId: "answer",
    kind: "inference" as const,
    decisionIds: [] as string[],
    evidence: [],
  }));
  const remainder = targetNodes - jsonNodeCount(request);
  if (remainder < 0 || remainder > 10_000) throw new Error(`cannot create ${targetNodes} nodes with the valid fixture`);
  request.envelope.claims[0]!.decisionIds = Array.from({ length: remainder }, (_, index) => `decision-${index}`);
  expect(jsonNodeCount(request)).toBe(targetNodes);
  return request;
}

describe("closed sidecar service protocol", () => {
  it("accepts exactly the canonical closed request and returns a deeply frozen value", () => {
    const request = validRequest();
    const parsed = parseCanonicalServiceRequest(encoded(request), MAX_BODY_BYTES);

    expect(parsed).toEqual(request);
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed.envelope)).toBe(true);
    expect(Object.isFrozen(parsed.envelope.policy)).toBe(true);
    expect(Object.isFrozen(parsed.envelope.policy.sources.allowedRoots)).toBe(true);
    expect(Object.isFrozen(parsed.envelope.claims[0]!.evidence[0]!)).toBe(true);
    expect(Reflect.set(parsed, "requestId", "changed")).toBe(false);
    expect(Reflect.set(parsed.envelope.response, "content", "changed")).toBe(false);
  });

  it.each([
    ['{"requestId":"a","requestId":"b"}', "top-level"],
    ['{"outer":{"key":1,"key":2}}', "nested object"],
    ['{"outer":[{"key":1,"key":2}]}', "object inside array"],
  ])("rejects duplicate JSON keys in a %s object", (raw) => {
    expect(() => parseCanonicalServiceRequest(Buffer.from(raw), MAX_BODY_BYTES)).toThrow(/duplicate/u);
  });

  it("rejects escaped-equivalent duplicate keys without echoing attacker content", () => {
    const secretKey = `private-${"x".repeat(4096)}`;
    const escaped = `\\u${secretKey.charCodeAt(0).toString(16).padStart(4, "0")}${secretKey.slice(1)}`;
    const raw = `{"${secretKey}":1,"${escaped}":2}`;
    let failure: unknown;
    try {
      parseCanonicalServiceRequest(Buffer.from(raw), MAX_BODY_BYTES);
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(SyntaxError);
    expect((failure as Error).message).toBe("duplicate JSON key");
    expect((failure as Error).message).not.toContain(secretKey);
  });

  it("rejects unknown outer keys", () => {
    expect(() => parseCanonicalServiceRequest(encoded({ ...validRequest(), extra: true }), MAX_BODY_BYTES)).toThrow(/unknown/u);
  });

  it("rejects an attacker-controlled unknown key without reflecting its content", () => {
    const attackerKey = "authorization\nset-cookie: private-token-value\r\n";
    let failure: unknown;
    try {
      parseCanonicalServiceRequest(encoded({ ...validRequest(), [attackerKey]: true }), MAX_BODY_BYTES);
    } catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(TypeError);
    expect((failure as Error).message).toBe("service request contains unknown keys");
    expect((failure as Error).message).not.toContain("authorization");
    expect((failure as Error).message).not.toContain("private-token-value");
    expect((failure as Error).message).not.toContain("\n");
    expect((failure as Error).message).not.toContain("\r");
  });

  it("rejects a long unknown key with a constant bounded error", () => {
    const attackerKey = `private-${"x".repeat(16_384)}`;
    let failure: unknown;
    try {
      parseCanonicalServiceRequest(encoded({ ...validRequest(), [attackerKey]: true }), MAX_BODY_BYTES);
    } catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(TypeError);
    expect((failure as Error).message).toBe("service request contains unknown keys");
    expect((failure as Error).message).not.toContain(attackerKey);
    expect((failure as Error).message.length).toBeLessThanOrEqual(64);
  });

  it.each([
    ["leading whitespace", (raw: string) => ` ${raw}`],
    ["trailing whitespace", (raw: string) => `${raw}\n`],
    ["alternate number encoding", (raw: string) => raw.replace('"size":10', '"size":1e1')],
    ["escaped string encoding", (raw: string) => raw.replace('"req-123"', '"\\u0072eq-123"')],
  ])("rejects noncanonical %s", (_name, mutate) => {
    const raw = canonicalJson(validRequest());
    expect(() => parseCanonicalServiceRequest(Buffer.from(mutate(raw)), MAX_BODY_BYTES)).toThrow(/canonical/u);
  });

  it("rejects a UTF-8 byte-order mark", () => {
    const raw = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), encoded(validRequest())]);
    expect(() => parseCanonicalServiceRequest(raw, MAX_BODY_BYTES)).toThrow();
  });

  it("enforces the exact maximum body-byte boundary", () => {
    const raw = encoded(validRequest());
    expect(parseCanonicalServiceRequest(raw, raw.byteLength)).toEqual(validRequest());
    expect(() => parseCanonicalServiceRequest(raw, raw.byteLength - 1)).toThrow(/maximum.*body|body.*maximum/u);
    expect(() => parseCanonicalServiceRequest(raw, 0)).toThrow(/maximum/u);
  });

  it("enforces exact and maximum-plus-one JSON depth before parsing", () => {
    const exact = `${"[".repeat(65)}null${"]".repeat(65)}`;
    expect(() => parseCanonicalServiceRequest(Buffer.from(exact), MAX_BODY_BYTES)).toThrow(/plain object/u);
    const over = `${"[".repeat(66)}null${"]".repeat(66)}`;
    expect(() => parseCanonicalServiceRequest(Buffer.from(over), MAX_BODY_BYTES)).toThrow(/maximum JSON depth exceeded/u);
  });

  it("accepts exactly 100,000 JSON values and rejects value 100,001 before JSON.parse", () => {
    const atLimit = requestWithJsonNodes(MAX_JSON_NODES);
    const atLimitRaw = canonicalJson(atLimit);
    expect(parseCanonicalServiceRequest(Buffer.from(atLimitRaw), MAX_BODY_BYTES)).toEqual(atLimit);

    const marker = '"decisionIds":[';
    const insertion = atLimitRaw.indexOf(marker) + marker.length;
    expect(insertion).toBeGreaterThan(marker.length - 1);
    const overLimitRaw = `${atLimitRaw.slice(0, insertion)}"overflow",${atLimitRaw.slice(insertion)}`;
    expect(() => parseCanonicalServiceRequest(Buffer.from(overLimitRaw), MAX_BODY_BYTES))
      .toThrow(/maximum JSON node count exceeded/u);
  });

  it("rejects large flat arrays with the bounded protocol error instead of RangeError", () => {
    const raw = `[${Array.from({ length: MAX_JSON_NODES }, () => "null").join(",")}]`;
    expect(() => parseCanonicalServiceRequest(Buffer.from(raw), MAX_BODY_BYTES))
      .toThrowError(new SyntaxError("maximum JSON node count exceeded"));
  });

  it("enforces the core response-content byte limit before admission", () => {
    const request = validRequest();
    request.envelope.response.content = "a".repeat(16 * 1024 * 1024 + 1);
    expect(() => parseCanonicalServiceRequest(encoded(request), 20 * 1024 * 1024)).toThrow(/too large|Maximum.*size/u);
  });

  it("enforces the independent canonical-envelope byte boundary", () => {
    const atMaximum = requestWithEnvelopeBytes(MAX_ENVELOPE_BYTES);
    expect(parseCanonicalServiceRequest(encoded(atMaximum), MAX_BODY_BYTES)).toEqual(atMaximum);

    const overMaximum = requestWithEnvelopeBytes(MAX_ENVELOPE_BYTES + 1);
    expect(() => parseCanonicalServiceRequest(encoded(overMaximum), MAX_BODY_BYTES)).toThrow(/envelope.*maximum|maximum.*envelope/u);
  });

  it.each(["requestId", "idempotencyKey", "bundleId"] as const)("enforces safe identifier syntax and length for %s", (field) => {
    for (const invalid of ["", "-starts-with-dash", "has/slash", "has space", "a".repeat(129), "é"] as const) {
      const request = validRequest();
      request[field] = invalid;
      expect(() => parseCanonicalServiceRequest(encoded(request), MAX_BODY_BYTES)).toThrow(new RegExp(field, "u"));
    }
    const request = validRequest();
    request[field] = `a${"._-Z9".repeat(25)}ab`;
    expect(request[field]).toHaveLength(128);
    expect(parseCanonicalServiceRequest(encoded(request), MAX_BODY_BYTES)[field]).toBe(request[field]);
  });

  it("rejects invalid UTF-8", () => {
    expect(() => parseCanonicalServiceRequest(Uint8Array.from([0xc3, 0x28]), MAX_BODY_BYTES)).toThrow(/UTF-8/u);
  });

  it("rejects numbers that decode to non-finite JavaScript values", () => {
    const raw = canonicalJson(validRequest()).replace('"size":10', '"size":1e400');
    expect(() => parseCanonicalServiceRequest(Buffer.from(raw), MAX_BODY_BYTES)).toThrow(/Non-finite/u);
  });

  it.each([null, [], [validRequest()]])("rejects non-object top-level JSON: %j", (value) => {
    expect(() => parseCanonicalServiceRequest(encoded(value), MAX_BODY_BYTES)).toThrow(/object/u);
  });

  it("rejects an unsupported service version", () => {
    expect(() => parseCanonicalServiceRequest(encoded({ ...validRequest(), serviceProtocolVersion: "2" }), MAX_BODY_BYTES)).toThrow(/version/u);
  });

  it.each([
    ["missing envelope field", () => {
      const envelope = validEnvelope() as unknown as Record<string, unknown>;
      delete envelope.claims;
      return envelope;
    }],
    ["unknown envelope field", () => ({ ...validEnvelope(), extra: true })],
    ["mistyped nested envelope field", () => ({ ...validEnvelope(), response: { content: 1, sections: [] } })],
  ])("rejects malformed envelope structure: %s", (_name, makeEnvelope) => {
    expect(() => parseCanonicalServiceRequest(encoded({ ...validRequest(), envelope: makeEnvelope() }), MAX_BODY_BYTES)).toThrow(/envelope|response|exactly/u);
  });

  it.each([
    ["request field", (raw: string) => raw.replace('"req-123"', '"\\ud800"')],
    ["nested object value", (raw: string) => raw.replace('"Supported response"', '"\\ud800"')],
    ["array value", (raw: string) => raw.replace('"docs"', '"\\ud800"')],
    ["nested object key", (raw: string) => raw.replace('"content"', '"\\ud800"')],
  ])("rejects escaped lone UTF-16 surrogates in a %s", (_name, mutate) => {
    expect(() => parseCanonicalServiceRequest(Buffer.from(mutate(canonicalJson(validRequest()))), MAX_BODY_BYTES)).toThrow(/surrogate/u);
  });

  it("returns lowercase SHA-256 only for the exact admitted request identity", () => {
    const raw = encoded(validRequest());
    const expected = createHash("sha256").update(raw).digest("hex");
    const parsed = parseCanonicalServiceRequest(raw, MAX_BODY_BYTES);
    expect(serviceRequestDigest(parsed)).toBe(expected);
    expect(serviceRequestDigest(parsed)).toMatch(/^[a-f0-9]{64}$/u);

    const copied = { ...parsed } as ParsedServiceRequest;
    expect(() => serviceRequestDigest(copied)).toThrow(/admitted request identity/u);
    const forged = validRequest() as unknown as ParsedServiceRequest;
    expect(() => serviceRequestDigest(forged)).toThrow(/admitted request identity/u);

    raw.fill(0);
    expect(serviceRequestDigest(parsed)).toBe(expected);
  });

  it("exposes a deeply readonly admitted request type", () => {
    const parsed = parseCanonicalServiceRequest(encoded(validRequest()), MAX_BODY_BYTES);
    const structural: ServiceRequest = validRequest();
    if (false) {
      // @ts-expect-error admitted requests are readonly
      parsed.requestId = "changed";
      // @ts-expect-error nested envelope fields are readonly
      parsed.envelope.response.content = "changed";
      // @ts-expect-error structural request values are not admitted identities
      serviceRequestDigest(structural);
    }
    expect(parsed.requestId).toBe("req-123");
  });
});

describe("closed sidecar service responses", () => {
  it("accepts and serializes an exactly bound PASS response", () => {
    const request = admittedRequest();
    const value = passResponse(request);
    const parsed = parseCanonicalServiceResponse(encoded(value), responseContext(request));
    expect(parsed).toEqual(value);
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed.receipt.verification.findings)).toBe(true);
    expect(Buffer.from(serializeCanonicalServiceResponse(value, responseContext(request))).toString("utf8")).toBe(canonicalJson(value));
  });

  it.each(["REVIEW", "BLOCKED"] as const)("accepts a closed %s refusal without release bytes", (status) => {
    const request = admittedRequest();
    const result = verification(status);
    const value = { serviceProtocolVersion: "1", requestId: request.requestId, status, verification: result, receipt: receipt(request, result) };
    expect(parseCanonicalServiceResponse(encoded(value), responseContext(request))).toEqual(value);
  });

  it("accepts only the terminal closed RELEASE_REFUSED shape", () => {
    const request = admittedRequest();
    const result = verification("PASS");
    const value = {
      serviceProtocolVersion: "1",
      requestId: request.requestId,
      status: "RELEASE_REFUSED",
      verification: result,
      receipt: receipt(request, result),
      release: { status: "BLOCKED", code: "RECEIPT_RECHECK_REFUSED", retryable: false },
    };
    expect(parseCanonicalServiceResponse(encoded(value), responseContext(request))).toEqual(value);
  });

  it("accepts only closed stable technical errors and permits omission of an unavailable request ID", () => {
    const request = admittedRequest();
    const withId = { serviceProtocolVersion: "1", requestId: request.requestId, error: { code: "BUNDLE_INVALID", retryable: false } };
    const withoutId = { serviceProtocolVersion: "1", error: { code: "INVALID_REQUEST", retryable: false } };
    expect(parseCanonicalServiceResponse(encoded(withId), responseContext(request))).toEqual(withId);
    expect(parseCanonicalServiceResponse(encoded(withoutId), responseContext(request))).toEqual(withoutId);
  });

  it.each([
    ["unknown wrapper field", (value: any) => ({ ...value, extra: true })],
    ["wrong request ID", (value: any) => ({ ...value, requestId: "other-request" })],
    ["wrapper status mismatch", (value: any) => ({ ...value, status: "REVIEW" })],
    ["receipt verification mismatch", (value: any) => ({ ...value, receipt: { ...value.receipt, verification: verification("REVIEW") } })],
    ["receipt envelope mismatch", (value: any) => ({ ...value, receipt: { ...value.receipt, envelopeDigest: "f".repeat(64) } })],
    ["receipt digest mismatch", (value: any) => ({ ...value, receipt: { ...value.receipt, receiptDigest: "f".repeat(64) } })],
    ["released digest mismatch", (value: any) => ({ ...value, releasedResponse: { ...value.releasedResponse, sha256: "f".repeat(64) } })],
    ["released bytes mismatch", (value: any) => ({ ...value, releasedResponse: { ...value.releasedResponse, bytes: Buffer.from("different", "utf8").toString("base64") } })],
  ])("rejects %s", (_name, mutate) => {
    const request = admittedRequest();
    expect(() => parseCanonicalServiceResponse(encoded(mutate(passResponse(request))), responseContext(request))).toThrow();
  });

  it("rejects release bytes on every refusal", () => {
    const request = admittedRequest();
    const result = verification("BLOCKED");
    const refusal = { serviceProtocolVersion: "1", requestId: request.requestId, status: "BLOCKED", verification: result, receipt: receipt(request, result), releasedResponse: passResponse(request).releasedResponse };
    expect(() => parseCanonicalServiceResponse(encoded(refusal), responseContext(request))).toThrow(/unknown|exact|release/u);
  });

  it("rejects a noncanonical response and an oversized response before persistence", () => {
    const request = admittedRequest();
    const raw = canonicalJson(passResponse(request));
    expect(() => parseCanonicalServiceResponse(Buffer.from(` ${raw}`), responseContext(request))).toThrow(/canonical/u);
    expect(() => parseCanonicalServiceResponse(Buffer.from(raw), { ...responseContext(request), maxBodyBytes: raw.length - 1 })).toThrow(/maximum|limit/u);
  });

  it("rejects duplicate keys and unknown nested response fields", () => {
    const request = admittedRequest();
    const raw = canonicalJson(passResponse(request));
    const duplicate = raw.replace('"requestId":"req-123"', '"requestId":"req-123","requestId":"req-123"');
    expect(() => parseCanonicalServiceResponse(Buffer.from(duplicate), responseContext(request))).toThrow(/duplicate/u);
    const value = passResponse(request);
    expect(() => parseCanonicalServiceResponse(encoded({ ...value, receipt: { ...value.receipt, unknown: true } }), responseContext(request))).toThrow(/receipt.*exact/u);
    expect(() => parseCanonicalServiceResponse(encoded({ ...value, releasedResponse: { ...value.releasedResponse, unknown: true } }), responseContext(request))).toThrow(/released response.*exact/u);
  });

  it("rejects invalid UTF-8, lone surrogates, and unsafe response limits", () => {
    const request = admittedRequest();
    expect(() => parseCanonicalServiceResponse(Uint8Array.from([0xc3, 0x28]), responseContext(request))).toThrow(/UTF-8/u);
    const raw = canonicalJson(passResponse(request)).replace('"agent-integrity-sidecar"', '"\\ud800"');
    expect(() => parseCanonicalServiceResponse(Buffer.from(raw), responseContext(request))).toThrow(/surrogate/u);
    expect(() => parseCanonicalServiceResponse(encoded(passResponse(request)), { ...responseContext(request), maxFindings: 10_001 })).toThrow(/hard ceilings/u);
  });

  it("rejects unknown error codes, fields, and mismatched safely parsed request IDs", () => {
    const request = admittedRequest();
    const base = { serviceProtocolVersion: "1", requestId: request.requestId, error: { code: "INVALID_REQUEST", retryable: false } };
    expect(() => parseCanonicalServiceResponse(encoded({ ...base, error: { code: "MADE_UP", retryable: false } }), responseContext(request))).toThrow(/error|code/u);
    expect(() => parseCanonicalServiceResponse(encoded({ ...base, error: { ...base.error, message: "secret path" } }), responseContext(request))).toThrow(/error|exact|unknown/u);
    expect(() => parseCanonicalServiceResponse(encoded({ ...base, requestId: "other" }), responseContext(request))).toThrow(/request/u);
  });

  it("rejects a verdict that contradicts its findings", () => {
    const request = admittedRequest();
    const value = passResponse(request);
    const contradictory = verification("BLOCKED");
    const mutated = { ...value, verification: { ...contradictory, status: "PASS" }, receipt: { ...value.receipt, verification: { ...contradictory, status: "PASS" } } };
    expect(() => parseCanonicalServiceResponse(encoded(mutated), responseContext(request))).toThrow(/inconsistent/u);
  });

  it("rejects noncanonical or reversed receipt timestamps", () => {
    const request = admittedRequest();
    const value = passResponse(request);
    expect(() => parseCanonicalServiceResponse(encoded({ ...value, receipt: { ...value.receipt, createdAt: "2026-09-28T19:00:00Z" } }), responseContext(request))).toThrow(/createdAt/u);
    expect(() => parseCanonicalServiceResponse(encoded({ ...value, receipt: { ...value.receipt, expiresAt: value.receipt.createdAt } }), responseContext(request))).toThrow(/interval/u);
  });

  it("enforces finding count and byte limits", () => {
    const request = admittedRequest();
    const initial = verification("REVIEW");
    const result = { ...initial, findings: [...initial.findings, { code: "test.second", severity: "review" as const, message: "Second bounded finding" }] };
    const value = { serviceProtocolVersion: "1", requestId: request.requestId, status: "REVIEW", verification: result, receipt: receipt(request, result) };
    expect(() => parseCanonicalServiceResponse(encoded(value), { ...responseContext(request), maxFindings: 1 })).toThrow(/findings.*limit/u);
    expect(() => parseCanonicalServiceResponse(encoded(value), { ...responseContext(request), maxFindingBytes: 16 })).toThrow(/finding.*limit/u);
  });

  it("rejects malformed receipt signatures and released base64", () => {
    const request = admittedRequest();
    const value = passResponse(request);
    expect(() => parseCanonicalServiceResponse(encoded({ ...value, receipt: { ...value.receipt, signature: { ...value.receipt.signature, value: `${"A".repeat(86)}__` } } }), responseContext(request))).toThrow(/signature/u);
    expect(() => parseCanonicalServiceResponse(encoded({ ...value, releasedResponse: { ...value.releasedResponse, bytes: `${value.releasedResponse.bytes}=` } }), responseContext(request))).toThrow(/base64|noncanonical/u);
  });

  it("exposes a closed response union", () => {
    const value: ServiceResponse = passResponse();
    if (false) {
      // @ts-expect-error release bytes are unavailable without narrowing to PASS
      value.releasedResponse;
    }
    expect(value.status).toBe("PASS");
  });
});
