import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { canonicalJson, FileReceiptStore, recheckReceipt, sha256Canonical, verifyTrustedEnvelope } from "@agent-integrity/core";
import type { AlphaIntegrityReceipt, IntegrityEnvelope } from "@agent-integrity/protocol";
import { releaseVerifiedReceipt, type ReleaseVerifiedReceiptOptions, type ReleaseResult } from "../src/release.js";

const roots: string[] = [];
afterEach(async () => {
  const results = await Promise.allSettled(roots.splice(0).map(root => rm(root, { recursive: true, force: true })));
  const failures = results.filter((result): result is PromiseRejectedResult => result.status === "rejected");
  if (failures.length) throw new AggregateError(failures.map(result => result.reason), "signed fixture cleanup failed");
});
const example = new URL("../../../examples/cli-quickstart/", import.meta.url);
const now = () => new Date("2026-11-14T01:00:00.000Z");

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "integrity-sdk-signed-"));
  roots.push(root); // Own the root before any later setup await can fail.
  await mkdir(join(root, "docs"));
  await mkdir(join(root, "integrity"));
  await writeFile(join(root, "docs/maintenance.md"), await readFile(new URL("docs/maintenance.md", example)));
  await writeFile(join(root, "integrity/decisions.yaml"), await readFile(new URL("integrity/decisions.yaml", example)));
  const request = JSON.parse(await readFile(new URL("request.json", example), "utf8")) as { envelope: IntegrityEnvelope };
  const envelope = request.envelope;
  const context = { projectRoot: root, allowedRoots: [...envelope.policy.sources.allowedRoots], decisionRegistryPath: envelope.policy.decisions.path, trustedPolicy: structuredClone(envelope.policy) };
  const verification = await verifyTrustedEnvelope(envelope, context);
  expect(verification.status).toBe("PASS");
  expect(verification.envelopeDigest).toBeDefined();
  const keys = generateKeyPairSync("ed25519");
  const trust: ReleaseVerifiedReceiptOptions["trust"] = {
    keys: { test: keys.publicKey.export({ type: "spki", format: "pem" }).toString() },
    issuer: "test-issuer", audience: "test-audience", purpose: "response-release", engineVersion: "test-engine",
    trustedPolicy: structuredClone(envelope.policy),
  };
  const store = new FileReceiptStore(join(root, "store"));
  async function issue(subject: IntegrityEnvelope, runId: string) {
    const verified = await verifyTrustedEnvelope(subject, context);
    expect(verified.status).toBe("PASS");
    const body = {
      protocolVersion: subject.protocolVersion, receiptVersion: "2-alpha" as const,
      engineVersion: trust.engineVersion, issuer: trust.issuer, audience: trust.audience, purpose: trust.purpose,
      nonce: runId, runId, createdAt: "2026-11-14T00:30:00.000Z", expiresAt: "2026-11-14T01:30:00.000Z",
      policyDigest: sha256Canonical(subject.policy), envelopeDigest: verified.envelopeDigest!,
      verification: { protocolVersion: verified.protocolVersion, status: verified.status, findings: structuredClone(verified.findings) },
    };
    const protectedSignature = { algorithm: "Ed25519" as const, keyId: "test" };
    const signed = { ...body, signature: { ...protectedSignature, value: sign(null, Buffer.from(canonicalJson({ protected: protectedSignature, body })), keys.privateKey).toString("base64") } };
    const receipt: AlphaIntegrityReceipt = { ...signed, receiptDigest: sha256Canonical(signed) };
    expect(recheckReceipt({ receipt, envelope: subject, now: now(), trust }).status).toBe("PASS");
    await store.issue(receipt);
    return receipt;
  }
  const receipt = await issue(envelope, "receipt-a");
  const options: ReleaseVerifiedReceiptOptions = { envelope, verification, context, receipt, receiptStore: store, now: now(), trust };
  return { root, options, issue };
}

function held(result: ReleaseResult) {
  expect(result.status).not.toBe("PASS");
  expect(Object.hasOwn(result, "response")).toBe(false);
}
async function assertConsumed(options: ReleaseVerifiedReceiptOptions, receipt = options.receipt) {
  // This real store consume must refuse; it never silently accepts a second consume.
  await expect(options.receiptStore.consume(receipt, now())).rejects.toThrow(/consum/i);
}

describe("releaseVerifiedReceipt transaction capture", () => {
  it("releases exact valid bytes, consumes the genuine receipt once and refuses replay", async () => {
    const { options } = await fixture();
    const result = await releaseVerifiedReceipt(options);
    expect(result.status).toBe("PASS");
    if (result.status === "PASS") {
      expect(result.response).toBe(options.envelope.response.content);
      expect(result.verification.envelopeDigest).toBe(options.receipt.envelopeDigest);
    }
    await assertConsumed(options);
    held(await releaseVerifiedReceipt(options));
  });

  it("blocks a different valid receipt without mutation, before consumption", async () => {
    const { options, issue } = await fixture();
    const other = structuredClone(options.envelope);
    Object.assign(other.response, { content: other.response.content + " " });
    Object.assign(other.response.sections[0]!, { byteEnd: Buffer.byteLength(other.response.content), sha256: createHash("sha256").update(other.response.content).digest("hex") });
    const receiptB = await issue(other, "receipt-b");
    held(await releaseVerifiedReceipt({ ...options, receipt: receiptB }));
    await options.receiptStore.consume(receiptB, now()); // Untouched valid receipt remained available.
  });

  it("never consumes a valid B receipt to release A after in-flight envelope replacement", async () => {
    const { options, issue } = await fixture();
    const other = structuredClone(options.envelope);
    Object.assign(other.response, { content: other.response.content + " " });
    Object.assign(other.response.sections[0]!, { byteEnd: Buffer.byteLength(other.response.content), sha256: createHash("sha256").update(other.response.content).digest("hex") });
    const receiptB = await issue(other, "receipt-b");
    const changing = { ...options, receipt: receiptB };
    const release = releaseVerifiedReceipt(changing);
    changing.envelope = other;
    held(await release);
    await options.receiptStore.consume(receiptB, now());
  });

  it.each(["envelope", "verification", "context", "receipt", "trust", "now", "receiptStore"] as const)("keeps the selected %s after invocation", async field => {
    const { options } = await fixture();
    const original = { ...options };
    const pending = releaseVerifiedReceipt(options);
    const replacements = {
      envelope: null, verification: null, context: null, receipt: null, trust: null,
      now: new Date("2099-01-01"), receiptStore: new FileReceiptStore(join(original.context.projectRoot, "other-store")),
    };
    Object.assign(options, { [field]: replacements[field] });
    const result = await pending;
    expect(result.status).toBe("PASS");
    if (result.status === "PASS") expect(result.response).toBe(original.envelope.response.content);
    await assertConsumed(original);
  });

  it("uses private receipt/trust/context/verification data and a copied Date", async () => {
    const { options } = await fixture();
    const receipt = structuredClone(options.receipt);
    const changing = { ...options, receipt };
    const expected = options.envelope.response.content;
    const originalReceipt = structuredClone(receipt);
    const pending = releaseVerifiedReceipt(changing);
    Object.assign(receipt, { audience: "changed" });
    Object.assign(changing.trust, { issuer: "changed", keys: {} });
    Object.assign(changing.context, { projectRoot: "/not-the-original-root" });
    Object.assign(changing.verification, { status: "BLOCKED" });
    changing.now.setTime(Date.parse("2099-01-01"));
    const result = await pending;
    expect(result.status).toBe("PASS");
    if (result.status === "PASS") expect(result.response).toBe(expected);
    await assertConsumed(options, originalReceipt);
  });

  it("owns nested receipt, trust keys, revocations and policy across the live await", async () => {
    const { options } = await fixture();
    const trust = { ...options.trust, keys: { ...options.trust.keys }, revokedKeyIds: [] as string[] };
    const changing = { ...options, trust };
    const originalReceipt = structuredClone(options.receipt);
    const expected = options.envelope.response.content;
    const expectedDigest = originalReceipt.envelopeDigest;
    const pending = releaseVerifiedReceipt(changing);
    trust.keys.test = "not an Ed25519 key";
    trust.revokedKeyIds.push("test");
    Object.assign(trust.trustedPolicy.rules, { contradictions: "block" });
    Object.assign(options.receipt.signature, { value: "A".repeat(86) + "==" });
    Object.assign(options.receipt.verification, { findings: [{ code: "changed", severity: "blocked", message: "caller mutation" }] });
    const result = await pending;
    expect(result.status).toBe("PASS");
    if (result.status === "PASS") {
      expect(result.response).toBe(expected);
      expect(result.verification.envelopeDigest).toBe(expectedDigest);
    }
    const marker = JSON.parse(await readFile(join(options.receiptStore.directory, "consumed", originalReceipt.receiptDigest + ".json"), "utf8")) as { receiptDigest: string; runId: string; nonce: string };
    expect(marker.receiptDigest).toBe(originalReceipt.receiptDigest);
    expect(marker.runId).toBe(originalReceipt.runId);
    expect(marker.nonce).toBe(originalReceipt.nonce);
    await assertConsumed(options, originalReceipt);
  });

  it("rejects a nested trust-key getter without invoking it or consuming", async () => {
    const { options } = await fixture();
    let calls = 0;
    Object.defineProperty(options.trust.keys, "test", { enumerable: true, get() { calls++; throw new Error("key getter"); } });
    held(await releaseVerifiedReceipt(options));
    expect(calls).toBe(0);
    await options.receiptStore.consume(options.receipt, now());
  });

  it("rejects unexpected nested undefined trust data before consumption", async () => {
    const { options } = await fixture();
    Object.assign(options.trust.keys, { unexpected: undefined });
    held(await releaseVerifiedReceipt(options));
    await options.receiptStore.consume(options.receipt, now());
  });

  it.each(["receipt", "trust", "now", "receiptStore"] as const)("rejects an accessor %s without invoking it", async field => {
    const { options } = await fixture();
    let calls = 0;
    Object.defineProperty(options, field, { enumerable: true, get() { calls++; throw new Error("caller getter"); } });
    held(await releaseVerifiedReceipt(options));
    expect(calls).toBe(0);
  });

  it("copies Date via its intrinsic without invoking an overridden getTime", async () => {
    const { options } = await fixture();
    let calls = 0;
    Object.defineProperty(options.now, "getTime", { value() { calls++; throw new Error("caller method"); } });
    expect((await releaseVerifiedReceipt(options)).status).toBe("PASS");
    expect(calls).toBe(0);
  });

  it("retains default behavior for explicitly undefined optional trust fields", async () => {
    const { options } = await fixture();
    Object.assign(options.trust, { maxClockSkewMs: undefined, maxLifetimeMs: undefined, revokedKeyIds: undefined });
    expect((await releaseVerifiedReceipt(options)).status).toBe("PASS");
  });

  it("retains the same transaction while real consumption is suspended", async () => {
    const { options } = await fixture();
    const selectedStore = options.receiptStore;
    const expectedReceipt = structuredClone(options.receipt);
    const expectedResponse = options.envelope.response.content;
    const originalTime = options.now.toISOString();
    const consume = selectedStore.consume.bind(selectedStore);
    let entered!: () => void;
    let resume!: () => void;
    const reached = new Promise<void>(resolve => { entered = resolve; });
    const gate = new Promise<void>(resolve => { resume = resolve; });
    selectedStore.consume = async (receipt, time) => { entered(); await gate; return consume(receipt, time); };
    const pending = releaseVerifiedReceipt(options);
    let result: ReleaseResult;
    try {
      await Promise.race([reached, pending.then(() => { throw new Error("release finished before consumption seam"); })]);
      options.now.setTime(Date.parse("2099-01-01"));
      Object.assign(options.receipt, { audience: "changed" });
      Object.assign(options.trust, { audience: "changed" });
      Object.assign(options, { envelope: null, verification: null, context: null, receipt: null, trust: null, now: null, receiptStore: null });
    } finally {
      resume();
      result = await pending; // Drain real durable work before root teardown, even on assertion failure.
    }
    expect(result.status).toBe("PASS");
    if (result.status === "PASS") {
      expect(result.response).toBe(expectedResponse);
      expect(result.verification.envelopeDigest).toBe(expectedReceipt.envelopeDigest);
    }
    const marker = JSON.parse(await readFile(join(selectedStore.directory, "consumed", expectedReceipt.receiptDigest + ".json"), "utf8")) as { consumedAt: string };
    expect(marker.consumedAt).toBe(originalTime);
    await expect(consume(expectedReceipt, now())).rejects.toThrow(/consum/i);
  });

  it("accepts frozen plain inputs without modifying caller data", async () => {
    const { options } = await fixture();
    const data = { envelope: options.envelope, verification: options.verification, context: options.context, receipt: options.receipt, trust: options.trust };
    const before = canonicalJson(data);
    function freeze(value: unknown): void {
      if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
        for (const child of Object.values(value)) freeze(child);
        Object.freeze(value);
      }
    }
    freeze(data);
    Object.freeze(options);
    expect((await releaseVerifiedReceipt(options)).status).toBe("PASS");
    expect(canonicalJson(data)).toBe(before);
  });

  it.each(["REVIEW", "BLOCKED"] as const)("holds a genuine %s verification before consumption", async status => {
    const { options } = await fixture();
    const envelope = structuredClone(options.envelope);
    if (status === "REVIEW") Object.assign(envelope.claims[0]!.evidence[0]!, { support: "ambiguous" });
    else Object.assign(envelope.claims[0]!, { evidence: [] });
    const verification = await verifyTrustedEnvelope(envelope, options.context);
    expect(verification.status).toBe(status);
    held(await releaseVerifiedReceipt({ ...options, envelope, verification }));
    await options.receiptStore.consume(options.receipt, now());
  });

  it("holds a real consumption failure and leaves the receipt unconsumed", async () => {
    const { options } = await fixture();
    const consume = options.receiptStore.consume.bind(options.receiptStore);
    options.receiptStore.consume = async () => { throw new Error("host store unavailable"); };
    held(await releaseVerifiedReceipt(options));
    await consume(options.receipt, now());
  });

  it("blocks pre-invocation verification mutation", async () => {
    const { options } = await fixture();
    Object.assign(options.verification, { status: "BLOCKED" });
    held(await releaseVerifiedReceipt(options));
    await options.receiptStore.consume(options.receipt, now());
  });

  it.each(["expired", "invalid-date", "bad-signature", "wrong-trust"])("holds %s without response", async mode => {
    const { options } = await fixture();
    if (mode === "expired") options.now.setTime(Date.parse("2026-11-15"));
    if (mode === "invalid-date") options.now.setTime(NaN);
    if (mode === "bad-signature") Object.assign(options.receipt.signature, { value: "A".repeat(86) + "==" });
    if (mode === "wrong-trust") Object.assign(options.trust, { audience: "wrong" });
    held(await releaseVerifiedReceipt(options));
  });
});
