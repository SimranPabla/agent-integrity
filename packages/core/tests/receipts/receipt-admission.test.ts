import { generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { canonicalJson } from "../../src/canonical-json.js";
import { sha256Canonical } from "../../src/hash.js";
import { verifyEnvelope } from "../../src/verify.js";
import { assertAlphaIntegrityReceipt } from "../../src/schema/validate-receipt.js";
import { captureJsonData } from "../../src/capture-json.js";
const live = vi.hoisted(() => ({ verify: vi.fn() }));
vi.mock("../../src/verify-trusted.js", () => ({ verifyTrustedEnvelope: live.verify }));
import { recheckReceipt, recheckTrustedReceipt } from "../../src/receipts/recheck-receipt.js";

// Supported synthetic subject from the independently reproduced C control, no stores/files written.
import { validEnvelope } from "../support/valid-envelope.js";
const envelope = validEnvelope();
const policy = envelope.policy;
function fixture() {
  const keys = generateKeyPairSync("ed25519");
  const verification = verifyEnvelope(envelope);
  const body: any = { protocolVersion: "1-alpha", receiptVersion: "2-alpha", engineVersion: "1", issuer: "i", audience: "a", purpose: "p", nonce: "n", runId: "r", createdAt: "2026-10-11T17:00:00Z", expiresAt: "2026-10-11T18:00:00Z", policyDigest: sha256Canonical(policy), envelopeDigest: verification.envelopeDigest, verification: { protocolVersion: "1-alpha", status: verification.status, findings: verification.findings } };
  const signature = { algorithm: "Ed25519", keyId: "k", value: sign(null, Buffer.from(canonicalJson({ protected: { algorithm: "Ed25519", keyId: "k" }, body })), keys.privateKey).toString("base64") };
  const signed = { ...body, signature };
  const receipt: any = { ...signed, receiptDigest: sha256Canonical(signed) };
  const options: any = { receipt, envelope, context: {}, now: new Date("2026-10-11T17:30:00Z"), trust: { keys: { k: keys.publicKey.export({ type: "spki", format: "pem" }).toString() }, issuer: "i", audience: "a", purpose: "p", engineVersion: "1", trustedPolicy: policy }, receiptStore: { consume: vi.fn().mockResolvedValue(undefined) } };
  return { receipt, options, verification };
}
describe("receipt-only ownership and admission", () => {
  it("retains admitted private identity/content across deterministic source await", async () => {
    const { receipt, options, verification } = fixture();
    expect(verification.status).toBe("PASS");
    const before = canonicalJson(receipt); const expected = JSON.parse(before);
    let finish!: (v: any) => void;
    live.verify.mockReset().mockImplementation(() => new Promise(resolve => { finish = resolve; }));
    const baseline = recheckReceipt(options); expect(baseline.status).toBe("PASS");
    expect(canonicalJson(receipt)).toBe(before);
    const pending = recheckTrustedReceipt(options);
    expect(live.verify).toHaveBeenCalledOnce();
    options.receipt = { replacement: true }; receipt.verification.status = "BLOCKED"; receipt.signature.value = "changed";
    const callerAfter = canonicalJson(receipt);
    finish(verification); const result = await pending;
    expect(result).toEqual(baseline); expect(canonicalJson(receipt)).toBe(callerAfter);
    const consumed = options.receiptStore.consume.mock.calls[0][0];
    expect(consumed).not.toBe(receipt); expect(consumed).not.toBe(options.receipt); expect(consumed).toEqual(expected);
    expect(canonicalJson(consumed)).toBe(before);
  });
  it("preserves canonical body/signature/digests and result shape for valid captured data", () => {
    const { receipt, options } = fixture(); const before = canonicalJson(receipt);
    const captured = captureJsonData(receipt); assertAlphaIntegrityReceipt(captured);
    expect(canonicalJson(captured)).toBe(before); expect(captured.signature).toEqual(receipt.signature);
    expect(recheckReceipt(options)).toEqual({ protocolVersion: "1-alpha", status: "PASS", findings: [], receiptDigest: receipt.receiptDigest, envelopeDigest: receipt.envelopeDigest });
    expect(options.receiptStore.consume).not.toHaveBeenCalled(); expect(canonicalJson(receipt)).toBe(before);
  });
  it.each(["missing", "accessor", "extra", "nested-accessor"])("rejects %s before source or consume without getters", async kind => {
    const { receipt, options } = fixture(); let reads = 0;
    if (kind === "missing") delete options.receipt;
    if (kind === "accessor") Object.defineProperty(options, "receipt", { get() { reads++; return receipt; } });
    if (kind === "extra") receipt.extra = true;
    if (kind === "nested-accessor") Object.defineProperty(receipt.verification, "status", { get() { reads++; return "PASS"; }, enumerable: true });
    live.verify.mockReset();
    for (const result of [recheckReceipt(options), await recheckTrustedReceipt(options)]) {
      expect(result.status).toBe("BLOCKED"); expect(result.findings[0].code).toBe("checker.failure"); expect(result.receiptDigest).toBeUndefined(); expect(result.envelopeDigest).toBeUndefined();
    }
    expect(reads).toBe(0); expect(live.verify).not.toHaveBeenCalled(); expect(options.receiptStore.consume).not.toHaveBeenCalled();
  });
  it("does not spread or read unrelated options during failed admission", async () => {
    const options: any = { receipt: null }; let reads = 0;
    Object.defineProperty(options, "unrelated", { get() { reads++; throw new Error("sentinel"); }, enumerable: true });
    expect(recheckReceipt(options).findings[0].code).toBe("checker.failure");
    expect((await recheckTrustedReceipt(options)).findings[0].code).toBe("checker.failure"); expect(reads).toBe(0);
  });
  it("keeps schema signature syntax separate from canonical decoded bytes", () => {
    const { receipt, options } = fixture(); receipt.signature.value = "A".repeat(85) + "B==";
    assertAlphaIntegrityReceipt(receipt);
    expect(recheckReceipt(options).findings.map(f => f.code)).toContain("receipt.invalid_signature_encoding");
  });
  it("keeps schema-valid leap seconds separate from existing Date.parse semantics", () => {
    const { receipt, options } = fixture(); receipt.createdAt = "2026-10-11T23:59:60Z";
    assertAlphaIntegrityReceipt(receipt);
    expect(recheckReceipt(options).findings.map(f => f.code)).toContain("receipt.invalid_time");
  });
});
