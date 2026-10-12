import type { AlphaIntegrityReceipt, EnvelopeVerificationResult } from "@agent-integrity/protocol";
import type { RecheckTrustedReceiptOptions } from "../../src/receipts/recheck-receipt.js";
import { generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { canonicalJson } from "../../src/canonical-json.js";
import { sha256Canonical } from "../../src/hash.js";
import { verifyEnvelope } from "../../src/verify.js";
import { assertAlphaIntegrityReceipt } from "../../src/schema/validate-receipt.js";
import { captureJsonData } from "../../src/capture-json.js";
const live = vi.hoisted(() => ({ verify: vi.fn() }));
vi.mock("../../src/verify-trusted.js", () => ({ verifyTrustedEnvelope: live.verify }));
import { recheckReceipt, recheckTrustedReceipt, validateTrustedReceipt } from "../../src/receipts/recheck-receipt.js";

// Supported synthetic subject from the independently reproduced C control, no stores/files written.
import { validEnvelope } from "../support/valid-envelope.js";
const envelope = validEnvelope();
const policy = envelope.policy;
function fixture() {
  const keys = generateKeyPairSync("ed25519");
  const verification = verifyEnvelope(envelope);
  const body: Omit<AlphaIntegrityReceipt, "signature" | "receiptDigest"> = { protocolVersion: "1-alpha", receiptVersion: "2-alpha", engineVersion: "1", issuer: "i", audience: "a", purpose: "p", nonce: "n", runId: "r", createdAt: "2026-10-11T17:00:00Z", expiresAt: "2026-10-11T18:00:00Z", policyDigest: sha256Canonical(policy), envelopeDigest: verification.envelopeDigest!, verification: { protocolVersion: "1-alpha", status: verification.status, findings: verification.findings } };
  const signature = { algorithm: "Ed25519" as const, keyId: "k", value: sign(null, Buffer.from(canonicalJson({ protected: { algorithm: "Ed25519", keyId: "k" }, body })), keys.privateKey).toString("base64") };
  const signed = { ...body, signature };
  const receipt: AlphaIntegrityReceipt = { ...signed, receiptDigest: sha256Canonical(signed) };
  const options: RecheckTrustedReceiptOptions = { receipt, envelope, context: {} as RecheckTrustedReceiptOptions["context"], now: new Date("2026-10-11T17:30:00Z"), trust: { keys: { k: keys.publicKey.export({ type: "spki", format: "pem" }).toString() }, issuer: "i", audience: "a", purpose: "p", engineVersion: "1", trustedPolicy: policy }, receiptStore: { consume: vi.fn().mockResolvedValue(undefined) } as unknown as NonNullable<RecheckTrustedReceiptOptions["receiptStore"]> };
  return { receipt, options, verification, consume: vi.mocked(options.receiptStore!.consume) };
}
describe("receipt-only ownership and admission", () => {
  it("retains admitted private identity/content across deterministic source await", async () => {
    const { receipt, options, verification, consume } = fixture();
    expect(verification.status).toBe("PASS");
    const before = canonicalJson(receipt); const expected = JSON.parse(before);
    let finish!: (value: EnvelopeVerificationResult) => void;
    live.verify.mockReset().mockImplementation(() => new Promise(resolve => { finish = resolve; }));
    const baseline = recheckReceipt(options); expect(baseline.status).toBe("PASS");
    expect(canonicalJson(receipt)).toBe(before);
    const pending = recheckTrustedReceipt(options);
    expect(live.verify).toHaveBeenCalledOnce();
    Object.defineProperty(options, "receipt", { value: { replacement: true } });
    Object.defineProperty(receipt.verification, "status", { value: "BLOCKED" });
    Object.defineProperty(receipt.signature, "value", { value: "changed" });
    const callerAfter = canonicalJson(receipt);
    finish(verification); const result = await pending;
    expect(result).toEqual(baseline); expect(canonicalJson(receipt)).toBe(callerAfter);
    expect(consume).toHaveBeenCalledOnce();
    const consumed = consume.mock.calls[0]![0];
    expect(consumed).not.toBe(receipt); expect(consumed).not.toBe(options.receipt); expect(consumed).toEqual(expected);
    expect(canonicalJson(consumed)).toBe(before);
  });
  it("validates one pre-await capture without consuming an extra store capability", async () => {
    const { receipt, options, verification, consume } = fixture();
    const baseline = recheckReceipt(options);
    let finish!: (value: EnvelopeVerificationResult) => void;
    live.verify.mockReset().mockImplementation(() => new Promise(resolve => { finish = resolve; }));
    const pending = validateTrustedReceipt(options);
    expect(live.verify).toHaveBeenCalledOnce();
    Object.defineProperty(options, "receipt", { get() { throw new Error("post-await reread"); } });
    Object.defineProperty(receipt.verification, "status", { value: "BLOCKED" });
    Object.defineProperty(receipt.signature, "value", { value: "changed" });
    finish(verification);
    expect(await pending).toEqual(baseline);
    expect(consume).not.toHaveBeenCalled();
  });

  it("requires a store for an otherwise valid admitted PASS and retains digests", async () => {
    const { options, verification, consume } = fixture();
    live.verify.mockReset().mockResolvedValue(verification);
    Reflect.deleteProperty(options, "receiptStore");
    const result = await recheckTrustedReceipt(options);
    expect(result.status).toBe("BLOCKED");
    expect(result.findings.map(finding => finding.code)).toEqual(["receipt.store_required"]);
    expect(result.receiptDigest).toBe(options.receipt.receiptDigest);
    expect(result.envelopeDigest).toBe(options.receipt.envelopeDigest);
    expect(consume).not.toHaveBeenCalled();
  });

  it("maps store refusal to replay without losing admitted digests", async () => {
    const { options, verification, consume } = fixture();
    live.verify.mockReset().mockResolvedValue(verification);
    consume.mockRejectedValueOnce(new Error("already consumed"));
    const result = await recheckTrustedReceipt(options);
    expect(result.status).toBe("BLOCKED");
    expect(result.findings.map(finding => finding.code)).toEqual(["receipt.replayed"]);
    expect(result.receiptDigest).toBe(options.receipt.receiptDigest);
    expect(result.envelopeDigest).toBe(options.receipt.envelopeDigest);
    expect(consume).toHaveBeenCalledOnce();
  });

  it.each(["REVIEW", "BLOCKED", "missing-digest", "throw"] as const)("does not consume on live source %s", async kind => {
    const { options, verification, consume } = fixture();
    live.verify.mockReset();
    if (kind === "throw") live.verify.mockRejectedValue(new Error("source failed"));
    else live.verify.mockResolvedValue(kind === "missing-digest"
      ? { protocolVersion: "1-alpha", status: "BLOCKED", findings: [] }
      : { ...verification, status: kind, findings: [{ code: "source.changed", severity: kind === "REVIEW" ? "review" : "blocked", message: "Source changed" }] });
    const result = await recheckTrustedReceipt(options);
    expect(result.status).not.toBe("PASS");
    expect(consume).not.toHaveBeenCalled();
    if (kind === "throw") {
      expect(result.findings[0]!.code).toBe("checker.failure");
      expect(result.receiptDigest).toBeUndefined();
    } else expect(result.receiptDigest).toBe(options.receipt.receiptDigest);
    if (kind === "missing-digest") {
      expect(result.findings.map(finding => finding.code)).toContain("receipt.live_source_check_failed");
      expect(result.envelopeDigest).toBeUndefined();
    }
  });

  it("preserves canonical body/signature/digests and result shape for valid captured data", () => {
    const { receipt, options } = fixture(); const before = canonicalJson(receipt);
    const captured = captureJsonData(receipt); assertAlphaIntegrityReceipt(captured);
    expect(canonicalJson(captured)).toBe(before); expect(captured.signature).toEqual(receipt.signature);
    expect(recheckReceipt(options)).toEqual({ protocolVersion: "1-alpha", status: "PASS", findings: [], receiptDigest: receipt.receiptDigest, envelopeDigest: receipt.envelopeDigest });
    expect(options.receiptStore!.consume).not.toHaveBeenCalled(); expect(canonicalJson(receipt)).toBe(before);
  });
  it.each(["missing", "accessor", "extra", "nested-accessor"])("rejects %s before source or consume without getters", async kind => {
    const { receipt, options } = fixture(); let reads = 0;
    if (kind === "missing") Reflect.deleteProperty(options, "receipt");
    if (kind === "accessor") Object.defineProperty(options, "receipt", { get() { reads++; return receipt; } });
    if (kind === "extra") Object.defineProperty(receipt, "extra", { value: true, enumerable: true });
    if (kind === "nested-accessor") Object.defineProperty(receipt.verification, "status", { get() { reads++; return "PASS"; }, enumerable: true });
    live.verify.mockReset();
    for (const result of [recheckReceipt(options), await recheckTrustedReceipt(options), await validateTrustedReceipt(options)]) {
      expect(result.status).toBe("BLOCKED"); expect(result.findings[0]!.code).toBe("checker.failure"); expect(result.receiptDigest).toBeUndefined(); expect(result.envelopeDigest).toBeUndefined();
    }
    expect(reads).toBe(0); expect(live.verify).not.toHaveBeenCalled(); expect(options.receiptStore!.consume).not.toHaveBeenCalled();
  });
  it("does not spread or read unrelated options during failed admission", async () => {
    const options = { receipt: null } as unknown as RecheckTrustedReceiptOptions; let reads = 0;
    Object.defineProperty(options, "unrelated", { get() { reads++; throw new Error("sentinel"); }, enumerable: true });
    expect(recheckReceipt(options).findings[0]!.code).toBe("checker.failure");
    expect((await recheckTrustedReceipt(options)).findings[0]!.code).toBe("checker.failure"); expect(reads).toBe(0);
  });
  it("keeps schema signature syntax separate from canonical decoded bytes", () => {
    const { receipt, options } = fixture(); Object.defineProperty(receipt.signature, "value", { value: "A".repeat(85) + "B==" });
    assertAlphaIntegrityReceipt(receipt);
    expect(recheckReceipt(options).findings.map(f => f.code)).toContain("receipt.invalid_signature_encoding");
  });
  it("keeps schema-valid leap seconds separate from existing Date.parse semantics", () => {
    const { receipt, options } = fixture(); Object.defineProperty(receipt, "createdAt", { value: "2026-10-11T23:59:60Z" });
    assertAlphaIntegrityReceipt(receipt);
    expect(recheckReceipt(options).findings.map(f => f.code)).toContain("receipt.invalid_time");
  });
});
