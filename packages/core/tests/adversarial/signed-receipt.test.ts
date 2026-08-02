import { generateKeyPairSync } from "node:crypto";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createReceipt, recheckTrustedReceipt, sha256Canonical, verifyTrustedEnvelope } from "../../src/index.js";
import { receiptSigningOptions, receiptTrust } from "../support/receipt-keys.js";
import { trustedEnvelopeFixture } from "../support/trusted-envelope.js";

async function issued(runId: string) {
  const directory = await mkdtemp(join(tmpdir(), "integrity-signed-receipt-"));
  const { envelope, context } = await trustedEnvelopeFixture();
  const verification = await verifyTrustedEnvelope(envelope, context);
  const receipt = await createReceipt({
    runId, path: join(directory, `${runId}.json`), envelope, verification, context,
    ...receiptSigningOptions,
    createdAt: new Date("2026-08-02T00:00:00.000Z"),
    expiresAt: new Date("2026-08-02T01:00:00.000Z"),
  });
  return { receipt, envelope, context };
}

describe("signed receipt authentication", () => {
  it("blocks a forged body even when the attacker recomputes the public digest", async () => {
    const { receipt, envelope, context } = await issued("forgery");
    const forgedWithoutDigest = { ...receipt, audience: "attacker" };
    const { receiptDigest: _old, ...body } = forgedWithoutDigest;
    const forged = { ...body, receiptDigest: sha256Canonical(body) };
    const result = await recheckTrustedReceipt({ receipt: forged, envelope, context, trust: receiptTrust, now: new Date("2026-08-02T00:30:00.000Z") });
    expect(result.status).toBe("BLOCKED");
    expect(result.findings.map((finding) => finding.code)).toContain("receipt.invalid_signature");
  });

  it.each([
    ["wrong audience", { audience: "other" }, "receipt.wrong_audience"],
    ["wrong purpose", { purpose: "other" }, "receipt.wrong_purpose"],
    ["wrong engine", { engineVersion: "9.9.9" }, "receipt.wrong_engine"],
    ["revoked key", { revokedKeyIds: ["test-key-1"] }, "receipt.key_revoked"],
  ])("blocks %s", async (_name, override, code) => {
    const { receipt, envelope, context } = await issued(`case-${code}`);
    const result = await recheckTrustedReceipt({ receipt, envelope, context, trust: { ...receiptTrust, ...override }, now: new Date("2026-08-02T00:30:00.000Z") });
    expect(result.findings.map((finding) => finding.code)).toContain(code);
  });

  it("blocks an unknown signing key", async () => {
    const { receipt, envelope, context } = await issued("unknown-key");
    const other = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString();
    const result = await recheckTrustedReceipt({ receipt, envelope, context, trust: { ...receiptTrust, keys: { other } }, now: new Date("2026-08-02T00:30:00.000Z") });
    expect(result.findings.map((finding) => finding.code)).toContain("receipt.unknown_key");
  });

  it("rejects excessive lifetime at issuance", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-lifetime-"));
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    await expect(createReceipt({ runId: "long", path: join(directory, "long.json"), envelope, verification, context, ...receiptSigningOptions,
      createdAt: new Date("2026-08-02T00:00:00.000Z"), expiresAt: new Date("2026-08-02T02:00:00.000Z") })).rejects.toThrow(/lifetime/u);
  });

  it("blocks receipts issued too far in the future", async () => {
    const { receipt, envelope, context } = await issued("future");
    const result = await recheckTrustedReceipt({ receipt, envelope, context, trust: receiptTrust, now: new Date("2026-08-01T23:00:00.000Z") });
    expect(result.findings.map((finding) => finding.code)).toContain("receipt.future_issued");
  });
});
