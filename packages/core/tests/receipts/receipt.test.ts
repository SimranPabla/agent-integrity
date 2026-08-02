import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createReceipt, recheckTrustedReceipt, verifyTrustedEnvelope } from "../../src/index.js";
import { trustedEnvelopeFixture } from "../support/trusted-envelope.js";
import { receiptSigner, receiptSigningOptions, receiptTrust } from "../support/receipt-keys.js";

describe("signed alpha receipts", () => {
  it("persists a producer-authenticated content-bound receipt without overwriting", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-receipt-"));
    const path = join(directory, "run-1.json");
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const receipt = await createReceipt({
      runId: "run-1",
      path,
      envelope,
      verification,
      context,
      ...receiptSigningOptions,
      createdAt: new Date("2026-08-02T00:00:00.000Z"),
      expiresAt: new Date("2026-08-02T01:00:00.000Z"),
    });

    expect(receipt.signature.algorithm).toBe("Ed25519");
    expect(receipt.signature.keyId).toBe(receiptSigner.keyId);
    expect(receipt.envelopeDigest).toBe(verification.envelopeDigest);
    expect(JSON.parse(await readFile(path, "utf8"))).toEqual(receipt);
    await expect(createReceipt({
      runId: "run-1",
      path,
      envelope,
      verification,
      context,
      ...receiptSigningOptions,
      createdAt: new Date("2026-08-02T00:00:00.000Z"),
      expiresAt: new Date("2026-08-02T01:00:00.000Z"),
    })).rejects.toThrow(/already exists/u);
  });

  it("rejects duplicate run IDs even when a different receipt filename is supplied", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-receipt-"));
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const common = {
      runId: "same-run",
      envelope,
      verification,
      context,
      createdAt: new Date("2026-08-02T00:00:00.000Z"),
      expiresAt: new Date("2026-08-02T01:00:00.000Z"),
      runRegistryDirectory: directory,
      ...receiptSigningOptions,
    };
    await createReceipt({ ...common, path: join(directory, "first.json") });
    await expect(createReceipt({ ...common, path: join(directory, "second.json") }))
      .rejects.toThrow(/run ID already exists/u);
  });

  it("passes a fresh receipt only when all live bound content is unchanged", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-receipt-"));
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const receipt = await createReceipt({
      runId: "run-2",
      path: join(directory, "run-2.json"),
      envelope,
      verification,
      context,
      ...receiptSigningOptions,
      createdAt: new Date("2026-08-02T00:00:00.000Z"),
      expiresAt: new Date("2026-08-02T01:00:00.000Z"),
    });
    const result = await recheckTrustedReceipt({ trust: receiptTrust, receipt, envelope, context, now: new Date("2026-08-02T00:30:00.000Z") });
    expect(result.status).toBe("PASS");
  });

  it("blocks expired receipts", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-receipt-"));
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const receipt = await createReceipt({
      runId: "run-3",
      path: join(directory, "run-3.json"),
      envelope,
      verification,
      context,
      ...receiptSigningOptions,
      createdAt: new Date("2026-08-02T00:00:00.000Z"),
      expiresAt: new Date("2026-08-02T01:00:00.000Z"),
    });
    const result = await recheckTrustedReceipt({ trust: receiptTrust, receipt, envelope, context, now: new Date("2026-08-02T01:00:00.000Z") });
    expect(result.status).toBe("BLOCKED");
    expect(result.findings.map((finding) => finding.code)).toContain("receipt.expired");
  });
});
