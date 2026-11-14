import { createPublicKey, sign, verify } from "node:crypto";
import { canonicalJson } from "@agent-integrity/core";
import { describe, expect, it } from "vitest";
import { SidecarConfigManager, createCageTrustManifest, parseCageTrustManifest, CAGE_MANIFEST_EXTENSION } from "../src/index.js";
import { NOW, task6Fixture } from "./support/task6-fixture.js";

describe("signed CAGE RFC 7517 trust manifest", () => {
  it("exports canonical public-only Ed25519 JWKS accepted by CAGE's current parser shape", async () => {
    const fixture = await task6Fixture(); const manager = new SidecarConfigManager(fixture.configPath, fixture.options); await manager.loadInitial();
    const bytes = createCageTrustManifest(manager.keyRegistry(), manager.manifestAuthority(), manager.current().manifest, manager.current().receipt);
    expect(Buffer.from(canonicalJson(JSON.parse(bytes.toString("utf8"))))).toEqual(bytes);
    const raw = JSON.parse(bytes.toString("utf8"));
    expect(raw.keys).toEqual([{ alg: "EdDSA", crv: "Ed25519", kid: "receipt-1", kty: "OKP", use: "sig", x: fixture.receipt.publicX }]);
    expect(bytes.toString("utf8")).not.toContain('"d"');
    const parsed = parseCageTrustManifest(bytes, { now: NOW, authorityKeys: { "authority-1": fixture.authority.publicX }, maximumFutureSkewSeconds: 60, maximumReceiptLifetimeSeconds: 3600 });
    expect(parsed.extension.generation).toBe(1); expect(Object.isFrozen(parsed)).toBe(true);
    expect(raw[CAGE_MANIFEST_EXTENSION].keyMetadata.map((entry: { kid: string }) => entry.kid)).toEqual(raw.keys.map((entry: { kid: string }) => entry.kid));
  });

  it("rejects tampering, unknown members, reordered metadata, padding, stale time, and rollback", async () => {
    const fixture = await task6Fixture(); const manager = new SidecarConfigManager(fixture.configPath, fixture.options); await manager.loadInitial();
    const bytes = createCageTrustManifest(manager.keyRegistry(), manager.manifestAuthority(), manager.current().manifest, manager.current().receipt);
    const raw = JSON.parse(bytes.toString("utf8"));
    const mutate = (change: (value: any) => void) => { const value = structuredClone(raw); change(value); return Buffer.from(canonicalJson(value)); };
    expect(() => parseCageTrustManifest(mutate((value) => { value.unknown = true; }), { now: NOW, authorityKeys: { "authority-1": fixture.authority.publicX }, maximumFutureSkewSeconds: 60, maximumReceiptLifetimeSeconds: 3600 })).toThrow(/unknown|manifest/u);
    expect(() => parseCageTrustManifest(mutate((value) => { value.keys[0].x += "="; }), { now: NOW, authorityKeys: { "authority-1": fixture.authority.publicX }, maximumFutureSkewSeconds: 60, maximumReceiptLifetimeSeconds: 3600 })).toThrow(/base64|public|JWK|digest/u);
    expect(() => parseCageTrustManifest(mutate((value) => { value[CAGE_MANIFEST_EXTENSION].generation = 0; }), { now: NOW, authorityKeys: { "authority-1": fixture.authority.publicX }, maximumFutureSkewSeconds: 60, maximumReceiptLifetimeSeconds: 3600 })).toThrow(/generation|digest|signature/u);
    expect(() => parseCageTrustManifest(bytes, { now: new Date("2026-09-29T19:00:00.000Z"), authorityKeys: { "authority-1": fixture.authority.publicX }, maximumFutureSkewSeconds: 60, maximumReceiptLifetimeSeconds: 3600 })).toThrow(/expired|fresh|valid/u);
    expect(() => parseCageTrustManifest(bytes, { now: NOW, authorityKeys: { "authority-1": fixture.authority.publicX }, maximumFutureSkewSeconds: 60, maximumReceiptLifetimeSeconds: 3600, accepted: { generation: 2, manifestDigest: "a".repeat(64) } })).toThrow(/rollback/u);
  });

  it("rejects equal-generation conflicts while accepting an identical cached pair", async () => {
    const fixture = await task6Fixture(); const manager = new SidecarConfigManager(fixture.configPath, fixture.options); await manager.loadInitial();
    const bytes = createCageTrustManifest(manager.keyRegistry(), manager.manifestAuthority(), manager.current().manifest, manager.current().receipt);
    const first = parseCageTrustManifest(bytes, { now: NOW, authorityKeys: { "authority-1": fixture.authority.publicX }, maximumFutureSkewSeconds: 60, maximumReceiptLifetimeSeconds: 3600 });
    expect(() => parseCageTrustManifest(bytes, { now: NOW, authorityKeys: { "authority-1": fixture.authority.publicX }, maximumFutureSkewSeconds: 60, maximumReceiptLifetimeSeconds: 3600, accepted: { generation: 1, manifestDigest: "b".repeat(64) } })).toThrow(/conflict/u);
    expect(parseCageTrustManifest(bytes, { now: NOW, authorityKeys: { "authority-1": fixture.authority.publicX }, maximumFutureSkewSeconds: 60, maximumReceiptLifetimeSeconds: 3600, accepted: { generation: 1, manifestDigest: first.extension.manifestDigest } }).extension.manifestDigest).toBe(first.extension.manifestDigest);
  });
});

describe("closed trust manifest adversarial matrix", () => {
  it.each(["private", "jose", "short-x", "duplicate", "missing-metadata", "extra-metadata", "wrong-kid", "metadata-unknown", "profile-unknown", "extension-unknown", "algorithm", "authority", "signature", "signature-padding", "validity", "revocation", "profile-limit"])("rejects %s", async (kind) => {
    const f = await task6Fixture(); const m = new SidecarConfigManager(f.configPath, f.options); await m.loadInitial();
    const raw = JSON.parse(createCageTrustManifest(m.keyRegistry(), m.manifestAuthority(), m.current().manifest, m.current().receipt).toString());
    const ext = raw[CAGE_MANIFEST_EXTENSION];
    switch (kind) {
      case "private": raw.keys[0].d = "secret"; break;
      case "jose": raw.keys[0].alg = "ES256"; break;
      case "short-x": raw.keys[0].x = "a".repeat(42); break;
      case "duplicate": raw.keys.push(raw.keys[0]); break;
      case "missing-metadata": ext.keyMetadata = []; break;
      case "extra-metadata": ext.keyMetadata.push(ext.keyMetadata[0]); break;
      case "wrong-kid": ext.keyMetadata[0].kid = "other"; break;
      case "metadata-unknown": ext.keyMetadata[0].extra = true; break;
      case "profile-unknown": ext.receiptProfile.extra = true; break;
      case "extension-unknown": ext.extra = true; break;
      case "algorithm": ext.signatureAlgorithm = "RSA"; break;
      case "authority": ext.authorityKeyId = "other"; break;
      case "signature": ext.signature = Buffer.alloc(64).toString("base64url"); break;
      case "signature-padding": ext.signature += "="; break;
      case "validity": ext.keyMetadata[0].notAfter = ext.keyMetadata[0].notBefore; break;
      case "revocation": ext.keyMetadata[0].revokedAt = ext.keyMetadata[0].notAfter; break;
      case "profile-limit": ext.receiptProfile.maximumReceiptLifetimeSeconds = 3601; break;
    }
    expect(() => parseCageTrustManifest(Buffer.from(canonicalJson(raw)), { now: NOW, authorityKeys: { "authority-1": f.authority.publicX }, maximumFutureSkewSeconds: 60, maximumReceiptLifetimeSeconds: 3600 })).toThrow();
  });
  it("binds sorted multi-key metadata and isolates returned canonical bytes", async () => {
    const f = await task6Fixture(); f.config.receipt.publicKeys.push({ ...f.config.receipt.publicKeys[0]!, kid: "receipt-2", x: f.authority.publicX }); await f.save();
    const m = new SidecarConfigManager(f.configPath, f.options); await m.loadInitial(); const bytes = createCageTrustManifest(m.keyRegistry(), m.manifestAuthority(), m.current().manifest, m.current().receipt);
    const options = { now: NOW, authorityKeys: { "authority-1": f.authority.publicX }, maximumFutureSkewSeconds: 60, maximumReceiptLifetimeSeconds: 3600 };
    const parsed = parseCageTrustManifest(bytes, options); const changed = parsed.canonicalBytes; changed[0] = 0; expect(Buffer.from(parsed.canonicalBytes)).toEqual(bytes);
    const raw = JSON.parse(bytes.toString()); raw[CAGE_MANIFEST_EXTENSION].keyMetadata.reverse(); expect(() => parseCageTrustManifest(Buffer.from(canonicalJson(raw)), options)).toThrow(/ordering/);
    // Fixture for the partner's existing generic keys/OKP/Ed25519/x/kid contract.
    const genericKeys = raw.keys.filter((key: any) => key.kty === "OKP" && key.crv === "Ed25519" && typeof key.x === "string" && typeof key.kid === "string");
    expect(genericKeys).toHaveLength(2);
    for (const key of genericKeys) {
      const decoded = Buffer.from(key.x, "base64url"); expect(decoded.byteLength).toBe(32);
      const imported = createPublicKey({ key: { kty: key.kty, crv: key.crv, x: key.x }, format: "jwk" });
      expect(imported.asymmetricKeyType).toBe("ed25519");
      const privateKey = key.kid === "receipt-1" ? m.selectSigningKey(NOW).privateKey : m.manifestAuthority().privateKey;
      const message = Buffer.from("CAGE fixture key import"); expect(verify(null, message, imported, sign(null, message, privateKey))).toBe(true);
    }
    expect(Object.isFrozen(parsed.keys[0])).toBe(true); expect(Object.isFrozen(parsed.extension.keyMetadata)).toBe(true);
  });
  it("rejects invalid acceptance ceilings and future publication using a fresh clock", async () => {
    const f = await task6Fixture(); const m = new SidecarConfigManager(f.configPath, f.options); await m.loadInitial(); const bytes = createCageTrustManifest(m.keyRegistry(), m.manifestAuthority(), m.current().manifest, m.current().receipt);
    const options = { now: NOW, authorityKeys: { "authority-1": f.authority.publicX }, maximumFutureSkewSeconds: 60, maximumReceiptLifetimeSeconds: 3600 };
    expect(() => parseCageTrustManifest(bytes, { ...options, maximumFutureSkewSeconds: NaN })).toThrow(/limits/);
    expect(() => parseCageTrustManifest(bytes, { ...options, now: new Date("2026-09-29T17:00:00.000Z") })).toThrow(/future/);
    expect(() => parseCageTrustManifest(bytes, { ...options, authorityKeys: { "authority-1": f.receipt.publicX } })).toThrow(/signature/);
  });
});
