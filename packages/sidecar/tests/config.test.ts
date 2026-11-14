import { writeFile } from "node:fs/promises";
import { canonicalJson } from "@agent-integrity/core";
import { describe, expect, it } from "vitest";
import { SidecarConfigManager, parseSidecarConfig, authenticateRequest } from "../src/index.js";
import { NOW, task6Fixture } from "./support/task6-fixture.js";

describe("closed sidecar configuration", () => {
  it("loads only an explicit closed file and returns a deeply frozen redacted snapshot", async () => {
    const fixture = await task6Fixture();
    process.env.AGENT_INTEGRITY_CONFIG = "/must/not/be/read";
    const manager = new SidecarConfigManager(fixture.configPath, fixture.options);
    const snapshot = await manager.loadInitial();
    expect(snapshot.paths).toMatchObject({ socketPath: fixture.config.paths.socketPath, bundleRoot: fixture.config.paths.bundleRoot, stateRoot: fixture.config.paths.stateRoot });
    expect(snapshot.stateChildren).toEqual({ lease: "lease", nonces: "nonces", receipts: "receipts", requests: "requests", snapshots: "snapshots", transactions: "transactions" });
    expect(snapshot.client.clientId).toBe("cage");
    expect(snapshot).not.toHaveProperty("secret");
    expect(canonicalJson(snapshot)).not.toContain("0123456789abcdef");
    expect(Object.isFrozen(snapshot)).toBe(true); expect(Object.isFrozen(snapshot.limits)).toBe(true);
    delete process.env.AGENT_INTEGRITY_CONFIG;
  });

  it("rejects unknown fields, relative paths, extra clients, and invalid bounds", async () => {
    const fixture = await task6Fixture();
    expect(() => parseSidecarConfig({ ...fixture.config, unknown: true })).toThrow(/unknown|configuration/u);
    expect(() => parseSidecarConfig({ ...fixture.config, paths: { ...fixture.config.paths, stateRoot: "relative" } })).toThrow(/absolute|path/u);
    expect(() => parseSidecarConfig({ ...fixture.config, client: [fixture.config.client, fixture.config.client] })).toThrow(/client|configuration/u);
    expect(() => parseSidecarConfig({ ...fixture.config, limits: { ...fixture.config.limits, maximumRequestBytes: 0 } })).toThrow(/limit|configuration/u);
  });

  it("preserves the last valid immutable snapshot when reload fails and atomically swaps a valid generation", async () => {
    const fixture = await task6Fixture();
    const manager = new SidecarConfigManager(fixture.configPath, fixture.options);
    const initial = await manager.loadInitial();
    await writeFile(fixture.configPath, "{}", { mode: 0o600 });
    await expect(manager.reload()).rejects.toThrow(/configuration/u);
    expect(manager.current()).toBe(initial);
    await writeFile(fixture.configPath, canonicalJson({ ...fixture.config, manifest: { ...fixture.config.manifest, generation: 2 } }), { mode: 0o600 });
    const updated = await manager.reload();
    expect(updated.manifest.generation).toBe(2); expect(manager.current()).toBe(updated); expect(updated).not.toBe(initial);
  });
});

describe("configuration lifecycle regressions", () => {
  it("rejects non-adjacent HMAC overlap, invalid generation, and hard ceiling violations", async () => {
    const f = await task6Fixture();
    for (const value of [0, "store/escape", null]) expect(() => parseSidecarConfig({ ...f.config, storeGeneration: value })).toThrow();
    for (const [field, value] of [["maximumTimestampSkewMs", 60_001], ["maximumBundleLifetimeMs", 900_001], ["maximumEnvelopeBytes", 2_000_000]]) expect(() => parseSidecarConfig({ ...f.config, limits: { ...f.config.limits, [field as string]: value } })).toThrow();
    const key = f.config.client.hmacKeys[0]!;
    const hmacKeys = [{ ...key, kid: "a" }, { ...key, kid: "b", notBefore: "2026-09-30T16:59:00.000Z", notAfter: "2026-09-30T17:01:00.000Z" }, { ...key, kid: "c" }];
    expect(() => parseSidecarConfig({ ...f.config, client: { ...f.config.client, hmacKeys } })).toThrow(/overlap/);
  });
  it("swaps both registries and preserves the previous snapshot on missing historical keys", async () => {
    const f = await task6Fixture(); const manager = new SidecarConfigManager(f.configPath, f.options); await manager.loadInitial();
    const initialHmac = manager.hmacRegistry(); const initialReceipt = manager.keyRegistry();
    f.config.client.hmacKeys[0]!.kid = "hmac-2"; f.config.manifest.generation = 2; await f.save(); await manager.reload();
    expect(manager.hmacRegistry()).not.toBe(initialHmac); expect(manager.keyRegistry()).not.toBe(initialReceipt);
    expect(manager.hmacRegistry().clients.cage!.keys).toHaveProperty("hmac-2");
    const current = manager.current(); const keys = manager.keyRegistry(); const hmacBeforeFailure = manager.hmacRegistry(); const authorityBeforeFailure = manager.manifestAuthority();
    f.config.receipt.privateKeys = [{ kid: "receipt-2", privateKeyFile: f.paths.authorityKeyPath }]; f.config.receipt.activeKeyId = "receipt-2";
    f.config.receipt.publicKeys = [{ ...f.config.receipt.publicKeys[0]!, kid: "receipt-2", x: f.authority.publicX }]; f.config.manifest.generation = 3;
    await f.save(); await expect(manager.reload()).rejects.toThrow(/historical/);
    expect(manager.hmacRegistry()).toEqual(hmacBeforeFailure); expect(manager.manifestAuthority()).toBe(authorityBeforeFailure);
    expect(manager.current()).toBe(current); expect(manager.keyRegistry()).toBe(keys);
  });
  it("rejects deployment changes, rollback, stale manifests, and unavailable HMAC keys", async () => {
    const f = await task6Fixture(); const manager = new SidecarConfigManager(f.configPath, f.options); await manager.loadInitial();
    f.config.storeGeneration = "store-2"; await f.save(); await expect(manager.reload()).rejects.toThrow(/identity/);
    f.config.storeGeneration = "store-1"; f.config.manifest.validUntil = NOW.toISOString(); await f.save(); await expect(manager.reload()).rejects.toThrow(/validity/);
    f.config.manifest.validUntil = "2026-09-29T19:00:00.000Z"; f.config.client.hmacKeys[0]!.revokedAt = NOW.toISOString(); await f.save(); await expect(manager.reload()).rejects.toThrow(/HMAC/);
  });
  it("rejects expiry at selection time and returns immutable canonical public metadata", async () => {
    const f = await task6Fixture(); const manager = new SidecarConfigManager(f.configPath, f.options); await manager.loadInitial();
    expect(() => manager.selectSigningKey(new Date(f.config.receipt.publicKeys[0]!.notAfter))).toThrow(/validity/);
    const publicKeys = manager.keyRegistry().publicSnapshot(); expect(Object.isFrozen(publicKeys)).toBe(true); expect(Object.isFrozen(publicKeys[0])).toBe(true);
    expect(canonicalJson(publicKeys)).not.toContain("PRIVATE");
  });
});

it("supplies a runtime-compatible HMAC registry", async () => {
  const f = await task6Fixture(); const m = new SidecarConfigManager(f.configPath, f.options); await m.loadInitial();
  const exposed = m.hmacRegistry().clients.cage!.keys["hmac-1"]!.secret; exposed.fill(0);
  expect(m.hmacRegistry().clients.cage!.keys["hmac-1"]!.secret[0]).toBe(48);
  expect(() => authenticateRequest({ request: {} as any, method: "POST", path: "/v1/verify-release", headers: { clientId: "cage", keyId: "unknown", timestampMs: String(NOW.getTime()), nonce: "nonce", mac: "a".repeat(43) }, nowMs: NOW.getTime(), maximumSkewMs: 1000, registry: m.hmacRegistry() })).toThrow("authentication key is inactive");
});


describe("scheduled HMAC revocation", () => {
  it("permits startup before revocation and rejects it at the exact boundary", async () => {
    const f = await task6Fixture(); const revokedAt = new Date(NOW.getTime() + 60_000);
    f.config.client.hmacKeys[0]!.revokedAt = revokedAt.toISOString(); await f.save();
    await expect(new SidecarConfigManager(f.configPath, f.options).loadInitial()).resolves.toBeDefined();
    await expect(new SidecarConfigManager(f.configPath, { ...f.options, now: () => revokedAt }).loadInitial()).rejects.toThrow(/HMAC/);
  });
  it("accepts a future revocation reload then preserves all material at the boundary", async () => {
    const f = await task6Fixture(); let now = NOW; const m = new SidecarConfigManager(f.configPath, { ...f.options, now: () => now }); await m.loadInitial();
    const revokedAt = new Date(NOW.getTime() + 60_000); f.config.client.hmacKeys[0]!.revokedAt = revokedAt.toISOString(); await f.save();
    await expect(m.reload()).resolves.toBeDefined();
    const snapshot = m.current(); const hmac = m.hmacRegistry(); const receipt = m.keyRegistry(); const authority = m.manifestAuthority();
    now = revokedAt; await expect(m.reload()).rejects.toThrow(/HMAC/);
    expect(m.current()).toBe(snapshot); expect(m.hmacRegistry()).toEqual(hmac); expect(m.keyRegistry()).toBe(receipt); expect(m.manifestAuthority()).toBe(authority);
  });
});

describe("reload generation and atomicity", () => {
  it.each(["issuer", "audience", "purpose", "engineVersion", "lifetime", "public-addition", "revocation", "issuedAt", "validUntil", "future-skew", "authority-id", "authority-key"])("rejects same-generation %s changes preserving all registries", async (kind) => {
    const f = await task6Fixture();
    f.config.receipt.publicKeys.push({ ...f.config.receipt.publicKeys[0]!, kid: "receipt-2", x: f.authority.publicX }); await f.save();
    const m = new SidecarConfigManager(f.configPath, f.options); const snapshot = await m.loadInitial();
    const hmac = m.hmacRegistry(); const receipt = m.keyRegistry(); const authority = m.manifestAuthority();
    if (["issuer", "audience", "purpose", "engineVersion"].includes(kind)) (f.config.receipt as any)[kind] += "-changed";
    if (kind === "lifetime") f.config.receipt.maximumReceiptLifetimeSeconds += 1;
    if (kind === "public-addition") f.config.receipt.publicKeys.push({ ...f.config.receipt.publicKeys[0]!, kid: "receipt-3" });
    if (kind === "revocation") f.config.receipt.publicKeys[1]!.revokedAt = NOW.toISOString();
    if (kind === "issuedAt") f.config.manifest.issuedAt = "2026-09-29T17:56:00.000Z";
    if (kind === "validUntil") f.config.manifest.validUntil = "2026-09-29T20:00:00.000Z";
    if (kind === "future-skew") f.config.manifest.maximumFutureSkewSeconds += 1;
    if (kind === "authority-id") f.config.manifest.authorityKeyId = "authority-2";
    if (kind === "authority-key") { f.config.manifest.authorityPrivateKeyFile = f.paths.receiptKeyPath; f.config.manifest.authorityPublicX = f.receipt.publicX; }
    f.config.client.hmacKeys[0]!.kid = "hmac-2"; await f.save();
    await expect(m.reload()).rejects.toThrow(/increased generation/);
    expect(m.current()).toBe(snapshot); expect(m.keyRegistry()).toBe(receipt); expect(m.manifestAuthority()).toBe(authority); expect(m.hmacRegistry()).toEqual(hmac);
    f.config.manifest.generation += 1; await f.save(); await expect(m.reload()).resolves.toBeDefined();
  });
  it("allows identical manifests and nonmanifest changes without advancing generation", async () => {
    const f = await task6Fixture(); const m = new SidecarConfigManager(f.configPath, f.options); await m.loadInitial(); await m.reload();
    f.config.client.hmacKeys[0]!.kid = "hmac-2"; f.config.limits.gracefulShutdownMs += 1; await f.save();
    await expect(m.reload()).resolves.toMatchObject({ manifest: { generation: 1 } }); expect(m.hmacRegistry().clients.cage!.keys).toHaveProperty("hmac-2");
  });
  it("explicitly rejects a lower generation and preserves all active material", async () => {
    const f = await task6Fixture(); f.config.manifest.generation = 2; await f.save(); const m = new SidecarConfigManager(f.configPath, f.options); const snapshot = await m.loadInitial();
    const hmac = m.hmacRegistry(); const receipt = m.keyRegistry(); const authority = m.manifestAuthority();
    f.config.manifest.generation = 1; await f.save(); await expect(m.reload()).rejects.toThrow(/rollback/);
    expect(m.current()).toBe(snapshot); expect(m.keyRegistry()).toBe(receipt); expect(m.manifestAuthority()).toBe(authority); expect(m.hmacRegistry()).toEqual(hmac);
  });
  it("reproduces rejection of __proto__ without weakening identifier grammar", async () => {
    const f = await task6Fixture();
    expect(() => parseSidecarConfig({ ...f.config, client: { ...f.config.client, clientId: "__proto__" } })).toThrow(/client ID/);
    expect(() => parseSidecarConfig({ ...f.config, client: { ...f.config.client, hmacKeys: [{ ...f.config.client.hmacKeys[0]!, kid: "__proto__" }] } })).toThrow(/key ID/);
  });
  it.each(["constructor", "toString"])("supports valid special identifier %s as an own HMAC registry key", async (id) => {
    const f = await task6Fixture(); f.config.client.clientId = id; f.config.client.hmacKeys[0]!.kid = id; await f.save(); const m = new SidecarConfigManager(f.configPath, f.options); await m.loadInitial();
    const clients = m.hmacRegistry().clients; expect(Object.hasOwn(clients, id)).toBe(true); expect(Object.hasOwn(clients[id]!.keys, id)).toBe(true); expect(clients[id]!.keys[id]!.secret.byteLength).toBe(32);
  });
});
