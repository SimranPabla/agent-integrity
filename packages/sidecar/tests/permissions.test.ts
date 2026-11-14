import { chmod, symlink, lstat, link } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { SidecarConfigManager } from "../src/index.js";
import { NOW, task6Fixture } from "./support/task6-fixture.js";

describe("sidecar filesystem identities and private keys", () => {
  it("accepts the exact private layout and matching active receipt key", async () => {
    const fixture = await task6Fixture();
    const manager = new SidecarConfigManager(fixture.configPath, fixture.options);
    await expect(manager.loadInitial()).resolves.toMatchObject({ receipt: { activeKeyId: "receipt-1" } });
    expect(manager.selectSigningKey(NOW).kid).toBe("receipt-1");
  });

  it("rejects broad secret permissions and symlinked key files", async () => {
    const broad = await task6Fixture(); await chmod(broad.paths.receiptKeyPath, 0o440);
    await expect(new SidecarConfigManager(broad.configPath, broad.options).loadInitial()).rejects.toThrow(/mode|permission/u);
    const linked = await task6Fixture(); const target = join(linked.root, "linked.pem"); await symlink(linked.paths.receiptKeyPath, target);
    linked.config.receipt.privateKeys[0]!.privateKeyFile = target;
    await linked.save();
    await expect(new SidecarConfigManager(linked.configPath, linked.options).loadInitial()).rejects.toThrow(/symlink|key/u);
  });

  it("rejects mismatched, expired, or revoked active signing keys", async () => {
    const mismatch = await task6Fixture(); mismatch.config.receipt.publicKeys[0]!.x = mismatch.authority.publicX;
    await mismatch.save();
    await expect(new SidecarConfigManager(mismatch.configPath, mismatch.options).loadInitial()).rejects.toThrow(/match|public/u);
    const expired = await task6Fixture(); expired.config.receipt.publicKeys[0]!.notAfter = NOW.toISOString();
    await expired.save();
    await expect(new SidecarConfigManager(expired.configPath, expired.options).loadInitial()).rejects.toThrow(/active|expired|valid/u);
    const revoked = await task6Fixture(); revoked.config.receipt.publicKeys[0]!.revokedAt = "2026-09-29T17:30:00.000Z";
    await revoked.save();
    await expect(new SidecarConfigManager(revoked.configPath, revoked.options).loadInitial()).rejects.toThrow(/revoked|active/u);
  });

  it("keeps a referenced recovery private key across reload and removes it after release", async () => {
    const fixture = await task6Fixture(); const manager = new SidecarConfigManager(fixture.configPath, fixture.options); await manager.loadInitial();
    const release = manager.retainRecoveryKey("receipt-1");
    fixture.config.receipt.privateKeys = [{ kid: "receipt-2", privateKeyFile: fixture.paths.authorityKeyPath }]; fixture.config.receipt.activeKeyId = "receipt-2";
    fixture.config.receipt.publicKeys.push({ kid: "receipt-2", x: fixture.authority.publicX, notBefore: "2026-09-29T17:00:00.000Z", notAfter: "2026-09-30T17:00:00.000Z", revokedAt: null });
    fixture.config.receipt.publicKeys.sort((left, right) => left.kid.localeCompare(right.kid));
    fixture.config.manifest.generation = 2;
    await fixture.save();
    await expect(manager.reload()).resolves.toMatchObject({ receipt: { activeKeyId: "receipt-2" } });
    expect(manager.recoverySigningKey("receipt-1").kid).toBe("receipt-1");
    fixture.config.manifest.generation = 3; await fixture.save(); await manager.reload();
    fixture.config.manifest.generation = 4; await fixture.save(); await manager.reload();
    expect(manager.recoverySigningKey("receipt-1").kid).toBe("receipt-1");
    release(); release(); expect(() => manager.recoverySigningKey("receipt-1")).toThrow(/unavailable/u);
  });
});

describe("injected Unix permission rejection", () => {
  it.each(["owner", "group", "mode", "parent", "membership", "same-identity"])("rejects unsafe %s", async (kind) => {
    const f = await task6Fixture();
    const options = { ...f.options, stat: async (path: string) => {
      const info = await f.options.stat(path);
      if (path === f.paths.socketDirectory) {
        if (kind === "owner") info.uid += 1;
        if (kind === "group") info.gid += 1;
        if (kind === "mode") info.mode |= 0o020;
      }
      if (kind === "parent" && path === f.root) info.mode |= 0o020;
      return info;
    } };
    if (kind === "membership") options.identity = () => ({ uid: f.config.identities.sidecarUid, gid: f.config.identities.sidecarGid + 1, groups: [] });
    if (kind === "same-identity") { f.config.identities.cageUid = f.config.identities.sidecarUid; await f.save(); }
    await expect(new SidecarConfigManager(f.configPath, options).loadInitial()).rejects.toThrow(/identity|group|ownership|permission|parent/);
  });
  it("rejects hardlinked secrets and symlinked ancestors", async () => {
    const f = await task6Fixture(); await link(f.paths.receiptKeyPath, join(f.root, "other.pem"));
    await expect(new SidecarConfigManager(f.configPath, f.options).loadInitial()).rejects.toThrow(/link/);
    const g = await task6Fixture();
    await expect(new SidecarConfigManager(g.configPath, { ...g.options, resolve: async (path) => path === g.paths.stateRoot ? path + "-different" : path }).loadInitial()).rejects.toThrow(/parent|path/);
  });
});


describe("exact client group boundary", () => {
  it.each(["extra", "missing-cage", "missing-sidecar", "duplicate", "unresolved"])("rejects %s membership", async (kind) => {
    const f = await task6Fixture(); const { sidecarUid: s, cageUid: c } = f.config.identities;
    const groupMembers = async () => { if (kind === "unresolved") throw new Error("group resolution failed"); return kind === "extra" ? [s, c, c + 1] : kind === "missing-cage" ? [s] : kind === "missing-sidecar" ? [c] : [s, s]; };
    await expect(new SidecarConfigManager(f.configPath, { ...f.options, groupMembers }).loadInitial()).rejects.toThrow(/group/);
  });
  it("accepts the exact set and own primary membership without supplementary duplication", async () => {
    const f = await task6Fixture();
    await expect(new SidecarConfigManager(f.configPath, { ...f.options, identity: () => ({ uid: f.config.identities.sidecarUid, gid: f.config.identities.sidecarGid, groups: [] }) }).loadInitial()).resolves.toBeDefined();
  });
});

describe("owner-only configuration modes", () => {
  it.each([0o400, 0o600])("accepts %s", async (mode) => { const f = await task6Fixture(); await chmod(f.configPath, mode); await expect(new SidecarConfigManager(f.configPath, f.options).loadInitial()).resolves.toBeDefined(); });
  it.each([0o000, 0o200, 0o440, 0o640, 0o604, 0o700, 0o4600, 0o2600, 0o1600])("rejects %s", async (mode) => { const f = await task6Fixture(); await chmod(f.configPath, mode); await expect(new SidecarConfigManager(f.configPath, f.options).loadInitial()).rejects.toThrow(/mode|permission/); });
  it("still rejects writable private secrets", async () => { const f = await task6Fixture(); await chmod(f.paths.hmacPath, 0o600); await expect(new SidecarConfigManager(f.configPath, f.options).loadInitial()).rejects.toThrow(/mode|permission/); });
});
