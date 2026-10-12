import { generateKeyPairSync } from "node:crypto";
import { chmod, mkdir, mkdtemp, writeFile, lstat, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach } from "vitest";
import { canonicalJson } from "@agent-integrity/core";

const roots: string[] = [];
afterEach(async () => { await Promise.all(roots.splice(0).map((path) => rm(path, { recursive: true, force: true }))); });

export const NOW = new Date("2026-09-29T18:00:00.000Z");

function keyPair() {
  const pair = generateKeyPairSync("ed25519");
  const jwk = pair.publicKey.export({ format: "jwk" });
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") throw new Error("unexpected Ed25519 fixture key");
  return { privatePem: pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString(), publicX: jwk.x, publicKey: pair.publicKey };
}

export async function task6Fixture() {
  const root = await mkdtemp(join(tmpdir(), "sidecar-task6-"));
  roots.push(root);
  const socketDirectory = join(root, "socket");
  const bundleRoot = join(root, "bundles");
  const stateRoot = join(root, "state");
  await Promise.all([mkdir(socketDirectory, { mode: 0o710 }), mkdir(bundleRoot, { mode: 0o750 }), mkdir(stateRoot, { mode: 0o700 })]);
  await Promise.all(["nonces", "requests", "receipts", "transactions", "snapshots", "lease"].map((name) => mkdir(join(stateRoot, name), { mode: 0o700 })));
  await chmod(socketDirectory, 0o710); await chmod(bundleRoot, 0o750); await chmod(stateRoot, 0o700);
  const receipt = keyPair(); const authority = keyPair();
  const hmacPath = join(root, "hmac.key"); const receiptKeyPath = join(root, "receipt.pem"); const authorityKeyPath = join(root, "authority.pem");
  await writeFile(hmacPath, Buffer.from("0123456789abcdef0123456789abcdef"), { mode: 0o400 });
  await writeFile(receiptKeyPath, receipt.privatePem, { mode: 0o400 });
  await writeFile(authorityKeyPath, authority.privatePem, { mode: 0o400 });
  await Promise.all([hmacPath, receiptKeyPath, authorityKeyPath].map((path) => chmod(path, 0o400)));
  const uid = process.getuid?.() ?? 1000; const gid = process.getgid?.() ?? 1000;
  const config = {
    version: 1, storeGeneration: "store-1",
    identities: { sidecarUid: uid, sidecarGid: gid, clientGid: gid, cageUid: uid + 1 },
    paths: { socketPath: join(socketDirectory, "sidecar.sock"), bundleRoot, stateRoot },
    client: { clientId: "cage", maximumKeyOverlapSeconds: 300, hmacKeys: [{ kid: "hmac-1", secretFile: hmacPath, notBefore: "2026-09-29T17:00:00.000Z", notAfter: "2026-09-30T17:00:00.000Z", revokedAt: null }] },
    receipt: {
      activeKeyId: "receipt-1", issuer: "agent-integrity", audience: "cage", purpose: "response-release", engineVersion: "0.1.0-alpha.2", maximumReceiptLifetimeSeconds: 3600,
      privateKeys: [{ kid: "receipt-1", privateKeyFile: receiptKeyPath }],
      publicKeys: [{ kid: "receipt-1", x: receipt.publicX, notBefore: "2026-09-29T17:00:00.000Z", notAfter: "2026-09-30T17:00:00.000Z", revokedAt: null }],
    },
    manifest: { generation: 1, issuedAt: "2026-09-29T17:55:00.000Z", validUntil: "2026-09-29T19:00:00.000Z", maximumFutureSkewSeconds: 60, authorityKeyId: "authority-1", authorityPrivateKeyFile: authorityKeyPath, authorityPublicX: authority.publicX },
    limits: { maximumRequestBytes: 1_048_576, maximumEnvelopeBytes: 1_048_576, maximumSourceBytes: 1_048_576, maximumTotalSourceBytes: 8_388_608, maximumResponseBytes: 1_048_576, maximumFindings: 1000, maximumTimestampSkewMs: 30_000, maximumBundleLifetimeMs: 900_000, gracefulShutdownMs: 30_000 },
  };
  const configPath = join(root, "sidecar.json");
  await writeFile(configPath, canonicalJson(config), { mode: 0o600 }); await chmod(configPath, 0o600);
  const options = { groupMembers: async (_gid: number) => [uid, uid + 1], now: () => NOW, identity: () => ({ uid, gid, groups: [gid] }), stat: async (path: string) => { const info = await lstat(path); if (path === bundleRoot) return Object.assign(info, { uid: uid + 1 }); if (path === root || path === tmpdir()) return Object.assign(info, { uid: 0, mode: 0o40755 }); return info; } };
  const save = async () => { await writeFile(configPath, canonicalJson(config)); };
  return { options, save, root, configPath, config, receipt, authority, paths: { socketDirectory, bundleRoot, stateRoot, hmacPath, receiptKeyPath, authorityKeyPath } };
}
