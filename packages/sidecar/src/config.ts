import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { dirname, isAbsolute, join, normalize } from "node:path";
import { canonicalJson } from "@agent-integrity/core";
import { loadKeyMaterial, type LoadedKeyMaterial, type ReceiptPrivateKeyRecord, type ReceiptKeyRegistry } from "./key-registry.js";

import { resolveClientGroupMembers } from "./client-group.js";
import { cageTrustManifestDigest } from "./cage-trust-manifest.js";

const SAFE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const B64URL32 = /^[A-Za-z0-9_-]{43}$/u;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const STATE_CHILDREN = Object.freeze({ lease: "lease", nonces: "nonces", receipts: "receipts", requests: "requests", snapshots: "snapshots", transactions: "transactions" });

export interface TimedKeyConfig { readonly kid: string; readonly notBefore: string; readonly notAfter: string; readonly revokedAt: string | null }
export interface ReceiptPublicKeyConfig extends TimedKeyConfig { readonly x: string }
export interface ParsedSidecarConfig {
  readonly version: 1;
  readonly storeGeneration: string;
  readonly loadedAt: string;
  readonly identities: Readonly<{ sidecarUid: number; sidecarGid: number; clientGid: number; cageUid: number }>;
  readonly paths: Readonly<{ socketPath: string; bundleRoot: string; stateRoot: string }>;
  readonly stateChildren: typeof STATE_CHILDREN;
  readonly client: Readonly<{ clientId: string; maximumKeyOverlapSeconds: number; hmacKeys: readonly (TimedKeyConfig & { readonly secretFile: string })[] }>;
  readonly receipt: Readonly<{ activeKeyId: string; issuer: string; audience: string; purpose: string; engineVersion: string; maximumReceiptLifetimeSeconds: number; privateKeys: readonly Readonly<{ kid: string; privateKeyFile: string }>[]; publicKeys: readonly ReceiptPublicKeyConfig[] }>;
  readonly manifest: Readonly<{ generation: number; issuedAt: string; validUntil: string; maximumFutureSkewSeconds: number; authorityKeyId: string; authorityPrivateKeyFile: string; authorityPublicX: string }>;
  readonly limits: Readonly<{ maximumRequestBytes: number; maximumEnvelopeBytes: number; maximumSourceBytes: number; maximumTotalSourceBytes: number; maximumResponseBytes: number; maximumFindings: number; maximumTimestampSkewMs: number; maximumBundleLifetimeMs: number; gracefulShutdownMs: number }>;
}
export type SidecarConfigSnapshot = Omit<ParsedSidecarConfig, "client"> & { readonly client: Readonly<{ clientId: string; maximumKeyOverlapSeconds: number; hmacKeyIds: readonly string[] }> };

function record(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new TypeError(`${label} configuration is invalid`);
  return value as Record<string, unknown>;
}
function exact(value: Record<string, unknown>, keys: readonly string[], label: string): void {
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new TypeError(`${label} configuration contains unknown or missing fields`);
}
function safe(value: unknown, label: string): asserts value is string { if (typeof value !== "string" || !SAFE.test(value)) throw new TypeError(`${label} configuration is invalid`); }
function bounded(value: unknown, label: string): asserts value is string { if (typeof value !== "string" || value.length === 0 || Buffer.byteLength(value, "utf8") > 256) throw new TypeError(`${label} configuration is invalid`); }
function absolute(value: unknown, label: string): asserts value is string { if (typeof value !== "string" || !isAbsolute(value) || normalize(value) !== value || value.includes("\0") || Buffer.byteLength(value, "utf8") > 4096) throw new TypeError(`${label} must be an absolute path`); }
function iso(value: unknown, label: string): asserts value is string { if (typeof value !== "string" || !ISO.test(value) || new Date(value).toISOString() !== value) throw new TypeError(`${label} configuration timestamp is invalid`); }
function positive(value: unknown, label: string, maximum = Number.MAX_SAFE_INTEGER): asserts value is number { if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > maximum) throw new TypeError(`${label} configuration limit is invalid`); }
function uid(value: unknown, label: string): asserts value is number { if (!Number.isSafeInteger(value) || (value as number) < 0) throw new TypeError(`${label} configuration identity is invalid`); }
function deepFreeze<T>(value: T): T { if (value !== null && typeof value === "object" && !Object.isFrozen(value)) { for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child); Object.freeze(value); } return value; }
function timedKey(value: unknown, extra: "secretFile" | "x"): TimedKeyConfig & Record<string, unknown> {
  const key = record(value, "key"); exact(key, ["kid", "notBefore", "notAfter", "revokedAt", extra], "key"); safe(key.kid, "key ID"); iso(key.notBefore, "key notBefore"); iso(key.notAfter, "key notAfter");
  if (Date.parse(key.notBefore) >= Date.parse(key.notAfter)) throw new TypeError("key validity configuration is invalid");
  if (key.revokedAt !== null) { iso(key.revokedAt, "key revokedAt"); if (Date.parse(key.revokedAt) < Date.parse(key.notBefore) || Date.parse(key.revokedAt) >= Date.parse(key.notAfter)) throw new TypeError("key revocation configuration is invalid"); }
  if (extra === "secretFile") absolute(key.secretFile, "secret file"); else if (typeof key.x !== "string" || !B64URL32.test(key.x) || Buffer.from(key.x, "base64url").byteLength !== 32 || Buffer.from(key.x, "base64url").toString("base64url") !== key.x) throw new TypeError("public key configuration is invalid");
  return key as TimedKeyConfig & Record<string, unknown>;
}
function sortedUnique<T extends { readonly kid: string }>(values: readonly T[], label: string): void { if (values.length < 1 || values.length > 128 || values.some((value, index) => index > 0 && values[index - 1]!.kid >= value.kid)) throw new TypeError(`${label} configuration must be sorted and unique`); }

export function parseSidecarConfig(value: unknown, loadedAt = new Date().toISOString()): ParsedSidecarConfig {
  const root = record(value, "sidecar"); exact(root, ["client", "identities", "limits", "manifest", "paths", "receipt", "storeGeneration", "version"], "sidecar"); if (root.version !== 1) throw new TypeError("sidecar configuration version is invalid");
  safe(root.storeGeneration, "store generation");
  const identities = record(root.identities, "identities"); exact(identities, ["cageUid", "clientGid", "sidecarGid", "sidecarUid"], "identities"); for (const field of ["cageUid", "clientGid", "sidecarGid", "sidecarUid"] as const) uid(identities[field], field);
  const paths = record(root.paths, "paths"); exact(paths, ["bundleRoot", "socketPath", "stateRoot"], "paths"); for (const field of ["bundleRoot", "socketPath", "stateRoot"] as const) absolute(paths[field], field);
  const client = record(root.client, "client"); exact(client, ["clientId", "hmacKeys", "maximumKeyOverlapSeconds"], "client"); safe(client.clientId, "client ID"); positive(client.maximumKeyOverlapSeconds, "maximum key overlap", 86_400); if (!Array.isArray(client.hmacKeys)) throw new TypeError("client HMAC configuration is invalid");
  const hmacKeys = client.hmacKeys.map((key) => timedKey(key, "secretFile")) as unknown as Array<TimedKeyConfig & { secretFile: string }>; sortedUnique(hmacKeys, "HMAC keys");
  for (let index = 0; index < hmacKeys.length; index += 1) for (let other = index + 1; other < hmacKeys.length; other += 1) { const overlap = Math.min(Date.parse(hmacKeys[index]!.notAfter), Date.parse(hmacKeys[other]!.notAfter)) - Math.max(Date.parse(hmacKeys[index]!.notBefore), Date.parse(hmacKeys[other]!.notBefore)); if (overlap > (client.maximumKeyOverlapSeconds as number) * 1000) throw new TypeError("HMAC key overlap exceeds configuration"); }
  const receipt = record(root.receipt, "receipt"); exact(receipt, ["activeKeyId", "audience", "engineVersion", "issuer", "maximumReceiptLifetimeSeconds", "privateKeys", "publicKeys", "purpose"], "receipt"); safe(receipt.activeKeyId, "active key ID"); for (const field of ["audience", "engineVersion", "issuer", "purpose"] as const) bounded(receipt[field], field); positive(receipt.maximumReceiptLifetimeSeconds, "maximum receipt lifetime", 86_400);
  if (!Array.isArray(receipt.privateKeys) || !Array.isArray(receipt.publicKeys)) throw new TypeError("receipt key configuration is invalid");
  const privateKeys = receipt.privateKeys.map((entry) => { const key = record(entry, "private key"); exact(key, ["kid", "privateKeyFile"], "private key"); safe(key.kid, "private key ID"); absolute(key.privateKeyFile, "private key file"); return { kid: key.kid, privateKeyFile: key.privateKeyFile }; }); sortedUnique(privateKeys, "private keys");
  const publicKeys = receipt.publicKeys.map((key) => timedKey(key, "x") as unknown as ReceiptPublicKeyConfig); sortedUnique(publicKeys, "public keys");
  if (!privateKeys.some((key) => key.kid === receipt.activeKeyId) || !publicKeys.some((key) => key.kid === receipt.activeKeyId)) throw new TypeError("active receipt private/public key configuration is missing");
  const manifest = record(root.manifest, "manifest"); exact(manifest, ["authorityKeyId", "authorityPrivateKeyFile", "authorityPublicX", "generation", "issuedAt", "maximumFutureSkewSeconds", "validUntil"], "manifest"); positive(manifest.generation, "manifest generation"); iso(manifest.issuedAt, "manifest issuedAt"); iso(manifest.validUntil, "manifest validUntil"); if (Date.parse(manifest.issuedAt) >= Date.parse(manifest.validUntil)) throw new TypeError("manifest validity configuration is invalid"); positive(manifest.maximumFutureSkewSeconds, "manifest future skew", 3600); safe(manifest.authorityKeyId, "authority key ID"); absolute(manifest.authorityPrivateKeyFile, "authority private key file"); if (typeof manifest.authorityPublicX !== "string" || !B64URL32.test(manifest.authorityPublicX) || Buffer.from(manifest.authorityPublicX, "base64url").toString("base64url") !== manifest.authorityPublicX) throw new TypeError("authority public key configuration is invalid");
  const limits = record(root.limits, "limits"); const limitNames = ["gracefulShutdownMs", "maximumBundleLifetimeMs", "maximumEnvelopeBytes", "maximumFindings", "maximumRequestBytes", "maximumResponseBytes", "maximumSourceBytes", "maximumTimestampSkewMs", "maximumTotalSourceBytes"] as const; exact(limits, limitNames, "limits"); for (const field of limitNames) positive(limits[field], field, field === "maximumFindings" ? 10_000 : 32 * 1024 * 1024);
  if ((limits.maximumTimestampSkewMs as number) > 60_000 || (limits.maximumBundleLifetimeMs as number) > 900_000 || (limits.maximumEnvelopeBytes as number) > (limits.maximumRequestBytes as number) || (limits.maximumSourceBytes as number) > (limits.maximumTotalSourceBytes as number)) throw new TypeError("configuration limits are inconsistent or exceed hard ceilings");
  iso(loadedAt, "loadedAt");
  return deepFreeze({ version: 1, storeGeneration: root.storeGeneration as string, loadedAt, identities: identities as unknown as ParsedSidecarConfig["identities"], paths: paths as unknown as ParsedSidecarConfig["paths"], stateChildren: STATE_CHILDREN, client: { clientId: client.clientId as string, maximumKeyOverlapSeconds: client.maximumKeyOverlapSeconds as number, hmacKeys }, receipt: { activeKeyId: receipt.activeKeyId as string, issuer: receipt.issuer as string, audience: receipt.audience as string, purpose: receipt.purpose as string, engineVersion: receipt.engineVersion as string, maximumReceiptLifetimeSeconds: receipt.maximumReceiptLifetimeSeconds as number, privateKeys, publicKeys }, manifest: manifest as unknown as ParsedSidecarConfig["manifest"], limits: limits as unknown as ParsedSidecarConfig["limits"] });
}

export interface SidecarIdentity { readonly uid: number; readonly gid: number; readonly groups: readonly number[] }
export interface SidecarFileStat { readonly mode: number; readonly uid: number; readonly gid: number; readonly nlink: number; readonly size: number; readonly dev: number; readonly ino: number; isSymbolicLink(): boolean; isFile(): boolean; isDirectory(): boolean }
export interface SidecarConfigManagerOptions {
  readonly now: () => Date;
  readonly groupMembers?: (gid: number) => Promise<readonly number[]>;
  readonly identity?: () => SidecarIdentity;
  readonly stat?: (path: string) => Promise<SidecarFileStat>;
  readonly resolve?: (path: string) => Promise<string>;
}
interface RecoveryEntry { readonly key: ReceiptPrivateKeyRecord; refs: number; retired: boolean }

export class SidecarConfigManager {
  readonly #path: string; readonly #options: SidecarConfigManagerOptions;
  #loading = false;
  #snapshot: SidecarConfigSnapshot | undefined; #parsed: ParsedSidecarConfig | undefined; #keys: LoadedKeyMaterial | undefined;
  readonly #recovery = new Map<string, RecoveryEntry>();
  constructor(path: string, options: SidecarConfigManagerOptions) { absolute(path, "configuration file"); this.#path = path; this.#options = options; }
  async loadInitial(): Promise<SidecarConfigSnapshot> { if (this.#snapshot !== undefined) throw new Error("configuration is already loaded"); return this.#load(); }
  async reload(): Promise<SidecarConfigSnapshot> { if (this.#snapshot === undefined) throw new Error("initial configuration is not loaded"); return this.#load(); }
  current(): SidecarConfigSnapshot { if (this.#snapshot === undefined) throw new Error("configuration is not loaded"); return this.#snapshot; }
  keyRegistry(): ReceiptKeyRegistry { if (this.#keys === undefined) throw new Error("configuration is not loaded"); return this.#keys.receiptRegistry; }
  manifestAuthority(): LoadedKeyMaterial["authority"] { if (this.#keys === undefined) throw new Error("configuration is not loaded"); return this.#keys.authority; }
  hmacRegistry(): LoadedKeyMaterial["hmacRegistry"] { if (this.#keys === undefined) throw new Error("configuration is not loaded"); const clients = Object.fromEntries(Object.entries(this.#keys.hmacRegistry.clients).map(([id, client]) => [id, Object.freeze({ keys: Object.freeze(Object.fromEntries(Object.entries(client.keys).map(([kid, key]) => [kid, Object.freeze({ ...key, secret: Uint8Array.from(key.secret) })]))) })])); return Object.freeze({ clients: Object.freeze(clients) }); }
  selectSigningKey(now: Date) { return this.keyRegistry().select(now); }
  retainRecoveryKey(kid: string): () => void { const key = this.#keys?.receiptRegistry.privateKey(kid); if (key === undefined) throw new Error("recovery signing key is unavailable"); const entry = this.#recovery.get(kid) ?? { key, refs: 0, retired: false }; entry.refs += 1; this.#recovery.set(kid, entry); let active = true; return () => { if (!active) return; active = false; entry.refs -= 1; if (entry.refs === 0 && entry.retired) this.#recovery.delete(kid); }; }
  recoverySigningKey(kid: string): ReceiptPrivateKeyRecord { const current = this.#keys?.receiptRegistry.privateKey(kid); if (current !== undefined) return current; const retained = this.#recovery.get(kid); if (retained === undefined || retained.refs < 1) throw new Error("recovery signing key is unavailable"); return retained.key; }

  async #load(): Promise<SidecarConfigSnapshot> {
    if (this.#loading) throw new Error("configuration load is already in progress");
    this.#loading = true;
    try { return await this.#loadCandidate(); } catch (error) { if (error instanceof Error && !((error as NodeJS.ErrnoException).code)) throw error; throw new Error("configuration filesystem operation failed"); } finally { this.#loading = false; }
  }
  async #loadCandidate(): Promise<SidecarConfigSnapshot> {
    const now = this.#options.now(); if (!(now instanceof Date) || !Number.isFinite(now.getTime())) throw new Error("configuration clock is invalid");
    const identity = this.#identity();
    const raw = await this.#readProtected(this.#path, identity.uid, identity.gid, [0o400, 0o600], 1024 * 1024);
    let value: unknown; try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw)); } catch { throw new Error("configuration JSON is invalid"); }
    const parsed = parseSidecarConfig(value, now.toISOString());
    if (parsed.identities.sidecarUid !== identity.uid || parsed.identities.sidecarGid !== identity.gid || parsed.identities.cageUid === identity.uid || !(identity.gid === parsed.identities.clientGid || identity.groups.includes(parsed.identities.clientGid))) throw new Error("process identity or group membership is invalid");
    const members = await (this.#options.groupMembers ?? resolveClientGroupMembers)(parsed.identities.clientGid);
    if (members.length !== 2 || new Set(members).size !== 2 || !members.includes(parsed.identities.cageUid) || !members.includes(parsed.identities.sidecarUid)) throw new Error("client group must contain exactly the CAGE and sidecar identities");
    await this.#validateLayout(parsed);
    if (Date.parse(parsed.manifest.issuedAt) > now.getTime() + parsed.manifest.maximumFutureSkewSeconds * 1000 || now.getTime() >= Date.parse(parsed.manifest.validUntil)) throw new Error("manifest configuration is outside its validity interval");
    if (!parsed.client.hmacKeys.some((key) => Date.parse(key.notBefore) <= now.getTime() && now.getTime() < Date.parse(key.notAfter) && (key.revokedAt === null || now.getTime() < Date.parse(key.revokedAt)))) throw new Error("no active HMAC key is available");
    const keys = await loadKeyMaterial(parsed, (path) => this.#readSecret(path, parsed.identities.sidecarUid));
    const redacted = deepFreeze({ ...parsed, client: { clientId: parsed.client.clientId, maximumKeyOverlapSeconds: parsed.client.maximumKeyOverlapSeconds, hmacKeyIds: parsed.client.hmacKeys.map((key) => key.kid) } }) as SidecarConfigSnapshot;
    if (this.#parsed !== undefined) {
      if (parsed.manifest.generation < this.#parsed.manifest.generation) throw new Error("manifest generation rollback is forbidden");
      if (parsed.manifest.generation === this.#parsed.manifest.generation && (cageTrustManifestDigest(keys.receiptRegistry, parsed.manifest, parsed.receipt) !== cageTrustManifestDigest(this.#keys!.receiptRegistry, this.#parsed.manifest, this.#parsed.receipt) || parsed.manifest.authorityPublicX !== this.#parsed.manifest.authorityPublicX)) throw new Error("changed manifest content requires increased generation");
      if (parsed.storeGeneration !== this.#parsed.storeGeneration || canonicalJson(parsed.paths) !== canonicalJson(this.#parsed.paths) || canonicalJson(parsed.identities) !== canonicalJson(this.#parsed.identities)) throw new Error("reload cannot change deployment identity");
      for (const previous of this.#parsed.receipt.publicKeys) { const next = parsed.receipt.publicKeys.find((key) => key.kid === previous.kid); if (next === undefined || next.x !== previous.x || next.notBefore !== previous.notBefore || next.notAfter !== previous.notAfter || (previous.revokedAt !== null && next.revokedAt !== previous.revokedAt)) throw new Error("historical public key retention or binding is invalid"); }
    }
    const previousKeys = this.#keys;
    this.#parsed = parsed; this.#keys = keys; this.#snapshot = redacted;
    if (previousKeys !== undefined) for (const [kid, entry] of this.#recovery) { if (keys.receiptRegistry.privateKey(kid) === undefined) entry.retired = true; else entry.retired = false; if (entry.refs === 0 && entry.retired) this.#recovery.delete(kid); }
    return redacted;
  }
  #identity(): SidecarIdentity { return this.#options.identity?.() ?? { uid: process.getuid?.() ?? -1, gid: process.getgid?.() ?? -1, groups: process.getgroups?.() ?? [] }; }
  async #inspect(path: string, expected: { type: "file" | "directory"; mode: number | readonly number[]; uid: number; gid?: number }): Promise<SidecarFileStat> {
    const info = await (this.#options.stat ?? lstat)(path);
    if (info.isSymbolicLink()) throw new Error("filesystem symlink is forbidden");
    if (expected.type === "file" ? !info.isFile() : !info.isDirectory()) throw new Error("filesystem type is invalid");
    if (!(Array.isArray(expected.mode) ? expected.mode : [expected.mode]).includes(info.mode & 0o7777) || info.uid !== expected.uid || (expected.gid !== undefined && info.gid !== expected.gid)) throw new Error("filesystem ownership, group, mode, or permission is invalid");
    if (expected.type === "file" && info.nlink !== 1) throw new Error("private file link count is invalid");
    if (await (this.#options.resolve ?? realpath)(path) !== path) throw new Error("filesystem parent symlink or unexpected path is forbidden");
    let parent = dirname(path);
    while (parent !== dirname(parent)) {
      const ancestor = await (this.#options.stat ?? lstat)(parent);
      if (!ancestor.isDirectory() || ancestor.isSymbolicLink() || (ancestor.uid !== 0 && ancestor.uid !== this.#identity().uid) || (ancestor.mode & 0o022) !== 0) throw new Error("filesystem parent ownership or permission is invalid");
      parent = dirname(parent);
    }
    return info;
  }
  async #readProtected(path: string, uid: number, gid: number | undefined, mode: number | readonly number[], maximum: number): Promise<Buffer> {
    const before = await this.#inspect(path, { type: "file", mode, uid, ...(gid === undefined ? {} : { gid }) });
    const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
      const opened = await handle.stat();
      if (opened.dev !== before.dev || opened.ino !== before.ino || !opened.isFile() || opened.nlink !== 1 || !(Array.isArray(mode) ? mode : [mode]).includes(opened.mode & 0o7777) || opened.uid !== before.uid || opened.gid !== before.gid || opened.size > maximum) throw new Error("protected file identity, permission, or size is invalid");
      const bytes = Buffer.alloc(maximum + 1); let bytesRead = 0;
      while (bytesRead < bytes.length) { const chunk = await handle.read(bytes, bytesRead, bytes.length - bytesRead, bytesRead); if (chunk.bytesRead === 0) break; bytesRead += chunk.bytesRead; }
      const after = await handle.stat(); const named = await this.#inspect(path, { type: "file", mode, uid, ...(gid === undefined ? {} : { gid }) });
      if (bytesRead !== opened.size || bytesRead > maximum || after.size !== opened.size || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs || named.dev !== opened.dev || named.ino !== opened.ino) throw new Error("protected file changed while reading");
      return bytes.subarray(0, bytesRead);
    } finally { await handle.close(); }
  }
  async #readSecret(path: string, uid: number): Promise<Buffer> { return this.#readProtected(path, uid, this.#identity().gid, 0o400, 64 * 1024); }
  async #validateLayout(config: ParsedSidecarConfig): Promise<void> {
    const ids = config.identities;
    const socketParent = await (this.#options.stat ?? lstat)(dirname(dirname(config.paths.socketPath)));
    if (socketParent.uid !== 0 || (socketParent.mode & 0o022) !== 0 || (socketParent.mode & 0o200) !== 0 && ids.sidecarUid === 0) throw new Error("socket parent must be root-owned and not service-writable");
    await this.#inspect(dirname(config.paths.socketPath), { type: "directory", mode: 0o710, uid: ids.sidecarUid, gid: ids.clientGid });
    await this.#inspect(config.paths.bundleRoot, { type: "directory", mode: 0o750, uid: ids.cageUid, gid: ids.clientGid });
    await this.#inspect(config.paths.stateRoot, { type: "directory", mode: 0o700, uid: ids.sidecarUid, gid: ids.sidecarGid });
    for (const child of Object.values(config.stateChildren)) await this.#inspect(join(config.paths.stateRoot, child), { type: "directory", mode: 0o700, uid: ids.sidecarUid, gid: ids.sidecarGid });
  }
}
