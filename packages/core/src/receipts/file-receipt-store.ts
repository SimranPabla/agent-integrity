import { createHash, randomUUID } from "node:crypto";
import { link, lstat, mkdir, open, opendir, readdir, rm, stat } from "node:fs/promises";
import { dirname, isAbsolute, join, relative } from "node:path";
import { constants } from "node:fs";
import { realpath } from "node:fs/promises";
import type { AlphaIntegrityReceipt } from "@agent-integrity/protocol";
import { canonicalJson } from "../canonical-json.js";
import { ReceiptOutputBoundary } from "./receipt-output-boundary.js";
import {
  consumedView,
  freezeValidated,
  parseStoredReceiptRecord,
  type ConsumedReceiptRecord,
  type IssuedReceiptRecord,
  type ClosedReceiptRecord,
  type ReceiptRecordKind,
  type StoredReceiptRecord,
} from "./receipt-store-records.js";

class DuplicateStoreRecordError extends Error {}

type QuotaReservationState = "not-reserved" | "possibly-reserved";

class QuotaReservationError extends Error {
  constructor(
    message: string,
    readonly reservationState: QuotaReservationState,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "QuotaReservationError";
  }
}

// Same whole-root bound as sidecar: 512 segments admitted by 1024 UTF-8 bytes,
// snapshots/<id>/project prefix, and eight bounded metadata levels.
const MAX_ROOT_INVENTORY_DEPTH = 512 + 3 + 8;
const SHA256 = /^[a-f0-9]{64}$/u;
const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const REASON_CODE = /^[A-Z][A-Z0-9_]{0,127}$/u;
const DEFAULT_MAX_STATE_BYTES = 64 * 1024;
const DEFAULT_MAX_DIRECTORY_BYTES = 4096;
const DEFAULT_MAX_RECORDS = 10_000;

export const RECEIPT_STORE_LOCK_AUTHORIZER = Symbol.for("agent-integrity.receipt-store-lock-authorizer");
export interface ReceiptStoreLockOwnership {
  readonly ownerToken: string;
  readonly storeGeneration: string;
  readonly rootIdentityDigest: string;
  readonly [RECEIPT_STORE_LOCK_AUTHORIZER]: () => void;
}

export function isUnsupportedDirectoryOpenError(error: unknown): boolean {
  return ["EPERM", "EACCES", "EISDIR"].includes((error as NodeJS.ErrnoException)?.code ?? "");
}

function markerName(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export interface FileReceiptStoreOptions {
  readonly maxStateBytes?: number;
  readonly maxDirectoryBytes?: number;
  readonly maxRecords?: number;
  /** Sidecar mode: bind every nested store lock to the state-root lease owner. */
  readonly lockOwnership?: ReceiptStoreLockOwnership;
  /** Test-only deterministic crash injection. */
  readonly faultInjector?: (point: string) => void | Promise<void>;
}

export class FileReceiptStore {
  readonly #maxStateBytes: number;
  readonly #maxRecords: number;

  constructor(readonly directory: string, readonly options: FileReceiptStoreOptions = {}) {
    const maxDirectoryBytes = options.maxDirectoryBytes ?? DEFAULT_MAX_DIRECTORY_BYTES;
    for (const [name, value] of [["maxStateBytes", options.maxStateBytes ?? DEFAULT_MAX_STATE_BYTES], ["maxDirectoryBytes", maxDirectoryBytes]] as const) {
      if (!Number.isSafeInteger(value) || value < 256 || value > 1024 * 1024) throw new Error(`${name} must be a safe integer between 256 and 1048576`);
    }
    const maxRecords = options.maxRecords ?? DEFAULT_MAX_RECORDS;
    if (!Number.isSafeInteger(maxRecords) || maxRecords < 1 || maxRecords > 1_000_000) throw new Error("maxRecords must be a safe integer between 1 and 1000000");
    if (typeof directory !== "string" || directory.length === 0 || Buffer.byteLength(directory, "utf8") > maxDirectoryBytes) throw new Error("receipt store directory is invalid or exceeds its configured limit");
    if (options.lockOwnership !== undefined) {
      const ownership = options.lockOwnership;
      if (!SAFE_IDENTIFIER.test(ownership.ownerToken) || !SAFE_IDENTIFIER.test(ownership.storeGeneration) || !SHA256.test(ownership.rootIdentityDigest) || Object.keys(ownership).sort().join(",") !== "ownerToken,rootIdentityDigest,storeGeneration" || typeof ownership[RECEIPT_STORE_LOCK_AUTHORIZER] !== "function") throw new Error("receipt store lock ownership is invalid");
    }
    this.#maxStateBytes = options.maxStateBytes ?? DEFAULT_MAX_STATE_BYTES;
    this.#maxRecords = maxRecords;
  }

  private path(kind: "runs" | "nonces" | "issued" | "consumed" | "closed" | "quota" | "transactions" | "recovery" | "cleanup", value: string): string {
    const raw = kind === "issued" || kind === "consumed" || kind === "closed" ? value : markerName(value);
    return join(this.directory, kind, `${raw}.json`);
  }

  private async initialize(): Promise<void> {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    await Promise.all(["runs", "nonces", "issued", "consumed", "closed", "quota", "transactions", "recovery", "cleanup", ".staging"].map((name) => mkdir(join(this.directory, name), { recursive: true, mode: 0o700 })));
  }

  private async syncDirectory(path: string): Promise<void> {
    let handle;
    try { handle = await open(path, "r"); }
    catch (error) { if (isUnsupportedDirectoryOpenError(error)) return; throw error; }
    try { await handle.sync(); }
    catch (error) { if (!["EINVAL", "ENOTSUP", "EISDIR"].includes((error as NodeJS.ErrnoException).code ?? "")) throw error; }
    finally { await handle.close(); }
  }

  private async publishJson(path: string, value: unknown, point: string, duplicateMessage: string, stagingDirectory = join(this.directory, ".staging")): Promise<void> {
    const temporary = join(stagingDirectory, `.integrity-${randomUUID()}.tmp`);
    const bytes = `${JSON.stringify(value)}\n`;
    if (Buffer.byteLength(bytes, "utf8") > this.#maxStateBytes) throw new Error("receipt store state exceeds configured limit");
    const handle = await open(temporary, "wx", 0o600);
    try {
      await handle.writeFile(bytes, "utf8");
      await handle.sync();
      await this.options.faultInjector?.(`${point}:after-temp-sync`);
      try { await link(temporary, path); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EEXIST") throw new DuplicateStoreRecordError(duplicateMessage);
        throw error;
      }
      await this.options.faultInjector?.(`${point}:before-directory-sync`);
      await this.syncDirectory(dirname(path));
      try { await this.options.faultInjector?.(`${point}:after-publish`); }
      catch (error) { Object.assign(error as object, { publishedPath: path }); throw error; }
    } finally {
      await handle.close();
      await rm(temporary, { force: true });
    }
  }

  /** Removes abandoned staging files only during an operator-enforced offline window. */
  async cleanupStaging(options: { readonly offlineExclusive: true }): Promise<number> {
    if (options?.offlineExclusive !== true) throw new Error("offlineExclusive staging cleanup is required");
    return this.withLock(async () => {
      const staging = join(this.directory, ".staging");
      const directory = await opendir(staging);
      let inspected = 0;
      let removed = 0;
      try {
        for await (const entry of directory) {
          inspected += 1;
          if (inspected > this.#maxRecords) throw new Error("staging entries exceed configured inspection limit");
          if (entry.isFile() && entry.name.startsWith(".integrity-") && entry.name.endsWith(".tmp")) {
            await rm(join(staging, entry.name));
            removed += 1;
          }
        }
      } finally { await directory.close().catch(() => undefined); }
      await this.syncDirectory(staging);
      return removed;
    });
  }

  private async readRecord(path: string, kind: ReceiptRecordKind): Promise<StoredReceiptRecord> {
    const before = await lstat(path);
    if (before.isSymbolicLink() || !before.isFile() || before.nlink !== 1) throw new Error("invalid receipt store state file");
    const handle = await open(path, "r");
    try {
      const info = await handle.stat();
      if (info.dev !== before.dev || info.ino !== before.ino || info.nlink !== 1) throw new Error("receipt store state identity changed");
      if (info.size > this.#maxStateBytes) throw new Error("receipt store state exceeds configured limit");
      const buffer = Buffer.alloc(this.#maxStateBytes + 1);
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
      if (bytesRead > this.#maxStateBytes) throw new Error("receipt store state exceeds configured limit");
      return parseStoredReceiptRecord(JSON.parse(buffer.subarray(0, bytesRead).toString("utf8")), kind);
    } finally { await handle.close(); }
  }

  private async readJson(path: string): Promise<Record<string, unknown>> {
    const before = await lstat(path);
    if (before.isSymbolicLink() || !before.isFile() || before.nlink !== 1) throw new Error("invalid receipt store state file");
    const handle = await open(path, "r");
    try {
      const info = await handle.stat();
      if (info.dev !== before.dev || info.ino !== before.ino || info.nlink !== 1) throw new Error("receipt store state identity changed");
      if (info.size > this.#maxStateBytes) throw new Error("receipt store state exceeds configured limit");
      const buffer = Buffer.alloc(this.#maxStateBytes + 1);
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
      if (bytesRead > this.#maxStateBytes) throw new Error("receipt store state exceeds configured limit");
      const value = JSON.parse(buffer.subarray(0, bytesRead).toString("utf8")) as unknown;
      if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new Error("invalid receipt store metadata");
      return value as Record<string, unknown>;
    } finally { await handle.close(); }
  }

  private async acquireLock(): Promise<string> {
    this.options.lockOwnership?.[RECEIPT_STORE_LOCK_AUTHORIZER]();
    await this.initialize();
    const ownerToken = this.options.lockOwnership?.ownerToken ?? randomUUID();
    const lock = this.options.lockOwnership === undefined
      ? { version: 1, ownerToken }
      : { version: 2, ...this.options.lockOwnership };
    await this.publishJson(join(this.directory, ".store-lock.json"), lock, "lock", "receipt store is locked; never steal a live or abandoned lock");
    return ownerToken;
  }

  private async releaseLock(ownerToken: string): Promise<void> {
    await this.options.faultInjector?.("lock:before-release");
    const lockPath = join(this.directory, ".store-lock.json");
    const lock = await this.readJson(lockPath);
    if (this.options.lockOwnership === undefined) {
      if (Object.keys(lock).sort().join(",") !== "ownerToken,version" || lock.version !== 1 || typeof lock.ownerToken !== "string" || !SAFE_IDENTIFIER.test(lock.ownerToken)) throw new Error("receipt store lock is malformed");
    } else {
      const expected = this.options.lockOwnership;
      if (Object.keys(lock).sort().join(",") !== "ownerToken,rootIdentityDigest,storeGeneration,version" || lock.version !== 2 || lock.ownerToken !== expected.ownerToken || lock.storeGeneration !== expected.storeGeneration || lock.rootIdentityDigest !== expected.rootIdentityDigest) throw new Error("receipt store nested lock ownership changed");
    }
    if (lock.ownerToken !== ownerToken) throw new Error("receipt store lock ownership changed");
    await rm(lockPath);
    await this.syncDirectory(this.directory);
  }

  private async withLock<T>(operation: (ownerToken: string) => Promise<T>): Promise<T> {
    const ownerToken = await this.acquireLock();
    try { return await operation(ownerToken); }
    finally { await this.releaseLock(ownerToken); }
  }

  /** Internal sidecar continuation. A prior token is NOT authority: independently prove the durable
   * complete root chain, recorded directory and marker, and current live root authorization. */
  async completeRootAuthorizedLockHandoff(options: {
    readonly offlineExclusive: true;
    readonly rootDirectory: string;
    readonly handoffPreviousOwnerToken: string;
    readonly lockName: string;
  }): Promise<void> {
    const owner = this.options.lockOwnership;
    if (options.offlineExclusive !== true || owner === undefined || !isAbsolute(options.rootDirectory) || !SAFE_IDENTIFIER.test(options.handoffPreviousOwnerToken) || !SAFE_IDENTIFIER.test(options.lockName)) throw new Error("protected nested handoff requires live root authority");
    owner[RECEIPT_STORE_LOCK_AUTHORIZER]();
    const root = options.rootDirectory;
    const digest = (value: unknown) => createHash("sha256").update(canonicalJson(value)).digest("hex");
    const directoryDigest = async (path: string) => {
      const info = await lstat(path);
      if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o777) !== 0o700 || (process.getuid !== undefined && info.uid !== process.getuid())) throw new Error("nested handoff directory is unsafe");
      return digest({ dev: String(info.dev), ino: String(info.ino), uid: info.uid, real: await realpath(path) });
    };
    const protectedRead = async (path: string): Promise<Record<string, unknown>> => {
      const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        const before = await handle.stat();
        if (!before.isFile() || before.nlink !== 1 || before.size > 64 * 1024 || (before.mode & 0o777) !== 0o600 || (process.getuid !== undefined && before.uid !== process.getuid())) throw new Error("nested handoff authority record is unsafe");
        const buffer = Buffer.alloc(64 * 1024 + 1); const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
        const after = await handle.stat(); const node = await lstat(path);
        if (bytesRead !== before.size || before.dev !== after.dev || before.ino !== after.ino || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs || node.isSymbolicLink() || node.dev !== before.dev || node.ino !== before.ino) throw new Error("nested handoff authority changed");
        const value: unknown = JSON.parse(buffer.subarray(0, bytesRead).toString("utf8"));
        if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new Error("nested handoff authority is malformed");
        return value as Record<string, unknown>;
      } finally { await handle.close(); }
    };
    const parseMarker = (value: unknown): Record<string, unknown> => {
      if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("nested handoff marker is malformed");
      const marker = value as Record<string, unknown>;
      if (Object.keys(marker).sort().join(",") !== "ownerToken,rootIdentityDigest,storeGeneration,version" || marker.version !== 2 || typeof marker.ownerToken !== "string" || !SAFE_IDENTIFIER.test(marker.ownerToken) || marker.storeGeneration !== owner.storeGeneration || marker.rootIdentityDigest !== owner.rootIdentityDigest) throw new Error("nested handoff marker ownership mismatch");
      return marker;
    };
    if (await realpath(root) !== root || await realpath(this.directory) !== this.directory || await directoryDigest(root) !== owner.rootIdentityDigest) throw new Error("nested handoff root identity or path mismatch");
    const handoffDirectoryIdentity = await directoryDigest(join(root, "handoffs"));
    const proofDirectoryIdentity = await directoryDigest(join(root, "nested-locks"));
    const lease = await protectedRead(join(root, "lease.json"));
    if (Object.keys(lease).sort().join(",") !== "nestedDirectoryIdentities,nestedLockNames,nestedLockPaths,ownerToken,rootIdentityDigest,startedAt,storeGeneration,version" || lease.version !== 2 || typeof lease.ownerToken !== "string" || !SAFE_IDENTIFIER.test(lease.ownerToken) || lease.rootIdentityDigest !== owner.rootIdentityDigest || lease.storeGeneration !== owner.storeGeneration || typeof lease.startedAt !== "string" || new Date(lease.startedAt).toISOString() !== lease.startedAt) throw new Error("nested handoff root lease mismatch");
    const names = lease.nestedLockNames;
    if (!Array.isArray(names) || names.length > 64 || names.some(name => typeof name !== "string" || !SAFE_IDENTIFIER.test(name)) || new Set(names).size !== names.length) throw new Error("nested handoff inventory malformed");
    const keys = [...names].sort().join(",");
    const mapping = lease.nestedLockPaths as Record<string, unknown>; const identities = lease.nestedDirectoryIdentities as Record<string, unknown>;
    if (mapping === null || typeof mapping !== "object" || Array.isArray(mapping) || identities === null || typeof identities !== "object" || Array.isArray(identities) || Object.keys(mapping).sort().join(",") !== keys || Object.keys(identities).sort().join(",") !== keys || new Set(Object.values(mapping)).size !== names.length) throw new Error("nested handoff inventory is partial");
    for (const name of names as string[]) {
      const path = mapping[name];
      if (typeof path !== "string" || Buffer.byteLength(path) > 1024 || !/^[A-Za-z0-9][A-Za-z0-9._-]*(?:\/[A-Za-z0-9][A-Za-z0-9._-]*)*\/\.store-lock\.json$/u.test(path) || path.split("/").some(part => part === "." || part === "..")) throw new Error("nested handoff path is unsafe");
      let current = root;
      for (const part of dirname(path).split("/")) { current = join(current, part); await directoryDigest(current); }
      if (await directoryDigest(current) !== identities[name]) throw new Error("nested handoff directory identity mismatch");
    }
    const path = mapping[options.lockName];
    if (typeof path !== "string" || relative(root, this.directory) !== dirname(path)) throw new Error("nested handoff store path mismatch");
    const handoffs = new Map<string, Record<string, unknown>>();
    const stream = await opendir(join(root, "handoffs")); let count = 0;
    try { for await (const entry of stream) {
      if (++count > 128 || !/^[a-f0-9]{64}\.json$/u.test(entry.name)) throw new Error("nested handoff chain bound or filename mismatch");
      const handoff = await protectedRead(join(root, "handoffs", entry.name));
      if (Object.keys(handoff).sort().join(",") !== "createdAt,nestedDirectoryIdentities,nestedLockNames,nestedLockPaths,nestedLocks,nestedMarkerIdentities,ownerToken,previousOwnerToken,rootIdentityDigest,storeGeneration,version" || handoff.version !== 2 || typeof handoff.previousOwnerToken !== "string" || !SAFE_IDENTIFIER.test(handoff.previousOwnerToken) || typeof handoff.ownerToken !== "string" || !SAFE_IDENTIFIER.test(handoff.ownerToken) || handoff.ownerToken === handoff.previousOwnerToken || entry.name !== markerName(handoff.previousOwnerToken) + ".json" || handoff.storeGeneration !== owner.storeGeneration || handoff.rootIdentityDigest !== owner.rootIdentityDigest || canonicalJson(handoff.nestedLockNames) !== canonicalJson(names) || canonicalJson(handoff.nestedLockPaths) !== canonicalJson(mapping) || canonicalJson(handoff.nestedDirectoryIdentities) !== canonicalJson(identities) || typeof handoff.createdAt !== "string" || new Date(handoff.createdAt).toISOString() !== handoff.createdAt) throw new Error("nested handoff chain mismatch");
      const locks = handoff.nestedLocks as Record<string, unknown>;
      if (locks === null || typeof locks !== "object" || Array.isArray(locks) || Object.keys(locks).sort().join(",") !== keys) throw new Error("nested handoff lock inventory is partial");
      const markerIdentities = handoff.nestedMarkerIdentities as Record<string, unknown>;
      if (markerIdentities === null || typeof markerIdentities !== "object" || Array.isArray(markerIdentities) || Object.keys(markerIdentities).sort().join(",") !== keys) throw new Error("nested handoff marker identities are partial");
      for (const name of names as string[]) { const identity = markerIdentities[name]; if (locks[name] === null) { if (identity !== null) throw new Error("absent nested marker identity mismatch"); } else { parseMarker(locks[name]); if (identity === null || typeof identity !== "object" || Object.keys(identity).sort().join(",") !== "ctimeMs,dev,ino,mtimeMs" || Object.values(identity).some(value => typeof value !== "number" || !Number.isFinite(value))) throw new Error("nested handoff marker identity malformed"); } }
      handoffs.set(handoff.previousOwnerToken, handoff);
    }} finally { await stream.close().catch(() => undefined); }
    let effective = lease.ownerToken; const chain: Record<string, unknown>[] = []; const visited = new Set<string>();
    while (handoffs.has(effective)) {
      if (visited.has(effective)) throw new Error("nested handoff chain cycle"); visited.add(effective);
      const handoff = handoffs.get(effective)!;
      // Carried old markers are valid only when an earlier immutable complete handoff recorded them.
      const locks = handoff.nestedLocks as Record<string, unknown>;
      for (const name of names as string[]) if (locks[name] !== null) {
        const marker = parseMarker(locks[name]);
        if (marker.ownerToken !== effective && !chain.some(prior => canonicalJson((prior.nestedLocks as Record<string, unknown>)[name]) === canonicalJson(marker) && canonicalJson((prior.nestedMarkerIdentities as Record<string, unknown>)[name]) === canonicalJson((handoff.nestedMarkerIdentities as Record<string, unknown>)[name]))) throw new Error("unproved prior nested marker identity");
      }
      chain.push(handoff); effective = handoff.ownerToken as string;
    }
    if (visited.size !== handoffs.size || effective !== owner.ownerToken) throw new Error("nested handoff current live root owner mismatch");
    const validateWholeRoot = async (): Promise<void> => {
      // Fail-only structural bound check precedes depth-proportional realpath work.
      // It grants no authority and caches no proof: successful roots still receive
      // the complete independent identity/marker scan below, freshly on every call.
      const boundPending = [{ directory: root, depth: 0 }]; let boundEntries = 0;
      while (boundPending.length !== 0) {
        const { directory, depth } = boundPending.pop()!;
        if (depth > MAX_ROOT_INVENTORY_DEPTH) throw new Error("nested handoff inventory depth exceeded");
        const info = await lstat(directory);
        if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o777) !== 0o700 || (process.getuid !== undefined && info.uid !== process.getuid())) throw new Error("nested handoff directory is unsafe");
        const stream = await opendir(directory);
        try { for await (const entry of stream) {
          if (++boundEntries > 100_000) throw new Error("nested handoff inventory bound exceeded");
          const path = join(directory, entry.name); const node = await lstat(path);
          if (node.isSymbolicLink()) throw new Error("nested handoff inventory symlink forbidden");
          if (node.isDirectory()) boundPending.push({ directory: path, depth: depth + 1 });
        }} finally { await stream.close().catch(() => undefined); }
      }
      if (await directoryDigest(root) !== owner.rootIdentityDigest || await directoryDigest(join(root, "handoffs")) !== handoffDirectoryIdentity || await directoryDigest(join(root, "nested-locks")) !== proofDirectoryIdentity) throw new Error("nested handoff authority directory identity changed");
      if (canonicalJson(await protectedRead(join(root, "lease.json"))) !== canonicalJson(lease)) throw new Error("nested handoff lease changed");
      const currentNames = await readdir(join(root, "handoffs"));
      if (currentNames.length !== chain.length) throw new Error("nested handoff effective authority changed");
      for (const record of chain) if (canonicalJson(await protectedRead(join(root, "handoffs", markerName(record.previousOwnerToken as string) + ".json"))) !== canonicalJson(record)) throw new Error("nested handoff immutable authority changed");
      const actual = new Map<string, Record<string, unknown>>(); let entries = 0;
      const expectedPaths = new Map((names as string[]).map(name => [mapping[name] as string, name]));
      const directoryIdentities = new Map<string, string>();
      const queuedIdentities = new Map<string, { dev: number; ino: number; uid: number }>();
      const pending = [{ directory: root, prefix: "", depth: 0 }];
      while (pending.length > 0) {
        const { directory, prefix, depth } = pending.pop()!;
        if (depth > MAX_ROOT_INVENTORY_DEPTH) throw new Error("nested handoff inventory depth exceeded");
        const before = await directoryDigest(directory);
        const queuedIdentity = queuedIdentities.get(directory);
        if (queuedIdentity !== undefined) {
          const actual = await lstat(directory);
          if (actual.dev !== queuedIdentity.dev || actual.ino !== queuedIdentity.ino || actual.uid !== queuedIdentity.uid) throw new Error("nested handoff inventory directory replaced");
        }
        directoryIdentities.set(directory, before);
        const directoryStream = await opendir(directory);
        try { for await (const entry of directoryStream) {
          if (++entries > 100_000) throw new Error("nested handoff inventory bound exceeded");
          const path = join(directory, entry.name); const node = await lstat(path); const rel = prefix === "" ? entry.name : prefix + "/" + entry.name;
          if (node.isSymbolicLink()) throw new Error("nested handoff inventory symlink forbidden");
          if (node.isDirectory()) { queuedIdentities.set(path, { dev: node.dev, ino: node.ino, uid: node.uid }); pending.push({ directory: path, prefix: rel, depth: depth + 1 }); continue; }
          if (entry.name === ".store-lock.json") {
            const name = expectedPaths.get(rel);
            if (name === undefined || node.size > 4096) throw new Error("unexpected nested handoff lock");
            const marker = parseMarker(await protectedRead(path));
            if (marker.ownerToken !== owner.ownerToken && !chain.some(record => canonicalJson((record.nestedLocks as Record<string, unknown>)[name]) === canonicalJson(marker))) throw new Error("foreign nested handoff lock");
            actual.set(name, marker);
          }
        }} finally { await directoryStream.close().catch(() => undefined); }
        if (await directoryDigest(directory) !== before) throw new Error("nested handoff inventory directory replaced");
      }
      // Recheck every ancestor after all descendant inspections, without retaining Dir handles.
      const ancestors = [...directoryIdentities];
      for (let offset = 0; offset < ancestors.length; offset += 4) {
        const checked = await Promise.allSettled(ancestors.slice(offset, offset + 4).map(async ([directory, before]) => {
          if (await directoryDigest(directory) !== before) throw new Error("nested handoff inventory directory replaced");
        }));
        for (const value of checked) if (value.status === "rejected") throw value.reason;
      }
      const allowedProofs = new Set<string>();
      for (const record of chain) for (const name of names as string[]) {
        const prior = (record.nestedLocks as Record<string, unknown>)[name];
        if (prior === null || parseMarker(prior).ownerToken !== record.previousOwnerToken) continue;
        const proofName = markerName(canonicalJson([record.previousOwnerToken, name])) + ".json";
        const doneName = proofName.replace(/\.json$/u, ".done.json"); allowedProofs.add(proofName); allowedProofs.add(doneName);
        let proof: Record<string, unknown> | undefined; let done: Record<string, unknown> | undefined;
        try { proof = await protectedRead(join(root, "nested-locks", proofName)); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
        try { done = await protectedRead(join(root, "nested-locks", doneName)); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
        if (proof !== undefined) {
          const { markerIdentity, ...base } = proof;
          if (canonicalJson(markerIdentity) !== canonicalJson((record.nestedMarkerIdentities as Record<string, unknown>)[name]) || canonicalJson(base) !== canonicalJson({version:1,handoffDigest:digest(record),lockName:name,lockPath:mapping[name],directoryIdentityDigest:identities[name],previousMarker:prior}) || markerIdentity === null || typeof markerIdentity !== "object" || Object.keys(markerIdentity).sort().join(",") !== "ctimeMs,dev,ino,mtimeMs" || Object.values(markerIdentity).some(value => typeof value !== "number" || !Number.isFinite(value))) throw new Error("nested handoff proof does not match immutable inventory");
        }
        if (done !== undefined && (proof === undefined || canonicalJson(done) !== canonicalJson({version:1,completionProofDigest:digest(proof)}))) throw new Error("nested handoff completion acknowledgment malformed");
        const marker = actual.get(name);
        if (marker !== undefined && canonicalJson(marker) === canonicalJson(prior)) {
          if (done !== undefined) throw new Error("completed nested marker reappeared");
          const originalInfo = await lstat(join(root, mapping[name] as string));
          if (canonicalJson((record.nestedMarkerIdentities as Record<string, unknown>)[name]) !== canonicalJson({dev:originalInfo.dev,ino:originalInfo.ino,mtimeMs:originalInfo.mtimeMs,ctimeMs:originalInfo.ctimeMs})) throw new Error("original nested handoff marker identity changed");
          if (proof !== undefined) { const info = await lstat(join(root, mapping[name] as string)); if (canonicalJson(proof.markerIdentity) !== canonicalJson({dev:info.dev,ino:info.ino,mtimeMs:info.mtimeMs,ctimeMs:info.ctimeMs})) throw new Error("nested handoff marker identity changed"); }
        } else if (marker === undefined) {
          if (proof === undefined) throw new Error("nested handoff marker missing without completion proof");
        } else if (done === undefined) throw new Error("nested handoff marker changed before acknowledgment");
      }
      for (const entry of await readdir(join(root, "nested-locks"))) if (!allowedProofs.has(entry)) throw new Error("unexpected nested handoff completion proof");
      for (const name of names as string[]) {
        let current = root;
        for (const part of dirname(mapping[name] as string).split("/")) { current = join(current, part); await directoryDigest(current); }
        if (await directoryDigest(current) !== identities[name]) throw new Error("nested handoff directory changed");
      }
    };
    await validateWholeRoot();
    await this.syncDirectory(join(root, "handoffs"));
    const handoff = chain.find(record => record.previousOwnerToken === options.handoffPreviousOwnerToken);
    if (handoff === undefined) throw new Error("nested handoff lacks durable complete authority");
    const previousMarker = parseMarker((handoff.nestedLocks as Record<string, unknown>)[options.lockName]);
    if (previousMarker.ownerToken !== handoff.previousOwnerToken) throw new Error("nested completion must use original immutable handoff");
    const proofBase = { version: 1, handoffDigest: digest(handoff), lockName: options.lockName, lockPath: path, directoryIdentityDigest: identities[options.lockName], previousMarker };
    const proofPath = join(root, "nested-locks", markerName(canonicalJson([handoff.previousOwnerToken, options.lockName])) + ".json");
    let proof: Record<string, unknown> | undefined;
    try { proof = await protectedRead(proofPath); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    const validateProof = (value: Record<string, unknown>) => {
      const { markerIdentity, ...base } = value;
      if (canonicalJson(markerIdentity) !== canonicalJson((handoff.nestedMarkerIdentities as Record<string, unknown>)[options.lockName]) || canonicalJson(base) !== canonicalJson(proofBase) || markerIdentity === null || typeof markerIdentity !== "object" || Object.keys(markerIdentity).sort().join(",") !== "ctimeMs,dev,ino,mtimeMs" || Object.values(markerIdentity).some(value => typeof value !== "number" || !Number.isFinite(value))) throw new Error("nested handoff completion proof mismatch");
    };
    if (proof !== undefined) validateProof(proof);
    const lockPath = join(this.directory, ".store-lock.json");
    const handle = await open(lockPath, constants.O_RDONLY | constants.O_NOFOLLOW).catch(error => {
      if ((error as NodeJS.ErrnoException).code === "ENOENT" && proof !== undefined) return undefined;
      throw error;
    });
    if (handle !== undefined) {
      try {
        const info = await handle.stat();
        if (!info.isFile() || info.nlink !== 1 || info.size > 4096 || (info.mode & 0o777) !== 0o600 || (process.getuid !== undefined && info.uid !== process.getuid())) throw new Error("nested handoff lock is unsafe");
        const markerIdentity = { dev: info.dev, ino: info.ino, mtimeMs: info.mtimeMs, ctimeMs: info.ctimeMs };
        if (canonicalJson(markerIdentity) !== canonicalJson((handoff.nestedMarkerIdentities as Record<string, unknown>)[options.lockName])) throw new Error("original nested handoff marker identity changed");
        const buffer = Buffer.alloc(4097); const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
        if (bytesRead !== info.size || canonicalJson(parseMarker(JSON.parse(buffer.subarray(0, bytesRead).toString("utf8")))) !== canonicalJson(previousMarker)) throw new Error("nested handoff prior marker changed");
        if (proof === undefined) {
          proof = { ...proofBase, markerIdentity };
          try { await this.publishJson(proofPath, proof, "handoff-proof", "nested completion proof already exists", dirname(proofPath)); }
          catch (error) { if (!(error instanceof DuplicateStoreRecordError)) throw error; proof = await protectedRead(proofPath); validateProof(proof); }
        }
        if (canonicalJson(proof.markerIdentity) !== canonicalJson(markerIdentity)) throw new Error("nested handoff lock identity changed after completion intent");
        await this.syncDirectory(dirname(proofPath));
        await this.options.faultInjector?.("handoff:after-proof");
        owner[RECEIPT_STORE_LOCK_AUTHORIZER]();
        await validateWholeRoot();
        if (await directoryDigest(root) !== owner.rootIdentityDigest || await directoryDigest(this.directory) !== identities[options.lockName]) throw new Error("nested handoff directory changed before removal");
        const after = await handle.stat(); const node = await lstat(lockPath);
        if (node.isSymbolicLink() || after.dev !== info.dev || after.ino !== info.ino || after.mtimeMs !== info.mtimeMs || after.ctimeMs !== info.ctimeMs || node.dev !== info.dev || node.ino !== info.ino) throw new Error("nested handoff marker changed before removal");
        await rm(lockPath);
        await this.options.faultInjector?.("handoff:after-remove");
      } finally { await handle.close(); }
    }
    await this.syncDirectory(this.directory);
    owner[RECEIPT_STORE_LOCK_AUTHORIZER]();
    const donePath = proofPath.replace(/\.json$/u, ".done.json");
    const done = { version: 1, completionProofDigest: digest(proof) };
    try { await this.publishJson(donePath, done, "handoff-completion", "nested completion already acknowledged", dirname(donePath)); }
    catch (error) { if (!(error instanceof DuplicateStoreRecordError)) throw error; if (canonicalJson(await protectedRead(donePath)) !== canonicalJson(done)) throw new Error("nested completion acknowledgment mismatch"); }
    await this.syncDirectory(dirname(donePath));
    await this.options.faultInjector?.("handoff:after-completion");
  }

  /** Offline operator action for a lock left by a crashed process. Exact token possession is required. */
  async recoverAbandonedLock(options: { readonly offlineExclusive: true; readonly ownerToken: string }): Promise<void> {
    if (this.options.lockOwnership !== undefined) throw new Error("nested lock recovery requires protected whole-root handoff authority, not token possession");
    await this.initialize();
    if (options?.offlineExclusive !== true || typeof options.ownerToken !== "string") throw new Error("offlineExclusive and exact ownerToken are required");
    await this.releaseLock(options.ownerToken);
  }

  private record(receipt: AlphaIntegrityReceipt, quotaSlot: number, transactionId: string): StoredReceiptRecord {
    if (!SHA256.test(receipt.receiptDigest)) throw new Error("receipt digest is invalid");
    return { version: 3, runId: receipt.runId, nonce: receipt.nonce, receiptDigest: receipt.receiptDigest, quotaSlot, transactionId };
  }

  private async reserveQuota(receipt: AlphaIntegrityReceipt, transactionId: string): Promise<StoredReceiptRecord> {
    const start = Number.parseInt(receipt.receiptDigest.slice(0, 8), 16) % this.#maxRecords;
    for (let offset = 0; offset < this.#maxRecords; offset += 1) {
      const slot = (start + offset) % this.#maxRecords;
      const record = this.record(receipt, slot, transactionId);
      try {
        await this.publishJson(this.path("quota", String(slot)), record, "quota", "quota slot exists");
        return record;
      } catch (error) {
        if (error instanceof DuplicateStoreRecordError) continue;
        const reservationState: QuotaReservationState = typeof (error as { publishedPath?: unknown }).publishedPath === "string"
          ? "possibly-reserved"
          : "not-reserved";
        throw new QuotaReservationError("quota reservation failed", reservationState, { cause: error });
      }
    }
    throw new QuotaReservationError(`receipt store has reached its ${this.#maxRecords} record limit`, "not-reserved");
  }

  private async quotaFor(transactionId: string): Promise<StoredReceiptRecord | undefined> {
    for (let slot = 0; slot < this.#maxRecords; slot += 1) {
      try { const record = await this.readRecord(this.path("quota", String(slot)), "quota"); if (record.transactionId === transactionId) return record; }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    }
    return undefined;
  }

  private async cleanupOwned(record: StoredReceiptRecord, paths: readonly string[]): Promise<void> {
    const journalPath = this.path("cleanup", record.receiptDigest);
    const journal = {
      version: record.version,
      runId: record.runId,
      nonce: record.nonce,
      receiptDigest: record.receiptDigest,
      quotaSlot: record.quotaSlot,
      transactionId: record.transactionId,
      cleanupPaths: paths,
    };
    try { await this.publishJson(journalPath, journal, "cleanup-journal", "cleanup journal exists"); }
    catch (error) {
      if (!(error instanceof DuplicateStoreRecordError)) throw error;
      const existing = await this.readRecord(journalPath, "cleanup");
      if (existing.transactionId !== record.transactionId) throw new Error("cleanup journal ownership mismatch");
    }
    for (const path of paths) {
      try {
        const actual = await this.readRecord(path, path.includes("/issued/") ? "issued" : path.includes("/consumed/") ? "consumed" : path.includes("/closed/") ? "closed" : path.includes("/quota/") ? "quota" : path.includes("/runs/") ? "run" : path.includes("/nonces/") ? "nonce" : "transaction");
        await this.options.faultInjector?.("cleanup:after-ownership-read");
        if (actual.transactionId !== record.transactionId || actual.receiptDigest !== record.receiptDigest) throw new Error("cleanup ownership mismatch");
        await rm(path);
        await this.syncDirectory(dirname(path));
        await this.options.faultInjector?.("cleanup:after-removal");
      } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    }
    await rm(journalPath);
    await this.syncDirectory(dirname(journalPath));
  }

  private async optionalRecord(path: string, kind: ReceiptRecordKind): Promise<StoredReceiptRecord | undefined> {
    try { return await this.readRecord(path, kind); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined; throw error; }
  }

  private sameBinding(actual: StoredReceiptRecord, expected: StoredReceiptRecord, intent = false): void {
    if (actual.runId !== expected.runId || actual.nonce !== expected.nonce || actual.receiptDigest !== expected.receiptDigest || actual.transactionId !== expected.transactionId || actual.quotaSlot !== (intent ? -1 : expected.quotaSlot)) throw new Error("receipt store record binding mismatch");
    if (actual.receipt !== undefined && expected.receipt !== undefined && canonicalJson(actual.receipt) !== canonicalJson(expected.receipt)) throw new Error("receipt store payload mismatch");
  }

  /** Bounded inventory also detects orphan pointers and reused transaction identities. */
  private async relatedRecords(receiptDigest: string, runId?: string, nonce?: string, transactionId?: string): Promise<Array<{ path: string; kind: ReceiptRecordKind; record: StoredReceiptRecord }>> {
    const result: Array<{ path: string; kind: ReceiptRecordKind; record: StoredReceiptRecord }> = [];
    const directories = [["transactions", "transaction"], ["quota", "quota"], ["runs", "run"], ["nonces", "nonce"], ["issued", "issued"], ["consumed", "consumed"], ["closed", "closed"], ["cleanup", "cleanup"]] as const;
    // Four independent directory inventories, each with sequential fresh reads.
    // No record reuse or authority sharing: all work stays under the same lock.
    // Settle the entire started batch before rejection or lock release.
    for (let offset = 0; offset < directories.length; offset += 4) {
      const checked = await Promise.allSettled(directories.slice(offset, offset + 4).map(async ([directory, kind]) => {
        const matches: Array<{ path: string; kind: ReceiptRecordKind; record: StoredReceiptRecord }> = [];
        const entries = await readdir(join(this.directory, directory), { withFileTypes: true });
        if (entries.length > this.#maxRecords) throw new Error("receipt store inventory exceeds configured limit");
        for (const entry of entries) {
          if (!entry.isFile() || !/^[a-f0-9]{64}\.json$/u.test(entry.name)) throw new Error("invalid receipt store inventory entry");
          const path = join(this.directory, directory, entry.name);
          const record = await this.readRecord(path, kind);
          const identity = directory === "quota" ? String(record.quotaSlot) : directory === "runs" ? record.runId : directory === "nonces" ? record.nonce : record.receiptDigest;
          if (this.path(directory, identity) !== path || (directory === "quota" && (record.quotaSlot < 0 || record.quotaSlot >= this.#maxRecords))) throw new Error("receipt store record path identity mismatch");
          if (record.receiptDigest === receiptDigest || (runId !== undefined && record.runId === runId) || (nonce !== undefined && record.nonce === nonce) || (transactionId !== undefined && record.transactionId === transactionId)) matches.push({ path, kind, record });
        }
        return matches;
      }));
      for (const value of checked) {
        if (value.status === "rejected") throw value.reason;
        for (const match of value.value) result.push(match);
      }
    }
    return result;
  }

  private async validatedIssued(receiptDigest: string): Promise<IssuedReceiptRecord | undefined> {
    const issued = await this.optionalRecord(this.path("issued", receiptDigest), "issued");
    const related = await this.relatedRecords(receiptDigest, issued?.runId, issued?.nonce, issued?.transactionId);
    if (issued === undefined) {
      if (related.length !== 0) throw new Error("missing issued receipt with surviving issuance pointers");
      return undefined;
    }
    if (issued.receiptDigest !== receiptDigest || issued.quotaSlot < 0 || issued.quotaSlot >= this.#maxRecords) throw new Error("issued receipt identity mismatch");
    for (const entry of related) {
      if (entry.kind === "cleanup") throw new Error("receipt cleanup is pending");
      this.sameBinding(entry.record, issued, entry.kind === "transaction");
    }
    for (const kind of ["transaction", "quota", "run", "nonce", "issued"] as const)
      if (related.filter(entry => entry.kind === kind).length !== 1) throw new Error("missing or contradictory issuance pointer");
    return issued as IssuedReceiptRecord;
  }

  /** Live coordinator only: complete the exact prepared issuance without rollback or replacement. */
  async completePreparedIssue(receipt: AlphaIntegrityReceipt, options: { readonly transactionId: string }): Promise<void> {
    if (this.options.lockOwnership === undefined) throw new Error("live root lock ownership is required for completion");
    if (!SAFE_IDENTIFIER.test(options?.transactionId ?? "")) throw new Error("a safe caller-supplied transactionId is required");
    // Snapshot caller input before the first asynchronous boundary.
    const prepared = structuredClone(receipt);
    parseStoredReceiptRecord({ ...this.record(prepared, -1, options.transactionId), receipt: prepared }, "issued");
    const transactionId = options.transactionId;
    return this.withLock(async () => {
      const intent = this.record(prepared, -1, transactionId);
      const related = await this.relatedRecords(prepared.receiptDigest, prepared.runId, prepared.nonce, transactionId);
      const intents = related.filter(entry => entry.kind === "transaction");
      const quotas = related.filter(entry => entry.kind === "quota");
      if (intents.length > 1 || quotas.length > 1 || (intents.length === 0 && related.length !== 0)) throw new Error("missing or contradictory prepared issuance intent");
      if (related.some(entry => entry.kind === "cleanup" || entry.kind === "closed" || entry.kind === "consumed")) throw new Error("cannot complete terminal or cleanup issuance");
      const quota = quotas[0]?.record;
      const expected = { ...this.record(prepared, quota?.quotaSlot ?? -1, transactionId), receipt: prepared };
      for (const entry of related) this.sameBinding(entry.record, expected, entry.kind === "transaction");
      if (quota === undefined && related.some(entry => entry.kind !== "transaction")) throw new Error("issuance pointers have no quota reservation");
      for (const kind of ["run", "nonce", "issued"] as const)
        if (related.filter(entry => entry.kind === kind).length > 1) throw new Error("contradictory issuance pointers");
      // Only ordered publication prefixes are explainable as interrupted issuance.
      const has = (kind: ReceiptRecordKind) => related.some(entry => entry.kind === kind);
      if ((has("nonce") && !has("run")) || (has("issued") && (!has("nonce") || !has("run")))) throw new Error("contradictory issuance publication order");
      const authorize = () => this.options.lockOwnership![RECEIPT_STORE_LOCK_AUTHORIZER]();
      if (intents.length === 0) { authorize(); await this.publishJson(this.path("transactions", prepared.receiptDigest), intent, "transaction", "issuance transaction already exists"); }
      // Existing publications must be synced again after a previous sync failure.
      for (const entry of related) await this.syncDirectory(dirname(entry.path));
      authorize();
      const record = quota ?? await this.reserveQuota(prepared, transactionId);
      for (const [kind, directory, identity] of [["run", "runs", prepared.runId], ["nonce", "nonces", prepared.nonce], ["issued", "issued", prepared.receiptDigest]] as const) {
        if (!has(kind)) {
          authorize();
          if (kind === "issued") await this.options.faultInjector?.("issue:before-issued");
          await this.publishJson(this.path(directory, identity), kind === "issued" ? { ...record, receipt: prepared } : record, kind, "issuance pointer already exists");
        }
      }
    });
  }

  async issue(receipt: AlphaIntegrityReceipt, options: { readonly transactionId: string }): Promise<void> {
    if (this.options.lockOwnership !== undefined) return this.completePreparedIssue(receipt, options);
    if (options === null || typeof options !== "object" || !SAFE_IDENTIFIER.test(options.transactionId)) throw new Error("a safe caller-supplied transactionId is required");
    parseStoredReceiptRecord({ ...this.record(receipt, -1, options.transactionId), receipt }, "issued");
    return this.withLock(async () => {
      const transactionId = options.transactionId;
      const intent = this.record(receipt, -1, transactionId);
      const transactionPath = this.path("transactions", receipt.receiptDigest);
      await this.publishJson(transactionPath, intent, "transaction", "issuance transaction already exists");
      let record: StoredReceiptRecord;
      try {
        record = await this.reserveQuota(receipt, transactionId);
      } catch (error) {
        if (error instanceof QuotaReservationError && error.reservationState === "not-reserved") {
          await this.cleanupOwned(intent, [transactionPath]);
        }
        throw error;
      }
      try {
        await this.publishJson(this.path("runs", receipt.runId), record, "run", `run ID already exists: ${receipt.runId}`);
        await this.publishJson(this.path("nonces", receipt.nonce), record, "nonce", `receipt nonce already exists: ${receipt.nonce}`);
        await this.options.faultInjector?.("issue:before-issued");
        await this.publishJson(this.path("issued", receipt.receiptDigest), { ...record, receipt }, "issued", "receipt is already issued");
      } catch (error) {
        if (typeof (error as { publishedPath?: unknown }).publishedPath !== "string") {
          await this.cleanupOwned(record, [this.path("nonces", receipt.nonce), this.path("runs", receipt.runId), transactionPath, this.path("quota", String(record.quotaSlot))]);
        }
        throw error;
      }
    });
  }

  async rollbackIssue(receiptDigest: string): Promise<void> {
    return this.withLock(async () => {
      const issued = await this.readRecord(this.path("issued", receiptDigest), "issued");
      try { await stat(this.path("consumed", receiptDigest)); throw new Error("cannot roll back a consumed receipt"); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
      await this.cleanupOwned(issued, [this.path("issued", receiptDigest), this.path("nonces", issued.nonce), this.path("runs", issued.runId), this.path("transactions", receiptDigest), this.path("quota", String(issued.quotaSlot))]);
    });
  }

  async reconcileCleanup(receiptDigest: string): Promise<void> {
    return this.withLock(async () => {
      const journal = await this.readRecord(this.path("cleanup", receiptDigest), "cleanup");
      if (!Array.isArray(journal.cleanupPaths)) throw new Error("cleanup journal is malformed");
      await this.cleanupOwned(journal, journal.cleanupPaths);
    });
  }

  async recoverInterruptedIssue(receipt: AlphaIntegrityReceipt, options: { readonly offlineExclusive: true; readonly transactionId: string }): Promise<void> {
    if (options?.offlineExclusive !== true || typeof options.transactionId !== "string") throw new Error("offlineExclusive recovery and transactionId are required");
    return this.withLock(async () => {
      const intent = await this.readRecord(this.path("transactions", receipt.receiptDigest), "transaction");
      if (intent.transactionId !== options.transactionId) throw new Error("recovery transaction ownership mismatch");
      parseStoredReceiptRecord({ ...intent, receipt }, "issued");
      try { await stat(this.path("issued", receipt.receiptDigest)); throw new Error("cannot recover a completed issuance"); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
      const quota = await this.quotaFor(options.transactionId);
      const record = quota ?? intent;
      const paths = [this.path("nonces", receipt.nonce), this.path("runs", receipt.runId), this.path("transactions", receipt.receiptDigest), ...(quota === undefined ? [] : [this.path("quota", String(quota.quotaSlot))])];
      await this.cleanupOwned(record, paths);
    });
  }

  async completeReceiptFile(receiptDigest: string, output: ReceiptOutputBoundary, safeRelativeName: string): Promise<AlphaIntegrityReceipt> {
    return this.withLock(async () => {
      if (!(output instanceof ReceiptOutputBoundary)) throw new Error("receipt output boundary is required");
      const record = await this.readRecord(this.path("issued", receiptDigest), "issued");
      const receipt = record.receipt;
      if (receipt === undefined) throw new Error("issued receipt payload is missing or mismatched");
      const bytes = Buffer.from(`${canonicalJson(receipt)}\n`, "utf8");
      if (bytes.byteLength > this.#maxStateBytes) throw new Error("receipt output exceeds configured limit");
      await output.publishEquivalent(safeRelativeName, bytes);
      await this.options.faultInjector?.("receipt-output:after-publish");
      return freezeValidated(structuredClone(receipt));
    });
  }

  async consume(receipt: AlphaIntegrityReceipt, consumedAt: Date): Promise<void> {
    return this.withLock(async () => {
      if (!(consumedAt instanceof Date) || !Number.isFinite(consumedAt.getTime())) throw new Error("consumedAt must be a valid Date");
      const issued = await this.readRecord(this.path("issued", receipt.receiptDigest), "issued");
      if (issued.runId !== receipt.runId || issued.nonce !== receipt.nonce) throw new Error("receipt registry binding mismatch");
      if (issued.receipt === undefined || canonicalJson(issued.receipt) !== canonicalJson(receipt)) throw new Error("receipt registry payload mismatch");
      try {
        await this.readRecord(this.path("closed", receipt.receiptDigest), "closed");
        throw new Error("cannot consume a closed receipt");
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
      await this.publishJson(this.path("consumed", receipt.receiptDigest), { ...issued, consumedAt: consumedAt.toISOString() }, "consumed", "receipt has already been consumed");
    });
  }

  async closeIssuedReceipt(receiptDigest: string, options: { readonly transactionId: string; readonly closedAt: Date; readonly reasonCode: string }): Promise<void> {
    if (!SHA256.test(receiptDigest) || !SAFE_IDENTIFIER.test(options?.transactionId ?? "") || !(options.closedAt instanceof Date) || !Number.isFinite(options.closedAt.getTime()) || !REASON_CODE.test(options.reasonCode)) throw new Error("invalid receipt close request");
    return this.withLock(async () => {
      const issued = await this.readRecord(this.path("issued", receiptDigest), "issued");
      if (issued.transactionId !== options.transactionId) throw new Error("receipt close transaction mismatch");
      try {
        await this.readRecord(this.path("consumed", receiptDigest), "consumed");
        throw new Error("cannot close a consumed receipt");
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
      await this.publishJson(this.path("closed", receiptDigest), { ...issued, closedAt: options.closedAt.toISOString(), reasonCode: options.reasonCode }, "closed", "receipt is already closed");
    });
  }

  async inspectIssuedRecordByDigest(receiptDigest: string): Promise<IssuedReceiptRecord | undefined> {
    if (!SHA256.test(receiptDigest)) throw new Error("receipt digest is invalid");
    return this.withLock(async () => {
      const record = await this.validatedIssued(receiptDigest);
      return record === undefined ? undefined : freezeValidated(structuredClone(record));
    });
  }

  async inspectIssuedRecordByRunId(runId: string): Promise<IssuedReceiptRecord | undefined> {
    if (!SAFE_IDENTIFIER.test(runId)) throw new Error("run ID is invalid");
    return this.withLock(async () => {
      const pointer = await this.optionalRecord(this.path("runs", runId), "run");
      if (pointer === undefined) {
        const related = await this.relatedRecords("", runId);
        if (related.length !== 0) throw new Error("missing run receipt pointer");
        return undefined;
      }
      if (pointer.runId !== runId) throw new Error("run receipt identity mismatch");
      const issued = await this.validatedIssued(pointer.receiptDigest);
      if (issued === undefined) throw new Error("missing issued receipt for run pointer");
      this.sameBinding(pointer, issued);
      return freezeValidated(structuredClone(issued));
    });
  }

  async inspectIssuedByDigest(receiptDigest: string): Promise<AlphaIntegrityReceipt | undefined> {
    return (await this.inspectIssuedRecordByDigest(receiptDigest))?.receipt;
  }

  async inspectIssuedByRunId(runId: string): Promise<AlphaIntegrityReceipt | undefined> {
    return (await this.inspectIssuedRecordByRunId(runId))?.receipt;
  }

  async inspectClosed(receiptDigest: string): Promise<ClosedReceiptRecord | undefined> {
    if (!SHA256.test(receiptDigest)) throw new Error("receipt digest is invalid");
    return this.withLock(async () => {
      const issued = await this.validatedIssued(receiptDigest);
      const closed = await this.optionalRecord(this.path("closed", receiptDigest), "closed");
      if (closed === undefined) return undefined;
      if (issued === undefined) throw new Error("closed receipt has no issued evidence");
      this.sameBinding(closed, issued);
      if (await this.optionalRecord(this.path("consumed", receiptDigest), "consumed") !== undefined) throw new Error("conflicting consumed and closed receipt evidence");
      return freezeValidated(structuredClone(closed)) as ClosedReceiptRecord;
    });
  }

  async inspectConsumed(receiptDigest: string): Promise<ConsumedReceiptRecord | undefined> {
    if (!SHA256.test(receiptDigest)) throw new Error("receipt digest is invalid");
    return this.withLock(async () => {
      const issued = await this.validatedIssued(receiptDigest);
      const consumed = await this.optionalRecord(this.path("consumed", receiptDigest), "consumed");
      if (consumed === undefined) return undefined;
      if (issued === undefined) throw new Error("consumed receipt has no issued evidence");
      this.sameBinding(consumed, issued);
      if (await this.optionalRecord(this.path("closed", receiptDigest), "closed") !== undefined) throw new Error("conflicting consumed and closed receipt evidence");
      return consumedView(consumed);
    });
  }

  async inspectCapacity(): Promise<{ readonly used: number; readonly maximum: number }> {
    return this.withLock(async () => {
      const entries = await readdir(join(this.directory, "quota"), { withFileTypes: true });
      if (entries.length > this.#maxRecords) throw new Error("receipt quota exceeds configured record limit");
      let used = 0;
      for (const entry of entries) {
        if (!entry.isFile() || !/^[a-f0-9]{64}\.json$/u.test(entry.name)) throw new Error("invalid receipt quota entry");
        await this.readRecord(join(this.directory, "quota", entry.name), "quota");
        used += 1;
      }
      return freezeValidated({ used, maximum: this.#maxRecords });
    });
  }
}
