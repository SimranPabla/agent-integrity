import { createHash, randomUUID } from "node:crypto";
import { lstat, realpath, open, opendir, mkdir } from "node:fs/promises";
import { constants } from "node:fs";
import { join, dirname } from "node:path";
import { canonicalJson, FileReceiptStore, RECEIPT_STORE_LOCK_AUTHORIZER, type ReceiptStoreLockOwnership } from "@agent-integrity/core";
import { DurableJsonDirectory, DurableRecordExistsError, type DurableJsonOptions } from "./durable-json.js";

// 1024 UTF-8 bytes admit at most 512 one-byte segments (including slashes).
// Add snapshots/<id>/project and eight bounded metadata levels; keep core in sync.
const MAX_ROOT_INVENTORY_DEPTH = 512 + 3 + 8;
const SAFE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const liveCapabilities = new WeakSet<object>();
const recordDigest = (value: unknown): string => createHash("sha256").update(canonicalJson(value)).digest("hex");
const completionName = (owner: string, name: string): string => recordDigest([owner, name]) + ".json";

export interface MutationCapability { readonly ownerToken: string; readonly storeGeneration: string; readonly rootIdentityDigest: string }
export interface StateCoordinatorOptions extends Partial<DurableJsonOptions> {
  readonly storeGeneration: string;
  readonly nestedLockNames: readonly string[];
  readonly nestedLockPaths?: Readonly<Record<string, string>>;
}
export interface CoordinatorLockOwnership {
  readonly ownerToken: string; readonly storeGeneration: string; readonly rootIdentityDigest: string;
}
interface LeaseRecord extends CoordinatorLockOwnership {
  readonly version: 2;
  readonly nestedLockNames: readonly string[];
  readonly nestedLockPaths: Readonly<Record<string, string>>;
  readonly nestedDirectoryIdentities: Readonly<Record<string, string>>;
  readonly startedAt: string;
}
interface HandoffRecord extends CoordinatorLockOwnership {
  readonly version: 2;
  readonly previousOwnerToken: string;
  readonly nestedLockNames: readonly string[];
  readonly nestedLockPaths: Readonly<Record<string, string>>;
  readonly nestedDirectoryIdentities: Readonly<Record<string, string>>;
  readonly nestedLocks: Readonly<Record<string, unknown>>;
  readonly nestedMarkerIdentities: Readonly<Record<string, unknown>>;
  readonly createdAt: string;
}

function closedLease(value: unknown): LeaseRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new Error("state-root lease is malformed");
  const record = value as Record<string, unknown>;
  if (Object.keys(record).sort().join(",") !== "nestedDirectoryIdentities,nestedLockNames,nestedLockPaths,ownerToken,rootIdentityDigest,startedAt,storeGeneration,version" || record.version !== 2 || typeof record.ownerToken !== "string" || !SAFE.test(record.ownerToken) || typeof record.storeGeneration !== "string" || !SAFE.test(record.storeGeneration) || typeof record.rootIdentityDigest !== "string" || !/^[a-f0-9]{64}$/u.test(record.rootIdentityDigest) || typeof record.startedAt !== "string" || new Date(record.startedAt).toISOString() !== record.startedAt || !Array.isArray(record.nestedLockNames) || record.nestedLockNames.some((name) => typeof name !== "string" || !SAFE.test(name))) throw new Error("state-root lease is malformed");
  trustedMapping(record.nestedLockNames as string[], record.nestedLockPaths);
  directoryIdentities(record.nestedLockNames as string[], record.nestedDirectoryIdentities);
  return record as unknown as LeaseRecord;
}
function closedHandoff(value: unknown): HandoffRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new Error("state-root handoff is malformed");
  const record = value as Record<string, unknown>;
  if (Object.keys(record).sort().join(",") !== "createdAt,nestedDirectoryIdentities,nestedLockNames,nestedLockPaths,nestedLocks,nestedMarkerIdentities,ownerToken,previousOwnerToken,rootIdentityDigest,storeGeneration,version" || record.version !== 2 || typeof record.ownerToken !== "string" || !SAFE.test(record.ownerToken) || typeof record.previousOwnerToken !== "string" || !SAFE.test(record.previousOwnerToken) || record.ownerToken === record.previousOwnerToken || typeof record.storeGeneration !== "string" || !SAFE.test(record.storeGeneration) || typeof record.rootIdentityDigest !== "string" || !/^[a-f0-9]{64}$/u.test(record.rootIdentityDigest) || typeof record.createdAt !== "string" || new Date(record.createdAt).toISOString() !== record.createdAt || !Array.isArray(record.nestedLockNames) || record.nestedLockNames.some((name) => typeof name !== "string" || !SAFE.test(name))) throw new Error("state-root handoff is malformed");
  const mapping = trustedMapping(record.nestedLockNames as string[], record.nestedLockPaths);
  directoryIdentities(record.nestedLockNames as string[], record.nestedDirectoryIdentities);
  if (record.nestedLocks === null || typeof record.nestedLocks !== "object" || Array.isArray(record.nestedLocks) || Object.keys(record.nestedLocks).sort().join(",") !== Object.keys(mapping).sort().join(",")) throw new Error("partial nested lock handoff");
  for (const value of Object.values(record.nestedLocks)) if (value !== null) { const marker = value as Record<string, unknown>; if (typeof marker.ownerToken !== "string" || !SAFE.test(marker.ownerToken)) throw new Error("nested handoff owner is malformed"); closedNestedLock(value, { ownerToken: marker.ownerToken, storeGeneration: record.storeGeneration as string, rootIdentityDigest: record.rootIdentityDigest as string }); }
  if (record.nestedMarkerIdentities === null || typeof record.nestedMarkerIdentities !== "object" || Array.isArray(record.nestedMarkerIdentities) || Object.keys(record.nestedMarkerIdentities).sort().join(",") !== Object.keys(mapping).sort().join(",")) throw new Error("partial nested marker identity inventory");
  for (const name of Object.keys(mapping)) { const identity = (record.nestedMarkerIdentities as Record<string, unknown>)[name]; if ((record.nestedLocks as Record<string, unknown>)[name] === null) { if (identity !== null) throw new Error("absent nested marker identity mismatch"); } else if (identity === null || typeof identity !== "object" || Object.keys(identity).sort().join(",") !== "ctimeMs,dev,ino,mtimeMs" || Object.values(identity).some(value => typeof value !== "number" || !Number.isFinite(value))) throw new Error("nested marker identity malformed"); }
  return record as unknown as HandoffRecord;
}
function directoryIdentities(names: readonly string[], value: unknown): void {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join(",") !== [...names].sort().join(",") || Object.values(value).some(id=>typeof id!=="string" || !/^[a-f0-9]{64}$/u.test(id))) throw new Error("nested directory identity inventory is invalid");
}
async function captureNestedDirectories(root: string, mapping: Readonly<Record<string,string>>): Promise<Readonly<Record<string,string>>> {
  const entries: Array<[string,string]> = [];
  for (const [name,path] of Object.entries(mapping)) {
    let current=root;
    for (const segment of dirname(path).split("/")) { current=join(current,segment); const info=await lstat(current); if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o777)!==0o700 || (process.getuid!==undefined && info.uid!==process.getuid())) throw new Error("configured nested lock directory is missing or unsafe"); }
    entries.push([name,await rootDigest(current)]);
  }
  return Object.freeze(Object.fromEntries(entries));
}
function trustedMapping(names: readonly string[], value: unknown): Readonly<Record<string, string>> {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype || Object.keys(value).sort().join(",") !== [...names].sort().join(",")) throw new Error("complete trusted nested lock path mapping is required");
  if (names.length > 64 || new Set(names).size !== names.length || names.some(name=>!SAFE.test(name))) throw new Error("nested lock inventory is invalid");
  const paths = value as Record<string, string>; const unique = new Set<string>();
  for (const path of Object.values(paths)) {
    if (typeof path !== "string" || Buffer.byteLength(path) > 1024 || !/^[A-Za-z0-9][A-Za-z0-9._-]*(?:\/[A-Za-z0-9][A-Za-z0-9._-]*)*\/\.store-lock\.json$/u.test(path) || path.split("/").some(part => part === "." || part === "..") || unique.has(path)) throw new Error("unsafe or duplicate nested lock path");
    unique.add(path);
  }
  return Object.freeze({ ...paths });
}
function closedNestedLock(value: unknown, owner: CoordinatorLockOwnership): void {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new Error("nested lock is malformed");
  const record = value as Record<string, unknown>;
  if (Object.keys(record).sort().join(",") !== "ownerToken,rootIdentityDigest,storeGeneration,version" || record.version !== 2 || record.ownerToken !== owner.ownerToken || record.storeGeneration !== owner.storeGeneration || record.rootIdentityDigest !== owner.rootIdentityDigest) throw new Error("nested lock ownership token, generation or root mismatch");
}
async function inspectNestedLocks(directory: string, lease: LeaseRecord, prior: readonly HandoffRecord[] = [], markerIdentities: Record<string, unknown> = {}): Promise<Readonly<Record<string, unknown>>> {
  const expected = new Set(Object.values(lease.nestedLockPaths)); const observed = new Map<string, unknown>(); const identities = new Map<string, { dev: number; ino: number; uid: number }>(); let entries = 0;
  const pending = [{ absolute: directory, prefix: "", depth: 0 }];
  while (pending.length > 0) {
    const { absolute, prefix, depth } = pending.pop()!;
    if (depth > MAX_ROOT_INVENTORY_DEPTH) throw new Error("nested lock inventory depth exceeded");
    const info = await lstat(absolute);
    if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o777) !== 0o700 || (process.getuid !== undefined && info.uid !== process.getuid())) throw new Error("nested inventory directory ownership or mode mismatch");
    const queuedIdentity = identities.get(absolute);
    if (queuedIdentity !== undefined && (queuedIdentity.dev !== info.dev || queuedIdentity.ino !== info.ino || queuedIdentity.uid !== info.uid)) throw new Error("nested inventory directory identity changed");
    identities.set(absolute, { dev: info.dev, ino: info.ino, uid: info.uid });
    const stream = await opendir(absolute);
    try { for await (const entry of stream) {
      if (++entries > 100_000) throw new Error("nested lock inventory bound exceeded");
      const relative = prefix === "" ? entry.name : prefix + "/" + entry.name; const full = join(absolute, entry.name); const node = await lstat(full);
      if (node.isSymbolicLink()) throw new Error("nested inventory symlink forbidden");
      if (node.isDirectory()) { identities.set(full, { dev: node.dev, ino: node.ino, uid: node.uid }); pending.push({ absolute: full, prefix: relative, depth: depth + 1 }); continue; }
      if (entry.name === ".store-lock.json") {
        if (!expected.has(relative)) throw new Error("unexpected additional nested lock");
        const handle = await open(full, constants.O_RDONLY | constants.O_NOFOLLOW);
        try {
          const before = await handle.stat();
          if (!before.isFile() || before.nlink !== 1 || before.size > 4096 || (before.mode & 0o777) !== 0o600 || (process.getuid !== undefined && before.uid !== process.getuid())) throw new Error("nested lock mode or ownership invalid");
          const buffer = Buffer.alloc(4097); const { bytesRead } = await handle.read(buffer,0,buffer.length,0); const after=await handle.stat(); const pathAfter=await lstat(full);
          if (bytesRead !== before.size || before.dev !== after.dev || before.ino !== after.ino || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs || pathAfter.ino !== after.ino || pathAfter.dev !== after.dev) throw new Error("nested lock changed during inspection");
          const value: unknown = JSON.parse(buffer.subarray(0,bytesRead).toString("utf8")); const name = Object.keys(lease.nestedLockPaths).find(name => lease.nestedLockPaths[name] === relative)!; const known = prior.some(handoff => canonicalJson(handoff.nestedLocks[name]) === canonicalJson(value)); closedNestedLock(value, known ? { ...lease, ownerToken: (value as CoordinatorLockOwnership).ownerToken } : lease); observed.set(relative, value); markerIdentities[name] = {dev:before.dev,ino:before.ino,mtimeMs:before.mtimeMs,ctimeMs:before.ctimeMs};
        } finally { await handle.close(); }
      }
    }} finally { await stream.close().catch(()=>undefined); }
  }
  // Absent locks are valid only when their configured owning directory actually exists and is protected.
  for (const path of expected) {
    const parts = dirname(path).split("/"); let current=directory;
    for (const part of parts) { current=join(current,part); const info=await lstat(current); if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o777)!==0o700 || (process.getuid !== undefined && info.uid!==process.getuid())) throw new Error("missing or unsafe configured nested lock directory"); }
  }
  const ancestors = [...identities];
  for (let offset = 0; offset < ancestors.length; offset += 4) {
    const checked = await Promise.allSettled(ancestors.slice(offset, offset + 4).map(async ([path, before]) => {
      const after = await lstat(path);
      if (!after.isDirectory() || after.isSymbolicLink() || before.dev !== after.dev || before.ino !== after.ino || before.uid !== after.uid || (after.mode & 0o777) !== 0o700) throw new Error("nested inventory directory identity changed");
    }));
    for (const value of checked) if (value.status === "rejected") throw value.reason;
  }
  for (const name of lease.nestedLockNames) if (!(name in markerIdentities)) markerIdentities[name] = null;
  return Object.freeze(Object.fromEntries(Object.entries(lease.nestedLockPaths).map(([name,path])=>[name,observed.get(path) ?? null])));
}
function sameInventory(left: readonly string[], right: readonly string[]): boolean { return canonicalJson([...left].sort()) === canonicalJson([...right].sort()); }
async function rootDigest(directory: string): Promise<string> {
  const info = await lstat(directory);
  return createHash("sha256").update(canonicalJson({ dev: String(info.dev), ino: String(info.ino), uid: info.uid, real: await realpath(directory) }), "utf8").digest("hex");
}

export function assertMutationCapability(value: unknown): asserts value is MutationCapability {
  if (value === null || typeof value !== "object" || !liveCapabilities.has(value as object)) throw new Error("live coordinator mutation capability is required");
}

export class StateCoordinator {
  readonly #root: DurableJsonDirectory;
  readonly #lease: LeaseRecord;
  #closed = false;
  #mutating = false;
  readonly #offlineRecovery: boolean;
  readonly #faultInjector: DurableJsonOptions["faultInjector"];
  #nestedHandoffCompleted: boolean;

  private constructor(root: DurableJsonDirectory, lease: LeaseRecord, offlineRecovery = false, faultInjector?: DurableJsonOptions["faultInjector"]) { this.#root = root; this.#lease = lease; this.#offlineRecovery = offlineRecovery; this.#faultInjector = faultInjector; this.#nestedHandoffCompleted = !offlineRecovery; }

  static async acquire(directory: string, options: StateCoordinatorOptions): Promise<StateCoordinator> {
    if (!SAFE.test(options.storeGeneration)) throw new TypeError("store generation is invalid");
    const nestedLockNames = [...new Set(options.nestedLockNames)].sort();
    if (nestedLockNames.length !== options.nestedLockNames.length || nestedLockNames.length > 64 || nestedLockNames.some((name) => !SAFE.test(name))) throw new TypeError("nested lock inventory is invalid");
    const nestedLockPaths = trustedMapping(nestedLockNames, options.nestedLockPaths ?? (nestedLockNames.length === 0 ? {} : undefined));
    const root = new DurableJsonDirectory(directory, {
      maxStateBytes: options.maxStateBytes ?? 64 * 1024,
      maxEntries: options.maxEntries ?? 128,
      ...(options.faultInjector === undefined ? {} : { faultInjector: options.faultInjector }),
    });
    await root.initialize(["handoffs", "nested-locks"]);
    try {
      closedLease(await root.read("lease.json"));
      throw new Error("state root already has a lease owner; lock stealing is forbidden");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    if ((await root.entries("handoffs")).length !== 0) throw new Error("orphaned state-root handoff evidence requires offline recovery");
    for (const path of Object.values(nestedLockPaths)) {
      let current=directory;
      for (const segment of dirname(path).split("/")) { current=join(current,segment); try { await mkdir(current,{mode:0o700}); } catch(error) { if ((error as NodeJS.ErrnoException).code!=="EEXIST") throw error; } const info=await lstat(current); if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o777)!==0o700 || (process.getuid!==undefined && info.uid!==process.getuid())) throw new Error("configured nested directory unsafe"); }
    }
    const nestedDirectoryIdentities = await captureNestedDirectories(directory, nestedLockPaths);
    const rootIdentityDigest = await rootDigest(directory);
    const lease: LeaseRecord = {
      version: 2,
      ownerToken: randomUUID(),
      storeGeneration: options.storeGeneration,
      rootIdentityDigest,
      nestedLockNames, nestedLockPaths, nestedDirectoryIdentities,
      startedAt: new Date().toISOString(),
    };
    if ((await root.entries("nested-locks")).length !== 0) throw new Error("orphaned nested lock completion evidence requires offline recovery");
    if (Object.values(await inspectNestedLocks(directory, lease)).some(value => value !== null)) throw new Error("stale nested locks require protected offline recovery");
    try { await root.publishCreateOnce("lease.json", lease); }
    catch (error) {
      if (!(error instanceof DurableRecordExistsError)) throw error;
      closedLease(await root.read("lease.json"));
      throw new Error("state root already has a lease owner; lock stealing is forbidden");
    }
    return new StateCoordinator(root, lease);
  }

  /** Offline recovery only: atomically append one complete ownership handoff and resume under its new token. */
  static async recoverAbandoned(directory: string, options: StateCoordinatorOptions & {
    readonly offlineExclusive: true;
    readonly expectedOwnerToken: string;
    readonly expectedRootIdentityDigest: string;
    readonly nextOwnerToken?: string;
  }): Promise<StateCoordinator> {
    if (options.offlineExclusive !== true || !SAFE.test(options.expectedOwnerToken) || !/^[a-f0-9]{64}$/u.test(options.expectedRootIdentityDigest)) throw new TypeError("offline recovery requires exact prior ownership");
    const nestedLockNames = [...new Set(options.nestedLockNames)].sort();
    if (nestedLockNames.length !== options.nestedLockNames.length || nestedLockNames.length > 64 || nestedLockNames.some((name) => !SAFE.test(name))) throw new TypeError("nested lock inventory is invalid");
    const nestedLockPaths = trustedMapping(nestedLockNames, options.nestedLockPaths ?? (nestedLockNames.length === 0 ? {} : undefined));
    const nextOwnerToken = options.nextOwnerToken ?? randomUUID();
    if (!SAFE.test(nextOwnerToken) || nextOwnerToken === options.expectedOwnerToken) throw new TypeError("next owner token is invalid");
    const root = new DurableJsonDirectory(directory, {
      maxStateBytes: options.maxStateBytes ?? 64 * 1024,
      maxEntries: options.maxEntries ?? 128,
      ...(options.faultInjector === undefined ? {} : { faultInjector: options.faultInjector }),
    });
    await root.initialize(["handoffs", "nested-locks"]);
    if (await rootDigest(directory) !== options.expectedRootIdentityDigest) throw new Error("state-root identity does not match offline recovery authority");
    const history = await StateCoordinator.#leaseHistory(root);
    const effective = history.effective;
    if (history.chain.some(handoff => handoff.previousOwnerToken === nextOwnerToken || handoff.ownerToken === nextOwnerToken)) throw new Error("root handoff owner token reuse is forbidden");
    if (effective.ownerToken !== options.expectedOwnerToken || effective.storeGeneration !== options.storeGeneration || effective.rootIdentityDigest !== options.expectedRootIdentityDigest || !sameInventory(effective.nestedLockNames, nestedLockNames) || canonicalJson(effective.nestedLockPaths) !== canonicalJson(nestedLockPaths)) throw new Error("offline recovery owner, generation, root, or complete nested-lock inventory mismatch");
    if (canonicalJson(await captureNestedDirectories(directory, nestedLockPaths)) !== canonicalJson(effective.nestedDirectoryIdentities)) throw new Error("configured nested directory identity changed");
    const inventory = await StateCoordinator.#validatedNestedInventory(root, effective);
    const nestedLocks = inventory.locks;
    const handoff: HandoffRecord = {
      version: 2,
      previousOwnerToken: effective.ownerToken,
      ownerToken: nextOwnerToken,
      storeGeneration: effective.storeGeneration,
      rootIdentityDigest: effective.rootIdentityDigest,
      nestedLockNames, nestedLockPaths, nestedDirectoryIdentities: effective.nestedDirectoryIdentities, nestedLocks, nestedMarkerIdentities: inventory.markerIdentities,
      createdAt: new Date().toISOString(),
    };
    const handoffPath = `handoffs/${createHash("sha256").update(effective.ownerToken, "utf8").digest("hex")}.json`;
    try { await root.publishCreateOnce(handoffPath, handoff); }
    catch (error) {
      if (!(error instanceof DurableRecordExistsError)) throw error;
      if (canonicalJson(closedHandoff(await root.read(handoffPath))) !== canonicalJson(handoff)) throw new Error("state-root owner already has a contradictory handoff");
      await root.ensurePublished(handoffPath, handoff);
    }
    return new StateCoordinator(root, { ...effective, ownerToken: nextOwnerToken }, true, options.faultInjector);
  }

  async withMutation<T>(operation: (capability: MutationCapability) => T | Promise<T>): Promise<T> {
    if (this.#closed) throw new Error("state coordinator is closed");
    if (this.#mutating) throw new Error("concurrent state mutation is forbidden");
    this.#mutating = true;
    try { await this.#assertLease(); } catch (error) { this.#mutating = false; throw error; }
    const capability = Object.freeze({ ownerToken: this.#lease.ownerToken, storeGeneration: this.#lease.storeGeneration, rootIdentityDigest: this.#lease.rootIdentityDigest });
    liveCapabilities.add(capability);
    try { return await operation(capability); }
    finally { liveCapabilities.delete(capability); this.#mutating = false; }
  }

  receiptStoreLockOwnership(capability: MutationCapability): ReceiptStoreLockOwnership {
    if (!this.#nestedHandoffCompleted) throw new Error("nested lock handoff must explicitly complete before new store authority is issued");
    return this.#receiptStoreLockOwnership(capability);
  }

  #receiptStoreLockOwnership(capability: MutationCapability): ReceiptStoreLockOwnership {
    assertMutationCapability(capability);
    if (capability.ownerToken !== this.#lease.ownerToken || capability.storeGeneration !== this.#lease.storeGeneration || capability.rootIdentityDigest !== this.#lease.rootIdentityDigest) throw new Error("mutation capability owner does not match state-root lease");
    const ownership = { ownerToken: capability.ownerToken, storeGeneration: capability.storeGeneration, rootIdentityDigest: capability.rootIdentityDigest } as ReceiptStoreLockOwnership;
    Object.defineProperty(ownership, RECEIPT_STORE_LOCK_AUTHORIZER, { enumerable: false, value: () => {
      assertMutationCapability(capability);
      if (this.#closed || capability.ownerToken !== this.#lease.ownerToken) throw new Error("receipt-store mutation is not authorized by the live state-root owner");
    } });
    return Object.freeze(ownership);
  }

  /** Explicit protected offline continuation; never invoked by acquire/startup. The operator's
   * offlineExclusive assertion is trusted authority, not OS proof that live writers stopped. */
  async completeNestedLockHandoff(capability: MutationCapability): Promise<void> {
    assertMutationCapability(capability);
    if (!this.#offlineRecovery) throw new Error("nested lock handoff requires explicit offline recovery ownership");
    const ownership = this.#receiptStoreLockOwnership(capability);
    await this.#assertLease();
    const inventory = await StateCoordinator.#validatedNestedInventory(this.#root, this.#lease);
    for (const handoff of inventory.chain) for (const name of handoff.nestedLockNames) {
      const marker = handoff.nestedLocks[name];
      if (marker === null || (marker as CoordinatorLockOwnership).ownerToken !== handoff.previousOwnerToken) continue;
      const proofName = completionName(handoff.previousOwnerToken, name);
      if (inventory.completed.has(proofName) && inventory.locks[name] !== null) continue;
      // Core independently parses the durable whole-root authority, not caller-supplied old tokens.
      const store = new FileReceiptStore(join(this.#root.path, dirname(handoff.nestedLockPaths[name]!)), {
        lockOwnership: ownership,
        ...(this.#faultInjector === undefined ? {} : { faultInjector: this.#faultInjector }),
      });
      await store.completeRootAuthorizedLockHandoff({ offlineExclusive: true, rootDirectory: this.#root.path, handoffPreviousOwnerToken: handoff.previousOwnerToken, lockName: name });
      await this.#assertLease();
      await StateCoordinator.#validatedNestedInventory(this.#root, this.#lease);
    }
    const final = await StateCoordinator.#validatedNestedInventory(this.#root, this.#lease);
    if (final.pending !== 0) throw new Error("nested lock handoff completion remains pending");
    this.#nestedHandoffCompleted = true;
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    if (this.#mutating) throw new Error("cannot close coordinator during mutation");
    this.#mutating = true;
    try {
      await this.#assertLease();
      const inventory = await StateCoordinator.#validatedNestedInventory(this.#root, this.#lease);
      if (Object.values(inventory.locks).some(value => value !== null) || inventory.pending > 0) throw new Error("nested lock handoff is incomplete; root authority must be preserved");
      for (const name of await this.#root.entries("nested-locks")) await this.#root.remove(`nested-locks/${name}`);
      for (const name of await this.#root.entries("handoffs")) await this.#root.remove(`handoffs/${name}`);
      await this.#root.remove("lease.json");
      this.#closed = true;
    } finally { this.#mutating = false; }
  }

  async #assertLease(): Promise<void> {
    const actual = await StateCoordinator.#effectiveLease(this.#root);
    if (canonicalJson(actual) !== canonicalJson(this.#lease)) throw new Error("state-root lease ownership changed");
  }

  static async #effectiveLease(root: DurableJsonDirectory): Promise<LeaseRecord> { return (await StateCoordinator.#leaseHistory(root)).effective; }

  static async #leaseHistory(root: DurableJsonDirectory): Promise<{ effective: LeaseRecord; chain: readonly HandoffRecord[] }> {
    const chain: HandoffRecord[] = [];
    const base = closedLease(await root.read("lease.json"));
    let effective = base;
    const handoffs = new Map<string, HandoffRecord>();
    for (const name of await root.entries("handoffs")) {
      if (!/^[a-f0-9]{64}\.json$/u.test(name)) throw new Error("unexpected state-root handoff entry");
      const handoff = closedHandoff(await root.read(`handoffs/${name}`));
      const expectedName = `${createHash("sha256").update(handoff.previousOwnerToken, "utf8").digest("hex")}.json`;
      if (name !== expectedName || handoffs.has(handoff.previousOwnerToken)) throw new Error("ambiguous state-root handoff chain");
      handoffs.set(handoff.previousOwnerToken, handoff);
    }
    const visited = new Set<string>();
    while (handoffs.has(effective.ownerToken)) {
      if (visited.has(effective.ownerToken)) throw new Error("cyclic state-root handoff chain");
      visited.add(effective.ownerToken);
      const handoff = handoffs.get(effective.ownerToken)!;
      if (handoff.storeGeneration !== effective.storeGeneration || handoff.rootIdentityDigest !== effective.rootIdentityDigest || !sameInventory(handoff.nestedLockNames, effective.nestedLockNames) || canonicalJson(handoff.nestedLockPaths) !== canonicalJson(effective.nestedLockPaths) || canonicalJson(handoff.nestedDirectoryIdentities) !== canonicalJson(effective.nestedDirectoryIdentities)) throw new Error("partial or mismatched state-root handoff");
      for (const name of handoff.nestedLockNames) { const marker = handoff.nestedLocks[name]; if (marker !== null && (marker as CoordinatorLockOwnership).ownerToken !== effective.ownerToken && !chain.some(prior => canonicalJson(prior.nestedLocks[name]) === canonicalJson(marker) && canonicalJson(prior.nestedMarkerIdentities[name]) === canonicalJson(handoff.nestedMarkerIdentities[name]))) throw new Error("unproved prior nested handoff marker identity"); }
      chain.push(handoff);
      effective = { ...effective, ownerToken: handoff.ownerToken };
    }
    if (visited.size !== handoffs.size) throw new Error("disconnected or ambiguous state-root handoff chain");
    return { effective, chain };
  }

  static async #validatedNestedInventory(root: DurableJsonDirectory, lease: LeaseRecord): Promise<{
    locks: Readonly<Record<string, unknown>>; markerIdentities: Readonly<Record<string, unknown>>; chain: readonly HandoffRecord[]; completed: ReadonlySet<string>; pending: number;
  }> {
    const { effective, chain } = await StateCoordinator.#leaseHistory(root);
    if (canonicalJson(effective) !== canonicalJson(lease)) throw new Error("nested handoff effective ownership changed");
    if (canonicalJson(await captureNestedDirectories(root.path, lease.nestedLockPaths)) !== canonicalJson(lease.nestedDirectoryIdentities)) throw new Error("nested directory identity changed");
    const markerIdentities: Record<string, unknown> = {};
    const locks = await inspectNestedLocks(root.path, lease, chain, markerIdentities);
    const entries = new Set(await root.entries("nested-locks")); const allowed = new Set<string>(); const completed = new Set<string>(); let pending = 0;
    for (const handoff of chain) for (const name of handoff.nestedLockNames) {
      const marker = handoff.nestedLocks[name];
      if (marker === null || (marker as CoordinatorLockOwnership).ownerToken !== handoff.previousOwnerToken) continue;
      const proofName = completionName(handoff.previousOwnerToken, name); const doneName = proofName.replace(/\.json$/u, ".done.json");
      allowed.add(proofName); allowed.add(doneName);
      let proof: Record<string, unknown> | undefined;
      if (entries.has(proofName)) {
        const value = await root.read("nested-locks/" + proofName);
        if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("nested completion proof malformed");
        proof = value as Record<string, unknown>;
        const { markerIdentity, ...base } = proof;
        const expected = { version: 1, handoffDigest: recordDigest(handoff), lockName: name, lockPath: handoff.nestedLockPaths[name], directoryIdentityDigest: handoff.nestedDirectoryIdentities[name], previousMarker: marker };
        if (canonicalJson(markerIdentity) !== canonicalJson(handoff.nestedMarkerIdentities[name]) || canonicalJson(base) !== canonicalJson(expected) || markerIdentity === null || typeof markerIdentity !== "object" || Object.keys(markerIdentity).sort().join(",") !== "ctimeMs,dev,ino,mtimeMs" || Object.values(markerIdentity).some(value => typeof value !== "number" || !Number.isFinite(value))) throw new Error("nested completion proof mismatch");
      }
      if (entries.has(doneName)) {
        if (proof === undefined || canonicalJson(await root.read("nested-locks/" + doneName)) !== canonicalJson({version:1,completionProofDigest:recordDigest(proof)})) throw new Error("nested completion acknowledgment mismatch");
        completed.add(proofName);
      } else pending++;
      const actual = locks[name];
      if (canonicalJson(actual) === canonicalJson(marker)) {
        if (completed.has(proofName)) throw new Error("completed prior nested lock reappeared");
        if (canonicalJson(markerIdentities[name]) !== canonicalJson(handoff.nestedMarkerIdentities[name])) throw new Error("original nested marker identity changed");
        if (proof !== undefined) { const info = await lstat(join(root.path, handoff.nestedLockPaths[name]!)); if (canonicalJson(proof.markerIdentity) !== canonicalJson({dev:info.dev,ino:info.ino,mtimeMs:info.mtimeMs,ctimeMs:info.ctimeMs})) throw new Error("nested marker identity changed after completion intent"); }
      } else if (actual === null) {
        if (proof === undefined) throw new Error("recorded nested lock is missing without completion proof");
      } else if (!completed.has(proofName)) throw new Error("prior nested lock changed before completion");
    }
    for (const entry of entries) if (!allowed.has(entry)) throw new Error("unexpected nested completion evidence");
    return { locks, markerIdentities, chain, completed, pending };
  }
}
