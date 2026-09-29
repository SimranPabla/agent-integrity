import { createHash, randomUUID } from "node:crypto";
import { lstat, realpath } from "node:fs/promises";
import { canonicalJson, RECEIPT_STORE_LOCK_AUTHORIZER, type ReceiptStoreLockOwnership } from "@agent-integrity/core";
import { DurableJsonDirectory, DurableRecordExistsError, type DurableJsonOptions } from "./durable-json.js";

const SAFE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const liveCapabilities = new WeakSet<object>();

export interface MutationCapability { readonly ownerToken: string; readonly storeGeneration: string; readonly rootIdentityDigest: string }
export interface StateCoordinatorOptions extends Partial<DurableJsonOptions> {
  readonly storeGeneration: string;
  readonly nestedLockNames: readonly string[];
}
export interface CoordinatorLockOwnership {
  readonly ownerToken: string; readonly storeGeneration: string; readonly rootIdentityDigest: string;
}
interface LeaseRecord extends CoordinatorLockOwnership {
  readonly version: 1;
  readonly nestedLockNames: readonly string[];
  readonly startedAt: string;
}
interface HandoffRecord extends CoordinatorLockOwnership {
  readonly version: 1;
  readonly previousOwnerToken: string;
  readonly nestedLockNames: readonly string[];
  readonly createdAt: string;
}

function closedLease(value: unknown): LeaseRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new Error("state-root lease is malformed");
  const record = value as Record<string, unknown>;
  if (Object.keys(record).sort().join(",") !== "nestedLockNames,ownerToken,rootIdentityDigest,startedAt,storeGeneration,version" || record.version !== 1 || typeof record.ownerToken !== "string" || !SAFE.test(record.ownerToken) || typeof record.storeGeneration !== "string" || !SAFE.test(record.storeGeneration) || typeof record.rootIdentityDigest !== "string" || !/^[a-f0-9]{64}$/u.test(record.rootIdentityDigest) || typeof record.startedAt !== "string" || new Date(record.startedAt).toISOString() !== record.startedAt || !Array.isArray(record.nestedLockNames) || record.nestedLockNames.some((name) => typeof name !== "string" || !SAFE.test(name))) throw new Error("state-root lease is malformed");
  return record as unknown as LeaseRecord;
}
function closedHandoff(value: unknown): HandoffRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new Error("state-root handoff is malformed");
  const record = value as Record<string, unknown>;
  if (Object.keys(record).sort().join(",") !== "createdAt,nestedLockNames,ownerToken,previousOwnerToken,rootIdentityDigest,storeGeneration,version" || record.version !== 1 || typeof record.ownerToken !== "string" || !SAFE.test(record.ownerToken) || typeof record.previousOwnerToken !== "string" || !SAFE.test(record.previousOwnerToken) || record.ownerToken === record.previousOwnerToken || typeof record.storeGeneration !== "string" || !SAFE.test(record.storeGeneration) || typeof record.rootIdentityDigest !== "string" || !/^[a-f0-9]{64}$/u.test(record.rootIdentityDigest) || typeof record.createdAt !== "string" || new Date(record.createdAt).toISOString() !== record.createdAt || !Array.isArray(record.nestedLockNames) || record.nestedLockNames.some((name) => typeof name !== "string" || !SAFE.test(name))) throw new Error("state-root handoff is malformed");
  return record as unknown as HandoffRecord;
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

  private constructor(root: DurableJsonDirectory, lease: LeaseRecord) { this.#root = root; this.#lease = lease; }

  static async acquire(directory: string, options: StateCoordinatorOptions): Promise<StateCoordinator> {
    if (!SAFE.test(options.storeGeneration)) throw new TypeError("store generation is invalid");
    const nestedLockNames = [...new Set(options.nestedLockNames)].sort();
    if (nestedLockNames.length !== options.nestedLockNames.length || nestedLockNames.length > 64 || nestedLockNames.some((name) => !SAFE.test(name))) throw new TypeError("nested lock inventory is invalid");
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
    for (const name of await root.entries("handoffs")) await root.remove(`handoffs/${name}`);
    const rootIdentityDigest = await rootDigest(directory);
    const lease: LeaseRecord = {
      version: 1,
      ownerToken: randomUUID(),
      storeGeneration: options.storeGeneration,
      rootIdentityDigest,
      nestedLockNames,
      startedAt: new Date().toISOString(),
    };
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
    const nextOwnerToken = options.nextOwnerToken ?? randomUUID();
    if (!SAFE.test(nextOwnerToken) || nextOwnerToken === options.expectedOwnerToken) throw new TypeError("next owner token is invalid");
    const root = new DurableJsonDirectory(directory, {
      maxStateBytes: options.maxStateBytes ?? 64 * 1024,
      maxEntries: options.maxEntries ?? 128,
      ...(options.faultInjector === undefined ? {} : { faultInjector: options.faultInjector }),
    });
    await root.initialize(["handoffs", "nested-locks"]);
    if (await rootDigest(directory) !== options.expectedRootIdentityDigest) throw new Error("state-root identity does not match offline recovery authority");
    const effective = await StateCoordinator.#effectiveLease(root);
    if (effective.ownerToken !== options.expectedOwnerToken || effective.storeGeneration !== options.storeGeneration || effective.rootIdentityDigest !== options.expectedRootIdentityDigest || !sameInventory(effective.nestedLockNames, nestedLockNames)) throw new Error("offline recovery owner, generation, root, or complete nested-lock inventory mismatch");
    const handoff: HandoffRecord = {
      version: 1,
      previousOwnerToken: effective.ownerToken,
      ownerToken: nextOwnerToken,
      storeGeneration: effective.storeGeneration,
      rootIdentityDigest: effective.rootIdentityDigest,
      nestedLockNames,
      createdAt: new Date().toISOString(),
    };
    const handoffPath = `handoffs/${createHash("sha256").update(effective.ownerToken, "utf8").digest("hex")}.json`;
    try { await root.publishCreateOnce(handoffPath, handoff); }
    catch (error) {
      if (!(error instanceof DurableRecordExistsError)) throw error;
      if (canonicalJson(closedHandoff(await root.read(handoffPath))) !== canonicalJson(handoff)) throw new Error("state-root owner already has a contradictory handoff");
    }
    return new StateCoordinator(root, { ...effective, ownerToken: nextOwnerToken });
  }

  async withMutation<T>(operation: (capability: MutationCapability) => T | Promise<T>): Promise<T> {
    if (this.#closed) throw new Error("state coordinator is closed");
    if (this.#mutating) throw new Error("concurrent state mutation is forbidden");
    await this.#assertLease();
    this.#mutating = true;
    const capability = Object.freeze({ ownerToken: this.#lease.ownerToken, storeGeneration: this.#lease.storeGeneration, rootIdentityDigest: this.#lease.rootIdentityDigest });
    liveCapabilities.add(capability);
    try { return await operation(capability); }
    finally { liveCapabilities.delete(capability); this.#mutating = false; }
  }

  receiptStoreLockOwnership(capability: MutationCapability): ReceiptStoreLockOwnership {
    assertMutationCapability(capability);
    if (capability.ownerToken !== this.#lease.ownerToken || capability.storeGeneration !== this.#lease.storeGeneration || capability.rootIdentityDigest !== this.#lease.rootIdentityDigest) throw new Error("mutation capability owner does not match state-root lease");
    const ownership = { ownerToken: capability.ownerToken, storeGeneration: capability.storeGeneration, rootIdentityDigest: capability.rootIdentityDigest } as ReceiptStoreLockOwnership;
    Object.defineProperty(ownership, RECEIPT_STORE_LOCK_AUTHORIZER, { enumerable: false, value: () => {
      assertMutationCapability(capability);
      if (this.#closed || capability.ownerToken !== this.#lease.ownerToken) throw new Error("receipt-store mutation is not authorized by the live state-root owner");
    } });
    return Object.freeze(ownership);
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    if (this.#mutating) throw new Error("cannot close coordinator during mutation");
    await this.#assertLease();
    await this.#root.remove("lease.json");
    for (const name of await this.#root.entries("handoffs")) await this.#root.remove(`handoffs/${name}`);
    this.#closed = true;
  }

  async #assertLease(): Promise<void> {
    const actual = await StateCoordinator.#effectiveLease(this.#root);
    if (canonicalJson(actual) !== canonicalJson(this.#lease)) throw new Error("state-root lease ownership changed");
  }

  static async #effectiveLease(root: DurableJsonDirectory): Promise<LeaseRecord> {
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
      if (handoff.storeGeneration !== effective.storeGeneration || handoff.rootIdentityDigest !== effective.rootIdentityDigest || !sameInventory(handoff.nestedLockNames, effective.nestedLockNames)) throw new Error("partial or mismatched state-root handoff");
      effective = { ...effective, ownerToken: handoff.ownerToken };
    }
    if (visited.size !== handoffs.size) throw new Error("disconnected or ambiguous state-root handoff chain");
    return effective;
  }
}
