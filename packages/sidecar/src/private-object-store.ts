import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { createHash } from "node:crypto";
import { DurableJsonDirectory, DurableRecordExistsError, type DurableJsonOptions } from "./durable-json.js";

import { assertMutationCapability, type MutationCapability } from "./state-coordinator.js";

const SHA256 = /^[a-f0-9]{64}$/u;
const DEFAULT_MAX_OBJECT_BYTES = 256 * 1024;
const DEFAULT_MAX_OBJECTS = 10_000;

interface StoredObject {
  readonly version: 1;
  readonly kind: "canonical-request" | "public-trust-registry";
  readonly sha256: string;
  readonly bytes: string;
}

export interface PrivateObjectStoreOptions extends Partial<DurableJsonOptions> {
  readonly maxObjectBytes?: number;
  readonly maxObjects?: number;
}

function digest(bytes: Uint8Array): string { return createHash("sha256").update(bytes).digest("hex"); }
function objectRecord(value: unknown, expectedKind: StoredObject["kind"], expectedDigest: string, maxBytes: number): Buffer {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new Error("private object is invalid");
  const record = value as Record<string, unknown>;
  if (Object.keys(record).sort().join(",") !== "bytes,kind,sha256,version" || record.version !== 1 || record.kind !== expectedKind || record.sha256 !== expectedDigest || typeof record.bytes !== "string") throw new Error("private object is invalid");
  const bytes = Buffer.from(record.bytes, "base64url");
  if (bytes.toString("base64url") !== record.bytes || bytes.byteLength > maxBytes || digest(bytes) !== expectedDigest) throw new Error("private object digest or size is invalid");
  return bytes;
}

export class PrivateObjectStore {
  readonly #root: DurableJsonDirectory;
  readonly #maxObjectBytes: number;
  readonly #maxObjects: number;
  readonly #faultInjector: DurableJsonOptions["faultInjector"];
  #publishing = false;

  constructor(directory: string, options: PrivateObjectStoreOptions = {}) {
    this.#maxObjectBytes = options.maxObjectBytes ?? DEFAULT_MAX_OBJECT_BYTES;
    const maxObjects = options.maxObjects ?? DEFAULT_MAX_OBJECTS;
    this.#maxObjects = maxObjects;
    this.#faultInjector = options.faultInjector;
    if (!Number.isSafeInteger(this.#maxObjectBytes) || this.#maxObjectBytes < 1 || this.#maxObjectBytes > 1024 * 1024) throw new TypeError("maximum object bytes is invalid");
    if (!Number.isSafeInteger(maxObjects) || maxObjects < 1 || maxObjects > 1_000_000) throw new TypeError("maximum object count is invalid");
    this.#root = new DurableJsonDirectory(directory, {
      maxStateBytes: options.maxStateBytes ?? Math.min(1024 * 1024, Math.max(1024, Math.ceil(this.#maxObjectBytes * 1.4))),
      maxEntries: options.maxEntries ?? maxObjects,
      ...(options.faultInjector === undefined ? {} : { faultInjector: options.faultInjector }),
    });
  }

  async publishCanonicalRequest(bytes: Uint8Array, expectedDigest: string): Promise<string> {
    return this.#publish("requests", "canonical-request", bytes, expectedDigest);
  }

  async readCanonicalRequest(objectId: string): Promise<Buffer> { return this.#read("requests", "canonical-request", objectId); }

  async publishTrustRegistry(bytes: Uint8Array, expectedDigest: string): Promise<string> {
    return this.#publish("registries", "public-trust-registry", bytes, expectedDigest);
  }

  async readTrustRegistry(objectId: string): Promise<Buffer> { return this.#read("registries", "public-trust-registry", objectId); }

  async removeCanonicalRequest(objectId: string): Promise<void> {
    this.#validateDigest(objectId);
    await this.#root.initialize(["requests", "registries"]);
    try { await this.#root.remove(`requests/${objectId}.json`); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; await syncRemovalDirectory(this.#root, "requests"); }
  }

  async removeTrustRegistry(capability: MutationCapability, objectId: string): Promise<void> {
    assertMutationCapability(capability);
    this.#validateDigest(objectId);
    await this.#root.initialize(["requests", "registries"]);
    await this.#faultInjector?.("object:before-registry-remove");
    // Validate complete immutable bytes before deletion; ENOENT is permitted
    // only for a caller's already-proved, durable compaction candidate.
    try { await this.#read("registries", "public-trust-registry", objectId); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    try { await this.#root.remove(`registries/${objectId}.json`); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; await syncRemovalDirectory(this.#root, "registries"); }
  }

  async inspectCapacity(): Promise<Readonly<{ used: number; maximum: number; requestObjectIds: readonly string[] }>> {
    await this.#root.initialize(["requests", "registries"]);
    let used = 0; const requestObjectIds: string[] = [];
    for (const [directory, kind] of [["requests", "canonical-request"], ["registries", "public-trust-registry"]] as const) {
      for (const name of await this.#root.entries(directory)) {
        if (!/^[a-f0-9]{64}\.json$/u.test(name)) throw new Error("unexpected private object entry");
        const id = name.slice(0, -5);
        objectRecord(await this.#root.read(`${directory}/${name}`), kind, id, this.#maxObjectBytes);
        used += 1; if (directory === "requests") requestObjectIds.push(id);
      }
    }
    return Object.freeze({ used, maximum: this.#maxObjects, requestObjectIds: Object.freeze(requestObjectIds) });
  }

  async #publish(directory: string, kind: StoredObject["kind"], input: Uint8Array, expectedDigest: string): Promise<string> {
    if (this.#publishing) throw new Error("concurrent private object publication is forbidden");
    this.#publishing = true;
    try {
    this.#validateDigest(expectedDigest);
    const bytes = Buffer.from(input);
    if (bytes.byteLength > this.#maxObjectBytes || digest(bytes) !== expectedDigest) throw new Error("private object digest or size is invalid");
    await this.#root.initialize(["requests", "registries"]);
    const value: StoredObject = { version: 1, kind, sha256: expectedDigest, bytes: bytes.toString("base64url") };
    const path = `${directory}/${expectedDigest}.json`;
    let existingValue: unknown;
    try { existingValue = await this.#root.read(path); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    if (existingValue !== undefined) {
      const existing = objectRecord(existingValue, kind, expectedDigest, this.#maxObjectBytes);
      if (!existing.equals(bytes)) throw new Error("private object publication conflict");
      await this.#root.ensurePublished(path, value);
      return expectedDigest;
    }
    if ((await this.inspectCapacity()).used >= this.#maxObjects) throw new Error("private object store capacity reached");
    try { await this.#root.publishCreateOnce(path, value); }
    catch (error) {
      if (!(error instanceof DurableRecordExistsError)) throw error;
      const existing = objectRecord(await this.#root.read(path), kind, expectedDigest, this.#maxObjectBytes);
      if (!existing.equals(bytes)) throw new Error("private object publication conflict");
      await this.#root.ensurePublished(path, value);
    }
    return expectedDigest;
    } finally { this.#publishing = false; }
  }

  async #read(directory: string, kind: StoredObject["kind"], objectId: string): Promise<Buffer> {
    this.#validateDigest(objectId);
    await this.#root.initialize(["requests", "registries"]);
    return objectRecord(await this.#root.read(`${directory}/${objectId}.json`), kind, objectId, this.#maxObjectBytes);
  }

  #validateDigest(value: string): void { if (!SHA256.test(value)) throw new TypeError("private object digest is invalid"); }
}

// Internal deletion retry barrier: an unlink may have succeeded before its
// directory sync failed. ENOENT alone is not proof of durable removal.
export async function syncRemovalDirectory(root: DurableJsonDirectory, relativeDirectory: string): Promise<void> {
  await root.assertIdentity();
  const path = root.resolve(relativeDirectory);
  const before = await lstat(path);
  if (!before.isDirectory() || before.isSymbolicLink() || (before.mode & 0o777) !== 0o700) throw new Error("cleanup directory identity invalid");
  let handle;
  try { handle = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW); }
  catch (error) { if (["EINVAL", "ENOTSUP", "EISDIR"].includes((error as NodeJS.ErrnoException).code ?? "")) { await root.assertIdentity(); return; } throw error; }
  try {
    const opened = await handle.stat();
    if (!opened.isDirectory() || opened.dev !== before.dev || opened.ino !== before.ino || opened.uid !== before.uid || (opened.mode & 0o777) !== 0o700) throw new Error("cleanup directory identity changed");
    try { await handle.sync(); }
    catch (error) { if (!["EINVAL", "ENOTSUP", "EISDIR"].includes((error as NodeJS.ErrnoException).code ?? "")) throw error; }
    const after = await lstat(path);
    if (after.isSymbolicLink() || after.dev !== opened.dev || after.ino !== opened.ino || after.uid !== opened.uid || (after.mode & 0o777) !== 0o700) throw new Error("cleanup directory identity changed");
  } finally { await handle.close(); }
  await root.assertIdentity();
}
