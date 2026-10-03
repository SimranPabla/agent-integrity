import { createHash } from "node:crypto";
import { DurableJsonDirectory, DurableRecordExistsError, type DurableJsonOptions } from "./durable-json.js";

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

  constructor(directory: string, options: PrivateObjectStoreOptions = {}) {
    this.#maxObjectBytes = options.maxObjectBytes ?? DEFAULT_MAX_OBJECT_BYTES;
    const maxObjects = options.maxObjects ?? DEFAULT_MAX_OBJECTS;
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
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  }

  async #publish(directory: string, kind: StoredObject["kind"], input: Uint8Array, expectedDigest: string): Promise<string> {
    this.#validateDigest(expectedDigest);
    const bytes = Buffer.from(input);
    if (bytes.byteLength > this.#maxObjectBytes || digest(bytes) !== expectedDigest) throw new Error("private object digest or size is invalid");
    await this.#root.initialize(["requests", "registries"]);
    const value: StoredObject = { version: 1, kind, sha256: expectedDigest, bytes: bytes.toString("base64url") };
    const path = `${directory}/${expectedDigest}.json`;
    try { await this.#root.publishCreateOnce(path, value); }
    catch (error) {
      if (!(error instanceof DurableRecordExistsError)) throw error;
      const existing = objectRecord(await this.#root.read(path), kind, expectedDigest, this.#maxObjectBytes);
      if (!existing.equals(bytes)) throw new Error("private object publication conflict");
    }
    return expectedDigest;
  }

  async #read(directory: string, kind: StoredObject["kind"], objectId: string): Promise<Buffer> {
    this.#validateDigest(objectId);
    await this.#root.initialize(["requests", "registries"]);
    return objectRecord(await this.#root.read(`${directory}/${objectId}.json`), kind, objectId, this.#maxObjectBytes);
  }

  #validateDigest(value: string): void { if (!SHA256.test(value)) throw new TypeError("private object digest is invalid"); }
}
