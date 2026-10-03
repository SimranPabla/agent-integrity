import { createHash } from "node:crypto";
import { isAbsolute } from "node:path";
import { DurableJsonDirectory, DurableRecordExistsError, type DurableJsonOptions } from "./durable-json.js";

const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const DIGEST = /^[a-f0-9]{64}$/u;
const DEFAULT_MAX_STATE_BYTES = 4096;
const DEFAULT_MAX_RECORDS = 100_000;
const DEFAULT_MAXIMUM_SKEW_MS = 60_000;

export interface NonceRecord {
  readonly version: 1;
  readonly clientId: string;
  readonly keyId: string;
  readonly nonce: string;
  readonly timestampMs: number;
  readonly bodyDigest: string;
  readonly retainedUntilMs: number;
}
export interface FileNonceStoreOptions {
  readonly maxStateBytes?: number;
  readonly maxRecords?: number;
  readonly maximumSkewMs?: number;
  readonly faultInjector?: DurableJsonOptions["faultInjector"];
}

function dataRecord(value: unknown, message: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new Error(message);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).some((key) => typeof key !== "string") || Object.values(descriptors).some((descriptor) => descriptor.get !== undefined || descriptor.set !== undefined || descriptor.enumerable !== true || !("value" in descriptor))) throw new Error(message);
  return Object.fromEntries(Object.entries(descriptors).map(([key, descriptor]) => [key, descriptor.value]));
}
function exactRecord(value: unknown, maximumSkewMs: number): NonceRecord {
  const record = dataRecord(value, "invalid nonce record");
  const expected = ["bodyDigest", "clientId", "keyId", "nonce", "retainedUntilMs", "timestampMs", "version"];
  const actual = Object.keys(record).sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new Error("invalid nonce record");
  if (record.version !== 1 || ![record.clientId, record.keyId, record.nonce].every((entry) => typeof entry === "string" && SAFE_IDENTIFIER.test(entry)) || typeof record.bodyDigest !== "string" || !DIGEST.test(record.bodyDigest) || !Number.isSafeInteger(record.timestampMs) || (record.timestampMs as number) < 1_000_000_000_000 || (record.timestampMs as number) > 9_999_999_999_999 || !Number.isSafeInteger(record.retainedUntilMs) || (record.retainedUntilMs as number) <= (record.timestampMs as number) + maximumSkewMs) throw new Error("invalid nonce record retention or fields");
  return Object.freeze({ ...(record as unknown as NonceRecord) });
}
function lengthDelimitedDigest(fields: readonly string[]): string {
  const hash = createHash("sha256");
  for (const field of fields) {
    const bytes = Buffer.from(field, "utf8");
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.byteLength);
    hash.update(length);
    hash.update(bytes);
  }
  return hash.digest("hex");
}
function recordKey(record: NonceRecord): string { return lengthDelimitedDigest([record.clientId, record.nonce]); }

interface QuotaRecord { readonly version: 1; readonly recordKey: string }
function exactQuota(value: unknown): QuotaRecord {
  const record = dataRecord(value, "invalid nonce quota state");
  if (Object.keys(record).sort().join(",") !== "recordKey,version" || record.version !== 1 || typeof record.recordKey !== "string" || !DIGEST.test(record.recordKey)) throw new Error("invalid nonce quota state");
  return { version: 1, recordKey: record.recordKey };
}

export class FileNonceStore {
  readonly #root: DurableJsonDirectory;
  readonly #maxRecords: number;
  readonly #maximumSkewMs: number;

  constructor(readonly directory: string, options: FileNonceStoreOptions = {}) {
    if (!isAbsolute(directory)) throw new TypeError("nonce store directory must be absolute");
    this.#maxRecords = options.maxRecords ?? DEFAULT_MAX_RECORDS;
    this.#maximumSkewMs = options.maximumSkewMs ?? DEFAULT_MAXIMUM_SKEW_MS;
    if (!Number.isSafeInteger(this.#maxRecords) || this.#maxRecords < 1 || this.#maxRecords > 1_000_000) throw new TypeError("nonce record limit is invalid");
    if (!Number.isSafeInteger(this.#maximumSkewMs) || this.#maximumSkewMs < 0 || this.#maximumSkewMs > 24 * 60 * 60 * 1000) throw new TypeError("nonce skew limit is invalid");
    this.#root = new DurableJsonDirectory(directory, { maxStateBytes: options.maxStateBytes ?? DEFAULT_MAX_STATE_BYTES, maxEntries: this.#maxRecords + 16, ...(options.faultInjector === undefined ? {} : { faultInjector: options.faultInjector }) });
  }

  async consume(input: NonceRecord): Promise<void> {
    const record = exactRecord(input, this.#maximumSkewMs);
    await this.#root.initialize(["records", "quota"]);
    await this.#ensureConfiguration();
    const key = recordKey(record);
    try {
      const existing = await this.#root.read(`records/${key}.json`);
      exactRecord(existing, this.#maximumSkewMs);
      throw new Error("authentication nonce replay: nonce was already consumed");
    } catch (error) {
      if ((error as NodeJS.ErrnoException)?.code !== "ENOENT") throw error;
    }
    await this.#reserveQuota(key);
    try { await this.#root.publishCreateOnce(`records/${key}.json`, record); }
    catch (error) {
      if (error instanceof DurableRecordExistsError) {
        exactRecord(await this.#root.read(`records/${key}.json`), this.#maximumSkewMs);
        throw new Error("authentication nonce replay: nonce was already consumed");
      }
      throw error;
    }
  }

  async #ensureConfiguration(): Promise<void> {
    const expected = { version: 1, maxRecords: this.#maxRecords, maximumSkewMs: this.#maximumSkewMs };
    try { await this.#root.publishCreateOnce("configuration.json", expected); }
    catch (error) {
      if (!(error instanceof DurableRecordExistsError)) throw error;
      const actual = await this.#root.read("configuration.json");
      if (actual === null || typeof actual !== "object" || Array.isArray(actual) || JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error("nonce store configuration mismatch");
    }
  }

  async #reserveQuota(key: string): Promise<void> {
    const start = Number.parseInt(key.slice(0, 12), 16) % this.#maxRecords;
    for (let offset = 0; offset < this.#maxRecords; offset += 1) {
      const slot = (start + offset) % this.#maxRecords;
      const path = `quota/${slot}.json`;
      try { await this.#root.publishCreateOnce(path, { version: 1, recordKey: key }); return; }
      catch (error) {
        if (!(error instanceof DurableRecordExistsError)) throw error;
        const existing = exactQuota(await this.#root.read(path));
        if (existing.recordKey === key) throw new Error("authentication nonce replay: nonce was already consumed");
      }
    }
    throw new Error(`nonce store has reached its ${this.#maxRecords} record quota limit`);
  }
}
