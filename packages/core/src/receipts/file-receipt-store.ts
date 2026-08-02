import { mkdir, open, rm, stat, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import type { AlphaIntegrityReceipt } from "@agent-integrity/protocol";
import { canonicalJson } from "../canonical-json.js";
import { sha256Canonical } from "../hash.js";

interface StoredReceipt {
  readonly version: 2;
  readonly runId: string;
  readonly nonce: string;
  readonly receiptDigest: string;
  readonly quotaSlot: number;
  readonly receipt?: AlphaIntegrityReceipt;
}

const SHA256 = /^[a-f0-9]{64}$/u;
const DEFAULT_MAX_STATE_BYTES = 64 * 1024;
const DEFAULT_MAX_DIRECTORY_BYTES = 4096;
const DEFAULT_MAX_RECORDS = 10_000;

function markerName(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export interface FileReceiptStoreOptions {
  readonly maxStateBytes?: number;
  readonly maxDirectoryBytes?: number;
  readonly maxRecords?: number;
}

export class FileReceiptStore {
  readonly #maxStateBytes: number;
  readonly #maxRecords: number;

  constructor(readonly directory: string, readonly options: FileReceiptStoreOptions = {}) {
    const maxDirectoryBytes = options.maxDirectoryBytes ?? DEFAULT_MAX_DIRECTORY_BYTES;
    for (const [name, value] of [["maxStateBytes", options.maxStateBytes ?? DEFAULT_MAX_STATE_BYTES], ["maxDirectoryBytes", maxDirectoryBytes]] as const) {
      if (!Number.isSafeInteger(value) || value < 256 || value > 1024 * 1024) {
        throw new Error(`${name} must be a safe integer between 256 and 1048576`);
      }
    }
    const maxRecords = options.maxRecords ?? DEFAULT_MAX_RECORDS;
    if (!Number.isSafeInteger(maxRecords) || maxRecords < 1 || maxRecords > 1_000_000) {
      throw new Error("maxRecords must be a safe integer between 1 and 1000000");
    }
    if (typeof directory !== "string" || directory.length === 0 || Buffer.byteLength(directory, "utf8") > maxDirectoryBytes) {
      throw new Error("receipt store directory is invalid or exceeds its configured limit");
    }
    this.#maxStateBytes = options.maxStateBytes ?? DEFAULT_MAX_STATE_BYTES;
    this.#maxRecords = maxRecords;
  }

  private path(kind: "runs" | "nonces" | "issued" | "consumed" | "quota", value: string): string {
    return join(this.directory, kind, `${kind === "issued" || kind === "consumed" ? value : markerName(value)}.json`);
  }

  private async initialize(): Promise<void> {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    await Promise.all(["runs", "nonces", "issued", "consumed", "quota"].map((name) =>
      mkdir(join(this.directory, name), { recursive: true, mode: 0o700 })));
  }

  private record(receipt: AlphaIntegrityReceipt, quotaSlot: number): StoredReceipt {
    if (!SHA256.test(receipt.receiptDigest)) throw new Error("receipt digest is invalid");
    return { version: 2, runId: receipt.runId, nonce: receipt.nonce, receiptDigest: receipt.receiptDigest, quotaSlot };
  }

  private async readRecord(path: string): Promise<StoredReceipt> {
    const handle = await open(path, "r");
    try {
      const info = await handle.stat();
      if (info.size > this.#maxStateBytes) throw new Error("receipt store state exceeds configured limit");
      const buffer = Buffer.alloc(this.#maxStateBytes + 1);
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
      if (bytesRead > this.#maxStateBytes) throw new Error("receipt store state exceeds configured limit");
      const value = JSON.parse(buffer.subarray(0, bytesRead).toString("utf8")) as Partial<StoredReceipt>;
      if (value.version !== 2 || typeof value.runId !== "string" || typeof value.nonce !== "string" || !SHA256.test(value.receiptDigest ?? "") || !Number.isSafeInteger(value.quotaSlot)) {
        throw new Error("invalid receipt store state");
      }
      return value as StoredReceipt;
    } finally {
      await handle.close();
    }
  }

  private async reserveQuota(receipt: AlphaIntegrityReceipt): Promise<StoredReceipt> {
    const start = Number.parseInt(receipt.receiptDigest.slice(0, 8), 16) % this.#maxRecords;
    for (let offset = 0; offset < this.#maxRecords; offset += 1) {
      const quotaSlot = (start + offset) % this.#maxRecords;
      const record = this.record(receipt, quotaSlot);
      try {
        await writeFile(this.path("quota", String(quotaSlot)), `${JSON.stringify(record)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
        return record;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      }
    }
    throw new Error(`receipt store has reached its ${this.#maxRecords} record limit`);
  }

  private async reserve(path: string, record: StoredReceipt, duplicateMessage: string): Promise<void> {
    try {
      await writeFile(path, `${JSON.stringify(record)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      throw new Error(duplicateMessage);
    }
  }

  private async removeIfOwned(path: string, receiptDigest: string): Promise<void> {
    try {
      const record = await this.readRecord(path);
      if (record.receiptDigest === receiptDigest) await rm(path);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }

  async issue(receipt: AlphaIntegrityReceipt): Promise<void> {
    await this.initialize();
    const record = await this.reserveQuota(receipt);
    const runPath = this.path("runs", receipt.runId);
    const noncePath = this.path("nonces", receipt.nonce);
    const issuedPath = this.path("issued", receipt.receiptDigest);
    let runReserved = false;
    let nonceReserved = false;
    try {
      await this.reserve(runPath, record, `run ID already exists: ${receipt.runId}`);
      runReserved = true;
      await this.reserve(noncePath, record, `receipt nonce already exists: ${receipt.nonce}`);
      nonceReserved = true;
      const issuedRecord = { ...record, receipt };
      if (Buffer.byteLength(JSON.stringify(issuedRecord), "utf8") > this.#maxStateBytes) throw new Error("receipt exceeds configured store state limit");
      await this.reserve(issuedPath, issuedRecord, "receipt is already issued");
    } catch (error) {
      if (nonceReserved) await this.removeIfOwned(noncePath, receipt.receiptDigest);
      if (runReserved) await this.removeIfOwned(runPath, receipt.receiptDigest);
      await this.removeIfOwned(this.path("quota", String(record.quotaSlot)), receipt.receiptDigest);
      throw error;
    }
  }

  /** Removes a fully or partially issued record, but only when every marker is owned by this digest. */
  async rollbackIssue(receiptDigest: string): Promise<void> {
    await this.initialize();
    const issuedPath = this.path("issued", receiptDigest);
    let record: StoredReceipt;
    try {
      record = await this.readRecord(issuedPath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      return;
    }
    try {
      await stat(this.path("consumed", receiptDigest));
      throw new Error("cannot roll back a consumed receipt");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    await this.removeIfOwned(issuedPath, receiptDigest);
    await this.removeIfOwned(this.path("nonces", record.nonce), receiptDigest);
    await this.removeIfOwned(this.path("runs", record.runId), receiptDigest);
    await this.removeIfOwned(this.path("quota", String(record.quotaSlot)), receiptDigest);
  }

  /** Recovers markers left before the authoritative issued record was committed. */
  async recoverInterruptedIssue(receipt: AlphaIntegrityReceipt): Promise<void> {
    await this.initialize();
    try {
      await stat(this.path("issued", receipt.receiptDigest));
      throw new Error("cannot recover a completed issuance");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    const runPath = this.path("runs", receipt.runId);
    try {
      const record = await this.readRecord(runPath);
      if (record.receiptDigest === receipt.receiptDigest) {
        await this.removeIfOwned(this.path("nonces", receipt.nonce), receipt.receiptDigest);
        await this.removeIfOwned(runPath, receipt.receiptDigest);
        await this.removeIfOwned(this.path("quota", String(record.quotaSlot)), receipt.receiptDigest);
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }

  /** Reconstructs the public receipt file from the authoritative committed issued record. */
  async completeReceiptFile(receiptDigest: string, outputPath: string): Promise<AlphaIntegrityReceipt> {
    await this.initialize();
    const record = await this.readRecord(this.path("issued", receiptDigest));
    const receipt = record.receipt;
    if (receipt === undefined || receipt.receiptDigest !== receiptDigest) throw new Error("issued receipt payload is missing or mismatched");
    const { receiptDigest: _digest, ...signed } = receipt;
    if (sha256Canonical(signed) !== receiptDigest) throw new Error("issued receipt payload failed its digest check");
    await mkdir(dirname(outputPath), { recursive: true });
    await writeFile(outputPath, `${canonicalJson(receipt)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
    return receipt;
  }

  async consume(receipt: AlphaIntegrityReceipt, consumedAt: Date): Promise<void> {
    await this.initialize();
    if (!(consumedAt instanceof Date) || !Number.isFinite(consumedAt.getTime())) throw new Error("consumedAt must be a valid Date");
    const issued = await this.readRecord(this.path("issued", receipt.receiptDigest));
    if (issued.runId !== receipt.runId || issued.nonce !== receipt.nonce) throw new Error("receipt registry binding mismatch");
    const consumed = { ...issued, consumedAt: consumedAt.toISOString() };
    try {
      await writeFile(this.path("consumed", receipt.receiptDigest), `${JSON.stringify(consumed)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") throw new Error("receipt has already been consumed");
      throw error;
    }
  }
}
