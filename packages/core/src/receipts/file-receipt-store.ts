import { createHash, randomUUID } from "node:crypto";
import { link, mkdir, open, opendir, rename, rm, stat } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { AlphaIntegrityReceipt } from "@agent-integrity/protocol";
import { sha256Canonical } from "../hash.js";

interface StoredReceipt {
  readonly version: 3;
  readonly runId: string;
  readonly nonce: string;
  readonly receiptDigest: string;
  readonly quotaSlot: number;
  readonly transactionId: string;
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
    this.#maxStateBytes = options.maxStateBytes ?? DEFAULT_MAX_STATE_BYTES;
    this.#maxRecords = maxRecords;
  }

  private path(kind: "runs" | "nonces" | "issued" | "consumed" | "quota" | "transactions" | "recovery", value: string): string {
    const raw = kind === "issued" || kind === "consumed" ? value : markerName(value);
    return join(this.directory, kind, `${raw}.json`);
  }

  private async initialize(): Promise<void> {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    await Promise.all(["runs", "nonces", "issued", "consumed", "quota", "transactions", "recovery", ".staging", ".quarantine"].map((name) => mkdir(join(this.directory, name), { recursive: true, mode: 0o700 })));
  }

  private async syncDirectory(path: string): Promise<void> {
    const handle = await open(path, "r");
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
        if ((error as NodeJS.ErrnoException).code === "EEXIST") throw new Error(duplicateMessage);
        throw error;
      }
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
    await this.initialize();
    if (options?.offlineExclusive !== true) throw new Error("offlineExclusive staging cleanup is required");
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
      if (value.version !== 3 || typeof value.runId !== "string" || typeof value.nonce !== "string" || !SHA256.test(value.receiptDigest ?? "") || !Number.isSafeInteger(value.quotaSlot) || typeof value.transactionId !== "string") throw new Error("invalid receipt store state");
      return value as StoredReceipt;
    } finally { await handle.close(); }
  }

  private record(receipt: AlphaIntegrityReceipt, quotaSlot: number, transactionId: string): StoredReceipt {
    if (!SHA256.test(receipt.receiptDigest)) throw new Error("receipt digest is invalid");
    return { version: 3, runId: receipt.runId, nonce: receipt.nonce, receiptDigest: receipt.receiptDigest, quotaSlot, transactionId };
  }

  private async reserveQuota(receipt: AlphaIntegrityReceipt, transactionId: string): Promise<StoredReceipt> {
    const start = Number.parseInt(receipt.receiptDigest.slice(0, 8), 16) % this.#maxRecords;
    for (let offset = 0; offset < this.#maxRecords; offset += 1) {
      const slot = (start + offset) % this.#maxRecords;
      const record = this.record(receipt, slot, transactionId);
      try { await this.publishJson(this.path("quota", String(slot)), record, "quota", "quota slot exists"); return record; }
      catch (error) { if (!/quota slot exists/u.test((error as Error).message)) throw error; }
    }
    throw new Error(`receipt store has reached its ${this.#maxRecords} record limit`);
  }

  private async removeOwnedExclusive(path: string, expected: StoredReceipt, claimId: string): Promise<void> {
    const quarantine = join(this.directory, ".quarantine", `${claimId}-${randomUUID()}.json`);
    try { await rename(path, quarantine); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return; throw error; }
    const actual = await this.readRecord(quarantine);
    if (actual.receiptDigest !== expected.receiptDigest || actual.transactionId !== expected.transactionId) {
      await link(quarantine, path).catch(() => undefined);
      throw new Error("recovery ownership changed while claiming marker");
    }
    await rm(quarantine);
    await this.syncDirectory(dirname(path));
  }

  async issue(receipt: AlphaIntegrityReceipt): Promise<void> {
    await this.initialize();
    const transactionId = randomUUID();
    const record = await this.reserveQuota(receipt, transactionId);
    const transactionPath = this.path("transactions", receipt.receiptDigest);
    const runPath = this.path("runs", receipt.runId);
    const noncePath = this.path("nonces", receipt.nonce);
    const issuedPath = this.path("issued", receipt.receiptDigest);
    let transactionReserved = false;
    let runReserved = false;
    let nonceReserved = false;
    let publishedFault = false;
    try {
      await this.publishJson(transactionPath, record, "transaction", "issuance transaction already exists");
      transactionReserved = true;
      await this.publishJson(runPath, record, "run", `run ID already exists: ${receipt.runId}`);
      runReserved = true;
      await this.publishJson(noncePath, record, "nonce", `receipt nonce already exists: ${receipt.nonce}`);
      nonceReserved = true;
      await this.options.faultInjector?.("issue:before-issued");
      await this.publishJson(issuedPath, { ...record, receipt }, "issued", "receipt is already issued");
    } catch (error) {
      publishedFault = typeof (error as { publishedPath?: unknown }).publishedPath === "string";
      if (!publishedFault) {
        const claimId = randomUUID();
        if (nonceReserved) await this.removeOwnedExclusive(noncePath, record, claimId);
        if (runReserved) await this.removeOwnedExclusive(runPath, record, claimId);
        if (transactionReserved) await this.removeOwnedExclusive(transactionPath, record, claimId);
        await this.removeOwnedExclusive(this.path("quota", String(record.quotaSlot)), record, claimId);
      }
      throw error;
    }
  }

  async rollbackIssue(receiptDigest: string): Promise<void> {
    await this.initialize();
    const issued = await this.readRecord(this.path("issued", receiptDigest));
    try { await stat(this.path("consumed", receiptDigest)); throw new Error("cannot roll back a consumed receipt"); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    const claimId = randomUUID();
    for (const path of [this.path("issued", receiptDigest), this.path("nonces", issued.nonce), this.path("runs", issued.runId), this.path("transactions", receiptDigest), this.path("quota", String(issued.quotaSlot))]) await this.removeOwnedExclusive(path, issued, claimId);
  }

  /** Offline-only recovery. The caller must prove no issuer is active for this store. */
  async recoverInterruptedIssue(receipt: AlphaIntegrityReceipt, options: { readonly offlineExclusive: true; readonly transactionId: string }): Promise<void> {
    await this.initialize();
    if (options?.offlineExclusive !== true || typeof options.transactionId !== "string") throw new Error("offlineExclusive recovery and transactionId are required");
    const transaction = await this.readRecord(this.path("transactions", receipt.receiptDigest));
    if (transaction.transactionId !== options.transactionId || transaction.receiptDigest !== receipt.receiptDigest) throw new Error("recovery transaction ownership mismatch");
    const recoveryPath = this.path("recovery", receipt.receiptDigest);
    await this.publishJson(recoveryPath, transaction, "recovery", "recovery is already claimed");
    try {
      try { await stat(this.path("issued", receipt.receiptDigest)); throw new Error("cannot recover a completed issuance"); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
      const current = await this.readRecord(this.path("transactions", receipt.receiptDigest));
      if (current.transactionId !== options.transactionId) throw new Error("recovery transaction changed");
      for (const path of [this.path("nonces", receipt.nonce), this.path("runs", receipt.runId), this.path("transactions", receipt.receiptDigest), this.path("quota", String(transaction.quotaSlot))]) await this.removeOwnedExclusive(path, transaction, options.transactionId);
    } finally { await this.removeOwnedExclusive(recoveryPath, transaction, options.transactionId); }
  }

  async completeReceiptFile(receiptDigest: string, outputPath: string): Promise<AlphaIntegrityReceipt> {
    await this.initialize();
    const record = await this.readRecord(this.path("issued", receiptDigest));
    const receipt = record.receipt;
    if (receipt === undefined || receipt.receiptDigest !== receiptDigest) throw new Error("issued receipt payload is missing or mismatched");
    const { receiptDigest: _digest, ...signed } = receipt;
    if (sha256Canonical(signed) !== receiptDigest) throw new Error("issued receipt payload failed its digest check");
    await mkdir(dirname(outputPath), { recursive: true });
    await this.publishJson(outputPath, receipt, "receipt-output", `receipt already exists: ${outputPath}`, dirname(outputPath));
    return receipt;
  }

  async consume(receipt: AlphaIntegrityReceipt, consumedAt: Date): Promise<void> {
    await this.initialize();
    if (!(consumedAt instanceof Date) || !Number.isFinite(consumedAt.getTime())) throw new Error("consumedAt must be a valid Date");
    const issued = await this.readRecord(this.path("issued", receipt.receiptDigest));
    if (issued.runId !== receipt.runId || issued.nonce !== receipt.nonce) throw new Error("receipt registry binding mismatch");
    await this.publishJson(this.path("consumed", receipt.receiptDigest), { ...issued, consumedAt: consumedAt.toISOString() }, "consumed", "receipt has already been consumed");
  }
}
