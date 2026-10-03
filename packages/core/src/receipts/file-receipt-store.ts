import { createHash, randomUUID } from "node:crypto";
import { link, lstat, mkdir, open, opendir, readdir, rm, stat } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { AlphaIntegrityReceipt } from "@agent-integrity/protocol";
import { canonicalJson } from "../canonical-json.js";
import { ReceiptOutputBoundary } from "./receipt-output-boundary.js";
import {
  consumedView,
  freezeValidated,
  parseStoredReceiptRecord,
  type ConsumedReceiptRecord,
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

  /** Offline operator action for a lock left by a crashed process. Exact token possession is required. */
  async recoverAbandonedLock(options: { readonly offlineExclusive: true; readonly ownerToken: string }): Promise<void> {
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

  async issue(receipt: AlphaIntegrityReceipt, options: { readonly transactionId: string }): Promise<void> {
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

  async inspectIssuedByDigest(receiptDigest: string): Promise<AlphaIntegrityReceipt | undefined> {
    if (!SHA256.test(receiptDigest)) throw new Error("receipt digest is invalid");
    return this.withLock(async () => {
      try {
        const record = await this.readRecord(this.path("issued", receiptDigest), "issued");
        return freezeValidated(structuredClone(record.receipt!));
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
        throw error;
      }
    });
  }

  async inspectIssuedByRunId(runId: string): Promise<AlphaIntegrityReceipt | undefined> {
    if (!SAFE_IDENTIFIER.test(runId)) throw new Error("run ID is invalid");
    return this.withLock(async () => {
      try {
        const pointer = await this.readRecord(this.path("runs", runId), "run");
        const issued = await this.readRecord(this.path("issued", pointer.receiptDigest), "issued");
        if (issued.runId !== runId || issued.transactionId !== pointer.transactionId) throw new Error("run receipt binding mismatch");
        return freezeValidated(structuredClone(issued.receipt!));
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
        throw error;
      }
    });
  }

  async inspectConsumed(receiptDigest: string): Promise<ConsumedReceiptRecord | undefined> {
    if (!SHA256.test(receiptDigest)) throw new Error("receipt digest is invalid");
    return this.withLock(async () => {
      try { return consumedView(await this.readRecord(this.path("consumed", receiptDigest), "consumed")); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
        throw error;
      }
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
