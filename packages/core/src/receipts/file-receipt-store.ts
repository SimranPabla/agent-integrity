import { mkdir, open, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import type { AlphaIntegrityReceipt } from "@agent-integrity/protocol";

interface StoredReceipt { readonly runId: string; readonly nonce: string; readonly receiptDigest: string; readonly state: "issued" | "consumed"; readonly consumedAt?: string }
interface Registry { readonly version: 1; readonly receipts: readonly StoredReceipt[] }
const EMPTY: Registry = { version: 1, receipts: [] };

export class FileReceiptStore {
  constructor(readonly directory: string, readonly options: { lockRetryMs?: number; lockTimeoutMs?: number; staleLockMs?: number } = {}) {}

  private async withLock<T>(operation: () => Promise<T>): Promise<T> {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    const lockPath = join(this.directory, ".lock");
    const deadline = Date.now() + (this.options.lockTimeoutMs ?? 5_000);
    let lock;
    for (;;) {
      try { lock = await open(lockPath, "wx", 0o600); break; }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST" || Date.now() >= deadline) throw error;
        try {
          const lockStat = await stat(lockPath);
          if (Date.now() - lockStat.mtimeMs > (this.options.staleLockMs ?? 30_000)) {
            await rm(lockPath, { force: true });
            continue;
          }
        } catch (lockError) {
          if ((lockError as NodeJS.ErrnoException).code !== "ENOENT") throw lockError;
        }
        await new Promise((resolve) => setTimeout(resolve, this.options.lockRetryMs ?? 10));
      }
    }
    try { return await operation(); }
    finally { await lock.close(); await rm(lockPath, { force: true }); }
  }

  private async read(): Promise<Registry> {
    try {
      const value = JSON.parse(await readFile(join(this.directory, "registry.json"), "utf8")) as Registry;
      if (value.version !== 1 || !Array.isArray(value.receipts)) throw new Error("invalid receipt registry");
      return value;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return EMPTY;
      throw error;
    }
  }

  private async write(registry: Registry): Promise<void> {
    const temporary = join(this.directory, `.registry.${process.pid}.${randomUUID()}.tmp`);
    await writeFile(temporary, `${JSON.stringify(registry)}\n`, { mode: 0o600, flag: "wx" });
    await rename(temporary, join(this.directory, "registry.json"));
  }

  async issue(receipt: AlphaIntegrityReceipt): Promise<void> {
    await this.withLock(async () => {
      const registry = await this.read();
      if (registry.receipts.some((entry) => entry.runId === receipt.runId)) throw new Error(`run ID already exists: ${receipt.runId}`);
      if (registry.receipts.some((entry) => entry.nonce === receipt.nonce)) throw new Error(`receipt nonce already exists: ${receipt.nonce}`);
      await this.write({ version: 1, receipts: [...registry.receipts, { runId: receipt.runId, nonce: receipt.nonce, receiptDigest: receipt.receiptDigest, state: "issued" }] });
    });
  }

  async rollbackIssue(receiptDigest: string): Promise<void> {
    await this.withLock(async () => {
      const registry = await this.read();
      const entry = registry.receipts.find((item) => item.receiptDigest === receiptDigest);
      if (entry?.state === "consumed") throw new Error("cannot roll back a consumed receipt");
      await this.write({ version: 1, receipts: registry.receipts.filter((item) => item.receiptDigest !== receiptDigest) });
    });
  }

  async consume(receipt: AlphaIntegrityReceipt, consumedAt: Date): Promise<void> {
    await this.withLock(async () => {
      const registry = await this.read();
      const index = registry.receipts.findIndex((entry) => entry.receiptDigest === receipt.receiptDigest);
      if (index < 0) throw new Error("receipt is not issued by this store");
      const current = registry.receipts[index]!;
      if (current.runId !== receipt.runId || current.nonce !== receipt.nonce) throw new Error("receipt registry binding mismatch");
      if (current.state === "consumed") throw new Error("receipt has already been consumed");
      const receipts = [...registry.receipts];
      receipts[index] = { ...current, state: "consumed", consumedAt: consumedAt.toISOString() };
      await this.write({ version: 1, receipts });
    });
  }
}
