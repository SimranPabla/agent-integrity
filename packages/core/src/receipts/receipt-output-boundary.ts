import { randomUUID } from "node:crypto";
import { link, lstat, open, readFile, realpath, rm } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { sha256Canonical } from "../hash.js";

const SAFE_FILENAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;

interface RootIdentity {
  readonly realPath: string;
  readonly device: number;
  readonly inode: number;
  readonly uid: number;
  readonly gid: number;
  readonly mode: number;
}

async function identity(path: string): Promise<RootIdentity> {
  const info = await lstat(path);
  if (info.isSymbolicLink() || !info.isDirectory()) throw new Error("receipt output root must be a real directory");
  if ((info.mode & 0o077) !== 0) throw new Error("receipt output root permissions are too broad");
  return {
    realPath: await realpath(path),
    device: info.dev,
    inode: info.ino,
    uid: info.uid,
    gid: info.gid,
    mode: info.mode & 0o777,
  };
}

async function syncDirectory(path: string): Promise<void> {
  const handle = await open(path, "r");
  try { await handle.sync(); }
  catch (error) {
    if (!["EINVAL", "ENOTSUP", "EISDIR"].includes((error as NodeJS.ErrnoException).code ?? "")) throw error;
  } finally { await handle.close(); }
}

export class ReceiptOutputBoundary {
  readonly rootIdentityDigest: string;

  private constructor(readonly root: string, readonly rootIdentity: RootIdentity) {
    this.rootIdentityDigest = sha256Canonical(rootIdentity);
  }

  static async open(root: string): Promise<ReceiptOutputBoundary> {
    if (!isAbsolute(root)) throw new Error("receipt output root must be absolute");
    const rootIdentity = await identity(root);
    if (rootIdentity.realPath !== root) throw new Error("receipt output root must be canonical");
    return new ReceiptOutputBoundary(root, rootIdentity);
  }

  async assertIdentity(): Promise<void> {
    if (sha256Canonical(await identity(this.root)) !== this.rootIdentityDigest) throw new Error("receipt output root identity changed");
  }

  validateName(name: string): string {
    if (!SAFE_FILENAME.test(name) || name === "." || name === "..") throw new Error("receipt output name must be one safe relative filename");
    return name;
  }

  async publishEquivalent(name: string, bytes: Uint8Array): Promise<void> {
    const safeName = this.validateName(name);
    await this.assertIdentity();
    const target = join(this.root, safeName);
    const temporary = join(this.root, `.receipt-${randomUUID()}.tmp`);
    const handle = await open(temporary, "wx", 0o600);
    try {
      await handle.writeFile(bytes);
      await handle.sync();
      try { await link(temporary, target); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        const existingInfo = await lstat(target);
        if (existingInfo.isSymbolicLink() || !existingInfo.isFile() || existingInfo.nlink !== 1) throw new Error("existing receipt output is not a single regular file");
        const existing = await readFile(target);
        if (!existing.equals(Buffer.from(bytes))) throw new Error("existing receipt output conflicts with the issued receipt");
      }
      await this.assertIdentity();
      await syncDirectory(this.root);
    } finally {
      await handle.close();
      await rm(temporary, { force: true });
    }
  }
}
