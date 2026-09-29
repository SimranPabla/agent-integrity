import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { chmod, link, lstat, mkdir, open, opendir, realpath, rm } from "node:fs/promises";
import { dirname, isAbsolute, join, relative } from "node:path";

export class DurableRecordExistsError extends Error {
  constructor() { super("durable record already exists"); this.name = "DurableRecordExistsError"; }
}

export interface DurableJsonOptions {
  readonly maxStateBytes: number;
  readonly maxEntries: number;
  readonly faultInjector?: (point: string) => void | Promise<void>;
}

interface Identity { readonly dev: bigint; readonly ino: bigint; readonly uid: number; readonly real: string }
interface SerializedIdentity { readonly dev: string; readonly ino: string; readonly uid: number; readonly real: string }
interface IdentityAnchor {
  readonly version: 1;
  readonly directory: string;
  readonly parent: SerializedIdentity;
  readonly root: SerializedIdentity;
  readonly children: Readonly<Record<string, SerializedIdentity>>;
}

function identity(info: Awaited<ReturnType<typeof lstat>>, real: string): Identity {
  return { dev: BigInt(info.dev), ino: BigInt(info.ino), uid: Number(info.uid), real };
}
function sameIdentity(left: Identity, right: Identity): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.uid === right.uid && left.real === right.real;
}
function currentUid(): number | undefined { return process.getuid?.(); }
function serializeIdentity(value: Identity): SerializedIdentity {
  return { dev: value.dev.toString(10), ino: value.ino.toString(10), uid: value.uid, real: value.real };
}
function sameSerializedIdentity(expected: SerializedIdentity, actual: Identity): boolean {
  return expected.dev === actual.dev.toString(10) && expected.ino === actual.ino.toString(10) && expected.uid === actual.uid && expected.real === actual.real;
}
function plainRecord(value: unknown, message: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new Error(message);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).some((key) => typeof key !== "string") || Object.values(descriptors).some((descriptor) => descriptor.get !== undefined || descriptor.set !== undefined || descriptor.enumerable !== true || !("value" in descriptor))) throw new Error(message);
  return Object.fromEntries(Object.entries(descriptors).map(([key, descriptor]) => [key, descriptor.value]));
}
function parseSerializedIdentity(value: unknown): SerializedIdentity {
  const record = plainRecord(value, "durable state identity anchor is invalid");
  if (Object.keys(record).sort().join(",") !== "dev,ino,real,uid" || typeof record.dev !== "string" || !/^[0-9]+$/u.test(record.dev) || typeof record.ino !== "string" || !/^[0-9]+$/u.test(record.ino) || !Number.isSafeInteger(record.uid) || typeof record.real !== "string" || !isAbsolute(record.real)) throw new Error("durable state identity anchor is invalid");
  return { dev: record.dev, ino: record.ino, uid: record.uid as number, real: record.real };
}

export class DurableJsonDirectory {
  readonly #directory: string;
  readonly #options: DurableJsonOptions;
  #rootIdentity: Identity | undefined;
  #parentIdentity: Identity | undefined;
  #childIdentities: ReadonlyMap<string, Identity> | undefined;

  constructor(directory: string, options: DurableJsonOptions) {
    if (!isAbsolute(directory)) throw new TypeError("durable state root must be absolute");
    if (!Number.isSafeInteger(options.maxStateBytes) || options.maxStateBytes < 128 || options.maxStateBytes > 1024 * 1024) throw new TypeError("maximum state bytes is invalid");
    if (!Number.isSafeInteger(options.maxEntries) || options.maxEntries < 1 || options.maxEntries > 1_000_000) throw new TypeError("maximum entries is invalid");
    this.#directory = directory;
    this.#options = options;
  }

  get path(): string { return this.#directory; }

  async initialize(subdirectories: readonly string[]): Promise<void> {
    const parent = dirname(this.#directory);
    const parentBefore = await this.#inspectDirectory(parent, false);
    let rootCreated = false;
    try { await mkdir(this.#directory, { mode: 0o700 }); rootCreated = true; }
    catch (error) { if ((error as NodeJS.ErrnoException)?.code !== "EEXIST") throw error; }
    if (rootCreated) await chmod(this.#directory, 0o700);
    const root = await this.#inspectDirectory(this.#directory, true);
    const parentAfter = await this.#inspectDirectory(parent, false);
    if (!sameIdentity(parentBefore, parentAfter)) throw new Error("durable state parent identity was replaced");
    if (this.#rootIdentity !== undefined && (!sameIdentity(this.#rootIdentity, root) || !sameIdentity(this.#parentIdentity!, parentAfter))) throw new Error("durable state root or parent identity was replaced");
    const children = new Map<string, Identity>();
    for (const name of subdirectories) {
      if (!/^[a-z][a-z0-9-]*$/u.test(name)) throw new TypeError("invalid durable state directory name");
      const child = join(this.#directory, name);
      let childCreated = false;
      try { await mkdir(child, { mode: 0o700 }); childCreated = true; }
      catch (error) { if ((error as NodeJS.ErrnoException)?.code !== "EEXIST") throw error; }
      if (childCreated) await chmod(child, 0o700);
      children.set(name, await this.#inspectDirectory(child, true));
    }
    await this.#verifyOrCreateIdentityAnchor(parentAfter, root, children);
    if (this.#rootIdentity === undefined) {
      this.#rootIdentity = root;
      this.#parentIdentity = parentAfter;
      this.#childIdentities = children;
    } else {
      for (const [name, expected] of this.#childIdentities!) {
        const actual = children.get(name);
        if (actual === undefined || !sameIdentity(expected, actual)) throw new Error("durable state child directory identity was replaced");
      }
    }
    await this.assertIdentity();
  }

  async assertIdentity(): Promise<void> {
    if (this.#rootIdentity === undefined || this.#parentIdentity === undefined || this.#childIdentities === undefined) throw new Error("durable state root is not initialized");
    const [root, parent] = await Promise.all([
      this.#inspectDirectory(this.#directory, true),
      this.#inspectDirectory(dirname(this.#directory), false),
    ]);
    if (!sameIdentity(this.#rootIdentity, root) || !sameIdentity(this.#parentIdentity, parent)) throw new Error("durable state root or parent identity was replaced");
    for (const [name, expected] of this.#childIdentities) {
      const actual = await this.#inspectDirectory(join(this.#directory, name), true);
      if (!sameIdentity(expected, actual)) throw new Error("durable state child directory identity was replaced");
    }
  }

  resolve(relativePath: string): string {
    const path = join(this.#directory, relativePath);
    const back = relative(this.#directory, path);
    if (back.startsWith("..") || isAbsolute(back)) throw new TypeError("durable record path escapes state root");
    return path;
  }

  async publishCreateOnce(relativePath: string, value: unknown): Promise<void> {
    await this.assertIdentity();
    const target = this.resolve(relativePath);
    const parent = dirname(target);
    await this.#inspectDirectory(parent, true);
    const bytes = Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
    if (bytes.byteLength > this.#options.maxStateBytes) throw new Error("durable state exceeds configured limit");
    const temporary = join(parent, `.sidecar-${randomUUID()}.tmp`);
    const handle = await open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    let temporaryExists = true;
    try {
      await handle.chmod(0o600);
      await this.#validateOpenFile(handle, "temporary durable record");
      await handle.writeFile(bytes);
      await this.#options.faultInjector?.("file:before-sync");
      await handle.sync();
      try { await link(temporary, target); }
      catch (error) {
        if ((error as NodeJS.ErrnoException)?.code === "EEXIST") {
          await this.#validateExistingNode(target);
          throw new DurableRecordExistsError();
        }
        throw error;
      }
      await rm(temporary);
      temporaryExists = false;
      await this.#validateExistingNode(target);
      await this.#syncDirectory(parent);
      await this.assertIdentity();
    } finally {
      await handle.close();
      if (temporaryExists) await rm(temporary, { force: true });
    }
  }

  async read(relativePath: string): Promise<unknown> {
    await this.assertIdentity();
    const path = this.resolve(relativePath);
    await this.#validateExistingNode(path);
    const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const info = await handle.stat();
      if (!info.isFile() || info.nlink !== 1) throw new Error("durable record is not a single-link regular file");
      if (info.size > this.#options.maxStateBytes) throw new Error("durable state exceeds configured limit");
      const buffer = Buffer.alloc(this.#options.maxStateBytes + 1);
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
      if (bytesRead > this.#options.maxStateBytes) throw new Error("durable state exceeds configured limit");
      try { return JSON.parse(buffer.subarray(0, bytesRead).toString("utf8")); }
      catch { throw new Error("invalid durable JSON state"); }
    } finally { await handle.close(); }
  }

  async entries(relativeDirectory: string): Promise<readonly string[]> {
    await this.assertIdentity();
    const path = this.resolve(relativeDirectory);
    await this.#inspectDirectory(path, true);
    const directory = await opendir(path);
    const names: string[] = [];
    try {
      for await (const entry of directory) {
        names.push(entry.name);
        if (names.length > this.#options.maxEntries) throw new Error("durable state entry limit exceeded");
      }
    } finally { await directory.close().catch(() => undefined); }
    return names.sort();
  }

  async #validateExistingNode(path: string): Promise<void> {
    const info = await lstat(path);
    if (info.isSymbolicLink()) throw new Error("durable record symlink is forbidden");
    if (!info.isFile()) throw new Error("durable record must be a regular file");
    if (info.nlink !== 1) throw new Error("durable record must have exactly one link");
    if ((info.mode & 0o777) !== 0o600) throw new Error("durable record mode must be 0600");
    const uid = currentUid();
    if (uid !== undefined && info.uid !== uid) throw new Error("durable record ownership is invalid");
  }

  async #validateOpenFile(handle: Awaited<ReturnType<typeof open>>, label: string): Promise<void> {
    const info = await handle.stat();
    if (!info.isFile() || info.nlink !== 1 || (info.mode & 0o777) !== 0o600) throw new Error(`${label} mode or type is invalid`);
    const uid = currentUid();
    if (uid !== undefined && info.uid !== uid) throw new Error(`${label} ownership is invalid`);
  }

  async #inspectDirectory(path: string, requirePrivate: boolean): Promise<Identity> {
    const info = await lstat(path);
    if (info.isSymbolicLink()) throw new Error("durable state directory symlink is forbidden");
    if (!info.isDirectory()) throw new Error("durable state path must be a directory");
    const mode = info.mode & 0o777;
    if (requirePrivate ? mode !== 0o700 : (mode & 0o022) !== 0) throw new Error("durable state directory mode or permissions are invalid");
    const uid = currentUid();
    if (uid !== undefined && info.uid !== uid) throw new Error("durable state directory ownership is invalid");
    return identity(info, await realpath(path));
  }

  #identityAnchorPath(): string {
    const name = createHash("sha256").update(this.#directory, "utf8").digest("hex");
    return join(dirname(this.#directory), `.agent-integrity-sidecar-${name}.identity.json`);
  }

  async #verifyOrCreateIdentityAnchor(parent: Identity, root: Identity, children: ReadonlyMap<string, Identity>): Promise<void> {
    const anchor: IdentityAnchor = {
      version: 1,
      directory: this.#directory,
      parent: serializeIdentity(parent),
      root: serializeIdentity(root),
      children: Object.fromEntries([...children.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([name, value]) => [name, serializeIdentity(value)])),
    };
    const path = this.#identityAnchorPath();
    try {
      const handle = await open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
      try {
        await handle.chmod(0o600);
        await this.#validateOpenFile(handle, "durable state identity anchor");
        await handle.writeFile(`${JSON.stringify(anchor)}\n`, "utf8");
        await handle.sync();
      } finally { await handle.close(); }
      await this.#syncDirectory(dirname(path));
      return;
    } catch (error) {
      if ((error as NodeJS.ErrnoException)?.code !== "EEXIST") throw error;
    }
    const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    let parsed: unknown;
    try {
      await this.#validateOpenFile(handle, "durable state identity anchor");
      const info = await handle.stat();
      if (info.size > 64 * 1024) throw new Error("durable state identity anchor is invalid");
      const buffer = Buffer.alloc(Number(info.size) + 1);
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
      if (bytesRead !== info.size) throw new Error("durable state identity anchor is invalid");
      parsed = JSON.parse(buffer.subarray(0, bytesRead).toString("utf8"));
    } catch { throw new Error("durable state identity anchor is invalid"); }
    finally { await handle.close(); }
    const record = plainRecord(parsed, "durable state identity anchor is invalid");
    if (Object.keys(record).sort().join(",") !== "children,directory,parent,root,version" || record.version !== 1 || record.directory !== this.#directory) throw new Error("durable state identity anchor is invalid");
    const expectedParent = parseSerializedIdentity(record.parent);
    const expectedRoot = parseSerializedIdentity(record.root);
    if (!sameSerializedIdentity(expectedParent, parent) || !sameSerializedIdentity(expectedRoot, root)) throw new Error("durable state root or parent identity was replaced");
    const childRecord = plainRecord(record.children, "durable state identity anchor is invalid");
    if (Object.keys(childRecord).sort().join(",") !== [...children.keys()].sort().join(",")) throw new Error("durable state child directory identity was replaced");
    for (const [name, actual] of children) {
      if (!sameSerializedIdentity(parseSerializedIdentity(childRecord[name]), actual)) throw new Error("durable state child directory identity was replaced");
    }
  }

  async #syncDirectory(path: string): Promise<void> {
    await this.#options.faultInjector?.("directory:before-sync");
    let handle;
    try {
      await this.#options.faultInjector?.("directory:open");
      handle = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    } catch (error) {
      if (["EINVAL", "ENOTSUP", "EISDIR"].includes((error as NodeJS.ErrnoException)?.code ?? "")) return;
      throw error;
    }
    try {
      await this.#options.faultInjector?.("directory:sync");
      await handle.sync();
    } catch (error) {
      if (!["EINVAL", "ENOTSUP", "EISDIR"].includes((error as NodeJS.ErrnoException)?.code ?? "")) throw error;
    } finally { await handle.close(); }
  }
}
