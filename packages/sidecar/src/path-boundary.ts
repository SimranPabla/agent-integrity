import { lstat, realpath } from "node:fs/promises";
import { isAbsolute, posix } from "node:path";

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;

export interface FileIdentity {
  readonly dev: bigint;
  readonly ino: bigint;
  readonly uid: number;
  readonly real: string;
}

export function assertSafeBundleId(value: unknown): string {
  if (typeof value !== "string" || !SAFE_ID.test(value) || value === "." || value === "..") throw new TypeError("bundle identifier is invalid");
  return value;
}

export function assertProjectRelativePath(value: unknown, maximumBytes: number): string {
  if (typeof value !== "string" || value.length === 0 || Buffer.byteLength(value, "utf8") > maximumBytes || value.includes("\\") || value.includes("\0") || isAbsolute(value)) throw new TypeError("project-relative path is invalid");
  const segments = value.split("/");
  if (segments.some((segment) => segment.length === 0 || segment === "." || segment === "..")) throw new TypeError("project-relative path is invalid");
  for (const segment of segments) {
    let decoded: string;
    try { decoded = decodeURIComponent(segment); } catch { throw new TypeError("project-relative path percent encoding is invalid"); }
    if (decoded === "." || decoded === ".." || decoded.includes("/") || decoded.includes("\\") || decoded.includes("\0")) throw new TypeError("project-relative path contains encoded traversal");
  }
  if (posix.normalize(value) !== value) throw new TypeError("project-relative path is not normalized");
  return value;
}

export function compareUtf8(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

export function assertSortedUniqueUtf8(values: readonly string[], label: string): void {
  for (let index = 1; index < values.length; index += 1) {
    if (compareUtf8(values[index - 1]!, values[index]!) >= 0) throw new Error(`${label} must be sorted and unique`);
  }
}

export function isWithinProjectRoot(path: string, root: string): boolean {
  return path === root || path.startsWith(`${root}/`);
}

export async function inspectDirectory(path: string, mode: "incoming" | "private"): Promise<FileIdentity> {
  const info = await lstat(path, { bigint: true });
  if (info.isSymbolicLink()) throw new Error("directory symlink is forbidden");
  if (!info.isDirectory()) throw new Error("filesystem path must be a directory");
  const permissions = Number(info.mode & 0o777n);
  if (mode === "private" ? permissions !== 0o700 : (permissions & 0o027) !== 0) throw new Error("directory mode or permissions are invalid");
  const uid = process.getuid?.();
  if (mode === "private" && uid !== undefined && Number(info.uid) !== uid) throw new Error("private directory ownership is invalid");
  return { dev: info.dev, ino: info.ino, uid: Number(info.uid), real: await realpath(path) };
}

export function sameFileIdentity(left: FileIdentity, right: FileIdentity): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.uid === right.uid && left.real === right.real;
}
