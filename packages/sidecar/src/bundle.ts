import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { chmod, lstat, mkdir, open, opendir, rename, rm } from "node:fs/promises";
import { dirname, isAbsolute, join } from "node:path";
import { canonicalJson, sha256Canonical } from "@agent-integrity/core";
import {
  assertProjectRelativePath,
  assertSafeBundleId,
  assertSortedUniqueUtf8,
  compareUtf8,
  inspectDirectory,
  isWithinProjectRoot,
  sameFileIdentity,
  type FileIdentity,
} from "./path-boundary.js";
import { serviceRequestDigest, type ParsedServiceRequest } from "./protocol.js";

const DIGEST = /^[a-f0-9]{64}$/u;
const TIMESTAMP = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/u;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const MANIFEST_KEYS = [
  "allowedSourceRoots", "bundleId", "decisionRegistryPath", "envelopeDigest",
  "evidenceCompleteness", "expiresAt", "files", "manifestDigest", "policyPath",
  "publishedAt", "requestId", "trustedConfigPath", "version",
] as const;
const HARD_MAX_MANIFEST_BYTES = 1024 * 1024;
const HARD_MAX_ROOTS = 64;
const HARD_MAX_FILES = 10_000;
const HARD_MAX_PATH_BYTES = 1024;
const HARD_MAX_FUTURE_SKEW_MS = 60_000;
const HARD_MAX_LIFETIME_MS = 15 * 60_000;

export interface BundleLimits {
  readonly maxManifestBytes: number;
  readonly maxAllowedSourceRoots: number;
  readonly maxFiles: number;
  readonly maxPathBytes: number;
  readonly maxFileBytes: number;
  readonly maxTotalBytes: number;
  readonly maxFutureSkewMs: number;
  readonly maxBundleLifetimeMs: number;
}

export interface BundleFileRecord {
  readonly path: string;
  readonly bytes: number;
  readonly sha256: string;
}

export interface BundleManifestV1 {
  readonly version: "1";
  readonly bundleId: string;
  readonly requestId: string;
  readonly envelopeDigest: string;
  readonly policyPath: string;
  readonly decisionRegistryPath: string;
  readonly trustedConfigPath: string;
  readonly allowedSourceRoots: readonly string[];
  readonly evidenceCompleteness: Readonly<{
    readonly attesterId: string;
    readonly statement: "complete-for-request";
    readonly collectedAt: string;
  }>;
  readonly publishedAt: string;
  readonly expiresAt: string;
  readonly files: readonly BundleFileRecord[];
  readonly manifestDigest: string;
}

export interface BundleSnapshot {
  readonly snapshotId: string;
  readonly snapshotPath: string;
  readonly projectRoot: string;
  readonly incomingManifestDigest: string;
  readonly policyPath: string;
  readonly decisionRegistryPath: string;
  readonly trustedConfigPath: string;
  readonly policyFile: string;
  readonly decisionRegistryFile: string;
  readonly trustedConfigFile: string;
  readonly allowedSourceRoots: readonly string[];
  readonly files: readonly BundleFileRecord[];
}

export interface BundleSnapshotOptions {
  readonly request: ParsedServiceRequest;
  readonly incomingRoot: string;
  readonly snapshotRoot: string;
  readonly nowMs: number;
  readonly limits: BundleLimits;
  readonly faultInjector?: (point: string, path?: string) => void | Promise<void>;
}

export interface OpenBundleSnapshotOptions {
  readonly snapshotRoot: string;
  readonly snapshotId: string;
  readonly limits: BundleLimits;
}

interface PrivateSnapshotManifest {
  readonly version: "1";
  readonly snapshotId: string;
  readonly incomingManifestDigest: string;
  readonly policyPath: string;
  readonly decisionRegistryPath: string;
  readonly trustedConfigPath: string;
  readonly allowedSourceRoots: readonly string[];
  readonly files: readonly BundleFileRecord[];
}

interface StableStat {
  readonly dev: bigint;
  readonly ino: bigint;
  readonly size: bigint;
  readonly nlink: bigint;
  readonly mode: bigint;
  readonly mtimeNs: bigint;
  readonly ctimeNs: bigint;
}

function dataRecord(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new Error(`${label} is invalid`);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).some((key) => typeof key !== "string") || Object.values(descriptors).some((descriptor) => descriptor.get !== undefined || descriptor.set !== undefined || descriptor.enumerable !== true || !("value" in descriptor))) throw new Error(`${label} is invalid`);
  return Object.fromEntries(Object.entries(descriptors).map(([key, descriptor]) => [key, descriptor.value]));
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new Error(`${label} contains unknown or missing fields`);
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  }
  return value;
}

function validateJsonTree(value: unknown): void {
  const stack: Array<{ value: unknown; depth: number }> = [{ value, depth: 0 }];
  let nodes = 0;
  while (stack.length > 0) {
    const current = stack.pop()!;
    nodes += 1;
    if (nodes > 100_000 || current.depth > 64) throw new Error("manifest JSON complexity exceeds the configured limit");
    if (typeof current.value === "string") {
      for (let index = 0; index < current.value.length; index += 1) {
        const unit = current.value.charCodeAt(index);
        if (unit >= 0xd800 && unit <= 0xdbff) {
          const next = current.value.charCodeAt(index + 1);
          if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error("manifest contains a lone surrogate");
          index += 1;
        } else if (unit >= 0xdc00 && unit <= 0xdfff) throw new Error("manifest contains a lone surrogate");
      }
    } else if (Array.isArray(current.value)) {
      for (const entry of current.value) stack.push({ value: entry, depth: current.depth + 1 });
    } else if (current.value !== null && typeof current.value === "object") {
      for (const [key, entry] of Object.entries(current.value)) {
        stack.push({ value: key, depth: current.depth + 1 }, { value: entry, depth: current.depth + 1 });
      }
    }
  }
}

function safeInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new Error(`${label} must be a non-negative safe integer`);
  return value as number;
}

function parseLimits(value: BundleLimits): BundleLimits {
  const record = dataRecord(value, "bundle limits");
  exactKeys(record, ["maxAllowedSourceRoots", "maxBundleLifetimeMs", "maxFileBytes", "maxFiles", "maxFutureSkewMs", "maxManifestBytes", "maxPathBytes", "maxTotalBytes"], "bundle limits");
  const limits = {
    maxManifestBytes: safeInteger(record.maxManifestBytes, "maximum manifest bytes"),
    maxAllowedSourceRoots: safeInteger(record.maxAllowedSourceRoots, "maximum source roots"),
    maxFiles: safeInteger(record.maxFiles, "maximum files"),
    maxPathBytes: safeInteger(record.maxPathBytes, "maximum path bytes"),
    maxFileBytes: safeInteger(record.maxFileBytes, "maximum file bytes"),
    maxTotalBytes: safeInteger(record.maxTotalBytes, "maximum total bytes"),
    maxFutureSkewMs: safeInteger(record.maxFutureSkewMs, "maximum future skew"),
    maxBundleLifetimeMs: safeInteger(record.maxBundleLifetimeMs, "maximum bundle lifetime"),
  };
  if (limits.maxManifestBytes > HARD_MAX_MANIFEST_BYTES || limits.maxAllowedSourceRoots > HARD_MAX_ROOTS || limits.maxFiles > HARD_MAX_FILES || limits.maxPathBytes > HARD_MAX_PATH_BYTES || limits.maxFutureSkewMs > HARD_MAX_FUTURE_SKEW_MS || limits.maxBundleLifetimeMs > HARD_MAX_LIFETIME_MS) throw new Error("bundle limit exceeds hard maximum");
  return Object.freeze(limits);
}

function canonicalTimestamp(value: unknown, label: string): { text: string; milliseconds: number } {
  if (typeof value !== "string" || !TIMESTAMP.test(value)) throw new Error(`${label} timestamp is invalid`);
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) throw new Error(`${label} timestamp is invalid`);
  return { text: value, milliseconds };
}

function parseManifestObject(value: unknown, limits: BundleLimits, nowMs: number): BundleManifestV1 {
  const root = dataRecord(value, "bundle manifest");
  exactKeys(root, MANIFEST_KEYS, "bundle manifest");
  if (root.version !== "1" || typeof root.bundleId !== "string" || !SAFE_ID.test(root.bundleId) || root.bundleId === "." || root.bundleId === ".." || typeof root.requestId !== "string" || !SAFE_ID.test(root.requestId) || typeof root.envelopeDigest !== "string" || !DIGEST.test(root.envelopeDigest) || typeof root.manifestDigest !== "string" || !DIGEST.test(root.manifestDigest)) throw new Error("bundle manifest identifiers or digests are invalid");
  const policyPath = assertProjectRelativePath(root.policyPath, limits.maxPathBytes);
  const decisionRegistryPath = assertProjectRelativePath(root.decisionRegistryPath, limits.maxPathBytes);
  const trustedConfigPath = assertProjectRelativePath(root.trustedConfigPath, limits.maxPathBytes);
  if (!Array.isArray(root.allowedSourceRoots) || root.allowedSourceRoots.length === 0 || root.allowedSourceRoots.length > limits.maxAllowedSourceRoots) throw new Error("allowed source roots exceed the configured limit");
  const allowedSourceRoots = root.allowedSourceRoots.map((entry) => assertProjectRelativePath(entry, limits.maxPathBytes));
  assertSortedUniqueUtf8(allowedSourceRoots, "allowed source roots");
  const evidence = dataRecord(root.evidenceCompleteness, "evidence completeness");
  exactKeys(evidence, ["attesterId", "collectedAt", "statement"], "evidence completeness");
  if (typeof evidence.attesterId !== "string" || !SAFE_ID.test(evidence.attesterId) || evidence.statement !== "complete-for-request") throw new Error("evidence completeness is invalid");
  const collected = canonicalTimestamp(evidence.collectedAt, "collectedAt");
  const published = canonicalTimestamp(root.publishedAt, "publishedAt");
  const expires = canonicalTimestamp(root.expiresAt, "expiresAt");
  if (!Number.isSafeInteger(nowMs) || nowMs < 0 || nowMs > 9_999_999_999_999) throw new Error("captured host time is invalid");
  if (collected.milliseconds > published.milliseconds) throw new Error("evidence collection time is after publication time");
  if (published.milliseconds >= expires.milliseconds) throw new Error("bundle publication must precede expiry");
  if (published.milliseconds > nowMs + limits.maxFutureSkewMs) throw new Error("bundle publication time exceeds future skew");
  if (nowMs >= expires.milliseconds) throw new Error("bundle is expired at the captured host time");
  if (expires.milliseconds - published.milliseconds > limits.maxBundleLifetimeMs) throw new Error("bundle lifetime exceeds the configured maximum");
  if (!Array.isArray(root.files) || root.files.length === 0 || root.files.length > limits.maxFiles) throw new Error("bundle files exceed the configured limit");
  let totalBytes = 0;
  const files = root.files.map((entry): BundleFileRecord => {
    const file = dataRecord(entry, "bundle manifest file");
    exactKeys(file, ["bytes", "path", "sha256"], "bundle manifest file");
    const path = assertProjectRelativePath(file.path, limits.maxPathBytes);
    if (path === "manifest.json") throw new Error("manifest.json cannot list itself");
    const bytes = safeInteger(file.bytes, "bundle file bytes");
    if (bytes > limits.maxFileBytes) throw new Error("bundle file bytes exceed the configured limit");
    totalBytes += bytes;
    if (!Number.isSafeInteger(totalBytes) || totalBytes > limits.maxTotalBytes) throw new Error("bundle total bytes exceed the configured limit");
    if (typeof file.sha256 !== "string" || !DIGEST.test(file.sha256)) throw new Error("bundle file digest is invalid");
    return Object.freeze({ path, bytes, sha256: file.sha256 });
  });
  assertSortedUniqueUtf8(files.map(({ path }) => path), "bundle files");
  const parsed: BundleManifestV1 = {
    version: "1", bundleId: root.bundleId, requestId: root.requestId,
    envelopeDigest: root.envelopeDigest, policyPath, decisionRegistryPath, trustedConfigPath,
    allowedSourceRoots: Object.freeze(allowedSourceRoots),
    evidenceCompleteness: Object.freeze({ attesterId: evidence.attesterId, statement: "complete-for-request", collectedAt: collected.text }),
    publishedAt: published.text, expiresAt: expires.text, files: Object.freeze(files), manifestDigest: root.manifestDigest,
  };
  const { manifestDigest: _ignored, ...unsigned } = parsed;
  if (sha256Canonical(unsigned) !== parsed.manifestDigest) throw new Error("bundle manifest self-digest mismatch");
  return deepFreeze(parsed);
}

async function boundedCanonicalJson(path: string, maximumBytes: number, mode: "incoming" | "private"): Promise<{ value: unknown; bytes: Buffer }> {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n) throw new Error("manifest must be a single-link regular file");
    const permissions = Number(before.mode & 0o777n);
    if (mode === "private" ? permissions !== 0o600 : (permissions & 0o027) !== 0) throw new Error("manifest mode or permissions are invalid");
    if (before.size > BigInt(maximumBytes)) throw new Error("manifest bytes exceed the configured limit");
    const buffer = Buffer.alloc(Number(before.size) + 1);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    const after = await handle.stat({ bigint: true });
    const pathAfter = await lstat(path, { bigint: true });
    if (bytesRead !== Number(before.size) || before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs || pathAfter.dev !== after.dev || pathAfter.ino !== after.ino) throw new Error("manifest changed while being read");
    const bytes = buffer.subarray(0, bytesRead);
    let value: unknown;
    try { value = JSON.parse(bytes.toString("utf8")); } catch { throw new Error("manifest JSON is invalid"); }
    validateJsonTree(value);
    if (!Buffer.from(canonicalJson(value), "utf8").equals(bytes)) throw new Error("manifest bytes are not canonical JSON");
    return { value, bytes };
  } finally { await handle.close(); }
}

function stableStat(info: Awaited<ReturnType<Awaited<ReturnType<typeof open>>["stat"]>>): StableStat {
  const value = info as unknown as { dev: bigint; ino: bigint; size: bigint; nlink: bigint; mode: bigint; mtimeNs: bigint; ctimeNs: bigint };
  return { dev: value.dev, ino: value.ino, size: value.size, nlink: value.nlink, mode: value.mode, mtimeNs: value.mtimeNs, ctimeNs: value.ctimeNs };
}
function sameStableStat(left: StableStat, right: StableStat): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size && left.nlink === right.nlink && left.mode === right.mode && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}
function validateIncomingFile(info: StableStat): void {
  if ((info.mode & BigInt(constants.S_IFMT)) !== BigInt(constants.S_IFREG)) throw new Error("incoming bundle entry must be a regular file");
  if (info.nlink !== 1n) throw new Error("incoming bundle file must have exactly one link");
  if ((Number(info.mode & 0o777n) & 0o027) !== 0) throw new Error("incoming bundle file mode or permissions are invalid");
}

async function listProjectFiles(root: string, maximumPathBytes: number, maximumEntries: number, mode: "incoming" | "private"): Promise<readonly string[]> {
  const files: string[] = [];
  let entries = 0;
  async function visit(directory: string, prefix: string): Promise<void> {
    await inspectDirectory(directory, mode);
    const stream = await opendir(directory);
    try {
      for await (const entry of stream) {
        entries += 1;
        if (entries > maximumEntries) throw new Error("bundle filesystem entry limit exceeded");
        const relative = prefix.length === 0 ? entry.name : `${prefix}/${entry.name}`;
        assertProjectRelativePath(relative, maximumPathBytes);
        const absolute = join(directory, entry.name);
        const info = await lstat(absolute, { bigint: true });
        if (info.isSymbolicLink()) throw new Error("bundle symlink is forbidden");
        if (info.isDirectory()) await visit(absolute, relative);
        else if (info.isFile()) files.push(relative);
        else throw new Error("bundle entry must be a regular file");
      }
    } finally { await stream.close().catch(() => undefined); }
  }
  await visit(root, "");
  return files.sort(compareUtf8);
}

function requireManifestBindings(manifest: BundleManifestV1, request: ParsedServiceRequest): void {
  if (manifest.bundleId !== request.bundleId || manifest.requestId !== request.requestId || manifest.envelopeDigest !== sha256Canonical(request.envelope)) throw new Error("bundle manifest request binding mismatch");
  const paths = new Map(manifest.files.map((record) => [record.path, record]));
  for (const required of [manifest.policyPath, manifest.decisionRegistryPath, manifest.trustedConfigPath]) {
    if (!paths.has(required)) throw new Error("required trusted path is not listed in bundle files");
  }
  if (request.envelope.policy.decisions.path !== manifest.decisionRegistryPath) throw new Error("decision registry path binding mismatch");
  const policyRoots = [...request.envelope.policy.sources.allowedRoots].sort(compareUtf8);
  if (canonicalJson(policyRoots) !== canonicalJson(manifest.allowedSourceRoots)) throw new Error("allowed source roots do not match the envelope policy roots");
  for (const source of request.envelope.sources) {
    const listed = paths.get(source.path);
    if (listed === undefined || listed.bytes !== source.size || listed.sha256 !== source.sha256) throw new Error("envelope source size or digest is not exactly bound to a manifest-listed file");
    const matches = manifest.allowedSourceRoots.filter((root) => isWithinProjectRoot(source.path, root));
    if (matches.length !== 1) throw new Error("envelope source must fall under exactly one allowed source root");
  }
  const decision = paths.get(manifest.decisionRegistryPath);
  if (decision?.sha256 !== request.envelope.decisionRegistryDigest) throw new Error("decision registry digest binding mismatch");
}

async function syncDirectory(path: string): Promise<void> {
  const handle = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { await handle.sync(); } finally { await handle.close(); }
}

async function ensurePrivateDirectory(path: string): Promise<void> {
  await mkdir(path, { recursive: true, mode: 0o700 });
  await chmod(path, 0o700);
  await inspectDirectory(path, "private");
}

async function copyVerifiedFile(source: string, target: string, record: BundleFileRecord, faultInjector?: BundleSnapshotOptions["faultInjector"]): Promise<void> {
  const sourceHandle = await open(source, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = stableStat(await sourceHandle.stat({ bigint: true }));
    validateIncomingFile(before);
    if (before.size !== BigInt(record.bytes)) throw new Error("incoming bundle file size mismatch");
    await ensurePrivateDirectory(dirname(target));
    const targetHandle = await open(target, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    try {
      await targetHandle.chmod(0o600);
      const hash = createHash("sha256");
      const buffer = Buffer.alloc(64 * 1024);
      let position = 0;
      while (position < record.bytes) {
        const { bytesRead } = await sourceHandle.read(buffer, 0, Math.min(buffer.length, record.bytes - position), position);
        if (bytesRead === 0) throw new Error("incoming bundle file ended before declared size");
        const chunk = buffer.subarray(0, bytesRead);
        hash.update(chunk);
        let written = 0;
        while (written < chunk.byteLength) {
          const result = await targetHandle.write(chunk, written, chunk.byteLength - written);
          if (result.bytesWritten === 0) throw new Error("private snapshot file write made no progress");
          written += result.bytesWritten;
        }
        position += bytesRead;
      }
      const extra = Buffer.alloc(1);
      if ((await sourceHandle.read(extra, 0, 1, position)).bytesRead !== 0) throw new Error("incoming bundle file exceeds declared size");
      await faultInjector?.("file:after-read", source);
      const after = stableStat(await sourceHandle.stat({ bigint: true }));
      if (!sameStableStat(before, after)) throw new Error("incoming bundle file changed during copy");
      const pathAfter = await lstat(source, { bigint: true });
      if (pathAfter.dev !== after.dev || pathAfter.ino !== after.ino || pathAfter.size !== after.size || pathAfter.mtimeNs !== after.mtimeNs || pathAfter.ctimeNs !== after.ctimeNs) throw new Error("incoming bundle file identity changed during copy");
      if (hash.digest("hex") !== record.sha256) throw new Error("incoming bundle file digest mismatch");
      await targetHandle.sync();
    } finally { await targetHandle.close(); }
    await syncDirectory(dirname(target));
  } finally { await sourceHandle.close(); }
}

function snapshotIdentity(manifestDigest: string, files: readonly BundleFileRecord[]): string {
  return sha256Canonical({ incomingManifestDigest: manifestDigest, files });
}

function snapshotDescriptor(root: string, manifest: PrivateSnapshotManifest): BundleSnapshot {
  const snapshotPath = join(root, manifest.snapshotId);
  const projectRoot = join(snapshotPath, "project");
  return deepFreeze({
    snapshotId: manifest.snapshotId, snapshotPath, projectRoot,
    incomingManifestDigest: manifest.incomingManifestDigest,
    policyPath: manifest.policyPath, decisionRegistryPath: manifest.decisionRegistryPath,
    trustedConfigPath: manifest.trustedConfigPath,
    policyFile: join(projectRoot, manifest.policyPath),
    decisionRegistryFile: join(projectRoot, manifest.decisionRegistryPath),
    trustedConfigFile: join(projectRoot, manifest.trustedConfigPath),
    allowedSourceRoots: [...manifest.allowedSourceRoots],
    files: manifest.files.map((file) => ({ ...file })),
  });
}

function parsePrivateManifest(value: unknown, expectedSnapshotId: string, limits: BundleLimits): PrivateSnapshotManifest {
  const record = dataRecord(value, "private snapshot manifest");
  exactKeys(record, ["allowedSourceRoots", "decisionRegistryPath", "files", "incomingManifestDigest", "policyPath", "snapshotId", "trustedConfigPath", "version"], "private snapshot manifest");
  if (record.version !== "1" || record.snapshotId !== expectedSnapshotId || typeof record.incomingManifestDigest !== "string" || !DIGEST.test(record.incomingManifestDigest)) throw new Error("private snapshot identity is invalid");
  const policyPath = assertProjectRelativePath(record.policyPath, limits.maxPathBytes);
  const decisionRegistryPath = assertProjectRelativePath(record.decisionRegistryPath, limits.maxPathBytes);
  const trustedConfigPath = assertProjectRelativePath(record.trustedConfigPath, limits.maxPathBytes);
  if (!Array.isArray(record.allowedSourceRoots) || record.allowedSourceRoots.length === 0 || record.allowedSourceRoots.length > limits.maxAllowedSourceRoots) throw new Error("private snapshot source roots are invalid");
  const allowedSourceRoots = record.allowedSourceRoots.map((root) => assertProjectRelativePath(root, limits.maxPathBytes));
  assertSortedUniqueUtf8(allowedSourceRoots, "private snapshot source roots");
  if (!Array.isArray(record.files) || record.files.length === 0 || record.files.length > limits.maxFiles) throw new Error("private snapshot files are invalid");
  let total = 0;
  const files = record.files.map((entry): BundleFileRecord => {
    const file = dataRecord(entry, "private snapshot file");
    exactKeys(file, ["bytes", "path", "sha256"], "private snapshot file");
    const path = assertProjectRelativePath(file.path, limits.maxPathBytes);
    const bytes = safeInteger(file.bytes, "private snapshot file bytes");
    if (bytes > limits.maxFileBytes) throw new Error("private snapshot file bytes exceed limit");
    total += bytes;
    if (!Number.isSafeInteger(total) || total > limits.maxTotalBytes) throw new Error("private snapshot total bytes exceed limit");
    if (typeof file.sha256 !== "string" || !DIGEST.test(file.sha256)) throw new Error("private snapshot file digest is invalid");
    return Object.freeze({ path, bytes, sha256: file.sha256 });
  });
  assertSortedUniqueUtf8(files.map(({ path }) => path), "private snapshot files");
  if (snapshotIdentity(record.incomingManifestDigest, files) !== expectedSnapshotId) throw new Error("private snapshot digest mismatch");
  for (const required of [policyPath, decisionRegistryPath, trustedConfigPath]) if (!files.some(({ path }) => path === required)) throw new Error("private snapshot required file is missing");
  return deepFreeze({ version: "1", snapshotId: expectedSnapshotId, incomingManifestDigest: record.incomingManifestDigest, policyPath, decisionRegistryPath, trustedConfigPath, allowedSourceRoots, files });
}

async function validatePrivateFile(path: string, record: BundleFileRecord): Promise<void> {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const info = await handle.stat({ bigint: true });
    if (!info.isFile() || info.nlink !== 1n || Number(info.mode & 0o777n) !== 0o600 || info.size !== BigInt(record.bytes)) throw new Error("private snapshot file mode, type, link count, or size mismatch");
    const hash = createHash("sha256");
    const buffer = Buffer.alloc(64 * 1024);
    let position = 0;
    while (position < record.bytes) {
      const { bytesRead } = await handle.read(buffer, 0, Math.min(buffer.length, record.bytes - position), position);
      if (bytesRead === 0) throw new Error("private snapshot file is truncated");
      hash.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }
    if (hash.digest("hex") !== record.sha256) throw new Error("private snapshot file digest mismatch");
  } finally { await handle.close(); }
}

export async function openPrivateBundleSnapshot(options: OpenBundleSnapshotOptions): Promise<BundleSnapshot> {
  const captured = dataRecord(options, "open snapshot options");
  exactKeys(captured, ["limits", "snapshotId", "snapshotRoot"], "open snapshot options");
  if (typeof captured.snapshotRoot !== "string" || !isAbsolute(captured.snapshotRoot)) throw new TypeError("snapshot root must be absolute");
  const limits = parseLimits(captured.limits as BundleLimits);
  const snapshotId = typeof captured.snapshotId === "string" && DIGEST.test(captured.snapshotId) ? captured.snapshotId : (() => { throw new TypeError("snapshot identifier is invalid"); })();
  const snapshotRoot = captured.snapshotRoot;
  const rootBefore = await inspectDirectory(snapshotRoot, "private");
  const snapshotPath = join(snapshotRoot, snapshotId);
  const snapshotBefore = await inspectDirectory(snapshotPath, "private");
  const projectRoot = join(snapshotPath, "project");
  const projectBefore = await inspectDirectory(projectRoot, "private");
  const parsed = await boundedCanonicalJson(join(snapshotPath, "snapshot.json"), limits.maxManifestBytes, "private");
  const manifest = parsePrivateManifest(parsed.value, snapshotId, limits);
  const maximumEntries = limits.maxFiles * 2 + limits.maxAllowedSourceRoots + 16;
  const actualFiles = await listProjectFiles(projectRoot, limits.maxPathBytes, maximumEntries, "private");
  const declaredFiles = manifest.files.map(({ path }) => path);
  if (canonicalJson(actualFiles) !== canonicalJson(declaredFiles)) throw new Error("private snapshot exhaustive file list mismatch");
  for (const record of manifest.files) await validatePrivateFile(join(projectRoot, record.path), record);
  const [rootAfter, snapshotAfter, projectAfter] = await Promise.all([inspectDirectory(snapshotRoot, "private"), inspectDirectory(snapshotPath, "private"), inspectDirectory(projectRoot, "private")]);
  if (!sameFileIdentity(rootBefore, rootAfter) || !sameFileIdentity(snapshotBefore, snapshotAfter) || !sameFileIdentity(projectBefore, projectAfter)) throw new Error("private snapshot identity was replaced during validation");
  return snapshotDescriptor(snapshotRoot, manifest);
}

async function writePrivateManifest(path: string, manifest: PrivateSnapshotManifest): Promise<void> {
  const handle = await open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  try {
    await handle.chmod(0o600);
    await handle.writeFile(canonicalJson(manifest), "utf8");
    await handle.sync();
  } finally { await handle.close(); }
}

export async function validateAndSnapshotBundle(options: BundleSnapshotOptions): Promise<BundleSnapshot> {
  const captured = dataRecord(options, "bundle snapshot options");
  const expectedKeys = captured.faultInjector === undefined ? ["incomingRoot", "limits", "nowMs", "request", "snapshotRoot"] : ["faultInjector", "incomingRoot", "limits", "nowMs", "request", "snapshotRoot"];
  exactKeys(captured, expectedKeys, "bundle snapshot options");
  if (typeof captured.incomingRoot !== "string" || typeof captured.snapshotRoot !== "string" || !isAbsolute(captured.incomingRoot) || !isAbsolute(captured.snapshotRoot)) throw new TypeError("bundle roots must be absolute");
  if (!Number.isSafeInteger(captured.nowMs)) throw new TypeError("captured host time is invalid");
  if (captured.faultInjector !== undefined && typeof captured.faultInjector !== "function") throw new TypeError("bundle fault injector is invalid");
  const request = captured.request as ParsedServiceRequest;
  serviceRequestDigest(request);
  const incomingRoot = captured.incomingRoot;
  const snapshotRoot = captured.snapshotRoot;
  const nowMs = captured.nowMs as number;
  const faultInjector = captured.faultInjector as BundleSnapshotOptions["faultInjector"];
  const limits = parseLimits(captured.limits as BundleLimits);
  const bundleId = assertSafeBundleId(request.bundleId);
  const incomingRootBefore = await inspectDirectory(incomingRoot, "incoming");
  await inspectDirectory(snapshotRoot, "private");
  const bundlePath = join(incomingRoot, bundleId);
  const bundleBefore = await inspectDirectory(bundlePath, "incoming");
  const projectPath = join(bundlePath, "project");
  const projectBefore = await inspectDirectory(projectPath, "incoming");
  const rawManifest = await boundedCanonicalJson(join(bundlePath, "manifest.json"), limits.maxManifestBytes, "incoming");
  const manifest = parseManifestObject(rawManifest.value, limits, nowMs);
  requireManifestBindings(manifest, request);
  const maximumEntries = limits.maxFiles * 2 + limits.maxAllowedSourceRoots + 16;
  const actualFiles = await listProjectFiles(projectPath, limits.maxPathBytes, maximumEntries, "incoming");
  const declaredFiles = manifest.files.map(({ path }) => path);
  if (canonicalJson(actualFiles) !== canonicalJson(declaredFiles)) throw new Error("incoming bundle exhaustive file list mismatch: extra or missing file");

  const staging = join(snapshotRoot, `.snapshot-${randomUUID()}.tmp`);
  await mkdir(staging, { mode: 0o700 });
  await chmod(staging, 0o700);
  let stagingExists = true;
  try {
    const stagingProject = join(staging, "project");
    await ensurePrivateDirectory(stagingProject);
    for (const record of manifest.files) await copyVerifiedFile(join(projectPath, record.path), join(stagingProject, record.path), record, faultInjector);
    const secondFiles = await listProjectFiles(projectPath, limits.maxPathBytes, maximumEntries, "incoming");
    if (canonicalJson(secondFiles) !== canonicalJson(declaredFiles)) throw new Error("incoming bundle changed during snapshot copy");
    await faultInjector?.("bundle:before-final-identity", bundlePath);
    let incomingRootAfter: FileIdentity;
    let bundleAfter: FileIdentity;
    let projectAfter: FileIdentity;
    try {
      [incomingRootAfter, bundleAfter, projectAfter] = await Promise.all([
        inspectDirectory(incomingRoot, "incoming"), inspectDirectory(bundlePath, "incoming"), inspectDirectory(projectPath, "incoming"),
      ]);
    } catch (error) { throw new Error("incoming bundle root identity was replaced during snapshot copy", { cause: error }); }
    if (!sameFileIdentity(incomingRootBefore, incomingRootAfter) || !sameFileIdentity(bundleBefore, bundleAfter) || !sameFileIdentity(projectBefore, projectAfter)) throw new Error("incoming bundle root identity was replaced during snapshot copy");
    const snapshotId = snapshotIdentity(manifest.manifestDigest, manifest.files);
    const privateManifest: PrivateSnapshotManifest = deepFreeze({
      version: "1", snapshotId, incomingManifestDigest: manifest.manifestDigest,
      policyPath: manifest.policyPath, decisionRegistryPath: manifest.decisionRegistryPath,
      trustedConfigPath: manifest.trustedConfigPath, allowedSourceRoots: [...manifest.allowedSourceRoots],
      files: manifest.files.map((file) => ({ ...file })),
    });
    await writePrivateManifest(join(staging, "snapshot.json"), privateManifest);
    await syncDirectory(stagingProject);
    await syncDirectory(staging);
    const destination = join(snapshotRoot, snapshotId);
    try {
      await lstat(destination);
      return await openPrivateBundleSnapshot({ snapshotRoot, snapshotId, limits });
    } catch (error) {
      if ((error as NodeJS.ErrnoException)?.code !== "ENOENT") throw error;
    }
    try {
      await rename(staging, destination);
      stagingExists = false;
      await syncDirectory(snapshotRoot);
    } catch (error) {
      if (!(["EEXIST", "ENOTEMPTY"].includes((error as NodeJS.ErrnoException)?.code ?? ""))) throw error;
    }
    return await openPrivateBundleSnapshot({ snapshotRoot, snapshotId, limits });
  } finally {
    if (stagingExists) await rm(staging, { recursive: true, force: true });
  }
}
