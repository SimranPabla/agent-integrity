import { createHash, createPublicKey, sign, verify, type KeyObject } from "node:crypto";
import { canonicalJson } from "@agent-integrity/core";
import type { SidecarConfigSnapshot } from "./config.js";
import type { ReceiptKeyRegistry } from "./key-registry.js";

export const CAGE_MANIFEST_EXTENSION = "https://github.com/SimranPabla/agent-integrity/params/jwks/receipt-manifest/v1" as const;
const SAFE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const B64URL32 = /^[A-Za-z0-9_-]{43}$/u;
const B64URL64 = /^[A-Za-z0-9_-]{86}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const DOMAIN = Buffer.from("cage-agent-integrity-trust-manifest-v1\0", "utf8");

export interface CageJwk { readonly alg: "EdDSA"; readonly crv: "Ed25519"; readonly kid: string; readonly kty: "OKP"; readonly use: "sig"; readonly x: string }
export interface CageKeyMetadata { readonly kid: string; readonly notBefore: string; readonly notAfter: string; readonly revokedAt: string | null }
export interface CageManifestExtension {
  readonly version: "1"; readonly generation: number; readonly issuedAt: string; readonly validUntil: string;
  readonly receiptProfile: Readonly<{ issuer: string; audience: string; purpose: string; engineVersion: string; maximumReceiptLifetimeSeconds: number; maximumFutureSkewSeconds: number }>;
  readonly keyMetadata: readonly CageKeyMetadata[]; readonly signatureAlgorithm: "Ed25519"; readonly authorityKeyId: string;
  readonly manifestDigest: string; readonly signature: string;
}
export interface ParsedCageTrustManifest { readonly keys: readonly CageJwk[]; readonly extension: CageManifestExtension; readonly canonicalBytes: Uint8Array }

function sha(value: Uint8Array | string): string { return createHash("sha256").update(value).digest("hex"); }
function plain(value: unknown, label: string): Record<string, unknown> { if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new Error(`${label} is invalid`); return value as Record<string, unknown>; }
function exact(value: Record<string, unknown>, fields: readonly string[], label: string): void { const actual = Object.keys(value).sort(); const expected = [...fields].sort(); if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index])) throw new Error(`${label} contains unknown or missing members`); }
function safe(value: unknown, label: string): asserts value is string { if (typeof value !== "string" || !SAFE.test(value)) throw new Error(`${label} is invalid`); }
function iso(value: unknown, label: string): asserts value is string { if (typeof value !== "string" || !ISO.test(value) || new Date(value).toISOString() !== value) throw new Error(`${label} timestamp is invalid`); }
function bounded(value: unknown, label: string): asserts value is string { if (typeof value !== "string" || value.length === 0 || Buffer.byteLength(value, "utf8") > 256) throw new Error(`${label} is invalid`); }
function positive(value: unknown, label: string): asserts value is number { if (!Number.isSafeInteger(value) || (value as number) < 1) throw new Error(`${label} is invalid`); }
function decode32(value: unknown, label: string): Buffer { if (typeof value !== "string" || !B64URL32.test(value)) throw new Error(`${label} public key base64url is invalid`); const bytes = Buffer.from(value, "base64url"); if (bytes.byteLength !== 32 || bytes.toString("base64url") !== value) throw new Error(`${label} public key length or encoding is invalid`); return bytes; }
function freeze<T>(value: T): T { if (value !== null && typeof value === "object" && !Object.isFrozen(value)) { for (const child of Object.values(value as Record<string, unknown>)) freeze(child); Object.freeze(value); } return value; }
function unsignedManifest(keys: readonly CageJwk[], extension: Omit<CageManifestExtension, "manifestDigest" | "signature">): unknown { return { keys, [CAGE_MANIFEST_EXTENSION]: extension }; }
function manifestDigest(keys: readonly CageJwk[], extension: Omit<CageManifestExtension, "manifestDigest" | "signature">): string { return sha(canonicalJson(unsignedManifest(keys, extension))); }
function signatureInput(digest: string): Buffer { return Buffer.concat([DOMAIN, Buffer.from(digest, "hex")]); }

function manifestContent(registry: ReceiptKeyRegistry, manifest: SidecarConfigSnapshot["manifest"], profile: SidecarConfigSnapshot["receipt"]) {
  const metadata = registry.publicSnapshot();
  const keys: CageJwk[] = metadata.map((key) => ({ alg: "EdDSA", crv: "Ed25519", kid: key.kid, kty: "OKP", use: "sig", x: key.x }));
  const extensionBase = {
    version: "1" as const, generation: manifest.generation, issuedAt: manifest.issuedAt, validUntil: manifest.validUntil,
    receiptProfile: { issuer: profile.issuer, audience: profile.audience, purpose: profile.purpose, engineVersion: profile.engineVersion, maximumReceiptLifetimeSeconds: profile.maximumReceiptLifetimeSeconds, maximumFutureSkewSeconds: manifest.maximumFutureSkewSeconds },
    keyMetadata: metadata.map(({ kid, notBefore, notAfter, revokedAt }) => ({ kid, notBefore, notAfter, revokedAt })),
    signatureAlgorithm: "Ed25519" as const, authorityKeyId: manifest.authorityKeyId,
  };
  return { keys, extensionBase };
}

export function cageTrustManifestDigest(registry: ReceiptKeyRegistry, manifest: SidecarConfigSnapshot["manifest"], profile: SidecarConfigSnapshot["receipt"]): string {
  const { keys, extensionBase } = manifestContent(registry, manifest, profile);
  return manifestDigest(keys, extensionBase);
}

export function createCageTrustManifest(registry: ReceiptKeyRegistry, authority: Readonly<{ keyId: string; privateKey: KeyObject; publicX: string }>, manifest: SidecarConfigSnapshot["manifest"], profile: SidecarConfigSnapshot["receipt"]): Buffer {
  if (authority.privateKey.asymmetricKeyType !== "ed25519" || authority.keyId !== manifest.authorityKeyId || authority.publicX !== manifest.authorityPublicX || createPublicKey(authority.privateKey).export({ format: "jwk" }).x !== authority.publicX) throw new Error("manifest authority binding is invalid");
  const { keys, extensionBase } = manifestContent(registry, manifest, profile);
  const digest = manifestDigest(keys, extensionBase);
  const signature = sign(null, signatureInput(digest), authority.privateKey).toString("base64url");
  if (!B64URL64.test(signature)) throw new Error("manifest authority signature encoding is invalid");
  return Buffer.from(canonicalJson({ keys, [CAGE_MANIFEST_EXTENSION]: { ...extensionBase, manifestDigest: digest, signature } }), "utf8");
}

export interface ParseCageTrustManifestOptions {
  readonly now: Date; readonly authorityKeys: Readonly<Record<string, string>>;
  readonly maximumFutureSkewSeconds: number; readonly maximumReceiptLifetimeSeconds: number;
  readonly accepted?: Readonly<{ generation: number; manifestDigest: string }>;
}

export function parseCageTrustManifest(raw: Uint8Array, options: ParseCageTrustManifestOptions): ParsedCageTrustManifest {
  if (!Number.isSafeInteger(options.maximumFutureSkewSeconds) || options.maximumFutureSkewSeconds < 0 || options.maximumFutureSkewSeconds > 3600 || !Number.isSafeInteger(options.maximumReceiptLifetimeSeconds) || options.maximumReceiptLifetimeSeconds < 1 || options.maximumReceiptLifetimeSeconds > 86_400) throw new Error("trust manifest acceptance limits are invalid");
  const bytes = Buffer.from(raw); if (bytes.byteLength < 1 || bytes.byteLength > 256 * 1024) throw new Error("trust manifest size is invalid");
  let value: unknown; try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); } catch { throw new Error("trust manifest JSON is invalid"); }
  if (canonicalJson(value) !== bytes.toString("utf8")) throw new Error("trust manifest must be canonical JSON");
  const root = plain(value, "trust manifest"); exact(root, [CAGE_MANIFEST_EXTENSION, "keys"], "trust manifest");
  if (!Array.isArray(root.keys) || root.keys.length < 1 || root.keys.length > 128) throw new Error("trust manifest JWK count is invalid");
  const keys: CageJwk[] = root.keys.map((entry) => {
    const key = plain(entry, "trust manifest JWK"); exact(key, ["alg", "crv", "kid", "kty", "use", "x"], "trust manifest JWK"); safe(key.kid, "JWK kid"); decode32(key.x, "JWK");
    if (key.kty !== "OKP" || key.crv !== "Ed25519" || key.use !== "sig" || key.alg !== "EdDSA") throw new Error("trust manifest JWK JOSE values are invalid");
    return key as unknown as CageJwk;
  });
  if (keys.some((key, index) => index > 0 && keys[index - 1]!.kid >= key.kid)) throw new Error("trust manifest JWK kids must be sorted and unique");
  const extension = plain(root[CAGE_MANIFEST_EXTENSION], "trust manifest extension"); exact(extension, ["authorityKeyId", "generation", "issuedAt", "keyMetadata", "manifestDigest", "receiptProfile", "signature", "signatureAlgorithm", "validUntil", "version"], "trust manifest extension");
  if (extension.version !== "1" || extension.signatureAlgorithm !== "Ed25519") throw new Error("trust manifest version or signature algorithm is invalid"); positive(extension.generation, "manifest generation"); iso(extension.issuedAt, "manifest issuedAt"); iso(extension.validUntil, "manifest validUntil"); if (Date.parse(extension.issuedAt) >= Date.parse(extension.validUntil)) throw new Error("trust manifest validity ordering is invalid"); safe(extension.authorityKeyId, "manifest authority key ID");
  if (typeof extension.manifestDigest !== "string" || !SHA256.test(extension.manifestDigest) || typeof extension.signature !== "string" || !B64URL64.test(extension.signature) || Buffer.from(extension.signature, "base64url").byteLength !== 64 || Buffer.from(extension.signature, "base64url").toString("base64url") !== extension.signature) throw new Error("trust manifest digest or signature encoding is invalid");
  const receiptProfile = plain(extension.receiptProfile, "receipt profile"); exact(receiptProfile, ["audience", "engineVersion", "issuer", "maximumFutureSkewSeconds", "maximumReceiptLifetimeSeconds", "purpose"], "receipt profile"); for (const field of ["audience", "engineVersion", "issuer", "purpose"] as const) bounded(receiptProfile[field], `receipt profile ${field}`); positive(receiptProfile.maximumFutureSkewSeconds, "receipt profile future skew"); positive(receiptProfile.maximumReceiptLifetimeSeconds, "receipt profile lifetime");
  if ((receiptProfile.maximumFutureSkewSeconds as number) > options.maximumFutureSkewSeconds || (receiptProfile.maximumReceiptLifetimeSeconds as number) > options.maximumReceiptLifetimeSeconds) throw new Error("trust manifest receipt profile exceeds configured ceilings");
  if (!Array.isArray(extension.keyMetadata) || extension.keyMetadata.length !== keys.length) throw new Error("trust manifest key metadata binding is invalid");
  const keyMetadata: CageKeyMetadata[] = extension.keyMetadata.map((entry, index) => {
    const metadata = plain(entry, "key metadata"); exact(metadata, ["kid", "notAfter", "notBefore", "revokedAt"], "key metadata"); safe(metadata.kid, "key metadata kid"); iso(metadata.notBefore, "key metadata notBefore"); iso(metadata.notAfter, "key metadata notAfter"); if (metadata.kid !== keys[index]!.kid || Date.parse(metadata.notBefore) >= Date.parse(metadata.notAfter)) throw new Error("trust manifest key metadata ordering or validity is invalid");
    if (metadata.revokedAt !== null) { iso(metadata.revokedAt, "key metadata revokedAt"); if (Date.parse(metadata.revokedAt) < Date.parse(metadata.notBefore) || Date.parse(metadata.revokedAt) >= Date.parse(metadata.notAfter)) throw new Error("trust manifest key revocation ordering is invalid"); }
    return metadata as unknown as CageKeyMetadata;
  });
  const unsignedExtension = { version: "1" as const, generation: extension.generation as number, issuedAt: extension.issuedAt as string, validUntil: extension.validUntil as string, receiptProfile: receiptProfile as unknown as CageManifestExtension["receiptProfile"], keyMetadata, signatureAlgorithm: "Ed25519" as const, authorityKeyId: extension.authorityKeyId as string };
  const expectedDigest = manifestDigest(keys, unsignedExtension); if (expectedDigest !== extension.manifestDigest) throw new Error("trust manifest digest mismatch");
  const authorityX = Object.hasOwn(options.authorityKeys, extension.authorityKeyId as string) ? options.authorityKeys[extension.authorityKeyId as string] : undefined; if (authorityX === undefined) throw new Error("trust manifest authority key is unknown"); decode32(authorityX, "authority");
  const authorityKey = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: authorityX }, format: "jwk" });
  if (!verify(null, signatureInput(expectedDigest), authorityKey, Buffer.from(extension.signature as string, "base64url"))) throw new Error("trust manifest signature verification failed");
  const now = options.now.getTime(); if (!Number.isFinite(now)) throw new Error("trust manifest clock is invalid");
  if (Date.parse(extension.issuedAt as string) > now + options.maximumFutureSkewSeconds * 1000) throw new Error("trust manifest is issued too far in the future"); if (now >= Date.parse(extension.validUntil as string)) throw new Error("trust manifest is expired");
  if (options.accepted !== undefined) { if (extension.generation < options.accepted.generation) throw new Error("trust manifest generation rollback"); if (extension.generation === options.accepted.generation && extension.manifestDigest !== options.accepted.manifestDigest) throw new Error("trust manifest equal-generation digest conflict"); }
  const parsedExtension: CageManifestExtension = { ...unsignedExtension, manifestDigest: extension.manifestDigest as string, signature: extension.signature as string };
  return Object.freeze({ keys: freeze(keys), extension: freeze(parsedExtension), get canonicalBytes() { return Uint8Array.from(bytes); } });
}
