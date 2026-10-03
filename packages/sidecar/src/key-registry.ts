import { createPrivateKey, createPublicKey, KeyObject } from "node:crypto";
import type { HmacRegistry } from "./auth.js";
import type { ParsedSidecarConfig, ReceiptPublicKeyConfig } from "./config.js";

export interface ReceiptPublicKeyRecord extends ReceiptPublicKeyConfig {
  readonly publicKey: KeyObject;
}
export interface ReceiptPrivateKeyRecord {
  readonly kid: string;
  readonly privateKey: KeyObject;
}

function freeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !(value instanceof KeyObject) && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

export class ReceiptKeyRegistry {
  readonly #publicKeys: ReadonlyMap<string, ReceiptPublicKeyRecord>;
  readonly #privateKeys: ReadonlyMap<string, ReceiptPrivateKeyRecord>;
  readonly activeKeyId: string;

  constructor(activeKeyId: string, publicKeys: readonly ReceiptPublicKeyRecord[], privateKeys: readonly ReceiptPrivateKeyRecord[]) {
    this.activeKeyId = activeKeyId;
    this.#publicKeys = new Map(publicKeys.map((key) => [key.kid, freeze(key)]));
    this.#privateKeys = new Map(privateKeys.map((key) => [key.kid, Object.freeze(key)]));
    Object.freeze(this);
  }

  select(now: Date): ReceiptPrivateKeyRecord & { readonly metadata: ReceiptPublicKeyRecord } {
    const metadata = this.#publicKeys.get(this.activeKeyId); const privateKey = this.#privateKeys.get(this.activeKeyId);
    if (metadata === undefined || privateKey === undefined) throw new Error("active receipt private/public key is unavailable");
    const time = now.getTime();
    if (!Number.isFinite(time) || time < Date.parse(metadata.notBefore) || time >= Date.parse(metadata.notAfter)) throw new Error("active receipt key is outside its validity interval");
    if (metadata.revokedAt !== null) throw new Error("active receipt key is revoked");
    return Object.freeze({ ...privateKey, metadata });
  }

  publicSnapshot(): readonly ReceiptPublicKeyConfig[] {
    return freeze([...this.#publicKeys.values()].sort((left, right) => left.kid < right.kid ? -1 : left.kid > right.kid ? 1 : 0).map(({ publicKey: _publicKey, ...key }) => ({ ...key })));
  }

  privateKey(kid: string): ReceiptPrivateKeyRecord | undefined { return this.#privateKeys.get(kid); }
}

export interface LoadedKeyMaterial {
  readonly hmacRegistry: HmacRegistry;
  readonly receiptRegistry: ReceiptKeyRegistry;
  readonly authority: Readonly<{ keyId: string; privateKey: KeyObject; publicX: string }>;
}

export async function loadKeyMaterial(config: ParsedSidecarConfig, readSecret: (path: string) => Promise<Buffer>): Promise<LoadedKeyMaterial> {
  const hmacKeys: Record<string, { secret: Uint8Array; validFromMs: number; validUntilMs: number; revokedAtMs?: number }> = Object.create(null);
  for (const key of config.client.hmacKeys) {
    const secret = await readSecret(key.secretFile);
    if (secret.byteLength < 32 || secret.byteLength > 1024) throw new Error("HMAC secret length is invalid");
    hmacKeys[key.kid] = Object.freeze({ secret: Uint8Array.from(secret), validFromMs: Date.parse(key.notBefore), validUntilMs: Date.parse(key.notAfter), ...(key.revokedAt === null ? {} : { revokedAtMs: Date.parse(key.revokedAt) }) });
  }
  const publicRecords: ReceiptPublicKeyRecord[] = config.receipt.publicKeys.map((key) => {
    const publicKey = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: key.x }, format: "jwk" });
    return { ...key, publicKey };
  });
  const publicByKid = new Map(publicRecords.map((key) => [key.kid, key]));
  const privateRecords: ReceiptPrivateKeyRecord[] = [];
  for (const key of config.receipt.privateKeys) {
    let privateKey: KeyObject;
    const secret = await readSecret(key.privateKeyFile);
    try { privateKey = createPrivateKey(secret); }
    catch { throw new Error("receipt private key cannot be parsed"); }
    if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("receipt private key must be Ed25519");
    const publicJwk = createPublicKey(privateKey).export({ format: "jwk" });
    if (publicJwk.kty !== "OKP" || publicJwk.crv !== "Ed25519" || typeof publicJwk.x !== "string" || publicByKid.get(key.kid)?.x !== publicJwk.x) throw new Error("receipt private key does not match public registry");
    privateRecords.push(Object.freeze({ kid: key.kid, privateKey }));
  }
  let authorityPrivate: KeyObject;
  const authoritySecret = await readSecret(config.manifest.authorityPrivateKeyFile);
  try { authorityPrivate = createPrivateKey(authoritySecret); }
  catch { throw new Error("manifest authority private key cannot be parsed"); }
  const authorityJwk = createPublicKey(authorityPrivate).export({ format: "jwk" });
  if (authorityPrivate.asymmetricKeyType !== "ed25519" || authorityJwk.kty !== "OKP" || authorityJwk.crv !== "Ed25519" || authorityJwk.x !== config.manifest.authorityPublicX) throw new Error("manifest authority private/public key mismatch");
  const registry = new ReceiptKeyRegistry(config.receipt.activeKeyId, publicRecords, privateRecords);
  registry.select(new Date(config.loadedAt));
  return Object.freeze({
    hmacRegistry: Object.freeze({ clients: Object.freeze({ [config.client.clientId]: Object.freeze({ keys: Object.freeze(hmacKeys) }) }) }),
    receiptRegistry: registry,
    authority: Object.freeze({ keyId: config.manifest.authorityKeyId, privateKey: authorityPrivate, publicX: config.manifest.authorityPublicX }),
  });
}
