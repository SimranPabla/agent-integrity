import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { isAbsolute, join, normalize } from "node:path";
import { assertIntegrityEnvelope, canonicalJson, parsePolicy, parseDecisionRegistry, sha256Canonical, type TrustedVerificationContext } from "@agent-integrity/core";
import type { IntegrityEnvelope } from "@agent-integrity/protocol";
import { openPrivateBundleSnapshot, type BundleLimits, type BundleFileRecord } from "./bundle.js";
import { assertProjectRelativePath, compareUtf8, isWithinProjectRoot } from "./path-boundary.js";

export interface VerificationLimits {
 readonly maxInputBytes: number; readonly maxOutputBytes: number;
 readonly maxPolicyBytes: number; readonly maxConfigBytes: number;
 readonly maxSourceBytes: number; readonly maxTotalSourceBytes: number;
 readonly maxItems: number; readonly maxFindings: number; readonly maxFindingBytes: number;
}
/** Data only: no request/receipt stores, keys, callbacks or mutation capabilities. */
export interface VerificationInput {
 readonly version: "1"; readonly canonicalEnvelope: string;
 readonly snapshotRoot: string; readonly snapshotId: string;
 readonly bundleLimits: BundleLimits; readonly limits: VerificationLimits;
}
export function freezeTree<T>(value: T): T {
 if (value !== null && typeof value === "object") {
  for (const child of Object.values(value)) freezeTree(child);
  Object.freeze(value);
 }
 return value;
}
export function closedRecord(value: unknown, keys: readonly string[]): Record<string, unknown> {
 if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new Error("invalid closed record");
 const descriptors = Object.getOwnPropertyDescriptors(value);
 if (Reflect.ownKeys(descriptors).length !== keys.length || keys.some(key => !Object.hasOwn(descriptors,key)) || Object.values(descriptors).some(d => !d.enumerable || !("value" in d) || d.get || d.set)) throw new Error("unknown, missing or accessor field");
 return Object.fromEntries(Object.entries(descriptors).map(([key,d])=>[key,d.value]));
}
function positive(value: unknown, maximum: number): number {
 if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1 || value > maximum) throw new Error("invalid limit");
 return value;
}
export function validateVerificationJsonTree(value: unknown, maxItems: number, depth=0, budget={nodes:0}): void {
 if (++budget.nodes > 100000 || depth > 64) throw new Error("JSON complexity limit");
 if (Array.isArray(value)) { if(value.length > maxItems) throw new Error("item limit"); for(const child of value) validateVerificationJsonTree(child,maxItems,depth+1,budget); }
 else if(value !== null && typeof value === "object") {
  for(const d of Object.values(Object.getOwnPropertyDescriptors(value))) { if (!("value" in d) || d.get || d.set || !d.enumerable) throw new Error("invalid JSON data"); validateVerificationJsonTree(d.value,maxItems,depth+1,budget); }
 }
 else if(typeof value === "string") {
  for(let i=0;i<value.length;i++) { const c=value.charCodeAt(i); if(c>=0xd800&&c<=0xdbff) {const n=value.charCodeAt(++i);if(!(n>=0xdc00&&n<=0xdfff))throw new Error("lone surrogate");}else if(c>=0xdc00&&c<=0xdfff)throw new Error("lone surrogate"); }
 } else if(value !== null && typeof value !== "boolean" && (typeof value !== "number" || !Number.isFinite(value))) throw new Error("invalid JSON data");
}
export function parseCanonicalEnvelope(text: string, limits: VerificationLimits): IntegrityEnvelope {
 if(Buffer.byteLength(text)>limits.maxInputBytes) throw new Error("envelope byte limit");
 const value: unknown=JSON.parse(text); validateVerificationJsonTree(value,limits.maxItems);
 if(canonicalJson(value)!==text) throw new Error("noncanonical envelope");
 assertIntegrityEnvelope(value); return freezeTree(value);
}
export function parseVerificationInput(value: unknown): VerificationInput {
 const r=closedRecord(value,["version","canonicalEnvelope","snapshotRoot","snapshotId","bundleLimits","limits"]);
 if(r.version!=="1" || typeof r.canonicalEnvelope!=="string" || typeof r.snapshotRoot!=="string" || !isAbsolute(r.snapshotRoot) || normalize(r.snapshotRoot)!==r.snapshotRoot || typeof r.snapshotId!=="string" || !/^[a-f0-9]{64}$/u.test(r.snapshotId)) throw new Error("invalid verification input");
 const l=closedRecord(r.limits,["maxInputBytes","maxOutputBytes","maxPolicyBytes","maxConfigBytes","maxSourceBytes","maxTotalSourceBytes","maxItems","maxFindings","maxFindingBytes"]);
 const limits: VerificationLimits={maxInputBytes:positive(l.maxInputBytes,16*1048576),maxOutputBytes:positive(l.maxOutputBytes,32*1048576),maxPolicyBytes:positive(l.maxPolicyBytes,1048576),maxConfigBytes:positive(l.maxConfigBytes,1048576),maxSourceBytes:positive(l.maxSourceBytes,16*1048576),maxTotalSourceBytes:positive(l.maxTotalSourceBytes,64*1048576),maxItems:positive(l.maxItems,10000),maxFindings:positive(l.maxFindings,10000),maxFindingBytes:positive(l.maxFindingBytes,65536)};
 const b=closedRecord(r.bundleLimits,["maxManifestBytes","maxAllowedSourceRoots","maxFiles","maxPathBytes","maxFileBytes","maxTotalBytes","maxFutureSkewMs","maxBundleLifetimeMs"]);
 const bundleLimits: BundleLimits={maxManifestBytes:positive(b.maxManifestBytes,1048576),maxAllowedSourceRoots:positive(b.maxAllowedSourceRoots,64),maxFiles:positive(b.maxFiles,10000),maxPathBytes:positive(b.maxPathBytes,1024),maxFileBytes:positive(b.maxFileBytes,16*1048576),maxTotalBytes:positive(b.maxTotalBytes,64*1048576),maxFutureSkewMs:positive(b.maxFutureSkewMs,60000),maxBundleLifetimeMs:positive(b.maxBundleLifetimeMs,900000)};
 const input: VerificationInput={version:"1",canonicalEnvelope:r.canonicalEnvelope,snapshotRoot:r.snapshotRoot,snapshotId:r.snapshotId,bundleLimits,limits};
 if(Buffer.byteLength(canonicalJson(input))>limits.maxInputBytes) throw new Error("serialized input byte limit");
 parseCanonicalEnvelope(input.canonicalEnvelope,limits); return freezeTree(input);
}
async function readBoundFile(project: string, record: BundleFileRecord, maximum: number): Promise<string> {
 if(record.bytes>maximum)throw new Error("trusted file byte limit");
 const path=join(project,record.path); const handle=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try {
  const before=await handle.stat({bigint:true});
  if(!before.isFile()||before.nlink!==1n||before.size!==BigInt(record.bytes)||Number(before.mode&0o777n)!==0o600)throw new Error("invalid private file");
  const buffer=Buffer.alloc(record.bytes+1);const {bytesRead}=await handle.read(buffer,0,buffer.length,0);
  const after=await handle.stat({bigint:true}); const atPath=await lstat(path,{bigint:true});
  if(bytesRead!==record.bytes || before.dev!==after.dev || before.ino!==after.ino || before.size!==after.size || before.mtimeNs!==after.mtimeNs || before.ctimeNs!==after.ctimeNs || atPath.dev!==after.dev || atPath.ino!==after.ino)throw new Error("private file changed");
  const bytes=buffer.subarray(0,bytesRead); if(createHash("sha256").update(bytes).digest("hex")!==record.sha256)throw new Error("private file digest mismatch");
  return new TextDecoder("utf-8",{fatal:true}).decode(bytes);
 }finally{await handle.close();}
}
export async function loadTrustedVerificationContext(raw: VerificationInput): Promise<TrustedVerificationContext> {
 const input=parseVerificationInput(raw);const envelope=parseCanonicalEnvelope(input.canonicalEnvelope,input.limits);
 const snapshot=await openPrivateBundleSnapshot({snapshotRoot:input.snapshotRoot,snapshotId:input.snapshotId,limits:input.bundleLimits});
 const files=new Map(snapshot.files.map(f=>[f.path,f]));
 const required=(path:string):BundleFileRecord=>{const file=files.get(path);if(!file)throw new Error("trusted file missing");return file;};
 const trustedPolicy=parsePolicy(await readBoundFile(snapshot.projectRoot,required(snapshot.policyPath),input.limits.maxPolicyBytes));
 const configText=await readBoundFile(snapshot.projectRoot,required(snapshot.trustedConfigPath),input.limits.maxConfigBytes);
 const configValue:unknown=JSON.parse(configText);validateVerificationJsonTree(configValue,input.limits.maxItems);
 if(canonicalJson(configValue)!==configText)throw new Error("noncanonical trusted config");
 const config=closedRecord(configValue,["allowedRoots","decisionRegistryPath","maxSourceBytes","maxTotalSourceBytes"]);
 if(!Array.isArray(config.allowedRoots)||config.allowedRoots.length===0||config.allowedRoots.length>input.bundleLimits.maxAllowedSourceRoots)throw new Error("invalid trusted roots");
 const allowedRoots=config.allowedRoots.map(r=>assertProjectRelativePath(r,input.bundleLimits.maxPathBytes));
 if(new Set(allowedRoots).size!==allowedRoots.length)throw new Error("duplicate trusted roots");
 const decisionRegistryPath=assertProjectRelativePath(config.decisionRegistryPath,input.bundleLimits.maxPathBytes);
 for(const roots of [allowedRoots,trustedPolicy.sources.allowedRoots,envelope.policy.sources.allowedRoots]) {
  roots.forEach(r=>assertProjectRelativePath(r,input.bundleLimits.maxPathBytes));
  if(canonicalJson([...roots].sort(compareUtf8))!==canonicalJson(snapshot.allowedSourceRoots))throw new Error("trusted roots binding mismatch");
 }
 if(decisionRegistryPath!==snapshot.decisionRegistryPath || trustedPolicy.decisions.path!==decisionRegistryPath || envelope.policy.decisions.path!==decisionRegistryPath || sha256Canonical(trustedPolicy)!==sha256Canonical(envelope.policy))throw new Error("trusted policy/decision binding mismatch");
 const maxSourceBytes=positive(config.maxSourceBytes,input.limits.maxSourceBytes);const maxTotalSourceBytes=positive(config.maxTotalSourceBytes,input.limits.maxTotalSourceBytes);
 let total=0;for(const source of envelope.sources) {const path=assertProjectRelativePath(source.path,input.bundleLimits.maxPathBytes);const file=required(path);if(file.bytes!==source.size || file.sha256!==source.sha256 || allowedRoots.filter(r=>isWithinProjectRoot(path,r)).length!==1)throw new Error("source manifest binding mismatch");total+=source.size;if(source.size>maxSourceBytes||total>maxTotalSourceBytes)throw new Error("source byte limit");}
 const decision=required(decisionRegistryPath);if(decision.sha256!==envelope.decisionRegistryDigest)throw new Error("decision digest binding mismatch");
 const registry=parseDecisionRegistry(await readBoundFile(snapshot.projectRoot,decision,1048576));if(registry.events.length>input.limits.maxItems)throw new Error("decision item limit");
 return freezeTree({projectRoot:snapshot.projectRoot,allowedRoots,decisionRegistryPath,trustedPolicy,maxSourceBytes,maxTotalSourceBytes});
}
