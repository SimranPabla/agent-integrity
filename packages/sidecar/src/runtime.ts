import type { Stats } from "node:fs";
import { createHash } from "node:crypto";
import { lstat, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { canonicalJson, FileReceiptStore, ReceiptOutputBoundary } from "@agent-integrity/core";
import { SidecarConfigManager, type SidecarConfigManagerOptions } from "./config.js";
import { StateCoordinator } from "./state-coordinator.js";
import { MutationScheduler } from "./scheduler.js";
import { PrivateObjectStore } from "./private-object-store.js";
import { RequestStore } from "./request-store.js";
import { FileNonceStore } from "./nonce-store.js";
import { VerifyReleaseService, type VerifyReleaseServiceOptions } from "./service.js";
import { Readiness } from "./readiness.js";
import { HealthModel } from "./health.js";
import { SidecarServer } from "./server.js";
import { SocketBoundary } from "./socket-boundary.js";
import { DurableJsonDirectory } from "./durable-json.js";
import { parseRequestState } from "./request-state.js";
import { parseCanonicalServiceRequest, serviceRequestDigest } from "./protocol.js";
import { recoverServiceTransaction } from "./recovery.js";
const sha=(value:Uint8Array|string)=>createHash("sha256").update(value).digest("hex");
export const COORDINATOR_LAYOUT=Object.freeze({nestedLockNames:Object.freeze(["receipts"]),nestedLockPaths:Object.freeze({receipts:"receipts/.store-lock.json"})});
export interface RuntimeOptions {readonly configOptions?:SidecarConfigManagerOptions;readonly coordinator?:StateCoordinator;}
export async function createRuntime(configPath:string,options:RuntimeOptions={}) {
 const configOptions=options.configOptions??{now:()=>new Date()},manager=new SidecarConfigManager(configPath,configOptions),config=await manager.loadInitial();
 const root=config.paths.stateRoot,out=join(root,config.stateChildren.transactions,"receipt-output");
 const coordinator=options.coordinator??await StateCoordinator.acquire(root,{storeGeneration:config.storeGeneration,...COORDINATOR_LAYOUT});
 let server:SidecarServer|undefined;
 try {
 // The root lease must be acquired before any output-directory mutation.
 const outputBoundary=await coordinator.withMutation(async()=>{
  try{await mkdir(out,{mode:0o700});}catch(error){if(!(error instanceof Error&&(error as NodeJS.ErrnoException).code==="EEXIST"))throw error;}
  return ReceiptOutputBoundary.open(out);
 });
 const scheduler=new MutationScheduler(coordinator,{maximumQueued:8,queueTimeoutMs:5000});
 const objects=new PrivateObjectStore(join(root,config.stateChildren.transactions,"private-objects"));
 const requests=new RequestStore(join(root,config.stateChildren.requests),objects);
 const nonces=new FileNonceStore(join(root,config.stateChildren.nonces),{maximumSkewMs:config.limits.maximumTimestampSkewMs});
 const boundary=await SocketBoundary.open(config.paths.socketPath,{sidecarUid:config.identities.sidecarUid,clientGid:config.identities.clientGid,...(configOptions.stat?{stat:async(path:string)=>{const s=await configOptions.stat!(path);return s as Stats;}}:{}),...(configOptions.resolve?{resolve:configOptions.resolve}:{})});
 const readiness=new Readiness(["CONFIGURATION","KEYS","ROOT_LEASE","CAPACITY","BUNDLE_ROOT","SNAPSHOT_ROOT","SOCKET"]);
 const receiptStore:VerifyReleaseServiceOptions["receiptStore"]=capability=>new FileReceiptStore(join(root,config.stateChildren.receipts),{lockOwnership:coordinator.receiptStoreLockOwnership(capability)});
 const serviceOptions:VerifyReleaseServiceOptions={requestStore:requests,scheduler,receiptStore,clientId:config.client.clientId,authRegistry:manager.hmacRegistry(),nonceStore:nonces,readiness,outputBoundary,outputName:"service-receipt",storeGeneration:config.storeGeneration,audience:config.receipt.audience,purpose:config.receipt.purpose,engineVersion:config.receipt.engineVersion,maximumReceiptLifetimeMs:config.receipt.maximumReceiptLifetimeSeconds*1000,deliveryWindowMs:config.receipt.maximumReceiptLifetimeSeconds*1000,now:configOptions.now,maximumAuthSkewMs:config.limits.maximumTimestampSkewMs,durable:{objects,incomingRoot:config.paths.bundleRoot,snapshotRoot:join(root,config.stateChildren.snapshots),keyRegistry:()=>manager.keyRegistry(),issuer:config.receipt.issuer,maximumRequestBytes:config.limits.maximumRequestBytes,verificationTimeoutMs:5000,bundleLimits:{maxManifestBytes:1048576,maxAllowedSourceRoots:64,maxFiles:10000,maxPathBytes:1024,maxFileBytes:config.limits.maximumSourceBytes,maxTotalBytes:config.limits.maximumTotalSourceBytes,maxFutureSkewMs:config.limits.maximumTimestampSkewMs,maxBundleLifetimeMs:config.limits.maximumBundleLifetimeMs},verificationLimits:{maxInputBytes:Math.min(32*1024*1024,config.limits.maximumEnvelopeBytes+1048576),maxOutputBytes:Math.min(32*1024*1024,config.limits.maximumResponseBytes+1048576),maxPolicyBytes:1048576,maxConfigBytes:1048576,maxSourceBytes:config.limits.maximumSourceBytes,maxTotalSourceBytes:config.limits.maximumTotalSourceBytes,maxItems:10000,maxFindings:config.limits.maximumFindings,maxFindingBytes:65536}}};
 const service=new VerifyReleaseService(serviceOptions);
 // Initialization is explicit startup work under root authority, never a probe.
 await coordinator.withMutation(async c=>{await receiptStore(c).inspectCapacity();await requests.inspectCapacity();});
 const observationStore=new FileReceiptStore(join(root,config.stateChildren.receipts));
 const configurationIdentity=(m:SidecarConfigManager)=>{const {loadedAt:_,...snapshot}=m.current();return sha(canonicalJson({snapshot,hmac:Object.fromEntries(Object.entries(m.hmacRegistry().clients).map(([id,c])=>[id,Object.fromEntries(Object.entries(c.keys).map(([kid,k])=>[kid,{...k,secret:sha(k.secret)}]))]))}));};
 const originalConfig=configurationIdentity(manager);
 let authority:Promise<{lease:boolean;capacity:boolean}>|undefined;
 const inspectAuthority=()=>authority??=(async()=>{
  try{await coordinator.inspectLease();}catch{return {lease:false,capacity:false};}
  let capacity=false;
  try{const checks=await Promise.allSettled([observationStore.observeCapacity(),requests.inspectCapacity()]);if(checks[0].status==="fulfilled"&&checks[1].status==="fulfilled"){const r=checks[0].value,p=checks[1].value;capacity=r.used<r.maximum-1&&p.used<p.maximum-1;}}catch{/* observation only */}
  try{await coordinator.inspectLease();return {lease:true,capacity};}catch{return {lease:false,capacity:false};}
 })().finally(()=>{authority=undefined;});
 const directory=async(path:string,mode:number,uid:number,gid:number)=>{const info=await(configOptions.stat??lstat)(path);return info.isDirectory()&&!info.isSymbolicLink()&&(info.mode&0o7777)===mode&&info.uid===uid&&info.gid===gid&&await(configOptions.resolve??(await import("node:fs/promises")).realpath)(path)===path;};
 const health=new HealthModel(readiness,{
 CONFIGURATION:async()=>{const fresh=new SidecarConfigManager(configPath,configOptions);await fresh.loadInitial();return configurationIdentity(fresh)===originalConfig;},
 KEYS:async()=>{const now=configOptions.now();manager.selectSigningKey(now);return Object.values(manager.hmacRegistry().clients).some(c=>Object.values(c.keys).some(k=>now.getTime()>=k.validFromMs&&now.getTime()<k.validUntilMs&&(k.revokedAtMs===undefined||now.getTime()<k.revokedAtMs)));},
 ROOT_LEASE:async()=>(await inspectAuthority()).lease,CAPACITY:async()=>(await inspectAuthority()).capacity,
 BUNDLE_ROOT:()=>directory(config.paths.bundleRoot,0o750,config.identities.cageUid,config.identities.clientGid),SNAPSHOT_ROOT:()=>directory(join(root,config.stateChildren.snapshots),0o700,config.identities.sidecarUid,config.identities.sidecarGid),
 SOCKET:async()=>{await boundary.validateBound();return true;},
 });
 server=new SidecarServer({boundary,service,health,stopAdmission:()=>scheduler.close(),limits:{maximumRequestBytes:config.limits.maximumRequestBytes,maximumEnvelopeBytes:config.limits.maximumEnvelopeBytes,maximumResponseBytes:Math.min(32*1024*1024,config.limits.maximumResponseBytes*2+2*1048576),maximumReleasedResponseBytes:config.limits.maximumResponseBytes,maximumHeaderBytes:8192,maximumHeaderCount:64,maximumEnvelopeItems:10000,maximumFindings:config.limits.maximumFindings,readTimeoutMs:10000,maximumConnections:16,gracefulShutdownMs:config.limits.gracefulShutdownMs}});
 const instance=server;
 return {config,manager,coordinator,scheduler,requests,objects,service,serviceOptions,boundary,health,server:instance,
 async start(){await instance.listen();const ready=await health.ready();if(!ready.ready){await instance.shutdown();throw Error("SERVICE_UNAVAILABLE");}},
 async shutdown(){const safe=await instance.shutdown();if(!safe)return false;try{await coordinator.close();return true;}catch{return false;}},
 async recoverAll(){return coordinator.withMutation(async capability=>{await requests.resumeExpiredCompactions(capability,configOptions.now());const records=new DurableJsonDirectory(join(root,config.stateChildren.requests),{maxStateBytes:1048576,maxEntries:80016});await records.initialize(["bindings","phases","tombstones"]);const ids=new Set<string>();for(const name of await records.entries("phases")){if(!/^[a-f0-9]{64}-(reserved|verified|receipt-prepared|receipt-issued|pass-consumed|release-refused|result-committed)\.json$/u.test(name))throw Error("RECOVERY_REQUIRED");const state=parseRequestState(await records.read("phases/"+name));if(state.phase==="tombstone")throw Error("RECOVERY_REQUIRED");ids.add(state.requestObjectId);}
 const capacity=await requests.inspectCapacity();if(ids.size>10000||capacity.orphanObjects!==0||capacity.used>(await records.entries("tombstones")).length+ids.size)throw Error("RECOVERY_REQUIRED");let completed=0;
 for(const id of ids){const raw=await objects.readCanonicalRequest(id);const request=parseCanonicalServiceRequest(raw,config.limits.maximumRequestBytes);if(serviceRequestDigest(request)!==id)throw Error("RECOVERY_REQUIRED");const state=await requests.lookup(config.client.clientId,config.storeGeneration,request.idempotencyKey,id);if(!state)throw Error("RECOVERY_REQUIRED");if(state.phase!=="tombstone"&&state.phase!=="result-committed"){await recoverServiceTransaction(serviceOptions,serviceOptions.durable,capability,state,configOptions.now);completed++;}}
 return completed;});},};
 }catch(error){if(server)await server.shutdown();try{await coordinator.close();}catch{/* preserve unsafe authority */}throw error;}
}
