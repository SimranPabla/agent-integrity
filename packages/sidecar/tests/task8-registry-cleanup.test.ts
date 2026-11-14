import { allowDiskIntegrationTime } from "./support/disk-integration-timeout.js";
allowDiskIntegrationTime();
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm, readdir, readFile, writeFile, chmod, unlink, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildReceipt, canonicalJson } from "@agent-integrity/core";
import { PrivateObjectStore } from "../src/private-object-store.js";
import { RequestStore } from "../src/request-store.js";
import { StateCoordinator, type MutationCapability } from "../src/state-coordinator.js";
import type { ActiveRequestState, ResultCommittedState } from "../src/request-state.js";
import { cleanupServiceFixtures, serviceFixture } from "./support/task8-service-fixture.js";
afterEach(cleanupServiceFixtures);
const sha=(v:string|Uint8Array)=>createHash("sha256").update(v).digest("hex");
const roots:string[]=[];
const drains=new Map<string,()=>Promise<void>>();
afterEach(async()=>{for(const root of roots.splice(0)){await drains.get(root)?.();await rm(root,{recursive:true,force:true});drains.delete(root);}});
const pair=generateKeyPairSync("ed25519");
const start="2030-01-01T00:00:00.000Z", deadline="2030-01-01T00:01:00.000Z";
async function fixture(maxObjects=8){const root=await mkdtemp(join(tmpdir(),"task8-registry-cleanup-"));roots.push(root);const coordinator=await StateCoordinator.acquire(join(root,"state"),{storeGeneration:"g1",nestedLockNames:[]});const pending=new Set<Promise<unknown>>();const mutate=coordinator.withMutation.bind(coordinator);coordinator.withMutation=async <T>(operation:(c:MutationCapability)=>T|Promise<T>):Promise<T>=>{const running=mutate(operation);pending.add(running);try{return await running;}finally{pending.delete(running);}};drains.set(root,async()=>{while(pending.size)await Promise.allSettled([...pending]);});let fault:((point:string)=>void|Promise<void>)|undefined;const options={faultInjector:(p:string)=>fault?.(p)};const objects=new PrivateObjectStore(join(root,"objects"),{...options,maxObjects});const requests=new RequestStore(join(root,"requests"),objects,options);return {root,objects,requests,coordinator,setFault:(f:typeof fault)=>{fault=f;}};}
type Fixture=Awaited<ReturnType<typeof fixture>>;
async function prepare(h:Fixture,c:MutationCapability,n:number,registry="registry-a", status:"PASS"|"REVIEW"="REVIEW",scope={clientId:"cage",storeGeneration:"g1"}){
 const bytes=Buffer.from(canonicalJson({requestId:"r"+n}));
 const reserved=await h.requests.reserve(c,{...scope,idempotencyKey:"i"+n,requestId:"r"+n,transactionId:"t"+n,requestDigest:sha(bytes),canonicalRequest:bytes});
 const verification={protocolVersion:"1-alpha" as const,status,findings:[]};
 const verified=await h.requests.advance(c,reserved,{phase:"verified",snapshotId:sha("snapshot"),envelopeDigest:sha("envelope"),verificationDigest:sha(canonicalJson(verification)),verification});
 await h.objects.publishTrustRegistry(Buffer.from(registry),sha(registry));
 return h.requests.advance(c,verified,{phase:"receipt-prepared",issuer:"issuer",signingTime:start,trustSnapshotObjectId:sha(registry),trustSnapshotDigest:sha(registry),keyId:"key",publicKeyDigest:sha("key"),runId:"run"+n,receiptNonce:"nonce"+n,createdAt:start,expiresAt:"2030-01-01T01:00:00.000Z",audience:"cage",purpose:"response-release",engineVersion:"0.1",maxLifetimeMs:3600000,receiptOutputName:"r"+n+".json",receiptOutputRootIdentity:sha("output"),trustedContextDigest:sha("context")});
}
async function finish(h:Fixture,c:MutationCapability,prepared:ActiveRequestState,n:number,deliveryDeadline=deadline):Promise<ResultCommittedState>{
 if(prepared.phase!=="receipt-prepared")throw new Error("fixture prepared missing");
 const signed=buildReceipt({runId:prepared.runId,envelope:{policy:{}} as never,verification:{...prepared.verification,envelopeDigest:prepared.envelopeDigest},createdAt:new Date(start),expiresAt:new Date(prepared.expiresAt),signer:{keyId:"key",issuer:"issuer",privateKey:pair.privateKey.export({type:"pkcs8",format:"pem"}).toString()},audience:"cage",purpose:"response-release",nonce:prepared.receiptNonce,engineVersion:"0.1"});
 const issued=await h.requests.advance(c,prepared,{phase:"receipt-issued",receiptDigest:signed.receiptDigest,receipt:signed});
 return await h.requests.advance(c,issued,{phase:"result-committed",outcome:"REVIEW",receiptExpiresAt:signed.expiresAt,deliveryDeadline,responseBytesRetained:true,response:{serviceProtocolVersion:"1",requestId:"r"+n,status:"REVIEW",verification:prepared.verification,receipt:signed}}) as ResultCommittedState;
}
describe("Task8 reference-aware registry cleanup",()=>{
 it("removes only the expired transaction's unreferenced registry and frees object capacity",async()=>{const h=await fixture();await h.coordinator.withMutation(async c=>{const terminal=await finish(h,c,await prepare(h,c,1),1);expect((await h.objects.inspectCapacity()).used).toBe(2);await expect(h.requests.compactExpired(c,terminal,new Date(start))).rejects.toThrow(/deadline/);await h.requests.compactExpired(c,terminal,new Date(deadline));expect((await h.objects.inspectCapacity()).used).toBe(0);expect((await h.requests.inspectCapacity()).used).toBe(1);await expect(h.objects.readTrustRegistry(sha("registry-a"))).rejects.toMatchObject({code:"ENOENT"});});await h.coordinator.close();});
 it("preserves shared registry with prepared and unexpired transactions through rotation",async()=>{const h=await fixture();await h.coordinator.withMutation(async c=>{const a=await finish(h,c,await prepare(h,c,1),1);const b=await prepare(h,c,2);await h.requests.compactExpired(c,a,new Date(deadline));expect(await h.objects.readTrustRegistry(sha("registry-a"))).toEqual(Buffer.from("registry-a"));const rotated=await finish(h,c,await prepare(h,c,3,"registry-b"),3);await h.requests.compactExpired(c,rotated,new Date(deadline));expect(await h.objects.readTrustRegistry(sha("registry-a"))).toEqual(Buffer.from("registry-a"));await expect(h.objects.readTrustRegistry(sha("registry-b"))).rejects.toMatchObject({code:"ENOENT"});const last=await finish(h,c,b,2);await h.requests.compactExpired(c,last,new Date(deadline));expect((await h.objects.inspectCapacity()).used).toBe(0);});await h.coordinator.close();});
});

describe("Task8 compaction crash prefixes",()=>{
 it.each(["cleanup:after-tombstone","cleanup:after-phases","cleanup:after-binding","cleanup:after-request","cleanup:after-registry"])("resumes %s from a fresh store and tombstone-only lookup",async(point)=>{
  const h=await fixture();await h.coordinator.withMutation(async c=>{
   const terminal=await finish(h,c,await prepare(h,c,1),1);
   h.setFault(p=>{if(p===point)throw new Error("injected "+point);});
   await expect(h.requests.compactExpired(c,terminal,new Date(deadline))).rejects.toThrow("injected "+point);
   expect((await h.requests.lookup("cage","g1","i1",terminal.requestDigest))?.phase).toBe("tombstone");
   expect((await h.requests.inspectCapacity()).used).toBe(1);
   h.setFault(undefined);
   const reopened=new RequestStore(join(h.root,"requests"),new PrivateObjectStore(join(h.root,"objects")));
   await reopened.resumeExpiredCompactions(c,new Date(deadline));
   expect((await h.objects.inspectCapacity()).used).toBe(0);
   expect((await reopened.inspectCapacity()).used).toBe(1);
   expect((await readdir(join(h.root,"requests"))).filter(n=>n.startsWith("cleanup-"))).toEqual([]);
   expect((await reopened.lookup("cage","g1","i1",terminal.requestDigest))?.phase).toBe("tombstone");
   await reopened.resumeExpiredCompactions(c,new Date(deadline));
  });await h.coordinator.close();
 });
 it("fails closed before deletion on unrelated orphan journal",async()=>{
  const h=await fixture();await h.coordinator.withMutation(async c=>{
   const terminal=await finish(h,c,await prepare(h,c,1),1);
   const phases=join(h.root,"requests","phases"),names=await readdir(phases);
   const name=names.find(n=>n.endsWith("-reserved.json"))!;
   await writeFile(join(phases,sha("orphan")+"-reserved.json"),await readFile(join(phases,name)),{mode:0o600});
   await expect(h.requests.compactExpired(c,terminal,new Date(deadline))).rejects.toThrow(/orphan/);
   expect((await h.objects.inspectCapacity()).used).toBe(2);
   expect(await readdir(join(h.root,"requests","tombstones"))).toEqual([]);
  });await h.coordinator.close();
 });
 it("fails closed on changed digest-bound cleanup intent before any retry deletion",async()=>{
  const h=await fixture();await h.coordinator.withMutation(async c=>{
   const terminal=await finish(h,c,await prepare(h,c,1),1);
   h.setFault(p=>{if(p==="cleanup:after-binding")throw new Error("prefix");});
   await expect(h.requests.compactExpired(c,terminal,new Date(deadline))).rejects.toThrow("prefix");h.setFault(undefined);
   const name=(await readdir(join(h.root,"requests"))).find(n=>n.startsWith("cleanup-"))!;
   const path=join(h.root,"requests",name),record=JSON.parse(await readFile(path,"utf8"));record.states[2].trustSnapshotObjectId=sha("fabricated");
   await writeFile(path,JSON.stringify(record));
   await expect(h.requests.resumeExpiredCompactions(c,new Date(deadline))).rejects.toThrow(/digest|schema/);
   expect((await h.objects.inspectCapacity()).used).toBe(2);
  });await h.coordinator.close();
 });
});

describe("Task8 additional reference and durable removal cases",()=>{
 it("protects a shared unexpired committed result and permanent tombstones",async()=>{
  const h=await fixture();await h.coordinator.withMutation(async c=>{
   const first=await finish(h,c,await prepare(h,c,1),1),later="2030-01-01T00:30:00.000Z";
   const second=await finish(h,c,await prepare(h,c,2),2,later);
   await h.requests.compactExpired(c,first,new Date(deadline));
   expect(await h.objects.readTrustRegistry(sha("registry-a"))).toEqual(Buffer.from("registry-a"));
   await expect(h.requests.compactExpired(c,second,new Date(deadline))).rejects.toThrow(/deadline/);
   await h.requests.compactExpired(c,second,new Date(later));
   expect((await h.objects.inspectCapacity()).used).toBe(0);expect((await h.requests.inspectCapacity()).used).toBe(2);
  });await h.coordinator.close();
 });
 it.each(["receipt-prepared","receipt-issued","pass-consumed","release-refused"])("preserves registry referenced by actual %s journal",async(phase)=>{
  const h=await fixture();await h.coordinator.withMutation(async c=>{
   const first=await finish(h,c,await prepare(h,c,1),1);
   let live=await prepare(h,c,2,"registry-a","PASS");if(live.phase!=="receipt-prepared")throw new Error("fixture");
   if(phase!=="receipt-prepared"){
    const signed=buildReceipt({runId:live.runId,envelope:{policy:{}} as never,verification:{...live.verification,envelopeDigest:live.envelopeDigest},createdAt:new Date(start),expiresAt:new Date(live.expiresAt),signer:{keyId:"key",issuer:"issuer",privateKey:pair.privateKey.export({type:"pkcs8",format:"pem"}).toString()},audience:"cage",purpose:"response-release",nonce:live.receiptNonce,engineVersion:"0.1"});
    live=await h.requests.advance(c,live,{phase:"receipt-issued",receiptDigest:signed.receiptDigest,receipt:signed});
    if(phase==="pass-consumed")live=await h.requests.advance(c,live,{phase,consumedMarkerDigest:sha("consumed"),consumedAt:"2030-01-01T00:00:01.000Z"});
    if(phase==="release-refused")live=await h.requests.advance(c,live,{phase,closedMarkerDigest:sha("closed"),response:{serviceProtocolVersion:"1",requestId:"r2",status:"RELEASE_REFUSED",verification:signed.verification,receipt:signed,release:{status:"BLOCKED",code:"RECEIPT_RECHECK_REFUSED",retryable:false}}});
   }
   await h.requests.compactExpired(c,first,new Date(deadline));
   expect(await h.objects.readTrustRegistry(sha("registry-a"))).toEqual(Buffer.from("registry-a"));
   expect((await h.requests.lookup("cage","g1","i2",live.requestDigest))?.phase).toBe(phase);
  });await h.coordinator.close();
 });
 it.each(["request","registry","tombstone"])("retries actual %s deletion/publication directory-sync failure",async(boundary)=>{
  const h=await fixture();await h.coordinator.withMutation(async c=>{
   const terminal=await finish(h,c,await prepare(h,c,1),1);let fired=false;
   h.setFault(async p=>{if(p!=="directory:before-sync"||fired)return;
    const requests=await readdir(join(h.root,"objects","requests")),registries=await readdir(join(h.root,"objects","registries")),tombstones=await readdir(join(h.root,"requests","tombstones"));
    if(boundary==="request"&&requests.length===0&&registries.length===1 || boundary==="registry"&&registries.length===0 || boundary==="tombstone"&&tombstones.length===1){fired=true;throw new Error("actual directory sync failure");}
   });
   await expect(h.requests.compactExpired(c,terminal,new Date(deadline))).rejects.toThrow("actual directory sync failure");expect(fired).toBe(true);h.setFault(undefined);
   const reopened=new RequestStore(join(h.root,"requests"),new PrivateObjectStore(join(h.root,"objects")));
   await reopened.resumeExpiredCompactions(c,new Date(deadline));expect((await h.objects.inspectCapacity()).used).toBe(0);
  });await h.coordinator.close();
 });
});

describe("Task8 fail-closed cleanup object guards",()=>{
 it.each(["mode","symlink"])("refuses a %s object without deleting journals or objects",async(kind)=>{
  const h=await fixture();await h.coordinator.withMutation(async c=>{
   const terminal=await finish(h,c,await prepare(h,c,1),1),path=join(h.root,"objects","registries",sha("registry-a")+".json");
   if(kind==="mode")await chmod(path,0o644);else{await unlink(path);await symlink(join(h.root,"objects","requests",terminal.requestObjectId+".json"),path);}
   await expect(h.requests.compactExpired(c,terminal,new Date(deadline))).rejects.toThrow(/mode|symlink|regular|private object/);
   expect(await readdir(join(h.root,"requests","tombstones"))).toEqual([]);expect(await readdir(join(h.root,"requests","bindings"))).toHaveLength(1);
   expect(await readdir(join(h.root,"objects","requests"))).toHaveLength(1);
  });await h.coordinator.close();
 });
 it("fails closed if another prepared transaction's referenced registry is missing",async()=>{
  const h=await fixture();await h.coordinator.withMutation(async c=>{
   const terminal=await finish(h,c,await prepare(h,c,1),1);await prepare(h,c,2,"registry-b");
   await unlink(join(h.root,"objects","registries",sha("registry-b")+".json"));
   await expect(h.requests.compactExpired(c,terminal,new Date(deadline))).rejects.toMatchObject({code:"ENOENT"});
   expect(await readdir(join(h.root,"requests","tombstones"))).toEqual([]);
   expect(await h.objects.readTrustRegistry(sha("registry-a"))).toEqual(Buffer.from("registry-a"));
  });await h.coordinator.close();
 });
 it("refuses registry deletion with forged or retired mutation capability",async()=>{
  const h=await fixture();let stale:MutationCapability|undefined;
  await h.coordinator.withMutation(async c=>{stale=c;await h.objects.publishTrustRegistry(Buffer.from("registry-a"),sha("registry-a"));});
  await expect(h.objects.removeTrustRegistry({} as never,sha("registry-a"))).rejects.toThrow(/capability/);
  await expect(h.objects.removeTrustRegistry(stale!,sha("registry-a"))).rejects.toThrow(/capability/);
  expect(await h.objects.readTrustRegistry(sha("registry-a"))).toEqual(Buffer.from("registry-a"));await h.coordinator.close();
 });
 it("reclaims exhausted combined request/registry capacity without resetting permanent identity",async()=>{
  const h=await fixture(2);await h.coordinator.withMutation(async c=>{
   const first=await finish(h,c,await prepare(h,c,1),1);
   await expect(h.objects.publishTrustRegistry(Buffer.from("registry-b"),sha("registry-b"))).rejects.toThrow(/capacity/);
   await h.requests.compactExpired(c,first,new Date(deadline));
   const second=await finish(h,c,await prepare(h,c,2,"registry-b"),2);expect((await h.objects.inspectCapacity()).used).toBe(2);
   await h.requests.compactExpired(c,second,new Date(deadline));expect((await h.objects.inspectCapacity()).used).toBe(0);
   expect((await h.requests.inspectCapacity()).used).toBe(2);
   await expect(h.requests.reserve(c,{clientId:"cage",storeGeneration:"g1",idempotencyKey:"i1",requestId:"r1",transactionId:"t1",requestDigest:first.requestDigest,canonicalRequest:Buffer.from(canonicalJson({requestId:"r1"}))})).rejects.toThrow(/tombstone|expired/);
  });await h.coordinator.close();
 });
});

it("retries an actual registry remove failure without losing cleanup identity",async()=>{
 const h=await fixture();await h.coordinator.withMutation(async c=>{
  const terminal=await finish(h,c,await prepare(h,c,1),1);
  h.setFault(p=>{if(p==="object:before-registry-remove")throw new Error("registry remove failed");});
  await expect(h.requests.compactExpired(c,terminal,new Date(deadline))).rejects.toThrow("registry remove failed");h.setFault(undefined);
  expect(await h.objects.readTrustRegistry(sha("registry-a"))).toEqual(Buffer.from("registry-a"));
  const reopened=new RequestStore(join(h.root,"requests"),new PrivateObjectStore(join(h.root,"objects")));
  await reopened.resumeExpiredCompactions(c,new Date(deadline));expect((await h.objects.inspectCapacity()).used).toBe(0);
 });await h.coordinator.close();
});

it("real active service recovery resumes interrupted expired cleanup while tombstone retries remain lookup-only",async()=>{
 const f=await serviceFixture();let fault:((p:string)=>void)|undefined;
 const h:Fixture={root:f.stateRoot,coordinator:f.coordinator,objects:f.objects,requests:new RequestStore(join(f.stateRoot,"requests"),f.objects,{faultInjector:p=>fault?.(p)}),setFault:value=>{fault=value as typeof fault;}};
 await f.trackOperation(()=>f.coordinator.withMutation(async c=>{
  const old=await finish(h,c,await prepare(h,c,99,"registry-old","REVIEW",{clientId:f.options.clientId,storeGeneration:f.options.storeGeneration}),99);
  fault=p=>{if(p==="cleanup:after-binding")throw new Error("interrupted cleanup");};
  await expect(h.requests.compactExpired(c,old,f.options.now!())).rejects.toThrow("interrupted cleanup");fault=undefined;
 }));
 expect((await readdir(join(f.stateRoot,"requests"))).filter(n=>n.startsWith("cleanup-"))).toHaveLength(1);
 const result=await f.newService().process(f.requestBytes,f.authHeaders());expect(result.status).toBe("PASS");
 expect((await readdir(join(f.stateRoot,"requests"))).filter(n=>n.startsWith("cleanup-"))).toEqual([]);
 await expect(f.objects.readTrustRegistry(sha("registry-old"))).rejects.toMatchObject({code:"ENOENT"});
 expect(await f.newService().process(f.requestBytes,f.authHeaders())).toEqual(result);
 await f.coordinator.close();
});

// Read every surviving journal, binding, intent, tombstone and object byte.
async function cleanupBytes(h:Fixture){
 const result:Record<string,string>={};
 for(const directory of ["requests","requests/phases","requests/bindings","requests/tombstones","objects/requests","objects/registries"]){
  for(const name of (await readdir(join(h.root,directory),{withFileTypes:true})).sort((a,b)=>a.name.localeCompare(b.name)))if(name.isFile())result[directory+"/"+name.name]=(await readFile(join(h.root,directory,name.name))).toString("base64");
 }
 return result;
}
async function interruptTombstone(h:Fixture,c:MutationCapability,n:number){
 const terminal=await finish(h,c,await prepare(h,c,n),n);
 h.setFault(p=>{if(p==="cleanup:after-tombstone")throw new Error("real tombstone prefix");});
 await expect(h.requests.compactExpired(c,terminal,new Date(deadline))).rejects.toThrow("real tombstone prefix");h.setFault(undefined);
 const key=sha(canonicalJson(["cage","g1","i"+n]));
 expect(await readdir(join(h.root,"requests","phases"))).toContain(key+"-receipt-prepared.json");
 expect(await readdir(join(h.root,"requests","bindings"))).toContain(key+".json");
 expect(await readdir(join(h.root,"requests","tombstones"))).toContain(key+".json");
 return {terminal,key};
}
describe("Task8 cleanup consistency N1/N2 negative controls",()=>{
 it.each(["interior-only","binding-first","no-tombstone-interior"])("N1 rejects actual %s corruption preserving all survivors",async(kind)=>{
  const h=await fixture();await h.coordinator.withMutation(async c=>{
   const {key}=await interruptTombstone(h,c,1);
   if(kind==="binding-first")await unlink(join(h.root,"requests","bindings",key+".json"));
   else await unlink(join(h.root,"requests","phases",key+"-receipt-prepared.json"));
   if(kind==="no-tombstone-interior")await unlink(join(h.root,"requests","tombstones",key+".json"));
   const before=await cleanupBytes(h);
   await expect(h.requests.resumeExpiredCompactions(c,new Date(deadline))).rejects.toThrow(/cleanup.*prefix|cleanup.*journal/);
   expect(await cleanupBytes(h)).toEqual(before);
  });await h.coordinator.close();
 });
 it("N1 rejects unrelated pending non-prefix before selected target gets a tombstone",async()=>{
  const h=await fixture();await h.coordinator.withMutation(async c=>{
   const target=await finish(h,c,await prepare(h,c,1),1);
   const {key}=await interruptTombstone(h,c,2);
   await unlink(join(h.root,"requests","phases",key+"-receipt-prepared.json"));
   const before=await cleanupBytes(h);
   await expect(h.requests.compactExpired(c,target,new Date(deadline))).rejects.toThrow(/cleanup.*prefix|cleanup.*journal/);
   expect(await cleanupBytes(h)).toEqual(before);
   expect(await readdir(join(h.root,"requests","tombstones"))).toEqual([key+".json"]);
  });await h.coordinator.close();
 });
 it("N2 rejects unrelated valid zero-phase binding before target tombstone or deletion",async()=>{
  const h=await fixture();await h.coordinator.withMutation(async c=>{
   const target=await finish(h,c,await prepare(h,c,1),1);
   const bytes=Buffer.from(canonicalJson({requestId:"r2"}));
   await h.requests.reserve(c,{clientId:"cage",storeGeneration:"g1",idempotencyKey:"i2",requestId:"r2",transactionId:"t2",requestDigest:sha(bytes),canonicalRequest:bytes});
   const key=sha(canonicalJson(["cage","g1","i2"]));
   await unlink(join(h.root,"requests","phases",key+"-reserved.json"));
   await expect(h.requests.lookup("cage","g1","i2",sha(bytes))).rejects.toThrow(/ambiguous/);
   const before=await cleanupBytes(h);
   await expect(h.requests.compactExpired(c,target,new Date(deadline))).rejects.toThrow(/ambiguous/);
   expect(await cleanupBytes(h)).toEqual(before);
   expect(await readdir(join(h.root,"requests","tombstones"))).toEqual([]);
  });await h.coordinator.close();
 });
});

describe("Task8 exact lexical deletion prefixes",()=>{
 it.each([0,1,2,3,4,5])("resumes actual phase-remove directory-sync failure after %i deletions",async(count)=>{
  const h=await fixture();await h.coordinator.withMutation(async c=>{
   const terminal=await finish(h,c,await prepare(h,c,1),1);
   const phases=join(h.root,"requests","phases"),original=(await readdir(phases)).sort();
   expect(original.map(n=>n.slice(65))).toEqual(["receipt-issued.json","receipt-prepared.json","reserved.json","result-committed.json","verified.json"]);
   let fired=false;
   h.setFault(async p=>{
    if(fired)return;
    if(count===0&&p==="cleanup:after-tombstone" || count>0&&p==="directory:before-sync"&&(await readdir(phases)).length===5-count){fired=true;throw new Error("actual ordered prefix");}
   });
   await expect(h.requests.compactExpired(c,terminal,new Date(deadline))).rejects.toThrow("actual ordered prefix");expect(fired).toBe(true);h.setFault(undefined);
   expect((await readdir(phases)).sort()).toEqual(original.slice(count));
   expect(await readdir(join(h.root,"requests","bindings"))).toHaveLength(1);
   const tombstones=await readdir(join(h.root,"requests","tombstones"));expect(tombstones).toHaveLength(1);
   const permanent=await readFile(join(h.root,"requests","tombstones",tombstones[0]!));
   const reopened=new RequestStore(join(h.root,"requests"),new PrivateObjectStore(join(h.root,"objects")));
   await reopened.resumeExpiredCompactions(c,new Date(deadline));
   expect((await h.objects.inspectCapacity()).used).toBe(0);
   expect(await readFile(join(h.root,"requests","tombstones",tombstones[0]!))).toEqual(permanent);
   await reopened.resumeExpiredCompactions(c,new Date(deadline));
  });await h.coordinator.close();
 });
 it("requires the complete current chain when intent publication precedes first tombstone",async()=>{
  const h=await fixture();await h.coordinator.withMutation(async c=>{
   const terminal=await finish(h,c,await prepare(h,c,1),1);let fired=false;
   h.setFault(async p=>{if(!fired&&p==="directory:before-sync"&&(await readdir(join(h.root,"requests"))).some(n=>n.startsWith("cleanup-"))){fired=true;throw new Error("intent sync prefix");}});
   await expect(h.requests.compactExpired(c,terminal,new Date(deadline))).rejects.toThrow("intent sync prefix");expect(fired).toBe(true);h.setFault(undefined);
   expect(await readdir(join(h.root,"requests","tombstones"))).toEqual([]);
   expect(await readdir(join(h.root,"requests","phases"))).toHaveLength(5);
   await h.requests.resumeExpiredCompactions(c,new Date(deadline));expect((await h.objects.inspectCapacity()).used).toBe(0);
  });await h.coordinator.close();
 });
});

async function branchTerminal(h:Fixture,c:MutationCapability,branch:"pass-consumed"|"release-refused"|"technical"):Promise<ResultCommittedState>{
 if(branch==="technical"){
  const bytes=Buffer.from(canonicalJson({requestId:"r1"}));
  const reserved=await h.requests.reserve(c,{clientId:"cage",storeGeneration:"g1",idempotencyKey:"i1",requestId:"r1",transactionId:"t1",requestDigest:sha(bytes),canonicalRequest:bytes});
  return await h.requests.advance(c,reserved,{phase:"result-committed",outcome:"BLOCKED",receiptExpiresAt:deadline,deliveryDeadline:deadline,responseBytesRetained:false,response:{serviceProtocolVersion:"1",requestId:"r1",error:{code:"BUNDLE_INVALID",retryable:false}}},{allowTechnicalTerminal:true}) as ResultCommittedState;
 }
 const prepared=await prepare(h,c,1,"registry-a","PASS");if(prepared.phase!=="receipt-prepared")throw new Error("prepared fixture");
 const signed=buildReceipt({runId:prepared.runId,envelope:{policy:{}} as never,verification:{...prepared.verification,envelopeDigest:prepared.envelopeDigest},createdAt:new Date(start),expiresAt:new Date(prepared.expiresAt),signer:{keyId:"key",issuer:"issuer",privateKey:pair.privateKey.export({type:"pkcs8",format:"pem"}).toString()},audience:"cage",purpose:"response-release",nonce:prepared.receiptNonce,engineVersion:"0.1"});
 const issued=await h.requests.advance(c,prepared,{phase:"receipt-issued",receiptDigest:signed.receiptDigest,receipt:signed});
 const response=branch==="release-refused"?{serviceProtocolVersion:"1",requestId:"r1",status:"RELEASE_REFUSED",verification:signed.verification,receipt:signed,release:{status:"BLOCKED",code:"RECEIPT_RECHECK_REFUSED",retryable:false}}:{serviceProtocolVersion:"1",requestId:"r1",status:"PASS",verification:signed.verification,receipt:signed,releasedResponse:{encoding:"base64",bytes:Buffer.from("exact").toString("base64"),sha256:sha("exact")}};
 const prior=await h.requests.advance(c,issued,branch==="release-refused"?{phase:branch,closedMarkerDigest:sha("closed"),response}:{phase:branch,consumedMarkerDigest:sha("consumed"),consumedAt:"2030-01-01T00:00:01.000Z"});
 return await h.requests.advance(c,prior,{phase:"result-committed",outcome:response.status,receiptExpiresAt:signed.expiresAt,deliveryDeadline:deadline,responseBytesRetained:true,response}) as ResultCommittedState;
}
describe("Task8 all legal branch deletion suffixes",()=>{
 it.each((["pass-consumed","release-refused","technical"] as const).flatMap(branch=>Array.from({length:branch==="technical"?3:7},(_,count)=>({branch,count}))))("resumes $branch lexical phase prefix $count",async({branch,count})=>{
  const h=await fixture();await h.coordinator.withMutation(async c=>{
   const terminal=await branchTerminal(h,c,branch),phases=join(h.root,"requests","phases"),original=(await readdir(phases)).sort();
   expect(original).toHaveLength(branch==="technical"?2:6);let fired=false;
   h.setFault(async p=>{if(!fired&&(count===0&&p==="cleanup:after-tombstone"||count>0&&p==="directory:before-sync"&&(await readdir(phases)).length===original.length-count)){fired=true;throw new Error("branch actual prefix");}});
   await expect(h.requests.compactExpired(c,terminal,new Date(deadline))).rejects.toThrow("branch actual prefix");expect(fired).toBe(true);h.setFault(undefined);
   expect((await readdir(phases)).sort()).toEqual(original.slice(count));
   expect(await readdir(join(h.root,"requests","bindings"))).toHaveLength(1);
   const tombstones=await readdir(join(h.root,"requests","tombstones"));expect(tombstones).toHaveLength(1);const permanent=await readFile(join(h.root,"requests","tombstones",tombstones[0]!));
   const reopened=new RequestStore(join(h.root,"requests"),new PrivateObjectStore(join(h.root,"objects")));
   await reopened.resumeExpiredCompactions(c,new Date(deadline));expect((await h.objects.inspectCapacity()).used).toBe(0);
   expect(await readFile(join(h.root,"requests","tombstones",tombstones[0]!))).toEqual(permanent);
   await reopened.resumeExpiredCompactions(c,new Date(deadline));
  });await h.coordinator.close();
 });
});
