import { allowDiskIntegrationTime } from "./support/disk-integration-timeout.js";
allowDiskIntegrationTime();
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cp, readFile, writeFile, mkdir, readdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { canonicalJson, FileReceiptStore, RECEIPT_STORE_LOCK_AUTHORIZER } from "@agent-integrity/core";
import { serviceFixture, cleanupServiceFixtures, hash } from "./support/task8-service-fixture.js";
import { StateCoordinator, assertMutationCapability } from "../src/state-coordinator.js";
import { serviceRequestDigest } from "../src/protocol.js";
const pendingGateReleases = new Set<() => void>();
afterEach(async () => {
 for (const release of pendingGateReleases) release();
 pendingGateReleases.clear();
 await cleanupServiceFixtures();
 vi.restoreAllMocks();
});
const coordinatorOptions = { storeGeneration: "generation-1", nestedLockNames: ["receipts"], nestedLockPaths: { receipts: "receipts/.store-lock.json" } };
async function addClock(f: Awaited<ReturnType<typeof serviceFixture>>) {
 const bundle = join(f.incomingRoot,"bundle-1"); const bytes=Buffer.from("ordinary private evidence\n");
 for(const name of ["clock.json","package-lock.json"])await writeFile(join(bundle,"project/docs",name),bytes,{mode:0o640});
 const manifest=JSON.parse(await readFile(join(bundle,"manifest.json"),"utf8"));
 for(const path of ["docs/clock.json","docs/package-lock.json"])manifest.files.push({path,bytes:bytes.length,sha256:hash(bytes)});
 manifest.files.sort((a:{path:string},b:{path:string})=>a.path < b.path ? -1 : 1);delete manifest.manifestDigest;manifest.manifestDigest=hash(canonicalJson(manifest));
 await writeFile(join(bundle,"manifest.json"),canonicalJson(manifest));
}
async function interrupted(f:Awaited<ReturnType<typeof serviceFixture>>,receipt: import("@agent-integrity/protocol").AlphaIntegrityReceipt) {
 const authority=await f.coordinator.withMutation(c=>({...c}));
 await f.coordinator.withMutation(async c=>{const store=new FileReceiptStore(join(f.stateRoot,"receipts"),{lockOwnership:f.coordinator.receiptStoreLockOwnership(c),faultInjector:p=>{if(p==="lock:before-release")throw Error("crash");}});await expect(store.issue(receipt,{transactionId:"transaction-1"})).rejects.toThrow();});
 const recovered=await StateCoordinator.recoverAbandoned(f.stateRoot,{...coordinatorOptions,offlineExclusive:true,expectedOwnerToken:authority.ownerToken,expectedRootIdentityDigest:authority.rootIdentityDigest});return {authority,recovered};
}
it("real fixed-root snapshots accept clock.json through close, restart and protected core handoff",async()=>{
 const f=await serviceFixture();return f.trackOperation(async()=>{await addClock(f);const result=await f.newService().process(f.requestBytes,f.authHeaders());expect(result.status).toBe("PASS");if(!("receipt" in result))throw Error("receipt missing");
 expect(f.snapshotRoot.startsWith(f.stateRoot+"/")).toBe(true);await f.restart();expect(await f.newService().process(f.requestBytes,f.authHeaders())).toEqual(result);
 const {recovered}=await interrupted(f,result.receipt);await recovered.withMutation(c=>recovered.completeNestedLockHandoff(c));await recovered.close();const again=await StateCoordinator.acquire(f.stateRoot,coordinatorOptions);await again.close();
});});
it("root and independent core reject undeclared .store-lock.json without removing authority",async()=>{
 const f=await serviceFixture();return f.trackOperation(async()=>{await addClock(f);const result=await f.newService().process(f.requestBytes,f.authHeaders());if(!("receipt" in result))throw Error("receipt missing");const {authority,recovered}=await interrupted(f,result.receipt);
 const foreign=join(f.stateRoot,"snapshots","foreign");await mkdir(foreign,{mode:0o700});await writeFile(join(foreign,".store-lock.json"),canonicalJson({version:2,...authority}),{mode:0o600});
 await expect(recovered.withMutation(c=>recovered.completeNestedLockHandoff(c))).rejects.toThrow(/unexpected/);
 await recovered.withMutation(async c=>{const store=new FileReceiptStore(join(f.stateRoot,"receipts"),{lockOwnership:{...c,[RECEIPT_STORE_LOCK_AUTHORIZER]:()=>assertMutationCapability(c)}});await expect(store.completeRootAuthorizedLockHandoff({offlineExclusive:true,rootDirectory:f.stateRoot,handoffPreviousOwnerToken:authority.ownerToken,lockName:"receipts"})).rejects.toThrow(/unexpected/);});
 await expect(recovered.close()).rejects.toThrow(/unexpected/);expect(await readdir(join(f.stateRoot,"handoffs"))).toHaveLength(1);expect(await readFile(join(foreign,".store-lock.json"),"utf8")).toBe(canonicalJson({version:2,...authority}));
 });
});

import * as protocol from "../src/protocol.js";
import * as auth from "../src/auth.js";
import * as bundles from "../src/bundle.js";
import * as worker from "../src/verification-runner.js";
import * as core from "@agent-integrity/core";
import * as sdk from "@agent-integrity/sdk";
it("actual ordered lifecycle retains one live capability and completed retry stops at lookup",async()=>{
 const f=await serviceFixture();return f.trackOperation(async()=>{const events:string[]=[];let live: import("../src/state-coordinator.js").MutationCapability|undefined;
 const trace=(label:string)=>{
  if(!["parse/digest","MAC","returned"].includes(label)||live)assertMutationCapability(live);
  events.push(label);
 };
 expect(()=>trace("AUTHnonce")).toThrow(); // negative control: no live capability exists before admission
 const parse=protocol.parseCanonicalServiceRequest;vi.spyOn(protocol,"parseCanonicalServiceRequest").mockImplementation((...a)=>{const v=parse(...a);trace("parse/digest");return v;});
 const mac=auth.authenticateRequest;vi.spyOn(auth,"authenticateRequest").mockImplementation((...a)=>{const v=mac(...a);trace("MAC");return v;});
 const mutation=f.coordinator.withMutation.bind(f.coordinator);vi.spyOn(f.coordinator,"withMutation").mockImplementation(operation=>mutation(async c=>{live=c;trace("capability");try{return await operation(c);}finally{live=undefined;}}));
 const nonce=f.options.nonceStore.consume.bind(f.options.nonceStore);vi.spyOn(f.options.nonceStore,"consume").mockImplementation(async(...a)=>{trace("AUTHnonce");return nonce(...a);});
 const lookup=f.requests.lookup.bind(f.requests);vi.spyOn(f.requests,"lookup").mockImplementation(async(...a)=>{trace("lookup");return lookup(...a);});
 const reserve=f.requests.reserve.bind(f.requests);vi.spyOn(f.requests,"reserve").mockImplementation(async(...a)=>{trace("reserve");return reserve(...a);});
 const publish=f.objects.publishCanonicalRequest.bind(f.objects);vi.spyOn(f.objects,"publishCanonicalRequest").mockImplementation(async(...a)=>{const v=await publish(...a);trace("private-request");return v;});
 const snapshot=bundles.validateAndSnapshotBundle;vi.spyOn(bundles,"validateAndSnapshotBundle").mockImplementation(async(...a)=>{const v=await snapshot(...a);trace("snapshot");return v;});
 const verify=worker.runTrustedVerification;vi.spyOn(worker,"runTrustedVerification").mockImplementation(async(...a)=>{trace("pureverify");return verify(...a);});
 const advance=f.requests.advance.bind(f.requests);vi.spyOn(f.requests,"advance").mockImplementation(async(...a)=>{const v=await advance(...a);trace(v.phase);return v;});
 const Registry = (await import("../src/key-registry.js")).ReceiptKeyRegistry;const select=Registry.prototype.select;vi.spyOn(Registry.prototype,"select").mockImplementation(function(...a){trace("freshkey");return select.apply(this,a);});
 const registry=f.objects.publishTrustRegistry.bind(f.objects);vi.spyOn(f.objects,"publishTrustRegistry").mockImplementation(async(...a)=>{const v=await registry(...a);trace("public-registry");return v;});
 const create=core.createReceipt;vi.spyOn(core,"createReceipt").mockImplementation(async(...a)=>{trace("createReceipt");return create(...a);});
 const issue=FileReceiptStore.prototype.issue;vi.spyOn(FileReceiptStore.prototype,"issue").mockImplementation(async function(...a){trace("issue");expect(a[1]?.transactionId).toBe("transaction-1");return issue.apply(this,a);});
 const output=FileReceiptStore.prototype.completeReceiptFile;vi.spyOn(FileReceiptStore.prototype,"completeReceiptFile").mockImplementation(async function(...a){trace("output");return output.apply(this,a);});
 const release=sdk.releaseVerifiedReceipt;vi.spyOn(sdk,"releaseVerifiedReceipt").mockImplementation(async(...a)=>{trace("freshSDKrecheck");return release(...a);});
 const consume=FileReceiptStore.prototype.consume;vi.spyOn(FileReceiptStore.prototype,"consume").mockImplementation(async function(...a){trace("consume");return consume.apply(this,a);});
 const inspect=FileReceiptStore.prototype.inspectConsumed;vi.spyOn(FileReceiptStore.prototype,"inspectConsumed").mockImplementation(async function(...a){trace("inspect-consumed");return inspect.apply(this,a);});
 const service=f.newService();const result=await service.process(f.requestBytes,f.authHeaders());trace("returned");
 const expected=["parse/digest","MAC","capability","MAC","AUTHnonce","lookup","reserve","private-request","snapshot","pureverify","verified","freshkey","public-registry","receipt-prepared","createReceipt","issue","output","receipt-issued","freshSDKrecheck","consume","inspect-consumed","pass-consumed","result-committed","returned"];
 let cursor=0;for(const event of events)if(event===expected[cursor])cursor++;expect(cursor,events.join(" -> ")).toBe(expected.length);
 if(!("releasedResponse" in result))throw Error("PASS missing");expect(Buffer.from(result.releasedResponse.bytes,"base64")).toEqual(Buffer.from(f.request.envelope.response.content,"utf8"));
 await rm(f.incomingRoot,{recursive:true});events.length=0;expect(await service.process(f.requestBytes,f.authHeaders())).toEqual(result);expect(events).toEqual(["parse/digest","MAC","capability","MAC","AUTHnonce","lookup"]);await f.coordinator.close();
 });
});

async function secondRequest(f:Awaited<ReturnType<typeof serviceFixture>>) {
 const value={...JSON.parse(f.requestBytes.toString()),requestId:"req-2",idempotencyKey:"idem-2",bundleId:"bundle-2"};
 await cp(join(f.incomingRoot,"bundle-1"),join(f.incomingRoot,"bundle-2"),{recursive:true});const path=join(f.incomingRoot,"bundle-2","manifest.json");const m=JSON.parse(await readFile(path,"utf8"));m.requestId=value.requestId;m.bundleId=value.bundleId;delete m.manifestDigest;m.manifestDigest=hash(canonicalJson(m));await writeFile(path,canonicalJson(m));return Buffer.from(canonicalJson(value));
}
describe("two distinct legitimate transactions share one service/output root with frozen unique names",()=>{
 let f: Awaited<ReturnType<typeof serviceFixture>>;let second: Buffer;let service: VerifyReleaseService;
 beforeEach(async()=>{
  // Only independent roots, input bundles, generated keys and host configuration are setup.
  // Both real requests, receipt checks, cached retries and close remain under the test budget.
  f=await serviceFixture();second=await secondRequest(f);let ordinal=0;
  f.options.transactionId=()=>"transaction-"+(++ordinal);
  f.options.deriveRunAndNonce=r=>({runId:"run-"+r.requestId,nonce:"nonce-"+r.requestId});service=f.newService();
 });
 it("issues both requests and preserves their exact distinct receipts and retries",()=>f.trackOperation(async()=>{
 const first=await service.process(f.requestBytes,f.authHeaders());const next=await service.process(second,f.authHeaders(second));expect(first.status).toBe("PASS");expect(next.status).toBe("PASS");if(!("receipt" in first)||!("receipt" in next))throw Error("missing receipts");expect(next.receipt.receiptDigest).not.toBe(first.receipt.receiptDigest);
 for(const [body,result] of [[f.requestBytes,first],[second,next]] as const){const r=protocol.parseCanonicalServiceRequest(body,1048576);const names=await readdir(join(f.stateRoot,"requests/phases"));const issued=await Promise.all(names.filter(n=>n.endsWith("-receipt-issued.json")).map(async n=>JSON.parse(await readFile(join(f.stateRoot,"requests/phases",n),"utf8"))));const state=issued.find(s=>s.requestDigest===serviceRequestDigest(r));if(!state)throw Error("missing persisted issued output");expect(canonicalJson(JSON.parse(await readFile(join(f.outputRoot,state.receiptOutputName),"utf8")))).toBe(canonicalJson(result.receipt));}
 expect(await service.process(f.requestBytes,f.authHeaders())).toEqual(first);expect(await service.process(second,f.authHeaders(second))).toEqual(next);await f.coordinator.close();
 }));
});

it.each(["key-expiry","timestamp-skew","abort"])("queued %s rejects before AUTHnonce or request mutation",async kind=>{
 const f=await serviceFixture();return f.trackOperation(async()=>{const initial=new Date("2030-01-01T00:05:00.000Z");
 if(kind==="key-expiry")f.options.authRegistry={clients:{"client-1":{keys:{auth1:{secret:f.authSecret,validFromMs:initial.getTime()-60000,validUntilMs:initial.getTime()+1}}}}};
 const service=f.newService();const nonce=vi.spyOn(f.options.nonceStore,"consume");const reserve=vi.spyOn(f.requests,"reserve");let entered!:()=>void,release!:()=>void;const started=new Promise<void>(r=>{entered=r;pendingGateReleases.add(r);});const gate=new Promise<void>(r=>{release=r;pendingGateReleases.add(r);});
 const active=f.options.scheduler.run(async()=>{entered();await gate;});await started;const controller=new AbortController();const pending=service.process(f.requestBytes,f.authHeaders(),controller.signal);const rejected=expect(pending).rejects.toMatchObject(kind==="abort"?{reason:"ABORTED"}:{code:"AUTHENTICATION_FAILED"});
 if(kind==="abort")controller.abort();else f.setTime(new Date(initial.getTime()+(kind==="key-expiry"?1:60001)));release();await active;await rejected;expect(nonce).not.toHaveBeenCalled();expect(reserve).not.toHaveBeenCalled();expect(f.options.readiness.snapshot().ready).toBe(true);await f.coordinator.close();
 });
});
it("real published authentication nonce survives storage failure and cannot be reused",async()=>{
 const f=await serviceFixture();return f.trackOperation(async()=>{const headers=f.authHeaders();const consume=f.options.nonceStore.consume.bind(f.options.nonceStore);vi.spyOn(f.options.nonceStore,"consume").mockImplementationOnce(async record=>{await consume(record);throw Error("after durable publication");});const service=f.newService();await expect(service.process(f.requestBytes,headers)).rejects.toMatchObject({reason:"RECOVERY_REQUIRED"});expect(f.options.readiness.snapshot().ready).toBe(false);vi.restoreAllMocks();await f.restart();await expect(f.newService().process(f.requestBytes,headers)).rejects.toMatchObject({code:"REPLAY_DETECTED"});expect(await f.requests.lookup("client-1","generation-1","idem-1",serviceRequestDigest(f.request))).toBeUndefined();await f.coordinator.close();
 });
});

it.each(["during-verification","after-verified"])("disconnect %s retains capability until recoverable boundary",async kind=>{
 const f=await serviceFixture();return f.trackOperation(async()=>{const controller=new AbortController();let entered!:()=>void,release!:()=>void;const started=new Promise<void>(r=>{entered=r;pendingGateReleases.add(r);});const gate=new Promise<void>(r=>{release=r;pendingGateReleases.add(r);});let cap:import("../src/state-coordinator.js").MutationCapability|undefined;
 const mutation=f.coordinator.withMutation.bind(f.coordinator);vi.spyOn(f.coordinator,"withMutation").mockImplementation(operation=>mutation(async c=>{cap=c;return operation(c);}));
 if(kind==="during-verification"){const real=worker.runTrustedVerification;vi.spyOn(worker,"runTrustedVerification").mockImplementationOnce(async(...a)=>{const running=real(...a);entered();const result=await running;await gate;return result;});}
 else {const advance=f.requests.advance.bind(f.requests);vi.spyOn(f.requests,"advance").mockImplementation(async(...a)=>{const v=await advance(...a);if(v.phase==="verified"){entered();await gate;}return v;});}
 const service=f.newService();const pending=service.process(f.requestBytes,f.authHeaders(),controller.signal);const assertion=kind==="during-verification"?expect(pending).rejects.toMatchObject({reason:"RECOVERY_REQUIRED"}):expect(pending).resolves.toMatchObject({status:"PASS"});await started;assertMutationCapability(cap);controller.abort();await expect(f.coordinator.close()).rejects.toThrow(/mutation/);await expect(f.coordinator.withMutation(()=>undefined)).rejects.toThrow(/concurrent/);release();await assertion;expect(()=>assertMutationCapability(cap)).toThrow();
 const state=await f.requests.lookup("client-1","generation-1","idem-1",serviceRequestDigest(f.request));expect(state?.phase).toBe(kind==="during-verification"?"reserved":"result-committed");if(kind==="during-verification"){expect(await readdir(f.outputRoot)).toEqual([]);expect(f.options.readiness.snapshot().ready).toBe(false);}else if(state&&"receipt" in state)expect(await f.store().inspectConsumed(state.receiptDigest)).toMatchObject({transactionId:"transaction-1"});await f.coordinator.close();
 });
});
import { RequestStore } from "../src/request-store.js";
import { VerifyReleaseService } from "../src/service.js";
it.each(["request","receipt"])("real service %s quota exhaustion preserves uniqueness and publishes no second receipt",async kind=>{
 const f=await serviceFixture();return f.trackOperation(async()=>{const second=await secondRequest(f);let ordinal=0;f.options.transactionId=()=>"transaction-"+(++ordinal);f.options.deriveRunAndNonce=r=>({runId:"run-"+r.requestId,nonce:"nonce-"+r.requestId});
 const requests=kind==="request"?new RequestStore(join(f.stateRoot,"requests"),f.objects,{maxRecords:1}):f.requests;
 const service=f.trackService(new VerifyReleaseService({...f.options,requestStore:requests,receiptStore:c=>new FileReceiptStore(join(f.stateRoot,"receipts"),{lockOwnership:f.coordinator.receiptStoreLockOwnership(c),...(kind==="receipt"?{maxRecords:1}:{})})}));
 const first=await service.process(f.requestBytes,f.authHeaders());expect(first.status).toBe("PASS");const issue=vi.spyOn(FileReceiptStore.prototype,"issue");await expect(service.process(second,f.authHeaders(second))).rejects.toMatchObject({reason:"RECOVERY_REQUIRED"});expect(f.options.readiness.snapshot().ready).toBe(false);if(kind==="request")expect(issue).not.toHaveBeenCalled();expect((await readdir(f.outputRoot)).filter(n=>n.endsWith(".json"))).toHaveLength(1);if("receipt" in first)expect(await f.store().inspectConsumed(first.receipt.receiptDigest)).toMatchObject({transactionId:"transaction-1"});await f.coordinator.close();
 });
});

it("unknown durable phase latches readiness before snapshot, verifier or receipt store",async()=>{
 const f=await serviceFixture();return f.trackOperation(async()=>{const reserve=f.requests.reserve.bind(f.requests);vi.spyOn(f.requests,"reserve").mockImplementationOnce(async(...a)=>{const state=await reserve(...a);throw Error("reserved crash");});await expect(f.newService().process(f.requestBytes,f.authHeaders())).rejects.toThrow();vi.restoreAllMocks();await f.restart();
 const phases=join(f.stateRoot,"requests","phases");const entries=await readdir(phases);const path=join(phases,entries[0]!);const state=JSON.parse(await readFile(path,"utf8"));await writeFile(path,canonicalJson({...state,phase:"unknown"}));const nonce=vi.spyOn(f.options.nonceStore,"consume");const snapshot=vi.spyOn(bundles,"validateAndSnapshotBundle");const verifier=vi.spyOn(worker,"runTrustedVerification");const issue=vi.spyOn(FileReceiptStore.prototype,"issue");const service=f.newService();await expect(service.process(f.requestBytes,f.authHeaders())).rejects.toMatchObject({reason:"RECOVERY_REQUIRED"});expect(f.options.readiness.snapshot().ready).toBe(false);await expect(service.process(f.requestBytes,f.authHeaders())).rejects.toMatchObject({reason:"NOT_READY"});expect(nonce).toHaveBeenCalledTimes(1);expect(snapshot).not.toHaveBeenCalled();expect(verifier).not.toHaveBeenCalled();expect(issue).not.toHaveBeenCalled();await f.coordinator.close();
 });
});
it("delayed refusal recovery preserves close marker but delivery window starts at result commit",async()=>{
 const f=await serviceFixture();return f.trackOperation(async()=>{f.options.deliveryWindowMs=1000;const initial=new Date("2030-01-01T00:05:00.000Z");let advance=f.requests.advance.bind(f.requests);vi.spyOn(f.requests,"advance").mockImplementation(async(...a)=>{const v=await advance(...a);if(v.phase==="receipt-issued")throw Error("issued crash");return v;});await expect(f.newService().process(f.requestBytes,f.authHeaders())).rejects.toThrow();vi.restoreAllMocks();await f.restart();advance=f.requests.advance.bind(f.requests);vi.spyOn(f.requests,"advance").mockImplementation(async(...a)=>{const v=await advance(...a);if(v.phase==="release-refused")throw Error("refusal crash");return v;});await expect(f.newService().process(f.requestBytes,f.authHeaders())).rejects.toThrow();vi.restoreAllMocks();const refused=await f.requests.lookup("client-1","generation-1","idem-1",serviceRequestDigest(f.request));if(!refused||!("receiptDigest" in refused))throw Error("missing refusal");const original=await f.store().inspectClosed(refused.receiptDigest);expect(original?.closedAt).toBe(initial.toISOString());await f.restart();f.setTime(new Date(initial.getTime()+20000));const result=await f.newService().process(f.requestBytes,f.authHeaders());expect(result.status).toBe("RELEASE_REFUSED");expect(result).not.toHaveProperty("releasedResponse");expect(await f.store().inspectClosed(refused.receiptDigest)).toEqual(original);const committed=await f.requests.lookup("client-1","generation-1","idem-1",serviceRequestDigest(f.request));expect(committed).toMatchObject({phase:"result-committed",deliveryDeadline:new Date(initial.getTime()+21000).toISOString()});f.setTime(new Date(initial.getTime()+20999));expect(await f.newService().process(f.requestBytes,f.authHeaders())).toEqual(result);f.setTime(new Date(initial.getTime()+21000));await expect(f.newService().process(f.requestBytes,f.authHeaders())).rejects.toMatchObject({reason:"RESULT_EXPIRED"});await f.coordinator.close();
 });
});

it("root authority failure latches readiness with no authentication nonce publication",async()=>{
 const f=await serviceFixture();return f.trackOperation(async()=>{const path=join(f.stateRoot,"lease.json");const lease=JSON.parse(await readFile(path,"utf8"));await writeFile(path,canonicalJson({...lease,ownerToken:"foreign-owner"}));const nonce=vi.spyOn(f.options.nonceStore,"consume");const service=f.newService();await expect(service.process(f.requestBytes,f.authHeaders())).rejects.toMatchObject({reason:"RECOVERY_REQUIRED"});expect(f.options.readiness.snapshot().ready).toBe(false);await expect(service.process(f.requestBytes,f.authHeaders())).rejects.toMatchObject({reason:"NOT_READY"});expect(nonce).not.toHaveBeenCalled();expect(await readFile(path,"utf8")).toBe(canonicalJson({...lease,ownerToken:"foreign-owner"}));
 });
});
