import { allowDiskIntegrationTime } from "./support/disk-integration-timeout.js";
allowDiskIntegrationTime();
import { afterEach, expect, it, vi } from "vitest";
const probe=vi.hoisted(()=>({held:"",entered:()=>{},release:()=>{},gate:Promise.resolve(),active:0}));
vi.mock("node:fs/promises",async()=>{
 const actual=await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
 return {...actual,lstat:async(...args:Parameters<typeof actual.lstat>)=>{
  const result=await actual.lstat(...args);
  if(String(args[0])===probe.held){probe.active++;probe.entered();try{await probe.gate;}finally{probe.active--;}}
  return result;
 }};
});
import { chmod,mkdtemp,readdir,readFile,writeFile,rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { serviceFixture,cleanupServiceFixtures } from "./support/task8-service-fixture.js";
import { serviceRequestDigest } from "../src/protocol.js";
import { DurableJsonDirectory } from "../src/durable-json.js";
import { FileReceiptStore,RECEIPT_STORE_LOCK_AUTHORIZER } from "../../core/src/receipts/file-receipt-store.js";
import { buildReceipt,verifyTrustedEnvelope } from "../../core/src/index.js";
import { trustedEnvelopeFixture } from "../../core/tests/support/trusted-envelope.js";
import { receiptSigningOptions } from "../../core/tests/support/receipt-keys.js";
const roots:string[]=[];
const operations:Promise<unknown>[]=[];
afterEach(async()=>{probe.entered();probe.release();await Promise.allSettled(operations.splice(0));probe.held="";await cleanupServiceFixtures();await Promise.all(roots.splice(0).map(root=>rm(root,{recursive:true,force:true})));});
async function root(){const p=await mkdtemp(join(tmpdir(),"task8-fresh-"));roots.push(p);await chmod(p,0o700);return p;}
function hold(path:string){probe.held=path;const entered=new Promise<void>(resolve=>probe.entered=resolve);probe.gate=new Promise<void>(resolve=>probe.release=resolve);return entered;}
async function stillPending(p:Promise<unknown>){expect(await Promise.race([p.then(()=>"settled",()=>"settled"),new Promise<string>(resolve=>setTimeout(()=>resolve("pending"),25))])).toBe("pending");}
it("fresh child validation drains every started inspection before rejecting",async()=>{
 const parent=await root(),state=join(parent,"state");const d=new DurableJsonDirectory(state,{maxStateBytes:4096,maxEntries:16});
 await d.initialize(["a","b","c","d","e"]);await chmod(join(state,"a"),0o750);
 const entered=hold(join(state,"b"));const pending=d.assertIdentity();operations.push(pending);const rejected=expect(pending).rejects.toThrow(/mode/);
 await entered;await stillPending(pending);expect(probe.active).toBe(1);probe.release();await rejected;expect(probe.active).toBe(0);
 probe.held="";await chmod(join(state,"a"),0o700);await d.assertIdentity();await chmod(join(state,"e"),0o750);await expect(d.assertIdentity()).rejects.toThrow(/mode/);
});
it("receipt inventory drains independent fresh reads before releasing its real store lock",async()=>{
 const parent=await root(),directory=join(parent,"store");const {envelope,context}=await trustedEnvelopeFixture();
 const receipt=buildReceipt({runId:"fresh-run",nonce:"fresh-nonce",envelope,verification:await verifyTrustedEnvelope(envelope,context),...receiptSigningOptions,createdAt:new Date("2026-08-02T00:00:00.000Z"),expiresAt:new Date("2026-08-02T01:00:00.000Z")});
 const store=new FileReceiptStore(directory,{maxRecords:3,lockOwnership:{ownerToken:"root-owner",storeGeneration:"generation-1",rootIdentityDigest:"a".repeat(64),[RECEIPT_STORE_LOCK_AUTHORIZER]:()=>{}}});
 await store.issue(receipt,{transactionId:"fresh-tx"});const [transaction]=(await readdir(join(directory,"transactions")));const bad=join(directory,"transactions",transaction!);const original=await readFile(bad);await writeFile(bad,"bad");
 const [quota]=(await readdir(join(directory,"quota")));const entered=hold(join(directory,"quota",quota!));const pending=store.inspectIssuedRecordByDigest(receipt.receiptDigest);operations.push(pending);const rejected=expect(pending).rejects.toThrow();
 await entered;await stillPending(pending);expect(probe.active).toBe(1);expect(JSON.parse(await readFile(join(directory,".store-lock.json"),"utf8"))).toMatchObject({ownerToken:"root-owner"});
 probe.release();await rejected;expect(probe.active).toBe(0);await expect(readFile(join(directory,".store-lock.json"))).rejects.toMatchObject({code:"ENOENT"});
 probe.held="";await writeFile(bad,original);expect((await store.inspectIssuedRecordByDigest(receipt.receiptDigest))?.receipt).toEqual(receipt);
 await writeFile(bad,"bad");await expect(store.inspectIssuedRecordByDigest(receipt.receiptDigest)).rejects.toThrow();
});

it("root failure drains the concurrent parent inspection before rejection",async()=>{
 const parent=await root(),state=join(parent,"state");const d=new DurableJsonDirectory(state,{maxStateBytes:4096,maxEntries:16});await d.initialize(["a"]);await chmod(state,0o750);
 const entered=hold(parent);const pending=d.assertIdentity();operations.push(pending);const rejected=expect(pending).rejects.toThrow(/mode/);
 await entered;await stillPending(pending);probe.release();await rejected;expect(probe.active).toBe(0);
});

it("journal validation drains fresh phase and binding reads before rejecting",async()=>{
 const f=await serviceFixture();return f.trackOperation(async()=>{
  expect((await f.newService().process(f.requestBytes,f.authHeaders())).status).toBe("PASS");
  const phases=join(f.stateRoot,"requests","phases");const names=await readdir(phases);const bad=join(phases,names.find(n=>n.endsWith("-pass-consumed.json"))!);const original=await readFile(bad);await writeFile(bad,"bad");
  const entered=hold(join(phases,names.find(n=>n.endsWith("-receipt-issued.json"))!));
  const pending=f.requests.lookup("client-1","generation-1","idem-1",serviceRequestDigest(f.request));operations.push(pending);const rejected=expect(pending).rejects.toThrow();
  await entered;await stillPending(pending);probe.release();await rejected;expect(probe.active).toBe(0);
  probe.held="";await writeFile(bad,original);expect((await f.requests.lookup("client-1","generation-1","idem-1",serviceRequestDigest(f.request)))?.phase).toBe("result-committed");
  await writeFile(bad,"bad");await expect(f.requests.lookup("client-1","generation-1","idem-1",serviceRequestDigest(f.request))).rejects.toThrow();
 });
});
