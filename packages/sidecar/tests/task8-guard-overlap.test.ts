import { allowDiskIntegrationTime } from "./support/disk-integration-timeout.js";
allowDiskIntegrationTime();
import { afterEach, expect, it, vi } from "vitest";
const probe=vi.hoisted(()=>({held:"",entered:()=>{},release:()=>{},gate:Promise.resolve(),active:0,record:false,seen:[] as string[]}));
vi.mock("node:fs/promises",async()=>{
 const actual=await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
 return {...actual,lstat:async(...args:Parameters<typeof actual.lstat>)=>{
  if(probe.record)probe.seen.push(String(args[0]));
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
afterEach(async()=>{probe.entered();probe.release();await Promise.allSettled(operations.splice(0));probe.held="";probe.record=false;probe.seen=[];await cleanupServiceFixtures();await Promise.all(roots.splice(0).map(root=>rm(root,{recursive:true,force:true})));});
async function root(){const p=await mkdtemp(join(tmpdir(),"task8-fresh-"));roots.push(p);await chmod(p,0o700);return p;}
function hold(path:string){probe.held=path;const entered=new Promise<void>(resolve=>probe.entered=resolve);probe.gate=new Promise<void>(resolve=>probe.release=resolve);return entered;}
async function stillPending(p:Promise<unknown>){expect(await Promise.race([p.then(()=>"settled",()=>"settled"),new Promise<string>(resolve=>setTimeout(()=>resolve("pending"),25))])).toBe("pending");}

it("root failure overlaps fresh children but drains them before rejection",async()=>{
 const parent=await root(),state=join(parent,"state");const d=new DurableJsonDirectory(state,{maxStateBytes:4096,maxEntries:16});await d.initialize(["a","b","c"]);await chmod(state,0o750);
 const entered=hold(join(state,"a"));const pending=d.assertIdentity();operations.push(pending);const rejected=expect(pending).rejects.toThrow(/mode/);
 expect(await Promise.race([entered.then(()=>"child-started"),pending.then(()=>"resolved",()=>"rejected")])).toBe("child-started");
 await stillPending(pending);expect(probe.active).toBe(1);probe.release();await rejected;expect(probe.active).toBe(0);
 probe.held="";await chmod(state,0o700);await d.assertIdentity();await chmod(join(state,"c"),0o750);await expect(d.assertIdentity()).rejects.toThrow(/mode/);
});

it("fresh guard batches never start the fifth inspection before the first four settle",async()=>{
 const parent=await root(),state=join(parent,"state");const d=new DurableJsonDirectory(state,{maxStateBytes:4096,maxEntries:16});await d.initialize(["a","b","c","d","e"]);
 probe.record=true;probe.seen=[];const entered=hold(join(state,"a"));const pending=d.assertIdentity();operations.push(pending);await entered;await stillPending(pending);
 expect(probe.seen).toEqual([state,parent,join(state,"a"),join(state,"b")]);probe.release();await pending;expect(probe.active).toBe(0);
 expect(probe.seen).toEqual([state,parent,...["a","b","c","d","e"].map(n=>join(state,n))]);probe.held="";probe.record=false;
 await chmod(join(state,"e"),0o750);await expect(d.assertIdentity()).rejects.toThrow(/mode/);
});

it("cleanup rejection drains four fresh journal reads before any tombstone or deletion",async()=>{
 const f=await serviceFixture();return f.trackOperation(async()=>{
  expect((await f.newService().process(f.requestBytes,f.authHeaders())).status).toBe("PASS");
  const terminal=await f.requests.lookup("client-1","generation-1","idem-1",serviceRequestDigest(f.request));if(terminal?.phase!=="result-committed")throw Error("missing terminal");
  const phases=join(f.stateRoot,"requests/phases"),names=await readdir(phases);const bad=join(phases,names.find(n=>n.endsWith("-pass-consumed.json"))!);const original=await readFile(bad);await writeFile(bad,"bad");
  const entered=hold(join(phases,names.find(n=>n.endsWith("-receipt-issued.json"))!));probe.record=true;probe.seen=[];
  const pending=f.coordinator.withMutation(c=>f.requests.compactExpired(c,terminal,new Date("2030-01-01T00:08:00.000Z")));operations.push(pending);const rejected=expect(pending).rejects.toThrow();
  expect(await Promise.race([entered.then(()=>"journal-started"),pending.then(()=>"resolved",()=>"rejected")])).toBe("journal-started");await stillPending(pending);
  expect([...new Set(probe.seen.filter(p=>p.startsWith(phases+"/")))].sort()).toEqual(names.slice(0,4).map(n=>join(phases,n)).sort());
  expect(await readdir(join(f.stateRoot,"requests/tombstones"))).toEqual([]);expect(await readdir(phases)).toEqual(names);expect(probe.active).toBe(1);
  probe.release();await rejected;expect(probe.active).toBe(0);probe.held="";probe.record=false;await writeFile(bad,original);await f.coordinator.close();
 });
});

it("teardown drains returned manual core inspection before deleting its owned root",async()=>{
 const f=await serviceFixture();const result=await f.newService().process(f.requestBytes,f.authHeaders());if(!("receipt" in result))throw Error("missing receipt");
 const consumed=join(f.stateRoot,"receipts/consumed"),[name]=await readdir(consumed);const entered=hold(join(consumed,name!));
 const pending=f.trackOperation(()=>f.store().inspectConsumed(result.receipt.receiptDigest));operations.push(pending);const checked=expect(pending).resolves.toMatchObject({transactionId:"transaction-1"});await entered;
 const cleanup=cleanupServiceFixtures();await stillPending(cleanup);expect(await readdir(f.stateRoot)).toContain("receipts");expect(probe.active).toBe(1);
 probe.release();await checked;await cleanup;expect(probe.active).toBe(0);probe.held="";await expect(readdir(f.stateRoot)).rejects.toMatchObject({code:"ENOENT"});
});
