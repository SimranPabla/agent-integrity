import { allowDiskIntegrationTime } from "./support/disk-integration-timeout.js";
allowDiskIntegrationTime();
import { afterEach, beforeEach, expect, it } from "vitest";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { canonicalJson, FileReceiptStore, RECEIPT_STORE_LOCK_AUTHORIZER } from "@agent-integrity/core";
import { serviceFixture, cleanupServiceFixtures, hash } from "./support/task8-service-fixture.js";
import { StateCoordinator, assertMutationCapability } from "../src/state-coordinator.js";
const options = { storeGeneration: "generation-1", nestedLockNames: ["receipts"], nestedLockPaths: { receipts: "receipts/.store-lock.json" } };
let f: Awaited<ReturnType<typeof serviceFixture>>;
const evidencePath = "docs/" + Array(13).fill("a").join("/") + "/e.md";
beforeEach(async ({ task }) => {
 f = await serviceFixture();
 const bundle = join(f.incomingRoot, "bundle-1"), bytes = Buffer.from("valid deep evidence\n");
 const path = join(bundle,"project",evidencePath);
 await mkdir(dirname(path),{recursive:true,mode:0o750});await writeFile(path,bytes,{mode:0o640});
 const manifest=JSON.parse(await readFile(join(bundle,"manifest.json"),"utf8"));
 manifest.files.push({path:evidencePath,bytes:bytes.length,sha256:hash(bytes)});
 manifest.files.sort((a:{path:string},b:{path:string})=>a.path<b.path?-1:1);
 delete manifest.manifestDigest;manifest.manifestDigest=hash(canonicalJson(manifest));
 await writeFile(join(bundle,"manifest.json"),canonicalJson(manifest));
 if (task.name.includes("over-bound")) {
  // Pure invalid-tree construction: no validation, service call or authority operation in hooks.
  let directory=f.stateRoot;for(let i=0;i<524;i++){directory=join(directory,"a");await mkdir(directory,{mode:0o700});}
 }
});
afterEach(cleanupServiceFixtures);
it("valid deep evidence snapshots PASS under leased root, closes, reacquires and completes independent core handoff",()=>f.trackOperation(async()=>{
 expect(Buffer.byteLength(evidencePath)).toBe(35);
 const result=await f.newService().process(f.requestBytes,f.authHeaders());expect(result.status).toBe("PASS");
 if(!("receipt" in result))throw Error("receipt missing");
 const [snapshot]=await readdir(f.snapshotRoot);
 expect(await readFile(join(f.snapshotRoot,snapshot!,"project",evidencePath),"utf8")).toBe("valid deep evidence\n");
 await f.restart();expect(await f.newService().process(f.requestBytes,f.authHeaders())).toEqual(result);
 const authority=await f.coordinator.withMutation(c=>({...c}));
 await f.coordinator.withMutation(async c=>{
  const store=new FileReceiptStore(join(f.stateRoot,"receipts"),{lockOwnership:f.coordinator.receiptStoreLockOwnership(c),faultInjector:p=>{if(p==="lock:before-release")throw Error("simulated crash");}});
  await expect(store.issue(result.receipt,{transactionId:"transaction-1"})).rejects.toThrow();
 });
 const recovered=await StateCoordinator.recoverAbandoned(f.stateRoot,{...options,offlineExclusive:true,expectedOwnerToken:authority.ownerToken,expectedRootIdentityDigest:authority.rootIdentityDigest});
 await recovered.withMutation(async c=>{
  const store=new FileReceiptStore(join(f.stateRoot,"receipts"),{lockOwnership:{...c,[RECEIPT_STORE_LOCK_AUTHORIZER]:()=>assertMutationCapability(c)}});
  await store.completeRootAuthorizedLockHandoff({offlineExclusive:true,rootDirectory:f.stateRoot,handoffPreviousOwnerToken:authority.ownerToken,lockName:"receipts"});
 });
 await recovered.withMutation(c=>recovered.completeNestedLockHandoff(c));await recovered.close();
 const again=await StateCoordinator.acquire(f.stateRoot,options);await again.close();
}));

it("both root and independent core reject over-bound subtree without changing authority",()=>f.trackOperation(async()=>{
 const authority=await f.coordinator.withMutation(c=>({...c}));
 await f.coordinator.withMutation(async c=>{
  const {buildReceipt,verifyTrustedEnvelope}=await import("@agent-integrity/core");
  const {trustedEnvelopeFixture}=await import("../../core/tests/support/trusted-envelope.js");
  const {receiptSigningOptions}=await import("../../core/tests/support/receipt-keys.js");
  const {envelope,context}=await trustedEnvelopeFixture();
  const receipt=buildReceipt({runId:"depth-run",nonce:"depth-nonce",envelope,verification:await verifyTrustedEnvelope(envelope,context),...receiptSigningOptions,createdAt:new Date("2026-08-02T00:00:00.000Z"),expiresAt:new Date("2026-08-02T01:00:00.000Z")});
  const store=new FileReceiptStore(join(f.stateRoot,"receipts"),{lockOwnership:f.coordinator.receiptStoreLockOwnership(c),faultInjector:p=>{if(p==="lock:before-release")throw Error("crash");}});
  await expect(store.issue(receipt,{transactionId:"depth-tx"})).rejects.toThrow();
 });
 // Persist a valid handoff before adding the invalid static tree so core independently reaches its scanner.
 const {rename}=await import("node:fs/promises");
 await rename(join(f.stateRoot,"a"),join(f.root,"saved-depth"));
 const recovered=await StateCoordinator.recoverAbandoned(f.stateRoot,{...options,offlineExclusive:true,expectedOwnerToken:authority.ownerToken,expectedRootIdentityDigest:authority.rootIdentityDigest});
 await rename(join(f.root,"saved-depth"),join(f.stateRoot,"a"));
 const marker=await readFile(join(f.stateRoot,"receipts/.store-lock.json"));
 await expect(recovered.close()).rejects.toThrow(/depth exceeded/);
 await recovered.withMutation(async c=>{
  const store=new FileReceiptStore(join(f.stateRoot,"receipts"),{lockOwnership:{...c,[RECEIPT_STORE_LOCK_AUTHORIZER]:()=>assertMutationCapability(c)}});
  await expect(store.completeRootAuthorizedLockHandoff({offlineExclusive:true,rootDirectory:f.stateRoot,handoffPreviousOwnerToken:authority.ownerToken,lockName:"receipts"})).rejects.toThrow(/depth exceeded/);
 });
 expect(await readFile(join(f.stateRoot,"receipts/.store-lock.json"))).toEqual(marker);expect(await readdir(join(f.stateRoot,"nested-locks"))).toEqual([]);
}));
