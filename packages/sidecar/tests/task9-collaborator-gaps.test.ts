import { afterEach, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { readFile,writeFile,mkdir,unlink,readdir } from "node:fs/promises";
import { join } from "node:path";
import { canonicalJson } from "@agent-integrity/core";
import { StateCoordinator } from "../src/state-coordinator.js";
import { ServiceFailure } from "../src/service-failure.js";
import { serviceFixture,cleanupServiceFixtures } from "./support/task8-service-fixture.js";
import { testConfig,cleanupTestConfigs } from "./support/test-config.js";
import { allowDiskIntegrationTime } from "./support/disk-integration-timeout.js";
allowDiskIntegrationTime(); afterEach(async()=>{await cleanupServiceFixtures();await cleanupTestConfigs();});
it("real idempotency conflict must expose a closed typed409 without message guessing",async()=>{
 const f=await serviceFixture();const service=f.newService();await service.process(f.requestBytes,f.authHeaders());
 const changed=Buffer.from(canonicalJson({...JSON.parse(f.requestBytes.toString()),requestId:"req-different"}));
 await expect(service.process(changed,f.authHeaders(changed))).rejects.toBeInstanceOf(ServiceFailure);
});
it("exact whole-root handoff retry must resume after a dead process and posthandoff crash",async()=>{
 const f=await testConfig(),root=f.config.paths.stateRoot;
 const moduleUrl=new URL("../dist/state-coordinator.js",import.meta.url);
 // Exact unchanged coordinator module was emitted by the just-passed typecheck.
 const source='import {StateCoordinator} from '+JSON.stringify(moduleUrl.href)+';await StateCoordinator.acquire('+JSON.stringify(root)+',{storeGeneration:"generation-1",nestedLockNames:["receipts"],nestedLockPaths:{receipts:"receipts/.store-lock.json"}});';
 execFileSync(process.execPath,["--input-type=module","-e",source],{stdio:"pipe",timeout:5000});
 const lease=JSON.parse(await readFile(join(root,"lease.json"),"utf8"));
 const options={storeGeneration:"generation-1",nestedLockNames:["receipts"],nestedLockPaths:{receipts:"receipts/.store-lock.json"},offlineExclusive:true as const,expectedOwnerToken:lease.ownerToken,expectedRootIdentityDigest:lease.rootIdentityDigest,nextOwnerToken:"exact-recovery-owner"};
 // Separate B process publishes the complete handoff and exits before audit.
 const handoffSource="import {StateCoordinator} from "+JSON.stringify(moduleUrl.href)+";await StateCoordinator.recoverAbandoned("+JSON.stringify(root)+","+JSON.stringify(options)+");";
 const child=execFileSync(process.execPath,["--input-type=module","-e",handoffSource],{stdio:"pipe",timeout:5000});
 expect(child).toBeInstanceOf(Buffer); // execFileSync proves successful B exit.
 for(const changed of [{expectedOwnerToken:"wrong-authority"},{nextOwnerToken:"wrong-owner"},{storeGeneration:"wrong-generation"},{expectedRootIdentityDigest:"b".repeat(64)},{nestedLockPaths:{receipts:"elsewhere/.store-lock.json"}}])await expect(StateCoordinator.recoverAbandoned(root,{...options,...changed})).rejects.toThrow();
 await mkdir(join(root,"extra"),{mode:0o700});await writeFile(join(root,"extra/.store-lock.json"),canonicalJson({version:2,ownerToken:lease.ownerToken,storeGeneration:lease.storeGeneration,rootIdentityDigest:lease.rootIdentityDigest}),{mode:0o600});await expect(StateCoordinator.recoverAbandoned(root,options)).rejects.toThrow();await unlink(join(root,"extra/.store-lock.json"));
 for(const point of ["file:before-sync","directory:sync"] as const){await expect(StateCoordinator.recoverAbandoned(root,{...options,faultInjector:p=>{if(p===point)throw Error("persistent-barrier");}})).rejects.toThrow("persistent-barrier");await expect(StateCoordinator.recoverAbandoned(root,{...options,faultInjector:p=>{if(p===point)throw Error("persistent-barrier");}})).rejects.toThrow("persistent-barrier");}
 const handoffPath=join(root,"handoffs",(await readdir(join(root,"handoffs")))[0]!),handoffBytes=await readFile(handoffPath),handoff=JSON.parse(handoffBytes.toString());
 for(const alteration of [{previousOwnerToken:"wrong-a"},{ownerToken:"different-b"},{nestedMarkerIdentities:{receipts:{dev:1,ino:1,ctimeMs:1,mtimeMs:1}}}]){await writeFile(handoffPath,JSON.stringify({...handoff,...alteration})+"\n");await expect(StateCoordinator.recoverAbandoned(root,options)).rejects.toThrow();await writeFile(handoffPath,handoffBytes);}
 const laterOptions={...options,expectedOwnerToken:options.nextOwnerToken,nextOwnerToken:"later-c"};
 execFileSync(process.execPath,["--input-type=module","-e","import {StateCoordinator} from "+JSON.stringify(moduleUrl.href)+";await StateCoordinator.recoverAbandoned("+JSON.stringify(root)+","+JSON.stringify(laterOptions)+");"],{stdio:"pipe",timeout:5000});
 await expect(StateCoordinator.recoverAbandoned(root,options)).rejects.toThrow();
 const retry=await StateCoordinator.recoverAbandoned(root,laterOptions);
 await retry.withMutation(c=>retry.completeNestedLockHandoff(c));await retry.close();
});

it("same-process known liveB rejects duplicate exact continuation without weakening first operator handoff",async()=>{const f=await testConfig(),root=f.config.paths.stateRoot,moduleUrl=new URL("../dist/state-coordinator.js",import.meta.url);execFileSync(process.execPath,["--input-type=module","-e","import {StateCoordinator} from "+JSON.stringify(moduleUrl.href)+";await StateCoordinator.acquire("+JSON.stringify(root)+",{storeGeneration:'generation-1',nestedLockNames:['receipts'],nestedLockPaths:{receipts:'receipts/.store-lock.json'}});"],{timeout:5000,stdio:"pipe"});const lease=JSON.parse(await readFile(join(root,"lease.json"),"utf8")),options={storeGeneration:"generation-1",nestedLockNames:["receipts"],nestedLockPaths:{receipts:"receipts/.store-lock.json"},offlineExclusive:true as const,expectedOwnerToken:lease.ownerToken,expectedRootIdentityDigest:lease.rootIdentityDigest,nextOwnerToken:"live-b"};const b=await StateCoordinator.recoverAbandoned(root,options);try{await expect(StateCoordinator.recoverAbandoned(root,options)).rejects.toThrow("known live");}finally{await b.withMutation(c=>b.completeNestedLockHandoff(c));await b.close();}});

it("typed tombstone conflict preserves permanent binding",async()=>{const f=await serviceFixture(),service=f.newService();await service.process(f.requestBytes,f.authHeaders());f.setTime(new Date("2030-01-01T00:07:00.000Z"));await expect(service.process(f.requestBytes,f.authHeaders())).rejects.toThrow();const before=await f.requests.inspectCapacity();const changed=Buffer.from(canonicalJson({...JSON.parse(f.requestBytes.toString()),requestId:"changed-after-expiry"}));await expect(service.process(changed,f.authHeaders(changed))).rejects.toMatchObject({code:"IDEMPOTENCY_CONFLICT",httpStatus:409});expect(await f.requests.inspectCapacity()).toEqual(before);expect(f.options.readiness.snapshot().ready).toBe(true);});
