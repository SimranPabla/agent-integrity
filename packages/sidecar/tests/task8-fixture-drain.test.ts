import { allowDiskIntegrationTime } from "./support/disk-integration-timeout.js";
allowDiskIntegrationTime();
import { afterEach,beforeEach,expect,it,vi } from "vitest";
import { lstat } from "node:fs/promises";
import { serviceFixture,cleanupServiceFixtures } from "./support/task8-service-fixture.js";
import { assertMutationCapability,type MutationCapability } from "../src/state-coordinator.js";
import * as worker from "../src/verification-runner.js";
let f:Awaited<ReturnType<typeof serviceFixture>>;
beforeEach(async()=>{f=await serviceFixture();});
afterEach(async()=>{await cleanupServiceFixtures();vi.restoreAllMocks();});
it("teardown aborts actual pure worker and waits for its return and capability retirement",async()=>{
 let enter!:()=>void;const entered=new Promise<void>(r=>enter=r);let cap:MutationCapability|undefined,workerSettled=false;
 const mutation=f.coordinator.withMutation.bind(f.coordinator);vi.spyOn(f.coordinator,"withMutation").mockImplementation(operation=>mutation(c=>{cap=c;return operation(c);}));
 const real=worker.runTrustedVerification;vi.spyOn(worker,"runTrustedVerification").mockImplementation(async(...args)=>{enter();const result=await real(...args);workerSettled=true;return result;});
 const service=f.newService();const operation=service.process(f.requestBytes,f.authHeaders());const rejection=expect(operation).rejects.toMatchObject({reason:"RECOVERY_REQUIRED"});
 await entered;assertMutationCapability(cap);await cleanupServiceFixtures();await rejection;
 expect(workerSettled).toBe(true);expect(()=>assertMutationCapability(cap)).toThrow();await expect(lstat(f.root)).rejects.toMatchObject({code:"ENOENT"});
 await expect(service.process(f.requestBytes,f.authHeaders())).rejects.toThrow(/retiring/);
});
it("teardown drains actual postverified terminal work before removing its owned root",async()=>{
 let enter!:()=>void,release!:()=>void;const entered=new Promise<void>(r=>enter=r),gate=new Promise<void>(r=>release=r);let cap:MutationCapability|undefined;
 const mutation=f.coordinator.withMutation.bind(f.coordinator);vi.spyOn(f.coordinator,"withMutation").mockImplementation(operation=>mutation(c=>{cap=c;return operation(c);}));
 const advance=f.requests.advance.bind(f.requests);vi.spyOn(f.requests,"advance").mockImplementation(async(...args)=>{const result=await advance(...args);if(result.phase==="verified"){enter();await gate;}return result;});
 const operation=f.newService().process(f.requestBytes,f.authHeaders());const result=expect(operation).resolves.toMatchObject({status:"PASS"});
 await entered;let drained=false;const teardown=cleanupServiceFixtures().then(()=>{drained=true;});
 try{expect((await lstat(f.root)).isDirectory()).toBe(true);expect(drained).toBe(false);assertMutationCapability(cap);await expect(f.coordinator.close()).rejects.toThrow(/mutation/);}finally{release();}
 await result;await teardown;expect(drained).toBe(true);expect(()=>assertMutationCapability(cap)).toThrow();await expect(lstat(f.root)).rejects.toMatchObject({code:"ENOENT"});
});
