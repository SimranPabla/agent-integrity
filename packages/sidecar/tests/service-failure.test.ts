import { afterEach, expect, it } from "vitest";
import { lstat, open, readdir, rm, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { ServiceFailure } from "../src/service-failure.js";
import { ServiceUnavailableError } from "../src/service.js";
import { serviceRequestDigest } from "../src/protocol.js";
import { cleanupServiceFixtures, serviceFixture } from "./support/task8-service-fixture.js";
import { allowDiskIntegrationTime } from "./support/disk-integration-timeout.js";
allowDiskIntegrationTime(); afterEach(cleanupServiceFixtures);
it("internal categories are closed immutable metadata with no cause or private diagnostics", () => {
  const error = new ServiceFailure("BUNDLE_INVALID");
  expect(error.message).toBe("BUNDLE_INVALID"); expect(error.httpStatus).toBe(422);
  expect(Object.isFrozen(error)).toBe(true); expect("cause" in error).toBe(false);
  expect(() => new ServiceFailure("/private/key" as never)).toThrow("INVALID_FAILURE_CATEGORY");
  expect(() => new ServiceFailure("__proto__" as never)).toThrow("INVALID_FAILURE_CATEGORY");
  expect({ code: "BUNDLE_INVALID" }).not.toBeInstanceOf(ServiceFailure);
});
it("private snapshot ENOENT is not incoming bundle absence and retains committed state", async () => {
  const f = await serviceFixture(); await rm(f.snapshotRoot, { recursive: true });
  await expect(f.newService().process(f.requestBytes, f.authHeaders())).rejects.toBeInstanceOf(ServiceUnavailableError);
  expect(await readdir(join(f.stateRoot, "nonces", "records"))).toHaveLength(1);
  expect((await f.requests.lookup("client-1", "generation-1", "idem-1", serviceRequestDigest(f.request)))?.phase).toBe("reserved");
  await f.coordinator.withMutation(async c => expect((await f.options.receiptStore(c).inspectCapacity()).used).toBe(0));
  expect(f.options.readiness.snapshot().ready).toBe(false);
});
it("actual private publication sync failure never becomes 422 even after visible rename", async () => {
  const f = await serviceFixture(); const probe = await open(f.snapshotRoot, "r");
  const proto = Object.getPrototypeOf(probe), original = proto.sync; await probe.close();
  const identity = await lstat(f.snapshotRoot); let barriers = 0;
  proto.sync = async function () { const s = await this.stat(); if (s.dev === identity.dev && s.ino === identity.ino) { barriers++; throw Error("private sync sentinel /protected/root"); } return original.call(this); };
  try {
    const service = f.newService(); let failure: unknown;
    try { await service.process(f.requestBytes, f.authHeaders()); } catch (error) { failure = error; }
    expect(failure).toBeInstanceOf(ServiceUnavailableError); expect(String(failure)).not.toContain("/protected");
    expect(barriers).toBeGreaterThan(0); expect((await readdir(f.snapshotRoot)).some(n => /^[a-f0-9]{64}$/u.test(n))).toBe(true);
    expect(await readdir(join(f.stateRoot, "nonces", "records"))).toHaveLength(1);
    expect((await f.requests.lookup("client-1", "generation-1", "idem-1", serviceRequestDigest(f.request)))?.phase).toBe("reserved");
    await f.coordinator.withMutation(async c => expect((await f.options.receiptStore(c).inspectCapacity()).used).toBe(0));
    expect(f.options.readiness.snapshot().ready).toBe(false);
  } finally { proto.sync = original; }
});
it("receipt-store fault is not bundle-invalid and never reflects diagnostics", async () => {
  const f = await serviceFixture(); f.setFault(() => { throw Error("receipt storage sentinel /private/key"); });
  let failure: unknown; try { await f.newService().process(f.requestBytes, f.authHeaders()); } catch (error) { failure = error; }
  expect(failure).toBeInstanceOf(ServiceUnavailableError); expect(String(failure)).not.toContain("/private/key");
  expect(await readdir(join(f.stateRoot, "nonces", "records"))).toHaveLength(1);
  expect(f.options.readiness.snapshot().ready).toBe(false);
});
for(const kind of ["digest","size","link","inaccessible","forbidden","identity"] as const)it("incoming copy "+kind+" is422 at origin and retains nonce reservation latch without issuance",async()=>{
 const f=await serviceFixture(),path=join(f.incomingRoot,"bundle-1","project","docs","approved.md");const fs=(await import("node:fs")).default,{syncBuiltinESMExports}=await import("node:module");const original=fs.promises.open;
 if(kind==="digest"){const b=await fs.promises.readFile(path);b[0]=b[0]===65?66:65;await writeFile(path,b);}if(kind==="size")await writeFile(path,"short");if(kind==="link")await fs.promises.link(path,join(f.root,"outside-project-link"));
 if(kind==="inaccessible"||kind==="forbidden"||kind==="identity"){fs.promises.open=async function(p:any,...args:any[]){if(String(p)===path){if(kind==="identity"){const b=await fs.promises.readFile(path);await fs.promises.unlink(path);await writeFile(path,b,{mode:0o640});}else throw Object.assign(Error("private source sentinel"),{code:kind==="forbidden"?"EPERM":"EACCES"});}return (original as any)(p,...args);};syncBuiltinESMExports();}
 try{let failure:any;try{await f.newService().process(f.requestBytes,f.authHeaders());}catch(e){failure=e;}expect(failure?.httpStatus).toBe(422);expect(String(failure)).not.toContain("sentinel");expect(await readdir(join(f.stateRoot,"nonces","records"))).toHaveLength(1);expect((await f.requests.lookup("client-1","generation-1","idem-1",serviceRequestDigest(f.request)))?.phase).toBe("reserved");await f.coordinator.withMutation(async c=>expect((await f.options.receiptStore(c).inspectCapacity()).used).toBe(0));expect(f.options.readiness.snapshot().ready).toBe(false);}finally{fs.promises.open=original;syncBuiltinESMExports();}
});
for(const kind of ["write","sync","publication"] as const)it("actual private target "+kind+" failure is503 retains nonce phase and no issuance",async()=>{
 const f=await serviceFixture(),probe=await open(f.snapshotRoot,"r"),proto=Object.getPrototypeOf(probe);await probe.close();const fs=(await import("node:fs")).default,{syncBuiltinESMExports}=await import("node:module"),originalOpen=fs.promises.open,originalWrite=proto.write,originalSync=proto.sync;const targets=new Set<any>();let hit=0;
 fs.promises.open=async function(p:any,...args:any[]){if(kind==="publication"&&String(p).endsWith("/snapshot.json")){hit++;throw Object.assign(Error("private publication sentinel"),{code:"EACCES"});}const h=await (originalOpen as any)(p,...args);if(String(p).includes("/.snapshot-")&&String(p).endsWith("/docs/approved.md"))targets.add(h);return h;};syncBuiltinESMExports();
 proto.write=async function(...args:any[]){if(kind==="write"&&targets.has(this)){hit++;throw Object.assign(Error("private write sentinel"),{code:"EACCES"});}return originalWrite.apply(this,args);};proto.sync=async function(...args:any[]){if(kind==="sync"&&targets.has(this)){hit++;throw Object.assign(Error("private sync sentinel"),{code:"EACCES"});}return originalSync.apply(this,args);};
 try{await expect(f.newService().process(f.requestBytes,f.authHeaders())).rejects.toBeInstanceOf(ServiceUnavailableError);expect(hit).toBeGreaterThan(0);expect(await readdir(join(f.stateRoot,"nonces","records"))).toHaveLength(1);expect((await f.requests.lookup("client-1","generation-1","idem-1",serviceRequestDigest(f.request)))?.phase).toBe("reserved");await f.coordinator.withMutation(async c=>expect((await f.options.receiptStore(c).inspectCapacity()).used).toBe(0));expect(f.options.readiness.snapshot().ready).toBe(false);}finally{proto.write=originalWrite;proto.sync=originalSync;fs.promises.open=originalOpen;syncBuiltinESMExports();}
});
for(const control of ["final-root","final-inventory"] as const)it("final incoming "+control+" recheck remains422, never publishes snapshot",async()=>{
 const f=await serviceFixture(),{validateAndSnapshotBundleForService}=await import("../src/bundle.js");let hit=0;
 await expect(validateAndSnapshotBundleForService({request:f.request,incomingRoot:f.incomingRoot,snapshotRoot:f.snapshotRoot,limits:f.options.durable!.bundleLimits,nowMs:Date.parse("2030-01-01T00:05:00.000Z"),faultInjector:async(phase,path)=>{if(control==="final-root"&&phase==="bundle:before-final-identity"){hit++;await (await import("node:fs/promises")).chmod(path,0o777);}if(control==="final-inventory"&&phase==="file:after-read"&&path.endsWith("approved.md")){hit++;await writeFile(join(f.incomingRoot,"bundle-1","project","extra.txt"),"extra");}}})).rejects.toMatchObject({httpStatus:422});expect(hit).toBe(1);expect(await readdir(f.snapshotRoot)).toEqual([]);
});
