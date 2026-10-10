import { allowDiskIntegrationTime } from "./support/disk-integration-timeout.js";
allowDiskIntegrationTime();
import { createHash } from "node:crypto";
import { chmod, mkdtemp, readFile, readdir, rm, rename, symlink, writeFile, open, readlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it, vi } from "vitest";
import { DurableJsonDirectory, DurableRecordExistsError } from "../src/durable-json.js";
import { PrivateObjectStore } from "../src/private-object-store.js";
import { RequestStore } from "../src/request-store.js";
import { StateCoordinator } from "../src/state-coordinator.js";

it.each(["generic", "private"])("%s real link retry rejects while publication sync remains failed then resumes unchanged", async kind => {
 const parent = await mkdtemp(join(tmpdir(), "task8-publication-")); await chmod(parent, 0o700);
 let armed = false, attempts = 0;
 const faultInjector = (point:string) => { if (point === "directory:before-sync" && armed) { attempts++; throw Error("publication sync remains failed"); } };
 const root = join(parent,"state");
 const directory = new DurableJsonDirectory(root,{maxStateBytes:4096,maxEntries:10,faultInjector});
 const objects = new PrivateObjectStore(root,{maxObjects:1,faultInjector});
 const bytes = Buffer.from("same bytes"), digest = createHash("sha256").update(bytes).digest("hex");
 try {
  if (kind === "generic") await directory.initialize(["records"]); else await objects.inspectCapacity();
  armed = true;
  const publish = () => kind === "generic" ? directory.publishCreateOnce("records/x.json",{x:1}) : objects.publishCanonicalRequest(bytes,digest);
  await expect(publish()).rejects.toThrow(/publication sync remains failed/);
  const path = kind === "generic" ? join(root,"records/x.json") : join(root,"requests",digest+".json");
  const before = await readFile(path); const first = attempts; expect(first).toBeGreaterThan(0);
  await expect(publish()).rejects.toThrow(/publication sync remains failed/);
  expect(attempts).toBeGreaterThan(first); expect(await readFile(path)).toEqual(before);
  armed = false;
  if (kind === "generic") await expect(publish()).rejects.toBeInstanceOf(DurableRecordExistsError); else await expect(publish()).resolves.toBe(digest);
  expect(await readFile(path)).toEqual(before);
  expect((await readdir(join(root,kind === "generic" ? "records" : "requests"))).filter(n=>n.endsWith(".tmp"))).toEqual([]);
 } finally { armed=false; await rm(parent,{recursive:true,force:true}); }
});

it("failed real binding link cannot reserve a phase until persistent sync failure clears", async () => {
 const parent=await mkdtemp(join(tmpdir(),"task8-binding-barrier-")); await chmod(parent,0o700);
 const coordinator=await StateCoordinator.acquire(join(parent,"state"),{storeGeneration:"generation-1",nestedLockNames:[]});
 const root=join(parent,"requests"), objects=new PrivateObjectStore(join(parent,"objects"));
 let armed=false, attempts=0, initialized=false;
 const requests=new RequestStore(root,objects,{faultInjector:async point=>{
  if(point==="directory:before-sync" && armed && initialized && (await readdir(join(root,"bindings"))).some(n=>n.endsWith(".json"))) {attempts++;throw Error("binding barrier remains failed");}
 }});
 const canonicalRequest=Buffer.from("request"), requestDigest=createHash("sha256").update(canonicalRequest).digest("hex");
 const input={clientId:"client",storeGeneration:"generation-1",idempotencyKey:"idem",requestId:"req",transactionId:"tx",canonicalRequest,requestDigest};
 try {
  await requests.inspectCapacity(); initialized=true; armed=true;
  await expect(coordinator.withMutation(c=>requests.reserve(c,input))).rejects.toThrow(/binding barrier remains failed/);
  const [name]=await readdir(join(root,"bindings")), before=await readFile(join(root,"bindings",name!)), first=attempts;
  expect(await readdir(join(root,"phases"))).toEqual([]);
  await expect(coordinator.withMutation(c=>requests.reserve(c,input))).rejects.toThrow(/binding barrier remains failed/);
  expect(attempts).toBeGreaterThan(first); expect(await readdir(join(root,"phases"))).toEqual([]);
  armed=false; await expect(coordinator.withMutation(c=>requests.reserve(c,input))).resolves.toMatchObject({phase:"reserved"});
  expect(await readFile(join(root,"bindings",name!))).toEqual(before);
 } finally {armed=false;await coordinator.close();await rm(parent,{recursive:true,force:true});}
});

it.each(["bytes","symlink","mode","uid"])("existing %s conflict rejects before publication sync",async kind=>{
 const parent=await mkdtemp(join(tmpdir(),"task8-invalid-publication-"));await chmod(parent,0o700);let attempts=0;
 const directory=new DurableJsonDirectory(join(parent,"state"),{maxStateBytes:4096,maxEntries:10,faultInjector:point=>{if(point==="directory:before-sync")attempts++;}});
 try {
  await directory.initialize(["records"]);await directory.publishCreateOnce("records/x.json",{x:1});const path=directory.resolve("records/x.json"),before=await readFile(path);
  if(kind==="bytes")await writeFile(path,JSON.stringify({x:2})+"\n");
  if(kind==="symlink"){await rename(path,path+".saved");await symlink(path+".saved",path);}
  if(kind==="mode")await chmod(path,0o640);
  if(kind==="uid")vi.spyOn(process,"getuid").mockReturnValue(process.getuid!()+1);
  const first=attempts;await expect(directory.ensurePublished("records/x.json",{x:1})).rejects.toThrow();expect(attempts).toBe(first);
  if(kind!=="bytes")expect(await readFile(path)).toEqual(before);
 } finally {vi.restoreAllMocks();await rm(parent,{recursive:true,force:true});}
});

it("postvalidation real file sync failure drains held peer before releasing mutation capability",async()=>{
 const parent=await mkdtemp(join(tmpdir(),"task8-barrier-drain-"));await chmod(parent,0o700);
 const coordinator=await StateCoordinator.acquire(join(parent,"state"),{storeGeneration:"generation-1",nestedLockNames:[]});
 const objects=new PrivateObjectStore(join(parent,"objects")),requests=new RequestStore(join(parent,"requests"),objects);
 const canonicalRequest=Buffer.from("request"),requestDigest=createHash("sha256").update(canonicalRequest).digest("hex");
 const input={clientId:"client",storeGeneration:"generation-1",idempotencyKey:"idem",requestId:"req",transactionId:"tx",canonicalRequest,requestDigest};
 const phases=join(parent,"requests","phases");let release=()=>{},enteredResolve=()=>{};
 const entered=new Promise<void>(resolve=>enteredResolve=resolve),held=new Promise<void>(resolve=>release=resolve);
 let armed=false,active=0,maximum=0,failed=0,pending:Promise<unknown>|undefined,waitTimer:ReturnType<typeof setTimeout>|undefined;
 const probe=await open(parent,"r"),prototype=Object.getPrototypeOf(probe),nativeSync=prototype.sync;await probe.close();
 try {
  const verified=await coordinator.withMutation(async c=>{const reserved=await requests.reserve(c,input);return requests.advance(c,reserved,{phase:"verified",snapshotId:requestDigest,envelopeDigest:requestDigest,verificationDigest:requestDigest,verification:{protocolVersion:"1-alpha",status:"PASS",findings:[]}});});
  const names=await readdir(phases),before=await Promise.all(names.map(n=>readFile(join(phases,n))));
  prototype.sync=async function(){const info=await this.stat();const path=info.isFile()?await readlink("/proc/self/fd/"+this.fd):"";
   if(armed&&path.startsWith(phases+"/")){active++;maximum=Math.max(maximum,active);try{if(path.endsWith("-reserved.json")){failed++;throw Error("real phase file sync remains failed");}enteredResolve();await held;return await nativeSync.call(this);}finally{active--;}}
   return nativeSync.call(this);
  };
  armed=true;pending=coordinator.withMutation(c=>requests.reserve(c,input));const rejected=expect(pending).rejects.toThrow(/real phase file sync remains failed/);
  await Promise.race([entered,new Promise<void>((_,reject)=>{waitTimer=setTimeout(()=>reject(Error("held phase barrier did not start")),1000);})]);clearTimeout(waitTimer);expect(await Promise.race([pending.then(()=>"settled",()=>"settled"),new Promise<string>(resolve=>setTimeout(()=>resolve("pending"),25))])).toBe("pending");
  expect(active).toBe(1);expect(maximum).toBeLessThanOrEqual(4);expect(failed).toBe(1);
  await expect(coordinator.withMutation(async()=>{})).rejects.toThrow(/concurrent/);
  expect(await readdir(phases)).toEqual(names);release();await rejected;expect(active).toBe(0);
  expect(await Promise.all(names.map(n=>readFile(join(phases,n))))).toEqual(before);
  armed=false;await expect(coordinator.withMutation(c=>requests.reserve(c,input))).resolves.toEqual(verified);
 } finally {clearTimeout(waitTimer);release();if(pending)await Promise.allSettled([pending]);prototype.sync=nativeSync;armed=false;expect(active).toBe(0);await coordinator.close();await rm(parent,{recursive:true,force:true});}
});
