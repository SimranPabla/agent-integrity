import { afterEach, expect, it, vi } from "vitest";
import { request } from "node:http";
import { Worker } from "node:worker_threads";
import { readdir, lstat, readFile, writeFile, chmod, rename, mkdir, symlink, unlink } from "node:fs/promises";
import { join } from "node:path";
import { canonicalJson } from "@agent-integrity/core";
import { createRuntime } from "../src/runtime.js";
import { StateCoordinator } from "../src/state-coordinator.js";
import * as runner from "../src/verification-runner.js";
import { testConfig, cleanupTestConfigs } from "./support/test-config.js";
import { allowDiskIntegrationTime } from "./support/disk-integration-timeout.js";
allowDiskIntegrationTime();
it("second runtime lease rejection cannot create receipt output or change owned state",async()=>{
 const f=await testConfig(),c=await StateCoordinator.acquire(f.config.paths.stateRoot,{storeGeneration:f.config.storeGeneration,nestedLockNames:["receipts"],nestedLockPaths:{receipts:"receipts/.store-lock.json"}});
 const out=join(f.config.paths.stateRoot,"transactions","receipt-output"),before=await inventory(f.config.paths.stateRoot);
 try{await expect(lstat(out)).rejects.toMatchObject({code:"ENOENT"});await expect(createRuntime(f.configPath,{configOptions:f.identityOptions})).rejects.toThrow();expect(await inventory(f.config.paths.stateRoot)).toBe(before);await expect(lstat(out)).rejects.toMatchObject({code:"ENOENT"});await c.inspectLease();}finally{await c.close();}
});
const runtimes:Awaited<ReturnType<typeof createRuntime>>[]=[];
afterEach(async()=>{vi.restoreAllMocks();for(const r of runtimes.splice(0))await r.shutdown();await cleanupTestConfigs();});
async function get(path:string,url:string){return new Promise<{status:number;value:any}>((resolve,reject)=>{const r=request({socketPath:path,path:url},s=>{const chunks:Buffer[]=[];s.on("data",b=>chunks.push(b));s.on("end",()=>resolve({status:s.statusCode!,value:JSON.parse(Buffer.concat(chunks).toString())}));});r.on("error",reject);r.end();});}
async function inventory(root:string):Promise<string>{const rows:unknown[]=[];async function walk(path:string){for(const name of (await readdir(path)).sort()){const full=join(path,name),s=await lstat(full);rows.push([full,s.ino,s.mode,s.size,s.mtimeMs,s.isFile()?await readFile(full,"base64"):null]);if(s.isDirectory())await walk(full);}}await walk(root);return JSON.stringify(rows);}
it("real held pure verifier and queued request leave live/ready healthy without mutation admission",async()=>{
 const f=await testConfig(),r=await createRuntime(f.configPath,{configOptions:f.identityOptions});runtimes.push(r);await r.start();
 let worker!:Worker,entered!:()=>void;const online=new Promise<void>(resolve=>entered=resolve),original=runner.runTrustedVerification;
 vi.spyOn(runner,"runTrustedVerification").mockImplementation((raw,options)=>original(raw,{...options,workerFactory:input=>{worker=new Worker("const {parentPort}=require('node:worker_threads');parentPort.once('message',async()=>{await import("+JSON.stringify(new URL("../dist/verification-worker.js",import.meta.url).href)+")});",{eval:true,workerData:input,stdout:true,stderr:true});worker.once("online",entered);return worker;}}));
 const active=r.service.process(f.requestBytes,f.authHeaders());await online;
 const queued=r.service.process(f.requestBytes,f.authHeaders());expect(r.scheduler.active).toBe(true);expect(r.scheduler.queued).toBe(1);
 const before=await inventory(f.config.paths.stateRoot),mutation=vi.spyOn(r.coordinator,"withMutation");
 let ready:any;try{expect((await get(f.config.paths.socketPath,"/health/live")).status).toBe(200);ready=await get(f.config.paths.socketPath,"/health/ready");expect(mutation).not.toHaveBeenCalled();expect(await inventory(f.config.paths.stateRoot)).toBe(before);}finally{mutation.mockRestore();worker.postMessage("go");await Promise.allSettled([active,queued]);}
 expect(ready).toEqual({status:200,value:{ready:true,reasons:[]}});
});
it("fresh root lease owner substitution fails readiness while valid active authority stays held",async()=>{
 const f=await testConfig(),r=await createRuntime(f.configPath,{configOptions:f.identityOptions});runtimes.push(r);await r.start();const path=join(f.config.paths.stateRoot,"lease.json"),bytes=await readFile(path),record=JSON.parse(bytes.toString());let release!:()=>void,entered!:()=>void;const gate=new Promise<void>(v=>release=v),started=new Promise<void>(v=>entered=v);const held=r.scheduler.run(async()=>{entered();await gate;});await started;
 try{await writeFile(path,canonicalJson({...record,ownerToken:"wrong-owner"}));const ready=await get(f.config.paths.socketPath,"/health/ready");expect(ready.status).toBe(503);expect(ready.value.reasons).toContain("ROOT_LEASE");expect((await get(f.config.paths.socketPath,"/health/live")).status).toBe(200);}finally{await writeFile(path,bytes);release();await held;}
});

for(const control of ["hmac-mode","hmac-bytes","private-mode","public-binding","hmac-expiry","key-revocation","bundle-mode","snapshot-mode","socket-mode","root-generation","quota-entry","quota-symlink","quota-file-mode","root-directory-swap"] as const)it("fresh readiness fails closed for "+control+" without mutation or lock",async()=>{
 const f=await testConfig(),r=await createRuntime(f.configPath,{configOptions:f.identityOptions});runtimes.push(r);await r.start();
 const state=f.config.paths.stateRoot,quota=join(state,"receipts","quota"),lease=join(state,"lease.json");let restore=async()=>{};
 if(control==="hmac-mode")await chmod(f.config.client.hmacKeys[0]!.secretFile,0o600);
 if(control==="hmac-bytes"){const path=f.config.client.hmacKeys[0]!.secretFile;await chmod(path,0o600);await writeFile(path,Buffer.alloc(32,9));await chmod(path,0o400);}
 if(control==="private-mode")await chmod(f.config.receipt.privateKeys[0]!.privateKeyFile,0o600);
 if(control==="public-binding"){f.config.receipt.publicKeys[0]!.x="a".repeat(43);await f.save();}
 if(control==="hmac-expiry"){f.config.client.hmacKeys[0]!.notAfter="2030-01-01T00:05:00.000Z";await f.save();}
 if(control==="key-revocation"){(f.config.receipt.publicKeys[0] as any).revokedAt="2030-01-01T00:04:00.000Z";await f.save();}
 if(control==="bundle-mode")await chmod(f.config.paths.bundleRoot,0o770);
 if(control==="snapshot-mode")await chmod(join(state,"snapshots"),0o750);
 if(control==="socket-mode")await chmod(f.config.paths.socketPath,0o600);
 if(control==="root-generation"){const bytes=await readFile(lease);await writeFile(lease,canonicalJson({...JSON.parse(bytes.toString()),storeGeneration:"other"}));restore=()=>writeFile(lease,bytes);}
 if(control==="quota-entry")await writeFile(join(quota,"unexpected"),"{}",{mode:0o600});
 if(control==="quota-symlink")await symlink(lease,join(quota,"a".repeat(64)+".json"));
 if(control==="quota-file-mode")await writeFile(join(quota,"a".repeat(64)+".json"),"{}",{mode:0o644});
 if(control==="root-directory-swap"){const path=join(state,"receipts"),old=path+"-original";await rename(path,old);await mkdir(path,{mode:0o700});restore=async()=>{await rename(path,path+"-replacement");await rename(old,path);};}
 const before=await inventory(state),mutation=vi.spyOn(r.coordinator,"withMutation");
 try{const ready=await get(f.config.paths.socketPath,"/health/ready");expect(ready.status).toBe(503);expect(ready.value.reasons.length).toBeGreaterThan(0);expect((await get(f.config.paths.socketPath,"/health/live")).status).toBe(200);expect(mutation).not.toHaveBeenCalled();expect(await inventory(state)).toBe(before);}finally{mutation.mockRestore();await restore();if(control==="socket-mode")await chmod(f.config.paths.socketPath,0o660);}
});
it("nested FIFO gives repeatable503 read-only readiness and leaves no stranded health I/O",async()=>{
 const f=await testConfig(),r=await createRuntime(f.configPath,{configOptions:f.identityOptions});runtimes.push(r);await r.start();const path=join(f.config.paths.stateRoot,"receipts",".store-lock.json"),{execFileSync}=await import("node:child_process");execFileSync("mkfifo",["-m","600",path]);const before=await inventory(f.config.paths.stateRoot),mutate=vi.spyOn(r.coordinator,"withMutation");
 try{for(let i=0;i<2;i++){const ready=await get(f.config.paths.socketPath,"/health/ready");expect(ready.status).toBe(503);expect(ready.value.reasons).toContain("ROOT_LEASE");}expect(await Promise.race([r.health.drain().then(()=>true),new Promise<false>(resolve=>setTimeout(()=>resolve(false),200))])).toBe(true);expect(mutate).not.toHaveBeenCalled();expect(await inventory(f.config.paths.stateRoot)).toBe(before);expect((await get(f.config.paths.socketPath,"/health/live")).status).toBe(200);}finally{mutate.mockRestore();await unlink(path);}
});
