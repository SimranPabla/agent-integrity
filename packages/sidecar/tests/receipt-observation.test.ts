import { afterEach,expect,it,vi } from "vitest";
import { createHash } from "node:crypto";
import { chmod,lstat,readdir,readFile,writeFile,symlink,rename,mkdir,link } from "node:fs/promises";
import { join } from "node:path";
import { FileReceiptStore } from "@agent-integrity/core";
import { serviceFixture,cleanupServiceFixtures } from "./support/task8-service-fixture.js";
import { allowDiskIntegrationTime } from "./support/disk-integration-timeout.js";
allowDiskIntegrationTime();afterEach(cleanupServiceFixtures);
const name=(n:number)=>createHash("sha256").update(String(n)).digest("hex")+".json";
const record=(slot:number)=>({version:3,runId:"run",nonce:"nonce",receiptDigest:"a".repeat(64),quotaSlot:slot,transactionId:"transaction"});
for(const control of ["entry","symlink","mode","hardlink","slot","oversize","quota-directory-mode","directory-swap","maximum"] as const)it("fresh capacity observation rejects "+control+" without lock or writes",async()=>{
 const f=await serviceFixture(),path=join(f.stateRoot,"receipts"),store=new FileReceiptStore(path,{maxRecords:2});await store.inspectCapacity();const quota=join(path,"quota"),file=join(quota,name(0));
 await writeFile(file,JSON.stringify(record(0)),{mode:0o600});expect(await store.observeCapacity()).toEqual({used:1,maximum:2});
 if(control==="entry")await writeFile(join(quota,"foreign"),"{}");if(control==="symlink")await symlink(file,join(quota,name(1)));if(control==="mode")await chmod(file,0o644);if(control==="hardlink")await link(file,join(quota,name(1)));if(control==="slot")await writeFile(file,JSON.stringify(record(1)));if(control==="oversize")await writeFile(file," ".repeat(1048577));if(control==="quota-directory-mode")await chmod(quota,0o750);if(control==="maximum")for(const slot of [1,2])await writeFile(join(quota,name(slot)),JSON.stringify(record(slot)),{mode:0o600});
 if(control==="directory-swap"){await rename(quota,quota+"-old");await mkdir(quota,{mode:0o750});}
 const before=await readdir(path),lock=vi.spyOn(store,"withLock" as any);try{await expect(store.observeCapacity()).rejects.toThrow();expect(lock).not.toHaveBeenCalled();expect(await readdir(path)).toEqual(before);await expect(lstat(join(path,".store-lock.json"))).rejects.toMatchObject({code:"ENOENT"});}finally{lock.mockRestore();}
});
it("normal fresh observation sees new quota and cannot rely on healthy cache",async()=>{const f=await serviceFixture(),path=join(f.stateRoot,"receipts"),store=new FileReceiptStore(path,{maxRecords:2});await store.inspectCapacity();expect(await store.observeCapacity()).toEqual({used:0,maximum:2});await writeFile(join(path,"quota",name(0)),JSON.stringify(record(0)),{mode:0o600});expect(await store.observeCapacity()).toEqual({used:1,maximum:2});});
it("nested FIFO lease observation rejects promptly without a writer",async()=>{
 const f=await serviceFixture(),path=join(f.stateRoot,"receipts",".store-lock.json");
 const {execFileSync}=await import("node:child_process"),{open,unlink}=await import("node:fs/promises"),{constants}=await import("node:fs");execFileSync("mkfifo",["-m","600",path]);
 let settled=false;const probe=f.coordinator.inspectLease().then(()=>{settled=true;return null;},e=>{settled=true;return e;});await new Promise(r=>setTimeout(r,150));const bounded=settled;
 if(!settled){const writer=await open(path,constants.O_WRONLY|constants.O_NONBLOCK);await writer.close();}
 const failure=await probe;await unlink(path);expect(failure).toBeInstanceOf(Error);expect(bounded).toBe(true);
});
it("quota regular-to-FIFO replacement cannot strand capacity observation",async()=>{
 const f=await serviceFixture(),path=join(f.stateRoot,"receipts"),store=new FileReceiptStore(path,{maxRecords:2});await store.inspectCapacity();const file=join(path,"quota",name(0));await writeFile(file,JSON.stringify(record(0)),{mode:0o600});
 const fs=(await import("node:fs")).default,{syncBuiltinESMExports}=await import("node:module"),{execFileSync}=await import("node:child_process");const original=fs.promises.open;let swapped=false;
 fs.promises.open=async function(p:any,...args:any[]){if(String(p)===file&&!swapped){swapped=true;await fs.promises.unlink(file);execFileSync("mkfifo",["-m","600",file]);}return (original as any)(p,...args);};syncBuiltinESMExports();
 let settled=false;const probe=store.observeCapacity().then(()=>{settled=true;return null;},e=>{settled=true;return e;});try{await new Promise(r=>setTimeout(r,150));const bounded=settled;if(!settled){const writer=await original(file,fs.constants.O_WRONLY|fs.constants.O_NONBLOCK);await writer.close();}expect(await probe).toBeInstanceOf(Error);expect(swapped).toBe(true);expect(bounded).toBe(true);}finally{fs.promises.open=original;syncBuiltinESMExports();}
});
