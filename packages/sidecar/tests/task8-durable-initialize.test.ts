import { allowDiskIntegrationTime } from "./support/disk-integration-timeout.js";
allowDiskIntegrationTime();
import { afterEach,beforeEach,expect,it,vi } from "vitest";
import { mkdtemp,mkdir,chmod,rename,rm,symlink,readFile,writeFile,readdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { DurableJsonDirectory } from "../src/durable-json.js";
let parent:string,root:string,directory:DurableJsonDirectory;
beforeEach(async()=>{parent=await mkdtemp(join(tmpdir(),"task8-init-"));await chmod(parent,0o700);root=join(parent,"state");directory=new DurableJsonDirectory(root,{maxStateBytes:4096,maxEntries:16});await directory.initialize(["records"]);});
afterEach(async()=>{vi.restoreAllMocks();await rm(parent,{recursive:true,force:true});await rm(parent+".saved",{recursive:true,force:true});});
it("healthy repeat retains exact persistent anchor",async()=>{const [name]=(await readdir(parent)).filter(n=>n.endsWith("identity.json"));const bytes=await readFile(join(parent,name!));await directory.initialize(["records"]);await directory.publishCreateOnce("records/x.json",{x:1});expect(await readFile(join(parent,name!))).toEqual(bytes);});
it.each(["root-delete","root-replace","root-symlink","root-mode","parent-replace","parent-symlink","parent-mode","owner","child-delete","child-replace","child-symlink","child-mode","anchor-delete","anchor-malformed","anchor-tamper","changed-childset"])("repeat rejects %s before mutation or repair",async(kind)=>{
 const [name]=(await readdir(parent)).filter(n=>n.endsWith("identity.json"));const anchor=join(parent,name!);
 if(kind==="root-delete")await rm(root,{recursive:true});
 if(kind==="root-replace"||kind==="root-symlink"){await rename(root,join(parent,"saved-state"));if(kind.endsWith("symlink"))await symlink(join(parent,"saved-state"),root);else await mkdir(root,{mode:0o700});}
 if(kind==="root-mode")await chmod(root,0o750);
 if(kind==="parent-replace"){await rename(parent,parent+".saved");await mkdir(parent,{mode:0o700});}
 if(kind==="parent-symlink"){await rename(parent,parent+".saved");await symlink(parent+".saved",parent);}
 if(kind==="parent-mode")await chmod(parent,0o777);
 if(kind==="owner"){const uid=process.getuid!();vi.spyOn(process,"getuid").mockReturnValue(uid+1);}
 if(kind==="child-delete")await rm(join(root,"records"),{recursive:true});
 if(kind==="child-replace"||kind==="child-symlink"){await rename(join(root,"records"),join(root,"saved-records"));if(kind.endsWith("symlink"))await symlink(join(root,"saved-records"),join(root,"records"));else await mkdir(join(root,"records"),{mode:0o700});}
 if(kind==="child-mode")await chmod(join(root,"records"),0o750);
 if(kind==="anchor-delete")await rm(anchor);
 if(kind==="anchor-malformed")await writeFile(anchor,"bad");
 if(kind==="anchor-tamper"){const data=JSON.parse(await readFile(anchor,"utf8"));data.root.ino="0";await writeFile(anchor,JSON.stringify(data));}
 await expect(directory.initialize(kind==="changed-childset"?["records","extra"]:["records"])).rejects.toThrow();
 if(kind==="child-delete")await expect(readFile(join(root,"records"))).rejects.toMatchObject({code:"ENOENT"});
 if(kind==="anchor-delete")await expect(readFile(anchor)).rejects.toMatchObject({code:"ENOENT"});
 if(kind==="changed-childset")await expect(readFile(join(root,"extra"))).rejects.toMatchObject({code:"ENOENT"});
});

it("first initialization retry preserves existing interrupted anchor authority",async()=>{
 const path=join(parent,"interrupted");let once=true;
 const fresh=new DurableJsonDirectory(path,{maxStateBytes:4096,maxEntries:16,faultInjector:point=>{if(point==="directory:before-sync"&&once){once=false;throw Error("sync interruption");}}});
 await expect(fresh.initialize(["records"])).rejects.toThrow(/sync interruption/);
 const names=(await readdir(parent)).filter(n=>n.endsWith("identity.json"));
 const before=await Promise.all(names.map(n=>readFile(join(parent,n))));
 await fresh.initialize(["records"]);await fresh.publishCreateOnce("records/x.json",{x:1});
 expect(await Promise.all(names.map(n=>readFile(join(parent,n))))).toEqual(before);
});

it("existing interrupted anchor retries the failed directory durability boundary",async()=>{
 const path=join(parent,"sync-retry");let syncAttempts=0;
 const fresh=new DurableJsonDirectory(path,{maxStateBytes:4096,maxEntries:16,faultInjector:point=>{if(point==="directory:before-sync"&&++syncAttempts<=2)throw Error("still not durable");}});
 await expect(fresh.initialize(["records"])).rejects.toThrow(/still not durable/);
 const names=(await readdir(parent)).filter(n=>n.endsWith("identity.json"));const before=await Promise.all(names.map(n=>readFile(join(parent,n))));
 await expect(fresh.initialize(["records"])).rejects.toThrow(/still not durable/);
 await fresh.initialize(["records"]);expect(syncAttempts).toBe(5);
 expect(await Promise.all(names.map(n=>readFile(join(parent,n))))).toEqual(before);
});
