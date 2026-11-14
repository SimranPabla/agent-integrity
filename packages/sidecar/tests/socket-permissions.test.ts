import { afterEach, expect, it } from "vitest";
import { chmod, lstat, mkdir, mkdtemp, readFile, rm, symlink, unlink, writeFile, rename } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:net";
import { SocketBoundary } from "../src/socket-boundary.js";
const roots: string[] = []; afterEach(async () => { for (const r of roots.splice(0)) await rm(r, { recursive: true, force: true }); });
export async function socketFixture() {
 const root=await mkdtemp(join(tmpdir(),"t9-sock-"));roots.push(root); const dir=join(root,"run");await mkdir(dir,{mode:0o710});await chmod(dir,0o710);
 const socketPath=join(dir,"s.sock"), uid=process.getuid()!,gid=process.getgid()!;
 const options={sidecarUid:uid,clientGid:gid,stat:async(path:string)=> {const s=await lstat(path);return path===root?Object.assign(s,{uid:0,mode:0o40555}):s;}};
 return {root,dir,socketPath,options};
}
it("pins root-parented0710 directory and rejects regular/symlink paths without unlink",async()=> {
 const f=await socketFixture();const b=await SocketBoundary.open(f.socketPath,f.options);
 await writeFile(f.socketPath,"foreign");await expect(b.prepare()).rejects.toThrow("SOCKET_UNSAFE");expect(await readFile(f.socketPath,"utf8")).toBe("foreign");
 await unlink(f.socketPath);await symlink("missing",f.socketPath);await expect(b.prepare()).rejects.toThrow("SOCKET_UNSAFE");expect((await lstat(f.socketPath)).isSymbolicLink()).toBe(true);
});
it("rejects broad directory and parent writable by service",async()=> {const f=await socketFixture();await chmod(f.dir,0o770);await expect(SocketBoundary.open(f.socketPath,f.options)).rejects.toThrow("SOCKET_UNSAFE");});
it("real UDS live-server rejection and postbind0660; foreign replacement survives safe teardown",async()=> {
 const f=await socketFixture();const b=await SocketBoundary.open(f.socketPath,f.options);await b.prepare();const server=createServer();await new Promise<void>((r,j)=>{server.once("error",j);server.listen(f.socketPath,r);});
 await b.captureBound();expect((await lstat(f.socketPath)).mode&0o7777).toBe(0o660);
 await expect((await SocketBoundary.open(f.socketPath,f.options)).prepare()).rejects.toThrow("SOCKET_LIVE");
 await unlink(f.socketPath);await writeFile(f.socketPath,"foreign");await expect(b.close(()=>new Promise<void>(r=>server.close(()=>r())))).rejects.toThrow("SOCKET_UNSAFE");expect(await readFile(f.socketPath,"utf8")).toBe("foreign");
 // Node/libuv close itself unlinks its original path. Relocate only this test's
 // foreign object before closing the test-owned handle, then restore it.
 await unlink(f.socketPath);await new Promise<void>(r=>server.close(()=>r()));await writeFile(f.socketPath,"foreign");
});

for(const control of ["uid","gid","parent","directory-swap"] as const)it("fresh socket identity "+control+" rejects before path removal",async()=>{
 const f=await socketFixture();let changed=false;const stat=async(path:string)=>{const s=await f.options.stat(path);if(changed){if(control==="uid"&&path===f.dir)Object.assign(s,{uid:s.uid+1});if(control==="gid"&&path===f.dir)Object.assign(s,{gid:s.gid+1});if(control==="parent"&&path===f.root)Object.assign(s,{ino:s.ino+1});}return s;};
 const b=await SocketBoundary.open(f.socketPath,{...f.options,stat});await writeFile(f.socketPath,"foreign");changed=true;if(control==="directory-swap"){await rename(f.dir,f.dir+"-old");await mkdir(f.dir,{mode:0o710});await writeFile(f.socketPath,"replacement");}
 await expect(b.prepare()).rejects.toThrow("SOCKET_UNSAFE");expect(await readFile(f.socketPath,"utf8")).toBe(control==="directory-swap"?"replacement":"foreign");
});
it("real stale owned socket requires live negative and preserves substituted path",async()=>{
 const f=await socketFixture(),server=createServer();await new Promise<void>(r=>server.listen(f.socketPath,r));const before=await lstat(f.socketPath);await rename(f.socketPath,f.socketPath+"-stale");await new Promise<void>(r=>server.close(()=>r()));await rename(f.socketPath+"-stale",f.socketPath);
 const b=await SocketBoundary.open(f.socketPath,f.options);expect(await b.isLive()).toBe(false);await b.prepare();await expect(lstat(f.socketPath)).rejects.toMatchObject({code:"ENOENT"});
 const server2=createServer();await new Promise<void>(r=>server2.listen(f.socketPath,r));await rename(f.socketPath,f.socketPath+"-stale");await new Promise<void>(r=>server2.close(()=>r()));await rename(f.socketPath+"-stale",f.socketPath);const original=await lstat(f.socketPath);
 const stat=async(path:string)=>{const s=await f.options.stat(path);if(path===f.socketPath)Object.assign(s,{uid:s.uid+1});return s;};await expect((await SocketBoundary.open(f.socketPath,{...f.options,stat})).prepare()).rejects.toThrow("SOCKET_UNSAFE");expect((await lstat(f.socketPath)).ino).toBe(original.ino);expect(before.isSocket()).toBe(true);
});
