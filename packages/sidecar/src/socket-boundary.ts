import { chmod, chown, lstat, realpath, unlink } from "node:fs/promises";
import { dirname, isAbsolute, normalize } from "node:path";
import { connect } from "node:net";
import type { Stats } from "node:fs";
export interface SocketIdentityOptions {
 readonly sidecarUid: number; readonly clientGid: number;
 readonly stat?: (path: string) => Promise<Stats>; readonly resolve?: (path: string) => Promise<string>;
}
function unsafe(): never { throw new Error("SOCKET_UNSAFE"); }
function same(a: Stats,b: Stats): boolean { return a.dev===b.dev&&a.ino===b.ino&&a.uid===b.uid&&a.gid===b.gid; }
/** No TCP listener and no process identity changes. Injectable stat is test-only;
 * production always observes the actual OS. Portable parent-race limits remain. */
export class SocketBoundary {
 readonly path: string; readonly #options: SocketIdentityOptions; readonly #directory: Stats; readonly #parent: Stats;
 #socket: Stats | undefined;
 private constructor(path:string,options:SocketIdentityOptions,directory:Stats,parent:Stats) {this.path=path;this.#options=options;this.#directory=directory;this.#parent=parent;}
 static async open(path:string, options:SocketIdentityOptions):Promise<SocketBoundary> {
  if(!isAbsolute(path)||normalize(path)!==path||path.includes("\0")||Buffer.byteLength(path)>103||!Number.isSafeInteger(options.sidecarUid)||!Number.isSafeInteger(options.clientGid))unsafe();
  const stat=options.stat??lstat,resolve=options.resolve??realpath,dir=dirname(path),parent=dirname(dir);
  const d=await stat(dir),p=await stat(parent);
  if(!d.isDirectory()||d.isSymbolicLink()||d.uid!==options.sidecarUid||d.gid!==options.clientGid||(d.mode&0o7777)!==0o710||await resolve(dir)!==dir||!p.isDirectory()||p.isSymbolicLink()||p.uid!==0||(p.mode&0o022)!==0||options.sidecarUid===0&&(p.mode&0o200)!==0||await resolve(parent)!==parent)unsafe();
  return new SocketBoundary(path,Object.freeze({...options}),d,p);
 }
 async #stat(path:string):Promise<Stats>{return (this.#options.stat??lstat)(path);}
 async validateDirectory():Promise<void> {
  const d=await this.#stat(dirname(this.path)),p=await this.#stat(dirname(dirname(this.path)));
  if(!same(d,this.#directory)||!same(p,this.#parent)||!d.isDirectory()||d.isSymbolicLink()||(d.mode&0o7777)!==0o710||!p.isDirectory()||p.isSymbolicLink()||(p.mode&0o022)!==0||await(this.#options.resolve??realpath)(dirname(this.path))!==dirname(this.path))unsafe();
 }
 #requireSocket(s:Stats):void {if(!s.isSocket()||s.isSymbolicLink()||s.uid!==this.#options.sidecarUid||s.gid!==this.#options.clientGid)unsafe();}
 async isLive():Promise<boolean> {
  return new Promise((resolve,reject)=>{const s=connect(this.path);const timer=setTimeout(()=>{s.destroy();reject(new Error("SOCKET_UNAVAILABLE"));},200);const done=(value:boolean)=>{clearTimeout(timer);s.destroy();resolve(value);};s.once("connect",()=>done(true));s.once("error",(e:NodeJS.ErrnoException)=>{clearTimeout(timer);s.destroy();if(e.code==="ECONNREFUSED"||e.code==="ENOENT")resolve(false);else reject(new Error("SOCKET_UNAVAILABLE"));});});
 }
 async prepare():Promise<void> {
  await this.validateDirectory(); let before:Stats;
  try {before=await this.#stat(this.path);}catch(e){if(e instanceof Error&&(e as NodeJS.ErrnoException).code==="ENOENT")return;throw e;}
  this.#requireSocket(before);if(await this.isLive())throw new Error("SOCKET_LIVE");
  await this.validateDirectory();const after=await this.#stat(this.path);this.#requireSocket(after);if(!same(before,after))unsafe();
  if(await(this.#options.resolve??realpath)(this.path)!==this.path)unsafe();await unlink(this.path);await this.validateDirectory();
 }
 async captureBound():Promise<void> {
  await this.validateDirectory();const before=await this.#stat(this.path);
  if(!before.isSocket()||before.isSymbolicLink()||before.uid!==this.#options.sidecarUid)unsafe();
  if(before.gid!==this.#options.clientGid)await chown(this.path,this.#options.sidecarUid,this.#options.clientGid);
  await chmod(this.path,0o660);await this.validateDirectory();const after=await this.#stat(this.path);this.#requireSocket(after);
  if(before.dev!==after.dev||before.ino!==after.ino||(after.mode&0o7777)!==0o660||await(this.#options.resolve??realpath)(this.path)!==this.path)unsafe();this.#socket=after;
 }
 async validateBound():Promise<void>{await this.validateDirectory();if(!this.#socket)unsafe();const s=await this.#stat(this.path);this.#requireSocket(s);if(!same(s,this.#socket)||(s.mode&0o7777)!==0o660||await(this.#options.resolve??realpath)(this.path)!==this.path)unsafe();}
 async close(closeHandle:()=>Promise<void>):Promise<void>{await this.validateBound();await closeHandle();await this.validateDirectory();try {const s=await this.#stat(this.path);this.#requireSocket(s);if(!this.#socket||!same(s,this.#socket))unsafe();await unlink(this.path);}catch(e){if(!(e instanceof Error&&(e as NodeJS.ErrnoException).code==="ENOENT"))throw e;}}
}
