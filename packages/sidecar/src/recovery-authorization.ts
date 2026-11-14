import { createHash } from "node:crypto";
import { constants, type Stats } from "node:fs";
import { open,lstat,realpath,unlink } from "node:fs/promises";
import { isAbsolute,normalize,dirname,relative,join } from "node:path";
import { canonicalJson } from "@agent-integrity/core";
import { DurableJsonDirectory,DurableRecordExistsError } from "./durable-json.js";
import { assertMutationCapability,type MutationCapability } from "./state-coordinator.js";
const SAFE=/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u, SHA=/^[a-f0-9]{64}$/u;
const digest=(v:unknown)=>createHash("sha256").update(canonicalJson(v)).digest("hex");
export interface RecoveryAuthorization {readonly version:1;readonly action:"recover";readonly storeGeneration:string;readonly rootIdentityDigest:string;readonly abandonedOwnerToken:string;readonly issuedAt:string;readonly expiresAt:string;readonly nonce:string;}
export interface AuthorizationOptions {readonly sidecarUid:number;readonly forbiddenRoots:readonly string[];readonly now:()=>Date;readonly stat?:(path:string)=>Promise<Stats>;}
function invalid():never{throw Error("RECOVERY_AUTHORIZATION_INVALID");}
export class RecoveryAuthorizationFile {
 readonly record:RecoveryAuthorization;readonly digest:string;readonly nextOwnerToken:string;readonly #path:string;readonly #options:AuthorizationOptions;readonly #identity:Stats;
 private constructor(path:string,options:AuthorizationOptions,record:RecoveryAuthorization,identity:Stats){this.#path=path;this.#options=options;this.record=Object.freeze(record);this.digest=digest(record);this.nextOwnerToken=digest(["recovery-owner-v1",record]);this.#identity=identity;}
 static async open(path:string,options:AuthorizationOptions):Promise<RecoveryAuthorizationFile>{try{
  if(!isAbsolute(path)||normalize(path)!==path||path.includes("\0")||options.forbiddenRoots.some(root=>{const r=relative(root,path);return r===""||!r.startsWith("..")&&!isAbsolute(r);}))invalid();
  if(await realpath(path)!==path)invalid();const stat=options.stat??lstat,identity=await stat(path),parent=await stat(dirname(path));
  if(!identity.isFile()||identity.isSymbolicLink()||identity.nlink!==1||(identity.mode&0o7777)!==0o400||![0,options.sidecarUid].includes(identity.uid)||identity.size>4096||!parent.isDirectory()||parent.isSymbolicLink()||(parent.mode&0o022)!==0||![0,options.sidecarUid].includes(parent.uid))invalid();
  const h=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW);let raw:Buffer;try{const before=await h.stat();if(before.dev!==identity.dev||before.ino!==identity.ino)invalid();raw=Buffer.alloc(4097);const n=await h.read(raw,0,raw.length,0);raw=raw.subarray(0,n.bytesRead);const after=await h.stat();if(after.size!==before.size||after.mtimeMs!==before.mtimeMs||after.ctimeMs!==before.ctimeMs||raw.length!==before.size)invalid();}finally{await h.close();}
  const value=JSON.parse(raw!.toString("utf8"));if(!value||Array.isArray(value)||Object.keys(value).sort().join(",")!=="abandonedOwnerToken,action,expiresAt,issuedAt,nonce,rootIdentityDigest,storeGeneration,version"||canonicalJson(value)!==raw!.toString("utf8")||value.version!==1||value.action!=="recover"||![value.storeGeneration,value.abandonedOwnerToken,value.nonce].every(v=>typeof v==="string"&&SAFE.test(v))||typeof value.rootIdentityDigest!=="string"||!SHA.test(value.rootIdentityDigest))invalid();
  const issued=Date.parse(value.issuedAt),expiry=Date.parse(value.expiresAt),now=options.now().getTime();if(!Number.isFinite(now)||!Number.isFinite(issued)||!Number.isFinite(expiry)||new Date(issued).toISOString()!==value.issuedAt||new Date(expiry).toISOString()!==value.expiresAt||issued>now||expiry<=now||issued>=expiry)invalid();
  const after=await stat(path);if(after.dev!==identity.dev||after.ino!==identity.ino||after.mtimeMs!==identity.mtimeMs||after.ctimeMs!==identity.ctimeMs)invalid();return new RecoveryAuthorizationFile(path,options,value,identity);
 }catch{invalid();}}
 async assertUnchanged():Promise<void>{const fresh=await RecoveryAuthorizationFile.open(this.#path,this.#options);if(fresh.digest!==this.digest||fresh.#identity.dev!==this.#identity.dev||fresh.#identity.ino!==this.#identity.ino||fresh.#identity.ctimeMs!==this.#identity.ctimeMs)invalid();}
 async auditStore(stateRoot:string){const store=new DurableJsonDirectory(stateRoot+"/transactions/recovery-authorizations",{maxStateBytes:4096,maxEntries:10000});await store.initialize([]);return store;}
 auditName():string{return digest(["recovery-authorization-nonce-v1",this.record.nonce])+".json";}
 async assertUnused(stateRoot:string):Promise<void>{
  // Read-only replay preflight; initialization belongs to capability-owned consume.
  const paths=[stateRoot,join(stateRoot,"transactions"),join(stateRoot,"transactions","recovery-authorizations")];
  const seen:Stats[]=[];
  for(const path of paths){let info:Stats;try{info=await lstat(path);}catch(e){if(path===paths[2]&&(e as NodeJS.ErrnoException).code==="ENOENT"){for(let i=0;i<seen.length;i++){const fresh=await lstat(paths[i]!);if(fresh.dev!==seen[i]!.dev||fresh.ino!==seen[i]!.ino||fresh.mode!==seen[i]!.mode||fresh.uid!==seen[i]!.uid||fresh.mtimeMs!==seen[i]!.mtimeMs||fresh.ctimeMs!==seen[i]!.ctimeMs)invalid();}return;}throw e;}if(!info.isDirectory()||info.isSymbolicLink()||(info.mode&0o7777)!==0o700||info.uid!==this.#options.sidecarUid||await realpath(path)!==path)invalid();seen.push(info);}
  try{await lstat(join(paths[2]!,this.auditName()));invalid();}catch(e){if((e as NodeJS.ErrnoException).code!=="ENOENT")throw e;}
  for(let i=0;i<paths.length;i++){const fresh=await lstat(paths[i]!);if(fresh.dev!==seen[i]!.dev||fresh.ino!==seen[i]!.ino||fresh.mode!==seen[i]!.mode||fresh.uid!==seen[i]!.uid||fresh.mtimeMs!==seen[i]!.mtimeMs||fresh.ctimeMs!==seen[i]!.ctimeMs)invalid();}
 }
 async consume(stateRoot:string,capability:MutationCapability):Promise<void>{assertMutationCapability(capability);if(capability.ownerToken!==this.nextOwnerToken||capability.storeGeneration!==this.record.storeGeneration||capability.rootIdentityDigest!==this.record.rootIdentityDigest)invalid();await this.assertUnused(stateRoot);await this.assertUnchanged();const store=await this.auditStore(stateRoot),audit={version:1,authorizationDigest:this.digest,nonce:this.record.nonce,storeGeneration:this.record.storeGeneration,rootIdentityDigest:this.record.rootIdentityDigest,previousOwnerToken:this.record.abandonedOwnerToken,nextOwnerToken:this.nextOwnerToken};try{await store.publishCreateOnce(this.auditName(),audit);}catch(e){if(e instanceof DurableRecordExistsError)invalid();throw e;}await store.ensurePublished(this.auditName(),audit);await this.assertUnchanged();await unlink(this.#path);const h=await open(dirname(this.#path),constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW);try{await h.sync();}finally{await h.close();}}
}
