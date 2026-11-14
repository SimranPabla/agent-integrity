import { fork, type ChildProcess } from 'node:child_process';
import { request } from 'node:http';
import { once } from 'node:events';
import { readFile, readdir, writeFile, cp, rm, symlink, lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJson } from '@agent-integrity/core';
import { testConfig, TEST_NOW, cleanupTestConfigs } from './test-config.js';
import { serviceFixture, hash } from './task8-service-fixture.js';
const children = new Set<ChildProcess>();
export async function cleanupTestServices() {
 for(const child of children) {if(child.exitCode===null && child.signalCode===null){child.kill('SIGKILL');await once(child,'exit');}children.delete(child);}
 await cleanupTestConfigs();
}
export async function testService(outcome:'PASS'|'REVIEW'|'BLOCKED'='PASS', scenario='normal') {
 const f = await testConfig();
 let body = f.requestBytes;
 if(outcome!=='PASS') {const source=await serviceFixture(TEST_NOW,outcome);body=source.requestBytes;await rm(join(f.config.paths.bundleRoot,'bundle-1'),{recursive:true});await cp(join(source.incomingRoot,'bundle-1'),join(f.config.paths.bundleRoot,'bundle-1'),{recursive:true});await source.coordinator.close();}
 let compiledDirectory: string | undefined;
 const isolateWorker = async (source: string) => {
  compiledDirectory=join(f.root,'compiled');
  await cp(fileURLToPath(new URL('../../dist/',import.meta.url)),compiledDirectory,{recursive:true});
  await symlink(fileURLToPath(new URL('../../../../node_modules',import.meta.url)),join(f.root,'node_modules'));
  await writeFile(join(f.root,'package.json'),JSON.stringify({type:'module'}));
  await writeFile(join(compiledDirectory,'verification-worker.js'),source);
 };
 const start = async (mode=scenario) => {
  const env={...process.env};delete env.VITEST;delete env.NODE_OPTIONS;
  const child=fork(fileURLToPath(new URL('./task10-process.mjs',import.meta.url)),[f.configPath,TEST_NOW.toISOString(),mode,...(compiledDirectory?[compiledDirectory]:[])],{env,execArgv:[],silent:true});children.add(child);
  let output='';child.stdout!.on('data',b=>output+=b);child.stderr!.on('data',b=>output+=b);
  const exited= new Promise<{code:number|null;signal:string|null}>(resolve=>child.once('exit',(code,signal)=>resolve({code,signal})));
  const ready=await Promise.race([once(child,'message').then(([m])=>m.ready===true),exited.then(()=>false)]);
  const control=async(command:string,value?:string)=>{const reply=once(child,'message');child.send({command,value});return (await reply)[0];};
  const stop=async()=>{if(child.exitCode===null&&child.signalCode===null){await control('shutdown');await exited;}children.delete(child);};
  return {child,ready,exited,stop,control,output:()=>output};
 };
 const headers=(bytes=body)=>{const h=f.authHeaders(bytes);return {'content-type':'application/json','x-agent-integrity-client':h.clientId,'x-agent-integrity-key-id':h.keyId,'x-agent-integrity-timestamp':h.timestampMs,'x-agent-integrity-nonce':h.nonce,'x-agent-integrity-signature':h.mac};};
 const send=async(bytes=body,h:Record<string,string>=headers(bytes),path='/v1/verify-release',method='POST')=>new Promise<{status:number;raw:string;body:any}>((resolve,reject)=>{
  const req=request({socketPath:f.config.paths.socketPath,path,method,headers:h},response=>{const chunks:Buffer[]=[];response.on('data',b=>chunks.push(b));response.on('end',()=>{const raw=Buffer.concat(chunks).toString();try{resolve({status:response.statusCode!,raw,body:JSON.parse(raw)});}catch(error){reject(error);}});});req.on('error',reject);req.end(bytes);
 });
 const manifestPath=join(f.config.paths.bundleRoot,'bundle-1','manifest.json');
 const changeManifest=async(change:(m:any)=>void)=>{const m=JSON.parse(await readFile(manifestPath,'utf8'));change(m);delete m.manifestDigest;m.manifestDigest=hash(canonicalJson(m));await writeFile(manifestPath,canonicalJson(m));};
 const saveCrashProof=async(point:string,stage:string,observation:unknown={})=>{
  const proof=process.env.TASK10_PROOF_DIR;if(!proof)return;
  const inventory:unknown[]=[];
  const visit=async(directory:string,prefix='')=>{for(const entry of await readdir(directory,{withFileTypes:true})){
   const path=join(directory,entry.name),relative=prefix+entry.name,s=await lstat(path);
   inventory.push({path:relative,dev:s.dev,ino:s.ino,nlink:s.nlink,mode:s.mode&0o7777,bytes:s.size,type:entry.isDirectory()?'directory':entry.isSymbolicLink()?'symlink':'file',...(entry.isFile()?{sha256:hash(await readFile(path))}:{})});
   if(entry.isDirectory())await visit(path,relative+'/');
  }};
  await visit(f.config.paths.stateRoot);
  await writeFile(join(proof,'crash-'+point.replaceAll(':','-')+'-'+stage+'.json'),JSON.stringify({point,stage,observation,inventory},null,2));
 };
 const counts=async()=>{const count=async(path:string)=>{try{return (await readdir(join(f.config.paths.stateRoot,path))).length;}catch(e){if((e as NodeJS.ErrnoException).code==='ENOENT')return 0;throw e;}};return {nonces:await count('nonces/records'),issued:await count('receipts/issued'),consumed:await count('receipts/consumed'),closed:await count('receipts/closed')};};
 return {...f,body,start,headers,send,changeManifest,counts,isolateWorker,saveCrashProof};
}
