import { mkdir,mkdtemp,readFile,rm,writeFile } from 'node:fs/promises';
import {join} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {afterEach,expect,it} from 'vitest';
import {cleanupTask7Fixtures,fixture} from './support/task7-fixture.js';
afterEach(cleanupTask7Fixtures);
const probes={
 'parameter-property':"class Parent {set x(v:number){throw Error('setter invoked');}} class Child extends Parent {constructor(public readonly x:number=7){super();}} const c=new Child();if(c.x!==7||!Object.hasOwn(c,'x')||!Object.getOwnPropertyDescriptor(c,'x')?.writable)throw Error('parameter semantics');import type {Absent} from './absent-type-only.js';",
 'mutable-enum-namespace-alias':"enum Mutable {A=3,B} (Mutable as unknown as {A:number}).A=11; namespace Named {export const value=Mutable.A;} import /* supported comment */ Alias=Named; if(Mutable.A!==11||Alias.value!==11||Mutable[4]!=='B')throw Error('enum semantics changed');",
 'decorator-fallback':"function decorate(value:Function){return value;} @decorate class Decorated {x=9;}if(new Decorated().x!==9)throw Error('decorator semantics changed');",
 'invalid-syntax':"enum Broken { A=; }",
 'api-absence':"class Box {constructor(public x:number=9){}}if(new Box().x!==9)throw Error('legacy API absence semantics');",
 'async-hooks':"class Box {constructor(public x:number=9){}}if(new Box().x!==9)throw Error('async loader semantics');",
};
it.each(Object.keys(probes))('fresh source loader preserves %s or fails closed',async kind=>{
 const repo=fileURLToPath(new URL('../../../',import.meta.url)),parent=join(repo,'dist');await mkdir(parent,{recursive:true});const scratch=await mkdtemp(join(parent,'task8-loader-control-'));
 try{
  for(const name of ['verification-runner','verification-worker','trusted-context','bundle','protocol','path-boundary'])await writeFile(join(scratch,name+'.ts'),await readFile(new URL('../src/'+name+'.ts',import.meta.url),'utf8'));
  const worker=join(scratch,'verification-worker.ts');await writeFile(worker,probes[kind as keyof typeof probes]+'\n'+await readFile(worker,'utf8'));
  const runnerPath=join(scratch,'verification-runner.ts');let source=await readFile(runnerPath,'utf8');
  if(kind==='api-absence'){expect(source).toContain("typeof nodeModule.stripTypeScriptTypes==='function'");source=source.replace("typeof nodeModule.stripTypeScriptTypes==='function'","false");}
  if(kind==='async-hooks'){expect(source).toContain("typeof module.registerHooks==='function'");source=source.replace("typeof module.registerHooks==='function'","false");}
  if(kind==='mutable-enum-namespace-alias'||kind==='decorator-fallback')source=source.replace('let output;if(',"if(url.endsWith('/verification-worker.ts')&&!legacySyntax)throw new Error('legacy syntax guard missing');let output;if(");
  if(kind==='parameter-property')source=source.replace('let output;if(',"if(url.endsWith('/verification-worker.ts')&&legacySyntax)throw new Error('native parameter path not selected');let output;if(");
  await writeFile(runnerPath,source);await writeFile(join(scratch,'verification-worker.js'),"throw Error('forbidden stale sibling');");
  const runner=await import(/* @vite-ignore */pathToFileURL(runnerPath).href);const f=await fixture();const result=await runner.runTrustedVerification(f.input,{timeoutMs:5000});
  if(kind==='invalid-syntax')expect(result).toEqual({kind:'technical-failure',code:'VERIFIER_FAILURE',reason:'invalid-output'});
  else{expect(result.kind).toBe('verified');if(result.kind==='verified')expect(result.verification.status).toBe('PASS');}
 }finally{await rm(scratch,{recursive:true,force:true});}
});
