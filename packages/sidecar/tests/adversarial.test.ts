import { afterEach, expect, it } from 'vitest';
import { canonicalJson } from '@agent-integrity/core';
import { chmod, readFile, readdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { testService, cleanupTestServices } from './support/test-service.js';
import { allowDiskIntegrationTime } from './support/disk-integration-timeout.js';
allowDiskIntegrationTime();afterEach(cleanupTestServices);
for(const phase of ['reserved','verified','receipt-prepared','receipt-issued','consumed-before-journal','pass-consumed','result-committed'])it('SIGKILL '+phase+' needs explicit abandoned handoff then original bound retry',async()=>{
 const f=await testService('PASS','crash:'+phase),p=await f.start();expect(p.ready).toBe(true);await expect(f.send()).rejects.toThrow();expect(await p.exited).toEqual({code:null,signal:'SIGKILL'});
 const before=await f.counts();const phases=await readdir(join(f.config.paths.stateRoot,'requests/phases'));expect(phases.length).toBeGreaterThan(0);
 const stopped=await f.start('normal');expect(stopped.ready).toBe(false);expect((await stopped.exited).code).toBe(1);expect(await f.counts()).toEqual(before);
 const recovered=await f.start('recover');expect(recovered.ready).toBe(true);const r=await f.send();expect(r.status).toBe(200);expect(r.body.status).toBe(phase==='receipt-issued'?'RELEASE_REFUSED':'PASS');expect(r.body.requestId).toBe('req-1');
 if(r.body.status==='RELEASE_REFUSED')expect(r.body).not.toHaveProperty('releasedResponse');
 expect((await f.send()).raw).toBe(r.raw);expect(await f.counts()).toMatchObject({issued:1,consumed:phase==='receipt-issued'?0:1});await recovered.stop();
});
it('simultaneous clients share one transaction; second process cannot own live state',async()=>{
 const f=await testService(),p=await f.start();expect(p.ready).toBe(true);const second=await f.start();expect(second.ready).toBe(false);expect((await second.exited).code).toBe(1);
 const [a,b]=await Promise.all([f.send(),f.send()]);expect(a.status).toBe(200);expect(b.raw).toBe(a.raw);expect(await f.counts()).toMatchObject({issued:1,consumed:1});await p.stop();
});
for(const attack of ['bad-mac','noncanonical','oversize','unknown-field','claims','sections','evidence','decisions'])it('compiled preadmission '+attack+' bounds disclose no content and mutate no stores',async()=>{
 const f=await testService(),p=await f.start();expect(p.ready).toBe(true);let body=f.body;const h:Record<string,string>=f.headers();
 if(attack==='bad-mac')h['x-agent-integrity-signature']='A'.repeat(43);
 if(attack==='noncanonical')body=Buffer.concat([body,Buffer.from(' ')]);
 if(attack==='oversize')body=Buffer.alloc(1048577,32);
 if(attack==='unknown-field')body=Buffer.from(canonicalJson({...JSON.parse(body.toString()),secret:'sentinel-sensitive'}));
 if(['claims','sections','evidence','decisions'].includes(attack)){const v=JSON.parse(body.toString()),e=v.envelope;
  if(attack==='decisions')e.decisions=Array.from({length:10001},(_,i)=>({eventId:'e'+i,decisionId:'d'+i,revision:1,action:'activate'}));
  else {const values=attack==='sections'?e.response.sections:e[attack];const list=Array.from({length:10001},()=>values[0]);if(attack==='sections')e.response.sections=list;else e[attack]=list;}
  body=Buffer.from(canonicalJson(v));
 }
 const r=await f.send(body,h);expect([400,401,413,422]).toContain(r.status);expect(Object.keys(r.body).sort()).toEqual(['error','requestId','serviceProtocolVersion'].filter(k=>k!=='requestId'||r.body.requestId!==undefined).sort());expect(r.body).not.toHaveProperty('receipt');expect(r.body).not.toHaveProperty('releasedResponse');expect(await f.counts()).toEqual({nonces:0,issued:0,consumed:0,closed:0});
 const disclosure=r.raw+p.output();for(const secret of [f.root,JSON.parse(f.body.toString()).envelope.response.content,'sentinel-sensitive',await readFile(f.config.receipt.privateKeys[0]!.privateKeyFile,'utf8'),(await readFile(f.config.client.hmacKeys[0]!.secretFile)).toString('base64')])expect(disclosure).not.toContain(secret);await p.stop();
});
for(const path of ['signer.pem','hmac.key','state','state/receipts'])it('compiled startup rejects broadened '+path+' mode',async()=>{
 const f=await testService();await chmod(join(f.root,path),path.includes('state')?0o755:0o644);const p=await f.start();expect(p.ready).toBe(false);expect((await p.exited).code).toBe(1);expect(p.output()).toBe(JSON.stringify({code:'COMMAND_FAILED'})+String.fromCharCode(10));await expect(f.send()).rejects.toThrow();
});

for(const point of ['transaction:after-publish','quota:after-publish','run:after-publish','nonce:after-publish','issued:after-publish','receipt-output:after-publish','consumed:after-publish'])it('real process crash after '+point+' reconstructs exactly one receipt and consumption',async()=>{
 const f=await testService('PASS','crash-store:'+point),p=await f.start();expect(p.ready).toBe(true);await expect(f.send()).rejects.toThrow();expect(await p.exited).toEqual({code:null,signal:'SIGKILL'});
 await f.saveCrashProof(point,'at-crash',{exit:await p.exited,counts:await f.counts()});
 const preparedFiles=(await readdir(join(f.config.paths.stateRoot,'requests/phases'))).filter(n=>n.endsWith('-receipt-prepared.json'));expect(preparedFiles).toHaveLength(1);
 const original=JSON.parse(await readFile(join(f.config.paths.stateRoot,'requests/phases',preparedFiles[0]!), 'utf8'));
 const recovered=await f.start('recover');await f.saveCrashProof(point,'after-handoff',{ready:recovered.ready,output:recovered.output()});expect(recovered.ready).toBe(true);const r=await f.send();await f.saveCrashProof(point,'after-retry',{status:r.status,error:r.body.error??null,counts:await f.counts()});expect(r.status).toBe(200);expect(r.body.status).toBe('PASS');expect(r.body.receipt.runId).toBe(original.runId);expect(r.body.receipt.nonce).toBe(original.receiptNonce);expect(r.body.receipt.createdAt).toBe(original.createdAt);
 expect((await f.send()).raw).toBe(r.raw);expect(await f.counts()).toMatchObject({issued:1,consumed:1});await recovered.stop();
});

for(const scenario of ['timeout','malformed'])it('isolated compiled worker '+scenario+' cannot mutate receipt state or leak stderr',async()=>{
 const f=await testService();const source="import {parentPort} from 'node:worker_threads';console.log('worker-private-output');console.error('worker-secret-output');"+(scenario==='timeout'?"setInterval(()=>{},1000);":"parentPort.postMessage(JSON.stringify({version:'1',verification:{status:'PASS'}}));");
 await f.isolateWorker(source);const p=await f.start();expect(p.ready).toBe(true);const r=await f.send();expect(r.status).toBe(503);expect(r.body.error.code).toBe('VERIFIER_FAILURE');expect(r.body).not.toHaveProperty('releasedResponse');expect(r.body).not.toHaveProperty('receipt');expect(await f.counts()).toMatchObject({issued:0,consumed:0});expect(p.output()+r.raw).not.toContain('worker-private-output');expect(p.output()+r.raw).not.toContain('worker-secret-output');await p.stop();
});

it('compiled receipt quota exhaustion preserves first issued and consumed receipt with no second bytes',async()=>{
 const f=await testService('PASS','quota-one'),p=await f.start();expect(p.ready).toBe(true);const first=await f.send();expect(first.body.status).toBe('PASS');
 const v=JSON.parse(f.body.toString());v.requestId='req-2';v.idempotencyKey='idem-2';const body=Buffer.from(canonicalJson(v));await f.changeManifest(m=>{m.requestId='req-2';});
 const second=await f.send(body);expect(second.status).toBe(503);expect(second.body).not.toHaveProperty('receipt');expect(second.body).not.toHaveProperty('releasedResponse');expect(await f.counts()).toMatchObject({issued:1,consumed:1});await p.stop();
});
it('compiled prepared receipt recovery retains original key across valid two-key signing rotation',async()=>{
 const f=await testService('PASS','crash:receipt-prepared'),p=await f.start();expect(p.ready).toBe(true);await expect(f.send()).rejects.toThrow();expect((await p.exited).signal).toBe('SIGKILL');
 const {generateKeyPairSync}=await import('node:crypto'),pair=generateKeyPairSync('ed25519'),keyPath=join(f.root,'signer2.pem');await writeFile(keyPath,pair.privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o400});f.config.receipt.privateKeys.push({kid:'key2',privateKeyFile:keyPath});f.config.receipt.publicKeys.push({kid:'key2',x:pair.publicKey.export({format:'jwk'}).x!,notBefore:'2029-01-01T00:00:00.000Z',notAfter:'2031-01-01T00:00:00.000Z',revokedAt:null});f.config.receipt.activeKeyId='key2';await f.save();
 const recovered=await f.start('recover');expect(recovered.ready).toBe(true);const r=await f.send();expect(r.body.status).toBe('PASS');expect(r.body.receipt.signature.keyId).toBe('key1');expect((await f.send()).raw).toBe(r.raw);expect(await f.counts()).toMatchObject({issued:1,consumed:1});await recovered.stop();
});

it('staging recovery cannot run with forged capability or an ordinary live coordinator',async()=>{
 const {serviceFixture}=await import('./support/task8-service-fixture.js');const f=await serviceFixture();
 await f.coordinator.withMutation(async c=>{await f.options.receiptStore(c).inspectCapacity();});
 const staged=join(f.stateRoot,'receipts/.staging/.integrity-00000000-0000-4000-8000-000000000000.tmp');await writeFile(staged,'unpublished-test-state',{mode:0o600});
 await expect(f.coordinator.completeNestedLockHandoff({} as never)).rejects.toThrow(/capability/);
 await expect(f.coordinator.withMutation(c=>f.coordinator.completeNestedLockHandoff(c))).rejects.toThrow(/offline recovery/);
 expect(await readFile(staged,'utf8')).toBe('unpublished-test-state');await f.coordinator.inspectLease();await f.coordinator.close();
});

// SPEC-T10-01: actual process death, not exception/finally cleanup.
for (const point of ['closed:after-publish', 'release-refused']) it('actual refusal SIGKILL '+point+' preserves original signed PASS and terminal no-byte replay', async () => {
 const {lstat}=await import('node:fs/promises');
 const {createPublicKey,verify}=await import('node:crypto');
 const {hash}=await import('./support/task8-service-fixture.js');
 const f=await testService('PASS',point==='closed:after-publish'?'refuse-crash-store:'+point:'refuse-crash:'+point);
 const inventory=async()=>{
  const files=new Map<string,{dev:number;ino:number;nlink:number;sha256:string;text:string}>();
  const visit=async(dir:string,prefix='')=>{for(const e of await readdir(dir,{withFileTypes:true})){
   const name=prefix+e.name,path=join(dir,e.name);if(e.isDirectory())await visit(path,name+'/');
   else if(e.isFile()){const s=await lstat(path),bytes=await readFile(path);files.set(name,{dev:s.dev,ino:s.ino,nlink:s.nlink,sha256:hash(bytes),text:bytes.toString('utf8')});}
  }};await visit(f.config.paths.stateRoot);return files;
 };
 const p=await f.start();expect(p.ready).toBe(true);
 await expect(f.send()).rejects.toThrow();expect(await p.exited).toEqual({code:null,signal:'SIGKILL'});
 const crashed=await inventory(),before=await f.counts();expect(before).toEqual({nonces:1,issued:1,consumed:0,closed:1});
 const phaseFiles=[...crashed.keys()].filter(n=>n.endsWith('-receipt-issued.json'));expect(phaseFiles).toHaveLength(1);
 const original=JSON.parse(crashed.get(phaseFiles[0]!)!.text),receipt=original.receipt,request=JSON.parse(f.body.toString());
 await f.saveCrashProof('refusal-'+point,'initial-original',{exit:await p.exited,counts:before,original,request});
 expect(original).toMatchObject({phase:'receipt-issued',clientId:f.config.client.clientId,storeGeneration:f.config.storeGeneration,requestId:request.requestId,requestDigest:hash(f.body),requestObjectId:hash(f.body),idempotencyKeyHash:hash(request.idempotencyKey),envelopeDigest:hash(canonicalJson(request.envelope))});
 expect(receipt.verification.status).toBe('PASS');expect(receipt.receiptDigest).toBe(original.receiptDigest);
 for(const key of ['runId','createdAt','expiresAt','issuer','audience','purpose','engineVersion','envelopeDigest'])expect(receipt[key]).toBe(original[key]);
 expect(receipt.nonce).toBe(original.receiptNonce);expect(receipt.policyDigest).toBe(hash(canonicalJson(request.envelope.policy)));
 expect(original.signingTime).toBe(original.createdAt);expect(original.maxLifetimeMs).toBe(f.config.receipt.maximumReceiptLifetimeSeconds*1000);
 for(const key of ['issuer','audience','purpose','engineVersion'])expect(original[key]).toBe(f.config.receipt[key as keyof typeof f.config.receipt]);
 expect(receipt.signature.keyId).toBe(original.keyId);expect(original.keyId).toBe('key1');
 const registryRecord=JSON.parse(crashed.get('transactions/private-objects/registries/'+original.trustSnapshotObjectId+'.json')!.text);
 expect(registryRecord).toMatchObject({version:1,kind:'public-trust-registry',sha256:original.trustSnapshotDigest});
 const registryText=Buffer.from(registryRecord.bytes,'base64url').toString('utf8');
 expect(hash(registryText)).toBe(original.trustSnapshotDigest);expect(original.trustSnapshotObjectId).toBe(original.trustSnapshotDigest);
 const registry=JSON.parse(registryText);expect(registry).toEqual(f.config.receipt.publicKeys);const key=registry.find((k:any)=>k.kid===original.keyId);
 expect(hash(canonicalJson(key))).toBe(original.publicKeyDigest);
 const {receiptDigest,signature,...signedBody}=receipt;expect(hash(canonicalJson({...signedBody,signature}))).toBe(receiptDigest);
 expect(verify(null,Buffer.from(canonicalJson({protected:{algorithm:signature.algorithm,keyId:signature.keyId},body:signedBody})),createPublicKey({key:{kty:'OKP',crv:'Ed25519',x:key.x},format:'jwk'}),Buffer.from(signature.value,'base64'))).toBe(true);
 const requestRecord=JSON.parse(crashed.get('transactions/private-objects/requests/'+original.requestObjectId+'.json')!.text);
 expect(requestRecord).toMatchObject({version:1,kind:'canonical-request',sha256:original.requestDigest});expect(Buffer.from(requestRecord.bytes,'base64url')).toEqual(f.body);
 expect(JSON.parse(crashed.get('transactions/receipt-output/'+original.receiptOutputName)!.text)).toEqual(receipt);
 const closedPath='receipts/closed/'+receiptDigest+'.json',closed=JSON.parse(crashed.get(closedPath)!.text);
 expect(closed).toMatchObject({transactionId:original.transactionId,receiptDigest});
 const refusedFiles=[...crashed.keys()].filter(n=>n.endsWith('-release-refused.json'));
 expect(refusedFiles).toHaveLength(point==='release-refused'?1:0);
 const refused=refusedFiles.length?JSON.parse(crashed.get(refusedFiles[0]!)!.text):undefined;
 if(refused){const {phase,...bindings}=original;expect(refused).toMatchObject(bindings);expect(refused.closedMarkerDigest).toBe(hash(canonicalJson(closed)));expect(refused.response.receipt).toEqual(receipt);expect(refused.response).not.toHaveProperty('releasedResponse');}
 const lease=JSON.parse(crashed.get('lease.json')!.text);
 await f.saveCrashProof('refusal-'+point,'at-crash',{exit:await p.exited,counts:before,original,closed,refused,request});
 const stopped=await f.start('normal');expect(stopped.ready).toBe(false);expect(await stopped.exited).toEqual({code:1,signal:null});expect(await f.counts()).toEqual(before);expect(await inventory()).toEqual(crashed);
 await f.saveCrashProof('refusal-'+point,'ordinary-start-denied',{counts:await f.counts()});
 const recovered=await f.start('recover');expect(recovered.ready).toBe(true);
 const handoff=await inventory(),handoffs=[...handoff.keys()].filter(n=>n.startsWith('handoffs/'));expect(handoffs).toHaveLength(1);
 const ownership=JSON.parse(handoff.get(handoffs[0]!)!.text);expect(ownership).toMatchObject({previousOwnerToken:lease.ownerToken,storeGeneration:lease.storeGeneration,rootIdentityDigest:lease.rootIdentityDigest,nestedLockNames:lease.nestedLockNames,nestedLockPaths:lease.nestedLockPaths,nestedDirectoryIdentities:lease.nestedDirectoryIdentities});expect(ownership.ownerToken).not.toBe(lease.ownerToken);
 const preserved=[...crashed].filter(([name])=>!name.includes('/.staging/')&&!name.endsWith('.store-lock.json'));
 const checkPreserved=(current:typeof crashed)=>{for(const [name,file] of preserved){const next=current.get(name);expect(next,name+' must retain original inode/hash').toMatchObject({dev:file.dev,ino:file.ino,sha256:file.sha256,text:file.text});expect(next!.nlink,name+' must be a single link').toBe(1);}};
 checkPreserved(handoff);expect(await f.counts()).toEqual(before);
 expect(crashed.get(closedPath)!.nlink).toBe(point==='closed:after-publish'?2:1);
 await f.saveCrashProof('refusal-'+point,'after-handoff',{ownership,original,closed,counts:await f.counts(),originalFilesPreserved:preserved.length});
 const result=await f.send();expect(result.status).toBe(200);expect(result.body).toMatchObject({status:'RELEASE_REFUSED',requestId:original.requestId,receipt,verification:receipt.verification});expect(result.body).not.toHaveProperty('releasedResponse');expect(result.raw).toBe(canonicalJson(result.body));if(refused)expect(result.raw).toBe(canonicalJson(refused.response));
 const retry=await f.send();expect(retry.raw).toBe(result.raw);expect(retry.body).not.toHaveProperty('releasedResponse');expect(await f.counts()).toEqual({nonces:3,issued:1,consumed:0,closed:1});
 checkPreserved(await inventory());expect(JSON.parse((await inventory()).get(closedPath)!.text)).toEqual(closed);
 await f.saveCrashProof('refusal-'+point,'after-retry',{original,closed,status:result.status,response:result.body,canonicalResponse:result.raw,byteIdenticalRetry:retry.raw===result.raw,counts:await f.counts(),originalFilesPreserved:preserved.length});
 await recovered.stop();const restarted=await f.start();expect(restarted.ready).toBe(true);expect((await f.send()).raw).toBe(result.raw);expect(await f.counts()).toMatchObject({issued:1,consumed:0,closed:1});await restarted.stop();
});
