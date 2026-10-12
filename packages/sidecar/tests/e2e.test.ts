import { afterEach, expect, it } from 'vitest';
import { canonicalJson } from '@agent-integrity/core';
import { createPublicKey, verify } from 'node:crypto';
import { rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { testService, cleanupTestServices } from './support/test-service.js';
import { hash } from './support/task8-service-fixture.js';
import { allowDiskIntegrationTime } from './support/disk-integration-timeout.js';
allowDiskIntegrationTime();afterEach(cleanupTestServices);
function assertSigned(result:any, f:Awaited<ReturnType<typeof testService>>) {
 const {receiptDigest,signature,...body}=result.receipt;
 expect(receiptDigest).toBe(hash(canonicalJson({...body,signature})));
 expect(body.envelopeDigest).toBe(hash(canonicalJson(JSON.parse(f.body.toString()).envelope)));
 expect(canonicalJson(result.verification)).toBe(canonicalJson(body.verification));
 expect(result.requestId).toBe('req-1');
 const key=f.config.receipt.publicKeys.find(k=>k.kid===signature.keyId)!;
 expect(verify(null,Buffer.from(canonicalJson({protected:{algorithm:signature.algorithm,keyId:signature.keyId},body})),createPublicKey({key:{kty:'OKP',crv:'Ed25519',x:key.x},format:'jwk'}),Buffer.from(signature.value,'base64'))).toBe(true);
}
for(const outcome of ['PASS','REVIEW','BLOCKED'] as const)it('compiled UDS '+outcome+' signs and replays exact canonical bytes',async()=>{
 const f=await testService(outcome),p=await f.start();expect(p.ready).toBe(true);
 const first=await f.send();expect(first.status).toBe(200);expect(first.body.status).toBe(outcome);assertSigned(first.body,f);expect(first.raw).toBe(canonicalJson(first.body));
 if(outcome==='PASS'){const bytes=Buffer.from(first.body.releasedResponse.bytes,'base64');expect(bytes).toEqual(Buffer.from(JSON.parse(f.body.toString()).envelope.response.content));expect(hash(bytes)).toBe(first.body.releasedResponse.sha256);}else expect(first.body).not.toHaveProperty('releasedResponse');
 const counts=await f.counts();expect(counts.issued).toBe(1);expect(counts.consumed).toBe(outcome==='PASS'?1:0);
 await rm(f.config.paths.bundleRoot,{recursive:true});expect((await f.send()).raw).toBe(first.raw);expect(await f.counts()).toEqual({...counts,nonces:counts.nonces+1});
 await p.stop();
 // Restore the required root, but not the deleted incoming bundle, for startup.
 const {mkdir}=await import('node:fs/promises');await mkdir(f.config.paths.bundleRoot,{mode:0o750});
 const restarted=await f.start();expect(restarted.ready).toBe(true);expect((await f.send()).raw).toBe(first.raw);await restarted.stop();
});
it('compiled release refusal retains signed prospective PASS and no bytes',async()=>{
 const f=await testService('PASS','refuse'),p=await f.start();expect(p.ready).toBe(true);const r=await f.send();expect(r.status).toBe(200);expect(r.body.status).toBe('RELEASE_REFUSED');assertSigned(r.body,f);expect(r.body).not.toHaveProperty('releasedResponse');expect(await f.counts()).toMatchObject({issued:1,consumed:0,closed:1});await p.control('time','2030-01-01T00:05:00.000Z');expect((await f.send()).raw).toBe(r.raw);await p.stop();
});
it('replayed nonce and changed idempotency body cannot issue or consume twice',async()=>{
 const f=await testService(),p=await f.start();expect(p.ready).toBe(true);const h=f.headers(),r=await f.send(f.body,h);expect(r.status).toBe(200);const before=await f.counts();expect((await f.send(f.body,h)).status).toBe(401);expect(await f.counts()).toEqual(before);
 const changed=Buffer.from(canonicalJson({...JSON.parse(f.body.toString()),requestId:'different'}));expect((await f.send(changed)).status).toBe(409);expect((await f.send()).raw).toBe(r.raw);expect(await f.counts()).toMatchObject({issued:1,consumed:1});await p.stop();
});
it('exact receipt expiry denies persisted PASS redelivery',async()=>{
 const f=await testService(),p=await f.start();const r=await f.send();expect(r.body.status).toBe('PASS');await p.control('time',r.body.receipt.expiresAt);const expired=await f.send();expect(expired.body.error.code).toBe('RESULT_EXPIRED');expect(expired.body).not.toHaveProperty('releasedResponse');expect(await f.counts()).toMatchObject({issued:1,consumed:1});await p.stop();
});
for(const kind of ['missing','expired','future','overlong','source','decision','policy','response'] as const)it('compiled bundle boundary rejects '+kind+' without receipt or bytes',async()=>{
 const f=await testService();let body=f.body;
 if(kind==='missing')await rm(join(f.config.paths.bundleRoot,'bundle-1','manifest.json'));
 if(kind==='expired')await f.changeManifest(m=>{m.expiresAt='2030-01-01T00:05:00.000Z';});
 if(kind==='future')await f.changeManifest(m=>{m.publishedAt='2030-01-01T00:07:00.000Z';m.evidenceCompleteness.collectedAt=m.publishedAt;});
 if(kind==='overlong')await f.changeManifest(m=>{m.expiresAt='2030-01-01T00:20:00.000Z';});
 if(['source','decision','policy'].includes(kind)){const file=kind==='source'?'docs/approved.md':kind==='decision'?'integrity/decisions.yaml':'integrity/policy.yaml';await writeFile(join(f.config.paths.bundleRoot,'bundle-1/project',file),'tampered');}
 if(kind==='response'){const v=JSON.parse(body.toString());v.envelope.response.content+='!';body=Buffer.from(canonicalJson(v));}
 const p=await f.start();expect(p.ready).toBe(true);const r=await f.send(body);expect(r.status).toBe(422);expect(r.body.error.code).toBe(kind==='missing'?'BUNDLE_UNAVAILABLE':'BUNDLE_INVALID');expect(r.body).not.toHaveProperty('receipt');expect(r.body).not.toHaveProperty('releasedResponse');expect(await f.counts()).toMatchObject({issued:0,consumed:0});await p.stop();
});
it('invalid config fails before socket bind with bounded process output',async()=>{
 const f=await testService();await writeFile(f.configPath,'{}');const p=await f.start();expect(p.ready).toBe(false);expect(await p.exited).toEqual({code:1,signal:null});expect(p.output()).toBe(JSON.stringify({code:'COMMAND_FAILED'})+String.fromCharCode(10));await expect(f.send()).rejects.toThrow();
});

it('two active HMAC keys share durable client nonce uniqueness',async()=>{
 const f=await testService();const {randomBytes,createHmac}=await import('node:crypto');const secret=randomBytes(32),keyPath=join(f.root,'hmac2.key');await writeFile(keyPath,secret,{mode:0o400});
 f.config.client.hmacKeys.push({kid:'auth2',secretFile:keyPath,notBefore:'2030-01-01T00:04:00.000Z',notAfter:'2030-01-01T00:06:00.000Z',revokedAt:null});await f.save();
 const p=await f.start();expect(p.ready).toBe(true);const h=f.headers();const r=await f.send(f.body,h);expect(r.status).toBe(200);
 const second={...h,'x-agent-integrity-key-id':'auth2'};const fields=['POST','/v1/verify-release','1','cage','auth2',h['x-agent-integrity-timestamp'],h['x-agent-integrity-nonce'],hash(f.body)];
 const mac=(values:string[])=>createHmac('sha256',secret).update(Buffer.concat([Buffer.from('agent-integrity-sidecar-auth-v1'),...values.map(v=>{const b=Buffer.from(v),n=Buffer.alloc(4);n.writeUInt32BE(b.length);return Buffer.concat([n,b]);})])).digest('base64url');
 second['x-agent-integrity-signature']=mac(fields);expect((await f.send(f.body,second)).status).toBe(401);
 fields[6]=randomBytes(16).toString('hex');second['x-agent-integrity-nonce']=fields[6];second['x-agent-integrity-signature']=mac(fields);expect((await f.send(f.body,second)).raw).toBe(r.raw);expect(await f.counts()).toMatchObject({nonces:2,issued:1,consumed:1});await p.stop();
});
