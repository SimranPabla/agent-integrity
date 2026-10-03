import { Worker } from 'node:worker_threads';
import { canonicalJson, sha256Canonical } from '@agent-integrity/core';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { runTrustedVerification, parseVerificationOutput } from '../src/verification-runner.js';
import { parseVerificationInput } from '../src/trusted-context.js';
import { cleanupTask7Fixtures, fixture, verificationLimits } from './support/task7-fixture.js';
afterEach(cleanupTask7Fixtures);
const fake = (source:string) => () => new Worker(source,{eval:true});
describe('cancellable pure verification',()=>{
 it.each(['pass','review','blocked'])('verifies conformance %s with live-bound bytes',async kind=>{const f=await fixture(kind);const r=await runTrustedVerification(f.input,{timeoutMs:5000});expect(r.kind).toBe('verified');if(r.kind==='verified')expect(r.verification.status).toBe(kind.toUpperCase());});
 it.each([
  ['exception', "throw new Error('private path secret')", 'worker-error'],
  ['invalid', "require('node:worker_threads').parentPort.postMessage('{}')", 'invalid-output'],
  ['exit', 'process.exit(0)', 'worker-error'],
  ['timeout', 'setInterval(()=>{},1000)', 'timeout'],
  ['oversize', "require('node:worker_threads').parentPort.postMessage('x'.repeat(1048577))", 'invalid-output'],
 ] as const)('fails closed on worker %s and terminates', async (name, source, reason) => {
  const f = await fixture(); let worker: Worker | undefined;
  const r = await runTrustedVerification(f.input, {
   timeoutMs: name === 'timeout' ? 100 : 5000,
   workerFactory: () => { worker = fake(source)(); return worker; },
  });
  expect(r).toEqual({kind:'technical-failure',code:'VERIFIER_FAILURE',reason});
  expect(worker?.threadId).toBe(-1);
  expect(JSON.stringify(r)).not.toMatch(/secret|private path|stack/);
 });
 it('terminates after abort', async () => {
  const f = await fixture(); const controller = new AbortController(); let worker: Worker | undefined;
  const p = runTrustedVerification(f.input, {timeoutMs:5000,signal:controller.signal,workerFactory:()=>{
   worker = fake('setInterval(()=>{},1000)')(); return worker;
  }});
  controller.abort();
  expect(await p).toEqual({kind:'technical-failure',code:'VERIFIER_FAILURE',reason:'aborted'});
  expect(worker?.threadId).toBe(-1);
 });
 it('does not start on pre-abort or invalid input', async () => {
  const f = await fixture(); const controller = new AbortController(); controller.abort(); let starts = 0;
  const factory = () => { starts++; return fake('process.exit(0)')(); };
  expect(await runTrustedVerification(f.input,{timeoutMs:5000,signal:controller.signal,workerFactory:factory}))
   .toEqual({kind:'technical-failure',code:'VERIFIER_FAILURE',reason:'aborted'});
  expect(await runTrustedVerification({...f.input,limits:{...verificationLimits,maxInputBytes:1}},{timeoutMs:5000,workerFactory:factory}))
   .toEqual({kind:'technical-failure',code:'VERIFIER_FAILURE',reason:'invalid-input'});
  expect(starts).toBe(0);
 });
 it('admits exactly the canonical serialized input bytes and rejects one byte less', async () => {
  const f = await fixture();
  let exact = {...f.input,limits:{...verificationLimits,maxInputBytes:1}};
  // maxInputBytes is itself serialized: converge its decimal-width fixed point.
  for (let i = 0; i < 10; i++) {
   const size = Buffer.byteLength(canonicalJson(exact));
   if (size === exact.limits.maxInputBytes) break;
   exact = {...exact,limits:{...exact.limits,maxInputBytes:size}};
  }
  const size = Buffer.byteLength(canonicalJson(exact));
  expect(exact.limits.maxInputBytes).toBe(size);
  expect(parseVerificationInput(exact)).toEqual(exact);
  const accepted = await runTrustedVerification(exact,{timeoutMs:5000});
  expect(accepted.kind).toBe('verified');
  if (accepted.kind === 'verified') expect(accepted.verification.status).toBe('PASS');
  const under = {...exact,limits:{...exact.limits,maxInputBytes:size-1}};
  expect(Buffer.byteLength(canonicalJson(under))).toBe(size);
  expect(()=>parseVerificationInput(under)).toThrow('serialized input byte limit');
  let starts = 0;
  expect(await runTrustedVerification(under,{timeoutMs:5000,workerFactory:()=>{starts++;return fake('process.exit(0)')();}}))
   .toEqual({kind:'technical-failure',code:'VERIFIER_FAILURE',reason:'invalid-input'});
  expect(starts).toBe(0);
 });
 it('checks exact input/output byte boundaries and closed findings schema',async()=>{const f=await fixture();const output=canonicalJson({version:'1',verification:{protocolVersion:'1-alpha',status:'PASS',findings:[],envelopeDigest:sha256Canonical(f.envelope)}});const exact={...f.input,limits:{...verificationLimits,maxOutputBytes:Buffer.byteLength(output)}};expect(parseVerificationOutput(output,exact).status).toBe('PASS');expect(()=>parseVerificationOutput(output,{...exact,limits:{...exact.limits,maxOutputBytes:Buffer.byteLength(output)-1}})).toThrow();for(const verification of [{protocolVersion:'1-alpha',status:'REVIEW',findings:[],envelopeDigest:sha256Canonical(f.envelope)},{protocolVersion:'1-alpha',status:'PASS',findings:[],envelopeDigest:'0'.repeat(64)},{protocolVersion:'1-alpha',status:'PASS',findings:[],envelopeDigest:sha256Canonical(f.envelope),receipt:{}},{protocolVersion:'1-alpha',status:'BLOCKED',findings:[{code:'checker.failure',severity:'blocked',message:'secret'}],envelopeDigest:sha256Canonical(f.envelope)}])expect(()=>parseVerificationOutput(canonicalJson({version:'1',verification}),f.input)).toThrow();});
 it('leaves snapshot files byte-identical and creates no state entries',async()=>{const f=await fixture();const before=await Promise.all(f.snapshot.files.map(file=>readFile(join(f.snapshot.projectRoot,file.path))));expect((await runTrustedVerification(f.input,{timeoutMs:5000})).kind).toBe('verified');const after=await Promise.all(f.snapshot.files.map(file=>readFile(join(f.snapshot.projectRoot,file.path))));expect(after).toEqual(before);expect((await readdir(f.root)).sort()).toEqual(['incoming','snapshots']);expect(await readdir(f.snapshotRoot)).toEqual([f.snapshot.snapshotId]);});
 it('validates finding counts, bytes, unknown fields and noncanonical output',async()=>{const f=await fixture();const finding={code:'claim.test',severity:'review',message:'review'};const encode=(findings:unknown[])=>canonicalJson({version:'1',verification:{protocolVersion:'1-alpha',status:'REVIEW',findings,envelopeDigest:sha256Canonical(f.envelope)}});expect(()=>parseVerificationOutput(encode([finding,finding]),{...f.input,limits:{...verificationLimits,maxFindings:1}})).toThrow();expect(()=>parseVerificationOutput(encode([finding]),{...f.input,limits:{...verificationLimits,maxFindingBytes:1}})).toThrow();expect(()=>parseVerificationOutput(encode([{...finding,sourceBytes:'secret'}]),f.input)).toThrow();expect(()=>parseVerificationOutput(encode([finding])+' ',f.input)).toThrow();});
 it('enforces output byte bounds',async()=>{const f=await fixture();expect(await runTrustedVerification({...f.input,limits:{...verificationLimits,maxOutputBytes:1}},{timeoutMs:5000})).toEqual({kind:'technical-failure',code:'VERIFIER_FAILURE',reason:'invalid-output'});});
});
