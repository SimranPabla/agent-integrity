import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { afterEach, expect, it } from 'vitest';
import { cleanupTask7Fixtures, fixture } from './support/task7-fixture.js';
afterEach(cleanupTask7Fixtures);

it('each source worker reads current reachable TS and never falls back to sibling JS', async () => {
 const repo = fileURLToPath(new URL('../../../', import.meta.url));
 const parent = join(repo,'dist'); await mkdir(parent,{recursive:true});
 const scratch = await mkdtemp(join(parent,'task7-source-'));
 try {
  // All mutations belong to this invocation, never the actual source tree.
  for(const name of ['verification-runner','verification-worker','trusted-context','bundle','protocol','path-boundary'])
   await writeFile(join(scratch,name+'.ts'),await readFile(new URL('../src/'+name+'.ts',import.meta.url),'utf8'));
  await writeFile(join(scratch,'verification-worker.js'),"throw Error('stale sibling must not load');");
  const runner = await import(/* @vite-ignore */ pathToFileURL(join(scratch,'verification-runner.ts')).href);
  const f = await fixture();
  const verdict = await runner.runTrustedVerification(f.input,{timeoutMs:5000});
  expect(verdict.kind).toBe('verified');
  expect(verdict.verification.status).toBe('PASS');
  // Changing a reachable dependency between invocations must affect the next
  // actual thread, ruling out compiled/module/result caches across workers.
  await writeFile(join(scratch,'protocol.ts'),"throw Error('current dependency sentinel');");
  expect(await runner.runTrustedVerification(f.input,{timeoutMs:5000}))
   .toEqual({kind:'technical-failure',code:'VERIFIER_FAILURE',reason:'invalid-output'});
  await rm(join(scratch,'verification-worker.ts'));
  expect(await runner.runTrustedVerification(f.input,{timeoutMs:5000}))
   .toEqual({kind:'technical-failure',code:'VERIFIER_FAILURE',reason:'invalid-output'});
 } finally { await rm(scratch,{recursive:true,force:true}); }
});
