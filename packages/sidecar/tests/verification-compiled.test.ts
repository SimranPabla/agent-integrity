import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { afterEach, expect, it } from 'vitest';
import { cleanupTask7Fixtures, fixture } from './support/task7-fixture.js';
afterEach(cleanupTask7Fixtures);

it('fresh compiled production worker uses sibling JS and isolates parent execArgv', async () => {
 const repo = fileURLToPath(new URL('../../../', import.meta.url));
 const scratchParent = join(repo, 'dist');
 await mkdir(scratchParent, {recursive:true});
 const scratch = await mkdtemp(join(scratchParent, 'task7-smoke-'));
 const fixtures: Awaited<ReturnType<typeof fixture>>[] = [];
 try {
  const output = join(scratch, 'compiled');
  const config = join(scratch, 'tsconfig.json');
  // Nonincremental, no references, no shared dist writes. Compile the current
  // worker/runner and their reachable relative imports with the root compiler.
  await writeFile(config, JSON.stringify({
   extends:join(repo,'tsconfig.base.json'),
   compilerOptions:{composite:false,incremental:false,declaration:false,declarationMap:false,sourceMap:false,
    rootDir:join(repo,'packages/sidecar/src'),outDir:output},
   files:[join(repo,'packages/sidecar/src/verification-runner.ts'),join(repo,'packages/sidecar/src/verification-worker.ts')],
  }));
  await promisify(execFile)(process.execPath,[join(repo,'node_modules/typescript/bin/tsc'),'--project',config,'--pretty','false'],
   {cwd:repo,timeout:30000,maxBuffer:1048576});
  const inputs = [];
  for (const kind of ['pass','review','blocked']) {
   const f = await fixture(kind); fixtures.push(f); inputs.push({kind,input:f.input});
  }
  const inputPath = join(scratch, 'inputs.json');
  await writeFile(inputPath, JSON.stringify(inputs));
  const harness = fileURLToPath(new URL('./support/task7-compiled-smoke.mjs',import.meta.url));
  const env = {...process.env}; delete env.VITEST;
  const {stdout} = await promisify(execFile)(process.execPath,
   ['--input-type=module','--eval',await readFile(harness,'utf8'),
    join(output,'verification-runner.js'),join(output,'verification-worker.js'),inputPath],
   {cwd:repo,env,timeout:30000,maxBuffer:1048576});
  expect(stdout.trim()).toBe('compiled sibling JS: PASS REVIEW BLOCKED; parent execArgv isolated; missing/sentinel sibling enforced');
 } finally {
  // Only exact invocation-owned trees; never remove shared dist or other tests.
  await Promise.all(fixtures.map(f=>rm(f.root,{recursive:true,force:true})));
  await rm(scratch,{recursive:true,force:true});
 }
}, 60000);
