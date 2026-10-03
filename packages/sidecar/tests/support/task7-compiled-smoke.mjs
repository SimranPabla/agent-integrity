import assert from 'node:assert/strict';
import { readFile, rename, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

// Launched via --input-type=module --eval: inheriting that flag into a file
// worker is invalid in Node, so all three successful verdicts prove isolation.
assert(process.execArgv.includes('--input-type=module'));
assert.equal(process.env.VITEST, undefined);
const [runnerPath, workerPath, inputsPath] = process.argv.slice(1);
const { runTrustedVerification } = await import(pathToFileURL(runnerPath).href);
const inputs = JSON.parse(await readFile(inputsPath, 'utf8'));
for (const {kind, input} of inputs) {
 const result = await runTrustedVerification(input, {timeoutMs:5000});
 assert.equal(result.kind, 'verified', JSON.stringify(result));
 assert.equal(result.verification.status, kind.toUpperCase());
}
// Prove that the exact sibling JS is selected, not a source or stale-dist
// fallback. Changes below affect only this invocation's private compile tree.
await rename(workerPath, workerPath + '.saved');
const missing = await runTrustedVerification(inputs[0].input, {timeoutMs:5000});
assert.deepEqual(missing, {kind:'technical-failure',code:'VERIFIER_FAILURE',reason:'worker-error'});
await writeFile(workerPath, "import {parentPort} from 'node:worker_threads'; parentPort.postMessage('{}');");
const sentinel = await runTrustedVerification(inputs[0].input, {timeoutMs:5000});
assert.deepEqual(sentinel, {kind:'technical-failure',code:'VERIFIER_FAILURE',reason:'invalid-output'});
console.log('compiled sibling JS: PASS REVIEW BLOCKED; parent execArgv isolated; missing/sentinel sibling enforced');
