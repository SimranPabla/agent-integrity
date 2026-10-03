import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { constants } from 'node:fs';
import { chmod, open, rename, rm } from 'node:fs/promises';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanupTask7Fixtures, fixture } from './support/task7-fixture.js';
afterEach(cleanupTask7Fixtures);

// Substitute only after exhaustive snapshot admission, before readBoundFile opens
// the policy. This tests that second open rather than bundle admission's lstat.
const substitution = vi.hoisted(() => ({ run: undefined as undefined | (() => Promise<void>) }));
vi.mock('../src/bundle.js', async importOriginal => {
 const original = await importOriginal<typeof import('../src/bundle.js')>();
 return {...original, openPrivateBundleSnapshot: async (options: Parameters<typeof original.openPrivateBundleSnapshot>[0]) => {
  const snapshot = await original.openPrivateBundleSnapshot(options);
  await substitution.run?.();
  return snapshot;
 }};
});
import { loadTrustedVerificationContext } from '../src/trusted-context.js';

describe('trusted policy FIFO substitution', () => {
 it('rejects a FIFO on the bound-file open without waiting for a writer', async () => {
  const f = await fixture(); let rescueUsed = false;
  substitution.run = async () => {
   await rename(f.snapshot.policyFile, f.snapshot.policyFile + '.original');
   await promisify(execFile)('mkfifo', [f.snapshot.policyFile], {timeout:5000});
   await chmod(f.snapshot.policyFile, 0o600);
  };
  // Safety rescue unblocks the *old* blocking open, so a regression is a bounded
  // assertion failure, not a libuv thread leak/hung test process.
  const rescue = setTimeout(() => {
   rescueUsed = true;
   void open(f.snapshot.policyFile, constants.O_WRONLY | constants.O_NONBLOCK)
    .then(handle => handle.close()).catch(() => {});
  }, 1000);
  try {
   await expect(loadTrustedVerificationContext(f.input)).rejects.toThrow('invalid private file');
   expect(rescueUsed).toBe(false);
  } finally {
   clearTimeout(rescue); substitution.run = undefined;
   await rm(f.root, {recursive:true,force:true});
  }
 }, 10000);
});
