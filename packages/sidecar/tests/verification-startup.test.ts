import { performance } from 'node:perf_hooks';
import { afterEach, expect, it } from 'vitest';
import { runTrustedVerification } from '../src/verification-runner.js';
import { cleanupTask7Fixtures, fixture } from './support/task7-fixture.js';
afterEach(cleanupTask7Fixtures);

// This is a cold, actual worker verdict, not a mock or a warmed loader. Fixture
// setup is excluded only from this startup measurement, not from the test budget.
// This strict 1s performance target is intentionally not relaxed for contention;
// an aggregate failure remains evidence, not a reason to increase budgets.
it('cold current-source verification stays within the service startup allowance', async () => {
 const f = await fixture();
 const start = performance.now();
 const result = await runTrustedVerification(f.input, {timeoutMs:5000});
 const elapsedMs = performance.now() - start;
 console.log(JSON.stringify({measurement:'cold-current-source-verification',elapsedMs,kind:result.kind}));
 expect(result.kind).toBe('verified');
 if(result.kind === 'verified') expect(result.verification.status).toBe('PASS');
 expect(elapsedMs).toBeLessThan(1000);
});
