import { allowDiskIntegrationTime } from "./support/disk-integration-timeout.js";
allowDiskIntegrationTime();
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { canonicalJson } from '@agent-integrity/core';
import { serviceRequestDigest } from '../src/protocol.js';
import { serviceFixture, cleanupServiceFixtures } from './support/task8-service-fixture.js';
afterEach(async () => { try { await cleanupServiceFixtures(); } finally { vi.restoreAllMocks(); } });
import { classifyDurableRecovery } from '../src/recovery.js';
describe('Task 8 crash recovery boundaries', () => {
    it('prepared publication must reconcile the issued record, never issue again', () => {
        expect(classifyDurableRecovery('receipt-prepared')).toBe('RECONCILE_ISSUE');
    });
    it('consume-before-journal must inspect consumption, never consume again', () => {
        expect(classifyDurableRecovery('receipt-issued')).toBe('INSPECT_CONSUMPTION');
    });
    it('committed-before-wire must replay immutable completed result', () => {
        expect(classifyDurableRecovery('result-committed')).toBe('REPLAY_RESULT');
    });
    it.each(['unknown', '', 'consumed', 'receipt_prepared', 'completed'])('unrecognized state %s fails closed', state => {
        expect(() => classifyDurableRecovery(state)).toThrow();
    });
});
describe('real disk and SDK restart recovery', () => {
    it.each(['reserved', 'verified', 'receipt-prepared', 'receipt-issued', 'pass-consumed', 'result-committed'])('recovers after %s publication with original transaction', async (phase) => {
        const f = await serviceFixture();
        return f.trackOperation(async () => {
            const advance = f.requests.advance.bind(f.requests);
            let fired = false;
            vi.spyOn(f.requests, 'advance').mockImplementation(async (...args) => { const result = await advance(...args); if (!fired && result.phase === phase) {
                fired = true;
                throw new Error('crash after ' + phase);
            } return result; });
            if (phase === 'reserved') {
                const reserve = f.requests.reserve.bind(f.requests);
                vi.spyOn(f.requests, 'reserve').mockImplementation(async (...args) => { const result = await reserve(...args); throw new Error('crash after reserved'); });
            }
            await expect(f.newService().process(f.requestBytes, f.authHeaders())).rejects.toThrow();
            vi.restoreAllMocks();
            const interrupted = await f.requests.lookup('client-1', 'generation-1', 'idem-1', serviceRequestDigest(f.request));
            expect(interrupted?.phase).toBe(phase);
            await f.restart();
            const result = await f.newService().process(f.requestBytes, f.authHeaders());
            expect(result.status).toBe(phase === 'receipt-issued' ? 'RELEASE_REFUSED' : 'PASS');
            expect(await f.newService().process(f.requestBytes, f.authHeaders())).toEqual(result);
            if (!('receipt' in result))
                throw new Error('missing receipt');
            if (phase === 'receipt-issued') {
                expect(await f.store().inspectConsumed(result.receipt.receiptDigest)).toBeUndefined();
                expect(await f.store().inspectClosed(result.receipt.receiptDigest)).toMatchObject({ transactionId: 'transaction-1', reasonCode: 'RELEASE_BLOCKED' });
                expect(result).not.toHaveProperty('releasedResponse');
            }
            else
                expect(await f.store().inspectConsumed(result.receipt.receiptDigest)).toMatchObject({ transactionId: 'transaction-1', runId: 'run-1', nonce: 'nonce-1' });
            const issuedName = (await readdir(join(f.stateRoot, 'requests/phases'))).find(name => name.endsWith('-receipt-issued.json'));
            if (!issuedName) throw new Error('missing original issued phase');
            const issuedState = JSON.parse(await readFile(join(f.stateRoot, 'requests/phases', issuedName), 'utf8'));
            expect(canonicalJson(JSON.parse(await readFile(join(f.outputRoot, issuedState.receiptOutputName), 'utf8')))).toBe(canonicalJson(result.receipt));
            await f.coordinator.close();
        });
    });
    describe.each(['transaction:after-publish', 'quota:after-publish', 'run:after-publish', 'nonce:after-publish', 'issued:after-publish', 'receipt-output:after-publish'])('completes exact original issuance after %s without new inputs', (point) => {
        let f: Awaited<ReturnType<typeof serviceFixture>>;
        // Keep only static root/bundle/key setup in the ordinary default-budget hook.
        // The injected issuance, recovery and exact replay assertions remain in the test.
        beforeEach(async () => { f = await serviceFixture(); });
        it('recovers the original transaction and exact committed replay', async () => {
        let fired = false;
        f.setFault(p => { if (!fired && p === point) {
            fired = true;
            throw new Error('injected crash');
        } });
        await expect(f.newService().process(f.requestBytes, f.authHeaders())).rejects.toThrow();
        expect(fired).toBe(true);
        f.setFault(undefined);
        const state = await f.requests.lookup('client-1', 'generation-1', 'idem-1', serviceRequestDigest(f.request));
        expect(state?.phase).toBe('receipt-prepared');
        await f.restart();
        const result = await f.newService().process(f.requestBytes, f.authHeaders());
        expect(result.status).toBe('PASS');
        expect(await f.newService().process(f.requestBytes, f.authHeaders())).toEqual(result);
        await f.coordinator.close();
        });
    });
});
import { readFile, writeFile, rm, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { createPublicKey, generateKeyPairSync } from 'node:crypto';
import { ReceiptKeyRegistry } from '../src/key-registry.js';
import { hash } from './support/task8-service-fixture.js';
async function stopAt(f: Awaited<ReturnType<typeof serviceFixture>>, phase: string, before = false) {
    const advance = f.requests.advance.bind(f.requests);
    let fired = false;
    vi.spyOn(f.requests, 'advance').mockImplementation(async (...args) => { if (before && !fired && args[2].phase === phase) {
        fired = true;
        throw new Error('crash before journal');
    } const result = await advance(...args); if (!before && !fired && result.phase === phase) {
        fired = true;
        throw new Error('crash after journal');
    } return result; });
    await expect(f.newService().process(f.requestBytes, f.authHeaders())).rejects.toThrow();
    expect(fired).toBe(true);
    vi.restoreAllMocks();
    const state = await f.requests.lookup('client-1', 'generation-1', 'idem-1', serviceRequestDigest(f.request));
    if (!state || state.phase === 'tombstone')
        throw new Error('no active state');
    return state;
}
describe('real ambiguous release and frozen recovery bindings', () => {
    it('consumption before journal recovers exact bytes at fresh time, never consumes twice', async () => {
        const f = await serviceFixture();
        const state = await stopAt(f, 'pass-consumed', true);
        expect(state.phase).toBe('receipt-issued');
        if (!('receipt' in state))
            throw new Error('missing receipt');
        const original = await f.store().inspectConsumed(state.receiptDigest);
        expect(original).toBeDefined();
        await f.restart();
        f.setTime(new Date('2030-01-01T00:05:10.000Z'));
        const consume = vi.spyOn((await import('@agent-integrity/core')).FileReceiptStore.prototype, 'consume');
        const result = await f.newService().process(f.requestBytes, f.authHeaders());
        expect(result.status).toBe('PASS');
        expect(consume).not.toHaveBeenCalled();
        expect(await f.store().inspectConsumed(state.receiptDigest)).toEqual(original);
        await f.restart();
        expect(await f.newService().process(f.requestBytes, f.authHeaders())).toEqual(result);
        await f.coordinator.close();
    });
    it('an SDK consume publication error is recovered only from real consumed evidence', async () => {
        const f = await serviceFixture();
        let fired = false;
        f.setFault(point => { if (!fired && point === 'consumed:after-publish') {
            fired = true;
            throw new Error('consume returned error');
        } });
        const result = await f.newService().process(f.requestBytes, f.authHeaders());
        expect(fired).toBe(true);
        expect(result.status).toBe('PASS');
        if (!('receipt' in result))
            throw new Error('receipt absent');
        expect(await f.store().inspectConsumed(result.receipt.receiptDigest)).toBeDefined();
        await f.coordinator.close();
    });
    it.each(['closed:after-publish', 'release-refused'])('preserves original refusal after %s with no reclose or bytes', async (fault) => {
        const f = await serviceFixture();
        await stopAt(f, 'receipt-issued');
        await f.restart();
        if (fault === 'closed:after-publish') {
            let fired = false;
            f.setFault(point => { if (!fired && point === fault) {
                fired = true;
                throw new Error('closed before journal');
            } });
            await expect(f.newService().process(f.requestBytes, f.authHeaders())).rejects.toThrow();
            expect(fired).toBe(true);
            f.setFault(undefined);
        }
        else
            await stopAt(f, 'release-refused');
        const state = await f.requests.lookup('client-1', 'generation-1', 'idem-1', serviceRequestDigest(f.request));
        if (!state || !('receipt' in state))
            throw new Error('no issued receipt');
        const original = await f.store().inspectClosed(state.receiptDigest);
        await f.restart();
        f.setTime(new Date('2030-01-01T00:05:20.000Z'));
        const close = vi.spyOn((await import('@agent-integrity/core')).FileReceiptStore.prototype, 'closeIssuedReceipt');
        const result = await f.newService().process(f.requestBytes, f.authHeaders());
        expect(result.status).toBe('RELEASE_REFUSED');
        expect(result).not.toHaveProperty('releasedResponse');
        expect(close).not.toHaveBeenCalled();
        expect(await f.store().inspectClosed(state.receiptDigest)).toEqual(original);
        if (state.phase === 'release-refused')
            expect(result).toEqual(state.response);
        await f.restart();
        expect(await f.newService().process(f.requestBytes, f.authHeaders())).toEqual(result);
        await f.coordinator.close();
    });
    it.each(['receipt-prepared', 'pass-consumed'])('fresh expiry after %s never reuses signing or consumed time', async (phase) => {
        const f = await serviceFixture();
        const state = await stopAt(f, phase);
        f.setTime(new Date('2030-01-01T00:06:00.000Z'));
        await f.restart();
        const service = f.newService();
        if (phase === 'pass-consumed') {
            await expect(service.process(f.requestBytes, f.authHeaders())).rejects.toMatchObject({ reason: 'RECOVERY_REQUIRED' });
            expect(service.recoveryFailure).toBe('RECOVERY_REQUIRED');
        }
        else {
            const result = await service.process(f.requestBytes, f.authHeaders());
            expect(result.status).toBe('RELEASE_REFUSED');
            expect(result).not.toHaveProperty('releasedResponse');
            if (!('receipt' in result))
                throw new Error('no receipt');
            expect(await f.store().inspectConsumed(result.receipt.receiptDigest)).toBeUndefined();
        }
        expect((await f.requests.lookup('client-1', 'generation-1', 'idem-1', serviceRequestDigest(f.request)))?.transactionId).toBe(state.transactionId);
        await f.coordinator.close();
    });
    it.each(['request', 'snapshot', 'registry', 'key'])('missing or tampered original %s fails closed unsigned and latches recovery readiness', async (kind) => {
        const f = await serviceFixture();
        const state = await stopAt(f, 'receipt-prepared');
        if (state.phase !== 'receipt-prepared')
            throw new Error('wrong phase');
        if (kind === 'request')
            await writeFile(join(f.stateRoot, 'transactions/private-objects/requests', state.requestObjectId + '.json'), '{}');
        if (kind === 'snapshot')
            await writeFile(join(f.snapshotRoot, state.snapshotId, 'project/docs/approved.md'), 'tampered');
        if (kind === 'registry')
            await writeFile(join(f.stateRoot, 'transactions/private-objects/registries', state.trustSnapshotObjectId + '.json'), '{}');
        if (kind === 'key')
            f.setRegistry(new ReceiptKeyRegistry('replacement', [], []));
        await f.restart();
        const service = f.newService();
        await expect(service.process(f.requestBytes, f.authHeaders())).rejects.toMatchObject({ code: 'SERVICE_UNAVAILABLE', reason: 'RECOVERY_REQUIRED' });
        expect(service.recoveryFailure).toBe('RECOVERY_REQUIRED');
        expect((await f.requests.lookup('client-1', 'generation-1', 'idem-1', serviceRequestDigest(f.request)))?.phase).toBe('receipt-prepared');
        await f.coordinator.close();
    });
    it('prepared recovery uses original complete registry despite rotation, revocation and unrelated keys', async () => {
        const f = await serviceFixture();
        const state = await stopAt(f, 'receipt-prepared');
        if (state.phase !== 'receipt-prepared')
            throw new Error('wrong phase');
        const old = f.registry();
        const replacement = generateKeyPairSync('ed25519');
        const keys = old.publicSnapshot().map(k => ({ ...k, revokedAt: '2030-01-01T00:05:01.000Z', publicKey: createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: k.x }, format: 'jwk' }) }));
        keys.push({ kid: 'key2', x: replacement.publicKey.export({ format: 'jwk' }).x!, notBefore: '2029-01-01T00:00:00.000Z', notAfter: '2031-01-01T00:00:00.000Z', revokedAt: null, publicKey: replacement.publicKey });
        f.setRegistry(new ReceiptKeyRegistry('key2', keys, [old.privateKey('key1')!, { kid: 'key2', privateKey: replacement.privateKey }]));
        f.setTime(new Date('2030-01-01T00:05:02.000Z'));
        await rm(f.incomingRoot, { recursive: true });
        await f.restart();
        const result = await f.newService().process(f.requestBytes, f.authHeaders());
        expect(result.status).toBe('PASS');
        if (!('receipt' in result))
            throw new Error('no receipt');
        expect(result.receipt.signature.keyId).toBe('key1');
        expect(result.receipt.createdAt).toBe(state.createdAt);
        expect(hash(await f.objects.readTrustRegistry(state.trustSnapshotObjectId))).toBe(state.trustSnapshotDigest);
        await f.coordinator.close();
    });
    it('completed retry bypasses removed original objects, bundle, keys and receipt store, including exact expiry', async () => {
        const f = await serviceFixture();
        const first = await f.newService().process(f.requestBytes, f.authHeaders());
        expect(first.status).toBe('PASS');
        await f.restart();
        await rm(join(f.stateRoot, 'transactions/private-objects/requests', serviceRequestDigest(f.request) + '.json'));
        for (const name of await readdir(join(f.stateRoot, 'transactions/private-objects/registries')))
            await rm(join(f.stateRoot, 'transactions/private-objects/registries', name));
        await rm(f.incomingRoot, { recursive: true });
        await rm(f.snapshotRoot, { recursive: true });
        f.setRegistry(new ReceiptKeyRegistry('gone', [], []));
        const issue = vi.spyOn((await import('@agent-integrity/core')).FileReceiptStore.prototype, 'completePreparedIssue');
        f.setTime(new Date('2030-01-01T00:05:59.999Z'));
        expect(await f.newService().process(f.requestBytes, f.authHeaders())).toEqual(first);
        expect(issue).not.toHaveBeenCalled();
        f.setTime(new Date('2030-01-01T00:06:00.000Z'));
        await expect(f.newService().process(f.requestBytes, f.authHeaders())).rejects.toMatchObject({ reason: 'RESULT_EXPIRED' });
        f.setTime(new Date('2030-01-02T00:00:00.000Z'));
        await expect(f.newService().process(f.requestBytes, f.authHeaders())).rejects.toMatchObject({ reason: 'RESULT_EXPIRED' });
        await f.coordinator.close();
    });
    it('corrupt phase journal latches recovery readiness rather than exposing parsed state', async () => {
        const f = await serviceFixture();
        await stopAt(f, 'receipt-prepared');
        const entries = await readdir(join(f.stateRoot, 'requests/phases')); // discover exact owned phase file without guessed digest
        const files = await Promise.all(entries.map(async (name) => ({ name, text: await readFile(join(f.stateRoot, 'requests/phases', name), 'utf8') })));
        const prepared = files.find(file => file.text.includes('receipt-prepared'));
        if (!prepared)
            throw new Error('prepared journal absent');
        await writeFile(join(f.stateRoot, 'requests/phases', prepared.name), '{}');
        await f.restart();
        const service = f.newService();
        await expect(service.process(f.requestBytes, f.authHeaders())).rejects.toMatchObject({ code: 'SERVICE_UNAVAILABLE', reason: 'RECOVERY_REQUIRED' });
        expect(service.recoveryFailure).toBe('RECOVERY_REQUIRED');
        await f.coordinator.close();
    });
});
describe('signed non-PASS and exact UTF-8 persisted results', () => {
    it.each(['REVIEW', 'BLOCKED'] as const)('recovers signed original %s issued receipt without consumption or bytes', async (outcome) => {
        const f = await serviceFixture(undefined, outcome);
        const state = await stopAt(f, 'receipt-issued');
        if (state.phase !== 'receipt-issued')
            throw new Error('unexpected phase');
        expect(state.receipt.verification.status).toBe(outcome);
        await f.restart();
        const core = await import('@agent-integrity/core');
        const consume = vi.spyOn(core.FileReceiptStore.prototype, 'consume');
        const create = vi.spyOn(core, 'createReceipt');
        const result = await f.newService().process(f.requestBytes, f.authHeaders());
        expect(result.status).toBe(outcome);
        expect(result).not.toHaveProperty('releasedResponse');
        expect(result.receipt).toEqual(state.receipt);
        expect(consume).not.toHaveBeenCalled();
        expect(create).not.toHaveBeenCalled();
        expect(await f.store().inspectConsumed(state.receiptDigest)).toBeUndefined();
        await f.restart();
        expect(await f.newService().process(f.requestBytes, f.authHeaders())).toEqual(result);
        await f.coordinator.close();
    });
    it('consumed recovery returns exact non-ASCII/newline bytes, not a JSON rendering', async () => {
        const content = '{ "message": "café ☃" }\n';
        const f = await serviceFixture(undefined, 'PASS', content);
        await stopAt(f, 'pass-consumed', true);
        await f.restart();
        const result = await f.newService().process(f.requestBytes, f.authHeaders());
        expect(result.status).toBe('PASS');
        if (!('releasedResponse' in result))
            throw new Error('no bytes');
        expect(Buffer.from(result.releasedResponse.bytes, 'base64')).toEqual(Buffer.from(content));
        expect(result.releasedResponse.sha256).toBe(hash(content));
        await f.coordinator.close();
    });
    it('output root substitution on an issued interrupted transaction fails closed', async () => {
        const f = await serviceFixture();
        await stopAt(f, 'receipt-issued');
        const fs = await import('node:fs/promises');
        await fs.rename(f.outputRoot, f.outputRoot + '-original');
        await fs.mkdir(f.outputRoot, { mode: 0o700 });
        await f.restart();
        const service = f.newService();
        await expect(service.process(f.requestBytes, f.authHeaders())).rejects.toMatchObject({ reason: 'RECOVERY_REQUIRED' });
        expect(service.recoveryFailure).toBe('RECOVERY_REQUIRED');
        await f.coordinator.close();
    });
    it.each(['expired', 'revoked'] as const)('fresh signing admission after verified rejects %s active key without issuance', async (kind) => {
        const f = await serviceFixture();
        await stopAt(f, 'verified');
        const old = f.registry();
        const keys = old.publicSnapshot().map(k => ({ ...k, ...(kind === 'expired' ? { notAfter: '2030-01-01T00:05:00.000Z' } : { revokedAt: '2030-01-01T00:05:00.000Z' }), publicKey: createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: k.x }, format: 'jwk' }) }));
        f.setRegistry(new ReceiptKeyRegistry('key1', keys, [old.privateKey('key1')!]));
        await f.restart();
        await expect(f.newService().process(f.requestBytes, f.authHeaders())).rejects.toMatchObject({ reason: 'RECOVERY_REQUIRED' });
        expect((await f.requests.lookup('client-1', 'generation-1', 'idem-1', serviceRequestDigest(f.request)))?.phase).toBe('verified');
        expect((await f.store().inspectCapacity()).used).toBe(0);
        await f.coordinator.close();
    });
});
it('fresh release enforces original frozen key interval, not current registry metadata', async () => {
    const f = await serviceFixture();
    const old = f.registry();
    const keys = old.publicSnapshot().map(k => ({ ...k, notAfter: '2030-01-01T00:05:05.000Z', publicKey: createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: k.x }, format: 'jwk' }) }));
    f.setRegistry(new ReceiptKeyRegistry('key1', keys, [old.privateKey('key1')!]));
    await stopAt(f, 'receipt-prepared');
    f.setRegistry(old);
    f.setTime(new Date('2030-01-01T00:05:05.000Z'));
    await f.restart();
    const result = await f.newService().process(f.requestBytes, f.authHeaders());
    expect(result.status).toBe('RELEASE_REFUSED');
    expect(result).not.toHaveProperty('releasedResponse');
    if (!('receipt' in result))
        throw new Error('receipt absent');
    expect(await f.store().inspectConsumed(result.receipt.receiptDigest)).toBeUndefined();
    await f.coordinator.close();
});
it('preserves REVIEW from a real create-once close marker before refusal journal', async () => {
    const f = await serviceFixture();
    const state = await stopAt(f, 'receipt-issued');
    if (state.phase !== 'receipt-issued')
        throw new Error('wrong phase');
    await f.options.scheduler.run(async (capability) => { await f.options.receiptStore(capability).closeIssuedReceipt(state.receiptDigest, { transactionId: state.transactionId, closedAt: new Date('2030-01-01T00:05:03.000Z'), reasonCode: 'RELEASE_REVIEW' }); });
    const marker = await f.store().inspectClosed(state.receiptDigest);
    await f.restart();
    const result = await f.newService().process(f.requestBytes, f.authHeaders());
    expect(result).toMatchObject({ status: 'RELEASE_REFUSED', release: { status: 'REVIEW', code: 'RECEIPT_RECHECK_REFUSED', retryable: false }, receipt: state.receipt });
    expect(result).not.toHaveProperty('releasedResponse');
    expect(await f.store().inspectClosed(state.receiptDigest)).toEqual(marker);
    await f.coordinator.close();
});
it('unreadable real consumed evidence is not absence and never closes or consumes again', async () => {
    const f = await serviceFixture();
    const state = await stopAt(f, 'pass-consumed', true);
    if (state.phase !== 'receipt-issued')
        throw new Error('wrong phase');
    const markerPath = join(f.stateRoot, 'receipts/consumed', state.receiptDigest + '.json');
    const marker = JSON.parse(await readFile(markerPath, 'utf8'));
    marker.transactionId = 'other-transaction';
    await writeFile(markerPath, canonicalJson(marker));
    await f.restart();
    const core = await import('@agent-integrity/core');
    const consume = vi.spyOn(core.FileReceiptStore.prototype, 'consume'), close = vi.spyOn(core.FileReceiptStore.prototype, 'closeIssuedReceipt');
    const service = f.newService();
    await expect(service.process(f.requestBytes, f.authHeaders())).rejects.toMatchObject({ reason: 'RECOVERY_REQUIRED' });
    expect(service.recoveryFailure).toBe('RECOVERY_REQUIRED');
    expect(consume).not.toHaveBeenCalled();
    expect(close).not.toHaveBeenCalled();
    expect(await readFile(markerPath, 'utf8')).toBe(canonicalJson(marker));
    await f.coordinator.close();
});


it('persisted refusal keeps original REVIEW response and generic close reason unchanged', async () => {
 const f = await serviceFixture();
 const state = await stopAt(f, 'receipt-issued');
 if (state.phase !== 'receipt-issued') throw new Error('wrong phase');
 const original = {serviceProtocolVersion:'1' as const,requestId:f.request.requestId,status:'RELEASE_REFUSED' as const,verification:state.receipt.verification,receipt:state.receipt,release:{status:'REVIEW' as const,code:'RECEIPT_RECHECK_REFUSED' as const,retryable:false as const}};
 await f.options.scheduler.run(async capability => {
  const store = f.options.receiptStore(capability);
  await store.closeIssuedReceipt(state.receiptDigest,{transactionId:state.transactionId,closedAt:new Date('2030-01-01T00:05:03.000Z'),reasonCode:'RELEASE_RECHECK_REFUSED'});
  const closed = await store.inspectClosed(state.receiptDigest);
  await f.requests.advance(capability,state,{phase:'release-refused',closedMarkerDigest:hash(canonicalJson(closed)),response:original});
 });
 const closed = await f.store().inspectClosed(state.receiptDigest);
 await f.restart();
 expect(await f.newService().process(f.requestBytes, f.authHeaders())).toEqual(original);
 expect(await f.store().inspectClosed(state.receiptDigest)).toEqual(closed);
 await f.coordinator.close();
});
