import { allowDiskIntegrationTime } from "./support/disk-integration-timeout.js";
allowDiskIntegrationTime();
import { afterEach, describe, expect, it, vi } from "vitest";
import { canonicalJson } from "@agent-integrity/core";
import { ServiceUnavailableError, exactResponseBytes } from "../src/service.js";
import { serviceRequestDigest } from "../src/protocol.js";
import { serviceFixture, cleanupServiceFixtures, hash } from "./support/task8-service-fixture.js";
import * as runner from "../src/verification-runner.js";
afterEach(async () => { vi.restoreAllMocks(); await cleanupServiceFixtures(); });
describe('Task 8 service outcome boundary', () => {
    it('retains exact UTF-8 response bytes, without JSON reserialization', { timeout: 5000 }, () => {
        const original = '{ "message": "café ☃" }\n';
        expect(exactResponseBytes('PASS', original)).toEqual(Buffer.from(original, 'utf8'));
    });
    it.each(['REVIEW', 'BLOCKED', 'TECHNICAL_ERROR'])('never releases response bytes for %s', { timeout: 5000 }, status => {
        expect(() => exactResponseBytes(status, 'secret')).toThrow();
    });
    it('uses a stable unsigned technical error boundary', { timeout: 5000 }, () => {
        const error = new ServiceUnavailableError('RECOVERY_REQUIRED');
        expect(error.code).toBe('SERVICE_UNAVAILABLE');
        expect(error.reason).toBe('RECOVERY_REQUIRED');
    });
    // Preserve the October 8 bounded replay regression, now with real snapshots and keys.
    it("commits a PASS response once, consumes the receipt, and replays the immutable result", async () => {
        const f = await serviceFixture(new Date("2026-10-08T00:00:00.000Z"));
        return f.trackOperation(async () => {
            const request = f.request; // the fixture uses real parseCanonicalServiceRequest, never a forged object
            const verify = vi.spyOn(runner, "runTrustedVerification");
            const service = f.newService();
            const first = await service.process(f.requestBytes, f.authHeaders());
            expect(first.status).toBe("PASS");
            if (!('receipt' in first) || !('releasedResponse' in first))
                throw new Error('missing PASS result');
            const expectedBytes = Buffer.from(request.envelope.response.content, "utf8");
            expect(first.releasedResponse).toEqual({ encoding: "base64", bytes: expectedBytes.toString("base64"), sha256: hash(expectedBytes) });
            expect(canonicalJson(first.verification)).toBe(canonicalJson(first.receipt.verification));
            expect(first.verification).not.toHaveProperty("envelopeDigest");
            expect(first.receipt.envelopeDigest).toBe(hash(canonicalJson(request.envelope)));
            await expect(f.store().inspectConsumed(first.receipt.receiptDigest)).resolves.toMatchObject({ transactionId: "transaction-1" });
            expect(await service.process(f.requestBytes, f.authHeaders())).toEqual(first);
            expect(verify).toHaveBeenCalledTimes(1);
            f.setTime(new Date("2026-10-08T00:00:59.999Z"));
            expect(await service.process(f.requestBytes, f.authHeaders())).toEqual(first);
            f.setTime(new Date("2026-10-08T00:01:00.000Z"));
            await expect(service.process(f.requestBytes, f.authHeaders())).rejects.toMatchObject({ reason: "RESULT_EXPIRED" });
            f.setTime(new Date("2026-10-09T00:00:00.000Z"));
            await expect(service.process(f.requestBytes, f.authHeaders())).rejects.toMatchObject({ reason: "RESULT_EXPIRED" });
            await expect(service.process(f.requestBytes, f.authHeaders())).rejects.toMatchObject({ reason: "RESULT_EXPIRED" });
            expect(verify).toHaveBeenCalledTimes(1);
            await expect(f.requests.lookup("client-1", "generation-1", "idem-1", serviceRequestDigest(request))).resolves.toMatchObject({ phase: "tombstone" });
            await f.coordinator.close();
        });
    });
});
it('requires a canonical authenticated body and captures raw bytes before async work', async () => {
    const f = await serviceFixture();
    return f.trackOperation(async () => {
        const service = f.newService();
        await expect(service.process(Buffer.from('{}'), f.authHeaders(Buffer.from('{}')))).rejects.toMatchObject({ code: 'AUTHENTICATION_FAILED' });
        expect(await f.requests.lookup('client-1', 'generation-1', 'idem-1', serviceRequestDigest(f.request))).toBeUndefined();
        const bytes = Buffer.from(f.requestBytes);
        const resultPromise = service.process(bytes, f.authHeaders(bytes));
        bytes.fill(0);
        const result = await resultPromise;
        expect(result.status).toBe('PASS');
        expect(await f.objects.readCanonicalRequest(serviceRequestDigest(f.request))).toEqual(f.requestBytes);
        expect(await service.process(f.requestBytes, f.authHeaders())).toEqual(result);
        await f.coordinator.close();
    });
});
