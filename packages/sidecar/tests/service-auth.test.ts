import { afterEach, describe, expect, it, vi } from "vitest";
import { randomBytes } from "node:crypto";
import { cleanupServiceFixtures, serviceFixture } from "./support/task8-service-fixture.js";

afterEach(async () => { vi.restoreAllMocks(); await cleanupServiceFixtures(); });

describe("Task8 mandatory service admission", () => {
  it("does not admit a queued request after the preceding request latches a storage failure", async () => {
    const fixture = await serviceFixture();
    const realConsume = fixture.options.nonceStore.consume.bind(fixture.options.nonceStore);
    let entered!: () => void;
    let release!: () => void;
    const started = new Promise<void>(resolve => { entered = resolve; });
    const gate = new Promise<void>(resolve => { release = resolve; });
    const consume = vi.spyOn(fixture.options.nonceStore, "consume").mockImplementationOnce(async record => {
      await realConsume(record); // the first authentication nonce really is durable
      entered();
      await gate;
      throw new Error("failure after nonce publication");
    });
    const reserve = vi.spyOn(fixture.requests, "reserve");
    const service = fixture.newService();
    const first = service.process(fixture.requestBytes, fixture.authHeaders());
    const firstAssertion = expect(first).rejects.toMatchObject({ reason: "RECOVERY_REQUIRED" });
    await started;
    const second = service.process(fixture.requestBytes, fixture.authHeaders());
    const secondAssertion = expect(second).rejects.toMatchObject({ reason: "NOT_READY" });
    release();
    await firstAssertion;
    await secondAssertion;
    expect(consume).toHaveBeenCalledTimes(1);
    expect(reserve).not.toHaveBeenCalled();
    expect(fixture.options.readiness.snapshot().ready).toBe(false);
    expect(await fixture.requests.lookup("client-1", "generation-1", "idem-1", (await import("../src/protocol.js")).serviceRequestDigest(fixture.request))).toBeUndefined();
    await fixture.coordinator.close();
  });
  it("rejects a changed body before durable admission", async () => {
    const fixture = await serviceFixture();
    const service = fixture.newService();
    const headers = fixture.authHeaders();
    const changed = Buffer.from(fixture.requestBytes);
    changed[changed.length - 1] ^= 1;
    await expect(service.process(changed, headers)).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });
  });

  it("requires a fresh authentication nonce for each completed retry", async () => {
    const fixture = await serviceFixture();
    const service = fixture.newService();
    await service.process(fixture.requestBytes, fixture.authHeaders());
    await expect(service.process(fixture.requestBytes, fixture.authHeaders())).resolves.toMatchObject({ status: "PASS" });
    await expect(service.process(fixture.requestBytes, fixture.authHeaders(fixture.requestBytes))).resolves.toMatchObject({ status: "PASS" });
  });

  it("does not allow readiness recovery to clear a latched failure", async () => {
    const fixture = await serviceFixture();
    const service = fixture.newService();
    fixture.options.readiness.fail("AMBIGUOUS_STATE");
    await expect(service.process(fixture.requestBytes, fixture.authHeaders())).rejects.toMatchObject({ reason: "NOT_READY" });
    fixture.options.readiness.set("AMBIGUOUS_STATE", true);
    await expect(service.process(fixture.requestBytes, fixture.authHeaders())).rejects.toMatchObject({ reason: "NOT_READY" });
  });

  it("rejects reuse of the exact authentication headers", async () => {
    const fixture = await serviceFixture();
    const service = fixture.newService();
    const headers = fixture.authHeaders();
    await service.process(fixture.requestBytes, headers);
    await expect(service.process(fixture.requestBytes, headers)).rejects.toMatchObject({ code: "REPLAY_DETECTED" });
  });

  it("rejects a valid MAC from a foreign configured client before nonce admission", async () => {
    const fixture = await serviceFixture();
    const secret = randomBytes(32);
    fixture.options.authRegistry = { clients: {
      ...fixture.options.authRegistry.clients,
      "client-2": { keys: { auth2: { secret, validFromMs: 1893455940000, validUntilMs: 1893459600000 } } },
    } };
    const service = fixture.newService();
    const consume = vi.spyOn(fixture.options.nonceStore, "consume");
    await expect(service.process(fixture.requestBytes, fixture.authHeadersFor("client-2", "auth2", secret))).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });
    expect(consume).not.toHaveBeenCalled();
  });

  it("rejects nonce reuse when the same client changes to an overlapping HMAC key", async () => {
    const fixture = await serviceFixture();
    const secret = randomBytes(32);
    fixture.options.authRegistry = { clients: { "client-1": { keys: {
      auth1: { secret: fixture.authSecret, validFromMs: 1893455940000, validUntilMs: 1894060800000 },
      auth2: { secret, validFromMs: 1893455940000, validUntilMs: 1894060800000 },
    } } } };
    const service = fixture.newService();
    const first = fixture.authHeaders();
    await service.process(fixture.requestBytes, first);
    await expect(service.process(fixture.requestBytes, fixture.authHeadersFor("client-1", "auth2", secret, fixture.requestBytes, first.nonce))).rejects.toMatchObject({ code: "REPLAY_DETECTED" });
  });

  it("rejects a valid canonical body signed with the original MAC", async () => {
    const fixture = await serviceFixture();
    const service = fixture.newService();
    const changed = Buffer.from(fixture.requestBytes.toString().replace("req-1", "req-2"));
    const consume = vi.spyOn(fixture.options.nonceStore, "consume");
    const mutation = vi.spyOn(fixture.coordinator, "withMutation");
    await expect(service.process(changed, fixture.authHeaders())).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });
    expect(consume).not.toHaveBeenCalled();
    expect(mutation).not.toHaveBeenCalled();
  });

  it("does not consume authentication nonces for queue-full or queued-timeout admission", async () => {
    const fixture = await serviceFixture();
    const service = fixture.newService();
    const consume = vi.spyOn(fixture.options.nonceStore, "consume");
    let release!: () => void;
    const active = fixture.options.scheduler.run(() => new Promise<void>(resolve => { release = resolve; }));
    const queued = service.process(fixture.requestBytes, fixture.authHeaders());
    await expect(service.process(fixture.requestBytes, fixture.authHeaders())).rejects.toMatchObject({ reason: "QUEUE_FULL" });
    await expect(queued).rejects.toMatchObject({ reason: "QUEUE_TIMEOUT" });
    expect(consume).not.toHaveBeenCalled();
    release();
    await active;
  });
});
