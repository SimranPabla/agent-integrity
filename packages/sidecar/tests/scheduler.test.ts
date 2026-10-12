import { describe, expect, it, vi } from "vitest";
import { MutationScheduler } from "../src/scheduler.js";

function harness() {
  let active = 0;
  const coordinator = { withMutation: vi.fn(async <T>(work: (capability: unknown) => Promise<T>) => {
    expect(active).toBe(0); active++;
    try { return await work(Object.freeze({ ownerToken: "test-owner" })); }
    finally { active--; }
  }) };
  return coordinator;
}
function gate() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => { release = resolve; });
  return { promise, release: () => release() };
}
describe("Task8 bounded capability admission", () => {
  it.each([
    { maximumQueued: -1, queueTimeoutMs: 1 },
    { maximumQueued: 0.5, queueTimeoutMs: 1 },
    { maximumQueued: Number.MAX_SAFE_INTEGER + 1, queueTimeoutMs: 1 },
    { maximumQueued: 1, queueTimeoutMs: 0 },
    { maximumQueued: 1, queueTimeoutMs: NaN },
    { maximumQueued: 1, queueTimeoutMs: Infinity },
  ])("rejects invalid bounds before mutation: %j", options => {
    const coordinator = harness();
    expect(() => new MutationScheduler(coordinator as never, options)).toThrow("invalid scheduler bounds");
    expect(coordinator.withMutation).not.toHaveBeenCalled();
  });
  it("preserves active ownership on shutdown and removes all waiting work", async () => {
    const coordinator = harness(); const scheduler = new MutationScheduler(coordinator as never, { maximumQueued: 2, queueTimeoutMs: 1000 });
    const pending = gate(); const entered = gate(); const work = vi.fn();
    const first = scheduler.run(async () => { entered.release(); await pending.promise; return "safe"; }); await entered.promise;
    const waiter = scheduler.run(work); const assertion = expect(waiter).rejects.toMatchObject({ reason: "SHUTDOWN" });
    scheduler.close(); scheduler.close();
    await assertion; expect(scheduler.active).toBe(true); expect(scheduler.queued).toBe(0);
    await expect(scheduler.run(work)).rejects.toMatchObject({ reason: "SHUTDOWN" });
    expect(work).not.toHaveBeenCalled(); expect(coordinator.withMutation).toHaveBeenCalledTimes(1);
    pending.release(); expect(await first).toBe("safe"); expect(scheduler.active).toBe(false);
  });
  it("continues the queue after a work failure without retaining failed ownership", async () => {
    const coordinator = harness(); const scheduler = new MutationScheduler(coordinator as never, { maximumQueued: 1, queueTimeoutMs: 1000 });
    const pending = gate(); const entered = gate(); const failure = new Error("work failed");
    const first = scheduler.run(async () => { entered.release(); await pending.promise; throw failure; });
    const assertion = expect(first).rejects.toBe(failure); await entered.promise;
    const second = scheduler.run(() => "next"); pending.release();
    await assertion; expect(await second).toBe("next"); expect(scheduler.active).toBe(false); expect(scheduler.queued).toBe(0);
  });
  it("never cancels admitted work on client abort and removes queued listeners on admission", async () => {
    const coordinator = harness(); const scheduler = new MutationScheduler(coordinator as never, { maximumQueued: 1, queueTimeoutMs: 1000 });
    const pending = gate(); const entered = gate(); const activeAbort = new AbortController(); const queuedAbort = new AbortController();
    const remove = vi.spyOn(queuedAbort.signal, "removeEventListener");
    const first = scheduler.run(async () => { entered.release(); await pending.promise; return "committed"; }, activeAbort.signal); await entered.promise;
    const second = scheduler.run(() => "second", queuedAbort.signal);
    activeAbort.abort(); expect(scheduler.active).toBe(true); expect(scheduler.queued).toBe(1);
    pending.release(); expect(await first).toBe("committed"); expect(await second).toBe("second");
    expect(remove).toHaveBeenCalledWith("abort", expect.any(Function)); queuedAbort.abort(); expect(scheduler.active).toBe(false);
  });
  it("rejects concurrent admission when queue capacity is zero", async () => {
    const coordinator = harness(); const scheduler = new MutationScheduler(coordinator as never, { maximumQueued: 0, queueTimeoutMs: 1000 });
    const pending = gate(); const first = scheduler.run(async () => pending.promise);
    await expect(scheduler.run(() => "no")).rejects.toMatchObject({ reason: "QUEUE_FULL" });
    pending.release(); await first; expect(scheduler.active).toBe(false);
  });
  it("holds exclusive capability through awaited completion", async () => {
    const coordinator = harness();
    const scheduler = new MutationScheduler(coordinator as never, { maximumQueued: 2, queueTimeoutMs: 1_000 });
    const pending = gate(); const entered = gate(); const events: string[] = [];
    const first = scheduler.run(async () => { events.push("first"); entered.release(); await pending.promise; events.push("done"); });
    await entered.promise;
    const second = scheduler.run(async () => { events.push("second"); });
    expect(events).toEqual(["first"]); expect(coordinator.withMutation).toHaveBeenCalledTimes(1);
    pending.release(); await Promise.all([first, second]);
    expect(events).toEqual(["first", "done", "second"]);
  });
  it("rejects overflow before acquiring any additional capability", async () => {
    const coordinator = harness(); const scheduler = new MutationScheduler(coordinator as never, { maximumQueued: 1, queueTimeoutMs: 1_000 });
    const pending = gate(); const entered = gate();
    const first = scheduler.run(async () => { entered.release(); await pending.promise; }); await entered.promise;
    const second = scheduler.run(async () => undefined);
    await expect(scheduler.run(async () => undefined)).rejects.toMatchObject({ code: "SERVICE_UNAVAILABLE", reason: "QUEUE_FULL" });
    expect(coordinator.withMutation).toHaveBeenCalledTimes(1);
    pending.release(); await Promise.all([first, second]);
  });
  it("times out queued work without acquiring its mutation capability", async () => {
    const coordinator = harness(); const scheduler = new MutationScheduler(coordinator as never, { maximumQueued: 1, queueTimeoutMs: 15 });
    const pending = gate(); const entered = gate();
    const first = scheduler.run(async () => { entered.release(); await pending.promise; }); await entered.promise;
    await expect(scheduler.run(async () => undefined)).rejects.toMatchObject({ code: "SERVICE_UNAVAILABLE", reason: "QUEUE_TIMEOUT" });
    expect(coordinator.withMutation).toHaveBeenCalledTimes(1);
    pending.release(); await first;
  });
  it("removes aborted queued work without mutation and admits the next waiter", async () => {
    const coordinator = harness(); const scheduler = new MutationScheduler(coordinator as never, { maximumQueued: 1, queueTimeoutMs: 1_000 });
    const pending = gate(); const entered = gate(); const abort = new AbortController();
    const first = scheduler.run(async () => { entered.release(); await pending.promise; }); await entered.promise;
    const queued = scheduler.run(async () => undefined, abort.signal); abort.abort();
    await expect(queued).rejects.toMatchObject({ code: "SERVICE_UNAVAILABLE", reason: "ABORTED" });
    expect(coordinator.withMutation).toHaveBeenCalledTimes(1);
    const next = scheduler.run(async () => "next"); pending.release(); await first; expect(await next).toBe("next");
  });
  it("does not enter the coordinator for an already-aborted request", async () => {
    const coordinator = harness(); const scheduler = new MutationScheduler(coordinator as never, { maximumQueued: 1, queueTimeoutMs: 1_000 });
    const abort = new AbortController(); abort.abort();
    await expect(scheduler.run(async () => undefined, abort.signal)).rejects.toMatchObject({ code: "SERVICE_UNAVAILABLE", reason: "ABORTED" });
    expect(coordinator.withMutation).not.toHaveBeenCalled();
  });
});
