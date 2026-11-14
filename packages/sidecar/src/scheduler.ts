import type { MutationCapability, StateCoordinator } from "./state-coordinator.js";

type Coordinator = Pick<StateCoordinator, "withMutation">;
export interface SchedulerOptions { readonly maximumQueued: number; readonly queueTimeoutMs: number }
export type AdmissionReason = "QUEUE_FULL" | "QUEUE_TIMEOUT" | "ABORTED" | "SHUTDOWN";
export class AdmissionError extends Error {
  readonly code = "SERVICE_UNAVAILABLE" as const;
  readonly retryable = true;
  constructor(readonly reason: AdmissionReason) { super(reason); this.name = "AdmissionError"; }
}
interface Entry {
  readonly work: (capability: MutationCapability) => unknown | Promise<unknown>;
  readonly resolve: (value: unknown) => void;
  readonly reject: (error: unknown) => void;
  cleanup: () => void;
}
/** Queue admission is entirely in memory and precedes the root mutation capability. */
export class MutationScheduler {
  readonly #coordinator: Coordinator;
  readonly #options: Readonly<SchedulerOptions>;
  readonly #queue: Entry[] = [];
  #active = false;
  #closed = false;
  constructor(coordinator: Coordinator, options: SchedulerOptions) {
    if (!Number.isSafeInteger(options.maximumQueued) || options.maximumQueued < 0 ||
        !Number.isSafeInteger(options.queueTimeoutMs) || options.queueTimeoutMs <= 0) throw new Error("invalid scheduler bounds");
    this.#coordinator = coordinator; this.#options = Object.freeze({ ...options });
  }
  run<T>(work: (capability: MutationCapability) => T | Promise<T>, signal?: AbortSignal): Promise<T> {
    if (this.#closed) return Promise.reject(new AdmissionError("SHUTDOWN"));
    if (signal?.aborted) return Promise.reject(new AdmissionError("ABORTED"));
    if (this.#active && this.#queue.length >= this.#options.maximumQueued) return Promise.reject(new AdmissionError("QUEUE_FULL"));
    return new Promise<T>((resolve, reject) => {
      const entry: Entry = { work, resolve: value => resolve(value as T), reject, cleanup: () => undefined };
      if (!this.#active) { this.#start(entry); return; }
      const remove = (reason: AdmissionReason): void => {
        const index = this.#queue.indexOf(entry);
        if (index < 0) return;
        this.#queue.splice(index, 1); entry.cleanup(); entry.reject(new AdmissionError(reason));
      };
      const abort = (): void => remove("ABORTED");
      const timer = setTimeout(() => remove("QUEUE_TIMEOUT"), this.#options.queueTimeoutMs);
      entry.cleanup = () => { clearTimeout(timer); signal?.removeEventListener("abort", abort); };
      this.#queue.push(entry); signal?.addEventListener("abort", abort, { once: true });
      if (signal?.aborted) abort();
    });
  }
  /** Reject waiting work only; active work retains ownership until it reaches its own safe boundary. */
  close(): void {
    this.#closed = true;
    for (const entry of this.#queue.splice(0)) { entry.cleanup(); entry.reject(new AdmissionError("SHUTDOWN")); }
  }
  get queued(): number { return this.#queue.length; }
  get active(): boolean { return this.#active; }
  #start(entry: Entry): void {
    this.#active = true; entry.cleanup();
    void this.#execute(entry);
  }
  async #execute(entry: Entry): Promise<void> {
    let value: unknown; let failed = false; let error: unknown;
    try { value = await this.#coordinator.withMutation(entry.work); }
    catch (cause) { failed = true; error = cause; }
    finally {
      this.#active = false;
      const next = this.#queue.shift(); if (next !== undefined) this.#start(next);
    }
    if (failed) entry.reject(error); else entry.resolve(value);
  }
}
