import { createHash } from "node:crypto";
import { canonicalJson } from "@agent-integrity/core";
import { DurableJsonDirectory, DurableRecordExistsError, type DurableJsonOptions } from "./durable-json.js";
import { PrivateObjectStore } from "./private-object-store.js";
import { assertTransition, parseRequestState, requestStateDigest, type ActiveRequestState, type RequestState, type ResultCommittedState, type TombstoneState } from "./request-state.js";
import { assertMutationCapability, type MutationCapability } from "./state-coordinator.js";

const SAFE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const DEFAULT_MAX_RECORDS = 10_000;

interface BindingRecord {
  readonly version: 1; readonly clientId: string; readonly storeGeneration: string; readonly idempotencyKeyHash: string;
  readonly requestDigest: string; readonly requestId: string; readonly transactionId: string; readonly requestObjectId: string;
}
export interface ReservationInput {
  readonly clientId: string; readonly storeGeneration: string; readonly idempotencyKey: string; readonly requestDigest: string;
  readonly requestId: string; readonly transactionId: string; readonly canonicalRequest: Uint8Array;
}
export interface RequestStoreOptions extends Partial<DurableJsonOptions> { readonly maxRecords?: number }

const phaseOrder: Readonly<Record<ActiveRequestState["phase"], number>> = {
  reserved: 0, verified: 10, "receipt-prepared": 20, "receipt-issued": 30,
  "pass-consumed": 40, "release-refused": 40, "result-committed": 50,
};
function sha(value: Uint8Array | string): string { return createHash("sha256").update(value).digest("hex"); }
function safe(value: string, label: string): void { if (!SAFE.test(value)) throw new TypeError(`${label} is invalid`); }
function keyFor(clientId: string, generation: string, idempotencyKey: string): string { return sha(canonicalJson([clientId, generation, idempotencyKey])); }
function bindingRecord(value: unknown): BindingRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new Error("request binding is invalid");
  const record = value as Record<string, unknown>;
  if (Object.keys(record).sort().join(",") !== "clientId,idempotencyKeyHash,requestDigest,requestId,requestObjectId,storeGeneration,transactionId,version" || record.version !== 1) throw new Error("request binding is invalid");
  for (const field of ["clientId", "storeGeneration", "requestId", "transactionId"] as const) if (typeof record[field] !== "string" || !SAFE.test(record[field])) throw new Error("request binding is invalid");
  for (const field of ["idempotencyKeyHash", "requestDigest", "requestObjectId"] as const) if (typeof record[field] !== "string" || !SHA256.test(record[field])) throw new Error("request binding is invalid");
  return record as unknown as BindingRecord;
}

export class RequestStore {
  readonly #root: DurableJsonDirectory;
  readonly #objects: PrivateObjectStore;
  readonly #maxRecords: number;

  constructor(directory: string, objects: PrivateObjectStore, options: RequestStoreOptions = {}) {
    this.#maxRecords = options.maxRecords ?? DEFAULT_MAX_RECORDS;
    if (!Number.isSafeInteger(this.#maxRecords) || this.#maxRecords < 1 || this.#maxRecords > 1_000_000) throw new TypeError("maximum request records is invalid");
    this.#objects = objects;
    this.#root = new DurableJsonDirectory(directory, {
      maxStateBytes: options.maxStateBytes ?? 1024 * 1024,
      maxEntries: options.maxEntries ?? this.#maxRecords * 8 + 16,
      ...(options.faultInjector === undefined ? {} : { faultInjector: options.faultInjector }),
    });
  }

  async reserve(capability: MutationCapability, input: ReservationInput): Promise<ActiveRequestState> {
    assertMutationCapability(capability);
    this.#validateReservation(input, capability);
    await this.#initialize();
    const requestBytes = Buffer.from(input.canonicalRequest);
    if (sha(requestBytes) !== input.requestDigest) throw new Error("canonical request digest mismatch");
    const bindingKey = keyFor(input.clientId, input.storeGeneration, input.idempotencyKey);
    const idempotencyKeyHash = sha(input.idempotencyKey);
    const tombstone = await this.#readOptional(`tombstones/${bindingKey}.json`);
    if (tombstone !== undefined) {
      const parsed = parseRequestState(tombstone);
      if (parsed.phase !== "tombstone") throw new Error("request tombstone is invalid");
      if (parsed.requestDigest !== input.requestDigest) throw new Error("idempotency-key digest conflict");
      throw new Error("expired idempotency key cannot be reused after tombstone compaction");
    }
    await this.#objects.publishCanonicalRequest(requestBytes, input.requestDigest);
    const expected: BindingRecord = { version: 1, clientId: input.clientId, storeGeneration: input.storeGeneration, idempotencyKeyHash, requestDigest: input.requestDigest, requestId: input.requestId, transactionId: input.transactionId, requestObjectId: input.requestDigest };
    const existing = await this.#readOptional(`bindings/${bindingKey}.json`);
    if (existing === undefined) {
      if ((await this.#root.entries("bindings")).length >= this.#maxRecords) throw new Error("request store capacity reached");
      try { await this.#root.publishCreateOnce(`bindings/${bindingKey}.json`, expected); }
      catch (error) {
        if (!(error instanceof DurableRecordExistsError)) throw error;
      }
    }
    const actual = bindingRecord(await this.#root.read(`bindings/${bindingKey}.json`));
    if (canonicalJson(actual) !== canonicalJson(expected)) throw new Error(actual.requestDigest === input.requestDigest ? "idempotency binding ownership conflict" : "idempotency-key digest conflict");
    const current = await this.#current(bindingKey);
    if (current !== undefined) return current;
    const reserved = parseRequestState({ ...expected, phase: "reserved" });
    if (reserved.phase !== "reserved") throw new Error("reserved request-state construction failed");
    await this.#publishPhase(bindingKey, reserved);
    return reserved;
  }

  async lookup(clientId: string, storeGeneration: string, idempotencyKey: string, requestDigest: string): Promise<RequestState | undefined> {
    safe(clientId, "clientId"); safe(storeGeneration, "storeGeneration"); safe(idempotencyKey, "idempotencyKey");
    if (!SHA256.test(requestDigest)) throw new TypeError("request digest is invalid");
    await this.#initialize();
    const bindingKey = keyFor(clientId, storeGeneration, idempotencyKey);
    const tombstone = await this.#readOptional(`tombstones/${bindingKey}.json`);
    if (tombstone !== undefined) {
      const state = parseRequestState(tombstone);
      if (state.phase !== "tombstone") throw new Error("request tombstone is invalid");
      if (state.requestDigest !== requestDigest) throw new Error("idempotency-key digest conflict");
      return state;
    }
    const binding = await this.#readOptional(`bindings/${bindingKey}.json`);
    if (binding === undefined) return undefined;
    const actual = bindingRecord(binding);
    if (actual.requestDigest !== requestDigest) throw new Error("idempotency-key digest conflict");
    const current = await this.#current(bindingKey);
    if (current === undefined) throw new Error("ambiguous request state: binding exists without a phase record");
    return current;
  }

  async advance(capability: MutationCapability, previous: ActiveRequestState, addition: Record<string, unknown>, options: { readonly allowTechnicalTerminal?: boolean } = {}): Promise<ActiveRequestState> {
    assertMutationCapability(capability);
    const prior = parseRequestState(previous);
    if (prior.phase === "tombstone") throw new Error("cannot advance a tombstone");
    if (prior.storeGeneration !== capability.storeGeneration) throw new Error("mutation capability generation mismatch");
    await this.#initialize();
    const bindingKey = await this.#bindingKeyForState(prior);
    const current = await this.#current(bindingKey);
    if (current === undefined || requestStateDigest(current) !== requestStateDigest(prior)) throw new Error("request state changed before transition");
    const identity = {
      version: 1 as const, clientId: prior.clientId, storeGeneration: prior.storeGeneration, idempotencyKeyHash: prior.idempotencyKeyHash,
      requestDigest: prior.requestDigest, requestId: prior.requestId, transactionId: prior.transactionId, requestObjectId: prior.requestObjectId,
    };
    const candidate = parseRequestState(addition.phase === "result-committed" ? { ...identity, ...addition } : { ...prior, ...addition });
    if (candidate.phase === "tombstone") throw new Error("tombstones are created only by compaction");
    if (!(options.allowTechnicalTerminal === true && prior.phase === "reserved" && candidate.phase === "result-committed")) assertTransition(prior, candidate);
    await this.#publishPhase(bindingKey, candidate);
    return candidate;
  }

  async compactExpired(capability: MutationCapability, terminal: ResultCommittedState, now: Date): Promise<TombstoneState> {
    assertMutationCapability(capability);
    const parsed = parseRequestState(terminal);
    if (parsed.phase !== "result-committed") throw new Error("only committed results may be compacted");
    if (parsed.storeGeneration !== capability.storeGeneration) throw new Error("mutation capability generation mismatch");
    if (!Number.isFinite(now.getTime()) || now.getTime() < new Date(parsed.deliveryDeadline).getTime()) throw new Error("result delivery deadline has not expired");
    await this.#initialize();
    const bindingKey = await this.#bindingKeyForState(parsed);
    const current = await this.#current(bindingKey);
    if (current?.phase !== "result-committed" || requestStateDigest(current) !== requestStateDigest(parsed)) throw new Error("terminal request state changed before compaction");
    const tombstone = parseRequestState({
      version: 1, phase: "tombstone", clientId: parsed.clientId, storeGeneration: parsed.storeGeneration,
      idempotencyKeyHash: parsed.idempotencyKeyHash, requestDigest: parsed.requestDigest, requestId: parsed.requestId,
      transactionId: parsed.transactionId, terminalOutcome: parsed.outcome, expiredAt: now.toISOString(),
    }) as TombstoneState;
    try { await this.#root.publishCreateOnce(`tombstones/${bindingKey}.json`, tombstone); }
    catch (error) {
      if (!(error instanceof DurableRecordExistsError)) throw error;
      if (requestStateDigest(parseRequestState(await this.#root.read(`tombstones/${bindingKey}.json`))) !== requestStateDigest(tombstone)) throw new Error("contradictory request tombstone publication");
    }
    for (const name of await this.#root.entries("phases")) if (name.startsWith(`${bindingKey}-`)) await this.#root.remove(`phases/${name}`);
    try { await this.#root.remove(`bindings/${bindingKey}.json`); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    if (!(await this.#requestObjectReferenced(parsed.requestObjectId))) await this.#objects.removeCanonicalRequest(parsed.requestObjectId);
    return tombstone;
  }

  async #initialize(): Promise<void> { await this.#root.initialize(["bindings", "phases", "tombstones"]); }
  async #readOptional(path: string): Promise<unknown | undefined> { try { return await this.#root.read(path); } catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined; throw error; } }
  async #publishPhase(bindingKey: string, state: ActiveRequestState): Promise<void> {
    const path = `phases/${bindingKey}-${state.phase}.json`;
    try { await this.#root.publishCreateOnce(path, state); }
    catch (error) {
      if (!(error instanceof DurableRecordExistsError)) throw error;
      const existing = parseRequestState(await this.#root.read(path));
      if (requestStateDigest(existing) !== requestStateDigest(state)) throw new Error("contradictory duplicate request-state publication");
    }
  }
  async #current(bindingKey: string): Promise<ActiveRequestState | undefined> {
    const states: ActiveRequestState[] = [];
    for (const name of await this.#root.entries("phases")) {
      if (!name.startsWith(`${bindingKey}-`)) continue;
      const state = parseRequestState(await this.#root.read(`phases/${name}`));
      if (state.phase === "tombstone") throw new Error("tombstone stored in active phase directory");
      states.push(state);
    }
    if (states.some((state) => state.phase === "pass-consumed") && states.some((state) => state.phase === "release-refused")) throw new Error("ambiguous contradictory request branches");
    states.sort((left, right) => phaseOrder[left.phase] - phaseOrder[right.phase]);
    for (let index = 1; index < states.length; index += 1) {
      const previous = states[index - 1]!; const next = states[index]!;
      if (!(previous.phase === "reserved" && next.phase === "result-committed")) assertTransition(previous, next);
    }
    return states.at(-1);
  }
  async #bindingKeyForState(state: ActiveRequestState): Promise<string> {
    for (const name of await this.#root.entries("bindings")) {
      const binding = bindingRecord(await this.#root.read(`bindings/${name}`));
      if (binding.clientId === state.clientId && binding.storeGeneration === state.storeGeneration && binding.idempotencyKeyHash === state.idempotencyKeyHash) {
        if (binding.requestDigest !== state.requestDigest || binding.requestId !== state.requestId || binding.transactionId !== state.transactionId || binding.requestObjectId !== state.requestObjectId) throw new Error("request-state binding conflict");
        return name.replace(/\.json$/u, "");
      }
    }
    throw new Error("request-state binding is missing");
  }
  async #requestObjectReferenced(objectId: string): Promise<boolean> {
    for (const name of await this.#root.entries("bindings")) if (bindingRecord(await this.#root.read(`bindings/${name}`)).requestObjectId === objectId) return true;
    return false;
  }
  #validateReservation(input: ReservationInput, capability: MutationCapability): void {
    for (const [label, value] of [["clientId", input.clientId], ["storeGeneration", input.storeGeneration], ["idempotencyKey", input.idempotencyKey], ["requestId", input.requestId], ["transactionId", input.transactionId]] as const) safe(value, label);
    if (!SHA256.test(input.requestDigest)) throw new TypeError("request digest is invalid");
    if (input.storeGeneration !== capability.storeGeneration) throw new Error("mutation capability generation mismatch");
    if (!(input.canonicalRequest instanceof Uint8Array)) throw new TypeError("canonical request bytes are required");
  }
}
