import { createHash } from "node:crypto";
import { canonicalJson } from "@agent-integrity/core";
import { DurableJsonDirectory, DurableRecordExistsError, type DurableJsonOptions } from "./durable-json.js";
import { PrivateObjectStore, syncRemovalDirectory } from "./private-object-store.js";
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

interface CleanupIntent { readonly name: string; readonly bindingKey: string; readonly states: readonly ActiveRequestState[]; readonly terminal: ResultCommittedState }
interface CleanupInventory { readonly cleanups: readonly CleanupIntent[]; readonly tombstones: ReadonlyMap<string, TombstoneState>; readonly requestReferences: ReadonlySet<string>; readonly registryReferences: ReadonlySet<string> }

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
  readonly #faultInjector: DurableJsonOptions["faultInjector"];

  constructor(directory: string, objects: PrivateObjectStore, options: RequestStoreOptions = {}) {
    this.#maxRecords = options.maxRecords ?? DEFAULT_MAX_RECORDS;
    if (!Number.isSafeInteger(this.#maxRecords) || this.#maxRecords < 1 || this.#maxRecords > 1_000_000) throw new TypeError("maximum request records is invalid");
    this.#objects = objects;
    this.#faultInjector = options.faultInjector;
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
      if (parsed.clientId !== input.clientId || parsed.storeGeneration !== input.storeGeneration || parsed.idempotencyKeyHash !== idempotencyKeyHash) throw new Error("tombstone binding identity mismatch");
      if (parsed.requestDigest !== input.requestDigest) throw new Error("idempotency-key digest conflict");
      throw new Error("expired idempotency key cannot be reused after tombstone compaction");
    }
    const expected: BindingRecord = { version: 1, clientId: input.clientId, storeGeneration: input.storeGeneration, idempotencyKeyHash, requestDigest: input.requestDigest, requestId: input.requestId, transactionId: input.transactionId, requestObjectId: input.requestDigest };
    const existing = await this.#readOptional(`bindings/${bindingKey}.json`);
    if (existing === undefined) {
      const capacity = await this.inspectCapacity();
      const objects = await this.#objects.inspectCapacity();
      const adoptsOrphan = objects.requestObjectIds.includes(input.requestDigest) && !(await this.#requestObjectReferenced(input.requestDigest));
      if (capacity.used + (adoptsOrphan ? 0 : 1) > this.#maxRecords) throw new Error("request store capacity reached");
      await this.#objects.publishCanonicalRequest(requestBytes, input.requestDigest);
      try { await this.#root.publishCreateOnce(`bindings/${bindingKey}.json`, expected); }
      catch (error) {
        if (!(error instanceof DurableRecordExistsError)) throw error;
      }
    }
    const actual = bindingRecord(await this.#root.read(`bindings/${bindingKey}.json`));
    if (canonicalJson(actual) !== canonicalJson(expected)) throw new Error(actual.requestDigest === input.requestDigest ? "idempotency binding ownership conflict" : "idempotency-key digest conflict");
    if (existing !== undefined) {
      await this.#objects.publishCanonicalRequest(requestBytes, actual.requestObjectId);
    }
    await this.#root.ensurePublished(`bindings/${bindingKey}.json`, expected);
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
      if (state.clientId !== clientId || state.storeGeneration !== storeGeneration || state.idempotencyKeyHash !== sha(idempotencyKey)) throw new Error("tombstone binding identity mismatch");
      if (state.requestDigest !== requestDigest) throw new Error("idempotency-key digest conflict");
      await this.#root.ensurePublished(`tombstones/${bindingKey}.json`, state);
      return state;
    }
    const binding = await this.#readOptional(`bindings/${bindingKey}.json`);
    if (binding === undefined) return undefined;
    const actual = bindingRecord(binding);
    if (actual.clientId !== clientId || actual.storeGeneration !== storeGeneration || actual.idempotencyKeyHash !== sha(idempotencyKey)) throw new Error("request binding identity mismatch");
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
    if (options.allowTechnicalTerminal === true && prior.phase === "reserved" && candidate.phase === "result-committed") {
      if (!("error" in candidate.response) || candidate.outcome !== "BLOCKED" || candidate.responseBytesRetained || Object.keys(identity).some(field => canonicalJson((identity as Record<string, unknown>)[field]) !== canonicalJson((candidate as unknown as Record<string, unknown>)[field]))) throw new Error("invalid technical terminal identity or branch");
    } else assertTransition(prior, candidate);
    await this.#publishPhase(bindingKey, candidate);
    return candidate;
  }

  async compactExpired(capability: MutationCapability, terminal: ResultCommittedState, now: Date): Promise<TombstoneState> {
    assertMutationCapability(capability);
    const parsed = parseRequestState(terminal);
    if (parsed.phase !== "result-committed") throw new Error("only committed results may be compacted");
    if (parsed.storeGeneration !== capability.storeGeneration) throw new Error("mutation capability generation mismatch");
    this.#assertExpired(parsed, now);
    await this.#initialize();
    // Retry an interrupted cleanup from its immutable, digest-bound copy of the
    // actual complete journal. Never reconstruct registry IDs from live config.
    const pending = await this.#cleanupInventory(capability, now, parsed);
    const existing = pending.cleanups.find(entry => requestStateDigest(entry.terminal) === requestStateDigest(parsed));
    if (existing !== undefined) return this.#completeCleanup(capability, existing, now);
    const completed = [...pending.tombstones.values()].find(tombstone => tombstone.clientId === parsed.clientId && tombstone.storeGeneration === parsed.storeGeneration && tombstone.idempotencyKeyHash === parsed.idempotencyKeyHash);
    if (completed !== undefined) { this.#assertTombstoneIdentity(completed, parsed); await syncRemovalDirectory(this.#root, ""); return completed; }
    const bindingKey = await this.#bindingKeyForState(parsed);
    const current = await this.#current(bindingKey);
    if (current?.phase !== "result-committed" || requestStateDigest(current) !== requestStateDigest(parsed)) throw new Error("terminal request state changed before compaction");
    const states: ActiveRequestState[] = [];
    for (const name of await this.#root.entries("phases")) if (name.startsWith(`${bindingKey}-`)) {
      const state = parseRequestState(await this.#root.read(`phases/${name}`));
      if (state.phase === "tombstone") throw new Error("invalid cleanup journal");
      states.push(state);
    }
    states.sort((a, b) => phaseOrder[a.phase] - phaseOrder[b.phase]);
    const record = { version: 1, bindingKey, states };
    const name = `cleanup-${bindingKey}-${sha(canonicalJson(record))}.json`;
    await this.#root.publishCreateOnce(name, record);
    const inventory = await this.#cleanupInventory(capability, now);
    const intent = inventory.cleanups.find(entry => entry.name === name);
    if (intent === undefined) throw new Error("cleanup intent missing");
    return this.#completeCleanup(capability, intent, now);
  }

  // Explicit capability-owned maintenance. Completed service retries remain
  // lookup-only; an interrupted tombstone does not authorize an object sweep.
  async resumeExpiredCompactions(capability: MutationCapability, now: Date): Promise<void> {
    assertMutationCapability(capability);
    if (!Number.isFinite(now.getTime())) throw new Error("invalid cleanup time");
    await this.#initialize();
    // Fresh bounded presence inspection is only a no-work shortcut, never a
    // deletion authorization. Every pending intent takes the complete fresh scan.
    if (!(await this.#root.entries("")).some(name => name.startsWith("cleanup-"))) {
      await syncRemovalDirectory(this.#root, "");
      return;
    }
    for (const intent of (await this.#cleanupInventory(capability, now)).cleanups) {
      await this.#completeCleanup(capability, intent, now);
    }
    await syncRemovalDirectory(this.#root, "");
  }

  #assertExpired(terminal: ResultCommittedState, now: Date): void {
    if (!Number.isFinite(now.getTime()) || now.getTime() < new Date(terminal.deliveryDeadline).getTime()) throw new Error("result delivery deadline has not expired");
  }

  async #completeCleanup(capability: MutationCapability, expected: CleanupIntent, now: Date): Promise<TombstoneState> {
    assertMutationCapability(capability);
    const fresh = await this.#cleanupInventory(capability, now);
    const intent = fresh.cleanups.find(entry => entry.name === expected.name);
    if (intent === undefined) throw new Error("cleanup intent changed");
    this.#assertExpired(intent.terminal, now);
    const { terminal, bindingKey } = intent;
    // A prior intent publication may have linked successfully before root sync failed.
    await syncRemovalDirectory(this.#root, "");
    let tombstone = fresh.tombstones.get(bindingKey);
    if (tombstone === undefined) {
      tombstone = parseRequestState({ version: 1, phase: "tombstone", clientId: terminal.clientId, storeGeneration: terminal.storeGeneration,
        idempotencyKeyHash: terminal.idempotencyKeyHash, requestDigest: terminal.requestDigest, requestId: terminal.requestId,
        transactionId: terminal.transactionId, terminalOutcome: terminal.outcome, expiredAt: now.toISOString() }) as TombstoneState;
      await this.#root.publishCreateOnce(`tombstones/${bindingKey}.json`, tombstone);
    }
    // Permanent uniqueness must be durable before any journal/object deletion.
    await syncRemovalDirectory(this.#root, "tombstones");
    await this.#faultInjector?.("cleanup:after-tombstone");
    // The intent is retained across EVERY deletion/sync prefix. Its full journal
    // is checked against every surviving phase/binding and permanent tombstone.
    for (const name of await this.#root.entries("phases")) if (name.startsWith(`${bindingKey}-`)) await this.#root.remove(`phases/${name}`);
    await syncRemovalDirectory(this.#root, "phases");
    await this.#faultInjector?.("cleanup:after-phases");
    await this.#removeOptional(`bindings/${bindingKey}.json`);
    await this.#faultInjector?.("cleanup:after-binding");
    const afterJournal = await this.#cleanupInventory(capability, now);
    if (!afterJournal.requestReferences.has(terminal.requestObjectId)) await this.#objects.removeCanonicalRequest(terminal.requestObjectId);
    await this.#faultInjector?.("cleanup:after-request");
    // Revalidate the complete reference inventory after request deletion too.
    const afterRequest = await this.#cleanupInventory(capability, now);
    const registryIds = new Set(intent.states.flatMap(state => "trustSnapshotObjectId" in state ? [state.trustSnapshotObjectId] : []));
    for (const id of registryIds) {
      if (!afterRequest.registryReferences.has(id)) await this.#objects.removeTrustRegistry(capability, id);
    }
    await this.#faultInjector?.("cleanup:after-registry");
    await this.#root.remove(intent.name);
    return tombstone;
  }

  async #removeOptional(path: string): Promise<void> {
    try { await this.#root.remove(path); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; await syncRemovalDirectory(this.#root, "bindings"); }
  }

  #parseCleanupIntent(name: string, value: unknown): CleanupIntent {
      if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("cleanup intent is invalid");
      const record = value as Record<string, unknown>;
      if (Object.keys(record).sort().join(",") !== "bindingKey,states,version" || record.version !== 1 || typeof record.bindingKey !== "string" || !SHA256.test(record.bindingKey) || !Array.isArray(record.states) || record.states.length < 2 || record.states.length > 7 || name !== `cleanup-${record.bindingKey}-${sha(canonicalJson(record))}.json`) throw new Error("cleanup intent digest or schema is invalid");
      const states = record.states.map(parseRequestState);
      if (states.some(state => state.phase === "tombstone")) throw new Error("cleanup contains tombstone as journal");
      const active = states as ActiveRequestState[];
      this.#validateJournal(active);
      const terminal = active.at(-1);
      if (terminal?.phase !== "result-committed" || terminal.requestObjectId !== terminal.requestDigest) throw new Error("cleanup terminal invalid");
    return { name, bindingKey: record.bindingKey as string, states: active, terminal };
  }

  async #cleanupInventory(capability: MutationCapability, now: Date, compacting?: ResultCommittedState): Promise<CleanupInventory> {
    assertMutationCapability(capability);
    const cleanups: CleanupIntent[] = [];
    const byKey = new Map<string, CleanupIntent>();
    for (const name of (await this.#root.entries("")).filter(name => name.startsWith("cleanup-"))) {
      const intent = this.#parseCleanupIntent(name, await this.#root.read(name));
      if (intent.terminal.storeGeneration !== capability.storeGeneration) throw new Error("cleanup generation mismatch");
      this.#assertExpired(intent.terminal, now);
      if (byKey.has(intent.bindingKey)) throw new Error("duplicate cleanup intent");
      cleanups.push(intent); byKey.set(intent.bindingKey, intent);
    }
    const tombstones = new Map<string, TombstoneState>();
    for (const name of await this.#root.entries("tombstones")) {
      if (!/^[a-f0-9]{64}\.json$/u.test(name)) throw new Error("unexpected tombstone entry");
      const state = parseRequestState(await this.#root.read(`tombstones/${name}`));
      if (state.phase !== "tombstone") throw new Error("invalid tombstone");
      const key = name.slice(0, -5); tombstones.set(key, state);
      const intent = byKey.get(key);
      if (intent !== undefined) {
        this.#assertTombstoneIdentity(state, intent.terminal);
        if (new Date(state.expiredAt).getTime() < new Date(intent.terminal.deliveryDeadline).getTime() || new Date(state.expiredAt).getTime() > now.getTime()) throw new Error("cleanup tombstone time conflict");
      }
    }
    const bindings = new Map<string, BindingRecord>();
    for (const name of await this.#root.entries("bindings")) {
      if (!/^[a-f0-9]{64}\.json$/u.test(name)) throw new Error("unexpected request binding entry");
      const binding = bindingRecord(await this.#root.read(`bindings/${name}`));
      if (binding.requestObjectId !== binding.requestDigest) throw new Error("request object binding mismatch");
      bindings.set(name.slice(0, -5), binding);
      const intent = byKey.get(name.slice(0, -5));
      if (intent !== undefined) this.#assertBindingIdentity(binding, intent.terminal);
      const tombstone = tombstones.get(name.slice(0, -5));
      if (tombstone !== undefined && intent === undefined) throw new Error("tombstone binding without cleanup proof");
    }
    const journals = new Map<string, ActiveRequestState[]>();
    const phaseNames = await this.#root.entries("phases");
    // Fresh global journal reads use the same bounded four-job cap as #current.
    // Checks depend only on the already-fresh binding/intent maps; drain before
    // rejection and update the local journal lists in original lexical order.
    for (let offset = 0; offset < phaseNames.length; offset += 4) {
      const checked = await Promise.allSettled(phaseNames.slice(offset, offset + 4).map(async name => {
        const state = parseRequestState(await this.#root.read(`phases/${name}`));
        if (state.phase === "tombstone" || !/^[a-f0-9]{64}-/u.test(name)) throw new Error("unexpected request phase entry");
        const key = name.slice(0, 64);
        if (name !== `${key}-${state.phase}.json`) throw new Error("request phase filename mismatch");
        const intent = byKey.get(key);
        const binding = bindings.get(key);
        if (binding === undefined && intent === undefined) throw new Error("orphan request journal");
        if (binding !== undefined) this.#assertBindingIdentity(binding, state);
        if (intent !== undefined && !intent.states.some(original => requestStateDigest(original) === requestStateDigest(state))) throw new Error("cleanup journal contradiction");
        return { key, state };
      }));
      for (const result of checked) {
        if (result.status === "rejected") throw result.reason;
        const { key, state } = result.value;
        const list = journals.get(key) ?? []; list.push(state); journals.set(key, list);
      }
    }
    const requestReferences = new Set<string>(), registryReferences = new Set<string>();
    for (const [key, binding] of bindings) {
      if (byKey.has(key)) continue;
      const states = journals.get(key) ?? [];
      if (states.length === 0) throw new Error("ambiguous request state: binding exists without a phase record");
      {
        // Independent current lookup retains a fresh binding read per phase.
        const current = await this.#current(key);
        if (compacting !== undefined && binding.clientId === compacting.clientId && binding.storeGeneration === compacting.storeGeneration && binding.idempotencyKeyHash === compacting.idempotencyKeyHash) {
          this.#assertBindingIdentity(binding, compacting);
          if (current?.phase !== "result-committed" || requestStateDigest(current) !== requestStateDigest(compacting)) throw new Error("terminal request state changed before compaction");
          this.#assertExpired(current, now);
          // Missing terminal objects are a cleanup retry, not authority to repair
          // inputs or restart verification. Other live references remain required.
          continue;
        }
      }
      requestReferences.add(binding.requestObjectId);
      for (const state of states) if ("trustSnapshotObjectId" in state) {
        if (state.trustSnapshotObjectId !== state.trustSnapshotDigest) throw new Error("registry object binding mismatch");
        registryReferences.add(state.trustSnapshotObjectId);
      }
    }
    for (const intent of cleanups) {
      const binding = bindings.get(intent.bindingKey), tombstone = tombstones.get(intent.bindingKey);
      // entries() and the removal loop use lexical filename order, NOT phase
      // chronology. The saved full chain proves history; only its exact ordered
      // deletion suffix proves the CURRENT journal is a reachable crash prefix.
      const ordered = intent.states.map(state => ({ name: `${intent.bindingKey}-${state.phase}.json`, state })).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
      const surviving = journals.get(intent.bindingKey) ?? [];
      const removed = ordered.length - surviving.length;
      const suffix = ordered.slice(removed);
      if (removed < 0 || suffix.some(original => !surviving.some(state => requestStateDigest(state) === requestStateDigest(original.state))) ||
          (binding === undefined && surviving.length !== 0) ||
          (tombstone === undefined && (binding === undefined || removed !== 0))) throw new Error("cleanup journal deletion prefix mismatch");
      if (tombstone === undefined) {
        if (binding === undefined) throw new Error("orphan cleanup intent");
        const current = await this.#current(intent.bindingKey);
        if (current === undefined || requestStateDigest(current) !== requestStateDigest(intent.terminal)) throw new Error("cleanup current terminal mismatch");
      }
    }
    // Bounded fresh object validation precedes any deletion, including unrelated
    // corrupt objects. Missing cleanup candidates are an idempotent retry only.
    await this.#objects.inspectCapacity();
    const reads: (() => Promise<Buffer>)[] = [
      ...[...requestReferences].map(id => () => this.#objects.readCanonicalRequest(id)),
      ...[...registryReferences].map(id => () => this.#objects.readTrustRegistry(id)),
    ];
    for (let offset = 0; offset < reads.length; offset += 4) {
      const checked = await Promise.allSettled(reads.slice(offset, offset + 4).map(read => read()));
      for (const value of checked) if (value.status === "rejected") throw value.reason;
    }
    return { cleanups, tombstones, requestReferences, registryReferences };
  }

  #assertBindingIdentity(binding: BindingRecord, state: ActiveRequestState): void {
    for (const field of ["version", "clientId", "storeGeneration", "idempotencyKeyHash", "requestDigest", "requestId", "transactionId", "requestObjectId"] as const) if (canonicalJson(binding[field]) !== canonicalJson(state[field])) throw new Error("journal binding identity mismatch");
  }
  #assertTombstoneIdentity(tombstone: TombstoneState, terminal: ResultCommittedState): void {
    for (const field of ["clientId", "storeGeneration", "idempotencyKeyHash", "requestDigest", "requestId", "transactionId"] as const) if (tombstone[field] !== terminal[field]) throw new Error("cleanup tombstone identity mismatch");
    if (tombstone.terminalOutcome !== terminal.outcome) throw new Error("cleanup tombstone outcome mismatch");
  }
  #validateJournal(states: ActiveRequestState[]): void {
    if (states[0]?.phase !== "reserved") throw new Error("request journal reserved predecessor missing");
    for (let index = 1; index < states.length; index++) {
      const previous = states[index - 1]!, next = states[index]!;
      if (previous.phase === "reserved" && next.phase === "result-committed") {
        this.#assertBindingIdentity(previous, next);
        if (!("error" in next.response) || next.outcome !== "BLOCKED" || next.responseBytesRetained) throw new Error("unproved technical terminal branch");
      } else assertTransition(previous, next);
    }
    for (const state of states) if ("trustSnapshotObjectId" in state && state.trustSnapshotObjectId !== state.trustSnapshotDigest) throw new Error("registry object binding mismatch");
  }

  async inspectCapacity(): Promise<Readonly<{ used: number; maximum: number; orphanObjects: number }>> {
    await this.#initialize();
    const keys = new Set<string>(); const references = new Set<string>();
    for (const name of await this.#root.entries("bindings")) {
      if (!/^[a-f0-9]{64}\.json$/u.test(name)) throw new Error("unexpected request binding entry");
      const binding = bindingRecord(await this.#root.read(`bindings/${name}`));
      keys.add(name); references.add(binding.requestObjectId);
    }
    for (const name of await this.#root.entries("tombstones")) {
      if (!/^[a-f0-9]{64}\.json$/u.test(name)) throw new Error("unexpected tombstone entry");
      const state = parseRequestState(await this.#root.read(`tombstones/${name}`));
      if (state.phase !== "tombstone") throw new Error("invalid tombstone");
      keys.add(name);
    }
    // Pending cleanup is still the same permanent request identity, not an
    // additional orphan request quota charge after its binding was removed.
    const cleanupKeys = new Set<string>();
    for (const name of (await this.#root.entries("")).filter(name => name.startsWith("cleanup-"))) {
      const intent = this.#parseCleanupIntent(name, await this.#root.read(name));
      if (cleanupKeys.has(intent.bindingKey)) throw new Error("duplicate cleanup intent");
      cleanupKeys.add(intent.bindingKey);
      const binding = await this.#readOptional(`bindings/${intent.bindingKey}.json`);
      if (binding !== undefined) this.#assertBindingIdentity(bindingRecord(binding), intent.terminal);
      const tombstone = await this.#readOptional(`tombstones/${intent.bindingKey}.json`);
      if (tombstone !== undefined) {
        const state = parseRequestState(tombstone);
        if (state.phase !== "tombstone") throw new Error("cleanup tombstone invalid");
        this.#assertTombstoneIdentity(state, intent.terminal);
      } else if (binding === undefined) throw new Error("orphan cleanup intent");
      keys.add(intent.bindingKey + ".json"); references.add(intent.terminal.requestObjectId);
    }
    const objects = await this.#objects.inspectCapacity();
    const orphanObjects = objects.requestObjectIds.filter(id => !references.has(id)).length;
    return Object.freeze({ used: keys.size + orphanObjects, maximum: this.#maxRecords, orphanObjects });
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
      await this.#root.ensurePublished(path, state);
    }
  }
  async #current(bindingKey: string): Promise<ActiveRequestState | undefined> {
    const states: ActiveRequestState[] = [];
    const names = (await this.#root.entries("phases")).filter(name => name.startsWith(`${bindingKey}-`));
    // Keep a fresh binding read for EVERY phase; batch only independent inspections.
    // No started read may outlive rejection and invocation-owned teardown.
    for (let offset = 0; offset < names.length; offset += 4) {
      const checked = await Promise.allSettled(names.slice(offset, offset + 4).map(async name => {
        const state = parseRequestState(await this.#root.read(`phases/${name}`));
        if (state.phase === "tombstone") throw new Error("tombstone stored in active phase directory");
        if (name !== `${bindingKey}-${state.phase}.json`) throw new Error("request phase filename mismatch");
        const binding = bindingRecord(await this.#root.read(`bindings/${bindingKey}.json`));
        for (const field of Object.keys(binding) as (keyof BindingRecord)[]) if (canonicalJson(binding[field]) !== canonicalJson(state[field])) throw new Error("journal binding identity mismatch");
        return state;
      }));
      for (const value of checked) {
        if (value.status === "rejected") throw value.reason;
        states.push(value.value);
      }
    }
    if (states.length > 0 && !states.some(state => state.phase === "reserved")) throw new Error("request journal reserved predecessor missing");
    if (states.some((state) => state.phase === "pass-consumed") && states.some((state) => state.phase === "release-refused")) throw new Error("ambiguous contradictory request branches");
    states.sort((left, right) => phaseOrder[left.phase] - phaseOrder[right.phase]);
    for (let index = 1; index < states.length; index += 1) {
      const previous = states[index - 1]!; const next = states[index]!;
      if (previous.phase === "reserved" && next.phase === "result-committed") {
        if (!("error" in next.response) || next.outcome !== "BLOCKED" || next.responseBytesRetained) throw new Error("unproved technical terminal branch");
      } else assertTransition(previous, next);
    }
    // A recovered visible phase may follow a previously failed link barrier.
    // Revalidate the complete legal journal before establishing publication durability.
    for (let offset = 0; offset < states.length; offset += 4) {
      const barriers = await Promise.allSettled(states.slice(offset, offset + 4).map(state =>
        this.#root.ensurePublished(`phases/${bindingKey}-${state.phase}.json`, state)));
      for (const barrier of barriers) if (barrier.status === "rejected") throw barrier.reason;
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
