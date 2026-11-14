import { allowDiskIntegrationTime } from "./support/disk-integration-timeout.js";
allowDiskIntegrationTime();
import { FileReceiptStore, buildReceipt, verifyTrustedEnvelope, RECEIPT_STORE_LOCK_AUTHORIZER } from "@agent-integrity/core";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, writeFile, mkdir, rename, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { StateCoordinator, assertMutationCapability } from "../src/state-coordinator.js";
import { trustedEnvelopeFixture } from "../../core/tests/support/trusted-envelope.js";
import { receiptSigningOptions } from "../../core/tests/support/receipt-keys.js";
const roots: string[] = [];
const pendingInvocations = new Set<Promise<unknown>>();
function trackInvocation<T>(operation: () => Promise<T>): Promise<T> {
 const pending = Promise.resolve().then(operation);
 pendingInvocations.add(pending);
 void pending.then(() => pendingInvocations.delete(pending), () => pendingInvocations.delete(pending));
 return pending;
}
afterEach(async () => {
 while (pendingInvocations.size !== 0) await Promise.allSettled([...pendingInvocations]);
 await Promise.all(roots.splice(0).map(path => rm(path, { recursive: true, force: true })));
});
const hash = (value: string) => createHash("sha256").update(value).digest("hex");
let receipt: ReturnType<typeof buildReceipt>;
beforeAll(async () => {
    const { envelope, context } = await trustedEnvelopeFixture();
    receipt = buildReceipt({ runId: "handoff-run", nonce: "handoff-nonce", envelope, verification: await verifyTrustedEnvelope(envelope, context), ...receiptSigningOptions, createdAt: new Date("2026-08-02T00:00:00.000Z"), expiresAt: new Date("2026-08-02T01:00:00.000Z") });
});
async function setup(names = ["receipts"], crash = true) {
    const parent = await mkdtemp(join(tmpdir(), "task8-handoff-"));
    roots.push(parent);
    const state = join(parent, "state");
    const options = { storeGeneration: "generation-1", nestedLockNames: names, nestedLockPaths: Object.fromEntries(names.map(name => [name, name + "/.store-lock.json"])) };
    const coordinator = await StateCoordinator.acquire(state, options);
    const authority = await coordinator.withMutation(c => ({ ...c }));
    if (crash)
        await coordinator.withMutation(async (c) => { for (const name of names) {
            const store = new FileReceiptStore(join(state, name), { lockOwnership: coordinator.receiptStoreLockOwnership(c), faultInjector: point => { if (point === "transaction:after-publish" || point === "lock:before-release")
                    throw new Error("simulated process crash"); } });
            await expect(store.issue(receipt, { transactionId: "original-tx" })).rejects.toThrow(/crash/);
        } });
    const recover = (extra: Record<string, unknown> = {}) => StateCoordinator.recoverAbandoned(state, { ...options, offlineExclusive: true, expectedOwnerToken: authority.ownerToken, expectedRootIdentityDigest: authority.rootIdentityDigest, ...extra });
    return { state, options, coordinator, authority, receipt, recover };
}
async function complete(coordinator: StateCoordinator) { return coordinator.withMutation(c => coordinator.completeNestedLockHandoff(c)); }
async function marker(state: string, name = "receipts") { return JSON.parse(await readFile(join(state, name, ".store-lock.json"), "utf8")); }
describe("Task8 protected whole-root nested lock handoff", () => {
    it("records a real interrupted store lock, explicitly completes it and uses only the effective new owner", async () => { const h = await setup(); expect(await marker(h.state)).toMatchObject(h.authority); await expect(StateCoordinator.acquire(h.state, h.options)).rejects.toThrow(/lease|owner/); const recovered = await h.recover(); await recovered.withMutation(c => expect(() => recovered.receiptStoreLockOwnership(c)).toThrow(/complete|handoff/)); await expect(recovered.close()).rejects.toThrow(/nested|handoff|lock/); await complete(recovered); await expect(marker(h.state)).rejects.toThrow(); await complete(recovered); await recovered.withMutation(async (c) => { const store = new FileReceiptStore(join(h.state, "receipts"), { lockOwnership: recovered.receiptStoreLockOwnership(c), faultInjector: point => { if (point === "lock:after-publish")
            throw new Error("observe current token"); } }); await expect(store.issue(h.receipt, { transactionId: "original-tx" })).rejects.toThrow(); expect(await marker(h.state)).toMatchObject(c); await expect(complete(recovered)).rejects.toThrow(/concurrent/); }); });
    it("allows actual same-store issuance and consume after completion", async () => { const h = await setup(); const recovered = await h.recover(); await complete(recovered); await recovered.withMutation(async (c) => { const store = new FileReceiptStore(join(h.state, "receipts"), { lockOwnership: recovered.receiptStoreLockOwnership(c) }); await store.completePreparedIssue(h.receipt, { transactionId: "original-tx" }); await store.consume(h.receipt, new Date("2026-08-02T00:20:00.000Z")); expect(await store.inspectConsumed(h.receipt.receiptDigest)).toMatchObject({ transactionId: "original-tx" }); }); await complete(recovered); await recovered.close(); await StateCoordinator.acquire(h.state, h.options); });
    it("handles absent locks without inventing completion authority", async () => { const h = await setup(["receipts"], false); const recovered = await h.recover(); await complete(recovered); expect(await readdir(join(h.state, "nested-locks"))).toEqual([]); await recovered.close(); });
    it("rejects token-only and forged capability reclaim", async () => { const h = await setup(); const recovered = await h.recover(); await expect(new FileReceiptStore(join(h.state, "receipts")).recoverAbandonedLock({ offlineExclusive: true, ownerToken: h.authority.ownerToken })).rejects.toThrow(/malformed|ownership/); await expect(recovered.completeNestedLockHandoff({ ...h.authority })).rejects.toThrow(/capability/); expect(await marker(h.state)).toMatchObject(h.authority); });
    it.each(["missing", "foreign", "generation", "root", "unexpected", "directory", "symlink"])("fails closed on %s after durable whole-root handoff", async (kind) => { const h = await setup(); const recovered = await h.recover(); const path = join(h.state, "receipts", ".store-lock.json"); if (kind === "missing")
        await rm(path);
    else if (kind === "unexpected") {
        await mkdir(join(h.state, "extra"), { mode: 0o700 });
        await writeFile(join(h.state, "extra", ".store-lock.json"), JSON.stringify({ version: 2, ...h.authority }), { mode: 0o600 });
    }
    else if (kind === "directory") {
        await rename(join(h.state, "receipts"), join(h.state, "saved"));
        await mkdir(join(h.state, "receipts"), { mode: 0o700 });
    }
    else if (kind === "symlink") {
        await rename(path, path + ".saved");
        await symlink(path + ".saved", path);
    }
    else {
        const old = await marker(h.state);
        await writeFile(path, JSON.stringify({ ...old, ...(kind === "foreign" ? { ownerToken: "foreign" } : kind === "generation" ? { storeGeneration: "wrong" } : { rootIdentityDigest: hash("wrong") }) }));
    } await expect(complete(recovered)).rejects.toThrow(); await expect(recovered.close()).rejects.toThrow(); const effective = await recovered.withMutation(c => ({ ...c })); await expect(StateCoordinator.recoverAbandoned(h.state, { ...h.options, offlineExclusive: true, expectedOwnerToken: effective.ownerToken, expectedRootIdentityDigest: effective.rootIdentityDigest })).rejects.toThrow(); expect(await readdir(join(h.state, "handoffs"))).toHaveLength(1); });
    it("rejects byte-identical marker replacement before completion intent", async () => { const h = await setup(); const recovered = await h.recover(); const path = join(h.state, "receipts", ".store-lock.json"); const old = await readFile(path); await rename(path, path + ".original"); await writeFile(path, old, { mode: 0o600 }); await expect(complete(recovered)).rejects.toThrow(/identity|replaced/); expect(await readFile(path)).toEqual(old); expect(await readdir(join(h.state, "nested-locks"))).toEqual([]); await expect(recovered.close()).rejects.toThrow(/identity|replaced/); });
    it("rejects fresh acquire on stale locks after lease removal", async () => { const h = await setup(); await rm(join(h.state, "lease.json")); await expect(StateCoordinator.acquire(h.state, h.options)).rejects.toThrow(/nested|lock/); await expect(readFile(join(h.state, "lease.json"))).rejects.toThrow(); });
    it("recovers crash after handoff persistence before return without rewriting immutable inventory", async () => { const h = await setup(); let fired = false; await expect(h.recover({ nextOwnerToken: "next-owner", faultInjector: async (point: string) => { if (point === "directory:before-sync" && !fired && (await readdir(join(h.state, "handoffs"))).length !== 0) {
            fired = true;
            throw new Error("handoff durable publication crash");
        } } })).rejects.toThrow(/crash/); const [name] = await readdir(join(h.state, "handoffs")); const before = await readFile(join(h.state, "handoffs", name!), "utf8"); const recovered = await StateCoordinator.recoverAbandoned(h.state, { ...h.options, offlineExclusive: true, expectedOwnerToken: "next-owner", expectedRootIdentityDigest: h.authority.rootIdentityDigest, nextOwnerToken: "third-owner" }); await complete(recovered); expect(await readFile(join(h.state, "handoffs", name!), "utf8")).toBe(before); });
    for (const point of ["handoff:after-proof", "handoff:after-remove", "handoff:after-completion"])
        for (const ordinal of [1, 2]) {
            it("resumes " + point + " at nested lock " + ordinal + " with create-once evidence across another root crash", async () => { const h = await setup(["receipts", "second"]); let fired = false; let count = 0; const recovered = await h.recover({ nextOwnerToken: "next-owner", faultInjector: (p: string) => { if (p === point && ++count === ordinal && !fired) {
                    fired = true;
                    throw new Error("completion crash");
                } } }); await expect(complete(recovered)).rejects.toThrow(/crash/); expect(fired).toBe(true); const files = await readdir(join(h.state, "handoffs")); const before = await readFile(join(h.state, "handoffs", files[0]!), "utf8"); const again = await StateCoordinator.recoverAbandoned(h.state, { ...h.options, offlineExclusive: true, expectedOwnerToken: "next-owner", expectedRootIdentityDigest: h.authority.rootIdentityDigest, nextOwnerToken: "third-owner" }); await complete(again); await complete(again); for (const name of h.options.nestedLockNames)
                await expect(marker(h.state, name)).rejects.toThrow(); expect(await readFile(join(h.state, "handoffs", files[0]!), "utf8")).toBe(before); await again.close(); });
        }
    it("completes a real consume lock left after consumed evidence persisted", async () => { const h = await setup(["receipts"], false); await h.coordinator.withMutation(async (c) => { const ownership = h.coordinator.receiptStoreLockOwnership(c); const store = new FileReceiptStore(join(h.state, "receipts"), { lockOwnership: ownership }); await store.issue(h.receipt, { transactionId: "original-tx" }); const interrupted = new FileReceiptStore(join(h.state, "receipts"), { lockOwnership: ownership, faultInjector: point => { if (point === "consumed:after-publish" || point === "lock:before-release")
            throw new Error("consume process crash"); } }); await expect(interrupted.consume(h.receipt, new Date("2026-08-02T00:20:00.000Z"))).rejects.toThrow(/crash/); }); expect(await marker(h.state)).toMatchObject(h.authority); const recovered = await h.recover(); await complete(recovered); await recovered.withMutation(async (c) => { const store = new FileReceiptStore(join(h.state, "receipts"), { lockOwnership: recovered.receiptStoreLockOwnership(c) }); expect(await store.inspectConsumed(h.receipt.receiptDigest)).toMatchObject({ transactionId: "original-tx" }); await expect(store.consume(h.receipt, new Date("2026-08-02T00:20:00.000Z"))).rejects.toThrow(/consumed/); }); await recovered.close(); });
    it("requires persisted whole-root handoff even with a live root authorizer", async () => { const h = await setup(); await h.coordinator.withMutation(async (c) => { const store = new FileReceiptStore(join(h.state, "receipts"), { lockOwnership: h.coordinator.receiptStoreLockOwnership(c) }); await expect(store.completeRootAuthorizedLockHandoff({ offlineExclusive: true, rootDirectory: h.state, handoffPreviousOwnerToken: c.ownerToken, lockName: "receipts" })).rejects.toThrow(/durable|handoff/); await expect(store.recoverAbandonedLock({ offlineExclusive: true, ownerToken: c.ownerToken })).rejects.toThrow(/handoff|authority/); }); expect(await marker(h.state)).toMatchObject(h.authority); });
    it.each(["marker-replaced", "proof-drift"])("rejects %s after durable per-lock intent", async (kind) => { const h = await setup(); let fired = false; const recovered = await h.recover({ faultInjector: (p: string) => { if (p === "handoff:after-proof" && !fired) {
            fired = true;
            throw new Error("intent crash");
        } } }); await expect(complete(recovered)).rejects.toThrow(/crash/); const old = await readFile(join(h.state, "receipts", ".store-lock.json")); if (kind === "marker-replaced") {
        await rename(join(h.state, "receipts", ".store-lock.json"), join(h.state, "receipts", "saved-marker"));
        await writeFile(join(h.state, "receipts", ".store-lock.json"), old, { mode: 0o600 });
    }
    else {
        const [name] = await readdir(join(h.state, "nested-locks"));
        const path = join(h.state, "nested-locks", name!);
        const proof = JSON.parse(await readFile(path, "utf8"));
        await writeFile(path, JSON.stringify({ ...proof, handoffDigest: hash("changed") }));
    } await expect(complete(recovered)).rejects.toThrow(/identity|proof|mismatch/); expect(await marker(h.state)).toMatchObject(h.authority); await expect(recovered.close()).rejects.toThrow(); });
    it("rejects old marker resurrection and preserves acknowledged completion evidence on repeat", async () => { const h = await setup(); const old = await readFile(join(h.state, "receipts", ".store-lock.json")); const recovered = await h.recover(); await complete(recovered); const names = await readdir(join(h.state, "nested-locks")); const before = await Promise.all(names.map(name => readFile(join(h.state, "nested-locks", name), "utf8"))); await complete(recovered); expect(await Promise.all(names.map(name => readFile(join(h.state, "nested-locks", name), "utf8")))).toEqual(before); await writeFile(join(h.state, "receipts", ".store-lock.json"), old, { mode: 0o600 }); await expect(complete(recovered)).rejects.toThrow(/reappeared/); await expect(recovered.close()).rejects.toThrow(/reappeared/); });
    it("refuses historic root token reuse before appending another handoff", async () => { const h = await setup(); const recovered = await h.recover(); const effective = await recovered.withMutation(c => ({ ...c })); await expect(StateCoordinator.recoverAbandoned(h.state, { ...h.options, offlineExclusive: true, expectedOwnerToken: effective.ownerToken, expectedRootIdentityDigest: effective.rootIdentityDigest, nextOwnerToken: h.authority.ownerToken })).rejects.toThrow(/reuse/); expect(await readdir(join(h.state, "handoffs"))).toHaveLength(1); });
    it("survives removal-before-ack followed by another completion crash without rewriting intent", () => trackInvocation(async () => {
        const h = await setup();
        const first = await h.recover({nextOwnerToken:"second-owner", faultInjector:(point:string)=>{if(point==="handoff:after-remove") throw new Error("first crash");}});
        await expect(complete(first)).rejects.toThrow(/first crash/);
        const [proofName] = await readdir(join(h.state,"nested-locks"));
        const proofBefore = await readFile(join(h.state,"nested-locks",proofName!),"utf8");
        const second = await StateCoordinator.recoverAbandoned(h.state,{...h.options,offlineExclusive:true,expectedOwnerToken:"second-owner",expectedRootIdentityDigest:h.authority.rootIdentityDigest,nextOwnerToken:"third-owner",faultInjector:point=>{if(point==="handoff:after-completion") throw new Error("second crash");}});
        await expect(complete(second)).rejects.toThrow(/second crash/);
        const third = await StateCoordinator.recoverAbandoned(h.state,{...h.options,offlineExclusive:true,expectedOwnerToken:"third-owner",expectedRootIdentityDigest:h.authority.rootIdentityDigest,nextOwnerToken:"fourth-owner"});
        await complete(third); await complete(third);
        expect(await readFile(join(h.state,"nested-locks",proofName!),"utf8")).toBe(proofBefore);
        await third.withMutation(async c=>{const store=new FileReceiptStore(join(h.state,"receipts"),{lockOwnership:third.receiptStoreLockOwnership(c)});await store.completePreparedIssue(h.receipt,{transactionId:"original-tx"});});
        await third.close();
    }));
    it.each(["identity-missing","identity-partial","identity-drift","identity-cross-state"])("fails closed on immutable handoff %s", async kind=>{
        const h=await setup();const recovered=await h.recover();const [name]=await readdir(join(h.state,"handoffs"));const path=join(h.state,"handoffs",name!);const handoff=JSON.parse(await readFile(path,"utf8"));
        if(kind==="identity-missing") delete handoff.nestedMarkerIdentities;
        else if(kind==="identity-partial") delete handoff.nestedMarkerIdentities.receipts;
        else if(kind==="identity-drift") handoff.nestedMarkerIdentities.receipts.ino++;
        else {const other=await setup();await other.recover();const [otherName]=await readdir(join(other.state,"handoffs"));handoff.nestedMarkerIdentities=JSON.parse(await readFile(join(other.state,"handoffs",otherName!),"utf8")).nestedMarkerIdentities;}
        await writeFile(path,JSON.stringify(handoff));
        await expect(complete(recovered)).rejects.toThrow(/handoff|identity/);await expect(recovered.close()).rejects.toThrow();expect(await marker(h.state)).toMatchObject(h.authority);expect(await readdir(join(h.state,"nested-locks"))).toEqual([]);
    });
    it("core independently rejects original marker replacement with live effective-root capability", async()=>{
        const h=await setup();const recovered=await h.recover();const path=join(h.state,"receipts",".store-lock.json");const old=await readFile(path);await rename(path,path+".original");await writeFile(path,old,{mode:0o600});
        await recovered.withMutation(async c=>{
            const ownership={...c,[RECEIPT_STORE_LOCK_AUTHORIZER]:()=>assertMutationCapability(c)};
            const store=new FileReceiptStore(join(h.state,"receipts"),{lockOwnership:ownership});
            await expect(store.completeRootAuthorizedLockHandoff({offlineExclusive:true,rootDirectory:h.state,handoffPreviousOwnerToken:h.authority.ownerToken,lockName:"receipts"})).rejects.toThrow(/identity/);
        });
        expect(await readFile(path)).toEqual(old);expect(await readdir(join(h.state,"nested-locks"))).toEqual([]);
    });
    it("rejects drifted identity on a carried prior marker in a later root handoff", async()=>{
        const h=await setup();const first=await h.recover({nextOwnerToken:"second-owner"});
        const next=await StateCoordinator.recoverAbandoned(h.state,{...h.options,offlineExclusive:true,expectedOwnerToken:"second-owner",expectedRootIdentityDigest:h.authority.rootIdentityDigest,nextOwnerToken:"third-owner"});
        const path=join(h.state,"handoffs",hash("second-owner")+".json");const record=JSON.parse(await readFile(path,"utf8"));record.nestedMarkerIdentities.receipts.ino++;await writeFile(path,JSON.stringify(record));
        await expect(complete(next)).rejects.toThrow(/identity|prior/);expect(await marker(h.state)).toMatchObject(h.authority);expect(await readdir(join(h.state,"nested-locks"))).toEqual([]);
    });
});
