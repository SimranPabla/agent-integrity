import { readFileSync } from "node:fs";
import Ajv from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { describe, expect, it } from "vitest";
import { assertAlphaIntegrityReceipt } from "../../src/schema/validate-receipt.js";
import { captureJsonData } from "../../src/capture-json.js";

const ajv = new Ajv({ allErrors: true });
addFormats(ajv);
const oracle = ajv.compile(JSON.parse(readFileSync(new URL("../../../../schemas/integrity-receipt.schema.json", import.meta.url), "utf8")));
const base: any = { protocolVersion: "1-alpha", receiptVersion: "2-alpha", engineVersion: "1", issuer: "i", audience: "a", purpose: "p", nonce: "n", runId: "r", createdAt: "2026-10-11T17:00:00Z", expiresAt: "2026-10-11T18:00:00Z", policyDigest: "a".repeat(64), envelopeDigest: "b".repeat(64), receiptDigest: "c".repeat(64), verification: { protocolVersion: "1-alpha", status: "PASS", findings: [{ code: "c", severity: "review", message: "m" }] }, signature: { algorithm: "Ed25519", keyId: "k", value: "A".repeat(86) + "==" } };
const vectors: [string, unknown][] = [["baseline", base]];
const add = (name: string, mutate: (r: any) => void) => { const r = structuredClone(base); mutate(r); vectors.push([name, r]); };
const at = (r: any, path: string[]) => path.reduce((v, k) => v[k], r);
for (const path of [[], ["verification"], ["signature"], ["verification", "findings", "0"]]) {
  const obj = at(base, path);
  for (const key of Object.keys(obj)) {
    add(path.join(".") + " missing " + key, r => { delete at(r, path)[key]; });
    for (const value of [null, false, 42, [], {}, "", "wrong", "\n"]) add(path.join(".") + " type/enum " + key + JSON.stringify(value), r => { at(r, path)[key] = value; });
  }
  add(path.join(".") + " extra", r => { at(r, path).extra = 1; });
  if (path.length) for (const value of [null, [], false, "x"]) add(path.join(".") + " nonobject " + JSON.stringify(value), r => { at(r, path.slice(0, -1))[path.at(-1)!] = value; });
}
for (const value of [null, [], false, 1, "x"]) vectors.push(["root primitive " + JSON.stringify(value), value]);
for (const field of ["engineVersion", "issuer", "audience", "purpose", "nonce", "signature.keyId"]) for (const value of [" ", "a".repeat(256), "a".repeat(257), "😀".repeat(256), "😀".repeat(257), "\ud800".repeat(256)]) add(field + " length " + value.length, r => { const p = field.split("."); at(r, p.slice(0, -1))[p.at(-1)!] = value; });
for (const field of ["policyDigest", "envelopeDigest", "receiptDigest"]) for (const value of ["a".repeat(63), "a".repeat(65), "A".repeat(64), "g".repeat(64), "a".repeat(64) + "\n"]) add(field + " pattern " + value, r => { r[field] = value; });
for (const value of ["r", "r".repeat(128), "r".repeat(129), "_r", "a._-", "a b", "é", "r\n"]) add("runId " + value, r => { r.runId = value; });
for (const value of ["A".repeat(85) + "==", "A".repeat(87) + "==", "A".repeat(85) + "B==", "A".repeat(86) + "==\n", "_".repeat(86) + "=="]) add("signature " + value, r => { r.signature.value = value; });
for (const status of ["PASS", "REVIEW", "BLOCKED"]) add(status, r => { r.verification.status = status; });
for (const severity of ["review", "blocked"]) add(severity, r => { r.verification.findings[0].severity = severity; });
for (const field of ["code", "message"]) for (const value of [" ", "\n", "😀", "x".repeat(10001)]) add(field + " valid untrimmed", r => { r.verification.findings[0][field] = value; });
add("path absent", r => { delete r.verification.findings[0].path; });
for (const value of ["", " ", 0, null]) add("path " + JSON.stringify(value), r => { r.verification.findings[0].path = value; });
add("10001 findings", r => { r.verification.findings = Array.from({ length: 10001 }, () => ({ code: " ", severity: "review", message: " ", path: "" })); });
const dates = ["2024-02-29", "2023-02-29", "1900-02-29", "2000-02-29", "0000-02-29", "2026-04-31", "2026-00-01", "2026-13-01", "2026-01-00", "2026-01-32", "2026-10-11"];
const times = ["17:00:00Z", "17:00:00", "17:00:00z", "17:00:00.123456789Z", "17:00:00.Z", "17:00:00x123Z", "17:00:00+06", "17:00:00-0630", "17:00:00+06:30", "17:00:00+23:59", "17:00:00+24:00", "17:00:00+00:60", "24:00:00Z", "23:59:60Z", "23:59:60.5Z", "23:59:61Z", "00:59:60+01:00", "00:29:60+00:30", "22:59:60-01:00", "17:60:00Z", "99:99:99Z"];
for (const field of ["createdAt", "expiresAt"]) for (const date of dates) for (const time of times) for (const sep of ["T", "t", " ", "\t", "\n", "TT"]) add(field + " " + JSON.stringify(date + sep + time), r => { r[field] = date + sep + time; });
function accepted(value: unknown): boolean { try { assertAlphaIntegrityReceipt(value); return true; } catch { return false; } }
describe("unchanged receipt schema differential, default full formats", () => {
  it.each(vectors)("%s", (_name, value) => { expect(accepted(value)).toBe(oracle(value)); });
  it("separates supported JSON equality from A1 descriptors/undefined/size exclusions", () => {
    const r = structuredClone(base); r.verification.findings[0].path = undefined;
    expect(() => captureJsonData(r)).toThrow(); expect(accepted(r)).toBe(false);
    let reads = 0; Object.defineProperty(r, "issuer", { get() { reads++; return "i"; }, enumerable: true });
    expect(() => captureJsonData(r)).toThrow(); expect(reads).toBe(0);
    const big = structuredClone(base); big.verification.findings = Array.from({ length: 100001 }, () => ({ code: "c", severity: "review", message: "m" }));
    expect(oracle(big)).toBe(true); expect(accepted(big)).toBe(true); expect(() => captureJsonData(big)).toThrow();
  });
});
