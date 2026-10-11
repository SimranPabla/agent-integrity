import type { AlphaIntegrityReceipt } from "@agent-integrity/protocol";

/* Date/time predicate adapted from ajv-formats 3.0.1 fullFormats.
MIT License

Copyright (c) 2020 Evgeny Poberezkin

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
function dateTime(value: string): boolean {
  const parts = value.split(/t|\s/i);
  if (parts.length !== 2) return false;
  const date = /^(\d\d\d\d)-(\d\d)-(\d\d)$/.exec(parts[0]!);
  if (!date) return false;
  const year = +date[1]!, month = +date[2]!, day = +date[3]!;
  const days = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  if (!(month >= 1 && month <= 12 && day >= 1 && day <= (month === 2 && leap ? 29 : days[month]!))) return false;
  const time = /^(\d\d):(\d\d):(\d\d(?:\.\d+)?)(z|([+-])(\d\d)(?::?(\d\d))?)?$/i.exec(parts[1]!);
  if (!time) return false;
  const hr = +time[1]!, min = +time[2]!, sec = +time[3]!;
  const sign = time[5] === "-" ? -1 : 1;
  const tzH = +(time[6] || 0), tzM = +(time[7] || 0);
  if (tzH > 23 || tzM > 59 || !time[4]) return false;
  if (hr <= 23 && min <= 59 && sec < 60) return true;
  const utcMin = min - tzM * sign;
  const utcHr = hr - tzH * sign - (utcMin < 0 ? 1 : 0);
  return (utcHr === 23 || utcHr === -1) && (utcMin === 59 || utcMin === -1) && sec < 61;
}

function requireShape(condition: boolean): asserts condition {
  if (!condition) throw new TypeError("Invalid 2-alpha receipt shape");
}
function object(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  requireShape(value !== null && typeof value === "object" && !Array.isArray(value));
  const record = value as Record<string, unknown>;
  requireShape(required.every(key => Object.hasOwn(record, key)) && Object.keys(record).every(key => required.includes(key) || optional.includes(key)));
  return record;
}
function string(value: unknown, max = Infinity): asserts value is string {
  requireShape(typeof value === "string");
  const length = [...value].length;
  requireShape(length >= 1 && length <= max);
}
function pattern(value: unknown, regex: RegExp): void {
  requireShape(typeof value === "string" && regex.test(value));
}

/** Shape assertion for supported JSON data, separate from capture and crypto/semantic checks.
 * Package-internal: no normalization, schema findings ceiling, or caller mutation.
 */
export function assertAlphaIntegrityReceipt(value: unknown): asserts value is AlphaIntegrityReceipt {
  const r = object(value, ["protocolVersion", "receiptVersion", "engineVersion", "issuer", "audience", "purpose", "nonce", "runId", "createdAt", "expiresAt", "policyDigest", "envelopeDigest", "verification", "signature", "receiptDigest"]);
  requireShape(r.protocolVersion === "1-alpha" && r.receiptVersion === "2-alpha");
  for (const key of ["engineVersion", "issuer", "audience", "purpose", "nonce"]) string(r[key], 256);
  pattern(r.runId, /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/);
  for (const key of ["policyDigest", "envelopeDigest", "receiptDigest"]) pattern(r[key], /^[a-f0-9]{64}$/);
  for (const key of ["createdAt", "expiresAt"]) requireShape(typeof r[key] === "string" && dateTime(r[key]));
  const v = object(r.verification, ["protocolVersion", "status", "findings"]);
  requireShape(v.protocolVersion === "1-alpha" && ["PASS", "REVIEW", "BLOCKED"].includes(v.status as string));
  requireShape(Array.isArray(v.findings));
  for (const item of v.findings) {
    const f = object(item, ["code", "severity", "message"], ["path"]);
    string(f.code); string(f.message);
    requireShape(f.severity === "review" || f.severity === "blocked");
    if (Object.hasOwn(f, "path")) requireShape(typeof f.path === "string");
  }
  const s = object(r.signature, ["algorithm", "keyId", "value"]);
  requireShape(s.algorithm === "Ed25519"); string(s.keyId, 256);
  requireShape(typeof s.value === "string" && [...s.value].length === 88);
  pattern(s.value, /^[A-Za-z0-9+/]{86}==$/);
}
