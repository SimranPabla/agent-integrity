import { describe, expect, it, vi } from "vitest";
import { captureJsonData, captureTrustedContext } from "../src/capture-json.js";
import { canonicalJson } from "../src/canonical-json.js";
import type { TrustedVerificationContext } from "../src/verify-trusted.js";

describe("descriptor data capture", () => {
  it("keeps dense canonical bytes and accepts frozen/null-prototype/shared data without mutating callers", () => {
    const shared = Object.freeze(Object.assign(Object.create(null), { x: -0, text: "é", flag: true, nil: null }));
    const input = Object.freeze({ a: Object.freeze([shared, shared]), z: "last" });
    const descriptors = Object.getOwnPropertyDescriptors(input);
    const captured = captureJsonData(input);
    expect(canonicalJson(captured)).toBe(canonicalJson(input));
    expect(captured).not.toBe(input);
    expect(captured.a[0]).not.toBe(shared);
    expect(captured.a[0]).not.toBe(captured.a[1]);
    expect(Object.getOwnPropertyDescriptors(input)).toEqual(descriptors);
    expect(Object.isFrozen(captured)).toBe(false);
    const mutable = { a: [{ b: 1 }] };
    expect(captureJsonData(mutable)).toEqual(mutable);
    expect(Object.isFrozen(mutable.a[0])).toBe(false);
  });
  it.each([
    ["undefined", () => ({ value: undefined })],
    ["function", () => ({ value: () => 1 })],
    ["bigint", () => 1n],
    ["symbol value", () => Symbol("bad")],
    ["nonfinite", () => ({ value: Infinity })],
    ["NaN", () => NaN],
    ["Date", () => new Date()],
    ["custom prototype", () => Object.create({ value: 1 })],
    ["subclass", () => new (class extends Array {})()],
    ["holes", () => new Array(1)],
    ["hidden", () => Object.defineProperty({}, "hidden", { value: 1 })],
    ["symbol key", () => ({ [Symbol("bad")]: 1 })],
    ["extra array property", () => Object.assign([], { extra: 1 })],
    ["hidden array index", () => Object.defineProperty([1], "0", { value: 1, enumerable: false })],
    ["dangerous proto", () => Object.defineProperty({}, "__proto__", { value: 1, enumerable: true })],
    ["dangerous constructor", () => ({ constructor: 1 })],
    ["dangerous prototype", () => ({ prototype: 1 })],
    ["cycle", () => { const value: any = {}; value.self = value; return value; }],
    ["inherited index", () => { const value = new Array(1); Object.setPrototypeOf(value, { 0: "inherited" }); return value; }],
  ])("rejects %s", (_name, create) => { expect(() => captureJsonData((create as () => unknown)())).toThrow(); });
  it("rejects getters (including hidden), array map and toJSON without invoking them", () => {
    const sentinel = vi.fn(() => "never");
    const cases = [
      Object.defineProperty({}, "value", { get: sentinel, enumerable: true }),
      Object.defineProperty({}, "hidden", { get: sentinel }),
      Object.defineProperty([1], "0", { get: sentinel, enumerable: true }),
      Object.assign([1], { map: sentinel }),
      Object.assign({}, { toJSON: sentinel }),
    ];
    for (const value of cases) expect(() => captureJsonData(value)).toThrow();
    expect(sentinel).not.toHaveBeenCalled();
  });
  it("omits only undefined root context ceilings, never nested or required undefined", () => {
    const context = { maxSourceBytes: undefined, maxTotalSourceBytes: undefined, allowedRoots: ["docs"] } as unknown as TrustedVerificationContext;
    expect(captureTrustedContext(context)).toEqual({ allowedRoots: ["docs"] });
    expect(() => captureJsonData(context)).toThrow();
    expect(() => captureTrustedContext({ ...context, projectRoot: undefined } as never)).toThrow();
    expect(() => captureTrustedContext({ ...context, trustedPolicy: { maxSourceBytes: undefined } } as never)).toThrow();
    const getter = vi.fn();
    expect(() => captureTrustedContext(Object.defineProperty({}, "maxSourceBytes", { get: getter, enumerable: true }) as never)).toThrow();
    expect(getter).not.toHaveBeenCalled();
  });
  it("matches container depth64, with primitives not counting as containers", () => {
    function nested(depth: number): unknown { let value: unknown = {}; for (let index = 0; index < depth; index++) value = { value }; return value; }
    expect(canonicalJson(captureJsonData(nested(64)))).toBe(canonicalJson(nested(64)));
    expect(() => captureJsonData(nested(65))).toThrow(/depth/);
    expect(() => canonicalJson(nested(65))).toThrow(/depth/);
  });
  it("counts 100000 container occurrences per root, including repeated shared references, not primitives", () => {
    const shared = {};
    const accepted = new Array(99_999).fill(shared);
    expect(captureJsonData(accepted)).toHaveLength(99_999);
    expect(captureJsonData(accepted)).toHaveLength(99_999); // Independent root budget, not accumulated.
    expect(() => captureJsonData(new Array(100_000).fill(shared))).toThrow(/node count/);
    expect(captureJsonData(new Array(100_001).fill(1))).toHaveLength(100_001);
  });
  it("checks UTF-8 bytes per string at 16MiB, not aggregate string bytes", () => {
    const max = "é".repeat(8 * 1024 * 1024);
    expect(captureJsonData([max, max])).toEqual([max, max]);
    expect(() => captureJsonData(max + "é")).toThrow(/string size/);
  });
});
