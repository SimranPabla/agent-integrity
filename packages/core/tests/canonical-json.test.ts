import { describe, expect, it } from "vitest";
import { canonicalJson, sha256Canonical } from "../src/index.js";

describe("canonical JSON", () => {
  it("sorts object keys recursively while preserving array order", () => {
    expect(canonicalJson({ z: 1, nested: { b: 2, a: 1 }, list: [2, 1] })).toBe(
      '{"list":[2,1],"nested":{"a":1,"b":2},"z":1}'
    );
  });

  it("produces equal hashes for equivalent objects", () => {
    expect(sha256Canonical({ b: "✓", a: 1 })).toBe(sha256Canonical({ a: 1, b: "✓" }));
  });

  it("normalizes negative zero", () => {
    expect(canonicalJson({ value: -0 })).toBe('{"value":0}');
  });

  it.each([NaN, Infinity, -Infinity])("rejects non-finite number %s", (value) => {
    expect(() => canonicalJson({ value })).toThrow(/Non-finite number/);
  });

  it("rejects undefined rather than silently dropping it", () => {
    expect(() => canonicalJson({ value: undefined })).toThrow(/Undefined value/);
  });

  it.each(["__proto__", "constructor", "prototype"])(
    "rejects the dangerous key %s without creating a digest collision",
    (key) => {
      const hostile = JSON.parse(`{"${key}":{"admin":true}}`) as unknown;
      expect(() => canonicalJson(hostile)).toThrow(/Dangerous object key/);
      expect(() => sha256Canonical(hostile)).toThrow(/Dangerous object key/);
    }
  );

  it("rejects class instances and objects with custom prototypes", () => {
    class Hostile { value = 1; }
    expect(() => canonicalJson(new Hostile())).toThrow(/plain JSON object/);
    expect(() => canonicalJson(Object.create({ inherited: true }))).toThrow(/plain JSON object/);
  });

  it("rejects accessors without executing them", () => {
    let executed = false;
    const value = Object.defineProperty({}, "secret", {
      enumerable: true,
      get() {
        executed = true;
        return "leaked";
      },
    });
    expect(() => canonicalJson(value)).toThrow(/Accessor property/);
    expect(executed).toBe(false);
  });

  it("rejects circular and excessively deep input", () => {
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    expect(() => canonicalJson(circular)).toThrow(/Circular reference/);

    let deep: unknown = null;
    for (let index = 0; index < 70; index += 1) deep = [deep];
    expect(() => canonicalJson(deep)).toThrow(/Maximum canonical JSON depth/);
  });
});


// Both public source exports get a fresh fixture; snapshots never read accessor values.
const exportsUnderTest = [["canonicalJson", canonicalJson], ["sha256Canonical", sha256Canonical]] as const;
type Fixture = { value: unknown; calls: { count: number }; watched: object[] };
function fixture(value: unknown, calls = { count: 0 }, watched: object[] = [value as object]): Fixture {
  return { value, calls, watched };
}
function snapshot(value: object) {
  return { keys: Reflect.ownKeys(value), prototype: Object.getPrototypeOf(value), descriptors: Reflect.ownKeys(value).map(key => Object.getOwnPropertyDescriptor(value, key)!) };
}
function unchanged(value: object, before: ReturnType<typeof snapshot>) {
  const after = snapshot(value);
  expect.soft(after.prototype).toBe(before.prototype);
  expect.soft(after.keys).toEqual(before.keys);
  expect.soft(after.descriptors.length).toBe(before.descriptors.length);
  for (let i = 0; i < before.descriptors.length; i++) {
    for (const field of ["value", "get", "set", "writable", "enumerable", "configurable"] as const) {
      expect.soft(after.descriptors[i]?.[field]).toBe(before.descriptors[i]![field]);
    }
  }
}
const oneDigest = "080a9ed428559ef602668b4c00f114f1a11c3f6b02a435f0bdc154578e4d7f22";
const twoDigest = "49a64717d5d4cb19952e6eac2946415cf6879adacf9908e7d872332d32c6e684";

for (const [exportName, run] of exportsUnderTest) {
  describe(exportName, () => {
    const rejects: [string, () => Fixture, string][] = [
      ["single hole", () => fixture(Array(1)), "$[0]"],
      ["two holes", () => fixture(Array(2)), "$[0]"],
      ["interior hole", () => fixture([1, , 2]), "$[1]"],
      ["trailing hole", () => fixture([1, ,]), "$[1]"],
      ...[false, true].map((getter): [string, () => Fixture, string] => [
        getter ? "inherited getter index" : "inherited data index", () => {
          const calls = { count: 0 }, value = Array(1), proto = Object.create(Array.prototype);
          Object.defineProperty(proto, "0", getter ? { get() { calls.count++; return 7; } } : { value: 7 });
          Object.setPrototypeOf(value, proto); return fixture(value, calls, [value, proto]);
        }, "$[0]",
      ]),
      ...["getter", "setter", "both"].map((kind): [string, () => Fixture, string] => [
        "own " + kind + " index", () => {
          const calls = { count: 0 }, value: unknown[] = [];
          Object.defineProperty(value, "0", { enumerable: true,
            ...(kind !== "setter" ? { get() { calls.count++; return 7; } } : {}),
            ...(kind !== "getter" ? { set(_v: unknown) { calls.count++; } } : {}) });
          return fixture(value, calls);
        }, "$[0]",
      ]),
      ["nested hole", () => { const inner = Array(1), outer = { list: [inner] }; return fixture(outer, { count: 0 }, [outer, outer.list, inner]); }, "$.list[0][0]"],
      ["nested getter", () => { const calls = { count: 0 }, inner = Object.defineProperty([], "0", { get() { calls.count++; return 1; } }); return fixture([inner], calls, [inner]); }, "$[0][0]"],
    ];
    it.each(rejects)("E rejects %s without invocation or mutation", (_name, make, path) => {
      const f = make(), before = f.watched.map(snapshot);
      let error: unknown; try { run(f.value); } catch (caught) { error = caught; }
      // Check sentinels even if the rejection assertion subsequently fails during RED.
      expect.soft(f.calls.count).toBe(0);
      f.watched.forEach((value, index) => unchanged(value, before[index]!));
      expect.soft(f.calls.count).toBe(0);
      expect(error).toBeInstanceOf(TypeError);
      expect((error as Error).message).toContain("at " + path);
    });

    const accepts: [string, () => Fixture, string, string][] = [
      ...["altered", "malformed", "throw"].map((kind): [string, () => Fixture, string, string] => [
        "caller map " + kind, () => { const calls = { count: 0 }, value = [1];
          Object.defineProperty(value, "map", { value() { calls.count++; if (kind === "throw") throw Error("sentinel map"); return [kind === "altered" ? "99" : "{"]; } });
          return fixture(value, calls);
        }, "[1]", oneDigest,
      ]),
      ...["map", "join", "constructor", "toJSON", "extra", "hidden"].map((key): [string, () => Fixture, string, string] => [
        "caller " + key + " getter", () => { const calls = { count: 0 }, value = [1];
          Object.defineProperty(value, key, { enumerable: key === "extra", get() { calls.count++; throw Error("sentinel " + key); } });
          return fixture(value, calls);
        }, "[1]", oneDigest,
      ]),
      ...[Symbol.iterator, Symbol("extra")].map((key): [string, () => Fixture, string, string] => [
        "symbol getter " + String(key), () => { const calls = { count: 0 }, value = [1];
          Object.defineProperty(value, key, { get() { calls.count++; throw Error("sentinel symbol"); } }); return fixture(value, calls);
        }, "[1]", oneDigest,
      ]),
      ["toJSON and iterator methods", () => { const calls = { count: 0 }, value = [1];
        Object.defineProperty(value, "toJSON", { value() { calls.count++; throw Error("sentinel toJSON"); } });
        Object.defineProperty(value, Symbol.iterator, { value() { calls.count++; throw Error("sentinel iterator"); } }); return fixture(value, calls);
      }, "[1]", oneDigest],
      ["subclass species", () => { const calls = { count: 0 }; class Dense extends Array { static get [Symbol.species](): ArrayConstructor { calls.count++; throw Error("sentinel species"); } }
        const value = new Dense(1, 2); return fixture(value, calls, [value, Dense]); }, "[1,2]", twoDigest],
      ["dense subclass", () => { class Dense extends Array {} return fixture(new Dense(1, 2)); }, "[1,2]", twoDigest],
      ["custom prototype", () => fixture(Object.setPrototypeOf([1], Object.create(Array.prototype))), "[1]", oneDigest],
      ["null prototype", () => fixture(Object.setPrototypeOf([1], null)), "[1]", oneDigest],
      ["nonenumerable nonwritable index", () => fixture(Object.defineProperty([1], "0", { value: 1, enumerable: false, writable: false })), "[1]", oneDigest],
      ["frozen array", () => fixture(Object.freeze([1, 2])), "[1,2]", twoDigest],
      ["nonwritable length", () => fixture(Object.defineProperty([1], "length", { writable: false })), "[1]", oneDigest],
    ];
    it.each(accepts)("E bypasses hooks / preserves %s", (_name, make, bytes, digest) => {
      const f = make(), before = f.watched.map(snapshot);
      let actual: unknown, error: unknown; try { actual = run(f.value); } catch (caught) { error = caught; }
      expect.soft(f.calls.count).toBe(0);
      f.watched.forEach((value, index) => unchanged(value, before[index]!));
      expect.soft(f.calls.count).toBe(0);
      expect(error).toBeUndefined();
      expect(actual).toBe(exportName === "canonicalJson" ? bytes : digest);
    });

    const goldens: [string, () => unknown, string, string][] = [
      ["dense sorted record / ordered array", () => ({ z: 1, nested: { b: 2, a: 1 }, list: [2, 1, null, true, "✓", -0] }), '{"list":[2,1,null,true,"✓",0],"nested":{"a":1,"b":2},"z":1}', "7606456978e956ac98b1b729f312d74db15b5c199e4062dee7d8d6e797d89c20"],
      ["empty", () => [], "[]", "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"],
      ["negative zero null Unicode escaping", () => [-0, null, "✓", '"\\\n\t'], '[0,null,"✓","\\\"\\\\\\n\\t"]', "3e07dff381b302e0be188b55c2584895c9c8cd55076ec5bede40ddfa3540ef84"],
      ["null prototype record", () => Object.assign(Object.create(null), { b: 2, a: 1 }), '{"a":1,"b":2}', "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"],
      ["shared noncyclic", () => { const child = { x: 1 }; return [child, child]; }, '[{"x":1},{"x":1}]', "aa36417ba1dc8446e96286be19248ef0da432d7a28dc507a839872ca29b9034c"],
    ];
    it.each(goldens)("preserves baseline literal %s", (_name, make, bytes, digest) => {
      expect(run(make())).toBe(exportName === "canonicalJson" ? bytes : digest);
    });
    it.each([undefined, NaN, Infinity, -Infinity, () => 1, Symbol("value"), 1n])("preserves unsupported array value rejection %s", value => {
      expect(() => run([value])).toThrow(TypeError);
      expect(() => run([value])).toThrow("at $[0]");
    });
    it("preserves array and record cycle rejection", () => {
      const array: unknown[] = []; array.push(array);
      const record: Record<string, unknown> = {}; record.self = record;
      expect(() => run(array)).toThrow("Circular reference at $[0]");
      expect(() => run(record)).toThrow("Circular reference at $.self");
    });
    it("keeps the record admission and hidden/symbol projection unchanged", () => {
      class Custom { x = 1; }
      expect(() => run(new Custom())).toThrow(/plain JSON object/);
      expect(() => run(Object.create({ x: 1 }))).toThrow(/plain JSON object/);
      for (const key of ["__proto__", "constructor", "prototype"]) expect(() => run(JSON.parse('{"' + key + '":1}'))).toThrow(/Dangerous object key/);
      let calls = 0;
      const accessor = Object.defineProperty({}, "x", { enumerable: true, get() { calls++; return 1; } });
      expect(() => run(accessor)).toThrow(/Accessor property/);
      const hidden = Object.defineProperty({ b: 2, a: 1 }, "hidden", { get() { calls++; throw Error("hidden"); } });
      Object.defineProperty(hidden, Symbol("extra"), { get() { calls++; throw Error("symbol"); } });
      expect(run(hidden)).toBe(exportName === "canonicalJson" ? '{"a":1,"b":2}' : "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777");
      expect(calls).toBe(0);
      expect(() => run({ x: undefined })).toThrow("Undefined value at $.x");
    });
    it("preserves exact container depth and primitive depth65", () => {
      const nest = (count: number) => { let value: unknown = null; for (let i = 0; i < count; i++) value = [value]; return value; };
      expect(() => run(nest(65))).not.toThrow();
      expect(() => run(nest(66))).toThrow(/Maximum canonical JSON depth/);
    });
    it.each([false, true])("preserves container occurrence boundary shared=%s", shared => {
      const make = (count: number) => { const child = {}; return Array.from({ length: count }, () => shared ? child : {}); };
      expect(() => run(make(99_999))).not.toThrow();
      expect(() => run(make(100_000))).toThrow("Maximum canonical JSON node count exceeded at $[99999]");
    });
    it("does not count primitive elements as container nodes", () => {
      expect(() => run(Array(100_001).fill(0))).not.toThrow();
    });
    it.each([false, true])("preserves per-string UTF8 boundary multibyte=%s", multibyte => {
      const text = multibyte ? "é".repeat(8_388_608) : "x".repeat(16_777_216);
      expect(Buffer.byteLength(text, "utf8")).toBe(16_777_216);
      expect(() => run(text)).not.toThrow();
      expect(() => run(text + "x")).toThrow("Maximum canonical JSON string size exceeded at $");
      expect(() => run({ list: [text] })).not.toThrow();
      expect(() => run({ list: [text + "x"] })).toThrow("Maximum canonical JSON string size exceeded at $.list[0]");
    });
  });
}
