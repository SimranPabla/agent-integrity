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
});
