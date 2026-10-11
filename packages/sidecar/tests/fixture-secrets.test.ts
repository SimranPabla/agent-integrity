import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseAllDocuments } from "yaml";
import { describe, expect, it } from "vitest";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const forbidden = new Set(["privatekey", "signingprivatekey", "hmacsecret", "hmacsecretbytes", "secret", "token", "accesstoken", "refreshtoken", "apikey", "password", "credential", "credentials", "clientsecret", "d"]);
function inspect(value: unknown, depth = 0, budget = { nodes: 0 }): void {
  if (depth > 64 || ++budget.nodes > 100_000) throw Error("fixture structure limit");
  if (Array.isArray(value)) { for (const child of value) inspect(child, depth + 1, budget); return; }
  if (value !== null && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      if (forbidden.has(key.toLowerCase().replace(/[_-]/gu, ""))) throw Error("forbidden fixture field");
      inspect(child, depth + 1, budget);
    }
  }
}
function parseFixture(source: string, extension: "json" | "yaml"): unknown {
  if (Buffer.byteLength(source) > 1024 * 1024) throw Error("fixture byte limit");
  // Enforce JSON grammar, then detect duplicates before object conversion.
  if (extension === "json") JSON.parse(source);
  const documents = parseAllDocuments(source, { schema: extension === "json" ? "json" : "core", uniqueKeys: true, strict: true });
  if (documents.length !== 1 || documents[0]!.errors.length || documents[0]!.warnings.length) throw Error("malformed or duplicate fixture");
  const value: unknown = documents[0]!.toJS({ maxAliasCount: 0 });
  inspect(value);
  return value;
}

describe("committed fixture credential boundary", () => {
  it("parses every committed JSON/YAML fixture, excluding generated runtime scratch", () => {
    const paths = execFileSync("git", ["ls-files", "-z"], { cwd: root }).toString().split("\0").filter((path) => /(?:^|\/)fixtures\/.*\.(?:json|ya?ml)$/u.test(path));
    expect(paths.length).toBeGreaterThan(0);
    for (const path of paths) {
      try { parseFixture(readFileSync(resolve(root, path), "utf8"), path.endsWith(".json") ? "json" : "yaml"); }
      catch { throw Error("unsafe or malformed fixture: " + path); }
    }
  });
  it("rejects private key, HMAC, token and credential fields recursively", () => {
    for (const key of forbidden) {
      expect(() => parseFixture(JSON.stringify({ nested: [{ [key]: null }] }), "json")).toThrow(/forbidden/u);
      expect(() => parseFixture("nested:\n  - " + key + ": null\n", "yaml")).toThrow(/forbidden/u);
    }
    expect(() => parseFixture('{"nested":{"HMAC_secret":null}}', "json")).toThrow(/forbidden/u);
  });
  it("permits protected-file references and public metadata, not substring matching", () => {
    const publicOnly = { privateKeyFile: "/protected/key.pem", secretFile: "/protected/auth.bin", authorityPrivateKeyFile: "/protected/authority.pem", publicKeys: [{ kid: "public-1", x: "public-metadata" }], abandonedOwnerToken: "public-reference", description: "token and credentials are forbidden fields" };
    expect(parseFixture(JSON.stringify(publicOnly), "json")).toEqual(publicOnly);
    expect(parseFixture("privateKeyFile: /protected/key.pem\nsecretFile: /protected/auth.bin\nkid: public-1\n", "yaml")).toEqual({ privateKeyFile: "/protected/key.pem", secretFile: "/protected/auth.bin", kid: "public-1" });
  });
  it("rejects malformed, duplicate, multiple-document and alias inputs", () => {
    for (const source of ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"a":']) expect(() => parseFixture(source, "json")).toThrow();
    for (const source of ["a: 1\na: 2\n", "a: [\n", "a: 1\n---\nb: 2\n", "a: &a [1]\nb: *a\n"]) expect(() => parseFixture(source, "yaml")).toThrow();
  });
  it("enforces byte and recursive depth ceilings", () => {
    expect(() => parseFixture(" ".repeat(1024 * 1024 + 1), "json")).toThrow(/limit/u);
    let value: unknown = null;
    for (let i = 0; i < 66; i++) value = { nested: value };
    expect(() => parseFixture(JSON.stringify(value), "json")).toThrow(/limit/u);
  });
});
