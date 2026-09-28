import { describe, expect, test } from "vitest";
import { parseNpmPackManifest } from "../../scripts/npm-pack-manifest.mjs";

const manifest = {
  name: "@agent-integrity/protocol",
  filename: "agent-integrity-protocol-0.1.0.tgz",
  size: 1024,
  files: [
    { path: "package.json" },
    { path: "README.md" },
    { path: "dist/index.js" },
  ],
};

describe("npm pack JSON compatibility", () => {
  test("accepts the npm 10 single-element array shape", () => {
    expect(parseNpmPackManifest(JSON.stringify([manifest]))).toEqual(manifest);
  });

  test("accepts the npm 12 package-keyed object shape", () => {
    expect(parseNpmPackManifest(JSON.stringify({ [manifest.name]: manifest }))).toEqual(manifest);
  });

  test.each([
    ["invalid JSON", "not-json", "invalid JSON"],
    ["an empty result", "[]", "exactly one manifest; received 0"],
    ["multiple array results", JSON.stringify([manifest, manifest]), "exactly one manifest; received 2"],
    ["multiple keyed results", JSON.stringify({ one: manifest, two: manifest }), "exactly one manifest; received 2"],
    ["a non-container result", "null", "result must be an array or keyed object"],
    ["an unkeyed object", JSON.stringify(manifest), "exactly one manifest; received 4"],
    ["a mismatched object key", JSON.stringify({ wrong: manifest }), "key does not match"],
    ["a missing package name", JSON.stringify([{ ...manifest, name: "" }]), "missing a package name"],
    ["a missing filename", JSON.stringify([{ ...manifest, filename: "" }]), "invalid tarball filename"],
    ["a traversing filename", JSON.stringify([{ ...manifest, filename: "../escape.tgz" }]), "invalid tarball filename"],
    ["a nested filename", JSON.stringify([{ ...manifest, filename: "nested/package.tgz" }]), "invalid tarball filename"],
    ["an invalid size", JSON.stringify([{ ...manifest, size: -1 }]), "invalid package size"],
    ["an invalid files list", JSON.stringify([{ ...manifest, files: [{ path: "" }] }]), "invalid files list"],
    ["a traversing file path", JSON.stringify([{ ...manifest, files: [{ path: "../secret" }] }]), "invalid files list"],
    ["an absolute file path", JSON.stringify([{ ...manifest, files: [{ path: "/secret" }] }]), "invalid files list"],
  ])("rejects %s", (_label, output, message) => {
    expect(() => parseNpmPackManifest(output)).toThrow(message);
  });
});
