import { describe, expect, it } from "vitest";
import { resolveClientGroupMembers } from "../src/client-group.js";

const passwd = "sidecar:x:100:200::/:/bin/false\ncage:x:101:201::/:/bin/false\nother:x:102:202::/:/bin/false\n";
const group = "clients:x:200:cage\n";
function reader(p = passwd, g = group) { return async (db: "passwd" | "group") => db === "passwd" ? p : g; }

describe("NSS group resolution", () => {
  it("unions primary and supplementary memberships", async () => { expect(await resolveClientGroupMembers(200, reader())).toEqual([100, 101]); });
  it("detects extra primary and supplementary identities", async () => {
    expect(await resolveClientGroupMembers(200, reader(passwd.replace("102:202", "102:200")))).toEqual([100, 101, 102]);
    expect(await resolveClientGroupMembers(200, reader(passwd, "clients:x:200:cage,other\n"))).toEqual([100, 101, 102]);
  });
  it.each(["missing", "unresolved", "truncated", "malformed", "alias", "duplicate-group", "oversize", "failure"])("fails closed on %s", async (kind) => {
    let p = passwd; let g = group;
    if (kind === "missing") g = "other:x:999:other\n";
    if (kind === "unresolved") g = "clients:x:200:unknown\n";
    if (kind === "truncated") p = p.trimEnd();
    if (kind === "malformed") p = "bad\n";
    if (kind === "alias") p += "alias:x:100:300::/:/bin/false\n";
    if (kind === "duplicate-group") g += "alias:x:200:cage\n";
    if (kind === "oversize") p = "a".repeat(4 * 1024 * 1024 + 1);
    const read = kind === "failure" ? async () => { throw new Error("NSS unavailable"); } : reader(p, g);
    await expect(resolveClientGroupMembers(200, read)).rejects.toThrow(/enumeration|resolution/);
  });
});
