import { describe, expect, it } from "vitest";
import { Readiness } from "../src/readiness.js";

describe("sidecar readiness", () => {
  it("fails closed until every required prerequisite is reported healthy", () => {
    const readiness = new Readiness(["CONFIGURATION", "ROOT_LEASE"]);
    expect(readiness.snapshot()).toEqual({ ready: false, reasons: ["CONFIGURATION", "ROOT_LEASE"] });
    readiness.set("CONFIGURATION", true);
    expect(readiness.snapshot()).toEqual({ ready: false, reasons: ["ROOT_LEASE"] });
    readiness.set("ROOT_LEASE", true);
    expect(readiness.snapshot()).toEqual({ ready: true, reasons: [] });
  });

  it("latches ambiguous failure and returns deterministic frozen snapshots", () => {
    const readiness = new Readiness(["CONFIGURATION"]);
    readiness.set("CONFIGURATION", true);
    readiness.fail("AMBIGUOUS_STATE");
    readiness.set("AMBIGUOUS_STATE", true);
    const snapshot = readiness.snapshot();
    expect(snapshot).toEqual({ ready: false, reasons: ["AMBIGUOUS_STATE"] });
    expect(Object.isFrozen(snapshot)).toBe(true);
    expect(Object.isFrozen(snapshot.reasons)).toBe(true);
    expect(readiness.snapshot()).toEqual(snapshot);
  });

  it("rejects unbounded or malformed reason codes", () => {
    expect(() => new Readiness(["bad-code"])).toThrow(/reason code/iu);
    const readiness = new Readiness(["CONFIGURATION"]);
    expect(() => readiness.fail("A".repeat(65))).toThrow(/reason code/iu);
  });
});
