import { describe, expect, it } from "vitest";
import { parseDecisionRegistry } from "../../src/decisions/parse-registry.js";

describe("parseDecisionRegistry", () => {
  it("parses a strict append-only event registry", () => {
    expect(parseDecisionRegistry("version: 1\nevents:\n  - eventId: e1\n    decisionId: d1\n    revision: 1\n    action: activate\n")).toEqual({
      version: 1,
      events: [{ eventId: "e1", decisionId: "d1", revision: 1, action: "activate" }],
    });
  });

  it.each([
    ["duplicate keys", "version: 1\nversion: 1\nevents: []\n"],
    ["aliases", "version: 1\nevents: &events []\ncopy: *events\n"],
    ["unknown fields", "version: 1\nevents: []\nextra: true\n"],
    ["invalid lifecycle", "version: 1\nevents:\n  - eventId: e1\n    decisionId: d1\n    revision: 1\n    action: reject\n"],
  ])("rejects %s", (_name, input) => {
    expect(() => parseDecisionRegistry(input)).toThrow();
  });
});
