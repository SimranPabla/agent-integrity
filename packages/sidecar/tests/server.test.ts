import { afterEach, describe, expect, it } from "vitest";
import { readdir, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { serviceRequestDigest } from "../src/protocol.js";
import { cleanupServiceFixtures, serviceFixture } from "./support/task8-service-fixture.js";
import { allowDiskIntegrationTime } from "./support/disk-integration-timeout.js";

// Real durable adapter integration, not a mocked transport error. Task 9 must
// distinguish these failures without reopening request-controlled bundle paths
// outside the lifetime coordinator or guessing from private exception messages.
allowDiskIntegrationTime();
afterEach(cleanupServiceFixtures);

describe("Task 9 real service prerequisites for stable HTTP mapping", () => {
  for (const scenario of [
    { name: "missing", expectedCode: "BUNDLE_UNAVAILABLE", change: async (path: string) => unlink(path) },
    { name: "invalid", expectedCode: "BUNDLE_INVALID", change: async (path: string) => writeFile(path, "{}") },
  ]) {
    it("requires distinguishable closed " + scenario.name + " bundle error for HTTP 422", async () => {
      const fixture = await serviceFixture();
      await scenario.change(join(fixture.incomingRoot, "bundle-1", "manifest.json"));
      let failure: unknown;
      try { await fixture.newService().process(fixture.requestBytes, fixture.authHeaders()); }
      catch (error) { failure = error; }
      // Check phase-aware safety before the deliberately RED mapping assertion.
      expect(failure).toBeInstanceOf(Error);
      expect(await readdir(join(fixture.stateRoot, "nonces", "records"))).toHaveLength(1);
      const state = await fixture.requests.lookup("client-1", "generation-1", "idem-1", serviceRequestDigest(fixture.request));
      expect(state?.phase).toBe("reserved");
      expect(state?.transactionId).toBe("transaction-1");
      await fixture.coordinator.withMutation(async capability => {
        expect((await fixture.options.receiptStore(capability).inspectCapacity()).used).toBe(0);
      });
      expect(fixture.options.readiness.snapshot()).toEqual({ ready: false, reasons: ["RECOVERY_REQUIRED"] });
      expect(failure).toMatchObject({ code: scenario.expectedCode });
    });
  }
});
