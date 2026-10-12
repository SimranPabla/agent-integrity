import { expect, it } from "vitest";
import { allowDiskIntegrationTime } from "./support/disk-integration-timeout.js";
allowDiskIntegrationTime();
it("disk integration allowance is fifteen seconds", ({ task }) => {
  expect(task.timeout).toBe(15000);
});
it("explicit unit allowance still overrides the disk-file default", { timeout: 5000 }, ({ task }) => {
  expect(task.timeout).toBe(5000);
});
