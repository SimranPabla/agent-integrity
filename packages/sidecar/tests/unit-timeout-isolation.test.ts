import { expect, it } from "vitest";
it("ordinary unit timeout remains five seconds in another file", ({ task }) => {
  expect(task.timeout).toBe(5000);
});
it("explicit compiled-worker allowance remains sixty seconds", { timeout: 60000 }, ({ task }) => {
  expect(task.timeout).toBe(60000);
});
