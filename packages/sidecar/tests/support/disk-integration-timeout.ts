import { vi } from "vitest";

// Authorized October 9, 2026: allow real disk/crash/recovery integration work
// 15 seconds. This is a test-runner allowance, not a service deadline or SLA.
export const DISK_INTEGRATION_TEST_TIMEOUT_MS = 15_000;
export function allowDiskIntegrationTime(): void {
  vi.setConfig({ testTimeout: DISK_INTEGRATION_TEST_TIMEOUT_MS });
}
