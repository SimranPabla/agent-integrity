import type { ServiceErrorCode } from "./protocol.js";

const CODES: Readonly<Partial<Record<ServiceErrorCode, readonly [number, boolean]>>> = Object.freeze({
  BUNDLE_UNAVAILABLE: [422, false], BUNDLE_INVALID: [422, false], RESOURCE_LIMIT: [422, false],
  STORAGE_UNAVAILABLE: [503, true], SIGNING_UNAVAILABLE: [503, true], VERIFIER_FAILURE: [503, true],
  SERVICE_UNAVAILABLE: [503, true], INTERNAL_FAILURE: [500, false], IDEMPOTENCY_CONFLICT: [409, false],
  RESULT_EXPIRED: [503, false], AUTHENTICATION_FAILED: [401, false], REPLAY_DETECTED: [401, false],
  INVALID_REQUEST: [400, false], UNSUPPORTED_PROTOCOL: [400, false], PAYLOAD_TOO_LARGE: [413, false],
});
/** Internal host-origin category only. No cause, diagnostic text, paths or input reflection. */
export class ServiceFailure extends Error {
  readonly code: ServiceErrorCode;
  readonly httpStatus: number;
  readonly retryable: boolean;
  readonly reason = "RECOVERY_REQUIRED" as const;
  constructor(code: ServiceErrorCode) {
    const category = Object.hasOwn(CODES, code) ? CODES[code] : undefined;
    if (!category) throw new TypeError("INVALID_FAILURE_CATEGORY");
    super(code); this.name = "ServiceFailure";
    this.code = code; this.httpStatus = category[0]; this.retryable = category[1];
    Object.freeze(this);
  }
}
