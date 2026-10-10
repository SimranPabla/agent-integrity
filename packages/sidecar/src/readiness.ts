const REASON_CODE = /^[A-Z][A-Z0-9_]{0,63}$/u;
const MAX_REASONS = 64;

export interface ReadinessSnapshot {
  readonly ready: boolean;
  readonly reasons: readonly string[];
}

/** Fail-closed, in-memory aggregation of sidecar-owned prerequisites. */
export class Readiness {
  readonly #required: readonly string[];
  readonly #healthy = new Map<string, boolean>();
  readonly #latched = new Set<string>();

  constructor(required: readonly string[]) {
    if (required.length > MAX_REASONS) throw new Error("too many readiness reason codes");
    const codes = [...new Set(required)];
    for (const code of codes) this.#assertCode(code);
    this.#required = Object.freeze(codes.sort());
    for (const code of this.#required) this.#healthy.set(code, false);
  }

  set(code: string, healthy: boolean): void {
    this.#assertCode(code);
    if (this.#latched.has(code)) {
      this.#healthy.set(code, false);
      return;
    }
    this.#healthy.set(code, healthy);
  }

  fail(code: string): void {
    this.#assertCode(code);
    if (this.#latched.size >= MAX_REASONS && !this.#latched.has(code)) throw new Error("too many readiness reason codes");
    this.#latched.add(code);
    this.#healthy.set(code, false);
  }

  snapshot(): ReadinessSnapshot {
    const reasons = [...this.#healthy.entries()]
      .filter(([, healthy]) => !healthy)
      .map(([code]) => code)
      .sort();
    const frozenReasons = Object.freeze(reasons);
    return Object.freeze({ ready: reasons.length === 0, reasons: frozenReasons });
  }

  #assertCode(code: string): void {
    if (!REASON_CODE.test(code)) throw new Error("invalid readiness reason code");
  }
}
