import type { TrustedVerificationContext } from "./verify-trusted.js";

const MAX_DEPTH = 64;
const MAX_NODES = 100_000;
const MAX_STRING_BYTES = 16 * 1024 * 1024;
const DANGEROUS_KEYS = new Set(["__proto__", "constructor", "prototype"]);
interface State { ancestors: Set<object>; nodes: number }

function capture(value: unknown, depth: number, state: State, optionalRootKeys: ReadonlySet<string>): unknown {
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (Buffer.byteLength(value, "utf8") > MAX_STRING_BYTES) throw new TypeError("Maximum capture string size exceeded");
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Non-finite capture number");
    return value;
  }
  if (typeof value !== "object") throw new TypeError("Unsupported capture value");
  const array = Array.isArray(value);
  const prototype = Object.getPrototypeOf(value);
  if (array ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null) {
    throw new TypeError("Expected ordinary array or plain JSON object");
  }
  if (depth > MAX_DEPTH) throw new TypeError("Maximum capture depth exceeded");
  if (++state.nodes > MAX_NODES) throw new TypeError("Maximum capture node count exceeded");
  if (state.ancestors.has(value)) throw new TypeError("Circular capture reference");
  state.ancestors.add(value);
  try {
    const keys = Reflect.ownKeys(value);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (array) {
      const lengthDescriptor = descriptors.length;
      if (!lengthDescriptor || !("value" in lengthDescriptor) || lengthDescriptor.enumerable ||
          !Number.isSafeInteger(lengthDescriptor.value) || lengthDescriptor.value < 0) {
        throw new TypeError("Invalid array length descriptor");
      }
      const length = lengthDescriptor.value as number;
      // Count keys before allocating: holes and extras must not become dense copies.
      if (keys.length !== length + 1) throw new TypeError("Sparse or extended array");
      for (const key of keys) {
        if (key === "length") continue;
        if (typeof key !== "string" || !/^(0|[1-9][0-9]*)$/u.test(key) || Number(key) >= length) {
          throw new TypeError("Unexpected array property");
        }
      }
      const result: unknown[] = [];
      for (let index = 0; index < length; index++) {
        const descriptor = descriptors[String(index)];
        if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) throw new TypeError("Invalid array index descriptor");
        result.push(capture(descriptor.value, depth + 1, state, optionalRootKeys));
      }
      return result;
    }
    const result: Record<string, unknown> = Object.create(null);
    for (const key of keys) {
      if (typeof key !== "string" || DANGEROUS_KEYS.has(key)) throw new TypeError("Unsupported capture key");
      const descriptor = descriptors[key];
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) throw new TypeError("Expected enumerable data property");
      if (depth === 0 && optionalRootKeys.has(key) && descriptor.value === undefined) continue;
      result[key] = capture(descriptor.value, depth + 1, state, optionalRootKeys);
    }
    return result;
  } finally {
    state.ancestors.delete(value);
  }
}

/** Copies supported JSON data through descriptors without invoking caller accessors or methods.
 * Limits apply per root and match canonicalJson's container-depth/node and per-string ceilings.
 * Hostile Proxy traps are not side-effect-free or reliably detectable; use trusted-host data.
 */
export function captureJsonData<T>(value: T): T {
  return capture(value, 0, { ancestors: new Set(), nodes: 0 }, new Set()) as T;
}

/** Captures a trusted context, omitting only absent/undefined optional byte ceilings. */
export function captureTrustedContext(value: TrustedVerificationContext): TrustedVerificationContext {
  return capture(value, 0, { ancestors: new Set(), nodes: 0 }, new Set(["maxSourceBytes", "maxTotalSourceBytes"])) as TrustedVerificationContext;
}
