import { createHash } from "node:crypto";
import { posix } from "node:path";
import type {
  EnvelopeVerificationResult,
  IntegrityEnvelope,
  IntegrityFinding,
} from "@agent-integrity/protocol";
import { calculateOutcome, checkerFailure } from "./outcome.js";
import { collectSourceBytes } from "./sources/collect-source.js";
import { verifyEnvelope } from "./verify.js";

export interface TrustedVerificationContext {
  readonly projectRoot: string;
  readonly allowedRoots: readonly string[];
  /** Maximum bytes read from one source. Defaults to 16 MiB. */
  readonly maxSourceBytes?: number;
  /** Maximum bytes retained across all sources. Defaults to 64 MiB. */
  readonly maxTotalSourceBytes?: number;
}

export const DEFAULT_MAX_SOURCE_BYTES = 16 * 1024 * 1024;
export const DEFAULT_MAX_TOTAL_SOURCE_BYTES = 64 * 1024 * 1024;

function blocked(code: string, message: string, path: string): IntegrityFinding {
  return { code, severity: "blocked", message, path };
}

function normalizedRoot(root: string): string {
  return posix.normalize(root.replaceAll("\\", "/")).replace(/\/$/u, "");
}

function assertTrustedContext(envelope: IntegrityEnvelope, context: TrustedVerificationContext): void {
  if (typeof context?.projectRoot !== "string" || context.projectRoot.trim() === "") {
    throw new Error("trusted projectRoot must be a non-empty path");
  }
  if (!Array.isArray(context.allowedRoots) || context.allowedRoots.length === 0 ||
      context.allowedRoots.some((root) => typeof root !== "string" || root.trim() === "")) {
    throw new Error("trusted allowedRoots must be a non-empty list of paths");
  }
  const trusted = [...new Set(context.allowedRoots.map(normalizedRoot))].sort();
  const policy = [...new Set(envelope.policy.sources.allowedRoots.map(normalizedRoot))].sort();
  if (trusted.length !== policy.length || trusted.some((root, index) => root !== policy[index])) {
    throw new Error("trusted allowedRoots must exactly match policy.sources.allowedRoots");
  }
  for (const [name, value] of [
    ["maxSourceBytes", context.maxSourceBytes],
    ["maxTotalSourceBytes", context.maxTotalSourceBytes],
  ] as const) {
    if (value !== undefined && (!Number.isSafeInteger(value) || value < 1)) {
      throw new Error(`${name} must be a positive safe integer`);
    }
  }
}

async function verifyTrustedUnsafe(
  envelope: IntegrityEnvelope,
  context: TrustedVerificationContext,
): Promise<EnvelopeVerificationResult> {
  const structural = verifyEnvelope(envelope);
  if (structural.envelopeDigest === undefined) return structural;
  try {
    assertTrustedContext(envelope, context);
  } catch (error) {
    return {
      ...calculateOutcome([...structural.findings, blocked(
        "source.context_invalid",
        error instanceof Error ? error.message : "trusted source context is invalid",
        "policy.sources.allowedRoots",
      )]),
      envelopeDigest: structural.envelopeDigest,
    };
  }

  const findings = [...structural.findings];
  const collected = new Map<string, Buffer>();
  const maxSourceBytes = context.maxSourceBytes ?? DEFAULT_MAX_SOURCE_BYTES;
  const maxTotalSourceBytes = context.maxTotalSourceBytes ?? DEFAULT_MAX_TOTAL_SOURCE_BYTES;
  let totalSourceBytes = 0;
  for (const [index, source] of envelope.sources.entries()) {
    try {
      const remainingBytes = maxTotalSourceBytes - totalSourceBytes;
      if (remainingBytes < 1) throw new Error(`sources exceed the ${maxTotalSourceBytes} byte total collection limit`);
      const live = await collectSourceBytes({
        projectRoot: context.projectRoot,
        allowedRoots: context.allowedRoots,
        sourcePath: source.path,
        maxBytes: Math.min(maxSourceBytes, remainingBytes),
      });
      totalSourceBytes += live.size;
      collected.set(source.sourceId, live.bytes);
      if (live.path !== source.path) findings.push(blocked("source.path_mismatch", "Source path is not the normalized live path", `sources[${index}].path`));
      if (live.size !== source.size) findings.push(blocked("source.size_mismatch", "Source size differs from live bytes", `sources[${index}].size`));
      if (live.sha256 !== source.sha256) findings.push(blocked("source.digest_mismatch", "Source digest differs from live bytes", `sources[${index}].sha256`));
    } catch (error) {
      findings.push(blocked(
        "source.collection_failed",
        error instanceof Error ? error.message : "source collection failed",
        `sources[${index}]`,
      ));
    }
  }

  for (const [index, evidence] of envelope.evidence.entries()) {
    const bytes = collected.get(evidence.sourceId);
    if (bytes === undefined) continue;
    if (evidence.anchor === undefined) {
      findings.push(blocked("evidence.anchor_missing", "Trusted evidence requires an exact source byte anchor", `evidence[${index}].anchor`));
      continue;
    }
    const { byteStart, byteEnd, sha256 } = evidence.anchor;
    if (byteStart < 0 || byteEnd <= byteStart || byteEnd > bytes.byteLength) {
      findings.push(blocked("evidence.anchor_out_of_range", "Evidence anchor is outside the source bytes", `evidence[${index}].anchor`));
      continue;
    }
    const actual = createHash("sha256").update(bytes.subarray(byteStart, byteEnd)).digest("hex");
    if (actual !== sha256) {
      findings.push(blocked("evidence.anchor_digest_mismatch", "Evidence anchor digest differs from live source bytes", `evidence[${index}].anchor.sha256`));
    }
  }

  return { ...calculateOutcome(findings), envelopeDigest: structural.envelopeDigest };
}

/** Recollects and validates every source before returning an outcome. */
export async function verifyTrustedEnvelope(
  envelope: IntegrityEnvelope,
  context: TrustedVerificationContext,
): Promise<EnvelopeVerificationResult> {
  try {
    return await verifyTrustedUnsafe(envelope, context);
  } catch (error) {
    return checkerFailure(error);
  }
}
