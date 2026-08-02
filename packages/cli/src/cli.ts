#!/usr/bin/env node
import { stdin, stdout } from "node:process";
import {
  parsePolicy,
  recheckTrustedReceipt,
  sha256Canonical,
  verifyTrustedEnvelope,
} from "@agent-integrity/core";
import type {
  AlphaIntegrityReceipt,
  IntegrityEnvelope,
  IntegrityStatus,
} from "@agent-integrity/protocol";

type JsonRecord = Record<string, unknown>;

function isRecord(value: unknown): value is JsonRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exitCode(status: IntegrityStatus): number {
  if (status === "PASS") return 0;
  if (status === "REVIEW") return 2;
  return 3;
}

function emit(value: unknown, code: number): never {
  stdout.write(`${JSON.stringify(value)}\n`);
  process.exit(code);
}

function invalidInput(message: string): never {
  return emit({ error: { code: "cli.invalid_input", message } }, 1);
}

async function readRequest(): Promise<JsonRecord> {
  let raw = "";
  for await (const chunk of stdin) raw += String(chunk);
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    return invalidInput("stdin must contain one valid JSON object");
  }
  if (!isRecord(value)) return invalidInput("stdin must contain one JSON object");
  return value;
}

function receiptBody(receipt: AlphaIntegrityReceipt): Omit<AlphaIntegrityReceipt, "receiptDigest"> {
  const { receiptDigest: _receiptDigest, ...body } = receipt;
  return body;
}

async function main(): Promise<never> {
  const command = process.argv[2];
  if (!command || !["validate-policy", "verify", "recheck", "inspect-receipt"].includes(command)) {
    return emit({ error: { code: "cli.unknown_command", message: `Unknown command: ${command ?? ""}` } }, 1);
  }
  const request = await readRequest();

  if (command === "validate-policy") {
    if (typeof request.policy !== "string") return invalidInput("policy must be a YAML string");
    try {
      return emit({ ok: true, policy: parsePolicy(request.policy) }, 0);
    } catch (error) {
      return invalidInput(error instanceof Error ? error.message : "policy validation failed");
    }
  }

  if (command === "verify") {
    if (!("envelope" in request)) return invalidInput("envelope is required");
    if (!isRecord(request.context)) return invalidInput("context with projectRoot and allowedRoots is required");
    const result = await verifyTrustedEnvelope(request.envelope as IntegrityEnvelope, request.context as never);
    return emit(result, exitCode(result.status));
  }

  if (command === "recheck") {
    if (!("receipt" in request) || !("envelope" in request) || typeof request.now !== "string") {
      return invalidInput("receipt, envelope, and ISO now are required");
    }
    const now = new Date(request.now);
    if (!Number.isFinite(now.getTime())) return invalidInput("now must be a valid ISO timestamp");
    if (!isRecord(request.context)) return invalidInput("context with projectRoot and allowedRoots is required");
    const result = await recheckTrustedReceipt({
      receipt: request.receipt as AlphaIntegrityReceipt,
      envelope: request.envelope as IntegrityEnvelope,
      now,
      context: request.context as never,
    });
    return emit(result, exitCode(result.status));
  }

  const receipt = request.receipt as AlphaIntegrityReceipt;
  if (!isRecord(receipt)) return invalidInput("receipt must be an object");
  try {
    const calculatedDigest = sha256Canonical(receiptBody(receipt));
    return emit({
      protocolVersion: receipt.protocolVersion,
      receiptVersion: receipt.receiptVersion,
      runId: receipt.runId,
      createdAt: receipt.createdAt,
      expiresAt: receipt.expiresAt,
      status: receipt.verification?.status,
      signatureStatus: receipt.signature?.status,
      receiptDigest: receipt.receiptDigest,
      validDigest: calculatedDigest === receipt.receiptDigest,
    }, calculatedDigest === receipt.receiptDigest ? 0 : 3);
  } catch (error) {
    return invalidInput(error instanceof Error ? error.message : "receipt inspection failed");
  }
}

void main().catch((error: unknown) => {
  emit({
    error: {
      code: "cli.internal_error",
      message: error instanceof Error ? error.message : "internal CLI failure",
    },
  }, 1);
});
