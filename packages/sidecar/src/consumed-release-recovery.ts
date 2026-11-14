import { canonicalJson, validateTrustedReceipt, type ValidateTrustedReceiptOptions } from "@agent-integrity/core";
import { releaseVerifiedResponse, type ReleaseResult } from "@agent-integrity/sdk";
import type { AlphaIntegrityReceipt, EnvelopeVerificationResult, IntegrityEnvelope } from "@agent-integrity/protocol";
import type { FileReceiptStore } from "@agent-integrity/core";
import { createHash } from "node:crypto";
export interface ConsumedReleaseRecoveryOptions extends Omit<ValidateTrustedReceiptOptions, "receiptStore"> {
    readonly receipt: AlphaIntegrityReceipt;
    readonly verification: EnvelopeVerificationResult;
    readonly receiptStore: FileReceiptStore;
    readonly preparedResponseBytes?: string;
    readonly expectedTransactionId: string;
    readonly expectedConsumedAt: Date;
    readonly preparedResponseDigest: string;
    readonly now: Date;
    readonly envelope: IntegrityEnvelope;
}
export async function recoverConsumedRelease(options: ConsumedReleaseRecoveryOptions): Promise<ReleaseResult> {
    const issued = await options.receiptStore.inspectIssuedRecordByDigest(options.receipt.receiptDigest);
    if (issued === undefined || issued.transactionId !== options.expectedTransactionId || canonicalJson(issued.receipt) !== canonicalJson(options.receipt))
        throw new Error("issued receipt record is missing or contradictory");
    const marker = await options.receiptStore.inspectConsumed(options.receipt.receiptDigest);
    if (marker === undefined || marker.transactionId !== options.expectedTransactionId || marker.receiptDigest !== options.receipt.receiptDigest || marker.runId !== options.receipt.runId || marker.nonce !== options.receipt.nonce || marker.consumedAt !== options.expectedConsumedAt.toISOString())
        throw new Error("consumed receipt marker is missing or contradictory");
    if (await options.receiptStore.inspectClosed(options.receipt.receiptDigest) !== undefined)
        throw new Error("consumed receipt has a contradictory closed marker");
    const checked = await validateTrustedReceipt({ receipt: options.receipt, envelope: options.envelope, now: options.now, trust: options.trust, context: options.context });
    if (checked.status !== "PASS")
        return { status: checked.status, verification: checked };
    const released = await releaseVerifiedResponse({ envelope: options.envelope, verification: options.verification, context: options.context });
    if (released.status === "PASS" && createHash("sha256").update(Buffer.from(released.response, "utf8")).digest("hex") !== options.preparedResponseDigest)
        throw new Error("recovered response bytes do not match prepared digest");
    if (released.status === "PASS" && options.preparedResponseBytes !== undefined && Buffer.from(released.response, "utf8").toString("base64") !== options.preparedResponseBytes)
        throw new Error("recovered response bytes differ from original preparation");
    return released;
}
