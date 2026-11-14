import { mkdir } from "node:fs/promises";
import { basename, dirname } from "node:path";
import {
  createReceipt,
  ReceiptOutputBoundary,
  type CreateReceiptOptions,
} from "../../src/index.js";

export async function createTestReceipt(
  options: Omit<CreateReceiptOptions, "outputBoundary" | "outputName" | "transactionId"> & { readonly path: string },
) {
  const { path, ...receiptOptions } = options;
  const parent = dirname(path);
  await mkdir(parent, { recursive: true });
  return createReceipt({
    ...receiptOptions,
    transactionId: `transaction-${receiptOptions.runId}`,
    outputBoundary: await ReceiptOutputBoundary.open(parent),
    outputName: basename(path),
  });
}
