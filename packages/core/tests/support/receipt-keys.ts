import { generateKeyPairSync } from "node:crypto";

const pair = generateKeyPairSync("ed25519");

export const receiptSigner = {
  keyId: "test-key-1",
  issuer: "test-issuer",
  privateKey: pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
};

export const receiptTrust = {
  keys: { "test-key-1": pair.publicKey.export({ type: "spki", format: "pem" }).toString() },
  issuer: "test-issuer",
  audience: "test-audience",
  purpose: "response-release",
  engineVersion: "0.1.0-alpha.0",
};

export const receiptSigningOptions = {
  signer: receiptSigner,
  audience: receiptTrust.audience,
  purpose: receiptTrust.purpose,
  nonce: "test-nonce-0001",
  engineVersion: receiptTrust.engineVersion,
};
