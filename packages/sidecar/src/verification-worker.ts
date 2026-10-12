import { isMainThread, parentPort, workerData } from "node:worker_threads";
import { canonicalJson, verifyTrustedEnvelope } from "@agent-integrity/core";
import { loadTrustedVerificationContext, parseCanonicalEnvelope, parseVerificationInput } from "./trusted-context.js";

/** Cooperative isolation only, not an OS sandbox for hostile code. */
export async function executeVerification(input: unknown): Promise<string> {
 const admitted=parseVerificationInput(input);
 const context=await loadTrustedVerificationContext(admitted);
 const envelope=parseCanonicalEnvelope(admitted.canonicalEnvelope,admitted.limits);
 const verification=await verifyTrustedEnvelope(envelope,context);
 if(verification.findings.some(f=>f.code==="checker.failure"))throw new Error("verifier failure");
 const output=canonicalJson({version:"1",verification});
 if(Buffer.byteLength(output)>admitted.limits.maxOutputBytes)throw new Error("output byte limit");
 return output;
}
if(!isMainThread && parentPort) {
 const port=parentPort;
 executeVerification(workerData).then(output=>port.postMessage(output)).catch(()=>{port.postMessage(null);});
}
