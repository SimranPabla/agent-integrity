import { Worker } from "node:worker_threads";
import { calculateOutcome, canonicalJson, sha256Canonical } from "@agent-integrity/core";
import type { EnvelopeVerificationResult, IntegrityFinding } from "@agent-integrity/protocol";
import { closedRecord, freezeTree, validateVerificationJsonTree, parseCanonicalEnvelope, parseVerificationInput, type VerificationInput } from "./trusted-context.js";

export type VerificationRunResult =
 | Readonly<{kind:"verified";verification:EnvelopeVerificationResult;canonicalOutput:string}>
 | Readonly<{kind:"technical-failure";code:"VERIFIER_FAILURE";reason:"invalid-input"|"worker-error"|"invalid-output"|"timeout"|"aborted"}>;
export interface VerificationRunOptions {
 readonly timeoutMs:number; readonly signal?:AbortSignal;
 /** Trusted parent/test seam; never serialized into worker data. */
 readonly workerFactory?:(input:VerificationInput)=>Worker;
}
function startWorker(input:VerificationInput):Worker {
 // Production always uses the sibling compiled JS; no source/dist fallback.
 if(!import.meta.url.endsWith(".ts"))return new Worker(new URL("./verification-worker.js",import.meta.url),{workerData:input,execArgv:[],stdout:true,stderr:true});
 // Source execution is a test-only Vite seam. The temporary module runner evaluates
 // current TS and its relative imports, never a possibly stale sidecar dist tree.
 if(!process.env.VITEST)throw new Error("source worker requires Vitest");
 const workerUrl=new URL("./verification-worker.ts",import.meta.url).pathname;
 const bootstrap="(async()=>{const {createServer}=await import('vite'); const server=await createServer({configFile:false,server:{middlewareMode:true},appType:'custom'}); try { await server.ssrLoadModule("+JSON.stringify(workerUrl)+"); } finally {await server.close();}})().catch(()=>{require('node:worker_threads').parentPort.postMessage(null)});";
 // The bootstrap path is trusted code metadata, not an addition to the closed input.
 return new Worker(bootstrap,{eval:true,workerData:input,execArgv:[],stdout:true,stderr:true});
}
export function parseVerificationOutput(raw:unknown,input:VerificationInput):EnvelopeVerificationResult {
 if(typeof raw!=="string"||Buffer.byteLength(raw)>input.limits.maxOutputBytes)throw new Error("output byte limit");
 const value:unknown=JSON.parse(raw);validateVerificationJsonTree(value,input.limits.maxItems);if(canonicalJson(value)!==raw)throw new Error("noncanonical output");
 const outer=closedRecord(value,["version","verification"]);if(outer.version!=="1")throw new Error("output version");
 const r=closedRecord(outer.verification,["protocolVersion","status","findings","envelopeDigest"]);
 if(r.protocolVersion!=="1-alpha" || !Array.isArray(r.findings) || r.findings.length>input.limits.maxFindings || r.envelopeDigest!==sha256Canonical(parseCanonicalEnvelope(input.canonicalEnvelope,input.limits)))throw new Error("invalid verification");
 const findings:IntegrityFinding[]=r.findings.map(value=>{
  if(value===null||typeof value!=="object")throw new Error("invalid finding");
  const f=closedRecord(value,Object.hasOwn(value,"path")?["code","severity","message","path"]:["code","severity","message"]);
  if(typeof f.code!=="string"||f.code.length===0||typeof f.message!=="string"||!['blocked','review'].includes(String(f.severity))||(f.path!==undefined&&typeof f.path!=="string")||Buffer.byteLength(canonicalJson(f))>input.limits.maxFindingBytes||f.code==="checker.failure")throw new Error("invalid finding");
  if(f.severity!=="blocked"&&f.severity!=="review")throw new Error("invalid severity");
  return {code:f.code,severity:f.severity,message:f.message,...(typeof f.path==="string"?{path:f.path}:{})};
 });
 const result=calculateOutcome(findings);if(result.status!==r.status)throw new Error("status mismatch");
 return freezeTree({...result,envelopeDigest:sha256Canonical(parseCanonicalEnvelope(input.canonicalEnvelope,input.limits))});
}
export async function runTrustedVerification(raw:unknown,options:VerificationRunOptions):Promise<VerificationRunResult> {
 const fail=(reason:Extract<VerificationRunResult,{kind:"technical-failure"}>['reason']):VerificationRunResult=>Object.freeze({kind:"technical-failure",code:"VERIFIER_FAILURE",reason});
 let input:VerificationInput;try{input=parseVerificationInput(raw);if(!Number.isSafeInteger(options.timeoutMs)||options.timeoutMs<1||options.timeoutMs>60000)throw new Error();}catch{return fail("invalid-input");}
 if(options.signal?.aborted)return fail("aborted");
 let worker:Worker;try{worker=(options.workerFactory??startWorker)(input);}catch{return fail("worker-error");}
 // Discard worker output streams; paths, source text and thrown errors never escape.
 worker.stdout?.resume();worker.stderr?.resume();
 return await new Promise<VerificationRunResult>(resolve=>{
  let finishing=false;
  const finish=async(result:VerificationRunResult)=>{if(finishing)return;finishing=true;clearTimeout(timer);options.signal?.removeEventListener("abort",abort);try{await worker.terminate();}catch{result=fail("worker-error");}resolve(result);};
  const abort=()=>{void finish(fail("aborted"));};
  const timer=setTimeout(()=>{void finish(fail("timeout"));},options.timeoutMs);
  worker.once("message",(output:unknown)=>{try{const verification=parseVerificationOutput(output,input);void finish(Object.freeze({kind:"verified",verification,canonicalOutput:typeof output==="string"?output:""}));}catch{void finish(fail("invalid-output"));}});
  worker.once("error",()=>{void finish(fail("worker-error"));});
  worker.once("exit",()=>{void finish(fail("worker-error"));});
  options.signal?.addEventListener("abort",abort,{once:true});if(options.signal?.aborted)abort();
 });
}
