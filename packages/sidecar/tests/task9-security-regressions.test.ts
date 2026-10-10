import { afterEach, expect, it, vi } from "vitest";
import fs, { constants } from "node:fs";
import { open, unlink, readdir, lstat, readFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { request as httpRequest } from "node:http";
import { join } from "node:path";
import { canonicalJson } from "@agent-integrity/core";
import { serviceRequestDigest, parseCanonicalServiceResponse } from "../src/protocol.js";
import * as protocol from "../src/protocol.js";
import { createRuntime } from "../src/runtime.js";
import { SidecarServer } from "../src/server.js";
import { parseSidecarConfig } from "../src/config.js";
import { serviceFixture, cleanupServiceFixtures } from "./support/task8-service-fixture.js";
import { testConfig, cleanupTestConfigs } from "./support/test-config.js";
import { allowDiskIntegrationTime } from "./support/disk-integration-timeout.js";
allowDiskIntegrationTime();
afterEach(async()=>{vi.restoreAllMocks();await cleanupServiceFixtures();await cleanupTestConfigs();});
const fifo=(path:string)=>execFileSync("mkfifo",["-m","640",path]);
// RED-only Linux rescue holds both ends until the exact operation drains,
// including when the admitted request has not reached its blocking open yet.
async function rescue(path:string){return await open(path,constants.O_RDWR|constants.O_NONBLOCK);}
for(const kind of ["fifo","at-open"] as const)it("incoming manifest "+kind+" rejects422 with no writer and retains nonce/reservation/no result",async()=>{
 const f=await serviceFixture(),path=join(f.incomingRoot,"bundle-1","manifest.json"),original=fs.promises.open;let swapped=false;
 if(kind==="fifo"){await unlink(path);fifo(path);}else{fs.promises.open=async function(p:any,...args:any[]){if(String(p)===path&&!swapped){swapped=true;await unlink(path);fifo(path);}return (original as any)(p,...args);};syncBuiltinESMExports();}
 let reserved!:()=>void;const admitted=new Promise<void>(resolve=>reserved=resolve),reserve=f.requests.reserve.bind(f.requests);f.requests.reserve=async(...args)=>{const state=await reserve(...args);reserved();return state;};let rescueHandle:Awaited<ReturnType<typeof open>>|undefined;
 let settled=false;const operation=f.newService().process(f.requestBytes,f.authHeaders()).then(v=>{settled=true;return v;},e=>{settled=true;return e;});
 try{await admitted;await new Promise(r=>setTimeout(r,300));const bounded=settled;if(!settled)rescueHandle=await rescue(path);const outcome=await operation;expect(outcome).toMatchObject({httpStatus:422,code:"BUNDLE_INVALID"});expect(bounded).toBe(true);if(kind==="at-open")expect(swapped).toBe(true);expect(await readdir(join(f.stateRoot,"nonces","records"))).toHaveLength(1);expect((await f.requests.lookup("client-1","generation-1","idem-1",serviceRequestDigest(f.request)))?.phase).toBe("reserved");await f.coordinator.withMutation(async c=>expect((await f.options.receiptStore(c).inspectCapacity()).used).toBe(0));expect(f.options.readiness.snapshot().ready).toBe(false);expect("releasedResponse"in outcome).toBe(false);expect(await readdir(f.snapshotRoot)).toEqual([]);}finally{fs.promises.open=original;syncBuiltinESMExports();if(!settled){rescueHandle??=await rescue(path);await operation;}await rescueHandle?.close();}
});
function send(f:Awaited<ReturnType<typeof testConfig>>){const h=f.authHeaders();return new Promise<{status:number;body:any}>((resolve,reject)=>{const r=httpRequest({socketPath:f.config.paths.socketPath,path:"/v1/verify-release",method:"POST",headers:{"content-type":"application/json","x-agent-integrity-client":h.clientId,"x-agent-integrity-key-id":h.keyId,"x-agent-integrity-timestamp":h.timestampMs,"x-agent-integrity-nonce":h.nonce,"x-agent-integrity-signature":h.mac}},s=>{const chunks:Buffer[]=[];s.on("data",b=>chunks.push(b));s.on("end",()=>resolve({status:s.statusCode!,body:JSON.parse(Buffer.concat(chunks).toString())}));});r.on("error",reject);r.end(f.requestBytes);});}
it("real manifest FIFO HTTP operation and runtime shutdown settle without rescue or unsafe lease release",async()=>{
 const f=await testConfig(),r=await createRuntime(f.configPath,{configOptions:f.identityOptions});await r.start();const path=join(f.config.paths.bundleRoot,"bundle-1","manifest.json");await unlink(path);fifo(path);let reserved!:()=>void;const admitted=new Promise<void>(resolve=>reserved=resolve),reserve=r.requests.reserve.bind(r.requests);r.requests.reserve=async(...args)=>{const state=await reserve(...args);reserved();return state;};let rescueHandle:Awaited<ReturnType<typeof open>>|undefined;let settled=false;const operation=send(f).then(v=>{settled=true;return v;});
 try{await admitted;await new Promise(resolve=>setTimeout(resolve,300));const bounded=settled;const stopping=r.shutdown();if(!settled){await new Promise(resolve=>setTimeout(resolve,300));rescueHandle=await rescue(path);}const response=await operation;expect(await stopping).toBe(true);expect(bounded).toBe(true);expect(response).toEqual({status:422,body:{serviceProtocolVersion:"1",requestId:"req-1",error:{code:"BUNDLE_INVALID",retryable:false}}});expect(await readdir(join(f.config.paths.stateRoot,"nonces","records"))).toHaveLength(1);expect(r.scheduler.active).toBe(false);expect(await r.requests.lookup("cage","generation-1","idem-1",serviceRequestDigest((await import("../src/protocol.js")).parseCanonicalServiceRequest(f.requestBytes,1048576)))).toMatchObject({phase:"reserved"});expect(await readdir(join(f.config.paths.stateRoot,"receipts","issued"))).toEqual([]);await expect(lstat(join(f.config.paths.stateRoot,"lease.json"))).rejects.toMatchObject({code:"ENOENT"});}finally{if(!settled){rescueHandle??=await rescue(path);await operation;}await rescueHandle?.close();await r.shutdown();}
});
for(const megabytes of [8,16])it("permitted"+megabytes+"MiB runtime returns tiny persisted PASS200 and identical retry rather than parser500",async()=>{
 const f=await testConfig();f.config.limits.maximumResponseBytes=megabytes*1048576;await f.save();const r=await createRuntime(f.configPath,{configOptions:f.identityOptions}),parse=vi.spyOn(protocol,"parseCanonicalServiceResponse");
 try{await r.start();const first=await send(f);expect(first.status).toBe(200);expect(first.body.status).toBe("PASS");expect(Buffer.from(first.body.releasedResponse.bytes,"base64").equals(Buffer.from(JSON.parse(f.requestBytes.toString()).envelope.response.content))).toBe(true);const again=await send(f);expect(again).toEqual(first);expect(parse.mock.calls.some(([,limits])=>limits.maxBodyBytes===Math.min(32,megabytes*2+2)*1048576&&limits.maxReleasedResponseBytes===megabytes*1048576)).toBe(true);expect(await readdir(join(f.config.paths.stateRoot,"receipts","issued"))).toHaveLength(1);}finally{parse.mockRestore();await r.shutdown();}
});
it("raw release config accepts16MiB hard ceiling and rejects16MiB+1 before runtime",async()=>{
 const f=await testConfig();expect(parseSidecarConfig({...f.config,limits:{...f.config.limits,maximumResponseBytes:16*1048576}}).limits.maximumResponseBytes).toBe(16*1048576);expect(()=>parseSidecarConfig({...f.config,limits:{...f.config.limits,maximumResponseBytes:16*1048576+1}})).toThrow(/ceiling|limit/);
});
it("server constructs wrapper32MiB/raw16MiB but rejects each at+1, never waits for a request",()=>{
 const limits={maximumRequestBytes:1048576,maximumEnvelopeBytes:1048576,maximumResponseBytes:32*1048576,maximumReleasedResponseBytes:16*1048576,maximumHeaderBytes:8192,maximumHeaderCount:32,maximumEnvelopeItems:10000,maximumFindings:10000,readTimeoutMs:100,maximumConnections:16,gracefulShutdownMs:3000};const options={boundary:{} as any,service:{} as any,health:{} as any,stopAdmission:()=>{},limits};expect(()=>new SidecarServer(options)).not.toThrow();for(const field of ["maximumResponseBytes","maximumReleasedResponseBytes"] as const)expect(()=>new SidecarServer({...options,limits:{...limits,[field]:limits[field]+1}})).toThrow();
},5000);
it("protocol wrapper32MiB and released16MiB ceilings remain independent",async()=>{
 const f=await serviceFixture(),limits={request:f.request,maxBodyBytes:32*1048576,maxFindings:10000,maxFindingBytes:65536,maxReleasedResponseBytes:16*1048576},bytes=Buffer.from(canonicalJson({serviceProtocolVersion:"1",error:{code:"INTERNAL_FAILURE",retryable:false}}));expect(parseCanonicalServiceResponse(bytes,limits)).toMatchObject({error:{code:"INTERNAL_FAILURE"}});for(const field of ["maxBodyBytes","maxReleasedResponseBytes"] as const)expect(()=>parseCanonicalServiceResponse(bytes,{...limits,[field]:limits[field]+1})).toThrow("hard ceilings");
});
