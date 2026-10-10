import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";
import type { Socket } from "node:net";
import { canonicalJson } from "@agent-integrity/core";
import { parseCanonicalServiceRequest, parseCanonicalServiceResponse, type ParsedServiceRequest, type ServiceErrorCode, type ResponseLimits, assertResponseLimitBounds, RESPONSE_HARD_CEILINGS } from "./protocol.js";
import { ServiceFailure } from "./service-failure.js";
import { ServiceUnavailableError, type VerifyReleaseService } from "./service.js";
import { AdmissionError } from "./scheduler.js";
import { SocketBoundary } from "./socket-boundary.js";
import { HealthModel } from "./health.js";
import type { AuthHeaders } from "./auth.js";
export interface TransportLimits {
 readonly maximumRequestBytes:number; readonly maximumEnvelopeBytes:number; readonly maximumResponseBytes:number;
 // Wrapper limit is independent from decoded released bytes. Omission keeps
 // bounded standalone callers compatible, capped at the protocol raw ceiling.
 readonly maximumReleasedResponseBytes?:number;
 readonly maximumHeaderBytes:number; readonly maximumHeaderCount:number;readonly maximumEnvelopeItems:number;
 readonly maximumFindings:number; readonly readTimeoutMs:number; readonly maximumConnections:number;readonly gracefulShutdownMs:number;
}
export interface SidecarServerOptions {
 readonly boundary:SocketBoundary;readonly service:Pick<VerifyReleaseService,"process">;readonly health:HealthModel;
 readonly limits:TransportLimits;readonly stopAdmission:()=>void;
}
const AUTH=Object.freeze({"x-agent-integrity-client":"clientId","x-agent-integrity-key-id":"keyId","x-agent-integrity-timestamp":"timestampMs","x-agent-integrity-nonce":"nonce","x-agent-integrity-signature":"mac"} as const);
function rawHeaders(request:IncomingMessage,limits:TransportLimits):AuthHeaders {
 const count=request.rawHeaders.length/2;let bytes=Buffer.byteLength(request.method??"")+Buffer.byteLength(request.url??"")+16;
 const values=new Map<string,string[]>();for(let i=0;i<request.rawHeaders.length;i+=2){const name=request.rawHeaders[i]!,value=request.rawHeaders[i+1]!;bytes+=Buffer.byteLength(name)+Buffer.byteLength(value)+4;const key=name.toLowerCase();values.set(key,[...(values.get(key)??[]),value]);}
 if(count>limits.maximumHeaderCount||bytes>limits.maximumHeaderBytes)throw new ServiceFailure("PAYLOAD_TOO_LARGE");
 if(request.method!=="POST")return {} as AuthHeaders;
 if(values.get("content-type")?.length!==1||values.get("content-type")?.[0]!=="application/json")throw new ServiceFailure("INVALID_REQUEST");
 const result:Record<string,string>={};for(const [name,key] of Object.entries(AUTH)){const v=values.get(name);if(v?.length!==1)throw new ServiceFailure("AUTHENTICATION_FAILED");result[key]=v[0]!;}
 return Object.freeze(result) as unknown as AuthHeaders;
}
async function body(request:IncomingMessage,limits:TransportLimits):Promise<Buffer>{
 return new Promise((resolve,reject)=>{let size=0,finished=false;const parts:Buffer[]=[];const finish=(error?:ServiceFailure)=>{if(finished)return;finished=true;clearTimeout(timer);request.removeListener("data",onData);request.removeListener("end",onEnd);request.removeListener("aborted",onAbort);request.removeListener("error",onAbort);if(error){request.pause();reject(error);}else resolve(Buffer.concat(parts,size));};const onData=(chunk:Buffer)=>{size+=chunk.length;if(size>limits.maximumRequestBytes)finish(new ServiceFailure("PAYLOAD_TOO_LARGE"));else parts.push(chunk);};const onEnd=()=>finish();const onAbort=()=>finish(new ServiceFailure("INVALID_REQUEST"));const timer=setTimeout(()=>finish(new ServiceFailure("INVALID_REQUEST")),limits.readTimeoutMs);request.on("data",onData);request.once("end",onEnd);request.once("aborted",onAbort);request.once("error",onAbort);});
}
function boundEnvelope(request:ParsedServiceRequest,limits:TransportLimits):void {
 const e=request.envelope;if(Buffer.byteLength(canonicalJson(e))>limits.maximumEnvelopeBytes)throw new ServiceFailure("PAYLOAD_TOO_LARGE");
 for(const a of [e.sources,e.decisions,e.evidence,e.claims,e.response.sections])if(a.length>limits.maximumEnvelopeItems)throw new ServiceFailure("RESOURCE_LIMIT");
 for(const c of e.claims)if(c.evidence.length>limits.maximumEnvelopeItems||c.decisionIds.length>limits.maximumEnvelopeItems)throw new ServiceFailure("RESOURCE_LIMIT");
}
export class SidecarServer {
 readonly #responseLimits:Readonly<Omit<ResponseLimits,"request">>;readonly #options:SidecarServerOptions;readonly #server:Server;readonly #connections=new Set<Socket>();readonly #headerTimers=new Map<Socket,ReturnType<typeof setTimeout>>();readonly #operations=new Set<Promise<void>>();readonly #aborts=new Set<AbortController>();#closing=false;#started=false;#listenerClosed:Promise<boolean>|undefined;
 constructor(options:SidecarServerOptions){const responseLimits={maxBodyBytes:options.limits.maximumResponseBytes,maxFindings:options.limits.maximumFindings,maxFindingBytes:65536,maxReleasedResponseBytes:options.limits.maximumReleasedResponseBytes??Math.min(options.limits.maximumResponseBytes,RESPONSE_HARD_CEILINGS.maxReleasedResponseBytes)};assertResponseLimitBounds(responseLimits);this.#responseLimits=Object.freeze(responseLimits);for(const value of Object.values(options.limits))if(!Number.isSafeInteger(value)||value<1||value>32*1024*1024)throw Error("INVALID_TRANSPORT_LIMITS");if(options.limits.maximumHeaderBytes>65536||options.limits.maximumHeaderCount>128||options.limits.maximumEnvelopeItems>10000||options.limits.maximumFindings>10000||options.limits.maximumConnections>128)throw Error("INVALID_TRANSPORT_LIMITS");this.#options={...options,limits:Object.freeze({...options.limits})};this.#server=createServer({maxHeaderSize:options.limits.maximumHeaderBytes,requestTimeout:0,headersTimeout:0,keepAliveTimeout:1},(r,s)=>{const op=this.#handle(r,s);this.#operations.add(op);void op.finally(()=>this.#operations.delete(op));});
 this.#server.on("connection",socket=>{if(this.#closing||this.#connections.size>=this.#options.limits.maximumConnections){this.#rawError(socket,new ServiceFailure("SERVICE_UNAVAILABLE"));return;}this.#connections.add(socket);const timer=setTimeout(()=>this.#rawError(socket,new ServiceFailure("INVALID_REQUEST")),this.#options.limits.readTimeoutMs);this.#headerTimers.set(socket,timer);socket.once("close",()=>{this.#connections.delete(socket);clearTimeout(timer);this.#headerTimers.delete(socket);});});
 this.#server.on("clientError",(error,socket)=>this.#rawError(socket as Socket,new ServiceFailure((error as NodeJS.ErrnoException).code==="HPE_HEADER_OVERFLOW"?"PAYLOAD_TOO_LARGE":"INVALID_REQUEST")));
 this.#server.on("checkContinue",(_request,response)=>{this.#error(response,new ServiceFailure("INVALID_REQUEST"));});
 }
 #rawError(socket:Socket,error:ServiceFailure):void{if(socket.destroyed)return;const bytes=canonicalJson({serviceProtocolVersion:"1",error:{code:error.code,retryable:error.retryable}});socket.end("HTTP/1.1 "+error.httpStatus+" Error\r\nContent-Type: application/json\r\nConnection: close\r\n"+(error.httpStatus===503?"Retry-After: 1\r\n":"")+"Content-Length: "+Buffer.byteLength(bytes)+"\r\n\r\n"+bytes);}
 async listen():Promise<void>{await this.#options.boundary.prepare();await new Promise<void>((resolve,reject)=>{this.#server.once("error",reject);this.#server.listen(this.#options.boundary.path,()=>{this.#server.removeListener("error",reject);resolve();});});this.#started=true;await this.#options.boundary.captureBound();}
 #send(response:ServerResponse,status:number,value:unknown):void{if(response.destroyed||response.writableEnded)return;const bytes=Buffer.from(canonicalJson(value));response.writeHead(status,{"Content-Type":"application/json","Content-Length":String(bytes.length),"Connection":"close",...(status===503?{"Retry-After":"1"}:{})});response.end(bytes);}
 #error(response:ServerResponse,error:unknown,requestId?:string):void {
 let code:ServiceErrorCode="INTERNAL_FAILURE",retryable=false,status=500;
 if(error instanceof ServiceFailure){code=error.code;retryable=error.retryable;status=error.httpStatus;}
 else if(error instanceof AdmissionError||error instanceof ServiceUnavailableError){code=error instanceof ServiceUnavailableError&&error.reason==="RESULT_EXPIRED"?"RESULT_EXPIRED":"SERVICE_UNAVAILABLE";retryable=code!=="RESULT_EXPIRED";status=503;}
 this.#send(response,status,{serviceProtocolVersion:"1",...(requestId?{requestId}:{}),error:{code,retryable}});
 }
 async #handle(request:IncomingMessage,response:ServerResponse):Promise<void>{const headerTimer=this.#headerTimers.get(request.socket);if(headerTimer)clearTimeout(headerTimer);this.#headerTimers.delete(request.socket);let admitted:ParsedServiceRequest|undefined;const abort=new AbortController();this.#aborts.add(abort);const disconnected=()=>abort.abort();response.once("close",disconnected);
 try{
  if(this.#closing)throw new ServiceFailure("SERVICE_UNAVAILABLE");
  // Header byte/count checks also apply to health, but health never enters the queue.
  if(request.method==="GET"&&(request.url==="/health/live"||request.url==="/health/ready")){rawHeaders(request,this.#options.limits);if(request.headers["transfer-encoding"]||request.headers["content-length"]&&request.headers["content-length"]!=="0")throw new ServiceFailure("INVALID_REQUEST");const result=request.url==="/health/live"?this.#options.health.live():await this.#options.health.ready();this.#send(response,"ready"in result&&!result.ready?503:200,result);return;}
  if(request.method!=="POST"||request.url!=="/v1/verify-release")throw new ServiceFailure("INVALID_REQUEST");
  // Capture raw duplicate controls now, but defer missing/invalid auth until the
  // side-effect-free closed canonical parser has completed.
  let headers:AuthHeaders|undefined,headerError:unknown;try{headers=rawHeaders(request,this.#options.limits);}catch(e){if(e instanceof ServiceFailure&&e.code==="AUTHENTICATION_FAILED")headerError=e;else throw e;}
  const bytes=await body(request,this.#options.limits);try{admitted=parseCanonicalServiceRequest(bytes,this.#options.limits.maximumRequestBytes);}catch{throw new ServiceFailure("INVALID_REQUEST");}boundEnvelope(admitted,this.#options.limits);if(headerError)throw headerError;if(!headers)throw new ServiceFailure("AUTHENTICATION_FAILED");
  const result=await this.#options.service.process(bytes,headers,abort.signal);const canonical=Buffer.from(canonicalJson(result));if(canonical.length>this.#options.limits.maximumResponseBytes)throw new ServiceFailure("RESOURCE_LIMIT");
  const validated=parseCanonicalServiceResponse(canonical,{request:admitted,...this.#responseLimits});
  if("error"in validated)throw new ServiceFailure(validated.error.code);this.#send(response,200,validated);
 }catch(error){this.#error(response,error,admitted?.requestId);}finally{this.#aborts.delete(abort);response.removeListener("close",disconnected);}
 }
 /** False leaves root authority held; callers must exit nonzero, never claim
  * cancellation of durable work or remove its lease before an actual drain. */
 async shutdown():Promise<boolean>{if(!this.#started)return true;this.#closing=true;this.#options.stopAdmission();for(const a of this.#aborts)a.abort();if(!this.#listenerClosed){try{await this.#options.boundary.validateBound();this.#listenerClosed=new Promise<boolean>(resolve=>this.#server.close(error=>resolve(!error)));}catch{return false;}}this.#server.closeIdleConnections();let timer:ReturnType<typeof setTimeout>|undefined;try{const drained=await Promise.race([Promise.allSettled([...this.#operations]).then(()=>true),new Promise<false>(r=>{timer=setTimeout(()=>r(false),this.#options.limits.gracefulShutdownMs);})]);if(!drained)return false;for(const s of this.#connections)s.destroy();if(!await this.#listenerClosed)return false;await this.#options.boundary.validateDirectory();this.#started=false;return true;}catch{return false;}finally{if(timer)clearTimeout(timer);}}
}
