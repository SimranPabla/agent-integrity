import { Readiness, type ReadinessSnapshot } from "./readiness.js";
/** At most one outstanding operation per prerequisite, even after timeout.
 * Timed-out observations never publish late health, and shutdown invalidates
 * every in-flight result. Probes are read-only and must settle their own I/O. */
export class HealthModel {
 readonly #state:Readiness;
 readonly #probes:Readonly<Record<string,()=>Promise<boolean>>>;
 readonly #timeout:number;
 readonly #pending=new Map<string,Promise<boolean>>();
 #flight:Promise<ReadinessSnapshot>|undefined;
 #closed=false;
 constructor(state:Readiness,probes:Readonly<Record<string,()=>Promise<boolean>>>,timeoutMs=1000){
  if(!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>5000||Object.keys(probes).length>64)throw Error("INVALID_HEALTH_MODEL");
  for(const key of Object.keys(probes))if(!/^[A-Z][A-Z0-9_]{0,63}$/u.test(key))throw Error("INVALID_HEALTH_MODEL");
  this.#state=state;this.#probes=Object.freeze({...probes});this.#timeout=timeoutMs;
 }
 live():Readonly<{live:true}>{return Object.freeze({live:true});}
 close():void{this.#closed=true;for(const code of Object.keys(this.#probes))this.#state.set(code,false);}
 async drain():Promise<void>{await Promise.allSettled([...this.#pending.values()]);}
 ready():Promise<ReadinessSnapshot>{
  if(this.#closed)return Promise.resolve(this.#state.snapshot());
  return this.#flight??=this.#check().finally(()=>{this.#flight=undefined;});
 }
 async #check():Promise<ReadinessSnapshot>{
  await Promise.all(Object.entries(this.#probes).map(async([code,probe])=>{
   // A previous timeout still has unsettled I/O: do not spawn another probe or
   // reinterpret that old observation as freshly healthy.
   if(this.#pending.has(code)){this.#state.set(code,false);return;}
   const operation=Promise.resolve().then(probe).catch(()=>false);
   this.#pending.set(code,operation);
   void operation.then(()=>{if(this.#pending.get(code)===operation)this.#pending.delete(code);});
   let timer:ReturnType<typeof setTimeout>|undefined;
   try{const healthy=await Promise.race([operation,new Promise<false>(r=>{timer=setTimeout(()=>r(false),this.#timeout);})]);this.#state.set(code,!this.#closed&&healthy===true);}finally{if(timer)clearTimeout(timer);}
  }));
  return this.#state.snapshot();
 }
}
