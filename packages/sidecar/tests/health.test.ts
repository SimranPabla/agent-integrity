import { expect,it } from "vitest";
it("repeated hung readiness probes have bounded outstanding callbacks and shutdown cannot be overwritten",async()=>{let calls=0,settle!:()=>void;const outstanding=new Promise<boolean>(r=>settle=()=>r(true));const state=new Readiness(["KEYS"]),h=new HealthModel(state,{KEYS:()=>{calls++;return outstanding;}},10);await h.ready();await h.ready();expect(calls).toBe(1);(h as any).close();settle();await outstanding;expect(await h.ready()).toEqual({ready:false,reasons:["KEYS"]});});
it("dynamic reason codes share the existing64 total bound",()=>{const s=new Readiness(["BASE"]);for(let i=0;i<63;i++)s.set("REASON_"+i,false);expect(()=>s.set("OVERFLOW",false)).toThrow();expect(s.snapshot().reasons).toHaveLength(64);});

import { HealthModel } from "../src/health.js";
import { Readiness } from "../src/readiness.js";
it("liveness has no prerequisite claims and readiness freshly checks each independent closed probe",async()=>{
 const state=new Readiness(["KEYS","ROOT_LEASE"]);let healthy=true,calls=0;
 const health=new HealthModel(state,{KEYS:async()=>{calls++;return healthy;},ROOT_LEASE:async()=>true},100);
 expect(health.live()).toEqual({live:true});expect(await health.ready()).toEqual({ready:true,reasons:[]});healthy=false;
 expect(await health.ready()).toEqual({ready:false,reasons:["KEYS"]});expect(calls).toBe(2);
 state.fail("RECOVERY_REQUIRED");healthy=true;expect(await health.ready()).toEqual({ready:false,reasons:["RECOVERY_REQUIRED"]});
});
it("hung or thrown probes fail closed without reflected exception text or queue work",async()=>{const h=new HealthModel(new Readiness(["CONFIGURATION"]),{CONFIGURATION:async()=>{throw Error("/secret");}},20);expect(JSON.stringify(await h.ready())).not.toContain("secret");const hung=new HealthModel(new Readiness(["KEYS"]),{KEYS:async()=>new Promise(()=>{})},20);expect(await hung.ready()).toEqual({ready:false,reasons:["KEYS"]});});
