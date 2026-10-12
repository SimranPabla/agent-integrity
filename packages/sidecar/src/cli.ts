#!/usr/bin/env node
import type { Stats } from "node:fs";
import { isAbsolute,normalize } from "node:path";
import { pathToFileURL } from "node:url";
import { canonicalJson } from "@agent-integrity/core";
import { SidecarConfigManager,type SidecarConfigManagerOptions } from "./config.js";
import { createRuntime,COORDINATOR_LAYOUT } from "./runtime.js";
import { SocketBoundary } from "./socket-boundary.js";
import { StateCoordinator } from "./state-coordinator.js";
import { RecoveryAuthorizationFile } from "./recovery-authorization.js";
export type CliArgs={command:"serve"|"check-config";config:string}|{command:"recover";config:string;authorizationFile:string;offlineExclusive:true};
const absolute=(v:string|undefined):v is string=>typeof v==="string"&&isAbsolute(v)&&normalize(v)===v&&!v.includes("\0");
export function parseCliArgs(args:readonly string[]):CliArgs {const [command,flag,config,...tail]=args;if(flag!=="--config"||!absolute(config))throw Error("INVALID_ARGUMENTS");if((command==="serve"||command==="check-config")&&tail.length===0)return {command,config};if(command==="recover"&&tail.length===3&&tail[0]==="--offline-exclusive"&&tail[1]==="--authorization-file"&&absolute(tail[2]))return {command,config,offlineExclusive:true,authorizationFile:tail[2]};throw Error("INVALID_ARGUMENTS");}
export interface CliOptions {readonly configOptions?:SidecarConfigManagerOptions;readonly write?:(line:string)=>void;}
export async function runCli(argv:readonly string[],options:CliOptions={}):Promise<number>{const write=options.write??(line=>process.stdout.write(line+"\n"));let runtime:Awaited<ReturnType<typeof createRuntime>>|undefined;let coordinator:StateCoordinator|undefined;let recovering=false;
 try{const args=parseCliArgs(argv),configOptions=options.configOptions??{now:()=>new Date()},manager=new SidecarConfigManager(args.config,configOptions),config=await manager.loadInitial();
 if(args.command==="check-config"){write(canonicalJson({code:"CONFIGURATION_VALID"}));return 0;}
 if(args.command==="recover"){
  const boundary=await SocketBoundary.open(config.paths.socketPath,{sidecarUid:config.identities.sidecarUid,clientGid:config.identities.clientGid,...(configOptions.stat?{stat:async(path:string)=>await configOptions.stat!(path) as Stats}:{}),...(configOptions.resolve?{resolve:configOptions.resolve}:{})});if(await boundary.isLive())throw Error("RECOVERY_REQUIRED");
  const auth=await RecoveryAuthorizationFile.open(args.authorizationFile,{sidecarUid:config.identities.sidecarUid,forbiddenRoots:[config.paths.bundleRoot,config.paths.stateRoot],now:configOptions.now,...(configOptions.stat?{stat:async(path:string)=>await configOptions.stat!(path) as Stats}:{})});if(auth.record.storeGeneration!==config.storeGeneration)throw Error("RECOVERY_REQUIRED");await auth.assertUnused(config.paths.stateRoot);await auth.assertUnchanged();if(await boundary.isLive())throw Error("RECOVERY_REQUIRED");
  coordinator=await StateCoordinator.recoverAbandoned(config.paths.stateRoot,{...COORDINATOR_LAYOUT,storeGeneration:config.storeGeneration,offlineExclusive:true,expectedOwnerToken:auth.record.abandonedOwnerToken,expectedRootIdentityDigest:auth.record.rootIdentityDigest,nextOwnerToken:auth.nextOwnerToken});recovering=true;
  // Consume authorization while immutable handoff remains intact, before any nested continuation.
  await coordinator.withMutation(c=>auth.consume(config.paths.stateRoot,c));
  await coordinator.withMutation(c=>coordinator!.completeNestedLockHandoff(c));runtime=await createRuntime(args.config,{configOptions,coordinator});await runtime.recoverAll();if(!await runtime.shutdown())throw Error("RECOVERY_REQUIRED");write(canonicalJson({code:"RECOVERY_COMPLETE"}));return 0;
 }
 runtime=await createRuntime(args.config,{configOptions});await runtime.start();write(canonicalJson({code:"SERVICE_STARTED"}));await new Promise<void>(resolve=>{const stop=()=>{process.removeListener("SIGTERM",stop);process.removeListener("SIGINT",stop);resolve();};process.once("SIGTERM",stop);process.once("SIGINT",stop);});const safe=await runtime.shutdown();write(canonicalJson({code:safe?"SERVICE_STOPPED":"SHUTDOWN_UNSAFE"}));return safe?0:1;
 }catch{if(runtime&&!recovering)await runtime.shutdown();write(canonicalJson({code:recovering?"RECOVERY_REQUIRED":"COMMAND_FAILED"}));return 1;}}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){void runCli(process.argv.slice(2)).then(code=>{process.exitCode=code;if(code!==0)process.exit(code);});}
