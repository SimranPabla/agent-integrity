// Test-only process driver. Compiled production runtime/worker; injected clock
// and metadata are NOT OS identity evidence (the separate Linux script is).
import { pathToFileURL } from 'node:url';
const compiled = process.argv[5] ? pathToFileURL(process.argv[5]+'/').href : new URL('../../dist/',import.meta.url).href;
const {createRuntime,COORDINATOR_LAYOUT} = await import(new URL('runtime.js',compiled));
const {StateCoordinator} = await import(new URL('state-coordinator.js',compiled));
const {VerifyReleaseService} = await import(new URL('service.js',compiled));
import { lstat, readFile } from 'node:fs/promises';

import { FileReceiptStore } from '@agent-integrity/core';
import { dirname } from 'node:path';
const [configPath, clock, scenario = 'normal'] = process.argv.slice(2);
let now = new Date(clock);
const root = dirname(configPath), uid = process.getuid(), gid = process.getgid();
const configOptions = { now: () => new Date(now), identity: () => ({uid,gid,groups:[gid]}),
 groupMembers: async () => [uid,uid+1], stat: async path => {
  const s = await lstat(path);
  if (path === root || path === '/tmp') return Object.assign(s,{uid:0,mode:0o40555});
  if (path === root+'/incoming') return Object.assign(s,{uid:uid+1});
  return s;
 }};
let runtime;
try {
 let coordinator;
 if (scenario === 'recover') {
  const stateRoot = root+'/state', lease = JSON.parse(await readFile(stateRoot+'/lease.json','utf8'));
  coordinator = await StateCoordinator.recoverAbandoned(stateRoot,{...COORDINATOR_LAYOUT,storeGeneration:lease.storeGeneration,offlineExclusive:true,expectedOwnerToken:lease.ownerToken,expectedRootIdentityDigest:lease.rootIdentityDigest});
  await coordinator.withMutation(c=>coordinator.completeNestedLockHandoff(c));
 }
 runtime = await createRuntime(configPath,{configOptions,...(coordinator?{coordinator}:{})});
 const originalStore = runtime.serviceOptions.receiptStore;
 const crashScenario=scenario.startsWith('refuse-crash:')||scenario.startsWith('refuse-crash-store:') ? scenario.slice('refuse-'.length) : scenario;
 if (crashScenario.startsWith('crash-store:') || scenario==='quota-one') runtime.serviceOptions.receiptStore = capability => {
  const store = originalStore(capability);
  return new FileReceiptStore(store.directory,{...store.options,...(scenario==='quota-one'?{maxRecords:1}:{}),faultInjector:point=>{if(crashScenario==='crash-store:'+point)process.kill(process.pid,'SIGKILL');}});
 };
 if(crashScenario.startsWith('crash-store:') || scenario==='quota-one') {
  const injectedService=new VerifyReleaseService(runtime.serviceOptions);
  runtime.service.process=injectedService.process.bind(injectedService);
 }
 const advance = runtime.requests.advance.bind(runtime.requests);
 const reserve = runtime.requests.reserve.bind(runtime.requests);
 let fired = false, refusalTimeAdvanced = false;
 runtime.requests.reserve = async (...args) => {
  const state = await reserve(...args);
  if (scenario === 'crash:reserved') process.kill(process.pid,'SIGKILL');
  return state;
 };
 runtime.requests.advance = async (...args) => {
  if (!fired && scenario === 'crash:consumed-before-journal' && args[2].phase === 'pass-consumed') process.kill(process.pid,'SIGKILL');
  const state = await advance(...args);
  if (!fired && crashScenario === 'crash:'+state.phase) process.kill(process.pid,'SIGKILL');
  if (!refusalTimeAdvanced && (scenario === 'refuse' || scenario.startsWith('refuse-crash')) && state.phase === 'receipt-issued') {refusalTimeAdvanced=true;now=new Date(now.getTime()+60000);}
  return state;
 };
 process.on('message', async message => {
  try {
   if(message.command==='time') now=new Date(message.value);
   if(message.command==='shutdown') {const safe=await runtime.shutdown();process.send?.({safe});process.exit(safe?0:1);}
   else process.send?.({ack:message.command});
  } catch {process.send?.({error:'CONTROL_FAILED'});}
 });
 await runtime.start();process.send?.({ready:true});
} catch {console.log(JSON.stringify({code:'COMMAND_FAILED'}));process.exit(1);}
