#!/bin/sh
# Temporary numeric Linux identities only: no accounts, NSS, services or config edits.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
[ "$(uname -s)" = Linux ] && [ "$(id -u)" = 0 ] || { echo 'INCONCLUSIVE: Linux root required for numeric UID/GID proof' >&2; exit 77; }
command -v setpriv >/dev/null 2>&1 || { echo 'INCONCLUSIVE: setpriv unavailable' >&2; exit 77; }
NODE=$(command -v node)
TMP=$(mktemp -d /tmp/ai-task10-id.XXXXXXXX)
PID=
cleanup() {
 if [ -n "$PID" ]; then kill "$PID" 2>/dev/null || :; wait "$PID" 2>/dev/null || :; fi
 case "$TMP" in /tmp/ai-task10-id.????????) [ -d "$TMP" ] && [ ! -L "$TMP" ] && rm -r -- "$TMP" ;; *) echo 'unsafe cleanup target' >&2; exit 1 ;; esac
 echo 'cleanup: exact owned identity proof directory removed'
}
trap cleanup 0
trap 'exit 1' 1 2 15
# Reject collisions; never alter real account/group state.
for uid in 61001 61002 61003; do
 if getent passwd "$uid" >/dev/null; then echo 'INCONCLUSIVE: numeric test UID occupied' >&2; exit 77; fi
done
for gid in 61001 61002 61003 61004; do
 if getent group "$gid" >/dev/null; then echo 'INCONCLUSIVE: numeric test GID occupied' >&2; exit 77; fi
done
chmod 755 "$TMP"
mkdir "$TMP/run" "$TMP/state" "$TMP/state/snapshots" "$TMP/state/requests" "$TMP/state/receipts" "$TMP/cage"
chown 61001:61004 "$TMP/run"; chmod 710 "$TMP/run"
chown -R 61001:61001 "$TMP/state"; chmod 700 "$TMP/state" "$TMP/state/"*
chown 61002:61002 "$TMP/cage"; chmod 700 "$TMP/cage"
# Generate test-only keys; no credentials are accepted by this script.
"$NODE" -e 'const fs=require("fs"),c=require("crypto"),r=process.argv[1];fs.writeFileSync(r+"/state/signing.pem",c.generateKeyPairSync("ed25519").privateKey.export({format:"pem",type:"pkcs8"}),{mode:256});const h=c.randomBytes(32);fs.writeFileSync(r+"/state/hmac",h,{mode:256});fs.writeFileSync(r+"/cage/hmac",h,{mode:256});' "$TMP"
chown 61001:61001 "$TMP/state/signing.pem" "$TMP/state/hmac"; chown 61002:61002 "$TMP/cage/hmac"
cp "$ROOT/packages/sidecar/dist/socket-boundary.js" "$TMP/socket-boundary.mjs"
cat > "$TMP/server.mjs" <<'JS'
import {SocketBoundary} from './socket-boundary.mjs';
import {createServer} from 'node:net';
import {readFile,access} from 'node:fs/promises';
const root=process.argv[2];
if(process.getuid()!==61001||!process.getgroups().includes(61004))throw Error('wrong actual sidecar identity');
await readFile(root+'/state/signing.pem');await readFile(root+'/state/hmac');
for(const name of ['snapshots','requests','receipts'])await access(root+'/state/'+name);
const boundary=await SocketBoundary.open(root+'/run/s.sock',{sidecarUid:61001,clientGid:61004});
await boundary.prepare();const server=createServer(s=>s.end('identity-boundary-ok'));
await new Promise((r,j)=>{server.once('error',j);server.listen(boundary.path,r);});await boundary.captureBound();
console.log('READY');
process.on('SIGTERM',async()=>{await boundary.close(()=>new Promise(r=>server.close(r)));process.exit(0);});
JS
setpriv --reuid=61001 --regid=61001 --groups=61004 --no-new-privs "$NODE" "$TMP/server.mjs" "$TMP" >"$TMP/server.stdout" 2>"$TMP/server.stderr" &
PID=$!
i=0
while ! grep -q READY "$TMP/server.stdout"; do
 i=$((i+1)); if [ "$i" -ge 100 ] || ! kill -0 "$PID" 2>/dev/null; then cat "$TMP/server.stderr" >&2; exit 1; fi
 sleep 0.05
done
cat > "$TMP/client.mjs" <<'JS'
import {readFile,access,writeFile,unlink,readdir} from 'node:fs/promises';
import {connect} from 'node:net';
const root=process.argv[2],cage=process.getuid()===61002;
if(cage){if(!process.getgroups().includes(61004))throw Error('missing real group');await readFile(root+'/cage/hmac');}
async function denied(fn){try{await fn();}catch(e){if(['EACCES','EPERM'].includes(e.code))return;throw e;}throw Error('unexpected access');}
for(const p of ['state/signing.pem','state/hmac','state/snapshots','state/requests','state/receipts'])await denied(()=>access(root+'/'+p));
await denied(()=>writeFile(root+'/run/replacement','attack'));await denied(()=>unlink(root+'/run/s.sock'));await denied(()=>readdir(root+'/run'));
const result=await new Promise((resolve,reject)=>{const s=connect(root+'/run/s.sock');let bytes='';s.on('data',b=>bytes+=b);s.on('end',()=>resolve(bytes));s.on('error',e=>{if(!cage&&['EACCES','EPERM'].includes(e.code))resolve('denied');else reject(e);});});
if(result!==(cage?'identity-boundary-ok':'denied'))throw Error('incorrect socket access');
console.log(cage?'PASS: actual CAGE UID/GID socket and key isolation':'PASS: actual unrelated UID socket denied');
JS
setpriv --reuid=61002 --regid=61002 --groups=61004 --no-new-privs "$NODE" "$TMP/client.mjs" "$TMP"
setpriv --reuid=61003 --regid=61003 --clear-groups --no-new-privs "$NODE" "$TMP/client.mjs" "$TMP"
kill "$PID"; wait "$PID"; PID=
[ ! -e "$TMP/run/s.sock" ]
echo 'PASS: compiled socket boundary and actual numeric identity permissions'
