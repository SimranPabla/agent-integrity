import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { canonicalJson, assertIntegrityEnvelope, sha256Canonical } from '@agent-integrity/core';
import { parseCanonicalServiceRequest, validateAndSnapshotBundle, type BundleLimits } from '../../src/index.js';
export const bundleLimits: BundleLimits = { maxManifestBytes: 1048576, maxAllowedSourceRoots: 64, maxFiles: 10000, maxPathBytes: 1024, maxFileBytes: 1048576, maxTotalBytes: 4194304, maxFutureSkewMs: 60000, maxBundleLifetimeMs: 900000 };
export const verificationLimits = { maxInputBytes: 1048576, maxOutputBytes: 1048576, maxPolicyBytes: 65536, maxConfigBytes: 65536, maxSourceBytes: 1048576, maxTotalSourceBytes: 4194304, maxItems: 10000, maxFindings: 10000, maxFindingBytes: 4096 };
const ownedFixtureRoots = new Set<string>();
export async function cleanupTask7Fixtures(): Promise<void> {
 const roots = [...ownedFixtureRoots];
 await Promise.all(roots.map(root => rm(root, { recursive: true, force: true })));
 roots.forEach(root => ownedFixtureRoots.delete(root));
}
export async function fixture(kind = 'pass', configChange: Record<string, unknown> = {}, policyChange?: (value: any) => void) {
 const root = await mkdtemp(join(tmpdir(), 'sidecar-task7-')); ownedFixtureRoots.add(root); const incomingRoot = join(root, 'incoming'); const snapshotRoot = join(root, 'snapshots');
 await mkdir(incomingRoot, { mode: 0o750 }); await mkdir(snapshotRoot, { mode: 0o700 });
 const data = JSON.parse(await readFile(new URL('../../../../tests/conformance/fixtures/'+kind+'.json', import.meta.url), 'utf8'));
 const envelope = data.envelope; const sourceBytes = Buffer.from(envelope.response.content); const hash = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');
 envelope.sources[0].size = sourceBytes.length; envelope.sources[0].sha256 = hash(sourceBytes); envelope.evidence[0].anchor = { byteStart: 0, byteEnd: sourceBytes.length, sha256: hash(sourceBytes) };
 const decisions = JSON.stringify({ version: 1, events: envelope.decisions }); envelope.decisionRegistryDigest = hash(Buffer.from(decisions));
 assertIntegrityEnvelope(envelope);
 const config = { allowedRoots: ['docs'], decisionRegistryPath: 'integrity/decisions.yaml', maxSourceBytes: 1048576, maxTotalSourceBytes: 4194304, ...configChange };
 const policy = structuredClone(envelope.policy); policyChange?.(policy);
 const entries: Array<[string,Buffer]> = [ [envelope.sources[0].path, sourceBytes], ['integrity/decisions.yaml', Buffer.from(decisions)], ['integrity/policy.yaml', Buffer.from(JSON.stringify(policy))], ['integrity/trusted-config.json', Buffer.from(canonicalJson(JSON.parse(JSON.stringify(config))))] ];
 const bundle = join(incomingRoot, 'bundle'); const project = join(bundle, 'project');
 for (const [path, bytes] of entries) { await mkdir(dirname(join(project, path)), { recursive: true, mode: 0o750 }); await writeFile(join(project, path), bytes, { mode: 0o640 }); }
 await chmod(bundle, 0o750);
 const unsigned = { version: '1', bundleId: 'bundle', requestId: 'request', envelopeDigest: sha256Canonical(envelope), policyPath: 'integrity/policy.yaml', decisionRegistryPath: 'integrity/decisions.yaml', trustedConfigPath: 'integrity/trusted-config.json', allowedSourceRoots: ['docs'], evidenceCompleteness: { attesterId: 'host', statement: 'complete-for-request', collectedAt: '2030-01-01T00:00:00.000Z' }, publishedAt: '2030-01-01T00:00:00.000Z', expiresAt: '2030-01-01T00:10:00.000Z', files: entries.map(([path, b]) => ({ path, bytes: b.length, sha256: hash(b) })).sort((a,b) => Buffer.compare(Buffer.from(a.path),Buffer.from(b.path))) };
 await writeFile(join(bundle,'manifest.json'),canonicalJson({...unsigned,manifestDigest:sha256Canonical(unsigned)}),{mode:0o640});
 const request = parseCanonicalServiceRequest(Buffer.from(canonicalJson({ serviceProtocolVersion:'1',requestId:'request',idempotencyKey:'idem',bundleId:'bundle',envelope })),1048576);
 const snapshot = await validateAndSnapshotBundle({request,incomingRoot,snapshotRoot,nowMs:Date.parse('2030-01-01T00:05:00.000Z'),limits:bundleLimits});
 return { root, snapshotRoot, snapshot, envelope, input: { version: '1' as const, canonicalEnvelope: canonicalJson(envelope), snapshotRoot, snapshotId: snapshot.snapshotId, bundleLimits, limits: verificationLimits } };
}
