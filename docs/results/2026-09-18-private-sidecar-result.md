# Private verified-release sidecar: executed result

## Date and decision

Executed October 10, 2026. The historical 2026-09-18 filename is not the execution date. This evidence document does not attest its own final tree hash.

**Implementation gates: qualified PASS. runtimeReady: false. Overall Task 10 runtime-ready acceptance: not established.** Real Linux UID/GID and no-network scripts exited 77 (INCONCLUSIVE), not PASS. Node 22 unavailable. No production deployment, OS isolation/sandbox, power-loss survival, CAGE runtime integration, partner acceptance, commercial adoption, legal correctness or distributed exactly-once guarantee is claimed. Task 11 final independent reviews remain pending.

## Fixed identities

- PUBLIC_BASE: 880ea482fce4a6ee8914f8922a8ab12cc0ba1a59
- TESTED_CODE_COMMIT: b8523dae9ff613dca6a2c9316774d76f75dd072f
- Parent: e0fca1edb0cbf499fdcab8c56d0032f6b8899a01
- Node v24.21.0; npm 12.0.2; TypeScript 5.8.3; Vitest 4.1.11; YAML 2.9.0.

Main and fresh detached exact-SHA checkout each independently ran the full suite: **978 passed, 2 skipped, 80 files**. This is not a sum. Fresh checkout used npm ci --ignore-scripts without borrowed node_modules/dist; retained read-only. Parent independently matched nine checkpoint-owned paths and all 12 main/18 clean command raw hashes/exits.

## External proof artifacts

Ephemeral external operator evidence is identified by logical filename/digest, not private host paths or raw ledger content:

- parent-handoff.json: 6555451b62f97a5d72d87675ed9a0e8d91775279c29770fd7f72d46cfea538a2
- parent-inspection.json: 859e693e250ec28386602a59ed8dd3628c424a1c226c19288330fd267e9d6864
- checkpoint-proof.json: d2972f62615d449ebc04ef93381c6972cb17e65c30a292a49af4722df7abf407
- clean-finalresult.json: f09c2bcc6c6665bb8f1d88f46b862e31be4ea3cfd85a5b28d6e4c980ecbd4327
- spec-finalresult.json: a50e87ff7e0cf2ee175aa29e1e19f71106893d9e99b3725ef690ba4b9af0ffb6
- security-finalresult.json: 1c47f099ddd3b99034189bbe2c5216d50648d73f1dd9b68255bc4b9d7e3353aa

## Exact executed commands and raw-log SHA-256

Portable presentations replace only the private detached path with <CLEAN_CHECKOUT>. Exits are actual; zero-byte logs use the normal empty SHA-256, not fabricated success text.

### mainGates

| ID | Command | Exit | Raw SHA-256 |
| --- | --- | ---: | --- |
| typecheck | npm run typecheck | 0 | e555120bb8a816065463919d8eb87b53e28f971c553b2afa373c184b267304b3 |
| full-tests | npx vitest run --maxWorkers=1 | 0 | 773ecaaf4471fafe58fbccc79c591b317fa0734e273cf0f831232c8d350a2620 |
| build | npm run build | 0 | 029aa06c2dc1cd84db37151faeb53aa56cfa5f96aa207635b9652010e6b74bf0 |
| release-check | npm run release:check | 0 | 048be6cf56e8c597ee48eb8e8cdb74b5c29b4567c4822ece283eef190dd7145a |
| pack-check | npm run pack:check | 0 | 65984e8cd34eeffa6cdfecb18c2400fda52246a096072d33f2b4700ddb5385eb |
| python-compile | python3 -c 'from pathlib import Path; compile(Path('"'"'examples/python-cli/verify_response.py'"'"').read_text(),'"'"'verify_response.py'"'"','"'"'exec'"'"')' | 0 | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| python-tests | python3 -m unittest discover -s examples/python-cli -p 'test_*.py' | 0 | baf49b59538192f3e136ca0404cac516ecb8dd2fe5ba1416604056f3080fa49c |
| python-smoke | python3 examples/python-cli/verify_response.py | 0 | 2291e0e99b7643ec4b1c8e8960b3ee4e83a0ebcec5f1ce3dc92b9259fb96cf03 |
| audit-full | npm audit --audit-level=high | 0 | 6d8c5c8f3d7684adb070417bd608d01ae90aa3dc26a65af03ffda4955f38d9a3 |
| audit-production | npm audit --omit=dev --audit-level=high | 0 | 6d8c5c8f3d7684adb070417bd608d01ae90aa3dc26a65af03ffda4955f38d9a3 |
| schema-invariance | git diff --exit-code 880ea482fce4a6ee8914f8922a8ab12cc0ba1a59 -- schemas/integrity-envelope.schema.json schemas/integrity-receipt.schema.json | 0 | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| diff-check | git diff --check | 0 | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |

### cleanInstall

| ID | Command | Exit | Raw SHA-256 |
| --- | --- | ---: | --- |
| add-detached | git worktree add --detach '<CLEAN_CHECKOUT>' b8523dae9ff613dca6a2c9316774d76f75dd072f | 0 | 0bc8f995a1ddf17d771ac62259aa7d7eb0d28774dddcf52925904682443da798 |
| exact-head | git rev-parse HEAD | 0 | a7f600e41c7d6efa120a137664df94b52f63527e7e12b884f700ac2d78ecf231 |
| node-version | node --version | 0 | f2ec568164f99546161909b0189b57bb5be3e80f8e2ccd8a51a4aed8c4055a04 |
| npm-version | npm --version | 0 | 2013b258fd4defb17ad242f1c447dd734dd9e1be76761494b4a9a3b6f2797241 |
| clean-install | npm ci --ignore-scripts | 0 | ee2ecf88a5013690ab69fab77a2be5e3c9603677e86de8a09ed556c9117f902b |
| typecheck | npm run typecheck | 0 | e555120bb8a816065463919d8eb87b53e28f971c553b2afa373c184b267304b3 |
| full-tests | npx vitest run --maxWorkers=1 | 0 | 9961c18cccaf9369c6c61b71f9bfe31b45111b2ca2b1552a79c64377ca60cc45 |
| build | npm run build | 0 | 029aa06c2dc1cd84db37151faeb53aa56cfa5f96aa207635b9652010e6b74bf0 |
| release-check | npm run release:check | 0 | 048be6cf56e8c597ee48eb8e8cdb74b5c29b4567c4822ece283eef190dd7145a |
| pack-check | npm run pack:check | 0 | c5361aadce41e4125a185df263d1a8d396576b4c3c69c8993da041d26055ec35 |
| python-five | python3 -m unittest discover -s examples/python-cli -p 'test_*.py' | 0 | baf49b59538192f3e136ca0404cac516ecb8dd2fe5ba1416604056f3080fa49c |
| python-example | python3 examples/python-cli/verify_response.py | 0 | 2291e0e99b7643ec4b1c8e8960b3ee4e83a0ebcec5f1ce3dc92b9259fb96cf03 |
| linux-identities | bash scripts/test-sidecar-unix-identities.sh | 77 | f293c725767ee8ed2155300804753fb8a69e0db4c083d10fdb1aa91d50b4e84d |
| no-network | bash scripts/test-sidecar-no-network.sh | 77 | f8ccc6625da168f2b33163ce52f4fee6b408ec8f136db41a538a1847a210cd0e |
| schema-invariance | git diff --exit-code 880ea482fce4a6ee8914f8922a8ab12cc0ba1a59 -- schemas/integrity-envelope.schema.json schemas/integrity-receipt.schema.json | 0 | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| diff-check | git diff --check | 0 | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| tracked-clean | git diff --exit-code | 0 | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| unchanged-head | git rev-parse HEAD | 0 | a7f600e41c7d6efa120a137664df94b52f63527e7e12b884f700ac2d78ecf231 |

## Reviewed fixes and watchpoints

Whole-current specification PASS and SECURITY_PASS are frozen qualified reports, with no mandatory repairs remaining; neither establishes OS/runtime readiness. SPEC-T10-01 closed two refusal publication windows using real forked compiled-runtime SIGKILL, unchanged failing startup, exact offline continuation and original-bound authenticated retries. Both retain one issued, zero consumed, one closed receipt and stable canonical no-byte refusal.

The twelve-line reviewed production repair performs guarded offline staging cleanup only after complete nested handoff, under a live offline-recovery capability and fresh root/generation/owner/inventory checks. Normal startup never steals ownership or cleans staging. Original trust/profile/signing-time/request/receipt identities, nonce retention, signatures and published nlink=1 remain enforced.

- W1: Dirent regular-file classification and broad .integrity-*.tmp selection; no fresh individual staging-file owner/mode recheck between enumeration and unlink. Protected state directories are sidecar-owned700 and exhaustively inventoried; CAGE/request/unrelated identities cannot create entries here. The trusted offline-exclusive operator assertion excludes concurrent same-identity writers. Existing function removes staging names only, not issued/consumed/closed evidence. No concrete untrusted deletion/uniqueness bypass within approved model.
- W2: Special/nonmatching staging entries and conservative record/root-inventory limits can remain or abort cleanup after partial unlink. Failure leaves cleanup/handoff completion/readiness failed; retriable explicit offline recovery remains necessary. Nonmatching/special files are not broadly deleted. This is an availability/operator-cleanliness limitation, not unauthorized release.
- W3: Task10 test harness injects clock/stat/group metadata and accumulates subprocess output without a production-size cap. This is test execution/diagnostic plumbing only. It neither proves real UID isolation nor changes production worker/HTTP/error/log resource bounds. Actual Linux qualification stays INCONCLUSIVE.
- W4: Named phase-boundary SIGKILL and injected failure tests cover finite seams, not all syscall interruption permutations. No universal crash-window or powerloss claim follows. Actual source create-once/fsync/one-link audit and explicit recovery are retained; unsupported interrupted states fail closed.

## Protected source and schema SHA-256

Exact tested-code bytes, required unchanged by documentation/scanner/fixture work. No final document-self hash is claimed.

| Path | SHA-256 |
| --- | --- |
| packages/core/src/canonical-json.ts | 604aa562ff8a49edda13533464ad872c4a66cb1bdf6eae1ae04d0cd8ab231cf0 |
| packages/core/src/claims/coverage.ts | d31a046222862d7d4bf5b87e0cf435da679681678448e0b1688b7e69d9c9b277 |
| packages/core/src/claims/evidence.ts | 5126f847f679f7d0b9ad379da7ca2fa15bc03ecba9026e10ec6e23043b09f477 |
| packages/core/src/decisions/parse-registry.ts | 1dc56d3b97271a17dd2c85421b880a314b7c1d0407ca10d01021d07ebd36f2d3 |
| packages/core/src/decisions/reduce-decisions.ts | 2997487296ba9276fe3e298aff4172e3bffbe401e64fc80c41f36b9a74225a02 |
| packages/core/src/hash.ts | 7cd86dfe8db588e84a43c0e008bb3e449c289c476f656de53ae51e6cfdab21a0 |
| packages/core/src/index.ts | 4f19906acd15cd08baa9f59e611d5956fab1f893cb42f35dc2714de192d09dd8 |
| packages/core/src/outcome.ts | 2b2642f7b5955d92e3fc8e18cf2b8005e3720db0f6c0eae2772b18e979e3c5e4 |
| packages/core/src/policy/parse-policy.ts | fd4ed66d9aa17f958026b5ba5b30674ba2d64fcb7a84f1cc72fd230ab0cdbecc |
| packages/core/src/receipts/build-receipt.ts | 64a9170143e5fed217b706726c4801c5d387bb6eae9947620630091023f7394e |
| packages/core/src/receipts/create-receipt.ts | 3559610213b1ce5af77e724f0af0ea2dcaad89c8a3c026e77bdadf1cffa62aeb |
| packages/core/src/receipts/file-receipt-store.ts | a66fc7e51dea10aa85b0984d7418be6ac48058fc491d13d3c9f356aa439317b8 |
| packages/core/src/receipts/receipt-output-boundary.ts | a277824ab13749fad6b0d2ecf9999a247e500ddb09f45a6751b923d567d1e7d9 |
| packages/core/src/receipts/receipt-store-records.ts | 709754838bf85bd23c297d4ddb7e0fed3a88734e335e29593c742cb7d9ed122a |
| packages/core/src/receipts/recheck-receipt.ts | 2c4cbbe69e382c3e6752ad0888f6b2866104525c1c2d13382462c651c408fb44 |
| packages/core/src/response/coverage.ts | 30235e95e7d66105b643c7bfb74a7c763e0c9b32fa566a1f5f06636864f13276 |
| packages/core/src/schema/validate-envelope.ts | b09c00f3efcebff22fe9d6181f5bde54b560599768f3526a47d1f2c9cb31e12f |
| packages/core/src/sources/collect-source.ts | 80038f53c84f01b7446754310729218b9d0a055f0bbb8d1e3d4ba830729f8956 |
| packages/core/src/sources/path-boundary.ts | bab724bc49e1c9f14c57329de375989141565a52d964bec0399042c8506d93ec |
| packages/core/src/verify-trusted.ts | b8a8187a4413d5c96239844da299d15a11c311bc6481190903a22666e2b15fec |
| packages/core/src/verify.ts | 8898a3ee2860a63856d7630f189ae8f95c973c7918f7bf53766571d2d58bda97 |
| packages/sidecar/src/auth.ts | 83590ca7a6a2acc08cda5ca494d113d5d88c6da8f819cb039c1112095f02af18 |
| packages/sidecar/src/bundle.ts | 54d72e44104ff04766bba986ff55cd1625fdfe33cf430b59a80cd7e5e30beb7f |
| packages/sidecar/src/cage-trust-manifest.ts | a5c433c67c087661be6a4eb08a95ed4a29113352a1267c0aa93a849ceb305f21 |
| packages/sidecar/src/cli.ts | 0547880827c7c8f9d0009f74ff2d473fa5722932e8a8a16963df2b8ac0cf2dd6 |
| packages/sidecar/src/client-group.ts | 62349ff48a191d6edad4fc812157a114d4b899d9b78d1f1dcdc5ac689343498a |
| packages/sidecar/src/config.ts | 6bf5b37cc0e08b1f0c7d6d02d9bf07ec0b497ff3f59b7d640338e566fcfb7910 |
| packages/sidecar/src/consumed-release-recovery.ts | b105c1b84d1f652a0b3a87100e989b92a135511562ff83e74c3a2c67d29a70a0 |
| packages/sidecar/src/durable-json.ts | 376173df75ca57029ae305190ef1e31555978b638680887b4ff22c2e4cac658a |
| packages/sidecar/src/health.ts | 4b2a4580f1d68c44b1aff374cbd2f7507a57543343efba22f32088655664118d |
| packages/sidecar/src/index.ts | ffb0520787ab3ccc02fd2655a70fad653dcc85818f60172c5324837a783349ad |
| packages/sidecar/src/key-registry.ts | 2bf8072a472b52634e79a1182a621c276b3a9bba6a1ee443afa5521f070be1e6 |
| packages/sidecar/src/nonce-store.ts | 58f0c01b8d44ef73ad165ab0a87cdd1d6d22f655de051da33e0f0c760f67de32 |
| packages/sidecar/src/path-boundary.ts | 39e6391e366ddf5f41c97322d37ca99fb1ef0a2a98e3085d7f7493d6d6382bd2 |
| packages/sidecar/src/private-object-store.ts | bce34c515f5bbf7c1532267d6b841d29fee3ef4cd9fea5a1db8e8457a39a1867 |
| packages/sidecar/src/protocol.ts | 5d7e18e934ccf67aa37ad9783f43412b2cf49c22811e5d5528913041712aa42d |
| packages/sidecar/src/readiness.ts | 7520323910ee92e009e5bf01622ba99e6a9905388093ca76980be5767a813e00 |
| packages/sidecar/src/recovery-authorization.ts | 63e2172e342df3a9a58ffa39cc59b301f1c83c2de0656e5bc50af66f3c70427a |
| packages/sidecar/src/recovery.ts | 5b5d7570493576fe7e0b559f4797c7cb71ff019ce9e2e4f4e42e0d7a1db168d9 |
| packages/sidecar/src/request-state.ts | af6f5fcdd90dbe539b6fbda48c8ed6f7f4ffe7af142e1692603813b89eff82ce |
| packages/sidecar/src/request-store.ts | 92087efcc08c727188d2cb613ceeaefbfb48b4f26d8e31dfe36482dedb2df711 |
| packages/sidecar/src/runtime.ts | ab4d466808ab0e58f13164d523365a08f79cbf462970be4f029fc381211bbad1 |
| packages/sidecar/src/scheduler.ts | 638acdc423feeb9c4a9dfd52ee460e1036d9daf88a4b7c6764f0fb7fe81bcd71 |
| packages/sidecar/src/server.ts | 5949c2664bb90696b54927589a3937fb78f5b0f3e70ab0f1dc530a4ec96c0abd |
| packages/sidecar/src/service-failure.ts | 372a34058e144ee1fdc44bc31bbe30194fe88938ca0985ddd917889267c88bed |
| packages/sidecar/src/service.ts | de8930c508289dce02fd51ef1d2eaf2ee6d1262343d4751acc9619a0f3d8c3b1 |
| packages/sidecar/src/socket-boundary.ts | c115bc37bd23c4d093c30410372da4605ccf02ac04c80e5add20801ac81fdfff |
| packages/sidecar/src/state-coordinator.ts | 470d3bdc8a2a7c0906fee319b95bae5670f479dd5dfca8b9624c65357260498d |
| packages/sidecar/src/trusted-context.ts | ae7c81f4d3636845600ff15ecd26a324c5bde5fe528e1d090f83fc741a9d4f25 |
| packages/sidecar/src/verification-runner.ts | 6f5f898006317927dcb7050afafa2f88ab9a21b7d082b23d6fbc029a19cf99f7 |
| packages/sidecar/src/verification-worker.ts | b8e8089f8bd5fd0bdcc32cd16917335f967909e266abe24075420a81cfdfa4a3 |
| schemas/integrity-envelope.schema.json | ea5e92b16d54403bbfa2a18e27d065442d20033184e24caa589145666a58c328 |
| schemas/integrity-receipt.schema.json | cf328f2476c1f5b6a47c52c4680fef853a2b4738c655c78e5fed4150c5110379 |

## Packaging and remaining assumptions

Exactly protocol/core/sdk/cli public tarballs passed isolated clean installation, imports and CLI execution. Private sidecar compiled fail-closed executable smoke passed separately; no sidecar tarball. Both public schemas remain byte-identical to PUBLIC_BASE. Full and production audits reported zero vulnerabilities at execution, not a future guarantee.

Trusted administrator/clock, protected single-host filesystem, complete NSS, one mutation owner, operator-asserted offline exclusivity, original key retention and correct CAGE evidence remain assumptions. Threads are not OS sandboxes. Node/libuv final-close race limits remain. Capacity/tombstones cannot be cleared; restoring old replay state is unsafe. See package README for exact routing/operation/recovery requirements.

Task 11 local checks are recorded in the separate operator proof inventory. Final independent reviews, documentation commit and prepare-not-publish PR remain parent-owned; this file claims neither its final commit/tree digest nor project completion.

## Task 11 local documentation checks — October 10, 2026

The six documentation/scanner/fixture paths were locally checked after the tested-code checkpoint; no production source changed. Serialized root verification used the exact sequence `npm run typecheck`, `npm test -- --maxWorkers=1`, `npm run build` (the root verify sequence with explicit serialization): **983 passed, 2 skipped, 81 files** in one actual full run. This is not added to the earlier counts as a combined run. The five new fixture tests passed, parsing all seven committed JSON/YAML fixtures; duplicate/malformed/alias documents and recursive forbidden credential fields fail closed, while file/public-metadata references remain permitted. Existing unit/disk/compiled deadlines and production hooks are unchanged.

The NUL-delimited scanner inventory covered all six new/modified paths (including three intent-to-add paths) and every other added/modified tracked path since PUBLIC_BASE, plus the readable operator-local runbook. Whole scan and Bash syntax exited0; synthetic nongenuine secret exited1 without exposing its value; missing runbook, missing ripgrep and injected scanner error each exited2. Ripgrep14.1.0 used an isolated official package and per-command PATH, not a global install. Final release, private/public pack, schema and whitespace checks passed. No real provisioning, service start/stop, backup/restore or deployment was exercised; those runbook commands remain UNVERIFIED. Final independent Task11 reviews and owner publication review remain pending.

| Current command | Exit | Raw log SHA-256 |
| --- | ---: | --- |
| npx vitest run packages/sidecar/tests/fixture-secrets.test.ts | 0 | b0d6b847cfa7851e5914db448df92ea212e98961aa8d2837debd0ea168a398e8 |
| git diff --check | 0 | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| git diff --exit-code 880ea482fce4a6ee8914f8922a8ab12cc0ba1a59 -- schemas/integrity-envelope.schema.json schemas/integrity-receipt.schema.json | 0 | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| npm run release:check | 0 | 048be6cf56e8c597ee48eb8e8cdb74b5c29b4567c4822ece283eef190dd7145a |
| npm run pack:check | 0 | 65984e8cd34eeffa6cdfecb18c2400fda52246a096072d33f2b4700ddb5385eb |
| npm run typecheck | 0 | e555120bb8a816065463919d8eb87b53e28f971c553b2afa373c184b267304b3 |
| npm test -- --maxWorkers=1 | 0 | d716a8117e353b85b14e2a4ec510fe161f8c6b7cf69379d86ee354de1c6c6100 |
| npm run build | 0 | 029aa06c2dc1cd84db37151faeb53aa56cfa5f96aa207635b9652010e6b74bf0 |
| bash scripts/check-sidecar-secrets.sh <SIDECAR_RUNBOOK_PATH> | 0 | 1071ef07875e55952016f49df1affc183822f50be566f7c96494cfb29fd3b4cb |
