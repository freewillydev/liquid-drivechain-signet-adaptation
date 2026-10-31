# Node Security Review and Upstream Reuse

## Scope and Baseline

Reviewed local master `e7c1e3942a56` (Betanet migration and bidder recovery),
using the already-integrated [Elements upstream revision
301acc64be91d9fce1282d1af7bb673a397b6df2](https://github.com/ElementsProject/elements/commit/301acc64be91d9fce1282d1af7bb673a397b6df2)
as the comparison baseline. This is not a claim that no newer upstream commits
exist. The node delta, excluding `src/test` and Qt translations, spans 189 files
with 38,732 insertions and 555 deletions before this patch.

This bounded source review and regression-tested refactor focuses on native deposit
and withdrawal authorization, BMM admission, parent RPC/enforcer boundaries,
and duplicated wallet serialization. No live funds, configuration or services
were changed. The discarded explicit-reissuance experiment was not restored.

## Findings Addressed

### Betanet migration changed historical deposit verification

`IsSlot24CtipScript` and the historical evidence builder selected the compiled
Betanet treasury opcode (`OP_NOP8`) for immutable slot-24 v2 transactions using
`OP_NOP5`. Two persisted-evidence/convergence tests failed on the initial run.
Restored the historical opcode explicitly using the existing treasury parser;
native Betanet still uses its frozen replay rules. The same tests subsequently
passed, and a negative fixture specifically rejects an `OP_NOP8` substitution
in historical evidence. This preserves old authenticated bytes rather than
relaxing the validator to accept either opcode.

### Legacy withdrawal destination could lose the intended payout

The non-PAK, non-native `sendtomainchain_legacy` path had a hand-written address
decoder. Unknown text (including unsupported address forms) fell back to an
`OP_RETURN` payout, while partial `ParseHex` decoding could silently truncate
malformed scripts. It accepted multiple Bitcoin HRPs without selecting the
configured parent network. Bundle construction occurred after `SendMoney`.
This is a funds-safety defect for a caller using the historical ECX path with
an eligible checkpoint, not evidence of an exploitable native Betanet bypass.

Both wallet paths now share the native path's spendable-script restrictions.
They use upstream `DecodeParentDestination`, `GetScriptForDestination`, `IsHex`
and `IsStandard`. Legacy destinations are validated before `SendMoney` can
commit/broadcast. Malformed, wrong-network, unspendable, unknown-witness and
oversized destinations fail closed. Valid parent addresses and supported exact
`hex:` scripts remain available. This deliberately removes the unsafe fallback;
arbitrary text is not a valid withdrawal destination.

### Already-cancelled subprocess requests could still execute

`RunBoundedCommand` checked cancellation only after fork/exec. A request already
cancelled at entry could therefore launch a side-effecting child (including a
bid submission) before the polling loop killed it. It now checks cancellation
before creating the pipe or child. Tests distinguish cancellation before and
after process creation. This does not promise rollback of a request already
sent, or eliminate the unavoidable race with cancellation after launch.

### Native deposit amount precheck used an ineffective upper bound

The RPC parsed an `int64_t` and compared it to the identical `CAmount` maximum.
It now uses upstream `MoneyRange` and rejects impossible values before parent
authentication. Existing consensus amount checks were not bypassed by this
precheck; this is input hardening, not a newly discovered inflation exploit.

## Upstream Reuse

- Removed the duplicate RPC-local withdrawal bundle encoder and tagged hash.
- The shared wallet builder uses `Sidechain::Bitcoin::CMutableTransaction`,
  `TX_NO_WITNESS`, `VectorWriter`, `GetHash`, `TaggedHash`, `WriteBE32` and
  `WriteBE64` instead of handwritten CompactSize, integer and output encoders.
- Kept the historical inputless rust-bitcoin transport marker separate from the
  no-witness bytes used for the M6 identity. A fixed, independently calculated
  vector checks exact bytes and M6 ID; additional tests cover CompactSize
  boundaries at script lengths 252/253 and the existing maximum of 10,000.
- Native Betanet's separate `drivechain::BuildNativeWithdrawalM6` and its
  genesis/slot/burn-outpoint binding are unchanged. The historical ECX slot-24
  marker is explicitly labeled; it is not silently relabeled as Betanet.

## Security Boundaries Retained

- Native withdrawal loading requires an active confirmed burn, exact pegged
  asset, one canonical burn output, a spendable non-dust parent payout, exact
  M6 round trip, and completed-withdrawal replay lookup. It rechecks the child
  anchor after disk reads and parent replay.
- Native deposit import still authenticates the parent outpoint/value/recipient
  and preserves the full recipient amount. Fee sponsorship remains separate.
- BMM proof commitments, parent replay schemas, parent genesis/checkpoints,
  slot 130, confidential amount/proof verification and CTV rules are unchanged.
- Native RPC remains loopback-bound and cookie-authenticated. Enforcer requests
  retain the method allowlist, mTLS credentials, bounded output and timeouts.
  Plain local parent HTTP is not end-to-end TLS; remote transport still needs
  the authenticated tunnel documented in `drivechain-rpc-security.md`.
- P2P admission still distinguishes invalid evidence from unavailable parent
  state, with ephemeral header limits and parent-validation backoff.

## Remaining Risks and Qualification Gaps

1. The historical ECX wallet flow is not a transactional burn/submission
   workflow: later network or bundle failures can occur after `SendMoney`.
   Its `subtractfeefromamount` path also constructs the bundle from the requested
   amount rather than rederiving the actual fee-subtracted burn. A dedicated
   prepared-transaction/recovery design is required for that historical path.
   The native node explicitly rejects fee subtraction and
   separates confirmed-burn submission; it does not use this legacy path.
2. BMM `AlreadyExists` handling does not recover an exact persisted candidate
   across restart. Final block validation still requires the exact mined
   commitment, but a different candidate can wait fruitlessly. This is a
   liveness/recovery issue, not permission to bypass BMM.
3. Authenticated enforcer subprocess execution intentionally fails closed on
   Windows. A Windows binary alone does not establish bidder/withdrawal feature
   parity; no transport fallback was added here.
4. The full ECX/USDD proof system, verifier archives, deployment commitments,
   economic assumptions and every P2P race were not audited exhaustively here.
   No claim of complete deposit/withdrawal lifecycle qualification follows from
   codec tests. Cross-platform builds, sanitizers, fuzzing and fresh isolated
   end-to-end/reorg/crash-recovery tests remain release gates.
5. The default master build lacks the separately staged frozen ECX catalogue
   build option. Its parent-bound Simplicity cache test expects a jet that is
   not decoded without `ECX_SIMPLICITY_CATALOGUE_FROZEN`. This test remains
   failing and was not skipped or weakened. Aligning selected feature builds,
   frozen identities and deployment evidence is separate release work; this
   refactor does not silently activate a catalogue or import those unmerged
   changes.

## Validation

Fresh macOS ARM64 Release build of `elementsd` and `test_elements` succeeded.
This was a separate build directory, using two workers at nice level 10, with
GUI, BDB, ZMQ and multiprocess disabled and the existing USDD/ECX verifier
archives explicitly supplied. Existing duplicate-library/Rust-personality
linker warnings remain. Neither binary was installed or started as a service.

- Final full C++ suite: **883 cases; 881 passed, one passed with warnings,
  one failed/aborted**. 20,020,347 of 20,020,351 assertions passed. The four
  failures are all in
  `elements_startup_validation_tests/native_candidate_parent_bound_script_cache`,
  the catalogue configuration issue described above. The warning concerns
  unavailable external script-assets fixtures. This is a failed release gate,
  not a passing full suite.
- Focused peg, BMM, withdrawal, treasury, pegin-witness, validation, key-I/O and
  signature-cache suites: **133 cases, 36,401 assertions passed**. This includes
  the new regressions and subprocess cancellation test. The other 750 cases
  were not selected in this separate focused run; none were removed or disabled
  in the full run.
- Identity refreeze Python suite: **23 tests passed**.
- `git diff --check` passed. Source/test changes total 191 insertions and
  410 deletions across eight files, a net reduction of 219 lines, excluding
  this report.

Evidence directory: `/Volumes/T705/SERVERRR/elements-security-build-20260922/`.
It contains `final-build.log`, `final-full-tests.log`, `final-focused-tests.log`,
`identity-tests.log`, the initial/after-fix security test logs,
`upstream-delta.tsv`, `CMakeCache.txt`, the built `bin/` artifacts, and
`node-audit.patch`. `SHA256SUMS` binds the final patch, report, configuration,
logs and binaries. Initial failures remain recorded rather than overwritten.

Working branch: `audit/node-security-upstream-20260922`, isolated checkout
`/Volumes/T705/SERVERRR/elements-security-20260922`. At completion of this
validation the changes were uncommitted; master, unrelated worktrees, live
services and remote branches had not been changed. A subsequent source merge
does not qualify or deploy the binary.
The existing master binaries are not validated by this separate build, and
this patched binary is not release-qualified while the gates above remain open.
