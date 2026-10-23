# Haskell migration

## Direct enforcer client

`GrpcClient.hs` performs unary mTLS gRPC through the linked C core. It does not
execute grpcurl or embed the enforcer. `EnforcerCodec.hs` selects seven typed
request/response pairs generated from the pinned CUSF schemas and explicitly
converts proto field names to the node's existing lowerCamelCase JSON interface.
Unknown request fields and conflicting aliases fail closed.

`grpc_bridge.cpp` is the narrow native ABI: exceptions do not cross callbacks,
output is bounded, and cancellation callbacks stay on the calling thread.
The network worker is joined before call/channel destruction. Retries are
disabled at the transport layer. The existing native credential/endpoint
admission and caller retry policy remain in place. Duplicate acceptance requires
gRPC status 6, not merely an error message containing `AlreadyExists`.

`GrpcDependencies.cmake` pins source archives and applies the small channel-option
patch needed for explicit TLS authority verification and disabling retries.
`grpc.project.freeze` locks the tested GHC 9.6.7 dependency set. Build prerequisites
include cabal-install >= 3.14.2.0 (3.16.1.0 recommended for fresh installs),
gRPC C-core development libraries and protobuf headers. Follow the verified
[Linux bootstrap and secure-index instructions](../../doc/build-unix.md#haskell-toolchain)
before `cabal update`; CMake checks the selected `ELEMENTS_CABAL` version early.
Generated
bindings live in the build directory. Native Windows packaging has a separate,
explicit opt-in qualification path in `doc/build-windows.md`; cross packaging
remains unqualified.
Do not ship locally built native dependencies for older OS deployment targets
without rebuilding and qualifying those dependencies for that target.

The actual C++/Haskell ABI can be checked with `haskell_grpc_probe` and
`test/grpc_transport.py`; the fixture uses the pinned protobuf descriptors and
isolated loopback TLS endpoints. See `doc/drivechain-rpc-security.md` for commands.
Historical migration entries below describe earlier transport arrangements.

`Deposit.BlockPreflightFlow` (store selector 282) owns fork-added block deposit
preflight traversal, coinbase/non-pegin skipping, witness/native/output checks,
and unavailable-versus-invalid rejection order. Native callbacks keep typed
witness verification and BlockValidationState diagnostics. Inherited peg-in
validation and the separate CheckPeginRipeness loop are not moved.

`Exchange.ParentContextFlow` (store selector 281) chooses admission context:
clear stale fields on Bitcoin-mode chains, otherwise read only the selected
native-parent or private-BMM source and bind its result or an absent parent.
Native adapters retain typed reads and field publication. Short-circuit source
checks remain unchanged; callback exceptions stop the workflow before binding.

Fork-added native/ECX production heights, native script-candidate and ephemeral
deposit-preflight heights, and sidechain-info RPC validation height reuse
`NextBlockHeight`. Existing non-null guards/locks remain native. The RPC shares
one computed next height across its reported depth and height; a chain height
of -1 advances to zero. Inherited Elements/Bitcoin height calculations are not
migration scope and remain unchanged. Signed overflow fails closed through the
existing adapter rather than invoking undefined native arithmetic.

`cursorCall` is the shared checked scalar-field reader for cursor callbacks.
Status-only wrappers use it directly, without allocating an unused result slot.
`workCall` layers guarded result publication over the same reader. Both retain
callback validation, field reset before every read and exception translation;
only nonnegative outcomes publish a result. This changes neither exported ABI
signatures nor the domain operations selected through `Check`/`Validation`.

`Deposit.InputLimit` owns the fork-added per-block native deposit cap. It walks
transaction/input facts in their original order, stops at the first excess
peg-in, and performs no reads on non-slot networks. The existing cursor ABI
provides only input counts and flags; callback failures and non-boolean flags
fail closed. Remaining budget is decremented rather than incrementing a
counter, avoiding overflow even at the ABI's maximum limit. Upstream transaction
and sigop checks surrounding this gate remain C++.

Periodic reverification keeps inherited `ActivateBestChain` and its logging
in C++. Haskell selector 229 prepares only the fork-added parent state and
mempool state (actions 1-7). Normal warm-up/refresh rejection still returns
to native activation; exceptions still prevent subsequent work. Former
activation actions 8-9 are no longer part of this flow.

Only fork-added behavior is migration scope; inherited Elements/Bitcoin
checks remain native even inside mixed functions. In preliminary peg-in
admission, C++ retains witness-vector completeness, the legacy witness
fallback, and its error handling. The added Drivechain slot/recognition
gate uses the existing lazy required-pair rule. Former selector 278 is
retired and rejects calls; its enum position is reserved so later selector
numbers do not change. The retired flow is not an alternative admission path.

Withdrawal journal admission accepts a bounded seven-byte bundle prefix in
its internal request, so Haskell owns witness-marker/short-frame admission.
The legacy 34-byte internal request remains supported; the extended request
is 42 bytes and carries explicit prefix length. Persisted journal bytes are
unchanged. Filename and magic come from `BmmConstants.journalHeader`; the magic
remains a native std::string when serialized, preserving its length framing.
`JournalIdentity` owns exact M6 digest matching and its rejection message.
The native digest is computed only after entry admission, using the existing
marker-stripping transport and upstream hash implementation. Both digests are
serialized through the same uint256 representation; no byte-order conversion
or journal disk-format change is introduced.

`Usdd.FrontierWire` selects the compact withdrawal-accumulator frontier fields
in ascending level order. It emits occupied read/write actions and, only while
reading, absent-level clearing actions. Native stream callbacks preserve typed
I/O and exceptions; no intermediate state buffer is introduced. Version checks
still precede count/root reads, and sanity checks still follow the frontier.
Property traces and native wire/truncation fixtures pin this ordering.

`BmmConstants.networkDefaultsHeader` supplies the native production default
and config filename without runtime calls during global initialization. Network
admission shares `productionChainName`; legacy chain aliases reuse upstream
`ChainTypeToString`. Argument precedence, locking, platform paths and section
lookup remain in the upstream argument manager. The default stays `elements`,
and internal test-network factories remain distinct from production admission.

Anchor serialization version and peg-event schema version have separate
Haskell definitions in `BmmConstants`, even though both are currently one.
Native `DrivechainAnchor` defaults and Haskell anchor validation share the
anchor definition. Deposit identity defaults reuse the existing slot constant;
an unauthenticated deposit's zero-slot initialization remains unchanged.

`ScriptPolicy.MerkleReplacement` owns the parent partial-Merkle replacement
sentinel, matched-leaf selection and required-index rule. Native code still
walks the upstream tree, consumes bits/hashes and rejects duplicate branches.
Matched outputs retain their original leaf hashes, even when the reconstructed
root uses a replacement. The final index search is skipped for the sentinel;
malformed-tree rejection still precedes replacement completion checks.

Simplicity's public proof lengths and owned-annex bound are generated from
`BmmConstants.simplicityHeader` into the public `policy_constants.h`. CMake
checks the checked-in header against Haskell; standalone consumers need only
the shipped include tree. Golden C assertions and Haskell tests pin the frozen
wire values. Field offsets and public structure layouts are unchanged.

`ScriptPolicy.AnnexRetention` owns optional full-annex admission. It checks
presence and the bounded size before reading the tag, then checks body length
and presence before comparing bytes. The byte comparison remains native
`memcmp`; no large annex copy is needed for validation. Native allocation,
owned copying and legacy transaction hashing are unchanged. A malformed optional
full annex must not invalidate or change the legacy annex hash.

`ScriptPolicy.OptionalEnvironment` owns Simplicity environment admission. Its
six modes cover roots, the BMM parent, bond identity, projection, incremental
activation and the optional prior-active checkpoint. Native C reports nonzero
field masks without exposing structure
layout to Haskell. Presence flags must be 0/1; unused mask bits and unknown modes
fail closed. Active projection permits either inbox count; inactive activation
ignores the separately validated bond identity. Native check order, error codes
and upstream evaluation remain unchanged. Property, C ABI and real execution
boundary tests pin these distinctions.

The checkpoint adapter reads the fixed 80-byte wire endpoint in Haskell. Active
endpoints require nonzero parent hash, MTP and state root, but permit zero height;
absent endpoints must be all zero, with a null pointer treated as absent bytes.
This is deliberately weaker than anchor authentication and must not be replaced
by the stricter `AnchorCheckpoint` constructor. Native storage and copying stay
unchanged.

`ScriptPolicy.ParameterGate` owns explicit-only activation and withdrawal
enablement. Native `Consensus::Params` stores the values; its out-of-line
methods in the bridge forward signed heights or slot-presence/replay-support
facts. Negative activation heights disable the rule; slot zero is present,
not absent. Unknown modes and malformed boolean facts fail the checked ABI.

`BmmConstants.grpcCredentialDefaults` generates the native TLS credential-path
defaults consumed by configuration and help output. Path resolution and secure
file metadata/open checks remain native adapters; no runtime call is needed to
read a default. Haskell and native golden tests pin the existing paths.

The internal `ParseM6` reply contains the parent fee followed by the validated
burn total, each an eight-byte little-endian amount. Haskell computes the total
after its existing money-range check. Native M6 publication copies it instead
of repeating arithmetic; the build path copies its already-validated input
burn amount. This changes only the internal call result, not M6 wire encoding.

Activation credit uses `BmmConstants.activationBudget` both in Haskell admission
and in the generated native activation header. That header also carries the
frozen `activationCmr`; generation adds no runtime call. Independent Haskell and
native golden checks pin the original budget and all 32 CMR bytes.

The migration covers all fork-added C++ behavior in stages. Upstream Elements
types, script parsing, cryptography, serialization and storage remain reusable
through C++ adapters. Do not port upstream code merely to avoid an adapter.

`Bmm.WorkQuoteDisplay` reuses the raw work-fee quote for mining RPC output. A
rejected quote hides partial cost/reserve values; an accepted zero-bid quote
retains those values but is not funded. The original raw quote API still returns
partial values on insufficient funding. Both share the same bounded output
writer. Direct RPC mining's BMM guard uses the existing short-circuit runner,
reading the proof flag only after the Elements-mode condition succeeds.

`ScriptPolicy.JournalVerifier` owns journal-verifier admission and result mapping.
`Drivechain.elements_hs_verify_journal` calls the linked Rust version and annex
verification functions directly through safe dynamic C FFI imports. Native code
supplies their addresses, not callbacks that implement verification. This keeps
optional-verifier builds linkable without a second Rust archive in the Haskell
runtime. Input buffers remain borrowed for the synchronous call; Rust must not
retain them. Rust `size_t` is represented by `CSize`, with a checked conversion
from the domain ABI's 64-bit length. Invalid input rejects before the ABI query;
missing functions or ABI mismatch return unavailable; only Rust status zero
accepts. The Rust proof implementation is unchanged. Native ABI tests exercise argument forwarding and every status class;
the node test also rejects a malformed proof through the linked Rust verifier.

`Drivechain.elements_hs_verifier_identity` also invokes the linked Rust version
and semantic-identity functions through safe dynamic FFI. It reuses
`ScriptPolicy.VerifierStartup` for admission order: frozen identity, availability,
ABI, identity format, successful export, then exact identity equality. Haskell
owns the zero-initialized 32-byte output buffer for the synchronous call. Native
code supplies function addresses (null in verifier-absent builds) and preserves
the existing error messages. Inactive startup does not read identity buffers or
call Rust. QuickCheck exercises the actual FFI with callback traces; native FFI
tests cover pointer availability and error clearing.

The exchange interpreter's Groth16 callback likewise uses a safe dynamic Haskell
FFI import with `CBool`/`CSize`, preserving the Rust C ABI and rejecting non-null
contexts before calling Rust. Proof buffers and the eight program-ID words are
borrowed, not copied or retained. The C++ callback catches failures before
returning to Simplicity C. The USDD Simplicity C jet uses `simplicity_ffi.h` to enter the
same Haskell journal policy. Haskell queries the Rust ABI before asking the native
annex accessor for bytes, then checks the tag and calls Rust. The native accessor
only exposes the existing transaction buffer. This preserves short-circuit order
and avoids a second ABI query. Missing verifier builds remain fail-closed.
The Elements Simplicity library also uses Haskell for canonical activation payloads
and checked 128-bit multiply/divide
and therefore always links `elements_haskell`. Standalone builds must supply
`HASKELL_LIBS` with the bridge archive, runtime library and runtime search path.
The separate `simplicity_bridge.cpp` object avoids pulling node adapters into these
standalone links. Verifier-enabled builds additionally need the Rust archive.

`Exchange.MulDiv128` computes the exact quotient with `Integer`, rejects zero
divisors and results exceeding 128 bits, and publishes two limbs only on success.
QuickCheck compares against the frozen native implementation, including output
canaries. An independent native test compares 10,000 cases against upstream
`arith_uint256` (the full product fits within 192 bits), including zero divisors
and output overflow. This changes implementation, not the accepted numeric range.
The standalone Elements Simplicity Makefile build also links and runs without a
Rust verifier when supplied only the Haskell bridge and runtime: 117 tests pass.

`CanonicalActivation` validates the exact 364-byte incremental activation public
values: version, ten nonzero identities, five positive scalar fields, ordered
price bounds, and separation of finite/successor configuration and predecessor
identities. The C adapter accepts only Haskell status 1; malformed lengths and
null pointers reject before reading memory. QuickCheck covers valid payloads and
targeted mutations against a frozen native oracle. Native ABI cases check all
three forbidden identity aliases and missing fields.

`CanonicalPublicValues` now shares the capital arithmetic for V4, V5 and the
incremental successor format. Each retains its own version, byte length, field
offsets, required identities, oracle and inbox rules. Arithmetic uses `Integer`:
an exact quotient or target that exceeds the encoded 128-bit field cannot match
that field, preserving overflow rejection without a native wide-integer engine.
The successor's signed-range checks remain stricter than the legacy target check.
The former C validators are retained only in the differential-test oracle.

`Groth16Header` owns the shared 79-byte envelope header checks for both modern
parsers and the legacy verifier. It checks magic, requested wire version, proof
format, pinned proof length and the eight canonical nonzero-together program
field elements. Native callers check total buffer lengths first, retain hashing
and buffer projection, and do not publish parser outputs on failure. The legacy
verifier compares the validated original ID bytes without re-encoding them.

`BondInput` shares reserve/collateral eligibility: current input, index at least
two, no peg-in or issuance, and a configured bond identity. Only eligible inputs
run the deferred script-hash comparison. The native adapter checks environment,
transaction and input-buffer bounds before projection; it selects the role's
expected hash but does not interpret eligibility. Both real C jet paths have an
exhaustive fixture matrix, including missing buffers and both issuance variants.

`JetHeight` owns the required sidechain-height predicate: authenticated projection
must be present and height nonzero. It deliberately has no signed or 32-bit upper
bound. The native adapter only writes the accepted Word64 to the frame. Boundary
tests include the top bit, UINT64_MAX and rejection without frame modification.

`Groth16Proof` handles all five proof-entry modes through one workflow. It reuses
header and canonical payload validation, checks pinned program/digest bytes,
requests native hashing when needed, and only then calls the provided verifier.
Legacy modes match identities before hashing; modern modes preserve their former
hash-before-identity-match order. Both callbacks use safe C FFI imports, with
borrowed buffers valid only for the synchronous call. This generic proof callback
retains the caller's context; the separate direct Rust adapter still rejects a
non-null context as required by its narrower contract. Hash failure, missing
callbacks and unknown layouts fail closed. Effect-trace properties and native
callback tests cover ordering, forwarding and rejection before verification.

`Groth16Envelope` is the common authenticated-envelope step used by proof
verification and public parsing. Parser FFI checks the exact output capacity and
all pointers before validation, then copies program ID, digest and public values
only on success. Publication masks asynchronous interruption between the three
copies. Native code retains the SHA256 implementation and fixed-size signatures;
no acceptance rule is duplicated in those parser wrappers. Canary tests cover
failed hashes, wrong capacities, missing callbacks and malformed envelopes.

Custody-receipt verification uses the same safe Rust boolean-result adapter.
The Haskell boundary checks the borrowed receipt buffer is exactly 138 bytes
per receipt before passing the count (not the byte length) to Rust. It rejects
missing functions, nonempty null buffers and lengths that cannot fit `size_t`.
The existing custody workflow still orders bitmap and commitment checks before
verification; Rust remains responsible for cryptographic receipt validity.

`ScriptPolicy.TransactionWeight` owns transaction standardness weight exceptions:
ordinary bytes keep their upstream cap, canonical bond-inbox and USDD annex
exceptions cannot combine, and proof-bearing transactions retain their total cap.
Native code supplies measured weights and existing limits. The guard rejects an
annex larger than the transaction before unsigned subtraction. QuickCheck and
native boundary parity tests preserve the pre-migration policy; this is not a
change to consensus transaction limits.

`ScriptPolicy.BondMarkerPolicy` preserves the preliminary bond-candidate scan
and the framed-marker policy check. Neither is a substitute for the full
canonical bond transaction validator: its stronger parser cannot replace these
deliberately weaker checks without changing which transactions are examined.
`WitnessAnnexFlow` (kind 263) owns ordered witness-annex routing through the
existing checked runner. Its four outcomes keep the stack, reject the input,
strip an annex, or strip and record a USDD annex. Native code
retains stack storage and existing classifiers; Haskell selects which classifiers
run, preserving frozen-activation precedence and missing-annex short circuits.

`TaprootWitnessPolicy` handles only the fork-added annex/Simplicity rules.
Native code retains inherited empty-stack/control-block checks, script-path
selection and Tapscript item limits. After those shape checks, adapters project
positive stack count, masked leaf version, script length, input index and
annex/bond facts. Haskell preserves the exact TapSimplicity shape and input-zero
canonical bond-inbox exception. Zero count or a non-byte leaf is an invalid ABI
call, not an alternative implementation of upstream witness validation.

`StandardnessGate` groups the remaining scalar policy decisions: all three
network/slot/feature facts must hold for USDD annex policy, any validated output
exception permits the nonstandard output, and witness resources require zero
error flags and a namespace count within the supplied upstream lane limit.
Native classifiers and error publication keep their order. Network facts are
read from immutable chain parameters; no effectful checks are eagerly moved.
The shared adapter rejects unknown kinds and nonzero unused scalar arguments.

`Bmm.PeerAdmissionFlow` reuses the checked runner for requested-block admission
(264) and initial header-sync backoff (265). Native adapters hold `cs_main` and
retain peer lookup and upstream sync eligibility checks. Request admission keeps
the native lookup even for already-requested drivechain blocks, but never reads
a missing state's header. Non-drivechain requests skip lookup. Backoff suppresses
the upstream sync callback entirely. Trace/exception tests cover these orderings;
they do not establish live P2P synchronization by themselves.

Peer timing comes from `BmmConstants`: pending block timeout and rejected-parent
backoff are 30 seconds, unavailable-parent backoff is 5 seconds. Generated native
constants feed chrono durations; `PeerBlockFlow` uses the same catalog's two-strike
threshold. Golden properties pin these values without changing network behavior.

## Domain ABI

`elements_hs_export_range_v1` retains bond-export modes 0 (preflight) and 1
(tip-bounded), with the 64-block limit. Mode 2 uses `Exchange.PegEventRange`:
activation must be zero, invalid start returns 1 before invalid count returns 2,
and count is limited to 1..10000. Success publishes the clamped end height;
rejection leaves output unchanged. Both paths share widened integer arithmetic.
Native peg-event iteration uses a widened index to avoid overflow at INT32_MAX.
Mode 3 uses `Exchange.PegEventStart` to select the default window from tip and
the Haskell catalogue's page size; start/count/activation must all be zero.
It publishes only the selected start, preserving canaries and output on failure.
RPC parameter parsing remains native, so a malformed explicit start still fails
before count parsing. Optional L1 query/append uses the shared lazy required-pair
rule: disabled queries perform neither effect, and query failure prevents append.
The existing numeric-range rule also enforces nonnegative configured slot values.

Availability mode 3 (`RPC`) requires one native fact. The ECX network guards and
peg-event tip guard use it before accessing context, parsing later fields or
dereferencing the captured index. Modes 0-2 retain their previous ordered facts.
Native adapters preserve their RPC errors and lock lifetime; malformed callback
replies and unknown modes fail closed. Tests cover empty RPC context, malformed
later arguments and missing tip before optional L1 work, with direct/FFI parity.

`Exchange.SourceSelection` composes `SourcePackage` directly and handles rejected
modified candidates: callback 7 removes the modified entry, then 8 marks the
transaction failed. Cleanup runs only on ordinary rejection (code 1), never on
success, callback/protocol failure or a non-modified candidate. Failure during
cleanup retains prior native effects and leaves the selected-source counter
unchanged. The native adapter owns the containers and still publishes the new
counter only after successful package insertion. The standalone package ABI is
retained; selection appends one exchange-state opcode without a new export.

`Deposit.FeeFreeSelection` evaluates raw fee, ancestor/descendant and parent/child
counts and signed timestamps, then composes `FeeFreeSelectionFlow` directly
(store selector 218, bound 16). It runs under existing native mempool locks and
preserves iteration order, short-circuit eligibility, conditional per-candidate
clock reads, package checks, insertion before counter publication, and singleton
cleanup before advancement. The deposit-state ABI adds one internal opcode, not
an export. The legacy boolean flow remains compatible. Native iterator/object
ownership, canonical verification and package checks remain. Step 11 reads the
entry timestamp and 17 reads the current clock only when age is positive and
earlier checks pass. Signed bit patterns are decoded before Integer cutoff
subtraction, avoiding signed overflow. Direct/ABI properties and native fault
tests cover the workflow; a 100,000-row scan is not a performance qualification.

`Bmm.TemplateCommitmentFlow` owns BMM-version marking (selector 216/bound 3) and
withdrawal-envelope admission (217/bound 11). Native header mutation, hash/envelope
snapshots, hashing, script serialization and coinbase insertion remain adapters.
Version marking reads Elements mode before proof eligibility. Envelope admission
preserves both Elements-mode observations and separate hash/envelope reads; it
looks up the envelope only for a nonzero new bundle or a predecessor lacking the
exchange-state flag, then checks availability and hash before inserting. Missing
or mismatched envelopes retain the original error and suppress insertion. Earlier
hash publication is retained on later failure. Safe callbacks permit script
serialization to reenter Haskell. Transcript/fault/publication tests do not replace
live concurrency or miner interoperability qualification.

`Bmm.TemplateSelectionFlow` (store selector 215, bound 5) controls the earlier
pre-mempool candidate-parent selection: clear prior selection, inspect native
slot availability, construct/authenticate the commitment candidate, then publish
only on success (or raise the unchanged error). Native coinbase/commitment-block
construction, script order, parent authentication and ownership remain. The
staged context is distinct from the published optional, so partial authentication
output cannot leak into selection. Safe reentry is required by the existing
authentication helper. Tests cover all native/authentication combinations,
exception prefixes, retained/reset/published states and original-thread execution.
This is deliberately separate from final-header parent authentication.

`Exchange.TemplateBudget` composes miner activation, snapshot admission and the
existing `AppendBudget` rule through one safe exchange-state-domain binding.
Signed 64-bit height/activation inputs preserve the native strict greater-than
gate. Callback 0 reads Elements mode; 1 acquires the native snapshot; 2..5 project
forced count/cursor and deposit count/cursor, only after successful acquisition.
The method invokes `validate (AppendBudget ...)` directly, without nested Check
dispatch or a return trip through ComputeSourceAppendBudget. The standalone API
remains and shares native diagnostics with the new bridge. Result codes are
0 success/bypass, 1 snapshot failure, 2 invalid cursor, 3 oversized backlog,
-1 invalid callback protocol. Normal rejection and bypass publish zero; malformed
protocols/callback exceptions leave the output untouched. The miner initializes
its budget to zero before entry. Native snapshot ownership/locks remain, and its
Haskell-backed implementation can safely reenter. Tests use an Integer oracle,
standalone-API parity, boundary heights/counters, buffer canaries and fault traces.

`Bmm.TemplateAdmissionFlow` (store selector 214, bound 8) owns the final replay
fence and candidate-validity gate in CreateNewBlock. Steps 1..3 lazily read the
assembly peg-in flag, current replay epoch and presence of peg-ins; 4 raises the
original replay-change diagnostic. Steps 5..6 select validation by explicit
option or native slot, 7 runs the native validator and 8 reports its state.
Replay rejection suppresses validation. Current epochs bypass the peg-in scan;
an explicit validation option bypasses the slot read, while a native slot forces
validation even without that option. Native transaction iteration, chainstate,
locks and BlockValidationState remain. The native diagnostic retains the outer
CreateNewBlock name rather than the callback's __func__. Tests cover all 64
predicate combinations, callback exception prefixes, thread identity and safe
Haskell reentry. They do not simulate a live replay publication race.

`Bmm.TemplateParentFlow` (store selector 213, bound 13) owns final candidate-parent
selection and exchange-header preparation order in CreateNewBlock. Steps 1..2
select Elements/native mode, 3 authenticates candidate P, 4..5 check an optional
supplied height, and 6 publishes the authenticated height. Steps 7..10 retain the
optional non-native BMM fallback. Step 11 prepares the exchange header; 12..13
raise the original native error or height-mismatch diagnostic. A failed fallback
does not reject the template; failed authentication/header preparation does.
Height publication before a later header failure remains observable. The shared
error buffer is cleared before header preparation. Native chainstate, cryptographic
authentication, locks and header ownership remain, with safe Haskell reentry.
The earlier pre-mempool parent selection is deliberately unchanged: it uses a
different candidate coinbase at a different time. Replay-generation fencing and
final candidate validity are still separate native policies.

`Bmm.StartupArgs` owns the fork-specific argument-admission prefix of
AppInitParameterInteraction. One safe configuration-domain call preserves lazy
reads, rejection order and timeout publication before host rejection. Native
callbacks retain ArgsManager, logging, private-file ownership and diagnostics;
existing bid/security helpers may safely reenter Haskell. Slot 256 means an
ordinary network. Slot, replacement and timeout reads carry full 64-bit values;
the existing native-int timeout conversion occurs before the callback returns.
Negative signed values convert to out-of-range unsigned values. No consensus or
configuration acceptance change is intended, including oversized timeout inputs
that previously narrowed to 1 or 2. Tightening that behavior is separate work.

Steps 1..3 handle reward compatibility. Step 4 runs the inherited native chain
metadata selection and Signet log unchanged; Haskell must not interpret that
upstream branch. Step 5 supplies Signet identity only for the fork's later
override restriction. The old log action 6 is retired. Steps 7..17 handle native
RPC security, bids, replacement, timeout and host; 18..19 ordinary-network
prohibitions; 20..21 Signet identity; 22..24 credential-file admission (reusing
8, 9 and 17). Boolean reads accept only 0/1; effects require 1. Steps 101..114
render the selected rejection. Result 0 accepts, 1 rejects, -1 is a protocol
failure. Invalid bounds perform no reads. Existing ABI operation numbers remain
unchanged and the new internal binding does not add a foreign export.

Tests compare direct and ABI execution to an independent ordered transcript,
exercise faults/thread identity at every successful native callback, and invoke
the real startup function on 30 configurations with exact error/timeout checks.
Three accepted-prefix cases stop at a later missing-directory error. These do
not qualify full daemon startup or instrument every filesystem/argument read.

`Usdd.ResourceAdmission` composes ResourceScan into block and miner-package
admission, using the existing BlockResources/PackageResources methods. A shared
ResourceReader selects immutable native transactions and supplies borrowed
witness spans; callbacks still run on the caller's thread under existing locks.
Resource flags stay inside Haskell, avoiding both recursive foreign entry and a
native flag-projection callback. The six-word internal options frame is mode,
flags, transaction count, initial usage, lane, weight limit (mode 0 block, 1
package, 2 policy weight). Step 6 reads a witness; transaction-selection steps
are 0/3/7 respectively.
Old standalone admission bindings remain compatible. Differential traces cover
disabled rules, rejection/advance order, callback failure prefixes and lazy
weight reads. Mode 2 uses PolicyResources to compose classification with
PolicyWithActivation. It preserves the full policy witness count even when
classification finds zero USDD annexes, and preserves partial native
weight publication before later rejection. AddToBlock remains separate.

`Usdd.ResourceScan` owns witness traversal, namespace accumulation and resource
flag union for a transaction. Native code supplies all borrowed witness spans
through a safe callback, without a duplicate namespace pre-scan. Empty witness
vectors need no standalone runtime entry. The profile is
decoded once; the shared legacy decoder invokes Resource/LegacyRequest methods
directly, without per-witness domain dispatch or nested Check adapters. Counts
and flags are strict, and the output count is published only after a complete
scan. The standalone legacy binding remains unchanged; the scan is an appended
internal binding, not another export. Mixed-profile reference tests, callback
failure/thread traces, ABI canaries and a 100000-row test cover this path.

`Exchange.EvaluatorSourceFlow` (store flow 269, bound 3) selects private
Simplicity identity configuration only after private-build and non-frozen facts.
Native code reports build flags and reads the two arguments in their original
order; the existing `EvaluatorIdentity` rule validates the selected values.
Frozen builds never consult private configuration. Callback-prefix/failure
properties and native RPC reporting tests cover this source selection.

BMM work-price and producer-reserve defaults originate in BmmConstants alongside
the bid and slot defaults. The producer, RPC quoting/submission and argument-help
text consume the generated values. Work price remains 1000 sats per kWU and
reserve remains zero; these are distinct from the default bid even where the
numeric value matches. The RPC rejection fixture checks default-price arithmetic
without making a parent-chain request.

`BmmConstants.privateJetPins` owns the historical 23-entry private Simplicity
catalogue's exact fingerprints, types, costs and order. `privateJetHeader`
reproduces the existing C initializer byte-for-byte, checked at configure time.
It is not the newer 24-entry typed catalogue: no identity re-derivation, cost
recalibration, activation or compatibility upgrade is implied. The native
initializer is retained as a checked generated artifact, not a second editable
policy definition. Golden properties check uniqueness, shape and fixed costs.
Per-witness native reads still cross the boundary. Block/miner workflows now use
ResourceAdmission for direct composition, and policy weight uses PolicyResources
through the same binding. Performance remains unqualified.

`Exchange.ActivationPolicyFlow` orders the fourteen activation-annex policy
checks through the bounded command runner (selector 212). Configuration/input
guards precede native parsing, then ordered identity comparisons; transaction
hashing remains lazy. Both standardness callers share this path. The Simplicity
parser, hash comparison primitives and native field offsets remain native.
Exhaustive predicate/fault traces and an explicit-configuration fixture cover
both callers. `Usdd.PolicyWithActivation` composes this command runner directly
inside `PolicyWeight`: steps 17..30 request its fourteen native facts through the
outer safe callback, without nested native-to-Haskell activation dispatch. Native
scratch buffers are reset per input. The standalone helper and v1 binding remain
compatible; the composed caller uses the appended v2 binding, not a new export.
Randomized multi-input traces and exhaustive activation/fault cases compare both
paths, including partial publication and same-thread callbacks. This does not
remove classifier reentry or establish a hot-path performance improvement.

`Usdd.PolicyWeight` orders resource failures before scanning witness items, skips
frozen activation annexes before querying policy enablement, and rejects a second
reserved annex before publishing another weight. Native CompactSize arithmetic
and immediate weight publication remain callbacks, preserving partial publication
if a later witness fails. The native reason strings are unchanged. This uses the
existing `usdd` domain/safe scalar transport and shared Check interpreter.
Property and callback tests cover ordering, failure prefixes and publication;
current-profile standardness passes. The frozen-profile integration fixture is
compiled out of this build and is not claimed as verified by these tests.
Its checks are also shared with a portable explicit-configuration fixture, which
exercises the real policy path without loading a production deployment profile.

`Usdd.PackageResources` controls miner package admission: peg-in eligibility,
native finality, optional candidate-parent script validation, then resource
classification and cumulative lane admission. It shares `exceedsLane` with
block admission, but deliberately does not inherit the block weight check.
The native iterator advances only after a row passes, under the caller's existing
locks. Callback thread identity and exception prefixes are tested. Accumulation
is private to the check; `AddToBlock` assertions and publication remain native.
The existing `usdd` domain and safe scalar callback transport are reused.

`Usdd.BlockResources` owns the block-wide resource scan, ordered rejection,
lazy transaction-weight reads and overflow-safe lane accounting. Its `usdd`
domain binding reuses the safe scalar callback transport: classify/count,
resource flags, and optional native transaction weight. Production block
admission composes classification through ResourceAdmission; the safe callback
transport is retained for native effects and other reentrant caller paths.
Native code retains the disabled-feature fast path, transaction lifetime and
unchanged rejection messages. The shared `Check` interpreter dispatches this
whole workflow; no new exported symbol or per-flag operation is introduced.
Property tests use an Integer reference and effect traces; native tests cover
all flag combinations and callback exceptions. Remaining policy helpers, direct
reuse of classification inside the outer workflow and performance qualification
remain separate work. This migration does not itself reduce boundary crossings.

`Bmm.HeaderAdmissionFlow` uses the existing command runner for header eligibility
and parent-context admission (selectors 210/211). Both share native index facts;
Haskell orders the reads and owns early acceptance/rejection. Ordinary networks
and genesis differ deliberately between the two modes. Null indexes and absent
anchors stop before dereference; context mode checks genesis before block status.
Native code retains cs_main and pointer lifetimes. Exhaustive predicate traces,
fault prefixes and the real index/context matrix cover both modes.

`Bmm.AnchorRule` owns persisted-anchor sanity and successor arithmetic. The
`bmm_proof` domain accepts the existing native 145-byte serialization, or two
anchors (candidate then predecessor) in one call. It preserves full 256-bit
work comparison, uint32 height wrap and the existing median-time bounds.
This is a pure `Check` rule: active-chain ancestry/authentication remains a
separate obligation. Native encoding and memberwise anchor equality are reused;
malformed ABI framing is distinct from a well-framed but invalid anchor.
Exchange admission uses the shared safe predicate transport because its native
callbacks can now reenter anchor validation. The FFI regression covers nested
success, rejection and thread identity, with a CTest timeout against deadlocks.
Replacement admission uses the same boundary with a uint32 status followed by
old/replacement anchors and an optional predecessor (294 or 439 bytes). It
requires authenticated ORPHANED status, two sane distinct anchors and, when
present, predecessor continuity. This batches the previous multiple calls;
it does not establish orphan status or ancestry itself. All anchor fields still
use their existing native serialization, not a new on-chain format.

`Bmm.AnchorCheckpoint` combines anchor sanity and the 80-byte prior-parent
checkpoint codec. Its appended `bmm_proof` selector consumes one native anchor
and publishes parent hash (32 bytes), height (8), MTP (8), and work (32), all
in the previous big-endian/display ordering. It reuses `AnchorRule` directly,
not a nested existential dispatch. Rejection preserves the output buffer. Native
code retains serialization, array ownership and optional-result handling; the
hex round trips and manual endian loop are removed. Golden checkpoint and
script-cache hashes, numeric-reference properties and ABI canaries cover this.

`ParentReplay.IndexCapitalFlow` (selector 209) owns capital-projection scan
termination, decode/index/root admission and publication ordering. It preserves
normal termination on key/namespace mismatch, errors without a final count log,
and earlier publications on a later failure. The native iterator and serializer
remain unchanged. Memory-only reload fixtures exercise valid and bad records.

`ParentReplay.IndexContinuityFlow` (selector 208) traverses loaded accumulator
indexes and selects genesis, predecessor/count and equal-state checks in their
original order. It stops at the first error before advancing the iterator.
Native index pointers and comparison primitives remain behind callbacks. Tests
cover ordered failure traces and real three-index reloads in a memory-only DB.

`ParentReplay.IndexDerivedFlow` (selector 207) sequences per-index anchor and
withdrawal-accumulator loading, genesis fallback and missing-state rejection.
Native callbacks retain DB reads and index publication. Earlier publications
are not rolled back on later failure. An in-memory block-index reload fixture
covers malformed/unreadable records, missing validated state and genesis fallback;
this does not replace full restart/reindex qualification.

`Exchange.SourcePackage` owns miner source-marker scanning, overflow/budget
admission and ordered package publication. Its exchange-state selector reuses
the scalar callback transport. Native code retains marker parsing, sorted
mempool entries, `AddToBlock` and modified-set removal. Selected counts publish
only after every callback completes; earlier native effects are not rolled back
if a later callback throws. Tests cover both this partial-failure contract and
the disabled-Elements/empty-package paths.

The peer workflows in `Bmm` use replay selectors 203-206 for full-block
outcomes, timers, locked header admission and post-lock header dispatch.
`PeerStrikes` uses an appended configuration-domain operation for its full-width
saturating count. These reuse the existing 15 foreign exports. Native callbacks
retain peer/index ownership and lock boundaries: timer effects run under
`cs_main`; block outcomes and header dispatch send messages after releasing it.
Tests compare independent action traces and failure prefixes, including mixed
known/unknown header scans and duplicate header requests after timer expiry.
They do not replace live P2P or restart qualification. Remaining native P2P
policy includes force-processing and initial-sync gates; migration is ongoing.

`Withdrawal.WalletIssueFlow` owns asset-dialog preflight sequencing and result
selection (kinds 201/202). The preflight remains outside the RPC exception
boundary. Qt retains amount conversion, string RPC parameters, formatting and
widget effects; Haskell orders availability, rejection, object/asset-field
selection and success publication. Mocked tests link the actual runtime and
cover missing RPC, invalid amounts, normal/fallback results and exceptions.
The RPC itself is always a fake in these tests; no asset is issued.

The obsolete LWK helper dialog and its refresh/send workflows are removed.
Flow IDs 198..200 remain reserved and reject every request, including bound
queries, without authorizing callbacks. Later IDs are unchanged. This does not
remove node-side LWK address aliases or standard node wallet functionality.

`GrpcRequestAdmission` extends request orchestration with method and payload
length admission before parsing. Native callbacks project saturated Word32
lengths; Haskell enforces the 128-byte method and 1..1048576-byte payload bounds.
Method parsing still precedes payload admission, JSON parsing precedes credential
checks, and no rejected path executes the child process. The original kind 145
remains unchanged; kind 197 uses the same transport without a new foreign export.
Native trace tests cover both flows and exceptions at each callback boundary.

`CredentialFileFlow` owns absolute-path admission, platform-specific read
sequencing, size/error handling and trailing LF-then-CR normalization. It composes
`PrivateFileAdmission` and `CredentialRead` on POSIX. Native callbacks retain
filesystem operations, buffers, descriptor lifetime and diagnostics. Windows
publishes the read buffer before checking stream/size failures, preserving the
previous behavior. Direct/ABI traces cover both branches; native filesystem tests
cover POSIX permissions, bounds and newline combinations. Native Windows
qualification remains outstanding. This adds no foreign export.

`CredentialRecordFlow` (273, three actions) composes file reading and credential
validation. Read failure exits without validation or diagnostic replacement;
only a successfully read invalid record is cleared and assigned a format error.
Native callbacks retain storage and diagnostic wording. Trace tests cover lazy
tails, malformed replies and exceptions before rejection effects.

`TlsFileAdmission` owns mTLS metadata policy and its short-circuit order. Native
callbacks supply filesystem observations and full-width unsigned identities;
Haskell compares ownership, permission bits, device and inode. Opened descriptors
are closed before an opened-file rejection is reported; native exception cleanup
handles interrupted workflows. Windows branch tests are not a substitute for
native Windows qualification.

`PrivateFileAdmission` validates POSIX credential metadata in order: regular-file
fact, owner UID versus effective UID, then group/other permission bits. Native
code retains the OS calls, type projections and error/descriptor actions. Raw
metadata outside the supported unsigned 32-bit range fails closed, and later
reads are skipped after rejection. No file contents are read by this operation.

`CredentialRead` owns the bounded POSIX credential read loop through the existing
safe scalar callback transport. Native callbacks return byte counts, UINT64_MAX
for EINTR, or UINT64_MAX-1 for a read error, and retain descriptor ownership.
The workflow controls offsets, short-read accumulation and the 4097-byte probe;
impossible counts reject without publishing output. Native errno is captured
before returning to Haskell. File permissions and Windows I/O remain native.

Configuration parser modes 7/8 validate rotating cookies and static credentials,
returning one acceptance byte or the existing syntax-rejection code. Native file
access and trailing newline normalization precede this parser unchanged. Exhaustive
byte comparisons and file-level tests preserve format, size and rejection behavior.

`GrpcTextAdmission` computes address shape, address byte/length admission and
authority byte admission in one request through the configuration export.
Native configuration sequencing consumes those facts in the original error
order. This is not a credential or connectivity check. Its comparison tests
cover all byte values, embedded NUL, scheme precedence and the 512-byte boundary.

Parent recovery reply/header admission uses `RecoveryReplyFlow` and
`RecoveryHeaderFlow` through the existing safe command transport. Field-type
guards precede native typed getters; active-chain lookup runs only after header
admission. Regression coverage checks short-circuit traces, nested RPC failures,
confirmation loss, active-hash changes and native exception propagation.
`RecoveryPeerReplyFlow` adds reply-shape admission before iterator initialization
and composes the original peer selector without changing its protocol. Tests
exercise both entries through direct execution and the native ABI.

The current ABI has **16 Haskell foreign exports**: 13 domain entrypoints
(`configuration`, `usdd`, `exchange_codec`, `exchange_state`,
`exchange_admission`, `parent_replay`, `bmm_codec`, `bmm_state`, `bmm_proof`,
`deposit_state`, `deposit_evidence`, `withdrawal`) and the three existing
`live_begin/resume/free` lifecycle functions. The C runtime initializer is a
separate sixteenth C symbol. Older per-rule names mentioned below are now
internal typed C++ bindings, **not** exported C functions.

`abi.def` groups handlers; its per-domain row order defines the operation IDs.
Append within a domain; never reorder/delete a row or change its signature in
the same ABI version. `generate_abi.py` derives both `DomainABI.hs` and the small
`domain_abi.h` binding declarations from the ordinary `Drivechain.hs` type
signatures. Run it after changing those inputs. The native build runs `--check`
and rejects stale generated bindings. `abi.h` implements native packing once;
`Abi.hs` implements shape checks, canonical integer decoding and invocation once.
No runtime registry, unchecked operation cast or capability widening is used.

Each domain call borrows separate scalar, data-pointer and callback lanes for
the duration of the call. Exact counts and non-null lane/result storage are
checked before reading lanes; narrow unsigned and signed-32 scalars must be
canonical. The transport returns 0 on successful dispatch, -1 for an unknown
operation/invalid frame, -2 for a noncanonical scalar, or -3 for an exception.
Domain accept/reject/error results are separate, sign-extended in the result
word. Shape/range rejection does not write that word or invoke the handler.
An exception does not publish the result word, but does not roll back effects
already performed by a handler; existing effect-order and transaction rules apply.
Direct properties cover signed-32 sign extension before handler invocation and
result-canary preservation for both IO exceptions and lazy result exceptions.
This is an in-process ABI, not a network format or a sandbox for invalid native
pointers. Existing non-reentry restrictions remain unless an entry explicitly
documents and tests safe nested callbacks, as BMM submission does below.

The old per-function C ABI is intentionally removed; rebuild native consumers
and the Haskell library together. Do not substitute the new library into an old
running process. Consensus serialization and persistent data formats are not
changed. Windows/cross-platform qualification remains outstanding.

### Shared store workflow runner

`ParentReplayStore` now executes its command loop in `Workflow.CommandFlow`,
through one appended parent-replay domain handler. The existing per-step ABI and
all flow IDs remain unchanged. The workflow calls the selected transition rule's
`Validation` method directly; standalone transition calls retain `Check` dispatch.
Native actions remain synchronous, borrowed callbacks with their original object
and lock lifetimes. The callback is imported `safe`, permitting nested Haskell
calls on the originating OS thread; it is not scheduled asynchronously. Exceptions
are captured, stop the workflow, and are rethrown with their native identity.
An Int64 callback result preserves all valid uint32 replies while reserving -1
for exceptions. Terminal actions ignore valid replies; committing actions finish
only on reply 1. Neither failures nor exceptions undo already-published effects.

The automatic producer uses this runner for native-vs-ECX routing, unsigned
nonce search admission, witness failure handling, and acceptance reporting
(`Bmm.ProductionRoutingFlow`, `BlockPreparationFlow`, `BlockAcceptanceFlow`).
These append flow IDs 307-309 without adding C ABI entries. A configured slot
selects only the native withdrawal-checkpoint producer; neither route falls
back to the other on failure. Nonce/hash operations, block ownership and
`ProcessNewBlock` remain native. Preparation preserves the original short lock
around extra-nonce mutation; no lock is extended across a bid or proof wait.
Acceptance still occurs only after the enclosing producer verifies mined BMM.
Tests cover exhaustive callback traces, malformed replies, native exception
identity, nested producer workflows, and real native preparation/acceptance.

The protocol remains resumable, but ordinary callers no longer cross the native
boundary for each transition. Their native actions still cross as callbacks.
No retry policy, iteration limit, persistent format or capability expansion is
introduced. Differential tests compare 6,112 traces/results/exceptions with the
previous native runner, including nested entry, invalid flow IDs and uint32
boundaries. Concurrent callers test originating-thread ownership; properties cover
command framing and a 100,000-action traversal. Other callback APIs retain their
own reentry restrictions. This does not qualify Linux or Windows behavior.

`Workflow.PredicateFlow` similarly owns deposit verification/parsing/lifecycle,
parent-tip validation and four peg-event loops. It shares the existing transition
rules, calling their methods directly after one outer Check dispatch. The native
RunRuleFlow and RunPegFlow loops are removed. A parent-replay handler covers tip
validation; a deposit-state handler covers verification (kind 0, existing start
phases), withdrawal status (1), L1 normalization (2), sidechain events (3) and L1
location (4). Event kinds require start 0. Old per-step ABI rows are unchanged.

Verification accepts transition 0 and rejects -1; event workflows require a
successful terminal action. Terminal bit 8 forwards the action's boolean result.
The runner preserves invalid-action versus failed-transition diagnostics and
rejects non-boolean callback replies. Safe synchronous callbacks preserve native
exception identity, nested calls, originating threads and earlier publications.
Native tests compare 960 exact traces/results/exceptions across all 15 public
entry paths with the old runners. Properties cover framing, null/invalid requests,
malformed replies and 100,000 iterations. No retry, rollback or export is added.

Fifteen exchange adapters now use ReadAdmission/ReadBoundAdmission directly,
removing the redundant ExchangeAdmission forwarding layer and its packing lambdas.
They retain the original int32 callback and zero exception fallback; original
exceptions are still rethrown after the Haskell call. This reuse changes neither
their transitions nor the callback reentry restrictions of their individual APIs.

This reduces the exported surface, not the number of underlying rules:
ordinary handlers still serve the domain APIs. It does not by itself reduce
crossings for every caller. The capital workflow additionally combines identity
binding and snapshot projection in one crossing: `CapitalRequest` carries
`IdentityBinding` and `SnapshotProjection`; after payload `Refl`, `interpret`
binds first, then projects only on success. Finite/incremental values are packed
once and return the complete 914-byte snapshot. Activation retains its separate
steps because intervening script checks must keep their original order.

`FrozenRequest` moves the complete V18 frozen-configuration decoding sequence
into one domain call. After payload `Refl`, `FrozenInput`, `DigestEffects`,
`XOnlyChecks` and `FrozenPublication` supply validation and ordered effects.
The generic interpreter reuses the existing profile validators and `ExceptT`
from `transformers` for early rejection. Native Elements retains tagged hashes,
public-key validation and materialization of decoded fields. Publication effects
preserve partial field updates on later rejection or exceptions, rather than
silently changing the old decoder to an atomic update. The ABI validates each
effect's exact input size; native exceptions propagate after returning from
Haskell. A test-only copy of the previous decoder checks acceptance, exact errors,
partial fields and cryptographic transcripts across mutations and failures.

`GenesisAdmissionFlow` owns the complete deployment/genesis admission ordering
through the existing resumable `ParentReplayStore` protocol (flow 162). It selects
the public/confidential branches, first failing error group and final snapshot
publication. Native actions retain transaction/coin access, upstream crypto and
previously migrated encoding helpers. Actions use the shared safe callback;
issuance, commitment, initialization and root helpers may invoke Haskell again.
The simple transition table uses the shared `Check`/`Validation` operation adapter
rather than introducing capability classes with no reusable behavior. Native
adapters preserve precise errors; identity and initialization errors are passed
through unchanged. This moves control ownership without promising fewer runtime
crossings for individual native actions. No flow-specific export is needed.

`CapitalProjectionFlow` (flow 163) extends resumable orchestration to the complete
post-script projection: genesis, carry-forward, incremental activation, finite
successor and incremental successor. It reuses native adapters for the existing
Haskell successor scan, admission and context validators through safe callbacks.
Carry-forward publishes the prior snapshot before identity checking; successor
decoding publishes before later context rejection; activation publishes only
after its checks. Appending inbox sources remains after publication. Preserve
these non-atomic effects and exact error precedence. The table uses the existing
Check/Validation dispatch and does not add an export. Native transcript tests
cover five branches, rejection, exceptions and modeled publication actions;
existing transaction fixtures exercise actual snapshot behavior.

`FrozenIdentityGroups` combines the final frozen-admission collision checks into
one identity-relation call (modes 9/10 for oracle/direct-price). It checks three
configuration hashes, three or five proof roles, nine covenant roles, then the
isolated state-node domain against four other domains. Existing IdentitySet and
IsolatedIdentity validators retain exact first-error behavior. Unlike deployment
configuration parsing, this collision-only stage does not independently reject
zero identities; the earlier required-identity checks still own that policy.
The native adapter reuses the required-identity table to avoid a second set of
field lists. Native and QuickCheck tests cover collisions, zeros and ignored
direct-price oracle roles. Four crossings and packing buffers become one, with
no new export or ordinary domain handler.

`FrozenAdmissionFlow` (flow 164) now owns the surrounding admission order:
deployment version/blinders, optional V6 decode and hash check, direct-price
oracle absence, required identities, physical inputs, bounds, registry and the
combined collision operation. Native actions use the shared safe callback, so
decoder and validation helpers can use Haskell themselves. Required-field
labels and native key/hash primitives remain adapters. Conversion roles reuse
indices 33 through 38 of the required-identity table. The simple table uses the
shared Check/Validation interpreter; it does not add an export. Tests cover
skipped/reachable actions, failures, exceptions, nested calls and production
direct-price error precedence.

`ActivationFacts` combines the startup physical/configuration join and required
covenant tuple check in identity-relation mode 11 (40 hashes). Its pure checks
retain mismatch-before-missing-tuple error precedence, frozen renderer/NUMS
identities, and the three covenant inequalities. Native hashing, parsing and
the catalogue activation guard remain unchanged. Differential tests retain the
original C++ predicates; QuickCheck covers malformed inputs and tuple mutations.
This adds no export or ordinary domain handler. Helper validation does not imply
end-to-end startup activation when the catalogue guard disables that path.

`RuntimeIdentities` checks the earlier runtime proof/matcher join through the
same identity API (mode 12, 16 hashes). It reuses IsolatedIdentity for the
transition/truthcoin inequality, then checks the seven configuration pairs.
Matching zero pairs are deliberately allowed here: presence rules belong to
the subsequent deployment validator. Both startup order and the old error remain
unchanged. Native mutation tests and QuickCheck cover these distinctions.

`DeploymentOutputs` reuses SpendScan to classify both startup transaction output
lists. Spend-scan ABI mode 2 interprets start as the skipped output index and end
as the output count; the skipped index must exist and is never read. The callback
returns eight fact bits: explicit asset, explicit value, null nonce, bond asset,
reissuance asset, USDD asset, nonzero amount, and designated token-burn index.
Unknown bits reject. Native getters are guarded by explicitness; Haskell owns
asset exclusions, the burn exception, traversal and first-rejection stopping.
Mode 2 returns 0 for acceptance, 2 for rejection and -1 for malformed input;
the existing output pointer is required but never written. Callback exceptions
retain the native adapter's rethrow behavior. No export or handler is added.

`StartupDeploymentFlow` (store flow 165) owns the enclosing physical startup
sequence: issuance, asset derivation, optional private inventory opening, burn,
authority shape/identity, deployment outputs, genesis linkage/authority and
genesis outputs. Actions 1..53 retain the old check/publication order; terminal
error actions 54..64 preserve the eleven original messages. Public deployment
skips only private inventory checks 12..17. Native crypto and data access execute
through safe callbacks, permitting existing Haskell issuance/output helpers to
run. Getter and indexed-access prerequisites remain earlier
steps. Native tests cover both paths, each failure/exception and nested calls;
QuickCheck covers the transition protocol. No new export or handler is needed.

`ConfigurationBindingFlow` (store flow 166) checks the startup configuration hash,
chain, pegged asset, parsed USDD asset, policy asset, forced-action domain, deposit
domain and collateral script hash in their original order. Error actions 9/10
preserve hash-vs-network mismatch distinction. Argument parsing at action 4 can
call Haskell through the safe callback; earlier failures skip it,
and its own error propagates without becoming a network mismatch. The simple
Check/Validation table adds no export or ordinary handler.

`IdentityFileFlow` (store flows 167/168) shares deployment identity admission and
reset policy. Reset bypasses precede configuration reads; existing identities
must match, while fresh directories bind before opening databases. Material
legacy data defers binding and rejects reindex/reset. Native actions retain file
access, atomic writes, hashing and exact diagnostics. The existing-identity
reset check uses the shared safe callback for nested Haskell calls. No new export
is added. An independent QuickCheck oracle
compares complete action prefixes and results; native lifecycle tests exercise
tampering, material data, reset bypasses and an obstructed temporary-file retry.
Native adapters retain database and filesystem ownership.

`MaterialScanFlow`/`MaterialLocationsFlow` (175/176) own directory traversal and
the ordered search of local index, external index, local block files, external
block files and chainstate directories. A match skips later locations; each scan
checks existence, iterator availability, entry type, name and final predicate in
that order. Native code retains filesystem access and iterator ownership.
Generated traces test lazy predicates and first-match
termination; fourteen real filesystem cases cover both block roots, orphan index
entries, block/undo files, snapshots and non-material lookalikes. Filesystem
resource ownership remains native.

`MaterialName` is an appended configuration-domain handler, not a new export.
It accepts a basename (not a complete path): chainstate mode matches the exact
case-sensitive prefix; block mode combines blk/rev prefixes with the .dat suffix.
Both block checks therefore use one call. Native code still extracts the filename
using its platform path implementation. A 343-name matrix compares both modes
with the original native predicates, including native path extension behavior,
and QuickCheck covers arbitrary byte basenames and invalid ABI arguments.

`IdentityWriteFlow` (store flow 174) orders temporary-file creation, write, file
commit, close, rename, directory commit and success logging. Write/commit failures
close once before removing the temporary file; close/rename failures remove it
without a second close. Native code retains FILE ownership through RAII, releasing
it only for the explicit fclose actions; exceptions across the bridge therefore
cannot leak an open FILE. Cleanup/error ordering and the existing DirectoryCommit
call remain unchanged. Generated traces cover each failure and
single-close behavior; native fixtures exercise real writes and obstructed-temp
failure/retry. These are not process-crash or power-loss durability tests.

The production writer now executes `IdentityWrite` in one configuration-domain
call, driving those same transitions in Haskell. Store flow 174 remains available
for compatibility, but the native writer no longer resumes across the boundary
for each action. Its callback is imported safe because filesystem operations can
block; native actions must still not call back into Haskell. Malformed callback
results stop immediately; native exceptions are captured at the C boundary and
rethrown after Haskell returns. Tests compare combined/resumable action traces,
inject invalid callback results and verify native exception identity and prefix.

`IdentityRecord` constructs the complete v3 data-directory identity in the
configuration domain (appended handler; export count unchanged). Input contains
the raw network bytes and two native-order 32-byte hashes. Haskell reverses each
hash for lowercase display, requests one native checksum of the complete prefix,
then formats that digest in the same way. The native caller retains the existing
Hash implementation. Output is exactly network length plus 258 bytes, with
capacity/overflow/null guards before reads or callbacks; callback failure leaves
output and written length unchanged. Tests check arbitrary bytes, exact prefix,
digest order, canaries and faults, while the native fixture verifies the real
checksum and record format. Native checksum callbacks must not reenter Haskell.

`IdentityBindingFlow` (store flow 169) orders the binding lifecycle: configuration,
disabled/in-memory bypasses, existing identity verification and audit, or missing
identity reindex protection, all-branch legacy validation, coins-history checks,
audit and atomic publication. Existing identities are never rewritten by this
flow. The native scans execute through safe callbacks and can invoke their
existing Haskell validators. A separate action-prefix oracle checks failures at
each stage; native fixtures check identity mismatch before invalid-header audit.

`IdentityAuditFlow` (store flow 170) owns persisted-header iteration: skip entries
without a predecessor, validate BMM before ECX, count only fully accepted headers,
and log only after exhausting the iterator. Native code owns the iterator, header
references and shared diagnostic formatting. Validators execute through the
shared safe callback, allowing their existing Haskell calls. Generated header
lists check exact action traces, including skipping,
failure short-circuiting and counting; a native fixture checks BMM precedence
when a header carries both invalid BMM and ECX flags. No new FFI export is added.

`IdentityHistoryFlow` (store flows 171/172) shares legacy-tree and ancestry
traversal. The native adapter owns pointers/iterators, the header namespace mask
and exact diagnostics. Tree mode checks namespace/special historical hash before
height for every entry. Ancestry mode first handles null/missing tips, then scans
all ancestors for namespace/special hashes before checking the original tip's
height. The special hash is read only when namespace flags are absent. Generated
trace tests independently model both orders, including early failures; native
tests cover all namespace masks, unknown coins tips, and the historical hash
without flags.

`IdentityCoinsFlow` (store flow 173) traverses all chainstates, checking exchange
tracker presence before BMM tracker presence, then best-block history and each
recovery head in order. Native code owns the snapshot of chainstate pointers and
the head vector; all reads and nested validators use the shared safe callback.
Generated two-level traces check empty lists, stage failures, head-index resets
and short-circuiting. A real disposable on-disk coins DB fixture writes `H`
recovery records while the DB is closed, reopens it through InitCoinsDB, and
verifies missing head 0/head 1 reject without changing either recovery records
or the absent best-block record. Valid heads permit binding without erasing them.
This tests persisted recovery records, not actual process-crash durability.

ConfigurationField mode 6 (`CUSTODIAN_REGISTRY`) reuses the hex decoder for the
startup registry argument: exactly 650 hexadecimal characters produce 325 bytes.
It accepts either case, rejects whitespace/NUL/nonhex/incorrect lengths, and does
not itself impose key validity or nonzero rules. Existing registry decoding still
checks record structure and keys afterward. The byte ABI rejects the wrong size
before copying input and keeps the existing capacity/canary behavior. Native
parser comparison tests cover every character position and boundary lengths.

FrozenBounds accepts one startup field (signed-positive mark price transported
as Word64) or three (initialization height, signed-32 activation height, parent
MTP). The price must be in 1..INT64_MAX; height in 1..activation-1, activation at
most INT32_MAX, and MTP in 1..UINT32_MAX. Unsigned encodings of negative arguments
reject. The two calls stay separate: successful price publication still occurs
before initialization argument reads/rejection. Native signed-reference tables
and QuickCheck compare signed boundary values, including negative activation.

`HashArguments` parses all 22 startup hash arguments in one Haskell invocation,
reusing ConfigurationField. Only direct-price roles 14..19 permit zero. Native
callbacks read text lazily and publish each successful hash before the next read;
they must not reenter Haskell or retain buffer pointers. This replaces the local
intermediate hash-argument resume flows (removed before publication). Reads use actions 0..21 with a 64-byte output
buffer (return 1 for wrong length); writes use 22..43 with a 32-byte input. Other
callback failures stop the workflow and native exceptions are rethrown. Result 0
means success; 4*(one-based role)+1/2 means syntax/nonzero failure. The adapter
returns a zero-based role and nonzero-failure flag for the existing error text.
Tests cover faults at every position, partial publication, both zero policies,
and reader/publisher exceptions. `BmmConstants.bondHashArguments` owns the ordered
names and emits `ECX_BOND_HASH_ARGUMENTS`; native code retains only the typed
destination pointers with a compile-time count check. The real ArgsManager test
uses distinct values for all 22 names to check lookup/publication order.

Genesis snapshot construction also uses the existing state-codec operation,
mode 11 (`GENESIS_SNAPSHOT`, capital profile 3). Its input is 15 raw hashes in
native field order plus one big-endian 64-bit mark price; height and parent MTP
remain scalar arguments. Output is the existing 914-byte version-4 snapshot.
Haskell shares fixed supply/coverage defaults and empty inbox construction with
activation, while retaining genesis-specific prices, oracle validity, receipt
root and finite proof profile. The native caller still authenticates issuance,
coins, initialization ancestry and the singleton script before materializing the
snapshot. This codec is not authentication and must not bypass those gates.

`GenesisRequest` also composes private/covenant root construction using declared
`GenesisEncoding` and `DigestEffects` capabilities. After payload `Refl`, the
interpreter rejects invalid input or runs the validated plan through the generic
digest helper. The same checked digest capability is used for custody roots.
The request packs 12 identities once, keeps the 242/725-byte intermediate states
inside Haskell, and returns four roots through one existing domain API. Native
callbacks only provide upstream tagged/SHA256 hashing and cannot reenter Haskell.
Five duplicate deterministic empty/inbox hashes are reused; the normal path uses
10 hashes instead of 15 and one C++-to-Haskell call instead of four. Zero bond or
funding roots stop after both are computed; zero private roots skip covenant
construction. Hash callback exceptions still propagate through the native
exception holder. These hash effects must be deterministic for a given kind and
input; they are not arbitrary stateful callbacks. This does not authenticate
genesis transactions or replace the preceding validation gates.

## Migrated rules

Exchange inbox arithmetic now uses `Exchange.InboxRule` through the shared
`Validation` adapter. `ComputeSourceAppendBudget` and `ValidateInboxLiveness`
project fixed-width counts and cursors through `elements_hs_exchange_inbox_v1`.
Four input words select budget validation; twelve select liveness validation.
The two output words encode write-present and value. Return codes 1 through 7
follow `InboxError` declaration order; -1 is an adapter failure, not rejection.
The native wrapper preserves error strings and the output write before deadline
failure. Native static assertions pin the 64/448/6 rule constants.

Qualification: 20,000 native differential scenarios (60,000 assertions), Integer
oracle and ABI canary properties, full native suite, and isolated installed
static/shared consumers. This inbox stage made the exchange C++ module 69 lines shorter; combined FFI and
Haskell additions mean this stage is not an overall production line reduction.

Processed-cursor admission uses `Exchange.Cursors`. Native marker decoding and
transaction hashing remain native; the final comparison is still conditional on
a transition with a marker. The standalone binding's four flag bits encode
transition, marker presence, empty activation and matching transaction. Four
input words carry prior and marker cursor pairs. `elements_hs_exchange_cursors_v1`
writes two output words only on success; codes 1/2/3 distinguish missing marker,
unexpected marker and invalid progress. Invalid flags/pointers return -1.
The empty-activation exception never infers progress. Full covenant authentication
is unchanged. Qualification adds 20,736 native boundary combinations (82,944
assertions), ABI properties and installed consumer success/rejection cases.
Other exchange-state, bond and capital-projection policy remains to migrate.

`CursorDerivation` now owns the surrounding transaction/output scan and duplicate
rejection. It calls the `Cursors` method directly after scanning, with no second
Check dispatch. This ordered workflow uses the existing Check/Validation adapter;
there is no need for another capability family merely to traverse outputs.
Native actions are: (1) output count, (2) decode (0 malformed, 1 absent, 2 marker),
(3) retain the first marker's transaction hash, and (4) compare that hash. Count
and retain actions require status 1; comparison accepts only 0/1. Full uint64
cursor values travel in two separate output words, not signed status results.
The workflow flags are transition/empty-activation in bits 0/1. Result codes
1/2/3 retain cursor errors, 4 preserves native parse diagnostics, 5 is a duplicate,
and -1 is an adapter fault. No cursors publish on rejection/exception. This scan
remains after complete inbox derivation and activation checks, preserving error
precedence. Its appended domain binding leaves the 15 foreign exports unchanged.

Tracked and successor authority admission uses `Exchange.Authority` through
`elements_hs_exchange_authority_v1`. Its ordered reader checks explicit asset,
explicit value, null nonce, successor-only asset/value continuity, then P2TR
length and opcode bytes. The native adapter contains exceptions and rethrows
after the Haskell call; readers must not reenter Haskell. `CheckAuthority` shares
the CTxOut projection and preserves caller-specific diagnostics. UTXO publication
and root hashing remain in their original positions. Native failure/exception
traces, property tests and installed-consumer checks cover the boundary. This
replaces policy bodies, but does not claim an overall line reduction.

`Exchange.StateTransition` owns singleton selection and successor derivation,
calling `SpendScan` and `TransactionShape` methods directly. It scans all prior
spends before inspecting the selected transaction, validates input zero and
output zero before authority, publishes the next outpoint/root, then rejects
same-block chaining. A later chaining failure does not undo publication.
The eight native actions retain outpoint comparisons, authority projection and
hashing. This workflow uses a safe callback because authority reenters Haskell;
the authority reader itself still must not reenter. Full-width counts remain
distinct from boolean/effect statuses. Native exceptions survive the boundary,
while invalid statuses fail closed. The new domain slot is append-only, with
15 foreign exports unchanged.

Nested rules reuse their `Validation` methods without repacking a `Check` or
performing another type dispatch. Withdrawal payout checks follow this pattern
inside the selected withdrawal operation; the redundant payout adapter is gone.
The standalone payout FFI and deposit output/authentication boundaries retain
`Check`/`Validate`. This removes wrapping, not validation or error ordering, and
does not introduce a Flow for a single arithmetic rule.

Forced-action body admission uses `Exchange.ForcedBody`, reusing Withdrawal's
big-endian decoder. It validates shape/version, deployment chain id, market,
order flags, quantities, fee bound and expiry ordering. The native wrapper keeps
Schnorr verification and its original domain tags, unsigned lengths and trader
offsets. Native static assertions pin body lengths; identifiers are supplied
from native configuration. `elements_hs_exchange_forced_body_v1` rejects invalid
kind/length before reading bytes and copies at most 208 body bytes. Native
byte-by-byte differential tests cover all byte values at every offset, plus
kind/length boundaries; ABI properties check bounds and input nonmutation.

Forced/deposit marker output checks now share `CheckMarkerOutput` and Haskell
`OutputProfile`; confidential collateral admission uses the second profile.
Both profiles reuse `firstFailure` with authority admission, and their C++
callbacks share exception containment. Getter and proof-array accesses remain
short-circuited after encoding/bounds checks. `elements_hs_exchange_profile_v1`
accepts marker mode 0 or collateral mode 1, returns 0/1 for accept/reject and -1
for invalid ABI input. Parsing, caller diagnostics and result publication remain
native. Profile reads must not reenter Haskell.

Forced-tranche work admission now uses `Exchange.Tranche`. It streams borrowed
kind bytes, stops at the first unknown kind or over-budget action, and preserves
the partial work count. Cancellation costs one, a limit action costs 64, and a
withdrawal costs zero. `elements_hs_exchange_tranche_v1` writes the partial count
for domain outcomes; invalid pointers/counts return -1. The native constant is
compile-time pinned. Authority/profile FFI wrappers also share one interpreter
helper while retaining their existing exported entry points.

`InboxRequest` owns `DeriveInboxNext` orchestration through ordinary `ExceptT`
after payload equality and DSL matching. `InboxScanning` parses and retains forced
then deposit markers in output order, calling the existing `SourceMarker`
validation method directly without another Check adapter. `InboxAppending`
resolves the parent lazily once, checks count overflow, reuses `trancheWork`,
and appends forced entries before deposits. `InboxTotals` carries both uint64
counts, accumulated work, and parent-resolution state. Runtime marker results
produce zero, one, or two entries of the closed `InboxSource` sum.
`appendContributions` folds these in forced-before-deposit order; an empty list
leaves state unchanged without parent lookup. Unsupported marker masks reject
before append effects, and final publication consumes the resulting state.

Incremental tranche work replaces rescanning all earlier kinds on every append;
all earlier accepted prefixes have already been checked and costs are nonnegative.
The standalone `Tranche` operation reuses the same step while preserving its
partial work output. Native parse/hash/append helpers remain synchronous safe
callbacks (including their nested Haskell calls), with no native buffers captured
in a suspended program. Earlier native root/count mutations remain on a later
failure; optional append counters are published only after complete success.
The tranche diagnostic reset still occurs before checking each forced kind.
Foreign exports remain 15; this simplification does not change the FFI contract.

Exchange and inbox trackers share native `EncodeTrackerRecord` and
`SetTrackerRecord` adapters, preserving upstream DataStream/CScript encoding and
SpendCoin-before-encoding-before-AddCoin ordering. Persisted-record tests compare
all three scripts against independently serialized fields and check coin metadata.

Exchange and inbox tracker decoders now share a native `DecodeTrackerRecord`
adapter, removing 26 production lines ahead of their policy migration. Native
DataStream/GetOp decoding, partial tracker writes, error labels and catch scope
are preserved. Public snapshot tests cover corruption and successful restoration
of all three tracker records.

Tracker admission now uses `TrackerPhase` through the shared ordered validator.
Encoding and script phases remain outside the native catch; payload admission
remains inside it after native deserialization. Five/seven/three ordered reads
respectively preserve guarded getters, upstream GetOp advancement and payload
short-circuiting. Invalid phases invoke no reader. Native object predicates,
storage, serialization and partial output lifetimes remain native. Phase failure,
exception and public corruption/restoration tests cover these boundaries.

`Configuration` owns ordered exchange activation preflight. Fourteen native
predicates provide disabled activation, reserved-outpoint checks, required fields
and finally frozen script hashing. Disabled activation returns false without
modifying the caller's error; success also preserves it. Hash construction remains
deferred until earlier checks pass. Exhaustive predicate combinations and reader
exceptions test precedence, with native hashing and configuration values unchanged.

`HeaderPhase` checks exchange headers before activation, after activation, and at
the genesis boundary using eleven/eight/six ordered predicates. Configuration
validation stays outside the callback to avoid reentering the Haskell runtime.
Native field access and deferred genesis hashing retain their order; failures
retain the existing messages. Reader exceptions are rethrown only after returning
from Haskell, and invalid phases never invoke the reader.

`ParentTarget` owns assembly target-height bounds and test-only successor
selection. A supplied target reads no fallback facts. Without one, production
rejects before reading the previous header; elementsregtest can derive its
successor, bounded to the committed 32-bit range. The native reader keeps Params
and block-index ownership; it does not reenter Haskell. ABI failures and native
reader exceptions do not publish an output.

`Connection` owns final exchange-state admission: six root/cursor comparisons
precede three reserved-coin reads, with coin reads skipped outside activation.
It reuses the ordered admission callback and native exception trampoline. BMM
lookup, derived-state construction and storage writes remain outside this reader
to preserve effect order and prevent nested Haskell calls.

`DisconnectPhase` sequences prior-header checks, undo equality, activation
record removal and count bounds. REMOVE callbacks mutate native coins: earlier
effects persist if a later action fails or throws, exactly as before. The shared
admission runner never invokes later steps after failure. State decoding and
inbox derivation stay outside callbacks because they can already enter Haskell.
Tests record attempted and completed prefixes, plus public activation teardown.

`Availability` guards prior-root, cursor and snapshot reads. Pointer presence
precedes version flags and any root dereference. Three root accessors share one
native pointer-to-member adapter; outputs are cleared before checks and populated
only on success, preserving each original diagnostic. Public-accessor tests cover
all pointer/flag/root combinations rather than only the abstract predicates.

Tracker, header, disconnect and availability phases share a bounded phase selector.
Selection traverses only the fixed phase table and rejects unknown Word32 values
without invoking readers. This replaces repeated guards and partial list indexing
while preserving the same ordered first-failure interpreter.

`SourceMarker` owns duplicate forced/deposit marker and premature-activation
policy. Native parsing remains outside the rule because parsers already enter
Haskell. Each parsed presence bit advances a bounded two-bit state; rejected
steps preserve that state. Forced parsing/checking still precedes deposit
parsing, and activation is checked last. The count helper retains its existing
second parsing pass. Native sequence tests compare against the original boolean
policy; ABI tests check unchanged outputs on failure and adjacent sentinels.

`M6Preimage` parses the bounded no-witness envelope body using existing Haskell
`readLE` plus bounded field/CompactSize readers. It preserves prefix, output,
zero-value, locktime and script-shape error precedence, returning only the two
32-byte commitments. Checkpoint lookup, native hashes and the final PXST binding
remain native. A frozen previous-parser oracle checks byte mutations, truncations
and length boundaries; ABI tests verify failure preservation and output canaries.

`EnvelopeHeader` validates version, fixed-header size and declared body length
using widened arithmetic. The native adapter bounds each read, supplies decoded
scalar fields and preserves errors on success. Duplicate detection still precedes
this rule; native canonical script comparison still follows it. Header boundary
tests cover version/length error precedence, including full-width ABI values.

`EnvelopeRequirement` chooses reject, skip, or verify from bundle presence,
change, prior activation and envelope presence. An unchanged nonzero commitment
still requires an envelope when crossing activation. Native parsing precedes the
rule; hashing and checkpoint checks run only for VERIFY. The full 16-case truth
table is tested against the original native branches and invalid ABI flags reject.

`CapitalIdentity` selects the frozen identity fields for the V5, incremental
successor and activation projections. It compares raw identities and activation's
BE64 execution fields, requiring exact public-value and expected-record sizes.
The native adapter packages fields; annex parsing and snapshot writes remain native.
Tests mutate every native input byte and cover ABI bounds and missing buffers.
The snapshot adapters use standard fixed-count copies for all 18 wide fields;
public projection tests check those bytes against the parsed annex offsets.
This keeps native storage marshaling explicit without repeated end-offset math.

`GenesisInitialization` owns the version branch and ordered context, legacy,
checkpoint ordering and authenticated-ancestor admission. Legacy initialization
never reads the previous block. Unknown versions reject after context checks;
ancestor lookup only follows all ordering guards. Native outputs still reset
before validation and are written only on success. Exhaustive predicate masks,
callback exceptions, QuickCheck and public ancestor/legacy fixtures cover this.

`Deployment` handles supported deployment versions before any reads, then public
zero-blinder requirements, activation and frozen-identity flags in that order.
Version 2 never reads blinders. Configuration decoding and subsequent frozen
identity validation remain native and only follow successful admission.

The native ExchangeResult helper shares bounded result/error handling across
eight adapters. A null diagnostic entry retains configuration's silent rejection;
success preserves existing diagnostics. Invalid results throw the caller-specific
exception before output assignments. Callback exceptions still rethrow earlier.

`FrozenBounds` owns the 16 frozen deployment numeric limits, including exact
Simplicity leaf version, inbox/queue capacities, supply and timing values plus
nonzero conversion age and bounded proof size. The fixed-width native projection
only packages fields; ABI count/null checks precede reads. Boundary tests compare
against the previous native predicate and check input preservation.

`IdentitySet` shares raw 32-byte uniqueness validation across frozen configuration,
active proof-program and covenant-role checks. Direct-price mode still excludes
the two inactive conversion programs. Separate calls retain original diagnostic
precedence; this rule does not add a nonzero-key requirement. The ABI is bounded
to 45 identities and permits an empty set. Tests cover every duplicate pair up
to that bound plus random byte identities, malformed shapes and null inputs.

The same bounded identity adapter supports `AbsentIdentities` for direct-price
conversion fields and `IsolatedIdentity` for the successor domain. Isolation only
compares the first identity with the rest; duplicates among the remaining domains
stay valid. Empty absence/uniqueness sets pass, while empty isolation fails. The
original distinct-identity ABI delegates to relation mode zero unchanged. Tests
exercise each absent-field byte, all ternary five-domain assignments, invalid
modes and installed static/shared consumers.

Relation mode 3 uses `ProofIdentities`: in list order, a zero identity returns
1, a collision with a later identity returns 2, and a valid set returns 0.
An early collision therefore takes precedence over a later missing identity.
The loader passes three active roles for direct-price configurations and five
otherwise. All other modes retain their original boolean result codes; malformed
buffers and unsupported modes fail closed. Exhaustive small-domain native tests
compare against the original loop, alongside randomized ABI properties.

`CustodianRegistry` validates five encryption/attestation pairs in row order,
checking absent keys before duplicates in each row. It reuses IdentitySet within
each key role; cross-role equality stays allowed. An earlier duplicate still
precedes a later absent key. Fixed-size native spans retain storage ownership;
the ABI copies two 160-byte buffers only after null checks. Native differential
tests cover all presence masks with duplicate locations and input preservation.

`RequiredIdentities` owns the frozen 45-field presence scan. Public deployment
skips inventory-asset blinder index 44; direct-price mode skips conversion roles
33..38. The ordered native table retains names and field access, while Haskell
returns zero or the first missing one-based index. Skipped fields are never read.
Tests cover every missing position and mode, callback exceptions and invalid flags.

`PhysicalInputs` owns the ordered physical activation admission, skipping the five
private blinder checks only for public deployment. Transaction/configuration
presence and frozen key/domain reads retain their native implementations; callbacks
contain no nested Haskell entry. Exhaustive masks and public projection failures
check short-circuiting, mode exclusions and unchanged diagnostics.

`SpendScan` selects at most one singleton input across transactions, or rejects any
successor spend in a suffix. Native readers only count matching input outpoints;
Haskell owns multiplicity, selection and transaction-level short-circuiting. Two
matching inputs in one transaction still reject. Reads do not invoke other Haskell
adapters. Authority checks and root assignment stay between the two scans, so a
late successor rejection preserves the original partial output. The native count
reads the entire current transaction (pure outpoint comparisons), but no later
transaction is read after rejection. Invalid ranges and callback exceptions leave
the selected output unchanged; empty scans clear it. End-exclusive Word64 ranges
cannot overflow at maxBound. Differential tests compare independent input loops
and cumulative counts; public header tests cover duplicate and chained spends.

`TransactionShape` reuses the ordered phase validator for transition input/output
presence, deployment/genesis linkage and issuance admission. Each native read is
guarded by the preceding Haskell checks (including first-input and explicit-value
access). Issuance verification stays in native VerifyPublicBondDeployment or
VerifyBondIssuance; neither currently enters Haskell. This callback contract must
be preserved if those verifiers are migrated later. Native errors and crypto call
ordering are unchanged. Exhaustive predicate masks, exception positions, invalid
phases and synthetic public-entry deployment failures check these boundaries.

Additional phases cover authorized deployment outputs, confirmed UTXO ordering and
the exact derived genesis singleton. Public outputs skip the private inventory
opening read entirely; the other fifteen facts keep the same indexes. Script
derivation, hashing and confidential-pair verification remain native with no nested
Haskell entry. Coin lookups stay outside the callback in their original order.
All predicate masks and exception positions are checked. An in-memory explicit
issuance/genesis fixture covers successful projection plus output substitution,
missing/spent state, confirmation ordering and derived-state mismatches; it does
not claim signature verification or production activation qualification.

`GenesisFunding` owns the fixed FundingStateV2 genesis encoding: version, causal
oracle band, expiry, initial rate/open interest and eight empty sampling buckets.
It uses the standard ByteString builder's big-endian words. Native tagged hashing
and optional encoded-output publication remain unchanged. The ABI requires an exact
725-byte buffer and rejects invalid capacity/null pointers before writing. Tests
compare an independent byte oracle over random Word64 inputs, boundary vectors,
buffer canaries, the existing Rust-derived root vector and the public projection
fixture. This moves the fork-specific format itself, not only admission ordering.

`GenesisState` encodes the 242-byte bond state and 1713-byte private ExchangeStateV2
using one checked adapter. Bond inputs are four raw hashes; private inputs are eight
raw hashes followed by the fixed bond/funding encodings. Haskell owns versioning,
fixed supply, field ordering, empty counters and repeated root placements. Native
hash construction stays unchanged. The adapter validates hash count, null members
and body sizes; the ABI validates both buffer sizes before reading/writing. Random
byte oracles, native boundary vectors and the existing independently derived roots
cover serialization; installed consumers cover both codec modes. The obsolete native
128-bit-zero append helper is removed.

The same ABI adds covenant mode: eleven raw hashes and a height produce the exact
468-byte genesis covenant preimage. `GenesisCovenant` owns its version, zero sequence
and counters, repeated inbox/empty roots and final height. Native SHA256 remains
unchanged. A named native `GenesisCodec` replaces the earlier private-state boolean;
ABI modes zero/one keep their encoding and mode two is covenant. Invalid modes,
lengths and pointers reject before buffer access.

Tap leaf/branch modes share that adapter for their 34/64-byte preimages. Haskell
owns the leaf version/length prefix and branch ordering over raw serialized bytes,
never arithmetic uint256 order. Genesis, incremental successor and staging rendering
reuse native tagged-hash helpers around these codecs. State-node SHA256 uses one
small native streaming adapter instead of duplicate temporary vectors. Genesis script
construction now occurs immediately before its admission call and passes only its
boolean result as the first fact; this preserves ordering without reentering Haskell
from a callback. Tests cover all byte versions, equal/reversed branches, adversarial
byte positions, random payloads, canaries and existing full rendering vectors.

`Checkpoint` reuses ordered admission for the bundle hash, prior-height and
active-chain checkpoint checks. Its eight lazy native reads preserve lookup
timing and short-circuit before any absent parent/checkpoint is dereferenced.
Native callback exceptions are rethrown before changing the diagnostic. Hashing,
chain-index lookup, M6 parsing and PXST construction retain their native boundaries.
Tests cover every predicate combination, exception at every read and public
envelope rejection for missing parents, invalid heights and altered checkpoints.

Native integer decoding reuses upstream `ReadBE32/64` and `ReadLE16/32/64`.
The native M6-envelope encoder also reuses `WriteLE32` for its fixed-width height
and size fields. Its exact script bytes, size rejection and input preservation
are checked against the previous encoder at payload and integer boundaries.
Local big-endian readers, the cursor loop and withdrawal-envelope endian loops
were removed (26 production lines). Existing bounds, offsets and CompactSize
canonicality remain unchanged. These are upstream codec primitives, not new
Haskell policy. Unaligned differential tests and exchange fixtures cover reuse.

The scalar operations own three previously C++ rules:

- Authenticated peg-in depth arithmetic (including the six-confirmation boundary).
- Exact four-byte treasury script recognition for NOP5/NOP8 and slot extraction.
  `TreasuryMatch` reuses that decoder and owns expected-slot bounds/equality.
  Its deferred read is never evaluated for an expected slot outside 0..255.
  The byte-span ABI rejects non-four-byte or null input without reading it;
  decoding uses existing little-endian helpers without alignment assumptions.
  The legacy extraction API and its output-on-success contract remain intact.
- Withdrawal burn/fee validation and payout calculation.

Native withdrawal construction and validation now also lives in `Withdrawal.hs`:
canonical burn scripts, explicit-asset/value and empty-proof requirements, M6
burn references, complete blinded M6 templates, replay-context matching, and
bounded legacy-frame preflight. `drivechain_withdrawal.cpp` contains object/byte
adapters and uses upstream transaction serialization, deserialization and hashing.
The 1..128-byte destination limit and all wire encodings remain unchanged.

`Deposit.hs` recognizes the six-item historical, eight-item native and eleven-item
deterministic witnesses, including their different amount-encoding rules. It also
owns deposit input/recipient policy: one recognized peg-in, no mixed legacy peg-in
or issuance, valid native destination, and exactly one recipient receiving the
full explicit pegged amount. Ordinary wallet inputs/outputs may sponsor fees.
Witness recognition is not deposit authentication: proof, CTIP, confirmation and
replay checks still run separately.

Authenticated deposit transaction checks now also use a `Validation` instance:
input/witness identity, explicit credit/fee outputs, destination, and conservation.
C++ projects upstream object fields into a bounded two-output adapter. Haskell
preserves error priority and sums amounts as `Integer`, so malformed values cannot
overflow a signed 64-bit accumulator. Proof/CTIP authentication is still separate.

Deterministic v2 evidence shape, field bounds, transaction identity, sequence
transition and header count are now Haskell rules too. Synchronous C++ callbacks
still use upstream transaction/hash and sequence/header deserialization. Rejected
evidence no longer publishes partially decoded output fields. Inclusion rules now
also require the exact outpoint, one matching Merkle leaf, the committed first
header, and an ordered, valid-PoW header chain. Upstream C++ supplies Merkle/hash
results and a lazy header callback; Haskell stops at the first invalid header.
CTIP rules require the historical treasury script, one prior-CTIP spend, and an
exact positive increase equal to the authenticated witness value. Native codecs
remain in C++. Historical NOP5 evidence is not
reinterpreted as NOP8.

Destination selection now scans through a lazy native GetOp/address-decoding
adapter: Haskell requires exactly one valid, nonempty OP_RETURN push with no
trailing script, preserves nonminimal PUSHDATA1/2/4, skips invalid addresses,
and stops at the second valid destination. Selected outputs are published only
after the complete scan succeeds. Both immutable checkpoint records and exact
transaction/outpoint lookup live in Haskell; C++ decodes their fixed 136-byte
private ABI records with upstream DataStream. Historical witness-value and
destination-validity rules use a separate Validation instance, preserving error
priority. Native tests compare both records against the former constants and
upstream serialization byte-for-byte. No checkpoint identity was changed.

Persisted CTIP validation is also a Haskell rule: explicit zero-valued native
state coins, push/DROP/FALSE script shape, exact decoded payload/marker, non-null
outpoint, positive treasury value and nonnegative sequence. C++ retains upstream
GetOp and DataStream decoding in a synchronous callback. Rejections leave the
caller state unchanged, and existing nonminimal outer pushes remain accepted.
State-presence, corruption, stale-state and parent-anchor decisions now use
`DepositStateRule`. Eight ordered phases preserve checkpoint overwrite rejection,
prior-state matching, connect/disconnect checks and immutable parent anchoring.
Native orchestration still reads/serializes/writes upstream coin objects and
projects their equality; no callback re-enters Haskell. Disconnect checks current
state before parsing evidence, while verification and connect parse first.
Live evidence network/genesis/challenge/synchronization decisions, deposit-block
confirmation/hash/height checks, unspent confirmed CTIP value checks, and CTIP
sequence/outpoint consistency now use `LiveEvidence`. Haskell requests native
JSON fields lazily, preserving error order and short-circuit parsing. These readers
use preloaded responses, not RPC or network I/O. C++ catches every callback
exception in an exception_ptr and rethrows only after returning from Haskell;
non-std RPC amount errors retain their original exception type. The same rule
now scans sidechain declarations and deposit events: exact slot/title/hash
identity, activation height, unique matching outpoint, positive exact value,
nonnegative sequence and valid destination. Native adapters only parse requested
fields; malformed later entries still reject an earlier match. Callback buffers
are released before traversal continues. State encoding/storage orchestration
and event normalization remain to migrate.

`PegEvent` now owns withdrawal lifecycle selection, normalized deposit numeric
bounds and the withdrawal status fold. Exactly one non-null lifecycle field is
required before checking its object type; terminal status wins over submitted
regardless of order, and conflicting terminal events fail. Native JSON decoding,
event rendering/deduplication and bundle matching remain adapters/orchestration.
Normalization deliberately retains nonnegative Int64 vouts rather than imposing
the stricter authenticated-outpoint Uint32 bound. Live-evidence readers now expose
raw output indexes before subsequent parsing and decoded address bytes in bounded
four-byte batches. Haskell enforces Uint32 bounds, nonempty printable addresses,
and only then requests upstream destination decoding. C++ hex parsing remains
upstream and rejects malformed/empty hex before those checks. No callback calls
a Haskell export recursively; the removed native helpers have no fallback.

`Bmm.hs` owns parent-state shape and historical BMM header-commitment checks.
State validation preserves interval truncation, period boundaries and the exact
11-timestamp requirement. Header preflight preserves native replay rejection,
genesis behavior and immutable checkpoint identity before native activation
configuration is read; a second phase checks required signalling/commitment.
Native Elements still uses its frozen parent replay, not historical signet proofs.
Proof envelope/entry bounds, canonical coinbase shape, exact Merkle membership,
header extension facts, final-parent and critical-hash binding, block proof bytes
and prior-state identity now use the same Haskell module. Native parsing and
hashing run only after their size/shape preflights succeed, preserving short
circuit order and error priority. Rejected proofs leave next_state unchanged.
M8 and sidechain-parent commitment selection now share Haskell traversal,
shape/domain/slot rules and duplicate rejection. The native callback only
projects upstream GetOp results and bytes; native uint256 conversion preserves
the distinct hash byte orders. Callback failures cannot cross the FFI, and native
exceptions are rethrown after Haskell returns. No callback or borrowed pointer
escapes the synchronous call. Non-minimal push encodings remain accepted exactly
as before; this is not a script-policy change.
The same scanner selects the last raw witness-commitment prefix for signet
validation (kind 2), without applying GetOp validity or M8 duplicate policy.
Native projection supplies only script size and six prefix bytes. Missing witness
outputs preserve the caller's error string; multiple witnesses are not an error.
Retarget scheduling and signed timespan clamping, including the off-boundary
short circuit, and upper-middle median-time selection also live in Haskell.
Upstream arith_uint256 compact conversion, fixed-width scaling and target-cap
arithmetic remain native, preserving their exact arithmetic semantics. Invalid
ABI intervals, overflowing clamp parameters and empty median arrays fail closed;
valid consensus parameters and authenticated eleven-timestamp states are unchanged.
Activation decisions now use a native/genesis preflight before configuration or
ancestry access, followed by private-height or public-checkpoint/version rules.
Private configuration errors retain their exact messages. Proof-of-work target
facts are checked in Haskell before native header hashing; compact decoding,
256-bit comparisons and hashing remain upstream adapters. No activation height,
checkpoint or proof-of-work limit is changed.
Signet solution extraction/clearing is now a post-Refl operation combining
`ScriptStream` and `ScriptRewrite`. Its generic helper selects only the first
matching payload, retains the four-byte prefix, re-emits pushes/opcodes, and
publishes only after the upstream cursor reaches the end. Native callbacks retain
GetOp, byte slicing and CScript serialization, including existing empty-push and
failed-GetOp-at-end behavior. Native exceptions are contained and rethrown after
the synchronous FFI returns; partially extracted solution bytes keep their prior
failure behavior. No callbacks perform RPC or reenter Haskell.
Signature preflight (witness-v0, nonempty signature and valid input index) and
the BIP143 hash-component plan now live in Haskell. The native writer consumes
bits for prevouts, sequences, all outputs or one output, preserving unknown base
types, ANYONECANPAY and out-of-range SINGLE's zero output hash. Serialization,
SHA-256, public-key parsing and ECDSA verification remain upstream adapters.
Signet validation uses a pure `SignetValidation` transition rule through the
shared `Check` interpreter. Positive results select the next native action,
zero accepts, and negative results preserve six domain errors; -7 is an ABI
fault. Native actions retain Bitcoin transaction construction, deserialization,
Merkle replacement and cryptography. Merkle shape rejection precedes original
coinbase hashing. Empty solutions skip decoding, while malformed and trailing
data remain distinct. Every transition returns before its native action runs,
so script extraction and signature checking may safely call their own Haskell
rules without runtime reentry.
`Codec` validates proof serialization size, decode preflight/schema/count,
canonical reserialization and attachment eligibility. It also validates
persisted-state asset/value facts, each script opcode and the decoded payload
marker/end condition. Upstream serializers and GetOp remain native. Each script
guard precedes reading the next opcode; payload validation precedes state
validation. Existing partial decode writes, non-minimal pushes and payload
diagnostic precedence are retained.
`Traversal` selects proof-entry actions, optional signet verification, entry
advancement and final parent/commitment/critical-hash validation. It uses the
shared `Check` interpreter without adding a callback into Haskell. Native code
executes an action and returns its result; only a successful terminal result
publishes the accumulated state. Existing detailed errors win over the extension
fallback. The last entry's coinbase alone supplies the M8 commitment, as before.
`Advance` now owns the parent's numeric state update: Word32 height wrapping,
header time/bits, eleven-entry rolling history and retarget-period boundaries.
The fixed-width ABI uses sixteen Word32 fields, validates its count/pointer and
fully evaluates the result before writing. Native code only projects/assigns
fields and computes the upstream header hash. The outer proof wrapper reuses
`Traversal` for bounds, commitment hashing, decoding, prior-state identity,
parent extraction and entry verification, preserving lazy error order.
`StateSource` selects persisted state or checkpoint fallback: native Elements
rejects the historical namespace before reading it, persisted-state corruption
cannot fall back, and the public checkpoint precedes private test configuration.
Native reads, immutable checkpoint data and compile-time private isolation stay
in C++. `Lifecycle` now selects connect/disconnect branches and write eligibility:
native-state exclusion, checkpoint overwrite/removal, required/incomplete proof
handling, missing/corrupt rollback state and verified prior-state restoration.
Detailed errors retain priority over the generic rollback diagnostic.
`StateFlow` now selects connect/disconnect read, verification and write actions.
Rollback parent extraction, entry verification and current-state comparison are
separate actions; failed verification reaches the existing diagnostic fallback
without selecting a write. Unexpected phases or positive replies are ABI faults.
Native code performs only the selected action through a safe callback. Remaining
low-level storage helpers are still in scope. No checkpoint or activation policy
was changed.

`StateExecution` now owns RunBmmStateFlow's loop, including the enclosing native
ConnectBmmState and DisconnectBmmState sequences. It invokes the existing
StateFlow method directly after one outer Check dispatch. Callback replies retain
the full signed int32 range, including negative domain results; INT64_MIN is an
out-of-range exception sentinel, never a valid reply. The appended bmm_state
handler returns 0 for success, 1 for domain rejection and -1 for an adapter fault.
The native wrapper retains its exact failure diagnostic and rethrows captured
exceptions with their original identity. No rollback or new retry policy exists.

Callbacks are synchronous, safe and bound to the originating native thread; they
may invoke existing Haskell-backed subworkflows without retaining objects beyond
the call. Native code retains coin/proof ownership, diagnostics, hashing and
storage operations. The per-step API and every state number remain unchanged.
Native tests compare 7,488 complete signed traces/results/exceptions with the old
runner. Properties also compare direct and ABI workflows with the frozen native
connect/disconnect oracle, including write attempts, signed boundaries, null
callbacks, unknown phases and 100,000 nonce iterations. Private construction and
persisted decoding also use the shared runner. Decoding tracks the last action
only to preserve its native exception boundary: script-stage exceptions escape,
while marker/state/payload/validation exceptions become the existing codec error.
Partial deserialization writes are not rolled back. Tests compare all seven
actions with false replies and exceptions before/after mutation, in addition to
real truncated/malformed payloads.

`ProofExecution` owns the enclosing signet solution, proof-entry and block-proof
loops. One appended bmm_proof handler shares their callback transport without
adding an export. The four unsigned 64-bit reply fields are zeroed before each
callback; traversal uses the first two. Callback status 1 means a complete reply,
not domain acceptance. Invalid kinds, phases, callback statuses and Haskell
exceptions fail closed with INT32_MIN; the native wrapper retains each protocol's
existing diagnostic. Existing per-step methods and ABI numbers remain available.

After one outer Check dispatch the workflow calls SignetValidation or Traversal
methods directly. It preserves negative domain outcomes, lazy action selection,
native exception rethrowing and the native thread during nested Haskell calls.
Traversal's PUBLISH_ENTRIES action is terminal: its reply is not a new acceptance
gate after next_state has been assigned. The signet DECODE action still catches
its local stream errors and supplies status 2; those are domain rejections, not
outer callback faults. Traversal's fallback diagnostic only fills an empty error.
This migration is not completion of all BMM adapters or the broader fork/ports.

`StateWrite` carries `StateReplacement`; after payload `Refl`, its generic helper
calls clear, prepare and publish methods in that order. Publication clamps a
negative signed height to zero. The native bridge collects the three commands in
a bounded stack buffer; its Haskell callback performs no storage or user effects.
Only after the interpreter returns successfully does the bridge run the commands.
Native actions retain coin construction, serialization and CCoinsView primitives.
An action exception propagates directly and stops subsequent steps, preserving
spend-before-encode and no rollback on prepare failure. Preparation can now invoke
another Haskell-backed operation without callback reentry; regression coverage
exercises this alongside every injected failure position. The direct FFI callback
contract is unchanged.

`StateEncode` carries `StateAssembly`; after payload `Refl`, its generic helper
selects marker serialization, parent serialization, payload push, DROP and FALSE.
It reuses the command transport and bounded native plan runner, while native
DataStream/CScript primitives retain upstream byte encoding. The interpreter
chooses protocol ordering and terminal opcodes, not a parallel serialization
implementation. The immutable checkpoint script is tested against an independent
wire vector; native action failures stop without executing later primitives.
`StateSource` also controls the persisted-state presence gate and decode-result
propagation. Missing state never decodes or modifies caller output; successful
reads retain caller diagnostics; failed decoding copies its diagnostic only when
an error destination exists. Presence deliberately does not imply validity.
Native GetCoin/AccessCoin and exact COutPoint equality remain upstream primitives.

Serialization boundary audit: `BmmL1State`, `BmmProofEntry` and `BmmProof` in
`drivechain_bmm.h` are native data/schema declarations using upstream READWRITE.
Their serializers have no conditional policy. They are reused by SerializeValue,
DeserializeExactly and persisted state; replacing them with a second Haskell
byte codec would duplicate the explicitly retained native serialization layer.
Canonicality, limits, validation and state-script assembly are Haskell decisions.
Signet preimage ordering and private proof-construction policy are procedural
behaviors, covered by the migrations below rather than this schema exemption.

Private proof construction now uses the existing `StateFlow` interpreter for its
enable/validation gates, coinbase/header construction sequence, PoW retry loop,
proof publication and final verification. Each native action finishes before the
next interpreter call, so validation and timing helpers cannot reenter Haskell.
As before, disabled/invalid requests do not publish a proof; final verification
failure occurs after publication. The nonce loop retains its original unbounded
retry behavior. `PrivateTemplate` now uses the shared Check/Validation adapter to
select coinbase/header versions, successor height, timestamp and M8 payload.
Word32 successor arithmetic wraps before timestamp comparison, and the slot is
narrowed to one byte, matching the original native code. Critical-hash bytes are
reversed from uint256 storage order, matching ParseHex(GetHex()). Native object
assignment, difficulty calculation adapters, hashing, Merkle construction and
serialization remain native primitives. Passing a
private syntax check does not qualify the linked private builder at runtime.

Private-flow evidence (`bmm-private-flow-*`): 59 properties/590,000 cases,
34 focused BMM tests/7,797 assertions, 923 native tests/20,039,477 assertions,
three runtime gates, installed static/shared isolation consumers and private
syntax all pass. The independent imperative model checks zero through 100 nonce
retries and failures before construction or after publication. Native template
fields were still native at that historical stage; linked private-runtime
validation remains explicitly outstanding.

Private-template evidence (`bmm-private-template-*`): 60 properties/600,000 cases,
39 payload types/1,521 dispatch pairs, 35 focused tests/7,815 assertions and
924 native tests/20,150,302 assertions. Three runtime gates, installed static and
shared isolation consumers, private syntax and diff checks pass. Canary buffers
and null-pointer faults preserve output boundaries; native GetHex comparison and
Word32 edge cases cover byte order and overflow. Linked private-runtime and
cross-platform qualification remain outstanding.

`Preimage` uses Check/Validation to select ordered witness-v0 signature fields
or modified signet-header fields. Both reuse the bounded native action runner;
HashWriter/VectorWriter perform upstream serialization only after Haskell has
returned. Invalid kinds never invoke a writer, and exceptions stop subsequent
fields. Signature hash-mode selection remains in the existing Signature rule.
`SignatureBytes` now selects the trailing hash-type byte and retained prefix
length through Check/Validation. The ABI leaves the input untouched and publishes
the length only after successful evaluation. Native code resizes the copied
signature using that length, after its existing CPubKey validity check. Empty or
invalid pointer/count calls fail without output mutation. No DER interpretation
or crypto implementation is duplicated in Haskell.
`SignetTemplate` selects the synthetic transaction version, locktime, sequence,
zero amount and script opcodes through Check/Validation. Native code constructs
the one-input/one-output objects and supplies the challenge script, using those
values. `SignetActions` now orders assembly and scriptSig/witness decoding via
the shared bounded action runner. Native effects execute only after Haskell
returns; parser exceptions retain the original partially decoded transaction.
Count/null guards and buffer canaries cover the fixed six-word template ABI;
action traces and injected failures cover both sequencing plans.
Signet-action evidence (`bmm-signet-actions-*`): 64 properties/640,000 cases,
43 payload types/1,849 dispatch pairs; 37 focused tests/9,029 assertions;
926 native tests/20,164,591 assertions. Three runtime gates, installed static
and shared consumers isolated from GHC/buildtree, private syntax and diff checks
pass. This does not qualify a whole private-catalogue node or other platforms.
`CommitmentBytes` owns extraction of a selected commitment payload: M8 removes
its five-byte prefix and reverses the 32 displayed-hash bytes; parent commitments
retain their 32 native bytes. Native GetOp and uint256 construction are unchanged.
The selection rule still validates the script before extraction. The bounded ABI
forces the complete result before writing and leaves outputs untouched on faults.
Randomized reference comparisons cover both byte orders, input immutability,
invalid kinds/lengths/nulls and output canaries; native tests compare with the
previous uint256S(HexStr(...)) conversion, not merely the new helper.
Commitment-byte evidence (`bmm-commitment-bytes-*`): 65 properties/650,000 cases,
44 payload types/1,936 dispatch pairs; 37 focused tests/9,033 assertions;
926 native tests/20,163,143 assertions, three runtime gates, isolated installed
static/shared consumers, private syntax and diff checks pass. Earlier seals
remain historical after this source and installed-artifact update.
Signet-template-value evidence (`bmm-signet-template-*`): 63 properties/630,000
cases, 42 payload types/1,764 dispatch pairs; 37 focused tests/8,969 assertions;
926 native tests/20,166,140 assertions. Runtime gates, installed static/shared
isolation consumers, private syntax and diff checks pass. The authentic signed
successor remains valid; this is not a whole-private-node qualification.
Signature-byte evidence (`bmm-signature-bytes-*`): 62 properties/620,000 cases,
41 payload types/1,681 dispatch pairs; 37 focused BMM tests/8,968 assertions;
926 native tests/19,827,389 assertions; three runtime gates and installed
static/shared isolation consumers pass. Native tests cover all 256 hash-type
bytes and the authentic signed successor; private syntax passes only for this
latest source (the prior linked-private executable is historical).
The authentic signed L2L successor fixture exercises both preimage paths end to
end; this is separate from the still-pending linked private-builder validation.

Preimage evidence (`bmm-preimage-*`): 61 properties/610,000 cases,
40 payload types/1,600 dispatch pairs, 36 focused tests/7,942 assertions and
925 native tests/19,922,083 assertions. Three runtime gates, installed static and
shared isolation consumers, private syntax and diff checks pass. Writer failures
and invalid-kind short-circuiting are covered alongside the authentic successor.

The persisted-read stage (`bmm-state-read-*`) passes 58 properties/580,000 cases,
33 focused tests/7,780 assertions and 922 native tests/19,890,575 assertions.
Three runtime gates, installed static/shared isolation consumers and private
catalogue syntax pass. The latter is not linked private-runtime qualification.
The node remains local and the full fork migration remains incomplete.

The state-encoding sequence stage is qualified by `bmm-state-encoding-*`:
58 properties/580,000 cases on both the pinned library and isolated v0.1.1.0;
38 payloads/1,444 dispatch pairs; 33 focused BMM tests/7,743 assertions;
922 full native tests/20,235,820 assertions; three FFI/runtime gates; rebuilt
installed static/shared consumers with GHC/buildtree inaccessible; private
catalogue syntax only (not private linked/runtime qualification). The checkpoint
wire vector is unchanged. No live service or dependency pin was changed.

`Timing.ParentMedian` reuses median calculation but rejects a zero result for
authenticated parent contexts. Its versioned ABI distinguishes domain rejection
(-1) from adapter faults (-2); the general median operation still accepts zero.
Native code validates state before this call, clears the output context first,
and only publishes its hash, height and median after acceptance.

`FingerprintRequest` carries `FingerprintSource`; after payload `Refl`, its
interpreter calls the generic `fingerprintPayload` helper. Haskell owns v4 field
ordering, integer widths, length prefixes, mandatory public checkpoint and
optional private checkpoint encoding. Native callbacks only project values:
group 0 is the scalar table; group 1 the blob table; groups 2/4 contain public/private
state fields (height, time, bits, period height/time, history count); groups 3/5
contain their timestamp histories. Blob indices 8/9 are the state hashes.
Byte pointers are borrowed only for a synchronous read. Callbacks must not reenter
Haskell. A complete, evaluated payload reaches the writer once; rejected input
does not publish a partial payload. Native exceptions are retained and rethrown
after returning through the FFI. Native SHA256 and its frozen namespace tag stay
in the hash adapter. Public mode never reads private-state fields.

The private `elements_hs_fingerprint_v2` ABI replaces the BMM-only v1 symbol;
native and Haskell libraries must be rebuilt together. Profile 0 preserves BMM
v4 encoding. Profile 1 selects `EncodeFingerprint ExchangeFormat` on the same payload
and capability, moving exchange v9 field ordering, widths, length prefixes and
private-height normalization into Haskell. It reads 39 scalar slots and 63 blob
slots (the last scalar is skipped in public mode). C++ supplies borrowed fields,
build flags, and upstream witness transaction serialization; tagged hashing stays
native. Unknown profiles fail before callbacks or output publication. This is an
internal ABI change, not a consensus format or network activation change.

Both formats share one GADT constructor and one payload type check. After Refl,
encodeFingerprint selects the generic layout workflow, then fully evaluates all
output bytes before returning to the FFI writer. Layout-specific helpers do not
publish output. A poisoned-byte source checks this evaluation boundary in both
formats; mismatched payloads still avoid evaluating either source or format.

Runtime settings use admission phase 15 on the existing guarded-read ABI.
Haskell combines checkpoint/activation flags and enforces build, network, paired
arguments and height priority. With neither private flag set, only those two
flags are read; invalid build/network/pair combinations never read height.
Native code retains the argument lookup, signed-height range projection and
final output publication. No callback in this path reenters Haskell.

Activation settings use phase 16: all nine presence flags are read in original
order. With none set, activation is absent and no network lookup occurs. Otherwise
network admission precedes the all-eight-required check; the ninth flag (bond V2)
is optional. The native loader retains individual value parsing and optional
bond setup. The dedicated adapter interprets absent/configured results separately
from guard errors; this phase is not a transaction-shape boolean result.

The BIP341 NUMS key and frozen V18 staging-renderer domain are owned by
BmmConstants.exchangeIdentities and emitted into exchange_constants.h during
configuration. Width is checked by the generator. Native tests freeze both byte
strings and independently hash the renderer-domain text. Native comparisons use
the generated constexpr arrays without runtime FFI, including inside callbacks.
The NUMS key must not be replaced by an operator-selected key with a known
discrete logarithm, which would permit a key-path bypass of the covenant leaves.

The same generator owns the finite/successor bond-inbox hash domains through
`bondInboxDomains` and `bondInboxCustodyDomains`. Native callbacks select the
Boolean profile and hash bytes with the existing cryptographic primitives.
All 26 labels, including custody tree suffix placement, are frozen against
the previous native construction; changing a label changes its commitment.

ConfigurationField owns raw/display hash, outpoint, spendable-script and bounded
frozen-configuration hex parsing. Configuration hex accepts at most 131072 hex
characters (65536 bytes), allows zero bytes and OP_RETURN bytes as data, and
rejects empty, odd, non-hex or oversized input with the original syntax error.
Its ABI rejects oversized input before copying. The existing script mode retains
its independent 10000-byte spendability limit.

Bond activation settings use transaction-shape phase 17: first the explicit
enable flag, then 36 required arguments, then three grouped requirements.
BmmConstants defines the argument names and generates the native lookup table.
Haskell stops at the first false result; the native adapter preserves lookup
exceptions and maps the result to the original diagnostic. This callback only
reads arguments and must not invoke Haskell recursively. Catalogue freeze
enforcement still precedes the workflow in the native loader.

HybridOracleProfile decodes the fixed 221-byte oracle record, checks version and
four exact nonzero Truthcoin identities, and reuses HybridOracleBounds for all
numeric policy. Its one ABI returns the two price values only after validation;
rejection leaves both outputs untouched. The outer native decoder retains the
same diagnostic, direct-price check, and crypto checks. Byte mutation tests use
an independent fixed-offset native reference and boundary confirmation counts.

TruthcoinProfile decodes the adjacent 390-byte authentication record. It checks
all nonzero fields, version, slot byte, confirmation count and proof bound, then
returns five raw hashes and a big-endian confirmation count. It shares
elements_hs_exchange_frozen_profile_v1 with the oracle decoder (modes 1 and 0).
The short-lived oracle-only export was replaced, not retained. Oracle prices
are also encoded big-endian over this ABI. Both modes publish only on success;
all native decoder callers discard failed decoded state.

The same frozen-profile ABI handles CheckpointProfile modes 2 (USDD) and 3
(Truthcoin anchor), each 73 input bytes and 64 output identity bytes. USDD
requires distinct nonzero identities and age in 1..1123200. Anchor requires
nonzero identities and age, with its authority different from the supplied
policy asset; it deliberately has no USDD age cap or identity-pair inequality.
Native differential tests cover those asymmetries and output preservation.

IdentityProfile extends frozen-profile modes with base identities (4, 178 input
bytes/161 output bytes) and availability (5, 71/64). The supplied expected
market/scheme is copied before validation. Base permits versions 5/6 and requires
all five identities nonzero. Availability binds the exact scheme, threshold 3,
registry size 5 and 16 MiB bound. Typed native adapters share one checked FFI
transport; native scheme hashing still uses the existing upstream hash helper.

MatcherProfile (mode 6, 85 bytes) consumes a strict boolean signer-validity
result from the native XOnlyPubKey implementation. Haskell checks version,
sequence, receipt and six-block inclusion constant and returns the receipt.
AccumulatorProfile (mode 7, 100 bytes) returns three identities after checking
nonzero fields, distinct forced/deposit domains and the 1..64 limit. The vault
hash is not required distinct here. Neither mode introduces a callback or export.

FrozenTail (mode 8, 260 bytes) validates inbox limits, six version-dependent
conversion identities and recursive-proof/bond constants in that order. It
reuses FrozenBounds, returning distinct error codes 1/2/3 and never writing the
ABI output buffer. The native decoder projects its retained bytes only after
success and still checks end-of-input. Direct-price mode requires all six
conversion identities absent; legacy pricing requires each nonzero.

BondProfile (mode 9, 485 bytes) checks fifteen nonzero identities, the generated
renderer and NUMS constants, tapleaf version, distinct process/refund programs,
twelve-block refund delay and the native-computed custody codec hash. Success
returns an empty payload: the ABI never writes its output buffer. Native code
projects the validated record and retains tagged hashing and curve validation.
This reuses the existing export, without callbacks or changes to encoded bytes.

ConfigurationIdentities (mode 10, 1977 bytes) reads the retained configuration
at its canonical field offsets and reuses IdentitySet/IsolatedIdentity. Its
strict Boolean phase selects base or outer checks at their original decoder
positions. Duplicate identities precede policy/cross-role errors. ECX may alias
the policy asset; version six excludes the six absent conversion identities
from outer uniqueness, but retains cross-role isolation. This is a relational
check, not a substitute for the preceding field/profile validation. It writes
no output and removes native pointer-list construction and temporary identities.

Deployment blinder checks share the identity-relation export: public mode uses
AbsentIdentities; private mode 4 requires exactly three hashes in issuance,
inventory-asset, inventory-value order. BlinderIdentities composes isolation
against zero and both inventory values before inventory uniqueness, retaining
the issuance error's precedence. Private inventory nonzero parsing remains at
the argument boundary; this relational rule does not add that requirement.

DeploymentIdentities composes configuration uniqueness, ordered proof identity
validation, nonzero covenant uniqueness, and successor-domain isolation in one
call. Identity modes 5/6 select legacy/direct pricing over exactly 22 hashes:
three configurations, five programs, nine covenants, five domains. Direct mode
ignores the last two programs. Existing ProofIdentities preserves its per-field
missing/collision precedence; subsequent stages run only after it succeeds.
Zero sentinels stay inside Haskell. Native code supplies one fixed identity
projection and preserves the five existing exception messages.

TransactionShape phase 18 owns the loader's eleven deployment-shape gates:
nonempty inputs/outputs, four bounds, three distinct output-index pairs, no
peg-in input, then exactly one issuance. Native callbacks read transaction facts
only; Haskell stops on the first failed check before native indexed access.
The loader keeps its original error rather than using the later physical
deployment/genesis linkage diagnostic. No callback reenters Haskell.

The native TransactionShape::ISSUANCE adapter now uses resumable store flow 151
(EXCHANGE_ISSUANCE). Its eight facts use the shared safe callback,
so issuance-verification actions can call Haskell at this boundary. The
zero-based native reader interface, original error and exception propagation
stay unchanged. Existing raw transaction-shape ABI phase 2 remains compatible
but must not be used directly with callbacks that reenter Haskell. Remaining
verifier migration must still audit its complete outer call graph.

VerifyBondIssuance now uses flow 152 / BOND_ISSUANCE, sharing IssuanceFlow's
short-circuit transition builder with flow 151. Seventeen native actions retain
input/witness bounds, blinder and issuance field checks, entropy/asset derivation,
fixed-supply opening verification, generator/commitment parsing, rangeproof
verification, then lower/upper supply bounds. Crypto stays in native Elements
and secp256k1. Lazy native field access occurs only after the corresponding bounds
actions succeed; failed crypto never exposes its output to later actions.

VerifyPublicBondDeployment uses PublicIssuanceFlow, store kind 153. Its first
23 actions preserve bounds, public-creation, issuance, derived-asset and designated
inventory/burn checks. Actions 24..27 scan outputs, rejecting a bond/token asset
outside its designated index and advancing only after both comparisons succeed.
Asset derivation and field reads remain native; Haskell owns branching and loop
termination. Each output asset is read once, preserving the original scan order.

HasOnlyExplicitCreations uses ExplicitCreationsFlow, store kind 154. Four scans
cover outputs, issuance values, output proofs and issuance proofs in that order.
Null issuance values bypass the explicit-value check; the first failing field
ends validation without reading later fields. Native actions only read fields
or advance the corresponding index, using the shared safe callback so
this check may be nested in the public issuance workflow.
Activation policy is unchanged. Differential transaction tests retain the
previous native implementation as an independent oracle.

ActivationPredecessorFlow (155) orders eight previous-root binding checks and
two covenant-script binding checks. Status 1 preserves the root error; status 2
preserves the script error. Native hashing and script construction run only
after earlier checks succeed, through the safe callback, and may call Haskell.
Input zero is never accessed before the nonempty-input check. Tests cover all
1,024 predicate combinations, action faults and existing activation fixtures.
Genesis, incremental-successor and inbox-staging scripts reuse upstream
GetScriptForDestination(WitnessV1Taproot), whose fixed 32-byte key output makes
the former staging output-shape recheck redundant. Taproot parity tests compare
upstream encoding against the prior manual encoding for 256 tweaked keys.

CapitalContextFlow shares finite (156) and incremental (157) transition context
validation. Both sequence profile/decode, canonical parse, script construction,
then transaction/header/BMM/inbox/matcher checks. `SuccessorBinding` owns the
public-value byte offsets for the predecessor covenant, transaction, previous
exchange root, parent hash, parent height/MTP and incremental sidechain height.
The native adapter passes raw hash bytes and three Word64 values; exact public
buffer sizes, profile and pointers are checked before ABI reads. Finite ignores
the sidechain-height value; incremental skips the finite previous-sequence field. Status 1
preserves decoder errors (or the profile fallback), 2 is a changed-annex error,
and 3 is a context mismatch. Pure field comparisons share action 6, so the
resumable flow has 11 finite or 10 incremental actions. No parsing, script,
snapshot-publication or cursor effect moves across this combined check. Exhaustive
Boolean traces and action faults cover both flows; byte-mutation and randomized
tests compare binding with the prior native checks, including uint64 boundaries,
malformed ABI inputs and the intentionally unbound finite height.
The incremental transaction fixture also exercises the complete projection with
u128 counters, then mutates predecessor, transaction, header, parent and height
bindings individually while keeping the annex canonical.

The native ExchangeHeader wrapper now uses resumable flows 158..160 for
inactive, active and genesis checks (11/8/6 actions). Read indexes remain
zero-based and the error strings, success behavior and exception propagation
are unchanged. Actions may call Haskell through the shared safe callback. The old
raw header ABI remains available for compatibility; its callbacks must not
reenter Haskell. This removes one prerequisite for migrating genesis encoders,
but all remaining callers must still be audited before those helpers move.

Fixed-width inbox genesis preimages now reuse upstream HashWriter serialization
directly: byte arrays and uint256 fields serialize as raw bytes without length
prefixes. This removes temporary concatenation buffers without adding an FFI
passthrough. The four domain/chain and domain/chain/configuration commitments,
both outcome domains and the zero-count queue retain their original hash tags
and byte order. Differential tests cover 256 input patterns and activation roots.

Bond deployment commitment encoding uses existing inbox codec ABI mode 15.
Haskell owns the legacy v2 marker (1), public v3 marker (3), fixed share supply,
big-endian indices and interleaving of six raw hashes. Input is 192 bytes and
output exactly 213; invalid versions, wide indices, shapes or null pointers
fail without output writes. The native entrypoint retains its invalid_argument
exception for unsupported versions. Both frozen encoding/hash vectors and
QuickCheck ABI canaries exercise the format. No new FFI export is introduced.

Fingerprint profile 2 encodes the activation identity record through the shared
FingerprintSource capability after payload Refl. Native code exposes two
upstream-serialized transactions, configuration bytes, 42 identities, the NUMS
key, initialization block and eight numbers. Haskell owns ordering, widths and
the unprefixed legacy layout; hashing stays native. It checks 32-byte identities
and bounded numeric widths before publishing. Both exchange runtime and
activation records share a flat native reader adapter. Tests compare the old
layout, malformed fields, callback exceptions and forced byte evaluation.

CarryIdentities uses identity ABI modes 7/8 for finite/incremental carry-forward
snapshots. Six actual identities are compared with the selected three frozen
profile identities and three shared root/asset/deployment identities. Exactly
15 hashes are accepted; the inactive profile's tuple is deliberately irrelevant.
The native wrapper rejects unsupported profile tags before reading identities.
Snapshot copy timing and the existing error are preserved; appending uses the
existing profile-aware helper. Tests mutate every byte and exercise ABI bounds.

SuccessorScanFlow (161) controls transaction selection and annex preflight.
It skips input/output-empty or root-mismatching candidates, rejects duplicate
matches immediately, and checks witness/stack/nonempty-annex/prefix only after
the scan. Statuses 1/2/3 preserve duplicate/missing/annex errors respectively.
Native hash calls occur outside Haskell. Pointer selection is borrowed from the
unchanged block and used for projection only after a unique scan; no transaction writes.

CapitalIdentity profile 2 reuses the capital-identity C ABI for incremental
activation context. Its 364-byte parsed public values bind six hashes at
offsets 4/36/100/164/196/228 and two BE64 fields at 324/332, alongside the
32-byte program ID. The expected record is exactly 240 bytes. Profiles 0/1
retain their existing layouts. The native adapter projects seven identities
and two uint64 values; Haskell owns the comparisons. Canonical annex parsing,
consumed-coin verification, successor-script checks and snapshot construction
remain separate gates. This relation is not proof verification on its own.
The private C++ adapter now accepts a profile number and optional numeric
context; consumers must rebuild. The exported C signature is unchanged.

CapitalSnapshot consolidates finite, incremental and activation projections in
state-codec modes 8/9/10. Input is ten context hashes followed by the parsed
public values (850/1627/364 bytes). Context order is active root, activation
configuration/asset/deployment, transition program/CMR, inventory script hash,
and activation queue/inbox/outcome genesis roots. Unused fields are ignored.
The scalar arguments supply activation height and execution MTP. Canonical
parsing and identity/context checks must precede this codec; it does not
authenticate arbitrary public values.

Output is existing version-4 BondV2CapitalSnapshot serialization (914 bytes).
Scalars use little endian, hashes retain their bytes and 128-bit arrays stay
big endian. Finite inventory arithmetic retains uint64 behavior; activation
uses fixed supply, zero defaults, coverage 12500 and MTP/28800 funding epoch.
Native code computes existing tagged roots and uses the upstream deserializer,
not C++ object-memory reinterpretation. Tests retain former native assignments
as independent references and compare every serialized byte across all three
profiles, including round-tripping over poisoned snapshots. Bounded ABI tests
cover lengths, null buffers and canaries. No new C FFI export is introduced.

Its shared bounded ABI publishes only complete parsed bytes and distinguishes
syntax, value and adapter errors. Native code supplies the existing messages.
Raw hashes retain order; display hashes and outpoint txids reverse it. Outpoint
indexes preserve ParseUInt32's leading-plus/leading-zero behavior and uint32
limit. Scripts reject malformed hex before OP_RETURN/size checks; oversized
hex is validated without allocating a decoded script. Native differential tests
use upstream IsHex, ParseUInt32, uint256S and CScript::IsUnspendable as references.

Node and wallet callers route through `bridge.cpp`, with no C++ fallback.
Node/genesis identities, commitments and proof programs are unchanged.
`test/reference.cpp` retains the old predicates only as test oracles.

## Class-constrained operations

The node uses only `Control.Operation` and `Control.Operation.Validation`
from [operation-capabilities](https://github.com/freewillydev/operation-capabilities).
Version 0.3 removes preparation pipelines, indexed capability requests, severity
dispatch, typed Flow, variable output schemas and curried capability descriptors.
Keep the tested CMake and Cabal commit pins in sync; there is no local framework copy.

Each custom interpreter calls `withOperation` before inspecting its typed DSL.
Payload equality preserves lazy mismatches; the constructor then supplies the
specific `Context` dictionaries. Ordinary class methods and generic helpers own
behavior. Domain failures stay in `Outcome`; `Nothing` is only a dispatch
mismatch. Packing and selecting an IO action do not execute it.

Wallet bundles use ordinary `ExceptT`: authenticate the anchor, plan the bundle,
construct its bytes, check the transaction frame, then produce wallet transport
framing. Anchor and planning errors remain distinct. Construction exceptions
propagate without being converted to domain rejection.

BMM submission passes the bid explicitly through a recursive `ExceptT` helper.
A replacement is published before the next parent check, no replacement occurs
after the third attempt, and failed/malformed callbacks stop subsequent effects.
Fingerprint selection uses the closed `FingerprintFormat` sum and existing
encoders instead of a second runtime type-selection layer.

The inbox scanner returns a list of the closed `InboxSource` sum: forced input,
deposit input, both in that order, or neither. A normal fold retains lazy parent
validation, overflow checks, work accounting and effect order. Arbitrary output
types cannot enter the list. No existential output schema is needed.

`WithdrawalRequest` declares `[WithdrawalRule, WithdrawalFrame]`. Its DSL
returns a reusable `WithdrawalAction -> Result` function. Each application
checks that action's frame before calling the body; invalid frames retain the
existing ABI fault rather than becoming a domain `Left`. The redundant
preparation/frame pass has been removed.

`Workflow.Finalize` retains associated input/result types for state encoding,
state replacement and signet extraction. Generic helpers require only their
actual capabilities; concrete DSL contexts provide the declared dictionaries
without application descriptors or additional index classes.

The optional `Check` adapter remains for simple Validation rules. Native
callback pointers and returned IO actions remain synchronous and must never
escape their owning FFI call. Existing encodings, errors and exported ABI
signatures are unchanged. Tests retain payload dispatch, lazy requests, deferred
effects, independent effect traces, failure injection and native consensus gates.

Withdrawal action 12 extracts an Ethereum claim from a fixed 116-byte private
request: first index, accepted count, signed explicit value, unit scale, and
maximum amount (five little-endian u64 fields), protocol version (u32), magic
(four bytes), push size (one byte), and the 67-byte script. It returns an empty
payload for a skipped output or 60 bytes containing amount (little-endian u64),
vault (32 bytes), and recipient (20 bytes). Script and amount rejection precede
index overflow; index overflow precedes empty vault/recipient rejection. Native
code retains output-object eligibility, iteration, claim construction and hashing.
The Integer-oracle property checks arithmetic independently of Word64 wrapping.

Accumulator ABI mode 4 applies a packed batch of 32-byte leaves through the
existing Haskell append rule. Unlike modes 0-3, a domain-failure result retains
the successfully appended prefix in the output buffer. Native code advances the
count by the smaller of the leaf count and remaining u64 capacity. An empty batch
preserves state without hashing. ApplyEthereumWithdrawals keeps its prior-state
sanity check and complete claim extraction before this call, and publishes the
optional claim list only after the entire batch succeeds. The batch property
compares sequential appends; the native regression checks partial overflow state
and preservation of the caller's claim list.

Accumulator mode 5 constructs all 65 empty roots in Haskell. The count argument
is the leaf-domain byte and prefix is the node-domain byte; both are checked to
fit u8, and the leaf count must be zero. The output is 65 consecutive 32-byte
hashes. Input state and empty-root contents are not read, so the native cache can
use the same buffer for both pointers. Each digest is produced by the upstream
SHA callback, which must not re-enter Haskell. Native static initialization still
owns caching and thread-safe one-time publication.

`elements_hs_usdd_checkpoint_v1` performs checkpoint state validation and hashing
as a single workflow. Two root/frontier buffers and counts, the empty-root cache,
node prefix, and a profile are passed explicitly. The profile contains a big-endian
u32 version, 32-byte display-order genesis, 32-byte display-order block hash, slot
byte, and remaining domain bytes. Haskell rejects null identities, validates the
prior accumulator before the next, checks monotonic count and coupled count/root
changes, then constructs the committed preimage. Results 1/2/3 retain the native
null-identity/malformed-transition/zero-digest distinctions; failed calls do not
publish output. Native code retains an early null guard, object conversion and
display-to-native digest reversal. This adds one workflow export and reuses the
existing hash callback; it does not add a Haskell-to-native callback interface.

`SignetRequest` similarly carries both `ScriptStream` and `ScriptRewrite` in its
DSL context. `Just Refl` calls `extractSignet`, which has only those capability
constraints, not `Operation` or `Typeable`. A second test stream without an
Operation instance reuses the helper and verifies edit order and conditional
publication. The low-level native rewrite adapter assumes the helper's checked
read/capture/append/publish sequence; it is not a general scripting sandbox.

Post-Refl composition qualification (`refl-composition-*`, October 10): a second
test payload reuses `applyWithdrawal` without an `Operation` instance; rejected
frames cannot execute its body. All 39 properties/390,000 cases, 898 native tests,
and three Haskell CTest gates pass after rebuilding the daemon and consensus
library. The shared library's documented planning example independently passes
80,000 checks, including domain failures and lazy rejection. Documentation/example
changes are local; the node's published library pin and core API are unchanged.
No deployment, installed-consumer rerun, or live lifecycle test is implied.

All FFI entry points use this dispatch. ABI tags, wire encodings, domain
errors and fault sentinels are unchanged. Witness payloads borrow C++ pointers
only for the synchronous call: never queue, cache or retain a request or its
returned IO action beyond it. Node tests retain all-payload dispatch, deferred
effects and consensus/ABI parity checks; framework type tests come from the library.

## ABI and runtime

GHC `foreign export ccall` generates `Drivechain_stub.h` for the C++ adapter.
Versioned export names bind the ABI at link time. Scalars use fixed-width
integers; the withdrawal byte API copies caller-owned input and returns into a
capacity-bounded caller-owned buffer. Neither side retains pointers. Replies
distinguish validation errors from infrastructure faults and the C++ adapter
checks each reply's shape before reading it. Error text is preserved; failed
burn-reference parsing now leaves all output arguments at their cleared defaults.

The byte ABI uses little-endian signed 64-bit amounts and consensus-order hash
bytes. Contexts contain genesis[32], slot[1], burn txid[32], vout[4, big endian].
Its private request envelopes are not network encodings. Operation numbers are
defined by `WithdrawalOp` and dispatched by `withdrawal`; bump the symbol version
before making an incompatible envelope change. The only script grammar interpreted
here is the bounded withdrawal OP_RETURN data envelope, not Script execution.

Deposit exports receive borrowed pointer/length tables. Haskell copies only
bounded prefix fields and invokes a caller-supplied upstream transaction decoder
and hash function for deterministic witnesses. Codec callbacks return 0/1; the
header callback returns PoW/link fact bits (0..3). The persisted-state decoder
returns 0 on decode failure or 8..15 with payload fact bits, filling two Int64s.
The destination v2 adapter reports the first nine-bit GetOp result in action 0
and the second in action 1, with nonempty/consumed flags in bits 9/10 (256 means
GetOp failure). Haskell requests both reads even after a first-read sentinel.
Action 2 decodes a grammar-matching address; action 3 publishes a valid candidate
before duplicate detection. The v1 packed-script export is retired. Faults use -3, distinct
from -1 (missing) and -2 (multiple). Checkpoint lookup returns zero for absence,
136 bytes for a match, and -1 for faults/capacity failure without writing output.
Live readers initialize four Int64 fields per step and return 1 for success or
0 for a retained parse exception; other statuses are faults. Live rule result -1
preserves the parser failure, -2 signals an adapter/runtime fault, and 1..37 are
domain rejections. The native orchestration rethrows retained exceptions outside
the FFI before reporting a rule result.
They must not throw or re-enter
Haskell and never retain pointers. Recipient policy receives
fixed-width flags/amounts derived from upstream C++ objects. Rejection preserves
output parameters and the existing error priority; runtime faults remain distinct.

The threaded RTS initializes exactly once in the shared runtime. It ignores
GHCRTS and command-line RTS options and leaves application signal handlers
alone. Haskell exceptions return distinct fault sentinels; adapters raise a
runtime error rather than disguising an infrastructure fault as an invalid
transaction. The runtime pins itself and its dependencies until process exit;
libconsensus consumers can unload/reload without unmapping live RTS workers.
Daemonization must precede FFI calls. After initialization, a forked child must
exec or exit without entering Haskell or using inherited RTS state.

## Native development build

A native GHC and matching ghc-pkg are required. Production uses base and bytestring.
Override `ELEMENTS_GHC` and `ELEMENTS_GHC_PKG` together when selecting a toolchain.
On first configure CMake downloads the pinned library archive, verifies SHA256,
and compiles its modules into the existing FFI runtime. No second runtime or
machine-local source path is required. Further builds reuse the build-local cache;
offline distributors can pre-populate it via CMake's standard FetchContent source
override. Cabal fetches the same commit as a package dependency for property tests.
The library's LICENSE and NOTICE are installed with each runtime component.

```sh
cmake --build BUILD_DIRECTORY --target elementsd test_elements elementsconsensus test_haskell_ffi test_haskell_loader -j 1
ctest --test-dir BUILD_DIRECTORY -R '^haskell_' --output-on-failure
BUILD_DIRECTORY/bin/test_elements --run_test=validation_tests,drivechain_bmm_tests,drivechain_peg_tests,drivechain_treasury_tests,drivechain_withdrawal_tests
```

`test_haskell_ffi` checks concurrent first initialization, calls and signal
ownership through the actual shared library, including byte-buffer calls and
concurrent C++ transaction-hash callbacks.
`test_haskell_loader` checks repeated concurrent load/init/call/unload cycles.
Run the 33 QuickCheck
properties from this directory with `cabal test elements-haskell-tests:properties --with-compiler=ghc-9.6.7`.
They compare against the old C++ predicates/frame guard, test payout conservation,
six-confirmation boundaries, codecs, noncanonical forms, explicit burns,
M6 context/shape rejection, output-buffer canaries/capacity, and deposit witness
and recipient policy parity. Dispatch tests cover all 324 payload/constructor pairs
(sixteen production types and an effectful test class in two forms), lazy
mismatch rejection without payload evaluation, all 11 withdrawal ABI tags, and
fault sentinels/unchanged output buffers, deferred effects, authenticated deposit
accounting parity, overflow rejection, deterministic evidence/inclusion callback
ordering, CTIP increases, full-width amount boundaries, all state/anchor phases,
invalid phase faults, legacy claims, destination callback ordering, immutable
lookup, bounded checkpoint replies, live evidence field-read traces and parser
faults:
10,000 cases each, replay seed 20261009. Structured shrinkers keep valid input
domains intact. QuickCheck,
random and splitmix are pinned in the Cabal files; these are test-only dependencies.
The pinned library's type tests reject ten ill-typed variants, including missing
dictionaries, duplicate capabilities, undeclared expansion, hidden class use,
coercing capability views and constructing the private envelope. CTest runs these
as `haskell_capability_types` with the selected GHC and build-local temporary files.
The native withdrawal tests independently compare against upstream Script and
transaction encoders for every destination length 1..128 and fee extremes, reject
every truncated M6 frame, and retain the fixed historical transaction/hash vectors.

The full native suite includes the authenticated-deposit adapter regressions.
The optional script vectors are enabled using `DIR_UNIT_TEST_DATA`
pointing to `deps/qa-assets` in the evidence directory. Its `script_assets_test.json`
comes from ElementsProject/qa-assets, Git blob `df73f953463b7788a144471e8da4f8ab49f5548c`;
the separate vector run passes 17,570 assertions. The pre-existing
`elements_startup_validation_tests/native_candidate_parent_bound_script_cache`
fixture failed even in the pre-refactor binary: it used the opt-in branch-5
parent-height jet rejected by the default catalogue. Its replacement uses the
supported native parent-MTP jet and preserves the cache/package parent-binding
test. Program bytes and CMR were checked with the native Simplicity decoder;
no production catalogue was enabled and no test was skipped.

Component installation bundles the linked GHC runtime dependency closure with
relative library paths. On macOS it re-signs relocated libraries. Installed
static/shared consensus consumers passed with toolchain/build-library reads
denied, including concurrent reload and ignored invalid GHCRTS settings.
Static pkg-config flags include the node's dead-code stripping needed by the
two existing Rust verifier archives. This is a static consensus archive with
a shared Haskell runtime, not a fully static executable.

The isolated functional-test node passed foreground/daemon startup, concurrent
read-only withdrawal-verification RPCs through Haskell, and clean shutdown.
Wallets and peers were disabled; no coins or live services were involved. The
installed production node correctly refused absent authenticated parent data;
its full authenticated lifecycle remains a separate qualification gate.
Evidence is under external `haskell-ffi-qualification-20261009`. The earlier
`functional-installed-lifecycle.log` qualifies runtime lifecycle before the deposit
migration. The `pipeline-*` logs and seal qualify the previous unconstrained-stage
and authenticated-deposit implementation (885 native cases). Current capability
type checks and 240,000 property cases pass in `capabilities-types.log` and
`capabilities-quickcheck.log`. Native daemon/libconsensus rebuild, all 886 native
cases (19,887,332 assertions), three Haskell CTest checks and sandboxed installed
static/shared consumers pass in the corresponding `capabilities-*` logs. The
source/artifact seal for that earlier stage is `capabilities-SHA256SUMS`.
Earlier `pipeline-*`, `operation-*` and `deposit-*` evidence is historical;
its source/binary hashes predate this stage.

The standalone-library integration passes all 240,000 property cases, 886 native
cases (20,310,468 assertions), ten library compile-rejection gates and the FFI/
runtime reload checks. Installed static/shared consumers pass with build/toolchain
reads denied. Evidence and the current seal are `library-integration-*`; preceding
source/artifact seals predate removal of the local framework copies.

The deposit-proof stage passes 270,000 property cases, all 144 dispatch pairs,
and all 887 native cases (20,248,473 assertions). Native fixtures cover 22 valid
and malformed proof variants, including nonzero treasury indices and contiguous
multi-header evidence. Three CTest checks, the maximum 2,017-header callback
boundary and installed static/shared proof consumers pass. Evidence is
`proof-rules-*`; the current source/artifact seal is `proof-rules-SHA256SUMS`.
The initial production-binary custom-chain startup attempt correctly rejected
the unsupported network; it is not a production authenticated-lifecycle pass.
The rebuilt non-production functional-test binary passes foreground/daemon
startup, 16 concurrent read-only RPC rejections and clean shutdown in fresh
private directories, with wallets, peers and bidding disabled and toolchain/build
reads denied (`proof-rules-functional-lifecycle.log`). No test processes remain.

The persisted-state stage passes 280,000 property cases and all 169 dispatch
pairs, 19 native codec/corruption variants, and the full 888-case native suite
(19,962,889 assertions). All three Haskell CTest gates and installed static/shared
consumers of the new callback pass. Evidence is `ctip-state-*`, sealed by
`ctip-state-SHA256SUMS`; its source/artifact seal predates the later state-phase
migration and library cleanup. Encoding and remaining authentication rules are
still pending migration.

The state-phase stage passes 290,000 property cases and all 196 dispatch pairs.
Twenty native state/action combinations cover missing, prior, advanced and corrupt
CTIP state; additional fixtures freeze proof-versus-state error order and exact
anchor errors. Failed transitions preserve stored coins. The full 889-case native
suite passes 19,894,979 assertions, all three Haskell CTest gates pass, and installed
static/shared state-rule consumers pass with build/GHC reads denied. Evidence is
`state-rules-*`, sealed by `state-rules-SHA256SUMS`. Earlier source/artifact seals
are historical. This stage did not rerun daemon lifecycle tests; the functional
lifecycle evidence above is from the proof stage. No live services were changed.

The checkpoint/destination stage passes 320,000 property cases and 289 dispatch
pairs. Native fixtures freeze both checkpoint records against upstream encoding,
reject altered checkpoint values, and cover 18 destination variants including
nonminimal pushes, invalid/trailing scripts, duplicate addresses and invalid
addresses before/after a valid one. The full 891-case suite passes 20,215,570
assertions; all three Haskell CTest gates and sandboxed installed static/shared
consumers pass. Evidence is `legacy-rules-*`, with current seal
`legacy-rules-SHA256SUMS`; earlier source/artifact seals are historical. Initial
test compile warnings/type ambiguity and a native hash-pointer type mismatch
were fixed without relaxing compiler checks. No daemon lifecycle was rerun in
this stage and no live services changed.

The live-evidence stage passes 330,000 property cases and 324 dispatch pairs,
including exact reader traces, parse failures, full-width scalar fields and
invalid phases. Native fixtures cover 15 network failure combinations, lazy
confirmation/value reads and preservation of non-std RPC exceptions. All 893
native cases pass 20,131,038 assertions; three Haskell CTest gates and installed
static/shared consumers pass with build/GHC reads denied. Evidence is
`live-rules-*`, sealed by `live-rules-SHA256SUMS`; earlier source/artifact seals
are historical. No live services changed or daemon lifecycle tests ran in this
stage. This seal predates the selection migration below.

The declaration/deposit-selection stage passes 340,000 property cases and 324
dispatch pairs, including scripted traversal parity for results and callback
counts. Native regressions cover error precedence, duplicate matching deposits
across blocks, atomic output publication, null/empty events and 32,000 unrelated
declarations. All 894 native cases pass 19,645,104 assertions. Three Haskell CTest
gates and installed static/shared consumers pass, including both selection phases
with build/GHC reads denied. Evidence is `selection-rules-*`, sealed by
`selection-rules-SHA256SUMS`; older source/artifact seals are historical. The
initial property log predates the callback-buffer lifetime fix; the final log
qualifies it. No daemon lifecycle was rerun and no live services changed.

The event-rule stage passes 350,000 property cases and 361 dispatch pairs, plus
all 895 native tests (20,038,987 assertions). New JSON fixtures exhaust the 27
null/nonobject/object lifecycle combinations and 27 deposit numeric combinations.
Existing order-independent terminal-status and conflicting-event tests pass.
All three Haskell CTest gates and sandboxed installed static/shared consumers
pass. Evidence is `event-rules-*`, sealed by `event-rules-SHA256SUMS`; earlier
source/artifact seals are historical. No lifecycle rerun or live-service change.

The address/outpoint stage passes all 350,000 property cases and 361 dispatch
pairs with revised lazy-reader traces. Native tests exercise all non-printable
byte values at four batch-boundary positions and full-width output-index limits
for both deposits and CTIPs. All 896 native tests pass 20,395,645 assertions;
three CTest gates and sandboxed installed static/shared consumers also pass.
Evidence is `address-rules-*`, sealed by `address-rules-SHA256SUMS`; previous
source/artifact seals are historical. No daemon lifecycle rerun or live change.

The first BMM stage passes 370,000 property cases and 441 dispatch pairs,
including the old C++ state predicate and both header phases. All eight enabled
BMM tests pass, including authentic successor/checkpoint fixtures; the full 897
native tests pass 20,052,271 assertions. CTest gates and sandboxed installed
static/shared consumers also pass. Evidence is `bmm-rules-*`, sealed by
`bmm-rules-SHA256SUMS`; earlier source/artifact seals are historical. A property
variable shadowing warning was corrected without relaxing compiler flags.
Private-catalogue-only activation tests require their separate build and were
not enabled here. No daemon lifecycle rerun, deployment or live service change.

The BMM proof-rule stage passes 380,000 property cases and 484 dispatch pairs.
All nine enabled BMM cases pass 131 assertions, and the full 898-case native
suite passes 19,980,370 assertions. Fixtures preserve failure priority and atomic
next-state output across envelope, state, size, parsing, extension and critical
hash failures. CTest gates and sandboxed installed static/shared consumers pass.
Evidence is `bmm-proof-rules-*`, sealed by `bmm-proof-rules-SHA256SUMS`; earlier
source/artifact seals are historical. Initial native failures were a new fixture
using its unchanged original parent hash; corrected focused/full final logs pass.
No production rule was relaxed to fix it. No private-catalogue/lifecycle rerun or
live-service change occurred.

The BMM commitment-selection stage passes 400,000 property cases and 529 dispatch
pairs, including callback traversal order, duplicate short-circuiting, malformed
adapter facts and absent callbacks. Ten BMM cases pass 173 assertions with real
GetOp handling of direct/PUSHDATA1/2/4 pushes, trailing bytes, truncation, wrong
slots, and duplicate parent/M8 commitments. The authentic successor fixture still
passes. The full 899-case native suite passes 20,095,892 assertions; all three
Haskell CTest gates pass. Evidence is `bmm-selection-*`, sealed by
`bmm-selection-SHA256SUMS`. An initial property build needed an explicit generator
type annotation; the final run passes. No installed-consumer, private-catalogue,
cross-platform or live lifecycle rerun is claimed for this revision.

The BMM timing stage passes 420,000 property cases and 576 dispatch pairs. Twelve
focused BMM cases pass 203 assertions, including full retarget-boundary proofs
with targets independently calculated by the previous native formula. All 901
native cases pass 20,150,484 assertions; three CTest gates and refreshed installed
static/shared consumers pass with the build tree and GHC installation denied.
The installed consumers also cover the preceding commitment-selection exports.
Evidence is `bmm-timing-*`, sealed by `bmm-timing-SHA256SUMS`. The initial property
link failed on a test-only std::vector dependency; the final oracle uses C sorting
and passed without changing production behavior or adding runtime dependencies.
No private-catalogue, cross-platform or live lifecycle rerun is claimed.

The witness-selection stage reuses the existing scanner rather than adding a
second output loop: 420,000 property cases (including callback counts), 576
dispatch pairs, thirteen focused BMM cases/213 assertions, and all 902 native
cases/20,025,379 assertions pass. Regression proofs distinguish first/last valid
and malformed signet solutions, short/wrong/nonminimal witness prefixes and
accepted trailing opcodes. All three CTest gates and refreshed sandboxed installed
static/shared consumers pass. Evidence `bmm-witness-*` is sealed by
`bmm-witness-SHA256SUMS`; earlier source/artifact seals are historical. Signet
solution extraction/clearing and validation orchestration remain in scope.
No live services, bidding, deployment or platform releases were changed.

The activation/PoW stage passes 430,000 property cases and 625 dispatch pairs.
Fifteen focused BMM cases pass 250 assertions, including activation boundaries,
error messages, invalid compact targets and high hashes with unchanged output
state. All 904 native cases/19,988,809 assertions, three CTest gates and refreshed
sandboxed installed static/shared consumers pass. The private-catalogue variant
of drivechain_bmm.cpp passes a compile-database-derived syntax check with
ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE enabled; this does not qualify its linked
runtime or private activation lifecycle. Evidence `bmm-activation-*` is sealed by
`bmm-activation-SHA256SUMS`. No deployment or live-service changes were made.

The signet-extraction stage passes 450,000 property cases and 676 dispatch pairs,
including native callback transcripts, injected write failure, lazy mismatches
and independent capability-instance reuse. Sixteen focused BMM cases/258
assertions and all 905 native cases/20,228,929 assertions pass. Real script
fixtures preserve first-solution selection, header-only prefixes, opcodes and
distinct parser-end failures; the authentic signed public fixture still passes.
Three CTest gates, refreshed sandboxed installed static/shared consumers and
private-catalogue BMM syntax checking pass. Evidence `signet-extraction-*` is sealed
by `signet-extraction-SHA256SUMS`. Initial property compilation required enabling
FlexibleInstances for the new capability list; final tests pass. No private
runtime, cross-platform or live lifecycle qualification is implied.

The signet hash-plan stage passes 460,000 property cases and 729 dispatch pairs.
Seventeen focused BMM cases/4,869 assertions exhaust all 256 hash-type bytes with
input/output bounds and retain the authentic signed successor fixture. All 906
native cases/20,066,831 assertions, three CTest gates, refreshed sandboxed static
and shared consumers, and private-catalogue BMM syntax checking pass. Evidence
`signet-hash-*` is sealed by `signet-hash-SHA256SUMS`. Initial test compilation
needed a non-shadowing QuickCheck variable and an explicit upstream interpreter
include for SIGHASH constants; final checks pass without weakening warnings.
No live-service, deployment, cross-platform or private-runtime qualification is
implied by these local checks.

The signet validation transition stage passes 47 properties/470,000 randomized
cases and all 784 dispatch pairs across 28 payload types. Its frozen control-flow
oracle compares both errors and action traces, including invalid ABI states,
empty/nonempty solutions, decode failures, Merkle shape and coinbase mismatch,
and signature rejection. Native tests cover all error messages and both success
paths, missing witness commitments, trailing solution bytes, unchanged output
state on rejection, and the authentic signed public successor. An initial
missing-witness test accidentally retained the helper's default commitment;
the corrected fixture explicitly omits it. The initial failing log is retained.
Final results: 19 BMM cases/4,907 assertions; 908 native cases/19,981,710
assertions; all three CTest gates; refreshed sandboxed static/shared consumers;
private-catalogue BMM syntax. Evidence `signet-flow-*` is sealed by
`signet-flow-SHA256SUMS`. This is local qualification only, not private-catalogue
runtime, authenticated production lifecycle, or other-platform validation.

The BMM codec stage passes 48 properties/480,000 cases and 841 dispatch pairs
across 29 payload types. Native fixtures cover proof size/schema/entry bounds,
attachment rejection without output changes, oversized serialization retaining
its produced bytes, and sixteen persisted-state variants. These include valid
non-minimal pushes, truncated/opcode/trailing-script errors, bad marker/trailing
payload, invalid state and explicit/confidential asset/value rejection. Tests
preserve decoded output mutation and diagnostic precedence rather than silently
introducing transactional decoding. Final results: 21 BMM cases/4,988 assertions,
910 native cases/19,837,516 assertions, three CTest gates, sandboxed installed
static/shared consumers, and private-catalogue BMM syntax. `bmm-codec-*` evidence
is sealed by `bmm-codec-SHA256SUMS`. No live, private-runtime or cross-platform
qualification was performed in this stage.

The BMM traversal stage passes 49 properties/490,000 cases and 900 dispatch
pairs across 30 payload types. The frozen loop oracle compares action transcripts,
advanced-entry counts, optional signet skipping and failures at each stage;
invalid positions and full-width final-index boundaries are also checked.
Native one- through four-entry proofs verify state accumulation, last-entry M8
binding and unchanged published state for every corrupted entry and final
commitment mismatch. Final results: 22 BMM cases/5,103 assertions, 911 native
cases/19,877,699 assertions, all three CTest gates, sandboxed installed static
and shared consumers, and private-catalogue BMM syntax. `bmm-traversal-*` is
sealed by `bmm-traversal-SHA256SUMS`. Parent-state advancement and storage remain
native work; these checks do not establish private-runtime, production lifecycle
or cross-platform qualification.

The parent-state advancement stage passes 50 properties/500,000 cases and 961
dispatch pairs across 31 payload types. Its native differential oracle covers
Word32 wrapping, full-width intervals, period rollover, timestamp shifting,
invalid intervals, pointer/count rejection and unchanged buffer canaries.
Native boundary tests and all prior multi-entry/retarget/authentic fixtures pass:
23 BMM cases/5,391 assertions and 912 native cases/20,095,436 assertions. Three
CTest gates, refreshed sandboxed installed static/shared consumers, and the
private-catalogue BMM syntax gate pass. `bmm-advance-*` is sealed by
`bmm-advance-SHA256SUMS`. Proof-wrapper and state/storage orchestration remain;
these local tests do not establish private-runtime, production lifecycle or
cross-platform qualification.

### Configuration transaction admission

`ConfigurationTransactions` uses the existing command runner to sequence
deployment decoding/publication, deployment-version admission, genesis
decoding/publication and the public-only explicit-creation check. The version
comes from the explicit deployment argument, never the pricing mode. Native
callbacks retain argument reads, transaction decoding and object publication.
The published deployment and version remain visible after a later rejection;
genesis is published before the public-creation check, matching prior behavior.
Tests compare private/public/error traces through direct and ABI execution and
inject native exceptions before every action while checking partial state and
nested interpretation. The catalogue-freeze guard is unchanged: this build's
tests do not exercise live activation. Registry admission and broader
configuration orchestration remain separate migration work.

`ConfigurationCovenants` similarly owns keyless-key admission, four ordered
single-leaf descriptor derivations, price admission/publication, and checkpoint
admission/publication. Native callbacks retain upstream key checks, tweaks,
hashing and field assignments; existing FrozenBounds methods retain numeric
rules. Each failed tweak stops before accessing its missing result. NUMS
failure skips curve validation. Initialization fields precede initialization
hash parsing, preserving partial state after an exception. Direct/ABI trace
properties and native fault-injection tests cover all guard and publication
steps, including nested numeric validation.

The proof-wrapper/state-source stage passes 52 properties/520,000 cases and
1,024 dispatch pairs across 32 payload types. A frozen wrapper oracle checks
stage order and short-circuit transcripts; state-source properties cover invalid
facts and corruption precedence. Native competing-failure fixtures check bounds,
hash, decode, prior state, missing parent and final commitment errors without
publishing state. Corrupt persisted storage rejects even with an eligible public
checkpoint. Results: 25 BMM cases/5,425 assertions; 914 native cases/19,970,059
assertions; three CTest gates; refreshed sandboxed static/shared consumers; and
private-catalogue BMM syntax. `bmm-wrapper-*` is sealed by
`bmm-wrapper-SHA256SUMS`. Connect/disconnect, remaining storage and broader fork
migration still need work. Private-runtime, production lifecycle and other
platforms were not qualified in this stage.

The connect/disconnect decision stage passes 53 properties/530,000 cases and
1,089 dispatch pairs across 33 payload types. Frozen branch rules cover all
lifecycle phases, error priorities and invalid ABI facts. In-memory native tests
exercise checkpoint initialization, overwrite rejection, removal, repeated
removal, corrupt stored state, no-op/incomplete candidates and missing rollback
state. Results: 26 BMM cases/5,460 assertions; 915 native cases/20,033,860
assertions; three CTest gates; sandboxed installed static/shared consumers; and
private-catalogue BMM syntax. `bmm-lifecycle-*` is sealed by
`bmm-lifecycle-SHA256SUMS`. Read/verify/write sequencing and storage helpers
remain native work. This is not production or private-runtime lifecycle
qualification, nor cross-platform validation.

The connect/disconnect sequencing stage passes 54 properties/540,000 cases and
1,156 dispatch pairs across 34 payload types. `StateFlow` selects native reads,
verification and writes between Haskell calls; a frozen imperative oracle checks
action order, short-circuiting and write attempts. Rollback extraction, proof
verification and current-state comparison remain separately ordered actions.
Results: 27 BMM cases/5,489 assertions; 916 native cases/20,077,228 assertions;
three CTest gates; refreshed sandboxed installed static/shared consumers; and
private-catalogue BMM syntax. `bmm-state-flow-*` is sealed by
`bmm-state-flow-SHA256SUMS`. Remaining BMM storage helpers and the broader fork
migration are incomplete. These checks do not qualify private runtime,
authenticated production lifecycle or other platforms.

The parent-context stage extends the existing median parity property with zero
rejection and invalid-pointer coverage: 54 properties/540,000 cases pass. The
payload dispatch matrix remains 34 types/1,156 pairs. A native regression checks
zero-median rejection, cleared outputs, recovery on a valid call and ABI faults.
Results: 28 BMM cases/5,498 assertions; 917 native cases/20,100,156 assertions;
three CTest gates; refreshed sandboxed installed static/shared consumers; and
private-catalogue BMM syntax. `bmm-parent-context-SHA256SUMS` seals the stage.
The upstream tracked-source diff is captured in `bmm-parent-context-upstream-scope.log`;
it is an inventory, not proof that remaining changes are migrated. Remaining
storage helpers, fingerprint construction and broader fork work are unfinished.

The fingerprint payload stage passes 55 properties/550,000 cases and 1,225
dispatch pairs across 35 payload types. Its frozen imperative encoder oracle
compares complete payload bytes, callback counts, short-circuit faults and
writer rejection in both mode layouts. Native regression checks the independent
public golden identity, absence of private reads, malformed blob rejection and
exception propagation. Results: 30 BMM cases/5,555 assertions; 919 native cases/
20,002,701 assertions; three CTest gates; refreshed sandboxed installed consumers
including the new API; and private-catalogue BMM syntax.
`bmm-fingerprint-SHA256SUMS` seals current evidence. The linked private node and
other platforms remain unqualified; randomized private-layout coverage is not
a substitute for those runtime gates.

`TargetScale` now owns retarget multiplication, division and pow-limit clamping.
It deliberately narrows the factor to Word32 (the native overload selected by
the prior code), wraps the product to 256 bits before dividing, then clamps.
Compact target decoding/encoding remains an upstream native adapter. The fixed
32-byte little-endian ABI reads both inputs before writing, so target/limit aliasing
is supported; faults leave the output unchanged. Do not replace these semantics
with unbounded multiplication during cleanup: that would change consensus.

The target-scaling stage passes 56 properties/560,000 cases and 1,296 dispatch
pairs across 36 payload types. An independent byte-limb multiplication/division
oracle checks the ABI, full-width divisors and canaries; 2,048 native differential
cases compare directly with upstream arith_uint256 operators. Native tests also
cover aliasing and unchanged output on division faults. Results: 31 BMM cases/
7,607 assertions; 920 native cases/19,820,848 assertions; three CTest gates;
refreshed sandboxed installed consumers; and private-catalogue BMM syntax.
`bmm-target-scale-SHA256SUMS` seals the stage. Storage sequencing/namespace and
the other remaining fork stages are not completed by these numeric tests.

The state-replacement stage passes 57 properties/570,000 cases and 1,369 dispatch
pairs across 37 payload types. A frozen imperative oracle checks callback order,
failure short-circuiting and signed height normalization; native injected failures
verify original exception types and that prepare failure does not undo the prior
spend. Existing in-memory checkpoint lifecycle tests exercise the real adapter.
Results: 32 BMM cases/7,707 assertions; 921 native cases/19,953,228 assertions;
three CTest gates; refreshed sandboxed installed consumers; and private-catalogue
BMM syntax. `bmm-state-write-SHA256SUMS` seals this stage. Stored-state encoding
and read/namespace helpers still remain; no live lifecycle was run.

This is not yet a distributable release. Third-party runtime license notices
still require collection/installation. Validated locally with GHC 9.6.7 and
macOS 11 object deployment targets, not on an actual macOS 11 host. GHC 9.14.1's
installed runtime requires macOS 26. Windows/cross-compilation is rejected pending
toolchain/runtime qualification; native Linux and its patchelf bundling remain
unverified. Do not replace platform releases with this build.

## Remaining stages

Persisted BMM decoding now uses `StateFlow` READ actions to order the push,
drop, end, marker, state, payload and final-state checks. Native parsers execute
between interpreter calls; their partial writes are not rolled back. Script
exceptions propagate, while payload exceptions retain the existing decode error.
The native fixture compares every truncated payload against the original stream
reads, including partially mutated state and exact error strings. Property tests
compare failure at every action with an independent sequential trace oracle.
State-decode evidence (`bmm-state-decode-*`): 66 properties/660,000 cases,
44 payload types/1,936 dispatch pairs; 37 focused tests/9,381 assertions;
926 native tests/19,942,989 assertions. Three runtime gates, installed
static/shared isolation consumers, private syntax and diff checks pass. Native
truncation parity covers all 116 payload lengths; linked-private and platform
qualification remain separate, and earlier artifact seals are historical.

Proof-entry transaction/proof decoding and their canonical reserialization checks
now use StateFlow ENTRY actions. Failure stops subsequent native reads, while
the final canonical mask and coinbase shape retain their prior semantics.
The missing-coinbase rejection is now a Proof rule with the original diagnostic.
Entry-decode evidence (`bmm-entry-decode-*`): 66 properties/660,000 cases,
44 payload types/1,936 dispatch pairs; 37 focused tests/9,396 assertions;
926 native tests/19,975,551 assertions. Three runtime gates, private syntax,
diff checks and installed static/shared consumers pass. Isolation denies both
the original build symlink and its relocated T705 target. The build directory
was moved without open files after Crucial exhausted writable space; executable
and consensus-library hashes were verified before rebuilding (`build-relocation-*`).

Preflight and parent/difficulty/time/PoW ordering now use StateFlow actions.
An extension mismatch skips later fact reads but still visits the extension
diagnostic check; PoW runs only after that check succeeds. The shared Haskell
runner executes native effects through safe callbacks, as in entry decoding.
Failure-trace properties and native exception/nested-rule tests cover this boundary.
Header-flow evidence (`bmm-header-flow-*`): 67 properties/670,000 cases,
44 payload types/1,936 dispatch pairs; 38 focused tests/9,610 assertions;
927 native tests/19,931,211 assertions. Runtime gates, installed static/shared
isolation consumers, private syntax and diff checks pass. Initial property-test
compilation failed on a test import; the corrected run is properties-final.log.
`bmm-header-flow-scope-audit.md` records inspected residual orchestration, not
a claim that BMM or the whole fork migration is complete.

Attachment and parent-context publication now use StateFlow ATTACH/CONTEXT
actions. Oversized serialization retains bytes without updating the commitment;
invalid context input still clears the output before checking state and median.
Native regression tests freeze these mutation and error-priority semantics.
Publication-flow evidence (`bmm-publication-flow-*`): 67 properties/670,000 cases,
44 payload types/1,936 dispatch pairs; 38 focused tests/9,679 assertions;
927 native tests/20,091,048 assertions. Three runtime gates, installed static/shared
isolation consumers, private syntax and diff checks pass. Earlier artifacts and
scope snapshots remain historical; this is not whole-fork completion.

Proof decoding and effective-state selection now use StateFlow PROOF/EFFECTIVE
actions. Decode failure still visits shape validation for its diagnostic; no
canonical serialization occurs afterward. Stored state precedes checkpoint
fallback, and a stored-state diagnostic prevents fallback. Public checkpoint
selection precedes private selection. Native proof truncation parity and frozen
selection traces cover partial mutation and branch order.
Selection-flow evidence (`bmm-selection-flow-*`): 68 properties/680,000 cases,
44 payload types/1,936 dispatch pairs; 38 default BMM tests/10,829 assertions;
927 default native tests/20,009,295 assertions. Runtime gates and isolated
installed static/shared consumers pass. Native proof parity covers 369 lengths.
Refreshed component-linked private build: 40 BMM tests/10,879 assertions and
929 full native tests/20,053,121 assertions. Only BMM source/tests use the private
macro; this is not a whole-private-node build. The exact recipe is recorded in
`bmm-selection-flow-private-recipe.json`; all evidence is checksummed.

Difficulty interval arithmetic now uses Check DifficultyInterval and `quot`,
matching defined C++ signed division (including negative truncation toward zero).
The fixed-width ABI has a separate status and output, so negative results remain
valid. Zero divisors and minBound / -1 reject without writing; the old native
expression had undefined behavior for those inputs. Upstream Consensus::Params
is unchanged. BmmConsensus calls the adapter at runtime, not static initialization.
Interval evidence (`bmm-interval-*`): 69 properties/690,000 cases,
45 payload types/2,025 dispatch pairs; 39 focused tests/10,846 assertions;
928 native tests/20,095,223 assertions. Runtime gates, installed static/shared
isolation consumers, private syntax and diff checks pass. The prior linked-private
executable predates this source and must be refreshed at the next broader gate.
Fixed preset migration must use lazy adapters to avoid starting Haskell during
C++ global initialization, retaining stable references and fingerprint identity.
Public/private BMM consensus preset values now come from Check ConsensusPreset:
six numeric fields, native-order PoW bytes and challenge bytes. The bounded ABI
forces all outputs before writing, rejects unknown modes/nulls, and preserves
canaries. Native lazy accessors construct stable const objects from those values;
they do not initialize Haskell during global initialization. Checkpoint records,
mode selection, and native aggregate default declarations remain to be audited.

Preset evidence (`bmm-presets-*`): 70 properties/700,000 cases, including
unchanged output buffers on null-pointer faults; 46 payload types/2,116 dispatch
pairs; 39 default focused tests/10,848 assertions and 928 native tests/20,182,431
assertions. Three runtime gates and isolated installed static/shared consumers
pass. The refreshed private BMM component passes 41 focused tests/10,898
assertions and 930 full-suite tests/20,111,312 assertions. Its recorded compile/link
recipe enables the private catalogue only for BMM source/tests; this is not a
whole-private-node build. Public/private fingerprint identities remain unchanged.

A full function-by-function BMM boundary audit remains required, including
fixed consensus/checkpoint projections and header inline methods. The earlier
scope snapshots are historical evidence, not an exhaustive completion gate.
CheckpointPreset now owns both public/private checkpoint records. Its fixed ABI
exports 16 u32 values (five fields plus eleven timestamps) and 32 native-order
hash bytes. All values are forced before writes; unknown modes and null pointers
fail without modifying output buffers. C++ retains native state construction and
serialization via lazy, stable-reference accessors, with private selection still
compile-time/runtime gated. Frozen-value parity and the 47-type dispatch matrix
cover the new adapter. Checkpoint evidence (`bmm-checkpoints-*`): 71 properties /
710,000 cases; 47 payload types / 2,209 dispatch pairs; 39 focused native tests /
10,850 assertions; 928 default native tests / 20,233,702 assertions. The refreshed
private component passes 930 tests / 20,131,293 assertions, including 41 BMM cases /
10,900 assertions and the unchanged private fingerprint. Three runtime gates,
installed static/shared consumers isolated from GHC and both build paths, and
diff checks pass. Private qualification remains component-level, not whole-node.
BMM is not fully migrated.
FixedIdentity now supplies the two public sidechain hashes, synthetic chainstate
outpoint, marker, signet/M8 magic and script flags in one bounded record: two u32
fields and 121 bytes. Native code lazily projects that record into existing
uint256, COutPoint and byte-container types. No Haskell call occurs during C++
global initialization. Frozen-byte parity, null-fault no-write checks and output
canaries cover the ABI; fingerprint/state fixtures cover the native projection.
Identity-stage evidence (`bmm-identity-*`): 73 properties/730,000 cases and 48
payload types/2,304 dispatch pairs; 928 default native tests/19,853,475 assertions,
including 39 BMM cases/10,868 assertions; 930 private-component tests/20,120,687
assertions, including 41 BMM cases/10,918 assertions. Runtime gates, installed
static/shared isolation consumers and diff checks pass. Both fingerprints remain
unchanged. The remaining control-flow audit is not complete.
BmmConstants is now the shared source for schema/slot/proof limits and consensus
aggregate defaults. CMake evaluates its pure header renderer at configure time
using the selected native GHC and tracks the module for reconfiguration. This
generates constexpr native declarations, preserving compile-time callers and
legacy aggregate construction without starting the RTS during global initialization.
ConsensusPreset consumes the same Haskell values. Native aggregate null/empty
fields remain unchanged; these are not replaced with the selected public preset.
The existing cross/Windows build qualification restriction remains in effect.
Defaults-stage evidence (`bmm-defaults-*`): 730,000 property cases; 929 default
native tests/20,049,598 assertions (40 BMM cases/10,883 assertions); 931 private
component tests/20,046,811 assertions (42 BMM cases/10,933 assertions). Independent
header generation, native compile-time/default-layout checks, three runtime gates,
installed static/shared isolation checks and diff checks pass. CMake dependency
evidence records both reconfiguration and runtime-library dependencies.
StateFlow now also owns consensus-mode selection and activation read ordering.
Its RETARGET and POW paths also sequence span selection/scaling and target/hash
checks. Native compact-target conversion and header hashing remain primitives;
the flow skips scaling for the no-retarget sentinel and never hashes a header
after target rejection. Real native actions run between interpreter calls and
retain existing exceptions and error strings.
Work-flow evidence (`bmm-work-flow-*`): 74 properties/740,000 cases; 930 default
native tests/19,934,413 assertions (41 BMM cases/10,902 assertions); 932 private
component tests/19,945,187 assertions (43 BMM cases/10,952 assertions). Three
runtime gates, installed static/shared isolation checks and diff checks pass.
Script inspection/extraction and the exhaustive BMM boundary audit remain open.
Script inspection now uses `elements_hs_bmm_commitment_v2` with an explicit
output-index/action callback. Haskell selects witness-prefix inspection or staged
opcode reads, requests the second GetOp only after OP_RETURN, then assembles the
metadata used by the existing scan. Native code retains GetOp and its cursor/data
state; callback failures preserve the captured native exception. Fields are range
checked before packing. The old private v1 callback ABI is replaced, not silently
reinterpreted; no public libelementsconsensus ABI changed. Extraction/publication
sequencing and the complete BMM boundary audit remain outstanding.
Inspection evidence (`bmm-inspection-*`): final 740,000 property cases; 931 default
native tests/20,272,889 assertions (42 BMM cases/11,120 assertions); 933 private
component tests/19,800,659 assertions (44 BMM cases/11,170 assertions). Three
runtime gates and rebuilt installed static/shared isolation consumers pass.
The final build refresh includes the callback field-range checks and fault tests.
EXTRACT/PARENT StateFlow phases now control selected-index gating, two native
GetOp replays, final hash conversion/publication and coinbase-presence gating.
Absent/ambiguous selections leave the output unchanged; a missing coinbase never
reaches transaction access. Parsing remains upstream and its already-validated
replay retains the original ignored GetOp return values. Native actions execute
between interpreter calls, including the nested commitment scan and byte rule.
Extraction evidence (`bmm-extraction-*`): 740,000 property cases; 931 default
native tests/19,831,992 assertions (42 BMM cases/11,182 assertions); 933 private
component tests/19,897,992 assertions (44 BMM cases/11,232 assertions). Runtime
gates, installed static/shared isolation consumers and diff checks pass. The full
boundary audit still includes signature and chainstate preflight sequencing.
The subsequent SIGNATURE StateFlow now orders witness/input preflight, public-key
validation, signature split, hashing and verification. `SignatureActions` reuses
the Preimage Check/Validation operation to choose ordered prevout, sequence and
output hashing, retaining ALL-output priority over SINGLE. Native hashing and
CPubKey verification remain primitives; native actions run between interpreter
calls, preserving exception propagation and allowing nested Haskell rules.
Signature-flow evidence (`bmm-signature-flow-*`): 750,000 property cases; 932
default native tests/20,258,181 assertions (43 BMM cases/11,402 assertions); 934
private-component tests/20,170,035 assertions (45 BMM cases/11,452 assertions).
Three runtime gates and installed static/shared isolation consumers pass. The
current upstream operation-capabilities 0.1.1.0 also passes 750,000 node cases,
80,000 library cases and 23 compile gates using an isolated version override;
the production dependency remains pinned to 0.1.0.0. Persisted-state preflight,
header lazy projections and the complete BMM boundary audit remain outstanding.
COIN StateFlow now owns the persisted-state guard sequence: unspent, explicit
asset, pegged asset, explicit value, zero value. Native accessors execute only
after their preceding guards; the existing STATE_ASSET diagnostic is preserved.
No persisted bytes or consensus parameters change. All 32 fact combinations
exercise exact early-stop traces; existing real-coin fixtures cover confidential
assets/values, wrong assets, nonzero values and unchanged state after rejection.
Coin-flow evidence (`bmm-coin-flow-*`): 750,000 property cases; 933 default native
tests/20,003,311 assertions (44 BMM cases/11,650 assertions); 935 private-component
tests/20,034,095 assertions (46 BMM cases/11,700 assertions). Three runtime gates,
installed static/shared isolation and diff checks pass. Native GetOp overload
selection and lazy header projection still require explicit boundary disposition
in the full BMM audit; these results do not complete the broader migration.
The subsequent function-level boundary audit (`bmm-boundary-audit-scope.md` in
the qualification directory) retains READ GetOp selection as native primitive
dispatch: Haskell chooses the phase and Codec owns opcode acceptance. It records
remaining effectful storage selection, entry mutation/publication gates and undo
height arithmetic. This is an inventory, not a completed BMM migration claim.
The duplicate tagged-SHA256 helper was removed in favor of upstream TaggedHash
and GetSHA256. BmmConstants now owns its unchanged domain tag; default structural
equality replaces manual BmmL1State field comparisons. Both frozen public/private
fingerprints remain unchanged. Audit-stage evidence: 750,000 property cases;
933 default tests/19,944,781 assertions (44 BMM cases/11,651 assertions); 935
private-component tests/20,141,850 assertions (46 BMM cases/11,701 assertions).
Three runtime gates, installed static/shared isolation and independently
regenerated-header equality pass. No wire schema, dependency pin or live node
was changed.
NATIVE_CHECK StateFlow now decides whether connection inspects persisted state:
nonempty proof bytes skip storage, while empty bytes request exactly one lookup;
Lifecycle retains the rejection and diagnostic. Incomplete-candidate inputs are
now raw immutable facts rather than duplicated native conjunctions. All 16 flag
combinations retain the old decision.
StateRestore is a constructor of the existing StateWrite operation. After Refl,
the shared StateReplacement methods compute the restore height and run the same
clear/prepare/publish helper. `max 1 height - 1` preserves nonnegative undo heights
without the old native `INT32_MIN - 1` undefined behavior; negative heights
normalize to zero. C++ storage remains unchanged. The private BmmStoreState C++
adapter now takes an optional restore flag; installed consumers were rebuilt.
Storage-flow evidence (`bmm-storage-flow-*`): 760,000 property cases; 934 default
native tests/20,022,274 assertions (45 BMM cases/11,834 assertions); 936 private
component tests/19,942,694 assertions (47 BMM cases/11,884 assertions). Three
runtime gates and both installed isolation consumers pass. Property/native
tests cover restore boundaries, callback failures, exact lookup/action traces,
diagnostics and capability dispatch. Entry-state publication and private-builder
residuals remain in scope; the full migration is not complete.
Traversal now owns initial-state copying, bounds-before-entry preparation and
final publication selection through INITIALIZE_ENTRIES, PREPARE_ENTRY and
PUBLISH_ENTRIES. Native publication returns immediately after the move, with no
subsequent Haskell call that could fail after changing the caller's output.
The transcript oracle includes the formerly implicit mutation points; native
fault tests cover every action and existing multi-entry fixtures prove rejected
proofs leave next_state unchanged. SetBmmState consumes the zero amount supplied
by the Haskell preparation action instead of duplicating the literal.
Entry-publication evidence (`bmm-entry-publication-*`): 760,000 property cases;
935 default native tests/20,003,189 assertions (46 BMM cases/12,187 assertions);
937 private-component tests/20,004,203 assertions (48 BMM cases/12,237 assertions).
Three runtime gates and rebuilt installed static/shared isolation consumers pass.
The consumer's old CRITICAL-to-done expectation was updated to explicitly check
CRITICAL-to-publication-to-done; the private traversal protocol requires matched
native/Haskell builds. No public consensus ABI or proof encoding changed.
The BMM module audit is dispositioned locally: private-builder nonce mutation,
hashing, native object construction and diagnostic presentation remain adapters
to Haskell's PRIVATE traversal/template. This does not qualify all cross-module
callers, other platforms, a whole private node or the overall migration. Next is
CTIP storage and deposit orchestration, reusing StateReplacement where applicable.
CTIP storage now reuses that existing StateWrite/StateRestore operation through
the historical BmmStoreState adapter. No new capability class, operation payload,
or FFI symbol was added. Haskell owns clear/prepare/publish order, the zero output
amount and normal/undo height normalization; native code retains Coin/view
construction and storage. DisconnectDepositState no longer subtracts height in
C++. The callback's native preparation remains outside the Haskell runtime.
CTIP-storage evidence (`ctip-storage-*`): 760,000 property cases; 936 default
native tests/20,046,843 assertions; 938 private-BMM-component tests/20,113,792
assertions. Both contain 38 peg tests/3,177 assertions. New integration checks
cover checkpoint creation, v2 connection, rollback and fresh cache views at six
boundary heights, comparing stored coin height, asset, amount, coinbase flag,
wire script and restored CTIP fields. The fixture persists across cache instances
in memory, not a real disk/process restart. Three runtime gates and installed
static/shared isolation consumers pass. CTIP codec/fixed identity and broader
deposit orchestration remain in scope, as does the rest of the full migration.
CTIP encoding now reuses StateEncode/StateAssembly through BmmEncodeState.
Haskell selects marker/payload serialization order, the push, and DROP/FALSE;
native code retains the unchanged field serialization and CScript primitives.
The action plan completes before native execution, including when encoding is
called during storage preparation. The CTIP storage fixture also compares the
v2 output against an independently assembled native reference script. This adds
no operation type, capability class or FFI entry point. Decoding, fixed identity
and deposit orchestration are not migrated by this change.
The subsequent CTIP identity step moves its slot, internal outpoint hash/index
and marker into BmmConstants.hs, reusing the build-time header generator. Native
code only constructs the upstream outpoint/vector types. No RTS call is needed
during static initialization. The storage fixture independently freezes the
original outpoint and script bytes; this does not change the historical slot or
introduce a configurable identity. CTIP decode orchestration remains pending.
CTIP script inspection now uses the CtipScript constructor of PersistedCtip:
the shared Check interpreter dispatches to its Validation method, which sequences
three native opcode reads and packs their nine-bit results. All three reads still
occur after a GetOp failure (256); the first retains its data push, and subsequent
reads use the original no-data overload. Native exceptions are captured by the
adapter and rethrown only after Haskell returns. Adapter values outside 0..256
fail closed without another read. The private elements_hs_ctip_script_v1 entry
requires a matched native/Haskell build, not a change to public consensus ABI.
QuickCheck covers mixed opcode triples and callback order; native tests cover
all 257 results and each failure position, including non-standard exceptions.
Coin fact collection and decoded-state publication remain to be dispositioned.
The decoder's remaining coin fact collection is guarded access to native asset
and amount encodings; marker/hash comparisons and DataStream reads project
native fields. PersistedCtip owns rejection policy and errors, and the native
caller publishes decoded output only after success. These are retained adapter
boundaries, not independent copies of the validation rules.
VerifyDeterministicDeposit now uses DepositVerification, a constructor on the
existing DepositStateRule payload. Its Check/Validation dispatch selects the
checkpoint/prior-state/build/verify path or witness-bounds/legacy-rejection/parse/
prior-state/verify path. Native actions run between pure interpreter calls, so
parsers and state checks may safely invoke Haskell themselves. Complete callback
transcripts are compared to the original branching logic for all 1,024 Boolean
outcome combinations in native tests and randomized QuickCheck cases. The private
elements_hs_deposit_verification_v1 entry requires matched builds. Evidence-anchor
verification and connect/disconnect orchestration remain native and in scope.
Evidence-anchor verification now uses the anchor entry of that same transition
operation. Haskell orders checkpoint lookup/check, witness bounds and legacy
rejection, v2 parsing, anchor validation and detailed mismatch presentation.
The native adapter formats the original two-hash diagnostic only when selected;
it does not replace parser errors. No new operation, capability or FFI symbol is
introduced, but the expanded private phase protocol requires matched builds.
Native tests enumerate all 128 anchor outcome combinations against the original
branch transcript; QuickCheck varies the same outcomes. Existing authenticated
checkpoint/v2 fixtures cover exact errors and real native parsing. CTIP connect
and disconnect orchestration remain pending.
CTIP connect/disconnect now use the same transition payload through
RunDepositLifecycle. Haskell orders checkpoint lookup, build/verify or v2 parsing,
prior/current state checks and the selected storage action. The private protocol
tags terminal actions with bit 256: native execution returns their result directly
without another interpreter call. This preserves publication and exception order,
including nested StateReplacement/StateAssembly calls outside an active callback.
Native SpendCoin failure still formats its original diagnostic and returns its
result. No new operation type or FFI symbol was added. Exhaustive native traces
cover both 128-outcome lifecycle tables and faults at every visited action;
QuickCheck independently compares the original branch order and terminal result.
The existing real coin/cache fixtures retain rollback and serialized-state checks.
This does not complete event normalization, parent replay or the wider migration.
Lifecycle evidence (`deposit-lifecycle-*`): 800,000 property cases, 940 default
native tests/20,172,138 assertions and 942 BMM-private-component tests/19,786,881
assertions pass. Both include 42 peg tests/7,839 assertions. Three runtime gates
and refreshed installed static/shared isolation consumers pass. The private run
compiles only BMM source/tests with the private flag, not the whole node.
ParseV2Deposit now uses the parsing entry of the shared transition operation.
Haskell orders bounds, evidence extraction, the three short-circuited native
deserializers, inclusion checks, early anchor assignment, previous-input scan,
witness extraction, CTIP/destination validation and final publication. Native
DataStream/hash/merkle/PoW primitives and output field assignments are retained.
The anchor still changes immediately after inclusion even if a later stage
rejects; full publication is terminal and has no subsequent interpreter call.
All 512 fallible-decision combinations are compared against the original native
branch transcript, with a QuickCheck counterpart. The previous-CTIP input scan
inside the selected native action still needs migration; this stage does not
claim all parsing or authentication behavior is complete.
The previous-CTIP scan now uses the shared transition operation as well. Haskell
orders input bounds, hash equality, output bounds, treasury script check, match
recording and advancement. It visits every input and selects the last matched
output's value, or zero when no match exists. Native callbacks retain upstream
field access and selected counter/last-output updates; script validation may call
Haskell safely between flow steps. Terminal value selection returns directly.
Native tests exhaust all 585 sequences of up to three input fact triples;
QuickCheck covers longer sequences and compares the complete guard trace, count
and last match. No new operation payload or FFI symbol is introduced. Remaining
authentication orchestration and event normalization still require an audit.
AuthenticateDepositEvidence now uses an authentication entry in the shared
transition operation: network checks, sidechain identity, deposit selection,
current CTIP verification, then terminal authenticated-output publication.
Native field readers and the existing exception-to-error boundary are unchanged;
selected native routines may invoke Haskell between transition calls. Tests cover
all 32 result combinations and exceptions at each action with no early output
publication, alongside the existing real JSON/error-order/atomicity fixtures.
The new entry reuses the operation payload and FFI symbol. Transaction fact
collection, identity/deposit selection internals and event normalization remain
subject to the full native-behavior inventory.
VerifyDepositTransaction now collects facts through DepositProjection on the
existing DepositStateRule payload. Haskell gates input count/index/witness count,
selects witness decoding only after the four input facts pass, and selects at most
two output reads even when the input shape is invalid. Native code retains field
access, explicit-value guards, decoding and fact projection. Counts cross the
private elements_hs_deposit_projection_v1 ABI as Word64 without truncation.
The original AuthenticatedDeposit rule still decides validity after collection.
Tests compare complete transcripts across zero, one, excess and maximum counts,
all four-bit input facts, and boundary output counts. Public ABI is unchanged;
the new private symbol requires matched native/Haskell builds.
Identity/deposit selection audit: VerifySidechainIdentity and FindDeposit already
delegate traversal, duplicate/missing-match rejection, validation order and address
checks to LiveEvidence. Their native callbacks retain guarded UniValue access,
bounded byte copying, selected index updates and native output construction.
VerifyCtip similarly projects native fields for Haskell validation before output
assignment. JSON schema helpers and event construction remain separate inventory.
GetWithdrawalBundleStatus now delegates null-ID preflight, event iteration,
kind/ID/status filtering, malformed-field rejection and finish ordering to
WithdrawalStatusFlow on the existing PegEvent payload. Normalization and lifecycle
state reduction remain their existing calls, executed between interpreter calls.
Native errors retain their original strings. The private flow symbol requires
matched builds. Exhaustive native filter transcripts and randomized multi-event
traces complement existing real normalization/status fixtures. L1 normalization,
sidechain event construction and status string projections remain in scope.
NormalizeL1PegEvents now uses L1Normalization on the shared PegEvent payload.
Haskell controls root/block/event shape checks, iteration, deposit-first dispatch,
optional withdrawal fields, duplicate insertion/comparison and error selection.
Native UniValue reads/writes and map insertion retain existing field order,
serialized-payload equality and diagnostics. Event-schema construction and string
projections remain native adapters pending their own inventory. The native runner
is shared with withdrawal-status traversal; effects occur between interpreter
calls. Native tests cover all 8,192 decision transcripts; QuickCheck checks valid
and invalid phase/result pairs. Real JSON fixtures cover multi-block traversal,
duplicates, optional fields, missing arrays and deposit priority over a malformed
withdrawal key. A new private symbol requires matched native/Haskell builds.
ExtractSidechainPegEvents now uses SidechainEvents on the same PegEvent payload
for bundle emission, transaction/input/output traversal, witness and pegout
guards, and emission order. Native callbacks retain transaction decoding and
UniValue construction, resetting scratch fields at the original per-item points.
Exhaustive 8,192 branch transcripts accompany real block fixtures with malformed
and absent witnesses and a wrong-asset output between accepted withdrawals.
WithdrawalStatus maps exact status bytes in Haskell and reuses the existing
lifecycle reducer through Check/Validation. The bounded byte-span ABI preserves
embedded NULs, case and whitespace rather than normalizing them. The bridge
shares existing error mapping; no native status-name classifier remains in
GetWithdrawalBundleStatus. Final status rendering and JSON schema construction
remain native inventory, not a claim that all peg-event behavior is migrated.
These private symbols require matched native/Haskell builds. No services or
published binaries are updated by local qualification.
L1Location now delegates header/hash/height/timestamp order and optional timestamp
selection to PegEvent's L1Location flow. Native schema parsers and UniValue writes
run between interpreter calls, preserving exception priority and insertion order.
Lifecycle names, final state names and acknowledgement labels are generated from
one Haskell table in BmmConstants; normalization uses the validated lifecycle
index instead of reclassifying status text in C++. Generated constexpr arrays
require no RTS call or static initialization and preserve all public strings.
LiveEvidence now uses a suspended EvidencePlan and the private v2 begin/resume/free
ABI. A stable handle owns an IORef containing only Haskell values and continuations;
each four-Int64 snapshot is copied before the borrowed native buffer expires.
ResumeEvidence uses the existing Check/Validation dispatch. The single rule plan
also serves the direct Haskell callback adapter used by operation-dispatch tests;
there is no duplicate domain-rule table. The production v1 callback export is
removed. Native RAII cleanup covers success, parser failure and native exceptions.
Native reads run between interpreter calls, permitting schema operations to call
Haskell without re-entering an active native callback. Six-phase differential
traces, independent/interleaved handles, polling, rejected post-completion input
and nested native-to-Haskell rule tests qualify this boundary. This removed the
callback dependency for the subsequent shared-schema migration.
Shared Require*/FindField helpers now use PegSchema on the existing PegEvent
payload. Haskell owns type acceptance, numeric-versus-string parsing selection,
hex type/content/optional-size ordering and object/camelCase/null-only snake_case
fallback. Native ParseInt64, UniValue typed access and IsHex remain upstream
primitives. Integer and hex adapters are shared by both diagnostic namespaces;
their original error strings and parse exceptions remain native. Terminal value
publication returns without another interpreter call. Hex limits use Word64 with
the original unsigned multiplication behavior on the supported 64-bit platforms.
ReadExecution now owns the schema and deposit-transaction-fact runners, using
the existing rules under one Check dispatch. The shared factsCall callback
transport also serves BMM proof execution: its separate callback status preserves
the full Word64 reply range, including wrapping hex limits. Native exceptions
are captured and rethrown on the original thread; terminal publication performs
no subsequent read. Differential tests cover complete and partial traces,
callback failures, nested validation, and unsigned boundary values.
The private schema ABI requires matched builds. Tests compare complete native
branch transcripts, including zero and wrapping limits, and authenticate real
fixtures with null versus invalid camelCase fields alongside valid snake_case.
Destination opcode sequencing and valid-candidate publication are now Haskell
decisions on the existing DepositDestination payload. Native callbacks retain
the script cursor, upstream GetOp/DecodeDestination/GetScriptForDestination and
selected assignments. Invalid prefixes do not skip the second read; valid
candidate publication still precedes duplicate rejection. The private v2 ABI
requires matched native/Haskell builds. A test-only adapter projects frozen
packed fixtures into primitive reads for old-C++ differential testing, without
duplicating production selection policy. Native action traces cover malformed
reads, decode/publication faults and duplicate detection; real script fixtures
retain nonminimal pushes, empty/trailing scripts and output atomicity coverage.
Event-ID construction now uses Check EventIdentity: Haskell owns all five
prefixes, separators, lifecycle suffixes and decimal formatting. The private
bounded-byte ABI carries numeric bits as Word64; bundle/L1 identities interpret
them as signed Int64, while sidechain vin/vout identifiers remain unsigned.
Native hashes and JSON serialization are unchanged. The 64-byte input bound is
checked before reading, and insufficient output capacity publishes no bytes.
Frozen C++ string expressions and output canaries cover exact bytes, embedded
bytes, full-width values and rejected kinds/statuses. The dispatch matrix now
includes 49 payload types / 2,401 pairs and lazy mismatch checks. The property
oracle uses std::string/to_string and links the platform C++ runtime explicitly.
Event field layouts now use Check EventLayout: Haskell owns the layouts,
field order, literal labels and lifecycle acknowledgements. The bounded private
ABI publishes a key and optional literal only after checking all output buffers.
Native UniValue reads and appends happen between interpreter calls, preserving
lazy schema parsing and allowing nested Haskell validation. The final append
returns without another interpreter call; borrowed views expire with the callback.
The dispatch matrix includes 50 payloads / 2,500 pairs. Frozen schema properties,
native callback-fault traces and complete JSON fixtures cover layout compatibility.
Layouts 15/16 also supply BMM request field order and the nested `hex` wrapper.
The native adapter retains UniValue encoding, signed numeric heights/slots and
decimal-string uint64 bid values. The shared encoder does not perform admission:
the caller's existing bid preflight remains separate. Complete JSON comparison
tests pin the previous bytes at signed/unsigned extremes; schema ABI tests cover
buffer bounds, unknown layouts and callback faults without network requests.
Checkpoint lookup, legacy-claim construction and CTIP reads now share the existing
DepositVerification flow interpreter. Haskell orders input/witness bounds, record
selection, witness/address decoding, claim validation and publication. Native
transaction access, checkpoint deserialization and address/script primitives stay
in adapters. A failed witness decode still precedes address decoding and claim
validation. CTIP decode uses temporary state; success assignment and optional
error assignment are terminal actions without another interpreter call. The ABI
adds action codes through 82 and requires matched builds. Property transcripts
and exhaustive native branch/fault tests cover these paths; a broader peg boundary
audit still precedes parent replay and whole-module completion.
The shared PegSchema also selects null defaults and accepts only a typed false
boolean. CTIP vout defaulting and IBD acceptance use these modes; native integer
parsing and boolean access occur only after the selected guard. The default/parse
callbacks are terminal, preserving exception behavior and publication order.
Guarded secondary identity/event/hash/amount reads share ReadWhen, backed by the
GUARDED PegSchema mode. A false guard never invokes the native reader; a true
guard invokes it between interpreter calls and returns immediately afterward.
Nested schema evaluation and non-std RPC exceptions retain their native behavior.

Parent replay begins in ParentReplay.hs with a simple Record validation payload.
Haskell selects the supplied unique/reproposal schema version and validates
deposit, BMM-edge and successful-withdrawal records. Native projections retain
hash/null checks and supply the upstream MAX_MONEY bound; no database or wire
format changes. The private fixed-width ABI rejects unknown kinds/fact bits and
retains parent-height overflow rejection. The 51-type dispatch matrix and frozen
C++ differential properties cover numeric/shape boundaries. IsSaneTip now uses
the Record payload's TipFlow: Haskell selects activation checks, proposal and
withdrawal loops, CTIP uniqueness, per-slot checks and previous-action handling.
Height, vote-window and amount arithmetic also lives in Record validation.
Native iterators, sets and optional/hash facts remain borrowed adapters; selected
actions use the shared safe callback and can invoke nested rules.
The boolean-flow runner is shared with deposit flows without changing their
diagnostics or terminal publication behavior. Frozen-original tip validation
is compared through real store Reset/Load fixtures, alongside transition and
callback-fault tests. StoreFlow on the same Record payload now selects ReadRecord
existence/decode/error ordering and Load preflight, identity/schema and tip checks.
The status-bearing runner uses safe callbacks for native database reads,
allowing nested record and tip validation. Terminal diagnostics need no further
transition. Load preserves its original exception boundary,
optional error clearing and caller-output mutation on failed tip validation;
ReadRecord retains upstream decoding and its partial-output behavior. Exhaustive
native transcripts cover all three flow kinds and faults at every visited action.
Reset now uses the same StoreFlow for seed validation, terminal lock release,
database reopening, batch assembly and synchronous commit/error selection. The
release remains outside the original catch boundary; reopening and batch lifetime
remain inside it. Native primitives retain LevelDB locking and atomic storage.
The four public readers also use StoreFlow for database/schema preflight,
read-status propagation, lazy sanity/identity/height checks and terminal errors.
ReadCheckedRecord shares the native decode/diagnostic adapter, keeping each
reader's original catch boundary and diagnostic text. Disk-backed malformed and
semantic-corruption fixtures check null diagnostics and decoded output retention.
Append now uses StoreFlow for contiguous-tip checks, identity/tip reads, all
record/duplicate/proposal loops, schema-dependent lookup and batch write order.
Native callbacks retain borrowed records, sets, hashes and LevelDB primitives.
Only the final selected action synchronously commits the batch. Its conditional
terminal tag returns immediately on successful commit, without another interpreter
call; a failed commit resumes solely to select its diagnostic. Reset shares this
commit boundary. Imperative original-order transcripts and per-callback faults
cover empty/multiple records, schema modes and optional edges; real-store rejected
appends preserve both the durable tip and absent records. This does not complete
transitive parent replay or wider call-site migration. Append's advanceable and
successor heights now use Record validation, sharing successor arithmetic with
BMM-edge validity. Full-width inputs reject values outside the 32-bit domain;
the original lazy max-height guard still precedes the next-height read.
BmmConstants generates unchanged replay schemas, key tags, status values, default
history rule and storage-mode flags. Native aliases/default arguments require no
RTS initialization. Frozen values, original numeric rules and a reopened-store
max-height fixture cover those boundaries. Zero/empty scratch initialization and
READWRITE field layouts remain native type/serialization adapters, not domain
transitions.
MainchainRPC's replay-store identity now uses the same StoreFlow protocol for
precondition assertions, writer construction, all34 typed preimage fields and
terminal hash publication. Native HashWriter serialization and cryptography are
unchanged; the domain string is generated from BmmConstants. The existing function
is declared in mainchainrpc.h so tests exercise it directly, with a frozen
pre-migration oracle, consensus-field variants and per-action exception traces.
Cache configuration, identity matching and launch preflight now use StoreFlow.
Haskell selects every assignment/predicate and preserves short-circuiting before
optional dereferences and RPC work. Shared Record POSITIVE/LESS validators own
threshold acceptance. Native checkpoint temporaries are constructed only when
their read is selected. Configuration's last assignment and preflight diagnostics
are terminal actions. Native mutation, epoch-counter increment, cryptography and
RPC primitives remain between interpreter calls. Two-failure transcripts and
per-action faults cover all three flows; callback field mappings are compared
against the pre-edit source. Store creation and load/rebuild selection now use
CACHE_LOAD, including forced-rebuild short-circuiting, all four load statuses,
checkpoint contradictions, log ordering and terminal loaded-state publication.
HEIGHT/LESS validators own checkpoint/activation height comparisons. Native tip
and error temporaries are created only at the selected load, and their scope ends
before reconstruction. The 4MiB cache and directory name are generated unchanged
from BmmConstants. Exhaustive decision/status transcripts preserve the original
selection and every native fault boundary. BOOTSTRAP_PREIMAGE now selects the
canonical preimage sequence and conditional CTIP fields; native typed hashing
retains the exact serialization. CACHE_REBUILD selects bootstrap versus genesis,
ordered slot validation, state assembly, cache clearing, store reset and terminal
success publication. Native temporaries are constructed at selected actions;
network reads and nested Haskell-backed storage calls occur between interpreter
calls. Reconstruction transcripts cover all Boolean branches and per-action
faults; actual preimage hashes are compared with the original serialization.
REPLAY_PREFLIGHT now controls cache identity/budget guards, checkpoint validation,
historical-height versus stale-tip checks, forced rebuild and target validation.
REPLAY_PUBLISH brackets advancement with checkpoint/target/cache-tip reads before
activation/deadline checks and terminal release-store publication. Cache clearing,
epoch invalidation, diagnostics and lazy reads retain their original order.
Independent imperative transcripts exhaust Boolean branches, mutable staleness
and every callback fault. Native mutex ownership is unchanged. The bootstrap
catalog and transitive RPC helpers remain separate migration work.
REPLAY_ADVANCE selects budget consumption, deadline/read/continuity
checks, transition and milestone validation, optional BMM edge construction,
durable append and in-memory publication for every block. Selected native
arithmetic and temporary construction/destruction remain adapters; all loop and
failure decisions are Haskell-owned. The height advances only below its target,
so a terminal UINT32_MAX block no longer wraps the loop counter. Fault transcripts
cover multi-block progress, unchanged memory on rejected append and terminal
height boundaries. REPLAY_LOCK selects blocking versus nonblocking acquisition,
authentication and terminal snapshot recording while native RAII retains the
mutex across the entire operation. REPLAY_BUDGET selects deadline, numeric
acceptance, nullable diagnostics and terminal decrement; REPLAY_SNAPSHOT selects
replacement and ordered field publication. SNAPSHOT on Record owns replacement
policy, including an explicit lower target replacing a warmer snapshot. Tests
cover all branch/fault transcripts, numeric and null-error cases, actual public
snapshot policy and native lock ownership/release on exceptions. The validation
budget and admission lifecycles use Haskell-generated constexpr action tables:
disabled scopes do nothing, first budget entry initializes state, and last exit
clears it according to the current depth, including non-LIFO destruction. Native
RAII effects and depth assertions remain adapters. No allocating FFI dispatch or
RTS call is introduced into noexcept cleanup. Tests compare all generated plans
with the original effect sequence and exercise actual nested, disabled,
non-LIFO and exception-unwound budgets through an interrupted no-network warmer.
Deadline and snapshot height deliberately remain unchanged on final exit.
PARENT_DEADLINE selects anchor interrupt, anchor timeout
and validation timeout in their original priority, preserving optional-pointer
guards and lazy clock reads. PARENT_CIRCUIT preserves budget-guarded backoff.
Native clocks, atomics and exception construction remain adapters. Haskell emits
the unchanged two-second/two-step budget and five-second backoff defaults as
constexpr values, without startup RTS calls. Branch/fault transcripts cover every
read and exception priority. This is not qualification of remaining RPC helpers
or a live wall-clock timeout test.
MILESTONE and MILESTONE_HASH now own proposal, activation and checkpoint
selection, guarded state reads and diagnostic order. Native block hashing,
message extraction, byte assembly and map/optional access remain adapters.
Checkpoint CTIP comparison still precedes proposal comparison; missing CTIPs and
pending proposals are never dereferenced. M1/M2 tags are emitted by BmmConstants
and compared against frozen bytes in property tests. Real block fixtures cover
wrong hashes, absent/duplicate/wrong-slot messages, wrong proposal states and
CTIP mismatches. Independent action transcripts cover two failed predicates and
faults at every visited native action. The compiled checkpoint catalog and
transitive RPC helpers were separate work. EXACT_MESSAGE subsequently
moves coinbase guards, complete output traversal and unique-match acceptance into
the same interpreter. SINGLE_PUSH preserves output clearing, two native GetOp
calls, OP_RETURN/push-opcode checks, trailing-byte rejection and success-only
payload publication. Nonminimal PUSHDATA1/2/4 envelopes remain accepted, matching
the original decoder. PINNED_STATE short-circuits optional identity and checkpoint
presence. Tests cover traversal/fault transcripts and real malformed, duplicate,
noncoinbase, null-transaction and nonminimal script envelopes.
The bootstrap catalog and its replay-version selection now come from
`BmmConstants.bootstrapHeader`, generated at CMake configuration. The native Slot
layout and constexpr API remain unchanged: version 4 exposes the seven original
rows, version 5 returns a null empty span, and other versions return nullopt.
The existing version-5 checkpoint-height assertion is emitted from the same
Haskell source. Frozen native field comparisons and compile-accept/reject gates
protect both data and compile-time rejection; there is no runtime RTS call or
fallback catalog. This does not migrate the broader deployment identity header.
EXACT_ADDRESS preserves payload comparison before the trailing-byte check, unlike
the extractor's publication path. CANONICAL_HASH retains its prechecks and then
assigns the decoded hash before checking lowercase spelling: uppercase input is
rejected but still mutates the output, as before. HEIGHT_PREFLIGHT keeps nonnumeric
diagnostics outside the original catch scope; HEIGHT_PARSE runs integer conversion,
the shared AMOUNT bounds rule and success-only height publication within it.
Pure public helpers allow real UniValue/Script differential tests without RPC.
Native JSON/script/hex decoding and native exception handling remain adapters.
PARENT_POW, BLOCK_PROOF and CHAINWORK select compact-target validation,
proof calculation and successor-work comparison in the original order. Native
arith_uint256 decoding and arithmetic are reused, including their existing
modular behavior. Parameter reads remain guarded; block-proof validation retains
its different negative/overflow/zero order from PoW validation. Tests compare
real compact encodings, target/hash boundaries, diagnostic priorities, chainwork
successors and callback faults. Broader RPC/header authentication remains work.
RAW_REQUEST, RAW_PREFLIGHT, RAW_DECODE and RAW_POSTFLIGHT select the raw parent
header request and validation sequence. Authenticated transport, native stream
decoding and hashing remain adapters. Both deadline checks stay outside the
decode catch; malformed/truncated decoding preserves partial header mutation,
and trailing-byte rejection precedes hash and proof-of-work checks. Offline
differential fixtures cover every header truncation length, malformed JSON/hex,
trailing bytes, hash mismatch and invalid/insufficient work. Action transcripts
also cover every callback fault and nested interpreter calls between effects.
MEDIAN_TIME controls predecessor traversal, deadline checks and terminal median
publication. MTP_SAMPLE bounds the window to eleven headers without incrementing
the starting height. This deliberately fixes the former uint32_t overflow at
UINT32_MAX (which led to an empty-vector access); all defined earlier behavior
is compared with the original algorithm. Native vector sorting and header
storage remain adapters. Injected readers and deadlines permit offline tests of
read failures, exception ordering, predecessor selection and unchanged output on
failure; no RPC is required by these fixtures.
HEADER_METADATA selects object/hash/type guards, integer decoding and height/
confirmation checks before active-chain lookup. Native UniValue reads and
conversion exceptions retain their order: a malformed chainwork may update the
decoded work before rejecting, height is decoded before confirmations, and no
new exception catch is introduced. Pairwise malformed-field fixtures compare
diagnostics, exceptions and partial outputs with the original block. The
containing authenticated-header orchestration composes this helper below.
HEADER_PREDECESSOR selects the genesis branch, guards the predecessor request,
validates its canonical metadata and checks contiguous height and chainwork.
Genesis never invokes the request callback. The caller still supplies the
existing authenticated RPC function, and native JSON/integer/arithmetic
operations remain adapters. Offline fixtures compare exact requests, returned
diagnostics and propagated exceptions against the original branches. Height is
already validated by HEADER_METADATA; this helper does not add a new catch or
move the enclosing verifier's final null-chainwork rejection.
VERIFIED_HEADER now selects the complete authenticated-header sequence, composing
the metadata, raw-header, predecessor and MTP helpers. Explicit native sources
provide the same production RPC, genesis, raw-header, MTP and deadline functions;
offline fixtures substitute sources to compare request order, propagated errors
and serialized output with the previous orchestration. Pinned-genesis reads
remain lazy. The final zero-work rejection intentionally remains after all five
verified-field writes. This source-injected helper does not itself authenticate
arbitrary callbacks: production supplies the existing authenticated functions.
Raw parent blocks now reuse RAW_PREFLIGHT, RAW_DECODE and RAW_POSTFLIGHT through
the same native adapter as raw headers; no duplicate Haskell flow was added.
Witness-aware block decoding and each format's diagnostics remain native. The
block fixtures compare every truncation of a witness-bearing payload, malformed
counts, hash/work errors, nullable diagnostics, partial vector/header state and
both deadline exceptions with the original decoder. They qualify decoding and
header PoW only; transaction/Merkle/signet validation follows the decoder in the
production caller.
BLOCK_TRANSACTIONS now owns coinbase/null-entry guards, both transaction scans,
Merkle mismatch/mutation rejection and the final deadline before signet lookup.
PERIODIC_DEADLINE defines the shared every-256-items rule over a Word64 index.
Native transaction hashes, vector storage and ComputeMerkleRoot remain adapters.
Fixtures compare original scan/error/deadline order around 256/512 boundaries,
and fault every action on short synthetic scans.
BLOCK_SIGNET now controls lazy challenge lookup, optional script construction,
signet verification and success-only deadline checking. VERIFIED_BLOCK controls
header/body reads and final hash agreement; rejected or throwing callbacks keep
their existing partial output mutations. Production supplies the original native
readers and signet checker. Fixtures compare configuration reads, deadlines,
diagnostics, exceptions and serialized output against the old wrappers.
RECOVERY_DEADLINE now selects the tighter-limit policy, with the 30-second
constant generated from BmmConstants. DrivechainParentRecoveryDeadline is the
non-copyable native lifetime adapter: it snapshots before reading the clock and
restores unconditionally in a noexcept destructor without calling Haskell while
unwinding. Nested-scope, constructor-failure and body-exception fixtures compare
the original lifetime behavior, including an already-expired outer deadline.
Parent signet signature hashing now reuses the BMM native adapter, whose HashPlan,
SignatureActions and Preimage operations own selection and field ordering in
Haskell. The duplicated native signature hash implementation is removed; an
original-native differential fixture covers all 256 hash-type bytes, three input
positions and zero through four outputs. Parent signet witness-output selection
also shares the BMM Commitment operation through BitcoinWitnessCommitmentIndex;
the native duplicate scan is removed. Differential fixtures cover empty outputs,
lengths 0 through 80, every mutated prefix byte and repeated valid commitments,
preserving last-match selection. The block's coinbase preflight remains before
the shared scan. Synthetic transaction assembly and four-field block-data
serialization now share BuildBitcoinSignetTransactions and BitcoinSignetBlockData
between BMM and parent signet verification; these execute the existing Template,
SignetActions and Preimage operations. Parent solution decode reuses RAW_DECODE
inside the same std::exception boundary, retaining SpanReader and exact errors.
Native byte comparisons cover challenge sizes and version/timestamp boundaries;
malformed and trailing solutions retain diagnostics with nullable error output.
Parent signature checking now adds only three StateFlow phases before reusing
the existing key/split/hash/verify phases. The witness/nonempty gate and explicit
native signature-encoding check precede key construction. SignatureBytes supplies
the hash-type split; native crypto stays unchanged. Fault/trace tests cover every
visited action and both parent-only reply transitions reject invalid values.
The parent and BMM adapters now share BitcoinSignetSignatureChecker. StateFlow
SIGNATURE_MODE selects the existing distinct paths; BMM retains input bounds
and parent retains explicit encoding checks before key parsing. Direct signed
fixtures cover both modes with selected flags, undefined hash types, malformed signatures/keys,
wrong signature version, BMM missing input and invalid mode rejection.
Modified-Merkle traversal now uses SIGNET_MERKLE on the existing StoreFlow runner.
Reserve, replacement coinbase, index initialization, bounds, transaction hashes
and increment stay ordered; upstream ComputeMerkleRoot runs as the terminal
native action. Existing LESS handles index bounds. Direct root comparisons and
per-action faults cover the loop without a new operation or FFI entry point.
PARENT_SIGNET owns the top-level validation gates and terminal diagnostics,
preserving genesis bypass and lazy coinbase reads. WARM_PARENT sequences parent
height lookup, checked integer parsing, hash lookup and replay warmup. Its shared
integer parser reuses HEIGHT_PARSE and AMOUNT without translating exceptions;
each caller retains its own catch and diagnostic policy. Warmup's no-slot bypass
and nullable error clearing remain native preflight. RPC_REPLY owns checked
envelope error precedence and lazy result access. CheckDrivechainRPCReply is the
shared native JSON adapter used by the real RPC caller and offline differential
fixtures; upstream HTTP transport is not replaced. AUTH_RETRY sequences cookie
authentication detection, invalidation and the active-validation-budget gate.
Password authentication never invalidates or reads the budget; cookie failures
invalidate before checking whether retry is allowed. Initial and retried RPCs
share one native success adapter. Native catch/rethrow scopes still own exception
lifetime and availability marking. RPC_TIMEOUT owns validation-budget precedence,
warm-deadline fallback and positive configured-timeout clamping. SIGNED_POSITIVE
and existing LESS supply numeric comparisons. Native chrono reads/conversions
remain lazy; both deadline paths share one terminal timeval adapter. No deadline
still uses the inherited configured-seconds API. COOKIE_CACHE selects try-lock
under a validation budget and blocking lock otherwise, then checks/copies the
cached credential while the native unique_lock remains alive. Failed try-lock
never reads cache state; cache misses leave the scope before the existing no-file
validation guard. CREDENTIAL_SOURCE enforces authentication-source conflicts and
native-chain inline-credential rejection before password lookup. CREDENTIAL_LOAD
checks the validation budget before host/path/file access, selects the credential
source, and publishes only successful loads under the native cache lock. Filesystem
security and argument access remain native adapters; exact diagnostics and lazy
reads are retained. Parent RPC response/header limits are emitted from the same
Haskell constant catalog as deadline/backoff values. The libevent C callback's
allocation guard remains a native adapter with constexpr limits, so no runtime
FFI call or new throwing path crosses that callback. Deadline and backoff native
chrono adapters consume generated values directly without redundant aliases.
ParentRulesForVersion is generated from the Haskell parent-rule catalog with only
versions 4 and 5 accepted. Native enums and aggregate types remain adapters;
frozen-identity static assertions still run at compile time, without RTS calls.
Full native tests compare exact enum choices, domains and proposal text. CMake
uses one generation loop for constant, bootstrap and parent-rule headers.
CHECKPOINT_IDENTITY preserves CTIP-first validation and the absent/present proposal
branches, including optional-hash guards and lazy native hashing. CHECKPOINT_CTIP
owns the canonical null/populated tuple and money bounds; existing LESS/HEIGHT
rules supply proposal/activation/checkpoint ordering. Native hash and scalar
projections remain adapters. HEADER_MTP owns ordered parent-header JSON validation;
HEIGHT_PARSE and AMOUNT are reused for numeric median-time conversion. Output is
zeroed natively before interpreter entry, nullable diagnostics remain lazy, and
the numeric conversion keeps its original exception scope. Remaining ownership
needs the full-fork inventory audit.
ACTIVATION_WINDOW owns the shared nonzero, strictly-below-max-age threshold
rule for unused-slot activation, used-slot activation and withdrawal inclusion.
AMOUNT is reused for signed slot bounds. Preflight retains its original lazy
proposal check, window order, output clearing and error precedence. Boundary
integration tests compare the original predicate; QuickCheck also covers the
full-width FFI inputs. This does not migrate the remaining block replay loop.
CTIP_BALANCE shares the amount predicate with AMOUNT and CHECKPOINT_CTIP and
owns the optional treasury balance rule for the configured slot and other slots.
Unlike checkpoint identity, an existing replay CTIP may have zero balance; an
absent CTIP must have zero balance. Proposal checks still precede this rule.
The same parent rule catalogue generates SupportedParentReplayRules: treasury
and M6 selectors are independently allowed, preserving all four existing mixed
combinations. Native enum types remain adapters; no runtime FFI is needed for
this constant allowlist. Unknown treasury bytes reject before slot validation.
PROPOSAL_CONSISTENCY, OTHER_SLOT_PREFLIGHT, PRIOR_M4_PREFLIGHT and
COINBASE_PREFLIGHT own the remaining preflight branch decisions. Native callbacks
only project the selected fields; CTIP_BALANCE executes between interpreter
calls, not through an unsafe Haskell callback. Empty/null coinbase guards remain
lazy, and prior-M4 validation preserves even the repeated ALARM comparison.
Trace/fault tests cover every boolean path and direct entrypoint tests freeze
proposal and coinbase/M4 diagnostic precedence. The replay loop remains separate.
M8Acceptance owns the pre-mutation transaction traversal, deadlines, skip path,
M7 acceptance and parent-reference ordering. Four native actions replace the old
M8_ACCEPTANCE callback stages, whose table remains available for ABI compatibility.
Native request values are reset before each extraction; the native map lookup
guards its iterator before comparing commitment hashes. Original
error precedence and first-rejection termination are covered by read/fault traces
and real mixed-transaction fixtures. Subsequent proposal/vote/CTIP replay still
requires migration.
CoinbaseMessages now owns ordered output traversal and duplicate M1/M2/M4/M7
rejection before M8 acceptance with eight native actions instead of the old
19-stage COINBASE_MESSAGES path. Its old table remains for ABI compatibility.
The stable message-kind projection uses explicit discriminator values 0..5.
Native set/map insertion, message movement/destruction and diagnostics remain
adapters. Haskell carries the seen-M4 flag and every-256-output deadline check. Trace
and mutation snapshots cover all three-message type combinations and injected
faults, with separate deadline boundaries and real duplicate-message fixtures.
M2Proposal owns skips, future-height rejection, uint32 wrapping vote increments,
used/unused threshold selection and activation ordering. Six native actions
replace the former 22-stage PROPOSAL_ACK callback path; the old table remains
available for ABI compatibility. Native adapters retain pending iterators and
active hash references. Erasure and active replacement precede replacement-error
reporting exactly as before; activation flag/height writes precede block hashing.
Trace/fault and real threshold/counter fixtures preserve these partial mutations.
M1 uses native try_emplace without replacing existing height/votes; the original
PROPOSAL_INSERT table remains available. WITHDRAWAL_PROPOSAL owns M3 active-slot rejection, lazy duplicate
scan, then identity/pending append order. Native containers and field access
remain adapters. Fault snapshots preserve partial append state, and entrypoint
fixtures stop at a later inactive-slot M3 to isolate these effects from expiry
and deferred output publication.
M4_UPVOTE owns target search, saturation skip, competing-bundle downvotes and
effective-action publication; M4_ALARM owns zero-guarded downvotes and publishes
only when at least one counter changes. LESS/POSITIVE are reused for counter
guards. Native iterators and counter writes remain adapters, with no vector
resizing during traversal. Snapshot/fault and real M4 fixtures cover zero,
near-saturation and saturated counters, including unchanged effective actions.
M4_LEADER owns leading-by-50 selection and its guarded upvote/publication. It
preserves first-leader ties and the maximum runner-up across replacements;
redundant writes of an unchanged local runner-up value are omitted. LESS/HEIGHT
are reused for comparisons. The upvote helper executes between interpreter
calls, preserving failure propagation and publication only after success. Real
block fixtures compare the original max/selection algorithm over empty lists,
ties, exact-gap thresholds and saturation.
Database keys, record formats
and synchronous batch semantics are unchanged.
Activation preflight precedes mode lookup; native argument and block reads execute
only for the selected branch, between interpreter calls. Public builds cannot
dispatch the private native action. Missing/invalid private activation heights
retain the existing exceptions, and no rejected preflight dereferences a null
previous block. Consensus accessors retain lazy construction and stable references.
Mode-stage evidence (`bmm-mode-*`): 72 properties/720,000 cases; 928 default
native tests/20,151,542 assertions, including 39 BMM cases/10,866 assertions;
930 private-component tests/20,446,797 assertions, including 41 BMM cases/10,916
assertions. Three runtime gates and installed static/shared isolation checks pass.
This remains BMM-component private qualification, not a whole-private-node build.
Component-level linked private-builder qualification passes; a full
private-catalogue node build is separate work.
Fingerprint payload construction is now interpreted
in Haskell; its tagged SHA256 primitive remains native.
`runtime_fingerprint_preserves_v4_wire_identity` freezes both mode identities.
Both public and private vectors now pass in the isolated BMM-linked executable.
Independent preimages and the pre-migration audit snapshot are in
`bmm-fingerprint-vectors.*` and `bmm-remaining-scope-audit.md` under qualification.

`bmm-private-linked-recipe.json` records the exact component-build method: compile
only drivechain_bmm.cpp and its tests with the private macro, then link those
objects into a separate test executable using existing default-catalogue objects
and libraries. The normal build is not overwritten. All 38 BMM tests/7,992
assertions pass, including three newly constructed synthetic proofs, serialization
round trips, wrong-commitment rejection, disabled/invalid-input no-publication,
and the independently calculated private fingerprint. This is local synthetic
data, not a public BMM request, network block, release build or whole-node private
catalogue qualification.
The full isolated executable also passes 927 tests/20,157,088 assertions; its
non-BMM objects still use the default catalogue as recorded in the recipe.

1. Finish release notices, minimum OS and Linux/Windows qualification, and the
   authenticated production lifecycle. Native macOS isolated lifecycle and
   installed static/shared consumer checks pass; they are not cross-platform evidence.
2. Move remaining deposit authentication/CTIP and BMM proof logic using versioned ABIs;
   retain upstream transaction parsing and hash functions. Native withdrawal
   construction/validation is migrated, but wallet/bundle orchestration is not.
3. Move parent replay, BIP300 CTIP/withdrawal transitions and BMM checks with
   historical-chain/reorg differential fixtures and unchanged state encodings.
4. Move exchange/USDD fork-specific validation and proof bindings, retaining the
   Rust SP1 verifier ABI and existing Simplicity implementation.
5. Move fork-added wallet, RPC, bridge/bidder and networking orchestration with
   explicit error, cancellation, locking and service-lifecycle contracts.

Each stage must delete the replaced production C++ logic, pass original tests
through the real FFI and preserve wire bytes and consensus outcomes. None of
these later stages is implied complete by the first-stage parity tests.

The scope baseline is the locally merged upstream commit
`301acc64be91d9fce1282d1af7bb673a397b6df2`. The remaining inventory includes
`drivechain_peg`, `drivechain_bmm`, `drivechain_parent_replay`, `mainchainrpc`,
`ecx_exchange_state`, `mainchainrpc_ecx`, the USDD annex/accumulator code, and fork
logic in validation, policy, init, miner, P2P, wallet/RPC and Qt. Declarations,
upstream types and necessary C++ adapters are not a reason to duplicate domain
rules. Tests/benchmarks must follow migrated behavior. This inventory is not a
claim that those components are already migrated.

M4 explicit/repeat dispatch now uses StoreFlow 74/75, reusing the existing
upvote/alarm helpers without an extra payload or capability class. Native slot
iteration and container lifetimes remain unchanged. Abstention skips pending
state access; inactive repeated slots and absent targets fail before publication.
The prior-action map is replaced only after successful message processing, while
earlier slot mutations survive a later failure as in the original implementation.
Evidence `m4-dispatch-*`: 145 properties (1,450,000 cases), 1,051 native tests
(29,516,438 assertions), three Haskell CTests, and installed static/shared
consumers with build-tree/GHC access denied. Fault traces and 32 real two-slot
replay fixtures cover skip, alarm, upvote, invalid target and partial mutations.
This is local macOS qualification, not a deployment or cross-platform claim.

Proposal expiry uses Record 19 (threshold, votes, age, maximum age). It checks
input bounds before subtraction and implements the original age/missed-vote
predicate. Height and withdrawal-age comparisons reuse existing Record rules;
native iterator erasure and diagnostic ordering are unchanged. This removes
the duplicated C++ expiry arithmetic without a new payload or capability class.
Evidence `replay-expiry-*`: 146 properties / 1,460,000 cases, 1,052 native tests
/ 29,312,944 assertions, three Haskell CTests and installed static/shared
consumer checks. The 657-assertion replay fixture covers used/unused windows,
inclusive age boundaries, excess votes, and earlier erasure before later
future-height failure for both proposals and withdrawals. Loop orchestration
and the broader fork-added inventory remain unfinished.

Expiry loop orchestration now uses StoreFlow 76/77, sharing iteration, height,
erase/advance and terminal-failure transitions. Proposals additionally check
votes before evaluating expiry. Native adapters retain iterator lifetimes and
error formatting; no container is traversed inside the FFI. The preceding
expiry predicates and replay boundary fixtures are reused.
Evidence `expiry-flow-*`: 147 properties / 1,470,000 cases, 1,053 native tests
/ 29,154,193 assertions, three Haskell CTests and installed static/shared
consumers. A new 4,350-assertion fault/trace fixture compares the original loops
against both flows over empty and three-entry combinations, including erasure
followed by failure. Outer slot traversal and CTIP processing remain native.

CTIP owner-map construction and input-spend scanning now use StoreFlow 78/79.
They reuse CTIP_BALANCE, PERIODIC_DEADLINE and LESS; native adapters retain
outpoints, map insertion/find/increment, references, and diagnostics. Duplicate
ownership precedes duplicate-spend checks, which precede output validation.
Input deadlines remain at indices divisible by 256, including index zero.
Evidence `ctip-scans-*`: 148 properties / 1,480,000 cases, 1,055 native tests
/ 29,443,547 assertions, three Haskell CTests and installed static/shared
consumers. New tests include 13,185 map/trace/fault/deadline assertions and
24 real-block diagnostic-order assertions. CTIP output scanning and M5/M6
transitions, plus the broader inventory, remain unfinished.

CTIP_OUTPUTS/CTIP_REPLACEMENTS (StoreFlow 80/81) now control treasury-output
scanning and replacement requirements. They reuse AMOUNT and PERIODIC_DEADLINE;
script extraction and map access remain native. Unknown scripts/inactive slots
skip amount validation, invalid amounts precede duplicate insertion, and
unspent owners skip replacement lookup. Native spend-map indexing still occurs
before that lookup, preserving its insertion effect.
Evidence `ctip-outputs-*`: 149 properties / 1,490,000 cases, 1,058 native tests
/ 29,653,690 assertions, three Haskell CTests and installed static/shared
consumers. New tests provide 10,617 trace/state/fault assertions and 116
real-block assertions over output skip/error order and replacement combinations.
CTIP change derivation and M5/M6 transitions remain native, as does the remaining
fork-added inventory. No deployment or cross-platform readiness is implied.

CTIP_CHANGES (StoreFlow 82) controls change derivation: parallel-treasury guards,
lazy old-value selection, zero-delta rejection, decrease counting and ordered
publication. Native adapters keep references, map indexing and vector storage;
the existing LESS rule compares amounts already bounded by preceding checks.
Publication and iterator advancement share one native action, with advancement
occurring only after successful vector insertion.
Evidence `ctip-changes-*`: 150 properties / 1,500,000 cases, 1,060 native tests
/ 29,393,257 assertions, three Haskell CTests and installed static/shared
consumers. New tests include 30,525 state/trace/fault assertions and 150 real
two-slot replay assertions spanning zero, decrease, increase and MAX_MONEY.
M5/M6 transaction handling and the broader fork-added inventory remain active.

M5_DEPOSIT (StoreFlow 83) owns address/amount gates, CTIP update sequencing and
optional mintable-deposit publication. Existing LESS, SIGNED_POSITIVE, AMOUNT
and HEIGHT rules are reused; parsing, bounded subtraction, hashing and native
storage remain in the adapter. Both CTIP fields update before publication
gates, and a later deposit failure does not roll back earlier updates/records.
Evidence `m5-deposit-*`: 151 properties / 1,510,000 cases, 1,063 native tests
/ 29,349,754 assertions, three Haskell CTests and installed static/shared
consumers. New tests include 6,621 fault/trace assertions, 64 replay cases
(264 assertions) spanning activation, collector, slot, address length and amount,
plus seven assertions for a valid deposit preceding a malformed later one.
M6 handling, outer traversal and the broader fork-added inventory remain active.

M6_WITHDRAWAL (StoreFlow 84) controls shape, ID, proposal/vote and repeated-M6
guards, followed by flag update, withdrawal recording, proposal erasure and CTIP
updates in their original order. Native ID derivation, hashing, find/erase and
storage remain adapters. Existing LESS handles the strict vote threshold.
Evidence `m6-withdrawal-*`: 152 properties / 1,520,000 cases, 1,065 native tests
/ 29,437,447 assertions, three Haskell CTests and installed static/shared
consumers. New tests add 26,103 fault/trace assertions over 2,048 gate combinations
and 272 real replay assertions over 40 proposal/vote/slot/collector cases.
Existing single-versus-sequential withdrawal fixtures also pass. M6 ID derivation
policy, outer dispatch/traversal and the broader fork-added inventory remain.

PRUNE_SLOTS/BLOCK_PUBLISH (StoreFlow 85/86) control replay cleanup and final
output publication. Pruning retains lazy field checks and native iterator
erasure. Final proposal validation precedes optional output moves, followed by
the final deadline check; a deadline exception does not undo those moves.
Evidence `replay-finish-*`: 153 properties / 1,530,000 cases, 1,068 native tests
/ 29,363,078 assertions, three Haskell CTests and installed static/shared
consumers. New tests include 3,828 pruning and 276 publication fault/trace
assertions, plus 144 real replay assertions over 24 valid slot/collector cases.
Outer dispatch/traversal, M6 ID policy and the broader inventory remain active.

M6_ID (StoreFlow 87) controls shape/range validation, payout iteration and
blinded hash/slot publication. AMOUNT is reused with successively bounded limits;
native adapters keep checked arithmetic, codecs, transaction cloning and hashing.
Upstream WriteBE64 replaces the manual eight-byte fee encoding loop.
Evidence `m6-id-*`: 154 properties / 1,540,000 cases, 1,070 native tests /
29,598,539 assertions, three Haskell CTests and installed static/shared consumers.
New tests include 41,748 fault/trace assertions and 10,368 assertions comparing
2,592 amount/opcode combinations against original errors, output reset behavior
and manual-fee-encoding hashes. Outer dispatch/traversal and the broader
fork-added inventory are still unfinished.

M4_MODE/ACTIVE_SLOTS (StoreFlow 88/89) control M4 preflight/mode selection and
active-slot collection. Explicit vote counts are checked before slot mutations;
malformed two-byte encoding precedes active-slot lookup. Native containers and
sorting retain configured/other-slot ordering. Mode results are 0 failure,
1 explicit, 2 leader, 3 repeat; no new payload or library API is introduced.
Evidence `m4-mode-*`: 155 properties / 1,550,000 cases, 1,073 native tests /
29,552,352 assertions, three Haskell CTests and installed static/shared consumers.
New tests add 390 mode, 936 traversal fault/trace assertions and 356 real replay
assertions over 40 vector/encoding/slot cases. Outer message/transaction/slot
orchestration and the broad fork-added inventory remain unfinished.

ParentReplayEach reuses StoreFlow 90 for short-circuiting range traversal. Five
native loops now share it: leader/repeated M4, other-slot proposal expiry,
active-slot withdrawal expiry and M5 changes. C++ owns begin/end/iterator and
element lifetimes; callbacks may modify elements but must not invalidate range
iterators. Callback results normalize to bool before crossing the flow protocol.
Evidence `replay-each-*`: 156 properties / 1,560,000 cases, 1,074 native tests /
29,532,654 assertions, three Haskell CTests and installed static/shared consumers.
An instrumented range compares native range-for behavior at begin/end, compare,
dereference, body and increment exceptions (196 assertions), including early
rejection, const/temporary ranges and nonzero integral callback results. Existing
multi-slot replay and M5 partial-failure fixtures remain passing. Outer message
and indexed transaction/vote traversal and the broad inventory remain active.

Outer message, explicit M4 vote and transaction traversal now also reuse
ParentReplayEach. Indexed loops use standard C++ iota ranges with immutable
bounds; preflight rejects empty blocks before the transaction range starts at 1.
No new operation, capability, ABI or Haskell rule was needed. Callback returns
replace continue without changing error propagation or per-iteration lifetimes.
Evidence `replay-outer-*`: 156 properties / 1,560,000 cases, 1,075 native tests /
29,588,855 assertions, three Haskell CTests and installed static/shared consumers.
Nested range rejection/exception tests add 56 assertions; existing multi-message,
multi-slot and multi-transaction partial mutation fixtures remain passing.
Message-kind dispatch and the wider fork-added behavior inventory remain active.

MESSAGE_DISPATCH (StoreFlow 91) now selects the parent-message handler after
the deadline check: M1/M2/M3 select their existing flows, M7 skips processing,
and other values reach the existing M4 mode validation and its exact errors.
It reuses Record/Validation and the flow ABI, without adding a payload/class.
Evidence `message-dispatch-*`: 157 properties / 1,570,000 cases, 1,076 native
tests / 29,638,893 assertions, three CTests and installed static/shared checks.
New native dispatch coverage adds 200 assertions for selected-handler faults,
early failure, unknown values and skipped handlers. The installed consumer now
checks every message kind. Parent-message parsing and the broad inventory remain
unfinished; this is not a deployment or cross-platform qualification.

M8_PARSE (StoreFlow 92) now owns ordered M8 shape checks and field publication.
Hash extraction reuses BmmCommitmentBytes: the critical hash is reversed, while
the parent hash stays in consensus order. No new decoder or FFI symbol was added.
Evidence `m8-parse-*`: 158 properties / 1,580,000 cases, 1,077 native tests /
29,605,981 assertions, three CTests and installed static/shared consumers.
Flow fault tests add 339 assertions. Real replay covers all 70 truncations,
extra trailing data and each single-byte mutation, preserving ignored malformed
lookalikes versus recognized-but-unaccepted requests. Coinbase parsing remains.

ParentReplay.Message now decodes coinbase payload tags, lengths and M4 votes in
one pure Validation instance. The native parser shrank from 84 to 21 lines;
M2/M3/M7 reuse BmmCommitmentBytes and M1 retains upstream Hash. This is a native
function reduction, not a claim that all added bridge/test lines disappeared.
The private parent_message_v1 ABI requires two metadata cells and count vote
cells, with a nonnull vote pointer even for empty input. Counts above INT32_MAX
and invalid pointers reject before reading/writing; output votes never exceed
input count. The caller owns allocation and the bridge bounds returned fields.
Evidence `parent-message-codec-*`: 159 properties / 1,590,000 cases; 52 payloads
and 2,704 dispatch combinations; 1,078 native tests / 30,010,335 assertions;
three CTests and installed static/shared consumers. All 65,536 two-byte and 256
one-byte votes are tested. A frozen C++ parser oracle checks randomized payloads,
buffer canaries, unchanged input and rejection without output writes. Initial
test-only name-shadowing warning was corrected; the failed log is retained.
The full fork migration and cross-platform/private-node qualification continue.

CONFIRMED_DEPOSIT (StoreFlow 93) owns deposit replay admission, lock selection,
snapshot epochs, corrupt-index invalidation, evidence/depth checks and optional
parent-tip RPC. Native RAII, store/RPC calls and the outer catch remain intact.
The native function is 58 lines shorter; no new operation type or FFI symbol.
Evidence `confirmed-deposit-*`: 160 properties / 1,600,000 cases, 1,079 native
tests / 30,228,929 assertions, three CTests and installed static/shared consumers.
4,116 deterministic scenarios compare original action order and every reached
fault, including actual mutex release (107,516 assertions). This is local
adapter/flow qualification, not a live parent RPC or disk-corruption exercise.
Argument and immutable-identity preflight before the try block remain native.

DEPOSIT_PREFLIGHT (StoreFlow 94) now controls error clearing, slot/payload checks,
diagnostic preservation, delayed Params access and ordered immutable identity
checks. DEPOSIT/POSITIVE rules are reused; a single native checkpoint projection
serves both deposit admission and cache initialization. No new payload or ABI.
Evidence `deposit-preflight-*`: 161 properties / 1,610,000 cases, 1,080 native
tests / 30,650,379 assertions, three CTests and installed static/shared consumers.
16,432 native scenarios cover all 14-bit identity combinations, argument/error
variants and each reached fault. With payload boundaries, 591,215 assertions
verify lazy reads, statuses and exact partial diagnostic changes. No live RPC.
Successful-withdrawal lookup and the wider module inventory remain active.

WITHDRAWAL_LOOKUP (StoreFlow 95) now owns successful-withdrawal lookup sequencing:
RPC before lock, guarded durable read, corruption/future-height rejection,
record-chain and tip rechecks, and terminal optional publication. Repeated
invalidation effects share native cases; the function is 36 lines shorter.
Native lock_guard lifetime and outer exception boundary remain intact.
Evidence `withdrawal-lookup-*`: 162 properties / 1,620,000 cases, 1,081 native
tests / 30,852,029 assertions, three CTests and installed static/shared consumers.
8,192 predicate combinations with each reached fault add 119,168 assertions,
including real mutex release. The installed tests cover found and not-found
tip checks. This is local flow/adapter validation, not a live reorg exercise.
Execution-anchor/context and broader fork-added behavior remain unfinished.

EXECUTION_ANCHOR/MEMPOOL_CONTEXT (StoreFlow 96/97) share tip parsing/recheck and
terminal publication transitions. Execution interval checks reuse HEIGHT/LESS,
preserving uint64 MTP range and short-circuiting before later RPC. Native context
construction remains deferred until after the first tip parse. Budget and catch
boundaries are unchanged. This stage migrates policy, not an overall LOC reduction.
Evidence `parent-context-*`: 163 properties / 1,630,000 cases, 1,082 native tests /
31,187,434 assertions, three CTests and installed static/shared consumers.
32,768 predicate scenarios with reached faults and numeric boundaries add 356,254
assertions. Stable/changed-tip installed checks verify publication for both flows.
No live RPC/reorg qualification; parent-block/BMM wrappers and caches remain.

BLOCK_PARENT_CONTEXT/EXTEND_PARENT_CONTEXT/BMM_BLOCK_PREFLIGHT/BMM_CONTEXT_RESULT
(StoreFlow 98..101) now own block wrapper sequencing, output clearing and guarded
publication. Native authentication retains its specific catch boundary; slot and
parent extraction remain outside that catch. BMM UNAVAILABLE remains distinct
from INVALID. No new operation, capability class or FFI entry point was needed.
Evidence `block-context-*`: 164 properties / 1,640,000 cases, 1,084 native tests /
31,175,000 assertions, three CTests and installed static/shared consumers.
512 predicate scenarios with reached faults add 5,856 assertions; ten actual
wrapper assertions verify reset behavior on invalid slots without RPC. This is
not live BMM/reorg qualification. Anchor reconciliation, caches and the wider
fork-added module inventory remain unfinished. Elements stays the default chain.

ANCHOR_RECONCILE (StoreFlow 102) now owns ordered anchor reconciliation. Only
active-height hash mismatches select ORPHANED; raw-block authentication, pinned
replay and context failures select UNAVAILABLE. Native block/header construction
is deferred until after both height checks. The original catch, nullable error
and diagnostic precedence remain unchanged; no new payload or FFI symbol.
Evidence `anchor-reconcile-*`: 165 properties / 1,650,000 cases, 1,085 native
tests / 31,661,783 assertions, three CTests and installed static/shared consumers.
All 65,536 predicate combinations with reached faults add 653,907 assertions.
No live RPC/reorg qualification. Native anchor preflight, snapshot membership,
epoch checks, warming and the wider fork-added inventory remain unfinished.

SNAPSHOT_MATCH/ADD/CONTAINS (StoreFlow 103..105) and ANCHOR_EPOCH (Record20)
now own snapshot membership and epoch policy. Native serialization, hashing and
map ownership remain unchanged. Duplicate entries require exact encoded identity;
missing entries skip serialization. No new operation, capability or ABI symbol.
Evidence `snapshot-membership-*`: 167 properties / 1,670,000 cases, 1,087 native
tests / 31,580,549 assertions, three CTests and installed static/shared consumers.
768 flow combinations with reached faults and 1,225 epoch/slot combinations add
11,884 assertions. Two earlier runs failed on fixture I/O (one confirmed ENOSPC);
the full external-TMPDIR rerun passed without source changes. Failed logs remain.
This migrates policy, not an overall LOC reduction or live reorg qualification.
Anchor preflight, epoch/tip fencing, warming and broader module work remain.

Canonical M7 extraction uses `Bmm.CanonicalMatchFlow` (StoreFlow 279,
`CANONICAL_MATCH`) after scanning all outputs. Zero and multiple matches retain
distinct diagnostics; only one match permits publishing the hash and then the
optional output index. `canonicalMatchOrder` checks callback order, faults and
ABI framing. Native extractor tests cover non-minimal pushes and nullable
outputs. See the `m7-publication-*` qualification evidence; this does not claim
that the complete mainchain RPC module has finished migration.

Explicit M4 application uses `ParentReplay.ExplicitVoteFlow` (StoreFlow 280,
`EXPLICIT_VOTE`) around the existing `ExplicitVote` arithmetic. Abstention skips
slot access, packing and publication. No-change outcomes publish nothing;
successful upvotes/alarms copy staged counters before inserting the effective
action; absent indices retain the original diagnostic. Native containers,
hash copies and error formatting remain adapters. Legacy flow 74 remains for
ABI compatibility; its fine-grained upvote/alarm protocol is not the packed
vote-result interface used here. QuickCheck verifies direct/ABI traces and
faults; native tests cover empty/present bundles, alarm, abstention, saturation
and publication state. This stage moves policy but does not reduce total LOC.

The later `snapshot-adapter-*` consolidation uses `ParentReplayAll<3>` for
`Matches` and `ParentReplayAll<2>` for canonical tip admission and the slot/epoch
preflight. These reuse RequiredFactsFlow with unchanged lazy predicate order.
Selector 103 is retained for ABI compatibility and its independent tests;
ADD/CONTAINS and the epoch rule are unchanged. Native error translation stays
outside the conjunction and executes only on failure.

SNAPSHOT_EPOCH_FENCE/TIP_FENCE (StoreFlow 106/107) now own generation and
active-tip freshness sequencing. Deadline checks precede generation reads;
successful tip matching still requires a final epoch/deadline check. Native
preflight and catches retain their original boundaries. No new payload or ABI.
Evidence `snapshot-fence-*`: 167 properties / 1,670,000 cases, 1,087 native tests
/ 31,856,947 assertions, three CTests and both installed consumers. Expanded
flow/fault coverage adds 4,992 assertions. This is local qualification, not a
live reorg test. Anchor preflight, warming and the broader inventory remain.

SNAPSHOT_WARM_ANCHOR/WARM (StoreFlow 108/109) now own bulk snapshot warming
and per-anchor decisions, reusing ParentReplayEach and POSITIVE. Native timeout
scope, catches, delayed allocation and error construction remain. Cached anchors
skip authentication; unavailable anchors abort; orphaned anchors are not retained.
Final freshness validation precedes terminal shared_ptr publication.
Evidence `snapshot-warm-*`: 167 properties / 1,670,000 cases, 1,087 native tests
/ 31,627,993 assertions, three CTests and installed consumers with nested-flow
checks. The extended fault test adds 7,776 assertions. This increases adapter
lines, rather than claiming a size reduction. Native preflight, context caches,
the broader fork-added inventory and platform qualification remain unfinished.

ANCHOR_PREFLIGHT/SNAPSHOT_WARM_PREFLIGHT (StoreFlow 110/111) now select nullable
error clearing, slot/sanity rejection, output reset and budget/interruption
precedence. Both remain outside their original native catch boundaries, and
the warming deadline scope is constructed only after successful preflight.
Evidence `anchor-preflight-*`: 167 properties / 1,670,000 cases, 1,087 native
tests / 31,733,377 assertions, three CTests and installed consumers. The expanded
4,608-scenario flow test passes 55,632 assertions. No live RPC was used. This
is not overall LOC reduction; parent context/cache policy and broader fork-added
module/platform qualification remain unfinished.

VERIFIED_PARENT_CONTEXT (StoreFlow112) now sequences reset, deferred native
block/header construction, depth-1 verification, pinned active replay and
terminal context publication. No new catch, payload, class or ABI entry point.
Evidence `verified-parent-*`: 167 properties / 1,670,000 cases, 1,087 native
tests / 31,841,292 assertions, three CTests and isolated installed consumers.
The extended flow/fault test adds 7,296 assertions. This is not live RPC or
restart qualification. Cache/probe policy and the broad inventory remain active;
no overall line-count reduction is claimed for this adapter migration.

EPOCH_CHANGED (Record21) now owns the cache-generation comparison. Both pruning
predicates share it, and std::erase_if removes duplicated native erase/remove
code. Clock sampling and expiry short-circuiting are unchanged. Evidence
`cache-epoch-*`: 168 properties / 1,680,000 cases, 1,088 native tests / 31,760,882
assertions, three CTests and isolated installed consumers. A new native test
adds 5,145 assertions for survivor order, expiry-read counts and epoch boundaries.
The production pruning function is shorter; added tests are not claimed as net
LOC savings. Capacity/probe policy and the broader inventory remain unfinished.

Both BMM cache capacity checks now reuse LESS with capacity/size projections.
Native append and single-pop behavior stay unchanged, including initially
oversized caches. No new rule, operation or ABI. Evidence `cache-capacity-*`:
169 properties / 1,690,000 cases, 1,089 native tests / 32,247,882 assertions,
three CTests and isolated installed consumers. The new deque/boundary regression
adds 278 assertions. Parent probe/lookup policy and the broader fork-added
inventory remain unfinished; this is not deployment or live-node qualification.

PARENT_PROBE_ERROR (StoreFlow113) now classifies parent-probe RPC errors with
guarded code parsing and nullable diagnostics. Unknown-parent rejection remains
distinct from unavailable RPC metadata. Height/confirmation checks reuse HEIGHT
and SIGNED_POSITIVE; height publication ordering stays unchanged. Evidence
`parent-probe-error-*`: 169 properties / 1,690,000 cases, 1,090 native tests /
31,630,332 assertions, three CTests and isolated installed consumers. New coverage
adds 5,568 flow/fault assertions and 14 signed numeric boundaries. No live RPC.
Metadata selection, active-chain probe/cache lookup and broad inventory remain.

PARENT_PROBE_METADATA (StoreFlow114) now sequences metadata shape, parsing,
range validation, partial height publication and active-chain classification.
Native conversion and RPC remain guarded actions with unchanged catch behavior.
Evidence `parent-probe-metadata-*`: 170 properties / 1,700,000 cases, 1,091
native tests / 31,747,731 assertions, three CTests and isolated consumers.
1,024 predicate/error combinations with reached faults add 15,561 assertions.
Installed checks cover status and partial height publication. No live RPC or
net source-size reduction is claimed. Request construction, edge/cache lookup
and the broader fork-added inventory/platform work remain unfinished.

BMM_EDGE_RECHECK (StoreFlow115) now selects parent/successor reads, matching,
epoch invalidation and diagnostics. Failed reads do not invalidate; observed
mismatches do, before diagnostic construction. Native release-store semantics
remain. Evidence `edge-recheck-*`: 171 properties / 1,710,000 cases, 1,092 native
tests / 31,850,034 assertions, three CTests and isolated installed consumers.
The new trace/fault/atomic-state regression adds 224 assertions. This is not
live reorg/concurrency qualification. Request/cache lookup and broad inventory
remain active; no net source-size reduction is claimed for this stage.

BMM_CACHE_PREFLIGHT (StoreFlow116) now sequences output reset, budget-aware
native locking, epoch read, ordered cache clearing and pruning. Native lock
ownership spans the remaining lookup; construction is deferred until after
reset. Evidence `bmm-cache-preflight-*`: 172 properties / 1,720,000 cases,
1,093 native tests / 31,803,491 assertions, three CTests and isolated consumers.
The new original-order/fault/mutex-release regression adds 264 assertions.
No live concurrency/RPC qualification or net LOC reduction is claimed.
Cache-hit/admission and broader fork-added inventory remain unfinished.

BMM_CACHE_HIT (StoreFlow117) now sequences cheap commitment rejection, active
edge/epoch checks, exact-Q snapshot recording and terminal context publication.
Reverse lookup and native lock/iterator ownership remain. Evidence `bmm-cache-hit-*`:
173 properties / 1,730,000 cases, 1,094 native tests / 31,797,399 assertions,
three CTests and isolated consumers. The new trace/fault/early-rejection test
adds 405 assertions. No live RPC or net LOC reduction is claimed. Cache-search,
untrusted admission and broader fork-added inventory remain unfinished.

BMM_CACHE_KEY (StoreFlow118) now owns lazy hash/slot matching, shared by positive
and negative cache searches using std::find_if. Search direction and first-hit
semantics remain unchanged. Evidence `bmm-cache-key-*`: 174 properties /
1,740,000 cases, 1,095 native tests / 31,791,408 assertions, three CTests and
isolated consumers. The 8,192-search trace/selection regression plus lazy fault
checks adds 16,387 assertions. Untrusted admission, request construction and
the broad inventory/platform work remain; no net LOC reduction is claimed.

BMM_UNTRUSTED_ADMISSION (StoreFlow119) now sequences locked index identity,
epoch/store/edge checks, ordered invalidation and commitment admission. Native
invalidation actions are shared; indexed entry construction remains deferred.
Evidence `bmm-admission-*`: 175 properties / 1,750,000 cases, 1,096 native tests
/ 31,694,805 assertions, three CTests and isolated installed consumers. The new
1,024-scenario trace/fault/lock test adds 17,028 assertions. No live disk corruption
or concurrency qualification is claimed. Request/cold-path policy and the broad
fork-added inventory remain; this stage does not claim net LOC reduction.

BMM_PROBE_RESULT (StoreFlow120) now handles unavailable/rejected probes and
pre-checkpoint rejection, preserving lazy diagnostic reads and cache-before-error
ordering. Existing ADVANCEABLE_HEIGHT and SUCCESSOR_HEIGHT rules replace the
cold-path numeric checks. Evidence `bmm-probe-result-*`: 176 properties /
1,760,000 cases, 1,097 native tests / 31,902,217 assertions, three CTests and
isolated static/shared installed consumers. The six-scenario trace/fault test
adds 75 assertions. No live RPC or overall LOC reduction is claimed. Cold-path
publication/final epoch policy, the broad fork-added inventory and platform
qualification remain unfinished. Elements remains the default network.

BMM_PUBLICATION (StoreFlow121) owns the final edge recheck, partial context
publication, epoch fence, cache insertion/eviction and candidate classification.
Native assignments retain their original order, and the observed commitment is
cached even when the caller's candidate is rejected. Evidence `bmm-publication-*`:
177 properties / 1,770,000 cases; 1,098 native tests / 31,922,345 assertions;
three CTests and isolated static/shared installed consumers. The 64-scenario
trace/fault test adds 1,194 assertions. No live reorg/concurrency qualification
or net LOC reduction is claimed. Cold-path successor preparation, other
fork-added modules and cross-platform qualification remain unfinished.

BMM_SUCCESSOR (StoreFlow122) sequences cold-path parent/successor reads, pinned
state, exact linkage and chainwork continuity. Optional native storage preserves
deferred construction and lifetime through publication; height rules are reused.
Evidence `bmm-successor-*`: 178 properties / 1,780,000 cases; 1,099 native tests /
31,751,341 assertions; three CTests and both isolated installed consumers. The
256-scenario trace/fault test adds 2,514 assertions. Broader fork migration and
platform qualification remain; no net LOC reduction or live RPC testing is claimed.
The repeated native BMM test runners are a concrete consolidation candidate.

The four plain BMM trace/fault tests share a test-only runner, reducing
drivechain_peg_tests.cpp by 33 lines without changing their assertion counts
(2,514 / 1,194 / 75 / 405). Specialized lock/atomic tests stay separate.
Evidence `bmm-test-consolidation-*`: rebuilt native suite, 1,099 cases /
31,883,529 assertions passed. No Haskell or production change in this cleanup;
Haskell/installed-consumer checks were not rerun. Broad migration remains active.

AUTHENTICATED_JSON (StoreFlow123) migrates enforcer response-admission sequencing
in mainchainrpc_ecx.cpp. mTLS transport, endpoint comparison, time/output limits,
JSON parsing and diagnostics remain native; lazy admission and response clearing
retain their order. Evidence `authenticated-json-*`: 179 properties / 1,790,000
cases; 1,100 native tests / 31,829,235 assertions; three CTests and both isolated
installed consumers. The shared runner covers 2,048 scenarios and per-action
faults with 46,077 assertions. No live network qualification or overall LOC
reduction is claimed. Bid/peg-data/ECX paths and broader migration remain.

BMM_BID_PREFLIGHT/BMM_BID_TXID (StoreFlow124/125) sequence bid numeric/identity
admission and response transaction-ID publication. Existing numeric rules handle
signed slots and the full unsigned bid range; native JSON/hex conversion and the
original exception boundary remain. Evidence `bmm-bid-admission-*`: 180 properties
/ 1,800,000 cases, 1,101 native tests / 31,644,054 assertions, three CTests and
isolated installed consumers. New trace/fault/boundary test: 1,030 assertions.
No live bids, overall LOC reduction or whole-refactor completion is claimed.
Request construction, checked mainchain RPC and peg-data/ECX policy remain.

The ECX checked-RPC wrapper reuses CheckDrivechainRPCReply (nine production lines
removed). Evidence `ecx-rpc-reuse-*`: build and helper regressions passed (2,120
direct JSON assertions and 26 flow assertions), but both full native runs failed
the existing fake-grpcurl mTLS test. The last run passed 1,100/1,101 cases; five
assertions failed. Isolated failures and a sampled isolated pass were retained;
the shell sample showed loader startup, not a proven root cause. No timeout or
assertion was weakened. Full qualification remains outstanding; investigate the
child startup failure before treating this gate as passed.

Follow-up evidence `grpc-startup-*`: test-only command timing/status diagnostics,
four isolated mTLS passes and a full native pass (1,101 cases / 31,765,190
assertions). The original two-second timeout and assertions are unchanged.
This recovers the current native gate for ECX RPC reuse; the earlier startup
failures remain unexplained and preserved, not claimed fixed. Fixture-dependent
preserved-replay inspection was not run. Haskell/ABI checks were not rerun for
this test-only change; the broader migration remains incomplete.

Validator requests in mainchainrpc_ecx.cpp now use UniValue directly, removing
the static JSON string/reparse layer and eight production lines. Evidence
`validator-json-objects-*`: build and all 1,102 native cases / 31,677,099
assertions passed; new wire-equivalence regression passed 58 assertions. No
Haskell/ABI changes or new runs of those unchanged components. The local mTLS
fixture passed in 373 ms; earlier startup flakiness remains a residual risk.
Peg-data and other fork-policy migration is still unfinished.

The ECX field-alias wrapper reuses the existing Haskell-backed peg selector,
preserving strict get_obj() validation at the ECX boundary. The selector's
implementation is unchanged; it now has a node-internal header declaration.
Evidence `ecx-field-reuse-*`: native/library rebuild, 1,103 native cases /
31,561,098 assertions and three Haskell CTests passed. New strictness/reference
regression: 906 assertions. No new Haskell operation or public C ABI; properties
and installed consumers were not rerun. Peg-data traversal and broader migration
remain unfinished; earlier mTLS startup flakiness remains a residual risk.

Current-library compatibility refreshed against published 0.1.1.0 commit
d10f6168cddcb01e89517546dd5c4b8749829c3e using an isolated Cabal project.
Evidence `library-current-refresh-*`: latest 180 node properties plus eight
library properties passed 10,000 cases each, and the library's positive type
examples plus 21 compile-rejection cases passed. Production remains pinned to
0.1.0.0/1c93d574; the newer version was enabled only with a test-project override.
This is local source compatibility, not native packaging/platform qualification
or a deployed upgrade. The separate dirty library checkout was untouched.

Deposit verification reuses LESS for full-width input/witness bounds. Historical
v2 evidence uses SIGNED_HEIGHT_WINDOW (Record22), with subtraction guarded by
nonnegative tip and ordered bounds. Evidence `deposit-numeric-admission-*`:
181 properties / 1,810,000 cases; 1,104 native cases / 32,039,566 assertions;
three CTests and both isolated installed consumers passed. New boundary/laziness
regression: 391 assertions. No new payload/class/FFI symbol; no net LOC reduction,
live deposit or whole-refactor completion is claimed. Fixture-dependent preserved
replay was not loaded. Remaining evidence/RPC/ECX policy still needs migration.

The shared IsHexField predicate reuses PegSchema HEX for six ECX evidence checks
and the existing peg hex reader. Native decoding, diagnostics and catch/continue
boundaries remain unchanged; no new operation or FFI symbol. Evidence
`ecx-hex-reuse-*`: native/library builds, 1,105 native cases / 32,027,375
assertions and three Haskell CTests passed. New equivalence/mutation regression:
1,137 assertions. Haskell source and public ABI are unchanged; properties and
installed consumers were not rerun. Remaining fork-policy migration is incomplete.

InboxEntry owns forced-action and deposit event serialization. The common input
contains chain ID, prior root and source txid; forced input then contains the body,
while deposit input contains the output hash and trader key. Five numeric fields
carry count, sidechain height, parent height, output index and kind/marker index.
The version and big-endian layout are Haskell rules; native tagged hashing and
tracker mutation remain outside the FFI. Invalid fields leave output untouched.
The same boundary provides STEP and WIDE_STEP codecs for root/count/event-hash
preimages. STEP encodes a uint64 count big-endian; WIDE_STEP preserves the existing
16 canonical counter bytes. Forced, deposit, bond and successor-bond inbox chains
use these codecs with their original distinct native hash tags.
BOND and WIDE_BOND extend that boundary with the seven-field numeric projection
and five hashes used by canonical bond entries. The suffix holds the 499-byte
marker tail, prefixed by the canonical 16-byte counter for WIDE_BOND. Haskell
produces exactly 700/708 bytes and checks the encoded length before copying. The
native duplicate fixed-size checks are removed; invalid codec inputs fail through
the adapter. Script parsing, hash tags and source exports remain native.
SourceBytes shares the bond and successor-bond deduplicated byte-budget rule.
It checks uint32 overflow before updating either total, then checks configured
caps against the updated totals. The existing inbox ABI mode 2 takes six words
(two totals, two additions, two limits) and returns two totals; status 1 denotes
overflow and status 2 denotes exceeded caps. Modes 0/1 retain their output schema.
Native callers invoke it only after a newly inserted source identity, preserving
deduplication and the profile-specific diagnostics.
MarkerBounds (inbox ABI mode 3, eleven fields) checks process-deadline overflow,
enqueue refund delay and marker/index bounds in that order. Its result uses the
presence/deadline schema: deadline overflow leaves the caller's deadline unchanged,
while later failures retain the computed deadline. Finite counter exhaustion is
checked here; successor 128-bit increment overflow remains at its original later
point. Marker count is compared for equality, preserving the existing rule.
BondMarker validates the decoded 503-byte marker against four frozen identities,
required nonzero commitments, bundle bounds, receipt quorum and staging sentinels.
Its call stays after native field decoding to preserve partially parsed output on
domain rejection. Identity/availability errors precede staging errors. Script
framing uses MarkerFrame; context hashing and wrapper signature verification stay native. This
validator does not claim to authenticate a signature on its own.
MARKER_CONTEXT reuses the inbox encoder to extract the canonical 236-byte context
from a 503-byte marker. It binds chain/configuration, action/staging/refund fields,
payload commitment and source authorization; the native profile-specific tagged
hash is unchanged. It runs after claim validation. Native tests mutate every
marker byte to verify both included and excluded fields.
MarkerFrame uses inbox ABI modes 7/8 to decode the exact finite/successor bond
script: OP_RETURN, minimal PUSHDATA2 of 503 bytes, ECXB magic, profile version and
kind 0..3, with no trailing bytes. Native payload output changes only on success.
The main parser and both immutable re-extraction sites share it; their existing
caller-specific diagnostics remain unchanged. Native differential tests retain
the former GetOp sequence as an independent reference.

LegacyMarkerFrame uses inbox ABI modes 16/17 for the ECXF forced-action and
ECXD deposit frames. It returns the payload only for one exact OP_RETURN push:
PUSHDATA1 with 8..255 payload bytes for ECXF, or a direct 73-byte push for ECXD.
The short PUSHDATA1 cases intentionally retain the old framing acceptance;
envelope/body validation still rejects invalid actions afterward. This decoder
does not validate the marker output, chain identity, trader key, or action body.
Those subsequent checks and their diagnostic order remain unchanged. The native
adapter bounds allocation before the FFI and leaves output untouched on failure.
QuickCheck covers payload preservation, mutation, nulls, capacities and output
canaries; the native differential test covers every prefix-byte value at lengths
0..260 against the original GetOp parser.

CustodyReceipts decodes the 3..5 ordered 138-byte receipts after bundle commitment
verification, preserving length/version/signer/EOF error precedence. The separate
receipt ABI returns concatenated receipts plus a one-byte signer bitmap, and writes
nothing on rejection. Its input copy is bounded to count*140+1 bytes: one extra byte
is enough to reject trailing data without copying an arbitrarily large annex.
Native tagged hashing and custody cryptography remain unchanged; decoding
does not establish authenticity. The native differential oracle retains the prior
loop and tests every truncation and byte mutation for each supported receipt count.

AnnexHeader reads only the 15-byte prefix/version/bundle-length/receipt-count header,
using the full annex size solely for bounds admission. It rejects malformed framing
before bundle/count policy and leaves native outputs untouched on failure. The
CUSTODY_WITNESS transaction-shape phase guards input/witness presence, scriptSig,
proof fields, stack size and signature length before examining other inputs for
duplicate annexes. Native projections cannot index a witness/stack before its guard
passes. Bundle hashing still follows these checks and precedes receipt decoding.
The signed-source regression mutates real witness fields and headers, and the
ordered-admission tests enumerate all 512 witness fact combinations and exceptions.

CustodyRoot now owns receipt binding/exact/leaf preimages and the ordered padded
Merkle tree. It accepts six raw identities and flattened fixed-size receipts;
native code supplies only tagged SHA-256 through a bounded callback. Hash stages
are binding, exact receipt, empty root, indexed leaf, padding, and ordered branch
(0..5). All receipt hashes precede indexed leaves, then padding and tree levels,
matching the former native effect order, even when padding is unused. Callback
exceptions stop hashing and are rethrown by the native adapter before a root is
published. The hash callback must not reenter Haskell. The receipt decoder remains
responsible for receipt authenticity prerequisites; root encoding is not signature
verification. Independent native tests compare every preimage, hash call and root
for zero through five receipts, plus every callback failure position.

SourceAdmission owns the frozen relay profile, source shape and exact serialized
byte-cap gate. Its numeric reads are ordered: five profile flags, four frozen
limits, five upstream transaction facts, transaction size, then witness size.
Native serialization occurs only when Haskell requests the corresponding size;
transaction failure suppresses witness serialization. Zero is invalid at every
stage, so a captured native exception returns zero to stop evaluation, then the
adapter rethrows the original exception without changing the error string. Native
serialization callbacks must not reenter Haskell. Existing upstream transaction
code supplies the bytes; Haskell owns 64-KiB/eight-entry/576-KiB/768-KiB policy.

SourceAuthorization extends the existing inbox codec (modes 9/10; 7/8 remain
marker-frame modes). Non-staged encoding is four hashes followed by the low 32 bits
of the output index, preserving the original PushU32Be conversion. Staged encoding
is the u32 length and exact native-serialized output, then intent/refund hashes and
u64 refund height. Its caller still validates serialization bounds before encoding.
Both profile-specific tagged hashes stay native. Bond marker envelopes now reuse
CheckMarkerOutput and its Haskell-backed six-field OutputProfile; no parallel
envelope validator or FFI symbol was added.

The marker uniqueness, staging index/output/serialized-size, authorization equality
and final singleton checks now share TransactionShape phases 8..13. Ordered native
projections retain safe access: staging output lookup follows both index checks,
and witness indexing follows its size guard. RenderBondInboxStagingV18 remains
between phases, never in a callback, because its codecs can call Haskell. Native
counter/list mutations and serialization remain at their original points. The
phase oracle covers every fact combination and exception position, while the real
signed-source fixture covers malformed commitments/proofs, missing witnesses,
duplicate/absent markers and authorization mismatch.

Custodian registry validation and wire decoding share registryRecords. Index/zero
key failure excludes the current record from the returned prefix; duplicate-key
failure includes it, matching configuration's original partial key updates. The
decoder adapter applies precisely that prefix before throwing the original error.
The 325-byte indexed X25519/Ed25519 encoding uses inbox mode 11; custody verification
no longer has a separate native encoder. Encoding deliberately does not validate
key policy. Native hashes and cryptographic verification continue to consume the
same bytes. Regression tests compare both key arrays after every rejection.

Inbox accumulation reuses SourceMarker for forced/deposit multiplicity, as does
source-transaction policy. Parsing still precedes admission for each marker.
ConsensusConfigured computes the guarded BMM identity predicate before entering
ExchangeConfiguration: its lazy identity initialization calls Haskell and cannot
run within the native callback. Test this from a fresh process, since other suites
can initialize the identity and mask a nested-entry deadlock:

```sh
test_elements --run_test=ecx_exchange_state_tests/header_rules_cover_before_activation_boundary_and_descendants
test_elements --run_test=ecx_exchange_state_tests
```

FFI reference: https://downloads.haskell.org/ghc/9.14.1/docs/users_guide/exts/ffi.html
# USDD proof admission

`Usdd.Annex` validates the annex namespace, header, lengths, identities and
strong-execution digest using at most 87 copied bytes. The full input length and
network's envelope/proof/digest profile are explicit inputs. Native code resets
the view first and constructs borrowed spans only after successful validation;
opaque proof bytes are not copied into Haskell. Earlier error precedence remains
unchanged, including namespace rejection before size rejection.

`Usdd.Admission` owns the admission sequence for the
strong-execution and parameterized proof lanes: annex validation, statement
selection, deferred native identity facts, then identity/BMM/activation policy.
The old proof-gate export is retired; `ProofGate` is an internal rule. A native
identity callback runs once only for an eligible strong statement, and
never for the parameterized lane. It must not reenter Haskell. The callback
uses borrowed spans only during the call; upstream cryptography remains native.
`READY_FOR_JET` permits verifier execution, not a state transition. The ABI
rejects invalid modes, boolean words, identity results and missing callbacks.
Standalone annex parsing retains its export because callers also need that
operation independently of proof admission. Both paths share `Usdd.Annex`.

Admission ABI v4 retires lane 0, rejecting it before any callback. Lane 1 retains
four failure bits (configuration, controller, guest, digest).
Haskell checks the 0..15 bound and selects errors in that order. Native code only
compares spans and checks lengths/nonzero values for this lane. Lane 2 never calls
the adapter. Combined-failure and invalid-fact tests freeze the decision order;
the network profile and verifier activation are unchanged.

The obsolete legacy fact encoding, rule and standalone identity export are gone.
Native gate tests now use real raw annexes for all identity errors and BMM/activation
outcomes; the retired lane is tested for rejection without invoking its callback.
Production legacy
admission and standalone policy/resource callers now use raw ABI
`elements_hs_usdd_legacy_v2`; only SHA-256 runs in its native callback.

`Usdd.Journal` replaces the native production parser. It preserves header-before-hash and hash-before-payload
validation ordering and returns the authenticated domain only on success. Its hash
function is an explicit effect; malformed adapter output is an exception, not a
journal error. The old native parser lives only in `test/usdd_journal_reference.h`
for differential tests. Calling the Haskell workflow from a native identity
callback would re-enter Haskell and is forbidden; the raw boundary avoids this.

`Usdd.LegacyRequest` composes raw controller/guest checks, `Journal`, and deployment
domain decisions with hashing as its only effect. Its expected identities must be
the pinned native deployment constants, not transaction-provided values.
`domainIdentity` preserves V1/V2 semantics: V2 requires a zero global domain and a
nonzero journal domain, not an alternate deployment allowlist.
Admission validates the bounded annex prefix
before copying its journal, then uses the same raw identity workflow as standalone
checks. Native callers provide the pinned identities and deployment profile; the
transaction cannot substitute its own expected identity. The boundary checks modes,
boolean flags, null pointers and representable lengths before dereferencing fields.
Native differential tests include a required valid fixture, truncated headers,
mutations both with and without recalculated payload hashes, payload size boundaries,
deployment versions, and configured-domain lengths. No live deployment is implied.

Raw ABI v2 adds resource mode to this same boundary. Its four shape words are
witness-item count, control-block size, first control byte (zero when absent),
and the pinned parameterized-profile flag. The carried controller span supplies
its own length. `Usdd.Resource` checks namespace eligibility, parser errors,
parameterized statement kind and exact Tapsimplicity shape before invoking the
shared legacy identity action. Parameterized resources never invoke that action.
The result bits are namespace, oversize, malformed envelope, wrong shape,
controller, guest, public values, deployment and domain, in that order.
`GetUsddSp1AnnexResourceUsage` retains native witness traversal, safe span
projection and bit/count aggregation; resource decisions are Haskell-owned.
An existing native namespace predicate skips unrelated witnesses before entering
the FFI; Haskell rechecks that predicate for every submitted resource request.
Policy callers reuse the completed resource scan rather than reparse and repeat
shape/identity checks. Their separate unknown-annex, activation, network, UTXO,
duplicate-annex and weight checks remain in place. Resource admission is not
proof verification or authorization of a spend.
No control body or proof bytes are copied solely for shape checks. Prefix reads
are bounded to 87 bytes, and the journal is copied only after valid parsing and
shape admission. The original scanner is kept in a test-only reference header.

## Shared Native Callback Imports

Parent replay store ABI v2 replaces v1. Phase `UINT32_MAX` with result zero
queries the per-flow action bound maintained beside `ParentReplay.StoreFlow`;
other metadata queries and unknown kinds reject. Ordinary phases retain their
previous semantics. The native action pump validates bounds in 1..255, then
retains its per-kind step, status, terminal and committing-bit checks. Actions
still run after the interpreter returns; this does not introduce FFI re-entry.

`BLOCK_ADMISSION` composes parent replay rule/configuration checks, proposal and
coinbase consistency, CTIP balance validation, and ordered global-slot/prior-M4
traversal. Haskell owns short-circuiting, loop advancement and error selection;
native actions project objects and reuse the existing validators. The initial
deadline check and output clearing stay before admission. No state is mutated
by admission, and coinbase collection/M8 acceptance still precede replay writes.
Nested validator calls are safe because the outer transition has already returned.

`TRANSACTION_REPLAY` composes CTIP owner, spend, output, replacement and delta
validation before selecting no-op, M6 withdrawal, or M5 deposit processing. It
short-circuits after the first failed stage without rolling back earlier effects,
matching replay's existing prefix-mutation contract. The selected M5/M6 flow is
the existing interpreter; no withdrawal or deposit policy is duplicated here.

`BLOCK_REPLAY` sequences admission, coinbase collection, M8 acceptance, message
dispatch, proposal expiry, withdrawal expiry, transaction replay, slot pruning,
and final publication. Each stage reuses existing flows. Initial deadline/output
clearing stays before the workflow; final deadline checking stays after output
publication. An M8 rejection leaves state untouched, while later failures retain
earlier replay effects. Only parsed messages, the accepted M7 map and derived
output vectors span stages; per-stage iterators remain native and local.

`USDD_GENESIS` (selector 129) is retired and rejects all calls. Inherited genesis
dry-run gating, output traversal and best-block publication stay native. Only
the fork-added persisted-accumulator rejection reuses Haskell's lazy pair rule;
native accumulator/index publication remains between output connection and
best-block publication. Tests cover real ConnectBlock modes and injected faults.

`USDD_ACCUMULATOR_CONNECTION` uses `Usdd.AccumulatorConnection` to admit the
predecessor, apply withdrawals and check persisted equality in the original order.
The application action invokes the existing Haskell block workflow only after
the outer transition has returned. Upstream dry-run/undo/timing code remains
native, with accumulator assignment still after successful undo storage. The
real undo-failure/retry fixture and corrupted-prior fixture guard that boundary.

`USDD_CHECKPOINT_CONNECTION` uses `Usdd.CheckpointConnection` for hash clearing,
slot/predecessor admission and checkpoint derivation. Its private native wrapper
requires an error reference: every caller supplies one. The existing derivation
workflow is invoked after the transition returns, and its errors are preserved.
No optional accumulator output remains on this wrapper; none of its callers used
that output. Public checkpoint/vector APIs are unchanged.

`Usdd.ClaimHashes` constructs burn-ID and leaf hash inputs and sequences both
hashes for accepted claims in one call. Modes 0/1 compute only the burn/leaf;
mode 2 returns burn32 followed by leaf32. The profile is prefix1/versionBE4 plus
two 32-byte domains. The private 168-byte input carries genesis/asset/vault32,
txid-or-burn32, voutBE4, indexBE8, amountBE8, recipient20. Standalone leaf mode
uses the supplied burn ID; combined mode substitutes the newly computed digest.
SHA-256 uses the existing native callback and cannot re-enter Haskell. Neither
digest is published if a callback fails. These are ABI bytes, not a new wire
format; existing independent cross-language claim vectors remain the oracle.
Test effect transcripts directly in Haskell and use native test doubles for this
unsafe FFI callback. A Haskell wrapper callback can deadlock by re-entering it.
ABI v2 replaces v1 and adds mode 3 for `Usdd.ClaimPrefix`: an initial index and
200-byte records (the 168-byte leaf input plus expected leaf32). It checks each
index before hashing its leaf and returns concatenated leaves only on complete
success. A counter range that would wrap is rejected. Empty batches are valid.
The native proof builder retains its up-front selected-index bounds check and
packs at most 128 records per call (25,600 bytes), bounding temporary ABI storage.
It publishes the selected claim only after every batch passes, then invokes the
existing Haskell inclusion-proof operation. Native batch packing does not make
canonicality decisions. Failures preserve the prior proof and root as before.

Mode 4 composes the existing withdrawal parser with combined claim hashing via
`Usdd.ExtractClaim`. Its 216-byte input is the existing 116-byte extraction request
followed by genesis32, asset32, txid32 and voutBE4. Success returns the existing
parsed amountLE8/vault32/recipient20 followed by burn32/leaf32 (124 bytes).
Code 1 skips a non-claim, code 2 rejects index overflow; neither writes output or
hashes. Hash failures also leave output untouched. Native code retains object
access and output publication, but accepted claims now cross into Haskell once
instead of separately for parsing and hashing. Block iteration still remains
native and is not claimed as migrated by mode 4 alone.

`Usdd.ExtractBlock` now drives transaction/output traversal, accepted-claim
counting, parse/hash sequencing, and incremental publication in one Haskell call
per block. Its native callback actions are 0 (transaction count), 1 (output count
plus one, or zero for a null transaction), 2 (script length and two fact bytes),
3 (publish the 124-byte claim), 4 (read the 216-byte candidate), and 5 (publish
an accumulator state). The v4 block export replaces v3 and retains an application
mode with prior count/state, empty roots and node prefix. Facts are explicit-asset, explicit-value, null-nonce and
nonzero-asset bits, followed by the first opcode (zero for an empty script).
Haskell requires length 67, flags 15, and OP_RETURN before invoking action 4.
Negative callback results abort; the C++ bridge
rethrows captured native exceptions after Haskell returns. Zero genesis precedes
all callbacks. A null transaction or index overflow preserves earlier published
claims. Native callbacks must not call Haskell. Object access and serialization
remain native; eligibility policy is now Haskell-owned.
`Usdd.ApplyBlock` validates the prior state before extraction, gathers accepted
leaves, publishes the prior state after extraction succeeds, then appends the
batch and publishes its final (possibly partial on overflow) state. Action 5
carries root/frontier2080 and the count in the callback's count argument. Native
code retains ownership transfer of optional claims only on success. Prior-state
bytes are copied before callbacks, so aliased previous/next objects are supported.
Hash exceptions during append leave the published prior state, as before.
Derivation mode uses `Usdd.DeriveBlock` to compose application and checkpoint
hashing. Action 6 obtains native block-hash/profile metadata after application
and clears the critical hash; its metadata includes whether previous/next alias.
Action 7 publishes a digest, or clears it on application rejection. A checkpoint
failure leaves the applied accumulator intact. Aliased callers commit final/final
as the existing API did; distinct callers commit the saved prior and final state.
Native block hashing and profile packing must remain free of Haskell calls.
This adds one block-workflow export and one callback interface (115/13 total),
replacing per-candidate native-to-Haskell calls with one block entry.

`Exchange.SourcePredecessor` uses mode 12 of the existing inbox-entry ABI to
check profile, nonzero heights/head, processed-count ordering and finite u64
representability, in that order. It compares u128 counters as big-endian bytes;
the successor profile retains the full width. Input is head32/count16/processed16
and seven Word64 fields (profile, proof profile, height, parent height, three
unused fields). Success returns head/count; rejection leaves output untouched.
No additional foreign export is needed.

`Exchange.SourceTracking` owns duplicate-wtxid fact checks and unique-source byte
budgets. Its ephemeral state is two BE32 totals followed by 104-byte records:
wtxid, txid, witness SHA256, witness length BE32, transaction length BE32. An
identical repeat bypasses accounting; conflicting facts reject before accounting.
The state never comes from chain data or disk and is discarded when block append
returns. The native caller initializes eight zero bytes and supplies authenticated
source facts after verification. The ABI receives four Word64 lengths/limits and
96 hash bytes, with output capacity of input-state size plus 104. On rejection
neither the output bytes nor written-length pointer changes. This replaces the
native map/counters without adding a native callback or an opaque GC-owned handle.

`Exchange.AppendMarker` owns one finite/successor inbox marker transition:
bounds, canonical frame, entry serialization, export publication, entry/step
hashing, and counter advance. It uses the shared `Check` interpreter and reuses
the custody-shaped callback import. Actions 0/1/2 publish deadline-BE64 plus entry,
hash the entry, and hash the step respectively. Native callbacks must not re-enter
Haskell; source and signature verification finish before calling this workflow.
The ABI takes 14 Word64 fields (11 MarkerBounds fields, sidechain height,
transaction size, witness size) and 683 bytes (five hashes, u128 counter, script).
Success publishes a 48-byte head/counter state; failures leave this buffer intact.
Exports precede both hashes and successor overflow rejection, so failure may leave
a visible export without advancing the caller's snapshot. Whole-block iteration,
source deduplication and snapshot publication still remain in the native adapter.

USDD withdrawal accumulator root calculation, sanity checking and append use one
`elements_hs_usdd_accumulator_v2` boundary. `Usdd.Accumulator` owns depth-64 traversal,
unused-frontier validation, carry propagation, clearing, overflow rejection and
root comparison. Native code supplies the pinned node prefix, cached empty roots
and fixed-size state/leaf buffers. SHA-256 reuses Deposit's existing hash callback;
it cannot re-enter Haskell. The state wire is a 32-byte root followed by 64
32-byte frontier nodes. Modes 0/1/2 compute, check and append respectively.
Mode 3 uses `Usdd.InclusionProof` to build siblings and the root from packed
32-byte leaves, then independently fold the chosen leaf through its siblings.
Its output wire is root plus 64 siblings. The native adapter rejects an invalid
claim index before hashing; `Usdd.ClaimPrefix` checks leaf canonicality before
this call. ABI v2 adds an explicit leaf count; legacy modes
require exactly one leaf, and proof mode rejects indexes outside the supplied
prefix before hashing. Count-to-byte conversion is checked before copying.
Failed checks/overflow do not publish output; append intentionally does not add
a new prior-state sanity requirement. Native serialization and the cached empty
root table remain unchanged. Differential tests cover every carry boundary and
dirty unused frontier nodes; existing cross-language commitments and round-trip
serialization remain regression gates.

Deposit header inspection shares the indexed Int32 callback import with opcode
inspection. Evidence decoding shares the output-field callback import with CTIP
decoding. Domain aliases remain at operation boundaries; they are not nominal
capability types. Each operation still owns its result-code checks and allocates
its exact output buffer (two Int64 fields for CTIP, three for evidence). This
deduplicates FFI declarations, not the native operations or their authorization.

Withdrawal `StateAnchor` shares the PXST preimage assembly between the wallet
and consensus envelope validation. Its private request is height[4, LE] followed
by genesis, previous-child, withdrawal and exchange commitments (32 bytes each).
After payload `Refl`, `WithdrawalRule` constructs version 1, slot 24, genesis,
height[4, BE], and the remaining commitments. Hashing stays native. This operation
does not reject zero commitments: wallet and consensus admission differ and stay
at their original call sites. Fixed vectors and independent ABI byte tests guard
the resulting 134-byte preimage. It reuses the withdrawal-byte export.

`Withdrawal.DestinationFlow` selects wallet destination decoding and admission
stages through the existing native action pump. It bounds hex before IsHex and
script size before IsStandard, then applies the original spendable-type allowlist.
The native adapter asserts the TxoutType ABI numbers and retains upstream address
decoding, parsing, classification and RPC errors. Each native action runs after
the Haskell transition returns. Unknown types are rejected, not treated as future
spendable classes. Tests freeze action order, errors and numeric boundaries.

`Withdrawal.WalletBundle` produces a payout and canonical fee script after
checking amount, fee, script length and outpoint presence. It reuses the existing
payout rule through `WithdrawalRule` after payload Refl. Its request is three
little-endian 64-bit words (amount, fee, script length) and a presence byte; its
18-byte success payload contains the payout and fee script. Native code retains
the upstream transaction serializer, input commitment hashing and txid hashing.
This is distinct from the existing context-bearing M6 format; neither format is
silently substituted for the other. Tests retain independent serialized vectors.

`WalletAnchor` reuses `StateAnchor` assembly after checking the wallet's required
genesis, withdrawal and exchange commitments. The previous-child hash may be zero.
Consensus callers retain the unchecked assembly operation; wallet-only rejection
is not imposed on consensus. The adapter translates only domain rejection to the
existing wallet RPC error. `StateMarker` constructs the canonical PXST OP_RETURN
script from the native tagged hash. Wallet marker admission still precedes bundle
amount validation, and fixed transaction vectors remain unchanged.

`BundleFlow` sequences wallet plan validation, native output construction,
optional marker insertion, upstream serialization, txid hashing and transport
encoding. Native actions run after each transition returns, allowing their own
Haskell calls without callback re-entry. `WalletTransport` adds the inputless
rust-bitcoin marker/flag after the version bytes; txid hashing still uses the
unmodified no-witness serialization. Its native adapter allocates an exact-size
reply with an Int32 size bound rather than the fixed small-operation buffer.
It is an internal byte transformation, not a transaction-validity check. Tests
cover absent/present markers, every effect-prefix exception and buffer canaries.

`EventFlow` traverses legacy wallet enforcer withdrawal events. Native actions
retain UniValue access, ParseHex and serialized-hash conversion. Haskell chooses
iteration, guards, first-match termination and submitted/succeeded/failed
precedence. An unknown status on a matching ID terminates with the empty result;
it does not search for a later recognized status. The action pump returns ordinals
0..3 for native string projection. This lookup is not authentication. Native
contract fixtures include invalid hex rejection and inter-byte whitespace.

`Withdrawal.PreflightFlow` (store flow 143) preserves legacy withdrawal readiness
ordering: tip presence, nonnegative height, uint32 height bound, configured fee,
TLS settings, executable, predecessor presence, ECX header bit, then non-null
state root. Each native callback supplies one fact; Haskell owns the conjunctions
and does not request height/header facts until their prerequisites pass.
Native rejection actions retain RPC errors; fee exceptions stop the
workflow, and TLS failure skips executable validation. This runs before the
existing submission flow can mutate the wallet or broadcast an irreversible burn.
The native trace test covers all 512 predicate combinations and every fault prefix;
QuickCheck compares direct and ABI traces, including malformed replies and faults.
it does not initiate a real withdrawal.

`Withdrawal.NativeSubmissionFlow` (270, bound 8) sequences the native withdrawal
send, committed wallet lookup, lazy wallet/transaction presence checks, burn-output
verification and optional verbose response. It runs only after existing preflight
and under the original wallet lock. Missing data preserves the RPC wallet error;
later failures never retry SendMoney. Native and QuickCheck traces exercise every
presence/verbosity combination, faults, malformed replies and direct/ABI parity.
The callback retains native wallet effects and JSON construction; it does not
submit an L1 bundle or change confirmation requirements.

`BindPriorActiveExchangeStateRoot` reuses `RequiredFactsFlow 4` (248) for ordered
exchange-root, forced-root, deposit-root and cursor lookup. Only successful
admission publishes the five staged values; rejection clears the five prior
context fields, while callback exceptions retain the original unwind behavior.
The native typed values never cross the FFI. Existing required-facts QuickCheck
and native trace tests cover all truth assignments, first-failure short circuit,
callback faults and malformed replies; this reuse needs no new flow or export.

The same binding uses `RequiredFactsFlow 3` (237, historically named
`REQUIRED_PROPOSAL` at the native boundary) for each bond identity triplet:
configuration hash, program ID, CMR. Both finite and successor evaluations still
occur, in that order, before the activation/frozen guards. Typed hash equality
remains native; Haskell owns conjunction and comparison short-circuiting.
`RequiredFactsFlow 2` guards predecessor/capital access. `BondContextFlow` (271,
bound 17) then reuses `RequiredFactsFlow 16` for activation, frozen status,
identity alternatives, asset/deployment equality, inbox-count conversion and ten
required commitments. Its identity reply is a two-bit finite/successor mask;
other replies remain boolean. Rejection leaves native reset adapters selected,
success selects typed publication, and exceptions retain unwind behavior.
QuickCheck and native traces cover each rejection point, alternative masks,
malformed replies and fault prefixes. No identity or commitment requirement is
removed by the migration.

`Deposit.DefaultWalletFlow` (store flow 142) controls the fork-added global
default-wallet fallback: load first, create only on `FAILED_NOT_FOUND`, stop on
all other failures. The native attempt adapter preserves fresh options/warnings/
errors, require-existing vs require-create, load verification disabled, creation
verification enabled, SQLite descriptor flags and load-on-start. It is called
only at the original zero-loaded-wallet fallback, not explicit wallet URIs or
multi-wallet selection. Native protocol tests cover every current database
status and injected exceptions, without creating a live wallet.

`Deposit.Preflight` shares signed-64-bit deposit argument validation through
`elements_hs_deposit_preflight_v1`. Rules 0/1 validate positive/nonnegative
native amounts against the supplied money bound; 2 preserves historical
positive-only values; 3 checks the historical fee against its deposit value;
4 checks uint32 output indices. Rules 5/9 require a true native-network/address
validity flag; 6 requires both Elements and parent-chain flags; 7/8 require both
the upstream hex-validity flag and exact-32-byte-length flag for txid/block hash.
Flag inputs accept only 1, never arbitrary nonzero values. Unknown rules return -1, domain rejection 0,
acceptance 1. Wallet call sites preserve parsing order, defaults and exact RPC
errors. Rule 10 allows federated peg-ins only when the native-slot flag is zero;
it shares the exact rejection diagnostic across all three legacy peg-in RPCs.
Network gates remain before wallet lookup. Rule 11 preserves the signed fee-cap
comparison without imposing a new nonnegative constraint; rule 2 also selects
positive sponsorship fees. These twelve rules share one
consolidated export, not one export per rule.

`BmmConstants.walletRpcRoute` owns deposit/withdrawal RPC factory selection.
The build generates the complete boolean route table: native slots take priority
over PAK for withdrawals; PAK never changes deposit routing. C++ binds factory
indices to the existing RPC handlers. The PAK accessor is a side-effect-free flag
read; no wallet or RPC factory is invoked while selecting the route. Golden tests
and native table tests enumerate all eight combinations. No runtime FFI is needed
for this finite policy, and the existing handler-specific admission gates remain.

`Deposit.NativeImportFlow` (store flow 141) sequences native deposit authentication,
transaction/witness construction, optional fee sponsorship and final immutable
transaction creation. The sponsorship action invokes `SponsorshipFlow` through
the shared safe callback. Its lexical wallet lock is released before finalization.
Protocol tests cover authentication failure, zero-fee bypass, nested signing
failure, prerequisite effects and exceptions at every visited outer/inner action.
RPC preflight and native transaction primitives remain outside Haskell.

`Deposit.ImportFlow` (store flow 140) sequences historical ECX deposit assembly:
base transaction, optional fee output, provisional witness, verification,
authenticated evidence, final witness, then final immutable transaction.
Verification and evidence failures retain separate native RPC errors. No final
witness or transaction is authorized after either failure. Native actions retain
the existing serializers and cryptographic verification implementations. Trace
tests inject exceptions at each visited action and check prerequisite effects;
QuickCheck covers the transition table and invalid replies. This is not a live
deposit test and does not migrate RPC preflight or the native import path.

`Deposit.SponsorshipFlow` (store flow 139) drives native deposit post-funding
admission, fee-cap rejection, selected-coin scanning and signing. The native
wallet lock encloses the entire action pump, preserving its original lifetime.
Funding and wallet/transaction primitives remain native; no callback reenters
Haskell. Rejection actions throw the original RPC errors and cannot continue to
signing. Zero-fee bypass and pre-funding preparation remain native. The native
trace test covers each rejection and injects exceptions at every visited action;
QuickCheck checks the full transition table, metadata and malformed replies.

`Deposit.SatoshiFlow` (store flow 138) shares number/string parsing across native
and historical deposit value/fee arguments. Native UniValue integer conversion
and ParseInt64 are retained, including their distinct error behavior; Haskell
selects the path and controls invalid-type/string rejection. Fee defaults and
monetary limits remain at their original call sites. Numeric conversion failures
propagate unchanged, while invalid strings/types retain the field-specific
RPC_INVALID_PARAMETER message. Regression tests compare the prior parser over
signed extremes, overflow, fractions, exponent notation, whitespace and NULs.

`Deposit.BroadcastFlow` (store flow 137) is shared by native and historical
deposit-import RPCs. Known wallet transactions skip broadcasting; a successful
single broadcast sets only the broadcast flag; recognized chain/mempool replay
messages set only already_imported. Other failures preserve RPC_TRANSACTION_REJECTED
and the original error bytes. Native string lookup remains an adapter. The old
third substring, "Transaction already in block chain", is subsumed by the first
"already in block chain" and has been removed without changing accepted strings.
Authentication and wallet-known lookup stay before this helper. Broadcast calls
run after the Haskell transition returns and exceptions stop the workflow.

`NativeGuard` (byte operation 23) validates the wallet's network availability,
withdrawal activation, subtract-fee and relay-policy booleans. Its two-byte frame
holds a stage 0..4 and strict boolean. Subtract-fee rejects true; the other stages
require true. Domain rejection retains the original error text. `NativeGuardResult`
(byte operation 24) shares that rule and returns a signed LE32 RPC code followed
by the message, or four zero bytes on acceptance. Haskell maps stages 0/1 to
METHOD_NOT_FOUND, 2/3 to INVALID_PARAMETER, and stage 4 (legacy Elements/parent-chain
support) to MISC_ERROR. The native RPC adapter only decodes and throws the result.
Operation 23 retains its original success/domain-error framing for compatibility;
malformed requests to either operation remain ABI failures. No export is added. The
caller preserves evaluation order: network then activation before wallet lookup,
subtract-fee after dust validation, and relay after script construction. Unknown
stages/flags fail closed through the existing ABI guard, not a policy default.

`ParentDust` (byte operation 22) computes the wallet's Bitcoin parent dust
threshold, not Elements dust. Native code retains witness-program detection and
Bitcoin CTxOut serialization. The five-byte request holds a LE32 serialized size
and strict witness boolean; Haskell adds 67 witness or 148 legacy spend bytes
with the existing uint32 semantics, then multiplies by three. At the fixed 3,000
sat/kvB rate this equals CFeeRate's calculation; a native static assertion guards
that rate assumption. Regression tests compare against CFeeRate for standard and
unusual scripts and uint32 boundaries. Unspendable/empty scripts are not given a
new special case: destination validation precedes the helper in the RPC.

`NativePayout` (byte operation 26) combines native payout admission and parent
dust validation in one interpreter evaluation. The 13-byte request contains
signed LE64 payout followed by the existing five-byte parent-dust frame. Its
12-byte reply is a signed LE32 RPC status (0, -3 monetary rejection, or -8 dust)
and LE64 dust threshold. Monetary rejection has precedence over dust. The
native adapter retains Bitcoin serialization, witness detection, and upstream
FormatMoney rendering; it no longer makes the monetary/dust decision. This
replaces two wallet boundary calls with one without adding a foreign export.

`NativeBurnPlan` (byte operation 27) continues preparation after payout admission
and native parameter parsing. Its request holds signed LE64 payout and parent
fee, the 32-byte parent genesis, and the destination script. It composes the
existing NativeAmount total rule and BuildScript capability method in that
order. A signed LE32 status prefixes either error text (-3 monetary, -8 script)
or the successful LE64 burn amount and canonical script. The C++ adapter checks
the response and throws the existing RPC exception. This removes another FFI
round trip without moving signing, wallet locking, or commit side effects into
callbacks. The payout-admitted precondition matches the former total helper.
Guard, burn-plan, and output-selection results share `encodeRpcResult`.
Their internal `Either (Int32, String) ByteString` values keep domain failures
structured until the boundary; burn-plan `do` sequencing short-circuits before
script construction when monetary admission fails. No wire format changes.

`NativeAmount` (byte operation 21) performs the wallet's monetary
preflight phases: validate a positive payout within MAX_MONEY, then validate the
parent fee and add it without exceeding MAX_MONEY. The 17-byte frame contains a
0/1/2 mode followed by signed little-endian payout and fee amounts. The first
phase ignores the fee; the second retains the original fee/total rule and assumes
the caller already validated the payout. The native RPC now uses NativePayout
for its first phase, with subtract-fee parsing still before the total check.
Domain
failures map to the original RPC_TYPE_ERROR text; malformed ABI frames fail
before interpretation. Mode 2 retains the legacy positive-only payout rule and
"Invalid amount for send" error, ignoring the fee without adding a money cap.
Only `LegacyWithdrawalAmount` remains as a native amount adapter; native callers
use the combined payout/burn workflows. Older modes remain byte-ABI regression
targets through the existing interpreter/export. `WithdrawalCheck` similarly
shares network guards between native and legacy RPCs.

`NativeOutputSelection` (byte operation 28) now owns native wallet burn-output
selection in one invocation. Native code projects every output
into 49-byte records: LE32 original output index, 32-byte explicit asset (or
zero), four asset/value/nonce/proof flags, signed LE64 amount, and an exact-script
comparison flag. Haskell skips records whose comparison flag is not one before
parsing their withdrawal fields. The header
contains expected asset and parent (32 bytes each), burn/payout/fee (LE64), and
LE32 script size followed by the common script. Haskell validates frame bounds,
reuses the native output parser, checks amounts, and rejects missing or duplicate
matches. It returns a signed RPC status with either the LE32 index or error
text. This replaces the per-field native switch and repeated FFI transitions;
native transaction serialization and field inspection remain native. Store
flow 136 remains available for compatibility, but the wallet no longer uses it.

The retained `OutputFlow` (store flow 136) models the earlier selection. It filters
the exact script before parsing the optional witness, checks burn/payout/fee in
order, and continues through the entire output list to reject duplicates. A
missing or duplicate matching output retains the wallet RPC error. C++ retains
transaction access, the upstream/native parser adapter and result storage; all
actions use the shared safe callback, permitting nested parser
calls into Haskell. Native object tests cover wrong assets, amounts, nonce,
script, absent/empty/nonempty witnesses, and duplicate or missing outputs.

`SubmissionFlow` (store flow 135) owns the legacy wallet submission sequence:
clear finalized bundle, reserve creation, send, resolve wallet transaction, scan
for the first withdrawal output, construct the bundle, broadcast, complete the
reservation, verify the L1 event, and format the response. Native actions use
the shared safe callback. Exceptions stop the sequence and
unwind the native reservation guard. Completion deliberately precedes event
verification: a later verification error must not release an already-submitted
bundle. Missing wallet transactions and missing outputs retain their original
RPC errors and precedence. Preflight and object/storage access remain native.
Fault-prefix tests cover all actions, missing data, first/later matches and both
response modes; these do not substitute for live RPC integration qualification.

`Bmm.GrpcExecutableFlow` (kind 146) orders absolute-path, platform support,
private-file and executable-access checks. Native adapters keep the OS-specific
predicates and diagnostics. Windows still rejects execution; this migration does
not enable a new platform transport. Request and executable flows reuse the
existing strict transition-table helper. Temporary-file tests never execute the
fixture. Method names and argv construction are handled by `GrpcPlan` below.

`Bmm.RpcServerFlow` (kind 147) rejects REST, validates the default port, and
iterates configured bindings in that order. Port validation reuses bounded
positive-value rule 0 from the existing preflight interface with bound 65535.
Native code retains ArgsManager, address splitting and diagnostics. Action 7
reports nonzero-port/nonempty-host facts; only valid facts reach action 10's
existing loopback validator. Haskell preserves first-invalid-binding rejection
and does not request loopback validation for an empty host or zero port.
No credential or listening socket is created by this workflow.

Replay record kind 23 centralizes configured-slot matching: configuration must
be present, both slots must be in 0..255 and the requested slot must match exactly.
Native parent RPC callers share this rule while retaining absent-configuration
and mismatch diagnostics. No network setting is modified by evaluation.

Genesis codec modes 5/6/7 encode the fixed ECX availability-scheme, custody
receipt and risk profiles (383/100/41 bytes). All take zero input bytes; hashing and domain
tags remain in the native adapter. Native layout parity tests preserve every
identity string, endian encoding and separator. Other modes retain their existing
nonempty input requirements and output sizes.
The frozen configuration decoder compares the risk segment to the canonical
encoding, preserving its existing risk-profile diagnostic. The native fixture
checks the full configuration hash and rejects mutations at every risk byte.

Inbox codec modes 13/14 encode staging descriptor/hidden-node preimages with
four/six 32-byte identities. Mode 13 inserts tree version 1 and a one-byte leaf
version; mode 14 inserts a big-endian uint32 output index and uint64 refund
height. Width checks reject overflow before copying output. Native code keeps
input admission, tagged hashing and Taproot operations; Rust vectors cover the
resulting commitments and output script. These modes share the existing ABI.
Transaction-shape phase 14 sequences the staging renderer's 16 input checks
in their original order, rejecting on the first failure. Native callbacks read
identities and validate the public key without re-entering Haskell; encoding
and hashing run only after admission returns. The existing error is unchanged.
Replay-store flow 149 sequences source-transaction scanning, marker parsing,
uniqueness, staged/non-staged authorization and witness verification. Native
actions run after the Haskell transition returns, allowing their existing
Haskell-backed validators without unsafe nested callback entry. Final singleton
validation follows the last output; failed checks never advance the iterator.
Flow 150 controls nested block-source scanning. Snapshot head/count publication
is the final action, reached only after all transactions and outputs pass.
Exported entries retain their previous incremental behavior: a later failure
does not undo entries already appended. Native action scopes keep serialization
buffers alive across marker exports; each new candidate transaction clears them.

### One declared capability list

`GrpcCapabilities`, `ScriptCapabilities` and `WithdrawalCapabilities` are shared
between each Operation instance and its GADT context. Use
`CapabilityContext DeclaredCaps ConcreteOperation` for the latter: it is a
nominal class carrying `Capabilities DeclaredCaps ConcreteOperation` as a
superclass. Directly using the reducing `Capabilities` type family as Context
does not satisfy the library's injective Context declaration on GHC 9.6.7.
The wrapper preserves that declaration without casts or weakening uniqueness.

After `eqT`/`Refl`, the same declared dictionaries expose each specific class
method. Helpers should still request only the capabilities they use; a complete
operation context is unnecessary for a decoder, planner or effect adapter.
Declare additional capabilities only for real shared contracts, not to inflate
the list. The
wrapper adds no runtime validation and does not prove any policy succeeded.

`Workflow.Finalize` is shared by state encoding, state replacement and signet
script extraction. Associated `FinalInput`/`FinalResult` types distinguish the
completion contracts: unit/unit, Word32/unit and Bool/Int32 respectively.
The latter declares `[ScriptStream, ScriptRewrite, Finalize]`; after payload
Refl, the generic loop reads, rewrites and finalizes using these dictionaries.
Failed parsing never finalizes; completed extraction publishes only when a
solution was captured. State preparation failure likewise prevents publishing.
The class shares completion structure, not the underlying effects or validation.

The frozen-bounds ABI accepts 16 fields for the original fixed bond limits,
9 for their inbox segment, 5 for their proof segment, or 17 fields for
hybrid-oracle numeric policy (schedule origin, epoch length,
source/Truthcoin confirmation minima, anchor/snapshot ages, liquidity, samples,
base/max weights, initial/max bands, haircut, boundary, deviation, ECX/USDD
conversion units). Schedule origin is unrestricted. Haskell checks positivity,
ordering and strict limits; the half-billion boundary check avoids arithmetic
overflow. Native parsing/identity checks precede policy evaluation. Parsing
the complete numeric segment on rejection only advances a private cursor; the
existing hybrid-oracle error and externally visible decoded fields are retained.
The decoder and frozen-state validator share the 9/5-field predicates. Decoder
callers discard the local decoded record on failure; segment-level evaluation
therefore preserves observable rejection behavior and existing diagnostics.

`Bmm.CredentialFlow` (kind 148) orders TLS regular-file, ownership, parent
directory, permission and secure-open checks. The first result distinguishes
rejection, POSIX and Windows. File open/fstat/close stay within one native action:
no descriptor crosses a Haskell transition. Platform-specific syscalls and
permission masks are unchanged, including no-follow/non-blocking open flags and
device/inode comparison. Windows retains its existing readable-file path.

Withdrawal preflight, output, submission, event, bundle and destination flows
share `ParentReplay.transition` with deposit and transport flows. Tables list
false/true successors and reject non-boolean replies; numeric result stages stay
explicit. Initial phase zero and terminal/error codes retain their prior meaning.
This consolidation removes duplicated branch/effect helpers without changing
action numbers, native ownership or failure ordering.

`Bmm.GrpcPlan` separates `GrpcPolicy` admission from
`GrpcArguments` construction. After payload `Refl`, rejection returns immediately;
acceptance returns a deferred function over the associated configuration type.
It preserves argument bytes and never invokes a shell. The native transport uses
`elements_hs_grpc_plan_v1` for admission and argv construction. One field checks
only the method (without a placeholder payload). Two fields admit
method/payload; eight add executable, CA, certificate, key, authority and address.
Replies contain a status byte followed by little-endian 32-bit length-prefixed
arguments (or diagnostic text on rejection). Native framing is bounded below
INT32_MAX; malformed replies throw before execution. Method-only preflight preserves
the separate payload/JSON check order.
Admission does not establish JSON validity or credential/executable security.

`Bmm.GrpcRequestFlow` (kind 145) owns request admission order: allowlisted method,
bounded payload, JSON object, TLS configuration, executable validation, then
command execution. Native adapters retain each predicate and exact diagnostic.
TLS validation may itself invoke kind 144 because actions execute after each
Haskell transition has returned. Process result, timeout, output bound and
cancellation semantics are unchanged. Tests cover failure and exception prefixes
and production rejection before any process execution. OS-specific executable
predicates and process execution remain native.

`Bmm.GrpcConfigFlow` sequences enforcer TLS configuration validation through the
existing replay-store action interface (kind 144). Endpoint syntax, numeric
loopback, endpoint agreement, authentication mode and authority checks precede
CA, certificate and private-key file validation. C++ retains argument parsing,
filesystem checks and exact diagnostic strings. No credential bytes cross the
FFI. A failed check stops the sequence; an exception cannot execute later checks.
Stage 5 reports three parsed facts (nonempty host, no leading hyphen, nonzero
port); Haskell requires all three. Stages 9/11 report optional endpoint presence,
and only present options reach equality checks 20/21. Native callbacks execute
synchronously inside the shared Haskell flow; absent options are never read.

`BundleAdmission` owns withdrawal reservation and conditional-clear admission.
Its 65-byte input is a strict boolean reservation byte followed by the current
and requested 32-byte bundle hashes. The two result bytes permit creation only
when idle and empty, and permit clearing only an exact hash match (including
null/null). Clear deliberately ignores the reservation flag. C++ holds the
bundle mutex across evaluation and the corresponding mutation; reset, completion,
envelope storage and RAII cleanup remain native. No callback is invoked by this
operation. Malformed frames and non-boolean flags fail closed.

`RpcFee` preserves the legacy RPC fee rule: positive, at most MAX_MONEY and less
than amount. Unlike the bundle payout rule it does not independently bound the
amount; callers perform their own amount parsing. `EventPolicy` returns separate
verification-rejection and final-bundle-clear decisions. Missing and failed
statuses reject verification; only succeeded/failed clear a bundle. Unknown
nonempty statuses retain the original accepted-but-not-final behavior. Native
adapters preserve RPC error codes and presentation, and no network action occurs
inside these pure operations.

Wallet bundle construction now uses `WalletBundleRequest` and the
`BuildWalletBundle` DSL. After payload equality, planning produces an abstract
`BundlePlan`, the native construction callback supplies canonical no-witness
transaction bytes, and Haskell assembles the transport. The callback must not
reenter Haskell and its returned storage must remain valid through the call.
The standalone native `PlanWithdrawalBundle` wrapper is removed. Replay-store
kind 133 (`WITHDRAWAL_BUNDLE`) is reserved and always rejected without callbacks;
later kind IDs retain their values. Internal consumers of that old flow must
switch to `BuildWithdrawalBundle` and rebuild. The exported domain count is
unchanged.

The construction callback's internal payload starts with LE32 transaction version,
a byte-sized role count, and that many ordered output roles: fee (0), inputs
commitment (1), payout (2), state marker (3). Haskell selects version 2 and roles
0/1/2, appending role 3 only for an anchored plan. Existing fee/input/marker
payloads follow the prefix. Native code materializes the typed outputs and uses
upstream hashing and transaction serialization; it does not choose the layout.
This internal callback format requires rebuilding both components together;
neither transaction bytes nor the external RPC format changes.

The version-2 wallet bundle request has an explicit length of 65 bytes: the
original 25-byte plan request plus txid[32], output index[4 LE], height[4 LE].
Version 1 continues to read only its original 25 bytes. Both use the same
capability interpreter; version 2 supplies the canonical two-outpoint commitment
preimage in the plan alongside the fee script. The native callback hashes that
preimage without calling back into Haskell. Byte operation 25 supplies the same
73-byte preimage for independent callers.

Version 3 appends genesis, previous-block, and exchange-root identities to that
request (161 bytes). `BundleAnchoring` hashes the input preimage, validates the
anchor, and constructs its state marker before `BundlePlanning` checks amounts.
`BundleConstruction` then supplies the native transaction and Haskell assembles
the transport. The three capabilities run within one Haskell invocation, replacing
four wallet-side invocations. Native SHA256d/tagged hashing and transaction
serialization remain callbacks, with no unsafe reentry into Haskell. Anchor
rejection retains its distinct RPC error; earlier failure prevents construction.
The v1/v2 framing is unchanged. Domain exports remain 15; v3 is an appended
internal binding. Rebuild native consumers for the extended C++ plan structure.

### External withdrawal verification workflow

`RpcVerifyFlow` (store flow 182) controls external M6 admission, domain checks,
chain authentication, canonical byte/id comparisons, paid-withdrawal rejection,
and result publication. It reuses `Check`/`Validation`; this finite sequence does
not need another capability hierarchy or foreign export. Native actions retain
transaction ownership, upstream decoding, hashing, chain locks and RPC errors.
Existing Haskell codec calls use the shared safe callback. The shared legacy
decoder already requires three outputs, so the
previous later missing-reference-output check was unreachable and is removed.

The paid check is a fact callback, not a native rejection decision: action 16
reports whether the claim is unpaid, action 18 formats the existing paid error,
and only action 17 publishes success. `RequiredPairFlow` (294) similarly selects
paid rejection before invoking submission, then distinguishes submission failure
from success. Native formatting preserves the M6 id, parent block and height.
The existing dispatcher is reused; no new FFI export or capability is introduced.

The same four-action rule now handles ECX UTXO and context admission under the
existing native chain lock. Actions 1 and 3 are ordered facts/effects; 2 and 4
are their terminal error adapters. Negative vout prevents coin lookup; absent
tip prevents snapshot loading; failed snapshot prevents parent reporting.
This factors the former withdrawal-only rule into ParentReplay without changing
selector 294 or its bounds. It uses the existing Check/Validation interpreter.
Initial network admission, native RPC parsing and lock acquisition remain outside
this rule. The ECX network admission is still pending scope review/migration.

QuickCheck models rejection prefixes, invalid responses, failed effects and
unexpectedly returning error actions. Native tests interrupt every action in
the successful sequence and check that no later action executes. Real RPC tests
preserve malformed-frame, wrong-domain and confirmation-parameter precedence
against the pre-migration baseline. These are not evidence of a successful
funded withdrawal or live parent reorg; that integration qualification remains.

### Withdrawal submission policy

Withdrawal byte action 32 moves transport admission and child-result precedence
into `SubmissionPolicy`, dispatched through the existing withdrawal
capabilities. Stage 0 is 14 bytes: stage, signed slot (LE32), bundle length (LE64),
Windows flag. Stage 1 is two bytes: stage and flags for cancelled, started,
timed-out, truncated, process error, reaped, zero exit, and AlreadyExists, in that
bit order. Stage 2 carries stage, the first seven flags, a duplicate-acceptance
boolean, and raw child output. Production uses stage 2 so Haskell owns the
duplicate match and its acceptance; stage 1 remains a compatibility input.
The one-byte reply is 0 for admission/success, 1-3 for preflight errors,
or 4-10 for ordered process errors. Malformed frames fail at the FFI boundary.

The node retains authenticated process invocation, cancellation, timeout, output
limits, reaping and error formatting. Bounded child output is copied into Haskell.
The preexisting substring-based AlreadyExists handling is preserved, not upgraded
to structured gRPC-status authentication. Windows submission remains unsupported.
Tests cover original native preflight errors, all 256 result-flag combinations,
case-sensitive substrings, partial matches and embedded NUL bytes;
these are not network submission or retry integration tests.

`ClassifyDrivechainGrpcResult` shares this policy between withdrawal and BMM
submission and formats the original native errors in one place. BMM does not
enable duplicate acceptance in this classifier: a nonzero exit must still reach
its existing replacement-bid attempt before its separate duplicate-response
handling. Process failures never enter that retry branch. A native parity test
covers all 256 child-flag combinations in both duplicate modes, including exact
error strings and clearing stale caller error text. Child resource ownership
remains native; retry orchestration uses the workflow below.

### BMM bounded submission workflow

`WorkBudget` owns Simplicity witness eligibility, annex/control indexing and
saturating work accumulation. It uses the existing safe indexed scalar callback
transport; native actions only read stack size, first byte (256 for empty),
element size and upstream serialized size. Serialization is requested only for
eligible stacks. Overflow ends the scan without reading later inputs, while a
callback failure propagates the original native exception, never saturation.
The original Word64 wrapping addition of the 50-unit offset is retained before
the multiplication and accumulation checks. Native assertions bind the Haskell
constants to the upstream annex/leaf/offset values. Tests compare actual witness
stacks with the frozen native rule and synthetic read traces at unsigned limits.

`WorkTotal` reuses the checked addition rule for block-level accumulation. Its
rejecting mode stops at the first overflow and publishes the preceding total;
its saturating mode caps the value but continues requested reads. Production
uses the rejecting scan over transaction budgets. RPC template rendering uses
one saturating addition at the original field-publication location. The shared
`workCall` transport supports both budget and total requests, with one final
publication on success or domain rejection and none on callback failure. Native
exception identity is preserved. The nested total-to-witness interpreter call
is covered by native tests; property tests compare ordered reads and results
against an independent Integer-based model, including invalid modes and canaries.

`WorkQuote` owns work-fee rounding, money-range checks, the original Word64
multiply/add overflow bound, reserve admission and bid calculation. One
configuration-domain call returns acceptance plus all three quote fields.
An insufficient-funds rejection retains verification fee and producer reserve;
earlier invalid/overflow rejection clears all fields. Native code resets the
quote before dispatch and copies the result without reimplementing the formula.
QuickCheck checks mathematical boundaries, partial outputs and buffer canaries;
native tests compare the frozen C++ rule across an edge grid and randomized
overflow thresholds. No fee policy or live bidding behavior is changed.

`SubmissionRequest` owns the three-attempt request sequence using `ExceptT`.
One configuration-domain entry replaces the per-stage C++ transition pump.
Six native actions provide parent lookup, authenticated invocation/classification,
replacement parsing, replacement logging, duplicate lookup, and final logging.
The third attempt has no replacement action. Parent checks precede every request;
process failures stop immediately; a nonzero exit tries replacement before
duplicate handling. Logs and bid assignment follow a successful replacement
parse. Haskell additionally checks that the returned bid increases and stays
within the original cap before publication. The callback context, process and
native strings remain owned by the synchronous C++ caller.

This entry uses a safe dynamic FFI call: transport/classification/fee helpers
already invoke Haskell, so their nested entry is intentional. Only scalar
arguments and the stable native context cross the outer callback boundary.
No borrowed movable Haskell storage is passed to those callbacks. See the
[GHC 9.6.7 safe-call contract](https://downloads.haskell.org/ghc/9.6.7/docs/users_guide/exts/ffi.html#guaranteed-call-safety).
Existing unsafe digest/parser callback restrictions are unchanged. Native tests
exercise real nested classifiers and fee parsing. The old 16-slot
`GrpcSubmissionFlow` has no production consumers and is removed. Store flow 183
remains reserved and fails closed before invoking a callback; neighboring selector
numbers are unchanged. The workflow retains independent trace models,
native retry/fee-parser tests and callback-fault tests, without a second runtime
implementation of the same retry policy.

QuickCheck compares exact action traces against a separate recursive model.
Native boundary fixtures use the actual fee parser and process classifier with
simulated request results, parent changes and duplicate predicates, and check
callback exceptions and invalid results. They do not submit bids or prove real
shutdown/reorg races or network retries. Foreign exports remain 15.
On POSIX, a separate test runs and reaps a small local process (success and
timeout) inside the callback, exercising the nested child-monitoring workflows.

### Producer admission

`StageAdmission` owns both producer paths' admission order and rejection reports,
not just the outer sequence. Native production requires the assigned slot,
chainman/mempool, tip, template, preparation, current predecessor, stored USDD
accumulator and derived checkpoint before submission. ECX production separately
requires its parent-chain configuration, deterministic state, bounded successor
height, work/fee quote, fixed slot and proof-bearing candidate. A successful bid
still precedes authenticated BMM waiting; acceptance follows the wait and, for
ECX, proof attachment. Native and ECX critical-hash algorithms remain distinct.

The existing Boolean callback ABI is unchanged. Additional callback steps expose
the formerly grouped checks; each rejection returns its original stage's status.
Haskell requests the original diagnostic only on an ordinary false result, never
after malformed replies or adapter exceptions. Reporting cannot resume a rejected
candidate. Positive fee gates are tested before submission and proof acquisition.

Native callbacks keep owned templates, hashing, and atomic snapshots under
`cs_main`. Tip/state and predecessor/accumulator reads are not split across lock
acquisitions. Snapshot diagnostics now run after releasing that lock; no lock is
held across submission or BMM waiting. QuickCheck checks direct/FFI traces and
original status codes at every failure position; native tests cover nested calls
and exceptions from both checks and reports. Routing, preparation and acceptance
now use the shared store runner described above, including tests of real native
nonce/witness handling and block acceptance. These tests do not establish a live
miner response or process-level producer race coverage, nor a full-file audit of
the mixed upstream and fork startup code in `init.cpp`.

### Replacement bid capabilities

`ReplacementBid` uses the direct `replacementBid` helper. After payload Refl,
`BidBounds` admits the request and `BidReplacementRules`
extracts the two fee fields and checks the signed adjustment against the cap.
The DSL carries a parser function. Ordinary sequencing runs both parser calls in
their original order, even if parsing the first amount fails; rejected bounds
or malformed framing call neither parser. Upstream C++ `ParseMoney` remains the
numeric parser through a narrow callback that must not reenter Haskell.

One appended configuration-domain binding carries the complete operation;
foreign exports remain 15. Rejection preserves the caller's output amount.
The native fixture compares against the frozen original C++ implementation,
including negative paid fees, marker precedence, trailing delimiters and bounds.
Property tests separately cover parser order, adjustment and lazy payload
dispatch. No network requests are involved.

### Bounded child monitoring

`ChildMonitorFlow` (store flow 184) owns the parent-side drain/reap/check/poll
sequence. Output truncation precedes cancellation, cancellation precedes the
deadline, and the deadline precedes successful completion, matching the former
native loop. It returns whether native cleanup must terminate the process group.
Clock reads, polling, pipe reads, fork/exec, signalling and reaping remain native.
No Haskell runs in the child between fork and exec.

The native caller retains a pending monitoring exception, terminates/reaps the
child and closes its pipe, then rethrows it. A real local-process test injects a
cancellation exception and verifies ECHILD/ESRCH for that specific child afterward.
This does not claim complete resource migration or protection from every possible
allocation failure during native cleanup. Existing timeout/truncation/cancellation
fixtures and the independent Haskell trace model also cover this workflow.

The same `ChildMonitorFlow` validation capability now handles the termination
grace loop (flow 185). Native actions keep the original 250 ms grace deadline,
10 ms poll and nonblocking-only drain. A pending grace exception cannot bypass
the unconditional native SIGKILL and final wait; an earlier monitor exception
takes precedence. The real-process escalation test waits for a child to install
SIGTERM-ignore, cancels it, and checks SIGKILL exit status plus ECHILD/ESRCH.
Signal delivery and final reaping still remain native; Windows is not qualified
by this POSIX test.

Native pipe and child handles now have stack-bound `unique_ptr` guards with
custom no-throw deleters; they do not allocate or delete the stack storage.
This covers unwinding before the Haskell monitor is entered as well as later
cleanup exceptions. The child guard is established only in the parent after
fork, kills an unreaped child/group and retries an interrupted final wait. Normal
reaping makes it a no-op. The pipe guard closes any remaining descriptors on
unwind, replacing repeated manual early-exit closes. This is a native lifetime
boundary for the Haskell workflows, not a completed migration of system calls.

### Exchange snapshot admission

`SnapshotContext` owns tip availability, ordered tracker reads, persisted root
and cursor agreement, and tracked-coin admission. Native primitives retain
chainstate access and final snapshot field assignments. The caller clears stale
output/error state before dispatch; publication occurs only after success.
Context disagreement uses its original diagnostic, while failed tracker/coin
reads retain the native child error. This workflow uses the safe policy callback
transport because tracker helpers themselves invoke Haskell. It must not use
the leaf-only unsafe availability reader. Tests cover every stopping point,
original exceptions, nested interpretation, null tips, missing version flags,
cursor mismatches, persisted corruption and snapshot reset behavior.

### Withdrawal envelope scan

`EnvelopeScan` owns activation and coinbase guards, candidate filtering,
duplicate precedence, canonical admission and checkpoint/preimage/anchor
sequencing. It calls the existing `EnvelopeRequirement` method directly rather
than dispatching a second `Check`. Native callbacks retain script decoding,
chain-index access, hashes and object ownership. Duplicate detection precedes
validation of a second candidate's header; noncandidate scripts remain ignored.
Successful validation preserves the caller's error string, and rejected child
checks preserve their original diagnostics. The safe policy callback transport
allows those child checks to invoke Haskell; callback exceptions are rethrown
before any bridge diagnostic is written.

Tests compare direct and ABI callback traces against an independent scan model,
inject callback failures, exercise nested interpretation at every step, and use
real checkpoint fixtures for malformed/duplicate ordering and ignored scripts.
`EnvelopePayload` now owns the ECXM version, checkpoint height/hash and bounded
M6 body encoding. The native builder only passes that payload to upstream
`CScript` OP_RETURN/push encoding. The ABI rejects invalid sizes before reading
pointers, requires exact output capacity and leaves rejected output untouched.
Frozen native builder comparisons cover size/push boundaries and height byte
order; randomized direct/ABI tests additionally check capacity and sentinel
preservation. Neither stage establishes complete fork migration or
cross-platform qualification.

The former standalone C++ `ExchangeEnvelopeRequirement` adapter and its
decision enum have been removed: production uses the rule inside EnvelopeScan.
Its frozen 16-case native policy test now drives that real workflow and checks
both diagnostics and whether checkpoint/preimage/anchor verification runs.
The versioned ABI handler and its Haskell tests remain for compatibility.

Base, availability, matcher and accumulator profile tests now call the domain
ABI directly from `ffi_tests.cpp`; their unused production C++ adapters were
removed. The full frozen-configuration reference uses native predicates for
these four sections instead of calling the Haskell implementation under test.
Matcher signer effects retain their original position before profile admission.
The two relocated mutation tests retain every input and output-canary check.

### Pruned parent peer selection

`RecoveryPeerFlow` uses the shared command runner for ordered peer/service
iteration. It skips malformed IDs/service arrays and non-string/non-NETWORK
services, requests from the first eligible peer exactly once, and stops on a
request exception rather than trying another peer. Native callbacks own JSON
values/iterators and the existing checked RPC call. Direct/ABI traces use an
independent list model; mocked recovery fixtures cover malformed entries,
multiple matches, empty peers, request failure and existing cancellation/reorg
paths. No live RPC is used in these tests.

`RecoveryBodyFlow` owns initial retrieval admission, recovery permission,
deadline setup, retry/wait ordering and the final height fence. Cancellation
precedes each poll's deadline check; waiting occurs only after a pruned reply;
active height is rechecked only after a non-error, non-null result. Native
callbacks retain RPC, steady-clock access and waiting. Independent direct/ABI
traces cover deadline outcomes without sleeping; mocked recovery fixtures also
check exact missing-result and changed-height diagnostics. Pruned reply
classification, checked-RPC validation and active-header admission have since
moved into `RecoveryReplyFlow` and `RecoveryHeaderFlow`; native callbacks retain
JSON projections and RPC effects.

The public block-parent extraction wrapper now reuses `StateExecution`'s existing
PARENT_START sequence. Its callback retains the stricter non-null/coinbase check
and the original diagnostic, and clears the output before entering the runner.
No additional state machine, capability or ABI is introduced. A frozen wrapper
comparison covers empty, null, non-coinbase, missing, malformed, duplicate and
valid commitments with and without an error pointer (50 assertions).
The `parent-wrapper-reuse` local native suite passes 1,373 cases; this is not
live parent-chain or cross-platform qualification.

Exchange source policy and marker counting share `AdmitSourceMarkers`, with
output traversal driven by the existing Haskell EACH runner. Native callbacks
retain the payload parsers and counter storage; forced parsing/admission precedes
deposit parsing/admission for every output. Counting publishes the admitted
marker bitmap instead of parsing a second time. Haskell rejects duplicates,
so each count is zero or one; malformed, duplicate or inactive markers leave
both counts zero. Native regressions cover empty, valid forced/deposit, combined
markers in either order, corrupt and duplicate transactions.
Canonical forced-output admission uses transaction-shape phase 19: check the
index, parse the output, then require a forced payload. Parse failure preserves
the parser diagnostic; bounds and absent-payload failures have distinct errors.
The `source-marker-reuse` full suite passes 1,373 cases, with all five Haskell
integration checks also passing. This is local validation, not live-chain proof.

Marker envelopes use transaction-shape phases 20/21. Both read version first,
then the forced-body length or deposit chain identity, then marker-output
admission. Haskell stops at the first failed read; exceptions propagate without
rewriting the diagnostic. One native adapter supplies these facts after framing
has established payload bounds, and retains upstream big-endian decoding and
hash comparison. Body validation and trader validation still follow envelope
admission. The ABI signature is unchanged; these appended phases require a
matched native/Haskell build.
The FFI maximum phase is derived from `transactionShapePhases`, which registers
both table-driven phases and slots reserved for custom control flow. This removes
the separately maintained admission limit. The direct/ABI property retains an
independent expected-code table and rejects phase 24 and Word32 maximum without
calling the reader.
Phase 22 admits deposit references: valid trader key, in-range output index,
non-self reference, then the seven confidential-collateral profile facts. The
native output pointer is obtained only after all three reference checks pass;
witness access occurs only after its bounds check. It retains separate reference
and collateral diagnostics and publishes the parsed payload only on success.
Native tests exercise every fact mask and exception prefix plus malformed keys,
out-of-range/self references and missing output witnesses through source policy.
Phase 23 gates forced-action signatures: validate the x-only trader key before
constructing the tagged digest and verifying Schnorr. Native cryptography is
unchanged. Key rejection retains its distinct error even if the signature is
also invalid; the direct/ABI phase tests cover skipped reads and exceptions.

`Record` AMOUNT_SUM admits an explicit amount only when the existing unsigned
total plus that nonnegative signed amount fits the supplied limit. Haskell uses
`Integer` for the addition; the native transaction checker updates storage only
after admission. This replaces the fork's subtraction-based overflow predicate,
not upstream individual-output validation. Deferred totals still bypass this
rule, and map ownership remains native. Tests compare
the ABI and direct rule against subtraction bounds, and compare all three native
total modes against the prior policy across signed and money-range boundaries.

Record selectors 25 and 26 cover output-total mode selection and definitive
parent rejection. The former returns a checked typed mode (defer, aggregate,
per-asset, reject), with defer taking precedence over explicit-asset requirements.
The latter rejects an invalid result only when its parent is not unavailable.
Mempool callers keep their valid-result fast paths and evaluate witness validation
before reading its unavailable output. Neither rule adds an ABI entry point or
capability class. Exhaustive native flag checks and direct/ABI property tests
cover valid combinations and malformed flags; these are not live outage tests.

`Bmm.HeaderLayout` consolidates the field-selection and version-normalization
policy shared by header serialization, decoding, and hashing. Haskell
keeps Bitcoin-mode version bits untouched; the native adapter performs field codecs
and hashes. On Elements, encoding derives bits 30/31 from object state; decoding
uses those wire bits and clears them from the stored version. Extension bits
16--20 retain their existing meanings and byte ordering. The appended codec
selector rejects unknown flags, incorrect output lengths, and null output without
writing. Direct/ABI properties check the independent layout calculation and output
canaries; the frozen 1,024-header matrix checks original hash/wire goldens and
decode/re-encode equality without changing its expected hashes.

Mode 16 returns raw version-bit presence without normalization or network gating.
The four public header predicates use this mode; block-body BMM inclusion uses
the ordinary network-gated layout instead. Thus a set bit 20 remains observable
on a Bitcoin header but never adds a BMM vector to its body. The native matrix
checks this distinction across all extension combinations and network modes.

Bit 5 of ordinary layout requests selects critical hashing (modes 32--47).
On Elements this adds output flag 256, requesting a zero BMM-proof hash in the
existing hash writer. Native code no longer copies and modifies a whole header
to obtain its critical hash. Bitcoin mode still returns no Elements fields.
Modes 17--31 and values above 47 remain invalid. Fork-added header masks are
generated from the same Haskell bit catalogue used by the layout rule; the
upstream dynamic-federation bit retains its original definition.

The preserved standalone consensus C ABI uses upstream `SpanReader` rather than
a fork-local copy of its byte reader. Null source pointers are rejected before
constructing the span. Existing flag, amount, input-index and trailing-byte error
precedence is retained, including acceptance of trailing amount bytes. The
`consensus_reader_SHARED` and `consensus_reader_STATIC` CTests exercise 130 cases
each (with and without an error pointer). These fixtures also passed against the
prior installed reader before replacement. This is native-code reuse, not a
Haskell serialization reimplementation.

Replay-store `CHILD_CHECKPOINT` owns checkpoint-source admission and the ordering
of native effects. It rejects an absent/unvalidated active tip, an unvalidated
snapshot, a missing/malformed withdrawal frontier, or a mismatched cache tip
before requesting a flush. Only then are native cursors constructed and checked
against the same expected block. The existing `Record`/`Check` operation and
command interpreter are reused without a new ABI entry point or capability.
Locks, cursor ownership, serialization and database calls remain native. The
trace property covers short-circuiting and failed callbacks; the chainstate test
checks unchanged errors and that rejected preparation does not flush a pending
claim, while a successful retry does.

`Exchange.ProductionIdentity` reuses `Admission` and its lazy `firstFailure`
traversal for canonical production identity validation. Native readers expose 108
individual field/hash comparisons; Haskell controls their order and maps them to
the original 32 diagnostic groups. Missing optionals and empty checkpoint maps
therefore stop evaluation before dependent reads. Both Taproot and Simplicity
deployment checks are expanded into individual facts, not hidden native Boolean
groups. The configuration-domain ABI selector is append-only and uses the safe
reentrant predicate transport, since checking the genesis hash reenters the header
layout rules. Success leaves diagnostic text unchanged; a null diagnostic pointer
is allowed. The preceding 38-mutation native baseline and a direct/ABI read-trace
property qualify first-error behavior. Chain defaults and identity constants are
unchanged; native comparisons do not parse or select a different network.

Configuration field 9 encodes the canonical Elements proposal description:
version zero, eight-byte title, then proposal text, manifest hash and source ID.
It reuses the existing field-codec ABI and bounds its encoded result to 65,536
bytes; the 52-byte trailer is mandatory. Native hashing and the existing-parent
proposal override are unchanged. Random byte/capacity tests and boundary canaries
cover the codec; native adapter checks include embedded NUL bytes and rejection
messages. This replaces the constructor's repeated vector insertion sequence.

`Deposit.ConfirmationPolicy` selects peg-in depth from pinned Alpha/Beta identity
facts without changing either manifest. Beta is checked first and stays six-deep;
the historical Alpha exception is one-deep only from child height 64. Other cases
return the configured unsigned depth unchanged. Alpha identity-only queries keep
their original read order. The common callback adapter now accepts either signed
result width, avoiding a second null/exception adapter for the full-width depth
result. Invalid replies and missing callbacks fail closed. Tests cover ordered
short-circuit reads, the height boundary, lazy dispatch mismatches and fallback
depths through UINT32_MAX.

`BmmConstants.peginIdentityHeader` generates the historical network, slot,
configured-depth and genesis/manifest pins consumed by that native callback.
These are frozen eligibility identities, not aliases for mutable network
defaults. Native code only projects typed equality facts; Haskell retains their
evaluation order and depth selection. Independent native fixtures mutate every
identity field and check both historical profiles and unrelated chains.

`Withdrawal.WalletIssueAmount` owns the issuance dialog's nonpositive-amount
guard. Qt still converts text to a native double and the RPC receives the original
string. A borrowed `Ptr Double` uses the existing pointer ABI lane, without adding
floating-point scalar encoding. The guard preserves `amount <= 0`, including
signed zero, infinities and unordered NaN; it is not the authoritative RPC amount
parser. Null input returns -1 and exceptions cannot cross the FFI. QuickCheck
compares random IEEE-754 values and explicit boundaries to the original native
comparison; Qt tests check the conversion and backend-call behavior together.

`Exchange.NetworkSelection` owns the production selector, retired `usdd` alias,
and exact-regtest Elements/deployment guards. Parameter construction and defaults
remain native. The append-only configuration ABI preserves length-delimited names
(including embedded NULs), case sensitivity and option rejection precedence;
invalid modes, flags and pointer/length pairs fail closed. A single native adapter
maps rule results to the unchanged startup diagnostics, removing duplicate alias
rejections. The regtest guard remains outside inherited custom-chain constructors.
Production basic setup reuses the same result through `NetworkSelectionStatus`,
then the existing ordered-facts runner checks the canonical chain identity and
linked verifier identity. Native diagnostics retain their distinct "binary" and
"program" wording. These gates still precede inherited networking/signal setup;
the functional-test-only exclusion is unchanged.

`Exchange.ContextPresence` classifies optional ECX context groups as absent (0),
complete (1), or partial (2). Six native readers share the same count-based rule;
present zero hashes/cursors remain present, not invalid. Zero required fields or
an impossible count fail the ABI with -1 and the native adapter throws. Native
tests enumerate every mask of the 2-, 3-, 7- and 8-field groups; property tests
exercise count boundaries through UINT32_MAX. Hash copying and optional value
lifetimes remain native, and partial BMM contexts never dereference missing fields.

`Exchange.ScriptCacheEncoding` owns only the fork-added script-cache byte layout.
Native `DataStream` serializes 20 optional hashes, seven optional uint64 values
and the optional 80-byte atomic-parent endpoint, after the activation-authenticated
flag. Presence flags must be 0/1; truncation and trailing bytes reject. Absent
fields become zero bytes, and scalars switch from native wire little endian to
the existing big-endian cache order. Group tags reuse `ContextPresence`, including
partial groups and present zero values. The full output is 822 bytes; endpoint-only
mode is the unchanged 115-byte versioned suffix. A new internal handler is appended
to `script_policy`, with bounded input/output lengths and no writes on rejection.

The native hasher still writes the authentication byte, inherited wtxid/flags,
native ECX domain digest and the remaining 821 context bytes in their original
order. Salt, crypto, cache ownership, locks and script execution remain native.
QuickCheck compares direct/ABI encoding, canaries, integer boundaries and malformed
frames. Native tests inject independently constructed pre-migration cache keys and
require real `CheckInputScripts` hits across every context field, absence, partial
groups and distinct field values. The existing V11 domain-hash oracle is retained.

`ScriptPolicy.TemplateAdmission` owns CTV opcode admission. Its five-bit input
records activation, CTV discouragement, NOP discouragement, future-length
discouragement, and stack-item presence. It returns ignore, discourage, empty
stack, or check hash. The native interpreter invokes the hash checker only for
the last outcome and retains all script error mappings and stack ownership.
The separate append-only `script_policy` ABI domain rejects malformed calls;
invalid flags or an absent item with a nonzero size fail closed. The pre-migration
native flag/stack/checker matrix is unchanged and retained as a regression gate.

`ScriptPolicy.VerifierStartup` owns SP1 startup identity admission. Inactive
deployments perform no fact reads. Active deployments check frozen identity,
verifier availability, ABI version, semantic-identity version, export status,
then exact identity, stopping on the first failure. Native code keeps verifier
calls and the output buffer; failed exports never reach the comparison. The
existing callback transport preserves exceptions and rejects invalid replies.
Tests cover every Boolean failure combination, exact diagnostics, null diagnostic
pointers, inactive laziness and direct/ABI trace parity. Installed consumers also
exercise the header's no-verifier compile-time path.

`ScriptPolicy.ActivationShape` guards stack indexing in the original order:
stack count, leaf size, annex size/tag, then control-block size/tag. The native
Simplicity parser remains authoritative for the annex payload. `ActivationBudget`
checks the frozen budget/input boundary before consulting pointer/identity,
parser and equality facts, then selects the ordinary or frozen budget in Haskell.
It shares ordered Boolean checks with verifier startup. The ABI returns status
separately from the budget, preserving every signed ordinary value (including
`-1` and `INT64_MIN`) without colliding with failure. Invalid callbacks leave the
output untouched.
The native adapter uses the safe reentrant callback because parsing calls back
into the shape rule. Boundaries and traces are tested, including malformed shape
leaving output buffers untouched and present null-valued identities failing credit.

`Exchange.AddressAlias` admits LWK's `ert`/`el` input prefixes only for the
canonical Elements network and never for parent-chain destinations. Its flags
encode parent/confidential context; unknown bits fail closed. Native codecs still
check encoding, checksum and witness rules, and canonical prefixes bypass alias
admission. Tests preserve canonical re-encoding (including the blinding key),
cover witness versions/lengths, case and network boundaries, and compare direct
and ABI admission with malformed pointer/length checks.

`Exchange.PaymentUri` selects and admits payment URI schemes using compact
scheme codes (the native adapter owns only their text spellings). Unknown
schemes reject; invalid flags/codes fail closed. Admission keeps the historical
acceptance of both Liquid schemes outside canonical Elements mode. Formatting
uses the chain-type context while admission uses network identity, preserving
their original distinction. Qt retains URL normalization, query parsing and
recipient publication. The native Qt URI matrix is tested before and after the
migration; direct/ABI properties and installed consumers cover the policy table.
Qt's IPC prefix also reuses the canonical Haskell selection. It is initialized
on first use, never during static startup, and remains Elements-only regardless
of later chain selection. Qt keeps case-insensitive prefix checks and rejection
of the double-slash spelling; these are covered by the native URI matrix.

`BmmConstants.resourceConstants` owns the frozen block/proof resource schedule
and per-block deposit cap. `resource_constants.h` is a checked-in generated
projection so source-only consumers retain compile-time constants without a GHC
runtime dependency. CMake rejects a stale projection. Regenerate with
`ghc -no-user-package-db -package-env - -hide-all-packages -package base src/haskell/BmmConstants.hs -e 'putStr BmmConstants.resourceHeader' > src/haskell/resource_constants.h`.
Native relationship assertions remain in the identity header; Haskell and native
golden tests pin all 13 original values. This changes ownership, not consensus
values, genesis, activation, or serialized state.
The same checked-in projection supplies the historical Alpha peg-in activation
height to native declarations and RPC reporting. `ConfirmationPolicy` reads that
single Haskell definition; the native public constant name and independent tests
at heights 63/64/65 remain unchanged. Betanet still requires six confirmations.

Accumulator results carry their computed count alongside the state bytes. The
batch cursor advances only after a successful append; partial overflow publishes
the successful prefix and its count. Native `AccumulatorFlow` and Haskell block
application consume that result instead of separately calculating saturation.
The count-returning v3 adapter leaves metadata untouched on scalar/proof rejection or invalid
inputs; proof-index and empty-root modes return their unchanged input metadata
on success. The v2 ABI remains a compatibility wrapper over the same behavior.

`Usdd.AccumulatorVersion` owns supported serialized-version admission. The native
serializer reads the version byte and consults this rule before reading count or
state, preserving its original error and failure position. A native static assert
pins the writer's version to the supported protocol. Every byte value is tested,
with ABI values outside the byte range failing closed; serialization regression
tests verify untouched destination state and unread suffix on version rejection.

`Bmm.MinedPreflightFlow` (store selector 234, bound 3) checks the configured
slot before testing a critical hash for nullness, and reports a null hash only
after slot admission. The shared command interpreter supplies short-circuiting;
native callbacks retain diagnostics. Parent-context retrieval and its exception
boundary remain after admission. Direct/ABI properties and native exception
traces cover each branch without adding an Operation instance or exported ABI.

`ParentReplay.ConfiguredSlotFlow` (selector 235, bound 4) orders missing-slot
and mismatched-slot diagnostics for every parent RPC admission caller. It reuses
the existing CONFIGURED_SLOT record rule rather than duplicating signed range
or identity comparisons. Native integration tests exercise ordinary and Elements
networks, null error pointers, and slot-before-hash rejection through the public
BMM lookup entry point; no parent request is needed for these rejection cases.
The same normal-return ordered pair also selects the final mempool sweep
diagnostic: epoch mismatch first, unavailable parent second. Its historical
CONFIGURED_SLOT selector name does not restrict callback payloads. Unlike
RequiredPairFlow, either diagnostic returns rejection rather than requiring an
exception. This reuse removes the native mutable error-selection flag; native
locks, error formatting and mempool mutation stay outside the interpreter.

`ParentReplay.MempoolSweepPreflight` (selector 310) owns the earlier sweep gate:
skip unconfigured networks, reject a zero/stale epoch, then either publish the
epoch for a pool-less chainstate or continue to the original locked sweep.
Epoch reads remain lazy; only the successful pool-less path requests publication.
The atomics and both native lock scopes are unchanged. Direct/ABI tests exhaust
Boolean paths and callback failures; native tests compare original effect traces
and exercise real chainstate rejection without touching the pool or parent epoch.

`ParentReplay.ParentRpcHostFlow` (selector 311) bypasses lookup on ordinary
networks, requires numeric parsing on native drivechains, and selects the IPv4
or IPv6 loopback rule without inspecting the other family's bytes. The native
adapter retains `LookupHost` with DNS disabled and the owned address. Existing
address rules and the command runner are reused; no C ABI export was added.
Tests retain the real host/address matrix and cover lazy failure at every step.

`Bmm.AnchorFlow` also owns three fork-only full-block admission workflows:

- `FullBlockPreflight` (312, bound 22) ignores unsolicited unknown blocks before
  parent work. Requested unknown blocks require an authenticated predecessor,
  ordinary block checks, checkpoint derivation, exact BMM authentication, anchor
  sanity/sequence and deposit preflight before header admission. The temporary
  index remains native and no persistent index is allocated by this workflow.
- `BlockAnchorAdmission` (313, bound 31) reuses the preauthenticated context or
  derives and authenticates the indexed block. It reports BMM status before
  rejecting, checks existing/predecessor anchors, then validates deposits. BMM
  invalidity marks both failed and dirty sets; deposit invalidity marks only
  dirty, matching the prior paths. Unavailability does neither. The selected
  anchor remains local until storage completes. Genesis bypasses deposits;
  ordinary non-genesis blocks retain the existing deposit-preflight call.
- `BlockAnchorPublication` (314, bound 11) runs after native disk placement and
  `ReceivedBlockTransactions`. It binds the anchor before notification and
  advances the best header only for an authenticated admitted block. Optional
  signal/parent checks stay lazy and in their original order.

These use the existing command interpreter, not additional Operation classes or
C exports. Native ownership, locks, hash/crypto verification, diagnostics, disk
writes and inherited block selection remain native. Independent procedural
references exercise direct/ABI traces and callback failures, including invalid
versus unavailable outcomes; real rejection tests check that unknown blocks do
not mutate the index, anchor, chain tip or coin best-block marker. This is not a
live-parent/miner test or cross-platform qualification.

`Bmm.DefinitiveWaitError` owns the five historical byte-substring classifications
used by the BMM waiter. Its append-only internal bmm-domain opcode accepts a
length-delimited byte string, preserving embedded NULs and case sensitivity.
The native wrapper rejects ABI failure rather than silently treating it as a
retryable error. Native truncation/mutation tests compare against the old C++
substring rule; QuickCheck compares direct and ABI results with a list-based
oracle and checks empty input and invalid pointer/length pairs. This preserves
the existing string-based policy; it does not introduce structured error codes.

`Bmm.CacheRoutingFlow` (store selector 236, bound 9) selects positive cached
edges, untrusted replay-index admission, negative cached parents, or continuation
to live probing. Positive hits finish even when their result is unavailable;
only successful index admission continues. Both trust-mode reads remain separate.
Native iterators and replay-lock scope remain inside their original adapters,
with safe nested Haskell calls. Randomized direct/ABI traces and exhaustive native
flag/status combinations cover early returns, callback exceptions and reentry.
These are routing tests, not live cache/reorg concurrency qualification.

`ParentReplay.RequiredFactsFlow` shares ordered fact admission and a final
rejection report for proposal activation (selector 237, three facts) and snapshot
tip replies (238, two facts). Later facts and diagnostics stay lazy. The proposal
height comparison reuses the existing HEIGHT rule, while hash comparison/parsing
remain native primitives. RPC fetches and exception boundaries remain outside
the same gates. Direct/ABI traces and native fault/reentry tests cover both uses.

`Bmm.MessageMatch` now shares byte matching for definitive wait errors and
duplicate submission responses. The submission reporting callback delegates its
two historical substrings to Haskell. A new internal bmm-domain opcode selects
the rule; the prior wait-error entry point delegates to it for compatibility.
Shared QuickCheck properties test both rules, arbitrary bytes and malformed ABI
inputs. Native tests include duplicate classification nested in BmmSubmit,
preserving success reporting for duplicates and rejection for other failures.

`Bmm.ReplacementLimit` validates the replacement allowance, reuses SelectedBid
admission, and caps Integer addition before converting to Int64. The native
submission setup no longer duplicates this arithmetic and retains its allowance
diagnostic. Direct/ABI QuickCheck compares the original subtraction-based cap
through signed-width boundaries; native tests cover MAX_MONEY and invalid input
precedence. This does not change retry count or permit bids above the money limit.

`Bmm.BidInputFlow` owns configured/default selection (239, bound 5) and ordered
parse/validate/publication (240, bound 7). It preserves publication before error
clearing on the default path, lazy argument reads, and no output update on parse
or range failure. Native ParseInt64 and ArgsManager are reused unchanged.
QuickCheck traces cover both modes and faults; native parser and nested workflow
tests check diagnostics, null error pointers, defaults and sentinel preservation.

Bid submission preparation reuses `RequiredFactsFlow 2` (selector 238,
`REQUIRED_PAIR`) for configured-bid admission followed by fee-aware selection.
This is the same workflow used to validate snapshot-tip replies: failure calls
the third action, while success skips it. The bidder's third action throws its
existing diagnostic before replacement settings are read. Native tests compose
the real parser and fee selector, checking short-circuiting, output preservation
and exception propagation. No additional Haskell workflow or ABI entry is needed.

`Bmm.FundedSubmissionFlow` (241, bound 4) sequences parent admission, the existing
funded bid transport and exactly one success/failure report. Stale parents skip
both transport and reporting; exceptions in any action propagate without an
extra report. The native adapter retains the original integer conversions and
transport API. Direct/ABI property traces and native exception-injection tests
cover every outcome; these tests do not submit a live funded bid.

`Bmm.WaitProbeFlow` handles commitment classification (242) and successor-height
admission/proof results (243), both with bound 2. Commitment success skips error
classification; an unchanged parent height skips proof construction. Results
remain 0 (retry), 1 (confirmed), or 2 (definitive rejection), interpreted by the
existing wait loop. Native error resets and the proof exception catch remain
outside the probe. Tests cover direct/ABI traces, callback faults and nested
execution inside BmmWait without making live RPC calls.

`Bmm.TemplateCreationFlow` (244, bound 4) admits the wallet reward destination
before constructing assembler options or a block template. Template status is
0 (unavailable), 1 (coinbase-only/idle), or 2 (selected mempool transactions).
Only status 2 proceeds to either native or ECX bid submission; a nonempty mempool
whose transactions are excluded by the assembler is still idle. This production
policy does not reject consensus-valid empty blocks or interrupt already-paid bids.
Failure reporting is selected in Haskell. Native options remain alive through reporting, while
their construction is deferred until reward admission succeeds. Shared property
and native trace/fault fixtures cover this flow and funded submission together.

`Bmm.RewardWalletFlow` (245, bound 6) owns wallet-loader admission and the
first-spendable-wallet search. It skips spendability queries for wallets with
private keys disabled and stops after the first match. Native wallet snapshots
and method calls remain unchanged. QuickCheck covers variable wallet lists and
native tests exhaust all zero-, one- and two-wallet configurations with faults.

`BmmConstants.bondFixedSupply` owns the fixed bond supply used by the Haskell
encoders and validators. The existing build-time generator emits the same value
as `ECX_BOND_FIXED_SUPPLY` for native commitment and issuance checks; no runtime
FFI call is needed. Independent expected encodings retain literal supply values
in tests, and native deployment tests reject adjacent issuance/inventory amounts,
including matching but incorrect pairs.

The two-field `FrozenBounds [height,limit]` shape checks a positive height below
an exclusive limit. Activation configuration uses the native `int` maximum as
that limit, retaining its original diagnostic and validation position. Signed
negative heights convert to large unsigned values and fail this bounded check.
QuickCheck and native tests compare against the original signed predicate,
including zero, both signed extremes, and the activation limit boundaries.

`Exchange.FrozenProfileFlow` (store selector 246, bound 8) selects network
admission, release-hash admission and ordered argument overrides. Native callbacks
retain parsing, argument access and the original exceptions. Nonmatching networks
skip all checks; absent arguments skip value reads; a conflicting override stops
before assignment while retaining earlier assignments. QuickCheck covers variable
argument lists and callback faults; native tests cover short lists exhaustively,
including exception propagation and partial application. Activation domain
inequality reuses `ExchangeDistinct`, without a new ABI or operation instance.

`ecx::ApplyFrozenProfile` is the native argument adapter shared by production
startup and the real-ArgsManager regression test. Its isolated tests parse actual
options, check matching and conflicting overrides, repeated application, malformed
release hashes and empty profiles. A nonmatching network does not inspect the
release-hash pointer or change arguments. This verifies actual adapter effects,
but does not replace full frozen-production startup qualification.

Activation script-hash admission reuses `RequiredFactsFlow 2` / `REQUIRED_PAIR`:
the native adapter checks non-null first, then computes and compares the upstream
SHA256 digest, and throws the original diagnostic on failure. A null hash never
invokes hashing. Native script fixtures verify digest matching and exact traces;
the existing shared-flow QuickCheck covers malformed callbacks and faults.

`Exchange.CapitalDecodeFlow` (247, bound 8) orders frozen identity admission,
active-root presence, annex parsing, identity binding and snapshot publication.
Finite and incremental native decoders share one adapter with compile-time parser
and field-layout selection. Their diagnostics remain distinct. Snapshot assignment
occurs only after all gates succeed; parser/FFI exceptions retain native unwinding.
QuickCheck covers gate combinations and callback faults. Existing positive annex
fixtures and negative identity cases exercise both adapters, with serialized
snapshot comparisons proving output preservation on root/annex rejection.

Persisted exchange-state detection reuses `ParentReplayEach` to scan the three
reserved trackers. The scan stops on the first unspent coin; absent/spent entries
continue in their original order. Native tests cover all 27 coin-state patterns
and read failures at each position, checking lookup order and exception identity.

Source-marker scanning uses `RequiredFactsFlow 4` (`REQUIRED_QUAD`, selector 248)
inside the existing Haskell-controlled output scan. Forced parsing and visitation
precede deposit parsing and visitation. A parser or visitor failure stops both
the per-output sequence and the outer scan, retaining its error. Shared property
and native trace/fault tests cover counts two, three and four; existing real
transaction policy/counting fixtures cover the source-marker consumer.

`Exchange.ConnectionPreflightFlow` (249, bound 17) admits the header and activation
state, then validates a supplied parent height or resolves the authenticated BMM
fallback. The incomplete-candidate exception keeps its original four lazy checks;
missing state remains permitted only on the existing runtime test network. Status
0 rejects, 1 accepts an inactive block, and 2 continues to state derivation. Native
BMM state construction is deferred until its lookup; errors and height publication
remain ordered before tracker writes. Properties cover branch combinations and
fault prefixes, while native activation tests reject mismatched supplied heights
without creating trackers or spending the genesis coin.

After preflight, connection reuses `ParentReplayEach` for five ordered stages:
derive expected state, validate commitments/reserved slots, publish exchange,
publish forced inbox, publish deposit inbox. Failed admission skips all writes.
Native write exceptions propagate without adding rollback; previously completed
writes retain their existing semantics. No new ABI or flow is introduced.

`Exchange.DisconnectPreflightFlow` (250, bound 16) owns active-height admission,
parent-height validation, ordered tracker reads and committed-root comparisons.
It returns reject/completed/continue, selecting activation removal before undo. It keeps
the original behavior of reading both inbox trackers before comparing their roots,
and skips the deposit-root comparison after a forced-root mismatch. Properties
cover paths and faults; native tests compare serialized tracker/genesis coins
after parent/root failures and after inactive disconnect, then verify removal.
Activation removal runs only after all tracker checks; its failure rejects the
disconnect, while success completes it without entering ordinary undo.

`Exchange.SingletonRecoveryFlow` (251, bound 11) scans block transactions in order
for the current singleton's creating transaction. It skips hashes for nonzero
output indices, stops at the first match, rejects a matched transaction without
inputs and otherwise retains the current outpoint when unmatched. Prior coin
presence precedes hashing/root validation. Native storage and hashing stay behind
callbacks. Restoration writes use the existing ordered `ParentReplayEach` helper.
Properties cover variable scans/faults; real undo tests reject missing and wrong
prior coins without changing any tracker, then successfully restore the right coin.

Inbox undo also reuses `ParentReplayEach`: count appends, reject underflow,
derive from restored counts, then compare the reconstructed inboxes. Subtraction
and the second derivation cannot run after a count failure. Mismatched prior inbox
roots fail before singleton recovery and leave tracker records unchanged.

`HeaderLifecycleFlow` shares six-action routing for header checking (252) and
preparation (253). Inactive headers take only the inactive action. Active checks
require configuration and active commitments before testing genesis commitments
at the activation height. Preparation requires configuration, parent target and
derived state before publishing any header fields. Native callbacks retain field
access, hashing and writes. Exhaustive trace tests cover both modes, every Boolean
input combination, callback faults, malformed replies and bounds.

The state-UTXO commitment reuses upstream `HashWriter` and `COutPoint`
serialization instead of temporary byte vectors and a fork-local LE32 helper.
Native byte-reference tests retain the original 100-byte tagged-hash preimage,
including single-SHA256 output hashing and little-endian outpoint indices.
Deposit and state commitments share that output-hashing adapter. Script and
witness hashing accepts borrowed byte spans, removing temporary vector copies
without retaining pointers beyond the synchronous hash call.

`ExpectedContextFlow` (254, bound 30) selects activation or continuation context.
It guards prior-index dereferences, verifies the tracked coin before deriving
the successor, reads both inbox trackers before comparing their header roots,
and preserves activation genesis publication/error order. Native callbacks hold
coins/trackers and supply cryptographic results. Deterministic trace tests cover
each failure location and callback fault; real transition tests reject null,
flag-mismatched and root-mismatched predecessors without publishing a header.
The following inbox/cursor/liveness sequence reuses `ParentReplayEach`: derive
inboxes, enforce activation counts, derive cursors, validate liveness. Failed
stages skip later work.
`ActivationCounts` uses inbox ABI mode 4 with three words (activation flag,
forced appends, deposit appends). Flags must be zero or one; activation rejects
either nonzero append count. The rule never publishes an output value, and
success preserves the caller's error string. Rejection retains the original
activation-genesis diagnostic. ABI tests include malformed flags/shapes, null
pointers, output canaries and full-width count boundaries.

Inbox ABI mode 5 accepts four Word64 fields (forced count, forced appends,
deposit count, deposit appends) and reuses `pending` to return two remaining
counts. Underflow returns 1 without writing; invalid shape or null pointers
return -1. Success returns 0 and writes exactly two words. Disconnect retains
its existing COUNTS admission and diagnostic before calling `ExchangePending`,
then publishes restored trackers in the original order. Native ABI boundary
tests are registered; execution against the freshly linked node is required.

`IncrementalScanFlow` (255, bound 20) guards capital/context reads and scans all
transactions in order. Ineligible transactions leave the result alone; eligible
transactions assign the annex/program/CMR match result, including resetting an
earlier success to false. Parsing still uses the native annex adapter, with fresh
zeroed parse buffers per eligible transaction. Trace/fault tests and a native
two-candidate matrix preserve last-matching-result semantics.

Custody receipt admission reuses `REQUIRED_QUAD` for count, bitmap, ordered-root
and cryptographic checks, preserving first failure and the shared diagnostic.
Encrypted bundle commitments stream the upstream big-endian length and raw
bundle bytes into the upstream tagged hasher, without a temporary bundle copy.
Real finite/successor custody fixtures and a corrupted-bundle rejection cover it.
Additional-input custody witness traversal reuses `ParentReplayEach`, stopping
at the first annex-like final stack item. Native callbacks only read the stack
and identify that item; the existing Haskell traversal owns iteration and early
exit. Empty stacks/items are allowed here, and a single item starting with 0x50
is forbidden. This custody rule is deliberately stricter than ordinary Taproot
annex recognition. Source-admission fixtures cover these boundaries; they do not
claim full script/signature validation for the synthetic additional inputs.
Tagged-hash callbacks consume borrowed byte spans synchronously, avoiding
temporary vector copies for custody, frozen-configuration, genesis and inbox
append commitments. No span is retained beyond the callback. State-node hashes
use upstream HashWriter serialization of the two raw uint256 values and a
single SHA256, preserving the original 64-byte preimage.

`ParentRequestFlow` (256, bound 5) shares request setup across successful
withdrawal lookup, execution anchors and mempool parent contexts: reset output,
clear an optional error, validate the configured slot, then run the request.
The native `ParentRequest` adapter retains exception translation around only
the request action; reset and slot validation retain their original exception
semantics. Validation budgets still surround execution-anchor/mempool requests.
Trace tests exercise null error pointers, early slot rejection, action results
and callback faults. Native tests verify reset/error behavior without RPC I/O.

`BundleEventFlow` owns legacy wallet withdrawal-event verification (257) and
final-event clearing (258). It reuses the existing event classification rather
than duplicating terminal-status policy. Verification preserves fetch, reply
construction, then missing/failed-event error ordering. Clearing skips lookup
when no bundle exists and clears only after a successful lookup reports a final
event. Native callbacks retain RPC, JSON and bundle-state effects. Trace/ABI
tests and native classifier/exception tests cover the orchestration; they do
not establish a live BIP300 withdrawal payout.

The legacy wallet bundle creation guard uses Haskell-generated lifecycle
tables for reservation outcomes and abort-on-unwind. Reservation acquisition
still happens atomically in the native node API. After acquisition there is no
runtime Haskell dispatch or allocation before the guard becomes active; its
destructor likewise does not enter the RTS. Completion retains the original
native commit-then-disable order. Generated-plan parity and native reservation
lifecycle tests preserve busy versus already-active diagnostics and cleanup.

Both wallet deposit import paths share `FinishDrivechainDeposit` for native
wallet lookup, the existing Haskell-backed broadcast policy, and JSON result
assembly. Native identity fields remain exclusive to the native deposit path;
amount, fee and authentication decisions remain in their respective paths.
The shared adapter releases the wallet lock before broadcasting, as before.

Peg slot, enforcer endpoint and historical withdrawal-fee defaults are defined
in BmmConstants and generated for native consumers. The settings header retains
its existing names as aliases; endpoint lookup and argument help use those
aliases. Values are unchanged. The wallet's parent RPC result adapter reuses
the Haskell-backed reply checker with optional results and its original
`mainchain` diagnostic prefix, translating reply errors to the wallet RPC code.
Transport errors remain outside that translation boundary.

`ExportReconstructFlow` (261) selects bond-inbox export reconstruction: only
profile 1 selects the incremental parser, and only a 0-to-1 transition resets
the working projection. Append failure precedes root/count mismatch checks.
Native adapters retain the existing parsers, genesis hashing and RPC errors;
Haskell and native trace tests cover profile values, faults and short-circuiting.

`ExportSnapshotFlow` owns export initialization (292) and range rechecking
(293). Initialization selects genesis without reading a predecessor, or requires
a verified predecessor before copying its projection. Rechecking stops before
looking up a height beyond the exported prefix; a changed included index raises
the existing reorg error. Native callbacks retain `cs_main`, snapshot copies,
chain-index lookups and error construction. These flows reuse the existing
parent-replay ABI and `Check`/`Validation` dispatch, with no new exported symbol.

Checkpoint header/entry/byte budgets and peg-event default/maximum page sizes
are owned by BmmConstants and emitted into the native constants header. RPC
admission and peg-event range validation share these values; native static
assertions and Haskell catalogue tests independently pin their original values.
Checkpoint byte accumulation uses the overflow-safe LANE_EXCEEDED predicate
before updating the native serialized-byte counter.

Bond export's default block count (1), block limit (64) and entry budget (8)
also come from that catalogue. The existing first-block exception to the entry
budget is retained: an empty result accepts its first reconstructed block before
subsequent appends use the bound. Request parsing and native result formatting
remain unchanged. Withdrawal accumulator admission reuses RequiredPairFlow to
select inactive-index versus missing-accumulator errors, without a mutable native
phase flag or repeated error-code/message selection.

The catalogue also owns native-withdrawal RPC defaults (one confirmation for
reading, six for submission/verification), the ten-second proof reconstruction
budget and the 4096-height interruption interval. RPC help and runtime defaults
use the same generated values. The interval replaces the former 0x0fff mask
without changing interruption heights. Clock acquisition, mutex ownership and
RPC argument decoding remain native adapters; no new FFI call is needed for
these immutable policy values. Native RPC tests omit the confirmation argument
to verify the defaults and preserve explicit-override coverage.

`Usdd.RpcProofFlow` (295) owns final proof acceptance and diagnostic precedence.
Count mismatch selects its error without building a proof. Failed construction
skips root comparison. Either construction or root failure selects a nonempty
proof diagnostic before the fallback root-mismatch message. Successful validation
does not inspect an unused diagnostic. Native callbacks retain proof storage,
cryptographic construction and JSON exception formatting. The shared interpreter
rejects malformed replies and returning error callbacks; no new FFI export is
needed. Native reference traces and QuickCheck exercise every rejection prefix.

Parent replay record rule 27 (`CACHE_EXPIRED`) removes cache entries on an
epoch mismatch or an expired timeout. Its only flag is the native clock's
timeout comparison; other flags fail closed. Edge entries pass no timeout.
Clock acquisition and container mutation remain native, with one shared clock
snapshot per pruning pass and unchanged cache sizes and timeout duration.
`BmmConstants` generates the native cache settings: eight authenticated edges,
64 rejected parents, and a five-second negative-cache lifetime. Native code
constructs the same steady-clock duration without a runtime FFI call. Boundary
tests pin these values and exercise eviction below, at, and above capacity.

`BmmConstants` also owns the legacy forced-action body sizes (201, 208 and
193 bytes) and deposit payload size (73 bytes). The generated native exchange
header and Haskell marker/body validators consume the same catalog. Independent
native static assertions and property expectations pin the existing wire sizes;
ABI capacity guards and frozen network identity headers remain unchanged.

`CursorPayload` recognizes the processed-cursor payload after upstream GetOp
has parsed one exact OP_RETURN push. Inbox codec mode 18 returns a status byte
(unrelated, valid, malformed) plus the two little-endian cursors. The native
adapter bounds the input to 22 bytes: this retains the exact valid 21-byte
payload and distinguishes every oversized payload without copying it in full.
Unrelated and malformed markers preserve both caller cursor values; malformed
matching markers still set the recognition flag before reporting failure.
Native parity tests cover lengths, magic/version mutations and endian extremes;
QuickCheck exercises real ABI bounds, output canaries and unchanged-on-error.

Transaction-shape phase 24 verifies a tracked singleton: the coin must exist,
then its output is copied and authority-checked, then its root is compared with
the persisted tracker. Error code 25 preserves the authority check's diagnostic
rather than replacing it. The existing safe predicate callback permits that
nested Haskell validation. Native hash/coin primitives are unchanged. Tests pin
short-circuit order and exercise missing coins, malformed authority scripts and
root mismatches through block-header preparation against an isolated coin view.

Exchange and inbox tracker reads share `GetTrackerRecord` for native UTXO
lookup, missing-record diagnostics and entry to the existing Haskell-backed
decoder. Their marker, diagnostic prefix and payload predicate remain distinct.
The corruption fixture checks missing records and restoration for all three
tracker namespaces in addition to malformed encoding, script and payload cases.

Legacy forced/deposit appends share `AppendInboxHash`, retaining Haskell STEP
encoding and upstream tagged hashing. Event encoding and both domain strings
stay explicit at their respective call sites. Root publication precedes count
increment, as before; the Haskell inbox workflow still checks count overflow.
The native source-block fixture independently reconstructs both event and step
preimages and compares exact header roots, then checks connect/disconnect state.

`AuthenticatedHeightFlow` (262) selects a supplied parent height or authenticated
BMM-state lookup. Supplied zero sets its diagnostic without publishing a height;
a fetched zero is published then rejected, leaving the prior diagnostic alone.
Lookup failure preserves a detailed decode error or supplies the existing
missing-authentication fallback. Native callbacks retain coin-state access and
assignments; the existing safe command callback supports nested BMM decoding.
Direct/ABI trace properties cover callback faults and malformed replies. Native
tests pin publication, diagnostic and lookup ordering at zero and integer bounds.

Deposit evidence and BMM proof adapters share block-bound transaction/proof
request construction through `CallMainChainTransactionHex`. The Haskell
workflows still determine request order; malformed-result diagnostics remain
caller-specific. CTIP discovery stays separate because it omits the block hash
and handles malformed candidate replies differently.

The compressed-SP1 jet cost is owned by `BmmConstants.compressedSp1Cost`.
`jetCostHeader` generates `src/simplicity/elements/primitiveJetCost.inc`;
the native build checks it alongside `resourceHeader` through the shared
`check_haskell_header` helper. Standalone Simplicity keeps a self-contained C
macro without a runtime dependency. The value remains 900007720 milliweight;
the golden property and native catalogue tests independently pin that value.
Regenerate with GHC using `-e 'putStr BmmConstants.jetCostHeader'`, as with
`resourceHeader`, writing to the checked-in `.inc` file. This change does not
alter any jet CMR, wire encoding or activation policy.

`JournalLegacy` is appended to the withdrawal operation ABI. It validates the
minimum seven-byte transport and the exact 00/01 marker, then removes only those
two marker bytes. The shared variable-length `WithdrawalTransport` adapter can
add or remove this marker; it is not a general witness transaction decoder.
Journal admission still precedes this transformation and native M6 hashing, so
existing diagnostic order and atomic file publication remain unchanged.

`ReservedInputsFlow` owns the Elements-mode reserved-state input scan. It skips
peg-ins, checks exchange state before BMM then CTIP for each ordinary input,
and stops at the first forbidden input before upstream coin lookup. Native
callbacks only expose transaction/outpoint facts and advance the cursor.
Trace properties pin every callback and malformed transition; native tests
pin reject reasons for mixed reserved inputs and preceding peg-ins.

Consensus deposit routing reuses `DepositWitnessKind`, the existing native
adapter to Haskell's `DepositWitness` classifier. It no longer infers native
deposits independently from an eight-item stack. Recognition runs once and does
not replace parent authentication or the selected output/evidence verifier.

Boolean ECX recognition also calls that classifier directly, without copying
unused claim-script/transaction outputs. The native federated proof verifier is
shared by both witness paths; its unchanged upstream cryptographic checks are
not duplicated or replaced with a second Haskell verifier.

Fee-free deposit admission reuses `RequiredFactsFlow 7`: input, output and
witness cardinality precede peg-in/issuance checks, witness recognition and
output validation. The native callback exposes facts only; the shared Haskell
flow stops on the first failure. Its eighth callback reports failure without
touching transaction data. Trace properties cover callback order, bounds and
faults; native fixtures include empty vectors and malformed witnesses.

The legacy and native deposit constructors share their upstream-style prefix
serializer and translated serialization error. The evidence constructor retains
its distinct unwrapped exception behavior. Both v2 formats use one marker
constant; wire-format fixtures pin prefixes, markers and address boundaries.

Address construction bounds use `nonEmptyBounded` through the existing scalar
record ABI. Deposit record admission and witness classification reuse the same
predicate. Native code retains the original invalid-argument exception and
checks the bound before serializing any amount. The size and limit remain
unsigned 64-bit across the ABI, avoiding narrowing of native container sizes.

`BmmConstants` owns the constructor/classifier address limit and v1/v2 deposit
markers. `resourceHeader` emits exact byte arrays (without string terminators)
for the native adapters. Configure-time header checks and golden/wire-format
tests guard against changing these consensus bytes during regeneration.

Initial peg-in format routing uses scalar rule 30. Native code supplies stack
size, marker equality and configured-slot presence; Haskell selects federated,
native, ECX, rejected ECX or rejected federated, plus the expected stack size.
The internal scalar reply packs the route in its low byte and expected count
above it; native and Haskell consumers must be rebuilt together. ECX rejection
still precedes prefix decoding, while the federated rejection is applied only
after shape/prefix checks, preserving diagnostic precedence. The route does not
authenticate a deposit. Native exhaustive adapter
tests cover all marker/slot combinations for stack sizes 0..12; properties also
cover malformed flags and full-width counts. Replay publication and defensive
address copying now reuse the Haskell address-limit constant as well.

ECX routes share the same prefix parser before calling `DepositWitnessKind`.
The former private ECX helper duplicated the route's guaranteed marker/size
checks and the classifier's asset/genesis checks, with an unreachable federated
fallback. It is removed. Tests cover six- and eleven-item routes, mismatched
identities and transactions, prefix-error precedence and unchanged status flags.
This reuse does not make legacy witness classification an authenticated deposit
proof; slot-assigned networks still reject the ECX route before parsing.

`DepositWitness` mode 3 performs only shallow legacy recognition: six items,
the exact legacy marker and a 32-byte txid item. It shares `legacyWitnessShape`
with full classification but does not inspect the prefix, copy the txid, hash a
transaction or write a value. Identity/hash/value pointers are unused in this
mode. The native `IsLegacyDrivechainDepositPeginWitness` delegates to it; invalid
amounts may still match the shape, exactly as before. It must not be used as
deposit authentication.

`BmmConstants.depositLayouts` owns construction order for the six-, eight- and
eleven-item witnesses. Generated byte tables select input-field indices, with
254/255 selecting the native/legacy marker. One native assembly loop moves the
typed fields into those positions. Upstream codecs still serialize amounts,
sequence numbers and headers. The legacy/native amount wrapper retains its
translated serialization error; evidence construction retains unwrapped errors.
Exact constructor tests distinguish all field identities and suffix positions.

`NativeAdmissionFlow` sequences configured-slot, witness, genesis, asset and
claim-script checks before the confirmed-deposit lookup. Invalid and unavailable
results both reject; only unavailable requests the optional native flag update.
Haskell selects native diagnostic callbacks before terminal rejection. Trace tests
cover first-failure short-circuiting, all lookup outcomes and callback faults.

Header layout includes an internal parent-height flag (bit 7 of the returned
field mask), derived from the two inbox version bits in Haskell. Wire encode,
decode, block hashing and disk-index serialization consume this single result.
No on-chain version bit or field is added; native golden hashes/bytes stay fixed.

`Exchange.ActivationAnchorFlow` (selector 272, bound 28) owns the one-shot
activation execution-anchor sequence. Eligibility and identity checks (1-17)
short-circuit without clearing the ordinary parent tuple. Optional parent fields
(18-20) are copied only when complete (21); the context is then cleared (22)
before anchor availability, non-null bid, decoding, lookup and MTP checks
(23-27). Only successful authentication publishes the anchor (28). The native
adapter retains typed comparisons, bounded byte extraction, parent lookup and
field assignments. It resets the authentication flag on entry as before.
QuickCheck compares direct and ABI flow traces, malformed replies and callback
faults; native tests additionally track capture, clearing and publication effects.
These sequencing tests do not replace live parent-chain reorg qualification.

`ParentReplay.currentEpoch` owns the nonzero, equal-generation fence shared by
anchor authorization (record 20) and mempool mining eligibility (record 31).
Both generations remain unsigned 64-bit values across the ABI. Anchor presence
and slot-range checks still apply independently; the shared predicate does not
authorize an absent anchor. `validation.h` retains only the native declaration,
with the implementation delegating through the existing record ABI. QuickCheck
and native boundary matrices cover zero, mismatches and generations above 32 bits.

The BMM-context RPC authentication flow (224, bound 6) first checks whether the
source stage selected a native anchor. Historical context returns immediately,
without warming or querying the native parent. Native context retains the
warm-up, nonzero epoch, active anchor, locked snapshot recheck, and publication
order. Lock acquisition and RPC error rendering remain native adapters. The
private test-block generator uses the existing lazy pair flow to require a
template before accessing its BMM-proof flag; it remains compile-time gated.

`BmmConstants.publicJetPins` owns the seven public fork-added jet records.
`publicJetHeader` generates `drivechainPrimitiveJetNode.inc`, included separately
from the unchanged upstream `primitiveJetNode.inc`. C designated initializers
keep enum-to-node mapping independent of declaration order. CMake rejects a
generated-file mismatch. The public and historical-private catalogues share the
same record renderer, while retaining distinct names, fingerprints and costs.
The compressed-SP1 cost comes from the existing Haskell-owned cost constant.
This is metadata generation, not a recalibration or change to jet execution.

`parentRulesHeader` also generates frozen identity selection and compile-time
profile guards. Betanet's replay version is shared with its catalogue entry and
empty-bootstrap version; slot checks use `sidechainSlot`. Unsupported versions,
mismatched local-rule domains and invalid Betanet/test-profile slot choices
still fail compilation. `drivechain_parent_rules.h` retains only native enum and
record adapters plus the generated include, without a parallel policy copy.

`ParentReplay.BranchReplayFlow` (283, bound 22) screens the fork-added crash
recovery branch before ordinary rollforward. It stops at null or the fork
boundary, rejects unreadable blocks, and requests validated replay on fork
header state, the historical checkpoint, pegins, or reserved state spends.
Header and reserved-outpoint checks are Elements-only; pegin detection is not.
Native callbacks retain block I/O, typed hashes/outpoints and output publication.
The inherited rollforward implementation is not migrated. QuickCheck covers
nested traversal and callback failures; native tests compare read/publication
order against the original boolean policy. These are not live crash tests.

`RecoveryAncestorFlow` (284, bound 13) preserves the fork's three-phase pointer
walk: align the first height, align the second, then walk together. Null checks
remain ordered before height/parent reads, including disjoint trees and unusual
stored heights. `RecoveryAdmissionFlow` (285, bound 8) screens both branches
before consulting persisted exchange/BMM flags and branch-derived requirements.
Only the fork's refusal policy is moved; native rollback, rollforward, cache
flush and progress reporting remain unchanged. Independent native pointer walks
and QuickCheck traces exercise these boundaries without touching live databases.

`EphemeralHeaderFlow` (286, bound 13) owns the fork-only full-block-first header
preflight: native network, absent index, header validity, predecessor presence,
failure status, authentication, contextual validity, then publication. Native
callbacks keep hashing, index access, existing validation routines and precise
error rendering. The optional predecessor output is cleared before dispatch and
published only on success. It does not migrate upstream AcceptBlockHeader logic.

`ConnectionAnchorFlow` (287, bound 11) owns the fork-only persisted-anchor
acceptance decision during block connection. An internally sane context is
required first. Only an absent anchor on a dry-run index skips equality and
predecessor checks; a persisted anchor must match even during a dry run. Existing
lazy predecessor predicates retain null/optional guards. Native callbacks keep
typed anchor construction/comparison and exact error text; no anchor is written
by this workflow. Native truth-table tests and QuickCheck traces cover early
errors, dry-run behavior, callback faults and malformed replies.

`ConnectionStateFlow` (288, bound 12) sequences the fork's post-CheckBlock state
connection: capture prior BMM state, optionally bind a private-network parent,
check/connect BMM, connect exchange state, then check the withdrawal envelope.
Non-Elements mode performs no state operations. Missing prior state or parent
lookup remains nonfatal; only successful lookups publish those optional values.
The parent capture occurs before BMM advances the view. Native callbacks retain
state objects, view access, and the three distinct consensus rejection messages.
The inherited block connection after these operations is untouched. Native
truth tables verify publication and order; QuickCheck also checks interruption
at every callback boundary and malformed ABI replies.

`Exchange.RuntimeActivation` computes the runtime-configured flag and earliest
activation height together, including an optional private checkpoint. Disabled
ordinary activation uses the Int32 maximum sentinel; private presence remains
distinct from its height. Its configuration-domain adapter rejects malformed
presence flags, nonzero absent payloads and null outputs before writing. Height
validation stays with the existing callers; this rule preserves signed minimum
selection rather than silently changing their validation policy.

`Exchange.LegacyMarkerFlow` (289, bound 6) shares forced-action/deposit marker
admission: magic detection, exact frame, envelope, typed payload validation,
then result publication. Absent markers succeed without a result; malformed
markers fail before publication. Native adapters retain script/key operations, payload
construction and distinct error messages. The optional result is cleared before
dispatch. QuickCheck checks callback faults and malformed replies; native tests
check all boolean paths, exact callback order and publication.

`Exchange.GenesisInitialization` also owns final publication selection. After
facts 0..4 pass for legacy initialization it invokes action 19; after facts 0,1
and 5..18 pass for checkpoint initialization it invokes action 20. Native
actions only assign the selected height and parent time. Invalid versions and
failed facts never publish; failed publication returns an internal error.
Outputs are cleared before dispatch. The existing ABI entry and error codes
are retained, with no additional operation or duplicated version selection.

`Exchange.MarkerAuthenticationFlow` (290, bound 6) requires the marker's
availability context before considering optional wrapper authentication. A
required signature first checks the key, then verifies the signature; an
invalid key never reaches verification. Native callbacks retain tagged hashing,
key construction and cryptography, with separate context/signature errors.
The signature digest is still computed before the key check. Existing parser
output mutation semantics and all preceding framing/identity checks are unchanged.

`TrackerPhase` encoding now distinguishes a missing coin (status 2) from a
malformed record (status 1), with success 0. Its existing ordered facts reject
absence before touching the output and reject confidential encodings before
explicit asset/value access. Native loading and decoding share one function;
the redundant pre-decoder spent check is removed. Script and payload phases
retain status 0/1, and native exception/diagnostic boundaries are unchanged.

`Unsigned32Fields` shares the inclusive 32-bit bound across argument values and
source serialization lengths. `FitsU32` takes unsigned fields; converting a
signed 64-bit argument to uint64 preserves admission because all negatives map
above UINT32_MAX. Empty lists pass. The read-only ABI rejects nonempty null
buffers and counts exceeding safe pointer-index arithmetic before reading.
Its configuration-domain handler is appended at index 36. Native argument
parsing, stream serialization, diagnostic text and casts remain adapters.

`StartupParentFlow` shares three stages: before database loading (selector 315),
before block verification (316), and before P2P/RPC exposure (291). Action 7
checks the native-drivechain gate first; an ordinary network returns success
without parent, chainstate or notification calls. Action 8 publishes the existing
startup notification only for loading and service exposure. Actions 1/2 authenticate the parent and read a
nonzero replay epoch. Action 3 sweeps the mempool; failure invokes warning action
4 but continues. Actions 5/6 reconcile anchors and activate the best chain.
Results 1/2 identify authentication and epoch failure; 3 is reconciliation or
activation failure (the native action retains the distinct diagnostic), and 0
is success. Warning action 4 must acknowledge completion. Exceptions
are rethrown by the native callback adapter without running later actions.
The loading stage ends after the epoch check and preserves its combined
authentication/epoch failure diagnostic. Verification warms the parent and then
reconciles, without reading the epoch, sweeping the mempool or activating.
The common native adapter retains RPC calls, chainstate locks, logs and exact
translated diagnostics, including the load-time empty-error fallback. Parent
outages still fail fatally before databases can be opened or reindexed; the
verification stage remains conditional on successful inherited LoadChainstate.
Native exception traces and independent property models cover all stages,
including the ordinary-network bypass and nonfatal service-time mempool sweep.

`StartupBundleFlow` (317) restores the withdrawal bundle after chain clients
start. It checks Elements parent mode (1), then acquires the native chain lock
and checks the tip (2). Only a present tip supplies its hash (3); publication
(4) and logging (5) remain under the same lock. Without a tip, publication uses
zero. Outside Elements parent mode, action 6 publishes zero without acquiring
the chain lock or logging. Native RAII owns the lock and releases it on all
exits; callback exceptions stop later effects. The final native BMM submission
gate reuses `ParentReplayAll<2>`: parent lookup exceptions still propagate,
while only submission exceptions are converted to logged failure.

`BlockValidationFlow` owns three fork-added sequences. Contextual header checks
(318) bypass Bitcoin-mode chains and run BMM before exchange validation.
Contextual output checks (319) preserve the configured transaction pass before
the active explicit-creations pass, including lazy activation reads inside the
first pass. Candidate self-checks (320) run contextual header, block and
contextual block checks before opening the native parent-validation budget.
Only non-genesis, assigned-slot candidates fetch parent context; successful
authentication publishes its pointer before the final dry-run connection.
Native callbacks retain diagnostic publication, locks, coins/index ownership,
script validation and budget destruction. Callback failure prevents later
actions. The inherited ordinary `TestBlockValidity` sequence is unchanged.
Connection/reindex reuses the same output rule per transaction, while contextual
validation keeps two separate whole-block passes; these orders are not merged.

The same validation family owns context-free checker selection (321), startup
reconciliation (322), and native exchange-parent selection (323). Context-free
screening selects the aggregate-deferred checker only when configured, without
moving the inherited transaction implementation. Reconciliation prepares its
snapshot before taking cs_main and the optional mempool mutex; native tracked
RAII locks remain held until the result and any stalled-state error are handled.
Exchange binding selects a present candidate before a derived BMM context,
then checks hash and median time. An unusable present candidate never falls
back to another source. It binds authenticated P, never successor Q.

`ApprovingParentHeight` (configuration handler 39) accepts parent heights in
0..UINT32_MAX-1 and returns their successor; -1 means out of range and -2 is an
adapter failure. The native output is untouched on rejection. `ChildBehind`
(handler 40) compares signed 64-bit heights without subtraction or narrowing,
including an empty child's -1 height. Fork-only candidate dummy-index height
uses the existing checked `NextBlockHeight`; inherited arithmetic is unchanged.
Startup bundle and reconciliation adapters use `UniqueLock`, retaining the
node's debug lock-order tracking as well as physical mutex ownership.

`BoundedWait` centralizes the positive wait rule `max 1 (min maximum value)`.
Its configuration handler 37 takes signed 64-bit values and returns -1 for a
nonpositive maximum; native adapters throw on an invalid result. Child polling
uses maximum 25 milliseconds, while automatic sync uses INT64_MAX seconds to
retain its prior minimum-only clamp. Clock reads, unit conversion and OS waits
remain native; this rule does not alter deadlines or add an upper sync limit.

`BoundedAppend` (configuration handler 38) selects the bytes retained from a
subprocess read: the lesser of its nonnegative count and remaining output
capacity. Unsigned capacity subtraction occurs only when used is below limit;
negative counts return -1 and the native adapter throws. OS reads, buffer
ownership, append, and truncation reporting remain native. This rule belongs
to the fork-added bounded subprocess runner, not upstream process handling.

`Bmm.ConnectionContextFlow` (store selector 296, bound 14) chooses block-connect
parent authentication in order: network slot, candidate context, critical-hash
derivation, finalized-context identity or fresh BMM verification. It publishes
the parent timestamp only after the selected path succeeds. Ordinary networks
reject a supplied candidate and otherwise do no parent work. Native callbacks
retain context ownership, authentication primitives and exact diagnostics;
the existing candidate/finalized exclusivity and dry-run assertions stay native.
The shared command interpreter handles this simple validation table without a
new Operation instance or exported FFI function. Native exhaustive traces and
QuickCheck cover lazy paths, failure precedence, publication and ABI failures.

`ScriptPolicy.ParameterGate` mode 2 owns whether an explicit-only activation
height is configured (nonnegative); its reserved second argument must be zero.
`Consensus::Params::ExplicitOnlyConfigured` shares this rule across context-free
screening, contextual validation and authoritative block connection. Mode 0
still owns activation at a particular height. Configuration does not mean the
rule is already active: future activation still defers context-free totals and
requires contextual rechecks. The distinct ordering of those rechecks remains
unchanged by this predicate extraction.

`Bmm.NextBlockHeight` mode 2 supplies the wide successor used when binding the
bond script context. It shares the existing configuration ABI handler without
changing modes 0 (absent) and 1 (checked Int32 successor). The native
`NextBondContextHeight` adapter checks the signed result range before converting
to uint64, preserving the old unsigned wrap for negative inputs and allowing
INT32_MAX + 1. It is not interchangeable with `NextBlockHeight`, which rejects
that upper boundary. No inherited height calculation uses the new mode.

`BlockValidationFlow` stages `FinalBmm` (324) and `BmmFailure` (325) own final
ConnectTip admission and the shared permanent/transient failure selection.
Final admission returns 0 for failure, 1 to continue validation, or 2 for a
retryable stall. Slot/genesis gates precede context construction and critical
hash derivation; only immutable INVALID evidence invokes InvalidBlockFound.
PARENT_REJECTED and UNAVAILABLE suppress the candidate without poisoning its
index. Native callbacks retain context ownership, state methods, locks and
diagnostics. Fatal/error callbacks must return false; unexpected successful
error callbacks fail the interpreter contract. The existing command runner
preserves caller-thread execution and exception propagation. No inherited
pegin-ripeness check or new FFI symbol is involved.

`BranchChoice` generalizes the former context-free transaction selector without
changing its ABI identifier (321), three actions or transition table.
`ParentReplayChoose` takes condition/true/false callbacks and invokes exactly
one branch, returning that branch's Boolean result. It is reused by context-free
checker selection, exchange script-context binding/clearing, and temporary
CheckTxInputs error handling. The latter leaves inherited permanent-invalid
handling outside the helper and preserves existing state methods and diagnostic
order. The native adapter checks action indices and preserves callback exceptions
and caller-thread execution. This adds neither a new flow nor a capability
framework; the existing Validation dispatch remains shared.

The same choice and conjunction helpers gate fork-added fee bypass/subsidy
dispatch, optional disconnect restoration, out-of-lock snapshot refresh and
SP1 resource checks. Disabled resource validation never constructs the reader
or dereferences transactions. Snapshot presence is sampled under cs_main, then
refresh executes after releasing that lock and before the existing chain/mempool
lock scope. The native mempool fee floor still precedes the relay-fee exemption;
inherited fee arithmetic and subsidy accumulation are unchanged. No additional
Haskell rule or ABI selector is needed for these compositions.
