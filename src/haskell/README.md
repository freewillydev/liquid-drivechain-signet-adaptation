# Haskell node workflows

This branch retains native BIP300/BIP301 and Utreexo, without an exchange.
The previous exchange and proof-verifier implementation is preserved on
`archive/exchange-usdd-sp1-20261027`, not linked into this branch.

## Boundaries

Inherited Elements validation, confidential-transaction cryptography and caches
remain in C++. Haskell owns fork-added decisions and workflow orchestration.
Native callbacks retain object ownership, checked serialization, cryptography,
database transactions, locks and external I/O. A callback must not publish state
before the workflow has authenticated its inputs and accepted the transition.

| Native owner | Retained responsibility |
| --- | --- |
| `consensus/tx_check.cpp` | Checked ABI bindings, native peg codecs |
| `mainchainrpc.cpp` | Parent RPC, replay snapshots and BMM bid wallet |
| `rpc/request.cpp` | Credential ownership and authenticated transport |
| `block_proof.cpp` | BMM proof admission and commitments |
| `pegins.cpp` | Deposit evidence |
| `txdb.cpp` | Parent replay storage |
| `node/blockstorage.cpp` | Parallel Utreexo accumulator |
| `node/transaction.cpp` | Automatic deposits and withdrawal journal |
| `validation.cpp` | Validated native block/coin snapshots and publication |
| `wallet/rpc/elements.cpp` | Native withdrawal wallet helpers |

## Private ABI

`abi.def` is the operation registry. `generate_abi.py` generates the checked
Haskell dispatcher and typed C++ bindings. The four version-3 families are:

- Node: configuration and script policy.
- Parent: authenticated parent replay workflows.
- BMM: admission, proof, codecs and state.
- Peg: deposits, evidence, deposit state and withdrawals.

Rebuild the node and its Haskell library together. The removed families are
absent; version 2 is not reused with different selector meanings. Unknown
sections, operations and malformed argument frames reject before effects.
Retired command numbers inside retained protocols remain reserved.
Direct gRPC and Utreexo have their own bounded interfaces.

`Binding::operator()` performs typed transport, not a consensus check by itself.
Reducing exported symbols does not reduce calls. Count static binding sites,
runtime entries and native callbacks separately. Prefer one complete workflow
over native code repeatedly entering Haskell for individual predicates.

## Operation design

Reuse `operation-capabilities`; do not duplicate its framework. Keep
`Operation op caps | op -> caps` and capability constraints on the existential.
An interpreter first proves payload equality, then matches its associated DSL
GADT to obtain the selected capability dictionary. Concrete behavior belongs in
the capability instance, not a growing central dispatcher.

`Withdrawal.WalletBundleRequest`, `Bmm.SubmissionRequest`, and the replay-store
operations are examples of composing complete workflows. Simple deterministic
rules use `Check` and `Validation`. `NodeRules` contains shared configuration,
fee, identity and cache rules, independently of exchange features.

Preserve lazy dispatch mismatches, validation order, short-circuiting, effect
ordering and FFI lifetimes. `Nothing` means dispatch mismatch, not invalid
consensus data. Native failures must cross the boundary through checked results,
not exceptions escaping a C callback. Capability visibility is an API discipline,
not evidence that authorization or validation occurred.

## Verification

Build with CMake and run the native tests, ABI/loader tests, Haskell properties
and relevant functional tests. `elements-haskell-tests.cabal` contains retained
native workflow properties. Test callback faults, malformed frames, lazy mismatches, state
rollback and successful execution, not only happy-path scalar results.

The fresh-chain identity has an independent derivation and mutation suite in
`contrib/devtools/elements_identity_refreeze.py` and its adjacent test file.
Old qualification records apply only to their exact source and binary hashes.
