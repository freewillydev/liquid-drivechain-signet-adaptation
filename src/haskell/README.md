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

## Compiler and test setup

Use **GHC 9.6.7** and **cabal-install >= 3.14.2.0**; Cabal 3.16.1.0 is
recommended for new installs. The node and its Haskell property tests use the
same compiler baseline. See the [toolchain setup](../../doc/build-unix.md#haskell-toolchain)
for installation and platform dependencies.

For an existing GHCup installation, install the versioned compiler without
changing the system default:

```sh
ghcup install ghc 9.6.7
ghc-9.6.7 --numeric-version
cabal --numeric-version
```

Run the Haskell property suite from the repository root:

```sh
cd src/haskell
cabal update
cabal test --enable-tests --with-compiler=ghc-9.6.7
```

Keep the versioned compiler on `PATH`, or pass its absolute path to
`--with-compiler`. This command explicitly enables the property test suite and
selects GHC 9.6.7 even if plain `ghc` resolves to a newer compiler. A native C++
compiler is also required for the suite's reference implementation.

The pinned test dependencies include `QuickCheck ==2.15.0.1`,
`random ==1.2.1.3` and `splitmix ==0.1.0.5`. GHC 9.14.1 supplies `base 4.22`,
which conflicts with this pinned splitmix version's `base <4.21` requirement.
That combination fails dependency resolution before any tests run. Select
GHC 9.6.7 rather than overriding dependency bounds.

For a full node build, select the same compiler explicitly when configuring
CMake from the repository root:

```sh
cmake -S . -B build -DBUILD_TESTS=ON \
  -DELEMENTS_GHC="$(command -v ghc-9.6.7)" \
  -DELEMENTS_CABAL="$(command -v cabal)"
cmake --build build -j1
ctest --test-dir build --output-on-failure
```

CMake caches the selected tool paths. Pass the explicit paths again when
reconfiguring an existing build; changing `PATH` alone may leave the cached
compiler selected. Use a separate build directory when switching compilers.

## Verification

Build with CMake and run the native tests, ABI/loader tests, Haskell properties
and relevant functional tests. `elements-haskell-tests.cabal` contains retained
native workflow properties. Test callback faults, malformed frames, lazy mismatches, state
rollback and successful execution, not only happy-path scalar results.

The fresh-chain identity has an independent derivation and mutation suite in
`contrib/devtools/elements_identity_refreeze.py` and its adjacent test file.
Old qualification records apply only to their exact source and binary hashes.
