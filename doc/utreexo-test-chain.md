# Parallel Utreexo test chain

The non-installed `elements-functional-test-node -chain=elementsutreexo` selects
a fresh custom Elements test chain. The production executable remains locked to
its existing canonical network. The test chain's
name participates in genesis/asset derivation and it uses P2P magic fabfb5e8
and port 19448. Use a new data directory. Existing Elements, Liquid and Bitcoin
networks are unchanged. Never point this experiment at an existing live data
directory or present it as a coordinated upgrade of that chain.

## Consensus

Every block after genesis must set version bit 15 and append the following
fields after existing header extensions and before the dynafed witness:

- u64 little-endian cumulative accumulator leaf count;
- CompactSize root count, followed by that many raw 32-byte roots, in rustreexo
  forest order. Count must equal popcount(leaves), leaves must be below 2^63.

This extension is decoded only in the test chain's serialization mode; the
meaning of version bit 15 is unchanged on existing networks.

Both the ordinary header hash and BMM critical hash cover these fields. This is
Thunder's mandatory post-block forest-root model, extended to commit the leaf
count explicitly. It is not Thunder wire compatibility. Genesis remains in its
existing serialization; the initial forest is deterministically seeded from
the genesis outputs that the node actually connects.

The v1 leaf is SHA256d of the existing native serialization of:
`string("Elements/Utreexo/Coin/v1"), genesis hash, outpoint, Coin`. The existing
durable Coin encoding includes creation height/coinbase status, asset and value
(explicit or committed), and script using Elements' standard compression. It
intentionally excludes the blinding nonce, which upstream omits from stored
UTXOs; the transaction ID in the outpoint already commits to it. This gives the
same leaf before and after a coin-cache flush or restart without changing any
upstream storage or cache behavior. No unblinding is performed. Unspendable
outputs are excluded exactly as in AddCoins. Outputs created and spent inside
one block cancel before the ordered additions are applied. Deletions cover
ordinary child inputs; parent peg-in inputs retain their existing independent
authentication and replay checks. Their newly created child outputs are added.

## Implementation and safety

C++ supplies canonically serialized existing Coin data. The linked Haskell FFI
admits the call into a small versioned Rust C ABI. Rust uses rustreexo pinned to
`b73cbac1f425f0e849faa279982ef4f5ec9f3754`; Cargo.lock pins its dependencies.
Each transition cross-checks MemForest against an independent Stump transition
using a generated deletion proof. Rust panics cannot cross the FFI boundary.

The normal UTXO database, confidential validation, signatures, script cache,
range-proof cache and surjection-proof cache are unchanged. A commitment match
does not skip any validation. Snapshots are written only after all normal checks
and the header-root comparison pass, including parallel script/proof checks.
Snapshot checksums and predecessor-header commitments are checked on load.

Snapshots are immutable block-hash-keyed entries under key prefix A in the block
index database. They are synchronously persisted before the script-valid marker.
Reorgs select the predecessor snapshot, without mutating another branch. A crash
may leave an unused snapshot but not a script-valid tip with an unwritten one.
Full reindex rebuilds the snapshots; chainstate reindex verifies/recreates them.
Missing or corrupt snapshots fail closed and require reindex, not silent reset.
Prefix U remains reserved; the Utreexo namespace is unchanged by the removal of
the previous exchange implementation.

This first parallel implementation intentionally follows Thunder's full-forest
snapshot approach. It keeps a serialized forest for each validated block, has
O(UTXO count) transition memory/copy cost, and potentially quadratic historical
snapshot storage. Pruning block files does not prune these snapshots. This is a
small isolated test-chain qualification implementation, not a resource-efficient
production rollout. Disk-backed forest/delta storage is a prerequisite for a
large-chain deployment. No automatic snapshot deletion or live deployment is
performed.

## Compact clients are separate

No proof-serving RPC or P2P extension, compact client, trusted snapshot bootstrap,
or accumulator-proof cache is added here. A future fully validating compact
client must authenticate supplied prevouts before consulting validation caches,
verify all existing Elements/fork rules and parent-chain evidence, maintain its
own roots and non-UTXO consensus state, and handle proof updates/reorgs. Headers
alone are not proof that a block is valid.

## Tests

- `cargo test --locked --manifest-path src/haskell/utreexo-rs/Cargo.toml`
- Native `utreexo_tests`: FFI, snapshot round trips, branches, duplicate/missing
  leaves, confidential coin field binding, header/disk serialization, BMM hash
  binding, bounded root decoding, mandatory header admission, inactive-network
  serialization, corrupt/stale snapshots and withdrawal-database key isolation.
- `test/functional/feature_utreexo.py`: two-node agreement, confidential payment,
  cache-enabled/disabled invalid-proof rejection, mandatory/wrong header roots,
  issuance/reissuance, restart, rollback/reconsideration and chainstate reindex.

Functional tests create only local custom-chain test assets. They do not start
or bid on the public parent network.

The functional fixture uses SQLite descriptor wallets (`--descriptors`). Build
`elements-functional-test-node` and `elements-functional-test-cli`, then pass the
build's `test/config.ini` to the test. Uninstalled macOS executables also need
`DYLD_LIBRARY_PATH` set to the build's `src/haskell` directory. Installed runtime
bundling is a separate release check. This change has not qualified Windows or
Linux packaging; it does not remove the existing Haskell cross-build restriction.

## Compared with SPV

SPV proves transaction inclusion in a selected header chain, but does not run all
transaction-validity rules. A future compact validator can authenticate prevouts
against roots it independently computed from valid history, then apply the same
signatures, confidential range/surjection proofs and fork-specific consensus
checks as a full node. It saves UTXO storage, not those validation costs, and must
download full block transactions and additional membership proofs. A header-root
match or an L1 BMM commitment alone is not sufficient to trust the state.
Using mainchain SPV additionally retains SPV's assumptions about parent-chain
validity. The client must still authenticate and replay all parent data required
by this fork's deposit, withdrawal and BMM rules; an isolated inclusion proof
does not establish a complete withdrawal-vote or treasury-state history.
