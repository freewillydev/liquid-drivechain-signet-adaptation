# Elements Native

This branch contains upstream Elements, native BIP300/BIP301 deposits,
withdrawals and BMM bidding, and the parallel Utreexo test-chain accumulator.
Confidential transaction range proofs, surjection proofs and amount validation
remain native Elements features.

No exchange, USDD bridge, SP1 jet, proof program or external verifier archive is
part of this branch. The fairmint exchange is maintained on `fairmint-exchange`.
The previous complete implementation is preserved on
`archive/exchange-usdd-sp1-20261027`.

## Chain Isolation

This branch targets a **fresh child chain**, not an upgrade of the running
Betanet child. Its data subdirectory is `elements-native-v1`, with P2P port
7072 and RPC port 7071. Never reuse another chain's databases or wallets.
The frozen identity is in `src/elements_drivechain_identity.h`; its independent
serializer is `contrib/devtools/elements_identity_refreeze.py`.

The current parent profile remains ECX Betanet, slot 24. A new matching sidechain
proposal must be activated before that parent can authenticate blocks and peg
operations for this fresh child. The former existing-proposal override is off.
This is not a production ECX identity. Its genesis, network magic and data
directory also differ from the fairmint branch; they are separate fresh chains.

## Build and Test

Use the platform instructions in `doc/build-unix.md` or `doc/build-osx.md` and the
Haskell requirements in `src/haskell/README.md`. CMake builds the Haskell library
and native node together. No USDD or SP1 verifier archive is required.

```sh
cmake -S . -B build -DBUILD_TESTS=ON
cmake --build build -j1
ctest --test-dir build --output-on-failure
```

Keep RPC private and authenticated. Configure a synced parent matching the frozen
network identity, using a local cookie or the authenticated TLS transport
described in `doc/drivechain-rpc-security.md`. Start with
`drivechainl1blocksync=0`; enabling a producer and funding its dedicated bidding
wallet are separate operator decisions.

## Documentation

- [Fresh-chain identity](doc/drivechain-network-identity.md)
- [Utreexo test chain](doc/utreexo-test-chain.md)
- [Deposits and withdrawals](doc/drivechain-peg-operations.md)
- [RPC reference](doc/supported-rpcs.md)
- [Security reporting](SECURITY.md)
- [MIT license](COPYING)
