# Supported RPC calls

This is a source-registration inventory for this Elements fork, including inherited
Bitcoin/Elements methods. Registration does **not** mean every method is usable on
every network, with every wallet type, or in every build. The running binary's
help is authoritative for arguments, defaults, results and availability:

```sh
elements-cli help
elements-cli help getdrivechainpegevents
elements-cli -rpcwallet=mywallet help importdrivechaindeposit
```

Use the same network and configuration options as your node. Wallet methods require
wallet support and, where applicable, a loaded wallet selected with `-rpcwallet`.
External-signer methods require external-signer build support. Historical queries
may need indexes or unpruned blocks. Deprecated, hidden and testing methods are
listed separately and are not stable application interfaces.

Never expose RPC directly to the public internet. Use cookie authentication or
configured RPC credentials and a protected transport. See
[RPC security](drivechain-rpc-security.md) and
[JSON-RPC transport](JSON-RPC-interface.md).
Key export methods expose secrets; send, submission, import, wallet and administrative
methods can change state or spend funds. Listing a method is not advice to execute it.

## Drivechain, exchange and proof interfaces

| RPC | Purpose and important limits |
| --- | --- |
| `importdrivechaindeposit` | Wallet call constructing a deposit claim. Native arguments are `mainchain_txid mainchain_vout mainchain_block_hash address value_sats (fee_sats deposit_fee_sats)`. Verifies exact deposit evidence, activation and confirmation depth using authenticated parent replay. `fee_sats` remains wallet-sponsored; `deposit_fee_sats` must exactly match the fee committed in the L1 destination and is deducted from the credit. Cannot combine both. Existing address-only deposits remain fee-free. Historical ECX routing has a different signature; consult the selected network's help. |
| `getdrivechaindepositdestination` | Encodes an Elements recipient and exact fee into the opaque L1 M5 destination, with optional BitWindow slot prefix in the result. Does not sign or broadcast. Requires native Drivechain mode. Use before funding, and upgrade validators before using nonzero committed fees. |
| `sendtomainchain` | Wallet peg-out entry point. Behavior depends on the configured network and peg-out policy; does not imply immediate L1 payout. |
| `getdrivechainpegevents` | Scans active-chain peg events. Optional `include_l1` queries the enforcer's `GetTwoWayPegData`; this is not the native deposit-validation authority. |
| `getdrivechainwithdrawalbundle` | Derives a canonical blinded M6 from a confirmed native pegged-asset burn. Does not submit it. |
| `verifydrivechainwithdrawalbundle` | Checks a proposed blinded M6 against its confirmed burn. Does not submit it or cast a vote. |
| `submitdrivechainwithdrawal` | Derives and idempotently submits the burn's bundle to the miner enforcer's wallet-free `BlockProducerService/ProposeWithdrawalBundle`. Submission is not approval or mined M6 inclusion. |
| `getbmmconsensuscontext` | Returns the active tip's authenticated prior-parent context. Does not choose a future block's parent or activate ECX. |
| `submitbmmworkbid` | Constructs, funds, signs and broadcasts a BIP301 M8 transaction through the explicit `drivechainbmmwallet` on parent RPC, subject to candidate fee, verification-work and reserve limits. Can spend bid funds; never falls back to an enforcer wallet. |
| `getecxconsensuscontext` | Returns ECX source heads and authenticated BMM clock used by mempool/next-block Simplicity execution. |
| `getecxstateutxoroot` | Computes the ECX header root for an existing unspent output; intended for freezing an activated-regtest genesis singleton. |
| `getecxbondinboxentries` | Reconstructs a bounded range of node-verified bond-inbox entries and source transactions from archival blocks. |
| `getusddwithdrawalaccumulator` | Returns the generic Ethereum-withdrawal accumulator. The root alone does not authorize USDD release; external deployment asset/vault identities must match. |
| `getusddwithdrawalproof` | Reconstructs withdrawal inclusion evidence from retained blocks; requires unpruned withdrawal blocks, with a 10,000-leaf and ten-second work bound. This is not an SP1 proof generator. |
| `getalphacheckpointevidence` | Captures bounded raw evidence at an exact active tip. Flushes the coins cache and holds the chain lock; not a lightweight polling call or a qualified proof. |
| `getsimplicityinfo` | Reports Simplicity information for the node. |
| `getsidechaininfo` | Reports Elements sidechain configuration/information. |

Enforcer gRPC methods are **not Elements JSON-RPC methods**. Withdrawals use
the miner's `ProposeWithdrawalBundle`; BMM bids use ordinary authenticated
parent wallet RPC and `sendrawtransaction`, not `CreateBmmCriticalDataTransaction`.
See [funding and miner endpoint setup](drivechain-rpc-security.md). Native
deposit validation uses local authenticated parent replay, with mainchain RPC
checks where needed. Platform and configuration restrictions still apply to
submissions; consult [peg operations](drivechain-peg-operations.md).

## Complete registered inventory by category

Names below follow the registration tables, not a guarantee of successful
execution in the current chain state. Fork-specific names above are repeated
in their registered categories for completeness.

### Control

`getmemoryinfo`, `getrpcinfo`, `help`, `logging`, `stop`, `uptime`.

### Blockchain and mempool

`dumptxoutset`, `getalphacheckpointevidence`, `getbestblockhash`, `getblock`,
`getblockchaininfo`, `getblockcount`, `getblockfilter`, `getblockfrompeer`,
`getblockhash`, `getblockheader`, `getblockstats`, `getbmmconsensuscontext`,
`getchainstates`, `getchaintips`, `getchaintxstats`, `getdeploymentinfo`,
`getdescriptoractivity`, `getdifficulty`, `getdrivechaindepositdestination`, `getdrivechainpegevents`,
`getdrivechainwithdrawalbundle`, `getecxbondinboxentries`,
`getecxconsensuscontext`, `getecxstateutxoroot`, `getmempoolancestors`,
`getmempooldescendants`, `getmempoolentry`, `getmempoolinfo`, `getrawmempool`,
`getsidechaininfo`, `getsimplicityinfo`, `gettxout`, `gettxoutproof`,
`gettxoutsetinfo`, `gettxspendingprevout`, `getusddwithdrawalaccumulator`,
`getusddwithdrawalproof`, `importmempool`, `loadtxoutset`, `preciousblock`,
`pruneblockchain`, `savemempool`, `scanblocks`, `scantxoutset`,
`submitdrivechainwithdrawal`, `verifychain`, `verifydrivechainwithdrawalbundle`,
`verifytxoutproof`.

### Mining and block assembly

`getblocktemplate`, `getmininginfo`, `getnetworkhashps`,
`getprioritisedtransactions`, `prioritisetransaction`, `submitblock`,
`submitbmmworkbid`, `submitheader`, `testproposedblock`.

Registered under generating:
`combineblocksigs`, `consumecompactsketch`, `consumegetblocktxn`,
`finalizecompactblock`, `getcompactsketch`, `getnewblockhex`.

These methods do not bypass the selected network's block-validity or BMM rules.

### Network

`addnode`, `clearbanned`, `disconnectnode`, `getaddednodeinfo`, `getaddrmaninfo`,
`getconnectioncount`, `getnettotals`, `getnetworkinfo`, `getnodeaddresses`,
`getpeerinfo`, `listbanned`, `ping`, `setban`, `setnetworkactive`.

### Raw transactions and PSBT/PSET

`analyzepsbt`, `calculateasset`, `combinepsbt`, `combinerawtransaction`,
`converttopsbt`, `createpsbt`, `createrawtransaction`, `decodepsbt`,
`decoderawtransaction`, `decodescript`, `descriptorprocesspsbt`, `finalizepsbt`,
`fundrawtransaction`, `getrawtransaction`, `joinpsbts`, `parsepsbt`,
`rawblindrawtransaction`, `rawissueasset`, `rawreissueasset`, `sendrawtransaction`,
`signrawtransactionwithkey`, `submitpackage`, `testmempoolaccept`,
`updatepsbtpegin`, `utxoupdatepsbt`.

`fundrawtransaction` requires wallet support. PSBT-named methods retain their
registered names on Elements; consult method help for supported PSET behavior.
Asset issuance/reissuance and confidential operations remain subject to network
consensus and policy restrictions.

### Utilities and external signers

`createblindedaddress`, `createmultisig`, `deriveaddresses`, `dumpassetlabels`,
`estimatesmartfee`, `getdescriptorinfo`, `getindexinfo`, `getpakinfo`,
`signmessagewithprivkey`, `tweakfedpegscript`, `validateaddress`, `verifymessage`.

External signer: `enumeratesigners`.

### Wallet

`abandontransaction`, `abortrescan`, `addmultisigaddress`, `backupwallet`,
`balance`, `blindrawtransaction`, `bumpfee`, `claimpegin`, `createrawpegin`,
`createwallet`, `createwalletdescriptor`, `destroyamount`, `dumpblindingkey`,
`dumpissuanceblindingkey`, `dumpmasterblindingkey`, `dumpprivkey`, `dumpwallet`,
`encryptwallet`, `getaddressesbylabel`, `getaddressinfo`, `getbalance`,
`getbalances`, `gethdkeys`, `getnewaddress`, `getpeginaddress`,
`getrawchangeaddress`, `getreceivedbyaddress`, `getreceivedbylabel`,
`gettransaction`, `getunconfirmedbalance`, `getwalletinfo`, `getwalletpakinfo`,
`importaddress`, `importblindingkey`, `importdescriptors`,
`importdrivechaindeposit`, `importissuanceblindingkey`, `importmasterblindingkey`,
`importmulti`, `importprivkey`, `importprunedfunds`, `importpubkey`, `importwallet`,
`initpegoutwallet`, `issueasset`, `keypoolrefill`, `listaddressgroupings`,
`listdescriptors`, `listissuances`, `listlabels`, `listlockunspent`,
`listreceivedbyaddress`, `listreceivedbylabel`, `listsinceblock`,
`listtransactions`, `listunspent`, `listwalletdir`, `listwallets`, `loadwallet`,
`lockunspent`, `migratewallet`, `newkeypool`, `psbtbumpfee`, `reissueasset`,
`removeprunedfunds`, `rescanblockchain`, `restorewallet`, `send`, `sendall`,
`sendmany`, `sendtoaddress`, `sendtomainchain`, `sethdseed`, `setlabel`,
`settxfee`, `setwalletflag`, `signblock`, `signmessage`,
`signrawtransactionwithwallet`, `simulaterawtransaction`, `unblindrawtransaction`,
`unloadwallet`, `upgradewallet`, `walletcreatefundedpsbt`, `walletdisplayaddress`,
`walletlock`, `walletpassphrase`, `walletpassphrasechange`, `walletprocesspsbt`.

`walletdisplayaddress` needs external-signer support. Legacy wallet operations
may reject descriptor wallets. Federated `claimpegin`, `createrawpegin` and
`getpeginaddress` are not substitutes for native Drivechain deposits: the
Drivechain network disables the legacy federated peg-in route.

### Hidden, testing and compatibility methods

Do not depend on these as stable production APIs:

`addconnection`, `addpeeraddress`, `calcfastmerkleroot`, `echo`, `echoipc`,
`echojson`, `estimaterawfee`, `generate`, `generateblock`, `generatepegoutproof`,
`generateprivatebmmblock`, `generatetoaddress`, `generatetodescriptor`,
`getorphantxs`, `getpegoutkeys`, `getrawaddrman`, `invalidateblock`,
`mockscheduler`, `reconsiderblock`, `sendmsgtopeer`, `setmocktime`,
`syncwithvalidationinterfacequeue`, `waitforblock`, `waitforblockheight`,
`waitfornewblock`.

`generate` is a compatibility stub that directs callers to the CLI `-generate`
option, not a working mining RPC. Test-only generation does not permit mining
public L1 blocks or bypassing public-chain BMM inclusion.

## Maintaining this list

Check the registration tables in [`src/rpc`](../src/rpc),
[`src/wallet/rpc/wallet.cpp`](../src/wallet/rpc/wallet.cpp) and
[`src/rpc/server.cpp`](../src/rpc/server.cpp), including conditional registrations.
Use `elements-cli help <method>` rather than copying argument schemas from an
unrelated Bitcoin Core, Elements or enforcer release.
