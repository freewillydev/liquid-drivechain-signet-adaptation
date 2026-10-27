# Native slot-24 deposits and withdrawals

This guide applies to the current `-chain=elements` node, not the historical
Liquid-signet/ECX bridge. Use a fresh `elements-native-v1` chain data directory. Do not
point the current binary at a preserved historical chain.

## Identity and transport

The frozen identity in `src/elements_drivechain_identity.h` specifies slot 24,
ECX Betanet with Bitcoin-mainnet ancestry, an empty signet challenge, and parent
checkpoint 967679 (`00000000000000000001b58cb69869f6067f0ecb3f2fe0f2263e62ba1ccb0c41`).
The [generated identity table](drivechain-network-identity.md) records the exact
genesis, asset, proposal and ports from that header.
This is not a runtime-selectable signet. Sharing Bitcoin's genesis and address
prefixes does not prove a connected node follows the intended parent fork.
Verify the checkpoint, enforcer compatibility revision, proposal identity, and
activation on the intended parent deployment before funding anything.
The former Betanet proposal is not reused; the new matching proposal must be activated.

Follow [RPC security](drivechain-rpc-security.md). Parent access requires
authentication on numeric loopback, preferably a private rotating cookie;
an explicit private credential file is supported for same-host bridges.
Enforcer requests use the linked Haskell gRPC client with mutual TLS. Keep
`drivechainl1blocksync=0` while preparing or auditing the deployment.

Automatic bidding only pays for candidates containing at least one selected
mempool transaction besides the coinbase. Empty candidates remain idle, including
when the assembler excludes all pending transactions. A bid already submitted
continues waiting for confirmation even if the mempool changes. This is producer
policy only; accepting other miners' consensus-valid empty blocks is unchanged.
No command below is authorization to spend real funds.

## Deposit

Create/load an Elements wallet and obtain an address that it controls. Create
the slot-24 M5 deposit through the parent wallet/enforcer, recording the exact
outpoint and intended destination. The node authenticates parent headers,
raw blocks, treasury transitions, destination and value from parent replay;
a bridge assertion or wallet balance is not deposit evidence.

The node automatically imports mature deposits for all recipients, including
external wallets, by default (`-drivechainautodeposit=1`). Every 30 seconds it
reads up to 64 records from the authenticated parent index and attempts at most
eight imports. It needs no loaded wallet or spending key and runs independently
of block bidding. A cursor wraps through the index; restarting starts another
pass. Already-claimed or mempool deposits are skipped using the normal peg-in
spent key. Missing, reorged or immature evidence cannot authorize an import.
Disable this local submission service with `-drivechainautodeposit=0`; ordinary
transaction validation remains enabled.

Discovery reads confirmed parent history, not just the current parent mempool:
a deposit mined while this node was offline is eligible on a later scan once
the parent replay catches up and the six-confirmation requirement is met.
Automatic import creates an Elements mempool transaction, not an immediate
Elements confirmation. A producer must still include the claim in a block
with a mined BIP301 commitment. No import RPC call is required for discovery.

Existing address-only deposits, including BitWindow deposits, continue to
credit the entire deposit without an Elements fee. BitWindow's existing fee
field is the **parent transaction fee**, not an Elements fee.

Manual import remains available after the required active parent depth:
six confirmations for the Betanet slot-24 identity, counting inclusion as one.
The frozen identity retains its historical 100-block parameter; the effective
Betanet confirmation policy is six, without changing that identity.

```sh
elements-cli -chain=elements -rpcwallet=<wallet> importdrivechaindeposit \
  "<mainchain-txid>" <mainchain-vout> "<mainchain-block-hash>" \
  "<elements-address>" <value-sats> <fee-sats> <deposit-fee-sats>
```

Both fee arguments default to zero. `fee_sats` retains its old meaning: a
maximum wallet-sponsored fee requiring separately spendable funds, without
reducing the deposit credit. `deposit_fee_sats` is instead the exact fee
committed on L1, as described below. They cannot both be nonzero.
Record the returned sidechain transaction ID. Check
`gettransaction`, `listunspent`, and the active confirming block, including
after restart. A mempool transaction is not confirmed spendable chain state.
Never substitute a different vout, address, amount, or parent block to work
around a rejection.

### Committing an Elements fee on L1

**Upgrade all sidechain validators before funding this new destination format.**
It changes native deposit consensus acceptance; older nodes cannot validate
fee-bearing claims. This does not change the meaning of existing deposits and
does not retroactively authorize a fee on them.

Before creating the L1 deposit, obtain its destination without signing or
broadcasting anything:

```sh
elements-cli -chain=elements getdrivechaindepositdestination "<elements-address>" 1000
```

The result's `destination` is the exact opaque M5 address field to pass to the
parent deposit builder. It encodes `dcfee1:1000:<elements-address>`; the fee is
a positive canonical integer in satoshis. Zero returns the original address.
`bitwindow_address` adds the configured `s24_` prefix for BitWindow's generic
parser. This does not add an Elements-fee control to BitWindow's deposit UI.
The parent transaction fee remains separate. The complete payload is limited
to 128 bytes, and the deposit must exceed the committed fee.

For example, a 100,000-satoshi deposit committing 1,000 satoshis credits 99,000
and pays exactly 1,000 to the Elements block producer. Automatic import uses
that exact split. The manual equivalent is:

```sh
elements-cli -chain=elements -rpcwallet=<wallet> importdrivechaindeposit \
  "<mainchain-txid>" <mainchain-vout> "<mainchain-block-hash>" \
  "<elements-address>" 100000 0 1000
```

Parent replay authenticates the full payload, gross value and outpoint. The
claim must preserve the recipient, exact net credit and exact explicit native
fee, with no extra inputs or redirected outputs. Changing the RPC fee or
witness cannot change the L1 authorization. The replay key remains the same
outpoint regardless of fee encoding. `deposit_value_sats` reports gross value;
`value_sats` and `amount` report net credit.

Choose a fee sufficient for relay before funding: a positive fee below relay
policy may remain unrelayed, and the commitment cannot be unilaterally bumped
or reduced afterward. Do not create another L1 deposit to retry an uncertain
import. Inspect the original outpoint and its claim first. A successful
automatic import is logged with its parent outpoint, Elements txid and fee;
deferred imports appear under validation debug logging.

## Withdrawal

Withdrawals remain supported. They burn the pegged asset on Elements and
propose a deterministic blinded M6 for BIP300 miner voting. A burn is
irreversible; enforcer acceptance of a proposal does not guarantee payment.
The historical ECX burn-and-submit wallet path is disabled before wallet access
or burning, including its fee-subtraction mode. The native path below remains
two-stage: a burn is not a payment. If proposal submission fails after the burn
confirms, retry submission of that same claim; do not burn again. This does not
change upstream PAK withdrawals on their supported networks.

Before creating a burn, check parent synchronization, mTLS connectivity,
destination ownership/network, available balance, sidechain fees, and the
explicit parent fee. Parent address prefixes alone cannot distinguish forks.

```sh
elements-cli -chain=elements -rpcwallet=<wallet> sendtomainchain \
  "<parent-address>" <payout-amount> false true <mainchain-fee>
```

Amounts here are coin-denominated, not satoshis. The verbose result identifies
the transaction and `withdrawal_vout`. With the shown `false` setting,
`burn_amount = payout_amount + mainchain_fee`; the Elements transaction fee
is separate. Save the returned IDs and the block hash once confirmed.

Inspect the exact claim without broadcasting:

```sh
elements-cli -chain=elements getdrivechainwithdrawalbundle \
  "<txid>" <withdrawal-vout> "<confirming-elements-blockhash>" 6
```

Once the burn has six active Elements confirmations, submit that exact claim:

```sh
elements-cli -chain=elements submitdrivechainwithdrawal \
  "<txid>" <withdrawal-vout> "<confirming-elements-blockhash>" 6
```

Six is the RPC's default submission depth; keep it explicit for auditability.
The node checks the active burn block, exact output, deterministic M6, and
authenticated parent payment state. Miners/operators can independently call:

```sh
elements-cli -chain=elements verifydrivechainwithdrawalbundle \
  "<blinded-m6-hex>" "<confirming-elements-blockhash>" 6
```

After a timeout or restart, inspect the same claim before retrying the same
submission arguments. Do not create another burn to recover an uncertain
submission. `getdrivechainwithdrawalbundle` reports `m6id`,
`paid_on_parent_chain`, and, when paid, the parent payment block hash/height.
Submission rejects an already-paid claim. The historical
`drivechainrecoverwithdrawal` journal API is not this native RPC path.

## Completion checks

- Parent replay, enforcer, and Elements agree on the frozen network and slot.
- Deposit UTXOs, amounts and ownership remain correct after restart.
- Withdrawal M6 ID/bytes match before and after restart.
- The authentic parent payment spends the expected treasury and pays the exact
  destination/value. Inspect the parent transaction, not just a UI status.
- Reorgs or lost depth invalidate confirmation assumptions. Recheck both active
  chains before reporting finality.
- BIP300 authorization depends on parent miner voting. A proposal may expire
  or fail; neither a submitted flag nor a sidechain burn means funds arrived.
