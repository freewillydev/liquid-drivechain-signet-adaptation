// Copyright (c) 2026 The Elements developers
// Distributed under the MIT software license, see the accompanying file COPYING.
#include <node/drivechain_deposits.h>

#include <common/args.h>
#include <logging.h>
#include <mainchainrpc.h>
#include <node/context.h>
#include <node/transaction.h>
#include <node/types.h>
#include <pegins.h>
#include <txmempool.h>
#include <validation.h>

namespace node {
void AutoImportDrivechainDeposits(NodeContext& node,
    std::optional<Sidechain::Bitcoin::COutPoint>& cursor)
{
    if (!node.args->GetBoolArg("-drivechainautodeposit", true) ||
        !Params().GetConsensus().drivechain_slot || !node.mempool || !node.chainman) return;
    DrivechainParentValidationBudget budget(true);
    try {
        const int height = WITH_LOCK(cs_main, return node.chainman->ActiveChain().Height() + 1);
        std::vector<DrivechainMintableDeposit> deposits;
        std::optional<Sidechain::Bitcoin::COutPoint> next;
        std::string error;
        if (!ListDrivechainDepositCandidates(cursor, height, deposits, next, &error)) {
            LogDebug(BCLog::VALIDATION, "Automatic deposit scan waiting: %s\n", error);
            return;
        }
        unsigned attempts{0};
        for (const auto& deposit : deposits) {
            CScript recipient;
            CAmount committed_fee{0};
            if (!DecodeDrivechainDepositDestination(std::string(deposit.address.begin(), deposit.address.end()),
                recipient, committed_fee) || deposit.value <= committed_fee) continue;
            const auto tx = CreateNativeDrivechainDeposit(deposit);
            {
                LOCK2(cs_main, node.mempool->cs);
                CCoinsViewMemPool view(&node.chainman->ActiveChainstate().CoinsTip(), *node.mempool);
                if (view.IsPeginSpent(GetPeginSpentKey(tx->witness.vtxinwit[0].m_pegin_witness, tx->vin[0].prevout))) continue;
            }
            // Never skip the normal parent proof/depth, replay and mempool checks.
            // No wallet, key, fee input or external enforcer assertion is used.
            const auto result = BroadcastTransaction(node, tx, error, /*max_tx_fee=*/0,
                /*relay=*/true, /*wait_callback=*/false);
            if (result == TransactionError::OK)
                LogPrintf("Automatically imported drivechain deposit %s:%u as %s (committed fee %d)\n",
                    deposit.outpoint.hash.ToString(), deposit.outpoint.n, tx->GetHash().ToString(), committed_fee);
            else
                LogDebug(BCLog::VALIDATION, "Automatic deposit %s:%u deferred: %s\n",
                    deposit.outpoint.hash.ToString(), deposit.outpoint.n, error);
            if (++attempts == 8) { cursor = deposit.outpoint; return; }
        }
        cursor = next;
    } catch (const std::exception& error) {
        // Retain the cursor on faults, so unavailable/reorged evidence is retried.
        LogDebug(BCLog::VALIDATION, "Automatic deposit scan deferred: %s\n", error.what());
    }
}
}
