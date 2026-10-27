// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/utxo_snapshot.h>

#include <haskell/bridge.h>
#include <logging.h>
#include <streams.h>
#include <sync.h>
#include <tinyformat.h>
#include <txdb.h>
#include <uint256.h>
#include <util/fs.h>
#include <validation.h>

#include <cassert>
#include <cstdio>
#include <optional>
#include <string>

namespace node {

ChildCheckpointSources PrepareChildCheckpointSources(ChainstateManager& chainman)
{
    AssertLockHeld(::cs_main);
    Chainstate& chainstate = chainman.ActiveChainstate();
    const CBlockIndex* tip = chainstate.m_chain.Tip();
    uint256 expected;
    decltype(chainstate.CoinsDB().SpentPeginCursor()) claims;
    decltype(chainstate.CoinsDB().CheckpointCoinCursor()) coins;
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::CHILD_CHECKPOINT,
        [&](uint32_t step) EXCLUSIVE_LOCKS_REQUIRED(cs_main) -> uint32_t {
            switch (step) {
            case 1: return tip != nullptr;
            case 2: return tip->IsValid(BLOCK_VALID_SCRIPTS);
            case 3: return chainman.IsSnapshotActive();
            case 4: return chainman.IsSnapshotValidated();
            case 7: expected = tip->GetBlockHash(); return 1;
            case 8: return chainstate.CoinsTip().GetBestBlock() == expected;
            case 9: chainstate.ForceFlushStateToDisk(); return 1;
            case 10:
                claims = chainstate.CoinsDB().SpentPeginCursor();
                coins = chainstate.CoinsDB().CheckpointCoinCursor();
                return 1;
            case 11: return chainstate.CoinsDB().GetBestBlock() == expected;
            case 12: return claims->GetBestBlock() == expected;
            case 13: return coins != nullptr;
            case 14: return coins->GetBestBlock() == expected;
            case 15: return chainstate.CoinsDB().GetHeadBlocks().empty();
            case 16: throw std::runtime_error("Child checkpoint requires a validated active chain");
            case 18: throw std::runtime_error("Child checkpoint cache/active tip mismatch");
            case 19: throw std::runtime_error("Child checkpoint database/active tip mismatch");
            default: throw std::logic_error("Unknown child checkpoint action");
            }
        });
    return {chainstate.m_chain.Genesis()->GetBlockHash(), expected, tip->nHeight,
        std::move(coins), std::move(claims)};
}

bool WriteSnapshotBaseBlockhash(Chainstate& snapshot_chainstate)
{
    AssertLockHeld(::cs_main);
    assert(snapshot_chainstate.m_from_snapshot_blockhash);

    const std::optional<fs::path> chaindir = snapshot_chainstate.CoinsDB().StoragePath();
    assert(chaindir); // Sanity check that chainstate isn't in-memory.
    const fs::path write_to = *chaindir / node::SNAPSHOT_BLOCKHASH_FILENAME;

    FILE* file{fsbridge::fopen(write_to, "wb")};
    AutoFile afile{file};
    if (afile.IsNull()) {
        LogPrintf("[snapshot] failed to open base blockhash file for writing: %s\n",
                  fs::PathToString(write_to));
        return false;
    }
    afile << *snapshot_chainstate.m_from_snapshot_blockhash;

    if (afile.fclose() != 0) {
        LogPrintf("[snapshot] failed to close base blockhash file %s after writing\n",
                  fs::PathToString(write_to));
        return false;
    }
    return true;
}

std::optional<uint256> ReadSnapshotBaseBlockhash(fs::path chaindir)
{
    if (!fs::exists(chaindir)) {
        LogPrintf("[snapshot] cannot read base blockhash: no chainstate dir "
            "exists at path %s\n", fs::PathToString(chaindir));
        return std::nullopt;
    }
    const fs::path read_from = chaindir / node::SNAPSHOT_BLOCKHASH_FILENAME;
    const std::string read_from_str = fs::PathToString(read_from);

    if (!fs::exists(read_from)) {
        LogPrintf("[snapshot] snapshot chainstate dir is malformed! no base blockhash file "
            "exists at path %s. Try deleting %s and calling loadtxoutset again?\n",
            fs::PathToString(chaindir), read_from_str);
        return std::nullopt;
    }

    uint256 base_blockhash;
    FILE* file{fsbridge::fopen(read_from, "rb")};
    AutoFile afile{file};
    if (afile.IsNull()) {
        LogPrintf("[snapshot] failed to open base blockhash file for reading: %s\n",
            read_from_str);
        return std::nullopt;
    }
    afile >> base_blockhash;

    int64_t position = afile.tell();
    afile.seek(0, SEEK_END);
    if (position != afile.tell()) {
        LogPrintf("[snapshot] warning: unexpected trailing data in %s\n", read_from_str);
    }
    return base_blockhash;
}

std::optional<fs::path> FindSnapshotChainstateDir(const fs::path& data_dir)
{
    fs::path possible_dir =
        data_dir / fs::u8path(strprintf("chainstate%s", SNAPSHOT_CHAINSTATE_SUFFIX));

    if (fs::exists(possible_dir)) {
        return possible_dir;
    }
    return std::nullopt;
}

} // namespace node
