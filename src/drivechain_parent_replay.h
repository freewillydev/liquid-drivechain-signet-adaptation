// Copyright (c) 2026 The Elements developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DRIVECHAIN_PARENT_REPLAY_H
#define BITCOIN_DRIVECHAIN_PARENT_REPLAY_H

#include <util/fs.h>
#include <haskell/bmm_constants.h>
#include <mainchainrpc.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

class CDBWrapper;

/** Persistent tip of the authenticated parent replay. */
struct DrivechainParentReplayTip {
    uint32_t height{0};
    uint256 hash;
    DrivechainParentReplayState state;

    SERIALIZE_METHODS(DrivechainParentReplayTip, obj)
    {
        READWRITE(obj.height, obj.hash, obj.state);
    }
};

enum class DrivechainReplayStoreLoadStatus {
    EMPTY = drivechain::REPLAY_LOAD_EMPTY,
    LOADED = drivechain::REPLAY_LOAD_LOADED,
    CORRUPT = drivechain::REPLAY_LOAD_CORRUPT,
    IDENTITY_MISMATCH = drivechain::REPLAY_LOAD_IDENTITY_MISMATCH,
};

enum class DrivechainReplayStoreReadStatus {
    FOUND = drivechain::REPLAY_READ_FOUND,
    NOT_FOUND = drivechain::REPLAY_READ_NOT_FOUND,
    CORRUPT = drivechain::REPLAY_READ_CORRUPT,
};

/**
 * Bounded-memory LevelDB index derived exclusively from authenticated parent
 * blocks. It is a cache, never a consensus trust root: identity mismatch,
 * malformed records, and active-parent reorgs require a full derived rebuild.
 */
class DrivechainParentReplayStore final
{
public:
    static constexpr uint32_t SCHEMA_VERSION{drivechain::REPLAY_UNIQUE_SCHEMA};
    static constexpr uint32_t REPROPOSAL_SCHEMA_VERSION{drivechain::REPLAY_REPROPOSAL_SCHEMA};

    DrivechainParentReplayStore(fs::path path, size_t cache_bytes, bool wipe,
        DrivechainWithdrawalHistoryRule history_rule = static_cast<DrivechainWithdrawalHistoryRule>(drivechain::REPLAY_DEFAULT_HISTORY_RULE));
    ~DrivechainParentReplayStore();

    DrivechainParentReplayStore(const DrivechainParentReplayStore&) = delete;
    DrivechainParentReplayStore& operator=(const DrivechainParentReplayStore&) = delete;

    DrivechainReplayStoreLoadStatus Load(const uint256& identity,
                                         DrivechainParentReplayTip& tip,
                                         std::string* error) const;

    /** Atomically wipe and seed the derived store with an authenticated tip. */
    bool Reset(const uint256& identity,
               const DrivechainParentReplayTip& seed,
               std::string* error);

    /** Atomically and synchronously append one authenticated active block. */
    bool Append(const DrivechainParentReplayTip& previous,
                const DrivechainParentReplayTip& next,
                const std::vector<DrivechainMintableDeposit>& deposits,
                const std::optional<std::pair<uint256, DrivechainReplayedBmmEdge>>& edge,
                const std::vector<DrivechainSuccessfulWithdrawal>& successful_withdrawals,
                const std::vector<DrivechainWithdrawalProposalIdentity>& withdrawal_proposals,
                std::string* error);

    bool Append(const DrivechainParentReplayTip& previous,
                const DrivechainParentReplayTip& next,
                const std::vector<DrivechainMintableDeposit>& deposits,
                const std::optional<std::pair<uint256, DrivechainReplayedBmmEdge>>& edge,
                const std::vector<DrivechainSuccessfulWithdrawal>& successful_withdrawals,
                std::string* error)
    {
        return Append(previous, next, deposits, edge,
                      successful_withdrawals, {}, error);
    }

    /** Compatibility overload for blocks containing no successful M6. */
    bool Append(const DrivechainParentReplayTip& previous,
                const DrivechainParentReplayTip& next,
                const std::vector<DrivechainMintableDeposit>& deposits,
                const std::optional<std::pair<uint256, DrivechainReplayedBmmEdge>>& edge,
                std::string* error)
    {
        return Append(previous, next, deposits, edge, {}, {}, error);
    }

    DrivechainReplayStoreReadStatus ReadDeposit(
        const Sidechain::Bitcoin::COutPoint& outpoint,
        DrivechainMintableDeposit& deposit,
        std::string* error) const;

    /** Bounded discovery only; callers must still authenticate depth and active-chain membership. */
    bool ListDeposits(const std::optional<Sidechain::Bitcoin::COutPoint>& after,
        size_t limit, std::vector<DrivechainMintableDeposit>& deposits,
        std::optional<Sidechain::Bitcoin::COutPoint>& next, std::string* error) const;

    DrivechainReplayStoreReadStatus ReadBmmEdge(
        const uint256& parent_hash,
        DrivechainReplayedBmmEdge& edge,
        std::string* error) const;

    /** Return the first payment; later re-proposals never replace this record. */
    DrivechainReplayStoreReadStatus ReadSuccessfulWithdrawal(
        uint8_t sidechain_slot,
        const uint256& m6id,
        DrivechainSuccessfulWithdrawal& withdrawal,
        std::string* error) const;

    DrivechainReplayStoreReadStatus ReadSuccessfulWithdrawalAtHeight(
        uint8_t sidechain_slot,
        const uint256& m6id,
        uint32_t height,
        DrivechainSuccessfulWithdrawal& withdrawal,
        std::string* error) const;

private:
    fs::path m_path;
    size_t m_cache_bytes;
    uint32_t m_schema_version;
    std::unique_ptr<CDBWrapper> m_db;
};

#endif // BITCOIN_DRIVECHAIN_PARENT_REPLAY_H
