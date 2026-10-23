// Copyright (c) 2026 The Elements developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <drivechain_parent_replay.h>

#include <consensus/amount.h>
#include <dbwrapper.h>
#include <hash.h>
#include <haskell/bridge.h>
#include <tinyformat.h>

#include <set>
#include <stdexcept>
#include <utility>

namespace {

using drivechain::DB_REPLAY_IDENTITY;
using drivechain::DB_REPLAY_TIP;
using drivechain::DB_REPLAY_DEPOSIT;
using drivechain::DB_REPLAY_BMM_EDGE;
using drivechain::DB_REPLAY_SUCCESSFUL_WITHDRAWAL;
using drivechain::DB_REPLAY_WITHDRAWAL_OCCURRENCE;

uint32_t StoreSchemaVersion(const DrivechainWithdrawalHistoryRule rule)
{
    static_assert(static_cast<uint32_t>(DrivechainWithdrawalHistoryRule::UNIQUE_M6ID) == 0);
    static_assert(static_cast<uint32_t>(DrivechainWithdrawalHistoryRule::ALLOW_REPROPOSAL) == 1);
    return drivechain::haskell::ParentReplaySchema(static_cast<uint32_t>(rule),
        DrivechainParentReplayStore::SCHEMA_VERSION, DrivechainParentReplayStore::REPROPOSAL_SCHEMA_VERSION);
}

struct DrivechainReplayStoreIdentity {
    uint32_t schema_version{0};
    uint256 identity;

    SERIALIZE_METHODS(DrivechainReplayStoreIdentity, obj)
    {
        READWRITE(obj.schema_version, obj.identity);
    }
};

bool SetStoreError(std::string* error, const std::string& message)
{
    if (error) *error = message;
    return false;
}

bool IsSaneTip(const DrivechainParentReplayTip& tip)
{
    using Kind = drivechain::haskell::ReplayRecordKind;
    const auto height_valid = [&](uint32_t height) {
        return drivechain::haskell::ParentReplayRecord(Kind::HEIGHT, 0, 0, height, tip.height);
    };
    const auto* active = &tip.state.active_proposal_hash;
    const auto* ctip = &tip.state.ctip;
    auto value = tip.state.ctip_value;
    const auto* proposals = &tip.state.pending_proposals;
    const auto* withdrawals = &tip.state.pending_withdrawals;
    auto proposal = proposals->begin();
    size_t withdrawal{0};
    auto slot = tip.state.other_slots.begin();
    auto action = tip.state.previous_m4_actions.begin();
    auto action_slot = tip.state.other_slots.end();
    bool configured{true}, configured_action_seen{false};
    std::set<uint256> m6ids;
    std::set<Sidechain::Bitcoin::COutPoint> ctips;
    return drivechain::haskell::ParentReplayTip([&](uint32_t step) {
        switch (step) {
        case 1: return !tip.hash.IsNull();
        case 2: return tip.state.required_proposal_activated;
        case 3: return !tip.state.active_proposal_hash.IsNull();
        case 4: return !tip.state.required_activation_block_hash.IsNull();
        case 5: return height_valid(tip.state.required_activation_height);
        case 6: return tip.state.required_activation_height == 0;
        case 7: return tip.state.required_activation_block_hash.IsNull();
        case 8: case 27: case 34: case 39: return ctip->has_value();
        case 9: case 35: return value == 0;
        case 10: case 24: case 32: return !active->IsNull();
        case 11: case 38: return drivechain::haskell::ParentReplayRecord(Kind::AMOUNT, 0, value, 0, MAX_MONEY);
        case 12: proposal = proposals->begin(); return true;
        case 13: return proposal != proposals->end();
        case 14: return !proposal->first.IsNull();
        case 15: return height_valid(proposal->second.proposal_height);
        case 16: return drivechain::haskell::ParentReplayRecord(Kind::PROPOSAL_VOTES, 0,
            proposal->second.votes, tip.height, proposal->second.proposal_height);
        case 17: ++proposal; return true;
        case 18: withdrawal = 0; m6ids.clear(); return true;
        case 19: return withdrawal < withdrawals->size();
        case 20: return height_valid((*withdrawals)[withdrawal].proposal_height);
        case 21: return drivechain::haskell::ParentReplayRecord(Kind::WITHDRAWAL_VOTES, 0,
            (*withdrawals)[withdrawal].votes, tip.height, (*withdrawals)[withdrawal].proposal_height);
        case 22: return m6ids.insert((*withdrawals)[withdrawal].m6id).second;
        case 23: ++withdrawal; return true;
        case 25: return withdrawals->empty();
        case 26: return configured;
        case 28: ctips.insert(**ctip); return true;
        case 29: slot = tip.state.other_slots.begin(); return true;
        case 30: return slot != tip.state.other_slots.end();
        case 31:
            configured = false;
            active = &slot->second.active_proposal_hash;
            ctip = &slot->second.ctip;
            value = slot->second.ctip_value;
            proposals = &slot->second.pending_proposals;
            withdrawals = &slot->second.pending_withdrawals;
            return true;
        case 33: return !ctip->has_value();
        case 36: ++slot; return true;
        case 40: action = tip.state.previous_m4_actions.begin(); return true;
        case 41: return ctips.insert(**ctip).second;
        case 42: return action != tip.state.previous_m4_actions.end();
        case 43: return action->second.type == DrivechainM4ActionType::UPVOTE;
        case 44: return action->second.type == DrivechainM4ActionType::ALARM;
        case 45: return action->second.m6id.IsNull();
        case 46:
            action_slot = tip.state.other_slots.find(action->first);
            return action_slot != tip.state.other_slots.end();
        case 47: return !action_slot->second.active_proposal_hash.IsNull();
        case 48: return configured_action_seen;
        case 49: return !tip.state.active_proposal_hash.IsNull();
        case 50: configured_action_seen = true; return true;
        case 51: ++action; return true;
        default: throw std::logic_error("invalid parent replay tip action");
        }
    });
}

bool IsSaneDeposit(const DrivechainMintableDeposit& deposit)
{
    const uint32_t facts = !deposit.outpoint.hash.IsNull() |
        ((deposit.outpoint.n != Sidechain::Bitcoin::COutPoint::NULL_INDEX) << 1) | ((!deposit.block_hash.IsNull()) << 2);
    return drivechain::haskell::ParentReplayRecord(drivechain::haskell::ReplayRecordKind::DEPOSIT,
        facts, deposit.value, deposit.address.size(), MAX_MONEY);
}

bool IsSaneEdge(const uint256& parent_hash,
                const DrivechainReplayedBmmEdge& edge)
{
    const uint32_t facts = !parent_hash.IsNull() | ((!edge.successor_hash.IsNull()) << 1) |
        (edge.has_canonical_commitment << 2) | ((!edge.committed_sidechain_hash.IsNull()) << 3);
    return drivechain::haskell::ParentReplayRecord(drivechain::haskell::ReplayRecordKind::EDGE,
        facts, 0, edge.parent_height, edge.successor_height);
}

bool IsSaneSuccessfulWithdrawal(
    const DrivechainSuccessfulWithdrawal& withdrawal)
{
    return drivechain::haskell::ParentReplayRecord(drivechain::haskell::ReplayRecordKind::WITHDRAWAL,
        !withdrawal.block_hash.IsNull());
}

auto SuccessfulWithdrawalKey(const uint8_t sidechain_slot,
                             const uint256& m6id)
{
    return std::make_pair(
        DB_REPLAY_SUCCESSFUL_WITHDRAWAL,
        std::make_pair(sidechain_slot, m6id));
}

auto WithdrawalOccurrenceKey(const uint8_t slot, const uint256& m6id, const uint32_t height)
{
    return std::make_pair(DB_REPLAY_WITHDRAWAL_OCCURRENCE,
        std::make_pair(std::make_pair(slot, m6id), height));
}

template <typename Key, typename Value>
DrivechainReplayStoreReadStatus ReadRecord(const CDBWrapper& db,
                                           const Key& key,
                                           Value& value,
                                           const char* description,
                                           std::string* error)
{
    static_assert(static_cast<uint32_t>(DrivechainReplayStoreReadStatus::FOUND) == 0 &&
        static_cast<uint32_t>(DrivechainReplayStoreReadStatus::NOT_FOUND) == 1 &&
        static_cast<uint32_t>(DrivechainReplayStoreReadStatus::CORRUPT) == 2);
    return static_cast<DrivechainReplayStoreReadStatus>(drivechain::haskell::ParentReplayStore(
        drivechain::haskell::ReplayStoreFlow::READ_RECORD, [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return db.Exists(key);
            case 2: return db.Read(key, value);
            case 3:
                if (error) *error = strprintf("persistent parent replay %s record is malformed", description);
                return 1;
            default: throw std::logic_error("invalid replay record read action");
            }
        }));
}

uint32_t ReadPreflight(const CDBWrapper* db, const uint32_t& schema,
                      drivechain::haskell::ReplayStoreFlow kind, const char* message, std::string* error)
{
    return drivechain::haskell::ParentReplayStore(kind, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return db != nullptr;
        case 2: return schema == DrivechainParentReplayStore::REPROPOSAL_SCHEMA_VERSION;
        case 3: return SetStoreError(error, message);
        default: throw std::logic_error("invalid replay read preflight action");
        }
    });
}

template <typename Key, typename Value, typename Check>
DrivechainReplayStoreReadStatus ReadCheckedRecord(
    const CDBWrapper& db, const Key& key, Value& value, const char* description,
    const char* inconsistent, drivechain::haskell::ReplayStoreFlow kind,
    Check check, std::string* error)
{
    return static_cast<DrivechainReplayStoreReadStatus>(drivechain::haskell::ParentReplayStore(
        kind, [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return static_cast<uint32_t>(ReadRecord(db, key, value, description, error));
            case 6: return SetStoreError(error, inconsistent);
            default: return check(step);
            }
        }));
}

} // namespace

DrivechainParentReplayStore::DrivechainParentReplayStore(
    fs::path path, const size_t cache_bytes, const bool wipe,
    const DrivechainWithdrawalHistoryRule history_rule)
    : m_path(std::move(path)),
      m_cache_bytes(cache_bytes),
      m_schema_version(StoreSchemaVersion(history_rule)),
      m_db(std::make_unique<CDBWrapper>(DBParams{
          .path = m_path, .cache_bytes = m_cache_bytes, .memory_only = drivechain::REPLAY_DB_MEMORY_ONLY,
          .wipe_data = wipe, .obfuscate = drivechain::REPLAY_DB_OBFUSCATE}))
{
}

DrivechainParentReplayStore::~DrivechainParentReplayStore() = default;

DrivechainReplayStoreLoadStatus DrivechainParentReplayStore::Load(
    const uint256& identity,
    DrivechainParentReplayTip& tip,
    std::string* error) const
{
    namespace hs = drivechain::haskell;
    static_assert(static_cast<uint32_t>(DrivechainReplayStoreLoadStatus::EMPTY) == 0 &&
        static_cast<uint32_t>(DrivechainReplayStoreLoadStatus::LOADED) == 1 &&
        static_cast<uint32_t>(DrivechainReplayStoreLoadStatus::CORRUPT) == 2 &&
        static_cast<uint32_t>(DrivechainReplayStoreLoadStatus::IDENTITY_MISMATCH) == 3);
    const auto preflight = hs::ParentReplayStore(hs::ReplayStoreFlow::LOAD_PREFLIGHT, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return error != nullptr;
        case 2: error->clear(); return 1;
        case 3: return m_db != nullptr;
        case 4: SetStoreError(error, "persistent parent replay database is not open"); return 1;
        default: throw std::logic_error("invalid replay load preflight action");
        }
    });
    if (preflight != 0) return static_cast<DrivechainReplayStoreLoadStatus>(preflight);
    try {
        DrivechainReplayStoreIdentity stored_identity;
        return static_cast<DrivechainReplayStoreLoadStatus>(hs::ParentReplayStore(
            hs::ReplayStoreFlow::LOAD, [&](uint32_t step) -> uint32_t {
                switch (step) {
                case 1: return static_cast<uint32_t>(ReadRecord(*m_db, DB_REPLAY_IDENTITY, stored_identity, "identity", error));
                case 2: return m_db->Exists(DB_REPLAY_TIP);
                case 3: return stored_identity.schema_version == m_schema_version;
                case 4: SetStoreError(error, "persistent parent replay has a tip but no identity"); return 1;
                case 5: return stored_identity.identity == identity;
                case 6: SetStoreError(error, "persistent parent replay schema or immutable network identity does not match"); return 1;
                case 7: return static_cast<uint32_t>(ReadRecord(*m_db, DB_REPLAY_TIP, tip, "tip", error));
                case 8: return IsSaneTip(tip);
                case 9: SetStoreError(error, "persistent parent replay tip is missing or internally inconsistent"); return 1;
                default: throw std::logic_error("invalid replay load action");
                }
            }));
    } catch (const std::exception& e) {
        SetStoreError(error, strprintf(
                                 "persistent parent replay load failed: %s", e.what()));
        return DrivechainReplayStoreLoadStatus::CORRUPT;
    }
}

bool DrivechainParentReplayStore::Reset(
    const uint256& identity,
    const DrivechainParentReplayTip& seed,
    std::string* error)
{
    // The replay store is a derived cache. Its authenticated seed is normally
    // parent genesis, but a pruned-light-client profile may instead seed the
    // exact immutable checkpoint whose complete replay state is committed by
    // the network identity. Validate the record itself here; the caller owns
    // authentication of the seed against that identity commitment.
    // Release LevelDB's directory lock before opening the same derived index
    // with fWipe. No reader can race this operation: callers hold the replay
    // mutex and the published epoch is zero.
    namespace hs = drivechain::haskell;
    if (!hs::ParentReplayStore(hs::ReplayStoreFlow::RESET_PREFLIGHT, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return IsSaneTip(seed);
        case 2: return SetStoreError(error, "refusing to seed persistent parent replay with an invalid tip");
        case 3: m_db.reset(); return 1;
        default: throw std::logic_error("invalid replay reset preflight action");
        }
    })) return false;
    try {
        std::optional<CDBBatch> batch;
        return hs::ParentReplayStore(hs::ReplayStoreFlow::RESET, [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1:
                m_db = std::make_unique<CDBWrapper>(DBParams{
                    .path = m_path, .cache_bytes = m_cache_bytes, .memory_only = drivechain::REPLAY_DB_MEMORY_ONLY,
                    .wipe_data = drivechain::REPLAY_RESET_WIPE, .obfuscate = drivechain::REPLAY_DB_OBFUSCATE});
                batch.emplace(*m_db);
                return 1;
            case 2: batch->Write(DB_REPLAY_IDENTITY, DrivechainReplayStoreIdentity{m_schema_version, identity}); return 1;
            case 3: batch->Write(DB_REPLAY_TIP, seed); return 1;
            case 4: return m_db->WriteBatch(*batch, drivechain::REPLAY_DB_SYNC);
            case 5: return SetStoreError(error, "failed to atomically seed persistent parent replay");
            default: throw std::logic_error("invalid replay reset action");
            }
        });
    } catch (const std::exception& e) {
        return SetStoreError(error, strprintf(
                                        "failed to rebuild persistent parent replay database: %s",
                                        e.what()));
    }
}

bool DrivechainParentReplayStore::Append(
    const DrivechainParentReplayTip& previous,
    const DrivechainParentReplayTip& next,
    const std::vector<DrivechainMintableDeposit>& deposits,
    const std::optional<std::pair<uint256, DrivechainReplayedBmmEdge>>& edge,
    const std::vector<DrivechainSuccessfulWithdrawal>& successful_withdrawals,
    const std::vector<DrivechainWithdrawalProposalIdentity>& withdrawal_proposals,
    std::string* error)
{
    namespace hs = drivechain::haskell;
    if (ReadPreflight(m_db.get(), m_schema_version, hs::ReplayStoreFlow::READ_PREFLIGHT,
        "persistent parent replay database is not open", error)) return false;
    try {
        DrivechainReplayStoreIdentity stored_identity;
        DrivechainParentReplayTip stored_tip;
        std::set<Sidechain::Bitcoin::COutPoint> block_outpoints;
        std::set<std::pair<uint8_t, uint256>> block_withdrawals, block_proposals;
        size_t d{0}, w{0}, p{0};
        std::optional<CDBBatch> batch;
        return hs::ParentReplayStore(hs::ReplayStoreFlow::APPEND, [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return IsSaneTip(previous);
            case 2: return IsSaneTip(next);
            case 3: return hs::ParentReplayRecord(hs::ReplayRecordKind::ADVANCEABLE_HEIGHT, 0, 0, previous.height);
            case 4: return hs::ParentReplayRecord(hs::ReplayRecordKind::SUCCESSOR_HEIGHT, 0, 0, previous.height, next.height);
            case 5: return SetStoreError(error, "refusing a non-contiguous persistent parent replay append");
            case 6: return static_cast<uint32_t>(ReadRecord(*m_db, DB_REPLAY_IDENTITY, stored_identity, "identity", error));
            case 7: return stored_identity.schema_version == m_schema_version;
            case 8: return SetStoreError(error, "persistent parent replay append uses the wrong schema");
            case 9: return static_cast<uint32_t>(ReadRecord(*m_db, DB_REPLAY_TIP, stored_tip, "tip", error));
            case 10: return stored_tip.height == previous.height;
            case 11: return stored_tip.hash == previous.hash;
            case 12: return (HashWriter{} << stored_tip.state).GetHash() == (HashWriter{} << previous.state).GetHash();
            case 13: return SetStoreError(error, "persistent parent replay tip changed before append");
            case 14: case 51: d = 0; return 1;
            case 15: case 52: return d < deposits.size();
            case 16: return IsSaneDeposit(deposits[d]);
            case 17: return deposits[d].block_height == next.height;
            case 18: return deposits[d].block_hash == next.hash;
            case 19: return block_outpoints.insert(deposits[d].outpoint).second;
            case 20: return m_db->Exists(std::make_pair(DB_REPLAY_DEPOSIT, deposits[d].outpoint));
            case 21: return SetStoreError(error, "persistent parent replay append contains a duplicate or malformed deposit");
            case 22: case 54: ++d; return 1;
            case 23: case 55: return edge.has_value();
            case 24: return IsSaneEdge(edge->first, edge->second);
            case 25: return edge->second.parent_height == previous.height;
            case 26: return edge->second.successor_height == next.height;
            case 27: return edge->second.successor_hash == next.hash;
            case 28: return edge->first == previous.hash;
            case 29: return m_db->Exists(std::make_pair(DB_REPLAY_BMM_EDGE, edge->first));
            case 30: return SetStoreError(error, "persistent parent replay append contains a duplicate or malformed BMM edge");
            case 31: case 57: w = 0; return 1;
            case 32: case 58: return w < successful_withdrawals.size();
            case 33: return IsSaneSuccessfulWithdrawal(successful_withdrawals[w]);
            case 34: return successful_withdrawals[w].block_height == next.height;
            case 35: return successful_withdrawals[w].block_hash == next.hash;
            case 36: return block_withdrawals.insert(std::make_pair(successful_withdrawals[w].sidechain_slot, successful_withdrawals[w].m6id)).second;
            case 37: case 46: return m_schema_version == SCHEMA_VERSION;
            case 38: case 59: return m_db->Exists(SuccessfulWithdrawalKey(successful_withdrawals[w].sidechain_slot, successful_withdrawals[w].m6id));
            case 39: return m_db->Exists(WithdrawalOccurrenceKey(successful_withdrawals[w].sidechain_slot, successful_withdrawals[w].m6id, successful_withdrawals[w].block_height));
            case 40: return SetStoreError(error, "persistent parent replay append contains a duplicate or malformed successful withdrawal");
            case 41: case 63: ++w; return 1;
            case 42: p = 0; return 1;
            case 43: return p < withdrawal_proposals.size();
            case 44: return block_proposals.insert(std::make_pair(withdrawal_proposals[p].sidechain_slot, withdrawal_proposals[p].m6id)).second;
            case 45: return SetStoreError(error, "persistent parent replay append contains a duplicate M3 proposal identity");
            case 47: return m_db->Exists(SuccessfulWithdrawalKey(withdrawal_proposals[p].sidechain_slot, withdrawal_proposals[p].m6id));
            case 48: return SetStoreError(error, "M3 re-proposes a withdrawal that already succeeded on the active parent chain");
            case 49: ++p; return 1;
            case 50: batch.emplace(*m_db); return 1;
            case 53: batch->Write(std::make_pair(DB_REPLAY_DEPOSIT, deposits[d].outpoint), deposits[d]); return 1;
            case 56: batch->Write(std::make_pair(DB_REPLAY_BMM_EDGE, edge->first), edge->second); return 1;
            case 60: batch->Write(SuccessfulWithdrawalKey(successful_withdrawals[w].sidechain_slot, successful_withdrawals[w].m6id), successful_withdrawals[w]); return 1;
            case 61: return m_schema_version == REPROPOSAL_SCHEMA_VERSION;
            case 62: batch->Write(WithdrawalOccurrenceKey(successful_withdrawals[w].sidechain_slot, successful_withdrawals[w].m6id, successful_withdrawals[w].block_height), successful_withdrawals[w]); return 1;
            case 64: batch->Write(DB_REPLAY_TIP, next); return 1;
            case 65: return m_db->WriteBatch(*batch, drivechain::REPLAY_DB_SYNC);
            case 66: return SetStoreError(error, "failed to atomically append persistent parent replay block");
            default: throw std::logic_error("invalid replay append action");
            }
        });
    } catch (const std::exception& e) {
        return SetStoreError(error, strprintf(
                                        "persistent parent replay append failed: %s", e.what()));
    }
}

DrivechainReplayStoreReadStatus DrivechainParentReplayStore::ReadDeposit(
    const Sidechain::Bitcoin::COutPoint& outpoint,
    DrivechainMintableDeposit& deposit,
    std::string* error) const
{
    namespace hs = drivechain::haskell;
    if (ReadPreflight(m_db.get(), m_schema_version, hs::ReplayStoreFlow::READ_PREFLIGHT,
        "persistent parent replay database is not open", error)) return DrivechainReplayStoreReadStatus::CORRUPT;
    try {
        return ReadCheckedRecord(
            *m_db, std::make_pair(DB_REPLAY_DEPOSIT, outpoint),
            deposit, "deposit", "persistent parent replay deposit record is internally inconsistent",
            hs::ReplayStoreFlow::DEPOSIT, [&](uint32_t step) {
                switch (step) {
                case 2: return IsSaneDeposit(deposit);
                case 3: return deposit.outpoint == outpoint;
                default: throw std::logic_error("invalid replay deposit read action");
                }
            }, error);
    } catch (const std::exception& e) {
        SetStoreError(error, strprintf(
                                 "persistent parent replay deposit read failed: %s", e.what()));
        return DrivechainReplayStoreReadStatus::CORRUPT;
    }
}

bool DrivechainParentReplayStore::ListDeposits(
    const std::optional<Sidechain::Bitcoin::COutPoint>& after, size_t limit,
    std::vector<DrivechainMintableDeposit>& deposits,
    std::optional<Sidechain::Bitcoin::COutPoint>& next, std::string* error) const
{
    deposits.clear();
    next.reset();
    if (limit == 0 || limit > 64)
        return SetStoreError(error, "invalid parent deposit scan limit or unopened index");
    if (ReadPreflight(m_db.get(), m_schema_version, drivechain::haskell::ReplayStoreFlow::READ_PREFLIGHT,
        "persistent parent replay database is not open", error)) return false;
    try {
        std::unique_ptr<CDBIterator> it(m_db->NewIterator());
        if (after) it->Seek(std::make_pair(DB_REPLAY_DEPOSIT, *after));
        else it->Seek(DB_REPLAY_DEPOSIT);
        std::vector<DrivechainMintableDeposit> page;
        std::optional<Sidechain::Bitcoin::COutPoint> cursor;
        while (it->Valid()) {
            uint8_t prefix{};
            if (!it->GetKey(prefix)) return SetStoreError(error, "malformed parent replay key");
            if (prefix != DB_REPLAY_DEPOSIT) break;
            std::pair<uint8_t, Sidechain::Bitcoin::COutPoint> key;
            if (!it->GetKey(key)) return SetStoreError(error, "malformed parent deposit key");
            if (after && key.second == *after) { it->Next(); continue; }
            if (page.size() == limit) { cursor = page.back().outpoint; break; }
            DrivechainMintableDeposit deposit;
            if (!it->GetValue(deposit) || !IsSaneDeposit(deposit) || deposit.outpoint != key.second)
                return SetStoreError(error, "malformed parent deposit scan record");
            page.push_back(std::move(deposit));
            it->Next();
        }
        it->CheckStatus();
        deposits = std::move(page);
        next = cursor;
        return true;
    } catch (const std::exception& e) {
        return SetStoreError(error, strprintf("parent deposit scan failed: %s", e.what()));
    }
}

DrivechainReplayStoreReadStatus DrivechainParentReplayStore::ReadBmmEdge(
    const uint256& parent_hash,
    DrivechainReplayedBmmEdge& edge,
    std::string* error) const
{
    namespace hs = drivechain::haskell;
    if (ReadPreflight(m_db.get(), m_schema_version, hs::ReplayStoreFlow::READ_PREFLIGHT,
        "persistent parent replay database is not open", error)) return DrivechainReplayStoreReadStatus::CORRUPT;
    try {
        return ReadCheckedRecord(
            *m_db, std::make_pair(DB_REPLAY_BMM_EDGE, parent_hash),
            edge, "BMM edge", "persistent parent replay BMM edge is internally inconsistent",
            hs::ReplayStoreFlow::EDGE, [&](uint32_t step) {
                if (step != 2) throw std::logic_error("invalid replay edge read action");
                return IsSaneEdge(parent_hash, edge);
            }, error);
    } catch (const std::exception& e) {
        SetStoreError(error, strprintf(
                                 "persistent parent replay BMM-edge read failed: %s", e.what()));
        return DrivechainReplayStoreReadStatus::CORRUPT;
    }
}

DrivechainReplayStoreReadStatus
DrivechainParentReplayStore::ReadSuccessfulWithdrawal(
    const uint8_t sidechain_slot,
    const uint256& m6id,
    DrivechainSuccessfulWithdrawal& withdrawal,
    std::string* error) const
{
    namespace hs = drivechain::haskell;
    if (ReadPreflight(m_db.get(), m_schema_version, hs::ReplayStoreFlow::READ_PREFLIGHT,
        "persistent parent replay database is not open", error)) return DrivechainReplayStoreReadStatus::CORRUPT;
    try {
        return ReadCheckedRecord(
            *m_db, SuccessfulWithdrawalKey(sidechain_slot, m6id),
            withdrawal, "successful withdrawal",
            "persistent parent replay successful-withdrawal record is internally inconsistent",
            hs::ReplayStoreFlow::WITHDRAWAL, [&](uint32_t step) {
                switch (step) {
                case 2: return IsSaneSuccessfulWithdrawal(withdrawal);
                case 3: return withdrawal.sidechain_slot == sidechain_slot;
                case 4: return withdrawal.m6id == m6id;
                default: throw std::logic_error("invalid replay withdrawal read action");
                }
            }, error);
    } catch (const std::exception& e) {
        SetStoreError(error, strprintf(
                                 "persistent parent replay successful-withdrawal read failed: %s",
                                 e.what()));
        return DrivechainReplayStoreReadStatus::CORRUPT;
    }
}

DrivechainReplayStoreReadStatus
DrivechainParentReplayStore::ReadSuccessfulWithdrawalAtHeight(
    const uint8_t sidechain_slot, const uint256& m6id, const uint32_t height,
    DrivechainSuccessfulWithdrawal& withdrawal, std::string* error) const
{
    namespace hs = drivechain::haskell;
    if (ReadPreflight(m_db.get(), m_schema_version, hs::ReplayStoreFlow::OCCURRENCE_PREFLIGHT,
        "withdrawal occurrence lookup requires the re-proposal replay schema", error)) return DrivechainReplayStoreReadStatus::CORRUPT;
    try {
        return ReadCheckedRecord(*m_db,
            WithdrawalOccurrenceKey(sidechain_slot, m6id, height), withdrawal,
            "withdrawal occurrence", "persistent parent replay withdrawal occurrence is internally inconsistent",
            hs::ReplayStoreFlow::OCCURRENCE, [&](uint32_t step) {
                switch (step) {
                case 2: return IsSaneSuccessfulWithdrawal(withdrawal);
                case 3: return withdrawal.sidechain_slot == sidechain_slot;
                case 4: return withdrawal.m6id == m6id;
                case 5: return withdrawal.block_height == height;
                default: throw std::logic_error("invalid replay occurrence read action");
                }
            }, error);
    } catch (const std::exception& e) {
        SetStoreError(error, strprintf("withdrawal occurrence read failed: %s", e.what()));
        return DrivechainReplayStoreReadStatus::CORRUPT;
    }
}
