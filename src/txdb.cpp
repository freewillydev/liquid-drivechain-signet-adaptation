// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txdb.h>

#include <chain.h>
#include <coins.h>
#include <consensus/merkle.h>
#include <dbwrapper.h>
#include <haskell/bridge.h>
#include <issuance.h>
#include <logging.h>
#include <primitives/transaction.h>
#include <random.h>
#include <serialize.h>
#include <uint256.h>
#include <util/vector.h>

#include <cassert>
#include <cstdlib>
#include <iterator>
#include <utility>

// ELEMENTS
#include <block_proof.h> // CheckProof
#include <chainparams.h> // Params()

static constexpr uint8_t DB_COIN{'C'};
static constexpr uint8_t DB_BEST_BLOCK{'B'};
static constexpr uint8_t DB_HEAD_BLOCKS{'H'};
// Keys used in previous version that might still be found in the DB:
static constexpr uint8_t DB_COINS{'c'};
// ELEMENTS
static constexpr uint8_t DB_PEGIN_FLAG{'w'};

bool CCoinsViewDB::NeedsUpgrade()
{
    std::unique_ptr<CDBIterator> cursor{m_db->NewIterator()};
    // DB_COINS was deprecated in v0.15.0, commit
    // 1088b02f0ccd7358d2b7076bb9e122d59d502d02
    cursor->Seek(std::make_pair(DB_COINS, uint256{}));
    std::pair<unsigned char, uint256> key;
    return cursor->Valid() && cursor->GetKey(key) && key.first == DB_COINS;
}

namespace {

struct CoinEntry {
    COutPoint* outpoint;
    uint8_t key;
    explicit CoinEntry(const COutPoint* ptr) : outpoint(const_cast<COutPoint*>(ptr)), key(DB_COIN)  {}

    SERIALIZE_METHODS(CoinEntry, obj) { READWRITE(obj.key, obj.outpoint->hash, VARINT(obj.outpoint->n)); }
};

} // namespace

CCoinsViewDB::CCoinsViewDB(DBParams db_params, CoinsViewOptions options) :
    m_db_params{std::move(db_params)},
    m_options{std::move(options)},
    m_db{std::make_unique<CDBWrapper>(m_db_params)} { }

void CCoinsViewDB::ResizeCache(size_t new_cache_size)
{
    // We can't do this operation with an in-memory DB since we'll lose all the coins upon
    // reset.
    if (!m_db_params.memory_only) {
        // Have to do a reset first to get the original `m_db` state to release its
        // filesystem lock.
        m_db.reset();
        m_db_params.cache_bytes = new_cache_size;
        m_db_params.wipe_data = false;
        m_db = std::make_unique<CDBWrapper>(m_db_params);
    }
}

std::optional<Coin> CCoinsViewDB::GetCoin(const COutPoint& outpoint) const
{
    if (Coin coin; m_db->Read(CoinEntry(&outpoint), coin)) return coin;
    return std::nullopt;
}

bool CCoinsViewDB::HaveCoin(const COutPoint &outpoint) const {
    return m_db->Exists(CoinEntry(&outpoint));
}

// ELEMENTS:
bool CCoinsViewDB::IsPeginSpent(const std::pair<uint256, COutPoint> &outpoint) const {
    return m_db->Exists(std::make_pair(DB_PEGIN_FLAG, outpoint));
}

uint256 CCoinsViewDB::GetBestBlock() const {
    uint256 hashBestChain;
    if (!m_db->Read(DB_BEST_BLOCK, hashBestChain))
        return uint256();
    return hashBestChain;
}

std::vector<uint256> CCoinsViewDB::GetHeadBlocks() const {
    std::vector<uint256> vhashHeadBlocks;
    if (!m_db->Read(DB_HEAD_BLOCKS, vhashHeadBlocks)) {
        return std::vector<uint256>();
    }
    return vhashHeadBlocks;
}

bool CCoinsViewDB::BatchWrite(CoinsViewCacheCursor& cursor, const uint256 &hashBlock) {
    CDBBatch batch(*m_db);
    size_t count = 0;
    size_t changed = 0;
    assert(!hashBlock.IsNull());

    uint256 old_tip = GetBestBlock();
    if (old_tip.IsNull()) {
        // We may be in the middle of replaying.
        std::vector<uint256> old_heads = GetHeadBlocks();
        if (old_heads.size() == 2) {
            if (old_heads[0] != hashBlock) {
                LogPrintLevel(BCLog::COINDB, BCLog::Level::Error, "The coins database detected an inconsistent state, likely due to a previous crash or shutdown. You will need to restart bitcoind with the -reindex-chainstate or -reindex configuration option.\n");
            }
            assert(old_heads[0] == hashBlock);
            old_tip = old_heads[1];
        }
    }

    // In the first batch, mark the database as being in the middle of a
    // transition from old_tip to hashBlock.
    // A vector is used for future extensibility, as we may want to support
    // interrupting after partial writes from multiple independent reorgs.
    batch.Erase(DB_BEST_BLOCK);
    batch.Write(DB_HEAD_BLOCKS, Vector(hashBlock, old_tip));

    for (auto it{cursor.Begin()}; it != cursor.End();) {
        if (it->second.IsDirty()) {
            // ELEMENTS:
            if (it->second.IsPegin()) {
                if (!it->second.peginSpent) {
                    batch.Erase(std::make_pair(DB_PEGIN_FLAG, it->first));
                } else {
                    // Once spent, we don't care about the entry data, so we store
                    // a static byte to indicate spentness.
                    batch.Write(std::make_pair(DB_PEGIN_FLAG, it->first), 1);
                }
            } else {
                // Non-pegin entries are stored the same way as in Core.
                CoinEntry entry(&it->first.second);
                if (it->second.coin.IsSpent()) {
                    batch.Erase(entry);
                } else {
                    batch.Write(entry, it->second.coin);
                }
            }
            changed++;
        }
        count++;
        it = cursor.NextAndMaybeErase(*it);
        if (batch.SizeEstimate() > m_options.batch_write_bytes) {
            LogDebug(BCLog::COINDB, "Writing partial batch of %.2f MiB\n", batch.SizeEstimate() * (1.0 / 1048576.0));
            m_db->WriteBatch(batch);
            batch.Clear();
            if (m_options.simulate_crash_ratio) {
                static FastRandomContext rng;
                if (rng.randrange(m_options.simulate_crash_ratio) == 0) {
                    LogPrintf("Simulating a crash. Goodbye.\n");
                    _Exit(0);
                }
            }
        }
    }

    // In the last batch, mark the database as consistent with hashBlock again.
    batch.Erase(DB_HEAD_BLOCKS);
    batch.Write(DB_BEST_BLOCK, hashBlock);

    LogDebug(BCLog::COINDB, "Writing final batch of %.2f MiB\n", batch.SizeEstimate() * (1.0 / 1048576.0));
    bool ret = m_db->WriteBatch(batch);
    LogDebug(BCLog::COINDB, "Committed %u changed transaction outputs (out of %u) to coin database...\n", (unsigned int)changed, (unsigned int)count);
    return ret;
}

size_t CCoinsViewDB::EstimateSize() const
{
    return m_db->EstimateSize(DB_COIN, uint8_t(DB_COIN + 1));
}

namespace {
// The generic DB decoder allows trailing data; checkpoint records must not.
template <typename T> struct ExactDBRecord {
    T value{};
    template <typename Stream> void Unserialize(Stream& stream)
    {
        stream >> value;
        if (!stream.empty()) throw std::ios_base::failure("Trailing checkpoint DB bytes");
    }
};
struct ExactCoinKey {
    COutPoint outpoint;
    template <typename Stream> void Unserialize(Stream& stream)
    {
        CoinEntry entry{&outpoint};
        stream >> entry;
        if (entry.key != DB_COIN || !stream.empty())
            throw std::ios_base::failure("Malformed checkpoint coin key");
    }
};

bool ReadCheckpointKey(CDBIterator& cursor, uint8_t expected,
    drivechain::haskell::ReplayStoreFlow flow, const std::function<bool(uint32_t)>& decode,
    const char* prefix_error, const char* record_error)
{
    cursor.CheckStatus();
    uint8_t prefix{};
    const auto result = drivechain::haskell::ParentReplayStore(flow, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return cursor.Valid();
        case 2: return cursor.GetKey(prefix);
        case 3: return prefix == expected;
        default: return decode(step);
        }
    });
    if (result == 2) throw dbwrapper_error(prefix_error);
    if (result == 3) throw dbwrapper_error(record_error);
    return result == 1;
}
}

CSpentPeginCursor::CSpentPeginCursor(std::unique_ptr<CDBIterator> cursor)
    : m_cursor(std::move(cursor))
{
    // Read metadata using the same LevelDB iterator snapshot as the claims.
    uint8_t prefix{};
    ExactDBRecord<uint8_t> key;
    ExactDBRecord<uint256> value;
    const auto admission = drivechain::haskell::ParentReplayStore(
        drivechain::haskell::ReplayStoreFlow::CHECKPOINT_METADATA, [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: case 4:
                m_cursor->Seek(step == 1 ? DB_HEAD_BLOCKS : DB_BEST_BLOCK);
                m_cursor->CheckStatus();
                return m_cursor->Valid();
            case 2: return m_cursor->GetKey(prefix);
            case 3: return prefix != DB_HEAD_BLOCKS;
            case 5: return m_cursor->GetKey(key);
            case 6: return key.value == DB_BEST_BLOCK;
            case 7: return m_cursor->GetValue(value);
            case 8: return !value.value.IsNull();
            default: throw std::logic_error("Invalid checkpoint metadata step");
            }
        });
    if (admission == 1)
        throw dbwrapper_error("Cannot snapshot an incomplete chainstate transition");
    if (admission != 0)
        throw dbwrapper_error("Missing or malformed checkpoint best block");
    m_best_block = value.value;
    m_cursor->Seek(DB_PEGIN_FLAG);
    ReadKey();
}

void CSpentPeginCursor::ReadKey()
{
    m_key.reset();
    ExactDBRecord<std::pair<uint8_t, std::pair<uint256, COutPoint>>> key;
    ExactDBRecord<int> value;
    if (ReadCheckpointKey(*m_cursor, DB_PEGIN_FLAG, drivechain::haskell::ReplayStoreFlow::CHECKPOINT_CLAIM,
        [&](uint32_t step) {
            switch (step) {
            case 4: return m_cursor->GetKey(key);
            case 5: return m_cursor->GetValue(value);
            case 6: return value.value == 1;
            default: throw std::logic_error("Invalid checkpoint claim step");
            }
        }, "Malformed spent-claim prefix", "Malformed spent-claim record")) m_key = key.value.second;
}

void CSpentPeginCursor::Next()
{
    if (!Valid()) return;
    m_cursor->Next();
    ReadKey();
}

std::unique_ptr<CSpentPeginCursor> CCoinsViewDB::SpentPeginCursor() const
{
    return std::make_unique<CSpentPeginCursor>(std::unique_ptr<CDBIterator>{m_db->NewIterator()});
}

/** Specialization of CCoinsViewCursor to iterate over a CCoinsViewDB */
class CCoinsViewDBCursor: public CCoinsViewCursor
{
public:
    // Prefer using CCoinsViewDB::Cursor() since we want to perform some
    // cache warmup on instantiation.
    CCoinsViewDBCursor(CDBIterator* pcursorIn, const uint256&hashBlockIn, bool strict = false):
        CCoinsViewCursor(hashBlockIn), pcursor(pcursorIn), m_strict(strict) {}
    ~CCoinsViewDBCursor() = default;

    bool GetKey(COutPoint &key) const override;
    bool GetValue(Coin &coin) const override;

    bool Valid() const override;
    void Next() override;

private:
    std::unique_ptr<CDBIterator> pcursor;
    std::pair<char, COutPoint> keyTmp;
    bool m_strict;
    void ReadStrictKey();

    friend class CCoinsViewDB;
};

void CCoinsViewDBCursor::ReadStrictKey()
{
    keyTmp.first = 0;
    ExactCoinKey key;
    if (ReadCheckpointKey(*pcursor, DB_COIN, drivechain::haskell::ReplayStoreFlow::CHECKPOINT_COIN_KEY,
        [&](uint32_t step) {
            if (step != 4) throw std::logic_error("Invalid checkpoint coin key step");
            return pcursor->GetKey(key);
        }, "Malformed checkpoint coin prefix", "Malformed checkpoint coin key")) keyTmp = {DB_COIN, key.outpoint};
}

std::unique_ptr<CCoinsViewCursor> CCoinsViewDB::CheckpointCoinCursor() const
{
    auto cursor = std::make_unique<CCoinsViewDBCursor>(m_db->NewIterator(), GetBestBlock(), true);
    cursor->pcursor->Seek(DB_COIN);
    cursor->ReadStrictKey();
    return cursor;
}

std::unique_ptr<CCoinsViewCursor> CCoinsViewDB::Cursor() const
{
    auto i = std::make_unique<CCoinsViewDBCursor>(
        const_cast<CDBWrapper&>(*m_db).NewIterator(), GetBestBlock());
    /* It seems that there are no "const iterators" for LevelDB.  Since we
       only need read operations on it, use a const-cast to get around
       that restriction.  */
    i->pcursor->Seek(DB_COIN);
    // Cache key of first record
    if (i->pcursor->Valid()) {
        CoinEntry entry(&i->keyTmp.second);
        i->pcursor->GetKey(entry);
        i->keyTmp.first = entry.key;
    } else {
        i->keyTmp.first = 0; // Make sure Valid() and GetKey() return false
    }
    return i;
}

bool CCoinsViewDBCursor::GetKey(COutPoint &key) const
{
    // Return cached key
    if (keyTmp.first == DB_COIN) {
        key = keyTmp.second;
        return true;
    }
    return false;
}

bool CCoinsViewDBCursor::GetValue(Coin &coin) const
{
    if (m_strict) {
        ExactDBRecord<Coin> record;
        const auto result = drivechain::haskell::ParentReplayStore(
            drivechain::haskell::ReplayStoreFlow::CHECKPOINT_COIN_VALUE, [&](uint32_t step) -> uint32_t {
                switch (step) {
                case 1: return Valid();
                case 2: pcursor->CheckStatus(); return 1;
                case 3: return pcursor->GetValue(record);
                case 4: return !record.value.IsSpent();
                default: throw std::logic_error("Invalid checkpoint coin value step");
                }
            });
        if (result == 0) return false;
        if (result != 1) throw dbwrapper_error("Malformed checkpoint coin value");
        coin = std::move(record.value);
        return true;
    }
    return pcursor->GetValue(coin);
}

bool CCoinsViewDBCursor::Valid() const
{
    return keyTmp.first == DB_COIN;
}

void CCoinsViewDBCursor::Next()
{
    if (m_strict) {
        if (!Valid()) return;
        pcursor->Next();
        ReadStrictKey();
        return;
    }
    pcursor->Next();
    CoinEntry entry(&keyTmp.second);
    if (!pcursor->Valid() || !pcursor->GetKey(entry)) {
        keyTmp.first = 0; // Invalidate cached key after last record so that Valid() and GetKey() return false
    } else {
        keyTmp.first = entry.key;
    }
}

// Fork-specific drivechain_parent_replay adapters.
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

template <typename... Values>
std::vector<unsigned char> ReplayRecordBytes(const Values&... values)
{
    DataStream stream;
    (stream << ... << values);
    return {UCharCast(stream.data()), UCharCast(stream.data()) + stream.size()};
}

template <typename Recover>
DrivechainReplayEffects ReplaySession(DrivechainReplayEffects effects, Recover recover)
{
    return [effects = std::move(effects), recover = std::move(recover)](
        uint32_t step, uint64_t index, std::span<const unsigned char> input) {
        try {
            if (step == 43) {
                if (index > 4 || !input.empty()) throw std::logic_error("invalid replay session completion");
                if (index == 4) throw std::runtime_error("Haskell replay store workflow failed");
                return ReplayRecordBytes(true, static_cast<uint32_t>(index));
            }
            auto reply = effects(step, index, input);
            reply.insert(reply.begin(), 1);
            return reply;
        } catch (const std::exception& e) {
            return ReplayRecordBytes(false, recover(e));
        }
    };
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
DrivechainReplayEffects ReplayLookupEffects(
    const CDBWrapper* db, uint32_t schema, Key key, Value& value,
    std::string* error, bool& reading)
{
    return [db, schema, key = std::move(key), &value, error, &reading](
        uint32_t step, uint64_t index, std::span<const unsigned char> input) -> std::vector<unsigned char> {
        if (index || (!input.empty() && step != 25)) throw std::logic_error("invalid replay lookup request");
        switch (step) {
        case 0: return ReplayRecordBytes(db != nullptr);
        case 8: return ReplayRecordBytes(schema);
        case 25: SetStoreError(error, std::string(input.begin(), input.end())); return {};
        case 26: return ReplayRecordBytes(key.second);
        case 27: reading = true; return ReplayRecordBytes(db->Exists(key));
        case 28:
            if (!db->Read(key, value)) return {0};
            return ReplayRecordBytes(true, value);
        default: throw std::logic_error("invalid replay lookup effect");
        }
    };
}

template <typename Key, typename Value>
DrivechainReplayStoreReadStatus ReadReplayRecord(
    const CDBWrapper* db, uint32_t schema, const Key& key, Value& value,
    drivechain::haskell::ReplayStoreWorkflow kind, const char* failure, std::string* error)
{
    static_assert(static_cast<uint32_t>(DrivechainReplayStoreReadStatus::FOUND) == 0 &&
        static_cast<uint32_t>(DrivechainReplayStoreReadStatus::NOT_FOUND) == 1 &&
        static_cast<uint32_t>(DrivechainReplayStoreReadStatus::CORRUPT) == 2);
    bool reading{false};
    try {
        return static_cast<DrivechainReplayStoreReadStatus>(drivechain::haskell::RunReplayStore(kind,
            ReplayLookupEffects(db, schema, key, value, error, reading)));
    } catch (const std::exception& e) {
        if (!reading) throw; // Preserve the original preflight exception boundary.
        SetStoreError(error, strprintf("%s: %s", failure, e.what()));
        return DrivechainReplayStoreReadStatus::CORRUPT;
    }
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
    return static_cast<DrivechainReplayStoreLoadStatus>(hs::RunReplayStore(hs::ReplayStoreWorkflow::LOAD_SESSION,
        LoadEffects(identity, tip, error)));
}

DrivechainReplayEffects DrivechainParentReplayStore::LoadEffects(
    const uint256& identity, DrivechainParentReplayTip& tip, std::string* error) const
{
    static_assert(static_cast<uint32_t>(DrivechainReplayStoreLoadStatus::EMPTY) == 0 &&
        static_cast<uint32_t>(DrivechainReplayStoreLoadStatus::LOADED) == 1 &&
        static_cast<uint32_t>(DrivechainReplayStoreLoadStatus::CORRUPT) == 2 &&
        static_cast<uint32_t>(DrivechainReplayStoreLoadStatus::IDENTITY_MISMATCH) == 3);
    auto reading = std::make_shared<bool>(false);
    return ReplaySession(
            [this, &identity, &tip, error, reading](uint32_t step, uint64_t index, std::span<const unsigned char> input) -> std::vector<unsigned char> {
                if (index || (!input.empty() && step != 25)) throw std::logic_error("invalid replay load request");
                switch (step) {
                case 0: return ReplayRecordBytes(m_db != nullptr);
                case 3: *reading = true; return ReplayRecordBytes(m_db->Exists(DB_REPLAY_IDENTITY));
                case 4: {
                    DrivechainReplayStoreIdentity value;
                    if (!m_db->Read(DB_REPLAY_IDENTITY, value)) return {0};
                    return ReplayRecordBytes(true, value);
                }
                case 5: return ReplayRecordBytes(m_db->Exists(DB_REPLAY_TIP));
                case 6:
                    if (!m_db->Read(DB_REPLAY_TIP, tip)) return {0};
                    return ReplayRecordBytes(true, tip);
                case 8: return ReplayRecordBytes(m_schema_version);
                case 25: SetStoreError(error, std::string(input.begin(), input.end())); break;
                case 26: return ReplayRecordBytes(identity);
                case 39: if (error) error->clear(); break;
                default: throw std::logic_error("invalid replay load effect");
                }
                return {};
            }, [reading, error](const std::exception& e) -> uint32_t {
        if (!*reading) throw; // Preserve the original preflight exception boundary.
        SetStoreError(error, strprintf(
                                 "persistent parent replay load failed: %s", e.what()));
        return static_cast<uint32_t>(DrivechainReplayStoreLoadStatus::CORRUPT);
    });
}

bool DrivechainParentReplayStore::Reset(
    const uint256& identity,
    const DrivechainParentReplayTip& seed,
    std::string* error)
{
    namespace hs = drivechain::haskell;
    return hs::RunReplayStore(hs::ReplayStoreWorkflow::RESET_SESSION, ResetEffects(identity, seed, error));
}

DrivechainReplayEffects DrivechainParentReplayStore::ResetEffects(
    const uint256& identity, const DrivechainParentReplayTip& seed, std::string* error)
{
    // The replay store is a derived cache. Its authenticated seed is normally
    // parent genesis, but a pruned-light-client profile may instead seed the
    // exact immutable checkpoint whose complete replay state is committed by
    // the network identity. Validate the record itself here; the caller owns
    // authentication of the seed against that identity commitment.
    // Release LevelDB's directory lock before opening the same derived index
    // with fWipe. No reader can race this operation: callers hold the replay
    // mutex and the published epoch is zero.
    struct ResetSession {
        bool rebuilding{false};
        std::optional<CDBBatch> batch;
    };
    auto session = std::make_shared<ResetSession>();
    return ReplaySession(
            [this, &identity, &seed, error, session](uint32_t step, uint64_t index, std::span<const unsigned char> input) -> std::vector<unsigned char> {
            auto& batch = session->batch;
            if (index || (!input.empty() && step != 25)) throw std::logic_error("invalid replay reset request");
            switch (step) {
            case 1: return ReplayRecordBytes(seed);
            case 23: batch.value().Write(DB_REPLAY_TIP, seed); break;
            case 24: return ReplayRecordBytes(m_db->WriteBatch(batch.value(), drivechain::REPLAY_DB_SYNC));
            case 25: SetStoreError(error, std::string(input.begin(), input.end())); break;
            case 40: m_db.reset(); break;
            case 41:
                session->rebuilding = true;
                m_db = std::make_unique<CDBWrapper>(DBParams{
                    .path = m_path, .cache_bytes = m_cache_bytes, .memory_only = drivechain::REPLAY_DB_MEMORY_ONLY,
                    .wipe_data = drivechain::REPLAY_RESET_WIPE, .obfuscate = drivechain::REPLAY_DB_OBFUSCATE});
                batch.emplace(*m_db);
                break;
            case 42: batch.value().Write(DB_REPLAY_IDENTITY, DrivechainReplayStoreIdentity{m_schema_version, identity}); break;
            default: throw std::logic_error("invalid replay reset effect");
            }
            return {};
        }, [session, error](const std::exception& e) -> uint32_t {
        session->batch.reset();
        if (!session->rebuilding) throw;
        return SetStoreError(error, strprintf(
                                        "failed to rebuild persistent parent replay database: %s",
                                        e.what()));
    });
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
    return hs::RunReplayStore(hs::ReplayStoreWorkflow::APPEND_SESSION,
        AppendEffects(previous, next, deposits, edge, successful_withdrawals, withdrawal_proposals, error));
}

DrivechainReplayEffects DrivechainParentReplayStore::AppendEffects(
    const DrivechainParentReplayTip& previous,
    const DrivechainParentReplayTip& next,
    const std::vector<DrivechainMintableDeposit>& deposits,
    const std::optional<std::pair<uint256, DrivechainReplayedBmmEdge>>& edge,
    const std::vector<DrivechainSuccessfulWithdrawal>& successful_withdrawals,
    const std::vector<DrivechainWithdrawalProposalIdentity>& withdrawal_proposals,
    std::string* error)
{
    auto session = std::make_shared<std::optional<CDBBatch>>();
    return ReplaySession(
            [this, &previous, &next, &deposits, &edge, &successful_withdrawals, &withdrawal_proposals, error, session](
                uint32_t step, uint64_t index, std::span<const unsigned char> input) -> std::vector<unsigned char> {
                auto& batch = *session;
                if (index > SIZE_MAX || (!input.empty() && step != 7 && step != 25))
                    throw std::logic_error("invalid replay append request");
                switch (step) {
                case 0: return ReplayRecordBytes(m_db != nullptr);
                case 1: return ReplayRecordBytes(previous);
                case 2: return ReplayRecordBytes(next);
                case 3: return ReplayRecordBytes(m_db->Exists(DB_REPLAY_IDENTITY));
                case 4: {
                    DrivechainReplayStoreIdentity value;
                    if (!m_db->Read(DB_REPLAY_IDENTITY, value)) return {0};
                    return ReplayRecordBytes(true, value);
                }
                case 5: return ReplayRecordBytes(m_db->Exists(DB_REPLAY_TIP));
                case 6: {
                    DrivechainParentReplayTip value;
                    if (!m_db->Read(DB_REPLAY_TIP, value)) return {0};
                    return ReplayRecordBytes(true, value);
                }
                case 7: return ReplayRecordBytes(Hash(input));
                case 8:
                    if (index == 0) return ReplayRecordBytes(m_schema_version);
                    if (index == 1) return ReplayRecordBytes(uint64_t{deposits.size()}, edge.has_value(),
                        uint64_t{successful_withdrawals.size()}, uint64_t{withdrawal_proposals.size()});
                    throw std::logic_error("invalid replay append shape");
                case 9: return ReplayRecordBytes(deposits.at(index));
                case 10: return ReplayRecordBytes(m_db->Exists(std::make_pair(DB_REPLAY_DEPOSIT, deposits.at(index).outpoint)));
                case 11: return ReplayRecordBytes(edge.value());
                case 12: return ReplayRecordBytes(m_db->Exists(std::make_pair(DB_REPLAY_BMM_EDGE, edge.value().first)));
                case 13: return ReplayRecordBytes(successful_withdrawals.at(index));
                case 14: return ReplayRecordBytes(m_db->Exists(SuccessfulWithdrawalKey(successful_withdrawals.at(index).sidechain_slot,
                    successful_withdrawals.at(index).m6id)));
                case 15: return ReplayRecordBytes(m_db->Exists(WithdrawalOccurrenceKey(successful_withdrawals.at(index).sidechain_slot,
                    successful_withdrawals.at(index).m6id, successful_withdrawals.at(index).block_height)));
                case 16: return ReplayRecordBytes(withdrawal_proposals.at(index).sidechain_slot, withdrawal_proposals.at(index).m6id);
                case 17: return ReplayRecordBytes(m_db->Exists(SuccessfulWithdrawalKey(withdrawal_proposals.at(index).sidechain_slot,
                    withdrawal_proposals.at(index).m6id)));
                case 18: batch.emplace(*m_db); break;
                case 19: batch.value().Write(std::make_pair(DB_REPLAY_DEPOSIT, deposits.at(index).outpoint), deposits.at(index)); break;
                case 20: batch.value().Write(std::make_pair(DB_REPLAY_BMM_EDGE, edge.value().first), edge.value().second); break;
                case 21: batch.value().Write(SuccessfulWithdrawalKey(successful_withdrawals.at(index).sidechain_slot,
                    successful_withdrawals.at(index).m6id), successful_withdrawals.at(index)); break;
                case 22: batch.value().Write(WithdrawalOccurrenceKey(successful_withdrawals.at(index).sidechain_slot,
                    successful_withdrawals.at(index).m6id, successful_withdrawals.at(index).block_height),
                    successful_withdrawals.at(index)); break;
                case 23: batch.value().Write(DB_REPLAY_TIP, next); break;
                case 24: return ReplayRecordBytes(m_db->WriteBatch(batch.value(), drivechain::REPLAY_DB_SYNC));
                case 25: SetStoreError(error, std::string(input.begin(), input.end())); break;
                default: throw std::logic_error("invalid replay append effect");
                }
                return {};
            }, [this, session, error](const std::exception& e) -> uint32_t {
        session->reset();
        if (!m_db) throw; // The original unopened-store diagnostic was outside this catch.
        return SetStoreError(error, strprintf("persistent parent replay append failed: %s", e.what()));
    });
}

DrivechainReplayStoreReadStatus DrivechainParentReplayStore::ReadDeposit(
    const Sidechain::Bitcoin::COutPoint& outpoint,
    DrivechainMintableDeposit& deposit,
    std::string* error) const
{
    return static_cast<DrivechainReplayStoreReadStatus>(drivechain::haskell::RunReplayStore(
        drivechain::haskell::ReplayStoreWorkflow::DEPOSIT_SESSION, DepositEffects(outpoint, deposit, error)));
}

DrivechainReplayEffects DrivechainParentReplayStore::DepositEffects(
    const Sidechain::Bitcoin::COutPoint& outpoint, DrivechainMintableDeposit& deposit,
    std::string* error) const
{
    auto reading = std::make_shared<bool>(false);
    return ReplaySession(ReplayLookupEffects(m_db.get(), m_schema_version,
        std::make_pair(DB_REPLAY_DEPOSIT, outpoint), deposit, error, *reading),
        [reading, error](const std::exception& e) -> uint32_t {
        if (!*reading) throw;
        SetStoreError(error, strprintf("persistent parent replay deposit read failed: %s", e.what()));
        return static_cast<uint32_t>(DrivechainReplayStoreReadStatus::CORRUPT);
    });
}

bool DrivechainParentReplayStore::ListDeposits(
    const std::optional<Sidechain::Bitcoin::COutPoint>& after, size_t limit,
    std::vector<DrivechainMintableDeposit>& deposits,
    std::optional<Sidechain::Bitcoin::COutPoint>& next, std::string* error) const
{
    return drivechain::haskell::RunReplayStore(drivechain::haskell::ReplayStoreWorkflow::SCAN_SESSION,
        ListDepositEffects(after, limit, deposits, next, error));
}

DrivechainReplayEffects DrivechainParentReplayStore::ListDepositEffects(
    const std::optional<Sidechain::Bitcoin::COutPoint>& after, size_t limit,
    std::vector<DrivechainMintableDeposit>& deposits,
    std::optional<Sidechain::Bitcoin::COutPoint>& next, std::string* error) const
{
    struct Scan {
        bool scanning{false};
        std::unique_ptr<CDBIterator> it;
        std::vector<DrivechainMintableDeposit> page;
        std::optional<Sidechain::Bitcoin::COutPoint> cursor;
        std::optional<DrivechainMintableDeposit> deposit;
    };
    auto scan = std::make_shared<Scan>();
    return ReplaySession(
            [this, after, limit, &deposits, &next, error, scan](uint32_t step, uint64_t index, std::span<const unsigned char> input) -> std::vector<unsigned char> {
                auto& [scanning, it, page, cursor, deposit] = *scan;
                if ((index && (step != 8 || index != 1)) || (!input.empty() && step != 25))
                    throw std::logic_error("invalid replay scan request");
                switch (step) {
                case 0: return ReplayRecordBytes(m_db != nullptr);
                case 8: return ReplayRecordBytes(uint64_t{limit});
                case 25: SetStoreError(error, std::string(input.begin(), input.end())); break;
                case 26: return after ? ReplayRecordBytes(true, *after) : ReplayRecordBytes(false);
                case 29: deposits.clear(); next.reset(); break;
                case 30:
                    scanning = true;
                    it.reset(m_db->NewIterator());
                    if (after) it->Seek(std::make_pair(DB_REPLAY_DEPOSIT, *after));
                    else it->Seek(DB_REPLAY_DEPOSIT);
                    break;
                case 31: return ReplayRecordBytes(it->Valid());
                case 32: {
                    uint8_t prefix{};
                    if (!it->GetKey(prefix)) return {0};
                    return ReplayRecordBytes(true, prefix);
                }
                case 33: {
                    std::pair<uint8_t, Sidechain::Bitcoin::COutPoint> key;
                    if (!it->GetKey(key)) return {0};
                    return ReplayRecordBytes(true, key.second);
                }
                case 34:
                    if (!it->GetValue(deposit.emplace())) return {0};
                    return ReplayRecordBytes(true, *deposit);
                case 35: page.push_back(std::move(deposit.value())); deposit.reset(); break;
                case 36: it->Next(); break;
                case 37: cursor = page.back().outpoint; break;
                case 38: it->CheckStatus(); deposits = std::move(page); next = cursor; break;
                default: throw std::logic_error("invalid replay scan effect");
                }
                return {};
            }, [scan, error](const std::exception& e) -> uint32_t {
                if (!scan->scanning) throw;
                return SetStoreError(error, strprintf("parent deposit scan failed: %s", e.what()));
            });
}

DrivechainReplayStoreReadStatus DrivechainParentReplayStore::ReadBmmEdge(
    const uint256& parent_hash,
    DrivechainReplayedBmmEdge& edge,
    std::string* error) const
{
    return ReadReplayRecord(m_db.get(), m_schema_version, std::make_pair(DB_REPLAY_BMM_EDGE, parent_hash),
        edge, drivechain::haskell::ReplayStoreWorkflow::EDGE,
        "persistent parent replay BMM-edge read failed", error);
}

DrivechainReplayStoreReadStatus
DrivechainParentReplayStore::ReadSuccessfulWithdrawal(
    const uint8_t sidechain_slot,
    const uint256& m6id,
    DrivechainSuccessfulWithdrawal& withdrawal,
    std::string* error) const
{
    return ReadReplayRecord(m_db.get(), m_schema_version, SuccessfulWithdrawalKey(sidechain_slot, m6id),
        withdrawal, drivechain::haskell::ReplayStoreWorkflow::WITHDRAWAL,
        "persistent parent replay successful-withdrawal read failed", error);
}

DrivechainReplayStoreReadStatus
DrivechainParentReplayStore::ReadSuccessfulWithdrawalAtHeight(
    const uint8_t sidechain_slot, const uint256& m6id, const uint32_t height,
    DrivechainSuccessfulWithdrawal& withdrawal, std::string* error) const
{
    return ReadReplayRecord(m_db.get(), m_schema_version, WithdrawalOccurrenceKey(sidechain_slot, m6id, height),
        withdrawal, drivechain::haskell::ReplayStoreWorkflow::OCCURRENCE,
        "withdrawal occurrence read failed", error);
}
