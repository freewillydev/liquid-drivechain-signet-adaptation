// Copyright (c) 2014-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/haskell_reference.h>
#include <bitcoin-build-config.h> // IWYU pragma: keep
#include <block_proof.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <chain.h>
#include <tuple>
#include <numeric>
#include <tinyformat.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/tx_check.h>
#include <consensus/tx_verify.h>
#include <crypto/sha256.h>
#include <drivechain_bmm.h>
#include <drivechain_parent_replay.h>
#include <dbwrapper.h>
#include <elements_drivechain_identity.h>
#include <init.h>
#include <haskell/rpc_security_constants.h>
#include <key.h>
#include <key_io.h>
#include <mainchainrpc.h>
#include <consensus/merkle.h>
#include <core_io.h>
#include <hash.h>
#include <net.h>
#include <net_processing.h>
#include <node/kernel_notifications.h>
#include <node/miner.h>
#include <node/interface_ui.h>
#include <pegins.h>
#include <policy/policy.h>
#include <pow.h>
#include <rpc/request.h>
#include <signet.h>
#include <script/signingprovider.h>
#include <streams.h>
#include <sync.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <util/chaintype.h>
#include <util/signalinterrupt.h>
#include <validation.h>

#include <algorithm>
#include <map>
#include <string>

#include <test/util/setup_common.h>
#include <test/util/mining.h>
#include <test/util/logging.h>
#include <test/util/txmempool.h>

#include <limits>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <thread>
#include <type_traits>

#ifndef WIN32
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#endif


#include <boost/test/unit_test.hpp>
#include <boost/signals2/connection.hpp>

// Legacy standalone entries remain test oracles, not production FFI sites.
namespace drivechain {
void BuildBitcoinSignetTransactions(const CScript& challenge,
    Sidechain::Bitcoin::CMutableTransaction& spend, Sidechain::Bitcoin::CMutableTransaction& sign)
{
    haskell::RunParentHeader(haskell::ParentHeaderWorkflow::SIGNET_BUILD, 0,
        [&](uint32_t step, uint64_t, std::span<const unsigned char> fields) {
            BitcoinSignetTransactionAction(step-200, fields, challenge, spend, sign);
            return std::vector<unsigned char>{1,0,0,0,0,0,0,0};
        });
}

std::vector<unsigned char> BitcoinSignetBlockData(const Sidechain::Bitcoin::CBlockHeader& header,
    const uint256& modified_merkle_root)
{
    std::vector<unsigned char> block_data;
    VectorWriter writer{block_data, 0};
    haskell::RunParentHeader(haskell::ParentHeaderWorkflow::SIGNET_DATA, 0,
        [&](uint32_t step, uint64_t) -> uint64_t {
            BitcoinSignetDataAction(step-300, header, modified_merkle_root, writer);
            return 1;
        });
    return block_data;
}

int BitcoinWitnessCommitmentIndex(const std::vector<Sidechain::Bitcoin::CTxOut>& outputs)
{
    int selected{-1};
    haskell::RunParentHeader(haskell::ParentHeaderWorkflow::SIGNET_COMMITMENT, 0,
        [&](uint32_t step, uint64_t index, std::span<const unsigned char>) {
            return BitcoinWitnessCommitmentNative(outputs, selected, step, index);
        });
    return selected;
}
} // namespace drivechain

namespace drivechain::haskell {
int M3Proposal(const std::function<int64_t(uint32_t,uint64_t)>& action)
{
    return ReferenceCheckedStatus(ReferenceReadBoundAdmission<int64_t,-1>(elements_hs_m3_proposal_v1,action),
        2,"Haskell M3 proposal admission failed");
}

int M2Proposal(uint32_t height, uint16_t unused_age, uint16_t unused_threshold,
    uint16_t used_age, uint16_t used_threshold, const std::function<int64_t(uint32_t,uint64_t)>& action)
{
    return ReferenceCheckedStatus(ReferenceReadBoundAdmission<int64_t,-1>(elements_hs_m2_proposal_v1,action,
        height,unused_age,unused_threshold,used_age,used_threshold),2,"Haskell M2 activation failed");
}

int CtipOwners(uint64_t count, uint64_t maximum, const std::function<int64_t(uint32_t)>& action)
{
    return ReferenceCheckedStatus(ReferenceReadBoundAdmission<int64_t,-1>(elements_hs_ctip_owners_v1,action,count,maximum),
        2,"Haskell CTIP ownership failed");
}

int CtipSpends(uint64_t count, const std::function<int32_t(uint32_t,uint64_t)>& action)
{
    return ReferenceCheckedStatus(ReferenceReadBoundAdmission<int32_t,-1>(elements_hs_ctip_spends_v1,action,count),
        1,"Haskell CTIP spend scan failed");
}

int CtipOutputs(uint64_t count, uint64_t maximum, const std::function<int64_t(uint32_t,uint64_t)>& action)
{
    return ReferenceCheckedStatus(ReferenceReadBoundAdmission<int64_t,-1>(elements_hs_ctip_outputs_v1,action,count,maximum),
        2,"Haskell CTIP output scan failed");
}

int CtipReplacements(uint64_t count, const std::function<int32_t(uint32_t)>& action)
{
    return ReferenceCheckedStatus(ReferenceReadBoundAdmission<int32_t,-1>(elements_hs_ctip_replacements_v1,action,count),
        1,"Haskell CTIP replacement scan failed");
}

int CtipChanges(uint64_t count, const std::function<int64_t(uint32_t)>& action)
{
    return ReferenceCheckedStatus(ReferenceReadBoundAdmission<int64_t,-1>(elements_hs_ctip_changes_v1,action,count),
        2,"Haskell CTIP change preparation failed");
}

int M5Deposit(int64_t old_value, int64_t new_value, uint64_t maximum, uint64_t output, uint64_t outputs,
    uint32_t flags, const std::function<int64_t(uint32_t,uint64_t)>& action)
{
    return ReferenceCheckedStatus(ReferenceReadBoundAdmission<int64_t,-1>(elements_hs_m5_deposit_v1,action,old_value,new_value,maximum,output,outputs,flags),
        2,"Haskell M5 deposit transition failed");
}

int M6Withdrawal(uint64_t decreases, uint64_t changes, uint64_t inputs, uint32_t threshold, bool single,
    const std::function<int64_t(uint32_t)>& action)
{
    return ReferenceCheckedStatus(ReferenceReadBoundAdmission<int64_t,-1>(elements_hs_m6_withdrawal_v1,action,decreases,changes,inputs,threshold,single),
        7,"Haskell M6 withdrawal transition failed");
}
}

namespace drivechain::haskell {
static void CheckReplayVoteShape(std::span<const unsigned char> hashes, size_t count)
{
    if (count > UINT32_MAX || hashes.size()/32 != count || hashes.size()%32 != 0)
        throw std::invalid_argument("invalid replay vote shape");
}

int M4Repeat(bool upvote, const std::function<int64_t(uint32_t)>& action)
{
    return ReferenceCheckedStatus(ReferenceReadBoundAdmission<int64_t,-1>(elements_hs_m4_repeat_v1,action,upvote),
        2,"Haskell repeated M4 failed");
}

int M4Mode(uint32_t flags, uint64_t votes, const std::function<int64_t(uint32_t)>& action)
{
    const auto result = ReferenceReadBoundAdmission<int64_t,-1>(elements_hs_m4_mode_v1,action,flags,votes);
    if (result < 1 || result > 6) throw std::runtime_error("Haskell M4 mode selection failed");
    return result;
}

int ReplayUpvote(std::span<const unsigned char> hashes, std::span<const unsigned char,32> target, std::span<uint16_t> votes)
{
    CheckReplayVoteShape(hashes,votes.size());
    elements_hs_runtime_init();
    return ReferenceCheckedStatus(elements_hs_replay_upvote_v1(votes.size(),const_cast<unsigned char*>(hashes.data()),
        const_cast<unsigned char*>(target.data()),votes.data()),2,"Haskell replay upvote failed");
}

bool ReplayAlarm(std::span<uint16_t> votes)
{
    if (votes.size() > UINT32_MAX) throw std::invalid_argument("invalid replay vote count");
    elements_hs_runtime_init();
    const auto result = elements_hs_replay_alarm_v1(votes.size(),votes.data());
    if (result != 1 && result != 2) throw std::runtime_error("Haskell replay alarm failed");
    return result == 1;
}

int64_t ReplayLeading(std::span<const unsigned char> hashes, std::span<uint16_t> votes)
{
    CheckReplayVoteShape(hashes,votes.size());
    elements_hs_runtime_init();
    const auto result = elements_hs_replay_leading_v1(votes.size(),const_cast<unsigned char*>(hashes.data()),votes.data());
    if (result < -1 || (result >= 0 && static_cast<uint64_t>(result) >= votes.size()))
        throw std::runtime_error("Haskell leading vote failed");
    return result;
}

int ReplayExplicit(uint16_t vote, std::span<const unsigned char> hashes, std::span<uint16_t> votes)
{
    if (vote == UINT16_MAX) return 0;
    CheckReplayVoteShape(hashes,votes.size());
    elements_hs_runtime_init();
    return ReferenceCheckedStatus(elements_hs_replay_explicit_v1(vote,votes.size(),
        const_cast<unsigned char*>(hashes.data()),votes.data()),3,"Haskell explicit vote failed");
}
}

// Standalone compatibility probe; production recovery composes this rule in Haskell.
namespace drivechain {
inline bool IsPrunedBlockReply(const UniValue& reply)
{
    const auto& error = reply["error"];
    return haskell::ParentReplayStore(haskell::ReplayStoreFlow::RECOVERY_PRUNED,[&](uint32_t step) {
        switch (step) {
        case 1: return error.isObject();
        case 2: return error["code"].isNum();
        case 3: return error["code"].getInt<int>()==-1;
        case 4: return error["message"].isStr();
        case 5: return error["message"].get_str()=="Block not available (pruned data)";
        default: throw std::logic_error("invalid pruned reply action");
        }
    })==0;
}
}

namespace Bitcoin = Sidechain::Bitcoin;

bool CheckBitcoinSignetBlockSolution(const Bitcoin::CBlock& block,
                                     const CScript& challenge,
                                     const uint256& genesis_hash,
                                     std::string* error)
{
    namespace hs = drivechain::haskell;
    return hs::RunParentHeader(hs::ParentHeaderWorkflow::SIGNET_VERIFY, 0,
        hs::PrepareParentSignet(block,challenge,genesis_hash,error));
}

static uint256 ComputeBitcoinModifiedMerkleRoot(const Bitcoin::CMutableTransaction& coinbase,
                                               const Bitcoin::CBlock& block)
{
    std::vector<uint256> leaves;
    uint256 root;
    drivechain::haskell::RunParentHeader(drivechain::haskell::ParentHeaderWorkflow::SIGNET_MERKLE,0,
        [&](uint32_t step,uint64_t index) -> uint64_t {
            switch (step) {
            case 601: leaves.reserve(block.vtx.size()); return 1;
            case 602: leaves.push_back(coinbase.GetHash()); return 1;
            case 603: return block.vtx.size();
            case 604: leaves.push_back(block.vtx.at(index)->GetHash()); return 1;
            case 605: root = ComputeMerkleRoot(std::move(leaves)); return 1;
            default: throw std::logic_error("invalid parent signet Merkle action");
            }
        });
    return root;
}

BOOST_AUTO_TEST_SUITE(haskell_workflow_boundary_tests)
BOOST_AUTO_TEST_CASE(parent_messages_publication_and_failure_boundaries)
{
    namespace hs = drivechain::haskell;
    std::vector<std::pair<uint32_t,uint64_t>> trace;
    const auto empty = [&](uint32_t step, uint64_t index, auto) {
        trace.emplace_back(step,index);
        return std::vector<unsigned char>{};
    };
    BOOST_CHECK_EQUAL(hs::ReplayMessages(0,100,{4,1,2,2},empty),0);
    BOOST_CHECK((trace == std::vector<std::pair<uint32_t,uint64_t>>{{40,0}}));
    trace.clear();
    BOOST_CHECK_EQUAL(hs::ReplayMessages(1,100,{4,1,2,2},[&](uint32_t step, uint64_t index, auto) {
        trace.emplace_back(step,index);
        return step == 0 ? std::vector<unsigned char>{5,2} : std::vector<unsigned char>{};
    }),0);
    BOOST_CHECK((trace == std::vector<std::pair<uint32_t,uint64_t>>{{0,0},{40,0}}));
    trace.clear();
    BOOST_CHECK_THROW(hs::ReplayMessages(1,100,{4,1,2,2},empty),std::runtime_error);
    BOOST_CHECK((trace == std::vector<std::pair<uint32_t,uint64_t>>{{0,0}}));
    trace.clear();
    const auto native = [&](uint32_t step, uint64_t index, auto) {
        trace.emplace_back(step,index);
        if (step == 0) return std::vector<unsigned char>{static_cast<unsigned char>(index ? 2 : 1),0};
        if (step == 11) {
            std::vector<unsigned char> reply(8);
            WriteLE64(reply.data(),101);
            return reply;
        }
        return std::vector<unsigned char>{};
    };
    // The first M1 mutation survives a later rejection, but final publication does not.
    BOOST_CHECK_EQUAL(hs::ReplayMessages(3,100,{4,1,2,2},native),0x101);
    const std::vector<std::pair<uint32_t,uint64_t>> expected{{0,0},{2,0},{0,1},{3,0},{11,0}};
    BOOST_CHECK(trace == expected);
    trace.clear();
    BOOST_CHECK_EXCEPTION(hs::ReplayMessages(3,100,{4,1,2,2},[&](uint32_t step, uint64_t index, auto input) {
        auto reply = native(step,index,input);
        if (step == 11) throw std::logic_error("first replay fault");
        return reply;
    }),std::logic_error,[](const auto& error) { return std::string(error.what()) == "first replay fault"; });
    BOOST_CHECK(trace == expected);
}
BOOST_AUTO_TEST_SUITE_END()

namespace {
void CheckStartupRejected(std::initializer_list<std::pair<std::string,std::string>> settings,
    const std::string& expected, const std::optional<std::string>& timeout = std::nullopt)
{
    ArgsManager args;
    args.ForceSetArg("-chain",Params().NetworkIDString());
    for (const auto& [key,value] : settings) args.ForceSetArg(key,value);
    std::vector<std::string> errors;
    boost::signals2::scoped_connection capture{uiInterface.ThreadSafeMessageBox_connect(
        [&](const bilingual_str& message,const std::string&,unsigned int) {
            errors.push_back(message.original);
            return false;
        })};
    BOOST_CHECK(!AppInitParameterInteraction(args));
    BOOST_REQUIRE_EQUAL(errors.size(),1);
    BOOST_CHECK_EQUAL(errors.front(),expected);
    BOOST_CHECK_EQUAL(args.IsArgSet("-mainchainrpctimeout"),timeout.has_value());
    if (timeout) BOOST_CHECK_EQUAL(args.GetArg("-mainchainrpctimeout",""),*timeout);
}

struct SignetParameterSetup : BasicTestingSetup {
    SignetParameterSetup() : BasicTestingSetup{ChainType::SIGNET} {}
};
}

BOOST_FIXTURE_TEST_CASE(signet_startup_parameter_precedence, SignetParameterSetup)
{
    BOOST_REQUIRE(!Params().GetConsensus().drivechain_slot);
    unsigned signet_logs{0};
    DebugLogHelper capture("Signet derived magic (message start):",[&](const std::string* line) {
        if (line) ++signet_logs;
        return false;
    });
    CheckStartupRejected({{"-drivechainrewardaddress","invalid"}},
        "-drivechainrewardaddress may only be used in an Elements parent-chain configuration");
    BOOST_CHECK_EQUAL(signet_logs,0U);
    CheckStartupRejected({{"-drivechainbmmbid","invalid"}},
        "-drivechainbmmbid may only be used on a native drivechain network");
    BOOST_CHECK_EQUAL(signet_logs,1U);
    CheckStartupRejected({{"-parentgenesisblockhash","not-the-parent"},
        {"-mainchainrpccredentialfile","missing-file"},{"-mainchainrpccookiefile","missing-cookie"}},
        "-parentgenesisblockhash cannot override the Signet chainparams identity");
    const auto missing=fs::PathToString(m_path_root / "missing-blocks");
    CheckStartupRejected({{"-parentgenesisblockhash",Params().ParentGenesisBlockHash().GetHex()},{"-blocksdir",missing}},
        "Specified blocks directory \""+missing+"\" does not exist.");
    BOOST_CHECK_EQUAL(signet_logs,3U);
}

bool CheckInputScripts(const CTransaction&, TxValidationState&, const CCoinsViewCache&,
    unsigned int, bool, bool, PrecomputedTransactionData&, ValidationCache&,
    std::vector<CCheck*>*) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

BOOST_FIXTURE_TEST_SUITE(validation_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(replay_traversal_preserves_native_lock_scope)
{
    Mutex mutex;
    LOCK(mutex);
    const auto caller = std::this_thread::get_id();
    const std::array<int, 3> entries{1, 2, 3};
    std::vector<int> visited;
    const std::function<bool(const int&)> visit = [&](const int& value) EXCLUSIVE_LOCKS_REQUIRED(mutex) {
        AssertLockHeld(mutex);
        BOOST_CHECK(std::this_thread::get_id() == caller);
        visited.push_back(value);
        return value != 2;
    };
    BOOST_CHECK(!drivechain::haskell::ParentReplayEach(entries, visit));
    BOOST_CHECK(visited == std::vector<int>({1, 2}));
    AssertLockHeld(mutex);
}


// Independent native encoding: presence bits distinguish absence from zero.
static uint256 ReferenceForkScriptCacheKey(const PrecomputedTransactionData& data,
    const CTransaction& tx, unsigned int flags, const ValidationCache& cache, bool correct_domain)
{
    CSHA256 hasher = cache.ScriptExecutionCacheHasher();
    const std::string domain = correct_domain ? "Elements/BMM-script-cache/v1" : "Elements/BMM-script-cache/v0";
    hasher.Write(tx.GetWitnessHash().ToUint256().begin(), 32)
        .Write(reinterpret_cast<unsigned char*>(&flags), sizeof(flags))
        .Write(reinterpret_cast<const unsigned char*>(domain.c_str()), domain.size() + 1);
    const unsigned char mtp_present = data.m_bmm_parent_mtp.has_value();
    hasher.Write(&mtp_present, 1);
    if (data.m_bmm_parent_mtp) {
        unsigned char bytes[8];
        WriteLE64(bytes, *data.m_bmm_parent_mtp);
        hasher.Write(bytes, 8);
    }
    const unsigned char endpoint_present = data.m_prior_active_bmm_parent_checkpoint.has_value();
    hasher.Write(&endpoint_present, 1);
    if (endpoint_present) hasher.Write(data.m_prior_active_bmm_parent_checkpoint->data(), 80);
    uint256 result;
    hasher.Finalize(result.begin());
    return result;
}

BOOST_AUTO_TEST_CASE(fork_script_cache_context_fields_are_distinct)
{
    LOCK(cs_main);
    auto& coins = m_node.chainman->ActiveChainstate().CoinsTip();
    const COutPoint outpoint(Txid::FromUint256(uint256::ONE), 0);
    coins.AddCoin(outpoint, Coin(CTxOut(policyAsset, 1000, CScript() << OP_TRUE), 0, false), false);
    CMutableTransaction spend;
    spend.vin.emplace_back(outpoint);
    spend.vout.emplace_back(policyAsset, 900, CScript() << OP_TRUE);
    const CTransaction tx(spend);
    PrecomputedTransactionData base;
    base.m_bmm_parent_mtp = 1;
    base.m_prior_active_bmm_parent_checkpoint = PriorActiveBmmParentCheckpoint{1};
    auto& cache = m_node.chainman->m_validation_cache;
    TxValidationState state;
    BOOST_REQUIRE(CheckInputScripts(tx, state, coins, 0, true, true, base, cache, nullptr));
    const auto probe = [&](PrecomputedTransactionData& context, ValidationCache& selected, unsigned int flags, bool hit)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        std::vector<CCheck*> checks;
        TxValidationState result;
        BOOST_CHECK(CheckInputScripts(tx, result, coins, flags, true, true, context, selected, &checks));
        BOOST_CHECK_EQUAL(checks.empty(), hit);
        for (auto* check : checks) delete check;
    };
    const auto check = [&](PrecomputedTransactionData& context, bool hit) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        probe(context, cache, 0, hit);
        for (bool correct : {false, true}) for (unsigned int flags : {0U, 1U, 0x01020304U}) {
            ValidationCache isolated{32768,32768};
            isolated.m_script_execution_cache.insert(ReferenceForkScriptCacheKey(context,tx,flags,isolated,correct));
            probe(context, isolated, flags, correct);
        }
    };
    check(base, true);
    for (uint64_t mtp : {uint64_t{0}, uint64_t{2}, uint64_t{UINT32_MAX}+1, UINT64_MAX}) {
        base.m_bmm_parent_mtp = mtp;
        check(base, false);
    }
    base.m_bmm_parent_mtp.reset();
    check(base, false);
    base.m_bmm_parent_mtp = 1;
    for (size_t i = 0; i < 80; ++i) {
        (*base.m_prior_active_bmm_parent_checkpoint)[i] ^= 1;
        check(base, false);
        (*base.m_prior_active_bmm_parent_checkpoint)[i] ^= 1;
    }
    base.m_prior_active_bmm_parent_checkpoint.reset();
    check(base, false);
    base.m_prior_active_bmm_parent_checkpoint = PriorActiveBmmParentCheckpoint{1};
    check(base, true);
}




BOOST_AUTO_TEST_CASE(rpc_direct_generation_guard_order)
{
    for (bool elements : {false,true}) for (bool proof : {false,true}) {
        std::vector<int> reads;
        const bool reject = drivechain::haskell::ParentReplayEach(std::array{0,1}, [&](int step) {
            reads.push_back(step);
            if (step == 0) return elements;
            if (!elements) throw std::logic_error("proof read before network admission");
            return proof;
        });
        BOOST_CHECK_EQUAL(reject,elements && proof);
        BOOST_CHECK(reads == (elements ? std::vector<int>{0,1} : std::vector<int>{0}));
    }
}

BOOST_AUTO_TEST_CASE(nested_pegin_scan_short_circuits)
{
    for (unsigned count = 0; count <= 4; ++count) {
        for (unsigned mask = 0; mask < (1U << count); ++mask) {
            std::vector<CMutableTransaction> transactions(3);
            for (unsigned i = 0; i < count; ++i) {
                CTxIn input;
                input.m_is_pegin = mask & (1U << i);
                transactions[i / 2].vin.push_back(input);
            }
            std::vector<bool> observed, expected;
            bool found{false};
            for (unsigned i = 0; i < count && !found; ++i) {
                found = mask & (1U << i);
                expected.push_back(found);
            }
            const bool actual = !drivechain::haskell::ParentReplayEach(transactions, [&](const auto& tx) {
                return drivechain::haskell::ParentReplayEach(tx.vin, [&](const CTxIn& input) {
                    observed.push_back(input.m_is_pegin);
                    return !input.m_is_pegin;
                });
            });
            BOOST_CHECK_EQUAL(actual, found);
            BOOST_CHECK(observed == expected);
        }
    }
}

BOOST_AUTO_TEST_CASE(deposit_transaction_uses_upstream_version)
{
    const CMutableTransaction transaction;
    BOOST_CHECK_EQUAL(transaction.version, 2U);
    BOOST_CHECK_EQUAL(transaction.nLockTime, 0U);
}

BOOST_AUTO_TEST_CASE(ephemeral_header_native_errors_clear_output)
{
    auto& chainman = *Assert(m_node.chainman);
    const auto& params = chainman.GetParams();
    auto& consensus = const_cast<Consensus::Params&>(params.GetConsensus());
    LOCK(cs_main);
    struct RestoreSlot {
        Consensus::Params& consensus;
        std::optional<uint8_t> slot;
        ~RestoreSlot() { consensus.drivechain_slot = slot; }
    } restore{consensus, consensus.drivechain_slot};
    const auto* genesis = chainman.m_blockman.LookupBlockIndex(params.GenesisBlock().GetHash());
    BOOST_REQUIRE(genesis);
    for (bool native : {false, true}) {
        consensus.drivechain_slot = native ? std::optional<uint8_t>{24} : std::nullopt;
        const CBlockIndex* predecessor = genesis;
        BlockValidationState state;
        BOOST_CHECK(!chainman.CheckDrivechainEphemeralHeader(params.GenesisBlock(), state, params, &predecessor));
        BOOST_CHECK(predecessor == nullptr);
        BOOST_CHECK(state.IsError());
        BOOST_CHECK_EQUAL(state.GetRejectReason(), native ? "ephemeral drivechain header is already indexed"
            : "ephemeral full-block-first header validation is only available on a native drivechain");
    }
}

BOOST_AUTO_TEST_CASE(connection_state_flow_matches_native_order)
{
    for (unsigned flags = 0; flags < 128; ++flags) {
        const auto bit = [&](unsigned index) { return bool(flags & (1U << index)); };
        std::vector<uint32_t> expected{1};
        bool stored{false}, bound{false};
        uint32_t error{0};
        if (bit(0)) {
            expected.push_back(2);
            if (bit(1)) { stored = true; expected.push_back(3); }
            expected.push_back(4);
            if (bit(2) && stored) {
                expected.push_back(5);
                if (bit(3)) { bound = true; expected.push_back(6); }
            }
            expected.push_back(7);
            if (!bit(4)) error = 8;
            else {
                expected.push_back(9);
                if (!bit(5)) error = 10;
                else { expected.push_back(11); if (!bit(6)) error = 12; }
            }
            if (error) expected.push_back(error);
        }
        std::vector<uint32_t> actual;
        bool actual_stored{false}, actual_bound{false};
        const bool result = drivechain::haskell::ParentReplayStore(
            drivechain::haskell::ReplayStoreFlow::CONNECTION_STATE, [&](uint32_t step) -> uint32_t {
            actual.push_back(step);
            switch (step) {
            case 1: return bit(0);
            case 2: return bit(1);
            case 3: actual_stored = true; return 1;
            case 4: return bit(2) && actual_stored;
            case 5: return bit(3);
            case 6: actual_bound = true; return 1;
            case 7: return bit(4);
            case 9: return bit(5);
            case 11: return bit(6);
            default: return 0;
            }
        });
        BOOST_CHECK_EQUAL(result, error == 0);
        BOOST_CHECK(actual == expected);
        BOOST_CHECK_EQUAL(actual_stored, stored);
        BOOST_CHECK_EQUAL(actual_bound, bound);
    }
}

BOOST_AUTO_TEST_CASE(connection_anchor_flow_matches_native_order)
{
    for (unsigned flags = 0; flags < 64; ++flags) {
        std::vector<uint32_t> expected;
        const auto fact = [&](unsigned index, uint32_t step) {
            expected.push_back(step);
            return bool(flags & (1U << index));
        };
        uint32_t error{0};
        if (!fact(0,1)) error = 2;
        else if (!fact(1,3)) { if (!fact(2,4)) error = 5; }
        else if (!fact(3,6)) error = 7;
        else if (fact(4,8)) error = 9;
        else if (fact(5,10)) error = 11;
        if (error) expected.push_back(error);
        std::vector<uint32_t> actual;
        const bool result = drivechain::haskell::ParentReplayStore(
            drivechain::haskell::ReplayStoreFlow::CONNECTION_ANCHOR, [&](uint32_t step) -> uint32_t {
            actual.push_back(step);
            constexpr std::array<uint32_t, 6> reads{1,3,4,6,8,10};
            const auto entry = std::find(reads.begin(), reads.end(), step);
            return entry != reads.end() && bool(flags & (1U << (entry - reads.begin())));
        });
        BOOST_CHECK_EQUAL(result, error == 0);
        BOOST_CHECK(actual == expected);
    }
}

BOOST_AUTO_TEST_CASE(ephemeral_header_flow_matches_native_order)
{
    for (unsigned flags = 0; flags < 128; ++flags) {
        std::vector<uint32_t> expected{1};
        const auto fact = [&](unsigned index, uint32_t step) {
            expected.push_back(step);
            return bool(flags & (1U << index));
        };
        uint32_t error{0};
        bool accepted{false};
        if (!(flags & 1)) error = 2;
        else if (fact(1,3)) error = 4;
        else if (!fact(2,5)) {}
        else if (!fact(3,6)) error = 7;
        else if (fact(4,8)) error = 9;
        else if (!fact(5,10)) error = 11;
        else if (fact(6,12)) { expected.push_back(13); accepted = true; }
        if (error) expected.push_back(error);
        std::vector<uint32_t> actual;
        bool published{false};
        const bool result = drivechain::haskell::ParentReplayStore(
            drivechain::haskell::ReplayStoreFlow::EPHEMERAL_HEADER, [&](uint32_t step) -> uint32_t {
            actual.push_back(step);
            if (step == 13) { published = true; return 1; }
            constexpr std::array<uint32_t, 7> reads{1,3,5,6,8,10,12};
            const auto entry = std::find(reads.begin(), reads.end(), step);
            return entry != reads.end() && bool(flags & (1U << (entry - reads.begin())));
        });
        BOOST_CHECK_EQUAL(result, accepted);
        BOOST_CHECK_EQUAL(published, accepted);
        BOOST_CHECK(actual == expected);
    }
}

BOOST_AUTO_TEST_CASE(recovery_ancestor_matches_native_pointer_walk)
{
    for (unsigned heights = 0; heights <= 64; ++heights) for (bool forest : {false, true}) {
        std::array<CBlockIndex, 6> nodes;
        for (size_t i = 0; i < nodes.size(); ++i) {
            nodes[i].pprev = i == 0 || (forest && i == 3) ? nullptr : &nodes[(i + 1) / 2 - 1];
            nodes[i].nHeight = heights == 64 ? (nodes[i].pprev ? nodes[i].pprev->nHeight + 1 : 0)
                : ((heights >> i) & 1U) ? 4 : -1;
        }
        for (size_t left = 0; left <= nodes.size(); ++left) for (size_t right = 0; right <= nodes.size(); ++right) {
            const CBlockIndex* first = left ? &nodes[left - 1] : nullptr;
            const CBlockIndex* second = right ? &nodes[right - 1] : nullptr;
            auto* expected_first = first;
            auto* expected_second = second;
            while (expected_first && expected_second && expected_first->nHeight > expected_second->nHeight)
                expected_first = expected_first->pprev;
            while (expected_first && expected_second && expected_second->nHeight > expected_first->nHeight)
                expected_second = expected_second->pprev;
            while (expected_first && expected_second && expected_first != expected_second) {
                expected_first = expected_first->pprev;
                expected_second = expected_second->pprev;
            }
            const bool matched = drivechain::haskell::ParentReplayStore(
                drivechain::haskell::ReplayStoreFlow::RECOVERY_ANCESTOR, [&](uint32_t step) -> uint32_t {
                switch (step) {
                case 1: case 5: case 9: return first != nullptr;
                case 2: case 6: case 10: return second != nullptr;
                case 3: return first->nHeight > second->nHeight;
                case 4: first = first->pprev; return 1;
                case 7: return second->nHeight > first->nHeight;
                case 8: second = second->pprev; return 1;
                case 11: return first != second;
                case 12: first = first->pprev; second = second->pprev; return 1;
                case 13: return first == second;
                default: throw std::logic_error("unexpected ancestor read");
                }
            });
            BOOST_CHECK_EQUAL(matched, expected_first == expected_second);
            BOOST_CHECK(first == expected_first);
            BOOST_CHECK(second == expected_second);
        }
    }
}

BOOST_AUTO_TEST_CASE(recovery_admission_matches_native_order)
{
    for (unsigned flags = 0; flags < 128; ++flags) {
        std::vector<uint32_t> expected;
        const auto fact = [&](uint32_t step) {
            expected.push_back(step);
            return bool(flags & (1U << (step - 1)));
        };
        bool accepted = fact(1) && fact(2);
        if (accepted && ((fact(3) && (fact(4) || fact(5))) || fact(6) || fact(7))) {
            expected.push_back(8);
            accepted = false;
        }
        std::vector<uint32_t> actual;
        const bool result = drivechain::haskell::ParentReplayStore(
            drivechain::haskell::ReplayStoreFlow::RECOVERY_ADMISSION, [&](uint32_t step) -> uint32_t {
            actual.push_back(step);
            return step == 8 ? 0 : bool(flags & (1U << (step - 1)));
        });
        BOOST_CHECK_EQUAL(result, accepted);
        BOOST_CHECK(actual == expected);
    }
}

BOOST_AUTO_TEST_CASE(branch_replay_matches_native_order)
{
    using Script = std::vector<std::pair<uint32_t, uint32_t>>;
    for (unsigned flags = 0; flags < 1024; ++flags) {
        const auto bit = [&](unsigned index) { return (flags >> index) & 1U; };
        const bool elements = bit(0), readable = bit(1);
        Script expected{{1,1},{2,1},{3,readable}};
        bool required{false};
        if (!readable) expected.emplace_back(4, 0);
        else {
            expected.emplace_back(5, elements);
            if (elements) for (unsigned i = 2; i < 6 && !required; ++i) {
                expected.emplace_back(i + 4, bit(i));
                required = bit(i);
            }
            if (!required) {
                expected.insert(expected.end(), {{11,1},{12,1},{13,1},{14,1},{15,bit(6)}});
                required = bit(6);
                if (!required) {
                    expected.emplace_back(16, elements);
                    if (elements) for (unsigned i = 7; i < 10 && !required; ++i) {
                        expected.emplace_back(i + 10, bit(i));
                        required = bit(i);
                    }
                }
                if (!required) expected.insert(expected.end(), {{20,1},{14,0},{21,1},{12,0},{22,1},{1,0}});
            }
            if (required) expected.emplace_back(10, 1);
        }
        size_t cursor{0};
        bool published{false};
        const bool accepted = drivechain::haskell::ParentReplayStore(
            drivechain::haskell::ReplayStoreFlow::BRANCH_REPLAY, [&](uint32_t step) {
                if (cursor >= expected.size()) throw std::logic_error("branch replay overread");
                BOOST_CHECK_EQUAL(step, expected[cursor].first);
                if (step == 10) published = true;
                return expected[cursor++].second;
            });
        BOOST_CHECK_EQUAL(accepted, readable);
        BOOST_CHECK_EQUAL(published, required);
        BOOST_CHECK_EQUAL(cursor, expected.size());
    }
}

BOOST_AUTO_TEST_CASE(block_deposit_preflight_matches_native_order)
{
    using Script = std::vector<std::pair<uint32_t, uint32_t>>;
    for (unsigned flags = 0; flags < 256; ++flags) {
        const auto bit = [&](unsigned index) { return (flags >> index) & 1U; };
        Script expected{{1, bit(0)}};
        bool accepted{true};
        if (bit(0)) {
            expected.insert(expected.end(), {{2,1},{3,1},{4,bit(1)}});
            if (!bit(1)) {
                expected.insert(expected.end(), {{5,1},{6,1},{7,bit(2)}});
                if (bit(2)) {
                    expected.insert(expected.end(), {{8,1},{9,bit(3)}});
                    uint32_t rejection{0};
                    if (!bit(3)) rejection = 13;
                    else {
                        expected.emplace_back(10, bit(4));
                        if (!bit(4)) {
                            expected.emplace_back(11, bit(5));
                            rejection = bit(5) ? 12 : 13;
                        } else {
                            expected.emplace_back(14, bit(6));
                            if (!bit(6)) rejection = 18;
                            else {
                                expected.emplace_back(15, bit(7));
                                if (!bit(7)) rejection = 19;
                            }
                        }
                    }
                    if (rejection) { expected.emplace_back(rejection, 0); accepted = false; }
                }
                if (accepted) expected.insert(expected.end(), {{16,1},{6,0}});
            }
            if (accepted) expected.insert(expected.end(), {{17,1},{3,0}});
        }
        size_t cursor{0};
        const auto actual = drivechain::haskell::ParentReplayStore(
            drivechain::haskell::ReplayStoreFlow::BLOCK_DEPOSIT_PREFLIGHT, [&](uint32_t step) {
                if (cursor >= expected.size()) throw std::logic_error("preflight overread");
                BOOST_CHECK_EQUAL(step, expected[cursor].first);
                return expected[cursor++].second;
            });
        BOOST_CHECK_EQUAL(actual, accepted);
        BOOST_CHECK_EQUAL(cursor, expected.size());
    }
}

BOOST_AUTO_TEST_CASE(retired_parent_context_selector_has_no_effects)
{
    unsigned calls{0};
    BOOST_CHECK_THROW(drivechain::haskell::ParentReplayStore(
        drivechain::haskell::ReplayStoreFlow::PARENT_CONTEXT, [&](uint32_t) { ++calls; return 1; }),
        std::runtime_error);
    BOOST_CHECK_EQUAL(calls, 0U);
}

BOOST_AUTO_TEST_CASE(next_block_height_boundaries)
{
    for (const int32_t height : {INT32_MIN, -1, 0, INT32_MAX - 1, INT32_MAX}) {
        BOOST_CHECK_EQUAL(drivechain::haskell::NextBlockHeight(false, height), -1);
        if (height == INT32_MAX) {
            BOOST_CHECK_THROW(drivechain::haskell::NextBlockHeight(true, height), std::runtime_error);
        } else {
            BOOST_CHECK_EQUAL(drivechain::haskell::NextBlockHeight(true, height), int64_t{height} + 1);
        }
    }
}


BOOST_AUTO_TEST_CASE(peer_block_dispatch_preserves_effects)
{
    namespace hs = drivechain::haskell;
    for (const uint32_t outcome : {0U, 1U, 2U, 3U, UINT32_MAX}) for (const bool present : {false, true}) {
        std::vector<uint32_t> trace, expected{1};
        if (outcome == 1) expected.push_back(2);
        if (outcome == 2) {
            expected.push_back(3);
            if (present) expected.push_back(4);
        }
        const auto result = hs::ParentReplayStore(hs::ReplayStoreFlow::PEER_BLOCK_DISPATCH,
            [&](uint32_t step) -> uint32_t {
                trace.push_back(step);
                if (step == 1) return outcome;
                if (step == 3) return present;
                return 1;
            });
        BOOST_CHECK_EQUAL(result, 1);
        BOOST_CHECK(trace == expected);
    }
}


BOOST_AUTO_TEST_CASE(fee_free_selection_raw_values)
{
    const auto caller = std::this_thread::get_id();
    for (int64_t age : {-1,0,1,10}) for (uint32_t changed : {4,5,6,7,8,9,12,13})
    for (uint64_t replacement : {uint64_t{0},uint64_t{1},uint64_t{2},UINT64_MAX}) {
        const auto field = [&](uint32_t step) -> uint64_t {
            if (step==changed) return replacement;
            if (step==4 || step==7 || step==8) return 0;
            if (step==11) return 95;
            if (step==17) return 100;
            return 1;
        };
        std::vector<uint32_t> expected{1,2,3};
        bool valid{true}, protocol{true};
        for (uint32_t step : {4,5,6,7,8,9}) {
            expected.push_back(step);
            const auto value=field(step);
            protocol=step!=9 || value<=1;
            valid=value==((step==4 || step==7 || step==8) ? 0 : 1);
            if (!valid) break;
        }
        if (valid && age>0) {
            expected.insert(expected.end(),{11,17});
            valid=95<=100-age;
        }
        if (valid) for (uint32_t step : {12,13}) {
            expected.push_back(step);
            protocol=field(step)<=1;
            valid=field(step)==1;
            if (!valid) break;
        }
        if (valid) expected.insert(expected.end(),{14,15});
        if (protocol) expected.insert(expected.end(),{16,3});
        for (size_t fault=0; fault<=expected.size(); ++fault) {
            std::vector<uint32_t> seen, effects;
            bool exhausted{false};
            const auto run = [&] {
                drivechain::haskell::FeeFreeSelection(age,[&](uint32_t step) -> uint64_t {
                    BOOST_CHECK(std::this_thread::get_id()==caller);
                    seen.push_back(step);
                    if (seen.size()==fault+1) throw std::runtime_error("raw selection fault");
                    if (step==9 || step==13) BOOST_CHECK_EQUAL(drivechain::haskell::BmmSelectedBid(1,0),1);
                    if (step==3) return !exhausted;
                    if (step>=14 && step<=16) effects.push_back(step);
                    if (step==16) exhausted=true;
                    return field(step);
                });
            };
            if (fault<expected.size() || !protocol) BOOST_CHECK_THROW(run(),std::runtime_error);
            else BOOST_CHECK_NO_THROW(run());
            const auto limit=std::min(fault+1,expected.size());
            BOOST_CHECK_EQUAL_COLLECTIONS(seen.begin(),seen.end(),expected.begin(),expected.begin()+limit);
            std::vector<uint32_t> wanted;
            for (size_t i=0; i<std::min(fault,expected.size()); ++i)
                if (expected[i]>=14 && expected[i]<=16) wanted.push_back(expected[i]);
            BOOST_CHECK_EQUAL_COLLECTIONS(effects.begin(),effects.end(),wanted.begin(),wanted.end());
        }
    }
    uint32_t rows{0};
    BOOST_CHECK_NO_THROW(drivechain::haskell::FeeFreeSelection(0,[&](uint32_t step) -> uint64_t {
        switch (step) {
        case 1: case 2: return 1;
        case 3: return rows<100000;
        case 4: return 1;
        case 16: ++rows; return 1;
        default: throw std::runtime_error("ineligible row reached later read");
        }
    }));
    BOOST_CHECK_EQUAL(rows,100000);
}

BOOST_AUTO_TEST_CASE(fee_free_selection_long_scan)
{
    uint32_t rows{0}, calls{0};
    BOOST_CHECK_EQUAL(drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::FEE_FREE_SELECTION,
        [&](uint32_t step) -> uint32_t {
            ++calls;
            switch (step) {
            case 1: case 2: return 1;
            case 3: return rows<100000;
            case 4: return 0;
            case 16: ++rows; return 1;
            default: throw std::runtime_error("rejected scan ran a later predicate");
            }
        }),1);
    BOOST_CHECK_EQUAL(rows,100000);
    BOOST_CHECK_EQUAL(calls,300003);
}

BOOST_AUTO_TEST_CASE(fee_free_selection_effect_order)
{
    const auto caller = std::this_thread::get_id();
    using Event = std::pair<uint32_t,size_t>;
    for (bool native : {false,true}) for (size_t size : {size_t{0},size_t{1},size_t{12}}) {
        const std::vector<uint32_t> rejected{0,4,5,6,7,8,9,11,12,13,0,0};
        const auto value = [&](uint32_t step,size_t index) {
            return step==10 ? index%2==1 : rejected.at(index)!=step;
        };
        std::vector<Event> expected{{1,0}};
        if (native) {
            expected.emplace_back(2,0);
            for (size_t i=0; i<size; ++i) {
                expected.emplace_back(3,i);
                const auto read = [&](uint32_t step) { expected.emplace_back(step,i); return value(step,i); };
                if (read(4) && read(5) && read(6) && read(7) && read(8) && read(9) &&
                    (!read(10) || read(11)) && read(12) && read(13)) {
                    expected.emplace_back(14,i);
                    expected.emplace_back(15,i);
                }
                expected.emplace_back(16,i);
            }
            expected.emplace_back(3,size);
        }
        for (size_t fault=0; fault<=expected.size(); ++fault) {
            size_t index{0};
            std::vector<Event> seen, effects;
            const auto run = [&] {
                return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::FEE_FREE_SELECTION,
                    [&](uint32_t step) -> uint32_t {
                        BOOST_CHECK(std::this_thread::get_id()==caller);
                        seen.emplace_back(step,index);
                        if (seen.size()==fault+1) throw std::runtime_error("fee-free fault");
                        if (step==1) return native;
                        if (step==2) { index=0; return 1; }
                        if (step==3) return index<size;
                        if (step>=14) {
                            effects.emplace_back(step,index);
                            if (step==16) ++index;
                            return 1;
                        }
                        BOOST_REQUIRE(index<size);
                        if (step==9 || step==13) BOOST_CHECK_EQUAL(drivechain::haskell::BmmSelectedBid(1,0),1);
                        return value(step,index);
                    });
            };
            if (fault==expected.size()) BOOST_CHECK_EQUAL(run(),1);
            else BOOST_CHECK_EXCEPTION(run(),std::runtime_error,
                [](const std::runtime_error& err) { return std::string{err.what()}=="fee-free fault"; });
            const std::vector<Event> prefix(expected.begin(),expected.begin()+std::min(fault+1,expected.size()));
            BOOST_CHECK(seen==prefix);
            std::vector<Event> published;
            for (size_t i=0; i<fault; ++i) if (expected[i].first>=14) published.push_back(expected[i]);
            BOOST_CHECK(effects==published);
        }
    }
}


BOOST_AUTO_TEST_CASE(template_selection_effect_order)
{
    const auto caller = std::this_thread::get_id();
    for (bool native : {false,true}) for (bool authenticated : {false,true}) {
        std::vector<uint32_t> expected{1,2};
        if (native) expected.insert(expected.end(),{3,authenticated ? 4U : 5U});
        for (size_t fault=0; fault<=expected.size(); ++fault) {
            std::vector<uint32_t> seen;
            std::optional<uint32_t> published{99}, staged;
            const auto run = [&] {
                return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::TEMPLATE_SELECTION,
                    [&](uint32_t step) -> uint32_t {
                        BOOST_CHECK(std::this_thread::get_id()==caller);
                        seen.push_back(step);
                        if (seen.size()==fault+1) throw std::runtime_error("selection fault");
                        switch (step) {
                        case 1: published.reset(); return 1;
                        case 2: return native;
                        case 3:
                            BOOST_CHECK_EQUAL(drivechain::haskell::BmmSelectedBid(1,0),1);
                            staged=42; return authenticated;
                        case 4: published=staged.value(); return 1;
                        case 5: return 1;
                        default: throw std::runtime_error("unexpected selection action");
                        }
                    });
            };
            if (fault==expected.size()) BOOST_CHECK_EQUAL(run(),!native || authenticated);
            else BOOST_CHECK_EXCEPTION(run(),std::runtime_error,
                [](const std::runtime_error& err) { return std::string{err.what()}=="selection fault"; });
            const std::vector<uint32_t> prefix(expected.begin(),expected.begin()+std::min(fault+1,expected.size()));
            BOOST_CHECK(seen==prefix);
            const std::optional<uint32_t> wanted = fault==0 ? std::optional<uint32_t>{99} :
                fault==expected.size() && native && authenticated ? std::optional<uint32_t>{42} : std::nullopt;
            BOOST_CHECK(published==wanted);
        }
    }
}


BOOST_AUTO_TEST_CASE(template_admission_effect_order)
{
    const auto caller = std::this_thread::get_id();
    for (uint32_t mask=0; mask<64; ++mask) {
        const auto value = [&](uint32_t step) -> uint32_t {
            if (step==4 || step==8) return 1;
            return (mask>>(step-(step>4 ? 2 : 1)))&1;
        };
        std::vector<uint32_t> expected;
        const auto read = [&](uint32_t step) { expected.push_back(step); return value(step); };
        const auto reference = [&]() -> uint32_t {
            if (read(1) && !read(2) && read(3)) { read(4); return 0; }
            if ((read(5) || read(6)) && !read(7)) { read(8); return 0; }
            return 1;
        };
        const auto wanted = reference();
        for (size_t fault=0; fault<=expected.size(); ++fault) {
            std::vector<uint32_t> seen;
            const auto run = [&] {
                return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::TEMPLATE_ADMISSION,
                    [&](uint32_t step) {
                        BOOST_CHECK(std::this_thread::get_id()==caller);
                        seen.push_back(step);
                        if (seen.size()==fault+1) throw std::runtime_error("template admission fault");
                        // The real validator also reenters Haskell-backed rules.
                        if (step==7) BOOST_CHECK_EQUAL(drivechain::haskell::BmmSelectedBid(1,0),1);
                        return value(step);
                    });
            };
            if (fault==expected.size()) BOOST_CHECK_EQUAL(run(),wanted);
            else BOOST_CHECK_EXCEPTION(run(),std::runtime_error,
                [](const std::runtime_error& err) { return std::string{err.what()}=="template admission fault"; });
            const std::vector<uint32_t> prefix(expected.begin(),expected.begin()+std::min(fault+1,expected.size()));
            BOOST_CHECK(seen==prefix);
        }
    }
}

BOOST_AUTO_TEST_CASE(template_parent_effect_order)
{
    const auto caller = std::this_thread::get_id();
    for (uint32_t mask=0; mask<512; ++mask) {
        const auto value = [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 6: case 10: case 12: case 13: return 1;
            case 7: step=4; break;
            case 8: step=6; break;
            case 9: step=7; break;
            case 11: step=8; break;
            }
            return (mask>>(step-1))&1;
        };
        std::vector<uint32_t> expected;
        const auto read = [&](uint32_t step) { expected.push_back(step); return value(step); };
        const auto reference = [&]() -> uint32_t {
            if (!read(1)) return 1;
            if (read(2)) {
                if (!read(3)) { read(12); return 0; }
                if (read(4) && !read(5)) { read(13); return 0; }
                read(6);
            } else if (!read(7)) {
                if (read(8) && read(9)) read(10);
            }
            if (!read(11)) { read(12); return 0; }
            return 1;
        };
        const auto wanted = reference();
        for (size_t fault=0; fault<=expected.size(); ++fault) {
            std::vector<uint32_t> seen;
            std::optional<uint32_t> published;
            const auto run = [&] {
                return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::TEMPLATE_PARENT,
                    [&](uint32_t step) {
                        BOOST_CHECK(std::this_thread::get_id()==caller);
                        seen.push_back(step);
                        if (seen.size()==fault+1) throw std::runtime_error("template fault");
                        if (step==6 || step==10) published=step;
                        return value(step);
                    });
            };
            if (fault==expected.size()) BOOST_CHECK_EQUAL(run(),wanted);
            else BOOST_CHECK_EXCEPTION(run(),std::runtime_error,
                [](const std::runtime_error& err) { return std::string{err.what()}=="template fault"; });
            const std::vector<uint32_t> prefix(expected.begin(),expected.begin()+std::min(fault+1,expected.size()));
            BOOST_CHECK(seen==prefix);
            std::optional<uint32_t> publication;
            for (size_t i=0; i<fault; ++i) if (expected[i]==6 || expected[i]==10) publication=expected[i];
            BOOST_CHECK(published==publication);
        }
    }
}

BOOST_AUTO_TEST_CASE(startup_argument_effect_order)
{
    const auto caller = std::this_thread::get_id();
    for (const uint32_t slot : {0U,24U,255U,256U}) {
        for (bool signet : {false,true}) {
            std::vector<uint32_t> expected{1,2,3,4,5};
            const std::vector<uint32_t> native{7,8,9,10,11,12,13,14,15,16,17};
            const std::vector<uint32_t> ordinary{18,19};
            const auto& network = slot<256 ? native : ordinary;
            expected.insert(expected.end(),network.begin(),network.end());
            if (signet) expected.insert(expected.end(),{20,21});
            expected.insert(expected.end(),{22,23,8,9,17,24});
            for (size_t fault=0; fault<=expected.size(); ++fault) {
                std::vector<uint32_t> seen;
                const auto run = [&] {
                    return drivechain::haskell::StartupArgs(slot,2,[&](uint32_t step) -> uint64_t {
                        BOOST_CHECK(std::this_thread::get_id()==caller);
                        seen.push_back(step);
                        if (seen.size()==fault+1) throw std::runtime_error("startup fault");
                        switch (step) {
                        case 5: return signet;
                        case 8: case 9: case 18: case 19: case 23: return 0;
                        case 10: return slot;
                        case 14: return MAX_MONEY;
                        case 15: return 2;
                        default: return 1;
                        }
                    });
                };
                if (fault==expected.size()) BOOST_CHECK(run());
                else BOOST_CHECK_EXCEPTION(run(),std::runtime_error,
                    [](const std::runtime_error& err) { return std::string{err.what()}=="startup fault"; });
                const std::vector<uint32_t> prefix(expected.begin(),expected.begin()+std::min(fault+1,expected.size()));
                BOOST_CHECK(seen==prefix);
            }
        }
    }
    BOOST_CHECK_THROW(drivechain::haskell::StartupArgs(257,2,[](uint32_t) -> uint64_t {
        BOOST_FAIL("invalid slot evaluated callback"); return 1;
    }),std::runtime_error);
}

BOOST_AUTO_TEST_CASE(ordinary_startup_parameter_precedence)
{
    BOOST_REQUIRE(!Params().GetConsensus().drivechain_slot);
    CheckStartupRejected({{"-drivechainrewardaddress","invalid"},{"-drivechainbmmslot","24"},{"-regtest","1"}},
        "-drivechainrewardaddress may only be used in an Elements parent-chain configuration");
    CheckStartupRejected({{"-drivechainbmmslot","24"},{"-drivechainbmmbid","invalid"}},
        "-drivechainbmmslot may only be used on a native drivechain network");
    CheckStartupRejected({{"-drivechainbmmbid","invalid"},{"-mainchainrpccredentialfile","missing-file"}},
        "-drivechainbmmbid may only be used on a native drivechain network");
    CheckStartupRejected({{"-mainchainrpccredentialfile","missing-file"},{"-mainchainrpccookiefile","missing-cookie"},
        {"-mainchainrpchost","localhost"}},
        "-mainchainrpccredentialfile is mutually exclusive with cookie and inline credential options");
    CheckStartupRejected({{"-mainchainrpccredentialfile","missing-file"},{"-mainchainrpchost","localhost"}},
        "Static parent RPC credential files require a numeric-loopback endpoint");
    const auto missing=fs::PathToString(m_path_root / "missing-blocks");
    CheckStartupRejected({{"-blocksdir",missing}},"Specified blocks directory \""+missing+"\" does not exist.");
}

// Pre-composition implementation retained only for trace/exception differential tests.
template <typename Rpc, typename Check, typename Wait>
UniValue OriginalFetchParentBlockBody(const std::string& hash, bool allow_recovery,
                             Rpc&& rpc, Check&& check, Wait&& wait)
{
    auto checked = [&](const std::string& method, const UniValue& params) -> UniValue {
        check();
        const auto reply = rpc(method, params);
        if (drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::RECOVERY_REPLY,[&](uint32_t step) {
            return step==1 ? reply["error"].isNull() : !reply["result"].isNull();
        }))
            throw std::runtime_error(method + " failed during parent block retrieval");
        return reply["result"];
    };
    UniValue block_params(UniValue::VARR);
    block_params.push_back(hash);
    block_params.push_back(0);
    auto active_height = [&]() {
        UniValue params(UniValue::VARR);
        params.push_back(hash);
        params.push_back(true);
        const UniValue header = checked("getblockheader", params);
        int height=0;
        UniValue active;
        drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::RECOVERY_HEADER,[&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return header["hash"].isStr();
            case 2: return header["hash"].get_str()==hash;
            case 3: return header["height"].isNum();
            case 4: return header["confirmations"].isNum();
            case 5: return header["height"].getInt<int>()>=0;
            case 6: return header["confirmations"].getInt<int>()>0;
            case 7: {
                height=header["height"].getInt<int>();
                UniValue height_params(UniValue::VARR);
                height_params.push_back(height); active=checked("getblockhash",height_params); return 1;
            }
            case 8: return active.isStr();
            case 9: return active.get_str()==hash;
            case 10: throw std::runtime_error("pruned parent block is not active");
            case 11: throw std::runtime_error("parent chain changed during block recovery");
            default: throw std::logic_error("invalid parent recovery header action");
            }
        });
        return height;
    };
    auto request_peer = [&] {
        const auto peers = checked("getpeerinfo", UniValue(UniValue::VARR));
        std::vector<UniValue>::const_iterator peer,service;
        drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::RECOVERY_PEER_REPLY,[&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return peer!=peers.getValues().end();
            case 2: return (*peer)["id"].isNum();
            case 3: return (*peer)["servicesnames"].isArray();
            case 4: service=(*peer)["servicesnames"].getValues().begin(); return 1;
            case 5: return service!=(*peer)["servicesnames"].getValues().end();
            case 6: return service->isStr();
            case 7: return service->get_str()=="NETWORK";
            case 8: ++service; return 1;
            case 9: ++peer; return 1;
            case 10: throw std::runtime_error("no parent peer offers full block service");
            case 11: {
                UniValue params(UniValue::VARR);
                params.push_back(hash); params.push_back((*peer)["id"]);
                checked("getblockfrompeer",params); return 1;
            }
            case 12: return peers.isArray();
            case 13: throw std::runtime_error("invalid parent peer response");
            case 14: peer=peers.getValues().begin(); return 1;
            default: throw std::logic_error("invalid parent recovery peer action");
            }
        });
    };
    UniValue reply;
    std::chrono::steady_clock::time_point deadline;
    int height=0;
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::RECOVERY_BODY,[&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: check(); reply=rpc("getblock",block_params); return 1;
        case 2: case 15: return drivechain::IsPrunedBlockReply(reply);
        case 3: case 17: return reply["error"].isNull();
        case 4: case 18: return !reply["result"].isNull();
        case 5: throw std::runtime_error("getblock failed: "+reply["error"].write());
        case 6: return allow_recovery;
        case 7: throw std::runtime_error("pruned parent block requires recovery outside consensus locks");
        case 8: deadline=std::chrono::steady_clock::now()+std::chrono::seconds{drivechain::PARENT_RECOVERY_SECONDS}; return 1;
        case 9: height=active_height(); return 1;
        case 10: request_peer(); return 1;
        case 11: check(); return 1;
        case 12: return std::chrono::steady_clock::now()>=deadline;
        case 13: throw std::runtime_error("parent block recovery timed out");
        case 14: reply=rpc("getblock",block_params); return 1;
        case 16: wait(); return 1;
        case 19: throw std::runtime_error("getblock failed during parent block recovery");
        case 20: return active_height()==height;
        case 21: throw std::runtime_error("parent block height changed during recovery");
        default: throw std::logic_error("invalid parent recovery body action");
        }
    });
    return reply["result"];
}

BOOST_AUTO_TEST_CASE(parent_pruned_body_recovery_preserves_active_chain_and_errors)
{
    auto json = [](const std::string& value) {
        UniValue result;
        if (!result.read(value)) throw std::runtime_error("invalid test JSON");
        return result;
    };
    const auto pruned = json(R"json({"error":{"code":-1,"message":"Block not available (pruned data)"},"result":null})json");
    const auto missing = json(R"({"error":{"code":-5,"message":"Block not found"},"result":null})");
    const auto body = json(R"({"error":null,"result":"00"})");
    const auto header = json(R"({"error":null,"result":{"hash":"requested","height":12,"confirmations":1}})");
    const auto active = json(R"({"error":null,"result":"requested"})");
    const auto peers = json(R"({"error":null,"result":[{"id":2,"servicesnames":["NETWORK_LIMITED"]},{"id":3,"servicesnames":["NETWORK"]}]})");
    const auto queued = json(R"({"error":null,"result":{}})");
    using Step = std::pair<std::string, UniValue>;
    const std::vector<Step> recovery{
        {"getblock", pruned}, {"getblockheader", header}, {"getblockhash", active},
        {"getpeerinfo", peers}, {"getblockfrompeer", queued}, {"getblock", pruned},
        {"getblock", body}, {"getblockheader", header}, {"getblockhash", active}};
    auto run = [&](std::vector<Step> steps, bool allow, bool succeeds, int waits_expected, const std::string& rejection="") {
        size_t index{0};
        int waits{0};
        auto rpc = [&](const std::string& method, const UniValue& params) {
            if (index >= steps.size()) throw std::runtime_error("unexpected extra RPC");
            BOOST_CHECK_EQUAL(method, steps[index].first);
            if (method == "getblock") BOOST_CHECK_EQUAL(params.write(), "[\"requested\",0]");
            if (method == "getblockfrompeer") BOOST_CHECK_EQUAL(params.write(), "[\"requested\",3]");
            return steps[index++].second;
        };
        auto fetch = [&] { return drivechain::FetchParentBlockBody(
            "requested", allow, rpc, [] {}, [&] { ++waits; }); };
        if (succeeds) {
            BOOST_CHECK_EQUAL(fetch().get_str(), "00");
        } else {
            BOOST_CHECK_EXCEPTION(fetch(), std::runtime_error,[&](const auto& error) {
                return rejection.empty() || error.what()==rejection;
            });
        }
        BOOST_CHECK_EQUAL(index, steps.size());
        BOOST_CHECK_EQUAL(waits, waits_expected);
    };
    run({{"getblock", body}}, false, true, 0);
    run({{"getblock", missing}}, true, false, 0);
    run({{"getblock", pruned}}, false, false, 0);
    run(recovery, true, true, 1);
    auto mixed_peers=recovery;
    mixed_peers[3].second=json(R"({"error":null,"result":[{"id":"bad","servicesnames":["NETWORK"]},{"id":2,"servicesnames":null},{"id":2,"servicesnames":[7,true,null,"network","NETWORK_LIMITED"]},{"id":3,"servicesnames":[{},false,"NETWORK","NETWORK"]},{"id":4,"servicesnames":["NETWORK"]}]})");
    run(mixed_peers,true,true,1);
    auto failed_request=std::vector<Step>(recovery.begin(),recovery.begin()+5);
    failed_request.back().second=missing;
    run(failed_request,true,false,0);
    auto empty_peers=std::vector<Step>(recovery.begin(),recovery.begin()+4);
    empty_peers.back().second=json(R"({"error":null,"result":[]})");
    run(empty_peers,true,false,0);
    for (const auto& wrong_peers : {"7","false","{}","\"NETWORK\""}) {
        auto invalid=std::vector<Step>(recovery.begin(),recovery.begin()+4);
        invalid.back().second=json(std::string{"{\"error\":null,\"result\":"}+wrong_peers+"}");
        run(invalid,true,false,0,"invalid parent peer response");
    }
    auto no_peer = std::vector<Step>(recovery.begin(), recovery.begin() + 4);
    no_peer.back().second = json(R"({"error":null,"result":[{"id":2,"servicesnames":["NETWORK_LIMITED"]}]})");
    run(no_peer, true, false, 0);
    auto reorg = recovery;
    reorg.back().second = json(R"({"error":null,"result":"other"})");
    run(reorg, true, false, 1);
    auto changed_height=recovery;
    changed_height[7].second=json(R"({"error":null,"result":{"hash":"requested","height":13,"confirmations":1}})");
    run(changed_height,true,false,1,"parent block height changed during recovery");
    const auto empty_result=json(R"({"error":null,"result":null})");
    for (size_t position : {1U,2U,3U,4U,7U,8U}) {
        for (const auto& bad_reply : {empty_result,missing}) {
            auto invalid=std::vector<Step>(recovery.begin(),recovery.begin()+position+1);
            invalid.back().second=bad_reply;
            run(invalid,true,false,position>=7 ? 1 : 0,
                invalid.back().first+" failed during parent block retrieval");
        }
    }
    for (const auto& wrong_active : {"7","false","[]","{}","\"other\""}) {
        auto invalid=std::vector<Step>(recovery.begin(),recovery.begin()+3);
        invalid.back().second=json(std::string{"{\"error\":null,\"result\":"}+wrong_active+"}");
        run(invalid,true,false,0,"parent chain changed during block recovery");
    }
    run({{"getblock",empty_result}},false,false,0,"getblock failed: null");
    auto empty_recovered=std::vector<Step>(recovery.begin(),recovery.begin()+6);
    empty_recovered.back().second=empty_result;
    run(empty_recovered,true,false,0,"getblock failed during parent block recovery");
    auto failed = std::vector<Step>(recovery.begin(), recovery.begin() + 6);
    failed.back().second = missing;
    run(failed, true, false, 0);
    for (const auto& invalid_header : {
             R"({"hash":7,"height":12,"confirmations":1})",
             R"({"hash":"requested","height":12,"confirmations":"1"})",
             R"({"hash":"requested","height":12,"confirmations":-1})",
             R"({})",
             R"({"hash":"other","height":12,"confirmations":1})",
             R"({"hash":"requested","height":12,"confirmations":0})",
             R"({"hash":"requested","height":-1,"confirmations":1})",
             R"({"hash":"requested","height":"12","confirmations":1})"}) {
        auto invalid = std::vector<Step>(recovery.begin(), recovery.begin() + 2);
        invalid.back().second = json(std::string{"{\"error\":null,\"result\":"} + invalid_header + "}");
        run(invalid, true, false, 0,"pruned parent block is not active");
    }
    int requests{0};
    int checks{0};
    auto cancelled_rpc = [&](const std::string&, const UniValue&) {
        ++requests;
        return pruned;
    };
    BOOST_CHECK_THROW(drivechain::FetchParentBlockBody(
        "requested", true, cancelled_rpc,
        [&] { if (++checks == 2) throw std::runtime_error("cancelled"); },
        [] {}), std::runtime_error);
    BOOST_CHECK_EQUAL(requests, 1);
    BOOST_CHECK(!drivechain::IsPrunedBlockReply(missing));
    BOOST_CHECK(drivechain::IsPrunedBlockReply(pruned));
    for (const auto& invalid_error : {"null","7","[]","{}",
             R"json({"code":"-1","message":"Block not available (pruned data)"})json",
             R"({"code":-1,"message":7})",
             R"({"code":-1,"message":"other"})"}) {
        BOOST_CHECK(!drivechain::IsPrunedBlockReply(json(std::string{"{\"error\":"}+invalid_error+"}")));
    }
    BOOST_CHECK_THROW(drivechain::IsPrunedBlockReply(json(
        R"({"error":{"code":2147483648,"message":null}})")),std::runtime_error);
}

BOOST_AUTO_TEST_CASE(parent_recovery_composition_matches_original_effects_and_exceptions)
{
    const auto json = [](const std::string& text) {
        UniValue result;
        if (!result.read(text)) throw std::runtime_error("invalid recovery fixture");
        return result;
    };
    const auto pruned = json(R"json({"error":{"code":-1,"message":"Block not available (pruned data)"},"result":null})json");
    const auto missing = json(R"({"error":{"code":-5,"message":"Block not found"},"result":null})");
    const auto body = json(R"({"error":null,"result":"00"})");
    const auto header = json(R"({"error":null,"result":{"hash":"requested","height":12,"confirmations":1}})");
    const auto active = json(R"({"error":null,"result":"requested"})");
    const auto peers = json(R"({"error":null,"result":[{"id":1,"servicesnames":["NETWORK_LIMITED"]},{"id":3,"servicesnames":[7,"NETWORK"]}]})");
    const auto queued = json(R"({"error":null,"result":{}})");
    struct Outcome {
        std::vector<std::string> trace;
        std::string value, error;
        int exception{0};
    };
    for (int scenario=0; scenario<15; ++scenario) {
        std::vector<UniValue> replies{pruned,header,active,peers,queued,pruned,body,header,active};
        switch (scenario) {
        case 0: replies={body}; break;
        case 2: replies={pruned}; break;
        case 3: replies={missing}; break;
        case 4: replies[1]=json(R"({"error":null,"result":{"hash":"requested","height":"12","confirmations":1}})"); break;
        case 5: replies[2]=json(R"({"error":null,"result":"other"})"); break;
        case 6: replies[3]=json(R"({"error":null,"result":[]})"); break;
        case 7: replies[4]=missing; break;
        case 8: replies[5]=missing; break;
        case 9: replies[7]=json(R"({"error":null,"result":{"hash":"requested","height":13,"confirmations":1}})"); break;
        case 10: replies[1]=json(R"({"error":null,"result":{"hash":"requested","height":2147483648,"confirmations":1}})"); break;
        case 11: replies[0]=json(R"({"error":{"code":2147483648,"message":null},"result":null})"); break;
        case 12: replies[1]=json(R"({"error":null,"result":{"hash":"other","height":12,"confirmations":1}})"); break;
        case 13: replies[3]=json(R"({"error":null,"result":false})"); break;
        case 14: replies[1]=json(R"({"error":null,"result":null})"); break;
        }
        const auto run = [&](bool migrated, int fault, bool nonstandard) {
            Outcome outcome;
            size_t request{0};
            const auto event = [&](std::string text) {
                const auto index=outcome.trace.size();
                outcome.trace.push_back(std::move(text));
                if (static_cast<int>(index)==fault) {
                    if (nonstandard) throw 73;
                    throw std::runtime_error("recovery callback fault");
                }
            };
            const auto rpc = [&](const std::string& method, const UniValue& params) {
                event(method+params.write());
                if (request>=replies.size()) throw std::logic_error("unexpected recovery request");
                return replies[request++];
            };
            const auto check = [&] { event("deadline"); };
            const auto wait = [&] { event("wait"); };
            try {
                const auto result = migrated ? drivechain::FetchParentBlockBody("requested",scenario!=2,rpc,check,wait)
                    : OriginalFetchParentBlockBody("requested",scenario!=2,rpc,check,wait);
                outcome.value=result.write();
            } catch (const std::exception& error) {
                outcome.exception=1; outcome.error=error.what();
            } catch (int code) {
                outcome.exception=code;
            }
            return outcome;
        };
        const auto complete = run(false,-1,false);
        BOOST_CHECK_EQUAL(complete.exception,scenario<=1 ? 0 : 1);
        for (int fault=-1; fault<=static_cast<int>(complete.trace.size()); ++fault) {
            for (bool nonstandard : {false,true}) {
                const auto expected=run(false,fault,nonstandard);
                const auto actual=run(true,fault,nonstandard);
                BOOST_CHECK(actual.trace==expected.trace);
                BOOST_CHECK_EQUAL(actual.value,expected.value);
                BOOST_CHECK_EQUAL(actual.exception,expected.exception);
                BOOST_CHECK_EQUAL(actual.error,expected.error);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(inspect_preserved_alpha_replay_copy)
{
    // Diagnostic fixture only. Never point this at a live or preserved original
    // database: LevelDB opening can recover/write metadata even without writes.
    const char* path = std::getenv("ECX_REPLAY_INSPECTION_COPY");
    if (!path) {
        BOOST_TEST_MESSAGE("No isolated replay copy supplied; inspection not performed");
        return;
    }
    const fs::path copy{path};
    BOOST_REQUIRE(copy.filename() == "replay-copy");
    const char* credential_file = std::getenv("ECX_REPLAY_INSPECTION_CREDENTIAL_FILE");
    BOOST_REQUIRE_MESSAGE(credential_file && *credential_file,
        "Explicit local parent RPC credentials required for replay inspection");
    std::pair<uint32_t, uint256> identity;
    {
        CDBWrapper db(DBParams{.path = copy, .cache_bytes = 1 << 20,
            .memory_only = false, .wipe_data = false, .obfuscate = false});
        BOOST_REQUIRE(db.Read(uint8_t{'I'}, identity));
    }
    BOOST_REQUIRE_EQUAL(identity.first, DrivechainParentReplayStore::SCHEMA_VERSION);
    // Independently serialize the selected Alpha parameters, not the DB identity.
    const auto alpha = CreateChainParams(ArgsManager{}, CBaseChainParams::ELEMENTS);
    const auto& consensus = alpha->GetConsensus();
    HashWriter writer;
    writer << std::string{"ELEMENTS_AUTHENTICATED_PARENT_REPLAY_STORE_V4"}
           << std::string{ElementsDrivechainIdentity::BIP300301_ENFORCER_REVISION}
           << std::string{ElementsDrivechainIdentity::BIP300301_LOCAL_RULE_DOMAIN}
           << std::string{ElementsDrivechainIdentity::BIP300301_LOCAL_RULE_ID}
           << alpha->HashGenesisBlock()
           << alpha->ParentGenesisBlockHash()
           << consensus.parentChainPowLimit
           << consensus.parent_signet_challenge
           << consensus.pegin_min_depth
           << *consensus.drivechain_slot
           << consensus.drivechain_protocol_manifest_hash
           << consensus.drivechain_proposal_description
           << *consensus.drivechain_proposal_hash
           << consensus.drivechain_parent_state_active_proposal_description
           << consensus.drivechain_parent_state_active_proposal_hash.value_or(uint256{})
           << consensus.drivechain_parent_state_proposal_height
           << consensus.drivechain_parent_state_proposal_block_hash
           << consensus.drivechain_parent_state_activation_height
           << consensus.drivechain_parent_state_activation_block_hash
           << consensus.drivechain_parent_state_height
           << consensus.drivechain_parent_state_hash
           << consensus.drivechain_parent_state_chainwork
           << consensus.drivechain_parent_state_ctip_txid
           << consensus.drivechain_parent_state_ctip_vout
           << consensus.drivechain_parent_state_ctip_value
           << uint256S(ElementsDrivechainIdentity::PARENT_CHECKPOINT_BOOTSTRAP_STATE_COMMITMENT)
           << consensus.drivechain_unused_slot_proposal_max_age
           << consensus.drivechain_unused_slot_activation_threshold
           << consensus.drivechain_used_slot_proposal_max_age
           << consensus.drivechain_used_slot_activation_threshold
           << consensus.drivechain_withdrawal_bundle_max_age
           << consensus.drivechain_withdrawal_bundle_inclusion_threshold
           << consensus.drivechain_m6_withdrawal_validation
           << consensus.drivechain_parent_state_replay_version;
    const uint256 expected_identity = writer.GetHash();
    BOOST_TEST_MESSAGE("SELECTED_ALPHA identity=" << expected_identity.GetHex()
        << " genesis=" << alpha->HashGenesisBlock().GetHex());
    BOOST_REQUIRE_EQUAL(identity.second.GetHex(), expected_identity.GetHex());
    DrivechainParentReplayStore store(copy, 1 << 20, false);
    DrivechainParentReplayTip tip;
    std::string error;
    BOOST_REQUIRE_MESSAGE(store.Load(identity.second, tip, &error) ==
        DrivechainReplayStoreLoadStatus::LOADED, error);
    BOOST_TEST_MESSAGE("STRUCTURAL_ONLY identity=" << identity.second.GetHex()
        << " height=" << tip.height << " hash=" << tip.hash.GetHex()
        << " activated=" << tip.state.required_proposal_activated
        << " activation_height=" << tip.state.required_activation_height);
    // Loading with a substituted identity must not accept the same database.
    uint256 wrong = identity.second;
    wrong.begin()[0] ^= 1;
    BOOST_CHECK(store.Load(wrong, tip, &error) ==
        DrivechainReplayStoreLoadStatus::IDENTITY_MISMATCH);
    // Matching configuration identity does not authenticate the active parent tip.
}

BOOST_AUTO_TEST_CASE(drivechain_parent_checkpoint_ctip_tuple)
{
    const uint256 null_txid;
    const uint256 populated_txid = uint256S(
        "0100000000000000000000000000000000000000000000000000000000000000");
    const uint32_t absent_vout = std::numeric_limits<uint32_t>::max();

    struct Vector {
        uint256 txid;
        uint32_t vout;
        CAmount value;
        bool valid;
    };
    const std::array<Vector, 11> vectors{{
        {null_txid, absent_vout, 0, true},
        {populated_txid, 0, 1, true},
        {populated_txid, 7, MAX_MONEY, true},
        {null_txid, 0, 0, false},
        {null_txid, absent_vout, 1, false},
        {null_txid, 0, 1, false},
        {populated_txid, absent_vout, 0, false},
        {populated_txid, absent_vout, 1, false},
        {populated_txid, 0, 0, false},
        {populated_txid, 0, -1, false},
        {populated_txid, 0, MAX_MONEY + 1, false},
    }};

    for (const auto& vector : vectors) {
        BOOST_CHECK_EQUAL(IsCanonicalDrivechainParentCheckpointCtip(
            vector.txid, vector.vout, vector.value), vector.valid);
    }
    for (const auto& txid : {null_txid, populated_txid})
    for (uint32_t vout : {0U, 1U, 0xfffffffeU, 0xffffffffU})
    for (CAmount value : std::array<CAmount,8>{std::numeric_limits<CAmount>::min(), -1, 0, 1, MAX_MONEY - 1,
        MAX_MONEY, MAX_MONEY + 1, std::numeric_limits<CAmount>::max()}) {
        const bool empty = txid.IsNull() && vout == absent_vout && value == 0;
        const bool populated = !txid.IsNull() && vout != absent_vout && value > 0 && MoneyRange(value);
        BOOST_CHECK_EQUAL(IsCanonicalDrivechainParentCheckpointCtip(txid, vout, value), empty || populated);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_parent_checkpoint_identity_state)
{
    const uint256 null_hash;
    const uint256 proposal_block = uint256S(
        "0200000000000000000000000000000000000000000000000000000000000000");
    const uint256 activation_block = uint256S(
        "0300000000000000000000000000000000000000000000000000000000000000");
    const uint256 ctip_txid = uint256S(
        "0400000000000000000000000000000000000000000000000000000000000000");
    const std::vector<unsigned char> description{0x01, 0x02, 0x03};
    const std::optional<uint256> description_hash{Hash(description)};
    const uint32_t absent_vout = std::numeric_limits<uint32_t>::max();

    struct Vector {
        std::vector<unsigned char> description;
        std::optional<uint256> proposal_hash;
        uint32_t proposal_height;
        uint256 proposal_block;
        uint32_t activation_height;
        uint256 activation_block;
        uint32_t checkpoint_height;
        uint256 ctip_txid;
        uint32_t ctip_vout;
        CAmount ctip_value;
        bool expected;
    };
    const std::array<Vector, 12> vectors{{
        {{}, std::nullopt, 0, null_hash, 0, null_hash, 1, null_hash, absent_vout, 0,
         true},
        {{}, std::optional<uint256>{null_hash}, 0, null_hash, 0, null_hash, 1, null_hash, absent_vout, 0,
         true},
        {description, description_hash, 1, proposal_block, 2, activation_block, 2, null_hash, absent_vout, 0,
         true},
        {description, description_hash, 1, proposal_block, 2, activation_block, 3, ctip_txid, 0, 1,
         true},
        {description, std::nullopt, 1, proposal_block, 2, activation_block, 3, null_hash, absent_vout, 0,
         false},
        {{}, description_hash, 0, null_hash, 0, null_hash, 1, null_hash, absent_vout, 0,
         false},
        {{}, std::nullopt, 1, null_hash, 0, null_hash, 1, null_hash, absent_vout, 0,
         false},
        {{}, std::nullopt, 0, proposal_block, 0, null_hash, 1, null_hash, absent_vout, 0,
         false},
        {description, description_hash, 2, proposal_block, 2, activation_block, 3, null_hash, absent_vout, 0,
         false},
        {description, description_hash, 1, proposal_block, 4, activation_block, 3, null_hash, absent_vout, 0,
         false},
        {description, std::optional<uint256>{uint256S("0500000000000000000000000000000000000000000000000000000000000000")},
         1, proposal_block, 2, activation_block, 3, null_hash, absent_vout, 0,
         false},
        {{}, std::nullopt, 0, null_hash, 0, null_hash, 1, ctip_txid, 0, 1,
         false},
    }};

    for (const auto& vector : vectors) {
        BOOST_CHECK_EQUAL(IsCanonicalDrivechainParentCheckpointIdentity(
            vector.description, vector.proposal_hash, vector.proposal_height,
            vector.proposal_block, vector.activation_height, vector.activation_block,
            vector.checkpoint_height, vector.ctip_txid, vector.ctip_vout,
            vector.ctip_value), vector.expected);
    }
}

static void TestBlockSubsidyHalvings(const Consensus::Params& consensusParams)
{
    int maxHalvings = 64;
    CAmount nInitialSubsidy = 50 * COIN;

    CAmount nPreviousSubsidy = nInitialSubsidy * 2; // for height == 0
    BOOST_CHECK_EQUAL(nPreviousSubsidy, nInitialSubsidy * 2);
    for (int nHalvings = 0; nHalvings < maxHalvings; nHalvings++) {
        int nHeight = nHalvings * consensusParams.nSubsidyHalvingInterval;
        CAmount nSubsidy = GetBlockSubsidy(nHeight, consensusParams);
        BOOST_CHECK(nSubsidy <= nInitialSubsidy);
        BOOST_CHECK_EQUAL(nSubsidy, nPreviousSubsidy / 2);
        nPreviousSubsidy = nSubsidy;
    }
    BOOST_CHECK_EQUAL(GetBlockSubsidy(maxHalvings * consensusParams.nSubsidyHalvingInterval, consensusParams), 0);
}

static void TestBlockSubsidyHalvings(int nSubsidyHalvingInterval)
{
    Consensus::Params consensusParams;
    consensusParams.nSubsidyHalvingInterval = nSubsidyHalvingInterval;
    consensusParams.genesis_subsidy = 50*COIN;
    TestBlockSubsidyHalvings(consensusParams);
}

BOOST_AUTO_TEST_CASE(block_subsidy_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    TestBlockSubsidyHalvings(chainParams->GetConsensus()); // As in main
    TestBlockSubsidyHalvings(150); // As in regtest
    TestBlockSubsidyHalvings(1000); // Just another interval
}

BOOST_AUTO_TEST_CASE(subsidy_limit_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    CAmount nSum = 0;
    for (int nHeight = 0; nHeight < 14000000; nHeight += 1000) {
        CAmount nSubsidy = GetBlockSubsidy(nHeight, chainParams->GetConsensus());
        BOOST_CHECK(nSubsidy <= 50 * COIN);
        nSum += nSubsidy * 1000;
        BOOST_CHECK(MoneyRange(nSum));
    }
    BOOST_CHECK_EQUAL(nSum, CAmount{2099999997690000});
}










BOOST_AUTO_TEST_CASE(canonical_m7_admission_and_output_reset)
{
    const auto expected = uint256S("0123");
    auto payload = ParseHex("d161736818" + expected.GetHex());
    for (unsigned push : {0, 1, 2, 4}) {
        CScript commitment;
        commitment << OP_RETURN;
        if (push == 0) commitment << payload;
        else {
            commitment << (push == 1 ? OP_PUSHDATA1 : push == 2 ? OP_PUSHDATA2 : OP_PUSHDATA4);
            for (unsigned byte = 0; byte < push; ++byte) commitment.push_back((payload.size() >> (8 * byte)) & 0xff);
            commitment.insert(commitment.end(), payload.begin(), payload.end());
        }
        for (int slot : {-1, 24, 256}) for (unsigned shape = 0; shape < 4; ++shape)
            for (unsigned matches = 0; matches < 3; ++matches) {
            Bitcoin::CBlock block;
            if (shape == 1) block.vtx.emplace_back();
            if (shape >= 2) {
                Bitcoin::CMutableTransaction tx;
                if (shape == 3) tx.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0, 0);
                tx.vout.emplace_back(0, CScript() << OP_RETURN << std::vector<unsigned char>{1});
                auto wrong_tag = payload;
                wrong_tag[0] ^= 1;
                tx.vout.emplace_back(0, CScript() << OP_RETURN << wrong_tag);
                auto wrong_slot = payload;
                wrong_slot[4] = 25;
                tx.vout.emplace_back(0, CScript() << OP_RETURN << wrong_slot);
                for (unsigned i = 0; i < matches; ++i) tx.vout.emplace_back(0, commitment);
                block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(tx)));
            }
            uint256 hash = uint256S("ff");
            uint32_t index = 99;
            std::string error;
            const bool valid = ExtractCanonicalDrivechainBmmCommitmentInBlock(block, slot, hash, &index, &error);
            const bool accepted = slot == 24 && shape == 3 && matches == 1;
            BOOST_CHECK_EQUAL(valid, accepted);
            BOOST_CHECK(hash == (accepted ? expected : uint256{}));
            BOOST_CHECK_EQUAL(index, accepted ? 3U : 0U);
            uint256 optional_hash = uint256S("ff");
            BOOST_CHECK_EQUAL(ExtractCanonicalDrivechainBmmCommitmentInBlock(block, slot, optional_hash, nullptr, nullptr), accepted);
            BOOST_CHECK(optional_hash == (accepted ? expected : uint256{}));
            if (slot != 24) BOOST_CHECK_EQUAL(error, "BIP301 M7 sidechain slot is outside the uint8 range");
            else if (shape != 3) BOOST_CHECK_EQUAL(error, "raw BMM block has no coinbase transaction");
            else if (matches == 0) BOOST_CHECK_EQUAL(error, "BMM successor has no enforcer-recognized M7 for sidechain slot 24");
            else if (matches == 2) BOOST_CHECK_EQUAL(error, "BMM successor has 2 enforcer-recognized M7 outputs for sidechain slot 24");
            else BOOST_CHECK(error.empty());
            for (bool same_hash : {false, true}) {
                const auto requested = same_hash ? expected : uint256S("ff");
                std::string match_error;
                uint32_t match_index = 99;
                BOOST_CHECK_EQUAL(MatchDrivechainBmmCommitmentInBlock(block, slot, requested, &match_index, &match_error), accepted && same_hash);
                BOOST_CHECK_EQUAL(match_index, accepted ? 3U : 0U);
                BOOST_CHECK_EQUAL(match_error, !accepted ? error : same_hash ? std::string{} :
                    "BMM successor commits to critical hash " + expected.GetHex() + ", expected " + requested.GetHex());
            }
        }
    }
}





BOOST_AUTO_TEST_CASE(drivechain_native_deposit_block_cap)
{
    Consensus::Params consensus = Params().GetConsensus();
    consensus.drivechain_slot = 24;
    consensus.signet_blocks = false;

    const auto make_block = [](const unsigned int deposit_count) {
        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        coinbase.vin[0].prevout.SetNull();
        coinbase.vin[0].scriptSig = CScript() << OP_0 << OP_0;
        coinbase.vout.emplace_back(CAsset(uint256::ONE), 0,
                                   CScript() << OP_TRUE);

        CMutableTransaction deposits;
        deposits.vout.emplace_back(CAsset(uint256::ONE), 0,
                                   CScript() << OP_TRUE);
        for (unsigned int i = 0; i < deposit_count; ++i) {
            CTxIn input(COutPoint(Txid::FromUint256(uint256::ONE), i));
            input.m_is_pegin = true;
            deposits.vin.push_back(std::move(input));
        }

        CBlock block;
        block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));
        block.vtx.push_back(MakeTransactionRef(std::move(deposits)));
        return block;
    };

    BlockValidationState at_cap_state;
    const CBlock at_cap = make_block(MAX_DRIVECHAIN_DEPOSITS_PER_BLOCK);
    BOOST_CHECK(CheckBlock(at_cap, at_cap_state, consensus,
                           /*fCheckPOW=*/false,
                           /*fCheckMerkleRoot=*/false));

    BlockValidationState above_cap_state;
    const CBlock above_cap =
        make_block(MAX_DRIVECHAIN_DEPOSITS_PER_BLOCK + 1);
    BOOST_CHECK(!CheckBlock(above_cap, above_cap_state, consensus,
                            /*fCheckPOW=*/false,
                            /*fCheckMerkleRoot=*/false));
    BOOST_CHECK_EQUAL(above_cap_state.GetRejectReason(),
                      "bad-drivechain-deposit-count");

    // Count across transaction boundaries, without relying on witness parsing.
    CBlock split = above_cap;
    CMutableTransaction first{*split.vtx.back()}, second{first};
    first.vin.resize(32);
    second.vin.erase(second.vin.begin(),second.vin.begin()+32);
    split.vtx.back() = MakeTransactionRef(std::move(first));
    split.vtx.push_back(MakeTransactionRef(std::move(second)));
    BlockValidationState split_state;
    BOOST_CHECK(!CheckBlock(split,split_state,consensus,false,false));
    BOOST_CHECK_EQUAL(split_state.GetRejectReason(),"bad-drivechain-deposit-count");
    consensus.drivechain_slot.reset();
    BlockValidationState ordinary_state;
    BOOST_CHECK(CheckBlock(split,ordinary_state,consensus,false,false));

    unsigned reads{0};
    const auto reader = [&](uint32_t step,uint64_t,uint64_t) -> uint64_t {
        ++reads;
        return step == 0 ? 100 : 1;
    };
    BOOST_CHECK(!drivechain::haskell::DepositInputLimit(true,10,64,reader));
    BOOST_CHECK_EQUAL(reads,66U); // One length plus the first 65 pegin flags.
    reads = 0;
    BOOST_CHECK(drivechain::haskell::DepositInputLimit(false,10,0,reader));
    BOOST_CHECK_EQUAL(reads,0U);
    BOOST_CHECK_THROW(drivechain::haskell::DepositInputLimit(true,1,1,
        [](uint32_t,uint64_t,uint64_t) -> uint64_t { throw std::logic_error("read failed"); }),std::logic_error);
}







BOOST_AUTO_TEST_CASE(explicit_m4_publication_preserves_state)
{
    namespace hs = drivechain::haskell;
    for (size_t count = 0; count <= 3; ++count) {
        for (uint16_t initial : {0, 1, 49, 50, 65535}) {
            for (uint16_t vote : {0, 1, 2, 65534, 65535}) {
                std::vector<unsigned char> hashes(32 * count);
                for (size_t i = 0; i < count; ++i) hashes[32 * i] = i + 1;
                std::vector<uint16_t> persisted(count, initial), expected = persisted, staged;
                const int result = hs::ReplayExplicit(vote, hashes, expected);
                std::vector<uint32_t> trace;
                unsigned published{0};
                bool error{false};
                const bool accepted = hs::ParentReplayStore(hs::ReplayStoreFlow::EXPLICIT_VOTE,
                    [&](uint32_t step) -> uint32_t {
                        trace.push_back(step);
                        switch (step) {
                        case 1: return vote == 65535;
                        case 2: staged = persisted; return hs::ReplayExplicit(vote, hashes, staged);
                        case 3:
                        case 4: persisted = staged; published = step - 2; return 1;
                        case 5: error = true; return 0;
                        default: BOOST_FAIL("unexpected explicit vote action"); return 0;
                        }
                    });
                std::vector<uint32_t> expected_trace{1};
                if (vote != 65535) {
                    expected_trace.push_back(2);
                    if (result != 0) expected_trace.push_back(result + 2);
                }
                BOOST_CHECK_EQUAL(accepted, result != 3);
                BOOST_CHECK_EQUAL(error, result == 3);
                BOOST_CHECK_EQUAL(published, result == 1 || result == 2 ? result : 0);
                BOOST_CHECK(persisted == expected);
                BOOST_CHECK(trace == expected_trace);
            }
        }
    }
}


BOOST_AUTO_TEST_CASE(full_block_admission_preserves_native_effect_order)
{
    namespace hs = drivechain::haskell;
    const std::array flows{hs::ReplayStoreFlow::FULL_BLOCK_PREFLIGHT,
        hs::ReplayStoreFlow::BLOCK_ANCHOR_ADMISSION,hs::ReplayStoreFlow::BLOCK_ANCHOR_PUBLICATION};
    const std::array<unsigned,3> bounds{22,31,11};
    const std::array<std::vector<uint32_t>,3> effects{{{6,8,12,14,16,20,22},
        {4,6,7,8,10,12,14,17,21,25,26,30,31},{2,6,11}}};
    for (unsigned flow = 0; flow < flows.size(); ++flow)
    for (uint32_t base : {0U,UINT32_MAX,UINT32_MAX ^ 4U})
    for (unsigned flip = 0; flip <= bounds[flow]; ++flip)
    for (size_t fault = 0; fault <= bounds[flow] + 1; ++fault) {
        const uint32_t mask = base ^ (flip ? 1U << (flip - 1) : 0);
        std::array<std::vector<uint32_t>,2> traces;
        std::array<uint32_t,2> results{};
        std::array<bool,2> threw{};
        for (unsigned migrated = 0; migrated < 2; ++migrated) {
            const auto action = [&](uint32_t step) -> uint32_t {
                traces[migrated].push_back(step);
                if (fault && traces[migrated].size() == fault) throw std::runtime_error("admission callback failed");
                if (std::find(effects[flow].begin(),effects[flow].end(),step) != effects[flow].end())
                    return flow != 0 || step == 22;
                return (mask >> (step - 1)) & 1U;
            };
            try {
                const auto original = [&]() -> uint32_t {
                    if (flow == 0) {
                        if (!action(1) || !action(2) || !action(3)) return 0;
                        if (!action(4)) return 1;
                        if (!action(5)) { action(6); return 2; }
                        if (!action(7)) { action(8); return 2; }
                        if (!action(9) || !action(10)) return 2;
                        if (!action(11)) { action(12); return 2; }
                        if (!action(13)) { action(14); return 2; }
                        if (!action(15)) { action(16); return 2; }
                        if (action(17) && (!action(18) || !action(19))) { action(20); return 2; }
                        if (!action(21)) return 2;
                        action(22);
                        return 0;
                    }
                    if (flow == 1) {
                        const auto reject = [&] { action(31); return 0U; };
                        if (action(1) && action(2)) {
                            if (action(3)) action(4);
                            else {
                                if (!action(5)) { action(6); return reject(); }
                                action(7);
                            }
                            action(8);
                            if (!action(9)) {
                                action(10);
                                if (action(11)) action(12);
                                return reject();
                            }
                            if (!action(13)) { action(14); return reject(); }
                            if (action(15) && !action(16)) { action(17); return reject(); }
                            if (action(18) && action(19) && !action(20)) { action(21); return reject(); }
                            if (action(22) && action(23) && !action(24)) { action(25); return reject(); }
                            action(26);
                        }
                        if (action(27) && !action(28)) {
                            if (action(29)) action(30);
                            return reject();
                        }
                        return 1;
                    }
                    if (action(1)) {
                        action(2);
                        if (action(3) && action(4) && action(5)) action(6);
                    }
                    if (action(7) && action(8) && (!action(9) || action(10))) action(11);
                    return 1;
                };
                results[migrated] = migrated ? hs::ParentReplayStore(flows[flow],action) : original();
            } catch (const std::runtime_error& error) {
                BOOST_CHECK_EQUAL(error.what(),"admission callback failed");
                threw[migrated] = true;
            }
        }
        BOOST_CHECK(traces[0] == traces[1]);
        BOOST_CHECK_EQUAL(results[0],results[1]);
        BOOST_CHECK_EQUAL(threw[0],threw[1]);
    }
}

BOOST_FIXTURE_TEST_CASE(full_block_preflight_rejection_does_not_mutate_index, RegTestingSetup)
{
    auto& chainman = *m_node.chainman;
    LOCK(cs_main);
    auto& consensus = const_cast<Consensus::Params&>(chainman.GetConsensus());
    CBlockIndex* tip = chainman.ActiveTip();
    BOOST_REQUIRE(tip);
    struct Restore {
        Consensus::Params& consensus;
        std::optional<uint8_t> slot;
        CBlockIndex* tip;
        uint32_t status;
        ~Restore() { consensus.drivechain_slot = slot; tip->nStatus = status; }
    } restore{consensus,consensus.drivechain_slot,tip,tip->nStatus};
    consensus.drivechain_slot = 24;
    const auto count = chainman.m_blockman.m_block_index.size();
    const auto anchor = tip->m_drivechain_anchor;
    const auto coins = chainman.ActiveChainstate().CoinsTip().GetBestBlock();
    for (unsigned scenario = 0; scenario < 4; ++scenario) {
        auto block = std::make_shared<CBlock>();
        block->nVersion = 4;
        block->hashPrevBlock = scenario == 1 ? uint256::ONE : tip->GetBlockHash();
        block->nBits = tip->nBits;
        block->nTime = tip->nTime + 1;
        while (block->nNonce < 10000 && !CheckProofOfWork(block->GetHash(),block->nBits,consensus)) ++block->nNonce;
        BOOST_REQUIRE(CheckProofOfWork(block->GetHash(),block->nBits,consensus));
        tip->nStatus = restore.status | (scenario == 2 ? BLOCK_FAILED_VALID : 0);
        CBlockIndex* output = tip;
        BlockValidationState state;
        bool new_block{true};
        DrivechainBlockAdmissionInfo info;
        info.bmm_status = DrivechainBmmStatus::VALID;
        info.parent_hash = uint256::ONE;
        info.successor_hash = uint256::ONE;
        BOOST_CHECK_EQUAL(chainman.AcceptBlock(block,state,&output,scenario != 0,nullptr,&new_block,true,&info),scenario == 0);
        BOOST_CHECK(!new_block);
        BOOST_CHECK(!info.bmm_status && info.parent_hash.IsNull() && info.successor_hash.IsNull());
        BOOST_CHECK(output == tip);
        if (scenario == 0) BOOST_CHECK(state.IsValid());
        else if (scenario == 2) BOOST_CHECK(state.IsError());
        else {
            BOOST_CHECK(state.IsInvalid());
            BOOST_CHECK_EQUAL(state.GetRejectReason(),scenario == 1 ? "prev-blk-not-found" : "bad-blk-length");
        }
        BOOST_CHECK_EQUAL(chainman.m_blockman.m_block_index.size(),count);
        BOOST_CHECK_EQUAL(tip->nStatus,restore.status | (scenario == 2 ? BLOCK_FAILED_VALID : 0));
        BOOST_CHECK(!chainman.m_blockman.LookupBlockIndex(block->GetHash()));
        BOOST_CHECK(tip->m_drivechain_anchor == anchor);
        BOOST_CHECK(chainman.ActiveChainstate().CoinsTip().GetBestBlock() == coins);
        BOOST_CHECK(chainman.ActiveTip() == tip);
    }
}

BOOST_AUTO_TEST_CASE(startup_and_sweep_preserve_lazy_native_callbacks)
{
    namespace hs = drivechain::haskell;
    for (bool host : {false,true}) for (unsigned mask = 0; mask < 64; ++mask)
    for (size_t fault = 0; fault <= 7; ++fault) {
        std::array<std::vector<uint32_t>,2> traces;
        std::array<uint32_t,2> results{};
        std::array<bool,2> threw{};
        for (unsigned migrated = 0; migrated < 2; ++migrated) {
            const auto action = [&](uint32_t step) -> uint32_t {
                traces[migrated].push_back(step);
                if (fault && traces[migrated].size() == fault) throw std::runtime_error("preflight read failed");
                if (!host && (step == 4 || step == 6)) return step == 6;
                return (mask >> (step - 1)) & 1U;
            };
            try {
                if (migrated) {
                    results[migrated] = hs::ParentReplayStore(host ? hs::ReplayStoreFlow::PARENT_RPC_HOST :
                        hs::ReplayStoreFlow::MEMPOOL_SWEEP_PREFLIGHT, action);
                } else {
                    const auto original = [&]() -> uint32_t {
                        if (!action(1)) return 1;
                        if (host) {
                            if (!action(2)) return 0;
                            if (action(3)) return action(4);
                            return action(5) ? action(6) : 0;
                        }
                        if (!action(2) || !action(3)) return action(4);
                        if (!action(5)) return action(6);
                        return 2;
                    };
                    results[migrated] = original();
                }
            } catch (const std::runtime_error& error) {
                BOOST_CHECK_EQUAL(error.what(),"preflight read failed");
                threw[migrated] = true;
            }
        }
        BOOST_CHECK(traces[0] == traces[1]);
        BOOST_CHECK_EQUAL(results[0],results[1]);
        BOOST_CHECK_EQUAL(threw[0],threw[1]);
    }
}

BOOST_AUTO_TEST_CASE(production_startup_reuses_network_admission)
{
    namespace hs = drivechain::haskell;
    for (const std::string& name : {std::string{}, std::string{"elements"}, std::string{"Elements"},
        std::string{"signet"}, std::string{"elements\0",9}}) {
        BOOST_CHECK_EQUAL(hs::NetworkSelectionStatus(hs::NetworkSelection::PRODUCTION,name),name == "elements" ? 0U : 1U);
    }
    BOOST_CHECK_THROW(hs::NetworkSelectionStatus(static_cast<hs::NetworkSelection>(3),"elements"),std::runtime_error);
    BOOST_CHECK_THROW(hs::NetworkSelectionStatus(hs::NetworkSelection::PRODUCTION,"elements",true),std::runtime_error);
    BOOST_CHECK_EXCEPTION(hs::ValidateNetworkSelection(hs::NetworkSelection::PRODUCTION,"signet"),
        std::runtime_error, [](const auto& error) {
            return std::string{error.what()} == "This program only supports the canonical -chain=elements production network";
        });

    std::string identity_error;
    BOOST_REQUIRE(!IsCanonicalElementsProductionIdentity(Params(),BaseParams(),&identity_error));
    std::vector<std::string> errors;
    boost::signals2::scoped_connection capture{uiInterface.ThreadSafeMessageBox_connect(
        [&](const bilingual_str& message,const std::string&,unsigned int) {
            errors.push_back(message.original);
            return false;
        })};
    std::atomic<int> status{0};
    for (const std::string chain : {"regtest","elements"}) {
        ArgsManager args;
        args.ForceSetArg("-chain",chain);
        BOOST_CHECK(!AppInitBasicSetup(args,status));
    }
    const std::vector<std::string> expected{
        "This binary only supports the built-in -chain=elements production mainnet identity",
        "Refusing to start with a noncanonical Elements production identity: " + identity_error};
    BOOST_CHECK(errors == expected);
}

BOOST_AUTO_TEST_CASE(drivechain_parent_rpc_host_is_loopback_only)
{
    for (uint32_t octet = 0; octet < 256; ++octet) {
        BOOST_CHECK_EQUAL(drivechain::haskell::ParentRpcAddress(4, (octet << 24) | 0x123456), octet == 127);
    }
    std::array<unsigned char,16> address{};
    address.back() = 1;
    BOOST_CHECK(drivechain::haskell::ParentRpcAddress(6, 0, address));
    for (size_t index = 0; index < address.size(); ++index) {
        address[index] ^= 2;
        BOOST_CHECK(!drivechain::haskell::ParentRpcAddress(6, 0, address));
        address[index] ^= 2;
    }
    BOOST_CHECK_THROW(drivechain::haskell::ParentRpcAddress(0, 0), std::runtime_error);
    BOOST_CHECK_THROW(drivechain::haskell::ParentRpcAddress(6, 0), std::runtime_error);
    BOOST_CHECK(IsMainchainRPCHostAllowed("127.0.0.1", true));
    BOOST_CHECK(IsMainchainRPCHostAllowed("127.255.255.254", true));
    BOOST_CHECK(IsMainchainRPCHostAllowed("::1", true));
    BOOST_CHECK(!IsMainchainRPCHostAllowed("0.0.0.0", true));
    BOOST_CHECK(!IsMainchainRPCHostAllowed("192.168.10.25", true));
    BOOST_CHECK(!IsMainchainRPCHostAllowed("10.0.0.2", true));
    BOOST_CHECK(!IsMainchainRPCHostAllowed("::", true));
    BOOST_CHECK(!IsMainchainRPCHostAllowed("fd00::1", true));
    BOOST_CHECK(!IsMainchainRPCHostAllowed("localhost", true));
    BOOST_CHECK(!IsMainchainRPCHostAllowed("parent.example", true));
    BOOST_CHECK(!IsMainchainRPCHostAllowed(
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion",
        true));

    // Ordinary Elements networks preserve their existing hostname support.
    BOOST_CHECK(IsMainchainRPCHostAllowed("localhost", false));
    BOOST_CHECK(IsMainchainRPCHostAllowed("parent.example", false));
}

BOOST_AUTO_TEST_CASE(mempool_witness_flow_preserves_error_selection)
{
    for (unsigned mask = 0; mask < 64; ++mask) {
        const bool pegin = mask & 1, complete = mask & 2, valid = mask & 4;
        const bool unavailable = mask & 8, native = mask & 16, outputs = mask & 32;
        unsigned index{0}, checks{0};
        bool seen{false}, invalid{false}, parent_unavailable{false};
        std::string witness_error, invalid_error, unavailable_error;
        BOOST_CHECK_EQUAL(drivechain::haskell::ParentReplayStore(
            drivechain::haskell::ReplayStoreFlow::MEMPOOL_WITNESS,
            [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return index < 2;
            case 2: return pegin;
            case 3: seen = true; return 1;
            case 4: return complete;
            case 5: invalid = true; invalid_error = "missing"; return 1;
            case 6: ++checks; witness_error = std::to_string(index); return valid;
            case 7: return unavailable;
            case 8: parent_unavailable = true; return unavailable_error.empty();
            case 9: unavailable_error = witness_error; return 1;
            case 10: invalid = true; invalid_error = witness_error; return 1;
            case 11: return native;
            case 12: invalid = true; invalid_error = "foreign"; return 1;
            case 13: return outputs;
            case 14: ++index; return 1;
            default: throw std::logic_error("unexpected mempool witness action");
            }
        }), 1U);
        const bool waiting = pegin && complete && !valid && unavailable;
        const std::string expected = !pegin ? "" : !complete ? "missing" :
            !valid ? (unavailable ? "" : "1") : !native ? "foreign" : !outputs ? "1" : "";
        BOOST_CHECK_EQUAL(index, 2U);
        BOOST_CHECK_EQUAL(checks, pegin && complete ? 2U : 0U);
        BOOST_CHECK_EQUAL(seen, pegin);
        BOOST_CHECK_EQUAL(invalid, !expected.empty());
        BOOST_CHECK_EQUAL(invalid_error, expected);
        BOOST_CHECK_EQUAL(parent_unavailable, waiting);
        BOOST_CHECK_EQUAL(unavailable_error, waiting ? "0" : "");
    }
}

BOOST_AUTO_TEST_CASE(preliminary_witness_preserves_fast_path_and_errors)
{
    for (unsigned mask = 0; mask < 32; ++mask) {
        const bool complete = mask & 1, native = mask & 2, recognized = mask & 4;
        const bool valid = mask & 8, unavailable = mask & 16;
        unsigned structural{0}, fallback{0}, failure{0};
        const bool accepted = complete && (drivechain::haskell::ParentReplayAll<2>({
            [&] { return native; },
            [&] { ++structural; return recognized; },
        }) || [&] { ++fallback; return valid; }());
        if (!accepted) failure = complete && unavailable ? 7 : 6;
        const bool expected = complete && ((native && recognized) || valid);
        BOOST_CHECK_EQUAL(accepted, expected);
        BOOST_CHECK_EQUAL(structural, complete && native ? 1U : 0U);
        BOOST_CHECK_EQUAL(fallback, complete && !(native && recognized) ? 1U : 0U);
        BOOST_CHECK_EQUAL(failure, expected ? 0U : complete && unavailable ? 7U : 6U);
    }
}

BOOST_AUTO_TEST_CASE(undo_witness_gate_preserves_legacy_fallback)
{
    for (unsigned mask = 0; mask < 8; ++mask) {
        const bool native = mask & 1, recognized = mask & 2, legacy = mask & 4;
        std::vector<unsigned> trace;
        const bool valid = drivechain::haskell::ParentReplayAll<2>({
            [&] { trace.push_back(1); return native; },
            [&] { trace.push_back(2); return recognized; },
        }) || [&] { trace.push_back(3); return legacy; }();
        std::vector<unsigned> expected{1};
        if (native) expected.push_back(2);
        if (!(native && recognized)) expected.push_back(3);
        BOOST_CHECK_EQUAL(valid, (native && recognized) || legacy);
        BOOST_CHECK_EQUAL_COLLECTIONS(trace.begin(), trace.end(), expected.begin(), expected.end());
    }
}

BOOST_AUTO_TEST_CASE(disconnect_restoration_stops_before_later_mutations)
{
    for (bool exchange : {false, true}) for (bool bmm : {false, true}) {
        std::vector<unsigned> trace;
        std::string error;
        const bool restored = drivechain::haskell::ParentReplayAll<2>({
            [&] { trace.push_back(1); if (!exchange) error = "exchange"; return exchange; },
            [&] { trace.push_back(2); if (!bmm) error = "bmm"; return bmm; },
        });
        if (restored) trace.push_back(3); // Best-block publication follows both restorations.
        std::vector<unsigned> expected{1};
        if (exchange) expected.push_back(2);
        if (exchange && bmm) expected.push_back(3);
        BOOST_CHECK_EQUAL(restored, exchange && bmm);
        BOOST_CHECK_EQUAL(error, !exchange ? "exchange" : !bmm ? "bmm" : "");
        BOOST_CHECK_EQUAL_COLLECTIONS(trace.begin(), trace.end(), expected.begin(), expected.end());
    }
}

BOOST_AUTO_TEST_CASE(deposit_disconnect_gate_preserves_undo_order)
{
    for (unsigned flags = 0; flags < 8; ++flags) for (unsigned fault = 0; fault <= 4; ++fault) {
        const auto run = [&](bool migrated) {
            std::vector<unsigned> trace;
            std::string error;
            bool complete{false};
            const auto step = [&](unsigned action) {
                trace.push_back(action);
                if (action == fault) throw std::runtime_error("rollback read failed");
                return bool(flags & (1U << (action - 1)));
            };
            try {
                const bool deposit = migrated ? drivechain::haskell::ParentReplayAll<2>({
                    [&] { return step(1); }, [&] { return step(2); },
                }) : step(1) && step(2);
                if (deposit && !step(3)) error = "CTIP restoration failed";
                else { step(4); complete = true; } // Inherited input undo follows restoration.
            } catch (const std::runtime_error& e) { error = e.what(); }
            return std::make_tuple(complete, trace, error);
        };
        const auto expected = run(false), actual = run(true);
        BOOST_CHECK(std::get<0>(actual) == std::get<0>(expected));
        BOOST_CHECK(std::get<1>(actual) == std::get<1>(expected));
        BOOST_CHECK_EQUAL(std::get<2>(actual), std::get<2>(expected));
    }
}

BOOST_AUTO_TEST_CASE(parent_block_authentication_stops_at_first_failure)
{
    for (unsigned flags = 0; flags < 8; ++flags) for (unsigned fault = 0; fault <= 3; ++fault) {
        const auto run = [&](bool migrated) {
            bool accepted{false};
            std::vector<unsigned> trace;
            std::string error;
            const auto check = [&](unsigned stage) {
                trace.push_back(stage);
                if (stage == fault) throw std::runtime_error("deadline");
                const bool valid = flags & (1U << stage);
                if (!valid) error = std::to_string(stage);
                return valid;
            };
            try {
                if (migrated) accepted = drivechain::haskell::ParentReplayAll<3>({
                    [&] { return check(0); }, [&] { return check(1); }, [&] { return check(2); },
                });
                else accepted = check(0) && check(1) && check(2);
            } catch (const std::runtime_error& e) { error = e.what(); }
            return std::make_tuple(accepted, trace, error);
        };
        const auto expected = run(false), actual = run(true);
        BOOST_CHECK(std::get<0>(actual) == std::get<0>(expected));
        BOOST_CHECK(std::get<1>(actual) == std::get<1>(expected));
        BOOST_CHECK_EQUAL(std::get<2>(actual), std::get<2>(expected));
    }
}

BOOST_AUTO_TEST_CASE(candidate_input_scan_preserves_preflight_and_coin_reads)
{
    namespace hs = drivechain::haskell;
    for (unsigned flags = 0; flags < 8; ++flags) {
        for (unsigned count = 0; count <= 3; ++count) for (unsigned mask = 0; mask < 64; ++mask) {
            std::vector<unsigned> inputs, reads, expected_reads;
            for (unsigned i = 0; i < count; ++i) inputs.push_back(i);
            bool expected = flags == 7;
            if (expected) for (unsigned i : inputs) {
                if ((mask >> (2*i)) & 1) continue; // Peg-in: no ordinary coin lookup.
                expected_reads.push_back(i);
                if ((mask >> (2*i)) & 2) { expected = false; break; }
            }
            const bool admitted = hs::ParentReplayAll<3>({
                [&] { return bool(flags & 1); }, [&] { return bool(flags & 2); },
                [&] { return bool(flags & 4); },
            }) && hs::ParentReplayEach(inputs, [&](unsigned i) {
                if ((mask >> (2*i)) & 1) return true;
                reads.push_back(i);
                return !((mask >> (2*i)) & 2);
            });
            BOOST_CHECK_EQUAL(admitted, expected);
            BOOST_CHECK_EQUAL_COLLECTIONS(reads.begin(), reads.end(), expected_reads.begin(), expected_reads.end());
        }
    }
}

BOOST_AUTO_TEST_CASE(mempool_policy_gates_preserve_lazy_checks)
{
    namespace hs = drivechain::haskell;
    for (bool enabled : {false, true}) for (bool valid : {false, true}) {
        unsigned checks{0};
        const bool reject = hs::ParentReplayAll<2>({
            [&] { return enabled; }, [&] { ++checks; return !valid; },
        });
        BOOST_CHECK_EQUAL(reject, enabled && !valid);
        BOOST_CHECK_EQUAL(checks, enabled ? 1U : 0U);
    }
    for (bool native : {false, true}) for (bool free : {false, true})
    for (bool canonical : {false, true})
    for (const auto& indices : std::vector<std::vector<unsigned>>{{}, {0}, {1}, {0, 1}}) {
        unsigned index_reads{0}, shape_checks{0};
        const bool eligible = hs::ParentReplayAll<4>({
            [&] { return native; },
            [&] { return hs::ParentReplayAll<2>({
                [&] { return indices.size() == 1; },
                [&] { ++index_reads; return indices.at(0) == 0; },
            }); },
            [&] { return free; },
            [&] { ++shape_checks; return canonical; },
        });
        const bool first = indices == std::vector<unsigned>{0};
        BOOST_CHECK_EQUAL(eligible, native && first && free && canonical);
        BOOST_CHECK_EQUAL(index_reads, native && indices.size() == 1 ? 1U : 0U);
        BOOST_CHECK_EQUAL(shape_checks, native && first && free ? 1U : 0U);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_connection_context_order)
{
    static_assert(static_cast<uint32_t>(drivechain::haskell::ReplayStoreFlow::CONNECTION_CONTEXT) == 296);
    for (unsigned mask = 0; mask < 64; ++mask) for (unsigned fault = 0; fault <= 14; ++fault) {
        const bool slot = mask & 1, candidate = mask & 2, derived = mask & 4;
        const bool finalized = mask & 8, matches = mask & 16, valid = mask & 32;
        std::array<std::vector<uint32_t>, 2> traces;
        std::array<bool, 2> accepted{}, threw{};
        std::array<unsigned, 2> published{};
        for (unsigned migrated = 0; migrated < 2; ++migrated) {
            const auto action = [&](uint32_t step) -> uint32_t {
                traces[migrated].push_back(step);
                if (step == fault) throw std::runtime_error("context failure");
                switch (step) {
                case 1: return slot;
                case 2: case 3: return candidate;
                case 6: return derived;
                case 8: return finalized;
                case 9: return matches;
                case 12: return valid;
                case 5: case 11: case 14: published[migrated] = step; return 1;
                case 4: case 7: case 10: case 13: return 0;
                default: throw std::logic_error("unexpected connection action");
                }
            };
            try {
                if (migrated) {
                    accepted[migrated] = drivechain::haskell::ParentReplayStore(
                        drivechain::haskell::ReplayStoreFlow::CONNECTION_CONTEXT, action);
                } else {
                    const auto original = [&] {
                        if (!action(1)) return action(2) ? action(4) : 1U;
                        if (action(3)) return action(5);
                        if (!action(6)) return action(7);
                        if (action(8)) return action(9) ? action(11) : action(10);
                        return action(12) ? action(14) : action(13);
                    };
                    accepted[migrated] = original();
                }
            } catch (const std::runtime_error& e) {
                BOOST_CHECK_EQUAL(e.what(), "context failure");
                threw[migrated] = true;
            }
        }
        BOOST_CHECK(traces[0] == traces[1]);
        BOOST_CHECK_EQUAL(accepted[0], accepted[1]);
        BOOST_CHECK_EQUAL(threw[0], threw[1]);
        BOOST_CHECK_EQUAL(published[0], published[1]);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_mempool_epoch_fences_native_pegins)
{
    for (bool epoch_matches : {false, true}) for (bool unavailable : {false, true}) {
        unsigned availability_reads{0};
        unsigned error_action{0};
        std::vector<uint32_t> trace;
        const bool may_mutate = drivechain::haskell::ParentReplayStore(
            drivechain::haskell::ReplayStoreFlow::CONFIGURED_SLOT,
            [&](uint32_t step) -> uint32_t {
                trace.push_back(step);
                switch (step) {
                case 1: return epoch_matches;
                case 2: case 4: error_action = step; return 0;
                case 3: ++availability_reads; return !unavailable;
                default: throw std::logic_error("invalid mempool epoch admission action");
                }
            });
        BOOST_CHECK_EQUAL(may_mutate, epoch_matches && !unavailable);
        BOOST_CHECK_EQUAL(availability_reads, epoch_matches ? 1U : 0U);
        BOOST_CHECK_EQUAL(error_action, !epoch_matches ? 2U : unavailable ? 4U : 0U);
        const std::vector<uint32_t> expected = !epoch_matches ? std::vector<uint32_t>{1,2}
            : unavailable ? std::vector<uint32_t>{1,3,4} : std::vector<uint32_t>{1,3};
        BOOST_CHECK(trace == expected);
    }
    const std::array<uint64_t, 6> epochs{0, 1, 2, 4294967295ULL, 4294967296ULL,
        std::numeric_limits<uint64_t>::max()};
    for (const auto authenticated : epochs) for (const auto observed : epochs) {
        BOOST_CHECK_EQUAL(IsDrivechainMempoolEpochCurrent(authenticated, observed),
            authenticated != 0 && authenticated == observed);
        unsigned reads{0};
        const bool admitted = drivechain::haskell::ParentReplayAll<2>({
            [&] { return observed != 0; },
            [&] { ++reads; return authenticated == observed; },
        });
        BOOST_CHECK_EQUAL(admitted, observed != 0 && authenticated == observed);
        BOOST_CHECK_EQUAL(reads, observed != 0 ? 1U : 0U);
    }
    BOOST_CHECK(!IsDrivechainMempoolEpochCurrent(0, 0));
    BOOST_CHECK(!IsDrivechainMempoolEpochCurrent(1, 0));
    BOOST_CHECK(!IsDrivechainMempoolEpochCurrent(2, 1));
    BOOST_CHECK(IsDrivechainMempoolEpochCurrent(1, 1));
    BOOST_CHECK(IsDrivechainMempoolEpochCurrent(
        std::numeric_limits<uint64_t>::max(),
        std::numeric_limits<uint64_t>::max()));
}

BOOST_AUTO_TEST_CASE(drivechain_mempool_sweep_preflight_preserves_state)
{
    auto& chainman = *m_node.chainman;
    auto& consensus = const_cast<Consensus::Params&>(chainman.GetParams().GetConsensus());
    struct RestoreSlot {
        Consensus::Params& consensus;
        std::optional<uint8_t> slot;
        ~RestoreSlot() { consensus.drivechain_slot = slot; }
    } restore{consensus,consensus.drivechain_slot};
    Chainstate without_pool{nullptr,chainman.m_blockman,chainman};
    const auto epoch = GetDrivechainParentReplayEpoch();
    const uint64_t stale = epoch == UINT64_MAX ? epoch - 1 : epoch + 1;
    const auto count = WITH_LOCK(m_node.mempool->cs, return m_node.mempool->size());
    for (bool native : {false,true}) {
        consensus.drivechain_slot = native ? std::optional<uint8_t>{24} : std::nullopt;
        for (Chainstate* state : {&without_pool,&chainman.ActiveChainstate()}) {
            for (uint64_t expected_epoch : {uint64_t{0},stale}) {
                std::string error{"old error"};
                BOOST_CHECK_EQUAL(state->RevalidateDrivechainMempoolForParentEpoch(expected_epoch,&error),!native);
                BOOST_CHECK_EQUAL(error,native ?
                    "authenticated parent replay generation is unavailable or changed before the mempool sweep" : "");
                BOOST_CHECK_EQUAL(state->RevalidateDrivechainMempoolForParentEpoch(expected_epoch,nullptr),!native);
            }
        }
    }
    BOOST_CHECK_EQUAL(GetDrivechainParentReplayEpoch(),epoch);
    BOOST_CHECK_EQUAL(WITH_LOCK(m_node.mempool->cs, return m_node.mempool->size()),count);
}

BOOST_AUTO_TEST_CASE(drivechain_mining_epoch_gate_preserves_lazy_reads)
{
    BOOST_REQUIRE(!Params().GetConsensus().drivechain_slot.has_value());
    BOOST_CHECK(m_node.chainman->ActiveChainstate().IsDrivechainMempoolCurrentForMining());
    for (bool native : {false, true}) for (bool current : {false, true})
    for (bool fail : {false, true}) {
        unsigned reads{0};
        bool threw{false};
        try {
            const bool admitted = !drivechain::haskell::ParentReplayAll<2>({
                [&] { return native; },
                [&] {
                    ++reads;
                    if (fail) throw std::runtime_error("epoch unavailable");
                    return !current;
                },
            });
            BOOST_CHECK_EQUAL(admitted, !native || current);
        } catch (const std::runtime_error& e) {
            BOOST_CHECK_EQUAL(e.what(), "epoch unavailable");
            threw = true;
        }
        BOOST_CHECK_EQUAL(reads, native ? 1U : 0U);
        BOOST_CHECK_EQUAL(threw, native && fail);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_removal_range_preserves_order_and_failure)
{
    std::vector<CTransactionRef> transactions;
    for (uint32_t count = 0; count < 5; ++count) {
        if (count) {
            CMutableTransaction tx;
            tx.nLockTime = count;
            transactions.push_back(MakeTransactionRef(tx));
        }
        for (size_t fault = 0; fault <= transactions.size(); ++fault) {
            std::array<std::vector<uint32_t>, 2> traces;
            std::array<bool, 2> threw{};
            for (unsigned migrated = 0; migrated < 2; ++migrated) {
                const auto remove = [&](const CTransactionRef& tx) {
                    traces[migrated].push_back(tx->nLockTime);
                    if (traces[migrated].size() == fault + 1) throw std::runtime_error("removal failed");
                    return true;
                };
                try {
                    if (migrated) drivechain::haskell::ParentReplayEach(transactions, remove);
                    else for (const auto& tx : transactions) remove(tx);
                } catch (const std::runtime_error& e) {
                    BOOST_CHECK_EQUAL(e.what(), "removal failed");
                    threw[migrated] = true;
                }
            }
            BOOST_CHECK(traces[0] == traces[1]);
            BOOST_CHECK_EQUAL(threw[0], threw[1]);
            BOOST_CHECK_EQUAL(threw[1], fault < transactions.size());
            BOOST_CHECK_EQUAL(traces[1].size(), std::min(fault + 1, transactions.size()));
        }
    }
}

BOOST_AUTO_TEST_CASE(drivechain_parent_rejection_strikes_are_per_edge)
{
    const uint256 p1 = uint256::ONE;
    const uint256 q1 = uint256S("02");
    const uint256 p2 = uint256S("03");
    const uint256 q2 = uint256S("04");

    BOOST_CHECK_EQUAL(NextDrivechainParentRejectedStrikeCount(
                          {}, {}, 0, p1, q1),
                      1U);
    BOOST_CHECK_EQUAL(NextDrivechainParentRejectedStrikeCount(
                          p1, q1, 1, p1, q1),
                      2U);
    BOOST_CHECK_EQUAL(NextDrivechainParentRejectedStrikeCount(
                          p1, q1, 99, p2, q2),
                      1U);
    BOOST_CHECK_EQUAL(NextDrivechainParentRejectedStrikeCount(
                          p1, q1, 1, {}, q1),
                      0U);
    const std::array<uint256,3> hashes{uint256{},p1,q1};
    const unsigned int limit=std::numeric_limits<unsigned int>::max();
    for (const auto& previous_parent : hashes)
    for (const auto& previous_successor : hashes)
    for (const auto& rejected_parent : hashes)
    for (const auto& rejected_successor : hashes)
    for (const unsigned int count : {0U,1U,limit-1,limit}) {
        const bool complete=!rejected_parent.IsNull() && !rejected_successor.IsNull();
        const bool same=previous_parent==rejected_parent && previous_successor==rejected_successor;
        const uint64_t incremented=std::min<uint64_t>(uint64_t{count}+1,limit);
        const unsigned int expected=!complete ? 0U : same && count!=0 ? incremented : 1U;
        BOOST_CHECK_EQUAL(NextDrivechainParentRejectedStrikeCount(previous_parent,
            previous_successor,count,rejected_parent,rejected_successor),expected);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_peer_admission_order)
{
    using namespace drivechain::haskell;
    static_assert(static_cast<uint32_t>(ReplayStoreFlow::PEER_REQUEST) == 264);
    static_assert(static_cast<uint32_t>(ReplayStoreFlow::PEER_SYNC) == 265);
    for (bool syncing : {false,true}) for (uint32_t mask=0; mask<32; ++mask) {
        const bool native=mask&1, requested=mask&2, exists=mask&4, pending=mask&8, matches=mask&16;
        std::vector<uint32_t> expected{1};
        bool accepted{false};
        if (syncing) {
            if (native) { expected.push_back(2); accepted=requested; }
        } else if (!native) { expected.push_back(7); accepted=requested; }
        else {
            expected.insert(expected.end(),{2,3});
            if (requested) accepted=true;
            else {
                expected.push_back(4);
                if (exists) {
                    expected.push_back(5);
                    if (pending) { expected.push_back(6); accepted=matches; }
                }
            }
        }
        std::vector<uint32_t> trace;
        const auto run = [&](size_t fault) {
            trace.clear();
            return ParentReplayStore(syncing ? ReplayStoreFlow::PEER_SYNC : ReplayStoreFlow::PEER_REQUEST,
                [&](uint32_t step) -> uint32_t {
                trace.push_back(step);
                if (trace.size()==fault) throw std::runtime_error("peer admission sentinel");
                switch (step) {
                case 1: return native;
                case 2: return syncing ? requested : true;
                case 3: case 7: return requested;
                case 4: return exists;
                case 5: BOOST_REQUIRE(exists); return pending;
                case 6: BOOST_REQUIRE(exists && pending); return matches;
                default: throw std::logic_error("invalid peer admission test step");
                }
            });
        };
        BOOST_CHECK_EQUAL(run(0),accepted);
        BOOST_CHECK(trace==expected);
        for (size_t fault=1; fault<=expected.size(); ++fault) {
            BOOST_CHECK_THROW(run(fault),std::runtime_error);
            BOOST_CHECK(trace==std::vector<uint32_t>(expected.begin(),expected.begin()+fault));
        }
    }
}

BOOST_AUTO_TEST_CASE(drivechain_peer_block_outcome_order)
{
    using namespace drivechain::haskell;
    for (const bool pending : {false,true})
    for (const bool authenticated : {false,true})
    for (const uint32_t status : {0U,1U,2U})
    for (const uint32_t strikes : {0U,1U,2U,UINT32_MAX})
    for (const bool resume : {false,true}) {
        std::vector<uint32_t> expected{1};
        int outcome=0;
        if (pending) {
            expected.push_back(2);
            if (authenticated) { expected.push_back(3); outcome=1; }
            else {
                expected.insert(expected.end(),{4,5});
                if (status==1) {
                    expected.insert(expected.end(),{6,strikes==0 ? 8U : strikes==1 ? 10U : 9U});
                    outcome=strikes>=2 ? 2 : 0;
                } else {
                    expected.push_back(12);
                    if (status==2) expected.push_back(8);
                    else {
                        expected.push_back(13);
                        if (resume) { expected.push_back(14); outcome=1; }
                    }
                }
            }
        }
        std::vector<uint32_t> trace;
        const auto run = [&](size_t fail) {
            trace.clear();
            return ParentReplayStore(ReplayStoreFlow::PEER_BLOCK,[&](uint32_t step) -> uint32_t {
                trace.push_back(step);
                if (trace.size()==fail) throw std::runtime_error("peer outcome callback failure");
                switch (step) {
                case 1: return pending;
                case 2: return authenticated;
                case 5: return status==1;
                case 6: return strikes;
                case 12: return status==2;
                case 13: return resume;
                default: return 1;
                }
            });
        };
        BOOST_CHECK_EQUAL(run(0),outcome);
        BOOST_CHECK(trace==expected);
        for (size_t fail=1; fail<=expected.size(); ++fail) {
            BOOST_CHECK_THROW(run(fail),std::runtime_error);
            BOOST_CHECK(trace==std::vector<uint32_t>(expected.begin(),expected.begin()+fail));
        }
    }
}

BOOST_AUTO_TEST_CASE(drivechain_peer_timer_order)
{
    using namespace drivechain::haskell;
    for (uint32_t mask=0; mask<32; ++mask) {
        const bool expired=mask&1, resume=mask&2, pending=mask&4;
        const bool authenticated=mask&8, deadline=mask&16;
        std::vector<uint32_t> expected{1};
        unsigned messages{0};
        if (expired) {
            expected.push_back(2);
            if (resume) { expected.push_back(3); ++messages; }
        }
        expected.push_back(4);
        if (pending) {
            expected.push_back(5);
            if (authenticated) { expected.push_back(6); ++messages; }
            else {
                expected.push_back(7);
                if (deadline) expected.push_back(8);
            }
        }
        const bool disconnected=pending && !authenticated && deadline;
        std::vector<uint32_t> trace;
        unsigned sent{0};
        const auto run = [&](size_t fault) {
            trace.clear();
            sent=0;
            return ParentReplayStore(ReplayStoreFlow::PEER_TIMER,[&](uint32_t step) -> uint32_t {
                trace.push_back(step);
                if (trace.size()==fault) throw std::runtime_error("peer timer callback failure");
                switch (step) {
                case 1: return expired;
                case 2: return resume;
                case 3: case 6: ++sent; return 1;
                case 4: return pending;
                case 5: return authenticated;
                case 7: return deadline;
                case 8: return 1;
                default: throw std::logic_error("unknown timer action");
                }
            });
        };
        BOOST_CHECK_EQUAL(run(0),disconnected);
        BOOST_CHECK(trace==expected);
        BOOST_CHECK_EQUAL(sent,messages);
        for (size_t fault=1; fault<=expected.size(); ++fault) {
            BOOST_CHECK_THROW(run(fault),std::runtime_error);
            BOOST_CHECK(trace==std::vector<uint32_t>(expected.begin(),expected.begin()+fault));
            const auto before_fault=expected.begin()+fault-1;
            BOOST_CHECK_EQUAL(sent,std::count(expected.begin(),before_fault,3U)+std::count(expected.begin(),before_fault,6U));
        }
    }
}

BOOST_AUTO_TEST_CASE(drivechain_peer_headers_order)
{
    using namespace drivechain::haskell;
    // Known/authenticated, known/rejected, unknown/accepted, unknown/rejected,
    // and unknown/failed-with-valid-state cover every scanner branch.
    std::vector<std::vector<unsigned>> samples{{}}, level{{}};
    for (unsigned depth=0; depth<3; ++depth) {
        std::vector<std::vector<unsigned>> next;
        for (const auto& prefix : level) for (unsigned kind=0; kind<5; ++kind) {
            auto sample=prefix;
            sample.push_back(kind);
            next.push_back(sample);
            samples.push_back(sample);
        }
        level=std::move(next);
    }
    for (unsigned mask=0; mask<16; ++mask) for (const auto& sample : samples) {
        const bool backoff=mask&1, expired=backoff && (mask&2);
        const bool pending=mask&4, authenticated=mask&8;
        std::vector<uint32_t> expected{1};
        uint32_t outcome{0};
        if (expired) expected.push_back(2);
        expected.push_back(3);
        if (backoff && !expired) expected.push_back(4);
        else {
            expected.push_back(5);
            if (pending) {
                expected.insert(expected.end(),{6,authenticated ? 7U : 8U});
                outcome=authenticated ? 2 : 0;
            } else {
                bool valid=true, last=false;
                expected.push_back(9);
                for (unsigned kind : sample) {
                    expected.push_back(10);
                    if (kind<2) {
                        expected.insert(expected.end(),{11,kind==0 ? 12U : 13U});
                        if (kind==1) { valid=false; break; }
                        last=true;
                        expected.push_back(9);
                    } else {
                        expected.push_back(14);
                        if (kind==2) { expected.insert(expected.end(),{15,16}); outcome=1; }
                        if (kind==3) valid=false;
                        break;
                    }
                }
                if (outcome!=1) {
                    expected.push_back(17);
                    if (valid) {
                        expected.push_back(18);
                        if (last) { expected.push_back(19); outcome=2; }
                    }
                }
            }
        }
        std::vector<uint32_t> trace;
        const auto run = [&](size_t fault) {
            trace.clear();
            size_t index{0};
            bool active=backoff, valid=true, last=false;
            return ParentReplayStore(ReplayStoreFlow::PEER_HEADERS,[&](uint32_t step) -> uint32_t {
                trace.push_back(step);
                if (trace.size()==fault) throw std::runtime_error("peer headers callback failure");
                switch (step) {
                case 1: return expired;
                case 2: active=false; return 1;
                case 3: return active;
                case 4: case 7: case 8: case 15: case 16: case 19: return 1;
                case 5: return pending;
                case 6: return authenticated;
                case 9: return index<sample.size();
                case 10: return sample.at(index)<2;
                case 11: return sample.at(index)==0;
                case 12: last=true; ++index; return 1;
                case 13: valid=false; return 1;
                case 14: valid=sample.at(index)!=3; return sample.at(index)==2;
                case 17: return valid;
                case 18: return last;
                default: throw std::logic_error("unknown header action");
                }
            });
        };
        BOOST_CHECK_EQUAL(run(0),outcome);
        BOOST_CHECK(trace==expected);
        for (size_t fault=1; fault<=expected.size(); ++fault) {
            BOOST_CHECK_THROW(run(fault),std::runtime_error);
            BOOST_CHECK(trace==std::vector<uint32_t>(expected.begin(),expected.begin()+fault));
        }
    }
}

BOOST_AUTO_TEST_CASE(drivechain_peer_dispatch_order)
{
    using namespace drivechain::haskell;
    for (unsigned state=0; state<3; ++state)
    for (uint32_t outcome : {0U,1U,2U,3U,UINT32_MAX}) {
        std::vector<uint32_t> expected{1};
        if (state!=0) {
            expected.push_back(2);
            if (state==1) expected.push_back(3);
        } else {
            expected.push_back(4);
            if (outcome==1) expected.insert(expected.end(),{5,7});
            if (outcome==2) expected.push_back(6);
        }
        std::vector<uint32_t> trace;
        const auto run = [&](size_t fault) {
            trace.clear();
            return ParentReplayStore(ReplayStoreFlow::PEER_DISPATCH,[&](uint32_t step) -> uint32_t {
                trace.push_back(step);
                if (trace.size()==fault) throw std::runtime_error("peer dispatch callback failure");
                switch (step) {
                case 1: return state==0;
                case 2: return state==1;
                case 4: return outcome;
                case 3: case 5: case 6: case 7: return 1;
                default: throw std::logic_error("unknown dispatch action");
                }
            });
        };
        // An impossible outcome is rejected only when it is actually consumed.
        if (state==0 && outcome>2) BOOST_CHECK_THROW(run(0),std::runtime_error);
        else BOOST_CHECK_EQUAL(run(0),0U);
        BOOST_CHECK(trace==expected);
        for (size_t fault=1; fault<=expected.size(); ++fault) {
            BOOST_CHECK_THROW(run(fault),std::runtime_error);
            BOOST_CHECK(trace==std::vector<uint32_t>(expected.begin(),expected.begin()+fault));
        }
    }
}




BOOST_AUTO_TEST_CASE(drivechain_index_derived_load_order)
{
    using namespace drivechain::haskell;
    for (unsigned mask=0; mask<128; ++mask) {
        const auto fact = [&](unsigned bit) { return (mask&(1U<<bit))!=0; };
        std::vector<uint32_t> expected{1};
        bool rejected{false};
        if (fact(0)) {
            expected.push_back(2);
            expected.push_back(fact(1) ? 4 : 3);
            rejected=!fact(1);
        }
        if (!rejected) {
            expected.push_back(5);
            if (fact(2)) {
                expected.push_back(6);
                if (fact(3)) expected.push_back(7);
                rejected=!fact(3) || !fact(4);
                expected.push_back(rejected ? 8 : 9);
            } else {
                expected.push_back(10);
                if (fact(5)) expected.push_back(11);
                else {
                    expected.push_back(12);
                    if (fact(6)) { expected.push_back(13); rejected=true; }
                }
            }
        }
        std::vector<uint32_t> trace, published;
        const auto run = [&](size_t fault) {
            trace.clear(); published.clear();
            return ParentReplayStore(ReplayStoreFlow::INDEX_DERIVED,[&](uint32_t step) -> uint32_t {
                trace.push_back(step);
                if (trace.size()==fault) throw std::runtime_error("derived index callback failure");
                switch (step) {
                case 1: return fact(0);
                case 2: return fact(1);
                case 5: return fact(2);
                case 6: return fact(3);
                case 7: return fact(4);
                case 10: return fact(5);
                case 12: return fact(6);
                case 4: case 9: case 11: published.push_back(step); return 1;
                case 3: case 8: case 13: return 1;
                default: throw std::logic_error("unknown index action");
                }
            });
        };
        for (size_t fault=0; fault<=expected.size(); ++fault) {
            if (fault==0) BOOST_CHECK_EQUAL(run(fault),rejected);
            else BOOST_CHECK_THROW(run(fault),std::runtime_error);
            const size_t executed=fault==0 ? expected.size() : fault;
            BOOST_CHECK(trace==std::vector(expected.begin(),expected.begin()+executed));
            std::vector<uint32_t> expected_publications;
            for (size_t i=0; i<(fault==0 ? executed : executed-1); ++i)
                if (expected[i]==4 || expected[i]==9 || expected[i]==11) expected_publications.push_back(expected[i]);
            BOOST_CHECK(published==expected_publications);
        }
    }
}

BOOST_AUTO_TEST_CASE(drivechain_index_continuity_order)
{
    using namespace drivechain::haskell;
    std::vector<std::vector<unsigned>> samples{{},{6},{25}};
    for (unsigned mask=0; mask<128; ++mask) {
        samples.push_back({mask});
        samples.push_back({6,25,mask,25});
    }
    for (const auto& rows : samples) {
        std::vector<uint32_t> expected{1};
        bool rejected{false};
        for (unsigned mask : rows) {
            const auto fact=[&](unsigned bit) { return (mask&(1U<<bit))!=0; };
            expected.push_back(2);
            if (!fact(0)) {
                expected.push_back(3);
                if (fact(1)) expected.push_back(4);
                if (!fact(1) || !fact(2)) { expected.push_back(5); rejected=true; }
            } else {
                expected.push_back(6);
                if (fact(3)) expected.push_back(7);
                if (!fact(3) || !fact(4)) { expected.push_back(9); rejected=true; }
                else {
                    expected.push_back(8);
                    if (fact(5)) {
                        expected.push_back(10);
                        if (!fact(6)) { expected.push_back(11); rejected=true; }
                    }
                }
            }
            if (rejected) break;
            expected.insert(expected.end(),{12,1});
        }
        std::vector<uint32_t> trace;
        const auto run=[&](size_t fault) {
            trace.clear();
            size_t index{0};
            return ParentReplayStore(ReplayStoreFlow::INDEX_CONTINUITY,[&](uint32_t step) -> uint32_t {
                trace.push_back(step);
                if (trace.size()==fault) throw std::runtime_error("continuity callback failure");
                const auto fact=[&](unsigned bit) { return (rows.at(index)&(1U<<bit))!=0; };
                switch (step) {
                case 1: return index<rows.size();
                case 2: return fact(0);
                case 3: return fact(1);
                case 4: return fact(2);
                case 6: return fact(3);
                case 7: return fact(4);
                case 8: return fact(5);
                case 10: return fact(6);
                case 12: ++index; return 1;
                case 5: case 9: case 11: return 1;
                default: throw std::logic_error("unknown continuity action");
                }
            });
        };
        BOOST_CHECK_EQUAL(run(0),rejected);
        BOOST_CHECK(trace==expected);
        for (size_t fault=1; fault<=expected.size(); ++fault) {
            BOOST_CHECK_THROW(run(fault),std::runtime_error);
            BOOST_CHECK(trace==std::vector(expected.begin(),expected.begin()+fault));
        }
    }
}

BOOST_AUTO_TEST_CASE(drivechain_header_admission_order)
{
    using namespace drivechain::haskell;
    for (bool context : {false,true}) for (unsigned mask=0; mask<128; ++mask) {
        std::vector<uint32_t> expected;
        const auto read=[&](uint32_t step) { expected.push_back(step); return (mask & (1U<<(step-1)))!=0; };
        const bool accepted=[&] {
            if (!read(1)) return !context;
            if (!read(2)) return false;
            if (context && read(5)) return false;
            if (read(3) || !read(4)) return false;
            if (!context && read(5)) return true;
            return read(6) && read(7);
        }();
        for (size_t fault=0; fault<=expected.size(); ++fault) {
            std::vector<uint32_t> trace;
            const auto run=[&] {
                return ParentReplayStore(context ? ReplayStoreFlow::PARENT_CONTEXT_ADMISSION :
                    ReplayStoreFlow::HEADER_AUTHENTICATION,[&](uint32_t step) -> uint32_t {
                    trace.push_back(step);
                    if (trace.size()==fault) throw std::runtime_error("header admission callback failure");
                    return (mask & (1U<<(step-1)))!=0;
                });
            };
            if (fault==0) BOOST_CHECK_EQUAL(run(),!accepted);
            else BOOST_CHECK_THROW(run(),std::runtime_error);
            BOOST_CHECK(trace==std::vector(expected.begin(),expected.begin()+(fault==0 ? expected.size() : fault)));
        }
    }
}


BOOST_AUTO_TEST_CASE(drivechain_bmm_bid_selection)
{
    for (const CAmount configured : {CAmount{-1},CAmount{0},CAmount{1},MAX_MONEY,MAX_MONEY+1}) {
        for (const CAmount fees : {CAmount{-1},CAmount{0},CAmount{1},MAX_MONEY,MAX_MONEY+1}) {
            CAmount actual{42};
            std::string message{"stale"};
            const bool valid_config = configured > 0 && MoneyRange(configured);
            const bool valid_fees = MoneyRange(fees);
            BOOST_CHECK_EQUAL(ComputeDrivechainBmmBid(configured,fees,actual,&message),valid_config && valid_fees);
            BOOST_CHECK_EQUAL(actual,valid_config && valid_fees ? std::max(configured,fees) : 42);
            BOOST_CHECK_EQUAL(message,!valid_config ? "configured BMM bid must be positive and within the money range" :
                !valid_fees ? "sidechain candidate fees are outside the money range" : "");
        }
    }
    CAmount selected{0};
    std::string error;
    BOOST_CHECK(ComputeDrivechainBmmBid(
        DEFAULT_DRIVECHAIN_BMM_BID, 0, selected, &error));
    BOOST_CHECK_EQUAL(selected, 1000);
    BOOST_CHECK(ComputeDrivechainBmmBid(1000, 2500, selected, &error));
    BOOST_CHECK_EQUAL(selected, 2500);
    BOOST_CHECK(ComputeDrivechainBmmBid(MAX_MONEY, MAX_MONEY,
                                        selected, &error));
    BOOST_CHECK_EQUAL(selected, MAX_MONEY);
    BOOST_CHECK(!ComputeDrivechainBmmBid(0, 0, selected, &error));
    BOOST_CHECK(!ComputeDrivechainBmmBid(-1, 0, selected, &error));
    BOOST_CHECK(!ComputeDrivechainBmmBid(1, -1, selected, &error));
    BOOST_CHECK(!ComputeDrivechainBmmBid(MAX_MONEY + 1, 0,
                                         selected, &error));

    CAmount parsed{0};
    BOOST_CHECK(ParseDrivechainBmmBid("1000", parsed, &error));
    BOOST_CHECK_EQUAL(parsed, 1000);
    BOOST_CHECK(ParseDrivechainBmmBid(
        util::ToString(MAX_MONEY), parsed, &error));
    BOOST_CHECK_EQUAL(parsed, MAX_MONEY);
    BOOST_CHECK(!ParseDrivechainBmmBid("1000garbage", parsed, &error));
    BOOST_CHECK(!ParseDrivechainBmmBid(" 1000", parsed, &error));
    BOOST_CHECK(!ParseDrivechainBmmBid("1000 ", parsed, &error));
    BOOST_CHECK(!ParseDrivechainBmmBid("0", parsed, &error));
    BOOST_CHECK(!ParseDrivechainBmmBid("-1", parsed, &error));
    BOOST_CHECK(!ParseDrivechainBmmBid(
        util::ToString(MAX_MONEY + 1), parsed, &error));
    for (const std::string value : {"", "invalid", " 1000", "1000 ", "0", "-1"}) {
        parsed = 42;
        error = "stale";
        BOOST_CHECK(!ParseDrivechainBmmBid(value,parsed,&error));
        BOOST_CHECK_EQUAL(parsed,42);
        BOOST_CHECK_EQUAL(error,(value == "0" || value == "-1") ?
            "configured BMM bid must be positive and within the money range" :
            "BMM bid must be a canonical base-10 integer");
        BOOST_CHECK(!ParseDrivechainBmmBid(value,parsed,nullptr));
        BOOST_CHECK_EQUAL(parsed,42);
    }
}

BOOST_AUTO_TEST_CASE(ecx_bid_preflight_error_translation)
{
    const uint256 hash = uint256S("1234"), sentinel = uint256S("abcd");
    using Case = std::tuple<int,uint64_t,uint32_t,uint256,uint256,std::string>;
    const std::vector<Case> cases{
        {-1,0,0,{}, {},"BMM sidechain slot is outside uint8 range"},
        {256,1,1,hash,hash,"BMM sidechain slot is outside uint8 range"},
        {24,0,1,hash,hash,"BMM bid must be positive and within the money range"},
        {24,uint64_t{MAX_MONEY}+1,1,hash,hash,"BMM bid must be positive and within the money range"},
        {24,1,0,hash,hash,"BMM bid identity is incomplete"},
        {24,1,1,{},hash,"BMM bid identity is incomplete"},
        {24,1,1,hash,{},"BMM bid identity is incomplete"},
    };
    for (const auto& [slot,bid,height,critical,parent,message] : cases) {
        for (const bool diagnostic : {false,true}) {
            uint256 txid = sentinel;
            std::string error{"stale"};
            BOOST_CHECK(!SubmitDrivechainBmmBid(slot,bid,height,critical,parent,txid,diagnostic ? &error : nullptr));
            BOOST_CHECK(txid == sentinel);
            BOOST_CHECK_EQUAL(error,diagnostic ? message : "stale");
        }
    }
}

BOOST_AUTO_TEST_CASE(shared_bmm_request_encoding)
{
    const uint256 critical = uint256S("1234"), parent = uint256S("abcdef");
    for (const int slot : {-1,24,255,256}) {
        for (const uint64_t bid : {uint64_t{0},uint64_t{1000},UINT64_MAX}) {
            for (const int64_t height : {INT64_MIN,int64_t{0},int64_t{UINT32_MAX},INT64_MAX}) {
                const auto request = BuildDrivechainBmmRequest(slot,bid,height,critical,parent);
                const auto original = strprintf(
                    "{\"sidechainId\":%d,\"valueSats\":\"%d\",\"height\":%d,\"criticalHash\":{\"hex\":\"%s\"},\"prevBytes\":{\"hex\":\"%s\"}}",
                    slot,bid,height,critical.GetHex(),parent.GetHex());
                BOOST_CHECK_EQUAL(request.write(),original);
                BOOST_CHECK_EQUAL(request["valueSats"].get_str(),std::to_string(bid));
                BOOST_CHECK_EQUAL(request["height"].getInt<int64_t>(),height);
                BOOST_CHECK_EQUAL(request["sidechainId"].getInt<int>(),slot);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(reward_wallet_short_circuit_order)
{
    namespace hs = drivechain::haskell;
    for (const bool loader : {false,true}) for (size_t count = 0; count <= 2; ++count) {
        for (unsigned mask = 0; mask < (1U << (2*count)); ++mask) {
            std::vector<std::pair<bool,bool>> wallets;
            for (size_t i = 0; i < count; ++i) wallets.emplace_back(mask & (1U << (2*i)),mask & (1U << (2*i+1)));
            std::vector<uint32_t> expected{1};
            bool accepted{false};
            if (loader) {
                expected.push_back(2);
                for (const auto& [disabled,spendable] : wallets) {
                    expected.insert(expected.end(),{3,4});
                    if (!disabled) expected.push_back(5);
                    if (!disabled && spendable) { accepted = true; break; }
                    expected.push_back(6);
                }
                if (!accepted) expected.push_back(3);
            }
            for (size_t fault = 0; fault <= expected.size(); ++fault) {
                size_t index{0};
                std::vector<uint32_t> trace;
                const auto invoke = [&] {
                    return hs::ParentReplayStore(hs::ReplayStoreFlow::REWARD_WALLET,[&](uint32_t step) -> uint32_t {
                        trace.push_back(step);
                        if (trace.size() == fault+1) throw std::runtime_error("reward wallet fault");
                        switch (step) {
                        case 1: return loader;
                        case 2: return 1;
                        case 3: return index < wallets.size();
                        case 4: return wallets.at(index).first;
                        case 5: return wallets.at(index).second;
                        case 6: ++index; return 1;
                        default: throw std::logic_error("unexpected wallet action");
                        }
                    });
                };
                if (fault == expected.size()) BOOST_CHECK_EQUAL(invoke(),accepted);
                else BOOST_CHECK_EXCEPTION(invoke(),std::runtime_error,[](const std::runtime_error& error) {
                    return std::string(error.what()) == "reward wallet fault";
                });
                const std::vector<uint32_t> prefix(expected.begin(),expected.begin()+std::min(fault+1,expected.size()));
                BOOST_CHECK(trace == prefix);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(drivechain_producer_lifecycle_order)
{
    namespace hs = drivechain::haskell;
    for (const auto flow : {hs::ReplayStoreFlow::PRODUCTION_ROUTING,
                           hs::ReplayStoreFlow::BLOCK_PREPARATION,
                           hs::ReplayStoreFlow::BLOCK_ACCEPTANCE}) {
        for (unsigned mask = 0; mask < 16; ++mask) {
            const auto fact = [&](uint32_t step) { return (mask & (1U << (step-1))) != 0; };
            std::vector<uint32_t> expected{1};
            bool accepted;
            if (flow == hs::ReplayStoreFlow::PRODUCTION_ROUTING) {
                const uint32_t selected = fact(1) ? 2 : 3;
                expected.push_back(selected);
                accepted = fact(selected);
            } else if (flow == hs::ReplayStoreFlow::BLOCK_PREPARATION) {
                if (!fact(1)) expected.push_back(2);
                accepted = fact(1) || fact(2);
                if (accepted) {
                    expected.push_back(3);
                    if (!fact(3)) {
                        expected.push_back(4);
                        if (fact(4)) { expected.push_back(5); accepted = false; }
                    }
                }
            } else {
                accepted = fact(1);
                if (!accepted) expected.push_back(2);
            }
            for (size_t fault = 0; fault <= expected.size(); ++fault) {
                for (const bool malformed : {false,true}) {
                    std::vector<uint32_t> trace;
                    const auto invoke = [&] {
                        return hs::ParentReplayStore(flow,[&](uint32_t step) -> uint32_t {
                            trace.push_back(step);
                            if (trace.size() == fault+1) {
                                if (malformed) return 2;
                                throw std::runtime_error("producer lifecycle fault");
                            }
                            if ((flow == hs::ReplayStoreFlow::BLOCK_PREPARATION && step == 5) ||
                                (flow == hs::ReplayStoreFlow::BLOCK_ACCEPTANCE && step == 2)) return 1;
                            return fact(step);
                        });
                    };
                    if (fault == expected.size()) BOOST_CHECK_EQUAL(invoke(),accepted);
                    else BOOST_CHECK_EXCEPTION(invoke(),std::runtime_error,[&](const std::runtime_error& error) {
                        return std::string(error.what()) == (malformed ?
                            "Haskell parent replay store evaluation failed" : "producer lifecycle fault");
                    });
                    const std::vector<uint32_t> prefix(expected.begin(),expected.begin()+std::min(fault+1,expected.size()));
                    BOOST_CHECK(trace == prefix);
                }
            }
        }
    }
}

BOOST_FIXTURE_TEST_CASE(drivechain_native_preparation_and_acceptance, RegTestingSetup)
{
    BOOST_REQUIRE(!g_signed_blocks);
    auto& chainman = *m_node.chainman;
    node::BlockAssembler::Options options;
    options.coinbase_output_script = CScript() << OP_TRUE;
    auto block = PrepareBlock(m_node,options);
    const int height = WITH_LOCK(cs_main, return chainman.ActiveHeight());
    BOOST_REQUIRE(PrepareDrivechainBlock(chainman,*block));
    BOOST_CHECK(block->hashMerkleRoot == BlockMerkleRoot(*block));
    BOOST_CHECK(CheckProofOfWork(block->GetHash(),block->nBits,Params().GetConsensus()));
    BOOST_REQUIRE(AcceptPreparedDrivechainBlock(chainman,*block));
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return chainman.ActiveHeight()),height+1);
    BOOST_CHECK(AcceptPreparedDrivechainBlock(chainman,*block));
    CBlock rejected;
    {
        ASSERT_DEBUG_LOG("generated sidechain block " + rejected.GetHash().ToString() + " was not accepted");
        BOOST_CHECK(!AcceptPreparedDrivechainBlock(chainman,rejected));
    }
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return chainman.ActiveHeight()),height+1);

    block = PrepareBlock(m_node,options);
    block->m_dynafed_params.m_current = DynaFedParamEntry(CScript(OP_FALSE),1000,uint256{});
    {
        ASSERT_DEBUG_LOG("cannot sign dynamic federation block because signblockscript is not WSH(OP_TRUE)");
        BOOST_CHECK(!PrepareDrivechainBlock(chainman,*block));
    }
    block->m_dynafed_params.m_current.m_signblockscript = GetScriptForDestination(WitnessV0ScriptHash(CScript(OP_TRUE)));
    BOOST_REQUIRE(m_interrupt());
    BOOST_CHECK(!PrepareDrivechainBlock(chainman,*block));
    BOOST_CHECK(block->m_signblock_witness.stack.empty());
    BOOST_REQUIRE(m_interrupt.reset());
    BOOST_REQUIRE(PrepareDrivechainBlock(chainman,*block));
    BOOST_CHECK(block->m_signblock_witness.stack == std::vector<std::vector<unsigned char>>{{OP_TRUE}});
}

BOOST_AUTO_TEST_CASE(shared_op_true_block_witness)
{
    const CScript op_true(OP_TRUE);
    const CScript matching = GetScriptForDestination(WitnessV0ScriptHash(op_true));
    for (const CScript script : {CScript(),CScript(OP_TRUE),CScript(OP_FALSE),matching}) {
        CBlock block;
        block.m_dynafed_params.m_current.m_signblockscript = script;
        block.m_signblock_witness.stack = {{0x42}};
        const bool accepted = script == matching;
        BOOST_CHECK_EQUAL(node::AppendOpTrueBlockWitness(block),accepted);
        std::vector<std::vector<unsigned char>> expected{{0x42}};
        if (accepted) expected.emplace_back(op_true.begin(),op_true.end());
        BOOST_CHECK(block.m_signblock_witness.stack == expected);
        BOOST_CHECK(block.m_dynafed_params.m_current.m_signblockscript == script);
        BOOST_CHECK_EQUAL(node::AppendOpTrueBlockWitness(block),accepted);
        if (accepted) expected.emplace_back(op_true.begin(),op_true.end());
        BOOST_CHECK(block.m_signblock_witness.stack == expected);
    }
}

BOOST_AUTO_TEST_CASE(shared_nonce_search_preserves_rpc_loop)
{
    auto consensus = Params().GetConsensus();
    consensus.powLimit = uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    for (const uint32_t bits : {0U,0x2100ffffU}) {
        for (const uint64_t budget : {0U,1U,2U,7U}) {
            for (const uint32_t nonce : {0U,UINT32_MAX-1,UINT32_MAX}) {
                for (const bool stopped : {false,true}) {
                    util::SignalInterrupt interrupt;
                    if (stopped) BOOST_REQUIRE(interrupt());
                    CBlock expected;
                    expected.nBits = bits;
                    expected.nNonce = nonce;
                    CBlock actual = expected;
                    uint64_t remaining = budget, expected_remaining = budget;
                    // Preserve the original RPC loop as an independent oracle.
                    while (expected_remaining > 0 && expected.nNonce < UINT32_MAX &&
                           !CheckProofOfWork(expected.GetHash(),expected.nBits,consensus) && !interrupt) {
                        ++expected.nNonce;
                        --expected_remaining;
                    }
                    const bool accepted = !(expected_remaining == 0 || bool{interrupt});
                    BOOST_CHECK_EQUAL(node::SearchBlockNonce(actual,remaining,consensus,interrupt),accepted);
                    BOOST_CHECK_EQUAL(actual.nNonce,expected.nNonce);
                    BOOST_CHECK_EQUAL(remaining,expected_remaining);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(extra_nonce_preserves_counter_and_coinbase_encoding)
{
    CBlock block;
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    block.vtx.push_back(MakeTransactionRef(coinbase));
    CBlockIndex previous;
    previous.nHeight=10;
    block.hashPrevBlock=uint256S("01");
    unsigned counter=0;
    node::IncrementExtraNonce(&block,&previous,counter);
    for (bool same_parent : {false,true}) for (unsigned initial : {0U,1U,UINT32_MAX-1,UINT32_MAX}) {
        if (!same_parent) block.hashPrevBlock=block.hashPrevBlock==uint256S("01") ? uint256S("02") : uint256S("01");
        counter=initial;
        const unsigned expected=same_parent ? initial+1 : 1;
        node::IncrementExtraNonce(&block,&previous,counter);
        BOOST_CHECK_EQUAL(counter,expected);
        BOOST_CHECK(block.vtx[0]->vin[0].scriptSig==(CScript() << 11 << CScriptNum(expected)));
        BOOST_CHECK(block.hashMerkleRoot==BlockMerkleRoot(block));
    }
}

BOOST_AUTO_TEST_CASE(bmm_wait_probe_order)
{
    namespace hs = drivechain::haskell;
    for (unsigned flags = 0; flags < 8; ++flags) {
        const bool proof = flags & 1, first = flags & 2, second = flags & 4;
        const auto flow = proof ? hs::ReplayStoreFlow::SUCCESSOR_PROBE : hs::ReplayStoreFlow::COMMITMENT_PROBE;
        const uint32_t status = proof ? (!first ? 0 : second ? 1 : 2) : (first ? 1 : second ? 2 : 0);
        std::vector<uint32_t> expected{1};
        if (first == proof) expected.push_back(2);
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            std::vector<uint32_t> trace;
            const auto probe = [&] {
                return hs::ParentReplayStore(flow,[&](uint32_t step) -> uint32_t {
                    trace.push_back(step);
                    if (trace.size() == fault+1) throw std::runtime_error("probe fault");
                    switch (step) {
                    case 1: return first;
                    case 2: return second;
                    default: throw std::logic_error("unexpected wait probe action");
                    }
                });
            };
            if (fault == expected.size()) {
                std::vector<uint32_t> outer;
                BOOST_CHECK_EQUAL(hs::BmmWait([&](uint32_t step) -> int32_t {
                    outer.push_back(step);
                    if (step == 2) return probe();
                    if (step == 6) return 0;
                    return 1;
                }),status == 1);
                const std::vector<uint32_t> expected_outer = status == 1 ?
                    std::vector<uint32_t>{1,2,4} : std::vector<uint32_t>{1,2,3,6};
                BOOST_CHECK(outer == expected_outer);
            } else BOOST_CHECK_EXCEPTION(probe(),std::runtime_error,[](const std::runtime_error& error) {
                return std::string(error.what()) == "probe fault";
            });
            const std::vector<uint32_t> prefix(expected.begin(),expected.begin()+std::min(fault+1,expected.size()));
            BOOST_CHECK(trace == prefix);
        }
    }
}

BOOST_AUTO_TEST_CASE(funded_bid_and_template_creation_order)
{
    namespace hs = drivechain::haskell;
    for (unsigned flags = 0; flags < 8; ++flags) {
        const bool current = flags & 1, submitted = flags & 2, creation = flags & 4;
        const auto flow = creation ? hs::ReplayStoreFlow::TEMPLATE_CREATION : hs::ReplayStoreFlow::FUNDED_SUBMISSION;
        std::vector<uint32_t> expected{1};
        if (creation) {
            if (!current) expected.push_back(2);
            else { expected.push_back(3); if (!submitted) expected.push_back(4); }
        } else if (current) expected.insert(expected.end(),{2,submitted ? 4U : 3U});
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            std::vector<uint32_t> trace;
            const auto invoke = [&] {
                return hs::ParentReplayStore(flow,[&](uint32_t step) -> uint32_t {
                    trace.push_back(step);
                    if (trace.size() == fault+1) throw std::runtime_error("funded bid fault");
                    switch (step) {
                    case 1: return current;
                    case 2: return creation ? 1 : submitted;
                    case 3: return creation ? (submitted ? 2 : 0) : 1;
                    case 4: return 1;
                    default: throw std::logic_error("unexpected funded submission action");
                    }
                });
            };
            if (fault == expected.size()) BOOST_CHECK_EQUAL(invoke(),current && submitted);
            else BOOST_CHECK_EXCEPTION(invoke(),std::runtime_error,[](const std::runtime_error& error) {
                return std::string(error.what()) == "funded bid fault";
            });
            const std::vector<uint32_t> prefix(expected.begin(),expected.begin()+std::min(fault+1,expected.size()));
            BOOST_CHECK(trace == prefix);
        }
    }
}

BOOST_AUTO_TEST_CASE(automatic_bidding_requires_selected_transactions)
{
    namespace hs = drivechain::haskell;
    for (const bool ecx : {false, true}) {
        for (const uint32_t candidate : {0U, 1U, 2U}) {
            unsigned templates{0}, bids{0}, waits{0}, accepts{0};
            bool mempool_has_transactions = candidate == 2;
            const bool produced = hs::BmmProduction(ecx, [&](uint32_t stage) {
                if (stage == (ecx ? 5U : 4U)) {
                    ++templates;
                    return hs::ParentReplayStore(hs::ReplayStoreFlow::TEMPLATE_CREATION,
                        [&](uint32_t step) -> uint32_t { return step == 3 ? candidate : 1; }) != 0;
                }
                if (stage == (ecx ? 10U : 7U)) {
                    ++bids;
                    BOOST_CHECK(mempool_has_transactions);
                    mempool_has_transactions = false;
                }
                // A paid candidate must finish even if the mempool changes while waiting.
                if (stage == (ecx ? 11U : 8U)) ++waits;
                if (stage == (ecx ? 13U : 9U)) ++accepts;
                return true;
            });
            BOOST_CHECK_EQUAL(templates, 1U);
            BOOST_CHECK_EQUAL(produced, candidate == 2);
            BOOST_CHECK_EQUAL(bids, candidate == 2 ? 1U : 0U);
            BOOST_CHECK_EQUAL(waits, bids);
            BOOST_CHECK_EQUAL(accepts, bids);
        }
    }
}

BOOST_AUTO_TEST_CASE(bid_preparation_required_pair)
{
    namespace hs = drivechain::haskell;
    for (const std::string input : {"invalid", "0", "1000"}) {
        for (const CAmount fees : {-1, 0, 2500}) {
            CAmount configured{42}, selected{43};
            std::string error;
            std::vector<uint32_t> trace;
            const auto prepare = [&] {
                return hs::ParentReplayStore(hs::ReplayStoreFlow::REQUIRED_PAIR,[&](uint32_t step) -> uint32_t {
                    trace.push_back(step);
                    switch (step) {
                    case 1: return ParseDrivechainBmmBid(input,configured,&error);
                    case 2: return ComputeDrivechainBmmBid(configured,fees,selected,&error);
                    case 3: throw std::runtime_error(error);
                    default: throw std::logic_error("unexpected preparation action");
                    }
                });
            };
            const bool parsed = input == "1000", valid = parsed && fees >= 0;
            if (valid) BOOST_CHECK(prepare());
            else BOOST_CHECK_EXCEPTION(prepare(),std::runtime_error,[&](const std::runtime_error& failure) {
                return !error.empty() && failure.what() == error;
            });
            BOOST_CHECK_EQUAL(configured,parsed ? 1000 : 42);
            BOOST_CHECK_EQUAL(selected,valid ? std::max<CAmount>(1000,fees) : 43);
            std::vector<uint32_t> expected{1};
            if (parsed) expected.push_back(2);
            if (!valid) expected.push_back(3);
            BOOST_CHECK(trace == expected);
        }
    }
}

BOOST_AUTO_TEST_CASE(configured_bid_default_and_explicit_paths)
{
    namespace hs = drivechain::haskell;
    for (unsigned flags = 0; flags < 8; ++flags) {
        const bool configured = flags & 1, valid = flags & 2, diagnostic = flags & 4;
        CAmount bid{42};
        std::string message{"stale"};
        std::string* error = diagnostic ? &message : nullptr;
        std::vector<uint32_t> trace;
        const bool result = hs::ParentReplayStore(hs::ReplayStoreFlow::CONFIGURED_BID,[&](uint32_t step) -> uint32_t {
            trace.push_back(step);
            switch (step) {
            case 1: return configured;
            case 2: return ParseDrivechainBmmBid(valid ? "1000" : "invalid",bid,error);
            case 3: bid = DEFAULT_DRIVECHAIN_BMM_BID; return 1;
            case 4: return error != nullptr;
            case 5: error->clear(); return 1;
            default: throw std::logic_error("unexpected configured bid action");
            }
        });
        BOOST_CHECK_EQUAL(result,!configured || valid);
        BOOST_CHECK_EQUAL(bid,!configured ? DEFAULT_DRIVECHAIN_BMM_BID : valid ? 1000 : 42);
        BOOST_CHECK_EQUAL(message,!diagnostic ? "stale" : !configured || valid ? "" : "BMM bid must be a canonical base-10 integer");
        std::vector<uint32_t> expected{1};
        if (configured) expected.push_back(2);
        else { expected.insert(expected.end(),{3,4}); if (diagnostic) expected.push_back(5); }
        BOOST_CHECK(trace == expected);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_bmm_wait_workflow)
{
    for (const uint32_t failed_log : {3U,4U,5U}) {
        bool failed{false};
        std::vector<uint32_t> trace;
        const bool result = drivechain::haskell::BmmWait([&](uint32_t step) -> int32_t {
            trace.push_back(step);
            if (step == failed_log && !failed) { failed = true; return 3; }
            if (step == 2) return failed_log == 4 ? 1 : failed_log == 5 ? 2 : 0;
            if (step == 6 && failed_log == 3) return 0;
            return 1;
        });
        const std::vector<uint32_t> expected = failed_log == 3 ? std::vector<uint32_t>{1,2,3,3,6} :
            failed_log == 4 ? std::vector<uint32_t>{1,2,4,3,6,1,2,4} :
            std::vector<uint32_t>{1,2,3,6,1,2,6,1,2,5,6,1,2,5};
        BOOST_CHECK_EQUAL(result,failed_log == 4);
        BOOST_CHECK(trace == expected);
    }
    for (const bool retain : {false,true}) {
        const std::vector<int32_t> probes{2,retain ? 3 : 0,2,2,1};
        size_t index{0};
        unsigned int logs{0},confirmed{0},abandoned{0};
        BOOST_CHECK_EQUAL(drivechain::haskell::BmmWait([&](uint32_t step) -> int32_t {
            switch (step) {
            case 1: case 6: return 1;
            case 2:
                // Real proof inspection reenters Haskell while the wait is active.
                if (drivechain::haskell::BmmSelectedBid(1,3) != 3) throw std::runtime_error("nested bid failed");
                return probes.at(index++);
            case 3: ++logs; return 1;
            case 4: ++confirmed; return 1;
            case 5: ++abandoned; return 1;
            default: throw std::logic_error("unexpected wait action");
            }
        }),!retain);
        BOOST_CHECK_EQUAL(index,retain ? 4U : 5U);
        BOOST_CHECK_EQUAL(logs,1U);
        BOOST_CHECK_EQUAL(confirmed,retain ? 0U : 1U);
        BOOST_CHECK_EQUAL(abandoned,retain ? 1U : 0U);
    }
    for (uint32_t fault=1; fault<=6; ++fault) {
        BOOST_CHECK_EXCEPTION(drivechain::haskell::BmmWait([&](uint32_t step) -> int32_t {
            if (step == fault) throw std::runtime_error("wait effect failure");
            if (step == 2) return fault == 4 ? 1 : fault == 5 ? 2 : 0;
            return 1;
        }),std::runtime_error,[](const std::runtime_error& error) {
            return std::string(error.what()) == "wait effect failure";
        });
    }
}

BOOST_AUTO_TEST_CASE(drivechain_production_stages)
{
    namespace hs = drivechain::haskell;
    for (const bool ecx : {false,true}) {
    const std::vector<uint32_t> stages = ecx ?
        std::vector<uint32_t>{1,19,2,20,3,15,4,5,6,16,7,8,9,17,10,18,11,12,13,14} :
        std::vector<uint32_t>{1,2,13,3,4,5,6,7,8,9,10};
    const std::map<uint32_t,uint32_t> reports = ecx ?
        std::map<uint32_t,uint32_t>{{1,101},{19,101},{2,102},{20,102},{3,103},{15,115},{4,104},
            {6,106},{16,116},{7,107},{9,109},{10,110},{12,112}} :
        std::map<uint32_t,uint32_t>{{1,101},{2,102},{13,102},{3,103},{6,106},{7,107}};
    for (size_t position=0; position<=stages.size(); ++position) {
        const uint32_t failure = position == stages.size() ? 0 : stages[position];
        std::vector<uint32_t> trace;
        std::vector<uint32_t> route;
        const bool result = hs::ParentReplayStore(hs::ReplayStoreFlow::PRODUCTION_ROUTING,[&](uint32_t step) -> uint32_t {
            route.push_back(step);
            if (step == 1) return !ecx;
            return hs::BmmProduction(ecx,[&](uint32_t stage) {
                trace.push_back(stage);
                if (stage == failure) return false;
                if (stage == (ecx ? 5U : 4U) && hs::BmmRewardAddress([](uint32_t) { return true; }) != 0)
                    throw std::runtime_error("nested reward failed");
                if (stage == (ecx ? 11U : 8U) && !hs::BmmWait([](uint32_t) -> int32_t { return 1; }))
                    throw std::runtime_error("nested wait failed");
                if (stage == (ecx ? 8U : 5U)) return hs::ParentReplayStore(
                    hs::ReplayStoreFlow::BLOCK_PREPARATION,[](uint32_t) -> uint32_t { return 1; }) != 0;
                if (stage == (ecx ? 13U : 9U)) return hs::ParentReplayStore(
                    hs::ReplayStoreFlow::BLOCK_ACCEPTANCE,[](uint32_t) -> uint32_t { return 1; }) != 0;
                return true;
            });
        });
        BOOST_CHECK_EQUAL(result,failure == 0);
        const std::vector<uint32_t> expected_route{1,ecx ? 3U : 2U};
        BOOST_CHECK(route == expected_route);
        std::vector<uint32_t> expected(stages.begin(),stages.begin()+std::min(position+1,stages.size()));
        if (const auto report = reports.find(failure); report != reports.end()) expected.push_back(report->second);
        BOOST_CHECK(trace == expected);
    }
    for (size_t position=0; position<stages.size(); ++position) {
        const auto failure = stages[position];
        uint32_t calls{0};
        BOOST_CHECK_EXCEPTION(drivechain::haskell::BmmProduction(ecx,[&](uint32_t stage) {
            ++calls;
            if (stage == failure) throw std::runtime_error("production failure");
            return true;
        }),std::runtime_error,[](const std::runtime_error& error) { return std::string(error.what()) == "production failure"; });
        BOOST_CHECK_EQUAL(calls,position+1);
    }
    for (const auto& [failure,report] : reports) {
        std::vector<uint32_t> trace;
        BOOST_CHECK_EXCEPTION(drivechain::haskell::BmmProduction(ecx,[&](uint32_t stage) {
            trace.push_back(stage);
            if (stage == report) throw std::runtime_error("production report failure");
            return stage != failure;
        }),std::runtime_error,[](const std::runtime_error& error) { return std::string(error.what()) == "production report failure"; });
        const auto rejected = std::find(stages.begin(),stages.end(),failure);
        BOOST_REQUIRE(rejected != stages.end());
        std::vector<uint32_t> expected(stages.begin(),rejected+1);
        expected.push_back(report);
        BOOST_CHECK(trace == expected);
    }
    }
}

BOOST_AUTO_TEST_CASE(drivechain_replay_leader_batch)
{
    const std::vector<uint16_t> values{0,1,49,50,51,65534,65535};
    std::vector<unsigned char> hashes;
    for (unsigned char i = 0; i < 3; ++i) hashes.insert(hashes.end(),32,i);
    BOOST_CHECK_EQUAL(drivechain::haskell::ReplayLeading({},{}),-1);
    for (const auto a : values) for (const auto b : values) for (const auto c : values) {
        std::vector<uint16_t> votes{a,b,c};
        const auto best = std::max_element(votes.begin(),votes.end());
        uint16_t runner{0};
        for (auto it = votes.begin(); it != votes.end(); ++it) if (it != best) runner = std::max(runner,*it);
        const int64_t expected = *best != UINT16_MAX && int(*best)-int(runner) >= 50 ? best-votes.begin() : -1;
        BOOST_CHECK_EQUAL(drivechain::haskell::ReplayLeading(hashes,votes),expected);
    }
    for (const auto value : values) {
        std::array<uint16_t,1> votes{value};
        BOOST_CHECK_EQUAL(drivechain::haskell::ReplayLeading(std::span{hashes}.first(32),votes),value >= 50 && value < UINT16_MAX ? 0 : -1);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_coinbase_collection_workflow)
{
    for (uint64_t count : {0,1,256,257,512,513}) {
        std::vector<std::pair<uint32_t,uint64_t>> seen, expected;
        for (uint64_t i = 0; i < count; ++i) {
            if (i % 256 == 0) expected.emplace_back(1,i);
            expected.emplace_back(2,i); expected.emplace_back(8,i);
        }
        BOOST_CHECK_EQUAL(drivechain::haskell::CoinbaseMessages(count,[&](uint32_t step,uint64_t index) -> int64_t {
            seen.emplace_back(step,index); return step == 2 ? 0 : 1;
        }),0);
        BOOST_CHECK(seen == expected);
    }
    for (uint32_t failed : {1,2,5,6,7,8}) {
        uint32_t last{0};
        BOOST_CHECK_THROW(drivechain::haskell::CoinbaseMessages(2,[&](uint32_t step,uint64_t index) -> int64_t {
            BOOST_CHECK_EQUAL(index,0); last = step;
            return step == failed ? -1 : step == 2 ? 5 : 1;
        }),std::runtime_error);
        BOOST_CHECK_EQUAL(last,failed);
        BOOST_CHECK_THROW(drivechain::haskell::CoinbaseMessages(2,[&](uint32_t step,uint64_t) -> int64_t {
            if (step == failed) throw std::logic_error("coinbase callback exception");
            return step == 2 ? 5 : 1;
        }),std::logic_error);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_m4_repeat_workflow)
{
    for (bool upvote : {false,true}) for (int64_t active : {0,1}) for (int64_t result : {0,1,2}) {
        std::vector<uint32_t> seen, expected{1};
        if (active) {
            expected.push_back(upvote ? 2 : 3);
            if (result == 1) expected.push_back(4);
        }
        const auto run = [&] {
            return drivechain::haskell::M4Repeat(upvote,[&](uint32_t step) -> int64_t {
                seen.push_back(step); return step == 1 ? active : step == 4 ? 1 : result;
            });
        };
        if (active && !upvote && result == 0) BOOST_CHECK_THROW(run(),std::runtime_error);
        else BOOST_CHECK_EQUAL(run(),!active ? 1 : result == 0 ? 2 : 0);
        BOOST_CHECK(seen == expected);
    }
    BOOST_CHECK_THROW(drivechain::haskell::M4Repeat(true,[](uint32_t) -> int64_t {
        throw std::logic_error("repeat effect exception");
    }),std::logic_error);
}

BOOST_AUTO_TEST_CASE(drivechain_m8_acceptance_workflow)
{
    for (uint64_t count : {0,1}) BOOST_CHECK_EQUAL(drivechain::haskell::M8Acceptance(count,
        [](uint32_t,uint64_t) -> int64_t { BOOST_FAIL("empty scan forced callback"); return -1; }),0);
    for (uint32_t failing = 0; failing <= 4; ++failing) {
        std::vector<std::pair<uint32_t,uint64_t>> seen, expected;
        for (uint64_t i = 1; i < 4; ++i) {
            for (uint32_t s = 1; s <= (i == 1 ? 2U : i == 2 && failing ? failing : 4U); ++s) expected.emplace_back(s,i);
            if (i == 2 && failing) break;
        }
        const auto run = [&] {
            return drivechain::haskell::M8Acceptance(4,[&](uint32_t stage,uint64_t index) -> int64_t {
                seen.emplace_back(stage,index);
                if (index == 2 && stage == failing) return -1;
                return index == 1 && stage == 2 ? 0 : 1;
            });
        };
        if (failing) BOOST_CHECK_THROW(run(),std::runtime_error);
        else BOOST_CHECK_EQUAL(run(),0);
        BOOST_CHECK(seen == expected);
    }
    for (uint32_t rejected : {3,4}) {
        BOOST_CHECK_EQUAL(drivechain::haskell::M8Acceptance(UINT64_MAX,[&](uint32_t stage,uint64_t index) -> int64_t {
            BOOST_CHECK_EQUAL(index,1);
            BOOST_CHECK(stage <= rejected);
            return stage == rejected ? 0 : 1;
        }),rejected-2);
    }
    BOOST_CHECK_THROW(drivechain::haskell::M8Acceptance(2,[](uint32_t,uint64_t) -> int64_t {
        throw std::logic_error("M8 deadline exception");
    }),std::logic_error);
}

BOOST_AUTO_TEST_CASE(drivechain_m2_proposal_workflow)
{
    for (int64_t proposed : {-2,95,96,98,99,100,101})
    for (uint32_t votes : {0U,1U,2U,65534U,65535U,UINT32_MAX}) for (bool used : {false,true})
    for (uint32_t flags = 0; flags < 8; ++flags) {
        std::vector<std::pair<uint32_t,uint64_t>> seen, expected{{1,0}};
        const uint32_t incremented = votes + 1;
        int status = 0;
        if (proposed > 100) status = 1;
        else if (proposed >= 0 && proposed != 100) {
            expected.emplace_back(2,0);
            expected.emplace_back(3,incremented);
            if (incremented > (used ? 2 : 1) && 100-proposed <= (used ? 2 : 4)) {
                expected.emplace_back(4,0); expected.emplace_back(5,0);
                if ((flags & 3) == 3 && !(flags & 4)) status = 2;
                if ((flags & 7) == 5) expected.emplace_back(6,0);
            }
        }
        const int actual = drivechain::haskell::M2Proposal(100,4,1,2,2,[&](uint32_t step,uint64_t value) -> int64_t {
            seen.emplace_back(step,value);
            switch (step) {
            case 1: return proposed;
            case 2: return votes;
            case 3: return used;
            case 5: return flags;
            default: return 1;
            }
        });
        BOOST_CHECK_EQUAL(actual,status);
        BOOST_CHECK(seen == expected);
    }
    for (uint32_t failed = 1; failed <= 6; ++failed) {
        uint32_t last{0};
        BOOST_CHECK_THROW(drivechain::haskell::M2Proposal(100,4,1,2,2,[&](uint32_t step,uint64_t) -> int64_t {
            last = step;
            if (step == failed) return -1;
            switch (step) { case 1: return 99; case 2: return 3; case 3: return 0; case 5: return 5; default: return 1; }
        }),std::runtime_error);
        BOOST_CHECK_EQUAL(last,failed);
        BOOST_CHECK_THROW(drivechain::haskell::M2Proposal(100,4,1,2,2,[&](uint32_t step,uint64_t) -> int64_t {
            if (step == failed) throw std::logic_error("activation effect exception");
            switch (step) { case 1: return 99; case 2: return 3; case 3: return 0; case 5: return 5; default: return 1; }
        }),std::logic_error);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_m4_mode_workflow)
{
    for (uint32_t flags = 0; flags < 16; ++flags) for (uint64_t votes : {0,1,2}) {
        uint32_t calls{0};
        const auto actual = drivechain::haskell::M4Mode(flags,votes,[&](uint32_t stage) -> int64_t {
            BOOST_CHECK_EQUAL(stage,1); ++calls; return 1;
        });
        const int expected = !(flags & 1) ? 4 : (flags & 2) ? 5 : (flags & 4) ? (votes == 1 ? 1 : 6) : (flags & 8) ? 2 : 3;
        BOOST_CHECK_EQUAL(actual,expected);
        BOOST_CHECK_EQUAL(calls,(flags & 1) && !(flags & 2) ? 1 : 0);
    }
    BOOST_CHECK_THROW(drivechain::haskell::M4Mode(16,0,[](uint32_t) -> int64_t {
        BOOST_FAIL("invalid flags forced slot lookup"); return 0;
    }),std::runtime_error);
    BOOST_CHECK_THROW(drivechain::haskell::M4Mode(5,0,[](uint32_t) -> int64_t { return -1; }),std::runtime_error);
    BOOST_CHECK_EQUAL(drivechain::haskell::M4Mode(5,UINT64_MAX,[](uint32_t) -> int64_t { return INT64_MAX; }),6);
    BOOST_CHECK_EQUAL(drivechain::haskell::M4Mode(5,INT64_MAX,[](uint32_t) -> int64_t { return INT64_MAX; }),1);
    BOOST_CHECK_THROW(drivechain::haskell::M4Mode(5,0,[](uint32_t) -> int64_t {
        throw std::logic_error("slot lookup exception");
    }),std::logic_error);
}

BOOST_AUTO_TEST_CASE(drivechain_m3_proposal_workflow)
{
    for (uint64_t match = 0; match <= 3; ++match) {
        std::vector<std::pair<uint32_t,uint64_t>> seen;
        const int result = drivechain::haskell::M3Proposal([&](uint32_t stage,uint64_t index) -> int64_t {
            seen.emplace_back(stage,index);
            if (stage == 2) return 3;
            if (stage == 3) return index == match;
            return 1;
        });
        std::vector<std::pair<uint32_t,uint64_t>> expected{{1,0},{2,0}};
        for (uint64_t i = 0; i < std::min<uint64_t>(3,match+1); ++i) expected.emplace_back(3,i);
        if (match == 3) { expected.emplace_back(4,0); expected.emplace_back(5,0); }
        BOOST_CHECK_EQUAL(result,match == 3 ? 0 : 2);
        BOOST_CHECK(seen == expected);
    }
    BOOST_CHECK_EQUAL(drivechain::haskell::M3Proposal([](uint32_t stage,uint64_t) -> int64_t {
        if (stage != 1) throw std::logic_error("inactive slot forced pending vector");
        return 0;
    }),1);
    for (uint32_t failed = 1; failed <= 5; ++failed) {
        uint32_t last{0};
        BOOST_CHECK_THROW(drivechain::haskell::M3Proposal([&](uint32_t stage,uint64_t) -> int64_t {
            last = stage;
            if (stage == failed) return -1;
            return stage == 3 ? 0 : 1;
        }),std::runtime_error);
        BOOST_CHECK_EQUAL(last,failed);
    }
    uint32_t calls{0};
    BOOST_CHECK_EQUAL(drivechain::haskell::M3Proposal([&](uint32_t stage,uint64_t index) -> int64_t {
        ++calls;
        BOOST_CHECK_EQUAL(index,0);
        return stage == 2 ? INT64_MAX : 1;
    }),2);
    BOOST_CHECK_EQUAL(calls,3);
    BOOST_CHECK_THROW(drivechain::haskell::M3Proposal([](uint32_t,uint64_t) -> int64_t {
        throw std::logic_error("M3 callback exception");
    }),std::logic_error);
}

BOOST_AUTO_TEST_CASE(drivechain_m6_id_workflow)
{
    for (bool has_slot : {false,true}) for (int64_t previous : {int64_t{100},INT64_MAX}) {
        std::vector<std::pair<uint32_t,uint64_t>> seen;
        BOOST_CHECK_EQUAL(drivechain::haskell::M6Id(3,1,previous,INT64_MAX,has_slot,
            [&](uint32_t stage,uint64_t value) -> int64_t {
                seen.emplace_back(stage,value);
                if (stage == 3) return 1;
                if (stage == 4) return 2;
                return 1;
            }),0);
        std::vector<std::pair<uint32_t,uint64_t>> expected{{1,0},{2,0},{3,0},{4,1},{4,2},{5,static_cast<uint64_t>(previous-5)}};
        if (has_slot) expected.emplace_back(6,0);
        BOOST_CHECK(seen == expected);
    }
    BOOST_CHECK_EQUAL(drivechain::haskell::M6Id(3,1,INT64_MAX,INT64_MAX,true,
        [](uint32_t stage,uint64_t) -> int64_t {
            if (stage == 3) return 0;
            return stage == 4 ? INT64_MAX : 1;
        }),5);
    for (uint32_t failed : {1,2,5,6}) {
        uint32_t last{0};
        BOOST_CHECK_THROW(drivechain::haskell::M6Id(1,1,1,100,true,
            [&](uint32_t stage,uint64_t) -> int64_t {
                last = stage; return stage == failed ? -1 : 1;
            }),std::runtime_error);
        BOOST_CHECK_EQUAL(last,failed);
    }
    uint32_t cleared{0};
    BOOST_CHECK_EQUAL(drivechain::haskell::M6Id(0,0,-1,100,true,
        [&](uint32_t stage,uint64_t) -> int64_t { cleared = stage; return 1; }),1);
    BOOST_CHECK_EQUAL(cleared,1);
    BOOST_CHECK_THROW(drivechain::haskell::M6Id(1,1,1,100,true,
        [](uint32_t,uint64_t) -> int64_t { throw std::logic_error("M6 callback exception"); }),std::logic_error);
}

BOOST_AUTO_TEST_CASE(drivechain_active_slot_selection)
{
    for (uint32_t configured = 0; configured < 256; ++configured) {
        std::vector<unsigned char> entries{static_cast<unsigned char>(configured),1};
        std::vector<unsigned char> expected{static_cast<unsigned char>(configured)};
        for (int slot = 255; slot >= 0; --slot) {
            entries.insert(entries.end(),{static_cast<unsigned char>(slot),static_cast<unsigned char>(slot%2)});
            if (slot%2) expected.push_back(slot);
        }
        std::sort(expected.begin(),expected.end());
        BOOST_CHECK(drivechain::haskell::ActiveSlots(entries) == expected);
    }
    BOOST_CHECK(drivechain::haskell::ActiveSlots({}).empty());
    const std::vector<unsigned char> inactive{24,0,0,0,255,0};
    BOOST_CHECK(drivechain::haskell::ActiveSlots(inactive).empty());
    const std::vector<unsigned char> odd{24};
    const std::vector<unsigned char> oversized(516,0);
    const std::vector<unsigned char> invalid{24,2};
    BOOST_CHECK_THROW(drivechain::haskell::ActiveSlots(odd),std::invalid_argument);
    BOOST_CHECK_THROW(drivechain::haskell::ActiveSlots(oversized),std::invalid_argument);
    BOOST_CHECK_THROW(drivechain::haskell::ActiveSlots(invalid),std::runtime_error);
}

BOOST_AUTO_TEST_CASE(drivechain_block_publication_workflow)
{
    for (uint32_t flags = 0; flags < 16; ++flags) {
        std::vector<uint32_t> seen;
        const bool actual = drivechain::haskell::BlockPublish(flags,[&](uint32_t stage) -> int32_t {
            seen.push_back(stage); return 1;
        });
        const bool accepted = !(flags & 1) || (flags & 2);
        std::vector<uint32_t> expected;
        if (accepted) {
            if (flags & 4) expected.push_back(1);
            if (flags & 8) expected.push_back(2);
            expected.push_back(3);
        }
        BOOST_CHECK_EQUAL(actual,accepted);
        BOOST_CHECK(seen == expected);
    }
    for (uint32_t failed = 1; failed <= 3; ++failed) for (int32_t result : {-1,0,2}) {
        uint32_t calls{0};
        BOOST_CHECK_THROW(drivechain::haskell::BlockPublish(15,[&](uint32_t stage) -> int32_t {
            ++calls; return stage == failed ? result : 1;
        }),std::runtime_error);
        BOOST_CHECK_EQUAL(calls,failed);
    }
    BOOST_CHECK_THROW(drivechain::haskell::BlockPublish(16,[](uint32_t) -> int32_t {
        BOOST_FAIL("invalid flags must not invoke callbacks"); return 1;
    }),std::runtime_error);
    std::vector<uint32_t> published;
    BOOST_CHECK_THROW(drivechain::haskell::BlockPublish(15,[&](uint32_t stage) -> int32_t {
        if (stage == 3) throw std::logic_error("deadline");
        published.push_back(stage); return 1;
    }),std::logic_error);
    BOOST_CHECK(published == std::vector<uint32_t>({1,2}));
}

BOOST_AUTO_TEST_CASE(drivechain_slot_pruning_workflow)
{
    std::map<uint32_t,int64_t> slots;
    for (uint32_t flags = 0; flags < 64; ++flags) slots[flags] = flags;
    slots[64] = 0;
    auto slot = slots.begin();
    std::vector<uint32_t> seen;
    drivechain::haskell::PruneSlots(slots.size(),[&](uint32_t stage) -> int64_t {
        seen.push_back(stage);
        BOOST_REQUIRE(slot != slots.end());
        switch (stage) {
        case 1: return slot->second;
        case 2: slot = slots.erase(slot); return 1;
        case 3: ++slot; return 1;
        default: BOOST_FAIL("invalid pruning stage"); return -1;
        }
    });
    BOOST_CHECK(slot == slots.end());
    BOOST_CHECK_EQUAL(slots.size(),63);
    BOOST_CHECK_EQUAL(slots.count(0),0);
    BOOST_CHECK_EQUAL(slots.count(64),0);
    BOOST_CHECK_EQUAL(seen.size(),130);
    for (uint32_t i = 0; i < 65; ++i) {
        BOOST_CHECK_EQUAL(seen[2*i],1);
        BOOST_CHECK_EQUAL(seen[2*i+1],i == 0 || i == 64 ? 2 : 3);
    }
    drivechain::haskell::PruneSlots(0,[](uint32_t) -> int64_t { throw std::logic_error("empty pruning forced"); });
    for (int64_t flags : {-1,64}) {
        uint32_t calls{0};
        BOOST_CHECK_THROW(drivechain::haskell::PruneSlots(UINT64_MAX,[&](uint32_t) -> int64_t {
            ++calls; return flags;
        }),std::runtime_error);
        BOOST_CHECK_EQUAL(calls,1);
    }
    for (int64_t flags : {0,1}) for (int64_t result : {-1,0,2}) {
        uint32_t calls{0};
        BOOST_CHECK_THROW(drivechain::haskell::PruneSlots(2,[&](uint32_t stage) -> int64_t {
            ++calls; return stage == 1 ? flags : result;
        }),std::runtime_error);
        BOOST_CHECK_EQUAL(calls,2);
    }
    BOOST_CHECK_THROW(drivechain::haskell::PruneSlots(1,[](uint32_t) -> int64_t {
        throw std::logic_error("pruning exception");
    }),std::logic_error);
}

BOOST_AUTO_TEST_CASE(drivechain_m6_withdrawal_workflow)
{
    for (bool single : {false,true}) for (bool configured : {false,true})
        for (bool applied : {false,true}) for (int64_t votes : {0,100,101,65535}) {
            std::vector<uint32_t> seen;
            const auto result = drivechain::haskell::M6Withdrawal(1,1,1,100,single,[&](uint32_t stage) -> int64_t {
                seen.push_back(stage);
                switch (stage) { case 1: return 0; case 5: return votes; case 6: return configured; case 7: return applied; default: return 1; }
            });
            std::vector<uint32_t> expected{1,2,3,4,5};
            int code{6};
            if (votes > 100) {
                expected.push_back(6);
                if (configured && single) expected.push_back(7);
                code = configured && single && applied ? 7 : 0;
                if (code == 0) {
                    if (configured) expected.push_back(8);
                    for (uint32_t stage = 9; stage <= 12; ++stage) expected.push_back(stage);
                }
            }
            BOOST_CHECK_EQUAL(result,code);
            BOOST_CHECK(seen == expected);
        }
    for (uint32_t failed = 1; failed <= 12; ++failed) {
        uint32_t last{0};
        BOOST_CHECK_THROW(drivechain::haskell::M6Withdrawal(1,1,1,100,true,[&](uint32_t stage) -> int64_t {
            last = stage;
            if (stage == failed) return -1;
            if (stage == 1 || stage == 7) return 0;
            return stage == 5 ? 101 : 1;
        }),std::runtime_error);
        BOOST_CHECK_EQUAL(last,failed);
    }
    for (uint32_t failed = 2; failed <= 4; ++failed) {
        uint32_t last{0};
        BOOST_CHECK_EQUAL(drivechain::haskell::M6Withdrawal(1,1,1,100,true,[&](uint32_t stage) -> int64_t {
            last = stage; return stage == 1 || stage == failed ? 0 : 1;
        }),failed+1);
        BOOST_CHECK_EQUAL(last,failed);
    }
    BOOST_CHECK_EQUAL(drivechain::haskell::M6Withdrawal(2,1,1,100,true,
        [](uint32_t) -> int64_t { throw std::logic_error("must stay lazy"); }),1);
    BOOST_CHECK_EQUAL(drivechain::haskell::M6Withdrawal(1,2,1,100,true,
        [](uint32_t) -> int64_t { throw std::logic_error("must stay lazy"); }),1);
    BOOST_CHECK_THROW(drivechain::haskell::M6Withdrawal(1,1,1,100,true,
        [](uint32_t) -> int64_t { throw std::logic_error("callback exception"); }),std::logic_error);
}

BOOST_AUTO_TEST_CASE(drivechain_m5_deposit_workflow)
{
    for (uint32_t flags = 0; flags < 8; ++flags) for (int64_t size : {0,1,128,129}) {
        std::vector<uint32_t> actions;
        uint64_t published{0};
        BOOST_CHECK_EQUAL(drivechain::haskell::M5Deposit(0,100,100,0,2,flags,[&](uint32_t stage,uint64_t value) -> int64_t {
            actions.push_back(stage); if (stage == 5) published = value; return stage == 4 ? size : 1;
        }),0);
        std::vector<uint32_t> expected{1,2,3};
        const bool publish = flags == 7 && size > 0 && size <= 128;
        if (flags == 7) expected.push_back(4);
        if (publish) expected.push_back(5);
        BOOST_CHECK(actions == expected);
        BOOST_CHECK_EQUAL(published,publish ? 100 : 0);
    }
    BOOST_CHECK_EQUAL(drivechain::haskell::M5Deposit(0,1,100,UINT64_MAX,UINT64_MAX,7,
        [](uint32_t,uint64_t) -> int64_t { throw std::logic_error("missing address"); }),1);
    for (uint32_t failed : {1,2,3,4,5}) {
        uint32_t last{0};
        BOOST_CHECK_THROW(drivechain::haskell::M5Deposit(0,1,100,0,2,7,[&](uint32_t stage,uint64_t) -> int64_t {
            last = stage; return stage == failed ? -1 : 1;
        }),std::runtime_error);
        BOOST_CHECK_EQUAL(last,failed);
    }
    BOOST_CHECK_EQUAL(drivechain::haskell::M5Deposit(INT64_MIN,INT64_MAX,UINT64_MAX,0,2,7,
        [](uint32_t,uint64_t) -> int64_t { return 1; }),2);
}

BOOST_AUTO_TEST_CASE(drivechain_ctip_changes_workflow)
{
    const std::array<int64_t,6> amounts{0,1,2,-1,INT64_MIN,INT64_MAX};
    for (bool present : {false,true}) for (bool spent : {false,true})
        for (auto old : amounts) for (auto next : amounts) {
            std::vector<uint32_t> actions;
            const auto result = drivechain::haskell::CtipChanges(1,[&](uint32_t stage) -> int64_t {
                actions.push_back(stage);
                switch (stage) { case 1: return present; case 2: return spent; case 3: return old; case 5: return next; default: return 1; }
            });
            std::vector<uint32_t> expected{1};
            int code{0};
            if (present) expected.push_back(2);
            if (present && !spent) code = 1;
            else {
                const auto previous = present ? old : 0;
                expected.push_back(present ? 3 : 4); expected.push_back(5);
                if (previous == next) code = 2;
                else {
                    if (static_cast<uint64_t>(next) < static_cast<uint64_t>(previous)) expected.push_back(6);
                    expected.push_back(7);
                }
            }
            BOOST_CHECK_EQUAL(result,code);
            BOOST_CHECK(actions == expected);
        }
    BOOST_CHECK_EQUAL(drivechain::haskell::CtipChanges(0,[](uint32_t) -> int64_t { throw std::logic_error("empty"); }),0);
    for (uint32_t failed : {1,2,4,6,7}) {
        uint32_t last{0};
        BOOST_CHECK_THROW(drivechain::haskell::CtipChanges(2,[&](uint32_t stage) -> int64_t {
            last = stage;
            if (stage == failed) return -1;
            if (stage == 1 && failed == 4) return 0;
            return stage == 3 ? 2 : 1;
        }),std::runtime_error);
        BOOST_CHECK_EQUAL(last,failed);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_ctip_replacements_workflow)
{
    for (unsigned mask = 0; mask < 256; ++mask) {
        unsigned index{0};
        std::vector<uint32_t> actions, expected;
        const auto result = drivechain::haskell::CtipReplacements(4,[&](uint32_t stage) -> int32_t {
            actions.push_back(stage);
            if (stage == 1) return (mask >> (2*index)) & 1;
            if (stage == 2) return (mask >> (2*index+1)) & 1;
            ++index; return 1;
        });
        int code{0};
        for (unsigned i = 0; i < 4; ++i) {
            expected.push_back(1);
            if ((mask >> (2*i)) & 1) {
                expected.push_back(2);
                if (!((mask >> (2*i+1)) & 1)) { code = 1; break; }
            }
            expected.push_back(3);
        }
        BOOST_CHECK_EQUAL(result,code);
        BOOST_CHECK(actions == expected);
    }
    BOOST_CHECK_EQUAL(drivechain::haskell::CtipReplacements(0,[](uint32_t) -> int32_t { throw std::logic_error("empty"); }),0);
    for (uint32_t failed : {1,2,3}) {
        std::vector<uint32_t> actions;
        BOOST_CHECK_THROW(drivechain::haskell::CtipReplacements(2,[&](uint32_t stage) -> int32_t {
            actions.push_back(stage); return stage == failed ? -1 : 1;
        }),std::runtime_error);
        BOOST_CHECK_EQUAL(actions.size(),failed);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_ctip_outputs_workflow)
{
    for (bool treasury : {false,true}) for (bool active : {false,true})
        for (int64_t value : {-1,0,1,100,101}) for (bool inserted : {false,true}) {
            std::vector<uint32_t> actions;
            const auto result = drivechain::haskell::CtipOutputs(1,100,[&](uint32_t stage,uint64_t) -> int64_t {
                actions.push_back(stage);
                switch (stage) { case 1: return 1; case 2: return treasury; case 3: return active; case 4: return value; case 5: return inserted; }
                throw std::logic_error("unexpected output action");
            });
            const bool valid = value >= 0 && value <= 100;
            BOOST_CHECK_EQUAL(result,!treasury || !active ? 0 : !valid ? 1 : !inserted ? 2 : 0);
            std::vector<uint32_t> expected{1,2};
            if (treasury) expected.push_back(3);
            if (treasury && active) { expected.push_back(4); if (valid) expected.push_back(5); }
            BOOST_CHECK(actions == expected);
        }
    for (uint32_t failed : {1,2,3,5})
        BOOST_CHECK_THROW(drivechain::haskell::CtipOutputs(2,100,[&](uint32_t stage,uint64_t) -> int64_t {
            return stage == failed ? -1 : 1;
        }),std::runtime_error);
    BOOST_CHECK_THROW(drivechain::haskell::CtipOutputs(uint64_t{UINT32_MAX}+1,100,[](uint32_t,uint64_t) -> int64_t {
        throw std::logic_error("oversized callback");
    }),std::runtime_error);
    std::vector<uint64_t> deadlines;
    BOOST_CHECK_EQUAL(drivechain::haskell::CtipOutputs(257,100,[&](uint32_t stage,uint64_t index) -> int64_t {
        if (stage == 1) { deadlines.push_back(index); return 1; }
        return 0;
    }),0);
    BOOST_CHECK(deadlines == (std::vector<uint64_t>{0,256}));
}

BOOST_AUTO_TEST_CASE(drivechain_ctip_spends_workflow)
{
    for (uint64_t count : {0,1,255,256,257,513}) {
        std::vector<uint64_t> deadlines, inspected;
        BOOST_CHECK_EQUAL(drivechain::haskell::CtipSpends(count,[&](uint32_t stage,uint64_t index) -> int32_t {
            if (stage == 1) { deadlines.push_back(index); return 1; }
            if (stage == 2) { inspected.push_back(index); return 0; }
            throw std::logic_error("unexpected spend update");
        }),0);
        BOOST_CHECK_EQUAL(inspected.size(),count);
        for (uint64_t i = 0; i < count; ++i) BOOST_CHECK_EQUAL(inspected[i],i);
        std::vector<uint64_t> expected;
        for (uint64_t i = 0; i < count; i += 256) expected.push_back(i);
        BOOST_CHECK(deadlines == expected);
    }
    unsigned spent{0};
    uint64_t last{0};
    BOOST_CHECK_EQUAL(drivechain::haskell::CtipSpends(5,[&](uint32_t stage,uint64_t index) -> int32_t {
        last = index; return stage == 3 ? ++spent : 1;
    }),1);
    BOOST_CHECK_EQUAL(spent,2);
    BOOST_CHECK_EQUAL(last,1);
    for (uint32_t failed : {1,2,3}) {
        uint32_t last_stage{0};
        BOOST_CHECK_THROW(drivechain::haskell::CtipSpends(5,[&](uint32_t stage,uint64_t) -> int32_t {
            last_stage = stage; return stage == failed ? -1 : 1;
        }),std::runtime_error);
        BOOST_CHECK_EQUAL(last_stage,failed);
    }
    BOOST_CHECK_THROW(drivechain::haskell::CtipSpends(1,[](uint32_t,uint64_t) -> int32_t { throw std::logic_error("deadline"); }),std::logic_error);
}

BOOST_AUTO_TEST_CASE(drivechain_ctip_ownership_workflow)
{
    for (bool present : {false,true}) for (int64_t value : {-1,0,1,100,101}) for (bool inserted : {false,true}) {
        std::vector<uint32_t> actions;
        const int actual = drivechain::haskell::CtipOwners(1,100,[&](uint32_t stage) -> int64_t {
            actions.push_back(stage);
            switch (stage) { case 1: return present; case 2: return value; case 3: return inserted; case 4: return 1; }
            throw std::logic_error("unexpected ownership action");
        });
        const bool valid = present ? value >= 0 && value <= 100 : value == 0;
        BOOST_CHECK_EQUAL(actual,!valid ? 1 : present && !inserted ? 2 : 0);
        std::vector<uint32_t> expected{1,2};
        if (valid) {
            if (present) expected.push_back(3);
            if (!present || inserted) expected.push_back(4);
        }
        BOOST_CHECK(actions == expected);
    }
    BOOST_CHECK_EQUAL(drivechain::haskell::CtipOwners(0,0,[](uint32_t) -> int64_t { throw std::logic_error("unreachable"); }),0);
    BOOST_CHECK_THROW(drivechain::haskell::CtipOwners(1,100,[](uint32_t) -> int64_t { throw std::logic_error("callback"); }),std::logic_error);
    for (uint32_t failed : {1,3,4}) {
        std::vector<uint32_t> actions;
        BOOST_CHECK_THROW(drivechain::haskell::CtipOwners(2,100,[&](uint32_t stage) -> int64_t {
            actions.push_back(stage);
            return stage == failed ? -1 : 1;
        }),std::runtime_error);
        BOOST_CHECK_EQUAL(actions.back(),failed);
        BOOST_CHECK_EQUAL(actions.size(),failed);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_withdrawal_expiry_workflow)
{
    for (uint32_t height : std::array<uint32_t,4>{0,10,11,UINT32_MAX})
        for (uint32_t proposed : std::array<uint32_t,4>{0,10,11,UINT32_MAX}) {
            std::vector<uint32_t> actions;
            const auto result = drivechain::haskell::ExpireWithdrawals(1,height,10,[&](uint32_t stage) -> int64_t {
                actions.push_back(stage);
                return stage == 1 ? proposed : 1;
            });
            BOOST_CHECK_EQUAL(result,proposed > height ? 1 : 0);
            const std::vector<uint32_t> expected = proposed > height ? std::vector<uint32_t>{1}
                : std::vector<uint32_t>{1,height-proposed > 10 ? 3U : 4U};
            BOOST_CHECK(actions == expected);
        }
    BOOST_CHECK_EQUAL(drivechain::haskell::ExpireWithdrawals(0,0,0,[](uint32_t) -> int64_t { throw std::logic_error("unreachable"); }),0);
    BOOST_CHECK_THROW(drivechain::haskell::ExpireWithdrawals(1,0,0,[](uint32_t) -> int64_t { throw std::logic_error("callback"); }),std::logic_error);
    std::vector<uint32_t> actions;
    BOOST_CHECK_THROW(drivechain::haskell::ExpireWithdrawals(2,100,10,[&](uint32_t stage) -> int64_t {
        actions.push_back(stage); return 0;
    }),std::runtime_error);
    BOOST_CHECK(actions == (std::vector<uint32_t>{1,3}));
}

BOOST_AUTO_TEST_CASE(drivechain_proposal_expiry_workflow)
{
    for (uint32_t height : std::array<uint32_t,6>{0,9,10,11,100,UINT32_MAX})
        for (uint32_t proposed : std::array<uint32_t,6>{0,9,10,11,100,UINT32_MAX}) for (int64_t votes : {0,1,5,10,65535}) {
            std::vector<uint32_t> actions;
            const int result = drivechain::haskell::ExpireProposals(1,height,5,10,[&](uint32_t action) -> int64_t {
                actions.push_back(action);
                return action == 1 ? proposed : action == 2 ? votes : 1;
            });
            if (proposed > height) {
                BOOST_CHECK_EQUAL(result,1);
                BOOST_CHECK(actions == std::vector<uint32_t>{1});
            } else if (static_cast<uint64_t>(votes) > height-proposed) {
                BOOST_CHECK_EQUAL(result,2);
                BOOST_CHECK(actions == (std::vector<uint32_t>{1,2}));
            } else {
                const auto age = height-proposed;
                const uint32_t effect = age > 10 || (age > 5 && age-votes >= 5) ? 3 : 4;
                BOOST_CHECK_EQUAL(result,0);
                BOOST_CHECK(actions == (std::vector<uint32_t>{1,2,effect}));
            }
        }
    BOOST_CHECK_EQUAL(drivechain::haskell::ExpireProposals(0,0,0,0,[](uint32_t) -> int64_t { throw std::logic_error("unreachable"); }),0);
    BOOST_CHECK_THROW(drivechain::haskell::ExpireProposals(1,10,5,10,[](uint32_t) -> int64_t { throw std::logic_error("callback failure"); }),std::logic_error);
    BOOST_CHECK_THROW(drivechain::haskell::ExpireProposals(1,10,5,10,[](uint32_t) -> int64_t { return -1; }),std::runtime_error);
}

BOOST_AUTO_TEST_CASE(proposal_expiry_preserves_slot_order_and_partial_mutations)
{
    for (unsigned first = 0; first < 4; ++first) for (unsigned second = 0; second < 4; ++second) {
        std::array<std::vector<std::pair<uint32_t, uint16_t>>, 2> pending;
        const std::array<unsigned, 2> shapes{first, second};
        for (unsigned i = 0; i < 2; ++i) if (shapes[i])
            pending[i].emplace_back(shapes[i] == 2 ? 21 : 0, shapes[i] == 3 ? 21 : 0);
        std::vector<unsigned> visits;
        std::array<int, 2> results{-1, -1};
        const auto expire = [&](unsigned slot) {
            visits.push_back(slot);
            auto it = pending[slot].begin();
            results[slot] = drivechain::haskell::ExpireProposals(pending[slot].size(), 20, 5, 10,
                [&](uint32_t action) -> int64_t {
                    switch (action) {
                    case 1: return it->first;
                    case 2: return it->second;
                    case 3: it = pending[slot].erase(it); return 1;
                    case 4: ++it; return 1;
                    default: throw std::logic_error("unexpected expiry action");
                    }
                });
            return results[slot] == 0;
        };
        const bool accepted = drivechain::haskell::ParentReplayAll<2>({
            [&] { return expire(0); }, [&] { return expire(1); },
        });
        BOOST_CHECK_EQUAL(accepted, first < 2 && second < 2);
        BOOST_CHECK(visits == (first < 2 ? std::vector<unsigned>{0, 1} : std::vector<unsigned>{0}));
        BOOST_CHECK_EQUAL(pending[0].size(), first >= 2 ? 1U : 0U);
        BOOST_CHECK_EQUAL(pending[1].size(), first >= 2 ? unsigned(second != 0) : unsigned(second >= 2));
        BOOST_CHECK_EQUAL(results[0], first < 2 ? 0 : first - 1);
        BOOST_CHECK_EQUAL(results[1], first >= 2 ? -1 : second < 2 ? 0 : int(second - 1));
    }
}

BOOST_AUTO_TEST_CASE(drivechain_replay_leading_workflow)
{
    const std::vector<uint16_t> values{0,1,49,50,51,65534,65535};
    BOOST_CHECK_EQUAL(drivechain::haskell::ReplayLeading({},{}),-1);
    for (unsigned mask = 0; mask < 8; ++mask)
        for (auto a : values) for (auto b : values) for (auto c : values) {
            std::vector<unsigned char> hashes;
            for (unsigned i = 0; i < 3; ++i) hashes.insert(hashes.end(),32,(mask >> i) & 1);
            std::vector<uint16_t> votes{a,b,c};
            auto expected = votes;
            const auto best = std::max_element(votes.begin(),votes.end());
            uint16_t runner{0};
            for (auto it = votes.begin(); it != votes.end(); ++it) if (it != best) runner = std::max(runner,*it);
            const int64_t leader = *best != UINT16_MAX && int(*best)-int(runner) >= 50 ? best-votes.begin() : -1;
            if (leader >= 0) {
                size_t target{0};
                while (hashes[32*target] != hashes[32*leader]) ++target;
                for (size_t i = 0; i < expected.size(); ++i)
                    expected[i] = i == target ? expected[i]+1 : expected[i] ? expected[i]-1 : 0;
            }
            BOOST_CHECK_EQUAL(drivechain::haskell::ReplayLeading(hashes,votes),leader);
            BOOST_CHECK(votes == expected);
        }
    std::vector<uint16_t> votes{50};
    BOOST_CHECK_THROW(drivechain::haskell::ReplayLeading({},votes),std::invalid_argument);
    BOOST_CHECK_EQUAL(votes[0],50);
}

BOOST_AUTO_TEST_CASE(drivechain_replay_explicit_workflow)
{
    for (unsigned mask = 0; mask < 8; ++mask)
        for (uint16_t a : {0,1,65534,65535}) for (uint16_t b : {0,1,65534,65535})
            for (uint16_t vote : {0,1,2,3,65534,65535}) {
                std::vector<unsigned char> hashes;
                for (unsigned i = 0; i < 3; ++i) hashes.insert(hashes.end(),32,(mask >> i) & 1);
                std::vector<uint16_t> values{a,b,0};
                auto expected = values;
                int code{0};
                if (vote == 65534) {
                    code = a || b ? 2 : 0;
                    for (auto& value : expected) if (value) --value;
                } else if (vote != 65535) {
                    if (vote >= expected.size()) code = 3;
                    else {
                        size_t selected{0};
                        while (hashes[selected*32] != hashes[vote*32]) ++selected;
                        if (expected[selected] < UINT16_MAX) {
                            code = 1;
                            for (size_t i = 0; i < expected.size(); ++i)
                                expected[i] = i == selected ? expected[i]+1 : expected[i] ? expected[i]-1 : 0;
                        }
                    }
                }
                BOOST_CHECK_EQUAL(drivechain::haskell::ReplayExplicit(vote,hashes,values),code);
                BOOST_CHECK(values == expected);
            }
    BOOST_CHECK_EQUAL(drivechain::haskell::ReplayExplicit(0,{},{}),3);
    BOOST_CHECK_EQUAL(drivechain::haskell::ReplayExplicit(65534,{},{}),0);
    BOOST_CHECK_EQUAL(drivechain::haskell::ReplayExplicit(65535,{},{}),0);
}

BOOST_AUTO_TEST_CASE(drivechain_replay_alarm_batch)
{
    for (unsigned mask = 0; mask < 256; ++mask) for (uint16_t value : {uint16_t{1},uint16_t{65535}}) {
        std::array<uint16_t,8> votes{};
        for (unsigned i = 0; i < votes.size(); ++i) if ((mask >> i) & 1) votes[i] = value;
        auto expected = votes;
        for (auto& vote : expected) if (vote) --vote;
        BOOST_CHECK_EQUAL(drivechain::haskell::ReplayAlarm(votes),mask != 0);
        BOOST_CHECK(votes == expected);
    }
    BOOST_CHECK(!drivechain::haskell::ReplayAlarm({}));
}

BOOST_AUTO_TEST_CASE(drivechain_replay_upvote_batch)
{
    for (size_t count = 0; count < 10; ++count) for (unsigned char target = 0; target < 4; ++target)
        for (uint16_t initial : {uint16_t{0},uint16_t{1},uint16_t{65534},uint16_t{65535}}) {
            std::vector<unsigned char> hashes;
            std::vector<uint16_t> votes(count,initial);
            for (size_t i = 0; i < count; ++i) hashes.insert(hashes.end(),32,i%3);
            auto expected = votes;
            size_t selected{0};
            while (selected < count && selected%3 != target) ++selected;
            const int code = selected == count ? 0 : expected[selected] == UINT16_MAX ? 2 : 1;
            if (code == 1) {
                ++expected[selected];
                for (size_t i = 0; i < count; ++i) if (i != selected && expected[i]) --expected[i];
            }
            std::array<unsigned char,32> key;
            key.fill(target);
            BOOST_CHECK_EQUAL(drivechain::haskell::ReplayUpvote(hashes,key,votes),code);
            BOOST_CHECK(votes == expected);
        }
    std::array<unsigned char,32> key{};
    std::vector<uint16_t> votes{1};
    BOOST_CHECK_THROW(drivechain::haskell::ReplayUpvote({},key,votes),std::invalid_argument);
    BOOST_CHECK_EQUAL(votes[0],1);
}

BOOST_AUTO_TEST_CASE(drivechain_raw_deposit_match_workflow)
{
    const std::vector<int64_t> success{0,1,0,1,1,1,0,1};
    for (uint32_t stage = 1; stage <= 8; ++stage) {
        for (const int64_t fact : std::vector<int64_t>{-1,0,1,2,INT64_MAX}) {
            uint32_t calls{0};
            const int expected = stage == 1 ? (fact == 0 ? 0 : fact == 1 ? 3 : fact == 2 ? 2 : -1) :
                fact < 0 || (stage != 6 && stage != 7 && fact > 1) ? -1 :
                (stage == 3 ? fact == 0 : stage == 7 ? fact <= 1 : fact == 1) ? 0 : stage+1;
            const auto run = [&] { return drivechain::haskell::DepositMatch(24,1,100,true,[&](uint32_t step) {
                BOOST_CHECK_EQUAL(step,++calls);
                return step == stage ? fact : success[step-1];
            }); };
            if (expected < 0) BOOST_CHECK_THROW(run(),std::runtime_error);
            else BOOST_CHECK_EQUAL(run(),expected);
            BOOST_CHECK_EQUAL(calls,expected == 0 ? 8 : stage);
        }
        uint32_t calls{0};
        BOOST_CHECK_EXCEPTION(drivechain::haskell::DepositMatch(24,1,100,true,[&](uint32_t step) {
            ++calls;
            if (step == stage) throw std::runtime_error("match effect failure");
            return success[step-1];
        }),std::runtime_error,[](const std::runtime_error& error) {
            return std::string(error.what()) == "match effect failure";
        });
        BOOST_CHECK_EQUAL(calls,stage);
    }
    for (int64_t slot : {-1,0,255,256}) for (int64_t amount : {0,1,100,101}) for (bool address : {false,true}) {
        uint32_t calls{0};
        const int result = drivechain::haskell::DepositMatch(slot,amount,100,address,[&](uint32_t step) {
            ++calls; return success[step-1];
        });
        const bool valid = slot >= 0 && slot <= 255 && amount > 0 && amount <= 100 && address;
        BOOST_CHECK_EQUAL(result,valid ? 0 : 1);
        BOOST_CHECK_EQUAL(calls,valid ? 8 : 0);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_unique_match_scan)
{
    using drivechain::haskell::MatchResult;
    for (uint64_t size = 0; size <= 8; ++size) {
        for (uint32_t mask = 0; mask < (1U << size); ++mask) {
            std::vector<uint64_t> positions;
            for (uint64_t i = 0; i < size; ++i) if ((mask >> i) & 1) positions.push_back(i);
            uint64_t index{UINT64_MAX}, next{0};
            const auto result = drivechain::haskell::FindUniqueMatch(size,[&](uint64_t i) {
                BOOST_CHECK_EQUAL(i,next++);
                return (mask >> i) & 1;
            },index);
            BOOST_CHECK(result == (positions.empty() ? MatchResult::MISSING :
                positions.size() == 1 ? MatchResult::UNIQUE : MatchResult::DUPLICATE));
            BOOST_CHECK_EQUAL(index,positions.size() == 1 ? positions[0] : UINT64_MAX);
            BOOST_CHECK_EQUAL(next,positions.size() > 1 ? positions[1]+1 : size);
        }
    }
    for (uint64_t fail = 0; fail < 8; ++fail) {
        uint64_t index{UINT64_MAX}, next{0};
        BOOST_CHECK_EXCEPTION(drivechain::haskell::FindUniqueMatch(8,[&](uint64_t i) {
            BOOST_CHECK_EQUAL(i,next++);
            if (i == fail) throw std::runtime_error("unique probe failed");
            return i == 0;
        },index),std::runtime_error,[](const std::runtime_error& error) {
            return std::string(error.what()) == "unique probe failed";
        });
        BOOST_CHECK_EQUAL(index,UINT64_MAX);
        BOOST_CHECK_EQUAL(next,fail+1);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_match_scan_workflow)
{
    for (uint64_t count = 0; count < 40; ++count) {
        uint64_t next{0};
        BOOST_CHECK_EQUAL(drivechain::haskell::CountMatches(count,[&](uint64_t index) {
            BOOST_CHECK_EQUAL(index,next++);
            return index % 3 == 0;
        }),(count+2)/3);
        BOOST_CHECK_EQUAL(next,count);
        for (uint64_t fail = 0; fail < count; ++fail) {
            next = 0;
            BOOST_CHECK_EXCEPTION(drivechain::haskell::CountMatches(count,[&](uint64_t index) {
                BOOST_CHECK_EQUAL(index,next++);
                if (index == fail) throw std::runtime_error("scan probe failed");
                return drivechain::haskell::TreasuryDelta(0,1,1,1);
            }),std::runtime_error,[](const std::runtime_error& error) {
                return std::string(error.what()) == "scan probe failed";
            });
            BOOST_CHECK_EQUAL(next,fail+1);
        }
    }
    bool called{false};
    BOOST_CHECK_THROW(drivechain::haskell::CountMatches(UINT64_MAX,[&](uint64_t) {
        called = true; return true;
    }),std::runtime_error);
    BOOST_CHECK(!called);
}

BOOST_AUTO_TEST_CASE(drivechain_treasury_delta_parity)
{
    const std::vector<int64_t> values{INT64_MIN,-1,0,1,2100000000000000LL,INT64_MAX};
    for (const auto previous : values) for (const auto current : values)
        for (const auto claimed : values) for (const auto maximum : values) {
            const bool expected = current >= 0 && current <= maximum && current > previous &&
                static_cast<__int128>(previous) + claimed == current;
            BOOST_CHECK_EQUAL(drivechain::haskell::TreasuryDelta(previous,current,claimed,maximum),expected);
        }
    for (int64_t previous = 0; previous < 100; ++previous) {
        BOOST_CHECK(drivechain::haskell::TreasuryDelta(previous,previous+100,100,1000));
        BOOST_CHECK(!drivechain::haskell::TreasuryDelta(previous,previous+100,99,1000));
    }
}

BOOST_AUTO_TEST_CASE(drivechain_deposit_verify_workflow)
{
    for (bool throws : {false,true}) {
        for (uint32_t fail = 0; fail <= 12; ++fail) {
            std::vector<uint32_t> trace;
            bool published{false};
            const auto run = [&] {
                drivechain::haskell::DepositVerify(0,1,1,[&](uint32_t stage) {
                    trace.push_back(stage);
                    if (stage == fail) {
                        if (throws) throw std::runtime_error("verification effect failure");
                        return false;
                    }
                    if (stage == 8) drivechain::haskell::DepositHeaders(0,0,[](uint32_t,uint64_t) { return true; });
                    if (stage == 12) published = true;
                    return true;
                });
            };
            if (fail) BOOST_CHECK_EXCEPTION(run(),std::runtime_error,[&](const std::runtime_error& error) {
                return std::string(error.what()) == (throws ? "verification effect failure" : "Haskell live deposit verification failed");
            });
            else BOOST_CHECK_NO_THROW(run());
            const uint32_t report = fail == 1 ? 13 : fail >= 3 && fail <= 5 ? 14 :
                fail == 6 ? 15 : fail == 7 ? 16 : fail >= 8 && fail <= 11 ? 17 : 0;
            const bool reported = !throws && report != 0;
            BOOST_CHECK_EQUAL(trace.size(), (fail ? fail : 12) + reported);
            BOOST_CHECK_EQUAL(published,fail == 0);
            for (size_t i = 0; i < std::min<size_t>(trace.size(), fail ? fail : 12); ++i) BOOST_CHECK_EQUAL(trace[i],i+1);
            if (reported && !trace.empty()) BOOST_CHECK_EQUAL(trace.back(), report);
        }
    }
    for (uint64_t index : {uint64_t{0},uint64_t{1},UINT64_MAX}) {
        for (uint64_t inputs : {uint64_t{0},uint64_t{1},UINT64_MAX}) {
            for (uint64_t witnesses : {uint64_t{0},uint64_t{1},UINT64_MAX}) {
                uint32_t calls{0};
                const auto run = [&] { drivechain::haskell::DepositVerify(index,inputs,witnesses,[&](uint32_t) {
                    ++calls; return true;
                }); };
                const bool valid = index < inputs && index < witnesses;
                if (valid) BOOST_CHECK_NO_THROW(run());
                else BOOST_CHECK_EXCEPTION(run(),std::runtime_error,[](const std::runtime_error& error) {
                    return std::string(error.what()) == "drivechain deposit input or witness index is out of range";
                });
                BOOST_CHECK_EQUAL(calls,valid ? 12 : 0);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(drivechain_deposit_verify_reports)
{
    for (const auto& [failure,report] : std::vector<std::pair<uint32_t,uint32_t>>{
            {1,13},{3,14},{4,14},{5,14},{6,15},{7,16},{8,17},{9,17},{10,17},{11,17}}) {
        std::vector<uint32_t> expected;
        for (uint32_t step = 1; step <= failure; ++step) expected.push_back(step);
        expected.push_back(report);
        for (bool throws : {false,true}) {
            std::vector<uint32_t> trace;
            BOOST_CHECK_EXCEPTION(drivechain::haskell::DepositVerify(0,1,1,[&](uint32_t stage) {
                trace.push_back(stage);
                if (stage == report && throws) throw std::runtime_error("deposit rejection " + std::to_string(report));
                return stage != failure;
            }), std::runtime_error, [&](const std::runtime_error& error) {
                return std::string(error.what()) == (throws ? "deposit rejection " + std::to_string(report) : "Haskell live deposit verification failed");
            });
            BOOST_CHECK(trace == expected);
        }
    }
}

BOOST_AUTO_TEST_CASE(drivechain_deposit_build_workflow)
{
    const std::vector<uint32_t> planned{1,5,6,7,2,3,4};
    for (uint32_t fail = 0; fail <= 7; ++fail) {
        std::vector<uint32_t> trace;
        const auto run = [&] {
            drivechain::haskell::DepositBuild(1,0,3,[&](uint32_t stage) {
                trace.push_back(stage);
                if (stage == fail) throw std::runtime_error("evidence effect failure");
                if (stage == 3) drivechain::haskell::DepositCtipSearch(1,[](uint32_t,uint64_t) -> int32_t { return 1; });
                if (stage == 4) drivechain::haskell::DepositHeaders(0,0,[](uint32_t,uint64_t) { return true; });
                return true;
            });
        };
        if (fail) BOOST_CHECK_EXCEPTION(run(),std::runtime_error,[](const std::runtime_error& error) {
            return std::string(error.what()) == "evidence effect failure";
        });
        else BOOST_CHECK_NO_THROW(run());
        const auto count = fail ? std::find(planned.begin(),planned.end(),fail)-planned.begin()+1 : planned.size();
        BOOST_CHECK(trace == std::vector<uint32_t>(planned.begin(),planned.begin()+count));
    }
    for (uint32_t fail : {5,6,7}) {
        std::vector<uint32_t> trace;
        BOOST_CHECK_EXCEPTION(drivechain::haskell::DepositBuild(1,0,3,[&](uint32_t stage) {
            trace.push_back(stage);
            if (stage == 8) throw std::runtime_error("authenticated outpoint mismatch");
            return stage != fail;
        }),std::runtime_error,[](const std::runtime_error& error) {
            return std::string(error.what()) == "authenticated outpoint mismatch";
        });
        auto expected = std::vector<uint32_t>(planned.begin(),std::find(planned.begin(),planned.end(),fail)+1);
        expected.push_back(8);
        BOOST_CHECK(trace == expected);
    }
    for (const int64_t sequence : {-1,0,1}) {
        for (const int64_t height : {-1,0}) {
            for (uint32_t flags = 0; flags <= 7; ++flags) {
                uint32_t calls{0};
                const auto run = [&] { drivechain::haskell::DepositBuild(sequence,height,flags,[&](uint32_t) {
                    ++calls; return true;
                }); };
                const bool valid = sequence > 0 && height >= 0 && flags == 3;
                if (valid) BOOST_CHECK_NO_THROW(run());
                else BOOST_CHECK_EXCEPTION(run(),std::runtime_error,[](const std::runtime_error& error) {
                    return std::string(error.what()) == "authenticated deposit cannot form a v2 CTIP transition";
                });
                BOOST_CHECK_EQUAL(calls,valid ? 7 : 0);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(drivechain_deposit_headers_workflow)
{
    for (const auto& [first,tip] : std::vector<std::pair<uint64_t,int64_t>>{
        {0,0},{10,12},{0,2016},{INT64_MAX-1,INT64_MAX}}) {
        uint64_t expected{first};
        uint32_t cleared{0}, fetched{0};
        BOOST_CHECK_NO_THROW(drivechain::haskell::DepositHeaders(first,tip,[&](uint32_t stage,uint64_t height) {
            if (stage == 1) { ++cleared; return true; }
            BOOST_CHECK_EQUAL(cleared,1);
            BOOST_CHECK_EQUAL(height,expected);
            if (stage == 2) ++fetched;
            else { BOOST_CHECK_EQUAL(stage,4); ++expected; }
            return true;
        }));
        BOOST_CHECK_EQUAL(fetched,static_cast<uint64_t>(tip)-first+1);
    }
    for (const auto& [first,tip] : std::vector<std::pair<uint64_t,int64_t>>{
        {0,-1},{11,10},{0,2017},{UINT64_MAX,INT64_MAX}}) {
        bool called{false};
        BOOST_CHECK_THROW(drivechain::haskell::DepositHeaders(first,tip,[&](uint32_t,uint64_t) {
            called = true; return true;
        }),std::runtime_error);
        BOOST_CHECK(!called);
    }
    for (uint32_t fail = 1; fail <= 5; ++fail) {
        uint32_t calls{0};
        BOOST_CHECK_EXCEPTION(drivechain::haskell::DepositHeaders(10,11,[&](uint32_t,uint64_t) {
            if (++calls == fail) throw std::runtime_error("header effect failure");
            return true;
        }),std::runtime_error,[](const std::runtime_error& error) { return std::string(error.what()) == "header effect failure"; });
        BOOST_CHECK_EQUAL(calls,fail);
    }
    using Step = std::pair<uint32_t,uint64_t>;
    for (uint64_t failed_height : {10,11}) for (bool throws : {false,true}) {
        std::vector<Step> trace;
        BOOST_CHECK_EXCEPTION(drivechain::haskell::DepositHeaders(10,11,[&](uint32_t stage,uint64_t height) {
            trace.emplace_back(stage,height);
            if (stage == 3 && throws) throw std::runtime_error("header trailing data");
            return stage != 2 || height != failed_height;
        }),std::runtime_error,[&](const std::runtime_error& error) {
            return std::string(error.what()) == (throws ? "header trailing data" : "Haskell deposit header build failed");
        });
        std::vector<Step> expected{{1,0}};
        for (uint64_t height = 10; height < failed_height; ++height) {
            expected.emplace_back(2,height);
            expected.emplace_back(4,height);
        }
        expected.emplace_back(2,failed_height);
        expected.emplace_back(3,failed_height);
        BOOST_CHECK(trace == expected);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_ctip_search_workflow)
{
    for (uint32_t mask = 0; mask < 8; ++mask) {
        uint32_t stored{0};
        uint32_t probes{0};
        const auto run = [&] {
            drivechain::haskell::DepositCtipSearch(3,[&](uint32_t stage,uint64_t index) -> int32_t {
                if (stage == 2) { ++stored; return 1; }
                if (stage != 1) return 1;
                ++probes;
                return (mask >> index) & 1;
            });
        };
        if (mask == 1 || mask == 2 || mask == 4) BOOST_CHECK_NO_THROW(run());
        else BOOST_CHECK_EXCEPTION(run(),std::runtime_error,[&](const std::runtime_error& error) {
            return std::string(error.what()) == (mask ? "deposit transaction spends multiple slot CTIP outputs" :
                "deposit transaction's prior CTIP transaction is unavailable");
        });
        BOOST_CHECK_EQUAL(stored, mask ? 1 : 0);
        BOOST_CHECK_EQUAL(probes, mask == 3 || mask == 7 ? 2 : 3);
    }
    uint32_t stores{0};
    BOOST_CHECK_NO_THROW(drivechain::haskell::DepositCtipSearch(2,[&](uint32_t stage,uint64_t) -> int32_t {
        if (stage != 2) return 1;
        return ++stores == 1 ? 0 : 1;
    }));
    BOOST_CHECK_EQUAL(stores,2);
    for (uint32_t fail : {1,3,4,5}) {
        std::vector<std::pair<uint32_t,uint64_t>> trace;
        BOOST_CHECK_NO_THROW(drivechain::haskell::DepositCtipSearch(2,[&](uint32_t stage,uint64_t index) -> int32_t {
            trace.emplace_back(stage,index);
            return index != 0 || stage != fail;
        }));
        std::vector<std::pair<uint32_t,uint64_t>> expected;
        for (uint32_t stage : {1,3,4,5}) {
            expected.emplace_back(stage,0);
            if (stage == fail) break;
        }
        for (uint32_t stage : {1,3,4,5,2}) expected.emplace_back(stage,1);
        BOOST_CHECK(trace == expected);
    }
    const std::vector<uint32_t> stages{1,3,4,5,2};
    for (const auto fail : stages) {
        std::vector<uint32_t> trace;
        BOOST_CHECK_EXCEPTION(drivechain::haskell::DepositCtipSearch(3,[&](uint32_t stage,uint64_t) -> int32_t {
            trace.push_back(stage);
            if (stage == fail) throw std::runtime_error("multiple slot CTIP transport failure");
            return 1;
        }),std::runtime_error,[](const std::runtime_error& error) {
            return std::string(error.what()) == "multiple slot CTIP transport failure";
        });
        BOOST_CHECK(trace == std::vector<uint32_t>(stages.begin(),std::find(stages.begin(),stages.end(),fail)+1));
    }
}

BOOST_AUTO_TEST_CASE(drivechain_proof_build_workflow)
{
    using Step = std::pair<uint32_t,uint64_t>;
    std::vector<Step> expected{{1,10},{2,12},{3,0}};
    for (uint64_t height : {11,12,13}) for (uint32_t stage : {4,9,10,11,12}) expected.emplace_back(stage,height);
    expected.emplace_back(5,0);
    for (size_t fail = 0; fail <= expected.size(); ++fail) {
        std::vector<Step> trace;
        const auto run = [&] {
            drivechain::haskell::BmmProofBuild(10,12,[&](uint32_t stage, uint64_t height) {
                trace.emplace_back(stage,height);
                if (trace.size() == fail) throw std::runtime_error("proof effect failure");
                return true;
            });
        };
        if (fail) BOOST_CHECK_EXCEPTION(run(), std::runtime_error, [](const std::runtime_error& error) {
            return std::string(error.what()) == "proof effect failure";
        });
        else BOOST_CHECK_NO_THROW(run());
        BOOST_CHECK_EQUAL(trace.size(), fail ? fail : expected.size());
        BOOST_CHECK(std::equal(trace.begin(),trace.end(),expected.begin()));
    }
    for (const auto& [previous,parent] : std::vector<std::pair<uint64_t,int64_t>>{
        {0,-1},{11,10},{10,138},{0,INT64_MAX},{UINT64_MAX,INT64_MAX},{INT64_MAX,INT64_MAX}}) {
        bool called{false};
        BOOST_CHECK_THROW(drivechain::haskell::BmmProofBuild(previous,parent,[&](uint32_t,uint64_t) {
            called = true; return true;
        }),std::runtime_error);
        BOOST_CHECK(!called);
    }
    uint32_t entries{0};
    BOOST_CHECK_NO_THROW(drivechain::haskell::BmmProofBuild(10,137,[&](uint32_t stage,uint64_t height) {
        if (stage == 4) { ++entries; BOOST_CHECK_EQUAL(height,10 + entries); }
        return true;
    }));
    BOOST_CHECK_EQUAL(entries,128);
}

BOOST_AUTO_TEST_CASE(drivechain_proof_build_rejections)
{
    using Step = std::pair<uint32_t,uint64_t>;
    std::vector<Step> success{{1,10},{2,12},{3,0}};
    for (uint64_t height : {11,12,13}) for (uint32_t stage : {4,9,10,11,12}) success.emplace_back(stage,height);
    success.emplace_back(5,0);
    for (uint32_t failure : {1,2,3,4,5,9,10,11,12}) for (bool throws : {false,true}) {
        const uint32_t report = failure == 1 ? 6 : failure == 2 ? 7 : failure == 5 ? 8 : failure >= 9 && failure <= 11 ? 13 : 0;
        const auto end = std::find_if(success.begin(), success.end(), [&](const Step& step) { return step.first == failure; });
        std::vector<Step> expected(success.begin(), end + 1), trace;
        if (report) expected.emplace_back(report, end->second);
        BOOST_CHECK_EXCEPTION(drivechain::haskell::BmmProofBuild(10,12,[&](uint32_t stage,uint64_t height) {
            trace.emplace_back(stage,height);
            if (stage == report && throws) throw std::runtime_error("proof rejection " + std::to_string(report));
            return stage != failure && stage != report;
        }), std::runtime_error, [&](const std::runtime_error& error) {
            return std::string(error.what()) == (report && throws ? "proof rejection " + std::to_string(report) : "Haskell BMM proof build failed");
        });
        BOOST_CHECK(trace == expected);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_periodic_reverification_order)
{
    namespace hs = drivechain::haskell;
    for (unsigned flags = 0; flags < 32; ++flags) {
        const bool native = flags & 1, warm = flags & 2, current = flags & 4,
                   refreshed = flags & 8, activated = flags & 16;
        std::vector<uint32_t> expected{1};
        if (native) {
            expected.push_back(2);
            if (!warm) expected.push_back(3);
            else {
                expected.insert(expected.end(),{4,5});
                if (!current) {
                    expected.push_back(6);
                    if (!refreshed) expected.push_back(7);
                }
            }
        }
        expected.push_back(8);
        if (!activated) expected.push_back(9);
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            std::vector<uint32_t> trace;
            const auto invoke = [&] {
                const auto action = [&](uint32_t stage) -> uint32_t {
                    trace.push_back(stage);
                    if (trace.size() == fault+1) throw std::runtime_error("reverification fault");
                    switch (stage) {
                    case 1: return native;
                    case 2: return warm;
                    case 5: return current;
                    case 6: return refreshed;
                    case 8: return activated;
                    default: return 1;
                    }
                };
                hs::ParentReplayStore(hs::ReplayStoreFlow::PERIODIC_REVERIFICATION, action);
                if (!action(8)) action(9);
                return 1U;
            };
            if (fault == expected.size()) BOOST_CHECK_EQUAL(invoke(),1U);
            else BOOST_CHECK_EXCEPTION(invoke(),std::runtime_error,[](const std::runtime_error& error) {
                return std::string(error.what()) == "reverification fault";
            });
            const std::vector<uint32_t> prefix(expected.begin(),expected.begin()+std::min(fault+1,expected.size()));
            BOOST_CHECK(trace == prefix);
        }
    }
}

BOOST_AUTO_TEST_CASE(mined_commitment_preflight_order)
{
    namespace hs = drivechain::haskell;
    for (unsigned flags = 0; flags < 4; ++flags) {
        const bool slot = flags & 1, non_null = flags & 2;
        std::vector<uint32_t> expected{1};
        if (slot) {
            expected.push_back(2);
            if (!non_null) expected.push_back(3);
        }
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            std::vector<uint32_t> trace;
            const auto invoke = [&] {
                return hs::ParentReplayStore(hs::ReplayStoreFlow::BMM_MINED_PREFLIGHT, [&](uint32_t step) -> uint32_t {
                    trace.push_back(step);
                    if (trace.size() == fault+1) throw std::runtime_error("mined preflight fault");
                    if (step == 1) return slot;
                    if (step == 2) return non_null;
                    return 0;
                });
            };
            if (fault == expected.size()) BOOST_CHECK_EQUAL(invoke(),slot && non_null);
            else BOOST_CHECK_EXCEPTION(invoke(),std::runtime_error,[](const std::runtime_error& error) {
                return std::string(error.what()) == "mined preflight fault";
            });
            const std::vector<uint32_t> prefix(expected.begin(),expected.begin()+std::min(fault+1,expected.size()));
            BOOST_CHECK(trace == prefix);
        }
    }
}


BOOST_AUTO_TEST_CASE(required_proposal_and_snapshot_reply_order)
{
    namespace hs = drivechain::haskell;
    for (const auto& [flow,count] : {std::pair{hs::ReplayStoreFlow::REQUIRED_PROPOSAL,3U},
                                   std::pair{hs::ReplayStoreFlow::REQUIRED_PAIR,2U},
                                   std::pair{hs::ReplayStoreFlow::REQUIRED_QUAD,4U}}) {
        for (unsigned flags = 0; flags < (1U << count); ++flags) {
            std::vector<uint32_t> expected;
            bool accepted{true};
            for (uint32_t step = 1; step <= count; ++step) {
                expected.push_back(step);
                if (!(flags & (1U << (step-1)))) {
                    expected.push_back(count+1);
                    accepted = false;
                    break;
                }
            }
            for (size_t fault = 0; fault <= expected.size(); ++fault) {
                std::vector<uint32_t> trace;
                const auto invoke = [&] {
                    return hs::ParentReplayStore(flow,[&](uint32_t step) -> uint32_t {
                        trace.push_back(step);
                        if (trace.size() == fault+1) throw std::runtime_error("required fact fault");
                        if (step == count+1) return 0;
                        const bool passed = flags & (1U << (step-1));
                        if (step == count) return hs::ParentReplayRecord(hs::ReplayRecordKind::HEIGHT,0,0,1,passed);
                        return passed;
                    });
                };
                if (fault == expected.size()) BOOST_CHECK_EQUAL(invoke(),accepted);
                else BOOST_CHECK_EXCEPTION(invoke(),std::runtime_error,[](const std::runtime_error& error) {
                    return std::string(error.what()) == "required fact fault";
                });
                const std::vector<uint32_t> prefix(expected.begin(),expected.begin()+std::min(fault+1,expected.size()));
                BOOST_CHECK(trace == prefix);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(bmm_rpc_authentication_presence_gate)
{
    namespace hs = drivechain::haskell;
    for (const bool present : {false, true}) for (uint32_t rejected = 0; rejected <= 4; ++rejected) {
        std::vector<uint32_t> trace;
        bool published{false};
        const auto result = hs::ParentReplayStore(hs::ReplayStoreFlow::RPC_BMM_AUTHENTICATION,
            [&](uint32_t step) -> uint32_t {
            trace.push_back(step);
            if (step == 1) return present;
            BOOST_REQUIRE(present);
            if (step == 6) published = true;
            return step != rejected + 1;
        });
        const uint32_t expected = !present || rejected == 0 ? 0 : rejected == 1 ? 1 : rejected <= 3 ? 2 : 3;
        BOOST_CHECK_EQUAL(result, expected);
        BOOST_CHECK_EQUAL(published, present && rejected == 0);
        std::vector<uint32_t> planned{1};
        if (present) for (uint32_t step = 2; step <= (rejected ? rejected + 1 : 6); ++step) planned.push_back(step);
        BOOST_CHECK(trace == planned);
    }
    std::unique_ptr<CBlock> block;
    BOOST_CHECK(!hs::ParentReplayAll<2>({[&] { return bool(block); }, [&] {
        BOOST_FAIL("missing private template must not be dereferenced");
        return block->HasBmmProof();
    }}));
}


BOOST_AUTO_TEST_CASE(credential_record_preserves_rejection_boundary)
{
    for (bool readable : {false, true}) for (bool valid : {false, true}) {
        std::vector<uint32_t> expected{1};
        if (readable) expected.push_back(2);
        if (readable && !valid) expected.push_back(3);
        for (uint32_t fault = 0; fault <= 3; ++fault) {
            std::vector<uint32_t> seen;
            std::string record{"unchanged"};
            const auto run = [&] {
                return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::CREDENTIAL_RECORD,
                    [&](uint32_t step) -> uint32_t {
                    seen.push_back(step);
                    if (step == fault) throw std::runtime_error("record fault");
                    if (step == 1) return readable;
                    if (step == 2) return valid;
                    BOOST_REQUIRE_EQUAL(step, 3U);
                    record.clear(); return 1;
                });
            };
            const auto stop = std::find(expected.begin(), expected.end(), fault);
            if (stop != expected.end()) BOOST_CHECK_THROW(run(), std::runtime_error);
            else BOOST_CHECK_EQUAL(run(), unsigned(readable && valid));
            BOOST_CHECK(seen == std::vector<uint32_t>(expected.begin(), stop == expected.end() ? stop : stop + 1));
            BOOST_CHECK_EQUAL(record.empty(), readable && !valid && stop == expected.end());
        }
    }
}

template <typename Gate>
static void CheckLazyHeaderGate(const std::vector<unsigned>& expected, bool result, Gate&& gate)
{
    for (size_t fault = 0; fault <= expected.size(); ++fault) {
        std::vector<unsigned> actual;
        const auto read = [&](unsigned step, bool value) {
            actual.push_back(step);
            if (actual.size() == fault + 1) throw std::runtime_error("header fact fault");
            return value;
        };
        if (fault == expected.size()) BOOST_CHECK_EQUAL(gate(read), result);
        else BOOST_CHECK_EXCEPTION(gate(read), std::runtime_error, [](const auto& error) {
            return std::string(error.what()) == "header fact fault";
        });
        BOOST_CHECK(actual == std::vector<unsigned>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
    }
}

BOOST_AUTO_TEST_CASE(best_header_gate_preserves_lazy_work_comparison)
{
    for (unsigned flags = 0; flags < 16; ++flags) {
        const bool native = flags & 1, authenticated = flags & 2, has_best = flags & 4, better = flags & 8;
        std::vector<unsigned> expected{1};
        if (native) {
            expected.push_back(2);
            if (authenticated) {
                expected.push_back(3);
                if (has_best) expected.push_back(4);
            }
        }
        CheckLazyHeaderGate(expected, native && authenticated && (!has_best || better), [&](const auto& read) {
            return drivechain::haskell::ParentReplayAll<3>({
                [&] { return read(1, native); },
                [&] { return read(2, authenticated); },
                [&] { return !drivechain::haskell::ParentReplayAll<2>({
                    [&] { return read(3, has_best); },
                    [&] { return !read(4, better); },
                }); },
            });
        });
    }
}

BOOST_AUTO_TEST_CASE(recalculated_header_gate_preserves_lazy_work_comparison)
{
    for (unsigned flags = 0; flags < 8; ++flags) {
        const bool authenticated = flags & 1, has_best = flags & 2, better = flags & 4;
        std::vector<unsigned> expected{1};
        if (authenticated) {
            expected.push_back(2);
            if (has_best) expected.push_back(3);
        }
        CheckLazyHeaderGate(expected, authenticated && (!has_best || better), [&](const auto& read) {
            return drivechain::haskell::ParentReplayAll<2>({
                [&] { return read(1, authenticated); },
                [&] { return drivechain::haskell::ParentReplayChoose({
                    [&] { return !read(2, has_best); }, [] { return true; },
                    [&] { return read(3, better); },
                }); },
            });
        });
    }
}

BOOST_AUTO_TEST_CASE(fork_gate_extensions_preserve_lazy_native_checks)
{
    for (bool outer : {false,true}) for (bool first : {false,true})
    for (bool second : {false,true}) for (bool alternative : {false,true}) {
        std::vector<unsigned> expected{1};
        if (outer) {
            expected.push_back(2);
            if (first != alternative) expected.push_back(3);
        }
        CheckLazyHeaderGate(expected, outer && (alternative ? first || second : first && second), [&](const auto& read) {
            return read(1,outer) && (alternative ? drivechain::haskell::ParentReplayChoose({
                [&] { return read(2,first); }, [] { return true; },
                [&] { return read(3,second); },
            }) : drivechain::haskell::ParentReplayAll<2>({
                [&] { return read(2,first); }, [&] { return read(3,second); },
            }));
        });
    }
}

BOOST_AUTO_TEST_CASE(native_witness_fallback_preserves_lazy_selection)
{
    for (bool native_network : {false,true}) for (bool native_witness : {false,true})
    for (bool legacy : {false,true}) {
        std::vector<unsigned> expected{1};
        if (native_network) expected.push_back(2);
        if (!native_network || !native_witness) expected.push_back(3);
        CheckLazyHeaderGate(expected,(native_network && native_witness) || legacy,[&](const auto& read) {
            return drivechain::haskell::ParentReplayChoose({
                [&] { return drivechain::haskell::ParentReplayAll<2>({
                    [&] { return read(1,native_network); }, [&] { return read(2,native_witness); },
                }); }, [] { return true; },
                [&] { return read(3,legacy); },
            });
        });
    }
    bool unavailable{false};
    std::string error="unchanged";
    BOOST_CHECK(drivechain::haskell::ParentReplayChoose({
        [] { return true; }, [] { return true; },
        [&]() -> bool { unavailable=true; error="parent queried"; throw std::runtime_error(error); },
    }));
    BOOST_CHECK(!unavailable);
    BOOST_CHECK_EQUAL(error,"unchanged");
}

BOOST_AUTO_TEST_CASE(deposit_connection_skips_coinbase)
{
    for (bool coinbase : {false, true}) for (bool connected : {false, true}) {
        std::vector<unsigned> expected{1};
        if (!coinbase) expected.push_back(2);
        CheckLazyHeaderGate(expected, coinbase || connected, [&](const auto& read) {
            return drivechain::haskell::ParentReplayChoose({
                [&] { return read(1, coinbase); }, [] { return true; },
                [&] { return read(2, connected); },
            });
        });
    }
    BOOST_CHECK(drivechain::haskell::ParentReplayChoose({
        [] { return true; }, [] { return true; },
        []() -> bool { throw std::runtime_error("coinbase must not connect deposit state"); },
    }));
}

BOOST_AUTO_TEST_CASE(header_batch_gate_preserves_lazy_authentication)
{
    for (unsigned flags = 0; flags < 8; ++flags) {
        const bool native = flags & 1, duplicate = flags & 2, authenticated = flags & 4;
        std::vector<unsigned> expected{1};
        if (native) {
            expected.push_back(2);
            if (duplicate) expected.push_back(3);
        }
        CheckLazyHeaderGate(expected, native && (!duplicate || !authenticated), [&](const auto& read) {
            return drivechain::haskell::ParentReplayAll<2>({
                [&] { return read(1, native); },
                [&] { return !drivechain::haskell::ParentReplayAll<2>({
                    [&] { return read(2, duplicate); },
                    [&] { return read(3, authenticated); },
                }); },
            });
        });
    }
}

BOOST_AUTO_TEST_CASE(required_facts_adapter_order)
{
    const auto check = []<size_t N>() {
        for (unsigned flags = 0; flags < (1U << N); ++flags) {
            std::vector<size_t> expected;
            bool accepted{true};
            for (size_t i = 0; i < N; ++i) {
                expected.push_back(i);
                if (!(flags & (1U << i))) { accepted = false; break; }
            }
            for (size_t fault = 0; fault <= expected.size(); ++fault) {
                std::vector<size_t> trace;
                std::array<std::function<bool()>, N> facts;
                for (size_t i = 0; i < N; ++i) facts[i] = [&, i] {
                    trace.push_back(i);
                    if (trace.size() == fault + 1) throw std::runtime_error("lazy fact fault");
                    return bool(flags & (1U << i));
                };
                const auto invoke = [&] { return drivechain::haskell::ParentReplayAll(facts); };
                if (fault == expected.size()) BOOST_CHECK_EQUAL(invoke(), accepted);
                else BOOST_CHECK_EXCEPTION(invoke(), std::runtime_error, [](const std::runtime_error& error) {
                    return std::string(error.what()) == "lazy fact fault";
                });
                const std::vector<size_t> prefix(expected.begin(), expected.begin() + std::min(fault + 1, expected.size()));
                BOOST_CHECK(trace == prefix);
            }
        }
    };
    check.template operator()<2>();
    check.template operator()<3>();
    check.template operator()<4>();
}

BOOST_AUTO_TEST_CASE(bmm_cache_routing_order)
{
    namespace hs = drivechain::haskell;
    for (unsigned flags = 0; flags < 16; ++flags) {
        const bool hit = flags & 1, first_trust = flags & 2, second_trust = flags & 4, negative = flags & 8;
        for (uint32_t cached = 0; cached < 4; ++cached) for (uint32_t indexed = 0; indexed < 4; ++indexed) {
            std::vector<uint32_t> expected{1,2};
            if (hit) expected.push_back(3);
            else {
                expected.push_back(4);
                if (first_trust) expected.push_back(5);
                if (!first_trust || indexed == 0) {
                    expected.push_back(6);
                    if (!second_trust) {
                        expected.insert(expected.end(),{7,8});
                        if (negative) expected.push_back(9);
                    }
                }
            }
            const bool finished = hit || (first_trust && indexed != 0) || (!second_trust && negative);
            for (size_t fault = 0; fault <= expected.size(); ++fault) {
                std::vector<uint32_t> trace;
                const auto invoke = [&] {
                    return hs::ParentReplayStore(hs::ReplayStoreFlow::BMM_CACHE_ROUTING, [&](uint32_t step) -> uint32_t {
                        trace.push_back(step);
                        if (trace.size() == fault+1) throw std::runtime_error("cache routing fault");
                        switch (step) {
                        case 1: case 7: return 1;
                        case 2: return hit;
                        case 3:
                            BOOST_CHECK(hs::ParentReplayStore(hs::ReplayStoreFlow::BMM_MINED_PREFLIGHT,
                                [](uint32_t) -> uint32_t { return 1; }));
                            return cached;
                        case 4: return first_trust;
                        case 5: return indexed;
                        case 6: return second_trust;
                        case 8: return negative;
                        case 9: return 3;
                        default: throw std::logic_error("unexpected cache routing action");
                        }
                    });
                };
                if (fault == expected.size()) BOOST_CHECK_EQUAL(invoke(),finished);
                else BOOST_CHECK_EXCEPTION(invoke(),std::runtime_error,[](const std::runtime_error& error) {
                    return std::string(error.what()) == "cache routing fault";
                });
                const std::vector<uint32_t> prefix(expected.begin(),expected.begin()+std::min(fault+1,expected.size()));
                BOOST_CHECK(trace == prefix);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(unconfigured_slot_rejects_before_hash)
{
    BOOST_REQUIRE(!Params().GetConsensus().drivechain_slot);
    std::string error;
    BOOST_CHECK(!IsDrivechainBmmCommitmentMined(uint256{}, uint256{}, 24, &error));
    BOOST_CHECK_EQUAL(error,"this network has no configured BIP300/301 sidechain slot");
    BOOST_CHECK(!IsDrivechainBmmCommitmentMined(uint256{}, uint256{}, 24));
}

BOOST_AUTO_TEST_CASE(wallet_command_result_order)
{
    namespace hs = drivechain::haskell;
    for (unsigned flags = 0; flags < 16; ++flags) {
        const bool finished = flags & 1, success = flags & 2, empty_error = flags & 4, parsed = flags & 8;
        const std::string expected_error = !finished ? "timeout" : !success ?
            (empty_error ? "stdout detail" : "stderr detail") : !parsed ? "parse error" : "";
        std::vector<uint32_t> expected{1}, trace;
        if (!finished) expected.push_back(2);
        else {
            expected.push_back(3);
            if (!success) {
                expected.insert(expected.end(),{4,5});
                if (empty_error) expected.push_back(6);
                expected.push_back(7);
            } else {
                expected.insert(expected.end(),{8,9});
                if (!parsed) expected.push_back(10);
            }
        }
        std::string error, observed;
        bool accepted{false};
        try {
            accepted = hs::ParentReplayStore(hs::ReplayStoreFlow::WALLET_COMMAND,[&](uint32_t stage) -> uint32_t {
                trace.push_back(stage);
                switch (stage) {
                case 1: return finished;
                case 2: throw std::runtime_error("timeout");
                case 3: return success;
                case 4: error = empty_error ? "" : "stderr detail"; return 1;
                case 5: return error.empty();
                case 6: error = "stdout detail"; return 1;
                case 7: throw std::runtime_error(error);
                case 8: return 1;
                case 9: return parsed;
                case 10: throw std::runtime_error("parse error");
                default: throw std::logic_error("unexpected wallet command action");
                }
            });
        } catch (const std::runtime_error& exception) { observed = exception.what(); }
        BOOST_CHECK_EQUAL(observed,expected_error);
        BOOST_CHECK_EQUAL(accepted,expected_error.empty());
        BOOST_CHECK(trace == expected);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_sync_lifecycle_order)
{
    namespace hs = drivechain::haskell;
    const auto check = [&](hs::ReplayStoreFlow flow, const std::vector<std::pair<uint32_t,uint32_t>>& script, uint32_t expected) {
        for (size_t fault = 0; fault <= script.size(); ++fault) {
            size_t calls{0};
            const auto invoke = [&] {
                return hs::ParentReplayStore(flow,[&](uint32_t stage) -> uint32_t {
                    BOOST_REQUIRE_LT(calls,script.size());
                    const auto [wanted,reply] = script[calls++];
                    BOOST_CHECK_EQUAL(stage,wanted);
                    if (calls == fault+1) throw std::runtime_error("sync lifecycle fault");
                    if (flow == hs::ReplayStoreFlow::SYNC_LOOP && stage == 2) {
                        BOOST_CHECK(hs::BmmSyncTick(10, 9, [](uint32_t) { return true; }));
                    }
                    return reply;
                });
            };
            if (fault == script.size()) BOOST_CHECK_EQUAL(invoke(),expected);
            else BOOST_CHECK_EXCEPTION(invoke(),std::runtime_error,[](const std::runtime_error& error) {
                return std::string(error.what()) == "sync lifecycle fault";
            });
            BOOST_CHECK_EQUAL(calls,std::min(fault+1,script.size()));
        }
    };
    for (uint32_t flags = 0; flags < 32; ++flags) {
        std::vector<std::pair<uint32_t,uint32_t>> script;
        for (uint32_t stage = 1; stage <= 5; ++stage) {
            const bool accepted = flags & (1U << (stage-1));
            script.emplace_back(stage,accepted);
            if (!accepted) break;
        }
        check(hs::ReplayStoreFlow::SYNC_PREFLIGHT,script,flags == 31);
    }
    for (bool height : {false,true}) for (bool hash : {false,true}) {
        std::vector<std::pair<uint32_t,uint32_t>> script{{1,1},{2,1},{3,height}};
        if (height) script.emplace_back(4,hash);
        if (!height || !hash) script.emplace_back(5,1);
        check(hs::ReplayStoreFlow::BID_PARENT,script,height && hash);
    }
    for (unsigned cycles = 0; cycles <= 8; ++cycles) for (bool shutdown : {false,true}) {
        std::vector<std::pair<uint32_t,uint32_t>> script;
        for (unsigned cycle = 0; cycle < cycles; ++cycle) script.insert(script.end(),{{1,1},{2,1},{3,1}});
        if (shutdown) script.emplace_back(1,0);
        else script.insert(script.end(),{{1,1},{2,1},{3,0}});
        check(hs::ReplayStoreFlow::SYNC_LOOP,script,1);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_sync_tick_stages)
{
    for (uint32_t failure : {0U,4U,5U}) {
        std::vector<uint32_t> trace;
        const bool result = drivechain::haskell::BmmSyncTick(10, 9, [&](uint32_t stage) {
            trace.push_back(stage);
            if (stage == failure) return false;
            return stage != 4 || drivechain::haskell::BmmProduction(false, [](uint32_t) { return true; });
        });
        BOOST_CHECK_EQUAL(result, failure == 0);
        BOOST_CHECK_EQUAL(trace.size(), failure == 4 ? 1 : 2);
        for (size_t index = 0; index < trace.size(); ++index) BOOST_CHECK_EQUAL(trace[index], index + 4);
    }
    for (int64_t child : {10,11}) {
        BOOST_CHECK(!drivechain::haskell::BmmSyncTick(10, child, [](uint32_t) -> bool {
            throw std::runtime_error("caught-up tick must not produce or report");
        }));
    }
    for (uint32_t failure : {4U,5U}) {
        uint32_t calls{0};
        BOOST_CHECK_EXCEPTION(drivechain::haskell::BmmSyncTick(10, 9, [&](uint32_t stage) {
            ++calls;
            if (stage == failure) throw std::runtime_error("sync tick failure");
            return true;
        }), std::runtime_error, [](const std::runtime_error& error) { return std::string(error.what()) == "sync tick failure"; });
        BOOST_CHECK_EQUAL(calls, failure - 3);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_bmm_replacement_bid)
{
    const std::string prefix = "insufficient fee, rejecting replacement txid, not enough additional fees to relay; ";
    CAmount bid{42};
    BOOST_CHECK(ComputeDrivechainBmmReplacementBid(prefix + "0.00 < 0.00000019\", data: None", 1000, 2000, bid));
    BOOST_CHECK_EQUAL(bid, 1019);
    BOOST_CHECK(ComputeDrivechainBmmReplacementBid(prefix + "-0.00000019 < 0.00000019", 1000, 2000, bid));
    BOOST_CHECK_EQUAL(bid, 1038);
    BOOST_CHECK(ComputeDrivechainBmmReplacementBid(prefix + "0.00000010 < 0.00000019", 1000, 2000, bid));
    BOOST_CHECK_EQUAL(bid, 1009);
    BOOST_CHECK(ComputeDrivechainBmmReplacementBid("insufficient fee, rejecting replacement txid, less fees than conflicting txs; 0.00001000 < 0.00001019", 1000, 2000, bid));
    BOOST_CHECK_EQUAL(bid, 1019);
    BOOST_CHECK(ComputeDrivechainBmmReplacementBid(prefix + "0.00 < 0.00000019", bid, 2000, bid));
    BOOST_CHECK_EQUAL(bid, 1038);
    for (const auto& text : {"0.00 < 0.00000019garbage", "0.00 < -1", "NaN < 0.00000019", "0.00 < 0.000000001", "0.00 < 21000001", "0.00 < 0.00"}) {
        BOOST_CHECK(!ComputeDrivechainBmmReplacementBid(prefix + text, 1000, 2000, bid));
    }
    BOOST_CHECK(!ComputeDrivechainBmmReplacementBid("timeout", 1000, 2000, bid));
    BOOST_CHECK(!ComputeDrivechainBmmReplacementBid(prefix + "0.00 < 0.00000019", 1000, 1000, bid));
    BOOST_CHECK(!ComputeDrivechainBmmReplacementBid(prefix + "0.00 < 0.00001001", 1000, 2000, bid));
    BOOST_CHECK(!ComputeDrivechainBmmReplacementBid(prefix + "0.00 < 0.00000019", MAX_MONEY - 1, MAX_MONEY, bid));
}

BOOST_AUTO_TEST_CASE(elements_production_identity_gate)
{
    ArgsManager args;
    const auto elements = CreateChainParams(args, CBaseChainParams::ELEMENTS);
    const auto elements_base = CreateBaseChainParams(CBaseChainParams::ELEMENTS);
    std::string error;
    BOOST_CHECK(IsCanonicalElementsProductionIdentity(*elements, *elements_base, &error));
    BOOST_CHECK(error.empty());

    const auto signet = CreateChainParams(args, CBaseChainParams::SIGNET);
    const auto signet_base = CreateBaseChainParams(CBaseChainParams::SIGNET);
    BOOST_CHECK(!IsCanonicalElementsProductionIdentity(*signet, *signet_base, &error));
    BOOST_CHECK(!error.empty());
}

BOOST_AUTO_TEST_CASE(elements_production_identity_mutation_matrix)
{
    struct MutableIdentity : CChainParams {
        explicit MutableIdentity(const CChainParams& base) : CChainParams(base) {}
        Consensus::Params& Rules() { return consensus; }
    };
    const auto original = CreateChainParams(ArgsManager{}, CBaseChainParams::ELEMENTS);
    const auto base = CreateBaseChainParams(CBaseChainParams::ELEMENTS);
    using Mutation = std::pair<const char*, std::function<void(Consensus::Params&)>>;
    const std::vector<Mutation> mutations{
        {"Elements/parent/slot mode", [](auto& p) { p.elements_mode = false; }},
        {"Elements/parent/slot mode", [](auto& p) { p.has_parent_chain = false; }},
        {"Elements/parent/slot mode", [](auto& p) { p.drivechain_slot.reset(); }},
        {"Elements/parent/slot mode", [](auto& p) { p.drivechain_slot = 130; }},
        {"parent-chain identity", [](auto& p) { p.parentChainPowLimit.SetNull(); }},
        {"parent-chain identity", [](auto& p) { p.parent_signet_challenge.push_back(0); }},
        {"parent-chain identity", [](auto& p) { ++p.pegin_min_depth; }},
        {"parent-chain identity", [](auto& p) { p.parent_chain_signblockscript = CScript() << OP_TRUE; }},
        {"signed-block/genesis mode", [](auto& p) { p.genesis_style = "invalid"; }},
        {"signed-block/genesis mode", [](auto& p) { p.signblockscript.clear(); }},
        {"signed-block/genesis mode", [](auto& p) { ++p.max_block_signature_size; }},
        {"signed-block/genesis mode", [](auto& p) { p.connect_genesis_outputs = false; }},
        {"signed-block/genesis mode", [](auto& p) { p.genesis_subsidy = 1; }},
        {"signed-block/genesis mode", [](auto& p) { p.fedpegScript.clear(); }},
        {"child genesis/asset identity", [](auto& p) { p.hashGenesisBlock.SetNull(); }},
        {"child genesis/asset identity", [](auto& p) { p.pegged_asset = CAsset(uint256::ONE); }},
        {"child genesis/asset identity", [](auto& p) { p.subsidy_asset = CAsset(uint256::ONE); }},
        {"Elements M1 proposal identity", [](auto& p) { p.drivechain_proposal_hash.reset(); }},
        {"Elements M1 proposal identity", [](auto& p) { p.drivechain_protocol_manifest_hash.SetNull(); }},
        {"Elements M1 proposal identity", [](auto& p) { p.drivechain_proposal_description.clear(); }},
        {"historical parent proposal milestones", [](auto& p) { p.drivechain_parent_state_active_proposal_hash = uint256::ONE; }},
        {"historical parent proposal milestones", [](auto& p) { ++p.drivechain_parent_state_proposal_height; }},
        {"historical parent proposal milestones", [](auto& p) { ++p.drivechain_parent_state_activation_height; }},
        {"parent replay checkpoint assertions", [](auto& p) { ++p.drivechain_parent_state_height; }},
        {"parent replay checkpoint assertions", [](auto& p) { ++p.drivechain_parent_state_ctip_vout; }},
        {"parent replay checkpoint assertions", [](auto& p) { ++p.drivechain_parent_state_ctip_value; }},
        {"parent replay identity", [](auto& p) { ++p.drivechain_unused_slot_proposal_max_age; }},
        {"parent replay identity", [](auto& p) { ++p.drivechain_unused_slot_activation_threshold; }},
        {"parent replay identity", [](auto& p) { ++p.drivechain_used_slot_proposal_max_age; }},
        {"parent replay identity", [](auto& p) { ++p.drivechain_used_slot_activation_threshold; }},
        {"parent replay identity", [](auto& p) { ++p.drivechain_withdrawal_bundle_max_age; }},
        {"parent replay identity", [](auto& p) { ++p.drivechain_withdrawal_bundle_inclusion_threshold; }},
        {"parent replay identity", [](auto& p) { ++p.drivechain_parent_state_replay_version; }},
        {"parent replay identity", [](auto& p) { ++p.drivechain_annex_feature_version; }},
        {"parent replay identity", [](auto& p) { p.drivechain_m6_withdrawal_validation = false; }},
        {"Taproot/Simplicity activation", [](auto& p) { ++p.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit; }},
        {"Taproot/Simplicity activation", [](auto& p) { ++p.vDeployments[Consensus::DEPLOYMENT_SIMPLICITY].nStartTime; }},
    };
    for (const auto& [field, mutate] : mutations) {
        MutableIdentity candidate{*original};
        std::string error{"unchanged"};
        BOOST_REQUIRE(IsCanonicalElementsProductionIdentity(candidate, *base, &error));
        BOOST_CHECK_EQUAL(error, "unchanged");
        mutate(candidate.Rules());
        BOOST_CHECK(!IsCanonicalElementsProductionIdentity(candidate, *base, nullptr));
        BOOST_CHECK(!IsCanonicalElementsProductionIdentity(candidate, *base, &error));
        BOOST_CHECK_EQUAL(error, "Elements production identity mismatch: " + std::string(field));
        // An earlier mismatch must win, independent of the later invalid field.
        candidate.Rules().elements_mode = false;
        BOOST_CHECK(!IsCanonicalElementsProductionIdentity(candidate, *base, &error));
        BOOST_CHECK_EQUAL(error, "Elements production identity mismatch: Elements/parent/slot mode");
    }
}

BOOST_AUTO_TEST_CASE(drivechain_bmm_wait_error_classification)
{
    const std::vector<std::string> markers{
        "BMM successor", "not the exact successor of committed parent",
        "not the active-chain block at its declared height",
        "cached parent edge has no unique enforcer-recognized M7",
        "expected critical hash does not match the cached enforcer-recognized M7"};
    const auto reference = [&](const std::string& message) {
        return std::any_of(markers.begin(),markers.end(),[&](const auto& marker) {
            return message.find(marker) != std::string::npos;
        });
    };
    for (const auto& marker : markers) {
        for (size_t size = 0; size <= marker.size(); ++size) {
            const std::string message = std::string("prefix\0",7) + marker.substr(0,size) + std::string("\0suffix",7);
            BOOST_CHECK_EQUAL(IsDefinitiveDrivechainBmmWaitError(message),reference(message));
        }
        for (size_t index = 0; index < marker.size(); ++index) {
            auto message = marker;
            message[index] = '\0';
            BOOST_CHECK_EQUAL(IsDefinitiveDrivechainBmmWaitError(message),reference(message));
        }
    }
    BOOST_CHECK(IsDefinitiveDrivechainBmmWaitError(
        "BMM successor has no enforcer-recognized M7 for sidechain slot 24"));
    BOOST_CHECK(IsDefinitiveDrivechainBmmWaitError(
        "cached parent edge has no unique enforcer-recognized M7; await a fresh authenticated edge"));
    BOOST_CHECK(IsDefinitiveDrivechainBmmWaitError(
        "expected critical hash does not match the cached enforcer-recognized M7; no parent RPC performed"));
    BOOST_CHECK(IsDefinitiveDrivechainBmmWaitError(
        "BMM block is not the exact successor of committed parent"));
    BOOST_CHECK(IsDefinitiveDrivechainBmmWaitError(
        "BMM block is not the active-chain block at its declared height"));

    BOOST_CHECK(!IsDefinitiveDrivechainBmmWaitError(
        "authenticated parent replay cache is not current"));
    BOOST_CHECK(!IsDefinitiveDrivechainBmmWaitError(
        "authenticated BMM edge cache is busy"));
    BOOST_CHECK(!IsDefinitiveDrivechainBmmWaitError(
        "parent RPC transport failure"));
    BOOST_CHECK(!IsDefinitiveDrivechainBmmWaitError(
        "parent-chain reorg raced BIP301 validation at successor Q"));
}

BOOST_AUTO_TEST_CASE(drivechain_bmm_duplicate_request_classification)
{
    namespace hs = drivechain::haskell;
    const auto duplicate = [](const std::string& message) {
        return hs::BmmMessageMatches(hs::BmmMessageKind::DUPLICATE_REQUEST, message);
    };
    for (const std::string marker : {"AlreadyExists", "same `sidechain_number` and `prev_bytes` already exists"}) {
        for (size_t size = 0; size <= marker.size(); ++size) {
            const std::string message = std::string("\0prefix",7) + marker.substr(0,size) + std::string("\0suffix",7);
            const bool expected = message.find("AlreadyExists") != std::string::npos ||
                message.find("same `sidechain_number` and `prev_bytes` already exists") != std::string::npos;
            BOOST_CHECK_EQUAL(duplicate(message),expected);
        }
    }
    BOOST_CHECK(!duplicate("alreadyexists"));
    BOOST_CHECK(!duplicate("BMM successor has no enforcer-recognized M7"));
    BOOST_CHECK(!duplicate("transport failure"));
    BOOST_CHECK_THROW(hs::BmmMessageMatches(static_cast<hs::BmmMessageKind>(2),""),std::runtime_error);
    for (const bool exists : {false,true}) {
        std::vector<uint32_t> trace;
        const int result = hs::BmmSubmit(100,100,[&](uint32_t step, uint64_t value) -> int64_t {
            trace.push_back(step);
            switch (step) {
            case 1: case 2: return 1;
            case 3: return 0;
            case 5: return duplicate(exists ? "AlreadyExists" : "transport failure");
            case 6: BOOST_CHECK_EQUAL(value,0U); return 1;
            default: throw std::logic_error("unexpected duplicate submission action");
            }
        });
        BOOST_CHECK_EQUAL(result,exists ? 0 : 2);
        std::vector<uint32_t> expected{1,2,3,5};
        if (exists) expected.push_back(6);
        BOOST_CHECK(trace == expected);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_bmm_parent_gate_skips_rpc_on_shutdown)
{
    namespace hs = drivechain::haskell;
    for (bool shutdown : {false,true}) for (bool same_tip : {false,true}) for (bool rpc_failure : {false,true}) {
        unsigned rpc_calls{0};
        std::vector<uint32_t> trace;
        bool threw{false};
        try {
            const int result=hs::BmmSubmit(100,100,[&](uint32_t step,uint64_t) -> int64_t {
                trace.push_back(step);
                if (step==1) return hs::ParentReplayAll<2>({[&] { return !shutdown; },[&] {
                    ++rpc_calls;
                    if (rpc_failure) throw std::runtime_error("parent RPC failure");
                    return same_tip;
                }});
                if (step==2) return 2;
                if (step==6) return 1;
                throw std::logic_error("unexpected submission action");
            });
            BOOST_CHECK_EQUAL(result,!shutdown && same_tip ? 0 : 1);
        } catch (const std::runtime_error& error) {
            threw=true;
            BOOST_CHECK_EQUAL(error.what(),"parent RPC failure");
        }
        BOOST_CHECK_EQUAL(rpc_calls,shutdown ? 0U : 1U);
        BOOST_CHECK_EQUAL(threw,!shutdown && rpc_failure);
        BOOST_CHECK(trace==(!shutdown && same_tip && !rpc_failure ?
            std::vector<uint32_t>{1,2,6} : std::vector<uint32_t>{1}));
    }
}

BOOST_AUTO_TEST_CASE(haskell_wait_intervals_match_native_bounds)
{
    const std::array<int64_t,8> values{INT64_MIN,-1,0,1,24,25,26,INT64_MAX};
    for (const auto value : values) for (const auto limit : values) {
        if (limit<1) BOOST_CHECK_EXCEPTION(drivechain::haskell::BoundedWait(value,limit),std::runtime_error,
            [](const std::runtime_error& error) { return std::string_view{error.what()}=="Haskell wait interval bounds failed"; });
        else BOOST_CHECK_EQUAL(drivechain::haskell::BoundedWait(value,limit),std::max<int64_t>(1,std::min(limit,value)));
    }
}

BOOST_AUTO_TEST_CASE(haskell_output_append_matches_native_bounds)
{
    const std::array<uint64_t,6> sizes{0,1,4095,4096,4097,UINT64_MAX};
    const std::array<int64_t,8> counts{INT64_MIN,-1,0,1,4095,4096,4097,INT64_MAX};
    for (const auto limit : sizes) for (const auto used : sizes) for (const auto count : counts) {
        if (count<0) BOOST_CHECK_EXCEPTION(drivechain::haskell::BoundedAppend(limit,used,count),std::runtime_error,
            [](const std::runtime_error& error) { return std::string_view{error.what()}=="Haskell output append bounds failed"; });
        else BOOST_CHECK_EQUAL(drivechain::haskell::BoundedAppend(limit,used,count),
            std::min<uint64_t>(limit>used ? limit-used : 0,static_cast<uint64_t>(count)));
    }
}

BOOST_AUTO_TEST_CASE(drivechain_bmm_replacement_limit)
{
    namespace hs = drivechain::haskell;
    const std::vector<CAmount> values{-1,0,1,MAX_MONEY-1,MAX_MONEY,MAX_MONEY+1,
        std::numeric_limits<CAmount>::min(),std::numeric_limits<CAmount>::max()};
    for (const CAmount selected : values) for (const CAmount extra : values) {
        if (!MoneyRange(extra)) BOOST_CHECK_EQUAL(hs::BmmReplacementLimit(selected,extra),-1);
        else if (selected <= 0 || !MoneyRange(selected))
            BOOST_CHECK_THROW(hs::BmmReplacementLimit(selected,extra),std::runtime_error);
        else BOOST_CHECK_EQUAL(hs::BmmReplacementLimit(selected,extra),
            selected + std::min(extra,MAX_MONEY-selected));
    }
}

#ifndef WIN32
BOOST_AUTO_TEST_CASE(bounded_child_escalates_ignored_sigterm)
{
    const auto pid_file = m_path_root / "grace-child.pid";
    pid_t child_pid{0};
    const auto result = RunBoundedCommand(
        {"/bin/sh","-c","trap '' TERM; echo $$ > \"$1\"; exec /bin/sleep 5","grace",fs::PathToString(pid_file)},
        std::chrono::milliseconds{2000},1024,[&] {
            std::ifstream input(pid_file);
            return static_cast<bool>(input >> child_pid);
        });
    BOOST_REQUIRE(result.started);
    BOOST_REQUIRE(child_pid > 0);
    BOOST_CHECK(result.exited);
    BOOST_CHECK(result.cancelled);
    BOOST_CHECK(!result.timed_out);
    BOOST_CHECK_EQUAL(result.exit_code,128+SIGKILL);
    int status{0};
    const auto waited = waitpid(child_pid,&status,WNOHANG);
    const int wait_error = errno;
    const int signalled = kill(child_pid,0);
    const int signal_error = errno;
    BOOST_CHECK_EQUAL(waited,-1);
    BOOST_CHECK_EQUAL(wait_error,ECHILD);
    BOOST_CHECK_EQUAL(signalled,-1);
    BOOST_CHECK_EQUAL(signal_error,ESRCH);
}

BOOST_AUTO_TEST_CASE(bounded_child_monitor_exception_reaps)
{
    const auto pid_file = m_path_root / "monitor-child.pid";
    pid_t child_pid{0};
    const auto run = [&] {
        return RunBoundedCommand({"/bin/sh","-c","echo $$ > \"$1\"; exec /bin/sleep 5","monitor",fs::PathToString(pid_file)},
            std::chrono::milliseconds{2000},1024,[&] {
                std::ifstream input(pid_file);
                if (!(input >> child_pid)) return false;
                throw std::runtime_error("injected monitor exception");
            });
    };
    BOOST_CHECK_EXCEPTION(run(),std::runtime_error,[](const std::runtime_error& error) {
        return std::string(error.what()) == "injected monitor exception";
    });
    BOOST_REQUIRE(child_pid > 0);
    int status{0};
    const auto waited = waitpid(child_pid,&status,WNOHANG);
    const int wait_error = errno;
    const int signalled = kill(child_pid,0);
    const int signal_error = errno;
    BOOST_CHECK_EQUAL(waited,-1);
    BOOST_CHECK_EQUAL(wait_error,ECHILD);
    BOOST_CHECK_EQUAL(signalled,-1);
    BOOST_CHECK_EQUAL(signal_error,ESRCH);
}

#endif

BOOST_AUTO_TEST_CASE(haskell_startup_load_parent_gates)
{
    for (bool warm : {false,true}) for (bool second : {false,true}) for (unsigned fault=0;fault<=2;++fault) {
        std::vector<unsigned> trace;
        bool reconciling{false}, threw{false};
        try {
            const bool accepted=drivechain::haskell::ParentReplayAll<2>({[&] {
                trace.push_back(1);
                if (fault==1) throw std::runtime_error("warm failure");
                return warm;
            }, [&] {
                trace.push_back(2);
                reconciling=true;
                if (fault==2) throw std::runtime_error("second gate failure");
                return second;
            }});
            BOOST_CHECK_EQUAL(accepted,warm && second);
        } catch (const std::runtime_error& error) {
            threw=true;
            BOOST_CHECK_EQUAL(error.what(),fault==1 ? "warm failure" : "second gate failure");
        }
        const bool reached_second=warm && fault!=1;
        BOOST_CHECK_EQUAL(reconciling,reached_second);
        BOOST_CHECK_EQUAL(threw,fault==1 || (fault==2 && reached_second));
        BOOST_CHECK(trace==(reached_second ? std::vector<unsigned>{1,2} : std::vector<unsigned>{1}));
    }
}

BOOST_AUTO_TEST_CASE(haskell_startup_parent_preserves_failure_order)
{
    namespace hs = drivechain::haskell;
    const std::array stages{hs::ReplayStoreFlow::STARTUP_PARENT_LOAD,
        hs::ReplayStoreFlow::STARTUP_PARENT_VERIFY, hs::ReplayStoreFlow::STARTUP_PARENT};
    for (unsigned stage=0;stage<stages.size();++stage)
    for (unsigned mask=0;mask<64;++mask) for (uint32_t fault=0;fault<=8;++fault) {
        const auto yes=[&](unsigned bit) { return (mask&(1U<<bit))!=0; };
        std::vector<uint32_t> expected{7};
        uint32_t outcome{0};
        if (yes(5)) {
            if (stage!=1) expected.push_back(8);
            expected.push_back(1); outcome=1;
            if (yes(0)) {
                if (stage==1) {
                    expected.push_back(5); outcome=yes(3) ? 0 : 3;
                } else {
                    expected.push_back(2); outcome=stage==0 ? 1 : 2;
                    if (yes(1)) {
                        outcome=0;
                        if (stage==2) {
                            expected.push_back(3);
                            if (!yes(2)) expected.push_back(4);
                            expected.push_back(5); outcome=3;
                            if (yes(3)) { expected.push_back(6); outcome=yes(4) ? 0 : 3; }
                        }
                    }
                }
            }
        }
        const auto stop=std::find(expected.begin(),expected.end(),fault);
        const bool throws=stop!=expected.end();
        if (throws) expected.erase(stop+1,expected.end());
        std::vector<uint32_t> trace;
        bool threw{false};
        try {
            const auto result=hs::ParentReplayStore(stages[stage],[&](uint32_t step) -> uint32_t {
                    trace.push_back(step);
                    if (step==fault) throw std::runtime_error("startup parent callback failure");
                    if (step==4 || step==8) return 1;
                    if (step==7) return yes(5);
                    return yes(step<4 ? step-1 : step-2);
                });
            BOOST_CHECK_EQUAL(result,outcome);
        } catch (const std::runtime_error& error) {
            threw=true;
            BOOST_CHECK_EQUAL(error.what(),"startup parent callback failure");
        }
        BOOST_CHECK_EQUAL(threw,throws);
        BOOST_CHECK(trace==expected);
    }
}

BOOST_AUTO_TEST_CASE(haskell_startup_bundle_restoration_order)
{
    namespace hs = drivechain::haskell;
    for (bool enabled : {false, true}) for (bool present : {false, true})
    for (uint32_t fault=0; fault<=6; ++fault) {
        std::vector<uint32_t> expected{1};
        if (!enabled) expected.push_back(6);
        else {
            expected.push_back(2);
            if (present) expected.push_back(3);
            expected.insert(expected.end(), {4,5});
        }
        const auto stop=std::find(expected.begin(),expected.end(),fault);
        const bool throws=stop!=expected.end();
        if (throws) expected.erase(stop+1,expected.end());
        std::vector<uint32_t> trace;
        bool locked{false}, selected{false}, published{false}, logged{false}, threw{false};
        try {
            BOOST_CHECK_EQUAL(hs::ParentReplayStore(hs::ReplayStoreFlow::STARTUP_BUNDLE,
                [&](uint32_t step) -> uint32_t {
                    trace.push_back(step);
                    if (step==fault) throw std::runtime_error("bundle callback failure");
                    switch (step) {
                    case 1: return enabled;
                    case 2: locked=true; return present;
                    case 3: BOOST_REQUIRE(locked && present); selected=true; break;
                    case 4: case 6:
                        BOOST_CHECK_EQUAL(locked,enabled);
                        BOOST_CHECK_EQUAL(selected,enabled && present);
                        published=true; break;
                    case 5: BOOST_REQUIRE(locked && published); logged=true; break;
                    default: BOOST_FAIL("unexpected bundle action");
                    }
                    return 1;
                }),0U);
        } catch (const std::runtime_error& e) {
            threw=true;
            BOOST_CHECK_EQUAL(e.what(),"bundle callback failure");
        }
        BOOST_CHECK_EQUAL(threw,throws);
        BOOST_CHECK(trace==expected);
        if (!throws) {
            BOOST_CHECK(published);
            BOOST_CHECK_EQUAL(logged,enabled);
        }
    }
}

BOOST_AUTO_TEST_CASE(haskell_submission_gate_exception_boundary)
{
    for (bool current : {false,true}) for (bool guard_fault : {false,true})
    for (bool submit_fault : {false,true}) {
        unsigned submissions{0}, logs{0};
        bool threw{false};
        try {
            const bool result=drivechain::haskell::ParentReplayAll<2>({
                [&] {
                    if (guard_fault) throw std::runtime_error("parent lookup");
                    return current;
                },
                [&] {
                    try {
                        ++submissions;
                        if (submit_fault) throw std::runtime_error("submission");
                        return true;
                    } catch (const std::exception&) { ++logs; return false; }
                },
            });
            BOOST_CHECK_EQUAL(result,current && !submit_fault);
        } catch (const std::runtime_error& e) {
            threw=true;
            BOOST_CHECK_EQUAL(e.what(),"parent lookup");
        }
        BOOST_CHECK_EQUAL(threw,guard_fault);
        BOOST_CHECK_EQUAL(submissions,current && !guard_fault ? 1U : 0U);
        BOOST_CHECK_EQUAL(logs,current && !guard_fault && submit_fault ? 1U : 0U);
    }
}

BOOST_AUTO_TEST_CASE(haskell_contextual_validation_preserves_order)
{
    namespace hs = drivechain::haskell;
    const std::array stages{hs::ReplayStoreFlow::CONTEXTUAL_HEADER,
        hs::ReplayStoreFlow::CONTEXTUAL_OUTPUTS, hs::ReplayStoreFlow::CANDIDATE_SELF_CHECK};
    for (unsigned stage=0; stage<stages.size(); ++stage)
    for (unsigned mask=0; mask<128; ++mask) for (uint32_t fault=0; fault<=9; ++fault) {
        const auto yes=[&](unsigned bit) { return (mask & (1U<<bit))!=0; };
        std::vector<uint32_t> expected;
        const auto fact=[&](uint32_t step, unsigned bit) { expected.push_back(step); return yes(bit); };
        bool valid{false};
        if (stage==0) valid=!fact(1,0) || (fact(2,1) && fact(3,2));
        else if (stage==1) valid=(!fact(1,0) || fact(2,1)) && (!fact(3,2) || fact(4,3));
        else if (fact(1,0) && fact(2,1) && fact(3,2)) {
            expected.push_back(4); // Native budget lifetime starts after all three checks.
            valid=true;
            if (!fact(5,3) && fact(6,4)) {
                valid=fact(7,5);
                if (valid) expected.push_back(8);
            }
            if (valid) valid=fact(9,6);
        }
        const auto stop=std::find(expected.begin(),expected.end(),fault);
        const bool throws=stop!=expected.end();
        if (throws) expected.erase(stop+1,expected.end());
        bool threw{false};
        std::vector<uint32_t> trace;
        try {
            const auto result=hs::ParentReplayStore(stages[stage],[&](uint32_t step) -> uint32_t {
                trace.push_back(step);
                if (step==fault) throw std::runtime_error("contextual callback failure");
                if (stage!=2 || step<=3) return yes(step-1);
                if (step==4 || step==8) return 1;
                return yes(step==9 ? 6 : step-2);
            });
            BOOST_CHECK_EQUAL(result,valid ? 1U : 0U);
        } catch (const std::runtime_error& error) {
            threw=true;
            BOOST_CHECK_EQUAL(error.what(),"contextual callback failure");
        }
        BOOST_CHECK_EQUAL(threw,throws);
        BOOST_CHECK(trace==expected);
    }
}

BOOST_FIXTURE_TEST_CASE(candidate_self_check_preserves_state_and_precedence, RegTestingSetup)
{
    node::BlockAssembler::Options options;
    options.coinbase_output_script = CScript() << OP_TRUE;
    const auto prepared = PrepareBlock(m_node,options);
    LOCK(cs_main);
    LOCK(m_node.mempool->cs);
    auto& chainman = *m_node.chainman;
    auto& chainstate = chainman.ActiveChainstate();
    CBlockIndex* tip = chainman.ActiveTip();
    BOOST_REQUIRE(tip);
    const auto best = chainstate.CoinsTip().GetBestBlock();
    const auto count = chainman.m_blockman.m_block_index.size();
    for (unsigned scenario=0; scenario<3; ++scenario) {
        CBlock block = *prepared;
        block.fChecked = block.m_checked_witness_commitment = block.m_checked_merkle_root = false;
        if (scenario) block.vtx.clear();
        if (scenario==1) block.nTime = tip->GetMedianTimePast();
        BlockValidationState state;
        BOOST_CHECK_EQUAL(TestBlockCandidateValidity(state,Params(),chainstate,block,tip,false,false),scenario==0);
        if (scenario==0) BOOST_CHECK(state.IsValid());
        else {
            BOOST_CHECK(state.IsInvalid());
            BOOST_CHECK_EQUAL(state.GetRejectReason(),scenario==1 ? "time-too-old" : "bad-blk-length");
        }
        BOOST_CHECK(chainman.ActiveTip()==tip);
        BOOST_CHECK(chainstate.CoinsTip().GetBestBlock()==best);
        BOOST_CHECK_EQUAL(chainman.m_blockman.m_block_index.size(),count);
    }
}


BOOST_AUTO_TEST_CASE(haskell_final_bmm_admission_order)
{
    namespace hs = drivechain::haskell;
    static_assert(static_cast<uint32_t>(hs::ReplayStoreFlow::FINAL_BMM)==324);
    static_assert(static_cast<uint32_t>(hs::ReplayStoreFlow::BMM_FAILURE)==325);
    const auto caller=std::this_thread::get_id();
    for (bool slot : {false,true}) for (bool genesis : {false,true})
    for (bool derived : {false,true})
    for (auto status : {DrivechainBmmStatus::VALID,DrivechainBmmStatus::INVALID,
                       DrivechainBmmStatus::PARENT_REJECTED,DrivechainBmmStatus::UNAVAILABLE})
    for (uint32_t fault=0; fault<=8; ++fault) {
        std::vector<uint32_t> expected{1};
        uint32_t outcome{1};
        if (slot) {
            expected.push_back(2);
            if (!genesis) {
                expected.push_back(3);
                if (!derived) { expected.push_back(4); outcome=0; }
                else {
                    expected.push_back(5);
                    if (status==DrivechainBmmStatus::INVALID) { expected.push_back(6); outcome=0; }
                    else {
                        expected.push_back(7);
                        if (status!=DrivechainBmmStatus::VALID) { expected.push_back(8); outcome=2; }
                    }
                }
            }
        }
        const auto stop=std::find(expected.begin(),expected.end(),fault);
        const bool throws=stop!=expected.end();
        if (throws) expected.erase(stop+1,expected.end());
        std::vector<uint32_t> trace, effects;
        BlockValidationState state;
        bool stalled{false}, invalidated{false}, context{false}, threw{false};
        try {
            const auto result=hs::ParentReplayStore(hs::ReplayStoreFlow::FINAL_BMM,
                [&](uint32_t step) -> uint32_t {
                BOOST_CHECK(std::this_thread::get_id()==caller);
                trace.push_back(step);
                if (step==fault) throw std::runtime_error("BMM callback failure");
                switch (step) {
                case 1: return slot;
                case 2: return !genesis;
                case 3: context=true; effects.push_back(3); return derived;
                case 4: effects.push_back(4); return state.Error("derivation failed");
                case 5: BOOST_CHECK(context); effects.push_back(5); return status==DrivechainBmmStatus::INVALID;
                case 6:
                    effects.push_back(6);
                    state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,"bad-drivechain-bmm");
                    invalidated=true;
                    return false;
                case 7: return status==DrivechainBmmStatus::VALID;
                case 8: effects.push_back(8); stalled=true; return true;
                default: throw std::logic_error("unexpected BMM action");
                }
            });
            BOOST_CHECK_EQUAL(result,outcome);
        } catch (const std::runtime_error& error) {
            threw=true;
            BOOST_CHECK_EQUAL(error.what(),"BMM callback failure");
        }
        BOOST_CHECK_EQUAL(threw,throws);
        BOOST_CHECK(trace==expected);
        std::vector<uint32_t> expected_effects;
        for (auto step : expected)
            if (step!=fault && (step==3 || step==4 || step==5 || step==6 || step==8)) expected_effects.push_back(step);
        BOOST_CHECK(effects==expected_effects);
        const auto ran=[&](uint32_t step) { return std::find(effects.begin(),effects.end(),step)!=effects.end(); };
        BOOST_CHECK_EQUAL(context,ran(3));
        BOOST_CHECK_EQUAL(state.IsInvalid(),ran(6));
        BOOST_CHECK_EQUAL(invalidated,ran(6));
        BOOST_CHECK_EQUAL(state.IsError(),ran(4));
        BOOST_CHECK_EQUAL(stalled,ran(8));
    }
}

BOOST_AUTO_TEST_CASE(haskell_branch_choice_preserves_effects)
{
    namespace hs = drivechain::haskell;
    static_assert(static_cast<uint32_t>(hs::ReplayStoreFlow::BRANCH_CHOICE)==321);
    const auto caller=std::this_thread::get_id();
    for (bool condition : {false,true}) for (bool yes : {false,true})
    for (bool no : {false,true}) for (uint32_t fault=0; fault<=3; ++fault) {
        std::vector<uint32_t> trace, expected{1,condition ? 2U : 3U};
        const auto stop=std::find(expected.begin(),expected.end(),fault);
        const bool throws=stop!=expected.end();
        if (throws) expected.erase(stop+1,expected.end());
        const auto call=[&](uint32_t step, bool result) {
            BOOST_CHECK(std::this_thread::get_id()==caller);
            trace.push_back(step);
            if (step==fault) throw std::runtime_error("branch callback failure");
            return result;
        };
        bool threw{false};
        try {
            const bool result=hs::ParentReplayChoose({
                [&] { return call(1,condition); }, [&] { return call(2,yes); }, [&] { return call(3,no); },
            });
            BOOST_CHECK_EQUAL(result,condition ? yes : no);
        } catch (const std::runtime_error& error) {
            threw=true;
            BOOST_CHECK_EQUAL(error.what(),"branch callback failure");
        }
        BOOST_CHECK_EQUAL(threw,throws);
        BOOST_CHECK(trace==expected);
    }
}

BOOST_AUTO_TEST_CASE(haskell_branch_choice_preserves_input_error_state)
{
    for (bool transient : {false,true}) for (unsigned prior=0; prior<3; ++prior) {
        BlockValidationState actual, expected;
        for (auto* state : {&actual,&expected}) {
            if (prior==1) state->Invalid(BlockValidationResult::BLOCK_CONSENSUS,"prior invalid");
            if (prior==2) state->Error("prior error");
        }
        TxValidationState input;
        if (transient) input.Error("parent unavailable");
        else input.Invalid(TxValidationResult::TX_CONSENSUS,"bad inputs","input detail");
        if (input.IsError()) expected.Error(input.ToString());
        else expected.Invalid(BlockValidationResult::BLOCK_CONSENSUS,input.GetRejectReason(),input.GetDebugMessage());
        const bool stopped=drivechain::haskell::ParentReplayChoose({
            [&] { return input.IsError(); },
            [&] { actual.Error(input.ToString()); return true; },
            [] { return false; },
        });
        if (!stopped) actual.Invalid(BlockValidationResult::BLOCK_CONSENSUS,input.GetRejectReason(),input.GetDebugMessage());
        BOOST_CHECK_EQUAL(stopped,transient);
        BOOST_CHECK_EQUAL(actual.IsError(),expected.IsError());
        BOOST_CHECK_EQUAL(actual.IsInvalid(),expected.IsInvalid());
        BOOST_CHECK(actual.GetResult()==expected.GetResult());
        BOOST_CHECK_EQUAL(actual.GetRejectReason(),expected.GetRejectReason());
        BOOST_CHECK_EQUAL(actual.GetDebugMessage(),expected.GetDebugMessage());
    }
}

BOOST_AUTO_TEST_CASE(haskell_pegin_failure_decisions)
{
    for (bool unavailable : {false,true}) for (unsigned prior=0; prior<3; ++prior) {
        TxValidationState actual, expected;
        for (auto* state : {&actual,&expected}) {
            if (prior==1) state->Invalid(TxValidationResult::TX_CONSENSUS,"prior invalid");
            if (prior==2) state->Error("prior error");
        }
        const std::string detail="witness detail";
        if (unavailable) expected.Error("drivechain parent state unavailable: " + detail);
        else expected.Invalid(TxValidationResult::TX_WITNESS_MUTATED,"pegin-no-witness",detail);
        unsigned effects{0};
        BOOST_CHECK(!drivechain::haskell::ParentReplayChoose({
            [&] { return unavailable; },
            [&] { ++effects; return actual.Error("drivechain parent state unavailable: " + detail); },
            [&] { ++effects; return actual.Invalid(TxValidationResult::TX_WITNESS_MUTATED,"pegin-no-witness",detail); },
        }));
        BOOST_CHECK_EQUAL(effects,1U);
        BOOST_CHECK_EQUAL(actual.IsError(),expected.IsError());
        BOOST_CHECK_EQUAL(actual.IsInvalid(),expected.IsInvalid());
        BOOST_CHECK(actual.GetResult()==expected.GetResult());
        BOOST_CHECK_EQUAL(actual.GetRejectReason(),expected.GetRejectReason());
        BOOST_CHECK_EQUAL(actual.GetDebugMessage(),expected.GetDebugMessage());
    }
    for (bool depth : {false,true}) for (bool unavailable : {false,true}) {
        std::vector<unsigned> expected{1};
        if (!depth) expected.push_back(2);
        CheckLazyHeaderGate(expected,!depth && !unavailable,[&](const auto& read) {
            return drivechain::haskell::ParentReplayAll<2>({
                [&] { return !read(1,depth); }, [&] { return !read(2,unavailable); },
            });
        });
    }
}

BOOST_AUTO_TEST_CASE(haskell_optional_validation_effects)
{
    namespace hs = drivechain::haskell;
    const auto caller=std::this_thread::get_id();
    for (bool enabled : {false,true}) for (bool first : {false,true})
    for (bool second : {false,true}) for (uint32_t fault=0; fault<=3; ++fault) {
        std::vector<uint32_t> trace, expected{1};
        if (enabled) {
            expected.push_back(2);
            if (first) expected.push_back(3);
        }
        const auto stop=std::find(expected.begin(),expected.end(),fault);
        const bool throws=stop!=expected.end();
        if (throws) expected.erase(stop+1,expected.end());
        const auto call=[&](uint32_t step,bool result) {
            BOOST_CHECK(std::this_thread::get_id()==caller);
            trace.push_back(step);
            if (step==fault) throw std::runtime_error("optional validation failure");
            return result;
        };
        bool threw{false};
        try {
            const bool result=hs::ParentReplayChoose({
                [&] { return call(1,enabled); },
                [&] { return hs::ParentReplayAll<2>({
                    [&] { return call(2,first); }, [&] { return call(3,second); },
                }); },
                [] { return true; },
            });
            BOOST_CHECK_EQUAL(result,!enabled || (first && second));
        } catch (const std::runtime_error& error) {
            threw=true;
            BOOST_CHECK_EQUAL(error.what(),"optional validation failure");
        }
        BOOST_CHECK_EQUAL(threw,throws);
        BOOST_CHECK(trace==expected);
    }
}

BOOST_AUTO_TEST_CASE(haskell_bmm_failure_state)
{
    namespace hs = drivechain::haskell;
    for (auto status : {DrivechainBmmStatus::INVALID,DrivechainBmmStatus::PARENT_REJECTED,
                       DrivechainBmmStatus::UNAVAILABLE}) {
        BlockValidationState state;
        std::vector<uint32_t> trace;
        const auto result=hs::ParentReplayStore(hs::ReplayStoreFlow::BMM_FAILURE,
            [&](uint32_t step) -> uint32_t {
            trace.push_back(step);
            switch (step) {
            case 1: return status==DrivechainBmmStatus::INVALID;
            case 2: return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,"bad-drivechain-bmm");
            case 3: return status==DrivechainBmmStatus::PARENT_REJECTED;
            case 4: return state.Error("parent rejected");
            case 5: return state.Error("unavailable");
            default: throw std::logic_error("unexpected BMM failure action");
            }
        });
        const std::vector<uint32_t> expected=status==DrivechainBmmStatus::INVALID ?
            std::vector<uint32_t>{1,2} : std::vector<uint32_t>{1,3,status==DrivechainBmmStatus::PARENT_REJECTED ? 4U : 5U};
        BOOST_CHECK(trace==expected);
        BOOST_CHECK_EQUAL(result,0U);
        BOOST_CHECK_EQUAL(state.IsInvalid(),status==DrivechainBmmStatus::INVALID);
        BOOST_CHECK_EQUAL(state.IsError(),status!=DrivechainBmmStatus::INVALID);
        BOOST_CHECK_EQUAL(state.GetRejectReason(),status==DrivechainBmmStatus::INVALID ? "bad-drivechain-bmm" :
            status==DrivechainBmmStatus::PARENT_REJECTED ? "parent rejected" : "unavailable");
    }
}

BOOST_AUTO_TEST_CASE(haskell_dynafed_mode_guard_is_lazy)
{
    for (bool elements : {false,true}) for (bool active : {false,true})
    for (bool fault : {false,true}) {
        unsigned reads{0};
        bool threw{false};
        try {
            const bool result=drivechain::haskell::ParentReplayAll<2>({
                [&] { return elements; },
                [&] {
                    ++reads;
                    if (fault) throw std::runtime_error("deployment lookup failure");
                    return active;
                },
            });
            BOOST_CHECK_EQUAL(result,elements && active);
        } catch (const std::runtime_error& error) {
            threw=true;
            BOOST_CHECK_EQUAL(error.what(),"deployment lookup failure");
        }
        BOOST_CHECK_EQUAL(reads,elements ? 1U : 0U);
        BOOST_CHECK_EQUAL(threw,elements && fault);
    }
}

BOOST_AUTO_TEST_CASE(haskell_parent_height_boundaries)
{
    for (int32_t height : {INT32_MIN,int32_t{-2},int32_t{-1},int32_t{0},int32_t{1},INT32_MAX-1,INT32_MAX}) {
        const auto expected = static_cast<uint64_t>(height) + uint64_t{1};
        BOOST_CHECK_EQUAL(drivechain::haskell::NextBondContextHeight(height),expected);
        if (height == INT32_MAX)
            BOOST_CHECK_THROW(drivechain::haskell::NextBlockHeight(true,height),std::runtime_error);
        else BOOST_CHECK_EQUAL(drivechain::haskell::NextBlockHeight(true,height),int64_t{height}+1);
    }
    for (int64_t parent : {INT64_MIN,int64_t{-1},int64_t{0},int64_t{1},int64_t{2147483647},
            int64_t{4294967294},int64_t{4294967295},INT64_MAX}) {
        uint64_t successor{73};
        const bool valid=parent>=0 && parent<4294967295;
        BOOST_CHECK_EQUAL(drivechain::haskell::ApprovingParentHeight(parent,successor),valid);
        BOOST_CHECK_EQUAL(successor,valid ? uint64_t(parent)+1 : 73U);
        for (int64_t child : {INT64_MIN,int64_t{-2147483648},int64_t{-1},int64_t{0},int64_t{2147483647},INT64_MAX}) {
            std::vector<uint32_t> calls;
            const bool produced = drivechain::haskell::BmmSyncTick(parent, child, [&](uint32_t step) {
                calls.push_back(step);
                return true;
            });
            BOOST_CHECK_EQUAL(produced, child < parent);
            BOOST_CHECK(calls == (child < parent ? std::vector<uint32_t>{4,5} : std::vector<uint32_t>{}));
        }
    }
}

BOOST_AUTO_TEST_CASE(haskell_mempool_height_laziness)
{
    for (bool enabled : {false,true}) {
        for (int32_t height : {int32_t{-1},int32_t{0},INT32_MAX-1,INT32_MAX}) {
            unsigned reads{0};
            int32_t observed{-17};
            const auto evaluate = [&] {
                return drivechain::haskell::ParentReplayAll<2>({
                    [&] { return enabled; },
                    [&] {
                        ++reads;
                        observed = drivechain::haskell::NextBlockHeight(true,height);
                        return true;
                    },
                });
            };
            if (enabled && height == INT32_MAX)
                BOOST_CHECK_THROW(evaluate(),std::runtime_error);
            else BOOST_CHECK_EQUAL(evaluate(),enabled);
            BOOST_CHECK_EQUAL(reads,enabled ? 1U : 0U);
            BOOST_CHECK_EQUAL(observed,enabled && height != INT32_MAX ? int64_t{height}+1 : -17);
        }
    }
}

BOOST_AUTO_TEST_CASE(ordinary_startup_reconciliation_preserves_chain)
{
    auto& chainman=*m_node.chainman;
    BOOST_REQUIRE(!chainman.GetConsensus().drivechain_slot);
    auto& chainstate=chainman.ActiveChainstate();
    const auto tip=WITH_LOCK(cs_main,return chainman.ActiveTip());
    const auto best=WITH_LOCK(cs_main,return chainstate.CoinsTip().GetBestBlock());
    BlockValidationState state;
    BOOST_CHECK(chainstate.ReconcileDrivechainAnchorsForStartup(state));
    BOOST_CHECK(state.IsValid());
    LOCK(cs_main);
    BOOST_CHECK(chainman.ActiveTip()==tip);
    BOOST_CHECK(chainstate.CoinsTip().GetBestBlock()==best);
}

#ifndef WIN32
BOOST_AUTO_TEST_CASE(bounded_direct_child_process)
{
    for (const std::vector<std::string>& argv : {std::vector<std::string>{}, {""}, {"not-executed"}}) {
        for (int64_t timeout : {-1,0,1}) for (size_t limit : {0U,1U}) {
            unsigned cancellations{0};
            const auto rejected = RunBoundedCommand(argv,std::chrono::milliseconds{timeout},limit,[&] {
                ++cancellations;
                return true;
            });
            const bool executable = !argv.empty() && !argv.front().empty();
            const bool valid = executable && timeout>0 && limit>0;
            BOOST_CHECK(!rejected.started && !rejected.exited && rejected.output.empty());
            BOOST_CHECK_EQUAL(rejected.cancelled,valid);
            BOOST_CHECK_EQUAL(cancellations,valid ? 1U : 0U);
            BOOST_CHECK_EQUAL(rejected.error,!executable ? "bounded command has no executable" :
                valid ? "" : "bounded command requires positive timeout and output limit");
        }
    }
    const BoundedCommandResult invalid_exec = RunBoundedCommand(
        {fs::PathToString(m_path_root / "missing-executable")},
        std::chrono::milliseconds{1000},1024);
    BOOST_REQUIRE(invalid_exec.started);
    BOOST_CHECK(invalid_exec.exited);
    BOOST_CHECK_EQUAL(invalid_exec.exit_code,127);
    BOOST_CHECK_EQUAL(invalid_exec.output,"execvp failed\n");

    unsigned preflight_calls{0};
    BOOST_CHECK_EXCEPTION(RunBoundedCommand({"not-executed"},std::chrono::milliseconds{1},1,[&]() -> bool {
        ++preflight_calls;
        throw std::runtime_error("preflight cancellation failure");
    }),std::runtime_error,[](const std::runtime_error& failure) {
        return std::string_view{failure.what()}=="preflight cancellation failure";
    });
    BOOST_CHECK_EQUAL(preflight_calls,1U);

    const BoundedCommandResult echo = RunBoundedCommand(
        {"/bin/echo", "bounded-child-ok"},
        std::chrono::milliseconds{1000}, 1024);
    BOOST_REQUIRE(echo.started);
    BOOST_CHECK(echo.exited);
    BOOST_CHECK_EQUAL(echo.exit_code, 0);
    BOOST_CHECK_EQUAL(echo.output, "bounded-child-ok\n");
    BOOST_CHECK(!echo.timed_out);
    BOOST_CHECK(!echo.output_truncated);

    const std::string binary_output("a\0b",3);
    for (const size_t limit : {2U,3U,4U}) {
        const BoundedCommandResult binary = RunBoundedCommand(
            {"/usr/bin/printf","a\\000b"},std::chrono::milliseconds{1000},limit);
        BOOST_REQUIRE(binary.started);
        BOOST_CHECK(binary.exited);
        BOOST_CHECK(!binary.timed_out);
        BOOST_CHECK_EQUAL(binary.output,binary_output.substr(0,limit));
        BOOST_CHECK_EQUAL(binary.output_truncated,limit < binary_output.size());
    }

    const BoundedCommandResult truncated = RunBoundedCommand(
        {"/usr/bin/yes", "x"}, std::chrono::milliseconds{1000}, 1024);
    BOOST_REQUIRE(truncated.started);
    BOOST_CHECK(truncated.exited);
    BOOST_CHECK(truncated.output_truncated);
    BOOST_CHECK_EQUAL(truncated.output.size(), 1024U);

    const BoundedCommandResult timed_out = RunBoundedCommand(
        {"/bin/sleep", "5"}, std::chrono::milliseconds{50}, 1024);
    BOOST_REQUIRE(timed_out.started);
    BOOST_CHECK(timed_out.exited);
    BOOST_CHECK(timed_out.timed_out);

    const BoundedCommandResult cancelled = RunBoundedCommand(
        {"/bin/sleep", "5"}, std::chrono::milliseconds{1000}, 1024,
        [] { return true; });
    BOOST_CHECK(!cancelled.started);
    BOOST_CHECK(!cancelled.exited);
    BOOST_CHECK(cancelled.cancelled);

    int cancellation_checks{0};
    const BoundedCommandResult cancelled_after_start = RunBoundedCommand(
        {"/bin/sleep", "5"}, std::chrono::milliseconds{1000}, 1024,
        [&] { return ++cancellation_checks > 1; });
    BOOST_REQUIRE(cancelled_after_start.started);
    BOOST_CHECK(cancelled_after_start.exited);
    BOOST_CHECK(cancelled_after_start.cancelled);
}
#endif

BOOST_AUTO_TEST_CASE(signet_parse_tests)
{
    ArgsManager signet_argsman;
    signet_argsman.ForceSetArg("-signetchallenge", "51"); // set challenge to OP_TRUE
    const auto signet_params = CreateChainParams(signet_argsman, ChainType::SIGNET);
    CBlock block;
    BOOST_CHECK(signet_params->GetConsensus().signet_challenge == std::vector<uint8_t>{OP_TRUE});
    CScript challenge{OP_TRUE};

    // empty block is invalid
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // no witness commitment
    CMutableTransaction cb;
    cb.vout.emplace_back(CAsset(), 0, CScript{});
    block.vtx.push_back(MakeTransactionRef(cb));
    block.vtx.push_back(MakeTransactionRef(cb)); // Add dummy tx to exercise merkle root code
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // no header is treated valid
    std::vector<uint8_t> witness_commitment_section_141{0xaa, 0x21, 0xa9, 0xed};
    for (int i = 0; i < 32; ++i) {
        witness_commitment_section_141.push_back(0xff);
    }
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(SignetTxs::Create(block, challenge));
    BOOST_CHECK(CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // no data after header, valid
    std::vector<uint8_t> witness_commitment_section_325{0xec, 0xc7, 0xda, 0xa2};
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(SignetTxs::Create(block, challenge));
    BOOST_CHECK(CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // Premature end of data, invalid
    witness_commitment_section_325.push_back(0x01);
    witness_commitment_section_325.push_back(0x51);
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // has data, valid
    witness_commitment_section_325.push_back(0x00);
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(SignetTxs::Create(block, challenge));
    BOOST_CHECK(CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // Extraneous data, invalid
    witness_commitment_section_325.push_back(0x00);
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));
}

static uint256 OriginalParentSignetSignatureHash(const CScript& script_code,
                                      const Bitcoin::CTransaction& transaction,
                                      const unsigned int input_index,
                                      const int hash_type)
{
    uint256 hash_prevouts;
    uint256 hash_sequence;
    uint256 hash_outputs;
    const int base_type = hash_type & 0x1f;

    if (!(hash_type & SIGHASH_ANYONECANPAY)) {
        HashWriter writer;
        for (const auto& input : transaction.vin) writer << input.prevout;
        hash_prevouts = writer.GetHash();
    }
    if (!(hash_type & SIGHASH_ANYONECANPAY) && base_type != SIGHASH_SINGLE && base_type != SIGHASH_NONE) {
        HashWriter writer;
        for (const auto& input : transaction.vin) writer << input.nSequence;
        hash_sequence = writer.GetHash();
    }
    if (base_type != SIGHASH_SINGLE && base_type != SIGHASH_NONE) {
        HashWriter writer;
        for (const auto& output : transaction.vout) writer << output;
        hash_outputs = writer.GetHash();
    } else if (base_type == SIGHASH_SINGLE && input_index < transaction.vout.size()) {
        HashWriter writer;
        writer << transaction.vout[input_index];
        hash_outputs = writer.GetHash();
    }

    HashWriter writer;
    writer << transaction.version;
    writer << hash_prevouts;
    writer << hash_sequence;
    writer << transaction.vin[input_index].prevout;
    writer << script_code;
    writer << int64_t{0};
    writer << transaction.vin[input_index].nSequence;
    writer << hash_outputs;
    writer << transaction.nLockTime;
    writer << static_cast<uint32_t>(hash_type);
    return writer.GetHash();
}

BOOST_AUTO_TEST_CASE(bitcoin_signet_modified_merkle_matches_native)
{
    for (size_t count : {0,1,2,3,4,7,8,9,31,32,33,65}) {
        Bitcoin::CBlock block;
        for (size_t i = 0; i < count; ++i) {
            Bitcoin::CMutableTransaction tx;
            tx.nLockTime = i;
            block.vtx.push_back(Bitcoin::MakeTransactionRef(tx));
        }
        if (count) block.vtx[0] = nullptr; // Only the replacement coinbase is hashed.
        for (int version : {0, 1, 2}) {
            Bitcoin::CMutableTransaction replacement;
            replacement.version = version;
            std::vector<uint256> leaves{replacement.GetHash()};
            for (size_t i = 1; i < count; ++i) leaves.push_back(block.vtx[i]->GetHash());
            BOOST_CHECK(ComputeBitcoinModifiedMerkleRoot(replacement, block) == ComputeMerkleRoot(std::move(leaves)));
        }
    }
}

BOOST_AUTO_TEST_CASE(bitcoin_signet_checker_modes_preserve_encoding_policy)
{
    using Checker = drivechain::BitcoinSignetSignatureChecker;
    Bitcoin::CMutableTransaction spend, sign;
    drivechain::BuildBitcoinSignetTransactions(CScript() << OP_TRUE, spend, sign);
    const Bitcoin::CTransaction tx{sign};
    const CScript script = CScript() << OP_TRUE;
    CKey key;
    key.MakeNewKey(true);
    const auto pubkey = key.GetPubKey();
    const std::vector<unsigned char> public_key(pubkey.begin(), pubkey.end());
    for (int type : {0, 1, 2, 3, 0x80, 0x81, 0x83}) {
        std::vector<unsigned char> signed_bytes;
        BOOST_REQUIRE(key.Sign(drivechain::BitcoinWitnessV0SignatureHash(script, tx, 0, type), signed_bytes));
        signed_bytes.push_back(type);
        for (unsigned flags : {0U, unsigned(SCRIPT_VERIFY_DERSIG), unsigned(SCRIPT_VERIFY_STRICTENC)}) {
            for (bool parent : {false, true}) {
                const Checker checker{tx, 0, parent ? Checker::Mode::PARENT : Checker::Mode::BMM};
                for (unsigned mutation = 0; mutation < 5; ++mutation) {
                    auto signature = signed_bytes;
                    auto bytes = public_key;
                    const auto version = mutation == 4 ? SigVersion::BASE : SigVersion::WITNESS_V0;
                    if (mutation == 1) signature.clear();
                    if (mutation == 2) signature[0] ^= 1;
                    if (mutation == 3) bytes.clear();
                    const auto original = [&] {
                        if (version != SigVersion::WITNESS_V0 || signature.empty()) return false;
                        ScriptError error{SCRIPT_ERR_OK};
                        if (parent && !CheckSignatureEncoding(signature, flags, &error)) return false;
                        CPubKey native_key(bytes);
                        if (!native_key.IsValid()) return false;
                        const auto digest = drivechain::BitcoinWitnessV0SignatureHash(script, tx, 0, signature.back());
                        return native_key.Verify(digest, std::vector<unsigned char>(signature.begin(), signature.end() - 1));
                    };
                    BOOST_CHECK_EQUAL(checker.CheckECDSASignature(signature, bytes, script, version, flags), original());
                    if (mutation == 0) {
                        const bool defined_type = (type & 0x7f) >= 1 && (type & 0x7f) <= 3;
                        BOOST_CHECK_EQUAL(checker.CheckECDSASignature(signature, bytes, script, version, flags),
                            !parent || !(flags & SCRIPT_VERIFY_STRICTENC) || defined_type);
                    }
                }
            }
        }
    }
    const Bitcoin::CTransaction empty{Bitcoin::CMutableTransaction{}};
    BOOST_CHECK(!Checker(empty, 0).CheckECDSASignature({1}, public_key, script, SigVersion::WITNESS_V0, 0));
    for (const int mode : {-1, 2, 3, 99}) {
        BOOST_CHECK_THROW(Checker(tx, 0, static_cast<Checker::Mode>(mode)).CheckECDSASignature(
            {1}, public_key, script, SigVersion::WITNESS_V0, 0), std::runtime_error);
    }
}

BOOST_AUTO_TEST_CASE(bitcoin_parent_signet_assembly_matches_native)
{
    for (unsigned size : {0U, 1U, 22U, 80U, 520U}) {
        const CScript challenge = CScript() << std::vector<unsigned char>(size, 0x42);
        Bitcoin::CMutableTransaction spend, sign, expected_spend, expected_sign;
        expected_spend.version = expected_sign.version = 0;
        expected_spend.nLockTime = expected_sign.nLockTime = 0;
        expected_spend.vin.emplace_back(Bitcoin::COutPoint(), CScript(OP_0), 0);
        expected_spend.vout.emplace_back(0, challenge);
        expected_sign.vin.emplace_back(Bitcoin::COutPoint(), CScript(), 0);
        expected_sign.vout.emplace_back(0, CScript(OP_RETURN));
        drivechain::BuildBitcoinSignetTransactions(challenge, spend, sign);
        const auto bytes = [](const Bitcoin::CMutableTransaction& tx) {
            DataStream stream;
            stream << TX_WITH_WITNESS(tx);
            return std::vector<std::byte>(stream.begin(), stream.end());
        };
        BOOST_CHECK(bytes(spend) == bytes(expected_spend));
        BOOST_CHECK(bytes(sign) == bytes(expected_sign));
    }
    for (int32_t version : {0, 1, -1, std::numeric_limits<int32_t>::min(), std::numeric_limits<int32_t>::max()}) {
        for (uint32_t time : {0U, 1U, 0xffffffffU}) {
            Bitcoin::CBlockHeader header;
            header.nVersion = version;
            header.hashPrevBlock = uint256::ONE;
            header.nTime = time;
            const uint256 root = uint256::FromHex("4242424242424242424242424242424242424242424242424242424242424242").value();
            std::vector<unsigned char> expected;
            VectorWriter writer{expected, 0};
            writer << version << header.hashPrevBlock << root << time;
            BOOST_CHECK(drivechain::BitcoinSignetBlockData(header, root) == expected);
        }
    }
}

BOOST_AUTO_TEST_CASE(bitcoin_parent_signet_decode_preserves_errors)
{
    const std::vector<std::vector<unsigned char>> solutions{{0}, {0, 0}, {0, 0, 0}, {0xfd, 0, 0}, {0, 0xfd, 0, 0}};
    for (size_t i = 0; i < solutions.size(); ++i) {
        Bitcoin::CBlock block;
        Bitcoin::CMutableTransaction coinbase;
        coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0, 0);
        std::vector<unsigned char> commitment{0xaa, 0x21, 0xa9, 0xed};
        commitment.resize(36, 0x42);
        std::vector<unsigned char> section{0xec, 0xc7, 0xda, 0xa2};
        section.insert(section.end(), solutions[i].begin(), solutions[i].end());
        coinbase.vout.emplace_back(0, CScript() << OP_RETURN << commitment << section);
        block.vtx.push_back(Bitcoin::MakeTransactionRef(coinbase));
        std::string error = "unchanged";
        BOOST_CHECK_EQUAL(CheckBitcoinSignetBlockSolution(block, CScript() << OP_TRUE, uint256{}, &error), i == 1);
        BOOST_CHECK_EQUAL(error, i == 1 ? "unchanged" : i == 2 ?
            "parent signet solution has trailing bytes" : "parent signet solution is not canonically encoded");
        BOOST_CHECK_EQUAL(CheckBitcoinSignetBlockSolution(block, CScript() << OP_TRUE, uint256{}, nullptr), i == 1);
    }
}

BOOST_AUTO_TEST_CASE(bitcoin_parent_witness_scan_matches_native)
{
    const auto original = [](const std::vector<Bitcoin::CTxOut>& outputs) {
        int selected{-1};
        for (size_t i = 0; i < outputs.size(); ++i) {
            const CScript& script = outputs[i].scriptPubKey;
            if (script.size() >= 38 && script[0] == OP_RETURN && script[1] == 0x24 &&
                script[2] == 0xaa && script[3] == 0x21 && script[4] == 0xa9 && script[5] == 0xed) {
                selected = static_cast<int>(i);
            }
        }
        return selected;
    };
    const std::vector<unsigned char> prefix{0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed};
    std::vector<Bitcoin::CTxOut> outputs;
    BOOST_CHECK_EQUAL(drivechain::BitcoinWitnessCommitmentIndex(outputs), -1);
    for (unsigned size = 0; size <= 80; ++size) {
        for (unsigned mutation = 0; mutation <= 6; ++mutation) {
            auto bytes = prefix;
            if (mutation < 6) bytes[mutation] ^= 1;
            bytes.resize(size, 0x42);
            const Bitcoin::CTxOut output{0, CScript(bytes.begin(), bytes.end())};
            outputs = {output};
            BOOST_CHECK_EQUAL(drivechain::BitcoinWitnessCommitmentIndex(outputs), original(outputs));
            auto valid = prefix;
            valid.resize(38, 0);
            const Bitcoin::CTxOut commitment{0, CScript(valid.begin(), valid.end())};
            outputs = {commitment, output};
            BOOST_CHECK_EQUAL(drivechain::BitcoinWitnessCommitmentIndex(outputs), original(outputs));
            outputs = {output, commitment, output, commitment, output};
            BOOST_CHECK_EQUAL(drivechain::BitcoinWitnessCommitmentIndex(outputs), original(outputs));
        }
    }
}

BOOST_AUTO_TEST_CASE(bitcoin_parent_signet_hash_selection_matches_native)
{
    Bitcoin::CMutableTransaction tx;
    tx.version = 2;
    tx.nLockTime = 12345;
    for (unsigned i = 0; i < 3; ++i) {
        tx.vin.emplace_back(Bitcoin::COutPoint(uint256::ONE, i), CScript() << OP_1, i + 1);
    }
    const CScript script = CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0x42) << OP_EQUALVERIFY << OP_CHECKSIG;
    for (unsigned count = 0; count <= 4; ++count) {
        const Bitcoin::CTransaction immutable{tx};
        for (unsigned index = 0; index < tx.vin.size(); ++index) {
            for (int type = 0; type < 256; ++type) {
                BOOST_CHECK(drivechain::BitcoinWitnessV0SignatureHash(script, immutable, index, type) ==
                            OriginalParentSignetSignatureHash(script, immutable, index, type));
            }
        }
        tx.vout.emplace_back(100 + count, CScript() << count);
    }
}

BOOST_AUTO_TEST_CASE(bitcoin_parent_signet_solution_is_checked_without_translation)
{
    Bitcoin::CBlock block;
    std::string early_error{"unchanged"};
    BOOST_CHECK(CheckBitcoinSignetBlockSolution(block, CScript() << OP_0, block.GetHash(), &early_error));
    BOOST_CHECK_EQUAL(early_error, "unchanged");
    BOOST_CHECK(!CheckBitcoinSignetBlockSolution(block, CScript() << OP_TRUE, uint256::ONE, &early_error));
    BOOST_CHECK_EQUAL(early_error, "parent signet block has no coinbase transaction");
    BOOST_CHECK(!CheckBitcoinSignetBlockSolution(block, CScript() << OP_TRUE, uint256::ONE, nullptr));
    block.vtx.push_back(nullptr);
    BOOST_CHECK(CheckBitcoinSignetBlockSolution(block, CScript() << OP_0, block.GetHash(), &early_error));
    block.vtx.clear();
    Bitcoin::CMutableTransaction coinbase;
    coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0, 0);

    Bitcoin::CMutableTransaction noncoinbase{coinbase};
    noncoinbase.vin[0].prevout = Bitcoin::COutPoint(uint256::ONE, 0);
    block.vtx.push_back(Bitcoin::MakeTransactionRef(noncoinbase));
    BOOST_CHECK(!CheckBitcoinSignetBlockSolution(block, CScript() << OP_TRUE, uint256::ONE, &early_error));
    BOOST_CHECK_EQUAL(early_error, "parent signet block has no coinbase transaction");
    block.vtx.clear();

    std::vector<unsigned char> witness_commitment{0xaa, 0x21, 0xa9, 0xed};
    witness_commitment.resize(36, 0x42);
    coinbase.vout.emplace_back(0, CScript() << OP_RETURN << witness_commitment);
    block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(coinbase)));

    std::string error;
    // The exact pinned parent genesis is consensus-special and has no Signet
    // solution. Only exact hash equality may bypass ordinary challenge checks.
    BOOST_CHECK(CheckBitcoinSignetBlockSolution(block, CScript() << OP_0, block.GetHash(), &error));
    BOOST_CHECK(CheckBitcoinSignetBlockSolution(block, CScript() << OP_TRUE, uint256::ONE, &error));
    BOOST_CHECK(!CheckBitcoinSignetBlockSolution(block, CScript() << OP_0, uint256::ONE, &error));

    Bitcoin::CBlock no_commitment = block;
    Bitcoin::CMutableTransaction malformed_coinbase(*no_commitment.vtx[0]);
    malformed_coinbase.vout[0].scriptPubKey = CScript() << OP_RETURN << std::vector<unsigned char>{0x01};
    no_commitment.vtx[0] = Bitcoin::MakeTransactionRef(std::move(malformed_coinbase));
    BOOST_CHECK(!CheckBitcoinSignetBlockSolution(no_commitment, CScript() << OP_TRUE, uint256::ONE, &error));
    BOOST_CHECK_EQUAL(error, "parent signet block has no witness commitment");
}

BOOST_AUTO_TEST_CASE(bitcoin_parent_signet_composed_workflow_matches_original_native)
{
    // Independent pre-consolidation control flow. Codecs and the script engine
    // remain native in both versions; no workflow or action-plan helpers here.
    const auto original = [](const Bitcoin::CBlock& block, const CScript& challenge,
                              const uint256& genesis, std::string* error) {
        const auto fail = [&](const std::string& message) { if (error) *error = message; return false; };
        if (block.GetHash() == genesis) return true;
        if (block.vtx.empty() || !block.vtx[0]->IsCoinBase())
            return fail("parent signet block has no coinbase transaction");
        int selected{-1};
        for (size_t i = 0; i < block.vtx[0]->vout.size(); ++i) {
            const auto& s = block.vtx[0]->vout[i].scriptPubKey;
            if (s.size() >= 38 && s[0] == 0x6a && s[1] == 0x24 && s[2] == 0xaa &&
                s[3] == 0x21 && s[4] == 0xa9 && s[5] == 0xed) selected = static_cast<int>(i);
        }
        if (selected < 0) return fail("parent signet block has no witness commitment");
        Bitcoin::CMutableTransaction coinbase{*block.vtx[0]}, spend, sign;
        auto& script = coinbase.vout[selected].scriptPubKey;
        std::vector<unsigned char> solution, push;
        CScript replacement;
        CScript::const_iterator cursor = script.begin();
        opcodetype opcode;
        bool found{false};
        const std::vector<unsigned char> tag{0xec,0xc7,0xda,0xa2};
        while (script.GetOp(cursor,opcode,push)) {
            if (push.empty()) { replacement << opcode; continue; }
            if (!found && push.size() > tag.size() && std::equal(tag.begin(),tag.end(),push.begin())) {
                solution.assign(push.begin()+tag.size(),push.end());
                push.resize(tag.size());
                found = true;
            }
            replacement << push;
        }
        if (found) script = replacement;
        spend.version = sign.version = 0;
        spend.nLockTime = sign.nLockTime = 0;
        spend.vin.emplace_back(Bitcoin::COutPoint(),CScript(OP_0),0);
        spend.vout.emplace_back(0,challenge);
        sign.vin.emplace_back(Bitcoin::COutPoint(),CScript(),0);
        sign.vout.emplace_back(0,CScript(OP_RETURN));
        if (!solution.empty()) {
            try {
                SpanReader reader{solution};
                reader >> sign.vin[0].scriptSig >> sign.vin[0].scriptWitness.stack;
                if (!reader.empty()) return fail("parent signet solution has trailing bytes");
            } catch (const std::exception&) {
                return fail("parent signet solution is not canonically encoded");
            }
        }
        std::vector<uint256> leaves{coinbase.GetHash()};
        for (size_t i = 1; i < block.vtx.size(); ++i) leaves.push_back(block.vtx[i]->GetHash());
        const auto root = ComputeMerkleRoot(std::move(leaves));
        std::vector<unsigned char> data;
        VectorWriter writer{data,0};
        writer << block.nVersion << block.hashPrevBlock << root << block.nTime;
        spend.vin[0].scriptSig << data;
        sign.vin[0].prevout = Bitcoin::COutPoint(spend.GetHash(),0);
        const Bitcoin::CTransaction immutable{std::move(sign)};
        const drivechain::BitcoinSignetSignatureChecker checker{immutable,0,
            drivechain::BitcoinSignetSignatureChecker::Mode::PARENT};
        ScriptError reason{SCRIPT_ERR_OK};
        if (!VerifyScript(immutable.vin[0].scriptSig,challenge,&immutable.vin[0].scriptWitness,
            SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_NULLDUMMY,checker,&reason))
            return fail(strprintf("parent signet solution failed challenge validation: %s",ScriptErrorString(reason)));
        return true;
    };
    const std::vector<std::vector<unsigned char>> solutions{
        {},{0},{0,0},{0,0,0},{0xfd,0,0},{0,0xfd,0,0},{1,0x51,0},{0,1,0},{0,1,1,0}};
    unsigned accepted{0}, rejected{0};
    for (unsigned shape = 0; shape < 10; ++shape) {
        for (const auto& solution : solutions) {
            for (const CScript& challenge : {CScript{},CScript() << OP_TRUE,CScript() << OP_0,CScript() << OP_VERIFY}) {
                Bitcoin::CBlock block;
                block.nVersion = -1;
                block.nTime = 0xffffffff;
                block.hashPrevBlock = uint256::ONE;
                Bitcoin::CMutableTransaction cb;
                cb.vin.emplace_back(Bitcoin::COutPoint(),CScript() << OP_0,0);
                std::vector<unsigned char> commitment{0xaa,0x21,0xa9,0xed};
                commitment.resize(36,0x42);
                std::vector<unsigned char> section{0xec,0xc7,0xda,0xa2};
                section.insert(section.end(),solution.begin(),solution.end());
                CScript output = CScript() << OP_RETURN << commitment << section;
                if (shape == 3) output = CScript() << OP_RETURN;
                if (shape == 4) output << std::vector<unsigned char>{0xec,0xc7,0xda,0xa2,0,0};
                if (shape == 5) output.push_back(OP_PUSHDATA4); // Truncated later operation.
                cb.vout.emplace_back(0,output);
                if (shape == 6) cb.vout.emplace_back(0,CScript() << OP_RETURN << commitment);
                if (shape == 7) cb.vout.insert(cb.vout.begin(),Bitcoin::CTxOut{0,CScript() << OP_RETURN << commitment});
                if (shape == 2) cb.vin[0].prevout = Bitcoin::COutPoint(uint256::ONE,0);
                if (shape != 1) block.vtx.push_back(Bitcoin::MakeTransactionRef(cb));
                if (shape == 8) {
                    for (unsigned i = 1; i < 258; ++i) {
                        Bitcoin::CMutableTransaction tx;
                        tx.nLockTime = i;
                        block.vtx.push_back(Bitcoin::MakeTransactionRef(tx));
                    }
                }
                const auto genesis = shape == 9 ? block.GetHash() : uint256::ONE;
                std::string expected{"unchanged"}, actual{"unchanged"};
                const bool valid = original(block,challenge,genesis,&expected);
                BOOST_CHECK_EQUAL(CheckBitcoinSignetBlockSolution(block,challenge,genesis,&actual),valid);
                BOOST_CHECK_EQUAL(actual,expected);
                BOOST_CHECK_EQUAL(CheckBitcoinSignetBlockSolution(block,challenge,genesis,nullptr),valid);
                valid ? ++accepted : ++rejected;
            }
        }
    }
    BOOST_CHECK_GT(accepted,0U);
    BOOST_CHECK_GT(rejected,0U);
}

BOOST_AUTO_TEST_CASE(layer_two_parent_signet_real_signature_regression)
{
    // LayerTwo-Labs Signet block 5580 is the immutable Elements parent replay
    // checkpoint. This vector exercises the actual P2WPKH challenge and a real
    // ECDSA Signet solution, not the OP_TRUE parser-only fixture above.
    static constexpr const char* RAW_BLOCK_5580 =
        "00000020027d89a3fdacc10943565cfdbc1d5a32fb6f3d638e3a5dc0c9b7fd4546020000f484c8e55e26cd1eb8d279dfbfd56c44a27995cdb4c057344f6b3e0951fc2b3db5c65a6a3d77031e24a88a0001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0302cc15ffffffff090000000000000000276a25d161736804554faf2df2135a463ad1fefdf6ecbffd27f2a2bfabba909376d9d628724dfe900000000000000000276a25d1617368093f9140f0756e966e730317341a8eb3826d0e9ba86f6e22e5a90f4ba4ad2eed390000000000000000276a25d161736862ecce70a22de077e7192456ebfd30ed617fc14eec92782936e5003307a81b27370000000000000000276a25d16173686323f3c921f22f6e4a7f9f8be1664028f2dd75ba3cc24a3794fe4c65e6222428450000000000000000276a25d16173680263c29a2764d747e4d1e94dc4de89aab1a844dcbcbcb0231715656f154a800ad50000000000000000276a25d16173680d82352000588a4ea8444ca7e585bfef39382703d2247a29389d01f9f9106c60d900000000000000000f6a0dd77d177601ffffffffffffffff00f2052a01000000160014fae83223f01759582ffe70f5f770eb8462f04da20000000000000000986a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c70ecc7daa2000247304402201e4aef7971e3279353d1c948c0af0a9e6a943a8dc8c9dcc106104c8d782bc09602206a4aadfeea8f8edf14dea5e158977ce1badf76b4faf4ab776081fab3f68738f8012103675b73e701c9dab7de809bb0000b4c1205f9a834d669a7f47c107a7d2c199f560120000000000000000000000000000000000000000000000000000000000000000000000000";

    DataStream stream(ParseHex(RAW_BLOCK_5580));
    Bitcoin::CBlock block;
    stream >> TX_WITH_WITNESS(block);
    BOOST_CHECK(stream.empty());
    BOOST_CHECK_EQUAL(
        block.GetHash(),
        uint256S("000002a28e4f1c4599a7878da30ce0197be99ffd1d8e6d20d1a032011448011e"));

    const std::vector<unsigned char> challenge_bytes =
        ParseHex("00148835832e28c816b7acd8fdb19772ab2199603a56");
    const CScript challenge(challenge_bytes.begin(), challenge_bytes.end());
    const uint256 parent_genesis = uint256S(
        "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6");
    std::string error;
    BOOST_CHECK(CheckBitcoinSignetBlockSolution(block, challenge, parent_genesis, &error));

    // nTime is covered by the Signet signature. The authentic solution must
    // fail if any signed header field is changed.
    Bitcoin::CBlock tampered = block;
    ++tampered.nTime;
    BOOST_CHECK(!CheckBitcoinSignetBlockSolution(tampered, challenge, parent_genesis, &error));
}

BOOST_AUTO_TEST_CASE(existing_signet_is_not_elements_drivechain)
{
    ArgsManager signet_argsman;
    const auto signet_params = CreateChainParams(signet_argsman, CBaseChainParams::SIGNET);
    const auto& consensus = signet_params->GetConsensus();

    // These values are part of the existing Signet genesis identity. Elements
    // Drivechain uses a newly generated Elements-mode network with Simplicity active;
    // silently changing either setting here would reinterpret an existing
    // chain under different consensus rules.
    BOOST_CHECK(!consensus.elements_mode);
    BOOST_CHECK_EQUAL(
        consensus.vDeployments[Consensus::DEPLOYMENT_SIMPLICITY].nStartTime,
        Consensus::BIP9Deployment::NEVER_ACTIVE);
}

BOOST_AUTO_TEST_CASE(parent_warmup_without_slot_clears_error_and_skips_rpc)
{
    BOOST_REQUIRE(!Params().GetConsensus().drivechain_slot.has_value());
    std::string error{"previous failure"};
    BOOST_CHECK(WarmDrivechainParentState(&error));
    BOOST_CHECK(error.empty());
    BOOST_CHECK(WarmDrivechainParentState(nullptr));
}

BOOST_AUTO_TEST_CASE(elements_is_default_and_prelaunch_usdd_alias_is_rejected)
{
    BOOST_CHECK_EQUAL(CBaseChainParams::DEFAULT, "elements");
    BOOST_CHECK_THROW(CreateBaseChainParams("usdd"), std::runtime_error);
    ArgsManager args;
    BOOST_CHECK_THROW(CreateChainParams(args, "usdd"), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(installed_programs_accept_only_elements_chain_selector)
{
    ArgsManager canonical;
    BOOST_CHECK_NO_THROW(EnsureElementsProductionChain(canonical));

    for (const char* const legacy : {"main", "test", "signet", "regtest", "liquidv1", "liquidtestnet", "usdd", "custom"}) {
        ArgsManager args;
        args.ForceSetArg("-chain", legacy);
        BOOST_CHECK_THROW(EnsureElementsProductionChain(args), std::runtime_error);
    }
}

BOOST_AUTO_TEST_CASE(network_selection_preserves_diagnostics_and_precedence)
{
    const auto check = [](auto action, const char* message) {
        BOOST_CHECK_EXCEPTION(action(), std::runtime_error,
            [&](const std::runtime_error& error) { return std::string(error.what()) == message; });
    };
    ArgsManager args;
    const char* legacy = "The pre-launch 'usdd' chain identity is unsupported; use -chain=elements";
    check([&] { CreateBaseChainParams("usdd"); }, legacy);
    check([&] { CreateChainParams(args, "usdd"); }, legacy);
    args.ForceSetArg("-chain", "signet");
    check([&] { EnsureElementsProductionChain(args); },
        "This program only supports the canonical -chain=elements production network");
    args.ForceSetArg("-con_elementsmode", "1");
    args.ForceSetArg("-vbparams", "simplicity:bad");
    check([&] { CreateChainParams(args, "regtest"); },
        "-con_elementsmode is not supported with -chain=regtest; use -chain=elementsregtest for Elements/ECX testing");
    args.ForceSetArg("-con_elementsmode", "0");
    check([&] { CreateChainParams(args, "regtest"); },
        "the Simplicity deployment is not supported with -chain=regtest; use an Elements-mode chain");
    args.ForceSetArg("-vbparams", "dynafed");
    check([&] { CreateChainParams(args, "regtest"); },
        "the dynafed deployment is not supported with -chain=regtest; use an Elements-mode chain");
}

BOOST_AUTO_TEST_CASE(elements_key_namespaces_match_documented_derivation_domains)
{
    const auto domain_hash = [](const char* domain) {
        std::array<unsigned char, CSHA256::OUTPUT_SIZE> result{};
        CSHA256()
            .Write(reinterpret_cast<const unsigned char*>(domain), std::strlen(domain))
            .Finalize(result.data());
        return result;
    };
    const auto wif = domain_hash(ElementsDrivechainIdentity::WIF_PREFIX_DOMAIN);
    const auto extpub = domain_hash(ElementsDrivechainIdentity::EXT_PUBLIC_KEY_PREFIX_DOMAIN);
    const auto extprv = domain_hash(ElementsDrivechainIdentity::EXT_SECRET_KEY_PREFIX_DOMAIN);
    BOOST_CHECK_EQUAL(wif[0], ElementsDrivechainIdentity::SECRET_KEY_PREFIX);
    BOOST_CHECK(std::equal(
        ElementsDrivechainIdentity::EXT_PUBLIC_KEY_PREFIX.begin(),
        ElementsDrivechainIdentity::EXT_PUBLIC_KEY_PREFIX.end(), extpub.begin()));
    BOOST_CHECK(std::equal(
        ElementsDrivechainIdentity::EXT_SECRET_KEY_PREFIX.begin(),
        ElementsDrivechainIdentity::EXT_SECRET_KEY_PREFIX.end(), extprv.begin()));
}

BOOST_AUTO_TEST_CASE(elements_chain_has_frozen_drivechain_identity)
{
    ArgsManager args;
    // These custom-chain switches must not alter the dedicated Elements network.
    args.ForceSetArg("-con_elementsmode", "0");
    args.ForceSetArg("-con_has_parent_chain", "0");
    args.ForceSetArg("-parentgenesisblockhash", uint256::ONE.GetHex());

    const auto params = CreateChainParams(args, CBaseChainParams::ELEMENTS);
    const auto& consensus = params->GetConsensus();
    const auto base_params = CreateBaseChainParams(CBaseChainParams::ELEMENTS);

    BOOST_CHECK_EQUAL(params->NetworkIDString(), "elements");
    BOOST_CHECK_EQUAL(base_params->DataDir(), "elements-native-v1");
    BOOST_CHECK_EQUAL(base_params->RPCPort(), 7071);
    BOOST_CHECK_EQUAL(base_params->MainchainRPCPort(), 28532);
    BOOST_CHECK_EQUAL(base_params->OnionServiceTargetPort(), 37072);
    BOOST_CHECK_EQUAL(params->GetDefaultPort(), 7072);

    BOOST_CHECK(consensus.elements_mode);
    BOOST_CHECK(consensus.has_parent_chain);
    BOOST_REQUIRE(consensus.drivechain_slot.has_value());
    BOOST_CHECK_EQUAL(*consensus.drivechain_slot, 24);
    BOOST_CHECK_EQUAL(
        params->ParentGenesisBlockHash(),
        uint256S("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"));
    BOOST_CHECK_EQUAL(
        HexStr(consensus.parent_signet_challenge),
        "");
    BOOST_CHECK_EQUAL(
        consensus.parentChainPowLimit,
        uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
    BOOST_CHECK(!consensus.signet_blocks);
    BOOST_CHECK(consensus.signblockscript == CScript() << OP_TRUE);
    BOOST_CHECK_EQUAL(
        params->HashGenesisBlock(),
        uint256S("fe05f7c76cfb50ef4f5594c761df25581e95a9946a64bc9d8f567235ffa485c9"));
    BOOST_CHECK_EQUAL(
        params->GenesisBlock().hashMerkleRoot,
        uint256S("d5a55d8261a4baaceca67e2c6b21bdeb4f3d56d579d05c188516be02b96b90d6"));
    BOOST_CHECK_EQUAL(
        consensus.pegged_asset.GetHex(),
        "2e69819685c22252a706f69ce67ab9ab36a633b91e61f6ee69216d6e1c7e90d3");
    BOOST_CHECK_EQUAL(params->GenesisBlock().nTime, 1784334600U);
    BOOST_CHECK(params->HashGenesisBlock() != params->ParentGenesisBlockHash());
    BOOST_CHECK(consensus.subsidy_asset == consensus.pegged_asset);

    BOOST_CHECK_EQUAL(
        consensus.drivechain_protocol_manifest_hash,
        uint256S("94831880cee118fe5266ebf3945528b370b1a0f668fb76cf2c3ca756b8d1068c"));
    BOOST_CHECK(!ElementsDrivechainIdentity::BETANET_EXISTING_ELEMENTS_TEST_PROFILE);
    BOOST_REQUIRE(consensus.drivechain_proposal_hash.has_value());
    BOOST_CHECK_EQUAL(
        *consensus.drivechain_proposal_hash,
        uint256S("a9980eaa8bb6893d4baea100f484000b4f72e4640fc0d9f3ebf8a2f29ae63460"));
    BOOST_REQUIRE(consensus.drivechain_parent_state_active_proposal_hash.has_value());
    BOOST_CHECK_EQUAL(
        *consensus.drivechain_parent_state_active_proposal_hash,
        uint256S("0000000000000000000000000000000000000000000000000000000000000000"));
    BOOST_CHECK_EQUAL(consensus.drivechain_parent_state_proposal_height, 0U);
    BOOST_CHECK_EQUAL(
        consensus.drivechain_parent_state_proposal_block_hash,
        uint256S("0000000000000000000000000000000000000000000000000000000000000000"));
    BOOST_CHECK_EQUAL(consensus.drivechain_parent_state_activation_height, 0U);
    BOOST_CHECK_EQUAL(
        consensus.drivechain_parent_state_activation_block_hash,
        uint256S("0000000000000000000000000000000000000000000000000000000000000000"));
    BOOST_CHECK_EQUAL(consensus.drivechain_parent_state_height, 967679U);
    BOOST_CHECK_EQUAL(
        consensus.drivechain_parent_state_hash,
        uint256S("00000000000000000001b58cb69869f6067f0ecb3f2fe0f2263e62ba1ccb0c41"));
    BOOST_CHECK_EQUAL(
        consensus.drivechain_parent_state_chainwork,
        uint256S("000000000000000000000000000000000000000148a384d49682843d3c74a5a0"));
    BOOST_CHECK_EQUAL(
        consensus.drivechain_parent_state_ctip_txid,
        uint256S("0000000000000000000000000000000000000000000000000000000000000000"));
    BOOST_CHECK_EQUAL(consensus.drivechain_parent_state_ctip_vout, 4294967295U);
    BOOST_CHECK_EQUAL(consensus.drivechain_parent_state_ctip_value, 0);
    BOOST_CHECK_EQUAL(consensus.drivechain_unused_slot_proposal_max_age, 2016U);
    BOOST_CHECK_EQUAL(consensus.drivechain_unused_slot_activation_threshold, 1008U);
    BOOST_CHECK_EQUAL(consensus.drivechain_used_slot_proposal_max_age, 26300U);
    BOOST_CHECK_EQUAL(consensus.drivechain_used_slot_activation_threshold, 13150U);
    BOOST_CHECK_EQUAL(consensus.drivechain_withdrawal_bundle_max_age, 26300U);
    BOOST_CHECK_EQUAL(consensus.drivechain_withdrawal_bundle_inclusion_threshold, 13150U);
    BOOST_CHECK_EQUAL(consensus.drivechain_parent_state_replay_version, 5U);
    BOOST_CHECK_EQUAL(consensus.drivechain_annex_feature_version, 2U);
    BOOST_CHECK(consensus.drivechain_m6_withdrawal_validation);

    BOOST_CHECK_EQUAL(
        consensus.vDeployments[Consensus::DEPLOYMENT_SIMPLICITY].nStartTime,
        Consensus::BIP9Deployment::ALWAYS_ACTIVE);
    BOOST_CHECK_EQUAL(params->Bech32HRP(), "elements");
    BOOST_CHECK_EQUAL(params->Blech32HRP(), "elementsl");
    BOOST_CHECK_EQUAL(params->ParentBech32HRP(), "bc");
    BOOST_CHECK_EQUAL(HexStr(params->MessageStart()), "97b20d51");
    BOOST_CHECK_EQUAL(MAX_BLOCK_WEIGHT, 4'000'000U);
    BOOST_CHECK_EQUAL(MAX_BLOCK_SERIALIZED_SIZE, 4'000'000U);
    BOOST_CHECK_EQUAL(HexStr(params->Base58Prefix(CChainParams::SECRET_KEY)), "37");
    BOOST_CHECK_EQUAL(HexStr(params->Base58Prefix(CChainParams::EXT_PUBLIC_KEY)), "18717df5");
    BOOST_CHECK_EQUAL(HexStr(params->Base58Prefix(CChainParams::EXT_SECRET_KEY)), "b263bd77");

    std::string identity_error;
    BOOST_CHECK_MESSAGE(
        IsCanonicalElementsProductionIdentity(*params, *base_params, &identity_error),
        identity_error);
}

// Reconstruct only the historical fields used by the Alpha depth predicate.
// This is not a canonical current-network identity or a runnable Alpha chain.
class HistoricalAlphaDepthParams final : public CChainParams {
public:
    HistoricalAlphaDepthParams() : CChainParams(*CreateChainParams(ArgsManager{}, CBaseChainParams::ELEMENTS))
    {
        consensus.drivechain_slot = 24;
        consensus.hashGenesisBlock = uint256S("672af009bd90bfc6527a5a9dda4c83aba0048c15cff3697d07e89a7f96fa5bcd");
        consensus.drivechain_protocol_manifest_hash = uint256S("fbd55822590e0e7a3389c2316171068b2fe7ddbb35c52aa010159bfbd92d09e6");
        consensus.pegin_min_depth = 100;
    }
};

BOOST_AUTO_TEST_CASE(betanet_pegin_requires_six_confirmations_without_changing_identity)
{
    ArgsManager args;
    // An ordinary configuration override cannot reduce the frozen depth.
    args.ForceSetArg("-peginconfirmationdepth", "0");
    const auto beta = CreateChainParams(args, CBaseChainParams::ELEMENTS);
    BOOST_CHECK(!HasAlphaPeginOneConfirmationUpgrade(*beta));
    BOOST_CHECK_EQUAL(beta->GetConsensus().pegin_min_depth, 100U);
    BOOST_CHECK_EQUAL(beta->GetConsensus().hashGenesisBlock.GetHex(),
        "fe05f7c76cfb50ef4f5594c761df25581e95a9946a64bc9d8f567235ffa485c9");
    for (const int height : {-1, 0, 63, 64, 65, std::numeric_limits<int>::max()}) {
        const auto depth = GetDrivechainPeginConfirmationDepth(*beta, height);
        BOOST_CHECK_EQUAL(depth, 6U);
        for (uint32_t parent = 1000; parent < 1005; ++parent) {
            BOOST_CHECK(!HasRequiredDrivechainDepositDepth(1000, parent, depth));
        }
        BOOST_CHECK(HasRequiredDrivechainDepositDepth(1000, 1005, depth));
        BOOST_CHECK(HasRequiredDrivechainDepositDepth(1000, 1006, depth));
        BOOST_CHECK(!HasRequiredDrivechainDepositDepth(1000, 999, depth));
    }
}

BOOST_AUTO_TEST_CASE(alpha_pegin_depth_upgrade_is_identity_and_height_scoped)
{
    const auto alpha = std::make_unique<HistoricalAlphaDepthParams>();
    const auto& consensus = alpha->GetConsensus();
    BOOST_CHECK(HasAlphaPeginOneConfirmationUpgrade(*alpha));
    BOOST_CHECK_EQUAL(ALPHA_PEGIN_ONE_CONFIRMATION_HEIGHT, 64);
    BOOST_CHECK_EQUAL(GetDrivechainPeginConfirmationDepth(*alpha), 100U);
    BOOST_CHECK_EQUAL(GetDrivechainPeginConfirmationDepth(*alpha, -1), 100U);
    BOOST_CHECK_EQUAL(GetDrivechainPeginConfirmationDepth(*alpha, 0), 100U);
    BOOST_CHECK_EQUAL(GetDrivechainPeginConfirmationDepth(*alpha, 63), 100U);
    BOOST_CHECK_EQUAL(GetDrivechainPeginConfirmationDepth(*alpha, 64), 1U);
    BOOST_CHECK_EQUAL(GetDrivechainPeginConfirmationDepth(*alpha, 65), 1U);
    BOOST_CHECK_EQUAL(GetDrivechainPeginConfirmationDepth(*alpha, std::numeric_limits<int>::max()), 1U);
    BOOST_CHECK_EQUAL(consensus.pegin_min_depth, 100U);
    BOOST_CHECK_EQUAL(consensus.hashGenesisBlock.GetHex(), "672af009bd90bfc6527a5a9dda4c83aba0048c15cff3697d07e89a7f96fa5bcd");
    BOOST_CHECK_EQUAL(consensus.drivechain_protocol_manifest_hash.GetHex(), "fbd55822590e0e7a3389c2316171068b2fe7ddbb35c52aa010159bfbd92d09e6");

    class MutatedIdentity final : public CChainParams {
    public:
        explicit MutatedIdentity(const CChainParams& source) : CChainParams(source) {}
        void WrongGenesis() { consensus.hashGenesisBlock = uint256::ONE; }
        void WrongSlot() { consensus.drivechain_slot = 25; }
        void WrongNetwork() { m_chain_type.chain_name = "elementsregtest"; }
        void WrongManifest() { consensus.drivechain_protocol_manifest_hash = uint256::ONE; }
        void WrongParent() { parentGenesisBlockHash = uint256::ONE; }
        void WrongMode() { consensus.elements_mode = false; }
        void NoParentChain() { consensus.has_parent_chain = false; }
        void NoSlot() { consensus.drivechain_slot.reset(); }
        void SetDepth(uint32_t depth) { consensus.pegin_min_depth = depth; }
    };
    for (const auto mutate : {&MutatedIdentity::WrongGenesis, &MutatedIdentity::WrongSlot,
                             &MutatedIdentity::WrongNetwork, &MutatedIdentity::WrongManifest,
                             &MutatedIdentity::WrongParent, &MutatedIdentity::WrongMode,
                             &MutatedIdentity::NoParentChain, &MutatedIdentity::NoSlot}) {
        MutatedIdentity other{*alpha};
        (other.*mutate)();
        BOOST_CHECK(!HasAlphaPeginOneConfirmationUpgrade(other));
        BOOST_CHECK_EQUAL(GetDrivechainPeginConfirmationDepth(other, 64), 100U);
        MutatedIdentity beta_other{*CreateChainParams(ArgsManager{}, CBaseChainParams::ELEMENTS)};
        (beta_other.*mutate)();
        BOOST_CHECK_EQUAL(GetDrivechainPeginConfirmationDepth(beta_other, 64), 100U);
    }
    const auto beta = CreateChainParams(ArgsManager{}, CBaseChainParams::ELEMENTS);
    for (bool historical : {false, true}) {
        MutatedIdentity other{historical ? *alpha : *beta};
        for (uint32_t depth : {0U, 1U, 6U, 99U, 101U, UINT32_MAX}) {
            other.SetDepth(depth);
            BOOST_CHECK(!HasAlphaPeginOneConfirmationUpgrade(other));
            for (int height : {-1, 63, 64, std::numeric_limits<int>::max()})
                BOOST_CHECK_EQUAL(GetDrivechainPeginConfirmationDepth(other, height), depth);
        }
    }
    const auto private_chain = CreateChainParams(ArgsManager{}, "elementsregtest");
    BOOST_CHECK(!HasAlphaPeginOneConfirmationUpgrade(*private_chain));
    BOOST_CHECK_EQUAL(GetDrivechainPeginConfirmationDepth(*private_chain, 64), private_chain->GetConsensus().pegin_min_depth);
    const auto signet = CreateChainParams(ArgsManager{}, CBaseChainParams::SIGNET);
    BOOST_CHECK(!HasAlphaPeginOneConfirmationUpgrade(*signet));
    BOOST_CHECK_EQUAL(GetDrivechainPeginConfirmationDepth(*signet, 64), signet->GetConsensus().pegin_min_depth);
}

BOOST_AUTO_TEST_CASE(pegin_confirmation_snapshot_exhausts_identity_mutations)
{
    class Identity final : public CChainParams {
    public:
        Identity(const CChainParams& source, unsigned mask) : CChainParams(source)
        {
            if (mask & 1) m_chain_type.chain_name = std::string(253, 'x');
            if (mask & 2) consensus.elements_mode = false;
            if (mask & 4) consensus.has_parent_chain = false;
            if (mask & 8) consensus.drivechain_slot.reset();
            else if (mask & 16) consensus.drivechain_slot = 25;
            if (mask & 32) consensus.hashGenesisBlock = uint256::ONE;
            if (mask & 64) parentGenesisBlockHash = uint256::ONE;
            if (mask & 128) consensus.drivechain_protocol_manifest_hash = uint256::ONE;
            if (mask & 256) consensus.pegin_min_depth = (mask & 1) ? UINT32_MAX : 0;
        }
    };
    const auto beta = CreateChainParams(ArgsManager{}, CBaseChainParams::ELEMENTS);
    const HistoricalAlphaDepthParams alpha;
    for (bool historical : {false,true}) for (unsigned mask = 0; mask < 512; ++mask) {
        BOOST_TEST_CONTEXT("historical=" << historical << ", mask=" << mask) {
            const Identity params{historical ? alpha : *beta, mask};
            BOOST_CHECK_EQUAL(HasAlphaPeginOneConfirmationUpgrade(params), historical && mask == 0);
            for (int height : {std::numeric_limits<int>::min(),-1,0,63,64,65,std::numeric_limits<int>::max()}) {
                const auto expected = mask ? params.GetConsensus().pegin_min_depth :
                    !historical ? 6U : height >= 64 ? 1U : 100U;
                BOOST_CHECK_EQUAL(GetDrivechainPeginConfirmationDepth(params,height),expected);
                const auto& network = params.NetworkIDString();
                BOOST_CHECK_EQUAL(PeginConfirmationSnapshot(params,height).size(),
                    8 + (network.size() < 253 ? 1 : 3) + network.size() + 4 + 96 + 4);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(alpha_pegin_depth_counts_authenticated_parent_inclusion)
{
    const auto alpha = std::make_unique<HistoricalAlphaDepthParams>();
    const uint32_t before = GetDrivechainPeginConfirmationDepth(*alpha, 63);
    const uint32_t after = GetDrivechainPeginConfirmationDepth(*alpha, 64);
    BOOST_CHECK(!HasRequiredDrivechainDepositDepth(1000, 1000, before));
    BOOST_CHECK(!HasRequiredDrivechainDepositDepth(1000, 1098, before));
    BOOST_CHECK(HasRequiredDrivechainDepositDepth(1000, 1099, before));
    BOOST_CHECK(HasRequiredDrivechainDepositDepth(1000, 1000, after));
    BOOST_CHECK(HasRequiredDrivechainDepositDepth(1000, 1001, after));
    BOOST_CHECK(!HasRequiredDrivechainDepositDepth(1000, 999, after));
    BOOST_CHECK(!HasRequiredDrivechainDepositDepth(1000, 1000, 0));
    BOOST_CHECK(!HasRequiredDrivechainDepositDepth(std::numeric_limits<uint32_t>::max(), 0, after));
    BOOST_CHECK(HasRequiredDrivechainDepositDepth(std::numeric_limits<uint32_t>::max(), std::numeric_limits<uint32_t>::max(), after));
    BOOST_CHECK(!HasRequiredDrivechainDepositDepth(1, std::numeric_limits<uint32_t>::max() - 1, std::numeric_limits<uint32_t>::max()));
    BOOST_CHECK(HasRequiredDrivechainDepositDepth(1, std::numeric_limits<uint32_t>::max(), std::numeric_limits<uint32_t>::max()));
    // The separate legacy federated coinbase-maturity safeguard is unchanged.
    BOOST_CHECK_EQUAL(COINBASE_MATURITY, 100);
}

BOOST_AUTO_TEST_CASE(elements_height_one_uses_simplicity_consensus_flags)
{
    ArgsManager args;
    const auto params = CreateChainParams(args, CBaseChainParams::ELEMENTS);

    CBlockIndex genesis_index{params->GenesisBlock()};
    genesis_index.nHeight = 0;
    const uint256 first_block_hash{};    CBlockIndex first_block_index;    first_block_index.phashBlock = &first_block_hash;
    first_block_index.pprev = &genesis_index;
    first_block_index.nHeight = 1;

    const unsigned int flags = GetBlockScriptFlagsForTesting(
        &first_block_index, params->GetConsensus());
    BOOST_CHECK(flags & SCRIPT_VERIFY_TAPROOT);
    BOOST_CHECK(flags & SCRIPT_VERIFY_SIMPLICITY);
    BOOST_CHECK(!(flags & SCRIPT_VERIFY_CHECKTEMPLATEVERIFY));
    const unsigned int elements_flags = SCRIPT_SIGHASH_RANGEPROOF | SCRIPT_VERIFY_SIMPLICITY;
    const unsigned int fork_flags = elements_flags;
    for (bool elements : {false,true}) {
        auto consensus = params->GetConsensus();
        consensus.elements_mode = elements;
        const unsigned int expected = (flags & ~fork_flags) |
            (elements ? flags & elements_flags : 0U);
        BOOST_CHECK_EQUAL(GetBlockScriptFlagsForTesting(&first_block_index,consensus),expected);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_mempool_parent_mtp_requires_sane_active_anchor)
{
    LOCK(cs_main);
    ArgsManager args;
    const auto elements = CreateChainParams(args, CBaseChainParams::ELEMENTS);
    const auto ordinary = CreateChainParams(args, CBaseChainParams::MAIN);

    BOOST_CHECK(!GetDrivechainMempoolParentMtp(
        nullptr, elements->GetConsensus()).has_value());

    CBlockIndex genesis{elements->GenesisBlock()};
    genesis.nHeight = 0;
    genesis.m_chain_tx_count = 1;
    BOOST_CHECK(!GetDrivechainMempoolParentMtp(
        &genesis, elements->GetConsensus()).has_value());

    CBlockIndex tip;
    tip.pprev = &genesis;
    tip.nHeight = 1;
    tip.m_chain_tx_count = 1;
    BOOST_CHECK(!GetDrivechainMempoolParentMtp(
        &tip, elements->GetConsensus()).has_value());

    DrivechainAnchor anchor;
    anchor.parent_block_hash = uint256S("01");
    anchor.bmm_block_hash = uint256S("02");
    anchor.parent_chainwork = uint256S("03");
    anchor.bmm_chainwork = uint256S("04");
    anchor.parent_height = 100;
    anchor.bmm_height = 101;
    anchor.parent_median_time_past = 123456;
    BOOST_REQUIRE(anchor.IsSane());
    tip.m_drivechain_anchor = anchor;

    const auto mtp = GetDrivechainMempoolParentMtp(
        &tip, elements->GetConsensus());
    BOOST_REQUIRE(mtp.has_value());
    BOOST_CHECK_EQUAL(*mtp, anchor.parent_median_time_past);
    BOOST_CHECK(!GetDrivechainMempoolParentMtp(
        &tip, ordinary->GetConsensus()).has_value());

    tip.m_chain_tx_count = 0;
    BOOST_CHECK(!GetDrivechainMempoolParentMtp(
        &tip, elements->GetConsensus()).has_value());
    tip.m_chain_tx_count = 1;
    tip.m_drivechain_anchor->bmm_height++;
    BOOST_CHECK(!tip.m_drivechain_anchor->IsSane());
    BOOST_CHECK(!GetDrivechainMempoolParentMtp(
        &tip, elements->GetConsensus()).has_value());
}

BOOST_AUTO_TEST_CASE(drivechain_authenticated_parent_context_matrix)
{
    LOCK(cs_main);
    ArgsManager args;
    const auto elements = CreateChainParams(args, CBaseChainParams::ELEMENTS);
    const auto ordinary = CreateChainParams(args, CBaseChainParams::MAIN);
    DrivechainAnchor anchor;
    anchor.parent_block_hash=uint256S("01");
    anchor.bmm_block_hash=uint256S("02");
    anchor.parent_chainwork=uint256S("03");
    anchor.bmm_chainwork=uint256S("04");
    anchor.bmm_height=1;
    for (uint64_t mtp : {uint64_t{0},uint64_t{UINT32_MAX}}) for (unsigned mask=0; mask<256; ++mask) {
        anchor.parent_median_time_past=mtp;
        anchor.version=(mask&64) ? 0 : 1;
        CBlockIndex tip;
        tip.nHeight=(mask&2) ? 0 : 1;
        tip.m_chain_tx_count=(mask&4) ? 0 : 1;
        tip.nStatus=((mask&8) ? BLOCK_FAILED_VALID : 0) | ((mask&16) ? BLOCK_FAILED_CHILD : 0);
        if (!(mask&32)) tip.m_drivechain_anchor=anchor;
        const auto* index=(mask&1) ? nullptr : &tip;
        const auto& consensus=(mask&128) ? ordinary->GetConsensus() : elements->GetConsensus();
        const bool header=(mask&128) || (!(mask&29) && ((mask&2) || !(mask&96)));
        BOOST_CHECK_EQUAL(IsDrivechainHeaderAuthenticated(index,consensus),header);
        const auto parent_mtp=GetDrivechainMempoolParentMtp(index,consensus);
        const auto checkpoint=GetPriorActiveBmmParentCheckpoint(index,consensus);
        BOOST_CHECK_EQUAL(parent_mtp.has_value(),mask==0);
        BOOST_CHECK_EQUAL(checkpoint.has_value(),mask==0);
        if (parent_mtp) BOOST_CHECK_EQUAL(*parent_mtp,mtp);
        if (checkpoint) BOOST_CHECK(*checkpoint==*EncodePriorActiveBmmParentCheckpoint(anchor));
    }
}

BOOST_AUTO_TEST_CASE(v11_prior_active_parent_checkpoint_codec_is_exact_and_fail_closed)
{
    LOCK(cs_main);
    DrivechainAnchor anchor;
    anchor.parent_block_hash = uint256S(
        "0123456789abcdef1032547698badcfeffeeddccbbaa99887766554433221100");
    anchor.bmm_block_hash = uint256S("02");
    anchor.parent_chainwork = uint256S(
        "102030405060708090a0b0c0d0e0f001112233445566778899aabbccddeeff00");
    anchor.bmm_chainwork = uint256S(
        "102030405060708090a0b0c0d0e0f001112233445566778899aabbccddeeff01");
    anchor.parent_height = 0x01020304;
    anchor.bmm_height = 0x01020305;
    anchor.parent_median_time_past = 0x01020304ULL;
    BOOST_REQUIRE(anchor.IsSane());

    const auto encoded = EncodePriorActiveBmmParentCheckpoint(anchor);
    BOOST_REQUIRE(encoded.has_value());
    const auto expected = ParseHex(
        "0123456789abcdef1032547698badcfeffeeddccbbaa99887766554433221100"
        "0000000001020304"
        "0000000001020304"
        "102030405060708090a0b0c0d0e0f001112233445566778899aabbccddeeff00");
    BOOST_REQUIRE_EQUAL(expected.size(), encoded->size());
    BOOST_CHECK_EQUAL_COLLECTIONS(encoded->begin(), encoded->end(),
                                  expected.begin(), expected.end());

    ArgsManager args;
    const auto elements = CreateChainParams(args, CBaseChainParams::ELEMENTS);
    const auto ordinary = CreateChainParams(args, CBaseChainParams::MAIN);
    CBlockIndex genesis{elements->GenesisBlock()};
    genesis.nHeight = 0;
    genesis.m_chain_tx_count = 1;
    BOOST_CHECK(!GetPriorActiveBmmParentCheckpoint(
        &genesis, elements->GetConsensus()).has_value());

    CBlockIndex authenticated_tip;
    authenticated_tip.pprev = &genesis;
    authenticated_tip.nHeight = 1;
    authenticated_tip.m_chain_tx_count = 1;
    authenticated_tip.m_drivechain_anchor = anchor;
    const auto authenticated = GetPriorActiveBmmParentCheckpoint(
        &authenticated_tip, elements->GetConsensus());
    BOOST_REQUIRE(authenticated.has_value());
    BOOST_CHECK_EQUAL_COLLECTIONS(authenticated->begin(), authenticated->end(),
                                  expected.begin(), expected.end());
    BOOST_CHECK(!GetPriorActiveBmmParentCheckpoint(
        &authenticated_tip, ordinary->GetConsensus()).has_value());

    authenticated_tip.m_chain_tx_count = 0;
    BOOST_CHECK(!GetPriorActiveBmmParentCheckpoint(
        &authenticated_tip, elements->GetConsensus()).has_value());
    authenticated_tip.m_chain_tx_count = 1;
    authenticated_tip.nStatus |= BLOCK_FAILED_VALID;
    BOOST_CHECK(!GetPriorActiveBmmParentCheckpoint(
        &authenticated_tip, elements->GetConsensus()).has_value());

    anchor.parent_block_hash.SetNull();
    BOOST_CHECK(!EncodePriorActiveBmmParentCheckpoint(anchor).has_value());
}

BOOST_AUTO_TEST_CASE(v11_atomic_parent_script_cache_suffix_is_exact_and_versioned)
{
    const auto endpoint_bytes = ParseHex(
        "000002574f02cf5ee7d7cb5272f48cdefc2484e8f8b73de99564bfe80b8c0712"
        "0000000000000001"
        "0000000064d54da7"
        "000000000000000000000000000000000000000000000000000000000093a828");
    BOOST_REQUIRE_EQUAL(endpoint_bytes.size(), PriorActiveBmmParentCheckpoint{}.size());
    PriorActiveBmmParentCheckpoint endpoint{};
    std::copy(endpoint_bytes.begin(), endpoint_bytes.end(), endpoint.begin());

    const auto suffix = EncodeV11AtomicBmmScriptCacheSuffix(endpoint);
    BOOST_REQUIRE_EQUAL(suffix.size(), 115U);
    BOOST_CHECK_EQUAL(HexStr(std::vector<unsigned char>(suffix.begin(), suffix.begin() + 32)),
                      "9fa5b41185f7391ffda63b6bb14ba79b138f46396bca42b75efde5dc5503fe26");
    BOOST_CHECK_EQUAL(suffix[32], 0U);
    BOOST_CHECK_EQUAL(suffix[33], 1U);
    BOOST_CHECK_EQUAL(suffix[34], 1U);
    BOOST_CHECK_EQUAL_COLLECTIONS(suffix.begin() + 35, suffix.end(),
                                  endpoint.begin(), endpoint.end());

    std::array<unsigned char, 32> suffix_hash{};
    CSHA256().Write(suffix.data(), suffix.size()).Finalize(suffix_hash.data());
    BOOST_CHECK_EQUAL(HexStr(suffix_hash),
                      "67a4ed04fc537cacdd079efb6d037f764ebc6e4e12fbf7c61f2c4c5aa6af3da0");

    std::array<unsigned char, 124> complete{};
    const auto legacy_prefix = ParseHex("010000000064d54da7");
    std::copy(legacy_prefix.begin(), legacy_prefix.end(), complete.begin());
    std::copy(suffix.begin(), suffix.end(), complete.begin() + 9);
    std::array<unsigned char, 32> complete_hash{};
    CSHA256().Write(complete.data(), complete.size()).Finalize(complete_hash.data());
    BOOST_CHECK_EQUAL(HexStr(complete_hash),
                      "56a6a70fe130fb1875ea9e12bd226780abf3f791366b2433ac727892c59fefcb");

    const auto absent = EncodeV11AtomicBmmScriptCacheSuffix(std::nullopt);
    BOOST_CHECK_EQUAL(absent[34], 0U);
    BOOST_CHECK(std::all_of(absent.begin() + 35, absent.end(),
                            [](unsigned char byte) { return byte == 0; }));
    std::array<unsigned char, 32> absent_hash{};
    CSHA256().Write(absent.data(), absent.size()).Finalize(absent_hash.data());
    BOOST_CHECK_EQUAL(HexStr(absent_hash),
                      "fd83f267b6d1cce359045086b514accdbcf03f6c2e00645fa4f5fb93fd9f3e91");
}

BOOST_AUTO_TEST_CASE(inactive_checktemplateverify_uses_standard_nop_policy)
{
    BOOST_CHECK(STANDARD_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS);
    BOOST_CHECK(!(STANDARD_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_CHECKTEMPLATEVERIFY));
    BOOST_CHECK(!(STANDARD_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_DISCOURAGE_CHECKTEMPLATEVERIFY));
}

BOOST_AUTO_TEST_CASE(drivechain_slot_is_not_enabled_on_other_builtin_networks)
{
    ArgsManager args;
    const std::vector<std::string> ordinary_networks{
        CBaseChainParams::MAIN,
        CBaseChainParams::TESTNET,
        CBaseChainParams::SIGNET,
        CBaseChainParams::REGTEST,
        CBaseChainParams::LIQUID1,
        CBaseChainParams::LIQUID1TEST,
        CBaseChainParams::LIQUIDTESTNET,
    };

    for (const auto& network : ordinary_networks) {
        const auto params = CreateChainParams(args, network);
        BOOST_CHECK_MESSAGE(!params->GetConsensus().drivechain_slot.has_value(), network);

        CBlockIndex genesis_index{params->GenesisBlock()};
        genesis_index.nHeight = 0;
        const uint256 first_block_hash{};        CBlockIndex first_block_index;        first_block_index.phashBlock = &first_block_hash;
        first_block_index.pprev = &genesis_index;
        first_block_index.nHeight = 1;
        const unsigned int flags = GetBlockScriptFlagsForTesting(
            &first_block_index, params->GetConsensus());
        BOOST_CHECK_MESSAGE(!(flags & SCRIPT_VERIFY_CHECKTEMPLATEVERIFY), network);
    }
}

BOOST_AUTO_TEST_CASE(anchor_ordering_preserves_height_hash_sort)
{
    const std::array<int, 5> heights{std::numeric_limits<int>::min(), -1, 0, 1, std::numeric_limits<int>::max()};
    const std::array<uint256, 3> hashes{uint256{}, uint256::ONE, uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")};
    std::array<CBlockIndex, 15> indexes;
    for (size_t i = 0; i < indexes.size(); ++i) {
        indexes[i].nHeight = heights[i / hashes.size()];
        indexes[i].phashBlock = &hashes[i % hashes.size()];
    }
    const auto compare = [&](const CBlockIndex* a, const CBlockIndex* b, bool migrated,
                             unsigned fault, std::vector<unsigned>& trace) {
        const auto action = [&](unsigned step) -> uint32_t {
            trace.push_back(step);
            if (trace.size() == fault) throw std::runtime_error("ordering failed");
            switch (step) {
            case 1: return a->nHeight != b->nHeight;
            case 2: return a->nHeight < b->nHeight;
            case 3: return a->GetBlockHash() < b->GetBlockHash();
            default: throw std::logic_error("invalid ordering fixture action");
            }
        };
        return migrated ? drivechain::haskell::ParentReplayStore(
            drivechain::haskell::ReplayStoreFlow::ANCHOR_ORDER, action) != 0 :
            bool(action(1) ? action(2) : action(3));
    };
    for (const auto& a : indexes) for (const auto& b : indexes)
    for (unsigned fault = 0; fault <= 2; ++fault) {
        std::array<std::vector<unsigned>, 2> traces;
        std::array<bool, 2> less{}, threw{};
        for (unsigned migrated = 0; migrated < 2; ++migrated) {
            try { less[migrated] = compare(&a, &b, migrated, fault, traces[migrated]); }
            catch (const std::runtime_error& e) {
                BOOST_CHECK_EQUAL(e.what(), "ordering failed");
                threw[migrated] = true;
            }
        }
        BOOST_CHECK(traces[0] == traces[1]);
        BOOST_CHECK_EQUAL(less[0], less[1]);
        BOOST_CHECK_EQUAL(threw[0], threw[1]);
    }
    std::array<unsigned, 6> permutation{0, 1, 6, 8, 12, 14};
    do {
        std::vector<const CBlockIndex*> expected;
        for (unsigned i : permutation) expected.push_back(&indexes[i]);
        auto actual = expected;
        std::sort(expected.begin(), expected.end(), [](const CBlockIndex* a, const CBlockIndex* b) {
            if (a->nHeight != b->nHeight) return a->nHeight < b->nHeight;
            return a->GetBlockHash() < b->GetBlockHash();
        });
        std::sort(actual.begin(), actual.end(), [&](const CBlockIndex* a, const CBlockIndex* b) {
            std::vector<unsigned> trace;
            return compare(a, b, true, 0, trace);
        });
        BOOST_CHECK(actual == expected);
    } while (std::next_permutation(permutation.begin(), permutation.end()));
}

BOOST_AUTO_TEST_CASE(reconciliation_gate_preserves_budget_and_snapshot_order)
{
    LOCK(cs_main);
    for (unsigned flags = 0; flags < 8; ++flags)
    for (unsigned fault = 0; fault <= 5; ++fault) {
        std::array<std::vector<unsigned>, 2> traces;
        std::array<bool, 2> proceed{}, stalled{}, reported{}, held{}, threw{};
        for (unsigned migrated = 0; migrated < 2; ++migrated) {
            std::optional<DrivechainParentValidationBudget> budget;
            const auto action = [&](unsigned step) -> uint32_t {
                AssertLockHeld(cs_main);
                traces[migrated].push_back(step);
                if (traces[migrated].size() == fault) throw std::runtime_error("reconciliation gate failed");
                switch (step) {
                case 1: return bool(flags & 1);
                case 2: budget.emplace(true); return 1;
                case 3: return bool(flags & 2);
                case 4: BOOST_REQUIRE(budget.has_value()); return bool(flags & 4);
                case 5: reported[migrated] = true; stalled[migrated] = true; return 1;
                default: throw std::logic_error("invalid reconciliation fixture action");
                }
            };
            try {
                if (migrated) proceed[migrated] = drivechain::haskell::ParentReplayStore(
                    drivechain::haskell::ReplayStoreFlow::RECONCILIATION_GATE, action);
                else {
                    const auto original = [&] {
                        if (!action(1)) return false;
                        action(2);
                        if (action(3) && !action(4)) { action(5); return false; }
                        return true;
                    };
                    proceed[migrated] = original();
                }
            } catch (const std::runtime_error& e) {
                BOOST_CHECK_EQUAL(e.what(), "reconciliation gate failed");
                threw[migrated] = true;
            }
            held[migrated] = budget.has_value();
            if (proceed[migrated]) BOOST_CHECK(held[migrated]);
        }
        BOOST_CHECK(traces[0] == traces[1]);
        BOOST_CHECK_EQUAL(proceed[0], proceed[1]);
        BOOST_CHECK_EQUAL(stalled[0], stalled[1]);
        BOOST_CHECK_EQUAL(reported[0], reported[1]);
        BOOST_CHECK_EQUAL(held[0], held[1]);
        BOOST_CHECK_EQUAL(threw[0], threw[1]);
    }
}

BOOST_AUTO_TEST_CASE(anchor_replacement_preserves_evidence_and_authorization_order)
{
    LOCK(cs_main);
    for (bool derived : {false, true})
    for (unsigned status = 0; status < 4; ++status)
    for (bool allowed : {false, true})
    for (bool prior_stall : {false, true})
    for (unsigned prefix = 0; prefix < 32; ++prefix)
    for (unsigned fault = 0; fault <= 16; ++fault) {
        std::array<std::vector<unsigned>, 2> traces;
        std::array<bool, 2> stalled{prior_stall, prior_stall}, replaced{}, result{}, threw{};
        std::array<unsigned, 2> reported{};
        std::array<bool, 2> predecessor_bound{}, fatal{};
        for (unsigned migrated = 0; migrated < 2; ++migrated) {
            const auto action = [&](unsigned step) -> uint32_t {
                AssertLockHeld(cs_main);
                traces[migrated].push_back(step);
                if (traces[migrated].size() == fault) throw std::runtime_error("replacement failed");
                switch (step) {
                case 1: return derived;
                case 2: stalled[migrated] = true; reported[migrated] = 1; return 1;
                case 3: return status == 0;
                case 4: return status == 1;
                case 5: stalled[migrated] = true; return 1;
                case 6: reported[migrated] = 2; return 1;
                case 7: return allowed;
                case 8: reported[migrated] = 3; return 1;
                case 9: replaced[migrated] = true; reported[migrated] = 4; return 1;
                case 10: return bool(prefix & 1);
                case 11: return bool(prefix & 2);
                case 12: return bool(prefix & 4);
                case 13: return bool(prefix & 8);
                case 14: predecessor_bound[migrated] = true; return 1;
                case 15: return bool(prefix & 16);
                case 16: fatal[migrated] = true; return 0;
                default: throw std::logic_error("invalid replacement fixture action");
                }
            };
            try {
                if (migrated) result[migrated] = drivechain::haskell::ParentReplayStore(
                    drivechain::haskell::ReplayStoreFlow::ANCHOR_REPLACEMENT, action);
                else {
                    const auto original = [&] {
                        if (!action(10)) return true;
                        if (!action(11)) return true;
                        if (action(12)) {
                            if (!action(13)) return true;
                            action(14);
                        }
                        if (!action(15)) { action(16); return false; }
                        if (!action(1)) action(2);
                        else if (!action(3)) {
                            if (action(4)) action(5);
                            action(6);
                        } else if (!action(7)) action(8);
                        else action(9);
                        return true;
                    };
                    result[migrated] = original();
                }
            } catch (const std::runtime_error& e) {
                BOOST_CHECK_EQUAL(e.what(), "replacement failed");
                threw[migrated] = true;
            }
        }
        BOOST_CHECK(traces[0] == traces[1]);
        BOOST_CHECK_EQUAL(stalled[0], stalled[1]);
        BOOST_CHECK_EQUAL(replaced[0], replaced[1]);
        BOOST_CHECK_EQUAL(reported[0], reported[1]);
        BOOST_CHECK_EQUAL(predecessor_bound[0], predecessor_bound[1]);
        BOOST_CHECK_EQUAL(fatal[0], fatal[1]);
        BOOST_CHECK_EQUAL(result[0], result[1]);
        BOOST_CHECK_EQUAL(threw[0], threw[1]);
    }
}

BOOST_AUTO_TEST_CASE(snapshot_backlog_preserves_reset_and_count_bounds)
{
    LOCK(cs_main);
    const uint64_t maximum = std::numeric_limits<uint32_t>::max();
    for (uint64_t count : {uint64_t{0}, uint64_t{1}, uint64_t{2}, maximum,
                          maximum + 1, std::numeric_limits<uint64_t>::max()})
    for (unsigned fault = 0; fault <= 2; ++fault) {
        std::array<std::vector<unsigned>, 2> traces;
        std::array<bool, 2> reset{}, result{}, threw{};
        for (unsigned migrated = 0; migrated < 2; ++migrated) {
            const auto action = [&](unsigned step) -> uint32_t {
                AssertLockHeld(cs_main);
                traces[migrated].push_back(step);
                if (traces[migrated].size() == fault) throw std::runtime_error("snapshot backlog failed");
                switch (step) {
                case 1: return std::min<uint64_t>(count, maximum);
                case 2: reset[migrated] = true; return 1;
                default: throw std::logic_error("invalid backlog fixture action");
                }
            };
            try {
                if (migrated) result[migrated] = drivechain::haskell::ParentReplayStore(
                    drivechain::haskell::ReplayStoreFlow::SNAPSHOT_BACKLOG, action);
                else {
                    action(1);
                    if (count <= 1) { action(2); result[migrated] = true; }
                }
            } catch (const std::runtime_error& e) {
                BOOST_CHECK_EQUAL(e.what(), "snapshot backlog failed");
                threw[migrated] = true;
            }
        }
        BOOST_CHECK(traces[0] == traces[1]);
        BOOST_CHECK_EQUAL(reset[0], reset[1]);
        BOOST_CHECK_EQUAL(result[0], result[1]);
        BOOST_CHECK_EQUAL(threw[0], threw[1]);
    }
}

BOOST_AUTO_TEST_CASE(candidate_admission_preserves_work_and_header_order)
{
    LOCK(cs_main);
    std::array<CBlockIndex, 3> indexes;
    for (unsigned i = 0; i < indexes.size(); ++i) indexes[i].nChainWork = i + 1;
    CBlockIndex* candidate = &indexes[1];
    for (unsigned tip = 0; tip <= 3; ++tip)
    for (unsigned header = 0; header <= 3; ++header)
    for (bool authenticated : {false, true})
    for (unsigned status = 0; status < 4; ++status)
    for (bool descends : {false, true})
    for (bool present : {false, true})
    for (bool eligible : {false, true})
    for (bool transactions : {false, true})
    for (unsigned fault = 0; fault <= 17; ++fault) {
        CBlockIndex* active_tip = tip ? &indexes[tip - 1] : nullptr;
        CBlockIndex* initial_header = header ? &indexes[header - 1] : nullptr;
        std::array<CBlockIndex*, 2> best_header{initial_header, initial_header};
        std::array<std::set<CBlockIndex*, node::CBlockIndexWorkComparator>, 2> candidates;
        std::array<std::set<CBlockIndex*>, 2> suppressed;
        std::array<std::vector<unsigned>, 2> traces;
        std::array<bool, 2> result{}, threw{}, stalled{};
        std::array<unsigned, 2> reported{};
        for (unsigned migrated = 0; migrated < 2; ++migrated) {
            suppressed[migrated].insert(candidate);
            if (present) candidates[migrated].insert(candidate);
            const auto action = [&](unsigned step) -> uint32_t {
                AssertLockHeld(cs_main);
                traces[migrated].push_back(step);
                if (traces[migrated].size() == fault) throw std::runtime_error("candidate admission failed");
                switch (step) {
                case 1: return active_tip == nullptr;
                case 2: return candidates[migrated].value_comp()(candidate, active_tip);
                case 3:
                    candidates[migrated].insert(candidate);
                    suppressed[migrated].erase(candidate);
                    return 1;
                case 4: return authenticated;
                case 5: return best_header[migrated] == nullptr;
                case 6: return node::CBlockIndexWorkComparator()(best_header[migrated], candidate);
                case 7: best_header[migrated] = candidate; return 1;
                case 8: return status == 0;
                case 9:
                    candidates[migrated].erase(candidate);
                    suppressed[migrated].insert(candidate);
                    return 1;
                case 10: return status == 1 && descends;
                case 11: best_header[migrated] = active_tip; return 1;
                case 12: return status == 2;
                case 13: reported[migrated] = 1; stalled[migrated] = true; return 1;
                case 14: reported[migrated] = 2; return 1;
                case 15: return 0; // Admission tail with no remaining ancestry.
                case 20: return eligible;
                case 21: suppressed[migrated].erase(candidate); return 1;
                case 22: return transactions;
                case 23:
                    candidates[migrated].erase(candidate);
                    suppressed[migrated].erase(candidate);
                    return 1;
                default: throw std::logic_error("invalid admission fixture action");
                }
            };
            try {
                if (migrated) result[migrated] = drivechain::haskell::ParentReplayStore(
                    drivechain::haskell::ReplayStoreFlow::CANDIDATE_ADMISSION, action);
                else {
                    if (!action(20)) action(21);
                    else if (!action(22)) action(23);
                    else {
                        BOOST_CHECK_EQUAL(action(15), 0U);
                        if (action(8)) {
                            if (action(1) || !action(2)) action(3);
                            if (action(4) && (action(5) || action(6))) action(7);
                        } else {
                            action(9);
                            if (action(10)) action(11);
                            if (action(12)) action(13); else action(14);
                        }
                    }
                    result[migrated] = true;
                }
            } catch (const std::runtime_error& e) {
                BOOST_CHECK_EQUAL(e.what(), "candidate admission failed");
                threw[migrated] = true;
            }
        }
        BOOST_CHECK(traces[0] == traces[1]);
        BOOST_CHECK(candidates[0] == candidates[1]);
        BOOST_CHECK(suppressed[0] == suppressed[1]);
        BOOST_CHECK(best_header[0] == best_header[1]);
        BOOST_CHECK_EQUAL(stalled[0], stalled[1]);
        BOOST_CHECK_EQUAL(reported[0], reported[1]);
        BOOST_CHECK_EQUAL(result[0], result[1]);
        BOOST_CHECK_EQUAL(threw[0], threw[1]);
    }
}

BOOST_AUTO_TEST_CASE(candidate_ancestry_preserves_first_failure_and_error)
{
    LOCK(cs_main);
    for (unsigned encoded = 0; encoded < 64; ++encoded)
    for (unsigned count = 0; count <= 3; ++count)
    for (unsigned fault = 0; fault <= 22; ++fault) {
        std::array<unsigned, 3> statuses;
        for (unsigned i = 0, value = encoded; i < statuses.size(); ++i, value /= 4) statuses[i] = value % 4;
        std::array<std::vector<unsigned>, 2> traces;
        std::array<unsigned, 2> cursor{}, chain_status{}, checked{};
        std::array<std::string, 2> error, checked_error;
        std::array<bool, 2> result{}, threw{}, admitted{}, stalled{};
        for (unsigned migrated = 0; migrated < 2; ++migrated) {
            const auto action = [&](unsigned step) -> uint32_t {
                AssertLockHeld(cs_main);
                traces[migrated].push_back(step);
                if (traces[migrated].size() == fault) throw std::runtime_error("ancestry failed");
                switch (step) {
                case 20: case 22: return 1;
                case 15: return cursor[migrated] < count;
                case 16:
                    checked[migrated] = statuses.at(cursor[migrated]);
                    checked_error[migrated] = strprintf("ancestor %u", cursor[migrated]);
                    return checked[migrated] == 1;
                case 17: return checked[migrated] == 2;
                case 18:
                    chain_status[migrated] = checked[migrated];
                    error[migrated] = checked_error[migrated];
                    return 1;
                case 19: ++cursor[migrated]; return 1;
                case 8: return chain_status[migrated] == 0;
                case 1: return 1;
                case 3: admitted[migrated] = true; return 1;
                case 4: return 0;
                case 9: admitted[migrated] = false; return 1;
                case 10: return 0;
                case 12: return chain_status[migrated] == 2;
                case 13: stalled[migrated] = true; return 1;
                case 14: return 1;
                default: throw std::logic_error("invalid ancestry fixture action");
                }
            };
            try {
                if (migrated) result[migrated] = drivechain::haskell::ParentReplayStore(
                    drivechain::haskell::ReplayStoreFlow::CANDIDATE_ADMISSION, action);
                else {
                    BOOST_CHECK_EQUAL(action(20), 1U);
                    BOOST_CHECK_EQUAL(action(22), 1U);
                    while (action(15)) {
                        if (action(16) || action(17)) { action(18); break; }
                        action(19);
                    }
                    if (action(8)) {
                        if (action(1)) action(3);
                        action(4);
                    } else {
                        action(9);
                        action(10);
                        if (action(12)) action(13); else action(14);
                    }
                    result[migrated] = true;
                }
            } catch (const std::runtime_error& e) {
                BOOST_CHECK_EQUAL(e.what(), "ancestry failed");
                threw[migrated] = true;
            }
        }
        BOOST_CHECK(traces[0] == traces[1]);
        BOOST_CHECK_EQUAL(cursor[0], cursor[1]);
        BOOST_CHECK_EQUAL(chain_status[0], chain_status[1]);
        BOOST_CHECK_EQUAL(error[0], error[1]);
        BOOST_CHECK_EQUAL(result[0], result[1]);
        BOOST_CHECK_EQUAL(threw[0], threw[1]);
        BOOST_CHECK_EQUAL(admitted[0], admitted[1]);
        BOOST_CHECK_EQUAL(stalled[0], stalled[1]);
    }
}

BOOST_AUTO_TEST_CASE(anchor_disconnection_preserves_stall_and_failure_order)
{
    LOCK(cs_main);
    for (unsigned encoded = 0; encoded < 27; ++encoded)
    for (unsigned count = 0; count <= 3; ++count)
    for (unsigned fail_at = 0; fail_at <= 3; ++fail_at)
    for (bool eligible : {false, true})
    for (bool descends : {false, true})
    for (unsigned fault = 0; fault <= 29; ++fault) {
        std::array<unsigned, 3> statuses;
        for (unsigned i = 0, value = encoded; i < statuses.size(); ++i, value /= 3) statuses[i] = value % 3;
        std::array<std::vector<unsigned>, 2> traces, suppressed, rolled_back;
        std::array<unsigned, 2> cursor{};
        std::array<bool, 2> result{}, threw{}, stalled{}, disconnected{}, failed_mempool{};
        std::array<bool, 2> successful_mempool{}, reinserted{};
        for (unsigned migrated = 0; migrated < 2; ++migrated) {
            const auto action = [&](unsigned step) -> uint32_t {
                AssertLockHeld(cs_main);
                traces[migrated].push_back(cursor[migrated] * 16 + step);
                if (traces[migrated].size() == fault) throw std::runtime_error("disconnect failed");
                switch (step) {
                case 1: return cursor[migrated] < count;
                case 2: return statuses[cursor[migrated]] == 0;
                case 3: return statuses[cursor[migrated]] == 1;
                case 4: stalled[migrated] = true; return 1;
                case 5: suppressed[migrated].push_back(cursor[migrated]); return 1;
                case 6:
                    if (cursor[migrated] == fail_at) return 0;
                    ++cursor[migrated]; return 1;
                case 7: failed_mempool[migrated] = true; return 0;
                case 8: disconnected[migrated] = true; return 1;
                case 9: return disconnected[migrated];
                case 10: successful_mempool[migrated] = true; return 1;
                case 11: return eligible;
                case 12: reinserted[migrated] = true; return 1;
                case 13: return descends;
                case 14: rolled_back[migrated].push_back(cursor[migrated]); return 1;
                default: throw std::logic_error("invalid disconnect fixture action");
                }
            };
            try {
                if (migrated) result[migrated] = drivechain::haskell::ParentReplayStore(
                    drivechain::haskell::ReplayStoreFlow::ANCHOR_DISCONNECT, action);
                else {
                    const auto original = [&] {
                        while (action(1)) {
                            if (action(2)) break;
                            if (action(3)) { action(4); break; }
                            action(5);
                            if (action(13)) action(14);
                            if (!action(6)) { action(7); return false; }
                            action(8);
                        }
                        if (action(9)) {
                            action(10);
                            if (action(11)) action(12);
                        }
                        return true;
                    };
                    result[migrated] = original();
                }
            } catch (const std::runtime_error& e) {
                BOOST_CHECK_EQUAL(e.what(), "disconnect failed");
                threw[migrated] = true;
            }
        }
        BOOST_CHECK(traces[0] == traces[1]);
        BOOST_CHECK(suppressed[0] == suppressed[1]);
        BOOST_CHECK(rolled_back[0] == rolled_back[1]);
        BOOST_CHECK_EQUAL(cursor[0], cursor[1]);
        BOOST_CHECK_EQUAL(result[0], result[1]);
        BOOST_CHECK_EQUAL(threw[0], threw[1]);
        BOOST_CHECK_EQUAL(stalled[0], stalled[1]);
        BOOST_CHECK_EQUAL(disconnected[0], disconnected[1]);
        BOOST_CHECK_EQUAL(failed_mempool[0], failed_mempool[1]);
        BOOST_CHECK_EQUAL(successful_mempool[0], successful_mempool[1]);
        BOOST_CHECK_EQUAL(reinserted[0], reinserted[1]);
    }
}

BOOST_AUTO_TEST_CASE(candidate_transaction_admission_preserves_set_effects)
{
    LOCK(cs_main);
    const std::array<unsigned, 4> validity{BLOCK_VALID_TREE, BLOCK_VALID_TRANSACTIONS,
        BLOCK_VALID_SCRIPTS, BLOCK_VALID_TRANSACTIONS | BLOCK_FAILED_VALID};
    for (unsigned status : validity) for (unsigned flags = 0; flags < 16; ++flags)
    for (unsigned mode = 0; mode < 3; ++mode) for (unsigned fault = 0; fault <= 6; ++fault) {
        CBlockIndex index;
        index.nStatus = status;
        index.m_chain_tx_count = flags & 4 ? 1 : 0;
        const CBlockIndex* candidate = flags & 1 ? &index : nullptr;
        std::array<std::vector<unsigned>, 2> traces;
        const unsigned initial = mode == 0 ? 0 : 3;
        std::array<unsigned, 2> effects{initial, initial};
        std::array<bool, 2> threw{};
        for (unsigned migrated = 0; migrated < 2; ++migrated) {
            const auto read = [&](unsigned step) -> bool {
                AssertLockHeld(cs_main);
                traces[migrated].push_back(step);
                if (traces[migrated].size() == fault) throw std::runtime_error("admission failed");
                switch (step) {
                case 1: return candidate != nullptr;
                case 2: return !(flags & 2);
                case 3: return candidate->IsValid(BLOCK_VALID_TRANSACTIONS);
                case 4: return candidate->HaveNumChainTxs();
                case 5: return flags & 8;
                case 6: effects[migrated] |= 1; return true;
                case 7: effects[migrated] &= ~2U; return true;
                case 8: effects[migrated] = 0; return true;
                case 9: effects[migrated] |= 4; return true;
                default: throw std::logic_error("invalid admission fixture action");
                }
            };
            const auto transactions = [&] {
                return migrated ? drivechain::haskell::ParentReplayAll<2>({
                    [&] { return read(3); }, [&] { return read(4); },
                }) : read(3) && read(4);
            };
            try {
                if (mode == 0) {
                    const bool eligible = migrated ? drivechain::haskell::ParentReplayAll<2>({
                        [&] { return read(1); }, transactions,
                    }) : read(1) && transactions();
                    if (eligible) read(6);
                } else if (mode == 1) {
                    if (migrated) drivechain::haskell::ParentReplayStore(
                        drivechain::haskell::ReplayStoreFlow::CANDIDATE_ADMISSION,
                        [&](uint32_t step) -> uint32_t {
                            switch (step) {
                            case 20: return drivechain::haskell::ParentReplayAll<2>({
                                [&] { return read(1); }, [&] { return read(2); },
                            });
                            case 21: return read(7);
                            case 22: return transactions();
                            case 23: return read(8);
                            case 15: read(9); return 0;
                            case 8: case 1: case 3: return 1;
                            case 4: return 0;
                            default: throw std::logic_error("invalid candidate filter action");
                            }
                        });
                    else {
                        if (!(read(1) && read(2))) read(7);
                        else if (!transactions()) read(8);
                        else read(9);
                    }
                } else {
                    const bool eligible = migrated ? drivechain::haskell::ParentReplayAll<4>({
                        [&] { return read(1); }, [&] { return read(2); },
                        [&] { return read(5); }, transactions,
                    }) : read(1) && read(2) && read(5) && transactions();
                    if (eligible) read(9);
                }
            } catch (const std::runtime_error& e) {
                BOOST_CHECK_EQUAL(e.what(), "admission failed");
                threw[migrated] = true;
            }
        }
        BOOST_CHECK(traces[0] == traces[1]);
        BOOST_CHECK_EQUAL(effects[0], effects[1]);
        BOOST_CHECK_EQUAL(threw[0], threw[1]);
    }
}

BOOST_AUTO_TEST_CASE(reconciliation_header_guard_preserves_lazy_ancestry)
{
    LOCK(cs_main);
    std::array<CBlockIndex, 4> nodes;
    nodes[0].nHeight = 0;
    for (unsigned i = 1; i < nodes.size(); ++i) {
        nodes[i].nHeight = i == 3 ? 1 : i;
        nodes[i].pprev = i == 3 ? &nodes[0] : &nodes[i - 1];
    }
    for (const auto& candidate : nodes)
    for (unsigned head = 0; head <= nodes.size(); ++head)
    for (bool gated : {false, true}) for (bool orphaned : {false, true})
    for (unsigned fault = 0; fault <= 4; ++fault) {
        const CBlockIndex* header = head ? &nodes[head - 1] : nullptr;
        std::array<std::vector<unsigned>, 2> traces;
        std::array<bool, 2> result{}, threw{};
        for (unsigned migrated = 0; migrated < 2; ++migrated) {
            const auto read = [&](unsigned step) {
                AssertLockHeld(cs_main);
                traces[migrated].push_back(step);
                if (traces[migrated].size() == fault) throw std::runtime_error("header guard failed");
                switch (step) {
                case 1: return orphaned;
                case 2: return header != nullptr;
                case 3: return header->nHeight >= candidate.nHeight;
                case 4: return header->GetAncestor(candidate.nHeight) == &candidate;
                default: throw std::logic_error("invalid header guard fixture action");
                }
            };
            try {
                if (migrated) {
                    const auto descends = [&] { return drivechain::haskell::ParentReplayAll<3>({
                        [&] { return read(2); }, [&] { return read(3); }, [&] { return read(4); },
                    }); };
                    result[migrated] = gated ? drivechain::haskell::ParentReplayAll<2>({
                        [&] { return read(1); }, descends,
                    }) : descends();
                } else result[migrated] = (!gated || read(1)) && read(2) && read(3) && read(4);
            } catch (const std::runtime_error& e) {
                BOOST_CHECK_EQUAL(e.what(), "header guard failed");
                threw[migrated] = true;
            }
        }
        BOOST_CHECK(traces[0] == traces[1]);
        BOOST_CHECK_EQUAL(result[0], result[1]);
        BOOST_CHECK_EQUAL(threw[0], threw[1]);
    }
}

BOOST_AUTO_TEST_CASE(candidate_ancestry_preserves_first_failure)
{
    LOCK(cs_main);
    std::array<CBlockIndex, 3> nodes;
    for (unsigned i = 0; i < nodes.size(); ++i) {
        nodes[i].nHeight = i;
        nodes[i].pprev = i ? &nodes[i - 1] : nullptr;
    }
    constexpr std::array statuses{DrivechainAnchorStatus::ACTIVE,
        DrivechainAnchorStatus::ORPHANED, DrivechainAnchorStatus::UNAVAILABLE};
    for (unsigned encoded = 0; encoded < 27; ++encoded)
    for (unsigned active = 0; active < 8; ++active)
    for (unsigned start = 0; start < 4; ++start)
    for (unsigned fault = 0; fault <= 13; ++fault) {
        std::array<DrivechainAnchorStatus, 3> answers;
        for (unsigned i = 0, value = encoded; i < answers.size(); ++i, value /= 3) answers[i] = statuses[value % 3];
        std::array<std::vector<unsigned>, 2> traces;
        std::array<DrivechainAnchorStatus, 2> result{statuses[0], statuses[0]};
        std::array<std::string, 2> errors;
        std::array<CBlockIndex*, 2> final_cursor{};
        std::array<bool, 2> threw{};
        for (unsigned migrated = 0; migrated < 2; ++migrated) {
            CBlockIndex* cursor = start ? &nodes[start - 1] : nullptr;
            DrivechainAnchorStatus checked{statuses[0]};
            const auto action = [&](unsigned step) -> bool {
                AssertLockHeld(cs_main);
                traces[migrated].push_back(step);
                if (traces[migrated].size() == fault) throw std::runtime_error("ancestry failed");
                switch (step) {
                case 1: return cursor != nullptr;
                case 2: return active & (1U << cursor->nHeight);
                case 3: checked = answers[cursor->nHeight]; return true;
                case 4: result[migrated] = checked; errors[migrated] = std::to_string(cursor->nHeight); return true;
                case 5: cursor = cursor->pprev; return true;
                default: throw std::logic_error("invalid ancestry fixture action");
                }
            };
            try {
                if (migrated) {
                    drivechain::haskell::ParentReplayWhile(
                        [&] { return drivechain::haskell::ParentReplayAll<2>({
                            [&] { return action(1); }, [&] { return !action(2); },
                        }); },
                        [&] {
                            action(3);
                            if (checked == statuses[1] || checked == statuses[2]) { action(4); return 0; }
                            return 1;
                        }, [&] { action(5); });
                } else {
                    while (action(1) && !action(2)) {
                        action(3);
                        if (checked == statuses[1] || checked == statuses[2]) { action(4); break; }
                        action(5);
                    }
                }
            } catch (const std::runtime_error& e) {
                BOOST_CHECK_EQUAL(e.what(), "ancestry failed");
                threw[migrated] = true;
            }
            final_cursor[migrated] = cursor;
        }
        BOOST_CHECK(traces[0] == traces[1]);
        BOOST_CHECK(result[0] == result[1]);
        BOOST_CHECK_EQUAL(errors[0], errors[1]);
        BOOST_CHECK(final_cursor[0] == final_cursor[1]);
        BOOST_CHECK_EQUAL(threw[0], threw[1]);
    }
}

BOOST_AUTO_TEST_CASE(anchor_publication_persists_before_readmission)
{
    LOCK(cs_main);
    for (unsigned flags = 0; flags < 8; ++flags)
    for (unsigned fault = 0; fault <= 4; ++fault) {
        std::array<std::vector<unsigned>, 2> traces;
        std::array<BlockValidationState, 2> states;
        std::array<bool, 2> result{}, threw{}, admitted{};
        std::array<unsigned, 2> writes{};
        for (unsigned migrated = 0; migrated < 2; ++migrated) {
            const auto action = [&](unsigned step) -> uint32_t {
                AssertLockHeld(cs_main);
                traces[migrated].push_back(step);
                if (traces[migrated].size() == fault) throw std::runtime_error("publication failed");
                switch (step) {
                case 1: return bool(flags & 1);
                case 2: ++writes[migrated]; return bool(flags & 2);
                case 3: return states[migrated].Error("Failed to atomically persist replacement drivechain anchors");
                case 4: admitted[migrated] = true; return bool(flags & 4);
                default: throw std::logic_error("invalid publication fixture action");
                }
            };
            try {
                if (migrated) result[migrated] = drivechain::haskell::ParentReplayStore(
                    drivechain::haskell::ReplayStoreFlow::ANCHOR_PUBLISH, action);
                else {
                    const auto original = [&] {
                        if (action(1) && !action(2)) return action(3);
                        return action(4);
                    };
                    result[migrated] = original();
                }
            } catch (const std::runtime_error& e) {
                BOOST_CHECK_EQUAL(e.what(), "publication failed");
                threw[migrated] = true;
            }
        }
        BOOST_CHECK(traces[0] == traces[1]);
        BOOST_CHECK_EQUAL(result[0], result[1]);
        BOOST_CHECK_EQUAL(threw[0], threw[1]);
        BOOST_CHECK_EQUAL(writes[0], writes[1]);
        BOOST_CHECK_EQUAL(admitted[0], admitted[1]);
        BOOST_CHECK_EQUAL(states[0].IsError(), states[1].IsError());
        BOOST_CHECK_EQUAL(states[0].GetRejectReason(), states[1].GetRejectReason());
        if (!fault) {
            BOOST_CHECK_EQUAL(writes[1], bool(flags & 1));
            BOOST_CHECK_EQUAL(admitted[1], !(flags & 1) || (flags & 2));
        }
    }
}

BOOST_AUTO_TEST_CASE(reanchor_traversal_preserves_skip_and_fatal_order)
{
    LOCK(cs_main);
    for (unsigned flags = 0; flags < 512; ++flags)
    for (unsigned fatal = 0; fatal < 3; ++fatal)
    for (unsigned fault = 0; fault <= 22; ++fault) {
        const std::array<unsigned, 2> candidates{flags, 511};
        std::array<std::vector<unsigned>, 2> traces, changed;
        std::array<bool, 2> completed{}, threw{};
        for (unsigned migrated = 0; migrated < 2; ++migrated) {
            unsigned index{0};
            const auto visit = [&](unsigned candidate) {
                const auto action = [&](unsigned step) -> bool {
                    AssertLockHeld(cs_main);
                    traces[migrated].push_back(index * 16 + step);
                    if (traces[migrated].size() == fault) throw std::runtime_error("reanchor failed");
                    if (step <= 9) return candidate & (1U << (step - 1));
                    if (step == 10) return index != fatal;
                    changed[migrated].push_back(index);
                    return true;
                };
                const auto process = [&] {
                    if (migrated) {
                        if (!drivechain::haskell::ParentReplayAll<3>({
                            [&] { return action(1); }, [&] { return action(2); },
                            [&] { return drivechain::haskell::ParentReplayAll<2>({
                                [&] { return action(3); },
                                [&] { return drivechain::haskell::ParentReplayAll<2>({[&] { return action(4); }, [&] { return action(5); }}); },
                            }); },
                        })) return true;
                        if (drivechain::haskell::ParentReplayAll<2>({[&] { return action(6); }, [&] { return action(7); }}) &&
                            !drivechain::haskell::ParentReplayAll<2>({[&] { return action(8); }, [&] { return action(9); }})) return true;
                    } else {
                        if (!action(1) || !action(2) || !action(3) || !action(4) || !action(5)) return true;
                        if (action(6) && action(7) && (!action(8) || !action(9))) return true;
                    }
                    if (!action(10)) return false;
                    return action(11);
                };
                const bool result = process();
                ++index;
                return result;
            };
            try {
                if (migrated) completed[migrated] = drivechain::haskell::ParentReplayEach(candidates, visit);
                else {
                    const auto original = [&] {
                        for (const auto candidate : candidates) if (!visit(candidate)) return false;
                        return true;
                    };
                    completed[migrated] = original();
                }
            } catch (const std::runtime_error& e) {
                BOOST_CHECK_EQUAL(e.what(), "reanchor failed");
                threw[migrated] = true;
            }
        }
        BOOST_CHECK(traces[0] == traces[1]);
        BOOST_CHECK(changed[0] == changed[1]);
        BOOST_CHECK_EQUAL(completed[0], completed[1]);
        BOOST_CHECK_EQUAL(threw[0], threw[1]);
    }
}

BOOST_AUTO_TEST_CASE(startup_anchor_reconciliation_fails_closed_without_disconnect)
{
    auto& chainman = *m_node.chainman;
    auto& chainstate = chainman.ActiveChainstate();
    auto& consensus = const_cast<Consensus::Params&>(chainman.GetParams().GetConsensus());
    BOOST_REQUIRE(!consensus.drivechain_slot);
    BOOST_REQUIRE(!chainman.m_interrupt);
    CBlockIndex* previous;
    uint256 best;
    {
        LOCK(cs_main);
        previous = chainstate.m_chain.Tip();
        BOOST_REQUIRE(previous);
        BOOST_REQUIRE_EQUAL(previous->nHeight, 0);
        best = chainstate.CoinsTip().GetBestBlock();
    }
    const auto hash = uint256S("1234");
    CBlockIndex missing;
    missing.phashBlock = &hash;
    missing.pprev = previous;
    missing.nHeight = previous->nHeight + 1;
    struct Restore {
        Chainstate& chainstate;
        Consensus::Params& params;
        CBlockIndex* tip;
        util::SignalInterrupt& interrupt;
        ~Restore() {
            LOCK(cs_main);
            chainstate.m_chain.SetTip(*tip);
            params.drivechain_slot.reset();
            if (interrupt) (void)interrupt.reset();
        }
    } restore{chainstate, consensus, previous, m_interrupt};
    consensus.drivechain_slot = 24;
    {
        LOCK(cs_main);
        chainstate.m_chain.SetTip(missing);
    }
    for (unsigned attempt = 0; attempt < 2; ++attempt) {
        BlockValidationState state;
        BOOST_CHECK(!chainstate.ReconcileDrivechainAnchorsForStartup(state));
        BOOST_CHECK(state.IsError());
        BOOST_CHECK_EQUAL(state.GetRejectReason(),
            "authenticated parent state unavailable during startup anchor reconciliation");
        LOCK(cs_main);
        BOOST_CHECK(chainstate.m_chain.Tip() == &missing);
        BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == best);
        BOOST_CHECK(!missing.m_drivechain_anchor);
        BOOST_CHECK_EQUAL(missing.nStatus & BLOCK_FAILED_MASK, 0U);
    }
    BOOST_REQUIRE(m_interrupt());
    BlockValidationState interrupted;
    BOOST_CHECK(!chainstate.ReconcileDrivechainAnchorsForStartup(interrupted));
    BOOST_CHECK_EQUAL(interrupted.GetRejectReason(),
        "cannot prepare startup drivechain anchors: drivechain anchor snapshot authentication interrupted");
    BOOST_REQUIRE(m_interrupt.reset());
    {
        LOCK(cs_main);
        chainstate.m_chain.SetTip(*previous);
    }
    BlockValidationState genesis;
    BOOST_CHECK(chainstate.ReconcileDrivechainAnchorsForStartup(genesis));
    BOOST_CHECK(genesis.IsValid());
    LOCK(cs_main);
    BOOST_CHECK(chainstate.m_chain.Tip() == previous);
    BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == best);
}

BOOST_AUTO_TEST_CASE(anchor_cache_preserves_epoch_and_lookup_precedence)
{
    LOCK(cs_main);
    for (unsigned flags = 0; flags < 128; ++flags)
    for (unsigned initial = 0; initial < 3; ++initial)
    for (unsigned fault = 0; fault <= 11; ++fault) {
        std::array<std::vector<unsigned>, 2> traces;
        std::array<unsigned, 2> status{initial, initial};
        std::array<std::string, 2> errors{"previous", "previous"};
        std::array<bool, 2> threw{};
        for (unsigned migrated = 0; migrated < 2; ++migrated) {
            const auto action = [&](unsigned step) -> uint32_t {
                AssertLockHeld(cs_main);
                traces[migrated].push_back(step);
                if (traces[migrated].size() == fault) throw std::runtime_error("cache failed");
                switch (step) {
                case 1: return bool(flags & 1);
                case 2:
                    if (!(flags & 2)) errors[migrated] = "stale epoch";
                    return bool(flags & 2);
                case 3: status[migrated] = 0; return 1;
                case 4: return bool(flags & 4);
                case 5: return bool(flags & 8);
                case 6: return bool(flags & 16);
                case 7: return bool(flags & 32);
                case 8: status[migrated] = 1; return 1;
                case 9: errors[migrated] = "absent"; return 1;
                case 10:
                    if (!migrated) return (flags & 1) && (flags & 64);
                    return drivechain::haskell::ParentReplayAll<2>({
                        [&] { return bool(flags & 1); }, [&] { return bool(flags & 64); },
                    });
                case 11: status[migrated] = 2; errors[migrated] = "live lookup"; return 1;
                default: throw std::logic_error("invalid cache fixture action");
                }
            };
            try {
                if (migrated) {
                    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::ANCHOR_CACHE, action);
                } else {
                    const auto original = [&] {
                        if (action(1) && !action(2)) { action(3); return; }
                        if (!action(4)) return;
                        if (action(5) || action(6)) { action(8); return; }
                        if (!action(7)) { action(9); return; }
                        if (action(10)) { action(8); return; }
                        action(11);
                    };
                    original();
                }
            } catch (const std::runtime_error& e) {
                BOOST_CHECK_EQUAL(e.what(), "cache failed");
                threw[migrated] = true;
            }
        }
        BOOST_CHECK(traces[0] == traces[1]);
        BOOST_CHECK_EQUAL(status[0], status[1]);
        BOOST_CHECK_EQUAL(errors[0], errors[1]);
        BOOST_CHECK_EQUAL(threw[0], threw[1]);
    }
}

BOOST_AUTO_TEST_CASE(anchor_preparation_preserves_publication_order)
{
    for (unsigned flags = 0; flags < 32; ++flags)
    for (unsigned fault = 0; fault <= 7; ++fault) {
        std::array<std::vector<unsigned>, 2> traces;
        std::array<bool, 2> accepted{}, threw{}, published{}, cleared{};
        for (unsigned migrated = 0; migrated < 2; ++migrated) {
            const auto action = [&](unsigned step) -> uint32_t {
                AssertLockNotHeld(cs_main);
                traces[migrated].push_back(step);
                if (traces[migrated].size() == fault) throw std::runtime_error("preparation failed");
                switch (step) {
                case 1: return bool(flags & 1);
                case 2: return bool(flags & 2);
                case 3: return 0;
                case 4: {
                    LOCK(cs_main);
                    cleared[migrated] = flags & 4;
                    return cleared[migrated];
                }
                case 5: return bool(flags & 8);
                case 6: return bool(flags & 16);
                case 7: {
                    LOCK(cs_main);
                    published[migrated] = true;
                    return 1;
                }
                default: throw std::logic_error("invalid preparation fixture action");
                }
            };
            try {
                if (migrated) {
                    accepted[migrated] = drivechain::haskell::ParentReplayStore(
                        drivechain::haskell::ReplayStoreFlow::SNAPSHOT_PREPARE, action);
                } else {
                    const auto original = [&] {
                        if (!action(1)) return true;
                        if (action(2)) { action(3); return false; }
                        if (action(4) || action(5)) return true;
                        if (!action(6)) return false;
                        action(7);
                        return true;
                    };
                    accepted[migrated] = original();
                }
            } catch (const std::runtime_error& e) {
                BOOST_CHECK_EQUAL(e.what(), "preparation failed");
                threw[migrated] = true;
            }
        }
        BOOST_CHECK(traces[0] == traces[1]);
        BOOST_CHECK_EQUAL(accepted[0], accepted[1]);
        BOOST_CHECK_EQUAL(threw[0], threw[1]);
        BOOST_CHECK_EQUAL(published[0], published[1]);
        BOOST_CHECK_EQUAL(cleared[0], cleared[1]);
    }
}

BOOST_AUTO_TEST_CASE(anchor_collection_preserves_shared_paths_and_stops)
{
    LOCK(cs_main);
    std::array<CBlockIndex, 5> nodes;
    for (unsigned i = 0; i < nodes.size(); ++i) nodes[i].nHeight = i;
    nodes[1].pprev = &nodes[0];
    nodes[2].pprev = &nodes[1];
    nodes[3].pprev = &nodes[1];
    nodes[4].pprev = &nodes[3];
    const std::array<const CBlockIndex*, 7> roots{&nodes[2], &nodes[4], &nodes[3], &nodes[2], nullptr, &nodes[0], &nodes[4]};
    for (unsigned present = 0; present < 32; ++present)
    for (unsigned active = 0; active < 32; ++active)
    for (unsigned fault = 0; fault <= 56; ++fault) {
        std::array<std::set<const CBlockIndex*>, 2> visited;
        std::array<std::vector<unsigned>, 2> appended, traces;
        std::array<bool, 2> threw{};
        for (unsigned migrated = 0; migrated < 2; ++migrated) {
            const auto path = [&](const CBlockIndex* index) {
                const auto action = [&](unsigned step) {
                    AssertLockHeld(cs_main);
                    traces[migrated].push_back(step);
                    if (traces[migrated].size() == fault) throw std::runtime_error("collection failed");
                    switch (step) {
                    case 1: return index != nullptr;
                    case 2: return index->nHeight > 0;
                    case 3: return visited[migrated].insert(index).second;
                    case 4: return bool(present & (1U << index->nHeight));
                    case 5: appended[migrated].push_back(index->nHeight); return true;
                    case 6: return bool(active & (1U << index->nHeight));
                    case 7: index = index->pprev; return true;
                    default: throw std::logic_error("invalid collection fixture action");
                    }
                };
                if (migrated) {
                    return drivechain::haskell::ParentReplayStore(
                        drivechain::haskell::ReplayStoreFlow::ANCHOR_COLLECT, action) != 0;
                } else {
                    while (action(1) && action(2)) {
                        if (!action(3)) break;
                        if (action(4)) action(5);
                        if (action(6)) break;
                        action(7);
                    }
                }
                return true;
            };
            try {
                if (migrated) drivechain::haskell::ParentReplayEach(roots, path);
                else for (const auto* root : roots) path(root);
            } catch (const std::runtime_error& e) {
                BOOST_CHECK_EQUAL(e.what(), "collection failed");
                threw[migrated] = true;
            }
        }
        BOOST_CHECK(traces[0] == traces[1]);
        BOOST_CHECK(appended[0] == appended[1]);
        BOOST_CHECK(visited[0] == visited[1]);
        BOOST_CHECK_EQUAL(threw[0], threw[1]);
    }
}

BOOST_AUTO_TEST_CASE(anchor_snapshot_reuse_preserves_probe_and_coverage_order)
{
    for (bool present : {false, true}) for (bool current : {false, true})
    for (unsigned count = 0; count <= 4; ++count) for (unsigned mask = 0; mask < (1U << count); ++mask)
    for (unsigned fault = 0; fault <= count + 3; ++fault) {
        std::vector<unsigned> anchors(count);
        std::iota(anchors.begin(), anchors.end(), 0);
        std::array<std::vector<unsigned>, 2> traces;
        std::array<bool, 2> reused{}, threw{};
        for (unsigned migrated = 0; migrated < 2; ++migrated) {
            const auto read = [&](unsigned step, bool result) {
                traces[migrated].push_back(step);
                if (step == fault) throw std::runtime_error("snapshot probe failed");
                return result;
            };
            const auto contains = [&](unsigned index) { return read(index + 4, mask & (1U << index)); };
            try {
                if (migrated) {
                    reused[migrated] = drivechain::haskell::ParentReplayAll<3>({
                        [&] { return read(1, present); },
                        [&] { return read(2, current); },
                        [&] { read(3, true); return drivechain::haskell::ParentReplayEach(anchors, contains); },
                    });
                } else if (read(1, present) && read(2, current)) {
                    read(3, true);
                    reused[migrated] = std::all_of(anchors.begin(), anchors.end(), contains);
                }
            } catch (const std::runtime_error& e) {
                BOOST_CHECK_EQUAL(e.what(), "snapshot probe failed");
                threw[migrated] = true;
            }
        }
        BOOST_CHECK(traces[0] == traces[1]);
        BOOST_CHECK_EQUAL(reused[0], reused[1]);
        BOOST_CHECK_EQUAL(threw[0], threw[1]);
        if (fault == 0) BOOST_CHECK_EQUAL(reused[1], present && current && mask == (1U << count) - 1);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_anchor_snapshot_exact_identity_and_generation)
{
    DrivechainAnchor anchor;
    anchor.parent_block_hash = uint256S("01");
    anchor.bmm_block_hash = uint256S("02");
    anchor.parent_chainwork = uint256S("10");
    anchor.bmm_chainwork = uint256S("20");
    anchor.parent_height = 100;
    anchor.bmm_height = 101;
    anchor.parent_median_time_past = 1'700'000'000;
    BOOST_REQUIRE(anchor.IsSane());
    const uint256 tip = uint256S("ff");
    DrivechainAnchorSnapshot snapshot{24, tip, 7};
    BOOST_REQUIRE(snapshot.Add(anchor, DrivechainAnchorStatus::ACTIVE));
    BOOST_CHECK(snapshot.Matches(24, tip, 7));
    BOOST_CHECK(snapshot.Contains(anchor, 24, 7));
    BOOST_CHECK(!snapshot.Contains(anchor, 23, 7));
    BOOST_CHECK(!snapshot.Contains(anchor, 24, 0));
    BOOST_CHECK(!snapshot.Contains(anchor, 24, 8));
    BOOST_CHECK(!snapshot.Matches(23, tip, 7));
    BOOST_CHECK(!snapshot.Matches(24, tip, 0));
    BOOST_CHECK(!snapshot.Matches(24, tip, 8));
    // A parent reorg OR ordinary extension must invalidate the old tip,
    // including before the background replay generation has noticed it.
    BOOST_CHECK(!snapshot.Matches(24, uint256S("fe"), 7));
    BOOST_CHECK(!snapshot.Matches(24, uint256{}, 7));

    // Every serialized field participates, including context fields that
    // leave the P/Q pair unchanged. Test each substitution independently.
    const std::array<std::function<void(DrivechainAnchor&)>, 8> mutations{{
        [](DrivechainAnchor& a) { ++a.version; },
        [](DrivechainAnchor& a) { a.parent_block_hash = uint256S("03"); },
        [](DrivechainAnchor& a) { a.bmm_block_hash = uint256S("04"); },
        [](DrivechainAnchor& a) { a.parent_chainwork = uint256S("11"); },
        [](DrivechainAnchor& a) { a.bmm_chainwork = uint256S("21"); },
        [](DrivechainAnchor& a) { ++a.parent_height; },
        [](DrivechainAnchor& a) { ++a.bmm_height; },
        [](DrivechainAnchor& a) { ++a.parent_median_time_past; },
    }};
    for (size_t i = 0; i < mutations.size(); ++i) {
        BOOST_TEST_CONTEXT("serialized anchor field " << i) {
            DrivechainAnchor changed = anchor;
            mutations[i](changed);
            BOOST_CHECK(changed != anchor);
            BOOST_CHECK(!snapshot.Contains(changed, 24, 7));
        }
    }
    // Height substitutions must also miss when their pair remains sane.
    auto other_height = anchor;
    ++other_height.parent_height;
    ++other_height.bmm_height;
    BOOST_REQUIRE(other_height.IsSane());
    BOOST_CHECK(!snapshot.Contains(other_height, 24, 7));

    for (const int invalid_slot : {-1, 256}) {
        DrivechainAnchorSnapshot invalid{invalid_slot, tip, 7};
        BOOST_CHECK(!invalid.Add(anchor, DrivechainAnchorStatus::ACTIVE));
        BOOST_CHECK(!invalid.Matches(invalid_slot, tip, 7));
    }
    DrivechainAnchorSnapshot no_epoch{24, tip, 0};
    BOOST_CHECK(!no_epoch.Add(anchor, DrivechainAnchorStatus::ACTIVE));
    BOOST_CHECK(!no_epoch.EpochMatches(24, 0));
    DrivechainAnchorSnapshot no_tip{24, uint256{}, 7};
    BOOST_CHECK(!no_tip.Add(anchor, DrivechainAnchorStatus::ACTIVE));
    BOOST_CHECK(!no_tip.Matches(24, uint256{}, 7));
}

BOOST_AUTO_TEST_CASE(drivechain_anchor_snapshot_bulk_positive_only)
{
    DrivechainAnchor anchor;
    anchor.parent_block_hash = uint256S("01");
    anchor.bmm_block_hash = uint256S("02");
    anchor.parent_chainwork = uint256S("10");
    anchor.bmm_chainwork = uint256S("20");
    anchor.parent_median_time_past = 1'700'000'000;
    DrivechainAnchorSnapshot snapshot{24, uint256S("ff"), 7};
    std::vector<DrivechainAnchor> anchors;
    // More than the 62-anchor startup regression: positive lookups are
    // in-memory and do not open/reset one parent budget per ancestor.
    DrivechainParentValidationBudget budget{/*enable=*/true};
    for (uint32_t height = 100; height < 228; ++height) {
        anchor.parent_height = height;
        anchor.bmm_height = height + 1;
        BOOST_REQUIRE(anchor.IsSane());
        BOOST_REQUIRE(snapshot.Add(anchor, DrivechainAnchorStatus::ACTIVE));
        anchors.push_back(anchor);
    }
    BOOST_CHECK_EQUAL(snapshot.Size(), 128U);
    for (const auto& active : anchors) {
        BOOST_CHECK(snapshot.Contains(active, 24, 7));
        BOOST_CHECK(snapshot.Add(active, DrivechainAnchorStatus::ACTIVE));
    }
    BOOST_CHECK_EQUAL(snapshot.Size(), 128U);

    ++anchor.parent_height;
    ++anchor.bmm_height;
    BOOST_REQUIRE(anchor.IsSane());
    BOOST_CHECK(!snapshot.Add(anchor, DrivechainAnchorStatus::ORPHANED));
    BOOST_CHECK(!snapshot.Add(anchor, DrivechainAnchorStatus::UNAVAILABLE));
    BOOST_CHECK(!snapshot.Contains(anchor, 24, 7));
    anchor.bmm_block_hash.SetNull();
    BOOST_REQUIRE(!anchor.IsSane());
    BOOST_CHECK(!snapshot.Add(anchor, DrivechainAnchorStatus::ACTIVE));
    BOOST_CHECK(!snapshot.Contains(anchor, 24, 7));
    BOOST_CHECK_EQUAL(snapshot.Size(), 128U);
}

BOOST_AUTO_TEST_CASE(drivechain_anchor_snapshot_failed_warm_clears_output)
{
    util::SignalInterrupt interrupt;
    std::string error;
    std::shared_ptr<const DrivechainAnchorSnapshot> result =
        std::make_shared<DrivechainAnchorSnapshot>(24, uint256S("ff"), 7);
    {
        DrivechainParentValidationBudget budget{/*enable=*/true};
        BOOST_CHECK(!WarmDrivechainAnchorSnapshot({}, 24, interrupt, result, &error));
        BOOST_CHECK(!result);
        BOOST_CHECK(error.find("inside a parent validation budget") != std::string::npos);
    }
    // These failures happen before RPC; no synthetic authentication or
    // network-dependent fixture is allowed to turn a partial result valid.
    result = std::make_shared<DrivechainAnchorSnapshot>(24, uint256S("ff"), 7);
    BOOST_CHECK(!WarmDrivechainAnchorSnapshot({}, -1, interrupt, result, &error));
    BOOST_CHECK(!result);
    BOOST_CHECK(!error.empty());
    result = std::make_shared<DrivechainAnchorSnapshot>(24, uint256S("ff"), 7);
    BOOST_REQUIRE(interrupt());
    BOOST_CHECK(!WarmDrivechainAnchorSnapshot({}, 24, interrupt, result, &error));
    BOOST_CHECK(!result);
    BOOST_CHECK(error.find("interrupted") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(drivechain_budget_lifecycle_handles_non_lifo_and_unwinding)
{
    static_assert(std::is_nothrow_destructible_v<DrivechainParentValidationBudget>);
    static_assert(std::is_nothrow_destructible_v<DrivechainUntrustedParentAdmission>);
    util::SignalInterrupt interrupt;
    BOOST_REQUIRE(interrupt());
    const auto check_active = [&](bool active) {
        std::string error;
        std::shared_ptr<const DrivechainAnchorSnapshot> result;
        BOOST_CHECK(!WarmDrivechainAnchorSnapshot({}, 24, interrupt, result, &error));
        BOOST_CHECK(!result);
        BOOST_CHECK(error.find(active ? "inside a parent validation budget" : "interrupted") != std::string::npos);
    };
    check_active(false);
    auto disabled = std::make_unique<DrivechainParentValidationBudget>(false);
    check_active(false);
    auto first = std::make_unique<DrivechainParentValidationBudget>(true);
    auto second = std::make_unique<DrivechainParentValidationBudget>(true);
    check_active(true);
    first.reset();
    check_active(true);
    disabled.reset();
    check_active(true);
    second.reset();
    check_active(false);
    struct Unwind {};
    try {
        DrivechainParentValidationBudget outer{true}, inner{true};
        check_active(true);
        throw Unwind{};
    } catch (const Unwind&) {}
    check_active(false);
    {
        DrivechainParentValidationBudget fresh{true};
        check_active(true);
    }
    check_active(false);
    {
        std::optional<DrivechainParentValidationBudget> deferred;
        check_active(false);
        deferred.emplace(true);
        check_active(true);
    }
    check_active(false);
}

BOOST_AUTO_TEST_CASE(drivechain_anchor_snapshot_does_not_outlive_locked_budget)
{
    DrivechainAnchorSnapshot snapshot{24, uint256S("ff"), 7};
    std::string error;
    DrivechainParentValidationBudget budget{/*enable=*/true};
    std::this_thread::sleep_for(std::chrono::milliseconds{2100});
    // Deadline rejection precedes the generation lookup, so this test needs
    // neither a fabricated replay epoch nor an available parent RPC server.
    BOOST_CHECK(!CheckDrivechainAnchorSnapshotEpoch(snapshot, 24, &error));
    BOOST_CHECK(error.find("work budget exhausted") != std::string::npos);
    // Nested budgets must not reset the two-second aggregate limit.
    DrivechainParentValidationBudget nested{/*enable=*/true};
    BOOST_CHECK(!CheckDrivechainAnchorSnapshotEpoch(snapshot, 24, &error));
    BOOST_CHECK(error.find("work budget exhausted") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(drivechain_anchor_sequence_is_strict)
{
    DrivechainAnchor previous;
    previous.parent_block_hash = uint256S("01");
    previous.bmm_block_hash = uint256S("02");
    previous.parent_chainwork = uint256S("10");
    previous.bmm_chainwork = uint256S("20");
    previous.parent_height = 100;
    previous.bmm_height = 101;
    previous.parent_median_time_past = 1'700'000'000;
    BOOST_REQUIRE(previous.IsSane());

    DrivechainAnchor contiguous;
    contiguous.parent_block_hash = previous.bmm_block_hash;
    contiguous.bmm_block_hash = uint256S("03");
    contiguous.parent_chainwork = previous.bmm_chainwork;
    contiguous.bmm_chainwork = uint256S("30");
    contiguous.parent_height = 101;
    contiguous.bmm_height = 102;
    contiguous.parent_median_time_past = previous.parent_median_time_past + 600;
    BOOST_REQUIRE(contiguous.IsSane());
    BOOST_CHECK(contiguous.Follows(previous));

    DrivechainAnchor wrong_contiguous_hash = contiguous;
    wrong_contiguous_hash.parent_block_hash = uint256S("ff");
    BOOST_CHECK(!wrong_contiguous_hash.Follows(previous));

    DrivechainAnchor skipped_parent_blocks = contiguous;
    skipped_parent_blocks.parent_block_hash = uint256S("04");
    skipped_parent_blocks.bmm_block_hash = uint256S("05");
    skipped_parent_blocks.parent_chainwork = uint256S("40");
    skipped_parent_blocks.bmm_chainwork = uint256S("50");
    skipped_parent_blocks.parent_height = 103;
    skipped_parent_blocks.bmm_height = 104;
    BOOST_REQUIRE(skipped_parent_blocks.IsSane());
    BOOST_CHECK(skipped_parent_blocks.Follows(previous));

    skipped_parent_blocks.parent_chainwork = previous.bmm_chainwork;
    BOOST_CHECK(!skipped_parent_blocks.Follows(previous));

    DrivechainAnchor malformed = contiguous;
    malformed.version = DrivechainAnchor::CURRENT_VERSION + 1;
    BOOST_CHECK(!malformed.IsSane());
    BOOST_CHECK(!malformed.Follows(previous));
}

BOOST_AUTO_TEST_CASE(drivechain_anchor_boundary_reference)
{
    const std::array<uint256,5> work{uint256{},uint256S("01"),uint256S("ff"),uint256S("0100"),
        uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")};
    const std::array<uint32_t,4> parents{0,1,UINT32_MAX-1,UINT32_MAX};
    const std::array<uint32_t,4> successors{0,1,2,UINT32_MAX};
    const std::array<uint64_t,4> times{0,UINT32_MAX,uint64_t{UINT32_MAX}+1,UINT64_MAX};
    for (uint8_t version : {0,1,2,255})
    for (bool parent_present : {false,true}) for (bool successor_present : {false,true})
    for (const auto& parent_work : work) for (const auto& successor_work : work)
    for (uint32_t parent_height : parents) for (uint32_t successor_height : successors)
    for (uint64_t median : times) {
        DrivechainAnchor anchor;
        anchor.version=version;
        anchor.parent_block_hash=parent_present ? uint256S("01") : uint256{};
        anchor.bmm_block_hash=successor_present ? uint256S("02") : uint256{};
        anchor.parent_chainwork=parent_work;
        anchor.bmm_chainwork=successor_work;
        anchor.parent_height=parent_height;
        anchor.bmm_height=successor_height;
        anchor.parent_median_time_past=median;
        // Fixed-width hexadecimal ordering and widened modular addition are
        // independent of the production arith_uint256 and unsigned expression.
        const bool expected=version==1 && parent_present && successor_present &&
            parent_work!=uint256{} && successor_work!=uint256{} &&
            successor_work.GetHex()>parent_work.GetHex() &&
            successor_height==((uint64_t{parent_height}+1)&UINT32_MAX) && median<=UINT32_MAX;
        BOOST_CHECK_EQUAL(anchor.IsSane(),expected);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_anchor_sequence_boundaries_and_encoding)
{
    DrivechainAnchor previous;
    previous.parent_block_hash=uint256S("01");
    previous.bmm_block_hash=uint256S("02");
    previous.parent_chainwork=uint256S("10");
    previous.bmm_chainwork=uint256S("20");
    previous.parent_height=100;
    previous.bmm_height=101;
    previous.parent_median_time_past=UINT32_MAX;
    DataStream bytes;
    bytes << previous;
    std::vector<unsigned char> golden(145,0);
    golden[0]=1; golden[1]=1; golden[33]=2; golden[65]=0x10; golden[97]=0x20;
    golden[129]=100; golden[133]=101;
    std::fill(golden.begin()+137,golden.begin()+141,0xff);
    BOOST_CHECK_EQUAL(HexStr(bytes),HexStr(golden));
    DrivechainAnchor decoded;
    bytes >> decoded;
    BOOST_CHECK(decoded==previous);
    BOOST_CHECK(bytes.empty());

    const std::array<uint32_t,5> heights{0,100,101,102,UINT32_MAX};
    const std::array<uint256,4> works{uint256S("10"),uint256S("20"),uint256S("21"),uint256S("0100")};
    for (uint32_t height : heights) for (const auto& value : works)
    for (bool same_hash : {false,true}) for (bool malformed : {false,true}) {
        auto candidate=previous;
        candidate.version=malformed ? 2 : 1;
        candidate.parent_height=height;
        candidate.bmm_height=static_cast<uint32_t>(uint64_t{height}+1);
        candidate.parent_chainwork=value;
        candidate.bmm_chainwork=uint256S("ffff");
        candidate.parent_block_hash=same_hash ? previous.bmm_block_hash : uint256S("03");
        candidate.parent_median_time_past=0;
        const bool expected=!malformed && height>=101 &&
            (height==101 ? same_hash && value==previous.bmm_chainwork : value.GetHex()>previous.bmm_chainwork.GetHex());
        BOOST_CHECK_EQUAL(candidate.Follows(previous),expected);
        auto bad_previous=previous;
        bad_previous.version=0;
        BOOST_CHECK(!candidate.Follows(bad_previous));
    }
}

BOOST_AUTO_TEST_CASE(drivechain_anchor_replacement_requires_proven_orphan)
{
    DrivechainAnchor predecessor;
    predecessor.parent_block_hash = uint256S("01");
    predecessor.bmm_block_hash = uint256S("02");
    predecessor.parent_chainwork = uint256S("10");
    predecessor.bmm_chainwork = uint256S("20");
    predecessor.parent_height = 100;
    predecessor.bmm_height = 101;
    predecessor.parent_median_time_past = 1'700'000'000;
    BOOST_REQUIRE(predecessor.IsSane());

    DrivechainAnchor old_anchor;
    old_anchor.parent_block_hash = predecessor.bmm_block_hash;
    old_anchor.bmm_block_hash = uint256S("03");
    old_anchor.parent_chainwork = predecessor.bmm_chainwork;
    old_anchor.bmm_chainwork = uint256S("30");
    old_anchor.parent_height = 101;
    old_anchor.bmm_height = 102;
    old_anchor.parent_median_time_past = 1'700'000'600;
    BOOST_REQUIRE(old_anchor.IsSane());

    DrivechainAnchor replacement = old_anchor;
    replacement.bmm_block_hash = uint256S("04");
    replacement.bmm_chainwork = uint256S("31");
    BOOST_REQUIRE(replacement.IsSane());

    BOOST_CHECK(IsDrivechainAnchorReplacementAllowed(
        DrivechainAnchorStatus::ORPHANED, old_anchor, replacement,
        &predecessor));
    BOOST_CHECK(!IsDrivechainAnchorReplacementAllowed(
        DrivechainAnchorStatus::ACTIVE, old_anchor, replacement,
        &predecessor));
    BOOST_CHECK(!IsDrivechainAnchorReplacementAllowed(
        DrivechainAnchorStatus::UNAVAILABLE, old_anchor, replacement,
        &predecessor));
    BOOST_CHECK(!IsDrivechainAnchorReplacementAllowed(
        DrivechainAnchorStatus::ORPHANED, old_anchor, old_anchor,
        &predecessor));

    DrivechainAnchor wrong_parent = replacement;
    wrong_parent.parent_block_hash = uint256S("ff");
    BOOST_CHECK(!IsDrivechainAnchorReplacementAllowed(
        DrivechainAnchorStatus::ORPHANED, old_anchor, wrong_parent,
        &predecessor));

    const auto sane = [](const DrivechainAnchor& a) {
        return a.version==1 && !a.parent_block_hash.IsNull() && !a.bmm_block_hash.IsNull() &&
            !a.parent_chainwork.IsNull() && !a.bmm_chainwork.IsNull() &&
            a.bmm_height==((uint64_t{a.parent_height}+1)&UINT32_MAX) &&
            a.bmm_chainwork.GetHex()>a.parent_chainwork.GetHex() && a.parent_median_time_past<=UINT32_MAX;
    };
    for (uint32_t status : {0U,1U,2U,3U,UINT32_MAX}) for (unsigned mask=0; mask<256; ++mask)
    for (bool has_predecessor : {false,true}) {
        auto old=old_anchor, next=replacement, prior=predecessor;
        if (mask&1) old.version=0;
        if (mask&2) next.version=2;
        if (mask&4) next=old;
        if (mask&8) prior.parent_chainwork.SetNull();
        if (mask&16) next.parent_block_hash=uint256S("ff");
        if (mask&32) { ++next.parent_height; ++next.bmm_height; }
        if (mask&64) next.parent_chainwork=uint256S("21");
        if (mask&128) next.parent_median_time_past=uint64_t{UINT32_MAX}+1;
        const bool follows=sane(prior) && next.parent_height>=prior.bmm_height &&
            (next.parent_height==prior.bmm_height ? next.parent_block_hash==prior.bmm_block_hash &&
                next.parent_chainwork==prior.bmm_chainwork : next.parent_chainwork.GetHex()>prior.bmm_chainwork.GetHex());
        const bool expected=status==1 && sane(old) && sane(next) && old!=next && (!has_predecessor || follows);
        BOOST_CHECK_EQUAL(IsDrivechainAnchorReplacementAllowed(static_cast<DrivechainAnchorStatus>(status),
            old,next,has_predecessor ? &prior : nullptr),expected);
    }
}


BOOST_AUTO_TEST_CASE(drivechain_best_header_requires_admitted_full_block)
{
    LOCK(cs_main);
    auto header=Params().GenesisBlock().GetBlockHeader();
    header.hashPrevBlock.SetNull();
    for (bool update : {false,true}) for (bool present : {false,true}) for (int relative : {-1,0,1}) {
        ++header.nNonce;
        CBlockIndex previous;
        const auto work=GetBlockProof(CBlockIndex(header));
        previous.nChainWork=relative<0 ? arith_uint256{0} : work+arith_uint256{unsigned(relative)};
        CBlockIndex* best=present ? &previous : nullptr;
        const auto original=best;
        const auto candidate=m_node.chainman->m_blockman.AddToBlockIndex(header,best,update);
        BOOST_REQUIRE(candidate);
        BOOST_CHECK(best==(update && (!present || previous.nChainWork<candidate->nChainWork) ? candidate : original));
    }
    Consensus::Params drivechain;
    drivechain.drivechain_slot = uint8_t{24};

    CBlockIndex index;
    index.nHeight = 1;
    BOOST_CHECK(!IsDrivechainHeaderAuthenticated(&index, drivechain));

    // Header metadata alone is insufficient. nChainTx is set only after an
    // admitted full block (and its ancestry) has been processed.
    index.nStatus |= BLOCK_HAVE_DATA;
    BOOST_CHECK(!IsDrivechainHeaderAuthenticated(&index, drivechain));

    DrivechainAnchor anchor;
    anchor.parent_block_hash = uint256S("01");
    anchor.bmm_block_hash = uint256S("02");
    anchor.parent_chainwork = uint256S("10");
    anchor.bmm_chainwork = uint256S("20");
    anchor.parent_height = 100;
    anchor.bmm_height = 101;
    anchor.parent_median_time_past = 1'700'000'000;
    BOOST_REQUIRE(anchor.IsSane());
    index.m_drivechain_anchor = anchor;
    BOOST_CHECK(!IsDrivechainHeaderAuthenticated(&index, drivechain));

    index.nTx = 1;
    index.m_chain_tx_count = 2;
    BOOST_CHECK(IsDrivechainHeaderAuthenticated(&index, drivechain));

    // Pruning removes local block bytes, not the fact that this full block was
    // admitted. It must not dead-end later drivechain synchronization.
    index.nStatus &= ~BLOCK_HAVE_DATA;
    BOOST_CHECK(IsDrivechainHeaderAuthenticated(&index, drivechain));

    index.nStatus |= BLOCK_FAILED_VALID;
    BOOST_CHECK(!IsDrivechainHeaderAuthenticated(&index, drivechain));

    Consensus::Params ordinary;
    BOOST_CHECK(IsDrivechainHeaderAuthenticated(&index, ordinary));
}

BOOST_AUTO_TEST_CASE(drivechain_unknown_sibling_headers_are_not_indexed)
{
    class TestDrivechainParams final : public CChainParams
    {
    public:
        TestDrivechainParams()
        {
            consensus = Params().GetConsensus();
            consensus.drivechain_slot = uint8_t{24};
        }
    } drivechain_params;

    // Header admission now reads the manager's immutable chain parameters.
    const ChainstateManager::Options chainman_opts{
        .chainparams = drivechain_params,
        .datadir = m_path_root / "header-admission",
        .check_block_index = 1,
        .notifications = *m_node.notifications,
        .worker_threads_num = 0,
        .script_execution_cache_bytes = 0,
        .signature_cache_bytes = 0,
    };
    const node::BlockManager::Options blockman_opts{
        .chainparams = drivechain_params,
        .blocks_dir = chainman_opts.datadir / "blocks",
        .notifications = chainman_opts.notifications,
        .block_tree_db_params = DBParams{
            .path = chainman_opts.datadir / "blocks" / "index",
            .cache_bytes = 1 << 20,
            .memory_only = true,
        },
    };
    fs::create_directories(blockman_opts.blocks_dir);
    ChainstateManager chainman{*m_node.shutdown_signal, chainman_opts, blockman_opts};
    size_t original_index_size;
    {
        LOCK(cs_main);
        chainman.InitializeChainstate(nullptr);
        original_index_size = chainman.m_blockman.m_block_index.size();
    }

    // Each call models another connection/reconnection offering a distinct
    // sibling. None has a full block/BMM proof, so global persistent width
    // must remain exactly unchanged.
    for (uint32_t nonce = 1; nonce <= 128; ++nonce) {
        CBlockHeader sibling;
        sibling.hashPrevBlock =
            drivechain_params.GetConsensus().hashGenesisBlock;
        sibling.nTime = 1'700'000'000;
        sibling.nNonce = nonce;
        BlockValidationState state;
        BOOST_CHECK(!chainman.ProcessNewBlockHeaders(
            std::span{&sibling, 1}, /*min_pow_checked=*/true, state));
        BOOST_CHECK(state.IsError());
    }

    LOCK(cs_main);
    BOOST_CHECK_EQUAL(
        chainman.m_blockman.m_block_index.size(),
        original_index_size);

    // Reindex can populate the index before the active chain has a tip.
    BOOST_REQUIRE(chainman.ActiveChain().Tip() == nullptr);
    chainman.RecalculateBestHeader();
    BOOST_CHECK(chainman.m_best_header == nullptr);
    CBlockIndex* genesis = chainman.m_blockman.InsertBlockIndex(
        drivechain_params.GetConsensus().hashGenesisBlock);
    BOOST_REQUIRE(genesis != nullptr);
    genesis->nTx = 1;
    genesis->m_chain_tx_count = 1;
    genesis->nChainWork = 1;
    chainman.RecalculateBestHeader();
    BOOST_CHECK(chainman.m_best_header == genesis);

    CBlockIndex* unauthenticated = chainman.m_blockman.InsertBlockIndex(uint256S("04"));
    BOOST_REQUIRE(unauthenticated != nullptr);
    unauthenticated->nHeight = 1;
    unauthenticated->nChainWork = 2;
    chainman.RecalculateBestHeader();
    BOOST_CHECK(chainman.m_best_header == genesis);

    DrivechainAnchor anchor;
    anchor.parent_block_hash = uint256S("01");
    anchor.bmm_block_hash = uint256S("02");
    anchor.parent_chainwork = uint256S("10");
    anchor.bmm_chainwork = uint256S("20");
    anchor.parent_height = 100;
    anchor.bmm_height = 101;
    anchor.parent_median_time_past = 1'700'000'000;
    BOOST_REQUIRE(anchor.IsSane());
    unauthenticated->m_drivechain_anchor = anchor;
    unauthenticated->nTx = 1;
    unauthenticated->m_chain_tx_count = 2;
    chainman.RecalculateBestHeader();
    BOOST_CHECK(chainman.m_best_header == unauthenticated);
    unauthenticated->nStatus |= BLOCK_FAILED_VALID;
    chainman.RecalculateBestHeader();
    BOOST_CHECK(chainman.m_best_header == genesis);
}

//! Test retrieval of valid assumeutxo values.
BOOST_AUTO_TEST_CASE(test_assumeutxo)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::REGTEST);

    // These heights don't have assumeutxo configurations associated, per the contents
    // of kernel/chainparams.cpp.
    std::vector<int> bad_heights{0, 100, 111, 115, 209, 211};

    for (auto empty : bad_heights) {
        const auto out = params->AssumeutxoForHeight(empty);
        BOOST_CHECK(!out);
    }

    const auto out110 = *params->AssumeutxoForHeight(110);
    BOOST_CHECK_EQUAL(out110.hash_serialized.ToString(), "6657b736d4fe4db0cbc796789e812d5dba7f5c143764b1b6905612f1830609d1");
    BOOST_CHECK_EQUAL(out110.m_chain_tx_count, 111U);

    const auto out110_2 = *params->AssumeutxoForBlockhash(uint256{"696e92821f65549c7ee134edceeeeaaa4105647a3c4fd9f298c0aec0ab50425c"});
    BOOST_CHECK_EQUAL(out110_2.hash_serialized.ToString(), "6657b736d4fe4db0cbc796789e812d5dba7f5c143764b1b6905612f1830609d1");
    BOOST_CHECK_EQUAL(out110_2.m_chain_tx_count, 111U);
}

BOOST_AUTO_TEST_CASE(block_malleation)
{
    // Test utilities that calls `IsBlockMutated` and then clears the validity
    // cache flags on `CBlock`.
    auto is_mutated = [](CBlock& block, bool check_witness_root) {
        bool mutated{IsBlockMutated(block, check_witness_root)};
        block.fChecked = false;
        block.m_checked_witness_commitment = false;
        block.m_checked_merkle_root = false;
        return mutated;
    };
    auto is_not_mutated = [&is_mutated](CBlock& block, bool check_witness_root) {
        return !is_mutated(block, check_witness_root);
    };

    // Test utilities to create coinbase transactions and insert witness
    // commitments.
    //
    // Note: this will not include the witness stack by default to avoid
    // triggering the "no witnesses allowed for blocks that don't commit to
    // witnesses" rule when testing other malleation vectors.
    auto create_coinbase_tx = [](bool include_witness = false) {
        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        coinbase.witness.vtxinwit.resize(1);
        if (include_witness) {
            coinbase.witness.vtxinwit[0].scriptWitness.stack.resize(1);
            coinbase.witness.vtxinwit[0].scriptWitness.stack[0] = std::vector<unsigned char>(32, 0x00);
        }

        coinbase.vout.resize(1);
        coinbase.vout[0].scriptPubKey.resize(MINIMUM_WITNESS_COMMITMENT);
        coinbase.vout[0].scriptPubKey[0] = OP_RETURN;
        coinbase.vout[0].scriptPubKey[1] = 0x24;
        coinbase.vout[0].scriptPubKey[2] = 0xaa;
        coinbase.vout[0].scriptPubKey[3] = 0x21;
        coinbase.vout[0].scriptPubKey[4] = 0xa9;
        coinbase.vout[0].scriptPubKey[5] = 0xed;

        auto tx = MakeTransactionRef(coinbase);
        assert(tx->IsCoinBase());
        return tx;
    };
    auto insert_witness_commitment = [](CBlock& block, uint256 commitment) {
        assert(!block.vtx.empty() && block.vtx[0]->IsCoinBase() && !block.vtx[0]->vout.empty());

        CMutableTransaction mtx{*block.vtx[0]};
        CHash256().Write(commitment).Write(std::vector<unsigned char>(32, 0x00)).Finalize(commitment);
        memcpy(&mtx.vout[0].scriptPubKey[6], commitment.begin(), 32);
        block.vtx[0] = MakeTransactionRef(mtx);
    };

    {
        CBlock block;

        // Empty block is expected to have merkle root of 0x0.
        BOOST_CHECK(block.vtx.empty());
        block.hashMerkleRoot = uint256{1};
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        block.hashMerkleRoot = uint256{};
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Block with a single coinbase tx is mutated if the merkle root is not
        // equal to the coinbase tx's hash.
        block.vtx.push_back(create_coinbase_tx());
        BOOST_CHECK(block.vtx[0]->GetHash() != block.hashMerkleRoot);
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        block.hashMerkleRoot = block.vtx[0]->GetHash();
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Block with two transactions is mutated if the merkle root does not
        // match the double sha256 of the concatenation of the two transaction
        // hashes.
        block.vtx.push_back(MakeTransactionRef(CMutableTransaction{}));
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        HashWriter hasher;
        hasher.write(block.vtx[0]->GetHash());
        hasher.write(block.vtx[1]->GetHash());
        block.hashMerkleRoot = hasher.GetHash();
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Block with two transactions is mutated if any node is duplicate.
        {
            block.vtx[1] = block.vtx[0];
            HashWriter hasher;
            hasher.write(block.vtx[0]->GetHash());
            hasher.write(block.vtx[1]->GetHash());
            block.hashMerkleRoot = hasher.GetHash();
            BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        }

        // Blocks with 64-byte coinbase transactions are not considered mutated
        block.vtx.clear();
        {
            CMutableTransaction mtx;
            mtx.vin.resize(1);
            mtx.vout.resize(1);
            mtx.vout[0].scriptPubKey.resize(4);
            block.vtx.push_back(MakeTransactionRef(mtx));
            block.hashMerkleRoot = block.vtx.back()->GetHash();
            assert(block.vtx.back()->IsCoinBase());
            assert(GetSerializeSize(TX_NO_WITNESS(block.vtx.back())) == 64);
        }
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));
    }

    {
        // Test merkle root malleation

        // Pseudo code to mine transactions tx{1,2,3}:
        //
        // ```
        // loop {
        //   tx1 = random_tx()
        //   tx2 = random_tx()
        //   tx3 = deserialize_tx(txid(tx1) || txid(tx2));
        //   if serialized_size_without_witness(tx3) == 64 {
        //     print(hex(tx3))
        //     break
        //   }
        // }
        // ```
        //
        // The `random_tx` function used to mine the txs below simply created
        // empty transactions with a random version field.
        CMutableTransaction tx1;
        BOOST_CHECK(DecodeHexTx(tx1, "ff204bd0000000000000", /*try_no_witness=*/true, /*try_witness=*/false));
        CMutableTransaction tx2;
        BOOST_CHECK(DecodeHexTx(tx2, "8ae53c92000000000000", /*try_no_witness=*/true, /*try_witness=*/false));
        CMutableTransaction tx3;
        BOOST_CHECK(DecodeHexTx(tx3, "cdaf22d00002c6a7f848f8ae4d30054e61dcf3303d6fe01d282163341f06feecc10032b3160fcab87bdfe3ecfb769206ef2d991b92f8a268e423a6ef4d485f06", /*try_no_witness=*/true, /*try_witness=*/false));
        {
            // Verify that double_sha256(txid1||txid2) == txid3
            HashWriter hasher;
            hasher.write(tx1.GetHash());
            hasher.write(tx2.GetHash());
            assert(hasher.GetHash() == tx3.GetHash());
            // Verify that tx3 is 64 bytes in size (without witness).
            assert(GetSerializeSize(TX_NO_WITNESS(tx3)) == 64);
        }

        CBlock block;
        block.vtx.push_back(MakeTransactionRef(tx1));
        block.vtx.push_back(MakeTransactionRef(tx2));
        uint256 merkle_root = block.hashMerkleRoot = BlockMerkleRoot(block);
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Mutate the block by replacing the two transactions with one 64-byte
        // transaction that serializes into the concatenation of the txids of
        // the transactions in the unmutated block.
        block.vtx.clear();
        block.vtx.push_back(MakeTransactionRef(tx3));
        BOOST_CHECK(!block.vtx.back()->IsCoinBase());
        BOOST_CHECK(BlockMerkleRoot(block) == merkle_root);
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
    }

    {
        CBlock block;
        block.vtx.push_back(create_coinbase_tx(/*include_witness=*/true));
        {
            CMutableTransaction mtx;
            mtx.vin.resize(1);
            mtx.witness.vtxinwit.resize(1);
            mtx.witness.vtxinwit[0].scriptWitness.stack.resize(1);
            mtx.witness.vtxinwit[0].scriptWitness.stack[0] = {0};
            block.vtx.push_back(MakeTransactionRef(mtx));
        }
        block.hashMerkleRoot = BlockMerkleRoot(block);
        // Block with witnesses is considered mutated if the witness commitment
        // is not validated.
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        // Block with invalid witness commitment is considered mutated.
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/true));

        // Block with valid commitment is not mutated
        {
            auto commitment{BlockWitnessMerkleRoot(block)};
            insert_witness_commitment(block, commitment);
            block.hashMerkleRoot = BlockMerkleRoot(block);
        }
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/true));

        // Malleating witnesses should be caught by `IsBlockMutated`.
        {
            CMutableTransaction mtx{*block.vtx[1]};
            assert(!mtx.witness.vtxinwit[0].scriptWitness.stack[0].empty());
            ++mtx.witness.vtxinwit[0].scriptWitness.stack[0][0];
            block.vtx[1] = MakeTransactionRef(mtx);
        }
        // Without also updating the witness commitment, the merkle root should
        // not change when changing one of the witnesses.
        BOOST_CHECK(block.hashMerkleRoot == BlockMerkleRoot(block));
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/true));
        {
            auto commitment{BlockWitnessMerkleRoot(block)};
            insert_witness_commitment(block, commitment);
            block.hashMerkleRoot = BlockMerkleRoot(block);
        }
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/true));

        // Test malleating the coinbase witness reserved value
        {
            CMutableTransaction mtx{*block.vtx[0]};
            mtx.witness.vtxinwit.resize(1);
            mtx.witness.vtxinwit[0].scriptWitness.stack.resize(0);
            block.vtx[0] = MakeTransactionRef(mtx);
            block.hashMerkleRoot = BlockMerkleRoot(block);
        }
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/true));
    }
}

// ELEMENTS: the offline (chainstate-less) SIGHASH_RANGEPROOF gating used by
// elements-tx must treat liquidv1 as known-active even though dynafed there is
// height-activated rather than ALWAYS_ACTIVE.
BOOST_AUTO_TEST_CASE(sighash_rangeproof_by_params_test)
{
    // liquidv1: dynafed is height-activated (nStartTime = 1000000), NOT the
    // ALWAYS_ACTIVE sentinel, but must be treated as active by params.
    const auto liquidv1 = CreateChainParams(*m_node.args, ChainType::LIQUID1);
    BOOST_CHECK(liquidv1->GetConsensus().vDeployments[Consensus::DEPLOYMENT_DYNA_FED].nStartTime
                != Consensus::BIP9Deployment::ALWAYS_ACTIVE);
    BOOST_CHECK(liquidv1->SighashRangeproofActiveByParams());

    // liquidv1test: overrides dynafed to ALWAYS_ACTIVE, so it is active by params
    // via the ALWAYS_ACTIVE branch (independent of the liquidv1 chain-type check).
    const auto liquidv1test = CreateChainParams(*m_node.args, ChainType::LIQUID1TEST);
    BOOST_CHECK_EQUAL(liquidv1test->GetConsensus().vDeployments[Consensus::DEPLOYMENT_DYNA_FED].nStartTime,
                      Consensus::BIP9Deployment::ALWAYS_ACTIVE);
    BOOST_CHECK(liquidv1test->SighashRangeproofActiveByParams());

    // regtest: dynafed never active by default; must be inactive by params.
    const auto regtest = CreateChainParams(*m_node.args, ChainType::REGTEST);
    BOOST_CHECK(!regtest->SighashRangeproofActiveByParams());
}

BOOST_AUTO_TEST_CASE(drivechain_withdrawal_bundle_wire_format)
{
    const CAmount amount{2'000'000};
    const CAmount mainchain_fee{1'000};
    const CScript payout_script = CScript() << OP_0 <<
        std::vector<unsigned char>(20, 0x11);
    const COutPoint withdrawal_outpoint(Txid::FromUint256(uint256::ONE), 7);

    const wallet::DrivechainWithdrawalBundle bundle =
        wallet::BuildDrivechainWithdrawalBundle(
            amount, mainchain_fee, payout_script, withdrawal_outpoint, 42);
    BOOST_CHECK_EQUAL(
        HexStr(bundle.bytes),
        "020000000001000300000000000000000a6a0800000000000003e8"
        "0000000000000000226a20f62b45f18ab38ddcfbd04c0828e56db8"
        "d872235fb4c4780840980aa0a8de0d5e98801e0000000000160014"
        "111111111111111111111111111111111111111100000000");

    BOOST_REQUIRE_GE(bundle.bytes.size(), 7U);
    BOOST_CHECK_EQUAL(bundle.bytes[4], 0); // SegWit marker
    BOOST_CHECK_EQUAL(bundle.bytes[5], 1); // SegWit flag
    BOOST_CHECK_EQUAL(bundle.bytes[6], 0); // actual empty vin

    // The enforcer uses rust-bitcoin's explicit inputless-transaction decoder.
    // Core's generic decoder rejects this deliberately non-broadcastable
    // blinded form, so decode its vector of outputs independently here.
    DataStream payload(
        std::vector<unsigned char>(bundle.bytes.begin() + 7, bundle.bytes.end()));
    std::vector<Bitcoin::CTxOut> outputs;
    uint32_t lock_time{0};
    payload >> outputs >> lock_time;
    BOOST_CHECK(payload.empty());
    BOOST_CHECK_EQUAL(lock_time, 0);
    BOOST_REQUIRE_EQUAL(outputs.size(), 3U);
    BOOST_CHECK_EQUAL(outputs[0].nValue, 0);
    BOOST_CHECK_EQUAL(outputs[1].nValue, 0);
    BOOST_CHECK_EQUAL(outputs[2].nValue, amount - mainchain_fee);
    BOOST_CHECK(outputs[2].scriptPubKey == payout_script);

    std::vector<unsigned char> no_witness_bytes;
    no_witness_bytes.insert(
        no_witness_bytes.end(), bundle.bytes.begin(), bundle.bytes.begin() + 4);
    no_witness_bytes.insert(
        no_witness_bytes.end(), bundle.bytes.begin() + 6, bundle.bytes.end());
    BOOST_CHECK_EQUAL(Hash(no_witness_bytes), bundle.m6id);
    BOOST_CHECK_EQUAL(
        bundle.m6id.GetHex(),
        "ce1626e43b1d163acaf3fac8ab9f6fb78158d99c53e25bbffdde3c9ed75f0e4b");

    std::vector<unsigned char> fee_bytes;
    fee_bytes.reserve(8);
    for (int byte = 7; byte >= 0; --byte) {
        fee_bytes.push_back((static_cast<uint64_t>(mainchain_fee) >>
                             (8 * byte)) & 0xff);
    }
    BOOST_CHECK(outputs[0].scriptPubKey ==
                (CScript() << OP_RETURN << fee_bytes));
}

BOOST_AUTO_TEST_CASE(drivechain_json_rpc_server_is_loopback_only)
{
    ArgsManager args;
    std::string error;
    BOOST_CHECK(ValidateNativeDrivechainRpcServerConfig(args, &error));
    BOOST_CHECK(error.empty());

    args.ForceSetArg("-rpcbind", "127.0.0.1");
    BOOST_CHECK(ValidateNativeDrivechainRpcServerConfig(args, &error));
    BOOST_CHECK(error.empty());
    args.ForceSetArg("-rpcbind", "[::1]:7041");
    BOOST_CHECK(ValidateNativeDrivechainRpcServerConfig(args, &error));
    BOOST_CHECK(error.empty());

    for (const std::string& unsafe : {
             "0.0.0.0", "[::]:7041", "192.168.1.10", "localhost",
             "rpc.example:7041", "", ":7041", "127.0.0.1:0", "[::1]:0"}) {
        args.ForceSetArg("-rpcbind", unsafe);
        BOOST_CHECK(!ValidateNativeDrivechainRpcServerConfig(args, &error));
        BOOST_CHECK(error.find("numeric IPv4 127/8 or IPv6 ::1") !=
                    std::string::npos);
    }

    // Existing authenticated local clients may retain explicit static auth or
    // rpcauth; transport remains local even when rpcallowip is also present.
    args.ForceSetArg("-rpcbind", "127.0.0.1");
    args.ForceSetArg("-rpcallowip", "127.0.0.1");
    args.ForceSetArg("-rpcuser", "bitwindow");
    args.ForceSetArg("-rpcpassword", "local-only-test-secret");
    BOOST_CHECK(ValidateNativeDrivechainRpcServerConfig(args, &error));
    args.ForceSetArg("-rest", "1");
    BOOST_CHECK(!ValidateNativeDrivechainRpcServerConfig(args, &error));
    BOOST_CHECK(error.find("unauthenticated") != std::string::npos);
    args.ForceSetArg("-rest", "0");
    BOOST_CHECK(ValidateNativeDrivechainRpcServerConfig(args, &error));
    for (const auto port : {"-9223372036854775808","-1","0","65536","9223372036854775807"}) {
        args.ForceSetArg("-rpcport",port);
        BOOST_CHECK(!ValidateNativeDrivechainRpcServerConfig(args,&error));
        BOOST_CHECK_EQUAL(error,"-rpcport must be between 1 and 65535");
    }
    args.ForceSetArg("-rest","1");
    BOOST_CHECK(!ValidateNativeDrivechainRpcServerConfig(args,&error));
    BOOST_CHECK(error.find("unauthenticated")!=std::string::npos);
    args.ForceSetArg("-rest","0");
    for (const auto port : {"1","65535"}) {
        args.ForceSetArg("-rpcport",port);
        BOOST_CHECK_MESSAGE(ValidateNativeDrivechainRpcServerConfig(args,&error),error);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_tls_metadata_preserves_rejection_and_close_order)
{
    for (bool key : {false,true}) {
        for (uint32_t corrupt : {0U,1U,3U,5U,7U,16U,17U,19U,9U,20U,11U,21U,22U,24U,25U,26U,28U}) {
            std::vector<uint32_t> seen;
            const auto accepted=drivechain::haskell::AdmitTlsCredentialFile(key,[&](uint32_t step) -> uint64_t {
                seen.push_back(step);
                switch (step) {
                case 1: case 3: case 7: case 16: case 11: case 21: return corrupt==step ? 0 : 1;
                case 5: case 15: case 17: case 18: case 22: case 23: return corrupt==step ? 42 : 41;
                case 9: case 19: case 20: case 24: case 25: return corrupt==step ? 1 : 0;
                case 26: case 27: case 28: case 29: return corrupt==step ? 0 : UINT64_MAX-3;
                default: return 1;
                }
            });
            const bool unused=key ? corrupt==20 || corrupt==25 : corrupt==9 || corrupt==24;
            BOOST_CHECK_EQUAL(accepted,corrupt==0 || unused);
            const bool attempted=std::find(seen.begin(),seen.end(),11)!=seen.end();
            BOOST_CHECK_EQUAL(std::count(seen.begin(),seen.end(),30),attempted ? 1 : 0);
            if (attempted && !accepted) {
                BOOST_REQUIRE_GE(seen.size(),2U);
                BOOST_CHECK_EQUAL(seen[seen.size()-2],30);
                BOOST_CHECK_EQUAL(seen.back(),12);
            }
        }
    }
    BOOST_CHECK_THROW(drivechain::haskell::AdmitTlsCredentialFile(true,[](uint32_t) -> uint64_t {
        throw std::logic_error("TLS metadata callback fault");
    }),std::logic_error);
}

BOOST_AUTO_TEST_CASE(drivechain_private_credential_admission_preserves_metadata_order)
{
    for (bool regular : {false,true}) for (int64_t owner : {0LL,1LL,4294967295LL})
    for (int64_t user : {0LL,1LL,4294967295LL}) for (int64_t permissions : {0LL,1LL,63LL}) {
        std::vector<uint32_t> expected{1},seen;
        if (!regular) expected.push_back(2);
        else {
            expected.insert(expected.end(),{3,4});
            if (owner!=user) expected.push_back(5);
            else {
                expected.push_back(6);
                if (permissions!=0) expected.push_back(7);
            }
        }
        const bool accepted=drivechain::haskell::AdmitPrivateCredentialFile([&](uint32_t step) -> int64_t {
            seen.push_back(step);
            switch (step) {
            case 1: return regular;
            case 3: return owner;
            case 4: return user;
            case 6: return permissions;
            default: return 1;
            }
        });
        BOOST_CHECK_EQUAL(accepted,regular && owner==user && permissions==0);
        BOOST_CHECK(seen==expected);
    }
    BOOST_CHECK_THROW(drivechain::haskell::AdmitPrivateCredentialFile([](uint32_t) -> int64_t {
        throw std::logic_error("metadata callback fault");
    }),std::logic_error);
}

BOOST_AUTO_TEST_CASE(drivechain_credential_read_preserves_short_reads_and_retries)
{
    for (const std::vector<uint64_t>& replies : {
            std::vector<uint64_t>{0},{1,2,3,0},{UINT64_MAX,1,UINT64_MAX,0},
            {1,UINT64_MAX-1},{4096,0},{4096,1},{4097},{UINT64_MAX-1},
            std::vector<uint64_t>(4097,1),std::vector<uint64_t>(1000,UINT64_MAX)}) {
        using Trace=std::vector<std::pair<uint64_t,uint64_t>>;
        Trace expected,observed;
        uint64_t wanted_used=0;
        uint32_t wanted=0;
        size_t i=0;
        while (wanted_used<4097) {
            expected.emplace_back(wanted_used,4097-wanted_used);
            const uint64_t count=i<replies.size() ? replies[i++] : 0;
            if (count==UINT64_MAX) continue;
            if (count==UINT64_MAX-1) { wanted=1; break; }
            if (count==0) break;
            wanted_used+=count;
        }
        if (wanted_used==4097) wanted=2;
        i=0;
        uint64_t used=17;
        const auto code=drivechain::haskell::ReadCredentialBytes(4097,[&](uint64_t offset,uint64_t available) {
            observed.emplace_back(offset,available);
            return i<replies.size() ? replies[i++] : 0;
        },used);
        BOOST_CHECK_EQUAL(code,wanted);
        BOOST_CHECK_EQUAL(used,wanted_used);
        BOOST_CHECK(observed==expected);
    }
    uint64_t unchanged=17;
    BOOST_CHECK_THROW(drivechain::haskell::ReadCredentialBytes(4097,[](uint64_t,uint64_t) -> uint64_t {
        throw std::logic_error("read callback fault");
    },unchanged),std::logic_error);
    BOOST_CHECK_EQUAL(unchanged,17);
}

BOOST_AUTO_TEST_CASE(drivechain_credential_records_preserve_native_predicates)
{
    auto check=[](const std::string& record) {
        const bool cookie=record.rfind("__cookie__:",0)==0 && record.size()==75 && IsHex(record.substr(11));
        const auto separator=record.find(':');
        const bool credentials=record.size()<=1024 && separator!=std::string::npos && separator!=0 &&
            separator+1!=record.size() && record.find(':',separator+1)==std::string::npos &&
            record.compare(0,separator,"__cookie__")!=0 &&
            std::all_of(record.begin(),record.end(),[](unsigned char c) { return c>=33 && c<=126; });
        BOOST_CHECK_EQUAL(drivechain::haskell::IsRpcCredentialRecord(record,true),cookie);
        BOOST_CHECK_EQUAL(drivechain::haskell::IsRpcCredentialRecord(record,false),credentials);
    };
    for (unsigned byte=0; byte<256; ++byte) {
        check("__cookie__:"+std::string(64,static_cast<char>(byte)));
        for (size_t size : {0U,1U,63U,64U,65U,1022U,1023U})
            check("u:"+std::string(size,static_cast<char>(byte)));
    }
    for (const std::string& record : {"",":","u:",":p","u::p","__cookie__:p","u:p\n","u:p\r","u:p"}) check(record);
}

BOOST_AUTO_TEST_CASE(drivechain_parent_cookie_is_atomic_private_and_canonical)
{
    const fs::path directory = m_path_root / "drivechain-parent-cookie";
    fs::create_directories(directory);
    const fs::path cookie_path = directory / ".cookie";
    const std::string expected = "__cookie__:" + std::string(64, 'a');
    {
        std::ofstream output(cookie_path, std::ios::binary);
        output << expected << '\n';
        BOOST_REQUIRE(output.good());
    }
#ifndef WIN32
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(cookie_path).c_str(), 0600), 0);
#endif

    std::string cookie;
    std::string error;
    BOOST_CHECK(ReadNativeDrivechainCookieFile(cookie_path, cookie, &error));
    BOOST_CHECK_EQUAL(cookie, expected);
    BOOST_CHECK(error.empty());

    {
        std::ofstream output(cookie_path, std::ios::binary | std::ios::trunc);
        output << "static-user:static-password\n";
        BOOST_REQUIRE(output.good());
    }
    BOOST_CHECK(!ReadNativeDrivechainCookieFile(cookie_path, cookie, &error));
    BOOST_CHECK(error.find("canonical rotating") != std::string::npos);

#ifndef WIN32
    {
        std::ofstream output(cookie_path, std::ios::binary | std::ios::trunc);
        output << expected << '\n';
        BOOST_REQUIRE(output.good());
    }
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(cookie_path).c_str(), 0644), 0);
    BOOST_CHECK(!ReadNativeDrivechainCookieFile(cookie_path, cookie, &error));
    BOOST_CHECK(error.find("deny all group and other access") != std::string::npos);
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(cookie_path).c_str(), 0600), 0);

    const fs::path cookie_link = directory / "linked-cookie";
    fs::create_symlink(cookie_path, cookie_link);
    BOOST_CHECK(!ReadNativeDrivechainCookieFile(cookie_link, cookie, &error));
    BOOST_CHECK(error.find("securely open") != std::string::npos);
#endif
}

BOOST_AUTO_TEST_CASE(drivechain_parent_static_credentials_are_private_and_explicit)
{
    const fs::path directory = m_path_root / "drivechain-parent-static-auth";
    fs::create_directories(directory);
    const fs::path path = directory / "credentials";
    std::string credentials{"stale credentials"};
    std::string error{"stale error"};
#ifdef WIN32
    // Do not promise POSIX ownership/mode guarantees on a platform without
    // them. The native rotating-cookie path remains a distinct interface.
    BOOST_CHECK(!ReadMainchainRpcCredentialFile(path, credentials, &error));
    BOOST_CHECK(credentials.empty());
    BOOST_CHECK(error.find("POSIX") != std::string::npos);
#else
    const auto write_credentials = [&](const std::string& contents) {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        output << contents;
        BOOST_REQUIRE(output.good());
        output.close();
        BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(path).c_str(), 0600), 0);
    };

    for (size_t size : {0U,1U,4095U,4096U,4097U,8192U}) {
        const std::string contents(size,'a');
        write_credentials(contents);
        BOOST_CHECK_EQUAL(ReadPrivateRpcAuthFile(path,credentials,&error),size<=4096);
        BOOST_CHECK_EQUAL(credentials,size<=4096 ? contents : std::string{});
        BOOST_CHECK_EQUAL(error,size<=4096 ? std::string{} : "mainchain RPC cookie file is unexpectedly large");
    }
    for (const std::string& contents : {"","\n","\r","\r\n","\n\r","\n\n","\r\r","a\r\n","a\n\r"}) {
        std::string expected=contents;
        if (!expected.empty() && expected.back()=='\n') expected.pop_back();
        if (!expected.empty() && expected.back()=='\r') expected.pop_back();
        write_credentials(contents);
        BOOST_REQUIRE(ReadPrivateRpcAuthFile(path,credentials,&error));
        BOOST_CHECK_EQUAL(credentials,expected);
        BOOST_CHECK(error.empty());
    }

    for (const std::string& suffix : {"", "\n", "\r\n"}) {
        write_credentials("bridge-user:bridge-password" + suffix);
        BOOST_REQUIRE(ReadMainchainRpcCredentialFile(path, credentials, &error));
        BOOST_CHECK_EQUAL(credentials, "bridge-user:bridge-password");
        BOOST_CHECK(error.empty());
        BOOST_CHECK(!ReadNativeDrivechainCookieFile(path, credentials, &error));
        BOOST_CHECK(credentials.empty());
        BOOST_CHECK(error.find("canonical rotating") != std::string::npos);
    }

    const std::vector<std::string> invalid{
        "", "user", ":password", "user:", "user:one:two",
        "user:pass word", "user:pass\tword", "user:pass\nword",
        "user:pass\n\n", std::string("user:pass\0word", 14),
        "__cookie__:" + std::string(64, 'a'),
        "user:" + std::string(1020, 'a'), std::string(4097, 'a'),
    };
    for (const std::string& contents : invalid) {
        write_credentials(contents);
        credentials = "stale credentials";
        BOOST_CHECK(!ReadMainchainRpcCredentialFile(path, credentials, &error));
        BOOST_CHECK(credentials.empty());
        BOOST_CHECK(!error.empty());
    }

    write_credentials("bridge-user:bridge-password");
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(path).c_str(), 0640), 0);
    BOOST_CHECK(!ReadMainchainRpcCredentialFile(path, credentials, &error));
    BOOST_CHECK(credentials.empty());
    BOOST_CHECK(error.find("deny all group and other access") != std::string::npos);
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(path).c_str(), 0600), 0);

    const fs::path link = directory / "linked-credentials";
    fs::create_symlink(path, link);
    BOOST_CHECK(!ReadMainchainRpcCredentialFile(link, credentials, &error));
    BOOST_CHECK(credentials.empty());
    BOOST_CHECK(error.find("securely open") != std::string::npos);

    const fs::path fifo = directory / "credential-fifo";
    BOOST_REQUIRE_EQUAL(mkfifo(fs::PathToString(fifo).c_str(), 0600), 0);
    BOOST_CHECK(!ReadMainchainRpcCredentialFile(fifo, credentials, &error));
    BOOST_CHECK(credentials.empty());
    BOOST_CHECK(error.find("regular file") != std::string::npos);

    BOOST_CHECK(!ReadMainchainRpcCredentialFile("relative-file", credentials, &error));
    BOOST_CHECK(credentials.empty());
    BOOST_CHECK(error.find("absolute") != std::string::npos);
#endif
}

BOOST_AUTO_TEST_CASE(drivechain_grpc_text_preserves_native_predicates)
{
    const auto clean=[](const std::string& text) {
        return std::none_of(text.begin(),text.end(),[](unsigned char c) { return c<=0x20 || c==0x7f; });
    };
    for (unsigned byte=0; byte<256; ++byte) {
        for (size_t size : {0U,1U,511U,512U,513U,1024U}) {
            for (bool scheme : {false,true}) {
                std::string address(size,static_cast<char>(byte));
                if (scheme) address+="://";
                const std::string authority(size,static_cast<char>(byte));
                const auto result=drivechain::haskell::AdmitGrpcText(address,authority);
                BOOST_CHECK_EQUAL(result.address_shape,!address.empty() && address.find("://")==std::string::npos);
                BOOST_CHECK_EQUAL(result.address_characters,address.size()<=512 && clean(address));
                BOOST_CHECK_EQUAL(result.authority_characters,clean(authority));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(drivechain_grpc_requires_authenticated_tls)
{
    BOOST_CHECK_EQUAL(drivechain::GRPC_CA_FILE,"enforcer-tls/ca.pem");
    BOOST_CHECK_EQUAL(drivechain::GRPC_CLIENT_CERT_FILE,"enforcer-tls/elements-client.pem");
    BOOST_CHECK_EQUAL(drivechain::GRPC_CLIENT_KEY_FILE,"enforcer-tls/elements-client-key.pem");
    const fs::path credentials = m_path_root / "drivechain-grpc-tls";
    fs::create_directories(credentials);
    const fs::path ca = credentials / "ca.pem";
    const fs::path certificate = credentials / "elements-client.pem";
    const fs::path key = credentials / "elements-client-key.pem";
    for (const fs::path& path : {ca, certificate, key}) {
        std::ofstream output(fs::PathToString(path));
        output << "test credential\n";
        BOOST_REQUIRE(output.good());
    }

#ifndef WIN32
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(ca).c_str(), 0644), 0);
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(certificate).c_str(), 0644), 0);
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(key).c_str(), 0600), 0);
#endif

    ArgsManager args;
    args.ForceSetArg("-drivechainbmmgrpcaddr", "127.0.0.1:55051");
    args.ForceSetArg("-drivechainbmmgrpcca", fs::PathToString(ca));
    args.ForceSetArg("-drivechainbmmgrpccert", fs::PathToString(certificate));
    args.ForceSetArg("-drivechainbmmgrpckey", fs::PathToString(key));

    std::string error;
    BOOST_CHECK(ValidateDrivechainGrpcTLSConfig(args, &error));
    BOOST_CHECK(error.empty());

    args.ForceSetArg("-drivechainbmmgrpcauthority", "bad\nauthority");
    args.ForceSetArg("-drivechainbmmgrpcaddr",std::string(513,'x')+"://");
    BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args,&error));
    BOOST_CHECK(error.find("without a URL scheme")!=std::string::npos);
    args.ForceSetArg("-drivechainbmmgrpcaddr",std::string(513,'x'));
    BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args,&error));
    BOOST_CHECK(error.find("excessive data")!=std::string::npos);
    args.ForceSetArg("-drivechainbmmgrpcauthority", "");

    args.ForceSetArg("-drivechainbmmgrpcaddr", "http://127.0.0.1:55051");
    BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args, &error));
    BOOST_CHECK(error.find("without a URL scheme") != std::string::npos);
    args.ForceSetArg("-drivechainbmmgrpcaddr", "127.0.0.1:55051");

    for (const std::string& address : {"192.168.1.2:55051", "localhost:55051", "[::]:55051", "rpc.example:55051"}) {
        args.ForceSetArg("-drivechainbmmgrpcaddr", address);
        BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args, &error));
    }
    args.ForceSetArg("-drivechainbmmgrpcaddr", "[::1]:55051");
    BOOST_CHECK(ValidateDrivechainGrpcTLSConfig(args, &error));
    for (const std::string& address : {":55051", "-host:55051", "127.0.0.1:0"}) {
        args.ForceSetArg("-drivechainbmmgrpcaddr",address);
        BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args,&error));
        BOOST_CHECK(error.find("non-empty host and nonzero port")!=std::string::npos);
    }
    args.ForceSetArg("-drivechainbmmgrpcaddr", "127.0.0.1:55051");
    args.ForceSetArg("-drivechainpegoutenforcer", "127.0.0.1:30301");
    args.ForceSetArg("-drivechainbmmwalletaddr", "127.0.0.1:30302");
    BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args,&error));
    BOOST_CHECK(error.find("-drivechainpegoutenforcer and")!=std::string::npos);
    args.ForceSetArg("-drivechainpegoutenforcer", "127.0.0.1:55051");
    BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args,&error));
    BOOST_CHECK(error.find("-drivechainbmmwalletaddr and")!=std::string::npos);
    args.ForceSetArg("-drivechainbmmwalletaddr", "127.0.0.1:30301");
    BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args, &error));
    args.ForceSetArg("-drivechainbmmwalletaddr", "127.0.0.1:55051");
    BOOST_CHECK(ValidateDrivechainGrpcTLSConfig(args, &error));

    args.ForceSetArg("-drivechainbmmgrpcauthority", "enforcer.local\nplaintext");
    BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args, &error));
    BOOST_CHECK(error.find("control characters") != std::string::npos);
    args.ForceSetArg("-drivechainbmmgrpcauthority", "enforcer.local");

    args.ForceSetArg("-drivechainbmmgrpcca",
                     fs::PathToString(credentials / "missing-ca.pem"));
    BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args, &error));
    BOOST_CHECK(error.find("non-symlink regular file") != std::string::npos);
    args.ForceSetArg("-drivechainbmmgrpcca", fs::PathToString(ca));

#ifndef WIN32
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(credentials).c_str(), 0770), 0);
    BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args, &error));
    BOOST_CHECK(error.find("credential directory") != std::string::npos);
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(credentials).c_str(), 0700), 0);

    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(key).c_str(), 0644), 0);
    BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args, &error));
    BOOST_CHECK(error.find("deny all group and other access") != std::string::npos);
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(key).c_str(), 0600), 0);

    const fs::path key_link = credentials / "linked-key.pem";
    fs::create_symlink(key, key_link);
    args.ForceSetArg("-drivechainbmmgrpckey", fs::PathToString(key_link));
    BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args, &error));
    BOOST_CHECK(error.find("non-symlink") != std::string::npos);
    args.ForceSetArg("-drivechainbmmgrpckey", fs::PathToString(key));

    // File admission does not imply a valid TLS certificate. The linked client
    // must reject these deliberately non-PEM fixtures, never fall back to plaintext.
    const auto invocation = RunAuthenticatedDrivechainGrpc(args,
        "cusf.mainchain.v1.ValidatorService/GetChainInfo", "{}",
        std::chrono::milliseconds{100}, 4096);
    BOOST_CHECK(invocation.started);
    BOOST_CHECK(invocation.exited);
    BOOST_CHECK(invocation.exit_code != 0);
    // C-core can report TLS rejection as a positive gRPC status with its
    // diagnostic in output, rather than as a negative local error in error.
    // Exercise the caller's classifier, including its duplicate-accepting mode.
    for (const bool accept_duplicate : {false, true}) {
        std::string diagnostic;
        const auto status = ClassifyDrivechainGrpcResult(invocation, accept_duplicate, diagnostic);
        BOOST_CHECK(status != DrivechainGrpcStatus::SUCCESS);
        BOOST_CHECK(!diagnostic.empty());
        if (invocation.exit_code > 0) {
            BOOST_CHECK(status == DrivechainGrpcStatus::NONZERO_EXIT);
            BOOST_REQUIRE(!invocation.output.empty());
            BOOST_CHECK(diagnostic.find(invocation.output) != std::string::npos);
        } else {
            BOOST_CHECK(!invocation.error.empty() || invocation.timed_out);
        }
    }
    const auto cancelled = RunAuthenticatedDrivechainGrpc(args,
        "cusf.mainchain.v1.ValidatorService/GetChainInfo", "{}",
        std::chrono::seconds{1}, 4096, [] { return true; });
    BOOST_CHECK(cancelled.cancelled);
#endif

    const BoundedCommandResult unknown_method = RunAuthenticatedDrivechainGrpc(
        args, "grpc.health.v1.Health/Check", "{}",
        std::chrono::seconds{1}, 1024);
    BOOST_CHECK(!unknown_method.started);
    BOOST_CHECK(unknown_method.error.find("unrecognized") != std::string::npos);

    const BoundedCommandResult non_object_payload = RunAuthenticatedDrivechainGrpc(
        args,
        "cusf.mainchain.v1.WalletService/BroadcastWithdrawalBundle",
        "[]", std::chrono::seconds{1}, 1024);
    BOOST_CHECK(!non_object_payload.started);
    BOOST_CHECK(non_object_payload.error.find("JSON object") != std::string::npos);
    args.ForceSetArg("-drivechainbmmconnectauthcookie", "obsolete-cookie");
    BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args, &error));
}

BOOST_AUTO_TEST_CASE(drivechain_reward_script_requires_wallet_owned_key_address)
{
    const CPubKey pubkey(ParseHex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"));
    const std::vector<CTxDestination> destinations{
        PKHash(pubkey), WitnessV0KeyHash(pubkey)};
    for (const auto& destination : destinations) {
        const std::string address = EncodeDestination(destination);
        CScript reward_script(OP_TRUE);
        std::string error{"stale error"};
        unsigned int ownership_checks{0};
        BOOST_REQUIRE(BuildDrivechainRewardScript(
            address,
            [&](const CTxDestination& decoded) {
                ++ownership_checks;
                return decoded == destination;
            },
            reward_script, &error));
        BOOST_CHECK(error.empty());
        BOOST_CHECK_EQUAL(ownership_checks, 1U);
        BOOST_CHECK(reward_script == GetScriptForDestination(destination));
        BOOST_CHECK(reward_script != CScript(OP_TRUE));

        // A valid address alone is not permission to pay a bid. Failure must
        // erase any previous script, including the old OP_TRUE fallback.
        BOOST_CHECK(!BuildDrivechainRewardScript(
            address, [](const CTxDestination&) { return false; },
            reward_script, &error));
        BOOST_CHECK(reward_script.empty());
        BOOST_CHECK(!error.empty());
        reward_script = CScript(OP_TRUE);
        BOOST_CHECK(!BuildDrivechainRewardScript(address, {}, reward_script));
        BOOST_CHECK(reward_script.empty());
        reward_script = CScript(OP_TRUE);
        BOOST_CHECK_EXCEPTION(BuildDrivechainRewardScript(address,
            [](const CTxDestination&) -> bool { throw std::runtime_error("reward ownership failure"); },
            reward_script,&error),std::runtime_error,
            [](const std::runtime_error& failure) { return std::string(failure.what()) == "reward ownership failure"; });
        BOOST_CHECK(reward_script.empty());
        BOOST_CHECK(error.empty());
    }
}

BOOST_AUTO_TEST_CASE(drivechain_reward_script_rejects_unsafe_destinations)
{
    const CPubKey pubkey(ParseHex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"));
    WitnessV0KeyHash confidential(pubkey);
    confidential.blinding_pubkey = pubkey;
    std::vector<unsigned char> future_program(32, 0);
    future_program[0] = 1;
    const WitnessUnknown future{2, future_program};
    const CScript anyone_can_spend = CScript() << OP_TRUE;
    const std::vector<std::string> rejected{
        "", "not-an-address", "51", "null",
        // A testnet address is not valid on this fixture's mainnet network.
        "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",
        EncodeDestination(ScriptHash(anyone_can_spend)),
        EncodeDestination(WitnessV0ScriptHash(anyone_can_spend)),
        EncodeDestination(WitnessV1Taproot(XOnlyPubKey(pubkey))),
        EncodeDestination(future),
        EncodeDestination(confidential),
    };
    for (const auto& address : rejected) {
        CScript reward_script(OP_TRUE);
        std::string error;
        bool ownership_checked{false};
        BOOST_CHECK(!BuildDrivechainRewardScript(
            address,
            [&](const CTxDestination&) {
                ownership_checked = true;
                return true;
            },
            reward_script, &error));
        BOOST_CHECK(reward_script.empty());
        BOOST_CHECK(!error.empty());
        BOOST_CHECK(!ownership_checked);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_withdrawal_capability_requires_replay_or_explicit_flag)
{
    Consensus::Params params;
    BOOST_CHECK(!params.DrivechainWithdrawalValidationEnabled());

    params.drivechain_slot = uint8_t{24};
    BOOST_CHECK(!params.DrivechainWithdrawalValidationEnabled());

    // A version number alone does not establish complete M3/M4/M6 and CTIP
    // validation. Even the current replay version requires the explicit,
    // identity-checked capability; the older version-2 shortcut was unsafe.
    for (const uint32_t replay_version : {2U, ElementsDrivechainIdentity::PARENT_REPLAY_VERSION}) {
        params.drivechain_parent_state_replay_version = replay_version;
        BOOST_CHECK(!params.DrivechainWithdrawalValidationEnabled());
    }

    params.drivechain_parent_state_replay_version = 0;
    BOOST_CHECK(!params.DrivechainWithdrawalValidationEnabled());

    params.drivechain_m6_withdrawal_validation = true;
    BOOST_CHECK(params.DrivechainWithdrawalValidationEnabled());

    // A capability flag alone must never turn the BIP300 wallet path on for
    // an ordinary Elements network.
    params.drivechain_slot.reset();
    BOOST_CHECK(!params.DrivechainWithdrawalValidationEnabled());
}

BOOST_AUTO_TEST_SUITE_END()

struct AlphaParentInspectionSetup : BasicTestingSetup {
    AlphaParentInspectionSetup() : BasicTestingSetup(ChainTypeMetaFrom(CBaseChainParams::ELEMENTS)) {}
};

BOOST_FIXTURE_TEST_SUITE(alpha_parent_inspection, AlphaParentInspectionSetup)
BOOST_AUTO_TEST_CASE(withdrawal_lookup_clears_on_preflight_and_authentication_failure)
{
    // Both paths fail before network I/O; the wrong slot must win over auth.
    gArgs.ForceSetArg("-mainchainrpccredentialfile", "unused-test-credential-file");
    gArgs.ForceSetArg("-mainchainrpcuser", "test-only");
    for (int slot : {23,24}) for (bool with_error : {false,true}) {
        std::optional<DrivechainSuccessfulWithdrawal> result{std::in_place};
        std::string error{"stale error"};
        BOOST_CHECK(!GetDrivechainSuccessfulWithdrawal(slot, uint256::ONE, result,
            with_error ? &error : nullptr));
        BOOST_CHECK(!result.has_value());
        if (with_error) {
            BOOST_CHECK(error.find(slot == 23 ? "slot must match" : "authentication mechanism") != std::string::npos);
            BOOST_CHECK(error.find("stale error") == std::string::npos);
        } else {
            BOOST_CHECK_EQUAL(error, "stale error");
        }
    }
}

BOOST_AUTO_TEST_CASE(execution_anchor_clears_on_wrong_slot)
{
    DrivechainParentBlockContext anchor, bid;
    anchor.parent_hash = uint256::ONE;
    anchor.parent_height = 42;
    anchor.parent_median_time_past = 123;
    anchor.parent_chainwork = uint256::ONE;
    std::string error;
    BOOST_CHECK(!GetDrivechainExecutionAnchor(23, uint256::ONE, 0, bid, anchor, &error));
    BOOST_CHECK(!error.empty());
    BOOST_CHECK(anchor.parent_hash.IsNull());
    BOOST_CHECK(anchor.parent_chainwork.IsNull());
    BOOST_CHECK_EQUAL(anchor.parent_height, 0U);
    BOOST_CHECK_EQUAL(anchor.parent_median_time_past, 0U);
}

BOOST_AUTO_TEST_CASE(execution_anchor_clears_on_authentication_error)
{
    gArgs.ForceSetArg("-mainchainrpccredentialfile", "unused-test-credential-file");
    gArgs.ForceSetArg("-mainchainrpcuser", "test-only");
    DrivechainParentBlockContext anchor, bid;
    anchor.parent_hash = uint256::ONE;
    anchor.parent_height = 42;
    anchor.parent_median_time_past = 123;
    anchor.parent_chainwork = uint256::ONE;
    std::string error;
    BOOST_CHECK(!GetDrivechainExecutionAnchor(24, uint256::ONE, 0, bid, anchor, &error));
    BOOST_CHECK(!error.empty());
    BOOST_CHECK(anchor.parent_hash.IsNull());
    BOOST_CHECK(anchor.parent_chainwork.IsNull());
    BOOST_CHECK_EQUAL(anchor.parent_height, 0U);
    BOOST_CHECK_EQUAL(anchor.parent_median_time_past, 0U);
}

BOOST_AUTO_TEST_CASE(mempool_parent_context_clears_on_failure)
{
    DrivechainParentBlockContext context;
    context.parent_hash = uint256::ONE;
    context.parent_height = 42;
    context.parent_median_time_past = 123;
    context.parent_chainwork = uint256::ONE;
    std::string error;
    // Reject the wrong slot before attempting any parent RPC.
    BOOST_CHECK(!GetDrivechainMempoolParentContext(23, context, &error));
    BOOST_CHECK(!error.empty());
    BOOST_CHECK(context.parent_hash.IsNull());
    BOOST_CHECK(context.parent_chainwork.IsNull());
    BOOST_CHECK_EQUAL(context.parent_height, 0U);
    BOOST_CHECK_EQUAL(context.parent_median_time_past, 0U);
}

BOOST_AUTO_TEST_CASE(mempool_parent_context_clears_on_authentication_error)
{
    // Conflicting authentication sources are rejected before network I/O.
    gArgs.ForceSetArg("-mainchainrpccredentialfile", "unused-test-credential-file");
    gArgs.ForceSetArg("-mainchainrpcuser", "test-only");
    DrivechainParentBlockContext context;
    context.parent_hash = uint256::ONE;
    context.parent_height = 42;
    context.parent_median_time_past = 123;
    context.parent_chainwork = uint256::ONE;
    std::string error;
    BOOST_CHECK(!GetDrivechainMempoolParentContext(24, context, &error));
    BOOST_CHECK(!error.empty());
    BOOST_CHECK(context.parent_hash.IsNull());
    BOOST_CHECK(context.parent_chainwork.IsNull());
    BOOST_CHECK_EQUAL(context.parent_height, 0U);
    BOOST_CHECK_EQUAL(context.parent_median_time_past, 0U);
}

BOOST_AUTO_TEST_SUITE_END()

struct ElementsTestingSetup : public TestingSetup {
    ElementsTestingSetup() : TestingSetup{ChainType::ELEMENTS} {}
};

namespace node {
// Test access to the real selection loop; no production authentication bypass.
struct NativePackageSelectionTestAccess {
    static std::vector<CTransactionRef> Select(Chainstate& chainstate,
        CTxMemPool& pool, const DrivechainParentBlockContext& parent)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) LOCKS_EXCLUDED(pool.cs)
    {
        BlockAssembler::Options options;
        options.blockMinFeeRate = CFeeRate(0);
        BlockAssembler assembler(chainstate, &pool, options);
        assembler.resetBlock();
        assembler.pblocktemplate = std::make_unique<CBlockTemplate>();
        assembler.nHeight = chainstate.m_chain.Tip()->nHeight + 1;
        assembler.m_lock_time_cutoff = chainstate.m_chain.Tip()->GetMedianTimePast();
        assembler.m_candidate_parent = parent;
        int packages{0}, descendants{0};
        assembler.addPackageTxs(packages, descendants);
        return assembler.pblocktemplate->block.vtx;
    }
};
}

BOOST_FIXTURE_TEST_SUITE(elements_startup_validation_tests, ElementsTestingSetup)

BOOST_AUTO_TEST_CASE(signed_producer_preparation_skips_nonce_search)
{
    BOOST_REQUIRE(g_signed_blocks);
    auto& chainman = *m_node.chainman;
    const CScript matching = GetScriptForDestination(WitnessV0ScriptHash(CScript(OP_TRUE)));
    BOOST_REQUIRE(m_interrupt());
    for (const CScript& script : {CScript(),CScript(OP_FALSE),matching}) {
        CBlock block;
        block.hashPrevBlock = WITH_LOCK(cs_main, return chainman.ActiveChain().Tip()->GetBlockHash());
        block.nNonce = 25;
        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        block.vtx.push_back(MakeTransactionRef(coinbase));
        block.m_dynafed_params.m_current.m_signblockscript = script;
        BOOST_CHECK_EQUAL(PrepareDrivechainBlock(chainman,block),script.empty() || script == matching);
        BOOST_CHECK_EQUAL(block.nNonce,25U);
        BOOST_CHECK(block.hashMerkleRoot == BlockMerkleRoot(block));
        const std::vector<std::vector<unsigned char>> witness = script == matching ?
            std::vector<std::vector<unsigned char>>{{OP_TRUE}} : std::vector<std::vector<unsigned char>>{};
        BOOST_CHECK(block.m_signblock_witness.stack == witness);
    }
    BOOST_REQUIRE(m_interrupt.reset());
}

BOOST_AUTO_TEST_CASE(configured_slot_rejects_before_hash)
{
    BOOST_REQUIRE(Params().GetConsensus().drivechain_slot);
    const int slot = *Params().GetConsensus().drivechain_slot;
    for (int requested : {-1, (slot+1)%256, 256}) {
        std::string error;
        BOOST_CHECK(!IsDrivechainBmmCommitmentMined(uint256{}, uint256{}, requested, &error));
        BOOST_CHECK_EQUAL(error,"drivechain sidechain slot must match configured slot " +
            std::to_string(slot) + ", got " + std::to_string(requested));
        BOOST_CHECK(!IsDrivechainBmmCommitmentMined(uint256{}, uint256{}, requested));
    }
    std::string error;
    BOOST_CHECK(!IsDrivechainBmmCommitmentMined(uint256{}, uint256{}, slot, &error));
    BOOST_CHECK_EQUAL(error,"BIP301 expected critical hash is null");
}

BOOST_AUTO_TEST_CASE(native_startup_parameter_precedence)
{
    BOOST_REQUIRE(Params().GetConsensus().drivechain_slot);
    const auto wrong_slot=std::to_string(*Params().GetConsensus().drivechain_slot+1);
    CheckStartupRejected({{"-rest","1"},{"-mainchainrpcuser","unused"},{"-drivechainbmmslot",wrong_slot}},
        "unauthenticated REST is not permitted on a native drivechain node");
    CheckStartupRejected({{"-rpcport","0"},{"-mainchainrpcpassword","unused"}},
        "-rpcport must be between 1 and 65535");
    for (const auto* key : {"-mainchainrpcuser","-mainchainrpcpassword"}) {
        CheckStartupRejected({{key,"unused"},{"-drivechainbmmslot",wrong_slot}},
            "Native parent RPC credentials must be supplied through a private cookie or explicit credential file, not command-line/config credentials");
    }
    CheckStartupRejected({{"-drivechainbmmslot",wrong_slot},{"-drivechainbmmbid","invalid"}},
        "-drivechainbmmslot is immutable for this chain and must be "+std::to_string(*Params().GetConsensus().drivechain_slot));
    CheckStartupRejected({{"-drivechainbmmbid","invalid"},{"-drivechainbmmreplacementextra","invalid"}},
        "Invalid -drivechainbmmbid: BMM bid must be a canonical base-10 integer");
    CheckStartupRejected({{"-drivechainbmmbid","0"},{"-drivechainbmmreplacementextra","invalid"}},
        "Invalid -drivechainbmmbid: configured BMM bid must be positive and within the money range");
    for (const auto& value : {std::string{"invalid"},std::string{"-1"},std::to_string(MAX_MONEY+1)}) {
        CheckStartupRejected({{"-drivechainbmmreplacementextra",value},{"-mainchainrpchost","localhost"}},
            "Invalid -drivechainbmmreplacementextra: expected nonnegative satoshis within money range");
    }
    CheckStartupRejected({{"-mainchainrpccredentialfile","missing-file"},{"-mainchainrpccookiefile","missing-cookie"}},
        "-mainchainrpccredentialfile is mutually exclusive with cookie and inline credential options","2");
}

BOOST_AUTO_TEST_CASE(native_startup_timeout_publication)
{
    BOOST_REQUIRE(Params().GetConsensus().drivechain_slot);
    const std::string host_error="-mainchainrpchost must be an IPv4 127/8 or IPv6 ::1 loopback address on a native drivechain network";
    const std::string timeout_error="-mainchainrpctimeout must be between 1 and 2 seconds on a native drivechain network";
    CheckStartupRejected({{"-mainchainrpchost","localhost"},{"-mainchainrpccredentialfile","missing-file"}},host_error,"2");
    for (int64_t value : {int64_t{-1},int64_t{0},int64_t{1},int64_t{2},int64_t{3},int64_t{2147483647},
        int64_t{4294967297},int64_t{4294967298},std::numeric_limits<int64_t>::max()}) {
        const int narrowed=static_cast<int>(value);
        const bool valid=narrowed>=1 && narrowed<=2;
        CheckStartupRejected({{"-mainchainrpctimeout",std::to_string(value)},{"-mainchainrpchost","localhost"},
            {"-mainchainrpccredentialfile","missing-file"}},valid ? host_error : timeout_error,
            std::to_string(valid ? narrowed : value));
    }
    const auto missing=fs::PathToString(m_path_root / "missing-blocks");
    CheckStartupRejected({{"-blocksdir",missing}},"Specified blocks directory \""+missing+"\" does not exist.","2");
}

BOOST_AUTO_TEST_CASE(native_candidate_script_precheck)
{
    LOCK(cs_main);
    LOCK(m_node.mempool->cs);
    auto& chainstate = m_node.chainman->ActiveChainstate();
    const COutPoint outpoint(Txid::FromUint256(uint256::ONE), 0);
    chainstate.CoinsTip().AddCoin(outpoint,
        Coin(CTxOut(policyAsset, 1000, CScript() << OP_TRUE), 0, false), false);
    CMutableTransaction spend;
    spend.vin.emplace_back(outpoint);
    spend.vout.emplace_back(policyAsset, 900, CScript() << OP_TRUE);
    CBlockHeader header;
    DrivechainParentBlockContext parent;
    parent.parent_hash = uint256::ONE;
    parent.parent_height = 1;
    parent.parent_median_time_past = 100;
    const auto check = [&](const CMutableTransaction& tx) EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_node.mempool->cs) {
        return CheckNativeCandidateTransactionScripts(CTransaction(tx), chainstate,
            *m_node.mempool, header, parent);
    };
    BOOST_CHECK(check(spend));
    // Ordinary spends remain eligible when P advances, including cached checks.
    parent.parent_hash = uint256S("02");
    ++parent.parent_height;
    ++parent.parent_median_time_past;
    BOOST_CHECK(check(spend));
    parent.parent_hash.SetNull();
    BOOST_CHECK(!check(spend));
    parent.parent_hash = uint256::ONE;
    spend.vin[0].prevout.n = 1;
    BOOST_CHECK(!check(spend));
    spend.vin[0].prevout = outpoint;
    spend.vin[0].scriptSig = CScript() << OP_RETURN;
    BOOST_CHECK(!check(spend));
}

BOOST_AUTO_TEST_CASE(native_candidate_parent_bound_script_cache)
{
    LOCK(cs_main);
    auto& chainstate = m_node.chainman->ActiveChainstate();
    // Native default-catalogue assertion: current_bmm_parent_mtp_required() == 42.
    // The optional ECX height jet is deliberately not enabled by this test.
    const auto program = ParseHex("dc9f871a822cc00000000000000a8180559b7204601026a41c0a");
    const auto cmr = ParseHex("3a735cd0933df6e1f6bbdff57c5bf50a1220b9f3f80360e73b4900e8dd4aae0a");
    const CScript leaf(cmr.begin(), cmr.end());
    TaprootBuilder builder;
    builder.Add(0, leaf, TAPROOT_LEAF_TAPSIMPLICITY);
    builder.Finalize(XOnlyPubKey::NUMS_H);
    const auto data = builder.GetSpendData();
    BOOST_REQUIRE_EQUAL(data.scripts.size(), 1U);
    const auto& controls = data.scripts.begin()->second;
    BOOST_REQUIRE_EQUAL(controls.size(), 1U);
    const COutPoint outpoint(Txid::FromUint256(uint256::ONE), 0);
    chainstate.CoinsTip().AddCoin(outpoint,
        Coin(CTxOut(policyAsset, 1000, GetScriptForDestination(builder.GetOutput())), 0, false), false);
    CMutableTransaction spend;
    spend.vin.emplace_back(outpoint);
    spend.vout.emplace_back(policyAsset, 900, CScript() << OP_TRUE);
    spend.witness.vtxinwit.resize(1);
    spend.witness.vtxinwit[0].scriptWitness.stack = {{}, program, cmr, *controls.begin()};
    CBlockHeader header;
    DrivechainParentBlockContext parent;
    parent.parent_hash = uint256::ONE;
    parent.parent_height = 42;
    parent.parent_median_time_past = 42;
    const auto check = [&]() EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        LOCK(m_node.mempool->cs);
        return CheckNativeCandidateTransactionScripts(CTransaction(spend), chainstate,
            *m_node.mempool, header, parent);
    };
    BOOST_CHECK(check());
    parent.parent_median_time_past = 43;
    BOOST_CHECK(!check());
    parent.parent_median_time_past = 42;
    BOOST_CHECK(check());

    // A dependent transaction must resolve its input from the mempool view,
    // but that does not make its stale ancestor eligible for a package.
    WITH_LOCK(m_node.mempool->cs, AddToMempool(*m_node.mempool, TestMemPoolEntryHelper{}.Fee(100).FromTx(spend)));
    CMutableTransaction child;
    child.vin.emplace_back(CTransaction(spend).GetHash(), 0);
    child.vout.emplace_back(policyAsset, 800, CScript() << OP_TRUE);
    const auto check_child = [&]() EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        LOCK(m_node.mempool->cs);
        return CheckNativeCandidateTransactionScripts(CTransaction(child), chainstate,
            *m_node.mempool, header, parent);
    };
    BOOST_CHECK(check_child());
    parent.parent_median_time_past = 43;
    BOOST_CHECK(check_child());
    BOOST_CHECK(!check());
    BOOST_CHECK_EQUAL(WITH_LOCK(m_node.mempool->cs, return m_node.mempool->size()), 1U);
    parent.parent_median_time_past = 42;
    BOOST_CHECK(check());
    const COutPoint independent_input(Txid::FromUint256(uint256S("03")), 0);
    chainstate.CoinsTip().AddCoin(independent_input,
        Coin(CTxOut(policyAsset, 1000, CScript() << OP_TRUE), 0, false), false);
    CMutableTransaction independent;
    independent.vin.emplace_back(independent_input);
    independent.vout.emplace_back(policyAsset, 900, CScript() << OP_TRUE);
    {
        LOCK(m_node.mempool->cs);
        AddToMempool(*m_node.mempool, TestMemPoolEntryHelper{}.Fee(100).FromTx(child));
        AddToMempool(*m_node.mempool, TestMemPoolEntryHelper{}.Fee(100).FromTx(independent));
    }
    const auto select = [&]() EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        return node::NativePackageSelectionTestAccess::Select(chainstate, *m_node.mempool, parent);
    };
    parent.parent_median_time_past = 43;
    const auto stale = select();
    BOOST_REQUIRE_EQUAL(stale.size(), 1U);
    BOOST_CHECK(stale.front()->GetHash() == CTransaction(independent).GetHash());
    parent.parent_median_time_past = 42;
    const auto fresh = select();
    BOOST_REQUIRE_EQUAL(fresh.size(), 3U);
    auto parent_pos = std::find_if(fresh.begin(), fresh.end(), [&](const auto& tx) { return tx->GetHash() == CTransaction(spend).GetHash(); });
    auto child_pos = std::find_if(fresh.begin(), fresh.end(), [&](const auto& tx) { return tx->GetHash() == CTransaction(child).GetHash(); });
    BOOST_CHECK(parent_pos < child_pos);
    BOOST_CHECK_EQUAL(WITH_LOCK(m_node.mempool->cs, return m_node.mempool->size()), 3U);
}

BOOST_AUTO_TEST_CASE(activates_genesis_from_empty_chain)
{
    LOCK(cs_main);
    const CBlockIndex* tip = m_node.chainman->ActiveChain().Tip();
    BOOST_REQUIRE(tip != nullptr);
    BOOST_CHECK_EQUAL(tip->nHeight, 0);
    BOOST_CHECK_EQUAL(tip->GetBlockHash(), Params().HashGenesisBlock());
}

BOOST_AUTO_TEST_CASE(native_parent_replay_cannot_use_historical_signet_bmm)
{
    BOOST_REQUIRE(Params().GetConsensus().drivechain_slot.has_value());
    CBlockIndex previous;
    const uint256 historical = uint256S("ce77dfe3b037f2e62624da0ee5e33ae3c23b8b18ddf3b87a687bb372a8406998");
    previous.phashBlock = &historical;
    previous.nVersion = CBlockHeader::BMM_PROOF_HF_MASK;
    BOOST_CHECK(!drivechain::BmmProofRequiredAfter(&previous));
    CCoinsView base;
    CCoinsViewCache view(&base);
    drivechain::BmmL1State parent;
    std::string error;
    BOOST_CHECK(!drivechain::GetEffectiveBmmState(view, &previous, parent, error));
    CBlock block;
    block.nVersion = CBlockHeader::BMM_PROOF_HF_MASK;
    block.hashBmmProof = uint256::ONE;
    BOOST_CHECK(!drivechain::CheckBmmHeader(block, &previous, error, true));
    BOOST_CHECK(!drivechain::ConnectBmmState(block, &previous, view, 1, true, error));
    block.nVersion = 1;
    block.hashBmmProof.SetNull();
    BOOST_CHECK(drivechain::CheckBmmHeader(block, &previous, error, false));
    BOOST_CHECK(drivechain::ConnectBmmState(block, &previous, view, 1, false, error));
    block.m_bmm_proof = {1};
    BOOST_CHECK(!drivechain::ConnectBmmState(block, &previous, view, 1, false, error));
}

BOOST_AUTO_TEST_CASE(native_alpha_rejects_ecx_deposit_codecs_without_parent_rpc)
{
    BOOST_REQUIRE(Params().GetConsensus().drivechain_slot.has_value());
    Sidechain::Bitcoin::CMutableTransaction parent;
    parent.vin.emplace_back(Sidechain::Bitcoin::COutPoint(uint256::ONE, 0));
    parent.vout.emplace_back(2'000, CScript() << OP_TRUE);
    const COutPoint outpoint(Txid::FromUint256(parent.GetHash()), 0);
    DrivechainDepositEvidence evidence;
    VectorWriter writer(evidence.deposit_tx, 0);
    writer << TX_WITH_WITNESS(parent);
    const auto legacy = CreateDrivechainDepositPeginWitness(
        2'000, Params().GetConsensus().pegged_asset,
        Params().ParentGenesisBlockHash(), CScript() << OP_TRUE, outpoint.hash);
    const auto deterministic = CreateDrivechainDepositPeginWitness(
        2'000, Params().GetConsensus().pegged_asset,
        Params().ParentGenesisBlockHash(), CScript() << OP_TRUE, evidence);

    for (const CScriptWitness& witness : {legacy, deterministic}) {
        BOOST_REQUIRE(IsEcxDrivechainDepositPeginWitness(witness, outpoint));
        bool parent_unavailable{true};
        bool depth_failed{true};
        std::string error;
        // Matching asset and parent genesis do not authorize the foreign
        // codec on Alpha. It must fail before any mutable parent query.
        BOOST_CHECK(!IsValidPeginWitness(
            witness, {}, outpoint, error, true, &depth_failed, &parent_unavailable));
        BOOST_CHECK(error.find("not a native Alpha CTIP witness") != std::string::npos);
        BOOST_CHECK(!parent_unavailable);
        BOOST_CHECK(!depth_failed);
    }
}

BOOST_AUTO_TEST_SUITE_END()
