// Copyright (c) 2012-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparamsbase.h>
#include <chainparams.h>
#include <chain.h>
#include <rpc/client.h>
#include <rpc/request.h>
#include <rpc/register.h>
#include <rpc/server.h>
#include <rpc/util.h>

#include <core_io.h>
#include <drivechain_withdrawal.h>
#include <haskell/bridge.h>
#include <haskell/bmm_constants.h>
#include <interfaces/chain.h>
#include <key_io.h>
#include <pegins.h>
#include <node/context.h>
#include <rpc/blockchain.h>
#include <rpc/client.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/time.h>
#include <util/strencodings.h>
#include <usdd_withdrawal_accumulator.h>
#include <validation.h>

#include <any>
#include <algorithm>
#include <array>
#include <memory>
#include <ranges>
#include <utility>

#include <boost/test/unit_test.hpp>

using util::SplitString;

static UniValue JSON(std::string_view json)
{
    UniValue value;
    BOOST_CHECK(value.read(json));
    return value;
}

class HasJSON
{
public:
    explicit HasJSON(std::string json) : m_json(std::move(json)) {}
    bool operator()(const UniValue& value) const
    {
        std::string json{value.write()};
        BOOST_CHECK_EQUAL(json, m_json);
        return json == m_json;
    };

private:
    const std::string m_json;
};

class RPCTestingSetup : public TestingSetup
{
public:
    UniValue TransformParams(const UniValue& params, std::vector<std::pair<std::string, bool>> arg_names) const;
    UniValue CallRPC(std::string args);
};

UniValue RPCTestingSetup::TransformParams(const UniValue& params, std::vector<std::pair<std::string, bool>> arg_names) const
{
    UniValue transformed_params;
    CRPCTable table;
    CRPCCommand command{"category", "method", [&](const JSONRPCRequest& request, UniValue&, bool) -> bool { transformed_params = request.params; return true; }, arg_names, /*unique_id=*/0};
    table.appendCommand("method", &command);
    JSONRPCRequest request;
    request.strMethod = "method";
    request.params = params;
    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
    table.execute(request);
    return transformed_params;
}

UniValue RPCTestingSetup::CallRPC(std::string args)
{
    std::vector<std::string> vArgs{SplitString(args, ' ')};
    std::string strMethod = vArgs[0];
    vArgs.erase(vArgs.begin());
    JSONRPCRequest request;
    request.context = &m_node;
    request.strMethod = strMethod;
    request.params = RPCConvertValues(strMethod, vArgs);
    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
    try {
        UniValue result = tableRPC.execute(request);
        return result;
    }
    catch (const UniValue& objError) {
        throw std::runtime_error(objError.find_value("message").get_str());
    }
}


BOOST_FIXTURE_TEST_SUITE(rpc_tests, RPCTestingSetup)

BOOST_AUTO_TEST_CASE(drivechain_deposit_destination_rpc)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    struct Restore {
        Consensus::Params& consensus;
        std::optional<uint8_t> slot;
        ~Restore() { consensus.drivechain_slot = slot; }
    } restore{consensus, consensus.drivechain_slot};
    const auto address = EncodeDestination(WitnessV0KeyHash(uint160{ParseHex(std::string(40, '3'))}));
    consensus.drivechain_slot.reset();
    BOOST_CHECK_THROW(CallRPC("getdrivechaindepositdestination " + address), std::runtime_error);
    consensus.drivechain_slot = 24;
    const auto plain = CallRPC("getdrivechaindepositdestination " + address);
    BOOST_CHECK_EQUAL(plain["destination"].get_str(), address);
    BOOST_CHECK_EQUAL(plain["deposit_fee_sats"].getInt<int64_t>(), 0);
    const auto paid = CallRPC("getdrivechaindepositdestination " + address + " 1000");
    const auto payload = "dcfee1:1000:" + address;
    BOOST_CHECK_EQUAL(paid["destination"].get_str(), payload);
    BOOST_CHECK_EQUAL(paid["bitwindow_address"].get_str(), "s24_" + payload);
    BOOST_CHECK_EQUAL(paid["sidechain_slot"].getInt<unsigned>(), 24);
    BOOST_CHECK_EQUAL(paid["destination_hex"].get_str(), HexStr(std::vector<unsigned char>(payload.begin(), payload.end())));
    for (const auto& fee : {"-1", "1.5", "1e3", "\"1000\"", "2100000000000001", "9223372036854775808"})
        BOOST_CHECK_THROW(CallRPC("getdrivechaindepositdestination " + address + " " + fee), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("getdrivechaindepositdestination invalid 1000"), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(withdrawal_proof_error_precedence)
{
    for (unsigned flags = 0; flags < 16; ++flags) for (unsigned fault = 0; fault <= 7; ++fault) {
        std::vector<unsigned> expected, actual;
        const auto run = [&](bool haskell, std::vector<unsigned>& trace) -> std::string {
            const auto action = [&](uint32_t step) -> uint32_t {
                trace.push_back(step);
                if (step == fault) throw std::runtime_error("adapter failure");
                switch (step) {
                case 1: return flags & 1 ? 1 : 0;
                case 2: throw JSONRPCError(RPC_INTERNAL_ERROR, "count mismatch");
                case 3: return flags & 2 ? 1 : 0;
                case 4: return flags & 4 ? 1 : 0;
                case 5: return flags & 8 ? 1 : 0;
                case 6: throw JSONRPCError(RPC_INTERNAL_ERROR, "proof diagnostic");
                case 7: throw JSONRPCError(RPC_INTERNAL_ERROR, "root mismatch");
                default: throw std::logic_error("unexpected proof action");
                }
            };
            try {
                if (haskell) {
                    BOOST_CHECK_EQUAL(drivechain::haskell::ParentReplayStore(
                        drivechain::haskell::ReplayStoreFlow::RPC_WITHDRAWAL_PROOF,action),1U);
                } else {
                    if (!action(1)) action(2);
                    if (!(action(3) && action(4))) action(action(5) ? 6 : 7);
                }
                return "success";
            } catch (const UniValue& error) {
                BOOST_CHECK_EQUAL(error["code"].getInt<int>(),RPC_INTERNAL_ERROR);
                return error["message"].get_str();
            } catch (const std::runtime_error& error) {
                return error.what();
            }
        };
        const auto previous = run(false,expected);
        BOOST_CHECK_EQUAL(run(true,actual),previous);
        BOOST_CHECK(actual == expected);
    }
}

BOOST_AUTO_TEST_CASE(withdrawal_rpc_paid_gate)
{
    for (bool verifying : {false,true})
    for (bool paid : {false,true})
    for (bool submitted : {false,true}) {
        bool submission_called{false}, published{false};
        std::vector<uint32_t> trace;
        const auto run = [&] {
            const auto status = drivechain::haskell::ParentReplayStore(verifying ?
                drivechain::haskell::ReplayStoreFlow::WITHDRAWAL_RPC_VERIFY :
                drivechain::haskell::ReplayStoreFlow::REQUIRED_PAIR_ERRORS,
                [&](uint32_t step) -> uint32_t {
                trace.push_back(step);
                if (step == (verifying ? 16U : 1U)) return !paid;
                if (step == (verifying ? 18U : 2U))
                    throw JSONRPCError(RPC_VERIFY_ALREADY_IN_UTXO_SET,"already paid");
                if (!verifying && step == 3) { submission_called = true; return submitted; }
                if (!verifying && step == 4) throw JSONRPCError(RPC_MISC_ERROR,"submission failed");
                if (verifying && step == 17) published = true;
                return 1;
            });
            if (!verifying) published = true;
            return status;
        };
        if (paid || (!verifying && !submitted))
            BOOST_CHECK_EXCEPTION(run(),UniValue,[&](const UniValue& error) {
                return error["code"].getInt<int>() == (paid ? RPC_VERIFY_ALREADY_IN_UTXO_SET : RPC_MISC_ERROR) &&
                    error["message"].get_str() == (paid ? "already paid" : "submission failed");
            });
        else BOOST_CHECK_EQUAL(run(),1U);
        BOOST_CHECK_EQUAL(submission_called,!verifying && !paid);
        BOOST_CHECK_EQUAL(published,!paid && (verifying || submitted));
        std::vector<uint32_t> expected;
        if (verifying) expected = {1,3,5,7,9,11,12,13,14,16,paid ? 18U : 17U};
        else if (paid) expected = {1,2};
        else if (submitted) expected = {1,3};
        else expected = {1,3,4};
        BOOST_CHECK(trace == expected);
    }
}

BOOST_AUTO_TEST_CASE(checkpoint_evidence_tip_and_state_admission)
{
    JSONRPCRequest request;
    request.context=&m_node;
    request.strMethod="getalphacheckpointevidence";
    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
    auto* tip=WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip());
    const auto tip_hash=tip->GetBlockHash();
    auto saved=WITH_LOCK(cs_main, return std::exchange(tip->m_usdd_withdrawal_accumulator,{}));
    const auto restore=[&](CBlockIndex* index) { LOCK(cs_main); index->m_usdd_withdrawal_accumulator=std::move(saved); };
    const std::unique_ptr<CBlockIndex,decltype(restore)> restore_guard(tip,restore);
    for (const auto& hash : {uint256{},uint256::ONE,tip_hash}) {
        request.params=UniValue(UniValue::VARR);
        request.params.push_back(hash.GetHex());
        BOOST_CHECK_EXCEPTION(tableRPC.execute(request),UniValue,[&](const UniValue& error) {
            const bool matched=hash==tip_hash;
            return error["code"].getInt<int>()==(matched ? RPC_MISC_ERROR : RPC_INVALID_PARAMETER) &&
                error["message"].get_str()==(matched ? "Checkpoint withdrawal state unavailable or invalid" :
                    "Checkpoint tip changed or is unavailable");
        });
    }
}

BOOST_AUTO_TEST_CASE(checkpoint_evidence_resource_limits)
{
    static_assert(drivechain::CHECKPOINT_HEADER_LIMIT == 10000);
    static_assert(drivechain::CHECKPOINT_ENTRY_LIMIT == 100000);
    static_assert(drivechain::CHECKPOINT_BYTE_LIMIT == 64 * 1024 * 1024);
    static_assert(drivechain::PEG_EVENT_DEFAULT_COUNT == 1000);
    static_assert(drivechain::PEG_EVENT_COUNT_LIMIT == 10000);
    for (uint32_t limit : {10000U,100000U,64U*1024*1024}) {
        for (uint64_t used : {uint64_t{0},uint64_t{limit-1},uint64_t{limit},uint64_t{limit+1},UINT64_MAX})
        for (uint64_t added : {uint64_t{0},uint64_t{1},uint64_t{limit},UINT64_MAX}) {
            const bool exceeds = used > limit || added > uint64_t{limit} - used;
            BOOST_CHECK_EQUAL(drivechain::haskell::ParentReplayRecord(
                drivechain::haskell::ReplayRecordKind::LANE_EXCEEDED,limit,0,used,added),exceeds);
        }
    }
    JSONRPCRequest request;
    request.context = &m_node;
    request.strMethod = "getalphacheckpointevidence";
    request.params = UniValue(UniValue::VARR);
    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
    auto* tip = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip());
    request.params.push_back(tip->GetBlockHash().GetHex());
    const int original_height = WITH_LOCK(cs_main, return tip->nHeight);
    const auto restore = [&](CBlockIndex* index) { LOCK(cs_main); index->nHeight = original_height; };
    const std::unique_ptr<CBlockIndex,decltype(restore)> restore_guard(tip,restore);
    for (int height : {10000,INT32_MAX}) {
        WITH_LOCK(cs_main, tip->nHeight = height);
        BOOST_CHECK_EXCEPTION(tableRPC.execute(request),UniValue,HasJSON(
            "{\"code\":-1,\"message\":\"Checkpoint header limit exceeded\"}"));
    }
}

BOOST_AUTO_TEST_CASE(checkpoint_coin_validation_short_circuits)
{
    for (unsigned mask=0; mask<16; ++mask) for (int fault=-1; fault<4; ++fault) {
        std::vector<unsigned> trace;
        const auto fact=[&](unsigned index) {
            trace.push_back(index);
            if (int(index)==fault) throw std::runtime_error("checkpoint read failed");
            return (mask & (1U<<index))!=0;
        };
        std::vector<unsigned> expected;
        bool throws=false;
        for (unsigned i=0;i<4;++i) {
            expected.push_back(i);
            if (int(i)==fault) { throws=true; break; }
            if (!(mask & (1U<<i))) break;
        }
        const auto validate=[&] { return drivechain::haskell::ParentReplayAll<4>({
            [&] { return fact(0); },[&] { return fact(1); },
            [&] { return fact(2); },[&] { return fact(3); }}); };
        if (throws) BOOST_CHECK_EXCEPTION(validate(),std::runtime_error,[](const auto& error) {
            return std::string_view{error.what()}=="checkpoint read failed";
        });
        else BOOST_CHECK_EQUAL(validate(),mask==15);
        BOOST_CHECK(trace==expected);
    }
}

BOOST_AUTO_TEST_CASE(bond_inbox_export_rejects_non_elements_before_range_checks)
{
    BOOST_REQUIRE(!Params().GetConsensus().elements_mode);
    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
    for (const auto& [start, count] : {std::pair{0,1}, std::pair{-1,65}}) {
        JSONRPCRequest request;
        request.context = &m_node;
        request.strMethod = "getecxbondinboxentries";
        request.params = UniValue(UniValue::VARR);
        request.params.push_back(start);
        request.params.push_back(count);
        BOOST_CHECK_EXCEPTION(tableRPC.execute(request), UniValue, [](const auto& error) {
            return error.find_value("message").get_str() == "frozen ECX bond V2 source export is unavailable";
        });
    }
}

BOOST_AUTO_TEST_CASE(peg_events_rejects_network_before_range_or_l1)
{
    BOOST_REQUIRE(!Params().GetConsensus().elements_mode);
    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
    for (bool include_l1 : {false,true}) for (const auto& [start,count] : {std::pair{0,1000},std::pair{-1,10001}}) {
        JSONRPCRequest request;
        request.context=&m_node;
        request.strMethod="getdrivechainpegevents";
        request.params=UniValue(UniValue::VARR);
        request.params.push_back(start);
        request.params.push_back(count);
        request.params.push_back(include_l1);
        BOOST_CHECK_EXCEPTION(tableRPC.execute(request),UniValue,
            HasJSON("{\"code\":-1,\"message\":\"getdrivechainpegevents is unavailable outside an Elements parent-chain configuration\"}"));
    }
}

BOOST_FIXTURE_TEST_CASE(sidechain_info_uses_next_validation_height, TestChain100Setup)
{
    JSONRPCRequest request;
    request.context = &m_node;
    request.strMethod = "getsidechaininfo";
    request.params = UniValue(UniValue::VARR);
    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
    const auto result = tableRPC.execute(request);
    const int height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    BOOST_CHECK_EQUAL(result["pegin_confirmation_depth_validation_height"].getInt<int>(),height+1);
    BOOST_CHECK_EQUAL(result["pegin_confirmation_depth"].getInt<uint64_t>(),
        GetDrivechainPeginConfirmationDepth(Params(),height+1));
    BOOST_CHECK_EQUAL(result["pegin_confirmation_depth_current_block"].getInt<uint64_t>(),
        GetDrivechainPeginConfirmationDepth(Params(),height));
    BOOST_CHECK_EQUAL(result["pegin_confirmation_depth_historical"].getInt<uint64_t>(),
        Params().GetConsensus().pegin_min_depth);
}

BOOST_AUTO_TEST_CASE(withdrawal_anchor_recheck_short_circuits)
{
    for (bool active : {false, true}) for (bool same_hash : {false, true}) {
        unsigned hash_reads{0};
        const bool anchored = drivechain::haskell::ParentReplayAll<2>({
            [&] { return active; }, [&] { ++hash_reads; return same_hash; },
        });
        BOOST_CHECK_EQUAL(anchored, active && same_hash);
        BOOST_CHECK_EQUAL(hash_reads, active ? 1U : 0U);
    }
    BOOST_CHECK_THROW((drivechain::haskell::ParentReplayAll<2>({
        [] { return true; }, []() -> bool { throw std::runtime_error("anchor read failed"); },
    })), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(withdrawal_nullable_candidate_and_output_match)
{
    const auto transaction=MakeTransactionRef(CMutableTransaction{});
    for (const auto& candidate : {CTransactionRef{},transaction})
    for (const auto& txid : {transaction->GetHash(),Txid::FromUint256(uint256::ONE)}) {
        unsigned reads{0};
        const bool matched=drivechain::haskell::ParentReplayAll<2>({
            [&] { return bool(candidate); },
            [&] { ++reads; return candidate->GetHash()==txid; }});
        BOOST_CHECK_EQUAL(matched,candidate && candidate->GetHash()==txid);
        BOOST_CHECK_EQUAL(reads,candidate ? 1U : 0U);
    }
    for (const auto& canonical : {std::optional<uint32_t>{},std::optional<uint32_t>{0},
        std::optional<uint32_t>{1},std::optional<uint32_t>{UINT32_MAX}})
    for (uint32_t vout : {0U,1U,UINT32_MAX})
        BOOST_CHECK_EQUAL(canonical==vout,canonical && *canonical==vout);
}

BOOST_AUTO_TEST_CASE(peg_event_range_boundaries)
{
    for (int32_t tip : {INT32_MIN,-1,0,1,998,999,1000,INT32_MAX}) {
        BOOST_CHECK_EQUAL(drivechain::haskell::PegEventStart(tip),std::max<int64_t>(0,int64_t{tip}-999));
        BOOST_CHECK_EQUAL(drivechain::haskell::ParentReplayRecord(
            drivechain::haskell::ReplayRecordKind::AMOUNT,0,tip,0,INT32_MAX),tip>=0);
    }
    for (int32_t start : {INT32_MIN,-1,0,1,10000,INT32_MAX-9999,INT32_MAX})
    for (int32_t count : {INT32_MIN,-1,0,1,10000,10001,INT32_MAX})
    for (int32_t tip : {-1,0,1,10000,INT32_MAX}) {
        int32_t end{12345};
        const uint32_t expected = start<0 || start>tip ? 1 : count<1 || count>10000 ? 2 : 0;
        BOOST_CHECK_EQUAL(drivechain::haskell::PegEventRange(start,count,tip,end),expected);
        if (expected) BOOST_CHECK_EQUAL(end,12345);
        else {
            BOOST_CHECK_EQUAL(end,std::min<int64_t>(tip,int64_t{start}+count-1));
            BOOST_CHECK(end>=start && end<=tip);
            BOOST_CHECK(int64_t{end}-start+1<=10000);
        }
    }
}

BOOST_AUTO_TEST_CASE(bond_export_catalogue_and_entry_budget)
{
    static_assert(drivechain::BOND_EXPORT_DEFAULT_BLOCKS == 1);
    static_assert(drivechain::BOND_EXPORT_BLOCK_LIMIT == 64);
    static_assert(drivechain::BOND_EXPORT_ENTRY_LIMIT == 8);
    for (uint64_t used : std::array<uint64_t,6>{0,1,7,8,9,UINT64_MAX})
    for (uint64_t added : std::array<uint64_t,4>{0,1,8,UINT64_MAX}) {
        bool compared{false};
        const bool rejected = drivechain::haskell::ParentReplayAll<2>({[&] { return used != 0; }, [&] {
            compared = true;
            return drivechain::haskell::ParentReplayRecord(drivechain::haskell::ReplayRecordKind::LANE_EXCEEDED,
                drivechain::BOND_EXPORT_ENTRY_LIMIT,0,used,added);
        }});
        BOOST_CHECK_EQUAL(rejected,used != 0 && (used > 8 || added > 8-used));
        BOOST_CHECK_EQUAL(compared,used != 0);
    }
}

BOOST_AUTO_TEST_CASE(ecx_network_guard_before_context_or_parameters)
{
    for (bool available : {false,true}) {
        unsigned reads{0};
        BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeAvailable(drivechain::haskell::Availability::RPC,
            [&](uint32_t step) { BOOST_CHECK_EQUAL(step,0U); ++reads; return available; }),available);
        BOOST_CHECK_EQUAL(reads,1U);
    }
    BOOST_CHECK_EXCEPTION(drivechain::haskell::ExchangeAvailable(drivechain::haskell::Availability::RPC,
        [](uint32_t) -> bool { throw std::runtime_error("availability read failed"); }),
        std::runtime_error,[](const auto& error) { return std::string_view{error.what()} == "availability read failed"; });
    BOOST_REQUIRE(!Params().GetConsensus().elements_mode);
    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
    for (bool root : {false,true}) {
        JSONRPCRequest request;
        request.strMethod = root ? "getecxstateutxoroot" : "getecxconsensuscontext";
        request.params = UniValue(UniValue::VARR);
        if (root) { request.params.push_back("not-a-hash"); request.params.push_back(-1); }
        BOOST_CHECK_EXCEPTION(tableRPC.execute(request),UniValue,[&](const UniValue& error) {
            return error["code"].getInt<int>() == RPC_MISC_ERROR && error["message"].get_str() ==
                (root ? "ECX state is unavailable outside an Elements-mode chain" :
                        "ECX consensus context is unavailable outside an Elements-mode chain");
        });
    }
}

BOOST_AUTO_TEST_CASE(peg_event_optional_l1_order)
{
    for (bool include : {false,true}) for (bool fail : {false,true}) {
        std::vector<int> events{1};
        bool queried{false};
        const auto merge = [&] {
            return drivechain::haskell::ParentReplayAll<2>({[&] { return include; }, [&] {
                queried = true;
                if (fail) throw std::runtime_error("L1 unavailable");
                events.push_back(2);
                return true;
            }});
        };
        if (include && fail) BOOST_CHECK_THROW(merge(),std::runtime_error);
        else BOOST_CHECK_EQUAL(merge(),include);
        BOOST_CHECK_EQUAL(queried,include);
        BOOST_CHECK(events == (include && !fail ? std::vector<int>{1,2} : std::vector<int>{1}));
    }
}

BOOST_AUTO_TEST_CASE(bond_export_reconstruction_order)
{
    for (uint32_t expected_profile : {0U,1U,2U,255U,UINT32_MAX})
    for (uint32_t working_profile : {0U,1U,2U,255U,UINT32_MAX})
    for (uint32_t flags=0; flags<8; ++flags) {
        const auto bit = [&](unsigned index) { return (flags>>index)&1; };
        const std::array<uint32_t,10> replies{0,expected_profile,working_profile,1,bit(0),bit(0),bit(1),bit(2),1,1};
        std::vector<uint32_t> expected{1}, trace;
        if (expected_profile==1) {
            expected.push_back(2);
            if (working_profile==0) expected.push_back(3);
        }
        expected.push_back(expected_profile==1 ? 5 : 4);
        uint32_t failure=0;
        if (!bit(0)) failure=9;
        else {
            expected.push_back(6);
            if (!bit(1)) failure=8;
            else { expected.push_back(7); if (!bit(2)) failure=8; }
        }
        if (failure) expected.push_back(failure);
        const auto run = [&] {
            return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::EXPORT_RECONSTRUCT,
                [&](uint32_t step) -> uint32_t {
                    trace.push_back(step);
                    if (step==8 || step==9) throw JSONRPCError(RPC_MISC_ERROR,std::to_string(step));
                    return replies.at(step);
                });
        };
        if (!failure) BOOST_CHECK_EQUAL(run(),1);
        else BOOST_CHECK_EXCEPTION(run(),UniValue,[&](const UniValue& error) {
            return error["code"].getInt<int>()==RPC_MISC_ERROR && error["message"].get_str()==std::to_string(failure);
        });
        BOOST_CHECK(trace==expected);
    }
}

BOOST_AUTO_TEST_CASE(parent_report_selection_order)
{
    for (uint32_t flags=0; flags<64; ++flags) for (uint32_t height : {0U,1U,UINT32_MAX}) {
        const auto bit = [&](unsigned index) { return (flags>>index)&1; };
        const std::array<uint32_t,15> replies{0,bit(0),bit(1),1,1,bit(2),bit(3),1,bit(4),height,1,1,height,bit(5),1};
        std::vector<uint32_t> expected{1}, trace;
        uint32_t failure{0};
        if (bit(0)) {
            expected.push_back(2);
            if (bit(1)) expected.push_back(4); else failure=3;
        } else {
            expected.push_back(5);
            if (bit(2)) {
                expected.push_back(6);
                if (!bit(3)) failure=7;
            } else {
                expected.push_back(8);
                if (!bit(4)) failure=7;
                else {
                    expected.push_back(9);
                    if (!height) failure=10; else expected.push_back(11);
                }
            }
        }
        if (!failure) {
            expected.push_back(12);
            if (!height) failure=14;
            else { expected.push_back(13); if (!bit(5)) failure=14; }
        }
        if (failure) expected.push_back(failure);
        const auto run = [&] {
            return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::PARENT_REPORT,
                [&](uint32_t step) -> uint32_t {
                trace.push_back(step);
                if (step==3 || step==7 || step==10 || step==14)
                    throw JSONRPCError(RPC_MISC_ERROR,std::to_string(step));
                return replies.at(step);
            });
        };
        if (!failure) BOOST_CHECK_EQUAL(run(),1);
        else BOOST_CHECK_EXCEPTION(run(),UniValue,[&](const UniValue& error) {
            return error["code"].getInt<int>()==RPC_MISC_ERROR && error["message"].get_str()==std::to_string(failure);
        });
        BOOST_CHECK(trace==expected);
    }
}

BOOST_AUTO_TEST_CASE(capital_report_admission_order)
{
    const std::array<const char*,3> capital_names{"Normal","ReduceOnly","Recovery"};
    const std::array<const char*,4> oracle_names{"Normal","ReduceOnly","Disputed","Halt"};
    BOOST_REQUIRE_EQUAL(drivechain::ECX_CAPITAL_MODES.size(),capital_names.size());
    BOOST_REQUIRE_EQUAL(drivechain::ECX_ORACLE_MODES.size(),oracle_names.size());
    for (size_t i=0; i<capital_names.size(); ++i) BOOST_CHECK_EQUAL(std::string(drivechain::ECX_CAPITAL_MODES.at(i)),capital_names[i]);
    for (size_t i=0; i<oracle_names.size(); ++i) BOOST_CHECK_EQUAL(std::string(drivechain::ECX_ORACLE_MODES.at(i)),oracle_names[i]);
    for (uint32_t version : {0U,3U,4U,5U,UINT32_MAX})
    for (uint32_t capital : {0U,2U,3U,255U})
    for (uint32_t oracle : {0U,3U,4U,255U})
    for (uint32_t safe : {0U,1U,2U,255U})
    for (uint32_t flags = 0; flags < 8; ++flags) {
        const std::array<uint32_t,7> replies{version,flags&1,(flags>>1)&1,capital,oracle,safe,(flags>>2)&1};
        const std::array<bool,7> valid{version==4,bool(flags&1),bool(flags&2),capital<=2,oracle<=3,safe<=1,bool(flags&4)};
        const auto passed = std::find(valid.begin(),valid.end(),false)-valid.begin();
        std::vector<uint32_t> trace;
        const auto run = [&] {
            return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::CAPITAL_REPORT,
                [&](uint32_t step) -> uint32_t {
                trace.push_back(step);
                if (step <= 2) return 1;
                if (step == 3) BOOST_FAIL("present projection rejected");
                if (step == 11) throw JSONRPCError(RPC_MISC_ERROR,"invalid capital snapshot");
                return replies.at(step-4);
            });
        };
        if (passed == 7) BOOST_CHECK_EQUAL(run(),1);
        else BOOST_CHECK_EXCEPTION(run(),UniValue,[](const UniValue& error) {
            return error["code"].getInt<int>() == RPC_MISC_ERROR && error["message"].get_str() == "invalid capital snapshot";
        });
        std::vector<uint32_t> expected{1,2};
        for (uint32_t step=4; step<=std::min<uint32_t>(passed+4,10); ++step) expected.push_back(step);
        if (passed != 7) expected.push_back(11);
        BOOST_CHECK(trace == expected);
    }
}

BOOST_AUTO_TEST_CASE(capital_report_optional_projection)
{
    for (bool enabled : {false,true})
    for (bool present : {false,true}) {
        std::optional<uint32_t> projection;
        if (present) projection = 4;
        std::vector<uint32_t> trace;
        const auto run = [&] {
            return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::CAPITAL_REPORT,
                [&](uint32_t step) -> uint32_t {
                    trace.push_back(step);
                    if (step == 1) return enabled;
                    if (step == 2) return projection.has_value();
                    if (step == 3) throw JSONRPCError(RPC_MISC_ERROR,
                        "active ECX V2 tip has no fully verified capital projection");
                    BOOST_REQUIRE(projection.has_value());
                    return step == 4 ? projection.value() : 1;
                });
        };
        if (enabled && !present) BOOST_CHECK_EXCEPTION(run(),UniValue,[](const UniValue& error) {
            return error["code"].getInt<int>() == RPC_MISC_ERROR && error["message"].get_str() ==
                "active ECX V2 tip has no fully verified capital projection";
        });
        else BOOST_CHECK_EQUAL(run(),enabled ? 1U : 0U);
        const std::vector<uint32_t> expected = !enabled ? std::vector<uint32_t>{1} :
            !present ? std::vector<uint32_t>{1,2,3} : std::vector<uint32_t>{1,2,4,5,6,7,8,9,10};
        BOOST_CHECK(trace == expected);
    }
}

BOOST_AUTO_TEST_CASE(bond_export_range_bounds)
{
    int32_t end = 123;
    BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeExportRange(100, 64, 100, std::nullopt, end), 0U);
    BOOST_CHECK_EQUAL(end, 100);
    BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeExportRange(100, 64, 100, 110, end), 0U);
    BOOST_CHECK_EQUAL(end, 110);
    BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeExportRange(100, 64, 100, 200, end), 0U);
    BOOST_CHECK_EQUAL(end, 163);
    BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeExportRange(INT32_MAX, 64, 100, INT32_MAX, end), 0U);
    BOOST_CHECK_EQUAL(end, INT32_MAX);
    for (int count : {0, 65, -1}) {
        BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeExportRange(100, count, 100, -1, end), 1U);
        BOOST_CHECK_EQUAL(end, INT32_MAX);
    }
    BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeExportRange(99, 1, 100, -1, end), 1U);
    BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeExportRange(100, 1, 100, -1, end), 2U);
    BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeExportRange(100, 1, 100, 99, end), 2U);
    BOOST_CHECK_EQUAL(end, INT32_MAX);
}

BOOST_AUTO_TEST_CASE(bond_inbox_export_snapshot_seed)
{
    for (bool genesis : {false,true})
    for (bool present : {false,true}) {
        std::optional<uint64_t> previous;
        if (present) previous = 42;
        uint64_t working{0};
        std::vector<uint32_t> trace;
        const auto run = [&] {
            return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::EXPORT_INITIALIZE,
                [&](uint32_t step) -> uint32_t {
                trace.push_back(step);
                switch (step) {
                case 1: return genesis;
                case 2: working = 1; return 1;
                case 3: return previous.has_value();
                case 4: throw JSONRPCError(RPC_MISC_ERROR, "predecessor lacks a verified bond-inbox projection");
                case 5: working = previous.value(); return 1;
                default: throw std::logic_error("unexpected seed action");
                }
            });
        };
        if (genesis || present) BOOST_CHECK_EQUAL(run(),1U);
        else BOOST_CHECK_EXCEPTION(run(),UniValue,HasJSON(
            "{\"code\":-1,\"message\":\"predecessor lacks a verified bond-inbox projection\"}"));
        BOOST_CHECK_EQUAL(working,genesis ? 1U : present ? 42U : 0U);
        const std::vector<uint32_t> expected = genesis ? std::vector<uint32_t>{1,2} :
            std::vector<uint32_t>{1,3,present ? 5U : 4U};
        BOOST_CHECK(trace == expected);
    }
}

BOOST_AUTO_TEST_CASE(bond_inbox_export_recheck_prefix)
{
    const std::array heights{0,1,2};
    for (int end = -1; end <= 3; ++end)
    for (int changed = -1; changed <= 2; ++changed) {
        std::vector<int> looked_up;
        const auto run = [&] {
            return drivechain::haskell::ParentReplayEach(heights, [&](int height) {
                return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::EXPORT_RECHECK,
                    [&](uint32_t step) -> uint32_t {
                    switch (step) {
                    case 1: return height <= end;
                    case 2: looked_up.push_back(height); return height != changed;
                    case 3: throw JSONRPCError(RPC_MISC_ERROR,
                        "bond-inbox export range was reorganized during reconstruction");
                    default: throw std::logic_error("unexpected recheck action");
                    }
                });
            });
        };
        const bool fails{changed >= 0 && changed <= end};
        if (fails) BOOST_CHECK_EXCEPTION(run(),UniValue,HasJSON(
            "{\"code\":-1,\"message\":\"bond-inbox export range was reorganized during reconstruction\"}"));
        else BOOST_CHECK_EQUAL(run(),end >= 2);
        std::vector<int> expected;
        for (int height : heights) {
            if (height > end) break;
            expected.push_back(height);
            if (height == changed) break;
        }
        BOOST_CHECK(looked_up == expected);
    }
}

BOOST_AUTO_TEST_CASE(bond_inbox_export_capture_range)
{
    for (int64_t first : {int64_t{0}, int64_t{100}, int64_t{INT32_MAX} - 63}) {
        for (int count : {1, 2, 64}) {
            const int64_t last = first + count - 1;
            for (int fault = -1; fault < count; ++fault) {
                std::vector<int64_t> reads, captured;
                bool failed{false};
                try {
                    BOOST_CHECK(drivechain::haskell::ParentReplayEach(
                        std::views::iota(first, last + 1), [&](int64_t height) {
                            reads.push_back(height);
                            if (height - first == fault) throw JSONRPCError(RPC_MISC_ERROR, "missing projection");
                            captured.push_back(height);
                            return true;
                        }));
                } catch (const UniValue& error) {
                    failed = true;
                    BOOST_CHECK_EQUAL(error["message"].get_str(), "missing projection");
                }
                BOOST_CHECK_EQUAL(failed, fault >= 0);
                BOOST_CHECK_EQUAL(captured.size(), fault < 0 ? count : fault);
                BOOST_CHECK_EQUAL(reads.size(), fault < 0 ? count : fault + 1);
                for (size_t i = 0; i < reads.size(); ++i) BOOST_CHECK_EQUAL(reads[i], first + i);
                for (size_t i = 0; i < captured.size(); ++i) BOOST_CHECK_EQUAL(captured[i], first + i);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(bond_inbox_export_iteration)
{
    for (size_t first = 0; first <= 10; ++first) {
        for (size_t second = 0; second <= 10; ++second) {
          for (size_t third = 0; third <= 10; ++third) {
            const std::array sizes{first, second, third};
            for (int fault = -1; fault < 3; ++fault) {
                size_t expected_count = 0, actual_count = 0;
                int expected_end = -1, actual_end = -1;
                std::vector<int> expected_reads, actual_reads;
                bool expected_truncated = false, actual_truncated = false;
                bool expected_error = false, actual_error = false;
                for (int i = 0; i < 3; ++i) {
                    expected_reads.push_back(i);
                    if (i == fault) { expected_error = true; break; }
                    if (expected_count && expected_count + sizes[i] > 8) {
                        expected_truncated = true;
                        break;
                    }
                    expected_count += sizes[i];
                    expected_end = i;
                }
                const std::array indices{0, 1, 2};
                try {
                    actual_truncated = !drivechain::haskell::ParentReplayEach(indices, [&](int i) {
                        actual_reads.push_back(i);
                        if (i == fault) throw JSONRPCError(RPC_MISC_ERROR, "reconstruction failed");
                        if (drivechain::haskell::ParentReplayAll<2>({
                            [&] { return actual_count != 0; },
                            [&] { return drivechain::haskell::ParentReplayRecord(
                                drivechain::haskell::ReplayRecordKind::LANE_EXCEEDED,
                                8, 0, actual_count, sizes[i]); },
                        })) return false;
                        actual_count += sizes[i];
                        actual_end = i;
                        return true;
                    });
                } catch (const UniValue& error) {
                    actual_error = true;
                    BOOST_CHECK_EQUAL(error["code"].getInt<int>(), RPC_MISC_ERROR);
                    BOOST_CHECK_EQUAL(error["message"].get_str(), "reconstruction failed");
                }
                BOOST_CHECK(actual_reads == expected_reads);
                BOOST_CHECK_EQUAL(actual_count, expected_count);
                BOOST_CHECK_EQUAL(actual_end, expected_end);
                BOOST_CHECK_EQUAL(actual_truncated, expected_truncated);
                BOOST_CHECK_EQUAL(actual_error, expected_error);
                if (!actual_error) {
                    BOOST_CHECK_GE(actual_end, 0);
                    BOOST_CHECK_EQUAL(actual_truncated, actual_end < 2);
                    for (const int64_t start : {int64_t{0}, int64_t{100}, int64_t{INT32_MAX} - 2}) {
                        const int64_t end = start + actual_end;
                        BOOST_CHECK_EQUAL(end + 1, std::max(start, end + 1));
                    }
                }
            }
          }
        }
    }
}

BOOST_AUTO_TEST_CASE(bond_inbox_export_entry_limit)
{
    namespace hs = drivechain::haskell;
    const std::array<uint64_t,9> counts{0,1,7,8,9,INT32_MAX,INT64_MAX,UINT64_MAX-1,UINT64_MAX};
    for (const auto current : counts) {
        for (const auto additional : counts) {
            bool consulted_limit{false};
            const bool stop = hs::ParentReplayAll<2>({
                [&] { return current != 0; },
                [&] {
                    consulted_limit = true;
                    return hs::ParentReplayRecord(hs::ReplayRecordKind::LANE_EXCEEDED,
                        8, 0, current, additional);
                },
            });
            // The sum is evaluated only when both operands fit the small cap.
            const bool expected = current != 0 &&
                (current > 8 || additional > 8 || current + additional > 8);
            BOOST_CHECK_EQUAL(stop, expected);
            BOOST_CHECK_EQUAL(consulted_limit, current != 0);
        }
    }
}

BOOST_AUTO_TEST_CASE(bond_inbox_export_reorg_fence)
{
    const std::array heights{10, 11, 12, 13};
    for (int end_height = 9; end_height <= 13; ++end_height) {
        for (int changed = 9; changed <= 14; ++changed) {
            std::vector<int> checked, expected;
            for (int height : heights) {
                if (height > end_height) break;
                expected.push_back(height);
                if (height == changed) break;
            }
            bool failed = false;
            try {
                LOCK(cs_main);
                const std::function<bool(int)> check_range = [&](int height) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
                    AssertLockHeld(cs_main);
                    if (height > end_height) return false;
                    checked.push_back(height);
                    if (height == changed) throw JSONRPCError(RPC_MISC_ERROR, "range reorganized");
                    return true;
                };
                drivechain::haskell::ParentReplayEach(heights, check_range);
            } catch (const UniValue& error) {
                failed = true;
                BOOST_CHECK_EQUAL(error["code"].getInt<int>(), RPC_MISC_ERROR);
                BOOST_CHECK_EQUAL(error["message"].get_str(), "range reorganized");
            }
            AssertLockNotHeld(cs_main);
            BOOST_CHECK(checked == expected);
            BOOST_CHECK_EQUAL(failed, changed >= 10 && changed <= end_height);
        }
    }
}

BOOST_AUTO_TEST_CASE(wide_decimal_json_numbers)
{
    struct Case { const char* hex; const char* positive; const char* signed_value; };
    for (const auto& example : {
        Case{"00000000000000000000000000000000", "0", "0"},
        Case{"00000000000000000000000000000001", "1", "1"},
        Case{"00000000000000010000000000000000", "18446744073709551616", "18446744073709551616"},
        Case{"7fffffffffffffffffffffffffffffff", "170141183460469231731687303715884105727", "170141183460469231731687303715884105727"},
        Case{"80000000000000000000000000000000", "170141183460469231731687303715884105728", "-170141183460469231731687303715884105728"},
        Case{"ffffffffffffffffffffffffffffffff", "340282366920938463463374607431768211455", "-1"}}) {
        const auto parsed = ParseHex(example.hex);
        std::array<unsigned char,16> bytes;
        std::copy(parsed.begin(),parsed.end(),bytes.begin());
        for (bool signed_value : {false,true}) {
            const auto text = drivechain::haskell::WideDecimal(bytes,signed_value);
            BOOST_CHECK_EQUAL(text,signed_value ? example.signed_value : example.positive);
            const UniValue number = EcxWideNumberToJSON(bytes,signed_value);
            BOOST_REQUIRE(number.isNum());
            BOOST_CHECK_EQUAL(number.write(),text);
            UniValue decoded;
            BOOST_REQUIRE(decoded.read(number.write()));
            BOOST_CHECK_EQUAL(decoded.getValStr(),text);
        }
    }
}

BOOST_AUTO_TEST_CASE(private_bmm_sequence_order)
{
    const std::array steps{1, 2, 3, 4, 5, 6, 7};
    for (unsigned mask = 0; mask < 128; ++mask) {
        std::vector<int> seen, expected;
        const bool accepted = drivechain::haskell::ParentReplayEach(steps, [&](int step) {
            AssertLockNotHeld(cs_main);
            seen.push_back(step);
            if (step == 2 || step == 4) {
                LOCK(cs_main);
                AssertLockHeld(cs_main);
            }
            return (mask & (1U << (step - 1))) != 0;
        });
        for (int step : steps) {
            expected.push_back(step);
            if (!(mask & (1U << (step - 1)))) break;
        }
        BOOST_CHECK(seen == expected);
        BOOST_CHECK_EQUAL(accepted, mask == 127);
        AssertLockNotHeld(cs_main);
    }
    for (int fault : steps) {
        int calls = 0;
        BOOST_CHECK_EXCEPTION(drivechain::haskell::ParentReplayEach(steps, [&](int step) {
            ++calls;
            LOCK(cs_main);
            if (step == fault) throw std::logic_error("private generation callback fault");
            return true;
        }), std::logic_error, [](const auto& error) {
            return std::string(error.what()) == "private generation callback fault";
        });
        BOOST_CHECK_EQUAL(calls, fault);
        AssertLockNotHeld(cs_main);
    }
}

BOOST_AUTO_TEST_CASE(bmm_context_snapshot_order)
{
    namespace hs = drivechain::haskell;
    for (unsigned mask=0; mask<32; ++mask) {
        std::vector<int> seen;
        bool published=false;
        const auto status=hs::ParentReplayStore(hs::ReplayStoreFlow::RPC_BMM_AUTHENTICATION,
            [&](uint32_t step) -> uint32_t {
                AssertLockNotHeld(cs_main);
                if (step==5) {
                    LOCK(cs_main);
                    return hs::ParentReplayEach(std::array{0,1,2,3,4}, std::function<bool(int)>{[&](int fact) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
                        AssertLockHeld(cs_main);
                        seen.push_back(fact);
                        return (mask & (1U<<fact)) != 0;
                    }});
                }
                if (step==6) published=true;
                return 1;
            });
        std::vector<int> expected;
        for (int fact=0; fact<5; ++fact) {
            expected.push_back(fact);
            if (!(mask & (1U<<fact))) break;
        }
        BOOST_CHECK(seen==expected);
        BOOST_CHECK_EQUAL(status, mask==31 ? 0U : 3U);
        BOOST_CHECK_EQUAL(published, mask==31);
    }
    for (int fault=0; fault<5; ++fault) {
        int calls=0;
        BOOST_CHECK_EXCEPTION(hs::ParentReplayStore(hs::ReplayStoreFlow::RPC_BMM_AUTHENTICATION,
            [&](uint32_t step) -> uint32_t {
                if (step!=5) return 1;
                LOCK(cs_main);
                return hs::ParentReplayEach(std::array{0,1,2,3,4}, std::function<bool(int)>{[&](int fact) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
                    AssertLockHeld(cs_main);
                    ++calls;
                    if (fact==fault) throw std::logic_error("snapshot callback fault");
                    return true;
                }});
            }), std::logic_error, [](const auto& error) {
                return std::string(error.what())=="snapshot callback fault";
            });
        AssertLockNotHeld(cs_main);
        BOOST_CHECK_EQUAL(calls,fault+1);
    }
}

BOOST_AUTO_TEST_CASE(simplicity_source_selection_order)
{
    namespace hs = drivechain::haskell;
    for (bool frozen : {false,true}) for (bool private_catalogue : {false,true}) {
        std::vector<uint32_t> expected{1};
        if (private_catalogue) {
            expected.push_back(2);
            if (!frozen) expected.push_back(3);
        }
        for (size_t fault=0; fault<=expected.size(); ++fault) {
            std::vector<uint32_t> seen;
            const auto run = [&] {
                return hs::ParentReplayStore(hs::ReplayStoreFlow::EVALUATOR_SOURCE,
                    [&](uint32_t step) -> uint32_t {
                        seen.push_back(step);
                        if (fault && seen.size()==fault) throw std::runtime_error("source read failed");
                        if (step==1) return private_catalogue;
                        if (step==2) return frozen;
                        BOOST_CHECK(private_catalogue && !frozen);
                        return 1;
                    });
            };
            if (fault) BOOST_CHECK_EXCEPTION(run(),std::runtime_error,[](const auto& error) {
                return std::string{error.what()}=="source read failed";
            });
            else BOOST_CHECK_EQUAL(run(),1U);
            BOOST_CHECK_EQUAL_COLLECTIONS(seen.begin(),seen.end(),expected.begin(),
                expected.begin()+(fault ? fault : expected.size()));
        }
    }
}

BOOST_AUTO_TEST_CASE(simplicity_identity_reporting)
{
    const auto initial{CallRPC("getsimplicityinfo")};
    const bool frozen{initial["catalogueFrozen"].get_bool()};
    const bool private_catalogue{initial["privateCatalogue"].get_bool()};
    const std::vector<std::string> identities{
        "", std::string(63, 'a'), std::string(65, 'a'), std::string(64, 'g'),
        std::string(63, 'a') + '\0', std::string(64, '0'), std::string(64, 'a'),
        std::string(64, 'F'), std::string(32, 'a') + std::string(32, 'B')};
    for (const auto& catalogue : identities) {
        for (const auto& program : identities) {
            // The fixture restores settings, including forced values, on exit.
            m_node.args->ForceSetArg("-ecxprivatesimplicitycataloguesha256", catalogue);
            m_node.args->ForceSetArg("-ecxprivatesimplicityprogramcmr", program);
            const auto result{CallRPC("getsimplicityinfo")};
            BOOST_CHECK_EQUAL(result.size(), 5U);
            BOOST_CHECK_EQUAL(result["catalogueFrozen"].get_bool(), frozen);
            BOOST_CHECK_EQUAL(result["privateCatalogue"].get_bool(), private_catalogue);
            if (private_catalogue && !frozen) {
                const auto valid_hash = [](const std::string& value) {
                    return value.size() == 64 && value.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos;
                };
                const bool valid{valid_hash(catalogue) && valid_hash(program)};
                BOOST_CHECK_EQUAL(result["active"].get_bool(), valid);
                BOOST_CHECK_EQUAL(result["catalogueSha256"].get_str(), valid ? catalogue : "");
                BOOST_CHECK_EQUAL(result["programCmr"].get_str(), valid ? program : "");
            } else {
                BOOST_CHECK_EQUAL(result.write(), initial.write());
            }
        }
    }
    const bool available{!initial["catalogueSha256"].get_str().empty()};
    BOOST_CHECK_EQUAL(initial["programCmr"].get_str().empty(), !available);
    BOOST_CHECK_EQUAL(initial["active"].get_bool(), available && (frozen || private_catalogue));
}

BOOST_AUTO_TEST_CASE(bmm_work_bid_admission)
{
    // Every case rejects before SubmitDrivechainBmmBid; no parent request is made.
    const std::string zero(64,'0');
    const std::string hash(64,'1');
    struct Case {
        std::string critical, previous;
        int64_t height, collected, work, reserve, bid;
        const char* error;
    };
    const Case cases[]{
        {zero,hash,0,-1,-1,-1,-1,"BMM hashes must be nonzero"},
        {hash,zero,1,100,0,0,1,"BMM hashes must be nonzero"},
        {hash,hash,0,-1,-1,-1,-1,"sidechain height is outside uint32 range"},
        {hash,hash,-1,100,0,0,1,"sidechain height is outside uint32 range"},
        {hash,hash,INT64_C(4294967296),100,0,0,1,"sidechain height is outside uint32 range"},
        {hash,hash,1,0,0,0,1,"invalid work-fee allocation"},
        {hash,hash,1,100,-1,0,1,"invalid work-fee allocation"},
        {hash,hash,1,100,0,-1,1,"invalid work-fee allocation"},
        {hash,hash,1,100,0,0,0,"invalid work-fee allocation"},
        {hash,hash,1,1,INT64_MAX,0,2,"candidate fees do not fund its priced verification work and reserve"},
        {hash,hash,1,1,0,2,1,"candidate fees do not fund its priced verification work and reserve"},
        {hash,hash,1,100,0,0,101,"BMM bid exceeds work-fee revenue available after costs: 101 > 100"},
        {hash,hash,1,2000,1000000,0,1001,"BMM bid exceeds work-fee revenue available after costs: 1001 > 1000"},
        {hash,hash,INT64_C(4294967295),100,0,0,101,"BMM bid exceeds work-fee revenue available after costs: 101 > 100"},
    };
    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
    for (const auto& test : cases) {
        JSONRPCRequest request;
        request.context=&m_node;
        request.strMethod="submitbmmworkbid";
        request.params=UniValue(UniValue::VARR);
        request.params.push_back(test.critical);
        request.params.push_back(test.height);
        request.params.push_back(test.previous);
        for (const int64_t number : {test.collected,test.work,test.reserve,test.bid}) request.params.push_back(number);
        BOOST_CHECK_EXCEPTION(tableRPC.execute(request),UniValue,[&](const UniValue& error) {
            return error["code"].getInt<int>()==RPC_INVALID_PARAMETER && error["message"].get_str()==test.error;
        });
    }
}

BOOST_AUTO_TEST_CASE(mainchain_cookie_network_defaults)
{
    BOOST_CHECK_EQUAL(
        GetDefaultMainchainAuthCookieFile(CBaseChainParams::ELEMENTS),
        ".cookie");
    BOOST_CHECK_EQUAL(
        GetDefaultMainchainAuthCookieFile(CBaseChainParams::LIQUID1),
        ".cookie");
    BOOST_CHECK_EQUAL(
        GetDefaultMainchainAuthCookieFile(CBaseChainParams::REGTEST),
        "regtest/.cookie");
    for (const auto& chain : {std::string{},std::string{"Elements"},std::string{"elements\0",9},
         std::string{"signet"},std::string{"liquidtestnet"},std::string{"custom"}})
        BOOST_CHECK_EQUAL(GetDefaultMainchainAuthCookieFile(chain),"regtest/.cookie");
}

BOOST_AUTO_TEST_CASE(rpc_namedparams)
{
    const std::vector<std::pair<std::string, bool>> arg_names{{"arg1", false}, {"arg2", false}, {"arg3", false}, {"arg4", false}, {"arg5", false}};

    // Make sure named arguments are transformed into positional arguments in correct places separated by nulls
    BOOST_CHECK_EQUAL(TransformParams(JSON(R"({"arg2": 2, "arg4": 4})"), arg_names).write(), "[null,2,null,4]");

    // Make sure named argument specified multiple times raises an exception
    BOOST_CHECK_EXCEPTION(TransformParams(JSON(R"({"arg2": 2, "arg2": 4})"), arg_names), UniValue,
                          HasJSON(R"({"code":-8,"message":"Parameter arg2 specified multiple times"})"));

    // Make sure named and positional arguments can be combined.
    BOOST_CHECK_EQUAL(TransformParams(JSON(R"({"arg5": 5, "args": [1, 2], "arg4": 4})"), arg_names).write(), "[1,2,null,4,5]");

    // Make sure a unknown named argument raises an exception
    BOOST_CHECK_EXCEPTION(TransformParams(JSON(R"({"arg2": 2, "unknown": 6})"), arg_names), UniValue,
                          HasJSON(R"({"code":-8,"message":"Unknown named parameter unknown"})"));

    // Make sure an overlap between a named argument and positional argument raises an exception
    BOOST_CHECK_EXCEPTION(TransformParams(JSON(R"({"args": [1,2,3], "arg4": 4, "arg2": 2})"), arg_names), UniValue,
                          HasJSON(R"({"code":-8,"message":"Parameter arg2 specified twice both as positional and named argument"})"));

    // Make sure extra positional arguments can be passed through to the method implementation, as long as they don't overlap with named arguments.
    BOOST_CHECK_EQUAL(TransformParams(JSON(R"({"args": [1,2,3,4,5,6,7,8,9,10]})"), arg_names).write(), "[1,2,3,4,5,6,7,8,9,10]");
    BOOST_CHECK_EQUAL(TransformParams(JSON(R"([1,2,3,4,5,6,7,8,9,10])"), arg_names).write(), "[1,2,3,4,5,6,7,8,9,10]");
}

BOOST_AUTO_TEST_CASE(rpc_namedonlyparams)
{
    const std::vector<std::pair<std::string, bool>> arg_names{{"arg1", false}, {"arg2", false}, {"opt1", true}, {"opt2", true}, {"options", false}};

    // Make sure optional parameters are really optional.
    BOOST_CHECK_EQUAL(TransformParams(JSON(R"({"arg1": 1, "arg2": 2})"), arg_names).write(), "[1,2]");

    // Make sure named-only parameters are passed as options.
    BOOST_CHECK_EQUAL(TransformParams(JSON(R"({"arg1": 1, "arg2": 2, "opt1": 10, "opt2": 20})"), arg_names).write(), R"([1,2,{"opt1":10,"opt2":20}])");

    // Make sure options can be passed directly.
    BOOST_CHECK_EQUAL(TransformParams(JSON(R"({"arg1": 1, "arg2": 2, "options":{"opt1": 10, "opt2": 20}})"), arg_names).write(), R"([1,2,{"opt1":10,"opt2":20}])");

    // Make sure options and named parameters conflict.
    BOOST_CHECK_EXCEPTION(TransformParams(JSON(R"({"arg1": 1, "arg2": 2, "opt1": 10, "options":{"opt1": 10}})"), arg_names), UniValue,
                          HasJSON(R"({"code":-8,"message":"Parameter options conflicts with parameter opt1"})"));

    // Make sure options object specified through args array conflicts.
    BOOST_CHECK_EXCEPTION(TransformParams(JSON(R"({"args": [1, 2, {"opt1": 10}], "opt2": 20})"), arg_names), UniValue,
                          HasJSON(R"({"code":-8,"message":"Parameter options specified twice both as positional and named argument"})"));
}

BOOST_AUTO_TEST_CASE(rpc_rawparams)
{
    // Test raw transaction API argument handling
    UniValue r;

    BOOST_CHECK_THROW(CallRPC("getrawtransaction"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("getrawtransaction not_hex"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("getrawtransaction a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed not_int"), std::runtime_error);

    BOOST_CHECK_THROW(CallRPC("createrawtransaction"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction null null"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction not_array"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction {} {}"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [] {}"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [] [] extra"), std::runtime_error);

    BOOST_CHECK_THROW(CallRPC("decoderawtransaction"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("decoderawtransaction null"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("decoderawtransaction DEADBEEF"), std::runtime_error);
    std::string rawtx = "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000";
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("decoderawtransaction ")+rawtx));
    BOOST_CHECK_EQUAL(r.get_obj().find_value("size").getInt<int>(), 193);
    BOOST_CHECK_EQUAL(r.get_obj().find_value("version").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(r.get_obj().find_value("locktime").getInt<int>(), 0);
    BOOST_CHECK_THROW(CallRPC(std::string("decoderawtransaction ")+rawtx+" extra"), std::runtime_error);
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("decoderawtransaction ")+rawtx+" false"));
    BOOST_CHECK_THROW(r = CallRPC(std::string("decoderawtransaction ")+rawtx+" false extra"), std::runtime_error);

    // Only check failure cases for sendrawtransaction, there's no network to send to...
    BOOST_CHECK_THROW(CallRPC("sendrawtransaction"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("sendrawtransaction null"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("sendrawtransaction DEADBEEF"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC(std::string("sendrawtransaction ")+rawtx+" extra"), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(rpc_togglenetwork)
{
    UniValue r;

    r = CallRPC("getnetworkinfo");
    bool netState = r.get_obj().find_value("networkactive").get_bool();
    BOOST_CHECK_EQUAL(netState, true);

    BOOST_CHECK_NO_THROW(CallRPC("setnetworkactive false"));
    r = CallRPC("getnetworkinfo");
    int numConnection = r.get_obj().find_value("connections").getInt<int>();
    BOOST_CHECK_EQUAL(numConnection, 0);

    netState = r.get_obj().find_value("networkactive").get_bool();
    BOOST_CHECK_EQUAL(netState, false);

    BOOST_CHECK_NO_THROW(CallRPC("setnetworkactive true"));
    r = CallRPC("getnetworkinfo");
    netState = r.get_obj().find_value("networkactive").get_bool();
    BOOST_CHECK_EQUAL(netState, true);
}

BOOST_AUTO_TEST_CASE(rpc_rawsign)
{
    UniValue r;
    // input is a 1-of-2 multisig (so is output):
    std::string prevout =
      "[{\"txid\":\"b4cc287e58f87cdae59417329f710f3ecd75a4ee1d2872b7248f50977c8493f3\","
      "\"vout\":1,\"scriptPubKey\":\"a914b10c9df5f7edf436c697f02f1efdba4cf399615187\","
      "\"redeemScript\":\"512103debedc17b3df2badbcdd86d5feb4562b86fe182e5998abd8bcd4f122c6155b1b21027e940bb73ab8732bfdf7f9216ecefca5b94d6df834e77e108f68e66f126044c052ae\"}]";
    r = CallRPC(std::string("createrawtransaction ")+prevout+" "+
      "[{\"3HqAe9LtNBjnsfM4CyYaWTnvCaUYT7v4oZ\":11}]");
    std::string notsigned = r.get_str();
    std::string privkey1 = "\"KzsXybp9jX64P5ekX1KUxRQ79Jht9uzW7LorgwE65i5rWACL6LQe\"";
    std::string privkey2 = "\"Kyhdf5LuKTRx4ge69ybABsiUAWjVRK4XGxAKk2FQLp2HjGMy87Z4\"";
    r = CallRPC(std::string("signrawtransactionwithkey ")+notsigned+" [] "+prevout);
    BOOST_CHECK(r.get_obj().find_value("complete").get_bool() == false);
    r = CallRPC(std::string("signrawtransactionwithkey ")+notsigned+" ["+privkey1+","+privkey2+"] "+prevout);
    BOOST_CHECK(r.get_obj().find_value("complete").get_bool() == true);
}

BOOST_AUTO_TEST_CASE(rpc_createraw_op_return)
{
    BOOST_CHECK_NO_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] [{\"data\":\"68656c6c6f776f726c64\"}]"));

    // Key not "data" (bad address)
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] [{\"somedata\":\"68656c6c6f776f726c64\"}]"), std::runtime_error);

    // Bad hex encoding of data output
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] [{\"data\":\"12345\"}]"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] [{\"data\":\"12345g\"}]"), std::runtime_error);

    // Data 81 bytes long
    BOOST_CHECK_NO_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] [{\"data\":\"010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081\"}]"));
}

BOOST_AUTO_TEST_CASE(rpc_format_monetary_values)
{
    BOOST_CHECK(ValueFromAmount(0LL).write() == "0.00000000");
    BOOST_CHECK(ValueFromAmount(1LL).write() == "0.00000001");
    BOOST_CHECK(ValueFromAmount(17622195LL).write() == "0.17622195");
    BOOST_CHECK(ValueFromAmount(50000000LL).write() == "0.50000000");
    BOOST_CHECK(ValueFromAmount(89898989LL).write() == "0.89898989");
    BOOST_CHECK(ValueFromAmount(100000000LL).write() == "1.00000000");
    BOOST_CHECK(ValueFromAmount(2099999999999990LL).write() == "20999999.99999990");
    BOOST_CHECK(ValueFromAmount(2099999999999999LL).write() == "20999999.99999999");

    BOOST_CHECK_EQUAL(ValueFromAmount(0).write(), "0.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount((COIN/10000)*123456789).write(), "12345.67890000");
    BOOST_CHECK_EQUAL(ValueFromAmount(-COIN).write(), "-1.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(-COIN/10).write(), "-0.10000000");

    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*100000000).write(), "100000000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*10000000).write(), "10000000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*1000000).write(), "1000000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*100000).write(), "100000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*10000).write(), "10000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*1000).write(), "1000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*100).write(), "100.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*10).write(), "10.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN).write(), "1.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/10).write(), "0.10000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/100).write(), "0.01000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/1000).write(), "0.00100000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/10000).write(), "0.00010000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/100000).write(), "0.00001000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/1000000).write(), "0.00000100");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/10000000).write(), "0.00000010");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/100000000).write(), "0.00000001");

    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::max()).write(), "92233720368.54775807");
    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::max() - 1).write(), "92233720368.54775806");
    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::max() - 2).write(), "92233720368.54775805");
    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::max() - 3).write(), "92233720368.54775804");
    // ...
    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::min() + 3).write(), "-92233720368.54775805");
    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::min() + 2).write(), "-92233720368.54775806");
    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::min() + 1).write(), "-92233720368.54775807");
    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::min()).write(), "-92233720368.54775808");
}

static UniValue ValueFromString(const std::string& str) noexcept
{
    UniValue value;
    value.setNumStr(str);
    return value;
}

BOOST_AUTO_TEST_CASE(rpc_parse_monetary_values)
{
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("-0.00000001")), UniValue);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0")), 0LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.00000000")), 0LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.00000001")), 1LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.17622195")), 17622195LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.5")), 50000000LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.50000000")), 50000000LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.89898989")), 89898989LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("1.00000000")), 100000000LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("20999999.9999999")), 2099999999999990LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("20999999.99999999")), 2099999999999999LL);

    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("1e-8")), COIN/100000000);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.1e-7")), COIN/100000000);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.01e-6")), COIN/100000000);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.00000000000000000000000000000000000001e+30")), 1);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.0000000000000000000000000000000000000000000000000000000000000000000000000001e+68")), COIN/100000000);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("10000000000000000000000000000000000000000000000000000000000000000e-64")), COIN);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000e64")), COIN);

    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("1e-9")), UniValue); //should fail
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("0.000000019")), UniValue); //should fail
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.00000001000000")), 1LL); //should pass, cut trailing 0
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("19e-9")), UniValue); //should fail
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.19e-6")), 19); //should pass, leading 0 is present
    BOOST_CHECK_EXCEPTION(AmountFromValue(".19e-6"), UniValue, HasJSON(R"({"code":-3,"message":"Invalid amount"})")); //should fail, no leading 0

    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("92233720368.54775808")), UniValue); //overflow error
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("1e+11")), UniValue); //overflow error
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("1e11")), UniValue); //overflow error signless
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("93e+9")), UniValue); //overflow error
}

BOOST_AUTO_TEST_CASE(rpc_ban)
{
    BOOST_CHECK_NO_THROW(CallRPC(std::string("clearbanned")));

    UniValue r;
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 127.0.0.0 add")));
    BOOST_CHECK_THROW(r = CallRPC(std::string("setban 127.0.0.0:8334")), std::runtime_error); //portnumber for setban not allowed
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    UniValue ar = r.get_array();
    UniValue o1 = ar[0].get_obj();
    UniValue adr = o1.find_value("address");
    BOOST_CHECK_EQUAL(adr.get_str(), "127.0.0.0/32");
    BOOST_CHECK_NO_THROW(CallRPC(std::string("setban 127.0.0.0 remove")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    BOOST_CHECK_EQUAL(ar.size(), 0U);

    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 127.0.0.0/24 add 9907731200 true")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = o1.find_value("address");
    int64_t banned_until{o1.find_value("banned_until").getInt<int64_t>()};
    BOOST_CHECK_EQUAL(adr.get_str(), "127.0.0.0/24");
    BOOST_CHECK_EQUAL(banned_until, 9907731200); // absolute time check

    BOOST_CHECK_NO_THROW(CallRPC(std::string("clearbanned")));

    auto now = 10'000s;
    SetMockTime(now);
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 127.0.0.0/24 add 200")));
    SetMockTime(now += 2s);
    const int64_t time_remaining_expected{198};
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = o1.find_value("address");
    banned_until = o1.find_value("banned_until").getInt<int64_t>();
    const int64_t ban_created{o1.find_value("ban_created").getInt<int64_t>()};
    const int64_t ban_duration{o1.find_value("ban_duration").getInt<int64_t>()};
    const int64_t time_remaining{o1.find_value("time_remaining").getInt<int64_t>()};
    BOOST_CHECK_EQUAL(adr.get_str(), "127.0.0.0/24");
    BOOST_CHECK_EQUAL(banned_until, time_remaining_expected + now.count());
    BOOST_CHECK_EQUAL(ban_duration, banned_until - ban_created);
    BOOST_CHECK_EQUAL(time_remaining, time_remaining_expected);

    // must throw an exception because 127.0.0.1 is in already banned subnet range
    BOOST_CHECK_THROW(r = CallRPC(std::string("setban 127.0.0.1 add")), std::runtime_error);

    BOOST_CHECK_NO_THROW(CallRPC(std::string("setban 127.0.0.0/24 remove")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    BOOST_CHECK_EQUAL(ar.size(), 0U);

    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 127.0.0.0/255.255.0.0 add")));
    BOOST_CHECK_THROW(r = CallRPC(std::string("setban 127.0.1.1 add")), std::runtime_error);

    BOOST_CHECK_NO_THROW(CallRPC(std::string("clearbanned")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    BOOST_CHECK_EQUAL(ar.size(), 0U);


    BOOST_CHECK_THROW(r = CallRPC(std::string("setban test add")), std::runtime_error); //invalid IP

    //IPv6 tests
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban FE80:0000:0000:0000:0202:B3FF:FE1E:8329 add")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = o1.find_value("address");
    BOOST_CHECK_EQUAL(adr.get_str(), "fe80::202:b3ff:fe1e:8329/128");

    BOOST_CHECK_NO_THROW(CallRPC(std::string("clearbanned")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 2001:db8::/ffff:fffc:0:0:0:0:0:0 add")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = o1.find_value("address");
    BOOST_CHECK_EQUAL(adr.get_str(), "2001:db8::/30");

    BOOST_CHECK_NO_THROW(CallRPC(std::string("clearbanned")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 2001:4d48:ac57:400:cacf:e9ff:fe1d:9c63/128 add")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = o1.find_value("address");
    BOOST_CHECK_EQUAL(adr.get_str(), "2001:4d48:ac57:400:cacf:e9ff:fe1d:9c63/128");
}

BOOST_AUTO_TEST_CASE(rpc_convert_values_generatetoaddress)
{
    UniValue result;

    BOOST_CHECK_NO_THROW(result = RPCConvertValues("generatetoaddress", {"101", "mkESjLZW66TmHhiFX8MCaBjrhZ543PPh9a"}));
    BOOST_CHECK_EQUAL(result[0].getInt<int>(), 101);
    BOOST_CHECK_EQUAL(result[1].get_str(), "mkESjLZW66TmHhiFX8MCaBjrhZ543PPh9a");

    BOOST_CHECK_NO_THROW(result = RPCConvertValues("generatetoaddress", {"101", "mhMbmE2tE9xzJYCV9aNC8jKWN31vtGrguU"}));
    BOOST_CHECK_EQUAL(result[0].getInt<int>(), 101);
    BOOST_CHECK_EQUAL(result[1].get_str(), "mhMbmE2tE9xzJYCV9aNC8jKWN31vtGrguU");

    BOOST_CHECK_NO_THROW(result = RPCConvertValues("generatetoaddress", {"1", "mkESjLZW66TmHhiFX8MCaBjrhZ543PPh9a", "9"}));
    BOOST_CHECK_EQUAL(result[0].getInt<int>(), 1);
    BOOST_CHECK_EQUAL(result[1].get_str(), "mkESjLZW66TmHhiFX8MCaBjrhZ543PPh9a");
    BOOST_CHECK_EQUAL(result[2].getInt<int>(), 9);

    BOOST_CHECK_NO_THROW(result = RPCConvertValues("generatetoaddress", {"1", "mhMbmE2tE9xzJYCV9aNC8jKWN31vtGrguU", "9"}));
    BOOST_CHECK_EQUAL(result[0].getInt<int>(), 1);
    BOOST_CHECK_EQUAL(result[1].get_str(), "mhMbmE2tE9xzJYCV9aNC8jKWN31vtGrguU");
    BOOST_CHECK_EQUAL(result[2].getInt<int>(), 9);
}

BOOST_AUTO_TEST_CASE(rpc_convert_values_importdrivechaindeposit)
{
    static constexpr const char* TXID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    static constexpr const char* BLOCK_HASH = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    static constexpr const char* ADDRESS = "elements1qexample";

    UniValue positional;
    BOOST_CHECK_NO_THROW(positional = RPCConvertValues(
        "importdrivechaindeposit", {TXID, "7", BLOCK_HASH, ADDRESS, "100000", "42"}));
    BOOST_CHECK_EQUAL(positional[0].get_str(), TXID);
    BOOST_CHECK_EQUAL(positional[1].getInt<int64_t>(), 7);
    BOOST_CHECK_EQUAL(positional[2].get_str(), BLOCK_HASH);
    BOOST_CHECK_EQUAL(positional[3].get_str(), ADDRESS);
    BOOST_CHECK_EQUAL(positional[4].getInt<int64_t>(), 100000);
    BOOST_CHECK_EQUAL(positional[5].getInt<int64_t>(), 42);

    UniValue named;
    BOOST_CHECK_NO_THROW(named = RPCConvertNamedValues(
        "importdrivechaindeposit",
        {std::string{"mainchain_txid="} + TXID,
         "mainchain_vout=7",
         std::string{"mainchain_block_hash="} + BLOCK_HASH,
         std::string{"address="} + ADDRESS,
         "value_sats=100000",
         "fee_sats=42"}));
    BOOST_CHECK_EQUAL(named["mainchain_txid"].get_str(), TXID);
    BOOST_CHECK_EQUAL(named["mainchain_vout"].getInt<int64_t>(), 7);
    BOOST_CHECK_EQUAL(named["mainchain_block_hash"].get_str(), BLOCK_HASH);
    BOOST_CHECK_EQUAL(named["address"].get_str(), ADDRESS);
    BOOST_CHECK_EQUAL(named["value_sats"].getInt<int64_t>(), 100000);
    BOOST_CHECK_EQUAL(named["fee_sats"].getInt<int64_t>(), 42);
    const auto committed = RPCConvertValues("importdrivechaindeposit",
        {TXID, "7", BLOCK_HASH, ADDRESS, "100000", "0", "1000"});
    BOOST_CHECK_EQUAL(committed[6].getInt<int64_t>(), 1000);
    const auto destination = RPCConvertValues("getdrivechaindepositdestination", {ADDRESS, "1000"});
    BOOST_CHECK_EQUAL(destination[1].getInt<int64_t>(), 1000);
}

BOOST_AUTO_TEST_CASE(rpc_convert_values_native_drivechain_withdrawal)
{
    static constexpr const char* TXID =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    static constexpr const char* BLOCK_HASH =
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    UniValue send;
    BOOST_CHECK_NO_THROW(send = RPCConvertValues(
        "sendtomainchain", {"tb1qexample", "1.25", "false", "true", "0.00001"}));
    BOOST_CHECK_EQUAL(send[0].get_str(), "tb1qexample");
    BOOST_CHECK_EQUAL(send[1].get_real(), 1.25);
    BOOST_CHECK_EQUAL(send[2].get_bool(), false);
    BOOST_CHECK_EQUAL(send[3].get_bool(), true);
    BOOST_CHECK_EQUAL(send[4].get_real(), 0.00001);

    UniValue build;
    BOOST_CHECK_NO_THROW(build = RPCConvertValues(
        "getdrivechainwithdrawalbundle", {TXID, "7", BLOCK_HASH, "3"}));
    BOOST_CHECK_EQUAL(build[0].get_str(), TXID);
    BOOST_CHECK_EQUAL(build[1].getInt<int>(), 7);
    BOOST_CHECK_EQUAL(build[2].get_str(), BLOCK_HASH);
    BOOST_CHECK_EQUAL(build[3].getInt<int>(), 3);

    UniValue verify;
    BOOST_CHECK_NO_THROW(verify = RPCConvertValues(
        "verifydrivechainwithdrawalbundle", {"010203", BLOCK_HASH, "6"}));
    BOOST_CHECK_EQUAL(verify[0].get_str(), "010203");
    BOOST_CHECK_EQUAL(verify[1].get_str(), BLOCK_HASH);
    BOOST_CHECK_EQUAL(verify[2].getInt<int>(), 6);

    UniValue submit;
    BOOST_CHECK_NO_THROW(submit = RPCConvertNamedValues(
        "submitdrivechainwithdrawal",
        {std::string{"txid="} + TXID,
         "vout=7",
         std::string{"blockhash="} + BLOCK_HASH,
         "minconfirmations=6"}));
    BOOST_CHECK_EQUAL(submit["txid"].get_str(), TXID);
    BOOST_CHECK_EQUAL(submit["vout"].getInt<int>(), 7);
    BOOST_CHECK_EQUAL(submit["blockhash"].get_str(), BLOCK_HASH);
    BOOST_CHECK_EQUAL(submit["minconfirmations"].getInt<int>(), 6);
}

static UniValue ExecuteWithdrawalRPC(node::NodeContext& node, const std::string& method,
                                    const std::vector<std::string>& args)
{
    JSONRPCRequest request;
    request.context = &node;
    request.strMethod = method;
    request.params = RPCConvertValues(method, args);
    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
    return tableRPC.execute(request);
}

BOOST_AUTO_TEST_CASE(withdrawal_rpc_disabled_and_parameter_precedence)
{
    BOOST_REQUIRE(!Params().GetConsensus().DrivechainWithdrawalValidationEnabled());
    const std::string hash(64, '0');
    for (const std::string method : {"getdrivechainwithdrawalbundle", "submitdrivechainwithdrawal"}) {
        for (const std::string vout : {"0", "1", "4294967294"}) for (const std::string depth : {"0", "1", "100001"}) {
            BOOST_CHECK_EXCEPTION(ExecuteWithdrawalRPC(m_node, method, {hash,vout,hash,depth}), UniValue,
                HasJSON("{\"code\":-32601,\"message\":\"Native BIP300 withdrawals are not enabled on this network\"}"));
        }
        for (const std::string vout : {"-9223372036854775808", "-1", "4294967295", "4294967296", "9223372036854775807"}) {
            BOOST_CHECK_EXCEPTION(ExecuteWithdrawalRPC(m_node, method, {hash,vout,hash,"1"}), UniValue,
                HasJSON("{\"code\":-8,\"message\":\"vout is outside the canonical uint32 range\"}"));
        }
    }
    for (const std::string encoded : {"", "0", "not-hex"}) {
        BOOST_CHECK_EXCEPTION(ExecuteWithdrawalRPC(m_node,"verifydrivechainwithdrawalbundle",{encoded,hash,"1"}), UniValue,
            HasJSON("{\"code\":-22,\"message\":\"blinded_m6 must be canonical hexadecimal\"}"));
    }
}

struct EnabledWithdrawalRPCSetup : TestingSetup {
    EnabledWithdrawalRPCSetup() : TestingSetup(ChainTypeMetaFrom("elements")) {}
};

struct EmptyElementsRPCSetup : ChainTestingSetup {
    EmptyElementsRPCSetup() : ChainTestingSetup(ChainTypeMetaFrom("elements"))
    {
        LOCK(cs_main);
        m_node.chainman->InitializeChainstate(m_node.mempool.get());
    }
};

BOOST_FIXTURE_TEST_CASE(bmm_context_missing_tip, EmptyElementsRPCSetup)
{
    {
        LOCK(cs_main);
        BOOST_REQUIRE(Params().GetConsensus().drivechain_slot);
        BOOST_REQUIRE(m_node.chainman->ActiveChain().Tip()==nullptr);
    }
    CRPCTable table;
    RegisterMiningRPCCommands(table);
    JSONRPCRequest request;
    request.context=&m_node;
    request.strMethod="getbmmconsensuscontext";
    request.params=UniValue(UniValue::VARR);
    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
    BOOST_CHECK_EXCEPTION(table.execute(request), UniValue,
        HasJSON("{\"code\":-1,\"message\":\"active sidechain tip is unavailable\"}"));
}

BOOST_FIXTURE_TEST_CASE(usdd_snapshot_missing_tip, EmptyElementsRPCSetup)
{
    {
        LOCK(cs_main);
        BOOST_REQUIRE(m_node.chainman->ActiveChain().Tip() == nullptr);
    }
    CRPCTable table;
    RegisterBlockchainRPCCommands(table);
    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
    for (const std::string method : {"getusddwithdrawalaccumulator", "getusddwithdrawalproof"}) {
        JSONRPCRequest request;
        request.context = &m_node;
        request.strMethod = method;
        request.params = UniValue(UniValue::VARR);
        if (method == "getusddwithdrawalproof") request.params.push_back(0);
        BOOST_CHECK_EXCEPTION(table.execute(request), UniValue,
            HasJSON("{\"code\":-5,\"message\":\"Block is not in the active chain\"}"));
    }
}

BOOST_FIXTURE_TEST_CASE(bmm_context_native_preflight, EnabledWithdrawalRPCSetup)
{
    BOOST_REQUIRE(Params().GetConsensus().drivechain_slot);
    {
        LOCK(cs_main);
        const auto* tip{m_node.chainman->ActiveChain().Tip()};
        BOOST_REQUIRE(tip);
        BOOST_REQUIRE_EQUAL(tip->nHeight, 0);
    }
    const auto rejected = [&](const char* message) {
        BOOST_CHECK_EXCEPTION(ExecuteWithdrawalRPC(m_node,"getbmmconsensuscontext",{}), UniValue,
            [&](const UniValue& error) {
                return error["code"].getInt<int>() == RPC_MISC_ERROR && error["message"].get_str() == message;
            });
    };
    // Admission rejects genesis before parent replay or RPC.
    rejected("active sidechain tip has no authenticated native BMM anchor");
}

BOOST_FIXTURE_TEST_CASE(ecx_state_utxo_eligibility, EnabledWithdrawalRPCSetup)
{
    const auto txid = Txid::FromUint256(uint256S("7131"));
    BOOST_CHECK_EXCEPTION(ExecuteWithdrawalRPC(m_node, "getecxstateutxoroot", {txid.GetHex(), "-1"}),
        UniValue, HasJSON("{\"code\":-8,\"message\":\"vout must be nonnegative\"}"));
    BOOST_CHECK_EXCEPTION(ExecuteWithdrawalRPC(m_node, "getecxstateutxoroot", {txid.GetHex(), "0"}),
        UniValue, HasJSON("{\"code\":-5,\"message\":\"ECX singleton UTXO not found\"}"));
    for (unsigned variant = 0; variant < 5; ++variant) {
        CTxOut output{Params().GetConsensus().pegged_asset, 1,
            CScript() << OP_1 << std::vector<unsigned char>(32, 1)};
        if (variant == 1) output.nAsset.vchCommitment.assign(33, 10);
        if (variant == 2) output.nValue.vchCommitment.assign(33, 8);
        if (variant == 3) output.nNonce.vchCommitment.assign(33, 2);
        if (variant == 4) output.scriptPubKey = CScript() << OP_TRUE;
        {
            LOCK(cs_main);
            m_node.chainman->ActiveChainstate().CoinsTip().AddCoin(
                COutPoint{txid, variant}, Coin{output, 0, false}, false);
        }
        const auto result = ExecuteWithdrawalRPC(m_node, "getecxstateutxoroot",
            {txid.GetHex(), std::to_string(variant)});
        BOOST_CHECK_EQUAL(result["eligible"].get_bool(), variant == 0);
        BOOST_CHECK_EQUAL(result["height"].getInt<int>(), 0);
        BOOST_CHECK_EQUAL(result["root"].get_str().size(), 64);
    }
    {
        LOCK(cs_main);
        m_node.chainman->ActiveChainstate().CoinsTip().AddCoin(COutPoint{txid, 5},
            Coin{CTxOut{Params().GetConsensus().pegged_asset, 1, CScript{}}, 0, false}, false);
    }
    BOOST_CHECK_EXCEPTION(ExecuteWithdrawalRPC(m_node, "getecxstateutxoroot", {txid.GetHex(), "5"}),
        UniValue, HasJSON("{\"code\":-5,\"message\":\"ECX singleton UTXO not found\"}"));
}

BOOST_FIXTURE_TEST_CASE(ecx_context_missing_tip, EmptyElementsRPCSetup)
{
    BOOST_CHECK_EXCEPTION(ExecuteWithdrawalRPC(m_node, "getecxconsensuscontext", {}),
        UniValue, HasJSON("{\"code\":-1,\"message\":\"active sidechain tip is unavailable\"}"));
}

BOOST_FIXTURE_TEST_CASE(peg_event_default_request, EnabledWithdrawalRPCSetup)
{
    const auto result = ExecuteWithdrawalRPC(m_node,"getdrivechainpegevents",{});
    BOOST_CHECK_EQUAL(result["range"]["start_height"].getInt<int>(),0);
    BOOST_CHECK_EQUAL(result["range"]["end_height"].getInt<int>(),0);
    BOOST_CHECK_EQUAL(result["sidechain_tip"]["height"].getInt<int>(),0);
    BOOST_CHECK(result["events"].isArray());
}

BOOST_FIXTURE_TEST_CASE(peg_event_missing_tip_before_range_or_l1, EmptyElementsRPCSetup)
{
    for (const std::string include : {"false","true"}) {
        BOOST_CHECK_EXCEPTION(ExecuteWithdrawalRPC(m_node,"getdrivechainpegevents",{"-1","0",include}),
            UniValue, HasJSON("{\"code\":-1,\"message\":\"Sidechain tip is unavailable\"}"));
    }
}

BOOST_FIXTURE_TEST_CASE(ecx_context_missing_snapshot, EnabledWithdrawalRPCSetup)
{
    BOOST_CHECK_EXCEPTION(ExecuteWithdrawalRPC(m_node, "getecxconsensuscontext", {}),
        UniValue, HasJSON("{\"code\":-1,\"message\":\"active tip has no complete ECX consensus context\"}"));
}

BOOST_AUTO_TEST_CASE(bmm_context_missing_state)
{
    BOOST_REQUIRE(!Params().GetConsensus().drivechain_slot);
    BOOST_CHECK_EXCEPTION(ExecuteWithdrawalRPC(m_node,"getbmmconsensuscontext",{}), UniValue,
        HasJSON("{\"code\":-1,\"message\":\"authenticated BMM parent-chain state is missing\"}"));
}

BOOST_AUTO_TEST_CASE(withdrawal_required_facts_preserve_effect_order)
{
    for (unsigned outcomes = 0; outcomes < 8; ++outcomes) {
        for (unsigned fault = 0; fault <= 3; ++fault) {
            std::vector<unsigned> actual, expected;
            const auto run = [&](bool haskell, std::vector<unsigned>& trace) {
                const auto fact = [&](unsigned step) {
                    trace.push_back(step);
                    if (step == fault) throw std::runtime_error("fact unavailable");
                    return (outcomes & (1U << step)) != 0;
                };
                try {
                    return static_cast<int>(haskell
                        ? drivechain::haskell::ParentReplayAll<3>({
                            [&] { return fact(0); }, [&] { return fact(1); }, [&] { return fact(2); }})
                        : fact(0) && fact(1) && fact(2));
                } catch (const std::runtime_error&) {
                    return -1;
                }
            };
            const int reference = run(false, expected);
            BOOST_CHECK_EQUAL(run(true, actual), reference);
            BOOST_CHECK(actual == expected);
        }
    }
}

BOOST_FIXTURE_TEST_CASE(usdd_proof_admission, EnabledWithdrawalRPCSetup)
{
    const auto reject = [&](const std::vector<std::string>& args, int code, const char* message) {
        BOOST_CHECK_EXCEPTION(ExecuteWithdrawalRPC(m_node, "getusddwithdrawalproof", args), UniValue,
            [&](const UniValue& error) {
                const bool matches = error["code"].getInt<int>() == code && error["message"].get_str() == message;
                BOOST_CHECK_MESSAGE(matches, "expected " << message << "; received " << error.write());
                return matches;
            });
    };
    reject({"-1", "not-a-hash"}, RPC_INVALID_PARAMETER, "Withdrawal index must not be negative");
    reject({"0", std::string(64, '0')}, RPC_INVALID_ADDRESS_OR_KEY, "Block is not in the active chain");
    BOOST_CHECK_EXCEPTION(ExecuteWithdrawalRPC(m_node, "getusddwithdrawalaccumulator", {std::string(64, '0')}),
        UniValue, HasJSON("{\"code\":-5,\"message\":\"Block is not in the active chain\"}"));

    LOCK(cs_main);
    auto* tip = m_node.chainman->ActiveChain().Tip();
    BOOST_REQUIRE(tip);
    // This fixture owns the chain. Always restore the index, including failures.
    struct Restore {
        CBlockIndex& tip;
        decltype(tip.m_usdd_withdrawal_accumulator) saved;
        ~Restore() { tip.m_usdd_withdrawal_accumulator = saved; }
    } restore{*tip, tip->m_usdd_withdrawal_accumulator};
    tip->m_usdd_withdrawal_accumulator.reset();
    reject({"0"}, RPC_INTERNAL_ERROR, "Withdrawal accumulator unavailable; reindex required");
    BOOST_CHECK_EXCEPTION(ExecuteWithdrawalRPC(m_node, "getusddwithdrawalaccumulator", {}),
        UniValue, HasJSON("{\"code\":-32603,\"message\":\"Withdrawal accumulator unavailable; reindex required\"}"));
    tip->m_usdd_withdrawal_accumulator.emplace();
    const auto snapshot = ExecuteWithdrawalRPC(m_node,"getusddwithdrawalaccumulator",{});
    BOOST_CHECK_EQUAL(snapshot["blockhash"].get_str(),tip->GetBlockHash().GetHex());
    BOOST_CHECK_EQUAL(snapshot["height"].getInt<int>(),tip->nHeight);
    BOOST_CHECK_EQUAL(snapshot["count"].getInt<uint64_t>(),0U);
    BOOST_CHECK_EQUAL(snapshot["root"].get_str(),HexStr(tip->m_usdd_withdrawal_accumulator->root));
    BOOST_CHECK(!snapshot["authorizing"].get_bool());
    reject({"0"}, RPC_INVALID_PARAMETER, "Withdrawal index is outside this accumulator");
    tip->m_usdd_withdrawal_accumulator->count = 10'001;
    reject({"10001"}, RPC_INVALID_PARAMETER, "Withdrawal index is outside this accumulator");
    for (int repeat = 0; repeat < 2; ++repeat) {
        reject({"10000"}, RPC_MISC_ERROR,
            "Proof reconstruction exceeds the safe RPC limit; use a dedicated permissionless indexer");
    }
    tip->m_usdd_withdrawal_accumulator->count = 10'000;
    // The fixture has no running RPC service. Reaching its interruption point
    // proves the inclusive limit passed admission without starting global RPC.
    BOOST_REQUIRE(!IsRPCRunning());
    reject({"9999"}, RPC_CLIENT_NOT_CONNECTED, "Shutting down");
}

BOOST_FIXTURE_TEST_CASE(usdd_history_rpc, TestChain100Setup)
{
    LOCK(cs_main);
    CChain& chain = m_node.chainman->ActiveChain();
    using State = decltype(chain.Tip()->m_usdd_withdrawal_accumulator);
    struct Restore {
        std::vector<std::pair<CBlockIndex*, State>> records;
        ~Restore() { for (auto& [index, state] : records) index->m_usdd_withdrawal_accumulator = state; }
    } restore;
    BOOST_REQUIRE_EQUAL(chain.Height(), 100);
    for (int height = 0; height <= chain.Height(); ++height) {
        auto* index = chain[height];
        restore.records.emplace_back(index, index->m_usdd_withdrawal_accumulator);
        index->m_usdd_withdrawal_accumulator.emplace();
    }
    chain.Tip()->m_usdd_withdrawal_accumulator->count = 1;
    const auto reject = [&](int code, const char* message) {
        BOOST_CHECK_EXCEPTION(ExecuteWithdrawalRPC(m_node, "getusddwithdrawalproof", {"0"}), UniValue,
            [&](const UniValue& error) {
                return error["code"].getInt<int>() == code && error["message"].get_str() == message;
            });
    };
    chain[50]->m_usdd_withdrawal_accumulator.reset();
    reject(RPC_INTERNAL_ERROR, "Discontinuous withdrawal accumulator; reindex required");
    chain[50]->m_usdd_withdrawal_accumulator.emplace();
    chain[50]->m_usdd_withdrawal_accumulator->count = 1;
    reject(RPC_INTERNAL_ERROR, "Nonmonotonic withdrawal accumulator; reindex required");
    for (int height = 51; height < chain.Height(); ++height) {
        chain[height]->m_usdd_withdrawal_accumulator->count = 1;
    }
    BOOST_REQUIRE(!IsRPCRunning());
    reject(RPC_CLIENT_NOT_CONNECTED, "Shutting down");
}

BOOST_FIXTURE_TEST_CASE(withdrawal_rpc_enabled_preflight, EnabledWithdrawalRPCSetup)
{
    static_assert(drivechain::WITHDRAWAL_READ_CONFIRMATIONS == 1);
    static_assert(drivechain::WITHDRAWAL_SUBMIT_CONFIRMATIONS == 6);
    static_assert(drivechain::WITHDRAWAL_PROOF_SECONDS == 10);
    static_assert(drivechain::WITHDRAWAL_PROOF_INTERRUPT_INTERVAL == 4096);
    for (int height : {0,1,4095,4096,4097,8192,INT32_MAX}) {
        BOOST_CHECK_EQUAL(height % drivechain::WITHDRAWAL_PROOF_INTERRUPT_INTERVAL == 0,
                          (height & 0x0fff) == 0);
    }
    BOOST_REQUIRE(Params().GetConsensus().DrivechainWithdrawalValidationEnabled());
    const std::string hash(64, '0');
    for (const std::string method : {"getdrivechainwithdrawalbundle", "submitdrivechainwithdrawal"}) {
        for (const std::string depth : {"-1", "0", "100001"}) {
            BOOST_CHECK_EXCEPTION(ExecuteWithdrawalRPC(m_node,method,{hash,"0",hash,depth}), UniValue,
                HasJSON("{\"code\":-8,\"message\":\"minconfirmations must be between 1 and 100000\"}"));
        }
        for (const std::string depth : {"1", "6", "100000"}) {
            BOOST_CHECK_EXCEPTION(ExecuteWithdrawalRPC(m_node,method,{hash,"0",hash,depth}), UniValue,
                HasJSON("{\"code\":-5,\"message\":\"Confirming block is not in the active Elements chain\"}"));
        }
    }
    const std::string genesis = Params().GetConsensus().hashGenesisBlock.GetHex();
    BOOST_CHECK_EXCEPTION(ExecuteWithdrawalRPC(m_node,"getdrivechainwithdrawalbundle",{hash,"0",genesis}), UniValue,
        HasJSON("{\"code\":-5,\"message\":\"Withdrawal transaction is not in the specified confirming block\"}"));
    BOOST_CHECK_EXCEPTION(ExecuteWithdrawalRPC(m_node,"submitdrivechainwithdrawal",{hash,"0",genesis}), UniValue,
        HasJSON("{\"code\":-25,\"message\":\"Native withdrawal burn has 1 confirmation(s); 6 required\"}"));
    const auto& genesis_block = Params().GenesisBlock();
    BOOST_REQUIRE(!genesis_block.vtx.empty());
    const auto genesis_txid = genesis_block.vtx.front()->GetHash().GetHex();
    BOOST_CHECK_EXCEPTION(ExecuteWithdrawalRPC(m_node,"getdrivechainwithdrawalbundle",{hash,"0",genesis,"1"}), UniValue,
        HasJSON("{\"code\":-5,\"message\":\"Withdrawal transaction is not in the specified confirming block\"}"));
    BOOST_CHECK_EXCEPTION(ExecuteWithdrawalRPC(m_node,"getdrivechainwithdrawalbundle",{genesis_txid,"1",genesis,"1"}), UniValue,
        HasJSON("{\"code\":-8,\"message\":\"Withdrawal vout is outside the transaction\"}"));
    BOOST_CHECK_EXCEPTION(ExecuteWithdrawalRPC(m_node,"getdrivechainwithdrawalbundle",{genesis_txid,"0",genesis,"1"}), UniValue,
        HasJSON("{\"code\":-25,\"message\":\"Requested outpoint is not the transaction's sole canonical native withdrawal burn\"}"));
    for (const std::string method : {"getdrivechainwithdrawalbundle", "submitdrivechainwithdrawal"}) {
        BOOST_CHECK_EXCEPTION(ExecuteWithdrawalRPC(m_node,method,{hash,"0",genesis,"2"}), UniValue,
            HasJSON("{\"code\":-25,\"message\":\"Native withdrawal burn has 1 confirmation(s); 2 required\"}"));
    }
    {
        LOCK(cs_main);
        CBlockIndex* tip = m_node.chainman->ActiveChain().Tip();
        BOOST_REQUIRE(tip);
        BOOST_REQUIRE_EQUAL(tip->GetBlockHash().GetHex(),genesis);
        struct RestoreStatus {
            CBlockIndex& index;
            uint32_t status;
            ~RestoreStatus() { index.nStatus = status; }
        } restore{*tip,tip->nStatus};
        tip->nStatus &= ~BLOCK_HAVE_DATA;
        for (const std::string method : {"getdrivechainwithdrawalbundle", "submitdrivechainwithdrawal"}) {
            BOOST_CHECK_EXCEPTION(ExecuteWithdrawalRPC(m_node,method,{hash,"0",genesis,"1"}), UniValue,
                HasJSON("{\"code\":-1,\"message\":\"Confirming block data is unavailable on this pruned node\"}"));
        }
    }
}

BOOST_FIXTURE_TEST_CASE(withdrawal_rpc_external_bundle_domains, EnabledWithdrawalRPCSetup)
{
    const auto& consensus = Params().GetConsensus();
    BOOST_REQUIRE(consensus.drivechain_slot);
    CTxOut burn;
    std::string error;
    const CScript destination = CScript() << OP_0 << std::vector<unsigned char>(20,1);
    BOOST_REQUIRE(drivechain::BuildNativeWithdrawalOutput(consensus.pegged_asset,
        Params().ParentGenesisBlockHash(),destination,100000,1000,burn,&error));
    drivechain::NativeWithdrawal withdrawal;
    BOOST_REQUIRE(drivechain::ParseNativeWithdrawalOutput(burn,nullptr,consensus.pegged_asset,
        Params().ParentGenesisBlockHash(),withdrawal,&error));
    const std::string unknown_block(64,'0');
    for (int alteration : {0,1,2}) {
        drivechain::NativeWithdrawalM6 bundle;
        BOOST_REQUIRE(drivechain::BuildNativeWithdrawalM6(
            alteration == 1 ? uint256S("01") : consensus.hashGenesisBlock,
            alteration == 2 ? static_cast<uint8_t>(*consensus.drivechain_slot+1) : *consensus.drivechain_slot,
            uint256S("42"),0,withdrawal,bundle,&error));
        const auto encoded = HexStr(bundle.legacy_serialization);
        if (alteration) {
            for (const std::string depth : {"0","1"}) {
                BOOST_CHECK_EXCEPTION(ExecuteWithdrawalRPC(m_node,"verifydrivechainwithdrawalbundle",{encoded,unknown_block,depth}), UniValue,
                    HasJSON("{\"code\":-25,\"message\":\"blinded M6 references a different Elements chain or sidechain slot\"}"));
            }
        } else {
            BOOST_CHECK_EXCEPTION(ExecuteWithdrawalRPC(m_node,"verifydrivechainwithdrawalbundle",
                {encoded,consensus.hashGenesisBlock.GetHex()}), UniValue,
                HasJSON("{\"code\":-25,\"message\":\"Native withdrawal burn has 1 confirmation(s); 6 required\"}"));
            BOOST_CHECK_EXCEPTION(ExecuteWithdrawalRPC(m_node,"verifydrivechainwithdrawalbundle",{encoded,unknown_block,"1"}), UniValue,
                HasJSON("{\"code\":-5,\"message\":\"Confirming block is not in the active Elements chain\"}"));
            BOOST_CHECK_EXCEPTION(ExecuteWithdrawalRPC(m_node,"verifydrivechainwithdrawalbundle",{encoded,unknown_block,"0"}), UniValue,
                HasJSON("{\"code\":-8,\"message\":\"minconfirmations must be between 1 and 100000\"}"));
        }
    }
    const std::string oversized(2*(drivechain::NATIVE_WITHDRAWAL_MAX_M6_LEGACY_SIZE+1),'0');
    BOOST_CHECK_EXCEPTION(ExecuteWithdrawalRPC(m_node,"verifydrivechainwithdrawalbundle",{oversized,unknown_block,"0"}), UniValue,
        HasJSON("{\"code\":-22,\"message\":\"blinded_m6 exceeds the canonical native-withdrawal serialization bound\"}"));
    for (size_t size : {size_t{1},size_t{drivechain::NATIVE_WITHDRAWAL_MAX_M6_LEGACY_SIZE}}) {
        BOOST_CHECK_EXCEPTION(ExecuteWithdrawalRPC(m_node,"verifydrivechainwithdrawalbundle",
            {std::string(2*size,'0'),unknown_block,"0"}),UniValue,
            HasJSON("{\"code\":-22,\"message\":\"blinded M6 does not have the bounded legacy zero-input/three-output frame\"}"));
    }
    Sidechain::Bitcoin::CMutableTransaction no_reference;
    no_reference.vout.emplace_back(0,CScript() << OP_RETURN);
    BOOST_CHECK_EXCEPTION(ExecuteWithdrawalRPC(m_node,"verifydrivechainwithdrawalbundle",
        {HexStr(drivechain::SerializeNativeWithdrawalM6Legacy(no_reference)),unknown_block,"0"}), UniValue,
        HasJSON("{\"code\":-22,\"message\":\"blinded M6 does not have the bounded legacy zero-input/three-output frame\"}"));
}

BOOST_AUTO_TEST_CASE(rpc_convert_values_usdd_withdrawal_proof)
{
    static constexpr const char* BLOCK_HASH =
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    UniValue positional;
    BOOST_CHECK_NO_THROW(positional = RPCConvertValues(
        "getusddwithdrawalproof", {"7", BLOCK_HASH}));
    BOOST_CHECK_EQUAL(positional[0].getInt<int>(), 7);
    BOOST_CHECK_EQUAL(positional[1].get_str(), BLOCK_HASH);

    UniValue named;
    BOOST_CHECK_NO_THROW(named = RPCConvertNamedValues(
        "getusddwithdrawalproof", {"index=7", std::string{"blockhash="} + BLOCK_HASH}));
    BOOST_CHECK_EQUAL(named["index"].getInt<int>(), 7);
    BOOST_CHECK_EQUAL(named["blockhash"].get_str(), BLOCK_HASH);
}

BOOST_AUTO_TEST_CASE(rpc_getblockstats_calculate_percentiles_by_weight)
{
    int64_t total_weight = 200;
    std::vector<std::pair<CAmount, int64_t>> feerates;
    feerates.reserve(200);
    CAmount result[NUM_GETBLOCKSTATS_PERCENTILES] = { 0 };

    for (int64_t i = 0; i < 100; i++) {
        feerates.emplace_back(1 ,1);
    }

    for (int64_t i = 0; i < 100; i++) {
        feerates.emplace_back(2 ,1);
    }

    CalculatePercentilesByWeight(result, feerates, total_weight);
    BOOST_CHECK_EQUAL(result[0], 1);
    BOOST_CHECK_EQUAL(result[1], 1);
    BOOST_CHECK_EQUAL(result[2], 1);
    BOOST_CHECK_EQUAL(result[3], 2);
    BOOST_CHECK_EQUAL(result[4], 2);

    // Test with more pairs, and two pairs overlapping 2 percentiles.
    total_weight = 100;
    CAmount result2[NUM_GETBLOCKSTATS_PERCENTILES] = { 0 };
    feerates.clear();

    feerates.emplace_back(1, 9);
    feerates.emplace_back(2 , 16); //10th + 25th percentile
    feerates.emplace_back(4 ,50); //50th + 75th percentile
    feerates.emplace_back(5 ,10);
    feerates.emplace_back(9 ,15);  // 90th percentile

    CalculatePercentilesByWeight(result2, feerates, total_weight);

    BOOST_CHECK_EQUAL(result2[0], 2);
    BOOST_CHECK_EQUAL(result2[1], 2);
    BOOST_CHECK_EQUAL(result2[2], 4);
    BOOST_CHECK_EQUAL(result2[3], 4);
    BOOST_CHECK_EQUAL(result2[4], 9);

    // Same test as above, but one of the percentile-overlapping pairs is split in 2.
    total_weight = 100;
    CAmount result3[NUM_GETBLOCKSTATS_PERCENTILES] = { 0 };
    feerates.clear();

    feerates.emplace_back(1, 9);
    feerates.emplace_back(2 , 11); // 10th percentile
    feerates.emplace_back(2 , 5); // 25th percentile
    feerates.emplace_back(4 ,50); //50th + 75th percentile
    feerates.emplace_back(5 ,10);
    feerates.emplace_back(9 ,15); // 90th percentile

    CalculatePercentilesByWeight(result3, feerates, total_weight);

    BOOST_CHECK_EQUAL(result3[0], 2);
    BOOST_CHECK_EQUAL(result3[1], 2);
    BOOST_CHECK_EQUAL(result3[2], 4);
    BOOST_CHECK_EQUAL(result3[3], 4);
    BOOST_CHECK_EQUAL(result3[4], 9);

    // Test with one transaction spanning all percentiles.
    total_weight = 104;
    CAmount result4[NUM_GETBLOCKSTATS_PERCENTILES] = { 0 };
    feerates.clear();

    feerates.emplace_back(1, 100);
    feerates.emplace_back(2, 1);
    feerates.emplace_back(3, 1);
    feerates.emplace_back(3, 1);
    feerates.emplace_back(999999, 1);

    CalculatePercentilesByWeight(result4, feerates, total_weight);

    for (int64_t i = 0; i < NUM_GETBLOCKSTATS_PERCENTILES; i++) {
        BOOST_CHECK_EQUAL(result4[i], 1);
    }
}

// Make sure errors are triggered appropriately if parameters have the same names.
BOOST_AUTO_TEST_CASE(check_dup_param_names)
{
    enum ParamType { POSITIONAL, NAMED, NAMED_ONLY };
    auto make_rpc = [](std::vector<std::tuple<std::string, ParamType>> param_names) {
        std::vector<RPCArg> params;
        std::vector<RPCArg> options;
        auto push_options = [&] { if (!options.empty()) params.emplace_back(strprintf("options%i", params.size()), RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "", std::move(options)); };
        for (auto& [param_name, param_type] : param_names) {
            if (param_type == POSITIONAL) {
                push_options();
                params.emplace_back(std::move(param_name), RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "description");
            } else {
                options.emplace_back(std::move(param_name), RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "description", RPCArgOptions{.also_positional = param_type == NAMED});
            }
        }
        push_options();
        return RPCHelpMan{"method_name", "description", params, RPCResults{}, RPCExamples{""}};
    };

    // No errors if parameter names are unique.
    make_rpc({{"p1", POSITIONAL}, {"p2", POSITIONAL}});
    make_rpc({{"p1", POSITIONAL}, {"p2", NAMED}});
    make_rpc({{"p1", POSITIONAL}, {"p2", NAMED_ONLY}});
    make_rpc({{"p1", NAMED}, {"p2", POSITIONAL}});
    make_rpc({{"p1", NAMED}, {"p2", NAMED}});
    make_rpc({{"p1", NAMED}, {"p2", NAMED_ONLY}});
    make_rpc({{"p1", NAMED_ONLY}, {"p2", POSITIONAL}});
    make_rpc({{"p1", NAMED_ONLY}, {"p2", NAMED}});
    make_rpc({{"p1", NAMED_ONLY}, {"p2", NAMED_ONLY}});

    // Error if parameters names are duplicates, unless one parameter is
    // positional and the other is named and .also_positional is true.
    BOOST_CHECK_THROW(make_rpc({{"p1", POSITIONAL}, {"p1", POSITIONAL}}), NonFatalCheckError);
    make_rpc({{"p1", POSITIONAL}, {"p1", NAMED}});
    BOOST_CHECK_THROW(make_rpc({{"p1", POSITIONAL}, {"p1", NAMED_ONLY}}), NonFatalCheckError);
    make_rpc({{"p1", NAMED}, {"p1", POSITIONAL}});
    BOOST_CHECK_THROW(make_rpc({{"p1", NAMED}, {"p1", NAMED}}), NonFatalCheckError);
    BOOST_CHECK_THROW(make_rpc({{"p1", NAMED}, {"p1", NAMED_ONLY}}), NonFatalCheckError);
    BOOST_CHECK_THROW(make_rpc({{"p1", NAMED_ONLY}, {"p1", POSITIONAL}}), NonFatalCheckError);
    BOOST_CHECK_THROW(make_rpc({{"p1", NAMED_ONLY}, {"p1", NAMED}}), NonFatalCheckError);
    BOOST_CHECK_THROW(make_rpc({{"p1", NAMED_ONLY}, {"p1", NAMED_ONLY}}), NonFatalCheckError);

    // Make sure duplicate aliases are detected too.
    BOOST_CHECK_THROW(make_rpc({{"p1", POSITIONAL}, {"p2|p1", NAMED_ONLY}}), NonFatalCheckError);
}

BOOST_AUTO_TEST_CASE(help_example)
{
    // test different argument types
    const RPCArgList& args = {{"foo", "bar"}, {"b", true}, {"n", 1}};
    BOOST_CHECK_EQUAL(HelpExampleCliNamed("test", args), "> bitcoin-cli -named test foo=bar b=true n=1\n");
    BOOST_CHECK_EQUAL(HelpExampleRpcNamed("test", args), "> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"test\", \"params\": {\"foo\":\"bar\",\"b\":true,\"n\":1}}' -H 'content-type: application/json' http://127.0.0.1:8332/\n");

    // test shell escape
    BOOST_CHECK_EQUAL(HelpExampleCliNamed("test", {{"foo", "b'ar"}}), "> bitcoin-cli -named test foo='b'''ar'\n");
    BOOST_CHECK_EQUAL(HelpExampleCliNamed("test", {{"foo", "b\"ar"}}), "> bitcoin-cli -named test foo='b\"ar'\n");
    BOOST_CHECK_EQUAL(HelpExampleCliNamed("test", {{"foo", "b ar"}}), "> bitcoin-cli -named test foo='b ar'\n");

    // test object params
    UniValue obj_value(UniValue::VOBJ);
    obj_value.pushKV("foo", "bar");
    obj_value.pushKV("b", false);
    obj_value.pushKV("n", 1);
    BOOST_CHECK_EQUAL(HelpExampleCliNamed("test", {{"name", obj_value}}), "> bitcoin-cli -named test name='{\"foo\":\"bar\",\"b\":false,\"n\":1}'\n");
    BOOST_CHECK_EQUAL(HelpExampleRpcNamed("test", {{"name", obj_value}}), "> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"test\", \"params\": {\"name\":{\"foo\":\"bar\",\"b\":false,\"n\":1}}}' -H 'content-type: application/json' http://127.0.0.1:8332/\n");

    // test array params
    UniValue arr_value(UniValue::VARR);
    arr_value.push_back("bar");
    arr_value.push_back(false);
    arr_value.push_back(1);
    BOOST_CHECK_EQUAL(HelpExampleCliNamed("test", {{"name", arr_value}}), "> bitcoin-cli -named test name='[\"bar\",false,1]'\n");
    BOOST_CHECK_EQUAL(HelpExampleRpcNamed("test", {{"name", arr_value}}), "> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"test\", \"params\": {\"name\":[\"bar\",false,1]}}' -H 'content-type: application/json' http://127.0.0.1:8332/\n");

    // test types don't matter for shell
    BOOST_CHECK_EQUAL(HelpExampleCliNamed("foo", {{"arg", true}}), HelpExampleCliNamed("foo", {{"arg", "true"}}));

    // test types matter for Rpc
    BOOST_CHECK_NE(HelpExampleRpcNamed("foo", {{"arg", true}}), HelpExampleRpcNamed("foo", {{"arg", "true"}}));
}

static void CheckRpc(const std::vector<RPCArg>& params, const UniValue& args, RPCHelpMan::RPCMethodImpl test_impl)
{
    auto null_result{RPCResult{RPCResult::Type::NONE, "", "None"}};
    const RPCHelpMan rpc{"dummy", "dummy description", params, null_result, RPCExamples{""}, test_impl};
    JSONRPCRequest req;
    req.params = args;

    rpc.HandleRequest(req);
}

BOOST_AUTO_TEST_CASE(rpc_arg_helper)
{
    constexpr bool DEFAULT_BOOL = true;
    constexpr auto DEFAULT_STRING = "default";
    constexpr uint64_t DEFAULT_UINT64_T = 3;

    //! Parameters with which the RPCHelpMan is instantiated
    const std::vector<RPCArg> params{
        // Required arg
        {"req_int", RPCArg::Type::NUM, RPCArg::Optional::NO, ""},
        {"req_str", RPCArg::Type::STR, RPCArg::Optional::NO, ""},
        // Default arg
        {"def_uint64_t", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_UINT64_T}, ""},
        {"def_string", RPCArg::Type::STR, RPCArg::Default{DEFAULT_STRING}, ""},
        {"def_bool", RPCArg::Type::BOOL, RPCArg::Default{DEFAULT_BOOL}, ""},
        // Optional arg without default
        {"opt_double", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, ""},
        {"opt_string", RPCArg::Type::STR, RPCArg::Optional::OMITTED, ""}
    };

    //! Check that `self.Arg` returns the same value as the `request.params` accessors
    RPCHelpMan::RPCMethodImpl check_positional = [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            BOOST_CHECK_EQUAL(self.Arg<int>("req_int"), request.params[0].getInt<int>());
            BOOST_CHECK_EQUAL(self.Arg<std::string>("req_str"), request.params[1].get_str());
            BOOST_CHECK_EQUAL(self.Arg<uint64_t>("def_uint64_t"), request.params[2].isNull() ? DEFAULT_UINT64_T : request.params[2].getInt<uint64_t>());
            BOOST_CHECK_EQUAL(self.Arg<std::string>("def_string"), request.params[3].isNull() ? DEFAULT_STRING : request.params[3].get_str());
            BOOST_CHECK_EQUAL(self.Arg<bool>("def_bool"), request.params[4].isNull() ? DEFAULT_BOOL : request.params[4].get_bool());
            if (!request.params[5].isNull()) {
                BOOST_CHECK_EQUAL(self.MaybeArg<double>("opt_double").value(), request.params[5].get_real());
            } else {
                BOOST_CHECK(!self.MaybeArg<double>("opt_double"));
            }
            if (!request.params[6].isNull()) {
                BOOST_CHECK(self.MaybeArg<std::string>("opt_string"));
                BOOST_CHECK_EQUAL(*self.MaybeArg<std::string>("opt_string"), request.params[6].get_str());
            } else {
                BOOST_CHECK(!self.MaybeArg<std::string>("opt_string"));
            }
            return UniValue{};
        };
    CheckRpc(params, UniValue{JSON(R"([5, "hello", null, null, null, null, null])")}, check_positional);
    CheckRpc(params, UniValue{JSON(R"([5, "hello", 4, "test", true, 1.23, "world"])")}, check_positional);
}

BOOST_AUTO_TEST_SUITE_END()
