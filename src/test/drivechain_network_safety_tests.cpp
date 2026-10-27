// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <bitcoin-build-config.h>
#include <common/args.h>
#include <consensus/params.h>
#include <elements_drivechain_identity.h>
#include <init.h>
#include <haskell/bridge.h>
#include <mainchainrpc.h>
#include <rpc/util.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>
#include <cstdlib>

#ifdef ENABLE_WALLET
namespace wallet { RPCHelpMan sendtomainchain_legacy(); }
#endif

BOOST_AUTO_TEST_SUITE(drivechain_network_safety_tests)

BOOST_AUTO_TEST_CASE(bidding_requires_independent_explicit_opt_in)
{
    ArgsManager args;
    BOOST_CHECK(!IsDrivechainAutomaticBiddingEnabled(args));
    args.ForceSetArg("-drivechainbmmwallet", "funded-wallet");
    args.ForceSetArg("-drivechainbmmbid", "250");
    args.ForceSetArg("-acceptbetanettestprofile", "1");
    BOOST_CHECK(!IsDrivechainAutomaticBiddingEnabled(args));
    args.ForceSetArg("-drivechainl1blocksync", "1");
    BOOST_CHECK(IsDrivechainAutomaticBiddingEnabled(args));
    args.ForceSetArg("-drivechainl1blocksync", "0");
    BOOST_CHECK(!IsDrivechainAutomaticBiddingEnabled(args));
}

BOOST_AUTO_TEST_CASE(fresh_profile_does_not_reuse_the_existing_proposal_exception)
{
    BOOST_REQUIRE(!ElementsDrivechainIdentity::BETANET_EXISTING_ELEMENTS_TEST_PROFILE);
    ArgsManager args;
    std::string error;
    BOOST_CHECK(CheckDrivechainTestProfileOptIn(args, &error));
    BOOST_CHECK(error.empty());
    args.ForceSetArg("-acceptbetanettestprofile", "0");
    BOOST_CHECK(CheckDrivechainTestProfileOptIn(args, nullptr));
    args.ForceSetArg("-acceptbetanettestprofile", "1");
    BOOST_CHECK(CheckDrivechainTestProfileOptIn(args, nullptr));
    BOOST_CHECK(!IsDrivechainAutomaticBiddingEnabled(args));
}

BOOST_AUTO_TEST_CASE(parent_network_rejects_shared_ancestry_and_malformed_replies)
{
    Consensus::Params consensus{};
    consensus.hashGenesisBlock = uint256S(ElementsDrivechainIdentity::GENESIS_HASH);
    const std::string correct{"00000000000000030101ba5cfea54b22becc79f95dc6040beb76e01dd9d04042"};
    UniValue response{correct};
    unsigned calls{0};
    bool unavailable{false};
    const auto request = [&](const std::string& method, const UniValue& params) {
        ++calls;
        BOOST_CHECK_EQUAL(method, "getblockhash");
        BOOST_REQUIRE_EQUAL(params.size(), 1U);
        BOOST_CHECK_EQUAL(params[0].getInt<int>(), 967680);
        if (unavailable) throw std::runtime_error("parent unavailable");
        return response;
    };
    std::string error;
    std::atomic<uint64_t> epoch{42};
    const auto check = [&](std::string* diagnostic) {
        return VerifyDrivechainParentRpcNetwork(consensus, request, epoch, diagnostic);
    };
    DrivechainAnchorSnapshot snapshot{24, uint256::ONE, 42};
    BOOST_CHECK(check(&error));
    BOOST_CHECK_EQUAL(epoch.load(), 42U);
    BOOST_CHECK(snapshot.EpochMatches(24, epoch.load()));
    for (const auto& rejected : {UniValue(), UniValue(UniValue::VARR), UniValue(967680),
         UniValue(std::string{ElementsDrivechainIdentity::PARENT_GENESIS}),
         UniValue(std::string(64, '0')), UniValue(correct.substr(1)),
         UniValue(" " + correct), UniValue(correct + "00")}) {
        response = rejected;
        epoch.store(42);
        BOOST_CHECK(!check(&error));
        BOOST_CHECK_EQUAL(epoch.load(), 0U);
        BOOST_CHECK(!snapshot.EpochMatches(24, epoch.load()));
        BOOST_CHECK(error.find("post-fork block") != std::string::npos);
        BOOST_CHECK(!check(nullptr));
    }
    unavailable = true;
    epoch.store(42);
    BOOST_CHECK(!check(&error));
    BOOST_CHECK_EQUAL(epoch.load(), 0U);
    BOOST_CHECK(error.find("parent unavailable") != std::string::npos);
    unavailable = false;
    response = UniValue(correct);
    BOOST_CHECK(check(nullptr));
    BOOST_CHECK_EQUAL(epoch.load(), 0U); // Identity alone must not revive replay authorization.
    BOOST_CHECK(!snapshot.EpochMatches(24, epoch.load()));
    response = UniValue(std::string(64, '1'));
    BOOST_CHECK(!check(nullptr));
    // The successful earlier call must not cache authorization for a new source.
    const auto before = calls;
    consensus.hashGenesisBlock = uint256::ONE;
    BOOST_CHECK(check(nullptr));
    BOOST_CHECK_EQUAL(calls, before); // Independent fixture networks are unchanged.
}

BOOST_AUTO_TEST_CASE(parent_network_preserves_exception_scope_and_exact_identity)
{
    Consensus::Params consensus{};
    consensus.hashGenesisBlock = uint256S(ElementsDrivechainIdentity::GENESIS_HASH);
    const std::string correct{"00000000000000030101ba5cfea54b22becc79f95dc6040beb76e01dd9d04042"};
    std::atomic<uint64_t> epoch{42};
    std::string error{"unchanged"};
    const auto nonstandard = [](const std::string&, const UniValue&) -> UniValue { throw 7; };
    BOOST_CHECK_THROW(VerifyDrivechainParentRpcNetwork(consensus,nonstandard,epoch,&error),int);
    BOOST_CHECK_EQUAL(epoch.load(),42U);
    BOOST_CHECK_EQUAL(error,"unchanged");
    const auto unavailable = [](const std::string&, const UniValue&) -> UniValue { throw std::domain_error("offline"); };
    BOOST_CHECK(!VerifyDrivechainParentRpcNetwork(consensus,unavailable,epoch,&error));
    BOOST_CHECK_EQUAL(epoch.load(),0U);
    BOOST_CHECK_EQUAL(error,"cannot verify ECX Betanet parent RPC identity: offline");
    for (size_t i = 0; i < correct.size(); ++i) {
        auto altered = correct;
        altered[i] = altered[i] == '0' ? '1' : '0';
        const auto wrong = [&](const std::string&, const UniValue&) { return UniValue(altered); };
        epoch.store(42);
        BOOST_CHECK(!VerifyDrivechainParentRpcNetwork(consensus,wrong,epoch,&error));
        BOOST_CHECK_EQUAL(epoch.load(),0U);
        BOOST_CHECK_EQUAL(error,"parent RPC does not serve the ECX Betanet post-fork block at height 967680");
    }
    // Canonical case is significant even when the numeric hash is identical.
    auto upper = correct;
    upper[upper.find('a')] = 'A';
    BOOST_CHECK(!VerifyDrivechainParentRpcNetwork(consensus,
        [&](const std::string&,const UniValue&) { return UniValue(upper); },epoch,&error));
    consensus.hashGenesisBlock = uint256::ONE;
    BOOST_CHECK(VerifyDrivechainParentRpcNetwork(consensus,nonstandard,epoch,&error));
    BOOST_CHECK_EQUAL(epoch.load(),0U);
}

BOOST_AUTO_TEST_CASE(parent_network_native_http_transport)
{
    Consensus::Params consensus{};
    consensus.hashGenesisBlock = uint256::ONE;
    std::atomic<uint64_t> epoch{42};
    std::string error{"unchanged"};
    BOOST_CHECK(VerifyDrivechainParentRpcNetwork(consensus, epoch, &error));
    BOOST_CHECK_EQUAL(epoch.load(), 42U);
    BOOST_CHECK_EQUAL(error, "unchanged");

    // The isolated Python HTTP harness supplies this endpoint; ordinary unit
    // runs never contact a parent node or use a wallet.
    const char* port = std::getenv("ELEMENTS_TEST_PARENT_RPC_PORT");
    if (!port) return;
    BasicTestingSetup setup{ChainType::REGTEST};
    gArgs.ForceSetArg("-mainchainrpchost", "127.0.0.1");
    gArgs.ForceSetArg("-mainchainrpcport", port);
    gArgs.ForceSetArg("-mainchainrpctimeout", "1");
    if (const char* cookie = std::getenv("ELEMENTS_TEST_PARENT_RPC_COOKIE")) {
        gArgs.ForceSetArg("-mainchainrpccookiefile", cookie);
    } else {
        gArgs.ForceSetArg("-mainchainrpcuser", "fixture");
        gArgs.ForceSetArg("-mainchainrpcpassword", "fixture");
    }
    const char* expected_error = std::getenv("ELEMENTS_TEST_PARENT_RPC_ERROR");
    BOOST_REQUIRE(expected_error);
    consensus.hashGenesisBlock = uint256S(ElementsDrivechainIdentity::GENESIS_HASH);
    const bool expected = std::string{expected_error}.empty();
    BOOST_CHECK_EQUAL(VerifyDrivechainParentRpcNetwork(consensus, epoch, &error), expected);
    BOOST_CHECK_EQUAL(epoch.load(), expected ? 42U : 0U);
    if (expected) BOOST_CHECK_EQUAL(error, "unchanged");
    else BOOST_CHECK(error.find(expected_error) != std::string::npos);
}

BOOST_AUTO_TEST_CASE(parent_active_hash_preserves_native_failure_and_stops_callbacks)
{
    namespace hs = drivechain::haskell;
    for (const bool standard : {false, true}) {
        std::vector<uint32_t> calls;
        const hs::NativeWorkflow native = [&](uint32_t step, uint64_t index, std::span<const unsigned char> input) {
            calls.push_back(step);
            BOOST_CHECK_EQUAL(index, 0U);
            BOOST_CHECK(input.empty());
            if (step == 7) return std::vector<unsigned char>{1, 2, 0, 0, 0, 0, 0, 0, 0};
            BOOST_REQUIRE_EQUAL(step, 1001U);
            if (standard) throw std::domain_error("original transport error");
            throw 7;
        };
        const auto run = [&] { hs::RunReplayStore(hs::ReplayStoreWorkflow::ACTIVE_HASH, native); };
        if (standard) {
            BOOST_CHECK_EXCEPTION(run(), std::domain_error, [](const std::domain_error& error) {
                return std::string{error.what()} == "original transport error";
            });
        } else {
            BOOST_CHECK_EXCEPTION(run(), int, [](int error) { return error == 7; });
        }
        const std::vector<uint32_t> expected{7, 1001};
        BOOST_CHECK_EQUAL_COLLECTIONS(calls.begin(), calls.end(), expected.begin(), expected.end());
    }
}

BOOST_AUTO_TEST_CASE(network_failure_is_unavailable_not_an_orphaned_anchor)
{
    namespace hs = drivechain::haskell;
    Consensus::Params consensus{};
    consensus.hashGenesisBlock = uint256S(ElementsDrivechainIdentity::GENESIS_HASH);
    // Exercise the same short-circuit at ANCHOR_RECONCILE's first read. Without
    // the network guard a wrong network's hash mismatch is misclassified as a reorg.
    const auto check = [&](int source, bool guarded, bool parent_matches) {
        BOOST_TEST_CONTEXT("source=" << source << ", guarded=" << guarded << ", parent_matches=" << parent_matches) {
            std::atomic<uint64_t> epoch{42};
            unsigned anchor_reads{0};
            const auto request = [&](const std::string&, const UniValue&) -> UniValue {
                if (source == 2) throw std::runtime_error("parent unavailable");
                return UniValue(source == 0 || (source == 3 && anchor_reads == 0) ?
                    "00000000000000030101ba5cfea54b22becc79f95dc6040beb76e01dd9d04042" :
                    std::string(64, '0'));
            };
            DrivechainAnchorStatus status;
            try {
                status = static_cast<DrivechainAnchorStatus>(hs::ParentReplayStore(
                    hs::ReplayStoreFlow::ANCHOR_RECONCILE, [&](uint32_t step) -> uint32_t {
                        if (step == 1) {
                            if (guarded && !VerifyDrivechainParentRpcNetwork(consensus, request, epoch, nullptr)) return 0;
                            ++anchor_reads;
                            return 1;
                        }
                        if (step == 2) return parent_matches;
                        if (step == 4) { ++anchor_reads; return 1; }
                        if (step == 5) return 0; // The successor height contains a different hash.
                        if (step == 3 || step == 6) {
                            if (guarded && !VerifyDrivechainParentRpcNetwork(consensus, request, epoch, nullptr))
                                throw std::runtime_error("parent RPC network unavailable before rollback");
                            return static_cast<uint32_t>(DrivechainAnchorStatus::ORPHANED);
                        }
                        BOOST_FAIL("Unexpected anchor action");
                        return 0;
                    }));
            } catch (const std::exception&) {
                status = DrivechainAnchorStatus::UNAVAILABLE;
            }
            const bool rejected = guarded && source != 0;
            BOOST_CHECK(status == (rejected ? DrivechainAnchorStatus::UNAVAILABLE : DrivechainAnchorStatus::ORPHANED));
            BOOST_CHECK_EQUAL(anchor_reads, guarded && (source == 1 || source == 2) ? 0U : (parent_matches ? 2U : 1U));
            BOOST_CHECK_EQUAL(epoch.load(), rejected ? 0U : 42U);
        }
    };
    for (const int source : {0, 1, 2, 3}) {
        for (const bool guarded : {false, true}) {
            for (const bool parent_matches : {false, true}) check(source, guarded, parent_matches);
        }
    }
}

#ifdef ENABLE_WALLET
BOOST_AUTO_TEST_CASE(legacy_withdrawal_rejects_before_wallet_lookup)
{
    // No wallet context exists. Any wallet access before rejection would fail.
    JSONRPCRequest request;
    request.strMethod = "sendtomainchain";
    for (const bool subtract : {false, true}) {
        for (const bool verbose : {false, true}) {
            request.params = UniValue(UniValue::VARR);
            request.params.push_back("hex:0014" + std::string(40, '1'));
            request.params.push_back("0.1");
            request.params.push_back(subtract);
            request.params.push_back(verbose);
            BOOST_CHECK_EXCEPTION(wallet::sendtomainchain_legacy().HandleRequest(request), UniValue,
                [](const UniValue& error) {
                    return error["code"].getInt<int>() == RPC_METHOD_NOT_FOUND &&
                        error["message"].get_str().find("no funds were burned") != std::string::npos;
                });
        }
    }
}
#endif

BOOST_AUTO_TEST_SUITE_END()
