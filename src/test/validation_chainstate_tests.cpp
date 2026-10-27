// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include <chainparams.h>
#include <consensus/validation.h>
#include <node/kernel_notifications.h>
#include <node/blockstorage.h>
#include <node/utxo_snapshot.h>
#include <random.h>
#include <rpc/blockchain.h>
#include <rpc/server.h>
#include <sync.h>
#include <streams.h>
#include <test/util/chainstate.h>
#include <test/util/coins.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <validation.h>

#include <vector>
#include <map>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(validation_chainstate_tests, ChainTestingSetup)

BOOST_FIXTURE_TEST_CASE(child_checkpoint_rpc_exports_source_blocks, TestChain100Setup)
{
    JSONRPCRequest request;
    request.context = &m_node;
    request.strMethod = "getalphacheckpointevidence";
    request.params = UniValue(UniValue::VARR);
    uint256 tip;
    {
        LOCK(cs_main);
        tip = m_node.chainman->ActiveChain().Tip()->GetBlockHash();
    }
    request.params.push_back(tip.GetHex());
    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
    const auto result = tableRPC.execute(request);
    BOOST_CHECK(!result["proof_ready"].get_bool());
    BOOST_CHECK_EQUAL(result["blockhash"].get_str(), tip.GetHex());
    BOOST_CHECK_EQUAL(result["headers"].size(), 101U);
    BOOST_CHECK(result["coins"].size() > 0);
    BOOST_CHECK(result["coin_source_blocks"].size() > 0);
    BOOST_CHECK(result["withdrawals"].isNull());
    {
        LOCK(cs_main);
        auto& manager = *m_node.chainman;
        const auto encode = [](const auto& value) {
            DataStream bytes;
            bytes << value;
            return HexStr(bytes);
        };
        auto sources = node::PrepareChildCheckpointSources(manager);
        for (int height = 0; height <= sources.height; ++height) {
            CBlock block;
            BOOST_REQUIRE(manager.m_blockman.ReadBlock(block, *manager.ActiveChain()[height]));
            BOOST_CHECK_EQUAL(result["headers"][height].get_str(), encode(TX_WITH_WITNESS(block.GetBlockHeader())));
        }
        std::map<std::string, UniValue> exported_coins;
        for (const auto& item : result["coins"].getValues())
            BOOST_REQUIRE(exported_coins.emplace(item["outpoint"].get_str(), item).second);
        size_t count{0};
        for (auto& cursor = sources.coins; cursor->Valid(); cursor->Next()) {
            COutPoint outpoint;
            Coin coin;
            BOOST_REQUIRE(cursor->GetKey(outpoint));
            BOOST_REQUIRE(cursor->GetValue(coin));
            const auto found = exported_coins.find(encode(outpoint));
            BOOST_REQUIRE(found != exported_coins.end());
            const auto& item = found->second;
            BOOST_CHECK_EQUAL(item["height"].getInt<uint32_t>(), static_cast<uint32_t>(coin.nHeight));
            BOOST_CHECK_EQUAL(item["coinbase"].get_bool(), coin.IsCoinBase());
            BOOST_CHECK_EQUAL(item["output"].get_str(), encode(coin.out));
            ++count;
        }
        BOOST_CHECK_EQUAL(exported_coins.size(), count);
    }
    mineBlocks(1);
    BOOST_CHECK_THROW(tableRPC.execute(request), UniValue); // exact tip required
}

BOOST_FIXTURE_TEST_CASE(child_checkpoint_sources_stay_at_one_tip, TestChain100Setup)
{
    auto& manager = *Assert(m_node.chainman);
    const auto claim = std::make_pair(uint256::ONE, COutPoint{Txid::FromUint256(uint256S("02")), 9});
    auto sources = [&] {
        LOCK(cs_main);
        manager.ActiveChainstate().CoinsTip().SetPeginSpent(claim, true);
        return node::PrepareChildCheckpointSources(manager);
    }();
    BOOST_CHECK_EQUAL(sources.height, 100);
    BOOST_REQUIRE(sources.spent_claims->Valid());
    BOOST_CHECK(sources.spent_claims->GetKey() == claim);
    BOOST_CHECK(sources.coins->GetBestBlock() == sources.block_hash);
    BOOST_CHECK(sources.spent_claims->GetBestBlock() == sources.block_hash);
    const auto read_coins = [](CCoinsViewCursor& cursor) {
        std::map<COutPoint, std::vector<std::byte>> coins;
        while (cursor.Valid()) {
            COutPoint outpoint;
            Coin coin;
            BOOST_REQUIRE(cursor.GetKey(outpoint));
            BOOST_REQUIRE(cursor.GetValue(coin));
            DataStream bytes;
            bytes << coin;
            coins.emplace(outpoint, std::vector<std::byte>{bytes.begin(), bytes.end()});
            cursor.Next();
        }
        return coins;
    };
    auto baseline = WITH_LOCK(cs_main, return node::PrepareChildCheckpointSources(manager));
    const auto before = read_coins(*baseline.coins);
    BOOST_REQUIRE(!before.empty());
    mineBlocks(1);
    auto after = [&] {
        LOCK(cs_main);
        manager.ActiveChainstate().CoinsTip().SetPeginSpent(claim, false);
        return node::PrepareChildCheckpointSources(manager);
    }();
    BOOST_CHECK_EQUAL(after.height, 101);
    BOOST_CHECK(after.block_hash != sources.block_hash);
    BOOST_CHECK(!after.spent_claims->Valid());
    BOOST_CHECK(sources.spent_claims->GetKey() == claim);
    BOOST_CHECK(read_coins(*sources.coins) == before);
    BOOST_CHECK(sources.block_hash == baseline.block_hash);

    LOCK(cs_main);
    auto& state = manager.ActiveChainstate();
    auto* tip = state.m_chain.Tip();
    state.CoinsTip().SetPeginSpent(claim, true);
    const auto rejects_without_flush = [&](const char* message) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        BOOST_CHECK_EXCEPTION(node::PrepareChildCheckpointSources(manager), std::runtime_error,
            [&](const auto& error) { return error.what() == std::string(message); });
        BOOST_CHECK(!state.CoinsDB().IsPeginSpent(claim));
        BOOST_CHECK(state.CoinsTip().IsPeginSpent(claim));
    };
    state.CoinsTip().SetBestBlock(uint256::ONE);
    rejects_without_flush("Child checkpoint cache/active tip mismatch");
    state.CoinsTip().SetBestBlock(tip->GetBlockHash());
    const auto final = node::PrepareChildCheckpointSources(manager);
    BOOST_CHECK(state.CoinsDB().IsPeginSpent(claim));
    BOOST_CHECK(final.block_hash == tip->GetBlockHash());
}

//! Test resizing coins-related Chainstate caches during runtime.
//!
BOOST_AUTO_TEST_CASE(validation_chainstate_resize_caches)
{
    ChainstateManager& manager = *Assert(m_node.chainman);
    CTxMemPool& mempool = *Assert(m_node.mempool);
    Chainstate& c1 = WITH_LOCK(cs_main, return manager.InitializeChainstate(&mempool));
    c1.InitCoinsDB(
        /*cache_size_bytes=*/1 << 23, /*in_memory=*/true, /*should_wipe=*/false);
    WITH_LOCK(::cs_main, c1.InitCoinsCache(1 << 23));
    BOOST_REQUIRE(c1.LoadGenesisBlock()); // Need at least one block loaded to be able to flush caches

    // Add a coin to the in-memory cache, upsize once, then downsize.
    {
        LOCK(::cs_main);
        const auto outpoint = AddTestCoin(m_rng, c1.CoinsTip());

        // Set a meaningless bestblock value in the coinsview cache - otherwise we won't
        // flush during ResizecoinsCaches() and will subsequently hit an assertion.
        c1.CoinsTip().SetBestBlock(m_rng.rand256());

        BOOST_CHECK(c1.CoinsTip().HaveCoinInCache(outpoint));

        c1.ResizeCoinsCaches(
            1 << 24,  // upsizing the coinsview cache
            1 << 22  // downsizing the coinsdb cache
        );

        // View should still have the coin cached, since we haven't destructed the cache on upsize.
        BOOST_CHECK(c1.CoinsTip().HaveCoinInCache(outpoint));

        c1.ResizeCoinsCaches(
            1 << 22,  // downsizing the coinsview cache
            1 << 23  // upsizing the coinsdb cache
        );

        // The view cache should be empty since we had to destruct to downsize.
        BOOST_CHECK(!c1.CoinsTip().HaveCoinInCache(outpoint));
    }
}

//! Test UpdateTip behavior for both active and background chainstates.
//!
//! When run on the background chainstate, UpdateTip should do a subset
//! of what it does for the active chainstate.
BOOST_FIXTURE_TEST_CASE(chainstate_update_tip, TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const auto get_notify_tip{[&]() {
        LOCK(m_node.notifications->m_tip_block_mutex);
        BOOST_REQUIRE(m_node.notifications->TipBlock());
        return *m_node.notifications->TipBlock();
    }};
    uint256 curr_tip = get_notify_tip();

    // Mine 10 more blocks, putting at us height 110 where a valid assumeutxo value can
    // be found.
    mineBlocks(10);

    // After adding some blocks to the tip, best block should have changed.
    BOOST_CHECK(get_notify_tip() != curr_tip);

    // Grab block 1 from disk; we'll add it to the background chain later.
    std::shared_ptr<CBlock> pblockone = std::make_shared<CBlock>();
    {
        LOCK(::cs_main);
        chainman.m_blockman.ReadBlock(*pblockone, *chainman.ActiveChain()[1]);
    }

    BOOST_REQUIRE(CreateAndActivateUTXOSnapshot(
        this, NoMalleation, /*reset_chainstate=*/ true));

    // Ensure our active chain is the snapshot chainstate.
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.IsSnapshotActive()));

    curr_tip = get_notify_tip();

    // Mine a new block on top of the activated snapshot chainstate.
    mineBlocks(1);  // Defined in TestChain100Setup.

    // After adding some blocks to the snapshot tip, best block should have changed.
    BOOST_CHECK(get_notify_tip() != curr_tip);

    curr_tip = get_notify_tip();

    BOOST_CHECK_EQUAL(chainman.GetAll().size(), 2);

    Chainstate& background_cs{*Assert([&]() -> Chainstate* {
        for (Chainstate* cs : chainman.GetAll()) {
            if (cs != &chainman.ActiveChainstate()) {
                return cs;
            }
        }
        return nullptr;
    }())};

    // Append the first block to the background chain.
    BlockValidationState state;
    CBlockIndex* pindex = nullptr;
    const CChainParams& chainparams = Params();
    bool newblock = false;

    // TODO: much of this is inlined from ProcessNewBlock(); just reuse PNB()
    // once it is changed to support multiple chainstates.
    {
        LOCK(::cs_main);
        bool checked = CheckBlock(*pblockone, state, chainparams.GetConsensus());
        BOOST_CHECK(checked);
        bool accepted = chainman.AcceptBlock(
            pblockone, state, &pindex, true, nullptr, &newblock, true);
        BOOST_CHECK(accepted);
    }

    // UpdateTip is called here
    bool block_added = background_cs.ActivateBestChain(state, pblockone);

    // Ensure tip is as expected
    BOOST_CHECK_EQUAL(background_cs.m_chain.Tip()->GetBlockHash(), pblockone->GetHash());

    // get_notify_tip() should be unchanged after adding a block to the background
    // validation chain.
    BOOST_CHECK(block_added);
    BOOST_CHECK_EQUAL(curr_tip, get_notify_tip());
}

BOOST_AUTO_TEST_SUITE_END()
