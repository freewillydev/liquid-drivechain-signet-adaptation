// Copyright (c) 2013-2019 The Elements Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <blind.h>
#include <blindpsbt.h>
#include <coins.h>
#include <consensus/tx_verify.h>
#include <issuance.h>
#include <random.h>
#include <uint256.h>
#include <validation.h>
#include <script/sigcache.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <secp256k1.h>

#include <array>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <streams.h>
#include <util/strencodings.h>
#include <thread>

// For elements serialization rules
struct ElementsSetup : public TestingSetup {
        ElementsSetup() : TestingSetup(ChainType::CUSTOM) {}
};

BOOST_FIXTURE_TEST_SUITE(blind_tests, ElementsSetup)

// Opt-in, stdin-only differential harness. Never print input transactions or
// private wallet data. Each line is one consensus-serialized transaction
// followed by a consensus-serialized vector of spent outputs.

// TODO: Make deterministic blinding wrapper function, test caching more exactly

BOOST_AUTO_TEST_CASE(blinding_fits_rpc_worker_stack)
{
    CKey recipient_key;
    CKey dummy_key;
    std::array<unsigned char, 32> recipient_secret{1, 2, 3};
    std::array<unsigned char, 32> dummy_secret{4, 5, 6};
    recipient_key.Set(recipient_secret.begin(), recipient_secret.end(), true);
    dummy_key.Set(dummy_secret.begin(), dummy_secret.end(), true);

    const CAsset asset(GetRandHash());
    CMutableTransaction tx;
    tx.vin.resize(2);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(ArithToUint256(1)), 0);
    tx.vin[1].prevout = COutPoint(Txid::FromUint256(ArithToUint256(2)), 0);
    tx.vout.emplace_back(asset, 100, CScript() << OP_TRUE);
    tx.vout.emplace_back(asset, 22, CScript());
    tx.vout.emplace_back(asset, 0, CScript() << OP_RETURN);

    std::vector<uint256> input_value_blinds(2);
    std::vector<uint256> input_asset_blinds(2);
    std::vector<CAsset> input_assets(2, asset);
    std::vector<CAmount> input_amounts{11, 111};
    std::vector<uint256> output_value_blinds;
    std::vector<uint256> output_asset_blinds;
    std::vector<CPubKey> output_pubkeys{
        recipient_key.GetPubKey(), CPubKey(), dummy_key.GetPubKey()};
    std::vector<CKey> no_issuance_keys;
    int blinded_outputs{-1};

    // On macOS std::thread uses the same approximately 512 KiB default stack
    // as an HTTP RPC worker. This call crashed before the blinding buffers were
    // moved to heap-backed storage.
    std::thread worker([&] {
        blinded_outputs = BlindTransaction(
            input_value_blinds,
            input_asset_blinds,
            input_assets,
            input_amounts,
            output_value_blinds,
            output_asset_blinds,
            output_pubkeys,
            no_issuance_keys,
            no_issuance_keys,
            tx);
    });
    worker.join();

    BOOST_CHECK_EQUAL(blinded_outputs, 2);
    BOOST_CHECK(tx.vout[0].nValue.IsCommitment());
    BOOST_CHECK(tx.vout[2].nValue.IsCommitment());
}

BOOST_AUTO_TEST_CASE(naive_blinding_test)
{
    BOOST_CHECK(InitRangeproofCache(DEFAULT_VALIDATION_CACHE_BYTES / 4));
    BOOST_CHECK(InitSurjectionproofCache(DEFAULT_VALIDATION_CACHE_BYTES / 4));

    CKey key1;
    CKey key2;
    CKey keyDummy;

    // Any asset id will do
    CAsset bitcoinID(GetRandHash());
    CAsset otherID(GetRandHash());
    CAsset unblinded_id;
    uint256 asset_blind;
    CScript op_true(OP_TRUE);
    std::vector<CKey> vDummy;

    unsigned char k1[32] = {1,2,3};
    unsigned char k2[32] = {22,33,44};
    unsigned char kDummy[32] = {133,144,155};
    key1.Set(&k1[0], &k1[32], true);
    key2.Set(&k2[0], &k2[32], true);
    keyDummy.Set(&kDummy[0], &kDummy[32], true);
    CPubKey pubkey1 = key1.GetPubKey();
    CPubKey pubkey2 = key2.GetPubKey();
    CPubKey pubkeyDummy = keyDummy.GetPubKey();

    uint256 blind3, blind4, blindDummy;

    std::vector<CTxOut> inputs;
    CTxOut btc_oo(bitcoinID, 11, CScript());
    CTxOut btc_ooo(bitcoinID, 111, CScript());
    CTxOut other_fzz(otherID, 500, CScript());
    CTxOut blind_ozz; // Will be computed later

    {
        inputs.clear();
        inputs.push_back(btc_oo);
        inputs.push_back(btc_ooo);

        // Build a transaction that spends 2 unblinded coins (11, 111), and produces a single blinded one (100) and fee (22).
        CMutableTransaction tx3;
        tx3.vin.resize(2);
        tx3.vin[0].prevout.hash = Txid::FromUint256(ArithToUint256(1));

        tx3.vin[0].prevout.n = 0;
        tx3.vin[1].prevout.hash = Txid::FromUint256(ArithToUint256(2));
        tx3.vin[1].prevout.n = 0;
        tx3.vout.resize(0);
        tx3.vout.emplace_back(bitcoinID, 100, CScript() << OP_TRUE);
        // Fee outputs are blank scriptpubkeys, and unblinded value/asset
        tx3.vout.emplace_back(bitcoinID, 22, CScript());
        BOOST_CHECK(VerifyAmounts(inputs, CTransaction(tx3), nullptr, false));

        // Malleate the output and check for correct handling of bad commitments
        // These will fail IsValid checks
        std::vector<unsigned char> asset_copy(tx3.vout[0].nAsset.vchCommitment);
        std::vector<unsigned char> value_copy(tx3.vout[0].nValue.vchCommitment);
        tx3.vout[0].nAsset.vchCommitment[0] = 122;
        BOOST_CHECK(!VerifyAmounts(inputs, CTransaction(tx3), nullptr, false));
        tx3.vout[0].nAsset.vchCommitment = asset_copy;
        tx3.vout[0].nValue.vchCommitment[0] = 122;
        BOOST_CHECK(!VerifyAmounts(inputs, CTransaction(tx3), nullptr, false));
        tx3.vout[0].nValue.vchCommitment = value_copy;

        // Make sure null values are handled correctly
        tx3.vout[0].nAsset.SetNull();
        BOOST_CHECK(!VerifyAmounts(inputs, CTransaction(tx3), nullptr, false));
        tx3.vout[0].nAsset.vchCommitment = asset_copy;
        tx3.vout[0].nValue.SetNull();
        BOOST_CHECK(!VerifyAmounts(inputs, CTransaction(tx3), nullptr, false));
        tx3.vout[0].nValue.vchCommitment = value_copy;

        // Bad nonce values will result in failure to deserialize
        tx3.vout[0].nNonce.SetNull();
        BOOST_CHECK(VerifyAmounts(inputs, CTransaction(tx3), nullptr, false));
        tx3.vout[0].nNonce.vchCommitment = tx3.vout[0].nValue.vchCommitment;
        BOOST_CHECK(!VerifyAmounts(inputs, CTransaction(tx3), nullptr, false));

        // Try to blind with a single non-fee output, which fails as its blinding factor ends up being zero.
        std::vector<uint256> input_blinds;
        std::vector<uint256> input_asset_blinds;
        std::vector<CAsset> input_assets;
        std::vector<CAmount> input_amounts;
        std::vector<uint256> output_blinds;
        std::vector<uint256> output_asset_blinds;
        std::vector<CPubKey> output_pubkeys;
        input_blinds.emplace_back();
        input_blinds.emplace_back();
        input_asset_blinds.emplace_back();
        input_asset_blinds.emplace_back();
        input_assets.push_back(bitcoinID);
        input_assets.push_back(bitcoinID);
        input_amounts.push_back(11);
        input_amounts.push_back(111);
        output_pubkeys.push_back(pubkey1);
        output_pubkeys.emplace_back();
        BOOST_CHECK(BlindTransaction(input_blinds, input_asset_blinds, input_assets, input_amounts, output_blinds, output_asset_blinds, output_pubkeys, vDummy, vDummy, tx3) == 0);

        // Add a dummy output. Must be unspendable since it's 0-valued.
        tx3.vout.emplace_back(bitcoinID, 0, CScript() << OP_RETURN);
        output_pubkeys.push_back(pubkeyDummy);
        BOOST_CHECK(BlindTransaction(input_blinds, input_asset_blinds, input_assets, input_amounts, output_blinds, output_asset_blinds, output_pubkeys, vDummy, vDummy, tx3) == 2);
        BOOST_CHECK(!tx3.vout[0].nValue.IsExplicit());
        BOOST_CHECK(!tx3.vout[2].nValue.IsExplicit());
        BOOST_CHECK(VerifyAmounts(inputs, CTransaction(tx3), nullptr, false));

        CAmount unblinded_amount;
        BOOST_CHECK(UnblindConfidentialPair(key2, tx3.vout[0].nValue, tx3.vout[0].nAsset, tx3.vout[0].nNonce, op_true, tx3.witness.vtxoutwit[0].vchRangeproof, unblinded_amount, blind3, unblinded_id, asset_blind) == 0);
        // Saving unblinded_id and asset_blind for later since we need for input
        BOOST_CHECK(UnblindConfidentialPair(key1, tx3.vout[0].nValue, tx3.vout[0].nAsset, tx3.vout[0].nNonce, op_true, tx3.witness.vtxoutwit[0].vchRangeproof, unblinded_amount, blind3, unblinded_id, asset_blind) == 1);
        BOOST_CHECK(unblinded_amount == 100);
        BOOST_CHECK(unblinded_id == bitcoinID);
        CAsset temp_asset;
        uint256 temp_asset_blinder;
        BOOST_CHECK(UnblindConfidentialPair(keyDummy, tx3.vout[2].nValue, tx3.vout[2].nAsset, tx3.vout[2].nNonce, CScript() << OP_RETURN, tx3.witness.vtxoutwit[2].vchRangeproof, unblinded_amount, blindDummy, temp_asset, temp_asset_blinder) == 1);
        BOOST_CHECK(unblinded_amount == 0);

        // Storing for next section
        BOOST_CHECK(tx3.vout[0].nValue.IsCommitment());
        BOOST_CHECK(tx3.vout[0].nAsset.IsCommitment());
        blind_ozz = tx3.vout[0];

        tx3.vout[1].nValue = CConfidentialValue(tx3.vout[1].nValue.GetAmount() - 1);
        BOOST_CHECK(!VerifyAmounts(inputs, CTransaction(tx3), nullptr, false));
    }

    {
        inputs.clear();
        inputs.push_back(btc_ooo);
        inputs.push_back(blind_ozz);

        // Build a transactions that spends an unblinded (111) and blinded (100) coin, and produces only unblinded coins (impossible)
        CMutableTransaction tx4;
        tx4.vin.resize(2);
        tx4.vin[0].prevout.hash = Txid::FromUint256(ArithToUint256(2));
        tx4.vin[0].prevout.n = 0;
        tx4.vin[1].prevout.hash = Txid::FromUint256(ArithToUint256(3));
        tx4.vin[1].prevout.n = 0;
        tx4.vout.emplace_back(bitcoinID, 30, CScript() << OP_TRUE);
        tx4.vout.emplace_back(bitcoinID, 40, CScript() << OP_TRUE);
        tx4.vout.emplace_back(bitcoinID, 111 + 100 - 30 - 40, CScript());
        BOOST_CHECK(!VerifyAmounts(inputs, CTransaction(tx4), nullptr, false)); // Spends a blinded coin with no blinded outputs to compensate.

        std::vector<uint256> input_blinds;
        std::vector<uint256> input_asset_blinds;
        std::vector<CAsset> input_assets;
        std::vector<CAmount> input_amounts;
        std::vector<uint256> output_blinds;
        std::vector<uint256> output_asset_blinds;
        std::vector<CPubKey> output_pubkeys;
        input_blinds.emplace_back();
        input_blinds.push_back(blind3);
        input_asset_blinds.emplace_back();
        input_asset_blinds.push_back(asset_blind);
        input_amounts.push_back(111);
        input_amounts.push_back(100);
        input_assets.push_back(unblinded_id);
        input_assets.push_back(unblinded_id);
        output_pubkeys.emplace_back();
        output_pubkeys.emplace_back();
        output_pubkeys.emplace_back();
        BOOST_CHECK(BlindTransaction(input_blinds, input_asset_blinds, input_assets, input_amounts, output_blinds, output_asset_blinds, output_pubkeys, vDummy, vDummy, tx4) == 0); // Blinds nothing
    }

    {
        inputs.clear();
        inputs.push_back(btc_ooo);
        inputs.push_back(blind_ozz);

        // Build a transactions that spends an unblinded (111) and blinded (100) coin, and produces a blinded (30), unblinded (40), and blinded (50) coin and fee (91)
        CMutableTransaction tx4;
        tx4.vin.resize(2);
        tx4.vin[0].prevout.hash = Txid::FromUint256(ArithToUint256(2));
        tx4.vin[0].prevout.n = 0;
        tx4.vin[1].prevout.hash = Txid::FromUint256(ArithToUint256(3));
        tx4.vin[1].prevout.n = 0;
        tx4.vout.emplace_back(bitcoinID, 30, CScript() << OP_TRUE);
        tx4.vout.emplace_back(bitcoinID, 40, CScript() << OP_TRUE);
        tx4.vout.emplace_back(bitcoinID, 50, CScript() << OP_TRUE);
        // Fee
        tx4.vout.emplace_back(bitcoinID, 111 + 100 - 30 - 40 - 50, CScript());
        BOOST_CHECK(!VerifyAmounts(inputs, CTransaction(tx4), nullptr, false)); // Spends a blinded coin with no blinded outputs to compensate.

        std::vector<uint256> input_blinds;
        std::vector<uint256> input_asset_blinds;
        std::vector<CAsset> input_assets;
        std::vector<CAmount> input_amounts;
        std::vector<uint256> output_blinds;
        std::vector<uint256> output_asset_blinds;
        std::vector<CPubKey> output_pubkeys;

        input_blinds.emplace_back();
        input_blinds.push_back(blind3);
        input_asset_blinds.emplace_back();
        input_asset_blinds.push_back(asset_blind);
        input_amounts.push_back(111);
        input_amounts.push_back(100);
        input_assets.push_back(unblinded_id);
        input_assets.push_back(unblinded_id);

        output_pubkeys.push_back(pubkey2);
        output_pubkeys.emplace_back();
        output_pubkeys.push_back(pubkey2);
        output_pubkeys.emplace_back();

        BOOST_CHECK(BlindTransaction(input_blinds, input_asset_blinds, input_assets, input_amounts, output_blinds, output_asset_blinds, output_pubkeys, vDummy, vDummy, tx4) == 2);
        BOOST_CHECK(!tx4.vout[0].nValue.IsExplicit());
        BOOST_CHECK(tx4.vout[1].nValue.IsExplicit());
        BOOST_CHECK(!tx4.vout[2].nValue.IsExplicit());
        BOOST_CHECK(VerifyAmounts(inputs, CTransaction(tx4), nullptr, false));

        CAmount unblinded_amount;
        CAsset asset_out;
        uint256 asset_blinder_out;
        BOOST_CHECK(UnblindConfidentialPair(key1, tx4.vout[0].nValue, tx4.vout[0].nAsset, tx4.vout[0].nNonce, op_true, tx4.witness.vtxoutwit[0].vchRangeproof, unblinded_amount, blind4, asset_out, asset_blinder_out) == 0);
        BOOST_CHECK(UnblindConfidentialPair(key2, tx4.vout[0].nValue, tx4.vout[0].nAsset, tx4.vout[0].nNonce, op_true, tx4.witness.vtxoutwit[0].vchRangeproof, unblinded_amount, blind4, asset_out, asset_blinder_out) == 1);
        BOOST_CHECK(unblinded_amount == 30);
        BOOST_CHECK(asset_out == unblinded_id);
        BOOST_CHECK(UnblindConfidentialPair(key2, tx4.vout[2].nValue, tx4.vout[2].nAsset, tx4.vout[2].nNonce, op_true, tx4.witness.vtxoutwit[2].vchRangeproof, unblinded_amount, blind4, asset_out, asset_blinder_out) == 1);
        BOOST_CHECK(asset_out == unblinded_id);
        BOOST_CHECK(unblinded_amount == 50);

        // Commit to the wrong script in the rangeproof
        BOOST_CHECK(UnblindConfidentialPair(key2, tx4.vout[2].nValue, tx4.vout[2].nAsset, tx4.vout[2].nNonce, CScript() << OP_FALSE, tx4.witness.vtxoutwit[2].vchRangeproof, unblinded_amount, blind4, asset_out, asset_blinder_out) == 0);

        // Make invalid public keys in nonce commitment, first of right size
        tx4.vout[2].nNonce.vchCommitment = std::vector<unsigned char>(33, 0);
        tx4.vout[2].nNonce.vchCommitment[0] = 0x03;
        BOOST_CHECK(UnblindConfidentialPair(key2, tx4.vout[2].nValue, tx4.vout[2].nAsset, tx4.vout[2].nNonce, op_true, tx4.witness.vtxoutwit[2].vchRangeproof, unblinded_amount, blind4, asset_out, asset_blinder_out) == 0);

        // Next, leading byte claiming to be 33 bytes in size
        tx4.vout[2].nNonce.vchCommitment.resize(1);
        BOOST_CHECK(UnblindConfidentialPair(key2, tx4.vout[2].nValue, tx4.vout[2].nAsset, tx4.vout[2].nNonce, op_true, tx4.witness.vtxoutwit[2].vchRangeproof, unblinded_amount, blind4, asset_out, asset_blinder_out) == 0);

        // Last, blank nonce commitment
        tx4.vout[2].nNonce.vchCommitment.clear();
        BOOST_CHECK(UnblindConfidentialPair(key2, tx4.vout[2].nValue, tx4.vout[2].nAsset, tx4.vout[2].nNonce, op_true, tx4.witness.vtxoutwit[2].vchRangeproof, unblinded_amount, blind4, asset_out, asset_blinder_out) == 0);

        tx4.vout[3].nValue = CConfidentialValue(tx4.vout[3].nValue.GetAmount() - 1);
        BOOST_CHECK(!VerifyAmounts(inputs, CTransaction(tx4), nullptr, false));

        // Check wallet borromean-based rangeproof results against expected args
        size_t proof_size = DEFAULT_RANGEPROOF_SIZE;
        BOOST_CHECK_EQUAL(tx4.witness.vtxoutwit[2].vchRangeproof.size(), proof_size);
        secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
        int exp = 0;
        int mantissa = 0;
        uint64_t min_value = 0;
        uint64_t max_value = 0;
        BOOST_CHECK(secp256k1_rangeproof_info(ctx, &exp, &mantissa, &min_value, &max_value, tx4.witness.vtxoutwit[2].vchRangeproof.data(), proof_size) == 1);
        BOOST_CHECK_EQUAL(exp, 0);
        BOOST_CHECK_EQUAL(mantissa, 52); // 52 bit default
        BOOST_CHECK_EQUAL(min_value, 1ULL);
        BOOST_CHECK_EQUAL(max_value, 4503599627370496ULL);
        secp256k1_context_destroy(ctx);
    }
    {
        inputs.clear();
        inputs.push_back(blind_ozz);
        inputs.push_back(other_fzz);

        // Spends 100 blinded bitcoin, 500 of unblinded "other"
        CMutableTransaction tx5;
        tx5.vin.resize(0);
        tx5.vout.resize(0);
        tx5.vin.emplace_back(COutPoint(Txid::FromUint256(ArithToUint256(3)), 0));
        tx5.vin.emplace_back(COutPoint(Txid::FromUint256(ArithToUint256(5)), 0));
        tx5.vout.emplace_back(bitcoinID, 29, CScript() << OP_TRUE);
        tx5.vout.emplace_back(bitcoinID, 70, CScript() << OP_TRUE);
        tx5.vout.emplace_back(otherID, 250, CScript() << OP_TRUE);
        tx5.vout.emplace_back(otherID, 249, CScript() << OP_TRUE);
        // Fees
        tx5.vout.emplace_back(bitcoinID, 1, CScript());
        tx5.vout.emplace_back(otherID, 1, CScript());

        // Blinds don't balance
        BOOST_CHECK(!VerifyAmounts(inputs, CTransaction(tx5), nullptr, false));

        // Blinding setup stuff
        std::vector<uint256> input_blinds;
        std::vector<uint256> input_asset_blinds;
        std::vector<CAsset> input_assets;
        std::vector<CAmount> input_amounts;
        std::vector<uint256> output_blinds;
        std::vector<uint256> output_asset_blinds;
        std::vector<CPubKey> output_pubkeys;
        input_blinds.push_back(blind3);
        input_blinds.emplace_back();
        input_asset_blinds.push_back(asset_blind);
        input_asset_blinds.emplace_back();
        input_amounts.push_back(100);
        input_amounts.push_back(500);
        input_assets.push_back(bitcoinID);
        input_assets.push_back(otherID);
        for (unsigned int i = 0; i < 6; i++) {
            output_pubkeys.push_back(pubkey2);
        }

        CMutableTransaction txtemp(tx5);

        // No blinding keys for fees, bails out blinding nothing, still invalid due to imbalance
        BOOST_CHECK(BlindTransaction(input_blinds, input_asset_blinds, input_assets, input_amounts, output_blinds, output_asset_blinds, output_pubkeys, vDummy, vDummy, txtemp) == -1);
        BOOST_CHECK(!VerifyAmounts(inputs, CTransaction(txtemp), nullptr, false));
        // Last will be implied blank keys
        output_pubkeys.resize(4);

        // Blind transaction, verify amounts
        txtemp = tx5;
        BOOST_CHECK(BlindTransaction(input_blinds, input_asset_blinds, input_assets, input_amounts, output_blinds, output_asset_blinds, output_pubkeys, vDummy, vDummy, txtemp) == 4);
        BOOST_CHECK(VerifyAmounts(inputs, CTransaction(txtemp), nullptr, false));

        // Transaction may not have spendable 0-value output
        txtemp.vout.emplace_back(CAsset(), 0, CScript() << OP_TRUE);
        BOOST_CHECK(!VerifyAmounts(inputs, CTransaction(txtemp), nullptr, false));

        // Create imbalance by removing fees, should still be able to blind
        txtemp = tx5;
        txtemp.vout.resize(5);
        BOOST_CHECK(!VerifyAmounts(inputs, CTransaction(txtemp), nullptr, false));
        txtemp.vout.resize(4);
        BOOST_CHECK(!VerifyAmounts(inputs, CTransaction(txtemp), nullptr, false));
        BOOST_CHECK(BlindTransaction(input_blinds, input_asset_blinds, input_assets, input_amounts, output_blinds, output_asset_blinds, output_pubkeys, vDummy, vDummy, txtemp) == 4);
        BOOST_CHECK(!VerifyAmounts(inputs, CTransaction(txtemp), nullptr, false));

        txtemp = tx5;
        // Remove other input, make surjection proof impossible for 2 "otherID" outputs
        std::vector<uint256> t_input_blinds;
        std::vector<uint256> t_input_asset_blinds;
        std::vector<CAsset> t_input_assets;
        std::vector<CAmount> t_input_amounts;

        t_input_blinds = input_blinds;
        t_input_asset_blinds = input_asset_blinds;
        t_input_assets = input_assets;
        t_input_amounts = input_amounts;
        txtemp.vin.resize(1);
        inputs.resize(1);
        t_input_blinds.resize(1);
        t_input_asset_blinds.resize(1);
        t_input_assets.resize(1);
        t_input_amounts.resize(1);
        BOOST_CHECK(!VerifyAmounts(inputs, CTransaction(txtemp), nullptr, false));
        BOOST_CHECK(BlindTransaction(t_input_blinds, t_input_asset_blinds, t_input_assets, t_input_amounts, output_blinds, output_asset_blinds, output_pubkeys, vDummy, vDummy, txtemp) == 2);
        BOOST_CHECK(!VerifyAmounts(inputs, CTransaction(txtemp), nullptr, false));
    }
}

BOOST_AUTO_TEST_CASE(spendable_zero_value_blinding_fails_without_abort)
{
    CKey key;
    unsigned char secret[32] = {1, 2, 3};
    key.Set(&secret[0], &secret[32], true);

    const CAsset asset(GetRandHash());
    CMutableTransaction tx;
    tx.vin.push_back(CTxIn(COutPoint(Txid::FromUint256(ArithToUint256(1)), 0)));
    // Confidential spendable outputs have a minimum range-proof value of one.
    // A zero-valued spendable output must be rejected, not abort the RPC worker.
    tx.vout.push_back(CTxOut(asset, 0, CScript() << OP_TRUE));
    tx.vout.push_back(CTxOut(asset, 9, CScript() << OP_TRUE));
    tx.vout.push_back(CTxOut(asset, 1, CScript()));

    std::vector<uint256> input_value_blinds{uint256()};
    std::vector<uint256> input_asset_blinds{uint256()};
    std::vector<CAsset> input_assets{asset};
    std::vector<CAmount> input_amounts{10};
    std::vector<uint256> output_value_blinds;
    std::vector<uint256> output_asset_blinds;
    std::vector<CPubKey> output_pubkeys{key.GetPubKey(), key.GetPubKey(), CPubKey()};
    std::vector<CKey> no_issuance_keys;

    BOOST_CHECK_EQUAL(
        BlindTransaction(input_value_blinds, input_asset_blinds, input_assets,
                         input_amounts, output_value_blinds, output_asset_blinds,
                         output_pubkeys, no_issuance_keys, no_issuance_keys, tx),
        -1);
}

BOOST_AUTO_TEST_CASE(confidential_reissuance_authority_round_trip)
{
    // Model a reissuance authority without a wallet, datadir, or live
    // UTXO. The authority's asset is a blinded reissuance-token generator.
    // Reissuance reveals the current public ABF, mints the derived asset, and
    // rotates the successor to a distinct generator with a confidential value
    // commitment that preserves balance.
    // Fixed issuance entropy provides exact secp256k1-zkp regression vectors.
    const uint256 entropy = uint256S(
        "0xf108d6c0265fd2bdc6b45277e3515804"
        "ea55892e6f342765b2df25a7023efb78");

    // The deployed token is normally written in display order. Consensus and
    // libsecp256k1 consume uint256's raw little-endian bytes instead. Freeze
    // both forms and the exact serialized unblinded generator H so controller
    // artifacts cannot accidentally hash the display string or reverse twice.
    const CAsset deployed_reissuance_token(uint256S(
        "9387c79c879d572ea18588f867414f15"
        "c77e061cd510398e15dd471dbf1337d4"));
    BOOST_CHECK_EQUAL(
        HexStr(std::vector<unsigned char>(
            deployed_reissuance_token.begin(), deployed_reissuance_token.end())),
        "d43713bf1d47dd158e3910d51c067ec7"
        "154f4167f88885a12e579d879cc78793");
    secp256k1_generator deployed_unblinded_generator;
    BOOST_REQUIRE_EQUAL(
        secp256k1_generator_generate(
            secp256k1_blind_context,
            &deployed_unblinded_generator,
            deployed_reissuance_token.begin()),
        1);
    std::array<unsigned char, 33> deployed_unblinded_generator_serialized{};
    BOOST_REQUIRE_EQUAL(
        secp256k1_generator_serialize(
            secp256k1_blind_context,
            deployed_unblinded_generator_serialized.data(),
            &deployed_unblinded_generator),
        1);
    BOOST_CHECK_EQUAL(
        HexStr(std::vector<unsigned char>(
            deployed_unblinded_generator_serialized.begin(),
            deployed_unblinded_generator_serialized.end())),
        "0b6445a8b61ae65dce7070ac735913e7"
        "d711e04485dda299812bcc091f170c4b81");

    const auto sequence_abf = [](uint64_t scalar) {
        std::array<unsigned char, 32> bytes{};
        for (size_t i = 0; i < sizeof(scalar); ++i) {
            bytes[bytes.size() - 1 - i] = scalar & 0xff;
            scalar >>= 8;
        }
        return uint256(bytes.data(), bytes.size());
    };
    const uint64_t current_sequence = 0;
    const uint64_t next_sequence = current_sequence + 1;
    const uint256 authority_abf = sequence_abf(current_sequence + 1);
    const uint256 successor_abf = sequence_abf(next_sequence + 1);
    BOOST_CHECK_EQUAL(
        HexStr(std::vector<unsigned char>(authority_abf.begin(), authority_abf.end())),
        std::string(62, '0') + "01");
    // uint256 display hex reverses the raw consensus/secp scalar bytes.
    BOOST_CHECK_EQUAL(authority_abf.GetHex(), "01" + std::string(62, '0'));
    constexpr CAmount mint_amount = 500;

    CAsset issued_asset;
    CAsset reissuance_token;
    CalculateAsset(issued_asset, entropy);
    CalculateReissuanceToken(reissuance_token, entropy, /*fConfidential=*/false);
    BOOST_CHECK_EQUAL(
        issued_asset.GetHex(),
        "8728cd6ff7c8732fa82e2e10636faa745ddb303655248f029b3cace24b78e5ec");
    BOOST_CHECK_EQUAL(reissuance_token.GetHex(), deployed_reissuance_token.GetHex());

    CConfidentialAsset authority_generator;
    secp256k1_generator generator;
    BlindAsset(authority_generator, generator, reissuance_token, authority_abf.begin());
    BOOST_CHECK_EQUAL(
        authority_generator.GetHex(),
        "0b9319dc4278ae093c4b651e352450ace17c79093cda960f3fcac2e4968e4e55f5");

    const std::array<uint64_t, 2> authority_values{1, 1};
    std::array<unsigned char, 32> unblinded_asset_blinder{};
    std::array<unsigned char, 32> unblinded_value_blinder{};
    std::array<unsigned char, 32> current_value_blinder{};
    const std::array<const unsigned char*, 2> current_asset_blinders{
        unblinded_asset_blinder.data(), authority_abf.begin()};
    const std::array<unsigned char*, 2> current_value_blinders{
        unblinded_value_blinder.data(), current_value_blinder.data()};
    BOOST_REQUIRE_EQUAL(
        secp256k1_pedersen_blind_generator_blind_sum(
            secp256k1_blind_context,
            authority_values.data(),
            current_asset_blinders.data(),
            current_value_blinders.data(),
            authority_values.size(),
            /*n_inputs=*/1),
        1);
    CConfidentialValue current_authority_value;
    secp256k1_pedersen_commitment current_value_commitment;
    CreateValueCommitment(
        current_authority_value,
        current_value_commitment,
        current_value_blinder.data(),
        generator,
        1);
    BOOST_CHECK_EQUAL(
        current_authority_value.GetHex(),
        "096445a8b61ae65dce7070ac735913e7d711e04485dda299812bcc091f170c4b81");

    const CScript current_controller = CScript() << OP_TRUE;
    const CScript successor_controller = CScript() << OP_TRUE << OP_TRUE;
    const CScript recipient = CScript() << OP_TRUE << OP_DROP << OP_TRUE;

    CTxOut current_authority(authority_generator, current_authority_value, current_controller);
    current_authority.nNonce.SetNull();
    const std::vector<CTxOut> inputs{current_authority};

    CMutableTransaction reissue;
    reissue.vin.emplace_back(COutPoint(Txid::FromUint256(uint256S("0x01")), 0));
    reissue.vin[0].assetIssuance.assetBlindingNonce = authority_abf;
    reissue.vin[0].assetIssuance.assetEntropy = entropy;
    reissue.vin[0].assetIssuance.nAmount = CConfidentialValue(mint_amount);
    reissue.vin[0].assetIssuance.nInflationKeys.SetNull();
    // The output proofs below make this a witness transaction; keep the input
    // witness vector structurally aligned even though the issuance is explicit.
    reissue.witness.vtxinwit.resize(1);
    reissue.vout.emplace_back(issued_asset, mint_amount, recipient);

    CConfidentialAsset successor_generator;
    secp256k1_generator successor_secp_generator;
    BlindAsset(
        successor_generator,
        successor_secp_generator,
        reissuance_token,
        successor_abf.begin());
    BOOST_CHECK_EQUAL(
        successor_generator.GetHex(),
        "0b7031cc832d89503a0746f15152bac4ec3b0a4b5f3f70906aa7b36a9b2f3d1de1");

    std::array<unsigned char, 32> successor_value_blinder{};
    const std::array<const unsigned char*, 2> successor_asset_blinders_for_balance{
        unblinded_asset_blinder.data(), successor_abf.begin()};
    const std::array<unsigned char*, 2> successor_value_blinders_for_balance{
        unblinded_value_blinder.data(), successor_value_blinder.data()};
    BOOST_REQUIRE_EQUAL(
        secp256k1_pedersen_blind_generator_blind_sum(
            secp256k1_blind_context,
            authority_values.data(),
            successor_asset_blinders_for_balance.data(),
            successor_value_blinders_for_balance.data(),
            authority_values.size(),
            /*n_inputs=*/1),
        1);

    CConfidentialValue successor_value;
    secp256k1_pedersen_commitment successor_value_commitment;
    CreateValueCommitment(
        successor_value,
        successor_value_commitment,
        successor_value_blinder.data(),
        successor_secp_generator,
        1);
    BOOST_CHECK_EQUAL(current_authority_value.GetHex(), successor_value.GetHex());
    reissue.vout.emplace_back(successor_generator, successor_value, successor_controller);
    reissue.witness.vtxoutwit.resize(reissue.vout.size());

    std::vector<secp256k1_fixed_asset_tag> surjection_targets(2);
    std::memcpy(&surjection_targets[0], reissuance_token.begin(), 32);
    std::memcpy(&surjection_targets[1], issued_asset.begin(), 32);
    secp256k1_generator issued_generator;
    BOOST_REQUIRE_EQUAL(
        secp256k1_generator_generate(
            secp256k1_blind_context, &issued_generator, issued_asset.begin()),
        1);
    const std::vector<secp256k1_generator> target_generators{
        generator, issued_generator};
    const std::vector<uint256> target_asset_blinders{authority_abf, uint256()};
    std::vector<unsigned char*> successor_value_blinders{
        successor_value_blinder.data()};
    std::vector<const unsigned char*> successor_asset_blinders{
        successor_abf.begin()};
    BOOST_REQUIRE(GenerateRangeproof(
        reissue.witness.vtxoutwit[1].vchRangeproof,
        successor_value_blinders,
        uint256S("0x04"),
        1,
        successor_controller,
        successor_value_commitment,
        successor_secp_generator,
        reissuance_token,
        successor_asset_blinders));

    // Elements' deployed surjection-proof rules reject an output generator
    // exactly equal to any input generator. A fixed-generator successor is
    // therefore consensus-impossible, even when the underlying asset matches.
    secp256k1_surjectionproof exact_reuse_proof;
    size_t exact_reuse_index = 0;
    std::array<unsigned char, 32> proof_seed{};
    proof_seed[0] = 1;
    BOOST_REQUIRE(secp256k1_surjectionproof_initialize(
        secp256k1_blind_context,
        &exact_reuse_proof,
        &exact_reuse_index,
        surjection_targets.data(),
        surjection_targets.size(),
        surjection_targets.size(),
        &surjection_targets[0],
        100,
        proof_seed.data()));
    BOOST_CHECK_EQUAL(
        secp256k1_surjectionproof_generate(
            secp256k1_blind_context,
            &exact_reuse_proof,
            target_generators.data(),
            target_generators.size(),
            &generator,
            exact_reuse_index,
            authority_abf.begin(),
            authority_abf.begin()),
        0);

    BOOST_REQUIRE(SurjectOutput(
        reissue.witness.vtxoutwit[1],
        surjection_targets,
        target_generators,
        target_asset_blinders,
        successor_asset_blinders,
        successor_secp_generator,
        reissuance_token));

    BOOST_CHECK(VerifyAmounts(inputs, CTransaction(reissue), nullptr, false));

    CMutableTransaction mutated(reissue);
    mutated.vin[0].assetIssuance.assetBlindingNonce = uint256S("0x02");
    BOOST_CHECK(!VerifyAmounts(inputs, CTransaction(mutated), nullptr, false));

    mutated = reissue;
    mutated.vin[0].assetIssuance.assetEntropy = uint256S("0x03");
    BOOST_CHECK(!VerifyAmounts(inputs, CTransaction(mutated), nullptr, false));

    std::vector<CTxOut> explicit_authority_inputs{current_authority};
    explicit_authority_inputs[0].nAsset = CConfidentialAsset(reissuance_token);
    BOOST_CHECK(!VerifyAmounts(explicit_authority_inputs, CTransaction(reissue), nullptr, false));

    mutated = reissue;
    mutated.vout[0].nValue = CConfidentialValue(mint_amount + 1);
    BOOST_CHECK(!VerifyAmounts(inputs, CTransaction(mutated), nullptr, false));

    mutated = reissue;
    mutated.vout[1].nValue = CConfidentialValue(2);
    BOOST_CHECK(!VerifyAmounts(inputs, CTransaction(mutated), nullptr, false));

    mutated = reissue;
    mutated.vout.emplace_back(authority_generator, CConfidentialValue(1), successor_controller);
    BOOST_CHECK(!VerifyAmounts(inputs, CTransaction(mutated), nullptr, false));

}
BOOST_AUTO_TEST_CASE(rangeproof_zero_value_spendable_script)
{
    // A rangeproof over a spendable script uses min_value = 1
    // (`min_value = scriptPubKey.IsUnspendable() ? 0 : 1`), and
    // secp256k1_rangeproof_sign returns 0 when min_value > value. A zero-valued
    // output to a spendable script therefore has no valid rangeproof, and the
    // creation helpers must report that rather than assert on it.

    const CAsset asset(GetRandHash());
    const uint256 asset_blinder = GetRandHash();
    const uint256 value_blinder = GetRandHash();
    const uint256 nonce = GetRandHash();

    const CScript spendable = CScript() << OP_TRUE;
    const CScript unspendable = CScript() << OP_RETURN;
    BOOST_CHECK(!spendable.IsUnspendable());
    BOOST_CHECK(unspendable.IsUnspendable());

    // Asset generator, shared by every case below
    CConfidentialAsset conf_asset;
    secp256k1_generator asset_gen;
    CreateAssetCommitment(conf_asset, asset_gen, asset, asset_blinder);

    // Commitments to 0 and to 1 under that generator
    CConfidentialValue conf_value_zero, conf_value_one;
    secp256k1_pedersen_commitment value_commit_zero, value_commit_one;
    CreateValueCommitment(conf_value_zero, value_commit_zero, value_blinder, asset_gen, 0);
    CreateValueCommitment(conf_value_one, value_commit_one, value_blinder, asset_gen, 1);

    std::vector<unsigned char> rangeproof;

    // Zero to a spendable script is unprovable. Before the fix, the caller at
    // blindpsbt.cpp:562 turns this false into assert(rangeresult) -> SIGABRT.
    BOOST_CHECK(!CreateValueRangeProof(rangeproof, value_blinder, nonce, 0, spendable,
                                       value_commit_zero, asset_gen, asset, asset_blinder));

    // Zero to an unspendable script gives min_value = 0 and must keep working:
    // this is the fee / issuance / OP_RETURN shape.
    BOOST_CHECK(CreateValueRangeProof(rangeproof, value_blinder, nonce, 0, unspendable,
                                      value_commit_zero, asset_gen, asset, asset_blinder));

    // The ordinary case is unaffected.
    BOOST_CHECK(CreateValueRangeProof(rangeproof, value_blinder, nonce, 1, spendable,
                                      value_commit_one, asset_gen, asset, asset_blinder));

    // Confirm the boundary is min_value and not something incidental, mirroring
    // the rangeproof_info check in naive_blinding_test.
    {
        secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
        int exp = 0;
        int mantissa = 0;
        uint64_t min_value = 0;
        uint64_t max_value = 0;
        BOOST_CHECK(secp256k1_rangeproof_info(ctx, &exp, &mantissa, &min_value, &max_value,
                                              rangeproof.data(), rangeproof.size()) == 1);
        BOOST_CHECK_EQUAL(min_value, 1ULL);
        secp256k1_context_destroy(ctx);
    }

    std::vector<unsigned char*> value_blindptrs;
    std::vector<const unsigned char*> asset_blindptrs;
    value_blindptrs.push_back(const_cast<unsigned char*>(value_blinder.begin()));
    asset_blindptrs.push_back(asset_blinder.begin());

    BOOST_CHECK(!GenerateRangeproof(rangeproof, value_blindptrs, nonce, 0, spendable,
                                    value_commit_zero, asset_gen, asset, asset_blindptrs));
    BOOST_CHECK(GenerateRangeproof(rangeproof, value_blindptrs, nonce, 0, unspendable,
                                   value_commit_zero, asset_gen, asset, asset_blindptrs));
    BOOST_CHECK(GenerateRangeproof(rangeproof, value_blindptrs, nonce, 1, spendable,
                                   value_commit_one, asset_gen, asset, asset_blindptrs));
}
BOOST_AUTO_TEST_SUITE_END()
