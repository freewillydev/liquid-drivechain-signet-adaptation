// Copyright (c) 2017-2017 Blockstream
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <arith_uint256.h>
#include <clientversion.h>
#include <chainparams.h>
#include <checkqueue.h>
#include <consensus/tx_verify.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <dbwrapper.h>
#include <drivechain_parent_replay.h>
#include <drivechain_parent_rules.h>
#include <drivechain_peg.h>
#include <elements_drivechain_identity.h>
#include <elements_drivechain_bootstrap.h>
#include <limits>
#include <type_traits>
#include <set>
#include <hash.h>
#include <haskell/bridge.h>
#include <key_io.h>
#include <mainchainrpc.h>
#include <drivechain_withdrawal.h>
#include <validation.h> // For CheckTransaction
#include <pegins.h>
#include <policy/policy.h>
#include <script/script.h>
#include <script/script_error.h>
#include <util/strencodings.h>
#include <validation.h>
#include <streams.h>
#include <signet.h>
#include <test/util/setup_common.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/test/unit_test.hpp>

namespace Bitcoin = Sidechain::Bitcoin;

std::vector<std::vector<unsigned char> > witness_stack = {
    ParseHex("00ca9a3b00000000"),
    ParseHex("ef4699c160d014d5ff79636d8a4cb990b9df4ebab649f144d19f5c495c585e47"),
    ParseHex("06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f"),
    ParseHex("00141eef6361cd1507a303834285d1521d6baf1b19ae"),
    ParseHex("0200000001b399292c8100b8a1b66eb23896f799c1712390d560af0f70e81acd2d17a3b06e0000000049483045022100c3c749623486ea57ea93dfaf78d85590d78c7590a25768fe80f0ea4d6047419002202a0a00a90392b86c53c0fdda908c4591ba28040c16c25734c23b7df3c8b70acd01feffffff0228196bee000000001976a914470dd41542ee1a1bd75f1a838878648c8d65622488ac00ca9a3b0000000017a914cb60b1d7f76ba12b45a116c482c165a74c5d7e388765000000"),
    ParseHex("000000205e3913a320cd2e3a2efa141e47419f54cb9e82320cf8dbc812fc19b9a1b2413a57f5e9fb4fa22de191454a241387f5d10cc794ee0fbf72ae2841baf3129a4eab8133025affff7f20000000000200000002f9d0be670007d38fceece999cb6144658a99c307ccc37f6d8f69129ed0f4545ff321df9790633bc33c67239c4174df8142ee616ee6a2e2788fe4820fe70e9bce0105")
};

std::vector<unsigned char> pegin_transaction = ParseHex("020000000101f321df9790633bc33c67239c4174df8142ee616ee6a2e2788fe4820fe70e9bce0100004000ffffffff0201ef4699c160d014d5ff79636d8a4cb990b9df4ebab649f144d19f5c495c585e4701000000003b9ab2e0001976a914809326f7628dc976fbe63806479a1b8dfcc8c4b988ac01ef4699c160d014d5ff79636d8a4cb990b9df4ebab649f144d19f5c495c585e47010000000000001720000000000000000002483045022100ae17064745d80650a6a5cbcbe15c8c45ba498d1c6f45a7c0f5f32d871b463fc60220799f2836471702c21f7cfe124651727b530ad41f7af4dc213c65f5030a2f6fc4012103a9d3c6c7c161a565a76113632fe13330cf2c0207ba79a76d1154cdc3cb94d940060800ca9a3b0000000020ef4699c160d014d5ff79636d8a4cb990b9df4ebab649f144d19f5c495c585e472006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f1600141eef6361cd1507a303834285d1521d6baf1b19aebe0200000001b399292c8100b8a1b66eb23896f799c1712390d560af0f70e81acd2d17a3b06e0000000049483045022100c3c749623486ea57ea93dfaf78d85590d78c7590a25768fe80f0ea4d6047419002202a0a00a90392b86c53c0fdda908c4591ba28040c16c25734c23b7df3c8b70acd01feffffff0228196bee000000001976a914470dd41542ee1a1bd75f1a838878648c8d65622488ac00ca9a3b0000000017a914cb60b1d7f76ba12b45a116c482c165a74c5d7e38876500000097000000205e3913a320cd2e3a2efa141e47419f54cb9e82320cf8dbc812fc19b9a1b2413a57f5e9fb4fa22de191454a241387f5d10cc794ee0fbf72ae2841baf3129a4eab8133025affff7f20000000000200000002f9d0be670007d38fceece999cb6144658a99c307ccc37f6d8f69129ed0f4545ff321df9790633bc33c67239c4174df8142ee616ee6a2e2788fe4820fe70e9bce010500000000");

COutPoint prevout(Txid::FromUint256(uint256S("ce9b0ee70f82e48f78e2a2e66e61ee4281df74419c23673cc33b639097df21f3")), 1);

const std::string fedpegscript_str = "512103dff4923d778550cc13ce0d887d737553b4b58f4e8e886507fc39f5e447b2186451ae";

// Needed for easier parent PoW check, and setting fedpegscript
struct FedpegSetup : public BasicTestingSetup {
        FedpegSetup() : BasicTestingSetup(ChainType::CUSTOM, {}, fedpegscript_str) {}
};

BOOST_FIXTURE_TEST_SUITE(pegin_witness_tests, FedpegSetup)

BOOST_AUTO_TEST_CASE(deposit_format_routing)
{
    using namespace drivechain::haskell;
    for (uint64_t count = 0; count <= 12; ++count) {
        for (const bool legacy : {false, true}) {
            for (const bool native : {false, true}) {
                for (const bool configured : {false, true}) {
                    const bool ecx = (count == 6 && legacy) || (count == 11 && native);
                    const auto expected = ecx ? (configured ? DepositRoute::REJECT_ECX : DepositRoute::ECX)
                                              : (native ? DepositRoute::NATIVE : configured ? DepositRoute::REJECT_FEDERATED : DepositRoute::FEDERATED);
                    const auto routing = SelectDepositRoute(count, legacy, native, configured);
                    BOOST_CHECK(routing.route == expected);
                    BOOST_CHECK_EQUAL(routing.expected_stack_size,ecx ? count : native ? 8 : 6);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(native_deposit_admission_order)
{
    using namespace drivechain::haskell;
    for (uint32_t failed = 0; failed <= 5; ++failed) {
        for (unsigned status = 0; status < 3; ++status) {
            std::vector<uint32_t> seen;
            bool unavailable = false;
            const auto result = ParentReplayStore(ReplayStoreFlow::NATIVE_DEPOSIT_ADMISSION,
                [&](uint32_t step) -> uint32_t {
                    seen.push_back(step);
                    if (step <= 5) return step != failed;
                    if (step == 6) return status == 0;
                    if (step == 7) return status == 2;
                    if (step == 8) unavailable = true;
                    return 0;
                });
            std::vector<uint32_t> expected;
            const auto last = failed ? failed : status == 0 ? 6U : status == 1 ? 7U : 8U;
            for (uint32_t step = 1; step <= last; ++step) expected.push_back(step);
            if (failed || status != 0) expected.push_back(failed ? failed + 8 : 14);
            BOOST_CHECK(seen == expected);
            BOOST_CHECK_EQUAL(result, failed == 0 && status == 0 ? 0U : 1U);
            BOOST_CHECK_EQUAL(unavailable, failed == 0 && status == 2);
        }
    }
}

BOOST_AUTO_TEST_CASE(ecx_route_reuses_deposit_classifier)
{
    BOOST_REQUIRE(!Params().GetConsensus().drivechain_slot.has_value());
    Sidechain::Bitcoin::CMutableTransaction transaction;
    transaction.vin.emplace_back(Sidechain::Bitcoin::COutPoint(uint256::ONE,0));
    transaction.vout.emplace_back(1,CScript() << OP_TRUE);
    DrivechainDepositEvidence evidence;
    VectorWriter(evidence.deposit_tx,0) << TX_NO_WITNESS(transaction);
    const COutPoint outpoint{Txid::FromUint256(transaction.GetHash()),0};
    const auto& asset = Params().GetConsensus().pegged_asset;
    const auto& genesis = Params().ParentGenesisBlockHash();
    const CScript claim = CScript() << OP_TRUE;
    for (const bool proven : {false,true}) {
        const auto original = proven ? CreateDrivechainDepositPeginWitness(1,asset,genesis,claim,evidence) :
            CreateDrivechainDepositPeginWitness(1,asset,genesis,claim,transaction.GetHash());
        for (unsigned fault=0; fault<10; ++fault) {
            auto witness = original;
            const char* expected="Invalid drivechain deposit pegin witness.";
            switch (fault) {
            case 0: expected="sentinel"; break;
            case 1: witness.stack[1][0] ^= 1; break;
            case 2: witness.stack[2][0] ^= 1; break;
            case 3: witness.stack[5][0] ^= 1; break;
            case 4: witness.stack[0].assign(8,0); break;
            case 5: witness.stack[0].clear(); expected="Could not deserialize value."; break;
            case 6: witness.stack[3].resize(101); expected="Claim script is too large."; break;
            case 7: witness.stack[1].pop_back(); expected="Asset type was not 32 bytes."; break;
            case 8: witness.stack[2].pop_back(); expected="Parent genesis blockhash was not 32 bytes."; break;
            case 9: witness.stack[5].clear(); break;
            }
            std::string error="sentinel";
            bool depth_failed=true, parent_unavailable=true;
            BOOST_CHECK_EQUAL(IsValidPeginWitness(witness,{},outpoint,error,false,&depth_failed,&parent_unavailable,0),fault==0);
            BOOST_CHECK_EQUAL(error,expected);
            BOOST_CHECK(!depth_failed);
            BOOST_CHECK(!parent_unavailable);
        }
    }
}

BOOST_AUTO_TEST_CASE(witness_valid)
{
    CScriptWitness witness;
    witness.stack = witness_stack;

    std::string err;

    std::vector<unsigned char> fedpegscript_bytes = ParseHex(fedpegscript_str);
    CScript fedpegscript(fedpegscript_bytes.begin(), fedpegscript_bytes.end());
    // Test sample was generated as "legacy" with p2sh-p2wsh fedpegscript
    CScript fedpeg_program(GetScriptForDestination(ScriptHash(GetScriptForDestination(WitnessV0ScriptHash(fedpegscript)))));
    std::vector<std::pair<CScript, CScript>> fedpegscripts;
    // TODO test with additional scripts
    fedpegscripts.emplace_back(fedpeg_program, fedpegscript);

    bool valid = IsValidPeginWitness(witness, fedpegscripts, prevout, err, false);
    BOOST_CHECK(err == "");
    BOOST_CHECK(valid);

    // Missing byte on each field to make claim ill-formatted
    // This will break deserialization and other data-matching checks
    for (unsigned int i = 0; i < witness.stack.size(); i++) {
        witness.stack[i].pop_back();
        BOOST_CHECK(!IsValidPeginWitness(witness, fedpegscripts, prevout, err, false));
        witness.stack = witness_stack;
        BOOST_CHECK(IsValidPeginWitness(witness, fedpegscripts, prevout, err, false));
    }

    // Test mismatched but valid nOut to proof
    COutPoint fake_prevout = prevout;
    fake_prevout.n = 0;
    BOOST_CHECK(!IsValidPeginWitness(witness, fedpegscripts, fake_prevout, err, false));

    // Test mismatched but valid txid
    fake_prevout = prevout;
    fake_prevout.hash = Txid::FromUint256(uint256S("2f103ee04a5649eecb932b4da4ca9977f53a12bbe04d9d1eb5ccc0f4a06334"));
    BOOST_CHECK(!IsValidPeginWitness(witness, fedpegscripts, fake_prevout, err, false));

    // Ensure that all witness stack sizes are handled
    BOOST_CHECK(IsValidPeginWitness(witness, fedpegscripts, prevout, err, false));
    for (unsigned int i = 0; i < witness.stack.size(); i++) {
        witness.stack.pop_back();
        BOOST_CHECK(!IsValidPeginWitness(witness, fedpegscripts, prevout, err, false));
    }
    witness.stack = witness_stack;

    // Extra element causes failure
    witness.stack.push_back(witness.stack.back());
    BOOST_CHECK(!IsValidPeginWitness(witness, fedpegscripts, prevout, err, false));
    witness.stack = witness_stack;

    // Check validation of peg-in transaction's inputs and balance
    DataStream ssTx(pegin_transaction);
    CTransactionRef txRef;
    try {
        ssTx >> TX_WITH_WITNESS(txRef);
    } catch (...) {
        BOOST_CHECK(false);
        return;
    }
    CTransaction tx(*txRef);

    // Only one(valid) input witness should exist, and should match
    BOOST_CHECK(tx.witness.vtxinwit.size() == 1);
    BOOST_CHECK(tx.witness.vtxinwit[0].m_pegin_witness.stack == witness_stack);
    BOOST_CHECK(tx.vin[0].m_is_pegin);
    // Check that serialization doesn't cause issuance to become non-null
    BOOST_CHECK(tx.vin[0].assetIssuance.IsNull());
    BOOST_CHECK(IsValidPeginWitness(tx.witness.vtxinwit[0].m_pegin_witness, fedpegscripts, prevout, err, false));

    CAmountMap fee_map;

    std::set<std::pair<uint256, COutPoint>> setPeginsSpent;
    TxValidationState state;
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    // Get the latest block index to look up fedpegscripts
    // For these tests, should be genesis-block-hardcoded consensus.fedpegscript
    BOOST_CHECK(Consensus::CheckTxInputs(tx, state, coins, 0, fee_map, setPeginsSpent, nullptr, false, true, fedpegscripts));
    BOOST_CHECK(setPeginsSpent.size() == 1);
    setPeginsSpent.clear();

    // Strip pegin_witness
    CMutableTransaction mtxn(tx);
    mtxn.witness.vtxinwit[0].m_pegin_witness.SetNull();
    CTransaction tx2(mtxn);
    BOOST_CHECK(!Consensus::CheckTxInputs(tx2, state, coins, 0, fee_map, setPeginsSpent, nullptr, false, true, fedpegscripts));
    BOOST_CHECK(setPeginsSpent.empty());

    // Invalidate peg-in (and spending) authorization by pegin marker.
    // This only checks for peg-in authorization, with the only input marked
    // as m_is_pegin
    CMutableTransaction mtxn2(tx);
    mtxn2.vin[0].m_is_pegin = false;
    CTransaction tx3(mtxn2);
    BOOST_CHECK(!Consensus::CheckTxInputs(tx3, state, coins, 0, fee_map, setPeginsSpent, nullptr, false, true, fedpegscripts));
    BOOST_CHECK(setPeginsSpent.empty());


    // TODO Test mixed pegin/non-pegin input case
    // TODO Test spending authorization in conjunction with valid witness program in pegin auth

}

BOOST_AUTO_TEST_CASE(drivechain_bmm_m7_all_slots_and_malformed_payloads)
{
    for (int slot = 0; slot < 256; ++slot) {
        std::vector<unsigned char> payload{0xd1,0x61,0x73,0x68,static_cast<unsigned char>(slot)};
        for (unsigned int i = 0; i < 32; ++i) payload.push_back(static_cast<unsigned char>(i + slot));
        uint256 expected;
        std::reverse_copy(payload.begin()+5,payload.end(),expected.begin());
        const auto check = [&](const std::vector<unsigned char>& candidate, bool accepted) {
            Bitcoin::CMutableTransaction coinbase;
            coinbase.vin.emplace_back(Bitcoin::COutPoint(),CScript() << OP_0,0);
            coinbase.vout.emplace_back(0,CScript() << OP_RETURN << candidate);
            Bitcoin::CBlock block;
            block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(coinbase)));
            uint256 actual = expected;
            uint32_t index{99};
            std::string error;
            BOOST_CHECK_EQUAL(ExtractCanonicalDrivechainBmmCommitmentInBlock(block,slot,actual,&index,&error),accepted);
            BOOST_CHECK_EQUAL(actual,accepted ? expected : uint256{});
            BOOST_CHECK_EQUAL(index,0U);
        };
        check(payload,true);
        auto malformed = payload;
        malformed[4] ^= 1;
        check(malformed,false);
        for (size_t i = 0; i < 4; ++i) {
            malformed = payload;
            malformed[i] ^= 1;
            check(malformed,false);
        }
        malformed = payload;
        malformed.pop_back();
        check(malformed,false);
        malformed = payload;
        malformed.push_back(0);
        check(malformed,false);
    }
}


BOOST_AUTO_TEST_CASE(drivechain_parent_replay_validates_pinned_enforcer_m8)
{
    constexpr int slot{24};
    constexpr uint16_t max_age{10};
    constexpr uint16_t threshold{5};
    const uint256 required_proposal = uint256S("11");
    const uint256 sidechain_hash = uint256S("22");
    const uint256 previous_parent = uint256S("33");

    const auto make_m7 = [](const uint256& hash) {
        std::vector<unsigned char> payload = ParseHex("d1617368");
        payload.push_back(slot);
        const std::vector<unsigned char> display_hash = ParseHex(hash.GetHex());
        payload.insert(payload.end(), display_hash.begin(), display_hash.end());
        return CScript() << OP_RETURN << payload;
    };
    const auto make_m8_script = [](const uint256& hash, const uint256& previous,
                                   const bool nonminimal) {
        std::vector<unsigned char> payload = ParseHex("00bf00");
        payload.push_back(slot);
        const std::vector<unsigned char> display_hash = ParseHex(hash.GetHex());
        payload.insert(payload.end(), display_hash.begin(), display_hash.end());
        payload.insert(payload.end(), previous.begin(), previous.end());
        if (!nonminimal) return CScript() << OP_RETURN << payload;
        CScript script;
        script.push_back(OP_RETURN);
        script.push_back(OP_PUSHDATA1);
        script.push_back(payload.size());
        script.insert(script.end(), payload.begin(), payload.end());
        return script;
    };
    const auto make_block = [&](const std::vector<CScript>& coinbase_messages,
                                const CScript& request_script) {
        Bitcoin::CMutableTransaction coinbase;
        coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
        for (const CScript& message : coinbase_messages) {
            coinbase.vout.emplace_back(0, message);
        }
        Bitcoin::CMutableTransaction request;
        request.vin.emplace_back(Bitcoin::COutPoint(uint256::ONE, 0));
        request.vout.emplace_back(0, request_script);
        Bitcoin::CBlock block;
        block.hashPrevBlock = previous_parent;
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(coinbase)));
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(request)));
        return block;
    };
    const auto apply = [&](const Bitcoin::CBlock& block, std::string& error) {
        DrivechainParentReplayState state;
        state.active_proposal_hash = required_proposal;
        state.required_proposal_activated = true;
        state.required_activation_height = 1;
        state.required_activation_block_hash = previous_parent;
        state.pending_proposals.emplace(uint256S("44"), DrivechainPendingProposal{0, 0});
        state.pending_withdrawals.push_back({uint256S("55"), 0, 1});
        state.ctip = Bitcoin::COutPoint(uint256S("66"), 0);
        state.ctip_value = 1000;
        state.other_slots[25].active_proposal_hash = required_proposal;
        state.other_slots[25].ctip = Bitcoin::COutPoint(uint256S("77"), 0);
        state.other_slots[25].ctip_value = 2000;
        state.previous_m4_actions[24] = {DrivechainM4ActionType::ALARM, uint256{}};
        DataStream before;
        before << state;
        std::vector<DrivechainMintableDeposit> deposits(1);
        std::vector<DrivechainSuccessfulWithdrawal> withdrawals(1);
        std::vector<DrivechainWithdrawalProposalIdentity> proposals(1);
        const bool result = ApplyDrivechainParentBlockState(
            block, 1, slot, required_proposal,
            max_age, threshold, max_age, threshold,
            max_age, threshold, state, &deposits, &error, &withdrawals, &proposals);
        DataStream after;
        after << state;
        BOOST_CHECK(deposits.empty() && withdrawals.empty() && proposals.empty());
        if (!result) {
            BOOST_CHECK(before.str() == after.str());
        } else {
            BOOST_CHECK(state.previous_m4_actions.empty());
            BOOST_CHECK(before.str() != after.str());
        }
        return result;
    };

    std::string error;
    BOOST_CHECK(apply(make_block(
        {make_m7(sidechain_hash)},
        make_m8_script(sidechain_hash, previous_parent, /*nonminimal=*/false)), error));
    BOOST_CHECK(!apply(make_block(
        {}, make_m8_script(sidechain_hash, previous_parent, /*nonminimal=*/false)), error));
    // M1 would add a proposal and no M4 would clear the previous actions, but
    // neither mutation may happen before all M8 requests have been accepted.
    BOOST_CHECK(!apply(make_block(
        {CScript() << OP_RETURN << ParseHex("d5e0c4af180102")},
        make_m8_script(sidechain_hash, previous_parent, /*nonminimal=*/false)), error));
    BOOST_CHECK(!apply(make_block(
        {make_m7(uint256S("44"))},
        make_m8_script(sidechain_hash, previous_parent, /*nonminimal=*/false)), error));
    BOOST_CHECK(!apply(make_block(
        {make_m7(sidechain_hash)},
        make_m8_script(sidechain_hash, uint256S("55"), /*nonminimal=*/false)), error));

    // M8BmmRequest::parse requires the exact PUSHBYTES_68 form. A PUSHDATA1
    // lookalike is not an M8 at all, so both implementations ignore it.
    BOOST_CHECK(apply(make_block(
        {}, make_m8_script(sidechain_hash, previous_parent, /*nonminimal=*/true)), error));
    Bitcoin::CBlock mixed = make_block({make_m7(sidechain_hash)},
        make_m8_script(sidechain_hash, previous_parent, false));
    mixed.vtx.insert(mixed.vtx.begin() + 1, make_block({}, CScript() << OP_TRUE).vtx[1]);
    mixed.vtx.push_back(mixed.vtx.back());
    BOOST_CHECK(apply(mixed, error));
    mixed.vtx.push_back(make_block({}, make_m8_script(sidechain_hash, uint256S("55"), false)).vtx[1]);
    BOOST_CHECK(!apply(mixed, error));
    BOOST_CHECK_EQUAL(error, "BIP301 M8 for slot 24 references an expired parent block");
    mixed.vtx.back() = make_block({}, make_m8_script(uint256S("44"), uint256S("55"), false)).vtx[1];
    BOOST_CHECK(!apply(mixed, error));
    BOOST_CHECK_EQUAL(error, "BIP301 M8 for slot 24 was not accepted by this block's M7");
    const CScript canonical = make_m8_script(sidechain_hash, previous_parent, false);
    BOOST_REQUIRE_EQUAL(canonical.size(), 70U);
    for (size_t length = 0; length < canonical.size(); ++length) {
        BOOST_CHECK(apply(make_block({}, CScript(canonical.begin(), canonical.begin() + length)), error));
    }
    CScript extended = canonical;
    extended.push_back(0);
    BOOST_CHECK(apply(make_block({}, extended), error));
    for (size_t byte = 0; byte < canonical.size(); ++byte) {
        CScript changed = canonical;
        changed[byte] ^= 1;
        // Header corruption is ignored; slot/hash mutations remain real M8s.
        BOOST_CHECK_EQUAL(apply(make_block({}, changed), error), byte < 5);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_parent_commitment_is_domain_separated_and_canonical)
{
    const uint256 parent_hash = uint256S("0123456789abcdef00112233445566778899aabbccddeeff1020304050607080");
    const auto make_block = [](const std::vector<CScript>& scripts) {
        CMutableTransaction coinbase;
        coinbase.vin.emplace_back(COutPoint(), CScript() << OP_0, 0);
        for (const CScript& script : scripts) {
            coinbase.vout.emplace_back(Params().GetConsensus().pegged_asset, 0, script);
        }
        CBlock block;
        block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));
        return block;
    };

    const CScript canonical = CreateDrivechainParentCommitmentScript(parent_hash);
    BOOST_REQUIRE_EQUAL(canonical.size(), 39U);
    BOOST_CHECK_EQUAL(HexStr(Span<const unsigned char>{canonical}.first(7)), "6a25454c4d5450");

    uint256 extracted;
    std::string err;
    for (int shape=0; shape<3; ++shape) {
        CBlock malformed;
        if (shape==1) malformed.vtx.emplace_back();
        if (shape==2) {
            CMutableTransaction ordinary;
            ordinary.vin.emplace_back(COutPoint(Txid::FromUint256(uint256::ONE),0),CScript(),0);
            ordinary.vout.emplace_back(Params().GetConsensus().pegged_asset,0,canonical);
            malformed.vtx.push_back(MakeTransactionRef(std::move(ordinary)));
        }
        extracted = parent_hash;
        err = "old error";
        BOOST_CHECK(!ExtractDrivechainParentHashFromBlock(malformed,extracted,&err));
        BOOST_CHECK(extracted.IsNull());
        BOOST_CHECK_EQUAL(err,"block has no coinbase transaction");
        extracted = parent_hash;
        BOOST_CHECK(!ExtractDrivechainParentHashFromBlock(malformed,extracted,nullptr));
        BOOST_CHECK(extracted.IsNull());
    }
    BOOST_CHECK(ExtractDrivechainParentHashFromBlock(make_block({canonical}), extracted, &err));
    BOOST_CHECK_EQUAL(extracted, parent_hash);

    const std::vector<unsigned char> unrelated_data(32, 0x42);
    BOOST_CHECK(ExtractDrivechainParentHashFromBlock(
        make_block({CScript() << OP_RETURN << unrelated_data, canonical}), extracted, &err));
    BOOST_CHECK_EQUAL(extracted, parent_hash);
    BOOST_CHECK(!ExtractDrivechainParentHashFromBlock(
        make_block({CScript() << OP_RETURN << unrelated_data}), extracted, &err));
    BOOST_CHECK(!ExtractDrivechainParentHashFromBlock(
        make_block({canonical, canonical}), extracted, &err));
    BOOST_CHECK_EQUAL(extracted,parent_hash);
    BOOST_CHECK_EQUAL(err,"block coinbase contains multiple canonical drivechain parent commitments");

    CScript trailing = canonical;
    trailing << OP_TRUE;
    BOOST_CHECK(!ExtractDrivechainParentHashFromBlock(make_block({trailing}), extracted, &err));
    BOOST_CHECK(extracted.IsNull());
    BOOST_CHECK_EQUAL(err,"block coinbase contains a noncanonical ELMTP parent commitment");

    std::vector<unsigned char> payload(canonical.begin() + 2, canonical.end());
    CScript nonminimal;
    nonminimal.push_back(OP_RETURN);
    nonminimal.push_back(OP_PUSHDATA1);
    nonminimal.push_back(payload.size());
    nonminimal.insert(nonminimal.end(), payload.begin(), payload.end());
    BOOST_CHECK(!ExtractDrivechainParentHashFromBlock(make_block({nonminimal}), extracted, &err));
    BOOST_CHECK(!ExtractDrivechainParentHashFromBlock(
        make_block({canonical, nonminimal}), extracted, &err));
    BOOST_CHECK(!ExtractDrivechainParentHashFromBlock(
        make_block({canonical, trailing}), extracted, &err));
    BOOST_CHECK_EQUAL(extracted,parent_hash);
    BOOST_CHECK_EQUAL(err,"block coinbase contains a noncanonical ELMTP parent commitment");
}

bool OriginalNestedTipSane(const DrivechainParentReplayTip& tip)
{
    if (tip.hash.IsNull()) return false;
    if (tip.state.required_proposal_activated) {
        if (tip.state.active_proposal_hash.IsNull() ||
            tip.state.required_activation_block_hash.IsNull() ||
            tip.state.required_activation_height > tip.height) {
            return false;
        }
    } else if (tip.state.required_activation_height != 0 ||
               !tip.state.required_activation_block_hash.IsNull()) {
        return false;
    }
    if (!tip.state.ctip && tip.state.ctip_value != 0) return false;
    if (tip.state.ctip && tip.state.active_proposal_hash.IsNull()) return false;
    if (tip.state.ctip_value < 0 || !MoneyRange(tip.state.ctip_value)) return false;
    for (const auto& proposal : tip.state.pending_proposals) {
        if (proposal.first.IsNull() ||
            proposal.second.proposal_height > tip.height ||
            proposal.second.votes >
                tip.height - proposal.second.proposal_height) {
            return false;
        }
    }
    std::set<uint256> configured_m6ids;
    for (const auto& withdrawal : tip.state.pending_withdrawals) {
        if (withdrawal.proposal_height > tip.height ||
            withdrawal.votes >
                static_cast<uint64_t>(tip.height - withdrawal.proposal_height) + 2 ||
            !configured_m6ids.insert(withdrawal.m6id).second) {
            return false;
        }
    }
    if (tip.state.active_proposal_hash.IsNull() &&
        !tip.state.pending_withdrawals.empty()) {
        return false;
    }
    std::set<Sidechain::Bitcoin::COutPoint> ctips;
    if (tip.state.ctip) ctips.insert(*tip.state.ctip);
    for (const auto& [slot, slot_state] : tip.state.other_slots) {
        if (slot_state.active_proposal_hash.IsNull() && slot_state.ctip) return false;
        if (!slot_state.ctip && slot_state.ctip_value != 0) return false;
        if (slot_state.ctip_value < 0 || !MoneyRange(slot_state.ctip_value)) return false;
        if (slot_state.ctip && !ctips.insert(*slot_state.ctip).second) return false;
        for (const auto& proposal : slot_state.pending_proposals) {
            if (proposal.first.IsNull() ||
                proposal.second.proposal_height > tip.height ||
                proposal.second.votes >
                    tip.height - proposal.second.proposal_height) {
                return false;
            }
        }
        std::set<uint256> m6ids;
        for (const auto& withdrawal : slot_state.pending_withdrawals) {
            if (withdrawal.proposal_height > tip.height ||
                withdrawal.votes >
                    static_cast<uint64_t>(tip.height - withdrawal.proposal_height) + 2 ||
                !m6ids.insert(withdrawal.m6id).second) {
                return false;
            }
        }
        if (slot_state.active_proposal_hash.IsNull() &&
            !slot_state.pending_withdrawals.empty()) {
            return false;
        }
    }
    bool configured_slot_action_seen{false};
    for (const auto& [slot, action] : tip.state.previous_m4_actions) {
        if ((action.type != DrivechainM4ActionType::UPVOTE &&
             action.type != DrivechainM4ActionType::ALARM) ||
            (action.type == DrivechainM4ActionType::ALARM && !action.m6id.IsNull())) {
            return false;
        }
        const auto other_slot = tip.state.other_slots.find(slot);
        if (other_slot != tip.state.other_slots.end()) {
            if (other_slot->second.active_proposal_hash.IsNull()) return false;
        } else {
            // other_slots deliberately excludes the configured slot. At most
            // one action key may therefore be absent from that map, and only
            // while the top-level configured slot is active.
            if (configured_slot_action_seen ||
                tip.state.active_proposal_hash.IsNull()) {
                return false;
            }
            configured_slot_action_seen = true;
        }
    }
    return true;
}

uint256 OriginalReplayStoreIdentity(const Consensus::Params& consensus)
{
    assert(consensus.drivechain_slot.has_value());
    assert(consensus.drivechain_proposal_hash.has_value());
    HashWriter writer;
    writer << std::string{"ELEMENTS_AUTHENTICATED_PARENT_REPLAY_STORE_V4"}
           << std::string{ElementsDrivechainIdentity::BIP300301_ENFORCER_REVISION}
           << std::string{ElementsDrivechainIdentity::BIP300301_LOCAL_RULE_DOMAIN}
           << std::string{ElementsDrivechainIdentity::BIP300301_LOCAL_RULE_ID}
           << Params().HashGenesisBlock()
           << Params().ParentGenesisBlockHash()
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
    return writer.GetHash();
}

BOOST_AUTO_TEST_CASE(replay_snapshot_policy_matches_original_boundaries)
{
    for (bool authenticated : {false, true})
    for (bool current_explicit : {false, true})
    for (bool next_explicit : {false, true})
    for (uint32_t current : {0U, 1U, UINT32_MAX})
    for (uint32_t next : {0U, 1U, UINT32_MAX}) {
        const bool expected = !authenticated || next_explicit || (!current_explicit && next >= current);
        BOOST_CHECK_EQUAL(ShouldReplaceDrivechainReplaySnapshot(
            authenticated, current, current_explicit, next_explicit, next), expected);
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_tip_haskell_matches_original_nested_invariants)
{
    const fs::path path = m_args.GetDataDirBase() / "reconstructed_nested_tips";
    const uint256 identity = uint256S("01");
    DrivechainParentReplayTip seed;
    seed.hash = uint256S("02");
    seed.height = 10;
    for (bool other : {false, true}) {
        for (unsigned variant = 0; variant < 28; ++variant) {
            auto tip = seed;
            auto& state = tip.state;
            state.active_proposal_hash = uint256S("03");
            auto& auxiliary = state.other_slots[25];
            auxiliary.active_proposal_hash = uint256S("04");
            auto& active = other ? auxiliary.active_proposal_hash : state.active_proposal_hash;
            auto& ctip = other ? auxiliary.ctip : state.ctip;
            auto& value = other ? auxiliary.ctip_value : state.ctip_value;
            auto& proposals = other ? auxiliary.pending_proposals : state.pending_proposals;
            auto& withdrawals = other ? auxiliary.pending_withdrawals : state.pending_withdrawals;
            ctip = Bitcoin::COutPoint(uint256S("05"), 0);
            value = 1;
            proposals.emplace(uint256S("06"), DrivechainPendingProposal{8, 2});
            withdrawals.push_back({uint256S("07"), 8, 4});
            switch (variant) {
            case 0: break;
            case 1: tip.hash.SetNull(); break;
            case 2: state.required_proposal_activated = true; break;
            case 3: state.required_activation_height = 1; break;
            case 4: state.required_activation_block_hash = uint256::ONE; break;
            case 5: active.SetNull(); break;
            case 6: ctip.reset(); break;
            case 7: value = -1; break;
            case 8: value = MAX_MONEY + 1; break;
            case 9: proposals.emplace(uint256{}, DrivechainPendingProposal{0, 0}); break;
            case 10: proposals.begin()->second.proposal_height = 11; break;
            case 11: proposals.begin()->second.votes = 3; break;
            case 12: withdrawals.front().proposal_height = 11; break;
            case 13: withdrawals.front().votes = 5; break;
            case 14: withdrawals.push_back(withdrawals.front()); break;
            case 15: ctip.reset(); value = 0; break;
            case 16: withdrawals.front().m6id.SetNull(); break;
            case 17: state.ctip = ctip; auxiliary.ctip = ctip; break;
            case 18: state.previous_m4_actions[24] = {DrivechainM4ActionType::UPVOTE, uint256::ONE}; break;
            case 19: state.previous_m4_actions[25] = {DrivechainM4ActionType::ALARM, uint256{}}; break;
            case 20: state.previous_m4_actions[25] = {DrivechainM4ActionType::ALARM, uint256::ONE}; break;
            case 21: state.previous_m4_actions[25] = {static_cast<DrivechainM4ActionType>(255), uint256{}}; break;
            case 22:
                state.previous_m4_actions[24] = {DrivechainM4ActionType::UPVOTE, uint256::ONE};
                state.previous_m4_actions[26] = {DrivechainM4ActionType::UPVOTE, uint256::ONE};
                break;
            case 23:
                state.required_proposal_activated = true;
                state.required_activation_height = tip.height;
                state.required_activation_block_hash = uint256::ONE;
                break;
            case 24:
                state.required_proposal_activated = true;
                state.required_activation_height = tip.height + 1;
                state.required_activation_block_hash = uint256::ONE;
                break;
            case 25: proposals.clear(); withdrawals.clear(); ctip.reset(); value = 0; active.SetNull(); break;
            case 26: value = MAX_MONEY; break;
            case 27: proposals.begin()->second.votes = 0; withdrawals.front().votes = 0; break;
            }
            const bool sane = OriginalNestedTipSane(tip);
            std::string error;
            {
                DrivechainParentReplayStore store(path, 1 << 20, true);
                BOOST_REQUIRE(store.Reset(identity, seed, &error));
                BOOST_CHECK_EQUAL(store.Reset(identity, tip, &error), sane);
                DrivechainParentReplayTip loaded;
                BOOST_REQUIRE(store.Load(identity, loaded, &error) == DrivechainReplayStoreLoadStatus::LOADED);
                BOOST_CHECK(loaded.hash == (sane ? tip.hash : seed.hash));
            }
            {
                CDBWrapper raw({.path = path, .cache_bytes = 1 << 20});
                BOOST_REQUIRE(raw.Write(uint8_t{'T'}, tip, true));
            }
            {
                DrivechainParentReplayStore store(path, 1 << 20, false);
                DrivechainParentReplayTip loaded;
                const auto result = store.Load(identity, loaded, &error);
                BOOST_CHECK(result == (sane ? DrivechainReplayStoreLoadStatus::LOADED : DrivechainReplayStoreLoadStatus::CORRUPT));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_work_helpers_match_original_arithmetic_and_errors)
{
    std::vector<uint32_t> encodings{0,1,0x01010000,0x01810000,0x02008000,0x03000001,
        0x1d00ffff,0x1d80ffff,0x207fffff,0x2100ffff,0x220000ff,0x23000001,UINT32_MAX};
    uint32_t random{0x12345678};
    for (unsigned i = 0; i < 512; ++i) { random = random * 1664525 + 1013904223; encodings.push_back(random); }
    const auto max_hash = uint256S(std::string(64,'f'));
    for (uint32_t bits : encodings) {
        bool negative{false}, overflow{false};
        arith_uint256 target, proof;
        target.SetCompact(bits, &negative, &overflow);
        if (!negative && !overflow && target != 0) proof = (~target / (target + 1)) + 1;
        BOOST_CHECK(GetDrivechainParentBlockProof(bits) == proof);
        for (const auto& hash : {uint256{}, ArithToUint256(target), ArithToUint256(target + 1), max_hash})
        for (bool diagnostic : {false,true}) {
            std::string error{"unchanged"}, expected_error = error;
            const bool valid_target = !(negative || target == 0 || overflow || target > UintToArith256(Params().GetConsensus().parentChainPowLimit));
            const bool accepted = valid_target && UintToArith256(hash) <= target;
            if (diagnostic && !accepted) expected_error = valid_target ? "parent header does not satisfy its proof-of-work target" : "parent header has an invalid proof-of-work target";
            BOOST_CHECK_EQUAL(CheckDrivechainParentProofOfWork(hash, bits, diagnostic ? &error : nullptr), accepted);
            BOOST_CHECK_EQUAL(error, expected_error);
        }
        for (const auto& parent : {uint256{}, uint256S("1234"), max_hash})
        for (unsigned delta : {0U,1U})
        for (bool diagnostic : {false,true}) {
            const auto successor = ArithToUint256(UintToArith256(parent) + proof + delta);
            const bool accepted = proof != 0 && UintToArith256(successor) == UintToArith256(parent) + proof;
            std::string error{"unchanged"};
            BOOST_CHECK_EQUAL(CheckDrivechainParentChainwork(parent, successor, bits, diagnostic ? &error : nullptr), accepted);
            BOOST_CHECK_EQUAL(error, diagnostic && !accepted ? "parent RPC chainwork does not match the authenticated successor header" : "unchanged");
        }
    }
}

BOOST_AUTO_TEST_CASE(verified_parent_headers_match_original_sources_and_publication)
{
    const auto pinned = uint256S("1234"), previous_hash = uint256S(std::string(64,'a'));
    struct Outcome {
        VerifiedMainchainHeader verified;
        bool accepted{false};
        std::string error{"unchanged"}, exception;
        std::vector<std::string> trace;
    };
    const auto state = [](const VerifiedMainchainHeader& verified) {
        DataStream stream;
        stream << verified.header << verified.chainwork << verified.height << verified.confirmations << verified.median_time_past;
        return stream.str();
    };
    for (unsigned scenario = 0; scenario < 21; ++scenario)
    for (bool diagnostic : {false,true})
    for (unsigned fault = 0; fault <= 12; ++fault) {
        const int minimum = scenario == 2 ? 0 : scenario == 3 ? -1 : 6;
        const int64_t height = scenario == 1 || scenario == 17 ? 0 : 10;
        Bitcoin::CBlockHeader raw;
        raw.hashPrevBlock = height == 0 ? uint256{} : previous_hash;
        raw.nBits = scenario == 17 ? 0 : 0x207fffff;
        raw.nTime = 123;
        const auto hash = raw.GetHash();
        const auto prior = uint256S("1234");
        const auto work = ArithToUint256(GetDrivechainParentBlockProof(raw.nBits) + (height == 0 ? arith_uint256{} : UintToArith256(prior)));
        UniValue metadata(UniValue::VOBJ), predecessor(UniValue::VOBJ);
        metadata.pushKV("hash", scenario == 7 ? uint256{}.GetHex() : hash.GetHex());
        UniValue height_json(height);
        if (scenario == 8) height_json = UniValue(-1);
        if (scenario == 18) BOOST_REQUIRE(height_json.read("1e0"));
        metadata.pushKV("height", height_json);
        metadata.pushKV("confirmations", scenario == 9 ? 5 : 6);
        metadata.pushKV("chainwork", scenario == 10 ? std::string(64,'A') : work.GetHex());
        metadata.pushKV("previousblockhash", height == 0 ? UniValue{} : UniValue(scenario == 14 ? uint256{}.GetHex() : previous_hash.GetHex()));
        predecessor.pushKV("hash", previous_hash.GetHex());
        predecessor.pushKV("height", scenario == 19 ? 3 : height-1);
        predecessor.pushKV("chainwork", scenario == 20 ? uint256{}.GetHex() : prior.GetHex());
        if (scenario == 6) metadata = UniValue{};
        if (scenario == 15) predecessor = UniValue{};
        const std::vector<UniValue> responses{
            UniValue(scenario == 4 ? "bad" : scenario == 5 ? uint256{}.GetHex() : pinned.GetHex()),
            metadata, UniValue(scenario == 11 ? uint256{}.GetHex() : scenario == 12 ? "bad" : hash.GetHex()), predecessor};
        const auto run = [&](bool migrated) {
            Outcome out;
            out.verified.header.nNonce = 99;
            out.verified.chainwork = uint256S("77");
            out.verified.height = 88;
            out.verified.confirmations = 99;
            out.verified.median_time_past = 111;
            unsigned requests{0};
            const auto event = [&](std::string text) {
                out.trace.push_back(std::move(text));
                if (out.trace.size()-1 == fault) throw std::runtime_error("injected source failure");
            };
            const auto reject = [&](const std::string& message) { if (diagnostic) out.error = message; return false; };
            const DrivechainParentHeaderSource source{
                [&]() -> const uint256& { event("pinned genesis"); return pinned; },
                [&](const std::string& method, const UniValue& params) { event(method + ":" + params.write()); return responses.at(requests++); },
                [&](const uint256& requested, Bitcoin::CBlockHeader& header, std::string*) {
                    event("raw:" + requested.GetHex()); header = raw;
                    return scenario == 13 ? reject("raw rejected") : true;
                },
                [&](const uint256& requested, uint32_t at_height, uint64_t& median, std::string*) {
                    event("median:" + requested.GetHex() + ":" + std::to_string(at_height)); median = 987;
                    return scenario == 16 ? reject("median rejected") : true;
                },
                [&] { event("deadline"); }};
            try {
                if (migrated) out.accepted = VerifyDrivechainParentHeader(hash, minimum, out.verified, diagnostic ? &out.error : nullptr, source);
                else out.accepted = [&] {
                    if (minimum < 1) return reject("minimum parent confirmations must be positive");
                    UniValue genesis_params(UniValue::VARR);
                    genesis_params.push_back(0);
                    uint256 rpc_genesis;
                    const auto genesis = source.request("getblockhash", genesis_params);
                    if (!ParseDrivechainCanonicalHash(genesis, rpc_genesis) || rpc_genesis != source.genesis())
                        return reject(strprintf("mainchain RPC genesis does not match pinned parent genesis %s", source.genesis().GetHex()));
                    UniValue params(UniValue::VARR);
                    params.push_back(hash.GetHex()); params.push_back(true);
                    const auto object = source.request("getblockheader", params);
                    uint256 parsed_work;
                    int64_t parsed_height{0}, confirmations{0};
                    if (!ParseDrivechainParentHeaderMetadata(object, hash, minimum, parsed_work, parsed_height, confirmations, diagnostic ? &out.error : nullptr)) return false;
                    UniValue active_params(UniValue::VARR);
                    active_params.push_back(parsed_height);
                    uint256 active_hash;
                    const auto active = source.request("getblockhash", active_params);
                    if (!ParseDrivechainCanonicalHash(active, active_hash) || active_hash != hash)
                        return reject("parent block is not the active-chain block at its declared height");
                    Bitcoin::CBlockHeader header;
                    if (!source.raw_header(hash, header, diagnostic ? &out.error : nullptr)) return false;
                    const auto& previous = object.get_obj()["previousblockhash"];
                    if (!CheckDrivechainParentPredecessor(previous, parsed_height, header, parsed_work, diagnostic ? &out.error : nullptr, source.request)) return false;
                    uint64_t median{0};
                    if (!source.median_time(hash, parsed_height, median, diagnostic ? &out.error : nullptr)) return false;
                    source.deadline();
                    out.verified.header = header;
                    out.verified.chainwork = parsed_work;
                    out.verified.height = static_cast<uint32_t>(parsed_height);
                    out.verified.confirmations = confirmations;
                    out.verified.median_time_past = median;
                    if (out.verified.chainwork.IsNull()) return reject("parent chainwork cannot be zero");
                    return true;
                }();
            } catch (const std::exception& e) { out.exception = e.what(); }
            return out;
        };
        const auto expected = run(false), actual = run(true);
        BOOST_CHECK_EQUAL(actual.accepted, expected.accepted);
        BOOST_CHECK_EQUAL(actual.error, expected.error);
        BOOST_CHECK_EQUAL(actual.exception, expected.exception);
        BOOST_CHECK(actual.trace == expected.trace);
        BOOST_CHECK(state(actual.verified) == state(expected.verified));
        if (fault == 12 && scenario == 17) {
            BOOST_CHECK(!actual.accepted);
            BOOST_CHECK(actual.verified.chainwork.IsNull());
            BOOST_CHECK_EQUAL(actual.verified.median_time_past, 987U);
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_predecessor_matches_original_rpc_and_validation)
{
    const auto previous_hash = uint256S(std::string(64,'a'));
    const auto prior_work = uint256S("1234");
    std::vector<UniValue> values;
    for (const auto* json : {"null","true","[]","{}","-1","0","1","9","4294967294","9223372036854775808","1.0"}) {
        UniValue value;
        BOOST_REQUIRE(value.read(json));
        values.push_back(value);
    }
    for (const auto& text : {std::string(64,'a'), std::string(64,'A'), std::string(64,'0'), prior_work.GetHex()}) values.emplace_back(text);
    struct Outcome {
        bool accepted{false};
        std::string error{"unchanged"}, exception;
        std::vector<std::string> requests;
    };
    for (int64_t height : {int64_t{0},int64_t{1},int64_t{10},int64_t{UINT32_MAX}})
    for (uint32_t bits : {0U,0x207fffffU,0x1d00ffffU})
    for (bool null_previous : {false,true})
    for (unsigned delta : {0U,1U}) {
        Bitcoin::CBlockHeader raw;
        raw.hashPrevBlock = null_previous ? uint256{} : previous_hash;
        raw.nBits = bits;
        const auto proof = GetDrivechainParentBlockProof(bits);
        const auto work = ArithToUint256((height == 0 ? arith_uint256{} : UintToArith256(prior_work)) + proof + delta);
        const std::array<std::string,3> fields{"hash","chainwork","height"};
        const std::array<UniValue,3> defaults{UniValue(previous_hash.GetHex()), UniValue(prior_work.GetHex()), UniValue(height-1)};
        std::vector<UniValue> metadata = values;
        for (unsigned field = 0; field < 3; ++field)
        for (const auto& value : values) {
            UniValue object(UniValue::VOBJ);
            for (unsigned i = 0; i < 3; ++i) object.pushKV(fields[i], i == field ? value : defaults[i]);
            metadata.push_back(object);
        }
        UniValue valid(UniValue::VOBJ);
        for (unsigned i = 0; i < 3; ++i) valid.pushKV(fields[i], defaults[i]);
        metadata.push_back(valid);
        for (const auto& previous : {UniValue{}, UniValue(previous_hash.GetHex()), UniValue(std::string(64,'A')), UniValue(std::string(64,'0'))})
        for (const auto& response : metadata)
        for (bool rpc_fault : {false,true})
        for (bool diagnostic : {false,true}) {
            const auto run = [&](bool migrated) {
                Outcome out;
                const auto reject = [&](const std::string& message) { if (diagnostic) out.error = message; return false; };
                const auto request = [&](const std::string& method, const UniValue& params) {
                    out.requests.push_back(method + ":" + params.write());
                    if (rpc_fault) throw std::runtime_error("fixture RPC failure");
                    return response;
                };
                try {
                    if (migrated) out.accepted = CheckDrivechainParentPredecessor(previous, height, raw, work, diagnostic ? &out.error : nullptr, request);
                    else out.accepted = [&] {
                        if (height == 0) {
                            if (!previous.isNull() || !raw.hashPrevBlock.IsNull()) return reject("parent genesis unexpectedly has a predecessor");
                            if (UintToArith256(work) != GetDrivechainParentBlockProof(raw.nBits)) return reject("parent genesis chainwork does not match its authenticated header");
                        } else {
                            uint256 parsed_previous;
                            if (!ParseDrivechainCanonicalHash(previous, parsed_previous) || parsed_previous != raw.hashPrevBlock)
                                return reject("verbose and raw parent headers disagree about previous block");
                            UniValue params(UniValue::VARR);
                            params.push_back(parsed_previous.GetHex());
                            params.push_back(true);
                            const auto object = request("getblockheader", params);
                            if (!object.isObject()) return reject("previous getblockheader result is not an object");
                            uint256 returned, previous_work;
                            const auto& previous_height = object.get_obj()["height"];
                            if (!ParseDrivechainCanonicalHash(object.get_obj()["hash"], returned) || returned != parsed_previous ||
                                !ParseDrivechainCanonicalHash(object.get_obj()["chainwork"], previous_work) ||
                                !previous_height.isNum() || previous_height.getInt<int64_t>() != height-1)
                                return reject("previous parent metadata is not canonical or contiguous");
                            const auto block_proof = GetDrivechainParentBlockProof(raw.nBits);
                            if (block_proof == 0 || UintToArith256(work) != UintToArith256(previous_work) + block_proof)
                                return reject("parent chainwork does not match its authenticated header and predecessor");
                        }
                        return true;
                    }();
                } catch (const std::exception& e) { out.exception = e.what(); }
                return out;
            };
            const auto expected = run(false), actual = run(true);
            BOOST_CHECK_EQUAL(actual.accepted, expected.accepted);
            BOOST_CHECK_EQUAL(actual.error, expected.error);
            BOOST_CHECK_EQUAL(actual.exception, expected.exception);
            BOOST_CHECK(actual.requests == expected.requests);
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_header_metadata_matches_original_errors_exceptions_and_outputs)
{
    const auto requested = uint256S(std::string(64, 'a'));
    std::vector<UniValue> values;
    for (const auto* json : {"null","true","[]","{}","-1","0","1","6","4294967295","4294967296",
        "9223372036854775807","9223372036854775808","-9223372036854775809","1.0","1e0"}) {
        UniValue value;
        BOOST_REQUIRE(value.read(json));
        values.push_back(value);
    }
    for (const auto& text : {std::string{}, std::string(64,'a'), std::string(64,'A'), std::string(64,'0'), std::string(64,'g')}) values.emplace_back(text);
    std::vector<UniValue> cases = values;
    const std::array<std::string,4> fields{"hash","height","confirmations","chainwork"};
    const std::array<UniValue,4> defaults{UniValue(requested.GetHex()), UniValue(10), UniValue(6), UniValue(std::string(64,'a'))};
    for (size_t first = 0; first < fields.size(); ++first)
    for (size_t second = first; second < fields.size(); ++second)
    for (const auto& a : values)
    for (const auto& b : values) {
        UniValue object(UniValue::VOBJ);
        for (size_t i = 0; i < fields.size(); ++i) object.pushKV(fields[i], i == first ? a : i == second ? b : defaults[i]);
        cases.push_back(object);
    }
    for (unsigned missing = 0; missing < 16; ++missing) {
        UniValue object(UniValue::VOBJ);
        for (unsigned i = 0; i < 4; ++i) if (!(missing & (1U<<i))) object.pushKV(fields[i], defaults[i]);
        cases.push_back(object);
    }
    struct Result {
        uint256 work{uint256S("dead")};
        int64_t height{77}, confirmations{88};
        bool accepted{false};
        std::string error{"unchanged"}, exception;
    };
    for (const auto& metadata : cases)
    for (int minimum : {1,6,INT_MAX})
    for (bool diagnostic : {false,true}) {
        const auto run = [&](bool migrated) {
            Result result;
            const auto reject = [&](const std::string& message) { if (diagnostic) result.error = message; return false; };
            try {
                if (migrated) result.accepted = ParseDrivechainParentHeaderMetadata(metadata, requested, minimum,
                    result.work, result.height, result.confirmations, diagnostic ? &result.error : nullptr);
                else result.accepted = [&] {
                    if (!metadata.isObject()) return reject("getblockheader result is not an object");
                    uint256 returned;
                    if (!ParseDrivechainCanonicalHash(metadata.get_obj()["hash"], returned) || returned != requested)
                        return reject("getblockheader hash does not match requested parent block");
                    const auto& height = metadata.get_obj()["height"];
                    const auto& confirmations = metadata.get_obj()["confirmations"];
                    const auto& work = metadata.get_obj()["chainwork"];
                    if (!height.isNum() || !confirmations.isNum() || !ParseDrivechainCanonicalHash(work, result.work))
                        return reject("getblockheader is missing canonical height, confirmations, or chainwork");
                    result.height = height.getInt<int64_t>();
                    result.confirmations = confirmations.getInt<int64_t>();
                    if (result.height < 0 || result.height > UINT32_MAX || result.confirmations < minimum)
                        return reject(strprintf("parent block has %d confirmations; %d required", result.confirmations, minimum));
                    return true;
                }();
            } catch (const std::exception& e) { result.exception = e.what(); }
            return result;
        };
        const auto expected = run(false), actual = run(true);
        BOOST_CHECK_EQUAL(actual.accepted, expected.accepted);
        BOOST_CHECK_EQUAL(actual.error, expected.error);
        BOOST_CHECK_EQUAL(actual.exception, expected.exception);
        BOOST_CHECK(actual.work == expected.work);
        BOOST_CHECK_EQUAL(actual.height, expected.height);
        BOOST_CHECK_EQUAL(actual.confirmations, expected.confirmations);
    }
}

BOOST_AUTO_TEST_CASE(parent_median_time_preserves_traversal_and_success_only_publication)
{
    struct Fault {};
    struct Outcome {
        bool accepted{false}, threw{false};
        uint64_t value{UINT64_MAX};
        std::vector<std::string> trace;
    };
    for (uint32_t height : {0U,1U,2U,3U,4U,5U,6U,7U,8U,9U,10U,11U,12U,UINT32_MAX-1,UINT32_MAX})
    for (unsigned pattern = 0; pattern < 4; ++pattern) {
        std::vector<Bitcoin::CBlockHeader> headers(11);
        uint256 previous;
        for (unsigned i = 11; i-- > 0;) {
            headers[i].hashPrevBlock = previous;
            headers[i].nTime = pattern == 0 ? i : pattern == 1 ? 10-i : pattern == 2 ? UINT32_MAX : (i*7)%11;
            previous = headers[i].GetHash();
        }
        const auto count = std::min<uint64_t>(11, uint64_t{height} + 1);
        for (unsigned failed_read = 0; failed_read <= count; ++failed_read)
        for (unsigned fault = 0; fault <= 2*count+1; ++fault) {
            const auto run = [&](bool migrated) {
                Outcome out;
                unsigned reads{0};
                const auto event = [&](std::string text) {
                    out.trace.push_back(std::move(text));
                    if (out.trace.size()-1 == fault) throw Fault{};
                };
                const auto deadline = [&] { event("deadline"); };
                const auto read = [&](const uint256& hash, Bitcoin::CBlockHeader& header) {
                    event(hash.GetHex());
                    if (reads == failed_read) return false;
                    header = headers.at(reads++);
                    return true;
                };
                try {
                    if (migrated) out.accepted = ComputeDrivechainParentMedianTimePast(previous, height, out.value, read, deadline);
                    else {
                        // Widen only the old overflowing count; all defined inputs retain the original algorithm.
                        const auto original = [&] {
                            std::vector<uint32_t> times;
                            times.reserve(11);
                            auto hash = previous;
                            for (unsigned i = 0; i < count; ++i) {
                                deadline();
                                Bitcoin::CBlockHeader header;
                                if (!read(hash, header)) return false;
                                times.push_back(header.nTime);
                                hash = header.hashPrevBlock;
                            }
                            std::sort(times.begin(), times.end());
                            deadline();
                            out.value = times[times.size()/2];
                            return true;
                        };
                        out.accepted = original();
                    }
                } catch (const Fault&) { out.threw = true; }
                return out;
            };
            const auto expected = run(false), actual = run(true);
            BOOST_CHECK_EQUAL(actual.accepted, expected.accepted);
            BOOST_CHECK_EQUAL(actual.threw, expected.threw);
            BOOST_CHECK_EQUAL(actual.value, expected.value);
            BOOST_CHECK(actual.trace == expected.trace);
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_recovery_deadline_preserves_nested_lifetimes_and_unwinding)
{
    using Clock = std::chrono::steady_clock;
    using Point = Clock::time_point;
    using Optional = std::optional<Point>;
    static_assert(!std::is_copy_constructible_v<DrivechainParentRecoveryDeadline>);
    static_assert(!std::is_move_constructible_v<DrivechainParentRecoveryDeadline>);
    static_assert(std::is_nothrow_destructible_v<DrivechainParentRecoveryDeadline>);
    const auto point = [](int seconds) { return Point{std::chrono::seconds{seconds}}; };
    struct Original {
        Optional& current;
        const Optional previous;
        Original(Optional& value, const std::function<Point()>& now) : current(value), previous(value) {
            const auto limit = now() + std::chrono::seconds{30};
            if (!previous || limit < *previous) current = limit;
        }
        ~Original() { current = previous; }
    };
    struct Outcome {
        Optional current;
        std::vector<Optional> observations;
        std::string trace, exception;
    };
    for (const auto& initial : {Optional{},Optional{point(99)},Optional{point(129)},Optional{point(130)},Optional{point(131)}})
    for (int nested_now : {0,99,100,101,200})
    for (unsigned mode = 0; mode < 6; ++mode) {
        const auto run = [&](bool migrated) {
            Outcome out;
            out.current = initial;
            const auto outer_clock = [&] {
                out.trace += 'O'; out.observations.push_back(out.current);
                if (mode == 1) throw std::runtime_error("outer clock");
                return point(100);
            };
            const auto inner_clock = [&] {
                out.trace += 'I'; out.observations.push_back(out.current);
                if (mode == 2) throw std::runtime_error("inner clock");
                return point(nested_now);
            };
            const auto inner_body = [&] {
                out.trace += 'B'; out.observations.push_back(out.current);
                if (mode == 3) throw std::runtime_error("inner body");
                if (mode == 4) out.current = point(999);
            };
            const auto outer_body = [&] {
                out.trace += 'A'; out.observations.push_back(out.current);
                try {
                    if (migrated) { DrivechainParentRecoveryDeadline inner(out.current,inner_clock); inner_body(); }
                    else { Original inner(out.current,inner_clock); inner_body(); }
                } catch (...) {
                    out.trace += 'E'; out.observations.push_back(out.current); throw;
                }
                out.trace += 'R'; out.observations.push_back(out.current);
                if (mode == 5) throw std::runtime_error("outer body");
            };
            try {
                if (migrated) { DrivechainParentRecoveryDeadline outer(out.current,outer_clock); outer_body(); }
                else { Original outer(out.current,outer_clock); outer_body(); }
            } catch (const std::exception& e) { out.exception = e.what(); }
            out.observations.push_back(out.current);
            return out;
        };
        const auto expected = run(false), actual = run(true);
        BOOST_CHECK(actual.current == initial);
        BOOST_CHECK(actual.current == expected.current);
        BOOST_CHECK(actual.observations == expected.observations);
        BOOST_CHECK_EQUAL(actual.trace, expected.trace);
        BOOST_CHECK_EQUAL(actual.exception, expected.exception);
    }
}

BOOST_AUTO_TEST_CASE(parent_block_signet_preserves_lazy_configuration_and_deadlines)
{
    Bitcoin::CMutableTransaction coinbase;
    coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0, 0);
    std::vector<unsigned char> commitment{0xaa,0x21,0xa9,0xed};
    commitment.resize(36,0x42);
    coinbase.vout.emplace_back(0, CScript() << OP_RETURN << commitment);
    for (unsigned shape = 0; shape < 3; ++shape)
    for (unsigned script = 0; script < 4; ++script)
    for (bool pinned : {false,true})
    for (bool diagnostic : {false,true})
    for (unsigned fault = 0; fault < 4; ++fault) {
        Bitcoin::CBlock block;
        auto tx = coinbase;
        if (shape == 1) tx.vout.clear();
        if (shape != 2) block.vtx.push_back(Bitcoin::MakeTransactionRef(tx));
        const std::vector<uint8_t> challenge = script == 0 ? std::vector<uint8_t>{} :
            std::vector<uint8_t>{uint8_t(script == 1 ? OP_TRUE : script == 2 ? OP_0 : OP_RETURN)};
        const auto genesis = pinned ? block.GetHash() : uint256::ONE;
        struct Outcome { bool accepted{false}; std::string error{"unchanged"}, exception, trace; };
        const auto run = [&](bool migrated) {
            Outcome out;
            const auto event = [&](char step) { out.trace += step; if (out.trace.size()-1 == fault) throw std::runtime_error("source fault"); };
            const auto read_challenge = [&]() -> const std::vector<uint8_t>& { event('C'); return challenge; };
            const auto read_genesis = [&]() -> const uint256& { event('G'); return genesis; };
            const auto deadline = [&] { event('D'); };
            try {
                if (migrated) out.accepted = CheckDrivechainParentBlockSignet(block, diagnostic ? &out.error : nullptr, read_challenge, read_genesis, deadline);
                else out.accepted = [&] {
                    const auto& bytes = read_challenge();
                    if (!bytes.empty()) {
                        const CScript native(bytes.begin(),bytes.end());
                        if (!CheckBitcoinSignetBlockSolution(block,native,read_genesis(),diagnostic ? &out.error : nullptr)) return false;
                        deadline();
                    }
                    return true;
                }();
            } catch (const std::exception& e) { out.exception = e.what(); }
            return out;
        };
        const auto expected = run(false), actual = run(true);
        BOOST_CHECK_EQUAL(actual.accepted, expected.accepted);
        BOOST_CHECK_EQUAL(actual.error, expected.error);
        BOOST_CHECK_EQUAL(actual.exception, expected.exception);
        BOOST_CHECK_EQUAL(actual.trace, expected.trace);
    }
}

BOOST_AUTO_TEST_CASE(verified_parent_blocks_preserve_partial_outputs_and_reader_order)
{
    struct Outcome {
        Bitcoin::CBlock block;
        VerifiedMainchainHeader verified;
        bool accepted{false};
        std::string error{"unchanged"}, exception, trace;
    };
    const auto snapshot = [](const Outcome& out) {
        DataStream stream;
        stream << out.block.GetBlockHeader() << out.block.fChecked << out.verified.header << out.verified.chainwork
            << out.verified.height << out.verified.confirmations << out.verified.median_time_past;
        return stream.str();
    };
    for (unsigned flags = 0; flags < 8; ++flags)
    for (bool diagnostic : {false,true})
    for (unsigned fault = 0; fault < 3; ++fault) {
        const auto run = [&](bool migrated) {
            Outcome out;
            out.block.nNonce = 77;
            out.verified.header.nNonce = 88;
            unsigned calls{0};
            const auto record = [&](const std::string& text) { out.trace += text; if (calls++ == fault) throw std::runtime_error("reader fault"); };
            const auto header = [&](const uint256& hash, int minimum, VerifiedMainchainHeader& verified, std::string* error) {
                verified.header.nNonce = 123;
                verified.chainwork = uint256::ONE;
                verified.height = 10; verified.confirmations = minimum; verified.median_time_past = 456;
                record("H:" + hash.GetHex() + ":" + std::to_string(minimum));
                if (!(flags & 1) && error) *error = "header rejected";
                return bool(flags & 1);
            };
            const auto body = [&](const uint256& hash, Bitcoin::CBlock& block, std::string* error) {
                block.nNonce = flags & 4 ? 123 : 124; block.fChecked = true;
                record("B:" + hash.GetHex());
                if (!(flags & 2) && error) *error = "body rejected";
                return bool(flags & 2);
            };
            try {
                if (migrated) out.accepted = VerifyDrivechainParentBlock(uint256::ONE, 6, out.block, out.verified,
                    diagnostic ? &out.error : nullptr, header, body);
                else out.accepted = [&] {
                    if (!header(uint256::ONE,6,out.verified,diagnostic ? &out.error : nullptr)) return false;
                    if (!body(uint256::ONE,out.block,diagnostic ? &out.error : nullptr)) return false;
                    if (out.block.GetBlockHeader().GetHash() != out.verified.header.GetHash()) {
                        if (diagnostic) out.error = "raw parent block header does not match authenticated header";
                        return false;
                    }
                    return true;
                }();
            } catch (const std::exception& e) { out.exception = e.what(); }
            return out;
        };
        const auto expected = run(false), actual = run(true);
        BOOST_CHECK_EQUAL(actual.accepted, expected.accepted);
        BOOST_CHECK_EQUAL(actual.error, expected.error);
        BOOST_CHECK_EQUAL(actual.exception, expected.exception);
        BOOST_CHECK_EQUAL(actual.trace, expected.trace);
        BOOST_CHECK(snapshot(actual) == snapshot(expected));
    }
}

BOOST_AUTO_TEST_CASE(parent_block_transactions_match_original_merkle_and_deadline_order)
{
    Bitcoin::CMutableTransaction coinbase;
    coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
    coinbase.vout.emplace_back(50, CScript() << OP_TRUE);
    const auto reward = Bitcoin::MakeTransactionRef(coinbase);
    std::vector<Bitcoin::CTransactionRef> transactions{reward};
    for (unsigned i = 1; i < 513; ++i) {
        auto tx = coinbase;
        tx.vin[0].prevout = Bitcoin::COutPoint(uint256::ONE, i);
        transactions.push_back(Bitcoin::MakeTransactionRef(std::move(tx)));
    }
    struct Outcome {
        bool accepted{false};
        unsigned deadlines{0};
        std::string error{"unchanged"}, exception;
    };
    for (unsigned size : {0U,1U,2U,3U,4U,255U,256U,257U,511U,512U,513U})
    for (unsigned variation = 0; variation < 9; ++variation)
    for (bool diagnostic : {false,true})
    for (unsigned fault = 0; fault < 7; ++fault) {
        Bitcoin::CBlock block;
        block.vtx.assign(transactions.begin(), transactions.begin()+size);
        if (size > 0 && variation == 1) block.vtx[0].reset();
        if (size > 0 && variation == 2) block.vtx[0] = transactions[1];
        if (size > 1 && variation == 3) block.vtx[size-1].reset();
        if (size > 1 && variation == 4) block.vtx[size-1] = reward;
        if (size > 256 && variation == 5) block.vtx[256].reset();
        if (size > 256 && variation == 6) block.vtx[256] = reward;
        if (size > 2 && variation == 7) block.vtx[size-1] = block.vtx[size-2];
        std::vector<uint256> hashes;
        for (const auto& tx : block.vtx) hashes.push_back(tx ? tx->GetHash() : uint256{});
        block.hashMerkleRoot = variation == 8 ? uint256::ONE : ComputeMerkleRoot(hashes);
        const auto run = [&](bool migrated) {
            Outcome out;
            const auto reject = [&](const char* message) { if (diagnostic) out.error = message; return false; };
            const auto deadline = [&] { if (out.deadlines++ == fault) throw std::runtime_error("fixture deadline"); };
            try {
                if (migrated) out.accepted = CheckDrivechainParentBlockTransactions(block, diagnostic ? &out.error : nullptr, deadline);
                else out.accepted = [&] {
                    if (block.vtx.empty() || !block.vtx[0] || !block.vtx[0]->IsCoinBase()) return reject("raw parent block has no coinbase transaction");
                    for (size_t i = 1; i < block.vtx.size(); ++i) {
                        if ((i & 0xffU) == 0) deadline();
                        if (!block.vtx[i] || block.vtx[i]->IsCoinBase()) return reject("raw parent block has a null transaction or multiple coinbases");
                    }
                    bool mutated{false};
                    std::vector<uint256> transaction_hashes;
                    transaction_hashes.reserve(block.vtx.size());
                    for (size_t i = 0; i < block.vtx.size(); ++i) {
                        if ((i & 0xffU) == 0) deadline();
                        transaction_hashes.push_back(block.vtx[i]->GetHash());
                    }
                    if (ComputeMerkleRoot(std::move(transaction_hashes), &mutated) != block.hashMerkleRoot || mutated)
                        return reject("raw parent block has an invalid or mutated transaction Merkle tree");
                    deadline();
                    return true;
                }();
            } catch (const std::exception& e) { out.exception = e.what(); }
            return out;
        };
        const auto expected = run(false), actual = run(true);
        BOOST_CHECK_EQUAL(actual.accepted, expected.accepted);
        BOOST_CHECK_EQUAL(actual.deadlines, expected.deadlines);
        BOOST_CHECK_EQUAL(actual.error, expected.error);
        BOOST_CHECK_EQUAL(actual.exception, expected.exception);
    }
}

BOOST_AUTO_TEST_CASE(parent_raw_blocks_preserve_witness_decode_mutation_and_deadlines)
{
    Bitcoin::CBlock block;
    block.nVersion = 1;
    block.hashMerkleRoot = uint256S("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
    block.nTime = 1296688602;
    block.nBits = 0x207fffff;
    block.nNonce = 2;
    Bitcoin::CMutableTransaction transaction;
    transaction.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
    transaction.vout.emplace_back(123, CScript() << OP_TRUE);
    block.vtx.push_back(Bitcoin::MakeTransactionRef(transaction));
    transaction.vin[0].prevout = Bitcoin::COutPoint(uint256::ONE, 7);
    transaction.vin[0].scriptWitness.stack = {{1,2,3},{4,5},{}};
    block.vtx.push_back(Bitcoin::MakeTransactionRef(transaction));
    const auto encode = [](const Bitcoin::CBlock& value) {
        DataStream stream;
        stream << TX_WITH_WITNESS(value);
        const auto bytes = stream.str();
        return HexStr(Span<const unsigned char>{reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size()});
    };
    // Partial vector decoding may leave null entries; do not dereference those when recording state.
    const auto snapshot = [](const Bitcoin::CBlock& value) {
        DataStream stream;
        stream << value.GetBlockHeader() << value.fChecked << uint64_t{value.vtx.size()};
        for (const auto& tx : value.vtx) {
            stream << bool(tx);
            if (tx) stream << TX_WITH_WITNESS(*tx);
        }
        return stream.str();
    };
    const auto hex = encode(block);
    std::vector<std::pair<UniValue,uint256>> cases;
    for (size_t length = 0; length <= hex.size(); length += 2) cases.emplace_back(UniValue(hex.substr(0,length)), block.GetHash());
    for (const auto* json : {"null","true","0","[]","{}"}) {
        UniValue value;
        BOOST_REQUIRE(value.read(json));
        cases.emplace_back(value, block.GetHash());
    }
    for (const auto& text : {std::string("0"),std::string("gg"),hex + "00",hex.substr(0,160) + "fd0100"}) cases.emplace_back(UniValue(text),block.GetHash());
    cases.emplace_back(UniValue(hex), uint256{});
    for (uint32_t bits : {0U,0x01810000U,0x23000001U,0x03000001U}) {
        auto altered = block;
        altered.nBits = bits;
        cases.emplace_back(UniValue(encode(altered)), altered.GetHash());
    }
    auto empty = block;
    empty.vtx.clear();
    cases.emplace_back(UniValue(encode(empty)), empty.GetHash());
    struct Outcome {
        Bitcoin::CBlock value;
        bool accepted{false};
        unsigned deadlines{0};
        std::string error{"unchanged"}, exception;
    };
    for (const auto& [raw,hash] : cases)
    for (bool diagnostic : {false,true})
    for (unsigned fault = 0; fault < 3; ++fault) {
        const auto run = [&](bool migrated) {
            Outcome out;
            out.value = block;
            out.value.nNonce = 88;
            out.value.hashPrevBlock = uint256S("dead");
            out.value.fChecked = true;
            const auto reject = [&](const std::string& message) { if (diagnostic) out.error = message; return false; };
            const auto deadline = [&] { if (out.deadlines++ == fault) throw std::runtime_error("fixture deadline"); };
            try {
                if (migrated) out.accepted = DecodeDrivechainRawParentBlock(raw, hash, out.value, diagnostic ? &out.error : nullptr, deadline);
                else out.accepted = [&] {
                    if (!raw.isStr() || !IsHex(raw.get_str())) return reject("getblock returned non-hex raw block data");
                    deadline();
                    try {
                        DataStream stream{ParseHex(raw.get_str())};
                        stream >> TX_WITH_WITNESS(out.value);
                        if (!stream.empty()) return reject("raw parent block has trailing bytes");
                    } catch (const std::exception& e) {
                        return reject(strprintf("cannot decode raw parent block: %s", e.what()));
                    }
                    deadline();
                    if (out.value.GetHash() != hash) return reject("raw parent block header does not match its requested hash");
                    return CheckDrivechainParentProofOfWork(hash, out.value.nBits, diagnostic ? &out.error : nullptr);
                }();
            } catch (const std::exception& e) { out.exception = e.what(); }
            return out;
        };
        const auto expected = run(false), actual = run(true);
        BOOST_CHECK_EQUAL(actual.accepted, expected.accepted);
        BOOST_CHECK_EQUAL(actual.deadlines, expected.deadlines);
        BOOST_CHECK_EQUAL(actual.error, expected.error);
        BOOST_CHECK_EQUAL(actual.exception, expected.exception);
        BOOST_CHECK(snapshot(actual.value) == snapshot(expected.value));
    }
}

BOOST_AUTO_TEST_CASE(parent_raw_headers_preserve_decode_errors_and_partial_mutation)
{
    const auto encode = [](const Bitcoin::CBlockHeader& header) {
        DataStream stream;
        stream << header;
        return stream.str();
    };
    Bitcoin::CBlockHeader genesis;
    genesis.nVersion = 1;
    genesis.hashMerkleRoot = uint256S("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
    genesis.nTime = 1296688602;
    genesis.nBits = 0x207fffff;
    genesis.nNonce = 2;
    const auto bytes = encode(genesis);
    const auto hex = HexStr(Span<const unsigned char>{reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size()});
    BOOST_REQUIRE_EQUAL(bytes.size(), 80U);
    BOOST_REQUIRE_EQUAL(genesis.GetHash().GetHex(), "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206");
    std::vector<std::pair<UniValue, uint256>> cases;
    for (size_t length = 0; length <= 80; ++length) cases.emplace_back(UniValue(hex.substr(0, 2 * length)), genesis.GetHash());
    for (const auto* text : {"null", "true", "123", "[]", "{}"}) {
        UniValue value;
        BOOST_REQUIRE(value.read(text));
        cases.emplace_back(value, genesis.GetHash());
    }
    for (const auto& text : {std::string("0"), std::string("gg"), hex + "00"}) cases.emplace_back(UniValue(text), genesis.GetHash());
    cases.emplace_back(UniValue(hex), uint256{});
    for (uint32_t bits : {0U, 0x01810000U, 0x23000001U, 0x03000001U}) {
        auto header = genesis;
        header.nBits = bits;
        const auto encoded = encode(header);
        cases.emplace_back(UniValue(HexStr(Span<const unsigned char>{reinterpret_cast<const unsigned char*>(encoded.data()), encoded.size()})), header.GetHash());
    }
    for (const auto& [raw, hash] : cases)
    for (bool diagnostics : {false, true}) {
        Bitcoin::CBlockHeader expected = genesis;
        expected.nVersion = 7;
        expected.nNonce = 123;
        expected.hashPrevBlock = uint256S("abcd");
        auto actual = expected;
        std::string expected_error{"unchanged"}, actual_error = expected_error;
        const auto reject = [&](const std::string& message) { if (diagnostics) expected_error = message; return false; };
        const bool accepted = [&] {
            if (!raw.isStr() || !IsHex(raw.get_str())) return reject("getblockheader returned non-hex raw header data");
            try {
                DataStream stream{ParseHex(raw.get_str())};
                stream >> expected;
                if (!stream.empty()) return reject("raw parent header has trailing bytes");
            } catch (const std::exception& e) {
                return reject(strprintf("cannot decode raw parent header: %s", e.what()));
            }
            if (expected.GetHash() != hash) return reject(strprintf("raw parent header hashes to %s, expected %s", expected.GetHash().GetHex(), hash.GetHex()));
            return CheckDrivechainParentProofOfWork(hash, expected.nBits, diagnostics ? &expected_error : nullptr);
        }();
        BOOST_CHECK_EQUAL(DecodeDrivechainRawParentHeader(raw, hash, actual, diagnostics ? &actual_error : nullptr), accepted);
        BOOST_CHECK_EQUAL(actual_error, expected_error);
        BOOST_CHECK(encode(actual) == encode(expected));
    }
}

BOOST_AUTO_TEST_CASE(parent_rpc_parsers_match_original_json_and_mutation_rules)
{
    std::vector<UniValue> values;
    for (const auto* json : {"null","false","true","[]","{}","0","-1","4294967295","4294967296",
        "1.0","1e0","9223372036854775807","9223372036854775808","-9223372036854775809"}) {
        UniValue value;
        BOOST_REQUIRE(value.read(json));
        values.push_back(value);
    }
    for (const auto& text : {std::string{}, std::string(64,'0'), std::string(64,'a'), std::string(64,'A'),
        std::string(63,'a'), std::string(65,'a'), std::string(64,'g'), std::string("0x") + std::string(62,'a'),
        std::string(" ") + std::string(63,'a'), std::string(63,'a') + " ", std::string(63,'a') + '\0'}) values.emplace_back(text);
    for (const auto& value : values) {
        auto expected_hash = uint256S("ff"), actual_hash = expected_hash;
        const bool expected = [&] {
            if (!value.isStr() || value.get_str().size() != 64 || !IsHex(value.get_str())) return false;
            expected_hash = uint256S(value.get_str());
            return value.get_str() == expected_hash.GetHex();
        }();
        BOOST_CHECK_EQUAL(ParseDrivechainCanonicalHash(value, actual_hash), expected);
        BOOST_CHECK(actual_hash == expected_hash);
        for (bool diagnostics : {false,true}) {
            uint32_t expected_height{77}, actual_height{77};
            std::string expected_error{"unchanged"}, actual_error = expected_error;
            const auto reject = [&](const char* text) { if (diagnostics) expected_error = text; return false; };
            const bool accepted = [&] {
                if (!value.isNum()) return reject("parent getblockcount returned a non-numeric height");
                try {
                    const auto parsed = value.getInt<int64_t>();
                    if (parsed < 0 || parsed > UINT32_MAX) return reject("parent tip height is outside the supported uint32 range");
                    expected_height = static_cast<uint32_t>(parsed);
                    return true;
                } catch (const std::exception&) {
                    return reject("parent getblockcount returned a noncanonical height");
                }
            }();
            BOOST_CHECK_EQUAL(ParseDrivechainParentHeight(value, actual_height, diagnostics ? &actual_error : nullptr), accepted);
            BOOST_CHECK_EQUAL(actual_height, expected_height);
            BOOST_CHECK_EQUAL(actual_error, expected_error);
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_header_mtp_matches_original_json_and_diagnostics)
{
    const uint256 expected_hash = uint256S("ab");
    const auto original = [&](const UniValue& header, uint64_t& output, std::string* error) {
        output = 0;
        const auto reject = [&](const char* message) { if (error) *error = message; return false; };
        if (!header.isObject()) return reject("getblockheader result is not an object");
        const auto& hash = header.get_obj()["hash"];
        if (!hash.isStr() || hash.get_str().size() != 64 || !IsHex(hash.get_str()))
            return reject("getblockheader result has no canonical 32-byte hash");
        if (hash.get_str() != expected_hash.GetHex() || uint256S(hash.get_str()) != expected_hash) {
            if (error) *error = strprintf("getblockheader returned hash %s, expected committed parent %s", hash.get_str(), expected_hash.GetHex());
            return false;
        }
        const auto& mtp = header.get_obj()["mediantime"];
        if (!mtp.isNum()) return reject("getblockheader result has no numeric mediantime");
        try {
            const int64_t parsed = mtp.getInt<int64_t>();
            if (parsed < 0 || static_cast<uint64_t>(parsed) > UINT32_MAX)
                return reject("getblockheader mediantime is outside the uint32 timestamp range");
            output = static_cast<uint64_t>(parsed);
        } catch (const std::exception&) { return reject("getblockheader mediantime is not a canonical integer"); }
        return true;
    };
    const auto check = [&](const UniValue& header) {
        for (bool diagnostics : {false,true}) {
            uint64_t actual{99}, expected{99};
            std::string actual_error{"unchanged"}, expected_error = actual_error;
            const bool valid = original(header, expected, diagnostics ? &expected_error : nullptr);
            BOOST_CHECK_EQUAL(ParseDrivechainParentHeader(header, expected_hash, actual, diagnostics ? &actual_error : nullptr), valid);
            BOOST_CHECK_EQUAL(actual, expected);
            BOOST_CHECK_EQUAL(actual_error, expected_error);
        }
    };
    std::vector<UniValue> values;
    for (const char* json : {"null","false","true","[]","{}","\"1\"","0","-1","4294967295","4294967296",
        "1.0","1e0","9223372036854775807","9223372036854775808","-9223372036854775809"}) {
        UniValue value;
        BOOST_REQUIRE(value.read(json));
        values.push_back(value);
        check(value);
    }
    std::vector<UniValue> hashes = values;
    for (const auto& text : {std::string{}, expected_hash.GetHex(), std::string(62,'0') + "AB",
        std::string(64,'0'), std::string(63,'a'), std::string(65,'a'), std::string(64,'g')}) hashes.emplace_back(text);
    for (const auto& hash : hashes) for (const auto& mtp : values) for (unsigned fields = 0; fields < 4; ++fields) {
        UniValue header{UniValue::VOBJ};
        if (fields & 1) header.pushKV("hash", hash);
        if (fields & 2) header.pushKV("mediantime", mtp);
        header.pushKV("time", 123); // A time field must not replace missing median time.
        check(header);
    }
}

BOOST_AUTO_TEST_CASE(shared_hex_field_matches_native_admission_without_mutation)
{
    std::vector<UniValue> values;
    for (const char* json : {"null", "false", "123", "[]", "{}", "\"\"", "\"00 ff\"", "\"0x00\"", "\"gg\""}) {
        UniValue value;
        BOOST_REQUIRE(value.read(json));
        values.push_back(value);
    }
    for (size_t length = 0; length <= 65; ++length) {
        values.emplace_back(std::string(length, 'a'));
        values.emplace_back(std::string(length, 'F'));
    }
    for (const auto& value : values) for (size_t bytes : {size_t{0}, size_t{1}, size_t{2}, size_t{32}}) {
        const auto before = value.write();
        const bool expected = value.isStr() && IsHex(value.get_str()) &&
            (bytes == 0 || value.get_str().size() == bytes * 2);
        BOOST_CHECK_EQUAL(drivechain::IsHexField(value, bytes), expected);
        BOOST_CHECK_EQUAL(value.write(), before);
    }
}

BOOST_AUTO_TEST_CASE(ecx_field_alias_reuse_preserves_strict_object_and_reference)
{
    std::vector<UniValue> values;
    for (const char* json : {"null", "false", "0", "\"text\"", "[]", "{}"}) {
        UniValue value;
        BOOST_REQUIRE(value.read(json));
        values.push_back(value);
    }
    const auto check = [&](const UniValue& value, const std::string& alias) {
        const auto before = value.write();
        const UniValue* expected{nullptr};
        const UniValue* actual{nullptr};
        std::string expected_error, actual_error;
        try {
            expected = &value.get_obj()["field"];
            if (expected->isNull()) expected = &value.get_obj()[alias];
        } catch (const std::exception& e) { expected_error = e.what(); }
        try { actual = &drivechain::FindField(value.get_obj(), "field", alias); }
        catch (const std::exception& e) { actual_error = e.what(); }
        BOOST_CHECK_EQUAL(actual_error, expected_error);
        BOOST_CHECK(actual == expected);
        BOOST_CHECK_EQUAL(value.write(), before);
    };
    for (const std::string alias : {"alias", "field"}) {
        for (const auto& value : values) check(value, alias);
        for (const auto& primary : values) for (const auto& fallback : values) {
            for (unsigned fields = 0; fields < 4; ++fields) {
                UniValue value(UniValue::VOBJ);
                if (fields & 1) value.pushKV("field", primary);
                if (fields & 2) value.pushKV(alias, fallback);
                check(value, alias);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(validator_request_objects_preserve_wire_json)
{
    UniValue empty;
    BOOST_REQUIRE(empty.read("{}"));
    BOOST_CHECK_EQUAL(UniValue(UniValue::VOBJ).write(), empty.write());
    for (int slot : {std::numeric_limits<int>::min(), -1, 0, 24, 130, 255, std::numeric_limits<int>::max()}) {
        UniValue previous_ctip, ctip(UniValue::VOBJ);
        BOOST_REQUIRE(previous_ctip.read(strprintf("{\"sidechainNumber\":%d}", slot)));
        ctip.pushKV("sidechainNumber", slot);
        BOOST_CHECK_EQUAL(ctip.write(), previous_ctip.write());
        for (const auto& hash : {uint256{}, uint256S(std::string(64, 'f')), uint256S(std::string(64, 'a'))}) {
            UniValue previous, request(UniValue::VOBJ), block_hash(UniValue::VOBJ);
            BOOST_REQUIRE(previous.read(strprintf("{\"sidechainId\":%d,\"endBlockHash\":{\"hex\":\"%s\"}}", slot, hash.GetHex())));
            request.pushKV("sidechainId", slot);
            block_hash.pushKV("hex", hash.GetHex());
            request.pushKV("endBlockHash", block_hash);
            BOOST_CHECK_EQUAL(request.write(), previous.write());
        }
    }
}

BOOST_AUTO_TEST_CASE(checked_rpc_reply_matches_original_error_priority)
{
    std::vector<UniValue> values;
    for (const auto* json : {"null", "false", "0", "\"text\"", "[]", "{}",
        "{\"code\":-1,\"message\":\"failure\"}", "[1,2]"}) {
        UniValue value;
        BOOST_REQUIRE(value.read(json));
        values.push_back(value);
    }
    const auto check = [&](const UniValue& reply) {
        const auto before = reply.write();
        for (const std::string& method : {std::string{}, std::string{"getblockhash"}, std::string{"mainchain getbestblockhash"}}) for (bool require_result : {false, true}) {
            UniValue expected, actual;
            std::string expected_error, actual_error;
            bool expected_threw{false}, actual_threw{false};
            try {
                const UniValue& error = reply["error"];
                if (!error.isNull()) throw std::runtime_error(strprintf("%s returned error: %s", method, error.write()));
                const UniValue& result = reply["result"];
                if (require_result && result.isNull()) throw std::runtime_error(strprintf("%s returned no result", method));
                expected = result;
            } catch (const std::exception& e) { expected_threw = true; expected_error = e.what(); }
            try { actual = CheckDrivechainRPCReply(method, reply, require_result); }
            catch (const std::exception& e) { actual_threw = true; actual_error = e.what(); }
            BOOST_CHECK_EQUAL(actual_threw, expected_threw);
            BOOST_CHECK_EQUAL(actual_error, expected_error);
            BOOST_CHECK_EQUAL(actual.write(), expected.write());
            BOOST_CHECK_EQUAL(reply.write(), before);
        }
    };
    for (const auto& error : values) for (const auto& result : values) {
        for (unsigned present = 0; present < 4; ++present) {
            UniValue reply{UniValue::VOBJ};
            if (present & 1) reply.pushKV("error", error);
            if (present & 2) reply.pushKV("result", result);
            check(reply);
        }
    }
    for (const auto& malformed : values) check(malformed);
}

BOOST_AUTO_TEST_CASE(parent_exact_address_matches_original_script_order)
{
    for (size_t size : {0U,1U,75U,76U,255U,256U}) {
        const std::vector<unsigned char> address(size, 0x42);
        for (unsigned encoding = 0; encoding < 4; ++encoding) {
            CScript script = CScript() << OP_RETURN;
            if (encoding == 0) script << address;
            else {
                const unsigned width = 1U << (encoding - 1);
                script.push_back(encoding == 1 ? OP_PUSHDATA1 : encoding == 2 ? OP_PUSHDATA2 : OP_PUSHDATA4);
                for (unsigned i = 0; i < width; ++i) script.push_back((size >> (8 * i)) & 255);
                script.insert(script.end(), address.begin(), address.end());
            }
            script << OP_0;
            for (size_t length = 0; length <= script.size(); ++length)
            for (bool matching : {false,true}) {
                auto candidate = address;
                if (!matching) candidate.push_back(0);
                const Bitcoin::CTxOut output(123, CScript(script.begin(), script.begin() + length));
                const bool expected = [&] {
                    auto pc = output.scriptPubKey.begin();
                    opcodetype opcode;
                    std::vector<unsigned char> pushed;
                    return output.scriptPubKey.GetOp(pc, opcode, pushed) && opcode == OP_RETURN &&
                        output.scriptPubKey.GetOp(pc, opcode, pushed) && opcode <= OP_PUSHDATA4 &&
                        pushed == candidate && pc == output.scriptPubKey.end();
                }();
                BOOST_CHECK_EQUAL(IsExactDrivechainOpReturnAddress(output, candidate), expected);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_message_extraction_preserves_script_envelopes)
{
    for (unsigned variant = 0; variant < 14; ++variant) {
        auto consensus = Params().GetConsensus();
        consensus.drivechain_slot = 24;
        consensus.drivechain_parent_state_active_proposal_hash = uint256S("aa");
        consensus.drivechain_parent_state_active_proposal_description = {1,2};
        consensus.drivechain_parent_state_proposal_height = 10;
        consensus.drivechain_parent_state_activation_height = 20;
        consensus.drivechain_parent_state_height = 30;
        DrivechainParentReplayState state;
        state.pending_proposals.emplace(uint256S("aa"), DrivechainPendingProposal{10,0});
        const auto payload = ParseHex("d5e0c4af180102");
        CScript script = CScript() << OP_RETURN << payload;
        bool valid = variant <= 3 || variant == 12;
        if (variant >= 1 && variant <= 3) {
            script = CScript() << OP_RETURN;
            script.push_back(variant == 1 ? OP_PUSHDATA1 : variant == 2 ? OP_PUSHDATA2 : OP_PUSHDATA4);
            script.push_back(payload.size());
            for (unsigned i = 1; i < (1U << (variant - 1)); ++i) script.push_back(0);
            script.insert(script.end(), payload.begin(), payload.end());
        }
        if (variant == 4) script << OP_0;
        if (variant == 5) script = CScript() << OP_RETURN;
        if (variant == 6) script = CScript() << OP_RETURN << OP_1;
        if (variant == 7) script = CScript() << payload;
        if (variant == 8) { script = CScript() << OP_RETURN << OP_PUSHDATA1; script.push_back(255); }
        if (variant == 9) script.clear();
        Bitcoin::CMutableTransaction coinbase;
        coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
        coinbase.vout.emplace_back(0, script);
        if (variant == 10) coinbase.vin[0].prevout = Bitcoin::COutPoint(uint256::ONE, 0);
        if (variant == 12) coinbase.vout.emplace_back(0, CScript() << OP_RETURN << std::vector<unsigned char>{0});
        if (variant == 13) coinbase.vout.push_back(coinbase.vout.front());
        Bitcoin::CBlock block;
        block.vtx.push_back(Bitcoin::MakeTransactionRef(coinbase));
        if (variant == 11) block.vtx[0].reset();
        consensus.drivechain_parent_state_proposal_block_hash = block.GetHash();
        std::string error;
        BOOST_CHECK_EQUAL(CheckDrivechainParentReplayMilestone(consensus, 10, block, state, &error), valid);
        BOOST_CHECK_EQUAL(CheckDrivechainParentReplayMilestone(consensus, 10, block, state, nullptr), valid);
        if (valid) BOOST_CHECK(error.empty());
        else if (variant == 10 || variant == 11) BOOST_CHECK_EQUAL(error, "pinned parent identity block has no coinbase transaction");
        else BOOST_CHECK_EQUAL(error, strprintf("pinned parent identity block contains %u copies of its expected drivechain message", variant == 13 ? 2U : 0U));
    }
}

BOOST_AUTO_TEST_CASE(parent_milestones_validate_real_messages_and_checkpoint_state)
{
    for (unsigned mode = 0; mode < 4; ++mode)
    for (unsigned variant = 0; variant < (mode < 2 ? 9U : 7U); ++variant) {
        auto consensus = Params().GetConsensus();
        consensus.drivechain_slot = 24;
        consensus.drivechain_parent_state_active_proposal_hash = uint256S("aa");
        consensus.drivechain_parent_state_active_proposal_description = mode == 3 ? std::vector<unsigned char>{} : std::vector<unsigned char>{1,2};
        consensus.drivechain_parent_state_proposal_height = 10;
        consensus.drivechain_parent_state_activation_height = 20;
        consensus.drivechain_parent_state_height = 30;
        consensus.drivechain_parent_state_ctip_txid = mode == 3 ? uint256{} : uint256S("bb");
        consensus.drivechain_parent_state_ctip_vout = 3;
        consensus.drivechain_parent_state_ctip_value = 42;
        const uint32_t height = mode == 0 ? 10 : mode == 1 ? 20 : 30;
        DrivechainParentReplayState state;
        if (mode == 0) state.pending_proposals.emplace(uint256S("aa"), DrivechainPendingProposal{10,0});
        if (mode == 1 || mode == 2) state.active_proposal_hash = uint256S("aa");
        if (mode == 2) { state.ctip = Bitcoin::COutPoint(uint256S("bb"), 3); state.ctip_value = 42; }
        Bitcoin::CMutableTransaction coinbase;
        coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
        auto payload = ParseHex(mode == 0 ? "d5e0c4af" : "d6e1c5df");
        payload.push_back(24);
        if (mode == 0) payload.insert(payload.end(), {1,2});
        else payload.insert(payload.end(), consensus.drivechain_parent_state_active_proposal_hash->begin(), consensus.drivechain_parent_state_active_proposal_hash->end());
        if (mode < 2 && variant == 5) payload[4] = 25;
        coinbase.vout.emplace_back(0, CScript() << OP_RETURN << payload);
        if (mode < 2 && variant == 3) coinbase.vout.clear();
        if (mode < 2 && variant == 4) coinbase.vout.push_back(coinbase.vout.front());
        Bitcoin::CBlock block;
        block.vtx.push_back(Bitcoin::MakeTransactionRef(coinbase));
        if (mode < 2 && variant == 2) block.vtx.clear();
        consensus.drivechain_parent_state_proposal_block_hash = block.GetHash();
        consensus.drivechain_parent_state_activation_block_hash = block.GetHash();
        consensus.drivechain_parent_state_hash = block.GetHash();
        std::string diagnostic;
        if (variant == 1) {
            consensus.drivechain_parent_state_proposal_block_hash = uint256S("cc");
            consensus.drivechain_parent_state_activation_block_hash = uint256S("cc");
            consensus.drivechain_parent_state_hash = uint256S("cc");
            diagnostic = "hashes to";
        } else if (mode < 2) {
            if (variant == 2) diagnostic = "no coinbase";
            if (variant >= 3 && variant <= 5) diagnostic = "copies of its expected";
            if (variant >= 6) {
                diagnostic = mode == 0 ? "pending proposal state" : "active proposal state";
                if (mode == 0) {
                    if (variant == 6) state.pending_proposals.clear();
                    if (variant == 7) state.pending_proposals.begin()->second.proposal_height = 11;
                    if (variant == 8) state.pending_proposals.begin()->second.votes = 1;
                } else {
                    if (variant == 7) state.pending_proposals.emplace(uint256S("aa"), DrivechainPendingProposal{10,0});
                    else state.active_proposal_hash.SetNull();
                }
            }
        } else if (variant >= 2) {
            diagnostic = "asserted active proposal and CTIP";
            if (variant == 2) state.active_proposal_hash = uint256S("dd");
            if (mode == 2) {
                if (variant == 3) state.ctip.reset();
                if (variant == 4) state.ctip->hash = uint256S("ee");
                if (variant == 5) state.ctip->n = 4;
                if (variant == 6) state.ctip_value = 41;
            } else {
                if (variant == 3) state.ctip = Bitcoin::COutPoint(uint256S("bb"), 3);
                if (variant >= 4) state.ctip_value = 1;
            }
        }
        std::string error;
        BOOST_CHECK_EQUAL(CheckDrivechainParentReplayMilestone(consensus, height, block, state, &error), variant == 0);
        BOOST_CHECK_EQUAL(CheckDrivechainParentReplayMilestone(consensus, height, block, state, nullptr), variant == 0);
        if (variant == 0) BOOST_CHECK(error.empty());
        else BOOST_CHECK(error.find(diagnostic) != std::string::npos);
        BOOST_CHECK(CheckDrivechainParentReplayMilestone(consensus, 31, block, state, nullptr));
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_bootstrap_preimage_matches_original_serialization)
{
    const std::vector<ElementsDrivechainBootstrap::Slot> fixtures{
        {0, "01", "00", 0, 0}, {24, "02", "03", UINT32_MAX, MAX_MONEY},
        {255, "00", "00", UINT32_MAX, -1}};
    for (uint32_t height : {0U, 1U, UINT32_MAX}) {
        for (size_t count = 0; count <= fixtures.size(); ++count) {
            auto consensus = Params().GetConsensus();
            consensus.drivechain_parent_state_height = height;
            consensus.drivechain_parent_state_hash = uint256S("a1");
            consensus.drivechain_parent_state_chainwork = uint256S("b2");
            const std::span<const ElementsDrivechainBootstrap::Slot> slots(fixtures.data(), count);
            HashWriter original, migrated;
            original << std::string{"ELEMENTS_BETANET_PARENT_REPLAY_BOOTSTRAP_V1"}
                     << consensus.drivechain_parent_state_height
                     << consensus.drivechain_parent_state_hash
                     << consensus.drivechain_parent_state_chainwork
                     << static_cast<uint32_t>(slots.size());
            for (const auto& slot : slots) {
                const auto ctip = uint256S(slot.ctip_txid);
                const bool has_ctip = !ctip.IsNull();
                original << slot.slot << uint256S(slot.active) << has_ctip;
                if (has_ctip) original << ctip << slot.ctip_vout << slot.ctip_value;
            }
            WriteDrivechainBootstrapPreimage(migrated, consensus, slots);
            BOOST_CHECK(original.GetHash() == migrated.GetHash());
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_identity_matches_original_field_serialization)
{
    for (unsigned variant = 0; variant < 34; ++variant) {
        auto consensus = Params().GetConsensus();
        consensus.drivechain_slot = 24;
        consensus.drivechain_proposal_hash = uint256S("11");
        switch (variant) {
        case 0: break;
        case 1: consensus.parentChainPowLimit = uint256S("12"); break;
        case 2: consensus.parent_signet_challenge = {1, 2, 3}; break;
        case 3: ++consensus.pegin_min_depth; break;
        case 4: consensus.drivechain_slot = 255; break;
        case 5: consensus.drivechain_protocol_manifest_hash = uint256S("13"); break;
        case 6: consensus.drivechain_proposal_description = {0, 1}; break;
        case 7: consensus.drivechain_proposal_hash = uint256S("14"); break;
        case 8: consensus.drivechain_parent_state_active_proposal_description = {2, 3}; break;
        case 9: consensus.drivechain_parent_state_active_proposal_hash = uint256S("15"); break;
        case 10: consensus.drivechain_parent_state_active_proposal_hash.reset(); break;
        case 11: ++consensus.drivechain_parent_state_proposal_height; break;
        case 12: consensus.drivechain_parent_state_proposal_block_hash = uint256S("16"); break;
        case 13: ++consensus.drivechain_parent_state_activation_height; break;
        case 14: consensus.drivechain_parent_state_activation_block_hash = uint256S("17"); break;
        case 15: ++consensus.drivechain_parent_state_height; break;
        case 16: consensus.drivechain_parent_state_hash = uint256S("18"); break;
        case 17: consensus.drivechain_parent_state_chainwork = uint256S("19"); break;
        case 18: consensus.drivechain_parent_state_ctip_txid = uint256S("1a"); break;
        case 19: ++consensus.drivechain_parent_state_ctip_vout; break;
        case 20: ++consensus.drivechain_parent_state_ctip_value; break;
        case 21: ++consensus.drivechain_unused_slot_proposal_max_age; break;
        case 22: ++consensus.drivechain_unused_slot_activation_threshold; break;
        case 23: ++consensus.drivechain_used_slot_proposal_max_age; break;
        case 24: ++consensus.drivechain_used_slot_activation_threshold; break;
        case 25: ++consensus.drivechain_withdrawal_bundle_max_age; break;
        case 26: ++consensus.drivechain_withdrawal_bundle_inclusion_threshold; break;
        case 27: consensus.drivechain_m6_withdrawal_validation = !consensus.drivechain_m6_withdrawal_validation; break;
        case 28: ++consensus.drivechain_parent_state_replay_version; break;
        case 29: consensus.drivechain_parent_state_height = UINT32_MAX; break;
        case 30: consensus.drivechain_parent_state_ctip_value = MAX_MONEY; break;
        case 31: consensus.drivechain_parent_state_ctip_value = -1; break;
        case 32: consensus.drivechain_parent_state_active_proposal_hash = uint256{}; break;
        case 33: consensus.drivechain_slot = 0; break;
        }
        BOOST_CHECK(DrivechainParentReplayStoreIdentity(consensus) == OriginalReplayStoreIdentity(consensus));
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_append_rejects_height_wrap_without_losing_tip)
{
    const auto path = m_args.GetDataDirBase() / "parent_replay_height_boundary";
    const auto identity = uint256S("01");
    DrivechainParentReplayTip previous;
    previous.height = UINT32_MAX - 1;
    previous.hash = uint256S("02");
    auto next = previous;
    next.height = UINT32_MAX;
    next.hash = uint256S("03");
    std::string error;
    {
        DrivechainParentReplayStore store(path, 1 << 20, true);
        BOOST_REQUIRE(store.Reset(identity, previous, &error));
        BOOST_REQUIRE(store.Append(previous, next, {}, std::nullopt, &error));
        auto wrapped = next;
        wrapped.height = 0;
        wrapped.hash = uint256S("04");
        BOOST_CHECK(!store.Append(next, wrapped, {}, std::nullopt, &error));
        BOOST_CHECK(!store.Append(next, next, {}, std::nullopt, &error));
    }
    DrivechainParentReplayStore reopened(path, 1 << 20, false);
    DrivechainParentReplayTip loaded;
    BOOST_REQUIRE(reopened.Load(identity, loaded, &error) == DrivechainReplayStoreLoadStatus::LOADED);
    BOOST_CHECK_EQUAL(loaded.height, UINT32_MAX);
    BOOST_CHECK(loaded.hash == next.hash);
}

BOOST_AUTO_TEST_CASE(parent_replay_public_reads_validate_persisted_records)
{
    const auto path = m_args.GetDataDirBase() / "parent_replay_read_shapes";
    const auto id = uint256S("01"), hash = uint256S("02");
    const Bitcoin::COutPoint outpoint(id, 0);
    for (unsigned family = 0; family < 4; ++family)
    for (unsigned variant = 0; variant < 6; ++variant) {
        std::string error;
        DrivechainMintableDeposit deposit{outpoint, hash, 1, 1000, {0x51}};
        DrivechainReplayedBmmEdge edge{hash, 0, 1, true, id};
        DrivechainSuccessfulWithdrawal withdrawal{24, id, 1, hash};
        bool corrupt = variant != 0;
        if (family == 0) {
            if (variant == 2) deposit.value = -1;
            if (variant == 3) deposit.block_hash.SetNull();
            if (variant == 4) deposit.outpoint.n = 1;
            if (variant == 5) deposit.address.clear();
        } else if (family == 1) {
            if (variant == 2) edge.successor_hash.SetNull();
            if (variant == 3) edge.successor_height = edge.parent_height;
            if (variant == 4) edge.committed_sidechain_hash.SetNull();
            // A noncanonical edge may retain an unused commitment hash.
            if (variant == 5) { edge.has_canonical_commitment = false; corrupt = false; }
        } else {
            if (variant == 2) withdrawal.block_hash.SetNull();
            if (variant == 3) withdrawal.sidechain_slot = 25;
            if (variant == 4) withdrawal.m6id = hash;
            if (variant == 5) { withdrawal.block_height = 2; corrupt = family == 3; }
        }
        {
            DrivechainParentReplayStore store(path, 1 << 20, true, DrivechainWithdrawalHistoryRule::ALLOW_REPROPOSAL);
            DrivechainParentReplayTip seed;
            seed.hash = hash;
            BOOST_REQUIRE(store.Reset(id, seed, &error));
        }
        {
            CDBWrapper raw({.path = path, .cache_bytes = 1 << 20});
            const auto write = [&](const auto& key, const auto& value) {
                return variant == 1 ? raw.Write(key, std::string{"malformed"}, true) : raw.Write(key, value, true);
            };
            if (family == 0) BOOST_REQUIRE(write(std::make_pair(drivechain::DB_REPLAY_DEPOSIT, outpoint), deposit));
            if (family == 1) BOOST_REQUIRE(write(std::make_pair(drivechain::DB_REPLAY_BMM_EDGE, id), edge));
            if (family == 2) BOOST_REQUIRE(write(std::make_pair(drivechain::DB_REPLAY_SUCCESSFUL_WITHDRAWAL, std::make_pair(uint8_t{24}, id)), withdrawal));
            if (family == 3) BOOST_REQUIRE(write(std::make_pair(drivechain::DB_REPLAY_WITHDRAWAL_OCCURRENCE,
                std::make_pair(std::make_pair(uint8_t{24}, id), uint32_t{1})), withdrawal));
        }
        DrivechainParentReplayStore store(path, 1 << 20, false, DrivechainWithdrawalHistoryRule::ALLOW_REPROPOSAL);
        for (bool diagnostic : {true, false}) {
            error.clear();
            auto* err = diagnostic ? &error : nullptr;
            auto status = DrivechainReplayStoreReadStatus::NOT_FOUND;
            if (family == 0) status = store.ReadDeposit(outpoint, deposit, err);
            if (family == 1) status = store.ReadBmmEdge(id, edge, err);
            if (family == 2) status = store.ReadSuccessfulWithdrawal(24, id, withdrawal, err);
            if (family == 3) status = store.ReadSuccessfulWithdrawalAtHeight(24, id, 1, withdrawal, err);
            BOOST_CHECK(status == (corrupt ? DrivechainReplayStoreReadStatus::CORRUPT : DrivechainReplayStoreReadStatus::FOUND));
            if (diagnostic && corrupt) BOOST_CHECK(error.find(variant == 1 ? "malformed" : "internally inconsistent") != std::string::npos);
        }
    }
}

BOOST_AUTO_TEST_CASE(explicit_bmm_snapshot_narrows_warmer_tip_for_deposits)
{
    // A cached BMM hit for Q=100 must replace a prior non-explicit warmer-tip
    // snapshot at 200. Otherwise a deposit at 150 (after Q) could be accepted
    // on the cache-hit path while the cold path correctly rejects it.
    BOOST_CHECK(ShouldReplaceDrivechainReplaySnapshot(
        /*current_authenticated=*/true, /*current_height=*/200,
        /*current_explicit_target=*/false,
        /*next_explicit_target=*/true, /*next_height=*/100));
    BOOST_CHECK(!ShouldReplaceDrivechainReplaySnapshot(
        /*current_authenticated=*/true, /*current_height=*/200,
        /*current_explicit_target=*/false,
        /*next_explicit_target=*/false, /*next_height=*/100));
    BOOST_CHECK(!ShouldReplaceDrivechainReplaySnapshot(
        /*current_authenticated=*/true, /*current_height=*/100,
        /*current_explicit_target=*/true,
        /*next_explicit_target=*/false, /*next_height=*/200));

}

BOOST_AUTO_TEST_CASE(persistent_parent_replay_store_restart_identity_and_corruption)
{
    const fs::path path = m_args.GetDataDirBase() / "parent_replay_store";
    const uint256 identity = uint256S("01");
    const uint256 wrong_identity = uint256S("02");
    const uint256 genesis_hash = uint256S("03");
    const uint256 block_hash = uint256S("04");
    const uint256 deposit_txid = uint256S("05");
    const uint256 committed_child = uint256S("06");
    const uint256 pending_proposal = uint256S("07");
    const uint256 ctip_txid = uint256S("08");
    const uint256 active_proposal = uint256S("09");
    const uint256 pending_m6id = uint256S("0a");
    const uint256 other_active_proposal = uint256S("0b");
    const uint256 other_pending_proposal = uint256S("0c");
    const uint256 other_pending_m6id = uint256S("0d");
    const uint256 other_ctip_txid = uint256S("0e");
    const uint256 second_block_hash = uint256S("0f");
    const uint256 successful_m6id = uint256S("10");

    DrivechainParentReplayTip genesis;
    genesis.hash = genesis_hash;
    DrivechainParentReplayTip next = genesis;
    next.height = 1;
    next.hash = block_hash;
    next.state.active_proposal_hash = active_proposal;
    next.state.pending_proposals.emplace(
        pending_proposal, DrivechainPendingProposal{0, 1});
    next.state.pending_withdrawals.push_back(
        DrivechainPendingWithdrawal{pending_m6id, 1, 2});
    next.state.ctip = Bitcoin::COutPoint{ctip_txid, 1};
    next.state.ctip_value = 0;
    DrivechainOtherSlotReplayState other_slot;
    other_slot.active_proposal_hash = other_active_proposal;
    other_slot.pending_proposals.emplace(
        other_pending_proposal, DrivechainPendingProposal{0, 1});
    other_slot.pending_withdrawals.push_back(
        DrivechainPendingWithdrawal{other_pending_m6id, 1, 2});
    other_slot.ctip = Bitcoin::COutPoint{other_ctip_txid, 2};
    other_slot.ctip_value = 0;
    next.state.other_slots.emplace(25, std::move(other_slot));
    next.state.previous_m4_actions.emplace(
        24, DrivechainM4Action{DrivechainM4ActionType::UPVOTE, pending_m6id});
    next.state.previous_m4_actions.emplace(
        25, DrivechainM4Action{DrivechainM4ActionType::ALARM, uint256{}});

    DrivechainMintableDeposit deposit{
        Bitcoin::COutPoint{deposit_txid, 0}, block_hash, 1, 1000,
        std::vector<unsigned char>{0x51}};
    DrivechainReplayedBmmEdge edge{
        block_hash, 0, 1, true, committed_child};
    DrivechainSuccessfulWithdrawal successful_withdrawal{
        24, successful_m6id, 1, block_hash};
    std::string error;

    {
        DrivechainParentReplayStore store(path, 1 << 20, /*wipe=*/true);
        BOOST_REQUIRE(store.Reset(identity, genesis, &error));
        for (unsigned variant = 0; variant < 10; ++variant) {
            auto bad_tip = next;
            auto bad_deposit = deposit;
            auto bad_edge = edge;
            auto bad_withdrawal = successful_withdrawal;
            switch (variant) {
            case 0: bad_tip.height = 2; break;
            case 1: bad_tip.hash.SetNull(); break;
            case 2: bad_deposit.block_hash = genesis_hash; break;
            case 3: bad_deposit.block_height = 0; break;
            case 4: bad_deposit.value = 0; break;
            case 5: bad_deposit.address.clear(); break;
            case 6: bad_edge.successor_hash = genesis_hash; break;
            case 7: bad_edge.successor_height = 2; break;
            case 8: bad_withdrawal.block_hash = genesis_hash; break;
            case 9: bad_withdrawal.block_height = 0; break;
            }
            BOOST_CHECK(!store.Append(genesis, bad_tip, {bad_deposit},
                std::make_optional(std::make_pair(genesis_hash, bad_edge)), {bad_withdrawal}, &error));
            DrivechainParentReplayTip loaded;
            BOOST_REQUIRE(store.Load(identity, loaded, &error) == DrivechainReplayStoreLoadStatus::LOADED);
            BOOST_CHECK(loaded.hash == genesis.hash);
            DrivechainMintableDeposit missing;
            BOOST_CHECK(store.ReadDeposit(deposit.outpoint, missing, &error) == DrivechainReplayStoreReadStatus::NOT_FOUND);
            DrivechainSuccessfulWithdrawal missing_withdrawal;
            BOOST_CHECK(store.ReadSuccessfulWithdrawal(24, successful_m6id, missing_withdrawal, &error) == DrivechainReplayStoreReadStatus::NOT_FOUND);
        }
        BOOST_REQUIRE(store.Append(
            genesis, next, {deposit},
            std::make_optional(std::make_pair(genesis_hash, edge)),
            {successful_withdrawal}, &error));
        BOOST_CHECK(!store.Append(
            genesis, next, {deposit},
            std::make_optional(std::make_pair(genesis_hash, edge)),
            {successful_withdrawal}, &error));

        // The legacy history rule rejects a previously paid M6. Betanet's
        // separate schema permits authenticated later proposal cycles.
        DrivechainParentReplayTip replay = next;
        replay.height = 2;
        replay.hash = second_block_hash;
        DrivechainSuccessfulWithdrawal duplicate_success{
            24, successful_m6id, 2, second_block_hash};
        BOOST_CHECK(!store.Append(
            next, replay, {}, std::nullopt, {duplicate_success}, &error));
        BOOST_CHECK(!store.Append(
            next, replay, {}, std::nullopt, {},
            {DrivechainWithdrawalProposalIdentity{24, successful_m6id}},
            &error));
        BOOST_CHECK(error.find("already succeeded") != std::string::npos);

        // Height/hash equality is insufficient: appends must also bind the
        // caller's complete previous replay state to the durable tip.
        DrivechainParentReplayTip altered_previous = next;
        altered_previous.state.ctip_value = 1;
        DrivechainParentReplayTip second = altered_previous;
        second.height = 2;
        second.hash = second_block_hash;
        BOOST_CHECK(!store.Append(altered_previous, second, {}, std::nullopt, &error));
    }

    {
        DrivechainParentReplayStore store(path, 1 << 20, /*wipe=*/false);
        DrivechainParentReplayTip loaded;
        BOOST_REQUIRE(store.Load(identity, loaded, &error) ==
                      DrivechainReplayStoreLoadStatus::LOADED);
        BOOST_CHECK_EQUAL(loaded.height, 1U);
        auto invalid_seed = loaded;
        invalid_seed.hash.SetNull();
        BOOST_CHECK(!store.Reset(identity, invalid_seed, &error));
        BOOST_CHECK_EQUAL(error, "refusing to seed persistent parent replay with an invalid tip");
        BOOST_REQUIRE(store.Load(identity, loaded, &error) == DrivechainReplayStoreLoadStatus::LOADED);
        BOOST_CHECK_EQUAL(loaded.height, 1U);
        BOOST_CHECK(loaded.hash == block_hash);
        BOOST_REQUIRE(loaded.state.ctip.has_value());
        BOOST_CHECK(loaded.state.ctip->hash == ctip_txid);
        BOOST_CHECK_EQUAL(loaded.state.ctip_value, 0);
        const auto pending = loaded.state.pending_proposals.find(pending_proposal);
        BOOST_REQUIRE(pending != loaded.state.pending_proposals.end());
        BOOST_CHECK_EQUAL(pending->second.proposal_height, 0U);
        BOOST_CHECK_EQUAL(pending->second.votes, 1U);
        BOOST_REQUIRE_EQUAL(loaded.state.pending_withdrawals.size(), 1U);
        BOOST_CHECK(loaded.state.pending_withdrawals[0].m6id == pending_m6id);
        BOOST_CHECK_EQUAL(loaded.state.pending_withdrawals[0].votes, 2U);
        const auto loaded_other = loaded.state.other_slots.find(25);
        BOOST_REQUIRE(loaded_other != loaded.state.other_slots.end());
        BOOST_CHECK(loaded_other->second.active_proposal_hash == other_active_proposal);
        const auto loaded_other_proposal =
            loaded_other->second.pending_proposals.find(other_pending_proposal);
        BOOST_REQUIRE(loaded_other_proposal !=
                      loaded_other->second.pending_proposals.end());
        BOOST_CHECK_EQUAL(loaded_other_proposal->second.votes, 1U);
        BOOST_REQUIRE(loaded_other->second.ctip.has_value());
        BOOST_CHECK(loaded_other->second.ctip->hash == other_ctip_txid);
        BOOST_CHECK_EQUAL(loaded_other->second.ctip_value, 0);
        BOOST_REQUIRE_EQUAL(loaded_other->second.pending_withdrawals.size(), 1U);
        BOOST_CHECK(loaded_other->second.pending_withdrawals[0].m6id == other_pending_m6id);
        BOOST_REQUIRE_EQUAL(loaded.state.previous_m4_actions.size(), 2U);
        BOOST_CHECK(loaded.state.previous_m4_actions.at(24).type ==
                    DrivechainM4ActionType::UPVOTE);
        BOOST_CHECK(loaded.state.previous_m4_actions.at(24).m6id == pending_m6id);
        BOOST_CHECK(loaded.state.previous_m4_actions.at(25).type ==
                    DrivechainM4ActionType::ALARM);
        BOOST_CHECK(loaded.state.previous_m4_actions.at(25).m6id.IsNull());
        BOOST_CHECK(store.Load(wrong_identity, loaded, &error) ==
                    DrivechainReplayStoreLoadStatus::IDENTITY_MISMATCH);

        DrivechainMintableDeposit loaded_deposit;
        BOOST_REQUIRE(store.ReadDeposit(deposit.outpoint, loaded_deposit, &error) ==
                      DrivechainReplayStoreReadStatus::FOUND);
        BOOST_CHECK(loaded_deposit.block_hash == block_hash);
        BOOST_CHECK_EQUAL(loaded_deposit.value, deposit.value);

        DrivechainReplayedBmmEdge loaded_edge;
        BOOST_REQUIRE(store.ReadBmmEdge(genesis_hash, loaded_edge, &error) ==
                      DrivechainReplayStoreReadStatus::FOUND);
        BOOST_CHECK(loaded_edge.successor_hash == block_hash);
        BOOST_CHECK(loaded_edge.committed_sidechain_hash == committed_child);

        DrivechainSuccessfulWithdrawal loaded_withdrawal;
        BOOST_REQUIRE(store.ReadSuccessfulWithdrawal(
                          24, successful_m6id, loaded_withdrawal, &error) ==
                      DrivechainReplayStoreReadStatus::FOUND);
        BOOST_CHECK_EQUAL(loaded_withdrawal.sidechain_slot, 24U);
        BOOST_CHECK(loaded_withdrawal.m6id == successful_m6id);
        BOOST_CHECK_EQUAL(loaded_withdrawal.block_height, 1U);
        BOOST_CHECK(loaded_withdrawal.block_hash == block_hash);
    }

    // A malformed durable tip is never interpreted as an empty or usable
    // index. The caller can safely rebuild this derived database from genesis.
    {
        CDBWrapper raw({.path = path, .cache_bytes = 1 << 20});
        BOOST_REQUIRE(raw.Write(uint8_t{'T'}, std::string{"malformed"}, true));
    }
    {
        DrivechainParentReplayStore store(path, 1 << 20, /*wipe=*/false);
        DrivechainParentReplayTip loaded;
        BOOST_CHECK(store.Load(identity, loaded, &error) ==
                    DrivechainReplayStoreLoadStatus::CORRUPT);
        BOOST_REQUIRE(store.Reset(identity, genesis, &error));
        BOOST_REQUIRE(store.Load(identity, loaded, &error) ==
                      DrivechainReplayStoreLoadStatus::LOADED);
        DrivechainMintableDeposit removed;
        BOOST_CHECK(store.ReadDeposit(deposit.outpoint, removed, &error) ==
                    DrivechainReplayStoreReadStatus::NOT_FOUND);
        DrivechainSuccessfulWithdrawal removed_withdrawal;
        BOOST_CHECK(store.ReadSuccessfulWithdrawal(
                        24, successful_m6id, removed_withdrawal, &error) ==
                    DrivechainReplayStoreReadStatus::NOT_FOUND);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_m5_address_output_value_is_not_part_of_deposit_amount)
{
    constexpr int sidechain_slot{24};
    constexpr CAmount old_treasury_value{50000};
    constexpr CAmount deposit_value{100000};
    constexpr CAmount address_output_burn{7000};
    const CScript treasury_script = CScript()
        << static_cast<opcodetype>(drivechain::FROZEN_PARENT_RULES.treasury_opcode)
        << std::vector<unsigned char>{sidechain_slot} << OP_TRUE;
    const std::vector<unsigned char> address{'e', 'l', 'e', 'm', 'e', 'n', 't', 's', '-', 'r', 'e', 'c', 'i', 'p', 'i', 'e', 'n', 't'};

    Bitcoin::CMutableTransaction previous;
    previous.vin.emplace_back(Bitcoin::COutPoint(uint256::ONE, 1));
    previous.vout.emplace_back(old_treasury_value, treasury_script);
    const Bitcoin::COutPoint previous_treasury(previous.GetHash(), 0);

    Bitcoin::CMutableTransaction deposit;
    deposit.vin.emplace_back(previous_treasury);
    deposit.vout.emplace_back(old_treasury_value + deposit_value, treasury_script);
    // BIP300 derives the deposit amount only from the treasury delta.  The
    // immediately following address output's nValue is ignored, even when it
    // provably burns additional BTC.
    deposit.vout.emplace_back(address_output_burn, CScript() << OP_RETURN << address);
    const Bitcoin::CTransactionRef deposit_ref = Bitcoin::MakeTransactionRef(std::move(deposit));

    Bitcoin::CMutableTransaction coinbase;
    coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
    Bitcoin::CBlock block;
    block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(coinbase)));
    block.vtx.push_back(deposit_ref);

    const COutPoint claimed_outpoint(Txid::FromUint256(deposit_ref->GetHash()), 0);
    const std::map<Bitcoin::COutPoint, Bitcoin::CTxOut> previous_outputs{
        {previous_treasury, previous.vout[0]},
    };
    std::string err;
    BOOST_CHECK(MatchDrivechainDepositInBlock(block, sidechain_slot, claimed_outpoint,
                                              deposit_value, address, previous_outputs, &err));
    BOOST_CHECK(!MatchDrivechainDepositInBlock(block, sidechain_slot, claimed_outpoint,
                                               deposit_value + address_output_burn, address,
                                               previous_outputs, &err));

    auto duplicate_block = block;
    duplicate_block.vtx.push_back(deposit_ref);
    // A second match must reject before inspecting any later transaction.
    duplicate_block.vtx.emplace_back();
    BOOST_CHECK(!MatchDrivechainDepositInBlock(duplicate_block, sidechain_slot, claimed_outpoint,
                                               deposit_value, address, previous_outputs, &err));
    BOOST_CHECK_EQUAL(err,"raw parent block contains duplicate deposit txids");
    auto missing_block = block;
    missing_block.vtx.resize(1);
    BOOST_CHECK(!MatchDrivechainDepositInBlock(missing_block, sidechain_slot, claimed_outpoint,
                                               deposit_value, address, previous_outputs, &err));
    BOOST_CHECK_EQUAL(err,"deposit outpoint is absent from raw parent block");

    Bitcoin::CMutableTransaction fabricated_coinbase;
    fabricated_coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
    fabricated_coinbase.vout.emplace_back(deposit_value, treasury_script);
    fabricated_coinbase.vout.emplace_back(address_output_burn, CScript() << OP_RETURN << address);
    const Bitcoin::CTransactionRef fabricated_ref =
        Bitcoin::MakeTransactionRef(std::move(fabricated_coinbase));
    Bitcoin::CBlock fabricated_block;
    fabricated_block.vtx.push_back(fabricated_ref);
    const COutPoint fabricated_outpoint(Txid::FromUint256(fabricated_ref->GetHash()), 0);
    BOOST_CHECK(!MatchDrivechainDepositInBlock(
        fabricated_block, sidechain_slot, fabricated_outpoint, deposit_value,
        address, {}, &err));
}

BOOST_AUTO_TEST_CASE(drivechain_deposit_address_and_previous_treasury_gates)
{
    const CScript treasury = CScript()
        << static_cast<opcodetype>(drivechain::FROZEN_PARENT_RULES.treasury_opcode)
        << std::vector<unsigned char>{24} << OP_TRUE;
    const std::vector<unsigned char> address{'a'};
    const Bitcoin::COutPoint prior(uint256::ONE,0);
    for (int following=0; following<3; ++following) for (int source=0; source<4; ++source) {
        Bitcoin::CMutableTransaction tx;
        tx.vin.emplace_back(prior);
        if (source==3) tx.vin.emplace_back(Bitcoin::COutPoint(uint256::ONE,1));
        tx.vout.emplace_back(150,treasury);
        if (following!=0) tx.vout.emplace_back(0,CScript() << OP_RETURN <<
            (following==1 ? std::vector<unsigned char>{'b'} : address));
        Bitcoin::CBlock block;
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(tx)));
        std::map<Bitcoin::COutPoint,Bitcoin::CTxOut> previous;
        if (source!=0) previous.emplace(prior,Bitcoin::CTxOut(50,source==1 ? CScript() << OP_TRUE : treasury));
        if (source==3) previous.emplace(Bitcoin::COutPoint(uint256::ONE,1),Bitcoin::CTxOut(50,treasury));
        std::string error;
        const bool accepted = MatchDrivechainDepositInBlock(block,24,
            COutPoint(Txid::FromUint256(block.vtx[0]->GetHash()),0),100,address,previous,&error);
        BOOST_CHECK_EQUAL(accepted,following==2 && source==2);
        if (following!=2) BOOST_CHECK_EQUAL(error,"BIP300 deposit does not contain the exact following address commitment");
        else if (source==3) BOOST_CHECK_EQUAL(error,"BIP300 deposit spends multiple treasury outputs for one slot");
        else if (source!=2) BOOST_CHECK_EQUAL(error,"BIP300 treasury value delta does not equal the claimed deposit amount");
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_m4_mode_guards_and_sorted_slots)
{
    const uint256 required = uint256S("11"), bundle = uint256S("01");
    for (unsigned flags = 0; flags < 4; ++flags) for (unsigned length = 0; length <= 4; ++length)
    for (bool two_byte : {false, true}) {
        DrivechainParentReplayState state;
        state.active_proposal_hash = required;
        state.pending_withdrawals.push_back({bundle, 1, 1});
        std::vector<uint8_t> slots;
        if (flags & 1) slots.push_back(5);
        slots.push_back(24);
        if (flags & 2) slots.push_back(25);
        for (auto slot : slots) if (slot != 24) {
            state.other_slots[slot].active_proposal_hash = required;
            state.other_slots[slot].pending_withdrawals.push_back({bundle, 1, 1});
        }
        state.previous_m4_actions[24] = {DrivechainM4ActionType::ALARM, uint256{}};
        auto payload = ParseHex(two_byte ? "d77d177602" : "d77d177601");
        for (unsigned i = 0; i < length; ++i) {
            payload.push_back(two_byte || i == 0 ? 0 : 0xff);
            if (two_byte) payload.push_back(0);
        }
        Bitcoin::CMutableTransaction cb;
        cb.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
        cb.vout.emplace_back(0, CScript() << OP_RETURN << payload);
        Bitcoin::CBlock block;
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(cb)));
        const bool valid = !two_byte && length == slots.size();
        std::string error;
        BOOST_CHECK_EQUAL(ApplyDrivechainParentBlockState(block, 2, 24, required,
            10, 5, 10, 5, 10, 5, state, nullptr, &error), valid);
        if (two_byte) BOOST_CHECK_EQUAL(error, "two-byte M4 contains no value requiring two-byte encoding");
        else if (!valid) BOOST_CHECK_EQUAL(error, strprintf("M4 vote vector has %u entries for %u active sidechains", length, slots.size()));
        for (auto slot : slots) {
            const auto& pending = slot == 24 ? state.pending_withdrawals : state.other_slots.at(slot).pending_withdrawals;
            BOOST_REQUIRE_EQUAL(pending.size(), 1U);
            BOOST_CHECK_EQUAL(pending.front().votes, valid && slot == slots.front() ? 2 : 1);
        }
        BOOST_REQUIRE_EQUAL(state.previous_m4_actions.size(), 1U);
        const auto target = valid ? slots.front() : 24;
        BOOST_REQUIRE(state.previous_m4_actions.count(target));
        BOOST_CHECK(state.previous_m4_actions.at(target).type == (valid ? DrivechainM4ActionType::UPVOTE : DrivechainM4ActionType::ALARM));
    }
}

BOOST_AUTO_TEST_CASE(m6_id_amounts_and_fee_encoding_match_original)
{
    const std::array<CAmount,6> values{-1, 0, 1, MAX_MONEY - 1, MAX_MONEY, MAX_MONEY + 1};
    for (auto opcode : {drivechain::TreasuryOpcode::NOP5, drivechain::TreasuryOpcode::NOP8})
    for (auto old_value : values) for (auto treasury : values) for (auto a : values) for (auto b : values) {
        Bitcoin::CMutableTransaction tx;
        tx.vin.emplace_back(Bitcoin::COutPoint(uint256S("01"), 0));
        tx.vout.emplace_back(treasury, CScript() << static_cast<opcodetype>(opcode) << std::vector<unsigned char>{24} << OP_TRUE);
        tx.vout.emplace_back(a, CScript() << OP_TRUE);
        tx.vout.emplace_back(b, CScript() << OP_TRUE);
        std::string expected_error;
        CAmount payout{0};
        if (old_value < 0 || !MoneyRange(old_value) || treasury < 0 || !MoneyRange(treasury)) {
            expected_error = "BIP300 M6 treasury amount is outside the money range";
        } else {
            for (auto value : {a, b}) {
                if (value < 0 || !MoneyRange(value) || value > MAX_MONEY - payout) {
                    expected_error = "BIP300 M6 payout total is outside the money range"; break;
                }
                payout += value;
            }
            if (expected_error.empty() && (treasury > old_value || payout > old_value - treasury))
                expected_error = "BIP300 M6 spends more than the previous treasury value";
        }
        uint256 expected;
        if (expected_error.empty()) {
            const uint64_t fee = old_value - treasury - payout;
            std::vector<unsigned char> bytes(8);
            for (size_t i = 0; i < bytes.size(); ++i) bytes[i] = static_cast<unsigned char>(fee >> (8 * (7 - i)));
            auto blinded = tx;
            blinded.vin.clear();
            blinded.vout[0] = Bitcoin::CTxOut(0, CScript() << OP_RETURN << bytes);
            expected = blinded.GetHash();
        }
        uint256 actual = uint256::ONE;
        uint8_t slot{99};
        std::string error;
        BOOST_CHECK_EQUAL(ComputeDrivechainM6Id(Bitcoin::CTransaction(tx), old_value, actual, &slot, &error, opcode), expected_error.empty());
        BOOST_CHECK_EQUAL(error, expected_error);
        BOOST_CHECK_EQUAL(actual, expected);
        BOOST_CHECK_EQUAL(slot, expected_error.empty() ? 24 : 99);
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_cleanup_retains_nonempty_slots)
{
    const uint256 required = uint256S("11"), proposal = uint256S("02");
    Bitcoin::CMutableTransaction cb;
    cb.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
    cb.vout.emplace_back(0, CScript() << OP_RETURN);
    Bitcoin::CBlock block;
    block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(cb)));
    for (unsigned flags = 0; flags < 16; ++flags) for (bool collect : {false, true}) {
        if ((flags & 8) && !(flags & 1)) continue;
        DrivechainParentReplayState state;
        state.active_proposal_hash = required;
        auto& other = state.other_slots[25];
        if (flags & 1) other.active_proposal_hash = proposal;
        if (flags & 2) other.pending_proposals.emplace(proposal, DrivechainPendingProposal{1, 0});
        if (flags & 4) other.pending_withdrawals.push_back({proposal, 1, 1});
        if (flags & 8) { other.ctip = Bitcoin::COutPoint(proposal, 0); other.ctip_value = 1000; }
        state.other_slots[26] = {};
        state.other_slots[27].active_proposal_hash = proposal;
        std::vector<DrivechainSuccessfulWithdrawal> withdrawals(1);
        std::vector<DrivechainWithdrawalProposalIdentity> proposals(1);
        std::string error;
        BOOST_REQUIRE(ApplyDrivechainParentBlockState(block, 2, 24, required,
            10, 5, 10, 5, 10, 5, state, nullptr, &error,
            collect ? &withdrawals : nullptr, collect ? &proposals : nullptr));
        BOOST_CHECK_EQUAL(state.other_slots.count(25), flags == 0 ? 0U : 1U);
        BOOST_CHECK_EQUAL(state.other_slots.count(26), 0U);
        BOOST_CHECK_EQUAL(state.other_slots.count(27), 1U);
        BOOST_CHECK_EQUAL(withdrawals.size(), collect ? 0U : 1U);
        BOOST_CHECK_EQUAL(proposals.size(), collect ? 0U : 1U);
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_m6_approval_and_publication_boundaries)
{
    const uint256 required = uint256S("11");
    const Bitcoin::COutPoint initial(uint256S("01"), 0);
    for (uint8_t slot : {24, 25}) for (bool proposed : {false, true}) for (bool collect : {false, true})
    for (uint16_t votes : {0, 4, 5, 6, 65535}) {
        DrivechainParentReplayState state;
        state.active_proposal_hash = required;
        state.other_slots[25].active_proposal_hash = required;
        auto& ctip = slot == 24 ? state.ctip : state.other_slots.at(25).ctip;
        auto& value = slot == 24 ? state.ctip_value : state.other_slots.at(25).ctip_value;
        auto& pending = slot == 24 ? state.pending_withdrawals : state.other_slots.at(25).pending_withdrawals;
        ctip = initial; value = 5000;
        Bitcoin::CMutableTransaction tx;
        tx.vin.emplace_back(initial);
        tx.vout.emplace_back(4000, CScript() << OP_NOP5 << std::vector<unsigned char>{slot} << OP_TRUE);
        tx.vout.emplace_back(900, CScript() << OP_TRUE);
        const auto txid = Bitcoin::CTransaction(tx).GetHash();
        uint256 m6id;
        uint8_t derived_slot{0};
        std::string error;
        BOOST_REQUIRE(ComputeDrivechainM6Id(Bitcoin::CTransaction(tx), 5000, m6id, &derived_slot, &error));
        if (proposed) pending.push_back({m6id, 1, votes});
        Bitcoin::CMutableTransaction cb;
        cb.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
        cb.vout.emplace_back(0, CScript() << OP_RETURN);
        Bitcoin::CBlock block;
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(cb)));
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(tx)));
        std::vector<DrivechainSuccessfulWithdrawal> withdrawals;
        const bool accepted = proposed && votes > 5;
        BOOST_CHECK_EQUAL(ApplyDrivechainParentBlockState(block, 2, 24, required,
            10, 5, 10, 5, 10, 5, state, nullptr, &error, collect ? &withdrawals : nullptr), accepted);
        BOOST_CHECK(ctip == (accepted ? Bitcoin::COutPoint(txid, 0) : initial));
        BOOST_CHECK_EQUAL(value, accepted ? 4000 : 5000);
        BOOST_CHECK_EQUAL(pending.size(), proposed && !accepted ? 1U : 0U);
        BOOST_REQUIRE_EQUAL(withdrawals.size(), accepted && collect ? 1U : 0U);
        if (!proposed) BOOST_CHECK_EQUAL(error, strprintf("BIP300 M6 %s was never proposed for slot %u", m6id.GetHex(), slot));
        else if (!accepted) BOOST_CHECK_EQUAL(error, strprintf("BIP300 M6 %s has %u votes, requiring more than %u", m6id.GetHex(), votes, 5));
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_m5_publication_gates)
{
    const uint256 required = uint256S("11");
    for (bool active : {false, true}) for (bool collect : {false, true})
    for (uint8_t slot : {24, 25}) for (size_t length : {0, 1, 128, 129}) for (CAmount amount : {CAmount{1}, MAX_MONEY}) {
        DrivechainParentReplayState state;
        state.active_proposal_hash = required;
        state.required_proposal_activated = active;
        state.other_slots[25].active_proposal_hash = required;
        const std::vector<unsigned char> address(length, 0x42);
        Bitcoin::CMutableTransaction cb;
        cb.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
        cb.vout.emplace_back(0, CScript() << OP_RETURN);
        Bitcoin::CMutableTransaction tx;
        tx.vin.emplace_back(Bitcoin::COutPoint(uint256S("01"), 0));
        tx.vout.emplace_back(amount, CScript() << OP_NOP5 << std::vector<unsigned char>{slot} << OP_TRUE);
        tx.vout.emplace_back(0, CScript() << OP_RETURN << address);
        const auto txid = Bitcoin::CTransaction(tx).GetHash();
        Bitcoin::CBlock block;
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(cb)));
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(tx)));
        std::vector<DrivechainMintableDeposit> deposits;
        std::string error;
        BOOST_REQUIRE(ApplyDrivechainParentBlockState(block, 2, 24, required,
            10, 5, 10, 5, 10, 5, state, collect ? &deposits : nullptr, &error));
        BOOST_CHECK((slot == 24 ? state.ctip : state.other_slots.at(25).ctip) == Bitcoin::COutPoint(txid, 0));
        BOOST_CHECK_EQUAL(slot == 24 ? state.ctip_value : state.other_slots.at(25).ctip_value, amount);
        const bool published = active && collect && slot == 24 && length > 0 && length <= 128;
        BOOST_REQUIRE_EQUAL(deposits.size(), published ? 1U : 0U);
        if (published) {
            BOOST_CHECK_EQUAL(deposits.front().value, amount);
            BOOST_CHECK(deposits.front().address == address);
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_m5_later_failure_keeps_earlier_deposit)
{
    const uint256 required = uint256S("11");
    DrivechainParentReplayState state;
    state.active_proposal_hash = required;
    state.required_proposal_activated = true;
    state.other_slots[25].active_proposal_hash = required;
    Bitcoin::CMutableTransaction cb;
    cb.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
    cb.vout.emplace_back(0, CScript() << OP_RETURN);
    Bitcoin::CMutableTransaction tx;
    tx.vin.emplace_back(Bitcoin::COutPoint(uint256S("01"), 0));
    for (uint8_t slot : {24, 25}) {
        tx.vout.emplace_back(1000, CScript() << OP_NOP5 << std::vector<unsigned char>{slot} << OP_TRUE);
        tx.vout.emplace_back(0, slot == 24 ? CScript() << OP_RETURN << std::vector<unsigned char>{0x42} : CScript() << OP_TRUE);
    }
    const auto txid = Bitcoin::CTransaction(tx).GetHash();
    Bitcoin::CBlock block;
    block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(cb)));
    block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(tx)));
    std::vector<DrivechainMintableDeposit> deposits;
    std::string error;
    BOOST_CHECK(!ApplyDrivechainParentBlockState(block, 2, 24, required,
        10, 5, 10, 5, 10, 5, state, &deposits, &error));
    BOOST_CHECK_EQUAL(error, "positive CTIP replacement for slot 25 has no following address");
    BOOST_CHECK(state.ctip == Bitcoin::COutPoint(txid, 0));
    BOOST_CHECK_EQUAL(state.ctip_value, 1000);
    BOOST_CHECK(!state.other_slots.at(25).ctip);
    BOOST_REQUIRE_EQUAL(deposits.size(), 1U);
    BOOST_CHECK_EQUAL(deposits.front().value, 1000);
}

BOOST_AUTO_TEST_CASE(parent_replay_ctip_change_derivation_order)
{
    const uint256 required = uint256S("11");
    const Bitcoin::COutPoint first(uint256S("01"), 0), second(uint256S("02"), 0);
    const std::array<CAmount,5> values{0, 999, 1000, 1001, MAX_MONEY};
    for (CAmount a : values) for (CAmount b : values) {
        DrivechainParentReplayState state;
        state.active_proposal_hash = required;
        state.ctip = first; state.ctip_value = 1000;
        auto& other = state.other_slots[25];
        other.active_proposal_hash = required;
        other.ctip = second; other.ctip_value = 1000;
        Bitcoin::CMutableTransaction cb;
        cb.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
        cb.vout.emplace_back(0, CScript() << OP_RETURN);
        Bitcoin::CMutableTransaction tx;
        tx.vin.emplace_back(first); tx.vin.emplace_back(second);
        tx.vout.emplace_back(a, CScript() << OP_NOP5 << std::vector<unsigned char>{24} << OP_TRUE);
        tx.vout.emplace_back(b, CScript() << OP_NOP5 << std::vector<unsigned char>{25} << OP_TRUE);
        Bitcoin::CBlock block;
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(cb)));
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(tx)));
        std::string error;
        BOOST_CHECK(!ApplyDrivechainParentBlockState(block, 2, 24, required,
            10, 5, 10, 5, 10, 5, state, nullptr, &error));
        BOOST_CHECK_EQUAL(error, a == 1000 ? "slot 24 CTIP replacement has zero value delta" :
            b == 1000 ? "slot 25 CTIP replacement has zero value delta" :
            a < 1000 || b < 1000 ? "parent transaction ambiguously mixes M5 and M6 transitions" :
            "positive CTIP replacement for slot 24 has no following address");
        BOOST_CHECK(state.ctip == first);
        BOOST_CHECK(other.ctip == second);
        BOOST_CHECK_EQUAL(state.ctip_value, 1000);
        BOOST_CHECK_EQUAL(other.ctip_value, 1000);
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_ctip_output_order_and_skips)
{
    const uint256 required = uint256S("11");
    const auto treasury_script = [](uint8_t slot) { return CScript() << OP_NOP5 << std::vector<unsigned char>{slot} << OP_TRUE; };
    for (unsigned first = 0; first < 5; ++first) for (unsigned second = 0; second < 5; ++second) {
        DrivechainParentReplayState state;
        state.active_proposal_hash = required;
        state.other_slots[25].active_proposal_hash = required;
        Bitcoin::CMutableTransaction cb;
        cb.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
        cb.vout.emplace_back(0, CScript() << OP_RETURN);
        Bitcoin::CMutableTransaction tx;
        tx.vin.emplace_back(Bitcoin::COutPoint(uint256S("01"), 0));
        std::set<unsigned> slots;
        std::string expected;
        for (auto code : {first, second}) {
            const unsigned slot = code == 1 ? 26 : code == 4 ? 25 : 24;
            const CAmount amount = code <= 1 || code == 3 ? -1 : 1000;
            tx.vout.emplace_back(amount, code == 0 ? CScript() << OP_TRUE : treasury_script(slot));
            if (!expected.empty() || code <= 1) continue;
            if (amount < 0) expected = "invalid treasury value for slot 24";
            else if (!slots.insert(slot).second) expected = strprintf("parent transaction creates multiple treasury outputs for slot %u", slot);
        }
        tx.vout.emplace_back(-1, treasury_script(25));
        if (expected.empty()) expected = "invalid treasury value for slot 25";
        Bitcoin::CBlock block;
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(cb)));
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(tx)));
        std::string error;
        BOOST_CHECK(!ApplyDrivechainParentBlockState(block, 2, 24, required,
            10, 5, 10, 5, 10, 5, state, nullptr, &error));
        BOOST_CHECK_EQUAL(error, expected);
        BOOST_CHECK(!state.ctip.has_value());
        BOOST_CHECK(!state.other_slots.at(25).ctip.has_value());
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_ctip_replacement_requirement)
{
    const uint256 required = uint256S("11");
    const Bitcoin::COutPoint treasury(uint256S("01"), 0), unknown(uint256S("02"), 0);
    for (bool spent : {false, true}) for (bool replaced : {false, true}) {
        DrivechainParentReplayState state;
        state.active_proposal_hash = required;
        state.ctip = treasury;
        state.ctip_value = 1000;
        Bitcoin::CMutableTransaction cb;
        cb.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
        cb.vout.emplace_back(0, CScript() << OP_RETURN);
        Bitcoin::CMutableTransaction tx;
        tx.vin.emplace_back(spent ? treasury : unknown);
        tx.vout.emplace_back(replaced ? 1000 : 0, replaced ?
            CScript() << OP_NOP5 << std::vector<unsigned char>{24} << OP_TRUE : CScript() << OP_TRUE);
        Bitcoin::CBlock block;
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(cb)));
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(tx)));
        std::string error;
        BOOST_CHECK_EQUAL(ApplyDrivechainParentBlockState(block, 2, 24, required,
            10, 5, 10, 5, 10, 5, state, nullptr, &error), !spent && !replaced);
        BOOST_CHECK_EQUAL(error, spent ? (replaced ? "slot 24 CTIP replacement has zero value delta" :
            "parent transaction spends slot 24 CTIP without replacement") :
            (replaced ? "parent transaction creates a parallel treasury output for slot 24" : ""));
        BOOST_CHECK(state.ctip == treasury);
        BOOST_CHECK_EQUAL(state.ctip_value, 1000);
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_ctip_scan_error_order)
{
    const uint256 required = uint256S("11");
    const Bitcoin::COutPoint treasury(uint256S("01"), 0), unknown(uint256S("02"), 0);
    for (bool duplicate_owner : {false, true}) for (unsigned known_inputs = 0; known_inputs <= 2; ++known_inputs) {
        DrivechainParentReplayState state;
        state.active_proposal_hash = required;
        state.ctip = treasury;
        state.ctip_value = 1000;
        auto& other = state.other_slots[25];
        other.active_proposal_hash = required;
        if (duplicate_owner) { other.ctip = treasury; other.ctip_value = 1000; }
        Bitcoin::CMutableTransaction cb;
        cb.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
        cb.vout.emplace_back(0, CScript() << OP_RETURN);
        Bitcoin::CMutableTransaction tx;
        tx.vin.emplace_back(unknown);
        for (unsigned i = 0; i < known_inputs; ++i) tx.vin.emplace_back(treasury);
        // Sentinel failure after the scans, without mutating a CTIP or minting.
        tx.vout.emplace_back(-1, CScript() << OP_NOP5 << std::vector<unsigned char>{24} << OP_TRUE);
        Bitcoin::CBlock block;
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(cb)));
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(tx)));
        std::string error;
        BOOST_CHECK(!ApplyDrivechainParentBlockState(block, 2, 24, required,
            10, 5, 10, 5, 10, 5, state, nullptr, &error));
        BOOST_CHECK_EQUAL(error, duplicate_owner ? "two drivechain slots share one canonical CTIP" :
            known_inputs == 2 ? "parent transaction spends slot 24 CTIP more than once" : "invalid treasury value for slot 24");
        BOOST_CHECK(state.ctip == treasury);
        BOOST_CHECK_EQUAL(state.ctip_value, 1000);
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_expiry_boundaries_match_original)
{
    const uint256 required = uint256S("11"), proposal = uint256S("01");
    Bitcoin::CMutableTransaction cb;
    cb.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
    cb.vout.emplace_back(0, CScript() << OP_RETURN);
    Bitcoin::CBlock block;
    block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(cb)));
    for (bool used : {false, true}) {
        for (uint32_t age = 0; age <= 12; ++age) for (uint32_t votes = 0; votes <= age + 1; ++votes) {
            DrivechainParentReplayState state;
            if (used) state.active_proposal_hash = required;
            state.pending_proposals.emplace(proposal, DrivechainPendingProposal{1, votes});
            state.other_slots[25].active_proposal_hash = required;
            state.other_slots[25].pending_withdrawals.push_back({proposal, 1, 1});
            const uint32_t max_age = used ? 10 : 8, threshold = used ? 5 : 3;
            const bool valid = votes <= age;
            const bool expired = valid && (age > max_age || (age > max_age - threshold && age - votes >= max_age - threshold));
            std::string error;
            BOOST_CHECK_EQUAL(ApplyDrivechainParentBlockState(block, age + 1, 24, required,
                8, 3, 10, 5, 10, 5, state, nullptr, &error), valid);
            BOOST_CHECK_EQUAL(state.pending_proposals.count(proposal), expired ? 0U : 1U);
            BOOST_CHECK_EQUAL(state.other_slots.at(25).pending_withdrawals.size(), valid && age > 10 ? 0U : 1U);
            if (!valid) BOOST_CHECK_EQUAL(error, "parent proposal has more votes than elapsed blocks for slot 24");
        }
    }
    // An earlier erase remains visible when a later entry has an invalid height.
    DrivechainParentReplayState state;
    state.pending_proposals.emplace(uint256{}, DrivechainPendingProposal{0, 0});
    state.pending_proposals.emplace(proposal, DrivechainPendingProposal{20, 0});
    std::string error;
    BOOST_CHECK(!ApplyDrivechainParentBlockState(block, 12, 24, required,
        8, 3, 10, 5, 10, 5, state, nullptr, &error));
    BOOST_CHECK_EQUAL(state.pending_proposals.size(), 1U);
    BOOST_CHECK_EQUAL(error, "parent proposal height is ahead of replay height for slot 24");
    state = {};
    state.active_proposal_hash = required;
    state.pending_withdrawals.push_back({proposal, 0, 1});
    state.pending_withdrawals.push_back({required, 20, 1});
    BOOST_CHECK(!ApplyDrivechainParentBlockState(block, 12, 24, required,
        8, 3, 10, 5, 10, 5, state, nullptr, &error));
    BOOST_REQUIRE_EQUAL(state.pending_withdrawals.size(), 1U);
    BOOST_CHECK_EQUAL(state.pending_withdrawals.front().m6id, required);
    BOOST_CHECK_EQUAL(error, "M3 proposal height is ahead of replay height");
}

BOOST_AUTO_TEST_CASE(parent_replay_m4_dispatch_preserves_partial_slot_mutations)
{
    const uint256 required = uint256S("11"), bundle = uint256S("01");
    const std::array<uint8_t,4> choices{0, 0xfe, 0xff, 1};
    for (bool repeat : {false, true}) {
        for (auto first : choices) for (auto second : choices) {
            DrivechainParentReplayState state;
            state.active_proposal_hash = required;
            state.other_slots[25].active_proposal_hash = required;
            state.pending_withdrawals.push_back({bundle, 1, 1});
            state.other_slots[25].pending_withdrawals.push_back({bundle, 1, 1});
            std::array<uint16_t,2> expected{1, 1};
            std::map<uint8_t, DrivechainM4Action> actions;
            const std::array<uint8_t,2> votes{first, second};
            for (size_t i = 0; i < votes.size(); ++i) {
                if (repeat && votes[i] != 0xff) state.previous_m4_actions[24 + i] =
                    votes[i] == 0xfe ? DrivechainM4Action{DrivechainM4ActionType::ALARM, uint256{}} :
                    DrivechainM4Action{DrivechainM4ActionType::UPVOTE, votes[i] == 0 ? bundle : uint256S("02")};
            }
            const auto previous = state.previous_m4_actions;
            bool ok{true};
            for (size_t i = 0; i < votes.size(); ++i) {
                if (votes[i] == 1) { ok = false; break; }
                if (votes[i] == 0xff) continue;
                expected[i] = votes[i] == 0 ? 2 : 0;
                actions[24 + i] = votes[i] == 0 ? DrivechainM4Action{DrivechainM4ActionType::UPVOTE, bundle} :
                    DrivechainM4Action{DrivechainM4ActionType::ALARM, uint256{}};
            }
            auto payload = ParseHex(repeat ? "d77d177600" : "d77d177601");
            if (!repeat) payload.insert(payload.end(), votes.begin(), votes.end());
            Bitcoin::CMutableTransaction cb;
            cb.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
            cb.vout.emplace_back(0, CScript() << OP_RETURN << payload);
            Bitcoin::CBlock block;
            block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(cb)));
            std::string error;
            BOOST_CHECK_EQUAL(ApplyDrivechainParentBlockState(block, 2, 24, required,
                10, 5, 10, 5, 10, 5, state, nullptr, &error), ok);
            BOOST_CHECK_EQUAL(state.pending_withdrawals.at(0).votes, expected[0]);
            BOOST_CHECK_EQUAL(state.other_slots.at(25).pending_withdrawals.at(0).votes, expected[1]);
            const auto& expected_actions = ok ? actions : previous;
            BOOST_REQUIRE_EQUAL(state.previous_m4_actions.size(), expected_actions.size());
            for (const auto& [slot, action] : expected_actions) {
                BOOST_REQUIRE(state.previous_m4_actions.count(slot));
                BOOST_CHECK(state.previous_m4_actions.at(slot).type == action.type);
                BOOST_CHECK_EQUAL(state.previous_m4_actions.at(slot).m6id, action.m6id);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_m4_leader_matches_original_selection)
{
    const uint256 required = uint256S("11");
    const std::array<uint256,3> hashes{uint256S("01"), uint256S("02"), uint256S("03")};
    const std::array<uint16_t,7> values{0, 1, 49, 50, 51, 65534, 65535};
    Bitcoin::CMutableTransaction cb;
    cb.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
    cb.vout.emplace_back(0, CScript() << OP_RETURN << ParseHex("d77d177603"));
    Bitcoin::CBlock block;
    block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(cb)));
    for (unsigned code = 0; code < 343; ++code) {
        for (size_t count = 0; count <= 3; ++count) {
            std::array<uint16_t,3> expected{values[code % 7], values[(code / 7) % 7], values[code / 49]};
            DrivechainParentReplayState state;
            state.active_proposal_hash = required;
            for (size_t i = 0; i < count; ++i) state.pending_withdrawals.push_back({hashes[i], 1, expected[i]});
            size_t leader{0};
            uint16_t second{0};
            bool effective{false};
            if (count != 0) {
                for (size_t i = 1; i < count; ++i) {
                    if (expected[i] > expected[leader]) {
                        second = std::max(second, expected[leader]); leader = i;
                    } else second = std::max(second, expected[i]);
                }
                const uint16_t lead = expected[leader];
                effective = lead >= second && static_cast<uint16_t>(lead - second) >= 50 && lead < 65535;
                if (effective) {
                    ++expected[leader];
                    for (size_t i = 0; i < count; ++i) if (i != leader && expected[i] > 0) --expected[i];
                }
            }
            std::string error;
            BOOST_REQUIRE(ApplyDrivechainParentBlockState(block, 2, 24, required,
                10, 5, 10, 5, 10, 5, state, nullptr, &error));
            BOOST_REQUIRE_EQUAL(state.pending_withdrawals.size(), count);
            for (size_t i = 0; i < count; ++i) BOOST_CHECK_EQUAL(state.pending_withdrawals[i].votes, expected[i]);
            BOOST_CHECK_EQUAL(state.previous_m4_actions.count(24), effective ? 1U : 0U);
            if (effective) {
                BOOST_CHECK(state.previous_m4_actions.at(24).type == DrivechainM4ActionType::UPVOTE);
                BOOST_CHECK_EQUAL(state.previous_m4_actions.at(24).m6id, hashes[leader]);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_m4_counter_boundaries_match_original)
{
    const uint256 required = uint256S("11");
    const std::array<uint256,3> hashes{uint256S("01"), uint256S("02"), uint256S("03")};
    const std::array<uint16_t,4> values{0, 1, 65534, 65535};
    for (unsigned code = 0; code < 64; ++code) {
        for (unsigned target = 0; target < 4; ++target) {
            std::array<uint16_t,3> expected{values[code % 4], values[(code / 4) % 4], values[code / 16]};
            DrivechainParentReplayState state;
            state.active_proposal_hash = required;
            for (size_t i = 0; i < hashes.size(); ++i) state.pending_withdrawals.push_back({hashes[i], 1, expected[i]});
            const bool alarm = target == 3;
            bool effective{false};
            if (alarm) {
                for (auto& votes : expected) if (votes > 0) { --votes; effective = true; }
            } else if (expected[target] != 65535) {
                ++expected[target]; effective = true;
                for (size_t i = 0; i < expected.size(); ++i) if (i != target && expected[i] > 0) --expected[i];
            }
            auto payload = ParseHex("d77d177601");
            payload.push_back(alarm ? 0xfe : target);
            Bitcoin::CMutableTransaction cb;
            cb.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
            cb.vout.emplace_back(0, CScript() << OP_RETURN << payload);
            Bitcoin::CBlock block;
            block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(cb)));
            std::string error;
            BOOST_REQUIRE(ApplyDrivechainParentBlockState(block, 2, 24, required,
                10, 5, 10, 5, 10, 5, state, nullptr, &error));
            BOOST_REQUIRE_EQUAL(state.pending_withdrawals.size(), 3U);
            for (size_t i = 0; i < expected.size(); ++i) BOOST_CHECK_EQUAL(state.pending_withdrawals[i].votes, expected[i]);
            BOOST_CHECK_EQUAL(state.previous_m4_actions.count(24), effective ? 1U : 0U);
            if (effective) {
                BOOST_CHECK(state.previous_m4_actions.at(24).type ==
                    (alarm ? DrivechainM4ActionType::ALARM : DrivechainM4ActionType::UPVOTE));
                BOOST_CHECK_EQUAL(state.previous_m4_actions.at(24).m6id, alarm ? uint256{} : hashes[target]);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_m1_m3_preserve_insert_and_append_state)
{
    const uint256 required = uint256S("01");
    const auto m3 = [](unsigned char slot, const uint256& hash) {
        auto payload = ParseHex("d45aa943");
        payload.push_back(slot);
        payload.insert(payload.end(), hash.begin(), hash.end());
        return CScript() << OP_RETURN << payload;
    };
    const auto block_for = [&](const CScript& first) {
        Bitcoin::CMutableTransaction cb;
        cb.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
        cb.vout.emplace_back(0, first);
        cb.vout.emplace_back(0, m3(25, required)); // Stop before expiry/output publication.
        Bitcoin::CBlock block;
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(cb)));
        return block;
    };
    const std::vector<unsigned char> description{1, 2};
    const uint256 identity = Hash(description);
    for (bool known : {false, true}) {
        DrivechainParentReplayState state;
        if (known) state.pending_proposals.emplace(identity, DrivechainPendingProposal{1, 2});
        std::string error;
        BOOST_CHECK(!ApplyDrivechainParentBlockState(block_for(CScript() << OP_RETURN << ParseHex("d5e0c4af180102")),
            5, 24, required, 10, 5, 10, 5, 10, 5, state, nullptr, &error));
        BOOST_CHECK_EQUAL(error, "M3 proposes a withdrawal for inactive sidechain slot 25");
        BOOST_REQUIRE_EQUAL(state.pending_proposals.count(identity), 1U);
        BOOST_CHECK_EQUAL(state.pending_proposals.at(identity).proposal_height, known ? 1U : 5U);
        BOOST_CHECK_EQUAL(state.pending_proposals.at(identity).votes, known ? 2U : 0U);
    }
    for (bool active : {false, true}) {
        for (unsigned target = 1; target <= 3; ++target) {
            const uint256 hash = uint256S(target == 1 ? "01" : target == 2 ? "02" : "03");
            DrivechainParentReplayState state;
            if (active) state.active_proposal_hash = required;
            state.pending_withdrawals = {{required, 1, 2}, {uint256S("02"), 2, 3}};
            std::vector<DrivechainWithdrawalProposalIdentity> proposals(1);
            std::string error;
            BOOST_CHECK(!ApplyDrivechainParentBlockState(block_for(m3(24, hash)), 5, 24, required,
                10, 5, 10, 5, 10, 5, state, nullptr, &error, nullptr, &proposals));
            const bool appended = active && target == 3;
            BOOST_REQUIRE_EQUAL(state.pending_withdrawals.size(), appended ? 3U : 2U);
            BOOST_CHECK_EQUAL(state.pending_withdrawals[0].votes, 2U);
            BOOST_CHECK_EQUAL(state.pending_withdrawals[1].votes, 3U);
            BOOST_CHECK(proposals.empty());
            if (appended) {
                BOOST_CHECK_EQUAL(state.pending_withdrawals.back().m6id, hash);
                BOOST_CHECK_EQUAL(state.pending_withdrawals.back().proposal_height, 5U);
                BOOST_CHECK_EQUAL(state.pending_withdrawals.back().votes, 1U);
                BOOST_CHECK_EQUAL(error, "M3 proposes a withdrawal for inactive sidechain slot 25");
            } else if (!active) {
                BOOST_CHECK_EQUAL(error, "M3 proposes a withdrawal for inactive sidechain slot 24");
            } else {
                BOOST_CHECK_EQUAL(error, "M3 withdrawal bundle " + hash.GetHex() + " is already pending for slot 24");
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_m2_activation_matches_original_thresholds)
{
    const uint256 required = uint256S("01"), old = uint256S("02");
    auto payload = ParseHex("d6e1c5df18");
    payload.insert(payload.end(), required.begin(), required.end());
    Bitcoin::CMutableTransaction coinbase;
    coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
    coinbase.vout.emplace_back(0, CScript() << OP_RETURN << payload);
    // Stop after M2, before the separate proposal-expiry pass can alter its result.
    auto inactive_m3 = ParseHex("d45aa94319");
    inactive_m3.insert(inactive_m3.end(), required.begin(), required.end());
    coinbase.vout.emplace_back(0, CScript() << OP_RETURN << inactive_m3);
    Bitcoin::CBlock block;
    block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(coinbase)));
    for (bool used : {false, true}) {
        for (bool known : {false, true}) {
            for (uint32_t proposed : {0U, 1U, 9U, 10U, 11U}) {
                for (uint32_t votes : {0U, 1U, 2U, 3U, 4U, UINT32_MAX}) {
                    DrivechainParentReplayState state;
                    state.active_proposal_hash = used ? old : uint256{};
                    if (known) state.pending_proposals.emplace(required, DrivechainPendingProposal{proposed, votes});
                    std::string error;
                    const bool valid = !known || proposed <= 10;
                    BOOST_CHECK(!ApplyDrivechainParentBlockState(block, 10, 24, required,
                        10, 2, 20, 4, 10, 5, state, nullptr, &error));
                    const uint32_t after = known && proposed < 10 ? votes + 1 : votes;
                    const bool activated = known && proposed < 10 && after > (used ? 4U : 2U);
                    BOOST_CHECK_EQUAL(state.required_proposal_activated, activated);
                    BOOST_CHECK_EQUAL(state.active_proposal_hash, activated ? required : used ? old : uint256{});
                    BOOST_CHECK_EQUAL(state.pending_proposals.count(required), known && !activated ? 1U : 0U);
                    if (known && !activated) BOOST_CHECK_EQUAL(state.pending_proposals.at(required).votes, after);
                    if (activated) {
                        BOOST_CHECK_EQUAL(state.required_activation_height, 10U);
                        BOOST_CHECK_EQUAL(state.required_activation_block_hash, block.GetHash());
                    }
                    BOOST_CHECK_EQUAL(error, valid ? "M3 proposes a withdrawal for inactive sidechain slot 25" :
                        "M2 proposal height is ahead of replay height");
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_coinbase_duplicate_priority_and_no_state_mutation)
{
    std::vector<CScript> scripts;
    for (const char* tag : {"d5e0c4af", "d6e1c5df", "d77d1776", "d1617368"}) {
        auto payload = ParseHex(tag);
        if (scripts.size() == 2) payload.push_back(0);
        else { payload.push_back(24); payload.resize(37, 1); }
        scripts.push_back(CScript() << OP_RETURN << payload);
    }
    const char* errors[]{"parent block contains a duplicate M1 proposal message",
        "parent block contains multiple M2 ACK messages for one slot",
        "parent block contains multiple M4 withdrawal ACK messages",
        "parent block contains multiple M7 commitments for one slot"};
    for (size_t first = 0; first < scripts.size(); ++first) {
        for (size_t second = 0; second < scripts.size(); ++second) {
            Bitcoin::CMutableTransaction coinbase;
            coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
            coinbase.vout.emplace_back(0, scripts[first]);
            for (unsigned n = 0; n < 257; ++n) coinbase.vout.emplace_back(0, CScript() << OP_TRUE);
            coinbase.vout.emplace_back(0, scripts[second]);
            coinbase.vout.emplace_back(0, scripts[first]);
            coinbase.vout.emplace_back(0, scripts[second]);
            Bitcoin::CBlock block;
            block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(coinbase)));
            DrivechainParentReplayState state;
            std::vector<DrivechainMintableDeposit> deposits(1);
            std::string error;
            BOOST_CHECK(!ApplyDrivechainParentBlockState(block, 1, 24, uint256S("01"),
                10, 5, 10, 5, 10, 5, state, &deposits, &error));
            BOOST_CHECK_EQUAL(error, errors[first]);
            BOOST_CHECK(deposits.empty());
            BOOST_CHECK(state.active_proposal_hash.IsNull() && state.pending_proposals.empty() &&
                state.pending_withdrawals.empty() && state.other_slots.empty() && !state.ctip);
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_coinbase_and_m4_preflight_match_original)
{
    const uint256 proposal = uint256S("01");
    for (unsigned shape = 0; shape < 4; ++shape) {
        Bitcoin::CBlock block;
        if (shape == 1) block.vtx.emplace_back();
        if (shape >= 2) {
            Bitcoin::CMutableTransaction tx;
            tx.vin.emplace_back(shape == 3 ? Bitcoin::COutPoint{} : Bitcoin::COutPoint(proposal, 0), CScript() << OP_0);
            block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(tx)));
        }
        for (unsigned type = 0; type <= 255; ++type) {
            for (bool null_hash : {false, true}) {
                DrivechainParentReplayState state;
                const auto action_type = static_cast<DrivechainM4ActionType>(type);
                state.previous_m4_actions[42] = {action_type, null_hash ? uint256{} : proposal};
                // A later invalid action keeps this test entirely within preflight.
                state.previous_m4_actions[43].type = static_cast<DrivechainM4ActionType>(0);
                const bool invalid = (action_type != DrivechainM4ActionType::UPVOTE && action_type != DrivechainM4ActionType::ALARM) ||
                    (action_type == DrivechainM4ActionType::ALARM && !null_hash);
                std::string error;
                BOOST_CHECK(!ApplyDrivechainParentBlockState(block, 1, 24, proposal, 10, 5, 10, 5, 10, 5, state, nullptr, &error));
                BOOST_CHECK_EQUAL(error, shape != 3 ? "parent-state replay block has no coinbase transaction" :
                    invalid ? "parent-state replay has malformed prior M4 action for slot 42" :
                    "parent-state replay has malformed prior M4 action for slot 43");
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_proposal_consistency_matches_original)
{
    const uint256 required = uint256S("01");
    for (bool activated : {false, true}) {
        for (const uint256 active : {uint256{}, required, uint256S("02")}) {
            for (bool has_ctip : {false, true}) {
                DrivechainParentReplayState state;
                state.required_proposal_activated = activated;
                state.active_proposal_hash = active;
                if (has_ctip) state.ctip = Bitcoin::COutPoint(required, 0);
                const bool invalid = (activated && active != required) || (active.IsNull() && has_ctip);
                std::string error;
                BOOST_CHECK(!ApplyDrivechainParentBlockState(Bitcoin::CBlock{}, 1, 24, required,
                    10, 5, 10, 5, 10, 5, state, nullptr, &error));
                BOOST_CHECK_EQUAL(error, invalid ? "parent-state replay began with an inconsistent active proposal" :
                    "parent-state replay block has no coinbase transaction");
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_rule_catalog_preserves_selector_combinations)
{
    for (unsigned opcode = 0; opcode <= 255; ++opcode) {
        for (const auto rule : {DrivechainM6ReplayRule::SINGLE_CONFIGURED_SLOT_M6, DrivechainM6ReplayRule::SEQUENTIAL_M6}) {
            const auto treasury = static_cast<drivechain::TreasuryOpcode>(opcode);
            const bool supported = (treasury == drivechain::TreasuryOpcode::NOP5 || treasury == drivechain::TreasuryOpcode::NOP8) &&
                (rule == DrivechainM6ReplayRule::SINGLE_CONFIGURED_SLOT_M6 || rule == DrivechainM6ReplayRule::SEQUENTIAL_M6);
            BOOST_CHECK_EQUAL(drivechain::SupportedParentReplayRules(treasury, rule), supported);
            DrivechainParentReplayState state;
            std::vector<DrivechainMintableDeposit> deposits(1);
            std::vector<DrivechainSuccessfulWithdrawal> withdrawals(1);
            std::vector<DrivechainWithdrawalProposalIdentity> proposals(1);
            std::string error;
            BOOST_CHECK(!ApplyDrivechainParentBlockState(Bitcoin::CBlock{}, 1, -1, uint256{},
                0, 0, 0, 0, 0, 0, state, &deposits, &error, &withdrawals, &proposals, treasury, rule));
            BOOST_CHECK_EQUAL(error, supported ? "invalid slot or proposal identity for parent-state replay" :
                "unsupported parent-state replay rules");
            BOOST_CHECK(deposits.empty() && withdrawals.empty() && proposals.empty());
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_ctip_balances_preserve_preflight_priority)
{
    const uint256 proposal = uint256S("01");
    Bitcoin::CMutableTransaction coinbase;
    coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
    Bitcoin::CBlock block;
    block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(coinbase)));
    const CAmount amounts[]{std::numeric_limits<CAmount>::min(), -1, 0, 1,
        MAX_MONEY - 1, MAX_MONEY, MAX_MONEY + 1, std::numeric_limits<CAmount>::max()};
    for (bool other : {false, true}) {
        for (bool has_ctip : {false, true}) {
            for (bool null_proposal : {false, true}) {
                for (CAmount value : amounts) {
                    DrivechainParentReplayState state;
                    auto& active = other ? state.other_slots[25].active_proposal_hash : state.active_proposal_hash;
                    auto& ctip = other ? state.other_slots[25].ctip : state.ctip;
                    auto& balance = other ? state.other_slots[25].ctip_value : state.ctip_value;
                    active = null_proposal ? uint256{} : proposal;
                    if (has_ctip) ctip = Bitcoin::COutPoint(proposal, 0);
                    balance = value;
                    // Stop after preflight even when the CTIP tuple is valid.
                    state.previous_m4_actions[42].type = static_cast<DrivechainM4ActionType>(0);
                    const bool malformed = has_ctip ? value < 0 || !MoneyRange(value) : value != 0;
                    const char* expected = !other && null_proposal && has_ctip ?
                        "parent-state replay began with an inconsistent active proposal" :
                        other && ((null_proposal && has_ctip) || malformed) ?
                        "parent-state replay began with malformed global slot state" :
                        !other && malformed ? "parent-state replay began with malformed CTIP state" :
                        "parent-state replay has malformed prior M4 action for slot 42";
                    std::string error;
                    BOOST_CHECK(!ApplyDrivechainParentBlockState(block, 1, 24, proposal,
                        10, 5, 10, 5, 10, 5, state, nullptr, &error));
                    BOOST_CHECK_EQUAL(error, expected);
                    BOOST_CHECK_EQUAL(balance, value);
                    BOOST_CHECK_EQUAL(ctip.has_value(), has_ctip);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_activation_windows_match_original_preflight)
{
    const uint16_t boundaries[]{0, 1, 2, 5, 10, 65534, 65535};
    for (int slot : {-1, 0, 24, 255, 256, std::numeric_limits<int>::min(), std::numeric_limits<int>::max()}) {
        for (bool null_proposal : {false, true}) {
            for (size_t window = 0; window < 3; ++window) {
                for (uint16_t age : boundaries) {
                    for (uint16_t threshold : boundaries) {
                        uint16_t ages[]{10, 10, 10}, thresholds[]{5, 5, 5};
                        ages[window] = age;
                        thresholds[window] = threshold;
                        DrivechainParentReplayState state;
                        std::vector<DrivechainMintableDeposit> deposits(1);
                        std::vector<DrivechainSuccessfulWithdrawal> withdrawals(1);
                        std::vector<DrivechainWithdrawalProposalIdentity> proposals(1);
                        std::string error;
                        const uint256 proposal = null_proposal ? uint256{} : uint256S("01");
                        BOOST_CHECK(!ApplyDrivechainParentBlockState(
                            Bitcoin::CBlock{}, 1, slot, proposal,
                            ages[0], thresholds[0], ages[1], thresholds[1], ages[2], thresholds[2],
                            state, &deposits, &error, &withdrawals, &proposals));
                        const bool invalid = slot < 0 || slot > 255 || null_proposal ||
                            age == 0 || threshold == 0 || threshold >= age;
                        BOOST_CHECK_EQUAL(error, invalid ? "invalid slot or proposal identity for parent-state replay" :
                            "parent-state replay block has no coinbase transaction");
                        BOOST_CHECK(deposits.empty() && withdrawals.empty() && proposals.empty());
                        BOOST_CHECK(state.active_proposal_hash.IsNull() && !state.ctip);
                    }
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(drivechain_parent_state_replay_matches_slot_voting_rules)
{
    constexpr int slot{24};
    constexpr uint16_t max_age{10};
    constexpr uint16_t threshold{5};
    const uint256 old_proposal = uint256S(
        "1111111111111111111111111111111111111111111111111111111111111111");
    const std::vector<unsigned char> required_description{'e', 'l', 'e', 'm', 'e', 'n', 't', 's'};
    const uint256 required_proposal = Hash(required_description);

    const auto make_m1 = [](const std::vector<unsigned char>& description) {
        std::vector<unsigned char> payload = ParseHex("d5e0c4af");
        payload.push_back(slot);
        payload.insert(payload.end(), description.begin(), description.end());
        return CScript() << OP_RETURN << payload;
    };
    const auto make_m2 = [](const uint256& proposal) {
        std::vector<unsigned char> payload = ParseHex("d6e1c5df");
        payload.push_back(slot);
        payload.insert(payload.end(), proposal.begin(), proposal.end());
        return CScript() << OP_RETURN << payload;
    };
    const auto make_block = [](const std::vector<CScript>& messages, const uint32_t nonce) {
        Bitcoin::CMutableTransaction coinbase;
        coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
        for (const CScript& message : messages) coinbase.vout.emplace_back(0, message);
        Bitcoin::CBlock block;
        block.nNonce = nonce;
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(coinbase)));
        return block;
    };
    const auto apply = [&](const Bitcoin::CBlock& block, const uint32_t height,
                           DrivechainParentReplayState& state, std::string& error) {
        return ApplyDrivechainParentBlockState(
            block, height, slot, required_proposal,
            max_age, threshold, max_age, threshold,
            /* withdrawal_max_age= */ 10, /* withdrawal_threshold= */ 5,
            state, nullptr, &error);
    };

    std::string error;
    DrivechainParentReplayState state;
    state.active_proposal_hash = old_proposal;

    // Same-block ACK is ignored, then six later ACKs activate the exact
    // Elements proposal. Unknown ACKs have no effect.
    BOOST_CHECK(apply(make_block({make_m1(required_description), make_m2(required_proposal)}, 100),
                      100, state, error));
    BOOST_REQUIRE_EQUAL(state.pending_proposals.count(required_proposal), 1U);
    BOOST_CHECK_EQUAL(state.pending_proposals.at(required_proposal).votes, 0U);
    // Repeating M1 in a later block must not restart the pending vote window.
    auto repeated_m1 = state;
    BOOST_REQUIRE(apply(make_block({make_m2(required_proposal)}, 101), 101, repeated_m1, error));
    BOOST_REQUIRE(apply(make_block({make_m1(required_description)}, 102), 102, repeated_m1, error));
    BOOST_REQUIRE_EQUAL(repeated_m1.pending_proposals.count(required_proposal), 1U);
    BOOST_CHECK_EQUAL(repeated_m1.pending_proposals.at(required_proposal).proposal_height, 100U);
    BOOST_CHECK_EQUAL(repeated_m1.pending_proposals.at(required_proposal).votes, 1U);
    const uint256 unknown = uint256S(
        "2222222222222222222222222222222222222222222222222222222222222222");
    BOOST_CHECK(apply(make_block({make_m2(unknown)}, 101), 101, state, error));
    BOOST_CHECK_EQUAL(state.pending_proposals.at(required_proposal).votes, 0U);
    for (uint32_t height = 102; height <= 107; ++height) {
        BOOST_CHECK(apply(make_block({make_m2(required_proposal)}, height),
                          height, state, error));
    }
    BOOST_CHECK(state.required_proposal_activated);
    BOOST_CHECK_EQUAL(state.required_activation_height, 107U);
    BOOST_CHECK_EQUAL(state.active_proposal_hash, required_proposal);

    // A re-proposal of the same required identity may reactivate harmlessly.
    BOOST_CHECK(apply(make_block({make_m1(required_description)}, 108), 108, state, error));
    for (uint32_t height = 109; height <= 114; ++height) {
        BOOST_CHECK(apply(make_block({make_m2(required_proposal)}, height),
                          height, state, error));
    }
    BOOST_CHECK_EQUAL(state.active_proposal_hash, required_proposal);

    // The enforcer accepts empty M1 descriptions. Before Elements activation an
    // arbitrary replacement is replayed but cannot authorize a mint; after
    // activation, its sixth ACK must terminal-halt V1.
    const std::vector<unsigned char> empty_description;
    const uint256 empty_proposal = Hash(empty_description);
    DrivechainParentReplayState preactivation;
    preactivation.active_proposal_hash = old_proposal;
    BOOST_CHECK(apply(make_block({make_m1(empty_description)}, 200), 200,
                      preactivation, error));
    for (uint32_t height = 201; height <= 206; ++height) {
        BOOST_CHECK(apply(make_block({make_m2(empty_proposal)}, height),
                          height, preactivation, error));
    }
    BOOST_CHECK(!preactivation.required_proposal_activated);
    BOOST_CHECK_EQUAL(preactivation.active_proposal_hash, empty_proposal);

    BOOST_CHECK(apply(make_block({make_m1(empty_description)}, 300), 300, state, error));
    for (uint32_t height = 301; height < 306; ++height) {
        BOOST_CHECK(apply(make_block({make_m2(empty_proposal)}, height), height, state, error));
    }
    BOOST_CHECK(!apply(make_block({make_m2(empty_proposal)}, 306), 306, state, error));

    // Coinbase message uniqueness is consensus-visible.
    DrivechainParentReplayState duplicate_ack;
    duplicate_ack.active_proposal_hash = old_proposal;
    BOOST_CHECK(!apply(make_block({make_m2(unknown), make_m2(unknown)}, 400),
                       400, duplicate_ack, error));

    DrivechainParentReplayState duplicate_m1;
    duplicate_m1.active_proposal_hash = old_proposal;
    BOOST_CHECK(!apply(
        make_block({make_m1(required_description), make_m1(required_description)}, 401),
        401, duplicate_m1, error));

    const std::vector<unsigned char> second_description{'o', 't', 'h', 'e', 'r'};
    const uint256 second_proposal = Hash(second_description);
    DrivechainParentReplayState distinct_m1s;
    distinct_m1s.active_proposal_hash = old_proposal;
    BOOST_CHECK(apply(
        make_block({make_m1(required_description), make_m1(second_description)}, 402),
        402, distinct_m1s, error));
    BOOST_CHECK_EQUAL(distinct_m1s.pending_proposals.count(required_proposal), 1U);
    BOOST_CHECK_EQUAL(distinct_m1s.pending_proposals.count(second_proposal), 1U);

    // The enforcer's ordinary instruction parser accepts a nonminimal push for
    // M1, while exact one-push/no-trailing framing still applies.
    const std::vector<unsigned char> nonminimal_description{'n'};
    std::vector<unsigned char> nonminimal_payload = ParseHex("d5e0c4af");
    nonminimal_payload.push_back(slot);
    nonminimal_payload.insert(nonminimal_payload.end(),
                              nonminimal_description.begin(),
                              nonminimal_description.end());
    CScript nonminimal_m1;
    nonminimal_m1.push_back(OP_RETURN);
    nonminimal_m1.push_back(OP_PUSHDATA1);
    nonminimal_m1.push_back(nonminimal_payload.size());
    nonminimal_m1.insert(nonminimal_m1.end(),
                         nonminimal_payload.begin(), nonminimal_payload.end());
    DrivechainParentReplayState nonminimal_state;
    nonminimal_state.active_proposal_hash = old_proposal;
    BOOST_CHECK(apply(make_block({nonminimal_m1}, 403), 403,
                      nonminimal_state, error));
    BOOST_CHECK_EQUAL(
        nonminimal_state.pending_proposals.count(Hash(nonminimal_description)), 1U);

    // Malformed-length or trailing M2-shaped scripts are ordinary scripts and
    // do not consume the one-valid-M2-per-slot allowance.
    std::vector<unsigned char> short_m2_payload = ParseHex("d6e1c5df");
    short_m2_payload.push_back(slot);
    short_m2_payload.insert(short_m2_payload.end(), 31, 0x00);
    CScript trailing_m2 = make_m2(unknown);
    trailing_m2 << OP_TRUE;
    DrivechainParentReplayState malformed_m2;
    malformed_m2.active_proposal_hash = old_proposal;
    BOOST_CHECK(apply(
        make_block({CScript() << OP_RETURN << short_m2_payload,
                    trailing_m2, make_m2(unknown)}, 404),
        404, malformed_m2, error));

    // With no ACKs, a used-slot proposal is present through age five and is
    // removed at age six when five votes are no longer attainable.
    DrivechainParentReplayState expiring;
    expiring.active_proposal_hash = old_proposal;
    BOOST_CHECK(apply(make_block({make_m1(required_description)}, 500), 500,
                      expiring, error));
    for (uint32_t height = 501; height <= 505; ++height) {
        BOOST_CHECK(apply(make_block({}, height), height, expiring, error));
    }
    BOOST_CHECK_EQUAL(expiring.pending_proposals.count(required_proposal), 1U);
    BOOST_CHECK(apply(make_block({}, 506), 506, expiring, error));
    BOOST_CHECK_EQUAL(expiring.pending_proposals.count(required_proposal), 0U);
}

BOOST_AUTO_TEST_CASE(drivechain_parent_replay_starts_unused_and_preserves_pending_state)
{
    constexpr int slot{24};
    constexpr uint16_t unused_max_age{4};
    constexpr uint16_t unused_threshold{1};
    constexpr uint16_t used_max_age{10};
    constexpr uint16_t used_threshold{5};
    const std::vector<unsigned char> first_description{'f', 'i', 'r', 's', 't'};
    const std::vector<unsigned char> required_description{'e', 'l', 'e', 'm', 'e', 'n', 't', 's'};
    const std::vector<unsigned char> pending_description{'p', 'e', 'n', 'd'};
    const uint256 first_proposal = Hash(first_description);
    const uint256 required_proposal = Hash(required_description);
    const uint256 pending_proposal = Hash(pending_description);

    const auto make_m1 = [](const std::vector<unsigned char>& description) {
        std::vector<unsigned char> payload = ParseHex("d5e0c4af");
        payload.push_back(slot);
        payload.insert(payload.end(), description.begin(), description.end());
        return CScript() << OP_RETURN << payload;
    };
    const auto make_m2 = [](const uint256& proposal) {
        std::vector<unsigned char> payload = ParseHex("d6e1c5df");
        payload.push_back(slot);
        payload.insert(payload.end(), proposal.begin(), proposal.end());
        return CScript() << OP_RETURN << payload;
    };
    const auto make_block = [](const std::vector<CScript>& messages,
                               const uint32_t nonce) {
        Bitcoin::CMutableTransaction coinbase;
        coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
        for (const CScript& message : messages) coinbase.vout.emplace_back(0, message);
        Bitcoin::CBlock block;
        block.nNonce = nonce;
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(coinbase)));
        return block;
    };
    const auto apply = [&](const Bitcoin::CBlock& block, const uint32_t height,
                           DrivechainParentReplayState& state,
                           std::vector<DrivechainMintableDeposit>* deposits,
                           std::string& error) {
        return ApplyDrivechainParentBlockState(
            block, height, slot, required_proposal,
            unused_max_age, unused_threshold, used_max_age, used_threshold,
            /* withdrawal_max_age= */ 10, /* withdrawal_threshold= */ 5,
            state, deposits, &error);
    };

    DrivechainParentReplayState state;
    std::vector<DrivechainMintableDeposit> deposits;
    std::string error;

    // Authenticate and apply height zero from truly empty state. A treasury-
    // shaped output in an inactive slot is ordinary anyone-can-spend output,
    // even though it would be malformed as an active-slot deposit.
    Bitcoin::CBlock genesis_like = make_block(
        {make_m1(first_description), make_m2(first_proposal)}, 0);
    Bitcoin::CMutableTransaction inactive_treasury;
    inactive_treasury.vin.emplace_back(Bitcoin::COutPoint(uint256::ONE, 0));
    inactive_treasury.vout.emplace_back(
        5000, CScript() << OP_NOP5 << std::vector<unsigned char>{slot} << OP_TRUE);
    genesis_like.vtx.push_back(
        Bitcoin::MakeTransactionRef(std::move(inactive_treasury)));
    BOOST_CHECK(apply(genesis_like, 0, state, &deposits, error));
    BOOST_CHECK(state.active_proposal_hash.IsNull());
    BOOST_CHECK(!state.ctip.has_value());
    BOOST_CHECK(deposits.empty());
    BOOST_CHECK_EQUAL(state.pending_proposals.at(first_proposal).votes, 0U);

    // The unused-slot pair (threshold 1) activates on the second later ACK.
    BOOST_CHECK(apply(make_block({make_m2(first_proposal)}, 1), 1,
                      state, nullptr, error));
    BOOST_CHECK(state.active_proposal_hash.IsNull());
    BOOST_CHECK(apply(make_block({make_m2(first_proposal)}, 2), 2,
                      state, nullptr, error));
    BOOST_CHECK_EQUAL(state.active_proposal_hash, first_proposal);

    // Replacement now uses the used-slot pair (threshold 5). Five ACKs do not
    // activate; the sixth does, without clearing unrelated pending proposals.
    BOOST_CHECK(apply(
        make_block({make_m1(required_description), make_m2(required_proposal)}, 3),
        3, state, nullptr, error));
    for (uint32_t height = 4; height <= 7; ++height) {
        BOOST_CHECK(apply(make_block({make_m2(required_proposal)}, height), height,
                          state, nullptr, error));
    }
    BOOST_CHECK(apply(
        make_block({make_m1(pending_description), make_m2(required_proposal)}, 8),
        8, state, nullptr, error));
    BOOST_CHECK_EQUAL(state.active_proposal_hash, first_proposal);
    BOOST_CHECK(apply(make_block({make_m2(required_proposal)}, 9), 9,
                      state, nullptr, error));
    BOOST_CHECK(state.required_proposal_activated);
    BOOST_CHECK_EQUAL(state.required_activation_height, 9U);
    BOOST_CHECK_EQUAL(state.active_proposal_hash, required_proposal);
    BOOST_CHECK_EQUAL(state.pending_proposals.count(pending_proposal), 1U);
}

BOOST_AUTO_TEST_CASE(drivechain_parent_ctip_replay_rejects_fabricated_transitions)
{
    constexpr int slot{24};
    constexpr uint16_t max_age{10};
    constexpr uint16_t threshold{5};
    const uint256 required_proposal = uint256S(
        "3333333333333333333333333333333333333333333333333333333333333333");
    const CScript treasury_script = CScript()
        << OP_NOP5 << std::vector<unsigned char>{slot} << OP_TRUE;
    const std::vector<unsigned char> address{'e', 'l', 'e', 'm', 'e', 'n', 't', 's'};
    const Bitcoin::COutPoint initial_ctip(
        uint256S("4444444444444444444444444444444444444444444444444444444444444444"), 0);

    const auto make_block = [](Bitcoin::CMutableTransaction transaction, const uint32_t nonce) {
        Bitcoin::CMutableTransaction coinbase;
        coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
        Bitcoin::CBlock block;
        block.nNonce = nonce;
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(coinbase)));
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(transaction)));
        return block;
    };
    const auto active_state = [&]() {
        DrivechainParentReplayState state;
        state.active_proposal_hash = required_proposal;
        state.required_proposal_activated = true;
        state.required_activation_height = 1;
        state.ctip = initial_ctip;
        state.ctip_value = 5000;
        return state;
    };
    const auto apply = [&](const Bitcoin::CBlock& block, DrivechainParentReplayState& state,
                           std::vector<DrivechainMintableDeposit>& deposits, std::string& error) {
        return ApplyDrivechainParentBlockState(
            block, 10, slot, required_proposal,
            max_age, threshold, max_age, threshold,
            /* withdrawal_max_age= */ 10, /* withdrawal_threshold= */ 5,
            state, &deposits, &error);
    };

    std::string error;
    std::vector<DrivechainMintableDeposit> deposits;
    Bitcoin::CMutableTransaction positive;
    positive.vin.emplace_back(initial_ctip);
    positive.vout.emplace_back(6000, treasury_script);
    positive.vout.emplace_back(700, CScript() << OP_RETURN << address);
    DrivechainParentReplayState state = active_state();
    BOOST_CHECK(apply(make_block(positive, 1), state, deposits, error));
    BOOST_REQUIRE_EQUAL(deposits.size(), 1U);
    BOOST_CHECK_EQUAL(deposits[0].value, 1000);
    BOOST_CHECK(deposits[0].address == address);
    BOOST_CHECK_EQUAL(state.ctip_value, 6000);

    Bitcoin::CMutableTransaction parallel;
    parallel.vin.emplace_back(Bitcoin::COutPoint(uint256::ONE, 0));
    parallel.vout.emplace_back(6000, treasury_script);
    parallel.vout.emplace_back(0, CScript() << OP_RETURN << address);
    state = active_state();
    BOOST_CHECK(!apply(make_block(parallel, 2), state, deposits, error));

    Bitcoin::CMutableTransaction theft;
    theft.vin.emplace_back(initial_ctip);
    theft.vout.emplace_back(5000, CScript() << OP_TRUE);
    state = active_state();
    BOOST_CHECK(!apply(make_block(theft, 3), state, deposits, error));

    Bitcoin::CMutableTransaction multiple;
    multiple.vin.emplace_back(initial_ctip);
    multiple.vout.emplace_back(5500, treasury_script);
    multiple.vout.emplace_back(5501, treasury_script);
    state = active_state();
    BOOST_CHECK(!apply(make_block(multiple, 4), state, deposits, error));

    Bitcoin::CMutableTransaction zero_delta;
    zero_delta.vin.emplace_back(initial_ctip);
    zero_delta.vout.emplace_back(5000, treasury_script);
    zero_delta.vout.emplace_back(0, CScript() << OP_RETURN << address);
    state = active_state();
    BOOST_CHECK(!apply(make_block(zero_delta, 5), state, deposits, error));

    Bitcoin::CMutableTransaction decrease;
    decrease.vin.emplace_back(initial_ctip);
    decrease.vout.emplace_back(4999, treasury_script);
    state = active_state();
    BOOST_CHECK(!apply(make_block(decrease, 6), state, deposits, error));

    // Empty pushed addresses are overlay-valid backing surplus, never a child
    // mint authorization. Missing the address output entirely remains invalid.
    Bitcoin::CMutableTransaction empty_address;
    empty_address.vin.emplace_back(initial_ctip);
    empty_address.vout.emplace_back(6000, treasury_script);
    empty_address.vout.emplace_back(0, CScript() << OP_RETURN << std::vector<unsigned char>{});
    state = active_state();
    BOOST_CHECK(apply(make_block(empty_address, 7), state, deposits, error));
    BOOST_CHECK(deposits.empty());
    BOOST_CHECK_EQUAL(state.ctip_value, 6000);

    // The parent permits arbitrary OP_RETURN address bytes, but the native
    // witness codec is capped at 128. Larger commitments remain backing
    // surplus and must not grow the mintable-deposit index.
    Bitcoin::CMutableTransaction oversized_address;
    oversized_address.vin.emplace_back(initial_ctip);
    oversized_address.vout.emplace_back(6000, treasury_script);
    oversized_address.vout.emplace_back(
        0, CScript() << OP_RETURN << std::vector<unsigned char>(129, 0x42));
    state = active_state();
    BOOST_CHECK(apply(make_block(oversized_address, 8), state, deposits, error));
    BOOST_CHECK(deposits.empty());
    BOOST_CHECK_EQUAL(state.ctip_value, 6000);

    Bitcoin::CMutableTransaction missing_address;
    missing_address.vin.emplace_back(initial_ctip);
    missing_address.vout.emplace_back(6000, treasury_script);
    state = active_state();
    BOOST_CHECK(!apply(make_block(missing_address, 9), state, deposits, error));

    // Before the frozen Elements proposal activates, exact increases update the
    // inherited CTIP but remain non-mintable backing surplus.
    DrivechainParentReplayState preactivation;
    preactivation.active_proposal_hash = uint256S(
        "5555555555555555555555555555555555555555555555555555555555555555");
    preactivation.ctip = initial_ctip;
    preactivation.ctip_value = 5000;
    BOOST_CHECK(apply(make_block(positive, 10), preactivation, deposits, error));
    BOOST_CHECK(deposits.empty());
    BOOST_CHECK_EQUAL(preactivation.ctip_value, 6000);
}

BOOST_AUTO_TEST_CASE(drivechain_parent_replay_accepts_only_miner_approved_m6)
{
    constexpr int slot{24};
    constexpr uint8_t other_slot{3};
    constexpr uint16_t max_age{10};
    constexpr uint16_t threshold{5};
    const uint256 required_proposal = uint256S(
        "3333333333333333333333333333333333333333333333333333333333333333");
    const uint256 other_proposal = uint256S(
        "0303030303030303030303030303030303030303030303030303030303030303");
    const Bitcoin::COutPoint initial_ctip(
        uint256S("4444444444444444444444444444444444444444444444444444444444444444"), 0);
    const CScript treasury_script = CScript()
        << OP_NOP5 << std::vector<unsigned char>{slot} << OP_TRUE;

    Bitcoin::CMutableTransaction withdrawal;
    withdrawal.vin.emplace_back(initial_ctip);
    withdrawal.vout.emplace_back(4000, treasury_script);
    withdrawal.vout.emplace_back(900, CScript() << OP_TRUE);
    const Bitcoin::CTransaction withdrawal_tx(withdrawal);
    uint256 m6id;
    uint8_t derived_slot{0};
    std::string error;
    BOOST_REQUIRE(ComputeDrivechainM6Id(
        withdrawal_tx, 5000, m6id, &derived_slot, &error));
    BOOST_CHECK_EQUAL(derived_slot, slot);

    const auto make_m3 = [](const uint8_t message_slot, const uint256& id) {
        std::vector<unsigned char> payload = ParseHex("d45aa943");
        payload.push_back(message_slot);
        payload.insert(payload.end(), id.begin(), id.end());
        return CScript() << OP_RETURN << payload;
    };
    const auto make_explicit_m4 = [](const std::vector<unsigned char>& votes) {
        std::vector<unsigned char> payload = ParseHex("d77d177601");
        payload.insert(payload.end(), votes.begin(), votes.end());
        return CScript() << OP_RETURN << payload;
    };
    const auto repeat_previous_m4 = []() {
        return CScript() << OP_RETURN << ParseHex("d77d177600");
    };
    const auto make_block = [](const std::vector<CScript>& messages,
                               const uint32_t nonce,
                               const Bitcoin::CMutableTransaction* transaction = nullptr) {
        Bitcoin::CMutableTransaction coinbase;
        coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
        for (const CScript& message : messages) coinbase.vout.emplace_back(0, message);
        Bitcoin::CBlock block;
        block.nNonce = nonce;
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(coinbase)));
        if (transaction) block.vtx.push_back(Bitcoin::MakeTransactionRef(*transaction));
        return block;
    };
    const auto apply = [&](const Bitcoin::CBlock& block,
                           const uint32_t height,
                           DrivechainParentReplayState& state,
                           std::vector<DrivechainSuccessfulWithdrawal>*
                               successful_withdrawals = nullptr,
                           std::vector<DrivechainWithdrawalProposalIdentity>*
                               withdrawal_proposals = nullptr) {
        return ApplyDrivechainParentBlockState(
            block, height, slot, required_proposal,
            max_age, threshold, max_age, threshold,
            max_age, threshold, state, nullptr, &error,
            successful_withdrawals, withdrawal_proposals);
    };

    DrivechainParentReplayState state;
    state.active_proposal_hash = required_proposal;
    state.required_proposal_activated = true;
    state.required_activation_height = 1;
    state.ctip = initial_ctip;
    state.ctip_value = 5000;
    state.other_slots[other_slot].active_proposal_hash = other_proposal;

    std::vector<DrivechainWithdrawalProposalIdentity> withdrawal_proposals;
    BOOST_REQUIRE(apply(
        make_block({make_m3(slot, m6id)}, 100), 100, state,
        nullptr, &withdrawal_proposals));
    BOOST_REQUIRE_EQUAL(state.pending_withdrawals.size(), 1U);
    BOOST_CHECK_EQUAL(state.pending_withdrawals[0].votes, 1U);
    BOOST_REQUIRE_EQUAL(withdrawal_proposals.size(), 1U);
    BOOST_CHECK_EQUAL(withdrawal_proposals[0].sidechain_slot, slot);
    BOOST_CHECK(withdrawal_proposals[0].m6id == m6id);

    // Active slots are globally sorted [3, 24]. A slot-24-only vote vector is
    // invalid; the correct vector abstains for slot 3 and selects index 0 for
    // slot 24. RepeatPrevious then reproduces that effective upvote.
    DrivechainParentReplayState wrong_vector = state;
    BOOST_CHECK(!apply(make_block({make_explicit_m4({0})}, 101), 101, wrong_vector));
    BOOST_REQUIRE(apply(make_block({make_explicit_m4({0xff, 0})}, 101), 101, state));
    BOOST_CHECK_EQUAL(state.pending_withdrawals[0].votes, 2U);
    for (uint32_t height = 102; height <= 104; ++height) {
        BOOST_REQUIRE(apply(make_block({repeat_previous_m4()}, height), height, state));
    }
    BOOST_CHECK_EQUAL(state.pending_withdrawals[0].votes, threshold);

    // BIP300 requires strictly more than the threshold.
    DrivechainParentReplayState exactly_threshold = state;
    BOOST_CHECK(!apply(make_block({}, 105, &withdrawal), 105, exactly_threshold));

    BOOST_REQUIRE(apply(make_block({repeat_previous_m4()}, 105), 105, state));
    BOOST_CHECK_EQUAL(state.pending_withdrawals[0].votes, threshold + 1);

    // Any payout mutation changes the blinded M6id and therefore cannot spend
    // the approved bundle.
    Bitcoin::CMutableTransaction tampered = withdrawal;
    tampered.vout[1].nValue += 1;
    DrivechainParentReplayState tampered_state = state;
    BOOST_CHECK(!apply(make_block({}, 106, &tampered), 106, tampered_state));

    const Bitcoin::CBlock successful_block =
        make_block({}, 106, &withdrawal);
    std::vector<DrivechainSuccessfulWithdrawal> successful_withdrawals;
    BOOST_REQUIRE(apply(
        successful_block, 106, state, &successful_withdrawals));
    BOOST_CHECK(state.pending_withdrawals.empty());
    BOOST_REQUIRE(state.ctip.has_value());
    BOOST_CHECK_EQUAL(state.ctip->hash, withdrawal_tx.GetHash());
    BOOST_CHECK_EQUAL(state.ctip->n, 0U);
    BOOST_CHECK_EQUAL(state.ctip_value, 4000);
    BOOST_REQUIRE_EQUAL(successful_withdrawals.size(), 1U);
    BOOST_CHECK_EQUAL(successful_withdrawals[0].sidechain_slot, slot);
    BOOST_CHECK(successful_withdrawals[0].m6id == m6id);
    BOOST_CHECK_EQUAL(successful_withdrawals[0].block_height, 106U);
    BOOST_CHECK(successful_withdrawals[0].block_hash ==
                successful_block.GetHash());
}

BOOST_AUTO_TEST_CASE(drivechain_parent_replay_accepts_exact_native_elwd_m6)
{
    constexpr int slot{24};
    constexpr uint16_t max_age{10};
    constexpr uint16_t threshold{5};
    constexpr CAmount old_ctip_value{200000};
    constexpr CAmount burn_amount{100000};
    constexpr CAmount parent_fee{1000};
    constexpr CAmount successor_ctip_value{old_ctip_value - burn_amount};
    const uint256 required_proposal = uint256S(
        "3333333333333333333333333333333333333333333333333333333333333333");
    const uint256 elements_genesis = uint256S(
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    const uint256 burn_txid = uint256S(
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
    const Bitcoin::COutPoint initial_ctip(
        uint256S("4444444444444444444444444444444444444444444444444444444444444444"), 0);
    const CScript treasury_script = CScript()
        << OP_NOP5 << std::vector<unsigned char>{slot} << OP_TRUE;

    drivechain::NativeWithdrawal withdrawal;
    withdrawal.destination = CScript() << OP_0 << ParseHex(
        "606162636465666768696a6b6c6d6e6f70717273");
    withdrawal.burn_amount = burn_amount;
    withdrawal.parent_fee = parent_fee;
    withdrawal.payout_amount = burn_amount - parent_fee;

    drivechain::NativeWithdrawalM6 blinded;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        drivechain::BuildNativeWithdrawalM6(
            elements_genesis, slot, burn_txid, 7, withdrawal, blinded, &error),
        error);

    Bitcoin::CMutableTransaction actual = blinded.blinded_transaction;
    actual.vin.emplace_back(initial_ctip);
    actual.vout[0] = Bitcoin::CTxOut(successor_ctip_value, treasury_script);
    const Bitcoin::CTransaction actual_tx(actual);
    uint256 actual_m6id;
    uint8_t actual_slot{0};
    BOOST_REQUIRE_MESSAGE(
        ComputeDrivechainM6Id(
            actual_tx, old_ctip_value, actual_m6id, &actual_slot, &error),
        error);
    BOOST_CHECK_EQUAL(actual_slot, slot);
    BOOST_CHECK(actual_m6id == blinded.m6id);

    DrivechainParentReplayState state;
    state.active_proposal_hash = required_proposal;
    state.required_proposal_activated = true;
    state.required_activation_height = 1;
    state.ctip = initial_ctip;
    state.ctip_value = old_ctip_value;
    state.pending_withdrawals = {
        {blinded.m6id, 99, threshold + 1},
    };

    Bitcoin::CMutableTransaction coinbase;
    coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
    Bitcoin::CBlock block;
    block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(coinbase)));
    block.vtx.push_back(Bitcoin::MakeTransactionRef(actual));

    std::vector<DrivechainSuccessfulWithdrawal> successful;
    BOOST_REQUIRE_MESSAGE(
        ApplyDrivechainParentBlockState(
            block, 100, slot, required_proposal,
            max_age, threshold, max_age, threshold, max_age, threshold,
            state, nullptr, &error, &successful),
        error);
    BOOST_REQUIRE(state.ctip.has_value());
    BOOST_CHECK(state.ctip->hash == actual_tx.GetHash());
    BOOST_CHECK_EQUAL(state.ctip->n, 0U);
    BOOST_CHECK_EQUAL(state.ctip_value, successor_ctip_value);
    BOOST_CHECK(state.pending_withdrawals.empty());
    BOOST_REQUIRE_EQUAL(successful.size(), 1U);
    BOOST_CHECK_EQUAL(successful[0].sidechain_slot, slot);
    BOOST_CHECK(successful[0].m6id == blinded.m6id);
}

BOOST_AUTO_TEST_CASE(drivechain_parent_replay_sequences_usdd_root_and_native_elwd_m6)
{
    constexpr int slot{24};
    constexpr uint16_t max_age{10};
    constexpr uint16_t threshold{5};
    constexpr CAmount initial_ctip_value{10000};
    constexpr CAmount root_successor_value{8999};
    constexpr CAmount native_burn_amount{4000};
    constexpr CAmount native_parent_fee{100};
    constexpr CAmount native_successor_value{
        root_successor_value - native_burn_amount};
    const uint256 required_proposal = uint256S(
        "3333333333333333333333333333333333333333333333333333333333333333");
    const CScript treasury_script = CScript()
        << OP_NOP5 << std::vector<unsigned char>{slot} << OP_TRUE;

    // Canonical two-output USDD accumulator M6 fixed across Elements, Rust,
    // Solidity, and the enforcer. Its CTIP successor is always vout zero.
    const std::vector<unsigned char> root_raw = ParseHex(
        "02000000011f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504"
        "030201000700000000ffffffff02272300000000000004b401185101000000000000"
        "00296a27555344444d3601dd6833a6a2db112477ab453d2886af0c9154de56f5e"
        "8fc8717e3f7974186b36700000000");
    DataStream root_stream(root_raw);
    Bitcoin::CMutableTransaction root_m6;
    root_stream >> TX_WITH_WITNESS(root_m6);
    BOOST_REQUIRE(root_stream.empty());
    const Bitcoin::CTransaction root_tx(root_m6);
    BOOST_REQUIRE_EQUAL(root_tx.vin.size(), 1U);
    BOOST_REQUIRE_EQUAL(root_tx.vout.size(), 2U);
    BOOST_CHECK_EQUAL(root_tx.vout[0].nValue, root_successor_value);

    uint256 root_m6id;
    uint8_t root_slot{0};
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        ComputeDrivechainM6Id(
            root_tx, initial_ctip_value, root_m6id, &root_slot, &error),
        error);
    BOOST_CHECK_EQUAL(root_slot, slot);

    drivechain::NativeWithdrawal native_withdrawal;
    native_withdrawal.destination = CScript() << OP_0 << ParseHex(
        "606162636465666768696a6b6c6d6e6f70717273");
    native_withdrawal.burn_amount = native_burn_amount;
    native_withdrawal.parent_fee = native_parent_fee;
    native_withdrawal.payout_amount = native_burn_amount - native_parent_fee;

    drivechain::NativeWithdrawalM6 native_blinded;
    BOOST_REQUIRE_MESSAGE(
        drivechain::BuildNativeWithdrawalM6(
            uint256S(
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
            slot,
            uint256S(
                "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"),
            7, native_withdrawal, native_blinded, &error),
        error);
    Bitcoin::CMutableTransaction native_m6 = native_blinded.blinded_transaction;
    native_m6.vin.emplace_back(Bitcoin::COutPoint(root_tx.GetHash(), 0));
    native_m6.vout[0] = Bitcoin::CTxOut(native_successor_value, treasury_script);
    const Bitcoin::CTransaction native_tx(native_m6);
    uint256 native_m6id;
    uint8_t native_slot{0};
    BOOST_REQUIRE_MESSAGE(
        ComputeDrivechainM6Id(
            native_tx, root_successor_value, native_m6id, &native_slot, &error),
        error);
    BOOST_CHECK_EQUAL(native_slot, slot);
    BOOST_CHECK(native_m6id == native_blinded.m6id);

    DrivechainParentReplayState state;
    state.active_proposal_hash = required_proposal;
    state.required_proposal_activated = true;
    state.required_activation_height = 1;
    state.ctip = root_tx.vin[0].prevout;
    state.ctip_value = initial_ctip_value;
    state.pending_withdrawals = {
        {root_m6id, 99, threshold + 1},
        {native_m6id, 99, threshold + 1},
    };

    const auto make_block = [](const Bitcoin::CMutableTransaction& transaction,
                               const uint32_t nonce) {
        Bitcoin::CMutableTransaction coinbase;
        coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
        Bitcoin::CBlock block;
        block.nNonce = nonce;
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(coinbase)));
        block.vtx.push_back(Bitcoin::MakeTransactionRef(transaction));
        return block;
    };
    const auto apply = [&](const Bitcoin::CBlock& block,
                           const uint32_t height,
                           std::vector<DrivechainSuccessfulWithdrawal>& successful) {
        return ApplyDrivechainParentBlockState(
            block, height, slot, required_proposal,
            max_age, threshold, max_age, threshold, max_age, threshold,
            state, nullptr, &error, &successful);
    };

    std::vector<DrivechainSuccessfulWithdrawal> successful;
    BOOST_REQUIRE_MESSAGE(apply(make_block(root_m6, 100), 100, successful), error);
    BOOST_REQUIRE_EQUAL(successful.size(), 1U);
    BOOST_CHECK(successful[0].m6id == root_m6id);
    BOOST_REQUIRE(state.ctip.has_value());
    BOOST_CHECK(state.ctip->hash == root_tx.GetHash());
    BOOST_CHECK_EQUAL(state.ctip->n, 0U);
    BOOST_CHECK_EQUAL(state.ctip_value, root_successor_value);

    successful.clear();
    BOOST_REQUIRE_MESSAGE(apply(make_block(native_m6, 101), 101, successful), error);
    BOOST_REQUIRE_EQUAL(successful.size(), 1U);
    BOOST_CHECK(successful[0].m6id == native_m6id);
    BOOST_REQUIRE(state.ctip.has_value());
    BOOST_CHECK(state.ctip->hash == native_tx.GetHash());
    BOOST_CHECK_EQUAL(state.ctip->n, 0U);
    BOOST_CHECK_EQUAL(state.ctip_value, native_successor_value);
    BOOST_CHECK(state.pending_withdrawals.empty());
}

BOOST_AUTO_TEST_CASE(drivechain_m6id_matches_usdd_and_enforcer_vector)
{
    const std::vector<unsigned char> raw = ParseHex(
        "02000000011f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504"
        "030201000700000000ffffffff02272300000000000004b401185101000000000000"
        "00296a27555344444d3601dd6833a6a2db112477ab453d2886af0c9154de56f5e"
        "8fc8717e3f7974186b36700000000");
    DataStream stream(raw);
    Bitcoin::CMutableTransaction mutable_tx;
    stream >> TX_WITH_WITNESS(mutable_tx);
    BOOST_REQUIRE(stream.empty());
    const Bitcoin::CTransaction transaction(mutable_tx);
    BOOST_CHECK_EQUAL(
        transaction.GetHash(),
        uint256S("641c51cde9625227dd15e9f8482d0c62700b3824d7bef9f5e83a689120f8acca"));

    uint256 m6id;
    uint8_t slot{0};
    std::string error;
    BOOST_REQUIRE(ComputeDrivechainM6Id(
        transaction, /* previous_treasury_value= */ 10000,
        m6id, &slot, &error));
    BOOST_CHECK_EQUAL(slot, 24U);
    BOOST_CHECK_EQUAL(
        m6id,
        uint256S("9cf04f94106990b941c4cd437435e376bf4bbd08671ddd8549169f251af6b5a9"));
}

BOOST_AUTO_TEST_CASE(drivechain_betanet_treasury_replay_and_m6_id)
{
    constexpr int slot{24};
    const uint256 proposal = uint256S("3333333333333333333333333333333333333333333333333333333333333333");
    const Bitcoin::COutPoint initial(uint256S("4444444444444444444444444444444444444444444444444444444444444444"), 0);
    Bitcoin::CMutableTransaction withdrawal;
    withdrawal.vin.emplace_back(initial);
    withdrawal.vout.emplace_back(4000, CScript() << OP_NOP8 << std::vector<unsigned char>{slot} << OP_TRUE);
    withdrawal.vout.emplace_back(900, CScript() << OP_TRUE);
    uint256 id;
    uint8_t derived_slot{0};
    std::string error;
    BOOST_REQUIRE(ComputeDrivechainM6Id(Bitcoin::CTransaction(withdrawal), 5000, id,
                                      &derived_slot, &error, drivechain::TreasuryOpcode::NOP8));
    BOOST_CHECK_EQUAL(derived_slot, slot);
    uint256 wrong_id;
    BOOST_CHECK(!ComputeDrivechainM6Id(Bitcoin::CTransaction(withdrawal), 5000, wrong_id,
                                      nullptr, &error, drivechain::TreasuryOpcode::NOP5));
    BOOST_CHECK(wrong_id.IsNull());

    Bitcoin::CMutableTransaction coinbase;
    coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
    Bitcoin::CBlock block;
    block.vtx.push_back(Bitcoin::MakeTransactionRef(coinbase));
    block.vtx.push_back(Bitcoin::MakeTransactionRef(withdrawal));
    const auto initial_state = [&] {
        DrivechainParentReplayState state;
        state.active_proposal_hash = proposal;
        state.required_proposal_activated = true;
        state.required_activation_height = 1;
        state.ctip = initial;
        state.ctip_value = 5000;
        state.pending_withdrawals = {{id, 99, 13151}};
        return state;
    };
    const auto apply = [&](DrivechainParentReplayState& state, drivechain::TreasuryOpcode opcode,
                           std::vector<DrivechainSuccessfulWithdrawal>& successes) {
        return ApplyDrivechainParentBlockState(block, 100, slot, proposal,
            2016, 1008, 26300, 13150, 26300, 13150,
            state, nullptr, &error, &successes, nullptr, opcode);
    };
    std::vector<DrivechainSuccessfulWithdrawal> successes;
    auto state = initial_state();
    BOOST_REQUIRE(apply(state, drivechain::TreasuryOpcode::NOP8, successes));
    BOOST_CHECK_EQUAL(state.ctip_value, 4000);
    BOOST_CHECK(state.ctip == Bitcoin::COutPoint(withdrawal.GetHash(), 0));
    BOOST_REQUIRE_EQUAL(successes.size(), 1U);
    BOOST_CHECK(state.pending_withdrawals.empty());

    state = initial_state();
    BOOST_CHECK(!apply(state, drivechain::TreasuryOpcode::NOP5, successes));
    BOOST_CHECK(successes.empty());
    state = initial_state();
    state.pending_withdrawals[0].votes = 13150;
    BOOST_CHECK(!apply(state, drivechain::TreasuryOpcode::NOP8, successes));
    BOOST_CHECK(successes.empty());
    state = initial_state();
    state.pending_withdrawals.clear();
    BOOST_CHECK(!apply(state, drivechain::TreasuryOpcode::NOP8, successes));
    BOOST_CHECK(successes.empty());
}

BOOST_AUTO_TEST_CASE(drivechain_betanet_chained_deposits)
{
    constexpr int slot{24};
    const uint256 proposal = uint256S("3333333333333333333333333333333333333333333333333333333333333333");
    const Bitcoin::COutPoint initial(uint256S("4444444444444444444444444444444444444444444444444444444444444444"), 0);
    const std::vector<unsigned char> address{'b', 'e', 't', 'a'};
    const auto initial_state = [&] {
        DrivechainParentReplayState state;
        state.active_proposal_hash = proposal;
        state.required_proposal_activated = true;
        state.required_activation_height = 1;
        state.ctip = initial;
        state.ctip_value = 5000;
        return state;
    };
    Bitcoin::CMutableTransaction coinbase;
    coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
    for (const opcodetype opcode : {OP_NOP8, OP_NOP5}) {
        const CScript treasury = CScript() << opcode << std::vector<unsigned char>{slot} << OP_TRUE;
        Bitcoin::CMutableTransaction first;
        first.vin.emplace_back(initial);
        first.vout.emplace_back(6000, treasury);
        first.vout.emplace_back(0, CScript() << OP_RETURN << address);
        Bitcoin::CMutableTransaction second;
        second.vin.emplace_back(Bitcoin::COutPoint(first.GetHash(), 0));
        second.vout.emplace_back(7500, treasury);
        second.vout.emplace_back(0, CScript() << OP_RETURN << address);
        Bitcoin::CBlock block;
        block.vtx = {Bitcoin::MakeTransactionRef(coinbase), Bitcoin::MakeTransactionRef(first),
                     Bitcoin::MakeTransactionRef(second)};
        auto state = initial_state();
        std::vector<DrivechainMintableDeposit> deposits;
        std::string error;
        const bool accepted = ApplyDrivechainParentBlockState(block, 100, slot, proposal,
            2016, 1008, 26300, 13150, 26300, 13150, state, &deposits, &error,
            nullptr, nullptr, drivechain::TreasuryOpcode::NOP8);
        if (opcode == OP_NOP5) {
            BOOST_CHECK(!accepted);
            BOOST_CHECK(deposits.empty());
            continue;
        }
        BOOST_REQUIRE_MESSAGE(accepted, error);
        BOOST_REQUIRE_EQUAL(deposits.size(), 2U);
        BOOST_CHECK_EQUAL(deposits[0].value, 1000);
        BOOST_CHECK_EQUAL(deposits[1].value, 1500);
        BOOST_CHECK(deposits[0].outpoint == Bitcoin::COutPoint(first.GetHash(), 0));
        BOOST_CHECK(deposits[1].outpoint == Bitcoin::COutPoint(second.GetHash(), 0));
        for (const auto& deposit : deposits) {
            BOOST_CHECK(deposit.address == address);
            BOOST_CHECK(deposit.block_hash == block.GetHash());
            BOOST_CHECK_EQUAL(deposit.block_height, 100U);
        }
        BOOST_CHECK_EQUAL(state.ctip_value, 7500);
        BOOST_CHECK(state.ctip == deposits[1].outpoint);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_parent_replay_rejects_two_configured_slot_m6s_in_one_block)
{
    constexpr int slot{24};
    constexpr uint16_t max_age{10};
    constexpr uint16_t threshold{5};
    const uint256 required_proposal = uint256S(
        "3333333333333333333333333333333333333333333333333333333333333333");
    const Bitcoin::COutPoint initial_ctip(
        uint256S("4444444444444444444444444444444444444444444444444444444444444444"), 0);
    const CScript treasury_script = CScript()
        << OP_NOP5 << std::vector<unsigned char>{slot} << OP_TRUE;

    Bitcoin::CMutableTransaction first;
    first.vin.emplace_back(initial_ctip);
    first.vout.emplace_back(4000, treasury_script);
    first.vout.emplace_back(999, CScript() << OP_TRUE);
    const Bitcoin::CTransaction first_tx(first);

    Bitcoin::CMutableTransaction second;
    second.vin.emplace_back(Bitcoin::COutPoint(first_tx.GetHash(), 0));
    second.vout.emplace_back(3000, treasury_script);
    second.vout.emplace_back(998, CScript() << OP_TRUE);
    const Bitcoin::CTransaction second_tx(second);

    uint256 first_m6id;
    uint256 second_m6id;
    std::string error;
    BOOST_REQUIRE(ComputeDrivechainM6Id(first_tx, 5000, first_m6id, nullptr, &error));
    BOOST_REQUIRE(ComputeDrivechainM6Id(second_tx, 4000, second_m6id, nullptr, &error));
    BOOST_REQUIRE(first_m6id != second_m6id);

    DrivechainParentReplayState state;
    state.active_proposal_hash = required_proposal;
    state.required_proposal_activated = true;
    state.required_activation_height = 1;
    state.ctip = initial_ctip;
    state.ctip_value = 5000;
    state.pending_withdrawals = {
        {first_m6id, 99, threshold + 1},
        {second_m6id, 99, threshold + 1},
    };

    Bitcoin::CMutableTransaction coinbase;
    coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
    Bitcoin::CBlock block;
    block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(coinbase)));
    block.vtx.push_back(Bitcoin::MakeTransactionRef(first));
    block.vtx.push_back(Bitcoin::MakeTransactionRef(second));

    BOOST_CHECK(!ApplyDrivechainParentBlockState(
        block, 100, slot, required_proposal,
        max_age, threshold, max_age, threshold, max_age, threshold,
        state, nullptr, &error));
    BOOST_CHECK(error.find("multiple successful M6 withdrawals") != std::string::npos);

    DrivechainParentReplayState one_state;
    one_state.active_proposal_hash = required_proposal;
    one_state.required_proposal_activated = true;
    one_state.required_activation_height = 1;
    one_state.ctip = initial_ctip;
    one_state.ctip_value = 5000;
    one_state.pending_withdrawals = {{first_m6id, 99, threshold + 1}};
    Bitcoin::CBlock one_block;
    one_block.vtx.push_back(block.vtx[0]);
    one_block.vtx.push_back(block.vtx[1]);
    BOOST_CHECK(ApplyDrivechainParentBlockState(
        one_block, 100, slot, required_proposal,
        max_age, threshold, max_age, threshold, max_age, threshold,
        one_state, nullptr, &error));
}

BOOST_AUTO_TEST_CASE(drivechain_betanet_sequential_withdrawals)
{
    constexpr int slot{24};
    constexpr uint32_t height{26399};
    const uint256 proposal = uint256S("33");
    const Bitcoin::COutPoint initial_ctip(uint256S("44"), 0);
    const CScript treasury = CScript() << OP_NOP8 << std::vector<unsigned char>{slot} << OP_TRUE;
    Bitcoin::CMutableTransaction first;
    first.vin.emplace_back(initial_ctip);
    first.vout.emplace_back(4000, treasury);
    first.vout.emplace_back(999, CScript() << OP_TRUE);
    Bitcoin::CMutableTransaction second;
    second.vin.emplace_back(Bitcoin::COutPoint(first.GetHash(), 0));
    second.vout.emplace_back(3000, treasury);
    second.vout.emplace_back(998, CScript() << OP_TRUE);
    uint256 first_id, second_id;
    std::string error;
    BOOST_REQUIRE(ComputeDrivechainM6Id(Bitcoin::CTransaction(first), 5000, first_id,
        nullptr, &error, drivechain::TreasuryOpcode::NOP8));
    BOOST_REQUIRE(ComputeDrivechainM6Id(Bitcoin::CTransaction(second), 4000, second_id,
        nullptr, &error, drivechain::TreasuryOpcode::NOP8));
    BOOST_REQUIRE(first_id != second_id);
    DrivechainParentReplayState initial;
    initial.active_proposal_hash = proposal;
    initial.required_proposal_activated = true;
    initial.required_activation_height = 1;
    initial.required_activation_block_hash = uint256S("77");
    initial.ctip = initial_ctip;
    initial.ctip_value = 5000;
    initial.pending_withdrawals = {{first_id, 99, 13151}, {second_id, 99, 13151}};
    Bitcoin::CMutableTransaction coinbase;
    coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
    Bitcoin::CBlock block;
    block.vtx = {Bitcoin::MakeTransactionRef(coinbase), Bitcoin::MakeTransactionRef(first),
                 Bitcoin::MakeTransactionRef(second)};
    std::vector<DrivechainSuccessfulWithdrawal> successes;
    auto apply = [&](const Bitcoin::CBlock& candidate, DrivechainParentReplayState& state,
                     DrivechainM6ReplayRule rule = DrivechainM6ReplayRule::SEQUENTIAL_M6) {
        return ApplyDrivechainParentBlockState(candidate, height, slot, proposal,
            2016, 1008, 26300, 13150, 26300, 13150, state, nullptr, &error,
            &successes, nullptr, drivechain::TreasuryOpcode::NOP8, rule);
    };
    auto state = initial;
    BOOST_REQUIRE_MESSAGE(apply(block, state), error);
    BOOST_REQUIRE_EQUAL(successes.size(), 2U);
    BOOST_CHECK(successes[0].m6id == first_id);
    BOOST_CHECK(successes[1].m6id == second_id);
    BOOST_CHECK(state.ctip == Bitcoin::COutPoint(second.GetHash(), 0));
    BOOST_CHECK_EQUAL(state.ctip_value, 3000);
    BOOST_CHECK(state.pending_withdrawals.empty());

    std::vector<unsigned char> m3 = ParseHex("d45aa943");
    m3.push_back(slot);
    m3.insert(m3.end(), first_id.begin(), first_id.end());
    auto proposal_coinbase = coinbase;
    proposal_coinbase.vout.emplace_back(0, CScript() << OP_RETURN << m3);
    Bitcoin::CBlock reproposal_block;
    reproposal_block.vtx = {Bitcoin::MakeTransactionRef(proposal_coinbase)};
    auto reproposed = state;
    std::vector<DrivechainWithdrawalProposalIdentity> reproposals;
    BOOST_REQUIRE(ApplyDrivechainParentBlockState(reproposal_block, height + 1, slot, proposal,
        2016, 1008, 26300, 13150, 26300, 13150, reproposed, nullptr, &error,
        nullptr, &reproposals, drivechain::TreasuryOpcode::NOP8,
        DrivechainM6ReplayRule::SEQUENTIAL_M6));
    BOOST_REQUIRE_EQUAL(reproposals.size(), 1U);
    BOOST_CHECK(reproposals[0].m6id == first_id);
    BOOST_REQUIRE_EQUAL(reproposed.pending_withdrawals.size(), 1U);
    BOOST_CHECK_EQUAL(reproposed.pending_withdrawals.front().votes, 1U);
    auto duplicate_proposal = reproposed;
    BOOST_CHECK(!ApplyDrivechainParentBlockState(reproposal_block, height + 2, slot, proposal,
        2016, 1008, 26300, 13150, 26300, 13150, duplicate_proposal, nullptr, &error,
        nullptr, nullptr, drivechain::TreasuryOpcode::NOP8,
        DrivechainM6ReplayRule::SEQUENTIAL_M6));

    const fs::path path = m_args.GetDataDirBase() / "betanet_sequential_replay";
    const uint256 identity = uint256S("55");
    DrivechainParentReplayTip previous;
    previous.height = height - 1;
    previous.hash = uint256S("66");
    previous.state = initial;
    DrivechainParentReplayTip next;
    next.height = height;
    next.hash = block.GetHash();
    next.state = state;
    {
        DrivechainParentReplayStore store(path, 1 << 20, /*wipe=*/true);
        BOOST_REQUIRE_MESSAGE(store.Reset(identity, previous, &error), error);
        BOOST_REQUIRE_MESSAGE(store.Append(previous, next, {}, std::nullopt, successes, &error), error);
    }
    {
        DrivechainParentReplayStore store(path, 1 << 20, /*wipe=*/false);
        DrivechainParentReplayTip loaded;
        BOOST_REQUIRE(store.Load(identity, loaded, &error) == DrivechainReplayStoreLoadStatus::LOADED);
        BOOST_CHECK(loaded.state.ctip == next.state.ctip);
        BOOST_CHECK_EQUAL(loaded.state.ctip_value, 3000);
        for (const auto& id : {first_id, second_id}) {
            DrivechainSuccessfulWithdrawal found;
            BOOST_REQUIRE(store.ReadSuccessfulWithdrawal(slot, id, found, &error) ==
                DrivechainReplayStoreReadStatus::FOUND);
            BOOST_CHECK_EQUAL(found.block_height, height);
            BOOST_CHECK(found.block_hash == block.GetHash());
        }
        BOOST_REQUIRE(store.Reset(identity, previous, &error));
        for (const auto& id : {first_id, second_id}) {
            DrivechainSuccessfulWithdrawal found;
            BOOST_CHECK(store.ReadSuccessfulWithdrawal(slot, id, found, &error) ==
                DrivechainReplayStoreReadStatus::NOT_FOUND);
        }
    }

    state = initial;
    BOOST_CHECK(!apply(block, state, DrivechainM6ReplayRule::SINGLE_CONFIGURED_SLOT_M6));
    BOOST_CHECK(successes.empty());
    state = initial;
    state.pending_withdrawals.back().votes = 13150;
    BOOST_CHECK(!apply(block, state));
    BOOST_CHECK(successes.empty());
    state = initial;
    state.pending_withdrawals.pop_back();
    BOOST_CHECK(!apply(block, state));
    BOOST_CHECK(successes.empty());
    auto reversed = block;
    std::swap(reversed.vtx[1], reversed.vtx[2]);
    state = initial;
    BOOST_CHECK(!apply(reversed, state));
    BOOST_CHECK(successes.empty());
    state = initial;
    BOOST_CHECK(!apply(block, state, static_cast<DrivechainM6ReplayRule>(255)));
    BOOST_CHECK(state.ctip == initial.ctip);
    BOOST_CHECK_EQUAL(state.ctip_value, initial.ctip_value);
}

BOOST_AUTO_TEST_CASE(betanet_reproposal_store_preserves_payment_occurrences)
{
    const fs::path path = m_args.GetDataDirBase() / "betanet_reproposal_replay";
    const uint256 identity = uint256S("81");
    const uint256 m6id = uint256S("82");
    constexpr auto rule = DrivechainWithdrawalHistoryRule::ALLOW_REPROPOSAL;
    DrivechainParentReplayTip seed;
    seed.hash = uint256S("83");
    auto first = seed;
    first.height = 1;
    first.hash = uint256S("84");
    auto proposal = first;
    proposal.height = 2;
    proposal.hash = uint256S("85");
    auto second = proposal;
    second.height = 3;
    second.hash = uint256S("86");
    const DrivechainSuccessfulWithdrawal first_payment{24, m6id, 1, first.hash};
    const DrivechainSuccessfulWithdrawal second_payment{24, m6id, 3, second.hash};
    std::string error;
    {
        DrivechainParentReplayStore store(path, 1 << 20, true, rule);
        BOOST_REQUIRE(store.Reset(identity, seed, &error));
        BOOST_REQUIRE(store.Append(seed, first, {}, std::nullopt, {first_payment}, &error));
        // Store fixtures exercise persistence only; parent consensus must
        // authenticate the intervening proposal/votes before calling Append.
        BOOST_REQUIRE(store.Append(first, proposal, {}, std::nullopt, {},
            {DrivechainWithdrawalProposalIdentity{24, m6id}}, &error));
        BOOST_CHECK(!store.Append(proposal, second, {}, std::nullopt,
            {second_payment, second_payment}, &error));
        BOOST_REQUIRE(store.Append(proposal, second, {}, std::nullopt, {second_payment}, &error));
        BOOST_CHECK(!store.Append(proposal, second, {}, std::nullopt, {second_payment}, &error));
    }
    {
        DrivechainParentReplayStore store(path, 1 << 20, false, rule);
        DrivechainParentReplayTip loaded;
        BOOST_REQUIRE(store.Load(identity, loaded, &error) == DrivechainReplayStoreLoadStatus::LOADED);
        BOOST_CHECK(loaded.hash == second.hash);
        DrivechainSuccessfulWithdrawal found;
        BOOST_REQUIRE(store.ReadSuccessfulWithdrawal(24, m6id, found, &error) ==
            DrivechainReplayStoreReadStatus::FOUND);
        BOOST_CHECK_EQUAL(found.block_height, 1U);
        BOOST_CHECK(found.block_hash == first.hash);
        for (const auto& payment : {first_payment, second_payment}) {
            BOOST_REQUIRE(store.ReadSuccessfulWithdrawalAtHeight(24, m6id,
                payment.block_height, found, &error) == DrivechainReplayStoreReadStatus::FOUND);
            BOOST_CHECK(found.block_hash == payment.block_hash);
        }
        BOOST_CHECK(store.ReadSuccessfulWithdrawalAtHeight(24, m6id, 2, found, &error) ==
            DrivechainReplayStoreReadStatus::NOT_FOUND);
        BOOST_CHECK(store.ReadSuccessfulWithdrawalAtHeight(25, m6id, 1, found, &error) ==
            DrivechainReplayStoreReadStatus::NOT_FOUND);
    }
    {
        DrivechainParentReplayStore legacy(path, 1 << 20, false);
        DrivechainParentReplayTip loaded;
        BOOST_CHECK(legacy.Load(identity, loaded, &error) == DrivechainReplayStoreLoadStatus::IDENTITY_MISMATCH);
        auto next = second;
        ++next.height;
        next.hash = uint256S("87");
        BOOST_CHECK(!legacy.Append(second, next, {}, std::nullopt, &error));
    }
    {
        DrivechainParentReplayStore store(path, 1 << 20, false, rule);
        BOOST_REQUIRE(store.Reset(identity, seed, &error));
        DrivechainSuccessfulWithdrawal found;
        BOOST_CHECK(store.ReadSuccessfulWithdrawal(24, m6id, found, &error) ==
            DrivechainReplayStoreReadStatus::NOT_FOUND);
        for (const uint32_t height : {1U, 3U}) {
            BOOST_CHECK(store.ReadSuccessfulWithdrawalAtHeight(24, m6id, height, found, &error) ==
                DrivechainReplayStoreReadStatus::NOT_FOUND);
        }
    }
    BOOST_CHECK_THROW(DrivechainParentReplayStore(path, 1 << 20, false,
        static_cast<DrivechainWithdrawalHistoryRule>(255)), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(drivechain_activation_block_deposit_is_mintable)
{
    constexpr int slot{24};
    constexpr uint16_t max_age{10};
    constexpr uint16_t threshold{5};
    constexpr uint32_t activation_height{7};
    const uint256 old_proposal = uint256S(
        "1111111111111111111111111111111111111111111111111111111111111111");
    const uint256 required_proposal = uint256S(
        "3333333333333333333333333333333333333333333333333333333333333333");
    const Bitcoin::COutPoint initial_ctip(
        uint256S("4444444444444444444444444444444444444444444444444444444444444444"), 0);

    std::vector<unsigned char> m2 = ParseHex("d6e1c5df");
    m2.push_back(slot);
    m2.insert(m2.end(), required_proposal.begin(), required_proposal.end());
    Bitcoin::CMutableTransaction coinbase;
    coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
    coinbase.vout.emplace_back(0, CScript() << OP_RETURN << m2);

    const CScript treasury_script = CScript()
        << OP_NOP5 << std::vector<unsigned char>{slot} << OP_TRUE;
    const std::vector<unsigned char> address{'e', 'l', 'e', 'm', 'e', 'n', 't', 's'};
    Bitcoin::CMutableTransaction deposit;
    deposit.vin.emplace_back(initial_ctip);
    deposit.vout.emplace_back(6000, treasury_script);
    deposit.vout.emplace_back(0, CScript() << OP_RETURN << address);

    Bitcoin::CBlock block;
    block.nNonce = activation_height;
    block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(coinbase)));
    block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(deposit)));

    DrivechainParentReplayState state;
    state.active_proposal_hash = old_proposal;
    state.pending_proposals.emplace(
        required_proposal, DrivechainPendingProposal{/* proposal_height= */ 1, /* votes= */ 5});
    state.ctip = initial_ctip;
    state.ctip_value = 5000;
    std::vector<DrivechainMintableDeposit> deposits;
    std::string error;
    BOOST_CHECK(ApplyDrivechainParentBlockState(
        block, activation_height, slot, required_proposal,
        max_age, threshold, max_age, threshold,
        /* withdrawal_max_age= */ 10, /* withdrawal_threshold= */ 5,
        state, &deposits, &error));
    BOOST_CHECK(state.required_proposal_activated);
    BOOST_CHECK_EQUAL(state.required_activation_height, activation_height);
    BOOST_CHECK_EQUAL(state.required_activation_block_hash, block.GetHash());
    BOOST_CHECK_EQUAL(state.active_proposal_hash, required_proposal);
    BOOST_REQUIRE_EQUAL(deposits.size(), 1U);
    BOOST_CHECK_EQUAL(deposits[0].value, 1000);
    BOOST_CHECK(deposits[0].address == address);
    BOOST_CHECK_EQUAL(deposits[0].block_height, activation_height);
}

BOOST_AUTO_TEST_CASE(native_deposit_fee_destination_codec)
{
    const auto address = EncodeDestination(WitnessV0KeyHash(uint160{ParseHex(std::string(40, '1'))}));
    const auto expected = GetScriptForDestination(DecodeDestination(address));
    for (const CAmount fee : {CAmount{0}, CAmount{1}, CAmount{1000}, MAX_MONEY}) {
        const auto payload = EncodeDrivechainDepositDestination(address, fee);
        CScript script;
        CAmount decoded{-1};
        BOOST_REQUIRE(DecodeDrivechainDepositDestination(payload, script, decoded));
        BOOST_CHECK(script == expected);
        BOOST_CHECK_EQUAL(decoded, fee);
        if (!fee) BOOST_CHECK_EQUAL(payload, address);
    }
    for (const auto& prefix : {"dcfee1:0:", "dcfee1:01:", "dcfee1:+1:", "dcfee1:-1:",
             "dcfee1: 1:", "dcfee1:1.0:", "dcfee1:2100000000000001:",
             "dcfee1:9223372036854775808:", "dcfee2:1000:", "dcfee1::"}) {
        CScript script;
        CAmount fee{42};
        BOOST_CHECK(!DecodeDrivechainDepositDestination(std::string(prefix) + address, script, fee));
        BOOST_CHECK(script.empty());
        BOOST_CHECK_EQUAL(fee, 0);
    }
    CScript script;
    CAmount fee{0};
    BOOST_CHECK(!DecodeDrivechainDepositDestination("dcfee1:1:not-an-address", script, fee));
    BOOST_CHECK(!DecodeDrivechainDepositDestination(std::string(129, 'x'), script, fee));
    BOOST_CHECK_THROW(EncodeDrivechainDepositDestination(address, -1), std::invalid_argument);
    BOOST_CHECK_THROW(EncodeDrivechainDepositDestination(address, MAX_MONEY + 1), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(native_deposit_committed_fee_outputs)
{
    const auto address = EncodeDestination(WitnessV0KeyHash(uint160{ParseHex(std::string(40, '2'))}));
    const auto payload = EncodeDrivechainDepositDestination(address, 1000);
    const DrivechainMintableDeposit deposit{Bitcoin::COutPoint(uint256S("dd"), 2), uint256S("ee"),
        1, 100000, {payload.begin(), payload.end()}};
    const auto tx = CreateNativeDrivechainDeposit(deposit);
    std::string error;
    BOOST_REQUIRE(CheckDrivechainDepositOutputs(*tx, 0, error));
    BOOST_CHECK_EQUAL(tx->vout[0].nValue.GetAmount(), 99000);
    BOOST_CHECK_EQUAL(tx->vout[1].nValue.GetAmount(), 1000);
    BOOST_CHECK(tx->vout[1].IsFee());
    BOOST_CHECK(!IsCanonicalFeeFreeDrivechainDeposit(*tx));
    const auto key = GetPeginSpentKey(tx->witness.vtxinwit[0].m_pegin_witness, tx->vin[0].prevout);
    for (unsigned mutation = 0; mutation < 13; ++mutation) {
        CMutableTransaction changed(*tx);
        switch (mutation) {
        case 0: changed.vout[0].nValue = CConfidentialValue(98999); changed.vout[1].nValue = CConfidentialValue(1001); break;
        case 1: changed.vout[0].nValue = CConfidentialValue(99001); changed.vout[1].nValue = CConfidentialValue(999); break;
        case 2: changed.vout[1].nValue = CConfidentialValue(999); break;
        case 3: changed.vout[1].nValue = CConfidentialValue(1001); break;
        case 4: changed.vout[0].scriptPubKey = CScript() << OP_TRUE; break;
        case 5: changed.vout[1].scriptPubKey = CScript() << OP_TRUE; break;
        case 6: changed.vout.push_back(changed.vout[1]); break;
        case 7: changed.vout.pop_back(); break;
        case 8: changed.vin.emplace_back(COutPoint(Txid::FromUint256(uint256S("cc")), 0)); changed.witness.vtxinwit.resize(2); break;
        case 9: changed.vout[1].nAsset = CConfidentialAsset(CAsset(uint256S("aa"))); break;
        case 10: changed.vout[1].nValue.vchCommitment.assign(33, 8); break;
        case 11: changed.vout[1].nNonce.vchCommitment.assign(33, 2); break;
        case 12: changed.witness.vtxinwit[0].m_pegin_witness.stack[7] = {address.begin(), address.end()}; break;
        }
        changed.witness.vtxoutwit.resize(changed.vout.size());
        BOOST_CHECK_MESSAGE(!CheckDrivechainDepositOutputs(CTransaction(changed), 0, error), mutation);
        BOOST_CHECK(GetPeginSpentKey(changed.witness.vtxinwit[0].m_pegin_witness, changed.vin[0].prevout) == key);
    }
    CMutableTransaction reordered(*tx);
    std::swap(reordered.vout[0], reordered.vout[1]);
    BOOST_CHECK(CheckDrivechainDepositOutputs(CTransaction(reordered), 0, error));
    auto too_small = deposit;
    too_small.value = 1000;
    BOOST_CHECK_THROW(CreateNativeDrivechainDeposit(too_small), std::invalid_argument);
    auto legacy = deposit;
    legacy.address = {address.begin(), address.end()};
    const auto free_tx = CreateNativeDrivechainDeposit(legacy);
    BOOST_CHECK(IsCanonicalFeeFreeDrivechainDeposit(*free_tx));
    BOOST_CHECK_EQUAL(free_tx->vout[0].nValue.GetAmount(), deposit.value);
    BOOST_CHECK(GetPeginSpentKey(free_tx->witness.vtxinwit[0].m_pegin_witness, free_tx->vin[0].prevout) == key);
}

BOOST_AUTO_TEST_CASE(parent_deposit_scan_paging_restart_and_corruption)
{
    const auto path = m_args.GetDataDirBase() / "deposit_scan";
    const auto id = uint256S("01");
    DrivechainParentReplayTip tip;
    tip.hash = uint256S("02");
    std::string error;
    {
        DrivechainParentReplayStore store(path, 1 << 20, true);
        BOOST_REQUIRE(store.Reset(id, tip, &error));
    }
    std::vector<DrivechainMintableDeposit> records;
    // Exercise the on-disk reader with bounded synthetic records, not an
    // authenticated parent-chain or minting fixture.
    {
        CDBWrapper db(DBParams{.path=path, .cache_bytes=1 << 20});
        for (unsigned i = 1; i <= 3; ++i) {
            auto record = DrivechainMintableDeposit{Bitcoin::COutPoint(uint256S(strprintf("%02x", i)), 0),
                uint256S("03"), 1, 1000, {'x'}};
            records.push_back(record);
            db.Write(std::make_pair(drivechain::DB_REPLAY_DEPOSIT, record.outpoint), record);
        }
    }
    std::optional<Bitcoin::COutPoint> cursor;
    std::vector<DrivechainMintableDeposit> page;
    for (unsigned i = 0; i < 3; ++i) {
        DrivechainParentReplayStore reopened(path, 1 << 20, false);
        std::optional<Bitcoin::COutPoint> next;
        BOOST_REQUIRE(reopened.ListDeposits(cursor, 1, page, next, &error));
        BOOST_REQUIRE_EQUAL(page.size(), 1U);
        BOOST_CHECK(page[0].outpoint == records[i].outpoint);
        BOOST_CHECK_EQUAL(next.has_value(), i < 2);
        cursor = next;
    }
    {
        CDBWrapper db(DBParams{.path=path, .cache_bytes=1 << 20});
        auto bad = records[1]; bad.value = -1;
        db.Write(std::make_pair(drivechain::DB_REPLAY_DEPOSIT, bad.outpoint), bad);
    }
    DrivechainParentReplayStore reopened(path, 1 << 20, false);
    BOOST_CHECK(!reopened.ListDeposits({}, 64, page, cursor, &error));
    BOOST_CHECK(page.empty());
    BOOST_CHECK(!cursor);
    BOOST_CHECK(!reopened.ListDeposits({}, 0, page, cursor, &error));
    BOOST_CHECK(!reopened.ListDeposits({}, 65, page, cursor, &error));
}

BOOST_AUTO_TEST_CASE(drivechain_deposit_outputs_are_bound_to_mainchain_address)
{
    const COutPoint deposit_outpoint(
        Txid::FromUint256(uint256S("00000000000000000000000000000000000000000000000000000000000000dd")), 2);
    const uint256 block_hash = uint256S("00000000000000000000000000000000000000000000000000000000000000ee");
    const CAmount deposit_value = 100000;
    const CAmount fee = 1000;
    const uint160 destination_hash{ParseHex("3412000000000000000000000000000000000000")};
    const CTxDestination destination = WitnessV0KeyHash(destination_hash);
    const std::string address_string = EncodeDestination(destination);
    const std::vector<unsigned char> address(address_string.begin(), address_string.end());

    CMutableTransaction mtx;
    mtx.version = 2;
    CTxIn pegin_input(deposit_outpoint, CScript(), CTxIn::SEQUENCE_FINAL);
    pegin_input.m_is_pegin = true;
    mtx.vin.push_back(pegin_input);
    mtx.vout.push_back(CTxOut(
        Params().GetConsensus().pegged_asset,
        deposit_value,
        GetScriptForDestination(destination)));
    mtx.witness.vtxinwit.resize(1);
    mtx.witness.vtxoutwit.resize(mtx.vout.size());
    mtx.witness.vtxinwit[0].m_pegin_witness = CreateDrivechainDepositPeginWitness(
        deposit_value,
        Params().GetConsensus().pegged_asset,
        Params().ParentGenesisBlockHash(),
        CScript() << OP_TRUE,
        deposit_outpoint,
        block_hash,
        address);

    std::string err;
    BOOST_CHECK(CheckDrivechainDepositOutputs(CTransaction(mtx), 0, err));
    BOOST_CHECK(IsCanonicalFeeFreeDrivechainDeposit(CTransaction(mtx)));

    for (unsigned kind = 0; kind < 7; ++kind) {
        CMutableTransaction malformed = mtx;
        switch (kind) {
        case 0: malformed.vin.clear(); malformed.witness.vtxinwit.clear(); break;
        case 1: malformed.vout.clear(); malformed.witness.vtxoutwit.clear(); break;
        case 2: malformed.witness.vtxinwit.clear(); break;
        case 3: malformed.vin[0].m_is_pegin = false; break;
        case 4: malformed.vin[0].assetIssuance.nAmount = CConfidentialValue(1); break;
        case 5: malformed.witness.vtxinwit[0].m_pegin_witness.stack.clear(); break;
        case 6: malformed.vin.resize(2); malformed.witness.vtxinwit.resize(2); break;
        }
        BOOST_CHECK(!IsCanonicalFeeFreeDrivechainDeposit(CTransaction(malformed)));
    }

    for (unsigned kind = 0; kind < 7; ++kind) {
        CMutableTransaction changed = mtx;
        std::string expected = "The committed deposit recipient must receive the exact explicit pegged-asset amount.";
        switch (kind) {
        case 0: changed.vout[0].nAsset.vchCommitment.assign(33, 0x0a); break;
        case 1: changed.vout[0].nValue.vchCommitment.assign(33, 0x08); break;
        case 2: changed.vout[0].nNonce.vchCommitment.assign(33, 0x02); break;
        case 3:
            changed.vout.push_back(changed.vout[0]);
            expected = "Drivechain deposit transaction must contain exactly one recipient output.";
            break;
        case 4:
            changed.vin[0].assetIssuance.nAmount = CConfidentialValue(1);
            expected = "Drivechain deposit inputs cannot contain an asset issuance.";
            break;
        case 5:
            changed.witness.vtxinwit[0].m_pegin_witness.stack[7] = {'?'};
            expected = "BIP300 deposit commits to an invalid Elements destination address.";
            break;
        case 6:
            changed.witness.vtxinwit[0].m_pegin_witness.stack[3] = {OP_FALSE};
            expected = "Drivechain deposit claim script must be OP_TRUE.";
            break;
        }
        BOOST_CHECK(!CheckDrivechainDepositOutputs(CTransaction(changed), 0, err));
        BOOST_CHECK_EQUAL(err, expected);
    }

    CMutableTransaction deducted = mtx;
    deducted.vout[0].nValue = CConfidentialValue(deposit_value - fee);
    deducted.vout.push_back(CTxOut(Params().GetConsensus().pegged_asset, fee, CScript()));
    deducted.witness.vtxoutwit.resize(deducted.vout.size());
    BOOST_CHECK(!CheckDrivechainDepositOutputs(CTransaction(deducted), 0, err));
    BOOST_CHECK(!IsCanonicalFeeFreeDrivechainDeposit(CTransaction(deducted)));

    CMutableTransaction redirected = mtx;
    redirected.vout[0].scriptPubKey = CScript() << OP_TRUE;
    BOOST_CHECK(!CheckDrivechainDepositOutputs(CTransaction(redirected), 0, err));

    CMutableTransaction inflated = mtx;
    inflated.vout[0].nValue = CConfidentialValue(deposit_value + 1);
    BOOST_CHECK(!CheckDrivechainDepositOutputs(CTransaction(inflated), 0, err));

    CMutableTransaction extra_input = mtx;
    extra_input.vin.push_back(CTxIn(COutPoint(Txid::FromUint256(uint256::ONE), 0)));
    extra_input.witness.vtxinwit.resize(2);
    BOOST_CHECK(CheckDrivechainDepositOutputs(CTransaction(extra_input), 0, err));
    BOOST_CHECK(!IsCanonicalFeeFreeDrivechainDeposit(CTransaction(extra_input)));

    CMutableTransaction extra_output = mtx;
    extra_output.vout.emplace_back(Params().GetConsensus().pegged_asset, 0, CScript() << OP_RETURN);
    extra_output.witness.vtxoutwit.resize(extra_output.vout.size());
    BOOST_CHECK(!IsCanonicalFeeFreeDrivechainDeposit(CTransaction(extra_output)));

    CMutableTransaction mixed_pegin = extra_input;
    mixed_pegin.vin[1].m_is_pegin = true;
    BOOST_CHECK(!CheckDrivechainDepositOutputs(CTransaction(mixed_pegin), 0, err));

    CMutableTransaction forged_marker = mtx;
    forged_marker.witness.vtxinwit[0].m_pegin_witness.stack[4].back() = '1';
    BOOST_CHECK(!IsDrivechainDepositPeginWitness(
        forged_marker.witness.vtxinwit[0].m_pegin_witness,
        forged_marker.vin[0].prevout));

    // Native witnesses use one canonical int64 amount encoding. The legacy
    // pegin parser remains unchanged, but a trailing byte cannot create a
    // second byte representation of the same BIP300 mint authorization.
    CMutableTransaction noncanonical_amount = mtx;
    BOOST_REQUIRE_EQUAL(
        noncanonical_amount.witness.vtxinwit[0].m_pegin_witness.stack[0].size(),
        sizeof(CAmount));
    noncanonical_amount.witness.vtxinwit[0].m_pegin_witness.stack[0].push_back(0);
    BOOST_CHECK(!IsDrivechainDepositPeginWitness(
        noncanonical_amount.witness.vtxinwit[0].m_pegin_witness,
        noncanonical_amount.vin[0].prevout));

    CMutableTransaction empty_address = mtx;
    empty_address.witness.vtxinwit[0].m_pegin_witness.stack[7].clear();
    BOOST_CHECK(!IsDrivechainDepositPeginWitness(
        empty_address.witness.vtxinwit[0].m_pegin_witness,
        empty_address.vin[0].prevout));

    CMutableTransaction oversized_address = mtx;
    oversized_address.witness.vtxinwit[0].m_pegin_witness.stack[7].assign(129, 'a');
    BOOST_CHECK(!IsDrivechainDepositPeginWitness(
        oversized_address.witness.vtxinwit[0].m_pegin_witness,
        oversized_address.vin[0].prevout));

    BOOST_CHECK_THROW(
        CreateDrivechainDepositPeginWitness(
            deposit_value, Params().GetConsensus().pegged_asset,
            Params().ParentGenesisBlockHash(), CScript() << OP_TRUE,
            deposit_outpoint, block_hash, {}),
        std::invalid_argument);
    BOOST_CHECK_THROW(
        CreateDrivechainDepositPeginWitness(
            deposit_value, Params().GetConsensus().pegged_asset,
            Params().ParentGenesisBlockHash(), CScript() << OP_TRUE,
            deposit_outpoint, block_hash, std::vector<unsigned char>(129, 'a')),
        std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(drivechain_deposit_constructor_wire_formats)
{
    const CAsset asset{uint256S("11")};
    const uint256 genesis{uint256S("22")}, txid{uint256S("33")}, block_hash{uint256S("44")};
    const CScript claim = CScript() << OP_TRUE;
    const COutPoint outpoint{Txid::FromUint256(txid), 3};
    const std::vector<unsigned char> address(128, 'a');
    DrivechainDepositEvidence evidence;
    evidence.deposit_tx={1,2}; evidence.txout_proof={3,4}; evidence.previous_ctip_tx={5,6};
    evidence.sequence_number=9; evidence.previous_sequence_number=8;
    evidence.headers.emplace_back();
    evidence.headers.back().nTime=123;
    std::vector<unsigned char> header_bytes;
    VectorWriter(header_bytes,0) << evidence.headers;
    for (const CAmount value : {CAmount{-1}, CAmount{0}, CAmount{1}, MAX_MONEY}) {
        const auto legacy = CreateDrivechainDepositPeginWitness(value, asset, genesis, claim, txid);
        const auto native = CreateDrivechainDepositPeginWitness(value, asset, genesis, claim, outpoint, block_hash, address);
        const auto proven = CreateDrivechainDepositPeginWitness(value, asset, genesis, claim, evidence);
        BOOST_REQUIRE_EQUAL(legacy.stack.size(), 6U);
        BOOST_REQUIRE_EQUAL(native.stack.size(), 8U);
        BOOST_REQUIRE_EQUAL(proven.stack.size(), 11U);
        BOOST_CHECK(IsLegacyDrivechainDepositPeginWitness(legacy));
        BOOST_CHECK(!IsLegacyDrivechainDepositPeginWitness(native));
        BOOST_CHECK(!IsLegacyDrivechainDepositPeginWitness(proven));
        std::vector<unsigned char> encoded;
        VectorWriter(encoded, 0) << value;
        const std::vector<std::vector<unsigned char>> prefix{
            encoded, {asset.begin(), asset.end()}, {genesis.begin(), genesis.end()}, {OP_TRUE}};
        for (const auto* witness : {&legacy, &native, &proven}) {
            BOOST_CHECK(std::equal(prefix.begin(), prefix.end(), witness->stack.begin()));
        }
        const std::string v1 = "drivechain-deposit-v1", v2 = "drivechain-deposit-v2";
        BOOST_CHECK(legacy.stack[4] == std::vector<unsigned char>(v1.begin(), v1.end()));
        BOOST_CHECK(native.stack[4] == std::vector<unsigned char>(v2.begin(), v2.end()));
        BOOST_CHECK(proven.stack[4] == native.stack[4]);
        BOOST_CHECK(native.stack[7] == address);
        BOOST_CHECK(legacy.stack[5] == std::vector<unsigned char>(txid.begin(),txid.end()));
        BOOST_CHECK(native.stack[5] == legacy.stack[5]);
        BOOST_CHECK(native.stack[6] == std::vector<unsigned char>(block_hash.begin(),block_hash.end()));
        BOOST_CHECK(proven.stack[5] == evidence.deposit_tx);
        BOOST_CHECK(proven.stack[6] == evidence.txout_proof);
        BOOST_CHECK(proven.stack[7] == evidence.previous_ctip_tx);
        BOOST_CHECK(proven.stack[8] == std::vector<unsigned char>({9,0,0,0,0,0,0,0}));
        BOOST_CHECK(proven.stack[9] == std::vector<unsigned char>({8,0,0,0,0,0,0,0}));
        BOOST_CHECK(proven.stack[10] == header_bytes);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_parent_header_mtp_is_strict)
{
    constexpr int test_slot{24};
    const std::optional<uint8_t>& configured_slot = Params().GetConsensus().drivechain_slot;
    BOOST_CHECK_EQUAL(IsDrivechainSidechainSlot(test_slot),
                      configured_slot.has_value() && *configured_slot == test_slot);
    BOOST_CHECK(!IsDrivechainSidechainSlot(-1));
    BOOST_CHECK(!IsDrivechainSidechainSlot(256));
    for (int slot=-1; slot<=256; ++slot) {
        BOOST_CHECK_EQUAL(IsDrivechainSidechainSlot(slot),configured_slot.has_value() && slot==*configured_slot);
    }
    for (uint64_t configured=0; configured<=256; ++configured) {
        for (const int requested : {-1,0,24,130,255,256}) {
            for (const bool present : {false,true}) {
                BOOST_CHECK_EQUAL(drivechain::haskell::ParentReplayRecord(
                    drivechain::haskell::ReplayRecordKind::CONFIGURED_SLOT,present,requested,configured),
                    present && configured<=255 && requested>=0 && static_cast<uint64_t>(requested)==configured);
            }
        }
    }

    const uint256 expected_hash = uint256S("00000000000000000000000000000000000000000000000000000000000000aa");
    uint64_t mtp{0};
    std::string err;

    UniValue header;
    BOOST_REQUIRE(header.read(strprintf("{\"hash\":\"%s\",\"mediantime\":1700000000}", expected_hash.GetHex())));
    BOOST_CHECK(ParseDrivechainParentHeader(header, expected_hash, mtp, &err));
    BOOST_CHECK_EQUAL(mtp, 1700000000U);

    const uint256 wrong_hash = uint256S("00000000000000000000000000000000000000000000000000000000000000bb");
    BOOST_REQUIRE(header.read(strprintf("{\"hash\":\"%s\",\"mediantime\":1700000000}", wrong_hash.GetHex())));
    BOOST_CHECK(!ParseDrivechainParentHeader(header, expected_hash, mtp, &err));

    std::string uppercase_hash = expected_hash.GetHex();
    uppercase_hash.replace(62, 2, "AA");
    BOOST_REQUIRE(header.read(strprintf("{\"hash\":\"%s\",\"mediantime\":1700000000}", uppercase_hash)));
    BOOST_CHECK(!ParseDrivechainParentHeader(header, expected_hash, mtp, &err));

    const std::vector<std::string> invalid_headers{
        "{}",
        "{\"hash\":1,\"mediantime\":1700000000}",
        "{\"hash\":\"00\",\"mediantime\":1700000000}",
        strprintf("{\"hash\":\"%s\"}", expected_hash.GetHex()),
        strprintf("{\"hash\":\"%s\",\"mediantime\":\"1700000000\"}", expected_hash.GetHex()),
        strprintf("{\"hash\":\"%s\",\"mediantime\":-1}", expected_hash.GetHex()),
        strprintf("{\"hash\":\"%s\",\"mediantime\":1.5}", expected_hash.GetHex()),
        strprintf("{\"hash\":\"%s\",\"mediantime\":4294967296}", expected_hash.GetHex()),
    };
    for (const std::string& json : invalid_headers) {
        BOOST_REQUIRE(header.read(json));
        BOOST_CHECK(!ParseDrivechainParentHeader(header, expected_hash, mtp, &err));
    }
}

BOOST_AUTO_TEST_CASE(drivechain_bmm_m7_requires_exact_canonical_commitment)
{
    const uint256 sidechain_hash = uint256S("0123456789abcdef00112233445566778899aabbccddeeff1020304050607080");

    const auto make_m7 = [](const int slot, const uint256& hash) {
        std::vector<unsigned char> payload = ParseHex("d1617368");
        payload.push_back(static_cast<unsigned char>(slot));
        const std::vector<unsigned char> display_hash = ParseHex(hash.GetHex());
        payload.insert(payload.end(), display_hash.begin(), display_hash.end());
        return CScript() << OP_RETURN << payload;
    };
    const auto make_block = [](const std::vector<CScript>& scripts) {
        Bitcoin::CMutableTransaction coinbase;
        coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0, 0);
        for (const CScript& script : scripts) coinbase.vout.emplace_back(0, script);
        Bitcoin::CBlock block;
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(coinbase)));
        return block;
    };

    std::string err;
    uint32_t output_index{99};
    uint256 parsed_hash;
    BOOST_CHECK(ExtractCanonicalDrivechainBmmCommitmentInBlock(
        make_block({CScript() << OP_RETURN << std::vector<unsigned char>{0x01},
                    make_m7(24, sidechain_hash)}),
        24, parsed_hash, &output_index, &err));
    BOOST_CHECK_EQUAL(parsed_hash, sidechain_hash);
    BOOST_CHECK_EQUAL(output_index, 1U);

    output_index = 99;
    BOOST_CHECK(MatchDrivechainBmmCommitmentInBlock(
        make_block({CScript() << OP_RETURN << std::vector<unsigned char>{0x01}, make_m7(24, sidechain_hash)}),
        24, sidechain_hash, &output_index, &err));
    BOOST_CHECK_EQUAL(output_index, 1U);

    // The pinned enforcer decodes critical_hash as ConsensusHex into an
    // opaque BmmCommitment, not a ReverseHex block hash. Preserve a fixed
    // cross-codec fixture independent of make_m7().
    const std::vector<unsigned char> enforcer_fixture_bytes = ParseHex(
        "6a25d1617368180123456789abcdef00112233445566778899aabbccddeeff1020304050607080");
    const CScript enforcer_fixture(
        enforcer_fixture_bytes.begin(), enforcer_fixture_bytes.end());
    BOOST_CHECK(MatchDrivechainBmmCommitmentInBlock(
        make_block({enforcer_fixture}), 24, sidechain_hash, nullptr, &err));

    const uint256 wrong_hash = uint256S("1123456789abcdef00112233445566778899aabbccddeeff1020304050607080");
    BOOST_CHECK(!MatchDrivechainBmmCommitmentInBlock(make_block({make_m7(24, wrong_hash)}),
                                                     24, sidechain_hash, nullptr, &err));
    BOOST_CHECK(!MatchDrivechainBmmCommitmentInBlock(make_block({make_m7(23, sidechain_hash)}),
                                                     24, sidechain_hash, nullptr, &err));
    BOOST_CHECK(!MatchDrivechainBmmCommitmentInBlock(
        make_block({make_m7(24, sidechain_hash), make_m7(24, sidechain_hash)}),
        24, sidechain_hash, nullptr, &err));

    CScript trailing = make_m7(24, sidechain_hash);
    trailing << OP_TRUE;
    BOOST_CHECK(!MatchDrivechainBmmCommitmentInBlock(make_block({trailing}),
                                                     24, sidechain_hash, nullptr, &err));

    std::vector<unsigned char> payload = ParseHex("d1617368");
    payload.push_back(24);
    const std::vector<unsigned char> display_hash = ParseHex(sidechain_hash.GetHex());
    payload.insert(payload.end(), display_hash.begin(), display_hash.end());
    CScript nonminimal;
    nonminimal.push_back(OP_RETURN);
    nonminimal.push_back(OP_PUSHDATA1);
    nonminimal.push_back(payload.size());
    nonminimal.insert(nonminimal.end(), payload.begin(), payload.end());
    // Exact commitment and single-push framing are required, but the pinned
    // enforcer intentionally permits non-minimal push opcodes.
    BOOST_CHECK(MatchDrivechainBmmCommitmentInBlock(make_block({nonminimal}),
                                                    24, sidechain_hash, nullptr, &err));
    BOOST_CHECK(!MatchDrivechainBmmCommitmentInBlock(
        make_block({make_m7(24, sidechain_hash), nonminimal}),
        24, sidechain_hash, nullptr, &err));

    for (const unsigned int length_bytes : {2U, 4U}) {
        CScript pushed;
        pushed.push_back(OP_RETURN);
        pushed.push_back(length_bytes == 2 ? OP_PUSHDATA2 : OP_PUSHDATA4);
        for (unsigned int byte = 0; byte < length_bytes; ++byte) {
            pushed.push_back(byte == 0 ? payload.size() : 0);
        }
        pushed.insert(pushed.end(), payload.begin(), payload.end());
        BOOST_CHECK(MatchDrivechainBmmCommitmentInBlock(make_block({pushed}),
                                                        24, sidechain_hash, nullptr, &err));
        // Removing payload bytes must not turn an incomplete push into M7.
        pushed.pop_back();
        BOOST_CHECK(!MatchDrivechainBmmCommitmentInBlock(make_block({pushed}),
                                                         24, sidechain_hash, nullptr, &err));
    }
    BOOST_CHECK(!MatchDrivechainBmmCommitmentInBlock(
        make_block({make_m7(24, sidechain_hash), make_m7(24, wrong_hash)}),
        24, sidechain_hash, nullptr, &err));

    CScript internal_endian;
    internal_endian << OP_RETURN;
    std::vector<unsigned char> internal_payload = ParseHex("d1617368");
    internal_payload.push_back(24);
    internal_payload.insert(internal_payload.end(), sidechain_hash.begin(), sidechain_hash.end());
    internal_endian << internal_payload;
    BOOST_CHECK(!MatchDrivechainBmmCommitmentInBlock(make_block({internal_endian}),
                                                     24, sidechain_hash, nullptr, &err));
}

BOOST_AUTO_TEST_CASE(drivechain_parent_withdrawal_replay_requires_approved_m6)
{
    constexpr int slot{24};
    constexpr uint16_t max_age{10};
    constexpr uint16_t threshold{5};
    const uint256 required_proposal = uint256S(
        "3333333333333333333333333333333333333333333333333333333333333333");
    const Bitcoin::COutPoint initial_ctip(
        uint256S("4444444444444444444444444444444444444444444444444444444444444444"), 0);
    const CScript treasury_script = CScript()
        << OP_NOP5 << std::vector<unsigned char>{slot} << OP_TRUE;

    const CAmount old_treasury_value{5000};
    const CAmount new_treasury_value{3900};
    const CAmount payout_value{1000};
    const CAmount mainchain_fee{
        old_treasury_value - new_treasury_value - payout_value};
    std::vector<unsigned char> fee_bytes;
    for (int byte = 7; byte >= 0; --byte) {
        fee_bytes.push_back(
            (static_cast<uint64_t>(mainchain_fee) >> (8 * byte)) & 0xff);
    }

    Bitcoin::CMutableTransaction blinded;
    blinded.version = 2;
    blinded.vout.emplace_back(0, CScript() << OP_RETURN << fee_bytes);
    blinded.vout.emplace_back(0, CScript() << OP_RETURN << std::vector<unsigned char>(32, 0x42));
    blinded.vout.emplace_back(payout_value, CScript() << OP_TRUE);
    const uint256 m6id = blinded.GetHash();

    Bitcoin::CMutableTransaction m6;
    m6.version = 2;
    m6.vin.emplace_back(initial_ctip);
    m6.vout.emplace_back(new_treasury_value, treasury_script);
    m6.vout.emplace_back(0, CScript() << OP_RETURN << std::vector<unsigned char>(32, 0x42));
    m6.vout.emplace_back(payout_value, CScript() << OP_TRUE);

    const auto make_m3 = [&](const uint8_t message_slot, const uint256& bundle_id) {
        std::vector<unsigned char> payload = ParseHex("d45aa943");
        payload.push_back(message_slot);
        payload.insert(payload.end(), bundle_id.begin(), bundle_id.end());
        return CScript() << OP_RETURN << payload;
    };
    const auto make_m4 = [](const std::vector<unsigned char>& votes) {
        std::vector<unsigned char> payload = ParseHex("d77d177601");
        payload.insert(payload.end(), votes.begin(), votes.end());
        return CScript() << OP_RETURN << payload;
    };
    const auto make_block = [](const std::vector<CScript>& messages,
                               const uint32_t nonce,
                               const std::optional<Bitcoin::CMutableTransaction>& transaction = std::nullopt) {
        Bitcoin::CMutableTransaction coinbase;
        coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
        for (const CScript& message : messages) coinbase.vout.emplace_back(0, message);
        Bitcoin::CBlock block;
        block.nNonce = nonce;
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(coinbase)));
        if (transaction) {
            block.vtx.push_back(Bitcoin::MakeTransactionRef(*transaction));
        }
        return block;
    };
    const auto active_state = [&] {
        DrivechainParentReplayState state;
        state.active_proposal_hash = required_proposal;
        state.required_proposal_activated = true;
        state.required_activation_height = 1;
        state.ctip = initial_ctip;
        state.ctip_value = old_treasury_value;
        return state;
    };
    const auto apply = [&](const Bitcoin::CBlock& block, const uint32_t height,
                           DrivechainParentReplayState& state, std::string& error) {
        return ApplyDrivechainParentBlockState(
            block, height, slot, required_proposal,
            max_age, threshold, max_age, threshold,
            max_age, threshold,
            state, nullptr, &error);
    };

    std::string error;

    // A matching M3 is not enough. The finalized M6 remains invalid until its
    // score is strictly greater than the network's inclusion threshold.
    DrivechainParentReplayState unapproved = active_state();
    BOOST_CHECK(apply(make_block({make_m3(slot, m6id)}, 10), 10, unapproved, error));
    BOOST_REQUIRE_EQUAL(unapproved.pending_withdrawals.size(), 1U);
    BOOST_CHECK_EQUAL(unapproved.pending_withdrawals.front().votes, 1U);
    BOOST_CHECK(!apply(make_block({}, 11, m6), 11, unapproved, error));

    // M4 indexes the sorted global active-slot list. Slot 5 precedes slot 24,
    // so each vector abstains for slot 5 and upvotes bundle index zero for 24.
    DrivechainParentReplayState approved = active_state();
    approved.other_slots[5].active_proposal_hash = uint256::ONE;
    BOOST_CHECK(apply(make_block({make_m3(slot, m6id)}, 20), 20, approved, error));
    for (uint32_t height = 21; height <= 24; ++height) {
        BOOST_CHECK(apply(make_block({make_m4({0xff, 0x00})}, height),
                          height, approved, error));
    }
    BOOST_CHECK_EQUAL(approved.pending_withdrawals.front().votes, 5U);
    BOOST_CHECK(!apply(make_block({}, 25, m6), 25, approved, error));

    // The fifth later upvote raises the initial score of one to six. M4 is
    // processed before M6 in the same block, matching the enforcer.
    BOOST_CHECK(apply(
        make_block({make_m4({0xff, 0x00})}, 25, m6), 25, approved, error));
    BOOST_CHECK(approved.pending_withdrawals.empty());
    BOOST_REQUIRE(approved.ctip.has_value());
    BOOST_CHECK_EQUAL(approved.ctip->hash, Bitcoin::CTransaction(m6).GetHash());
    BOOST_CHECK_EQUAL(approved.ctip->n, 0U);
    BOOST_CHECK_EQUAL(approved.ctip_value, new_treasury_value);

    // A different fee produces a different blinded M6id and cannot consume
    // approval for the original bundle.
    DrivechainParentReplayState mismatched = active_state();
    mismatched.pending_withdrawals.push_back(
        DrivechainPendingWithdrawal{m6id, 30, threshold + 1});
    Bitcoin::CMutableTransaction wrong_fee = m6;
    wrong_fee.vout[0].nValue = new_treasury_value - 1;
    BOOST_CHECK(!apply(make_block({}, 30, wrong_fee), 30, mismatched, error));

    // A malformed global vote vector cannot be interpreted as a vote for the
    // configured slot.
    DrivechainParentReplayState malformed_votes = active_state();
    malformed_votes.other_slots[5].active_proposal_hash = uint256::ONE;
    BOOST_CHECK(apply(make_block({make_m3(slot, m6id)}, 40), 40,
                      malformed_votes, error));
    BOOST_CHECK(!apply(make_block({make_m4({0x00})}, 41), 41,
                       malformed_votes, error));

    // Executing an approved M6 for another active sidechain must advance that
    // slot's CTIP and remove its bundle. Otherwise subsequent global M4 indices
    // drift even though this slot's own state is unchanged.
    constexpr uint8_t auxiliary_slot{5};
    const Bitcoin::COutPoint auxiliary_initial_ctip(
        uint256S("5555555555555555555555555555555555555555555555555555555555555555"), 0);
    const CAmount auxiliary_old_value{6000};
    const CAmount auxiliary_new_value{4900};
    const CScript auxiliary_treasury_script = CScript()
        << OP_NOP5 << std::vector<unsigned char>{auxiliary_slot} << OP_TRUE;

    Bitcoin::CMutableTransaction auxiliary_blinded;
    auxiliary_blinded.version = 2;
    auxiliary_blinded.vout.emplace_back(0, CScript() << OP_RETURN << fee_bytes);
    auxiliary_blinded.vout.emplace_back(
        0, CScript() << OP_RETURN << std::vector<unsigned char>(32, 0x43));
    auxiliary_blinded.vout.emplace_back(payout_value, CScript() << OP_TRUE);
    const uint256 auxiliary_m6id = auxiliary_blinded.GetHash();

    Bitcoin::CMutableTransaction auxiliary_m6;
    auxiliary_m6.version = 2;
    auxiliary_m6.vin.emplace_back(auxiliary_initial_ctip);
    auxiliary_m6.vout.emplace_back(auxiliary_new_value, auxiliary_treasury_script);
    auxiliary_m6.vout.emplace_back(
        0, CScript() << OP_RETURN << std::vector<unsigned char>(32, 0x43));
    auxiliary_m6.vout.emplace_back(payout_value, CScript() << OP_TRUE);

    DrivechainParentReplayState cross_slot = active_state();
    auto& auxiliary_state = cross_slot.other_slots[auxiliary_slot];
    auxiliary_state.active_proposal_hash = uint256::ONE;
    auxiliary_state.ctip = auxiliary_initial_ctip;
    auxiliary_state.ctip_value = auxiliary_old_value;
    BOOST_CHECK(apply(
        make_block({make_m3(auxiliary_slot, auxiliary_m6id),
                    make_m3(slot, m6id)}, 50),
        50, cross_slot, error));
    for (uint32_t height = 51; height <= 54; ++height) {
        BOOST_CHECK(apply(make_block({make_m4({0x00, 0xff})}, height),
                          height, cross_slot, error));
    }
    BOOST_CHECK(apply(
        make_block({make_m4({0x00, 0xff})}, 55, auxiliary_m6),
        55, cross_slot, error));
    BOOST_CHECK(auxiliary_state.pending_withdrawals.empty());
    BOOST_REQUIRE(auxiliary_state.ctip.has_value());
    BOOST_CHECK_EQUAL(
        auxiliary_state.ctip->hash, Bitcoin::CTransaction(auxiliary_m6).GetHash());
    BOOST_CHECK_EQUAL(auxiliary_state.ctip->n, 0U);
    BOOST_CHECK_EQUAL(auxiliary_state.ctip_value, auxiliary_new_value);
    BOOST_REQUIRE_EQUAL(cross_slot.pending_withdrawals.size(), 1U);
    BOOST_CHECK_EQUAL(cross_slot.pending_withdrawals.front().votes, 1U);

    // Slot 5 remains in the vector because it is still active, but slot 24's
    // bundle is still index zero and receives the intended vote.
    BOOST_CHECK(apply(make_block({make_m4({0xff, 0x00})}, 56),
                      56, cross_slot, error));
    BOOST_CHECK_EQUAL(cross_slot.pending_withdrawals.front().votes, 2U);
}

BOOST_AUTO_TEST_SUITE_END()
