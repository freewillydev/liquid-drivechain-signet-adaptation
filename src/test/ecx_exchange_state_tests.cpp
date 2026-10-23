// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.

#include <ecx_exchange_state.h>
#include <addresstype.h>
#include <haskell/bridge.h>
#include <haskell/simplicity_ffi.h>
#include <blind.h>
#include <confidential_validation.h>
#include <issuance.h>
#include <core_io.h>
#include <rpc/util.h>
#include <univalue.h>
#include <cstdlib>
#include <bit>
#include <fstream>
#include <iterator>
#include <tuple>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <coins.h>
#include <consensus/tx_verify.h>
#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <crypto/common.h>
#include <drivechain_bmm.h>
#include <drivechain_peg.h>
#include <hash.h>
#include <key.h>
#include <node/ecx_deployment_identity.h>
#include <node/blockstorage.h>
#include <validation.h>
#include <txdb.h>
#include <policy/policy.h>
#include <policy/feerate.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
extern "C" {
#include <simplicity/elements/env.h>
}
#include <streams.h>
#include <undo.h>
#include <test/ecx_simplicity_test_shim.h>
#include <test/util/setup_common.h>
#include <test/data/ecx_v17_configuration.hex.h>
#include <test/data/ecx_v18_configuration.hex.h>
#include <test/data/ecx_successor_bond_inbox_source_v23.hex.h>
#include <test/data/ecx_finite_bond_source.h>
#include <util/strencodings.h>
#include <util/readwritefile.h>
#include <common/args.h>

#include <boost/test/unit_test.hpp>

#include <map>
#include <random.h>
#include <limits>
#include <set>
#include <tuple>

namespace {
#include <test/capital_snapshot_reference.h>
#include <haskell/exchange_constants.h>

#ifdef ECX_PRODUCTION_ACTIVATION_PROFILE_FROZEN
// Run each case in a separate process: LayerTwoLabsExchangeConsensus caches
// its first successful load. Never exercise this against live chain data.
struct FrozenAlphaProfileSetup : BasicTestingSetup {
    FrozenAlphaProfileSetup() : BasicTestingSetup(ChainTypeMetaFrom("elements"))
    {
        // BasicTestingSetup clears the fee asset; production initialization
        // resolves it to the immutable Alpha pegged asset before loading ECX.
        ::policyAsset = Params().GetConsensus().pegged_asset;
    }
};
#endif

struct ElementsTestingSetup : BasicTestingSetup {
    ElementsTestingSetup()
        : BasicTestingSetup(ChainTypeMetaFrom("elementsregtest"))
    {
    }
};

class MemoryCoinsView final : public CCoinsView
{
public:
    std::map<COutPoint, Coin> coins;

    std::optional<Coin> GetCoin(const COutPoint& outpoint) const override
    {
        const auto it = coins.find(outpoint);
        if (it == coins.end() || it->second.IsSpent()) return std::nullopt;
        return it->second;
    }

    bool BatchWrite(CoinsViewCacheCursor& cursor, const uint256&) override
    {
        for (auto it = cursor.Begin(); it != cursor.End(); it = cursor.NextAndMaybeErase(*it)) {
            if (it->second.IsDirty()) {
                if (it->second.coin.IsSpent()) {
                    coins.erase(it->first.second);
                } else {
                    coins[it->first.second] = it->second.coin;
                }
            }
        }
        return true;
    }
};

CScript TaprootScript(unsigned char value)
{
    return CScript() << OP_1 << std::vector<unsigned char>(32, value);
}

CTxOut AuthorityOutput(unsigned char script_byte, CAmount amount = 1)
{
    return CTxOut(
        Params().GetConsensus().pegged_asset,
        amount,
        TaprootScript(script_byte));
}

ecx::ExchangeConsensus ConfiguredConsensus(
    int height,
    const COutPoint& genesis,
    const uint256& genesis_root)
{
    ecx::ExchangeConsensus consensus;
    consensus.activation_height = height;
    consensus.genesis_state_outpoint = genesis;
    consensus.genesis_state_root = genesis_root;
    consensus.chain_id.fill(0x11);
    consensus.forced_action_domain.fill(0x22);
    consensus.deposit_inbox_domain.fill(0x33);
    consensus.collateral_vault_script = TaprootScript(0x44);
    CSHA256 hasher;
    hasher.Write(
        consensus.collateral_vault_script.data(),
        consensus.collateral_vault_script.size());
    hasher.Finalize(consensus.collateral_vault_script_hash.begin());
    return consensus;
}

void PopulateTestBondV2FrozenIdentities(ecx::ExchangeConsensus& consensus)
{
    auto& frozen{consensus.bond_v2};
    frozen.activation_enabled = true;
    frozen.identities_frozen = true;
    frozen.deployment_transaction = MakeTransactionRef(CMutableTransaction{});
    frozen.genesis_transaction = MakeTransactionRef(CMutableTransaction{});
    frozen.canonical_configuration_bytes = {1};
    const auto fill = [](uint256& value, unsigned char byte) {
        std::fill(value.begin(), value.end(), byte);
    };
    fill(frozen.public_state_domain_sha256, 19);
    fill(frozen.state_node_domain_sha256, 20);
    fill(frozen.incremental_activation_program_id, 70);
    fill(frozen.incremental_activation_configuration_hash, 71);
    fill(frozen.incremental_activation_cmr, 72);
    fill(frozen.incremental_successor_program_id, 73);
    fill(frozen.incremental_successor_configuration_hash, 74);
    fill(frozen.incremental_successor_transition_cmr, 75);
    fill(frozen.incremental_successor_state_node_domain_sha256, 76);
    fill(frozen.inventory_cmr, 21);
    fill(frozen.redemption_queue_cmr, 22);
    fill(frozen.ecx_btc_conversion_program_id, 23);
    fill(frozen.ecx_btc_redemption_covenant_commitment, 24);
    fill(frozen.ecx_btc_source_checkpoint_commitment, 25);
    fill(frozen.usdd_usd_conversion_program_id, 26);
    fill(frozen.usdd_usd_redemption_covenant_commitment, 27);
    fill(frozen.usdd_usd_source_checkpoint_commitment, 28);
    fill(frozen.matcher_genesis_receipt_hash, 29);
    fill(frozen.order_receipts_genesis_root, 30);
    fill(frozen.genesis_availability_root, 31);
    fill(frozen.inventory_covenant_script_sha256, 32);
    fill(frozen.reissuance_token_burn_script_sha256, 33);
    fill(frozen.state_authority_asset_id, 34);
    fill(frozen.inventory_asset_blinding_factor, 35);
    fill(frozen.inventory_value_blinding_factor, 36);
    fill(frozen.issuance_value_blinding_factor, 93);
    fill(frozen.redemption_queue_script_sha256, 37);
    fill(frozen.insurance_reserve_script_sha256, 38);
    fill(frozen.insurance_reserve_covenant_cmr, 39);
    fill(frozen.bond_inbox_redemption_staging_template_commitment, 40);
    const std::vector<unsigned char> renderer_domain{ParseHex(
        "d8ca7883769dd73830987f727a34939d2d9b69a3e783e0a2e1cca35fa4872e6f")};
    std::copy(
        renderer_domain.begin(), renderer_domain.end(),
        frozen.bond_inbox_redemption_staging_renderer_domain.begin());
    const std::vector<unsigned char> nums_internal_key{ParseHex(
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")};
    std::copy(
        nums_internal_key.begin(), nums_internal_key.end(),
        frozen.bond_inbox_redemption_staging_internal_key.begin());
    fill(frozen.bond_inbox_redemption_staging_process_cmr, 42);
    fill(frozen.bond_inbox_redemption_staging_refund_cmr, 43);
    fill(frozen.bond_inbox_domain, 44);
    fill(frozen.bond_inbox_custody_receipt_codec_hash, 45);
    fill(frozen.availability_scheme_hash, 46);
    fill(frozen.availability_custodian_registry_hash, 47);
    fill(frozen.collateral_vault_covenant_cmr, 48);
    frozen.bond_inbox_redemption_staging_tapleaf_version = 0xbe;
    frozen.bond_inbox_refund_minimum_parent_blocks = 12;
    frozen.bond_inbox_inclusion_blocks = 6;
    frozen.bond_inbox_max_bundle_bytes = 64 * 1024;
    frozen.bond_inbox_max_entries_per_sidechain_block = 8;
    frozen.bond_inbox_max_unique_source_witness_bytes_per_sidechain_block =
        576 * 1024;
    frozen.bond_inbox_max_unique_source_transaction_bytes_per_sidechain_block =
        768 * 1024;
    frozen.bond_inbox_max_pending_entries_per_transition = 64;
    frozen.bond_inbox_max_consumed_entries_per_transition = 64;
    frozen.bond_redemption_max_queue_entries = 4096;
    frozen.matcher_execution_inclusion_parent_blocks = 6;
    frozen.maximum_conversion_age_seconds = 3600;
    frozen.maximum_conversion_proof_bytes = 16 * 1024 * 1024;
    frozen.recursive_proof_marker_bytes = 32;
    frozen.fixed_supply_atoms = UINT64_C(2100000000000000);
    frozen.redemption_delay_parent_blocks = 1008;
    for (size_t i = 0; i < frozen.custodian_encryption_keys.size(); ++i) {
        frozen.custodian_encryption_keys[i].fill(50 + i);
        frozen.custodian_attestation_keys[i].fill(60 + i);
    }
    frozen.usdd_asset_id = CAsset(uint256S("37"));
    std::copy(
        nums_internal_key.begin(), nums_internal_key.end(),
        frozen.keyless_internal_key.begin());
    frozen.genesis_mark_price = 1;
}

struct TestBlockIndex : CBlockIndex {
    uint256 hash;

    TestBlockIndex(const CBlock& block, int height, CBlockIndex* previous = nullptr)
        : CBlockIndex{block}, hash{block.GetHash()}
    {
        phashBlock = &hash;
        nHeight = height;
        pprev = previous;
    }
};

uint256 TestSha256(const std::vector<unsigned char>& bytes)
{
    uint256 result;
    CSHA256 hasher;
    if (!bytes.empty()) hasher.Write(bytes.data(), bytes.size());
    hasher.Finalize(result.begin());
    return result;
}

uint256 TestTaggedHash(const std::string& tag, const std::vector<unsigned char>& bytes)
{
    const uint256 tag_hash{TestSha256(
        std::vector<unsigned char>(tag.begin(), tag.end()))};
    uint256 result;
    CSHA256 hasher;
    hasher.Write(tag_hash.begin(), 32).Write(tag_hash.begin(), 32);
    if (!bytes.empty()) hasher.Write(bytes.data(), bytes.size());
    hasher.Finalize(result.begin());
    return result;
}

CScript TestBondV2SuccessorScript(
    const ecx::ExchangeConsensus& consensus,
    const uint256& covenant_state_hash)
{
    std::vector<unsigned char> state_node_preimage;
    state_node_preimage.insert(
        state_node_preimage.end(),
        consensus.bond_v2.state_node_domain_sha256.begin(),
        consensus.bond_v2.state_node_domain_sha256.end());
    state_node_preimage.insert(
        state_node_preimage.end(), covenant_state_hash.begin(), covenant_state_hash.end());
    const uint256 state_node{TestSha256(state_node_preimage)};

    const auto leaf_hash = [](const uint256& cmr) {
        std::vector<unsigned char> payload{TAPROOT_LEAF_TAPSIMPLICITY, 32};
        payload.insert(payload.end(), cmr.begin(), cmr.end());
        return TestTaggedHash("TapLeaf/elements", payload);
    };
    const auto branch_hash = [](const uint256& left, const uint256& right) {
        std::vector<unsigned char> payload;
        if (std::lexicographical_compare(
                left.begin(), left.end(), right.begin(), right.end())) {
            payload.insert(payload.end(), left.begin(), left.end());
            payload.insert(payload.end(), right.begin(), right.end());
        } else {
            payload.insert(payload.end(), right.begin(), right.end());
            payload.insert(payload.end(), left.begin(), left.end());
        }
        return TestTaggedHash("TapBranch/elements", payload);
    };
    const uint256 transition_leaf{leaf_hash(consensus.bond_v2.transition_cmr)};
    const uint256 activation_leaf{
        leaf_hash(consensus.bond_v2.incremental_activation_cmr)};
    const uint256 activation_or_state{branch_hash(activation_leaf, state_node)};
    const uint256 root{branch_hash(transition_leaf, activation_or_state)};
    const XOnlyPubKey internal{Span<const unsigned char>(
        consensus.bond_v2.keyless_internal_key.data(), 32)};
    const auto tweaked{internal.CreateTapTweak(&root)};
    if (!tweaked) return {};
    return CScript() << OP_1 << std::vector<unsigned char>(
        tweaked->first.begin(), tweaked->first.end());
}

CScript TestBondV2IncrementalSuccessorScript(
    const ecx::ExchangeConsensus& consensus,
    const uint256& successor_state_root)
{
    std::vector<unsigned char> state_node_preimage;
    state_node_preimage.insert(
        state_node_preimage.end(),
        consensus.bond_v2.incremental_successor_state_node_domain_sha256.begin(),
        consensus.bond_v2.incremental_successor_state_node_domain_sha256.end());
    state_node_preimage.insert(
        state_node_preimage.end(), successor_state_root.begin(), successor_state_root.end());
    const uint256 state_node{TestSha256(state_node_preimage)};

    std::vector<unsigned char> leaf_preimage{TAPROOT_LEAF_TAPSIMPLICITY, 32};
    leaf_preimage.insert(
        leaf_preimage.end(),
        consensus.bond_v2.incremental_successor_transition_cmr.begin(),
        consensus.bond_v2.incremental_successor_transition_cmr.end());
    const uint256 transition_leaf{TestTaggedHash("TapLeaf/elements", leaf_preimage)};
    std::vector<unsigned char> branch_preimage;
    if (std::lexicographical_compare(
            transition_leaf.begin(), transition_leaf.end(),
            state_node.begin(), state_node.end())) {
        branch_preimage.insert(
            branch_preimage.end(), transition_leaf.begin(), transition_leaf.end());
        branch_preimage.insert(branch_preimage.end(), state_node.begin(), state_node.end());
    } else {
        branch_preimage.insert(branch_preimage.end(), state_node.begin(), state_node.end());
        branch_preimage.insert(
            branch_preimage.end(), transition_leaf.begin(), transition_leaf.end());
    }
    const uint256 root{TestTaggedHash("TapBranch/elements", branch_preimage)};
    const XOnlyPubKey internal{Span<const unsigned char>(
        consensus.bond_v2.keyless_internal_key.data(), 32)};
    const auto tweaked{internal.CreateTapTweak(&root)};
    if (!tweaked) return {};
    return CScript() << OP_1 << std::vector<unsigned char>(
        tweaked->first.begin(), tweaked->first.end());
}

void TestPushU32Be(std::vector<unsigned char>& bytes, uint32_t value)
{
    bytes.push_back((value >> 24) & 0xff);
    bytes.push_back((value >> 16) & 0xff);
    bytes.push_back((value >> 8) & 0xff);
    bytes.push_back(value & 0xff);
}

void TestPushU64Be(std::vector<unsigned char>& bytes, uint64_t value)
{
    for (int shift = 56; shift >= 0; shift -= 8) {
        bytes.push_back((value >> shift) & 0xff);
    }
}

void TestPushU128Be(
    std::vector<unsigned char>& bytes,
    uint64_t high,
    uint64_t low)
{
    TestPushU64Be(bytes, high);
    TestPushU64Be(bytes, low);
}

void TestAppendFill(
    std::vector<unsigned char>& bytes,
    unsigned char value,
    size_t count = 32)
{
    bytes.insert(bytes.end(), count, value);
}

struct AnnexVerifierRecorder
{
    unsigned int calls{0};
    bool reject{false};
};

bool CheckTestSp1Proof(
    void* context,
    const unsigned char proof[ECX_SP1_GROTH16_PROOF_LEN],
    size_t proof_len,
    const uint32_t program_id_words[8],
    const unsigned char public_values_sha256[32],
    const char* expected_digest)
{
    auto& recorder{*static_cast<AnnexVerifierRecorder*>(context)};
    ++recorder.calls;
    if (proof_len != ECX_SP1_GROTH16_PROOF_LEN) return false;
    for (size_t i = 0; i < proof_len; ++i) {
        if (proof[i] != 0xa5) return false;
    }
    for (size_t i = 0; i < 8; ++i) {
        if (program_id_words[i] != i + 1) return false;
    }
    const auto expected_hash = ParseHex(expected_digest);
    return !recorder.reject && std::equal(
        expected_hash.begin(), expected_hash.end(), public_values_sha256);
}

bool TestSp1Verifier(
    void* context,
    const unsigned char proof[ECX_SP1_GROTH16_PROOF_LEN],
    size_t proof_len,
    const uint32_t program_id_words[8],
    const unsigned char public_values_sha256[32])
{
    return CheckTestSp1Proof(context, proof, proof_len, program_id_words, public_values_sha256,
        "8d6dfa4aa7f674825e7d237028b78c242fbc127b59a8b152599e59c8e11522df");
}

bool TestIncrementalActivationSp1Verifier(
    void* context,
    const unsigned char proof[ECX_SP1_GROTH16_PROOF_LEN],
    size_t proof_len,
    const uint32_t program_id_words[8],
    const unsigned char public_values_sha256[32])
{
    return CheckTestSp1Proof(context, proof, proof_len, program_id_words, public_values_sha256,
        "5cc1295a4757282f49662e61cc2b20eec325418c17807da9c35548cb9b4951c2");
}

bool TestIncrementalSuccessorSp1Verifier(
    void* context,
    const unsigned char proof[ECX_SP1_GROTH16_PROOF_LEN],
    size_t proof_len,
    const uint32_t program_id_words[8],
    const unsigned char public_values_sha256[32])
{
    return CheckTestSp1Proof(context, proof, proof_len, program_id_words, public_values_sha256,
        "97af54a6584a6453f697b1099ecf42eb68ebc3b7228e0a908a345f1328a9b706");
}

std::vector<unsigned char> BondV2PublicValuesVector()
{
    std::vector<unsigned char> values;
    values.reserve(850);
    TestAppendFill(values, 1);
    TestPushU32Be(values, 5);
    for (unsigned char value = 2; value <= 7; ++value) TestAppendFill(values, value);
    TestPushU64Be(values, 8);
    TestPushU64Be(values, 9);
    for (unsigned char value = 10; value <= 16; ++value) TestAppendFill(values, value);
    TestPushU128Be(values, 0, 1000);
    TestPushU64Be(values, 100);
    TestPushU128Be(values, 0, 1000000000);
    TestPushU128Be(values, 0, 800);
    TestPushU128Be(values, 0, 1000);
    TestPushU128Be(values, 0, 12500);
    values.push_back(0);
    TestPushU64Be(values, 23);
    TestPushU64Be(values, 24);
    TestPushU64Be(values, 25);
    TestPushU32Be(values, static_cast<uint32_t>(-26));
    TestPushU64Be(values, 27);
    TestPushU64Be(values, 28);
    TestPushU64Be(values, 29);
    TestAppendFill(values, 17);       // oracle certificate
    TestPushU64Be(values, 30);       // valid-through parent MTP
    values.push_back(0);             // oracle Normal
    TestAppendFill(values, 18);      // next encrypted availability
    TestAppendFill(values, 19);      // inbox head
    TestPushU64Be(values, 4);        // inbox entry count
    TestAppendFill(values, 20);      // processed root
    TestPushU64Be(values, 3);        // processed cursor
    TestAppendFill(values, 21);      // outcome root
    TestPushU64Be(values, 3);        // outcome count
    TestAppendFill(values, 22);      // execution receipt batch root
    TestPushU64Be(values, 5);        // previous execution sequence
    TestPushU64Be(values, 6);        // next execution sequence
    BOOST_REQUIRE_EQUAL(values.size(), 850U);
    BOOST_REQUIRE_EQUAL(
        HexStr(TestSha256(values)),
        "8d6dfa4aa7f674825e7d237028b78c242fbc127b59a8b152599e59c8e11522df");
    return values;
}

std::vector<unsigned char> TestSp1AnnexPayload(bool v2)
{
    const std::vector<unsigned char> values{BondV2PublicValuesVector()};
    const uint256 values_hash{TestSha256(values)};
    std::vector<unsigned char> annex{'E', 'C', 'X', 'S', 'P', '1', 0};
    annex.push_back(v2 ? 4 : 2);
    annex.push_back(2);
    annex.push_back(1);
    annex.push_back(0);
    for (uint32_t word = 1; word <= 8; ++word) TestPushU32Be(annex, word);
    annex.insert(annex.end(), values_hash.begin(), values_hash.end());
    TestPushU32Be(annex, ECX_SP1_GROTH16_PROOF_LEN);
    annex.insert(annex.end(), ECX_SP1_GROTH16_PROOF_LEN, 0xa5);
    if (v2) annex.insert(annex.end(), values.begin(), values.end());
    BOOST_REQUIRE_EQUAL(annex.size(), v2 ? 1285U : 435U);
    return annex;
}

std::vector<unsigned char> IncrementalActivationPublicValuesVector()
{
    std::vector<unsigned char> values;
    values.reserve(ECX_SP1_INCREMENTAL_ACTIVATION_PUBLIC_VALUES_LEN);
    TestPushU32Be(values, 1);
    for (unsigned char value = 1; value <= 10; ++value) {
        TestAppendFill(values, value);
    }
    TestPushU64Be(values, 11);
    TestPushU64Be(values, 12);
    TestPushU64Be(values, 100);
    TestPushU64Be(values, 90);
    TestPushU64Be(values, 110);
    BOOST_REQUIRE_EQUAL(
        values.size(), ECX_SP1_INCREMENTAL_ACTIVATION_PUBLIC_VALUES_LEN);
    BOOST_REQUIRE_EQUAL(
        HexStr(TestSha256(values)),
        "5cc1295a4757282f49662e61cc2b20eec325418c17807da9c35548cb9b4951c2");
    return values;
}

std::vector<unsigned char> TestIncrementalActivationAnnexPayload()
{
    const std::vector<unsigned char> values{
        IncrementalActivationPublicValuesVector()};
    const uint256 values_hash{TestSha256(values)};
    std::vector<unsigned char> annex{'E', 'C', 'X', 'S', 'P', '1', 0, 5, 2, 1, 0};
    for (uint32_t word = 1; word <= 8; ++word) TestPushU32Be(annex, word);
    annex.insert(annex.end(), values_hash.begin(), values_hash.end());
    TestPushU32Be(annex, ECX_SP1_GROTH16_PROOF_LEN);
    annex.insert(annex.end(), ECX_SP1_GROTH16_PROOF_LEN, 0xa5);
    annex.insert(annex.end(), values.begin(), values.end());
    BOOST_REQUIRE_EQUAL(annex.size(), 799U);
    return annex;
}

std::vector<unsigned char> IncrementalSuccessorPublicValuesVector()
{
    std::vector<unsigned char> values;
    values.reserve(ECX_SP1_INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN);
    TestPushU32Be(values, 23);
    for (unsigned char value = 1; value <= 40; ++value) {
        TestAppendFill(values, value);
    }
    for (uint64_t value : {
             UINT64_C(30), UINT64_C(31), UINT64_C(32), UINT64_C(100),
             UINT64_C(90), UINT64_C(110), UINT64_C(2100000000000000),
             UINT64_C(100), UINT64_C(2099999999999900), UINT64_C(28),
             UINT64_C(0), UINT64_C(31)}) {
        TestPushU64Be(values, value);
    }
    TestPushU128Be(values, UINT64_MAX, UINT64_MAX - 32); // signed i128 -33
    for (uint64_t value : {
             8, 7, 8, 10, 9, 1000, 34, 9000000, 11250, 26, 27, 40, 39, 38}) {
        TestPushU128Be(values, 0, value);
    }
    TestPushU32Be(values, UINT32_MAX - 99); // signed i32 -100
    values.push_back(1); // reduce-only
    values.push_back(0); // normal oracle
    values.push_back(1); // operationally safe
    BOOST_REQUIRE_EQUAL(
        values.size(), ECX_SP1_INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN);
    BOOST_REQUIRE_EQUAL(
        HexStr(TestSha256(values)),
        "97af54a6584a6453f697b1099ecf42eb68ebc3b7228e0a908a345f1328a9b706");
    return values;
}

std::vector<unsigned char> TestIncrementalSuccessorAnnexPayload()
{
    const std::vector<unsigned char> values{
        IncrementalSuccessorPublicValuesVector()};
    const uint256 values_hash{TestSha256(values)};
    std::vector<unsigned char> annex{'E', 'C', 'X', 'S', 'P', '1', 0, 6, 2, 1, 0};
    for (uint32_t word = 1; word <= 8; ++word) TestPushU32Be(annex, word);
    annex.insert(annex.end(), values_hash.begin(), values_hash.end());
    TestPushU32Be(annex, ECX_SP1_GROTH16_PROOF_LEN);
    annex.insert(annex.end(), ECX_SP1_GROTH16_PROOF_LEN, 0xa5);
    annex.insert(annex.end(), values.begin(), values.end());
    BOOST_REQUIRE_EQUAL(annex.size(), 2062U);
    return annex;
}

void RecommitIncrementalSuccessorPublicValues(std::vector<unsigned char>& annex)
{
    BOOST_REQUIRE_EQUAL(annex.size(), 2062U);
    const std::vector<unsigned char> values(annex.begin() + 435, annex.end());
    const uint256 hash{TestSha256(values)};
    std::copy(hash.begin(), hash.end(), annex.begin() + 43);
}

void RecommitV2PublicValues(std::vector<unsigned char>& annex)
{
    BOOST_REQUIRE_EQUAL(annex.size(), 1285U);
    const std::vector<unsigned char> values(annex.begin() + 435, annex.end());
    const uint256 hash{TestSha256(values)};
    std::copy(hash.begin(), hash.end(), annex.begin() + 43);
}

bool StrictlyParsesV2(const std::vector<unsigned char>& annex)
{
    std::array<unsigned char, 32> program{};
    std::array<unsigned char, 32> digest{};
    std::array<unsigned char, ECX_SP1_PUBLIC_VALUES_V5_LEN> values{};
    return simplicity_elements_parse_sp1_groth16_v4_public_values_v5_annex(
        annex.data(), annex.size(), program.data(), digest.data(), values.data());
}

void TestPushU64Le(std::vector<unsigned char>& bytes, uint64_t value)
{
    for (int shift = 0; shift <= 56; shift += 8) {
        bytes.push_back((value >> shift) & 0xff);
    }
}

void TestPushU32Le(std::vector<unsigned char>& bytes, uint32_t value)
{
    for (int shift = 0; shift <= 24; shift += 8) bytes.push_back((value >> shift) & 0xff);
}

void TestPushBitcoinOutput(
    std::vector<unsigned char>& bytes,
    uint64_t amount,
    const CScript& script)
{
    TestPushU64Le(bytes, amount);
    BOOST_REQUIRE(script.size() < 253);
    bytes.push_back(script.size());
    bytes.insert(bytes.end(), script.begin(), script.end());
}

std::vector<unsigned char> TestM6(
    uint32_t checkpoint_height,
    const uint256& previous_hash,
    const uint256& state_root,
    unsigned char anchor_mutation = 0)
{
    const uint256 withdrawal_commitment{uint256S("77")};
    std::vector<unsigned char> anchor_payload{1, 24};
    const uint256 child_genesis{Params().GetConsensus().hashGenesisBlock};
    anchor_payload.insert(anchor_payload.end(), child_genesis.begin(), child_genesis.end());
    TestPushU32Be(anchor_payload, checkpoint_height);
    anchor_payload.insert(anchor_payload.end(), previous_hash.begin(), previous_hash.end());
    anchor_payload.insert(anchor_payload.end(), withdrawal_commitment.begin(), withdrawal_commitment.end());
    anchor_payload.insert(anchor_payload.end(), state_root.begin(), state_root.end());
    uint256 anchor{TestTaggedHash("ECX/perps-m6-state/v1", anchor_payload)};
    anchor.begin()[0] ^= anchor_mutation;
    const CScript fee = CScript() << OP_RETURN << std::vector<unsigned char>(8, 0);
    const CScript inputs = CScript() << OP_RETURN <<
        std::vector<unsigned char>(withdrawal_commitment.begin(), withdrawal_commitment.end());
    const CScript payout = CScript() << OP_TRUE;
    std::vector<unsigned char> pxst{'P', 'X', 'S', 'T', 1};
    pxst.insert(pxst.end(), anchor.begin(), anchor.end());
    const CScript state = CScript() << OP_RETURN << pxst;
    std::vector<unsigned char> bytes;
    TestPushU32Le(bytes, 2);
    bytes.push_back(0);
    bytes.push_back(4);
    TestPushBitcoinOutput(bytes, 0, fee);
    TestPushBitcoinOutput(bytes, 0, inputs);
    TestPushBitcoinOutput(bytes, 1000, payout);
    TestPushBitcoinOutput(bytes, 0, state);
    TestPushU32Le(bytes, 0);
    return bytes;
}

CTransactionRef TestCoinbase(const std::optional<CScript>& commitment = std::nullopt)
{
    CMutableTransaction transaction;
    transaction.vin.resize(1);
    transaction.vin[0].prevout.SetNull();
    transaction.vin[0].scriptSig = CScript() << 1 << OP_0;
    if (commitment.has_value()) {
        transaction.vout.emplace_back(::policyAsset, 0, *commitment);
    }
    transaction.vout.emplace_back(::policyAsset, 0, CScript() << OP_RETURN);
    return MakeTransactionRef(std::move(transaction));
}

CTxOut CursorMarker(uint64_t forced_cursor, uint64_t deposit_cursor)
{
    std::vector<unsigned char> payload{'E', 'C', 'X', 'C', 1};
    TestPushU64Le(payload, forced_cursor);
    TestPushU64Le(payload, deposit_cursor);
    return CTxOut(::policyAsset, 0, CScript() << OP_RETURN << payload);
}

uint256 RawHash(const std::string& hex)
{
    const std::vector<unsigned char> bytes{ParseHex(hex)};
    BOOST_REQUIRE_EQUAL(bytes.size(), 32);
    uint256 result;
    std::copy(bytes.begin(), bytes.end(), result.begin());
    return result;
}

CKey TestTraderKey()
{
    const std::array<unsigned char, 32> secret{{
        1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32}};
    CKey key;
    key.Set(secret.begin(), secret.end(), true);
    BOOST_REQUIRE(key.IsValid());
    return key;
}

std::vector<unsigned char> SignedCancelBody(
    const ecx::ExchangeConsensus& consensus,
    const CKey& key)
{
    static constexpr std::array<unsigned char, 16> market{{
        'E', 'C', 'X', '-', 'U', 'S', 'D', 'D', '-', 'P', 'E', 'R', 'P', 0, 0, 0}};
    const XOnlyPubKey trader{key.GetPubKey()};
    std::vector<unsigned char> body;
    body.reserve(201);
    body.push_back(1);
    body.insert(body.end(), consensus.chain_id.begin(), consensus.chain_id.end());
    body.insert(body.end(), market.begin(), market.end());
    body.insert(body.end(), trader.begin(), trader.end());
    body.insert(body.end(), 32, 0x55);
    TestPushU64Be(body, 7);
    TestPushU64Be(body, 100);
    TestPushU64Be(body, 200);
    BOOST_REQUIRE_EQUAL(body.size(), 137);
    std::array<unsigned char, 64> signature{};
    BOOST_REQUIRE(key.SignSchnorr(
        TestTaggedHash("ECX/cancel-order/v1", body),
        Span<unsigned char>(signature),
        nullptr,
        uint256{}));
    body.insert(body.end(), signature.begin(), signature.end());
    BOOST_REQUIRE_EQUAL(body.size(), 201);
    return body;
}

CMutableTransaction ForcedCancelTransaction(
    const ecx::ExchangeConsensus& consensus,
    const CKey& key,
    bool corrupt_signature = false)
{
    std::vector<unsigned char> body{SignedCancelBody(consensus, key)};
    if (corrupt_signature) body[137] ^= 1;
    std::vector<unsigned char> payload{'E', 'C', 'X', 'F', 1, 0};
    payload.push_back((body.size() >> 8) & 0xff);
    payload.push_back(body.size() & 0xff);
    payload.insert(payload.end(), body.begin(), body.end());
    CMutableTransaction tx;
    tx.vout.emplace_back(::policyAsset, 0, CScript() << OP_RETURN << payload);
    return tx;
}

CMutableTransaction ConfidentialDepositTransaction(
    const ecx::ExchangeConsensus& consensus,
    const CKey& key,
    bool include_proofs = true)
{
    const XOnlyPubKey trader{key.GetPubKey()};
    CTxOut deposit;
    deposit.nAsset.vchCommitment.assign(33, 0x41);
    deposit.nAsset.vchCommitment[0] = 10;
    deposit.nValue.vchCommitment.assign(33, 0x42);
    deposit.nValue.vchCommitment[0] = 8;
    deposit.nNonce.vchCommitment.assign(33, 0x43);
    deposit.nNonce.vchCommitment[0] = 2;
    deposit.scriptPubKey = consensus.collateral_vault_script;

    std::vector<unsigned char> marker{'E', 'C', 'X', 'D', 1};
    marker.insert(marker.end(), consensus.chain_id.begin(), consensus.chain_id.end());
    TestPushU32Be(marker, 0);
    marker.insert(marker.end(), trader.begin(), trader.end());
    BOOST_REQUIRE_EQUAL(marker.size(), 73);

    CMutableTransaction tx;
    tx.vout.push_back(std::move(deposit));
    tx.vout.emplace_back(::policyAsset, 0, CScript() << OP_RETURN << marker);
    tx.witness.vtxoutwit.resize(2);
    if (include_proofs) {
        tx.witness.vtxoutwit[0].vchRangeproof = {0x51};
        tx.witness.vtxoutwit[0].vchSurjectionproof = {0x52};
    }
    return tx;
}

void CheckActivationAnnexPolicy(const ecx::ExchangeConsensus& consensus)
{
    const auto& frozen = consensus.bond_v2;
    CMutableTransaction tx;
    tx.vin.emplace_back(consensus.genesis_state_outpoint);
    tx.vout.emplace_back(Params().GetConsensus().pegged_asset, 10'000,
        CScript() << OP_1 << std::vector<unsigned char>(32,1));
    tx.witness.vtxinwit.resize(1);
    auto& stack = tx.witness.vtxinwit[0].scriptWitness.stack;
    stack.resize(5);
    stack[2].assign(frozen.incremental_activation_cmr.begin(),frozen.incremental_activation_cmr.end());
    stack[3].resize(33); stack[3][0]=0xbe;
    auto& a=stack[4]; a.resize(800);
    const unsigned char prefix[]{0x50,'E','C','X','S','P','1',0,5,2,1,0};
    std::copy(std::begin(prefix),std::end(prefix),a.begin());
    std::copy(frozen.incremental_activation_program_id.begin(),frozen.incremental_activation_program_id.end(),a.begin()+12);
    a[78]=1; a[79]=100; a[439]=1;
    for (unsigned i=0;i<10;++i) a[436+4+32*i+31]=i+1;
    for (unsigned offset : {324,332,340,348,356}) a[436+offset+7]=1;
    const auto put=[&](size_t offset,const auto& hash) {
        std::copy(hash.begin(),hash.end(),a.begin()+436+offset);
    };
    put(4,frozen.incremental_activation_configuration_hash);
    put(36,frozen.configuration_hash);
    put(100,frozen.incremental_successor_configuration_hash);
    put(228,consensus.chain_id);
    const auto txid=CTransaction{tx}.GetHash();
    std::transform(txid.begin(),txid.end(),a.begin()+600,
        [](std::byte b){return std::to_integer<unsigned char>(b);});
    CSHA256().Write(a.data()+436,364).Finalize(a.data()+44);
    const auto standard=[&](const CMutableTransaction& candidate,const ecx::ExchangeConsensus* config) {
        std::string reason;
        const bool accepted=IsStandardTx(CTransaction{candidate},MAX_OP_RETURN_RELAY,true,
            CFeeRate(DUST_RELAY_TX_FEE_BITCOIN),reason,config);
        MemoryCoinsView base;
        CCoinsViewCache coins(&base);
        for (const auto& input : candidate.vin) {
            coins.AddCoin(input.prevout, Coin(CTxOut(Params().GetConsensus().pegged_asset,
                10'000,TaprootScript(1)),1,false),false);
        }
        BOOST_CHECK_EQUAL(IsWitnessStandard(CTransaction{candidate},coins,config),accepted);
        return accepted;
    };
    // These are transport-policy fixtures, not valid consensus proof evidence.
    BOOST_REQUIRE(standard(tx,&consensus));
    BOOST_CHECK(!standard(tx,nullptr));
    for (unsigned offset : {12,440,472,536,600,664}) {
        auto bad=tx;
        auto& annex=bad.witness.vtxinwit[0].scriptWitness.stack[4];
        annex[offset]^=1;
        CSHA256().Write(annex.data()+436,364).Finalize(annex.data()+44);
        BOOST_CHECK(!standard(bad,&consensus));
    }
    auto bad=tx; bad.vout[0].nValue.SetToAmount(9'999);
    BOOST_CHECK(!standard(bad,&consensus));
    bad=tx; bad.witness.vtxinwit[0].scriptWitness.stack[2][0]^=1;
    BOOST_CHECK(!standard(bad,&consensus));
    bad=tx; bad.witness.vtxinwit[0].scriptWitness.stack[4][1]='U';
    BOOST_CHECK(!standard(bad,&consensus));
    auto disabled=consensus;
    disabled.bond_v2.activation_enabled=false;
    BOOST_CHECK(!standard(tx,&disabled));
    disabled=consensus; disabled.bond_v2.identities_frozen=false;
    BOOST_CHECK(!standard(tx,&disabled));
    disabled=consensus; disabled.bond_v2.incremental_activation_cmr.SetNull();
    BOOST_CHECK(!standard(tx,&disabled));

    // Rebind the txid after moving the annex: only its input position is wrong.
    bad=tx;
    bad.vin.emplace_back(Txid::FromUint256(uint256S("07")),1);
    bad.witness.vtxinwit.emplace_back();
    std::swap(bad.witness.vtxinwit[0],bad.witness.vtxinwit[1]);
    auto& moved=bad.witness.vtxinwit[1].scriptWitness.stack.back();
    const auto moved_txid=CTransaction{bad}.GetHash();
    std::transform(moved_txid.begin(),moved_txid.end(),moved.begin()+600,
        [](std::byte b){return std::to_integer<unsigned char>(b);});
    CSHA256().Write(moved.data()+436,364).Finalize(moved.data()+44);
    BOOST_CHECK(!standard(bad,&consensus));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(ecx_exchange_state_tests, ElementsTestingSetup)

BOOST_AUTO_TEST_CASE(unsigned32_fields_preserve_signed_and_length_bounds)
{
    namespace hs = drivechain::haskell;
    BOOST_CHECK(hs::FitsU32({}));
    for (int64_t value : {INT64_MIN, int64_t{-1}, int64_t{0}, int64_t{1}, int64_t{UINT32_MAX},
            int64_t{UINT32_MAX} + 1, INT64_MAX}) {
        BOOST_CHECK_EQUAL(hs::FitsU32(std::array{static_cast<uint64_t>(value)}),
            value >= 0 && value <= UINT32_MAX);
    }
    const std::array<uint64_t,6> sizes{0, 1, UINT32_MAX - 1, UINT32_MAX, uint64_t{UINT32_MAX} + 1, UINT64_MAX};
    for (auto transaction : sizes) for (auto witness : sizes) {
        BOOST_CHECK_EQUAL(hs::FitsU32(std::array{transaction, witness}),
            transaction <= UINT32_MAX && witness <= UINT32_MAX);
    }
}

BOOST_AUTO_TEST_CASE(source_marker_scan_stops_at_first_match)
{
    const std::array<unsigned char, 4> magic{'E','C','X','B'};
    for (size_t count = 0; count < 8; ++count) {
        for (size_t match = 0; match <= count; ++match) {
            std::vector<CScript> scripts(count, CScript() << OP_TRUE);
            if (match < count) scripts[match] = CScript() << OP_RETURN << std::vector<unsigned char>(magic.begin(), magic.end());
            const size_t reads = std::min(match + 1, count);
            for (size_t fault = 0; fault <= reads; ++fault) {
                size_t visited{0};
                const auto scan = [&] {
                    return !drivechain::haskell::ParentReplayEach(scripts, [&](const CScript& script) {
                        if (visited++ == fault) throw std::runtime_error("source scan fault");
                        return !drivechain::haskell::ReturnMarker(magic, script);
                    });
                };
                if (fault < reads) BOOST_CHECK_THROW(scan(), std::runtime_error);
                else BOOST_CHECK_EQUAL(scan(), match < count);
                BOOST_CHECK_EQUAL(visited, std::min(fault + 1, reads));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(marker_authentication_preserves_short_circuit_order)
{
    for (unsigned flags = 0; flags < 16; ++flags) {
        const bool context = flags & 1, required = flags & 2, key = flags & 4, signature = flags & 8;
        std::vector<uint32_t> expected{1};
        if (!context) expected.push_back(2);
        else {
            expected.push_back(3);
            if (required) {
                expected.push_back(4);
                if (key) expected.push_back(5);
                if (!key || !signature) expected.push_back(6);
            }
        }
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            std::vector<uint32_t> seen;
            unsigned error{0};
            const auto run = [&] {
                return drivechain::haskell::ParentReplayStore(
                    drivechain::haskell::ReplayStoreFlow::MARKER_AUTHENTICATION,
                    [&](uint32_t step) -> uint32_t {
                        seen.push_back(step);
                        if (seen.size() == fault + 1) throw std::runtime_error("authentication fault");
                        switch (step) {
                        case 1: return context;
                        case 2: error = 1; return false;
                        case 3: return required;
                        case 4: return key;
                        case 5: return signature;
                        case 6: error = 2; return false;
                        default: throw std::logic_error("unexpected authentication action");
                        }
                    });
            };
            if (fault < expected.size()) BOOST_CHECK_THROW(run(), std::runtime_error);
            else {
                BOOST_CHECK_EQUAL(run(), context && (!required || (key && signature)));
                BOOST_CHECK_EQUAL(error, !context ? 1U : required && (!key || !signature) ? 2U : 0U);
            }
            BOOST_CHECK(seen == std::vector<uint32_t>(expected.begin(),
                expected.begin() + std::min(fault + 1, expected.size())));
        }
    }
}

BOOST_AUTO_TEST_CASE(legacy_marker_flow_preserves_publication_order)
{
    for (unsigned flags = 0; flags < 16; ++flags) {
        const auto bit = [&](unsigned index) { return bool(flags & (1U << index)); };
        std::vector<uint32_t> expected{1};
        if (bit(0)) {
            expected.push_back(2);
            if (!bit(1)) expected.push_back(3);
            else {
                expected.push_back(4);
                if (bit(2)) { expected.push_back(5); if (bit(3)) expected.push_back(6); }
            }
        }
        std::vector<uint32_t> actual;
        bool published{false};
        const bool accepted = drivechain::haskell::ParentReplayStore(
            drivechain::haskell::ReplayStoreFlow::LEGACY_MARKER, [&](uint32_t step) -> uint32_t {
            actual.push_back(step);
            switch (step) {
            case 1: return bit(0);
            case 2: return bit(1);
            case 3: return 0;
            case 4: return bit(2);
            case 5: return bit(3);
            case 6: published = true; return 1;
            default: throw std::logic_error("unexpected marker action");
            }
        });
        BOOST_CHECK_EQUAL(accepted, !bit(0) || (bit(1) && bit(2) && bit(3)));
        BOOST_CHECK_EQUAL(published, flags == 15);
        BOOST_CHECK(actual == expected);
    }
}

BOOST_AUTO_TEST_CASE(network_eligibility_preserves_short_circuit_order)
{
    for (unsigned flags = 0; flags < 8; ++flags) {
        const bool elements = flags & 1, regtest = flags & 2, frozen = flags & 4;
        std::vector<unsigned> expected{1};
        if (elements) expected.push_back(2);
        if (!(elements && regtest)) expected.push_back(3);
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            std::vector<unsigned> seen;
            const auto fact = [&](unsigned step, bool value) {
                seen.push_back(step);
                if (seen.size() == fault + 1) throw std::runtime_error("network fact fault");
                return value;
            };
            const auto invoke = [&] {
                return !drivechain::haskell::ParentReplayAll<2>({
                    [&] { return !drivechain::haskell::ParentReplayAll<2>({
                        [&] { return fact(1, elements); },
                        [&] { return fact(2, regtest); },
                    }); },
                    [&] { return fact(3, !frozen); },
                });
            };
            if (fault == expected.size()) BOOST_CHECK_EQUAL(invoke(), (elements && regtest) || frozen);
            else BOOST_CHECK_EXCEPTION(invoke(), std::runtime_error,
                [](const auto& error) { return std::string(error.what()) == "network fact fault"; });
            BOOST_CHECK(seen == std::vector<unsigned>(expected.begin(),
                expected.begin() + std::min(fault + 1, expected.size())));
        }
    }
}

BOOST_AUTO_TEST_CASE(return_marker_matches_native_search)
{
    for (const std::array<unsigned char,4> magic : {
            std::array<unsigned char,4>{'E','C','X','F'}, {'E','C','X','D'}, {0,0,0,0}, {0x6a,1,2,3}}) {
        for (unsigned prefix = 0; prefix < 256; ++prefix) for (unsigned offset = 0; offset < 8; ++offset) {
            std::vector<unsigned char> script(offset, 0x42);
            script.insert(script.begin(), prefix);
            script.insert(script.end(), magic.begin(), magic.end());
            for (unsigned truncated = 0; truncated <= 4; ++truncated) {
                const auto bytes = std::span{script}.first(script.size()-truncated);
                const bool expected = !bytes.empty() && bytes[0] == OP_RETURN &&
                    std::search(bytes.begin()+1,bytes.end(),magic.begin(),magic.end()) != bytes.end();
                BOOST_CHECK_EQUAL(drivechain::haskell::ReturnMarker(magic,bytes), expected);
            }
        }
        BOOST_CHECK(!drivechain::haskell::ReturnMarker(magic,{}));
    }
}

BOOST_AUTO_TEST_CASE(exchange_interface_frozen_defaults)
{
    const ecx::ExchangeConsensus consensus;
    BOOST_CHECK_EQUAL(ecx::EXCHANGE_STATE_INTERFACE_VERSION, 1);
    BOOST_CHECK_EQUAL(ecx::EXCHANGE_SCRIPT_CACHE_REVISION, 12);
    BOOST_CHECK_EQUAL(ecx::ECX_CONSENSUS_RULESET_REVISION, 6);
    BOOST_CHECK_EQUAL(consensus.activation_height, std::numeric_limits<int>::max());
    BOOST_CHECK_EQUAL(consensus.bond_v2.deployment_version, 2U);
    BOOST_CHECK(ecx::BOND_V2_PARTITIONED_INCREMENTAL_RECOVERY_BOUND_PROVEN);
}

BOOST_AUTO_TEST_CASE(policy_annex_detection_short_stacks)
{
    const COutPoint outpoint{Txid::FromUint256(uint256S("01")), 0};
    MemoryCoinsView base;
    CCoinsViewCache coins(&base);
    coins.AddCoin(outpoint, Coin(CTxOut(Params().GetConsensus().pegged_asset,
        10'000, TaprootScript(1)), 1, false), false);
    CMutableTransaction tx;
    tx.vin.emplace_back(outpoint);
    tx.vout.emplace_back(Params().GetConsensus().pegged_asset, 10'000, TaprootScript(1));
    tx.witness.vtxinwit.resize(1);
    using Stack = std::vector<std::vector<unsigned char>>;
    const std::vector<std::pair<Stack, bool>> cases{
        {{}, true}, {{{}}, true}, {{{0x50}}, true},
        {{{0}, {}}, false}, {{{0}, {0x50}}, false}, {{{0}, {0x51}}, true},
    };
    for (const auto& [stack, accepted] : cases) {
        tx.witness.vtxinwit[0].scriptWitness.stack = stack;
        BOOST_CHECK_EQUAL(IsWitnessStandard(CTransaction{tx}, coins), accepted);
    }
}

BOOST_AUTO_TEST_CASE(owned_annex_preserves_hashes_and_lifetime)
{
    BOOST_CHECK(ecx_test_owned_annex());
}

BOOST_AUTO_TEST_CASE(optional_checkpoint_environment_boundary)
{
    for (bool present : {false,true}) {
        for (unsigned fields=0; fields<16; ++fields) {
            unsigned char bytes[80]{};
            const unsigned offsets[]{31,39,47,79};
            for (unsigned i=0; i<4; ++i) bytes[offsets[i]] = fields & (1U << i) ? 255 : 0;
            for (bool missing : {false,true}) {
                bool accepted=false;
                BOOST_REQUIRE(ecx_test_checkpoint_environment(present,missing ? nullptr : bytes,&accepted));
                BOOST_CHECK_EQUAL(accepted, present ? !missing && (fields==13 || fields==15) : missing || fields==0);
            }
        }
        for (unsigned offset=0; offset<80; ++offset) {
            unsigned char bytes[80]{};
            bytes[offset]=1;
            bool accepted=true;
            BOOST_REQUIRE(ecx_test_checkpoint_environment(present,bytes,&accepted));
            BOOST_CHECK(!accepted);
        }
    }
}

BOOST_AUTO_TEST_CASE(optional_environment_execution_boundary)
{
    for (unsigned kind=0; kind<7; ++kind) {
        const unsigned limit = kind<3 ? 2 : kind==4 ? 256 : 8;
        for (uint8_t present : {uint8_t{0},uint8_t{1},uint8_t{2},uint8_t{255}}) {
            for (unsigned fields=0; fields<limit; ++fields) {
                ecx_prior_active_root_env env{};
                unsigned char* roots[]{env.bond_v2_configuration_hash_wire,env.bond_v2_asset_id_wire,
                    env.bond_v2_deployment_commitment_wire,env.bond_v2_transition_cmr_wire,
                    env.bond_v2_insurance_reserve_script_sha256_wire,env.bond_v2_insurance_reserve_cmr_wire,
                    env.bond_v2_collateral_vault_script_sha256_wire,env.bond_v2_collateral_vault_cmr_wire};
                if (kind<3) {
                    uint8_t* flags[]{&env.present,&env.forced_inbox_present,&env.deposit_inbox_present};
                    unsigned char* values[]{env.root_wire,env.forced_inbox_root_wire,env.deposit_inbox_root_wire};
                    *flags[kind]=present;
                    values[kind][31]=fields;
                } else if (kind==3) {
                    env.current_bmm_parent_present=present;
                    env.current_bmm_parent_block_hash_wire[31]=fields & 1;
                    env.current_bmm_parent_height=fields & 2 ? UINT64_MAX : 0;
                    env.current_bmm_parent_mtp=fields & 4 ? UINT64_MAX : 0;
                } else if (kind==4) {
                    env.bond_v2_identity_present=present;
                    for (unsigned i=0; i<8; ++i) roots[i][31]=(fields >> i) & 1;
                } else if (kind==5) {
                    env.bond_v2_projection_present=present;
                    env.prior_active_bond_inbox_root_wire[31]=fields & 1;
                    env.prior_active_bond_inbox_count=fields & 2 ? UINT64_MAX : 0;
                    env.current_sidechain_height=fields & 4 ? UINT64_MAX : 0;
                } else {
                    env.bond_v2_incremental_activation_identity_present=present;
                    env.bond_v2_incremental_activation_cmr_wire[31]=fields & 1;
                    env.incremental_successor_transition_cmr_wire[31]=(fields >> 1) & 1;
                    env.bond_v2_identity_present=(fields >> 2) & 1;
                    for (auto root : roots) root[31]=env.bond_v2_identity_present;
                }
                const bool expected = present<=1 && (kind==5 ?
                    (present ? fields==5 || fields==7 : fields==0) : kind==6 ?
                    (present ? fields==7 : fields==0 || fields==4) : fields==(present ? limit-1 : 0));
                bool accepted=false;
                BOOST_REQUIRE(ecx_test_environment_admission(&env,&accepted));
                BOOST_CHECK_EQUAL(accepted,expected);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(required_height_frame_boundaries)
{
    for (bool present : {false,true}) {
        for (uint64_t height : std::array<uint64_t,5>{0,1,2,UINT64_C(1)<<63,UINT64_MAX}) {
            bool accepted=false;
            uint64_t output=91;
            BOOST_REQUIRE(ecx_test_height_jet_frame(present,height,&accepted,&output));
            BOOST_CHECK_EQUAL(accepted,present && height!=0);
            BOOST_CHECK_EQUAL(output,accepted ? height : 91);
        }
    }
}

BOOST_AUTO_TEST_CASE(bond_input_jet_eligibility_matrix)
{
    for (uint32_t flags=0; flags<256; ++flags) {
        for (uint32_t index=0; index<5; ++index) {
            for (uint32_t current=0; current<5; ++current) {
                for (bool collateral : {false,true}) {
                    BOOST_CHECK_EQUAL(ecx_test_bond_input_frame(index,current,flags,collateral),
                        index==2 && current==2 && flags==12);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(wide_arithmetic_upstream_oracle)
{
    FastRandomContext random{true};
    const std::array<uint64_t,7> edges{0,1,2,3,UINT64_C(1)<<63,UINT64_MAX-1,UINT64_MAX};
    for (size_t sample=0; sample<10000; ++sample) {
        std::array<uint64_t,5> input;
        size_t edge_index=sample;
        for (auto& limb : input) {
            limb=sample<2401 ? edges[edge_index%edges.size()] : random.rand64();
            edge_index/=edges.size();
        }
        // Include both full-width divisors and small divisors that expose overflow.
        if (sample%3==0) input[3]=0;
        if (sample%11==0) input[4]=0;
        const arith_uint256 value=(arith_uint256(input[0])<<64)|arith_uint256(input[1]);
        const arith_uint256 divisor=(arith_uint256(input[3])<<64)|arith_uint256(input[4]);
        arith_uint256 quotient;
        if (divisor!=0) quotient=(value*arith_uint256(input[2]))/divisor;
        const bool accepted=divisor!=0 && quotient.bits()<=128;
        uint64_t output[]{91,92,93,94};
        BOOST_CHECK_EQUAL(elements_haskell_muldiv128(input[0],input[1],input[2],input[3],input[4],
            output+1,output+2),accepted);
        BOOST_CHECK_EQUAL(output[0],91);
        BOOST_CHECK_EQUAL(output[3],94);
        BOOST_CHECK_EQUAL(output[1],accepted ? arith_uint256(quotient>>64).GetLow64() : 92);
        BOOST_CHECK_EQUAL(output[2],accepted ? quotient.GetLow64() : 93);
    }
}

BOOST_AUTO_TEST_CASE(activation_annex_policy_explicit_configuration)
{
    LOCK(cs_main);
    struct RestoreParams {
        std::string network{Params().NetworkIDString()};
        ~RestoreParams() { SelectParams(network); }
    } restore;
    SelectParams(CBaseChainParams::ELEMENTS);
    BOOST_REQUIRE(Params().GetConsensus().drivechain_slot.has_value());
    auto consensus=ConfiguredConsensus(1,COutPoint{Txid::FromUint256(uint256::ONE),0},uint256::ONE);
    auto& frozen=consensus.bond_v2;
    frozen.activation_enabled=true;
    frozen.identities_frozen=true;
    frozen.incremental_activation_cmr=uint256S("01");
    frozen.incremental_activation_program_id=uint256S("02");
    frozen.incremental_activation_configuration_hash=uint256S("03");
    frozen.configuration_hash=uint256S("04");
    frozen.incremental_successor_configuration_hash=uint256S("05");
    CheckActivationAnnexPolicy(consensus);
}

BOOST_AUTO_TEST_CASE(deployment_identity_file_lifecycle)
{
    const auto directory=gArgs.GetDataDirNet();
    fs::create_directories(directory);
    const auto identity=directory / "ecx_consensus.dat";
    std::string error;
    BOOST_REQUIRE(!fs::exists(identity));
    BOOST_REQUIRE_MESSAGE(node::CheckEcxDeploymentIdentity(error),error);
    const auto [read_ok,original]=ReadBinaryFile(identity);
    BOOST_REQUIRE(read_ok);
    BOOST_REQUIRE(!original.empty());
    BOOST_CHECK(original.size()<=1024);
    const auto prefix=std::string{"ecx-consensus-datadir-v3\nnetwork="}+Params().NetworkIDString()+
        "\ngenesis="+Params().GetConsensus().hashGenesisBlock.GetHex()+"\nfingerprint=";
    BOOST_REQUIRE(original.rfind(prefix,0)==0);
    const auto checksum_offset=prefix.size()+64+1;
    BOOST_REQUIRE(original.size()==checksum_offset+9+64+1);
    BOOST_CHECK_EQUAL(original[prefix.size()+64],'\n');
    const std::vector<unsigned char> preimage(original.begin(),original.begin()+checksum_offset);
    BOOST_CHECK_EQUAL(original.substr(checksum_offset),"checksum="+Hash(preimage).GetHex()+"\n");
    BOOST_CHECK(!fs::exists(directory / "ecx_consensus.dat.new"));
    BOOST_CHECK(node::CheckEcxDeploymentIdentity(error));
    BOOST_CHECK(ReadBinaryFile(identity).second==original);
    for (size_t size : {1023U, 1024U, 1025U}) {
        BOOST_REQUIRE(WriteBinaryFile(identity, std::string(size, 'x')));
        BOOST_CHECK(!node::CheckEcxDeploymentIdentity(error));
        BOOST_CHECK(error.find("does not match this data directory") != std::string::npos);
        BOOST_CHECK_EQUAL(ReadBinaryFile(identity).second.size(), size);
    }
    BOOST_REQUIRE(WriteBinaryFile(identity,"tampered"));
    BOOST_CHECK(!node::CheckEcxDeploymentIdentity(error));
    BOOST_CHECK(error.find("does not match this data directory")!=std::string::npos);
    BOOST_CHECK(!node::CheckEcxDeploymentResetAllowed(true,false,error));
    BOOST_CHECK(node::CheckEcxDeploymentResetAllowed(false,false,error));
    BOOST_CHECK(node::CheckEcxDeploymentResetAllowed(true,true,error));
    BOOST_CHECK_EQUAL(ReadBinaryFile(identity).second,"tampered");

    BOOST_REQUIRE(fs::remove(identity));
    const auto index=directory / "blocks" / "index";
    fs::create_directories(index);
    const auto orphan=index / "000001.ldb";
    BOOST_REQUIRE(WriteBinaryFile(orphan,"fixture"));
    BOOST_CHECK(node::CheckEcxDeploymentIdentity(error));
    BOOST_CHECK(!fs::exists(identity));
    BOOST_CHECK(!node::CheckEcxDeploymentResetAllowed(true,false,error));
    BOOST_CHECK(error.find("before ECX consensus identity first-binding")!=std::string::npos);
    gArgs.ForceSetArg("-reindex","1");
    BOOST_CHECK(!node::CheckEcxDeploymentIdentity(error));
    BOOST_CHECK(error.find("while reindexing existing data")!=std::string::npos);
    BOOST_CHECK(!fs::exists(identity));
    BOOST_CHECK_EQUAL(ReadBinaryFile(orphan).second,"fixture");
    BOOST_REQUIRE(fs::remove(orphan));
    const auto temporary=directory / "ecx_consensus.dat.new";
    fs::create_directory(temporary);
    BOOST_REQUIRE(WriteBinaryFile(temporary / "obstruction","preserve"));
    BOOST_CHECK(!node::CheckEcxDeploymentIdentity(error));
    BOOST_CHECK(!error.empty());
    BOOST_CHECK(!fs::exists(identity));
    BOOST_CHECK_EQUAL(ReadBinaryFile(temporary / "obstruction").second,"preserve");
    BOOST_REQUIRE(fs::remove(temporary / "obstruction"));
    BOOST_REQUIRE(fs::remove(temporary));
    BOOST_REQUIRE_MESSAGE(node::CheckEcxDeploymentIdentity(error),error);
    BOOST_CHECK(error.empty());
    BOOST_CHECK(ReadBinaryFile(identity).second==original);
}

BOOST_AUTO_TEST_CASE(deployment_identity_material_data_locations)
{
    const auto directory=gArgs.GetDataDirNet();
    fs::create_directories(directory);
    const auto external=gArgs.GetDataDirBase() / "external-blocks";
    fs::create_directories(external);
    gArgs.ForceSetArg("-blocksdir",fs::PathToString(external));
    gArgs.ClearPathCache();
    const auto blocks=gArgs.GetBlocksDirPath();
    BOOST_REQUIRE(blocks!=directory / "blocks");
    const auto identity=directory / "ecx_consensus.dat";
    struct Case { fs::path path; bool material; bool is_directory{false}; };
    const std::vector<Case> cases{
        {directory / "blocks/index/orphan.ldb",true},
        {blocks / "index/orphan.ldb",true},
        {directory / "blocks/blk00000.dat",true},
        {directory / "blocks/rev00000.dat",true},
        {blocks / "blk00000.dat",true},
        {blocks / "rev00000.dat",true},
        {blocks / "blk.dat",true},
        {blocks / "blk00000.dat.bak",false},
        {blocks / "notblk.dat",false},
        {directory / "chainstate_snapshot/orphan",true},
        {directory / "not-chainstate/orphan",false},
        {directory / "chainstate_empty",false,true},
        {blocks / "blk-directory.dat",false,true},
        {blocks / "index/orphan-directory",true,true},
    };
    std::string error;
    for (const auto& item : cases) {
        BOOST_TEST_CONTEXT(fs::PathToString(item.path)) {
            fs::create_directories(item.path.parent_path());
            if (item.is_directory) fs::create_directory(item.path);
            else BOOST_REQUIRE(WriteBinaryFile(item.path,"preserve"));
            BOOST_CHECK_EQUAL(node::CheckEcxDeploymentResetAllowed(true,false,error),!item.material);
            BOOST_CHECK(!fs::exists(identity));
            BOOST_REQUIRE_MESSAGE(node::CheckEcxDeploymentIdentity(error),error);
            BOOST_CHECK_EQUAL(fs::exists(identity),!item.material);
            fs::remove(identity);
            for (const auto* flag : {"-reindex","-reindex-chainstate"}) {
                gArgs.ForceSetArg(flag,"1");
                BOOST_CHECK_EQUAL(node::CheckEcxDeploymentIdentity(error),!item.material);
                BOOST_CHECK_EQUAL(fs::exists(identity),!item.material);
                if (item.material) BOOST_CHECK(error.find("while reindexing existing data")!=std::string::npos);
                fs::remove(identity);
                gArgs.ForceSetArg(flag,"0");
            }
            if (!item.is_directory) BOOST_CHECK_EQUAL(ReadBinaryFile(item.path).second,"preserve");
            BOOST_REQUIRE(fs::remove(item.path));
        }
    }
}

BOOST_AUTO_TEST_CASE(deployment_identity_material_name_parity)
{
    for (const std::string prefix : {"","blk","rev","chainstate","Blk","xblk",".blk"}) {
        for (const std::string middle : {"",".","..","00000","-snapshot",".dat","\xc3\xa9"}) {
            for (const std::string suffix : {".dat",".DAT",".dat.bak","",".",".dat.",".datx"}) {
                const auto name=prefix+middle+suffix;
                BOOST_TEST_CONTEXT(name) {
                    const bool block=(name.rfind("blk",0)==0 || name.rfind("rev",0)==0) &&
                        fs::PathFromString(name).extension()==".dat";
                    BOOST_CHECK_EQUAL(drivechain::haskell::MaterialName(false,name),block);
                    BOOST_CHECK_EQUAL(drivechain::haskell::MaterialName(true,name),name.rfind("chainstate",0)==0);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(deployment_identity_write_callback_exceptions)
{
    const std::vector<uint32_t> success{1,3,4,7,9,11,12};
    for (const auto fault : success) {
        std::vector<uint32_t> seen;
        BOOST_CHECK_EXCEPTION(drivechain::haskell::IdentityWrite([&](uint32_t action) {
            seen.push_back(action);
            if (action==fault) throw std::runtime_error("identity write fixture");
            return true;
        }),std::runtime_error,[](const auto& error) { return std::string(error.what())=="identity write fixture"; });
        const std::vector<uint32_t> expected(success.begin(),std::find(success.begin(),success.end(),fault)+1);
        BOOST_CHECK(seen==expected);
    }
    BOOST_CHECK_THROW(drivechain::haskell::IdentityWrite({}),std::invalid_argument);
}

struct DeploymentChainSetup : TestingSetup {
    DeploymentChainSetup() : TestingSetup(ChainTypeMetaFrom("elementsregtest")) {}
};

BOOST_FIXTURE_TEST_CASE(deployment_identity_rejects_unsafe_side_branch, DeploymentChainSetup)
{
    LOCK(cs_main);
    auto& chainman=*m_node.chainman;
    const auto identity=gArgs.GetDataDirNet() / "ecx_consensus.dat";
    fs::remove(identity); // Only the disposable fixture directory.
    std::string error;
    const auto index_path=gArgs.GetDataDirNet() / "blocks" / "index";
    fs::create_directories(index_path);
    const auto orphan=index_path / "fixture.ldb";
    BOOST_REQUIRE(WriteBinaryFile(orphan,"fixture"));
    chainman.m_blockman.m_blockfiles_indexed=false;
    BOOST_CHECK(!node::BindEcxDeploymentIdentityIfNeeded(chainman,false,error));
    BOOST_CHECK(error.find("block-index reindex is in progress")!=std::string::npos);
    BOOST_CHECK(!fs::exists(identity));
    BOOST_REQUIRE(fs::remove(orphan));
    chainman.m_blockman.m_blockfiles_indexed=true;
    const uint256 hash=uint256S("1234");
    BOOST_REQUIRE(!chainman.m_blockman.LookupBlockIndex(hash));
    CBlockIndex* branch=chainman.m_blockman.InsertBlockIndex(hash);
    struct RemoveBranch {
        node::BlockManager& blocks;
        uint256 hash;
        ~RemoveBranch() { LOCK(cs_main); blocks.m_block_index.erase(hash); }
    } cleanup{chainman.m_blockman,hash};
    branch->pprev=chainman.ActiveChain().Genesis();
    branch->nHeight=1;
    branch->nVersion=CBlockHeader::EXCHANGE_STATE_HF_MASK;
    BOOST_CHECK(node::BindEcxDeploymentIdentityIfNeeded(chainman,true,error));
    BOOST_CHECK(!fs::exists(identity));
    branch->nHeight=std::numeric_limits<int>::max();
    for (const auto flag : {CBlockHeader::BMM_PROOF_HF_MASK,CBlockHeader::EXCHANGE_STATE_HF_MASK,
            CBlockHeader::FORCED_INBOX_HF_MASK,CBlockHeader::DEPOSIT_INBOX_HF_MASK,CBlockHeader::INBOX_CURSOR_HF_MASK}) {
        branch->nVersion=flag;
        BOOST_CHECK(!node::BindEcxDeploymentIdentityIfNeeded(chainman,false,error));
        BOOST_CHECK(error.find("block-index branch already contains an ECX/BMM header")!=std::string::npos);
        BOOST_CHECK(!fs::exists(identity));
    }
    branch->nVersion=0;
    branch->nHeight=std::numeric_limits<int>::max();
    BOOST_CHECK(!node::BindEcxDeploymentIdentityIfNeeded(chainman,false,error));
    BOOST_CHECK(error.find("block-index branch already reaches header")!=std::string::npos);
    BOOST_CHECK(!fs::exists(identity));
    branch->nHeight=1;
    BOOST_REQUIRE_MESSAGE(node::BindEcxDeploymentIdentityIfNeeded(chainman,false,error),error);
    BOOST_CHECK(fs::exists(identity));
    const auto original=ReadBinaryFile(identity).second;
    branch->nVersion=CBlockHeader::EXCHANGE_STATE_HF_MASK;
    BOOST_REQUIRE(WriteBinaryFile(identity,"tampered"));
    BOOST_CHECK(!node::BindEcxDeploymentIdentityIfNeeded(chainman,false,error));
    BOOST_CHECK(error.find("does not match this data directory")!=std::string::npos);
    BOOST_CHECK_EQUAL(ReadBinaryFile(identity).second,"tampered");
    BOOST_REQUIRE(WriteBinaryFile(identity,original));
    branch->nVersion |= CBlockHeader::BMM_PROOF_HF_MASK;
    BOOST_CHECK(!node::BindEcxDeploymentIdentityIfNeeded(chainman,false,error));
    BOOST_CHECK(error.find("violates BMM rules")!=std::string::npos);
    BOOST_CHECK(ReadBinaryFile(identity).second==original);
    branch->nVersion=CBlockHeader::EXCHANGE_STATE_HF_MASK;
    BOOST_CHECK(!node::BindEcxDeploymentIdentityIfNeeded(chainman,false,error));
    BOOST_CHECK(error.find("violates ECX rules")!=std::string::npos);
    BOOST_CHECK(ReadBinaryFile(identity).second==original);
    branch->nVersion=0;
    BOOST_REQUIRE(fs::remove(identity));
    const auto historical_hash=drivechain::LayerTwoLabsPublicSidechainBlock2();
    auto* historical=chainman.m_blockman.InsertBlockIndex(historical_hash);
    BOOST_REQUIRE(historical);
    RemoveBranch historical_cleanup{chainman.m_blockman,historical_hash};
    historical->pprev=chainman.ActiveChain().Genesis();
    historical->nHeight=1;
    historical->nVersion=0;
    BOOST_CHECK(!node::BindEcxDeploymentIdentityIfNeeded(chainman,false,error));
    BOOST_CHECK(error.find("block-index branch already contains an ECX/BMM header")!=std::string::npos);
    BOOST_CHECK(error.find(historical_hash.GetHex())!=std::string::npos);
    BOOST_CHECK(!fs::exists(identity));
}

BOOST_FIXTURE_TEST_CASE(deployment_identity_rejects_persisted_coins_state, DeploymentChainSetup)
{
    auto& chainman=*m_node.chainman;
    const auto identity=gArgs.GetDataDirNet() / "ecx_consensus.dat";
    fs::remove(identity);
    LOCK(cs_main);
    BOOST_REQUIRE(chainman.ActiveChainstate().CoinsTip().Flush());
    auto& coins=chainman.ActiveChainstate().CoinsDB();
    const auto original=coins.GetBestBlock();
    BOOST_REQUIRE(!original.IsNull());
    const auto unknown=uint256S("987654321");
    BOOST_REQUIRE(!chainman.m_blockman.LookupBlockIndex(unknown));
    const auto set_best=[&](const uint256& hash) {
        CCoinsViewCache changes(&coins);
        changes.SetBestBlock(hash);
        BOOST_REQUIRE(changes.Flush());
    };
    set_best(unknown);
    std::string error;
    BOOST_CHECK(!node::BindEcxDeploymentIdentityIfNeeded(chainman,false,error));
    BOOST_CHECK(error.find("coins best block")!=std::string::npos);
    BOOST_CHECK(error.find("absent from the block index")!=std::string::npos);
    BOOST_CHECK(coins.GetBestBlock()==unknown);
    BOOST_CHECK(!fs::exists(identity));

    const COutPoint tracker{Txid::FromUint256(uint256S("e31f7fb1e9489bfb9f6a73c10f80ecdcce1f276fbdf0cf85c02e3bcf174dc041")),0};
    BOOST_REQUIRE(ecx::IsExchangeStateInternalOutpoint(tracker));
    {
        CCoinsViewCache changes(&coins);
        changes.AddCoin(tracker,Coin(CTxOut(policyAsset,1,CScript() << OP_TRUE),1,false),false);
        changes.SetBestBlock(unknown);
        BOOST_REQUIRE(changes.Flush());
    }
    BOOST_REQUIRE(ecx::HasPersistedExchangeConsensusState(coins));
    BOOST_CHECK(!node::BindEcxDeploymentIdentityIfNeeded(chainman,false,error));
    BOOST_CHECK(error.find("chainstate already contains ECX/BMM tracker state")!=std::string::npos);
    BOOST_CHECK(coins.HaveCoin(tracker));
    BOOST_CHECK(coins.GetBestBlock()==unknown);
    BOOST_CHECK(!fs::exists(identity));
    {
        CCoinsViewCache changes(&coins);
        BOOST_REQUIRE(changes.SpendCoin(tracker));
        changes.SetBestBlock(original);
        BOOST_REQUIRE(changes.Flush());
    }
    BOOST_REQUIRE_MESSAGE(node::BindEcxDeploymentIdentityIfNeeded(chainman,false,error),error);
    BOOST_CHECK(fs::exists(identity));
}

BOOST_FIXTURE_TEST_CASE(deployment_identity_preserves_recovery_heads, DeploymentChainSetup)
{
    auto& chainman=*m_node.chainman;
    LOCK(cs_main);
    auto& state=chainman.ActiveChainstate();
    const auto identity=gArgs.GetDataDirNet() / "ecx_consensus.dat";
    fs::remove(identity);
    const auto genesis=state.m_chain.Genesis()->GetBlockHash();
    const auto unknown=uint256S("987654321");
    BOOST_REQUIRE(!chainman.m_blockman.LookupBlockIndex(unknown));
    const fs::path name{"identity-recovery"};
    const auto path=chainman.m_options.datadir / name;
    std::string error;
    for (const unsigned missing : {1U,0U,2U}) {
        state.ResetCoinsViews();
        std::vector<uint256> heads{genesis,genesis};
        if (missing<2) heads[missing]=unknown;
        {
            // Actual txdb recovery keys, written while no coins DB owns the path.
            CDBWrapper db(DBParams{.path=path,.cache_bytes=1<<20,.obfuscate=true});
            BOOST_REQUIRE(db.Erase(uint8_t{'B'}));
            BOOST_REQUIRE(db.Write(uint8_t{'H'},heads));
        }
        state.InitCoinsDB(1<<20,false,false,name);
        BOOST_REQUIRE(state.CoinsDB().GetBestBlock().IsNull());
        BOOST_REQUIRE(state.CoinsDB().GetHeadBlocks()==heads);
        const bool bound=node::BindEcxDeploymentIdentityIfNeeded(chainman,false,error);
        BOOST_CHECK_EQUAL(bound,missing==2);
        if (missing<2) {
            BOOST_CHECK(error.find("coins crash-recovery head "+std::to_string(missing))!=std::string::npos);
            BOOST_CHECK(error.find("absent from the block index")!=std::string::npos);
            BOOST_CHECK(!fs::exists(identity));
        } else {
            BOOST_CHECK(error.empty());
            BOOST_CHECK(fs::exists(identity));
        }
        BOOST_CHECK(state.CoinsDB().GetBestBlock().IsNull());
        BOOST_CHECK(state.CoinsDB().GetHeadBlocks()==heads);
    }
    state.ResetCoinsViews();
    {
        CDBWrapper db(DBParams{.path=path,.cache_bytes=1<<20,.obfuscate=true});
        BOOST_REQUIRE(db.Erase(uint8_t{'H'}));
        BOOST_REQUIRE(db.Write(uint8_t{'B'},genesis));
    }
    state.InitCoinsDB(1<<20,false,false,name);
    state.InitCoinsCache(1<<20);
}

BOOST_AUTO_TEST_CASE(checkpoint_genesis_initialization_is_stable_and_ancestor_bound)
{
    ecx::ExchangeConsensus consensus{};
    auto& frozen{consensus.bond_v2};
    const uint256 hash{uint256S("1234")};
    CBlockIndex anchor;
    anchor.nHeight = 5;
    anchor.phashBlock = &hash;
    DrivechainAnchor parent;
    parent.parent_block_hash = uint256S("11");
    parent.bmm_block_hash = uint256S("12");
    parent.parent_chainwork = uint256S("01");
    parent.bmm_chainwork = uint256S("02");
    parent.parent_height = 10;
    parent.bmm_height = 11;
    parent.parent_median_time_past = 100;
    anchor.m_drivechain_anchor = parent;
    CBlockIndex intermediate;
    intermediate.nHeight = 6;
    intermediate.pprev = &anchor;
    CBlockIndex previous;
    previous.nHeight = 7;
    previous.pprev = &intermediate;
    frozen.genesis_initialization_version = 2;
    frozen.genesis_initialization_height = 5;
    frozen.genesis_initialization_block_hash = hash;
    frozen.genesis_initialization_parent_mtp = 100;
    uint64_t height{0}, mtp{0};
    std::string error;
    const auto resolve = [&](uint32_t creation, uint64_t current) {
        return ecx::ResolveBondV2GenesisInitialization(
            &previous, creation, current, height, mtp, error, consensus);
    };
    BOOST_REQUIRE(resolve(6, 110));
    BOOST_CHECK_EQUAL(height, 5);
    BOOST_CHECK_EQUAL(mtp, 100);
    BOOST_REQUIRE(resolve(7, 120));
    BOOST_CHECK_EQUAL(height, 5);
    BOOST_CHECK_EQUAL(mtp, 100);
    // Equality is allowed: initialization uses the authenticated parent clock,
    // not elapsed wall time or a newly invented timestamp at signing.
    BOOST_REQUIRE(resolve(6, 100));
    BOOST_CHECK_EQUAL(height, 5);
    BOOST_CHECK_EQUAL(mtp, 100);
    const auto reject = [&](uint32_t creation, uint64_t current) {
        height = 999;
        mtp = 999;
        BOOST_CHECK(!resolve(creation, current));
        BOOST_CHECK_EQUAL(height, 0);
        BOOST_CHECK_EQUAL(mtp, 0);
        BOOST_CHECK(!error.empty());
    };
    reject(0, 100);
    reject(6, 0);
    const auto saved_parent = anchor.m_drivechain_anchor;
    anchor.m_drivechain_anchor->parent_block_hash.SetNull();
    reject(6, 100);
    anchor.m_drivechain_anchor = saved_parent;
    // A same-height replacement after reorg is not the frozen ancestor.
    const uint256 replacement_hash{uint256S("5678")};
    anchor.phashBlock = &replacement_hash;
    reject(6, 100);
    anchor.phashBlock = &hash;
    BOOST_REQUIRE(resolve(6, 100));
    BOOST_CHECK(error.empty());
    BOOST_CHECK(!resolve(5, 120));
    BOOST_CHECK(!resolve(8, 120));
    BOOST_CHECK(!resolve(6, 99));
    frozen.genesis_initialization_block_hash = uint256S("99");
    BOOST_CHECK(!resolve(6, 120));
    frozen.genesis_initialization_block_hash = hash;
    anchor.m_drivechain_anchor->parent_median_time_past = 101;
    BOOST_CHECK(!resolve(6, 120));
    anchor.m_drivechain_anchor.reset();
    BOOST_CHECK(!resolve(6, 120));
    frozen.genesis_initialization_version = 1;
    BOOST_CHECK(!resolve(6, 120));
    BOOST_CHECK_EQUAL(height, 0);
    BOOST_CHECK_EQUAL(mtp, 0);
    frozen.genesis_initialization_version = 0;
    reject(6, 120);
    frozen.genesis_initialization_height = 0;
    frozen.genesis_initialization_block_hash.SetNull();
    frozen.genesis_initialization_parent_mtp = 0;
    BOOST_REQUIRE(ecx::ResolveBondV2GenesisInitialization(nullptr, 6, 120, height, mtp, error, consensus));
    BOOST_CHECK_EQUAL(height, 6);
    BOOST_CHECK_EQUAL(mtp, 120);
    BOOST_CHECK(error.empty());
}

BOOST_AUTO_TEST_CASE(genesis_funding_matches_current_rust_band_encoding)
{
    ecx::ExchangeConsensus consensus{};
    consensus.bond_v2.genesis_mark_price = 3'000'000'000;
    uint256 state, bond, funding, covenant;
    BOOST_REQUIRE(ecx::ComputeBondV2EmptyGenesisRoots(
        consensus, 39, 1'700'000'000, state, bond, funding, covenant));
    BOOST_CHECK_EQUAL(funding, RawHash(
        "ae301bba06a2b3ccf1d4fd7c05a2f36fc476e4dd064c0bb30e1fdd857c7550c2"));
    for (unsigned flags = 0; flags < 7; ++flags) {
        state = bond = funding = covenant = uint256S("01");
        consensus.bond_v2.genesis_mark_price = flags & 4 ? 3'000'000'000 : 0;
        BOOST_CHECK(!ecx::ComputeBondV2EmptyGenesisRoots(consensus,
            flags & 1 ? 39 : 0, flags & 2 ? 1'700'000'000 : 0, state, bond, funding, covenant));
        BOOST_CHECK(state.IsNull() && bond.IsNull() && funding.IsNull() && covenant.IsNull());
    }
}

BOOST_AUTO_TEST_CASE(haskell_genesis_funding_matches_native_encoding)
{
    const std::array<uint64_t, 6> values{0, 1, 255, UINT32_MAX, UINT64_C(0x8000000000000000), UINT64_MAX};
    for (auto mtp : values) for (auto price : values) {
        std::vector<unsigned char> expected{2};
        for (auto value : {mtp, price, price, price, mtp, UINT64_MAX}) TestPushU64Be(expected, value);
        expected.insert(expected.end(), 20, 0);
        for (unsigned bucket = 0; bucket < 8; ++bucket) {
            TestPushU64Be(expected, UINT64_MAX);
            expected.push_back(bucket);
            expected.insert(expected.end(), 64, 0);
            TestPushU64Be(expected, 0);
            expected.push_back(0);
        }
        const auto actual = drivechain::haskell::ExchangeGenesisFunding(mtp, price);
        BOOST_REQUIRE_EQUAL(actual.size(), 725);
        BOOST_CHECK_EQUAL_COLLECTIONS(actual.begin(), actual.end(), expected.begin(), expected.end());
    }
}

BOOST_AUTO_TEST_CASE(haskell_fixed_profiles_match_native_layout)
{
    using namespace drivechain::haskell;
    std::vector<unsigned char> profile{'E','C','X','W','I','T','1',0,0,1,3,5,0,0,0,0,1,0,0,0};
    for (const std::string& name : {"XChaCha20-Poly1305","HKDF-SHA256","X25519",
        "Ristretto255-Feldman","Ed25519","ECX/witness-bundle-root/v1",
        "ECX/witness-bundle-header/v1","ECX/witness-payload-aad/v1","ECX/witness-share-aad/v1",
        "ECX/witness-payload-key/v1","ECX/witness-share-key/v1","ECX/witness-custodian-attestation/v1",
        "ECX/witness-custody-receipt/v1","ECX/witness-share-hash/v1"}) {
        for (int shift=24; shift>=0; shift-=8) profile.push_back((name.size()>>shift)&255);
        profile.insert(profile.end(),name.begin(),name.end());
    }
    BOOST_REQUIRE_EQUAL(profile.size(),383U);
    BOOST_CHECK(ExchangeGenesisState(GenesisCodec::AVAILABILITY_SCHEME,0,0,{})==profile);
    const std::string layout="version:u8|bundle_root:32|context:32|witness_len:u64be|custodian_index:u8(1..5)|ed25519_signature:64";
    BOOST_CHECK(ExchangeGenesisState(GenesisCodec::CUSTODY_RECEIPT,0,0,{})==std::vector<unsigned char>(layout.begin(),layout.end()));
    for (const auto codec : {GenesisCodec::AVAILABILITY_SCHEME,GenesisCodec::CUSTODY_RECEIPT}) {
        BOOST_CHECK_THROW(ExchangeGenesisState(codec,0,0,{profile.data()}),std::runtime_error);
    }
}

BOOST_AUTO_TEST_CASE(haskell_genesis_state_codecs_match_native_layout)
{
    std::array<std::array<unsigned char, 32>, 8> hashes{};
    for (unsigned i = 0; i < hashes.size(); ++i) hashes[i].fill(i+1);
    const std::vector<unsigned char> bond(242, 0x71), funding(725, 0x72);
    const std::array<uint64_t, 3> values{0, 1, UINT64_MAX};
    for (bool private_state : {false, true}) for (auto height : values) for (auto price : values) {
        std::vector<unsigned char> expected{2};
        const auto append = [&](unsigned i) { expected.insert(expected.end(), hashes[i].begin(), hashes[i].end()); };
        if (private_state) {
            expected.push_back(4);
            append(0);
            const std::array<unsigned char, 16> market{'E','C','X','-','U','S','D','D','-','P','E','R','P',0,0,0};
            expected.insert(expected.end(), market.begin(), market.end());
            TestPushU64Be(expected, 0); TestPushU64Be(expected, height); TestPushU64Be(expected, price);
            expected.insert(expected.end(), 80, 0); TestPushU64Be(expected, 0); append(1);
            for (unsigned i : {2,3}) { append(i); TestPushU64Be(expected, 0); append(i); TestPushU64Be(expected, 0); }
            for (unsigned i = 0; i < 5; ++i) append(4);
            append(5);
            expected.insert(expected.end(), bond.begin(), bond.end());
            expected.insert(expected.end(), funding.begin(), funding.end());
            TestPushU64Be(expected, 0); TestPushU64Be(expected, height);
            append(6); TestPushU64Be(expected, 0); append(6); TestPushU64Be(expected, 0);
            append(7); TestPushU64Be(expected, 0); append(4); append(4);
        } else {
            append(0); append(1); append(2); expected.insert(expected.end(), 16, 0);
            TestPushU64Be(expected, 2100000000000000ULL); TestPushU64Be(expected, 0);
            TestPushU64Be(expected, 2100000000000000ULL); expected.insert(expected.end(), 48, 0);
            append(3); expected.insert(expected.end(), 25, 0);
        }
        const auto actual = private_state ? drivechain::haskell::ExchangeGenesisState(drivechain::haskell::GenesisCodec::PRIVATE_STATE, height, price,
            {hashes[0].data(), hashes[1].data(), hashes[2].data(), hashes[3].data(), hashes[4].data(), hashes[5].data(), hashes[6].data(), hashes[7].data()}, bond, funding) :
            drivechain::haskell::ExchangeGenesisState(drivechain::haskell::GenesisCodec::BOND, height, price, {hashes[0].data(), hashes[1].data(), hashes[2].data(), hashes[3].data()});
        BOOST_REQUIRE_EQUAL(actual.size(), private_state ? 1713 : 242);
        BOOST_CHECK_EQUAL_COLLECTIONS(actual.begin(), actual.end(), expected.begin(), expected.end());
    }
    BOOST_CHECK_THROW(drivechain::haskell::ExchangeGenesisState(drivechain::haskell::GenesisCodec::BOND, 0, 0, {}), std::runtime_error);
    BOOST_CHECK_THROW(drivechain::haskell::ExchangeGenesisState(drivechain::haskell::GenesisCodec::BOND, 0, 0,
        {hashes[0].data(), hashes[1].data(), nullptr, hashes[3].data()}), std::runtime_error);
    BOOST_CHECK_THROW(drivechain::haskell::ExchangeGenesisState(drivechain::haskell::GenesisCodec::PRIVATE_STATE, 0, 0,
        {hashes[0].data(), hashes[1].data(), hashes[2].data(), hashes[3].data(), hashes[4].data(), hashes[5].data(), hashes[6].data(), hashes[7].data()}), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(haskell_genesis_roots_preserve_composed_encodings_and_failures)
{
    using Bytes=std::vector<unsigned char>;
    using Digest=std::array<unsigned char,32>;
    FastRandomContext random{true};
    for (unsigned sample=0;sample<64;++sample) for (int zero_kind : {-1,0,1,2,3,4,5,6,7,8,9}) {
        std::array<Digest,12> fields;
        for (auto& field : fields) for (auto& byte : field) byte=random.randbits(8);
        const uint64_t height=sample==0 ? 0 : sample==1 ? UINT64_MAX : random.rand64();
        const uint64_t mtp=sample==0 ? 0 : sample==1 ? UINT64_MAX : random.rand64();
        const uint64_t price=sample==0 ? 0 : sample==1 ? UINT64_MAX : random.rand64();
        std::vector<std::pair<uint32_t,Bytes>> expected_calls;
        const auto hash=[&](uint32_t kind,std::span<const unsigned char> bytes) {
            expected_calls.emplace_back(kind,Bytes(bytes.begin(),bytes.end()));
            Digest digest{};
            const unsigned char domain=kind;
            if (static_cast<int>(kind)!=zero_kind) CSHA256().Write(&domain,1).Write(bytes.data(),bytes.size()).Finalize(digest.data());
            return digest;
        };
        const auto concatenate=[](std::initializer_list<Digest> hashes) {
            Bytes result;
            for (const auto& h : hashes) result.insert(result.end(),h.begin(),h.end());
            return result;
        };
        const auto zero=[](const Digest& digest) { return std::all_of(digest.begin(),digest.end(),[](auto b) { return b==0; }); };
        const auto queue=hash(0,{});
        const auto bond=drivechain::haskell::ExchangeGenesisState(drivechain::haskell::GenesisCodec::BOND,0,0,
            {fields[0].data(),fields[1].data(),fields[2].data(),queue.data()});
        const auto bond_root=hash(1,bond);
        const auto funding=drivechain::haskell::ExchangeGenesisFunding(mtp,price);
        const auto funding_root=hash(2,funding);
        Digest private_root{}, covenant_root{};
        if (!zero(bond_root) && !zero(funding_root)) {
            const auto empty=hash(3,{}), forced=hash(4,concatenate({fields[6],fields[3]})),
                deposits=hash(5,concatenate({fields[7],fields[3]})), inbox=hash(6,concatenate({fields[8],fields[3],fields[9]})),
                outcome=hash(7,concatenate({fields[8],fields[3],fields[9]}));
            const auto state=drivechain::haskell::ExchangeGenesisState(drivechain::haskell::GenesisCodec::PRIVATE_STATE,height,price,
                {fields[3].data(),fields[4].data(),forced.data(),deposits.data(),empty.data(),fields[5].data(),inbox.data(),outcome.data()},bond,funding);
            private_root=hash(8,state);
            if (!zero(private_root)) {
                const auto covenant=drivechain::haskell::ExchangeGenesisState(drivechain::haskell::GenesisCodec::COVENANT,height,0,
                    {fields[10].data(),private_root.data(),fields[11].data(),forced.data(),deposits.data(),fields[9].data(),
                     bond_root.data(),funding_root.data(),empty.data(),inbox.data(),outcome.data()});
                covenant_root=hash(9,covenant);
            }
        }
        const auto call=[&](const drivechain::haskell::CustodyHash& callback) {
            return drivechain::haskell::ExchangeGenesisRoots(height,mtp,price,
                {fields[0].data(),fields[1].data(),fields[2].data(),fields[3].data(),fields[4].data(),fields[5].data(),
                 fields[6].data(),fields[7].data(),fields[8].data(),fields[9].data(),fields[10].data(),fields[11].data()},callback);
        };
        const auto reference_calls=expected_calls;
        expected_calls.clear();
        const auto actual=call(hash);
        BOOST_CHECK(expected_calls==reference_calls);
        BOOST_CHECK_EQUAL(HexStr(actual),HexStr(concatenate({private_root,bond_root,funding_root,covenant_root})));
        if (sample==0 && zero_kind==-1) for (uint32_t fail=0;fail<10;++fail) {
            uint32_t calls=0;
            BOOST_CHECK_EXCEPTION(call([&](uint32_t kind,std::span<const unsigned char>) {
                BOOST_CHECK_EQUAL(kind,calls++);
                if (kind==fail) throw std::runtime_error("genesis injected failure");
                Digest digest; digest.fill(1); return digest;
            }),std::runtime_error,[](const auto& e) { return std::string(e.what())=="genesis injected failure"; });
            BOOST_CHECK_EQUAL(calls,fail+1);
        }
    }
}

BOOST_AUTO_TEST_CASE(haskell_genesis_covenant_matches_native_layout)
{
    std::array<std::array<unsigned char, 32>, 11> hashes{};
    for (unsigned i = 0; i < hashes.size(); ++i) hashes[i].fill(i+1);
    const std::array<uint64_t, 4> heights{0, 1, UINT32_MAX, UINT64_MAX};
    for (auto height : heights) {
        std::vector<unsigned char> expected;
        const auto append = [&](unsigned i) { expected.insert(expected.end(), hashes[i].begin(), hashes[i].end()); };
        append(0); TestPushU32Be(expected, 4); TestPushU64Be(expected, 0);
        for (unsigned i = 1; i < 8; ++i) append(i);
        append(8); append(8); append(9); TestPushU64Be(expected, 0);
        append(9); TestPushU64Be(expected, 0); append(10); TestPushU64Be(expected, 0);
        TestPushU64Be(expected, 0); TestPushU64Be(expected, height);
        const auto actual = drivechain::haskell::ExchangeGenesisState(drivechain::haskell::GenesisCodec::COVENANT, height, 0,
            {hashes[0].data(), hashes[1].data(), hashes[2].data(), hashes[3].data(), hashes[4].data(), hashes[5].data(),
             hashes[6].data(), hashes[7].data(), hashes[8].data(), hashes[9].data(), hashes[10].data()});
        BOOST_REQUIRE_EQUAL(actual.size(), 468);
        BOOST_CHECK_EQUAL_COLLECTIONS(actual.begin(), actual.end(), expected.begin(), expected.end());
    }
    BOOST_CHECK_THROW(drivechain::haskell::ExchangeGenesisState(static_cast<drivechain::haskell::GenesisCodec>(8), 0, 0, {}), std::runtime_error);
    BOOST_CHECK_THROW(drivechain::haskell::ExchangeGenesisState(drivechain::haskell::GenesisCodec::COVENANT, 0, 0, {}), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(haskell_marker_claims_match_identity_quorum_and_staging_rules)
{
    namespace hs = drivechain::haskell;
    std::array<unsigned char,32> identity{};
    for (unsigned kind = 0; kind < 4; ++kind) {
        std::vector<unsigned char> payload(503,0);
        for (size_t offset : {70U,102U,210U,306U,370U,407U}) payload[offset] = 1;
        payload[5] = kind;
        payload[405] = 1;
        if (kind == 1) payload[134] = payload[170] = payload[209] = 1;
        else std::fill(payload.begin()+166,payload.begin()+170,255);
        std::string error;
        const auto check = [&] { return hs::ExchangeBondMarker(1,payload,
            {identity.data(),identity.data(),identity.data(),identity.data()},error); };
        for (unsigned bitmap = 0; bitmap < 256; ++bitmap) {
            payload[406] = bitmap;
            error = "unchanged";
            const bool valid = bitmap < 32 && std::popcount(bitmap) >= 3;
            BOOST_CHECK_EQUAL(check(),valid);
            BOOST_CHECK_EQUAL(error,valid ? "unchanged" : "ECX bond-inbox marker identities/availability claim are invalid");
        }
        payload[406] = 7;
        for (size_t offset : {6U,38U,70U,102U,210U,242U,274U,306U,370U,407U}) {
            payload[offset] ^= 1;
            BOOST_CHECK(!check());
            BOOST_CHECK_EQUAL(error,"ECX bond-inbox marker identities/availability claim are invalid");
            payload[offset] ^= 1;
        }
        for (size_t offset : {134U,166U,170U,209U}) {
            const auto old = payload[offset];
            payload[offset] = kind == 1 ? 0 : 1;
            if (offset == 166 && kind == 1) std::fill(payload.begin()+166,payload.begin()+170,255);
            BOOST_CHECK(!check());
            BOOST_CHECK_EQUAL(error,"ECX bond-inbox marker staging sentinels are invalid");
            payload[offset] = old;
            if (offset == 166 && kind == 1) std::fill(payload.begin()+166,payload.begin()+170,0);
        }
    }
}

BOOST_AUTO_TEST_CASE(haskell_marker_bounds_preserve_order_and_deadline)
{
    std::array<unsigned char,32> hash{};
    std::array<unsigned char,16> count{};
    std::vector<unsigned char> script{106,77,247,1,69,67,88,66,1,0};
    script.resize(507);
    for (uint64_t successor : {0U,1U}) for (unsigned mask = 0; mask < 128; ++mask) {
        script[8] = successor ? 3 : 1;
        std::array<uint64_t,14> fields{successor,10,6,1,4,14,0,8,0,0,0,1,1,1};
        if (mask & 1) fields[1] = UINT64_MAX;
        if (mask & 2) fields[4] = UINT64_MAX;
        if (mask & 4) fields[5] = 0;
        if (mask & 8) fields[6] = 8;
        if (mask & 16) fields[8] = UINT64_MAX;
        if (mask & 32) fields[9] = uint64_t{UINT32_MAX}+1;
        if (mask & 64) fields[10] = uint64_t{UINT32_MAX}+1;
        const int code = (mask & 1) ? 1 : (mask & 6) ? 2 :
            ((mask & (8|32|64)) || (!successor && (mask & 16))) ? 3 : 0;
        uint64_t deadline{123};
        std::string error{"unchanged"};
        std::array<unsigned char,48> state;
        state.fill(0xa5);
        std::vector<uint32_t> effects;
        BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeAppendMarker(fields,
            {hash.data(),hash.data(),hash.data(),hash.data(),hash.data()},count,script,
            [&](uint32_t action, auto bytes, auto digest) {
                effects.push_back(action);
                if (action == 0) deadline = ReadBE64(bytes.data());
                else std::fill(digest.begin(),digest.end(),0);
            },state,error), code == 0);
        BOOST_CHECK_EQUAL(deadline, code == 0 ? 16U : 123U);
        BOOST_CHECK(effects == (code == 0 ? std::vector<uint32_t>{0,1,2} : std::vector<uint32_t>{}));
        if (code) BOOST_CHECK(std::all_of(state.begin(),state.end(),[](auto byte) { return byte == 0xa5; }));
        static const std::array<std::string,4> finite{"unchanged","ECX bond-inbox process deadline overflows u64",
            "ECX bond-inbox enqueue refund boundary is earlier than the frozen observed-parent delay",
            "ECX bond-inbox block exceeds its marker/index bounds"};
        static const std::array<std::string,4> next{"unchanged","ECX successor bond-inbox process deadline overflows u64",
            "ECX successor bond-inbox enqueue refund boundary is too early",
            "ECX successor bond-inbox block exceeds marker/index bounds"};
        BOOST_CHECK_EQUAL(error,(successor ? next : finite)[code]);
    }
    std::string error{"unchanged"};
    std::array<unsigned char,48> state{};
    BOOST_CHECK_THROW(drivechain::haskell::ExchangeAppendMarker({2},
        {hash.data(),hash.data(),hash.data(),hash.data(),hash.data()},count,script,
        [](uint32_t, auto, auto) { BOOST_FAIL("invalid profile invoked an effect"); },state,error),std::runtime_error);
    BOOST_CHECK_EQUAL(error,"unchanged");
    script[8] = 1;
    for (uint32_t failure : {0U,1U,2U}) {
        state.fill(0xa5);
        std::vector<uint32_t> effects;
        BOOST_CHECK_THROW(drivechain::haskell::ExchangeAppendMarker({0,10,6,0,0,0,0,8,0,0,0,1,1,1},
            {hash.data(),hash.data(),hash.data(),hash.data(),hash.data()},count,script,
            [&](uint32_t action, auto, auto digest) {
                effects.push_back(action);
                if (action == failure) throw std::runtime_error("injected append effect failure");
                std::fill(digest.begin(),digest.end(),0);
            },state,error),std::runtime_error);
        BOOST_REQUIRE_EQUAL(effects.size(),failure+1);
        BOOST_CHECK_EQUAL(effects.back(),failure);
        BOOST_CHECK(std::all_of(state.begin(),state.end(),[](auto byte) { return byte == 0xa5; }));
        BOOST_CHECK_EQUAL(error,"unchanged");
    }
}

BOOST_AUTO_TEST_CASE(haskell_source_tracker_preserves_failure_state)
{
    for (bool successor : {false,true}) for (uint32_t initial : {0U,1U,UINT32_MAX})
    for (uint32_t addition : {0U,1U,UINT32_MAX}) for (uint32_t cap : {0U,1U,UINT32_MAX})
    for (bool transaction_side : {false,true}) {
        std::vector<unsigned char> state(8);
        WriteBE32(state.data(), transaction_side ? 0 : initial);
        WriteBE32(state.data()+4, transaction_side ? initial : 0);
        const auto before = state;
        std::array<unsigned char,32> hash{};
        const uint32_t aw = transaction_side ? 0 : addition, at = transaction_side ? addition : 0;
        const uint64_t sum = uint64_t{initial} + addition;
        const bool overflow = sum > UINT32_MAX;
        const bool accepted = !overflow && sum <= cap;
        std::string error{"unchanged"};
        BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeTrackSource(successor,{aw,at,cap,cap},
            {hash.data(),hash.data(),hash.data()},state,error), accepted);
        if (!accepted) BOOST_CHECK(state == before);
        BOOST_CHECK_EQUAL(ReadBE32(state.data()+(transaction_side ? 4 : 0)), accepted ? sum : initial);
        BOOST_CHECK_EQUAL(ReadBE32(state.data()+(transaction_side ? 0 : 4)), 0U);
        const std::string prefix = successor ? "ECX successor bond-inbox block " : "ECX bond-inbox block ";
        BOOST_CHECK_EQUAL(error, accepted ? "unchanged" : prefix + (overflow ? "source byte accounting overflowed" :
            successor ? "exceeds source byte caps" : "exceeds deduplicated source byte caps"));
    }
}

BOOST_AUTO_TEST_CASE(haskell_inbox_entries_match_native_serialization)
{
    namespace hs = drivechain::haskell;
    std::array<unsigned char, 160> hashes{};
    for (size_t i = 0; i < hashes.size(); ++i) hashes[i] = static_cast<unsigned char>(i);
    for (bool deposit : {false, true}) for (uint64_t value : {uint64_t{0}, uint64_t{1}, UINT64_MAX}) {
        const uint32_t vout = static_cast<uint32_t>(value);
        const uint64_t extra = deposit ? vout : static_cast<uint8_t>(value);
        for (size_t length : {0U, 1U, 64U}) {
            std::vector<unsigned char> body(deposit ? 0 : length, 0xa5);
            std::vector<unsigned char> expected{1};
            expected.insert(expected.end(), hashes.begin(), hashes.begin()+32);
            TestPushU64Be(expected, value);
            expected.insert(expected.end(), hashes.begin()+32, hashes.begin()+64);
            TestPushU64Be(expected, value);
            TestPushU64Be(expected, value);
            expected.insert(expected.end(), hashes.begin()+64, hashes.begin()+96);
            TestPushU32Be(expected, vout);
            if (deposit) {
                TestPushU32Be(expected, extra);
                expected.insert(expected.end(), hashes.begin()+96, hashes.end());
            } else {
                expected.push_back(extra);
                expected.insert(expected.end(), body.begin(), body.end());
            }
            const auto keys = deposit ? std::initializer_list<const unsigned char*>{hashes.data(), hashes.data()+32, hashes.data()+64, hashes.data()+96, hashes.data()+128} :
                std::initializer_list<const unsigned char*>{hashes.data(), hashes.data()+32, hashes.data()+64};
            BOOST_CHECK(hs::ExchangeInboxEntry(deposit ? hs::InboxCodec::DEPOSIT : hs::InboxCodec::FORCED,
                {value,value,value,vout,extra}, keys, body) == expected);
        }
    }
    BOOST_CHECK_THROW(hs::ExchangeInboxEntry(hs::InboxCodec::FORCED, {0,0,0,0,256},
        {hashes.data(), hashes.data()+32, hashes.data()+64}), std::runtime_error);
    BOOST_CHECK_THROW(hs::ExchangeInboxEntry(hs::InboxCodec::DEPOSIT, {0,0,0,UINT64_MAX,0},
        {hashes.data(), hashes.data()+32, hashes.data()+64, hashes.data()+96, hashes.data()+128}), std::runtime_error);
    BOOST_CHECK_THROW(hs::ExchangeInboxEntry(hs::InboxCodec::FORCED, {}, {nullptr,hashes.data(),hashes.data()}), std::runtime_error);
    for (uint64_t count : {uint64_t{0}, uint64_t{1}, UINT64_MAX}) {
        std::vector<unsigned char> expected(hashes.begin(), hashes.begin()+32);
        TestPushU64Be(expected, count);
        expected.insert(expected.end(), hashes.begin()+32, hashes.begin()+64);
        BOOST_CHECK(hs::ExchangeInboxEntry(hs::InboxCodec::STEP, {count}, {hashes.data(),hashes.data()+32}) == expected);
    }
    std::vector<unsigned char> wide(hashes.begin(), hashes.begin()+32);
    wide.insert(wide.end(), hashes.begin()+64, hashes.begin()+80);
    wide.insert(wide.end(), hashes.begin()+32, hashes.begin()+64);
    BOOST_CHECK(hs::ExchangeInboxEntry(hs::InboxCodec::WIDE_STEP, {}, {hashes.data(),hashes.data()+32},
        std::span<const unsigned char>{hashes.data()+64,16}) == wide);
    BOOST_CHECK_THROW(hs::ExchangeInboxEntry(hs::InboxCodec::WIDE_STEP, {}, {hashes.data(),hashes.data()+32}), std::runtime_error);
    BOOST_CHECK_THROW(hs::ExchangeInboxEntry(static_cast<hs::InboxCodec>(7), {}, {}), std::runtime_error);
    for (bool wide_bond : {false,true}) for (uint64_t count : {uint64_t{0},uint64_t{1},UINT64_MAX}) {
        std::vector<unsigned char> body(wide_bond ? 515 : 499,0xa5);
        std::vector<unsigned char> expected{static_cast<unsigned char>(wide_bond ? 2 : 1)};
        if (wide_bond) expected.insert(expected.end(),body.begin(),body.begin()+16);
        else TestPushU64Be(expected,count);
        expected.insert(expected.end(),hashes.begin(),hashes.begin()+32);
        TestPushU64Be(expected,count);
        TestPushU64Be(expected,count);
        expected.insert(expected.end(),hashes.begin()+32,hashes.begin()+128);
        TestPushU32Be(expected,UINT32_MAX);
        expected.insert(expected.end(),hashes.begin()+128,hashes.end());
        for (unsigned i = 0; i < 3; ++i) TestPushU32Be(expected,UINT32_MAX);
        expected.insert(expected.end(),499,0xa5);
        const auto codec = wide_bond ? hs::InboxCodec::WIDE_BOND : hs::InboxCodec::BOND;
        BOOST_CHECK(hs::ExchangeInboxEntry(codec,{count,count,count,UINT32_MAX,UINT32_MAX,UINT32_MAX,UINT32_MAX},
            {hashes.data(),hashes.data()+32,hashes.data()+64,hashes.data()+96,hashes.data()+128},body) == expected);
    }
}

BOOST_AUTO_TEST_CASE(haskell_registry_codec_preserves_partial_configuration)
{
    using Keys = std::array<std::array<unsigned char,32>,5>;
    Keys encryption,attestation;
    std::vector<unsigned char> canonical;
    for (size_t i=0;i<5;++i) {
        encryption[i].fill(i+10); attestation[i].fill(i+20);
        canonical.push_back(i+1);
        canonical.insert(canonical.end(),encryption[i].begin(),encryption[i].end());
        canonical.insert(canonical.end(),attestation[i].begin(),attestation[i].end());
    }
    BOOST_CHECK(drivechain::haskell::ExchangeRegistryEncoding(encryption,attestation)==canonical);
    const auto check = [&](const std::vector<unsigned char>& bytes) {
        Keys expected_encryption,expected_attestation;
        for (auto& key : expected_encryption) key.fill(0xa5);
        for (auto& key : expected_attestation) key.fill(0x5a);
        auto actual_encryption=expected_encryption,actual_attestation=expected_attestation;
        std::string expected_error;
        for (size_t i=0;i<5;++i) {
            const auto offset=i*65;
            const auto zero = [&](size_t start) { return std::all_of(bytes.begin()+start,bytes.begin()+start+32,[](auto b) { return b==0; }); };
            if (bytes[offset]!=i+1 || zero(offset+1) || zero(offset+33)) {
                expected_error="ECX bond V2 custodian registry indices/keys are noncanonical"; break;
            }
            std::copy_n(bytes.data()+offset+1,32,expected_encryption[i].begin());
            std::copy_n(bytes.data()+offset+33,32,expected_attestation[i].begin());
            for (size_t prior=0;prior<i;++prior) if (expected_encryption[i]==expected_encryption[prior] || expected_attestation[i]==expected_attestation[prior]) {
                expected_error="ECX bond V2 custodian registry contains duplicate keys"; break;
            }
            if (!expected_error.empty()) break;
        }
        std::string actual_error;
        try { drivechain::haskell::ExchangeRegistryDecoding(bytes,actual_encryption,actual_attestation); }
        catch (const std::runtime_error& error) { actual_error=error.what(); }
        BOOST_CHECK_EQUAL(actual_error,expected_error);
        BOOST_CHECK(actual_encryption==expected_encryption);
        BOOST_CHECK(actual_attestation==expected_attestation);
    };
    check(canonical);
    for (size_t i=0;i<325;++i) for (unsigned char value : {0,1,2,5,255}) {
        auto mutated=canonical; mutated[i]=value; check(mutated);
    }
    for (size_t i=0;i<5;++i) for (size_t role : {1U,33U}) {
        auto zeroed=canonical; std::fill_n(zeroed.begin()+i*65+role,32,0); check(zeroed);
        for (size_t prior=0;prior<i;++prior) {
            auto duplicate=canonical;
            std::copy_n(duplicate.begin()+prior*65+role,32,duplicate.begin()+i*65+role);
            check(duplicate);
            if (i<4) { duplicate[(i+1)*65]=0; check(duplicate); }
        }
    }
}

BOOST_AUTO_TEST_CASE(haskell_source_authorization_matches_native_preimages)
{
    namespace hs=drivechain::haskell;
    std::array<unsigned char,128> hashes;
    for (size_t i=0;i<hashes.size();++i) hashes[i]=i;
    for (uint64_t value : {uint64_t{0},uint64_t{1},uint64_t{UINT32_MAX},uint64_t{UINT32_MAX}+1,UINT64_MAX}) {
        std::vector<unsigned char> expected(hashes.begin(),hashes.end());
        TestPushU32Be(expected,static_cast<uint32_t>(value));
        BOOST_CHECK(hs::ExchangeInboxEntry(hs::InboxCodec::NO_STAGING_AUTH,{value},
            {hashes.data(),hashes.data()+32,hashes.data()+64,hashes.data()+96})==expected);
        for (size_t size : {1U,34U,128U,65536U}) {
            std::vector<unsigned char> body(size);
            for (size_t i=0;i<size;++i) body[i]=i;
            expected.clear(); TestPushU32Be(expected,size);
            expected.insert(expected.end(),body.begin(),body.end());
            expected.insert(expected.end(),hashes.begin(),hashes.begin()+64);
            TestPushU64Be(expected,value);
            BOOST_CHECK(hs::ExchangeInboxEntry(hs::InboxCodec::STAGING_AUTH,{value},
                {hashes.data(),hashes.data()+32},body)==expected);
        }
    }
    BOOST_CHECK_THROW(hs::ExchangeInboxEntry(hs::InboxCodec::STAGING_AUTH,{},
        {hashes.data(),hashes.data()+32},{}),std::runtime_error);
    BOOST_CHECK_THROW(hs::ExchangeInboxEntry(hs::InboxCodec::NO_STAGING_AUTH,{},
        {hashes.data(),hashes.data()+32}),std::runtime_error);
}

BOOST_AUTO_TEST_CASE(haskell_source_admission_preserves_profile_shape_and_size_order)
{
    const std::array<uint64_t,16> baseline{1,1,1,1,1,65536,8,589824,786432,1,1,1,1,1,786432,589824};
    const std::array<const char*,5> errors{"unchanged","ECX bond-inbox relay profile is not frozen",
        "ECX bond-inbox source transaction has an invalid input/output/witness form",
        "ECX bond-inbox source transaction exceeds its frozen exact byte cap",
        "ECX bond-inbox source witness exceeds its frozen exact byte cap"};
    const auto check = [&](const std::array<uint64_t,16>& fields) {
        size_t failed=0;
        while (failed<14 && fields[failed]==baseline[failed]) ++failed;
        if (failed==14 && fields[14]>0 && fields[14]<=fields[8]) ++failed;
        if (failed==15 && fields[15]>0 && fields[15]<=fields[7]) ++failed;
        const unsigned code=failed==16 ? 0 : failed<9 ? 1 : failed<14 ? 2 : failed-11;
        size_t reads=0;
        std::string error=errors[0];
        BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeSourceAdmission([&](uint64_t step) {
            BOOST_CHECK_EQUAL(step,reads++); return fields.at(step);
        },error),code==0);
        BOOST_CHECK_EQUAL(reads,std::min(failed+1,size_t{16}));
        BOOST_CHECK_EQUAL(error,errors[code]);
    };
    for (unsigned mask=0;mask<65536;++mask) {
        auto fields=baseline;
        for (unsigned i=0;i<16;++i) if (!(mask&(1U<<i))) fields[i]=0;
        check(fields);
    }
    for (size_t i=0;i<16;++i) {
        for (uint64_t value : {uint64_t{0},uint64_t{1},baseline[i]-1,baseline[i]+1,UINT64_MAX}) {
            auto fields=baseline; fields[i]=value; check(fields);
        }
        size_t reads=0;
        std::string error="unchanged";
        BOOST_CHECK_EXCEPTION(drivechain::haskell::ExchangeSourceAdmission([&](uint64_t step) {
            ++reads;
            if (step==i) throw std::runtime_error("source serialization/read failed");
            return baseline.at(step);
        },error),std::runtime_error,[](const auto& failure) { return std::string(failure.what())=="source serialization/read failed"; });
        BOOST_CHECK_EQUAL(reads,i+1);
        BOOST_CHECK_EQUAL(error,"unchanged");
    }
}

BOOST_AUTO_TEST_CASE(haskell_custody_root_matches_native_tree_and_effects)
{
    using Digest = std::array<unsigned char,32>;
    using Trace = std::vector<std::pair<uint32_t,std::vector<unsigned char>>>;
    Digest zero{};
    const auto no_hash = [](uint32_t,std::span<const unsigned char>) { BOOST_FAIL("invalid root performed hashing"); return Digest{}; };
    for (size_t size : {1U,137U,139U,691U,828U}) {
        const std::vector<unsigned char> invalid(size,0);
        BOOST_CHECK_THROW(drivechain::haskell::ExchangeCustodyRoot(1,
            {zero.data(),zero.data(),zero.data(),zero.data(),zero.data(),zero.data()},invalid,no_hash),std::runtime_error);
    }
    BOOST_CHECK_THROW(drivechain::haskell::ExchangeCustodyRoot(UINT64_MAX,
        {zero.data(),zero.data(),zero.data(),zero.data(),zero.data(),zero.data()},{},no_hash),std::runtime_error);
    BOOST_CHECK_THROW(drivechain::haskell::ExchangeCustodyRoot(1,{}, {},no_hash),std::invalid_argument);
    for (unsigned count=0;count<=5;++count) for (unsigned seed=0;seed<16;++seed) {
        std::array<Digest,6> identities;
        for (size_t field=0;field<6;++field) for (size_t byte=0;byte<32;++byte) identities[field][byte]=seed+field*32+byte;
        std::vector<unsigned char> receipts(count*138);
        for (size_t byte=0;byte<receipts.size();++byte) receipts[byte]=seed+byte;
        const uint32_t bundle=seed ? seed*65536 : UINT32_MAX;
        const auto hash = [](uint32_t kind,std::span<const unsigned char> bytes) {
            Digest result;
            const unsigned char tag=kind;
            CSHA256().Write(&tag,1).Write(bytes.data(),bytes.size()).Finalize(result.data());
            return result;
        };
        Trace expected_trace;
        const auto reference_hash = [&](uint32_t kind,const std::vector<unsigned char>& bytes) {
            expected_trace.emplace_back(kind,bytes); return hash(kind,bytes);
        };
        std::vector<Digest> leaves;
        for (size_t i=0;i<count;++i) {
            const std::vector<unsigned char> receipt{receipts.begin()+i*138,receipts.begin()+(i+1)*138};
            std::vector<unsigned char> binding;
            for (size_t field=0;field<4;++field) binding.insert(binding.end(),identities[field].begin(),identities[field].end());
            TestPushU32Be(binding,bundle);
            for (size_t field=4;field<6;++field) binding.insert(binding.end(),identities[field].begin(),identities[field].end());
            binding.push_back(receipt[73]-1);
            const auto digest=reference_hash(0,binding);
            std::vector<unsigned char> exact(digest.begin(),digest.end());
            TestPushU32Be(exact,receipt.size());
            exact.insert(exact.end(),receipt.begin(),receipt.end());
            leaves.push_back(reference_hash(1,exact));
        }
        Digest expected;
        if (leaves.empty()) expected=reference_hash(2,{});
        else {
            std::vector<Digest> nodes;
            for (size_t i=0;i<leaves.size();++i) {
                std::vector<unsigned char> leaf; TestPushU64Be(leaf,i);
                leaf.insert(leaf.end(),leaves[i].begin(),leaves[i].end());
                nodes.push_back(reference_hash(3,leaf));
            }
            size_t width=1; while (width<nodes.size()) width<<=1;
            nodes.resize(width,reference_hash(4,{}));
            while (nodes.size()>1) {
                std::vector<Digest> next;
                for (size_t i=0;i<nodes.size();i+=2) {
                    std::vector<unsigned char> branch(nodes[i].begin(),nodes[i].end());
                    branch.insert(branch.end(),nodes[i+1].begin(),nodes[i+1].end());
                    next.push_back(reference_hash(5,branch));
                }
                nodes=std::move(next);
            }
            expected=nodes.front();
        }
        Trace observed;
        const auto run = [&](const drivechain::haskell::CustodyHash& callback) {
            return drivechain::haskell::ExchangeCustodyRoot(bundle,{identities[0].data(),identities[1].data(),identities[2].data(),
                identities[3].data(),identities[4].data(),identities[5].data()},receipts,callback);
        };
        BOOST_CHECK(run([&](uint32_t kind,std::span<const unsigned char> bytes) {
            observed.emplace_back(kind,std::vector<unsigned char>{bytes.begin(),bytes.end()}); return hash(kind,bytes);
        }) == expected);
        BOOST_CHECK(observed == expected_trace);
        for (size_t fail=0;fail<expected_trace.size();++fail) {
            observed.clear();
            BOOST_CHECK_EXCEPTION(run([&](uint32_t kind,std::span<const unsigned char> bytes) {
                observed.emplace_back(kind,std::vector<unsigned char>{bytes.begin(),bytes.end()});
                if (observed.size()==fail+1) throw std::runtime_error("custody hash failure");
                return hash(kind,bytes);
            }),std::runtime_error,[](const auto& error) { return std::string(error.what())=="custody hash failure"; });
            BOOST_CHECK(observed == Trace(expected_trace.begin(),expected_trace.begin()+fail+1));
        }
    }
}

BOOST_AUTO_TEST_CASE(haskell_annex_header_matches_native_decoder)
{
    const std::array<std::string,3> errors{"unchanged",
        "ECX bond-inbox source annex has a noncanonical prefix/version",
        "ECX bond-inbox source annex has invalid bundle/receipt lengths"};
    const auto check = [&](const std::vector<unsigned char>& input, uint64_t expected, uint64_t limit) {
        const std::array<unsigned char,9> prefix{0x50,'E','C','X','B','I','N','2',0};
        int code{0}; uint32_t length{0}; uint8_t count{0};
        if (input.size() < prefix.size()+6 || !std::equal(prefix.begin(),prefix.end(),input.begin()) || input[9]!=1) code=1;
        else {
            length=ReadBE32(input.data()+10); count=input[14];
            if (length==0 || length!=expected || length>limit || count<3 || count>5 || length>input.size()-15) code=2;
        }
        uint32_t actual_length{0xa5}; uint8_t actual_count{0xa5};
        std::string error=errors[0];
        BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeAnnexHeader(input,expected,limit,actual_length,actual_count,error),code==0);
        BOOST_CHECK_EQUAL(error,errors[code]);
        BOOST_CHECK_EQUAL(actual_length,code ? 0xa5 : length);
        BOOST_CHECK_EQUAL(actual_count,code ? 0xa5 : count);
    };
    std::vector<unsigned char> canonical{0x50,'E','C','X','B','I','N','2',0,1,0,0,0,1,3,0x42};
    check(canonical,1,1);
    for (size_t n=0;n<canonical.size();++n) check({canonical.begin(),canonical.begin()+n},1,1);
    for (size_t offset=0;offset<15;++offset) for (unsigned value=0;value<256;++value) {
        auto mutated=canonical; mutated[offset]=value; check(mutated,1,1);
    }
    for (uint32_t length : {0U,1U,2U,65536U,UINT32_MAX})
        for (uint64_t expected : {uint64_t{0},uint64_t{length},UINT64_MAX})
            for (uint64_t limit : {uint64_t{0},uint64_t{length},UINT64_MAX}) {
                auto input=canonical; WriteBE32(input.data()+10,length); check(input,expected,limit);
            }
}

BOOST_AUTO_TEST_CASE(haskell_custody_receipts_match_native_decoder)
{
    const std::array<std::string,5> errors{"unchanged",
        "ECX bond-inbox source annex truncated a receipt length",
        "ECX bond-inbox source annex receipt length is noncanonical",
        "ECX bond-inbox source annex receipts are not registry ordered",
        "ECX bond-inbox source annex receipt evidence is invalid"};
    for (uint32_t count = 3; count <= 5; ++count) {
        std::vector<unsigned char> canonical(count * 140,0x42);
        for (size_t i = 0; i < count; ++i) {
            canonical[i*140] = 0; canonical[i*140+1] = 138;
            canonical[i*140+2] = 1; canonical[i*140+75] = i+1;
        }
        const auto check = [&](const std::vector<unsigned char>& input) {
            std::vector<unsigned char> expected;
            uint8_t bitmap{0}, previous{0};
            size_t cursor{0};
            int code{0};
            for (size_t i = 0; i < count; ++i) {
                if (cursor+2 > input.size()) { code = 1; break; }
                const auto length = (unsigned(input[cursor]) << 8) | input[cursor+1];
                cursor += 2;
                if (length != 138 || cursor+length > input.size()) { code = 2; break; }
                const auto signer = input[cursor+73];
                if (input[cursor] != 1 || signer < 1 || signer > 5 || signer <= previous) { code = 3; break; }
                previous = signer;
                bitmap |= 1U << (signer-1);
                expected.insert(expected.end(),input.begin()+cursor,input.begin()+cursor+length);
                cursor += length;
            }
            if (code == 0 && cursor != input.size()) code = 4;
            std::vector<unsigned char> actual{0xa5};
            uint8_t actual_bitmap{0xa5};
            std::string error = errors[0];
            BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeCustodyReceipts(count,input,actual,actual_bitmap,error),code == 0);
            BOOST_CHECK_EQUAL(error,errors[code]);
            BOOST_CHECK(actual == (code ? std::vector<unsigned char>{0xa5} : expected));
            BOOST_CHECK_EQUAL(actual_bitmap,code ? 0xa5 : bitmap);
        };
        check(canonical);
        for (size_t size = 0; size < canonical.size(); ++size)
            check({canonical.begin(),canonical.begin()+size});
        for (size_t offset = 0; offset < canonical.size(); ++offset) {
            for (unsigned char byte : {0,1,3,5,6,138,255}) {
                auto mutated = canonical; mutated[offset] = byte; check(mutated);
            }
        }
        auto trailing = canonical; trailing.push_back(0); check(trailing);
        // Earlier malformed receipt wins over a later truncation/trailing byte.
        trailing[2] = 0; check(trailing); trailing.resize(141); check(trailing);
    }
    std::vector<unsigned char> output{0xa5};
    uint8_t bitmap{0xa5};
    std::string error{"unchanged"};
    for (uint32_t count : {0U,2U,6U,UINT32_MAX})
        BOOST_CHECK_THROW(drivechain::haskell::ExchangeCustodyReceipts(count,{},output,bitmap,error),std::invalid_argument);
    BOOST_CHECK(output == std::vector<unsigned char>{0xa5});
    BOOST_CHECK_EQUAL(bitmap,0xa5);
    BOOST_CHECK_EQUAL(error,"unchanged");
}

BOOST_AUTO_TEST_CASE(haskell_marker_frame_matches_native_script_parser)
{
    for (bool successor : {false,true}) {
        std::vector<unsigned char> payload(503,0x42);
        std::copy_n("ECXB",4,payload.begin());
        payload[4] = successor ? 3 : 1;
        payload[5] = 0;
        const CScript canonical = CScript() << OP_RETURN << payload;
        const auto check = [&](const CScript& script) {
            auto cursor = script.begin();
            opcodetype opcode;
            std::vector<unsigned char> expected;
            const bool accepted = script.GetOp(cursor,opcode) && opcode == OP_RETURN &&
                script.GetOp(cursor,opcode,expected) && opcode == OP_PUSHDATA2 && cursor == script.end() &&
                expected.size() == 503 && std::equal(expected.begin(),expected.begin()+4,"ECXB") &&
                expected[4] == (successor ? 3 : 1) && expected[5] <= 3;
            std::vector<unsigned char> actual{0xa5};
            BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeMarkerFrame(successor,script,actual),accepted);
            BOOST_CHECK(actual == (accepted ? expected : std::vector<unsigned char>{0xa5}));
        };
        check(canonical);
        for (size_t offset = 0; offset < canonical.size(); ++offset) for (unsigned char byte : {0,1,3,255}) {
            auto script = canonical;
            script[offset] = byte;
            check(script);
        }
        for (size_t size = 0; size < canonical.size(); ++size) check(CScript(canonical.begin(),canonical.begin()+size));
        auto trailing = canonical;
        trailing << OP_0;
        check(trailing);
        CScript nonminimal;
        nonminimal << OP_RETURN;
        const std::array<unsigned char,5> push{OP_PUSHDATA4,247,1,0,0};
        nonminimal.insert(nonminimal.end(),push.begin(),push.end());
        nonminimal.insert(nonminimal.end(),payload.begin(),payload.end());
        check(nonminimal);
    }
}

BOOST_AUTO_TEST_CASE(haskell_marker_context_preserves_field_binding)
{
    namespace hs = drivechain::haskell;
    const std::array<std::pair<size_t,size_t>,9> fields{{{6,32},{38,32},{102,32},{134,32},{166,4},{170,32},{202,8},{210,32},{407,32}}};
    for (size_t offset = 0; offset < 503; ++offset) {
        std::vector<unsigned char> payload(503,0);
        payload[offset] = 1;
        std::vector<unsigned char> expected;
        for (const auto& [begin,size] : fields) expected.insert(expected.end(),payload.begin()+begin,payload.begin()+begin+size);
        BOOST_CHECK(hs::ExchangeInboxEntry(hs::InboxCodec::MARKER_CONTEXT,{}, {},payload) == expected);
    }
    BOOST_CHECK_THROW(hs::ExchangeInboxEntry(hs::InboxCodec::MARKER_CONTEXT,{}, {},std::vector<unsigned char>(502)),std::runtime_error);
}

BOOST_AUTO_TEST_CASE(haskell_activation_fingerprint_matches_native_layout)
{
    for (unsigned seed=0;seed<64;++seed) {
        const std::array<uint64_t,8> numbers{0,UINT32_MAX,seed,42,UINT64_MAX,255,UINT32_MAX,seed};
        std::vector<std::vector<unsigned char>> blobs(47);
        for (unsigned i=0;i<blobs.size();++i) blobs[i].assign(i<3 ? seed+i : 32,seed+i);
        std::vector<unsigned char> expected;
        const auto bytes=[&](unsigned i) { expected.insert(expected.end(),blobs[i].begin(),blobs[i].end()); };
        const auto number=[&](unsigned width,unsigned i) {
            for (unsigned shift=width;shift>0;--shift) expected.push_back(numbers[i]>>(8*(shift-1)));
        };
        bytes(0); bytes(1);
        for (unsigned i=0;i<4;++i) number(4,i);
        bytes(2);
        for (unsigned i=3;i<46;++i) bytes(i);
        number(8,4); number(1,5); number(4,6); bytes(46); number(8,7);
        const auto read=[&](uint32_t group,uint32_t index,uint64_t& value,const unsigned char*& data) {
            if (group==0 && index<numbers.size()) { value=numbers[index]; return true; }
            if (group!=1 || index>=blobs.size()) return false;
            value=blobs[index].size(); data=blobs[index].data(); return true;
        };
        BOOST_CHECK(drivechain::haskell::BmmFingerprint(read,2)==expected);
        blobs[3+seed%44].pop_back();
        BOOST_CHECK_THROW(drivechain::haskell::BmmFingerprint(read,2),std::runtime_error);
    }
    BOOST_CHECK_EXCEPTION(drivechain::haskell::BmmFingerprint([](auto,auto,auto&,auto&) -> bool {
        throw std::logic_error("activation fingerprint fault");
    },2),std::logic_error,[](const auto& error) { return std::string(error.what())=="activation fingerprint fault"; });
}

BOOST_AUTO_TEST_CASE(genesis_hash_streaming_matches_previous_preimages)
{
    ecx::ExchangeConsensus consensus;
    for (unsigned seed=0;seed<256;++seed) {
        for (unsigned index=0;index<32;++index) {
            consensus.forced_action_domain[index]=seed+index;
            consensus.deposit_inbox_domain[index]=seed-index;
            consensus.chain_id[index]=seed^index;
            consensus.bond_v2.bond_inbox_domain.begin()[index]=seed+2*index;
            consensus.bond_v2.configuration_hash.begin()[index]=seed+3*index;
        }
        const auto pair=[&](const auto& domain) {
            std::vector<unsigned char> bytes(domain.begin(),domain.end());
            bytes.insert(bytes.end(),consensus.chain_id.begin(),consensus.chain_id.end());
            return bytes;
        };
        BOOST_CHECK(ecx::ComputeForcedInboxGenesis(consensus)==TestTaggedHash("ECX/forced-inbox-genesis/v1",pair(consensus.forced_action_domain)));
        BOOST_CHECK(ecx::ComputeDepositInboxGenesis(consensus)==TestTaggedHash("ECX/deposit-inbox-genesis/v1",pair(consensus.deposit_inbox_domain)));
        auto triple=pair(consensus.bond_v2.bond_inbox_domain);
        triple.insert(triple.end(),consensus.bond_v2.configuration_hash.begin(),consensus.bond_v2.configuration_hash.end());
        BOOST_CHECK(ecx::BondInboxGenesisHead(consensus)==TestTaggedHash("ECX/bond-inbox-genesis/v2",triple));
        BOOST_CHECK(ecx::IncrementalSuccessorBondInboxGenesisHead(consensus)==TestTaggedHash("ECX/successor-bond-inbox-genesis/v2-u128",triple));
        for (const auto* tag : {"ECX/bond-inbox-outcomes-genesis/v4-expired-unavailable-v2","ECX/successor-bond-inbox-outcomes-genesis/v2-u128"}) {
            BOOST_CHECK((::TaggedHash(tag) << consensus.bond_v2.bond_inbox_domain << consensus.chain_id << consensus.bond_v2.configuration_hash).GetSHA256()==TestTaggedHash(tag,triple));
        }
    }
    BOOST_CHECK((::TaggedHash("ECX/successor-redemption-queue/v2-u128") << uint32_t{0}).GetSHA256()==
        TestTaggedHash("ECX/successor-redemption-queue/v2-u128",std::vector<unsigned char>(4,0)));
}

BOOST_AUTO_TEST_CASE(haskell_taproot_preimages_preserve_serialized_order)
{
    using drivechain::haskell::GenesisCodec;
    std::array<unsigned char, 32> left{}, right{};
    const XOnlyPubKey internal{Span<const unsigned char>(ECX_BIP341_NUMS_XONLY.data(),32)};
    for (unsigned version = 0; version <= 255; ++version) {
        left.fill(version);
        const auto encoded = drivechain::haskell::ExchangeGenesisState(GenesisCodec::TAP_LEAF, version, 0, {left.data()});
        std::vector<unsigned char> expected{static_cast<unsigned char>(version), 32};
        expected.insert(expected.end(), left.begin(), left.end());
        BOOST_CHECK(encoded == expected);
        const auto leaf=TestTaggedHash("TapLeaf/elements",encoded);
        const auto tweaked=internal.CreateTapTweak(&leaf);
        BOOST_REQUIRE(tweaked.has_value());
        CScript original;
        original << OP_1 << std::vector<unsigned char>(tweaked->first.begin(),tweaked->first.end());
        BOOST_CHECK(GetScriptForDestination(WitnessV1Taproot(tweaked->first))==original);
    }
    for (unsigned i = 0; i < 32; ++i) for (unsigned byte : {0U,1U,128U,255U}) {
        left.fill(0); right.fill(0);
        left[i] = byte; right[31-i] = 1;
        std::vector<unsigned char> expected;
        const bool less = std::lexicographical_compare(left.begin(), left.end(), right.begin(), right.end());
        const auto& first = less ? left : right;
        const auto& second = less ? right : left;
        expected.insert(expected.end(), first.begin(), first.end());
        expected.insert(expected.end(), second.begin(), second.end());
        BOOST_CHECK(drivechain::haskell::ExchangeGenesisState(GenesisCodec::TAP_BRANCH, 0, 0, {left.data(), right.data()}) == expected);
        BOOST_CHECK(drivechain::haskell::ExchangeGenesisState(GenesisCodec::TAP_BRANCH, 0, 0, {right.data(), left.data()}) == expected);
    }
    std::vector<unsigned char> equal(left.begin(), left.end());
    equal.insert(equal.end(), left.begin(), left.end());
    BOOST_CHECK(drivechain::haskell::ExchangeGenesisState(GenesisCodec::TAP_BRANCH, 0, 0, {left.data(), left.data()}) == equal);
    BOOST_CHECK_THROW(drivechain::haskell::ExchangeGenesisState(GenesisCodec::TAP_LEAF, 256, 0, {left.data()}), std::runtime_error);
    BOOST_CHECK_THROW(drivechain::haskell::ExchangeGenesisState(GenesisCodec::TAP_LEAF, UINT64_MAX, 0, {left.data()}), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(genesis_full_roots_and_script_match_rust_materializer)
{
    // Synthetic frozen_configuration_fixture + check_creation_independence
    // in ecx-bond-action-client. This is serialization, not live authentication.
    ecx::ExchangeConsensus consensus{};
    consensus.chain_id.fill(0xcc);
    consensus.forced_action_domain.fill(0x11);
    consensus.deposit_inbox_domain.fill(0x12);
    const auto repeated = [](unsigned char byte) {
        uint256 result;
        std::fill(result.begin(), result.end(), byte);
        return result;
    };
    auto& b = consensus.bond_v2;
    b.genesis_mark_price = 3'000'000'000;
    b.bond_asset_id = repeated(0x77);
    b.bond_deployment_commitment = repeated(0x88);
    b.inventory_covenant_script_sha256 = repeated(0x70);
    b.matcher_genesis_receipt_hash = repeated(0x10);
    b.bond_inbox_domain = repeated(0x46);
    b.order_receipts_genesis_root = repeated(4);
    b.genesis_availability_root = repeated(3);
    b.public_state_domain_sha256 = repeated(5);
    b.state_node_domain_sha256 = repeated(6);
    b.transition_cmr = repeated(8);
    b.incremental_activation_cmr = repeated(9);
    b.configuration_hash = RawHash("3df93f4bcb331b1ecf1784bcff2a7ac6e9835f4f1ca03f9c30f92e6ac7a67528");
    const auto key = ParseHex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    std::copy(key.begin(), key.end(), b.keyless_internal_key.begin());
    uint256 state, bond, funding, covenant;
    BOOST_REQUIRE(ecx::ComputeBondV2EmptyGenesisRoots(
        consensus, 39, 1'700'000'000, state, bond, funding, covenant));
    BOOST_CHECK_EQUAL(state, RawHash("2a3138979463a11b1a1f32eddf87f178def27eb245cd6e395543e40391ef61c7"));
    BOOST_CHECK_EQUAL(bond, RawHash("42d03521b322730cb12768b4e9092962969aa07f262da8306f2cd5561862881e"));
    BOOST_CHECK_EQUAL(funding, RawHash("ae301bba06a2b3ccf1d4fd7c05a2f36fc476e4dd064c0bb30e1fdd857c7550c2"));
    BOOST_CHECK_EQUAL(covenant, RawHash("f4c6825dab61df693292077a9d84b93e586f4693cbafbbe5bd7b2a7f7d88208f"));
    CScript script;
    BOOST_REQUIRE(ecx::ComputeBondV2FiniteStateScript(consensus, covenant, script));
    BOOST_CHECK_EQUAL(HexStr(script), "5120156fa2e4f41f964e2331da133c3517d68dd70f6e85c66e5764f769b17909733a");
}

BOOST_AUTO_TEST_CASE(external_prepared_genesis_roots)
{
    const char* path = std::getenv("ECX_TEST_RUNTIME_CANDIDATE");
    if (!path) { BOOST_TEST_MESSAGE("External genesis comparison not requested"); return; }
    const auto read = [](const char* file) {
        BOOST_REQUIRE(file != nullptr);
        std::ifstream input(file);
        BOOST_REQUIRE(input.good());
        const std::string bytes{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
        UniValue value;
        BOOST_REQUIRE(value.read(bytes));
        return value;
    };
    const auto candidate = read(path);
    const auto configuration = read(std::getenv("ECX_TEST_GENESIS_CONFIGURATION"));
    const auto genesis = read(std::getenv("ECX_TEST_GENESIS_MATERIALIZATION"));
    BOOST_REQUIRE_EQUAL(candidate["schema"].get_str(), "ECX_ALPHA_OFFLINE_RUNTIME_CANDIDATE_V1");
    BOOST_REQUIRE_EQUAL(genesis["schema"].get_str(), "ECX_BOND_V2_FINITE_GENESIS_MATERIALIZATION_V2");
    const auto& args = candidate["candidate_arguments"];
    const auto hash = [&](const char* key) { return RawHash(args[key].get_str()); };
    const auto array_hash = [&](const char* key) {
        const auto& a = configuration[key];
        BOOST_REQUIRE(a.isArray());
        BOOST_REQUIRE_EQUAL(a.size(), 32U);
        uint256 result;
        for (size_t i = 0; i < 32; ++i) {
            const auto byte = a[i].getInt<unsigned int>();
            BOOST_REQUIRE_LE(byte, 255U);
            result.begin()[i] = byte;
        }
        return result;
    };
    ecx::ExchangeConsensus consensus{};
    const auto copy_arg = [&](const char* key, auto& destination) {
        const auto value = hash(key);
        std::copy(value.begin(), value.end(), destination.begin());
    };
    copy_arg("-ecxchainid", consensus.chain_id);
    copy_arg("-ecxforcedactiondomain", consensus.forced_action_domain);
    copy_arg("-ecxdepositinboxdomain", consensus.deposit_inbox_domain);
    auto& b = consensus.bond_v2;
    b.genesis_mark_price = std::stoull(args["-ecxbondv2genesismarkprice"].get_str());
    b.bond_asset_id = array_hash("bond_asset_id");
    b.bond_deployment_commitment = array_hash("bond_deployment_commitment");
    b.inventory_covenant_script_sha256 = array_hash("bond_inventory_script_sha256");
    b.bond_inbox_domain = array_hash("bond_inbox_domain");
    b.matcher_genesis_receipt_hash = hash("-ecxbondv2matcherreceipt");
    b.order_receipts_genesis_root = hash("-ecxbondv2orderreceiptsroot");
    b.genesis_availability_root = hash("-ecxbondv2availabilityroot");
    b.public_state_domain_sha256 = hash("-ecxbondv2publicstatedomain");
    b.state_node_domain_sha256 = hash("-ecxbondv2statenodedomain");
    b.transition_cmr = hash("-ecxbondv2transitioncmr");
    b.incremental_activation_cmr = hash("-ecxbondv2incrementalactivationcmr");
    b.configuration_hash = hash("-ecxbondv2configurationhash");
    copy_arg("-ecxbondv2keylessinternalkey", b.keyless_internal_key);
    uint256 encoded_hash;
    std::string error;
    BOOST_REQUIRE(ecx::ValidateBondV2FrozenConfigurationV18(
        ParseHex(args["-ecxbondv2configurationbytes"].get_str()), encoded_hash, error));
    BOOST_CHECK_EQUAL(encoded_hash, b.configuration_hash);
    BOOST_CHECK_EQUAL(b.configuration_hash, RawHash(genesis["configuration_hash_hex"].get_str()));
    const auto height = std::stoull(args["-ecxbondv2initializationheight"].get_str());
    const auto mtp = std::stoull(args["-ecxbondv2initializationmtp"].get_str());
    BOOST_CHECK_EQUAL(height, genesis["initialization"]["height"].getInt<uint64_t>());
    BOOST_CHECK_EQUAL(mtp, genesis["initialization"]["parent_mtp"].getInt<uint64_t>());
    uint256 state, bond, funding, covenant;
    BOOST_REQUIRE(ecx::ComputeBondV2EmptyGenesisRoots(consensus, height, mtp, state, bond, funding, covenant));
    BOOST_CHECK_EQUAL(state, RawHash(genesis["private_state_root_hex"].get_str()));
    BOOST_CHECK_EQUAL(bond, RawHash(genesis["bond_state_root_hex"].get_str()));
    BOOST_CHECK_EQUAL(funding, RawHash(genesis["funding_state_root_hex"].get_str()));
    BOOST_CHECK_EQUAL(covenant, RawHash(genesis["covenant_state_hash_hex"].get_str()));
    CScript script;
    BOOST_REQUIRE(ecx::ComputeBondV2FiniteStateScript(consensus, covenant, script));
    BOOST_CHECK_EQUAL(HexStr(script), genesis["state_script_hex"].get_str());
    // Exercise the actual fixed-covenant joins enforced by the loader, not
    // only the finite state script. This does not bypass its release gate.
    const XOnlyPubKey internal{Span<const unsigned char>(b.keyless_internal_key.data(), 32)};
    for (const auto& binding : std::array<std::pair<uint256, uint256>, 4>{{
        {hash("-ecxbondv2inventorycmr"), array_hash("bond_inventory_script_sha256")},
        {hash("-ecxbondv2queuecmr"), array_hash("bond_redemption_queue_script_sha256")},
        {array_hash("collateral_vault_covenant_cmr"), hash("-ecxcollateralvaultscripthash")},
        {array_hash("insurance_reserve_covenant_cmr"), array_hash("insurance_reserve_script_sha256")},
    }}) {
        std::vector<unsigned char> leaf_payload{TAPROOT_LEAF_TAPSIMPLICITY, 32};
        leaf_payload.insert(leaf_payload.end(), binding.first.begin(), binding.first.end());
        BOOST_CHECK(drivechain::haskell::ExchangeGenesisState(drivechain::haskell::GenesisCodec::TAP_LEAF,
            TAPROOT_LEAF_TAPSIMPLICITY,0,{binding.first.begin()})==leaf_payload);
        const auto leaf = TestTaggedHash("TapLeaf/elements", leaf_payload);
        const auto tweaked = internal.CreateTapTweak(&leaf);
        BOOST_REQUIRE(tweaked.has_value());
        CScript covenant_script;
        covenant_script << OP_1 << std::vector<unsigned char>(tweaked->first.begin(), tweaked->first.end());
        BOOST_CHECK(GetScriptForDestination(WitnessV1Taproot(tweaked->first))==covenant_script);
        uint256 digest;
        CSHA256().Write(covenant_script.data(), covenant_script.size()).Finalize(digest.begin());
        BOOST_CHECK_EQUAL(digest, binding.second);
    }
    // Input joins and native derivation only: not ancestry, signatures, or release qualification.
}

BOOST_AUTO_TEST_CASE(external_preserved_bond_deployment_openings)
{
    // Explicit opt-in: never replace the repository fixtures or require a
    // developer's private runtime configuration for ordinary test execution.
    const char* path = std::getenv("ECX_TEST_BOND_PROFILE");
    if (!path) { BOOST_TEST_MESSAGE("External deployment check not requested"); return; }
    std::ifstream input(path);
    BOOST_REQUIRE(input.good());
    const std::string bytes{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    UniValue profile;
    BOOST_REQUIRE(profile.read(bytes));
    const auto& args = profile["arguments"];
    auto number = [&](const char* key) -> uint32_t {
        const auto& value = args[key];
        return value.isStr() ? std::stoul(value.get_str()) : value.getInt<uint32_t>();
    };
    auto raw = [&](const char* key) {
        const auto decoded = ParseHex(args[key].get_str());
        BOOST_REQUIRE_EQUAL(decoded.size(), 32U);
        uint256 value;
        std::copy(decoded.begin(), decoded.end(), value.begin());
        return value;
    };
    CMutableTransaction mutable_tx;
    BOOST_REQUIRE(DecodeHexTx(mutable_tx, args["-ecxbondv2deploymenttx"].get_str(), true, true));
    const CTransaction tx(mutable_tx);
    const auto issuance_index = number("-ecxbondv2issuanceinput");
    const auto issuance_blinder = raw("-ecxbondv2issuancevalueblinder");
    const auto inventory_abf = raw("-ecxbondv2inventoryassetblinder");
    const auto inventory_vbf = raw("-ecxbondv2inventoryvalueblinder");
    BOOST_REQUIRE(issuance_blinder != inventory_abf && issuance_blinder != inventory_vbf);
    BOOST_REQUIRE(ecx::VerifyBondIssuance(tx, issuance_index, issuance_blinder));
    uint256 entropy;
    const auto& issuance = tx.vin.at(issuance_index);
    GenerateAssetEntropy(entropy, issuance.prevout, issuance.assetIssuance.assetEntropy);
    CAsset asset, token;
    CalculateAsset(asset, entropy);
    CalculateReissuanceToken(token, entropy, true);
    const auto& inventory = tx.vout.at(number("-ecxbondv2inventoryoutput"));
    BOOST_REQUIRE(VerifyConfidentialPair(inventory.nValue, inventory.nAsset,
        2'100'000'000'000'000, asset, inventory_vbf, inventory_abf));
    const auto& burn = tx.vout.at(number("-ecxbondv2burnoutput"));
    BOOST_REQUIRE(burn.nAsset.IsExplicit() && burn.nAsset.GetAsset() == token);
    BOOST_REQUIRE(burn.nValue.IsExplicit() && burn.nValue.GetAmount() == 1);
    BOOST_REQUIRE(burn.nNonce.IsNull() && burn.scriptPubKey.IsUnspendable());
    BOOST_TEST_MESSAGE("Verified preserved deployment issuance/inventory/token: " << tx.GetHash().ToString());
    // This deliberately does not claim signatures, input conservation, source
    // UTXO authentication, genesis linkage or full deployment qualification.
}

BOOST_AUTO_TEST_CASE(external_public_deployment_relation)
{
    const char* path = std::getenv("ECX_TEST_PUBLIC_DEPLOYMENT");
    if (!path) { BOOST_TEST_MESSAGE("External public deployment not requested"); return; }
    std::ifstream input(path);
    BOOST_REQUIRE(input.good());
    const std::string bytes{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    UniValue candidate;
    BOOST_REQUIRE(candidate.read(bytes));
    BOOST_REQUIRE_EQUAL(candidate["schema"].get_str(), "ALPHA_PUBLIC_DEPLOYMENT_MIGRATION_CANDIDATE_V1");
    CMutableTransaction mutable_tx;
    BOOST_REQUIRE(DecodeHexTx(mutable_tx, candidate["transactionHex"].get_str(), true, true));
    const CTransaction tx(mutable_tx);
    BOOST_REQUIRE_EQUAL(tx.vin.size(), 2);
    BOOST_REQUIRE_EQUAL(tx.vout.size(), 5);
    TxValidationState legacy_totals, per_asset_totals;
    BOOST_CHECK(!CheckTransaction(tx, legacy_totals, false));
    BOOST_CHECK_EQUAL(legacy_totals.GetRejectReason(), "bad-txns-txouttotal-toolarge");
    BOOST_CHECK(CheckTransaction(tx, per_asset_totals, true));
    BOOST_CHECK(Consensus::HasOnlyExplicitCreations(tx));
    BOOST_REQUIRE(ecx::VerifyPublicBondDeployment(tx, 0, 0, 1));
    uint256 entropy;
    GenerateAssetEntropy(entropy, tx.vin[0].prevout, tx.vin[0].assetIssuance.assetEntropy);
    CAsset asset, token;
    CalculateAsset(asset, entropy);
    CalculateReissuanceToken(token, entropy, false);
    BOOST_CHECK_EQUAL(tx.GetHash().ToString(), candidate["candidateTxid"].get_str());
    BOOST_CHECK_EQUAL(asset.GetHex(), candidate["bondAsset"].get_str());
    BOOST_CHECK_EQUAL(token.GetHex(), candidate["tokenAsset"].get_str());
    const auto script_hash = [](const CScript& script) {
        uint256 result;
        CSHA256().Write(script.data(), script.size()).Finalize(result.begin());
        return result;
    };
    const auto commitment = ecx::BondDeploymentCommitment(3,
        {tx.GetHash().ToUint256(), tx.vin[0].prevout.hash.ToUint256(), tx.vin[0].prevout.n,
         asset.id, token.id, 0, 1, script_hash(tx.vout[0].scriptPubKey), script_hash(tx.vout[1].scriptPubKey)});
    // Independently derived by the Rust public relation from these candidate bytes.
    BOOST_CHECK_EQUAL(HexStr(Span{commitment.begin(), commitment.end()}),
        "0dbfe1a4dc3fc5089ca31c6f346e49cbd86567393e2a4d9357f1f89b46c260ac");
    if (const char* funding_path = std::getenv("ECX_TEST_PUBLIC_DEPLOYMENT_FUNDING")) {
        std::ifstream funding_file(funding_path);
        BOOST_REQUIRE(funding_file.good());
        const std::string funding_bytes{std::istreambuf_iterator<char>(funding_file), std::istreambuf_iterator<char>()};
        UniValue funding;
        BOOST_REQUIRE(funding.read(funding_bytes));
        std::vector<CTxOut> prevouts;
        for (const auto& in : tx.vin) {
            bool found = false;
            for (const auto& entry : funding["inputs"].getValues()) {
                if (entry["txid"].get_str() != in.prevout.hash.ToString() || entry["vout"].getInt<uint32_t>() != in.prevout.n) continue;
                BOOST_REQUIRE(!found);
                const auto& output = entry["output"];
                const auto script_bytes = ParseHex(output["scriptPubKey"]["hex"].get_str());
                CTxOut out;
                out.nAsset = CConfidentialAsset(CAsset(uint256S(output["asset"].get_str())));
                out.nValue = CConfidentialValue(AmountFromValue(output["value"]));
                out.scriptPubKey = CScript(script_bytes.begin(), script_bytes.end());
                prevouts.push_back(out);
                found = true;
            }
            BOOST_REQUIRE(found);
        }
        // Unsigned serialization lacks input witnesses: issuance verification
        // rejects before checking conservation. No consensus relaxation needed.
        BOOST_CHECK(!VerifyAmounts(prevouts, tx, nullptr, false));
        mutable_tx.witness.vtxinwit.resize(mutable_tx.vin.size());
        BOOST_CHECK(VerifyAmounts(prevouts, CTransaction(mutable_tx), nullptr, false));
        BOOST_CHECK_EQUAL(CTransaction(mutable_tx).GetHash(), tx.GetHash());
        mutable_tx.vout[0].nValue = CConfidentialValue(mutable_tx.vout[0].nValue.GetAmount() - 1);
        BOOST_CHECK(!VerifyAmounts(prevouts, CTransaction(mutable_tx), nullptr, false));
    }
    // This does not validate input signatures/UTXOs or a production configuration join.
}

BOOST_AUTO_TEST_CASE(confidential_bond_issuance_checks_opening_and_rangeproof)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.witness.vtxinwit.resize(1);
    auto& issuance = tx.vin[0].assetIssuance;
    issuance.nInflationKeys = CConfidentialValue(1);
    uint256 entropy;
    GenerateAssetEntropy(entropy, tx.vin[0].prevout, issuance.assetEntropy);
    CAsset asset;
    CalculateAsset(asset, entropy);
    const uint256 blinder = uint256S("01");
    const uint256 nonce = uint256S("02");
    secp256k1_generator generator;
    BOOST_REQUIRE(secp256k1_generator_generate(secp256k1_blind_context, &generator, asset.begin()));
    secp256k1_pedersen_commitment commitment;
    CreateValueCommitment(issuance.nAmount, commitment, blinder.begin(), generator, 2'100'000'000'000'000);
    auto& proof = tx.witness.vtxinwit[0].vchIssuanceAmountRangeproof;
    proof.resize(5134);
    size_t size = proof.size();
    BOOST_REQUIRE(secp256k1_rangeproof_sign(secp256k1_blind_context, proof.data(), &size,
        0, &commitment, blinder.begin(), nonce.begin(), 0, 52,
        2'100'000'000'000'000, nullptr, 0, nullptr, 0, &generator));
    proof.resize(size);
    BOOST_CHECK(ecx::VerifyBondIssuance(CTransaction(tx), 0, blinder));
    BOOST_CHECK(!ecx::VerifyBondIssuance(CTransaction(tx), 1, blinder));
    BOOST_CHECK(!ecx::VerifyBondIssuance(CTransaction(tx), 0, uint256{}));
    BOOST_CHECK(!ecx::VerifyBondIssuance(CTransaction(tx), 0, nonce));
    const auto original = tx;
    proof[0] ^= 1;
    BOOST_CHECK(!ecx::VerifyBondIssuance(CTransaction(tx), 0, blinder));
    tx = original;
    tx.witness.vtxinwit[0].vchIssuanceAmountRangeproof.clear();
    BOOST_CHECK(!ecx::VerifyBondIssuance(CTransaction(tx), 0, blinder));
    tx = original;
    tx.witness.vtxinwit[0].vchInflationKeysRangeproof = {1};
    BOOST_CHECK(!ecx::VerifyBondIssuance(CTransaction(tx), 0, blinder));
    tx = original;
    tx.vin[0].assetIssuance.nAmount = CConfidentialValue(2'100'000'000'000'000);
    BOOST_CHECK(!ecx::VerifyBondIssuance(CTransaction(tx), 0, blinder));
    tx = original;
    tx.vin[0].assetIssuance.assetBlindingNonce = nonce;
    BOOST_CHECK(!ecx::VerifyBondIssuance(CTransaction(tx), 0, blinder));
}

BOOST_AUTO_TEST_CASE(bond_deployment_commitment_encoding_vector)
{
    const auto sequence = [](unsigned char start) {
        uint256 value;
        for (size_t i = 0; i < 32; ++i) value.begin()[i] = start + i;
        return value;
    };
    const ecx::BondDeploymentCommitmentFields fields{
        sequence(0), sequence(32), 0x01020304, sequence(64), sequence(96),
        0x05060708, 0x090a0b0c, sequence(128), sequence(160)};
    const auto bytes = ecx::EncodeBondDeploymentCommitment(3, fields);
    BOOST_REQUIRE_EQUAL(bytes.size(), 213);
    BOOST_CHECK_EQUAL(HexStr(bytes),
        "03000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f01020304"
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
        "000775f05a07400005060708090a0b0c"
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
    // Independent hashlib/struct vector: compare digest bytes, not uint256 display order.
    const auto public_hash = ecx::BondDeploymentCommitment(3, fields);
    BOOST_CHECK_EQUAL(HexStr(Span{public_hash.begin(), public_hash.end()}),
        "d6f052787853cd42b3d7838d424ea45f59d14b3bce3373c33fb3f871f919b1bf");
    auto legacy = bytes;
    legacy[0] = 1;
    BOOST_CHECK(ecx::EncodeBondDeploymentCommitment(2, fields) == legacy);
    const auto legacy_hash = ecx::BondDeploymentCommitment(2, fields);
    BOOST_CHECK_EQUAL(HexStr(Span{legacy_hash.begin(), legacy_hash.end()}),
        "2fbd5df12cd975d4afd10470e9f06a76e6cfb7c41fbd79d9391f677864caa7e8");
    const auto unsupported=[](const std::invalid_argument& error) {
        return std::string_view{error.what()}=="unsupported bond deployment version";
    };
    for (uint32_t version : {0U,1U,4U,255U,65535U,UINT32_MAX}) {
        BOOST_CHECK_EXCEPTION(ecx::EncodeBondDeploymentCommitment(version,fields),std::invalid_argument,unsupported);
        BOOST_CHECK_EXCEPTION(ecx::BondDeploymentCommitment(version,fields),std::invalid_argument,unsupported);
    }
}

BOOST_AUTO_TEST_CASE(reserved_exchange_outpoints_match_exact_identities)
{
    const std::array<uint256,3> hashes{
        uint256S("e31f7fb1e9489bfb9f6a73c10f80ecdcce1f276fbdf0cf85c02e3bcf174dc041"),
        uint256S("c3fd019db845c81a68a561f5ab67d92c3ab2505cb2c8212f02511e07e8c2f2a1"),
        uint256S("0cc4c302121a9d75c8a0e520253c1740520a6d6f4d03db6947a99565175d6586")};
    BOOST_CHECK(!ecx::IsExchangeStateInternalOutpoint(COutPoint{}));
    for (const auto& hash : hashes) {
        for (uint32_t n : {0U,1U,65535U,UINT32_MAX})
            BOOST_CHECK_EQUAL(ecx::IsExchangeStateInternalOutpoint(COutPoint{Txid::FromUint256(hash),n}),n==0);
        for (size_t bit=0;bit<256;++bit) {
            auto changed=hash;
            changed.begin()[bit/8]^=1U<<(bit%8);
            BOOST_CHECK(!ecx::IsExchangeStateInternalOutpoint(COutPoint{Txid::FromUint256(changed),0}));
        }
    }
}

BOOST_AUTO_TEST_CASE(exchange_configuration_reserved_identity_precedence)
{
    const std::array<const char*,5> hashes{
        "e31f7fb1e9489bfb9f6a73c10f80ecdcce1f276fbdf0cf85c02e3bcf174dc041",
        "c3fd019db845c81a68a561f5ab67d92c3ab2505cb2c8212f02511e07e8c2f2a1",
        "0cc4c302121a9d75c8a0e520253c1740520a6d6f4d03db6947a99565175d6586",
        "f0bcf7ca88c8a7c66d74d5540d5458ead1a15df5a8b6b98c08032a1300579ff9",
        "2d15ce4b128995291c4e38d36b8ae411a15bf80d7acee97cf5f58d2fc4de52b1"};
    for (const auto* hash : hashes) for (uint32_t n : {0U,1U}) {
        ecx::ExchangeConsensus consensus;
        consensus.genesis_state_outpoint = COutPoint{Txid::FromUint256(uint256S(hash)),n};
        std::string error;
        BOOST_CHECK(ecx::CheckExchangeStateHeader(CBlockHeader{},1,error,consensus));
        consensus.activation_height=1;
        BOOST_CHECK(!ecx::CheckExchangeStateHeader(CBlockHeader{},1,error,consensus));
        BOOST_CHECK_EQUAL(error,n==0 ? "ECX genesis state outpoint collides with a reserved chainstate record" :
            "ECX activation parameters are incomplete");
    }
}

BOOST_AUTO_TEST_CASE(bond_inbox_generated_hash_domains)
{
    for (const bool successor : {false,true}) {
        // Independent pre-migration domain construction.
        const std::string prefix = successor ? "ECX/successor-bond-inbox-" : "ECX/bond-inbox-";
        const std::string version = successor ? "/v2-u128" : "/v2";
        const std::array<const char*,7> actual{
            ECX_BOND_CONTEXT_TAGS[successor], ECX_BOND_SIGNATURE_TAGS[successor],
            ECX_BOND_BUNDLE_TAGS[successor], ECX_BOND_STAGING_AUTH_TAGS[successor],
            ECX_BOND_NO_STAGING_AUTH_TAGS[successor], ECX_BOND_ENTRY_TAGS[successor], ECX_BOND_STEP_TAGS[successor]};
        const std::array<const char*,7> names{"availability-context","marker-signature",
            "encrypted-availability-bundle","staging-source-authorization",
            "no-staging-source-authorization","entry","step"};
        for (size_t i=0;i<names.size();++i) BOOST_CHECK_EQUAL(actual[i],prefix+names[i]+version);
        const std::string tree = prefix+"custody-receipts"+version;
        const std::array<std::string,6> custody{prefix+"custody-receipt-binding"+version,
            prefix+"exact-custody-receipt"+version,tree+"/empty",tree+"/leaf",tree+"/pad",tree+"/node"};
        for (size_t i=0;i<custody.size();++i) BOOST_CHECK_EQUAL(ECX_BOND_CUSTODY_TAGS[successor][i],custody[i]);
    }
}

BOOST_AUTO_TEST_CASE(public_bond_deployment_exact_relation)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256S("1234")), 7};
    auto& issuance = tx.vin[0].assetIssuance;
    issuance.assetEntropy = uint256S("5678");
    issuance.nAmount = CConfidentialValue(2'100'000'000'000'000);
    issuance.nInflationKeys = CConfidentialValue(1);
    uint256 entropy;
    GenerateAssetEntropy(entropy, tx.vin[0].prevout, issuance.assetEntropy);
    CAsset asset, token, confidential_token;
    CalculateAsset(asset, entropy);
    CalculateReissuanceToken(token, entropy, false);
    CalculateReissuanceToken(confidential_token, entropy, true);
    BOOST_REQUIRE(token != confidential_token);
    tx.vout.resize(2);
    tx.vout[0].nAsset = CConfidentialAsset(asset);
    tx.vout[0].nValue = issuance.nAmount;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;
    tx.vout[1].nAsset = CConfidentialAsset(token);
    tx.vout[1].nValue = CConfidentialValue(1);
    tx.vout[1].scriptPubKey = CScript{} << OP_RETURN;
    BOOST_REQUIRE(ecx::VerifyPublicBondDeployment(CTransaction(tx), 0, 0, 1));
    const auto reject = [&](auto mutate) {
        auto changed = tx;
        mutate(changed);
        BOOST_CHECK(!ecx::VerifyPublicBondDeployment(CTransaction(changed), 0, 0, 1));
    };
    reject([&](auto& value) { value.vout[1].nAsset = CConfidentialAsset(confidential_token); });
    reject([](auto& value) { value.vin[0].m_is_pegin = true; });
    reject([](auto& value) { value.vin.push_back(value.vin[0]); });
    reject([](auto& value) { value.vin[0].assetIssuance.nAmount = CConfidentialValue(1); });
    reject([](auto& value) { value.vin[0].assetIssuance.assetBlindingNonce = uint256S("01"); });
    reject([](auto& value) { value.vout[0].nValue = CConfidentialValue(1); });
    for (const CAmount amount : {2'099'999'999'999'999LL, 2'100'000'000'000'001LL}) {
        reject([&](auto& value) { value.vin[0].assetIssuance.nAmount = CConfidentialValue(amount); });
        reject([&](auto& value) { value.vout[0].nValue = CConfidentialValue(amount); });
        reject([&](auto& value) {
            value.vin[0].assetIssuance.nAmount = CConfidentialValue(amount);
            value.vout[0].nValue = CConfidentialValue(amount);
        });
    }
    reject([](auto& value) { value.vout[0].scriptPubKey = CScript{} << OP_RETURN; });
    reject([](auto& value) { value.vout[1].scriptPubKey = CScript{} << OP_TRUE; });
    reject([](auto& value) { value.vout.push_back(value.vout[0]); });
    reject([](auto& value) { value.vout.push_back(value.vout[1]); });
    reject([](auto& value) { value.vout[0].nNonce.vchCommitment.assign(33, 2); });
    reject([](auto& value) { value.witness.vtxinwit.resize(1); value.witness.vtxinwit[0].vchIssuanceAmountRangeproof = {1}; });
    reject([](auto& value) { value.witness.vtxinwit.resize(1); value.witness.vtxinwit[0].vchInflationKeysRangeproof = {1}; });
    reject([](auto& value) { value.witness.vtxoutwit.resize(2); value.witness.vtxoutwit[0].vchRangeproof = {1}; });
    reject([](auto& value) { value.witness.vtxoutwit.resize(2); value.witness.vtxoutwit[0].vchSurjectionproof = {1}; });
    BOOST_CHECK(!ecx::VerifyPublicBondDeployment(CTransaction(tx), 1, 0, 1));
    BOOST_CHECK(!ecx::VerifyPublicBondDeployment(CTransaction(tx), 0, 0, 0));
    BOOST_CHECK(!ecx::VerifyPublicBondDeployment(CTransaction(tx), 0, 0, 2));
    BOOST_CHECK(!ecx::VerifyBondIssuance(CTransaction(tx), 0, uint256{}));
    for (uint32_t issuer = 0; issuer < 4; ++issuer) {
        auto positioned = tx;
        positioned.vin.assign(4, CTxIn{});
        positioned.vin[issuer] = tx.vin[0];
        BOOST_REQUIRE(ecx::VerifyPublicBondDeployment(CTransaction(positioned), issuer, 0, 1));
        for (uint32_t other = 0; other < 4; ++other) {
            auto pegin = positioned;
            pegin.vin[other].m_is_pegin = true;
            BOOST_CHECK(!ecx::VerifyPublicBondDeployment(CTransaction(pegin), issuer, 0, 1));
            if (other != issuer) {
                auto duplicate = positioned;
                duplicate.vin[other] = tx.vin[0];
                BOOST_CHECK(!ecx::VerifyPublicBondDeployment(CTransaction(duplicate), issuer, 0, 1));
            }
        }
        positioned.vin[issuer].assetIssuance.SetNull();
        BOOST_CHECK(!ecx::VerifyPublicBondDeployment(CTransaction(positioned), issuer, 0, 1));
    }
}

BOOST_AUTO_TEST_CASE(tapbranch_ordering_uses_serialized_hash_bytes_not_arithmetic_value)
{
    uint256 serialized_first;
    serialized_first.begin()[31] = 1;
    uint256 serialized_second;
    serialized_second.begin()[0] = 1;

    // TapBranch/elements sorts the 32 serialized bytes.  These values are
    // intentionally ordered the other way when interpreted as little-endian
    // integers, so a future UintToArith256 conversion cannot silently pass.
    BOOST_CHECK(serialized_first < serialized_second);
    BOOST_CHECK(UintToArith256(serialized_second) <
                UintToArith256(serialized_first));
}

BOOST_AUTO_TEST_CASE(finite_state_tree_preauthorizes_incremental_activation_leaf)
{
    ecx::ExchangeConsensus consensus{ConfiguredConsensus(
        50, COutPoint{Txid::FromUint256(uint256S("50")), 0}, uint256S("51"))};
    PopulateTestBondV2FrozenIdentities(consensus);
    std::fill(
        consensus.bond_v2.transition_cmr.begin(),
        consensus.bond_v2.transition_cmr.end(), 0x11);
    const uint256 covenant_state_hash{uint256S("1234")};
    CScript production;
    BOOST_REQUIRE(ecx::ComputeBondV2FiniteStateScript(
        consensus, covenant_state_hash, production));
    BOOST_CHECK_EQUAL(
        HexStr(production),
        HexStr(TestBondV2SuccessorScript(consensus, covenant_state_hash)));

    ecx::ExchangeConsensus changed{consensus};
    changed.bond_v2.incremental_activation_cmr.begin()[0] ^= 1;
    CScript changed_script;
    BOOST_REQUIRE(ecx::ComputeBondV2FiniteStateScript(
        changed, covenant_state_hash, changed_script));
    BOOST_CHECK_NE(HexStr(production), HexStr(changed_script));
}

BOOST_AUTO_TEST_CASE(state_authority_output_eligibility)
{
    for (unsigned mask = 0; mask < 32; ++mask) {
        auto output = AuthorityOutput(1);
        if (mask & 1) output.nAsset.vchCommitment.assign(33, 10);
        if (mask & 2) output.nValue.vchCommitment.assign(33, 8);
        if (mask & 4) output.nNonce.vchCommitment.assign(33, 2);
        if (mask & 8) output.scriptPubKey[0] = OP_0;
        if (mask & 16) output.scriptPubKey[1] = 0x21;
        BOOST_CHECK_EQUAL(ecx::IsStateAuthorityOutput(output), mask == 0);
    }
    for (unsigned size = 0; size <= 35; ++size) {
        auto output = AuthorityOutput(1);
        output.scriptPubKey.resize(size);
        BOOST_CHECK_EQUAL(ecx::IsStateAuthorityOutput(output), size == 34);
    }
    // Eligibility is a shape check, not a new restriction on authority amounts.
    for (CAmount amount : {-1, 0, 1}) {
        BOOST_CHECK(ecx::IsStateAuthorityOutput(AuthorityOutput(1, amount)));
    }
}

BOOST_AUTO_TEST_CASE(incremental_activation_binds_consumed_finite_coin)
{
    ecx::ExchangeConsensus consensus{ConfiguredConsensus(
        50, COutPoint{Txid::FromUint256(uint256S("50")), 0}, uint256S("51"))};
    PopulateTestBondV2FrozenIdentities(consensus);
    ecx::BondV2CapitalSnapshot prior;
    prior.proof_profile = 0;
    prior.covenant_state_hash = uint256S("1234");
    CTxOut output{AuthorityOutput(1)};
    BOOST_REQUIRE(ecx::ComputeBondV2FiniteStateScript(
        consensus, prior.covenant_state_hash, output.scriptPubKey));
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256S("1235")), 0});
    const Coin coin{output, 49, false};
    prior.exchange_state_root = ecx::ComputeStateUtxoRoot(
        Params().GetConsensus().hashGenesisBlock, tx.vin[0].prevout, output);
    std::string error;
    auto check = [&](const CMutableTransaction& candidate, const Coin& spent,
                     const ecx::BondV2CapitalSnapshot& snapshot) {
        return ecx::CheckBondV2ActivationPredecessorCoin(CTransaction{candidate},
            spent, prior.exchange_state_root, snapshot, error, consensus);
    };
    BOOST_CHECK(check(tx, coin, prior));
    auto changed_tx{tx};
    changed_tx.vin[0].prevout.n = 1;
    BOOST_CHECK(!check(changed_tx, coin, prior));
    changed_tx = tx;
    changed_tx.vin[0].m_is_pegin = true;
    BOOST_CHECK(!check(changed_tx, coin, prior));
    BOOST_CHECK(!check(tx, Coin{}, prior));
    auto changed_output{output};
    changed_output.scriptPubKey = CScript{} << OP_TRUE;
    BOOST_CHECK(!check(tx, Coin{changed_output, 49, false}, prior));
    auto changed_prior{prior};
    changed_prior.covenant_state_hash = uint256S("4321");
    BOOST_CHECK(!check(tx, coin, changed_prior));
    BOOST_CHECK(error.find("covenant-state bound") != std::string::npos);
    changed_prior = prior;
    changed_prior.exchange_state_root.SetNull();
    BOOST_CHECK(!check(tx, coin, changed_prior));
    changed_prior = prior;
    changed_prior.proof_profile = 1;
    BOOST_CHECK(!check(tx, coin, changed_prior));
}

#include <test/frozen_configuration_reference.h>

BOOST_AUTO_TEST_CASE(haskell_genesis_admission_order_and_short_circuit)
{
    using namespace drivechain::haskell;
    for (bool public_deployment : {false,true}) for (uint32_t failure=0;failure<=64;++failure) {
        if (failure==3 || failure==24 || failure==5 || failure==42 || failure==64) continue;
        for (bool throws : {false,true}) {
            std::vector<uint32_t> expected,actual;
            bool expected_throw=false,actual_throw=false,published=false;
            uint32_t expected_status=0,actual_status=0;
            const auto check=[&](uint32_t step,uint32_t error) {
                expected.push_back(step);
                if (failure!=step) return true;
                expected_status=1;
                if (throws) expected_throw=true;
                else if (error) expected.push_back(error);
                return false;
            };
            const auto reference=[&] {
                if (!check(1,0) || !check(2,65)) return;
                expected.push_back(3);
                if (public_deployment && !check(4,66)) return;
                expected.push_back(5);
                for (uint32_t step=6;step<=14;++step) if (!check(step,67)) return;
                for (uint32_t step=15;step<=22;++step) if (!check(step,68)) return;
                if (!check(23,69)) return;
                expected.push_back(24);
                for (uint32_t step=public_deployment ? 26 : 25;step<=40;++step) if (!check(step,70)) return;
                if (!check(41,71)) return;
                expected.push_back(42);
                for (uint32_t step=43;step<=53;++step) if (!check(step,72)) return;
                if (!check(54,0) || !check(55,73)) return;
                for (uint32_t step=56;step<=63;++step) if (!check(step,74)) return;
                expected.push_back(64);
            };
            reference();
            try {
                actual_status=ParentReplayStore(ReplayStoreFlow::GENESIS_ADMISSION,[&](uint32_t step) -> uint32_t {
                    actual.push_back(step);
                    if (step==failure && throws) throw std::runtime_error("genesis action failure");
                    if (step==3 || step==24) return public_deployment;
                    if (step==17) {
                        std::string error;
                        BOOST_REQUIRE(ExchangeTransactionShape(TransactionShape::ISSUANCE,[](uint32_t) { return true; },error));
                    }
                    if (step==64) published=true;
                    return step!=failure;
                });
            } catch (const std::runtime_error& error) {
                BOOST_CHECK_EQUAL(error.what(),"genesis action failure"); actual_throw=true;
            }
            BOOST_CHECK(actual==expected);
            BOOST_CHECK_EQUAL(actual_throw,expected_throw);
            if (!throws || !expected_throw) BOOST_CHECK_EQUAL(actual_status,expected_status);
            BOOST_CHECK_EQUAL(published,expected.back()==64);
        }
    }
}

BOOST_AUTO_TEST_CASE(haskell_capital_admission_short_circuit_facts)
{
    namespace hs = drivechain::haskell;
    for (bool present : {false,true}) for (int height : {-1,0,1})
    for (bool signalled : {false,true}) for (bool capital : {false,true}) {
        CBlockIndex index;
        index.nHeight=height;
        index.nVersion=signalled ? CBlockHeader::EXCHANGE_STATE_HF_MASK : 0;
        if (capital) index.ecxBondV2Capital.emplace();
        const CBlockIndex* previous=present ? &index : nullptr;
        unsigned height_reads{0}, version_reads{0}, capital_reads{0};
        BOOST_CHECK_EQUAL(hs::ParentReplayAll<3>({[&] { return previous!=nullptr; },
            [&] { ++height_reads; return previous->nHeight>=0; },
            [&] { ++version_reads; return (static_cast<uint32_t>(previous->nVersion)&CBlockHeader::EXCHANGE_STATE_HF_MASK)!=0; }}),
            previous && previous->nHeight>=0 && (static_cast<uint32_t>(previous->nVersion)&CBlockHeader::EXCHANGE_STATE_HF_MASK)!=0);
        BOOST_CHECK_EQUAL(height_reads,present ? 1U : 0U);
        BOOST_CHECK_EQUAL(version_reads,present && height>=0 ? 1U : 0U);
        BOOST_CHECK_EQUAL(hs::ParentReplayAll<2>({[&] { return previous!=nullptr; },
            [&] { ++capital_reads; return previous->ecxBondV2Capital.has_value(); }}),
            previous && previous->ecxBondV2Capital.has_value());
        BOOST_CHECK_EQUAL(capital_reads,present ? 1U : 0U);
    }
    for (size_t size=0;size<=9;++size) for (unsigned byte=0;byte<=255;++byte)
    for (unsigned char version : {5,6}) {
        std::vector<unsigned char> annex(size,static_cast<unsigned char>(byte));
        unsigned reads{0};
        BOOST_CHECK_EQUAL(hs::ParentReplayAll<2>({[&] { return annex.size()>7; },
            [&] { ++reads; return annex[7]==version; }}),annex.size()>7 && annex[7]==version);
        BOOST_CHECK_EQUAL(reads,size>7 ? 1U : 0U);
    }
    for (bool empty : {false,true}) for (uint64_t forced : std::array<uint64_t,3>{0,1,UINT64_MAX})
    for (uint64_t deposits : std::array<uint64_t,3>{0,1,UINT64_MAX}) {
        BOOST_CHECK_EQUAL(hs::ParentReplayAll<3>({[&] { return empty; },
            [&] { return forced==0; }, [&] { return deposits==0; }}),empty && forced==0 && deposits==0);
    }
    for (const auto& asset : {uint256::ZERO,uint256::ONE})
    for (const auto& expected : {uint256::ZERO,uint256::ONE})
    for (const auto& token : {uint256::ZERO,uint256::ONE}) {
        BOOST_CHECK_EQUAL(hs::ParentReplayAll<2>({[&] { return asset==expected; },
            [&] { return asset!=token; }}),asset==expected && asset!=token);
    }
}

BOOST_AUTO_TEST_CASE(haskell_capital_projection_branches_and_publication)
{
    using namespace drivechain::haskell;
    const std::array<std::vector<uint32_t>,5> paths{{
        {1,2,3,4,5,6}, {1,2,3,7,8,9,10,11},
        {1,2,3,7,8,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29},
        {1,2,3,7,8,12,13,14,15,16,30,32,34,35},
        {1,2,3,7,8,12,13,14,15,16,30,31,33,34,35}}};
    const std::map<uint32_t,uint32_t> errors{{2,36},{4,37},{7,38},{10,39},
        {12,40},{13,40},{14,40},{17,41},{18,42},{19,42},{20,42},{21,42},
        {23,43},{24,43},{25,44},{26,45},{27,45}};
    const std::set<uint32_t> branches{3,8,16,30}, writes{5,9,28,31,32,33,34};
    for (size_t mode=0;mode<paths.size();++mode) for (uint32_t failure=0;failure<=35;++failure) {
        if (branches.contains(failure)) continue;
        for (bool throws : {false,true}) {
            if (!throws && (failure==9 || failure==28 || failure==33 || failure==34)) continue;
            std::vector<uint32_t> expected,actual,expected_writes,actual_writes;
            bool expected_throw=false,actual_throw=false;
            uint32_t expected_status=0,actual_status=0;
            for (auto step : paths[mode]) {
                expected.push_back(step);
                if (step==failure) {
                    expected_status=1; expected_throw=throws;
                    if (!throws && errors.contains(step)) expected.push_back(errors.at(step));
                    break;
                }
                if (writes.contains(step)) expected_writes.push_back(step);
            }
            try {
                actual_status=ParentReplayStore(ReplayStoreFlow::CAPITAL_PROJECTION,[&](uint32_t step) -> uint32_t {
                    actual.push_back(step);
                    if (step==failure) {
                        if (throws) throw std::runtime_error("capital action failure");
                        return 0;
                    }
                    if (writes.contains(step)) actual_writes.push_back(step);
                    if (step==3) return mode==0;
                    if (step==8) return mode==1;
                    if (step==16) return mode==2;
                    if (step==30) return mode==4;
                    if (step==5 || step==31 || step==32) {
                        std::string error;
                        BOOST_REQUIRE(ExchangeTransactionShape(TransactionShape::ISSUANCE,[](uint32_t) { return true; },error));
                    }
                    return 1;
                });
            } catch (const std::runtime_error& error) {
                BOOST_CHECK_EQUAL(error.what(),"capital action failure"); actual_throw=true;
            }
            BOOST_CHECK(actual==expected);
            BOOST_CHECK(actual_writes==expected_writes);
            BOOST_CHECK_EQUAL(actual_throw,expected_throw);
            if (!expected_throw) BOOST_CHECK_EQUAL(actual_status,expected_status);
        }
    }
}

BOOST_AUTO_TEST_CASE(haskell_capital_projection_preserves_rejected_carry_snapshot)
{
    auto consensus=ConfiguredConsensus(50,COutPoint{Txid::FromUint256(uint256S("50")),0},uint256S("51"));
    PopulateTestBondV2FrozenIdentities(consensus);
    unsigned char identity=1;
    for (auto* field : {&consensus.bond_v2.transition_program_id,&consensus.bond_v2.configuration_hash,
            &consensus.bond_v2.bond_asset_id,&consensus.bond_v2.bond_deployment_commitment,
            &consensus.bond_v2.transition_journal_domain_sha256,&consensus.bond_v2.transition_cmr,
            &consensus.bond_v2.identity_derivation_record_sha256})
        std::fill(field->begin(),field->end(),identity++);
    CBlock block;
    block.hashExchangeStateRoot=uint256S("52");
    TestBlockIndex previous{block,50};
    ecx::BondV2CapitalSnapshot prior,result;
    DataStream prior_bytes{std::vector<unsigned char>(914,0xa5)};
    prior_bytes >> prior;
    previous.ecxBondV2Capital=prior;
    MemoryCoinsView base;
    CCoinsViewCache view{&base};
    const std::array<const char*,9> identity_errors{"ECX bond V2 capital projection requested before activation",
        "finite, activation, and incremental-successor configurations collide", "incremental proof program identity collides",
        "frozen ECX bond V2 covenant CMR roles collide", "incremental successor state-node identity collides",
        "unsupported ECX deployment version", "canonical FrozenConfigurationV2/V18 must be exactly 1977 bytes",
        "direct-price configuration hash mismatch", "direct-price configuration requires absent oracle conversion identities"};
    for (unsigned fault=0;fault<identity_errors.size();++fault) {
        auto candidate=consensus;
        auto& frozen=candidate.bond_v2;
        if (fault==1) frozen.configuration_hash=frozen.incremental_activation_configuration_hash;
        if (fault==2) frozen.transition_program_id=frozen.incremental_activation_program_id;
        if (fault==3) frozen.transition_cmr=frozen.incremental_activation_cmr;
        if (fault==4) frozen.incremental_successor_state_node_domain_sha256=frozen.public_state_domain_sha256;
        if (fault==5) frozen.deployment_version=99;
        if (fault==6) frozen.canonical_configuration_bytes={6};
        if (fault>=7) {
            auto bytes=ParseHex(ECX_V18_CONFIGURATION_HEX);
            bytes[0]=6;
            std::copy_n(bytes.begin()+50,32,bytes.begin()+114);
            WriteBE64(bytes.data()+1031,100000000); WriteBE64(bytes.data()+1039,100000000);
            std::fill(bytes.begin()+1753,bytes.begin()+1945,0);
            frozen.canonical_configuration_bytes=bytes;
            if (fault==8) frozen.configuration_hash=TestTaggedHash("ECX/frozen-configuration/v18-no-history-keyless-staging-renderer-v2",bytes);
        }
        std::string error;
        BOOST_CHECK(!ecx::DeriveBondV2CapitalProjectionAfterScripts(block,&previous,view,49,uint256S("53"),8,9,result,error,candidate));
        BOOST_CHECK_EQUAL(error,identity_errors[fault]);
    }
    for (int mode=0;mode<3;++mode) {
        DataStream poison{std::vector<unsigned char>(914,0x11)};
        poison >> result;
        DataStream before;
        before << result;
        std::string error;
        BOOST_CHECK(!ecx::DeriveBondV2CapitalProjectionAfterScripts(block,mode==1 ? nullptr : &previous,
            view,mode==0 ? 49 : 51,uint256S("53"),8,9,result,error,consensus));
        BOOST_CHECK_EQUAL(error,mode==0 ? "ECX bond V2 capital projection requested before activation" :
            mode==1 ? "ECX bond V2 predecessor lacks a verified block-index capital projection" :
            "ECX bond V2 carry-forward projection is not root/frozen-identity bound");
        DataStream actual,expected;
        actual << result;
        if (mode==2) expected << prior;
        BOOST_CHECK_EQUAL(HexStr(actual),mode==2 ? HexStr(expected) : HexStr(before));
    }
}

BOOST_AUTO_TEST_CASE(haskell_frozen_configuration_matches_complete_decoder)
{
    using Bytes=std::vector<unsigned char>;
    using Groups=std::array<Bytes,8>;
    using Trace=std::vector<std::tuple<uint32_t,Bytes,Groups>>;
    const auto crypto=[](uint32_t kind,std::span<const unsigned char> input) {
        std::array<unsigned char,32> result{};
        if (kind==3) result[0]=XOnlyPubKey(Span<const unsigned char>(input.data(),input.size())).IsFullyValid();
        else {
            const char* tags[]{"ECX/witness-availability-scheme/v1","ECX/witness-custody-receipt-codec/v1",
                "ECX/bond-inbox-redemption-staging-template/v3-no-history"};
            const auto digest=TestTaggedHash(tags[kind],{input.begin(),input.end()});
            std::copy(digest.begin(),digest.end(),result.begin());
        }
        return result;
    };
    const auto check=[&](const Bytes& input,int fail=-1) {
        ReferenceFrozenConfiguration before;
        before.direct_price=true; before.chain_id=uint256S("dead"); before.fixed_supply_atoms=47;
        before.staging_tapleaf_version=0x66;
        auto reference=before;
        auto actual=ReferenceFrozenGroups(before);
        Trace expected_trace,actual_trace;
        std::string expected_error="stale",actual_error="stale";
        bool expected_ok=false,actual_ok=false,expected_threw=false,actual_threw=false;
        const auto effect=[&](uint32_t kind,std::span<const unsigned char> bytes,Trace& trace,const Groups& state) {
            trace.emplace_back(kind,Bytes(bytes.begin(),bytes.end()),state);
            if (static_cast<int>(trace.size())==fail+1) throw std::runtime_error("frozen injected failure");
            return crypto(kind,bytes);
        };
        try { expected_ok=ReferenceDecodeFrozenConfigurationV18(input,reference,expected_error,
            [&](uint32_t kind,std::span<const unsigned char> bytes) { return effect(kind,bytes,expected_trace,ReferenceFrozenGroups(reference)); }); }
        catch (const std::runtime_error& e) { BOOST_CHECK_EQUAL(e.what(),"frozen injected failure"); expected_threw=true; }
        try { actual_ok=drivechain::haskell::ExchangeFrozenConfiguration(input,REFERENCE_FROZEN_MARKET,
            [&](uint32_t kind,std::span<const unsigned char> bytes) {
                if (kind>=4) { actual.at(kind-4).assign(bytes.begin(),bytes.end()); return std::array<unsigned char,32>{}; }
                return effect(kind,bytes,actual_trace,actual);
            },actual_error); }
        catch (const std::runtime_error& e) { BOOST_CHECK_EQUAL(e.what(),"frozen injected failure"); actual_threw=true; }
        BOOST_CHECK_EQUAL(actual_ok,expected_ok);
        BOOST_CHECK_EQUAL(actual_threw,expected_threw);
        BOOST_CHECK_EQUAL(actual_error,expected_error);
        BOOST_CHECK(actual==ReferenceFrozenGroups(reference));
        BOOST_CHECK(actual_trace==expected_trace);
        if (fail<0) {
            uint256 digest;
            std::string error;
            BOOST_CHECK_EQUAL(ecx::ValidateBondV2FrozenConfigurationV18(input,digest,error),expected_ok);
            BOOST_CHECK_EQUAL(error,expected_error);
        }
    };
    for (bool direct : {false,true}) {
        auto base=ParseHex(ECX_V18_CONFIGURATION_HEX);
        if (direct) {
            base[0]=6;
            std::copy_n(base.begin()+50,32,base.begin()+114);
            WriteBE64(base.data()+1031,100000000); WriteBE64(base.data()+1039,100000000);
            std::fill(base.begin()+1753,base.begin()+1945,0);
        }
        check(base);
        for (int fail=0;fail<5;++fail) check(base,fail);
        for (size_t i=0;i<base.size();++i) for (unsigned char mask : {1,128,255}) {
            auto mutated=base; mutated[i]^=mask; check(mutated);
        }
        for (size_t size : {0U,100U,1976U,1978U,4096U}) { auto invalid=base; invalid.resize(size); check(invalid); }
    }
}

BOOST_AUTO_TEST_CASE(frozen_configuration_v18_exact_rust_vector_and_mutations)
{
    static constexpr size_t COLLATERAL_COVENANT_CMR_OFFSET{1232};
    static constexpr size_t ECX_ASSET_OFFSET{50};
    static constexpr size_t USDD_ASSET_OFFSET{82};
    static constexpr size_t STATE_AUTHORITY_ASSET_OFFSET{146};
    static constexpr size_t TRUTHCOIN_ANCHOR_AUTHORITY_OFFSET{754};
    static constexpr size_t AVAILABILITY_SCHEME_OFFSET{293};
    static constexpr size_t MATCHER_FORCED_INCLUSION_BLOCKS_OFFSET{1128};
    static constexpr size_t STAGING_TEMPLATE_OFFSET{1392};
    static constexpr size_t STAGING_RENDERER_DOMAIN_OFFSET{1424};
    static constexpr size_t STAGING_INTERNAL_KEY_OFFSET{1456};
    static constexpr size_t INSURANCE_COVENANT_CMR_OFFSET{1589};
    static constexpr size_t INBOX_INCLUSION_BLOCKS_OFFSET{1717};
    const std::vector<unsigned char> bytes{ParseHex(ECX_V18_CONFIGURATION_HEX)};
    BOOST_REQUIRE_EQUAL(bytes.size(), 1977U);
    BOOST_REQUIRE_EQUAL(bytes[0], 5U);
    BOOST_REQUIRE_EQUAL(bytes[1], 3U);

    uint256 configuration_hash;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        ecx::ValidateBondV2FrozenConfigurationV18(
            bytes, configuration_hash, error),
        error);
    BOOST_CHECK_EQUAL(
        HexStr(configuration_hash),
        "ec2c8cdb6a538079fb7a1b6688476c03476e7ecf2bd0114ab49a1a6a246ade1e");
    BOOST_CHECK_EQUAL(
        configuration_hash,
        TestTaggedHash(
            "ECX/frozen-configuration/v18-no-history-keyless-staging-renderer-v2",
            bytes));

    const auto rejects = [&](std::vector<unsigned char> candidate) {
        uint256 rejected_hash;
        std::string rejection;
        BOOST_CHECK(!ecx::ValidateBondV2FrozenConfigurationV18(
            candidate, rejected_hash, rejection));
        BOOST_CHECK(rejected_hash.IsNull());
        BOOST_CHECK(!rejection.empty());
    };
    const auto risk=drivechain::haskell::ExchangeGenesisState(drivechain::haskell::GenesisCodec::RISK_PROFILE,0,0,{});
    BOOST_REQUIRE_EQUAL(risk.size(),41U);
    BOOST_CHECK(risk==std::vector<unsigned char>(bytes.begin()+251,bytes.begin()+292));
    for (size_t i=251; i<292; ++i) {
        auto mutated=bytes;
        mutated[i]^=1;
        uint256 rejected_hash;
        std::string rejection;
        BOOST_CHECK(!ecx::ValidateBondV2FrozenConfigurationV18(mutated,rejected_hash,rejection));
        BOOST_CHECK(rejected_hash.IsNull());
        BOOST_CHECK_EQUAL(rejection,"noncanonical FrozenConfigurationV2/V18: risk profile");
    }
    std::vector<unsigned char> wrong_outer_version{bytes};
    wrong_outer_version[0] = 4;
    rejects(std::move(wrong_outer_version));
    std::vector<unsigned char> wrong_base_version{bytes};
    wrong_base_version[1] = 4;
    rejects(std::move(wrong_base_version));
    std::vector<unsigned char> ecx_equals_usdd{bytes};
    std::copy(
        ecx_equals_usdd.begin() + ECX_ASSET_OFFSET,
        ecx_equals_usdd.begin() + ECX_ASSET_OFFSET + 32,
        ecx_equals_usdd.begin() + USDD_ASSET_OFFSET);
    rejects(std::move(ecx_equals_usdd));
    std::vector<unsigned char> anchor_equals_state_authority{bytes};
    std::copy(
        anchor_equals_state_authority.begin() + STATE_AUTHORITY_ASSET_OFFSET,
        anchor_equals_state_authority.begin() + STATE_AUTHORITY_ASSET_OFFSET + 32,
        anchor_equals_state_authority.begin() + TRUTHCOIN_ANCHOR_AUTHORITY_OFFSET);
    rejects(std::move(anchor_equals_state_authority));
    std::vector<unsigned char> wrong_availability_scheme{bytes};
    wrong_availability_scheme[AVAILABILITY_SCHEME_OFFSET] ^= 1;
    rejects(std::move(wrong_availability_scheme));
    std::vector<unsigned char> wrong_matcher_forced_window{bytes};
    wrong_matcher_forced_window[MATCHER_FORCED_INCLUSION_BLOCKS_OFFSET + 3] ^= 1;
    rejects(std::move(wrong_matcher_forced_window));
    std::vector<unsigned char> zero_collateral_cmr{bytes};
    std::fill(
        zero_collateral_cmr.begin() + COLLATERAL_COVENANT_CMR_OFFSET,
        zero_collateral_cmr.begin() + COLLATERAL_COVENANT_CMR_OFFSET + 32,
        0);
    rejects(std::move(zero_collateral_cmr));
    std::vector<unsigned char> zero_reserve_cmr{bytes};
    std::fill(
        zero_reserve_cmr.begin() + INSURANCE_COVENANT_CMR_OFFSET,
        zero_reserve_cmr.begin() + INSURANCE_COVENANT_CMR_OFFSET + 32,
        0);
    rejects(std::move(zero_reserve_cmr));
    std::vector<unsigned char> duplicate_cmr{bytes};
    std::copy(
        duplicate_cmr.begin() + COLLATERAL_COVENANT_CMR_OFFSET,
        duplicate_cmr.begin() + COLLATERAL_COVENANT_CMR_OFFSET + 32,
        duplicate_cmr.begin() + INSURANCE_COVENANT_CMR_OFFSET);
    BOOST_CHECK(!ecx::ValidateBondV2FrozenConfigurationV18(duplicate_cmr, configuration_hash, error));
    BOOST_CHECK_EQUAL(error, "noncanonical FrozenConfigurationV2/V18: duplicate outer identity");
    rejects(std::move(duplicate_cmr));
    std::vector<unsigned char> wrong_template{bytes};
    wrong_template[STAGING_TEMPLATE_OFFSET] ^= 1;
    rejects(std::move(wrong_template));
    std::vector<unsigned char> wrong_renderer_domain{bytes};
    wrong_renderer_domain[STAGING_RENDERER_DOMAIN_OFFSET + 31] ^= 1;
    rejects(std::move(wrong_renderer_domain));
    std::vector<unsigned char> wrong_internal_key{bytes};
    wrong_internal_key[STAGING_INTERNAL_KEY_OFFSET] ^= 1;
    rejects(std::move(wrong_internal_key));
    std::vector<unsigned char> wrong_inclusion_limit{bytes};
    wrong_inclusion_limit[INBOX_INCLUSION_BLOCKS_OFFSET + 3] ^= 1;
    rejects(std::move(wrong_inclusion_limit));
    std::vector<unsigned char> trailing{bytes};
    trailing.push_back(0);
    rejects(std::move(trailing));
    std::vector<unsigned char> truncated{bytes};
    truncated.pop_back();
    rejects(std::move(truncated));

    // V17 is retained only as a historical fixture and is never accepted by
    // the live V18 decoder, even if its former tagged digest is known.
    rejects(ParseHex(ECX_V17_CONFIGURATION_HEX));
}

BOOST_AUTO_TEST_CASE(frozen_configuration_v18_native_ecx_fee_asset_alias)
{
    // Byte offsets in the exact, historical V18 Rust vector. This test does
    // not make the fixture a live deployment or qualify a new proof binary.
    static constexpr size_t ECX_ASSET_OFFSET{50};
    static constexpr size_t POLICY_ASSET_OFFSET{114};
    static constexpr std::array<size_t, 10> OTHER_BASE_IDENTITIES{{
        2, 82, 146, 179, 211, 754, 1096, 1132, 1164, 1196,
    }};
    const std::vector<unsigned char> original{ParseHex(ECX_V18_CONFIGURATION_HEX)};
    BOOST_REQUIRE_EQUAL(original.size(), 1977U);

    std::vector<unsigned char> native_fees{original};
    std::copy_n(
        native_fees.begin() + ECX_ASSET_OFFSET, 32,
        native_fees.begin() + POLICY_ASSET_OFFSET);
    uint256 configuration_hash;
    std::string error;
    BOOST_REQUIRE_MESSAGE(ecx::ValidateBondV2FrozenConfigurationV18(
        native_fees, configuration_hash, error), error);
    BOOST_CHECK_EQUAL(configuration_hash, TestTaggedHash(
        "ECX/frozen-configuration/v18-no-history-keyless-staging-renderer-v2",
        native_fees));
    BOOST_CHECK_NE(configuration_hash, TestTaggedHash(
        "ECX/frozen-configuration/v18-no-history-keyless-staging-renderer-v2",
        original));

    // Native ECX may pay fees. USDD, authority assets, and every unrelated
    // domain/identity must still be rejected as aliases of the policy asset.
    for (const size_t offset : OTHER_BASE_IDENTITIES) {
        BOOST_TEST_CONTEXT("policy asset aliases identity at byte " << offset) {
            std::vector<unsigned char> collision{original};
            std::copy_n(
                collision.begin() + offset, 32,
                collision.begin() + POLICY_ASSET_OFFSET);
            BOOST_CHECK(!ecx::ValidateBondV2FrozenConfigurationV18(
                collision, configuration_hash, error));
            BOOST_CHECK(configuration_hash.IsNull());
            BOOST_CHECK(!error.empty());
        }
    }
    std::vector<unsigned char> zero_policy{native_fees};
    std::fill_n(zero_policy.begin() + POLICY_ASSET_OFFSET, 32, 0);
    BOOST_CHECK(!ecx::ValidateBondV2FrozenConfigurationV18(
        zero_policy, configuration_hash, error));
    BOOST_CHECK(configuration_hash.IsNull());

    // The one allowed alias must not mask another duplicate base identity.
    std::vector<unsigned char> ecx_equals_usdd{native_fees};
    std::copy_n(ecx_equals_usdd.begin() + ECX_ASSET_OFFSET, 32,
        ecx_equals_usdd.begin() + 82);
    BOOST_CHECK(!ecx::ValidateBondV2FrozenConfigurationV18(
        ecx_equals_usdd, configuration_hash, error));
    BOOST_CHECK(configuration_hash.IsNull());
    BOOST_CHECK_EQUAL(error, "noncanonical FrozenConfigurationV2/V18: duplicate base identity");
    const std::array<size_t, 11> base_offsets{{2, 50, 82, 146, 179, 211, 754, 1096, 1132, 1164, 1196}};
    for (size_t i = 0; i < base_offsets.size(); ++i) {
        auto zero = original;
        std::fill_n(zero.begin() + base_offsets[i], 32, 0);
        BOOST_CHECK(!ecx::ValidateBondV2FrozenConfigurationV18(zero, configuration_hash, error));
        BOOST_CHECK(configuration_hash.IsNull());
        for (size_t j = 0; j < i; ++j) {
            auto duplicate = native_fees;
            std::copy_n(duplicate.begin() + base_offsets[j], 32, duplicate.begin() + base_offsets[i]);
            BOOST_CHECK(!ecx::ValidateBondV2FrozenConfigurationV18(duplicate, configuration_hash, error));
            BOOST_CHECK(configuration_hash.IsNull());
        }
    }
}

BOOST_AUTO_TEST_CASE(frozen_configuration_v18_cross_role_identity_collisions)
{
    const auto original = ParseHex(ECX_V18_CONFIGURATION_HEX);
    // Change the role being isolated, leaving the staging descriptor intact.
    const auto rejects_alias = [&](size_t destination, size_t source) {
        auto bytes = original;
        std::copy_n(bytes.begin() + source, 32, bytes.begin() + destination);
        uint256 hash;
        std::string error;
        BOOST_CHECK(!ecx::ValidateBondV2FrozenConfigurationV18(bytes, hash, error));
        BOOST_CHECK(hash.IsNull());
        BOOST_CHECK_EQUAL(error, "noncanonical FrozenConfigurationV2/V18: cross-role identity collision");
    };
    for (size_t source : {1132U, 1164U, 293U, 325U}) rejects_alias(1653, source);
    for (size_t source : {1753U, 1785U, 1489U, 1521U, 1232U, 1589U}) rejects_alias(681, source);
}

BOOST_AUTO_TEST_CASE(frozen_configuration_v18_version_six_absent_oracle_conversions)
{
    std::vector<unsigned char> bytes{ParseHex(ECX_V18_CONFIGURATION_HEX)};
    BOOST_REQUIRE_EQUAL(bytes.size(), 1977U);
    bytes[0] = 6;
    std::copy_n(bytes.begin() + 50, 32, bytes.begin() + 114);
    for (const size_t offset : {1031U, 1039U}) {
        for (size_t i = 0; i < 8; ++i) {
            bytes[offset + i] = (UINT64_C(100000000) >> (8 * (7 - i))) & 0xff;
        }
    }
    std::fill(bytes.begin() + 1753, bytes.begin() + 1945, 0);
    uint256 digest;
    std::string error;
    BOOST_REQUIRE_MESSAGE(ecx::ValidateBondV2FrozenConfigurationV18(bytes, digest, error), error);
    const auto rejects = [&](std::vector<unsigned char> invalid) {
        BOOST_CHECK(!ecx::ValidateBondV2FrozenConfigurationV18(invalid, digest, error));
        BOOST_CHECK(digest.IsNull());
        BOOST_CHECK(!error.empty());
    };
    for (const size_t offset : {1753U, 1785U, 1817U, 1849U, 1881U, 1913U,
                               114U, 1031U, 1039U}) {
        auto invalid = bytes;
        invalid[offset] ^= 1;
        rejects(std::move(invalid));
    }
    for (const unsigned char version : {5, 7}) {
        auto invalid = bytes;
        invalid[0] = version;
        rejects(std::move(invalid));
    }
    // Exercise the runtime gate independently of the structural decoder.
    // This deliberately incomplete consensus is not a valid activation.
    ecx::ExchangeConsensus consensus{};
    auto& frozen = consensus.bond_v2;
    frozen.activation_enabled = true;
    frozen.identities_frozen = true;
    frozen.canonical_configuration_bytes = bytes;
    frozen.configuration_hash = TestTaggedHash(
        "ECX/frozen-configuration/v18-no-history-keyless-staging-renderer-v2", bytes);
    ecx::BondV2CapitalSnapshot snapshot;
    BOOST_CHECK(!ecx::DecodeBondV2CapitalProjection({}, uint256{}, snapshot, error, consensus));
    BOOST_CHECK_EQUAL(error, "missing frozen ECX bond V2 transition program");
    frozen.usdd_usd_conversion_program_id = uint256S("01");
    BOOST_CHECK(!ecx::DecodeBondV2CapitalProjection({}, uint256{}, snapshot, error, consensus));
    BOOST_CHECK_EQUAL(error, "direct-price configuration requires absent oracle conversion identities");
    frozen.usdd_usd_conversion_program_id.SetNull();
    frozen.configuration_hash.begin()[0] ^= 1;
    BOOST_CHECK(!ecx::DecodeBondV2CapitalProjection({}, uint256{}, snapshot, error, consensus));
    BOOST_CHECK_EQUAL(error, "direct-price configuration hash mismatch");
}

BOOST_AUTO_TEST_CASE(v18_no_history_staging_renderer_matches_rust_vector)
{
    ecx::ExchangeConsensus consensus{ConfiguredConsensus(
        50, COutPoint{Txid::FromUint256(uint256S("50")), 0}, uint256S("51"))};
    PopulateTestBondV2FrozenIdentities(consensus);
    consensus.chain_id.fill(1);
    consensus.bond_v2.configuration_hash = RawHash(
        "e931a255224cf33a6a5fa701ceb164e95a17e5c0bb5ac8ab4e4c5ba0728b7363");
    consensus.bond_v2.bond_inbox_redemption_staging_template_commitment =
        RawHash("35eacbcd9ff74d6e37e505f1458b7cbd631a126d437c7a09d50e66eec56f9e56");
    consensus.bond_v2.bond_inbox_redemption_staging_renderer_domain =
        RawHash("d8ca7883769dd73830987f727a34939d2d9b69a3e783e0a2e1cca35fa4872e6f");
    consensus.bond_v2.bond_inbox_redemption_staging_process_cmr =
        RawHash("1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e");
    consensus.bond_v2.bond_inbox_redemption_staging_refund_cmr =
        RawHash("2020202020202020202020202020202020202020202020202020202020202020");
    const uint256 signer{RawHash(
        "e7e9acacbdb43fc9fb71a8db1536c0f866caa78def49f666fa121a6f7954bb01")};
    const uint256 intent{RawHash(
        "3737373737373737373737373737373737373737373737373737373737373737")};
    const uint256 refund_script{RawHash(
        "3838383838383838383838383838383838383838383838383838383838383838")};
    ecx::BondInboxStagingRenderV18 rendered;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        ecx::RenderBondInboxStagingV18(
            signer, intent, 0, refund_script, 1012, rendered, error, consensus),
        error);
    BOOST_CHECK_EQUAL(HexStr(rendered.process_leaf_hash),
        "3fe278e4460370d1ebd1f082504e72ee7d390b2cd0281a58466092a9d0593130");
    BOOST_CHECK_EQUAL(HexStr(rendered.refund_leaf_hash),
        "8a8a8991b79c63483ba9b7bca2ab3738a34ea819d560d520f744d4e83883c778");
    BOOST_CHECK_EQUAL(HexStr(rendered.hidden_node_hash),
        "b9ac34936211f599aa2f0a108936605f9621085b88b80f60ac826e0e7b27e874");
    BOOST_CHECK_EQUAL(HexStr(rendered.lower_branch_hash),
        "e032812b4ac93f75dcf8f2ca08d8d042971802174c055cb6359327f0b8b4389f");
    BOOST_CHECK_EQUAL(HexStr(rendered.top_branch_hash),
        "affa0246f1d6235d5feac1537d8fcd12fa695bea29812c6c39d52c981f32c5d5");
    BOOST_CHECK_EQUAL(HexStr(rendered.script_pubkey),
        "512024fb6e85f3cb2f7a399ce3c62897330d353ddf49aa4e5f2c53ec55e6ef93ba80");
    BOOST_CHECK_EQUAL(HexStr(TestSha256(std::vector<unsigned char>(
        rendered.script_pubkey.begin(), rendered.script_pubkey.end()))),
        "4385ee863343948312e1ac68dbf9e3b9aaa64825ee5bc0723d24cd4f1de1ba0e");

    ecx::ExchangeConsensus wrong_domain{consensus};
    wrong_domain.bond_v2.bond_inbox_redemption_staging_renderer_domain.begin()[0] ^= 1;
    BOOST_CHECK(!ecx::RenderBondInboxStagingV18(
        signer, intent, 0, refund_script, 1012, rendered, error, wrong_domain));
    ecx::ExchangeConsensus key_path_bypass{consensus};
    key_path_bypass.bond_v2.bond_inbox_redemption_staging_internal_key.begin()[0] ^= 1;
    BOOST_CHECK(!ecx::RenderBondInboxStagingV18(
        signer, intent, 0, refund_script, 1012, rendered, error, key_path_bypass));
    ecx::ExchangeConsensus swapped{consensus};
    std::swap(
        swapped.bond_v2.bond_inbox_redemption_staging_process_cmr,
        swapped.bond_v2.bond_inbox_redemption_staging_refund_cmr);
    BOOST_REQUIRE(ecx::RenderBondInboxStagingV18(
        signer, intent, 0, refund_script, 1012, rendered, error, swapped));
    BOOST_CHECK_NE(HexStr(rendered.script_pubkey),
        "512024fb6e85f3cb2f7a399ce3c62897330d353ddf49aa4e5f2c53ec55e6ef93ba80");
}

BOOST_AUTO_TEST_CASE(sp1_v5_annex_binds_exact_public_values_and_preserves_v1)
{
    const std::vector<unsigned char> values{BondV2PublicValuesVector()};
    const uint256 values_hash{TestSha256(values)};
    const std::array<unsigned char, 32> expected_program{{
        0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4,
        0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 8}};
    AnnexVerifierRecorder recorder;
    const std::vector<unsigned char> v2{TestSp1AnnexPayload(true)};
    BOOST_CHECK_EQUAL(
        HexStr(TestSha256(v2)),
        "f5c241fd10f4b0593dc43ad39232e98038a43a39007ae527087fefd14942b57d");
    std::vector<unsigned char> wire_v2{0x50};
    wire_v2.insert(wire_v2.end(), v2.begin(), v2.end());
    BOOST_CHECK_EQUAL(
        HexStr(TestSha256(wire_v2)),
        "71d92946400fd6bd70c3f358eb65ba6b067a0e18cf644154a6ddbc5cc47c302b");
    BOOST_REQUIRE(simplicity_elements_verify_sp1_groth16_v4_public_values_v5_annex_sha256(
        v2.data(), v2.size(), expected_program.data(), values_hash.begin(),
        TestSp1Verifier, &recorder));
    BOOST_CHECK_EQUAL(recorder.calls, 1U);

    std::vector<unsigned char> bad_values{v2};
    bad_values[435] ^= 1;
    BOOST_CHECK(!simplicity_elements_verify_sp1_groth16_v4_public_values_v5_annex_sha256(
        bad_values.data(), bad_values.size(), expected_program.data(),
        values_hash.begin(), TestSp1Verifier, &recorder));
    BOOST_CHECK_EQUAL(recorder.calls, 1U);

    std::vector<unsigned char> bad_mode{v2};
    bad_mode[435 + 556] = 3;
    BOOST_CHECK(!simplicity_elements_verify_sp1_groth16_v4_public_values_v5_annex_sha256(
        bad_mode.data(), bad_mode.size(), expected_program.data(),
        values_hash.begin(), TestSp1Verifier, &recorder));
    BOOST_CHECK_EQUAL(recorder.calls, 1U);

    std::vector<unsigned char> trailing{v2};
    trailing.push_back(0);
    BOOST_CHECK(!simplicity_elements_verify_sp1_groth16_v4_public_values_v5_annex_sha256(
        trailing.data(), trailing.size(), expected_program.data(),
        values_hash.begin(), TestSp1Verifier, &recorder));
    BOOST_CHECK_EQUAL(recorder.calls, 1U);

    std::vector<unsigned char> duplicate{v2};
    duplicate.insert(duplicate.end(), values.begin(), values.end());
    BOOST_CHECK(!simplicity_elements_verify_sp1_groth16_v4_public_values_v5_annex_sha256(
        duplicate.data(), duplicate.size(), expected_program.data(),
        values_hash.begin(), TestSp1Verifier, &recorder));
    BOOST_CHECK_EQUAL(recorder.calls, 1U);

    const std::vector<unsigned char> v1{TestSp1AnnexPayload(false)};
    BOOST_CHECK(!simplicity_elements_verify_sp1_groth16_v4_public_values_v5_annex_sha256(
        v1.data(), v1.size(), expected_program.data(), values_hash.begin(),
        TestSp1Verifier, &recorder));
    BOOST_CHECK_EQUAL(recorder.calls, 1U);
    BOOST_REQUIRE(simplicity_elements_verify_sp1_groth16_annex_sha256(
        v1.data(), v1.size(), expected_program.data(), values_hash.begin(),
        TestSp1Verifier, &recorder, false));
    BOOST_CHECK_EQUAL(recorder.calls, 2U);

    std::vector<unsigned char> wrong_version{v2};
    wrong_version[7] = 2;
    BOOST_CHECK(!simplicity_elements_verify_sp1_groth16_v4_public_values_v5_annex_sha256(
        wrong_version.data(), wrong_version.size(), expected_program.data(),
        values_hash.begin(), TestSp1Verifier, &recorder));
    BOOST_CHECK_EQUAL(recorder.calls, 2U);
}

BOOST_AUTO_TEST_CASE(sp1_haskell_proof_callback_boundary)
{
    const auto annex=TestSp1AnnexPayload(true);
    const auto hash=+[](unsigned char* output,const unsigned char* input,size_t size) {
        CSHA256().Write(input,size).Finalize(output);
        return true;
    };
    const auto failedHash=+[](unsigned char*,const unsigned char*,size_t) { return false; };
    AnnexVerifierRecorder recorder;
    const auto call=[&](auto hasher,auto verifier) {
        return elements_haskell_groth16_proof(2,annex.data(),annex.size(),annex.data()+11,
            annex.data()+43,hasher,verifier,&recorder);
    };
    BOOST_REQUIRE(call(hash,TestSp1Verifier));
    BOOST_CHECK_EQUAL(recorder.calls,1U);
    recorder.calls=0;
    BOOST_CHECK(!call(failedHash,TestSp1Verifier));
    BOOST_CHECK(!call(nullptr,TestSp1Verifier));
    BOOST_CHECK(!call(hash,nullptr));
    BOOST_CHECK(!elements_haskell_groth16_proof(2,nullptr,annex.size(),annex.data()+11,
        annex.data()+43,hash,TestSp1Verifier,&recorder));
    BOOST_CHECK(!elements_haskell_groth16_proof(2,annex.data(),SIZE_MAX,annex.data()+11,
        annex.data()+43,hash,TestSp1Verifier,&recorder));
    BOOST_CHECK(!elements_haskell_groth16_proof(99,annex.data(),annex.size(),annex.data()+11,
        annex.data()+43,hash,TestSp1Verifier,&recorder));
    BOOST_CHECK_EQUAL(recorder.calls,0U);
    recorder.reject=true;
    BOOST_CHECK(!call(hash,TestSp1Verifier));
    BOOST_CHECK_EQUAL(recorder.calls,1U);
}

BOOST_AUTO_TEST_CASE(sp1_shared_envelope_parser_boundaries)
{
    using Parser = bool (*)(const unsigned char*,size_t,unsigned char*,unsigned char*,unsigned char*);
    const std::array<Parser,4> parsers{
        simplicity_elements_parse_sp1_groth16_v2_annex,
        simplicity_elements_parse_sp1_groth16_v4_public_values_v5_annex,
        simplicity_elements_parse_sp1_groth16_v5_incremental_activation_annex,
        simplicity_elements_parse_sp1_groth16_v6_incremental_successor_annex};
    constexpr size_t prefix = 79 + ECX_SP1_GROTH16_PROOF_LEN;
    auto legacy = TestSp1AnnexPayload(true);
    legacy.resize(prefix + ECX_SP1_PUBLIC_VALUES_V4_LEN);
    legacy[7] = 3;
    legacy[prefix+35] = 4;
    const auto hash = TestSha256(std::vector<unsigned char>(legacy.begin()+prefix,legacy.end()));
    std::copy(hash.begin(),hash.end(),legacy.begin()+43);
    const std::array fixtures{legacy,TestSp1AnnexPayload(true),
        TestIncrementalActivationAnnexPayload(),TestIncrementalSuccessorAnnexPayload()};
    for (size_t kind=0; kind<parsers.size(); ++kind) {
        const auto& valid = fixtures[kind];
        BOOST_CHECK(elements_haskell_groth16_header(valid[7],valid.data(),79));
        BOOST_CHECK(!elements_haskell_groth16_header(valid[7],valid.data(),78));
        BOOST_CHECK(!elements_haskell_groth16_header(valid[7],valid.data(),80));
        BOOST_CHECK(!elements_haskell_groth16_header(valid[7],nullptr,79));
        BOOST_CHECK(!elements_haskell_groth16_header(256,valid.data(),79));
        if (kind!=2) {
            const uint32_t version=kind==0 ? 4 : kind==1 ? 5 : 23;
            const uint32_t size=valid.size()-prefix;
            BOOST_CHECK(elements_haskell_canonical_values(version,valid.data()+prefix,size));
            BOOST_CHECK(!elements_haskell_canonical_values(version,valid.data()+prefix,size-1));
            BOOST_CHECK(!elements_haskell_canonical_values(version,valid.data()+prefix,size+1));
            BOOST_CHECK(!elements_haskell_canonical_values(version,nullptr,size));
            BOOST_CHECK(!elements_haskell_canonical_values(99,valid.data()+prefix,size));
        }
        const auto check = [&](const std::vector<unsigned char>& input, bool expected, int missing=0) {
            std::array<unsigned char,34> program, digest;
            program.fill(0x5a); digest.fill(0x5a);
            std::vector<unsigned char> values(valid.size()-prefix+2,0x5a);
            BOOST_CHECK_EQUAL(parsers[kind](missing==1 ? nullptr : input.data(),input.size(),
                missing==2 ? nullptr : program.data()+1,missing==3 ? nullptr : digest.data()+1,
                missing==4 ? nullptr : values.data()+1),expected);
            if (expected) {
                BOOST_CHECK(std::equal(program.begin()+1,program.end()-1,input.begin()+11));
                BOOST_CHECK(std::equal(digest.begin()+1,digest.end()-1,input.begin()+43));
                BOOST_CHECK(std::equal(values.begin()+1,values.end()-1,input.begin()+prefix));
            } else {
                BOOST_CHECK(std::all_of(program.begin(),program.end(),[](auto c) { return c==0x5a; }));
                BOOST_CHECK(std::all_of(digest.begin(),digest.end(),[](auto c) { return c==0x5a; }));
                BOOST_CHECK(std::all_of(values.begin(),values.end(),[](auto c) { return c==0x5a; }));
            }
            BOOST_CHECK(program.front()==0x5a && program.back()==0x5a && digest.front()==0x5a &&
                digest.back()==0x5a && values.front()==0x5a && values.back()==0x5a);
        };
        check(valid,true);
        for (int missing=1; missing<=4; ++missing) check(valid,false,missing);
        for (size_t offset : std::array<size_t,8>{0,7,8,9,10,43,75,78}) {
            auto changed=valid; changed[offset]^=1; check(changed,false);
        }
        auto changed=valid; changed.pop_back(); check(changed,false);
        changed=valid; changed.push_back(0); check(changed,false);
        changed=valid; std::fill(changed.begin()+11,changed.begin()+43,0); check(changed,false);
        changed=valid; changed[11]=0x7f; changed[12]=0; changed[13]=0; changed[14]=1; check(changed,false);
        for (size_t other=0; other<fixtures.size(); ++other) if (kind!=other) check(fixtures[other],false);
    }
}

BOOST_AUTO_TEST_CASE(sp1_haskell_parse_publication_boundary)
{
    const auto annex=TestSp1AnnexPayload(true);
    const auto hash=+[](unsigned char* output,const unsigned char* input,size_t size) {
        CSHA256().Write(input,size).Finalize(output);
        return true;
    };
    const auto failedHash=+[](unsigned char*,const unsigned char*,size_t) { return false; };
    std::array<unsigned char,34> program,digest;
    std::array<unsigned char,852> values;
    const auto check=[&](uint32_t capacity,size_t size,auto hasher,bool expected) {
        program.fill(0x5a); digest.fill(0x5a); values.fill(0x5a);
        BOOST_CHECK_EQUAL(elements_haskell_parse_groth16(2,annex.data(),size,program.data()+1,
            digest.data()+1,values.data()+1,capacity,hasher),expected);
        if (expected) {
            BOOST_CHECK(std::equal(program.begin()+1,program.end()-1,annex.begin()+11));
            BOOST_CHECK(std::equal(digest.begin()+1,digest.end()-1,annex.begin()+43));
            BOOST_CHECK(std::equal(values.begin()+1,values.end()-1,annex.begin()+435));
        } else {
            BOOST_CHECK(std::all_of(program.begin(),program.end(),[](auto c){return c==0x5a;}));
            BOOST_CHECK(std::all_of(digest.begin(),digest.end(),[](auto c){return c==0x5a;}));
            BOOST_CHECK(std::all_of(values.begin(),values.end(),[](auto c){return c==0x5a;}));
        }
        BOOST_CHECK(program.front()==0x5a && program.back()==0x5a && digest.front()==0x5a &&
            digest.back()==0x5a && values.front()==0x5a && values.back()==0x5a);
    };
    check(850,annex.size(),hash,true);
    for (uint32_t capacity : {0U,849U,851U,UINT32_MAX}) check(capacity,annex.size(),hash,false);
    check(850,SIZE_MAX,hash,false);
    check(850,annex.size(),failedHash,false);
    check(850,annex.size(),nullptr,false);
}

BOOST_AUTO_TEST_CASE(sp1_shared_frame_dispatch_matrix)
{
    auto v4=TestSp1AnnexPayload(true);
    v4.resize(435+609);
    v4[7]=3;
    v4[435+35]=4;
    const auto digest=TestSha256(std::vector<unsigned char>(v4.begin()+435,v4.end()));
    std::copy(digest.begin(),digest.end(),v4.begin()+43);
    const std::array fixtures{TestSp1AnnexPayload(false),v4,TestSp1AnnexPayload(true),
        TestIncrementalActivationAnnexPayload(),TestIncrementalSuccessorAnnexPayload()};
    struct Expected { const std::vector<unsigned char>* annex; unsigned calls{0}; };
    const auto verifier=+[](void* context,const unsigned char* proof,size_t size,
                           const uint32_t* program,const unsigned char* hash) {
        auto& expected=*static_cast<Expected*>(context);
        ++expected.calls;
        const auto& annex=*expected.annex;
        if (size!=356 || !std::equal(proof,proof+size,annex.begin()+79) ||
            !std::equal(hash,hash+32,annex.begin()+43)) return false;
        for (uint32_t i=0; i<8; ++i) if (program[i]!=i+1) return false;
        return true;
    };
    for (uint32_t kind=0; kind<5; ++kind) {
        for (size_t format=0; format<fixtures.size(); ++format) {
            const auto& annex=fixtures[format];
            Expected expected{&annex};
            bool accepted=false;
            BOOST_REQUIRE(ecx_test_groth16_jet_frame(kind,annex.data(),annex.size(),
                annex.data()+11,annex.data()+43,verifier,&expected,&accepted));
            const bool supported=kind==format || (kind==0 && format==1);
            BOOST_CHECK_EQUAL(accepted,supported);
            BOOST_CHECK_EQUAL(expected.calls,supported ? 1U : 0U);
            BOOST_REQUIRE(ecx_test_groth16_jet_frame(kind,annex.data(),annex.size(),
                annex.data()+11,annex.data()+43,nullptr,&expected,&accepted));
            BOOST_CHECK(!accepted);
        }
    }
}

BOOST_AUTO_TEST_CASE(sp1_incremental_activation_annex_is_disjoint_and_fail_closed)
{
    const std::array<unsigned char, 32> expected_program{{
        0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4,
        0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 8}};
    const std::vector<unsigned char> values{
        IncrementalActivationPublicValuesVector()};
    const uint256 digest{TestSha256(values)};
    const std::vector<unsigned char> annex{TestIncrementalActivationAnnexPayload()};
    std::array<unsigned char, 32> parsed_program{};
    std::array<unsigned char, 32> parsed_digest{};
    std::array<unsigned char, ECX_SP1_INCREMENTAL_ACTIVATION_PUBLIC_VALUES_LEN>
        parsed_values{};
    AnnexVerifierRecorder recorder;

    BOOST_REQUIRE(simplicity_elements_parse_sp1_groth16_v5_incremental_activation_annex(
        annex.data(), annex.size(), parsed_program.data(), parsed_digest.data(),
        parsed_values.data()));
    BOOST_CHECK(std::equal(
        expected_program.begin(), expected_program.end(), parsed_program.begin()));
    BOOST_CHECK(std::equal(digest.begin(), digest.end(), parsed_digest.begin()));
    BOOST_CHECK(std::equal(values.begin(), values.end(), parsed_values.begin()));
    BOOST_REQUIRE(simplicity_elements_verify_sp1_groth16_v5_incremental_activation_annex_sha256(
        annex.data(), annex.size(), expected_program.data(), digest.begin(),
        TestIncrementalActivationSp1Verifier, &recorder));
    BOOST_CHECK_EQUAL(recorder.calls, 1U);

    std::array<unsigned char, ECX_SP1_PUBLIC_VALUES_V5_LEN> normal_values{};
    BOOST_CHECK(!simplicity_elements_parse_sp1_groth16_v4_public_values_v5_annex(
        annex.data(), annex.size(), parsed_program.data(), parsed_digest.data(),
        normal_values.data()));
    const std::vector<unsigned char> normal{TestSp1AnnexPayload(true)};
    BOOST_CHECK(!simplicity_elements_parse_sp1_groth16_v5_incremental_activation_annex(
        normal.data(), normal.size(), parsed_program.data(), parsed_digest.data(),
        parsed_values.data()));

    std::vector<unsigned char> bad_semantics{annex};
    WriteBE64(bad_semantics.data() + 435 + 348, 101);
    // Keep the digest valid so rejection exercises lower > mark, not hashing.
    const auto bad_semantics_hash = TestSha256(
        std::vector<unsigned char>(bad_semantics.begin() + 435, bad_semantics.end()));
    std::copy(bad_semantics_hash.begin(), bad_semantics_hash.end(), bad_semantics.begin() + 43);
    BOOST_CHECK(!simplicity_elements_parse_sp1_groth16_v5_incremental_activation_annex(
        bad_semantics.data(), bad_semantics.size(), parsed_program.data(),
        parsed_digest.data(), parsed_values.data()));

    std::vector<unsigned char> wrong_digest{annex};
    wrong_digest[43] ^= 1;
    BOOST_CHECK(!simplicity_elements_parse_sp1_groth16_v5_incremental_activation_annex(
        wrong_digest.data(), wrong_digest.size(), parsed_program.data(),
        parsed_digest.data(), parsed_values.data()));
    std::vector<unsigned char> wrong_version{annex};
    wrong_version[7] = 4;
    BOOST_CHECK(!simplicity_elements_parse_sp1_groth16_v5_incremental_activation_annex(
        wrong_version.data(), wrong_version.size(), parsed_program.data(),
        parsed_digest.data(), parsed_values.data()));
    std::vector<unsigned char> trailing{annex};
    trailing.push_back(0);
    BOOST_CHECK(!simplicity_elements_parse_sp1_groth16_v5_incremental_activation_annex(
        trailing.data(), trailing.size(), parsed_program.data(),
        parsed_digest.data(), parsed_values.data()));

    recorder.reject = true;
    BOOST_CHECK(!simplicity_elements_verify_sp1_groth16_v5_incremental_activation_annex_sha256(
        annex.data(), annex.size(), expected_program.data(), digest.begin(),
        TestIncrementalActivationSp1Verifier, &recorder));
    BOOST_CHECK_EQUAL(recorder.calls, 2U);
}

BOOST_AUTO_TEST_CASE(sp1_incremental_successor_annex_is_exact_disjoint_and_fail_closed)
{
    const std::array<unsigned char, 32> expected_program{{
        0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4,
        0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 8}};
    const std::vector<unsigned char> values{
        IncrementalSuccessorPublicValuesVector()};
    const uint256 digest{TestSha256(values)};
    const std::vector<unsigned char> annex{TestIncrementalSuccessorAnnexPayload()};
    std::array<unsigned char, 32> parsed_program{};
    std::array<unsigned char, 32> parsed_digest{};
    std::array<unsigned char, ECX_SP1_INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN>
        parsed_values{};
    AnnexVerifierRecorder recorder;

    BOOST_REQUIRE(simplicity_elements_parse_sp1_groth16_v6_incremental_successor_annex(
        annex.data(), annex.size(), parsed_program.data(), parsed_digest.data(),
        parsed_values.data()));
    BOOST_CHECK(std::equal(
        expected_program.begin(), expected_program.end(), parsed_program.begin()));
    BOOST_CHECK(std::equal(digest.begin(), digest.end(), parsed_digest.begin()));
    BOOST_CHECK(std::equal(values.begin(), values.end(), parsed_values.begin()));
    BOOST_REQUIRE(simplicity_elements_verify_sp1_groth16_v6_incremental_successor_annex_sha256(
        annex.data(), annex.size(), expected_program.data(), digest.begin(),
        TestIncrementalSuccessorSp1Verifier, &recorder));
    BOOST_CHECK_EQUAL(recorder.calls, 1U);

    std::array<unsigned char, ECX_SP1_INCREMENTAL_ACTIVATION_PUBLIC_VALUES_LEN>
        activation_values{};
    BOOST_CHECK(!simplicity_elements_parse_sp1_groth16_v5_incremental_activation_annex(
        annex.data(), annex.size(), parsed_program.data(), parsed_digest.data(),
        activation_values.data()));
    const std::vector<unsigned char> activation{TestIncrementalActivationAnnexPayload()};
    BOOST_CHECK(!simplicity_elements_parse_sp1_groth16_v6_incremental_successor_annex(
        activation.data(), activation.size(), parsed_program.data(), parsed_digest.data(),
        parsed_values.data()));

    const size_t values_offset{435};
    const size_t scalar_offset{values_offset + 4 + 40 * 32};
    const size_t wide_offset{scalar_offset + 12 * 8 + 16};
    const auto recommit = [](std::vector<unsigned char>& candidate) {
        const std::vector<unsigned char> public_values{
            candidate.begin() + 435, candidate.end()};
        const uint256 hash{TestSha256(public_values)};
        std::copy(hash.begin(), hash.end(), candidate.begin() + 43);
    };
    std::vector<unsigned char> wrong_deficit{annex};
    wrong_deficit[wide_offset + 32 + 15] = 9;
    recommit(wrong_deficit);
    BOOST_CHECK(!simplicity_elements_parse_sp1_groth16_v6_incremental_successor_annex(
        wrong_deficit.data(), wrong_deficit.size(), parsed_program.data(),
        parsed_digest.data(), parsed_values.data()));
    std::vector<unsigned char> wrong_mode{annex};
    wrong_mode[values_offset + 1624] = 0;
    recommit(wrong_mode);
    BOOST_CHECK(!simplicity_elements_parse_sp1_groth16_v6_incremental_successor_annex(
        wrong_mode.data(), wrong_mode.size(), parsed_program.data(),
        parsed_digest.data(), parsed_values.data()));
    std::vector<unsigned char> noncanonical_bool{annex};
    noncanonical_bool.back() = 2;
    recommit(noncanonical_bool);
    BOOST_CHECK(!simplicity_elements_parse_sp1_groth16_v6_incremental_successor_annex(
        noncanonical_bool.data(), noncanonical_bool.size(), parsed_program.data(),
        parsed_digest.data(), parsed_values.data()));
    for (const auto& mutation : std::vector<std::pair<size_t, unsigned char>>{
             {scalar_offset + 48 + 7, 1},       // fixed issued supply
             {wide_offset + 112 + 15, 1},       // NAV
             {wide_offset + 144 + 15, 28},      // queue head > tail
             {wide_offset + 192 + 15, 41},      // inbox cursor > count
             {scalar_offset + 80 + 7, 1},       // funding epoch
             {values_offset + 1625, 4},         // oracle mode
         }) {
        std::vector<unsigned char> candidate{annex};
        candidate[mutation.first] = mutation.second;
        recommit(candidate);
        BOOST_CHECK(!simplicity_elements_parse_sp1_groth16_v6_incremental_successor_annex(
            candidate.data(), candidate.size(), parsed_program.data(),
            parsed_digest.data(), parsed_values.data()));
    }
    std::vector<unsigned char> trailing{annex};
    trailing.push_back(0);
    BOOST_CHECK(!simplicity_elements_parse_sp1_groth16_v6_incremental_successor_annex(
        trailing.data(), trailing.size(), parsed_program.data(), parsed_digest.data(),
        parsed_values.data()));

    recorder.reject = true;
    BOOST_CHECK(!simplicity_elements_verify_sp1_groth16_v6_incremental_successor_annex_sha256(
        annex.data(), annex.size(), expected_program.data(), digest.begin(),
        TestIncrementalSuccessorSp1Verifier, &recorder));
    BOOST_CHECK_EQUAL(recorder.calls, 2U);
}

BOOST_AUTO_TEST_CASE(sp1_incremental_successor_jet_frame_routes_to_exact_verifier)
{
    // This tests the real frame adapter and annex parser. The recorder is a
    // test callback, not a substitute for the separately qualified SP1 backend.
    const std::array<unsigned char, 32> expected_program{{
        0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4,
        0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 8}};
    const std::vector<unsigned char> annex{TestIncrementalSuccessorAnnexPayload()};
    const uint256 digest{TestSha256(IncrementalSuccessorPublicValuesVector())};
    AnnexVerifierRecorder recorder;
    const auto evaluate = [&](const std::vector<unsigned char>& candidate,
                              const std::array<unsigned char, 32>& program,
                              const uint256& public_values_digest,
                              bool backend_present = true) {
        bool valid{false};
        BOOST_REQUIRE(ecx_test_successor_jet_frame(
            candidate.data(), candidate.size(), program.data(), public_values_digest.begin(),
            backend_present ? TestIncrementalSuccessorSp1Verifier : nullptr, &recorder, &valid));
        return valid;
    };
    BOOST_CHECK(evaluate(annex, expected_program, digest));
    BOOST_CHECK_EQUAL(recorder.calls, 1U);
    auto wrong_program{expected_program};
    wrong_program[0] ^= 1;
    BOOST_CHECK(!evaluate(annex, wrong_program, digest));
    uint256 wrong_digest{digest};
    wrong_digest.begin()[0] ^= 1;
    BOOST_CHECK(!evaluate(annex, expected_program, wrong_digest));
    BOOST_CHECK(!evaluate(annex, expected_program, digest, false));
    BOOST_CHECK(!evaluate({}, expected_program, digest));
    BOOST_CHECK(!evaluate(TestIncrementalActivationAnnexPayload(), expected_program, digest));
    auto truncated{annex};
    truncated.pop_back();
    BOOST_CHECK(!evaluate(truncated, expected_program, digest));
    auto trailing{annex};
    trailing.push_back(0);
    BOOST_CHECK(!evaluate(trailing, expected_program, digest));
    auto bad_bool{annex};
    bad_bool.back() = 2;
    const uint256 recommitted{TestSha256(std::vector<unsigned char>{bad_bool.begin() + 435, bad_bool.end()})};
    std::copy(recommitted.begin(), recommitted.end(), bad_bool.begin() + 43);
    BOOST_CHECK(!evaluate(bad_bool, expected_program, recommitted));
    BOOST_CHECK_EQUAL(recorder.calls, 1U); // Parser/identity failures never reach the backend.
    recorder.reject = true;
    BOOST_CHECK(!evaluate(annex, expected_program, digest));
    BOOST_CHECK_EQUAL(recorder.calls, 2U);
}

BOOST_AUTO_TEST_CASE(incremental_successor_projection_script_and_u128_snapshot_are_exact)
{
    ecx::ExchangeConsensus consensus{ConfiguredConsensus(
        50, COutPoint{Txid::FromUint256(uint256S("50")), 0}, uint256S("51"))};
    PopulateTestBondV2FrozenIdentities(consensus);
    const auto fill = [](uint256& value, unsigned char byte) {
        std::fill(value.begin(), value.end(), byte);
    };
    const std::array<unsigned char, 32> successor_program{{
        0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4,
        0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 8}};
    std::copy(successor_program.begin(), successor_program.end(),
        consensus.bond_v2.incremental_successor_program_id.begin());
    fill(consensus.bond_v2.incremental_successor_configuration_hash, 1);
    fill(consensus.bond_v2.configuration_hash, 13);
    consensus.chain_id.fill(14);
    fill(consensus.bond_v2.bond_asset_id, 15);
    fill(consensus.bond_v2.bond_deployment_commitment, 16);
    fill(consensus.bond_v2.inventory_covenant_script_sha256, 17);
    fill(consensus.bond_v2.transition_program_id, 80);
    fill(consensus.bond_v2.transition_journal_domain_sha256, 77);
    fill(consensus.bond_v2.transition_cmr, 78);
    fill(consensus.bond_v2.identity_derivation_record_sha256, 79);

    std::vector<unsigned char> annex{TestIncrementalSuccessorAnnexPayload()};
    const size_t public_values_offset{435};
    const size_t wide_offset{4 + 40 * 32 + 112};
    for (const size_t field_offset : {
             size_t{96},  // matcher execution sequence
             size_t{176}, // inbox entry count
             size_t{192}, // inbox processed cursor
             size_t{208}, // inbox outcome count
         }) {
        annex[public_values_offset + wide_offset + field_offset + 7] = 1;
    }
    RecommitIncrementalSuccessorPublicValues(annex);

    ecx::BondV2CapitalSnapshot snapshot;
    std::string error;
    const uint256 active_root{uint256S("52")};
    BOOST_REQUIRE_MESSAGE(
        ecx::DecodeBondV2IncrementalSuccessorCapitalProjection(
            annex, active_root, snapshot, error, consensus),
        error);
    BOOST_CHECK_EQUAL(snapshot.version, ecx::BOND_V2_CAPITAL_SNAPSHOT_VERSION);
    BOOST_CHECK_EQUAL(snapshot.proof_profile, 1U);
    BOOST_CHECK(snapshot.exchange_state_root == active_root);
    const auto decoded_snapshot_hash = (HashWriter{} << snapshot).GetHash();
    BOOST_CHECK(!ecx::DecodeBondV2IncrementalSuccessorCapitalProjection(annex,uint256{},snapshot,error,consensus));
    BOOST_CHECK_EQUAL(error,"ECX incremental successor projection has no active exchange root");
    BOOST_CHECK((HashWriter{} << snapshot).GetHash() == decoded_snapshot_hash);
    BOOST_CHECK(!ecx::DecodeBondV2IncrementalSuccessorCapitalProjection({},active_root,snapshot,error,consensus));
    BOOST_CHECK_EQUAL(error,"ECX incremental successor lacks one canonical version-6/PublicValuesV23 annex");
    BOOST_CHECK((HashWriter{} << snapshot).GetHash() == decoded_snapshot_hash);
    BOOST_CHECK(snapshot.configuration_hash ==
        consensus.bond_v2.incremental_successor_configuration_hash);
    uint256 expected_outcome_root;
    uint256 expected_availability_root;
    fill(expected_outcome_root, 25);
    fill(expected_availability_root, 8);
    BOOST_CHECK(snapshot.bond_inbox_outcome_root == expected_outcome_root);
    BOOST_CHECK(snapshot.encrypted_availability_root == expected_availability_root);
    BOOST_CHECK(snapshot.node_bond_inbox_head_root == snapshot.bond_inbox_head_root);
    BOOST_CHECK(!snapshot.matcher_execution_sequence.FitsU64());
    BOOST_CHECK(!snapshot.bond_inbox_entry_count.FitsU64());
    BOOST_CHECK(!snapshot.bond_inbox_processed_cursor.FitsU64());
    BOOST_CHECK(!snapshot.bond_inbox_outcome_count.FitsU64());

    for (const auto& [bytes, offset] : std::array<std::pair<const unsigned char*, size_t>, 13>{{
        {snapshot.global_funding_index_numerator.data(), wide_offset - 16},
        {snapshot.full_bound_deficit.data(), wide_offset + 32},
        {snapshot.target_reserve.data(), wide_offset + 48},
        {snapshot.insurance_reserve.data(), wide_offset + 64},
        {snapshot.controlled_usdd_atoms.data(), wide_offset + 80},
        {snapshot.matcher_execution_sequence.bytes.data(), wide_offset + 96},
        {snapshot.nav_per_whole_share.data(), wide_offset + 112},
        {snapshot.coverage_bps.data(), wide_offset + 128},
        {snapshot.redemption_head.bytes.data(), wide_offset + 144},
        {snapshot.redemption_tail.bytes.data(), wide_offset + 160},
        {snapshot.bond_inbox_entry_count.bytes.data(), wide_offset + 176},
        {snapshot.bond_inbox_processed_cursor.bytes.data(), wide_offset + 192},
        {snapshot.bond_inbox_outcome_count.bytes.data(), wide_offset + 208}}}) {
        BOOST_CHECK(std::equal(bytes, bytes + 16, annex.begin() + public_values_offset + offset));
    }

    CScript rendered;
    BOOST_REQUIRE(ecx::ComputeBondV2IncrementalSuccessorScript(
        consensus, snapshot.covenant_state_hash, rendered));
    BOOST_CHECK(rendered == TestBondV2IncrementalSuccessorScript(
        consensus, snapshot.covenant_state_hash));
    BOOST_CHECK(rendered != TestBondV2SuccessorScript(
        consensus, snapshot.covenant_state_hash));

    for (unsigned flags = 0; flags < 8; ++flags) {
        auto missing = consensus;
        auto state_root = snapshot.covenant_state_hash;
        if (!(flags & 1)) state_root.SetNull();
        if (!(flags & 2)) missing.bond_v2.incremental_successor_transition_cmr.SetNull();
        if (!(flags & 4)) missing.bond_v2.incremental_successor_state_node_domain_sha256.SetNull();
        const CScript sentinel = CScript() << OP_RETURN;
        CScript actual = sentinel;
        BOOST_CHECK_EQUAL(ecx::ComputeBondV2IncrementalSuccessorScript(missing, state_root, actual), flags == 7);
        BOOST_CHECK(actual == (flags == 7 ? rendered : sentinel));
    }

    // Bind the decoded u128 state to a real transition/header context.
    CMutableTransaction transition;
    transition.vin.emplace_back(COutPoint{Txid::FromUint256(uint256S("60")),0});
    transition.vout.push_back(AuthorityOutput(1));
    transition.vout[0].scriptPubKey=rendered;
    CBlock prior_block;
    prior_block.hashExchangeStateRoot=uint256S("61");
    TestBlockIndex previous{prior_block,50};
    previous.ecxBondV2Capital=snapshot;
    previous.ecxBondV2Capital->exchange_state_root=prior_block.hashExchangeStateRoot;
    std::copy_n(annex.begin()+435+36,32,previous.ecxBondV2Capital->covenant_state_hash.begin());
    const uint256 parent_hash=uint256S("62");
    const auto bind=[&](size_t offset,const uint256& hash) { std::copy(hash.begin(),hash.end(),annex.begin()+435+offset); };
    bind(100,CTransaction(transition).GetHash().ToUint256());
    bind(132,prior_block.hashExchangeStateRoot);
    bind(164,parent_hash);
    WriteBE64(annex.data()+435+1284,8);
    WriteBE64(annex.data()+435+1292,9);
    WriteBE64(annex.data()+435+1300,51);
    MemoryCoinsView base;
    CCoinsViewCache view{&base};
    ecx::BondV2CapitalSnapshot projected;
    const auto project=[&](std::vector<unsigned char> payload) {
        RecommitIncrementalSuccessorPublicValues(payload);
        payload.insert(payload.begin(),0x50);
        transition.witness.vtxinwit.resize(1);
        transition.witness.vtxinwit[0].scriptWitness.stack={{0},std::move(payload)};
        CBlock block;
        block.vtx={MakeTransactionRef(transition)};
        block.hashExchangeStateRoot=ecx::ComputeStateUtxoRoot(Params().GetConsensus().hashGenesisBlock,
            COutPoint{block.vtx[0]->GetHash(),0},transition.vout[0]);
        return ecx::DeriveBondV2CapitalProjectionAfterScripts(block,&previous,view,51,parent_hash,8,9,projected,error,consensus);
    };
    BOOST_REQUIRE_MESSAGE(project(annex),error);
    BOOST_CHECK(projected.previous_matcher_execution_sequence==snapshot.matcher_execution_sequence);
    BOOST_CHECK_EQUAL(projected.last_transition_sidechain_height,51U);
    for (size_t offset : {36U,100U,132U,164U,1291U,1299U,1307U}) {
        auto changed=annex;
        changed[435+offset]^=1;
        BOOST_CHECK(!project(changed));
        BOOST_CHECK_EQUAL(error,"ECX incremental successor does not bind the transition/header/BMM/cursor context");
    }
    BOOST_REQUIRE_MESSAGE(project(annex),error);

    DataStream serialized;
    serialized << snapshot;
    ecx::BondV2CapitalSnapshot round_trip;
    serialized >> round_trip;
    BOOST_CHECK(round_trip.matcher_execution_sequence ==
        snapshot.matcher_execution_sequence);
    BOOST_CHECK(round_trip.bond_inbox_entry_count == snapshot.bond_inbox_entry_count);
    BOOST_CHECK(round_trip.bond_inbox_processed_cursor ==
        snapshot.bond_inbox_processed_cursor);
    BOOST_CHECK(round_trip.bond_inbox_outcome_count ==
        snapshot.bond_inbox_outcome_count);

    std::vector<unsigned char> changed_outcome{annex};
    changed_outcome[public_values_offset + 4 + 24 * 32] ^= 0x80;
    RecommitIncrementalSuccessorPublicValues(changed_outcome);
    ecx::BondV2CapitalSnapshot changed_snapshot;
    BOOST_REQUIRE_MESSAGE(
        ecx::DecodeBondV2IncrementalSuccessorCapitalProjection(
            changed_outcome, active_root, changed_snapshot, error, consensus),
        error);
    BOOST_CHECK(changed_snapshot.bond_inbox_outcome_root !=
        snapshot.bond_inbox_outcome_root);

    std::vector<unsigned char> wrong_configuration{annex};
    wrong_configuration[public_values_offset + 4] ^= 1;
    RecommitIncrementalSuccessorPublicValues(wrong_configuration);
    BOOST_CHECK(!ecx::DecodeBondV2IncrementalSuccessorCapitalProjection(
        wrong_configuration, active_root, changed_snapshot, error, consensus));
    BOOST_CHECK(error.find("frozen program/configuration/deployment") !=
        std::string::npos);
}

BOOST_AUTO_TEST_CASE(finite_source_accepts_real_custody_fixture)
{
    auto consensus = ConfiguredConsensus(50, COutPoint{Txid::FromUint256(uint256S("50")), 0}, uint256S("51"));
    PopulateTestBondV2FrozenIdentities(consensus);
    consensus.chain_id.fill(1);
    std::fill(consensus.bond_v2.configuration_hash.begin(), consensus.bond_v2.configuration_hash.end(), 2);
    consensus.bond_v2.availability_scheme_hash = RawHash(ECX_FINITE_SCHEME);
    consensus.bond_v2.availability_custodian_registry_hash = RawHash(ECX_FINITE_REGISTRY);
    for (size_t i = 0; i < 5; ++i) {
        const auto encryption = ParseHex(ECX_FINITE_ENCRYPTION[i]);
        const auto attestation = ParseHex(ECX_FINITE_ATTESTATION[i]);
        std::copy(encryption.begin(), encryption.end(), consensus.bond_v2.custodian_encryption_keys[i].begin());
        std::copy(attestation.begin(), attestation.end(), consensus.bond_v2.custodian_attestation_keys[i].begin());
    }
    CMutableTransaction source;
    source.vin.emplace_back(COutPoint{Txid::FromUint256(uint256S("61")), 0});
    source.vout.emplace_back(::policyAsset, 0, CScript() << OP_RETURN << ParseHex(ECX_FINITE_MARKER));
    source.witness.vtxinwit.resize(1);
    source.witness.vtxinwit[0].scriptWitness.stack = {std::vector<unsigned char>(64, 0x33), ParseHex(ECX_FINITE_ANNEX)};
    CBlock block;
    block.vtx.push_back(MakeTransactionRef(source));
    ecx::BondV2CapitalSnapshot initial;
    initial.node_bond_inbox_head_root = uint256S("52");
    auto snapshot = initial;
    std::vector<ecx::BondInboxSourceExport> exported;
    std::string error;
    BOOST_REQUIRE_MESSAGE(ecx::IsCanonicalBondInboxSourceTransaction(*block.vtx[0], error, consensus), error);
    const std::vector<std::vector<std::vector<unsigned char>>> other_stacks{
        {}, {{}}, {{0x51}}, {{0x50}}, {{0x50},{0x51}}, {{0x51},{0x50}}, {{},{0x50}}};
    for (size_t input = 0; input < 4; ++input) {
        for (bool issuance : {false,true}) {
            auto changed = source;
            changed.vin.resize(4);
            changed.witness.vtxinwit.resize(4);
            if (issuance) changed.vin[input].assetIssuance.nAmount = CConfidentialValue(1);
            else changed.vin[input].m_is_pegin = true;
            BOOST_CHECK(!ecx::IsCanonicalBondInboxSourceTransaction(CTransaction(changed), error, consensus));
            BOOST_CHECK_EQUAL(error, "ECX bond-inbox source transaction has an invalid input/output/witness form");
        }
    }
    for (const auto& stack : other_stacks) {
        for (size_t input = 1; input <= 3; ++input) {
            auto changed = source;
            changed.vin.resize(4);
            changed.witness.vtxinwit.resize(4);
            changed.witness.vtxinwit[input].scriptWitness.stack = stack;
            const bool accepted = stack.empty() || stack.back().empty() || stack.back()[0] != 0x50;
            BOOST_CHECK_EQUAL(ecx::IsCanonicalBondInboxSourceTransaction(CTransaction(changed), error, consensus), accepted);
            if (!accepted) BOOST_CHECK_EQUAL(error, "ECX bond-inbox source contains a second Taproot annex");
        }
    }
    BOOST_REQUIRE_MESSAGE(ecx::AppendBondInboxSourcesForBlock(block, 10, 1000, snapshot, error, consensus, &exported), error);
    BOOST_REQUIRE_EQUAL(exported.size(), 1U);
    BOOST_CHECK_EQUAL(exported[0].proof_profile, 0U);
    BOOST_CHECK_EQUAL(exported[0].entry_index, 0U);
    DataStream witness;
    witness << block.vtx[0]->witness;
    const std::vector<unsigned char> witness_bytes(UCharCast(witness.data()), UCharCast(witness.data()) + witness.size());
    std::vector<unsigned char> expected{1};
    const auto append_hash = [&](const auto& value) {
        for (auto byte : value) expected.push_back(static_cast<unsigned char>(byte));
    };
    TestPushU64Be(expected, 0);
    append_hash(initial.node_bond_inbox_head_root);
    TestPushU64Be(expected, 10);
    TestPushU64Be(expected, 1000);
    append_hash(block.GetHash());
    append_hash(block.vtx[0]->GetHash());
    append_hash(block.vtx[0]->GetWitnessHash());
    TestPushU32Be(expected, exported[0].source_transaction.size());
    append_hash(TestSha256(witness_bytes));
    TestPushU32Be(expected, witness_bytes.size());
    TestPushU32Be(expected, 0);
    TestPushU32Be(expected, 0);
    const auto marker = ParseHex(ECX_FINITE_MARKER);
    expected.insert(expected.end(), marker.begin()+4, marker.end());
    BOOST_CHECK(exported[0].canonical_entry == expected);
    const auto entry_hash = TestTaggedHash("ECX/bond-inbox-entry/v2", expected);
    expected.assign(initial.node_bond_inbox_head_root.begin(), initial.node_bond_inbox_head_root.end());
    TestPushU64Be(expected, 0);
    append_hash(entry_hash);
    BOOST_CHECK(snapshot.node_bond_inbox_head_root == TestTaggedHash("ECX/bond-inbox-step/v2", expected));
    BOOST_CHECK(snapshot.node_bond_inbox_entry_count == ecx::BigEndianUint128{1});
    BOOST_CHECK(snapshot.node_bond_inbox_head_root != initial.node_bond_inbox_head_root);
    const auto valid_source = block.vtx[0];
    const auto first_entry = exported[0].canonical_entry;
    block.vtx.push_back(valid_source);
    snapshot = initial;
    exported.clear();
    // Repeated sources consume byte budgets once, but each marker advances the inbox.
    BOOST_REQUIRE_MESSAGE(ecx::AppendBondInboxSourcesForBlock(block, 10, 1000, snapshot, error, consensus, &exported), error);
    BOOST_REQUIRE_EQUAL(exported.size(), 2U);
    BOOST_CHECK_EQUAL(exported[1].entry_index, 1U);
    BOOST_CHECK_EQUAL(exported[1].source_transaction_index, 1U);
    BOOST_CHECK(snapshot.node_bond_inbox_entry_count == ecx::BigEndianUint128{2});
    BOOST_CHECK(exported[0].canonical_entry == first_entry);
    for (bool witness_limit : {false, true}) {
        auto too_small = consensus;
        if (witness_limit) --too_small.bond_v2.bond_inbox_max_unique_source_witness_bytes_per_sidechain_block;
        else --too_small.bond_v2.bond_inbox_max_unique_source_transaction_bytes_per_sidechain_block;
        snapshot = initial;
        exported.clear();
        BOOST_CHECK(!ecx::AppendBondInboxSourcesForBlock(block, 10, 1000, snapshot, error, too_small, &exported));
        BOOST_CHECK_EQUAL(error, "invalid ECX bond-inbox source transaction: ECX bond-inbox relay profile is not frozen");
        BOOST_CHECK(exported.empty());
        BOOST_CHECK(snapshot.node_bond_inbox_head_root == initial.node_bond_inbox_head_root);
        BOOST_CHECK(snapshot.node_bond_inbox_entry_count == initial.node_bond_inbox_entry_count);
    }
    const auto marker_limit = consensus.bond_v2.bond_inbox_max_entries_per_sidechain_block;
    block.vtx.resize(marker_limit, valid_source);
    snapshot = initial;
    exported.clear();
    BOOST_REQUIRE_MESSAGE(ecx::AppendBondInboxSourcesForBlock(block, 10, 1000, snapshot, error, consensus, &exported), error);
    BOOST_REQUIRE_EQUAL(exported.size(), marker_limit);
    BOOST_CHECK(snapshot.node_bond_inbox_entry_count == ecx::BigEndianUint128{marker_limit});
    const auto final_entry = exported.back().canonical_entry;
    block.vtx.push_back(valid_source);
    snapshot = initial;
    exported.clear();
    BOOST_CHECK(!ecx::AppendBondInboxSourcesForBlock(block, 10, 1000, snapshot, error, consensus, &exported));
    BOOST_CHECK_EQUAL(error, "ECX bond-inbox block exceeds its marker/index bounds");
    BOOST_REQUIRE_EQUAL(exported.size(), marker_limit);
    BOOST_CHECK(exported[0].canonical_entry == first_entry);
    BOOST_CHECK(exported.back().canonical_entry == final_entry);
    BOOST_CHECK(snapshot.node_bond_inbox_head_root == initial.node_bond_inbox_head_root);
    BOOST_CHECK(snapshot.node_bond_inbox_entry_count == initial.node_bond_inbox_entry_count);
    block.vtx.resize(1);
    source.witness.vtxinwit[0].scriptWitness.stack[1].back() ^= 1;
    block.vtx[0] = MakeTransactionRef(source);
    snapshot = initial;
    exported.clear();
    BOOST_CHECK(!ecx::AppendBondInboxSourcesForBlock(block, 10, 1000, snapshot, error, consensus, &exported));
    BOOST_CHECK_EQUAL(error, "invalid ECX bond-inbox source transaction: ECX bond-inbox source annex receipt evidence is invalid");
    BOOST_CHECK(exported.empty());
    BOOST_CHECK(snapshot.node_bond_inbox_head_root == initial.node_bond_inbox_head_root);
    source.witness.vtxinwit[0].scriptWitness.stack[1] = ParseHex(ECX_FINITE_ANNEX);
    source.vout[0].scriptPubKey.back() ^= 1;
    block.vtx[0] = MakeTransactionRef(source);
    BOOST_CHECK(!ecx::AppendBondInboxSourcesForBlock(block, 10, 1000, snapshot, error, consensus, &exported));
    BOOST_CHECK_EQUAL(error, "invalid ECX bond-inbox source transaction: ECX bond-inbox marker wrapper signature is invalid");
    BOOST_CHECK(exported.empty());
    block.vtx.insert(block.vtx.begin(), valid_source);
    exported.resize(1);
    exported[0].proof_profile = 99;
    BOOST_CHECK(!ecx::AppendBondInboxSourcesForBlock(block, 10, 1000, snapshot, error, consensus, &exported));
    BOOST_REQUIRE_EQUAL(exported.size(), 2U);
    BOOST_CHECK_EQUAL(exported[0].proof_profile, 99U);
    BOOST_CHECK(exported[1].canonical_entry == first_entry);
    BOOST_CHECK(snapshot.node_bond_inbox_head_root == initial.node_bond_inbox_head_root);
    BOOST_CHECK(snapshot.node_bond_inbox_entry_count == ecx::BigEndianUint128{0});
    block.vtx.resize(1);
    snapshot.node_bond_inbox_entry_count = UINT64_MAX;
    exported.clear();
    BOOST_CHECK(!ecx::AppendBondInboxSourcesForBlock(block, 10, 1000, snapshot, error, consensus, &exported));
    BOOST_CHECK_EQUAL(error, "ECX bond-inbox block exceeds its marker/index bounds");
    BOOST_CHECK(exported.empty());
    BOOST_CHECK(snapshot.node_bond_inbox_entry_count == ecx::BigEndianUint128{UINT64_MAX});
}

BOOST_AUTO_TEST_CASE(incremental_successor_empty_block_preserves_u128_inbox_projection)
{
    ecx::ExchangeConsensus consensus{ConfiguredConsensus(
        50, COutPoint{Txid::FromUint256(uint256S("50")), 0}, uint256S("51"))};
    PopulateTestBondV2FrozenIdentities(consensus);
    ecx::BondV2CapitalSnapshot snapshot;
    snapshot.proof_profile = 1;
    snapshot.node_bond_inbox_head_root = uint256S("52");
    snapshot.bond_inbox_head_root = snapshot.node_bond_inbox_head_root;
    snapshot.node_bond_inbox_entry_count.bytes[7] = 1;
    snapshot.node_bond_inbox_entry_count.bytes[15] = 9;
    snapshot.bond_inbox_entry_count = snapshot.node_bond_inbox_entry_count;
    const ecx::BigEndianUint128 expected_count{
        snapshot.node_bond_inbox_entry_count};
    const uint256 expected_head{snapshot.node_bond_inbox_head_root};
    CBlock block;
    std::vector<ecx::BondInboxSourceExport> exported;
    std::string error;

    BOOST_REQUIRE_MESSAGE(
        ecx::AppendIncrementalSuccessorBondInboxSourcesForBlock(
            block, 51, 101, snapshot, error, consensus, &exported),
        error);
    BOOST_CHECK(exported.empty());
    BOOST_CHECK(snapshot.node_bond_inbox_head_root == expected_head);
    BOOST_CHECK(snapshot.node_bond_inbox_entry_count == expected_count);
    BOOST_CHECK(!snapshot.node_bond_inbox_entry_count.FitsU64());

    BOOST_CHECK(!ecx::AppendBondInboxSourcesForBlock(
        block, 51, 101, snapshot, error, consensus, &exported));
    BOOST_CHECK_EQUAL(error, "finite ECX bond-inbox source tracker exceeds its u64 wire");
    BOOST_CHECK(snapshot.node_bond_inbox_head_root == expected_head);
    BOOST_CHECK(snapshot.node_bond_inbox_entry_count == expected_count);
    snapshot.node_bond_inbox_entry_count = 9;
    snapshot.bond_inbox_entry_count = 9;
    BOOST_REQUIRE(ecx::AppendBondInboxSourcesForBlock(
        block, 51, 101, snapshot, error, consensus, &exported));
    BOOST_CHECK(error.empty());
    BOOST_CHECK(exported.empty());
    BOOST_CHECK(snapshot.node_bond_inbox_entry_count == ecx::BigEndianUint128{9});

    snapshot.proof_profile = 0;
    BOOST_CHECK(!ecx::AppendIncrementalSuccessorBondInboxSourcesForBlock(
        block, 51, 101, snapshot, error, consensus));
    BOOST_CHECK(error.find("no canonical predecessor") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(incremental_successor_accepts_real_rust_crypto_source_vector)
{
    ecx::ExchangeConsensus consensus{ConfiguredConsensus(
        50, COutPoint{Txid::FromUint256(uint256S("50")), 0}, uint256S("51"))};
    PopulateTestBondV2FrozenIdentities(consensus);
    const auto assign_hash = [](auto& target, const char* raw_hex) {
        const std::vector<unsigned char> bytes{ParseHex(raw_hex)};
        BOOST_REQUIRE_EQUAL(bytes.size(), target.size());
        std::copy(bytes.begin(), bytes.end(), target.begin());
    };
    assign_hash(consensus.chain_id, ECX_SUCCESSOR_BOND_INBOX_V23_CHAIN_ID);
    auto& frozen{consensus.bond_v2};
    assign_hash(
        frozen.configuration_hash,
        ECX_SUCCESSOR_BOND_INBOX_V23_CONFIGURATION_HASH);
    assign_hash(frozen.bond_asset_id, ECX_SUCCESSOR_BOND_INBOX_V23_BOND_ASSET);
    assign_hash(
        frozen.bond_inbox_redemption_staging_internal_key,
        ECX_SUCCESSOR_BOND_INBOX_V23_STAGING_INTERNAL_KEY);
    assign_hash(
        frozen.bond_inbox_redemption_staging_process_cmr,
        ECX_SUCCESSOR_BOND_INBOX_V23_PROCESS_CMR);
    assign_hash(
        frozen.bond_inbox_redemption_staging_refund_cmr,
        ECX_SUCCESSOR_BOND_INBOX_V23_REFUND_CMR);
    assign_hash(
        frozen.availability_scheme_hash,
        ECX_SUCCESSOR_BOND_INBOX_V23_AVAILABILITY_SCHEME);
    assign_hash(
        frozen.availability_custodian_registry_hash,
        ECX_SUCCESSOR_BOND_INBOX_V23_AVAILABILITY_REGISTRY);
    const std::array<const char*, 5> encryption_keys{{
        ECX_SUCCESSOR_BOND_INBOX_V23_CUSTODIAN_1_ENCRYPTION,
        ECX_SUCCESSOR_BOND_INBOX_V23_CUSTODIAN_2_ENCRYPTION,
        ECX_SUCCESSOR_BOND_INBOX_V23_CUSTODIAN_3_ENCRYPTION,
        ECX_SUCCESSOR_BOND_INBOX_V23_CUSTODIAN_4_ENCRYPTION,
        ECX_SUCCESSOR_BOND_INBOX_V23_CUSTODIAN_5_ENCRYPTION}};
    const std::array<const char*, 5> attestation_keys{{
        ECX_SUCCESSOR_BOND_INBOX_V23_CUSTODIAN_1_ATTESTATION,
        ECX_SUCCESSOR_BOND_INBOX_V23_CUSTODIAN_2_ATTESTATION,
        ECX_SUCCESSOR_BOND_INBOX_V23_CUSTODIAN_3_ATTESTATION,
        ECX_SUCCESSOR_BOND_INBOX_V23_CUSTODIAN_4_ATTESTATION,
        ECX_SUCCESSOR_BOND_INBOX_V23_CUSTODIAN_5_ATTESTATION}};
    for (size_t index = 0; index < encryption_keys.size(); ++index) {
        assign_hash(frozen.custodian_encryption_keys[index], encryption_keys[index]);
        assign_hash(frozen.custodian_attestation_keys[index], attestation_keys[index]);
    }
    struct PolicyAssetRestore {
        CAsset original{::policyAsset};
        ~PolicyAssetRestore() { ::policyAsset = original; }
    } policy_asset_restore;
    ::policyAsset = CAsset(RawHash(ECX_SUCCESSOR_BOND_INBOX_V23_POLICY_ASSET));
    BOOST_REQUIRE_MESSAGE(
        ::policyAsset.id == RawHash(ECX_SUCCESSOR_BOND_INBOX_V23_POLICY_ASSET),
        "actual policy asset bytes=" << HexStr(::policyAsset.id) <<
        " vector bytes=" << ECX_SUCCESSOR_BOND_INBOX_V23_POLICY_ASSET);

    const std::vector<unsigned char> source_bytes{
        ParseHex(ECX_SUCCESSOR_BOND_INBOX_V23_TRANSACTION_HEX)};
    BOOST_REQUIRE_EQUAL(
        source_bytes.size(), ECX_SUCCESSOR_BOND_INBOX_V23_TRANSACTION_LEN);
    uint256 source_sha256;
    CSHA256().Write(source_bytes.data(), source_bytes.size())
        .Finalize(source_sha256.begin());
    BOOST_CHECK(source_sha256 ==
        RawHash(ECX_SUCCESSOR_BOND_INBOX_V23_TRANSACTION_SHA256));
    DataStream source_stream(source_bytes);
    CMutableTransaction source;
    source_stream >> TX_WITH_WITNESS(source);
    BOOST_REQUIRE(source_stream.empty());
    const CTransaction immutable_source{source};
    BOOST_CHECK(immutable_source.GetHash() ==
        RawHash(ECX_SUCCESSOR_BOND_INBOX_V23_TXID));
    BOOST_CHECK(immutable_source.GetWitnessHash() ==
        RawHash(ECX_SUCCESSOR_BOND_INBOX_V23_WTXID));

    const auto initial_snapshot = [] {
        ecx::BondV2CapitalSnapshot snapshot;
        snapshot.proof_profile = 1;
        snapshot.node_bond_inbox_head_root = uint256S("52");
        snapshot.bond_inbox_head_root = snapshot.node_bond_inbox_head_root;
        // The frozen Rust vector starts at (u64::MAX + 1) << 32 == 2^96.
        snapshot.node_bond_inbox_entry_count.bytes[3] = 1;
        snapshot.bond_inbox_entry_count = snapshot.node_bond_inbox_entry_count;
        return snapshot;
    };
    ecx::BondV2CapitalSnapshot snapshot{initial_snapshot()};
    CBlock block;
    block.vtx.push_back(MakeTransactionRef(source));
    std::vector<ecx::BondInboxSourceExport> exported;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        ecx::AppendIncrementalSuccessorBondInboxSourcesForBlock(
            block, 10, 1000, snapshot, error, consensus, &exported),
        error);
    BOOST_REQUIRE_EQUAL(exported.size(), 1U);
    BOOST_CHECK_EQUAL(exported[0].proof_profile, 1U);
    BOOST_CHECK(exported[0].entry_index_u128 ==
        initial_snapshot().node_bond_inbox_entry_count);
    BOOST_CHECK_EQUAL(exported[0].canonical_entry.size(), 708U);
    BOOST_CHECK(exported[0].source_transaction == source_bytes);
    BOOST_CHECK(exported[0].source_txid ==
        RawHash(ECX_SUCCESSOR_BOND_INBOX_V23_TXID));
    BOOST_CHECK(exported[0].source_wtxid ==
        RawHash(ECX_SUCCESSOR_BOND_INBOX_V23_WTXID));
    BOOST_CHECK_EQUAL(exported[0].marker_vout, 1U);
    BOOST_CHECK(snapshot.node_bond_inbox_entry_count.bytes[3] == 1);
    BOOST_CHECK(snapshot.node_bond_inbox_entry_count.bytes[15] == 1);
    BOOST_CHECK(snapshot.node_bond_inbox_head_root != uint256S("52"));

    auto exhausted = initial_snapshot();
    exhausted.node_bond_inbox_entry_count.bytes.fill(255);
    const auto exhausted_count = exhausted.node_bond_inbox_entry_count;
    std::vector<ecx::BondInboxSourceExport> overflow_exports;
    BOOST_CHECK(!ecx::AppendIncrementalSuccessorBondInboxSourcesForBlock(
        block, 10, 1000, exhausted, error, consensus, &overflow_exports));
    BOOST_CHECK_EQUAL(error, "ECX successor bond-inbox entry count overflows u128");
    BOOST_REQUIRE_EQUAL(overflow_exports.size(), 1U);
    BOOST_CHECK(overflow_exports[0].entry_index_u128 == exhausted_count);
    BOOST_CHECK_EQUAL(overflow_exports[0].entry_index, 0U);
    BOOST_CHECK(exhausted.node_bond_inbox_entry_count == exhausted_count);
    BOOST_CHECK(exhausted.node_bond_inbox_head_root == uint256S("52"));

    auto finite_snapshot = initial_snapshot();
    finite_snapshot.node_bond_inbox_entry_count = 0;
    finite_snapshot.bond_inbox_entry_count = 0;
    std::vector<ecx::BondInboxSourceExport> finite_exports;
    BOOST_CHECK(!ecx::AppendBondInboxSourcesForBlock(
        block, 10, 1000, finite_snapshot, error, consensus, &finite_exports));
    BOOST_CHECK(error.starts_with("invalid ECX bond-inbox source transaction: "));
    BOOST_CHECK(finite_exports.empty());
    BOOST_CHECK(finite_snapshot.node_bond_inbox_head_root == uint256S("52"));
    BOOST_CHECK(finite_snapshot.node_bond_inbox_entry_count == ecx::BigEndianUint128{0});

    // Frozen relay limits are checked before source-byte accounting.
    for (bool witness_cap : {false,true}) {
        auto capped = consensus;
        if (witness_cap) capped.bond_v2.bond_inbox_max_unique_source_witness_bytes_per_sidechain_block = 0;
        else capped.bond_v2.bond_inbox_max_unique_source_transaction_bytes_per_sidechain_block = 0;
        auto rejected = initial_snapshot();
        std::vector<ecx::BondInboxSourceExport> rejected_exports;
        BOOST_CHECK(!ecx::AppendIncrementalSuccessorBondInboxSourcesForBlock(
            block,10,1000,rejected,error,capped,&rejected_exports));
        BOOST_CHECK_EQUAL(error,"invalid ECX successor bond-inbox source transaction: ECX bond-inbox relay profile is not frozen");
        BOOST_CHECK(rejected.node_bond_inbox_head_root == initial_snapshot().node_bond_inbox_head_root);
        BOOST_CHECK(rejected.node_bond_inbox_entry_count == initial_snapshot().node_bond_inbox_entry_count);
        BOOST_CHECK(rejected_exports.empty());
    }

    const auto rejects = [&](CMutableTransaction mutated,
                             const std::string& expected_error) {
        CBlock rejected_block;
        rejected_block.vtx.push_back(MakeTransactionRef(std::move(mutated)));
        ecx::BondV2CapitalSnapshot rejected_snapshot{initial_snapshot()};
        std::string rejected_error;
        BOOST_CHECK(!ecx::AppendIncrementalSuccessorBondInboxSourcesForBlock(
            rejected_block, 10, 1000, rejected_snapshot, rejected_error,
            consensus));
        BOOST_CHECK_MESSAGE(
            rejected_error.find(expected_error) != std::string::npos,
            rejected_error);
        BOOST_CHECK(rejected_snapshot.node_bond_inbox_head_root == uint256S("52"));
        BOOST_CHECK(rejected_snapshot.node_bond_inbox_entry_count ==
            initial_snapshot().node_bond_inbox_entry_count);
    };

    CMutableTransaction bad_bundle{source};
    auto& bundle_annex=bad_bundle.witness.vtxinwit[0].scriptWitness.stack[1];
    BOOST_REQUIRE_GT(bundle_annex.size(),15U);
    bundle_annex[15]^=1;
    rejects(std::move(bad_bundle),"bundle commitment mismatched");

    CMutableTransaction bad_receipt{source};
    BOOST_REQUIRE_EQUAL(
        bad_receipt.witness.vtxinwit[0].scriptWitness.stack.size(), 2U);
    bad_receipt.witness.vtxinwit[0].scriptWitness.stack[1].back() ^= 1;
    rejects(std::move(bad_receipt), "receipt evidence is invalid");

    BOOST_REQUIRE_EQUAL(source.vout[1].scriptPubKey.size(),507U);
    BOOST_REQUIRE_EQUAL(source.vout[1].scriptPubKey[9],1U);
    const auto staging_index=ReadBE32(source.vout[1].scriptPubKey.data()+170);
    BOOST_REQUIRE(staging_index<source.vout.size());
    for (unsigned fault=0;fault<7;++fault) {
        CMutableTransaction malformed{source};
        auto& staging=malformed.vout[staging_index];
        switch (fault) {
        case 0: staging.scriptPubKey=CScript() << OP_1; break;
        case 1: staging.nAsset=CConfidentialAsset(::policyAsset); break;
        case 2: staging.nValue.SetToAmount(1); break;
        case 3: staging.nNonce.vchCommitment.clear(); break;
        case 4: malformed.witness.vtxoutwit.clear(); break;
        case 5: malformed.witness.vtxoutwit[staging_index].vchSurjectionproof.clear(); break;
        case 6: malformed.witness.vtxoutwit[staging_index].vchRangeproof.clear(); break;
        }
        rejects(std::move(malformed),"staging output is not the exact confidential frozen descriptor form");
    }
    CMutableTransaction wrong_authorization{source};
    wrong_authorization.vout[staging_index].nValue.vchCommitment.back()^=1;
    rejects(std::move(wrong_authorization),"marker source authorization is invalid");
    CMutableTransaction duplicate_marker{source};
    duplicate_marker.vout.push_back(duplicate_marker.vout[1]);
    duplicate_marker.witness.vtxoutwit.resize(duplicate_marker.vout.size());
    rejects(std::move(duplicate_marker),"too many or duplicate markers");
    CMutableTransaction absent_marker{source};
    absent_marker.vout[1].scriptPubKey.clear();
    BOOST_CHECK(!ecx::IsCanonicalBondInboxSourceTransaction(CTransaction(absent_marker),error,consensus));
    BOOST_CHECK_EQUAL(error,"ECX bond-inbox source transaction must contain exactly one marker");

    CMutableTransaction nonzero_marker{source};
    nonzero_marker.vout[1].nValue.SetToAmount(1);
    rejects(std::move(nonzero_marker),"marker output envelope is noncanonical");
    CMutableTransaction wrong_marker_asset{source};
    wrong_marker_asset.vout[1].nAsset=CConfidentialAsset(CAsset(uint256S("ff")));
    rejects(std::move(wrong_marker_asset),"marker output envelope is noncanonical");
    CMutableTransaction marker_proof{source};
    marker_proof.witness.vtxoutwit.resize(marker_proof.vout.size());
    marker_proof.witness.vtxoutwit[1].vchRangeproof={1};
    rejects(std::move(marker_proof),"marker output envelope is noncanonical");

    for (bool transaction_cap : {false,true}) {
        CMutableTransaction oversized{source};
        oversized.witness.vtxinwit[0].vchIssuanceAmountRangeproof.resize(transaction_cap ? 786432 : 589824);
        rejects(std::move(oversized),transaction_cap ? "source transaction exceeds its frozen exact byte cap" : "source witness exceeds its frozen exact byte cap");
    }
    CMutableTransaction pegin_source{source};
    pegin_source.vin[0].m_is_pegin=true;
    rejects(std::move(pegin_source),"invalid input/output/witness form");

    for (unsigned fault=0;fault<9;++fault) {
        CMutableTransaction malformed{source};
        auto& witness=malformed.witness.vtxinwit[0];
        std::string expected;
        switch (fault) {
        case 0: malformed.vin[0].scriptSig = CScript() << OP_0; expected="lacks its designated Taproot annex input"; break;
        case 1: witness.vchIssuanceAmountRangeproof={1}; expected="not an exact key-path annex spend"; break;
        case 2: witness.vchInflationKeysRangeproof={1}; expected="not an exact key-path annex spend"; break;
        case 3: witness.m_pegin_witness.stack={{1}}; expected="not an exact key-path annex spend"; break;
        case 4: witness.scriptWitness.stack.push_back({1}); expected="not an exact key-path annex spend"; break;
        case 5: witness.scriptWitness.stack[0].resize(63); expected="not an exact key-path annex spend"; break;
        case 6: witness.scriptWitness.stack[1][9]=0; expected="noncanonical prefix/version"; break;
        case 7: witness.scriptWitness.stack[1][14]=2; expected="invalid bundle/receipt lengths"; break;
        case 8: witness.scriptWitness.stack[1].resize(14); expected="noncanonical prefix/version"; break;
        }
        rejects(std::move(malformed),expected);
    }
    CMutableTransaction second_annex{source};
    second_annex.vin.push_back(second_annex.vin[0]);
    second_annex.witness.vtxinwit.push_back(second_annex.witness.vtxinwit[0]);
    rejects(std::move(second_annex),"contains a second Taproot annex");
    for (const auto& stack : {
            std::vector<std::vector<unsigned char>>{},
            std::vector<std::vector<unsigned char>>{{}},
            std::vector<std::vector<unsigned char>>{{0x51}},
            std::vector<std::vector<unsigned char>>{{0x50}, {0x51}}}) {
        CMutableTransaction extra_input{source};
        extra_input.vin.push_back(extra_input.vin[0]);
        extra_input.vin.back().prevout.n++;
        extra_input.witness.vtxinwit.emplace_back();
        extra_input.witness.vtxinwit.back().scriptWitness.stack = stack;
        CBlock accepted_block;
        accepted_block.vtx.push_back(MakeTransactionRef(std::move(extra_input)));
        auto accepted_snapshot = initial_snapshot();
        BOOST_CHECK(ecx::AppendIncrementalSuccessorBondInboxSourcesForBlock(
            accepted_block,10,1000,accepted_snapshot,error,consensus));
    }
    // Custody forbids annex-like final items even without a preceding signature.
    for (const auto& stack : {
            std::vector<std::vector<unsigned char>>{{0x50}},
            std::vector<std::vector<unsigned char>>{{}, {0x50, 0x01}}}) {
        CMutableTransaction extra_annex{source};
        extra_annex.vin.push_back(extra_annex.vin[0]);
        extra_annex.witness.vtxinwit.emplace_back();
        extra_annex.witness.vtxinwit.back().scriptWitness.stack = stack;
        rejects(std::move(extra_annex),"contains a second Taproot annex");
    }

    CMutableTransaction bad_marker_signature{source};
    bad_marker_signature.vout[1].scriptPubKey.back() ^= 1;
    rejects(std::move(bad_marker_signature), "wrapper signature is invalid");

    CMutableTransaction bad_marker_context{source};
    BOOST_REQUIRE_EQUAL(bad_marker_context.vout[1].scriptPubKey.size(), 507U);
    bad_marker_context.vout[1].scriptPubKey[4 + 338] ^= 1;
    rejects(std::move(bad_marker_context), "availability context is invalid");

    for (unsigned char kind : {0,1,2,3}) {
        CMutableTransaction absent_authorization{source};
        auto& script = absent_authorization.vout[1].scriptPubKey;
        BOOST_REQUIRE_EQUAL(script.size(),507U);
        script[9] = kind;
        std::fill(script.begin()+411,script.begin()+443,0);
        rejects(std::move(absent_authorization), "marker identities/availability claim are invalid");
    }

    CMutableTransaction historical_marker_version{source};
    // OP_RETURN PUSHDATA2 length occupies four bytes; byte four is the
    // successor marker version and must never accept the finite-V18 value.
    historical_marker_version.vout[1].scriptPubKey[8] = 1;
    rejects(std::move(historical_marker_version), "exact minimal-PUSHDATA2");
}

BOOST_AUTO_TEST_CASE(sp1_v2_public_capital_semantics_fail_closed)
{
    const std::vector<unsigned char> valid{TestSp1AnnexPayload(true)};
    BOOST_REQUIRE(StrictlyParsesV2(valid));

    const auto rejects_recommitted_mutation = [&valid](
        size_t offset,
        const std::vector<unsigned char>& replacement) {
        std::vector<unsigned char> candidate{valid};
        BOOST_REQUIRE(offset + replacement.size() <= 850U);
        std::copy(
            replacement.begin(), replacement.end(),
            candidate.begin() + 435 + offset);
        RecommitV2PublicValues(candidate);
        BOOST_CHECK(!StrictlyParsesV2(candidate));
    };
    const auto be64 = [](uint64_t value) {
        std::vector<unsigned char> bytes;
        TestPushU64Be(bytes, value);
        return bytes;
    };
    const auto be128 = [](uint64_t high, uint64_t low) {
        std::vector<unsigned char> bytes;
        TestPushU128Be(bytes, high, low);
        return bytes;
    };

    rejects_recommitted_mutation(524, be128(0, 999));       // ceil(125%)
    rejects_recommitted_mutation(540, be128(0, 12499));     // coverage
    rejects_recommitted_mutation(492, be128(0, 999999999)); // NAV
    rejects_recommitted_mutation(484, be64(2100000000000001)); // supply
    rejects_recommitted_mutation(556, std::vector<unsigned char>{1}); // derived mode
    rejects_recommitted_mutation(557, be64(0));               // zero minimum
    rejects_recommitted_mutation(557, be64(24));              // equal bounds
    rejects_recommitted_mutation(585, be64(29));             // head > tail
    rejects_recommitted_mutation(601, be64(101));            // queued > outstanding
    rejects_recommitted_mutation(601, be64(0));              // nonempty queue/zero aggregate
    rejects_recommitted_mutation(593, be64(27));              // empty indices/nonzero aggregate
    rejects_recommitted_mutation(
        581, std::vector<unsigned char>{0, 0, 0x27, 0x11});  // +10001 ppm
    rejects_recommitted_mutation(
        581, std::vector<unsigned char>{0xff, 0xff, 0xd8, 0xef}); // -10001 ppm
    for (const size_t hash_offset : {
             0U, 36U, 68U, 100U, 132U, 164U, 196U,
             244U, 276U, 308U, 340U, 372U, 404U, 436U,
             609U, 650U, 682U, 722U, 762U, 802U}) {
        rejects_recommitted_mutation(
            hash_offset, std::vector<unsigned char>(32, 0));
    }
    rejects_recommitted_mutation(228, be64(0));              // parent height
    rejects_recommitted_mutation(236, be64(0));              // parent MTP
    rejects_recommitted_mutation(641, be64(8));              // stale oracle
    rejects_recommitted_mutation(649, std::vector<unsigned char>{4}); // oracle mode
    rejects_recommitted_mutation(714, be64(2));              // cursor > entry count
    rejects_recommitted_mutation(794, be64(2));              // outcome count != cursor
    rejects_recommitted_mutation(842, be64(4));              // execution rollback

    // Both products below overflow a naive u128 multiply. Exact division is
    // nevertheless representable and must accept the same vector as Rust:
    // reserve == deficit == NAV == 2^120, coverage 10000, mode ReduceOnly.
    std::vector<unsigned char> large_valid{valid};
    const std::vector<unsigned char> two_to_120{
        be128(UINT64_C(0x0100000000000000), 0)};
    const std::vector<unsigned char> five_two_to_118{
        be128(UINT64_C(0x0140000000000000), 0)};
    const std::vector<unsigned char> one_share{be64(100000000)};
    const std::vector<unsigned char> ten_thousand{be128(0, 10000)};
    std::copy(two_to_120.begin(), two_to_120.end(), large_valid.begin() + 435 + 468);
    std::copy(one_share.begin(), one_share.end(), large_valid.begin() + 435 + 484);
    std::copy(two_to_120.begin(), two_to_120.end(), large_valid.begin() + 435 + 492);
    std::copy(two_to_120.begin(), two_to_120.end(), large_valid.begin() + 435 + 508);
    std::copy(five_two_to_118.begin(), five_two_to_118.end(), large_valid.begin() + 435 + 524);
    std::copy(ten_thousand.begin(), ten_thousand.end(), large_valid.begin() + 435 + 540);
    large_valid[435 + 556] = 1;
    RecommitV2PublicValues(large_valid);
    BOOST_CHECK(StrictlyParsesV2(large_valid));

    // A naive reserve*10000 overflows here. The exact overflow-safe division
    // path must reject instead of wrapping into a plausible coverage value.
    std::vector<unsigned char> extreme{valid};
    const std::vector<unsigned char> max_i128{
        be128(0x7fff'ffff'ffff'ffffULL, 0xffff'ffff'ffff'ffffULL)};
    const std::vector<unsigned char> one128{be128(0, 1)};
    const std::vector<unsigned char> two128{be128(0, 2)};
    const std::vector<unsigned char> zero128{be128(0, 0)};
    const std::vector<unsigned char> zero64{be64(0)};
    std::copy(
        max_i128.begin(), max_i128.end(),
        extreme.begin() + 435 + 468);
    std::copy(one128.begin(), one128.end(), extreme.begin() + 435 + 508);
    std::copy(two128.begin(), two128.end(), extreme.begin() + 435 + 524);
    std::copy(zero64.begin(), zero64.end(), extreme.begin() + 435 + 484);
    std::copy(zero128.begin(), zero128.end(), extreme.begin() + 435 + 492);
    RecommitV2PublicValues(extreme);
    BOOST_CHECK(!StrictlyParsesV2(extreme));

    std::vector<unsigned char> high_bit_reserve{valid};
    high_bit_reserve[435 + 468] = 0x80;
    RecommitV2PublicValues(high_bit_reserve);
    BOOST_CHECK(!StrictlyParsesV2(high_bit_reserve));

    std::vector<unsigned char> high_bit_deficit{valid};
    high_bit_deficit[435 + 508] = 0x80;
    RecommitV2PublicValues(high_bit_deficit);
    BOOST_CHECK(!StrictlyParsesV2(high_bit_deficit));

    std::vector<unsigned char> zero_deficit{valid};
    std::copy(zero128.begin(), zero128.end(), zero_deficit.begin() + 435 + 508);
    std::copy(zero128.begin(), zero128.end(), zero_deficit.begin() + 435 + 524);
    std::copy(ten_thousand.begin(), ten_thousand.end(), zero_deficit.begin() + 435 + 540);
    zero_deficit[435 + 540 + 14] = 0x30;
    zero_deficit[435 + 540 + 15] = 0xd4; // exact 12,500 sentinel
    RecommitV2PublicValues(zero_deficit);
    BOOST_CHECK(StrictlyParsesV2(zero_deficit));
    zero_deficit[435 + 540 + 15] ^= 1;
    RecommitV2PublicValues(zero_deficit);
    BOOST_CHECK(!StrictlyParsesV2(zero_deficit));
}

BOOST_AUTO_TEST_CASE(bond_v2_projection_is_frozen_and_activation_fails_closed)
{
    ecx::ExchangeConsensus consensus{ConfiguredConsensus(
        50, COutPoint{Txid::FromUint256(uint256S("50")), 0}, uint256S("51"))};
    PopulateTestBondV2FrozenIdentities(consensus);
    const std::array<unsigned char, 32> program{{
        0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4,
        0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 8}};
    std::copy(program.begin(), program.end(),
        consensus.bond_v2.transition_program_id.begin());
    std::fill(consensus.bond_v2.configuration_hash.begin(),
        consensus.bond_v2.configuration_hash.end(), 2);
    std::fill(consensus.bond_v2.bond_asset_id.begin(),
        consensus.bond_v2.bond_asset_id.end(), 11);
    std::fill(consensus.bond_v2.bond_deployment_commitment.begin(),
        consensus.bond_v2.bond_deployment_commitment.end(), 12);
    std::fill(consensus.bond_v2.transition_journal_domain_sha256.begin(),
        consensus.bond_v2.transition_journal_domain_sha256.end(), 1);
    std::fill(consensus.bond_v2.transition_cmr.begin(),
        consensus.bond_v2.transition_cmr.end(), 17);
    std::fill(consensus.bond_v2.identity_derivation_record_sha256.begin(),
        consensus.bond_v2.identity_derivation_record_sha256.end(), 18);

    ecx::BondV2CapitalSnapshot snapshot;
    std::string error;
    const std::vector<unsigned char> annex{TestSp1AnnexPayload(true)};
    BOOST_REQUIRE_MESSAGE(
        ecx::DecodeBondV2CapitalProjection(
            annex, uint256S("52"), snapshot, error, consensus),
        error);
    BOOST_CHECK_EQUAL(snapshot.version, 4U);
    BOOST_CHECK_EQUAL(snapshot.outstanding_share_atoms, 100U);
    for (const auto& [bytes, offset] : std::array<std::pair<const unsigned char*, size_t>, 5>{{
        {snapshot.insurance_reserve.data(), 468}, {snapshot.nav_per_whole_share.data(), 492},
        {snapshot.full_bound_deficit.data(), 508}, {snapshot.target_reserve.data(), 524},
        {snapshot.coverage_bps.data(), 540}}}) {
        BOOST_CHECK(std::equal(bytes, bytes + 16, annex.begin() + 435 + offset));
    }
    BOOST_CHECK_EQUAL(snapshot.capital_mode, 0U);
    BOOST_CHECK_EQUAL(snapshot.funding_epoch, 25U);
    BOOST_CHECK_EQUAL(snapshot.redemption_head, 27U);
    BOOST_CHECK_EQUAL(snapshot.redemption_tail, 28U);
    BOOST_CHECK_EQUAL(snapshot.queued_redemption_share_atoms, 29U);
    BOOST_CHECK(std::all_of(
        snapshot.legacy_fee_pool.begin(), snapshot.legacy_fee_pool.end(),
        [](unsigned char byte) { return byte == 0; }));

    ecx::ExchangeConsensus substituted{consensus};
    substituted.bond_v2.configuration_hash.begin()[0] ^= 1;
    const auto decoded_snapshot_hash = (HashWriter{} << snapshot).GetHash();
    BOOST_CHECK(!ecx::DecodeBondV2CapitalProjection(annex,uint256{},snapshot,error,consensus));
    BOOST_CHECK_EQUAL(error,"ECX bond V2 capital projection has no active exchange root");
    BOOST_CHECK((HashWriter{} << snapshot).GetHash() == decoded_snapshot_hash);
    BOOST_CHECK(!ecx::DecodeBondV2CapitalProjection({},uint256S("52"),snapshot,error,consensus));
    BOOST_CHECK_EQUAL(error,"ECX bond V2 transition lacks one canonical version-4/PublicValuesV5 annex");
    BOOST_CHECK((HashWriter{} << snapshot).GetHash() == decoded_snapshot_hash);
    BOOST_CHECK(!ecx::DecodeBondV2CapitalProjection(
        annex, uint256S("52"), snapshot, error, substituted));
    BOOST_CHECK(error.find("source-frozen") != std::string::npos);
    BOOST_CHECK((HashWriter{} << snapshot).GetHash() == decoded_snapshot_hash);

    substituted = consensus;
    substituted.bond_v2.identity_derivation_record_sha256.SetNull();
    BOOST_CHECK(!ecx::DecodeBondV2CapitalProjection(
        annex, uint256S("52"), snapshot, error, substituted));
    BOOST_CHECK(error.find("identity derivation") != std::string::npos);

    using FrozenIdentity = ecx::ExchangeConsensus::BondV2FrozenConsensus;
    for (uint256 FrozenIdentity::* field : {
             &FrozenIdentity::incremental_activation_program_id,
             &FrozenIdentity::incremental_activation_configuration_hash,
             &FrozenIdentity::incremental_activation_cmr,
             &FrozenIdentity::incremental_successor_program_id,
             &FrozenIdentity::incremental_successor_configuration_hash,
             &FrozenIdentity::incremental_successor_transition_cmr,
             &FrozenIdentity::incremental_successor_state_node_domain_sha256,
         }) {
        substituted = consensus;
        (substituted.bond_v2.*field).SetNull();
        BOOST_CHECK(!ecx::DecodeBondV2CapitalProjection(
            annex, uint256S("52"), snapshot, error, substituted));
        BOOST_CHECK(error.find("missing frozen ECX bond V2") != std::string::npos);
    }

    substituted = consensus;
    substituted.bond_v2.incremental_activation_configuration_hash =
        substituted.bond_v2.configuration_hash;
    BOOST_CHECK(!ecx::DecodeBondV2CapitalProjection(
        annex, uint256S("52"), snapshot, error, substituted));
    BOOST_CHECK(error.find("configurations collide") != std::string::npos);

    substituted = consensus;
    substituted.bond_v2.incremental_successor_program_id =
        substituted.bond_v2.transition_program_id;
    BOOST_CHECK(!ecx::DecodeBondV2CapitalProjection(
        annex, uint256S("52"), snapshot, error, substituted));
    BOOST_CHECK(error.find("proof program identity collides") != std::string::npos);

    substituted = consensus;
    substituted.bond_v2.incremental_successor_transition_cmr =
        substituted.bond_v2.transition_cmr;
    BOOST_CHECK(!ecx::DecodeBondV2CapitalProjection(
        annex, uint256S("52"), snapshot, error, substituted));
    BOOST_CHECK(error.find("covenant CMR roles collide") != std::string::npos);

    for (bool encryption : {false, true}) for (bool duplicate : {false, true}) {
        substituted = consensus;
        auto& keys = encryption ? substituted.bond_v2.custodian_encryption_keys : substituted.bond_v2.custodian_attestation_keys;
        if (duplicate) keys[1] = keys[0];
        keys[4].fill(0);
        BOOST_CHECK(!ecx::DecodeBondV2CapitalProjection(annex, uint256S("52"), snapshot, error, substituted));
        BOOST_CHECK_EQUAL(error, duplicate ? "duplicate frozen ECX bond V2 custodian registry key" :
            "incomplete frozen ECX bond V2 custodian registry");
    }

    substituted = consensus;
    substituted.bond_v2.keyless_internal_key[0] ^= 1;
    BOOST_CHECK(!ecx::DecodeBondV2CapitalProjection(
        annex, uint256S("52"), snapshot, error, substituted));
    BOOST_CHECK(error.find("physical activation inputs") != std::string::npos);

    for (unsigned fault = 0; fault < 7; ++fault) {
        substituted = consensus;
        auto& input = substituted.bond_v2;
        switch (fault) {
        case 0: input.deployment_transaction.reset(); break;
        case 1: input.genesis_transaction.reset(); break;
        case 2: input.canonical_configuration_bytes.clear(); break;
        case 3: input.genesis_mark_price = 0; break;
        case 4: input.inventory_value_blinding_factor.SetNull(); break;
        case 5: input.issuance_value_blinding_factor.SetNull(); break;
        default: input.issuance_value_blinding_factor = input.inventory_value_blinding_factor; break;
        }
        BOOST_CHECK(!ecx::DecodeBondV2CapitalProjection(annex, uint256S("52"), snapshot, error, substituted));
        BOOST_CHECK_EQUAL(error, "incomplete frozen ECX bond V2 physical activation inputs");
    }

    substituted = consensus;
    substituted.bond_v2.bond_inbox_redemption_staging_internal_key.begin()[0] ^= 1;
    BOOST_CHECK(!ecx::DecodeBondV2CapitalProjection(
        annex, uint256S("52"), snapshot, error, substituted));
    BOOST_CHECK(error.find("physical activation inputs") != std::string::npos);

    CBlock activation;
    activation.hashExchangeStateRoot = consensus.genesis_state_root;
    MemoryCoinsView activation_base;
    CCoinsViewCache activation_view{&activation_base};
    BOOST_CHECK(!ecx::DeriveBondV2CapitalProjectionAfterScripts(
        activation,
        nullptr,
        activation_view,
        consensus.activation_height,
        uint256S("53"),
        1,
        2,
        snapshot,
        error,
        consensus));
    BOOST_CHECK(error.find("physical deployment/genesis linkage") != std::string::npos);
    for (unsigned fault = 0; fault < 12; ++fault) {
        auto candidate = consensus;
        auto& frozen = candidate.bond_v2;
        CMutableTransaction deployment;
        deployment.vin.emplace_back(COutPoint{Txid::FromUint256(uint256S("71")), 0});
        deployment.vout.push_back(AuthorityOutput(0x31));
        if (fault >= 10) deployment.vin[0].assetIssuance.nAmount.SetToAmount(1);
        if (fault == 10) deployment.vin[0].assetIssuance.assetBlindingNonce = uint256S("01");
        frozen.deployment_transaction = MakeTransactionRef(deployment);
        CMutableTransaction genesis;
        genesis.vin.emplace_back(COutPoint{frozen.deployment_transaction->GetHash(), 0});
        genesis.vout.push_back(AuthorityOutput(0x32));
        if (fault == 7) genesis.vin.clear();
        if (fault == 8) genesis.vin[0].prevout.n = 1;
        frozen.genesis_transaction = fault == 0 ? frozen.deployment_transaction : MakeTransactionRef(genesis);
        candidate.genesis_state_outpoint = COutPoint{frozen.genesis_transaction->GetHash(), 0};
        frozen.issuance_input_index = frozen.inventory_output_index = 0;
        frozen.reissuance_token_burn_output_index = frozen.state_authority_source_output_index = 0;
        switch (fault) {
        case 1: candidate.genesis_state_outpoint.hash = Txid::FromUint256(uint256S("72")); break;
        case 2: frozen.issuance_input_index = 1; break;
        case 3: frozen.inventory_output_index = 1; break;
        case 4: frozen.reissuance_token_burn_output_index = 1; break;
        case 5: frozen.state_authority_source_output_index = 1; break;
        case 6: candidate.genesis_state_outpoint.n = 1; break;
        }
        BOOST_CHECK(!ecx::DeriveBondV2CapitalProjectionAfterScripts(activation, nullptr, activation_view,
            candidate.activation_height, uint256S("53"), 1, 2, snapshot, error, candidate));
        BOOST_CHECK_EQUAL(error, fault < 9 ? "ECX bond V2 physical deployment/genesis linkage changed" :
            "ECX bond V2 deployment/genesis issuance shape changed");
    }

    // Synthetic projection fixture: no signatures, live chain, or production activation.
    auto public_consensus = consensus;
    auto& frozen = public_consensus.bond_v2;
    frozen.deployment_version = 3;
    frozen.inventory_asset_blinding_factor.SetNull();
    frozen.inventory_value_blinding_factor.SetNull();
    frozen.issuance_value_blinding_factor.SetNull();
    CMutableTransaction deployment;
    deployment.vin.emplace_back(COutPoint{Txid::FromUint256(uint256S("81")), 0});
    deployment.vin[0].assetIssuance.nAmount = CConfidentialValue(2'100'000'000'000'000);
    deployment.vin[0].assetIssuance.nInflationKeys = CConfidentialValue(1);
    uint256 entropy;
    GenerateAssetEntropy(entropy, deployment.vin[0].prevout, deployment.vin[0].assetIssuance.assetEntropy);
    CAsset asset, token;
    CalculateAsset(asset, entropy);
    CalculateReissuanceToken(token, entropy, false);
    deployment.vout.emplace_back(asset, 2'100'000'000'000'000, CScript() << OP_1);
    deployment.vout.emplace_back(token, 1, CScript() << OP_RETURN);
    deployment.vout.emplace_back(CAsset(frozen.state_authority_asset_id), 1, CScript() << OP_1);
    frozen.issuance_input_index = frozen.inventory_output_index = 0;
    frozen.reissuance_token_burn_output_index = 1;
    frozen.state_authority_source_output_index = 2;
    frozen.bond_asset_id = asset.id;
    const auto script_hash = [](const CScript& script) {
        uint256 hash;
        CSHA256().Write(script.data(), script.size()).Finalize(hash.begin());
        return hash;
    };
    frozen.inventory_covenant_script_sha256 = script_hash(deployment.vout[0].scriptPubKey);
    frozen.reissuance_token_burn_script_sha256 = script_hash(deployment.vout[1].scriptPubKey);
    frozen.deployment_transaction = MakeTransactionRef(deployment);
    const auto deployment_id = frozen.deployment_transaction->GetHash();
    frozen.bond_deployment_commitment = ecx::BondDeploymentCommitment(3,
        {deployment_id.ToUint256(), deployment.vin[0].prevout.hash.ToUint256(), 0, asset.id, token.id, 0, 1,
         frozen.inventory_covenant_script_sha256, frozen.reissuance_token_burn_script_sha256});
    uint256 state_root, bond_root, funding_root, covenant_root;
    BOOST_REQUIRE(ecx::ComputeBondV2EmptyGenesisRoots(public_consensus, 20, 1000,
        state_root, bond_root, funding_root, covenant_root));
    CScript genesis_script;
    BOOST_REQUIRE(ecx::ComputeBondV2FiniteStateScript(public_consensus, covenant_root, genesis_script));
    CMutableTransaction genesis;
    genesis.vin.emplace_back(COutPoint{deployment_id, 2});
    genesis.vout.emplace_back(CAsset(frozen.state_authority_asset_id), 1, genesis_script);
    frozen.genesis_transaction = MakeTransactionRef(genesis);
    public_consensus.genesis_state_outpoint = COutPoint{frozen.genesis_transaction->GetHash(), 0};
    public_consensus.genesis_state_root = ecx::ComputeStateUtxoRoot(Params().GetConsensus().hashGenesisBlock,
        public_consensus.genesis_state_outpoint, genesis.vout[0]);
    BOOST_REQUIRE(ecx::VerifyPublicBondDeployment(*frozen.deployment_transaction, 0, 0, 1));
    for (unsigned fault = 0; fault < 18; ++fault) {
        auto candidate = public_consensus;
        Coin inventory_coin{deployment.vout[0], 10, false};
        Coin genesis_coin{genesis.vout[0], 20, false};
        switch (fault) {
        case 1: candidate.bond_v2.inventory_covenant_script_sha256 = uint256S("82"); break;
        case 2: candidate.bond_v2.state_authority_asset_id = uint256S("83"); break;
        case 3: candidate.bond_v2.reissuance_token_burn_script_sha256 = uint256S("84"); break;
        case 6: inventory_coin.out.nValue = CConfidentialValue(2); break;
        case 7: genesis_coin.out.nValue = CConfidentialValue(2); break;
        case 8: inventory_coin.nHeight = 0; break;
        case 9: genesis_coin.nHeight = 0; break;
        case 10: inventory_coin.nHeight = 0x7fffffff; break;
        case 11: genesis_coin.nHeight = 0x7fffffff; break;
        case 12: genesis_coin.nHeight = 9; break;
        case 13: inventory_coin.nHeight = genesis_coin.nHeight = candidate.activation_height; break;
        case 14: genesis_coin.nHeight = candidate.activation_height; break;
        case 15: candidate.bond_v2.transition_cmr = uint256S("85"); break;
        case 16: candidate.genesis_state_root = uint256S("86"); break;
        case 17: genesis_coin.nHeight = 21; break;
        }
        MemoryCoinsView base;
        CCoinsViewCache coins{&base};
        if (fault != 4) coins.AddCoin(COutPoint{deployment_id, 0}, std::move(inventory_coin), false);
        if (fault != 5) coins.AddCoin(candidate.genesis_state_outpoint, std::move(genesis_coin), false);
        CBlock block;
        block.hashExchangeStateRoot = candidate.genesis_state_root;
        DataStream poisoned{std::vector<unsigned char>(914,0xa5)};
        poisoned >> snapshot;
        DataStream before;
        before << snapshot;
        const bool accepted = ecx::DeriveBondV2CapitalProjectionAfterScripts(block, nullptr, coins,
            candidate.activation_height, uint256S("53"), 1, 1000, snapshot, error, candidate);
        BOOST_CHECK_MESSAGE(accepted == (fault == 0), "fault " << fault << ": " << error);
        if (fault == 0) {
            BOOST_CHECK_EQUAL(snapshot.inventory_share_atoms, 2'100'000'000'000'000ULL);
            BOOST_CHECK_EQUAL(snapshot.exchange_state_root, candidate.genesis_state_root);
            std::vector<unsigned char> outcome_seed(frozen.bond_inbox_domain.begin(),frozen.bond_inbox_domain.end());
            outcome_seed.insert(outcome_seed.end(),candidate.chain_id.begin(),candidate.chain_id.end());
            outcome_seed.insert(outcome_seed.end(),frozen.configuration_hash.begin(),frozen.configuration_hash.end());
            const std::array<uint256,15> identities{candidate.genesis_state_root,frozen.configuration_hash,
                frozen.bond_asset_id,frozen.bond_deployment_commitment,frozen.transition_program_id,frozen.transition_cmr,
                covenant_root,bond_root,funding_root,frozen.inventory_covenant_script_sha256,
                TestTaggedHash("ECX/redemption-queue/v2/empty",{}),frozen.genesis_availability_root,
                ecx::BondInboxGenesisHead(candidate),TestTaggedHash("ECX/bond-inbox-outcomes-genesis/v4-expired-unavailable-v2",outcome_seed),
                TestTaggedHash("ECX/central-matcher-execution-receipt-batch/v2/empty",{})};
            DataStream expected, actual;
            expected << ReferenceGenesisCapitalSnapshot(identities,20,1000,frozen.genesis_mark_price);
            actual << snapshot;
            BOOST_CHECK_EQUAL(HexStr(actual),HexStr(expected));
        } else {
            BOOST_CHECK_EQUAL(error, fault < 4 ? "ECX bond V2 deployment outputs differ from the authorized facts" :
                fault < 15 ? "ECX bond V2 activation requires confirmed ordered deployment and genesis UTXOs" :
                "ECX bond V2 genesis singleton is not the exact derived empty state");
            DataStream after;
            after << snapshot;
            BOOST_CHECK_EQUAL(HexStr(after),HexStr(before));
        }
    }
}

BOOST_AUTO_TEST_CASE(incremental_activation_projection_requires_exact_undo)
{
    // Synthetic post-script projection coverage, not Groth16 verification.
    ecx::ExchangeConsensus consensus{ConfiguredConsensus(
        50, COutPoint{Txid::FromUint256(uint256S("50")), 0}, uint256S("51"))};
    PopulateTestBondV2FrozenIdentities(consensus);
    const auto fill_identity = [](uint256& value, unsigned char byte) {
        std::fill(value.begin(), value.end(), byte);
    };
    fill_identity(consensus.bond_v2.transition_program_id, 1);
    fill_identity(consensus.bond_v2.configuration_hash, 2);
    fill_identity(consensus.bond_v2.bond_asset_id, 11);
    fill_identity(consensus.bond_v2.bond_deployment_commitment, 12);
    fill_identity(consensus.bond_v2.transition_journal_domain_sha256, 16);
    fill_identity(consensus.bond_v2.transition_cmr, 17);
    fill_identity(consensus.bond_v2.identity_derivation_record_sha256, 18);
    auto annex{TestIncrementalActivationAnnexPayload()};
    std::copy(consensus.bond_v2.incremental_activation_program_id.begin(),
        consensus.bond_v2.incremental_activation_program_id.end(), annex.begin() + 11);
    const auto bind_hash = [&](size_t offset, const uint256& hash) {
        std::copy(hash.begin(), hash.end(), annex.begin() + 435 + offset);
    };
    bind_hash(4, consensus.bond_v2.incremental_activation_configuration_hash);
    bind_hash(36, consensus.bond_v2.configuration_hash);
    bind_hash(100, consensus.bond_v2.incremental_successor_configuration_hash);
    const uint256 private_root{uint256S("1234")};
    const uint256 covenant_root{uint256S("5678")};
    const uint256 successor_root{uint256S("9876")};
    const uint256 parent_hash{uint256S("abcd")};
    BOOST_REQUIRE(private_root != covenant_root);
    bind_hash(68, private_root);
    bind_hash(132, successor_root);
    bind_hash(196, parent_hash);
    std::copy(consensus.chain_id.begin(), consensus.chain_id.end(), annex.begin() + 435 + 228);
    const auto bind_u64 = [&](size_t offset, uint64_t value) {
        std::vector<unsigned char> encoded;
        TestPushU64Be(encoded, value);
        std::copy(encoded.begin(), encoded.end(), annex.begin() + 435 + offset);
    };
    bind_u64(324, 51);
    bind_u64(332, 9);
    CTxOut predecessor{AuthorityOutput(1)};
    BOOST_REQUIRE(ecx::ComputeBondV2FiniteStateScript(consensus, covenant_root,
        predecessor.scriptPubKey));
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256S("1235")), 0});
    tx.vout.push_back(AuthorityOutput(1));
    BOOST_REQUIRE(ecx::ComputeBondV2IncrementalSuccessorScript(consensus,
        successor_root, tx.vout[0].scriptPubKey));
    bind_hash(164, CTransaction{tx}.GetHash().ToUint256());
    const std::vector<unsigned char> values(annex.begin() + 435, annex.end());
    const uint256 digest{TestSha256(values)};
    std::copy(digest.begin(), digest.end(), annex.begin() + 43);
    std::vector<unsigned char> wire{0x50};
    wire.insert(wire.end(), annex.begin(), annex.end());
    tx.witness.vtxinwit.resize(1);
    tx.witness.vtxinwit[0].scriptWitness.stack = {{0}, wire};
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    CBlock block;
    block.vtx = {MakeTransactionRef(coinbase), MakeTransactionRef(tx)};
    block.hashExchangeStateRoot = ecx::ComputeStateUtxoRoot(
        Params().GetConsensus().hashGenesisBlock,
        COutPoint{block.vtx[1]->GetHash(), 0}, tx.vout[0]);
    CBlock prior_block;
    prior_block.hashExchangeStateRoot = ecx::ComputeStateUtxoRoot(
        Params().GetConsensus().hashGenesisBlock, tx.vin[0].prevout, predecessor);
    TestBlockIndex previous{prior_block, 50};
    ecx::BondV2CapitalSnapshot prior;
    prior.exchange_state_root = prior_block.hashExchangeStateRoot;
    prior.covenant_state_hash = covenant_root;
    previous.ecxBondV2Capital = prior;
    CBlockUndo undo;
    undo.vtxundo.resize(1);
    undo.vtxundo[0].vprevout.emplace_back(predecessor, 49, false);
    MemoryCoinsView base;
    CCoinsViewCache view{&base};
    ecx::BondV2CapitalSnapshot result;
    std::string error;
    const auto project = [&](const CBlockUndo* supplied) {
        return ecx::DeriveBondV2CapitalProjectionAfterScripts(block, &previous,
            view, 51, parent_hash, 8, 9, result, error, consensus, supplied);
    };
    BOOST_REQUIRE_MESSAGE(project(&undo), error);
    BOOST_CHECK_EQUAL(result.proof_profile, 1);
    BOOST_CHECK_EQUAL(result.covenant_state_hash, successor_root);
    BOOST_CHECK(result.redemption_queue_root==TestTaggedHash("ECX/successor-redemption-queue/v2-u128",std::vector<unsigned char>(4,0)));
    std::vector<unsigned char> outcome_preimage(consensus.bond_v2.bond_inbox_domain.begin(),consensus.bond_v2.bond_inbox_domain.end());
    outcome_preimage.insert(outcome_preimage.end(),consensus.chain_id.begin(),consensus.chain_id.end());
    outcome_preimage.insert(outcome_preimage.end(),consensus.bond_v2.configuration_hash.begin(),consensus.bond_v2.configuration_hash.end());
    BOOST_CHECK(result.bond_inbox_outcome_root==TestTaggedHash("ECX/successor-bond-inbox-outcomes-genesis/v2-u128",outcome_preimage));
    const auto original_tx=tx;
    for (size_t offset : {size_t{11},size_t{435+4},size_t{435+36},size_t{435+100},size_t{435+164},
                         size_t{435+196},size_t{435+228},size_t{435+331},size_t{435+339}}) {
        auto& modified=tx.witness.vtxinwit[0].scriptWitness.stack.back();
        modified[1+offset]^=1;
        const uint256 modified_digest=TestSha256(std::vector<unsigned char>(modified.begin()+436,modified.end()));
        std::copy(modified_digest.begin(),modified_digest.end(),modified.begin()+44);
        block.vtx[1]=MakeTransactionRef(tx);
        BOOST_CHECK(!project(&undo));
        BOOST_CHECK_EQUAL(error,"ECX incremental activation does not bind the frozen predecessor/transaction/BMM context");
        tx=original_tx;
    }
    block.vtx[1]=MakeTransactionRef(original_tx);
    BOOST_REQUIRE_MESSAGE(project(&undo),error);
    BOOST_CHECK(!project(nullptr));
    BOOST_CHECK(error.find("undo context") != std::string::npos);
    CBlockUndo missing;
    BOOST_CHECK(!project(&missing));
    auto malformed{undo};
    malformed.vtxundo[0].vprevout.clear();
    BOOST_CHECK(!project(&malformed));
    malformed = undo;
    malformed.vtxundo[0].vprevout[0].Clear();
    BOOST_CHECK(!project(&malformed));
    malformed = undo;
    malformed.vtxundo[0].vprevout[0].out.scriptPubKey = CScript{} << OP_TRUE;
    BOOST_CHECK(!project(&malformed));
    BOOST_REQUIRE_MESSAGE(project(&undo), error);
}

BOOST_AUTO_TEST_CASE(bond_v2_projection_follows_each_verified_reorg_branch)
{
    ecx::ExchangeConsensus consensus{ConfiguredConsensus(
        50, COutPoint{Txid::FromUint256(uint256S("50")), 0}, uint256S("51"))};
    PopulateTestBondV2FrozenIdentities(consensus);
    const std::array<unsigned char, 32> program{{
        0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4,
        0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 8}};
    std::copy(program.begin(), program.end(), consensus.bond_v2.transition_program_id.begin());
    std::fill(consensus.bond_v2.configuration_hash.begin(), consensus.bond_v2.configuration_hash.end(), 2);
    std::fill(consensus.bond_v2.bond_asset_id.begin(), consensus.bond_v2.bond_asset_id.end(), 11);
    std::fill(consensus.bond_v2.bond_deployment_commitment.begin(), consensus.bond_v2.bond_deployment_commitment.end(), 12);
    std::fill(consensus.bond_v2.transition_journal_domain_sha256.begin(), consensus.bond_v2.transition_journal_domain_sha256.end(), 1);
    std::fill(consensus.bond_v2.transition_cmr.begin(), consensus.bond_v2.transition_cmr.end(), 17);
    std::fill(consensus.bond_v2.identity_derivation_record_sha256.begin(), consensus.bond_v2.identity_derivation_record_sha256.end(), 18);

    CBlock previous_block;
    std::fill(previous_block.hashExchangeStateRoot.begin(), previous_block.hashExchangeStateRoot.end(), 6);
    TestBlockIndex previous{previous_block, 50};
    ecx::BondV2CapitalSnapshot previous_capital;
    previous_capital.exchange_state_root = previous.hashExchangeStateRoot;
    previous_capital.configuration_hash = consensus.bond_v2.configuration_hash;
    previous_capital.bond_asset_id = consensus.bond_v2.bond_asset_id;
    previous_capital.bond_deployment_commitment = consensus.bond_v2.bond_deployment_commitment;
    previous_capital.transition_program_id = consensus.bond_v2.transition_program_id;
    previous_capital.transition_cmr = consensus.bond_v2.transition_cmr;
    std::fill(
        previous_capital.covenant_state_hash.begin(),
        previous_capital.covenant_state_hash.end(), 3);
    std::fill(
        previous_capital.node_bond_inbox_head_root.begin(),
        previous_capital.node_bond_inbox_head_root.end(), 19);
    previous_capital.node_bond_inbox_entry_count = 4;
    previous_capital.matcher_execution_sequence = 5;
    previous.ecxBondV2Capital = previous_capital;
    uint256 parent_hash;
    std::fill(parent_hash.begin(), parent_hash.end(), 7);
    MemoryCoinsView projection_base;
    CCoinsViewCache projection_view{&projection_base};

    const auto branch = [&](unsigned char script_byte) {
        CMutableTransaction mutable_tx;
        mutable_tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256S("60")), 0});
        mutable_tx.vout.push_back(AuthorityOutput(0x60));
        std::vector<unsigned char> annex{TestSp1AnnexPayload(true)};
        uint256 next_covenant_state_hash;
        std::copy(
            annex.begin() + 435 + 100,
            annex.begin() + 435 + 132,
            next_covenant_state_hash.begin());
        mutable_tx.vout[0].scriptPubKey =
            TestBondV2SuccessorScript(consensus, next_covenant_state_hash);
        BOOST_REQUIRE(!mutable_tx.vout[0].scriptPubKey.empty());
        // A branch-specific non-state output changes txid/outpoint while the
        // same proven next covenant state remains committed at output zero.
        mutable_tx.vout.push_back(AuthorityOutput(script_byte));
        const CTransaction without_witness{mutable_tx};
        std::copy(
            without_witness.GetHash().ToUint256().begin(), without_witness.GetHash().ToUint256().end(),
            annex.begin() + 435 + 132);
        RecommitV2PublicValues(annex);
        std::vector<unsigned char> wire_annex{0x50};
        wire_annex.insert(wire_annex.end(), annex.begin(), annex.end());
        mutable_tx.witness.vtxinwit.resize(1);
        mutable_tx.witness.vtxinwit[0].scriptWitness.stack = {
            std::vector<unsigned char>{0}, std::move(wire_annex)};
        CBlock block;
        block.vtx = {MakeTransactionRef(std::move(mutable_tx))};
        block.hashExchangeStateRoot = ecx::ComputeStateUtxoRoot(
            Params().GetConsensus().hashGenesisBlock,
            COutPoint{block.vtx[0]->GetHash(), 0},
            block.vtx[0]->vout[0]);
        ecx::BondV2CapitalSnapshot projection;
        std::string error;
        BOOST_REQUIRE_MESSAGE(
            ecx::DeriveBondV2CapitalProjectionAfterScripts(
                block, &previous, projection_view, 51, parent_hash, 8, 9,
                projection, error, consensus),
            error);
        BOOST_CHECK_EQUAL(projection.exchange_state_root, block.hashExchangeStateRoot);
        return std::make_pair(block, projection);
    };

    const auto left{branch(0x61)};
    const auto right{branch(0x62)};
    BOOST_CHECK(left.second.exchange_state_root != right.second.exchange_state_root);

    TestBlockIndex left_index{left.first, 51, &previous};
    left_index.ecxBondV2Capital = left.second;
    CBlock carry;
    carry.hashExchangeStateRoot = left.first.hashExchangeStateRoot;
    ecx::BondV2CapitalSnapshot carried;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        ecx::DeriveBondV2CapitalProjectionAfterScripts(
            carry, &left_index, projection_view, 52, parent_hash, 8, 9,
            carried, error, consensus),
        error);
    BOOST_CHECK_EQUAL(carried.exchange_state_root, left.second.exchange_state_root);
    BOOST_CHECK(carried.exchange_state_root != right.second.exchange_state_root);
}

BOOST_AUTO_TEST_CASE(inbox_simplicity_context_presence_is_tristate)
{
    PrecomputedTransactionData txdata;
    BOOST_CHECK_EQUAL(txdata.EcxForcedInboxPresence(), 0);
    BOOST_CHECK_EQUAL(txdata.EcxDepositInboxPresence(), 0);
    BOOST_CHECK_EQUAL(txdata.EcxBondV2ProjectionPresence(), 0);

    txdata.m_prior_active_forced_inbox_root = uint256S("01");
    txdata.m_prior_active_deposit_processed_cursor = 0;
    BOOST_CHECK_EQUAL(txdata.EcxForcedInboxPresence(), 2);
    BOOST_CHECK_EQUAL(txdata.EcxDepositInboxPresence(), 2);

    txdata.m_prior_active_forced_processed_cursor = 0;
    txdata.m_prior_active_deposit_inbox_root = uint256S("02");
    BOOST_CHECK_EQUAL(txdata.EcxForcedInboxPresence(), 1);
    BOOST_CHECK_EQUAL(txdata.EcxDepositInboxPresence(), 1);

    txdata.m_prior_active_bond_inbox_root = uint256S("03");
    BOOST_CHECK_EQUAL(txdata.EcxBondV2ProjectionPresence(), 2);
    txdata.m_prior_active_bond_inbox_count = 0;
    BOOST_CHECK_EQUAL(txdata.EcxBondV2ProjectionPresence(), 2);
    txdata.m_current_sidechain_height = 101;
    BOOST_CHECK_EQUAL(txdata.EcxBondV2ProjectionPresence(), 1);
    txdata.m_current_sidechain_height.reset();
    BOOST_CHECK_EQUAL(txdata.EcxBondV2ProjectionPresence(), 2);

    txdata.m_prior_active_forced_inbox_root.reset();
    txdata.m_prior_active_deposit_processed_cursor.reset();
    BOOST_CHECK_EQUAL(txdata.EcxForcedInboxPresence(), 2);
    BOOST_CHECK_EQUAL(txdata.EcxDepositInboxPresence(), 2);
}

BOOST_AUTO_TEST_CASE(simplicity_context_presence_exhaustive_masks)
{
    PrecomputedTransactionData txdata;
    const auto check = [](auto fields, auto read) {
        const unsigned limit = 1U << std::tuple_size_v<decltype(fields)>;
        for (unsigned mask = 0; mask < limit; ++mask) {
            unsigned index = 0;
            const auto assign = [&](auto* field) {
                if (mask & (1U << index++)) field->emplace();
                else field->reset();
            };
            std::apply([&](auto*... field) { (assign(field), ...); }, fields);
            BOOST_CHECK_EQUAL(read(), mask == 0 ? 0 : mask == limit - 1 ? 1 : 2);
        }
    };
    check(std::tuple{&txdata.m_bond_v2_configuration_hash, &txdata.m_bond_v2_asset_id,
        &txdata.m_bond_v2_deployment_commitment, &txdata.m_bond_v2_transition_cmr,
        &txdata.m_bond_v2_collateral_vault_script_sha256, &txdata.m_bond_v2_collateral_vault_cmr,
        &txdata.m_bond_v2_insurance_reserve_script_sha256, &txdata.m_bond_v2_insurance_reserve_cmr},
        [&] { return txdata.EcxBondV2IdentityPresence(); });
    check(std::tuple{&txdata.m_bond_v2_incremental_activation_program_id,
        &txdata.m_bond_v2_incremental_activation_configuration_hash, &txdata.m_bond_v2_incremental_activation_cmr,
        &txdata.m_incremental_successor_program_id, &txdata.m_bond_v2_incremental_successor_configuration_hash,
        &txdata.m_incremental_successor_transition_cmr, &txdata.m_incremental_successor_state_node_domain_sha256},
        [&] { return txdata.EcxBondV2IncrementalActivationIdentityPresence(); });
    check(std::tuple{&txdata.m_prior_active_bond_inbox_root, &txdata.m_prior_active_bond_inbox_count,
        &txdata.m_current_sidechain_height}, [&] { return txdata.EcxBondV2ProjectionPresence(); });
    check(std::tuple{&txdata.m_current_bmm_parent_block_hash, &txdata.m_current_bmm_parent_height,
        &txdata.m_current_bmm_parent_mtp}, [&] { return txdata.EcxCurrentBmmPresence(); });
    check(std::tuple{&txdata.m_prior_active_forced_inbox_root, &txdata.m_prior_active_forced_processed_cursor},
        [&] { return txdata.EcxForcedInboxPresence(); });
    check(std::tuple{&txdata.m_prior_active_deposit_inbox_root, &txdata.m_prior_active_deposit_processed_cursor},
        [&] { return txdata.EcxDepositInboxPresence(); });
    BOOST_CHECK_THROW(drivechain::haskell::ContextPresence(1, 0), std::runtime_error);
    BOOST_CHECK_THROW(drivechain::haskell::ContextPresence(3, 2), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(header_rules_cover_before_activation_boundary_and_descendants)
{
    const ecx::ExchangeConsensus consensus{ConfiguredConsensus(
        10,
        COutPoint{Txid::FromUint256(uint256S("11")), 7},
        uint256S("22"))};
    std::string error;

    CBlockHeader before;
    before.nVersion = 0x20000000;
    BOOST_CHECK_MESSAGE(
        ecx::CheckExchangeStateHeader(before, 9, error, consensus),
        error);
    before.nVersion |= CBlockHeader::EXCHANGE_STATE_HF_MASK;
    before.hashExchangeStateRoot = uint256S("03");
    BOOST_CHECK(!ecx::CheckExchangeStateHeader(before, 9, error, consensus));
    BOOST_CHECK(error.find("forbidden before activation") != std::string::npos);

    CBlockHeader activation;
    activation.nVersion = 0x20000000 |
        CBlockHeader::EXCHANGE_STATE_HF_MASK |
        CBlockHeader::FORCED_INBOX_HF_MASK |
        CBlockHeader::DEPOSIT_INBOX_HF_MASK |
        CBlockHeader::INBOX_CURSOR_HF_MASK;
    activation.hashExchangeStateRoot = consensus.genesis_state_root;
    activation.hashForcedInboxRoot = ecx::ComputeForcedInboxGenesis(consensus);
    activation.hashDepositInboxRoot = ecx::ComputeDepositInboxGenesis(consensus);
    activation.ecxParentHeight = 1;
    BOOST_CHECK_MESSAGE(
        ecx::CheckExchangeStateHeader(activation, 10, error, consensus),
        error);
    for (size_t length : {0U,1U,252U,253U,4096U}) {
        auto configured=consensus;
        configured.collateral_vault_script=CScript{} << std::vector<unsigned char>(length,0x51);
        configured.collateral_vault_script_hash=TestSha256({configured.collateral_vault_script.begin(),
            configured.collateral_vault_script.end()});
        BOOST_CHECK_MESSAGE(ecx::CheckExchangeStateHeader(activation,10,error,configured),error);
        configured.collateral_vault_script_hash.begin()[0]^=1;
        BOOST_CHECK(!ecx::CheckExchangeStateHeader(activation,10,error,configured));
        BOOST_CHECK(!error.empty());
    }
    CBlockIndex persisted_activation{activation};
    persisted_activation.nHeight = 10;
    BOOST_CHECK_MESSAGE(
        ecx::CheckExchangeStateIndexHeader(
            persisted_activation, error, consensus),
        error);

    CBlockHeader wrong_activation{activation};
    wrong_activation.hashExchangeStateRoot = uint256S("04");
    BOOST_CHECK(!ecx::CheckExchangeStateHeader(
        wrong_activation, 10, error, consensus));
    BOOST_CHECK(error.find("frozen genesis roots") != std::string::npos);

    CBlockHeader descendant{activation};
    descendant.hashExchangeStateRoot = uint256S("05");
    descendant.hashForcedInboxRoot = uint256S("06");
    descendant.hashDepositInboxRoot = uint256S("07");
    descendant.forcedProcessedCursor = 8;
    descendant.depositProcessedCursor = 9;
    descendant.sourceBacklogOldestParentHeight = 1;
    BOOST_CHECK_MESSAGE(
        ecx::CheckExchangeStateHeader(descendant, 11, error, consensus),
        error);
    descendant.nVersion &= ~CBlockHeader::DEPOSIT_INBOX_HF_MASK;
    BOOST_CHECK(!ecx::CheckExchangeStateHeader(descendant, 11, error, consensus));
    BOOST_CHECK(error.find("required and nonzero") != std::string::npos);
    CBlockIndex persisted_descendant{descendant};
    persisted_descendant.nHeight = 11;
    BOOST_CHECK(!ecx::CheckExchangeStateIndexHeader(
        persisted_descendant, error, consensus));
    BOOST_CHECK(error.find("required and nonzero") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(consensus_rejects_spends_of_all_synthetic_state_outpoints)
{
    MemoryCoinsView base;
    CCoinsViewCache view(&base);
    const std::vector<COutPoint> reserved{
        COutPoint{
            Txid::FromUint256(uint256S("f0bcf7ca88c8a7c66d74d5540d5458ead1a15df5a8b6b98c08032a1300579ff9")),
            0},
        COutPoint{
            Txid::FromUint256(uint256S("2d15ce4b128995291c4e38d36b8ae411a15bf80d7acee97cf5f58d2fc4de52b1")),
            0},
    };
    BOOST_REQUIRE(drivechain::IsBmmStateInternalOutpoint(reserved[0]));
    BOOST_REQUIRE(drivechain::IsCtipStateInternalOutpoint(reserved[1]));

    for (const COutPoint& outpoint : reserved) {
        for (const bool script_checks : {false, true}) {
            CMutableTransaction mutable_transaction;
            mutable_transaction.vin.emplace_back(outpoint);
            const CTransaction transaction{mutable_transaction};
            TxValidationState state;
            CAmountMap fees;
            std::set<std::pair<uint256, COutPoint>> pegins;
            BOOST_CHECK(!Consensus::CheckTxInputs(
                transaction,
                state,
                view,
                1,
                fees,
                pegins,
                nullptr,
                false,
                script_checks,
                {}));
            BOOST_CHECK_EQUAL(
                state.GetRejectReason(),
                "bad-drivechain-internal-state-spend");
        }
    }

    const std::vector<COutPoint> all_reserved{
        COutPoint{
            Txid::FromUint256(uint256S("e31f7fb1e9489bfb9f6a73c10f80ecdcce1f276fbdf0cf85c02e3bcf174dc041")),
            0},
        COutPoint{
            Txid::FromUint256(uint256S("c3fd019db845c81a68a561f5ab67d92c3ab2505cb2c8212f02511e07e8c2f2a1")),
            0},
        COutPoint{
            Txid::FromUint256(uint256S("0cc4c302121a9d75c8a0e520253c1740520a6d6f4d03db6947a99565175d6586")),
            0},
        reserved[0],
        reserved[1],
    };
    for (size_t index = 0; index < 3; ++index) {
        for (const bool script_checks : {false, true}) {
            CMutableTransaction mutable_transaction;
            mutable_transaction.vin.emplace_back(all_reserved[index]);
            const CTransaction transaction{mutable_transaction};
            TxValidationState state;
            CAmountMap fees;
            std::set<std::pair<uint256, COutPoint>> pegins;
            BOOST_CHECK(!Consensus::CheckTxInputs(
                transaction,
                state,
                view,
                1,
                fees,
                pegins,
                nullptr,
                false,
                script_checks,
                {}));
            BOOST_CHECK_EQUAL(
                state.GetRejectReason(),
                "bad-ecx-internal-state-spend");
        }
    }
    for (const bool exchange_first : {false, true}) {
        for (const bool prepend_pegin : {false, true}) {
            CMutableTransaction ordered;
            if (prepend_pegin) {
                ordered.vin.emplace_back(all_reserved[0]);
                ordered.vin.back().m_is_pegin = true;
            }
            ordered.vin.emplace_back(all_reserved[exchange_first ? 0 : 3]);
            ordered.vin.emplace_back(all_reserved[exchange_first ? 3 : 0]);
            TxValidationState state;
            CAmountMap fees;
            std::set<std::pair<uint256, COutPoint>> pegins;
            BOOST_CHECK(!Consensus::CheckTxInputs(CTransaction{ordered}, state, view, 1,
                fees, pegins, nullptr, false, false, {}));
            BOOST_CHECK_EQUAL(state.GetRejectReason(), exchange_first ?
                "bad-ecx-internal-state-spend" : "bad-drivechain-internal-state-spend");
        }
    }
    for (const COutPoint& outpoint : all_reserved) {
        const ecx::ExchangeConsensus consensus{
            ConfiguredConsensus(10, outpoint, uint256S("22"))};
        CBlockHeader header;
        std::string error;
        BOOST_CHECK(!ecx::CheckExchangeStateHeader(header, 10, error, consensus));
        BOOST_CHECK(error.find("collides with a reserved chainstate record") !=
                    std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(runtime_consensus_fingerprint_binds_every_field)
{
    const ecx::ExchangeConsensus consensus{ConfiguredConsensus(
        10,
        COutPoint{Txid::FromUint256(uint256S("11")), 7},
        uint256S("22"))};
    const std::string network_id{"elementsregtest"};
    const uint256 genesis_hash{uint256S("33")};
    const uint256 policy_asset{uint256S("44")};
    const uint256 bmm_fingerprint{uint256S("55")};
    const auto compute = [&](
                             const ecx::ExchangeConsensus& value,
                             const std::string& network,
                             const uint256& genesis,
                             const uint256& policy,
                             const uint256& bmm,
                             const bool private_bmm_enabled,
                             const uint32_t private_bmm_activation_height) {
        return ecx::ComputeRuntimeConsensusFingerprint(
            value,
            network,
            genesis,
            policy,
            bmm,
            private_bmm_enabled,
            private_bmm_activation_height);
    };
    const auto compute_default = [&](const ecx::ExchangeConsensus& value) {
        return compute(
            value,
            network_id,
            genesis_hash,
            policy_asset,
            bmm_fingerprint,
            true,
            20);
    };
    const uint256 expected{compute_default(consensus)};
    BOOST_TEST_MESSAGE("runtime-fingerprint baseline " << expected.GetHex());
    BOOST_CHECK_EQUAL(
        expected,
        compute_default(consensus));

    const auto check_consensus_mutation = [&](auto mutate) {
        ecx::ExchangeConsensus changed{consensus};
        mutate(changed);
        const auto fingerprint=compute_default(changed);
        BOOST_TEST_MESSAGE("runtime-fingerprint mutation " << fingerprint.GetHex());
        BOOST_CHECK_NE(expected, fingerprint);
    };
    check_consensus_mutation([](auto& value) { ++value.activation_height; });
    check_consensus_mutation([](auto& value) { ++value.bond_v2.deployment_version; });
    check_consensus_mutation([](auto& value) { value.genesis_state_outpoint.hash = Txid::FromUint256(uint256S("12")); });
    check_consensus_mutation([](auto& value) { ++value.genesis_state_outpoint.n; });
    check_consensus_mutation([](auto& value) { value.genesis_state_root = uint256S("23"); });
    check_consensus_mutation([](auto& value) { value.chain_id[0] ^= 1; });
    check_consensus_mutation([](auto& value) { value.forced_action_domain[0] ^= 1; });
    check_consensus_mutation([](auto& value) { value.deposit_inbox_domain[0] ^= 1; });
    check_consensus_mutation([](auto& value) { value.collateral_vault_script.push_back(OP_TRUE); });
    check_consensus_mutation([](auto& value) { value.collateral_vault_script_hash.begin()[0] ^= 1; });

    using BondConfig = std::remove_cvref_t<decltype(consensus.bond_v2)>;
    for (auto member : {
        &BondConfig::inventory_asset_blinding_factor, &BondConfig::inventory_value_blinding_factor,
        &BondConfig::issuance_value_blinding_factor, &BondConfig::transition_program_id,
        &BondConfig::configuration_hash, &BondConfig::bond_asset_id, &BondConfig::bond_deployment_commitment,
        &BondConfig::collateral_vault_covenant_cmr, &BondConfig::inventory_covenant_script_sha256,
        &BondConfig::reissuance_token_burn_script_sha256, &BondConfig::redemption_queue_script_sha256,
        &BondConfig::insurance_reserve_script_sha256, &BondConfig::insurance_reserve_covenant_cmr,
        &BondConfig::state_authority_asset_id, &BondConfig::public_state_domain_sha256,
        &BondConfig::state_node_domain_sha256, &BondConfig::transition_journal_domain_sha256,
        &BondConfig::transition_cmr, &BondConfig::incremental_activation_program_id,
        &BondConfig::incremental_activation_configuration_hash, &BondConfig::incremental_activation_cmr,
        &BondConfig::incremental_successor_program_id, &BondConfig::incremental_successor_configuration_hash,
        &BondConfig::incremental_successor_transition_cmr, &BondConfig::incremental_successor_state_node_domain_sha256,
        &BondConfig::inventory_cmr, &BondConfig::redemption_queue_cmr, &BondConfig::ecx_btc_conversion_program_id,
        &BondConfig::ecx_btc_redemption_covenant_commitment, &BondConfig::ecx_btc_source_checkpoint_commitment,
        &BondConfig::usdd_usd_conversion_program_id, &BondConfig::usdd_usd_redemption_covenant_commitment,
        &BondConfig::usdd_usd_source_checkpoint_commitment, &BondConfig::matcher_genesis_receipt_hash,
        &BondConfig::order_receipts_genesis_root, &BondConfig::genesis_availability_root,
        &BondConfig::identity_derivation_record_sha256}) {
        check_consensus_mutation([&](auto& value) { (value.bond_v2.*member).begin()[0] ^= 1; });
    }
    for (auto member : {&BondConfig::issuance_input_index, &BondConfig::inventory_output_index,
                       &BondConfig::reissuance_token_burn_output_index, &BondConfig::state_authority_source_output_index}) {
        check_consensus_mutation([&](auto& value) { ++(value.bond_v2.*member); });
    }
    check_consensus_mutation([](auto& value) { value.bond_v2.activation_enabled = !value.bond_v2.activation_enabled; });
    check_consensus_mutation([](auto& value) { value.bond_v2.identities_frozen = !value.bond_v2.identities_frozen; });
    check_consensus_mutation([](auto& value) { value.bond_v2.canonical_configuration_bytes.push_back(1); });
    check_consensus_mutation([](auto& value) { value.bond_v2.keyless_internal_key[0] ^= 1; });
    check_consensus_mutation([](auto& value) { ++value.bond_v2.genesis_mark_price; });
    check_consensus_mutation([](auto& value) { value.bond_v2.usdd_asset_id.id.begin()[0] ^= 1; });
    check_consensus_mutation([](auto& value) { value.bond_v2.deployment_transaction = MakeTransactionRef(CMutableTransaction{}); });
    check_consensus_mutation([](auto& value) { value.bond_v2.genesis_transaction = MakeTransactionRef(CMutableTransaction{}); });

    BOOST_CHECK_NE(expected, compute(consensus, network_id, genesis_hash, policy_asset, bmm_fingerprint, false, 0));
    BOOST_CHECK_NE(expected, compute(consensus, network_id, genesis_hash, policy_asset, bmm_fingerprint, true, 21));
    BOOST_CHECK_NE(expected, compute(consensus, "regtest", genesis_hash, policy_asset, bmm_fingerprint, true, 20));
    BOOST_CHECK_NE(expected, compute(consensus, network_id, uint256S("34"), policy_asset, bmm_fingerprint, true, 20));
    BOOST_CHECK_NE(expected, compute(consensus, network_id, genesis_hash, uint256S("45"), bmm_fingerprint, true, 20));
    BOOST_CHECK_NE(expected, compute(consensus, network_id, genesis_hash, policy_asset, uint256S("56"), true, 20));
    BOOST_CHECK_NE(expected, compute(ecx::ExchangeConsensus{}, network_id, genesis_hash, policy_asset, bmm_fingerprint, false, 0));
}

BOOST_AUTO_TEST_CASE(forced_action_relay_policy_is_narrow_and_fail_closed)
{
    const COutPoint genesis{Txid::FromUint256(uint256S("11")), 0};
    const ecx::ExchangeConsensus consensus{
        ConfiguredConsensus(10, genesis, uint256S("22"))};
    const CKey key{TestTraderKey()};
    const CTransaction canonical{ForcedCancelTransaction(consensus, key)};
    std::string reason;

    reason="stale error";
    BOOST_CHECK(ecx::IsCanonicalForcedActionOutput(canonical,0,reason,consensus));
    BOOST_CHECK(reason.empty());
    for (size_t index : {canonical.vout.size(),std::numeric_limits<size_t>::max()}) {
        BOOST_CHECK(!ecx::IsCanonicalForcedActionOutput(canonical,index,reason,consensus));
        BOOST_CHECK_EQUAL(reason,"ECX forced-action output index is out of range");
    }
    CMutableTransaction ordinary;
    ordinary.vout.push_back(AuthorityOutput(0x7e));
    BOOST_CHECK(!ecx::IsCanonicalForcedActionOutput(CTransaction{ordinary},0,reason,consensus));
    BOOST_CHECK_EQUAL(reason,"output is not a canonical ECX forced action");

    BOOST_REQUIRE_GT(canonical.vout[0].scriptPubKey.size(), MAX_OP_RETURN_RELAY);
    BOOST_CHECK(!IsStandardTx(
        canonical,
        MAX_OP_RETURN_RELAY,
        true,
        CFeeRate(DUST_RELAY_TX_FEE_BITCOIN),
        reason));
    BOOST_CHECK(IsStandardTx(
        canonical,
        MAX_OP_RETURN_RELAY,
        true,
        CFeeRate(DUST_RELAY_TX_FEE_BITCOIN),
        reason,
        &consensus));
    BOOST_CHECK(!ecx::CheckSourceTransactionPolicy(
        canonical, 9, reason, consensus));
    BOOST_CHECK(ecx::CheckSourceTransactionPolicy(
        canonical, 10, reason, consensus));
    for (int activation : {-1,0,10,INT32_MAX}) {
        auto configured=consensus;
        configured.activation_height=activation;
        for (int height : {INT32_MIN,-1,0,9,10,11,INT32_MAX}) {
            reason="stale";
            BOOST_CHECK(ecx::CheckSourceTransactionPolicy(CTransaction{ordinary},height,reason,configured));
            BOOST_CHECK(reason.empty());
            const bool active=activation!=INT32_MAX && height>=activation;
            BOOST_CHECK_EQUAL(ecx::CheckSourceTransactionPolicy(canonical,height,reason,configured),active);
            BOOST_CHECK_EQUAL(reason,active ? "" : "ECX source transaction is premature before exchange activation");
        }
    }

    for (bool bad_signature : {false,true}) {
        auto invalid_key=ForcedCancelTransaction(consensus,key,bad_signature);
        auto& script=invalid_key.vout[0].scriptPubKey;
        std::fill(script.begin()+60,script.begin()+92,0xff);
        BOOST_CHECK(!ecx::IsCanonicalForcedActionOutput(CTransaction{invalid_key},0,reason,consensus));
        BOOST_CHECK_EQUAL(reason,"ECX forced action contains an invalid x-only trader key");
    }

    const CTransaction corrupt{ForcedCancelTransaction(consensus, key, true)};
    BOOST_CHECK(!IsStandardTx(
        corrupt,
        MAX_OP_RETURN_RELAY,
        true,
        CFeeRate(DUST_RELAY_TX_FEE_BITCOIN),
        reason,
        &consensus));
    BOOST_CHECK(!ecx::CheckSourceTransactionPolicy(
        corrupt, 10, reason, consensus));
    const auto parse_error=reason;
    BOOST_CHECK_EQUAL(parse_error,"ECX forced action signature is invalid");
    BOOST_CHECK(!ecx::IsCanonicalForcedActionOutput(corrupt,0,reason,consensus));
    BOOST_CHECK_EQUAL(reason,parse_error);

    CMutableTransaction duplicate{ForcedCancelTransaction(consensus, key)};
    duplicate.vout.push_back(duplicate.vout[0]);
    BOOST_CHECK(!ecx::CheckSourceTransactionPolicy(
        CTransaction{duplicate}, 10, reason, consensus));
    const std::string first_error=reason;
    auto mixed=duplicate;
    const auto invalid_deposit=ConfidentialDepositTransaction(consensus,key,false);
    mixed.vout.push_back(invalid_deposit.vout[1]);
    mixed.witness.vtxoutwit.resize(mixed.vout.size());
    BOOST_CHECK(!ecx::CheckSourceTransactionPolicy(CTransaction{mixed},10,reason,consensus));
    BOOST_CHECK_EQUAL(reason,first_error);
    uint64_t mixed_forced{99},mixed_deposits{99};
    BOOST_CHECK(!ecx::CountSourceTransactionMarkers(CTransaction{mixed},mixed_forced,mixed_deposits,reason,consensus));
    BOOST_CHECK_EQUAL(reason,first_error);
    BOOST_CHECK_EQUAL(mixed_forced,0U);
    BOOST_CHECK_EQUAL(mixed_deposits,0U);

    for (const auto& tx : {CTransaction{CMutableTransaction{}}, canonical, corrupt, CTransaction{duplicate}}) {
        uint64_t forced{99}, deposits{99};
        const bool expected = tx.vout.empty() || tx.GetHash() == canonical.GetHash();
        const bool accepted = ecx::CountSourceTransactionMarkers(tx, forced, deposits, reason, consensus);
        BOOST_CHECK_EQUAL(accepted, expected);
        BOOST_CHECK_EQUAL(forced, accepted && !tx.vout.empty() ? 1U : 0U);
        BOOST_CHECK_EQUAL(deposits, 0U);
        if (accepted) BOOST_CHECK(reason.empty());
        else BOOST_CHECK(!reason.empty());
    }
    for (unsigned shape = 0; shape < 3; ++shape) {
        auto deposit = ConfidentialDepositTransaction(consensus, key, shape != 1);
        if (shape == 2) {
            deposit.vout.push_back(deposit.vout[1]);
            deposit.witness.vtxoutwit.resize(3);
        }
        uint64_t forced{99}, deposits{99};
        const bool accepted = ecx::CountSourceTransactionMarkers(CTransaction{deposit}, forced, deposits, reason, consensus);
        BOOST_CHECK_EQUAL(accepted, shape == 0);
        BOOST_CHECK_EQUAL(forced, 0U);
        BOOST_CHECK_EQUAL(deposits, shape == 0 ? 1U : 0U);
        if (shape == 2) BOOST_CHECK_EQUAL(reason, "an Elements transaction may contain only one ECX deposit marker");
    }
    // Exercise the migrated decoder through the actual source-policy path,
    // retaining framing-before-envelope errors and all-or-nothing counters.
    for (bool forced_marker : {false,true}) {
        for (unsigned witness_shape = 0; witness_shape < 4; ++witness_shape) {
            auto candidate = forced_marker ? ForcedCancelTransaction(consensus,key) :
                ConfidentialDepositTransaction(consensus,key);
            const size_t marker_index = forced_marker ? 0 : 1;
            candidate.witness.vtxoutwit.resize(marker_index + (witness_shape != 0));
            if (witness_shape == 2) candidate.witness.vtxoutwit[marker_index].vchRangeproof = {1};
            if (witness_shape == 3) candidate.witness.vtxoutwit[marker_index].vchSurjectionproof = {1};
            uint64_t forced{99}, deposits{99};
            const bool accepted = witness_shape < 2;
            BOOST_CHECK_EQUAL(ecx::CountSourceTransactionMarkers(CTransaction{candidate},forced,deposits,reason,consensus),accepted);
            BOOST_CHECK_EQUAL(forced, accepted && forced_marker ? 1U : 0U);
            BOOST_CHECK_EQUAL(deposits, accepted && !forced_marker ? 1U : 0U);
            if (!accepted) BOOST_CHECK_EQUAL(reason, forced_marker ?
                "ECX forced action marker envelope is non-canonical" :
                "ECX deposit marker envelope or chain id is non-canonical");
        }
        for (unsigned defect=0; defect<6; ++defect) {
            auto candidate = forced_marker ? ForcedCancelTransaction(consensus,key) :
                ConfidentialDepositTransaction(consensus,key);
            auto& marker = candidate.vout[forced_marker ? 0 : 1];
            const size_t prefix = forced_marker ? 3 : 2;
            if (defect == 0 || defect == 4) marker.scriptPubKey.push_back(OP_0);
            if (defect == 1) --marker.scriptPubKey[prefix-1];
            if (defect == 2 || defect == 4) marker.scriptPubKey[prefix+4] = 0;
            if (defect == 3) marker.nValue = CConfidentialValue(1);
            if (defect == 5) marker.scriptPubKey[prefix+(forced_marker ? 6 : 5)] ^= 1;
            const std::string expected = defect == 2 || defect == 3 || defect == 5 ?
                (forced_marker ? "ECX forced action marker envelope is non-canonical" :
                    "ECX deposit marker envelope or chain id is non-canonical") :
                (forced_marker ? "ECX forced action output is not one exact minimal OP_RETURN push" :
                    "ECX deposit marker is not one exact minimal OP_RETURN push");
            const CTransaction transaction{candidate};
            uint64_t forced{99}, deposits{99};
            BOOST_CHECK(!ecx::CountSourceTransactionMarkers(transaction,forced,deposits,reason,consensus));
            BOOST_CHECK_EQUAL(reason,expected);
            BOOST_CHECK_EQUAL(forced,0U);
            BOOST_CHECK_EQUAL(deposits,0U);
            BOOST_CHECK(!ecx::CheckSourceTransactionPolicy(transaction,10,reason,consensus));
            BOOST_CHECK_EQUAL(reason,expected);
        }
    }
    for (unsigned defect=0; defect<5; ++defect) {
        auto candidate=ConfidentialDepositTransaction(consensus,key);
        auto& script=candidate.vout[1].scriptPubKey;
        if (defect==0 || defect==4) std::fill(script.begin()+43,script.end(),0xff);
        if (defect==1 || defect==4) WriteBE32(script.data()+39,UINT32_MAX);
        if (defect==2) WriteBE32(script.data()+39,1);
        if (defect==3 || defect==4) candidate.witness.vtxoutwit.clear();
        const std::string expected=defect==3 ?
            "ECX deposit does not match the confidential collateral vault profile" :
            "ECX deposit marker has an invalid trader or referenced vout";
        uint64_t forced{99},deposits{99};
        BOOST_CHECK(!ecx::CountSourceTransactionMarkers(CTransaction{candidate},forced,deposits,reason,consensus));
        BOOST_CHECK_EQUAL(reason,expected);
        BOOST_CHECK_EQUAL(forced,0U);
        BOOST_CHECK_EQUAL(deposits,0U);
    }
    for (bool forced_first : {false,true}) {
        auto combined=ConfidentialDepositTransaction(consensus,key);
        combined.vout.push_back(canonical.vout[0]);
        combined.witness.vtxoutwit.resize(3);
        if (forced_first) std::swap(combined.vout[1],combined.vout[2]);
        for (unsigned duplicate_kind=0; duplicate_kind<3; ++duplicate_kind) {
            auto candidate=combined;
            if (duplicate_kind) {
                candidate.vout.push_back(combined.vout[duplicate_kind]);
                candidate.witness.vtxoutwit.resize(4);
            }
            uint64_t forced{99},deposits{99};
            BOOST_CHECK_EQUAL(ecx::CountSourceTransactionMarkers(CTransaction{candidate},forced,deposits,reason,consensus),
                duplicate_kind==0);
            BOOST_CHECK_EQUAL(forced,duplicate_kind==0 ? 1U : 0U);
            BOOST_CHECK_EQUAL(deposits,duplicate_kind==0 ? 1U : 0U);
            BOOST_CHECK_EQUAL(reason.empty(),duplicate_kind==0);
        }
        BOOST_CHECK(!ecx::CheckSourceTransactionPolicy(CTransaction{combined},9,reason,consensus));
    }
}

BOOST_AUTO_TEST_CASE(ecx_drivechain_pegout_is_standard_without_pak)
{
    const ecx::ExchangeConsensus consensus{
        ConfiguredConsensus(10, COutPoint{Txid::FromUint256(uint256S("11")), 0}, uint256S("22"))};
    CScript pegout_data = CScript() << OP_RETURN;
    const uint256 parent_genesis = Params().ParentGenesisBlockHash();
    pegout_data << std::vector<unsigned char>(parent_genesis.begin(), parent_genesis.end());
    pegout_data << std::vector<unsigned char>(64, 0x51);
    CMutableTransaction tx;
    tx.vout.emplace_back(
        Params().GetConsensus().pegged_asset,
        25'000,
        pegout_data);
    std::string reason;
    BOOST_REQUIRE_GT(tx.vout[0].scriptPubKey.size(), MAX_OP_RETURN_RELAY);
    BOOST_CHECK(!IsStandardTx(
        CTransaction{tx}, MAX_OP_RETURN_RELAY, true, CFeeRate(DUST_RELAY_TX_FEE_BITCOIN), reason));
    BOOST_CHECK(IsStandardTx(
        CTransaction{tx}, MAX_OP_RETURN_RELAY, true, CFeeRate(DUST_RELAY_TX_FEE_BITCOIN), reason,
        &consensus));
}

BOOST_AUTO_TEST_CASE(haskell_forced_body_matches_native_encoding_rules)
{
    const std::array<unsigned char, 32> chain{};
    const std::array<unsigned char, 16> market{'E','C','X','-','U','S','D','D','-','P','E','R','P',0,0,0};
    const auto reference = [&](unsigned kind, const std::vector<unsigned char>& b) {
        const size_t size = kind == 0 ? 201 : kind == 1 ? 208 : kind == 2 ? 193 : 0;
        if (!size || b.size() != size || b[0] != 1) return 1;
        if (!std::equal(chain.begin(), chain.end(), b.begin()+1)) return 2;
        const bool matches = std::equal(market.begin(), market.end(), b.begin()+33);
        if (kind == 0) return matches && ReadBE64(b.data()+129) >= ReadBE64(b.data()+121) ? 0 : 3;
        if (kind == 1) return matches && b[81] <= 1 && b[82] == 1 && b[83] == 1 &&
            ReadBE64(b.data()+84) && ReadBE64(b.data()+92) && ReadBE64(b.data()+92) <= INT64_MAX &&
            ReadBE32(b.data()+116) <= 10000 && ReadBE64(b.data()+136) >= ReadBE64(b.data()+128) ? 0 : 4;
        return ReadBE64(b.data()+73) && ReadBE64(b.data()+121) >= ReadBE64(b.data()+113) ? 0 : 5;
    };
    for (unsigned kind = 0; kind < 3; ++kind) {
        std::vector<unsigned char> base(kind == 0 ? 201 : kind == 1 ? 208 : 193, 0);
        base[0] = 1;
        std::copy(market.begin(), market.end(), base.begin()+33);
        if (kind == 1) { base[82] = base[83] = base[91] = base[99] = 1; }
        if (kind == 2) base[80] = 1;
        BOOST_REQUIRE_EQUAL(reference(kind, base), 0);
        for (size_t i = 0; i < base.size(); ++i) for (unsigned byte = 0; byte < 256; ++byte) {
            auto body = base;
            body[i] = byte;
            BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeForcedBody(kind, body, chain, market), reference(kind, body));
        }
        for (unsigned candidate = 0; candidate < 5; ++candidate) for (unsigned size = 0; size < 212; ++size) {
            auto body = base;
            body.resize(size);
            BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeForcedBody(candidate, body, chain, market), reference(candidate, body));
        }
    }
}

BOOST_AUTO_TEST_CASE(haskell_tranche_matches_native_partial_work)
{
    for (unsigned sample = 0; sample < 4096; ++sample) {
        std::vector<uint8_t> kinds(sample % 130, sample % 3);
        if (!kinds.empty() && sample % 4) kinds[(sample / 3) % kinds.size()] = (sample / 7) % 256;
        uint32_t order_work{999}, actual_work{999};
        std::string error{"stale"}, actual_error{"stale"};
        const auto reference = [&]() -> bool {
    order_work = 0;
    error.clear();
    for (const uint8_t kind : kinds) {
        uint32_t action_work{0};
        switch (kind) {
        case 0:
            action_work = 1;
            break;
        case 1:
            action_work = ecx::MAX_FORCED_TRANCHE_ORDER_WORK;
            break;
        case 2:
            break;
        default:
            error = "unknown ECX forced-action kind";
            return false;
        }
        if (action_work > ecx::MAX_FORCED_TRANCHE_ORDER_WORK - order_work) {
            error = "parent-height tranche exceeds the 64-operation budget";
            return false;
        }
        order_work += action_work;
    }
    return true;
        };
        const bool expected = reference();
        const bool actual = ecx::ComputeForcedTrancheOrderWork(kinds, actual_work, actual_error);
        BOOST_CHECK_EQUAL(actual, expected);
        BOOST_CHECK_EQUAL(actual_work, order_work);
        BOOST_CHECK_EQUAL(actual_error, error);
    }
}

BOOST_AUTO_TEST_CASE(exchange_endian_readers_match_legacy_loops)
{
    uint64_t seed{0x656378};
    for (unsigned sample = 0; sample < 2048; ++sample) {
        std::array<unsigned char, 16> bytes{};
        for (auto& byte : bytes) {
            seed = seed * 6364136223846793005ULL + 1;
            byte = seed >> 32;
        }
        const auto preserved = bytes;
        for (unsigned offset = 0; offset < 8; ++offset) {
            uint64_t big{0}, little{0};
            uint32_t big32{0};
            for (unsigned index = 0; index < 8; ++index) {
                big = (big << 8) | bytes[offset+index];
                little |= uint64_t{bytes[offset+index]} << (8*index);
                if (index < 4) big32 = (big32 << 8) | bytes[offset+index];
            }
            BOOST_CHECK_EQUAL(ReadBE64(bytes.data()+offset), big);
            BOOST_CHECK_EQUAL(ReadBE32(bytes.data()+offset), big32);
            BOOST_CHECK_EQUAL(ReadLE64(bytes.data()+offset), little);
            BOOST_CHECK_EQUAL(ReadLE32(bytes.data()+offset), uint32_t(little));
            BOOST_CHECK_EQUAL(ReadLE16(bytes.data()+offset), uint16_t(little));
        }
        BOOST_CHECK(bytes == preserved);
    }
}

BOOST_AUTO_TEST_CASE(haskell_configuration_preserves_precedence_and_disabled_error)
{
    const std::array<std::string, 3> errors{
        "ECX genesis state outpoint collides with a reserved chainstate record",
        "ECX activation parameters are incomplete",
        "ECX collateral vault script hash does not match its frozen bytes"};
    for (unsigned mask = 0; mask < (1U << 14); ++mask) {
        unsigned first{0}, reads{0};
        while (first < 14 && (mask & (1U << first))) ++first;
        std::string error{"unchanged"};
        const bool result = drivechain::haskell::ExchangeConfiguration([&](uint32_t step) {
            BOOST_CHECK_EQUAL(step, reads++);
            return (mask & (1U << step)) != 0;
        }, error);
        BOOST_CHECK_EQUAL(result, first == 14);
        BOOST_CHECK_EQUAL(reads, std::min(14U, first+1));
        BOOST_CHECK_EQUAL(error, first == 0 || first == 14 ? "unchanged" : errors[first < 4 ? 0 : first < 13 ? 1 : 2]);
    }
    for (unsigned failed = 0; failed < 14; ++failed) {
        unsigned reads{0};
        std::string error{"unchanged"};
        BOOST_CHECK_EXCEPTION(drivechain::haskell::ExchangeConfiguration([&](uint32_t step) {
            ++reads;
            if (step == failed) throw std::runtime_error("configuration read");
            return true;
        }, error), std::runtime_error, [](const std::runtime_error& e) { return std::string(e.what()) == "configuration read"; });
        BOOST_CHECK_EQUAL(reads, failed+1);
        BOOST_CHECK_EQUAL(error, "unchanged");
    }
}

BOOST_AUTO_TEST_CASE(haskell_inbox_derivation_preserves_partial_appends)
{
    namespace hs = drivechain::haskell;
    for (uint64_t forced : {uint64_t{0},UINT64_MAX-1,UINT64_MAX})
    for (uint64_t deposits : {uint64_t{0},UINT64_MAX-1,UINT64_MAX})
    for (bool parent : {false,true})
    for (unsigned kind : {0U,1U,2U,3U}) {
        uint64_t forced_effects{0}, deposit_effects{0}, published_f{99}, published_d{99};
        unsigned parent_reads{0};
        std::string error{"unchanged"};
        const bool accepted = hs::ExchangeDeriveInbox(2,forced,deposits,
            [&](uint32_t step, uint64_t a, uint64_t b) -> int64_t {
            switch (step) {
            case 1: return 1;
            case 2:
            case 4: return 2;
            case 3:
            case 5: return 1;
            case 6: ++parent_reads; error = "parent error"; return parent;
            case 7: error.clear(); return kind;
            case 8: ++forced_effects; return 1;
            case 9: ++deposit_effects; return 1;
            case 10: published_f = a; published_d = b; return 1;
            default: throw std::logic_error("unexpected inbox action");
            }
        },error);
        uint64_t wanted_f{0}, wanted_d{0};
        std::string expected_error{"parent error"};
        bool expected{false};
        if (parent) {
            unsigned work{0};
            expected = true;
            for (unsigned tx = 0; tx < 2; ++tx) {
                if (forced + wanted_f == UINT64_MAX) {
                    expected_error = "ECX forced inbox index overflow"; expected = false; break;
                }
                expected_error.clear();
                if (kind > 2 || work + (kind == 0 ? 1 : kind == 1 ? 64 : 0) > 64) {
                    expected_error = std::string("ECX forced-action source tranche is overweight: ") +
                        (kind > 2 ? "unknown ECX forced-action kind" : "parent-height tranche exceeds the 64-operation budget");
                    expected = false; break;
                }
                work += kind == 0 ? 1 : kind == 1 ? 64 : 0;
                ++wanted_f;
                if (deposits + wanted_d == UINT64_MAX) {
                    expected_error = "ECX deposit inbox index overflow"; expected = false; break;
                }
                ++wanted_d;
            }
        }
        BOOST_CHECK_EQUAL(accepted,expected);
        BOOST_CHECK_EQUAL(error,expected_error);
        BOOST_CHECK_EQUAL(forced_effects,wanted_f);
        BOOST_CHECK_EQUAL(deposit_effects,wanted_d);
        BOOST_CHECK_EQUAL(published_f,expected ? wanted_f : 99U);
        BOOST_CHECK_EQUAL(published_d,expected ? wanted_d : 99U);
        BOOST_CHECK_EQUAL(parent_reads,1U);
    }
}

BOOST_AUTO_TEST_CASE(haskell_inbox_derivation_guards_callbacks)
{
    namespace hs = drivechain::haskell;
    for (unsigned fault = 1; fault <= 10; ++fault) for (bool exception : {false,true}) {
        std::vector<unsigned> seen;
        std::string error{"unchanged"};
        const auto run = [&] {
            return hs::ExchangeDeriveInbox(1,0,0,[&](uint32_t step, uint64_t, uint64_t) -> int64_t {
                seen.push_back(step);
                if (step == fault) {
                    if (exception) throw std::logic_error("inbox callback sentinel");
                    return -1;
                }
                if (step == 2 || step == 4) return 2;
                return step == 7 ? 0 : 1;
            },error);
        };
        if (exception) BOOST_CHECK_EXCEPTION(run(),std::logic_error,[](const auto& e) {
            return std::string(e.what()) == "inbox callback sentinel";
        });
        else BOOST_CHECK_THROW(run(),std::runtime_error);
        BOOST_CHECK_EQUAL(seen.back(),fault);
        BOOST_CHECK_EQUAL(seen.size(),fault);
        BOOST_CHECK_EQUAL(error,"unchanged");
    }
    std::string error{"unchanged"};
    unsigned calls{0};
    BOOST_CHECK(hs::ExchangeDeriveInbox(0,UINT64_MAX,UINT64_MAX,[&](uint32_t step, uint64_t forced, uint64_t deposits) {
        ++calls; BOOST_CHECK_EQUAL(step,10U); BOOST_CHECK_EQUAL(forced,0U); BOOST_CHECK_EQUAL(deposits,0U); return 1;
    },error));
    BOOST_CHECK_EQUAL(calls,1U);
    BOOST_CHECK_EQUAL(error,"unchanged");
}

BOOST_AUTO_TEST_CASE(haskell_state_transition_preserves_partial_publication)
{
    namespace hs = drivechain::haskell;
    for (bool carry : {false,true}) for (bool authority : {false,true}) for (bool chained : {false,true}) {
        unsigned state{0}, authority_calls{0};
        std::string error{"unchanged"};
        const bool accepted = hs::ExchangeTransition(3,[&](uint32_t step, uint64_t index) -> uint64_t {
            if (step == 1) return !carry && index == 1;
            if (step == 2) { state = 1; return 1; }
            BOOST_CHECK_EQUAL(index,step == 8 ? 2U : 1U);
            if (step == 6) {
                ++authority_calls;
                BOOST_CHECK_EQUAL(hs::ExchangeAuthority(true,[](uint32_t) { return true; }),0);
                if (!authority) error = "authority rejected";
                return authority;
            }
            if (step == 7) state = 2;
            return step == 8 ? chained : 1;
        },error);
        BOOST_CHECK_EQUAL(accepted,carry || (authority && !chained));
        BOOST_CHECK_EQUAL(authority_calls,carry ? 0U : 1U);
        BOOST_CHECK_EQUAL(state,carry ? 1U : authority ? 2U : 0U);
        BOOST_CHECK_EQUAL(error,accepted ? "unchanged" : !authority ? "authority rejected" :
            "a block may contain at most one ECX state transition");
    }
    for (uint32_t fault = 1; fault <= 8; ++fault) for (bool exception : {false,true}) {
        unsigned state{0};
        std::vector<uint32_t> seen;
        std::string error{"unchanged"};
        const auto run = [&] {
            return hs::ExchangeTransition(3,[&](uint32_t step, uint64_t index) -> uint64_t {
                seen.push_back(step);
                if (step == 2) state = 1;
                if (step == 7) state = 2;
                if (step == fault) {
                    if (exception) throw std::logic_error("transition callback sentinel");
                    return step == 1 || step == 8 ? UINT64_MAX : 2;
                }
                if (step == 1) return fault != 2 && index == 1;
                return step == 8 ? 0 : 1;
            },error);
        };
        if (exception) BOOST_CHECK_EXCEPTION(run(),std::logic_error,[](const auto& e) {
            return std::string(e.what()) == "transition callback sentinel";
        });
        else if (fault == 1 || fault == 8) BOOST_CHECK(!run());
        else BOOST_CHECK_THROW(run(),std::runtime_error);
        BOOST_REQUIRE(!seen.empty());
        BOOST_CHECK_EQUAL(seen.back(),fault);
        BOOST_CHECK_EQUAL(state,fault == 2 ? 1U : fault >= 7 ? 2U : 0U);
        BOOST_CHECK_EQUAL(error,exception || (fault != 1 && fault != 8) ? "unchanged" :
            fault == 1 ? "more than one transaction spends the ECX singleton" :
            "a block may contain at most one ECX state transition");
    }
}

BOOST_AUTO_TEST_CASE(haskell_cursor_derivation_preserves_outputs_and_callback_failures)
{
    namespace hs = drivechain::haskell;
    for (uint32_t fault = 0; fault <= 4; ++fault)
    for (int32_t bad : {-1, 3, std::numeric_limits<int32_t>::min(), std::numeric_limits<int32_t>::max()})
    for (bool exception : {false,true}) {
        std::vector<uint32_t> seen;
        std::string error{"unchanged"};
        uint64_t forced{42}, deposit{43};
        const auto run = [&] {
            return hs::ExchangeDeriveCursors(1,1,UINT64_MAX-1,UINT64_MAX,
                [&](uint32_t step, uint64_t tx, uint64_t index, uint64_t* fields) {
                seen.push_back(step);
                BOOST_CHECK_EQUAL(tx,0U);
                BOOST_CHECK_EQUAL(index,0U);
                if (step == fault) {
                    if (exception) throw std::logic_error("cursor callback sentinel");
                    return bad;
                }
                if (step == 1) fields[0] = 1;
                if (step == 2) { fields[0] = UINT64_MAX-1; fields[1] = UINT64_MAX; }
                return step == 2 ? 2 : 1;
            },forced,deposit,error);
        };
        if (!fault) BOOST_CHECK(run());
        else if (exception) BOOST_CHECK_EXCEPTION(run(),std::logic_error,[](const auto& e) {
            return std::string(e.what()) == "cursor callback sentinel";
        });
        else BOOST_CHECK_THROW(run(),std::runtime_error);
        BOOST_CHECK_EQUAL(seen.size(),fault ? fault : 4U);
        BOOST_CHECK_EQUAL(forced,fault ? 42U : UINT64_MAX-1);
        BOOST_CHECK_EQUAL(deposit,fault ? 43U : UINT64_MAX);
        BOOST_CHECK_EQUAL(error,"unchanged");
    }
    std::string error{"native parser error"};
    uint64_t forced{42}, deposit{43};
    BOOST_CHECK(!hs::ExchangeDeriveCursors(1,1,0,0,
        [](uint32_t step, uint64_t, uint64_t, uint64_t* fields) {
            fields[0] = 1; return step == 2 ? 0 : 1;
        },forced,deposit,error));
    BOOST_CHECK_EQUAL(error,"native parser error");
    BOOST_CHECK_EQUAL(forced,42U);
    BOOST_CHECK_EQUAL(deposit,43U);
    unsigned calls{0};
    const auto unread = [&](uint32_t, uint64_t, uint64_t, uint64_t*) { ++calls; return -1; };
    BOOST_CHECK_THROW(hs::ExchangeDeriveCursors(UINT64_MAX,4,0,0,unread,forced,deposit,error),std::runtime_error);
    BOOST_CHECK_EQUAL(calls,0U);
    BOOST_CHECK(hs::ExchangeDeriveCursors(0,0,UINT64_MAX,UINT64_MAX,unread,forced,deposit,error));
    BOOST_CHECK_EQUAL(calls,0U);
    BOOST_CHECK_EQUAL(forced,UINT64_MAX);
    BOOST_CHECK_EQUAL(deposit,UINT64_MAX);
}

BOOST_AUTO_TEST_CASE(haskell_source_marker_sequences_match_boolean_policy)
{
    namespace hs = drivechain::haskell;
    const std::array<std::string, 3> errors{
        "an Elements transaction may contain only one ECX forced action",
        "an Elements transaction may contain only one ECX deposit marker",
        "ECX source transaction is premature before exchange activation"};
    for (unsigned inputs = 0; inputs < 4096; ++inputs) for (bool active : {false,true}) {
        bool forced{false}, deposit{false}, rejected{false};
        uint32_t seen{0};
        std::string error{"unchanged"};
        for (unsigned index = 0; index < 6 && !rejected; ++index) for (unsigned kind = 0; kind < 2; ++kind) {
            const bool present = (inputs & (1U << (index*2+kind))) != 0;
            bool& old = kind == 0 ? forced : deposit;
            const bool duplicate = present && old;
            const bool accepted = hs::ExchangeSourceMarker(seen, static_cast<hs::SourceMarker>(kind), present, error);
            if (!duplicate && present) old = true;
            BOOST_CHECK_EQUAL(accepted, !duplicate);
            BOOST_CHECK_EQUAL(seen, unsigned(forced) + 2*unsigned(deposit));
            BOOST_CHECK_EQUAL(error, duplicate ? errors[kind] : "unchanged");
            if (duplicate) { rejected = true; break; }
        }
        if (!rejected) {
            const bool expected = active || (!forced && !deposit);
            BOOST_CHECK_EQUAL(hs::ExchangeSourceMarker(seen, hs::SourceMarker::ACTIVATION, active, error), expected);
            BOOST_CHECK_EQUAL(seen, unsigned(forced) + 2*unsigned(deposit));
            BOOST_CHECK_EQUAL(error, expected ? "unchanged" : errors[2]);
        }
    }
    uint32_t invalid{4};
    std::string error{"unchanged"};
    BOOST_CHECK_THROW(hs::ExchangeSourceMarker(invalid, hs::SourceMarker::FORCED, true, error), std::runtime_error);
    BOOST_CHECK_EQUAL(invalid, 4U);
    BOOST_CHECK_EQUAL(error, "unchanged");
}

BOOST_AUTO_TEST_CASE(prior_commitment_accessors_preserve_outputs_and_errors)
{
    using Getter = bool (*)(const CBlockIndex*, uint256&, std::string&);
    const std::array<Getter, 3> getters{ecx::GetPriorActiveExchangeStateRoot,
        ecx::GetPriorActiveForcedInboxRoot, ecx::GetPriorActiveDepositInboxRoot};
    const std::array<uint256 CBlockIndex::*, 3> members{&CBlockIndex::hashExchangeStateRoot,
        &CBlockIndex::hashForcedInboxRoot, &CBlockIndex::hashDepositInboxRoot};
    const std::array<uint32_t, 4> masks{CBlockHeader::EXCHANGE_STATE_HF_MASK,
        CBlockHeader::FORCED_INBOX_HF_MASK, CBlockHeader::DEPOSIT_INBOX_HF_MASK, CBlockHeader::INBOX_CURSOR_HF_MASK};
    const std::array<std::string, 3> errors{"prior-active ECX state root is unavailable",
        "prior-active ECX forced inbox root is unavailable", "prior-active ECX deposit inbox root is unavailable"};
    for (bool present : {false,true}) for (unsigned signals = 0; signals < 16; ++signals)
    for (unsigned roots = 0; roots < 8; ++roots) {
        CBlockIndex previous;
        previous.nVersion = 0;
        for (unsigned bit = 0; bit < 4; ++bit) if (signals & (1U << bit)) previous.nVersion |= masks[bit];
        for (unsigned bit = 0; bit < 3; ++bit) if (roots & (1U << bit)) previous.*members[bit] = uint256S("12");
        previous.forcedProcessedCursor = 123;
        previous.depositProcessedCursor = 456;
        for (unsigned kind = 0; kind < 3; ++kind) {
            uint256 result = uint256S("99");
            std::string error{"stale"};
            const bool expected = present && (signals & (1U << kind)) && (roots & (1U << kind));
            BOOST_CHECK_EQUAL(getters[kind](present ? &previous : nullptr, result, error), expected);
            BOOST_CHECK(result == (expected ? uint256S("12") : uint256{}));
            BOOST_CHECK_EQUAL(error, expected ? "" : errors[kind]);
        }
        uint64_t forced{99}, deposit{99};
        std::string error{"stale"};
        const bool expected = present && (signals & 8);
        BOOST_CHECK_EQUAL(ecx::GetPriorActiveInboxCursors(present ? &previous : nullptr, forced, deposit, error), expected);
        BOOST_CHECK_EQUAL(forced, expected ? 123U : 0U);
        BOOST_CHECK_EQUAL(deposit, expected ? 456U : 0U);
        BOOST_CHECK_EQUAL(error, expected ? "" : "prior active block has no ECX processed-cursor commitment");
    }
}

BOOST_AUTO_TEST_CASE(haskell_disconnect_activation_routing)
{
    namespace hs = drivechain::haskell;
    for (bool activation : {false,true}) {
        for (bool removed : {false,true}) {
            std::vector<uint32_t> seen;
            const auto status=hs::ParentReplayStore(hs::ReplayStoreFlow::DISCONNECT_PREFLIGHT,
                [&](uint32_t step) -> uint32_t {
                    seen.push_back(step);
                    if (step==15) return activation;
                    if (step==16) return removed;
                    return true;
                });
            std::vector<uint32_t> expected{1,2,3,4,6,7,8,10,11,12,13,15};
            if (activation) expected.push_back(16);
            BOOST_CHECK(seen==expected);
            BOOST_CHECK_EQUAL(status,activation ? unsigned(removed) : 2U);
        }
    }
}

BOOST_AUTO_TEST_CASE(haskell_disconnect_preserves_partial_effects)
{
    namespace hs = drivechain::haskell;
    const std::array<unsigned, 4> sizes{7,4,3,2};
    const std::array<std::string, 6> errors{
        "prior ECX header state is unavailable during disconnect",
        "prior ECX inbox header state is unavailable during disconnect",
        "ECX inbox undo does not reproduce the disconnected header state",
        "ECX activation tracker could not be removed",
        "ECX activation inbox trackers could not be removed",
        "ECX inbox count underflow during disconnect"};
    for (unsigned phase = 0; phase < sizes.size(); ++phase)
    for (unsigned failed = 0; failed <= sizes[phase]; ++failed)
    for (bool throws : {false,true}) {
        unsigned calls{0}, effects{0};
        bool caught{false}, accepted{false};
        std::string error{"unchanged"};
        try {
            accepted = hs::ExchangeDisconnect(static_cast<hs::DisconnectPhase>(phase), [&](uint32_t step) {
                BOOST_CHECK_EQUAL(step, calls++);
                if (step == failed) {
                    if (throws) throw std::runtime_error("disconnect action");
                    return false;
                }
                ++effects;
                return true;
            }, error);
        } catch (const std::runtime_error& e) {
            caught = true;
            BOOST_CHECK_EQUAL(e.what(), "disconnect action");
        }
        const unsigned code = phase == 0 ? (failed < 3 ? 1 : 2) : phase == 1 ? 3 :
            phase == 2 ? (failed == 0 ? 4 : 5) : 6;
        BOOST_CHECK_EQUAL(calls, std::min(sizes[phase], failed+1));
        BOOST_CHECK_EQUAL(effects, std::min(sizes[phase], failed));
        BOOST_CHECK_EQUAL(caught, throws && failed < sizes[phase]);
        if (!caught) BOOST_CHECK_EQUAL(accepted, failed == sizes[phase]);
        BOOST_CHECK_EQUAL(error, caught || accepted ? "unchanged" : errors[code-1]);
    }
    unsigned calls{0};
    std::string error{"unchanged"};
    BOOST_CHECK_THROW(hs::ExchangeDisconnect(static_cast<hs::DisconnectPhase>(4), [&](uint32_t) {
        ++calls; return true;
    }, error), std::runtime_error);
    BOOST_CHECK_EQUAL(calls, 0U);
    BOOST_CHECK_EQUAL(error, "unchanged");
}

BOOST_AUTO_TEST_CASE(haskell_connection_preserves_precedence_and_exceptions)
{
    for (bool activation : {false,true}) {
        const unsigned count = activation ? 9 : 6;
        for (unsigned mask = 0; mask < (1U << 9); ++mask) {
            unsigned first{0}, reads{0};
            while (first < count && (mask & (1U << first))) ++first;
            std::string error{"unchanged"};
            const bool accepted = drivechain::haskell::ExchangeConnection(activation, [&](uint32_t step) {
                BOOST_CHECK_EQUAL(step, reads++);
                return (mask & (1U << step)) != 0;
            }, error);
            BOOST_CHECK_EQUAL(accepted, first == count);
            BOOST_CHECK_EQUAL(reads, std::min(count, first+1));
            BOOST_CHECK_EQUAL(error, accepted ? "unchanged" : first < 6 ?
                "ECX header roots do not match deterministic singleton and inbox derivation" :
                "ECX activation cannot overwrite a reserved chainstate outpoint");
        }
        for (unsigned failed = 0; failed < count; ++failed) {
            unsigned reads{0};
            std::string error{"unchanged"};
            BOOST_CHECK_EXCEPTION(drivechain::haskell::ExchangeConnection(activation, [&](uint32_t step) {
                ++reads;
                if (step == failed) throw std::runtime_error("connection reader");
                return true;
            }, error), std::runtime_error, [](const std::runtime_error& e) {
                return std::string(e.what()) == "connection reader";
            });
            BOOST_CHECK_EQUAL(reads, failed+1);
            BOOST_CHECK_EQUAL(error, "unchanged");
        }
    }
}

BOOST_AUTO_TEST_CASE(haskell_parent_target_bounds_lazy_reads_and_exceptions)
{
    namespace hs = drivechain::haskell;
    for (bool supplied : {false,true}) for (bool test : {false,true})
    for (uint64_t value : {uint64_t{0}, uint64_t{1}, uint64_t{4294967294},
                          uint64_t{4294967295}, uint64_t{4294967296}, UINT64_MAX}) {
        std::optional<uint64_t> height = supplied ? std::make_optional(value) : std::nullopt;
        const auto original = height;
        unsigned reads{0};
        std::string error{"unchanged"};
        const bool result = hs::ExchangeParentTarget(height, [&](uint32_t step) -> uint64_t {
            BOOST_CHECK_EQUAL(step, reads++);
            return step == 0 ? test : value;
        }, error);
        const bool missing = !supplied && !test;
        const bool valid = !missing && (supplied ? value > 0 && value <= UINT32_MAX : value < UINT32_MAX);
        BOOST_CHECK_EQUAL(result, valid);
        BOOST_CHECK_EQUAL(reads, supplied ? 0U : test ? 2U : 1U);
        BOOST_CHECK(height == (valid ? std::make_optional(supplied ? value : value+1) : original));
        BOOST_CHECK_EQUAL(error, valid ? "unchanged" : missing ?
            "ECX block assembly requires an authenticated target parent height" :
            "ECX target parent height is outside the committed 32-bit range");
    }
    for (unsigned failed : {0U,1U}) {
        std::optional<uint64_t> height;
        std::string error{"unchanged"};
        unsigned reads{0};
        BOOST_CHECK_EXCEPTION(hs::ExchangeParentTarget(height, [&](uint32_t step) -> uint64_t {
            ++reads;
            if (step == failed) throw std::runtime_error("parent target reader");
            return 1;
        }, error), std::runtime_error, [](const std::runtime_error& e) {
            return std::string(e.what()) == "parent target reader";
        });
        BOOST_CHECK_EQUAL(reads, failed+1);
        BOOST_CHECK(!height);
        BOOST_CHECK_EQUAL(error, "unchanged");
    }
}

BOOST_AUTO_TEST_CASE(haskell_header_phase_order_and_exceptions)
{
    namespace hs = drivechain::haskell;
    const std::array<unsigned, 3> sizes{11,8,6};
    const std::array<std::string, 3> errors{
        "ECX header extensions are forbidden before activation",
        "all ECX header extensions are required and nonzero after activation",
        "ECX activation header does not commit the frozen genesis roots"};
    for (unsigned phase = 0; phase < 3; ++phase) for (unsigned failed = 0; failed <= sizes[phase]; ++failed)
    for (bool throws : {false,true}) {
        unsigned reads{0};
        bool caught{false}, accepted{false};
        std::string error{"unchanged"};
        try {
            accepted = hs::ExchangeHeader(static_cast<hs::HeaderPhase>(phase), [&](uint32_t step) {
                BOOST_CHECK_EQUAL(step, reads++);
                BOOST_CHECK(hs::ExchangeDistinct(std::array<const unsigned char*,0>{}));
                if (step == failed && throws) throw std::runtime_error("header reader failure");
                return step != failed;
            }, error);
        } catch (const std::runtime_error& e) {
            caught = true;
            BOOST_CHECK_EQUAL(e.what(), "header reader failure");
        }
        BOOST_CHECK_EQUAL(reads, std::min(sizes[phase], failed+1));
        BOOST_CHECK_EQUAL(caught, throws && failed < sizes[phase]);
        if (!caught) BOOST_CHECK_EQUAL(accepted, failed == sizes[phase]);
        BOOST_CHECK_EQUAL(error, caught || accepted ? "unchanged" : errors[phase]);
    }
    unsigned reads{0};
    std::string error{"unchanged"};
    BOOST_CHECK_THROW(hs::ExchangeHeader(static_cast<hs::HeaderPhase>(3), [&](uint32_t) {
        ++reads; return true;
    }, error), std::runtime_error);
    BOOST_CHECK_EQUAL(reads, 0U);
    BOOST_CHECK_EQUAL(error, "unchanged");
}

BOOST_AUTO_TEST_CASE(haskell_tracker_phase_order_and_exceptions)
{
    namespace hs = drivechain::haskell;
    const std::array<unsigned, 3> sizes{5,7,3};
    for (unsigned phase = 0; phase < 3; ++phase) for (unsigned failed = 0; failed <= sizes[phase]; ++failed)
    for (bool throws : {false,true}) {
        unsigned reads{0};
        bool caught{false};
        uint32_t status{99};
        try {
            status = hs::ExchangeTracker(static_cast<hs::TrackerPhase>(phase), [&](uint32_t step) {
                BOOST_CHECK_EQUAL(step, reads++);
                if (step == failed && throws) throw std::runtime_error("tracker reader failure");
                return step != failed;
            });
        } catch (const std::runtime_error& e) {
            caught = true;
            BOOST_CHECK_EQUAL(e.what(), "tracker reader failure");
        }
        BOOST_CHECK_EQUAL(reads, std::min(sizes[phase], failed+1));
        BOOST_CHECK_EQUAL(caught, throws && failed < sizes[phase]);
        if (!caught) BOOST_CHECK_EQUAL(status, failed == sizes[phase] ? 0U : phase == 0 && failed == 0 ? 2U : 1U);
    }
    unsigned invalid_reads{0};
    BOOST_CHECK_THROW(hs::ExchangeTracker(static_cast<hs::TrackerPhase>(3), [&](uint32_t) {
        ++invalid_reads; return true;
    }), std::runtime_error);
    BOOST_CHECK_EQUAL(invalid_reads, 0U);
}

BOOST_AUTO_TEST_CASE(haskell_output_profile_read_order_and_exceptions)
{
    for (bool collateral : {false,true}) for (unsigned failed = 0; failed <= 7; ++failed)
    for (bool throws : {false,true}) {
        const unsigned size = collateral ? 7 : 6;
        unsigned reads{0};
        bool caught{false}, accepted{false};
        try {
            accepted = drivechain::haskell::ExchangeProfile(collateral, [&](uint32_t step) {
                BOOST_CHECK_EQUAL(step, reads++);
                if (step == failed && throws) throw std::runtime_error("profile reader failure");
                return step != failed;
            });
        } catch (const std::runtime_error& e) {
            caught = true;
            BOOST_CHECK_EQUAL(e.what(), "profile reader failure");
        }
        BOOST_CHECK_EQUAL(reads, std::min(size, failed+1));
        BOOST_CHECK_EQUAL(caught, throws && failed < size);
        if (!caught) BOOST_CHECK_EQUAL(accepted, failed >= size);
    }
}

BOOST_AUTO_TEST_CASE(haskell_authority_read_order_and_exception_boundary)
{
    for (bool successor : {false,true}) for (unsigned failed = 0; failed <= 8; ++failed)
    for (bool throws : {false,true}) {
        const std::vector<uint32_t> steps = successor ? std::vector<uint32_t>{0,1,2,3,4,5,6,7}
                                                     : std::vector<uint32_t>{0,1,2,5,6,7};
        const auto stop = std::find(steps.begin(), steps.end(), failed);
        const std::vector<uint32_t> expected(steps.begin(), stop == steps.end() ? stop : std::next(stop));
        std::vector<uint32_t> seen;
        bool caught{false};
        int result{-1};
        try {
            result = drivechain::haskell::ExchangeAuthority(successor, [&](uint32_t step) {
                seen.push_back(step);
                if (step == failed && throws) throw std::runtime_error("authority reader failure");
                return step != failed;
            });
        } catch (const std::runtime_error& e) {
            caught = true;
            BOOST_CHECK_EQUAL(e.what(), "authority reader failure");
        }
        BOOST_CHECK(seen == expected);
        BOOST_CHECK_EQUAL(caught, throws && stop != steps.end());
        if (!caught) {
            const std::array<int, 8> codes{1,1,1,2,3,4,4,4};
            BOOST_CHECK_EQUAL(result, stop == steps.end() ? 0 : codes[failed]);
        }
    }
}

BOOST_AUTO_TEST_CASE(haskell_processed_cursors_match_native_admission)
{
    const std::array<uint64_t, 6> edges{0,1,2,63,64,UINT64_MAX};
    for (uint32_t flags = 0; flags < 16; ++flags)
    for (auto pf : edges) for (auto pd : edges)
    for (auto mf : edges) for (auto md : edges) {
        const bool transitioned = flags & 1, found = flags & 2,
            empty_incremental_activation = flags & 4, same_transaction = flags & 8;
        const uint64_t previous_forced_cursor = pf, previous_deposit_cursor = pd,
            marker_forced = mf, marker_deposit = md;
        uint64_t next_forced_cursor{101}, next_deposit_cursor{102}, actual_f{101}, actual_d{102};
        std::string error{"unchanged"}, actual_error{"unchanged"};
        const auto reference = [&]() -> bool {
    if (transitioned && !found && empty_incremental_activation &&
        previous_forced_cursor == 0 && previous_deposit_cursor == 0) {
        next_forced_cursor = 0;
        next_deposit_cursor = 0;
        return true;
    }
    if (transitioned != found) {
        error = transitioned
            ? "ECX state transition is missing its processed-cursor marker"
            : "ECX processed-cursor marker requires a state transition";
        return false;
    }
    if (!transitioned) {
        next_forced_cursor = previous_forced_cursor;
        next_deposit_cursor = previous_deposit_cursor;
        return true;
    }
    if (!same_transaction ||
        marker_forced < previous_forced_cursor ||
        marker_deposit < previous_deposit_cursor) {
        error = "ECX processed cursors are not monotonic or are outside the state transition";
        return false;
    }
    next_forced_cursor = marker_forced;
    next_deposit_cursor = marker_deposit;
    return true;
        };
        const bool expected = reference();
        const std::array<uint64_t, 4> fields{pf,pd,mf,md};
        const bool actual = drivechain::haskell::ExchangeCursors(flags, fields, actual_f, actual_d, actual_error);
        BOOST_CHECK_EQUAL(actual, expected);
        BOOST_CHECK_EQUAL(actual_f, next_forced_cursor);
        BOOST_CHECK_EQUAL(actual_d, next_deposit_cursor);
        BOOST_CHECK_EQUAL(actual_error, error);
    }
}

BOOST_AUTO_TEST_CASE(haskell_inbox_liveness_matches_native_rules)
{
    using namespace ecx;
    uint64_t seed{0x74657374};
    const std::array<uint64_t, 16> edges{0,1,5,6,7,63,64,65,447,448,449,
        UINT64_MAX-7,UINT64_MAX-6,UINT64_MAX-5,UINT64_MAX-1,UINT64_MAX};
    for (unsigned trial = 0; trial < 20000; ++trial) {
        std::array<uint64_t, 12> fields{};
        for (auto& field : fields) {
            seed = seed * 6364136223846793005ULL + 1;
            field = trial % 3 ? edges[(seed >> 32) % edges.size()] : seed;
        }
        // Include valid cursors/backlogs as well as unconstrained simultaneous faults.
        if (trial % 2) for (unsigned i = 0; i < 8; i += 2) {
            fields[i] %= 70;
            fields[i+1] %= fields[i]+1;
        }
        struct Count { uint64_t count; };
        const Count previous_forced{fields[0]}, previous_deposits{fields[2]},
            next_forced{fields[4]}, next_deposits{fields[6]};
        const auto previous_forced_cursor = fields[1], previous_deposit_cursor = fields[3],
            next_forced_cursor = fields[5], next_deposit_cursor = fields[7],
            forced_appends = fields[8], deposit_appends = fields[9],
            previous_oldest_parent_height = fields[10], current_parent_height = fields[11];
        uint64_t next_oldest_parent_height{123456}, actual{123456};
        std::string error{"unchanged"}, actual_error{"unchanged"};
        const auto reference = [&]() -> bool {
    if (previous_forced_cursor > previous_forced.count ||
        previous_deposit_cursor > previous_deposits.count ||
        next_forced_cursor > next_forced.count ||
        next_deposit_cursor > next_deposits.count) {
        error = "ECX processed cursor exceeds its source entry count";
        return false;
    }
    if (forced_appends > MAX_COMBINED_SAME_PARENT_APPENDS ||
        deposit_appends > MAX_COMBINED_SAME_PARENT_APPENDS - forced_appends) {
        error = "ECX source appends exceed the combined same-parent limit";
        return false;
    }
    const uint64_t previous_forced_pending =
        previous_forced.count - previous_forced_cursor;
    const uint64_t previous_deposit_pending =
        previous_deposits.count - previous_deposit_cursor;
    if (previous_forced_pending > MAX_COMBINED_PENDING_WITNESS_ENTRIES ||
        previous_deposit_pending >
            MAX_COMBINED_PENDING_WITNESS_ENTRIES - previous_forced_pending ||
        forced_appends >
            MAX_COMBINED_PENDING_WITNESS_ENTRIES - previous_forced_pending - previous_deposit_pending ||
        deposit_appends >
            MAX_COMBINED_PENDING_WITNESS_ENTRIES - previous_forced_pending - previous_deposit_pending - forced_appends) {
        error = "ECX source suffix exceeds the maximum transition witness profile";
        return false;
    }
    const uint64_t next_forced_pending = next_forced.count - next_forced_cursor;
    const uint64_t next_deposit_pending = next_deposits.count - next_deposit_cursor;
    if (next_forced_pending > MAX_COMBINED_UNCONSUMED ||
        next_deposit_pending > MAX_COMBINED_UNCONSUMED - next_forced_pending) {
        error = "ECX combined unconsumed source backlog exceeds consensus bounds";
        return false;
    }
    const uint64_t previous_pending =
        previous_forced_pending + previous_deposit_pending;
    const uint64_t next_pending = next_forced_pending + next_deposit_pending;
    if (next_pending == 0) {
        next_oldest_parent_height = 0;
        return true;
    }
    if (current_parent_height == 0) {
        error = "ECX pending source backlog has no authenticated parent height";
        return false;
    }
    if (previous_pending == 0) {
        next_oldest_parent_height = current_parent_height;
    } else {
        if (previous_oldest_parent_height == 0 ||
            previous_oldest_parent_height > current_parent_height) {
            error = "ECX prior backlog age commitment is missing or invalid";
            return false;
        }
        next_oldest_parent_height = previous_oldest_parent_height;
    }
    if (next_oldest_parent_height >
            std::numeric_limits<uint64_t>::max() - FORCED_INCLUSION_BLOCKS ||
        current_parent_height >=
            next_oldest_parent_height + FORCED_INCLUSION_BLOCKS) {
        error = "ECX source backlog exceeded the forced-inclusion deadline";
        return false;
    }
    return true;

        };
        const bool expected = reference();
        const bool accepted = drivechain::haskell::ExchangeInbox(fields, actual, actual_error);
        BOOST_TEST_CONTEXT("trial " << trial) {
            BOOST_CHECK_EQUAL(accepted, expected);
            BOOST_CHECK_EQUAL(actual, next_oldest_parent_height);
            BOOST_CHECK_EQUAL(actual_error, error);
        }
    }
}

BOOST_AUTO_TEST_CASE(source_append_budget_is_chainstate_bounded)
{
    ecx::ExchangeConsensusSnapshot snapshot;
    snapshot.forced_entry_count = 40;
    snapshot.forced_processed_cursor = 10;
    snapshot.deposit_entry_count = 35;
    snapshot.deposit_processed_cursor = 5;
    uint64_t budget{0};
    std::string reason;
    BOOST_REQUIRE(ecx::ComputeSourceAppendBudget(snapshot, budget, reason));
    BOOST_CHECK_EQUAL(budget, 4U);

    snapshot.deposit_entry_count = 40;
    BOOST_CHECK(!ecx::ComputeSourceAppendBudget(snapshot, budget, reason));
    BOOST_CHECK_EQUAL(budget, 0U);

    snapshot = {};
    snapshot.forced_entry_count = 1;
    snapshot.forced_processed_cursor = 2;
    BOOST_CHECK(!ecx::ComputeSourceAppendBudget(snapshot, budget, reason));
    BOOST_CHECK_EQUAL(budget, 0U);

    snapshot = {};
    BOOST_REQUIRE(ecx::ComputeSourceAppendBudget(snapshot, budget, reason));
    BOOST_CHECK_EQUAL(budget, ecx::MAX_COMBINED_UNCONSUMED);
}

BOOST_AUTO_TEST_CASE(forced_action_source_tranches_are_resource_weighted)
{
    uint32_t work{0};
    std::string reason;
    BOOST_REQUIRE(ecx::ComputeForcedTrancheOrderWork(
        std::vector<uint8_t>(64, 0), work, reason));
    BOOST_CHECK_EQUAL(work, 64U);
    BOOST_CHECK(!ecx::ComputeForcedTrancheOrderWork(
        std::vector<uint8_t>(65, 0), work, reason));

    BOOST_REQUIRE(ecx::ComputeForcedTrancheOrderWork(
        {2, 1, 2}, work, reason));
    BOOST_CHECK_EQUAL(work, 64U);
    BOOST_CHECK(!ecx::ComputeForcedTrancheOrderWork(
        {1, 0}, work, reason));
    BOOST_CHECK(!ecx::ComputeForcedTrancheOrderWork(
        {1, 1}, work, reason));
    BOOST_CHECK(!ecx::ComputeForcedTrancheOrderWork(
        {0, 3}, work, reason));
    BOOST_CHECK_EQUAL(work, 1U);
}

BOOST_AUTO_TEST_CASE(state_utxo_root_matches_original_encoding)
{
    const auto consensus=ConfiguredConsensus(10,COutPoint{},uint256S("22"));
    auto large=AuthorityOutput(0x21);
    large.scriptPubKey=CScript{} << std::vector<unsigned char>(300,0x51);
    const auto confidential=ConfidentialDepositTransaction(consensus,TestTraderKey()).vout[0];
    for (const auto& output : {CTxOut{},AuthorityOutput(0x22),large,confidential}) {
        DataStream serialized;
        serialized << output;
        const auto digest=TestSha256({UCharCast(serialized.data()),UCharCast(serialized.data())+serialized.size()});
        for (uint32_t index : {0U,1U,255U,256U,0x12345678U,UINT32_MAX}) {
            for (unsigned char seed : {0,1,255}) {
                uint256 genesis,txid;
                std::fill(genesis.begin(),genesis.end(),seed);
                std::fill(txid.begin(),txid.end(),seed^0x5a);
                std::vector<unsigned char> expected(genesis.begin(),genesis.end());
                expected.insert(expected.end(),txid.begin(),txid.end());
                TestPushU32Le(expected,index);
                expected.insert(expected.end(),digest.begin(),digest.end());
                BOOST_CHECK_EQUAL(ecx::ComputeStateUtxoRoot(genesis,COutPoint{Txid::FromUint256(txid),index},output),
                    TestTaggedHash("ECX/header-state/v1",expected));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(header_extension_is_append_only_and_bmm_covered)
{
    CBlockHeader legacy;
    legacy.nVersion = 0x20000000 |
        CBlockHeader::WITHDRAWAL_BUNDLE_HF_MASK |
        CBlockHeader::BMM_PROOF_HF_MASK;
    legacy.hashPrevBlock = uint256S("01");
    legacy.hashMerkleRoot = uint256S("02");
    legacy.hashWithdrawalBundle = uint256S("03");
    legacy.hashBmmProof = uint256S("04");
    legacy.nTime = 5;
    legacy.nBits = 6;
    legacy.nNonce = 7;

    DataStream before;
    before << legacy;
    CBlockHeader extended{legacy};
    extended.nVersion |= CBlockHeader::EXCHANGE_STATE_HF_MASK;
    extended.hashExchangeStateRoot = uint256S("05");
    DataStream after;
    after << extended;

    BOOST_REQUIRE_EQUAL(after.size(), before.size() + 32);
    BOOST_CHECK(std::equal(before.begin() + 4, before.end(), after.begin() + 4));

    CBlockHeader source_extended{extended};
    source_extended.nVersion |= CBlockHeader::FORCED_INBOX_HF_MASK |
        CBlockHeader::DEPOSIT_INBOX_HF_MASK;
    source_extended.hashForcedInboxRoot = uint256S("06");
    source_extended.hashDepositInboxRoot = uint256S("07");
    source_extended.ecxParentHeight = 8;
    DataStream source_bytes;
    source_bytes << source_extended;
    BOOST_REQUIRE_EQUAL(source_bytes.size(), after.size() + 68);
    BOOST_CHECK(std::equal(after.begin() + 4, after.end(), source_bytes.begin() + 4));

    CBlockHeader cursor_extended{source_extended};
    cursor_extended.nVersion |= CBlockHeader::INBOX_CURSOR_HF_MASK;
    cursor_extended.forcedProcessedCursor = 9;
    cursor_extended.depositProcessedCursor = 10;
    cursor_extended.sourceBacklogOldestParentHeight = 11;
    DataStream cursor_bytes;
    cursor_bytes << cursor_extended;
    BOOST_REQUIRE_EQUAL(cursor_bytes.size(), source_bytes.size() + 24);
    BOOST_CHECK(std::equal(
        source_bytes.begin() + 4, source_bytes.end(), cursor_bytes.begin() + 4));

    const uint256 critical{source_extended.GetBmmCriticalHash()};
    CBlockHeader proof_mutation{source_extended};
    proof_mutation.hashBmmProof = uint256S("09");
    BOOST_CHECK_EQUAL(proof_mutation.GetBmmCriticalHash(), critical);
    CBlockHeader withdrawal_mutation{source_extended};
    withdrawal_mutation.hashWithdrawalBundle = uint256S("0a");
    BOOST_CHECK_NE(withdrawal_mutation.GetBmmCriticalHash(), critical);
    CBlockHeader state_mutation{source_extended};
    state_mutation.hashExchangeStateRoot = uint256S("0b");
    BOOST_CHECK_NE(state_mutation.GetBmmCriticalHash(), critical);
    CBlockHeader forced_mutation{source_extended};
    forced_mutation.hashForcedInboxRoot = uint256S("0c");
    BOOST_CHECK_NE(forced_mutation.GetBmmCriticalHash(), critical);
    CBlockHeader deposit_mutation{source_extended};
    deposit_mutation.hashDepositInboxRoot = uint256S("0d");
    BOOST_CHECK_NE(deposit_mutation.GetBmmCriticalHash(), critical);
    CBlockHeader height_mutation{source_extended};
    ++height_mutation.ecxParentHeight;
    BOOST_CHECK_NE(height_mutation.GetBmmCriticalHash(), critical);
    const uint256 cursor_critical{cursor_extended.GetBmmCriticalHash()};
    CBlockHeader cursor_mutation{cursor_extended};
    ++cursor_mutation.forcedProcessedCursor;
    BOOST_CHECK_NE(cursor_mutation.GetBmmCriticalHash(), cursor_critical);
    cursor_mutation = cursor_extended;
    ++cursor_mutation.depositProcessedCursor;
    BOOST_CHECK_NE(cursor_mutation.GetBmmCriticalHash(), cursor_critical);
    CBlockHeader age_mutation{cursor_extended};
    ++age_mutation.sourceBacklogOldestParentHeight;
    BOOST_CHECK_NE(age_mutation.GetBmmCriticalHash(), cursor_critical);

    CBlockHeader decoded;
    source_bytes >> decoded;
    BOOST_CHECK(source_bytes.empty());
    BOOST_CHECK_EQUAL(decoded.hashWithdrawalBundle, source_extended.hashWithdrawalBundle);
    BOOST_CHECK_EQUAL(decoded.hashBmmProof, source_extended.hashBmmProof);
    BOOST_CHECK_EQUAL(decoded.hashExchangeStateRoot, source_extended.hashExchangeStateRoot);
    BOOST_CHECK_EQUAL(decoded.hashForcedInboxRoot, source_extended.hashForcedInboxRoot);
    BOOST_CHECK_EQUAL(decoded.hashDepositInboxRoot, source_extended.hashDepositInboxRoot);
    BOOST_CHECK_EQUAL(decoded.ecxParentHeight, source_extended.ecxParentHeight);
}

BOOST_AUTO_TEST_CASE(activation_transition_disconnect_and_reorg_are_symmetric)
{
    MemoryCoinsView persistent;
    CCoinsViewCache view{&persistent};
    const COutPoint genesis{Txid::FromUint256(uint256S("11")), 0};
    const CTxOut genesis_output{AuthorityOutput(0x21)};
    view.AddCoin(genesis, Coin(genesis_output, 1, false), false);
    const uint256 genesis_root = ecx::ComputeStateUtxoRoot(
        Params().GetConsensus().hashGenesisBlock,
        genesis,
        genesis_output);
    const ecx::ExchangeConsensus consensus{
        ConfiguredConsensus(10, genesis, genesis_root)};

    CBlock activation;
    activation.nVersion = CBlockHeader::EXCHANGE_STATE_HF_MASK |
        CBlockHeader::FORCED_INBOX_HF_MASK |
        CBlockHeader::DEPOSIT_INBOX_HF_MASK |
        CBlockHeader::INBOX_CURSOR_HF_MASK;
    activation.hashExchangeStateRoot = genesis_root;
    activation.hashForcedInboxRoot = ecx::ComputeForcedInboxGenesis(consensus);
    activation.hashDepositInboxRoot = ecx::ComputeDepositInboxGenesis(consensus);
    activation.ecxParentHeight = 100;
    std::string error;
    for (const uint64_t supplied : {uint64_t{0},uint64_t{99},uint64_t{101},UINT64_MAX}) {
        BOOST_CHECK(!ecx::ConnectExchangeState(activation,nullptr,view,10,error,consensus,supplied));
        BOOST_CHECK_EQUAL(error,"ECX supplied parent height disagrees with the committed header height");
        BOOST_CHECK(!ecx::HasPersistedExchangeConsensusState(view));
        BOOST_CHECK(view.HaveCoin(genesis));
    }
    {
        CCoinsViewCache fallback{&view};
        drivechain::BmmL1State missing;
        BOOST_REQUIRE(!drivechain::GetBmmState(fallback,missing));
        BOOST_REQUIRE_MESSAGE(ecx::ConnectExchangeState(activation,nullptr,fallback,10,error,consensus),error);
        BOOST_CHECK(ecx::HasPersistedExchangeConsensusState(fallback));
    }
    BOOST_CHECK(!ecx::HasPersistedExchangeConsensusState(view));
    BOOST_REQUIRE_MESSAGE(
        ecx::ConnectExchangeState(activation, nullptr, view, 10, error, consensus, 100),
        error);
    TestBlockIndex activation_index{activation, 10};

    for (unsigned fault=0; fault<3; ++fault) {
        CCoinsViewCache corrupted{&view};
        corrupted.SpendCoin(genesis);
        if (fault) {
            auto altered=AuthorityOutput(0x23);
            if (fault==1) altered.scriptPubKey=CScript() << OP_TRUE;
            corrupted.AddCoin(genesis,Coin(altered,1,false),false);
        }
        CBlock candidate;
        const auto before=candidate.GetHash();
        BOOST_CHECK(!ecx::PrepareExchangeStateHeader(candidate,&activation_index,corrupted,11,error,consensus,101));
        BOOST_CHECK_EQUAL(error,fault==0 ? "tracked ECX singleton is missing from the UTXO set" :
            fault==1 ? "ECX state authority must be a P2TR output" :
            "tracked ECX singleton does not match its persisted root");
        BOOST_CHECK_EQUAL(candidate.GetHash(),before);
    }

    CMutableTransaction transition;
    transition.vin.emplace_back(genesis);
    transition.vout.push_back(AuthorityOutput(0x22));
    // Empty inboxes alone do not exempt an ordinary transition from its marker.
    CBlock unmarked;
    unmarked.vtx.push_back(MakeTransactionRef(transition));
    const auto unmarked_before=unmarked.GetHash();
    BOOST_CHECK(!ecx::PrepareExchangeStateHeader(
        unmarked, &activation_index, view, 11, error, consensus, 101));
    BOOST_CHECK_EQUAL(error, "ECX state transition is missing its processed-cursor marker");
    BOOST_CHECK_EQUAL(unmarked.GetHash(),unmarked_before);
    transition.vout.push_back(CursorMarker(0, 0));
    const auto canonical_cursor = transition.vout.back().scriptPubKey;
    BOOST_REQUIRE_EQUAL(canonical_cursor.size(), 23U);
    const std::vector<unsigned char> cursor_payload(canonical_cursor.begin() + 2, canonical_cursor.end());
    std::vector<CScript> ignored_envelopes{
        CScript{}, CScript() << OP_PUSHDATA1, CScript() << OP_TRUE << cursor_payload,
        CScript() << OP_RETURN, CScript() << OP_RETURN << OP_TRUE,
        CScript() << OP_RETURN << OP_PUSHDATA2,
        CScript(canonical_cursor) << OP_DROP,
    };
    ignored_envelopes.push_back(canonical_cursor);
    ignored_envelopes.back().pop_back();
    for (const auto& script : ignored_envelopes) {
        CMutableTransaction with_ignored{transition};
        with_ignored.vout.emplace_back(::policyAsset, 0, script);
        CBlock candidate;
        candidate.vtx.push_back(MakeTransactionRef(with_ignored));
        BOOST_CHECK_MESSAGE(ecx::PrepareExchangeStateHeader(
            candidate, &activation_index, view, 11, error, consensus, 101), error);
    }
    for (const std::vector<unsigned char>& prefix : {
            std::vector<unsigned char>{OP_RETURN, OP_PUSHDATA1, 21},
            std::vector<unsigned char>{OP_RETURN, OP_PUSHDATA2, 21, 0},
            std::vector<unsigned char>{OP_RETURN, OP_PUSHDATA4, 21, 0, 0, 0}}) {
        CMutableTransaction nonminimal{transition};
        auto& script = nonminimal.vout.back().scriptPubKey;
        script.assign(prefix.begin(), prefix.end());
        script.insert(script.end(), cursor_payload.begin(), cursor_payload.end());
        CBlock candidate;
        candidate.vtx.push_back(MakeTransactionRef(nonminimal));
        BOOST_CHECK_MESSAGE(ecx::PrepareExchangeStateHeader(
            candidate, &activation_index, view, 11, error, consensus, 101), error);
    }
    for (unsigned mutation=0; mutation<8; ++mutation) {
        TestBlockIndex altered{activation,10};
        switch (mutation) {
        case 1: altered.nVersion^=CBlockHeader::EXCHANGE_STATE_HF_MASK; break;
        case 2: altered.hashExchangeStateRoot=uint256S("ff"); break;
        case 3: altered.nVersion^=CBlockHeader::FORCED_INBOX_HF_MASK; break;
        case 4: altered.nVersion^=CBlockHeader::DEPOSIT_INBOX_HF_MASK; break;
        case 5: altered.nVersion^=CBlockHeader::INBOX_CURSOR_HF_MASK; break;
        case 6: altered.hashForcedInboxRoot=uint256S("ff"); break;
        case 7: altered.hashDepositInboxRoot=uint256S("ff"); break;
        }
        CBlock candidate;
        candidate.vtx.push_back(MakeTransactionRef(transition));
        const auto before=candidate.GetHash();
        BOOST_CHECK(!ecx::PrepareExchangeStateHeader(candidate,mutation==0 ? nullptr : &altered,
            view,11,error,consensus,101));
        BOOST_CHECK_EQUAL(error,mutation<3 ? "persisted ECX tracker disagrees with the prior header root" :
            "persisted ECX inbox trackers disagree with the prior header roots");
        BOOST_CHECK_EQUAL(candidate.GetHash(),before);
    }
    CBlock next;
    next.vtx.push_back(MakeTransactionRef(transition));
    BOOST_REQUIRE_MESSAGE(
        ecx::PrepareExchangeStateHeader(
            next, &activation_index, view, 11, error, consensus, 101),
        error);
    BOOST_CHECK(next.HasExchangeState());
    BOOST_CHECK_NE(next.hashExchangeStateRoot, genesis_root);
    const auto reject_transition = [&](const std::vector<CTransactionRef>& transactions, const char* expected) {
        CBlock candidate;
        candidate.vtx = transactions;
        BOOST_CHECK(!ecx::PrepareExchangeStateHeader(candidate, &activation_index, view, 11, error, consensus, 101));
        BOOST_CHECK_EQUAL(error, expected);
    };
    CMutableTransaction duplicate_cursor{transition};
    duplicate_cursor.vout.push_back(CursorMarker(0, 0));
    reject_transition({MakeTransactionRef(duplicate_cursor)},
        "an ECX block may contain only one processed-cursor marker");
    CMutableTransaction other_marker;
    other_marker.vout.push_back(CursorMarker(0, 0));
    reject_transition({MakeTransactionRef(transition), MakeTransactionRef(other_marker)},
        "an ECX block may contain only one processed-cursor marker");
    CMutableTransaction outside_transition{transition};
    outside_transition.vout.pop_back();
    reject_transition({MakeTransactionRef(outside_transition), MakeTransactionRef(other_marker)},
        "ECX processed cursors are not monotonic or are outside the state transition");
    other_marker.vout[0].scriptPubKey = CScript() << OP_RETURN << std::vector<unsigned char>{'E','C','X','C',2};
    reject_transition({MakeTransactionRef(transition), MakeTransactionRef(other_marker)},
        "ECX processed-cursor marker has an invalid version or length");
    CMutableTransaction duplicate{transition};
    duplicate.vin.emplace_back(genesis);
    reject_transition({MakeTransactionRef(duplicate)}, "more than one transaction spends the ECX singleton");
    reject_transition({MakeTransactionRef(transition), MakeTransactionRef(transition)},
        "more than one transaction spends the ECX singleton");
    CMutableTransaction wrong_input{transition};
    wrong_input.vin.insert(wrong_input.vin.begin(), CTxIn{COutPoint{Txid::FromUint256(uint256S("99")), 0}});
    reject_transition({MakeTransactionRef(wrong_input)}, "ECX singleton must be transition input zero");
    CMutableTransaction missing_output{transition};
    missing_output.vout.clear();
    reject_transition({MakeTransactionRef(missing_output)}, "ECX transition has no successor output zero");
    CMutableTransaction chained{transition};
    chained.vin[0].prevout = COutPoint{next.vtx[0]->GetHash(), 0};
    reject_transition({MakeTransactionRef(transition), MakeTransactionRef(chained)},
        "a block may contain at most one ECX state transition");
    BOOST_REQUIRE_MESSAGE(
        ecx::ConnectExchangeState(
            next, &activation_index, view, 11, error, consensus, 101),
        error);

    const COutPoint successor{next.vtx[0]->GetHash(), 0};
    BOOST_REQUIRE(view.SpendCoin(genesis));
    view.AddCoin(successor, Coin(next.vtx[0]->vout[0], 11, false), false);

    TestBlockIndex next_index{next, 11, &activation_index};
    uint256 prior_root;
    BOOST_REQUIRE_MESSAGE(
        ecx::GetPriorActiveExchangeStateRoot(&next_index, prior_root, error),
        error);
    BOOST_CHECK_EQUAL(prior_root, next.hashExchangeStateRoot);

    // Mirror DisconnectBlock ordering: transaction undo runs first.
    BOOST_REQUIRE(view.SpendCoin(successor));
    const auto tracker_hash = [&] {
        HashWriter writer;
        for (const char* key : {
            "e31f7fb1e9489bfb9f6a73c10f80ecdcce1f276fbdf0cf85c02e3bcf174dc041",
            "c3fd019db845c81a68a561f5ab67d92c3ab2505cb2c8212f02511e07e8c2f2a1",
            "0cc4c302121a9d75c8a0e520253c1740520a6d6f4d03db6947a99565175d6586"})
            writer << view.AccessCoin(COutPoint{Txid::FromUint256(uint256S(key)),0});
        return writer.GetHash();
    };
    const auto before_undo=tracker_hash();
    for (bool forced : {false,true}) {
        auto& root=forced ? activation_index.hashForcedInboxRoot : activation_index.hashDepositInboxRoot;
        const auto original=root;
        root=uint256S("01");
        BOOST_CHECK(!ecx::DisconnectExchangeState(next,&activation_index,view,11,error,consensus,101));
        BOOST_CHECK_EQUAL(error,"ECX inbox undo does not reproduce the disconnected header state");
        BOOST_CHECK(tracker_hash()==before_undo);
        root=original;
    }
    BOOST_CHECK(!ecx::DisconnectExchangeState(next,&activation_index,view,11,error,consensus,101));
    BOOST_CHECK_EQUAL(error,"prior ECX singleton was not restored by transaction undo");
    BOOST_CHECK(tracker_hash()==before_undo);
    view.AddCoin(genesis,Coin(AuthorityOutput(0x7e),1,false),true);
    BOOST_CHECK(!ecx::DisconnectExchangeState(next,&activation_index,view,11,error,consensus,101));
    BOOST_CHECK_EQUAL(error,"restored ECX singleton disagrees with prior header root");
    BOOST_CHECK(tracker_hash()==before_undo);
    BOOST_REQUIRE(view.SpendCoin(genesis));
    view.AddCoin(genesis, Coin(genesis_output, 1, false), true);
    BOOST_REQUIRE_MESSAGE(
        ecx::DisconnectExchangeState(
            next, &activation_index, view, 11, error, consensus, 101),
        error);

    CBlock alternative;
    BOOST_REQUIRE_MESSAGE(
        ecx::PrepareExchangeStateHeader(
            alternative, &activation_index, view, 11, error, consensus, 102),
        error);
    BOOST_CHECK_EQUAL(alternative.hashExchangeStateRoot, genesis_root);
}

BOOST_AUTO_TEST_CASE(snapshot_admission_read_order_and_exceptions)
{
    for (uint32_t passed=0; passed<=14; ++passed) {
        for (bool throws : {false,true}) {
            std::vector<uint32_t> seen;
            std::string error{"existing"};
            const auto run = [&] {
                return drivechain::haskell::ExchangeSnapshot([&](uint32_t step) {
                    seen.push_back(step);
                    BOOST_CHECK(drivechain::haskell::ExchangeAvailable(
                        drivechain::haskell::Availability::ROOT,[](uint32_t) { return true; }));
                    if (step == passed && throws) throw std::logic_error("snapshot read fault");
                    if (step == passed && ((step >= 4 && step <= 6) || step == 13)) error = "child snapshot failure";
                    return step < passed;
                },error);
            };
            if (throws && passed < 14) {
                BOOST_CHECK_EXCEPTION(run(),std::logic_error,[](const auto& e) { return std::string(e.what()) == "snapshot read fault"; });
                BOOST_CHECK_EQUAL(error,"existing");
            } else {
                BOOST_CHECK_EQUAL(run(),passed == 14);
                BOOST_CHECK_EQUAL(error,passed == 14 ? "existing" : passed < 4 ?
                    "active tip has no complete ECX consensus context" :
                    (passed < 7 || passed == 13) ? "child snapshot failure" :
                    "persisted ECX context disagrees with the active tip");
            }
            BOOST_CHECK_EQUAL(seen.size(),std::min<uint32_t>(14,passed+1));
            for (uint32_t i=0; i<seen.size(); ++i) BOOST_CHECK_EQUAL(seen[i],i);
        }
    }
}

BOOST_AUTO_TEST_CASE(persisted_tracker_corruption_preserves_error_classes)
{
    const COutPoint genesis{Txid::FromUint256(uint256S("11")), 0};
    const CTxOut genesis_output{AuthorityOutput(0x21)};
    const uint256 root = ecx::ComputeStateUtxoRoot(Params().GetConsensus().hashGenesisBlock, genesis, genesis_output);
    const auto consensus = ConfiguredConsensus(10, genesis, root);
    CBlock activation;
    activation.nVersion = CBlockHeader::EXCHANGE_STATE_HF_MASK | CBlockHeader::FORCED_INBOX_HF_MASK |
        CBlockHeader::DEPOSIT_INBOX_HF_MASK | CBlockHeader::INBOX_CURSOR_HF_MASK;
    activation.hashExchangeStateRoot = root;
    activation.hashForcedInboxRoot = ecx::ComputeForcedInboxGenesis(consensus);
    activation.hashDepositInboxRoot = ecx::ComputeDepositInboxGenesis(consensus);
    activation.ecxParentHeight = 100;
    MemoryCoinsView persistent;
    CCoinsViewCache view{&persistent};
    view.AddCoin(genesis, Coin(CTxOut{genesis_output}, 1, false), false);
    std::string error;
    BOOST_REQUIRE_MESSAGE(ecx::ConnectExchangeState(activation, nullptr, view, 10, error, consensus, 100), error);
    TestBlockIndex tip{activation, 10};
    ecx::ExchangeConsensusSnapshot snapshot;
    BOOST_REQUIRE_MESSAGE(ecx::GetExchangeConsensusSnapshot(view, &tip, snapshot, error), error);
    const auto rejected = [&](const CBlockIndex* candidate, const char* expected) {
        snapshot.exchange_state_root = root;
        snapshot.forced_entry_count = 99;
        error = "stale snapshot error";
        BOOST_CHECK(!ecx::GetExchangeConsensusSnapshot(view,candidate,snapshot,error));
        BOOST_CHECK_EQUAL(error,expected);
        BOOST_CHECK(snapshot.exchange_state_root.IsNull());
        BOOST_CHECK_EQUAL(snapshot.forced_entry_count,0U);
    };
    rejected(nullptr,"active tip has no complete ECX consensus context");
    const auto saved_version = tip.nVersion;
    for (const auto mask : {CBlockHeader::EXCHANGE_STATE_HF_MASK,CBlockHeader::FORCED_INBOX_HF_MASK,
                           CBlockHeader::DEPOSIT_INBOX_HF_MASK,CBlockHeader::INBOX_CURSOR_HF_MASK}) {
        tip.nVersion = saved_version & ~mask;
        rejected(&tip,mask == CBlockHeader::INBOX_CURSOR_HF_MASK ?
            "persisted ECX context disagrees with the active tip" : "active tip has no complete ECX consensus context");
        tip.nVersion = saved_version;
    }
    tip.forcedProcessedCursor = 1;
    rejected(&tip,"persisted ECX context disagrees with the active tip");
    tip.forcedProcessedCursor = 0;
    tip.depositProcessedCursor = 1;
    rejected(&tip,"persisted ECX context disagrees with the active tip");
    tip.depositProcessedCursor = 0;
    BOOST_REQUIRE_MESSAGE(ecx::GetExchangeConsensusSnapshot(view,&tip,snapshot,error),error);
    const std::array<const char*, 3> keys{
        "e31f7fb1e9489bfb9f6a73c10f80ecdcce1f276fbdf0cf85c02e3bcf174dc041",
        "c3fd019db845c81a68a561f5ab67d92c3ab2505cb2c8212f02511e07e8c2f2a1",
        "0cc4c302121a9d75c8a0e520253c1740520a6d6f4d03db6947a99565175d6586"};
    for (unsigned index = 0; index < keys.size(); ++index) {
        const COutPoint key{Txid::FromUint256(uint256S(keys[index])), 0};
        const Coin& persisted = view.AccessCoin(key);
        const CTxOut original = persisted.out;
        const std::array<std::string, 3> markers{"ecx-state-v1", "ecx-forced-v1", "ecx-deposit-v1"};
        DataStream expected;
        expected << std::vector<unsigned char>(markers[index].begin(), markers[index].end());
        if (index == 0) expected << genesis << root;
        else expected << (index == 1 ? activation.hashForcedInboxRoot : activation.hashDepositInboxRoot) << uint64_t{0};
        const auto* data = reinterpret_cast<const unsigned char*>(expected.data());
        BOOST_CHECK(original.scriptPubKey == (CScript{} << std::vector<unsigned char>(data, data + expected.size()) << OP_DROP << OP_FALSE));
        BOOST_CHECK(original.nAsset.IsExplicit());
        BOOST_CHECK(original.nAsset.GetAsset() == Params().GetConsensus().pegged_asset);
        BOOST_CHECK(original.nValue.IsExplicit());
        BOOST_CHECK_EQUAL(original.nValue.GetAmount(), 0);
        BOOST_CHECK_EQUAL(persisted.nHeight, 10U);
        BOOST_CHECK(!persisted.IsCoinBase());
        const std::string prefix = index == 0 ? "persisted ECX tracker" : "persisted ECX inbox tracker";
        BOOST_REQUIRE(view.SpendCoin(key));
        BOOST_CHECK(!ecx::GetExchangeConsensusSnapshot(view,&tip,snapshot,error));
        BOOST_CHECK_EQUAL(error,prefix + " is missing");
        BOOST_CHECK(snapshot.exchange_state_root.IsNull());
        view.AddCoin(key,Coin(CTxOut{original},10,false),true);
        BOOST_REQUIRE_MESSAGE(ecx::GetExchangeConsensusSnapshot(view,&tip,snapshot,error),error);
        for (unsigned mutation = 0; mutation < (index == 0 ? 11U : 9U); ++mutation) {
            CTxOut output = original;
            std::string suffix;
            if (mutation == 0 || (mutation >= 5 && mutation <= 7)) {
                if (mutation == 0) output.nValue.SetToAmount(1);
                if (mutation == 5) output.nAsset = CConfidentialAsset(CAsset(uint256S("ff")));
                if (mutation == 6) output.nAsset.vchCommitment.assign(33, 10);
                if (mutation == 7) output.nValue.vchCommitment.assign(33, 8);
                suffix = " has invalid asset or value encoding";
            } else if (mutation == 1) {
                output.scriptPubKey = CScript{} << OP_TRUE;
                suffix = " script is malformed";
            } else {
                std::vector<unsigned char> payload;
                auto cursor = original.scriptPubKey.begin();
                opcodetype opcode;
                BOOST_REQUIRE(original.scriptPubKey.GetOp(cursor, opcode, payload));
                if (mutation == 2) { payload = {255}; suffix = " cannot be decoded"; }
                if (mutation == 3) { BOOST_REQUIRE(payload.size() > 1); payload[1] ^= 1; suffix = " payload is invalid"; }
                if (mutation == 4) { payload.push_back(0); suffix = " payload is invalid"; }
                if (mutation >= 8) {
                    DataStream invalid_record;
                    invalid_record << std::vector<unsigned char>(markers[index].begin(), markers[index].end());
                    if (index == 0) invalid_record << (mutation >= 9 ? COutPoint{} : genesis)
                        << (mutation != 9 ? uint256::ZERO : root);
                    else invalid_record << uint256::ZERO << uint64_t{0};
                    const auto* bytes = reinterpret_cast<const unsigned char*>(invalid_record.data());
                    payload.assign(bytes, bytes + invalid_record.size());
                    suffix = " payload is invalid";
                }
                output.scriptPubKey = CScript{} << payload << OP_DROP << OP_FALSE;
            }
            BOOST_REQUIRE(view.SpendCoin(key));
            view.AddCoin(key, Coin(std::move(output), 10, false), true);
            BOOST_CHECK(!ecx::GetExchangeConsensusSnapshot(view, &tip, snapshot, error));
            BOOST_CHECK_EQUAL(error, prefix + suffix);
            BOOST_REQUIRE(view.SpendCoin(key));
            view.AddCoin(key, Coin(CTxOut{original}, 10, false), true);
            BOOST_REQUIRE_MESSAGE(ecx::GetExchangeConsensusSnapshot(view, &tip, snapshot, error), error);
        }
    }
}

BOOST_AUTO_TEST_CASE(activation_disconnect_removes_only_tracker_records)
{
    const COutPoint genesis{Txid::FromUint256(uint256S("11")), 0};
    const CTxOut genesis_output{AuthorityOutput(0x21)};
    const auto consensus = ConfiguredConsensus(10, genesis,
        ecx::ComputeStateUtxoRoot(Params().GetConsensus().hashGenesisBlock, genesis, genesis_output));
    MemoryCoinsView persistent;
    CCoinsViewCache view{&persistent};
    view.AddCoin(genesis, Coin(CTxOut{genesis_output}, 1, false), false);
    CBlock activation;
    std::string error;
    BOOST_REQUIRE_MESSAGE(ecx::PrepareExchangeStateHeader(activation, nullptr, view, 10, error, consensus, 100), error);
    BOOST_REQUIRE_MESSAGE(ecx::ConnectExchangeState(activation, nullptr, view, 10, error, consensus, 100), error);
    const std::array<const char*,3> keys{
        "e31f7fb1e9489bfb9f6a73c10f80ecdcce1f276fbdf0cf85c02e3bcf174dc041",
        "c3fd019db845c81a68a561f5ab67d92c3ab2505cb2c8212f02511e07e8c2f2a1",
        "0cc4c302121a9d75c8a0e520253c1740520a6d6f4d03db6947a99565175d6586"};
    const auto coin_hashes = [&] {
        std::vector<uint256> hashes;
        for (const auto* key : keys) hashes.push_back((HashWriter{} << view.AccessCoin(COutPoint{Txid::FromUint256(uint256S(key)),0})).GetHash());
        hashes.push_back((HashWriter{} << view.AccessCoin(genesis)).GetHash());
        return hashes;
    };
    const auto before=coin_hashes();
    for (unsigned mutation=0; mutation<5; ++mutation) {
        auto invalid=activation;
        uint64_t parent{100};
        if (mutation==0) invalid.ecxParentHeight=0;
        if (mutation==1) parent=99;
        if (mutation==2) invalid.hashExchangeStateRoot.begin()[0]^=1;
        if (mutation==3) invalid.hashForcedInboxRoot.begin()[0]^=1;
        if (mutation==4) invalid.hashDepositInboxRoot.begin()[0]^=1;
        BOOST_CHECK(!ecx::DisconnectExchangeState(invalid,nullptr,view,10,error,consensus,parent));
        BOOST_CHECK_EQUAL(error,mutation<2 ? "ECX disconnected block has an inconsistent parent height" :
            mutation==2 ? "persisted ECX tracker disagrees with disconnected header" :
            "persisted ECX inbox trackers disagree with disconnected header");
        BOOST_CHECK(coin_hashes()==before);
    }
    BOOST_CHECK(ecx::DisconnectExchangeState(CBlock{},nullptr,view,9,error,consensus,0));
    BOOST_CHECK(error.empty());
    BOOST_CHECK(coin_hashes()==before);
    BOOST_REQUIRE_MESSAGE(ecx::DisconnectExchangeState(activation, nullptr, view, 10, error, consensus, 100), error);
    for (const char* key : keys)
        BOOST_CHECK(view.AccessCoin(COutPoint{Txid::FromUint256(uint256S(key)), 0}).IsSpent());
    BOOST_CHECK(!view.AccessCoin(genesis).IsSpent());
    BOOST_CHECK(view.AccessCoin(genesis).out == genesis_output);
}

BOOST_AUTO_TEST_CASE(activation_does_not_overwrite_reserved_state_coins)
{
    const COutPoint genesis{Txid::FromUint256(uint256S("11")), 0};
    const CTxOut genesis_output{AuthorityOutput(0x21)};
    const uint256 genesis_root = ecx::ComputeStateUtxoRoot(
        Params().GetConsensus().hashGenesisBlock,
        genesis,
        genesis_output);
    const ecx::ExchangeConsensus consensus{
        ConfiguredConsensus(10, genesis, genesis_root)};
    CBlock activation;
    activation.nVersion = CBlockHeader::EXCHANGE_STATE_HF_MASK |
        CBlockHeader::FORCED_INBOX_HF_MASK |
        CBlockHeader::DEPOSIT_INBOX_HF_MASK |
        CBlockHeader::INBOX_CURSOR_HF_MASK;
    activation.hashExchangeStateRoot = genesis_root;
    activation.hashForcedInboxRoot = ecx::ComputeForcedInboxGenesis(consensus);
    activation.hashDepositInboxRoot = ecx::ComputeDepositInboxGenesis(consensus);
    activation.ecxParentHeight = 100;

    const std::vector<COutPoint> trackers{
        COutPoint{
            Txid::FromUint256(uint256S("e31f7fb1e9489bfb9f6a73c10f80ecdcce1f276fbdf0cf85c02e3bcf174dc041")),
            0},
        COutPoint{
            Txid::FromUint256(uint256S("c3fd019db845c81a68a561f5ab67d92c3ab2505cb2c8212f02511e07e8c2f2a1")),
            0},
        COutPoint{
            Txid::FromUint256(uint256S("0cc4c302121a9d75c8a0e520253c1740520a6d6f4d03db6947a99565175d6586")),
            0},
    };
    for (const COutPoint& tracker : trackers) {
        MemoryCoinsView persistent;
        CCoinsViewCache view{&persistent};
        view.AddCoin(genesis, Coin(genesis_output, 1, false), false);
        const CTxOut collision{AuthorityOutput(0x55, 7)};
        view.AddCoin(tracker, Coin(collision, 1, false), false);
        std::string error;
        BOOST_CHECK(!ecx::ConnectExchangeState(
            activation, nullptr, view, 10, error, consensus, 100));
        BOOST_CHECK(error.find("cannot overwrite") != std::string::npos);
        const Coin& preserved{view.AccessCoin(tracker)};
        BOOST_CHECK(!preserved.IsSpent());
        BOOST_CHECK(preserved.out == collision);
        for (const auto& untouched : trackers) {
            if (untouched != tracker) BOOST_CHECK(view.AccessCoin(untouched).IsSpent());
        }
        BOOST_CHECK(!view.AccessCoin(genesis).IsSpent());
        BOOST_CHECK(view.AccessCoin(genesis).out == genesis_output);
    }
}

BOOST_AUTO_TEST_CASE(rejects_bad_header_authority_and_same_block_chaining)
{
    MemoryCoinsView persistent;
    CCoinsViewCache view{&persistent};
    const COutPoint genesis{Txid::FromUint256(uint256S("21")), 0};
    const CTxOut genesis_output{AuthorityOutput(0x31)};
    view.AddCoin(genesis, Coin(genesis_output, 1, false), false);
    const uint256 genesis_root = ecx::ComputeStateUtxoRoot(
        Params().GetConsensus().hashGenesisBlock,
        genesis,
        genesis_output);
    const ecx::ExchangeConsensus consensus{
        ConfiguredConsensus(10, genesis, genesis_root)};
    CBlock activation;
    activation.nVersion = CBlockHeader::EXCHANGE_STATE_HF_MASK |
        CBlockHeader::FORCED_INBOX_HF_MASK |
        CBlockHeader::DEPOSIT_INBOX_HF_MASK |
        CBlockHeader::INBOX_CURSOR_HF_MASK;
    activation.hashExchangeStateRoot = genesis_root;
    activation.hashForcedInboxRoot = ecx::ComputeForcedInboxGenesis(consensus);
    activation.hashDepositInboxRoot = ecx::ComputeDepositInboxGenesis(consensus);
    activation.ecxParentHeight = 100;
    std::string error;
    BOOST_REQUIRE(ecx::ConnectExchangeState(
        activation, nullptr, view, 10, error, consensus, 100));
    TestBlockIndex previous{activation, 10};

    CMutableTransaction changed_value;
    changed_value.vin.emplace_back(genesis);
    changed_value.vout.push_back(AuthorityOutput(0x32, 2));
    CBlock invalid;
    invalid.vtx.push_back(MakeTransactionRef(changed_value));
    BOOST_CHECK(!ecx::PrepareExchangeStateHeader(
        invalid, &previous, view, 11, error, consensus, 101));
    BOOST_CHECK(error.find("value") != std::string::npos);

    CMutableTransaction first;
    first.vin.emplace_back(genesis);
    first.vout.push_back(AuthorityOutput(0x33));
    CMutableTransaction second;
    second.vin.emplace_back(COutPoint{first.GetHash(), 0});
    second.vout.push_back(AuthorityOutput(0x34));
    invalid.vtx = {MakeTransactionRef(first), MakeTransactionRef(second)};
    BOOST_CHECK(!ecx::PrepareExchangeStateHeader(
        invalid, &previous, view, 11, error, consensus, 101));
    BOOST_CHECK(error.find("at most one") != std::string::npos);

    CBlock wrong_root;
    wrong_root.nVersion = CBlockHeader::EXCHANGE_STATE_HF_MASK |
        CBlockHeader::FORCED_INBOX_HF_MASK |
        CBlockHeader::DEPOSIT_INBOX_HF_MASK |
        CBlockHeader::INBOX_CURSOR_HF_MASK;
    wrong_root.hashExchangeStateRoot = uint256S("99");
    wrong_root.hashForcedInboxRoot = previous.hashForcedInboxRoot;
    wrong_root.hashDepositInboxRoot = previous.hashDepositInboxRoot;
    wrong_root.ecxParentHeight = 101;
    BOOST_CHECK(!ecx::ConnectExchangeState(
        wrong_root, &previous, view, 11, error, consensus, 101));
    BOOST_CHECK(error.find("deterministic") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(incremental_scan_keeps_last_matching_result)
{
    const std::array<unsigned,5> patterns{127,15,126,63,95};
    for (unsigned first : patterns) {
        for (unsigned second : patterns) {
            const std::array<unsigned,2> rows{first,second};
            size_t index{0};
            bool actual{false},expected{false};
            for (unsigned row : rows) if ((row&15)==15) expected=row==127;
            const auto status=drivechain::haskell::ParentReplayStore(
                drivechain::haskell::ReplayStoreFlow::INCREMENTAL_SCAN,[&](uint32_t step) -> uint32_t {
                    if (step<=8) return true;
                    if (step==9) return index<rows.size();
                    if (step<=16) return (rows.at(index)&(1U<<(step-10)))!=0;
                    if (step==18) actual=false;
                    else if (step==19) actual=true;
                    else if (step==20) ++index;
                    else throw std::logic_error("invalid test scan step");
                    return true;
                });
            BOOST_CHECK_EQUAL(status,1U);
            BOOST_CHECK_EQUAL(index,rows.size());
            BOOST_CHECK_EQUAL(actual,expected);
        }
    }
}

BOOST_AUTO_TEST_CASE(activation_inbox_counts_preserve_output_and_error)
{
    for (uint64_t active : {0U,1U}) {
        for (uint64_t forced : {uint64_t{0},uint64_t{1},UINT64_MAX}) {
            for (uint64_t deposits : {uint64_t{0},uint64_t{1},UINT64_MAX}) {
                uint64_t output{77};
                std::string error{"original"};
                const bool expected=!active || (forced==0 && deposits==0);
                BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeInbox(
                    std::array<uint64_t,3>{active,forced,deposits},output,error),expected);
                BOOST_CHECK_EQUAL(output,77U);
                BOOST_CHECK_EQUAL(error,expected ? "original" : "ECX activation block must carry the frozen inbox genesis state");
            }
        }
    }
    uint64_t output{77};
    std::string error{"original"};
    BOOST_CHECK_THROW(drivechain::haskell::ExchangeInbox(std::array<uint64_t,3>{2,0,0},output,error),std::runtime_error);
    BOOST_CHECK_EQUAL(output,77U);
    BOOST_CHECK_EQUAL(error,"original");
}

BOOST_AUTO_TEST_CASE(frozen_source_formats_are_verified_and_accumulated)
{
    struct ElementsModeGuard {
        const bool previous{g_con_elementsmode};
        ElementsModeGuard() { g_con_elementsmode = true; }
        ~ElementsModeGuard() { g_con_elementsmode = previous; }
    } elements_mode;

    MemoryCoinsView persistent;
    CCoinsViewCache view{&persistent};
    const COutPoint genesis{Txid::FromUint256(uint256S("31")), 0};
    const CTxOut genesis_output{AuthorityOutput(0x41)};
    view.AddCoin(genesis, Coin(genesis_output, 1, false), false);
    const uint256 genesis_root = ecx::ComputeStateUtxoRoot(
        Params().GetConsensus().hashGenesisBlock,
        genesis,
        genesis_output);
    const ecx::ExchangeConsensus consensus{
        ConfiguredConsensus(20, genesis, genesis_root)};

    // These are independent protocol-core-compatible tagged-SHA256 vectors.
    BOOST_CHECK_EQUAL(
        ecx::ComputeForcedInboxGenesis(consensus),
        RawHash("079e7311c6e2b15563b1f7b9007fda9aa633a4596532f63207de98c698e93aff"));
    BOOST_CHECK_EQUAL(
        ecx::ComputeDepositInboxGenesis(consensus),
        RawHash("c1c4a175d3a9fb7f6e1c0f44de8b181d05eda6fb278f0a2744b91427093e2f63"));

    CBlock activation;
    activation.nVersion = CBlockHeader::EXCHANGE_STATE_HF_MASK |
        CBlockHeader::FORCED_INBOX_HF_MASK |
        CBlockHeader::DEPOSIT_INBOX_HF_MASK |
        CBlockHeader::INBOX_CURSOR_HF_MASK;
    activation.hashExchangeStateRoot = genesis_root;
    activation.hashForcedInboxRoot = ecx::ComputeForcedInboxGenesis(consensus);
    activation.hashDepositInboxRoot = ecx::ComputeDepositInboxGenesis(consensus);
    activation.ecxParentHeight = 500;
    std::string error;
    const CKey trader{TestTraderKey()};
    const auto reject_activation = [&](const std::vector<CTransactionRef>& transactions, const char* expected) {
        CBlock candidate{activation};
        candidate.vtx = transactions;
        const auto original_header = candidate.GetHash();
        BOOST_CHECK(!ecx::PrepareExchangeStateHeader(candidate, nullptr, view, 20, error, consensus, 500));
        BOOST_CHECK_EQUAL(error, expected);
        BOOST_CHECK_EQUAL(candidate.GetHash(), original_header);
        BOOST_CHECK(!view.AccessCoin(genesis).IsSpent());
    };
    const auto forced = MakeTransactionRef(ForcedCancelTransaction(consensus, trader));
    const auto deposit = MakeTransactionRef(ConfidentialDepositTransaction(consensus, trader));
    for (const auto& sources : std::vector<std::vector<CTransactionRef>>{{forced}, {deposit}, {forced, deposit}}) {
        reject_activation(sources, "ECX activation block must carry the frozen inbox genesis state");
    }
    const auto bad_signature = MakeTransactionRef(ForcedCancelTransaction(consensus, trader, true));
    CBlock invalid_source{activation};
    invalid_source.vtx = {bad_signature};
    BOOST_CHECK(!ecx::PrepareExchangeStateHeader(invalid_source, nullptr, view, 20, error, consensus, 500));
    BOOST_CHECK(error.find("signature") != std::string::npos);
    CMutableTransaction premature_transition;
    premature_transition.vin.emplace_back(genesis);
    premature_transition.vout.push_back(AuthorityOutput(0x42));
    reject_activation({MakeTransactionRef(premature_transition), bad_signature},
        "ECX activation block must carry the frozen genesis state");
    TestBlockIndex ignored_prior{activation, 19};
    ignored_prior.forcedProcessedCursor = 99;
    ignored_prior.depositProcessedCursor = 98;
    ignored_prior.sourceBacklogOldestParentHeight = 97;
    CBlock prepared_activation;
    BOOST_REQUIRE_MESSAGE(ecx::PrepareExchangeStateHeader(
        prepared_activation, &ignored_prior, view, 20, error, consensus, 500), error);
    BOOST_CHECK_EQUAL(prepared_activation.hashExchangeStateRoot, activation.hashExchangeStateRoot);
    BOOST_CHECK_EQUAL(prepared_activation.hashForcedInboxRoot, activation.hashForcedInboxRoot);
    BOOST_CHECK_EQUAL(prepared_activation.hashDepositInboxRoot, activation.hashDepositInboxRoot);
    BOOST_CHECK_EQUAL(prepared_activation.forcedProcessedCursor, 0U);
    BOOST_CHECK_EQUAL(prepared_activation.depositProcessedCursor, 0U);
    BOOST_CHECK_EQUAL(prepared_activation.sourceBacklogOldestParentHeight, 0U);
    BOOST_REQUIRE_MESSAGE(
        ecx::ConnectExchangeState(
            activation, nullptr, view, 20, error, consensus, 500),
        error);
    TestBlockIndex previous{activation, 20};

    CBlock invalid_signature;
    invalid_signature.vtx.push_back(MakeTransactionRef(
        ForcedCancelTransaction(consensus, trader, true)));
    BOOST_CHECK(!ecx::PrepareExchangeStateHeader(
        invalid_signature, &previous, view, 21, error, consensus, 501));
    BOOST_CHECK(error.find("signature") != std::string::npos);

    CBlock missing_deposit_proofs;
    missing_deposit_proofs.vtx.push_back(MakeTransactionRef(
        ConfidentialDepositTransaction(consensus, trader, false)));
    BOOST_CHECK(!ecx::PrepareExchangeStateHeader(
        missing_deposit_proofs, &previous, view, 21, error, consensus, 501));
    BOOST_CHECK(error.find("confidential collateral vault") != std::string::npos);

    CMutableTransaction duplicate_forced{
        ForcedCancelTransaction(consensus, trader)};
    duplicate_forced.vout.push_back(duplicate_forced.vout[0]);
    CBlock duplicate_block;
    duplicate_block.vtx.push_back(MakeTransactionRef(std::move(duplicate_forced)));
    BOOST_CHECK(!ecx::PrepareExchangeStateHeader(
        duplicate_block, &previous, view, 21, error, consensus, 501));
    BOOST_CHECK(error.find("only one ECX forced action") != std::string::npos);

    CMutableTransaction duplicate_deposit{
        ConfidentialDepositTransaction(consensus, trader)};
    duplicate_deposit.vout.push_back(duplicate_deposit.vout[1]);
    duplicate_deposit.witness.vtxoutwit.resize(3);
    CBlock duplicate_deposit_block;
    duplicate_deposit_block.vtx.push_back(MakeTransactionRef(std::move(duplicate_deposit)));
    BOOST_CHECK(!ecx::PrepareExchangeStateHeader(
        duplicate_deposit_block, &previous, view, 21, error, consensus, 501));
    BOOST_CHECK_EQUAL(error, "an Elements transaction may contain only one ECX deposit marker");

    CBlock source_block;
    source_block.vtx.push_back(MakeTransactionRef(
        ForcedCancelTransaction(consensus, trader)));
    source_block.vtx.push_back(MakeTransactionRef(
        ConfidentialDepositTransaction(consensus, trader)));
    BOOST_REQUIRE_MESSAGE(
        ecx::PrepareExchangeStateHeader(
            source_block, &previous, view, 21, error, consensus, 501),
        error);
    BOOST_CHECK_NE(source_block.hashForcedInboxRoot, activation.hashForcedInboxRoot);
    BOOST_CHECK_NE(source_block.hashDepositInboxRoot, activation.hashDepositInboxRoot);
    for (unsigned kind=0; kind<2; ++kind) {
        const auto& tx=*source_block.vtx[kind];
        const auto& root=kind ? activation.hashDepositInboxRoot : activation.hashForcedInboxRoot;
        const auto txid=tx.GetHash().ToUint256();
        std::vector<unsigned char> event{1};
        event.insert(event.end(),consensus.chain_id.begin(),consensus.chain_id.end());
        TestPushU64Be(event,0);
        event.insert(event.end(),root.begin(),root.end());
        TestPushU64Be(event,21);
        TestPushU64Be(event,501);
        event.insert(event.end(),txid.begin(),txid.end());
        TestPushU32Be(event,0);
        if (kind) {
            TestPushU32Be(event,1);
            DataStream serialized;
            serialized << tx.vout[0];
            const auto* data=UCharCast(serialized.data());
            const auto output_hash=TestSha256(std::vector<unsigned char>(data,data+serialized.size()));
            event.insert(event.end(),output_hash.begin(),output_hash.end());
            const XOnlyPubKey key{trader.GetPubKey()};
            event.insert(event.end(),key.begin(),key.end());
        } else {
            const auto& script=tx.vout[0].scriptPubKey;
            auto cursor=script.begin();
            opcodetype opcode;
            std::vector<unsigned char> payload;
            BOOST_REQUIRE(script.GetOp(cursor,opcode));
            BOOST_REQUIRE(script.GetOp(cursor,opcode,payload));
            BOOST_REQUIRE(payload.size()>=8);
            event.push_back(payload[5]);
            event.insert(event.end(),payload.begin()+8,payload.end());
        }
        const auto hash=TestTaggedHash(kind ? "ECX/deposit-event/v1" : "ECX/forced-action-entry/v1",event);
        std::vector<unsigned char> step(root.begin(),root.end());
        TestPushU64Be(step,0);
        step.insert(step.end(),hash.begin(),hash.end());
        BOOST_CHECK_EQUAL(kind ? source_block.hashDepositInboxRoot : source_block.hashForcedInboxRoot,
            TestTaggedHash(kind ? "ECX/deposit-inbox-step/v1" : "ECX/forced-inbox-step/v1",step));
    }
    BOOST_CHECK_EQUAL(source_block.ecxParentHeight, 501U);
    BOOST_REQUIRE_MESSAGE(
        ecx::ConnectExchangeState(
            source_block, &previous, view, 21, error, consensus, 501),
        error);
    TestBlockIndex source_index{source_block, 21, &previous};
    ecx::ExchangeConsensusSnapshot snapshot;
    BOOST_REQUIRE_MESSAGE(
        ecx::GetExchangeConsensusSnapshot(
            view, &source_index, snapshot, error),
        error);
    BOOST_CHECK_EQUAL(snapshot.exchange_state_root, genesis_root);
    BOOST_CHECK_EQUAL(snapshot.forced_inbox_root, source_block.hashForcedInboxRoot);
    BOOST_CHECK_EQUAL(snapshot.forced_entry_count, 1U);
    BOOST_CHECK_EQUAL(snapshot.deposit_inbox_root, source_block.hashDepositInboxRoot);
    BOOST_CHECK_EQUAL(snapshot.deposit_entry_count, 1U);

    BOOST_REQUIRE_MESSAGE(
        ecx::DisconnectExchangeState(
            source_block, &previous, view, 21, error, consensus, 501),
        error);
    BOOST_REQUIRE_MESSAGE(
        ecx::GetExchangeConsensusSnapshot(
            view, &previous, snapshot, error),
        error);
    BOOST_CHECK_EQUAL(snapshot.forced_inbox_root, activation.hashForcedInboxRoot);
    BOOST_CHECK_EQUAL(snapshot.forced_entry_count, 0U);
    BOOST_CHECK_EQUAL(snapshot.deposit_inbox_root, activation.hashDepositInboxRoot);
    BOOST_CHECK_EQUAL(snapshot.deposit_entry_count, 0U);
}

BOOST_AUTO_TEST_CASE(public_cursor_liveness_bounds_carry_forward_spam)
{
    MemoryCoinsView persistent;
    CCoinsViewCache view{&persistent};
    const COutPoint genesis{Txid::FromUint256(uint256S("41")), 0};
    const CTxOut genesis_output{AuthorityOutput(0x51)};
    view.AddCoin(genesis, Coin(genesis_output, 1, false), false);
    const uint256 genesis_root = ecx::ComputeStateUtxoRoot(
        Params().GetConsensus().hashGenesisBlock,
        genesis,
        genesis_output);
    const ecx::ExchangeConsensus consensus{
        ConfiguredConsensus(30, genesis, genesis_root)};
    CBlock activation;
    activation.nVersion = CBlockHeader::EXCHANGE_STATE_HF_MASK |
        CBlockHeader::FORCED_INBOX_HF_MASK |
        CBlockHeader::DEPOSIT_INBOX_HF_MASK |
        CBlockHeader::INBOX_CURSOR_HF_MASK;
    activation.hashExchangeStateRoot = genesis_root;
    activation.hashForcedInboxRoot = ecx::ComputeForcedInboxGenesis(consensus);
    activation.hashDepositInboxRoot = ecx::ComputeDepositInboxGenesis(consensus);
    activation.ecxParentHeight = 700;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        ecx::ConnectExchangeState(
            activation, nullptr, view, 30, error, consensus, 700),
        error);
    TestBlockIndex activation_index{activation, 30};
    const CKey trader{TestTraderKey()};

    CBlock sixty_four;
    for (uint32_t index = 0; index < ecx::MAX_COMBINED_UNCONSUMED; ++index) {
        CMutableTransaction forced{ForcedCancelTransaction(consensus, trader)};
        forced.nLockTime = index;
        sixty_four.vtx.push_back(MakeTransactionRef(std::move(forced)));
    }
    BOOST_REQUIRE_MESSAGE(
        ecx::PrepareExchangeStateHeader(
            sixty_four, &activation_index, view, 31, error, consensus, 701),
        error);
    BOOST_CHECK_EQUAL(sixty_four.forcedProcessedCursor, 0U);
    BOOST_REQUIRE_MESSAGE(
        ecx::ConnectExchangeState(
            sixty_four, &activation_index, view, 31, error, consensus, 701),
        error);
    TestBlockIndex backlog_index{sixty_four, 31, &activation_index};

    CBlock before_deadline;
    BOOST_REQUIRE_MESSAGE(
        ecx::PrepareExchangeStateHeader(
            before_deadline, &backlog_index, view, 32, error, consensus, 706),
        error);
    BOOST_CHECK_EQUAL(before_deadline.sourceBacklogOldestParentHeight, 701U);
    CBlock at_deadline;
    BOOST_CHECK(!ecx::PrepareExchangeStateHeader(
        at_deadline, &backlog_index, view, 32, error, consensus, 707));
    BOOST_CHECK(error.find("deadline") != std::string::npos);

    CBlock sixty_fifth;
    sixty_fifth.vtx.push_back(MakeTransactionRef(
        ForcedCancelTransaction(consensus, trader)));
    BOOST_CHECK(!ecx::PrepareExchangeStateHeader(
        sixty_fifth, &backlog_index, view, 32, error, consensus, 702));
    BOOST_CHECK(error.find("backlog") != std::string::npos);

    CMutableTransaction missing_marker;
    missing_marker.vin.emplace_back(genesis);
    missing_marker.vout.push_back(AuthorityOutput(0x52));
    CBlock missing_marker_block;
    missing_marker_block.vtx.push_back(MakeTransactionRef(missing_marker));
    BOOST_CHECK(!ecx::PrepareExchangeStateHeader(
        missing_marker_block, &backlog_index, view, 32, error, consensus, 702));
    BOOST_CHECK(error.find("missing") != std::string::npos);

    CMutableTransaction bad_cursor;
    bad_cursor.vin.emplace_back(genesis);
    bad_cursor.vout.push_back(AuthorityOutput(0x53));
    bad_cursor.vout.push_back(CursorMarker(65, 0));
    CBlock bad_cursor_block;
    bad_cursor_block.vtx.push_back(MakeTransactionRef(bad_cursor));
    BOOST_CHECK(!ecx::PrepareExchangeStateHeader(
        bad_cursor_block, &backlog_index, view, 32, error, consensus, 702));
    BOOST_CHECK(error.find("exceeds") != std::string::npos);

    CMutableTransaction consume;
    consume.vin.emplace_back(genesis);
    consume.vout.push_back(AuthorityOutput(0x54));
    consume.vout.push_back(CursorMarker(64, 0));
    CBlock consumed;
    consumed.vtx.push_back(MakeTransactionRef(consume));
    BOOST_REQUIRE_MESSAGE(
        ecx::PrepareExchangeStateHeader(
            consumed, &backlog_index, view, 32, error, consensus, 702),
        error);
    BOOST_CHECK_EQUAL(consumed.forcedProcessedCursor, 64U);
    BOOST_REQUIRE_MESSAGE(
        ecx::ConnectExchangeState(
            consumed, &backlog_index, view, 32, error, consensus, 702),
        error);
    const COutPoint successor{consumed.vtx[0]->GetHash(), 0};
    BOOST_REQUIRE(view.SpendCoin(genesis));
    view.AddCoin(successor, Coin(consumed.vtx[0]->vout[0], 32, false), false);
    TestBlockIndex consumed_index{consumed, 32, &backlog_index};

    CBlock after_advance;
    CMutableTransaction next_forced{ForcedCancelTransaction(consensus, trader)};
    next_forced.nLockTime = 99;
    after_advance.vtx.push_back(MakeTransactionRef(std::move(next_forced)));
    BOOST_REQUIRE_MESSAGE(
        ecx::PrepareExchangeStateHeader(
            after_advance, &consumed_index, view, 33, error, consensus, 703),
        error);
    BOOST_CHECK_EQUAL(after_advance.forcedProcessedCursor, 64U);
}

BOOST_AUTO_TEST_CASE(capital_projection_deployment_preflight_preserves_snapshot)
{
    for (unsigned version : {0U,2U,3U,4U}) for (unsigned mask = 0; mask < 32; ++mask) {
        ecx::ExchangeConsensus consensus{};
        auto& frozen = consensus.bond_v2;
        frozen.deployment_version = version;
        if (!(mask & 1)) frozen.inventory_asset_blinding_factor = uint256S("01");
        if (!(mask & 2)) frozen.inventory_value_blinding_factor = uint256S("01");
        if (!(mask & 4)) frozen.issuance_value_blinding_factor = uint256S("01");
        frozen.activation_enabled = mask & 8;
        frozen.identities_frozen = mask & 16;
        const char* expected = version != 2 && version != 3 ? "unsupported ECX deployment version" :
            version == 3 && (mask & 7) != 7 ? "public ECX deployment requires zero blinders" :
            !(mask & 8) ? "ECX bond V2 activation is disabled" :
            !(mask & 16) ? "ECX bond V2 identities are not source-frozen" : nullptr;
        if (!expected) continue;
        ecx::BondV2CapitalSnapshot snapshot;
        snapshot.exchange_state_root = uint256S("1234");
        std::string error;
        BOOST_CHECK(!ecx::DecodeBondV2CapitalProjection({}, uint256{}, snapshot, error, consensus));
        BOOST_CHECK_EQUAL(error, expected);
        BOOST_CHECK(snapshot.exchange_state_root == uint256S("1234"));
    }
}

BOOST_AUTO_TEST_CASE(haskell_physical_inputs_preserve_native_order)
{
    for (bool public_deployment : {false,true}) {
        std::vector<unsigned> steps;
        for (unsigned i = 0; i < 13; ++i) if (!public_deployment || i < 4 || i > 8) steps.push_back(i);
        for (unsigned mask = 0; mask < 8192; ++mask) {
            std::vector<unsigned> expected, observed;
            bool accepted{true};
            for (unsigned step : steps) {
                expected.push_back(step);
                if (!(mask & (1U << step))) { accepted = false; break; }
            }
            BOOST_CHECK_EQUAL(drivechain::haskell::ExchangePhysicalInputs(public_deployment, [&](uint32_t step) {
                observed.push_back(step);
                return (mask & (1U << step)) != 0;
            }), accepted);
            BOOST_CHECK(observed == expected);
        }
        for (unsigned failed : steps) {
            std::vector<unsigned> observed;
            BOOST_CHECK_THROW(drivechain::haskell::ExchangePhysicalInputs(public_deployment, [&](uint32_t step) {
                observed.push_back(step);
                if (step == failed) throw std::logic_error("physical read");
                return true;
            }), std::logic_error);
            std::vector<unsigned> expected;
            for (unsigned step : steps) { expected.push_back(step); if (step == failed) break; }
            BOOST_CHECK(observed == expected);
        }
    }
}

BOOST_AUTO_TEST_CASE(haskell_required_identity_selection_preserves_order)
{
    for (bool public_deployment : {false,true}) for (bool direct : {false,true}) {
        std::vector<unsigned> required;
        for (unsigned i = 0; i < 45; ++i) {
            if ((public_deployment && i == 44) || (direct && i >= 33 && i <= 38)) continue;
            required.push_back(i);
        }
        for (unsigned missing = 0; missing <= 45; ++missing) {
            const bool rejected = std::find(required.begin(), required.end(), missing) != required.end();
            std::vector<unsigned> expected;
            for (unsigned i : required) { expected.push_back(i); if (i == missing) break; }
            std::vector<unsigned> observed;
            const int code = drivechain::haskell::ExchangeRequiredIdentity(public_deployment, direct, [&](uint32_t i) {
                observed.push_back(i);
                return i != missing;
            });
            BOOST_CHECK_EQUAL(code, rejected ? missing + 1 : 0);
            BOOST_CHECK(observed == expected);
            observed.clear();
            const auto throwing = [&] { return drivechain::haskell::ExchangeRequiredIdentity(public_deployment, direct, [&](uint32_t i) {
                observed.push_back(i);
                if (i == missing) throw std::logic_error("identity read");
                return true;
            }); };
            if (rejected) BOOST_CHECK_THROW(throwing(), std::logic_error);
            else BOOST_CHECK_EQUAL(throwing(), 0);
            BOOST_CHECK(observed == expected);
        }
    }
}

BOOST_AUTO_TEST_CASE(haskell_registry_preserves_native_error_precedence)
{
    for (unsigned mask = 0; mask < 1024; ++mask) for (unsigned duplicate = 0; duplicate < 9; ++duplicate) {
        std::array<std::array<unsigned char, 32>, 5> encryption{}, attestation{};
        for (unsigned i = 0; i < 5; ++i) {
            encryption[i].fill((mask & (1U << i)) ? i + 1 : 0);
            attestation[i].fill((mask & (1U << (i + 5))) ? i + 1 : 0);
        }
        if (duplicate && duplicate < 5) encryption[duplicate] = encryption[0];
        if (duplicate >= 5) attestation[duplicate-4] = attestation[0];
        int expected{0};
        for (size_t i = 0; i < 5 && !expected; ++i) {
            if (encryption[i] == std::array<unsigned char,32>{} || attestation[i] == std::array<unsigned char,32>{}) expected = 1;
            else for (size_t j = 0; j < i; ++j) {
                if (encryption[i] == encryption[j] || attestation[i] == attestation[j]) { expected = 2; break; }
            }
        }
        const auto saved_encryption = encryption, saved_attestation = attestation;
        std::string error{"unchanged"};
        BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeRegistry(encryption, attestation, error), expected == 0);
        BOOST_CHECK_EQUAL(error, expected == 0 ? "unchanged" : expected == 1 ?
            "incomplete frozen ECX bond V2 custodian registry" : "duplicate frozen ECX bond V2 custodian registry key");
        BOOST_CHECK(encryption == saved_encryption && attestation == saved_attestation);
    }
}

BOOST_AUTO_TEST_CASE(haskell_identity_relations_preserve_domain_semantics)
{
    std::array<std::array<unsigned char, 32>, 6> values{};
    std::array<const unsigned char*, 6> identities{};
    for (size_t i = 0; i < values.size(); ++i) identities[i] = values[i].data();
    BOOST_CHECK(drivechain::haskell::ExchangeAbsent(identities));
    BOOST_CHECK(drivechain::haskell::ExchangeAbsent(std::array{values[0].data()}));
    for (auto& key : values) for (auto& byte : key) {
        byte = 1;
        BOOST_CHECK(!drivechain::haskell::ExchangeAbsent(identities));
        BOOST_CHECK(!drivechain::haskell::ExchangeAbsent(std::array{key.data()}));
        byte = 0;
    }
    for (unsigned pattern = 0; pattern < 243; ++pattern) {
        unsigned digits = pattern;
        for (size_t i = 0; i < 5; ++i) { values[i].fill(digits % 3); digits /= 3; }
        const bool expected = std::none_of(values.begin() + 1, values.begin() + 5,
            [&](const auto& value) { return value == values[0]; });
        BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeIsolated(std::span{identities}.first(5)), expected);
    }
    BOOST_CHECK(drivechain::haskell::ExchangeAbsent({}));
    BOOST_CHECK(!drivechain::haskell::ExchangeIsolated({}));
    values[0].fill(1);
    for (size_t i = 1; i < 5; ++i) values[i].fill(2);
    BOOST_CHECK(drivechain::haskell::ExchangeIsolated(std::span{identities}.first(5)));
    BOOST_CHECK(!drivechain::haskell::ExchangeDistinct(std::span{identities}.first(5)));
}

BOOST_AUTO_TEST_CASE(haskell_configuration_identity_sentinels_match_native)
{
    const uint256 zero;
    std::array<uint256,9> values;
    std::array<const unsigned char*,10> identities{zero.begin()};
    for (size_t i=0;i<values.size();++i) identities[i+1]=values[i].begin();
    for (size_t changed=0;changed<values.size();++changed) {
        for (unsigned replacement=0;replacement<=10;++replacement) {
            for (size_t i=0;i<values.size();++i) values[i]=uint256{static_cast<uint8_t>(i+1)};
            values[changed]=uint256{static_cast<uint8_t>(replacement)};
            bool expected=true;
            for (size_t i=0;i<values.size();++i) {
                if (values[i].IsNull()) expected=false;
                for (size_t j=0;j<i;++j) if (values[i]==values[j]) expected=false;
            }
            BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeDistinct(identities),expected);
        }
    }
    std::array<const unsigned char*,6> domains{values[0].begin(),zero.begin(),
        values[1].begin(),values[2].begin(),values[3].begin(),values[4].begin()};
    for (unsigned pattern=0;pattern<243;++pattern) {
        unsigned digits=pattern;
        for (size_t i=0;i<5;++i) { values[i]=uint256{static_cast<uint8_t>(digits%3)}; digits/=3; }
        const bool expected=!values[0].IsNull() &&
            std::none_of(values.begin()+1,values.begin()+5,[&](const auto& value) { return value==values[0]; });
        BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeIsolated(domains),expected);
    }
}

BOOST_AUTO_TEST_CASE(haskell_proof_identity_order_matches_native)
{
    std::array<uint256,5> values;
    std::array<const unsigned char*,5> identities{};
    for (size_t i=0;i<values.size();++i) identities[i]=values[i].begin();
    for (unsigned pattern=0;pattern<7776;++pattern) {
        unsigned digits=pattern;
        for (auto& value : values) { value=uint256{static_cast<uint8_t>(digits%6)}; digits/=6; }
        for (size_t count : {3U,5U}) {
            int expected=0;
            for (size_t i=0;i<count && !expected;++i) {
                if (values[i].IsNull()) expected=1;
                else for (size_t j=i+1;j<count;++j) if (values[i]==values[j]) { expected=2; break; }
            }
            try {
                drivechain::haskell::ExchangeProofIdentities(std::span{identities}.first(count));
                BOOST_CHECK_EQUAL(expected,0);
            } catch (const std::runtime_error& error) {
                BOOST_REQUIRE(expected!=0);
                BOOST_CHECK_EQUAL(error.what(),expected==1 ? "proof program identity is missing" :
                    "incremental proof program identity collides with another proof role");
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(haskell_bond_settings_preserve_lookup_order)
{
    BOOST_CHECK_EQUAL(std::size(ECX_BOND_ARGUMENTS),39);
    for (int missing=-1;missing<40;++missing) for (int fault=-1;fault<40;++fault) {
        unsigned reads=0;
        const int last=missing<0 ? 39 : missing;
        const bool reached=fault>=0 && fault<=last;
        try {
            const auto code=drivechain::haskell::ExchangeBondSettings([&](uint32_t step) {
                BOOST_CHECK_EQUAL(step,reads++);
                if (static_cast<int>(step)==fault) throw std::runtime_error("bond lookup failed");
                return static_cast<int>(step)!=missing;
            });
            BOOST_CHECK(!reached);
            BOOST_CHECK_EQUAL(code,missing<0 ? 0 : missing>36 ? 38 : missing+1);
        } catch (const std::runtime_error& error) {
            BOOST_CHECK(reached);
            BOOST_CHECK_EQUAL(error.what(),"bond lookup failed");
        }
        BOOST_CHECK_EQUAL(reads,1+(reached ? fault : last));
    }
}

BOOST_AUTO_TEST_CASE(haskell_oracle_profile_matches_native)
{
    std::array<std::array<unsigned char,32>,4> truth{};
    std::array<const unsigned char*,4> identities{};
    std::vector<unsigned char> valid{1};
    for (size_t i=0;i<4;++i) {
        truth[i].fill(i+1); identities[i]=truth[i].data();
        valid.insert(valid.end(),truth[i].begin(),truth[i].end());
    }
    const std::array<unsigned,16> widths{8,8,4,8,8,8,4,4,4,4,4,4,4,4,8,8};
    const std::array<uint64_t,16> fields{0,1,1,1,1,1,1,0,1000000,0,9999,9999,499999999,10000,100000000,100000000};
    for (size_t i=0;i<fields.size();++i) for (unsigned b=widths[i];b>0;--b)
        valid.push_back(static_cast<unsigned char>(fields[i] >> ((b-1)*8)));
    BOOST_REQUIRE_EQUAL(valid.size(),221);
    const auto reference=[&](const std::vector<unsigned char>& bytes,uint32_t confirmations) {
        if (bytes[0]!=1) return false;
        for (size_t i=0;i<4;++i) if (!std::equal(truth[i].begin(),truth[i].end(),bytes.begin()+1+i*32) ||
            std::all_of(truth[i].begin(),truth[i].end(),[](auto b) { return b==0; })) return false;
        return ReadBE64(bytes.data()+137)>0 && ReadBE32(bytes.data()+145)>0 && ReadBE32(bytes.data()+145)<=confirmations &&
            ReadBE64(bytes.data()+149)>0 && ReadBE64(bytes.data()+157)>0 && ReadBE64(bytes.data()+165)>0 &&
            ReadBE32(bytes.data()+173)>0 && ReadBE32(bytes.data()+177)<=ReadBE32(bytes.data()+181) &&
            ReadBE32(bytes.data()+181)<=1000000 && ReadBE32(bytes.data()+185)<=ReadBE32(bytes.data()+189) &&
            ReadBE32(bytes.data()+189)<10000 && ReadBE32(bytes.data()+193)<10000 &&
            ReadBE32(bytes.data()+197)<500000000 && ReadBE32(bytes.data()+201)>0 && ReadBE32(bytes.data()+201)<=10000 &&
            ReadBE64(bytes.data()+205)>0 && ReadBE64(bytes.data()+213)>0;
    };
    for (size_t offset=0;offset<valid.size();++offset) for (unsigned replacement : {0U,1U,255U}) {
        auto bytes=valid; bytes[offset]=replacement;
        for (uint32_t confirmations : {0U,1U,6U,UINT32_MAX}) {
            std::array<uint64_t,2> prices{123,456};
            const bool expected=reference(bytes,confirmations);
            BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeOracleProfile(confirmations,bytes,identities,prices),expected);
            BOOST_CHECK_EQUAL(prices[0],expected ? ReadBE64(bytes.data()+205) : 123);
            BOOST_CHECK_EQUAL(prices[1],expected ? ReadBE64(bytes.data()+213) : 456);
        }
    }
    std::array<uint64_t,2> prices{123,456};
    truth[0].fill(0);
    std::fill_n(valid.begin()+1,32,0);
    BOOST_CHECK(!drivechain::haskell::ExchangeOracleProfile(6,valid,identities,prices));
    valid.pop_back();
    BOOST_CHECK_THROW(drivechain::haskell::ExchangeOracleProfile(6,valid,identities,prices),std::runtime_error);
    BOOST_CHECK_EQUAL(prices[0],123);
    BOOST_CHECK_EQUAL(prices[1],456);
}

BOOST_AUTO_TEST_CASE(haskell_truthcoin_profile_matches_native)
{
    std::vector<unsigned char> valid(390,1); valid[0]=3;
    WriteBE32(valid.data()+386,16777216);
    const auto reference=[](const std::vector<unsigned char>& bytes) {
        if (bytes[0]!=3 || bytes[85]==0 || ReadBE64(bytes.data()+118)==0 ||
            ReadBE32(bytes.data()+382)==0 || ReadBE32(bytes.data()+386)==0 || ReadBE32(bytes.data()+386)>16777216) return false;
        if (std::all_of(bytes.begin()+1,bytes.begin()+21,[](auto b) { return b==0; })) return false;
        for (size_t offset : {21U,53U,86U,126U,158U,190U,222U,254U,286U,318U,350U})
            if (std::all_of(bytes.begin()+offset,bytes.begin()+offset+32,[](auto b) { return b==0; })) return false;
        return true;
    };
    const auto check=[&](const std::vector<unsigned char>& bytes) {
        std::array<unsigned char,164> fields; fields.fill(0xa5);
        const bool expected=reference(bytes);
        BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeTruthcoinProfile(bytes,fields),expected);
        if (expected) {
            BOOST_CHECK(std::equal(fields.begin(),fields.begin()+160,bytes.begin()+190));
            BOOST_CHECK(std::equal(fields.begin()+160,fields.end(),bytes.begin()+382));
        } else BOOST_CHECK(std::all_of(fields.begin(),fields.end(),[](auto b) { return b==0xa5; }));
    };
    check(valid);
    for (size_t offset=0;offset<390;++offset) for (unsigned replacement : {0U,1U,255U}) {
        auto bytes=valid; bytes[offset]=replacement; check(bytes);
    }
    for (size_t offset : {21U,53U,86U,126U,158U,190U,222U,254U,286U,318U,350U}) {
        auto bytes=valid; std::fill_n(bytes.begin()+offset,32,0); check(bytes);
    }
    for (auto [offset,size] : {std::pair{1U,20U},std::pair{118U,8U},std::pair{382U,4U},std::pair{386U,4U}}) {
        auto bytes=valid; std::fill_n(bytes.begin()+offset,size,0); check(bytes);
    }
    std::array<unsigned char,164> fields;
    valid.pop_back();
    BOOST_CHECK_THROW(drivechain::haskell::ExchangeTruthcoinProfile(valid,fields),std::runtime_error);
}

BOOST_AUTO_TEST_CASE(haskell_checkpoint_profiles_match_native)
{
    std::array<unsigned char,32> policy; policy.fill(3);
    for (bool anchor : {false,true}) {
        std::vector<unsigned char> valid(73,1);
        const size_t second=anchor ? 41 : 33, age=anchor ? 33 : 65;
        std::fill_n(valid.begin()+second,32,2); WriteBE64(valid.data()+age,1);
        const auto check=[&](const std::vector<unsigned char>& bytes) {
            const auto nonzero=[&](size_t offset) { return std::any_of(bytes.begin()+offset,bytes.begin()+offset+32,[](auto b) { return b!=0; }); };
            const bool expected=bytes[0]==1 && nonzero(1) && nonzero(second) && ReadBE64(bytes.data()+age)>0 &&
                (anchor ? !std::equal(policy.begin(),policy.end(),bytes.begin()+1) :
                 !std::equal(bytes.begin()+1,bytes.begin()+33,bytes.begin()+second) && ReadBE64(bytes.data()+age)<=1123200);
            std::array<unsigned char,64> output; output.fill(0xa5);
            BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeCheckpointProfile(anchor,bytes,policy,output),expected);
            if (expected) {
                BOOST_CHECK(std::equal(output.begin(),output.begin()+32,bytes.begin()+1));
                BOOST_CHECK(std::equal(output.begin()+32,output.end(),bytes.begin()+second));
            } else BOOST_CHECK(std::all_of(output.begin(),output.end(),[](auto b) { return b==0xa5; }));
        };
        check(valid);
        for (size_t i=0;i<73;++i) for (unsigned replacement : {0U,1U,255U}) { auto bytes=valid; bytes[i]=replacement; check(bytes); }
        for (uint64_t value : {uint64_t{0},uint64_t{1},uint64_t{1123200},uint64_t{1123201},UINT64_MAX}) {
            auto bytes=valid; WriteBE64(bytes.data()+age,value); check(bytes);
        }
        for (size_t offset : {size_t{1},second}) { auto bytes=valid; std::fill_n(bytes.begin()+offset,32,0); check(bytes); }
        auto bytes=valid; std::copy_n(bytes.begin()+1,32,bytes.begin()+second); check(bytes);
        bytes=valid; std::copy(policy.begin(),policy.end(),bytes.begin()+1); check(bytes);
        std::array<unsigned char,64> output;
        bytes.pop_back();
        BOOST_CHECK_THROW(drivechain::haskell::ExchangeCheckpointProfile(anchor,bytes,policy,output),std::runtime_error);
    }
}


BOOST_AUTO_TEST_CASE(haskell_successor_scan_matches_native_search)
{
    for (unsigned count=0;count<=3;++count) for (unsigned pattern=0;pattern<(1U<<(3*count));++pattern)
        for (unsigned flags=0;flags<16;++flags) {
            std::vector<unsigned> candidates(count);
            for (unsigned i=0;i<count;++i) candidates[i]=(pattern>>(3*i))&7;
            std::optional<unsigned> expected_match,match;
            unsigned expected_status=0,index=0;
            for (unsigned i=0;i<count;++i) if (candidates[i]==7) {
                if (expected_match) { expected_status=1; break; }
                expected_match=i;
            }
            if (!expected_status) expected_status=!expected_match || !(flags&1) ? 2 : flags==15 ? 0 : 3;
            const auto status=drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::SUCCESSOR_SCAN,
                [&](uint32_t step) -> uint32_t {
                    if (step>=2 && step<=5) BOOST_REQUIRE(index<count);
                    switch (step) {
                    case 1: return index<count;
                    case 2: return candidates[index]&1;
                    case 3: return (candidates[index]&2)!=0;
                    case 4:
                        BOOST_CHECK(drivechain::haskell::ExchangeDistinct(std::array<const unsigned char*,0>{}));
                        return (candidates[index]&4)!=0;
                    case 5: return match.has_value();
                    case 6: ++index; return 1;
                    case 7: return match.has_value();
                    case 8: match=index; return 1;
                    default: return (flags & (1U<<(step-9)))!=0;
                    }
                });
            BOOST_CHECK_EQUAL(status,expected_status);
            BOOST_CHECK(match==expected_match);
        }
}

BOOST_AUTO_TEST_CASE(haskell_carry_identities_match_both_profiles)
{
    for (uint32_t profile : {0U,1U}) {
        std::array<uint256,15> hashes;
        for (unsigned i=6;i<15;++i) std::fill(hashes[i].begin(),hashes[i].end(),i);
        for (unsigned i=0;i<3;++i) hashes[i]=hashes[(profile ? 9 : 6)+i];
        for (unsigned i=3;i<6;++i) hashes[i]=hashes[9+i];
        std::array<const unsigned char*,15> pointers;
        for (unsigned i=0;i<15;++i) pointers[i]=hashes[i].begin();
        const auto original=[&] {
            return hashes[0]==hashes[profile ? 9 : 6] && hashes[1]==hashes[profile ? 10 : 7] &&
                hashes[2]==hashes[profile ? 11 : 8] && hashes[3]==hashes[12] && hashes[4]==hashes[13] && hashes[5]==hashes[14];
        };
        BOOST_CHECK(drivechain::haskell::ExchangeCarryIdentity(profile,pointers));
        for (auto& hash : hashes) for (auto& byte : hash) {
            byte^=1;
            BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeCarryIdentity(profile,pointers),original());
            byte^=1;
        }
        BOOST_CHECK(!drivechain::haskell::ExchangeCarryIdentity(2,pointers));
        BOOST_CHECK(!drivechain::haskell::ExchangeCarryIdentity(UINT32_MAX,pointers));
    }
}

BOOST_AUTO_TEST_CASE(haskell_capital_context_order_and_faults)
{
    for (bool incremental : {false,true}) {
        const auto flow=incremental ? drivechain::haskell::ReplayStoreFlow::INCREMENTAL_CONTEXT : drivechain::haskell::ReplayStoreFlow::FINITE_CONTEXT;
        std::vector<unsigned> steps;
        const unsigned start=incremental ? 7 : 1;
        for (unsigned step=start;step<start+6;++step) steps.push_back(step);
        for (unsigned step=13;step<=(incremental ? 16U : 17U);++step) steps.push_back(step);
        for (unsigned mask=0;mask<(1U<<steps.size());++mask) {
            unsigned expected_reads=0,expected_status=0,reads=0;
            for (const auto step : steps) {
                if (!(mask & (1U << expected_reads++))) { expected_status=step<=start+1 ? 1 : step==start+2 ? 2 : 3; break; }
            }
            const auto status=drivechain::haskell::ParentReplayStore(flow,[&](uint32_t step) -> uint32_t {
                BOOST_REQUIRE(reads<steps.size());
                BOOST_CHECK_EQUAL(step,steps[reads]);
                return (mask & (1U << reads++))!=0;
            });
            BOOST_CHECK_EQUAL(status,expected_status);
            BOOST_CHECK_EQUAL(reads,expected_reads);
        }
        for (const auto fault : steps) {
            std::vector<unsigned> seen;
            BOOST_CHECK_EXCEPTION(drivechain::haskell::ParentReplayStore(flow,[&](uint32_t step) -> uint32_t {
                seen.push_back(step);
                BOOST_CHECK(drivechain::haskell::ExchangeDistinct(std::array<const unsigned char*,0>{}));
                if (step==fault) throw std::logic_error("capital context fault");
                return 1;
            }),std::logic_error,[](const auto& error) { return std::string(error.what())=="capital context fault"; });
            BOOST_CHECK(seen==std::vector<unsigned>(steps.begin(),std::find(steps.begin(),steps.end(),fault)+1));
        }
    }
}

BOOST_AUTO_TEST_CASE(haskell_activation_predecessor_order_and_faults)
{
    for (unsigned mask=0;mask<1024;++mask) {
        unsigned expected_reads=0,expected_status=0,reads=0;
        for (unsigned step=1;step<=10;++step) {
            ++expected_reads;
            if (!(mask & (1U << (step-1)))) { expected_status=step<=8 ? 1 : 2; break; }
        }
        const auto status=drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::ACTIVATION_PREDECESSOR,
            [&](uint32_t step) -> uint32_t {
                BOOST_CHECK_EQUAL(step,++reads);
                BOOST_CHECK(drivechain::haskell::ExchangeDistinct(std::array<const unsigned char*,0>{}));
                return (mask & (1U << (step-1)))!=0;
            });
        BOOST_CHECK_EQUAL(status,expected_status);
        BOOST_CHECK_EQUAL(reads,expected_reads);
    }
    for (unsigned fault=1;fault<=10;++fault) {
        unsigned reads=0;
        BOOST_CHECK_EXCEPTION(drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::ACTIVATION_PREDECESSOR,
            [&](uint32_t step) -> uint32_t { ++reads; if (step==fault) throw std::logic_error("predecessor fault"); return 1; }),
            std::logic_error,[](const auto& error) { return std::string(error.what())=="predecessor fault"; });
        BOOST_CHECK_EQUAL(reads,fault);
    }
}

BOOST_AUTO_TEST_CASE(haskell_public_issuance_scan_matches_native_order)
{
    for (unsigned count=0;count<5;++count) for (unsigned bad=0;bad<=count;++bad)
        for (unsigned kind : {25U,26U}) for (unsigned failed=0;failed<=23;++failed) {
            std::vector<unsigned> expected,seen;
            for (unsigned step=1;step<=(failed ? failed : 23);++step) expected.push_back(step);
            if (!failed) for (unsigned index=0;;++index) {
                expected.push_back(24);
                if (index==count) break;
                expected.push_back(25);
                expected.push_back(28);
                if (index==bad && kind==25) break;
                expected.push_back(26);
                expected.push_back(29);
                if (index==bad) break;
                expected.push_back(27);
            }
            unsigned index=0;
            const auto status=drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::PUBLIC_BOND_ISSUANCE,
                [&](uint32_t step) -> uint32_t {
                    seen.push_back(step);
                    BOOST_CHECK(drivechain::haskell::ExchangeDistinct(std::array<const unsigned char*,0>{}));
                    if (step<=23) return step!=failed;
                    if (step==24) return index<count;
                    if (step==27) { ++index; return 1; }
                    if (step==25 || step==26) return 0;
                    return step-3!=kind || index!=bad;
                });
            BOOST_CHECK_EQUAL(status,failed || bad<count ? 1U : 0U);
            BOOST_CHECK(seen==expected);
        }
    std::vector<unsigned> path;
    for (unsigned step=1;step<=25;++step) path.push_back(step);
    for (unsigned step : {28U,26U,29U,27U}) path.push_back(step);
    for (unsigned fault=1;fault<=29;++fault) {
        std::vector<unsigned> reads;
        BOOST_CHECK_EXCEPTION(drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::PUBLIC_BOND_ISSUANCE,
            [&](uint32_t step) -> uint32_t {
                reads.push_back(step);
                if (step==fault) throw std::logic_error("public issuance fault");
                return step!=25 && step!=26;
            }),
            std::logic_error,[](const auto& error) { return std::string(error.what())=="public issuance fault"; });
        const auto end=std::find(path.begin(),path.end(),fault)+1;
        BOOST_CHECK_EQUAL_COLLECTIONS(reads.begin(),reads.end(),path.begin(),end);
    }
}

BOOST_AUTO_TEST_CASE(haskell_public_issuance_output_short_circuit)
{
    for (unsigned mask=0;mask<16;++mask) {
        std::vector<unsigned> expected,seen;
        const auto fact=[&](unsigned step) {
            const unsigned bit=step==25 ? 0 : step==28 ? 1 : step==26 ? 2 : 3;
            return bool(mask & (1U<<bit));
        };
        const auto read=[&](unsigned step) { expected.push_back(step); return fact(step); };
        const bool accepted=(read(25) || read(28)) && (read(26) || read(29));
        unsigned index=0;
        const auto status=drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::PUBLIC_BOND_ISSUANCE,
            [&](uint32_t step) -> uint32_t {
                if (step<=23) return 1;
                if (step==24) return index==0;
                if (step==27) { ++index; return 1; }
                seen.push_back(step);
                return fact(step);
            });
        BOOST_CHECK_EQUAL(status,accepted ? 0U : 1U);
        BOOST_CHECK_EQUAL(index,accepted ? 1U : 0U);
        BOOST_CHECK(seen==expected);
    }
}

BOOST_AUTO_TEST_CASE(haskell_bond_issuance_order_and_faults)
{
    for (unsigned failed=0;failed<=17;++failed) for (unsigned fault=0;fault<=17;++fault) {
        unsigned reads=0;
        const auto run=[&] {
            return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::BOND_ISSUANCE,
                [&](uint32_t step) -> uint32_t {
                    BOOST_CHECK_EQUAL(step,++reads);
                    BOOST_CHECK(drivechain::haskell::ExchangeDistinct(std::array<const unsigned char*,0>{}));
                    if (step==fault) throw std::logic_error("bond issuance fault");
                    return step!=failed;
                });
        };
        const unsigned last=failed ? failed : 17;
        if (fault && fault<=last) {
            BOOST_CHECK_EXCEPTION(run(),std::logic_error,[](const auto& error) { return std::string(error.what())=="bond issuance fault"; });
            BOOST_CHECK_EQUAL(reads,fault);
        } else { BOOST_CHECK_EQUAL(run(),failed ? 1U : 0U); BOOST_CHECK_EQUAL(reads,last); }
    }
}

BOOST_AUTO_TEST_CASE(haskell_issuance_actions_can_call_haskell_after_resume)
{
    for (int fault=-1;fault<8;++fault) {
        unsigned reads=0; std::string error="unchanged";
        const auto run=[&] {
            return drivechain::haskell::ExchangeTransactionShape(drivechain::haskell::TransactionShape::ISSUANCE,
                [&](uint32_t step) {
                    BOOST_CHECK_EQUAL(step,reads++);
                    BOOST_CHECK(drivechain::haskell::ExchangeDistinct(std::array<const unsigned char*,0>{}));
                    if (static_cast<int>(step)==fault) throw std::logic_error("resumed issuance fault");
                    return true;
                },error);
        };
        if (fault<0) BOOST_CHECK(run());
        else BOOST_CHECK_EXCEPTION(run(),std::logic_error,[](const auto& exception) {
            return std::string(exception.what())=="resumed issuance fault";
        });
        BOOST_CHECK_EQUAL(reads,fault<0 ? 8U : static_cast<unsigned>(fault+1));
        BOOST_CHECK_EQUAL(error,"unchanged");
    }
}

BOOST_AUTO_TEST_CASE(haskell_deployment_arguments_short_circuit)
{
    using drivechain::haskell::TransactionShape;
    for (unsigned mask=0;mask<2048;++mask) {
        unsigned failed=0;
        while (failed<11 && (mask & (1U<<failed))) ++failed;
        unsigned reads=0; std::string error="unchanged";
        BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeTransactionShape(TransactionShape::DEPLOYMENT_ARGUMENTS,
            [&](uint32_t step) { BOOST_CHECK_EQUAL(step,reads++); return (mask & (1U<<step))!=0; },error),failed==11);
        BOOST_CHECK_EQUAL(reads,std::min(failed+1,11U));
        BOOST_CHECK_EQUAL(error,failed==11 ? "unchanged" : "ECX bond V2 deployment transaction shape is invalid");
    }
    for (unsigned fault=0;fault<11;++fault) {
        unsigned reads=0; std::string error="unchanged";
        BOOST_CHECK_EXCEPTION(drivechain::haskell::ExchangeTransactionShape(TransactionShape::DEPLOYMENT_ARGUMENTS,
            [&](uint32_t step) { ++reads; if (step==fault) throw std::logic_error("shape read"); return true; },error),
            std::logic_error,[](const auto& exception) { return std::string(exception.what())=="shape read"; });
        BOOST_CHECK_EQUAL(reads,fault+1);
        BOOST_CHECK_EQUAL(error,"unchanged");
    }
}

BOOST_AUTO_TEST_CASE(haskell_frozen_admission_order_and_reentry)
{
    using namespace drivechain::haskell;
    const std::array<std::vector<uint32_t>,3> paths{{{1,2,7,8,9,10,11},{1,2,3,4,5,7,8,9,10,11},{1,2,3,4,5,6,7,8,9,10,11}}};
    const std::map<uint32_t,uint32_t> errors{{4,12},{6,13},{8,14},{9,15}};
    for (size_t mode=0;mode<paths.size();++mode) for (uint32_t failure=0;failure<=11;++failure) {
        if (failure==2 || failure==5) continue;
        for (bool throws : {false,true}) {
            std::vector<uint32_t> expected,actual;
            bool expected_throw=false,actual_throw=false;
            uint32_t expected_status=0,actual_status=0;
            for (auto step : paths[mode]) {
                expected.push_back(step);
                if (step!=failure) continue;
                expected_status=1; expected_throw=throws;
                if (!throws && errors.contains(step)) expected.push_back(errors.at(step));
                break;
            }
            try {
                actual_status=ParentReplayStore(ReplayStoreFlow::FROZEN_ADMISSION,[&](uint32_t step) -> uint32_t {
                    actual.push_back(step);
                    if (step==failure) {
                        if (throws) throw std::runtime_error("frozen admission failure");
                        return 0;
                    }
                    if (step==2) return mode!=0;
                    if (step==5) return mode==2;
                    if (step==1) {
                        std::string error;
                        BOOST_REQUIRE(ExchangeDeployment(2,[](uint32_t) { return true; },error));
                    }
                    return 1;
                });
            } catch (const std::runtime_error& error) {
                BOOST_CHECK_EQUAL(error.what(),"frozen admission failure"); actual_throw=true;
            }
            BOOST_CHECK(actual==expected);
            BOOST_CHECK_EQUAL(actual_throw,expected_throw);
            if (!expected_throw) BOOST_CHECK_EQUAL(actual_status,expected_status);
        }
    }
}

#include <test/activation_facts_reference.h>

BOOST_AUTO_TEST_CASE(haskell_hash_argument_catalog)
{
    const std::array expected{
        "-ecxbondv2publicstatedomain", "-ecxbondv2statenodedomain", "-ecxbondv2journaldomain", "-ecxbondv2transitioncmr",
        "-ecxbondv2incrementalactivationprogramid", "-ecxbondv2incrementalactivationconfigurationhash", "-ecxbondv2incrementalactivationcmr",
        "-ecxbondv2incrementalsuccessorprogramid", "-ecxbondv2incrementalsuccessorconfigurationhash", "-ecxbondv2incrementalsuccessortransitioncmr",
        "-ecxbondv2incrementalsuccessorstatenodedomain", "-ecxbondv2inventorycmr", "-ecxbondv2queuecmr", "-ecxbondv2ecxbtcprogramid",
        "-ecxbondv2ecxbtcredemptioncovenant", "-ecxbondv2ecxbtcsourcecheckpoint", "-ecxbondv2usddusdprogramid",
        "-ecxbondv2usddusdredemptioncovenant", "-ecxbondv2usddusdsourcecheckpoint", "-ecxbondv2matcherreceipt",
        "-ecxbondv2orderreceiptsroot", "-ecxbondv2availabilityroot"};
    BOOST_REQUIRE_EQUAL(ECX_BOND_HASH_ARGUMENTS.size(), expected.size());
    ArgsManager args;
    for (size_t i=0;i<expected.size();++i) {
        BOOST_CHECK_EQUAL(ECX_BOND_HASH_ARGUMENTS[i],expected[i]);
        args.AddArg(expected[i], "", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
        args.ForceSetArg(expected[i],HexStr(std::vector<unsigned char>(32,i+1)));
    }
    size_t published{0};
    const auto failure=drivechain::haskell::ParseHashArguments(false,
        [&](uint32_t index) { return args.GetArg(ECX_BOND_HASH_ARGUMENTS.at(index), ""); },
        [&](uint32_t index,std::span<const unsigned char,32> bytes) {
            BOOST_CHECK_EQUAL(index,published++);
            BOOST_CHECK(std::all_of(bytes.begin(),bytes.end(),[&](auto byte) { return byte==index+1; }));
        });
    BOOST_CHECK(!failure);
    BOOST_CHECK_EQUAL(published,expected.size());
}

BOOST_AUTO_TEST_CASE(haskell_hash_arguments_preserve_partial_updates)
{
    using namespace drivechain::haskell;
    for (bool direct : {false,true}) for (uint32_t fault=0;fault<=22;++fault) for (bool malformed : {false,true}) {
        std::array<std::vector<unsigned char>,22> fields;
        std::vector<uint32_t> seen;
        const bool accepted=!fault || (!malformed && direct && fault>=14 && fault<=19);
        const auto failure=ParseHashArguments(direct,[&](uint32_t index) {
            seen.push_back(index+1);
            return index+1==fault ? (malformed ? std::string("bad") : std::string(64,'0')) : std::string(64,'1');
        },[&](uint32_t index,std::span<const unsigned char,32> bytes) { fields.at(index).assign(bytes.begin(),bytes.end()); });
        BOOST_CHECK_EQUAL(!failure,accepted);
        if (failure) { BOOST_CHECK_EQUAL(failure->first+1,fault); BOOST_CHECK_EQUAL(failure->second,!malformed); }
        BOOST_CHECK_EQUAL(seen.size(),accepted ? 22 : fault);
        for (uint32_t i=0;i<22;++i) {
            if (accepted || i+1<fault) BOOST_CHECK(fields[i]==std::vector<unsigned char>(32,i+1==fault ? 0 : 0x11));
            else BOOST_CHECK(fields[i].empty());
        }
    }
}

BOOST_AUTO_TEST_CASE(haskell_hash_arguments_stop_on_native_exceptions)
{
    for (uint32_t fault=0;fault<22;++fault) for (bool publication : {false,true}) {
        std::vector<uint32_t> seen;
        BOOST_CHECK_EXCEPTION(drivechain::haskell::ParseHashArguments(false,[&](uint32_t index) {
            seen.push_back(2*index);
            if (!publication && index==fault) throw std::logic_error("read fault");
            return std::string(64,'1');
        },[&](uint32_t index,std::span<const unsigned char,32>) {
            seen.push_back(2*index+1);
            if (publication && index==fault) throw std::logic_error("publish fault");
        }),std::logic_error,[&](const std::logic_error& e) { return std::string(e.what())==(publication ? "publish fault" : "read fault"); });
        BOOST_CHECK_EQUAL(seen.size(),2*fault+(publication ? 2 : 1));
        for (size_t i=0;i<seen.size();++i) BOOST_CHECK_EQUAL(seen[i],i);
    }
}

BOOST_AUTO_TEST_CASE(haskell_configuration_binding_preserves_order)
{
    using namespace drivechain::haskell;
    for (uint32_t failed=0;failed<=8;++failed) for (bool throws : {false,true}) {
        std::vector<uint32_t> seen,expected;
        for (uint32_t step=1;step<=(failed ? failed : 8);++step) expected.push_back(step);
        if (failed && !throws) expected.push_back(failed==1 ? 9 : 10);
        try {
            auto result=ParentReplayStore(ReplayStoreFlow::CONFIGURATION_BINDING,[&](uint32_t step) -> uint32_t {
                seen.push_back(step);
                if (step==4) {
                    auto bytes=ParseConfigurationField(ConfigurationField::NONZERO_HASH,std::string(64,'1'),"bad hex","zero hash");
                    BOOST_REQUIRE_EQUAL(bytes.size(),32);
                }
                if (step==failed) { if (throws) throw std::logic_error("binding fault"); return 0; }
                return 1;
            });
            BOOST_CHECK(!failed || !throws);
            BOOST_CHECK_EQUAL(result,failed ? 1 : 0);
        } catch (const std::logic_error& e) {
            BOOST_REQUIRE(failed && throws);
            BOOST_CHECK_EQUAL(e.what(),"binding fault");
        }
        BOOST_CHECK(seen==expected);
    }
}

BOOST_AUTO_TEST_CASE(haskell_configuration_binding_preserves_nested_parse_error)
{
    using namespace drivechain::haskell;
    std::vector<uint32_t> seen;
    BOOST_CHECK_EXCEPTION(ParentReplayStore(ReplayStoreFlow::CONFIGURATION_BINDING,[&](uint32_t step) -> uint32_t {
        seen.push_back(step);
        if (step==4) ParseConfigurationField(ConfigurationField::NONZERO_HASH,"invalid","bad hex","zero hash");
        return 1;
    }),std::runtime_error,[](const std::runtime_error& e) { return std::string(e.what())=="bad hex"; });
    BOOST_CHECK((seen==std::vector<uint32_t>{1,2,3,4}));
}

BOOST_AUTO_TEST_CASE(haskell_startup_deployment_preserves_order)
{
    using namespace drivechain::haskell;
    const auto failure_action=[](uint32_t step) {
        for (auto [limit,code] : std::array<std::pair<uint32_t,uint32_t>,11>{{{5,54},{9,55},{17,56},{23,57},{30,58},{36,59},{37,60},{39,61},{44,62},{52,63},{53,64}}})
            if (step<=limit) return code;
        return uint32_t{0};
    };
    for (bool public_deployment : {false,true}) for (uint32_t failed=0;failed<=53;++failed) for (bool throws : {false,true}) {
        if (failed==11) continue;
        std::vector<uint32_t> path,seen;
        for (uint32_t step=1;step<=53;++step) if (!public_deployment || step<12 || step>17) path.push_back(step);
        auto position=std::find(path.begin(),path.end(),failed);
        const bool reached=position!=path.end();
        auto expected=path;
        if (reached) {
            expected.erase(expected.begin()+std::distance(path.begin(),position)+1,expected.end());
            if (!throws && failed!=6 && failed!=10 && failed!=24 && failed!=31 && failed!=38) expected.push_back(failure_action(failed));
        }
        try {
            const auto status=ParentReplayStore(ReplayStoreFlow::STARTUP_DEPLOYMENT,[&](uint32_t step) -> uint32_t {
                seen.push_back(step);
                if (step==3) {
                    const auto verify=[&](bool selected_public) {
                        BOOST_REQUIRE_EQUAL(selected_public,public_deployment);
                        if (step==failed) { if (throws) throw std::logic_error("startup fault"); return false; }
                        BOOST_REQUIRE(ExchangeDeploymentOutputs(0,1,[](uint64_t) -> uint64_t { throw std::logic_error("skipped read"); }));
                        return true;
                    };
                    return ParentReplayChoose({[&] { return public_deployment; },
                        [&] { return verify(true); }, [&] { return verify(false); }});
                }
                if (step==failed) { if (throws) throw std::logic_error("startup fault"); return 0; }
                if (step==11) return public_deployment;
                if (step==37 || step==53)
                    BOOST_REQUIRE(ExchangeDeploymentOutputs(0,1,[](uint64_t) -> uint64_t { throw std::logic_error("skipped read"); }));
                return 1;
            });
            BOOST_CHECK(!throws || !reached);
            BOOST_CHECK_EQUAL(status,reached ? 1 : 0);
        } catch (const std::logic_error& e) {
            BOOST_REQUIRE(throws && reached);
            BOOST_CHECK_EQUAL(e.what(),"startup fault");
        }
        BOOST_CHECK(seen==expected);
    }
}

BOOST_AUTO_TEST_CASE(haskell_configuration_gates_preserve_effects)
{
    using drivechain::haskell::ParentReplayChoose;
    for (bool enabled : {false,true}) {
        unsigned configured=0;
        BOOST_CHECK(ParentReplayChoose({[&] { return enabled; },
            [&] { ++configured; return true; }, [] { return true; }}));
        BOOST_CHECK_EQUAL(configured,enabled ? 1U : 0U);
        const auto configure=[&] {
            return ParentReplayChoose({[&] { return enabled; },
                []() -> bool { throw std::runtime_error("configuration failure"); }, [] { return true; }});
        };
        if (enabled) BOOST_CHECK_THROW(configure(),std::runtime_error);
        else BOOST_CHECK(configure());
    }
    for (bool matches : {false,true}) {
        std::string error="unchanged";
        BOOST_CHECK_EQUAL(ParentReplayChoose({[&] { return matches; }, [] { return true; },
            [&] { error="commitment mismatch"; return false; }}),matches);
        BOOST_CHECK_EQUAL(error,matches ? "unchanged" : "commitment mismatch");
    }
}

BOOST_AUTO_TEST_CASE(haskell_activation_cursor_selection_is_lazy_and_full_width)
{
    for (bool activation : {false,true}) for (uint64_t source : {uint64_t{0},uint64_t{1},UINT64_MAX}) {
        const uint64_t* previous=activation ? nullptr : &source;
        uint64_t value=0;
        unsigned reads=0;
        BOOST_CHECK(drivechain::haskell::ParentReplayChoose({[&] { return activation; }, [] { return true; },
            [&] { ++reads; BOOST_REQUIRE(previous!=nullptr); value=*previous; return true; }}));
        BOOST_CHECK_EQUAL(reads,activation ? 0U : 1U);
        BOOST_CHECK_EQUAL(value,activation ? 0 : source);
    }
}

BOOST_AUTO_TEST_CASE(haskell_tracker_height_preserves_signed_bounds)
{
    using drivechain::haskell::ExchangeTrackerHeight;
    for (int32_t height : {INT32_MIN,INT32_MIN+1,-1,0,1,INT32_MAX}) {
        BOOST_CHECK_EQUAL(ExchangeTrackerHeight(false,height),std::max(height,int32_t{0}));
        if (height==INT32_MIN) BOOST_CHECK_THROW(ExchangeTrackerHeight(true,height),std::runtime_error);
        else BOOST_CHECK_EQUAL(ExchangeTrackerHeight(true,height),int64_t{height}-1);
    }
}

BOOST_AUTO_TEST_CASE(haskell_deployment_output_classification)
{
    for (uint64_t flags=0;flags<512;++flags) {
        const bool asset=flags&1, value=flags&2, nonce=flags&4, bond=flags&8,
            token=flags&16, usdd=flags&32, nonzero=flags&64, burn=flags&128;
        const bool expected=flags<256 && !(!asset || !value || !nonce || bond ||
            (token && !burn) || (usdd && nonzero));
        std::vector<uint64_t> seen;
        BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeDeploymentOutputs(0,2,[&](uint64_t index) {
            seen.push_back(index); return flags;
        }),expected);
        BOOST_CHECK(seen==std::vector<uint64_t>{1});
    }
    std::vector<uint64_t> seen;
    BOOST_CHECK(!drivechain::haskell::ExchangeDeploymentOutputs(1,4,[&](uint64_t index) {
        seen.push_back(index); return index==2 ? 0 : 7;
    }));
    BOOST_CHECK((seen==std::vector<uint64_t>{0,2}));
    BOOST_CHECK(drivechain::haskell::ExchangeDeploymentOutputs(0,1,[](uint64_t) -> uint64_t { throw std::logic_error("skipped"); }));
    BOOST_CHECK_THROW(drivechain::haskell::ExchangeDeploymentOutputs(1,1,[](uint64_t) { return 7; }),std::runtime_error);
    BOOST_CHECK_THROW(drivechain::haskell::ExchangeDeploymentOutputs(0,2,[](uint64_t) -> uint64_t { throw std::logic_error("read failure"); }),std::logic_error);
}

BOOST_AUTO_TEST_CASE(haskell_runtime_identities_match_previous_predicates)
{
    std::array<uint256,16> baseline;
    for (size_t i=0;i<16;++i) std::fill(baseline[i].begin(),baseline[i].end(),i+1);
    for (size_t i=2;i<16;i+=2) baseline[i+1]=baseline[i];
    const auto check=[](const auto& h) {
        const bool rejected=h[0]==h[1] || h[2]!=h[3] || h[4]!=h[5] || h[6]!=h[7] ||
            h[8]!=h[9] || h[10]!=h[11] || h[12]!=h[13] || h[14]!=h[15];
        std::array<const unsigned char*,16> pointers;
        for (size_t i=0;i<16;++i) pointers[i]=h[i].begin();
        try { drivechain::haskell::ExchangeRuntimeIdentities(pointers); BOOST_CHECK(!rejected); }
        catch (const std::runtime_error& e) {
            BOOST_REQUIRE(rejected);
            BOOST_CHECK_EQUAL(e.what(),"runtime proof/matcher identities differ from FrozenConfigurationV2/V18");
        }
    };
    check(baseline);
    for (size_t i=0;i<16;++i) {
        auto h=baseline; h[i].SetNull(); check(h);
        for (size_t byte=0;byte<32;++byte) for (unsigned char mask : {1,128,255}) {
            h=baseline; h[i].begin()[byte]^=mask; check(h);
        }
    }
    auto h=baseline; h[0]=h[1]; check(h);
    for (size_t i=2;i<16;i+=2) { h=baseline; h[i].SetNull(); h[i+1].SetNull(); check(h); }
}

BOOST_AUTO_TEST_CASE(haskell_activation_facts_match_previous_predicates)
{
    std::array<uint256,40> baseline;
    for (size_t i=0;i<baseline.size();++i) std::fill(baseline[i].begin(),baseline[i].end(),i+1);
    const std::vector<std::vector<size_t>> groups{{0,1},{2,3},{4,5,6},{7,8},{9,10},{11,12},{13,14},
        {15,16},{17,18},{19,20},{21,22},{25,26,27},{24,28},{29,30}};
    for (const auto& group : groups) for (auto index : group) baseline[index]=baseline[group.front()];
    for (auto index : {13,14}) std::copy(ECX_BOND_STAGING_RENDERER_DOMAIN_V18.begin(),ECX_BOND_STAGING_RENDERER_DOMAIN_V18.end(),baseline[index].begin());
    for (auto index : {15,16}) std::copy(ECX_BIP341_NUMS_XONLY.begin(),ECX_BIP341_NUMS_XONLY.end(),baseline[index].begin());
    const char* errors[]{"FrozenConfigurationV2/V18 bond/deployment/covenant identities do not match physical Tx1/Tx2 activation facts",
        "ECX bond V2 activation lacks a complete frozen covenant CMR tuple"};
    const auto check=[&](const auto& hashes) {
        const auto expected=ReferenceActivationFacts(hashes);
        std::array<const unsigned char*,40> pointers;
        for (size_t i=0;i<hashes.size();++i) pointers[i]=hashes[i].begin();
        try { drivechain::haskell::ExchangeActivationFacts(pointers); BOOST_CHECK_EQUAL(expected,0); }
        catch (const std::runtime_error& error) { BOOST_REQUIRE(expected>0); BOOST_CHECK_EQUAL(error.what(),errors[expected-1]); }
    };
    BOOST_REQUIRE_EQUAL(ReferenceActivationFacts(baseline),0);
    check(baseline);
    for (size_t i=0;i<40;++i) {
        auto hashes=baseline; hashes[i].SetNull(); check(hashes);
        for (size_t byte=0;byte<32;++byte) for (unsigned char mask : {1,128,255}) {
            hashes=baseline; hashes[i].begin()[byte]^=mask; check(hashes);
        }
    }
    for (const auto& group : groups) {
        auto hashes=baseline;
        for (auto index : group) hashes[index].SetNull();
        check(hashes);
    }
    auto collision=baseline; collision[23]=collision[22]; check(collision);
    collision=baseline; collision[24]=collision[28]=collision[22]; check(collision);
    collision=baseline; collision[0].SetNull(); collision[31].SetNull(); check(collision);
}

BOOST_AUTO_TEST_CASE(haskell_frozen_identity_groups_match_native)
{
    const std::array<const char*,4> errors{"finite, activation, and incremental-successor configurations collide",
        "incremental proof program identity collides", "frozen ECX bond V2 covenant CMR roles collide",
        "incremental successor state-node identity collides"};
    for (bool direct : {false,true}) for (size_t first=0;first<22;++first) for (size_t second=0;second<=22;++second) {
        std::array<std::array<unsigned char,32>,22> hashes;
        for (size_t i=0;i<hashes.size();++i) hashes[i].fill(i+1);
        if (direct) { hashes[6].fill(0); hashes[7].fill(0); }
        if (second==22) hashes[first].fill(0); else hashes[first]=hashes[second];
        const auto duplicate=[&](size_t begin,size_t end) {
            for (size_t i=begin;i<end;++i) for (size_t j=i+1;j<end;++j) if (hashes[i]==hashes[j]) return true;
            return false;
        };
        const int expected=duplicate(0,3) ? 1 : duplicate(3,direct ? 6 : 8) ? 2 : duplicate(8,17) ? 3 :
            std::find(hashes.begin()+18,hashes.end(),hashes[17])!=hashes.end() ? 4 : 0;
        std::array<const unsigned char*,22> pointers;
        for (size_t i=0;i<hashes.size();++i) pointers[i]=hashes[i].data();
        std::string error="stale";
        BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeFrozenIdentities(direct,pointers,error),expected==0);
        BOOST_CHECK_EQUAL(error,expected ? errors[expected-1] : "");
    }
}

BOOST_AUTO_TEST_CASE(haskell_deployment_identity_pipeline_matches_native)
{
    const std::array<const char*,5> errors{
        "finite, activation, and incremental-successor configuration hashes must be distinct",
        "proof program identity is missing", "incremental proof program identity collides with another proof role",
        "incremental activation covenant identity is missing or collides", "incremental successor state-node identity is missing or collides"};
    for (bool direct : {false,true}) {
        std::array<std::array<unsigned char,32>,22> valid;
        for (size_t i=0;i<valid.size();++i) valid[i].fill(i+1);
        if (direct) { valid[6].fill(0); valid[7].fill(0); }
        const auto check=[&](const auto& values) {
            const auto zero=[&](size_t i) { return std::all_of(values[i].begin(),values[i].end(),[](auto byte) { return byte==0; }); };
            int expected=0;
            for (size_t i=0;i<3;++i) for (size_t j=i+1;j<3;++j) if (values[i]==values[j]) expected=1;
            const size_t end=direct ? 6 : 8;
            for (size_t i=3;i<end && !expected;++i) {
                if (zero(i)) expected=2;
                else for (size_t j=i+1;j<end;++j) if (values[i]==values[j]) expected=3;
            }
            if (!expected) for (size_t i=8;i<17;++i) {
                if (zero(i)) expected=4;
                for (size_t j=i+1;j<17;++j) if (values[i]==values[j]) expected=4;
            }
            if (!expected) {
                if (zero(17)) expected=5;
                for (size_t j=18;j<22;++j) if (values[17]==values[j]) expected=5;
            }
            std::array<const unsigned char*,22> pointers;
            for (size_t i=0;i<22;++i) pointers[i]=values[i].data();
            try { drivechain::haskell::ExchangeDeploymentIdentities(direct,pointers); BOOST_CHECK_EQUAL(expected,0); }
            catch (const std::runtime_error& error) { BOOST_REQUIRE(expected>0); BOOST_CHECK_EQUAL(error.what(),errors[expected-1]); }
        };
        check(valid);
        for (size_t i=0;i<22;++i) {
            auto missing=valid; missing[i].fill(0); check(missing);
            for (size_t j=0;j<22;++j) {
                auto values=valid; values[j]=values[i]; check(values);
                values[17].fill(0); check(values);
                values[8].fill(0); check(values);
                values[3].fill(0); check(values);
                values[0]=values[1]; check(values);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(haskell_deployment_blinder_order_matches_native)
{
    for (bool public_deployment : {false,true}) for (unsigned issuance=0;issuance<4;++issuance)
        for (unsigned asset=0;asset<4;++asset) for (unsigned value=0;value<4;++value) {
            std::array<unsigned char,32> i,a,v; i.fill(issuance); a.fill(asset); v.fill(value);
            const char* expected=nullptr;
            if (public_deployment) {
                if (issuance || asset || value) expected="public ECX deployment requires zero blinders";
            } else if (!issuance || issuance==asset || issuance==value) expected="ECX bond V2 issuance blinder must be nonzero and distinct";
            else if (asset==value) expected="ECX bond V2 inventory blinders must be distinct";
            try {
                drivechain::haskell::ExchangeDeploymentBlinders(public_deployment,std::array<const unsigned char*,3>{i.data(),a.data(),v.data()});
                BOOST_CHECK(expected==nullptr);
            } catch (const std::runtime_error& error) {
                BOOST_REQUIRE(expected!=nullptr);
                BOOST_CHECK_EQUAL(error.what(),expected);
            }
        }
    std::array<unsigned char,32> zero{};
    BOOST_CHECK_THROW(drivechain::haskell::ExchangeDeploymentBlinders(false,
        std::array<const unsigned char*,3>{nullptr,zero.data(),zero.data()}),std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(haskell_configuration_identity_order_matches_native)
{
    const std::vector<size_t> base{2,50,82,146,179,211,754,1096,1132,1164,1196};
    const std::vector<size_t> bond{1232,1264,1296,1328,1360,1392,1424,1456,1489,1521,1557,1589,1621,1653,1685};
    const std::vector<size_t> conversions{1753,1785,1817,1849,1881,1913};
    auto offsets=base;
    offsets.insert(offsets.end(),bond.begin(),bond.end());
    offsets.insert(offsets.end(),conversions.begin(),conversions.end());
    offsets.insert(offsets.end(),{114,293,325,681});
    for (bool direct : {false,true}) {
        std::vector<unsigned char> valid(1977,0); valid[0]=direct ? 6 : 5;
        for (size_t i=0;i<offsets.size();++i) std::fill_n(valid.begin()+offsets[i],32,i+1);
        if (direct) for (auto offset : conversions) std::fill_n(valid.begin()+offset,32,0);
        const auto check=[&](const std::vector<unsigned char>& bytes) {
            const auto same=[&](size_t a,size_t b) { return std::equal(bytes.begin()+a,bytes.begin()+a+32,bytes.begin()+b); };
            for (bool outer : {false,true}) {
                auto unique=outer ? bond : base;
                if (outer && !direct) unique.insert(unique.end(),conversions.begin(),conversions.end());
                int expected=0;
                for (size_t i=0;i<unique.size();++i) for (size_t j=i+1;j<unique.size();++j)
                    if (same(unique[i],unique[j])) expected=1;
                if (!expected && !outer && !same(114,50)) for (auto offset : base) if (same(114,offset)) expected=2;
                if (!expected && outer) {
                    for (auto offset : {1132,1164,293,325}) if (same(1653,offset)) expected=2;
                    for (auto offset : {1753,1785,1489,1521,1232,1589}) if (same(681,offset)) expected=2;
                }
                std::string error="unchanged";
                BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeConfigurationIdentities(outer,bytes,error),expected==0);
                const char* reason=outer ? (expected==1 ? "duplicate outer identity" : "cross-role identity collision") :
                    (expected==1 ? "duplicate base identity" : "policy asset aliases an unrelated base identity");
                BOOST_CHECK_EQUAL(error,expected ? std::string("noncanonical FrozenConfigurationV2/V18: ")+reason : "unchanged");
            }
        };
        check(valid);
        for (auto a : offsets) for (auto b : offsets) {
            auto bytes=valid; std::copy_n(valid.begin()+a,32,bytes.begin()+b); check(bytes);
            std::copy_n(bytes.begin()+base[0],32,bytes.begin()+base[1]);
            std::copy_n(bytes.begin()+bond[0],32,bytes.begin()+bond[1]); check(bytes);
        }
        for (auto offset : offsets) { auto bytes=valid; std::fill_n(bytes.begin()+offset,32,0); check(bytes); }
        valid.pop_back(); std::string error;
        BOOST_CHECK_THROW(drivechain::haskell::ExchangeConfigurationIdentities(true,valid,error),std::runtime_error);
    }
}

BOOST_AUTO_TEST_CASE(haskell_bond_profile_matches_native)
{
    std::array<unsigned char,32> codec; codec.fill(9);
    std::vector<unsigned char> valid(485,1);
    std::copy(ECX_BOND_STAGING_RENDERER_DOMAIN_V18.begin(),ECX_BOND_STAGING_RENDERER_DOMAIN_V18.end(),valid.begin()+192);
    std::copy(ECX_BIP341_NUMS_XONLY.begin(),ECX_BIP341_NUMS_XONLY.end(),valid.begin()+224);
    valid[256]=0xbe; std::fill_n(valid.begin()+289,32,2); WriteBE32(valid.data()+321,12);
    std::copy(codec.begin(),codec.end(),valid.begin()+453);
    const std::array<size_t,15> offsets{0,32,64,96,128,160,192,224,257,289,325,357,389,421,453};
    const auto check=[&](const std::vector<unsigned char>& bytes) {
        bool expected=true;
        for (auto offset : offsets)
            if (std::all_of(bytes.begin()+offset,bytes.begin()+offset+32,[](auto b) { return b==0; })) expected=false;
        expected=expected && std::equal(bytes.begin()+192,bytes.begin()+224,ECX_BOND_STAGING_RENDERER_DOMAIN_V18.begin()) &&
            std::equal(bytes.begin()+224,bytes.begin()+256,ECX_BIP341_NUMS_XONLY.begin()) && bytes[256]==0xbe &&
            !std::equal(bytes.begin()+257,bytes.begin()+289,bytes.begin()+289) && ReadBE32(bytes.data()+321)==12 &&
            std::equal(codec.begin(),codec.end(),bytes.begin()+453);
        BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeBondProfile(bytes,codec),expected);
    };
    BOOST_CHECK(drivechain::haskell::ExchangeBondProfile(valid,codec));
    for (size_t i=0;i<valid.size();++i) for (unsigned byte : {0U,1U,255U}) { auto bytes=valid; bytes[i]=byte; check(bytes); }
    for (auto offset : offsets) { auto bytes=valid; std::fill_n(bytes.begin()+offset,32,0); check(bytes); }
    auto bytes=valid; std::copy_n(bytes.begin()+257,32,bytes.begin()+289); check(bytes);
    codec[0]^=1; check(valid); codec[0]^=1;
    valid.pop_back();
    BOOST_CHECK_THROW(drivechain::haskell::ExchangeBondProfile(valid,codec),std::runtime_error);
}

BOOST_AUTO_TEST_CASE(haskell_frozen_tail_matches_native)
{
    const std::array<uint32_t,9> limits{6,65536,8,589824,786432,64,64,4096,6};
    const std::array<const char*,3> errors{"bond inbox/matcher limits","versioned oracle conversion identities","recursive proof/bond constants or trailing bytes"};
    for (bool direct : {false,true}) {
        std::vector<unsigned char> valid(260,0);
        for (size_t i=0;i<9;++i) WriteBE32(valid.data()+i*4,limits[i]);
        std::fill(valid.begin()+36,valid.begin()+228,direct ? 0 : 1);
        WriteBE64(valid.data()+228,1); WriteBE32(valid.data()+236,1); WriteBE32(valid.data()+240,32);
        WriteBE64(valid.data()+244,2100000000000000); WriteBE64(valid.data()+252,1008);
        const auto check=[&](const std::vector<unsigned char>& bytes) {
            int expected=0;
            for (size_t i=0;i<9;++i) if (ReadBE32(bytes.data()+i*4)!=limits[i]) expected=1;
            for (size_t i=0;i<6 && !expected;++i) {
                const bool zero=std::all_of(bytes.begin()+36+i*32,bytes.begin()+68+i*32,[](auto b) { return b==0; });
                if (zero!=direct) expected=2;
            }
            if (!expected && (ReadBE64(bytes.data()+228)==0 || ReadBE32(bytes.data()+236)==0 || ReadBE32(bytes.data()+236)>16777216 ||
                ReadBE32(bytes.data()+240)!=32 || ReadBE64(bytes.data()+244)!=2100000000000000 || ReadBE64(bytes.data()+252)!=1008)) expected=3;
            std::string error="unchanged";
            BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeFrozenTail(direct,bytes,error),expected==0);
            BOOST_CHECK_EQUAL(error,expected ? std::string("noncanonical FrozenConfigurationV2/V18: ")+errors[expected-1] : "unchanged");
        };
        check(valid);
        for (size_t offset=0;offset<260;++offset) for (unsigned byte : {0U,1U,255U}) { auto bytes=valid; bytes[offset]=byte; check(bytes); }
        for (size_t i=0;i<6;++i) { auto bytes=valid; std::fill_n(bytes.begin()+36+i*32,32,direct ? 1 : 0); check(bytes); }
        auto bytes=valid; WriteBE32(bytes.data()+240,0); check(bytes);
        std::fill_n(bytes.begin()+36,32,direct ? 1 : 0); check(bytes);
        WriteBE32(bytes.data(),0); check(bytes);
        bytes.pop_back(); std::string error="unchanged";
        BOOST_CHECK_THROW(drivechain::haskell::ExchangeFrozenTail(direct,bytes,error),std::runtime_error);
    }
}

BOOST_AUTO_TEST_CASE(bond_uint128_native_codec_boundaries)
{
    for (const uint64_t value : {uint64_t{0}, uint64_t{1}, uint64_t{255}, uint64_t{256}, UINT64_MAX}) {
        ecx::BigEndianUint128 encoded{value};
        std::array<unsigned char, 16> expected{};
        for (size_t i = 0; i < 8; ++i) expected[15-i] = static_cast<unsigned char>(value >> (8*i));
        BOOST_CHECK(encoded.bytes == expected);
        uint64_t decoded{42};
        BOOST_REQUIRE(encoded.ToU64(decoded));
        BOOST_CHECK_EQUAL(decoded, value);
        for (size_t i = 0; i < 8; ++i) {
            auto wide = encoded;
            wide.bytes[i] = 1;
            decoded = 42;
            BOOST_CHECK(!wide.ToU64(decoded));
            BOOST_CHECK_EQUAL(decoded, 42);
            wide = value;
            BOOST_CHECK(wide.bytes == expected);
        }
    }
}

BOOST_AUTO_TEST_CASE(policy_candidate_scan_short_circuit)
{
    for (bool context : {false, true}) for (bool canonical : {false, true}) {
        for (unsigned mask = 0; mask < 32; ++mask) {
            unsigned reads{0}, validations{0};
            const bool result = drivechain::haskell::ParentReplayAll<3>({
                [&] { return context; },
                [&] {
                    std::optional<uint64_t> unused;
                    return !drivechain::haskell::ExchangeSpendScan(false, 0, 5, [&](uint64_t index) {
                        ++reads;
                        return bool(mask & (1U << index));
                    }, unused);
                },
                [&] { ++validations; return canonical; },
            });
            unsigned expected_reads{0};
            if (context) do { ++expected_reads; } while (expected_reads < 5 && !(mask & (1U << (expected_reads - 1))));
            BOOST_CHECK_EQUAL(result, context && mask != 0 && canonical);
            BOOST_CHECK_EQUAL(reads, expected_reads);
            BOOST_CHECK_EQUAL(validations, unsigned(context && mask != 0));
        }
    }
}

BOOST_AUTO_TEST_CASE(haskell_spend_selection_preserves_order_and_failures)
{
    for (bool unique : {false, true}) {
        for (unsigned encoded = 0; encoded < 243; ++encoded) {
            std::array<uint64_t, 5> counts{};
            auto digits = encoded;
            for (auto& count : counts) { count = digits % 3; digits /= 3; }
            for (uint64_t start = 0; start <= counts.size(); ++start) {
                std::optional<uint64_t> expected;
                std::vector<uint64_t> expected_reads;
                bool accepted = true;
                for (uint64_t i = start; i < counts.size(); ++i) {
                    expected_reads.push_back(i);
                    for (uint64_t n = 0; n < counts[i]; ++n) {
                        if (!unique || expected) { accepted = false; break; }
                        expected = i;
                    }
                    if (!accepted) break;
                }
                std::optional<uint64_t> actual{99};
                std::vector<uint64_t> reads;
                BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeSpendScan(unique, start, counts.size(),
                    [&](uint64_t i) { reads.push_back(i); return counts[i]; }, actual), accepted);
                BOOST_CHECK(actual == (accepted ? expected : std::optional<uint64_t>{99}));
                BOOST_CHECK(reads == expected_reads);
            }
        }
        std::optional<uint64_t> actual{99};
        BOOST_CHECK_THROW(drivechain::haskell::ExchangeSpendScan(unique, 0, 1,
            [](uint64_t) -> uint64_t { throw std::runtime_error("spend read"); }, actual), std::runtime_error);
        BOOST_CHECK(actual == 99);
        BOOST_CHECK_THROW(drivechain::haskell::ExchangeSpendScan(unique, 2, 1,
            [](uint64_t) -> uint64_t { BOOST_FAIL("invalid range read"); return 0; }, actual), std::runtime_error);
        BOOST_CHECK(actual == 99);
        BOOST_CHECK(drivechain::haskell::ExchangeSpendScan(unique, UINT64_MAX, UINT64_MAX,
            [](uint64_t) -> uint64_t { BOOST_FAIL("empty range read"); return 0; }, actual));
        BOOST_CHECK(!actual);
        BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeSpendScan(unique, UINT64_MAX-1, UINT64_MAX,
            [](uint64_t) -> uint64_t { return 1; }, actual), unique);
        BOOST_CHECK(actual == (unique ? std::optional<uint64_t>{UINT64_MAX-1} : std::nullopt));
    }
}

BOOST_AUTO_TEST_CASE(haskell_block_sources_preserves_publish_boundary)
{
    for (uint32_t failed : {0U,3U,4U,5U,8U}) {
        unsigned transaction=0, output=0, appended=0, published=0;
        std::vector<uint32_t> trace;
        const auto result=drivechain::haskell::ParentReplayStore(
            drivechain::haskell::ReplayStoreFlow::EXCHANGE_BLOCK_SOURCES,
            [&](uint32_t action) -> uint32_t {
                trace.push_back(action);
                if (action==failed && (action!=8 || appended==1)) return 0;
                switch (action) {
                case 1: return transaction<2;
                case 2: return transaction==1;
                case 5: return drivechain::haskell::ExchangeFrozenBounds(std::array<uint64_t,5>{1,1,32,2100000000000000,1008});
                case 6: return output<3;
                case 7: return output!=0;
                case 8: ++appended; return 1;
                case 9: ++output; return 1;
                case 10: ++transaction; output=0; return 1;
                case 11: ++published; return 1;
                default: return 1;
                }
            });
        std::vector<uint32_t> expected{1,2,10,1,2,3,4,5,6,7,9,6,7,8,9,6,7,8,9,6,10,1,11};
        if (failed) {
            auto stop=std::find(expected.begin(),expected.end(),failed);
            if (failed==8) stop=std::find(stop+1,expected.end(),failed);
            expected.erase(stop+1,expected.end());
        }
        BOOST_CHECK(trace==expected);
        BOOST_CHECK_EQUAL(result,failed ? 0 : 1);
        BOOST_CHECK_EQUAL(published,failed ? 0 : 1);
        BOOST_CHECK_EQUAL(appended,failed==8 ? 1 : failed ? 0 : 2);
    }
}

BOOST_AUTO_TEST_CASE(haskell_source_transaction_resumes_after_native_actions)
{
    for (bool staged : {false,true}) {
        for (uint32_t failed : {0U,3U,4U,5U,7U,8U,9U,10U,12U}) {
            if (failed==(staged ? 8U : 7U)) continue;
            unsigned index=0;
            std::vector<uint32_t> trace;
            const auto result=drivechain::haskell::ParentReplayStore(
                drivechain::haskell::ReplayStoreFlow::EXCHANGE_SOURCE_TRANSACTION,
                [&](uint32_t action) -> uint32_t {
                    trace.push_back(action);
                    if (action==failed) return 0;
                    if (action==1) return index<2;
                    if (action==2) return index==1;
                    if (action==6) return staged;
                    if (action==11) ++index;
                    if (action==9) return drivechain::haskell::ExchangeFrozenBounds(
                        std::array<uint64_t,5>{1,1,32,2100000000000000,1008});
                    return 1;
                });
            std::vector<uint32_t> expected{1,2,11,1,2,3,4,5,6,staged ? 7U : 8U,9,10,11,1,12};
            if (failed) expected.erase(std::find(expected.begin(),expected.end(),failed)+1,expected.end());
            BOOST_CHECK(trace==expected);
            BOOST_CHECK_EQUAL(result,failed ? 0 : 1);
        }
    }
}

BOOST_AUTO_TEST_CASE(haskell_marker_selection_matches_native_scans)
{
    namespace hs = drivechain::haskell;
    for (unsigned size=0;size<=4;++size) for (unsigned byte=0;byte<=255;++byte) {
        const std::vector<unsigned char> bytes(size,static_cast<unsigned char>(byte));
        const CScript script(bytes.begin(),bytes.end());
        BOOST_CHECK_EQUAL(hs::ParentReplayAll<2>({[&] { return !script.empty(); },
            [&] { return script[0]==OP_RETURN; }}),!script.empty() && script[0]==OP_RETURN);
        auto native_cursor=script.begin(), cursor=script.begin();
        opcodetype native_opcode=OP_INVALIDOPCODE, opcode=OP_INVALIDOPCODE;
        const bool parsed=script.GetOp(native_cursor,native_opcode);
        unsigned inspected{0};
        const bool actual=hs::ParentReplayAll<2>({[&] { return script.GetOp(cursor,opcode); },
            [&] { ++inspected; return opcode==OP_RETURN; }});
        BOOST_CHECK_EQUAL(actual,parsed && native_opcode==OP_RETURN);
        BOOST_CHECK_EQUAL(inspected,parsed ? 1U : 0U);
        BOOST_CHECK_EQUAL(cursor-script.begin(),native_cursor-script.begin());
        BOOST_CHECK_EQUAL(opcode,native_opcode);
    }
    for (size_t count=0;count<=6;++count) for (size_t duplicate=0;duplicate<=count;++duplicate) {
        std::vector<uint256> ids(count,uint256::ZERO);
        if (duplicate<count) ids[duplicate]=uint256::ONE;
        size_t visited{0};
        const bool unique=hs::ParentReplayEach(ids,[&](const uint256& id) { ++visited; return id!=uint256::ONE; });
        BOOST_CHECK_EQUAL(unique,std::find(ids.begin(),ids.end(),uint256::ONE)==ids.end());
        BOOST_CHECK_EQUAL(visited,duplicate<count ? duplicate+1 : count);
    }
}

BOOST_AUTO_TEST_CASE(haskell_startup_bounds_match_signed_predicates)
{
    using drivechain::haskell::ExchangeFrozenBounds;
    const std::array<int64_t,10> values{INT64_MIN,-1,0,1,2,INT32_MAX,int64_t{INT32_MAX}+1,UINT32_MAX,int64_t{UINT32_MAX}+1,INT64_MAX};
    for (auto price : values)
        BOOST_CHECK_EQUAL(ExchangeFrozenBounds(std::array<uint64_t,1>{static_cast<uint64_t>(price)}),price>0);
    for (auto height : values) for (int32_t activation : {INT32_MIN,-1,0,1,2,INT32_MAX}) for (auto mtp : values) {
        const bool expected=!(height<=0 || height>=activation || mtp<=0 || mtp>UINT32_MAX);
        BOOST_CHECK_EQUAL(ExchangeFrozenBounds(std::array<uint64_t,3>{static_cast<uint64_t>(height),
            static_cast<uint64_t>(activation),static_cast<uint64_t>(mtp)}),expected);
    }
    BOOST_CHECK(!ExchangeFrozenBounds(std::array<uint64_t,3>{1,uint64_t{INT32_MAX}+1,1}));
}

BOOST_AUTO_TEST_CASE(haskell_configuration_fields_match_native_parsers)
{
    const auto reference=[](unsigned kind,const std::string& text,std::vector<unsigned char>& output) {
        if (kind==6) {
            if (text.size()!=650 || !IsHex(text)) return 1;
            output=ParseHex(text); return 0;
        }
        if (kind==5) {
            if (text.empty() || text.size()>131072 || !IsHex(text)) return 1;
            output=ParseHex(text);
            return 0;
        }
        if (kind==2) {
            const auto colon=text.find(':');
            uint32_t index{0};
            if (colon!=64 || text.find(':',colon+1)!=std::string::npos ||
                !IsHex(text.substr(0,colon)) || !ParseUInt32(text.substr(colon+1),&index)) return 1;
            const uint256 hash=uint256S(text.substr(0,colon));
            if (hash.IsNull()) return 2;
            output.assign(hash.begin(),hash.end());
            output.resize(36);
            WriteBE32(output.data()+32,index);
            return 0;
        }
        if ((kind!=3 && text.size()!=64) || !IsHex(text)) return 1;
        output=ParseHex(text);
        if (kind==3) return CScript(output.begin(),output.end()).IsUnspendable() ? 2 : 0;
        if (kind!=0 && std::all_of(output.begin(),output.end(),[](auto byte) { return byte==0; })) return 2;
        if (kind==4) std::reverse(output.begin(),output.end());
        return 0;
    };
    std::vector<std::string> cases{"", "0", "00", "6a", "6A", " 00", "00 ", "gg",
        std::string(64,'0'),std::string(64,'A'),std::string(20000,'0'),std::string(20002,'0'),std::string("00\0",3),
        std::string(131070,'a'),std::string(131072,'F'),std::string(131073,'0'),std::string(131074,'0'),
        std::string(131071,'0')+"g"};
    const std::string hash="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    for (const auto& suffix : {"0","+0","0001","4294967295","+4294967295","4294967296",
                              "-0","-1","+-1","++1","1:2","1 ","", "+"}) {
        cases.push_back(hash+":"+suffix);
        cases.push_back(std::string(64,'0')+":"+suffix);
    }
    for (unsigned value=0; value<256; ++value) {
        std::array<unsigned char,32> bytes;
        for (unsigned i=0;i<bytes.size();++i) bytes[i]=value+i;
        const auto hex=HexStr(bytes);
        cases.push_back(hex);
        cases.push_back(hex+":+"+std::to_string(value*16777215U));
        auto malformed=hex;
        malformed[value%64]='g';
        cases.push_back(malformed);
    }
    for (size_t size : {648,649,650,651,652}) for (char digit : {'0','F','a','g'}) cases.push_back(std::string(size,digit));
    for (size_t index=0;index<650;++index) {
        std::string malformed(650,'a'); malformed[index]=index%2 ? 'g' : '\0'; cases.push_back(malformed);
    }
    for (unsigned kind=0;kind<7;++kind) for (const auto& text:cases) {
        std::vector<unsigned char> expected;
        const int error=reference(kind,text,expected);
        try {
            const auto actual=drivechain::haskell::ParseConfigurationField(
                static_cast<drivechain::haskell::ConfigurationField>(kind),text,"syntax","value");
            BOOST_CHECK_EQUAL(error,0);
            BOOST_CHECK(actual==expected);
        } catch (const std::runtime_error& exception) {
            BOOST_CHECK_NE(error,0);
            BOOST_CHECK_EQUAL(exception.what(),error==1 ? "syntax" : "value");
        }
    }
}

BOOST_AUTO_TEST_CASE(haskell_generated_exchange_identities_preserve_frozen_bytes)
{
    BOOST_CHECK_EQUAL(HexStr(ECX_BIP341_NUMS_XONLY),
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0");
    BOOST_CHECK_EQUAL(HexStr(ECX_BOND_STAGING_RENDERER_DOMAIN_V18),
        "d8ca7883769dd73830987f727a34939d2d9b69a3e783e0a2e1cca35fa4872e6f");
    const std::string domain{"ECX/bond-inbox-redemption-staging-renderer/v3-no-history"};
    std::array<unsigned char,32> digest{};
    CSHA256().Write(reinterpret_cast<const unsigned char*>(domain.data()),domain.size()).Finalize(digest.data());
    BOOST_CHECK(digest==ECX_BOND_STAGING_RENDERER_DOMAIN_V18);
}

BOOST_AUTO_TEST_CASE(haskell_legacy_marker_frames_match_native_parser)
{
    // Independent pre-refactor GetOp grammar, including short PUSHDATA1 frames.
    const auto original = [](bool forced, const CScript& script, std::vector<unsigned char>& payload) {
        auto cursor = script.begin();
        opcodetype opcode;
        if (!script.GetOp(cursor,opcode) || opcode != OP_RETURN ||
            !script.GetOp(cursor,opcode,payload) || cursor != script.end()) return false;
        const std::array<unsigned char,4> magic{'E','C','X',static_cast<unsigned char>(forced ? 'F' : 'D')};
        if (forced) {
            if (opcode != OP_PUSHDATA1 || script.size() != payload.size()+3 ||
                script[1] != OP_PUSHDATA1 || script[2] != payload.size() || payload.size()<8) return false;
        } else if (opcode != 73 || script.size()!=75 || payload.size()!=73) return false;
        return std::equal(magic.begin(),magic.end(),payload.begin());
    };
    const auto check = [&](bool forced, const CScript& script) {
        std::vector<unsigned char> expected, actual{0xa5};
        const bool accepted=original(forced,script,expected);
        BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeLegacyMarkerFrame(forced,script,actual),accepted);
        BOOST_CHECK(actual == (accepted ? expected : std::vector<unsigned char>{0xa5}));
    };
    for (bool forced : {false,true}) {
        for (size_t size=0; size<=260; ++size) {
            CScript script;
            script.resize(size);
            const std::vector<unsigned char> prefix = forced ?
                std::vector<unsigned char>{106,76,static_cast<unsigned char>(size>=3 ? size-3 : 0),69,67,88,70} :
                std::vector<unsigned char>{106,73,69,67,88,68};
            std::copy_n(prefix.begin(),std::min(prefix.size(),size),script.begin());
            check(forced,script);
            for (size_t offset=0; offset<std::min(prefix.size(),size); ++offset) {
                const auto saved=script[offset];
                for (unsigned byte=0; byte<256; ++byte) {
                    script[offset]=byte;
                    check(forced,script);
                }
                script[offset]=saved;
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(haskell_cursor_payload_matches_native_rules)
{
    for (const uint64_t value : {uint64_t{0},uint64_t{1},uint64_t{0x123456789abcdef0},uint64_t{UINT64_MAX}}) {
        std::vector<unsigned char> payload(21);
        std::copy_n("ECXC",4,payload.begin());
        payload[4] = 1;
        WriteLE64(payload.data()+5,value);
        WriteLE64(payload.data()+13,~value);
        bool marker{false};
        uint64_t forced{}, deposit{};
        std::string error;
        BOOST_REQUIRE(drivechain::haskell::ExchangeCursorPayload(payload,marker,forced,deposit,error));
        BOOST_CHECK(marker);
        BOOST_CHECK_EQUAL(forced,value);
        BOOST_CHECK_EQUAL(deposit,~value);
    }
    for (size_t size = 0; size <= 256; ++size) {
        std::vector<unsigned char> payload(size,0xff);
        const std::array<unsigned char,5> header{'E','C','X','C',1};
        std::copy_n(header.begin(),std::min(size,header.size()),payload.begin());
        for (size_t offset = 0; offset < std::max(size_t{1},std::min(size,size_t{5})); ++offset) {
            for (unsigned byte = 0; byte < 256; ++byte) {
                auto input = payload;
                if (size) input[offset] = byte;
                const bool expected_marker = size >= 4 && std::equal(header.begin(),header.begin()+4,input.begin());
                const bool accepted = !expected_marker || (size == 21 && input[4] == 1);
                bool marker{true};
                uint64_t forced{123}, deposit{456};
                std::string error{"unchanged"};
                BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeCursorPayload(input,marker,forced,deposit,error),accepted);
                BOOST_CHECK_EQUAL(marker,expected_marker);
                BOOST_CHECK_EQUAL(forced,accepted && marker ? UINT64_MAX : 123);
                BOOST_CHECK_EQUAL(deposit,accepted && marker ? UINT64_MAX : 456);
                BOOST_CHECK_EQUAL(error,accepted ? "unchanged" : "ECX processed-cursor marker has an invalid version or length");
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(haskell_deployment_input_scans)
{
    namespace hs = drivechain::haskell;
    for (size_t count=0;count<=5;++count) {
        for (size_t issuances=0;issuances<=count;++issuances) {
            for (size_t pegin=0;pegin<=count;++pegin) {
                CMutableTransaction tx;
                tx.vin.resize(count);
                for (size_t i=0;i<issuances;++i) tx.vin[i].assetIssuance.nAmount=CConfidentialValue(1);
                if (pegin<count) tx.vin[pegin].m_is_pegin=true;
                const bool expected=!tx.vin.empty() &&
                    std::none_of(tx.vin.begin(),tx.vin.end(),[](const auto& in) { return in.m_is_pegin; }) &&
                    std::count_if(tx.vin.begin(),tx.vin.end(),[](const auto& in) { return !in.assetIssuance.IsNull(); })==1;
                bool counted{false};
                std::string error;
                const bool accepted=hs::ExchangeTransactionShape(hs::TransactionShape::DEPLOYMENT_ARGUMENTS,
                    [&](uint32_t step) {
                        if (step==0) return !tx.vin.empty();
                        if (step<9) return true; // Other fields passed their independent shape checks.
                        if (step==9) return hs::ParentReplayEach(tx.vin,[](const auto& in) { return !in.m_is_pegin; });
                        counted=true;
                        return hs::CountMatches(tx.vin.size(),[&](uint64_t i) { return !tx.vin[i].assetIssuance.IsNull(); })==1;
                    },error);
                BOOST_CHECK_EQUAL(accepted,expected);
                BOOST_CHECK_EQUAL(counted,count>0 && pegin==count);
                size_t pegin_checks{0}, issuance_checks{0};
                const bool clean=hs::ParentReplayEach(tx.vin,[&](const auto& in) {
                    return hs::ParentReplayAll<2>({[&] { ++pegin_checks; return !in.m_is_pegin; },
                        [&] { ++issuance_checks; return in.assetIssuance.IsNull(); }});
                });
                size_t expected_pegin{0}, expected_issuance{0};
                const bool native_clean=std::none_of(tx.vin.begin(),tx.vin.end(),[&](const auto& in) {
                    ++expected_pegin;
                    if (in.m_is_pegin) return true;
                    ++expected_issuance;
                    return !in.assetIssuance.IsNull();
                });
                BOOST_CHECK_EQUAL(clean,native_clean);
                BOOST_CHECK_EQUAL(pegin_checks,expected_pegin);
                BOOST_CHECK_EQUAL(issuance_checks,expected_issuance);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(haskell_authority_input_counts)
{
    const COutPoint authority{Txid::FromUint256(uint256::ONE),7};
    for (size_t count=0;count<=6;++count) {
        for (unsigned mask=0;mask<(1U<<count);++mask) {
            CMutableTransaction tx;
            tx.vin.resize(count);
            for (size_t i=0;i<count;++i) if (mask&(1U<<i)) tx.vin[i].prevout=authority;
            const auto expected=std::count_if(tx.vin.begin(),tx.vin.end(),
                [&](const auto& in) { return in.prevout==authority; });
            BOOST_CHECK_EQUAL(drivechain::haskell::CountMatches(tx.vin.size(),
                [&](uint64_t i) { return tx.vin[i].prevout==authority; }),expected);
        }
    }
}

BOOST_AUTO_TEST_CASE(haskell_transaction_shape_preserves_guard_order)
{
    const std::array<unsigned, 15> sizes{3, 9, 8, 16, 16, 11, 8, 9, 2, 2, 8, 2, 1, 1, 16};
    const std::array<const char*, 17> errors{
        "ECX singleton must be transition input zero", "ECX transition has no successor output zero",
        "ECX bond V2 physical deployment/genesis linkage changed", "ECX bond V2 deployment/genesis issuance shape changed",
        "ECX bond V2 deployment outputs differ from the authorized facts",
        "ECX bond V2 activation requires confirmed ordered deployment and genesis UTXOs",
        "ECX bond V2 genesis singleton is not the exact derived empty state",
        "ECX bond-inbox source lacks its designated Taproot annex input",
        "ECX bond-inbox designated input is not an exact key-path annex spend",
        "ECX bond-inbox source contains a second Taproot annex",
        "ECX bond-inbox source has too many or duplicate markers",
        "ECX bond-inbox staging output index is invalid",
        "ECX bond-inbox staging output is not the exact confidential frozen descriptor form",
        "ECX bond-inbox staging output serialization is invalid",
        "ECX bond-inbox marker source authorization is invalid",
        "ECX bond-inbox source transaction must contain exactly one marker",
        "ECX V18 staging renderer inputs or frozen identity are invalid"};
    for (uint32_t phase = 0; phase < sizes.size(); ++phase) {
        const auto kind = static_cast<drivechain::haskell::TransactionShape>(phase);
        const unsigned first = phase == 4 ? 1 : 0;
        for (unsigned mask = 0; mask < (1U << sizes[phase]); ++mask) {
            unsigned failed = first;
            while (failed < sizes[phase] && (mask & (1U << failed))) ++failed;
            unsigned reads = 0;
            std::string error{"unchanged"};
            BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeTransactionShape(kind, [&](uint32_t step) {
                BOOST_CHECK_EQUAL(step, first + reads++);
                return (mask & (1U << step)) != 0;
            }, error), failed == sizes[phase]);
            BOOST_CHECK_EQUAL(reads, std::min(failed+1, sizes[phase])-first);
            const unsigned error_index = phase >= 8 ? phase+2 : phase == 7 ? (failed < 3 ? 7 : failed < 8 ? 8 : 9) : phase == 0 ? (failed < 2 ? 0 : 1) : phase < 3 ? phase+1 : phase < 5 ? 4 : phase;
            BOOST_CHECK_EQUAL(error, failed == sizes[phase] ? "unchanged" : errors[error_index]);
        }
        for (unsigned failed = first; failed < sizes[phase]; ++failed) {
            std::string error{"unchanged"};
            unsigned reads = 0;
            BOOST_CHECK_THROW(drivechain::haskell::ExchangeTransactionShape(kind, [&](uint32_t step) {
                ++reads;
                if (step == failed) throw std::runtime_error("shape read");
                return true;
            }, error), std::runtime_error);
            BOOST_CHECK_EQUAL(reads, failed+1-first);
            BOOST_CHECK_EQUAL(error, "unchanged");
        }
    }
    for (unsigned mask=0; mask<8; ++mask) {
        std::vector<uint32_t> seen;
        std::string reason{"parser detail"};
        const auto accepted=drivechain::haskell::ExchangeTransactionShape(
            drivechain::haskell::TransactionShape::CANONICAL_FORCED,[&](uint32_t step) {
                seen.push_back(step);
                return (mask & (1U<<step))!=0;
            },reason);
        const size_t reads=!(mask&1) ? 1 : !(mask&2) ? 2 : 3;
        BOOST_CHECK_EQUAL(accepted,mask==7);
        std::vector<uint32_t> expected{0,1,2};
        expected.resize(reads);
        BOOST_CHECK(seen==expected);
        BOOST_CHECK_EQUAL(seen.size(),reads);
        BOOST_CHECK_EQUAL(reason,!(mask&1) ? "ECX forced-action output index is out of range" :
            !(mask&2) || mask==7 ? "parser detail" : "output is not a canonical ECX forced action");
    }
    std::string error{"unchanged"};
    BOOST_CHECK_THROW(drivechain::haskell::ExchangeTransactionShape(
        static_cast<drivechain::haskell::TransactionShape>(25), [](uint32_t) {
            BOOST_FAIL("invalid phase read"); return true;
        }, error), std::runtime_error);
    BOOST_CHECK_EQUAL(error, "unchanged");
}

BOOST_AUTO_TEST_CASE(tracked_coin_admission_preserves_errors_and_order)
{
    for (unsigned mask=0; mask<8; ++mask) {
        std::vector<uint32_t> seen;
        std::string error{"unchanged"};
        const bool accepted=drivechain::haskell::ExchangeTransactionShape(
            drivechain::haskell::TransactionShape::TRACKED_COIN,[&](uint32_t step) {
                seen.push_back(step);
                if (step==1 && !(mask&2)) error="authority detail";
                return (mask & (1U<<step))!=0;
            },error);
        BOOST_CHECK_EQUAL(accepted,mask==7);
        std::vector<uint32_t> expected{0,1,2};
        expected.resize(!(mask&1) ? 1 : !(mask&2) ? 2 : 3);
        BOOST_CHECK(seen==expected);
        BOOST_CHECK_EQUAL(error,!(mask&1) ? "tracked ECX singleton is missing from the UTXO set" :
            !(mask&2) ? "authority detail" : !(mask&4) ?
            "tracked ECX singleton does not match its persisted root" : "unchanged");
    }
}

BOOST_AUTO_TEST_CASE(authenticated_parent_height_preserves_publication_and_errors)
{
    for (unsigned mask=0; mask<8; ++mask) {
        for (uint64_t height : {uint64_t{0},uint64_t{1},uint64_t{UINT32_MAX},uint64_t{UINT64_MAX}}) {
            const bool supplied=mask&1, fetched=mask&2, empty=mask&4;
            uint64_t output{123};
            std::string error{"unchanged"};
            std::vector<uint32_t> seen;
            const auto accepted=drivechain::haskell::ParentReplayStore(
                drivechain::haskell::ReplayStoreFlow::AUTHENTICATED_HEIGHT,[&](uint32_t step) -> uint32_t {
                seen.push_back(step);
                switch (step) {
                case 1: return supplied;
                case 2: BOOST_REQUIRE(supplied); return height!=0;
                case 3: error="zero supplied"; return 1;
                case 4: output=height; return 1;
                case 5: BOOST_REQUIRE(!supplied); return fetched;
                case 6: return empty;
                case 7: error="missing authenticated state"; return 1;
                case 8: error="decode detail"; return 1;
                case 9: output=height; return 1;
                case 10: return output!=0;
                default: throw std::logic_error("invalid height test action");
                }
            });
            const std::vector<uint32_t> expected=supplied ?
                std::vector<uint32_t>{1,2,height ? 4U : 3U} : fetched ?
                std::vector<uint32_t>{1,5,9,10} : std::vector<uint32_t>{1,5,6,empty ? 7U : 8U};
            BOOST_CHECK(seen==expected);
            BOOST_CHECK_EQUAL(accepted,height!=0 && (supplied || fetched));
            BOOST_CHECK_EQUAL(output,(supplied ? height!=0 : fetched) ? height : 123);
            BOOST_CHECK_EQUAL(error,supplied ? (height ? "unchanged" : "zero supplied") :
                fetched ? "unchanged" : empty ? "missing authenticated state" : "decode detail");
        }
    }
}

BOOST_AUTO_TEST_CASE(marker_envelope_reads_stop_at_first_failure)
{
    using Kind = drivechain::haskell::TransactionShape;
    for (const auto kind : {Kind::FORCED_ENVELOPE,Kind::DEPOSIT_ENVELOPE}) {
        for (unsigned mask=0; mask<8; ++mask) {
            for (bool throws : {false,true}) {
                unsigned reads=0, first=0;
                while (first<3 && (mask & (1U<<first))) ++first;
                std::string error{"unchanged"};
                const auto run = [&] {
                    return drivechain::haskell::ExchangeTransactionShape(kind,[&](uint32_t step) {
                        BOOST_CHECK_EQUAL(step,reads++);
                        if (throws && step==first) throw std::runtime_error("envelope read");
                        return (mask & (1U<<step))!=0;
                    },error);
                };
                if (throws && first<3) BOOST_CHECK_THROW(run(),std::runtime_error);
                else BOOST_CHECK_EQUAL(run(),first==3);
                BOOST_CHECK_EQUAL(reads,std::min(first+1,3U));
                BOOST_CHECK_EQUAL(error,throws || first==3 ? "unchanged" :
                    kind==Kind::FORCED_ENVELOPE ? "ECX forced action marker envelope is non-canonical" :
                    "ECX deposit marker envelope or chain id is non-canonical");
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(deposit_reference_checks_preserve_guarded_access)
{
    for (unsigned mask=0; mask<1024; ++mask) {
        unsigned first=0;
        while (first<10 && (mask & (1U<<first))) ++first;
        for (bool throws : {false,true}) {
            unsigned reads=0;
            std::string error{"unchanged"};
            const auto run = [&] {
                return drivechain::haskell::ExchangeTransactionShape(
                    drivechain::haskell::TransactionShape::DEPOSIT_REFERENCE,[&](uint32_t step) {
                        BOOST_CHECK_EQUAL(step,reads++);
                        if (throws && step==first) throw std::runtime_error("deposit fact");
                        return (mask & (1U<<step))!=0;
                    },error);
            };
            if (throws && first<10) BOOST_CHECK_THROW(run(),std::runtime_error);
            else BOOST_CHECK_EQUAL(run(),first==10);
            BOOST_CHECK_EQUAL(reads,std::min(first+1,10U));
            BOOST_CHECK_EQUAL(error,throws || first==10 ? "unchanged" : first<3 ?
                "ECX deposit marker has an invalid trader or referenced vout" :
                "ECX deposit does not match the confidential collateral vault profile");
        }
    }
}

BOOST_AUTO_TEST_CASE(haskell_runtime_settings_preserve_priority_and_lazy_height)
{
    const std::array<const char*, 5> errors{
        "private ECX BMM parameters require a private-E2E build",
        "private ECX BMM parameters are restricted to elementsregtest",
        "-ecxprivatebmmcheckpoint requires an explicit -ecxprivatebmmactivationheight",
        "-ecxprivatebmmactivationheight requires -ecxprivatebmmcheckpoint=1",
        "invalid -ecxprivatebmmactivationheight"};
    for (unsigned mask=0; mask<32; ++mask) {
        const bool checkpoint=mask&1, activation=mask&2, private_build=mask&4, test_network=mask&8, height_ok=mask&16;
        const int expected=(!checkpoint && !activation) ? 0 : !private_build ? 18 : !test_network ? 19 :
            !activation ? 20 : !checkpoint ? 21 : !height_ok ? 22 : 0;
        std::vector<uint32_t> trace, wanted{0,1};
        if (checkpoint || activation) {
            wanted.push_back(2);
            if (private_build) {
                wanted.push_back(3);
                if (test_network && checkpoint && activation) wanted.push_back(4);
            }
        }
        std::string error{"unchanged"};
        BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeTransactionShape(
            drivechain::haskell::TransactionShape::RUNTIME_SETTINGS,
            [&](uint32_t step) { trace.push_back(step); return (mask & (1U<<step))!=0; },error), expected==0);
        BOOST_CHECK(trace==wanted);
        BOOST_CHECK_EQUAL(error,expected==0 ? "unchanged" : errors[expected-18]);
    }
}

BOOST_AUTO_TEST_CASE(haskell_activation_settings_preserve_optional_and_required_fields)
{
    for (unsigned mask=0; mask<1024; ++mask) {
        const bool present=(mask&511)!=0, network=mask&512, complete=(mask&255)==255;
        unsigned reads=0;
        try {
            const bool configured=drivechain::haskell::ExchangeActivationSettings([&](uint32_t step) {
                BOOST_CHECK_EQUAL(step,reads++);
                return (mask & (1U<<step))!=0;
            });
            BOOST_CHECK(!present || (network && complete));
            BOOST_CHECK_EQUAL(configured,present);
        } catch (const std::runtime_error& error) {
            BOOST_CHECK(present && (!network || !complete));
            const std::string expected = !network
                ? "ECX runtime activation parameters are restricted to elementsregtest; production deployments must freeze them in source"
                : "ECX regtest activation requires -ecxactivationheight, -ecxgenesisstateoutpoint, -ecxgenesisstateroot, -ecxchainid, -ecxforcedactiondomain, -ecxdepositinboxdomain, -ecxcollateralvaultscript, and -ecxcollateralvaultscripthash together";
            BOOST_CHECK_EQUAL(error.what(),expected);
        }
        BOOST_CHECK_EQUAL(reads,present ? 10U : 9U);
    }
}

BOOST_AUTO_TEST_CASE(haskell_distinct_identities_matches_pairwise_native)
{
    for (size_t count = 0; count <= 45; ++count) {
        std::vector<std::array<unsigned char, 32>> values(count);
        std::vector<const unsigned char*> identities;
        for (size_t i = 0; i < count; ++i) { values[i].fill(i); identities.push_back(values[i].data()); }
        BOOST_CHECK(drivechain::haskell::ExchangeDistinct(identities));
        for (size_t i = 0; i < count; ++i) for (size_t j = i + 1; j < count; ++j) {
            const auto saved = values[j];
            values[j] = values[i];
            BOOST_CHECK(!drivechain::haskell::ExchangeDistinct(identities));
            BOOST_CHECK(values[j] == values[i]);
            values[j] = saved;
        }
    }
    const std::array<const unsigned char*, 1> missing{nullptr};
    BOOST_CHECK_THROW(drivechain::haskell::ExchangeDistinct(missing), std::invalid_argument);
    const std::array<const unsigned char*, 46> oversized{};
    BOOST_CHECK_THROW(drivechain::haskell::ExchangeDistinct(oversized), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(haskell_frozen_bounds_matches_native_policy)
{
    for (const int64_t height : std::array<int64_t,8>{INT64_MIN,-1,0,1,INT_MAX-1,INT_MAX,int64_t{INT_MAX}+1,INT64_MAX}) {
        BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeFrozenBounds(
            std::array<uint64_t,2>{static_cast<uint64_t>(height),INT_MAX}), height>0 && height<INT_MAX);
    }
    const std::array<uint64_t, 16> baseline{TAPROOT_LEAF_TAPSIMPLICITY,12,6,64*1024,8,576*1024,768*1024,
        64,64,4096,6,3600,16*1024*1024,32,2100000000000000ULL,1008};
    for (size_t index = 0; index < baseline.size(); ++index) {
        for (uint64_t value : std::array<uint64_t, 7>{0,1,baseline[index]-1,baseline[index],baseline[index]+1,UINT32_MAX,UINT64_MAX}) {
            auto fields = baseline;
            fields[index] = value;
            const bool expected = fields[0] == TAPROOT_LEAF_TAPSIMPLICITY && fields[1] == 12 && fields[2] == 6 &&
                fields[3] == 64*1024 && fields[4] == 8 && fields[5] == 576*1024 && fields[6] == 768*1024 &&
                fields[7] == 64 && fields[8] == 64 && fields[9] == 4096 && fields[10] == 6 &&
                fields[11] != 0 && fields[12] != 0 && fields[12] <= 16*1024*1024 && fields[13] == 32 &&
                fields[14] == 2100000000000000ULL && fields[15] == 1008;
            const auto original = fields;
            BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeFrozenBounds(fields), expected);
            BOOST_CHECK(fields == original);
        }
    }
}

BOOST_AUTO_TEST_CASE(runtime_activation_summary_matches_native_policy)
{
    constexpr std::array<int32_t, 6> heights{INT32_MIN, -1, 0, 1, INT32_MAX - 1, INT32_MAX};
    for (const auto activation : heights) for (const auto private_height : heights) for (bool present : {false,true}) {
        const auto result = drivechain::haskell::ExchangeRuntimeActivation(activation,
            present ? std::optional<int32_t>{private_height} : std::nullopt);
        BOOST_CHECK_EQUAL(result.first, activation != INT32_MAX || present);
        BOOST_CHECK_EQUAL(result.second, std::min(activation, present ? private_height : INT32_MAX));
    }
}

BOOST_AUTO_TEST_CASE(haskell_frozen_profile_order_and_unwind)
{
    namespace hs = drivechain::haskell;
    for (unsigned mask = 0; mask < 256; ++mask) {
        for (size_t count = 0; count <= 3; ++count) {
            const bool network = mask & 1, canonical = mask & 2;
            const auto present = [&](size_t i) { return (mask >> (2 + 2*i)) & 1; };
            const auto matches = [&](size_t i) { return (mask >> (3 + 2*i)) & 1; };
            std::vector<uint32_t> expected{1};
            size_t applied{0};
            std::string error;
            if (network) {
                expected.push_back(2);
                if (!canonical) { expected.push_back(3); error = "hash"; }
                else for (;;) {
                    expected.push_back(4);
                    if (applied == count) break;
                    expected.push_back(5);
                    if (present(applied)) {
                        expected.push_back(6);
                        if (!matches(applied)) { expected.push_back(7); error = "override"; break; }
                    }
                    expected.push_back(8);
                    ++applied;
                }
            }
            size_t index{0};
            std::vector<uint32_t> trace;
            std::string caught;
            try {
                BOOST_CHECK_EQUAL(hs::ParentReplayStore(hs::ReplayStoreFlow::FROZEN_PROFILE,
                    [&](uint32_t step) -> uint32_t {
                        trace.push_back(step);
                        switch (step) {
                        case 1: return network;
                        case 2: return canonical;
                        case 3: throw std::runtime_error("hash");
                        case 4: return index < count;
                        case 5: BOOST_REQUIRE(index < count); return present(index);
                        case 6: BOOST_REQUIRE(index < count); return matches(index);
                        case 7: throw std::runtime_error("override");
                        case 8: BOOST_REQUIRE(index < count); ++index; return true;
                        default: throw std::logic_error("unexpected callback");
                        }
                    }), 1U);
            } catch (const std::runtime_error& e) { caught = e.what(); }
            BOOST_CHECK_EQUAL(caught, error);
            BOOST_CHECK_EQUAL(index, applied);
            BOOST_CHECK(trace == expected);
        }
    }
}

BOOST_AUTO_TEST_CASE(frozen_profile_real_argument_manager)
{
    const std::array<std::pair<const char*,const char*>,3> profile{{
        {"-first", "one"}, {"-second", "two"}, {"-third", "three"}}};
    const std::string valid_hash(64, 'a');
    for (bool network : {false,true}) for (bool conflict : {false,true}) {
        ArgsManager args;
        for (const auto& [name,value] : profile) args.AddArg(name, "", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
        const char* argv[]{"elements-test",conflict ? "-second=other" : "-second=two"};
        std::string parse_error;
        BOOST_REQUIRE(args.ParseParameters(2,argv,parse_error));
        std::string caught;
        try { ecx::ApplyFrozenProfile(args,network,network ? valid_hash.c_str() : nullptr,profile); }
        catch (const std::runtime_error& e) { caught=e.what(); }
        BOOST_CHECK_EQUAL(caught,network && conflict ?
            "operator override conflicts with the source-frozen ECX production profile: -second" : "");
        BOOST_CHECK_EQUAL(args.IsArgSet("-first"),network);
        if (network) BOOST_CHECK_EQUAL(args.GetArg("-first",""),"one");
        BOOST_CHECK_EQUAL(args.GetArg("-second",""),conflict ? "other" : "two");
        BOOST_CHECK_EQUAL(args.IsArgSet("-third"),network && !conflict);
        if (network && !conflict) {
            BOOST_CHECK_EQUAL(args.GetArg("-third",""),"three");
            BOOST_CHECK_NO_THROW(ecx::ApplyFrozenProfile(args,true,valid_hash.c_str(),profile));
        }
    }
    for (const auto& hash : {std::string{},std::string(63,'a'),std::string(65,'a'),std::string(64,'g'),
            std::string(63,'a')+" ",std::string(63,'a')+"\n",std::string(63,'a')+char(0x80)}) {
        ArgsManager args;
        BOOST_CHECK_EXCEPTION(ecx::ApplyFrozenProfile(args,true,hash.c_str(),profile),std::runtime_error,
            [](const auto& e) { return std::string{e.what()} == "source-frozen ECX production release-record hash is noncanonical"; });
        for (const auto& [name,value] : profile) BOOST_CHECK(!args.IsArgSet(name));
    }
    ArgsManager empty;
    BOOST_CHECK_NO_THROW(ecx::ApplyFrozenProfile(empty,true,valid_hash.c_str(),{}));
    for (const char digit : std::string{"0123456789abcdefABCDEF"}) {
        ArgsManager args;
        args.AddArg("-first", "", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
        const std::string hash(64,digit);
        ecx::ApplyFrozenProfile(args,true,hash.c_str(),std::span{profile}.first(1));
        BOOST_CHECK_EQUAL(args.GetArg("-first",""),"one");
    }
}

BOOST_AUTO_TEST_CASE(configuration_digest_admission_order)
{
    namespace hs = drivechain::haskell;
    for (const auto& script : std::vector<std::vector<unsigned char>>{{},{OP_TRUE},{OP_RETURN},{0,32,1},std::vector<unsigned char>(10000,0x51)}) {
        const uint256 digest = TestSha256(script);
        for (const auto& supplied : {uint256{},digest,uint256S("01")}) {
            bool hashed{false};
            std::vector<uint32_t> trace;
            std::string caught;
            try {
                hs::ParentReplayStore(hs::ReplayStoreFlow::REQUIRED_PAIR,[&](uint32_t step) -> uint32_t {
                    trace.push_back(step);
                    switch (step) {
                    case 1: return !supplied.IsNull();
                    case 2: hashed=true; return supplied==TestSha256(script);
                    default: throw std::runtime_error("-ecxcollateralvaultscripthash does not match the frozen raw script bytes");
                    }
                });
            } catch (const std::runtime_error& e) { caught=e.what(); }
            const bool accepted=!supplied.IsNull() && supplied==digest;
            BOOST_CHECK_EQUAL(hashed,!supplied.IsNull());
            BOOST_CHECK_EQUAL(caught,accepted ? "" : "-ecxcollateralvaultscripthash does not match the frozen raw script bytes");
            const auto expected=supplied.IsNull() ? std::vector<uint32_t>{1,3} :
                accepted ? std::vector<uint32_t>{1,2} : std::vector<uint32_t>{1,2,3};
            BOOST_CHECK(trace==expected);
        }
    }
}

BOOST_AUTO_TEST_CASE(persisted_exchange_scan_short_circuits)
{
    const std::array<COutPoint,3> expected{{
        {Txid::FromUint256(uint256S("e31f7fb1e9489bfb9f6a73c10f80ecdcce1f276fbdf0cf85c02e3bcf174dc041")),0},
        {Txid::FromUint256(uint256S("c3fd019db845c81a68a561f5ab67d92c3ab2505cb2c8212f02511e07e8c2f2a1")),0},
        {Txid::FromUint256(uint256S("0cc4c302121a9d75c8a0e520253c1740520a6d6f4d03db6947a99565175d6586")),0}}};
    struct View final : CCoinsView {
        std::array<std::optional<Coin>,3> coins;
        mutable std::vector<COutPoint> reads;
        size_t fault{3};
        std::optional<Coin> GetCoin(const COutPoint& outpoint) const override {
            const auto index=reads.size();
            reads.push_back(outpoint);
            if (index==fault) throw std::runtime_error("coin read failure");
            return coins.at(index);
        }
    };
    for (unsigned pattern=0; pattern<27; ++pattern) for (size_t fault=0; fault<=3; ++fault) {
        View view;
        view.fault=fault;
        size_t first=3;
        unsigned states=pattern;
        for (size_t i=0; i<3; ++i,states/=3) {
            if (states%3==1) view.coins[i]=Coin{};
            if (states%3==2) {
                view.coins[i]=Coin(CTxOut(policyAsset,1,CScript{} << OP_TRUE),1,false);
                first=std::min(first,i);
            }
        }
        const size_t count=std::min(first+1,size_t{3});
        if (fault<count) BOOST_CHECK_EXCEPTION(ecx::HasPersistedExchangeConsensusState(view),std::runtime_error,
            [](const auto& e) { return std::string{e.what()}=="coin read failure"; });
        else BOOST_CHECK_EQUAL(ecx::HasPersistedExchangeConsensusState(view),first<3);
        const size_t reads=std::min(count,fault+1);
        BOOST_REQUIRE_EQUAL(view.reads.size(),reads);
        BOOST_CHECK(std::equal(view.reads.begin(),view.reads.end(),expected.begin()));
    }
}

BOOST_AUTO_TEST_CASE(haskell_result_rejection_preserves_diagnostics_and_outputs)
{
    namespace hs = drivechain::haskell;
    std::string error{"unchanged"};
    uint32_t seen{0};
    BOOST_CHECK_EXCEPTION(hs::ExchangeSourceMarker(seen, static_cast<hs::SourceMarker>(3), true, error),
        std::runtime_error, [](const auto& e) { return std::string(e.what()) == "Haskell exchange source marker failed"; });
    BOOST_CHECK_EQUAL(seen, 0U);
    uint64_t forced{17}, deposit{19};
    const std::array<uint64_t, 4> cursors{};
    BOOST_CHECK_EXCEPTION(hs::ExchangeCursors(UINT32_MAX, cursors, forced, deposit, error),
        std::runtime_error, [](const auto& e) { return std::string(e.what()) == "Haskell exchange cursor validation failed"; });
    BOOST_CHECK_EQUAL(forced, 17U);
    BOOST_CHECK_EQUAL(deposit, 19U);
    std::array<unsigned char, 64> output;
    output.fill(0xa5);
    const std::vector<unsigned char> oversized(100001);
    BOOST_CHECK_EXCEPTION(hs::ExchangeM6Preimage(oversized, output, error),
        std::runtime_error, [](const auto& e) { return std::string(e.what()) == "Haskell ECX M6 parser failed"; });
    BOOST_CHECK(std::all_of(output.begin(), output.end(), [](auto byte) { return byte == 0xa5; }));
    unsigned reads{0};
    BOOST_CHECK_EXCEPTION(hs::ExchangeDisconnect(static_cast<hs::DisconnectPhase>(4),
        [&](uint32_t) { ++reads; return true; }, error), std::runtime_error,
        [](const auto& e) { return std::string(e.what()) == "Haskell exchange disconnect failed"; });
    BOOST_CHECK_EQUAL(reads, 0U);
    BOOST_CHECK(!hs::ExchangeConfiguration([](uint32_t) { return false; }, error));
    BOOST_CHECK_EQUAL(error, "unchanged");
}

BOOST_AUTO_TEST_CASE(haskell_deployment_preserves_order)
{
    const std::array<const char*, 4> errors{
        "unsupported ECX deployment version", "public ECX deployment requires zero blinders",
        "ECX bond V2 activation is disabled", "ECX bond V2 identities are not source-frozen"};
    for (uint32_t version : {0U, 1U, 2U, 3U, 4U, UINT32_MAX}) {
        const std::vector<unsigned> steps = version == 2 ? std::vector<unsigned>{3,4} :
            version == 3 ? std::vector<unsigned>{0,1,2,3,4} : std::vector<unsigned>{};
        for (unsigned mask = 0; mask < 32; ++mask) {
            unsigned code = version == 2 || version == 3 ? 0 : 1;
            std::vector<unsigned> expected, observed;
            for (unsigned step : steps) {
                expected.push_back(step);
                if (!(mask & (1U << step))) { code = step < 3 ? 2 : step; break; }
            }
            std::string error{"unchanged"};
            BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeDeployment(version, [&](uint32_t step) {
                observed.push_back(step);
                return (mask & (1U << step)) != 0;
            }, error), code == 0);
            BOOST_CHECK(observed == expected);
            BOOST_CHECK_EQUAL(error, code ? errors[code-1] : "unchanged");
        }
        for (unsigned failed : steps) {
            std::string error{"unchanged"};
            BOOST_CHECK_THROW(drivechain::haskell::ExchangeDeployment(version, [&](uint32_t step) {
                if (step == failed) throw std::logic_error("deployment read");
                return true;
            }, error), std::logic_error);
            BOOST_CHECK_EQUAL(error, "unchanged");
        }
    }
}

BOOST_AUTO_TEST_CASE(haskell_genesis_initialization_preserves_order)
{
    const std::array<const char*, 4> errors{
        "ECX genesis initialization requires nonzero authenticated context",
        "ECX legacy genesis cannot contain checkpoint initialization fields",
        "ECX checkpoint genesis initialization has invalid ordering or version",
        "ECX genesis initialization is not the pinned authenticated ancestor"};
    for (uint32_t version : {0U, 1U, 2U, 3U, UINT32_MAX}) {
        std::vector<unsigned> steps{0,1};
        if (version == 0) steps.insert(steps.end(), {2,3,4});
        if (version == 2) for (unsigned i = 5; i < 19; ++i) steps.push_back(i);
        for (unsigned mask = 0; mask < (1U << steps.size()); ++mask) {
            unsigned first{0};
            while (first < steps.size() && (mask & (1U << first))) ++first;
            const unsigned code = first == steps.size() ? (version == 0 || version == 2 ? 0 : 3) :
                steps[first] < 2 ? 1 : steps[first] < 5 ? 2 : steps[first] < 14 ? 3 : 4;
            size_t reads{0}, publications{0};
            std::string error{"unchanged"};
            BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeGenesisInitialization(version, [&](uint32_t step) {
                if (step >= 19) {
                    BOOST_CHECK_EQUAL(code, 0U);
                    BOOST_CHECK_EQUAL(step, version == 0 ? 19U : 20U);
                    BOOST_CHECK_EQUAL(reads, steps.size());
                    ++publications;
                    return true;
                }
                BOOST_REQUIRE(reads < steps.size());
                BOOST_CHECK_EQUAL(step, steps[reads]);
                return (mask & (1U << reads++)) != 0;
            }, error), code == 0);
            BOOST_CHECK_EQUAL(reads, std::min(steps.size(), size_t{first + 1}));
            BOOST_CHECK_EQUAL(publications, code == 0 ? 1U : 0U);
            BOOST_CHECK_EQUAL(error, code == 0 ? "unchanged" : errors[code-1]);
        }
        if (version == 0 || version == 2) {
            steps.push_back(version == 0 ? 19 : 20);
            std::string error{"unchanged"};
            BOOST_CHECK_THROW(drivechain::haskell::ExchangeGenesisInitialization(version,
                [](uint32_t step) { return step < 19; }, error), std::runtime_error);
            BOOST_CHECK_EQUAL(error, "unchanged");
        }
        for (unsigned failed : steps) {
            std::string error{"unchanged"};
            BOOST_CHECK_THROW(drivechain::haskell::ExchangeGenesisInitialization(version, [&](uint32_t step) {
                if (step == failed) throw std::logic_error("genesis read");
                return true;
            }, error), std::logic_error);
            BOOST_CHECK_EQUAL(error, "unchanged");
        }
    }
}

BOOST_AUTO_TEST_CASE(haskell_capital_snapshot_preserves_complete_serialization)
{
    FastRandomContext random{true};
    for (uint32_t profile=0;profile<3;++profile) for (unsigned sample=0;sample<256;++sample) {
        std::array<uint256,10> context;
        for (auto& hash : context) for (auto& byte : hash) byte=random.randbits(8);
        std::vector<unsigned char> values(profile==0 ? 850 : profile==1 ? 1627 : 364);
        for (auto& byte : values) byte=random.randbits(8);
        const uint64_t height=sample==0 ? 0 : sample==1 ? UINT64_MAX : random.rand64();
        const uint64_t mtp=sample==0 ? 28799 : sample==1 ? 28800 : random.rand64();
        const auto encode=[&] {
            return drivechain::haskell::ExchangeGenesisState(static_cast<drivechain::haskell::GenesisCodec>(8+profile),height,mtp,
                {context[0].begin(),context[1].begin(),context[2].begin(),context[3].begin(),context[4].begin(),
                 context[5].begin(),context[6].begin(),context[7].begin(),context[8].begin(),context[9].begin()},values);
        };
        const auto encoded=encode();
        DataStream expected;
        expected << ReferenceCapitalSnapshot(profile,values,context,height,mtp);
        BOOST_REQUIRE_EQUAL(expected.size(),914);
        BOOST_CHECK_EQUAL(HexStr(encoded),HexStr(expected));
        ecx::BondV2CapitalSnapshot restored;
        DataStream poisoned{std::vector<unsigned char>(914,0xa5)};
        poisoned >> restored;
        DataStream stream{encoded};
        stream >> restored;
        BOOST_CHECK(stream.empty());
        DataStream roundtrip;
        roundtrip << restored;
        BOOST_CHECK_EQUAL(HexStr(roundtrip),HexStr(expected));
        values.pop_back();
        BOOST_CHECK_THROW(encode(),std::runtime_error);
    }
}

BOOST_AUTO_TEST_CASE(haskell_genesis_snapshot_preserves_complete_serialization)
{
    FastRandomContext random{true};
    for (unsigned sample=0;sample<512;++sample) {
        std::array<uint256,15> hashes;
        for (auto& hash : hashes) for (auto& byte : hash) byte=random.randbits(8);
        const uint64_t height=sample==0 ? 0 : sample==1 ? UINT64_MAX : random.rand64();
        const uint64_t mtp=sample==0 ? 0 : sample==1 ? 28799 : sample==2 ? 28800 : sample==3 ? UINT64_MAX : random.rand64();
        const uint64_t price=sample==0 ? 0 : sample==1 ? UINT64_MAX : random.rand64();
        std::array<unsigned char,8> body;
        WriteBE64(body.data(),price);
        const auto encode=[&](std::span<const unsigned char> input) {
            return drivechain::haskell::ExchangeGenesisState(drivechain::haskell::GenesisCodec::GENESIS_SNAPSHOT,height,mtp,
                {hashes[0].begin(),hashes[1].begin(),hashes[2].begin(),hashes[3].begin(),hashes[4].begin(),
                 hashes[5].begin(),hashes[6].begin(),hashes[7].begin(),hashes[8].begin(),hashes[9].begin(),
                 hashes[10].begin(),hashes[11].begin(),hashes[12].begin(),hashes[13].begin(),hashes[14].begin()},input);
        };
        const auto encoded=encode(body);
        DataStream expected;
        expected << ReferenceGenesisCapitalSnapshot(hashes,height,mtp,price);
        BOOST_REQUIRE_EQUAL(expected.size(),914);
        BOOST_CHECK_EQUAL(HexStr(encoded),HexStr(expected));
        ecx::BondV2CapitalSnapshot restored;
        DataStream poisoned{std::vector<unsigned char>(914,0xa5)};
        poisoned >> restored;
        DataStream stream{encoded};
        stream >> restored;
        BOOST_CHECK(stream.empty());
        DataStream roundtrip;
        roundtrip << restored;
        BOOST_CHECK_EQUAL(HexStr(roundtrip),HexStr(expected));
        BOOST_CHECK_THROW(encode(std::span{body}.first(7)),std::runtime_error);
    }
}

BOOST_AUTO_TEST_CASE(haskell_bound_capital_projection_matches_reference)
{
    FastRandomContext random{true};
    for (uint32_t profile : {0U,1U}) for (unsigned sample=0;sample<128;++sample) {
        std::vector<unsigned char> values(profile==0 ? 850 : 1627);
        for (auto& byte : values) byte=random.randbits(8);
        const std::vector<size_t> offsets=profile==0 ? std::vector<size_t>{0,36,276,308} : std::vector<size_t>{4,388,420,452,484,516};
        std::array<uint256,7> identities;
        for (auto& byte : identities[0]) byte=random.randbits(8);
        for (size_t i=0;i<offsets.size();++i) std::copy_n(values.data()+offsets[i],32,identities[i+1].begin());
        std::array<uint256,10> context;
        for (auto& hash : context) for (auto& byte : hash) byte=random.randbits(8);
        context[4]=identities[0];
        std::array<unsigned char,914> output;
        const auto call=[&] {
            const auto expected=profile==0 ? std::initializer_list<const unsigned char*>{identities[0].begin(),identities[1].begin(),
                identities[2].begin(),identities[3].begin(),identities[4].begin()} :
                std::initializer_list<const unsigned char*>{identities[0].begin(),identities[1].begin(),identities[2].begin(),identities[3].begin(),
                    identities[4].begin(),identities[5].begin(),identities[6].begin()};
            return drivechain::haskell::ExchangeCapitalIdentity(profile,std::span<const unsigned char,32>{context[4].begin(),32},values,expected,{},
                {context[0].begin(),context[5].begin(),context[6].begin()},output);
        };
        output.fill(0xa5);
        BOOST_REQUIRE(call());
        DataStream reference;
        reference << ReferenceCapitalSnapshot(profile,values,context,0,0);
        BOOST_CHECK_EQUAL(HexStr(output),HexStr(reference));
        for (size_t i=0;i<=offsets.size();++i) {
            identities[i].begin()[0]^=1;
            output.fill(0xa5);
            BOOST_CHECK(!call());
            BOOST_CHECK(std::all_of(output.begin(),output.end(),[](auto byte) { return byte==0xa5; }));
            identities[i].begin()[0]^=1;
        }
    }
}

BOOST_AUTO_TEST_CASE(haskell_capital_identity_matches_native_fields)
{
    for (uint32_t profile : {0U,1U,2U}) {
        const std::vector<size_t> offsets = profile==2 ? std::vector<size_t>{4,36,100,164,196,228} :
            profile==1 ? std::vector<size_t>{4,388,420,452,484,516} :
            std::vector<size_t>{0,36,276,308};
        std::vector<unsigned char> values(profile==2 ? 364 : profile==1 ? 1627 : 850);
        for (size_t i = 0; i < values.size(); ++i) values[i] = i * 37;
        std::array<std::array<unsigned char, 32>, 7> expected{};
        std::array<unsigned char, 32> program{};
        for (size_t i = 0; i < program.size(); ++i) program[i] = i + 13;
        expected[0] = program;
        for (size_t i = 0; i < offsets.size(); ++i) std::copy_n(values.begin() + offsets[i], 32, expected[i+1].begin());
        uint64_t height=ReadBE64(values.data()+324),mtp=ReadBE64(values.data()+332);
        const auto check = [&] {
            if (profile) return drivechain::haskell::ExchangeCapitalIdentity(profile, program, values,
                {expected[0].data(), expected[1].data(), expected[2].data(), expected[3].data(),
                 expected[4].data(), expected[5].data(), expected[6].data()},
                profile==2 ? std::initializer_list<uint64_t>{height,mtp} : std::initializer_list<uint64_t>{});
            return drivechain::haskell::ExchangeCapitalIdentity(false, program, values,
                {expected[0].data(), expected[1].data(), expected[2].data(), expected[3].data(), expected[4].data()});
        };
        BOOST_CHECK(check());
        for (size_t i = 0; i < values.size(); ++i) {
            values[i] ^= 1;
            const bool matches = !(profile==2 && i>=324 && i<340) && std::none_of(offsets.begin(), offsets.end(), [&](size_t offset) {
                return i >= offset && i < offset + 32;
            });
            BOOST_CHECK_EQUAL(check(), matches);
            values[i] ^= 1;
        }
        for (auto& byte : program) { byte ^= 1; BOOST_CHECK(!check()); byte ^= 1; }
        for (auto& identity : expected) for (auto& byte : identity) {
            byte^=1;
            // The last two identities are not part of the finite profile.
            BOOST_CHECK_EQUAL(check(),profile==0 && &identity>=&expected[5]);
            byte^=1;
        }
        if (profile==2) {
            for (uint64_t value : {UINT64_C(0),UINT64_C(1),UINT64_MAX}) {
                height=value; mtp=value;
                WriteBE64(values.data()+324,value); WriteBE64(values.data()+332,value);
                BOOST_CHECK(check());
                height^=1; BOOST_CHECK(!check()); height^=1;
                mtp^=1; BOOST_CHECK(!check()); mtp^=1;
            }
        }
        BOOST_CHECK_THROW(drivechain::haskell::ExchangeCapitalIdentity(profile, program, values, {}), std::runtime_error);
        BOOST_CHECK_THROW(drivechain::haskell::ExchangeCapitalIdentity(profile, program, values, {nullptr}), std::invalid_argument);
        BOOST_CHECK_THROW(drivechain::haskell::ExchangeCapitalIdentity(3, program, values, {}), std::runtime_error);
    }
}

BOOST_AUTO_TEST_CASE(haskell_successor_binding_matches_native_fields)
{
    for (bool incremental : {false,true}) {
        std::vector<unsigned char> values(incremental ? 1627 : 850);
        for (size_t i=0;i<values.size();++i) values[i]=i*37;
        const std::array<size_t,4> offsets=incremental ? std::array<size_t,4>{36,100,132,164} :
            std::array<size_t,4>{68,132,164,196};
        const size_t scalar_offset=incremental ? 1284 : 228;
        std::array<std::array<unsigned char,32>,4> hashes;
        std::array<const unsigned char*,4> pointers;
        for (size_t i=0;i<hashes.size();++i) {
            std::copy_n(values.data()+offsets[i],32,hashes[i].data());
            pointers[i]=hashes[i].data();
        }
        std::array<uint64_t,3> context{ReadBE64(values.data()+scalar_offset),ReadBE64(values.data()+scalar_offset+8),
            incremental ? ReadBE64(values.data()+1300) : UINT64_MAX};
        const auto check=[&] { return drivechain::haskell::ExchangeSuccessorBinding(incremental,values,pointers,context); };
        const auto original=[&] {
            for (size_t i=0;i<hashes.size();++i)
                if (!std::equal(hashes[i].begin(),hashes[i].end(),values.begin()+offsets[i])) return false;
            return ReadBE64(values.data()+scalar_offset)==context[0] &&
                ReadBE64(values.data()+scalar_offset+8)==context[1] &&
                (!incremental || ReadBE64(values.data()+1300)==context[2]);
        };
        BOOST_REQUIRE(check());
        std::vector<size_t> bound_offsets(offsets.begin(),offsets.end());
        bound_offsets.insert(bound_offsets.end(),{scalar_offset,scalar_offset+8});
        if (incremental) bound_offsets.push_back(1300);
        for (unsigned mask=0;mask<(1U<<bound_offsets.size());++mask) {
            for (size_t i=0;i<bound_offsets.size();++i) if (mask & (1U<<i)) values[bound_offsets[i]]^=1;
            BOOST_CHECK_EQUAL(check(),original());
            for (size_t i=0;i<bound_offsets.size();++i) if (mask & (1U<<i)) values[bound_offsets[i]]^=1;
        }
        for (auto& byte : values) {
            byte^=1; BOOST_CHECK_EQUAL(check(),original()); byte^=1;
        }
        for (auto& hash : hashes) for (auto& byte : hash) {
            byte^=1; BOOST_CHECK_EQUAL(check(),original()); byte^=1;
        }
        for (uint64_t number : {UINT64_C(0),UINT64_C(1),UINT64_MAX}) {
            context.fill(number);
            WriteBE64(values.data()+scalar_offset,number);
            WriteBE64(values.data()+scalar_offset+8,number);
            if (incremental) WriteBE64(values.data()+1300,number);
            BOOST_REQUIRE(check());
            for (auto& scalar : context) {
                scalar^=1; BOOST_CHECK_EQUAL(check(),original()); scalar^=1;
            }
        }
        values.pop_back(); BOOST_CHECK_THROW(check(),std::runtime_error);
        values.push_back(0); values.push_back(0); BOOST_CHECK_THROW(check(),std::runtime_error);
        values.clear(); BOOST_CHECK_THROW(check(),std::runtime_error);
        pointers[0]=nullptr; BOOST_CHECK_THROW(check(),std::invalid_argument);
    }
}

BOOST_AUTO_TEST_CASE(haskell_checkpoint_preserves_read_order)
{
    const std::array<const char*, 3> errors{
        "ECX M6 envelope does not hash to hashWithdrawalBundle",
        "ECX M6 checkpoint is not a prior block",
        "ECX M6 checkpoint is not the committed active-chain state"};
    for (unsigned mask = 0; mask < 256; ++mask) {
        unsigned first{0};
        while (first < 8 && (mask & (1U << first))) ++first;
        unsigned reads{0};
        std::string error{"unchanged"};
        BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeCheckpoint([&](uint32_t step) {
            BOOST_CHECK_EQUAL(step, reads++);
            BOOST_REQUIRE(step <= first);
            return (mask & (1U << step)) != 0;
        }, error), first == 8);
        BOOST_CHECK_EQUAL(reads, std::min(8U, first + 1));
        BOOST_CHECK_EQUAL(error, first == 8 ? "unchanged" : errors[first == 0 ? 0 : first < 3 ? 1 : 2]);
    }
    for (unsigned failed = 0; failed < 8; ++failed) {
        unsigned reads{0};
        std::string error{"unchanged"};
        BOOST_CHECK_THROW(drivechain::haskell::ExchangeCheckpoint([&](uint32_t step) {
            ++reads;
            if (step == failed) throw std::logic_error("checkpoint read");
            return true;
        }, error), std::logic_error);
        BOOST_CHECK_EQUAL(reads, failed + 1);
        BOOST_CHECK_EQUAL(error, "unchanged");
    }
}

BOOST_AUTO_TEST_CASE(haskell_envelope_header_matches_native_policy)
{
    for (size_t size : {0U, 4U, 5U, 44U, 45U, 46U, 100045U, 100046U}) {
        for (unsigned version : {0U, 1U, 255U}) {
            for (uint32_t body : {0U, 1U, 100000U, 100001U, UINT32_MAX}) {
                std::vector<unsigned char> payload(size, 0);
                if (size > 4) payload[4] = version;
                if (size >= 45) WriteLE32(payload.data() + 41, body);
                std::string error{"unchanged"};
                const bool malformed = size < 45 || version != 1;
                const bool bad_length = body == 0 || body > 100000 || size != uint64_t{45} + body;
                BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeEnvelopeHeader(payload, error), !malformed && !bad_length);
                BOOST_CHECK_EQUAL(error, malformed ? "malformed ECX M6 envelope" :
                    bad_length ? "invalid ECX M6 envelope length" : "unchanged");
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(haskell_envelope_requirement_matches_native_policy)
{
    namespace hs = drivechain::haskell;
    enum class Decision { REJECT, SKIP, VERIFY };
    for (bool nonnull : {false,true}) for (bool changed : {false,true})
    for (bool prior_active : {false,true}) for (bool present : {false,true}) {
        std::string expected{"unchanged"}, actual{"unchanged"};
        auto decision = Decision::VERIFY;
        const bool needs = nonnull && (changed || !prior_active);
        if (!needs && !changed) {
            decision = present ? Decision::REJECT : Decision::SKIP;
            if (present) expected = "ECX M6 envelope may appear only when hashWithdrawalBundle changes";
        } else if (!nonnull) {
            decision = present ? Decision::REJECT : Decision::SKIP;
            if (present) expected = "ECX M6 envelope exists while clearing the withdrawal bundle commitment";
        } else if (!present) {
            decision = Decision::REJECT;
            expected = "withdrawal bundle commitment lacks its ECX M6 envelope";
        }
        unsigned remaining=present;
        std::vector<uint32_t> verification;
        const bool accepted=hs::ExchangeEnvelopeScan([&](uint32_t step) -> int32_t {
            switch (step) {
            case 0: return 0;
            case 4: return remaining!=0;
            case 13: --remaining; return 1;
            case 14: return unsigned(nonnull) | (unsigned(changed)<<1) | (unsigned(prior_active)<<2);
            case 15: case 16: case 17: verification.push_back(step); return 1;
            default: return 1;
            }
        },actual);
        BOOST_CHECK_EQUAL(accepted,decision!=Decision::REJECT);
        const std::vector<uint32_t> expected_verification=decision==Decision::VERIFY ? std::vector<uint32_t>{15,16,17} : std::vector<uint32_t>{};
        BOOST_CHECK(verification==expected_verification);
        BOOST_CHECK_EQUAL(actual, expected);
    }
}

BOOST_AUTO_TEST_CASE(haskell_m6_parser_matches_frozen_native_parser)
{
    const auto reference = [](const std::vector<unsigned char>& raw, std::array<unsigned char, 64>& commitments, std::string& error) {
    size_t offset{0};
    const auto read_le32 = [&raw, &offset](uint32_t& value) {
        if (offset + 4 > raw.size()) return false;
        value = ReadLE32(raw.data() + offset);
        offset += 4;
        return true;
    };
    const auto read_le64 = [&raw, &offset](uint64_t& value) {
        if (offset + 8 > raw.size()) return false;
        value = ReadLE64(raw.data() + offset);
        offset += 8;
        return true;
    };
    const auto read_compact = [&raw, &offset](uint64_t& value) {
        if (offset >= raw.size()) return false;
        const unsigned char prefix = raw[offset++];
        if (prefix < 253) { value = prefix; return true; }
        const size_t width = prefix == 253 ? 2 : prefix == 254 ? 4 : 8;
        if (offset + width > raw.size()) return false;
        value = width == 2 ? ReadLE16(raw.data() + offset) : width == 4 ? ReadLE32(raw.data() + offset) : ReadLE64(raw.data() + offset);
        offset += width;
        return (width == 2 && value >= 253) || (width == 4 && value > 0xffff) ||
            (width == 8 && value > 0xffffffffULL);
    };
    uint32_t version{0};
    uint64_t input_count{0};
    uint64_t output_count{0};
    if (!read_le32(version) || version != 2 || !read_compact(input_count) || input_count != 0 ||
        !read_compact(output_count) || output_count != 4) {
        error = "ECX M6 preimage has a noncanonical transaction prefix";
        return false;
    }
    std::array<std::vector<unsigned char>, 4> scripts;
    for (size_t i = 0; i < scripts.size(); ++i) {
        uint64_t amount{0};
        uint64_t script_size{0};
        if (!read_le64(amount) || !read_compact(script_size) || script_size > 10000 ||
            offset + script_size > raw.size()) {
            error = "ECX M6 preimage has an invalid output";
            return false;
        }
        scripts[i].assign(raw.begin() + offset, raw.begin() + offset + script_size);
        offset += script_size;
        if ((i == 0 || i == 1 || i == 3) && amount != 0) {
            error = "ECX M6 commitment outputs must remain zero-valued";
            return false;
        }
    }
    uint32_t locktime{0};
    if (!read_le32(locktime) || locktime != 0 || offset != raw.size()) {
        error = "ECX M6 preimage has trailing or noncanonical locktime bytes";
        return false;
    }
    if (scripts[1].size() != 34 || scripts[1][0] != OP_RETURN || scripts[1][1] != 32 ||
        scripts[3].size() != 39 || scripts[3][0] != OP_RETURN || scripts[3][1] != 37 ||
        !std::equal(scripts[3].begin() + 2, scripts[3].begin() + 6, "PXST") || scripts[3][6] != 1) {
        error = "ECX M6 preimage lacks its canonical commitment or PXST output";
        return false;
    }
    std::copy(scripts[1].begin() + 2, scripts[1].end(), commitments.begin());
    std::copy(scripts[3].begin() + 7, scripts[3].end(), commitments.begin() + 32);
    return true;
    };
    const auto check = [&](const std::vector<unsigned char>& raw) {
        std::array<unsigned char, 64> expected, actual;
        expected.fill(0xa5); actual.fill(0xa5);
        std::string old_error{"unchanged"}, new_error{"unchanged"};
        const auto preserved = raw;
        BOOST_CHECK_EQUAL(drivechain::haskell::ExchangeM6Preimage(raw, actual, new_error), reference(raw, expected, old_error));
        BOOST_CHECK_EQUAL(new_error, old_error);
        BOOST_CHECK(actual == expected);
        BOOST_CHECK(raw == preserved);
    };
    const auto canonical = TestM6(30, uint256S("33"), uint256S("44"));
    check(canonical);
    for (size_t size = 0; size < canonical.size(); ++size)
        check(std::vector<unsigned char>(canonical.begin(), canonical.begin() + size));
    for (size_t index = 0; index < canonical.size(); ++index) for (unsigned byte = 0; byte < 256; ++byte) {
        auto changed = canonical;
        changed[index] = byte;
        check(changed);
    }
    for (size_t size : {size_t{0}, size_t{1}, size_t{252}, size_t{253}, size_t{10000}, size_t{10001}}) {
        std::array<std::vector<unsigned char>, 4> scripts{
            std::vector<unsigned char>(size, 0x51), std::vector<unsigned char>(34, 0x12),
            std::vector<unsigned char>(size, 0x52), std::vector<unsigned char>(39, 0x34)};
        scripts[1][0] = OP_RETURN; scripts[1][1] = 32;
        const std::array<unsigned char, 7> prefix{OP_RETURN,37,'P','X','S','T',1};
        std::copy(prefix.begin(), prefix.end(), scripts[3].begin());
        DataStream stream;
        stream << uint32_t{2};
        WriteCompactSize(stream, 0);
        WriteCompactSize(stream, 4);
        for (unsigned index = 0; index < 4; ++index) stream << uint64_t{index == 2 ? UINT64_MAX : 0} << scripts[index];
        stream << uint32_t{0};
        const auto* data = reinterpret_cast<const unsigned char*>(stream.data());
        check(std::vector<unsigned char>(data, data + stream.size()));
    }
}

BOOST_AUTO_TEST_CASE(configuration_covenant_publication_order)
{
    for (uint32_t rejected : {0U,2U,3U,4U,6U,8U,10U,12U,16U}) {
        std::vector<uint32_t> expected;
        for (uint32_t step=1; step<=(rejected ? rejected : 18); ++step) expected.push_back(step);
        if (rejected) expected.push_back(rejected<4 ? 19 : rejected<12 ? 20 : rejected==12 ? 21 : 22);
        for (size_t fault=0; fault<=expected.size(); ++fault) {
            std::vector<uint32_t> seen,completed;
            const auto run=[&] {
                return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::CONFIGURATION_COVENANTS,
                    [&](uint32_t step) -> uint32_t {
                        seen.push_back(step);
                        BOOST_REQUIRE_EQUAL(step,expected.at(seen.size()-1));
                        if (seen.size()-1==fault) throw std::logic_error("covenant action fault");
                        if (step>18) throw std::runtime_error("covenant rejected "+std::to_string(step));
                        BOOST_CHECK(drivechain::haskell::ExchangeFrozenBounds(std::array<uint64_t,1>{1}));
                        completed.push_back(step);
                        return step!=rejected;
                    });
            };
            if (fault<expected.size()) BOOST_CHECK_EXCEPTION(run(),std::logic_error,
                [](const auto& error) { return std::string(error.what())=="covenant action fault"; });
            else if (rejected) BOOST_CHECK_EXCEPTION(run(),std::runtime_error,
                [&](const auto& error) { return std::string(error.what())=="covenant rejected "+std::to_string(expected.back()); });
            else BOOST_CHECK_EQUAL(run(),0U);
            const auto count=std::min(fault,size_t(rejected ? rejected : 18));
            BOOST_CHECK_EQUAL(completed.size(),count);
            for (uint32_t publication : {1U,5U,7U,9U,11U,13U,17U,18U})
                BOOST_CHECK_EQUAL(std::count(completed.begin(),completed.end(),publication),publication<=count ? 1 : 0);
            BOOST_CHECK_EQUAL(seen.size(),std::min(expected.size(),fault+1));
        }
    }
}

BOOST_AUTO_TEST_CASE(configuration_transaction_publication_order)
{
    using drivechain::haskell::ParentReplayStore;
    using drivechain::haskell::ReplayStoreFlow;
    for (uint32_t version : {0U,2U,3U,UINT32_MAX}) {
        const unsigned last = version==2 ? 8 : version==3 ? 9 : 11;
        const std::vector<uint32_t> expected = last==11 ? std::vector<uint32_t>{1,2,3,4,11} :
            last==8 ? std::vector<uint32_t>{1,2,3,4,5,6,7,8} : std::vector<uint32_t>{1,2,3,4,5,6,7,8,9};
        for (size_t fault=0; fault<=expected.size(); ++fault) {
            std::vector<uint32_t> seen;
            bool deployment=false,genesis=false;
            uint32_t published_version=0;
            const auto run=[&] {
                return ParentReplayStore(ReplayStoreFlow::CONFIGURATION_TRANSACTIONS,[&](uint32_t step) {
                    seen.push_back(step);
                    BOOST_REQUIRE_EQUAL(step,expected.at(seen.size()-1));
                    if (seen.size()-1==fault) throw std::logic_error("configuration action fault");
                    BOOST_CHECK(drivechain::haskell::ExchangeAvailable(drivechain::haskell::Availability::ROOT,
                        [](uint32_t) { return true; }));
                    if (step==3) deployment=true;
                    if (step==4) { published_version=version; return version; }
                    if (step==7) genesis=true;
                    if (step==8) return uint32_t(version==3);
                    if (step==11) throw std::runtime_error("unsupported ECX deployment version");
                    return uint32_t{1};
                });
            };
            if (fault<expected.size()) BOOST_CHECK_EXCEPTION(run(),std::logic_error,
                [](const auto& error) { return std::string(error.what())=="configuration action fault"; });
            else if (last==11) BOOST_CHECK_EXCEPTION(run(),std::runtime_error,
                [](const auto& error) { return std::string(error.what())=="unsupported ECX deployment version"; });
            else BOOST_CHECK_EQUAL(run(),0U);
            BOOST_CHECK_EQUAL(deployment,fault>2);
            BOOST_CHECK_EQUAL(published_version,fault>3 ? version : 0U);
            BOOST_CHECK_EQUAL(genesis,last!=11 && fault>6);
            BOOST_CHECK_EQUAL(seen.size(),std::min(expected.size(),fault+1));
        }
    }
}

BOOST_AUTO_TEST_CASE(envelope_scan_nested_reads_and_exceptions)
{
    const std::vector<std::pair<uint32_t,int32_t>> script{
        {0,0},{1,1},{2,1},{3,1},{4,1},{5,1},{6,1},{7,1},{8,1},{9,1},
        {10,1},{11,1},{12,1},{13,1},{4,0},{14,3},{15,1},{16,1},{17,1}};
    for (size_t fault=0; fault<=script.size(); ++fault) {
        size_t index{0};
        std::string error{"preserved"};
        const auto run = [&] {
            return drivechain::haskell::ExchangeEnvelopeScan([&](uint32_t step) -> int32_t {
                BOOST_CHECK_EQUAL(step,script.at(index).first);
                BOOST_CHECK(drivechain::haskell::ExchangeAvailable(
                    drivechain::haskell::Availability::ROOT,[](uint32_t) { return true; }));
                const auto reply = script[index++].second;
                if (index-1 == fault) throw std::logic_error("envelope read fault");
                return reply;
            },error);
        };
        if (fault < script.size()) {
            BOOST_CHECK_EXCEPTION(run(),std::logic_error,[](const auto& e) { return std::string(e.what()) == "envelope read fault"; });
        } else BOOST_CHECK(run());
        BOOST_CHECK_EQUAL(index,std::min(script.size(),fault+1));
        BOOST_CHECK_EQUAL(error,"preserved");
    }
}

BOOST_AUTO_TEST_CASE(withdrawal_envelope_encoding_matches_frozen_builder)
{
    for (uint32_t height : {0U, 1U, 255U, 256U, 65535U, 65536U, UINT32_MAX})
    for (size_t size : {size_t{0}, size_t{1}, size_t{75}, size_t{76}, size_t{255}, size_t{256},
                       size_t{65535}, size_t{65536}, size_t{100000}, size_t{100001}}) {
        ecx::WithdrawalBundleEnvelopeV1 envelope{height, uint256S("0123456789abcdef"), std::vector<unsigned char>(size)};
        for (size_t index = 0; index < size; ++index) envelope.m6_no_witness[index] = static_cast<unsigned char>(index*37);
        const auto preserved = envelope.m6_no_witness;
        if (size == 0 || size > 100000) {
            BOOST_CHECK_EXCEPTION(ecx::BuildWithdrawalBundleEnvelopeScript(envelope), std::invalid_argument,
                [](const std::invalid_argument& e) { return std::string(e.what()) == "ECX M6 envelope preimage size is invalid"; });
        } else {
            std::vector<unsigned char> expected{'E','C','X','M',1};
            for (unsigned shift = 0; shift < 32; shift += 8) expected.push_back((height >> shift) & 0xff);
            expected.insert(expected.end(), envelope.checkpoint_block_hash.begin(), envelope.checkpoint_block_hash.end());
            for (unsigned shift = 0; shift < 32; shift += 8) expected.push_back((size >> shift) & 0xff);
            expected.insert(expected.end(), preserved.begin(), preserved.end());
            BOOST_CHECK(ecx::BuildWithdrawalBundleEnvelopeScript(envelope) == (CScript{} << OP_RETURN << expected));
        }
        BOOST_CHECK(envelope.m6_no_witness == preserved);
    }
}

BOOST_AUTO_TEST_CASE(withdrawal_bundle_requires_authenticated_m6_pxst_preimage)
{
    const COutPoint genesis{Txid::FromUint256(uint256S("91")), 0};
    const uint256 state_root{uint256S("92")};
    const ecx::ExchangeConsensus consensus{ConfiguredConsensus(30, genesis, state_root)};
    CBlock before_block;
    TestBlockIndex before{before_block, 29};
    const uint256 before_hash{uint256S("93")};
    before.phashBlock = &before_hash;
    CBlock checkpoint_block;
    checkpoint_block.nVersion = CBlockHeader::EXCHANGE_STATE_HF_MASK;
    checkpoint_block.hashExchangeStateRoot = state_root;
    TestBlockIndex checkpoint{checkpoint_block, 30, &before};
    const uint256 checkpoint_hash{uint256S("94")};
    checkpoint.phashBlock = &checkpoint_hash;
    const std::vector<unsigned char> m6{
        TestM6(30, before.GetBlockHash(), state_root)};
    const ecx::WithdrawalBundleEnvelopeV1 envelope{
        30, checkpoint.GetBlockHash(), m6};

    CBlock block;
    block.nVersion = CBlockHeader::EXCHANGE_STATE_HF_MASK;
    block.hashExchangeStateRoot = state_root;
    block.hashWithdrawalBundle = Hash(m6);
    block.vtx = {TestCoinbase(ecx::BuildWithdrawalBundleEnvelopeScript(envelope))};
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        ecx::CheckWithdrawalBundleEnvelope(block, &checkpoint, 31, error, consensus),
        error);

    const CScript malformed = CScript{} << OP_RETURN << std::vector<unsigned char>{'E','C','X','M',2};
    for (bool duplicate : {false,true}) {
        CMutableTransaction coinbase{*block.vtx[0]};
        CTxOut extra = coinbase.vout.back();
        extra.scriptPubKey = malformed;
        if (duplicate) coinbase.vout.push_back(extra);
        else coinbase.vout.insert(coinbase.vout.begin(),extra);
        CBlock rejected{block};
        rejected.vtx = {MakeTransactionRef(std::move(coinbase))};
        BOOST_CHECK(!ecx::CheckWithdrawalBundleEnvelope(rejected,&checkpoint,31,error,consensus));
        BOOST_CHECK_EQUAL(error,duplicate ? "duplicate ECX M6 envelope" : "malformed ECX M6 envelope");
    }
    {
        CMutableTransaction coinbase{*block.vtx[0]};
        for (const auto& script : {CScript{} << OP_TRUE, CScript{} << OP_RETURN,
             CScript{} << OP_RETURN << std::vector<unsigned char>{'E','C','X','M'},
             ecx::BuildWithdrawalBundleEnvelopeScript(envelope) << OP_TRUE}) {
            CTxOut extra = coinbase.vout.back();
            extra.scriptPubKey = script;
            coinbase.vout.insert(coinbase.vout.begin(),extra);
        }
        CBlock ignored{block};
        ignored.vtx = {MakeTransactionRef(std::move(coinbase))};
        error = "preserved on success";
        BOOST_REQUIRE(ecx::CheckWithdrawalBundleEnvelope(ignored,&checkpoint,31,error,consensus));
        BOOST_CHECK_EQUAL(error,"preserved on success");
    }

    for (unsigned fault = 0; fault < 7; ++fault) {
        CBlock rejected{block};
        auto bad_envelope = envelope;
        const CBlockIndex* parent = &checkpoint;
        switch (fault) {
        case 0: rejected.hashWithdrawalBundle = uint256S("95"); break;
        case 1: parent = nullptr; break;
        case 2: bad_envelope.checkpoint_height = 31; break;
        case 3: bad_envelope.checkpoint_block_hash.SetNull(); break;
        case 4: checkpoint.pprev = nullptr; break;
        case 5: checkpoint.nVersion = 0; break;
        case 6: checkpoint.hashExchangeStateRoot.SetNull(); break;
        }
        rejected.vtx = {TestCoinbase(ecx::BuildWithdrawalBundleEnvelopeScript(bad_envelope))};
        BOOST_CHECK(!ecx::CheckWithdrawalBundleEnvelope(rejected, parent, 31, error, consensus));
        BOOST_CHECK_EQUAL(error, fault == 0 ? "ECX M6 envelope does not hash to hashWithdrawalBundle" :
            fault < 3 ? "ECX M6 checkpoint is not a prior block" :
            "ECX M6 checkpoint is not the committed active-chain state");
        checkpoint.pprev = &before;
        checkpoint.nVersion = checkpoint_block.nVersion;
        checkpoint.hashExchangeStateRoot = state_root;
    }

    CBlock missing{block};
    missing.vtx = {TestCoinbase()};
    BOOST_CHECK(!ecx::CheckWithdrawalBundleEnvelope(missing, &checkpoint, 31, error, consensus));
    BOOST_CHECK(error.find("lacks") != std::string::npos);

    CBlock wrong_pxst{block};
    const std::vector<unsigned char> bad_m6{
        TestM6(30, before.GetBlockHash(), state_root, 1)};
    wrong_pxst.hashWithdrawalBundle = Hash(bad_m6);
    wrong_pxst.vtx = {TestCoinbase(ecx::BuildWithdrawalBundleEnvelopeScript(
        ecx::WithdrawalBundleEnvelopeV1{30, checkpoint.GetBlockHash(), bad_m6}))};
    BOOST_CHECK(!ecx::CheckWithdrawalBundleEnvelope(
        wrong_pxst, &checkpoint, 31, error, consensus));
    BOOST_CHECK(error.find("PXST") != std::string::npos);

    TestBlockIndex committed{block, 31, &checkpoint};
    CBlock carry;
    carry.hashWithdrawalBundle = block.hashWithdrawalBundle;
    carry.vtx = {TestCoinbase()};
    BOOST_REQUIRE_MESSAGE(
        ecx::CheckWithdrawalBundleEnvelope(carry, &committed, 32, error, consensus),
        error);
    carry.vtx = {TestCoinbase(ecx::BuildWithdrawalBundleEnvelopeScript(envelope))};
    BOOST_CHECK(!ecx::CheckWithdrawalBundleEnvelope(carry, &committed, 32, error, consensus));
    BOOST_CHECK(error.find("only when") != std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()

#ifdef ECX_PRODUCTION_ACTIVATION_PROFILE_FROZEN
BOOST_FIXTURE_TEST_SUITE(ecx_frozen_alpha_profile_tests, FrozenAlphaProfileSetup)

BOOST_AUTO_TEST_CASE(load_actual_frozen_profile)
{
    BOOST_REQUIRE_EQUAL(Params().NetworkIDString(), "elements");
    BOOST_REQUIRE_EQUAL(Params().GetConsensus().hashGenesisBlock.GetHex(),
        "672af009bd90bfc6527a5a9dda4c83aba0048c15cff3697d07e89a7f96fa5bcd");
    const auto& consensus = ecx::LayerTwoLabsExchangeConsensus();
    BOOST_CHECK_EQUAL(consensus.activation_height,
        gArgs.GetIntArg("-ecxactivationheight", -1));
    BOOST_CHECK(consensus.bond_v2.activation_enabled);
    BOOST_CHECK(consensus.bond_v2.identities_frozen);
    BOOST_REQUIRE(consensus.bond_v2.deployment_transaction);
    BOOST_REQUIRE(consensus.bond_v2.genesis_transaction);
    BOOST_CHECK_EQUAL(consensus.genesis_state_outpoint.hash.GetHex(),
        consensus.bond_v2.genesis_transaction->GetHash().GetHex());
}

BOOST_AUTO_TEST_CASE(reject_conflicting_operator_override)
{
    gArgs.ForceSetArg("-ecxactivationheight", "1");
    BOOST_CHECK_EXCEPTION(ecx::LayerTwoLabsExchangeConsensus(), std::runtime_error,
        [](const std::runtime_error& error) {
            return std::string(error.what()).find(
                "operator override conflicts with the source-frozen") != std::string::npos;
        });
}

BOOST_AUTO_TEST_CASE(activation_annex_policy_requires_exact_frozen_bindings)
{
    CheckActivationAnnexPolicy(ecx::LayerTwoLabsExchangeConsensus());
}

BOOST_AUTO_TEST_SUITE_END()
#endif
