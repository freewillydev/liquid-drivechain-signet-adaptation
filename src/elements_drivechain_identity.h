// Copyright (c) 2026 The Elements developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ELEMENTS_DRIVECHAIN_IDENTITY_H
#define BITCOIN_ELEMENTS_DRIVECHAIN_IDENTITY_H

#ifdef ELEMENTS_DRIVECHAIN_IDENTITY_SELECTED
#error "Multiple frozen Elements network identities included in one translation unit"
#endif
#define ELEMENTS_DRIVECHAIN_IDENTITY_SELECTED

#include <array>
#include <cstdint>
#include <limits>
#include <haskell/resource_constants.h>

/**
 * Production identity of the sole built-in Elements Drivechain mainnet network.
 *
 * These values and the generated resource table have no runtime dependencies, so
 * startup gates, chain parameters, and wire codecs cannot silently drift.
 * Changing any network/consensus value defines a different network and
 * requires a new genesis. The explicitly labelled enforcer compatibility pin
 * instead invalidates the derived replay store through its identity hash.
 */
namespace ElementsDrivechainIdentity {

inline constexpr char NETWORK_ID[]{"elements"};
inline constexpr uint8_t SIDECHAIN_SLOT{24};

// Fresh child profile. An existing parent proposal cannot authorize this chain.
inline constexpr bool BETANET_EXISTING_ELEMENTS_TEST_PROFILE{false};
inline constexpr char PROPOSAL_TEXT[]{"Elements Native v1; native BIP300/301; replay v5; sequential M6; BMM block hash; Simplicity active; slot 24"};

inline constexpr char P2P_MAGIC_DOMAIN[]{"ecash-elements-native-slot24-p2p-v1"};
inline constexpr std::array<uint8_t, 4> P2P_MESSAGE_START{{0x97, 0xb2, 0x0d, 0x51}};
inline constexpr uint16_t P2P_PORT{7072};
inline constexpr uint16_t RPC_PORT{7071};
inline constexpr uint16_t MAINCHAIN_RPC_PORT{28532};
inline constexpr uint16_t ONION_TARGET_PORT{37072};
inline constexpr char DATA_DIR[]{"elements-native-v1"};

// Canonical child coinbase commitment: OP_RETURN || PUSHBYTES_37 ||
// "ELMTP" || parent_hash_internal_bytes.
inline constexpr std::array<uint8_t, 5> PARENT_COMMITMENT_TAG{{'E', 'L', 'M', 'T', 'P'}};

inline constexpr uint8_t PUBKEY_ADDRESS_PREFIX{68};
inline constexpr uint8_t SCRIPT_ADDRESS_PREFIX{13};
inline constexpr uint8_t BLINDED_ADDRESS_PREFIX{6};
inline constexpr uint8_t PARENT_PUBKEY_ADDRESS_PREFIX{0};
inline constexpr uint8_t PARENT_SCRIPT_ADDRESS_PREFIX{5};

// First byte(s) of SHA256 over the documented ASCII derivation domains.
inline constexpr char WIF_PREFIX_DOMAIN[]{"ecash-elements-drivechain-wif-v1"};
inline constexpr uint8_t SECRET_KEY_PREFIX{0x37};
inline constexpr char EXT_PUBLIC_KEY_PREFIX_DOMAIN[]{"ecash-elements-drivechain-extpub-v1"};
inline constexpr std::array<uint8_t, 4> EXT_PUBLIC_KEY_PREFIX{{0x18, 0x71, 0x7d, 0xf5}};
inline constexpr char EXT_SECRET_KEY_PREFIX_DOMAIN[]{"ecash-elements-drivechain-extprv-v1"};
inline constexpr std::array<uint8_t, 4> EXT_SECRET_KEY_PREFIX{{0xb2, 0x63, 0xbd, 0x77}};

inline constexpr char BECH32_HRP[]{"elements"};
inline constexpr char BLECH32_HRP[]{"elementsl"};
inline constexpr char PARENT_BECH32_HRP[]{"bc"};
inline constexpr char PARENT_BLECH32_HRP[]{"bc"};

inline constexpr char PARENT_GENESIS[]{
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"};
inline constexpr char PARENT_POW_LIMIT[]{
    "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
inline constexpr char PARENT_SIGNET_CHALLENGE[]{
    ""};
// Base LayerTwo-Labs/bip300301_enforcer revision whose parent-consensus
// parsing and state transitions are mirrored by the authenticated replay.
inline constexpr char BIP300301_ENFORCER_REVISION[]{
    "0e27251ef351a522c72ab9ef079f75e06075390f"};
// Parent compatibility rules mirrored in the accompanying enforcer:
// sequential authenticated M6/CTIP transitions and bundle reproposal.
// BIP300301_LOCAL_RULE_ID is raw SHA256 of this exact ASCII domain (no NUL).
inline constexpr char BIP300301_LOCAL_RULE_DOMAIN[]{
    "ELEMENTS_SLOT24_SEQUENTIAL_M6_REPROPOSAL_V1"};
inline constexpr char BIP300301_LOCAL_RULE_ID[]{"e3aef07fcbf7c2a8e1b51d1deba7d552df546079f4b4e49b966dd9b5d059fb39"};
inline constexpr uint32_t PEGIN_MIN_DEPTH{100};

inline constexpr char GENESIS_STYLE[]{"elements"};
inline constexpr uint8_t SIGNBLOCK_CHALLENGE_OPCODE{0x51}; // OP_TRUE
inline constexpr uint32_t MAX_BLOCK_SIGNATURE_SIZE{1};
inline constexpr uint32_t GENESIS_TIME{1784334600};
inline constexpr uint32_t GENESIS_NONCE{0};
inline constexpr uint32_t GENESIS_BITS{0x207fffff};
inline constexpr int32_t GENESIS_VERSION{1};

inline constexpr int TAPROOT_DEPLOYMENT_BIT{2};
inline constexpr int SIMPLICITY_DEPLOYMENT_BIT{21};
inline constexpr int64_t DEPLOYMENT_ALWAYS_ACTIVE{-1};
inline constexpr int64_t DEPLOYMENT_NO_TIMEOUT{std::numeric_limits<int64_t>::max()};
inline constexpr int DEPLOYMENT_MIN_ACTIVATION_HEIGHT{0};

inline constexpr char HISTORICAL_PROPOSAL_DESCRIPTION_HEX[]{""};
inline constexpr char HISTORICAL_PROPOSAL_HASH[]{
    "0000000000000000000000000000000000000000000000000000000000000000"};
inline constexpr uint32_t HISTORICAL_PROPOSAL_HEIGHT{0};
inline constexpr char HISTORICAL_PROPOSAL_BLOCK_HASH[]{
    "0000000000000000000000000000000000000000000000000000000000000000"};
inline constexpr uint32_t HISTORICAL_ACTIVATION_HEIGHT{0};
inline constexpr char HISTORICAL_ACTIVATION_BLOCK_HASH[]{
    "0000000000000000000000000000000000000000000000000000000000000000"};

inline constexpr uint32_t PARENT_CHECKPOINT_HEIGHT{967679};
inline constexpr char PARENT_CHECKPOINT_HASH[]{
    "00000000000000000001b58cb69869f6067f0ecb3f2fe0f2263e62ba1ccb0c41"};
inline constexpr char PARENT_CHECKPOINT_CHAINWORK[]{
    "000000000000000000000000000000000000000148a384d49682843d3c74a5a0"};
inline constexpr char PARENT_CHECKPOINT_CTIP_TXID[]{
    "0000000000000000000000000000000000000000000000000000000000000000"};
inline constexpr uint32_t PARENT_CHECKPOINT_CTIP_VOUT{4294967295};
inline constexpr int64_t PARENT_CHECKPOINT_CTIP_VALUE{0};
// SHA256 of the canonical authenticated parent replay bootstrap state. Zero
// means the legacy genesis-derived bootstrap. A nonzero value is inseparable
// from the child identity and replay-store identity.
inline constexpr char PARENT_CHECKPOINT_BOOTSTRAP_STATE_COMMITMENT[]{
    "d03b3b5cb1d1afdb48645d258335fa8407a8ff5d71459568e4ddf419f75b6f5b"};

inline constexpr uint16_t UNUSED_PROPOSAL_MAX_AGE{2016};
inline constexpr uint16_t UNUSED_ACTIVATION_THRESHOLD{1008};
inline constexpr uint16_t USED_PROPOSAL_MAX_AGE{26300};
inline constexpr uint16_t USED_ACTIVATION_THRESHOLD{13150};
inline constexpr uint16_t WITHDRAWAL_BUNDLE_MAX_AGE{26300};
inline constexpr uint16_t WITHDRAWAL_BUNDLE_INCLUSION_THRESHOLD{13150};
inline constexpr uint32_t PARENT_REPLAY_VERSION{5};
inline constexpr uint32_t ANNEX_FEATURE_VERSION{2};
inline constexpr uint16_t CURRENT_BMM_PARENT_MTP_JET_CATALOGUE_ITEM{51};
inline constexpr std::array<uint8_t, 3> CURRENT_BMM_PARENT_MTP_JET_ENCODING{{
    0x7c, 0x38, 0xcc,
}};
inline constexpr std::array<uint8_t, 32> CURRENT_BMM_PARENT_MTP_JET_CMR{{
    0x12, 0xdc, 0x3d, 0x4f, 0x22, 0x46, 0x68, 0x73,
    0xda, 0xaf, 0x83, 0xb1, 0x0e, 0x1c, 0xfa, 0x1e,
    0xa5, 0x51, 0xe2, 0x3a, 0xe7, 0xd0, 0xfb, 0xd6,
    0xd9, 0xda, 0x64, 0xce, 0x7e, 0x89, 0xa3, 0xe2,
}};
inline constexpr uint64_t CURRENT_BMM_PARENT_MTP_JET_COST_MWU{108};

// Filled from the reproducible CElementsDrivechainParams construction. These
// strings are compared by the release-mode startup identity gate.
inline constexpr char PROTOCOL_MANIFEST_HASH[]{"94831880cee118fe5266ebf3945528b370b1a0f668fb76cf2c3ca756b8d1068c"};
inline constexpr char PROPOSAL_DESCRIPTION_HEX[]{"0008456c656d656e7473456c656d656e7473204e61746976652076313b206e6174697665204249503330302f3330313b207265706c61792076353b2073657175656e7469616c204d363b20424d4d20626c6f636b20686173683b2053696d706c6963697479206163746976653b20736c6f742032348c06d1b856a73c2ccf76fb68f6a0b170b3285594f3eb6652fe18e1ce8018839490448700bdaa1ef40ccf2a02d8d07b9fb5cd598f"};
inline constexpr char PROPOSAL_HASH[]{"a9980eaa8bb6893d4baea100f484000b4f72e4640fc0d9f3ebf8a2f29ae63460"};
inline constexpr char IDENTITY_COMMITMENT[]{"948c7254ea3df2c1e84f5b4e0f85b631e55ec44aad0b54f3ad624f2aea4ff7d3"};
inline constexpr char GENESIS_HASH[]{"fe05f7c76cfb50ef4f5594c761df25581e95a9946a64bc9d8f567235ffa485c9"};
inline constexpr char GENESIS_MERKLE_ROOT[]{"d5a55d8261a4baaceca67e2c6b21bdeb4f3d56d579d05c188516be02b96b90d6"};
inline constexpr char PEGGED_ASSET[]{"2e69819685c22252a706f69ce67ab9ab36a633b91e61f6ee69216d6e1c7e90d3"};

} // namespace ElementsDrivechainIdentity

#endif // BITCOIN_ELEMENTS_DRIVECHAIN_IDENTITY_H
