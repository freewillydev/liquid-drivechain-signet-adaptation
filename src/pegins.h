// Copyright (c) 2017-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PEGINS_H
#define BITCOIN_PEGINS_H

#include <consensus/amount.h>
#include <consensus/params.h>
#include <merkleblock.h>
#include <primitives/bitcoin/transaction.h>
#include <primitives/bitcoin/merkleblock.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <chain.h>

#include <string>
#include <variant>
#include <vector>

struct DrivechainDepositEvidence
{
    std::vector<unsigned char> deposit_tx;
    std::vector<unsigned char> txout_proof;
    std::vector<unsigned char> previous_ctip_tx;
    int64_t sequence_number{0};
    int64_t previous_sequence_number{0};
    std::vector<Sidechain::Bitcoin::CBlockHeader> headers;
};

struct DrivechainMintableDeposit;
/** Canonical opaque M5 destination: legacy address, or dcfee1:<satoshis>:<address>.
 * The parent replay authenticates these exact bytes, including the fee.
 */
bool DecodeDrivechainDepositDestination(const std::string& payload, CScript& recipient, CAmount& fee);
std::string EncodeDrivechainDepositDestination(const std::string& address, CAmount fee);
/** Construct the exact native claim; normal consensus validation authenticates it. */
CTransactionRef CreateNativeDrivechainDeposit(const DrivechainMintableDeposit& deposit);

/** Calculates script necessary for p2ch peg-in transactions */
CScript calculate_contract(const CScript& federationRedeemScript, const CScript& witnessProgram);
bool GetAmountFromParentChainPegin(CAmount& amount, const Sidechain::Bitcoin::CTransaction& txBTC, unsigned int nOut);
bool GetAmountFromParentChainPegin(CAmount& amount, const CTransaction& txBTC, unsigned int nOut);
/** Check whether a parent chain block hash satisfies the proof-of-work requirement specified by nBits */
bool CheckParentProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params&);
/**
 * Check pegin witness validity. For native deposits, child_height must come
 * from the validated block index or active tip + 1, not witness data. The
 * default unknown height retains the historical confirmation depth.
 */
bool IsValidPeginWitness(const CScriptWitness& pegin_witness,
                         const std::vector<std::pair<CScript, CScript>>& fedpegscripts,
                         const COutPoint& prevout,
                         std::string& err_msg,
                         bool check_depth,
                         bool* depth_failed = nullptr,
                         bool* parent_unavailable = nullptr,
                         int child_height = -1);
/** Parse a BIP300 deposit witness. This does not by itself authorize minting. */
/** Haskell codec classification: 0 invalid, 1 legacy, 2 native, 3 deterministic.
 * Modes: 0 any, 1 ECX only, 2 native only. Value is written only on success.
 * Recognition does not authenticate parent evidence or authorize minting.
 */
int32_t DepositWitnessKind(const CScriptWitness& witness, const COutPoint& prevout,
                          uint32_t mode, CAmount& value);
bool IsDrivechainDepositPeginWitness(const CScriptWitness& pegin_witness,
                                     const COutPoint& prevout,
                                     CAmount* value = nullptr,
                                     CScript* claim_script = nullptr,
                                     uint256* mainchain_block_hash = nullptr,
                                     std::vector<unsigned char>* address = nullptr);
/**
 * Recognize only the ECX legacy/deterministic deposit codecs, never a native
 * Alpha CTIP witness. This selects ECX anchor/state handling; it does not
 * authorize minting or replace verification of the deterministic evidence.
 */
bool IsEcxDrivechainDepositPeginWitness(const CScriptWitness& pegin_witness,
                                       const COutPoint& prevout);
/** Require the committed sidechain address to receive the exact deposit amount. */
bool CheckDrivechainDepositOutputs(const CTransaction& tx, unsigned int pegin_index, std::string& err_msg);
/**
 * Match the uniquely bounded zero-fee native-deposit transaction shape used
 * by relay and block assembly policy. This performs no parent RPC.
 */
bool IsCanonicalFeeFreeDrivechainDeposit(const CTransaction& tx);
/** Return true only for the historical v1 marker format. */
bool IsLegacyDrivechainDepositPeginWitness(const CScriptWitness& pegin_witness);

/** Extract the consensus-anchored fields from a BIP300/301 drivechain deposit import. */
bool GetDrivechainDepositPeginData(const CScriptWitness& pegin_witness, const COutPoint& prevout, CAmount& value, CScript& claim_script, uint256& mainchain_txid);
/** Decode the deterministic v2 evidence committed by a drivechain deposit witness. */
bool GetDrivechainDepositEvidence(const CScriptWitness& pegin_witness, const COutPoint& prevout, DrivechainDepositEvidence& evidence, std::string& error);
/** Return the duplicate-claim key used for sidechain pegin/deposit spent tracking. */
std::pair<uint256, COutPoint> GetPeginSpentKey(const CScriptWitness& pegin_witness, const COutPoint& prevout);
/** Create a proof reference for a BIP300/301 drivechain deposit import. */
CScriptWitness CreateDrivechainDepositPeginWitness(const CAmount& value,
                                                   const CAsset& asset,
                                                   const uint256& genesis_hash,
                                                   const CScript& claim_script,
                                                   const COutPoint& mainchain_outpoint,
                                                   const uint256& mainchain_block_hash,
                                                   const std::vector<unsigned char>& address);
/** Create a pegin witness for a trusted BIP300/301 drivechain deposit import. */
CScriptWitness CreateDrivechainDepositPeginWitness(const CAmount& value, const CAsset& asset, const uint256& genesis_hash, const CScript& claim_script, const uint256& mainchain_txid);
/** Create a deterministic v2 drivechain deposit witness. */
CScriptWitness CreateDrivechainDepositPeginWitness(
    const CAmount& value,
    const CAsset& asset,
    const uint256& genesis_hash,
    const CScript& claim_script,
    const DrivechainDepositEvidence& evidence);

/* Consensus-critical. Matching against telescoped multisig used on Liquid v1:
 * Pseudo-structure:
 * Check number of elements on stack
 * If enough for federation multisig, push all multisig args onto stack except OP_CMS
 * If not, check CSV timeout, then if successful, push emergency key multisig args on
 * stack except OP_CMS. End if, then push OP_CMS.
 */
bool MatchLiquidWatchman(const CScript& script);

/** Get full fedpegscripts from two previous epoch starts based on given index
 * nextblock_validation is false when doing block validation, true for mempool
 * or "lookahead" purposes. Newest epochs first. The first returned element is the
 * scriptPubKey for the script, the second is the witnessScript. */
std::vector<std::pair<CScript, CScript>> GetValidFedpegScripts(const CBlockIndex* pblockindex, const Consensus::Params& params, bool nextblock_validation);

/** Create the peg-in witness stack */
CScriptWitness CreatePeginWitness(const CAmount& value, const CAsset& asset, const uint256& genesis_hash, const CScript& claim_script, const CTransactionRef& tx_ref, const CMerkleBlock& merkle_block);
CScriptWitness CreatePeginWitness(const CAmount& value, const CAsset& asset, const uint256& genesis_hash, const CScript& claim_script, const Sidechain::Bitcoin::CTransactionRef& tx_ref, const Sidechain::Bitcoin::CMerkleBlock& merkle_block);

/** Break out the individual parts of the peg-in witness stack */
bool DecomposePeginWitness(const CScriptWitness& witness, CAmount& value, CAsset& asset, uint256& genesis_hash, CScript& claim_script, std::variant<std::monostate, Sidechain::Bitcoin::CTransactionRef, CTransactionRef>& tx, std::variant<std::monostate, Sidechain::Bitcoin::CMerkleBlock, CMerkleBlock>& merkle_block);

#endif // BITCOIN_PEGINS_H
