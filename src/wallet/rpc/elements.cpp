// Copyright (c) 2009-2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <assetsdir.h>
#include <node/drivechain_withdrawal_bundle.h>
#include <block_proof.h>
#include <core_io.h>
#include <deploymentstatus.h>
#include <drivechain_peg.h>
#include <drivechain_settings.h>
#include <drivechain_withdrawal.h>
#include <dynafed.h>
#include <hash.h>
#include <issuance.h>
#include <key_io.h>
#include <mainchainrpc.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <node/context.h>
#include <node/kernel_notifications.h>
#include <rpc/rawtransaction_util.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/generic.hpp>
#include <script/pegins.h>
#include <script/solver.h>
#include <secp256k1.h>
#include <streams.h>
#include <util/check.h>
#include <util/signalinterrupt.h>
#include <util/moneystr.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <common/args.h>
#include <util/fs_helpers.h>
#include <wallet/coincontrol.h>
#include <wallet/drivechain_withdrawal.h>
#include <haskell/bridge.h>
#include <haskell/bmm_constants.h>
#include <haskell/wallet_rpc.h>
#include <wallet/fees.h>
#include <wallet/receive.h>
#include <wallet/rpc/util.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <limits>
#include <optional>

using wallet::BlindDetails;
using wallet::CAddressBookData;
using wallet::CCoinControl;
using wallet::CRecipient;
using wallet::CWallet;
using wallet::CWalletTx;
using wallet::GetMinimumFee;
using wallet::GetWalletForJSONRPCRequest;
using wallet::IssuanceDetails;
using wallet::mapValue_t;
using wallet::LegacyScriptPubKeyMan;

// forward declarations
namespace wallet {
UniValue SendMoney(CWallet& wallet, const CCoinControl &coin_control, std::vector<CRecipient> &recipients, mapValue_t map_value, bool verbose, bool ignore_blind_fail);
RPCHelpMan signrawtransactionwithwallet();
}

// ELEMENTS commands

namespace {
static secp256k1_context *secp256k1_ctx;

static CAmount DrivechainWithdrawalFee(const CAmount amount)
{
    const CAmount fee = gArgs.GetIntArg(
        "-drivechainpegoutmainfeesats", DEFAULT_DRIVECHAIN_PEGOUT_MAIN_FEE_SATS);
    try {
        return drivechain::haskell::WithdrawalRpcFee(amount, fee);
    } catch (const std::invalid_argument& error) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, error.what());
    }
}


struct CheckpointWithdrawalBundle
{
    std::vector<unsigned char> bytes;
    std::vector<unsigned char> no_witness_bytes;
    uint32_t checkpoint_height{0};
    uint256 checkpoint_block_hash;
    uint256 previous_child_hash;
    uint256 exchange_state_root;
    uint256 m6id;
};


static CheckpointWithdrawalBundle BuildCheckpointWithdrawalBundle(
    CAmount amount,
    const CScript& payout_script,
    const COutPoint& withdrawal_outpoint,
    uint32_t sidechain_block_height,
    const uint256& checkpoint_block_hash,
    const uint256& child_genesis,
    const uint256& previous_child_hash,
    const uint256& exchange_state_root)
{
    CheckpointWithdrawalBundle bundle;
    auto encoded = wallet::BuildDrivechainWithdrawalBundle(
        amount, DrivechainWithdrawalFee(amount), payout_script, withdrawal_outpoint,
        sidechain_block_height, child_genesis, previous_child_hash, exchange_state_root);
    bundle.bytes = std::move(encoded.bytes);
    bundle.no_witness_bytes = std::move(encoded.no_witness_bytes);
    bundle.checkpoint_height = sidechain_block_height;
    bundle.checkpoint_block_hash = checkpoint_block_hash;
    bundle.previous_child_hash = previous_child_hash;
    bundle.exchange_state_root = exchange_state_root;
    bundle.m6id = encoded.m6id;
    return bundle;
}

static UniValue CallAuthenticatedDrivechainJSONResult(
    const std::string& enforcer,
    const std::string& method,
    const UniValue& payload)
{
    UniValue result;
    std::string error;
    if (!CallAuthenticatedDrivechainJSON(enforcer, method, payload, result, &error)) {
        throw JSONRPCError(RPC_MISC_ERROR, strprintf("Drivechain enforcer request failed: %s", error));
    }
    return result;
}

static UniValue CallMainChainRPCResult(const std::string& method, const UniValue& params)
{
    const UniValue reply = CallMainChainRPC(method, params);
    try {
        return CheckDrivechainRPCReply("mainchain " + method, reply, /*require_result=*/false);
    } catch (const std::runtime_error& error) {
        throw JSONRPCError(RPC_MISC_ERROR, error.what());
    }
}

static std::string FetchDrivechainWithdrawalBundleEventStatus(const int sidechain_id, const std::string& enforcer, const std::string& m6id_hex, std::string& mainchain_tip)
{
    UniValue no_params(UniValue::VARR);
    mainchain_tip = CallMainChainRPCResult("getbestblockhash", no_params).get_str();

    UniValue end_block_hash(UniValue::VOBJ);
    end_block_hash.pushKV("hex", mainchain_tip);

    UniValue payload(UniValue::VOBJ);
    payload.pushKV("sidechainId", sidechain_id);
    payload.pushKV("endBlockHash", end_block_hash);

    const UniValue peg_data = CallAuthenticatedDrivechainJSONResult(
        enforcer,
        "cusf.mainchain.v1.ValidatorService/GetTwoWayPegData",
        payload);
    return wallet::FindWithdrawalBundleEventStatus(peg_data, m6id_hex);
}

static UniValue VerifyDrivechainWithdrawalBundleEvent(const int sidechain_id, const std::string& enforcer, const std::string& m6id_hex)
{
    std::string mainchain_tip, status;
    UniValue verification;
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::BUNDLE_EVENT_CHECK,
      [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: status = FetchDrivechainWithdrawalBundleEventStatus(sidechain_id, enforcer, m6id_hex, mainchain_tip); return 1;
        case 2:
            verification.setObject();
            verification.pushKV("mainchain_tip", mainchain_tip);
            verification.pushKV("m6id", m6id_hex);
            verification.pushKV("event_status", status.empty() ? "missing" : status);
            return 1;
        case 3: return drivechain::haskell::ClassifyWithdrawalEvent(status).rejection;
        case 4: throw JSONRPCError(
            RPC_MISC_ERROR,
            strprintf(
                "Drivechain withdrawal bundle broadcast returned, but the enforcer has no withdrawal bundle event for M6 id %s at L1 tip %s",
                m6id_hex,
                mainchain_tip));
        case 5: throw JSONRPCError(RPC_MISC_ERROR, strprintf("Drivechain withdrawal bundle M6 id %s is already marked failed on L1", m6id_hex));
        default: throw std::logic_error("invalid withdrawal event check action");
        }
      });
    return verification;
}

static void ClearFinalDrivechainWithdrawalBundle()
{
    const uint256 current_bundle_hash = node::GetCurrentDrivechainWithdrawalBundleHash();
    std::string mainchain_tip, status;
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::BUNDLE_EVENT_CLEAR,
      [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return !current_bundle_hash.IsNull();
        case 2:
            status = FetchDrivechainWithdrawalBundleEventStatus(DEFAULT_DRIVECHAIN_SIDECHAIN_SLOT,
                GetDrivechainGrpcAddress(gArgs), current_bundle_hash.GetHex(), mainchain_tip);
            return 1;
        case 3: return drivechain::haskell::ClassifyWithdrawalEvent(status).clear;
        case 4: node::ClearCurrentDrivechainWithdrawalBundleHash(current_bundle_hash); return 1;
        default: throw std::logic_error("invalid withdrawal event clear action");
        }
      });
}

class DrivechainWithdrawalBundleCreationGuard
{
private:
    bool m_active{false};

public:
    DrivechainWithdrawalBundleCreationGuard()
    {
        uint256 current_bundle_hash;
        bool creation_in_progress{false};
        const bool acquired = node::TryBeginDrivechainWithdrawalBundleCreation(current_bundle_hash, creation_in_progress);
        const unsigned flags = (unsigned{acquired} << 1) | unsigned{creation_in_progress};
        switch (drivechain::WITHDRAWAL_BUNDLE_RESERVE_ACTIONS[flags][0]) {
        case 1: m_active = true; return;
        case 2: throw JSONRPCError(RPC_WALLET_ERROR, "A drivechain withdrawal bundle is already being created; wait for that sendtomainchain call to finish before creating another bundle");
        case 3: throw JSONRPCError(RPC_WALLET_ERROR, strprintf(
                "A drivechain withdrawal bundle is already active: %s. Wait for it to complete on L1 before creating another bundle",
                current_bundle_hash.GetHex()));
        default: std::terminate();
        }
    }

    ~DrivechainWithdrawalBundleCreationGuard()
    {
        for (const auto action : drivechain::WITHDRAWAL_BUNDLE_ABORT_ACTIONS[unsigned{m_active} << 1]) {
            switch (action) {
            case 0: return;
            case 1: node::AbortDrivechainWithdrawalBundleCreation(); break;
            default: std::terminate();
            }
        }
    }

    void Complete(const CheckpointWithdrawalBundle& bundle)
    {
        node::CompleteDrivechainWithdrawalBundleCreation(
            bundle.m6id,
            node::DrivechainWithdrawalBundleEnvelope{
                bundle.checkpoint_height,
                bundle.checkpoint_block_hash,
                bundle.no_witness_bytes});
        m_active = false;
    }
};

static UniValue BroadcastDrivechainWithdrawalBundle(const CheckpointWithdrawalBundle& bundle)
{
    const int sidechain_id = DEFAULT_DRIVECHAIN_SIDECHAIN_SLOT;

    const std::string tx_base64 = EncodeBase64(MakeUCharSpan(bundle.bytes));
    const std::string tx_hex = HexStr(bundle.bytes);
    const std::string m6id_hex = bundle.m6id.GetHex();

    UniValue payload(UniValue::VOBJ);
    payload.pushKV("sidechainId", sidechain_id);
    payload.pushKV("transaction", tx_base64);

    const std::string enforcer = GetDrivechainGrpcAddress(gArgs);
    UniValue result(UniValue::VOBJ);
    result.pushKV("enabled", true);
    result.pushKV("sidechain_id", sidechain_id);
    result.pushKV("enforcer", enforcer);
    result.pushKV("m6id", m6id_hex);
    result.pushKV("checkpoint_height", static_cast<uint64_t>(bundle.checkpoint_height));
    result.pushKV("checkpoint_block_hash", bundle.checkpoint_block_hash.GetHex());
    result.pushKV("previous_child_hash", bundle.previous_child_hash.GetHex());
    result.pushKV("exchange_state_root", bundle.exchange_state_root.GetHex());
    result.pushKV("withdrawal_bundle_hex", tx_hex);
    result.pushKV(
        "broadcast_response",
        CallAuthenticatedDrivechainJSONResult(
            enforcer,
            "cusf.mainchain.v1.BlockProducerService/ProposeWithdrawalBundle",
            payload));
    return result;
}

class CSecp256k1Init {
public:
    CSecp256k1Init() {
        secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    }
    ~CSecp256k1Init() {
        secp256k1_context_destroy(secp256k1_ctx);
    }
};
static CSecp256k1Init instance_of_csecp256k1;
}

namespace wallet {
RPCHelpMan signblock()
{
    return RPCHelpMan{"signblock",
                "\nSigns a block proposal, checking that it would be accepted first. Errors if it cannot sign the block. Note that this call adds the witnessScript to your wallet for signing purposes! This function is intended for QA and testing.\n",
                {
                    {"blockhex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex-encoded block from getnewblockhex"},
                    {"witnessScript", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The hex-encoded witness script. Required for dynamic federation blocks. Argument is \"\" when the block is P2WPKH."},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "pubkey", "signature's pubkey"},
                            {RPCResult::Type::STR_HEX, "sig", "the signature itself"},
                        }},
                    },
                },
                RPCExamples{
                    HelpExampleCli("signblock", "0000002018c6f2f913f9902aeab...5ca501f77be96de63f609010000000000000000015100000000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (!g_signed_blocks) {
        throw JSONRPCError(RPC_MISC_ERROR, "Signed blocks are not active for this network.");
    }

    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    CBlock block;
    if (!DecodeHexBlk(block, request.params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

    LegacyScriptPubKeyMan* spk_man = pwallet->GetLegacyScriptPubKeyMan();
    if (!spk_man) {
        throw JSONRPCError(RPC_WALLET_ERROR, "This type of wallet does not support this command");
    }

    {
        LOCK(cs_main);
        uint256 hash = block.GetHash();
        if (pwallet->chain().hasBlocks(hash, 0, std::nullopt))
            throw JSONRPCError(RPC_VERIFY_ERROR, "already have block");

        CBlockIndex* const pindexPrev = wallet->chain().getTip();
        // TestBlockValidity only supports blocks built on the current Tip
        if (block.hashPrevBlock != pindexPrev->GetBlockHash())
            throw JSONRPCError(RPC_VERIFY_ERROR, "proposal was not based on our best chain");

        BlockValidationState state;
        if (!wallet->chain().testBlockValidity(state, Params(), block, pindexPrev, false, true) || !state.IsValid()) {
            std::string strRejectReason = state.GetRejectReason();
            if (strRejectReason.empty())
                throw JSONRPCError(RPC_VERIFY_ERROR, state.IsInvalid() ? "Block proposal was invalid" : "Error checking block proposal");
            throw JSONRPCError(RPC_VERIFY_ERROR, strRejectReason);
        }
    }

    // Expose SignatureData internals in return value in lieu of "Partially Signed Bitcoin Blocks"
    SignatureData block_sigs;
    if (block.m_dynafed_params.IsNull()) {
        GenericSignScript(*spk_man, block.GetBlockHeader(), block.proof.challenge, block_sigs, SCRIPT_NO_SIGHASH_BYTE /* additional_flags */);
    } else {
        if (request.params[1].isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Signing dynamic blocks requires the witnessScript argument");
        }
        std::vector<unsigned char> witness_bytes(ParseHex(request.params[1].get_str()));
        // Note that we're adding the signblockscript to the wallet so it can actually
        // satisfy witness program scriptpubkeys
        if (!witness_bytes.empty()) {
            spk_man->AddCScript(CScript(witness_bytes.begin(), witness_bytes.end()));
        }
        GenericSignScript(*spk_man, block.GetBlockHeader(), block.m_dynafed_params.m_current.m_signblockscript, block_sigs, SCRIPT_VERIFY_NONE /* additional_flags */);
    }

    // Error if sig data didn't "grow"
    if (!block_sigs.complete && block_sigs.signatures.empty()) {
        throw JSONRPCError(RPC_VERIFY_ERROR, "Could not sign the block.");
    }
    UniValue ret(UniValue::VARR);
    for (const auto& signature : block_sigs.signatures) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("pubkey", HexStr(signature.second.first));
        obj.pushKV("sig", HexStr(MakeByteSpan(signature.second.second)));
        ret.push_back(obj);
    }
    return ret;
},
    };
}

RPCHelpMan getpeginaddress()
{
    return RPCHelpMan{"getpeginaddress",
                "\nReturns information needed for claimpegin to move coins to the sidechain.\n"
                "The user should send coins from their Bitcoin wallet to the mainchain_address returned.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "mainchain_address", "mainchain deposit address to send bitcoin to"},
                        {RPCResult::Type::STR_HEX, "claim_script", "Full script hex committed to by the mainchain address. This may be required in `claimpegin` to retrieve pegged-in funds\n"},
                        {RPCResult::Type::STR_AMOUNT, "pegin_min_amount", /*optional=*/true, "Minimum peg-in amount in " + CURRENCY_UNIT},
                        {RPCResult::Type::NUM, "pegin_min_height", /*optional=*/true, "Minimum block height for peg-in amount rule"},
                        {RPCResult::Type::BOOL, "pegin_min_active", /*optional=*/true, "Whether the peg-in minimum height rule is active at the current tip"},
                        {RPCResult::Type::STR_AMOUNT, "pegin_subsidy_threshold", /*optional=*/true, "Peg-in subsidy threshold amount"},
                        {RPCResult::Type::NUM, "pegin_subsidy_height", /*optional=*/true, "Block height at which peg-in subsidy activates"},
                        {RPCResult::Type::BOOL, "pegin_subsidy_active", /*optional=*/true, "Whether peg-in subsidy is active at the current tip"},
                    },
                },
                RPCExamples{
                    HelpExampleCli("getpeginaddress", "")
            + HelpExampleRpc("getpeginaddress", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    wallet::CheckDepositArgument(wallet::DepositArgument::FEDERATED_NETWORK, Params().GetConsensus().drivechain_slot.has_value());

    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    if (pwallet->chain().isInitialBlockDownload()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "This action cannot be completed during initial sync or reindexing.");
    }

    LegacyScriptPubKeyMan* spk_man = pwallet->GetLegacyScriptPubKeyMan();
    if (!spk_man) {
        throw JSONRPCError(RPC_WALLET_ERROR, "This type of wallet does not support this command");
    }

    if (!pwallet->IsLocked()) {
        pwallet->TopUpKeyPool();
    }

    // Use native witness destination
    auto dest = pwallet->GetNewDestination(OutputType::BECH32, "");
    if (!dest) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(dest).original);
    }

    CScript dest_script = GetScriptForDestination(*dest);

    // Also add raw scripts to index to recognize later.
    spk_man->AddCScript(dest_script);

    // Get P2CH deposit address on mainchain from most recent fedpegscript.
    const CChainParams& chainparams = Params();
    const Consensus::Params& consensus = chainparams.GetConsensus();
    const auto& fedpegscripts = GetValidFedpegScripts(pwallet->chain().getTip(), consensus, true /* nextblock_validation */);
    if (fedpegscripts.empty()) {
        std::string message = "No valid fedpegscripts.";
        if (!g_con_elementsmode) {
            message += " Not running in Elements mode, check your 'chain' param.";
        }
        throw JSONRPCError(RPC_INTERNAL_ERROR, message);
    }
    CTxDestination mainchain_dest(WitnessV0ScriptHash(calculate_contract(fedpegscripts.front().second, dest_script)));
    // P2SH-wrapped is the only valid choice for non-dynafed chains but still an
    // option for dynafed-enabled ones as well
    VersionBitsCache versionbitscache;
    if (!DeploymentActiveAfter(pwallet->chain().getTip(), consensus, Consensus::DEPLOYMENT_DYNA_FED, versionbitscache) ||
                fedpegscripts.front().first.IsPayToScriptHash()) {
        mainchain_dest = ScriptHash(GetScriptForDestination(mainchain_dest));
    }

    UniValue ret(UniValue::VOBJ);

    ret.pushKV("mainchain_address", EncodeParentDestination(mainchain_dest));
    ret.pushKV("claim_script", HexStr(dest_script));

    PeginMinimum pegin_minimum = Params().GetPeginMinimum();
    if (pegin_minimum.amount > 0) {
        ret.pushKV("pegin_min_amount", FormatMoney(pegin_minimum.amount));
    }
    if (pegin_minimum.height < std::numeric_limits<int>::max()) {
        ret.pushKV("pegin_min_height", pegin_minimum.height);
        ret.pushKV("pegin_min_active", wallet->chain().getTip()->nHeight >= pegin_minimum.height);
    }

    PeginSubsidy pegin_subsidy = Params().GetPeginSubsidy();
    if (pegin_subsidy.threshold > 0) {
        ret.pushKV("pegin_subsidy_threshold", FormatMoney(pegin_subsidy.threshold));
    }
    if (pegin_subsidy.height < std::numeric_limits<int>::max()) {
        ret.pushKV("pegin_subsidy_height", pegin_subsidy.height);
        ret.pushKV("pegin_subsidy_active", wallet->chain().getTip()->nHeight >= pegin_subsidy.height);
    }

    return ret;
},
    };
}

//! Derive BIP32 tweak from master xpub to child pubkey.
bool DerivePubTweak(const std::vector<uint32_t>& vPath, const CPubKey& keyMaster, const ChainCode &ccMaster, std::vector<unsigned char>& tweakSum)
{
    tweakSum.clear();
    tweakSum.resize(32);
    std::vector<unsigned char> tweak;
    CPubKey keyParent = keyMaster;
    CPubKey keyChild;
    ChainCode ccChild;
    ChainCode ccParent = ccMaster;
    for (unsigned int i = 0; i < vPath.size(); i++) {
        if ((vPath[i] >> 31) != 0) {
            return false;
        }
        if (!keyParent.Derive(keyChild, ccChild, vPath[i], ccParent, &tweak)) return false;
        CHECK_NONFATAL(tweak.size() == 32);
        ccParent = ccChild;
        keyParent = keyChild;
        if (i == 0) {
            tweakSum = tweak;
        } else {
            bool ret = secp256k1_ec_seckey_tweak_add(secp256k1_ctx, tweakSum.data(), tweak.data());
            if (!ret) {
                return false;
            }
        }
    }
    return true;
}

// For general cryptographic design of peg-out authorization scheme, see: https://github.com/ElementsProject/secp256k1-zkp/blob/secp256k1-zkp/src/modules/whitelist/whitelist.md
RPCHelpMan initpegoutwallet()
{
    return RPCHelpMan{"initpegoutwallet",
                "\nThis call is for Liquid network initialization on the Liquid wallet. The wallet generates a new Liquid pegout authorization key (PAK) unless `liquid_pak` is provided, and stores it in the Liquid wallet. It then combines this with the `bitcoin_descriptor` to finally create a PAK entry for the network. This allows the user to send Liquid coins directly to a secure offline Bitcoin wallet at the derived path from the bitcoin_descriptor using the `sendtomainchain` command. Losing the Liquid PAK or offline Bitcoin root key will result in the inability to pegout funds, so immediate backup upon initialization is required. Requires a legacy wallet.\n" +
                wallet::HELP_REQUIRING_PASSPHRASE,
                {
                    {"bitcoin_descriptor", RPCArg::Type::STR, RPCArg::Optional::NO, "The Bitcoin descriptor that includes a single extended pubkey. Must be one of the following: pkh(<xpub>), sh(wpkh(<xpub>)), or wpkh(<xpub>). This is used as the destination chain for the Bitcoin destination wallet. The derivation path from the xpub is given by the descriptor, typically `0/k`, reflecting the external chain of the wallet. DEPRECATED: If a plain xpub is given, pkh(<xpub>) is assumed, with the `0/k` derivation from that xpub. See link for more details on script descriptors: https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md"},
                    {"bip32_counter", RPCArg::Type::NUM , RPCArg::Default{0}, "The `k` in `0/k` to be set as the next address to derive from the `bitcoin_descriptor`. This will be stored in the wallet and incremented on each successful `sendtomainchain` invocation."},
                    {"liquid_pak", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The Liquid wallet pubkey in hex to be used as the Liquid PAK for pegout authorization. The private key must be in the wallet if argument is given. If this argument is not provided one will be generated and stored in the wallet automatically and returned."}
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "pakentry", "PAK entry to be used at network initialization time in the form of: `pak=<bitcoin_pak>:<liquid_pak>`"},
                        {RPCResult::Type::STR_HEX, "liquid_pak", "Liquid PAK pubkey, which is stored in the local Liquid wallet. This can be used in subsequent calls to `initpegoutwallet` to avoid generating a new `liquid_pak`"},
                        {RPCResult::Type::STR, "liquid_pak_address", "corresponding address for `liquid_pak`. Useful for `dumpprivkey` for wallet backup or transfer"},
                        {RPCResult::Type::ARR_FIXED, "address_lookahead", "the three next Bitcoin addresses the wallet will use for `sendtomainchain` based on `bip32_counter`",
                            {RPCResult{RPCResult::Type::STR, "", ""}}},
                    }
                },
                RPCExamples{
                    HelpExampleCli("initpegoutwallet", "sh(wpkh(tpubDAY5hwtonH4NE8zY46ZMFf6B6F3fqMis7cwfNihXXpAg6XzBZNoHAdAzAZx2peoU8nTWFqvUncXwJ9qgE5VxcnUKxdut8F6mptVmKjfiwDQ/0/*))")
            + HelpExampleRpc("initpegoutwallet", "sh(wpkh(tpubDAY5hwtonH4NE8zY46ZMFf6B6F3fqMis7cwfNihXXpAg6XzBZNoHAdAzAZx2peoU8nTWFqvUncXwJ9qgE5VxcnUKxdut8F6mptVmKjfiwDQ/0/*))")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    LOCK(pwallet->cs_wallet);

    LegacyScriptPubKeyMan* spk_man = pwallet->GetLegacyScriptPubKeyMan();
    if (!spk_man) {
        throw JSONRPCError(RPC_WALLET_ERROR, "This type of wallet does not support this command");
    }

    // Check that network cares about PAK
    if (!Params().GetEnforcePak()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "PAK enforcement is not enabled on this network.");
    }

    if (!pwallet->IsLocked())
        pwallet->TopUpKeyPool();

    // Generate a new key that is added to wallet or set from argument
    CPubKey online_pubkey;
    if (request.params[2].isNull()) {
        std::string error;
        if (!pwallet->GetOnlinePakKey(online_pubkey, error)) {
            throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, error);
        }
    } else {
        online_pubkey = CPubKey(ParseHex(request.params[2].get_str()));
        if (!online_pubkey.IsFullyValid()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Error: Given liquid_pak is not valid.");
        }
        if (!spk_man->HaveKey(online_pubkey.GetID())) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Error: liquid_pak could not be found in wallet");
        }
    }

    // Parse offline counter
    int counter = 0;
    if (!request.params[1].isNull()) {
        counter = request.params[1].getInt<int>();
        if (counter < 0 || counter > 1000000000) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "bip32_counter must be between 0 and 1,000,000,000, inclusive.");
        }
    }

    std::string bitcoin_desc = request.params[0].get_str();
    std::string xpub_str;

    // First check for naked xpub, and impute it as pkh(<xpub>/0/*) for backwards compat
    CExtPubKey xpub = DecodeExtPubKey(bitcoin_desc);
    if (xpub.pubkey.IsFullyValid()) {
        bitcoin_desc = "pkh(" + bitcoin_desc + "/0/*)";
    }

    FlatSigningProvider provider;
    std::string error;
    auto descs = Parse(bitcoin_desc, provider, error); // don't require checksum
    if (descs.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, error);
    }
    auto& desc = descs.at(0);
    if (!desc->IsRange()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "bitcoin_descriptor must be a ranged descriptor.");
    }

    // Check if we can actually generate addresses(catches hardened derivation steps etc) before
    // writing to cache
    UniValue address_list(UniValue::VARR);
    for (int i = counter; i < counter+3; i++) {
        std::vector<CScript> scripts;
        if (!desc->Expand(i, provider, scripts, provider)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Could not generate lookahead addresses with descriptor. Are there hardened derivations after the xpub?");
        }
        CTxDestination destination;
        ExtractDestination(scripts[0], destination);
        address_list.push_back(EncodeParentDestination(destination));
    }

    // For our manual pattern matching, we don't want the checksum part.
    auto checksum_char = bitcoin_desc.find('#');
    if (checksum_char != std::string::npos) {
        bitcoin_desc = bitcoin_desc.substr(0, checksum_char);
    }

    // Three acceptable descriptors:
    if (bitcoin_desc.substr(0, 8) ==  "sh(wpkh("
            && bitcoin_desc.substr(bitcoin_desc.size()-2, 2) == "))") {
        xpub_str = bitcoin_desc.substr(8, bitcoin_desc.size()-2);
    } else if (bitcoin_desc.substr(0, 5) ==  "wpkh("
            && bitcoin_desc.substr(bitcoin_desc.size()-1, 1) == ")") {
        xpub_str = bitcoin_desc.substr(5, bitcoin_desc.size()-1);
    } else if (bitcoin_desc.substr(0, 4) == "pkh("
            && bitcoin_desc.substr(bitcoin_desc.size()-1, 1) == ")") {
        xpub_str = bitcoin_desc.substr(4, bitcoin_desc.size()-1);
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "bitcoin_descriptor is not of any type supported: pkh(<xpub>), sh(wpkh(<xpub>)), wpkh(<xpub>), or <xpub>.");
    }

    // Strip off leading key origin
    if (xpub_str.find(']') != std::string::npos) {
        xpub_str = xpub_str.substr(xpub_str.find(']') + 1, std::string::npos);
    }

    // Strip off following range
    xpub_str = xpub_str.substr(0, xpub_str.find('/'));

    xpub = DecodeExtPubKey(xpub_str);

    if (!xpub.pubkey.IsFullyValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "bitcoin_descriptor does not contain a valid extended pubkey for this network.");
    }

    // Parse master pubkey
    CPubKey masterpub = xpub.pubkey;
    secp256k1_pubkey masterpub_secp;
    int ret = secp256k1_ec_pubkey_parse(secp256k1_ctx, &masterpub_secp, masterpub.begin(), masterpub.size());
    if (ret != 1) {
        throw JSONRPCError(RPC_WALLET_ERROR, "bitcoin_descriptor could not be parsed.");
    }

    // Store the keys and metadata
    if (!pwallet->SetOnlinePubKey(online_pubkey) ||
            !pwallet->SetOfflineXPubKey(xpub) ||
            !pwallet->SetOfflineCounter(counter) ||
            !pwallet->SetOfflineDescriptor(bitcoin_desc)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Failure to initialize pegout wallet.");
    }

    // Negate the pubkey
    ret = secp256k1_ec_pubkey_negate(secp256k1_ctx, &masterpub_secp);

    std::vector<unsigned char> negatedpubkeybytes;
    negatedpubkeybytes.resize(33);
    size_t len = 33;
    ret = secp256k1_ec_pubkey_serialize(secp256k1_ctx, &negatedpubkeybytes[0], &len, &masterpub_secp, SECP256K1_EC_COMPRESSED);
    CHECK_NONFATAL(ret == 1);
    CHECK_NONFATAL(len == 33);
    CHECK_NONFATAL(negatedpubkeybytes.size() == 33);

    UniValue pak(UniValue::VOBJ);
    pak.pushKV("pakentry", "pak=" + HexStr(MakeByteSpan(negatedpubkeybytes)) + ":" + HexStr(online_pubkey));
    pak.pushKV("liquid_pak", HexStr(online_pubkey));
    pak.pushKV("liquid_pak_address", EncodeDestination(PKHash(online_pubkey)));
    pak.pushKV("address_lookahead", address_list);
    return pak;
},
    };
}

RPCHelpMan sendtomainchain_drivechain()
{
    return RPCHelpMan{"sendtomainchain",
                "\nIrreversibly burns the native pegged asset on Elements as the first step "
                "of a BIP300 withdrawal. The burn must confirm before anybody calls "
                "submitdrivechainwithdrawal to propose its exact blinded M6.\n"
                + wallet::HELP_REQUIRING_PASSPHRASE,
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The destination address on Bitcoin mainchain, or hex:<scriptPubKey>"},
                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The net amount paid to the Bitcoin destination"},
                    {"subtractfeefromamount", RPCArg::Type::BOOL, RPCArg::Default{false}, "Must be false. The Elements transaction fee is separate from the irreversible burn."},
                    {"verbose", RPCArg::Type::BOOL, RPCArg::Default{false}, "If true, return extra information about the transaction."},
                    {"mainchainfee", RPCArg::Type::AMOUNT, RPCArg::Default{0}, "Bitcoin miner fee committed by this withdrawal. The burned amount is amount + mainchainfee."},
                },
                {
                    RPCResult{"if verbose is not set or set to false",
                        RPCResult::Type::STR_HEX, "txid", "Transaction ID of the resulting sidechain transaction",
                    },
                    RPCResult{"if verbose is set to true",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "txid", "The transaction id."},
                            {RPCResult::Type::NUM, "withdrawal_vout", "The canonical unspendable burn output."},
                            {RPCResult::Type::STR_AMOUNT, "burn_amount", "Total native pegged asset destroyed."},
                            {RPCResult::Type::STR_AMOUNT, "payout_amount", "Net Bitcoin payout encoded by the burn."},
                            {RPCResult::Type::STR_AMOUNT, "mainchain_fee", "Bitcoin miner fee encoded by the burn."},
                            {RPCResult::Type::STR, "status", "awaiting_confirmation"},
                            {RPCResult::Type::STR, "fee_reason", "The Elements transaction fee reason."}
                        },
                    },
                },
                RPCExamples{
                    HelpExampleCli("sendtomainchain", "\"tb1q...\" 0.1 false true 0.00001")
            + HelpExampleRpc("sendtomainchain", "\"tb1q...\" 0.1 false true 0.00001")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const Consensus::Params& consensus = Params().GetConsensus();
    // Reject unsupported identities before wallet lookup can load/create a wallet.
    wallet::CheckWithdrawal(wallet::WithdrawalCheck::NETWORK,consensus.drivechain_slot.has_value());
    wallet::CheckWithdrawal(wallet::WithdrawalCheck::ACTIVATION,consensus.DrivechainWithdrawalValidationEnabled());

    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    LOCK(pwallet->cs_wallet);
    EnsureWalletIsUnlocked(*pwallet);

    const std::string destination_arg = request.params[0].get_str();
    const CScript destination_script = wallet::DecodeDrivechainWithdrawalDestination(destination_arg);

    const CAmount payout_amount = wallet::ValidateNativePayout(destination_script, AmountFromValue(request.params[1], true));
    const bool subtract_fee = request.params[2].isNull()
        ? false
        : request.params[2].get_bool();
    wallet::CheckWithdrawal(wallet::WithdrawalCheck::SUBTRACT_FEE,subtract_fee);
    const bool verbose = request.params[3].isNull()
        ? false
        : request.params[3].get_bool();
    const CAmount parent_fee = request.params[4].isNull()
        ? 0
        : AmountFromValue(request.params[4], true);
    CScript burn_script;
    const CAmount burn_amount = wallet::PrepareNativeBurn(Params().ParentGenesisBlockHash(),
        destination_script,payout_amount,parent_fee,burn_script);
    const std::optional<unsigned> max_datacarrier_bytes =
        gArgs.GetBoolArg("-datacarrier", DEFAULT_ACCEPT_DATACARRIER)
            ? std::make_optional<unsigned>(gArgs.GetIntArg("-datacarriersize", MAX_OP_RETURN_RELAY))
            : std::nullopt;
    TxoutType burn_type;
    wallet::CheckWithdrawal(wallet::WithdrawalCheck::RELAY,IsStandard(burn_script,max_datacarrier_bytes,burn_type));

    std::vector<CRecipient> recipients;
    recipients.push_back({CNoDestination{burn_script},
                          burn_amount,
                          consensus.pegged_asset,
                          CPubKey(),
                          false});

    mapValue_t map_value;
    map_value["drivechain_withdrawal"] = "native-v1";
    map_value["drivechain_parent_fee_sats"] = util::ToString(parent_fee);
    CCoinControl no_coin_control;
    UniValue send_result, result(UniValue::VOBJ);
    std::string txid_hex;
    const CWalletTx* wallet_tx{nullptr};
    uint32_t withdrawal_vout{0};
    const auto detailed = drivechain::haskell::ParentReplayStore(
        drivechain::haskell::ReplayStoreFlow::NATIVE_WITHDRAWAL_SUBMISSION,
        [&](uint32_t step) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet) -> uint32_t {
        switch (step) {
        case 1:
            send_result = SendMoney(*pwallet, no_coin_control, recipients, std::move(map_value),
                true /* verbose */, true /* ignore_blind_fail */);
            break;
        case 2:
            txid_hex = send_result["txid"].get_str();
            wallet_tx = pwallet->GetWalletTx(uint256S(txid_hex));
            break;
        case 3: return wallet_tx != nullptr;
        case 4: return bool(wallet_tx->tx);
        case 5: throw JSONRPCError(RPC_WALLET_ERROR,
            "Committed withdrawal transaction is unavailable in the wallet");
        case 6:
            withdrawal_vout = wallet::FindNativeWithdrawalOutput(*wallet_tx->tx,
                burn_script, consensus.pegged_asset, Params().ParentGenesisBlockHash(),
                burn_amount, payout_amount, parent_fee);
            break;
        case 7: return verbose;
        case 8:
            result.pushKV("txid", txid_hex);
            result.pushKV("withdrawal_vout", static_cast<uint64_t>(withdrawal_vout));
            result.pushKV("burn_amount", ValueFromAmount(burn_amount));
            result.pushKV("payout_amount", ValueFromAmount(payout_amount));
            result.pushKV("mainchain_fee", ValueFromAmount(parent_fee));
            result.pushKV("bitcoin_script_pub_key", HexStr(destination_script));
            result.pushKV("status", "awaiting_confirmation");
            result.pushKV("fee_reason", send_result["fee_reason"]);
            result.pushKV("next_step", strprintf("submitdrivechainwithdrawal %s %u <confirming_block_hash>",
                txid_hex, withdrawal_vout));
            break;
        default: throw std::logic_error("invalid native withdrawal submission action");
        }
        return 1;
    });
    return detailed ? result : UniValue(txid_hex);
},
    };
}

/** Historical ECX BIP300 peg-out path; never selected for a native slot. */
RPCHelpMan sendtomainchain_legacy()
{
    return RPCHelpMan{"sendtomainchain",
                "\nSends sidechain funds to the given mainchain address through the BIP300 drivechain peg-out mechanism.\n"
                "This RPC requires the authenticated enforcer to report the submitted withdrawal bundle in L1 two-way-peg data.\n"
                + wallet::HELP_REQUIRING_PASSPHRASE,
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The destination address on Bitcoin mainchain, or hex:<scriptPubKey>"},
                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount being sent to Bitcoin mainchain"},
                    {"subtractfeefromamount", RPCArg::Type::BOOL, RPCArg::Default{false}, "The fee will be deducted from the amount being pegged-out."},
                    {"verbose", RPCArg::Type::BOOL, RPCArg::Default{false}, "If true, return extra information about the transaction."},
                },
                {
                    RPCResult{"if verbose is not set or set to false",
                        RPCResult::Type::STR_HEX, "txid", "Transaction ID of the resulting sidechain transaction",
                    },
                    RPCResult{"if verbose is set to true",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "txid", "The transaction id."},
                            {RPCResult::Type::STR, "fee_reason", /*optional=*/true, "The transaction fee reason."},
                            {RPCResult::Type::OBJ, "drivechain_pegout", "BIP300 withdrawal bundle broadcast result."}
                        },
                    },
                },
                RPCExamples{
                    HelpExampleCli("sendtomainchain", "\"tb1q...\" 0.1")
            + HelpExampleRpc("sendtomainchain", "\"tb1q...\" 0.1")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto& consensus = Params().GetConsensus();
    wallet::CheckWithdrawal(wallet::WithdrawalCheck::LEGACY_NETWORK,
        drivechain::haskell::ParentReplayAll<2>({[&] { return consensus.elements_mode; },
            [&] { return consensus.has_parent_chain; }}));
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    LOCK(pwallet->cs_wallet);

    EnsureWalletIsUnlocked(*pwallet);

    const std::string mainchain_destination = request.params[0].get_str();

    // Validate before SendMoney can commit or broadcast an irreversible burn.
    const CScript payout_script = wallet::DecodeDrivechainWithdrawalDestination(mainchain_destination);

    const CAmount nAmount = wallet::LegacyWithdrawalAmount(AmountFromValue(request.params[1]));

    bool subtract_fee = false;
    if (!request.params[2].isNull()) {
        subtract_fee = request.params[2].get_bool();
    }

    const std::vector<unsigned char> destination_bytes(mainchain_destination.begin(), mainchain_destination.end());
    CScript mainchain_script;
    mainchain_script << destination_bytes;

    uint256 genesisBlockHash = Params().ParentGenesisBlockHash();

    // Asset type is implicit, no need to add to script
    NullData nulldata;
    nulldata << std::vector<unsigned char>(genesisBlockHash.begin(), genesisBlockHash.end());
    nulldata << std::vector<unsigned char>(mainchain_script.begin(), mainchain_script.end());
    CTxDestination address(nulldata);
    const CScript sidechain_withdrawal_script = GetScriptForDestination(address);

    std::vector<CRecipient> recipients;
    CRecipient recipient = {address, nAmount, Params().GetConsensus().pegged_asset, CPubKey(), subtract_fee};
    recipients.push_back(recipient);

    /* Fail before SendMoney mutates the wallet or broadcasts a sidechain
     * transaction.  The withdrawal bundle is inseparable from its finalized
     * ECX checkpoint, so discovering a missing/wrong checkpoint afterwards
     * would strand an unauthorizable pegout while returning an RPC error. */
    CBlockIndex* const chain_tip = pwallet->chain().getTip();
    std::string transport_error;
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::WITHDRAWAL_PREFLIGHT,
        [&](uint32_t action) -> uint32_t {
        switch (action) {
        case 1: return chain_tip != nullptr;
        case 9: return chain_tip->nHeight >= 0;
        case 10: return static_cast<uint64_t>(chain_tip->nHeight) <= std::numeric_limits<uint32_t>::max();
        case 2: throw JSONRPCError(RPC_WALLET_ERROR, "Cannot determine sidechain height for drivechain withdrawal bundle");
        case 3: DrivechainWithdrawalFee(nAmount); return 1;
        case 4: return ValidateDrivechainGrpcTLSConfig(gArgs, &transport_error);
        case 5: throw JSONRPCError(RPC_INVALID_PARAMETER, transport_error);
        case 6: return 1; // The transport is linked into the node; no executable admission.
        case 7: return chain_tip->pprev != nullptr;
        case 11: return (static_cast<uint32_t>(chain_tip->nVersion) & CBlockHeader::EXCHANGE_STATE_HF_MASK) != 0;
        case 12: return !chain_tip->hashExchangeStateRoot.IsNull();
        case 8: throw JSONRPCError(RPC_WALLET_ERROR, "Cannot withdraw before a finalized ECX state header is active");
        default: throw std::logic_error("invalid withdrawal preflight action");
        }
    });
    const uint32_t checkpoint_height{static_cast<uint32_t>(chain_tip->nHeight)};
    const uint256 checkpoint_block_hash{chain_tip->GetBlockHash()};
    const uint256 previous_child_hash{chain_tip->pprev->GetBlockHash()};
    const uint256 checkpoint_exchange_state_root{chain_tip->hashExchangeStateRoot};

    EnsureWalletIsUnlocked(*pwallet);

    bool verbose = request.params[3].isNull() ? false : request.params[3].get_bool();
    mapValue_t mapValue;
    CCoinControl no_coin_control; // This is a deprecated API
    no_coin_control.m_include_unsafe_inputs = true;
    std::optional<DrivechainWithdrawalBundleCreationGuard> withdrawal_bundle_creation;
    std::optional<CheckpointWithdrawalBundle> withdrawal_bundle;
    UniValue send_result, drivechain_result;
    std::string txid_str, tx_hex;
    uint256 txid;
    const CWalletTx* wtx{nullptr};
    uint32_t withdrawal_vout{0};
    // Native actions run after each Haskell transition returns; the guard spans
    // the entire workflow and remains completed if event verification fails.
    const auto result = drivechain::haskell::ParentReplayStore(
        drivechain::haskell::ReplayStoreFlow::WITHDRAWAL_SUBMISSION,
        [&](uint32_t step) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet) -> uint32_t {
        switch (step) {
        case 1: ClearFinalDrivechainWithdrawalBundle(); break;
        case 2: withdrawal_bundle_creation.emplace(); break;
        case 3:
            send_result = SendMoney(*pwallet, no_coin_control, recipients, std::move(mapValue), true /* verbose */, true /* ignore_blind_fail */);
            break;
        case 4:
            txid_str = send_result.isObject() ? send_result["txid"].get_str() : send_result.get_str();
            txid = uint256S(txid_str);
            wtx = pwallet->GetWalletTx(txid);
            break;
        case 5: return drivechain::haskell::ParentReplayAll<2>({[&] { return wtx != nullptr; },
            [&] { return bool(wtx->tx); }});
        case 6: throw JSONRPCError(RPC_WALLET_ERROR, "Created pegout transaction is not available in the wallet");
        case 7: withdrawal_vout = 0; break;
        case 8: return withdrawal_vout < wtx->tx->vout.size();
        case 9: return wtx->tx->vout[withdrawal_vout].scriptPubKey == sidechain_withdrawal_script;
        case 10: ++withdrawal_vout; break;
        case 11: throw JSONRPCError(RPC_WALLET_ERROR, "Created pegout transaction does not contain the expected sidechain withdrawal output");
        case 12:
            tx_hex = EncodeHexTx(*wtx->tx);
            withdrawal_bundle = BuildCheckpointWithdrawalBundle(
                nAmount, payout_script, COutPoint(Txid::FromUint256(txid), withdrawal_vout),
                checkpoint_height, checkpoint_block_hash, Params().GetConsensus().hashGenesisBlock,
                previous_child_hash, checkpoint_exchange_state_root);
            break;
        case 13: drivechain_result = BroadcastDrivechainWithdrawalBundle(*withdrawal_bundle); break;
        case 14: withdrawal_bundle_creation->Complete(*withdrawal_bundle); break;
        case 15:
            drivechain_result.pushKV("l1_event_verification", VerifyDrivechainWithdrawalBundleEvent(
                drivechain_result["sidechain_id"].getInt<int>(), drivechain_result["enforcer"].get_str(),
                withdrawal_bundle->m6id.GetHex()));
            break;
        case 16:
            drivechain_result.pushKV("sidechain_pegout_tx_hex", tx_hex);
            drivechain_result.pushKV("sidechain_withdrawal_vout", static_cast<int>(withdrawal_vout));
            drivechain_result.pushKV("sidechain_height", static_cast<uint64_t>(checkpoint_height));
            break;
        case 17: return verbose;
        case 18: send_result.pushKV("drivechain_pegout", drivechain_result); break;
        default: throw std::logic_error("Invalid Haskell withdrawal submission action");
        }
        return 1;
    });
    return result ? send_result : UniValue(txid_str);
},
    };
}

// ELEMENTS: Copied from script/descriptor.cpp

typedef std::vector<uint32_t> KeyPath;

/** Split a string on every instance of sep, returning a vector. */
std::vector<Span<const char>> Split(const Span<const char>& sp, char sep)
{
    std::vector<Span<const char>> ret;
    auto it = sp.begin();
    auto start = it;
    while (it != sp.end()) {
        if (*it == sep) {
            ret.emplace_back(start, it);
            start = it + 1;
        }
        ++it;
    }
    ret.emplace_back(start, it);
    return ret;
}

/** Parse a key path, being passed a split list of elements (the first element is ignored). */
bool ParseKeyPath(const std::vector<Span<const char>>& split, KeyPath& out)
{
    for (size_t i = 1; i < split.size(); ++i) {
        Span<const char> elem = split[i];
        bool hardened = false;
        if (elem.size() > 0 && (elem[elem.size() - 1] == '\'' || elem[elem.size() - 1] == 'h')) {
            elem = elem.first(elem.size() - 1);
            hardened = true;
        }
        uint32_t p;
        if (!ParseUInt32(std::string(elem.begin(), elem.end()), &p) || p > 0x7FFFFFFFUL) return false;
        out.push_back(p | (((uint32_t)hardened) << 31));
    }
    return true;
}

////////////////////////////

RPCHelpMan sendtomainchain_pak()
{
    return RPCHelpMan{"sendtomainchain",
                "\nSends Liquid funds to the Bitcoin mainchain, through the federated withdraw mechanism. The wallet internally generates the returned `bitcoin_address` via `bitcoin_descriptor` and `bip32_counter` previously set in `initpegoutwallet`. The counter will be incremented upon successful send, avoiding address re-use. Requires a legacy wallet. Minimum peg-out amount is 0.00100000 BTC.\n"
                + wallet::HELP_REQUIRING_PASSPHRASE,
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Must be \"\". Only for non-PAK `sendtomainchain` compatibility."},
                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount being sent to `bitcoin_address` (minimum 0.00100000 BTC)."},
                    {"subtractfeefromamount", RPCArg::Type::BOOL, RPCArg::Default{false}, "The fee will be deducted from the amount being pegged-out."},
                    {"verbose", RPCArg::Type::BOOL, RPCArg::Default{false}, "If true, return extra information about the transaction."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "bitcoin_address", "destination address on Bitcoin mainchain"},
                        {RPCResult::Type::STR_HEX, "txid", "transaction ID of the resulting Liquid transaction"},
                        {RPCResult::Type::STR, "fee_reason", /*optional=*/true, "If verbose is set to true, the Liquid transaction fee reason"},
                        {RPCResult::Type::STR, "bitcoin_descriptor", "Bitcoin descriptor string used for peg-out destination derivation"},
                        {RPCResult::Type::STR, "bip32_counter", "derivation counter for the `bitcoin_descriptor`"},
                    },
                },
                RPCExamples{
                    HelpExampleCli("sendtomainchain", "\"\" 0.1")
            + HelpExampleRpc("sendtomainchain", "\"\" 0.1")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    LOCK(pwallet->cs_wallet);

    EnsureWalletIsUnlocked(*pwallet);

    if (!request.params[0].get_str().empty()) {
        throw JSONRPCError(RPC_TYPE_ERROR, "`address` argument must be \"\" for PAK-enabled networks as the address is generated automatically.");
    }

    //amount
    CAmount nAmount = AmountFromValue(request.params[1]);
    if (nAmount < 100000)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount for send, must send more than 0.00100000 BTC");

    bool subtract_fee = false;
    if (!request.params[2].isNull()) {
        subtract_fee = request.params[2].get_bool();
    }

    CPAKList paklist = GetActivePAKList(pwallet->chain().getTip(), Params().GetConsensus());
    if (paklist.IsReject()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Pegout freeze is under effect to aid a pak transition to a new list. Please consult the network operator.");
    }

    // Fetch pegout key data
    int counter = pwallet->offline_counter;
    CExtPubKey& xpub = pwallet->offline_xpub;
    CPubKey& onlinepubkey = pwallet->online_key;

    if (counter < 0) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Pegout authorization for this wallet has not been set. Please call `initpegoutwallet` with the appropriate arguments first.");
    }

    FlatSigningProvider provider;
    std::string error;
    auto descriptors = Parse(pwallet->offline_desc, provider, error);

    LegacyScriptPubKeyMan* spk_man = pwallet->GetLegacyScriptPubKeyMan();
    if (!spk_man) {
        throw JSONRPCError(RPC_WALLET_ERROR, "This type of wallet does not support this command");
    }

    // If descriptor not previously set, generate it
    if (descriptors.empty()) {
        std::string offline_desc = "pkh(" + EncodeExtPubKey(xpub) + "0/*)";
        if (!pwallet->SetOfflineDescriptor(offline_desc)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Couldn't set wallet descriptor for peg-outs.");
        }

        descriptors = Parse(pwallet->offline_desc, provider, error);
        if (descriptors.empty()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "descriptor still null. This is a bug in elementsd.");
        }
    }
    auto& descriptor = descriptors.at(0);

    std::string desc_str = pwallet->offline_desc;
    std::string xpub_str = EncodeExtPubKey(xpub);

    // TODO: More properly expose key parsing functionality

    // Strip last parenths(up to 2) and "/*" to let ParseKeyPath do its thing
    desc_str.erase(std::remove(desc_str.begin(), desc_str.end(), ')'), desc_str.end());
    desc_str = desc_str.substr(0, desc_str.size()-2);

    // Since we know there are no key origin data, directly call inner parsing functions
    Span<const char> span(desc_str.data(), desc_str.size());
    auto split = Split(span, '/');
    KeyPath key_path;
    if (!ParseKeyPath(split, key_path)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Stored keypath in descriptor cannot be parsed.");
    }
    key_path.push_back(counter);

    secp256k1_pubkey onlinepubkey_secp;
    if (secp256k1_ec_pubkey_parse(secp256k1_ctx, &onlinepubkey_secp, onlinepubkey.begin(), onlinepubkey.size()) != 1) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Pubkey is invalid");
    }

    // Get index of given online key
    int whitelistindex=-1;
    std::vector<secp256k1_pubkey> pak_online = paklist.OnlineKeys();
    for (unsigned int i=0; i<pak_online.size(); i++) {
        if (memcmp((void *)&pak_online[i], (void *)&onlinepubkey_secp, sizeof(secp256k1_pubkey)) == 0) {
            whitelistindex = i;
            break;
        }
    }
    if (whitelistindex == -1)
        throw JSONRPCError(RPC_WALLET_ERROR, "Given online key is not in Pegout Authorization Key List");

    // Parse master pubkey
    CPubKey masterpub = xpub.pubkey;
    secp256k1_pubkey masterpub_secp;
    int ret = secp256k1_ec_pubkey_parse(secp256k1_ctx, &masterpub_secp, masterpub.begin(), masterpub.size());
    if (ret != 1) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Master pubkey could not be parsed.");
    }

    secp256k1_pubkey btcpub_secp;
    memcpy(&btcpub_secp, &masterpub_secp, sizeof(secp256k1_pubkey));

    // Negate master pubkey
    ret = secp256k1_ec_pubkey_negate(secp256k1_ctx, &masterpub_secp);

    // Make sure negated master pubkey is in PAK list at same index as online_pubkey
    if (memcmp((void *)&paklist.OfflineKeys()[whitelistindex], (void *)&masterpub_secp, sizeof(secp256k1_pubkey)) != 0) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Given bitcoin_descriptor cannot be found in same entry as known liquid_pak");
    }

    // Get online PAK
    CKey masterOnlineKey;
    if (!spk_man->GetKey(onlinepubkey.GetID(), masterOnlineKey))
        throw JSONRPCError(RPC_WALLET_ERROR, "Given online key is in master set but not in wallet");

    // Tweak offline pubkey by tweakSum aka sumkey to get bitcoin key
    std::vector<unsigned char> tweakSum;
    if (!DerivePubTweak(key_path, xpub.pubkey, xpub.chaincode, tweakSum)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Could not create xpub tweak to generate proof.");
    }
    ret = secp256k1_ec_pubkey_tweak_add(secp256k1_ctx, &btcpub_secp, tweakSum.data());
    CHECK_NONFATAL(ret);

    std::vector<unsigned char> btcpubkeybytes;
    btcpubkeybytes.resize(33);
    size_t btclen = 33;
    ret = secp256k1_ec_pubkey_serialize(secp256k1_ctx, &btcpubkeybytes[0], &btclen, &btcpub_secp, SECP256K1_EC_COMPRESSED);
    CHECK_NONFATAL(ret == 1);
    CHECK_NONFATAL(btclen == 33);
    CHECK_NONFATAL(btcpubkeybytes.size() == 33);

    //Create, verify whitelist proof
    secp256k1_whitelist_signature sig;
    if(secp256k1_whitelist_sign(secp256k1_ctx, &sig, &paklist.OnlineKeys()[0], &paklist.OfflineKeys()[0], paklist.size(), &btcpub_secp, UCharCast(masterOnlineKey.begin()), &tweakSum[0], whitelistindex) != 1) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Pegout authorization proof signing failed");
    }

    if (secp256k1_whitelist_verify(secp256k1_ctx, &sig, &paklist.OnlineKeys()[0], &paklist.OfflineKeys()[0], paklist.size(), &btcpub_secp) != 1) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Pegout authorization proof was created and signed but is invalid");
    }

    //Serialize
    const size_t expectedOutputSize = 1 + 32 * (1 + paklist.size());
    CHECK_NONFATAL(1 + 32 * (1 + 256) >= expectedOutputSize);
    unsigned char output[1 + 32 * (1 + 256)];
    size_t outlen = expectedOutputSize;
    secp256k1_whitelist_signature_serialize(secp256k1_ctx, output, &outlen, &sig);
    CHECK_NONFATAL(outlen == expectedOutputSize);
    std::vector<unsigned char> whitelistproof(output, output + expectedOutputSize / sizeof(unsigned char));

    // Derive the end address in mainchain
    std::vector<CScript> scripts;
    if (!descriptor->Expand(counter, provider, scripts, provider)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Could not generate mainchain destination with descriptor. This is a bug.");
    }
    CHECK_NONFATAL(scripts.size() == 1);
    CScript mainchain_script = scripts[0];
    CTxDestination bitcoin_address;
    ExtractDestination(mainchain_script, bitcoin_address);

    uint256 genesisBlockHash = Params().ParentGenesisBlockHash();
    NullData nulldata;
    nulldata << std::vector<unsigned char>(genesisBlockHash.begin(), genesisBlockHash.end());
    nulldata << std::vector<unsigned char>(mainchain_script.begin(), mainchain_script.end());
    nulldata << btcpubkeybytes;
    nulldata << whitelistproof;
    CTxDestination address(nulldata);
    CHECK_NONFATAL(GetScriptForDestination(nulldata).IsPegoutScript(genesisBlockHash));

    std::vector<CRecipient> recipients;
    CRecipient recipient = {address, nAmount, Params().GetConsensus().pegged_asset, CPubKey(), subtract_fee};
    recipients.push_back(recipient);

    if (!ScriptHasValidPAKProof(GetScriptForDestination(nulldata), Params().ParentGenesisBlockHash(), paklist)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Resulting scriptPubKey is non-standard. Ensure pak=reject is not set");
    }

    bool verbose = request.params[3].isNull() ? false: request.params[3].get_bool();
    mapValue_t mapValue;
    CCoinControl no_coin_control; // This is a deprecated API
    UniValue tx_hash_hex = SendMoney(*pwallet, no_coin_control, recipients, std::move(mapValue), verbose, true /* ignore_blind_fail */);

    pwallet->SetOfflineCounter(counter+1);

    std::stringstream ss;
    ss << counter;

    UniValue obj(UniValue::VOBJ);
    if (!verbose) {
        obj.pushKV("txid", tx_hash_hex);
    } else {
        obj.pushKV("txid", tx_hash_hex["txid"]);
        obj.pushKV("fee_reason", tx_hash_hex["fee_reason"]);
    }
    obj.pushKV("bitcoin_address", EncodeParentDestination(bitcoin_address));
    obj.pushKV("bip32_counter", ss.str());
    obj.pushKV("bitcoin_descriptor", pwallet->offline_desc);
    return obj;
},
    };
}

// Preserve the existing Liquid/federated wallet behavior on ordinary Elements
// networks. Only an explicitly slot-assigned network selects the native
// drivechain path (which applies its own fail-closed M6 capability gate).
RPCHelpMan sendtomainchain()
{
    const std::array factories{sendtomainchain_legacy, sendtomainchain_pak, sendtomainchain_drivechain};
    const unsigned flags = (unsigned{Params().GetConsensus().drivechain_slot.has_value()} << 1) |
        unsigned{Params().GetEnforcePak()};
    return factories[drivechain::WALLET_RPC_ROUTES[1][flags]]();
}

extern UniValue signrawtransaction(const JSONRPCRequest& request);

template <typename T_tx_ref, typename T_merkle_block>
static UniValue createrawpegin(const JSONRPCRequest& request, T_tx_ref& txBTCRef, T_merkle_block& merkleBlock)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    LOCK(pwallet->cs_wallet);

    std::vector<unsigned char> txData = ParseHex(request.params[0].get_str());
    std::vector<unsigned char> txOutProofData = ParseHex(request.params[1].get_str());

    std::set<CScript> claim_scripts;
    if (!request.params[2].isNull()) {
        const std::string claim_script = request.params[2].get_str();
        if (!IsHex(claim_script)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Given claim_script is not hex.");
        }
        // If given manually, no need for it to be a witness script
        std::vector<unsigned char> witnessBytes(ParseHex(claim_script));
        CScript witness_script(witnessBytes.begin(), witnessBytes.end());
        claim_scripts.insert(std::move(witness_script));
    }
    else {
        // Look for known wpkh address in wallet
        for (std::map<CTxDestination, CAddressBookData>::const_iterator iter = pwallet->m_address_book.begin(); iter != pwallet->m_address_book.end(); ++iter) {
            CScript dest_script = GetScriptForDestination(iter->first);
            claim_scripts.insert(std::move(dest_script));
        }
    }

    // Make the tx
    CMutableTransaction mtx;

    // Construct peg-in input
    CreatePegInInput(mtx, 0, txBTCRef, merkleBlock, claim_scripts, txData, txOutProofData, wallet->chain().getTip());

    // Get value for peg-in output
    CAmount value = 0;
    if (!GetAmountFromParentChainPegin(value, *txBTCRef, mtx.vin[0].prevout.n)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Amounts to peg-in must be explicit and asset must be %s", Params().GetConsensus().parent_pegged_asset.GetHex()));
    }

    const PeginMinimum pegin_minimum = Params().GetPeginMinimum();
    if (pwallet->chain().getTip()->nHeight >= pegin_minimum.height && value < pegin_minimum.amount) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Peg-in amount (%d) is lower than the minimum peg-in amount for this chain (%d).", FormatMoney(value), FormatMoney(pegin_minimum.amount)));
    }

    const PeginSubsidy pegin_subsidy = Params().GetPeginSubsidy();
    bool subsidy_required = pwallet->chain().getTip()->nHeight >= pegin_subsidy.height && value < pegin_subsidy.threshold;
    if (subsidy_required && !gArgs.GetBoolArg("-validatepegin", Params().GetConsensus().has_parent_chain) && request.params[3].isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Bitcoin transaction fee rate must be supplied, because validatepegin is off and this peg-in requires a burn subsidy.");
    }

    CAmount fee = 0;
    uint32_t parent_vsize = 0;
    CFeeRate feerate = CFeeRate{0};
    if (gArgs.GetBoolArg("-validatepegin", false) && subsidy_required) {
        std::string txid = txBTCRef->GetHash().ToString();
        std::string blockhash = merkleBlock.header.GetHash().ToString();
        UniValue params(UniValue::VARR);
        params.push_back(txid);
        params.push_back(2);
        params.push_back(blockhash);
        UniValue result = CallMainChainRPC("getrawtransaction", params);
        if (result["error"].isStr()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, result["error"]["message"].get_str());
        } else {
            parent_vsize = result["result"]["vsize"].getInt<uint64_t>();
            if (result["result"]["fee"].isNum()) {
                fee = static_cast<CAmount>(std::round(result["result"]["fee"].get_real() * COIN));
            } else if (result["result"]["fee"].isObject()) {
                std::string asset = Params().GetConsensus().parent_pegged_asset.GetHex();
                if (result["result"]["fee"][asset].isNum()) {
                    fee = static_cast<CAmount>(std::round(result["result"]["fee"][asset].get_real() * COIN));
                } else {
                    throw JSONRPCError(RPC_MISC_ERROR, "No fee result for the parent pegged asset.");
                }
            } else {
                throw JSONRPCError(RPC_MISC_ERROR, "Fee result is not a number or object.");
            }
            // when parent feerate is less than 1 sat/vb, use 1 sat/vb for the calculation
            feerate = std::max(CFeeRate{fee, parent_vsize}, CFeeRate{1000});
        }
    } else if (!request.params[3].isNull()) {
        // manual feerate, specified in sats/vb but CFeeRate takes sats/Kvb
        CAmount satsperk = static_cast<CAmount>(std::round(request.params[3].get_real() * 1000));
        feerate = std::max(CFeeRate{satsperk}, CFeeRate{1000});
    }

    // Manually construct peg-in transaction, sign it, and send it off.
    // Decrement the output value as much as needed given the total vsize to
    // pay the fees.

    if (!pwallet->IsLocked())
        pwallet->TopUpKeyPool();

    // Generate a new key that is added to wallet
    auto wpkhash = pwallet->GetNewDestination(OutputType::BECH32, "");
    if (!wpkhash) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(wpkhash).original);
    }

    // add a wallet output for the peg-in value
    mtx.vout.emplace_back(Params().GetConsensus().pegged_asset, value, GetScriptForDestination(*wpkhash));
    if (subsidy_required) {
        // add an op_return for the peg-in fee subsidy
        mtx.vout.emplace_back(Params().GetConsensus().pegged_asset, 0, CScript() << OP_RETURN);
    }
    // add a fee output
    mtx.vout.emplace_back(Params().GetConsensus().pegged_asset, 0, CScript());

    // Estimate fee for transaction, decrement fee output (including witness data)
    unsigned int nBytes = GetVirtualTransactionSize(CTransaction(mtx)) + (1 + 1 + 72 + 1 + 33) / WITNESS_SCALE_FACTOR;
    CCoinControl coin_control;
    FeeCalculation feeCalc;
    CAmount nFeeNeeded = GetMinimumFee(*pwallet, nBytes, coin_control, &feeCalc);

    if (nFeeNeeded == CAmount{0} && feeCalc.reason == FeeReason::FALLBACK) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Fee estimation failed. Fallbackfee is disabled. Wait a few blocks or enable -fallbackfee.");
    }

    if (subsidy_required) {
        CHECK_NONFATAL(mtx.vout.size() == 3);

        // calculate the subsidy as the amount required to spend the P2WSH output
        const auto& fedpegscripts = GetValidFedpegScripts(pwallet->chain().getTip(), Params().GetConsensus(), true /* nextblock_validation */);
        int t = 0;
        int n = 0;
        CHECK_NONFATAL(fedpegscripts.size() > 0);
        CHECK_NONFATAL(ParseFedPegQuorum(fedpegscripts[0].second, t, n));

        // P2WSH input is 41 bytes: txid (32) + vout (4) + scriptsig len (1) + sequence (4)
        // the witness to spend is `t` signatures + the script size
        unsigned int weight = WITNESS_SCALE_FACTOR * (32 + 4 + 1 + 4) + (t * 72 + fedpegscripts[0].second.size());
        unsigned int vbytes = (weight + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;

        CAmount subsidy = feerate.GetFee(vbytes);

        CAmount value = mtx.vout[0].nValue.GetAmount() - nFeeNeeded - subsidy;
        mtx.vout[0].nValue = value;
        mtx.vout[1].nValue = subsidy;
        mtx.vout[2].nValue = nFeeNeeded;
        if (IsDust(mtx.vout[0], pwallet->chain().relayDustFee())) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Peg-in transaction would create dust output.");
        }
    } else {
        CHECK_NONFATAL(mtx.vout.size() == 2);
        mtx.vout[0].nValue = mtx.vout[0].nValue.GetAmount() - nFeeNeeded;
        mtx.vout[1].nValue = nFeeNeeded;
    }

    UniValue ret(UniValue::VOBJ);

    // Return hex
    std::string strHex = EncodeHexTx(CTransaction(mtx));
    ret.pushKV("hex", strHex);

    // Additional block lee-way to avoid bitcoin block races
    if (gArgs.GetBoolArg("-validatepegin", Params().GetConsensus().has_parent_chain)) {
        unsigned int required_depth = Params().GetConsensus().pegin_min_depth + 2;
        std::vector<uint256> txHashes;
        std::vector<unsigned int> txIndices;
        merkleBlock.txn.ExtractMatches(txHashes, txIndices);
        if (txIndices[0] == 0) {
            required_depth = std::max(required_depth, (unsigned int)COINBASE_MATURITY+2);
        }
        ret.pushKV("mature", IsConfirmedBitcoinBlock(merkleBlock.header.GetHash(), required_depth, merkleBlock.txn.GetNumTransactions()));
    }

    return ret;
}

RPCHelpMan createrawpegin()
{
    return RPCHelpMan{"createrawpegin",
                "\nCreates a raw transaction to claim coins from the main chain by creating a peg-in transaction with the necessary metadata after the corresponding Bitcoin transaction.\n"
                "Note that this call will not sign the transaction.\n"
                "If a transaction is not relayed it may require manual addition to a functionary mempool in order for it to be mined.\n",
                {
                    {"bitcoin_tx", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The raw bitcoin transaction (in hex) depositing bitcoin to the mainchain_address generated by getpeginaddress"},
                    {"txoutproof", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "A rawtxoutproof (in hex) generated by the mainchain daemon's `gettxoutproof` containing a proof of only bitcoin_tx"},
                    {"claim_script", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The full script hex from getpeginaddress. If omitted, every script in the wallet address book is tried as a candidate claim script."},
                    {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "The fee rate of the Bitcoin transaction in sats/vb. Required when validatepegin=0, including when a peg-in subsidy requires it."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hex", "raw transaction data"},
                        {RPCResult::Type::BOOL, "mature", /*optional=*/true, "Whether the peg-in is mature (only included when validating peg-ins)"},
                    },
                },
                RPCExamples{
                    HelpExampleCli("createrawpegin", "\"0200000002b80a99d63ca943d72141750d983a3eeda3a5c5a92aa962884ffb141eb49ffb4f000000006a473044022031ffe1d76decdfbbdb7e2ee6010e865a5134137c261e1921da0348b95a207f9e02203596b065c197e31bcc2f80575154774ac4e80acd7d812c91d93c4ca6a3636f27012102d2130dfbbae9bd27eee126182a39878ac4e117d0850f04db0326981f43447f9efeffffffb80a99d63ca943d72141750d983a3eeda3a5c5a92aa962884ffb141eb49ffb4f010000006b483045022100cf041ce0eb249ae5a6bc33c71c156549c7e5ad877ae39e2e3b9c8f1d81ed35060220472d4e4bcc3b7c8d1b34e467f46d80480959183d743dad73b1ed0e93ec9fd14f012103e73e8b55478ab9c5de22e2a9e73c3e6aca2c2e93cd2bad5dc4436a9a455a5c44feffffff0200e1f5050000000017a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87e86cbe00000000001976a914a25fe72e7139fd3f61936b228d657b2548b3936a88acc0020000\", \"00000020976e918ed537b0f99028648f2a25c0bd4513644fb84d9cbe1108b4df6b8edf6ba715c424110f0934265bf8c5763d9cc9f1675a0f728b35b9bc5875f6806be3d19cd5b159ffff7f2000000000020000000224eab3da09d99407cb79f0089e3257414c4121cb85a320e1fd0f88678b6b798e0713a8d66544b6f631f9b6d281c71633fb91a67619b189a06bab09794d5554a60105\" \"0014058c769ffc7d12c35cddec87384506f536383f9c\"")
            + HelpExampleRpc("createrawpegin", "\"0200000002b80a99d63ca943d72141750d983a3eeda3a5c5a92aa962884ffb141eb49ffb4f000000006a473044022031ffe1d76decdfbbdb7e2ee6010e865a5134137c261e1921da0348b95a207f9e02203596b065c197e31bcc2f80575154774ac4e80acd7d812c91d93c4ca6a3636f27012102d2130dfbbae9bd27eee126182a39878ac4e117d0850f04db0326981f43447f9efeffffffb80a99d63ca943d72141750d983a3eeda3a5c5a92aa962884ffb141eb49ffb4f010000006b483045022100cf041ce0eb249ae5a6bc33c71c156549c7e5ad877ae39e2e3b9c8f1d81ed35060220472d4e4bcc3b7c8d1b34e467f46d80480959183d743dad73b1ed0e93ec9fd14f012103e73e8b55478ab9c5de22e2a9e73c3e6aca2c2e93cd2bad5dc4436a9a455a5c44feffffff0200e1f5050000000017a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87e86cbe00000000001976a914a25fe72e7139fd3f61936b228d657b2548b3936a88acc0020000\", \"00000020976e918ed537b0f99028648f2a25c0bd4513644fb84d9cbe1108b4df6b8edf6ba715c424110f0934265bf8c5763d9cc9f1675a0f728b35b9bc5875f6806be3d19cd5b159ffff7f2000000000020000000224eab3da09d99407cb79f0089e3257414c4121cb85a320e1fd0f88678b6b798e0713a8d66544b6f631f9b6d281c71633fb91a67619b189a06bab09794d5554a60105\", \"0014058c769ffc7d12c35cddec87384506f536383f9c\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    wallet::CheckDepositArgument(wallet::DepositArgument::FEDERATED_NETWORK, Params().GetConsensus().drivechain_slot.has_value());

    if (!IsHex(request.params[0].get_str()) || !IsHex(request.params[1].get_str())) {
        throw JSONRPCError(RPC_TYPE_ERROR, "the first two arguments must be hex strings");
    }

    UniValue ret(UniValue::VOBJ);
    if (Params().GetConsensus().ParentChainHasPow()) {
        Sidechain::Bitcoin::CTransactionRef txBTCRef;
        Sidechain::Bitcoin::CMerkleBlock merkleBlock;
        ret = createrawpegin(request, txBTCRef, merkleBlock);
        if (!CheckParentProofOfWork(merkleBlock.header.GetHash(), merkleBlock.header.nBits, Params().GetConsensus())) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid tx out proof");
        }
    } else {
        CTransactionRef txBTCRef;
        CMerkleBlock merkleBlock;
        ret = createrawpegin(request, txBTCRef, merkleBlock);
        if (!CheckProofSignedParent(merkleBlock.header, Params().GetConsensus())) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid tx out proof");
        }
    }
    return ret;
},
    };
}

RPCHelpMan claimpegin()
{
    return RPCHelpMan{"claimpegin",
                "\nClaim coins from the main chain by creating a peg-in transaction with the necessary metadata after the corresponding Bitcoin transaction.\n"
                "Note that the transaction will not be relayed until it is buried at least `pegin_min_depth + 2` blocks deep (chain-dependent).\n"
                "If a transaction is not relayed it may require manual addition to a functionary mempool in order for it to be mined.\n",
                {
                    {"bitcoin_tx", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The raw bitcoin transaction (in hex) depositing bitcoin to the mainchain_address generated by getpeginaddress"},
                    {"txoutproof", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "A rawtxoutproof (in hex) generated by the mainchain daemon's `gettxoutproof` containing a proof of only bitcoin_tx"},
                    {"claim_script", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The full script hex from getpeginaddress. If omitted, every script in the wallet address book is tried as a candidate claim script."},
                    {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "The fee rate of the Bitcoin transaction in sats/vb. Required when validatepegin=0, including when a peg-in subsidy requires it."},
                },
                RPCResult{
                    RPCResult::Type::STR_HEX, "txid", "txid of the resulting sidechain transaction",
                },
                RPCExamples{
                    HelpExampleCli("claimpegin", "\"0200000002b80a99d63ca943d72141750d983a3eeda3a5c5a92aa962884ffb141eb49ffb4f000000006a473044022031ffe1d76decdfbbdb7e2ee6010e865a5134137c261e1921da0348b95a207f9e02203596b065c197e31bcc2f80575154774ac4e80acd7d812c91d93c4ca6a3636f27012102d2130dfbbae9bd27eee126182a39878ac4e117d0850f04db0326981f43447f9efeffffffb80a99d63ca943d72141750d983a3eeda3a5c5a92aa962884ffb141eb49ffb4f010000006b483045022100cf041ce0eb249ae5a6bc33c71c156549c7e5ad877ae39e2e3b9c8f1d81ed35060220472d4e4bcc3b7c8d1b34e467f46d80480959183d743dad73b1ed0e93ec9fd14f012103e73e8b55478ab9c5de22e2a9e73c3e6aca2c2e93cd2bad5dc4436a9a455a5c44feffffff0200e1f5050000000017a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87e86cbe00000000001976a914a25fe72e7139fd3f61936b228d657b2548b3936a88acc0020000\" \"00000020976e918ed537b0f99028648f2a25c0bd4513644fb84d9cbe1108b4df6b8edf6ba715c424110f0934265bf8c5763d9cc9f1675a0f728b35b9bc5875f6806be3d19cd5b159ffff7f2000000000020000000224eab3da09d99407cb79f0089e3257414c4121cb85a320e1fd0f88678b6b798e0713a8d66544b6f631f9b6d281c71633fb91a67619b189a06bab09794d5554a60105\" \"0014058c769ffc7d12c35cddec87384506f536383f9c\"")
            + HelpExampleRpc("claimpegin", "\"0200000002b80a99d63ca943d72141750d983a3eeda3a5c5a92aa962884ffb141eb49ffb4f000000006a473044022031ffe1d76decdfbbdb7e2ee6010e865a5134137c261e1921da0348b95a207f9e02203596b065c197e31bcc2f80575154774ac4e80acd7d812c91d93c4ca6a3636f27012102d2130dfbbae9bd27eee126182a39878ac4e117d0850f04db0326981f43447f9efeffffffb80a99d63ca943d72141750d983a3eeda3a5c5a92aa962884ffb141eb49ffb4f010000006b483045022100cf041ce0eb249ae5a6bc33c71c156549c7e5ad877ae39e2e3b9c8f1d81ed35060220472d4e4bcc3b7c8d1b34e467f46d80480959183d743dad73b1ed0e93ec9fd14f012103e73e8b55478ab9c5de22e2a9e73c3e6aca2c2e93cd2bad5dc4436a9a455a5c44feffffff0200e1f5050000000017a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87e86cbe00000000001976a914a25fe72e7139fd3f61936b228d657b2548b3936a88acc0020000\", \"00000020976e918ed537b0f99028648f2a25c0bd4513644fb84d9cbe1108b4df6b8edf6ba715c424110f0934265bf8c5763d9cc9f1675a0f728b35b9bc5875f6806be3d19cd5b159ffff7f2000000000020000000224eab3da09d99407cb79f0089e3257414c4121cb85a320e1fd0f88678b6b798e0713a8d66544b6f631f9b6d281c71633fb91a67619b189a06bab09794d5554a60105\", \"0014058c769ffc7d12c35cddec87384506f536383f9c\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    wallet::CheckDepositArgument(wallet::DepositArgument::FEDERATED_NETWORK, Params().GetConsensus().drivechain_slot.has_value());

    CTransactionRef tx_ref;
    CMutableTransaction mtx;

    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    LOCK(pwallet->cs_wallet);

    if (pwallet->chain().isInitialBlockDownload()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Peg-ins cannot be completed during initial sync or reindexing.");
    }

    // NOTE: Making an RPC from within another RPC is not generally a good idea. In particular, it
    //   is necessary to copy the URI, which contains the wallet if one was given; otherwise
    //   multi-wallet support will silently break. The resulting request object is still missing a
    //   bunch of other fields, although they are usually not used by RPC handlers. This is a
    //   brittle hack, and further examples of this pattern should not be introduced.

    // Get raw peg-in transaction
    JSONRPCRequest req;
    req.context = request.context;
    req.URI = request.URI;
    req.params = request.params;
    UniValue ret(createrawpegin().HandleRequest(req));  // See the note above, on why this is a bad idea.

    // Make sure it can be propagated and confirmed
    if (!ret["mature"].isNull() && ret["mature"].get_bool() == false) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Peg-in Bitcoin transaction needs more confirmations to be sent.");
    }

    // Sign it
    JSONRPCRequest req2;
    req2.context = request.context;
    req2.URI = request.URI;
    UniValue varr(UniValue::VARR);
    varr.push_back(ret["hex"]);
    req2.params = varr;
    UniValue result = signrawtransactionwithwallet().HandleRequest(req2);  // See the note above, on why this is a bad idea.

    if (!DecodeHexTx(mtx, result["hex"].get_str(), false, true)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    // To check if it's not double spending an existing peg-in UTXO, we check mempool acceptance.
    const MempoolAcceptResult res = pwallet->chain().testPeginClaimAcceptance(MakeTransactionRef(mtx));
    if (res.m_result_type != MempoolAcceptResult::ResultType::VALID) {
        bilingual_str error = Untranslated(strprintf("Error: The transaction was rejected! Reason given: %s", res.m_state.ToString()));
        throw JSONRPCError(RPC_WALLET_ERROR, error.original);
    }

    // Send it
    mapValue_t mapValue;
    pwallet->CommitTransaction(MakeTransactionRef(mtx), mapValue, {} /* orderForm */);

    return mtx.GetHash().GetHex();
},
    };
}

static UniValue FinishDrivechainDeposit(CWallet& wallet, const CTransactionRef& tx,
    const uint256& mainchain_txid, const std::string& address, CAmount amount,
    CAmount deposit_amount, CAmount fee_sats,
    std::optional<std::pair<int64_t,uint256>> native_identity = std::nullopt)
{
    const uint256 side_txid = tx->GetHash();
    const std::string tx_hex = EncodeHexTx(*tx);
    bool known;
    {
        LOCK(wallet.cs_wallet);
        known = wallet.GetWalletTx(side_txid) != nullptr;
    }
    const auto [already_imported, broadcast] = wallet::BroadcastDrivechainDeposit(known, [&](std::string& error) {
        return wallet.chain().broadcastTransaction(tx, /*max_tx_fee=*/0, /*relay=*/true, error);
    });
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("txid", side_txid.GetHex());
    ret.pushKV("mainchain_txid", mainchain_txid.GetHex());
    if (native_identity) {
        ret.pushKV("mainchain_vout", native_identity->first);
        ret.pushKV("mainchain_block_hash", native_identity->second.GetHex());
    }
    ret.pushKV("address", address);
    ret.pushKV("amount", ValueFromAmount(amount));
    ret.pushKV("value_sats", amount);
    ret.pushKV("deposit_value_sats", deposit_amount);
    ret.pushKV("fee_sats", fee_sats);
    ret.pushKV("hex", tx_hex);
    ret.pushKV("already_imported", already_imported);
    ret.pushKV("broadcast", broadcast);
    return ret;
}

static RPCHelpMan importdrivechaindeposit_native()
{
    return RPCHelpMan{"importdrivechaindeposit",
                "\nImport a confirmed BIP300/301 drivechain deposit into this Elements wallet.\n"
                "The node independently checks the raw parent-chain block, canonical treasury transition,\n"
                "outpoint, value, destination commitment, active-chain membership, and confirmation depth.\n",
                {
                    {"mainchain_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The confirmed mainchain deposit transaction id."},
                    {"mainchain_vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The exact BIP300 deposit outpoint index."},
                    {"mainchain_block_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The mainchain block containing the BIP300 deposit event."},
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The Elements address committed by the BIP300 deposit."},
                    {"value_sats", RPCArg::Type::NUM, RPCArg::Optional::NO, "The exact deposit value in satoshis."},
                    {"fee_sats", RPCArg::Type::NUM, RPCArg::Default{0}, "Maximum optional fee sponsored by this wallet for an address-only deposit. Cannot be combined with deposit_fee_sats."},
                    {"deposit_fee_sats", RPCArg::Type::NUM, RPCArg::Default{0}, "Exact Elements fee committed in the L1 deposit destination, deducted from value_sats. Use getdrivechaindepositdestination before creating the L1 deposit. Cannot alter an existing deposit's fee."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "txid", "The deterministic wallet credit transaction id."},
                        {RPCResult::Type::STR_HEX, "mainchain_txid", "The mainchain deposit transaction id."},
                        {RPCResult::Type::NUM, "mainchain_vout", "The mainchain deposit output index."},
                        {RPCResult::Type::STR_HEX, "mainchain_block_hash", "The mainchain block containing the deposit."},
                        {RPCResult::Type::STR, "address", "The credited Elements address."},
                        {RPCResult::Type::STR_AMOUNT, "amount", "The credited amount in pegged asset units."},
                        {RPCResult::Type::NUM, "value_sats", "The credited amount in satoshis."},
                        {RPCResult::Type::NUM, "deposit_value_sats", "The deposit input value in satoshis."},
                        {RPCResult::Type::NUM, "fee_sats", "The actual Elements fee, either wallet-sponsored or committed in the L1 deposit."},
                        {RPCResult::Type::STR_HEX, "hex", "The sidechain transaction hex."},
                        {RPCResult::Type::BOOL, "already_imported", "Whether this sidechain deposit transaction was already known."},
                        {RPCResult::Type::BOOL, "broadcast", "Whether the transaction was broadcast by this call."},
                    },
                },
                RPCExamples{
                    HelpExampleCli("importdrivechaindeposit", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" 0 \"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\" \"el1qq...\" 100000")
            + HelpExampleRpc("importdrivechaindeposit", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\", 0, \"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\", \"el1qq...\", 100000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto& drivechain_slot = Params().GetConsensus().drivechain_slot;
    wallet::CheckDepositArgument(wallet::DepositArgument::NATIVE_NETWORK, drivechain_slot.has_value());

    // Reject unsupported ordinary-network calls before the global
    // auto-default-wallet path can create or load any wallet on disk.
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    const std::string mainchain_txid_str = request.params[0].get_str();
    wallet::CheckDepositArgument(wallet::DepositArgument::TXID, IsHex(mainchain_txid_str), mainchain_txid_str.size() == 64);

    const int64_t mainchain_vout = request.params[1].getInt<int64_t>();
    wallet::CheckDepositArgument(wallet::DepositArgument::OUTPUT_INDEX, mainchain_vout);

    const std::string mainchain_block_hash_str = request.params[2].get_str();
    wallet::CheckDepositArgument(wallet::DepositArgument::BLOCK_HASH, IsHex(mainchain_block_hash_str), mainchain_block_hash_str.size() == 64);

    const std::string address = request.params[3].get_str();
    const CTxDestination dest = DecodeDestination(address);
    wallet::CheckDepositArgument(wallet::DepositArgument::ADDRESS, IsValidDestination(dest));

    const int64_t value_sats = wallet::ParseDrivechainSatoshis(request.params[4],"value_sats");
    wallet::CheckDepositArgument(wallet::DepositArgument::NATIVE_VALUE, value_sats);
    const int64_t max_fee_sats = wallet::ParseDrivechainSatoshis(request.params[5], "fee_sats", 0);
    wallet::CheckDepositArgument(wallet::DepositArgument::NATIVE_FEE, max_fee_sats);
    const int64_t deposit_fee_sats = wallet::ParseDrivechainSatoshis(request.params[6], "deposit_fee_sats", 0);
    wallet::CheckDepositArgument(wallet::DepositArgument::HISTORICAL_FEE, deposit_fee_sats, value_sats);
    if (deposit_fee_sats && max_fee_sats)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Choose a committed deposit fee or a sponsored fee, not both");
    const CAmount deposit_amount = value_sats;
    const CAmount amount = deposit_amount - deposit_fee_sats;

    const uint256 mainchain_txid = uint256S(mainchain_txid_str);
    const uint256 mainchain_block_hash = uint256S(mainchain_block_hash_str);
    const COutPoint mainchain_outpoint(Txid::FromUint256(mainchain_txid), static_cast<uint32_t>(mainchain_vout));
    std::string committed_destination;
    try { committed_destination = EncodeDrivechainDepositDestination(address, deposit_fee_sats); }
    catch (const std::invalid_argument& e) { throw JSONRPCError(RPC_INVALID_PARAMETER, e.what()); }
    const std::vector<unsigned char> address_bytes(committed_destination.begin(), committed_destination.end());
    const CBlockIndex* active_tip = pwallet->chain().getTip();
    std::string deposit_error;
    CMutableTransaction mtx;
    CTransactionRef tx_ref;
    CAmount fee_sats{deposit_fee_sats};
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::DEPOSIT_NATIVE_IMPORT,
        [&](uint32_t stage) -> uint32_t {
        switch (stage) {
        case 1: return IsConfirmedDrivechainDeposit(mainchain_block_hash,
            *drivechain_slot,
            mainchain_outpoint,
            deposit_amount,
            address_bytes,
            &deposit_error,
            drivechain::haskell::NextBlockHeight(active_tip != nullptr, active_tip ? active_tip->nHeight : 0));
        case 2:
            throw JSONRPCError(RPC_VERIFY_REJECTED, strprintf("BIP300 deposit validation failed: %s", deposit_error));
        case 3: {
            mtx = CMutableTransaction{*CreateNativeDrivechainDeposit({
                Sidechain::Bitcoin::COutPoint(mainchain_outpoint.hash, mainchain_outpoint.n),
                mainchain_block_hash, 0, deposit_amount, address_bytes})};
            return 1;
        }
        case 4: return drivechain::haskell::DepositPreflight(2, max_fee_sats, 0);

        // The recipient receives the full deposit. Permissionless relayers may
        // sponsor ordinary signed wallet inputs for the network fee; they can
        // never choose a fee that is deducted from the mint authorization.
        case 5: {
            CCoinControl coin_control;
            const std::vector<CRecipient> recipients{{dest, amount, Params().GetConsensus().pegged_asset, CPubKey{}, false}};
            const CTxOut pegin_output = GetPeginOutputFromWitness(
                mtx.witness.vtxinwit[0].m_pegin_witness);
            CMutableTransaction funding_inputs{mtx};
            funding_inputs.vout.clear();
            funding_inputs.witness.vtxoutwit.clear();
            LOCK(pwallet->cs_wallet);
            auto funded = wallet::FundTransaction(
                *pwallet, funding_inputs, recipients, std::nullopt,
                /*lockUnspents=*/false, coin_control);
            std::map<COutPoint, Coin> input_coins;
            auto coin = input_coins.end();
            std::map<int, bilingual_str> signing_errors;
            drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::DEPOSIT_SPONSORSHIP,
                [&](uint32_t action) -> uint32_t {
                switch (action) {
                case 1: return bool(funded);
                case 2:
                    throw JSONRPCError(RPC_WALLET_ERROR,
                        strprintf("Unable to sponsor drivechain deposit fee: %s",
                            util::ErrorString(funded).original));
                case 3:
                    fee_sats = funded->fee;
                    mtx = CMutableTransaction{*funded->tx};
                    return drivechain::haskell::DepositPreflight(11, fee_sats, max_fee_sats);
                case 4:
                    throw JSONRPCError(RPC_WALLET_ERROR,
                        strprintf("Required sidechain fee %s exceeds fee_sats limit %s",
                            FormatMoney(fee_sats), FormatMoney(max_fee_sats)));
                case 5:
                    for (const CTxIn& input : mtx.vin)
                        input_coins[input.prevout];
                    pwallet->chain().findCoins(input_coins);
                    input_coins[mainchain_outpoint] = Coin(pegin_output, 0, false);
                    coin = input_coins.begin();
                    return 1;
                case 6: return coin != input_coins.end();
                case 7: return coin->second.IsSpent();
                case 8:
                    throw JSONRPCError(RPC_WALLET_ERROR, "Unable to locate a selected fee-sponsoring wallet input");
                case 9: ++coin; return 1;
                case 10: return pwallet->SignTransaction(mtx, input_coins, SIGHASH_DEFAULT, signing_errors);
                case 11:
                    throw JSONRPCError(RPC_WALLET_ERROR, "Unable to sign the fee-sponsoring wallet inputs");
                default: throw std::logic_error("invalid deposit sponsorship action");
                }
            });
            return 1;
        }
        case 6: tx_ref = MakeTransactionRef(mtx); return 1;
        default: throw std::logic_error("invalid native deposit import action");
        }
    });
    return FinishDrivechainDeposit(*pwallet, tx_ref, mainchain_txid, address, amount,
        deposit_amount, fee_sats, std::pair{mainchain_vout, mainchain_block_hash});
},
    };
}


static RPCHelpMan importdrivechaindeposit_ecx()
{
    return RPCHelpMan{"importdrivechaindeposit",
                "\nImport a confirmed BIP300/301 drivechain deposit into this Elements wallet.\n"
                "The node independently verifies the exact deposit outpoint, destination, value, CTIP,\n"
                "sidechain identity, mainchain network, and canonical confirmation through the enforcer\n"
                "before broadcasting a sidechain transaction anchored in the UTXO set.\n",
                {
                    {"mainchain_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The mainchain deposit transaction id observed in two-way-peg data."},
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The Elements address to credit."},
                    {"value_sats", RPCArg::Type::NUM, RPCArg::Optional::NO, "The deposit value in satoshis."},
                    {"fee_sats", RPCArg::Type::NUM, RPCArg::Default{1000}, "The sidechain relay fee to subtract from the credited output."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "txid", "The deterministic wallet credit transaction id."},
                        {RPCResult::Type::STR_HEX, "mainchain_txid", "The mainchain deposit transaction id."},
                        {RPCResult::Type::STR, "address", "The credited Elements address."},
                        {RPCResult::Type::STR_AMOUNT, "amount", "The credited amount in pegged asset units."},
                        {RPCResult::Type::NUM, "value_sats", "The credited amount in satoshis."},
                        {RPCResult::Type::NUM, "deposit_value_sats", "The deposit input value in satoshis."},
                        {RPCResult::Type::NUM, "fee_sats", "The sidechain relay fee subtracted from the credited output."},
                        {RPCResult::Type::STR_HEX, "hex", "The sidechain transaction hex."},
                        {RPCResult::Type::BOOL, "already_imported", "Whether this sidechain deposit transaction was already known."},
                        {RPCResult::Type::BOOL, "broadcast", "Whether the transaction was broadcast by this call."},
                    },
                },
                RPCExamples{
                    HelpExampleCli("importdrivechaindeposit", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" \"el1qq...\" 100000")
            + HelpExampleRpc("importdrivechaindeposit", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\", \"el1qq...\", 100000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto& consensus = Params().GetConsensus();
    wallet::CheckDepositArgument(wallet::DepositArgument::HISTORICAL_NETWORK, consensus.elements_mode, consensus.has_parent_chain);
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    const std::string mainchain_txid_str = request.params[0].get_str();
    wallet::CheckDepositArgument(wallet::DepositArgument::TXID, IsHex(mainchain_txid_str), mainchain_txid_str.size() == 64);

    const std::string address = request.params[1].get_str();
    const CTxDestination dest = DecodeDestination(address);
    wallet::CheckDepositArgument(wallet::DepositArgument::ADDRESS, IsValidDestination(dest));

    const int64_t value_sats = wallet::ParseDrivechainSatoshis(request.params[2],"value_sats");
    wallet::CheckDepositArgument(wallet::DepositArgument::HISTORICAL_VALUE, value_sats);
    const int64_t fee_sats = wallet::ParseDrivechainSatoshis(request.params[3], "fee_sats", 1000);
    wallet::CheckDepositArgument(wallet::DepositArgument::HISTORICAL_FEE, fee_sats, value_sats);
    const CAmount deposit_amount = value_sats;
    const CAmount amount = value_sats - fee_sats;

    const uint256 mainchain_txid = uint256S(mainchain_txid_str);
    CMutableTransaction mtx;
    CTransactionRef tx_ref;
    std::string authentication_error;
    drivechain::AuthenticatedDeposit authenticated;
    DrivechainDepositEvidence evidence;
    const auto install_witness = [&](const auto& proof) {
        mtx.witness.vtxinwit[0].m_pegin_witness = CreateDrivechainDepositPeginWitness(
            deposit_amount, Params().GetConsensus().pegged_asset,
            Params().ParentGenesisBlockHash(), CScript() << OP_TRUE, proof);
    };
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::DEPOSIT_IMPORT,
        [&](uint32_t action) -> uint32_t {
        switch (action) {
        case 1: {
            CTxIn pegin_input(COutPoint(Txid::FromUint256(mainchain_txid), 0), CScript(), CTxIn::SEQUENCE_FINAL);
            pegin_input.m_is_pegin = true;
            mtx.vin.push_back(pegin_input);
            mtx.vout.push_back(CTxOut(Params().GetConsensus().pegged_asset, amount, GetScriptForDestination(dest)));
            return 1;
        }
        case 2: return drivechain::haskell::ParentReplayAll<2>({
            [&] { return g_con_elementsmode; },
            [&] { return drivechain::haskell::DepositPreflight(2, fee_sats, 0); },
        });
        case 3:
            mtx.vout.push_back(CTxOut(Params().GetConsensus().pegged_asset, fee_sats, CScript()));
            return 1;
        case 4:
            mtx.witness.vtxinwit.resize(1);
            mtx.witness.vtxoutwit.resize(mtx.vout.size());
            install_witness(mainchain_txid);
            tx_ref = MakeTransactionRef(mtx);
            return 1;
        case 5: return VerifyDrivechainDeposit(*tx_ref, 0, &authenticated, &authentication_error);
        case 6: throw JSONRPCError(RPC_VERIFY_REJECTED, "Drivechain deposit authentication failed: " + authentication_error);
        case 7: return BuildDrivechainDepositEvidence(authenticated, evidence, &authentication_error);
        case 8: throw JSONRPCError(RPC_VERIFY_REJECTED, "Drivechain deposit evidence construction failed: " + authentication_error);
        case 9: install_witness(evidence); return 1;
        case 10: tx_ref = MakeTransactionRef(mtx); return 1;
        default: throw std::logic_error("invalid deposit import action");
        }
    });
    return FinishDrivechainDeposit(*pwallet, tx_ref, mainchain_txid, address, amount,
        deposit_amount, fee_sats);
},
    };
}

// Rewind the outputs to unblinded, and push placeholders for blinding info. Not exported.
void FillBlinds(CWallet* pwallet, CMutableTransaction& tx, std::vector<uint256>& output_value_blinds, std::vector<uint256>& output_asset_blinds, std::vector<CPubKey>& output_pubkeys, std::vector<CKey>& asset_keys, std::vector<CKey>& token_keys) {

    // Resize witness before doing anything
    tx.witness.vtxinwit.resize(tx.vin.size());
    tx.witness.vtxoutwit.resize(tx.vout.size());

    for (size_t nOut = 0; nOut < tx.vout.size(); ++nOut) {
        CTxOut& out = tx.vout[nOut];
        if (out.nValue.IsExplicit()) {
            CPubKey pubkey(out.nNonce.vchCommitment);
            if (!pubkey.IsFullyValid()) {
                output_pubkeys.emplace_back();
            } else {
                output_pubkeys.push_back(pubkey);
            }
            output_value_blinds.emplace_back();
            output_asset_blinds.emplace_back();
        } else if (out.nValue.IsCommitment()) {
            CTxOutWitness* ptxoutwit = &tx.witness.vtxoutwit[nOut];
            uint256 blinding_factor;
            uint256 asset_blinding_factor;
            CAsset asset;
            CAmount amount;
            // This can only be used to recover things like change addresses and self-sends.
            if (UnblindConfidentialPair(pwallet->GetBlindingKey(&out.scriptPubKey), out.nValue, out.nAsset, out.nNonce, out.scriptPubKey, ptxoutwit->vchRangeproof, amount, blinding_factor, asset, asset_blinding_factor) != 0) {
                // Wipe out confidential info from output and output witness
                CScript scriptPubKey = tx.vout[nOut].scriptPubKey;
                CTxOut newOut(asset, amount, scriptPubKey);
                tx.vout[nOut] = newOut;
                ptxoutwit->SetNull();

                // Mark for re-blinding with same key that deblinded it
                CPubKey pubkey(pwallet->GetBlindingKey(&out.scriptPubKey).GetPubKey());
                output_pubkeys.push_back(pubkey);
                output_value_blinds.emplace_back();
                output_asset_blinds.emplace_back();
            } else {
                output_pubkeys.emplace_back();
                output_value_blinds.emplace_back();
                output_asset_blinds.emplace_back();
            }
        } else {
            // Null or invalid, do nothing for that output
            output_pubkeys.emplace_back();
            output_value_blinds.emplace_back();
            output_asset_blinds.emplace_back();
        }
    }

    // Fill out issuance blinding keys to be used directly as nonce for rangeproof
    for (size_t nIn = 0; nIn < tx.vin.size(); ++nIn) {
        CAssetIssuance& issuance = tx.vin[nIn].assetIssuance;
        if (issuance.IsNull()) {
            asset_keys.emplace_back();
            token_keys.emplace_back();
            continue;
        }

        // Calculate underlying asset for use as blinding key script
        CAsset asset;
        // New issuance, compute the asset ids
        if (issuance.assetBlindingNonce.IsNull()) {
            uint256 entropy;
            GenerateAssetEntropy(entropy, tx.vin[nIn].prevout, issuance.assetEntropy);
            CalculateAsset(asset, entropy);
        }
        // Re-issuance
        else {
            // TODO Give option to skip blinding when the reissuance token was derived without blinding ability. For now we assume blinded
            // hashAssetIdentifier doubles as the entropy on reissuance
            CalculateAsset(asset, issuance.assetEntropy);
        }

        // Special format for issuance blinding keys, unique for each transaction
        CScript blindingScript = CScript() << OP_RETURN << std::vector<unsigned char>(tx.vin[nIn].prevout.hash.ToUint256().begin(), tx.vin[nIn].prevout.hash.ToUint256().end()) << tx.vin[nIn].prevout.n;

        for (size_t nPseudo = 0; nPseudo < 2; nPseudo++) {
            bool issuance_asset = (nPseudo == 0);
            std::vector<CKey>& issuance_blinding_keys = issuance_asset ? asset_keys : token_keys;
            CConfidentialValue& conf_value = issuance_asset ? issuance.nAmount : issuance.nInflationKeys;
            if (conf_value.IsCommitment()) {
                // Rangeproof must exist
                if (tx.witness.vtxinwit.size() <= nIn) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Transaction issuance is already blinded but has no attached rangeproof.");
                }
                CTxInWitness& txinwit = tx.witness.vtxinwit[nIn];
                std::vector<unsigned char>& vchRangeproof = issuance_asset ? txinwit.vchIssuanceAmountRangeproof : txinwit.vchInflationKeysRangeproof;
                uint256 blinding_factor;
                uint256 asset_blinding_factor;
                CAmount amount;
                if (UnblindConfidentialPair(pwallet->GetBlindingKey(&blindingScript), conf_value, CConfidentialAsset(asset), CConfidentialNonce(), CScript(), vchRangeproof, amount, blinding_factor, asset, asset_blinding_factor) != 0) {
                    // Wipe out confidential info from issuance
                    vchRangeproof.clear();
                    conf_value = CConfidentialValue(amount);
                    // One key blinds both values, single key needed for issuance reveal
                    issuance_blinding_keys.push_back(pwallet->GetBlindingKey(&blindingScript));
                } else {
                    // If  unable to unblind, leave it alone in next blinding step
                    issuance_blinding_keys.emplace_back();
                }
            } else if (conf_value.IsExplicit()) {
                // Use wallet to generate blindingkey used directly as nonce
                // as user is not "sending" to anyone.
                // Always assumed we want to blind here.
                // TODO Signal intent for all blinding via API including replacing nonce commitment
                issuance_blinding_keys.push_back(pwallet->GetBlindingKey(&blindingScript));
            } else  {
                // Null or invalid, don't try anything but append an empty key
                issuance_blinding_keys.emplace_back();
            }
        }
    }
}

RPCHelpMan importdrivechaindeposit()
{
    // Alpha consumes its authenticated native eight-item CTIP witness, never
    // an ECX Connect/JSON evidence record with the same version marker.
    const std::array factories{importdrivechaindeposit_ecx, importdrivechaindeposit_native};
    const unsigned flags = unsigned{Params().GetConsensus().drivechain_slot.has_value()} << 1;
    return factories[drivechain::WALLET_RPC_ROUTES[0][flags]]();
}

RPCHelpMan blindrawtransaction()
{
    return RPCHelpMan{"blindrawtransaction",
                "\nConvert one or more outputs of a raw transaction into confidential ones using only wallet inputs.\n"
                "Returns the hex-encoded raw transaction.\n"
                "The output keys used can be specified by using a confidential address in createrawtransaction.\n"
                "This call may add an additional 0-value unspendable output in order to balance the blinders.\n",
                {
                    {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "A hex-encoded raw transaction."},
                    {"ignoreblindfail", RPCArg::Type::BOOL , RPCArg::Default{true}, "Return a transaction even when a blinding attempt fails due to number of blinded inputs/outputs."},
                    {"asset_commitments", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "An array of input asset generators. If provided, this list must be empty, or match the final input commitment list, including ordering, to make a valid surjection proof. This list does not include generators for issuances, as these assets are inherently unblinded.",
                        {
                            {"assetcommitment", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "A hex-encoded asset commitment, one for each input."
            "                        Null commitments must be \"\"."},
                        }
                    },
                    {"blind_issuances", RPCArg::Type::BOOL , RPCArg::Default{true}, "Blind the issuances found in the raw transaction or not. All issuances will be blinded if true."},
                    {"totalblinder", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Ignored for now."},
                },
                RPCResult{
                    RPCResult::Type::STR_HEX, "transaction", "serialized transaction",
                },
                RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    std::vector<unsigned char> txData(ParseHexV(request.params[0], "argument 1"));
    DataStream ssData(MakeByteSpan(txData));
    CMutableTransaction tx;
    try {
        ssData >> TX_WITH_WITNESS(tx);
    } catch (const std::exception &) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    bool ignore_blind_fail = true;
    if (!request.params[1].isNull()) {
        ignore_blind_fail = request.params[1].get_bool();
    }

    std::vector<std::vector<unsigned char> > auxiliary_generators;
    if (!request.params[2].isNull()) {
        UniValue assetCommitments = request.params[2].get_array();
        if (assetCommitments.size() != 0 && assetCommitments.size() < tx.vin.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Asset commitment array must have at least as many entries as transaction inputs.");
        }
        for (size_t nIn = 0; nIn < assetCommitments.size(); nIn++) {
            if (assetCommitments[nIn].isStr()) {
                std::string assetcommitment = assetCommitments[nIn].get_str();
                if (IsHex(assetcommitment) && assetcommitment.size() == 66) {
                    auxiliary_generators.push_back(ParseHex(assetcommitment));
                    continue;
                }
            }
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Asset commitments must be a hex encoded string of length 66.");
        }
    }

    bool blind_issuances = request.params[3].isNull() || request.params[3].get_bool();

    LOCK(pwallet->cs_wallet);

    const CBlockIndex* active_tip = pwallet->chain().getTip();
    const int child_height = drivechain::haskell::NextBlockHeight(active_tip != nullptr, active_tip ? active_tip->nHeight : 0);
    const auto& fedpegscripts = GetValidFedpegScripts(active_tip, Params().GetConsensus(), true /* nextblock_validation */);

    std::vector<uint256> input_blinds;
    std::vector<uint256> input_asset_blinds;
    std::vector<CAsset> input_assets;
    std::vector<CAmount> input_amounts;
    int n_blinded_ins = 0;
    for (size_t nIn = 0; nIn < tx.vin.size(); ++nIn) {
        COutPoint prevout = tx.vin[nIn].prevout;

        // Special handling for peg-in inputs: no blinds and explicit amount/asset.
        if (tx.vin[nIn].m_is_pegin) {
            std::string err;
            if (tx.witness.vtxinwit.size() != tx.vin.size() || !IsValidPeginWitness(tx.witness.vtxinwit[nIn].m_pegin_witness, fedpegscripts, prevout, err, false,
                    nullptr, nullptr, child_height)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Transaction contains invalid peg-in input: %s", err));
            }
            CTxOut pegin_output = GetPeginOutputFromWitness(tx.witness.vtxinwit[nIn].m_pegin_witness);
            input_blinds.emplace_back();
            input_asset_blinds.emplace_back();
            input_assets.push_back(pegin_output.nAsset.GetAsset());
            input_amounts.push_back(pegin_output.nValue.GetAmount());
            continue;
        }

        const auto& it = pwallet->mapWallet.find(prevout.hash);
        if (it == pwallet->mapWallet.end() || InputIsMine(*pwallet, tx.vin[nIn]) == wallet::ISMINE_NO) {
            // For inputs we don't own, input assetcommitments for the surjection must be supplied.
            if (auxiliary_generators.size() > 0) {
                input_blinds.emplace_back();
                input_asset_blinds.emplace_back();
                input_assets.emplace_back();
                input_amounts.push_back(-1);
                continue;
            }
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter: transaction spends from non-wallet output and no assetcommitment list was given.");
        }

        if (prevout.n >= it->second.tx->vout.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter: transaction spends non-existing output");
        }
        input_blinds.push_back(it->second.GetOutputAmountBlindingFactor(*pwallet, prevout.n));
        input_asset_blinds.push_back(it->second.GetOutputAssetBlindingFactor(*pwallet, prevout.n));
        input_assets.push_back(it->second.GetOutputAsset(*pwallet, prevout.n));
        input_amounts.push_back(it->second.GetOutputValueOut(*pwallet, prevout.n));
        if (it->second.tx->vout[prevout.n].nValue.IsCommitment()) {
            n_blinded_ins += 1;
        }
    }

    std::vector<uint256> output_blinds;
    std::vector<uint256> output_asset_blinds;
    std::vector<CPubKey> output_pubkeys;
    std::vector<CKey> asset_keys;
    std::vector<CKey> token_keys;
    // This fills out issuance blinding data for you from the wallet itself
    FillBlinds(pwallet, tx, output_blinds, output_asset_blinds, output_pubkeys, asset_keys, token_keys);

    if (!blind_issuances) {
        asset_keys.clear();
        token_keys.clear();
    }

    // How many are we trying to blind?
    int num_pubkeys = 0;
    unsigned int key_index = 0;
    for (unsigned int i = 0; i < output_pubkeys.size(); i++) {
        const CPubKey& key = output_pubkeys[i];
        if (key.IsValid()) {
            num_pubkeys++;
            key_index = i;
        }
    }
    for (const CKey& key : asset_keys) {
        if (key.IsValid()) num_pubkeys++;
    }
    for (const CKey& key : token_keys) {
        if (key.IsValid()) num_pubkeys++;
    }

    if (num_pubkeys == 0 && n_blinded_ins == 0) {
        // Vacuous, just return the transaction
        return EncodeHexTx(CTransaction(tx));
    } else if (n_blinded_ins > 0 && num_pubkeys == 0) {
        if (tx.vout.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Unable to blind transaction: transaction has no outputs to balance blinded inputs against.");
        }
        // Blinded inputs need to balanced with something to be valid, make a dummy.
        CTxOut newTxOut(tx.vout.back().nAsset.GetAsset(), 0, CScript() << OP_RETURN);
        tx.vout.push_back(newTxOut);
        num_pubkeys++;
        output_pubkeys.push_back(pwallet->GetBlindingPubKey(newTxOut.scriptPubKey));
    } else if (n_blinded_ins == 0 && num_pubkeys == 1) {
        if (ignore_blind_fail) {
            // Just get rid of the ECDH key in the nonce field and return
            tx.vout[key_index].nNonce.SetNull();
            return EncodeHexTx(CTransaction(tx));
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Unable to blind transaction: Add another output to blind in order to complete the blinding.");
        }
    }

    if (BlindTransaction(input_blinds, input_asset_blinds, input_assets, input_amounts, output_blinds, output_asset_blinds, output_pubkeys, asset_keys, token_keys, tx, (auxiliary_generators.size() ? &auxiliary_generators : nullptr)) != num_pubkeys) {
        // TODO Have more rich return values, communicating to user what has been blinded
        // User may be ok not blinding something that for instance has no corresponding type on input
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unable to blind transaction: Are you sure each asset type to blind is represented in the inputs?");
    }

    return EncodeHexTx(CTransaction(tx));
},
    };
}

RPCHelpMan unblindrawtransaction()
{
    return RPCHelpMan{"unblindrawtransaction",
                "\nRecovers unblinded transaction outputs from blinded outputs and issuance inputs when possible using wallet's known blinding keys, and strips related witness data.\n",
                {
                    {"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex string of the raw transaction."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hex", "unblinded raw transaction"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("unblindrawtransaction", "\"blindedtransactionhex\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    CMutableTransaction tx;
    if (!DecodeHexTx(tx, request.params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");

    std::vector<uint256> output_value_blinds;
    std::vector<uint256> output_asset_blinds;
    std::vector<CPubKey> output_pubkeys;
    std::vector<CKey> asset_keys;
    std::vector<CKey> token_keys;
    FillBlinds(pwallet, tx, output_value_blinds, output_asset_blinds, output_pubkeys, asset_keys, token_keys);

    UniValue result(UniValue::VOBJ);
    result.pushKV("hex", EncodeHexTx(CTransaction(tx)));
    return result;
},
    };
}

static CTransactionRef SendGenerationTransaction(const CScript& asset_script, const CPubKey &asset_pubkey, const CScript& token_script, const CPubKey &token_pubkey, CAmount asset_amount, CAmount token_amount, IssuanceDetails* issuance_details, CWallet* pwallet)
{
    CAsset reissue_token = issuance_details->reissuance_token;
    CAmount curBalance = GetBalance(*pwallet).m_mine_trusted[reissue_token];

    if (!reissue_token.IsNull() && curBalance <= 0) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "No available reissuance tokens in wallet.");
    }

    std::vector<CRecipient> vecSend;
    // Signal outputs to skip "funding" with fixed asset numbers 1, 2, ...
    // We don't know the asset during initial issuance until inputs are chosen
    if (asset_script.size() > 0) {
        CTxDestination dest;
        if (!ExtractDestination(asset_script, dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid asset destination script");
        }
        vecSend.push_back({dest, asset_amount, CAsset(uint256S("1")), asset_pubkey, false});
    }
    if (token_script.size() > 0) {
        CTxDestination dest;
        if (!ExtractDestination(token_script, dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid token destination script");
        }
        CRecipient recipient = {dest, token_amount, CAsset(uint256S("2")), token_pubkey, false};
        // We need to select the issuance token(s) to spend
        if (!reissue_token.IsNull()) {
            recipient.asset = reissue_token;
            recipient.nAmount = curBalance; // Or 1?
            // If the issuance token *is* the fee asset, subtract fee from this output
            if (reissue_token == ::policyAsset) {
                recipient.fSubtractFeeFromAmount = true;
            }
        }
        vecSend.push_back(recipient);
    }

    bilingual_str error;
    CCoinControl dummy_control;
    BlindDetails blind_details;
    util::Result<CreatedTransactionResult> txr = CreateTransaction(*pwallet, vecSend, std::nullopt,
                dummy_control, true, &blind_details, issuance_details);
    if (!txr) {
        throw JSONRPCError(RPC_WALLET_ERROR, error.original);
    }

    mapValue_t map_value;
    pwallet->CommitTransaction((*txr).tx, std::move(map_value), {} /* orderForm */, &blind_details);

    return (*txr).tx;
}

RPCHelpMan issueasset()
{
    return RPCHelpMan{"issueasset",
                "\nCreate an asset. Must have funds in wallet to do so. Returns issuance details including txid, vin, entropy, asset, and token.\n"
                "For more fine-grained control such as multiple issuances, see `rawissueasset` RPC call.\n",
                {
                    {"assetamount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount of asset to generate. Note that the amount is BTC-like, with 8 decimal places."},
                    {"tokenamount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount of reissuance tokens to generate. Note that the amount is BTC-like, with 8 decimal places. These will allow you to reissue the asset if in wallet using `reissueasset`. These tokens are not consumed during reissuance."},
                    {"blind", RPCArg::Type::BOOL, RPCArg::Default{true}, "Whether to blind the issuances."},
                    {"contract_hash", RPCArg::Type::STR_HEX, RPCArg::Default{"0000...0000"}, "Contract hash that is put into issuance definition. Must be 32 bytes worth in hex string form. This will affect the asset id."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "txid", "Transaction id for issuance"},
                        {RPCResult::Type::NUM, "vin", "The input position of the issuance in the transaction"},
                        {RPCResult::Type::STR_HEX, "entropy", "Entropy of the asset type"},
                        {RPCResult::Type::STR_HEX, "asset", "Asset type for issuance"},
                        {RPCResult::Type::STR_HEX, "token", "Token type for issuance"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("issueasset", "10 0")
            + HelpExampleRpc("issueasset", "10, 0")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    LOCK(pwallet->cs_wallet);

    if (!g_con_elementsmode) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Issuance can only be done on elements-style chains. Note: `-regtest` is Bitcoin's regtest mode, instead try `-chain=<custom chain name>`");
    }

    CAmount nAmount = AmountFromValue(request.params[0], false);
    CAmount nTokens = AmountFromValue(request.params[1], false);
    if (nAmount == 0 && nTokens == 0) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Issuance must have one non-zero component");
    }

    bool blind_issuances = request.params[2].isNull() || request.params[2].get_bool();

    // Check for optional contract to hash into definition
    uint256 contract_hash;
    if (!request.params[3].isNull()) {
        contract_hash = ParseHashV(request.params[3], "contract_hash");
    }

    if (!pwallet->IsLocked())
        pwallet->TopUpKeyPool();

    // Generate a new key that is added to wallet
    bilingual_str error;
    CPubKey newKey;
    CScript asset_script;
    CScript token_script;
    CPubKey asset_dest_blindpub;
    CPubKey token_dest_blindpub;

    if (nAmount > 0) {
        auto asset_dest = pwallet->GetNewDestination(OutputType::BECH32, "");
        if (!asset_dest) {
            throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(asset_dest).original);
        }
        asset_script = GetScriptForDestination(*asset_dest);
        asset_dest_blindpub = pwallet->GetBlindingPubKey(GetScriptForDestination(*asset_dest));
    }
    if (nTokens > 0) {
        auto token_dest = pwallet->GetNewDestination(OutputType::BECH32, "");
        if (!token_dest) {
            throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(token_dest).original);
        }
        token_script = GetScriptForDestination(*token_dest);
        token_dest_blindpub = pwallet->GetBlindingPubKey(GetScriptForDestination(*token_dest));
    }

    CAsset dummyasset;
    IssuanceDetails issuance_details;
    issuance_details.blind_issuance = blind_issuances;
    issuance_details.contract_hash = contract_hash;
    CTransactionRef tx_ref = SendGenerationTransaction(asset_script, asset_dest_blindpub, token_script, token_dest_blindpub, nAmount, nTokens, &issuance_details, pwallet);

    // Calculate asset type, assumes first vin is used for issuance
    CAsset asset;
    CAsset token;
    CHECK_NONFATAL(!tx_ref->vin.empty());
    GenerateAssetEntropy(issuance_details.entropy, tx_ref->vin[0].prevout, issuance_details.contract_hash);
    CalculateAsset(asset, issuance_details.entropy);
    CalculateReissuanceToken(token, issuance_details.entropy, blind_issuances);

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("txid", tx_ref->GetHash().GetHex());
    ret.pushKV("vin", 0);
    ret.pushKV("entropy", issuance_details.entropy.GetHex());
    ret.pushKV("asset", asset.GetHex());
    ret.pushKV("token", token.GetHex());
    return ret;
},

    };
}

RPCHelpMan reissueasset()
{
    return RPCHelpMan{"reissueasset",
                "\nCreate more of an already issued asset. Must have reissuance token in wallet to do so. Reissuing does not affect your reissuance token balance, only asset.\n"
                "For more fine-grained control such as reissuing from a multi-signature address cold wallet, see `rawreissueasset` RPC call.\n",
                {
                    {"asset", RPCArg::Type::STR, RPCArg::Optional::NO, "The asset you want to re-issue. The corresponding token must be in your wallet."},
                    {"assetamount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount of additional asset to generate. Note that the amount is BTC-like, with 8 decimal places."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "txid", "transaction id for issuance"},
                        {RPCResult::Type::NUM, "vin", "input position of the issuance in the transaction"},
                    },
                },
                RPCExamples{
                    HelpExampleCli("reissueasset", "<asset> 0")
            + HelpExampleRpc("reissueasset", "<asset>, 0")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    LOCK(pwallet->cs_wallet);

    if (!g_con_elementsmode) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Issuance can only be done on elements-style chains. Note: `-regtest` is Bitcoin's regtest mode, instead try `-chain=<custom chain name>`");
    }

    std::string assetstr = request.params[0].get_str();
    CAsset asset = GetAssetFromString(assetstr);

    CAmount nAmount = AmountFromValue(request.params[1], false);
    if (nAmount <= 0) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Reissuance must create a non-zero amount.");
    }

    if (!pwallet->IsLocked()) {
        pwallet->TopUpKeyPool();
    }

    // Find the entropy and reissuance token in wallet
    IssuanceDetails issuance_details;
    issuance_details.reissuance_asset = asset;
    std::map<uint256, std::pair<CAsset, CAsset> > tokenMap = pwallet->GetReissuanceTokenTypes();
    for (const auto& it : tokenMap) {
        if (it.second.second == asset) {
            issuance_details.entropy = it.first;
            issuance_details.reissuance_token = it.second.first;
        }
        if (it.second.first == asset) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Asset given is a reissuance token type and can not be reissued.");
        }
    }
    if (issuance_details.reissuance_token.IsNull()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Asset reissuance token definition could not be found in wallet.");
    }

    // Add destination for the to-be-created asset
    bilingual_str error;
    auto asset_dest = pwallet->GetNewDestination(OutputType::BECH32, "");
    if (!asset_dest) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(asset_dest).original);
    }
    CPubKey asset_dest_blindpub = pwallet->GetBlindingPubKey(GetScriptForDestination(*asset_dest));

    // Add destination for tokens we are moving
    auto token_dest = pwallet->GetNewDestination(OutputType::BECH32, "");
    if (!token_dest) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(token_dest).original);
    }
    CPubKey token_dest_blindpub = pwallet->GetBlindingPubKey(GetScriptForDestination(*token_dest));

    // Attempt a send.
    CTransactionRef tx_ref = SendGenerationTransaction(GetScriptForDestination(*asset_dest), asset_dest_blindpub, GetScriptForDestination(*token_dest), token_dest_blindpub, nAmount, -1, &issuance_details, pwallet);
    CHECK_NONFATAL(!tx_ref->vin.empty());

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("txid", tx_ref->GetHash().GetHex());
    for (uint64_t i = 0; i < tx_ref->vin.size(); i++) {
        if (!tx_ref->vin[i].assetIssuance.IsNull()) {
            obj.pushKV("vin", i);
            break;
        }
    }

    return obj;
},
    };
}

RPCHelpMan listissuances()
{
    return RPCHelpMan{"listissuances",
                "\nList all issuances known to the wallet for the given asset, or for all issued assets if none provided.\n",
                {
                    {"asset", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "The asset whose issuances you wish to list. Accepts either the asset hex or the locally assigned asset label."},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "List of transaction issuances and information in wallet",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "txid", "Transaction id for issuance"},
                            {RPCResult::Type::STR_HEX, "entropy", "Entropy of the asset type"},
                            {RPCResult::Type::STR_HEX, "asset", "Asset type for issuance if known"},
                            {RPCResult::Type::STR, "assetlabel", /*optional=*/true, "Asset label for issuance if set"},
                            {RPCResult::Type::STR_HEX, "token", /*optional=*/true, "Token type for issuance"},
                            {RPCResult::Type::NUM, "vin", "The input position of the issuance in the transaction"},
                            {RPCResult::Type::STR_AMOUNT, "assetamount", "The amount of asset issued. Is -1 if blinded and unknown to wallet"},
                            {RPCResult::Type::STR_AMOUNT, "tokenamount", /*optional=*/true, "The reissuance token amount issued. Is -1 if blinded and unknown to wallet"},
                            {RPCResult::Type::BOOL, "isreissuance", "Whether this is a reissuance"},
                            {RPCResult::Type::STR_HEX, "assetblinds", "Blinding factor for asset amounts"},
                            {RPCResult::Type::STR_HEX, "tokenblinds", /*optional=*/true, "Blinding factor for token amounts"},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("listissuances", "<asset>")
            + HelpExampleRpc("listissuances", "<asset>")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    LOCK(pwallet->cs_wallet);

    std::string assetstr;
    CAsset asset_filter;
    if (!request.params[0].isNull()) {
        assetstr = request.params[0].get_str();
        asset_filter = GetAssetFromString(assetstr);
    }

    UniValue issuancelist(UniValue::VARR);
    for (const auto& it : pwallet->mapWallet) {
        const CWalletTx* pcoin = &it.second;
        CAsset asset;
        CAsset token;
        uint256 entropy;
        for (uint64_t vinIndex = 0; vinIndex < pcoin->tx->vin.size(); vinIndex++) {
            UniValue item(UniValue::VOBJ);
            const CAssetIssuance& issuance = pcoin->tx->vin[vinIndex].assetIssuance;
            if (issuance.IsNull()) {
                continue;
            }
            if (issuance.assetBlindingNonce.IsNull()) {
                GenerateAssetEntropy(entropy, pcoin->tx->vin[vinIndex].prevout, issuance.assetEntropy);
                CalculateAsset(asset, entropy);
                // Null is considered explicit
                CalculateReissuanceToken(token, entropy, issuance.nAmount.IsCommitment());
                item.pushKV("isreissuance", false);
                item.pushKV("token", token.GetHex());
                CAmount itamount = pcoin->GetIssuanceAmount(*pwallet, vinIndex, true);
                item.pushKV("tokenamount", (itamount == -1 ) ? -1 : ValueFromAmount(itamount));
                item.pushKV("tokenblinds", pcoin->GetIssuanceBlindingFactor(*pwallet, vinIndex, true).GetHex());
                item.pushKV("entropy", entropy.GetHex());
            } else {
                CalculateAsset(asset, issuance.assetEntropy);
                item.pushKV("isreissuance", true);
                item.pushKV("entropy", issuance.assetEntropy.GetHex());
            }
            item.pushKV("txid", pcoin->tx->GetHash().GetHex());
            item.pushKV("vin", vinIndex);
            item.pushKV("asset", asset.GetHex());
            const std::string label = gAssetsDir.GetLabel(asset);
            if (label != "") {
                item.pushKV("assetlabel", label);
            }
            CAmount iaamount = pcoin->GetIssuanceAmount(*pwallet, vinIndex, false);
            item.pushKV("assetamount", (iaamount == -1 ) ? -1 : ValueFromAmount(iaamount));
            item.pushKV("assetblinds", pcoin->GetIssuanceBlindingFactor(*pwallet, vinIndex, false).GetHex());
            if (!asset_filter.IsNull() && asset_filter != asset) {
                continue;
            }
            issuancelist.push_back(item);
        }
    }
    return issuancelist;
},
    };
}

RPCHelpMan destroyamount()
{
    return RPCHelpMan{"destroyamount",
                "\nDestroy an amount of a given asset.\n\n",
                {
                    {"asset", RPCArg::Type::STR, RPCArg::Optional::NO, "Hex asset id or asset label to destroy."},
                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount to destroy (8 decimals above the minimal unit)."},
                    {"comment", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "A comment used to store what the transaction is for.\n"
            "                             This is not part of the transaction, just kept in your wallet."},
                    {"verbose", RPCArg::Type::BOOL, RPCArg::Default{false}, "If true, return extra information about the transaction."},
                },
                {
                    RPCResult{"if verbose is not set or set to false",
                        RPCResult::Type::STR_HEX, "txid", "the transaction id",
                    },
                    RPCResult{"if verbose is set to true",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "txid", "the transaction id"},
                            {RPCResult::Type::STR, "fee_reason", "The transaction fee reason."},
                        },
                    },
                },
                RPCExamples{
                    HelpExampleCli("destroyamount", "\"bitcoin\" 100")
            + HelpExampleCli("destroyamount", "\"bitcoin\" 100 \"destroy assets\"")
            + HelpExampleRpc("destroyamount", "\"bitcoin\" 100 \"destroy assets\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    LOCK(pwallet->cs_wallet);

    std::string strasset = request.params[0].get_str();
    CAsset asset = GetAssetFromString(strasset);

    CAmount nAmount = AmountFromValue(request.params[1]);
    if (nAmount <= 0) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount to destroy");
    }

    mapValue_t mapValue;
    if (request.params.size() > 2 && !request.params[2].isNull() && !request.params[2].get_str().empty()) {
        mapValue["comment"] = request.params[2].get_str();
    }

    EnsureWalletIsUnlocked(*pwallet);

    bool verbose = request.params[3].isNull() ? false : request.params[3].get_bool();
    NullData nulldata;
    CTxDestination address(nulldata);
    std::vector<CRecipient> recipients;
    CRecipient recipient = {address, nAmount, asset, CPubKey(), false /* subtract_fee */};
    recipients.push_back(recipient);
    CCoinControl no_coin_control; // This is a deprecated API
    return SendMoney(*pwallet, no_coin_control, recipients, std::move(mapValue), verbose, true /* ignore_blind_fail */);
},
    };
}

// Only used for functionary integration tests
RPCHelpMan generatepegoutproof()
{
    return RPCHelpMan{"generatepegoutproof",
                "\nONLY FOR TESTING: Generates pegout authorization proof for pegout based on the summed privkey and returns in hex. Result should be passed as an argument in `sendtomainchain`. Caution: Whitelist proof-validating mempools will filter incorrect pegoutproofs but aren't consensus enforced!\n",
                {
                    {"sumkey", RPCArg::Type::STR, RPCArg::Optional::NO, "Base58 summed key of Bitcoin and offline key"},
                    {"btcpubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex pegout destination Bitcoin pubkey"},
                    {"onlinepubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "hex `online pubkey`"},
                },
                RPCResult{
                    RPCResult::Type::STR_HEX, "pegoutproof", "pegout authorization proof to be passed into sendtomainchain",
                },
                RPCExamples{
                    HelpExampleCli("generatepegoutproof", "\"cQtNrRngdc4RJ9CkuTVKVLyxPFsijiTJySob24xCdKXGohdFhXML\" \"02c611095119e3dc96db428a0e190a3e142237bcd2efa4fb358257497885af3ab6\" \"0390695fff5535780df1e04c1f6c10e7c0a399fa56cfce34bf8108d0a9bc7a437b\"")
            + HelpExampleRpc("generatepegoutproof", "\"cQtNrRngdc4RJ9CkuTVKVLyxPFsijiTJySob24xCdKXGohdFhXML\" \"02c611095119e3dc96db428a0e190a3e142237bcd2efa4fb358257497885af3ab6\" \"0390695fff5535780df1e04c1f6c10e7c0a399fa56cfce34bf8108d0a9bc7a437b\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    LOCK(pwallet->cs_wallet);

    if (!IsHex(request.params[1].get_str()))
        throw JSONRPCError(RPC_TYPE_ERROR, "btcpubkey must be hex string");
    if (!IsHex(request.params[2].get_str()))
        throw JSONRPCError(RPC_TYPE_ERROR, "onlinepubkey must be hex string");

    //Parse private keys

    CKey summedSecret = DecodeSecret(request.params[0].get_str());
    if (!summedSecret.IsValid()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid summed private key encoding");
    }

    std::vector<unsigned char> sumprivkeybytes(UCharCast(summedSecret.begin()), UCharCast(summedSecret.end()));
    std::vector<unsigned char> btcpubkeybytes = ParseHex(request.params[1].get_str());
    std::vector<unsigned char> onlinepubkeybytes = ParseHex(request.params[2].get_str());

    //Parse onlinepubkey
    CPubKey onlinepubkey;
    onlinepubkey.Set(onlinepubkeybytes.begin(), onlinepubkeybytes.end());
    if (!onlinepubkey.IsFullyValid())
        throw JSONRPCError(RPC_WALLET_ERROR, "Invalid online pubkey");
    secp256k1_pubkey onlinepubkey_secp;
    if (!secp256k1_ec_pubkey_parse(secp256k1_ctx, &onlinepubkey_secp, &onlinepubkeybytes[0], onlinepubkeybytes.size()))
        throw JSONRPCError(RPC_WALLET_ERROR, "Invalid online pubkey");

    CPAKList paklist = GetActivePAKList(pwallet->chain().getTip(), Params().GetConsensus());
    if (paklist.IsReject()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Pegout freeze is under effect to aid a pak transition to a new list. Please consult the network operator.");
    }

    LegacyScriptPubKeyMan* spk_man = pwallet->GetLegacyScriptPubKeyMan();
    if (!spk_man) {
        throw JSONRPCError(RPC_WALLET_ERROR, "This type of wallet does not support this command");
    }

    //Find PAK online pubkey on PAK list
    int whitelistindex=-1;
    std::vector<secp256k1_pubkey> pak_online = paklist.OnlineKeys();
    for (unsigned int i=0; i<pak_online.size(); i++) {
        if (!memcmp((void *)&pak_online[i], (void *)&onlinepubkey_secp, sizeof(secp256k1_pubkey)))
            whitelistindex = i;
    }
    if (whitelistindex == -1)
        throw JSONRPCError(RPC_WALLET_ERROR, "Given online key is not in Pegout Authorization Key List");

    CKey masterOnlineKey;
    if (!spk_man->GetKey(onlinepubkey.GetID(), masterOnlineKey))
        throw JSONRPCError(RPC_WALLET_ERROR, "Given online key is in master set but not in wallet");

    //Parse own offline pubkey
    secp256k1_pubkey btcpubkey;
    if (secp256k1_ec_pubkey_parse(secp256k1_ctx, &btcpubkey, &btcpubkeybytes[0], btcpubkeybytes.size()) != 1)
        throw JSONRPCError(RPC_WALLET_ERROR, "btcpubkey is invalid pubkey");

    //Create, verify whitelist proof
    secp256k1_whitelist_signature sig;
    if(secp256k1_whitelist_sign(secp256k1_ctx, &sig, &paklist.OnlineKeys()[0], &paklist.OfflineKeys()[0], paklist.size(), &btcpubkey, UCharCast(masterOnlineKey.begin()), &sumprivkeybytes[0], whitelistindex) != 1)
        throw JSONRPCError(RPC_WALLET_ERROR, "Pegout authorization proof signing failed");

    if (secp256k1_whitelist_verify(secp256k1_ctx, &sig, &paklist.OnlineKeys()[0], &paklist.OfflineKeys()[0], paklist.size(), &btcpubkey) != 1)
        throw JSONRPCError(RPC_WALLET_ERROR, "Pegout authorization proof was created and signed but is invalid");

    //Serialize and return as hex
    size_t expectedOutputSize = 1 + 32 * (1 + paklist.size());
    const size_t preSize = expectedOutputSize;
    CHECK_NONFATAL(1 + 32 * (1 + 256) >= expectedOutputSize);
    unsigned char output[1 + 32 * (1 + 256)];
    secp256k1_whitelist_signature_serialize(secp256k1_ctx, output, &expectedOutputSize, &sig);
    CHECK_NONFATAL(expectedOutputSize == preSize);
    std::vector<unsigned char> voutput(output, output + expectedOutputSize / sizeof(output[0]));

    return HexStr(MakeByteSpan(voutput));
},
    };
}

// Only used for functionary integration tests
RPCHelpMan getpegoutkeys()
{
    return RPCHelpMan{"getpegoutkeys",
                "\n(DEPRECATED) Please see `initpegoutwallet` and `sendtomainchain` for best-supported and easiest workflow. This call is for the Liquid network participants' `offline` wallet ONLY. Returns `sumkeys` corresponding to the sum of the Offline PAK and the imported Bitcoin key. The wallet must have the Offline private PAK to succeed. The output will be used in `generatepegoutproof` and `sendtomainchain`. Care is required to keep the bitcoin private key, as well as the `sumkey` safe, as a leak of both results in the leak of your `offlinekey`. Therefore it is recommended to create Bitcoin keys and do Bitcoin transaction signing directly on an offline wallet co-located with your offline Liquid wallet.\n",
                {
                    {"btcprivkey", RPCArg::Type::STR, RPCArg::Optional::NO, "Base58 Bitcoin private key that will be combined with the offline privkey"},
                    {"offlinepubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "33-byte compressed public key encoded as 66 hex characters, to combine with btcprivkey. Primarily intended for integration testing."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "sumkey", "Base58-encoded sum key"},
                        {RPCResult::Type::STR_HEX, "btcpubkey", "the bitcoin pubkey that corresponds to the pegout destination Bitcoin address"},
                        {RPCResult::Type::STR, "btcaddress", "Destination Bitcoin address for the funds being pegged out using these keys"},
                    },
                },
                RPCExamples{
                    HelpExampleCli("getpegoutkeys", "\"5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF\" \"0389275d512326f7016e014d8625f709c01f23bd0dc16522bf9845a9ee1ef6cbf9\"")
            + HelpExampleRpc("getpegoutkeys", "\"5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF\", \"0389275d512326f7016e014d8625f709c01f23bd0dc16522bf9845a9ee1ef6cbf9\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    LOCK(pwallet->cs_wallet);

    LegacyScriptPubKeyMan* spk_man = pwallet->GetLegacyScriptPubKeyMan();
    if (!spk_man) {
        throw JSONRPCError(RPC_WALLET_ERROR, "This type of wallet does not support this command");
    }

    if (!request.params[1].isStr() || !IsHex(request.params[1].get_str()) || request.params[1].get_str().size() != 66) {
        throw JSONRPCError(RPC_TYPE_ERROR, "offlinepubkey must be hex string of size 66");
    }

    std::vector<unsigned char> offlinepubbytes = ParseHex(request.params[1].get_str());
    CPubKey offline_pub = CPubKey(offlinepubbytes.begin(), offlinepubbytes.end());

    if (!offline_pub.IsFullyValid()) {
        throw JSONRPCError(RPC_TYPE_ERROR, "offlinepubkey is not a valid pubkey");
    }

    CKey pegoutkey;
    if (!spk_man->GetKey(offline_pub.GetID(), pegoutkey))
        throw JSONRPCError(RPC_WALLET_ERROR, "Offline key can not be found in wallet");

    CKey bitcoinkey = DecodeSecret(request.params[0].get_str());
    if (!bitcoinkey.IsValid()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Private key outside allowed range");
    }

    CPubKey bitcoinpubkey = bitcoinkey.GetPubKey();
    CHECK_NONFATAL(bitcoinkey.VerifyPubKey(bitcoinpubkey));

    std::vector<unsigned char> pegoutkeybytes(UCharCast(pegoutkey.begin()), UCharCast(pegoutkey.end()));
    std::vector<unsigned char> pegoutsubkeybytes(UCharCast(bitcoinkey.begin()), UCharCast(bitcoinkey.end()));

    if (!secp256k1_ec_seckey_tweak_add(secp256k1_ctx, &pegoutkeybytes[0], &pegoutsubkeybytes[0]))
        throw JSONRPCError(RPC_WALLET_ERROR, "Summed key invalid");

    CKey sumseckey;
    sumseckey.Set(pegoutkeybytes.begin(), pegoutkeybytes.end(), true);

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("sumkey", EncodeSecret(sumseckey));
    ret.pushKV("btcpubkey", HexStr(bitcoinpubkey));
    ret.pushKV("btcaddress", EncodeParentDestination(PKHash(bitcoinpubkey.GetID())));

    return ret;
},
    };
}

// END ELEMENTS commands
//
} // namespace wallet
