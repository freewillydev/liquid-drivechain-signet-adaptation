// Copyright (c) 2017-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pegins.h>
#include <limits>
#include <span>

#include <addresstype.h>
#include <arith_uint256.h>
#include <block_proof.h>
#include <chainparams.h>
#include <crypto/hmac_sha256.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <key_io.h>
#include <mainchainrpc.h>
#include <haskell/bridge.h>
#include <haskell/resource_constants.h>
#include <merkleblock.h>
#include <pow.h>
#include <primitives/transaction.h>
#include <primitives/bitcoin/merkleblock.h>
#include <secp256k1.h>
#include <script/interpreter.h>
#include <streams.h>
#include <util/moneystr.h>
#include <dynafed.h>

//
// ELEMENTS
//

#include <validation.h>

namespace {
static secp256k1_context* secp256k1_ctx_validation;

class Secp256k1Ctx
{
public:
    Secp256k1Ctx() {
        assert(secp256k1_ctx_validation == nullptr);
        secp256k1_ctx_validation = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
        assert(secp256k1_ctx_validation != nullptr);
    }

    ~Secp256k1Ctx() {
        assert(secp256k1_ctx_validation != nullptr);
        secp256k1_context_destroy(secp256k1_ctx_validation);
        secp256k1_ctx_validation = nullptr;
    }
};
static Secp256k1Ctx instance_of_secp256k1ctx;

static const std::vector<unsigned char> DRIVECHAIN_DEPOSIT_MARKER(
    std::begin(ElementsDrivechainIdentity::DEPOSIT_MARKER), std::end(ElementsDrivechainIdentity::DEPOSIT_MARKER));
static const std::vector<unsigned char> ECX_LEGACY_DEPOSIT_MARKER(
    std::begin(ElementsDrivechainIdentity::LEGACY_DEPOSIT_MARKER), std::end(ElementsDrivechainIdentity::LEGACY_DEPOSIT_MARKER));

template <typename T>
static bool DeserializeExactly(const std::vector<unsigned char>& bytes, T& value)
{
    try {
        DataStream stream(bytes);
        stream >> TX_WITH_WITNESS(value);
        return stream.empty();
    } catch (...) {
        return false;
    }
}

template <typename T>
static std::vector<unsigned char> SerializeEvidenceField(const T& value)
{
    DataStream stream;
    stream << TX_WITH_WITNESS(value);
    return std::vector<unsigned char>(
        UCharCast(stream.data()),
        UCharCast(stream.data()) + stream.size());
}

static int32_t HashDepositTransaction(const unsigned char* bytes, uint32_t size, unsigned char* hash)
{
    try {
        Sidechain::Bitcoin::CMutableTransaction tx;
        DataStream stream{Span<const unsigned char>{bytes, size}};
        stream >> TX_WITH_WITNESS(tx);
        if (!stream.empty()) return 0;
        const uint256 txid = tx.GetHash();
        std::copy(txid.begin(), txid.end(), hash);
        return 1;
    } catch (...) { return 0; }
}

static bool ReadPeginWitnessPrefix(const CScriptWitness& pegin_witness, CAmount& value, CAsset& asset, uint256& genesis_hash, CScript& claim_script, std::string& err_msg)
{
    const auto& stack = pegin_witness.stack;
    if (stack.size() < 4) {
        err_msg = "Not enough stack items.";
        return false;
    }

    DataStream stream(stack[0]);
    try {
        stream >> value;
    } catch (...) {
        err_msg = "Could not deserialize value.";
        return false;
    }

    if (!MoneyRange(value)) {
        err_msg = "Value was not in valid value range.";
        return false;
    }

    if (stack[1].size() != 32) {
        err_msg = "Asset type was not 32 bytes.";
        return false;
    }
    asset = CAsset(stack[1]);

    if (stack[2].size() != 32) {
        err_msg = "Parent genesis blockhash was not 32 bytes.";
        return false;
    }
    genesis_hash = uint256(stack[2]);

    claim_script = CScript(stack[3].begin(), stack[3].end());
    if (claim_script.size() > 100) {
        err_msg = "Claim script is too large.";
        return false;
    }

    return true;
}
}

bool GetAmountFromParentChainPegin(CAmount& amount, const Sidechain::Bitcoin::CTransaction& txBTC, unsigned int nOut)
{
    amount = txBTC.vout[nOut].nValue;
    return true;
}

bool GetAmountFromParentChainPegin(CAmount& amount, const CTransaction& txBTC, unsigned int nOut)
{
    if (!txBTC.vout[nOut].nValue.IsExplicit()) {
        return false;
    }
    if (!txBTC.vout[nOut].nAsset.IsExplicit()) {
        return false;
    }
    if (txBTC.vout[nOut].nAsset.GetAsset() != Params().GetConsensus().parent_pegged_asset) {
        return false;
    }
    amount = txBTC.vout[nOut].nValue.GetAmount();
    return true;
}

// Takes federation redeem script and adds HMAC_SHA256(pubkey, scriptPubKey) as a tweak to each pubkey
CScript calculate_contract(const CScript& federation_script, const CScript& scriptPubKey) {
    CScript scriptDestination;

    bool is_liquidv1_watchman = MatchLiquidWatchman(federation_script);

    CScript::const_iterator sdpc = federation_script.begin();
    std::vector<unsigned char> vch;
    opcodetype opcodeTmp;
    bool liquid_op_else_found = false;
    while (federation_script.GetOp(sdpc, opcodeTmp, vch))
    {

        // For liquidv1 initial watchman template, don't tweak emergency keys
        if (is_liquidv1_watchman && opcodeTmp == OP_ELSE) {
            liquid_op_else_found = true;
        }

        size_t pub_len = 33;
        if (vch.size() == pub_len && !liquid_op_else_found)
        {
            unsigned char tweak[32];
            CHMAC_SHA256(vch.data(), pub_len).Write(scriptPubKey.data(), scriptPubKey.size()).Finalize(tweak);
            int ret;
            secp256k1_pubkey watchman;
            secp256k1_pubkey tweaked;
            ret = secp256k1_ec_pubkey_parse(secp256k1_ctx_validation, &watchman, vch.data(), pub_len);
            assert(ret == 1);
            ret = secp256k1_ec_pubkey_parse(secp256k1_ctx_validation, &tweaked, vch.data(), pub_len);
            assert(ret == 1);
            // If someone creates a tweak that makes this fail, they broke SHA256
            ret = secp256k1_ec_pubkey_tweak_add(secp256k1_ctx_validation, &tweaked, tweak);
            assert(ret == 1);
            unsigned char new_pub[33];
            ret = secp256k1_ec_pubkey_serialize(secp256k1_ctx_validation, new_pub, &pub_len, &tweaked, SECP256K1_EC_COMPRESSED);
            assert(ret == 1);
            assert(pub_len == 33);

            // push tweaked pubkey
            std::vector<unsigned char> pub_vec(new_pub, new_pub + pub_len);
            scriptDestination << pub_vec;

            // Sanity checks to reduce pegin risk. If the tweaked
            // value flips a bit, we may lose pegin funds irretrievably.
            // We take the tweak, derive its pubkey and check that
            // `tweaked - watchman = tweak` to check the computation
            // two different ways
            secp256k1_pubkey tweaked2;
            ret = secp256k1_ec_pubkey_create(secp256k1_ctx_validation, &tweaked2, tweak);
            assert(ret);
            ret = secp256k1_ec_pubkey_negate(secp256k1_ctx_validation, &watchman);
            assert(ret);
            secp256k1_pubkey* pubkey_combined[2];
            pubkey_combined[0] = &watchman;
            pubkey_combined[1] = &tweaked;
            secp256k1_pubkey maybe_tweaked2;
            ret = secp256k1_ec_pubkey_combine(secp256k1_ctx_validation, &maybe_tweaked2, pubkey_combined, 2);
            assert(ret);
            assert(!memcmp(&maybe_tweaked2, &tweaked2, 64));
        } else {
            // add to script untouched
            if (vch.size() > 0) {
                scriptDestination << vch;
            } else {
                scriptDestination << opcodeTmp;
            }
        }
    }

    return scriptDestination;
}

template<typename T>
static bool CheckPeginTx(const std::vector<unsigned char>& tx_data, T& pegtx, const COutPoint& prevout, const CAmount claim_amount, const CScript& claim_script, const std::vector<std::pair<CScript, CScript>>& fedpegscripts)
{
    try {
        DataStream pegtx_stream(tx_data);
        pegtx_stream >> TX_WITH_WITNESS(pegtx);
        if (!pegtx_stream.empty()) {
            return false;
        }
    } catch (std::exception&) {
        // Invalid encoding of transaction
        return false;
    }

    // Check that transaction matches txid
    if (pegtx->GetHash() != prevout.hash) {
        return false;
    }

    if (prevout.n >= pegtx->vout.size()) {
        return false;
    }
    CAmount amount = 0;
    if (!GetAmountFromParentChainPegin(amount, *pegtx, prevout.n)) {
        return false;
    }
    // Check the transaction nout/value matches
    if (claim_amount != amount) {
        return false;
    }

    // Check that the witness program matches the p2ch on the (p2sh-)p2wsh
    // transaction output. We support multiple scripts as a grace period for peg-in users
    for (const auto& scripts : fedpegscripts) {
        int fedpeg_version = 0;
        std::vector<unsigned char> fedpeg_program;
        scripts.first.IsWitnessProgram(fedpeg_version, fedpeg_program);
        // We immediately return true if any fedpegscripts are unencumbered
        // by currently-known parent chain segwit versions.
        // TODO: Refactor for future versionbits deployment of parent-segwit version
        if (fedpeg_version > 0) {
            return true;
        }
        CScript tweaked_fedpegscript = calculate_contract(scripts.second, claim_script);
        CScript expected_script(GetScriptForDestination(WitnessV0ScriptHash(tweaked_fedpegscript)));
        if (scripts.first.IsPayToScriptHash()) {
            expected_script = GetScriptForDestination(ScriptHash(expected_script));
        }
        if (pegtx->vout[prevout.n].scriptPubKey == expected_script) {
            return true;
        }
    }
    return false;
}

template<typename T>
static bool GetBlockAndTxFromMerkleBlock(uint256& block_hash, uint256& tx_hash, unsigned int& tx_index, T& merkle_block, const std::vector<unsigned char>& merkle_block_raw)
{
    try {
        std::vector<uint256> tx_hashes;
        std::vector<unsigned int> tx_indices;
        DataStream merkle_block_stream{merkle_block_raw};
        merkle_block_stream >> TX_NO_WITNESS(merkle_block);
        block_hash = merkle_block.header.GetHash();

        if (!merkle_block_stream.empty()) {
           return false;
        }
        if (merkle_block.txn.ExtractMatches(tx_hashes, tx_indices) != merkle_block.header.hashMerkleRoot || tx_hashes.size() != 1) {
            return false;
        }
        tx_hash = tx_hashes[0];
        tx_index = tx_indices[0];
    } catch (std::exception&) {
        // Invalid encoding of merkle block
        return false;
    }
    return true;
}

bool CheckParentProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.parentChainPowLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}

static bool CheckFederatedPegin(const std::vector<std::vector<unsigned char>>& stack,
    const std::vector<std::pair<CScript, CScript>>& fedpegscripts, const COutPoint& prevout,
    CAmount value, const CAsset& asset, const uint256& gen_hash, const CScript& claim_script,
    std::string& err_msg, bool check_depth, bool* depth_failed)
{
    // 0) Return false if !consensus.has_parent_chain
    if (!Params().GetConsensus().has_parent_chain) {
        err_msg = "Parent chain is not enabled on this network.";
        return false;
    }

    uint256 block_hash;
    uint256 tx_hash;
    int num_txs;
    unsigned int tx_index = 0;
    // Get txout proof
    if (Params().GetConsensus().ParentChainHasPow()) {
        Sidechain::Bitcoin::CMerkleBlock merkle_block_pow;
        if (!GetBlockAndTxFromMerkleBlock(block_hash, tx_hash, tx_index, merkle_block_pow, stack[5])) {
            err_msg = "Could not extract block and tx from merkleblock.";
            return false;
        }
        if (!CheckParentProofOfWork(block_hash, merkle_block_pow.header.nBits, Params().GetConsensus())) {
            err_msg = "Parent proof of work is invalid or insufficient.";
            return false;
        }

        Sidechain::Bitcoin::CTransactionRef pegtx;
        if (!CheckPeginTx(stack[4], pegtx, prevout, value, claim_script, fedpegscripts)) {
            err_msg = "Peg-in tx is invalid.";
            return false;
        }

        num_txs = merkle_block_pow.txn.GetNumTransactions();
    } else {
        CMerkleBlock merkle_block;
        if (!GetBlockAndTxFromMerkleBlock(block_hash, tx_hash, tx_index, merkle_block, stack[5])) {
            err_msg = "Could not extract block and tx from merkleblock.";
            return false;
        }

        if (!CheckProofSignedParent(merkle_block.header, Params().GetConsensus())) {
            err_msg = "Parent signed block is invalid.";
            return false;
        }

        CTransactionRef pegtx;
        if (!CheckPeginTx(stack[4], pegtx, prevout, value, claim_script, fedpegscripts)) {
            err_msg = "Peg-in tx is invalid.";
            return false;
        }

        num_txs = merkle_block.txn.GetNumTransactions();
    }

    // Check that the merkle proof corresponds to the txid
    if (prevout.hash != tx_hash) {
        err_msg = "Merkle proof and txid mismatch.";
        return false;
    }

    // Check the genesis block corresponds to a valid peg (only one for now)
    if (gen_hash != Params().ParentGenesisBlockHash()) {
        err_msg = "Parent genesis block mismatch.";
        return false;
    }

    // Check the asset type corresponds to a valid pegged asset (only one for now)
    if (asset != Params().GetConsensus().pegged_asset) {
        return false;
    }

    // Finally, validate peg-in via rpc call
    if (check_depth && gArgs.GetBoolArg("-validatepegin", Params().GetConsensus().has_parent_chain)) {
        unsigned int required_depth = Params().GetConsensus().pegin_min_depth;
        // Don't allow coinbase output claims before coinbase maturity
        if (tx_index == 0) {
            required_depth = std::max(required_depth, (unsigned int)COINBASE_MATURITY);
        }
        if (!IsConfirmedBitcoinBlock(block_hash, required_depth, num_txs)) {
            err_msg = "Needs more confirmations.";
            if (depth_failed) {
                *depth_failed = true;
            }
            return false;
        }
    }
    return true;
}

bool IsValidPeginWitness(const CScriptWitness& pegin_witness,
                         const std::vector<std::pair<CScript, CScript>>& fedpegscripts,
                         const COutPoint& prevout,
                         std::string& err_msg,
                         bool check_depth,
                         bool* depth_failed,
                         bool* parent_unavailable,
                         const int child_height) {
    if (depth_failed) {
        *depth_failed = false;
    }
    if (parent_unavailable) {
        *parent_unavailable = false;
    }

    const auto& items = pegin_witness.stack;
    const auto routing = drivechain::haskell::SelectDepositRoute(items.size(),
        items.size() >= 5 && items[4] == ECX_LEGACY_DEPOSIT_MARKER,
        items.size() >= 5 && items[4] == DRIVECHAIN_DEPOSIT_MARKER,
        Params().GetConsensus().drivechain_slot.has_value());
    const auto route = routing.route;
    if (route == drivechain::haskell::DepositRoute::REJECT_ECX) {
        err_msg = "ECX deposit evidence is not a native Alpha CTIP witness.";
        return false;
    }

    // Format on stack is as follows:
    // 1) value - the value of the pegin output
    // 2) asset type - the asset type being pegged in
    // 3) genesis blockhash - genesis block of the parent chain
    // 4) claim script - script to be evaluated for spend authorization
    // 5) serialized transaction - serialized bitcoin transaction
    // 6) txout proof - merkle proof connecting transaction to header
    //
    // First 4 values(plus prevout) are enough to validate a peg-in without any internal knowledge
    // of Bitcoin serialization. This is useful for further abstraction by outsourcing
    // the other validity checks to RPC calls.

    const std::vector<std::vector<unsigned char> >& stack = pegin_witness.stack;
    const bool is_drivechain_deposit = route == drivechain::haskell::DepositRoute::NATIVE;
    const size_t expected_stack_size = routing.expected_stack_size;
    if (stack.size() != expected_stack_size) {
        err_msg = strprintf("Peg-in witness has %u stack items; expected %u.", stack.size(), expected_stack_size);
        return false;
    }

    CAmount value;
    CAsset asset;
    uint256 gen_hash;
    CScript claim_script;
    if (!ReadPeginWitnessPrefix(pegin_witness, value, asset, gen_hash, claim_script, err_msg)) return false;

    if (route == drivechain::haskell::DepositRoute::ECX) {
        const bool valid = IsDrivechainDepositPeginWitness(pegin_witness, prevout, nullptr, nullptr);
        if (!valid) err_msg = "Invalid drivechain deposit pegin witness.";
        return valid;
    }

    // Drivechain deposits are anchored by the bridge/two-way-peg data instead of
    // the legacy Elements parent-chain merkle proof, so recognize this marker
    // before applying the legacy parent-chain-enabled guard below.
    if (is_drivechain_deposit) {
        const auto& drivechain_slot = Params().GetConsensus().drivechain_slot;
        uint256 mainchain_block_hash;
        std::vector<unsigned char> address;
        std::string deposit_error;
        DrivechainDepositStatus deposit_status{};
        static const char* errors[]{"", "Drivechain deposits are not enabled on this network.",
            "Invalid drivechain deposit pegin witness.", "Parent genesis block mismatch.",
            "Pegin asset is not the pegged asset.", "Drivechain deposit claim script must be OP_TRUE."};
        const auto result = drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::NATIVE_DEPOSIT_ADMISSION,
            [&](uint32_t step) -> uint32_t {
                switch (step) {
                case 1: return drivechain_slot.has_value();
                case 2: return IsDrivechainDepositPeginWitness(pegin_witness, prevout, nullptr, nullptr, &mainchain_block_hash, &address);
                case 3: return gen_hash == Params().ParentGenesisBlockHash();
                case 4: return asset == Params().GetConsensus().pegged_asset;
                case 5: return claim_script == (CScript() << OP_TRUE);
                case 6:
                    deposit_status = GetConfirmedDrivechainDepositStatus(mainchain_block_hash, *drivechain_slot,
                        prevout, value, address, &deposit_error, child_height);
                    return deposit_status == DrivechainDepositStatus::VALID;
                case 7: return deposit_status == DrivechainDepositStatus::UNAVAILABLE;
                case 8: if (parent_unavailable) *parent_unavailable = true; return 0;
                case 9: case 10: case 11: case 12: case 13: err_msg = errors[step - 8]; return 0;
                case 14: err_msg = strprintf("BIP300 deposit is not confirmed on the mainchain: %s", deposit_error); return 0;
                default: throw std::runtime_error("Unknown native deposit admission step");
                }
            });
        if (result > 1) throw std::runtime_error("Invalid native deposit admission result");
        return result == 0;
    }

    // A slot-assigned Drivechain uses only native CTIP deposits. Accepting a
    // legacy federated pegin on the same network would create a second minting
    // path for the identical pegged asset, outside the BIP300 treasury delta
    // and duplicate-claim domain.
    if (route == drivechain::haskell::DepositRoute::REJECT_FEDERATED) {
        err_msg = "Legacy federated peg-ins are disabled on a Drivechain network.";
        return false;
    }

    return CheckFederatedPegin(stack, fedpegscripts, prevout, value, asset, gen_hash,
                               claim_script, err_msg, check_depth, depth_failed);
}

int32_t DepositWitnessKind(const CScriptWitness& witness, const COutPoint& prevout,
                          uint32_t mode, CAmount& value)
{
    return drivechain::haskell::DepositWitness(witness.stack, mode,
        Params().GetConsensus().pegged_asset.begin(), Params().ParentGenesisBlockHash().begin(),
        prevout.hash.ToUint256().begin(), HashDepositTransaction, value);
}

bool IsDrivechainDepositPeginWitness(const CScriptWitness& pegin_witness,
                                     const COutPoint& prevout,
                                     CAmount* out_value,
                                     CScript* out_claim_script,
                                     uint256* out_mainchain_block_hash,
                                     std::vector<unsigned char>* out_address)
{
    const auto& stack = pegin_witness.stack;
    CAmount value;
    if (!DepositWitnessKind(pegin_witness, prevout, out_mainchain_block_hash || out_address ? 2 : 0, value)) return false;
    if (out_value != nullptr) *out_value = value;
    if (out_claim_script != nullptr) *out_claim_script = CScript(stack[3].begin(), stack[3].end());
    if (out_mainchain_block_hash != nullptr) *out_mainchain_block_hash = uint256(stack[6]);
    if (out_address != nullptr) *out_address = stack[7];
    return true;
}

bool DecodeDrivechainDepositDestination(const std::string& payload, CScript& recipient, CAmount& fee)
{
    recipient.clear();
    fee = 0;
    if (payload.empty() || payload.size() > 128) return false;
    std::string address = payload;
    CAmount committed_fee{0};
    if (payload.starts_with("dcfee1:")) {
        const auto separator = payload.find(':', 7);
        if (separator == std::string::npos) return false;
        const auto encoded_fee = payload.substr(7, separator - 7);
        if (!ParseInt64(encoded_fee, &committed_fee) || !MoneyRange(committed_fee) ||
            committed_fee == 0 || std::to_string(committed_fee) != encoded_fee) return false;
        address = payload.substr(separator + 1);
    }
    const auto destination = DecodeDestination(address);
    if (!IsValidDestination(destination)) return false;
    recipient = GetScriptForDestination(destination);
    fee = committed_fee;
    return true;
}

std::string EncodeDrivechainDepositDestination(const std::string& address, CAmount fee)
{
    if (!IsValidDestination(DecodeDestination(address)) || !MoneyRange(fee))
        throw std::invalid_argument("invalid drivechain deposit address or fee");
    const std::string payload = fee ? "dcfee1:" + std::to_string(fee) + ":" + address : address;
    if (payload.size() > 128) throw std::invalid_argument("drivechain deposit destination exceeds 128 bytes");
    return payload;
}

CTransactionRef CreateNativeDrivechainDeposit(const DrivechainMintableDeposit& deposit)
{
    CScript recipient;
    CAmount fee{0};
    if (!DecodeDrivechainDepositDestination(std::string(deposit.address.begin(), deposit.address.end()), recipient, fee) ||
        !MoneyRange(deposit.value) || deposit.value <= fee)
        throw std::invalid_argument("invalid native deposit destination or value");
    CMutableTransaction tx;
    const COutPoint outpoint(Txid::FromUint256(deposit.outpoint.hash), deposit.outpoint.n);
    tx.vin.emplace_back(outpoint);
    tx.vin[0].m_is_pegin = true;
    tx.vout.emplace_back(Params().GetConsensus().pegged_asset, deposit.value - fee, recipient);
    if (fee) tx.vout.emplace_back(Params().GetConsensus().pegged_asset, fee, CScript());
    tx.witness.vtxinwit.resize(1);
    tx.witness.vtxoutwit.resize(tx.vout.size());
    tx.witness.vtxinwit[0].m_pegin_witness = CreateDrivechainDepositPeginWitness(
        deposit.value, Params().GetConsensus().pegged_asset, Params().ParentGenesisBlockHash(),
        CScript() << OP_TRUE, outpoint, deposit.block_hash, deposit.address);
    return MakeTransactionRef(std::move(tx));
}

bool CheckDrivechainDepositOutputs(const CTransaction& tx, const unsigned int pegin_index, std::string& err_msg)
{
    if (pegin_index >= tx.vin.size() || pegin_index >= tx.witness.vtxinwit.size()) {
        err_msg = "Drivechain deposit input or witness index is out of range.";
        return false;
    }
    std::vector<unsigned char> inputs, outputs;
    std::vector<int64_t> amounts;
    for (unsigned int i = 0; i < tx.vin.size(); ++i) {
        const bool recognized = i < tx.witness.vtxinwit.size() &&
            IsDrivechainDepositPeginWitness(tx.witness.vtxinwit[i].m_pegin_witness, tx.vin[i].prevout);
        inputs.push_back(recognized | (tx.vin[i].m_is_pegin << 1));
    }

    CAmount deposit_value{0};
    CScript claim_script;
    std::vector<unsigned char> address_bytes;
    const bool native = IsDrivechainDepositPeginWitness(tx.witness.vtxinwit[pegin_index].m_pegin_witness,
        tx.vin[pegin_index].prevout, &deposit_value, &claim_script, nullptr, &address_bytes);
    const std::string address(address_bytes.begin(), address_bytes.end());
    CScript expected_script;
    CAmount committed_fee{0};
    const bool valid_destination = DecodeDrivechainDepositDestination(address, expected_script, committed_fee);
    for (const CTxOut& output : tx.vout) {
        outputs.push_back((output.scriptPubKey == expected_script) |
            ((output.nAsset.IsExplicit() && output.nAsset.GetAsset() == Params().GetConsensus().pegged_asset) << 1) |
            (output.nValue.IsExplicit() << 2) | (output.nNonce.IsCommitment() << 3));
        amounts.push_back(output.nValue.IsExplicit() ? output.nValue.GetAmount() : 0);
    }
    const uint32_t facts = !tx.vin[pegin_index].assetIssuance.IsNull() | (native << 1) |
        ((claim_script == (CScript() << OP_TRUE)) << 2) | (valid_destination << 3);
    if (committed_fee > 0 && committed_fee >= deposit_value) {
        err_msg = "Committed Elements fee must be less than the authenticated deposit value.";
        return false;
    }
    if (!drivechain::haskell::DepositOutputs(facts, deposit_value - committed_fee, inputs, outputs, amounts, err_msg)) return false;
    if (!committed_fee) return true;

    // Reuse the existing exact one-credit/one-fee Haskell validator. The first
    // check fixes the net credit; conservation then fixes the fee to the L1
    // commitment. No sponsor inputs, redirected change or extra outputs exist.
    std::array<unsigned char, 2> flags{};
    std::array<int64_t, 2> values{};
    for (size_t i = 0; i < std::min(tx.vout.size(), flags.size()); ++i) {
        const auto& output = tx.vout[i];
        flags[i] = ((outputs[i] & 2) != 0) | (output.nValue.IsExplicit() << 1) |
            (output.nNonce.IsNull() << 2) | (output.scriptPubKey.empty() << 3) |
            ((output.scriptPubKey == expected_script) << 4);
        values[i] = amounts[i];
    }
    const uint32_t input_facts = tx.vin[pegin_index].m_is_pegin | (1 << 1) |
        (tx.vin[pegin_index].scriptSig.empty() << 2) | (tx.vin[pegin_index].assetIssuance.IsNull() << 3) |
        (native << 4) | (1 << 5) | ((claim_script == (CScript() << OP_TRUE)) << 6);
    return drivechain::haskell::AuthenticatedDeposit(tx.vin.size(), pegin_index, tx.witness.vtxinwit.size(),
        input_facts, deposit_value, deposit_value, tx.vout.size(), flags, values, err_msg);
}

bool IsCanonicalFeeFreeDrivechainDeposit(const CTransaction& tx)
{
    std::string error;
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::FEE_FREE_DEPOSIT,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return tx.vin.size() == 1;
            case 2: return tx.vout.size() == 1;
            case 3: return tx.witness.vtxinwit.size() == 1;
            case 4: return tx.vin[0].m_is_pegin;
            case 5: return tx.vin[0].assetIssuance.IsNull();
            case 6: return IsDrivechainDepositPeginWitness(tx.witness.vtxinwit[0].m_pegin_witness, tx.vin[0].prevout);
            case 7: return CheckDrivechainDepositOutputs(tx, 0, error);
            default: return 0;
            }
        });
}

bool GetDrivechainDepositPeginData(const CScriptWitness& pegin_witness, const COutPoint& prevout, CAmount& out_value, CScript& out_claim_script, uint256& out_mainchain_txid)
{
    CAmount value;
    if (!DepositWitnessKind(pegin_witness, prevout, 1, value)) return false;
    out_value = value;
    const auto& claim = pegin_witness.stack[3];
    out_claim_script = CScript(claim.begin(), claim.end());
    out_mainchain_txid = prevout.hash.ToUint256();
    return true;
}

bool IsEcxDrivechainDepositPeginWitness(const CScriptWitness& pegin_witness,
                                       const COutPoint& prevout)
{
    CAmount value;
    return DepositWitnessKind(pegin_witness, prevout, 1, value) != 0;
}

bool IsLegacyDrivechainDepositPeginWitness(const CScriptWitness& pegin_witness)
{
    int64_t unused{0};
    return drivechain::haskell::DepositWitness(pegin_witness.stack,3,
        nullptr,nullptr,nullptr,nullptr,unused) != 0;
}

bool GetDrivechainDepositEvidence(
    const CScriptWitness& pegin_witness,
    const COutPoint& prevout,
    DrivechainDepositEvidence& evidence,
    std::string& error)
{
    const auto& stack = pegin_witness.stack;
    struct Context {
        const std::vector<std::vector<unsigned char>>& stack;
        DrivechainDepositEvidence decoded;
    } context{stack, {}};
    // Invoked only after Haskell has checked the stack shape and byte bounds.
    const auto decode = +[](void* opaque, int64_t* result) -> int32_t {
        auto& [fields, value] = *static_cast<Context*>(opaque);
        if (!DeserializeExactly(fields[8], value.sequence_number) ||
            !DeserializeExactly(fields[9], value.previous_sequence_number) ||
            !DeserializeExactly(fields[10], value.headers)) return 0;
        result[0] = value.sequence_number;
        result[1] = value.previous_sequence_number;
        result[2] = value.headers.size();
        return 1;
    };
    if (!drivechain::haskell::DepositEvidence(stack, prevout.hash.ToUint256().begin(),
            HashDepositTransaction, decode, &context, error)) return false;
    context.decoded.deposit_tx = stack[5];
    context.decoded.txout_proof = stack[6];
    context.decoded.previous_ctip_tx = stack[7];
    evidence = std::move(context.decoded);
    return true;
}

std::pair<uint256, COutPoint> GetPeginSpentKey(const CScriptWitness& pegin_witness, const COutPoint& prevout)
{
    if (IsDrivechainDepositPeginWitness(pegin_witness, prevout)) {
        return std::make_pair(prevout.hash, prevout);
    }
    return std::make_pair(uint256(pegin_witness.stack[2]), prevout);
}

bool MatchLiquidWatchman(const CScript& script)
{
    CScript::const_iterator it = script.begin();
    std::vector<unsigned char> data;
    opcodetype opcode;

    // Stack depth check for branch choice
    if (!script.GetOp(it, opcode, data) || opcode != OP_DEPTH) {
        return false;
    }
    // Take in value, then check equality
    if (!script.GetOp(it, opcode, data) ||
            !script.GetOp(it, opcode, data) ||
            opcode != OP_EQUAL) {
        return false;
    }
    // IF EQUAL
    if (!script.GetOp(it, opcode, data) || opcode != OP_IF) {
        return false;
    }
    // Take in value k, make sure minimally encoded number from 1 to 16
    if (!script.GetOp(it, opcode, data) ||
            opcode > OP_16 ||
            (opcode < OP_1NEGATE && !CheckMinimalPush(data, opcode))) {
        return false;
    }
    opcodetype opcode2 = opcode;
    std::vector<unsigned char> num = data;
    // Iterate through multisig stuff until ELSE is hit
    while (opcode != OP_ELSE) {
        if (!script.GetOp(it, opcode, data)) {
            return false;
        }
    }
    // Take minimally-encoded CSV push number k'
    if (!script.GetOp(it, opcode, data) ||
            opcode > OP_16 || (opcode < OP_1NEGATE && !CheckMinimalPush(data, opcode))) {
        return false;
    }
    // CSV
    if (!script.GetOp(it, opcode, data) || opcode != OP_CHECKSEQUENCEVERIFY) {
        return false;
    }
    // Drop the CSV number
    if (!script.GetOp(it, opcode, data) || opcode != OP_DROP) {
        return false;
    }
    // Take the minimally-encoded n of k-of-n multisig arg
    if (!script.GetOp(it, opcode, data) ||
            opcode > OP_16 || (opcode < OP_1NEGATE && !CheckMinimalPush(data, opcode)) ) {
        return false;
    }

    // The two multisig k-numbers must not match, otherwise ELSE branch can not be reached
    if (opcode == opcode2 && num == data) {
        return false;
    }

    // Find the ENDIF
    while (opcode != OP_ENDIF) {
        if (!script.GetOp(it, opcode, data)) {
            return false;
        }
    }
    // CHECKMULTISIG
    if (!script.GetOp(it, opcode, data) || opcode != OP_CHECKMULTISIG) {
        return false;
    }
    // No more pushes
    return (it == script.end());
}

std::vector<std::pair<CScript, CScript>> GetValidFedpegScripts(const CBlockIndex* pblockindex, const Consensus::Params& params, bool nextblock_validation)
{
    assert(pblockindex);

    std::vector<std::pair<CScript, CScript>> fedpegscripts;

    const int32_t epoch_length = (int32_t) params.dynamic_epoch_length;
    const int32_t epoch_age = pblockindex->nHeight % epoch_length;
    const int32_t epoch_start_height = pblockindex->nHeight - epoch_age;

    // In mempool and general "enforced next block" RPC we need to look ahead one block
    // to see if we're on a boundary. If so, put that epoch's fedpegscript in place
    if (nextblock_validation && epoch_age == epoch_length - 1) {
        DynaFedParamEntry next_param = ComputeNextBlockFullCurrentParameters(pblockindex, params);
        fedpegscripts.emplace_back(next_param.m_fedpeg_program, next_param.m_fedpegscript);
    }

    // Next we walk backwards up to M epoch starts
    for (int32_t i = 0; i < (int32_t) params.total_valid_epochs; i++) {
        // We are within total_valid_epochs of the genesis
        if (i * epoch_length > epoch_start_height) {
            break;
        }

        const CBlockIndex* p_epoch_start = pblockindex->GetAncestor(epoch_start_height-i*epoch_length);

        // We're done here, for whatever reason.
        if (!p_epoch_start) {
            break;
        }

        if (node::fTrimHeaders) {
            LOCK(cs_main);
            ForceUntrimHeader(p_epoch_start);
        }
        if (!p_epoch_start->dynafed_params().IsNull()) {
            fedpegscripts.emplace_back(p_epoch_start->dynafed_params().m_current.m_fedpeg_program, p_epoch_start->dynafed_params().m_current.m_fedpegscript);
        } else {
            fedpegscripts.emplace_back(GetScriptForDestination(ScriptHash(GetScriptForDestination(WitnessV0ScriptHash(params.fedpegScript)))), params.fedpegScript);
        }
    }
    // Only return up to the latest total_valid_epochs fedpegscripts, which are enforced
    fedpegscripts.resize(std::min(fedpegscripts.size(), params.total_valid_epochs));
    return fedpegscripts;
}

template<typename T_tx_ref, typename T_merkle_block>
CScriptWitness CreatePeginWitnessInner(const CAmount& value, const CAsset& asset, const uint256& genesis_hash, const CScript& claim_script, const T_tx_ref& tx_ref, const T_merkle_block& merkle_block)
{
    std::vector<unsigned char> value_bytes;
    VectorWriter ss_val(value_bytes, 0);
    try {
        ss_val << value;
    } catch (...) {
        throw std::ios_base::failure("Amount serialization is invalid.");
    }

    // Strip witness data for proof inclusion since only TXID-covered fields matters
    DataStream ss_tx{};
    ss_tx << TX_NO_WITNESS(tx_ref);
    const auto* ss_tx_ptr = UCharCast(ss_tx.data());
    std::vector<unsigned char> tx_data_stripped(ss_tx_ptr, ss_tx_ptr + ss_tx.size());

    // Serialize merkle block
    DataStream ss_txout_proof{};
    ss_txout_proof << TX_NO_WITNESS(merkle_block);
    const auto* ss_txout_ptr = UCharCast(ss_txout_proof.data());
    std::vector<unsigned char> txout_proof_bytes(ss_txout_ptr, ss_txout_ptr + ss_txout_proof.size());

    // Construct pegin proof
    CScriptWitness pegin_witness;
    std::vector<std::vector<unsigned char>>& stack = pegin_witness.stack;
    stack.push_back(value_bytes);
    stack.emplace_back(asset.begin(), asset.end());
    stack.emplace_back(genesis_hash.begin(), genesis_hash.end());
    stack.emplace_back(claim_script.begin(), claim_script.end());
    stack.push_back(tx_data_stripped);
    stack.push_back(txout_proof_bytes);
    return pegin_witness;
}

CScriptWitness CreatePeginWitness(const CAmount& value, const CAsset& asset, const uint256& genesis_hash, const CScript& claim_script, const CTransactionRef& tx_ref, const CMerkleBlock& merkle_block)
{
    return CreatePeginWitnessInner(value, asset, genesis_hash, claim_script, tx_ref, merkle_block);
}
CScriptWitness CreatePeginWitness(const CAmount& value, const CAsset& asset, const uint256& genesis_hash, const CScript& claim_script, const Sidechain::Bitcoin::CTransactionRef& tx_ref, const Sidechain::Bitcoin::CMerkleBlock& merkle_block)
{
    return CreatePeginWitnessInner(value, asset, genesis_hash, claim_script, tx_ref, merkle_block);
}

static std::vector<unsigned char> SerializeDepositValue(const CAmount& value)
{
    try {
        return SerializeEvidenceField(value);
    } catch (...) {
        throw std::ios_base::failure("Amount serialization is invalid.");
    }
}

static CScriptWitness AssembleDepositWitness(std::span<const unsigned char> layout,
    std::vector<std::vector<unsigned char>> fields)
{
    CScriptWitness witness;
    for (const auto field : layout) {
        if (field == 254) witness.stack.push_back(DRIVECHAIN_DEPOSIT_MARKER);
        else if (field == 255) witness.stack.push_back(ECX_LEGACY_DEPOSIT_MARKER);
        else witness.stack.push_back(std::move(fields.at(field)));
    }
    return witness;
}

CScriptWitness CreateDrivechainDepositPeginWitness(const CAmount& value,
                                                   const CAsset& asset,
                                                   const uint256& genesis_hash,
                                                   const CScript& claim_script,
                                                   const COutPoint& mainchain_outpoint,
                                                   const uint256& mainchain_block_hash,
                                                   const std::vector<unsigned char>& address)
{
    if (!drivechain::haskell::ParentReplayRecord(drivechain::haskell::ReplayRecordKind::NONEMPTY_BOUNDED, 0, 0, address.size(), ElementsDrivechainIdentity::DEPOSIT_ADDRESS_LIMIT)) {
        throw std::invalid_argument("Drivechain deposit address must contain 1..128 bytes.");
    }
    return AssembleDepositWitness(ElementsDrivechainIdentity::NATIVE_DEPOSIT_LAYOUT,
        {SerializeDepositValue(value), {asset.begin(),asset.end()}, {genesis_hash.begin(),genesis_hash.end()},
         {claim_script.begin(),claim_script.end()},
         {mainchain_outpoint.hash.ToUint256().begin(),mainchain_outpoint.hash.ToUint256().end()},
         {mainchain_block_hash.begin(),mainchain_block_hash.end()}, address});
}

CScriptWitness CreateDrivechainDepositPeginWitness(const CAmount& value, const CAsset& asset, const uint256& genesis_hash, const CScript& claim_script, const uint256& mainchain_txid)
{
    return AssembleDepositWitness(ElementsDrivechainIdentity::LEGACY_DEPOSIT_LAYOUT,
        {SerializeDepositValue(value), {asset.begin(),asset.end()}, {genesis_hash.begin(),genesis_hash.end()},
         {claim_script.begin(),claim_script.end()}, {mainchain_txid.begin(),mainchain_txid.end()}});
}

CScriptWitness CreateDrivechainDepositPeginWitness(
    const CAmount& value,
    const CAsset& asset,
    const uint256& genesis_hash,
    const CScript& claim_script,
    const DrivechainDepositEvidence& evidence)
{
    return AssembleDepositWitness(ElementsDrivechainIdentity::EVIDENCE_DEPOSIT_LAYOUT,
        {SerializeEvidenceField(value), {asset.begin(),asset.end()}, {genesis_hash.begin(),genesis_hash.end()},
         {claim_script.begin(),claim_script.end()}, evidence.deposit_tx, evidence.txout_proof, evidence.previous_ctip_tx,
         SerializeEvidenceField(evidence.sequence_number), SerializeEvidenceField(evidence.previous_sequence_number),
         SerializeEvidenceField(evidence.headers)});
}

bool DecomposePeginWitness(const CScriptWitness& witness, CAmount& value, CAsset& asset, uint256& genesis_hash, CScript& claim_script, std::variant<std::monostate, Sidechain::Bitcoin::CTransactionRef, CTransactionRef>& tx, std::variant<std::monostate, Sidechain::Bitcoin::CMerkleBlock, CMerkleBlock>& merkle_block)
{
    const auto& stack = witness.stack;

    if (stack.size() != 6) return false;
    if (stack[1].size() != 32) return false; // asset
    if (stack[2].size() != 32) return false; // parent genesis hash

    CAmount tmp_value{0};
    CAsset tmp_asset;
    uint256 tmp_genesis_hash;
    CScript tmp_claim_script;
    std::variant<std::monostate, Sidechain::Bitcoin::CTransactionRef, CTransactionRef> tmp_tx;
    std::variant<std::monostate, Sidechain::Bitcoin::CMerkleBlock, CMerkleBlock> tmp_merkle_block;

    try {
        DataStream stream{stack[0]};
        stream >> tmp_value;

        tmp_asset = CAsset(stack[1]);
        tmp_genesis_hash = uint256(stack[2]);
        tmp_claim_script = CScript(stack[3].begin(), stack[3].end());

        DataStream ss_tx(stack[4]);
        if (Params().GetConsensus().ParentChainHasPow()) {
            Sidechain::Bitcoin::CTransactionRef btc_tx;
            ss_tx >> TX_WITH_WITNESS(btc_tx);
            tmp_tx = btc_tx;
        } else {
            CTransactionRef elem_tx;
            ss_tx >> TX_WITH_WITNESS(elem_tx);
            tmp_tx = elem_tx;
        }

        DataStream ss_proof(stack[5]);
        if (Params().GetConsensus().ParentChainHasPow()) {
            Sidechain::Bitcoin::CMerkleBlock tx_proof;
            ss_proof >> TX_WITH_WITNESS(tx_proof);
            tmp_merkle_block = tx_proof;
        } else {
            CMerkleBlock tx_proof;
            ss_proof >> TX_WITH_WITNESS(tx_proof);
            tmp_merkle_block = tx_proof;
        }
    } catch (const std::exception&) {
        // Malformed encoding. Report failure rather than propagating
        return false;
    }

    value = tmp_value;
    asset = tmp_asset;
    genesis_hash = tmp_genesis_hash;
    claim_script = tmp_claim_script;
    tx = std::move(tmp_tx);
    merkle_block = std::move(tmp_merkle_block);
    return true;
}
