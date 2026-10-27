// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <chain.h>
#include <primitives/block.h>
#include <script/interpreter.h>
#include <script/generic.hpp>

bool CheckChallenge(const CBlockHeader& block, CBlockIndex& indexLast, const Consensus::Params& params)
{
    if (g_signed_blocks) {
        if (indexLast.trimmed()) {
            // Create a dummy block index to temporarily hold the untrimmed data
            CBlockIndex tmp_index;
            const CBlockIndex* pindexUntrimmed = indexLast.untrim_to(&tmp_index);
            return block.proof.challenge == pindexUntrimmed->get_proof().challenge;
        } else {
            return block.proof.challenge == indexLast.get_proof().challenge;
        }
    } else {
        return block.nBits == GetNextWorkRequired(&indexLast, &block, params);
    }
}

static bool CheckProofGeneric(const CBlockHeader& block, const uint32_t max_block_signature_size, const CScript& challenge, const CScript& scriptSig, const CScriptWitness& witness)
{
    // Legacy blocks have empty witness, dynafed blocks have empty scriptSig
    bool is_dyna = !witness.stack.empty();

    // Check signature limits for blocks
    if (scriptSig.size() > max_block_signature_size) {
        return false;
    } else if (witness.GetSerializedSize() > max_block_signature_size) {
        return false;
    }

    // Some anti-DoS flags, though max_block_signature_size caps the possible
    // danger in malleation of the block witness data.
    unsigned int proof_flags = SCRIPT_VERIFY_P2SH // For cleanstack evaluation under segwit flag
        | SCRIPT_VERIFY_STRICTENC // Minimally-sized DER sigs
        | SCRIPT_VERIFY_NULLDUMMY // No extra data stuffed into OP_CMS witness
        | SCRIPT_VERIFY_CLEANSTACK // No extra pushes leftover in witness
        | SCRIPT_VERIFY_MINIMALDATA // Pushes are minimally-sized
        | SCRIPT_VERIFY_SIGPUSHONLY // Witness is push-only
        | SCRIPT_VERIFY_LOW_S // Stop easiest signature fiddling
        | SCRIPT_VERIFY_WITNESS // Witness and to enforce cleanstack
        | (is_dyna ? SCRIPT_VERIFY_NONE : SCRIPT_NO_SIGHASH_BYTE); // Non-dynafed blocks do not have sighash byte
    return GenericVerifyScript(scriptSig, witness, challenge, proof_flags, block);
}

bool CheckProof(const CBlockHeader& block, const Consensus::Params& params)
{
    if (g_signed_blocks) {
        const DynaFedParams& dynafed_params = block.m_dynafed_params;
        if (dynafed_params.IsNull()) {
            return CheckProofGeneric(block, params.max_block_signature_size, params.signblockscript, block.proof.solution, CScriptWitness());
        } else {
            return CheckProofGeneric(block, dynafed_params.m_current.m_signblock_witness_limit, dynafed_params.m_current.m_signblockscript, CScript(), block.m_signblock_witness);
        }
    } else {
        return CheckProofOfWork(block.GetHash(), block.nBits, params);
    }
}

bool CheckProofSignedParent(const CBlockHeader& block, const Consensus::Params& params)
{
    const DynaFedParams& dynafed_params = block.m_dynafed_params;
    if (dynafed_params.IsNull()) {
        return CheckProofGeneric(block, params.max_block_signature_size, params.parent_chain_signblockscript, block.proof.solution, CScriptWitness());
    } else {
        // Dynamic federations means we cannot validate the signer set
        // at least without tracking the parent chain more directly.
        // Note that we do not even serialize dynamic federation block witness data
        // currently for merkle proofs which is the only context in which
        // this function is currently used.
        return true;
    }
}

// Fork-specific drivechain_bmm adapters.
// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <drivechain_bmm.h>
#include <haskell/bridge.h>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <crypto/common.h>
#include <hash.h>
#include <primitives/bitcoin/merkleblock.h>
#include <primitives/bitcoin/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <streams.h>
#include <util/strencodings.h>
#include <common/args.h>

#include <algorithm>
#include <array>
#include <exception>
#include <limits>
#include <optional>
#include <stdexcept>
#include <utility>

namespace drivechain {
int64_t BmmConsensus::DifficultyAdjustmentInterval() const
{
    return haskell::BmmDifficultyInterval(target_timespan, target_spacing);
}

namespace {

struct BmmIdentity
{
    std::array<uint256, 2> blocks;
    COutPoint outpoint;
    std::vector<unsigned char> marker;
    std::array<unsigned char, 4> signet_header, m8_magic;
    uint32_t script_flags;
};

const BmmIdentity& Identity()
{
    static const BmmIdentity identity = [] {
        std::array<uint32_t, 2> fields{};
        std::array<unsigned char, 121> bytes{};
        haskell::BmmFixedIdentity(fields, bytes);
        // ABI: three hashes, 17-byte marker, two four-byte magic values.
        return BmmIdentity{
            {uint256{bytes.data(), 32}, uint256{bytes.data() + 32, 32}},
            {Txid::FromUint256(uint256{bytes.data() + 64, 32}), fields[0]},
            {bytes.begin() + 96, bytes.begin() + 113},
            {bytes[113], bytes[114], bytes[115], bytes[116]},
            {bytes[117], bytes[118], bytes[119], bytes[120]}, fields[1]};
    }();
    return identity;
}

BmmConsensus MakeBmmConsensus(uint32_t mode)
{
    std::array<uint64_t, 6> fields{};
    std::array<unsigned char, 32> pow_limit{};
    std::array<unsigned char, 22> challenge{};
    const auto size = haskell::BmmConsensusPreset(mode, fields, pow_limit, challenge);
    return {uint256{pow_limit.data(), pow_limit.size()}, static_cast<int64_t>(fields[0]),
        static_cast<int64_t>(fields[1]), CScript(challenge.begin(), challenge.begin() + size),
        static_cast<int>(fields[2]), fields[3], fields[4], bool(fields[5])};
}

const BmmConsensus& PublicBmmConsensus()
{
    static const auto consensus = MakeBmmConsensus(0);
    return consensus;
}

#ifdef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
const BmmConsensus& PrivateBmmConsensus()
{
    static const auto consensus = MakeBmmConsensus(1);
    return consensus;
}

bool PrivateE2eBmmEnabled()
{
    return gArgs.GetBoolArg("-ecxprivatebmmcheckpoint", false);
}
#endif

BmmL1State MakeBmmCheckpoint(uint32_t mode)
{
    std::array<uint32_t, 16> fields{};
    std::array<unsigned char, 32> hash{};
    haskell::BmmCheckpointPreset(mode, fields, hash);
    return {uint256{hash.data(), hash.size()}, fields[0], fields[1], fields[2],
        fields[3], fields[4], {fields.begin() + 5, fields.end()}};
}

const BmmL1State& PublicBmmCheckpoint()
{
    static const auto state = MakeBmmCheckpoint(0);
    return state;
}

#ifdef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
// Private checkpoint selection remains compile-time and runtime gated.
const BmmL1State& PrivateBmmCheckpoint()
{
    static const auto state = MakeBmmCheckpoint(1);
    return state;
}
#endif


template <typename T>
bool DeserializeExactly(const std::vector<unsigned char>& bytes, T& value)
{
    try {
        DataStream stream{bytes};
        stream >> TX_WITH_WITNESS(value);
        return stream.empty();
    } catch (...) {
        return false;
    }
}

template <typename T>
std::vector<unsigned char> SerializeValue(const T& value)
{
    DataStream stream;
    stream << TX_WITH_WITNESS(value);
    return {
        UCharCast(stream.data()),
        UCharCast(stream.data()) + stream.size()};
}

template <typename T, size_t N>
std::vector<unsigned char> SerializeValue(const std::array<T, N>& values)
{
    DataStream stream;
    for (const auto& value : values) stream << TX_WITH_WITNESS(value);
    return {UCharCast(stream.data()), UCharCast(stream.data()) + stream.size()};
}

#ifdef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
bool ValidState(const BmmL1State& state, const BmmConsensus& consensus, std::string& error)
{
    return haskell::BmmState(!state.block_hash.IsNull(), consensus.DifficultyAdjustmentInterval(),
        state.height, state.block_time, state.n_bits, state.period_start_height, state.period_start_time,
        state.recent_times.size(), state.recent_times.empty() ? 0 : state.recent_times.back(), error);
}
#endif

#ifdef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
uint32_t ExpectedNextBits(
    const BmmL1State& previous,
    const BmmConsensus& consensus)
{
    uint32_t bits = previous.n_bits;
    haskell::RunBmmRetarget(previous.height, consensus.DifficultyAdjustmentInterval(),
        consensus.target_timespan, previous.block_time, previous.period_start_time,
        [&](uint32_t step, uint64_t, std::span<const unsigned char> bytes) -> std::vector<unsigned char> {
        switch (step) {
        case 0: {
            const uint256 next = ArithToUint256(arith_uint256{}.SetCompact(previous.n_bits));
            std::vector<unsigned char> result(next.begin(), next.end());
            result.insert(result.end(), consensus.pow_limit.begin(), consensus.pow_limit.end());
            return result;
        }
        case 1: {
            if (bytes.size() != 32) throw std::logic_error("invalid BMM retarget output");
            uint256 next;
            std::copy(bytes.begin(), bytes.end(), next.begin());
            bits = UintToArith256(next).GetCompact();
            return {};
        }
        default: throw std::logic_error("unexpected BMM retarget step");
        }
    });
    return bits;
}
#endif

} // namespace

namespace {
struct BitcoinSignatureEffects {
    const CScript& script_code;
    const Sidechain::Bitcoin::CTransaction& transaction;
    unsigned int input_index;
    int hash_type;
    uint256 hash_prevouts{}, hash_sequence{}, hash_outputs{}, digest{};
    HashWriter writer{};

    template <typename Items, typename Field>
    static uint256 HashItems(const Items& items, Field field)
    {
        HashWriter writer;
        for (const auto& item : items) writer << field(item);
        return writer.GetHash();
    }

    void Apply(uint32_t action)
    {
        switch (action) {
        case 100:
            hash_prevouts = HashItems(transaction.vin, [](const auto& input) -> const auto& { return input.prevout; });
            break;
        case 101:
            hash_sequence = HashItems(transaction.vin, [](const auto& input) { return input.nSequence; });
            break;
        case 102:
            hash_outputs = HashItems(transaction.vout, [](const auto& output) -> const auto& { return output; });
            break;
        case 103:
            hash_outputs = (HashWriter{} << transaction.vout[input_index]).GetHash();
            break;
        case 200: writer << transaction.version; break;
        case 201: writer << hash_prevouts; break;
        case 202: writer << hash_sequence; break;
        case 203: writer << transaction.vin[input_index].prevout; break;
        case 204: writer << script_code; break;
        case 205: writer << int64_t{0}; break;
        case 206: writer << transaction.vin[input_index].nSequence; break;
        case 207: writer << hash_outputs; break;
        case 208: writer << transaction.nLockTime; break;
        case 209: writer << hash_type; break;
        case 210: digest = writer.GetHash(); break;
        default: throw std::logic_error("invalid BMM signature hash effect");
        }
    }
};
} // namespace

uint256 BitcoinWitnessV0SignatureHash(
    const CScript& script_code,
    const Sidechain::Bitcoin::CTransaction& transaction,
    const unsigned int input_index,
    const int hash_type)
{
    BitcoinSignatureEffects effects{script_code,transaction,input_index,hash_type};
    haskell::RunBitcoinSignature(haskell::BitcoinSignatureWorkflow::HASH,hash_type,false,
        input_index,transaction.vin.size(),transaction.vout.size(),{},
        [&](uint32_t step,uint64_t,std::span<const unsigned char> actions) -> std::vector<unsigned char> {
            if (step != 4) throw std::logic_error("invalid BMM signature hash request");
            for (const auto action : actions) effects.Apply(action);
            return {};
        });
    return effects.digest;
}

bool BitcoinSignetSignatureChecker::CheckECDSASignature(
    const std::vector<unsigned char>& signature_with_type,
    const std::vector<unsigned char>& public_key, const CScript& script_code,
    const SigVersion sigversion, unsigned int flags) const
{
    ScriptError script_error{SCRIPT_ERR_OK};
    std::optional<CPubKey> pubkey;
    std::vector<unsigned char> signature;
    BitcoinSignatureEffects effects{script_code,m_transaction,m_input_index,0};
    // The checker cannot select the separate hash-only entry mode.
    const auto kind = m_mode == Mode::BMM ? haskell::BitcoinSignatureWorkflow::BMM :
        m_mode == Mode::PARENT ? haskell::BitcoinSignatureWorkflow::PARENT :
        static_cast<haskell::BitcoinSignatureWorkflow>(3);
    return haskell::RunBitcoinSignature(kind,0,sigversion == SigVersion::WITNESS_V0,
        m_input_index,m_transaction.vin.size(),m_transaction.vout.size(),signature_with_type,
        [&](uint32_t step,uint64_t value,std::span<const unsigned char> input) -> std::vector<unsigned char> {
        switch (step) {
        case 0: return {static_cast<unsigned char>(CheckSignatureEncoding(signature_with_type, flags, &script_error))};
        case 1:
            pubkey.emplace(public_key);
            return {static_cast<unsigned char>(pubkey->IsValid())};
        case 2:
            signature.assign(input.begin(),input.end());
            effects.hash_type = value;
            return {};
        case 3: return {static_cast<unsigned char>(pubkey->Verify(effects.digest, signature))};
        case 4:
            for (const auto action : input) effects.Apply(action);
            return {};
        default: throw std::logic_error("invalid BMM signature verification request");
        }
    });
}

namespace {

struct BmmSignetNative {
    const Sidechain::Bitcoin::CMutableTransaction& original_coinbase;
    Sidechain::Bitcoin::CMerkleBlock proof;
    const BmmConsensus& consensus;
    std::string& error;
    Sidechain::Bitcoin::CMutableTransaction modified_coinbase{original_coinbase};
    int commitment_index{-1};
    std::vector<unsigned char> signet_solution{}, pushdata{}, block_data{};
    Sidechain::Bitcoin::CMutableTransaction transaction_to_spend{}, transaction_spending{};
    std::vector<uint256> matches{};
    std::vector<unsigned int> indices{};
    uint256 modified_merkle_root{};
    CScript::const_iterator cursor{};
    CScript replacement{};
    opcodetype opcode{OP_INVALIDOPCODE};
    VectorWriter writer{block_data, 0};
    std::unique_ptr<DataStream> stream{};

    std::vector<unsigned char> operator()(uint32_t step, uint64_t index, std::span<const unsigned char> input)
    {
        if (step >= 40 && step <= 42) {
            if (!input.empty()) throw std::logic_error("invalid signet witness payload");
            return BitcoinWitnessCommitmentNative(modified_coinbase.vout, commitment_index, step+460, index);
        }
        if (index || (!input.empty() && step != 90 && (step < 20 || step > 25)))
            throw std::logic_error("invalid BMM signet projection");
        if (step >= 20 && step <= 25) {
            BitcoinSignetTransactionAction(step-20, input, consensus.signet_challenge, transaction_to_spend, transaction_spending);
            return SerializeValue(uint64_t{1});
        }
        if (step >= 30 && step <= 33) {
            BitcoinSignetDataAction(step-30, proof.header, modified_merkle_root, writer);
            return SerializeValue(uint64_t{1});
        }
        // Preserve the old catch-all decoder boundary, not the parent RPC's
        // narrower std::exception contract. No exception crosses FFI here.
        if (step >= 60 && step <= 63) {
            try {
                if (step == 60) stream = std::make_unique<DataStream>(signet_solution);
                else {
                    if (!stream) throw std::logic_error("missing signet reader");
                    if (step == 61) *stream >> transaction_spending.vin[0].scriptSig;
                    if (step == 62) *stream >> transaction_spending.vin[0].scriptWitness.stack;
                    if (step == 63) return SerializeValue(uint64_t{!stream->empty()});
                }
                return SerializeValue(uint64_t{1});
            } catch (...) { return SerializeValue(uint64_t{2}); }
        }
        switch (step) {
        case 10: {
            const auto& script = modified_coinbase.vout.at(commitment_index).scriptPubKey;
            const bool parsed = script.GetOp(cursor, opcode, pushdata);
            int64_t prefix{0};
            for (size_t i = 0; i < std::min<size_t>(4, pushdata.size()); ++i) prefix |= int64_t(pushdata[i]) << (8*i);
            return SerializeValue(std::array<int64_t,4>{parsed, cursor == script.end(), int64_t(pushdata.size()), prefix});
        }
        case 11:
            if (pushdata.size() < 4) throw std::runtime_error("invalid signet adapter capture");
            signet_solution.assign(pushdata.begin()+4, pushdata.end());
            pushdata.resize(4);
            break;
        case 12: replacement << pushdata; break;
        case 13: replacement << opcode; break;
        case 14: modified_coinbase.vout.at(commitment_index).scriptPubKey = replacement; break;
        case 54:
            signet_solution.clear();
            cursor = modified_coinbase.vout.at(commitment_index).scriptPubKey.begin();
            break;
        case 53: return SerializeValue(uint64_t{!signet_solution.empty()});
        case 64: stream.reset(); break;
        case 50:
            modified_merkle_root = proof.txn.ExtractMatchesWithReplacement(matches, indices, 0, modified_coinbase.GetHash());
            return SerializeValue(std::array<uint64_t,4>{!modified_merkle_root.IsNull(), matches.size(), indices.size(), indices.empty() ? 0 : indices[0]});
        case 51: return SerializeValue(uint64_t{matches.at(0) == original_coinbase.GetHash()});
        case 52: {
            transaction_to_spend.vin[0].scriptSig << block_data;
            transaction_spending.vin[0].prevout = {transaction_to_spend.GetHash(), 0};
            const Sidechain::Bitcoin::CTransaction immutable_to_spend{transaction_to_spend};
            const Sidechain::Bitcoin::CTransaction immutable_spending{transaction_spending};
            const BitcoinSignetSignatureChecker checker{immutable_spending, 0};
            return SerializeValue(uint64_t{VerifyScript(immutable_spending.vin[0].scriptSig, immutable_to_spend.vout[0].scriptPubKey,
                &immutable_spending.vin[0].scriptWitness, Identity().script_flags, checker)});
        }
        case 90: error.assign(input.begin(), input.end()); break;
        default: throw std::runtime_error("invalid native signet action");
        }
        return SerializeValue(uint64_t{1});
    }
};

// Haskell owns selection and byte ordering; native GetOp and hash objects stay here.
template <typename Output>
struct BmmCommitmentNative {
    const std::vector<Output>* outputs;
    const uint32_t kind;
    const int* slot;
    uint256& commitment;
    std::string& error;
    CScript::const_iterator cursor{};
    std::vector<unsigned char> data{};

    std::vector<unsigned char> operator()(uint32_t step, uint64_t index, std::span<const unsigned char> input)
    {
        if (!outputs) throw std::logic_error("missing BMM commitment outputs");
        if (step != 23 && step != 90 && !input.empty()) throw std::logic_error("invalid BMM commitment payload");
        if (step == 0) {
            if (index || outputs->size() > std::numeric_limits<uint32_t>::max()) throw std::length_error("BMM output count");
            return SerializeValue(std::array<uint64_t,3>{kind, uint64_t(int64_t(slot ? *slot : 0)), outputs->size()});
        }
        if (step == 23 || step == 90) {
            if (index) throw std::logic_error("invalid BMM publication index");
            if (step == 90) error.assign(input.begin(), input.end());
            else {
                if (input.size() != 32) throw std::logic_error("invalid commitment hash publication");
                commitment = uint256{input.data(), input.size()};
            }
            return SerializeValue(uint64_t{1});
        }
        const auto& script = outputs->at(index).scriptPubKey;
        std::array<int64_t,4> fields{};
        switch (step) {
        case 10:
            fields[0] = script.size();
            for (size_t i = 0; i < std::min<size_t>(6, script.size()); ++i) fields[1] |= int64_t(script[i]) << (8*i);
            break;
        case 11:
            cursor = script.begin();
            data.clear();
            [[fallthrough]];
        case 12: {
            opcodetype opcode;
            fields[0] = script.GetOp(cursor, opcode, data) ? uint32_t(opcode) : 256;
            break;
        }
        case 13:
            fields[0] = cursor == script.end();
            fields[1] = data.size();
            for (size_t i = 0; i < std::min<size_t>(4, data.size()); ++i) fields[2] |= int64_t(data[i]) << (8*i);
            fields[3] = data.size() > 4 ? data[4] : 0;
            break;
        case 14:
            if (kind != 3 || data.size() != 37) throw std::logic_error("invalid parent commitment publication");
            commitment = uint256(data.data()+5, uint256::size());
            break;
        case 20: case 21: {
            if (step == 20) cursor = script.begin();
            opcodetype opcode;
            script.GetOp(cursor, opcode, data);
            return SerializeValue(uint64_t{1});
        }
        case 22: return data;
        default: throw std::logic_error("invalid BMM script action");
        }
        return SerializeValue(fields);
    }
};

struct BmmStateStorageNative {
    CCoinsViewCache& view;
    const BmmL1State& state;
    const int height;
    const BmmIdentity& identity{Identity()};
    DataStream stream{};
    CScript script{};
    std::optional<CTxOut> output{};

    std::vector<unsigned char> operator()(uint32_t step, uint64_t value, std::span<const unsigned char> input)
    {
        if (!input.empty() || value > UINT32_MAX) throw std::logic_error("invalid BMM state storage fields");
        std::vector<unsigned char> reply(8);
        switch (step) {
        case 0: WriteLE64(reply.data(), static_cast<uint32_t>(height)); return reply;
        case 10: view.SpendCoin(identity.outpoint); break;
        case 11: stream << identity.marker; break;
        case 12: stream << state; break;
        case 13: script << std::vector<unsigned char>(UCharCast(stream.data()), UCharCast(stream.data()) + stream.size()); break;
        case 14:
            if (value > 255) throw std::logic_error("invalid BMM state opcode");
            script << static_cast<opcodetype>(value); break;
        case 15: output.emplace(Params().GetConsensus().pegged_asset, value, script); break;
        case 16:
            view.AddCoin(identity.outpoint, Coin(std::move(output.value()), value, false), true);
            break;
        default: throw std::logic_error("invalid BMM state storage action");
        }
        WriteLE64(reply.data(), 1);
        return reply;
    }
};

} // namespace

void BitcoinSignetTransactionAction(uint32_t action, std::span<const unsigned char> encoded,
    const CScript& challenge,
    Sidechain::Bitcoin::CMutableTransaction& spend, Sidechain::Bitcoin::CMutableTransaction& sign)
{
    if (encoded.size() != 24) throw std::logic_error("invalid signet assembly fields");
    const auto field = [&](size_t index) { return ReadLE32(encoded.data()+4*index); };
    switch (action) {
    case 0: spend.version = sign.version = field(0); break;
    case 1: spend.nLockTime = sign.nLockTime = field(1); break;
    case 2: spend.vin.emplace_back(Sidechain::Bitcoin::COutPoint(), CScript(static_cast<opcodetype>(field(4))), field(2)); break;
    case 3: spend.vout.emplace_back(field(3), challenge); break;
    case 4: sign.vin.emplace_back(Sidechain::Bitcoin::COutPoint(), CScript(), field(2)); break;
    case 5: sign.vout.emplace_back(field(3), CScript(static_cast<opcodetype>(field(5)))); break;
    default: throw std::logic_error("invalid signet assembly action");
    }
}

void BitcoinSignetDataAction(uint32_t field, const Sidechain::Bitcoin::CBlockHeader& header,
    const uint256& modified_merkle_root, VectorWriter& writer)
{
    switch (field) {
    case 0: writer << header.nVersion; break;
    case 1: writer << header.hashPrevBlock; break;
    case 2: writer << modified_merkle_root; break;
    case 3: writer << header.nTime; break;
    default: throw std::logic_error("invalid signet header field");
    }
}

std::vector<unsigned char> BitcoinWitnessCommitmentNative(
    const std::vector<Sidechain::Bitcoin::CTxOut>& outputs, int& selected, uint32_t step, uint64_t index)
{
    std::vector<unsigned char> result(8);
    switch (step) {
    case 500:
        if (outputs.size() > std::numeric_limits<uint32_t>::max()) throw std::length_error("BMM output count");
        WriteLE64(result.data(), outputs.size());
        break;
    case 501: {
        const auto& script = outputs.at(index).scriptPubKey;
        uint64_t prefix{0};
        for (size_t i = 0; i < std::min<size_t>(6,script.size()); ++i) prefix |= uint64_t{script[i]} << (8*i);
        result.resize(16);
        WriteLE64(result.data(), script.size());
        WriteLE64(result.data()+8, prefix);
        break;
    }
    case 502:
        selected = index == std::numeric_limits<uint64_t>::max() ? -1 : static_cast<int>(index);
        WriteLE64(result.data(), selected >= 0);
        break;
    default: throw std::logic_error("invalid signet witness action");
    }
    return result;
}

bool ExtractTaggedParentCommitment(const std::vector<CTxOut>& outputs, uint256& parent, std::string& error)
{
    BmmCommitmentNative<CTxOut> native{&outputs, 3, nullptr, parent, error};
    return haskell::RunReplayStore(haskell::ReplayStoreWorkflow::COMMITMENT, std::ref(native)) == 1;
}

const BmmConsensus& LayerTwoLabsBmmConsensus()
{
    using Step = haskell::BmmStateStep;
    const BmmConsensus* selected = nullptr;
    haskell::RunBmmStateFlow(Step::CONSENSUS_START, [&](Step step) -> int32_t {
        switch (step) {
        case Step::MODE_SELECT:
#ifdef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
            return PrivateE2eBmmEnabled();
#else
            return 0;
#endif
#ifdef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
        case Step::MODE_PRIVATE: selected = &PrivateBmmConsensus(); return 1;
#endif
        case Step::MODE_PUBLIC: selected = &PublicBmmConsensus(); return 1;
        default: throw std::logic_error("unexpected BMM consensus step");
        }
    });
    if (!selected) throw std::logic_error("missing BMM consensus selection");
    return *selected;
}

const BmmL1State& LayerTwoLabsInitialBmmState()
{
    return PublicBmmCheckpoint();
}

const uint256& LayerTwoLabsPublicSidechainBlock1()
{
    return Identity().blocks[0];
}

const uint256& LayerTwoLabsPublicSidechainBlock2()
{
    return Identity().blocks[1];
}

uint256 RuntimeBmmConsensusFingerprint()
{
    const BmmConsensus& consensus{LayerTwoLabsBmmConsensus()};
    const BmmL1State* states[]{&PublicBmmCheckpoint(),
#ifdef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
        &PrivateBmmCheckpoint()
#else
        nullptr
#endif
    };
    const bool private_mode =
#ifdef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
        PrivateE2eBmmEnabled();
#else
        false;
#endif
    const std::array<uint64_t, 11> numbers{
        BMM_PROOF_SCHEMA_VERSION, CBlockHeader::BMM_PROOF_HF_MASK, private_mode,
        static_cast<uint64_t>(consensus.target_timespan), static_cast<uint64_t>(consensus.target_spacing),
        consensus.require_signet_solution, static_cast<uint32_t>(consensus.sidechain_slot),
        consensus.max_entries, consensus.max_proof_bytes, Identity().outpoint.n, Identity().script_flags};
    const std::array<std::span<const unsigned char>, 8> blobs{{
        {consensus.pow_limit.begin(), consensus.pow_limit.size()},
        {consensus.signet_challenge.data(), consensus.signet_challenge.size()},
        {Identity().blocks[0].begin(), Identity().blocks[0].size()},
        {Identity().blocks[1].begin(), Identity().blocks[1].size()},
        {Identity().outpoint.hash.ToUint256().begin(), Identity().outpoint.hash.ToUint256().size()},
        Identity().marker, Identity().signet_header, Identity().m8_magic}};
    const auto payload = haskell::BmmFingerprint(
        [&](uint32_t group, uint32_t index, uint64_t& value, const unsigned char*& bytes) {
            if (group == 0) {
                if (index >= numbers.size()) return false;
                value = numbers[index];
            } else if (group == 1) {
                if (index < blobs.size()) {
                    value = blobs[index].size();
                    bytes = blobs[index].data();
                } else {
                    if (index > 9 || !states[index - 8]) return false;
                    value = states[index - 8]->block_hash.size();
                    bytes = states[index - 8]->block_hash.begin();
                }
            } else {
                if (group > 5 || !states[(group - 2) / 2]) return false;
                const auto& state = *states[(group - 2) / 2];
                if (group & 1) {
                    if (index >= state.recent_times.size()) return false;
                    value = state.recent_times[index];
                } else {
                    const std::array<uint64_t, 6> fields{state.height, state.block_time, state.n_bits,
                        state.period_start_height, state.period_start_time, state.recent_times.size()};
                    if (index >= fields.size()) return false;
                    value = fields[index];
                }
            }
            return true;
        });
    auto writer = TaggedHash(BMM_FINGERPRINT_TAG);
    writer.write(AsBytes(Span{payload}));
    return writer.GetSHA256();
}

bool HasPersistedBmmConsensusState(const CCoinsView& view)
{
    const auto coin = view.GetCoin(Identity().outpoint);
    return coin && !coin->IsSpent();
}

bool IsBmmStateInternalOutpoint(const COutPoint& outpoint)
{
    return outpoint == Identity().outpoint;
}

namespace {

std::vector<unsigned char> BmmHeaderObservation(const CBlockIndex* previous,
    uint32_t step, uint64_t index, std::span<const unsigned char> input)
{
    if (step == 0) throw std::runtime_error(std::string(input.begin(), input.end()));
    if (index != 0 || !input.empty()) throw std::logic_error("unexpected BMM header observation input");
    const auto words = [](std::initializer_list<uint64_t> values) {
        std::vector<unsigned char> bytes(values.size()*8);
        size_t offset = 0;
        for (const auto value : values) { WriteLE64(bytes.data()+offset, value); offset += 8; }
        return bytes;
    };
    switch (step) {
    case 1: return words({uint64_t(bool(Params().GetConsensus().drivechain_slot)) |
        (uint64_t(previous != nullptr) << 1)});
    case 2:
#ifdef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
        return words({uint64_t(PrivateE2eBmmEnabled())});
#else
        return words({0});
#endif
#ifdef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
    case 3: {
        if (!previous) throw std::logic_error("missing BMM activation predecessor");
        const bool present = gArgs.IsArgSet("-ecxprivatebmmactivationheight");
        return words({uint64_t(present), uint64_t(previous->nHeight),
            uint64_t(present ? gArgs.GetIntArg("-ecxprivatebmmactivationheight", -1) : -1)});
    }
#endif
    case 4:
        if (!previous) throw std::logic_error("missing BMM activation predecessor");
        return words({uint64_t(previous->GetBlockHash() == Identity().blocks[1]) |
            (uint64_t((static_cast<uint32_t>(previous->nVersion) & CBlockHeader::BMM_PROOF_HF_MASK) != 0) << 1)});
    default: throw std::logic_error("unexpected BMM header observation");
    }
}

} // namespace

bool BmmProofRequiredAfter(const CBlockIndex* previous)
{
    return haskell::RunReplayStore(haskell::ReplayStoreWorkflow::BMM_PROOF_REQUIRED,
        [&](uint32_t step, uint64_t index, std::span<const unsigned char> input) {
            return BmmHeaderObservation(previous, step, index, input);
        }) == 1;
}

namespace {

std::vector<unsigned char> BmmHeaderPolicyObservation(
    int32_t version, const uint256& proof_commitment, const uint256& block_hash,
    const CBlockIndex* previous, std::string& error, bool allow_incomplete_candidate,
    uint32_t step, uint64_t index, std::span<const unsigned char> input)
{
    if (step != 10 && step != 11) return BmmHeaderObservation(previous, step, index, input);
    if (index != 0 || (step == 10 && !input.empty()))
        throw std::logic_error("unexpected BMM header policy input");
    if (step == 11) {
        error.assign(input.begin(), input.end());
        return SerializeValue(uint64_t{1});
    }
    const bool native = bool(Params().GetConsensus().drivechain_slot);
    const uint32_t facts = native | ((previous != nullptr) << 1) |
        ((!native && previous && previous->GetBlockHash() == Identity().blocks[0]) << 2) |
        ((block_hash == Identity().blocks[1]) << 3) |
        (((static_cast<uint32_t>(version) & CBlockHeader::BMM_PROOF_HF_MASK) != 0) << 4) |
        ((!proof_commitment.IsNull()) << 5) | (allow_incomplete_candidate << 7);
    return SerializeValue(uint64_t{facts});
}

bool CheckBmmHeaderCommitments(
    const int32_t version,
    const uint256& proof_commitment,
    const uint256& block_hash,
    const CBlockIndex* previous,
    std::string& error,
    const bool allow_incomplete_candidate)
{
    error.clear();
    return haskell::RunReplayStore(haskell::ReplayStoreWorkflow::BMM_HEADER_POLICY,
        [&](uint32_t step, uint64_t index, std::span<const unsigned char> input) {
            return BmmHeaderPolicyObservation(version, proof_commitment, block_hash, previous,
                error, allow_incomplete_candidate, step, index, input);
        }) == 1;
}

} // namespace

bool CheckBmmHeader(
    const CBlockHeader& block,
    const CBlockIndex* previous,
    std::string& error,
    const bool allow_incomplete_candidate)
{
    return CheckBmmHeaderCommitments(
        block.nVersion,
        block.hashBmmProof,
        block.GetHash(),
        previous,
        error,
        allow_incomplete_candidate);
}

bool CheckBmmIndexHeader(
    const CBlockIndex& index,
    std::string& error)
{
    return CheckBmmHeaderCommitments(
        index.nVersion,
        index.hashBmmProof,
        index.GetBlockHash(),
        index.pprev,
        error,
        /* allow_incomplete_candidate */ false);
}

namespace {
struct BmmProofSessionNative {
    const BmmProof& proof;
    std::string& error;
    const std::vector<unsigned char>* input_bytes{nullptr};
    std::vector<unsigned char>* output_bytes{nullptr};
    BmmProof* decoded{nullptr};
    CBlock* attached{nullptr};
    std::function<std::array<uint64_t,4>(uint32_t)> observe{};
    haskell::NativeWorkflow headers{};
    haskell::NativeWorkflow commitments{};
    haskell::NativeWorkflow signet{};

    std::vector<unsigned char> operator()(uint32_t step, uint64_t index, std::span<const unsigned char> input)
    {
        if (step >= 700 && step <= 790) {
            if (!signet) throw std::logic_error("missing native BMM signet projection");
            return signet(step-700, index, input);
        }
        if (step >= 500 && step <= 690) {
            if (!commitments) throw std::logic_error("missing native BMM commitment projection");
            return commitments(step, index, input);
        }
        if (step >= 400 && step <= 409) {
            if (!headers) throw std::logic_error("missing native BMM header projection");
            return headers(step, index, input);
        }
        if (index || (step != 390 && !input.empty())) throw std::logic_error("invalid BMM proof session request");
        const auto require = []<typename T>(T* ptr) -> T& {
            if (!ptr) throw std::logic_error("missing native BMM proof object");
            return *ptr;
        };
        std::vector<unsigned char> reply(8);
        uint64_t value{1};
        switch (step) {
        case 300:
            try {
                auto& bytes = require(output_bytes);
                bytes = SerializeValue(proof);
                reply.resize(9);
                reply[0] = 1;
                WriteLE64(reply.data()+1, bytes.size());
                return reply;
            } catch (const std::exception& exception) {
                const std::string message{exception.what()};
                reply.assign(1, 0);
                reply.insert(reply.end(), message.begin(), message.end());
                return reply;
            }
        case 301: value = require(input_bytes).size(); break;
        case 302: value = DeserializeExactly(require(input_bytes), require(decoded)); break;
        case 303: value = proof.version; break;
        case 304: value = proof.entries.size(); break;
        case 305: value = SerializeValue(proof) == require(input_bytes); break;
        case 306: value = require(attached).HasBmmProof(); break;
        case 307: {
            auto& block = require(attached);
            block.hashBmmProof = BmmProofCommitment(block.m_bmm_proof);
            break;
        }
        case 390: error.assign(input.begin(), input.end()); break;
        case 391: value = error.empty(); break;
        case 392: error.clear(); break;
        default: {
            if (step > 255 || !observe) throw std::logic_error("invalid BMM proof session observation");
            const auto fields = observe(step);
            reply.resize(32);
            for (size_t i = 0; i < fields.size(); ++i) WriteLE64(reply.data()+8*i, fields[i]);
            return reply;
        }
        }
        WriteLE64(reply.data(), value);
        return reply;
    }
};

} // namespace

bool SerializeBmmProof(
    const BmmProof& proof,
    std::vector<unsigned char>& bytes,
    std::string& error)
{
    try {
        BmmProofSessionNative native{proof, error};
        native.output_bytes = &bytes;
        return haskell::RunReplayStore(haskell::ReplayStoreWorkflow::PROOF_ENCODE, std::ref(native)) == 1;
    } catch (const std::exception& exception) {
        error = exception.what();
        return false;
    }
}

bool DeserializeBmmProof(
    const std::vector<unsigned char>& bytes,
    BmmProof& proof,
    std::string& error)
{
    BmmProofSessionNative native{proof, error};
    native.input_bytes = &bytes;
    native.decoded = &proof;
    return haskell::RunReplayStore(haskell::ReplayStoreWorkflow::PROOF_DECODE, std::ref(native)) == 1;
}

uint256 BmmProofCommitment(const std::vector<unsigned char>& bytes)
{
    return Hash(bytes);
}

bool AttachBmmProof(CBlock& block, const BmmProof& proof, std::string& error)
{
    BmmProofSessionNative native{proof, error};
    native.output_bytes = &block.m_bmm_proof;
    native.attached = &block;
    return haskell::RunReplayStore(haskell::ReplayStoreWorkflow::PROOF_ATTACH, std::ref(native)) == 1;
}

#ifdef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
bool BuildPrivateE2eBmmProof(
    const BmmL1State& previous,
    const uint256& critical_hash,
    BmmProof& proof,
    std::string& error)
{
    error.clear();
    Sidechain::Bitcoin::CMutableTransaction coinbase;
    Sidechain::Bitcoin::CBlockHeader header;
    arith_uint256 target;
    using Step = haskell::BmmStateStep;
    std::array<uint32_t, 4> fields{};
    return haskell::RunBmmStateFlow(Step::PRIVATE_START, [&](Step step) -> int32_t {
        switch (step) {
        case Step::PRIVATE_ENABLED: {
            const bool enabled = PrivateE2eBmmEnabled();
            if (!enabled) error = "private BMM proof construction is disabled";
            return enabled;
        }
        case Step::PRIVATE_VALID:
            return ValidState(previous, PrivateBmmConsensus(), error);
        case Step::PRIVATE_COINBASE: {
            std::array<unsigned char, 37> m8{};
            haskell::BmmPrivateTemplate(previous.height, previous.block_time,
                haskell::BmmMedian(previous.recent_times), BMM_SIDECHAIN_SLOT,
                std::span<const unsigned char, 32>{critical_hash.begin(), 32}, fields, m8);
            coinbase.version = fields[0];
            coinbase.vin.resize(1);
            coinbase.vin[0].prevout.SetNull();
            coinbase.vin[0].scriptSig = CScript() << static_cast<int64_t>(fields[1]);
            coinbase.vout.emplace_back(0, CScript() << OP_RETURN << std::vector<unsigned char>(m8.begin(), m8.end()));

            return 1;
        }
        case Step::PRIVATE_HEADER:
            header.nVersion = fields[2];
            header.hashPrevBlock = previous.block_hash;
            header.hashMerkleRoot = coinbase.GetHash();
            header.nTime = fields[3];
            header.nBits = ExpectedNextBits(previous, PrivateBmmConsensus());
            target.SetCompact(header.nBits);
            return 1;
        case Step::PRIVATE_POW:
            return UintToArith256(header.GetHash()) <= target;
        case Step::PRIVATE_NONCE:
            ++header.nNonce;
            return 1;
        case Step::PRIVATE_ASSEMBLE: {
            Sidechain::Bitcoin::CMerkleBlock merkle;
            merkle.header = header;
            merkle.txn = Sidechain::Bitcoin::CPartialMerkleTree(
                {coinbase.GetHash()}, {true});
            proof = BmmProof{};
            proof.previous_state = previous;
            proof.entries.push_back({SerializeValue(coinbase), SerializeValue(merkle)});

            return 1;
        }
        case Step::PRIVATE_VERIFY: {
            BmmL1State next;
            return VerifyBmmProofEntries(proof, critical_hash, previous.block_hash,
                next, error, PrivateBmmConsensus());
        }
        default: throw std::logic_error("invalid private BMM construction action");
        }
    });
}
#endif

namespace {
struct BmmProofEntriesNative {
    const BmmProof& proof;
    const uint256& expected_critical_hash;
    const uint256& expected_parent_hash;
    BmmL1State& next_state;
    std::string& error;
    const BmmConsensus& consensus;
    Sidechain::Bitcoin::CMutableTransaction coinbase{};
    Sidechain::Bitcoin::CMerkleBlock merkle_proof{};
    std::vector<uint256> matches{};
    std::vector<unsigned int> indices{};
    uint256 mined_commitment{};
    arith_uint256 target{};
    size_t index{0};
    BmmCommitmentNative<Sidechain::Bitcoin::CTxOut> commitment{&coinbase.vout, 0, &consensus.sidechain_slot, mined_commitment, error};
    std::unique_ptr<BmmSignetNative> signet{};

    std::vector<unsigned char> Signet(uint32_t step, uint64_t position, std::span<const unsigned char> input)
    {
        if (step == 0 || step == 1) {
            if (position || !input.empty()) throw std::logic_error("invalid BMM signet lifetime request");
            if (step == 0) signet = std::make_unique<BmmSignetNative>(coinbase, merkle_proof, consensus, error);
            else signet.reset();
            return SerializeValue(uint64_t{1});
        }
        if (!signet) throw std::logic_error("missing BMM signet state");
        return (*signet)(step, position, input);
    }

    std::vector<unsigned char> Header(uint32_t step, uint64_t position, std::span<const unsigned char> input)
    {
        if (position || (!input.empty() && step != 405 && step != 406 && step != 407 && step != 409))
            throw std::logic_error("invalid BMM header projection request");
        const auto& prior = proof.previous_state;
        const auto& header = merkle_proof.header;
        switch (step) {
        case 400:
            return SerializeValue(std::array<uint64_t,11>{!prior.block_hash.IsNull(),
                uint64_t(consensus.target_timespan), uint64_t(consensus.target_spacing),
                prior.height, prior.block_time, prior.n_bits, prior.period_start_height, prior.period_start_time,
                prior.recent_times.size(), prior.recent_times.empty() ? 0 : prior.recent_times.back(), proof.entries.size()});
        case 401: return SerializeValue(prior);
        case 402: return SerializeValue(header.hashPrevBlock);
        case 403: return SerializeValue(std::array<uint32_t,2>{header.nTime, header.nBits});
        case 404: return SerializeValue(header.GetHash());
        case 405: {
            if (input.size() != 4) throw std::logic_error("invalid BMM compact target input");
            const uint256 decoded = ArithToUint256(arith_uint256{}.SetCompact(ReadLE32(input.data())));
            std::vector<unsigned char> bytes(decoded.begin(), decoded.end());
            bytes.insert(bytes.end(), consensus.pow_limit.begin(), consensus.pow_limit.end());
            return bytes;
        }
        case 406:
            if (input.size() != 32) throw std::logic_error("invalid BMM target output");
            return SerializeValue(UintToArith256(uint256{input.data(),input.size()}).GetCompact());
        case 407: {
            BmmL1State decoded;
            if (input.size() != 97 || !DeserializeExactly(std::vector<unsigned char>(input.begin(), input.end()), decoded))
                throw std::logic_error("invalid BMM state publication");
            next_state = std::move(decoded);
            break;
        }
        case 408: ++index; break;
        case 409: throw std::runtime_error(std::string(input.begin(), input.end()));
        default: throw std::logic_error("invalid BMM header projection");
        }
        return SerializeValue(uint64_t{1});
    }

    std::array<uint64_t,4> operator()(uint32_t action)
    {
        using Step = haskell::BmmTraversalStep;
        const auto& header = merkle_proof.header;
        switch (static_cast<Step>(action)) {
        case Step::RESET_ENTRY: coinbase = {}; merkle_proof = {}; return {1,0,0,0};
        case Step::DECODE_COINBASE: return {DeserializeExactly(proof.entries.at(index).coinbase_tx,coinbase),0,0,0};
        case Step::DECODE_MERKLE: return {DeserializeExactly(proof.entries.at(index).coinbase_proof,merkle_proof),0,0,0};
        case Step::CANONICAL_COINBASE: return {SerializeValue(coinbase) == proof.entries.at(index).coinbase_tx,0,0,0};
        case Step::CANONICAL_MERKLE: return {SerializeValue(merkle_proof) == proof.entries.at(index).coinbase_proof,0,0,0};
        case Step::COINBASE_SHAPE: return {!coinbase.vin.empty() && coinbase.vin[0].prevout.IsNull(),coinbase.vin.size(),0,0};
        case Step::POW_TARGET: {
            bool negative{false}, overflow{false};
            target.SetCompact(header.nBits, &negative, &overflow);
            const uint64_t facts = negative | ((target == 0) << 1) | (overflow << 2) |
                ((target > UintToArith256(consensus.pow_limit)) << 3);
            return {facts,consensus.require_signet_solution,0,0};
        }
        case Step::POW_HASH: return {UintToArith256(header.GetHash()) <= target,0,0,0};
        case Step::PREFLIGHT:
            return {proof.version == BMM_PROOF_SCHEMA_VERSION,proof.entries.size(),consensus.max_entries,0};
        case Step::ENTRY_BOUNDS: {
            const auto& entry = proof.entries.at(index);
            return {0,entry.coinbase_tx.size(),entry.coinbase_proof.size(),MAX_BLOCK_WEIGHT / WITNESS_SCALE_FACTOR};
        }
        case Step::MERKLE: {
            matches.clear();
            indices.clear();
            const bool root = merkle_proof.txn.ExtractMatches(matches, indices) == merkle_proof.header.hashMerkleRoot;
            return {root,matches.size(),indices.size(),indices.empty() ? UINT32_MAX : indices[0]};
        }
        case Step::COINBASE:
            return {matches.at(0) == coinbase.GetHash(),0,0,0};
        case Step::PARENT:
            return {merkle_proof.header.hashPrevBlock == expected_parent_hash,0,0,0};
        case Step::CRITICAL:
            return {mined_commitment == expected_critical_hash,0,0,0};
        default: throw std::runtime_error("invalid native BMM traversal action");
        }
    }
};
} // namespace

bool VerifyBmmProofEntries(
    const BmmProof& proof,
    const uint256& expected_critical_hash,
    const uint256& expected_parent_hash,
    BmmL1State& next_state,
    std::string& error,
    const BmmConsensus& consensus)
{
    BmmProofEntriesNative entries{proof, expected_critical_hash, expected_parent_hash, next_state, error, consensus};
    BmmProofSessionNative native{proof, error};
    native.observe = std::ref(entries);
    native.headers = [&](auto step, auto index, auto input) { return entries.Header(step, index, input); };
    native.signet = [&](auto step, auto index, auto input) { return entries.Signet(step, index, input); };
    native.commitments = [&](auto step, auto index, auto input) { return entries.commitment(step-500, index, input); };
    return haskell::RunReplayStore(haskell::ReplayStoreWorkflow::PROOF_ENTRIES, std::ref(native)) == 1;
}

namespace {
struct BmmBlockProofNative {
    const CBlock& block;
    const BmmL1State& expected_previous;
    std::string& error;
    const BmmConsensus& consensus;
    BmmProof proof{};
    uint256 parent_hash{}, critical_hash{};
    BmmCommitmentNative<CTxOut> parent{nullptr, 1, nullptr, parent_hash, error};
    BmmProofEntriesNative entries;
    BmmProofSessionNative native;

    BmmBlockProofNative(const CBlock& block_in, const BmmL1State& prior, BmmL1State& next,
        std::string& error_in, const BmmConsensus& consensus_in)
        : block(block_in), expected_previous(prior), error(error_in), consensus(consensus_in),
          entries{proof, critical_hash, parent_hash, next, error, consensus}, native{proof, error}
    {
        native.input_bytes = &block.m_bmm_proof;
        native.decoded = &proof;
        native.headers = [this](auto step, auto index, auto input) { return entries.Header(step, index, input); };
        native.signet = [this](auto step, auto index, auto input) { return entries.Signet(step, index, input); };
        native.observe = [this](uint32_t step) { return Observe(step); };
        native.commitments = [this](auto step, auto index, auto input) {
            if (step < 600) return entries.commitment(step-500, index, input);
            parent.outputs = &block.vtx.at(0)->vout;
            return parent(step-600, index, input);
        };
    }
    BmmBlockProofNative(const BmmBlockProofNative&) = delete;
    BmmBlockProofNative& operator=(const BmmBlockProofNative&) = delete;

    std::array<uint64_t,4> Observe(uint32_t step)
    {
        using Step = haskell::BmmTraversalStep;
        switch (static_cast<Step>(step)) {
        case Step::BLOCK_BOUNDS:
            return {uint64_t{block.HasBmmProof()} | (uint64_t{!block.hashBmmProof.IsNull()} << 1),block.m_bmm_proof.size(),consensus.max_proof_bytes,0};
        case Step::BLOCK_HASH:
            return {BmmProofCommitment(block.m_bmm_proof) == block.hashBmmProof,0,0,0};
        case Step::BLOCK_PRIOR:
            return {proof.previous_state == expected_previous,0,0,0};
        case Step::PARENT_COINBASE:
            return {!block.vtx.empty(),0,0,0};
        case Step::BLOCK_ENTRIES:
            critical_hash = block.GetBmmCriticalHash();
            return {1,0,0,0};
        default: return entries(step);
        }
    }
};
} // namespace

bool VerifyBmmProof(
    const CBlock& block,
    const BmmL1State& expected_previous,
    BmmL1State& next_state,
    std::string& error,
    const BmmConsensus& consensus)
{
    BmmBlockProofNative proof{block, expected_previous, next_state, error, consensus};
    return haskell::RunReplayStore(haskell::ReplayStoreWorkflow::PROOF_BLOCK, std::ref(proof.native)) == 1;
}

namespace {

struct BmmStateNative {
    const BmmL1State& state;
    BmmL1State* output{nullptr};
    const CCoinsViewCache* view{nullptr};
    const CBlockIndex* previous{nullptr};
    BmmParentContext* context{nullptr};
    std::string* error{nullptr};
    const Coin* coin{nullptr};
    CScript::const_iterator cursor;
    std::vector<unsigned char> data, marker;
    std::optional<DataStream> stream;

    static std::vector<unsigned char> Words(std::initializer_list<uint64_t> values)
    {
        std::vector<unsigned char> bytes(values.size()*8);
        size_t offset = 0;
        for (auto value : values) { WriteLE64(bytes.data()+offset, value); offset += 8; }
        return bytes;
    }

    std::vector<unsigned char> operator()(uint32_t step, uint64_t index, std::span<const unsigned char> input)
    {
        if ((index != 0 && !(step == 33 && index == 1)) ||
            (!input.empty() && step != 26 && step != 33 && step != 90)) throw std::logic_error("invalid BMM state request");
        if (step >= 2 && step <= 12 && !coin) throw std::logic_error("missing BMM state coin");
        const auto observe = [&]() -> std::vector<unsigned char> {
            switch (step) {
            case 1:
                if (!view) throw std::logic_error("missing BMM coin view");
                coin = &view->AccessCoin(Identity().outpoint);
                cursor = coin->out.scriptPubKey.begin();
                return Words({uint64_t(!coin->IsSpent())});
            case 2: return Words({uint64_t(!coin->IsSpent())});
            case 3: return Words({uint64_t(coin->out.nAsset.IsExplicit())});
            case 4: return Words({uint64_t(coin->out.nAsset.GetAsset() == Params().GetConsensus().pegged_asset)});
            case 5: return Words({uint64_t(coin->out.nValue.IsExplicit())});
            case 6: return Words({uint64_t(coin->out.nValue.GetAmount() == 0)});
            case 10: case 11: case 12: {
                opcodetype opcode{OP_INVALIDOPCODE};
                const bool parsed = step == 10 ? coin->out.scriptPubKey.GetOp(cursor, opcode, data) :
                    coin->out.scriptPubKey.GetOp(cursor, opcode);
                return Words({uint64_t(parsed) | (uint64_t(step == 12 && cursor == coin->out.scriptPubKey.end()) << 1),
                    uint64_t(parsed ? opcode : 0)});
            }
            case 20: stream.emplace(data); *stream >> marker; return {};
            case 21:
                if (!output || !stream) throw std::logic_error("missing BMM state output");
                *stream >> *output; return {};
            case 22:
                if (!stream) throw std::logic_error("missing BMM state payload");
                return Words({uint64_t(stream->empty()) | (uint64_t(marker == Identity().marker) << 1)});
            case 23: return Words({uint64_t(!state.block_hash.IsNull()), state.height, state.block_time, state.n_bits,
                state.period_start_height, state.period_start_time, state.recent_times.size(),
                state.recent_times.empty() ? 0 : state.recent_times.back()});
            case 24: case 32: return BmmHeaderObservation(nullptr, 2, 0, {});
            case 25: {
                if (state.recent_times.size() != 11) throw std::logic_error("invalid BMM context history size");
                std::vector<unsigned char> bytes(88);
                for (size_t i = 0; i < 11; ++i) WriteLE64(bytes.data()+8*i, state.recent_times[i]);
                return bytes;
            }
            case 26:
                if (!context || input.size() != 8) throw std::logic_error("invalid BMM context publication");
                *context = {state.block_hash, state.height, ReadLE64(input.data())};
                return Words({1});
            case 30: return Words({uint64_t(bool(Params().GetConsensus().drivechain_slot))});
            case 31: return Words({uint64_t(previous && previous->GetBlockHash() == Identity().blocks[1])});
            case 33: {
                if (!output || input.size() != 96) throw std::logic_error("invalid BMM checkpoint output");
#ifndef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
                if (index) throw std::logic_error("private BMM checkpoint is disabled");
#endif
                std::array<uint32_t,16> fields{};
                for (size_t i = 0; i < fields.size(); ++i) fields[i] = ReadLE32(input.data()+32+4*i);
                *output = {uint256{input.data(),32}, fields[0], fields[1], fields[2], fields[3], fields[4],
                    {fields.begin()+5, fields.end()}};
                return Words({1});
            }
            case 90:
                if (error) error->assign(input.begin(), input.end());
                return Words({1});
            default: throw std::logic_error("unknown BMM state observation");
            }
        };
        if (step < 20 || step > 25) return observe();
        const auto owned = [&] { auto bytes = observe(); bytes.insert(bytes.begin(), 1); return bytes; };
        if (!output) return owned();
        try { return owned(); } catch (...) { return {0}; }
    }
};

} // namespace

bool GetBmmState(const CCoinsViewCache& view, BmmL1State& state, std::string* error)
{
    BmmStateNative native{.state=state, .output=&state, .view=&view, .error=error};
    return haskell::RunReplayStore(haskell::ReplayStoreWorkflow::BMM_STATE_READ, std::ref(native)) == 1;
}

bool GetBmmParentContext(const BmmL1State& state, BmmParentContext& context, std::string& error)
{
    error.clear();
    context = {};
    BmmStateNative native{.state=state, .context=&context, .error=&error};
    return haskell::RunReplayStore(haskell::ReplayStoreWorkflow::BMM_STATE_CONTEXT, std::ref(native)) == 1;
}

bool GetEffectiveBmmState(const CCoinsViewCache& view, const CBlockIndex* previous, BmmL1State& state, std::string& error)
{
    BmmStateNative native{.state=state, .output=&state, .view=&view, .previous=previous, .error=&error};
    return haskell::RunReplayStore(haskell::ReplayStoreWorkflow::BMM_STATE_EFFECTIVE, std::ref(native)) == 1;
}

namespace {
struct BmmChainNative {
    const CBlock& block;
    const CBlockIndex* previous;
    CCoinsViewCache& view;
    const int height;
    const bool allow_incomplete;
    std::string& error;
    BmmL1State current{}, next{};
    BmmConsensus consensus{};
    BmmStateNative state{.state=current, .output=&current, .view=&view, .previous=previous, .error=&error};
    BmmBlockProofNative proof{block, current, next, error, consensus};
    std::optional<BmmStateStorageNative> storage{};

    std::vector<unsigned char> operator()(uint32_t step, uint64_t index, std::span<const unsigned char> input)
    {
        if (step >= 1000 && step <= 1011) {
            if (step != 1010 && step != 1011) return BmmHeaderObservation(previous, step-1000, index, input);
            return BmmHeaderPolicyObservation(block.nVersion, block.hashBmmProof, block.GetHash(), previous,
                error, false, step-1000, index, input);
        }
        if (step >= 2000 && step <= 2090) return state(step-2000, index, input);
        if (step >= 3000 && step <= 3790) return proof.native(step-3000, index, input);
        if (step >= 4000 && step <= 4016) {
            if (!storage) throw std::logic_error("missing BMM storage projection");
            return (*storage)(step-4000, index, input);
        }
        if (index != 0 && step != 5000) throw std::logic_error("invalid BMM chain index");
        if (!input.empty() && step != 90 && step != 2999) throw std::logic_error("invalid BMM chain payload");
        uint64_t result{1};
        switch (step) {
        case 0: result = bool(Params().GetConsensus().drivechain_slot); break;
        case 1: result = block.HasBmmProof(); break;
        case 2: result = !block.m_bmm_proof.empty(); break;
        case 3: result = block.hashBmmProof.IsNull(); break;
        case 4: result = allow_incomplete; break;
        case 5: result = HasPersistedBmmConsensusState(view); break;
        case 6: result = view.SpendCoin(Identity().outpoint); break;
        case 7: result = current == next; break;
        case 8: return SerializeValue(current);
        case 10: result = block.GetHash() == Identity().blocks[1]; break;
        case 11: result = previous != nullptr; break;
        case 12:
            if (!previous) throw std::logic_error("missing BMM checkpoint predecessor");
            result = previous->GetBlockHash() == Identity().blocks[0]; break;
        case 90: error.assign(input.begin(), input.end()); break;
        case 92: return {error.begin(), error.end()};
        case 2998: proof.critical_hash = block.GetBmmCriticalHash(); break;
        case 2999: {
            if (input.size() < 80 || input.size() > 102) throw std::logic_error("invalid BMM consensus projection");
            const auto field = [&](size_t i) { return ReadLE64(input.data()+8*i); };
            consensus = {uint256{input.data()+48,32}, static_cast<int64_t>(field(0)),
                static_cast<int64_t>(field(1)), CScript(input.begin()+80, input.end()),
                static_cast<int>(field(2)), field(3), field(4), bool(field(5))};
            break;
        }
        case 5000:
            if (index > 2 || storage) throw std::logic_error("invalid BMM storage selection");
            storage.emplace(BmmStateStorageNative{view, index == 0 ? current : index == 1 ? next : proof.proof.previous_state, height});
            break;
        default: throw std::logic_error("invalid BMM chain observation");
        }
        return SerializeValue(result);
    }
};
} // namespace

bool ConnectBmmState(
    const CBlock& block,
    const CBlockIndex* previous,
    CCoinsViewCache& view,
    const int height,
    const bool allow_incomplete_candidate,
    std::string& error)
{
    BmmChainNative native{block, previous, view, height, allow_incomplete_candidate, error};
    return haskell::RunReplayStore(haskell::ReplayStoreWorkflow::CHAIN_CONNECT, std::ref(native)) == 1;
}

bool DisconnectBmmState(
    const CBlock& block,
    const CBlockIndex* previous,
    CCoinsViewCache& view,
    const int height,
    std::string& error)
{
    BmmChainNative native{block, previous, view, height, false, error};
    return haskell::RunReplayStore(haskell::ReplayStoreWorkflow::CHAIN_DISCONNECT, std::ref(native)) == 1;
}

} // namespace drivechain
