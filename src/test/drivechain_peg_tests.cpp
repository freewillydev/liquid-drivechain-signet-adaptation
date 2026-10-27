// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/haskell_reference.h>
#include <drivechain_bmm.h>
#include <drivechain_peg.h>
#include <drivechain_parent_replay.h>
#include <drivechain_withdrawal.h>
#include <drivechain_settings.h>
#include <haskell/bridge.h>
#include <haskell/wallet_rpc.h>
#include <hash.h>

#include <arith_uint256.h>
#include <bech32.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <key_io.h>
#include <mainchainrpc.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <node/drivechain_withdrawal_bundle.h>
#include <node/drivechain_withdrawal_journal.h>
#include <rpc/request.h>
#include <pegins.h>
#include <primitives/bitcoin/block.h>
#include <primitives/bitcoin/merkleblock.h>
#include <primitives/transaction.h>
#include <script/solver.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <util/moneystr.h>
#include <wallet/rpc/util.h>
#include <wallet/db.h>
#include <streams.h>

#include <boost/test/unit_test.hpp>

#include <chrono>
#include <atomic>
#include <deque>
#include <fstream>
#include <map>
#include <ranges>
#include <tuple>
#include <mutex>

#ifndef WIN32
#include <sys/stat.h>
#endif

// Sealed predecessor adapters. The production RPC executes the complete
// withdrawal workflow in Haskell; these remain test-only compatibility oracles.
namespace wallet {
void CheckWithdrawal(WithdrawalCheck check, bool value)
{
    const std::array<unsigned char,2> input{static_cast<unsigned char>(check),value};
    std::vector<unsigned char> output;
    if (!drivechain::haskell::WithdrawalBytes(drivechain::haskell::WithdrawalOp::NATIVE_GUARD_RESULT,input,output,nullptr))
        throw std::runtime_error("Haskell withdrawal guard evaluation failed");
    if (const auto code = static_cast<int32_t>(ReadLE32(output.data())); code != 0)
        throw JSONRPCError(code,std::string(output.begin()+4,output.end()));
}

CAmount ValidateNativePayout(const CScript& destination, CAmount payout)
{
    static_assert(DUST_RELAY_TX_FEE_BITCOIN == 3000);
    std::array<unsigned char,13> input{};
    int version{0};
    std::vector<unsigned char> program, output;
    WriteLE64(input.data(),payout);
    input[12] = destination.IsWitnessProgram(version,program);
    WriteLE32(input.data()+8, static_cast<uint32_t>(GetSerializeSize(Sidechain::Bitcoin::CTxOut(0,destination))));
    if (!drivechain::haskell::WithdrawalBytes(drivechain::haskell::WithdrawalOp::NATIVE_PAYOUT,input,output,nullptr) || output.size()!=12)
        throw std::runtime_error("Haskell native payout evaluation failed");
    const auto code=static_cast<int32_t>(ReadLE32(output.data()));
    if (code == RPC_TYPE_ERROR) throw JSONRPCError(code,"Invalid withdrawal payout amount");
    if (code == RPC_INVALID_PARAMETER) throw JSONRPCError(code,strprintf(
        "Bitcoin withdrawal payout is dust for this destination (minimum %s)",FormatMoney(ReadLE64(output.data()+4))));
    if (code != 0) throw std::runtime_error("Invalid Haskell native payout result");
    return payout;
}

CAmount PrepareNativeBurn(const uint256& parent, const CScript& destination,
    CAmount payout, CAmount fee, CScript& burn)
{
    std::vector<unsigned char> input(16), output;
    WriteLE64(input.data(),payout);
    WriteLE64(input.data()+8,fee);
    input.insert(input.end(),parent.begin(),parent.end());
    input.insert(input.end(),destination.begin(),destination.end());
    burn.clear();
    if (!drivechain::haskell::WithdrawalBytes(drivechain::haskell::WithdrawalOp::NATIVE_BURN_PLAN,input,output,nullptr))
        throw std::runtime_error("Haskell native burn planning failed");
    const auto code=static_cast<int32_t>(ReadLE32(output.data()));
    if (code == RPC_TYPE_ERROR || code == RPC_INVALID_PARAMETER)
        throw JSONRPCError(code,std::string(output.begin()+4,output.end()));
    if (code != 0 || output.size()<12) throw std::runtime_error("Invalid Haskell native burn plan");
    burn.assign(output.begin()+12,output.end());
    return static_cast<CAmount>(ReadLE64(output.data()+4));
}

CAmount LegacyWithdrawalAmount(CAmount payout)
{
    std::array<unsigned char,17> input{};
    input[0] = 2;
    WriteLE64(input.data()+1, payout);
    std::vector<unsigned char> output;
    std::string error;
    if (!drivechain::haskell::WithdrawalBytes(drivechain::haskell::WithdrawalOp::NATIVE_AMOUNT, input, output, &error))
        throw JSONRPCError(RPC_TYPE_ERROR, error);
    return static_cast<CAmount>(ReadLE64(output.data()));
}

uint32_t FindNativeWithdrawalOutput(const CTransaction& tx, const CScript& burn_script,
    const CAsset& asset, const uint256& parent_genesis, CAmount burn, CAmount payout, CAmount fee)
{
    std::vector<unsigned char> input(asset.begin(),asset.end()), output;
    input.insert(input.end(),parent_genesis.begin(),parent_genesis.end());
    input.resize(92);
    WriteLE64(input.data()+64,burn); WriteLE64(input.data()+72,payout); WriteLE64(input.data()+80,fee);
    WriteLE32(input.data()+88,static_cast<uint32_t>(burn_script.size()));
    input.insert(input.end(),burn_script.begin(),burn_script.end());
    for (uint32_t index=0; index<tx.vout.size(); ++index) {
        const auto& candidate=tx.vout[index];
        const size_t offset=input.size();
        input.resize(offset+49);
        WriteLE32(input.data()+offset,index);
        const CAsset actual=candidate.nAsset.IsExplicit() ? candidate.nAsset.GetAsset() : CAsset{};
        std::copy(actual.begin(),actual.end(),input.begin()+offset+4);
        input[offset+36]=candidate.nAsset.IsExplicit(); input[offset+37]=candidate.nValue.IsExplicit();
        input[offset+38]=candidate.nNonce.IsNull();
        input[offset+39]=index>=tx.witness.vtxoutwit.size() || tx.witness.vtxoutwit[index].IsNull();
        WriteLE64(input.data()+offset+40,candidate.nValue.IsExplicit() ? candidate.nValue.GetAmount() : 0);
        input[offset+48]=candidate.scriptPubKey == burn_script;
    }
    if (!drivechain::haskell::WithdrawalBytes(drivechain::haskell::WithdrawalOp::NATIVE_OUTPUT_SELECTION,input,output,nullptr))
        throw std::runtime_error("Haskell native output selection failed");
    const auto code=static_cast<int32_t>(ReadLE32(output.data()));
    if (code == RPC_WALLET_ERROR) throw JSONRPCError(code,std::string(output.begin()+4,output.end()));
    if (code != 0 || output.size()!=8) throw std::runtime_error("Invalid Haskell native output selection");
    return ReadLE32(output.data()+4);
}

namespace {
static std::array<unsigned char,40> WithdrawalInputContext(const COutPoint& outpoint, uint32_t height)
{
    std::array<unsigned char,40> context{};
    std::copy_n(UCharCast(outpoint.hash.begin()),32,context.begin());
    WriteLE32(context.data()+32,outpoint.n);
    WriteLE32(context.data()+36,height);
    return context;
}

DrivechainWithdrawalBundle BuildBundle(
    CAmount amount, CAmount mainchain_fee, const CScript& payout_script,
    const COutPoint& withdrawal_outpoint, uint32_t sidechain_block_height,
    std::span<const unsigned char> anchor_context)
{
    static_assert(MAX_SCRIPT_SIZE == 10000);
    Sidechain::Bitcoin::CMutableTransaction tx;
    DrivechainWithdrawalBundle result;
    result.bytes = drivechain::haskell::BuildWithdrawalBundle(amount, mainchain_fee,
        payout_script.size(), !withdrawal_outpoint.IsNull(), [&](const auto& plan) -> const std::vector<unsigned char>& {
        tx.version = plan.version;
        for (const auto role : plan.outputs) {
            switch (role) {
            case 0: tx.vout.emplace_back(0, CScript(plan.fee_script.begin(),plan.fee_script.end())); break;
            case 1: tx.vout.emplace_back(0, CScript() << OP_RETURN << ToByteVector(Hash(plan.inputs))); break;
            case 2: tx.vout.emplace_back(plan.payout,payout_script); break;
            case 3: tx.vout.emplace_back(0, CScript(plan.marker.begin(),plan.marker.end())); break;
            default: throw std::logic_error("invalid withdrawal output role");
            }
        }
        VectorWriter{result.no_witness_bytes, 0, TX_NO_WITNESS(tx)};
        result.m6id = tx.GetHash();
        return result.no_witness_bytes;
    }, WithdrawalInputContext(withdrawal_outpoint,sidechain_block_height), anchor_context);
    return result;
}
} // namespace

std::string FindWithdrawalBundleEventStatus(const UniValue& peg_data, const std::string& m6id_hex)
{
    const UniValue& blocks = peg_data["blocks"];
    std::vector<UniValue>::const_iterator block_it, event_it;
    const UniValue *events{nullptr}, *bundle{nullptr}, *m6id{nullptr}, *status{nullptr};
    std::vector<unsigned char> bytes;
    uint256 event_m6id;
    const auto selected = drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::WITHDRAWAL_EVENT,
        [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return blocks.isArray();
        case 2: block_it = blocks.getValues().begin(); return 1;
        case 3: return block_it != blocks.getValues().end();
        case 4: events = &(*block_it)["blockInfo"]["events"]; return events->isArray();
        case 5: event_it = events->getValues().begin(); return 1;
        case 6: ++block_it; return 1;
        case 7: return event_it != events->getValues().end();
        case 8: bundle = &(*event_it)["withdrawalBundle"]; return bundle->isObject();
        case 9: m6id = &(*bundle)["m6id"]["hex"]; return m6id->isStr();
        case 10: ++event_it; return 1;
        case 11: bytes = ParseHex(m6id->get_str()); return std::min<size_t>(bytes.size(), UINT32_MAX);
        case 12: std::copy(bytes.begin(), bytes.end(), event_m6id.begin()); return event_m6id.GetHex() == m6id_hex;
        case 13: status = &(*bundle)["event"]; return status->isObject();
        case 14: return !(*status)["submitted"].isNull();
        case 15: return !(*status)["succeeded"].isNull();
        case 16: return !(*status)["failed"].isNull();
        default: throw std::logic_error("invalid withdrawal event step");
        }
    });
    return drivechain::WITHDRAWAL_STATE_NAMES[selected];
}

CScript DecodeDrivechainWithdrawalDestination(const std::string& destination)
{
    static_assert(static_cast<int>(TxoutType::PUBKEY) == 2 && static_cast<int>(TxoutType::PUBKEYHASH) == 3 &&
        static_cast<int>(TxoutType::SCRIPTHASH) == 4 && static_cast<int>(TxoutType::MULTISIG) == 5 &&
        static_cast<int>(TxoutType::WITNESS_V0_SCRIPTHASH) == 7 && static_cast<int>(TxoutType::WITNESS_V0_KEYHASH) == 8 &&
        static_cast<int>(TxoutType::WITNESS_V1_TAPROOT) == 9);
    static_assert(drivechain::NATIVE_WITHDRAWAL_MAX_DESTINATION_SIZE == 128);
    CScript script;
    std::string hex, error;
    CTxDestination address;
    TxoutType type{TxoutType::NONSTANDARD};
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::WITHDRAWAL_DESTINATION, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return destination.starts_with("hex:");
        case 2: hex = destination.substr(4); return std::min<size_t>(hex.size(), UINT32_MAX);
        case 3: return IsHex(hex);
        case 4: throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "hex: destination must be a nonempty, bounded hexadecimal scriptPubKey");
        case 5: address = DecodeParentDestination(destination, error); return IsValidDestination(address);
        case 6: {
            const auto bytes = ParseHex(hex);
            script = CScript(bytes.begin(), bytes.end()); return 1;
        }
        case 8: script = GetScriptForDestination(address); return 1;
        case 9: return std::min<size_t>(script.size(), UINT32_MAX);
        case 10: throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address: " + error);
        case 11: return IsStandard(script, std::nullopt, type);
        case 12: throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Bitcoin destination must be a standard script of 1..128 bytes");
        case 13: return static_cast<uint32_t>(type);
        case 14: throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Bitcoin destination must be a recognized spendable script");
        default: throw std::logic_error("invalid withdrawal destination step");
        }
    });
    return script;
}

DrivechainWithdrawalBundle BuildDrivechainWithdrawalBundle(
    CAmount amount, CAmount mainchain_fee, const CScript& payout_script,
    const COutPoint& withdrawal_outpoint, uint32_t sidechain_block_height)
{
    return BuildBundle(amount, mainchain_fee, payout_script, withdrawal_outpoint,
                       sidechain_block_height, {});
}

DrivechainWithdrawalBundle BuildDrivechainWithdrawalBundle(
    CAmount amount, CAmount mainchain_fee, const CScript& payout_script,
    const COutPoint& withdrawal_outpoint, uint32_t sidechain_block_height,
    const uint256& child_genesis, const uint256& previous_child_hash,
    const uint256& exchange_state_root)
{
    std::array<unsigned char,96> anchor_context{};
    std::copy_n(child_genesis.begin(),32,anchor_context.begin());
    std::copy_n(previous_child_hash.begin(),32,anchor_context.begin()+32);
    std::copy_n(exchange_state_root.begin(),32,anchor_context.begin()+64);
    try {
        return BuildBundle(amount, mainchain_fee, payout_script, withdrawal_outpoint,
                           sidechain_block_height, anchor_context);
    } catch (const drivechain::haskell::WithdrawalAnchorError& error) {
        throw JSONRPCError(RPC_MISC_ERROR,error.what());
    }
}
} // namespace wallet

namespace {

const std::string MAINCHAIN_TIP{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
const std::string DEPOSIT_BLOCK{"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"};
const std::string DEPOSIT_TXID{"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"};
const std::string NEXT_CTIP_TXID{"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"};
const std::string SIGNET_CHALLENGE{"00148835832e28c816b7acd8fdb19772ab2199603a56"};
const std::string HASH_ID_1{"5883560531f013b9b27b2f9cfbac4f64ee5062b95ad3e21593a8f6916530b74b"};
const std::string HASH_ID_2{"b2b7b20f3fbc4baf50e9d39f58661c6168e279d4"};

bool OriginalReplayTip(const DrivechainParentReplayTip& tip)
{
    using Kind = drivechain::haskell::ReplayRecordKind;
    const auto height_valid = [&](uint32_t height) {
        return drivechain::haskell::ParentReplayRecord(Kind::HEIGHT, 0, 0, height, tip.height);
    };
    const auto* active = &tip.state.active_proposal_hash;
    const auto* ctip = &tip.state.ctip;
    auto value = tip.state.ctip_value;
    const auto* proposals = &tip.state.pending_proposals;
    const auto* withdrawals = &tip.state.pending_withdrawals;
    auto proposal = proposals->begin();
    size_t withdrawal{0};
    auto slot = tip.state.other_slots.begin();
    auto action = tip.state.previous_m4_actions.begin();
    auto action_slot = tip.state.other_slots.end();
    bool configured{true}, configured_action_seen{false};
    std::set<uint256> m6ids;
    std::set<Sidechain::Bitcoin::COutPoint> ctips;
    return drivechain::haskell::ParentReplayTip([&](uint32_t step) {
        switch (step) {
        case 1: return !tip.hash.IsNull();
        case 2: return tip.state.required_proposal_activated;
        case 3: return !tip.state.active_proposal_hash.IsNull();
        case 4: return !tip.state.required_activation_block_hash.IsNull();
        case 5: return height_valid(tip.state.required_activation_height);
        case 6: return tip.state.required_activation_height == 0;
        case 7: return tip.state.required_activation_block_hash.IsNull();
        case 8: case 27: case 34: case 39: return ctip->has_value();
        case 9: case 35: return value == 0;
        case 10: case 24: case 32: return !active->IsNull();
        case 11: case 38: return drivechain::haskell::ParentReplayRecord(Kind::AMOUNT, 0, value, 0, MAX_MONEY);
        case 12: proposal = proposals->begin(); return true;
        case 13: return proposal != proposals->end();
        case 14: return !proposal->first.IsNull();
        case 15: return height_valid(proposal->second.proposal_height);
        case 16: return drivechain::haskell::ParentReplayRecord(Kind::PROPOSAL_VOTES, 0,
            proposal->second.votes, tip.height, proposal->second.proposal_height);
        case 17: ++proposal; return true;
        case 18: withdrawal = 0; m6ids.clear(); return true;
        case 19: return withdrawal < withdrawals->size();
        case 20: return height_valid((*withdrawals)[withdrawal].proposal_height);
        case 21: return drivechain::haskell::ParentReplayRecord(Kind::WITHDRAWAL_VOTES, 0,
            (*withdrawals)[withdrawal].votes, tip.height, (*withdrawals)[withdrawal].proposal_height);
        case 22: return m6ids.insert((*withdrawals)[withdrawal].m6id).second;
        case 23: ++withdrawal; return true;
        case 25: return withdrawals->empty();
        case 26: return configured;
        case 28: ctips.insert(**ctip); return true;
        case 29: slot = tip.state.other_slots.begin(); return true;
        case 30: return slot != tip.state.other_slots.end();
        case 31:
            configured = false;
            active = &slot->second.active_proposal_hash;
            ctip = &slot->second.ctip;
            value = slot->second.ctip_value;
            proposals = &slot->second.pending_proposals;
            withdrawals = &slot->second.pending_withdrawals;
            return true;
        case 33: return !ctip->has_value();
        case 36: ++slot; return true;
        case 40: action = tip.state.previous_m4_actions.begin(); return true;
        case 41: return ctips.insert(**ctip).second;
        case 42: return action != tip.state.previous_m4_actions.end();
        case 43: return action->second.type == DrivechainM4ActionType::UPVOTE;
        case 44: return action->second.type == DrivechainM4ActionType::ALARM;
        case 45: return action->second.m6id.IsNull();
        case 46:
            action_slot = tip.state.other_slots.find(action->first);
            return action_slot != tip.state.other_slots.end();
        case 47: return !action_slot->second.active_proposal_hash.IsNull();
        case 48: return configured_action_seen;
        case 49: return !tip.state.active_proposal_hash.IsNull();
        case 50: configured_action_seen = true; return true;
        case 51: ++action; return true;
        default: throw std::logic_error("invalid parent replay tip action");
        }
    });
}

UniValue ParseJson(const std::string& json)
{
    UniValue result;
    if (!result.read(json)) throw std::runtime_error("invalid test JSON: " + json);
    return result;
}

std::string TestDepositAddress()
{
    return EncodeDestination(WitnessV0KeyHash(uint160(ParseHex("00112233445566778899aabbccddeeff00112233"))));
}

UniValue MainchainInfo(
    const std::string& chain = "signet",
    const std::string& challenge = SIGNET_CHALLENGE,
    bool ibd = false)
{
    return ParseJson(strprintf(
        R"json({"chain":"%s","blocks":100,"bestblockhash":"%s","initialblockdownload":%s,"signet_challenge":"%s"})json",
        chain,
        MAINCHAIN_TIP,
        ibd ? "true" : "false",
        challenge));
}

UniValue EnforcerChainInfo(const std::string& network = "NETWORK_SIGNET")
{
    return ParseJson(strprintf(R"json({"network":"%s"})json", network));
}

UniValue EnforcerTip(const std::string& hash = MAINCHAIN_TIP, int64_t height = 100)
{
    return ParseJson(strprintf(
        R"json({"blockHeaderInfo":{"blockHash":{"hex":"%s"},"height":"%d"}})json",
        hash,
        height));
}

UniValue Sidechains(
    int slot = 24,
    const std::string& title = "Elements",
    const std::string& hash_id_1 = HASH_ID_1,
    const std::string& hash_id_2 = HASH_ID_2)
{
    return ParseJson(strprintf(
        R"json({"sidechains":[{"sidechainNumber":%d,"activationHeight":50,"declaration":{"v0":{"title":"%s","hashId1":{"hex":"%s"},"hashId2":{"hex":"%s"}}}}]})json",
        slot,
        title,
        hash_id_1,
        hash_id_2));
}

UniValue TwoWayPegData(
    const std::string& txid = DEPOSIT_TXID,
    int64_t vout = 0,
    const std::string& address = TestDepositAddress(),
    int64_t value = 2000,
    int64_t sequence = 8,
    bool include_event = true)
{
    const std::string address_hex = HexStr(address);
    const std::string events = include_event
        ? strprintf(
            R"json([{"deposit":{"sequenceNumber":"%d","outpoint":{"txid":{"hex":"%s"},"vout":%d},"output":{"address":{"hex":"%s"},"valueSats":"%d"}}}])json",
            sequence,
            txid,
            vout,
            address_hex,
            value)
        : "[]";
    return ParseJson(strprintf(
        R"json({"blocks":[{"blockHeaderInfo":{"blockHash":{"hex":"%s"},"height":90},"blockInfo":{"events":%s}}]})json",
        DEPOSIT_BLOCK,
        events));
}

UniValue Ctip(
    const std::string& txid = DEPOSIT_TXID,
    int64_t value = 14'402'000,
    int64_t sequence = 8,
    int64_t vout = 0)
{
    return ParseJson(strprintf(
        R"json({"ctip":{"txid":{"hex":"%s"},"vout":%d,"value":"%d","sequenceNumber":"%d"}})json",
        txid,
        vout,
        value,
        sequence));
}

drivechain::DepositIdentity Identity()
{
    drivechain::DepositIdentity identity;
    identity.sidechain_slot = 24;
    identity.sidechain_network = Params().NetworkIDString();
    identity.mainchain_network = "signet";
    identity.mainchain_signet_challenge = SIGNET_CHALLENGE;
    identity.enforcer_network = "NETWORK_SIGNET";
    identity.mainchain_genesis = Params().ParentGenesisBlockHash();
    identity.title = "Elements";
    identity.hash_id_1 = HASH_ID_1;
    identity.hash_id_2 = HASH_ID_2;
    return identity;
}

bool Authenticate(
    drivechain::AuthenticatedDeposit& authenticated,
    std::string& error,
    const UniValue& mainchain_info = MainchainInfo(),
    const UniValue& enforcer_chain_info = EnforcerChainInfo(),
    const UniValue& enforcer_tip = EnforcerTip(),
    const UniValue& sidechains = Sidechains(),
    const UniValue& two_way_peg_data = TwoWayPegData(),
    const UniValue& ctip = Ctip(),
    const std::string& sidechain_network = Params().NetworkIDString(),
    const drivechain::DepositIdentity& identity = Identity(),
    const COutPoint& outpoint = COutPoint(Txid::FromUint256(uint256S(DEPOSIT_TXID)), 0),
    CAmount value = 2000)
{
    return drivechain::AuthenticateDepositEvidence(
        mainchain_info,
        Params().ParentGenesisBlockHash(),
        enforcer_chain_info,
        enforcer_tip,
        sidechains,
        two_way_peg_data,
        ctip,
        sidechain_network,
        identity,
        outpoint,
        value,
        authenticated,
        error);
}

CMutableTransaction DepositTransaction(
    const drivechain::AuthenticatedDeposit& authenticated,
    const CScript& destination_script,
    CAmount credit = 1900,
    CAmount fee = 100)
{
    CMutableTransaction tx;
    tx.version = 2;
    CTxIn input(authenticated.outpoint, CScript(), CTxIn::SEQUENCE_FINAL);
    input.m_is_pegin = true;
    tx.vin.push_back(input);
    tx.vout.emplace_back(Params().GetConsensus().pegged_asset, credit, destination_script);
    if (fee > 0) {
        tx.vout.emplace_back(Params().GetConsensus().pegged_asset, fee, CScript());
    }
    tx.witness.vtxinwit.resize(1);
    tx.witness.vtxoutwit.resize(tx.vout.size());
    tx.witness.vtxinwit[0].m_pegin_witness = CreateDrivechainDepositPeginWitness(
        authenticated.value,
        Params().GetConsensus().pegged_asset,
        Params().ParentGenesisBlockHash(),
        CScript() << OP_TRUE,
        authenticated.outpoint.hash);
    return tx;
}

template <typename T>
std::vector<unsigned char> Serialize(const T& value)
{
    DataStream stream;
    stream << TX_WITH_WITNESS(value);
    return {
        UCharCast(stream.data()),
        UCharCast(stream.data()) + stream.size()};
}

CScript CtipScript(const opcodetype opcode = OP_NOP5)
{
    return CScript() << opcode << std::vector<unsigned char>{24} << OP_1;
}

struct SlotAssignedPeginSetup : BasicTestingSetup {
    SlotAssignedPeginSetup() : BasicTestingSetup(ChainType::ELEMENTS) {}
};

class DrivechainPegTestingSetup : public BasicTestingSetup
{
public:
    DrivechainPegTestingSetup()
        : BasicTestingSetup(
              ChainTypeMetaFrom("liquid-signet"),
              {.extra_args = {
                  "-con_elementsmode=1",
                  "-con_has_parent_chain=1",
                  "-parentgenesisblockhash=00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
                  "-parentpubkeyprefix=111",
                  "-parentscriptprefix=196",
                  "-parent_bech32_hrp=tb",
                  "-parent_blech32_hrp=tb",
                  "-bech32_hrp=ert",
                  "-blech32_hrp=el",
              }})
    {
    }
};

CTransaction LegacyPublicDeposit()
{
    CMutableTransaction tx;
    DataStream stream(
        ParseHex("020000000101ea6bf0d0cd29414c524e1bfb175299dcb945f438200d596bbe4ba547b7aee47d0000004000ffffffff0201579008c2884b22c31d545e3887d73efd5a412d16aeb9bd8ccbeba8eaa605b71101000000000000076c001600142ab51216604aace97fd71de08cbb29078f42b8b101579008c2884b22c31d545e3887d73efd5a412d16aeb9bd8ccbeba8eaa605b7110100000000000000640000000000000000000608d00700000000000020579008c2884b22c31d545e3887d73efd5a412d16aeb9bd8ccbeba8eaa605b71120f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e9739881080000000151156472697665636861696e2d6465706f7369742d763120ea6bf0d0cd29414c524e1bfb175299dcb945f438200d596bbe4ba547b7aee47d00000000"));
    stream >> TX_WITH_WITNESS(tx);
    BOOST_REQUIRE(stream.empty());
    return CTransaction(tx);
}

bool ReferenceVerifyDepositTransaction(
    const CTransaction& tx,
    const size_t input_index,
    const drivechain::AuthenticatedDeposit& authenticated,
    std::string& error)
{
    return [&] {
        uint32_t facts{0};
        CAmount witness_value{0};
        std::array<unsigned char, 2> flags{};
        std::array<int64_t, 2> amounts{};
        drivechain::haskell::DepositTransactionFacts([&](uint32_t step) -> uint64_t {
            switch (step) {
            case 1: return tx.vin.size();
            case 2: return input_index;
            case 3: return tx.witness.vtxinwit.size();
            case 4: {
                const auto& input = tx.vin[0];
                facts = input.m_is_pegin | ((input.prevout == authenticated.outpoint) << 1) |
                    (input.scriptSig.empty() << 2) | (input.assetIssuance.IsNull() << 3);
                return facts;
            }
            case 5: {
                CScript claim_script;
                uint256 mainchain_txid;
                const bool decoded = GetDrivechainDepositPeginData(tx.witness.vtxinwit[0].m_pegin_witness,
                    tx.vin[0].prevout, witness_value, claim_script, mainchain_txid);
                facts |= (decoded << 4) | ((mainchain_txid == authenticated.outpoint.hash) << 5) |
                    ((claim_script == (CScript() << OP_TRUE)) << 6);
                return 0;
            }
            case 7: case 9: return tx.vout.size();
            case 8: case 10: {
                const size_t i = (step - 8) / 2;
                const auto& output = tx.vout[i];
                flags[i] = (output.nAsset.IsExplicit() && output.nAsset.GetAsset() == Params().GetConsensus().pegged_asset) |
                    (output.nValue.IsExplicit() << 1) | (output.nNonce.IsNull() << 2) |
                    (output.scriptPubKey.empty() << 3) | ((output.scriptPubKey == authenticated.destination_script) << 4);
                amounts[i] = output.nValue.IsExplicit() ? output.nValue.GetAmount() : 0;
                return 0;
            }
            default: throw std::logic_error("invalid deposit fact projection action");
            }
        });
        return drivechain::haskell::AuthenticatedDeposit(tx.vin.size(), input_index, tx.witness.vtxinwit.size(), facts,
            authenticated.value, witness_value, tx.vout.size(), flags, amounts, error);
    }();
}

struct DeterministicFixture
{
    DrivechainDepositEvidence evidence;
    CTransactionRef transaction;
    uint256 anchor;

    explicit DeterministicFixture(const opcodetype opcode = OP_NOP5)
    {
        const std::vector<unsigned char> previous_raw = ParseHex(
            "02000000000102ba1b6b0b25cbed783a2bb5bcfcb18d54115388b1a53454417ea20ce06c2de8dd0100000000fdffffffabede444d25da6440680778541b4f5876388e10cd9da94f55a546eeab5700a010000000000ffffffff03d0c1db000000000004b401185100000000000000002d6a2b65727431713932363379396e7166326b776a6c3768726873676577656671373835397739337a356e3878388f1c00000000000016001420ee25f486b457599d671fec23be2a2ffbb8efc20247304402203cdbeac736b8c0b97fe7f9ad9b1d76fc7b60d2a7ef907942c52fd7481c509c5702201f27991af112244d8e159546587f0d2dd98f49e5a8eaed5919932a2d5f8f6dfa012103ddd93dd5a45116fb7febe151d9b4d9f7cdccc84ffb94dbe7d5665aa2bafed1dd00fe180000");
        Sidechain::Bitcoin::CMutableTransaction previous_tx;
        {
            DataStream stream(previous_raw);
            stream >> TX_WITH_WITNESS(previous_tx);
            BOOST_REQUIRE(stream.empty());
            BOOST_REQUIRE_EQUAL(
                previous_tx.GetHash().GetHex(),
                "7de4aeb747a54bbe6b590d2038f445b9dc995217fb1b4e524c4129cdd0f06bea");
        }

        Sidechain::Bitcoin::CMutableTransaction deposit_tx;
        deposit_tx.version = 2;
        deposit_tx.vin.emplace_back(
            Sidechain::Bitcoin::COutPoint(previous_tx.GetHash(), 0));
        deposit_tx.vout.emplace_back(14'404'000, CtipScript(opcode));
        const std::string address = TestDepositAddress();
        deposit_tx.vout.emplace_back(
            0,
            CScript() << OP_RETURN << std::vector<unsigned char>(address.begin(), address.end()));

        Sidechain::Bitcoin::CBlock l1_block;
        l1_block.nVersion = 1;
        l1_block.hashPrevBlock = uint256S("01");
        l1_block.hashMerkleRoot = deposit_tx.GetHash();
        l1_block.nTime = 1;
        l1_block.nBits = UintToArith256(Params().GetConsensus().parentChainPowLimit).GetCompact();
        while (!CheckParentProofOfWork(
            l1_block.GetHash(),
            l1_block.nBits,
            Params().GetConsensus())) {
            ++l1_block.nNonce;
        }
        l1_block.vtx = {Sidechain::Bitcoin::MakeTransactionRef(deposit_tx)};

        Sidechain::Bitcoin::CMerkleBlock proof;
        proof.header = l1_block.GetBlockHeader();
        proof.txn = Sidechain::Bitcoin::CPartialMerkleTree(
            {deposit_tx.GetHash()},
            {true});
        evidence.deposit_tx = Serialize(deposit_tx);
        evidence.txout_proof = Serialize(proof);
        evidence.previous_ctip_tx = previous_raw;
        evidence.sequence_number = 9;
        evidence.previous_sequence_number = 8;
        evidence.headers = {l1_block.GetBlockHeader()};
        anchor = l1_block.GetHash();

        drivechain::AuthenticatedDeposit authenticated;
        authenticated.outpoint = COutPoint(Txid::FromUint256(deposit_tx.GetHash()), 0);
        authenticated.value = 2'000;
        authenticated.destination_script = GetScriptForDestination(
            DecodeDestination(address));
        CMutableTransaction side_tx = DepositTransaction(
            authenticated,
            authenticated.destination_script);
        side_tx.witness.vtxinwit[0].m_pegin_witness =
            CreateDrivechainDepositPeginWitness(
                authenticated.value,
                Params().GetConsensus().pegged_asset,
                Params().ParentGenesisBlockHash(),
                CScript() << OP_TRUE,
                evidence);
        transaction = MakeTransactionRef(side_tx);
    }
};

class RestartablePeginView final : public CCoinsView
{
public:
    std::set<std::pair<uint256, COutPoint>> spent;
    std::map<COutPoint, Coin> coins;

    std::optional<Coin> GetCoin(const COutPoint& outpoint) const override
    {
        const auto it = coins.find(outpoint);
        if (it == coins.end() || it->second.IsSpent()) return std::nullopt;
        return it->second;
    }

    bool IsPeginSpent(const std::pair<uint256, COutPoint>& outpoint) const override
    {
        return spent.count(outpoint) != 0;
    }

    bool BatchWrite(CoinsViewCacheCursor& cursor, const uint256&) override
    {
        for (auto it = cursor.Begin(); it != cursor.End(); it = cursor.NextAndMaybeErase(*it)) {
            if (it->second.IsPegin() &&
                it->second.IsDirty()) {
                if (it->second.peginSpent) {
                    spent.insert(it->first);
                } else {
                    spent.erase(it->first);
                }
            } else if (it->second.IsDirty()) {
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

} // namespace

BOOST_FIXTURE_TEST_SUITE(drivechain_peg_tests, DrivechainPegTestingSetup)

BOOST_FIXTURE_TEST_CASE(federated_deposit_rejection_preserves_prefix_errors, SlotAssignedPeginSetup)
{
    BOOST_REQUIRE(Params().GetConsensus().drivechain_slot.has_value());
    const char* errors[]{"Peg-in witness has 5 stack items; expected 6.",
        "Could not deserialize value.", "Asset type was not 32 bytes.",
        "Parent genesis blockhash was not 32 bytes.", "Claim script is too large.",
        "Legacy federated peg-ins are disabled on a Drivechain network."};
    for (unsigned fault=0; fault<6; ++fault) {
        CScriptWitness witness;
        witness.stack = {std::vector<unsigned char>(8),std::vector<unsigned char>(32),
            std::vector<unsigned char>(32),{OP_TRUE},{},{}};
        switch (fault) {
        case 0: witness.stack.pop_back(); break;
        case 1: witness.stack[0].clear(); break;
        case 2: witness.stack[1].pop_back(); break;
        case 3: witness.stack[2].pop_back(); break;
        case 4: witness.stack[3].resize(101); break;
        }
        std::string error;
        bool depth_failed=true, parent_unavailable=true;
        BOOST_CHECK(!IsValidPeginWitness(witness,{},COutPoint{},error,false,&depth_failed,&parent_unavailable,0));
        BOOST_CHECK_EQUAL(error,errors[fault]);
        BOOST_CHECK(!depth_failed);
        BOOST_CHECK(!parent_unavailable);
    }
}

BOOST_AUTO_TEST_CASE(deposit_sequence_predecessor_boundaries)
{
    for (const int64_t current : {INT64_MIN, int64_t{-1}, int64_t{0}, int64_t{1}, int64_t{2}, INT64_MAX}) {
        if (current > 0) BOOST_CHECK_EQUAL(drivechain::haskell::PreviousDepositSequence(current), current - 1);
        else BOOST_CHECK_THROW(drivechain::haskell::PreviousDepositSequence(current), std::runtime_error);
    }
}

BOOST_AUTO_TEST_CASE(ctip_lookup_failure_classification_preserves_search)
{
    namespace hs = drivechain::haskell;
    for (const std::string message : {"", "RPC unavailable", "multiple slot CTIP",
             "deposit spends multiple slot CTIP outputs", "Multiple slot CTIP", "multiple slot ctip", "multiple slot CTI"}) {
        const bool fatal = message.find("multiple slot CTIP") != std::string::npos;
        BOOST_CHECK_EQUAL(hs::DepositMessageMatches(2, message), fatal);
        unsigned calls{0}, stored{0};
        std::string caught;
        try {
            hs::DepositCtipSearch(3, [&](uint32_t stage, uint64_t index) -> int32_t {
                ++calls;
                try {
                    if (index == 0) throw std::runtime_error(message);
                    if (stage == 2) ++stored;
                    return index == 1;
                } catch (const std::runtime_error& exception) {
                    if (hs::DepositMessageMatches(2, exception.what())) throw;
                }
                return 0;
            });
        } catch (const std::runtime_error& exception) {
            caught = exception.what();
        }
        BOOST_CHECK_EQUAL(caught, fatal ? message : "");
        BOOST_CHECK_EQUAL(calls, fatal ? 1U : 7U);
        BOOST_CHECK_EQUAL(stored, fatal ? 0U : 1U);
    }
    BOOST_CHECK_THROW(hs::DepositMessageMatches(3, "multiple slot CTIP"), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(generated_peg_identity_defaults)
{
    static_assert(drivechain::PEG_EVENT_SCHEMA_VERSION == 1);
    BOOST_CHECK_EQUAL(drivechain::DepositIdentity{}.sidechain_slot, 24);
    BOOST_CHECK_EQUAL(drivechain::AuthenticatedDeposit{}.sidechain_slot, 0);
    const drivechain::CtipState original{COutPoint(Txid::FromUint256(uint256{1}),2),3,4};
    BOOST_CHECK(original == original);
    auto changed=original;
    changed.outpoint.n=3; BOOST_CHECK(!(original==changed));
    changed=original; changed.value=4; BOOST_CHECK(!(original==changed));
    changed=original; changed.sequence_number=5; BOOST_CHECK(!(original==changed));
}

BOOST_AUTO_TEST_CASE(shared_event_writer_preserves_bmm_request_wire)
{
    const uint256 critical = uint256S("12"), parent = uint256S("34");
    for (uint64_t bid : {uint64_t{0}, uint64_t{1000}, std::numeric_limits<uint64_t>::max()}) {
        const auto request = BuildDrivechainBmmRequest(24, bid, 935000, critical, parent);
        BOOST_CHECK_EQUAL(request.write(), strprintf(
            "{\"sidechainId\":24,\"valueSats\":\"%s\",\"height\":935000,"
            "\"criticalHash\":{\"hex\":\"%s\"},\"prevBytes\":{\"hex\":\"%s\"}}",
            std::to_string(bid), critical.GetHex(), parent.GetHex()));
    }
    UniValue object(UniValue::VOBJ);
    object.pushKV("existing", true);
    drivechain::AppendEvent(object, drivechain::haskell::EventLayoutKind::HEX,
        [](uint32_t index) { BOOST_CHECK_EQUAL(index, 0U); return UniValue("abcd"); });
    BOOST_CHECK_EQUAL(object.write(), "{\"existing\":true,\"hex\":\"abcd\"}");
    BOOST_CHECK_THROW(drivechain::AppendEvent(object, drivechain::haskell::EventLayoutKind::HEX,
        [](uint32_t) -> UniValue { throw std::runtime_error("source failed"); }), std::runtime_error);
    BOOST_CHECK_EQUAL(object.write(), "{\"existing\":true,\"hex\":\"abcd\"}");
}

BOOST_AUTO_TEST_CASE(two_way_peg_request_schema_preserves_wire)
{
    using Kind = drivechain::haskell::EventLayoutKind;
    for (const int slot : {-1, 0, 24, 255, 256}) {
        UniValue request(UniValue::VOBJ), hash(UniValue::VOBJ);
        drivechain::AppendEvent(hash, Kind::HEX, [](uint32_t) { return UniValue(uint256S("01").GetHex()); });
        drivechain::AppendEvent(request, Kind::TWO_WAY_PEG_REQUEST,
            [&](uint32_t index) { return index == 0 ? UniValue(slot) : hash; });
        BOOST_CHECK_EQUAL(request.write(), strprintf(
            "{\"sidechainId\":%d,\"endBlockHash\":{\"hex\":\"%s\"}}", slot, uint256S("01").GetHex()));
    }
}

BOOST_AUTO_TEST_CASE(live_address_bytes_and_outpoint_bounds_are_haskell_rules)
{
    const auto address = TestDepositAddress();
    for (const size_t position : {size_t{0}, size_t{3}, size_t{4}, address.size() - 1}) {
        for (unsigned byte = 0; byte <= 255; ++byte) {
            if (byte >= 0x21 && byte <= 0x7e) continue;
            auto changed = address;
            changed[position] = static_cast<char>(byte);
            drivechain::AuthenticatedDeposit authenticated;
            authenticated.address = "untouched";
            std::string error;
            BOOST_CHECK(!Authenticate(authenticated, error, MainchainInfo(), EnforcerChainInfo(), EnforcerTip(),
                Sidechains(), TwoWayPegData(DEPOSIT_TXID, 0, changed)));
            BOOST_CHECK_EQUAL(error, "deposit address contains non-printable bytes");
            BOOST_CHECK_EQUAL(authenticated.address, "untouched");
        }
    }
    for (const int64_t index : std::array<int64_t, 5>{-1, 0, 4294967295LL, 4294967296LL, INT64_MAX}) {
        drivechain::AuthenticatedDeposit authenticated;
        std::string error;
        const auto outpoint = COutPoint(Txid::FromUint256(uint256S(DEPOSIT_TXID)), static_cast<uint32_t>(index));
        const bool valid = index >= 0 && index <= UINT32_MAX;
        BOOST_CHECK_EQUAL(Authenticate(authenticated, error, MainchainInfo(), EnforcerChainInfo(), EnforcerTip(),
            Sidechains(), TwoWayPegData(DEPOSIT_TXID, index), Ctip(DEPOSIT_TXID, 14'402'000, 8, index),
            Params().NetworkIDString(), Identity(), outpoint), valid);
        if (!valid) {
            BOOST_CHECK_EQUAL(error, "deposit vout is out of range");
            BOOST_CHECK(!Authenticate(authenticated, error, MainchainInfo(), EnforcerChainInfo(), EnforcerTip(),
                Sidechains(), TwoWayPegData(), Ctip(DEPOSIT_TXID, 14'402'000, 8, index)));
            BOOST_CHECK_EQUAL(error, "deposit vout is out of range");
        }
    }
}

BOOST_AUTO_TEST_CASE(live_selection_preserves_scan_order_and_atomicity)
{
    const auto selected = Sidechains()["sidechains"][0];
    const auto block = TwoWayPegData()["blocks"][0];
    const auto event = block["blockInfo"]["events"][0];
    const auto array = [](std::initializer_list<UniValue> entries) {
        UniValue result(UniValue::VARR);
        for (const auto& entry : entries) result.push_back(entry);
        return result;
    };
    const auto with = [](UniValue object, const std::string& key, UniValue value) {
        object.pushKV(key, std::move(value));
        return object;
    };
    const auto events = [&](UniValue entries) {
        return with(block, "blockInfo", with(ParseJson("{}"), "events", std::move(entries)));
    };
    const auto missing_output = with(ParseJson("{}"), "deposit",
        with(ParseJson("{}"), "outpoint", event["deposit"]["outpoint"]));
    const std::vector<std::pair<UniValue, std::string>> declarations{
        {array({}), "expected sidechain slot is not active"},
        {array({selected, UniValue()}), "sidechain entry must be an object"},
        {array({selected, selected}), "enforcer returned duplicate sidechain slot"},
        {array({with(selected, "activationHeight", -1)}), "sidechain activation height is not active at the enforcer tip"},
        {array({with(selected, "declaration", ParseJson(R"({"v0":{"title":"wrong"}})"))}), "sidechain declaration identity does not match the configured slot"},
    };
    const std::vector<std::pair<UniValue, std::string>> deposits{
        {array({}), "confirmed deposit outpoint is absent from canonical two-way-peg data"},
        {array({block, UniValue()}), "GetTwoWayPegData block must be an object"},
        {array({events(ParseJson("{}"))}), "GetTwoWayPegData events must be an array"},
        {array({events(array({UniValue()}))}), "GetTwoWayPegData event must be an object"},
        {array({events(array({ParseJson(R"({"deposit":false})")}))}), "deposit event must be an object"},
        {array({block, events(array({missing_output}))}), "duplicate confirmed deposit event for outpoint"},
        {array({events(array({event, UniValue()}))}), "GetTwoWayPegData event must be an object"},
    };
    for (bool declaration : {true, false}) {
        for (const auto& [entries, expected] : declaration ? declarations : deposits) {
            drivechain::AuthenticatedDeposit authenticated;
            authenticated.value = 123;
            authenticated.address = "untouched";
            std::string error;
            BOOST_CHECK(!Authenticate(authenticated, error, MainchainInfo(), EnforcerChainInfo(), EnforcerTip(),
                declaration ? with(Sidechains(), "sidechains", entries) : Sidechains(),
                declaration ? TwoWayPegData() : with(TwoWayPegData(), "blocks", entries)));
            BOOST_CHECK_EQUAL(error, expected);
            BOOST_CHECK_EQUAL(authenticated.value, 123);
            BOOST_CHECK_EQUAL(authenticated.address, "untouched");
        }
    }
    UniValue many(UniValue::VARR);
    for (unsigned i = 0; i < 32000; ++i) many.push_back(ParseJson(R"({"sidechainNumber":25})"));
    many.push_back(selected);
    drivechain::AuthenticatedDeposit authenticated;
    std::string error;
    BOOST_REQUIRE(Authenticate(authenticated, error, MainchainInfo(), EnforcerChainInfo(), EnforcerTip(),
        with(Sidechains(), "sidechains", many),
        with(TwoWayPegData(), "blocks", array({events(UniValue()), events(array({})), block}))));
    BOOST_CHECK_EQUAL(authenticated.value, 2000);
    BOOST_CHECK_EQUAL(authenticated.address, TestDepositAddress());
}

BOOST_AUTO_TEST_CASE(live_evidence_keeps_network_failure_order_and_output_atomicity)
{
    const std::array<const char*, 15> errors{{
        "configured sidechain slot is out of range",
        "sidechain network does not match the configured identity",
        "mainchain genesis does not match the configured network",
        "mainchain blockchain info is missing",
        "drivechain evidence field 'chain' must be a string",
        "mainchain network does not match the configured network",
        "mainchain signet challenge does not match the configured network",
        "mainchain is not fully synchronized",
        "drivechain evidence field 'bestblockhash' must be a string",
        "enforcer network does not match the configured mainchain",
        "drivechain evidence field 'network' must be a string",
        "enforcer network does not match the configured mainchain",
        "drivechain evidence field 'blockHeaderInfo' must be an object",
        "enforcer tip is not synchronized with the canonical mainchain tip",
        "enforcer tip is not synchronized with the canonical mainchain tip",
    }};
    for (unsigned mutation = 0; mutation < errors.size(); ++mutation) {
        BOOST_TEST_CONTEXT("live network mutation " << mutation) {
            auto mainchain = MainchainInfo(), enforcer = EnforcerChainInfo(), tip = EnforcerTip();
            auto identity = Identity();
            switch (mutation) {
            case 0: identity.sidechain_slot = -1; mainchain = UniValue(); break;
            case 1: identity.sidechain_network = "wrong"; mainchain = UniValue(); break;
            case 2: identity.mainchain_genesis = uint256::ONE; mainchain = UniValue(); break;
            case 3: mainchain = UniValue(); break;
            case 4: mainchain = ParseJson("{}"); break;
            case 5: mainchain = ParseJson(R"({"chain":"wrong"})"); break;
            case 6: mainchain = MainchainInfo("signet", "00"); break;
            case 7: mainchain = MainchainInfo("signet", SIGNET_CHALLENGE, true); break;
            case 8: mainchain = ParseJson(strprintf(R"({"chain":"signet","signet_challenge":"%s","initialblockdownload":false})", SIGNET_CHALLENGE)); break;
            case 9: enforcer = UniValue(); break;
            case 10: enforcer = ParseJson("{}"); break;
            case 11: enforcer = EnforcerChainInfo("wrong"); tip = UniValue(); break;
            case 12: tip = UniValue(); break;
            case 13: tip = EnforcerTip(DEPOSIT_BLOCK); break;
            case 14: tip = EnforcerTip(MAINCHAIN_TIP, 99); break;
            }
            drivechain::AuthenticatedDeposit authenticated;
            authenticated.value = 123;
            authenticated.current_ctip_value = 456;
            authenticated.address = "untouched";
            std::string error;
            BOOST_CHECK(!Authenticate(authenticated, error, mainchain, enforcer, tip,
                Sidechains(), TwoWayPegData(), Ctip(), Params().NetworkIDString(), identity));
            BOOST_CHECK_EQUAL(error, errors[mutation]);
            BOOST_CHECK_EQUAL(authenticated.value, 123);
            BOOST_CHECK_EQUAL(authenticated.current_ctip_value, 456);
            BOOST_CHECK_EQUAL(authenticated.address, "untouched");
        }
    }
}

BOOST_AUTO_TEST_CASE(live_confirmation_preserves_lazy_reads_and_rpc_exception_types)
{
    drivechain::AuthenticatedDeposit authenticated;
    std::string error;
    BOOST_REQUIRE(Authenticate(authenticated, error));
    const std::vector<std::pair<std::string, std::string>> headers{
        {"null", "mainchain deposit block header is missing"},
        {R"({"confirmations":0})", "drivechain evidence field 'height' must be an integer"},
        {R"({"confirmations":0,"height":89,"hash":false})", "mainchain deposit block is no longer confirmed"},
        {R"({"confirmations":6,"height":89,"hash":false})", "mainchain deposit block height changed"},
        {R"({"confirmations":6,"height":90})", "mainchain deposit block hash is missing or malformed"},
        {strprintf(R"({"confirmations":6,"height":90,"hash":"%s"})", MAINCHAIN_TIP), "mainchain deposit block hash changed"},
    };
    for (const auto& [json, expected] : headers) {
        BOOST_CHECK(!drivechain::VerifyDepositBlockConfirmation(ParseJson(json), authenticated, error));
        BOOST_CHECK_EQUAL(error, expected);
    }
    for (const auto& hash : {"null", "false", "17", "{}", "[]", "\"\"", "\"00\"",
            "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "\"gaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""}) {
        error = "untouched";
        BOOST_CHECK(!drivechain::VerifyDepositBlockConfirmation(
            ParseJson(strprintf(R"({"confirmations":6,"height":90,"hash":%s})", hash)), authenticated, error));
        BOOST_CHECK_EQUAL(error, "mainchain deposit block hash is missing or malformed");
    }
    const std::vector<std::pair<std::string, std::string>> outputs{
        {"null", "current CTIP outpoint is not unspent on the canonical mainchain"},
        {R"({"confirmations":0,"value":{}})", "current CTIP outpoint is not confirmed"},
        {R"({"confirmations":1,"value":null})", "current CTIP value does not match the enforcer"},
        {R"({"confirmations":1,"value":0.14401})", "current CTIP value does not match the enforcer"},
    };
    for (const auto& [json, expected] : outputs) {
        BOOST_CHECK(!drivechain::VerifyCurrentCtipOutput(ParseJson(json), authenticated, error));
        BOOST_CHECK_EQUAL(error, expected);
    }
    for (const auto& amount : {"{}", "\"bad\"", "-1"}) {
        error = "untouched";
        BOOST_CHECK_EXCEPTION(drivechain::VerifyCurrentCtipOutput(
            ParseJson(strprintf(R"({"confirmations":1,"value":%s})", amount)), authenticated, error),
            UniValue, [](const UniValue& rpc_error) { return rpc_error["code"].getInt<int>() == -3; });
        BOOST_CHECK_EQUAL(error, "untouched");
    }
}

BOOST_AUTO_TEST_CASE(live_reader_defaults_and_boolean_types_preserve_authentication)
{
    for (const auto& encoded : {"false", "true", "null", "0", "\"false\"", "{}", "[]"}) {
        auto info = MainchainInfo();
        info.pushKV("initialblockdownload", ParseJson(encoded));
        drivechain::AuthenticatedDeposit result;
        result.value = 777;
        std::string error;
        const bool accepted = Authenticate(result, error, info);
        BOOST_CHECK_EQUAL(accepted, std::string(encoded) == "false");
        if (!accepted) {
            BOOST_CHECK_EQUAL(error, "mainchain is not fully synchronized");
            BOOST_CHECK_EQUAL(result.value, 777);
        }
    }
    for (const auto& encoded : {"", ",\"vout\":null", ",\"vout\":0", ",\"vout\":\"0\"",
            ",\"vout\":false", ",\"vout\":{}", ",\"vout\":\"bad\""}) {
        const auto ctip = ParseJson(strprintf(
            R"({"ctip":{"txid":{"hex":"%s"},"value":"14402000","sequenceNumber":"8"%s}})", DEPOSIT_TXID, encoded));
        drivechain::AuthenticatedDeposit result;
        result.value = 777;
        std::string error;
        const std::string value(encoded);
        const bool expected = value.empty() || value == ",\"vout\":null" ||
            value == ",\"vout\":0" || value == ",\"vout\":\"0\"";
        BOOST_CHECK_EQUAL(Authenticate(result, error, MainchainInfo(), EnforcerChainInfo(), EnforcerTip(),
            Sidechains(), TwoWayPegData(), ctip), expected);
        if (expected) BOOST_CHECK_EQUAL(result.current_ctip.n, 0U);
        else {
            BOOST_CHECK_EQUAL(error, "drivechain evidence field 'vout' must be an integer");
            BOOST_CHECK_EQUAL(result.value, 777);
        }
    }
}

BOOST_AUTO_TEST_CASE(live_evidence_reads_run_outside_the_interpreter)
{
    namespace haskell = drivechain::haskell;
    struct Reads { uint32_t fault; bool throws; std::vector<uint32_t> visited; };
    const auto read = +[](void* opaque, uint32_t step, int64_t* fields) -> int32_t {
        auto& state = *static_cast<Reads*>(opaque);
        state.visited.push_back(step);
        if (haskell::WithdrawalStatus(0, "submitted") != 1) throw std::logic_error("nested rule failed");
        if (step == state.fault) {
            if (state.throws) throw std::domain_error("native reader failure");
            return 0;
        }
        std::fill_n(fields, 4, 1);
        return 1;
    };
    for (uint32_t fault = 0; fault <= 3; ++fault) {
        for (const bool throws : {false, true}) {
            Reads state{fault, throws, {}};
            std::string error{"untouched"};
            bool accepted{false}, caught{false};
            try {
                accepted = haskell::LiveEvidence(haskell::LiveEvidencePhase::CONFIRMATION,
                    read, &state, "parser failure", error);
            } catch (const std::domain_error& failure) {
                BOOST_CHECK_EQUAL(failure.what(), "native reader failure");
                caught = true;
            }
            BOOST_CHECK_EQUAL(accepted, fault == 3);
            BOOST_CHECK_EQUAL(caught, throws && fault < 3);
            BOOST_CHECK_EQUAL(error, fault < 3 && !throws ? "parser failure" : "untouched");
            const std::vector<uint32_t> expected = fault == 0 ? std::vector<uint32_t>{0} :
                fault == 1 ? std::vector<uint32_t>{0,1} : std::vector<uint32_t>{0,1,2};
            BOOST_CHECK(state.visited == expected);
        }
    }
}

BOOST_AUTO_TEST_CASE(peg_schema_keeps_original_lazy_branch_transcripts)
{
    namespace haskell = drivechain::haskell;
    using Kind = haskell::PegSchemaKind;
    for (const auto kind : {Kind::TYPE, Kind::INTEGER, Kind::HEX, Kind::FIELD, Kind::NULL_DEFAULT, Kind::FALSE_BOOLEAN, Kind::GUARDED}) {
        for (unsigned bits = 0; bits < 8; ++bits) {
            for (const uint64_t limit : {uint64_t{0}, uint64_t{1}, uint64_t{32}, uint64_t{1} << 63, UINT64_MAX}) {
                for (const uint64_t size : {uint64_t{0}, uint64_t{2}, uint64_t{64}, UINT64_MAX - 1, UINT64_MAX}) {
                    std::vector<uint32_t> expected, actual;
                    const auto read = [&](uint32_t step) -> uint64_t {
                        expected.push_back(step);
                        if (kind == Kind::HEX && step == 3) return size;
                        if (kind == Kind::INTEGER && (step == 2 || step == 5)) return 1;
                        if (kind == Kind::HEX && step == 4) return 1;
                        if (kind == Kind::FIELD && (step == 2 || step == 4 || step == 5)) return 1;
                        if (kind == Kind::NULL_DEFAULT && step != 1) return 1;
                        if (kind == Kind::GUARDED && step == 2) return 1;
                        return (bits >> (step == 1 ? 0 : step == 4 ? 2 : 1)) & 1;
                    };
                    bool wanted{false};
                    switch (kind) {
                    case Kind::TYPE: wanted = read(1); break;
                    case Kind::INTEGER:
                        if (read(1)) wanted = read(2);
                        else if (read(3) && read(4)) wanted = read(5);
                        break;
                    case Kind::HEX:
                        if (read(1) && read(2) && (limit == 0 || read(3) == limit * 2)) wanted = read(4);
                        break;
                    case Kind::FIELD: wanted = !read(1) ? read(2) : read(3) ? read(4) : read(5); break;
                    case Kind::NULL_DEFAULT: wanted = read(1) ? read(2) : read(3); break;
                    case Kind::FALSE_BOOLEAN: wanted = read(1) && !read(2); break;
                    case Kind::GUARDED: wanted = !read(1) || read(2); break;
                    }
                    const auto frozen = expected;
                    expected.clear();
                    const bool accepted = haskell::PegSchema(kind, limit, [&](uint32_t step) {
                        actual.push_back(step);
                        return read(step);
                    });
                    BOOST_CHECK_EQUAL(accepted, wanted);
                    BOOST_CHECK(actual == frozen);
                    for (size_t fault = 0; fault < frozen.size(); ++fault) {
                        struct NativeFault {};
                        size_t calls{0};
                        BOOST_CHECK_THROW(haskell::PegSchema(kind, limit, [&](uint32_t step) -> uint64_t {
                            BOOST_CHECK_EQUAL(step, frozen.at(calls));
                            if (calls++ == fault) throw NativeFault{};
                            return read(step);
                        }), NativeFault);
                        BOOST_CHECK_EQUAL(calls, fault + 1);
                    }
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(guarded_reads_are_lazy_and_preserve_native_exceptions)
{
    namespace hs = drivechain::haskell;
    unsigned calls{0};
    struct NativeFault {};
    hs::ReadWhen(false, [&] { ++calls; throw NativeFault{}; });
    BOOST_CHECK_EQUAL(calls, 0U);
    hs::ReadWhen(true, [&] {
        ++calls;
        BOOST_CHECK_EQUAL(hs::WithdrawalStatus(0, "submitted"), 1);
        hs::ReadWhen(false, [&] { BOOST_FAIL("nested false read executed"); });
        hs::ReadWhen(true, [&] { ++calls; });
    });
    BOOST_CHECK_EQUAL(calls, 2U);
    BOOST_CHECK_THROW(hs::ReadWhen(true, [&] { ++calls; throw NativeFault{}; }), NativeFault);
    BOOST_CHECK_EQUAL(calls, 3U);
    BOOST_CHECK_EXCEPTION(hs::ReadWhen(true, [] { throw ParseJson(R"({"code":-3})"); }),
        UniValue, [](const UniValue& error) { return error["code"].getInt<int>() == -3; });
}

BOOST_AUTO_TEST_CASE(peg_schema_alias_fallback_is_null_only)
{
    for (const auto& [camel, accepted] : std::vector<std::pair<std::string, bool>>{
        {"null", true}, {"\"8\"", true}, {"8", true}, {"\"bad\"", false}, {"false", false}}) {
        auto ctip = ParseJson(strprintf(R"json({"ctip":{"txid":{"hex":"%s"},"vout":0,
          "value":"14402000","sequenceNumber":%s,"sequence_number":"8"}})json", DEPOSIT_TXID, camel));
        drivechain::AuthenticatedDeposit authenticated;
        std::string error;
        BOOST_CHECK_EQUAL(Authenticate(authenticated, error, MainchainInfo(), EnforcerChainInfo(),
            EnforcerTip(), Sidechains(), TwoWayPegData(), ctip), accepted);
        if (accepted) BOOST_CHECK_EQUAL(authenticated.current_ctip_sequence, 8);
        else BOOST_CHECK_EQUAL(error, "drivechain evidence field 'sequenceNumber' must be an integer");
    }
}

BOOST_AUTO_TEST_CASE(haskell_checkpoints_preserve_both_immutable_records)
{
    struct Expected {
        const char* txid;
        const char* parent;
        const char* previous;
        int64_t value, ctip, sequence;
        const char* address;
    };
    const std::array<Expected, 2> records{{
        {"feed724d3382997ae6500d8185353e116d557a4f299b58e8f722c1aa400ab730",
         "000001d9988239435d51e763fd4231893dad22d7d03048266a5e21361e2db065",
         "7de4aeb747a54bbe6b590d2038f445b9dc995217fb1b4e524c4129cdd0f06bea",
         2000, 14402000, 8, "ert1q9263y9nqf2kwjl7hrhsgewefq7859w93z5n8x8"},
        {"7d78b50fa26e51ca01d1a916820971e46dd6d11e8da7c06571b95d8c6dd4a382",
         "00000268748226d792c32914d26f5608a766a13741f3762c35cb053084ac4d1c",
         "010a70b5e1fca8e8433dd2efc7c3b8f0783e98b133bbf03bcbe05cdd29a4edab",
         100000, 14400000, 7, "ert1q2d25juv3qvlk90pfsnqed7f9wzzgevp8y2vfmv"},
    }};
    for (const auto& expected : records) {
        const auto identity = uint256S(expected.txid), previous = uint256S(expected.previous);
        std::vector<unsigned char> actual;
        BOOST_REQUIRE(drivechain::haskell::LegacyCheckpoint(true, identity.begin(), previous.begin(), 0, actual));
        DataStream encoded;
        encoded << uint256S(expected.parent) << COutPoint(Txid::FromUint256(previous), 0) <<
            expected.value << expected.ctip << expected.sequence << std::string(expected.address);
        BOOST_CHECK(actual == std::vector<unsigned char>(UCharCast(encoded.data()), UCharCast(encoded.data()) + encoded.size()));
        const auto unchanged = actual;
        auto wrong_identity = identity, wrong_previous = previous;
        wrong_identity.begin()[0] ^= 1;
        wrong_previous.begin()[0] ^= 1;
        BOOST_CHECK(!drivechain::haskell::LegacyCheckpoint(true, wrong_identity.begin(), previous.begin(), 0, actual));
        BOOST_CHECK(!drivechain::haskell::LegacyCheckpoint(true, identity.begin(), wrong_previous.begin(), 0, actual));
        BOOST_CHECK(!drivechain::haskell::LegacyCheckpoint(true, identity.begin(), previous.begin(), 1, actual));
        BOOST_CHECK(!drivechain::haskell::LegacyCheckpoint(false, nullptr, nullptr, 0, actual));
        BOOST_CHECK(actual == unchanged);
    }
    const auto checkpoint = LegacyPublicDeposit();
    CMutableTransaction wrong_value(checkpoint);
    wrong_value.witness.vtxinwit[0].m_pegin_witness.stack[0] = Serialize(int64_t{2001});
    BOOST_CHECK(wrong_value.GetHash() == checkpoint.GetHash());
    RestartablePeginView persistent;
    CCoinsViewCache view(&persistent);
    std::string error;
    BOOST_CHECK(!drivechain::VerifyDeterministicDeposit(CTransaction(wrong_value), 0, view, error));
    BOOST_CHECK_EQUAL(error, "historical drivechain checkpoint witness does not match its immutable value");
    BOOST_CHECK(!drivechain::ConnectDepositState(CTransaction(wrong_value), 0, view, 2, error));
    BOOST_CHECK_EQUAL(error, "historical drivechain checkpoint witness does not match its immutable value");
    BOOST_REQUIRE(view.Flush());
    BOOST_CHECK(persistent.coins.empty());
}

BOOST_AUTO_TEST_CASE(destination_selection_preserves_upstream_scripts_and_address_rules)
{
    DeterministicFixture fixture;
    RestartablePeginView persistent;
    CCoinsViewCache view(&persistent);
    std::string error;
    BOOST_REQUIRE(drivechain::ConnectDepositState(LegacyPublicDeposit(), 0, view, 2, error));
    const auto address = TestDepositAddress();
    const std::vector<unsigned char> data(address.begin(), address.end());
    for (unsigned mutation = 0; mutation < 18; ++mutation) {
        BOOST_TEST_CONTEXT("destination mutation " << mutation) {
            auto evidence = fixture.evidence;
            Sidechain::Bitcoin::CMutableTransaction deposit;
            DataStream{evidence.deposit_tx} >> TX_WITH_WITNESS(deposit);
            auto& script = deposit.vout[1].scriptPubKey;
            if ((mutation >= 1 && mutation <= 3) || mutation == 15) {
                script = CScript() << OP_RETURN;
                const unsigned width = mutation == 2 ? 2 : mutation == 3 ? 4 : 1;
                script << (width == 1 ? OP_PUSHDATA1 : width == 2 ? OP_PUSHDATA2 : OP_PUSHDATA4);
                script.push_back(data.size());
                for (unsigned i = 1; i < width; ++i) script.push_back(0);
                script.insert(script.end(), data.begin(), data.end());
            }
            const CScript invalid = CScript() << OP_RETURN << std::vector<unsigned char>{'b','a','d'};
            switch (mutation) {
            case 4: script.front() = OP_TRUE; break;
            case 5: script << OP_FALSE; break;
            case 6: script = CScript() << OP_RETURN << OP_0; break;
            case 7: script = invalid; break;
            case 8: deposit.vout.push_back(deposit.vout[1]); break;
            case 9: {
                const auto alternate = EncodeDestination(WitnessV0KeyHash(uint160(ParseHex("0000000000000000000000000000000000000001"))));
                deposit.vout.emplace_back(0, CScript() << OP_RETURN << std::vector<unsigned char>(alternate.begin(), alternate.end()));
                break;
            }
            case 10: deposit.vout.pop_back(); break;
            case 11: case 15: deposit.vout.insert(deposit.vout.begin() + 1, Sidechain::Bitcoin::CTxOut(0, invalid)); break;
            case 12: deposit.vout.emplace_back(0, invalid); break;
            case 13: script = CScript() << OP_RETURN << OP_PUSHDATA2; break;
            case 14: deposit.vout.emplace_back(0, CScript() << OP_RETURN << OP_DUP); break;
            case 16: script.clear(); break;
            case 17: deposit.vout[1].nValue = 1; break;
            }
            Sidechain::Bitcoin::CMerkleBlock proof;
            proof.header = evidence.headers.front();
            proof.header.hashMerkleRoot = deposit.GetHash();
            proof.txn = Sidechain::Bitcoin::CPartialMerkleTree({deposit.GetHash()}, {true});
            while (!CheckParentProofOfWork(proof.header.GetHash(), proof.header.nBits, Params().GetConsensus())) ++proof.header.nNonce;
            evidence.headers = {proof.header};
            evidence.deposit_tx = Serialize(deposit);
            evidence.txout_proof = Serialize(proof);
            CMutableTransaction tx(*fixture.transaction);
            tx.vin[0].prevout = COutPoint(Txid::FromUint256(deposit.GetHash()), 0);
            tx.witness.vtxinwit[0].m_pegin_witness = CreateDrivechainDepositPeginWitness(2000,
                Params().GetConsensus().pegged_asset, Params().ParentGenesisBlockHash(), CScript() << OP_TRUE, evidence);
            const bool valid = mutation < 4 || mutation == 11 || mutation == 12 || mutation == 14 || mutation == 15 || mutation == 17;
            error.clear();
            BOOST_CHECK_EQUAL(drivechain::VerifyDepositEvidenceAnchor(CTransaction(tx), 0, proof.header.GetHash(), error), valid);
            if (valid) BOOST_CHECK_MESSAGE(drivechain::VerifyDeterministicDeposit(CTransaction(tx), 0, view, error), error);
            else BOOST_CHECK_EQUAL(error, mutation == 8 || mutation == 9
                ? "deposit transaction contains multiple valid sidechain destinations"
                : "deposit transaction does not commit a valid sidechain destination");
        }
    }
}

BOOST_AUTO_TEST_CASE(destination_inspection_preserves_read_and_publication_order)
{
    struct Inspector {
        std::array<int32_t, 4> replies;
        std::vector<std::pair<uint32_t, uint32_t>> calls;
    };
    const auto inspect = +[](void* opaque, uint32_t index, uint32_t action) -> int32_t {
        auto& state = *static_cast<Inspector*>(opaque);
        state.calls.emplace_back(index, action);
        return state.replies.at(action);
    };
    for (const int32_t first : {-1, 0, 106, 256, 512}) {
        for (const int32_t second : {-1, 0, 43 | (3 << 9), 256 | (3 << 9), 2048}) {
            for (const int32_t decoded : {-1, 0, 1, 2}) {
                for (const int32_t published : {0, 1, 2}) {
                    for (const uint32_t count : {1U, 2U}) {
                        Inspector state{{first, second, decoded, published}, {}};
                        std::vector<std::pair<uint32_t, uint32_t>> expected;
                        int result{-1};
                        for (uint32_t i = 0; i < count; ++i) {
                            expected.emplace_back(i, 0);
                            if (first < 0 || first > 511) { result = -3; break; }
                            expected.emplace_back(i, 1);
                            if (second < 0 || second > 2047) { result = -3; break; }
                            if (first != 106 || (second & 511) > 78 || (second >> 9) != 3) continue;
                            expected.emplace_back(i, 2);
                            if (decoded == 0) continue;
                            if (decoded != 1) { result = -3; break; }
                            expected.emplace_back(i, 3);
                            if (published != 1) { result = -3; break; }
                            if (result >= 0) { result = -2; break; }
                            result = i;
                        }
                        std::string error;
                        bool accepted{false}, threw{false};
                        try { accepted = drivechain::haskell::DepositDestination(count, inspect, &state, error); }
                        catch (const std::runtime_error& failure) {
                            threw = true;
                            BOOST_CHECK_EQUAL(failure.what(), "Haskell destination evaluation failed");
                        }
                        BOOST_CHECK_EQUAL(accepted, result >= 0);
                        BOOST_CHECK_EQUAL(threw, result == -3);
                        BOOST_CHECK(state.calls == expected);
                        if (result == -1) BOOST_CHECK_EQUAL(error, "deposit transaction does not commit a valid sidechain destination");
                        if (result == -2) BOOST_CHECK_EQUAL(error, "deposit transaction contains multiple valid sidechain destinations");
                    }
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(deposit_codec_dispatch_keeps_native_and_ecx_state_separate)
{
    const CTransaction legacy = LegacyPublicDeposit();
    const DeterministicFixture deterministic;
    const COutPoint outpoint = legacy.vin[0].prevout;
    const std::string address = TestDepositAddress();
    const CScriptWitness native = CreateDrivechainDepositPeginWitness(
        2'000, Params().GetConsensus().pegged_asset,
        Params().ParentGenesisBlockHash(), CScript() << OP_TRUE, outpoint,
        uint256S(DEPOSIT_BLOCK), std::vector<unsigned char>(address.begin(), address.end()));

    // The shared spent-key/amount parser recognizes all deposit formats, but
    // ECX Connect/DisconnectDepositState and evidence anchors must never run
    // on Alpha's distinct eight-item native witness.
    BOOST_REQUIRE_EQUAL(native.stack.size(), 8U);
    CAmount classified_value{-1};
    BOOST_CHECK_EQUAL(DepositWitnessKind(native, outpoint, 0, classified_value), 2);
    BOOST_CHECK_EQUAL(classified_value, 2'000);
    BOOST_CHECK_EQUAL(DepositWitnessKind(native, outpoint, 1, classified_value), 0);
    BOOST_CHECK_EQUAL(classified_value, 2'000);
    BOOST_CHECK(IsDrivechainDepositPeginWitness(native, outpoint));
    classified_value = -1;
    BOOST_CHECK(IsDrivechainDepositPeginWitness(native, outpoint, &classified_value));
    BOOST_CHECK_EQUAL(classified_value, 2'000);
    BOOST_CHECK(!IsEcxDrivechainDepositPeginWitness(native, outpoint));
    BOOST_CHECK(GetPeginSpentKey(native, outpoint) == std::make_pair(outpoint.hash.ToUint256(), outpoint));

    for (size_t length : {size_t{0}, size_t{100}, size_t{101}}) {
        CScriptWitness altered = native;
        altered.stack[3].assign(length, OP_TRUE);
        BOOST_CHECK_EQUAL(IsDrivechainDepositPeginWitness(altered, outpoint), length <= 100);
        CAmount amount{-1};
        BOOST_CHECK_EQUAL(IsDrivechainDepositPeginWitness(altered, outpoint, &amount), length <= 100);
        BOOST_CHECK_EQUAL(amount, length <= 100 ? 2'000 : -1);
    }
    for (size_t field : {size_t{0}, size_t{1}, size_t{2}, size_t{5}, size_t{6}}) {
        CScriptWitness altered = native;
        altered.stack[field].push_back(0);
        CAmount untouched{123};
        BOOST_CHECK(!IsDrivechainDepositPeginWitness(altered, outpoint, &untouched));
        BOOST_CHECK_EQUAL(untouched, 123);
    }

    for (const CTransaction* tx : {&legacy, deterministic.transaction.get()}) {
        const CScriptWitness& witness = tx->witness.vtxinwit[0].m_pegin_witness;
        const COutPoint& deposit = tx->vin[0].prevout;
        BOOST_CHECK_EQUAL(DepositWitnessKind(witness, deposit, 0, classified_value), tx == &legacy ? 1 : 3);
        classified_value = -1;
        BOOST_CHECK_EQUAL(DepositWitnessKind(witness, deposit, 2, classified_value), 0);
        BOOST_CHECK_EQUAL(classified_value, -1);
        BOOST_CHECK(IsDrivechainDepositPeginWitness(witness, deposit));
        CAmount expected_amount{-1}, extracted_amount{-1};
        BOOST_REQUIRE(DepositWitnessKind(witness, deposit, 0, expected_amount));
        BOOST_CHECK(IsDrivechainDepositPeginWitness(witness, deposit, &extracted_amount));
        BOOST_CHECK_EQUAL(extracted_amount, expected_amount);
        BOOST_CHECK(IsEcxDrivechainDepositPeginWitness(witness, deposit));
        BOOST_CHECK(!IsEcxDrivechainDepositPeginWitness(witness, COutPoint(Txid::FromUint256(uint256::ONE), deposit.n)));

        CScriptWitness altered = witness;
        altered.stack[4][0] ^= 1;
        BOOST_CHECK(!IsEcxDrivechainDepositPeginWitness(altered, deposit));
        altered = witness;
        altered.stack.pop_back();
        BOOST_CHECK(!IsEcxDrivechainDepositPeginWitness(altered, deposit));

        // Historical prefixes accept trailing amount bytes; native witnesses
        // above do not. Preserve this deliberate compatibility distinction.
        altered = witness;
        altered.stack[0].push_back(0);
        BOOST_CHECK(IsEcxDrivechainDepositPeginWitness(altered, deposit));
        uint256 block_hash{uint256::ONE};
        BOOST_CHECK(!IsDrivechainDepositPeginWitness(witness, deposit, nullptr, nullptr, &block_hash));
        BOOST_CHECK(block_hash == uint256::ONE);
        if (witness.stack.size() == 11) {
            altered = witness;
            altered.stack[5].push_back(0);
            BOOST_CHECK(!IsEcxDrivechainDepositPeginWitness(altered, deposit));
            altered.stack[5].clear();
            BOOST_CHECK(!IsEcxDrivechainDepositPeginWitness(altered, deposit));
        }
    }
}

BOOST_AUTO_TEST_CASE(peg_event_rules_preserve_json_errors_and_numeric_bounds)
{
    for (const char* wrong : {"null","false","0","\"text\"","{}"}) {
        const auto input = ParseJson(std::string("{\"blocks\":") + wrong + "}");
        BOOST_CHECK_EXCEPTION(drivechain::NormalizeL1PegEvents(input,24),std::runtime_error,
            [](const auto& error) { return std::string(error.what()) == "drivechain peg data field 'blocks' must be an array"; });
    }
    constexpr std::array<const char*, 3> names{"submitted", "succeeded", "failed"};
    const auto response = [&](const UniValue& lifecycle) {
        return ParseJson(strprintf(
            R"({"blocks":[{"blockHeaderInfo":{"blockHash":{"hex":"%s"},"height":90},"blockInfo":{"events":[{"withdrawalBundle":{"m6id":{"hex":"%s"},"event":%s}}]}}]})",
            DEPOSIT_BLOCK, DEPOSIT_TXID, lifecycle.write()));
    };
    for (unsigned mask = 0; mask < 27; ++mask) {
        unsigned encoded = mask, count = 0, selected = 0;
        bool object{false};
        UniValue lifecycle(UniValue::VOBJ);
        for (unsigned i = 0; i < 3; ++i, encoded /= 3) {
            const auto field = encoded % 3;
            lifecycle.pushKV(names[i], field == 0 ? UniValue() : field == 1 ? ParseJson("false") : ParseJson("{}"));
            if (field) { ++count; selected = i; object = field == 2; }
        }
        if (count == 1 && object) {
            const auto events = drivechain::NormalizeL1PegEvents(response(lifecycle), 24);
            BOOST_REQUIRE_EQUAL(events.size(), 1);
            BOOST_CHECK_EQUAL(events[0]["status"].get_str(), names[selected]);
        } else {
            const std::string expected = count == 1 ? "withdrawal bundle lifecycle state must be an object" :
                "withdrawal bundle event must contain exactly one lifecycle state";
            BOOST_CHECK_EXCEPTION(drivechain::NormalizeL1PegEvents(response(lifecycle), 24),
                std::runtime_error, [&](const auto& error) { return error.what() == expected; });
        }
    }
    for (const int64_t index : {-1LL, 0LL, 4294967296LL}) {
        for (const int64_t value : {-1LL, 0LL, 1LL}) {
            for (const int64_t sequence : {-1LL, 0LL, 1LL}) {
                const auto input = TwoWayPegData(DEPOSIT_TXID, index, TestDepositAddress(), value, sequence);
                if (index >= 0 && value > 0 && sequence >= 0) {
                    const auto events = drivechain::NormalizeL1PegEvents(input, 24);
                    BOOST_REQUIRE_EQUAL(events.size(), 1);
                    BOOST_CHECK_EQUAL(events[0]["mainchain_vout"].getInt<int64_t>(), index);
                } else {
                    BOOST_CHECK_EXCEPTION(drivechain::NormalizeL1PegEvents(input, 24), std::runtime_error,
                        [](const auto& error) { return std::string(error.what()) == "deposit contains an invalid negative or zero numeric field"; });
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(normalizes_l1_lifecycle_and_deduplicates)
{
    UniValue response;
    BOOST_REQUIRE(response.read(R"json({
      "blocks": [
        {
          "blockHeaderInfo": {"blockHash":{"hex":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"height":10,"timestamp":"20"},
          "blockInfo": {"events":[
            {"deposit":{"sequenceNumber":"2","outpoint":{"txid":{"hex":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"vout":0},"output":{"address":{"hex":"abcd"},"valueSats":"1000"}}},
            {"deposit":{"sequenceNumber":"2","outpoint":{"txid":{"hex":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"vout":0},"output":{"address":{"hex":"abcd"},"valueSats":"1000"}}},
            {"withdrawalBundle":{"m6id":{"hex":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"event":{"submitted":{}}}}
          ]}
        },
        {
          "blockHeaderInfo": {"blockHash":{"hex":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},"height":"11","timestamp":"21"},
          "blockInfo": {"events":[
            {"withdrawalBundle":{"m6id":{"hex":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"event":{"succeeded":{"sequenceNumber":"3","transaction":{"hex":"00"}}}}}
          ]}
        },
        {
          "blockHeaderInfo": {"blockHash":{"hex":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"},"height":12},
          "blockInfo": {}
        }
      ]
    })json"));

    const UniValue events = drivechain::NormalizeL1PegEvents(response, 24);
    BOOST_REQUIRE(events.isArray());
    BOOST_CHECK_EQUAL(events.size(), 3U);
    BOOST_CHECK_EQUAL(events[0]["kind"].get_str(), "deposit");
    BOOST_CHECK_EQUAL(events[0]["value_sats"].getInt<int64_t>(), 1000);
    BOOST_CHECK_EQUAL(events[1]["status"].get_str(), "submitted");
    BOOST_CHECK_EQUAL(events[1]["acknowledgement"].get_str(), "pending");
    BOOST_CHECK_EQUAL(events[2]["status"].get_str(), "succeeded");
    BOOST_CHECK_EQUAL(events[2]["acknowledgement"].get_str(), "accepted");
    const auto expected = ParseJson(R"json([
      {"event_id":"l1:deposit:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:0","source":"l1","kind":"deposit","status":"l1_confirmed","sidechain_id":24,"sequence_number":2,"mainchain_txid":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","mainchain_vout":0,"address_hex":"abcd","value_sats":1000,"l1":{"block_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","height":10,"timestamp":20}},
      {"event_id":"l1:withdrawal:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc:submitted:10","source":"l1","kind":"withdrawal_bundle","status":"submitted","sidechain_id":24,"m6id":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","acknowledgement":"pending","l1":{"block_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","height":10,"timestamp":20}},
      {"event_id":"l1:withdrawal:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc:succeeded:11","source":"l1","kind":"withdrawal_bundle","status":"succeeded","sidechain_id":24,"m6id":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","sequence_number":3,"mainchain_transaction":"00","acknowledgement":"accepted","l1":{"block_hash":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","height":11,"timestamp":21}}
    ])json");
    BOOST_CHECK_EQUAL(events.write(), expected.write());
}

BOOST_AUTO_TEST_CASE(normalization_keeps_deposit_priority_over_withdrawal)
{
    const auto original = TwoWayPegData(DEPOSIT_TXID, 0, TestDepositAddress(), 1000, 2);
    const auto expected = drivechain::NormalizeL1PegEvents(original, 24);
    UniValue block = original["blocks"][0];
    UniValue event = block["blockInfo"]["events"][0];
    event.pushKV("withdrawalBundle", ParseJson("{}"));
    UniValue events(UniValue::VARR);
    events.push_back(ParseJson("{}"));
    events.push_back(event);
    UniValue info(UniValue::VOBJ);
    info.pushKV("events", events);
    block.pushKV("blockInfo", info);
    UniValue blocks(UniValue::VARR);
    blocks.push_back(block);
    UniValue response(UniValue::VOBJ);
    response.pushKV("blocks", blocks);
    BOOST_CHECK_EQUAL(drivechain::NormalizeL1PegEvents(response, 24).write(), expected.write());
}

BOOST_AUTO_TEST_CASE(l1_location_and_lifecycle_preserve_schema_and_lazy_errors)
{
    const std::array<std::string, 3> states{"submitted", "succeeded", "failed"};
    const std::array<std::string, 3> acknowledgements{"pending", "accepted", "rejected"};
    for (size_t i = 0; i < states.size(); ++i) {
        for (const std::string timestamp : {"", ",\"timestamp\":null", ",\"timestamp\":20", ",\"timestamp\":\"20\""}) {
            const auto response = ParseJson(strprintf(R"json({"blocks":[{
              "blockHeaderInfo":{"blockHash":{"hex":"%s"},"height":"10"%s},
              "blockInfo":{"events":[{"withdrawalBundle":{"m6id":{"hex":"%s"},"event":{"%s":{}}}}]}
            }]})json", MAINCHAIN_TIP, timestamp, DEPOSIT_TXID, states[i]));
            const auto events = drivechain::NormalizeL1PegEvents(response, 24);
            BOOST_REQUIRE_EQUAL(events.size(), 1U);
            BOOST_CHECK_EQUAL(events[0]["status"].get_str(), states[i]);
            BOOST_CHECK_EQUAL(events[0]["acknowledgement"].get_str(), acknowledgements[i]);
            BOOST_CHECK_EQUAL(drivechain::GetWithdrawalBundleStatus(response, 24, uint256S(DEPOSIT_TXID)), states[i]);
            const bool has_timestamp = timestamp.find("20") != std::string::npos;
            const std::string expected = strprintf("{\"block_hash\":\"%s\",\"height\":10%s}",
                MAINCHAIN_TIP, has_timestamp ? ",\"timestamp\":20" : "");
            BOOST_CHECK_EQUAL(events[0]["l1"].write(), expected);
        }
    }
    const auto malformed = ParseJson(R"json({"blocks":[{
      "blockHeaderInfo":{"blockHash":{"hex":"bad"},"height":false,"timestamp":false},
      "blockInfo":{"events":false}}]})json");
    BOOST_CHECK_EXCEPTION(drivechain::NormalizeL1PegEvents(malformed, 24), std::runtime_error,
        [](const auto& error) { return std::string(error.what()) == "drivechain peg data field 'hex' must be valid hex"; });
}

BOOST_AUTO_TEST_CASE(l1_location_flow_preserves_order_and_native_faults)
{
    for (const bool timestamp : {false, true}) {
        const std::vector<uint32_t> expected = timestamp ? std::vector<uint32_t>{1,2,3,4,5,6} : std::vector<uint32_t>{1,2,3,4,6};
        for (const uint32_t fault : {0U,1U,2U,3U,4U,5U,6U}) {
            std::vector<uint32_t> actual;
            bool threw{false};
            try {
                drivechain::haskell::L1LocationFlow([&](uint32_t step) {
                    actual.push_back(step);
                    if (step == fault) throw std::domain_error("location fixture");
                    return step != 4 || timestamp;
                });
            } catch (const std::domain_error& error) {
                BOOST_CHECK_EQUAL(error.what(), "location fixture");
                threw = true;
            }
            auto wanted = expected;
            const auto stop = std::find(wanted.begin(), wanted.end(), fault);
            BOOST_CHECK_EQUAL(threw, stop != wanted.end());
            if (stop != wanted.end()) wanted.erase(stop + 1, wanted.end());
            BOOST_CHECK(actual == wanted);
        }
    }
}

BOOST_AUTO_TEST_CASE(withdrawal_status_prefers_terminal_event_independent_of_order)
{
    const uint256 m6id = uint256S(
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    UniValue reversed;
    BOOST_REQUIRE(reversed.read(R"json({
      "blocks": [
        {
          "blockHeaderInfo": {"blockHash":{"hex":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},"height":11},
          "blockInfo": {"events":[
            {"withdrawalBundle":{"m6id":{"hex":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"event":{"succeeded":{}}}}
          ]}
        },
        {
          "blockHeaderInfo": {"blockHash":{"hex":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"height":10},
          "blockInfo": {"events":[
            {"withdrawalBundle":{"m6id":{"hex":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"event":{"submitted":{}}}}
          ]}
        }
      ]
    })json"));

    BOOST_CHECK_EQUAL(
        drivechain::GetWithdrawalBundleStatus(reversed, 24, m6id),
        "succeeded");
    BOOST_CHECK(
        drivechain::GetWithdrawalBundleStatus(reversed, 24, uint256S("01")).empty());

    UniValue uppercase;
    BOOST_REQUIRE(uppercase.read(R"json({
      "blocks": [{
        "blockHeaderInfo": {"blockHash":{"hex":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"height":12},
        "blockInfo": {"events":[
          {"withdrawalBundle":{"m6id":{"hex":"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"},"event":{"succeeded":{}}}}
        ]}
      }]
    })json"));
    BOOST_CHECK_EQUAL(
        drivechain::GetWithdrawalBundleStatus(uppercase, 24, m6id),
        "succeeded");

    UniValue conflicting;
    BOOST_REQUIRE(conflicting.read(R"json({
      "blocks": [
        {
          "blockHeaderInfo": {"blockHash":{"hex":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"height":10},
          "blockInfo": {"events":[
            {"withdrawalBundle":{"m6id":{"hex":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"event":{"succeeded":{}}}}
          ]}
        },
        {
          "blockHeaderInfo": {"blockHash":{"hex":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},"height":11},
          "blockInfo": {"events":[
            {"withdrawalBundle":{"m6id":{"hex":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"event":{"failed":{}}}}
          ]}
        }
      ]
    })json"));
    BOOST_CHECK_THROW(
        drivechain::GetWithdrawalBundleStatus(conflicting, 24, m6id),
        std::runtime_error);
}

BOOST_AUTO_TEST_CASE(withdrawal_status_text_preserves_exact_matching_and_errors)
{
    namespace haskell = drivechain::haskell;
    for (const int64_t prior : {-1, 0, 1, 2, 3, 4}) {
        for (const auto& status : std::array<std::string, 8>{"submitted", "succeeded", "failed", "", "Submitted", "failed ", "unknown", std::string("failed\0suffix", 13)}) {
            const int ordinal = status == "submitted" ? 0 : status == "succeeded" ? 1 : status == "failed" ? 2 : 3;
            std::string expected_error, actual_error;
            int64_t expected{-99}, actual{-99};
            try { expected = haskell::PegEvent(haskell::PegEventKind::STATUS, prior, ordinal); }
            catch (const std::runtime_error& error) { expected_error = error.what(); }
            try { actual = haskell::WithdrawalStatus(prior, status); }
            catch (const std::runtime_error& error) { actual_error = error.what(); }
            BOOST_CHECK_EQUAL(actual, expected);
            BOOST_CHECK_EQUAL(actual_error, expected_error);
        }
    }
}

BOOST_AUTO_TEST_CASE(rejects_malformed_l1_contract)
{
    UniValue missing_blocks;
    BOOST_REQUIRE(missing_blocks.read("{}"));
    BOOST_CHECK_THROW(drivechain::NormalizeL1PegEvents(missing_blocks, 24), std::runtime_error);

    UniValue ambiguous_status;
    BOOST_REQUIRE(ambiguous_status.read(R"json({"blocks":[{"blockHeaderInfo":{"blockHash":{"hex":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"height":1},"blockInfo":{"events":[{"withdrawalBundle":{"m6id":{"hex":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"event":{"submitted":{},"failed":{}}}}]}}]})json"));
    BOOST_CHECK_THROW(drivechain::NormalizeL1PegEvents(ambiguous_status, 24), std::runtime_error);

    UniValue bad_txid;
    BOOST_REQUIRE(bad_txid.read(R"json({"blocks":[{"blockHeaderInfo":{"blockHash":{"hex":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"height":1},"blockInfo":{"events":[{"deposit":{"sequenceNumber":0,"outpoint":{"txid":{"hex":"nope"},"vout":0},"output":{"address":{"hex":"00"},"valueSats":1}}}]}}]})json"));
    BOOST_CHECK_THROW(drivechain::NormalizeL1PegEvents(bad_txid, 24), std::runtime_error);

    UniValue conflicting_duplicate;
    BOOST_REQUIRE(conflicting_duplicate.read(R"json({"blocks":[{"blockHeaderInfo":{"blockHash":{"hex":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"height":1},"blockInfo":{"events":[{"deposit":{"sequenceNumber":0,"outpoint":{"txid":{"hex":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"vout":0},"output":{"address":{"hex":"00"},"valueSats":1}}},{"deposit":{"sequenceNumber":0,"outpoint":{"txid":{"hex":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"vout":0},"output":{"address":{"hex":"00"},"valueSats":2}}}]}}]})json"));
    BOOST_CHECK_THROW(drivechain::NormalizeL1PegEvents(conflicting_duplicate, 24), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(parent_replay_store_flows_preserve_status_and_fault_order)
{
    namespace hs = drivechain::haskell;
    struct NativeFault {};
    for (uint32_t kind = 0; kind < 11; ++kind) {
        for (uint32_t variant = 0; variant < 256; ++variant) {
            const auto reply = [&](uint32_t step) -> uint32_t {
                if (kind == 1 && step == 1) return variant % 3;
                if (kind == 1 && step == 7) return (variant / 3) % 3;
                if (kind == 3 && step > 1) return step == 3;
                if (kind == 4 && step != 4) return step != 5;
                if (kind >= 7 && step == 1) return variant % 3;
                if ((kind >= 7 && step == 6) || ((kind == 5 || kind == 6) && step == 3)) return 0;
                if ((kind == 0 && step == 3) || (kind == 1 && (step == 4 || step == 6 || step == 9)) ||
                    (kind == 2 && (step == 2 || step == 4))) return 1;
                return (variant >> (step % 8)) & 1;
            };
            std::vector<uint32_t> expected, actual;
            const auto read = [&](uint32_t step) { expected.push_back(step); return reply(step); };
            const auto original = [&]() -> uint32_t {
                if (kind == 5 || kind == 6) {
                    if (!read(1) || (kind == 6 && !read(2))) { read(3); return 2; }
                    return 0;
                }
                if (kind >= 7) {
                    const auto status = read(1);
                    if (status != 0) return status;
                    if (!read(2) || (kind != 8 && !read(3)) ||
                        (kind >= 9 && !read(4)) || (kind == 10 && !read(5))) {
                        read(6); return 2;
                    }
                    return 0;
                }
                if (kind == 3) {
                    if (!read(1)) { read(2); return 0; }
                    read(3); return 1;
                }
                if (kind == 4) {
                    read(1); read(2); read(3);
                    if (read(4)) return 1;
                    read(5); return 0;
                }
                if (kind == 0) {
                    if (!read(1)) return 1;
                    if (read(2)) return 0;
                    read(3); return 2;
                }
                if (kind == 2) {
                    if (read(1)) read(2);
                    if (read(3)) return 0;
                    read(4); return 2;
                }
                const auto identity = read(1);
                if (identity == 1) {
                    if (!read(2)) return 0;
                    read(4); return 2;
                }
                if (identity == 2) return 2;
                if (!read(3) || !read(5)) { read(6); return 3; }
                const auto tip = read(7);
                if (tip != 0 || !read(8)) {
                    if (tip != 2) read(9);
                    return 2;
                }
                return 1;
            };
            const auto status = original();
            BOOST_CHECK_EQUAL(hs::ParentReplayStore(static_cast<hs::ReplayStoreFlow>(kind), [&](uint32_t step) {
                actual.push_back(step);
                BOOST_CHECK_EQUAL(hs::ParentReplaySchema(0, 4, 5), 4U);
                return reply(step);
            }), status);
            BOOST_CHECK(actual == expected);
            for (size_t fault = 0; fault < expected.size(); ++fault) {
                size_t reads{0};
                BOOST_CHECK_THROW(hs::ParentReplayStore(static_cast<hs::ReplayStoreFlow>(kind), [&](uint32_t step) -> uint32_t {
                    BOOST_CHECK_EQUAL(step, expected.at(reads));
                    if (reads++ == fault) throw NativeFault{};
                    return reply(step);
                }), NativeFault);
                BOOST_CHECK_EQUAL(reads, fault + 1);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_store_sessions_preserve_recovery_and_atomicity)
{
    namespace hs = drivechain::haskell;
    const auto identity = uint256S("01");
    const DrivechainParentReplayTip seed{100,uint256S("02"),{}}, next{101,uint256S("03"),{}};
    const std::vector<DrivechainMintableDeposit> deposits;
    const std::optional<std::pair<uint256,DrivechainReplayedBmmEdge>> edge;
    const std::vector<DrivechainSuccessfulWithdrawal> withdrawals;
    const std::vector<DrivechainWithdrawalProposalIdentity> proposals;
    for (unsigned family = 0; family < 3; ++family) for (bool late : {false,true}) for (bool native_fault : {false,true}) {
        DrivechainParentReplayStore store(m_args.GetDataDirBase() / "replay-session-fault",1 << 20,true);
        std::string error;
        BOOST_REQUIRE(store.Reset(identity,seed,&error));
        DrivechainParentReplayTip loaded;
        auto effects = family == 0 ? store.LoadEffects(identity,loaded,&error) :
            family == 1 ? store.ResetEffects(identity,seed,&error) :
                store.AppendEffects(seed,next,deposits,edge,withdrawals,proposals,&error);
        const auto mode = family == 0 ? hs::ReplayStoreWorkflow::LOAD_SESSION :
            family == 1 ? hs::ReplayStoreWorkflow::RESET_SESSION : hs::ReplayStoreWorkflow::APPEND_SESSION;
        const uint32_t fault = family == 0 ? (late ? 6 : 39) : (late ? 23 : 1);
        std::vector<uint32_t> calls;
        const auto callback = [&](uint32_t step,uint64_t index,std::span<const unsigned char> input) {
            calls.push_back(step);
            if (step == fault && native_fault) return effects(99,0,{});
            auto reply = effects(step,index,input);
            if (step == fault) reply.push_back(0);
            return reply;
        };
        const bool recoverable = late || family == 2;
        if (recoverable) {
            BOOST_CHECK_EQUAL(hs::RunReplayStore(mode,callback),family == 0 ? 2U : 0U);
            const std::string prefix = family == 0 ? "persistent parent replay load failed: " :
                family == 1 ? "failed to rebuild persistent parent replay database: " :
                    "persistent parent replay append failed: ";
            const std::string failure = native_fault ?
                (family == 0 ? "invalid replay load effect" : family == 1 ? "invalid replay reset effect" : "invalid replay append effect") :
                "Haskell replay store workflow failed";
            BOOST_CHECK_EQUAL(error,prefix+failure);
            BOOST_CHECK_EQUAL(calls.back(),43U);
        } else {
            BOOST_CHECK_THROW(hs::RunReplayStore(mode,callback),std::exception);
            BOOST_CHECK_EQUAL(calls.back(),native_fault ? fault : 43U);
        }
        BOOST_CHECK(std::find(calls.begin(),calls.end(),24U) == calls.end());
        effects = {};
        const auto status = store.Load(identity,loaded,&error);
        if (family == 1 && late) {
            BOOST_CHECK(status == DrivechainReplayStoreLoadStatus::EMPTY);
        } else {
            BOOST_REQUIRE(status == DrivechainReplayStoreLoadStatus::LOADED);
            BOOST_CHECK_EQUAL(loaded.height,seed.height);
            BOOST_CHECK(loaded.hash == seed.hash);
        }
        BOOST_REQUIRE(store.Reset(identity,seed,&error));
        BOOST_REQUIRE(store.Append(seed,next,deposits,edge,withdrawals,proposals,&error));
        BOOST_REQUIRE(store.Load(identity,loaded,&error) == DrivechainReplayStoreLoadStatus::LOADED);
        BOOST_CHECK_EQUAL(loaded.height,next.height);
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_block_session_preserves_parameters_and_errors)
{
    Sidechain::Bitcoin::CBlock block;
    DrivechainParentReplayState state;
    const uint256 proposal = uint256S("01");
    auto effects = MakeDrivechainParentBlockEffects(block, 123, 24, proposal,
        2,1,4,3,6,5, state, nullptr, nullptr, nullptr, nullptr,
        drivechain::TreasuryOpcode::NOP5, DrivechainM6ReplayRule::SINGLE_CONFIGURED_SLOT_M6);
    const auto parameters = effects(20480,0,{});
    BOOST_REQUIRE_EQUAL(parameters.size(), 28U);
    BOOST_CHECK_EQUAL(ReadLE32(parameters.data()), 123U);
    BOOST_CHECK_EQUAL(ReadLE64(parameters.data()+4), uint64_t{2} | (uint64_t{1}<<16) |
        (uint64_t{4}<<32) | (uint64_t{3}<<48));
    BOOST_CHECK_EQUAL(ReadLE32(parameters.data()+12), 6U);
    BOOST_CHECK_EQUAL(ReadLE32(parameters.data()+16), 5U);
    BOOST_CHECK_EQUAL(ReadLE32(parameters.data()+20), 0xb4U);
    BOOST_CHECK_EQUAL(ReadLE32(parameters.data()+24), 1U);
    auto retained = effects;
    effects = {};
    BOOST_CHECK(retained(20481,0,{}) == std::vector<unsigned char>{1});
    BOOST_CHECK(retained(20481,1,{}) == std::vector<unsigned char>{0});
    const std::array<std::string, 4> messages{
        "Haskell parent block replay failed", "Haskell M2 activation failed",
        "Haskell M3 proposal admission failed", "Haskell M4 workflow failed"};
    for (unsigned code = 2; code <= 5; ++code) {
        BOOST_CHECK_EXCEPTION(retained(20481,code,{}), std::runtime_error,
            [&](const auto& error) { return error.what() == messages[code-2]; });
    }
    BOOST_CHECK_THROW(retained(20480,1,{}), std::logic_error);
    BOOST_CHECK_THROW(retained(20482,0,{}), std::logic_error);
}

BOOST_AUTO_TEST_CASE(parent_replay_typed_cache_progress_matches_previous_control_flow)
{
    namespace hs = drivechain::haskell;
    using Key = std::tuple<std::optional<uint8_t>, std::optional<uint256>, uint256, uint256,
        std::array<uint16_t, 6>, uint32_t>;
    using Event = std::tuple<uint32_t, uint64_t, std::vector<unsigned char>>;
    const auto bytes = [](const auto&... values) {
        DataStream stream;
        (stream << ... << values);
        return std::vector<unsigned char>{UCharCast(stream.data()), UCharCast(stream.data()) + stream.size()};
    };
    const auto hash = [](uint32_t height) { return ArithToUint256(arith_uint256{uint64_t{height} + 1}); };
    struct Rejected {};
    for (unsigned flags = 0; flags < 64; ++flags) for (unsigned mode = 0; mode < 29; ++mode) {
        const bool locked = flags & 1, require_active = flags & 2, activated = flags & 4, has_error = flags & 8;
        const uint32_t checkpoint = flags & 16 ? UINT32_MAX - 3 : 100;
        uint32_t initial_height = checkpoint + ((flags & 32) ? 2 : 0);
        uint32_t target = checkpoint + ((flags & 32) ? 1 : 2);
        if (mode == 6) target = checkpoint - 1;
        if (mode == 27) { initial_height = UINT32_MAX - 1; target = UINT32_MAX; }
        if (mode == 28) initial_height = checkpoint - 1;
        const Key configured{mode == 1 ? std::nullopt : std::optional<uint8_t>{24},
            mode == 2 ? std::nullopt : std::optional<uint256>{hash(1)}, hash(2),
            mode == 3 ? uint256{} : hash(checkpoint), {2,1,4,3,6,5}, 5};
        const auto snapshot = [&](const Key& key, const auto&... fields) {
            const auto& windows = std::get<4>(key);
            auto encoded = bytes(std::get<0>(key).has_value(), std::get<0>(key).value_or(0),
                std::get<1>(key).has_value(), std::get<1>(key).value_or(uint256{}),
                std::get<2>(key), std::get<3>(key), windows[0], windows[1], windows[2],
                windows[3], windows[4], windows[5], std::get<5>(key));
            const auto tail = bytes(fields...);
            encoded.insert(encoded.end(), tail.begin(), tail.end());
            return encoded;
        };
        struct Result {
            unsigned status;
            std::vector<Event> events;
            std::string error;
            uint32_t height, remaining;
            uint256 hash;
            bool published;
        };
        const auto run = [&](bool migrated, size_t fault) -> Result {
            Key key = configured;
            if (mode == 5) {
                switch (flags % 10) {
                case 0: std::get<0>(key) = 25; break;
                case 1: std::get<1>(key) = hash(3); break;
                case 2: std::get<2>(key) = hash(3); break;
                case 3: std::get<3>(key) = hash(3); break;
                case 4: std::get<5>(key) = 4; break;
                default: ++std::get<4>(key)[flags % 6]; break;
                }
            }
            bool initialized = mode != 4 && mode != 22, published = true;
            uint32_t height = initial_height, remaining = mode == 16 ? 0 : 4;
            uint256 current_hash = hash(height), pending_hash;
            unsigned hash_reads{0}, writes{0};
            std::vector<Event> events;
            std::string error{"stale"};
            const uint256 active_proposal = mode == 14 ? hash(3) : hash(1);
            const uint32_t activation_height = mode == 15 ? target + 1 : checkpoint;
            Sidechain::Bitcoin::CBlock replay_block;
            Sidechain::Bitcoin::CMutableTransaction replay_coinbase;
            replay_coinbase.vin.resize(1);
            if (mode != 19) replay_block.vtx.push_back(Sidechain::Bitcoin::MakeTransactionRef(replay_coinbase));
            DrivechainParentReplayState replay_state;
            DrivechainReplayEffects block_effects;
            const auto call = [&](uint32_t step, uint64_t index, std::span<const unsigned char> input) -> std::vector<unsigned char> {
                events.emplace_back(step, index, std::vector<unsigned char>(input.begin(), input.end()));
                if (fault && events.size() == fault) throw std::domain_error("cache fixture fault");
                if (step >= 30000 && step <= 50481) {
                    BOOST_REQUIRE(bool(block_effects));
                    return block_effects(step-30000,index,input);
                }
                if (step != 11 && step != 12 && step != 19 && step != 206 && step != 425 && step != 507 && step != 525) BOOST_CHECK(input.empty());
                if ((step >= 400 && step <= 443) || (step >= 500 && step <= 543)) {
                    const bool loading = step < 500;
                    const auto command = step - (loading ? 400 : 500);
                    std::vector<unsigned char> reply;
                    switch (command) {
                    case 0: case 3: case 5: reply = bytes(true); break;
                    case 1: reply = bytes(DrivechainParentReplayTip{height,current_hash,{}}); break;
                    case 2: reply = bytes(DrivechainParentReplayTip{height+1,pending_hash,{}}); break;
                    case 4: reply = bytes(true,uint32_t{5},hash(1)); break;
                    case 6: reply = bytes(true,DrivechainParentReplayTip{
                        loading ? checkpoint : height,loading ? hash(checkpoint) : current_hash,{}}); break;
                    case 7: reply = bytes(hash(3)); break;
                    case 8: reply = index == 0 ? bytes(uint32_t{5}) : bytes(uint64_t{0},false,uint64_t{0},uint64_t{0}); break;
                    case 18: case 23: case 39: break;
                    case 24: if (mode != 21) ++writes; reply = bytes(mode != 21); break;
                    case 25: if (has_error) error.assign(input.begin(),input.end()); break;
                    case 26: reply = bytes(hash(1)); break;
                    case 43: return bytes(true,static_cast<uint32_t>(index));
                    default: throw std::logic_error("unexpected cache store effect");
                    }
                    reply.insert(reply.begin(),1);
                    return reply;
                }
                switch (step) {
                case 0: return snapshot(configured, checkpoint, target, hash(target), require_active);
                case 1: {
                    auto encoded = snapshot(key, height, current_hash, activated, active_proposal, activation_height);
                    encoded.insert(encoded.begin(), initialized);
                    return encoded;
                }
                case 2: return bytes(locked);
                case 3: return bytes(remaining, has_error);
                case 4: remaining = index; return {};
                case 5:
                    BOOST_CHECK(index == 1 || index == 7 || index == 8);
                    return bytes(int64_t(index == 7 && locked));
                case 6: published = false; return {};
                case 7: initialized = false; height = 0; current_hash = {}; return {};
                case 8: case 26: return {};
                case 300: return snapshot(configured, std::vector<unsigned char>{1}, hash(1), std::vector<unsigned char>{2},
                    uint32_t{1}, hash(1), uint32_t{2}, hash(2), checkpoint, hash(4), uint256{}, UINT32_MAX,
                    int64_t{0}, hash(0), true, uint32_t{5}, uint64_t{MAX_MONEY});
                case 301: return bytes(hash(1));
                case 302: return bytes(hash(2));
                case 303: return mode == 22 || mode == 26 ? bytes(false) : bytes(true, hash(0));
                case 304: return bytes(true, checkpoint, hash(4));
                case 319: return bytes(uint64_t{MAX_MONEY});
                case 320: case 27: return {};
                case 311: return bytes(checkpoint+1, std::vector<unsigned char>{2}, uint256{}, hash(1),
                    checkpoint, hash(1), true, hash(2), uint32_t{2}, false);
                case 310:
                    if (index == 114) { key = configured; initialized = true; }
                    if (index == 218) height = checkpoint;
                    if (index == 219) current_hash = hash(height);
                    return bytes(int64_t{index == 204 || index == 205 ? 0 :
                        index == 225 ? checkpoint+1 : index == 209 ? checkpoint : 1});
                case 9: {
                    ++hash_reads;
                    if (mode == 24 && hash_reads == flags % 6 + 1) return bytes(false);
                    const unsigned corrupt = mode == 8 || mode == 26 ? 2 :
                        mode >= 9 && mode <= 13 ? (mode == 9 ? 1 : mode - 7) : 0;
                    return bytes(true, hash(hash_reads == corrupt ? 0 : index));
                }
                case 10: return mode == 23 ? bytes(false) : bytes(true, mode == 7 ? height - 1 : height);
                case 11: if (has_error) error.assign(input.begin(), input.end()); return {};
                case 12: pending_hash = uint256{input.data(), input.size()}; return {};
                case 13: return bytes(mode != 25);
                case 14: return bytes(mode == 17 ? hash(0) : current_hash);
                case 15: case 18: case 19: case 23: case 25: case 206: return {};
                case 201: return bytes(int32_t{24}, false, uint256{});
                case 202: return bytes(true, uint64_t{0});
                case 16:
                    replay_state = {};
                    block_effects = MakeDrivechainParentBlockEffects(replay_block, index, 24,
                        *std::get<1>(configured), 2,1,4,3,6,5, replay_state, nullptr,
                        has_error ? &error : nullptr, nullptr, nullptr,
                        drivechain::TreasuryOpcode::NOP5, DrivechainM6ReplayRule::SINGLE_CONFIGURED_SLOT_M6);
                    return block_effects(20480,0,{});
                case 28: block_effects = {}; return {};
                case 17: return bytes(mode != 20);
                case 100: return bytes(uint32_t{1}, std::vector<unsigned char>{}, true, uint8_t{24}, true, hash(1),
                    uint32_t{2}, hash(2), uint32_t{3}, hash(3), uint32_t{4}, hash(4), uint256{}, uint32_t{0}, int64_t{0});
                case 20: return bytes(mode != 18);
                case 21:
                    return bytes(uint64_t{MAX_MONEY});
                case 22: BOOST_CHECK(writes > 0); --writes; height = index; current_hash = pending_hash; return {};
                case 24: BOOST_CHECK_EQUAL(writes, 0U); published = true; return {};
                default: throw std::logic_error("unexpected cache fixture effect");
                }
            };
            const auto effect = [&](uint32_t step, uint64_t index = 0) { return call(step, index, {}); };
            const auto boolean = [&](uint32_t step, uint64_t index = 0) { return effect(step,index).at(0) != 0; };
            const auto fail = [&](const std::string& message) {
                call(11,0,{reinterpret_cast<const unsigned char*>(message.data()),message.size()});
                throw Rejected{};
            };
            const auto deadline = [&] {
                effect(5,1); effect(5,7);
                if (locked) effect(5,8);
            };
            const auto active_hash = [&](uint32_t at) {
                DataStream stream{effect(9,at)};
                bool present;
                stream >> present;
                if (!present) throw Rejected{};
                uint256 result;
                stream >> result;
                return result;
            };
            const auto initialize = [&](bool force) {
                effect(8,force);
                effect(300); effect(301); effect(302);
                const bool available = boolean(303);
                if (available) {
                    effect(304);
                    for (uint32_t step = 101; step <= 114; ++step) effect(310,step);
                    effect(310,200); effect(310,201);
                    for (uint32_t step = 601; step <= 638; ++step) effect(310,step);
                    for (uint32_t step : {639,204,205}) effect(310,step);
                    effect(319);
                    for (uint32_t step : {439,400,403,404,408,426,405,406}) effect(step);
                    effect(443,1); effect(320);
                    effect(311);
                    for (uint32_t step : {218,219,220,250}) effect(310,step);
                }
                effect(26);
                return available;
            };
            const auto reference = [&]() -> unsigned {
                effect(0);
                if (!std::get<0>(configured) || !std::get<1>(configured) || std::get<3>(configured).IsNull()) return 1;
                if (target < checkpoint) fail(strprintf("parent height %u predates native drivechain launch checkpoint %u", target, checkpoint));
                effect(1);
                if (!initialized || key != configured) {
                    if (boolean(2)) fail("authenticated parent replay cache is not warmed");
                    effect(6); effect(7);
                    if (!initialize(false)) return 0;
                    effect(1);
                }
                if (active_hash(checkpoint) != std::get<3>(configured)) {
                    effect(6); fail("active parent chain no longer contains the pinned drivechain launch checkpoint");
                }
                bool stale{false};
                if (target < height) {
                    DataStream stream{effect(10)};
                    bool present;
                    stream >> present;
                    if (!present) return 0;
                    uint32_t active;
                    stream >> active;
                    stale = active < height;
                }
                if (!stale) stale = active_hash(height) != current_hash;
                if (stale) {
                    effect(6);
                    if (boolean(2)) fail("authenticated parent replay cache is stale after a parent reorganization");
                    effect(7);
                    if (!initialize(true)) return 0;
                    effect(1);
                }
                if (active_hash(target) != hash(target)) fail("requested parent replay target is not active at its claimed height");
                if (height < target) {
                    const auto steps = target-height;
                    if (boolean(2)) {
                        deadline(); effect(3);
                        if (steps > remaining) {
                            if (has_error) fail(strprintf(
                                "parent replay needs %u uncached blocks; locked validation permits at most %u before background warming", steps, remaining));
                            return 0;
                        }
                        effect(4,remaining-steps);
                    }
                    while (height < target) {
                        const uint32_t next = height+1;
                        deadline();
                        const auto block_hash = active_hash(next);
                        call(12,next,bytes(block_hash));
                        if (!boolean(13)) return 0;
                        DataStream stream{effect(14)};
                        uint256 previous; stream >> previous;
                        if (previous != current_hash) {
                            effect(6); fail("authenticated parent-state replay is not a contiguous chain");
                        }
                        effect(15);
                        effect(16,next);
                        // The independent cache reference composes the retained
                        // standalone block interpreter over the same native scope.
                        const auto replay = hs::ReplayParentBlock(next, {2,1,4,3}, 6,5,0xb4,true,
                            [&](uint32_t step, uint64_t index, std::span<const unsigned char> input) {
                                return call(30000+step,index,input);
                            });
                        const bool applied = boolean(50481,replay);
                        effect(28);
                        if (!applied || !boolean(17,next)) { effect(6); return 0; }
                        effect(100); // No milestone at this fixture's synthetic height.
                        deadline(); effect(18);
                        if (checkpoint < next) {
                            effect(25); effect(201); effect(202);
                            const std::string message{"BMM successor has no enforcer-recognized M7 for sidechain slot 24"};
                            call(206,0,{reinterpret_cast<const unsigned char*>(message.data()),message.size()});
                            call(19,next,bytes(false));
                        }
                        if (!boolean(20)) { effect(6); return 0; }
                        effect(21,next);
                        for (uint32_t step : {500,501,502,503,504,508,505,506}) effect(step);
                        const auto state = bytes(DrivechainParentReplayState{});
                        call(507,0,state); call(507,0,state); effect(508,1);
                        effect(518); effect(523);
                        const bool appended = effect(524).at(1) != 0;
                        if (!appended) {
                            const std::string message{"failed to atomically append persistent parent replay block"};
                            call(525,0,{reinterpret_cast<const unsigned char*>(message.data()),message.size()});
                        }
                        effect(543,appended); effect(27);
                        if (!appended) { effect(6); return 0; }
                        effect(22,next); effect(23);
                    }
                }
                if (active_hash(checkpoint) != std::get<3>(configured)) {
                    effect(6); fail("parent-chain reorg raced the pinned launch checkpoint check");
                }
                if (active_hash(target) != hash(target)) {
                    effect(6); fail("parent-chain reorg raced the replay target check");
                }
                effect(1);
                if (active_hash(height) != current_hash) {
                    effect(6); fail("parent-chain reorg raced the replay cache tip check");
                }
                if (require_active && !(activated && active_proposal == *std::get<1>(key) && activation_height <= target))
                    fail(strprintf("configured Elements slot proposal is not active at parent height %u", target));
                deadline(); effect(24);
                return 1;
            };
            unsigned status;
            try { status = migrated ? hs::RunReplayStore(hs::ReplayStoreWorkflow::CACHE, call) : reference(); }
            catch (const Rejected&) { status = 0; }
            catch (const std::domain_error&) { status = 2; }
            return {status, events, error, height, remaining, current_hash, published};
        };
        const auto expected = run(false,0);
        for (size_t fault = 0; fault <= expected.events.size(); ++fault) {
            const auto reference = fault ? run(false,fault) : expected;
            const auto actual = run(true,fault);
            BOOST_CHECK_EQUAL(actual.status, reference.status);
            BOOST_CHECK(actual.events == reference.events);
            BOOST_CHECK_EQUAL(actual.error, reference.error);
            BOOST_CHECK_EQUAL(actual.height, reference.height);
            BOOST_CHECK_EQUAL(actual.remaining, reference.remaining);
            BOOST_CHECK(actual.hash == reference.hash);
            BOOST_CHECK_EQUAL(actual.published, reference.published);
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_typed_load_preserves_states_errors_and_faults)
{
    namespace hs = drivechain::haskell;
    const auto bytes = [](const auto&... values) {
        DataStream stream;
        (stream << ... << values);
        return std::vector<unsigned char>{UCharCast(stream.data()), UCharCast(stream.data()) + stream.size()};
    };
    const auto identity = uint256S("01");
    for (unsigned flags = 0; flags < 1024; ++flags) {
        const bool open = flags & 1, present = flags & 2, readable = flags & 4, schema = flags & 8;
        const bool matches = flags & 16, has_tip = flags & 32, read_tip = flags & 64, sane = flags & 128;
        const bool has_error = flags & 256;
        const uint32_t version = flags & 512 ? 5 : 4;
        DrivechainParentReplayTip tip;
        tip.height = 100;
        if (sane) tip.hash = uint256S("02");
        std::vector<uint32_t> expected{39, 0};
        std::string expected_error;
        unsigned status{2};
        if (!open) expected_error = "persistent parent replay database is not open";
        else {
            expected.push_back(3);
            if (!present) {
                expected.push_back(5);
                if (has_tip) expected_error = "persistent parent replay has a tip but no identity";
                else status = 0;
            } else {
                expected.push_back(4);
                if (!readable) expected_error = "persistent parent replay identity record is malformed";
                else {
                    expected.push_back(8);
                    if (schema) expected.push_back(26);
                    if (!schema || !matches) {
                        status = 3;
                        expected_error = "persistent parent replay schema or immutable network identity does not match";
                    } else {
                        expected.push_back(5);
                        if (has_tip) expected.push_back(6);
                        if (has_tip && !read_tip) expected_error = "persistent parent replay tip record is malformed";
                        else if (!has_tip || !sane) expected_error = "persistent parent replay tip is missing or internally inconsistent";
                        else status = 1;
                    }
                }
            }
        }
        if (!expected_error.empty()) expected.push_back(25);
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            std::vector<uint32_t> seen;
            std::string error{"stale"};
            const auto run = [&] {
                return hs::RunReplayStore(hs::ReplayStoreWorkflow::LOAD,
                    [&](uint32_t step, uint64_t index, std::span<const unsigned char> input) {
                        seen.push_back(step);
                        BOOST_CHECK_EQUAL(index, 0U);
                        if (fault && seen.size() == fault) throw std::domain_error("load fixture fault");
                        if (step == 25) {
                            if (has_error) error.assign(input.begin(), input.end());
                            return std::vector<unsigned char>{};
                        }
                        BOOST_CHECK(input.empty());
                        switch (step) {
                        case 0: return bytes(open);
                        case 3: return bytes(present);
                        case 4: return readable ? bytes(true, uint32_t(schema ? version : 0), matches ? identity : uint256{}) : bytes(false);
                        case 5: return bytes(has_tip);
                        case 6: return read_tip ? bytes(true, tip) : bytes(false);
                        case 8: return bytes(version);
                        case 26: return bytes(identity);
                        case 39: if (has_error) error.clear(); return std::vector<unsigned char>{};
                        default: throw std::logic_error("unexpected load effect");
                        }
                    });
            };
            if (fault) BOOST_CHECK_THROW(run(), std::domain_error);
            else {
                BOOST_CHECK_EQUAL(run(), status);
                BOOST_CHECK_EQUAL(error, has_error ? expected_error : "stale");
            }
            auto prefix = expected;
            if (fault) prefix.resize(fault);
            BOOST_CHECK(seen == prefix);
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_typed_reset_validates_before_release_and_commits_once)
{
    namespace hs = drivechain::haskell;
    const auto bytes = [](const auto& value) {
        DataStream stream;
        stream << value;
        return std::vector<unsigned char>{UCharCast(stream.data()), UCharCast(stream.data()) + stream.size()};
    };
    for (unsigned flags = 0; flags < 8; ++flags) {
        const bool sane = flags & 1, committed = flags & 2, has_error = flags & 4;
        DrivechainParentReplayTip seed;
        if (sane) seed.hash = uint256S("01");
        const unsigned status = sane && committed;
        std::vector<uint32_t> expected{1};
        if (sane) expected.insert(expected.end(), {40, 41, 42, 23, 24});
        if (!status) expected.push_back(25);
        const std::string expected_error = !has_error || status ? "stale" : sane ?
            "failed to atomically seed persistent parent replay" :
            "refusing to seed persistent parent replay with an invalid tip";
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            std::vector<uint32_t> seen;
            std::string error{"stale"};
            const auto run = [&] {
                return hs::RunReplayStore(hs::ReplayStoreWorkflow::RESET,
                    [&](uint32_t step, uint64_t index, std::span<const unsigned char> input) {
                        seen.push_back(step);
                        BOOST_CHECK_EQUAL(index, 0U);
                        if (fault && seen.size() == fault) throw std::domain_error("reset fixture fault");
                        if (step == 25) {
                            if (has_error) error.assign(input.begin(), input.end());
                        } else BOOST_CHECK(input.empty());
                        switch (step) {
                        case 1: return bytes(seed);
                        case 24: return bytes(committed);
                        case 23: case 25: case 40: case 41: case 42: return std::vector<unsigned char>{};
                        default: throw std::logic_error("unexpected reset effect");
                        }
                    });
            };
            if (fault) BOOST_CHECK_THROW(run(), std::domain_error);
            else { BOOST_CHECK_EQUAL(run(), status); BOOST_CHECK_EQUAL(error, expected_error); }
            auto prefix = expected;
            if (fault) prefix.resize(fault);
            BOOST_CHECK(seen == prefix);
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_append_preserves_loops_batch_order_and_faults)
{
    namespace hs = drivechain::haskell;
    struct NativeFault {};
    for (uint32_t shape = 0; shape < 12; ++shape) {
        for (uint32_t failed = 0; failed <= 66; ++failed) {
            const auto make_reply = [&]() {
                return [&, visits = std::array<unsigned, 67>{}](uint32_t step) mutable -> uint32_t {
                    ++visits.at(step);
                    switch (step) {
                    case 15: case 32: case 43: case 52: case 58: return visits[step] <= shape % 3;
                    case 6: case 9: return failed == step ? 1 + shape % 2 : 0;
                    case 5: case 8: case 13: case 21: case 30: case 40: case 45: case 48: case 66: return 0;
                    case 14: case 22: case 31: case 41: case 42: case 49: case 50: case 51:
                    case 53: case 54: case 56: case 57: case 60: case 62: case 63: case 64: return 1;
                    case 20: case 29: case 38: case 39: case 47: return failed == step;
                    case 23: case 55: return ((shape & 2) != 0) != (failed == step);
                    case 37: case 46: return ((shape & 1) != 0) != (failed == step);
                    case 61: return ((shape & 1) == 0) != (failed == step);
                    case 59: return ((visits[step] & 1) != 0) != (failed == step);
                    default: return failed != step;
                    }
                };
            };
            std::vector<uint32_t> expected, actual;
            auto original_reply = make_reply();
            const auto read = [&](uint32_t step) { expected.push_back(step); return original_reply(step); };
            const auto reject = [&](uint32_t step) { read(step); return 0U; };
            const auto original = [&]() -> uint32_t {
                if (!read(1) || !read(2) || !read(3) || !read(4)) return reject(5);
                if (read(6) != 0 || !read(7)) return reject(8);
                if (read(9) != 0 || !read(10) || !read(11) || !read(12)) return reject(13);
                read(14);
                while (read(15)) {
                    if (!read(16) || !read(17) || !read(18) || !read(19) || read(20)) return reject(21);
                    read(22);
                }
                if (read(23) && (!read(24) || !read(25) || !read(26) || !read(27) || !read(28) || read(29))) return reject(30);
                read(31);
                while (read(32)) {
                    if (!read(33) || !read(34) || !read(35) || !read(36) ||
                        (read(37) && read(38)) || read(39)) return reject(40);
                    read(41);
                }
                read(42);
                while (read(43)) {
                    if (!read(44)) return reject(45);
                    if (read(46) && read(47)) return reject(48);
                    read(49);
                }
                read(50); read(51);
                while (read(52)) { read(53); read(54); }
                if (read(55)) read(56);
                read(57);
                while (read(58)) {
                    if (!read(59)) read(60);
                    if (read(61)) read(62);
                    read(63);
                }
                read(64);
                if (!read(65)) return reject(66);
                return 1;
            };
            const auto status = original();
            auto reply = make_reply();
            BOOST_CHECK_EQUAL(hs::ParentReplayStore(hs::ReplayStoreFlow::APPEND, [&](uint32_t step) {
                actual.push_back(step);
                BOOST_CHECK_EQUAL(hs::ParentReplaySchema(0, 4, 5), 4U);
                return reply(step);
            }), status);
            BOOST_CHECK(actual == expected);
            for (size_t fault = 0; fault < expected.size(); ++fault) {
                auto fault_reply = make_reply();
                size_t reads{0};
                BOOST_CHECK_THROW(hs::ParentReplayStore(hs::ReplayStoreFlow::APPEND, [&](uint32_t step) -> uint32_t {
                    BOOST_CHECK_EQUAL(step, expected.at(reads));
                    if (reads++ == fault) throw NativeFault{};
                    return fault_reply(step);
                }), NativeFault);
                BOOST_CHECK_EQUAL(reads, fault + 1);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_typed_lookup_preserves_records_status_and_faults)
{
    namespace hs = drivechain::haskell;
    const auto bytes = [](const auto&... values) {
        DataStream stream;
        (stream << ... << values);
        return std::vector<unsigned char>{UCharCast(stream.data()), UCharCast(stream.data()) + stream.size()};
    };
    const auto id = uint256S("01"), block = uint256S("02");
    const Sidechain::Bitcoin::COutPoint out(id, 0);
    constexpr const char* descriptions[]{"deposit", "BMM edge", "successful withdrawal", "withdrawal occurrence"};
    constexpr const char* inconsistent[]{"deposit record", "BMM edge", "successful-withdrawal record", "withdrawal occurrence"};
    for (unsigned family = 0; family < 4; ++family)
    for (unsigned variant = 0; variant < 16; ++variant)
    for (unsigned flags = 0; flags < 16; ++flags) {
        const bool open = flags & 1, schema = flags & 2, present = flags & 4, readable = flags & 8;
        const auto kind = static_cast<hs::ReplayStoreWorkflow>(family + 2);
        std::vector<unsigned char> key, record;
        bool sane{false};
        if (family == 0) {
            DrivechainMintableDeposit value{out, block, 1, 1000, {0x51}};
            switch (variant) {
            case 1: value.outpoint.hash.SetNull(); break;
            case 2: value.outpoint.n = UINT32_MAX; break;
            case 3: value.block_hash.SetNull(); break;
            case 4: value.value = -1; break;
            case 5: value.value = 0; break;
            case 6: value.value = MAX_MONEY; break;
            case 7: value.value = MAX_MONEY + 1; break;
            case 8: value.address.clear(); break;
            case 9: value.address.resize(10000); break;
            case 10: value.address.resize(10001); break;
            case 11: value.outpoint.n = 1; break;
            case 12: value.block_height = UINT32_MAX; break;
            default: break;
            }
            const uint32_t facts = !value.outpoint.hash.IsNull() | ((value.outpoint.n != UINT32_MAX) << 1) |
                ((!value.block_hash.IsNull()) << 2);
            sane = hs::ParentReplayRecord(hs::ReplayRecordKind::DEPOSIT, facts, value.value, value.address.size(), MAX_MONEY) && value.outpoint == out;
            key = bytes(out); record = bytes(true, value);
        } else if (family == 1) {
            DrivechainReplayedBmmEdge value{block, 0, 1, true, id};
            uint256 parent = id;
            switch (variant) {
            case 1: parent.SetNull(); break;
            case 2: value.successor_hash.SetNull(); break;
            case 3: value.parent_height = UINT32_MAX; value.successor_height = 0; break;
            case 4: value.successor_height = 0; break;
            case 5: value.successor_height = 2; break;
            case 6: value.committed_sidechain_hash.SetNull(); break;
            case 7: value.has_canonical_commitment = false; break;
            case 8: value.has_canonical_commitment = false; value.committed_sidechain_hash.SetNull(); break;
            case 9: value.parent_height = UINT32_MAX-1; value.successor_height = UINT32_MAX; break;
            default: break;
            }
            const uint32_t facts = !parent.IsNull() | ((!value.successor_hash.IsNull()) << 1) |
                (value.has_canonical_commitment << 2) | ((!value.committed_sidechain_hash.IsNull()) << 3);
            sane = hs::ParentReplayRecord(hs::ReplayRecordKind::EDGE, facts, 0, value.parent_height, value.successor_height);
            key = bytes(parent); record = bytes(true, value);
        } else {
            DrivechainSuccessfulWithdrawal value{24, id, 1, block};
            switch (variant) {
            case 1: value.block_hash.SetNull(); break;
            case 2: value.sidechain_slot = 25; break;
            case 3: value.m6id.SetNull(); break;
            case 4: value.block_height = 2; break;
            case 5: value.block_height = UINT32_MAX; break;
            default: break;
            }
            sane = !value.block_hash.IsNull() && value.sidechain_slot == 24 && value.m6id == id &&
                (family != 3 || value.block_height == 1);
            key = family == 3 ? bytes(uint8_t{24}, id, uint32_t{1}) : bytes(uint8_t{24}, id);
            record = bytes(true, value);
        }
        std::vector<uint32_t> expected{0};
        std::string expected_error;
        unsigned status{0};
        if (open && family == 3) expected.push_back(8);
        if (!open || (family == 3 && !schema)) {
            status = 2;
            expected_error = family == 3 ? "withdrawal occurrence lookup requires the re-proposal replay schema" :
                "persistent parent replay database is not open";
        } else {
            expected.push_back(27);
            if (!present) status = 1;
            else {
                expected.push_back(28);
                if (!readable) {
                    status = 2;
                    expected_error = strprintf("persistent parent replay %s record is malformed", descriptions[family]);
                } else {
                    expected.push_back(26);
                    if (!sane) {
                        status = 2;
                        expected_error = strprintf("persistent parent replay %s is internally inconsistent", inconsistent[family]);
                    }
                }
            }
        }
        if (!expected_error.empty()) expected.push_back(25);
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            std::vector<uint32_t> seen;
            std::string error;
            const auto run = [&] {
                return hs::RunReplayStore(kind,[&](uint32_t step, uint64_t index, std::span<const unsigned char> input) {
                    seen.push_back(step);
                    BOOST_CHECK_EQUAL(index, 0U);
                    if (fault && seen.size() == fault) throw std::domain_error("lookup fixture fault");
                    if (step == 25) { error.assign(input.begin(), input.end()); return std::vector<unsigned char>{}; }
                    BOOST_CHECK(input.empty());
                    switch (step) {
                    case 0: return bytes(open);
                    case 8: return bytes(uint32_t(schema ? 5 : 4));
                    case 26: return key;
                    case 27: return bytes(present);
                    case 28: return readable ? record : bytes(false);
                    default: throw std::logic_error("unexpected lookup effect");
                    }
                });
            };
            if (fault) BOOST_CHECK_THROW(run(), std::domain_error);
            else { BOOST_CHECK_EQUAL(run(), status); BOOST_CHECK_EQUAL(error, expected_error); }
            auto prefix = expected;
            if (fault) prefix.resize(fault);
            BOOST_CHECK(seen == prefix);
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_typed_tip_matches_native_records)
{
    namespace hs = drivechain::haskell;
    FastRandomContext rng(true);
    const auto bytes = [](const DrivechainParentReplayTip& tip) {
        DataStream stream;
        stream << tip;
        return std::vector<unsigned char>{UCharCast(stream.data()), UCharCast(stream.data()) + stream.size()};
    };
    const auto run = [&](const std::vector<unsigned char>& record) {
        return hs::RunReplayStore(hs::ReplayStoreWorkflow::CHECK_TIP,
            [&](uint32_t step, uint64_t index, std::span<const unsigned char> input) {
                BOOST_REQUIRE_EQUAL(step, 1U);
                BOOST_REQUIRE_EQUAL(index, 0U);
                BOOST_REQUIRE(input.empty());
                return record;
            });
    };
    DrivechainParentReplayTip seed;
    seed.height = 100;
    seed.hash = uint256S("01");
    seed.state.active_proposal_hash = uint256S("02");
    seed.state.required_proposal_activated = true;
    seed.state.required_activation_height = 50;
    seed.state.required_activation_block_hash = uint256S("03");
    seed.state.pending_proposals.emplace(uint256S("04"), DrivechainPendingProposal{90, 10});
    seed.state.pending_withdrawals.push_back({uint256S("05"), 90, 12});
    seed.state.ctip = Sidechain::Bitcoin::COutPoint(uint256S("06"), 0);
    seed.state.ctip_value = 100;
    seed.state.other_slots[7].active_proposal_hash = uint256S("07");
    seed.state.other_slots[7].ctip = Sidechain::Bitcoin::COutPoint(uint256S("08"), 0);
    seed.state.other_slots[7].ctip_value = 100;
    seed.state.previous_m4_actions[7] = {DrivechainM4ActionType::ALARM, {}};
    seed.state.previous_m4_actions[24] = {DrivechainM4ActionType::UPVOTE, uint256S("09")};
    for (unsigned fixture = 0; fixture < 10000; ++fixture) {
        auto tip = seed;
        auto& state = tip.state;
        for (unsigned mutation = 0; mutation < fixture % 4; ++mutation) {
            switch (rng.randrange(22)) {
            case 0: tip.height = rng.randbool() ? rng.rand32() : 0; break;
            case 1: tip.hash.SetNull(); break;
            case 2: state.active_proposal_hash.SetNull(); break;
            case 3: state.required_proposal_activated = rng.randbool(); break;
            case 4: state.required_activation_height = rng.rand32(); break;
            case 5: state.required_activation_block_hash.SetNull(); break;
            case 6: state.ctip.reset(); break;
            case 7: state.ctip_value = rng.randbool() ? -1 : MAX_MONEY + 1; break;
            case 8: state.pending_proposals[uint256{}] = {0, 0}; break;
            case 9: state.pending_proposals.begin()->second.proposal_height = rng.rand32(); break;
            case 10: state.pending_proposals.begin()->second.votes = rng.rand32(); break;
            case 11: state.pending_withdrawals.front().proposal_height = rng.rand32(); break;
            case 12: state.pending_withdrawals.front().votes = rng.randrange(65536); break;
            case 13: state.pending_withdrawals.push_back(state.pending_withdrawals.front()); break;
            case 14: state.other_slots[7].ctip = state.ctip; break;
            case 15: state.other_slots[7].active_proposal_hash.SetNull(); break;
            case 16: state.other_slots[7].ctip_value = rng.randbool() ? -1 : 0; break;
            case 17: state.other_slots[7].pending_withdrawals = state.pending_withdrawals; break;
            case 18: state.previous_m4_actions[25] = state.previous_m4_actions[24]; break;
            case 19: state.previous_m4_actions[7].type = static_cast<DrivechainM4ActionType>(rng.randrange(256)); break;
            case 20: state.previous_m4_actions[7].m6id = uint256S("01"); break;
            case 21: state.previous_m4_actions.clear(); break;
            }
        }
        BOOST_CHECK_EQUAL(run(bytes(tip)), OriginalReplayTip(tip));
    }
    auto encoded = bytes(seed);
    for (size_t length = 0; length < encoded.size(); ++length) {
        BOOST_CHECK_THROW(run({encoded.begin(), encoded.begin() + length}), std::runtime_error);
    }
    encoded.push_back(0);
    BOOST_CHECK_THROW(run(encoded), std::runtime_error);
    auto large = seed;
    for (uint32_t i = 0; i < 300; ++i) {
        uint256 key;
        WriteLE32(key.begin(), i + 1);
        large.state.pending_proposals.emplace(key, DrivechainPendingProposal{90, i % 11});
    }
    BOOST_CHECK_EQUAL(run(bytes(large)), OriginalReplayTip(large));
}


BOOST_AUTO_TEST_CASE(parent_replay_typed_append_preserves_records_and_effects)
{
    namespace hs = drivechain::haskell;
    const auto encode = [](const auto&... values) {
        DataStream stream;
        (stream << ... << values);
        return std::vector<unsigned char>{UCharCast(stream.data()), UCharCast(stream.data()) + stream.size()};
    };
    const auto nonzero = [](const uint256& hash) { return !hash.IsNull(); };
    struct Fixture {
        DrivechainParentReplayTip previous, next, stored;
        uint32_t schema{4}, stored_schema{4};
        bool open{true}, identity_exists{true}, identity_read{true}, tip_exists{true}, tip_read{true}, commit{true};
        bool deposit_exists{false}, edge_exists{false}, withdrawal_exists{false}, occurrence_exists{false}, proposal_exists{false};
        std::vector<DrivechainMintableDeposit> deposits;
        std::optional<std::pair<uint256, DrivechainReplayedBmmEdge>> edge;
        std::vector<DrivechainSuccessfulWithdrawal> withdrawals;
        std::vector<DrivechainWithdrawalProposalIdentity> proposals;
    };
    Fixture seed;
    seed.previous.height = 100;
    seed.previous.hash = uint256S("01");
    seed.next.height = 101;
    seed.next.hash = uint256S("02");
    seed.stored = seed.previous;
    seed.deposits.push_back({{uint256S("03"), 0}, seed.next.hash, 101, 100, {0x51}});
    seed.edge = std::make_pair(seed.previous.hash, DrivechainReplayedBmmEdge{seed.next.hash, 100, 101, true, uint256S("04")});
    seed.withdrawals.push_back({24, uint256S("05"), 101, seed.next.hash});
    seed.proposals.push_back({24, uint256S("06")});
    using Event = std::tuple<uint32_t, uint64_t, std::vector<unsigned char>>;
    using Events = std::vector<Event>;
    struct NativeFault {};
    const auto run = [&](const Fixture& f, bool migrated, int fault, Events& events) {
        const auto call = [&](uint32_t step, uint64_t index, std::span<const unsigned char> input) -> std::vector<unsigned char> {
            // Compare observable database effects and diagnostics, not pure field reads.
            if (step == 3 || step == 4 || step == 5 || step == 6 || step == 10 || step == 12 ||
                step == 14 || step == 15 || step == 17 || step >= 18) {
                events.emplace_back(step, index, std::vector<unsigned char>(input.begin(), input.end()));
                if (static_cast<int>(events.size()) == fault) throw NativeFault{};
            }
            switch (step) {
            case 0: return encode(f.open);
            case 1: return encode(f.previous);
            case 2: return encode(f.next);
            case 3: return encode(f.identity_exists);
            case 4: return f.identity_read ? encode(true, f.stored_schema, uint256{}) : encode(false);
            case 5: return encode(f.tip_exists);
            case 6: return f.tip_read ? encode(true, f.stored) : encode(false);
            case 7: return encode(Hash(input));
            case 8: return index == 0 ? encode(f.schema) : encode(uint64_t{f.deposits.size()}, f.edge.has_value(),
                uint64_t{f.withdrawals.size()}, uint64_t{f.proposals.size()});
            case 9: return encode(f.deposits.at(index));
            case 10: return encode(f.deposit_exists);
            case 11: return encode(f.edge.value());
            case 12: return encode(f.edge_exists);
            case 13: return encode(f.withdrawals.at(index));
            case 14: return encode(f.withdrawal_exists);
            case 15: return encode(f.occurrence_exists);
            case 16: return encode(f.proposals.at(index).sidechain_slot, f.proposals.at(index).m6id);
            case 17: return encode(f.proposal_exists);
            case 24: return encode(f.commit);
            default: return {};
            }
        };
        try {
            if (migrated) return int(hs::RunReplayStore(hs::ReplayStoreWorkflow::APPEND, call));
            const auto effect = [&](uint32_t step, uint64_t index = 0) { call(step, index, {}); };
            const auto query = [&](uint32_t step, uint64_t index = 0) { return call(step, index, {}).at(0) != 0; };
            const auto error = [&](const std::string& message) {
                call(25, 0, std::span{reinterpret_cast<const unsigned char*>(message.data()), message.size()});
                return 0;
            };
            const auto read = [&](uint32_t present, uint32_t record, const char* name) {
                if (!query(present)) return false;
                if (query(record)) return true;
                error(std::string("persistent parent replay ") + name + " record is malformed");
                return false;
            };
            if (!f.open) return error("persistent parent replay database is not open");
            if (!OriginalReplayTip(f.previous) || !OriginalReplayTip(f.next) ||
                f.previous.height == UINT32_MAX || f.next.height != f.previous.height + 1)
                return error("refusing a non-contiguous persistent parent replay append");
            if (!read(3, 4, "identity") || f.stored_schema != f.schema)
                return error("persistent parent replay append uses the wrong schema");
            if (!read(5, 6, "tip") || f.stored.height != f.previous.height || f.stored.hash != f.previous.hash ||
                (HashWriter{} << f.stored.state).GetHash() != (HashWriter{} << f.previous.state).GetHash())
                return error("persistent parent replay tip changed before append");
            std::set<Sidechain::Bitcoin::COutPoint> deposits;
            for (size_t i = 0; i < f.deposits.size(); ++i) {
                const auto& d = f.deposits[i];
                const uint32_t facts = nonzero(d.outpoint.hash) | ((d.outpoint.n != UINT32_MAX) << 1) | (nonzero(d.block_hash) << 2);
                if (!hs::ParentReplayRecord(hs::ReplayRecordKind::DEPOSIT, facts, d.value, d.address.size(), MAX_MONEY) ||
                    d.block_height != f.next.height || d.block_hash != f.next.hash || !deposits.insert(d.outpoint).second || query(10, i))
                    return error("persistent parent replay append contains a duplicate or malformed deposit");
            }
            if (f.edge) {
                const auto& [parent, edge] = *f.edge;
                const uint32_t facts = nonzero(parent) | (nonzero(edge.successor_hash) << 1) |
                    (edge.has_canonical_commitment << 2) | (nonzero(edge.committed_sidechain_hash) << 3);
                if (!hs::ParentReplayRecord(hs::ReplayRecordKind::EDGE, facts, 0, edge.parent_height, edge.successor_height) ||
                    edge.parent_height != f.previous.height || edge.successor_height != f.next.height ||
                    edge.successor_hash != f.next.hash || parent != f.previous.hash || query(12))
                    return error("persistent parent replay append contains a duplicate or malformed BMM edge");
            }
            std::set<std::pair<uint8_t, uint256>> withdrawals, proposals;
            for (size_t i = 0; i < f.withdrawals.size(); ++i) {
                const auto& w = f.withdrawals[i];
                if (!nonzero(w.block_hash) || w.block_height != f.next.height || w.block_hash != f.next.hash ||
                    !withdrawals.emplace(w.sidechain_slot, w.m6id).second || (f.schema == 4 && query(14, i)) || query(15, i))
                    return error("persistent parent replay append contains a duplicate or malformed successful withdrawal");
            }
            for (size_t i = 0; i < f.proposals.size(); ++i) {
                const auto& p = f.proposals[i];
                if (!proposals.emplace(p.sidechain_slot, p.m6id).second)
                    return error("persistent parent replay append contains a duplicate M3 proposal identity");
                if (f.schema == 4 && query(17, i))
                    return error("M3 re-proposes a withdrawal that already succeeded on the active parent chain");
            }
            effect(18);
            for (size_t i = 0; i < f.deposits.size(); ++i) effect(19, i);
            if (f.edge) effect(20);
            for (size_t i = 0; i < f.withdrawals.size(); ++i) {
                if (!query(14, i)) effect(21, i);
                if (f.schema == 5) effect(22, i);
            }
            effect(23);
            return query(24) ? 1 : error("failed to atomically append persistent parent replay block");
        } catch (const NativeFault&) {
            return -1;
        }
    };
    FastRandomContext rng(true);
    for (unsigned fixture = 0; fixture < 1800; ++fixture) {
        auto f = seed;
        f.schema = f.stored_schema = fixture % 2 ? 5 : 4;
        if (fixture % 6 == 0) { f.deposits.clear(); f.withdrawals.clear(); f.proposals.clear(); f.edge.reset(); }
        for (unsigned mutation = 0; mutation < fixture % 4; ++mutation) {
            switch (rng.randrange(28)) {
            case 0: f.open = false; break;
            case 1: f.identity_exists = false; break;
            case 2: f.identity_read = false; break;
            case 3: f.tip_exists = false; break;
            case 4: f.tip_read = false; break;
            case 5: f.commit = false; break;
            case 6: f.stored_schema = 99; break;
            case 7: f.previous.height = UINT32_MAX; break;
            case 8: f.next.height = rng.rand32(); break;
            case 9: f.next.hash.SetNull(); break;
            case 10: f.stored.height = 99; break;
            case 11: f.stored.hash.SetNull(); break;
            case 12: f.stored.state.ctip_value = 1; break;
            case 13: f.deposit_exists = true; break;
            case 14: f.edge_exists = true; break;
            case 15: f.withdrawal_exists = true; break;
            case 16: f.occurrence_exists = true; break;
            case 17: f.proposal_exists = true; break;
            case 18: f.deposits.push_back(seed.deposits.front()); break;
            case 19: f.withdrawals.push_back(seed.withdrawals.front()); break;
            case 20: f.proposals.push_back(seed.proposals.front()); break;
            case 21: if (!f.deposits.empty()) f.deposits[0].value = rng.randbool() ? -1 : MAX_MONEY + 1; break;
            case 22: if (!f.deposits.empty()) f.deposits[0].address.resize(rng.randbool() ? 0 : 10001); break;
            case 23: if (!f.deposits.empty()) f.deposits[0].outpoint.SetNull(); break;
            case 24: if (!f.withdrawals.empty()) f.withdrawals[0].block_height = 100; break;
            case 25: if (f.edge) f.edge->second.committed_sidechain_hash.SetNull(); break;
            case 26: if (f.edge) f.edge->first.SetNull(); break;
            case 27: if (!f.deposits.empty()) f.deposits[0].block_hash.SetNull(); break;
            }
        }
        Events expected, actual;
        const int status = run(f, false, -1, expected);
        BOOST_CHECK_EQUAL(run(f, true, -1, actual), status);
        BOOST_CHECK(actual == expected);
        for (size_t fault = 1; fault <= expected.size(); ++fault) {
            Events old_fault, new_fault;
            BOOST_CHECK_EQUAL(run(f, false, fault, old_fault), -1);
            BOOST_CHECK_EQUAL(run(f, true, fault, new_fault), -1);
            BOOST_CHECK(new_fault == old_fault);
            BOOST_CHECK_EQUAL(new_fault.size(), fault);
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_tip_callbacks_preserve_exception_boundaries)
{
    namespace hs = drivechain::haskell;
    const std::vector<uint32_t> expected{1,2,3,4,5,8,10,11,12,13,18,19,24,26,27,29,30,40,42};
    struct NativeFault {};
    for (size_t fault = 0; fault <= expected.size(); ++fault) {
        size_t reads{0};
        const auto run = [&] {
            return hs::ParentReplayTip([&](uint32_t step) {
                BOOST_CHECK_EQUAL(step, expected.at(reads));
                if (reads++ == fault) throw NativeFault{};
                BOOST_CHECK(hs::ParentReplayRecord(hs::ReplayRecordKind::AMOUNT, 0, 1, 0, MAX_MONEY));
                return step != 13 && step != 19 && step != 27 && step != 30 && step != 42;
            });
        };
        if (fault < expected.size()) BOOST_CHECK_THROW(run(), NativeFault);
        else BOOST_CHECK(run());
        BOOST_CHECK_EQUAL(reads, std::min(fault + 1, expected.size()));
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_identity_preserves_every_native_read_and_fault)
{
    namespace hs = drivechain::haskell;
    struct NativeFault {};
    uint32_t reads{0};
    BOOST_CHECK_EQUAL(hs::ParentReplayStore(hs::ReplayStoreFlow::IDENTITY, [&](uint32_t step) {
        BOOST_CHECK_EQUAL(step, ++reads);
        BOOST_CHECK_EQUAL(hs::ParentReplaySchema(0, 4, 5), 4U);
        return 1U;
    }), 1U);
    BOOST_CHECK_EQUAL(reads, 38U);
    for (uint32_t fault = 1; fault <= 38; ++fault) {
        reads = 0;
        BOOST_CHECK_THROW(hs::ParentReplayStore(hs::ReplayStoreFlow::IDENTITY, [&](uint32_t step) -> uint32_t {
            BOOST_CHECK_EQUAL(step, ++reads);
            if (step == fault) throw NativeFault{};
            return 1;
        }), NativeFault);
        BOOST_CHECK_EQUAL(reads, fault);
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_cache_flows_preserve_order_and_failure_boundaries)
{
    namespace hs = drivechain::haskell;
    struct NativeFault {};
    for (uint32_t kind = 13; kind <= 15; ++kind) {
        for (uint32_t first = 0; first <= 26; ++first) {
            for (uint32_t second = 0; second <= 26; ++second) {
                const auto reply = [&](uint32_t step) -> uint32_t {
                    if (kind == 13) return 1;
                    if (kind == 15 && (step == 19 || step == 22 || step == 26)) return 0;
                    return step != first && step != second;
                };
                std::vector<uint32_t> expected, actual;
                const auto read = [&](uint32_t step) { expected.push_back(step); return reply(step); };
                const auto original = [&]() -> uint32_t {
                    if (kind == 13) {
                        for (uint32_t step = 1; step <= 14; ++step) read(step);
                        return 1;
                    }
                    if (kind == 14) {
                        for (uint32_t step = 1; step <= 14; ++step) if (!read(step)) return 0;
                        return 1;
                    }
                    if (!read(1)) return 0;
                    for (uint32_t step = 2; step <= 18; ++step) {
                        if (!read(step)) { read(19); return 2; }
                    }
                    if (!read(20)) return 2;
                    if (!read(21)) { read(22); return 2; }
                    if (!read(23)) return 2;
                    if (!read(24) || !read(25)) { read(26); return 2; }
                    return 1;
                };
                const auto status = original();
                BOOST_CHECK_EQUAL(hs::ParentReplayStore(static_cast<hs::ReplayStoreFlow>(kind), [&](uint32_t step) {
                    actual.push_back(step);
                    BOOST_CHECK(hs::ParentReplayRecord(hs::ReplayRecordKind::LESS, 0, 0, 1, 2));
                    return reply(step);
                }), status);
                BOOST_CHECK(actual == expected);
                for (size_t fault = 0; fault < expected.size(); ++fault) {
                    size_t reads{0};
                    BOOST_CHECK_THROW(hs::ParentReplayStore(static_cast<hs::ReplayStoreFlow>(kind), [&](uint32_t step) -> uint32_t {
                        BOOST_CHECK_EQUAL(step, expected.at(reads));
                        if (reads++ == fault) throw NativeFault{};
                        return reply(step);
                    }), NativeFault);
                    BOOST_CHECK_EQUAL(reads, fault + 1);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_cache_load_preserves_selection_and_publication)
{
    namespace hs = drivechain::haskell;
    struct NativeFault {};
    for (uint32_t variant = 0; variant < 4096; ++variant) {
        for (uint32_t load_status = 0; load_status < 4; ++load_status) {
            const auto reply = [&](uint32_t step) -> uint32_t {
                switch (step) {
                case 1: return variant & 1;
                case 4: return (variant >> 1) & 1;
                case 5: return (variant >> 2) & 1;
                case 6: return load_status;
                case 9: case 10: case 11: case 12: case 13: case 14: case 15: case 16: case 17:
                    return (variant >> (step - 6)) & 1;
                case 22: return load_status == 2;
                case 23: return load_status == 3;
                default: return 1;
                }
            };
            std::vector<uint32_t> expected, actual;
            const auto read = [&](uint32_t step) { expected.push_back(step); return reply(step); };
            const auto original = [&]() -> uint32_t {
                if (!read(1)) read(2);
                read(3);
                if (read(4) || read(5)) return 0;
                const auto status = read(6);
                if (status == 1) {
                    read(7); read(8);
                    const bool contradiction = read(9) && ((read(10) && read(11)) ||
                        (read(12) && (read(13) || read(14) || read(15))) || (read(16) && read(17)));
                    if (!contradiction) { read(18); read(19); read(20); return 1; }
                    read(21);
                }
                if (read(22) || read(23)) read(24);
                return 0;
            };
            const auto status = original();
            BOOST_CHECK_EQUAL(hs::ParentReplayStore(hs::ReplayStoreFlow::CACHE_LOAD, [&](uint32_t step) {
                actual.push_back(step);
                BOOST_CHECK_EQUAL(hs::ParentReplaySchema(1, 4, 5), 5U);
                return reply(step);
            }), status);
            BOOST_CHECK(actual == expected);
            for (size_t fault = 0; fault < expected.size(); ++fault) {
                size_t reads{0};
                BOOST_CHECK_THROW(hs::ParentReplayStore(hs::ReplayStoreFlow::CACHE_LOAD, [&](uint32_t step) -> uint32_t {
                    BOOST_CHECK_EQUAL(step, expected.at(reads));
                    if (reads++ == fault) throw NativeFault{};
                    return reply(step);
                }), NativeFault);
                BOOST_CHECK_EQUAL(reads, fault + 1);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_bootstrap_preimage_preserves_effect_order)
{
    namespace hs = drivechain::haskell;
    struct NativeFault {};
    for (const size_t count : {0U, 1U, 3U}) {
        for (uint32_t bits = 0; bits < 8; ++bits) {
            std::vector<uint32_t> expected{1,2,3,4,5,6};
            for (size_t index = 0; index < count; ++index) {
                for (uint32_t step = 7; step <= 14; ++step) expected.push_back(step);
                if ((bits >> index) & 1) for (uint32_t step = 15; step <= 17; ++step) expected.push_back(step);
                expected.push_back(18);
            }
            expected.push_back(7);
            for (size_t fault = 0; fault <= expected.size(); ++fault) {
                size_t index{0}, reads{0};
                const auto run = [&] {
                    return hs::ParentReplayStore(hs::ReplayStoreFlow::BOOTSTRAP_PREIMAGE, [&](uint32_t step) -> uint32_t {
                        BOOST_CHECK_EQUAL(step, expected.at(reads));
                        if (reads++ == fault) throw NativeFault{};
                        BOOST_CHECK_EQUAL(hs::ParentReplaySchema(1, 4, 5), 5U);
                        if (step == 7) return index < count;
                        if (step == 14) return (bits >> index) & 1;
                        if (step == 18) ++index;
                        return 1;
                    });
                };
                if (fault < expected.size()) {
                    BOOST_CHECK_THROW(run(), NativeFault);
                    BOOST_CHECK_EQUAL(reads, fault + 1);
                } else {
                    BOOST_CHECK_EQUAL(run(), 1U);
                    BOOST_CHECK_EQUAL(reads, expected.size());
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_bootstrap_reconstruction_preserves_effect_order)
{
    namespace hs = drivechain::haskell;
    struct NativeFault {};
    const std::vector<uint32_t> branches{1,5,6,12,13,14,19,23,26,27,30,35,41,42,46};
    for (uint32_t variant = 0; variant < (1U << branches.size()); ++variant) {
        for (const size_t count : {0U, 2U}) {
            size_t index{0};
            const auto reply = [&](uint32_t step) -> uint32_t {
                if (step == 11) return index < count;
                if (step == 31) ++index;
                const auto it = std::find(branches.begin(), branches.end(), step);
                return it == branches.end() ? 1 : (variant >> (it - branches.begin())) & 1;
            };
            std::vector<uint32_t> expected, actual;
            const auto read = [&](uint32_t step) { expected.push_back(step); return reply(step); };
            const auto original = [&]() -> uint32_t {
                if (read(1)) {
                    read(2); read(3); read(4);
                    if (!read(5) || !read(6)) { read(7); read(8); return 0; }
                    read(9); read(10);
                    while (read(11)) {
                        if (!read(12) || !read(13) || !read(14)) { read(15); read(16); return 0; }
                        read(17); read(18);
                        if (!read(19)) { read(20); read(21); return 0; }
                        read(22);
                        if (read(23)) { read(24); read(25); }
                        else if (!read(26) || !read(27)) { read(28); read(29); return 0; }
                        if (!read(30)) { read(38); read(39); return 0; }
                        read(31);
                    }
                    read(32); read(33); read(34);
                } else {
                    read(40);
                    if (!read(41)) { read(36); return 0; }
                    if (!read(42)) { read(43); read(44); return 0; }
                    read(45);
                    if (!read(46)) { read(36); return 0; }
                    read(47); read(48); read(49);
                }
                if (!read(35)) { read(36); return 0; }
                read(37); return 1;
            };
            const auto status = original();
            index = 0;
            BOOST_CHECK_EQUAL(hs::ParentReplayStore(hs::ReplayStoreFlow::CACHE_REBUILD, [&](uint32_t step) {
                actual.push_back(step);
                BOOST_CHECK_EQUAL(hs::ParentReplaySchema(1, 4, 5), 5U);
                return reply(step);
            }), status);
            BOOST_CHECK(actual == expected);
            for (size_t fault = 0; fault < expected.size(); ++fault) {
                index = 0;
                size_t reads{0};
                BOOST_CHECK_THROW(hs::ParentReplayStore(hs::ReplayStoreFlow::CACHE_REBUILD, [&](uint32_t step) -> uint32_t {
                    BOOST_CHECK_EQUAL(step, expected.at(reads));
                    if (reads++ == fault) throw NativeFault{};
                    return reply(step);
                }), NativeFault);
                BOOST_CHECK_EQUAL(reads, fault + 1);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_boundaries_preserve_reorg_and_publication_order)
{
    namespace hs = drivechain::haskell;
    struct NativeFault {};
    for (const bool publication : {false, true}) {
        const auto kind = publication ? hs::ReplayStoreFlow::REPLAY_PUBLISH : hs::ReplayStoreFlow::REPLAY_PREFLIGHT;
        const std::vector<uint32_t> branches = publication ? std::vector<uint32_t>{1,2,5,6,9,10,13,14} :
            std::vector<uint32_t>{1,2,4,5,9,10,11,14,15,16,18,19,22,25,26,27};
        for (uint32_t variant = 0; variant < (1U << branches.size()); ++variant) {
            bool stale{false};
            const auto reply = [&](uint32_t step) -> uint32_t {
                const auto it = std::find(branches.begin(), branches.end(), step);
                const uint32_t value = it == branches.end() ? 1 : (variant >> (it - branches.begin())) & 1;
                if (!publication) {
                    if (step == 16 || step == 19) { stale = value; return 1; }
                    if (step == 17 || step == 20) return stale;
                }
                return value;
            };
            std::vector<uint32_t> expected, actual;
            const auto read = [&](uint32_t step) { expected.push_back(step); return reply(step); };
            const auto original = [&]() -> uint32_t {
                if (publication) {
                    if (!read(1)) return 0;
                    if (!read(2)) { read(3); read(4); return 0; }
                    if (!read(5)) return 0;
                    if (!read(6)) { read(7); read(8); return 0; }
                    if (!read(9)) return 0;
                    if (!read(10)) { read(11); read(12); return 0; }
                    if (read(13) && !read(14)) return 0;
                    read(15); read(16); return 1;
                }
                if (!read(1)) return 0;
                if (!read(2)) { read(3); return 2; }
                if (!read(4)) {
                    if (read(5)) { read(6); return 2; }
                    read(7); read(8);
                    if (!read(9)) return 2;
                }
                if (!read(10)) return 2;
                if (!read(11)) { read(12); read(13); return 2; }
                if (read(14)) {
                    if (!read(15)) return 2;
                    read(16);
                }
                if (!read(17)) {
                    if (!read(18)) return 2;
                    read(19);
                }
                if (read(20)) {
                    read(21);
                    if (read(22)) { read(23); return 2; }
                    read(24);
                    if (!read(25)) return 2;
                }
                if (!read(26)) return 2;
                if (!read(27)) { read(28); return 2; }
                return 1;
            };
            const auto status = original();
            stale = false;
            BOOST_CHECK_EQUAL(hs::ParentReplayStore(kind, [&](uint32_t step) {
                actual.push_back(step);
                BOOST_CHECK_EQUAL(hs::ParentReplaySchema(1, 4, 5), 5U);
                return reply(step);
            }), status);
            BOOST_CHECK(actual == expected);
            for (size_t fault = 0; fault < expected.size(); ++fault) {
                stale = false;
                size_t reads{0};
                BOOST_CHECK_THROW(hs::ParentReplayStore(kind, [&](uint32_t step) -> uint32_t {
                    BOOST_CHECK_EQUAL(step, expected.at(reads));
                    if (reads++ == fault) throw NativeFault{};
                    return reply(step);
                }), NativeFault);
                BOOST_CHECK_EQUAL(reads, fault + 1);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_advance_preserves_commit_order_and_terminal_height)
{
    namespace hs = drivechain::haskell;
    struct NativeFault {};
    const std::vector<uint32_t> branches{3,9,11,12,19,20,24,28,29};
    const std::vector<std::pair<uint32_t, uint32_t>> bounds{
        {0,0},{5,3},{0,1},{3,6},{UINT32_MAX-2,UINT32_MAX},{UINT32_MAX,UINT32_MAX}};
    for (const auto& [start,target] : bounds) {
        for (uint32_t variant = 0; variant < (1U << branches.size()); ++variant) {
            for (const uint64_t fail_height : {uint64_t{start}+1, uint64_t{start}+2}) {
                uint32_t height{start}, durable{start}, memory{start};
                const auto reply = [&](uint32_t step) -> uint32_t {
                    const auto it = std::find(branches.begin(), branches.end(), step);
                    const bool value = it == branches.end() || (step != 3 && height != fail_height) ||
                        ((variant >> (it - branches.begin())) & 1);
                    if (step == 1) return start < target;
                    if (step == 5) return hs::ParentReplayRecord(hs::ReplayRecordKind::LESS, 0, 0, height, target);
                    if (step == 6) { BOOST_REQUIRE(height < target); ++height; }
                    if (step == 27) { BOOST_REQUIRE(height > 0); BOOST_CHECK_EQUAL(memory, height-1); }
                    if (step == 29 && value) durable = height;
                    if (step == 31) { BOOST_CHECK_EQUAL(durable, height); memory = height; }
                    return value;
                };
                std::vector<uint32_t> expected, actual;
                const auto read = [&](uint32_t step) { expected.push_back(step); return reply(step); };
                const auto original = [&]() -> uint32_t {
                    if (!read(1)) return 1;
                    read(2);
                    if (!read(3)) return 0;
                    read(4);
                    while (read(5)) {
                        read(6); read(7); read(8);
                        if (!read(9)) return 0;
                        read(10);
                        if (!read(11)) return 0;
                        if (!read(12)) { read(13); read(14); return 0; }
                        read(15); read(16); read(17); read(18);
                        if (!read(19) || !read(20)) { read(21); return 0; }
                        read(22); read(23);
                        if (read(24)) { read(25); read(26); read(27); }
                        if (!read(28) || !read(29)) { read(21); return 0; }
                        read(30); read(31); read(32); read(33);
                    }
                    return 1;
                };
                const auto status = original();
                const auto expected_memory = memory;
                const auto expected_durable = durable;
                height = durable = memory = start;
                BOOST_CHECK_EQUAL(hs::ParentReplayStore(hs::ReplayStoreFlow::REPLAY_ADVANCE, [&](uint32_t step) {
                    actual.push_back(step);
                    return reply(step);
                }), status);
                BOOST_CHECK(actual == expected);
                BOOST_CHECK_EQUAL(memory, expected_memory);
                BOOST_CHECK_EQUAL(durable, expected_durable);
                if (status && start < target) BOOST_CHECK_EQUAL(memory, target);
                for (size_t fault = 0; fault < expected.size(); ++fault) {
                    height = durable = memory = start;
                    size_t reads{0};
                    BOOST_CHECK_THROW(hs::ParentReplayStore(hs::ReplayStoreFlow::REPLAY_ADVANCE, [&](uint32_t step) -> uint32_t {
                        BOOST_CHECK_EQUAL(step, expected.at(reads));
                        if (reads++ == fault) throw NativeFault{};
                        return reply(step);
                    }), NativeFault);
                    BOOST_CHECK_EQUAL(reads, fault + 1);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_budget_snapshot_and_lock_preserve_effect_order)
{
    namespace hs = drivechain::haskell;
    struct NativeFault {};
    for (const auto kind : {hs::ReplayStoreFlow::REPLAY_BUDGET, hs::ReplayStoreFlow::REPLAY_SNAPSHOT,
                            hs::ReplayStoreFlow::REPLAY_LOCK}) {
        for (uint32_t variant = 0; variant < 64; ++variant) {
            const auto reply = [&](uint32_t step) -> uint32_t {
                if (kind == hs::ReplayStoreFlow::REPLAY_BUDGET && (step == 1 || step == 3 || step == 4)) return (variant >> step) & 1;
                if (kind == hs::ReplayStoreFlow::REPLAY_SNAPSHOT && step <= 2) return (variant >> step) & 1;
                if (kind == hs::ReplayStoreFlow::REPLAY_LOCK && (step == 1 || step == 2 || step == 5)) return (variant >> step) & 1;
                return 1;
            };
            std::vector<uint32_t> expected, actual;
            const auto read = [&](uint32_t step) { expected.push_back(step); return reply(step); };
            const auto original = [&]() -> uint32_t {
                if (kind == hs::ReplayStoreFlow::REPLAY_BUDGET) {
                    if (!read(1)) return 1;
                    read(2);
                    if (!read(3)) { if (read(4)) read(5); return 0; }
                    read(6); return 1;
                }
                if (kind == hs::ReplayStoreFlow::REPLAY_SNAPSHOT) {
                    if (!read(1) || !read(2)) return 0;
                    for (uint32_t step = 3; step <= 7; ++step) read(step);
                    return 0;
                }
                if (read(1)) { if (!read(2)) { read(3); return 0; } }
                else read(4);
                if (!read(5)) return 0;
                read(6); return 1;
            };
            const auto status = original();
            BOOST_CHECK_EQUAL(hs::ParentReplayStore(kind, [&](uint32_t step) {
                actual.push_back(step);
                BOOST_CHECK_EQUAL(hs::ParentReplaySchema(1, 4, 5), 5U);
                return reply(step);
            }), status);
            BOOST_CHECK(actual == expected);
            for (size_t fault = 0; fault < expected.size(); ++fault) {
                size_t reads{0};
                BOOST_CHECK_THROW(hs::ParentReplayStore(kind, [&](uint32_t step) -> uint32_t {
                    BOOST_CHECK_EQUAL(step, expected.at(reads));
                    if (reads++ == fault) throw NativeFault{};
                    return reply(step);
                }), NativeFault);
                BOOST_CHECK_EQUAL(reads, fault + 1);
            }
        }
    }
    for (const uint32_t remaining : {0U,1U,UINT32_MAX}) {
        for (const uint32_t requested : {0U,1U,UINT32_MAX}) {
            uint32_t budget = remaining;
            bool diagnosed{false};
            const auto result = hs::ParentReplayStore(hs::ReplayStoreFlow::REPLAY_BUDGET, [&](uint32_t step) -> uint32_t {
                if (step == 3) return hs::ParentReplayRecord(hs::ReplayRecordKind::HEIGHT, 0, 0, requested, budget);
                if (step == 5) diagnosed = true;
                if (step == 6) budget -= requested;
                return 1;
            });
            BOOST_CHECK_EQUAL(result, requested <= remaining);
            BOOST_CHECK_EQUAL(budget, requested <= remaining ? remaining - requested : remaining);
            BOOST_CHECK_EQUAL(diagnosed, requested > remaining);
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_lock_keeps_raii_scope_across_interpreter_calls)
{
    namespace hs = drivechain::haskell;
    struct NativeFault {};
    std::mutex mutex;
    for (const bool budget : {false, true}) {
        for (const uint32_t fault : {0U,5U,6U}) {
            const auto run = [&] {
                std::unique_lock<std::mutex> lock(mutex, std::defer_lock);
                return hs::ParentReplayStore(hs::ReplayStoreFlow::REPLAY_LOCK, [&](uint32_t step) -> uint32_t {
                    switch (step) {
                    case 1: return budget;
                    case 2: return lock.try_lock();
                    case 3: BOOST_FAIL("uncontended replay lock was rejected"); return 0;
                    case 4: lock.lock(); return 1;
                    case 5: case 6:
                        BOOST_CHECK(lock.owns_lock());
                        BOOST_CHECK_EQUAL(hs::ParentReplaySchema(1, 4, 5), 5U);
                        if (step == fault) throw NativeFault{};
                        return 1;
                    default: throw std::logic_error("unexpected lock action");
                    }
                });
            };
            if (fault) BOOST_CHECK_THROW(run(), NativeFault);
            else BOOST_CHECK_EQUAL(run(), 1U);
            std::unique_lock<std::mutex> released(mutex, std::try_to_lock);
            BOOST_REQUIRE(released.owns_lock());
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_work_flows_preserve_short_circuit_and_faults)
{
    namespace hs = drivechain::haskell;
    struct Fault {};
    for (const auto kind : {hs::ReplayStoreFlow::PARENT_POW, hs::ReplayStoreFlow::BLOCK_PROOF, hs::ReplayStoreFlow::CHAINWORK})
    for (unsigned flags = 0; flags < 32; ++flags) {
        std::vector<uint32_t> expected, actual;
        const auto reply = [&](uint32_t step) -> uint32_t {
            if (step == 1) return 1;
            if (kind == hs::ReplayStoreFlow::PARENT_POW && (step == 6 || step == 8)) return 0;
            if (kind == hs::ReplayStoreFlow::BLOCK_PROOF && (step == 5 || step == 6)) return 1;
            if (kind == hs::ReplayStoreFlow::CHAINWORK && step == 5) return 0;
            return (flags >> (step == 7 ? 4 : step - 2)) & 1;
        };
        const auto read = [&](uint32_t step) { expected.push_back(step); return reply(step); };
        const auto original = [&]() -> uint32_t {
            read(1);
            if (kind == hs::ReplayStoreFlow::PARENT_POW) {
                if (read(2) || read(3) || read(4) || read(5)) return read(6);
                return read(7) ? read(8) : 1U;
            }
            if (kind == hs::ReplayStoreFlow::BLOCK_PROOF) {
                if (read(2) || read(3) || read(4)) { read(5); return 0; }
                read(6); return 1;
            }
            return read(2) || read(3) ? read(5) : 1U;
        };
        const auto status = original();
        BOOST_CHECK_EQUAL(hs::ParentReplayStore(kind, [&](uint32_t step) {
            actual.push_back(step);
            BOOST_CHECK(hs::ParentReplayRecord(hs::ReplayRecordKind::POSITIVE, 0, 0, 1));
            return reply(step);
        }), status);
        BOOST_CHECK(actual == expected);
        for (size_t fault = 0; fault < expected.size(); ++fault) {
            actual.clear();
            BOOST_CHECK_THROW(hs::ParentReplayStore(kind, [&](uint32_t step) -> uint32_t {
                actual.push_back(step);
                if (actual.size() - 1 == fault) throw Fault{};
                return reply(step);
            }), Fault);
            BOOST_CHECK(actual == std::vector<uint32_t>(expected.begin(), expected.begin() + fault + 1));
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_signet_flow_preserves_order_and_faults)
{
    namespace hs = drivechain::haskell;
    for (unsigned flags = 0; flags < 128; ++flags) {
        const auto bit = [&](unsigned n) { return (flags >> n) & 1U; };
        const auto reply = [&](uint32_t action) -> uint32_t {
            switch (action) {
            case 1: return bit(0);
            case 2: return bit(1);
            case 3: return bit(2);
            case 5: return bit(3);
            case 10: return bit(4);
            case 11: return bit(5);
            case 16: return bit(6);
            case 4: case 6: case 17: return 0;
            default: return 1;
            }
        };
        std::vector<uint32_t> expected;
        const auto step = [&](uint32_t action) { expected.push_back(action); return reply(action); };
        const bool accepted = [&] {
            if (step(1)) return true;
            if (step(2) || !step(3)) { step(4); return false; }
            if (!step(5)) { step(6); return false; }
            step(7); step(8); step(9);
            if (!step(10) && !step(11)) return false;
            step(12); step(13); step(14); step(15);
            if (step(16)) return true;
            step(17); return false;
        }();
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            std::vector<uint32_t> seen;
            const auto run = [&] {
                return hs::ParentReplayStore(hs::ReplayStoreFlow::PARENT_SIGNET, [&](uint32_t action) {
                    seen.push_back(action);
                    if (seen.size() == fault + 1) throw std::runtime_error("parent signet action fault");
                    return reply(action);
                });
            };
            if (fault < expected.size()) BOOST_CHECK_THROW(run(), std::runtime_error);
            else BOOST_CHECK_EQUAL(run(), accepted);
            BOOST_CHECK(seen == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_warmup_flow_preserves_rpc_order_and_faults)
{
    namespace hs = drivechain::haskell;
    for (unsigned flags = 0; flags < 16; ++flags) {
        const auto reply = [&](uint32_t action) -> uint32_t {
            switch (action) {
            case 2: return flags & 1;
            case 4: return (flags >> 1) & 1;
            case 6: return (flags >> 2) & 1;
            case 8: return (flags >> 3) & 1;
            default: return 1;
            }
        };
        std::vector<uint32_t> expected{1,2};
        bool accepted{false};
        if (!reply(2)) expected.push_back(3);
        else {
            expected.push_back(4);
            if (reply(4)) {
                expected.insert(expected.end(), {5,6});
                expected.push_back(reply(6) ? 8 : 7);
                accepted = reply(6) && reply(8);
            }
        }
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            std::vector<uint32_t> seen;
            const auto run = [&] {
                return hs::ParentReplayStore(hs::ReplayStoreFlow::WARM_PARENT, [&](uint32_t action) {
                    seen.push_back(action);
                    if (seen.size() == fault + 1) throw std::runtime_error("warmup fault");
                    return reply(action);
                });
            };
            if (fault < expected.size()) BOOST_CHECK_THROW(run(), std::runtime_error);
            else BOOST_CHECK_EQUAL(run(), accepted);
            BOOST_CHECK(seen == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
        }
    }
}

BOOST_AUTO_TEST_CASE(replay_each_matches_range_for_lifetimes_and_faults)
{
    struct Range {
        std::vector<unsigned> values, events;
        size_t fault;
        void event(unsigned n) {
            events.push_back(n);
            if (events.size() == fault + 1) throw std::runtime_error("range fault");
        }
        struct Iterator {
            Range* range;
            size_t index;
            bool operator!=(const Iterator& other) const { range->event(3); return index != other.index; }
            unsigned& operator*() const { range->event(5); return range->values.at(index); }
            Iterator& operator++() { range->event(4); ++index; return *this; }
        };
        Iterator begin() { event(1); return {this, 0}; }
        Iterator end() { event(2); return {this, values.size()}; }
    };
    for (unsigned count : {0, 1, 3}) for (unsigned reject = 0; reject <= count; ++reject) {
        const auto run = [&](bool migrated, size_t fault) {
            Range range{{0, 1, 2}, {}, fault};
            range.values.resize(count);
            const auto body = [&](unsigned& value) {
                range.event(6);
                value += 10;
                return value != reject + 10;
            };
            unsigned outcome{0};
            try {
                const auto original = [&] { for (auto& value : range) if (!body(value)) return false; return true; };
                outcome = migrated ? drivechain::haskell::ParentReplayEach(range, body) : original();
            } catch (const std::runtime_error&) { outcome = 2; }
            return std::make_tuple(outcome, range.values, range.events);
        };
        const auto baseline = run(false, 1000);
        for (size_t fault = 0; fault <= std::get<2>(baseline).size(); ++fault) {
            const auto expected = run(false, fault), actual = run(true, fault);
            BOOST_CHECK_EQUAL(std::get<0>(actual), std::get<0>(expected));
            BOOST_CHECK(std::get<1>(actual) == std::get<1>(expected));
            BOOST_CHECK(std::get<2>(actual) == std::get<2>(expected));
        }
    }
    const std::array<unsigned,3> immutable{1, 2, 3};
    unsigned total{0};
    BOOST_CHECK(drivechain::haskell::ParentReplayEach(immutable, [&](unsigned value) { total += value; return 2; }));
    BOOST_CHECK_EQUAL(total, 6U);
    BOOST_CHECK(drivechain::haskell::ParentReplayEach(std::vector<unsigned>{4, 5}, [&](unsigned value) { total += value; return true; }));
    BOOST_CHECK_EQUAL(total, 15U);
}

BOOST_AUTO_TEST_CASE(m4_mode_bridge_preserves_selection_and_lazy_slot_lookup)
{
    namespace hs = drivechain::haskell;
    for (uint32_t flags = 0; flags <= 16; ++flags)
        for (uint64_t votes : {uint64_t{0}, uint64_t{1}, UINT64_MAX})
            for (int64_t active : {int64_t{-1}, int64_t{0}, int64_t{1}, INT64_MAX}) {
                const bool reads = flags <= 15 && (flags & 1) && !(flags & 2);
                const int expected = flags > 15 ? -1 : !(flags & 1) ? 4 : (flags & 2) ? 5 :
                    active < 0 ? -1 : (flags & 4) ? (votes == uint64_t(active) ? 1 : 6) : (flags & 8) ? 2 : 3;
                for (bool fault : {false, true}) {
                    unsigned calls{0};
                    const auto run = [&] { return hs::M4Mode(flags, votes, [&](uint32_t step) -> int64_t {
                        BOOST_CHECK_EQUAL(step, 1U);
                        ++calls;
                        if (fault) throw std::runtime_error("M4 slot lookup failed");
                        return active;
                    }); };
                    if (expected < 0 || (reads && fault)) BOOST_CHECK_THROW(run(), std::runtime_error);
                    else BOOST_CHECK_EQUAL(run(), expected);
                    BOOST_CHECK_EQUAL(calls, unsigned(reads));
                }
            }
}

BOOST_AUTO_TEST_CASE(transaction_activation_gate_short_circuits_hash_access)
{
    namespace hs = drivechain::haskell;
    for (bool activated : {false, true}) for (bool matches : {false, true}) for (bool fault : {false, true}) {
        unsigned reads{0};
        const auto run = [&] { return hs::ParentReplayAll<2>({[&] { return activated; }, [&] {
            ++reads;
            if (fault) throw std::runtime_error("activation hash access failed");
            return matches;
        }}); };
        if (activated && fault) BOOST_CHECK_THROW(run(), std::runtime_error);
        else BOOST_CHECK_EQUAL(run(), activated && matches);
        BOOST_CHECK_EQUAL(reads, unsigned(activated));
    }
}

BOOST_AUTO_TEST_CASE(ctip_spend_membership_preserves_duplicate_stop_and_effects)
{
    namespace hs = drivechain::haskell;
    for (unsigned encoding = 0; encoding < 256; ++encoding) {
        std::array<uint8_t, 4> slots{};
        for (unsigned i = 0; i < slots.size(); ++i) slots[i] = (encoding >> (2 * i)) & 3;
        std::map<uint8_t, unsigned> counts;
        std::set<uint8_t> spent;
        std::vector<uint64_t> expected, observed;
        int wanted{0};
        for (uint64_t i = 0; i < slots.size(); ++i) {
            expected.push_back(i);
            if (slots[i] && ++counts[slots[i]] > 1) { wanted = 1; break; }
        }
        const auto result = hs::CtipSpends(slots.size(), [&](uint32_t step, uint64_t i) -> int32_t {
            switch (step) {
            case 1: return 1;
            case 2: observed.push_back(i); return slots[i] != 0;
            case 3: return spent.insert(slots[i]).second ? 1 : 2;
            default: throw std::logic_error("invalid CTIP membership test action");
            }
        });
        BOOST_CHECK_EQUAL(result, wanted);
        BOOST_CHECK(observed == expected);
        for (uint8_t slot = 0; slot < 4; ++slot) BOOST_CHECK_EQUAL(spent.contains(slot), counts[slot] != 0);
    }
}

BOOST_AUTO_TEST_CASE(m4_mode_flow_preserves_guard_order_and_result)
{
    namespace hs = drivechain::haskell;
    const std::array<uint32_t,5> gates{1, 3, 6, 7, 9};
    for (unsigned flags = 0; flags < 32; ++flags) {
        const auto reply = [&](uint32_t n) -> uint32_t {
            const auto gate = std::find(gates.begin(), gates.end(), n);
            return gate == gates.end() ? 1 : (flags >> (gate - gates.begin())) & 1U;
        };
        std::vector<uint32_t> expected;
        const auto step = [&](uint32_t n) { expected.push_back(n); return reply(n); };
        const unsigned result = [&] {
            if (!step(1)) { step(2); return 0; }
            if (step(3)) { step(4); return 0; }
            step(5);
            if (step(6)) { if (!step(7)) { step(8); return 0; } return 1; }
            return step(9) ? 2 : 3;
        }();
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            std::vector<uint32_t> seen, effects;
            const auto run = [&] { return hs::ParentReplayStore(hs::ReplayStoreFlow::M4_MODE, [&](uint32_t n) {
                seen.push_back(n);
                if (seen.size() == fault + 1) throw std::runtime_error("M4 mode fault");
                effects.push_back(n); return reply(n);
            }); };
            if (fault < expected.size()) BOOST_CHECK_THROW(run(), std::runtime_error);
            else BOOST_CHECK_EQUAL(run(), result);
            BOOST_CHECK(seen == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
            BOOST_CHECK(effects == std::vector<uint32_t>(expected.begin(), expected.begin() + fault));
        }
    }
}

template <typename Response>
static void CheckReplayFlowFaults(drivechain::haskell::ReplayStoreFlow flow,
    const std::vector<uint32_t>& expected, uint32_t status, Response response)
{
    for (size_t fault = 0; fault <= expected.size(); ++fault) {
        BOOST_TEST_CONTEXT("flow " << static_cast<uint32_t>(flow) << ", fault " << fault) {
            std::vector<uint32_t> seen, effects;
            const auto run = [&] { return drivechain::haskell::ParentReplayStore(flow, [&](uint32_t step) {
                seen.push_back(step);
                if (seen.size() == fault + 1) throw std::runtime_error("replay flow fault");
                effects.push_back(step);
                return response(step);
            }); };
            if (fault < expected.size()) BOOST_CHECK_THROW(run(), std::runtime_error);
            else BOOST_CHECK_EQUAL(run(), status);
            BOOST_CHECK(effects == std::vector<uint32_t>(expected.begin(), expected.begin() + fault));
            BOOST_CHECK(seen == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
        }
    }
}

BOOST_AUTO_TEST_CASE(deposit_numeric_admission_preserves_full_width_bounds)
{
    namespace hs = drivechain::haskell;
    const std::array<int64_t, 7> heights{std::numeric_limits<int64_t>::min(), -1, 0, 1, 2016, 2017, std::numeric_limits<int64_t>::max()};
    for (int64_t tip : heights) for (int64_t start : heights) {
        if (start < 0) continue; // The evidence builder rejects these before RPC.
        for (uint64_t limit : {uint64_t{0}, uint64_t{1}, uint64_t{2016}, std::numeric_limits<uint64_t>::max()}) {
            const bool original = tip >= start && uint64_t(tip - start) <= limit;
            BOOST_CHECK_EQUAL(hs::ParentReplayRecord(hs::ReplayRecordKind::SIGNED_HEIGHT_WINDOW,
                0, tip, uint64_t(start), limit), original);
        }
    }
    BOOST_CHECK(!hs::ParentReplayRecord(hs::ReplayRecordKind::SIGNED_HEIGHT_WINDOW, 0,
        std::numeric_limits<int64_t>::max(), uint64_t{1} << 63, std::numeric_limits<uint64_t>::max()));
    const std::array<uint64_t, 5> sizes{0,1,255,uint64_t{1} << 63,std::numeric_limits<uint64_t>::max()};
    for (uint64_t index : sizes) for (uint64_t inputs : sizes) for (uint64_t witnesses : sizes) {
        unsigned witness_reads{0};
        const bool accepted = hs::ParentReplayRecord(hs::ReplayRecordKind::LESS, 0, 0, index, inputs) &&
            (++witness_reads, hs::ParentReplayRecord(hs::ReplayRecordKind::LESS, 0, 0, index, witnesses));
        BOOST_CHECK_EQUAL(accepted, index < inputs && index < witnesses);
        BOOST_CHECK_EQUAL(witness_reads, unsigned(index < inputs));
    }
}

BOOST_AUTO_TEST_CASE(bmm_bid_preserves_validation_and_txid_publication_order)
{
    namespace hs = drivechain::haskell;
    for (auto flow : {hs::ReplayStoreFlow::BMM_BID_PREFLIGHT, hs::ReplayStoreFlow::BMM_BID_TXID}) {
        const bool preflight = flow == hs::ReplayStoreFlow::BMM_BID_PREFLIGHT;
        const std::vector<uint32_t> predicates = preflight ? std::vector<uint32_t>{1,3,4,6,7,8} : std::vector<uint32_t>{2,5,6,7};
        for (unsigned flags = 0; flags < (1U << predicates.size()); ++flags) {
            const auto response = [&](uint32_t step) -> uint32_t {
                auto found = std::find(predicates.begin(), predicates.end(), step);
                return found == predicates.end() ? 1 : (flags >> (found - predicates.begin())) & 1;
            };
            std::vector<uint32_t> expected;
            const auto action = [&](uint32_t step) { expected.push_back(step); return response(step); };
            const auto original = [&]() -> uint32_t {
                if (preflight) {
                    if (!action(1)) { action(2); return 0; }
                    if (!action(3) || !action(4)) { action(5); return 0; }
                    if (!action(6) || !action(7) || !action(8)) { action(9); return 0; }
                } else {
                    action(1);
                    if (!action(2)) { action(3); return 0; }
                    action(4);
                    if (!action(5) || !action(6) || !action(7)) { action(8); return 0; }
                    action(9);
                }
                return 1;
            };
            const auto wanted = original();
            CheckReplayFlowFaults(flow, expected, wanted, response);
        }
    }
    for (int slot : {std::numeric_limits<int>::min(), -1, 0, 24, 255, 256, std::numeric_limits<int>::max()}) {
        BOOST_CHECK_EQUAL(hs::ParentReplayRecord(hs::ReplayRecordKind::HEIGHT, 0, 0,
            static_cast<uint64_t>(slot), 255), slot >= 0 && slot <= 255);
    }
    for (uint64_t bid : {uint64_t{0}, uint64_t{1}, uint64_t{MAX_MONEY}, uint64_t{MAX_MONEY} + 1,
                         uint64_t{1} << 63, std::numeric_limits<uint64_t>::max()}) {
        BOOST_CHECK_EQUAL(hs::ParentReplayRecord(hs::ReplayRecordKind::POSITIVE, 0, 0, bid, 0) &&
            !hs::ParentReplayRecord(hs::ReplayRecordKind::LESS, 0, 0, MAX_MONEY, bid),
            bid > 0 && bid <= uint64_t{MAX_MONEY});
    }
}

BOOST_AUTO_TEST_CASE(authenticated_json_preserves_lazy_transport_and_response_clearing)
{
    namespace hs = drivechain::haskell;
    const std::array<uint32_t, 12> predicates{2,4,8,9,10,11,12,13,14,17,18,22};
    for (unsigned flags = 0; flags < (1U << predicates.size()); ++flags) {
        const auto response = [&](uint32_t step) -> uint32_t {
            if (step == 5 || step == 15 || step == 20) step = 2;
            auto found = std::find(predicates.begin(), predicates.end(), step);
            return found == predicates.end() ? 1 : (flags >> (found - predicates.begin())) & 1;
        };
        std::vector<uint32_t> expected;
        const auto action = [&](uint32_t step) { expected.push_back(step); return response(step); };
        const auto original = [&]() -> uint32_t {
            action(1);
            if (action(2)) action(3);
            if (!action(4)) { if (action(5)) action(6); return 0; }
            action(7);
            if (!action(8) || !action(9) || !action(10) || !action(11) ||
                !action(12) || !action(13) || !action(14)) {
                if (action(15)) action(action(22) ? 16 : 23);
                return 0;
            }
            if (!action(17) || !action(18)) {
                action(19);
                if (action(20)) action(21);
                return 0;
            }
            return 1;
        };
        const auto wanted = original();
        CheckReplayFlowFaults(hs::ReplayStoreFlow::AUTHENTICATED_JSON, expected, wanted, response);
    }
}

BOOST_AUTO_TEST_CASE(bmm_context_workflow_preserves_native_faults_and_lock_lifetimes)
{
    namespace hs = drivechain::haskell;
    using Event = std::pair<uint32_t,uint64_t>;
    for (unsigned route = 0; route < 5; ++route) {
        const bool cached = route == 2, peer = route == 1 || route == 3;
        std::vector<Event> expected;
        const auto steps = [&](std::initializer_list<uint32_t> values) {
            for (const auto value : values) expected.emplace_back(value,0);
        };
        steps({1,2,3,4,6,9,10});
        if (cached) steps({11});
        expected.emplace_back(13,cached ? 1 : 0);
        steps({15});
        expected.emplace_back(10,1);
        steps({13,15,16});
        if (cached) {
            steps({17,18,19,20,21,22,23,24,25,26});
        } else {
            steps({27});
            if (peer) {
                steps({28,29});
                for (uint64_t index = 1; index <= 14; ++index) expected.emplace_back(30,index);
                steps({31,32});
                if (route == 1) {
                    expected.emplace_back(0,8);
                    steps({43});
                } else {
                    steps({33,34,78,38,39,40,41,42,43,27,48,54,55,57,58});
                    expected.emplace_back(59,101);
                    steps({60,61,62,63,64,65,66,67,68,69,70,72,73,74,75,77});
                }
            } else {
                steps({27,44,48});
                if (route == 4) {
                    steps({49,50});
                    expected.emplace_back(51,5);
                    steps({52});
                }
            }
        }
        for (unsigned kind = 0; kind < 4; ++kind) {
            const size_t attempts = kind == 0 ? 1 : expected.size();
            for (size_t fault = 0; fault < attempts; ++fault) {
                std::mutex cache_mutex, replay_mutex;
                std::vector<Event> seen;
                bool standard{false}, nonstandard{false};
                unsigned status{99};
                {
                    std::optional<std::unique_lock<std::mutex>> cache_lock, replay_lock;
                    const auto scalar = [](uint64_t value) {
                        std::vector<unsigned char> bytes(8);
                        for (size_t i = 0; i < bytes.size(); ++i) bytes[i] = value >> (8*i);
                        return bytes;
                    };
                    const auto native = [&](uint32_t step, uint64_t index, std::span<const unsigned char> input) {
                        BOOST_REQUIRE(input.empty());
                        const auto position = seen.size();
                        seen.emplace_back(step,index);
                        if (kind == 1 && position == fault) throw std::runtime_error("original BMM context failure");
                        if (kind == 2 && position == fault) throw 678;
                        if (kind == 3 && position == fault) return std::vector<unsigned char>(9,0);
                        switch (step) {
                        case 0: return scalar(3);
                        case 2: cache_lock.emplace(cache_mutex,std::defer_lock); break;
                        case 4: return scalar(cache_lock->try_lock());
                        case 6: case 11: case 23: case 24: case 31: case 73: return scalar(7);
                        case 10: return scalar(cached && index == 0 ? 1 : 0);
                        case 16: return scalar(cached ? 1 : 0);
                        case 27: return scalar(peer);
                        case 28: replay_lock.emplace(replay_mutex,std::defer_lock); break;
                        case 29: return scalar(replay_lock->try_lock());
                        case 32: return scalar(route != 1);
                        case 34: case 78: return scalar(0);
                        case 38: case 39: case 62: return scalar(101);
                        case 40: case 54: case 58: return scalar(100);
                        case 43: replay_lock.reset(); break;
                        case 44: return scalar(0);
                        case 48:
                            BOOST_CHECK(!replay_lock);
                            return scalar(route == 0 ? 2 : route == 4 ? 1 : 0);
                        case 55: return scalar(99);
                        default: break;
                        }
                        return scalar(1);
                    };
                    try {
                        status = hs::RunReplayStore(hs::ReplayStoreWorkflow::BMM_CONTEXT,native);
                    } catch (const std::exception& error) {
                        standard = true;
                        if (kind == 1) BOOST_CHECK_EQUAL(error.what(),"original BMM context failure");
                    } catch (int value) {
                        nonstandard = true;
                        BOOST_CHECK_EQUAL(value,678);
                    }
                }
                std::unique_lock recovered_cache(cache_mutex,std::try_to_lock);
                BOOST_REQUIRE(recovered_cache.owns_lock());
                std::unique_lock recovered_replay(replay_mutex,std::try_to_lock);
                BOOST_REQUIRE(recovered_replay.owns_lock());
                if (kind == 0) {
                    BOOST_CHECK(!standard && !nonstandard);
                    BOOST_CHECK_EQUAL(status,route < 2 ? 3U : route == 4 ? 2U : 0U);
                    BOOST_CHECK(seen == expected);
                } else {
                    BOOST_CHECK(kind == 2 ? nonstandard : standard);
                    std::vector<Event> prefix(expected.begin(),expected.begin()+fault+1);
                    const auto opened = std::find(expected.begin(),expected.end(),Event{28,0});
                    const auto closed = std::find(expected.begin(),expected.end(),Event{43,0});
                    if (kind == 3 && opened != expected.end() && expected.begin()+fault > opened &&
                        expected.begin()+fault < closed) prefix.emplace_back(43,0);
                    BOOST_CHECK(seen == prefix);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(bmm_successor_preserves_preparation_and_failure_order)
{
    namespace hs = drivechain::haskell;
    for (uint32_t height : {0U,1U,uint32_t{INT32_MAX},UINT32_MAX-1,UINT32_MAX}) {
        uint64_t successor{42};
        const bool accepted=hs::ApprovingParentHeight(height,successor);
        BOOST_CHECK_EQUAL(accepted,hs::ParentReplayRecord(hs::ReplayRecordKind::ADVANCEABLE_HEIGHT,0,0,height,0));
        BOOST_CHECK_EQUAL(successor,accepted ? uint64_t{height}+1 : 42);
    }
    const std::array<uint32_t, 8> predicates{1,2,4,5,6,7,8,11};
    for (unsigned flags = 0; flags < 256; ++flags) {
        const auto response = [&](uint32_t step) -> uint32_t {
            auto found = std::find(predicates.begin(), predicates.end(), step);
            return found == predicates.end() ? 1 : (flags >> (found - predicates.begin())) & 1;
        };
        std::vector<uint32_t> expected;
        const auto action = [&](uint32_t step) { expected.push_back(step); return response(step); };
        const auto original = [&]() -> uint32_t {
            if (!action(1)) return 3;
            if (!action(2)) { action(3); return 3; }
            if (!action(4) || !action(5) || !action(6)) return 3;
            if (!action(7) || !action(8)) { action(9); return 3; }
            action(10);
            return action(11) ? 0 : 3;
        };
        const auto wanted = original();
        CheckReplayFlowFaults(hs::ReplayStoreFlow::BMM_SUCCESSOR, expected, wanted, response);
    }
}

BOOST_AUTO_TEST_CASE(bmm_publication_preserves_partial_output_and_cache_order)
{
    namespace hs = drivechain::haskell;
    const std::array<uint32_t, 6> predicates{1,3,8,9,12,16};
    for (unsigned flags = 0; flags < 64; ++flags) {
        const auto response = [&](uint32_t step) -> uint32_t {
            if (step == 14) step = 3;
            auto found = std::find(predicates.begin(), predicates.end(), step);
            return found == predicates.end() ? 1 : (flags >> (found - predicates.begin())) & 1;
        };
        std::vector<uint32_t> expected;
        const auto action = [&](uint32_t step) { expected.push_back(step); return response(step); };
        const auto original = [&]() -> uint32_t {
            if (!action(1)) return 3;
            action(2);
            if (action(3)) action(4); else action(5);
            action(6); action(7);
            if (!action(8) || !action(9)) { action(10); return 3; }
            action(11);
            if (action(12)) action(13);
            if (!action(14)) { action(15); return 2; }
            if (!action(16)) { action(17); return 2; }
            return 0;
        };
        const auto wanted = original();
        CheckReplayFlowFaults(hs::ReplayStoreFlow::BMM_PUBLICATION, expected, wanted, response);
    }
}

BOOST_AUTO_TEST_CASE(bmm_probe_result_preserves_cache_and_diagnostic_order)
{
    namespace hs = drivechain::haskell;
    for (unsigned status = 0; status < 3; ++status) for (bool below : {false, true}) {
        const auto response = [&](uint32_t step) -> uint32_t {
            if (step == 1) return status == 2;
            if (step == 2) return status == 1;
            if (step == 5) return below;
            return 1;
        };
        std::vector<uint32_t> expected;
        const auto action = [&](uint32_t step) { expected.push_back(step); return response(step); };
        const auto original = [&]() -> uint32_t {
            if (action(1)) return 3;
            if (action(2)) { action(3); action(4); return 2; }
            if (action(5)) { action(6); action(7); action(8); return 2; }
            return 0;
        };
        const auto wanted = original();
        CheckReplayFlowFaults(hs::ReplayStoreFlow::BMM_PROBE_RESULT, expected, wanted, response);
    }
}

BOOST_AUTO_TEST_CASE(untrusted_bmm_admission_preserves_invalidation_and_lock_lifetime)
{
    namespace hs = drivechain::haskell;
    const std::array<uint32_t, 10> predicates{1,3,4,6,9,13,15,16,22,23};
    for (unsigned flags = 0; flags < 1024; ++flags) {
        const auto response = [&](uint32_t step) -> uint32_t {
            auto found = std::find(predicates.begin(), predicates.end(), step);
            return found == predicates.end() ? 1 : (flags >> (found - predicates.begin())) & 1;
        };
        std::vector<uint32_t> expected;
        const auto action = [&](uint32_t step) { expected.push_back(step); return response(step); };
        const auto fail = [&](uint32_t step) { action(step); return 3U; };
        const auto original = [&]() -> uint32_t {
            if (!action(1)) return fail(2);
            if (!action(3) || !action(4)) return fail(5);
            if (!action(6)) return fail(7);
            action(8);
            if (action(9)) { action(10); action(11); return fail(12); }
            if (action(13)) return fail(14);
            if (!action(15) || !action(16)) { action(18); action(19); action(20); return fail(21); }
            if (!action(22) || !action(23)) return fail(24);
            return 0;
        };
        const auto status = original();
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            std::mutex mutex;
            std::vector<uint32_t> seen, effects;
            const auto run = [&] {
                std::unique_lock<std::mutex> lock(mutex, std::defer_lock);
                return hs::ParentReplayStore(hs::ReplayStoreFlow::BMM_UNTRUSTED_ADMISSION, [&](uint32_t step) {
                    seen.push_back(step);
                    if (seen.size() == fault + 1) throw std::runtime_error("untrusted admission fault");
                    effects.push_back(step);
                    if (step == 1 && response(step)) return uint32_t(lock.try_lock());
                    return response(step);
                });
            };
            if (fault < expected.size()) BOOST_CHECK_THROW(run(), std::runtime_error);
            else BOOST_CHECK_EQUAL(run(), status);
            BOOST_CHECK(effects == std::vector<uint32_t>(expected.begin(), expected.begin() + fault));
            BOOST_CHECK(seen == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
            std::unique_lock released(mutex, std::try_to_lock);
            BOOST_REQUIRE(released.owns_lock());
        }
    }
}

BOOST_AUTO_TEST_CASE(bmm_cache_search_preserves_direction_first_match_and_lazy_slots)
{
    namespace hs = drivechain::haskell;
    for (unsigned flags = 0; flags < 4096; ++flags) for (bool reverse : {false, true}) {
        std::array<unsigned, 6> entries{0,1,2,3,4,5};
        if (reverse) std::reverse(entries.begin(), entries.end());
        std::vector<unsigned> expected, actual;
        const auto old_match = [&](unsigned entry) {
            expected.push_back(entry * 2);
            if (!((flags >> (entry * 2)) & 1)) return false;
            expected.push_back(entry * 2 + 1);
            return bool((flags >> (entry * 2 + 1)) & 1);
        };
        const auto wanted = std::find_if(entries.begin(), entries.end(), old_match);
        const auto found = std::find_if(entries.begin(), entries.end(), [&](unsigned entry) {
            return hs::ParentReplayStore(hs::ReplayStoreFlow::BMM_CACHE_KEY, [&](uint32_t step) -> uint32_t {
                actual.push_back(entry * 2 + step - 1);
                return (flags >> (entry * 2 + step - 1)) & 1;
            });
        });
        BOOST_CHECK(found == wanted);
        BOOST_CHECK(actual == expected);
    }
    unsigned calls{0};
    BOOST_CHECK(!hs::ParentReplayStore(hs::ReplayStoreFlow::BMM_CACHE_KEY, [&](uint32_t step) -> uint32_t {
        ++calls;
        if (step == 2) throw std::runtime_error("slot must not be read");
        return 0;
    }));
    BOOST_CHECK_EQUAL(calls, 1U);
    BOOST_CHECK_THROW(hs::ParentReplayStore(hs::ReplayStoreFlow::BMM_CACHE_KEY, [](uint32_t step) -> uint32_t {
        if (step == 2) throw std::runtime_error("slot fault");
        return 1;
    }), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(bmm_cache_hit_preserves_cheap_rejection_and_publication_order)
{
    namespace hs = drivechain::haskell;
    const std::array<uint32_t, 5> predicates{1,3,5,7,8};
    for (unsigned flags = 0; flags < 32; ++flags) {
        const auto response = [&](uint32_t step) -> uint32_t {
            auto found = std::find(predicates.begin(), predicates.end(), step);
            return found == predicates.end() ? 1 : (flags >> (found - predicates.begin())) & 1;
        };
        std::vector<uint32_t> expected;
        const auto action = [&](uint32_t step) { expected.push_back(step); return response(step); };
        const auto original = [&]() -> uint32_t {
            if (!action(1)) { action(2); return 3; }
            if (!action(3)) { action(4); return 3; }
            if (!action(5)) return 3;
            action(6);
            if (!action(7) || !action(8)) { action(9); return 3; }
            action(10); action(11); return 0;
        };
        const auto status = original();
        CheckReplayFlowFaults(hs::ReplayStoreFlow::BMM_CACHE_HIT, expected, status, response);
        if (!(flags & 1) || !(flags & 2)) BOOST_CHECK(std::find(expected.begin(), expected.end(), 5) == expected.end());
    }
}

BOOST_AUTO_TEST_CASE(bmm_cache_preflight_preserves_effect_order_and_lock_release)
{
    namespace hs = drivechain::haskell;
    for (unsigned flags = 0; flags < 8; ++flags) {
        const auto response = [&](uint32_t step) -> uint32_t {
            if (step == 3) return flags & 1;
            if (step == 4) return (flags >> 1) & 1;
            if (step == 8) return (flags >> 2) & 1;
            return 1;
        };
        std::vector<uint32_t> expected;
        const auto action = [&](uint32_t step) { expected.push_back(step); return response(step); };
        const auto original = [&]() -> uint32_t {
            action(1); action(2);
            if (action(3)) { if (!action(4)) { action(5); return 3; } }
            else action(6);
            action(7);
            if (!action(8)) { action(9); action(10); action(11); return 3; }
            action(12); return 0;
        };
        const auto status = original();
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            std::mutex mutex;
            std::vector<uint32_t> seen, effects;
            const auto run = [&] {
                std::optional<std::unique_lock<std::mutex>> lock;
                return hs::ParentReplayStore(hs::ReplayStoreFlow::BMM_CACHE_PREFLIGHT, [&](uint32_t step) {
                    seen.push_back(step);
                    if (seen.size() == fault + 1) throw std::runtime_error("cache preflight fault");
                    effects.push_back(step);
                    if (step == 2) lock.emplace(mutex, std::defer_lock);
                    if (step == 4 && response(step)) return uint32_t(lock->try_lock());
                    if (step == 6) lock->lock();
                    return response(step);
                });
            };
            if (fault < expected.size()) BOOST_CHECK_THROW(run(), std::runtime_error);
            else BOOST_CHECK_EQUAL(run(), status);
            BOOST_CHECK(effects == std::vector<uint32_t>(expected.begin(), expected.begin() + fault));
            BOOST_CHECK(seen == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
            std::unique_lock released(mutex, std::try_to_lock);
            BOOST_REQUIRE(released.owns_lock());
        }
    }
}

BOOST_AUTO_TEST_CASE(bmm_edge_recheck_invalidates_only_observed_mismatches)
{
    namespace hs = drivechain::haskell;
    const std::array<uint32_t, 4> predicates{1,2,5,6};
    for (unsigned flags = 0; flags < 16; ++flags) {
        const auto response = [&](uint32_t step) -> uint32_t {
            auto found = std::find(predicates.begin(), predicates.end(), step);
            return found == predicates.end() ? 1 : (flags >> (found - predicates.begin())) & 1;
        };
        std::vector<uint32_t> expected;
        const auto action = [&](uint32_t step) { expected.push_back(step); return response(step); };
        const auto original = [&]() -> bool {
            if (!action(1)) return false;
            if (!action(2)) { action(3); action(4); return false; }
            if (!action(5)) return false;
            if (!action(6)) { action(7); action(8); return false; }
            return true;
        };
        const auto result = original();
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            std::vector<uint32_t> seen, effects;
            std::atomic<uint64_t> epoch{7};
            const auto run = [&] { return hs::ParentReplayStore(hs::ReplayStoreFlow::BMM_EDGE_RECHECK, [&](uint32_t step) {
                seen.push_back(step);
                if (seen.size() == fault + 1) throw std::runtime_error("edge recheck fault");
                effects.push_back(step);
                if (step == 3 || step == 7) epoch.store(0, std::memory_order_release);
                return response(step);
            }); };
            if (fault < expected.size()) BOOST_CHECK_THROW(run(), std::runtime_error);
            else BOOST_CHECK_EQUAL(run(), unsigned(result));
            const std::vector<uint32_t> prefix(expected.begin(), expected.begin() + fault);
            BOOST_CHECK(effects == prefix);
            BOOST_CHECK(seen == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
            const bool invalidated = std::find(prefix.begin(), prefix.end(), 3) != prefix.end() ||
                                     std::find(prefix.begin(), prefix.end(), 7) != prefix.end();
            BOOST_CHECK_EQUAL(epoch.load(std::memory_order_acquire), invalidated ? 0 : 7);
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_probe_metadata_preserves_order_partial_output_and_faults)
{
    namespace hs = drivechain::haskell;
    const std::array<uint32_t, 9> predicates{1,5,6,7,8,13,17,20,21};
    for (unsigned flags = 0; flags < 1024; ++flags) {
        const auto response = [&](uint32_t step) -> uint32_t {
            auto found = std::find(predicates.begin(), predicates.end(), step);
            if (found != predicates.end()) return (flags >> (found - predicates.begin())) & 1;
            if (step == 2 || step == 9 || step == 14 || step == 18 || step == 22) return (flags >> 9) & 1;
            return 1;
        };
        std::vector<uint32_t> expected;
        const auto action = [&](uint32_t step) { expected.push_back(step); return response(step); };
        const auto failure = [&](uint32_t check, uint32_t status) { if (action(check)) action(check + 1); return status; };
        const auto original = [&]() -> uint32_t {
            if (!action(1)) return failure(2, 2);
            action(4);
            if (!action(5) || !action(6) || !action(7) || !action(8)) return failure(9, 2);
            action(11); action(12);
            if (!action(13)) return failure(14, 2);
            action(16);
            if (!action(17)) return failure(18, 1);
            if (!action(20)) return 2;
            if (!action(21)) return failure(22, 1);
            return 0;
        };
        const auto status = original();
        CheckReplayFlowFaults(hs::ReplayStoreFlow::PARENT_PROBE_METADATA, expected, status, response);
    }
}

BOOST_AUTO_TEST_CASE(parent_probe_numeric_gates_match_signed_native_boundaries)
{
    namespace hs = drivechain::haskell;
    for (int64_t value : {INT64_MIN, int64_t{-1}, int64_t{0}, int64_t{1},
                         int64_t{UINT32_MAX}, int64_t{UINT32_MAX} + 1, INT64_MAX}) {
        BOOST_CHECK_EQUAL(hs::ParentReplayRecord(hs::ReplayRecordKind::HEIGHT, 0, 0, 0, static_cast<uint64_t>(value)),
                          value >= 0 && value <= UINT32_MAX);
        BOOST_CHECK_EQUAL(hs::ParentReplayRecord(hs::ReplayRecordKind::SIGNED_POSITIVE, 0, value, 0, 0), value > 0);
    }
}

BOOST_AUTO_TEST_CASE(required_pegin_depth_preserves_zero_and_uint32_boundaries)
{
    for (uint32_t configured : {0U, 1U, 6U, uint32_t{INT32_MAX}, uint32_t{INT32_MAX} + 1U, UINT32_MAX})
        BOOST_CHECK_EQUAL(drivechain::haskell::RequiredPeginDepth(configured), std::max(1U, configured));
}

BOOST_AUTO_TEST_CASE(replay_distance_preserves_uint32_bounds_and_rejects_underflow)
{
    const std::array<uint32_t, 6> values{0, 1, INT32_MAX, uint32_t{INT32_MAX} + 1, UINT32_MAX - 1, UINT32_MAX};
    for (uint32_t upper : values) for (uint32_t lower : values) {
        if (lower > upper) BOOST_CHECK_THROW(drivechain::haskell::ReplayDistance(upper, lower), std::runtime_error);
        else BOOST_CHECK_EQUAL(drivechain::haskell::ReplayDistance(upper, lower), upper - lower);
    }
}

BOOST_AUTO_TEST_CASE(parent_predecessor_preserves_signed_range_without_underflow)
{
    const std::array<int64_t, 9> heights{INT64_MIN, INT64_MIN + 1, -2, -1, 0, 1, UINT32_MAX, INT64_MAX - 1, INT64_MAX};
    for (int64_t height : heights) for (int64_t previous : heights)
        BOOST_CHECK_EQUAL(drivechain::haskell::ParentReplayRecord(
            drivechain::haskell::ReplayRecordKind::SIGNED_PREDECESSOR, 0, previous, static_cast<uint64_t>(height), 0),
            height != INT64_MIN && previous == height - 1);
}

BOOST_AUTO_TEST_CASE(cache_capacity_preserves_single_eviction_and_newest_entry)
{
    namespace hs = drivechain::haskell;
    for (size_t limit : {size_t{0}, size_t{1}, size_t{8}, size_t{64}}) {
        for (size_t count = 0; count <= limit + 2; ++count) {
            std::deque<size_t> expected;
            for (size_t i = 0; i < count; ++i) expected.push_back(i);
            auto actual = expected;
            expected.push_back(count);
            actual.push_back(count);
            if (expected.size() > limit) expected.pop_front();
            unsigned evictions{0};
            hs::ParentReplayAll<2>({
                [&] { return hs::ParentReplayRecord(hs::ReplayRecordKind::LESS, 0, 0, limit, actual.size()); },
                [&] { ++evictions; actual.pop_front(); return true; }});
            BOOST_CHECK_EQUAL(evictions, unsigned(count + 1 > limit));
            BOOST_CHECK(actual == expected);
            BOOST_CHECK_EQUAL(actual.size(), count + 1 - unsigned(count + 1 > limit));
            if (!actual.empty()) BOOST_CHECK_EQUAL(actual.back(), count);
        }
    }
    for (uint64_t limit : {uint64_t{0}, uint64_t{8}, uint64_t{64}, UINT64_MAX})
        for (uint64_t size : {uint64_t{0}, uint64_t{8}, uint64_t{9}, uint64_t{64}, uint64_t{65}, UINT64_MAX})
            BOOST_CHECK_EQUAL(hs::ParentReplayRecord(hs::ReplayRecordKind::LESS, 0, 0, limit, size), size > limit);
}

BOOST_AUTO_TEST_CASE(cache_pruning_preserves_survivors_order_and_expiry_short_circuit)
{
    namespace hs = drivechain::haskell;
    const std::array<uint64_t, 5> epochs{0, 1, 7, uint64_t{1} << 63, UINT64_MAX};
    for (uint64_t current : epochs) for (unsigned mask = 0; mask < 256; ++mask) for (bool negative : {false, true}) {
        std::deque<std::pair<uint64_t, int>> original;
        for (unsigned i = 0; i < 8; ++i) original.emplace_back((mask & (1U << i)) ? current : epochs[i % epochs.size()], int(i) - 3);
        auto actual = original;
        unsigned old_expiry_reads{0}, new_expiry_reads{0};
        const auto old_predicate = [&](const auto& entry) {
            return entry.first != current || (negative && (++old_expiry_reads, entry.second <= 0));
        };
        original.erase(std::remove_if(original.begin(), original.end(), old_predicate), original.end());
        std::erase_if(actual, [&](const auto& entry) {
            return hs::ParentReplayRecord(hs::ReplayRecordKind::EPOCH_CHANGED, 0, 0, entry.first, current) ||
                (negative && (++new_expiry_reads, entry.second <= 0));
        });
        BOOST_CHECK(actual == original);
        BOOST_CHECK_EQUAL(new_expiry_reads, old_expiry_reads);
    }
    for (uint64_t stored : epochs) for (uint64_t current : epochs)
        BOOST_CHECK_EQUAL(hs::ParentReplayRecord(hs::ReplayRecordKind::EPOCH_CHANGED, 0, 0, stored, current), stored != current);
}

BOOST_AUTO_TEST_CASE(snapshot_membership_flows_preserve_lazy_effects_and_faults)
{
    namespace hs = drivechain::haskell;
    static_assert(unsigned(DrivechainAnchorStatus::ACTIVE) == 0 && unsigned(DrivechainAnchorStatus::UNAVAILABLE) == 2);
    for (unsigned kind = 103; kind <= 113; ++kind) for (unsigned flags = 0; flags < 512; ++flags) {
        const auto response = [&](uint32_t step) -> uint32_t {
            if (kind == 112 && (step == 1 || step == 2)) return 1;
            if ((kind == 110 && step == 2) || (kind == 111 && (step == 1 || step == 3))) return 1;
            if (kind == 108 && step == 5) return (flags >> 4) & 3;
            if ((kind == 108 && step == 1) || (kind == 109 && (step == 1 || step == 2 || step == 6))) return 1;
            if (kind == 106 && step == 1) return 1;
            if ((kind == 104 && (step == 5 || step == 6)) ||
                (kind == 105 && (step == 3 || step == 5))) return 1;
            return (flags >> (step - 1)) & 1;
        };
        std::vector<uint32_t> expected;
        const auto action = [&](uint32_t step) { expected.push_back(step); return response(step); };
        const auto original = [&]() -> uint32_t {
            if (kind == 113) {
                if (action(1)) return 0;
                if (action(2) && action(3) && action(4)) {
                    if (action(5)) action(6);
                    return 1;
                }
                if (action(7)) action(8);
                return 2;
            }
            if (kind == 112) {
                action(1); action(2);
                if (!action(3) || !action(4)) return 0;
                action(5); return 1;
            }
            if (kind == 110) {
                if (action(1)) action(2);
                if (!action(3)) return 2;
                if (!action(4)) { action(5); return 2; }
                return 0;
            }
            if (kind == 111) {
                action(1);
                if (action(2)) action(3);
                if (action(4) || action(5)) { action(6); return 0; }
                if (action(7)) { action(8); return 0; }
                return action(9);
            }
            if (kind == 108) {
                action(1);
                if (!action(2)) { action(3); return false; }
                if (action(4)) return true;
                const auto status = action(5);
                if (status == 2) { action(7); return false; }
                if (status == 0 && !action(6)) { action(8); return false; }
                return true;
            }
            if (kind == 109) {
                action(1); action(2);
                if (!action(3)) { action(4); return false; }
                if (!action(5)) return false;
                action(6);
                if (!action(7) || !action(8)) return false;
                action(9); return true;
            }
            if (kind == 106 || kind == 107) {
                if (!action(1)) return false;
                if (!action(2)) { action(3); return false; }
                return kind == 106 || action(4);
            }
            if (kind == 103) return action(1) && action(2) && action(3);
            if (kind == 104) {
                if (!action(1) || !action(2) || !action(3) || !action(4)) return false;
                action(5); action(6);
                return action(7) || action(8);
            }
            if (!action(1) || !action(2)) return false;
            action(3);
            if (!action(4)) return false;
            action(5);
            return action(6);
        };
        const auto result = original();
        CheckReplayFlowFaults(static_cast<hs::ReplayStoreFlow>(kind), expected, unsigned(result), response);
    }
}

BOOST_AUTO_TEST_CASE(snapshot_epoch_boundaries_match_original_native_rule)
{
    const std::array<int, 7> slots{std::numeric_limits<int>::min(), -1, 0, 24, 255, 256, std::numeric_limits<int>::max()};
    const std::array<uint64_t, 5> epochs{0, 1, 7, uint64_t{1} << 63, std::numeric_limits<uint64_t>::max()};
    for (int stored_slot : slots) for (int requested_slot : slots)
        for (uint64_t stored : epochs) for (uint64_t requested : epochs) {
            const bool expected = stored_slot >= 0 && stored_slot <= 255 && stored_slot == requested_slot && stored != 0 && stored == requested;
            DrivechainAnchorSnapshot snapshot{stored_slot, uint256::ONE, stored};
            BOOST_CHECK_EQUAL(snapshot.EpochMatches(requested_slot, requested), expected);
            BOOST_CHECK_EQUAL(snapshot.Matches(requested_slot, uint256::ONE, requested), expected);
            BOOST_CHECK(!snapshot.Matches(requested_slot, uint256{}, requested));
            DrivechainAnchorSnapshot no_tip{stored_slot, uint256{}, stored};
            BOOST_CHECK(!no_tip.Matches(requested_slot, uint256{}, requested));
        }
}

BOOST_AUTO_TEST_CASE(anchor_reconciliation_preserves_rollback_classification_and_faults)
{
    namespace hs = drivechain::haskell;
    static_assert(static_cast<unsigned>(DrivechainAnchorStatus::ACTIVE) == 0);
    static_assert(static_cast<unsigned>(DrivechainAnchorStatus::ORPHANED) == 1);
    static_assert(static_cast<unsigned>(DrivechainAnchorStatus::UNAVAILABLE) == 2);
    const std::array<uint32_t, 16> gates{1,2,4,5,7,8,9,10,11,12,13,14,15,16,17,18};
    for (unsigned flags = 0; flags < 65536; ++flags) {
        const auto response = [&](uint32_t step) -> uint32_t {
            const auto gate = std::find(gates.begin(), gates.end(), step);
            return gate == gates.end() ? 1U : (flags >> std::distance(gates.begin(), gate)) & 1U;
        };
        std::vector<uint32_t> expected;
        const auto action = [&](uint32_t step) { expected.push_back(step); return response(step); };
        const auto original = [&]() -> uint32_t {
            if (!action(1)) return 2;
            if (!action(2)) { action(3); return 1; }
            if (!action(4)) return 2;
            if (!action(5)) { action(6); return 1; }
            if (!action(7) || !action(8) || !action(9)) return 2;
            if (!action(10) || !action(11) || !action(12) || !action(13) ||
                !action(14) || !action(15) || !action(16)) {
                if (action(17) && action(18)) action(19);
                return 2;
            }
            return 0;
        };
        const auto status = original();
        CheckReplayFlowFaults(hs::ReplayStoreFlow::ANCHOR_RECONCILE, expected, status, response);
    }
}

BOOST_AUTO_TEST_CASE(block_context_flows_preserve_resets_statuses_and_faults)
{
    namespace hs = drivechain::haskell;
    static_assert(static_cast<unsigned>(DrivechainBmmStatus::VALID) == 0);
    static_assert(static_cast<unsigned>(DrivechainBmmStatus::INVALID) == 1);
    static_assert(static_cast<unsigned>(DrivechainBmmStatus::UNAVAILABLE) == 3);
    for (unsigned kind = 98; kind <= 101; ++kind) for (unsigned flags = 0; flags < 128; ++flags) {
        const auto response = [&](uint32_t step) -> uint32_t {
            if ((kind != 101 && step == 1) || (kind == 100 && step == 3)) return 1;
            return (flags >> (step - 1)) & 1;
        };
        std::vector<uint32_t> expected;
        const auto action = [&](uint32_t step) { expected.push_back(step); return response(step); };
        const auto original = [&]() -> uint32_t {
            if (kind == 101) { if (action(1)) return 1; action(2); return 0; }
            action(1);
            if (kind == 98) return action(2) && action(3) && action(4);
            if (kind == 99) { if (!action(2)) return 0; action(3); return 1; }
            if (action(2)) action(3);
            if (!action(4)) return 3;
            if (!action(5)) { action(6); return 1; }
            return action(7) ? 0 : 1;
        };
        const auto status = original();
        CheckReplayFlowFaults(static_cast<hs::ReplayStoreFlow>(kind), expected, status, response);
    }
}

BOOST_AUTO_TEST_CASE(block_context_wrappers_clear_outputs_on_invalid_slot_without_rpc)
{
    CBlock block;
    DrivechainParentBlockContext parent;
    parent.parent_hash = uint256::ONE;
    parent.parent_height = 42;
    std::string error{"old"};
    BOOST_CHECK(!GetDrivechainParentBlockContext(block, -1, parent, &error));
    BOOST_CHECK(parent.parent_hash.IsNull());
    BOOST_CHECK_EQUAL(parent.parent_height, 0U);
    DrivechainBmmBlockContext bmm;
    bmm.critical_hash = uint256::ONE;
    bmm.parent_height = 42;
    BOOST_CHECK(!GetDrivechainParentBlockContext(block, -1, bmm, &error));
    BOOST_CHECK(bmm.critical_hash.IsNull());
    BOOST_CHECK_EQUAL(bmm.parent_height, 0U);
    bmm.critical_hash = uint256::ONE;
    BOOST_CHECK(GetDrivechainBmmBlockStatus(block, uint256::ONE, -1, bmm, &error) == DrivechainBmmStatus::UNAVAILABLE);
    BOOST_CHECK(bmm.critical_hash.IsNull());
    bmm.critical_hash = uint256::ONE;
    BOOST_CHECK(!GetDrivechainBmmBlockContext(block, uint256::ONE, -1, bmm, nullptr));
    BOOST_CHECK(bmm.critical_hash.IsNull());
}

BOOST_AUTO_TEST_CASE(parent_commitment_wrapper_preserves_coinbase_admission)
{
    const auto original = [](const CBlock& block, uint256& parent, std::string* error) {
        parent.SetNull();
        if (block.vtx.empty() || !block.vtx[0] || !block.vtx[0]->IsCoinBase()) {
            if (error) *error = "block has no coinbase transaction";
            return false;
        }
        std::string ignored;
        return drivechain::ExtractTaggedParentCommitment(block.vtx[0]->vout, parent, error ? *error : ignored);
    };
    for (unsigned shape = 0; shape < 7; ++shape) for (bool diagnostics : {false, true}) {
        CBlock block;
        CMutableTransaction tx;
        tx.vin.resize(1);
        if (shape == 2) tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
        if (shape >= 4) {
            tx.vout.resize(shape == 6 ? 2 : 1);
            tx.vout[0].scriptPubKey = CreateDrivechainParentCommitmentScript(uint256::ONE);
            if (shape == 5) tx.vout[0].scriptPubKey.pop_back();
            if (shape == 6) tx.vout[1].scriptPubKey = tx.vout[0].scriptPubKey;
        }
        if (shape == 1) block.vtx.push_back({});
        else if (shape >= 2) block.vtx.push_back(MakeTransactionRef(tx));
        uint256 expected = uint256::ONE, actual = uint256::ONE;
        std::string expected_error{"unchanged"}, actual_error{"unchanged"};
        const bool accepted = original(block, expected, diagnostics ? &expected_error : nullptr);
        BOOST_CHECK_EQUAL(ExtractDrivechainParentHashFromBlock(block, actual, diagnostics ? &actual_error : nullptr), accepted);
        BOOST_CHECK(actual == expected);
        BOOST_CHECK_EQUAL(actual_error, expected_error);
        if (shape < 3) BOOST_CHECK(actual.IsNull());
        if (shape == 4) BOOST_CHECK(accepted);
    }
}

BOOST_AUTO_TEST_CASE(parent_context_flows_preserve_rpc_short_circuiting_and_publication)
{
    namespace hs = drivechain::haskell;
    const std::array<uint32_t, 14> gates{1,3,4,5,6,7,8,9,11,12,13,14,15,16};
    for (bool execution : {false, true}) for (unsigned flags = 0; flags < 16384; ++flags) {
        std::vector<uint32_t> expected;
        const auto accepted = [&](uint32_t step) {
            const auto found = std::find(gates.begin(), gates.end(), step);
            return found == gates.end() ? 1U : (flags >> std::distance(gates.begin(), found)) & 1U;
        };
        const auto action = [&](uint32_t step) { expected.push_back(step); return accepted(step); };
        const auto original = [&]() -> bool {
            if (!action(1)) { action(2); return false; }
            if (!action(3)) return false;
            if (execution) {
                if (!action(4)) return false;
                if (!action(5) || !action(6) || !action(7) || !action(8) || !action(9)) { action(10); return false; }
                if (!action(11) || !action(12)) return false;
                if (!action(13) || !action(14)) { action(17); return false; }
            }
            if (!action(15) || !action(16)) { action(17); return false; }
            action(18);
            return true;
        };
        const auto result = original();
        CheckReplayFlowFaults(execution ? hs::ReplayStoreFlow::EXECUTION_ANCHOR : hs::ReplayStoreFlow::MEMPOOL_CONTEXT,
            expected, result, accepted);
    }
    for (uint32_t first : {0U, 1U, UINT32_MAX - 1, UINT32_MAX}) for (uint32_t second : {0U, 1U, UINT32_MAX - 1, UINT32_MAX}) {
        BOOST_CHECK_EQUAL(hs::ParentReplayRecord(hs::ReplayRecordKind::HEIGHT, 0, 0, first, second), first <= second);
    }
    const std::array<uint64_t, 6> times{0,1,UINT32_MAX,uint64_t{UINT32_MAX} + 1,uint64_t{1} << 63,UINT64_MAX};
    for (uint64_t first : times) for (uint64_t second : times) {
        BOOST_CHECK_EQUAL(!hs::ParentReplayRecord(hs::ReplayRecordKind::LESS, 0, 0, second, first), first <= second);
    }
}

BOOST_AUTO_TEST_CASE(withdrawal_lookup_preserves_invalidation_publication_and_lock)
{
    namespace hs = drivechain::haskell;
    const std::array<uint32_t, 13> gates{1,2,4,5,8,9,10,14,15,17,18,23,24};
    const auto original = [](const auto& action) -> uint32_t {
        if (!action(1) || !action(2)) return 0;
        action(3);
        if (!action(4)) return 0;
        if (!action(5)) { action(6); return 0; }
        action(7);
        if (action(8) || (action(9) && action(10))) {
            action(11); action(12); action(13);
            if (action(14) && action(15)) action(30);
            return 0;
        }
        if (action(16)) {
            if (!action(17)) return 0;
            if (!action(18)) { action(19); action(20); action(21); action(22); return 0; }
        }
        if (!action(23)) return 0;
        if (!action(24)) { action(25); action(26); action(27); action(28); return 0; }
        if (action(29)) action(31);
        return 1;
    };
    for (unsigned flags = 0; flags < 8192; ++flags) {
        std::mutex mutex;
        const auto run = [&](bool migrated, size_t fault, std::vector<uint32_t>& seen, std::vector<uint32_t>& effects) {
            std::optional<std::lock_guard<std::mutex>> lock;
            const auto action = [&](uint32_t step) -> uint32_t {
                seen.push_back(step);
                if (seen.size() == fault + 1) throw std::runtime_error("withdrawal lookup fault");
                if (step >= 4 && !lock) throw std::logic_error("withdrawal lookup without lock");
                effects.push_back(step);
                if (step == 3) { lock.emplace(mutex); return 1; }
                if (step == 16 || step == 29) step = 9;
                const auto gate = std::find(gates.begin(), gates.end(), step);
                return gate == gates.end() ? 1 : (flags >> std::distance(gates.begin(), gate)) & 1;
            };
            return migrated ? hs::ParentReplayStore(hs::ReplayStoreFlow::WITHDRAWAL_LOOKUP, action) : original(action);
        };
        std::vector<uint32_t> expected, original_effects;
        const auto result = run(false, SIZE_MAX, expected, original_effects);
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            std::vector<uint32_t> seen, effects;
            if (fault < expected.size()) BOOST_CHECK_THROW(run(true, fault, seen, effects), std::runtime_error);
            else BOOST_CHECK_EQUAL(run(true, fault, seen, effects), result);
            BOOST_CHECK(seen == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
            BOOST_CHECK(effects == std::vector<uint32_t>(expected.begin(), expected.begin() + fault));
            std::unique_lock released(mutex, std::try_to_lock);
            BOOST_REQUIRE(released.owns_lock());
        }
    }
}

BOOST_AUTO_TEST_CASE(deposit_fee_predicates_signed_boundaries)
{
    namespace hs = drivechain::haskell;
    const std::array<int64_t, 5> values{INT64_MIN, -1, 0, 1, INT64_MAX};
    for (const auto fee : values) {
        BOOST_CHECK_EQUAL(hs::DepositPreflight(2, fee, 0), fee > 0);
        for (const auto maximum : values)
            BOOST_CHECK_EQUAL(hs::DepositPreflight(11, fee, maximum), fee <= maximum);
        for (bool elements : {false, true}) {
            unsigned reads{0};
            const bool funded = hs::ParentReplayAll<2>({
                [&] { return elements; },
                [&] { ++reads; return hs::DepositPreflight(2, fee, 0); },
            });
            BOOST_CHECK_EQUAL(funded, elements && fee > 0);
            BOOST_CHECK_EQUAL(reads, unsigned(elements));
        }
    }
    BOOST_CHECK_THROW(hs::DepositPreflight(12, 0, 0), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(deposit_preflight_preserves_diagnostics_and_lazy_identity)
{
    namespace hs = drivechain::haskell;
    std::vector<std::pair<unsigned,unsigned>> scenarios;
    for (unsigned args = 0; args < 16; ++args) for (unsigned identity : {0U, 16382U, 16383U})
        scenarios.emplace_back(args, identity);
    for (unsigned identity = 0; identity < 16384; ++identity) scenarios.emplace_back(7, identity);
    const auto original = [](const auto& action) -> uint32_t {
        if (action(1)) action(2);
        if (!action(3) || !action(4)) {
            if (action(5) && action(6)) action(7);
            return 1;
        }
        action(8);
        for (uint32_t step = 9; step <= 22; ++step) {
            if (!action(step)) { action(23); return 2; }
        }
        return 0;
    };
    for (const auto& [args, identity] : scenarios) {
        const auto run = [&](bool migrated, size_t fault, std::vector<uint32_t>& seen, std::string& message) {
            bool configured{false};
            const auto action = [&](uint32_t step) -> uint32_t {
                seen.push_back(step);
                if (seen.size() == fault + 1) throw std::runtime_error("preflight fault");
                switch (step) {
                case 1: case 5: return args & 1;
                case 2: message.clear(); return 1;
                case 3:
                    if (!(args & 2) && (args & 1) && (args & 8)) message = "slot error";
                    return (args >> 1) & 1;
                case 4: return (args >> 2) & 1;
                case 6: return message.empty();
                case 7: message = "invalid payload"; return 1;
                case 8: configured = true; return 1;
                case 23: if (args & 1) message = "invalid identity"; return 2;
                default:
                    if (!configured) throw std::logic_error("early config read");
                    if (step == 10 && !(identity & 1)) throw std::logic_error("unguarded optional hash");
                    return (identity >> (step - 9)) & 1;
                }
            };
            return migrated ? hs::ParentReplayStore(hs::ReplayStoreFlow::DEPOSIT_PREFLIGHT, action) : original(action);
        };
        std::vector<uint32_t> expected;
        std::string initial{"old"};
        const auto status = run(false, SIZE_MAX, expected, initial);
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            std::vector<uint32_t> before, after;
            std::string old_error{"old"}, new_error{"old"};
            if (fault < expected.size()) {
                BOOST_CHECK_THROW(run(false, fault, before, old_error), std::runtime_error);
                BOOST_CHECK_THROW(run(true, fault, after, new_error), std::runtime_error);
            } else {
                BOOST_CHECK_EQUAL(run(false, fault, before, old_error), status);
                BOOST_CHECK_EQUAL(run(true, fault, after, new_error), status);
            }
            BOOST_CHECK(before == after);
            BOOST_CHECK_EQUAL(old_error, new_error);
        }
    }
    for (int64_t value : {INT64_MIN, int64_t{-1}, int64_t{0}, int64_t{1}, int64_t{MAX_MONEY}, int64_t{MAX_MONEY + 1}, INT64_MAX}) {
        for (uint64_t size : {uint64_t{0}, uint64_t{1}, uint64_t{128}, uint64_t{129}, UINT64_MAX}) {
            BOOST_CHECK_EQUAL(hs::ParentReplayRecord(hs::ReplayRecordKind::DEPOSIT, 7, value, size, MAX_MONEY),
                value > 0 && MoneyRange(value) && size > 0 && size <= 128);
        }
    }
}

BOOST_FIXTURE_TEST_CASE(deposit_admission_native_entry_preserves_status_and_errors, SlotAssignedPeginSetup)
{
    const auto& consensus = Params().GetConsensus();
    BOOST_REQUIRE(consensus.drivechain_slot.has_value());
    const int configured = *consensus.drivechain_slot;
    for (const int slot : {INT_MIN, -1, 0, configured, 255, 256, INT_MAX}) {
        for (const CAmount amount : {INT64_MIN, int64_t{-1}, int64_t{0}, int64_t{1}, int64_t{MAX_MONEY}, int64_t{MAX_MONEY+1}, INT64_MAX}) {
            for (const size_t size : {size_t{0},size_t{1},size_t{128},size_t{129}}) {
                const std::vector<unsigned char> address(size, 1);
                std::string message{"old diagnostic"};
                const auto status = GetConfirmedDrivechainDepositStatus(uint256{},slot,COutPoint{},amount,address,&message);
                const auto silent = GetConfirmedDrivechainDepositStatus(uint256{},slot,COutPoint{},amount,address,nullptr);
                BOOST_CHECK(status == silent);
                if (slot != configured) {
                    BOOST_CHECK(status == DrivechainDepositStatus::INVALID);
                    BOOST_CHECK_EQUAL(message,strprintf("drivechain sidechain slot must match configured slot %u, got %d", configured,slot));
                } else if (amount <= 0 || !MoneyRange(amount) || size == 0 || size > 128) {
                    BOOST_CHECK(status == DrivechainDepositStatus::INVALID);
                    BOOST_CHECK_EQUAL(message,"invalid slot, amount, or address for drivechain deposit");
                } else {
                    // The real serialized identity passes; no unit-test cache is authenticated.
                    BOOST_CHECK(status == DrivechainDepositStatus::UNAVAILABLE);
                    BOOST_CHECK_EQUAL(message,"authenticated parent replay cache is not warmed");
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(deposit_admission_callback_failures_preserve_native_exception)
{
    namespace hs = drivechain::haskell;
    for (const uint32_t failure : {0U,1U,4U}) {
        std::vector<uint32_t> seen;
        const auto native = [&](uint32_t step, uint64_t index, std::span<const unsigned char> input) {
            BOOST_CHECK_EQUAL(index,0U);
            BOOST_CHECK(step == 4 || input.empty());
            seen.push_back(step);
            if (step == failure) throw std::runtime_error("original admission native failure");
            if (step == 1) return std::vector<unsigned char>(22, 0); // Unconfigured slot.
            return std::vector<unsigned char>{};
        };
        BOOST_CHECK_EXCEPTION(hs::RunReplayStore(hs::ReplayStoreWorkflow::DEPOSIT_ADMISSION,native),
            std::runtime_error, [](const auto& error) { return std::string(error.what()) == "original admission native failure"; });
        const std::vector<uint32_t> expected = failure == 0 ? std::vector<uint32_t>{0} :
            failure == 1 ? std::vector<uint32_t>{0,1} : std::vector<uint32_t>{0,1,4};
        BOOST_CHECK(seen == expected);
    }
    for (unsigned mode = 0; mode < 3; ++mode) {
        unsigned calls{0};
        BOOST_CHECK_THROW(hs::RunReplayStore(hs::ReplayStoreWorkflow::DEPOSIT_ADMISSION,
            [&](uint32_t step, uint64_t, std::span<const unsigned char>) {
                ++calls;
                if (step == 0) return std::vector<unsigned char>{};
                std::vector<unsigned char> reply(22,0);
                if (mode == 0) reply.pop_back();
                if (mode == 1) reply.push_back(0);
                if (mode == 2) reply[0] = 2;
                return reply;
            }), std::runtime_error);
        BOOST_CHECK_EQUAL(calls,2U);
    }
}

BOOST_AUTO_TEST_CASE(confirmed_deposit_flow_preserves_order_faults_and_lock_lifetime)
{
    namespace hs = drivechain::haskell;
    static_assert(static_cast<unsigned>(DrivechainDepositStatus::VALID) == 0);
    static_assert(static_cast<unsigned>(DrivechainDepositStatus::INVALID) == 1);
    static_assert(static_cast<unsigned>(DrivechainDepositStatus::UNAVAILABLE) == 2);
    const std::array<uint32_t, 17> gates{1,2,5,9,11,13,14,17,21,23,24,25,27,30,33,34,43};
    const uint32_t success = ((1U << 17) - 1) ^ (1U << 7) ^ (1U << 8);
    std::vector<uint32_t> scenarios{0, UINT32_MAX, success};
    for (unsigned bit = 0; bit < 17; ++bit) scenarios.push_back(success ^ (1U << bit));
    uint32_t random{42};
    for (unsigned i = 0; i < 4096; ++i) {
        random = random * 1664525U + 1013904223U;
        scenarios.push_back(random);
    }
    const auto original = [](const auto& action) -> uint32_t {
        if (action(1)) { if (!action(2)) { action(3); return 2; } }
        else action(4);
        if (!action(5)) { action(6); return 2; }
        action(7);
        if (action(8) && action(9)) {
            action(10);
            if (!action(11)) { action(12); return 2; }
        }
        if (!action(13)) return 2;
        if (!action(14)) { action(15); return 2; }
        action(16);
        if (action(17)) { action(18); action(19); action(20); return 2; }
        if (action(21)) { action(22); return action(43) ? 1 : 2; }
        if (!action(23) || !action(24) || !action(25)) { action(26); return action(43) ? 1 : 2; }
        if (!action(27)) { action(28); return action(43) ? 1 : 2; }
        action(29);
        if (!action(30)) { action(31); return action(43) ? 1 : 2; }
        if (action(32)) {
            if (!action(33)) return 2;
            if (!action(34)) { action(35); action(36); return 2; }
            if (action(37)) action(38);
        }
        action(39);
        return 0;
    };
    for (uint32_t flags : scenarios) {
        std::mutex mutex;
        const auto run = [&](bool migrated, size_t fault, std::vector<uint32_t>& seen, std::vector<uint32_t>& effects) {
            std::unique_lock<std::mutex> lock(mutex, std::defer_lock);
            bool standalone{true}, explicit_target{false};
            const auto fact = [&](uint32_t step) {
                const auto entry = std::find(gates.begin(), gates.end(), step);
                return (flags >> std::distance(gates.begin(), entry)) & 1U;
            };
            const auto action = [&](uint32_t step) -> uint32_t {
                seen.push_back(step);
                if (seen.size() == fault + 1) throw std::runtime_error("confirmed deposit fault");
                if (step >= 5 && !lock.owns_lock()) throw std::logic_error("confirmed deposit without lock");
                effects.push_back(step);
                if (step == 2) return fact(2) && lock.try_lock();
                if (step == 4) { lock.lock(); return 1; }
                if (step == 10) { standalone = false; explicit_target = fact(43); return 1; }
                if (step == 32) return standalone;
                if (step == 43) return explicit_target;
                if (step == 8 || step == 37) return fact(1);
                if (std::find(gates.begin(), gates.end(), step) != gates.end()) return fact(step);
                return 1;
            };
            return migrated ? hs::ParentReplayStore(hs::ReplayStoreFlow::CONFIRMED_DEPOSIT, action) : original(action);
        };
        std::vector<uint32_t> expected, original_effects;
        const auto status = run(false, SIZE_MAX, expected, original_effects);
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            std::vector<uint32_t> seen, effects;
            if (fault < expected.size()) BOOST_CHECK_THROW(run(true, fault, seen, effects), std::runtime_error);
            else BOOST_CHECK_EQUAL(run(true, fault, seen, effects), status);
            BOOST_CHECK(seen == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
            BOOST_CHECK(effects == std::vector<uint32_t>(expected.begin(), expected.begin() + fault));
            std::unique_lock released(mutex, std::try_to_lock);
            BOOST_REQUIRE(released.owns_lock());
        }
    }
}

BOOST_AUTO_TEST_CASE(confirmed_deposit_fold_uses_native_store_and_preserves_lifetimes)
{
    namespace hs = drivechain::haskell;
    const auto bytes = [](const auto&... values) {
        DataStream stream;
        (stream << ... << values);
        return std::vector<unsigned char>{UCharCast(stream.data()), UCharCast(stream.data()) + stream.size()};
    };
    const auto proposal = uint256S("01"), checkpoint = uint256S("02"), block = uint256S("03");
    const Sidechain::Bitcoin::COutPoint out(proposal, 0);
    const DrivechainMintableDeposit record{out,block,101,1000,{0x51}};
    DrivechainParentReplayStore store(m_args.GetDataDirBase() / "confirmed-deposit-fold",1 << 20,true);
    std::string error;
    const DrivechainParentReplayTip seed{100,checkpoint,{}}, tip{101,block,{}};
    BOOST_REQUIRE(store.Reset(proposal,seed,&error));
    BOOST_REQUIRE(store.Append(seed,tip,{record},std::nullopt,{}, {},&error));
    const auto key = [&](uint32_t version) {
        return bytes(true,uint8_t{24},true,proposal,checkpoint,checkpoint,
            uint16_t{2},uint16_t{1},uint16_t{4},uint16_t{3},uint16_t{6},uint16_t{5},version);
    };
    // Exercise the real recoverable database closure, not a second fake lookup.
    for (unsigned mode = 0; mode <= 22; ++mode) for (unsigned flags = 0; flags < 4; ++flags) {
        const bool budget = flags != 0, anchored = flags >= 2, explicit_target = flags == 3;
        const uint32_t activation = mode == 9 ? 111 : mode == 17 ? 102 : 0;
        const uint64_t epoch = mode == 4 ? 0 : 5;
        std::mutex mutex;
        std::vector<uint32_t> seen;
        bool session_live{false};
        const auto run = [&](size_t fault) {
            seen.clear(); error.clear();
            std::unique_lock lock(mutex,std::defer_lock);
            DrivechainMintableDeposit loaded;
            DrivechainReplayEffects lookup;
            const auto native = [&](uint32_t step,uint64_t index,std::span<const unsigned char> input) {
                seen.push_back(step);
                if (seen.size() == fault) throw std::domain_error("confirmed fold native fault");
                if (step >= 3 && step != 15) BOOST_REQUIRE(lock.owns_lock());
                if (step >= 200) return bytes(true, uint64_t{step == 200 ? 0U : step == 242 ? 64U : 1U});
                if (step >= 100) {
                    BOOST_REQUIRE(session_live);
                    if (mode == 12 && step == 128) return lookup(99,0,{});
                    if (mode == 13 && step == 128) {
                        auto invalid = record;
                        invalid.outpoint.hash.SetNull();
                        return bytes(true,true,invalid);
                    }
                    return lookup(step-100,index,input);
                }
                BOOST_CHECK(step == 14 || index == 0);
                BOOST_CHECK(step == 15 || input.empty());
                switch (step) {
                case 0: return bytes(budget);
                case 1: return bytes(mode != 1 && lock.try_lock());
                case 2: lock.lock(); break;
                case 3: {
                    auto snapshot = bytes(mode != 2);
                    const auto identity = key(5);
                    snapshot.insert(snapshot.end(),identity.begin(),identity.end());
                    const auto state = bytes(uint32_t{110},block,mode != 7,mode == 8 ? checkpoint : proposal,activation,epoch);
                    snapshot.insert(snapshot.end(),state.begin(),state.end());
                    return snapshot;
                }
                case 4: return anchored ? bytes(true,uint32_t{110},mode == 6 ? uint64_t{4} : epoch,explicit_target) : bytes(false);
                case 5: return bytes(mode != 10);
                case 6: {
                    auto lifetime = std::shared_ptr<bool>(&session_live,[](bool* live) { *live = false; });
                    session_live = true;
                    auto effects = store.DepositEffects(mode == 11 ? Sidechain::Bitcoin::COutPoint(proposal,1) : out,loaded,&error);
                    lookup = [effects = std::move(effects),lifetime](uint32_t action,uint64_t n,std::span<const unsigned char> data) {
                        return effects(action,n,data);
                    };
                    break;
                }
                case 7: return bytes(loaded,mode == 14 ? checkpoint : block,int64_t{mode == 15 ? 1001 : 1000},
                    std::vector<unsigned char>{static_cast<unsigned char>(mode == 16 ? 0x52 : 0x51)});
                case 8: return bytes(int64_t{0}, std::string{}, false, false, false, uint8_t{0},
                    uint256{}, uint256{}, uint256{}, uint32_t{mode == 20 ? 11U : 6U});
                case 9: return mode == 18 ? bytes(false) : bytes(true,mode == 19 ? checkpoint : block);
                case 10: case 11: case 12: case 13: break;
                case 14:
                    BOOST_CHECK_EQUAL(index,epoch);
                    if (mode >= 21) throw std::runtime_error(mode == 21 ? "parent deadline expired" :
                        "authenticated parent replay epoch revoked during deposit validation");
                    break;
                case 15: error.assign(input.begin(),input.end()); break;
                case 16: return key(mode == 3 ? 4 : 5);
                case 17: lookup = {}; BOOST_CHECK(!session_live); break;
                case 18: return bytes(mode == 5 ? uint64_t{4} : epoch);
                default: throw std::logic_error("unexpected confirmation fold effect");
                }
                return std::vector<unsigned char>{};
            };
            return hs::RunReplayStore(hs::ReplayStoreWorkflow::CONFIRMED_DEPOSIT,native);
        };
        const unsigned rejected = explicit_target ? 1 : 2;
        unsigned expected = 0;
        std::string expected_error;
        if (mode == 1 && budget) { expected = 2; expected_error = "authenticated parent replay cache is busy warming"; }
        else if (mode >= 2 && mode <= 5) { expected = 2; expected_error = "authenticated parent replay cache is not warmed"; }
        else if (mode == 6 && anchored) { expected = 2; expected_error = "authenticated parent replay cache changed during validation"; }
        else if (mode >= 7 && mode <= 9) { expected = 2; expected_error = "configured Elements slot proposal is not active at parent height 110"; }
        else if (mode == 10) { expected = 2; expected_error = "persistent authenticated parent replay index is not open"; }
        else if (mode == 11) { expected = rejected; expected_error = explicit_target ?
            "deposit is not a genesis-replay-derived canonical CTIP increase before the block's authenticated parent anchor" :
            "deposit is not present in the currently warmed parent replay snapshot"; }
        else if (mode == 12) { expected = 2; expected_error = "persistent parent replay deposit read failed: invalid replay lookup effect"; }
        else if (mode == 13) { expected = 2; expected_error = "persistent parent replay deposit record is internally inconsistent"; }
        else if (mode >= 14 && mode <= 16) { expected = rejected; expected_error = "deposit does not exactly match the genesis-replay-derived canonical CTIP increase"; }
        else if (mode == 17) { expected = rejected; expected_error = "native deposit at parent height 101 predates Elements proposal activation at height 102"; }
        else if (mode == 18 && !anchored) { expected = 2; }
        else if (mode == 19 && !anchored) { expected = 2; expected_error = "authenticated parent replay cache is stale after a parent reorganization"; }
        else if (mode == 20) { expected = rejected; expected_error = "deposit at parent height 101 does not have 11 confirmations through authenticated parent height 110"; }
        if (mode >= 21) BOOST_CHECK_THROW(run(0),std::runtime_error);
        else { BOOST_CHECK_EQUAL(run(0),expected); BOOST_CHECK_EQUAL(error,expected_error); }
        BOOST_CHECK(!session_live);
        const auto complete = seen;
        if (mode == 12 || mode == 13) {
            const std::vector<uint32_t> invalidation{17,10,11,12};
            BOOST_CHECK(std::equal(invalidation.begin(),invalidation.end(),complete.end()-invalidation.size()));
        }
        if (expected == 0 && mode < 21) {
            BOOST_REQUIRE_EQUAL(complete.back(),14U);
            BOOST_CHECK_EQUAL(std::count(complete.begin(),complete.end(),9U),anchored ? 0 : 1);
            BOOST_CHECK_EQUAL(std::count(complete.begin(),complete.end(),13U),budget && !anchored ? 1 : 0);
        }
        for (size_t fault = 1; fault <= complete.size(); ++fault) {
            BOOST_CHECK_EXCEPTION(run(fault),std::domain_error,[](const auto& e) {
                return std::string(e.what()) == "confirmed fold native fault";
            });
            BOOST_CHECK(seen == std::vector<uint32_t>(complete.begin(),complete.begin()+fault));
            BOOST_CHECK(!session_live);
            std::unique_lock released(mutex,std::try_to_lock);
            BOOST_REQUIRE(released.owns_lock());
        }
    }
}

BOOST_AUTO_TEST_CASE(deposit_candidate_fold_preserves_native_scan_cursor_and_lifetimes)
{
    namespace hs = drivechain::haskell;
    const auto bytes = [](const auto&... values) {
        DataStream stream;
        (stream << ... << values);
        return std::vector<unsigned char>{UCharCast(stream.data()), UCharCast(stream.data()) + stream.size()};
    };
    const auto proposal = uint256S("01"), checkpoint = uint256S("02"), block = uint256S("03");
    DrivechainParentReplayStore store(m_args.GetDataDirBase() / "deposit-candidate-fold",1 << 20,true);
    std::string error;
    DrivechainParentReplayTip tip{100,checkpoint,{}};
    std::vector<DrivechainMintableDeposit> records;
    BOOST_REQUIRE(store.Reset(proposal,tip,&error));
    for (unsigned i = 0; i < 72; ++i) {
        const auto hash = uint256S(strprintf("%02x",i+1));
        DrivechainParentReplayTip next{101+i,hash,{}};
        records.push_back({Sidechain::Bitcoin::COutPoint(hash,0),hash,101+i,1000,{0x51}});
        BOOST_REQUIRE(store.Append(tip,next,{records.back()},std::nullopt,{}, {},&error));
        tip = next;
    }
    const auto key = [&](uint32_t version) {
        return bytes(true,uint8_t{24},true,proposal,checkpoint,checkpoint,
            uint16_t{2},uint16_t{1},uint16_t{4},uint16_t{3},uint16_t{6},uint16_t{5},version);
    };
    for (unsigned mode = 0; mode <= 11; ++mode) for (int after_index : {-1,63,70,71})
    for (uint32_t depth : {0U,1U,6U,UINT32_MAX}) {
        const auto after = after_index < 0 ? std::nullopt : std::optional{records[after_index].outpoint};
        const uint32_t activation = mode == 9 ? 173 : 130;
        std::vector<DrivechainMintableDeposit> selected;
        std::optional<Sidechain::Bitcoin::COutPoint> cursor;
        std::vector<uint32_t> seen;
        std::mutex mutex;
        bool session_live{false};
        const auto run = [&](size_t fault) {
            selected.clear(); cursor.reset(); error.clear(); seen.clear();
            std::unique_lock lock(mutex,std::defer_lock);
            std::vector<DrivechainMintableDeposit> page;
            DrivechainReplayEffects scan;
            return hs::RunReplayStore(hs::ReplayStoreWorkflow::DEPOSIT_CANDIDATES,
                [&](uint32_t step,uint64_t index,std::span<const unsigned char> input) {
                seen.push_back(step);
                if (seen.size() == fault) throw std::domain_error("candidate native fault");
                if (step != 0 && step != 11) BOOST_REQUIRE(lock.owns_lock());
                if (step >= 100) {
                    BOOST_REQUIRE(session_live);
                    if (mode == 10 && step == 134) return scan(99,0,{});
                    if (mode == 11 && step == 134) {
                        auto invalid = records.front(); invalid.value = 0;
                        return bytes(true,true,invalid);
                    }
                    return scan(step-100,index,input);
                }
                BOOST_CHECK(index == 0 || step == 9 || step == 10);
                BOOST_CHECK(input.empty() || step == 11);
                switch (step) {
                case 0: return bytes(mode != 1 && lock.try_lock());
                case 1: {
                    auto frame = bytes(mode != 2);
                    const auto identity = key(5);
                    frame.insert(frame.end(),identity.begin(),identity.end());
                    const auto state = bytes(uint32_t{172},block,mode != 7,mode == 8 ? checkpoint : proposal,
                        activation,uint64_t{mode == 5 ? 0U : 5U});
                    frame.insert(frame.end(),state.begin(),state.end());
                    return frame;
                }
                case 2: return key(mode == 3 ? 4 : 5);
                case 3: return bytes(mode != 4);
                case 4: return bytes(uint64_t{mode == 6 ? 4U : 5U});
                case 5: {
                    auto lifetime = std::shared_ptr<bool>(&session_live,[](bool* live) { *live = false; });
                    session_live = true;
                    auto effects = store.ListDepositEffects(after,64,page,cursor,&error);
                    scan = [effects = std::move(effects),lifetime](uint32_t command,uint64_t n,std::span<const unsigned char> data) {
                        return effects(command,n,data);
                    };
                    return bytes(uint64_t{MAX_MONEY});
                }
                case 6: scan = {}; BOOST_CHECK(!session_live); break;
                case 7: BOOST_CHECK(!session_live); return bytes(int64_t{0}, std::string{}, false, false, false, uint8_t{0},
                    uint256{}, uint256{}, uint256{}, depth);
                case 8: return bytes(uint64_t{page.size()});
                case 9: return bytes(page.at(index).block_height);
                case 10: selected.push_back(std::move(page.at(index))); break;
                case 11: error.assign(input.begin(),input.end()); break;
                default: throw std::logic_error("unexpected candidate fold effect");
                }
                return std::vector<unsigned char>{};
            });
        };
        const size_t begin = after_index+1, end = std::min(begin+64,records.size());
        const bool failed_scan = mode >= 10 && begin < end;
        const bool accepted = (mode == 0 || mode >= 10) && !failed_scan;
        BOOST_CHECK_EQUAL(run(0),accepted);
        BOOST_CHECK(!session_live);
        std::vector<Sidechain::Bitcoin::COutPoint> expected, actual;
        if (accepted) for (size_t i = begin; i < end; ++i) {
            const auto& record = records[i];
            if (record.block_height >= activation && uint64_t{172}-record.block_height+1 >= std::max(1U,depth))
                expected.push_back(record.outpoint);
        }
        for (const auto& record : selected) {
            actual.push_back(record.outpoint);
            BOOST_CHECK_EQUAL(record.value,1000);
            BOOST_CHECK(record.address == std::vector<unsigned char>{0x51});
        }
        BOOST_CHECK(actual == expected);
        BOOST_CHECK(cursor == (accepted && end < records.size() ? std::optional{records[end-1].outpoint} : std::nullopt));
        const std::string expected_error = mode >= 1 && mode <= 6 ? "authenticated parent deposit index is unavailable" :
            mode >= 7 && mode <= 9 ? "configured Elements slot proposal is not active at parent height 172" :
            failed_scan ? (mode == 10 ? "parent deposit scan failed: invalid replay scan effect" : "malformed parent deposit scan record") : "";
        BOOST_CHECK_EQUAL(error,expected_error);
        const auto complete = seen;
        // Every reached boundary is faulted on a small real page; successful
        // large pages above independently check the unfiltered lookahead cursor.
        if (after_index == 70 && depth == 0) for (size_t fault = 1; fault <= complete.size(); ++fault) {
            BOOST_CHECK_EXCEPTION(run(fault),std::domain_error,[](const auto& e) {
                return std::string(e.what()) == "candidate native fault";
            });
            BOOST_CHECK(seen == std::vector<uint32_t>(complete.begin(),complete.begin()+fault));
            BOOST_CHECK(!session_live);
            std::unique_lock released(mutex,std::try_to_lock);
            BOOST_REQUIRE(released.owns_lock());
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_message_codec_preserves_all_vote_values)
{
    namespace hs = drivechain::haskell;
    for (unsigned value = 0; value <= 65535; ++value) {
        const std::vector<unsigned char> bytes{0xd7, 0x7d, 0x17, 0x76, 2,
            static_cast<unsigned char>(value), static_cast<unsigned char>(value >> 8)};
        const auto parsed = hs::ParseParentMessage(bytes);
        BOOST_CHECK_EQUAL(parsed.kind, 4U);
        BOOST_CHECK_EQUAL(parsed.encoding, value <= 253 ? 0U : 2U);
        BOOST_REQUIRE_EQUAL(parsed.votes.size(), 1U);
        BOOST_CHECK_EQUAL(parsed.votes[0], value);
    }
    for (unsigned value = 0; value < 256; ++value) {
        const std::vector<unsigned char> bytes{0xd7, 0x7d, 0x17, 0x76, 1,
            static_cast<unsigned char>(value)};
        const auto parsed = hs::ParseParentMessage(bytes);
        BOOST_CHECK_EQUAL(parsed.kind, 4U);
        BOOST_CHECK_EQUAL(parsed.encoding, 2U);
        BOOST_REQUIRE_EQUAL(parsed.votes.size(), 1U);
        BOOST_CHECK_EQUAL(parsed.votes[0], value >= 254 ? value + 65280 : value);
    }
    const auto empty = hs::ParseParentMessage({});
    BOOST_CHECK_EQUAL(empty.kind, 0U);
    BOOST_CHECK_EQUAL(empty.encoding, 0U);
    BOOST_CHECK(empty.votes.empty());
}

BOOST_AUTO_TEST_CASE(m8_parser_preserves_lazy_access_and_partial_output)
{
    namespace hs = drivechain::haskell;
    for (unsigned flags = 0; flags < 32; ++flags) {
        const auto passes = [&](uint32_t step) { return (flags >> (step == 1 ? 0 : step - 2)) & 1; };
        std::vector<uint32_t> expected;
        bool accepted{true};
        for (uint32_t step = 1; step <= 9; ++step) {
            expected.push_back(step);
            if ((step == 1 || (step >= 3 && step <= 6)) && !passes(step)) {
                accepted = false;
                break;
            }
        }
        CheckReplayFlowFaults(hs::ReplayStoreFlow::M8_PARSE, expected, accepted, [&](uint32_t step) -> uint32_t {
            if (step == 1 || (step >= 3 && step <= 6)) return passes(step);
            return 1;
        });
    }
}

BOOST_AUTO_TEST_CASE(replay_message_dispatch_preserves_handler_order_and_faults)
{
    namespace hs = drivechain::haskell;
    for (uint32_t type : {0U, 1U, 2U, 3U, 4U, 5U, 6U, UINT32_MAX}) {
        const uint32_t handler = type >= 1 && type <= 3 ? type + 2 : 6;
        std::vector<uint32_t> expected{1, 2};
        if (type != 5) expected.push_back(handler);
        for (bool accepted : {false, true}) {
            CheckReplayFlowFaults(hs::ReplayStoreFlow::MESSAGE_DISPATCH, expected, type == 5 || accepted,
                [&](uint32_t step) -> uint32_t {
                    if (step == 1) return 1;
                    if (step == 2) return type;
                    BOOST_CHECK_EQUAL(step, handler);
                    return accepted;
                });
        }
    }
}

BOOST_AUTO_TEST_CASE(replay_block_admission_preserves_order_loops_and_exceptions)
{
    namespace hs = drivechain::haskell;
    for (uint32_t rejected : {0, 1, 3, 4, 5, 6, 7, 9, 11, 13, 16, 20}) {
        for (unsigned count : {0, 1, 3}) {
            unsigned other{0}, prior{0};
            const auto action = [&](uint32_t n) -> uint32_t {
                if (n == 15) return other < count;
                if (n == 19) return prior < count;
                if (n == 18) ++other;
                if (n == 22) ++prior;
                if (n == rejected && (n != 16 || other + 1 == count) && (n != 20 || prior + 1 == count)) return 0;
                // Real admission actions also invoke Haskell validators after
                // the outer transition returns, never through active callbacks.
                return hs::ParentReplayRecord(hs::ReplayRecordKind::POSITIVE, 0, 0, 1);
            };
            std::vector<uint32_t> expected;
            const auto step = [&](uint32_t n) { expected.push_back(n); return action(n); };
            const bool result = [&] {
                if (!step(1)) { step(2); return false; }
                if (!step(3) || !step(4) || !step(5) || !step(6) || !step(7)) { step(8); return false; }
                if (!step(9)) { step(10); return false; }
                if (!step(11)) { step(12); return false; }
                if (!step(13)) { step(14); return false; }
                while (step(15)) { if (!step(16)) { step(17); return false; } step(18); }
                while (step(19)) { if (!step(20)) { step(21); return false; } step(22); }
                return true;
            }();
            for (size_t fault = 0; fault <= expected.size(); ++fault) {
                other = prior = 0;
                std::vector<uint32_t> seen, effects;
                const auto run = [&] { return hs::ParentReplayStore(hs::ReplayStoreFlow::BLOCK_ADMISSION, [&](uint32_t n) {
                    seen.push_back(n);
                    if (seen.size() == fault + 1) throw std::runtime_error("admission fault");
                    effects.push_back(n);
                    return action(n);
                }); };
                if (fault < expected.size()) BOOST_CHECK_THROW(run(), std::runtime_error);
                else BOOST_CHECK_EQUAL(run(), result);
                BOOST_CHECK(seen == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
                BOOST_CHECK(effects == std::vector<uint32_t>(expected.begin(), expected.begin() + fault));
                BOOST_CHECK_EQUAL(other, std::count(effects.begin(), effects.end(), 18));
                BOOST_CHECK_EQUAL(prior, std::count(effects.begin(), effects.end(), 22));
            }
        }
    }
}



BOOST_AUTO_TEST_CASE(replay_each_index_ranges_preserve_nested_short_circuiting)
{
    namespace hs = drivechain::haskell;
    for (size_t begin : {0, 1}) for (size_t count : {0, 1, 3}) {
        const size_t end = begin + count;
        for (size_t stop = begin; stop <= end; ++stop) for (bool throws : {false, true}) {
            std::vector<size_t> effects;
            const auto run = [&] {
                return hs::ParentReplayEach(std::views::iota(begin, end), [&](size_t index) {
                    return hs::ParentReplayEach(std::views::iota(size_t{0}, size_t{2}), [&](size_t inner) {
                        if (index == stop && inner == 1) {
                            if (throws) throw std::runtime_error("later replay failure");
                            return false;
                        }
                        effects.push_back(index * 2 + inner);
                        return true;
                    });
                });
            };
            if (throws && stop < end) BOOST_CHECK_THROW(run(), std::runtime_error);
            else BOOST_CHECK_EQUAL(run(), stop == end);
            std::vector<size_t> expected;
            for (size_t index = begin; index < stop; ++index) {
                expected.push_back(index * 2);
                expected.push_back(index * 2 + 1);
            }
            if (stop < end) expected.push_back(stop * 2);
            BOOST_CHECK(effects == expected);
        }
    }
}

BOOST_AUTO_TEST_CASE(active_slots_flow_preserves_sort_and_partial_publication)
{
    namespace hs = drivechain::haskell;
    const std::array<unsigned,3> slots{5, 25, 30};
    for (unsigned flags = 0; flags < 16; ++flags) for (unsigned count : {0, 3}) {
        unsigned index{0};
        std::vector<unsigned> active;
        const auto snapshot = [&] { auto s = active; s.push_back(index); return s; };
        const auto action = [&](uint32_t n) -> uint32_t {
            switch (n) {
            case 1: return flags & 1;
            case 2: active.push_back(24); return 1;
            case 3: return index < count;
            case 4: return (flags >> (index + 1)) & 1;
            case 5: active.push_back(slots.at(index)); return 1;
            case 6: ++index; return 1;
            case 7: std::sort(active.begin(), active.end()); return 1;
            default: throw std::logic_error("invalid active slots test action");
            }
        };
        std::vector<uint32_t> expected;
        std::vector<std::vector<unsigned>> states{snapshot()};
        const auto step = [&](uint32_t n) { expected.push_back(n); auto r = action(n); states.push_back(snapshot()); return r; };
        if (step(1)) step(2);
        while (step(3)) { if (step(4)) step(5); step(6); }
        step(7);
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            index = 0; active.clear();
            std::vector<uint32_t> seen;
            const auto run = [&] { return hs::ParentReplayStore(hs::ReplayStoreFlow::ACTIVE_SLOTS, [&](uint32_t n) {
                seen.push_back(n);
                if (seen.size() == fault + 1) throw std::runtime_error("active slots fault");
                return action(n);
            }); };
            if (fault < expected.size()) BOOST_CHECK_THROW(run(), std::runtime_error);
            else BOOST_CHECK(run());
            BOOST_CHECK(seen == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
            BOOST_CHECK(snapshot() == states.at(fault));
        }
    }
}

BOOST_AUTO_TEST_CASE(m6_id_flow_preserves_lazy_validation_and_hash_publication)
{
    namespace hs = drivechain::haskell;
    const std::array<uint32_t,10> gates{2, 4, 6, 8, 9, 13, 14, 17, 18, 26};
    for (unsigned flags = 0; flags < 1024; ++flags) for (unsigned count : {0, 2}) {
        unsigned index{0};
        const auto reply = [&](uint32_t n) -> uint32_t {
            if (n == 11) return index < count;
            if (n == 16) ++index;
            const auto gate = std::find(gates.begin(), gates.end(), n);
            return gate == gates.end() ? 1 : (flags >> (gate - gates.begin())) & 1U;
        };
        std::vector<uint32_t> expected;
        const auto step = [&](uint32_t n) { expected.push_back(n); return reply(n); };
        const bool result = [&] {
            step(1);
            if (step(2)) { step(3); return false; }
            if (!step(4)) { step(5); return false; }
            if (!step(6)) { step(7); return false; }
            if (!step(8) || !step(9)) { step(10); return false; }
            while (step(11)) {
                step(12);
                if (!step(13) || !step(14)) { step(15); return false; }
                step(16);
            }
            if (!step(17) || !step(18)) { step(19); return false; }
            for (uint32_t n = 20; n <= 25; ++n) step(n);
            if (step(26)) step(27);
            return true;
        }();
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            index = 0;
            std::vector<uint32_t> seen, effects;
            const auto run = [&] { return hs::ParentReplayStore(hs::ReplayStoreFlow::M6_ID, [&](uint32_t n) {
                seen.push_back(n);
                if (seen.size() == fault + 1) throw std::runtime_error("M6 identity fault");
                effects.push_back(n);
                return reply(n);
            }); };
            if (fault < expected.size()) BOOST_CHECK_THROW(run(), std::runtime_error);
            else BOOST_CHECK_EQUAL(run(), result);
            BOOST_CHECK(seen == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
            BOOST_CHECK(effects == std::vector<uint32_t>(expected.begin(), expected.begin() + fault));
            BOOST_CHECK_EQUAL(index, std::count(effects.begin(), effects.end(), 16));
        }
    }
}

BOOST_AUTO_TEST_CASE(replay_slot_pruning_preserves_lazy_checks_and_erasure)
{
    namespace hs = drivechain::haskell;
    for (unsigned flags = 0; flags < 64; ++flags) for (unsigned count : {0, 3}) {
        const std::vector<unsigned> initial{flags, 63, flags ^ 63};
        auto entries = initial; entries.resize(count);
        unsigned index{0};
        const auto snapshot = [&] { auto s = entries; s.push_back(index); return s; };
        const auto action = [&](uint32_t n) -> uint32_t {
            if (n == 1) return index < entries.size();
            if (n >= 2 && n <= 7) return (entries.at(index) >> (n - 2)) & 1U;
            if (n == 8) { entries.erase(entries.begin() + index); return 1; }
            if (n == 9) { ++index; return 1; }
            throw std::logic_error("invalid replay pruning test action");
        };
        std::vector<uint32_t> expected;
        std::vector<std::vector<unsigned>> states{snapshot()};
        const auto step = [&](uint32_t n) { expected.push_back(n); auto r = action(n); states.push_back(snapshot()); return r; };
        while (step(1)) {
            if (step(2) && step(3) && step(4) && step(5) && step(6) && step(7)) step(8);
            else step(9);
        }
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            entries = initial; entries.resize(count); index = 0;
            std::vector<uint32_t> seen;
            const auto run = [&] { return hs::ParentReplayStore(hs::ReplayStoreFlow::PRUNE_SLOTS, [&](uint32_t n) {
                seen.push_back(n);
                if (seen.size() == fault + 1) throw std::runtime_error("pruning fault");
                return action(n);
            }); };
            if (fault < expected.size()) BOOST_CHECK_THROW(run(), std::runtime_error);
            else BOOST_CHECK(run());
            BOOST_CHECK(seen == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
            BOOST_CHECK(snapshot() == states.at(fault));
        }
    }
}

BOOST_AUTO_TEST_CASE(replay_block_publication_preserves_final_deadline_order)
{
    namespace hs = drivechain::haskell;
    const std::array<uint32_t,4> gates{1, 2, 4, 6};
    for (unsigned flags = 0; flags < 16; ++flags) {
        const auto reply = [&](uint32_t n) -> uint32_t {
            const auto gate = std::find(gates.begin(), gates.end(), n);
            return gate == gates.end() ? 1 : (flags >> (gate - gates.begin())) & 1U;
        };
        std::vector<uint32_t> expected;
        const auto step = [&](uint32_t n) { expected.push_back(n); return reply(n); };
        const bool result = [&] {
            if (step(1) && step(2)) { step(3); return false; }
            if (step(4)) step(5);
            if (step(6)) step(7);
            step(8); return true;
        }();
        CheckReplayFlowFaults(hs::ReplayStoreFlow::BLOCK_PUBLISH, expected, result, reply);
    }
}

BOOST_AUTO_TEST_CASE(m6_withdrawal_flow_preserves_guards_and_partial_mutations)
{
    namespace hs = drivechain::haskell;
    const std::array<uint32_t,11> gates{1, 2, 5, 6, 8, 9, 12, 14, 16, 17, 18};
    for (unsigned flags = 0; flags < 2048; ++flags) {
        const auto reply = [&](uint32_t n) -> uint32_t {
            const auto gate = std::find(gates.begin(), gates.end(), n == 20 ? 17 : n);
            return gate == gates.end() ? 1 : (flags >> (gate - gates.begin())) & 1U;
        };
        std::vector<uint32_t> expected;
        const auto step = [&](uint32_t n) { expected.push_back(n); return reply(n); };
        const bool result = [&] {
            if (!step(1) || !step(2)) { step(3); return false; }
            step(4);
            if (!step(5) || !step(6)) { step(7); return false; }
            if (!step(8)) return false;
            if (!step(9)) { step(10); return false; }
            step(11);
            if (!step(12)) { step(13); return false; }
            if (!step(14)) { step(15); return false; }
            if (step(16) && step(17) && step(18)) { step(19); return false; }
            if (step(20)) step(21);
            step(22); step(23); step(24); step(25);
            return true;
        }();
        CheckReplayFlowFaults(hs::ReplayStoreFlow::M6_WITHDRAWAL, expected, result, reply);
    }
}

BOOST_AUTO_TEST_CASE(m5_deposit_flow_preserves_validation_mutation_and_publication)
{
    namespace hs = drivechain::haskell;
    const std::array<uint32_t,9> gates{1, 2, 5, 6, 10, 11, 12, 13, 14};
    for (unsigned flags = 0; flags < 512; ++flags) {
        const auto reply = [&](uint32_t n) -> uint32_t {
            const auto gate = std::find(gates.begin(), gates.end(), n);
            return gate == gates.end() ? 1 : (flags >> (gate - gates.begin())) & 1U;
        };
        std::vector<uint32_t> expected;
        const auto step = [&](uint32_t n) { expected.push_back(n); return reply(n); };
        const bool result = [&] {
            if (!step(1) || !step(2)) { step(3); return false; }
            step(4);
            if (!step(5) || !step(6)) { step(7); return false; }
            step(8); step(9);
            if (step(10) && step(11) && step(12) && step(13) && step(14)) step(15);
            return true;
        }();
        CheckReplayFlowFaults(hs::ReplayStoreFlow::M5_DEPOSIT, expected, result, reply);
    }
}

BOOST_AUTO_TEST_CASE(ctip_changes_preserve_values_publication_and_faults)
{
    namespace hs = drivechain::haskell;
    const std::array<int64_t,8> old_values{0, 0, 5, 5, 5, 5, 2100000000000000LL, 0};
    const std::array<int64_t,8> new_values{0, 5, 5, 5, 4, 6, 0, 2100000000000000LL};
    for (unsigned code = 0; code < 512; ++code) for (unsigned count : {0, 3}) {
        const std::array<unsigned,3> entries{code % 8, (code / 8) % 8, code / 64};
        std::array<int64_t,7> state{}; // index, selected, old, new, decreases, spend reads, error
        std::vector<int64_t> published;
        const auto snapshot = [&] { auto result = published; result.insert(result.end(), state.begin(), state.end()); return result; };
        const auto action = [&](uint32_t n) -> uint32_t {
            const auto selected = [&] { return entries.at(state[1]); };
            switch (n) {
            case 1: return state[0] < count;
            case 2: state[1] = state[0]; return 1;
            case 3: return selected() >= 2;
            case 4: state[5] |= 1LL << state[0]; return selected() != 2;
            case 5: state[6] = 1; return 0;
            case 6: state[2] = old_values.at(selected()); return 1;
            case 7: state[2] = 0; return 1;
            case 8: state[3] = new_values.at(selected()); return 1;
            case 9: return state[3] == state[2];
            case 10: state[6] = 2; return 0;
            case 11: return state[3] < state[2];
            case 12: ++state[4]; return 1;
            case 13: published.push_back(state[2]); published.push_back(state[3]); ++state[0]; return 1;
            default: throw std::logic_error("invalid CTIP change test action");
            }
        };
        std::vector<uint32_t> expected;
        std::vector<std::vector<int64_t>> states{snapshot()};
        const auto step = [&](uint32_t n) { expected.push_back(n); auto r = action(n); states.push_back(snapshot()); return r; };
        const bool result = [&] {
            while (step(1)) {
                step(2);
                if (step(3)) { if (!step(4)) { step(5); return false; } step(6); }
                else step(7);
                step(8);
                if (step(9)) { step(10); return false; }
                if (step(11)) step(12);
                step(13);
            }
            return true;
        }();
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            state = {}; published.clear();
            std::vector<uint32_t> seen;
            const auto run = [&] { return hs::ParentReplayStore(hs::ReplayStoreFlow::CTIP_CHANGES, [&](uint32_t n) {
                seen.push_back(n);
                if (seen.size() == fault + 1) throw std::runtime_error("CTIP change fault");
                return action(n);
            }); };
            if (fault < expected.size()) BOOST_CHECK_THROW(run(), std::runtime_error);
            else BOOST_CHECK_EQUAL(run(), result);
            BOOST_CHECK(seen == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
            BOOST_CHECK(snapshot() == states.at(fault));
        }
    }
}

BOOST_AUTO_TEST_CASE(ctip_outputs_preserve_lazy_checks_maps_and_faults)
{
    namespace hs = drivechain::haskell;
    for (auto kind : {hs::ReplayStoreFlow::CTIP_OUTPUTS, hs::ReplayStoreFlow::CTIP_REPLACEMENTS}) {
        for (unsigned code = 0; code < 125; ++code) for (unsigned count : {0, 3}) {
            const std::array<unsigned,3> entries{code % 5, (code / 5) % 5, code / 25};
            std::array<unsigned,6> state{}; // index, parsed value, inserted keys, error, deadlines, spend-map reads
            const auto action = [&](uint32_t n) -> uint32_t {
                auto& index = state[0]; auto& value = state[1];
                if (n == 1) return index < count;
                if (kind == hs::ReplayStoreFlow::CTIP_OUTPUTS) {
                    switch (n) {
                    case 2: return index % 256 == 0;
                    case 3: ++state[4]; return 1;
                    case 4: value = entries.at(index); return value != 0;
                    case 5: return value != 1;
                    case 6: return value != 2;
                    case 7: state[3] = 1; return 0;
                    case 8: {
                        const unsigned key = value == 4 ? 2 : 1;
                        if (state[2] & key) return 0;
                        state[2] |= key; return 1;
                    }
                    case 9: state[3] = 2; return 0;
                    case 10: ++index; return 1;
                    }
                } else {
                    switch (n) {
                    case 2: state[5] |= 1U << index; return entries.at(index) >= 2;
                    case 3: return entries.at(index) == 3;
                    case 4: state[3] = 3; return 0;
                    case 5: ++index; return 1;
                    }
                }
                throw std::logic_error("invalid CTIP output test action");
            };
            std::vector<uint32_t> expected;
            std::vector<std::array<unsigned,6>> states{state};
            const auto step = [&](uint32_t n) { expected.push_back(n); auto r = action(n); states.push_back(state); return r; };
            const bool result = [&] {
                while (step(1)) {
                    if (kind == hs::ReplayStoreFlow::CTIP_OUTPUTS) {
                        if (step(2)) step(3);
                        if (step(4) && step(5)) {
                            if (!step(6)) { step(7); return false; }
                            if (!step(8)) { step(9); return false; }
                        }
                        step(10);
                    } else {
                        if (step(2) && !step(3)) { step(4); return false; }
                        step(5);
                    }
                }
                return true;
            }();
            for (size_t fault = 0; fault <= expected.size(); ++fault) {
                state = {};
                std::vector<uint32_t> seen;
                const auto run = [&] { return hs::ParentReplayStore(kind, [&](uint32_t n) {
                    seen.push_back(n);
                    if (seen.size() == fault + 1) throw std::runtime_error("CTIP output fault");
                    return action(n);
                }); };
                if (fault < expected.size()) BOOST_CHECK_THROW(run(), std::runtime_error);
                else BOOST_CHECK_EQUAL(run(), result);
                BOOST_CHECK(seen == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
                BOOST_CHECK(state == states.at(fault));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(ctip_scans_preserve_maps_deadlines_and_faults)
{
    namespace hs = drivechain::haskell;
    for (auto kind : {hs::ReplayStoreFlow::CTIP_OWNERS, hs::ReplayStoreFlow::CTIP_SPENDS}) {
        for (unsigned code = 0; code < 125; ++code) for (unsigned count : {0, 3}) {
            const std::array<unsigned,3> entries{code % 5, (code / 5) % 5, code / 25};
            std::array<unsigned,6> state{}; // index, projected value, two map entries, error, deadlines
            const auto action = [&](uint32_t n) -> uint32_t {
                auto& index = state[0]; auto& value = state[1];
                if (n == 1) return index < count;
                if (n == 8) { ++index; return 1; }
                if (kind == hs::ReplayStoreFlow::CTIP_OWNERS) {
                    switch (n) {
                    case 2: value = entries.at(index); return 1;
                    case 3: return value != 0;
                    case 4: state[4] = 1; return 0;
                    case 5: return value != 1;
                    case 6: {
                        auto& entry = state[value == 4 ? 3 : 2];
                        if (entry) return 0;
                        entry = 1; return 1;
                    }
                    case 7: state[4] = 2; return 0;
                    }
                } else {
                    switch (n) {
                    case 2: return index % 256 == 0;
                    case 3: ++state[5]; return 1;
                    case 4: value = entries.at(index); return 1;
                    case 5: return value != 0;
                    case 6: return ++state[value % 2 == 0 ? 3 : 2] > 1;
                    case 7: state[4] = 2; return 0;
                    }
                }
                throw std::logic_error("invalid CTIP scan test action");
            };
            std::vector<uint32_t> expected;
            std::vector<std::array<unsigned,6>> states{state};
            const auto step = [&](uint32_t n) { expected.push_back(n); auto r = action(n); states.push_back(state); return r; };
            const bool result = [&] {
                while (step(1)) {
                    if (kind == hs::ReplayStoreFlow::CTIP_OWNERS) {
                        step(2);
                        if (!step(3)) { step(4); return false; }
                        if (step(5) && !step(6)) { step(7); return false; }
                    } else {
                        if (step(2)) step(3);
                        step(4);
                        if (step(5) && step(6)) { step(7); return false; }
                    }
                    step(8);
                }
                return true;
            }();
            for (size_t fault = 0; fault <= expected.size(); ++fault) {
                state = {};
                std::vector<uint32_t> seen;
                const auto run = [&] { return hs::ParentReplayStore(kind, [&](uint32_t n) {
                    seen.push_back(n);
                    if (seen.size() == fault + 1) throw std::runtime_error("CTIP scan fault");
                    return action(n);
                }); };
                if (fault < expected.size()) BOOST_CHECK_THROW(run(), std::runtime_error);
                else BOOST_CHECK_EQUAL(run(), result);
                BOOST_CHECK(seen == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
                BOOST_CHECK(state == states.at(fault));
            }
        }
    }
    for (unsigned count : {0, 1, 255, 256, 257, 513}) {
        unsigned index{0}, deadlines{0};
        BOOST_CHECK(hs::ParentReplayStore(hs::ReplayStoreFlow::CTIP_SPENDS, [&](uint32_t n) -> uint32_t {
            switch (n) {
            case 1: return index < count;
            case 2: return index % 256 == 0;
            case 3: ++deadlines; return 1;
            case 4: return 1;
            case 5: return 0;
            case 8: ++index; return 1;
            default: throw std::logic_error("unexpected CTIP deadline test action");
            }
        }));
        BOOST_CHECK_EQUAL(index, count);
        BOOST_CHECK_EQUAL(deadlines, (count + 255) / 256);
    }
}

BOOST_AUTO_TEST_CASE(proposal_expiry_profile_selection_is_lazy)
{
    namespace hs = drivechain::haskell;
    for (bool used : {false, true}) for (bool accepted : {false, true}) for (bool fault : {false, true}) {
        unsigned calls{0};
        const auto expire = [&](uint16_t threshold, uint16_t max_age) {
            ++calls;
            BOOST_CHECK_EQUAL(threshold, used ? UINT16_MAX - 1 : 1);
            BOOST_CHECK_EQUAL(max_age, used ? UINT16_MAX : 2);
            if (fault) throw std::runtime_error("selected expiry failed");
            return accepted;
        };
        const auto run = [&] {
            return hs::ParentReplayChoose({[&] { return used; },
                [&] { return expire(UINT16_MAX - 1, UINT16_MAX); },
                [&] { return expire(1, 2); }});
        };
        if (fault) BOOST_CHECK_THROW(run(), std::runtime_error);
        else BOOST_CHECK_EQUAL(run(), accepted);
        BOOST_CHECK_EQUAL(calls, 1U);
    }
}

BOOST_AUTO_TEST_CASE(expiry_flows_preserve_iteration_effects_and_faults)
{
    namespace hs = drivechain::haskell;
    for (auto kind : {hs::ReplayStoreFlow::EXPIRE_PROPOSALS, hs::ReplayStoreFlow::EXPIRE_WITHDRAWALS}) {
        for (unsigned code = 0; code < 64; ++code) for (unsigned count : {0, 3}) {
            const std::vector<unsigned> initial{code % 4, (code / 4) % 4, code / 16};
            auto entries = initial;
            entries.resize(count);
            unsigned index{0}, error{0};
            const auto snapshot = [&] { auto state = entries; state.push_back(index); state.push_back(error); return state; };
            const auto action = [&](uint32_t n) -> uint32_t {
                switch (n) {
                case 1: return index < entries.size();
                case 2: return entries.at(index) != 0;
                case 3: error = 1; return 0;
                case 4: return entries.at(index) != 1;
                case 5: error = 2; return 0;
                case 6: return entries.at(index) == 3;
                case 7: entries.erase(entries.begin() + index); return 1;
                case 8: ++index; return 1;
                default: throw std::logic_error("invalid expiry test action");
                }
            };
            std::vector<uint32_t> expected;
            std::vector<std::vector<unsigned>> states{snapshot()};
            const auto step = [&](uint32_t n) { expected.push_back(n); auto r = action(n); states.push_back(snapshot()); return r; };
            const bool result = [&] {
                while (step(1)) {
                    if (!step(2)) { step(3); return false; }
                    if (kind == hs::ReplayStoreFlow::EXPIRE_PROPOSALS && !step(4)) { step(5); return false; }
                    if (step(6)) step(7); else step(8);
                }
                return true;
            }();
            for (size_t fault = 0; fault <= expected.size(); ++fault) {
                entries = initial; entries.resize(count); index = error = 0;
                std::vector<uint32_t> seen;
                const auto run = [&] { return hs::ParentReplayStore(kind, [&](uint32_t n) {
                    seen.push_back(n);
                    if (seen.size() == fault + 1) throw std::runtime_error("expiry fault");
                    return action(n);
                }); };
                if (fault < expected.size()) BOOST_CHECK_THROW(run(), std::runtime_error);
                else BOOST_CHECK_EQUAL(run(), result);
                BOOST_CHECK(seen == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
                BOOST_CHECK(snapshot() == states.at(fault));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(m4_dispatch_flows_preserve_skip_calls_and_publication)
{
    namespace hs = drivechain::haskell;
    for (const auto kind : {hs::ReplayStoreFlow::M4_EXPLICIT, hs::ReplayStoreFlow::M4_REPEAT}) {
        for (unsigned flags = 0; flags < 256; ++flags) {
            const auto reply = [&](uint32_t n) -> uint32_t {
                if ((kind == hs::ReplayStoreFlow::M4_EXPLICIT && (n == 2 || n == 7 || n == 10)) ||
                    (kind == hs::ReplayStoreFlow::M4_REPEAT && (n == 2 || n == 3 || n == 8))) return 1;
                return (flags >> (n - 1)) & 1U;
            };
            std::vector<uint32_t> expected;
            const auto step = [&](uint32_t n) { expected.push_back(n); return reply(n); };
            const bool result = [&] {
                if (kind == hs::ReplayStoreFlow::M4_EXPLICIT) {
                    if (step(1)) return true;
                    step(2);
                    bool effective;
                    if (step(3)) effective = step(4);
                    else {
                        if (!step(5)) { step(7); return false; }
                        if (!step(6)) return false;
                        effective = step(8);
                    }
                    if (effective) step(10);
                    return true;
                }
                if (step(1)) { step(2); return false; }
                step(3);
                bool effective;
                if (step(4)) { if (!step(5)) return false; effective = step(7); }
                else effective = step(6);
                if (effective) step(8);
                return true;
            }();
            CheckReplayFlowFaults(kind, expected, result, reply);
        }
    }
}

BOOST_AUTO_TEST_CASE(m4_leader_flow_preserves_selection_effects_and_faults)
{
    namespace hs = drivechain::haskell;
    const std::array<unsigned,7> values{0, 1, 49, 50, 51, 65534, 65535};
    for (unsigned code = 0; code < 343; ++code) {
        const std::array<unsigned,3> votes{values[code % 7], values[(code / 7) % 7], values[code / 49]};
        for (unsigned count : {0, 1, 3}) {
            for (bool upvote_ok : {false, true}) {
                std::array<unsigned,7> state{0, 1, 0, 0, 0, 0, 0}; // leader, index, second, lead, prepared, called, published
                const auto action = [&](uint32_t n) -> uint32_t {
                    auto& leader = state[0]; auto& index = state[1]; auto& second = state[2]; auto& lead = state[3];
                    switch (n) {
                    case 1: return count == 0;
                    case 2: return index < count;
                    case 3: return votes.at(index) > votes.at(leader);
                    case 4: return second < votes.at(leader);
                    case 5: second = votes.at(leader); return 1;
                    case 6: return second < votes.at(index);
                    case 7: leader = index; return 1;
                    case 8: ++index; return 1;
                    case 9: lead = votes.at(leader); return 1;
                    case 10: second = votes.at(index); return 1;
                    case 11: return lead >= second;
                    case 12: return lead - second >= 50;
                    case 13: return lead < 65535;
                    case 14: ++state[4]; return 1;
                    case 15: ++state[5]; return upvote_ok;
                    case 16: ++state[6]; return 1;
                    default: throw std::logic_error("invalid leader test action");
                    }
                };
                std::vector<uint32_t> expected;
                std::vector<std::array<unsigned,7>> states{state};
                const auto step = [&](uint32_t n) { expected.push_back(n); auto r = action(n); states.push_back(state); return r; };
                const bool result = [&] {
                    if (step(1)) return true;
                    while (step(2)) {
                        if (step(3)) { if (step(4)) step(5); step(7); }
                        else if (step(6)) step(10);
                        step(8);
                    }
                    step(9);
                    if (step(11) && step(12) && step(13)) {
                        step(14); if (!step(15)) return false; step(16);
                    }
                    return true;
                }();
                for (size_t fault = 0; fault <= expected.size(); ++fault) {
                    state = {0, 1, 0, 0, 0, 0, 0};
                    std::vector<uint32_t> seen;
                    const auto run = [&] {
                        return hs::ParentReplayStore(hs::ReplayStoreFlow::M4_LEADER, [&](uint32_t n) {
                            seen.push_back(n);
                            if (seen.size() == fault + 1) throw std::runtime_error("M4 leader fault");
                            return action(n);
                        });
                    };
                    if (fault < expected.size()) BOOST_CHECK_THROW(run(), std::runtime_error);
                    else BOOST_CHECK_EQUAL(run(), result);
                    BOOST_CHECK(seen == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
                    BOOST_CHECK(state == states.at(fault));
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(m4_vote_flows_preserve_counters_effects_and_faults)
{
    namespace hs = drivechain::haskell;
    const std::array<uint16_t,4> values{0, 1, 65534, 65535};
    for (const auto kind : {hs::ReplayStoreFlow::M4_UPVOTE, hs::ReplayStoreFlow::M4_ALARM}) {
        for (unsigned code = 0; code < 64; ++code) {
            const std::array<uint16_t,3> initial{values[code % 4], values[(code / 4) % 4], values[code / 16]};
            for (unsigned count : {0, 3}) {
                for (unsigned wanted = 0; wanted <= count; ++wanted) {
                    auto votes = initial;
                    unsigned target{0}, entry{0}, effective{0}, error{0};
                    bool changed{false};
                    const auto snapshot = [&] { return std::array<unsigned,8>{votes[0], votes[1], votes[2], target, entry, effective, error, unsigned(changed)}; };
                    const auto action = [&](uint32_t n) -> uint32_t {
                        if (kind == hs::ReplayStoreFlow::M4_ALARM) {
                            switch (n) {
                            case 1: return entry < count;
                            case 2: return votes.at(entry) > 0;
                            case 3: --votes.at(entry); changed = true; return 1;
                            case 4: ++entry; return 1;
                            case 5: return changed;
                            case 6: effective = 2; return 1;
                            default: throw std::logic_error("invalid alarm test action");
                            }
                        }
                        switch (n) {
                        case 1: return target < count;
                        case 2: return target == wanted;
                        case 3: ++target; return 1;
                        case 4: error = 1; return 0;
                        case 5: return votes.at(target) < 65535;
                        case 6: ++votes.at(target); entry = 0; return 1;
                        case 7: return entry < count;
                        case 8: return entry != target;
                        case 9: return votes.at(entry) > 0;
                        case 10: --votes.at(entry); return 1;
                        case 11: ++entry; return 1;
                        case 12: effective = 1; return 1;
                        default: throw std::logic_error("invalid upvote test action");
                        }
                    };
                    std::vector<uint32_t> expected;
                    std::vector<std::array<unsigned,8>> states{snapshot()};
                    const auto step = [&](uint32_t n) { expected.push_back(n); auto r = action(n); states.push_back(snapshot()); return r; };
                    const bool result = [&] {
                        if (kind == hs::ReplayStoreFlow::M4_ALARM) {
                            while (step(1)) { if (step(2)) step(3); step(4); }
                            if (step(5)) { step(6); return true; }
                            return false;
                        }
                        bool found{false};
                        while (step(1)) { if (step(2)) { found = true; break; } step(3); }
                        if (!found) { step(4); return false; }
                        if (!step(5)) return true;
                        step(6);
                        while (step(7)) { if (step(8) && step(9)) step(10); step(11); }
                        step(12); return true;
                    }();
                    for (size_t fault = 0; fault <= expected.size(); ++fault) {
                        votes = initial; target = entry = effective = error = 0; changed = false;
                        std::vector<uint32_t> seen;
                        const auto run = [&] {
                            return hs::ParentReplayStore(kind, [&](uint32_t n) {
                                seen.push_back(n);
                                if (seen.size() == fault + 1) throw std::runtime_error("M4 vote fault");
                                return action(n);
                            });
                        };
                        if (fault < expected.size()) BOOST_CHECK_THROW(run(), std::runtime_error);
                        else BOOST_CHECK_EQUAL(run(), result);
                        BOOST_CHECK(seen == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
                        BOOST_CHECK(snapshot() == states.at(fault));
                    }
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(proposal_admission_preserves_effects_and_faults)
{
    namespace hs = drivechain::haskell;
    for (const auto kind : {hs::ReplayStoreFlow::PROPOSAL_INSERT, hs::ReplayStoreFlow::WITHDRAWAL_PROPOSAL}) {
        for (bool flag : {false, true}) {
            for (unsigned count = 0; count <= 4; ++count) {
                for (unsigned duplicate = 0; duplicate <= count; ++duplicate) {
                    std::array<unsigned,4> state{}; // index, identity writes, pending writes, error
                    const auto action = [&](uint32_t n) -> uint32_t {
                        if (kind == hs::ReplayStoreFlow::PROPOSAL_INSERT) {
                            if (n == 1) return flag;
                            ++state[2]; return 1;
                        }
                        switch (n) {
                        case 1: return flag;
                        case 2: case 6: state[3] = n; return 0;
                        case 4: return state[0] < count;
                        case 5: return state[0] == duplicate;
                        case 7: ++state[0]; return 1;
                        case 8: ++state[1]; return 1;
                        case 9: ++state[2]; return 1;
                        default: return 1;
                        }
                    };
                    std::vector<uint32_t> expected;
                    std::vector<std::array<unsigned,4>> states{state};
                    const auto step = [&](uint32_t n) { expected.push_back(n); auto r = action(n); states.push_back(state); return r; };
                    const bool result = [&] {
                        if (kind == hs::ReplayStoreFlow::PROPOSAL_INSERT) {
                            if (step(1)) step(2);
                            return true;
                        }
                        if (step(1)) { step(2); return false; }
                        step(3);
                        while (step(4)) {
                            if (step(5)) { step(6); return false; }
                            step(7);
                        }
                        step(8); step(9); return true;
                    }();
                    for (size_t fault = 0; fault <= expected.size(); ++fault) {
                        state = {};
                        std::vector<uint32_t> seen;
                        const auto run = [&] {
                            return hs::ParentReplayStore(kind, [&](uint32_t n) {
                                seen.push_back(n);
                                if (seen.size() == fault + 1) throw std::runtime_error("proposal admission fault");
                                return action(n);
                            });
                        };
                        if (fault < expected.size()) BOOST_CHECK_THROW(run(), std::runtime_error);
                        else BOOST_CHECK_EQUAL(run(), result);
                        BOOST_CHECK(seen == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
                        BOOST_CHECK(state == states.at(fault));
                    }
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(proposal_ack_preserves_lazy_order_and_partial_mutations)
{
    namespace hs = drivechain::haskell;
    const std::array<uint32_t,11> gates{1,2,3,7,10,11,14,15,16,18,19};
    for (unsigned flags = 0; flags < 2048; ++flags) {
        const auto reply = [&](uint32_t n) -> uint32_t {
            auto it = std::find(gates.begin(), gates.end(), n);
            return it == gates.end() ? 1 : (flags >> std::distance(gates.begin(), it)) & 1U;
        };
        std::vector<uint32_t> expected;
        const auto step = [&](uint32_t n) { expected.push_back(n); return reply(n); };
        const bool result = [&] {
            if (!step(1) || step(2)) return true;
            if (step(3)) { step(4); return false; }
            step(5); step(6);
            if (step(7)) step(8); else step(9);
            if (step(10) && step(11)) {
                step(12); step(13);
                if (step(14)) {
                    if (step(15) && step(16)) { step(17); return false; }
                    if (step(18) && step(19)) { step(20); step(21); step(22); }
                }
            }
            return true;
        }();
        CheckReplayFlowFaults(hs::ReplayStoreFlow::PROPOSAL_ACK, expected, result, reply);
    }
}

BOOST_AUTO_TEST_CASE(coinbase_collection_preserves_order_mutations_and_faults)
{
    namespace hs = drivechain::haskell;
    for (unsigned sequence = 0; sequence < 216; ++sequence) {
        const std::array<unsigned,3> types{sequence % 6, (sequence / 6) % 6, sequence / 36};
        unsigned index{0}, error{0};
        bool saw_m4{false};
        std::set<unsigned> m1, m2, m7, accepted;
        std::vector<unsigned> appended;
        const auto reset = [&] { index = error = 0; saw_m4 = false; m1.clear(); m2.clear(); m7.clear(); accepted.clear(); appended.clear(); };
        const auto snapshot = [&] { return std::array<size_t,8>{index, error, size_t(saw_m4), m1.size(), m2.size(), m7.size(), accepted.size(), appended.size()}; };
        const auto action = [&](uint32_t n) -> uint32_t {
            switch (n) {
            case 1: return index < types.size();
            case 2: return index % 256 == 0;
            case 5: return types.at(index);
            case 6: return m1.insert(index % 2).second;
            case 8: return m2.insert(index % 2).second;
            case 10: return saw_m4;
            case 12: saw_m4 = true; return 1;
            case 14: return m7.insert(index % 2).second;
            case 16: accepted.insert(index % 2); return 1;
            case 18: appended.push_back(types.at(index)); return 1;
            case 19: ++index; return 1;
            case 7: case 9: case 11: case 15: error = n; return 0;
            default: return 1;
            }
        };
        std::vector<uint32_t> expected;
        std::vector<std::array<size_t,8>> states{snapshot()};
        const auto step = [&](uint32_t n) { expected.push_back(n); auto r = action(n); states.push_back(snapshot()); return r; };
        const bool result = [&] {
            while (step(1)) {
                if (step(2)) step(3);
                step(4);
                const auto type = step(5);
                if (type == 0) { step(19); continue; }
                if (type == 1 && !step(6)) { step(7); return false; }
                if (type == 2 && !step(8)) { step(9); return false; }
                if (type == 4 && step(10)) { step(11); return false; }
                if (type == 4) step(12);
                if (type == 5 && !step(14)) { step(15); return false; }
                if (type == 5) step(16);
                step(18);
                step(19);
            }
            return true;
        }();
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            reset();
            std::vector<uint32_t> seen;
            const auto run = [&] {
                return hs::ParentReplayStore(hs::ReplayStoreFlow::COINBASE_MESSAGES, [&](uint32_t n) {
                    seen.push_back(n);
                    if (seen.size() == fault + 1) throw std::runtime_error("coinbase collection fault");
                    return action(n);
                });
            };
            if (fault < expected.size()) BOOST_CHECK_THROW(run(), std::runtime_error);
            else BOOST_CHECK_EQUAL(run(), result);
            BOOST_CHECK(seen == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
            BOOST_CHECK(snapshot() == states.at(fault));
        }
    }
    for (unsigned count : {0, 1, 255, 256, 257, 513}) {
        unsigned index{0};
        std::vector<unsigned> deadlines;
        BOOST_CHECK_EQUAL(hs::ParentReplayStore(hs::ReplayStoreFlow::COINBASE_MESSAGES, [&](uint32_t n) -> uint32_t {
            switch (n) {
            case 1: return index < count;
            case 2: return hs::ParentReplayRecord(hs::ReplayRecordKind::PERIODIC_DEADLINE, 0, 0, index);
            case 3: deadlines.push_back(index); return 1;
            case 5: return 0;
            case 19: ++index; return 1;
            default: return 1;
            }
        }), 1U);
        std::vector<unsigned> expected;
        for (unsigned i = 0; i < count; i += 256) expected.push_back(i);
        BOOST_CHECK(deadlines == expected);
        BOOST_CHECK_EQUAL(index, count);
    }
}

BOOST_AUTO_TEST_CASE(m8_acceptance_flow_preserves_traversal_and_faults)
{
    namespace hs = drivechain::haskell;
    for (unsigned count : {0, 1, 2, 3}) {
        for (unsigned flags = 0; flags < 256; ++flags) {
            unsigned index{0};
            const auto action = [&](uint32_t step) -> uint32_t {
                const unsigned bits = flags >> (4 * (index % 2));
                switch (step) {
                case 1: return index < count;
                case 3: return bits & 1U;
                case 5: return (bits >> 1) & 1U;
                case 6: return (bits >> 2) & 1U;
                case 8: return (bits >> 3) & 1U;
                case 7: case 9: return 0;
                case 11: ++index; return 1;
                default: return 1;
                }
            };
            std::vector<uint32_t> expected;
            const auto step = [&](uint32_t n) { expected.push_back(n); return action(n); };
            const bool result = [&] {
                while (step(1)) {
                    step(2);
                    if (step(3)) {
                        step(4);
                        if (!step(5) || !step(6)) { step(7); return false; }
                        if (!step(8)) { step(9); return false; }
                    }
                    step(11);
                }
                return true;
            }();
            for (size_t fault = 0; fault <= expected.size(); ++fault) {
                index = 0;
                std::vector<uint32_t> seen;
                const auto run = [&] {
                    return hs::ParentReplayStore(hs::ReplayStoreFlow::M8_ACCEPTANCE, [&](uint32_t n) {
                        seen.push_back(n);
                        if (seen.size() == fault + 1) throw std::runtime_error("M8 traversal fault");
                        return action(n);
                    });
                };
                if (fault < expected.size()) BOOST_CHECK_THROW(run(), std::runtime_error);
                else BOOST_CHECK_EQUAL(run(), result);
                BOOST_CHECK(seen == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
                BOOST_CHECK_EQUAL(index, std::count(expected.begin(), expected.begin() + fault, 11U));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_preflight_flows_preserve_short_circuit_and_faults)
{
    namespace hs = drivechain::haskell;
    for (const auto kind : {hs::ReplayStoreFlow::PROPOSAL_CONSISTENCY, hs::ReplayStoreFlow::OTHER_SLOT_PREFLIGHT,
                           hs::ReplayStoreFlow::PRIOR_M4_PREFLIGHT, hs::ReplayStoreFlow::COINBASE_PREFLIGHT}) {
        for (unsigned flags = 0; flags < 16; ++flags) {
            const auto reply = [&](uint32_t action) { return (flags >> (action - 1)) & 1U; };
            std::vector<uint32_t> expected;
            const auto read = [&](uint32_t action) { expected.push_back(action); return reply(action) != 0; };
            const bool accepted = [&] {
                switch (kind) {
                case hs::ReplayStoreFlow::PROPOSAL_CONSISTENCY: return !((read(1) && read(2)) || (read(3) && read(4)));
                case hs::ReplayStoreFlow::OTHER_SLOT_PREFLIGHT: return !(read(1) || (read(2) && read(3)) || !read(4));
                case hs::ReplayStoreFlow::PRIOR_M4_PREFLIGHT: return !((!read(1) && !read(2)) || (read(3) && !read(4)));
                case hs::ReplayStoreFlow::COINBASE_PREFLIGHT: return !(read(1) || !read(2) || !read(3));
                default: throw std::logic_error("unknown preflight test");
                }
            }();
            for (size_t fault = 0; fault <= expected.size(); ++fault) {
                std::vector<uint32_t> seen;
                const auto run = [&] {
                    return hs::ParentReplayStore(kind, [&](uint32_t action) {
                        seen.push_back(action);
                        if (seen.size() == fault + 1) throw std::runtime_error("preflight read fault");
                        return reply(action);
                    });
                };
                if (fault < expected.size()) BOOST_CHECK_THROW(run(), std::runtime_error);
                else BOOST_CHECK_EQUAL(run(), accepted);
                BOOST_CHECK(seen == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(header_mtp_flow_preserves_lazy_json_reads_and_faults)
{
    namespace hs = drivechain::haskell;
    for (unsigned flags = 0; flags < 256; ++flags) {
        const std::array<uint32_t,8> gates{2,5,6,7,9,10,13,15};
        const auto reply = [&](uint32_t action) -> uint32_t {
            const auto it = std::find(gates.begin(), gates.end(), action);
            return it == gates.end() ? 1 : (flags >> std::distance(gates.begin(), it)) & 1U;
        };
        std::vector<uint32_t> expected;
        const auto step = [&](uint32_t action) { expected.push_back(action); return reply(action); };
        const bool accepted = [&] {
            if (!step(2)) { step(3); return false; }
            step(4);
            if (!step(5) || !step(6) || !step(7)) { step(8); return false; }
            if (!step(9) || !step(10)) { step(11); return false; }
            step(12);
            if (!step(13)) { step(14); return false; }
            return step(15) != 0;
        }();
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            std::vector<uint32_t> seen;
            const auto run = [&] {
                return hs::ParentReplayStore(hs::ReplayStoreFlow::HEADER_MTP, [&](uint32_t action) {
                    seen.push_back(action);
                    if (seen.size() == fault + 1) throw std::runtime_error("header MTP fault");
                    return reply(action);
                });
            };
            if (fault < expected.size()) BOOST_CHECK_THROW(run(), std::runtime_error);
            else BOOST_CHECK_EQUAL(run(), accepted);
            BOOST_CHECK(seen == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
        }
    }
}

BOOST_AUTO_TEST_CASE(checkpoint_identity_flow_preserves_lazy_reads_and_faults)
{
    namespace hs = drivechain::haskell;
    for (unsigned flags = 0; flags < 4096; ++flags) {
        const auto bit = [&](unsigned n) { return (flags >> n) & 1U; };
        const auto reply = [&](uint32_t action) -> uint32_t {
            switch (action) {
            case 1: return bit(0);
            case 2: case 11: return bit(1);
            case 3: case 12: return bit(2);
            case 4: case 13: return bit(3);
            case 5: return bit(4);
            case 6: case 15: return bit(5);
            case 7: return bit(6);
            case 8: case 16: return bit(7);
            case 9: return bit(8);
            case 14: return bit(9);
            case 17: return bit(10);
            case 18: return bit(11);
            default: throw std::logic_error("invalid identity test action");
            }
        };
        std::vector<uint32_t> expected;
        const auto step = [&](uint32_t action) { expected.push_back(action); return reply(action); };
        const bool accepted = [&] {
            if (!step(1)) return false;
            const bool absent = step(2) && (!step(3) || step(4)) && step(5) && step(6) && step(7) && step(8);
            if (absent) return step(9) != 0;
            return !step(11) && step(12) && !step(13) && step(14) && !step(15) && !step(16) && step(17) && step(18);
        }();
        CheckReplayFlowFaults(hs::ReplayStoreFlow::CHECKPOINT_IDENTITY, expected, accepted, reply);
    }
}

BOOST_AUTO_TEST_CASE(credential_flows_preserve_lazy_security_gates_and_faults)
{
    namespace hs = drivechain::haskell;
    for (unsigned flags = 0; flags < 64; ++flags) {
        const auto bit = [&](unsigned n) { return (flags >> n) & 1U; };
        const auto reply = [&](uint32_t action) -> uint32_t {
            switch (action) {
            case 1: return bit(0);
            case 2: return bit(1);
            case 3: case 7: return bit(2);
            case 4: case 8: return bit(3);
            case 6: return bit(4);
            case 11: return bit(5);
            default: return 1;
            }
        };
        std::vector<uint32_t> expected;
        const auto step = [&](uint32_t action) { expected.push_back(action); return reply(action); };
        const bool accepted = [&] {
            if (step(1) && (step(2) || step(3) || step(4))) { step(5); return false; }
            if (step(6) && (step(7) || step(8))) { step(9); return false; }
            step(10);
            if (!step(11)) return false;
            step(12); return true;
        }();
        CheckReplayFlowFaults(hs::ReplayStoreFlow::CREDENTIAL_SOURCE, expected, accepted, reply);
    }
    for (unsigned flags = 0; flags < 32; ++flags) {
        const auto reply = [&](uint32_t action) -> uint32_t {
            switch (action) {
            case 1: return flags & 1;
            case 3: return (flags >> 1) & 1;
            case 4: return (flags >> 2) & 1;
            case 5: return (flags >> 3) & 1;
            case 7: return (flags >> 4) & 1;
            default: return 1;
            }
        };
        std::vector<uint32_t> expected;
        const auto step = [&](uint32_t action) { expected.push_back(action); return reply(action); };
        const bool accepted = [&] {
            if (step(1)) { step(2); return false; }
            if (step(3)) {
                if (!step(4) || !step(5)) { step(6); return false; }
            } else if (!step(7)) { step(8); return false; }
            step(9); return true;
        }();
        CheckReplayFlowFaults(hs::ReplayStoreFlow::CREDENTIAL_LOAD, expected, accepted, reply);
    }
}

BOOST_AUTO_TEST_CASE(cookie_cache_flow_preserves_lock_scope_and_faults)
{
    namespace hs = drivechain::haskell;
    for (bool budget : {false,true}) for (bool available : {false,true}) for (bool hit : {false,true}) {
        std::vector<uint32_t> expected{1, budget ? 2U : 4U};
        const bool locked = !budget || available;
        if (!locked) expected.push_back(3);
        else {
            expected.push_back(5);
            if (hit) expected.push_back(6);
        }
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            std::mutex mutex;
            std::vector<uint32_t> seen;
            bool copied{false};
            const auto run = [&] {
                std::unique_lock<std::mutex> lock(mutex, std::defer_lock);
                return hs::ParentReplayStore(hs::ReplayStoreFlow::COOKIE_CACHE, [&](uint32_t action) -> uint32_t {
                    seen.push_back(action);
                    if (seen.size() == fault + 1) throw std::runtime_error("cache fault");
                    switch (action) {
                    case 1: return budget;
                    case 2: return available && lock.try_lock();
                    case 3: return 0;
                    case 4: lock.lock(); return 1;
                    case 5: BOOST_CHECK(lock.owns_lock()); return hit;
                    case 6: BOOST_CHECK(lock.owns_lock()); copied = true; return 1;
                    default: throw std::logic_error("invalid cache test action");
                    }
                });
            };
            if (fault < expected.size()) BOOST_CHECK_THROW(run(), std::runtime_error);
            else BOOST_CHECK_EQUAL(run(), locked && hit);
            BOOST_CHECK(seen == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
            BOOST_CHECK_EQUAL(copied, fault == expected.size() && locked && hit);
            std::unique_lock released(mutex, std::try_to_lock);
            BOOST_CHECK(released.owns_lock());
        }
    }
}

BOOST_AUTO_TEST_CASE(rpc_timeout_preserves_deadline_precedence_and_faults)
{
    namespace hs = drivechain::haskell;
    for (bool budget : {false,true}) for (bool warm : {false,true})
    for (int64_t micros : {-1000001LL,-1LL,0LL,1LL,999999LL,1000000LL,1000001LL,2000000LL})
    for (int64_t configured : {-1LL,0LL,1LL,2LL,9223372036854775807LL}) {
        std::vector<uint32_t> expected{1};
        int64_t expected_micros = micros;
        unsigned terminal{0};
        if (budget) {
            expected.insert(expected.end(), {2,3});
            terminal = micros > 0 ? 5 : 4;
        } else {
            expected.push_back(6);
            if (!warm) terminal = 14;
            else {
                expected.insert(expected.end(), {7,8});
                if (micros <= 0) terminal = 9;
                else {
                    expected.insert(expected.end(), {10,11});
                    if (configured > 0) {
                        expected.push_back(12);
                        if (configured < (micros + 999999) / 1000000) {
                            expected.push_back(13);
                            expected_micros = configured * 1000000;
                        }
                    }
                    terminal = 5;
                }
            }
        }
        expected.push_back(terminal);
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            std::vector<uint32_t> seen;
            int64_t remaining{0};
            bool wrote{false};
            const auto run = [&] {
                return hs::ParentReplayStore(hs::ReplayStoreFlow::RPC_TIMEOUT, [&](uint32_t action) -> uint32_t {
                    seen.push_back(action);
                    if (seen.size() == fault + 1) throw std::runtime_error("timeout fault");
                    switch (action) {
                    case 1: return budget;
                    case 2: case 7: remaining = micros; return 1;
                    case 3: case 8: return hs::ParentReplayRecord(hs::ReplayRecordKind::SIGNED_POSITIVE, 0, remaining, 0, 0);
                    case 6: return warm;
                    case 11: return hs::ParentReplayRecord(hs::ReplayRecordKind::SIGNED_POSITIVE, 0, configured, 0, 0);
                    case 12: return hs::ParentReplayRecord(hs::ReplayRecordKind::LESS, 0, 0, configured, (remaining + 999999) / 1000000);
                    case 13: remaining = configured * 1000000; return 1;
                    case 5: case 14: wrote = true; return 1;
                    default: return 1;
                    }
                });
            };
            if (fault < expected.size()) BOOST_CHECK_THROW(run(), std::runtime_error);
            else BOOST_CHECK_EQUAL(run(), terminal == 5 || terminal == 14);
            BOOST_CHECK(seen == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
            BOOST_CHECK_EQUAL(wrote, fault == expected.size() && (terminal == 5 || terminal == 14));
            if (wrote && terminal == 5) BOOST_CHECK_EQUAL(remaining, expected_micros);
        }
    }
}

BOOST_AUTO_TEST_CASE(rpc_cookie_retry_preserves_invalidation_order_and_faults)
{
    namespace hs = drivechain::haskell;
    for (bool cookie : {false, true}) for (bool budget : {false, true}) {
        const std::vector<uint32_t> expected = cookie ? std::vector<uint32_t>{1,2,3} : std::vector<uint32_t>{1};
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            std::vector<uint32_t> seen;
            bool invalidated{false};
            const auto run = [&] {
                return hs::ParentReplayStore(hs::ReplayStoreFlow::AUTH_RETRY, [&](uint32_t action) -> uint32_t {
                    seen.push_back(action);
                    if (seen.size() == fault + 1) throw std::runtime_error("cookie retry fault");
                    switch (action) {
                    case 1: return cookie;
                    case 2: invalidated = true; return 1;
                    case 3: BOOST_CHECK(invalidated); return budget;
                    default: throw std::logic_error("invalid retry test action");
                    }
                });
            };
            if (fault < expected.size()) BOOST_CHECK_THROW(run(), std::runtime_error);
            else BOOST_CHECK_EQUAL(run(), cookie && !budget);
            BOOST_CHECK(seen == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
            BOOST_CHECK_EQUAL(invalidated, cookie && fault >= 2);
        }
    }
}

BOOST_AUTO_TEST_CASE(rpc_reply_flow_preserves_lazy_result_and_faults)
{
    namespace hs = drivechain::haskell;
    for (unsigned flags = 0; flags < 4; ++flags) {
        const bool error_null = flags & 1, result_null = flags & 2;
        std::vector<uint32_t> expected{1};
        if (!error_null) expected.push_back(2);
        else {
            expected.push_back(3);
            if (result_null) expected.push_back(4);
        }
        CheckReplayFlowFaults(hs::ReplayStoreFlow::RPC_REPLY, expected, error_null && !result_null,
            [&](uint32_t action) -> uint32_t { return action == 1 ? error_null : action == 3 ? result_null : 1; });
    }
}

BOOST_AUTO_TEST_CASE(parent_signet_merkle_flow_preserves_order_and_faults)
{
    namespace hs = drivechain::haskell;
    for (size_t count = 0; count < 6; ++count) {
        std::vector<uint32_t> expected{1,2,3};
        for (size_t i = 1; i < count; ++i) expected.insert(expected.end(), {4,5,6});
        expected.insert(expected.end(), {4,7});
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            size_t index{0}, roots{0};
            std::vector<uint32_t> seen;
            const auto run = [&] {
                return hs::ParentReplayStore(hs::ReplayStoreFlow::SIGNET_MERKLE, [&](uint32_t action) -> uint32_t {
                    seen.push_back(action);
                    if (seen.size() == fault + 1) throw std::runtime_error("Merkle action fault");
                    switch (action) {
                    case 3: index = 1; break;
                    case 4: return hs::ParentReplayRecord(hs::ReplayRecordKind::LESS, 0, 0, index, count);
                    case 6: ++index; break;
                    case 7: ++roots; break;
                    }
                    return 1;
                });
            };
            if (fault < expected.size()) BOOST_CHECK_THROW(run(), std::runtime_error);
            else BOOST_CHECK_EQUAL(run(), 1);
            BOOST_CHECK(seen == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
            BOOST_CHECK_EQUAL(roots, fault == expected.size() ? 1 : 0);
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_recovery_flow_preserves_lazy_comparison_and_terminal_write)
{
    namespace hs = drivechain::haskell;
    struct Fault {};
    for (unsigned flags = 0; flags < 4; ++flags) {
        const auto reply = [&](uint32_t step) -> uint32_t { return step == 2 ? flags & 1 : step == 3 ? (flags >> 1) & 1 : 1; };
        std::vector<uint32_t> expected{1,2};
        if (flags & 1) expected.push_back(3);
        if (!(flags & 1) || flags & 2) expected.push_back(4);
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            std::vector<uint32_t> actual;
            uint32_t result{99};
            bool threw{false};
            try {
                result = hs::ParentReplayStore(hs::ReplayStoreFlow::RECOVERY_DEADLINE, [&](uint32_t step) -> uint32_t {
                    actual.push_back(step);
                    if (actual.size()-1 == fault) throw Fault{};
                    return reply(step);
                });
            } catch (const Fault&) { threw = true; }
            BOOST_CHECK_EQUAL(threw, fault < expected.size());
            BOOST_CHECK_EQUAL(result, fault < expected.size() ? 99U : 1U);
            BOOST_CHECK(actual == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault+1, expected.size())));
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_block_wrapper_flows_preserve_lazy_actions_and_faults)
{
    namespace hs = drivechain::haskell;
    struct Fault {};
    for (const auto kind : {hs::ReplayStoreFlow::BLOCK_SIGNET, hs::ReplayStoreFlow::VERIFIED_BLOCK})
    for (unsigned flags = 0; flags < 8; ++flags) {
        const auto reply = [&](uint32_t step) -> uint32_t {
            if (kind == hs::ReplayStoreFlow::VERIFIED_BLOCK) return step == 4 ? 0 : (flags >> (step-1)) & 1;
            if (step == 2) return flags & 1;
            if (step == 4) return (flags >> 1) & 1;
            return 1;
        };
        std::vector<uint32_t> expected;
        const auto read = [&](uint32_t step) { expected.push_back(step); return reply(step); };
        const auto status = [&]() -> uint32_t {
            if (kind == hs::ReplayStoreFlow::BLOCK_SIGNET) {
                read(1);
                if (read(2)) return 1;
                read(3);
                if (!read(4)) return 0;
                read(5); return 1;
            }
            if (!read(1) || !read(2)) return 0;
            return read(3) ? 1U : read(4);
        }();
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            std::vector<uint32_t> actual;
            uint32_t result{99};
            bool threw{false};
            try {
                result = hs::ParentReplayStore(kind, [&](uint32_t step) -> uint32_t {
                    actual.push_back(step);
                    if (actual.size()-1 == fault) throw Fault{};
                    return reply(step);
                });
            } catch (const Fault&) { threw = true; }
            BOOST_CHECK_EQUAL(threw, fault < expected.size());
            BOOST_CHECK_EQUAL(result, fault < expected.size() ? 99U : status);
            BOOST_CHECK(actual == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault+1, expected.size())));
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_block_transaction_flow_preserves_scans_and_faults)
{
    namespace hs = drivechain::haskell;
    struct Fault {};
    for (uint32_t count = 0; count <= 5; ++count)
    for (unsigned variant = 0; variant < 8; ++variant) {
        uint32_t index{0};
        const auto reply = [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return count == 0;
            case 2: return variant != 1;
            case 3: return variant != 2;
            case 4: case 11: case 27: return 0;
            case 5: index = 1; return 1;
            case 6: case 18: return index < count;
            // Short synthetic scans exercise both branches; the real periodic rule has separate boundary fixtures.
            case 7: case 19: return index % 2 == 0;
            case 9: return variant != 3 || index != count-1;
            case 10: return variant == 4 && index == count-1;
            case 12: case 22: ++index; return 1;
            case 17: index = 0; return 1;
            case 25: return variant == 5 || variant == 7;
            case 26: return variant == 6 || variant == 7;
            default: return 1;
            }
        };
        std::vector<uint32_t> expected;
        const auto read = [&](uint32_t step) { expected.push_back(step); return reply(step); };
        const auto status = [&]() -> uint32_t {
            if (read(1) || !read(2) || !read(3)) return read(4);
            read(5);
            while (read(6)) {
                if (read(7)) read(8);
                if (!read(9) || read(10)) return read(11);
                read(12);
            }
            read(14); read(15); read(16); read(17);
            while (read(18)) {
                if (read(19)) read(20);
                read(21); read(22);
            }
            read(24);
            if (read(25) || read(26)) return read(27);
            read(28); return 1;
        }();
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            index = 0;
            std::vector<uint32_t> actual;
            uint32_t result{99};
            bool threw{false};
            try {
                result = hs::ParentReplayStore(hs::ReplayStoreFlow::BLOCK_TRANSACTIONS, [&](uint32_t step) -> uint32_t {
                    actual.push_back(step);
                    if (actual.size()-1 == fault) throw Fault{};
                    return reply(step);
                });
            } catch (const Fault&) { threw = true; }
            BOOST_CHECK_EQUAL(threw, fault < expected.size());
            BOOST_CHECK_EQUAL(result, fault < expected.size() ? 99U : status);
            BOOST_CHECK(actual == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault+1, expected.size())));
        }
    }
}

BOOST_AUTO_TEST_CASE(verified_parent_header_flow_preserves_all_effects_and_faults)
{
    namespace hs = drivechain::haskell;
    struct Fault {};
    const std::vector<uint32_t> predicates{1,6,7,13,17,18,21,23,25,32};
    for (unsigned flags = 0; flags < (1U << predicates.size()); ++flags) {
        const auto reply = [&](uint32_t step) -> uint32_t {
            const auto found = std::find(predicates.begin(), predicates.end(), step);
            if (found != predicates.end()) return (flags >> std::distance(predicates.begin(), found)) & 1;
            return step != 2 && step != 8 && step != 19 && step != 33;
        };
        std::vector<uint32_t> expected;
        const auto read = [&](uint32_t step) { expected.push_back(step); return reply(step); };
        const auto status = [&]() -> uint32_t {
            if (!read(1)) return read(2);
            read(3); read(4); read(5);
            if (!read(6) || !read(7)) return read(8);
            read(9); read(10); read(11); read(12);
            if (!read(13)) return 0;
            read(14); read(15); read(16);
            if (!read(17) || !read(18)) return read(19);
            read(20);
            if (!read(21)) return 0;
            read(22);
            if (!read(23)) return 0;
            read(24);
            if (!read(25)) return 0;
            for (uint32_t step = 26; step <= 31; ++step) read(step);
            return read(32) ? read(33) : 1U;
        }();
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            std::vector<uint32_t> actual;
            uint32_t result{99};
            bool threw{false};
            try {
                result = hs::ParentReplayStore(hs::ReplayStoreFlow::VERIFIED_HEADER, [&](uint32_t step) -> uint32_t {
                    actual.push_back(step);
                    if (actual.size()-1 == fault) throw Fault{};
                    return reply(step);
                });
            } catch (const Fault&) { threw = true; }
            BOOST_CHECK_EQUAL(threw, fault < expected.size());
            BOOST_CHECK_EQUAL(result, fault < expected.size() ? 99U : status);
            BOOST_CHECK(actual == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault+1, expected.size())));
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_predecessor_flow_preserves_rpc_guards_and_faults)
{
    namespace hs = drivechain::haskell;
    struct Fault {};
    const std::vector<uint32_t> predicates{1,2,3,4,7,8,14,17,18,19,20,21,24,25};
    for (unsigned flags = 0; flags < (1U << predicates.size()); ++flags) {
        const auto reply = [&](uint32_t step) -> uint32_t {
            const auto found = std::find(predicates.begin(), predicates.end(), step);
            if (found != predicates.end()) return (flags >> std::distance(predicates.begin(), found)) & 1;
            return (step >= 10 && step <= 13) || step == 16 || step == 23;
        };
        std::vector<uint32_t> expected;
        const auto read = [&](uint32_t step) { expected.push_back(step); return reply(step); };
        const auto status = [&]() -> uint32_t {
            if (read(1)) {
                if (!read(2) || !read(3)) return read(5);
                return read(4) ? 1U : read(6);
            }
            if (!read(7) || !read(8)) return read(9);
            read(10); read(11); read(12); read(13);
            if (!read(14)) return read(15);
            read(16);
            if (!read(17) || !read(18) || !read(19) || !read(20) || !read(21)) return read(22);
            read(23);
            return read(24) || !read(25) ? read(26) : 1U;
        }();
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            std::vector<uint32_t> actual;
            uint32_t result{99};
            bool threw{false};
            try {
                result = hs::ParentReplayStore(hs::ReplayStoreFlow::HEADER_PREDECESSOR, [&](uint32_t step) -> uint32_t {
                    actual.push_back(step);
                    if (actual.size()-1 == fault) throw Fault{};
                    return reply(step);
                });
            } catch (const Fault&) { threw = true; }
            BOOST_CHECK_EQUAL(threw, fault < expected.size());
            BOOST_CHECK_EQUAL(result, fault < expected.size() ? 99U : status);
            BOOST_CHECK(actual == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault+1, expected.size())));
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_header_metadata_flow_preserves_short_circuit_and_faults)
{
    namespace hs = drivechain::haskell;
    struct Fault {};
    const std::vector<uint32_t> predicates{1,3,4,9,10,11,15,16,17};
    for (unsigned flags = 0; flags < 512; ++flags) {
        const auto reply = [&](uint32_t step) -> uint32_t {
            const auto found = std::find(predicates.begin(), predicates.end(), step);
            if (found != predicates.end()) return (flags >> std::distance(predicates.begin(), found)) & 1;
            return step == 6 || step == 7 || step == 8 || step == 13 || step == 14;
        };
        std::vector<uint32_t> expected;
        const auto read = [&](uint32_t step) { expected.push_back(step); return reply(step); };
        const auto status = [&]() -> uint32_t {
            if (!read(1)) return read(2);
            if (!read(3) || !read(4)) return read(5);
            read(6); read(7); read(8);
            if (!read(9) || !read(10) || !read(11)) return read(12);
            read(13); read(14);
            return read(15) || read(16) || read(17) ? read(18) : 1U;
        }();
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            std::vector<uint32_t> actual;
            uint32_t result{99};
            bool threw{false};
            try {
                result = hs::ParentReplayStore(hs::ReplayStoreFlow::HEADER_METADATA, [&](uint32_t step) -> uint32_t {
                    actual.push_back(step);
                    if (actual.size()-1 == fault) throw Fault{};
                    return reply(step);
                });
            } catch (const Fault&) { threw = true; }
            BOOST_CHECK_EQUAL(threw, fault < expected.size());
            BOOST_CHECK_EQUAL(result, fault < expected.size() ? 99U : status);
            BOOST_CHECK(actual == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault+1, expected.size())));
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_median_flow_preserves_all_effects_and_faults)
{
    namespace hs = drivechain::haskell;
    struct Fault {};
    for (uint32_t count = 1; count <= 11; ++count)
    for (uint32_t failed = 0; failed <= count; ++failed) {
        std::vector<uint32_t> expected{1,2,3};
        for (uint32_t i = 0; i < count; ++i) {
            for (uint32_t action = 4; action <= 7; ++action) expected.push_back(action);
            if (i == failed) break;
            for (uint32_t action = 8; action <= 11; ++action) expected.push_back(action);
        }
        if (failed == count) for (auto action : {4U,12U,13U,14U}) expected.push_back(action);
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            std::vector<uint32_t> actual;
            uint32_t index{0}, status{99};
            bool threw{false};
            try {
                status = hs::ParentReplayStore(hs::ReplayStoreFlow::MEDIAN_TIME, [&](uint32_t step) -> uint32_t {
                    actual.push_back(step);
                    if (actual.size()-1 == fault) throw Fault{};
                    if (step == 4) return hs::ParentReplayRecord(hs::ReplayRecordKind::MTP_SAMPLE, 0, 0, index, count-1);
                    if (step == 7) return index != failed;
                    if (step == 11) ++index;
                    return 1;
                });
            } catch (const Fault&) { threw = true; }
            BOOST_CHECK_EQUAL(threw, fault < expected.size());
            BOOST_CHECK_EQUAL(status, fault < expected.size() ? 99U : uint32_t{failed == count});
            BOOST_CHECK(actual == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault+1, expected.size())));
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_raw_flows_preserve_order_and_faults)
{
    namespace hs = drivechain::haskell;
    struct Fault {};
    for (const auto kind : {hs::ReplayStoreFlow::RAW_PREFLIGHT, hs::ReplayStoreFlow::RAW_DECODE,
        hs::ReplayStoreFlow::RAW_POSTFLIGHT, hs::ReplayStoreFlow::RAW_REQUEST})
    for (unsigned flags = 0; flags < 32; ++flags) {
        std::vector<uint32_t> expected, actual;
        const auto reply = [&](uint32_t step) -> uint32_t {
            switch (kind) {
            case hs::ReplayStoreFlow::RAW_PREFLIGHT:
                if (step == 3) return 0;
                if (step == 4) return 1;
                break;
            case hs::ReplayStoreFlow::RAW_DECODE:
                if (step <= 2) return 1;
                if (step == 4) return 0;
                break;
            case hs::ReplayStoreFlow::RAW_POSTFLIGHT:
                if (step == 1) return 1;
                if (step == 4) return 0;
                break;
            default: if (step < 5) return 1;
            }
            return (flags >> (step - 1)) & 1;
        };
        const auto read = [&](uint32_t step) { expected.push_back(step); return reply(step); };
        const auto status = [&]() -> uint32_t {
            switch (kind) {
            case hs::ReplayStoreFlow::RAW_PREFLIGHT:
                if (!read(1) || !read(2)) return read(3);
                read(4); return 1;
            case hs::ReplayStoreFlow::RAW_DECODE:
                read(1); read(2); return read(3) ? read(4) : 1U;
            case hs::ReplayStoreFlow::RAW_POSTFLIGHT:
                read(1); return read(2) ? read(3) : read(4);
            default: read(1); read(2); read(3); read(4); return read(5);
            }
        }();
        BOOST_CHECK_EQUAL(hs::ParentReplayStore(kind, [&](uint32_t step) {
            actual.push_back(step);
            BOOST_CHECK(hs::ParentReplayRecord(hs::ReplayRecordKind::POSITIVE, 0, 0, 1));
            return reply(step);
        }), status);
        BOOST_CHECK(actual == expected);
        for (size_t fault = 0; fault < expected.size(); ++fault) {
            actual.clear();
            BOOST_CHECK_THROW(hs::ParentReplayStore(kind, [&](uint32_t step) -> uint32_t {
                actual.push_back(step);
                if (actual.size() - 1 == fault) throw Fault{};
                return reply(step);
            }), Fault);
            BOOST_CHECK(actual == std::vector<uint32_t>(expected.begin(), expected.begin() + fault + 1));
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_rpc_parse_flows_preserve_lazy_reads_and_faults)
{
    namespace hs = drivechain::haskell;
    struct Fault {};
    for (const auto kind : {hs::ReplayStoreFlow::EXACT_ADDRESS, hs::ReplayStoreFlow::CANONICAL_HASH,
        hs::ReplayStoreFlow::HEIGHT_PREFLIGHT, hs::ReplayStoreFlow::HEIGHT_PARSE})
    for (unsigned flags = 0; flags < 64; ++flags) {
        std::vector<uint32_t> expected, actual;
        const auto reply = [&](uint32_t step) -> uint32_t {
            if (kind == hs::ReplayStoreFlow::EXACT_ADDRESS && step <= 2) return 1;
            if (kind == hs::ReplayStoreFlow::CANONICAL_HASH && step == 4) return 1;
            if (kind == hs::ReplayStoreFlow::HEIGHT_PREFLIGHT && step == 2) return 0;
            if (kind == hs::ReplayStoreFlow::HEIGHT_PARSE) {
                if (step == 1 || step == 4) return 1;
                if (step == 3) return 0;
            }
            const auto bit = kind == hs::ReplayStoreFlow::EXACT_ADDRESS ? step - 3 : step - 1;
            return (flags >> bit) & 1;
        };
        const auto read = [&](uint32_t step) { expected.push_back(step); return reply(step); };
        const auto original = [&]() -> uint32_t {
            switch (kind) {
            case hs::ReplayStoreFlow::EXACT_ADDRESS:
                read(1); read(2);
                return read(3) && read(4) && read(5) && read(6) && read(7) && read(8);
            case hs::ReplayStoreFlow::CANONICAL_HASH:
                if (!read(1) || !read(2) || !read(3)) return 0;
                read(4); return read(5);
            case hs::ReplayStoreFlow::HEIGHT_PREFLIGHT: return read(1) ? 1U : read(2);
            case hs::ReplayStoreFlow::HEIGHT_PARSE:
                read(1); return read(2) ? read(4) : read(3);
            default: throw std::logic_error("invalid reference parser kind");
            }
        };
        const auto status = original();
        BOOST_CHECK_EQUAL(hs::ParentReplayStore(kind, [&](uint32_t step) { actual.push_back(step); return reply(step); }), status);
        BOOST_CHECK(actual == expected);
        for (size_t fault = 0; fault < expected.size(); ++fault) {
            actual.clear();
            BOOST_CHECK_THROW(hs::ParentReplayStore(kind, [&](uint32_t step) -> uint32_t {
                actual.push_back(step);
                if (actual.size() - 1 == fault) throw Fault{};
                return reply(step);
            }), Fault);
            BOOST_CHECK(actual == std::vector<uint32_t>(expected.begin(), expected.begin() + fault + 1));
        }
    }
    BOOST_CHECK_EQUAL(drivechain::PARENT_HASH_HEX_LENGTH, 64U);
}

BOOST_AUTO_TEST_CASE(parent_message_flows_preserve_traversal_and_fault_order)
{
    namespace hs = drivechain::haskell;
    struct Fault {};
    for (unsigned flags = 0; flags < 8; ++flags) {
        unsigned combinations{1};
        for (unsigned outputs = 0; outputs <= 4; ++outputs, combinations *= 3) {
            for (unsigned shape = 0; shape < combinations; ++shape) {
                std::vector<uint32_t> expected, actual;
                const auto run = [&](bool native, size_t fault, std::vector<uint32_t>& trace) {
                    unsigned index{0}, matches{0}, digits{shape};
                    std::vector<unsigned> output_kind;
                    for (unsigned i = 0; i < outputs; ++i) { output_kind.push_back(digits % 3); digits /= 3; }
                    const auto read = [&](uint32_t step) -> uint32_t {
                        trace.push_back(step);
                        if (trace.size() - 1 == fault) throw Fault{};
                        switch (step) {
                        case 1: case 2: case 3: return (flags >> (step - 1)) & 1;
                        case 4: case 15: return 0;
                        case 5: matches = 0; return 1;
                        case 6: index = 0; return 1;
                        case 7: return index < outputs;
                        case 8: case 12: return 1;
                        case 9: return output_kind.at(index) != 0;
                        case 10: return output_kind.at(index) == 2;
                        case 11: ++matches; return 1;
                        case 13: ++index; return 1;
                        case 14: return matches == 1;
                        default: throw std::logic_error("unexpected message action");
                        }
                    };
                    if (native) return hs::ParentReplayStore(hs::ReplayStoreFlow::EXACT_MESSAGE, read);
                    if (!read(1) || !read(2) || !read(3)) return read(4);
                    read(5); read(6);
                    while (read(7)) {
                        read(8);
                        if (read(9) && read(10)) read(11);
                        read(12); read(13);
                    }
                    return read(14) ? 1U : read(15);
                };
                const auto expected_status = run(false, SIZE_MAX, expected);
                BOOST_CHECK_EQUAL(run(true, SIZE_MAX, actual), expected_status);
                BOOST_CHECK(actual == expected);
                for (size_t fault = 0; fault < expected.size(); ++fault) {
                    actual.clear();
                    BOOST_CHECK_THROW(run(true, fault, actual), Fault);
                    BOOST_CHECK(actual == std::vector<uint32_t>(expected.begin(), expected.begin() + fault + 1));
                }
            }
        }
    }
    for (bool parser : {false, true})
    for (unsigned flags = 0; flags < 32; ++flags) {
        const auto kind = parser ? hs::ReplayStoreFlow::SINGLE_PUSH : hs::ReplayStoreFlow::PINNED_STATE;
        std::vector<uint32_t> expected, actual;
        const auto reply = [&](uint32_t step) -> uint32_t {
            if (parser && (step <= 3 || step == 9)) return 1;
            return (flags >> (step - (parser ? 4 : 1))) & 1;
        };
        const auto read = [&](uint32_t step) { expected.push_back(step); return reply(step); };
        if (parser) { read(1); read(2); read(3); }
        bool accepted{true};
        for (uint32_t step = parser ? 4 : 1; step <= (parser ? 8 : 3); ++step) {
            if (!read(step)) { accepted = false; break; }
        }
        if (parser && accepted) read(9);
        BOOST_CHECK_EQUAL(hs::ParentReplayStore(kind, [&](uint32_t step) { actual.push_back(step); return reply(step); }), uint32_t(accepted));
        BOOST_CHECK(actual == expected);
        for (size_t fault = 0; fault < expected.size(); ++fault) {
            actual.clear();
            BOOST_CHECK_THROW(hs::ParentReplayStore(kind, [&](uint32_t step) -> uint32_t {
                actual.push_back(step);
                if (actual.size() - 1 == fault) throw Fault{};
                return reply(step);
            }), Fault);
            BOOST_CHECK(actual == std::vector<uint32_t>(expected.begin(), expected.begin() + fault + 1));
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_milestones_preserve_guarded_reads_and_fault_order)
{
    namespace hs = drivechain::haskell;
    struct Fault {};
    for (uint32_t first = 0; first <= 44; ++first)
    for (uint32_t second = 0; second <= 44; ++second) {
        const auto reply = [&](uint32_t step) -> uint32_t {
            if (step == 14 || step == 26 || step == 44) return 0;
            return step != first && step != second;
        };
        std::vector<uint32_t> expected, actual;
        const auto read = [&](uint32_t step) { expected.push_back(step); return reply(step); };
        const auto original = [&]() -> uint32_t {
            read(1);
            if (read(2) && read(3)) {
                if (!read(4)) return 0;
                read(5); read(6); read(7);
                if (!read(8)) return 0;
                read(9);
                if (!read(10) || !read(11) || !read(12)) return read(14);
                read(13);
            }
            if (read(15) && read(16)) {
                if (!read(17)) return 0;
                read(18); read(19); read(20);
                if (!read(21)) return 0;
                if (!read(22) || !read(23)) return read(26);
                read(24);
            }
            if (read(27)) {
                if (!read(28)) return 0;
                read(29);
                const bool ctip = read(30) ? read(31) && read(32) && read(33) && read(34) : read(35) && read(36);
                read(ctip ? 37 : 38);
                read(read(39) ? 40 : 41);
                if (!read(42) || !read(43)) return read(44);
            }
            return 1;
        };
        // Only predicates may fail; assignment callbacks always complete.
        const std::set<uint32_t> assignments{1,5,6,7,9,13,18,19,20,24,29,37,38,40,41};
        if (assignments.count(first) || assignments.count(second)) continue;
        const auto status = original();
        BOOST_CHECK_EQUAL(hs::ParentReplayStore(hs::ReplayStoreFlow::MILESTONE, [&](uint32_t step) {
            actual.push_back(step);
            BOOST_CHECK(hs::ParentReplayRecord(hs::ReplayRecordKind::POSITIVE, 0, 0, 1));
            return reply(step);
        }), status);
        BOOST_CHECK(actual == expected);
        for (size_t fault = 0; fault < expected.size(); ++fault) {
            size_t reads{0};
            BOOST_CHECK_THROW(hs::ParentReplayStore(hs::ReplayStoreFlow::MILESTONE, [&](uint32_t step) -> uint32_t {
                BOOST_CHECK_EQUAL(step, expected.at(reads));
                if (reads++ == fault) throw Fault{};
                return reply(step);
            }), Fault);
            BOOST_CHECK_EQUAL(reads, fault + 1);
        }
    }
    for (bool matches : {false, true}) {
        std::vector<uint32_t> actual;
        BOOST_CHECK_EQUAL(hs::ParentReplayStore(hs::ReplayStoreFlow::MILESTONE_HASH, [&](uint32_t step) {
            actual.push_back(step);
            return step == 1 ? uint32_t(matches) : 0U;
        }), uint32_t(matches));
        BOOST_CHECK(actual == (matches ? std::vector<uint32_t>{1} : std::vector<uint32_t>{1,2}));
    }
}

BOOST_AUTO_TEST_CASE(parent_milestone_workflow_matches_native_reference)
{
    namespace Bitcoin = Sidechain::Bitcoin;
    const auto reference = [](const Consensus::Params& c, uint32_t height, const Bitcoin::CBlock& block,
                             const DrivechainParentReplayState& state, std::string* error) {
        const auto fail = [&](const std::string& message) { if (error) *error = message; return false; };
        const auto hash = [&](const uint256& expected) {
            return block.GetHash() == expected || fail(strprintf(
                "authenticated parent milestone height %u hashes to %s, expected %s",
                height, block.GetHash().GetHex(), expected.GetHex()));
        };
        const auto message = [&](const std::vector<unsigned char>& expected) {
            if (block.vtx.empty() || !block.vtx[0] || !block.vtx[0]->IsCoinBase())
                return fail("pinned parent identity block has no coinbase transaction");
            size_t matches{0};
            for (const auto& out : block.vtx[0]->vout) {
                auto pc = out.scriptPubKey.begin();
                opcodetype opcode{};
                std::vector<unsigned char> pushed;
                if (out.scriptPubKey.GetOp(pc, opcode, pushed) && opcode == OP_RETURN &&
                    out.scriptPubKey.GetOp(pc, opcode, pushed) && opcode <= OP_PUSHDATA4 &&
                    pc == out.scriptPubKey.end() && pushed == expected) ++matches;
            }
            return matches == 1 || fail(strprintf(
                "pinned parent identity block contains %u copies of its expected drivechain message", matches));
        };
        const bool post = !c.drivechain_parent_state_active_proposal_description.empty();
        if (post && height == c.drivechain_parent_state_proposal_height) {
            if (!hash(c.drivechain_parent_state_proposal_block_hash)) return false;
            auto payload = ParseHex("d5e0c4af");
            payload.push_back(*c.drivechain_slot);
            payload.insert(payload.end(), c.drivechain_parent_state_active_proposal_description.begin(),
                c.drivechain_parent_state_active_proposal_description.end());
            if (!message(payload)) return false;
            const auto found = state.pending_proposals.find(*c.drivechain_parent_state_active_proposal_hash);
            if (found == state.pending_proposals.end() || found->second.proposal_height != height || found->second.votes != 0)
                return fail("authenticated parent proposal milestone did not derive the expected pending proposal state");
        }
        if (post && height == c.drivechain_parent_state_activation_height) {
            if (!hash(c.drivechain_parent_state_activation_block_hash)) return false;
            auto payload = ParseHex("d6e1c5df");
            payload.push_back(*c.drivechain_slot);
            payload.insert(payload.end(), c.drivechain_parent_state_active_proposal_hash->begin(),
                c.drivechain_parent_state_active_proposal_hash->end());
            if (!message(payload)) return false;
            if (state.active_proposal_hash != *c.drivechain_parent_state_active_proposal_hash ||
                state.pending_proposals.count(*c.drivechain_parent_state_active_proposal_hash) != 0)
                return fail("authenticated parent activation milestone did not derive the expected active proposal state");
        }
        if (height == c.drivechain_parent_state_height) {
            if (!hash(c.drivechain_parent_state_hash)) return false;
            const bool ctip = !c.drivechain_parent_state_ctip_txid.IsNull() ? state.ctip &&
                state.ctip->hash == c.drivechain_parent_state_ctip_txid && state.ctip->n == c.drivechain_parent_state_ctip_vout &&
                state.ctip_value == c.drivechain_parent_state_ctip_value : !state.ctip && state.ctip_value == 0;
            const bool proposal = post ? state.active_proposal_hash == *c.drivechain_parent_state_active_proposal_hash :
                state.active_proposal_hash.IsNull();
            if (!proposal || !ctip) return fail("authenticated parent checkpoint milestone did not derive the asserted active proposal and CTIP");
        }
        return true;
    };
    for (unsigned mode = 0; mode < 5; ++mode)
    for (unsigned flags = 0; flags < 256; ++flags)
    for (unsigned envelope = 0; envelope < 4; ++envelope) {
        auto c = Params().GetConsensus();
        const uint32_t height = mode < 3 ? 10 * (mode+1) : mode == 3 ? 42 : 10;
        c.drivechain_slot = flags & 128 ? 255 : 24;
        c.drivechain_parent_state_active_proposal_hash = uint256S("aa");
        c.drivechain_parent_state_active_proposal_description = flags & 1 ? std::vector<unsigned char>{} : std::vector<unsigned char>{1,2};
        c.drivechain_parent_state_proposal_height = 10;
        c.drivechain_parent_state_activation_height = mode == 4 ? 10 : 20;
        c.drivechain_parent_state_height = mode == 4 ? 10 : 30;
        c.drivechain_parent_state_ctip_txid = flags & 2 ? uint256{} : uint256S("bb");
        c.drivechain_parent_state_ctip_vout = flags & 128 ? UINT32_MAX : 3;
        c.drivechain_parent_state_ctip_value = flags & 128 ? MAX_MONEY : 42;
        DrivechainParentReplayState state;
        if (!(flags & 4)) state.pending_proposals.emplace(uint256S("aa"),
            DrivechainPendingProposal{flags & 8 ? height+1 : height, flags & 16 ? 1U : 0U});
        state.active_proposal_hash = flags & 32 ? uint256{} : uint256S("aa");
        if (!(flags & 4)) state.ctip = Bitcoin::COutPoint(flags & 8 ? uint256S("cc") : uint256S("bb"),
            flags & 16 ? 4 : c.drivechain_parent_state_ctip_vout);
        state.ctip_value = flags & 32 ? 0 : c.drivechain_parent_state_ctip_value;
        Bitcoin::CMutableTransaction coinbase;
        coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
        auto payload = ParseHex(mode == 1 ? "d6e1c5df" : "d5e0c4af");
        payload.push_back(*c.drivechain_slot);
        if (mode == 1) payload.insert(payload.end(), c.drivechain_parent_state_active_proposal_hash->begin(),
            c.drivechain_parent_state_active_proposal_hash->end());
        else payload.insert(payload.end(), c.drivechain_parent_state_active_proposal_description.begin(),
            c.drivechain_parent_state_active_proposal_description.end());
        CScript script;
        script << OP_RETURN;
        if (envelope == 0) script << payload;
        else {
            script.push_back(envelope == 1 ? OP_PUSHDATA1 : envelope == 2 ? OP_PUSHDATA2 : OP_PUSHDATA4);
            script.push_back(payload.size());
            for (unsigned i = 1; i < (1U << (envelope-1)); ++i) script.push_back(0);
            script.insert(script.end(), payload.begin(), payload.end());
        }
        coinbase.vout.emplace_back(0, script);
        if (flags & 64) {
            switch (flags % 4) {
            case 0: coinbase.vout.push_back(coinbase.vout.front()); break;
            case 1: coinbase.vout[0].scriptPubKey << OP_0; break;
            case 2: coinbase.vout[0].scriptPubKey.pop_back(); break;
            case 3: coinbase.vin[0].prevout = Bitcoin::COutPoint(uint256::ONE,0); break;
            }
        }
        Bitcoin::CBlock block;
        block.vtx.push_back(Bitcoin::MakeTransactionRef(coinbase));
        c.drivechain_parent_state_proposal_block_hash = block.GetHash();
        c.drivechain_parent_state_activation_block_hash = block.GetHash();
        c.drivechain_parent_state_hash = flags & 64 ? uint256S("cc") : block.GetHash();
        for (bool diagnostic : {false,true}) {
            std::string expected{"unchanged"}, actual{"unchanged"};
            const auto valid = reference(c,height,block,state,diagnostic ? &expected : nullptr);
            BOOST_CHECK_EQUAL(CheckDrivechainParentReplayMilestone(c,height,block,state,diagnostic ? &actual : nullptr),valid);
            BOOST_CHECK_EQUAL(actual,expected);
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_deadlines_preserve_short_circuit_and_exception_priority)
{
    namespace hs = drivechain::haskell;
    struct Rejection { uint32_t action; };
    struct NativeFault {};
    for (const bool circuit : {false, true}) {
        const auto kind = circuit ? hs::ReplayStoreFlow::PARENT_CIRCUIT : hs::ReplayStoreFlow::PARENT_DEADLINE;
        for (uint32_t flags = 0; flags < 64; ++flags) {
            const auto reply = [&](uint32_t step) -> uint32_t {
                if ((circuit && step == 3) || (!circuit && (step == 4 || step == 6 || step == 9))) throw Rejection{step};
                const std::vector<uint32_t> facts = circuit ? std::vector<uint32_t>{1,2} : std::vector<uint32_t>{1,2,3,5,7,8};
                const auto it = std::find(facts.begin(), facts.end(), step);
                BOOST_REQUIRE(it != facts.end());
                return (flags >> (it - facts.begin())) & 1;
            };
            std::vector<uint32_t> expected, actual;
            const auto read = [&](uint32_t step) { expected.push_back(step); return reply(step); };
            uint32_t expected_rejection{0}, actual_rejection{0};
            try {
                if (circuit) { if (read(1) && read(2)) read(3); }
                else {
                    if (read(1)) {
                        if (read(2) && read(3)) read(4);
                        if (read(5)) read(6);
                    }
                    if (read(7) && read(8)) read(9);
                }
            } catch (const Rejection& rejected) { expected_rejection = rejected.action; }
            try {
                BOOST_CHECK_EQUAL(hs::ParentReplayStore(kind, [&](uint32_t step) {
                    actual.push_back(step);
                    BOOST_CHECK(hs::ParentReplayRecord(hs::ReplayRecordKind::POSITIVE, 0, 0, 1));
                    return reply(step);
                }), 0U);
            } catch (const Rejection& rejected) { actual_rejection = rejected.action; }
            BOOST_CHECK_EQUAL(actual_rejection, expected_rejection);
            BOOST_CHECK(actual == expected);
            for (size_t fault = 0; fault < expected.size(); ++fault) {
                size_t reads{0};
                BOOST_CHECK_THROW(hs::ParentReplayStore(kind, [&](uint32_t step) -> uint32_t {
                    BOOST_CHECK_EQUAL(step, expected.at(reads));
                    if (reads++ == fault) throw NativeFault{};
                    return reply(step);
                }), NativeFault);
                BOOST_CHECK_EQUAL(reads, fault + 1);
            }
        }
    }
    BOOST_CHECK_EQUAL(drivechain::LOCKED_PARENT_DEADLINE_SECONDS, 2);
    BOOST_CHECK_EQUAL(drivechain::LOCKED_MAX_REPLAY_STEPS, 2U);
    BOOST_CHECK_EQUAL(drivechain::PARENT_RPC_BACKOFF_SECONDS, 5);
}

BOOST_AUTO_TEST_CASE(parent_rpc_generated_limits_match_original_boundaries)
{
    BOOST_CHECK_EQUAL(DEFAULT_DRIVECHAIN_SIDECHAIN_SLOT, 24);
    BOOST_CHECK_EQUAL(DEFAULT_DRIVECHAIN_PEGOUT_MAIN_FEE_SATS, 10000);
    BOOST_CHECK_EQUAL(DEFAULT_DRIVECHAIN_GRPC_ENDPOINT, "127.0.0.1:55051");
    ArgsManager defaults;
    defaults.ForceSetArg("-datadir", gArgs.GetArg("-datadir", ""));
    BOOST_CHECK_EQUAL(GetDrivechainGrpcAddress(defaults), DEFAULT_DRIVECHAIN_GRPC_ENDPOINT);
    BOOST_CHECK_EQUAL(drivechain::MAX_MAINCHAIN_RPC_RESPONSE_SIZE, 16U * 1024 * 1024);
    BOOST_CHECK_EQUAL(drivechain::MAX_MAINCHAIN_RPC_HEADER_SIZE, 64U * 1024);
    for (size_t size : {size_t{0}, size_t{65535}, size_t{65536}, size_t{65537},
        size_t{16777215}, size_t{16777216}, size_t{16777217}, std::numeric_limits<size_t>::max()}) {
        BOOST_CHECK_EQUAL(size > drivechain::MAX_MAINCHAIN_RPC_RESPONSE_SIZE, size > 16U * 1024 * 1024);
        BOOST_CHECK_EQUAL(size > drivechain::MAX_MAINCHAIN_RPC_HEADER_SIZE, size > 64U * 1024);
    }
}

BOOST_AUTO_TEST_CASE(parent_lifecycle_generated_plans_match_original_effect_sequences)
{
    for (unsigned flags = 0; flags < 4; ++flags) {
        const bool enabled = flags & 2, boundary = flags & 1;
        const auto check = [&](const auto& actual, std::vector<uint8_t> expected) {
            expected.resize(8, 0);
            BOOST_CHECK_EQUAL_COLLECTIONS(actual.begin(), actual.end(), expected.begin(), expected.end());
        };
        std::vector<uint8_t> enter, exit, admit, release;
        if (enabled) {
            enter.push_back(1);
            if (boundary) for (uint8_t step = 2; step <= 8; ++step) enter.push_back(step);
            exit = {1,2};
            if (boundary) for (uint8_t step = 3; step <= 7; ++step) exit.push_back(step);
            admit = {1};
            release = {1,2};
        }
        check(drivechain::PARENT_BUDGET_ENTER_ACTIONS[flags], enter);
        check(drivechain::PARENT_BUDGET_EXIT_ACTIONS[flags], exit);
        check(drivechain::PARENT_ADMISSION_ENTER_ACTIONS[flags], admit);
        check(drivechain::PARENT_ADMISSION_EXIT_ACTIONS[flags], release);
        check(drivechain::WITHDRAWAL_BUNDLE_RESERVE_ACTIONS[flags], {uint8_t(enabled ? 1 : boundary ? 2 : 3)});
        check(drivechain::WITHDRAWAL_BUNDLE_ABORT_ACTIONS[flags], enabled ? std::vector<uint8_t>{1} : std::vector<uint8_t>{});
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_record_rules_preserve_native_boundaries)
{
    namespace hs = drivechain::haskell;
    using Kind = hs::ReplayRecordKind;
    BOOST_CHECK_EQUAL(hs::ParentReplaySchema(0, 4, 5), 4U);
    BOOST_CHECK_EQUAL(hs::ParentReplaySchema(1, 4, 5), 5U);
    BOOST_CHECK_THROW(hs::ParentReplaySchema(2, 4, 5), std::invalid_argument);
    for (uint32_t facts = 0; facts < 8; ++facts) {
        for (int64_t amount : {int64_t{-1}, int64_t{0}, int64_t{1}, int64_t{2100000000000000}, int64_t{2100000000000001}}) {
            for (uint64_t size : {0U, 1U, 128U, 129U}) {
                const bool expected = facts == 7 && amount > 0 && amount <= 2100000000000000 && size > 0 && size <= 128;
                BOOST_CHECK_EQUAL(hs::ParentReplayRecord(Kind::DEPOSIT, facts, amount, size, 2100000000000000), expected);
            }
        }
    }
    for (uint32_t facts = 0; facts < 16; ++facts) {
        for (uint64_t parent : {0U, 1U, UINT32_MAX - 1, UINT32_MAX}) {
            for (uint64_t successor : {uint64_t{0}, parent, parent + 1}) {
                const bool expected = (facts & 1) && (facts & 2) && parent != UINT32_MAX &&
                    successor == parent + 1 && (!(facts & 4) || (facts & 8));
                BOOST_CHECK_EQUAL(hs::ParentReplayRecord(Kind::EDGE, facts, 0, parent, successor), expected);
            }
        }
    }
    BOOST_CHECK(!hs::ParentReplayRecord(Kind::WITHDRAWAL, 0));
    BOOST_CHECK(hs::ParentReplayRecord(Kind::WITHDRAWAL, 1));
    BOOST_CHECK_THROW(hs::ParentReplayRecord(Kind::WITHDRAWAL, 2), std::runtime_error);
    BOOST_CHECK_THROW(hs::ParentReplayRecord(static_cast<Kind>(UINT32_MAX), 0), std::runtime_error);
    for (const uint64_t parent : {uint64_t{0}, uint64_t{1}, uint64_t{UINT32_MAX - 1}, uint64_t{UINT32_MAX}, uint64_t{UINT32_MAX} + 1, uint64_t{UINT64_MAX}}) {
        BOOST_CHECK_EQUAL(hs::ParentReplayRecord(Kind::ADVANCEABLE_HEIGHT, 0, 0, parent), parent < UINT32_MAX);
        BOOST_CHECK_EQUAL(hs::ParentReplayRecord(Kind::POSITIVE, 0, 0, parent), parent > 0);
        for (const uint64_t child : {uint64_t{0}, parent, parent + 1, uint64_t{UINT64_MAX}}) {
            BOOST_CHECK_EQUAL(hs::ParentReplayRecord(Kind::LESS, 0, 0, parent, child), parent < child);
            BOOST_CHECK_EQUAL(hs::ParentReplayRecord(Kind::SUCCESSOR_HEIGHT, 0, 0, parent, child),
                parent < UINT32_MAX && child == parent + 1);
        }
    }
}

BOOST_AUTO_TEST_CASE(parent_replay_generated_constants_preserve_storage_contract)
{
    BOOST_CHECK_EQUAL(DrivechainParentReplayStore::SCHEMA_VERSION, 4U);
    BOOST_CHECK_EQUAL(DrivechainParentReplayStore::REPROPOSAL_SCHEMA_VERSION, 5U);
    BOOST_CHECK_EQUAL(drivechain::REPLAY_DEFAULT_HISTORY_RULE, static_cast<uint8_t>(DrivechainWithdrawalHistoryRule::UNIQUE_M6ID));
    BOOST_CHECK_EQUAL(drivechain::DRIVECHAIN_PARENT_REPLAY_DB_CACHE_BYTES, 4U << 20);
    BOOST_CHECK_EQUAL(std::string{drivechain::PARENT_REPLAY_DIRECTORY}, "parent-replay");
    const std::vector<int> actual{drivechain::DB_REPLAY_IDENTITY, drivechain::DB_REPLAY_TIP,
        drivechain::DB_REPLAY_DEPOSIT, drivechain::DB_REPLAY_BMM_EDGE,
        drivechain::DB_REPLAY_SUCCESSFUL_WITHDRAWAL, drivechain::DB_REPLAY_WITHDRAWAL_OCCURRENCE,
        static_cast<int>(DrivechainReplayStoreLoadStatus::EMPTY), static_cast<int>(DrivechainReplayStoreLoadStatus::LOADED),
        static_cast<int>(DrivechainReplayStoreLoadStatus::CORRUPT), static_cast<int>(DrivechainReplayStoreLoadStatus::IDENTITY_MISMATCH),
        static_cast<int>(DrivechainReplayStoreReadStatus::FOUND), static_cast<int>(DrivechainReplayStoreReadStatus::NOT_FOUND),
        static_cast<int>(DrivechainReplayStoreReadStatus::CORRUPT), drivechain::REPLAY_DB_MEMORY_ONLY,
        drivechain::REPLAY_DB_OBFUSCATE, drivechain::REPLAY_DB_SYNC, drivechain::REPLAY_RESET_WIPE};
    const std::vector<int> expected{'I', 'T', 'd', 'e', 'w', 'W', 0, 1, 2, 3, 0, 1, 2, 0, 0, 1, 1};
    BOOST_CHECK_EQUAL_COLLECTIONS(actual.begin(), actual.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(deposit_access_preserves_lazy_reads_and_native_faults)
{
    namespace hs = drivechain::haskell;
    using Step = hs::DepositVerifyStep;
    struct NativeFault {};
    for (uint32_t start : {67U, 72U, 77U}) {
        const auto run = [&](const std::function<bool(Step)>& action) {
            if (start == 67) return hs::RunCheckpointLookup(action);
            if (start == 72) return hs::RunLegacyClaim(action);
            return hs::RunCtipRead(action);
        };
        for (uint32_t mask = 0; mask < 32; ++mask) {
            const auto passed = [&](uint32_t step) { return (mask & (1U << (step - start - 1))) != 0; };
            std::vector<uint32_t> expected;
            bool accepted{false};
            if (start == 77) {
                expected.push_back(78);
                if (passed(78)) {
                    expected.push_back(79);
                    accepted = passed(79);
                    if (accepted) {
                        expected.push_back(82);
                        accepted = passed(82);
                    } else {
                        expected.push_back(80);
                        if (passed(80)) { expected.push_back(81); accepted = passed(81); }
                    }
                }
            } else {
                for (uint32_t step = start + 1; step <= start + 4; ++step) {
                    expected.push_back(step);
                    accepted = passed(step);
                    if (!accepted) break;
                }
            }
            std::vector<uint32_t> actual;
            BOOST_CHECK_EQUAL(run([&](Step step) {
                const auto index = static_cast<uint32_t>(step);
                actual.push_back(index);
                BOOST_CHECK_EQUAL(hs::WithdrawalStatus(0, "submitted"), 1);
                return passed(index);
            }), accepted);
            BOOST_CHECK(actual == expected);
            for (size_t fault = 0; fault < expected.size(); ++fault) {
                size_t reads{0};
                BOOST_CHECK_THROW(run([&](Step step) {
                    BOOST_CHECK_EQUAL(static_cast<uint32_t>(step), expected.at(reads));
                    if (reads++ == fault) throw NativeFault{};
                    return passed(static_cast<uint32_t>(step));
                }), NativeFault);
                BOOST_CHECK_EQUAL(reads, fault + 1);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(event_identities_preserve_native_integer_formatting)
{
    namespace haskell = drivechain::haskell;
    using Kind = haskell::EventIdentityKind;
    const std::string hash(64, 'a');
    for (const uint64_t number : {uint64_t{0}, uint64_t{1}, uint64_t{INT64_MAX}, uint64_t{1} << 63, UINT64_MAX}) {
        const auto signed_number = std::to_string(static_cast<int64_t>(number));
        const auto unsigned_number = std::to_string(number);
        BOOST_CHECK_EQUAL(haskell::EventIdentity(Kind::BUNDLE, hash, number), "sidechain:bundle:" + hash + ":" + signed_number);
        BOOST_CHECK_EQUAL(haskell::EventIdentity(Kind::DEPOSIT, hash, number), "sidechain:deposit:" + hash + ":" + unsigned_number);
        BOOST_CHECK_EQUAL(haskell::EventIdentity(Kind::WITHDRAWAL, hash, number), "sidechain:withdrawal:" + hash + ":" + unsigned_number);
        BOOST_CHECK_EQUAL(haskell::EventIdentity(Kind::L1_DEPOSIT, hash, number), "l1:deposit:" + hash + ":" + signed_number);
        const std::array<std::string, 3> names{"submitted", "succeeded", "failed"};
        for (uint32_t status = 0; status < names.size(); ++status)
            BOOST_CHECK_EQUAL(haskell::EventIdentity(Kind::L1_WITHDRAWAL, hash, number, status),
                "l1:withdrawal:" + hash + ":" + names[status] + ":" + signed_number);
    }
    BOOST_CHECK_THROW(haskell::EventIdentity(Kind::L1_WITHDRAWAL, hash, 0, 3), std::runtime_error);
    BOOST_CHECK_THROW(haskell::EventIdentity(static_cast<Kind>(5), hash, 0), std::runtime_error);
    BOOST_CHECK_THROW(haskell::EventIdentity(Kind::BUNDLE, std::string(65, 'a'), 0), std::length_error);
}

BOOST_AUTO_TEST_CASE(event_layout_preserves_fields_and_native_callback_boundaries)
{
    namespace hs = drivechain::haskell;
    using Kind = hs::EventLayoutKind;
    const std::array<std::string, 18> layouts{{
        "event_id source=sidechain kind=bundle_commitment status=sidechain_committed m6id sidechain",
        "event_id source=sidechain kind=deposit status=sidechain_confirmed sidechain_txid vin mainchain_txid mainchain_vout value_sats asset claim_script sidechain",
        "event_id source=sidechain kind=withdrawal status=sidechain_confirmed sidechain_txid vout value_sats asset mainchain_genesis_hash mainchain_script",
        "event_id source=l1 kind=deposit status=l1_confirmed sidechain_id sequence_number mainchain_txid mainchain_vout address_hex value_sats",
        "event_id source=l1 kind=withdrawal_bundle status=",
        "m6id", "sidechain", "sequence_number", "mainchain_transaction", "acknowledgement=",
        "l1", "block_hash height", "block_hash", "height", "timestamp",
        "sidechainId valueSats height criticalHash prevBytes", "hex", "sidechainId endBlockHash",
    }};
    const std::array<std::string, 3> statuses{{"submitted", "succeeded", "failed"}};
    const std::array<std::string, 3> acknowledgements{{"pending", "accepted", "rejected"}};
    struct NativeFault {};
    for (uint32_t kind = 0; kind < layouts.size(); ++kind) {
        for (uint32_t status = 0; status < statuses.size(); ++status) {
            auto expected = layouts[kind];
            if (kind == 4) expected += statuses[status] + " sidechain_id m6id";
            if (kind == 9) expected += acknowledgements[status];
            std::vector<std::string> fields;
            hs::EventFields(static_cast<Kind>(kind), status,
                [&](uint32_t index, std::string_view key, std::optional<std::string_view> literal) {
                    BOOST_CHECK_EQUAL(index, fields.size());
                    // Native work may itself invoke another Haskell operation.
                    BOOST_CHECK_EQUAL(hs::EventIdentity(hs::EventIdentityKind::DEPOSIT, "aa", index),
                        "sidechain:deposit:aa:" + std::to_string(index));
                    fields.push_back(std::string(key) + (literal ? "=" + std::string(*literal) : ""));
                });
            std::string actual;
            for (const auto& field : fields) actual += (actual.empty() ? "" : " ") + field;
            BOOST_CHECK_EQUAL(actual, expected);
            for (size_t fault = 0; fault < fields.size(); ++fault) {
                size_t reads = 0;
                BOOST_CHECK_THROW(hs::EventFields(static_cast<Kind>(kind), status,
                    [&](uint32_t index, std::string_view key, std::optional<std::string_view> literal) {
                        BOOST_CHECK_EQUAL(index, reads++);
                        BOOST_CHECK_EQUAL(std::string(key) + (literal ? "=" + std::string(*literal) : ""), fields[index]);
                        if (index == fault) throw NativeFault{};
                    }), NativeFault);
                BOOST_CHECK_EQUAL(reads, fault + 1);
            }
        }
    }
    const auto unexpected = [](uint32_t, std::string_view, std::optional<std::string_view>) { BOOST_FAIL("invalid layout published a field"); };
    BOOST_CHECK_THROW(hs::EventFields(static_cast<Kind>(18), 0, unexpected), std::runtime_error);
    BOOST_CHECK_THROW(hs::EventFields(Kind::L1_WITHDRAWAL, 3, unexpected), std::runtime_error);
    BOOST_CHECK_THROW(hs::EventFields(Kind::ACKNOWLEDGEMENT, 3, unexpected), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(extracts_consensus_anchored_sidechain_events)
{
    const uint256 mainchain_txid = uint256S("01");
    CMutableTransaction deposit;
    deposit.version = 2;
    CTxIn deposit_input(COutPoint(Txid::FromUint256(mainchain_txid), 0));
    deposit_input.m_is_pegin = true;
    deposit.vin.push_back(deposit_input);
    deposit.vout.emplace_back(Params().GetConsensus().pegged_asset, 99'000, CScript() << OP_TRUE);
    deposit.vout.emplace_back(Params().GetConsensus().pegged_asset, 1'000, CScript());
    deposit.witness.vtxinwit.resize(1);
    deposit.witness.vtxoutwit.resize(2);
    deposit.witness.vtxinwit[0].m_pegin_witness = CreateDrivechainDepositPeginWitness(
        100'000,
        Params().GetConsensus().pegged_asset,
        Params().ParentGenesisBlockHash(),
        CScript() << OP_TRUE,
        mainchain_txid);

    CMutableTransaction withdrawal;
    withdrawal.version = 2;
    const CScript destination = CScript() << OP_TRUE;
    const CScript pegout = CScript()
        << OP_RETURN
        << std::vector<unsigned char>(Params().ParentGenesisBlockHash().begin(), Params().ParentGenesisBlockHash().end())
        << std::vector<unsigned char>(destination.begin(), destination.end());
    withdrawal.vout.emplace_back(Params().GetConsensus().pegged_asset, 25'000, pegout);

    CBlock block;
    block.nVersion = 1;
    block.vtx = {MakeTransactionRef(deposit), MakeTransactionRef(withdrawal)};
    block.hashMerkleRoot = BlockMerkleRoot(block);
    block.hashWithdrawalBundle = uint256S("02");

    const UniValue events = drivechain::ExtractSidechainPegEvents(block, 7, uint256::ZERO);
    BOOST_REQUIRE_EQUAL(events.size(), 3U);
    BOOST_CHECK_EQUAL(events[0]["kind"].get_str(), "bundle_commitment");
    BOOST_CHECK_EQUAL(events[1]["kind"].get_str(), "deposit");
    BOOST_CHECK_EQUAL(events[1]["value_sats"].getInt<int64_t>(), 100'000);
    BOOST_CHECK_EQUAL(events[2]["kind"].get_str(), "withdrawal");
    BOOST_CHECK_EQUAL(events[2]["value_sats"].getInt<int64_t>(), 25'000);

    const auto block_hash = block.GetHash().GetHex();
    const auto bundle_hash = block.hashWithdrawalBundle.GetHex();
    const auto deposit_hash = block.vtx[0]->GetHash().GetHex();
    const auto withdrawal_hash = block.vtx[1]->GetHash().GetHex();
    const auto asset = Params().GetConsensus().pegged_asset.GetHex();
    const auto location = "{\"block_hash\":\"" + block_hash + "\",\"height\":7}";
    const auto expected = ParseJson(
        "[{\"event_id\":\"sidechain:bundle:" + bundle_hash + ":7\",\"source\":\"sidechain\",\"kind\":\"bundle_commitment\",\"status\":\"sidechain_committed\",\"m6id\":\"" + bundle_hash + "\",\"sidechain\":" + location + "},"
        "{\"event_id\":\"sidechain:deposit:" + deposit_hash + ":0\",\"source\":\"sidechain\",\"kind\":\"deposit\",\"status\":\"sidechain_confirmed\",\"sidechain_txid\":\"" + deposit_hash + "\",\"vin\":0,\"mainchain_txid\":\"" + mainchain_txid.GetHex() + "\",\"mainchain_vout\":0,\"value_sats\":100000,\"asset\":\"" + asset + "\",\"claim_script\":\"51\",\"sidechain\":" + location + "},"
        "{\"event_id\":\"sidechain:withdrawal:" + withdrawal_hash + ":0\",\"source\":\"sidechain\",\"kind\":\"withdrawal\",\"status\":\"sidechain_confirmed\",\"sidechain_txid\":\"" + withdrawal_hash + "\",\"vout\":0,\"value_sats\":25000,\"asset\":\"" + asset + "\",\"mainchain_genesis_hash\":\"" + Params().ParentGenesisBlockHash().GetHex() + "\",\"mainchain_script\":\"51\",\"m6id\":\"" + bundle_hash + "\",\"sidechain\":" + location + "}]");
    BOOST_CHECK_EQUAL(events.write(), expected.write());

    const UniValue repeated_bundle = drivechain::ExtractSidechainPegEvents(block, 7, block.hashWithdrawalBundle);
    BOOST_REQUIRE_EQUAL(repeated_bundle.size(), 2U);
    BOOST_CHECK_EQUAL(repeated_bundle[0]["event_id"].get_str(), events[1]["event_id"].get_str());

    CBlock replacement = block;
    replacement.vtx = {MakeTransactionRef(withdrawal)};
    replacement.hashMerkleRoot = BlockMerkleRoot(replacement);
    replacement.hashWithdrawalBundle.SetNull();
    const UniValue replacement_events = drivechain::ExtractSidechainPegEvents(replacement, 7, uint256::ZERO);
    BOOST_REQUIRE_EQUAL(replacement_events.size(), 1U);
    BOOST_CHECK_EQUAL(replacement_events[0]["kind"].get_str(), "withdrawal");
    BOOST_CHECK(replacement_events[0]["event_id"].get_str() != events[1]["event_id"].get_str());

    const std::array batches{events,UniValue(UniValue::VARR),repeated_bundle,replacement_events};
    for (size_t stop=0; stop<=batches.size(); ++stop) {
        UniValue reference(UniValue::VARR), combined(UniValue::VARR);
        for (size_t i=0; i<stop; ++i)
            for (const auto& event : batches[i].getValues()) reference.push_back(event);
        size_t visited{0};
        const auto append = [&] {
            return drivechain::haskell::ParentReplayEach(batches,[&](const UniValue& batch) {
                if (visited++ == stop) throw std::runtime_error("event batch unavailable");
                combined.push_backV(batch.getValues());
                return true;
            });
        };
        if (stop<batches.size()) BOOST_CHECK_THROW(append(),std::runtime_error);
        else BOOST_CHECK(append());
        BOOST_CHECK_EQUAL(visited,std::min(stop+1,batches.size()));
        BOOST_CHECK_EQUAL(combined.write(),reference.write());
    }

    deposit.vin.push_back(deposit_input);
    deposit.vin.push_back(deposit_input);
    deposit.witness.vtxinwit.resize(2); // One malformed witness, then one missing witness.
    withdrawal.vout.emplace_back(CAsset(uint256S("ff")), 12'000, pegout);
    withdrawal.vout.emplace_back(Params().GetConsensus().pegged_asset, 13'000, pegout);
    block.vtx = {MakeTransactionRef(deposit), MakeTransactionRef(withdrawal)};
    block.hashMerkleRoot = BlockMerkleRoot(block);
    const UniValue guarded = drivechain::ExtractSidechainPegEvents(block, 8, uint256::ZERO);
    BOOST_REQUIRE_EQUAL(guarded.size(), 4U);
    BOOST_CHECK_EQUAL(guarded[1]["kind"].get_str(), "deposit");
    BOOST_CHECK_EQUAL(guarded[1]["vin"].getInt<int>(), 0);
    BOOST_CHECK_EQUAL(guarded[2]["vout"].getInt<int>(), 0);
    BOOST_CHECK_EQUAL(guarded[2]["value_sats"].getInt<int64_t>(), 25'000);
    BOOST_CHECK_EQUAL(guarded[3]["vout"].getInt<int>(), 2);
    BOOST_CHECK_EQUAL(guarded[3]["value_sats"].getInt<int64_t>(), 13'000);
}

BOOST_AUTO_TEST_CASE(restores_active_bundle_after_restart)
{
    const uint256 bundle_hash = uint256S("03");
    node::RestoreCurrentDrivechainWithdrawalBundleHash(bundle_hash);
    BOOST_CHECK(node::GetCurrentDrivechainWithdrawalBundleHash() == bundle_hash);
    node::RestoreCurrentDrivechainWithdrawalBundleHash(uint256::ZERO);
}

BOOST_AUTO_TEST_CASE(authenticates_exact_deposit_and_transaction)
{
    drivechain::AuthenticatedDeposit authenticated;
    std::string error;
    BOOST_REQUIRE_MESSAGE(Authenticate(authenticated, error), error);
    BOOST_CHECK(authenticated.outpoint == COutPoint(Txid::FromUint256(uint256S(DEPOSIT_TXID)), 0));
    BOOST_CHECK_EQUAL(authenticated.value, 2000);
    BOOST_CHECK_EQUAL(authenticated.sequence_number, 8);
    BOOST_CHECK_EQUAL(authenticated.address, TestDepositAddress());
    BOOST_CHECK(authenticated.current_ctip == authenticated.outpoint);

    const UniValue header = ParseJson(strprintf(
        R"json({"hash":"%s","height":90,"confirmations":11})json",
        DEPOSIT_BLOCK));
    BOOST_CHECK_MESSAGE(drivechain::VerifyDepositBlockConfirmation(header, authenticated, error), error);
    BOOST_CHECK_MESSAGE(
        drivechain::VerifyCurrentCtipOutput(
            ParseJson(R"json({"value":0.14402000,"confirmations":2})json"),
            authenticated,
            error),
        error);

    const CTransaction tx(DepositTransaction(authenticated, authenticated.destination_script));
    BOOST_CHECK_MESSAGE(drivechain::VerifyDepositTransaction(tx, 0, authenticated, error), error);
}

BOOST_AUTO_TEST_CASE(authenticated_deposit_ffi_preserves_rejections_and_error_priority)
{
    drivechain::AuthenticatedDeposit authenticated;
    std::string error;
    BOOST_REQUIRE_MESSAGE(Authenticate(authenticated, error), error);
    const auto valid = DepositTransaction(authenticated, authenticated.destination_script);
    const auto reject = [&](const CMutableTransaction& changed, size_t index, const std::string& expected) {
        error.clear();
        BOOST_CHECK(!drivechain::VerifyDepositTransaction(CTransaction(changed), index, authenticated, error));
        BOOST_CHECK_EQUAL(error, expected);
    };
    reject(valid, std::numeric_limits<size_t>::max(), "drivechain deposit transaction must contain exactly one input");
    for (int mutation = 0; mutation < 17; ++mutation) {
        auto changed = valid;
        std::string expected;
        switch (mutation) {
        case 0: changed.vin.clear(); changed.witness.vtxinwit.clear(); expected = "exactly one input"; break;
        case 1: changed.vin.push_back(changed.vin[0]); expected = "exactly one input"; break;
        case 2: changed.witness.vtxinwit.clear(); expected = "witness count"; break;
        case 3: changed.vin[0].m_is_pegin = false; expected = "authenticated outpoint"; break;
        case 4: changed.vin[0].prevout.n++; expected = "authenticated outpoint"; break;
        case 5: changed.vin[0].scriptSig << OP_TRUE; expected = "authenticated outpoint"; break;
        case 6: changed.vin[0].assetIssuance.nAmount = CConfidentialValue(1); expected = "authenticated outpoint"; break;
        case 7: changed.witness.vtxinwit[0].m_pegin_witness.stack[0][0] ^= 1; expected = "authenticated deposit"; break;
        case 8: changed.witness.vtxinwit[0].m_pegin_witness.stack[3] = {OP_FALSE}; expected = "authenticated deposit"; break;
        case 9: changed.witness.vtxinwit[0].m_pegin_witness.stack[5][0] ^= 1; expected = "authenticated deposit"; break;
        case 10: changed.vout.clear(); changed.witness.vtxoutwit.clear(); expected = "one credit output"; break;
        case 11: changed.vout.push_back(changed.vout[1]); expected = "one credit output"; break;
        case 12: changed.vout[0].nAsset.vchCommitment.assign(33, 0x0a); expected = "explicit native asset"; break;
        case 13: changed.vout[0].nValue.vchCommitment.assign(33, 0x08); expected = "explicit native asset"; break;
        case 14: changed.vout[0].nNonce.vchCommitment.assign(33, 0x02); expected = "explicit native asset"; break;
        case 15: changed.vout[1] = changed.vout[0]; expected = "value and fee"; break;
        case 16: changed.vout[0].nValue = CConfidentialValue(std::numeric_limits<int64_t>::max()); expected = "value and fee"; break;
        }
        BOOST_CHECK(!drivechain::VerifyDepositTransaction(CTransaction(changed), 0, authenticated, error));
        BOOST_CHECK_MESSAGE(error.find(expected) != std::string::npos, error);
    }
    auto changed = valid;
    changed.vout[0].scriptPubKey = CScript() << OP_FALSE;
    changed.vout[1].nValue.vchCommitment.assign(33, 0x08);
    reject(changed, 0, "drivechain deposit destination script does not match enforcer data");
    std::swap(changed.vout[0], changed.vout[1]);
    reject(changed, 0, "drivechain deposit outputs must use explicit native asset values");
    changed = valid;
    std::swap(changed.vout[0], changed.vout[1]);
    BOOST_CHECK_MESSAGE(drivechain::VerifyDepositTransaction(CTransaction(changed), 0, authenticated, error), error);
    const CTransaction no_fee(DepositTransaction(authenticated, authenticated.destination_script, authenticated.value, 0));
    BOOST_CHECK_MESSAGE(drivechain::VerifyDepositTransaction(no_fee, 0, authenticated, error), error);
}

BOOST_AUTO_TEST_CASE(authenticates_nonzero_deposit_vout)
{
    drivechain::AuthenticatedDeposit authenticated;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        Authenticate(
            authenticated,
            error,
            MainchainInfo(),
            EnforcerChainInfo(),
            EnforcerTip(),
            Sidechains(),
            TwoWayPegData(DEPOSIT_TXID, 7),
            Ctip(DEPOSIT_TXID, 14'402'000, 8, 7),
            Params().NetworkIDString(),
            Identity(),
            COutPoint(Txid::FromUint256(uint256S(DEPOSIT_TXID)), 7),
            2000),
        error);
    BOOST_CHECK(authenticated.outpoint == COutPoint(Txid::FromUint256(uint256S(DEPOSIT_TXID)), 7));
    BOOST_CHECK(authenticated.current_ctip == authenticated.outpoint);
}

BOOST_AUTO_TEST_CASE(withdrawal_bundle_is_confirmation_bound)
{
    const CScript payout_script = CScript() << OP_TRUE;
    const COutPoint withdrawal_outpoint(Txid::FromUint256(uint256S("11")), 3);
    const uint256 genesis = uint256S("22");
    const uint256 previous = uint256S("33");
    const uint256 exchange_root = uint256S("44");

    const wallet::DrivechainWithdrawalBundle first =
        wallet::BuildDrivechainWithdrawalBundle(
            100'000, 1'000, payout_script, withdrawal_outpoint,
            50, genesis, previous, exchange_root);
    const wallet::DrivechainWithdrawalBundle same =
        wallet::BuildDrivechainWithdrawalBundle(
            100'000, 1'000, payout_script, withdrawal_outpoint,
            50, genesis, previous, exchange_root);
    const wallet::DrivechainWithdrawalBundle moved_height =
        wallet::BuildDrivechainWithdrawalBundle(
            100'000, 1'000, payout_script, withdrawal_outpoint,
            51, genesis, previous, exchange_root);

    BOOST_CHECK(!first.bytes.empty());
    BOOST_CHECK(!first.m6id.IsNull());
    BOOST_CHECK(first.bytes == same.bytes);
    BOOST_CHECK(first.m6id == same.m6id);
    BOOST_CHECK(first.bytes != moved_height.bytes);
    BOOST_CHECK(first.m6id != moved_height.m6id);

    // Independent fixed vector: preserves the original inputless codec and
    // ECX tagged-hash bytes while reusing the upstream transaction serializer.
    BOOST_CHECK_EQUAL(HexStr(first.no_witness_bytes),
        "02000000000400000000000000000a6a0800000000000003e8"
        "0000000000000000226a20b082a80c8313dddcada453a1b9c33576f4cfa590b5bcc7d22014dbff28c3b79f"
        "b88201000000000001510000000000000000276a255058535401"
        "7cf36ebee8f4244cef45c66f4adc027076916867e262c3c763a2e66a73df0ca800000000");
    BOOST_CHECK_EQUAL(first.m6id.GetHex(), "84e3552a4944266891be14858c43ecc9790cd2b5745f1db3aa535e071362e625");
    auto transported = first.no_witness_bytes;
    transported.insert(transported.begin() + 4, {0, 1});
    BOOST_CHECK(first.bytes == transported);
}

BOOST_AUTO_TEST_CASE(withdrawal_inputs_commitment_boundaries)
{
    const CScript payout = CScript() << OP_TRUE;
    for (const auto& txid : {uint256{}, uint256S("11"), uint256S(std::string(64,'f'))})
    for (const uint32_t index : {0U, 1U, 255U, 256U, UINT32_MAX})
    for (const uint32_t height : {0U, 1U, 255U, 256U, 65536U, UINT32_MAX})
    for (const bool anchored : {false,true}) {
        const COutPoint outpoint{Txid::FromUint256(txid),index};
        const auto build = [&] {
            return anchored ? wallet::BuildDrivechainWithdrawalBundle(1000,1,payout,outpoint,height,
                uint256S("22"),uint256S("33"),uint256S("44")) :
                wallet::BuildDrivechainWithdrawalBundle(1000,1,payout,outpoint,height);
        };
        if (outpoint.IsNull()) {
            BOOST_CHECK_THROW(build(),std::invalid_argument);
            continue;
        }
        const auto bundle = build();
        const std::vector<COutPoint> inputs{outpoint,COutPoint{Txid{},height}};
        const auto expected = (HashWriter{} << inputs).GetHash();
        DataStream bytes{bundle.no_witness_bytes};
        Sidechain::Bitcoin::CMutableTransaction tx;
        bytes >> TX_NO_WITNESS(tx);
        BOOST_REQUIRE_EQUAL(tx.vout.size(),anchored ? 4U : 3U);
        BOOST_CHECK(tx.vout[1].scriptPubKey == (CScript() << OP_RETURN << ToByteVector(expected)));
        BOOST_CHECK_EQUAL(tx.vout[1].nValue,0);
        BOOST_CHECK(bytes.empty());
        BOOST_CHECK(tx.GetHash()==bundle.m6id);
    }
}

BOOST_AUTO_TEST_CASE(withdrawal_anchor_payload_preserves_all_commitments)
{
    for (const uint32_t height : {0U, 1U, 255U, 256U, 65536U, UINT32_MAX}) {
        for (const unsigned int zero_field : {0U, 1U, 2U, 3U, 4U}) {
            std::array<uint256, 4> fields{uint256S("11"), uint256S("22"), uint256S("33"), uint256S("44")};
            if (zero_field < fields.size()) fields[zero_field].SetNull();
            std::vector<unsigned char> expected{1,24};
            expected.insert(expected.end(), fields[0].begin(), fields[0].end());
            for (const int shift : {24,16,8,0}) expected.push_back(height >> shift);
            for (size_t i = 1; i < fields.size(); ++i)
                expected.insert(expected.end(), fields[i].begin(), fields[i].end());
            BOOST_CHECK(drivechain::haskell::WithdrawalAnchorPayload(height,
                {fields[0].begin(), fields[1].begin(), fields[2].begin(), fields[3].begin()}) == expected);
        }
    }
}

BOOST_AUTO_TEST_CASE(withdrawal_codec_uses_bitcoin_serialization)
{
    for (const size_t size : {1U, 252U, 253U, 254U, 10000U}) {
        const std::vector<unsigned char> script_bytes(size, OP_TRUE);
        const CScript script(script_bytes.begin(), script_bytes.end());
        const auto bundle = wallet::BuildDrivechainWithdrawalBundle(
            100'000, 1'000, script, COutPoint(Txid::FromUint256(uint256S("11")), 3), 50);
        DataStream bytes{bundle.no_witness_bytes};
        Sidechain::Bitcoin::CMutableTransaction tx;
        bytes >> TX_NO_WITNESS(tx);
        BOOST_CHECK(bytes.empty());
        BOOST_CHECK(tx.vin.empty());
        BOOST_REQUIRE_EQUAL(tx.vout.size(), 3U);
        BOOST_CHECK_EQUAL(tx.version, 2U);
        BOOST_CHECK_EQUAL(tx.nLockTime, 0U);
        BOOST_CHECK_EQUAL(tx.vout[2].nValue, 99'000);
        BOOST_CHECK(tx.vout[2].scriptPubKey == script);
        BOOST_CHECK(tx.GetHash() == bundle.m6id);
    }
    BOOST_CHECK_THROW(wallet::BuildDrivechainWithdrawalBundle(
        1000, 1000, CScript() << OP_TRUE,
        COutPoint(Txid::FromUint256(uint256S("11")), 3), 50), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(withdrawal_marker_admission_preserves_error_precedence)
{
    const COutPoint outpoint(Txid::FromUint256(uint256S("11")), 3);
    const uint256 nonzero = uint256S("22");
    const auto marker_error = [](const UniValue& error) {
        return error["code"].getInt<int>() == -1 && error["message"].get_str() ==
            "Cannot create PXST marker with a null consensus commitment";
    };
    for (const bool null_genesis : {false, true}) {
        for (const bool null_root : {false, true}) {
            for (const CAmount amount : {int64_t{0}, int64_t{100000}}) {
                const auto build = [&] {
                    return wallet::BuildDrivechainWithdrawalBundle(amount, 1000, CScript() << OP_TRUE,
                        outpoint, 50, null_genesis ? uint256{} : nonzero, uint256{},
                        null_root ? uint256{} : nonzero);
                };
                if (null_genesis || null_root) BOOST_CHECK_EXCEPTION(build(), UniValue, marker_error);
                else if (!amount) BOOST_CHECK_THROW(build(), std::invalid_argument);
                else BOOST_CHECK(!build().bytes.empty());
            }
        }
    }
    std::array<uint256,4> fields{nonzero, uint256{}, nonzero, nonzero};
    BOOST_CHECK_NO_THROW(drivechain::haskell::WithdrawalAnchorPayload(0,
        {fields[0].begin(),fields[1].begin(),fields[2].begin(),fields[3].begin()}, true));
    fields[2].SetNull();
    BOOST_CHECK_THROW(drivechain::haskell::WithdrawalAnchorPayload(0,
        {fields[0].begin(),fields[1].begin(),fields[2].begin(),fields[3].begin()}, true), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(haskell_wallet_anchor_workflow)
{
    std::array<unsigned char,40> context{};
    std::array<unsigned char,96> anchor{};
    context[0]=0x11; WriteLE32(context.data()+32,3); WriteLE32(context.data()+36,50);
    anchor[0]=0x22; anchor[32]=0x33; anchor[64]=0x44;
    const std::vector<unsigned char> serialized{2,0,0,0,7,8,9,0};
    unsigned calls{0};
    const auto construct=[&](const drivechain::haskell::WithdrawalBundlePlan& plan) -> const std::vector<unsigned char>& {
        ++calls;
        BOOST_CHECK_EQUAL(plan.payout,99'000);
        BOOST_CHECK_EQUAL(plan.version,2);
        BOOST_CHECK(plan.outputs == std::vector<unsigned char>({0,1,2,3}));
        BOOST_REQUIRE_EQUAL(plan.marker.size(),39U);
        BOOST_CHECK_EQUAL(HexStr(plan.marker),"6a2550585354017cf36ebee8f4244cef45c66f4adc027076916867e262c3c763a2e66a73df0ca8");
        BOOST_REQUIRE_EQUAL(plan.inputs.size(),73U);
        return serialized;
    };
    auto expected=serialized; expected.insert(expected.begin()+4,{0,1});
    BOOST_CHECK(drivechain::haskell::BuildWithdrawalBundle(100'000,1'000,1,true,construct,context,anchor)==expected);
    BOOST_CHECK_EQUAL(calls,1U);
    for (const size_t size : {1U,95U,97U}) {
        const std::vector<unsigned char> malformed(size,0);
        BOOST_CHECK_THROW(drivechain::haskell::BuildWithdrawalBundle(100'000,1'000,1,true,construct,context,malformed),std::invalid_argument);
    }
    BOOST_CHECK_THROW(drivechain::haskell::BuildWithdrawalBundle(100'000,1'000,1,true,construct,{},anchor),std::invalid_argument);
    const auto failure=[&](const auto&) -> const std::vector<unsigned char>& { ++calls; throw std::runtime_error("constructor fault"); };
    BOOST_CHECK_EXCEPTION(drivechain::haskell::BuildWithdrawalBundle(100'000,1'000,1,true,failure,context,anchor),std::runtime_error,
        [](const std::runtime_error& error) { return std::string(error.what())=="constructor fault"; });
    BOOST_CHECK_EQUAL(calls,2U);
    anchor[0]=0;
    BOOST_CHECK_EXCEPTION(drivechain::haskell::BuildWithdrawalBundle(0,1'000,1,true,construct,context,anchor),drivechain::haskell::WithdrawalAnchorError,
        [](const auto& error) { return std::string(error.what())=="Cannot create PXST marker with a null consensus commitment"; });
    BOOST_CHECK_EQUAL(calls,2U);
}

BOOST_AUTO_TEST_CASE(retired_withdrawal_bundle_flow_rejects_without_effects)
{
    unsigned calls{0};
    BOOST_CHECK_THROW(drivechain::haskell::ParentReplayStore(
        drivechain::haskell::ReplayStoreFlow::WITHDRAWAL_BUNDLE,
        [&](uint32_t) -> uint32_t { ++calls; return 1; }),std::runtime_error);
    BOOST_CHECK_EQUAL(calls,0);
    BOOST_CHECK_THROW(drivechain::haskell::WithdrawalTransport(std::vector<unsigned char>{1,2,3}), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(native_withdrawal_submission_effect_order)
{
    namespace hs = drivechain::haskell;
    for (unsigned flags=0; flags<8; ++flags) {
        const bool present=flags&1, transaction=flags&2, verbose=flags&4;
        std::vector<uint32_t> expected{1,2,3};
        if (!present) expected.push_back(5);
        else {
            expected.push_back(4);
            if (!transaction) expected.push_back(5);
            else {
                expected.insert(expected.end(), {6,7});
                if (verbose) expected.push_back(8);
            }
        }
        for (size_t fail=0; fail<=expected.size(); ++fail) {
            std::vector<uint32_t> actual;
            unsigned sends{0};
            try {
                const auto result = hs::ParentReplayStore(hs::ReplayStoreFlow::NATIVE_WITHDRAWAL_SUBMISSION,
                    [&](uint32_t step) -> uint32_t {
                    actual.push_back(step);
                    if (step==1) ++sends;
                    if (actual.size()==fail+1) throw std::runtime_error("injected");
                    switch (step) {
                    case 1: case 2: return 1;
                    case 3: return present;
                    case 4: BOOST_REQUIRE(present); return transaction;
                    case 5: throw std::runtime_error("missing committed transaction");
                    case 6: BOOST_REQUIRE(present && transaction); return 1;
                    case 7: return verbose;
                    case 8: BOOST_REQUIRE(verbose); return 1;
                    default: throw std::logic_error("invalid submission action");
                    }
                });
                BOOST_CHECK(fail==expected.size() && present && transaction);
                BOOST_CHECK_EQUAL(result,unsigned{verbose});
            } catch (const std::runtime_error&) {
                BOOST_CHECK(fail<expected.size() || !present || !transaction);
            }
            BOOST_CHECK_EQUAL(sends,1U);
            const auto size=std::min(fail+1,expected.size());
            BOOST_CHECK_EQUAL_COLLECTIONS(actual.begin(),actual.end(),expected.begin(),expected.begin()+size);
        }
    }
}

BOOST_AUTO_TEST_CASE(withdrawal_preflight_effect_order)
{
    namespace hs = drivechain::haskell;
    const std::array<uint32_t,9> order{1,9,10,3,4,6,7,11,12};
    const std::array<uint32_t,9> errors{2,2,2,0,5,5,8,8,8};
    for (unsigned flags=0; flags<512; ++flags) {
        const bool accepted=flags==511;
        std::vector<uint32_t> expected;
        for (size_t index=0; index<order.size(); ++index) {
            expected.push_back(order[index]);
            if (!(flags & (1U << index))) {
                if (errors[index]) expected.push_back(errors[index]);
                break;
            }
        }
        for (size_t fail=0; fail<=expected.size(); ++fail) {
            std::vector<uint32_t> actual;
            try {
                const auto result = hs::ParentReplayStore(hs::ReplayStoreFlow::WITHDRAWAL_PREFLIGHT,
                    [&](uint32_t step) -> uint32_t {
                    actual.push_back(step);
                    if (actual.size()==fail+1) throw std::runtime_error("injected");
                    const auto found = std::find(order.begin(),order.end(),step);
                    if (found==order.end()) throw std::runtime_error("preflight rejected");
                    const auto index = std::distance(order.begin(),found);
                    BOOST_CHECK_EQUAL(flags & ((1U << index)-1), (1U << index)-1);
                    const bool reply = flags & (1U << index);
                    if (step==3 && !reply) throw std::runtime_error("fee rejected");
                    return reply;
                });
                BOOST_CHECK_EQUAL(result,1U);
                BOOST_CHECK(fail==expected.size() && accepted);
            } catch (const std::runtime_error&) {
                BOOST_CHECK(fail<expected.size() || !accepted);
            }
            const auto size=std::min(fail+1,expected.size());
            BOOST_CHECK_EQUAL_COLLECTIONS(actual.begin(),actual.end(),expected.begin(),expected.begin()+size);
        }
    }
}

BOOST_AUTO_TEST_CASE(default_wallet_load_create_order)
{
    namespace hs = drivechain::haskell;
    using wallet::DatabaseStatus;
    const std::array statuses{DatabaseStatus::SUCCESS,DatabaseStatus::FAILED_BAD_PATH,
        DatabaseStatus::FAILED_BAD_FORMAT,DatabaseStatus::FAILED_ALREADY_LOADED,
        DatabaseStatus::FAILED_ALREADY_EXISTS,DatabaseStatus::FAILED_NOT_FOUND,
        DatabaseStatus::FAILED_CREATE,DatabaseStatus::FAILED_LOAD,DatabaseStatus::FAILED_VERIFY,
        DatabaseStatus::FAILED_ENCRYPT,DatabaseStatus::FAILED_INVALID_BACKUP_FILE};
    for (auto status : statuses) for (bool loaded : {false,true}) for (bool created : {false,true}) {
        const bool missing = status==DatabaseStatus::FAILED_NOT_FOUND;
        std::vector<uint32_t> expected{1};
        if (!loaded) {
            expected.push_back(2);
            if (!missing) expected.push_back(3);
            else {
                expected.push_back(4);
                if (!created) expected.push_back(5);
            }
        }
        for (size_t fail=0; fail<=expected.size(); ++fail) {
            std::vector<uint32_t> actual;
            try {
                const auto result = hs::ParentReplayStore(hs::ReplayStoreFlow::DEFAULT_WALLET,
                    [&](uint32_t step) -> uint32_t {
                    actual.push_back(step);
                    if (actual.size()==fail+1) throw std::runtime_error("injected");
                    switch (step) {
                    case 1: return loaded;
                    case 2: return missing;
                    case 4: BOOST_CHECK(!loaded && missing); return created;
                    default: throw std::runtime_error("wallet failed");
                    }
                });
                BOOST_CHECK_EQUAL(result,1U);
                BOOST_CHECK(fail==expected.size() && (loaded || (missing && created)));
            } catch (const std::runtime_error&) {
                BOOST_CHECK(fail<expected.size() || (!loaded && (!missing || !created)));
            }
            const auto size = std::min(fail+1,expected.size());
            BOOST_CHECK_EQUAL_COLLECTIONS(actual.begin(),actual.end(),expected.begin(),expected.begin()+size);
        }
    }
}

BOOST_AUTO_TEST_CASE(wallet_rpc_route_priority)
{
    for (unsigned native : {0U,1U}) for (unsigned pak : {0U,1U}) {
        const unsigned flags = (native << 1) | pak;
        BOOST_CHECK_EQUAL(drivechain::WALLET_RPC_ROUTES[0][flags], native);
        BOOST_CHECK_EQUAL(drivechain::WALLET_RPC_ROUTES[1][flags], native ? 2 : pak);
    }
}

BOOST_AUTO_TEST_CASE(deposit_argument_bounds_and_errors)
{
    const std::array<int64_t,9> values{INT64_MIN,-1,0,1,4294967295LL,4294967296LL,MAX_MONEY,MAX_MONEY+1,INT64_MAX};
    const std::array messages{
        "value_sats must be positive and within the money range",
        "fee_sats must be a non-negative monetary amount",
        "value_sats must be greater than zero",
        "fee_sats must be non-negative and less than value_sats",
        "mainchain_vout must be a valid uint32 output index"};
    for (uint32_t rule=0; rule<5; ++rule) for (int64_t amount : values) for (int64_t bound : values) {
        const bool expected = rule==0 ? amount>0 && amount<=bound :
            rule==1 ? amount>=0 && amount<=bound : rule==2 ? amount>0 :
            rule==3 ? amount>=0 && amount<bound : amount>=0 && amount<=std::numeric_limits<uint32_t>::max();
        bool accepted=false;
        try {
            wallet::CheckDepositArgument(static_cast<wallet::DepositArgument>(rule),amount,bound);
            accepted=true;
        } catch (const UniValue& error) {
            BOOST_CHECK_EQUAL(error["code"].getInt<int>(),RPC_INVALID_PARAMETER);
            BOOST_CHECK_EQUAL(error["message"].get_str(),messages[rule]);
        }
        BOOST_CHECK_EQUAL(accepted,expected);
    }
    BOOST_CHECK_THROW(wallet::CheckDepositArgument(static_cast<wallet::DepositArgument>(11),0),std::runtime_error);
    BOOST_CHECK_NO_THROW(wallet::CheckDepositArgument(wallet::DepositArgument::NATIVE_VALUE,MAX_MONEY));
    BOOST_CHECK_THROW(wallet::CheckDepositArgument(wallet::DepositArgument::NATIVE_VALUE,MAX_MONEY+1),UniValue);
    BOOST_CHECK_NO_THROW(wallet::CheckDepositArgument(wallet::DepositArgument::HISTORICAL_VALUE,INT64_MAX));
}

BOOST_AUTO_TEST_CASE(deposit_context_preflight_errors)
{
    const std::array codes{RPC_METHOD_NOT_FOUND,RPC_MISC_ERROR,RPC_INVALID_PARAMETER,RPC_INVALID_PARAMETER,RPC_INVALID_ADDRESS_OR_KEY,RPC_METHOD_NOT_FOUND};
    const std::array messages{
        "Native BIP300 deposits are not enabled on this network",
        "importdrivechaindeposit is unavailable outside an Elements parent-chain configuration",
        "mainchain_txid must be a 32-byte hex transaction id",
        "mainchain_block_hash must be a 32-byte hex block hash",
        "Invalid Elements address",
        "Legacy federated peg-ins are disabled on a Drivechain network; use importdrivechaindeposit"};
    for (uint32_t rule=5; rule<11; ++rule) for (int64_t first : {-1,0,1,2}) for (int64_t second : {-1,0,1,2}) {
        bool accepted=false;
        try {
            wallet::CheckDepositArgument(static_cast<wallet::DepositArgument>(rule),first,second);
            accepted=true;
        } catch (const UniValue& error) {
            BOOST_CHECK_EQUAL(error["code"].getInt<int>(),codes[rule-5]);
            BOOST_CHECK_EQUAL(error["message"].get_str(),messages[rule-5]);
        }
        BOOST_CHECK_EQUAL(accepted,rule==10 ? first==0 : first==1 && ((rule==5 || rule==9) || second==1));
    }
    for (const std::string& hex : {std::string{},std::string(63,'a'),std::string(64,'a'),std::string(64,'F'),
                                   std::string(65,'a'),std::string(64,'g'),std::string(64,'\0')}) {
        for (auto rule : {wallet::DepositArgument::TXID,wallet::DepositArgument::BLOCK_HASH}) {
            bool accepted=false;
            try { wallet::CheckDepositArgument(rule,IsHex(hex),hex.size()==64); accepted=true; }
            catch (const UniValue&) {}
            BOOST_CHECK_EQUAL(accepted,IsHex(hex) && hex.size()==64);
        }
    }
}

BOOST_AUTO_TEST_CASE(deposit_satoshi_parsing_preserves_json_contract)
{
    const auto capture = [](const std::function<int64_t()>& action) -> std::tuple<int,int64_t,std::string> {
        try { return {0,action(),{}}; }
        catch (const UniValue& error) { return {1,error["code"].getInt<int>(),error["message"].get_str()}; }
        catch (const std::exception& error) { return {2,0,error.what()}; }
    };
    for (const char* json : {"null","true","false","[]","{}","0","-1","1",
            "9223372036854775807","-9223372036854775808","9223372036854775808",
            "-9223372036854775809","1.0","1.5","1e3","\"0\"","\"-1\"",
            "\"9223372036854775807\"","\"-9223372036854775808\"","\"9223372036854775808\"",
            "\"\"","\" 1\"","\"1 \"","\"+1\"","\"001\"","\"1.0\"","\"42\\u0000\""}) {
        const UniValue value = ParseJson(json);
        for (const char* field : {"value_sats","fee_sats"}) {
            for (const auto fallback : {std::optional<int64_t>{}, std::optional<int64_t>{0},
                   std::optional<int64_t>{1000}, std::optional<int64_t>{std::numeric_limits<int64_t>::min()},
                   std::optional<int64_t>{std::numeric_limits<int64_t>::max()}}) {
                const auto expected = capture([&] {
                    if (fallback && value.isNull()) return *fallback;
                    int64_t amount{0};
                    if (value.isNum()) return value.getInt<int64_t>();
                    if (value.isStr() && ParseInt64(value.get_str(),&amount)) return amount;
                    throw JSONRPCError(RPC_INVALID_PARAMETER,strprintf("%s must be an integer number of satoshis",field));
                });
                const auto actual = capture([&] { return wallet::ParseDrivechainSatoshis(value,field,fallback); });
                BOOST_TEST_CONTEXT(json << " / " << field) { BOOST_CHECK(actual==expected); }
            }
        }
    }
    const UniValue absent(UniValue::VARR);
    BOOST_CHECK_EQUAL(wallet::ParseDrivechainSatoshis(absent[5], "fee_sats", 0), 0);
    BOOST_CHECK_EQUAL(wallet::ParseDrivechainSatoshis(absent[3], "fee_sats", 1000), 1000);
    BOOST_CHECK_THROW(wallet::ParseDrivechainSatoshis(absent[4], "value_sats"), UniValue);
}

BOOST_AUTO_TEST_CASE(deposit_broadcast_preserves_replay_and_errors)
{
    const std::vector<std::string> errors{"", "rejected", "already in block chain",
        "Transaction already in block chain", "txn-already-in-mempool",
        "prefix txn-already-in-mempool suffix", "Already in block chain",
        std::string("prefix\0already in block chain",29),
        "txn-already-in-mempoo", "already in block chai",
        "already in block chain txn-already-in-mempool"};
    for (bool known : {false,true}) {
        for (bool success : {false,true}) {
            for (const auto& message : errors) {
                unsigned calls=0;
                const bool duplicate = message.find("already in block chain")!=std::string::npos ||
                    message.find("txn-already-in-mempool")!=std::string::npos ||
                    message.find("Transaction already in block chain")!=std::string::npos;
                try {
                    const auto result = wallet::BroadcastDrivechainDeposit(known,[&](std::string& error) {
                        ++calls; error=message;
                        BOOST_CHECK_EQUAL(drivechain::haskell::WithdrawalPayout(10,1,MAX_MONEY),9);
                        return success;
                    });
                    BOOST_CHECK(known || success || duplicate);
                    BOOST_CHECK_EQUAL(result.already_imported,known || (!success && duplicate));
                    BOOST_CHECK_EQUAL(result.broadcast,!known && success);
                } catch (const UniValue& error) {
                    BOOST_CHECK(!known && !success && !duplicate);
                    BOOST_CHECK_EQUAL(error["code"].getInt<int>(),-26);
                    BOOST_CHECK_EQUAL(error["message"].get_str(),message);
                }
                BOOST_CHECK_EQUAL(calls,known ? 0U : 1U);
            }
        }
    }
    const auto throwing = [](std::string&) -> bool { throw std::runtime_error("broadcast failed"); };
    BOOST_CHECK(wallet::BroadcastDrivechainDeposit(true,throwing).already_imported);
    BOOST_CHECK_THROW(wallet::BroadcastDrivechainDeposit(false,throwing),std::runtime_error);
}

BOOST_AUTO_TEST_CASE(deposit_native_import_nested_effect_order)
{
    namespace hs = drivechain::haskell;
    for (bool confirmed : {false,true}) for (bool sponsor : {false,true})
    for (bool signed_ok : {false,true}) {
        std::vector<uint32_t> expected{1};
        if (!confirmed) expected.push_back(2);
        else {
            expected.insert(expected.end(),{3,4});
            if (sponsor) {
                expected.insert(expected.end(),{5,101,103,105,106,110});
                if (!signed_ok) expected.push_back(111);
            }
            if (!sponsor || signed_ok) expected.push_back(6);
        }
        for (size_t fail=0; fail<=expected.size(); ++fail) {
            std::vector<uint32_t> actual;
            bool built=false, sponsored=false;
            const auto record = [&](uint32_t step) {
                actual.push_back(step);
                if (actual.size()==fail+1) throw std::runtime_error("injected");
            };
            try {
                const auto status = hs::ParentReplayStore(hs::ReplayStoreFlow::DEPOSIT_NATIVE_IMPORT,
                    [&](uint32_t step) -> uint32_t {
                    record(step);
                    switch (step) {
                    case 1: return confirmed;
                    case 2: throw std::runtime_error("unconfirmed");
                    case 3: BOOST_CHECK(confirmed); built=true; return 1;
                    case 4: return sponsor;
                    case 5:
                        BOOST_CHECK(built);
                        hs::ParentReplayStore(hs::ReplayStoreFlow::DEPOSIT_SPONSORSHIP,
                            [&](uint32_t inner) -> uint32_t {
                            record(100+inner);
                            if (inner==6) return 0;
                            if (inner==10) return signed_ok;
                            if (inner==11) throw std::runtime_error("signing failed");
                            return 1;
                        });
                        sponsored=true;
                        return 1;
                    case 6: BOOST_CHECK(built && (!sponsor || sponsored)); return 1;
                    default: throw std::logic_error("unexpected action");
                    }
                });
                BOOST_CHECK_EQUAL(status,1U);
                BOOST_CHECK(fail==expected.size() && confirmed && (!sponsor || signed_ok));
            } catch (const std::runtime_error&) {
                BOOST_CHECK(fail<expected.size() || !confirmed || (sponsor && !signed_ok));
            }
            const auto size = std::min(fail+1,expected.size());
            BOOST_CHECK_EQUAL_COLLECTIONS(actual.begin(),actual.end(),expected.begin(),expected.begin()+size);
        }
    }
}

BOOST_AUTO_TEST_CASE(deposit_import_effect_order)
{
    namespace hs = drivechain::haskell;
    for (bool fee : {false,true}) for (bool verified : {false,true})
    for (bool evidence : {false,true}) {
        std::vector<uint32_t> expected{1,2};
        if (fee) expected.push_back(3);
        expected.insert(expected.end(),{4,5});
        if (!verified) expected.push_back(6);
        else {
            expected.push_back(7);
            if (!evidence) expected.push_back(8);
            else expected.insert(expected.end(),{9,10});
        }
        for (size_t fail=0; fail<=expected.size(); ++fail) {
            std::vector<uint32_t> actual;
            bool provisional=false, checked=false, built=false, installed=false;
            try {
                const auto status = hs::ParentReplayStore(hs::ReplayStoreFlow::DEPOSIT_IMPORT,
                    [&](uint32_t step) -> uint32_t {
                    actual.push_back(step);
                    if (actual.size()==fail+1) throw std::runtime_error("injected");
                    switch (step) {
                    case 2: return fee;
                    case 4: provisional=true; return 1;
                    case 5: BOOST_CHECK(provisional); checked=verified; return verified;
                    case 6: case 8: throw std::runtime_error("domain rejection");
                    case 7: BOOST_CHECK(checked); built=evidence; return evidence;
                    case 9: BOOST_CHECK(built); installed=true; return 1;
                    case 10: BOOST_CHECK(installed); return 1;
                    default: return 1;
                    }
                });
                BOOST_CHECK_EQUAL(status,1U);
                BOOST_CHECK(fail==expected.size() && verified && evidence);
            } catch (const std::runtime_error&) {
                BOOST_CHECK(fail<expected.size() || !verified || !evidence);
            }
            const auto size = std::min(fail+1,expected.size());
            BOOST_CHECK_EQUAL_COLLECTIONS(actual.begin(),actual.end(),expected.begin(),expected.begin()+size);
        }
    }
}

BOOST_AUTO_TEST_CASE(deposit_sponsorship_effect_order)
{
    namespace hs = drivechain::haskell;
    for (bool funded : {false,true}) for (bool within_cap : {false,true})
    for (unsigned count=0; count<4; ++count) for (unsigned spent=0; spent<=count; ++spent)
    for (bool signed_ok : {false,true}) {
        std::vector<uint32_t> expected{1};
        if (!funded) expected.push_back(2);
        else {
            expected.push_back(3);
            if (!within_cap) expected.push_back(4);
            else {
                expected.push_back(5);
                for (unsigned i=0; i<count; ++i) {
                    expected.insert(expected.end(),{6,7});
                    expected.push_back(i==spent ? 8 : 9);
                    if (i==spent) break;
                }
                if (spent==count) {
                    expected.insert(expected.end(),{6,10});
                    if (!signed_ok) expected.push_back(11);
                }
            }
        }
        // Fault injection at every visited action proves there are no later effects.
        for (size_t fail=0; fail<=expected.size(); ++fail) {
            std::vector<uint32_t> actual;
            unsigned cursor=0;
            try {
                const auto status = hs::ParentReplayStore(hs::ReplayStoreFlow::DEPOSIT_SPONSORSHIP,
                    [&](uint32_t step) -> uint32_t {
                    actual.push_back(step);
                    if (actual.size()==fail+1) throw std::runtime_error("injected");
                    switch (step) {
                    case 1: return funded;
                    case 3: return within_cap;
                    case 5: cursor=0; return 1;
                    case 6: return cursor<count;
                    case 7: return cursor==spent;
                    case 9: ++cursor; return 1;
                    case 10: return signed_ok;
                    default: throw std::runtime_error("domain rejection");
                    }
                });
                BOOST_CHECK_EQUAL(status,1U);
                BOOST_CHECK(fail==expected.size() && funded && within_cap && spent==count && signed_ok);
            } catch (const std::runtime_error&) {
                BOOST_CHECK(fail<expected.size() || !funded || !within_cap || spent<count || !signed_ok);
            }
            const auto size = std::min(fail+1,expected.size());
            BOOST_CHECK_EQUAL_COLLECTIONS(actual.begin(),actual.end(),expected.begin(),expected.begin()+size);
        }
    }
}

BOOST_AUTO_TEST_CASE(withdrawal_native_guard_errors)
{
    const std::array<const char*,5> messages{
        "Native BIP300 withdrawals are not enabled on this network",
        "Native BIP300 withdrawals are disabled on this drivechain: full M3/M4/M6 withdrawal-vote and CTIP-decrease consensus validation is not implemented",
        "subtractfeefromamount is not supported for native BIP300 withdrawals; the Elements fee must remain separate from the exact burn",
        "The resulting irreversible burn is not relayable under this Elements network's standard policy",
        "sendtomainchain is unavailable outside an Elements parent-chain configuration"};
    for (unsigned char stage=0; stage<5; ++stage) {
        for (bool value : {false,true}) {
            const bool valid = value==(stage!=2);
            try {
                wallet::CheckWithdrawal(static_cast<wallet::WithdrawalCheck>(stage),value);
                BOOST_CHECK(valid);
            } catch (const UniValue& error) {
                BOOST_CHECK(!valid);
                BOOST_CHECK_EQUAL(error["code"].getInt<int>(),stage==4 ? -1 : stage<2 ? -32601 : -8);
                BOOST_CHECK_EQUAL(error["message"].get_str(),messages[stage]);
            }
        }
    }
    BOOST_CHECK_THROW(wallet::CheckWithdrawal(static_cast<wallet::WithdrawalCheck>(255),true),std::runtime_error);
}

BOOST_AUTO_TEST_CASE(withdrawal_parent_dust_matches_bitcoin_sizing)
{
    std::vector<CScript> scripts{
        CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20,1) << OP_EQUALVERIFY << OP_CHECKSIG,
        CScript() << OP_0 << std::vector<unsigned char>(20,2),
        CScript() << OP_0 << std::vector<unsigned char>(32,3),
        CScript() << OP_1 << std::vector<unsigned char>(32,4),
        CScript() << OP_16 << std::vector<unsigned char>(40,5), CScript() << OP_RETURN};
    for (size_t size : {0,1,20,128,252,253,10000}) {
        const std::vector<unsigned char> bytes(size,OP_TRUE);
        scripts.emplace_back(bytes.begin(),bytes.end());
    }
    for (const auto& script : scripts) {
        int version{0};
        std::vector<unsigned char> program;
        const uint32_t spend = script.IsWitnessProgram(version,program) ? 67 : 148;
        TxoutType type{TxoutType::NONSTANDARD};
        std::array<unsigned char,10> facts{};
        facts[4] = IsStandard(script,std::nullopt,type);
        WriteLE32(facts.data(),static_cast<uint32_t>(type));
        const auto output_size = static_cast<uint32_t>(GetSerializeSize(Sidechain::Bitcoin::CTxOut(0,script)));
        WriteLE32(facts.data()+5,output_size);
        facts[9] = spend == 67;
        const std::array allowed{TxoutType::PUBKEY,TxoutType::PUBKEYHASH,TxoutType::SCRIPTHASH,
            TxoutType::MULTISIG,TxoutType::WITNESS_V0_SCRIPTHASH,TxoutType::WITNESS_V0_KEYHASH,TxoutType::WITNESS_V1_TAPROOT};
        std::vector<unsigned char> policy;
        BOOST_REQUIRE(drivechain::haskell::WithdrawalBytes(drivechain::haskell::WithdrawalOp::PARENT_POLICY,facts,policy,nullptr));
        BOOST_REQUIRE_EQUAL(policy.size(), 9U);
        BOOST_CHECK_EQUAL(policy[0],facts[4] && std::find(allowed.begin(),allowed.end(),type) != allowed.end());
        BOOST_CHECK_EQUAL(ReadLE64(policy.data()+1),CFeeRate(DUST_RELAY_TX_FEE_BITCOIN).GetFee(output_size+spend));
        for (CAmount amount : {CAmount{0},CAmount{1},MAX_MONEY}) {
            const auto size = static_cast<uint32_t>(GetSerializeSize(Sidechain::Bitcoin::CTxOut(amount,script)));
            const CAmount dust=CFeeRate(DUST_RELAY_TX_FEE_BITCOIN).GetFee(size+spend);
            BOOST_CHECK_EQUAL(wallet::ValidateNativePayout(script,dust),dust);
            BOOST_CHECK_EXCEPTION(wallet::ValidateNativePayout(script,dust-1),UniValue,
                [](const UniValue& error) { return error["code"].getInt<int>() == RPC_INVALID_PARAMETER; });
        }
    }
    BOOST_CHECK_EQUAL(wallet::ValidateNativePayout(scripts[0],546),546);
    BOOST_CHECK_EQUAL(wallet::ValidateNativePayout(scripts[1],294),294);
    for (uint32_t size : {0U,1U,31U,UINT32_MAX-148,UINT32_MAX-67,UINT32_MAX}) {
        for (unsigned char witness : {0,1}) {
            std::array<unsigned char,5> input{};
            WriteLE32(input.data(),size); input[4]=witness;
            std::vector<unsigned char> output;
            BOOST_REQUIRE(drivechain::haskell::WithdrawalBytes(drivechain::haskell::WithdrawalOp::PARENT_DUST,input,output,nullptr));
            BOOST_REQUIRE_EQUAL(output.size(), 8U);
            BOOST_CHECK_EQUAL(ReadLE64(output.data()),CFeeRate(3000).GetFee(size+(witness ? 67U : 148U)));
        }
    }
}

BOOST_AUTO_TEST_CASE(withdrawal_native_amount_boundaries)
{
    const auto prior_amount=[](unsigned char mode,CAmount payout,CAmount fee=0) {
        std::array<unsigned char,17> input{};
        input[0]=mode;
        WriteLE64(input.data()+1,payout); WriteLE64(input.data()+9,fee);
        std::vector<unsigned char> output;
        std::string error;
        if (!drivechain::haskell::WithdrawalBytes(drivechain::haskell::WithdrawalOp::NATIVE_AMOUNT,input,output,&error))
            throw JSONRPCError(RPC_TYPE_ERROR,error);
        BOOST_REQUIRE_EQUAL(output.size(), 8U);
        return static_cast<CAmount>(ReadLE64(output.data()));
    };
    const std::vector<CAmount> values{std::numeric_limits<CAmount>::min(),-1,0,1,
        MAX_MONEY-1,MAX_MONEY,MAX_MONEY+1,std::numeric_limits<CAmount>::max()};
    for (auto payout : values) {
        const auto rejected = [](const UniValue& error, const char* message) {
            BOOST_CHECK_EQUAL(error["code"].getInt<int>(),-3);
            BOOST_CHECK_EQUAL(error["message"].get_str(),message);
        };
        try {
            BOOST_CHECK_EQUAL(prior_amount(0,payout),payout);
            BOOST_CHECK(payout>0 && MoneyRange(payout));
        } catch (const UniValue& error) {
            BOOST_CHECK(payout<=0 || !MoneyRange(payout));
            rejected(error,"Invalid withdrawal payout amount");
        }
        for (auto fee : values) {
            const bool valid = fee>=0 && MoneyRange(fee) && payout<=MAX_MONEY-fee;
            try {
                BOOST_CHECK_EQUAL(wallet::LegacyWithdrawalAmount(payout),payout);
                BOOST_CHECK_EQUAL(prior_amount(2,payout,fee),payout);
                BOOST_CHECK(payout>0);
            } catch (const UniValue& error) {
                BOOST_CHECK(payout<=0);
                rejected(error,"Invalid amount for send");
            }
            try {
                const auto total = prior_amount(1,payout,fee);
                BOOST_REQUIRE(valid);
                BOOST_CHECK_EQUAL(total,payout+fee);
            } catch (const UniValue& error) {
                BOOST_CHECK(!valid);
                rejected(error,"Invalid mainchain fee or withdrawal total");
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(withdrawal_native_output_selection)
{
    const CAsset asset{uint256S("1234")};
    const uint256 genesis{uint256S("5678")};
    const CScript destination = CScript() << OP_0 << std::vector<unsigned char>(20,42);
    CTxOut canonical;
    BOOST_REQUIRE(drivechain::BuildNativeWithdrawalOutput(asset,genesis,destination,100000,1000,canonical));
    std::vector<CTxOut> candidates(7,canonical);
    candidates[1].scriptPubKey = CScript() << OP_TRUE;
    candidates[2].nAsset.SetToAsset(CAsset{uint256S("9999")});
    candidates[3].nValue.SetToAmount(100001);
    candidates[4].nNonce.vchCommitment.assign(33,2);
    candidates[5].nAsset.vchCommitment.assign(33,10);
    candidates[6].nValue.vchCommitment.assign(33,8);
    const auto check = [&](const CMutableTransaction& tx, int expected, int changed) {
        try {
            const auto index = wallet::FindNativeWithdrawalOutput(CTransaction{tx},canonical.scriptPubKey,
                asset,genesis,100000+(changed==1),99000+(changed==2),1000+(changed==3));
            BOOST_CHECK(expected>=0);
            BOOST_CHECK_EQUAL(index,expected);
        } catch (const UniValue& error) {
            BOOST_CHECK(expected<0);
            BOOST_CHECK_EQUAL(error["code"].getInt<int>(),-4);
            BOOST_CHECK_EQUAL(error["message"].get_str(),expected==-2 ?
                "Committed transaction contains multiple native withdrawal burns" :
                "Committed transaction is missing its exact native withdrawal burn");
        }
    };
    check(CMutableTransaction{},-1,0);
    for (size_t first=0; first<candidates.size(); ++first) {
        for (size_t second=0; second<candidates.size(); ++second) {
            for (int witness=0; witness<4; ++witness) {
                CMutableTransaction tx;
                tx.vout = {candidates[first],candidates[second]};
                if (witness) tx.witness.vtxoutwit.resize(witness==1 ? 2 : 1);
                if (witness==2) tx.witness.vtxoutwit[0].vchRangeproof = {1};
                if (witness==3) tx.witness.vtxoutwit[0].vchSurjectionproof = {1};
                const bool a = first==0 && witness<2, b = second==0;
                check(tx,a && b ? -2 : a ? 0 : b ? 1 : -1,0);
                for (int changed=1; changed<=3; ++changed) check(tx,-1,changed);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(withdrawal_submission_preserves_effect_prefixes)
{
    for (const bool available : {false,true}) {
        for (int match : {-1,0,2}) {
            for (const bool verbose : {false,true}) {
                std::vector<uint32_t> sequence{1,2,3,4,5};
                if (!available) sequence.push_back(6);
                else {
                    sequence.push_back(7);
                    for (int i=0; i<3; ++i) {
                        sequence.insert(sequence.end(),{8,9});
                        if (i==match) break;
                        sequence.push_back(10);
                    }
                    if (match<0) sequence.insert(sequence.end(),{8,11});
                    else {
                        sequence.insert(sequence.end(),{12,13,14,15,16,17});
                        if (verbose) sequence.push_back(18);
                    }
                }
                for (uint32_t fault=0; fault<=18; ++fault) {
                    std::vector<uint32_t> expected, actual;
                    bool completed{false}, reserved{false}, released{false}, threw{false};
                    for (auto step : sequence) {
                        expected.push_back(step);
                        if (step==fault) break;
                    }
                    int index=0;
                    try {
                        struct Release {
                            bool& reserved; bool& released;
                            ~Release() { released=reserved; reserved=false; }
                        } release{reserved,released};
                        const auto result = drivechain::haskell::ParentReplayStore(
                            drivechain::haskell::ReplayStoreFlow::WITHDRAWAL_SUBMISSION, [&](uint32_t step) -> uint32_t {
                            actual.push_back(step);
                            if (step==fault || step==6 || step==11) throw std::runtime_error("submission fault");
                            // Calls into Haskell are legal here: the transition has returned.
                            BOOST_CHECK_EQUAL(drivechain::haskell::WithdrawalPayout(10,1,MAX_MONEY),9);
                            if (step==2) reserved=true;
                            if (step==14) { completed=true; reserved=false; }
                            if (step==5) return available;
                            if (step==8) return index<3;
                            if (step==9) return index==match;
                            if (step==10) ++index;
                            return step==17 ? verbose : 1;
                        });
                        BOOST_CHECK_EQUAL(result,verbose);
                    } catch (const std::runtime_error& error) {
                        BOOST_CHECK_EQUAL(error.what(),"submission fault"); threw=true;
                    }
                    BOOST_CHECK(actual==expected);
                    BOOST_CHECK_EQUAL(threw,!available || match<0 || std::find(sequence.begin(),sequence.end(),fault)!=sequence.end());
                    const auto reached = [&](uint32_t step) {
                        return std::find(expected.begin(),expected.end(),step)!=expected.end() && step!=fault;
                    };
                    BOOST_CHECK_EQUAL(completed,reached(14));
                    BOOST_CHECK_EQUAL(released,reached(2) && !reached(14));
                    BOOST_CHECK(!reserved);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(withdrawal_event_lookup_preserves_legacy_semantics)
{
    const uint256 id = uint256S("ab1234");
    const std::string serialized = HexStr(std::vector<unsigned char>(id.begin(), id.end()));
    const auto event = [&](const std::string& hex, const std::string& status) {
        return ParseJson(strprintf(R"({"withdrawalBundle":{"m6id":{"hex":"%s"},"event":%s}})", hex, status));
    };
    const auto block = [](const std::vector<UniValue>& entries) {
        UniValue events(UniValue::VARR), info(UniValue::VOBJ), result(UniValue::VOBJ);
        for (const auto& entry : entries) events.push_back(entry);
        info.pushKV("events", events); result.pushKV("blockInfo", info); return result;
    };
    const auto lookup = [&](const std::vector<UniValue>& entries) {
        UniValue blocks(UniValue::VARR), data(UniValue::VOBJ);
        for (const auto& entry : entries) blocks.push_back(entry);
        data.pushKV("blocks", blocks);
        return wallet::FindWithdrawalBundleEventStatus(data, id.GetHex());
    };
    for (const auto& [status, expected] : std::vector<std::pair<std::string,std::string>>{
            {"null", ""}, {"[]", ""}, {"{}", ""},
            {R"({"submitted":false})", "submitted"},
            {R"({"submitted":{},"succeeded":{},"failed":{}})", "submitted"},
            {R"({"submitted":null,"succeeded":[],"failed":{}})", "succeeded"},
            {R"({"failed":0})", "failed"}}) {
        BOOST_CHECK_EQUAL(lookup({block({event(serialized, status)})}), expected);
    }
    const auto good = event(serialized, R"({"succeeded":{}})");
    BOOST_CHECK_EQUAL(lookup({block({event(serialized, "{}"), good})}), "");
    BOOST_CHECK_EQUAL(lookup({block({event(serialized, R"({"failed":{}})")}), block({good})}), "failed");
    BOOST_CHECK_EQUAL(lookup({ParseJson("{}"), block({ParseJson("null"),
        event(serialized.substr(2), "{}"), event(serialized+"00", "{}"),
        event(id.GetHex(), "{}"), good})}), "succeeded");
    BOOST_CHECK_EQUAL(lookup({block({event(serialized+"zz", R"({"submitted":{}})")})}), "");
    BOOST_CHECK_EQUAL(lookup({block({event(" " + serialized.substr(0,2) + " " + serialized.substr(2) + " ",
        R"({"submitted":{}})")})}), "submitted");
    for (const auto& malformed : {"null", "[]", "{}", R"({"blocks":{}})"})
        BOOST_CHECK(wallet::FindWithdrawalBundleEventStatus(ParseJson(malformed), id.GetHex()).empty());
    const std::vector<std::pair<UniValue,std::optional<std::string>>> candidates{
        {ParseJson("null"), std::nullopt}, {ParseJson("{}"), std::nullopt},
        {ParseJson(R"({"withdrawalBundle":{"m6id":{"hex":12}}})"), std::nullopt},
        {event(serialized+"zz", "{}"), std::nullopt},
        {event(serialized.substr(2), "{}"), std::nullopt},
        {event(id.GetHex(), "{}"), std::nullopt},
        {event(serialized, "null"), std::string{}},
        {event(serialized, R"({"submitted":false})"), "submitted"},
        {good, "succeeded"}, {event(serialized, R"({"failed":0})"), "failed"}};
    for (const auto& first : candidates) {
        for (const auto& second : candidates) {
            const auto expected = first.second.value_or(second.second.value_or(""));
            BOOST_CHECK_EQUAL(lookup({block({first.first, second.first})}), expected);
            BOOST_CHECK_EQUAL(lookup({block({first.first}), ParseJson("{}"), block({}), block({second.first})}), expected);
        }
    }
}

BOOST_AUTO_TEST_CASE(withdrawal_rpc_policies_preserve_boundaries)
{
    for (const int64_t amount : {INT64_MIN, int64_t{-1}, int64_t{0}, int64_t{1}, int64_t{MAX_MONEY}, int64_t{MAX_MONEY+1}, INT64_MAX}) {
        for (const int64_t fee : {INT64_MIN, int64_t{-1}, int64_t{0}, int64_t{1}, int64_t{MAX_MONEY}, int64_t{MAX_MONEY+1}, INT64_MAX}) {
            if (fee > 0 && MoneyRange(fee) && fee < amount) {
                BOOST_CHECK_EQUAL(drivechain::haskell::WithdrawalRpcFee(amount,fee), fee);
            } else {
                BOOST_CHECK_EXCEPTION(drivechain::haskell::WithdrawalRpcFee(amount,fee), std::invalid_argument,
                    [](const std::invalid_argument& error) {
                        return std::string(error.what()) == "-drivechainpegoutmainfeesats must be positive and less than the withdrawal amount";
                    });
            }
        }
    }
    const std::vector<std::string> statuses{"", "submitted", "succeeded", "failed", "Failed", "unknown", std::string("failed\0",7)};
    for (size_t i = 0; i < statuses.size(); ++i) {
        const auto decision = drivechain::haskell::ClassifyWithdrawalEvent(statuses[i]);
        BOOST_CHECK_EQUAL(decision.rejection, i == 0 ? 1 : i == 3 ? 2 : 0);
        BOOST_CHECK_EQUAL(decision.clear, i == 2 || i == 3);
    }
}

BOOST_AUTO_TEST_CASE(withdrawal_bundle_admission_boundaries)
{
    const COutPoint outpoint(Txid::FromUint256(uint256S("11")), 3);
    const auto invalid = [](const std::invalid_argument& error) {
        return std::string(error.what()) == "Invalid blinded withdrawal amount, fee, payout, or outpoint";
    };
    for (const CAmount amount : {INT64_MIN, int64_t{-1}, int64_t{0}, int64_t{1}, int64_t{MAX_MONEY}, int64_t{MAX_MONEY + 1}, INT64_MAX}) {
        for (const CAmount fee : {INT64_MIN, int64_t{-1}, int64_t{0}, int64_t{1}, int64_t{MAX_MONEY}, int64_t{MAX_MONEY + 1}, INT64_MAX}) {
            for (const size_t size : {0U, 1U, 10000U, 10001U}) {
                for (const bool null_outpoint : {false, true}) {
                    const std::vector<unsigned char> script_bytes(size, OP_TRUE);
                    const CScript script(script_bytes.begin(), script_bytes.end());
                    const auto build = [&] {
                        return wallet::BuildDrivechainWithdrawalBundle(amount, fee, script,
                            null_outpoint ? COutPoint{} : outpoint, 50);
                    };
                    const bool accepted = MoneyRange(amount) && amount != 0 && MoneyRange(fee) &&
                        fee < amount && size != 0 && size <= MAX_SCRIPT_SIZE && !null_outpoint;
                    if (!accepted) {
                        BOOST_CHECK_EXCEPTION(build(), std::invalid_argument, invalid);
                    } else {
                        DataStream bytes{build().no_witness_bytes};
                        Sidechain::Bitcoin::CMutableTransaction tx;
                        bytes >> TX_NO_WITNESS(tx);
                        BOOST_REQUIRE_EQUAL(tx.vout.size(), 3U);
                        BOOST_CHECK_EQUAL(tx.vout[2].nValue, amount - fee);
                        BOOST_CHECK(tx.vout[2].scriptPubKey == script);
                        BOOST_CHECK(bytes.empty());
                    }
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(withdrawal_destination_rejects_lossy_or_unspendable_input)
{
    const WitnessV0KeyHash key(uint160(ParseHex("00112233445566778899aabbccddeeff00112233")));
    const auto script = GetScriptForDestination(key);
    const auto address = EncodeParentDestination(key);
    BOOST_CHECK(wallet::DecodeDrivechainWithdrawalDestination(address) == script);
    BOOST_CHECK(wallet::DecodeDrivechainWithdrawalDestination("hex:" + HexStr(script)) == script);
    const PKHash legacy(uint160(ParseHex("00112233445566778899aabbccddeeff00112233")));
    BOOST_CHECK(wallet::DecodeDrivechainWithdrawalDestination(EncodeParentDestination(legacy)) ==
                GetScriptForDestination(legacy));
    const auto decoded = bech32::Decode(address);
    BOOST_CHECK_THROW(wallet::DecodeDrivechainWithdrawalDestination(
        bech32::Encode(decoded.encoding, "wrong", decoded.data)), UniValue);
    for (const auto& invalid : {
            std::string{}, std::string{"not-an-address"}, std::string{"hex:"},
            std::string{"hex:6a"}, std::string{"hex:51"},
            "hex:" + HexStr(script) + "zz", "hex:" + HexStr(script) + "0",
            "hex:" + std::string(258, '0')}) {
        BOOST_CHECK_THROW(wallet::DecodeDrivechainWithdrawalDestination(invalid), UniValue);
    }
}

BOOST_AUTO_TEST_CASE(withdrawal_destination_flow_matches_native_order)
{
    for (uint32_t flags = 0; flags < 16; ++flags) {
        for (uint32_t hex_size : {0U, 1U, 256U, 257U, UINT32_MAX}) {
            for (uint32_t script_size : {0U, 1U, 128U, 129U, UINT32_MAX}) {
                for (uint32_t type = 0; type < 14; ++type) {
                    std::vector<uint32_t> expected{1}, actual;
                    uint32_t failure = 0;
                    const auto fail = [&](uint32_t step) { expected.push_back(step); failure = step; };
                    if (flags & 1) {
                        expected.push_back(2);
                        if (hex_size > 256) fail(4);
                        else {
                            expected.push_back(3);
                            if (!(flags & 2)) fail(4); else expected.push_back(6);
                        }
                    } else {
                        expected.push_back(5);
                        if (!(flags & 4)) fail(10); else expected.push_back(8);
                    }
                    if (!failure) {
                        expected.push_back(9);
                        if (!script_size || script_size > 128) fail(12);
                        else {
                            expected.push_back(11);
                            if (!(flags & 8)) fail(12);
                            else {
                                expected.push_back(13);
                                if (!(type == 2 || type == 3 || type == 4 || type == 5 ||
                                      type == 7 || type == 8 || type == 9)) fail(14);
                            }
                        }
                    }
                    uint32_t observed = 0;
                    try {
                        BOOST_CHECK(drivechain::haskell::ParentReplayStore(
                            drivechain::haskell::ReplayStoreFlow::WITHDRAWAL_DESTINATION,
                            [&](uint32_t step) -> uint32_t {
                                actual.push_back(step);
                                switch (step) {
                                case 1: return !!(flags & 1);
                                case 2: return hex_size;
                                case 3: return !!(flags & 2);
                                case 5: return !!(flags & 4);
                                case 6: case 8: return 1;
                                case 9: return script_size;
                                case 11: return !!(flags & 8);
                                case 13: return type;
                                default: throw step;
                                }
                            }));
                    } catch (uint32_t step) { observed = step; }
                    BOOST_CHECK_EQUAL(observed, failure);
                    BOOST_CHECK(actual == expected);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(withdrawal_journal_distinguishes_missing_and_corrupt)
{
    const fs::path journal_dir = m_path_root / "withdrawal-journal";
    fs::create_directories(journal_dir);

    node::WithdrawalJournalEntry read_entry;
    std::string error;
    BOOST_CHECK(
        node::ReadWithdrawalJournal(journal_dir, read_entry, &error) ==
        node::WithdrawalJournalReadResult::MISSING);

    node::WithdrawalJournalEntry entry;
    entry.sidechain_txid = uint256S("66");
    entry.sidechain_vout = 4;
    entry.sidechain_height = 72;
    entry.amount = 100'000;
    entry.mainchain_fee = 1'000;
    entry.destination = "test-destination";
    entry.payout_script = CScript() << OP_TRUE;
    entry.sidechain_slot = 24;
    entry.created_time = 1;
    const wallet::DrivechainWithdrawalBundle bundle =
        wallet::BuildDrivechainWithdrawalBundle(
            entry.amount, entry.mainchain_fee, entry.payout_script,
            entry.Outpoint(), entry.sidechain_height, uint256S("77"),
            uint256S("88"), uint256S("99"));
    entry.m6id = bundle.m6id;
    entry.bundle_bytes = bundle.bytes;
    auto legacy = bundle.bytes;
    legacy.erase(legacy.begin() + 4, legacy.begin() + 6);
    BOOST_CHECK(drivechain::haskell::WithdrawalTransport(bundle.bytes, true) == legacy);
    BOOST_CHECK(drivechain::haskell::WithdrawalTransport(legacy) == bundle.bytes);
    for (size_t length = 0; length < 7; ++length) {
        const std::vector<unsigned char> short_bundle(length);
        BOOST_CHECK_THROW(drivechain::haskell::WithdrawalTransport(short_bundle, true), std::runtime_error);
        auto invalid=entry;
        invalid.bundle_bytes=short_bundle;
        BOOST_CHECK(!node::WriteWithdrawalJournal(journal_dir,invalid));
    }
    BOOST_CHECK(node::WithdrawalJournalPath(journal_dir)==journal_dir / "drivechain_withdrawal.dat");
    BOOST_REQUIRE(node::WriteWithdrawalJournal(journal_dir, entry));
    BOOST_REQUIRE(
        node::ReadWithdrawalJournal(journal_dir, read_entry, &error) ==
        node::WithdrawalJournalReadResult::OK);
    BOOST_CHECK(read_entry.m6id == entry.m6id);
    BOOST_CHECK(read_entry.Outpoint() == entry.Outpoint());
    BOOST_CHECK(read_entry.bundle_bytes == entry.bundle_bytes);

    for (int fault = 0; fault < 14; ++fault) {
        auto invalid = entry;
        switch (fault) {
        case 0: invalid.version = 2; break;
        case 1: invalid.state = 5; break;
        case 2: invalid.m6id.SetNull(); break;
        case 3: invalid.sidechain_txid.SetNull(); break;
        case 4: invalid.amount = 0; break;
        case 5: invalid.mainchain_fee = invalid.amount; break;
        case 6: invalid.sidechain_slot = -1; break;
        case 7: invalid.destination.clear(); break;
        case 8: invalid.payout_script.clear(); break;
        case 9: invalid.payout_script = CScript() << OP_RETURN; break;
        case 10: invalid.created_time = 0; break;
        case 11: invalid.bundle_bytes.resize(6); break;
        case 12: invalid.bundle_bytes[4] = 1; break;
        case 13: invalid.bundle_bytes[5] = 2; break;
        }
        BOOST_CHECK(!node::WriteWithdrawalJournal(journal_dir, invalid));
        BOOST_REQUIRE(node::ReadWithdrawalJournal(journal_dir, read_entry, &error) ==
                      node::WithdrawalJournalReadResult::OK);
        BOOST_CHECK(read_entry.bundle_bytes == entry.bundle_bytes);
        BOOST_CHECK(read_entry.m6id == entry.m6id);
    }

    node::WithdrawalJournalEntry mismatched = entry;
    mismatched.bundle_bytes.back() ^= 1;
    BOOST_CHECK(!node::WriteWithdrawalJournal(journal_dir, mismatched));

    // Valid serialization isolates each verification stage from decoding failure.
    for (int fault = 0; fault < 4; ++fault) {
        const std::string magic = fault == 0 ? "wrong-journal" : "ELEMENTS_DRIVECHAIN_WITHDRAWAL_JOURNAL_V1";
        auto invalid = entry;
        if (fault == 2) invalid.created_time = 0;
        if (fault == 3) invalid.bundle_bytes.back() ^= 1;
        HashWriter hasher;
        hasher << magic << invalid;
        const uint256 checksum = fault == 1 ? uint256{} : hasher.GetHash();
        DataStream encoded;
        encoded << magic << invalid << checksum;
        {
            std::ofstream output(node::WithdrawalJournalPath(journal_dir), std::ios::binary | std::ios::trunc);
            output.write(reinterpret_cast<const char*>(encoded.data()), encoded.size());
            BOOST_REQUIRE(output.good());
        }
        read_entry = entry;
        BOOST_CHECK(node::ReadWithdrawalJournal(journal_dir, read_entry, &error) == node::WithdrawalJournalReadResult::CORRUPT);
        BOOST_CHECK(error.find(fault == 0 ? "is not a withdrawal journal" :
            fault == 1 ? "checksum mismatch" : fault == 2 ? "journal creation time is invalid" :
            "journal M6 identity does not match its serialized bundle") != std::string::npos);
        BOOST_CHECK(read_entry.created_time == entry.created_time);
        BOOST_CHECK(read_entry.bundle_bytes == entry.bundle_bytes);
        BOOST_CHECK(node::ReadWithdrawalJournal(journal_dir, read_entry, nullptr) == node::WithdrawalJournalReadResult::CORRUPT);
    }

    {
        std::ofstream corrupt(
            node::WithdrawalJournalPath(journal_dir),
            std::ios::binary | std::ios::trunc);
        BOOST_REQUIRE(corrupt.is_open());
        corrupt << "not-a-valid-withdrawal-journal";
    }
    BOOST_CHECK(
        node::ReadWithdrawalJournal(journal_dir, read_entry, &error) ==
        node::WithdrawalJournalReadResult::CORRUPT);
    BOOST_CHECK(!error.empty());
    BOOST_REQUIRE(node::ClearWithdrawalJournal(journal_dir));
    BOOST_CHECK(node::ClearWithdrawalJournal(journal_dir));
    BOOST_CHECK(!node::WriteWithdrawalJournal(journal_dir / "missing-parent", entry));
    const auto blocked = node::WithdrawalJournalPath(journal_dir);
    fs::create_directories(blocked / "keep");
    BOOST_CHECK(!node::WriteWithdrawalJournal(journal_dir, entry));
    BOOST_CHECK(!node::ClearWithdrawalJournal(journal_dir));
    BOOST_CHECK(fs::is_directory(blocked / "keep"));
    BOOST_REQUIRE(fs::remove(blocked / "keep"));
    BOOST_CHECK(node::ClearWithdrawalJournal(journal_dir));
    BOOST_CHECK(fs::directory_iterator(journal_dir) == fs::directory_iterator{});
}

BOOST_AUTO_TEST_CASE(authenticated_enforcer_request_order)
{
    using namespace drivechain::haskell;
    for (const bool admission : {false,true}) {
    for (uint32_t failure : admission ? std::vector<uint32_t>{0,11,1,12,5,7,8} : std::vector<uint32_t>{0,1,3,5,7,8}) {
        std::vector<uint32_t> expected;
        for (uint32_t action : admission ? std::vector<uint32_t>{11,1,12,5,7,8,10} : std::vector<uint32_t>{1,3,5,7,8,10}) {
            expected.push_back(action);
            if (action==failure) {
                expected.push_back(action==11 ? 2 : action==12 ? 4 : action<7 ? action+1 : 9);
                break;
            }
        }
        std::vector<uint32_t> trace;
        const auto invoke = [&](size_t stop) {
            trace.clear();
            return ParentReplayStore(admission ? ReplayStoreFlow::GRPC_REQUEST_ADMISSION : ReplayStoreFlow::GRPC_REQUEST, [&](uint32_t action) -> uint32_t {
                trace.push_back(action);
                if (trace.size()==stop) throw std::runtime_error("request fault");
                if (action==11) return failure==11 ? 129 : 128;
                if (action==12) return failure==12 ? 0 : 1048576;
                if (action==7 && failure!=7) {
                    return ParentReplayStore(ReplayStoreFlow::GRPC_CONFIG, [](uint32_t step) { return step==5 ? 7U : 1U; });
                }
                return action!=failure;
            });
        };
        BOOST_CHECK_EQUAL(invoke(0), failure==0 ? 1 : 0);
        BOOST_CHECK(trace==expected);
        for (size_t stop=1; stop<=expected.size(); ++stop) {
            BOOST_CHECK_THROW(invoke(stop), std::runtime_error);
            BOOST_CHECK(trace==std::vector<uint32_t>(expected.begin(),expected.begin()+stop));
        }
    }
    }
    ArgsManager args;
    const std::string method="cusf.mainchain.v1.ValidatorService/GetChainTip";
    const auto request = [&](const std::string& name, const std::string& payload) {
        return RunAuthenticatedDrivechainGrpc(args,name,payload,std::chrono::milliseconds{1},1,[] { return true; });
    };
    BOOST_CHECK_EQUAL(request("unrecognized", "").error,"refusing an unrecognized enforcer gRPC method");
    for (const size_t size : {128U,129U,1024U})
        BOOST_CHECK_EQUAL(request(std::string(size,'x'), "").error,"refusing an unrecognized enforcer gRPC method");
    for (const auto& payload : {std::string{},std::string((1U<<20)+1,'x')})
        BOOST_CHECK_EQUAL(request(method,payload).error,"enforcer gRPC payload must contain 1..1048576 bytes");
    for (const auto& payload : {"[]","null","{","1"})
        BOOST_CHECK_EQUAL(request(method,payload).error,"enforcer gRPC payload must be one JSON object");
    BOOST_CHECK_EQUAL(request(method,std::string(1U<<20,'x')).error,"enforcer gRPC payload must be one JSON object");
    args.ForceSetArg("-drivechainbmmgrpcaddr","https://127.0.0.1:55051");
    BOOST_CHECK_EQUAL(request(method,"{}").error,"-drivechainbmmgrpcaddr must be a host:port endpoint without a URL scheme");
}

BOOST_AUTO_TEST_CASE(authenticated_enforcer_argument_plan)
{
    using drivechain::haskell::GrpcPlan;
    for (const auto& method : {
        "cusf.mainchain.v1.WalletService/CreateBmmCriticalDataTransaction",
        "cusf.mainchain.v1.WalletService/BroadcastWithdrawalBundle",
        "cusf.mainchain.v1.BlockProducerService/ProposeWithdrawalBundle",
        "cusf.mainchain.v1.ValidatorService/GetTwoWayPegData",
        "cusf.mainchain.v1.ValidatorService/GetChainInfo",
        "cusf.mainchain.v1.ValidatorService/GetChainTip",
        "cusf.mainchain.v1.ValidatorService/GetSidechains",
        "cusf.mainchain.v1.ValidatorService/GetCtip"}) {
        BOOST_CHECK(GrpcPlan(std::array<std::string,1>{method}).empty());
        for (const std::string& invalid : {std::string(method)+" "," "+std::string(method),std::string(method)+std::string(1,'\0')})
            BOOST_CHECK_THROW(GrpcPlan(std::array<std::string,1>{invalid}),std::invalid_argument);
        BOOST_CHECK(GrpcPlan(std::array<std::string,2>{method,"{}"}).empty());
        for (const std::string& authority : {std::string{},std::string{"host"}}) {
            const std::string key{"key\0data",8};
            const std::array<std::string,8> fields{method,"{}","/tool with spaces","ca","cert",key,authority,"127.0.0.1:1"};
            BOOST_CHECK_THROW(GrpcPlan(fields),std::invalid_argument);
        }
    }
    BOOST_CHECK_THROW(GrpcPlan(std::array<std::string,1>{"invalid"}),std::invalid_argument);
    BOOST_CHECK_THROW(GrpcPlan(std::array<std::string,3>{"invalid","",""}),std::invalid_argument);
    BOOST_CHECK_THROW(GrpcPlan(std::array<std::string,2>{"invalid",""}),std::invalid_argument);
    BOOST_CHECK_THROW(GrpcPlan(std::array<std::string,2>{"cusf.mainchain.v1.ValidatorService/GetCtip",""}),std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(rpc_server_configuration_order)
{
    using namespace drivechain::haskell;
    for (const std::vector<uint32_t>& expected : {
        std::vector<uint32_t>{1,2}, {1,3,4}, {1,3,5,6}, {1,3,5,6,7,8},
        {1,3,5,6,7,10,8}, {1,3,5,6,7,10,9,6,7,8}, {1,3,5,6,7,10,9,6}}) {
        std::vector<uint32_t> trace;
        const auto run = [&](size_t stop) {
            trace.clear();
            return ParentReplayStore(ReplayStoreFlow::RPC_SERVER,[&](uint32_t action) -> uint32_t {
                BOOST_CHECK_EQUAL(action,expected.at(trace.size()));
                trace.push_back(action);
                if (trace.size()==stop) throw std::runtime_error("RPC config fault");
                const auto next=trace.size()<expected.size() ? expected[trace.size()] : 0;
                switch (action) {
                case 1: return next==2;
                case 3: return next==5;
                case 6: return next==7;
                case 7: return next==10 ? 3 : 0;
                case 10: return next==9;
                default: return 1;
                }
            });
        };
        BOOST_CHECK_EQUAL(run(0),expected.back()==6 ? 1 : 0);
        BOOST_CHECK(trace==expected);
        for (size_t stop=1; stop<=expected.size(); ++stop) {
            BOOST_CHECK_THROW(run(stop),std::runtime_error);
            BOOST_CHECK(trace==std::vector<uint32_t>(expected.begin(),expected.begin()+stop));
        }
    }
}

BOOST_AUTO_TEST_CASE(authenticated_enforcer_executable_order)
{
    using namespace drivechain::haskell;
    for (uint32_t failure : {0U,1U,3U,5U,6U}) {
        std::vector<uint32_t> expected;
        for (uint32_t action : {1U,3U,5U,6U}) {
            expected.push_back(action);
            if (action==failure) {
                if (action!=5) expected.push_back(action+1);
                break;
            }
        }
        std::vector<uint32_t> trace;
        const auto invoke = [&](size_t stop) {
            trace.clear();
            return ParentReplayStore(ReplayStoreFlow::GRPC_EXECUTABLE, [&](uint32_t action) -> uint32_t {
                trace.push_back(action);
                if (trace.size()==stop) throw std::runtime_error("executable check fault");
                return action!=failure;
            });
        };
        BOOST_CHECK_EQUAL(invoke(0),failure==0 ? 1 : 0);
        BOOST_CHECK(trace==expected);
        for (size_t stop=1; stop<=expected.size(); ++stop) {
            BOOST_CHECK_THROW(invoke(stop),std::runtime_error);
            BOOST_CHECK(trace==std::vector<uint32_t>(expected.begin(),expected.begin()+stop));
        }
    }
}

BOOST_AUTO_TEST_CASE(authenticated_enforcer_configuration_fails_closed)
{
    using namespace drivechain::haskell;
    for (const auto windows : {false,true}) {
        const std::vector<uint32_t> path=windows ? std::vector<uint32_t>{1,13} : std::vector<uint32_t>{1,3,5,7,9,11};
        auto failures=path;
        failures.push_back(0);
        for (const auto failure : failures) {
            std::vector<uint32_t> expected;
            for (const auto action : path) {
                expected.push_back(action);
                if (action==failure) { expected.push_back(action+1); break; }
            }
            std::vector<uint32_t> trace;
            const auto run = [&](size_t stop) {
                trace.clear();
                return ParentReplayStore(ReplayStoreFlow::CREDENTIAL,[&](uint32_t action) -> uint32_t {
                    trace.push_back(action);
                    if (trace.size()==stop) throw std::runtime_error("credential fault");
                    if (action==failure) return 0;
                    return action==1 && windows ? 2 : 1;
                });
            };
            BOOST_CHECK_EQUAL(run(0),failure==0 ? 1 : 0);
            BOOST_CHECK(trace==expected);
            for (size_t stop=1; stop<=expected.size(); ++stop) {
                BOOST_CHECK_THROW(run(stop),std::runtime_error);
                BOOST_CHECK(trace==std::vector<uint32_t>(expected.begin(),expected.begin()+stop));
            }
        }
    }
    for (const bool configured : {false,true}) {
    const std::vector<uint32_t> checks = configured ?
        std::vector<uint32_t>{1,3,5,7,9,20,11,21,13,15,17,18,19} :
        std::vector<uint32_t>{1,3,5,7,9,11,13,15,17,18,19};
    for (const uint32_t failure : configured ? std::vector<uint32_t>{0,1,3,5,7,20,21,13,15,17,18,19} :
                                             std::vector<uint32_t>{0,1,3,5,7,13,15,17,18,19}) {
        std::vector<uint32_t> expected;
        for (const auto action : checks) {
            expected.push_back(action);
            if (action == failure) {
                if (action==20 || action==21) expected.push_back(action==20 ? 10 : 12);
                else if (action < 17) expected.push_back(action + 1);
                break;
            }
        }
        std::vector<uint32_t> actual;
        const auto reply = [&](uint32_t action) -> uint32_t {
            return action==failure ? 0 : action==5 ? 7 : (action==9 || action==11) ? configured : 1;
        };
        const auto status = ParentReplayStore(ReplayStoreFlow::GRPC_CONFIG, [&](uint32_t action) {
            actual.push_back(action);
            return reply(action);
        });
        BOOST_CHECK_EQUAL(status, failure == 0 ? 1 : 0);
        BOOST_CHECK(actual == expected);
        for (size_t stop = 0; stop < expected.size(); ++stop) {
            actual.clear();
            BOOST_CHECK_THROW(ParentReplayStore(ReplayStoreFlow::GRPC_CONFIG, [&](uint32_t action) {
                actual.push_back(action);
                if (actual.size() == stop + 1) throw std::runtime_error("TLS check fault");
                return reply(action);
            }), std::runtime_error);
            BOOST_CHECK(actual == std::vector<uint32_t>(expected.begin(), expected.begin() + stop + 1));
        }
    }
    }
    const fs::path tls_dir = m_path_root / "enforcer-tls";
    fs::create_directories(tls_dir);
    const fs::path ca = tls_dir / "ca.pem";
    const fs::path cert = tls_dir / "client.pem";
    const fs::path key = tls_dir / "client-key.pem";
    for (const fs::path& path : {ca, cert, key}) {
        std::ofstream file(path);
        BOOST_REQUIRE(file.is_open());
        file << "test credential\n";
    }
#ifndef WIN32
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(tls_dir).c_str(), 0700), 0);
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(ca).c_str(), 0600), 0);
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(cert).c_str(), 0600), 0);
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(key).c_str(), 0600), 0);
#endif

    ArgsManager args;
    args.ForceSetArg("-drivechainbmmgrpcaddr", "127.0.0.1:55051");
    args.ForceSetArg("-drivechainbmmgrpcca", fs::PathToString(ca));
    args.ForceSetArg("-drivechainbmmgrpccert", fs::PathToString(cert));
    args.ForceSetArg("-drivechainbmmgrpckey", fs::PathToString(key));
    std::string error;
    BOOST_CHECK_MESSAGE(ValidateDrivechainGrpcTLSConfig(args, &error), error);

    for (const auto& endpoint : {"miner.example:55051", "192.0.2.1:55051", "[2001:db8::1]:55051", "localhost:55051"}) {
        args.ForceSetArg("-drivechainbmmgrpcaddr", endpoint);
        args.ForceSetArg("-drivechainenforcerremote", "0");
        BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args, &error));
        args.ForceSetArg("-drivechainenforcerremote", "1");
        BOOST_CHECK_MESSAGE(ValidateDrivechainGrpcTLSConfig(args, &error), error);
    }
    for (const auto& endpoint : {"dns:///miner.example:55051", "unix:/tmp/socket", "miner..example:55051",
            "-miner.example:55051", "miner-.example:55051", "user@miner.example:55051",
            "miner.example/path:55051", "miner.example:0", "miner.example:65536"}) {
        args.ForceSetArg("-drivechainbmmgrpcaddr", endpoint);
        BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args, &error));
    }
    // Remote admission never skips credential checks.
    args.ForceSetArg("-drivechainbmmgrpcaddr", "miner.example:55051");
    args.ForceSetArg("-drivechainbmmgrpcca", fs::PathToString(tls_dir / "missing.pem"));
    BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args, &error));
    args.ForceSetArg("-drivechainbmmgrpcca", fs::PathToString(ca));
    args.ForceSetArg("-drivechainbmmgrpcaddr", "127.0.0.1:55051");
    args.ForceSetArg("-drivechainenforcerremote", "0");

    args.ForceSetArg("-drivechainpegoutenforcer", "127.0.0.1:55052");
    BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args, &error));
    BOOST_CHECK(error.find("same authenticated endpoint") != std::string::npos);

    args.ForceSetArg("-drivechainpegoutenforcer", "127.0.0.1:55051");
    BOOST_CHECK_MESSAGE(ValidateDrivechainGrpcTLSConfig(args, &error), error);

    args.ForceSetArg("-drivechainbmmgrpcaddr", "127.0.0.1:55051 injected");
    args.ForceSetArg("-drivechainpegoutenforcer", "127.0.0.1:55051 injected");
    BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args, &error));
    BOOST_CHECK(error.find("whitespace") != std::string::npos);

#ifndef WIN32
    args.ForceSetArg("-drivechainbmmgrpcaddr", "127.0.0.1:55051");
    args.ForceSetArg("-drivechainpegoutenforcer", "127.0.0.1:55051");
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(key).c_str(), 0644), 0);
    BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args, &error));
    BOOST_CHECK(error.find("deny all group and other access") != std::string::npos);
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(key).c_str(),0600),0);
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(tls_dir).c_str(),0770),0);
    BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args,&error));
    BOOST_CHECK(error.find("directory must be owned")!=std::string::npos);
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(tls_dir).c_str(),0700),0);
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(ca).c_str(),0664),0);
    BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args,&error));
    BOOST_CHECK(error.find("certificate must deny")!=std::string::npos);
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(ca).c_str(),0600),0);
    const auto alias=tls_dir/"key-link";
    fs::create_symlink(key,alias);
    args.ForceSetArg("-drivechainbmmgrpckey",fs::PathToString(alias));
    BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args,&error));
    BOOST_CHECK(error.find("non-symlink regular file")!=std::string::npos);
    args.ForceSetArg("-drivechainbmmgrpckey",fs::PathToString(key));
    BOOST_CHECK_MESSAGE(ValidateDrivechainGrpcTLSConfig(args,&error),error);
#endif
}

BOOST_AUTO_TEST_CASE(mainchain_cookie_is_private_and_canonical)
{
    const fs::path directory = m_path_root / "mainchain-cookie";
    fs::create_directories(directory);
    const fs::path cookie_path = directory / ".cookie";
    const std::string expected = "__cookie__:" + std::string(64, 'a');
    {
        std::ofstream output(cookie_path, std::ios::binary);
        output << expected << '\n';
        BOOST_REQUIRE(output.good());
    }
#ifndef WIN32
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(cookie_path).c_str(), 0600), 0);
#endif

    std::string cookie;
    std::string error;
    BOOST_CHECK(ReadMainchainAuthCookieFile(cookie_path, cookie, &error));
    BOOST_CHECK_EQUAL(cookie, expected);
    BOOST_CHECK(error.empty());

    {
        std::ofstream output(cookie_path, std::ios::binary | std::ios::trunc);
        output << "static-user:static-password\n";
        BOOST_REQUIRE(output.good());
    }
    BOOST_CHECK(!ReadMainchainAuthCookieFile(cookie_path, cookie, &error));
    BOOST_CHECK(error.find("canonical rotating") != std::string::npos);
    BOOST_CHECK(cookie.empty());

#ifndef WIN32
    {
        std::ofstream output(cookie_path, std::ios::binary | std::ios::trunc);
        output << expected << '\n';
        BOOST_REQUIRE(output.good());
    }
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(cookie_path).c_str(), 0644), 0);
    BOOST_CHECK(!ReadMainchainAuthCookieFile(cookie_path, cookie, &error));
    BOOST_CHECK(error.find("deny all group and other access") != std::string::npos);
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(cookie_path).c_str(), 0600), 0);

    const fs::path cookie_link = directory / "linked-cookie";
    fs::create_symlink(cookie_path, cookie_link);
    BOOST_CHECK(!ReadMainchainAuthCookieFile(cookie_link, cookie, &error));
    BOOST_CHECK(error.find("securely open") != std::string::npos);
    cookie = "must be cleared";
    BOOST_CHECK(!ReadMainchainAuthCookieFile(directory, cookie, &error));
    BOOST_CHECK(cookie.empty());
    BOOST_CHECK(error.find("not a regular file") != std::string::npos);
#endif
}

BOOST_AUTO_TEST_CASE(bounded_child_process_enforces_limits)
{
#ifndef WIN32
    const BoundedCommandResult success = RunBoundedCommand(
        {"/usr/bin/printf", "direct-argv"},
        std::chrono::seconds{1},
        128);
    BOOST_CHECK(success.started);
    BOOST_CHECK(success.exited);
    BOOST_CHECK_EQUAL(success.exit_code, 0);
    BOOST_CHECK_EQUAL(success.output, "direct-argv");

    const BoundedCommandResult timeout = RunBoundedCommand(
        {"/bin/sleep", "2"},
        std::chrono::milliseconds{25},
        128);
    BOOST_CHECK(timeout.started);
    BOOST_CHECK(timeout.exited);
    BOOST_CHECK(timeout.timed_out);

    const BoundedCommandResult bounded_output = RunBoundedCommand(
        {"/usr/bin/yes", "x"},
        std::chrono::seconds{1},
        64);
    BOOST_CHECK(bounded_output.started);
    BOOST_CHECK(bounded_output.exited);
    BOOST_CHECK(bounded_output.output_truncated);
    BOOST_CHECK_EQUAL(bounded_output.output.size(), 64U);
#endif
}

BOOST_AUTO_TEST_CASE(rejects_mismatched_txid_vout_address_and_value)
{
    drivechain::AuthenticatedDeposit authenticated;
    std::string error;

    BOOST_CHECK(!Authenticate(
        authenticated,
        error,
        MainchainInfo(),
        EnforcerChainInfo(),
        EnforcerTip(),
        Sidechains(),
        TwoWayPegData(),
        Ctip(),
        Params().NetworkIDString(),
        Identity(),
        COutPoint(Txid::FromUint256(uint256S("01")), 0),
        2000));
    BOOST_CHECK(error.find("absent") != std::string::npos);

    BOOST_CHECK(!Authenticate(
        authenticated,
        error,
        MainchainInfo(),
        EnforcerChainInfo(),
        EnforcerTip(),
        Sidechains(),
        TwoWayPegData(),
        Ctip(),
        Params().NetworkIDString(),
        Identity(),
        COutPoint(Txid::FromUint256(uint256S(DEPOSIT_TXID)), 1),
        2000));
    BOOST_CHECK(error.find("absent") != std::string::npos);

    BOOST_CHECK(!Authenticate(
        authenticated,
        error,
        MainchainInfo(),
        EnforcerChainInfo(),
        EnforcerTip(),
        Sidechains(),
        TwoWayPegData(),
        Ctip(),
        Params().NetworkIDString(),
        Identity(),
        COutPoint(Txid::FromUint256(uint256S(DEPOSIT_TXID)), 0),
        1999));
    BOOST_CHECK(error.find("value") != std::string::npos);

    BOOST_REQUIRE_MESSAGE(Authenticate(authenticated, error), error);
    const CTransaction wrong_destination(
        DepositTransaction(authenticated, CScript() << OP_TRUE));
    BOOST_CHECK(!drivechain::VerifyDepositTransaction(wrong_destination, 0, authenticated, error));
    BOOST_CHECK(error.find("destination script") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(rejects_stale_or_contradictory_ctip)
{
    drivechain::AuthenticatedDeposit authenticated;
    std::string error;
    BOOST_CHECK(!Authenticate(
        authenticated,
        error,
        MainchainInfo(),
        EnforcerChainInfo(),
        EnforcerTip(),
        Sidechains(),
        TwoWayPegData(),
        Ctip(DEPOSIT_TXID, 14'400'000, 7)));
    BOOST_CHECK(error.find("predates") != std::string::npos);

    BOOST_CHECK(!Authenticate(
        authenticated,
        error,
        MainchainInfo(),
        EnforcerChainInfo(),
        EnforcerTip(),
        Sidechains(),
        TwoWayPegData(),
        Ctip(NEXT_CTIP_TXID, 14'402'000, 8)));
    BOOST_CHECK(error.find("does not match") != std::string::npos);

    BOOST_CHECK(Authenticate(
        authenticated,
        error,
        MainchainInfo(),
        EnforcerChainInfo(),
        EnforcerTip(),
        Sidechains(),
        TwoWayPegData(),
        Ctip(NEXT_CTIP_TXID, 14'401'000, 9)));
    BOOST_CHECK_EQUAL(authenticated.current_ctip_sequence, 9);
}

BOOST_AUTO_TEST_CASE(rejects_alternate_slot_identity_and_networks)
{
    drivechain::AuthenticatedDeposit authenticated;
    std::string error;

    BOOST_CHECK(!Authenticate(
        authenticated,
        error,
        MainchainInfo(),
        EnforcerChainInfo(),
        EnforcerTip(),
        Sidechains(23),
        TwoWayPegData(),
        Ctip()));
    BOOST_CHECK(error.find("slot") != std::string::npos);

    BOOST_CHECK(!Authenticate(
        authenticated,
        error,
        MainchainInfo(),
        EnforcerChainInfo(),
        EnforcerTip(),
        Sidechains(24, "Not Elements"),
        TwoWayPegData(),
        Ctip()));
    BOOST_CHECK(error.find("identity") != std::string::npos);

    BOOST_CHECK(!Authenticate(authenticated, error, MainchainInfo("regtest")));
    BOOST_CHECK(error.find("mainchain network") != std::string::npos);
    BOOST_CHECK(!Authenticate(
        authenticated,
        error,
        MainchainInfo("signet", "51")));
    BOOST_CHECK(error.find("challenge") != std::string::npos);
    BOOST_CHECK(!Authenticate(
        authenticated,
        error,
        MainchainInfo(),
        EnforcerChainInfo("NETWORK_REGTEST")));
    BOOST_CHECK(error.find("enforcer network") != std::string::npos);
    BOOST_CHECK(!Authenticate(
        authenticated,
        error,
        MainchainInfo(),
        EnforcerChainInfo(),
        EnforcerTip(),
        Sidechains(),
        TwoWayPegData(),
        Ctip(),
        "alternate-sidechain"));
    BOOST_CHECK(error.find("sidechain network") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(rejects_missing_enforcer_data_and_confirmation_loss)
{
    drivechain::AuthenticatedDeposit authenticated;
    std::string error;
    const UniValue missing;

    BOOST_CHECK(!Authenticate(
        authenticated,
        error,
        MainchainInfo(),
        missing));
    BOOST_CHECK(!Authenticate(
        authenticated,
        error,
        MainchainInfo(),
        EnforcerChainInfo(),
        missing));
    BOOST_CHECK(!Authenticate(
        authenticated,
        error,
        MainchainInfo(),
        EnforcerChainInfo(),
        EnforcerTip(),
        missing));
    BOOST_CHECK(!Authenticate(
        authenticated,
        error,
        MainchainInfo(),
        EnforcerChainInfo(),
        EnforcerTip(),
        Sidechains(),
        TwoWayPegData(DEPOSIT_TXID, 0, TestDepositAddress(), 2000, 8, false)));
    BOOST_CHECK(error.find("absent") != std::string::npos);
    BOOST_CHECK(!Authenticate(
        authenticated,
        error,
        MainchainInfo(),
        EnforcerChainInfo(),
        EnforcerTip(),
        Sidechains(),
        TwoWayPegData(),
        missing));

    BOOST_REQUIRE_MESSAGE(Authenticate(authenticated, error), error);
    const UniValue reorged = ParseJson(strprintf(
        R"json({"hash":"%s","height":90,"confirmations":-1})json",
        DEPOSIT_BLOCK));
    BOOST_CHECK(!drivechain::VerifyDepositBlockConfirmation(reorged, authenticated, error));
    BOOST_CHECK(error.find("no longer confirmed") != std::string::npos);
    BOOST_CHECK(!drivechain::VerifyDepositBlockConfirmation(
        ParseJson(R"json({"height":90,"confirmations":11})json"),
        authenticated,
        error));
    BOOST_CHECK(error.find("hash is missing") != std::string::npos);
    BOOST_CHECK(!drivechain::VerifyCurrentCtipOutput(
        ParseJson(R"json({"value":0.14401000,"confirmations":2})json"),
        authenticated,
        error));
    BOOST_CHECK(error.find("value") != std::string::npos);
    BOOST_CHECK(!drivechain::VerifyCurrentCtipOutput(
        ParseJson(R"json({"value":0.14402000,"confirmations":0})json"),
        authenticated,
        error));
    BOOST_CHECK(error.find("not confirmed") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(rejects_value_smuggling_and_persists_replay_state)
{
    drivechain::AuthenticatedDeposit authenticated;
    std::string error;
    BOOST_REQUIRE_MESSAGE(Authenticate(authenticated, error), error);

    CMutableTransaction wrong_total = DepositTransaction(
        authenticated,
        authenticated.destination_script,
        1800,
        100);
    BOOST_CHECK(!drivechain::VerifyDepositTransaction(
        CTransaction(wrong_total),
        0,
        authenticated,
        error));
    BOOST_CHECK(error.find("value and fee") != std::string::npos);

    CMutableTransaction extra_input = DepositTransaction(
        authenticated,
        authenticated.destination_script);
    extra_input.vin.emplace_back(COutPoint(Txid::FromUint256(uint256S("01")), 0));
    extra_input.witness.vtxinwit.resize(2);
    BOOST_CHECK(!drivechain::VerifyDepositTransaction(
        CTransaction(extra_input),
        0,
        authenticated,
        error));
    BOOST_CHECK(error.find("exactly one input") != std::string::npos);

    const CTransaction valid_tx(DepositTransaction(authenticated, authenticated.destination_script));
    const auto replay_key = GetPeginSpentKey(
        valid_tx.witness.vtxinwit[0].m_pegin_witness,
        valid_tx.vin[0].prevout);
    RestartablePeginView persistent;
    {
        CCoinsViewCache first_process(&persistent);
        BOOST_CHECK(!first_process.IsPeginSpent(replay_key));
        first_process.SetPeginSpent(replay_key, true);
        BOOST_REQUIRE(first_process.Flush());
    }
    {
        CCoinsViewCache restarted_process(&persistent);
        BOOST_CHECK(restarted_process.IsPeginSpent(replay_key));
        const auto other_vout = std::make_pair(
            replay_key.first,
            COutPoint(replay_key.second.hash, replay_key.second.n + 1));
        BOOST_CHECK(!restarted_process.IsPeginSpent(other_vout));
    }
}

BOOST_AUTO_TEST_CASE(haskell_deterministic_evidence_codec_boundaries)
{
    DeterministicFixture fixture;
    const auto& valid = fixture.transaction->witness.vtxinwit[0].m_pegin_witness;
    const auto& outpoint = fixture.transaction->vin[0].prevout;
    std::string error;
    DrivechainDepositEvidence decoded;
    BOOST_REQUIRE_MESSAGE(GetDrivechainDepositEvidence(valid, outpoint, decoded, error), error);
    BOOST_CHECK(decoded.deposit_tx == fixture.evidence.deposit_tx);
    BOOST_CHECK(decoded.txout_proof == fixture.evidence.txout_proof);
    BOOST_CHECK(decoded.previous_ctip_tx == fixture.evidence.previous_ctip_tx);
    BOOST_CHECK(Serialize(decoded.headers) == Serialize(fixture.evidence.headers));
    BOOST_CHECK_EQUAL(decoded.sequence_number, 9);
    BOOST_CHECK_EQUAL(decoded.previous_sequence_number, 8);
    const auto reject = [&](const CScriptWitness& changed, const char* message) {
        decoded.sequence_number = -999;
        error.clear();
        BOOST_CHECK(!GetDrivechainDepositEvidence(changed, outpoint, decoded, error));
        BOOST_CHECK_MESSAGE(error.find(message) != std::string::npos, error);
        BOOST_CHECK_EQUAL(decoded.sequence_number, -999);
    };
    auto changed = valid;
    changed.stack.pop_back();
    reject(changed, "deterministic v2");
    changed = valid;
    changed.stack[4].push_back(0);
    reject(changed, "deterministic v2");
    for (const size_t field : {5, 6, 7, 10}) {
        changed = valid;
        changed.stack[field].clear();
        reject(changed, "consensus bound");
        changed.stack[field].resize(field == 10 ? 2017 * 80 + 17 : MAX_BLOCK_SERIALIZED_SIZE + 1);
        reject(changed, "consensus bound");
    }
    changed = valid;
    changed.stack[5].push_back(0);
    reject(changed, "txid is invalid");
    changed = valid;
    changed.stack[5][0] ^= 1;
    reject(changed, "txid is invalid");
    for (const size_t field : {8, 9, 10}) {
        changed = valid;
        changed.stack[field].push_back(0);
        reject(changed, "non-canonical");
        changed = valid;
        changed.stack[field].pop_back();
        reject(changed, "non-canonical");
    }
    for (const auto [current, previous] : std::array<std::pair<int64_t, int64_t>, 5>{{
             {-1, 0}, {0, -1}, {9, 9}, {10, 8}, {0, std::numeric_limits<int64_t>::max()}}}) {
        changed = valid;
        changed.stack[8] = Serialize(current);
        changed.stack[9] = Serialize(previous);
        reject(changed, "sequence transition");
    }
    changed = valid;
    changed.stack[8] = Serialize(std::numeric_limits<int64_t>::max());
    changed.stack[9] = Serialize(std::numeric_limits<int64_t>::max() - 1);
    BOOST_CHECK_MESSAGE(GetDrivechainDepositEvidence(changed, outpoint, decoded, error), error);
    auto headers = fixture.evidence.headers;
    headers.clear();
    changed = valid;
    changed.stack[10] = Serialize(headers);
    reject(changed, "header chain length");
    headers.resize(2017, fixture.evidence.headers[0]);
    changed.stack[10] = Serialize(headers);
    BOOST_REQUIRE_MESSAGE(GetDrivechainDepositEvidence(changed, outpoint, decoded, error), error);
    BOOST_CHECK_EQUAL(decoded.headers.size(), 2017);
    headers.push_back(headers.back());
    changed.stack[10] = Serialize(headers);
    reject(changed, "consensus bound");
    changed = valid;
    changed.stack[10] = {0xfd, 1, 0}; // Non-minimal CompactSize, followed by a valid header.
    const auto header = Serialize(fixture.evidence.headers[0]);
    changed.stack[10].insert(changed.stack[10].end(), header.begin(), header.end());
    reject(changed, "non-canonical");
}

BOOST_AUTO_TEST_CASE(validates_persisted_v2_evidence_without_external_services)
{
    RestartablePeginView persistent;
    std::string error;
    {
        CCoinsViewCache view(&persistent);
        const CTransaction checkpoint = LegacyPublicDeposit();
        BOOST_REQUIRE_MESSAGE(
            drivechain::VerifyDeterministicDeposit(checkpoint, 0, view, error),
            error);
        BOOST_REQUIRE_MESSAGE(
            drivechain::VerifyDepositEvidenceAnchor(
                checkpoint,
                0,
                uint256S("000001d9988239435d51e763fd4231893dad22d7d03048266a5e21361e2db065"),
                error),
            error);
        BOOST_REQUIRE_MESSAGE(
            drivechain::ConnectDepositState(checkpoint, 0, view, 2, error),
            error);
        BOOST_REQUIRE(view.Flush());
    }

    DeterministicFixture fixture;
    {
        CCoinsViewCache restarted(&persistent);
        drivechain::CtipState state;
        BOOST_REQUIRE(drivechain::GetCtipState(restarted, state, &error));
        BOOST_CHECK_EQUAL(state.sequence_number, 8);
        BOOST_CHECK_EQUAL(state.value, 14'402'000);
        BOOST_REQUIRE_MESSAGE(
            drivechain::VerifyDeterministicDeposit(
                *fixture.transaction,
                0,
                restarted,
                error),
            error);
        BOOST_REQUIRE_MESSAGE(
            drivechain::VerifyDepositEvidenceAnchor(
                *fixture.transaction,
                0,
                fixture.anchor,
                error),
            error);
        BOOST_CHECK(!drivechain::VerifyDepositEvidenceAnchor(
            *fixture.transaction,
            0,
            uint256S("02"),
            error));
        BOOST_REQUIRE_MESSAGE(
            drivechain::ConnectDepositState(
                *fixture.transaction,
                0,
                restarted,
                3,
                error),
            error);
        BOOST_REQUIRE(restarted.Flush());
    }

    {
        CCoinsViewCache restarted(&persistent);
        drivechain::CtipState state;
        BOOST_REQUIRE(drivechain::GetCtipState(restarted, state, &error));
        BOOST_CHECK_EQUAL(state.sequence_number, 9);
        BOOST_CHECK_EQUAL(state.value, 14'404'000);
        BOOST_CHECK(!drivechain::VerifyDeterministicDeposit(
            *fixture.transaction,
            0,
            restarted,
            error));
        BOOST_CHECK(error.find("stale") != std::string::npos);
        BOOST_REQUIRE_MESSAGE(
            drivechain::DisconnectDepositState(
                *fixture.transaction,
                0,
                restarted,
                3,
                error),
            error);
        BOOST_REQUIRE(restarted.Flush());
    }

    CCoinsViewCache rolled_back(&persistent);
    drivechain::CtipState restored;
    BOOST_REQUIRE(drivechain::GetCtipState(rolled_back, restored, &error));
    BOOST_CHECK_EQUAL(restored.sequence_number, 8);
    BOOST_CHECK_EQUAL(restored.value, 14'402'000);
}

BOOST_AUTO_TEST_CASE(treasury_workflow_preserves_multiple_deposits_and_exception_prefixes)
{
    namespace hs = drivechain::haskell;
    using Event = std::pair<uint32_t,uint64_t>;
    const auto reply = [](uint32_t step,uint64_t index) -> int64_t {
        switch (step) {
        case 0:
            switch (index) {
            case 0: return 1;
            case 1: case 2: return 2;
            case 3: case 6: return 0;
            case 4: return 100;
            case 5: return 120;
            case 7: return 7;
            default: throw std::logic_error("unexpected treasury fact");
            }
        case 102: case 503: return 100;
        case 304: case 505: return 120;
        case 302: return index % 2 == 0;
        case 704: return 32;
        default: return 1;
        }
    };
    std::vector<Event> trace;
    BOOST_CHECK_EQUAL(hs::ReplayTreasuryTransaction(1,1,4,1000,100,true,[&](uint32_t s,uint64_t i) {
        trace.emplace_back(s,i);
        return reply(s,i);
    }),0);
    BOOST_CHECK_EQUAL(std::count(trace.begin(),trace.end(),Event{705,20}),2);
    BOOST_CHECK_EQUAL(std::count(trace.begin(),trace.end(),Event{800,1}),1);
    struct NativeFailure : std::logic_error { NativeFailure() : std::logic_error("native marker") {} };
    for (size_t fault = 0; fault < trace.size(); ++fault) {
        std::vector<Event> observed;
        BOOST_CHECK_THROW(hs::ReplayTreasuryTransaction(1,1,4,1000,100,true,[&](uint32_t s,uint64_t i) {
            observed.emplace_back(s,i);
            if (observed.size() == fault+1) throw NativeFailure{};
            return reply(s,i);
        }),NativeFailure);
        BOOST_CHECK_EQUAL(observed.size(),fault+1);
        BOOST_CHECK(std::equal(observed.begin(),observed.end(),trace.begin()));
    }
}

BOOST_AUTO_TEST_CASE(deposit_verification_preserves_native_branch_transcript)
{
    using Step = drivechain::haskell::DepositVerifyStep;
    for (uint32_t flags = 0; flags < 1024; ++flags) {
        std::vector<uint32_t> expected, actual;
        const auto prior = [&](uint32_t step) {
            expected.push_back(step);
            return (flags & (1U << (step - 1))) != 0;
        };
        const auto reference = [&] {
            if (prior(1)) return prior(2) && prior(3) && prior(4);
            if (prior(5) && prior(6)) { prior(7); return false; }
            return prior(8) && prior(9) && prior(10);
        };
        const bool want = reference();
        const bool got = drivechain::haskell::RunDepositVerification([&](Step step) {
            const auto index = static_cast<uint32_t>(step);
            actual.push_back(index);
            return (flags & (1U << (index - 1))) != 0;
        });
        BOOST_CHECK_EQUAL(got, want);
        BOOST_CHECK(actual == expected);
    }
}

BOOST_AUTO_TEST_CASE(deposit_anchor_preserves_native_branch_transcript)
{
    using Step = drivechain::haskell::DepositVerifyStep;
    for (uint32_t flags = 0; flags < 128; ++flags) {
        std::vector<uint32_t> expected, actual;
        const auto outcome = [&](uint32_t step) { return step == 7 || (flags & (1U << (step - 12))) != 0; };
        const auto prior = [&](uint32_t step) { expected.push_back(step); return outcome(step); };
        const auto reference = [&] {
            if (prior(12)) return prior(13);
            if (prior(14) && prior(15)) { prior(7); return false; }
            if (!prior(16)) return false;
            if (!prior(17)) { prior(18); return false; }
            return true;
        };
        const bool want = reference();
        const bool got = drivechain::haskell::RunDepositVerification([&](Step step) {
            const auto index = static_cast<uint32_t>(step);
            actual.push_back(index);
            return outcome(index);
        }, true);
        BOOST_CHECK_EQUAL(got, want);
        BOOST_CHECK(actual == expected);
    }
}

BOOST_AUTO_TEST_CASE(deposit_lifecycle_preserves_order_and_terminal_publication)
{
    using Step = drivechain::haskell::DepositVerifyStep;
    for (bool undo : {false, true}) {
        for (uint32_t flags = 0; flags < 128; ++flags) {
            std::vector<uint32_t> expected, actual;
            const auto outcome = [&](uint32_t step) { return (flags & (1U << (step - (undo ? 28 : 20)))) != 0; };
            const auto prior = [&](uint32_t step) { expected.push_back(step); return outcome(step); };
            const auto reference = [&] {
                if (!undo) {
                    if (prior(20)) return prior(21) && prior(22) && prior(23);
                    return prior(24) && prior(25) && prior(26);
                }
                if (!prior(28)) return false;
                if (prior(29)) return prior(30) && prior(31);
                return prior(32) && prior(33) && prior(34);
            };
            const bool want = reference();
            const bool got = drivechain::haskell::RunDepositLifecycle([&](Step step) {
                const auto index = static_cast<uint32_t>(step);
                actual.push_back(index);
                return outcome(index);
            }, undo);
            BOOST_CHECK_EQUAL(got, want);
            BOOST_CHECK(actual == expected);
            for (size_t failure = 0; failure < expected.size(); ++failure) {
                size_t calls{0};
                BOOST_CHECK_THROW(drivechain::haskell::RunDepositLifecycle([&](Step step) {
                    if (calls++ == failure) throw std::runtime_error("lifecycle fault");
                    return outcome(static_cast<uint32_t>(step));
                }, undo), std::runtime_error);
                BOOST_CHECK_EQUAL(calls, failure + 1);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(deposit_parsing_preserves_order_and_terminal_publication)
{
    using Step = drivechain::haskell::DepositVerifyStep;
    constexpr std::array<uint32_t, 9> decisions{36, 37, 39, 40, 41, 42, 44, 48, 49};
    for (uint32_t flags = 0; flags < 512; ++flags) {
        std::vector<uint32_t> expected, actual;
        const auto outcome = [&](uint32_t step) {
            const auto it = std::find(decisions.begin(), decisions.end(), step);
            return it == decisions.end() || (flags & (1U << std::distance(decisions.begin(), it))) != 0;
        };
        const auto prior = [&](uint32_t step) { expected.push_back(step); return outcome(step); };
        const auto reference = [&] {
            if (!prior(36) || !prior(37)) { prior(38); return false; }
            if (!prior(39)) return false;
            if (!prior(40) || !prior(41) || !prior(42)) { prior(43); return false; }
            if (!prior(44)) return false;
            prior(45); prior(46); prior(47);
            return prior(48) && prior(49) && prior(50);
        };
        const bool want = reference();
        const bool got = drivechain::haskell::RunDepositParsing([&](Step step) {
            const auto index = static_cast<uint32_t>(step);
            actual.push_back(index);
            return outcome(index);
        });
        BOOST_CHECK_EQUAL(got, want);
        BOOST_CHECK(actual == expected);
    }
}

BOOST_AUTO_TEST_CASE(ctip_input_scan_preserves_guards_count_and_last_match)
{
    using Step = drivechain::haskell::DepositVerifyStep;
    for (size_t size = 0; size <= 3; ++size) {
        for (uint32_t bits = 0; bits < (1U << (3 * size)); ++bits) {
            std::vector<uint32_t> expected, actual;
            size_t want_count{0}, want_last{0}, count{0}, last{0}, index{0};
            for (size_t i = 0; i < size; ++i) {
                const auto flags = (bits >> (3 * i)) & 7;
                expected.insert(expected.end(), {52, 53});
                if (flags & 1) {
                    expected.push_back(54);
                    if (flags & 2) {
                        expected.push_back(55);
                        if (flags & 4) { expected.push_back(56); ++want_count; want_last = i; }
                    }
                }
                expected.push_back(57);
            }
            expected.insert(expected.end(), {52, 58, want_count ? 59U : 60U});
            drivechain::haskell::RunCtipInputScan([&](Step step) {
                actual.push_back(static_cast<uint32_t>(step));
                switch (step) {
                case Step::SCAN_BOUNDS: return index < size;
                case Step::SCAN_HASH: return ((bits >> (3 * index)) & 1) != 0;
                case Step::SCAN_OUTPUT_BOUNDS: return ((bits >> (3 * index)) & 2) != 0;
                case Step::SCAN_SCRIPT: return ((bits >> (3 * index)) & 4) != 0;
                case Step::SCAN_MATCH: ++count; last = index; return true;
                case Step::SCAN_ADVANCE: ++index; return true;
                case Step::SCAN_PRESENT: return count != 0;
                case Step::SCAN_VALUE: case Step::SCAN_EMPTY: return true;
                default: throw std::logic_error("unexpected CTIP scan action");
                }
            });
            BOOST_CHECK_EQUAL(count, want_count);
            BOOST_CHECK_EQUAL(last, want_last);
            BOOST_CHECK(actual == expected);
        }
    }
}

BOOST_AUTO_TEST_CASE(deposit_authentication_preserves_checks_and_publication)
{
    using Step = drivechain::haskell::DepositVerifyStep;
    for (uint32_t flags = 0; flags < 32; ++flags) {
        std::vector<uint32_t> expected, actual;
        bool want{true};
        for (uint32_t step = 62; step <= 66; ++step) {
            expected.push_back(step);
            if (!(flags & (1U << (step - 62)))) { want = false; break; }
        }
        const bool got = drivechain::haskell::RunDepositAuthentication([&](Step step) {
            const auto index = static_cast<uint32_t>(step);
            actual.push_back(index);
            return (flags & (1U << (index - 62))) != 0;
        });
        BOOST_CHECK_EQUAL(got, want);
        BOOST_CHECK(actual == expected);
    }
    for (uint32_t failure = 62; failure <= 66; ++failure) {
        uint32_t calls{0};
        bool published{false};
        try {
            drivechain::haskell::RunDepositAuthentication([&](Step step) {
                ++calls;
                if (static_cast<uint32_t>(step) == failure) throw 42;
                if (step == Step::AUTH_PUBLISH) published = true;
                return true;
            });
            BOOST_FAIL("authentication exception was swallowed");
        } catch (int value) { BOOST_CHECK_EQUAL(value, 42); }
        BOOST_CHECK_EQUAL(calls, failure - 61);
        BOOST_CHECK(!published);
    }
}

BOOST_AUTO_TEST_CASE(deposit_projection_preserves_shape_gates_and_output_reads)
{
    for (uint64_t inputs : std::array<uint64_t, 4>{0, 1, 2, UINT64_MAX})
    for (uint64_t index : std::array<uint64_t, 3>{0, 1, UINT64_MAX})
    for (uint64_t witnesses : std::array<uint64_t, 4>{0, 1, 2, UINT64_MAX})
    for (uint64_t facts = 0; facts <= 16; ++facts)
    for (uint64_t outputs : std::array<uint64_t, 5>{0, 1, 2, 3, UINT64_MAX}) {
        std::vector<uint32_t> expected{1}, actual;
        if (inputs == 1) {
            expected.push_back(2);
            if (index == 0) {
                expected.push_back(3);
                if (witnesses == 1) {
                    expected.push_back(4);
                    if (facts == 15) expected.push_back(5);
                }
            }
        }
        expected.push_back(7);
        if (outputs > 0) {
            expected.insert(expected.end(), {8, 9});
            if (outputs > 1) expected.push_back(10);
        }
        drivechain::haskell::DepositTransactionFacts([&](uint32_t step) -> uint64_t {
            actual.push_back(step);
            switch (step) {
            case 1: return inputs;
            case 2: return index;
            case 3: return witnesses;
            case 4: return facts;
            case 7: case 9: return outputs;
            case 5: case 8: case 10: return 0;
            default: throw std::logic_error("unexpected projection action");
            }
        });
        BOOST_CHECK(actual == expected);
    }
}

BOOST_AUTO_TEST_CASE(deposit_claim_workflow_matches_original_native_projection)
{
    const auto base = LegacyPublicDeposit();
    for (unsigned mutation = 0; mutation <= 30; ++mutation) {
        BOOST_TEST_CONTEXT("claim mutation " << mutation) {
            CMutableTransaction tx(base);
            drivechain::AuthenticatedDeposit authenticated;
            authenticated.outpoint = base.vin[0].prevout;
            authenticated.value = 2000;
            authenticated.destination_script = base.vout[0].scriptPubKey;
            size_t index{0};
            auto& stack = tx.witness.vtxinwit[0].m_pegin_witness.stack;
            switch (mutation) {
            case 1: tx.vin.clear(); tx.witness.vtxinwit.clear(); break;
            case 2: tx.vin.resize(2); break;
            case 3: index = 1; break;
            case 4: tx.witness.vtxinwit.clear(); break;
            case 5: tx.vin.resize(2); tx.witness.vtxinwit.resize(2); break;
            case 6: tx.vin[0].m_is_pegin = false; break;
            case 7: authenticated.outpoint.n = 1; break;
            case 8: tx.vin[0].scriptSig << OP_TRUE; break;
            case 9: tx.vin[0].assetIssuance.nAmount = CConfidentialValue(1); break;
            case 10: stack[0] = Serialize(int64_t{2001}); break;
            case 11: stack[1].assign(32,0); break;
            case 12: stack[2].assign(32,0); break;
            case 13: stack[3] = {OP_FALSE}; break;
            case 14: stack[4] = {}; break;
            case 15: stack[5].assign(32,0); break;
            case 16: authenticated.value = 2001; break;
            case 17: tx.vout.clear(); tx.witness.vtxoutwit.clear(); break;
            case 18: tx.vout.push_back(tx.vout[0]); break;
            case 19: tx.vout[0].nAsset = CConfidentialAsset(CAsset()); break;
            case 20: tx.vout[0].nValue = CConfidentialValue(0); break;
            case 21: tx.vout[0].scriptPubKey = CScript() << OP_TRUE; break;
            case 22: tx.vout[1].nValue = CConfidentialValue(-1); break;
            case 23: std::swap(tx.vout[0],tx.vout[1]); break;
            case 24: tx.vout.resize(1); tx.witness.vtxoutwit.resize(1); tx.vout[0].nValue = CConfidentialValue(2000); break;
            case 25: tx.vout[1].scriptPubKey = tx.vout[0].scriptPubKey; break;
            case 26: tx.vout[0].scriptPubKey.clear(); break;
            case 27: tx.vout[0].nValue = CConfidentialValue(1999); tx.vout[1].nValue = CConfidentialValue(1); break;
            case 28: authenticated.outpoint.hash = Txid{}; stack[0].clear(); break;
            case 29: stack.resize(8); break;
            case 30: index = SIZE_MAX; break;
            }
            const CTransaction changed(tx);
            std::string wanted_error{"unchanged"}, actual_error{"unchanged"};
            const bool wanted = ReferenceVerifyDepositTransaction(changed,index,authenticated,wanted_error);
            const bool actual = drivechain::VerifyDepositTransaction(changed,index,authenticated,actual_error);
            if (mutation == 0) BOOST_REQUIRE(wanted);
            BOOST_CHECK_EQUAL(actual,wanted);
            BOOST_CHECK_EQUAL(actual_error,wanted_error);
        }
    }
}

BOOST_AUTO_TEST_CASE(withdrawal_status_traversal_preserves_filters_and_errors)
{
    for (bool valid : {false, true})
    for (bool present : {false, true})
    for (uint32_t flags = 0; flags < 512; ++flags) {
        std::vector<uint32_t> expected, actual;
        bool consumed{false};
        const auto outcome = [&](uint32_t step) {
            switch (step) {
            case 1: return valid;
            case 2: case 14: case 17: return true;
            case 3: case 11: case 15: return false;
            case 4: return present && !consumed;
            case 16: consumed = true; return true;
            default: return (flags & (1U << (step - 5))) != 0;
            }
        };
        const auto read = [&](uint32_t step) { expected.push_back(step); return outcome(step); };
        const auto reference = [&] {
            if (!read(1)) { read(3); return false; }
            read(2);
            while (read(4)) {
                if (!read(5) || !read(6) || !read(7) || !read(8)) { read(16); continue; }
                if (!read(9) || !read(10)) { read(11); return false; }
                if (!read(12)) { read(16); continue; }
                if (!read(13)) { read(15); return false; }
                read(14); read(16);
            }
            return read(17);
        };
        const bool want = reference();
        consumed = false;
        bool got{true};
        try {
            drivechain::haskell::WithdrawalStatusFlow([&](uint32_t step) {
                actual.push_back(step);
                return outcome(step);
            });
        } catch (const std::runtime_error&) { got = false; }
        BOOST_CHECK_EQUAL(got, want);
        BOOST_CHECK(actual == expected);
    }
}

BOOST_AUTO_TEST_CASE(l1_normalization_preserves_original_branch_transcripts)
{
    constexpr std::array<uint32_t, 13> decisions{1,4,5,8,9,12,13,14,17,19,21,28,30};
    for (uint32_t flags = 0; flags < (1U << decisions.size()); ++flags) {
        std::vector<uint32_t> expected, actual;
        bool block_done{false}, event_done{false};
        const auto outcome = [&](uint32_t step) {
            if (step == 3 || step == 7 || step == 11 || step == 15 || step == 33) return false;
            if (step == 10) event_done = false;
            if (step == 31) event_done = true;
            if (step == 32) block_done = true;
            const auto it = std::find(decisions.begin(), decisions.end(), step);
            const bool flag = it == decisions.end() || (flags & (1U << std::distance(decisions.begin(), it))) != 0;
            return flag && !(step == 4 && block_done) && !(step == 12 && event_done);
        };
        const auto read = [&](uint32_t step) { expected.push_back(step); return outcome(step); };
        const auto reference = [&] {
            if (!read(1)) { read(3); return false; }
            read(2);
            while (read(4)) {
                if (!read(5)) { read(7); return false; }
                read(6);
                if (read(8)) { read(32); continue; }
                if (!read(9)) { read(11); return false; }
                read(10);
                while (read(12)) {
                    if (!read(13)) { read(15); return false; }
                    if (read(14)) read(16);
                    else if (read(17)) {
                        read(18);
                        if (read(19)) read(20);
                        if (read(21)) read(22);
                        read(23);
                    } else { read(31); continue; }
                    read(27);
                    if (read(28)) read(29);
                    else if (!read(30)) { read(33); return false; }
                    read(31);
                }
                read(32);
            }
            return read(34);
        };
        const bool want = reference();
        block_done = event_done = false;
        bool got{true};
        try {
            drivechain::haskell::L1NormalizationFlow([&](uint32_t step) {
                actual.push_back(step);
                return outcome(step);
            });
        } catch (const std::runtime_error&) { got = false; }
        BOOST_CHECK_EQUAL(got, want);
        BOOST_CHECK(actual == expected);
    }
}

BOOST_AUTO_TEST_CASE(sidechain_event_traversal_preserves_guard_and_emission_order)
{
    constexpr std::array<uint32_t, 13> decisions{1,2,4,6,7,8,11,12,13,14,15,16,18};
    for (uint32_t flags = 0; flags < (1U << decisions.size()); ++flags) {
        std::vector<uint32_t> expected, actual;
        bool tx_done{false}, input_done{false}, output_done{false};
        const auto outcome = [&](uint32_t step) {
            if (step == 5) input_done = output_done = false;
            if (step == 10) input_done = true;
            if (step == 25) output_done = true;
            if (step == 26) tx_done = true;
            const auto it = std::find(decisions.begin(), decisions.end(), step);
            const bool flag = it == decisions.end() || (flags & (1U << std::distance(decisions.begin(), it))) != 0;
            return flag && !(step == 4 && tx_done) && !(step == 6 && input_done) && !(step == 11 && output_done);
        };
        const auto read = [&](uint32_t step) { expected.push_back(step); return outcome(step); };
        if (read(1) && read(2)) read(3);
        while (read(4)) {
            read(5);
            while (read(6)) {
                if (read(7) && read(8)) read(9);
                read(10);
            }
            while (read(11)) {
                if (read(12) && read(13) && read(14) && read(15) && read(16)) {
                    read(17);
                    if (read(18)) read(19);
                    read(20);
                }
                read(25);
            }
            read(26);
        }
        read(27);
        tx_done = input_done = output_done = false;
        drivechain::haskell::SidechainEventFlow([&](uint32_t step) {
            actual.push_back(step);
            return outcome(step);
        });
        BOOST_CHECK(actual == expected);
    }
}

BOOST_AUTO_TEST_CASE(ctip_script_read_order_and_adapter_faults)
{
    for (uint32_t opcode = 0; opcode <= 256; ++opcode) {
        std::vector<uint32_t> calls;
        const auto packed = drivechain::haskell::CtipScript([&](uint32_t index) {
            calls.push_back(index);
            return static_cast<int32_t>(opcode);
        });
        BOOST_CHECK_EQUAL(packed, opcode | (opcode << 9) | (opcode << 18));
        BOOST_CHECK(calls == std::vector<uint32_t>({0, 1, 2}));
    }
    for (uint32_t failure = 0; failure < 3; ++failure) {
        for (const int32_t invalid : {-1, 257, INT32_MAX}) {
            uint32_t calls{0};
            BOOST_CHECK_THROW(drivechain::haskell::CtipScript([&](uint32_t index) {
                ++calls;
                return index == failure ? invalid : 0;
            }), std::runtime_error);
            BOOST_CHECK_EQUAL(calls, failure + 1);
        }
        uint32_t calls{0};
        try {
            drivechain::haskell::CtipScript([&](uint32_t index) {
                ++calls;
                if (index == failure) throw 42;
                return 0;
            });
            BOOST_FAIL("native exception was not propagated");
        } catch (int value) { BOOST_CHECK_EQUAL(value, 42); }
        BOOST_CHECK_EQUAL(calls, failure + 1);
    }
}

BOOST_AUTO_TEST_CASE(ctip_storage_reuses_ordered_replacement_and_safe_undo_height)
{
    const CTransaction checkpoint = LegacyPublicDeposit();
    DeterministicFixture fixture;
    for (const int32_t height : {INT32_MIN, -1, 0, 1, 3, INT32_MAX}) {
        RestartablePeginView persistent;
        std::string error;
        drivechain::CtipState initial;
        {
            CCoinsViewCache view(&persistent);
            BOOST_REQUIRE(drivechain::ConnectDepositState(checkpoint, 0, view, height, error));
            BOOST_REQUIRE(drivechain::GetCtipState(view, initial, &error));
            BOOST_REQUIRE(view.Flush());
        }
        BOOST_REQUIRE_EQUAL(persistent.coins.size(), 1U);
        const auto point = persistent.coins.begin()->first;
        BOOST_CHECK(point == COutPoint(Txid::FromUint256(uint256S("2d15ce4b128995291c4e38d36b8ae411a15bf80d7acee97cf5f58d2fc4de52b1")), 0));
        const auto checkpoint_output = persistent.coins.at(point).out;
        BOOST_CHECK(drivechain::IsCtipStateInternalOutpoint(point));
        BOOST_CHECK_EQUAL(initial.value, 14'402'000);
        BOOST_CHECK_EQUAL(initial.sequence_number, 8);
        const std::vector<unsigned char> marker{'d','r','i','v','e','c','h','a','i','n','-','c','t','i','p','-','v','1'};
        DataStream reference;
        reference << marker << initial.outpoint << initial.value << initial.sequence_number;
        const std::vector<unsigned char> bytes{UCharCast(reference.data()), UCharCast(reference.data()) + reference.size()};
        BOOST_CHECK(checkpoint_output.scriptPubKey == (CScript() << bytes << OP_DROP << OP_FALSE));
        BOOST_CHECK(checkpoint_output.nAsset.GetAsset() == Params().GetConsensus().pegged_asset);
        BOOST_CHECK_EQUAL(checkpoint_output.nValue.GetAmount(), 0);
        BOOST_CHECK_EQUAL(persistent.coins.at(point).nHeight, static_cast<uint32_t>(std::max(height, 0)));
        BOOST_CHECK(!persistent.coins.at(point).fCoinBase);
        {
            CCoinsViewCache restarted(&persistent);
            BOOST_REQUIRE(drivechain::ConnectDepositState(*fixture.transaction, 0, restarted, height, error));
            drivechain::CtipState next;
            BOOST_REQUIRE(drivechain::GetCtipState(restarted, next, &error));
            BOOST_CHECK_EQUAL(next.sequence_number, 9);
            BOOST_REQUIRE(restarted.Flush());
            DataStream next_reference;
            next_reference << marker << next.outpoint << next.value << next.sequence_number;
            const std::vector<unsigned char> next_bytes{UCharCast(next_reference.data()), UCharCast(next_reference.data()) + next_reference.size()};
            BOOST_CHECK(persistent.coins.at(point).out.scriptPubKey == (CScript() << next_bytes << OP_DROP << OP_FALSE));
        }
        BOOST_REQUIRE_EQUAL(persistent.coins.size(), 1U);
        BOOST_CHECK_EQUAL(persistent.coins.at(point).nHeight, static_cast<uint32_t>(std::max(height, 0)));
        {
            CCoinsViewCache restarted(&persistent);
            BOOST_REQUIRE(drivechain::DisconnectDepositState(*fixture.transaction, 0, restarted, height, error));
            BOOST_REQUIRE(restarted.Flush());
        }
        BOOST_REQUIRE_EQUAL(persistent.coins.size(), 1U);
        BOOST_CHECK(persistent.coins.at(point).out == checkpoint_output);
        BOOST_CHECK_EQUAL(persistent.coins.at(point).nHeight,
            static_cast<uint32_t>(std::max<int64_t>(int64_t{height} - 1, 0)));
        BOOST_CHECK(!persistent.coins.at(point).fCoinBase);
        CCoinsViewCache restarted(&persistent);
        drivechain::CtipState restored;
        BOOST_REQUIRE(drivechain::GetCtipState(restarted, restored, &error));
        BOOST_CHECK(restored == initial);
    }
}

BOOST_AUTO_TEST_CASE(ctip_transition_rules_preserve_state_and_failure_order)
{
    const CTransaction checkpoint = LegacyPublicDeposit();
    DeterministicFixture fixture;
    const std::array<std::array<const char*, 5>, 4> failures{{
        {{"", "no authenticated prior", "missing authenticated", "without authenticated", "without authenticated"}},
        {{"cannot overwrite", "", "", "", "inconsistent during disconnect"}},
        {{"cannot overwrite", "stale", "stale", "inconsistent during disconnect", ""}},
        {{"script is malformed", "script is malformed", "script is malformed", "script is malformed", "script is malformed"}},
    }};
    for (unsigned state = 0; state < failures.size(); ++state) {
        for (unsigned action = 0; action < failures[state].size(); ++action) {
            BOOST_TEST_CONTEXT("state " << state << ", action " << action) {
                RestartablePeginView persistent;
                std::string error;
                if (state) {
                    CCoinsViewCache setup(&persistent);
                    BOOST_REQUIRE(drivechain::ConnectDepositState(checkpoint, 0, setup, 2, error));
                    if (state == 2) BOOST_REQUIRE(drivechain::ConnectDepositState(*fixture.transaction, 0, setup, 3, error));
                    BOOST_REQUIRE(setup.Flush());
                    if (state == 3) persistent.coins.begin()->second.out.scriptPubKey.back() = OP_TRUE;
                }
                const auto before = persistent.coins;
                CCoinsViewCache view(&persistent);
                error = "untouched";
                bool accepted{false};
                switch (action) {
                case 0: accepted = drivechain::VerifyDeterministicDeposit(checkpoint, 0, view, error); break;
                case 1: accepted = drivechain::VerifyDeterministicDeposit(*fixture.transaction, 0, view, error); break;
                case 2: accepted = drivechain::ConnectDepositState(*fixture.transaction, 0, view, 3, error); break;
                case 3: accepted = drivechain::DisconnectDepositState(checkpoint, 0, view, 2, error); break;
                case 4: accepted = drivechain::DisconnectDepositState(*fixture.transaction, 0, view, 3, error); break;
                }
                const std::string expected = failures[state][action];
                BOOST_CHECK_EQUAL(accepted, expected.empty());
                BOOST_CHECK_MESSAGE(error.find(expected) != std::string::npos, error);
                BOOST_REQUIRE(view.Flush());
                if (!accepted || action < 2) {
                    BOOST_REQUIRE_EQUAL(persistent.coins.size(), before.size());
                    for (const auto& [outpoint, coin] : before) {
                        const auto& after = persistent.coins.at(outpoint);
                        BOOST_CHECK(after.out == coin.out);
                        BOOST_CHECK_EQUAL(after.nHeight, coin.nHeight);
                        BOOST_CHECK_EQUAL(after.fCoinBase, coin.fCoinBase);
                    }
                } else {
                    CCoinsViewCache restarted(&persistent);
                    drivechain::CtipState current;
                    BOOST_CHECK_EQUAL(drivechain::GetCtipState(restarted, current), action != 3);
                    if (action != 3) BOOST_CHECK_EQUAL(current.sequence_number, action == 2 ? 9 : 8);
                }
            }
        }
    }

    // Verification/connect parse first, but disconnect must read current state first.
    CMutableTransaction malformed(*fixture.transaction);
    malformed.witness.vtxinwit[0].m_pegin_witness.stack[8].push_back(0);
    for (const bool corrupt : {false, true}) {
        RestartablePeginView persistent;
        std::string error;
        if (corrupt) {
            CCoinsViewCache setup(&persistent);
            BOOST_REQUIRE(drivechain::ConnectDepositState(checkpoint, 0, setup, 2, error));
            BOOST_REQUIRE(setup.Flush());
            persistent.coins.begin()->second.out.scriptPubKey.back() = OP_TRUE;
        }
        CCoinsViewCache view(&persistent);
        const CTransaction invalid(malformed);
        BOOST_CHECK(!drivechain::VerifyDeterministicDeposit(invalid, 0, view, error));
        BOOST_CHECK(error.find("non-canonical") != std::string::npos);
        BOOST_CHECK(!drivechain::ConnectDepositState(invalid, 0, view, 3, error));
        BOOST_CHECK(error.find("non-canonical") != std::string::npos);
        BOOST_CHECK(!drivechain::DisconnectDepositState(invalid, 0, view, 3, error));
        BOOST_CHECK(error.find(corrupt ? "script is malformed" : "without authenticated") != std::string::npos);
    }
    std::string error;
    BOOST_CHECK(!drivechain::VerifyDepositEvidenceAnchor(checkpoint, 0, uint256::ONE, error));
    BOOST_CHECK_EQUAL(error, "historical drivechain checkpoint is not in its immutable L1 parent block");
    BOOST_CHECK(!drivechain::VerifyDepositEvidenceAnchor(*fixture.transaction, 0, uint256::ONE, error));
    BOOST_CHECK_EQUAL(error, strprintf("drivechain deposit evidence anchor %s does not match sidechain block L1 parent %s",
        fixture.anchor.GetHex(), uint256::ONE.GetHex()));
    BOOST_CHECK(!drivechain::VerifyDepositEvidenceAnchor(CTransaction(malformed), 0, uint256::ONE, error));
    BOOST_CHECK(error.find("non-canonical") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(historical_deposit_evidence_rejects_betanet_treasury_opcode)
{
    DeterministicFixture wrong_opcode(OP_NOP8);
    std::string error;
    BOOST_CHECK(!drivechain::VerifyDepositEvidenceAnchor(
        *wrong_opcode.transaction, 0, wrong_opcode.anchor, error));
    BOOST_CHECK(error.find("slot-24 CTIP") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(deposit_proof_ffi_preserves_native_authentication_and_error_priority)
{
    const std::vector<std::string> errors{
        "", "merkle proof", "merkle proof", "merkle proof", "proof-of-work", "contiguous",
        "slot-24 CTIP", "slot-24 CTIP", "exactly one authenticated prior CTIP",
        "exactly one authenticated prior CTIP", "CTIP increase", "CTIP increase",
        "CTIP increase", "CTIP increase", "merkle proof", "outpoint is absent",
        "proof-of-work", "contiguous", "CTIP increase", "slot-24 CTIP", "", "",
        "slot-24 CTIP", "slot-24 CTIP", "exactly one authenticated prior CTIP"};
    const auto mine = [](Sidechain::Bitcoin::CBlockHeader& header) {
        while (!CheckParentProofOfWork(header.GetHash(), header.nBits, Params().GetConsensus())) ++header.nNonce;
    };
    for (size_t mutation = 0; mutation < errors.size(); ++mutation) {
        BOOST_TEST_CONTEXT("deposit proof mutation " << mutation) {
            DeterministicFixture fixture;
            auto evidence = fixture.evidence;
            Sidechain::Bitcoin::CMutableTransaction deposit, previous;
            DataStream{evidence.deposit_tx} >> TX_WITH_WITNESS(deposit);
            DataStream{evidence.previous_ctip_tx} >> TX_WITH_WITNESS(previous);
            switch (mutation) {
            case 6: deposit.vout[0].scriptPubKey = CtipScript(OP_NOP8); break;
            case 7: deposit.vout[0].nValue = 0; break;
            case 8: deposit.vin[0].prevout.hash = uint256::ONE; break;
            case 9: deposit.vin.push_back(deposit.vin.front()); break;
            case 10: previous.vout[0].nValue = 0; deposit.vin[0].prevout.hash = previous.GetHash(); break;
            case 11: deposit.vout[0].nValue = previous.vout[0].nValue; break;
            case 18:
                previous.vout[0].nValue = std::numeric_limits<int64_t>::min();
                deposit.vin[0].prevout.hash = previous.GetHash();
                deposit.vout[0].nValue = std::numeric_limits<int64_t>::max();
                break;
            case 19: deposit.vout[0].nValue = -1; break;
            case 21:
                previous.vout.insert(previous.vout.begin(), Sidechain::Bitcoin::CTxOut(0, CScript() << OP_RETURN));
                deposit.vin[0].prevout = Sidechain::Bitcoin::COutPoint(previous.GetHash(), 1);
                deposit.vout.insert(deposit.vout.begin(), Sidechain::Bitcoin::CTxOut(0, CScript() << OP_RETURN));
                break;
            case 22: deposit.vout[0].scriptPubKey << OP_TRUE; break;
            case 23: deposit.vout[0].scriptPubKey.resize(100000); break;
            case 24:
                previous.vout[0].scriptPubKey.resize(100000);
                deposit.vin[0].prevout.hash = previous.GetHash();
                break;
            }
            Sidechain::Bitcoin::CMerkleBlock proof;
            proof.header = evidence.headers.front();
            proof.header.hashMerkleRoot = deposit.GetHash();
            proof.txn = Sidechain::Bitcoin::CPartialMerkleTree({deposit.GetHash()}, {mutation != 1});
            if (mutation == 2) proof.header.hashMerkleRoot = uint256::ONE;
            if (mutation == 14) {
                proof.txn = Sidechain::Bitcoin::CPartialMerkleTree({deposit.GetHash(), uint256::ONE}, {true, true});
                std::vector<uint256> matches;
                std::vector<unsigned int> indices;
                proof.header.hashMerkleRoot = proof.txn.ExtractMatches(matches, indices);
            }
            if (mutation == 4) proof.header.nBits = 0;
            else mine(proof.header);
            evidence.headers = {proof.header};
            if (mutation == 3) ++evidence.headers[0].nNonce;
            if (mutation == 5 || mutation == 16 || mutation == 17 || mutation == 20) {
                auto child = proof.header;
                child.hashPrevBlock = mutation == 20 ? proof.header.GetHash() : uint256::ONE;
                ++child.nTime;
                if (mutation == 16) child.nBits = 0;
                else mine(child);
                evidence.headers.push_back(child);
                if (mutation == 17) {
                    child.nBits = 0;
                    evidence.headers.push_back(child);
                }
            }
            evidence.deposit_tx = Serialize(deposit);
            evidence.previous_ctip_tx = Serialize(previous);
            evidence.txout_proof = Serialize(proof);
            CMutableTransaction tx(*fixture.transaction);
            tx.vin[0].prevout = COutPoint(Txid::FromUint256(deposit.GetHash()), mutation == 15 ? 99 : mutation == 21 ? 1 : 0);
            auto& witness = tx.witness.vtxinwit[0].m_pegin_witness;
            witness = CreateDrivechainDepositPeginWitness(mutation == 12 ? 2001 : 2000,
                Params().GetConsensus().pegged_asset, Params().ParentGenesisBlockHash(), CScript() << OP_TRUE, evidence);
            if (mutation == 13) witness.stack[1][0] ^= 1;
            std::string error;
            const bool accepted = drivechain::VerifyDepositEvidenceAnchor(CTransaction(tx), 0, evidence.headers.back().GetHash(), error);
            BOOST_CHECK_EQUAL(accepted, errors[mutation].empty());
            BOOST_CHECK_MESSAGE(error.find(errors[mutation]) != std::string::npos, error);
        }
    }
}

BOOST_AUTO_TEST_CASE(rejects_corrupted_stale_and_noncanonical_v2_evidence)
{
    RestartablePeginView persistent;
    std::string error;
    CCoinsViewCache view(&persistent);
    const CTransaction checkpoint = LegacyPublicDeposit();
    BOOST_REQUIRE(drivechain::ConnectDepositState(checkpoint, 0, view, 2, error));

    DeterministicFixture fixture;
    CMutableTransaction corrupted(*fixture.transaction);
    corrupted.witness.vtxinwit[0].m_pegin_witness.stack[6].back() ^= 1;
    BOOST_CHECK(!drivechain::VerifyDeterministicDeposit(
        CTransaction(corrupted),
        0,
        view,
        error));

    CMutableTransaction stale(*fixture.transaction);
    DrivechainDepositEvidence stale_evidence = fixture.evidence;
    stale_evidence.previous_sequence_number = 7;
    stale.witness.vtxinwit[0].m_pegin_witness =
        CreateDrivechainDepositPeginWitness(
            2'000,
            Params().GetConsensus().pegged_asset,
            Params().ParentGenesisBlockHash(),
            CScript() << OP_TRUE,
            stale_evidence);
    BOOST_CHECK(!drivechain::VerifyDeterministicDeposit(
        CTransaction(stale),
        0,
        view,
        error));
    BOOST_CHECK(error.find("sequence") != std::string::npos);

    CMutableTransaction trailing(*fixture.transaction);
    trailing.witness.vtxinwit[0].m_pegin_witness.stack[8].push_back(0);
    BOOST_CHECK(!drivechain::VerifyDeterministicDeposit(
        CTransaction(trailing),
        0,
        view,
        error));
    BOOST_CHECK(error.find("non-canonical") != std::string::npos);

    BOOST_CHECK_EQUAL(
        HexStr(fixture.transaction->witness.vtxinwit[0].m_pegin_witness.stack[8]),
        "0900000000000000");
    BOOST_CHECK_EQUAL(
        HexStr(fixture.transaction->witness.vtxinwit[0].m_pegin_witness.stack[9]),
        "0800000000000000");
}

BOOST_AUTO_TEST_CASE(persists_zero_value_state_and_fails_closed_on_corruption)
{
    RestartablePeginView persistent;
    std::string error;
    {
        CCoinsViewCache view(&persistent);
        const CTransaction checkpoint = LegacyPublicDeposit();
        BOOST_REQUIRE(drivechain::ConnectDepositState(checkpoint, 0, view, 2, error));
        BOOST_REQUIRE(view.Flush());
    }

    BOOST_REQUIRE_EQUAL(persistent.coins.size(), size_t{1});
    const Coin& state_coin = persistent.coins.begin()->second;
    BOOST_REQUIRE(state_coin.out.nValue.IsExplicit());
    BOOST_CHECK_EQUAL(state_coin.out.nValue.GetAmount(), 0);

    persistent.coins.begin()->second.out.scriptPubKey.back() ^= 1;
    CCoinsViewCache restarted(&persistent);
    drivechain::CtipState state;
    BOOST_CHECK(!drivechain::GetCtipState(restarted, state, &error));
    BOOST_CHECK(error.find("malformed") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(persisted_ctip_ffi_preserves_codec_and_rejects_corruption_atomically)
{
    RestartablePeginView persistent;
    std::string error;
    drivechain::CtipState expected;
    {
        CCoinsViewCache view(&persistent);
        BOOST_REQUIRE(drivechain::ConnectDepositState(LegacyPublicDeposit(), 0, view, 2, error));
        BOOST_REQUIRE(drivechain::GetCtipState(view, expected, &error));
        BOOST_REQUIRE(view.Flush());
    }
    const Coin original = persistent.coins.begin()->second;
    auto cursor = original.out.scriptPubKey.begin();
    opcodetype opcode;
    std::vector<unsigned char> payload, marker;
    BOOST_REQUIRE(original.out.scriptPubKey.GetOp(cursor, opcode, payload));
    DataStream{payload} >> marker;
    const std::vector<std::string> errors{
        "", "asset or value", "asset or value", "asset or value", "asset or value",
        "script is malformed", "script is malformed", "script is malformed", "cannot be decoded",
        "payload is invalid", "payload is invalid", "payload is invalid", "payload is invalid",
        "payload is invalid", "payload is invalid", "", "cannot be decoded", "script is malformed", ""};
    for (size_t mutation = 0; mutation < errors.size(); ++mutation) {
        BOOST_TEST_CONTEXT("persisted CTIP mutation " << mutation) {
            Coin changed(original);
            auto fields = expected;
            auto modified_marker = marker;
            if (mutation == 9) modified_marker.front() ^= 1;
            if (mutation == 10) fields.outpoint = COutPoint(Txid::FromUint256(uint256{}), 0);
            if (mutation == 11) fields.value = 0;
            if (mutation == 12) fields.value = -1;
            if (mutation == 13) fields.sequence_number = -1;
            if (mutation == 18) fields.value = fields.sequence_number = std::numeric_limits<int64_t>::max();
            DataStream stream;
            stream << modified_marker << fields.outpoint << fields.value << fields.sequence_number;
            std::vector<unsigned char> data(UCharCast(stream.data()), UCharCast(stream.data()) + stream.size());
            if (mutation == 8) data.pop_back();
            if (mutation == 14) data.push_back(0);
            if (mutation == 16) {
                data.erase(data.begin());
                data.insert(data.begin(), {0xfd, static_cast<unsigned char>(marker.size()), 0});
            }
            changed.out.scriptPubKey = CScript() << data << OP_DROP << OP_FALSE;
            if (mutation == 0) BOOST_CHECK(changed.out.scriptPubKey == original.out.scriptPubKey);
            switch (mutation) {
            case 1: changed.out.nValue.SetToAmount(1); break;
            case 2: changed.out.nAsset.SetToAsset(CAsset(uint256::ONE)); break;
            case 3: changed.out.nAsset.vchCommitment.assign(33, 10); break;
            case 4: changed.out.nValue.vchCommitment.assign(33, 8); break;
            case 5: changed.out.scriptPubKey[changed.out.scriptPubKey.size() - 2] = OP_DUP; break;
            case 6: changed.out.scriptPubKey.back() = OP_TRUE; break;
            case 7: changed.out.scriptPubKey << OP_FALSE; break;
            case 15:
                changed.out.scriptPubKey = CScript() << OP_PUSHDATA1;
                changed.out.scriptPubKey.push_back(data.size());
                changed.out.scriptPubKey.insert(changed.out.scriptPubKey.end(), data.begin(), data.end());
                changed.out.scriptPubKey << OP_DROP << OP_FALSE;
                break;
            case 17: changed.out.scriptPubKey = CScript() << OP_PUSHDATA2; break;
            }
            persistent.coins.begin()->second = changed;
            CCoinsViewCache restarted(&persistent);
            drivechain::CtipState actual = expected;
            actual.value = 123;
            const auto untouched = actual;
            error.clear();
            const bool accepted = drivechain::GetCtipState(restarted, actual, &error);
            BOOST_CHECK_EQUAL(accepted, errors[mutation].empty());
            BOOST_CHECK_MESSAGE(error.find(errors[mutation]) != std::string::npos, error);
            BOOST_CHECK(actual == (accepted ? fields : untouched));
            actual = untouched;
            BOOST_CHECK_EQUAL(drivechain::GetCtipState(restarted, actual, nullptr), accepted);
            BOOST_CHECK(actual == (accepted ? fields : untouched));
        }
    }
}

BOOST_AUTO_TEST_CASE(converges_across_independent_views_and_reorg_rollback)
{
    RestartablePeginView first;
    RestartablePeginView second;
    DeterministicFixture fixture;

    const auto connect = [&](RestartablePeginView& persistent) {
        std::string error;
        CCoinsViewCache view(&persistent);
        const CTransaction checkpoint = LegacyPublicDeposit();
        BOOST_REQUIRE(drivechain::ConnectDepositState(checkpoint, 0, view, 2, error));
        BOOST_REQUIRE(drivechain::VerifyDeterministicDeposit(
            *fixture.transaction,
            0,
            view,
            error));
        BOOST_REQUIRE(drivechain::ConnectDepositState(
            *fixture.transaction,
            0,
            view,
            3,
            error));
        BOOST_REQUIRE(view.Flush());
    };
    connect(first);
    connect(second);

    BOOST_REQUIRE_EQUAL(first.coins.size(), size_t{1});
    BOOST_REQUIRE_EQUAL(second.coins.size(), size_t{1});
    BOOST_CHECK(first.coins.begin()->first == second.coins.begin()->first);
    BOOST_CHECK(first.coins.begin()->second.out == second.coins.begin()->second.out);

    const auto disconnect = [&](RestartablePeginView& persistent) {
        std::string error;
        CCoinsViewCache view(&persistent);
        BOOST_REQUIRE(drivechain::DisconnectDepositState(
            *fixture.transaction,
            0,
            view,
            3,
            error));
        BOOST_REQUIRE(view.Flush());
    };
    disconnect(first);
    disconnect(second);

    CCoinsViewCache first_restarted(&first);
    CCoinsViewCache second_restarted(&second);
    drivechain::CtipState first_state;
    drivechain::CtipState second_state;
    std::string error;
    BOOST_REQUIRE(drivechain::GetCtipState(first_restarted, first_state, &error));
    BOOST_REQUIRE(drivechain::GetCtipState(second_restarted, second_state, &error));
    BOOST_CHECK(first_state == second_state);
    BOOST_CHECK_EQUAL(first_state.sequence_number, 8);
}

BOOST_AUTO_TEST_SUITE_END()
