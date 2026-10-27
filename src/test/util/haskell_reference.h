// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#ifndef ELEMENTS_TEST_HASKELL_REFERENCE_H
#define ELEMENTS_TEST_HASKELL_REFERENCE_H

#include <haskell/bridge.h>
#include <haskell/domain_abi.h>
#include <exception>
#include <consensus/amount.h>
#include <crypto/common.h>
#include <algorithm>
#include <chrono>
#include <univalue.h>
#include <haskell/bmm_constants.h>
#include <primitives/transaction.h>
#include <hash.h>

// Preserved predecessor retrieval entry for differential tests only.
namespace drivechain {

/** Availability only. The caller must authenticate the returned block bytes.
 * RPC, deadline and wait callbacks allow deterministic testing of recovery.
 * Never allow recovery while holding consensus locks.
 */
template <typename Rpc, typename Check, typename Wait>
UniValue FetchParentBlockBody(const std::string& hash, bool allow_recovery,
                             Rpc&& rpc, Check&& check, Wait&& wait)
{
    UniValue auxiliary, header, active, peers;
    std::string method;
    auto request = [&](const std::string& name, const UniValue& params) {
        check();
        auxiliary = rpc(name, params);
        method = name;
    };
    UniValue block_params(UniValue::VARR);
    block_params.push_back(hash);
    block_params.push_back(0);
    std::vector<UniValue>::const_iterator peer,service;
    UniValue reply;
    std::chrono::steady_clock::time_point deadline;
    int height=0;
    haskell::ParentReplayStore(haskell::ReplayStoreFlow::RECOVERY_COMPOSED,[&](uint32_t step) -> int64_t {
        switch (step) {
        case 1: check(); reply=rpc("getblock",block_params); return 1;
        case 3: case 17: return reply["error"].isNull();
        case 4: case 18: return !reply["result"].isNull();
        case 5: throw std::runtime_error("getblock failed: "+reply["error"].write());
        case 6: return allow_recovery;
        case 7: throw std::runtime_error("pruned parent block requires recovery outside consensus locks");
        case 8: deadline=std::chrono::steady_clock::now()+std::chrono::seconds{PARENT_RECOVERY_SECONDS}; return 1;
        case 11: check(); return 1;
        case 12: return std::chrono::steady_clock::now()>=deadline;
        case 13: throw std::runtime_error("parent block recovery timed out");
        case 14: reply=rpc("getblock",block_params); return 1;
        case 16: wait(); return 1;
        case 19: throw std::runtime_error("getblock failed during parent block recovery");
        case 21: throw std::runtime_error("parent block height changed during recovery");
        case 101: return reply["error"].isObject();
        case 102: return reply["error"]["code"].isNum();
        case 103: return reply["error"]["code"].getInt<int>()==-1;
        case 104: return reply["error"]["message"].isStr();
        case 105: return reply["error"]["message"].get_str()=="Block not available (pruned data)";
        case 200: {
            UniValue params(UniValue::VARR);
            params.push_back(hash); params.push_back(true);
            request("getblockheader",params); return 1;
        }
        case 201: return header["hash"].isStr();
        case 202: return header["hash"].get_str()==hash;
        case 203: return header["height"].isNum();
        case 204: return header["confirmations"].isNum();
        case 205: return header["height"].getInt<int>()>=0;
        case 206: return header["confirmations"].getInt<int>()>0;
        case 207: {
            height=header["height"].getInt<int>();
            UniValue params(UniValue::VARR);
            params.push_back(height); request("getblockhash",params); return 1;
        }
        case 208: return active.isStr();
        case 209: return active.get_str()==hash;
        case 210: throw std::runtime_error("pruned parent block is not active");
        case 211: throw std::runtime_error("parent chain changed during block recovery");
        case 212: header=auxiliary["result"]; auxiliary.setNull(); return 1;
        case 213: header.setNull(); active.setNull(); return height;
        case 214: active=auxiliary["result"]; auxiliary.setNull(); return 1;
        case 301: return auxiliary["error"].isNull();
        case 302: return !auxiliary["result"].isNull();
        case 303: throw std::runtime_error(method+" failed during parent block retrieval");
        case 400: request("getpeerinfo",UniValue(UniValue::VARR)); return 1;
        case 401: return peer!=peers.getValues().end();
        case 402: return (*peer)["id"].isNum();
        case 403: return (*peer)["servicesnames"].isArray();
        case 404: service=(*peer)["servicesnames"].getValues().begin(); return 1;
        case 405: return service!=(*peer)["servicesnames"].getValues().end();
        case 406: return service->isStr();
        case 407: return service->get_str()=="NETWORK";
        case 408: ++service; return 1;
        case 409: ++peer; return 1;
        case 410: throw std::runtime_error("no parent peer offers full block service");
        case 411: {
            UniValue params(UniValue::VARR);
            params.push_back(hash); params.push_back((*peer)["id"]);
            request("getblockfrompeer",params); return 1;
        }
        case 412: return peers.isArray();
        case 413: throw std::runtime_error("invalid parent peer response");
        case 414: peer=peers.getValues().begin(); return 1;
        case 415: peers=auxiliary["result"]; auxiliary.setNull(); return 1;
        case 417: auxiliary.setNull(); peers.setNull(); return 1;
        default: throw std::logic_error("invalid parent recovery body action");
        }
    });
    return reply["result"];
}
} // namespace drivechain

extern "C" void elements_hs_runtime_init(void);

// Standalone test entry; production composes the parent Signet capabilities in Haskell.
bool CheckBitcoinSignetBlockSolution(const Sidechain::Bitcoin::CBlock& block,
    const CScript& challenge, const uint256& genesis_hash, std::string* error = nullptr);

namespace drivechain::haskell {

inline void BmmAdvance(int64_t interval, uint32_t time, uint32_t bits, std::span<uint32_t, 16> fields)
{
    elements_hs_runtime_init();
    if (elements_hs_bmm_advance_v1(interval, time, bits, fields.size(), fields.data()) != 0)
        throw std::runtime_error("Haskell BMM advancement failed");
}
// Retained legacy two-entry write/encode path for differential tests only.
template <typename Plan>
inline void ReferenceBmmActionPlan(const Plan& plan, const std::function<void(uint32_t, uint32_t)>& action)
{
    elements_hs_runtime_init();
    struct Context {
        std::array<std::pair<uint32_t, uint32_t>, 10> steps{};
        size_t count{0};
    } context;
    const auto callback = +[](void* opaque, uint32_t step, uint32_t normalized_height) -> int32_t {
        auto& ctx = *static_cast<Context*>(opaque);
        if (ctx.count == ctx.steps.size()) return 0;
        ctx.steps[ctx.count++] = {step, normalized_height};
        return 1;
    };
    if (plan(reinterpret_cast<HsFunPtr>(callback), &context) != 1)
        throw std::runtime_error("Haskell BMM action plan failed");
    for (size_t i = 0; i < context.count; ++i) action(context.steps[i].first, context.steps[i].second);
}

inline void BmmStoreState(int32_t height, const std::function<void(uint32_t, uint32_t)>& action, bool restore = false)
{
    ReferenceBmmActionPlan([height, restore](HsFunPtr callback, void* context) {
        return restore ? elements_hs_bmm_restore_state_v1(height, callback, context)
                       : elements_hs_bmm_store_state_v1(height, callback, context);
    }, action);
}

inline void BmmEncodeState(const std::function<void(uint32_t, uint32_t)>& action)
{
    ReferenceBmmActionPlan(elements_hs_bmm_encode_state_v1, action);
}

inline int64_t BmmParentMedian(std::span<const uint32_t> times, std::string& error)
{
    elements_hs_runtime_init();
    if (times.size() > std::numeric_limits<uint32_t>::max()) throw std::length_error("BMM median history too large");
    const auto result = elements_hs_bmm_parent_median_v1(times.size(), const_cast<uint32_t*>(times.data()));
    if (result < -1 || result > std::numeric_limits<uint32_t>::max()) throw std::runtime_error("Haskell BMM parent median evaluation failed");
    if (result == -1) error = "authenticated BMM parent median time past is zero";
    return result;
}

inline int32_t ReferenceBmmStateSourceResult(int32_t result, const std::string& state_error, std::string& error)
{
    if (result < -3 || result > 5) throw std::runtime_error("Haskell BMM state source failed");
    if (result == -1) error = "native Elements requires its authenticated parent replay, not signet BMM state";
    if (result == -2) error = state_error;
    if (result == -3) error = "authenticated BMM parent-chain state is missing";
    return result;
}

inline int32_t BmmStateSource(uint32_t phase, uint32_t facts, const std::string& state_error, std::string& error)
{
    elements_hs_runtime_init();
    return ReferenceBmmStateSourceResult(elements_hs_bmm_state_source_v1(phase, facts),state_error,error);
}

struct ParentMessage {
    uint32_t kind, encoding;
    std::vector<uint16_t> votes;
};

inline ParentMessage ParseParentMessage(std::span<const unsigned char> payload)
{
    elements_hs_runtime_init();
    if (payload.size() > INT32_MAX) throw std::length_error("parent message too large");
    std::array<uint32_t, 2> fields{};
    std::vector<uint16_t> votes(payload.empty() ? 1 : payload.size());
    const auto count = elements_hs_parent_message_v1(payload.size(),
        const_cast<unsigned char*>(payload.data()), fields.data(), votes.data());
    if (count < 0 || static_cast<size_t>(count) > payload.size() || fields[0] > 5 || fields[1] > 3)
        throw std::runtime_error("Haskell parent message parsing failed");
    votes.resize(count);
    return {fields[0], fields[1], std::move(votes)};
}

inline uint32_t ReplayDistance(uint32_t upper, uint32_t lower)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_replay_distance_v1(upper, lower);
    if (result < 0 || result > UINT32_MAX) throw std::runtime_error("Haskell replay distance evaluation failed");
    return static_cast<uint32_t>(result);
}

inline int32_t BmmHeader(uint32_t facts, std::string& error)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_bmm_header_v1(facts);
    constexpr std::array<const char*, 5> errors{{
        "historical signet BMM proof is not valid on native Elements",
        "public-signet height 2 does not match its immutable checkpoint",
        "public-signet descendant does not signal deterministic BMM proof",
        "deterministic BMM header has no proof commitment",
        "deterministic BMM proof cannot activate outside the public-signet checkpoint",
    }};
    if (result < 0 || result > 6) throw std::runtime_error("Haskell BMM header evaluation failed");
    if (result > 0 && result < 6) error = errors[result - 1];
    return result;
}

inline bool ParentRpcAddress(uint32_t family, uint32_t ipv4, std::span<const unsigned char> ipv6 = {})
{
    if (ipv6.size() > 16) throw std::invalid_argument("invalid parent RPC address length");
    elements_hs_runtime_init();
    const int code = elements_hs_parent_rpc_address_v1(family, ipv4, ipv6.size(), const_cast<unsigned char*>(ipv6.data()));
    if (code < 0 || code > 1) throw std::runtime_error("Haskell parent RPC address failed");
    return code == 1;
}

inline bool LegacyCheckpoint(bool eligible, const unsigned char* txid, const unsigned char* previous,
    uint32_t vout, std::vector<unsigned char>& record)
{
    elements_hs_runtime_init();
    std::array<unsigned char, 136> reply{};
    const auto size = elements_hs_checkpoint_v1(eligible, const_cast<unsigned char*>(txid),
        const_cast<unsigned char*>(previous), vout, reply.data(), reply.size());
    if (size != 0 && size != static_cast<int32_t>(reply.size())) throw std::runtime_error("Haskell checkpoint lookup failed");
    if (size) record.assign(reply.begin(), reply.end());
    return size != 0;
}

inline bool LegacyClaim(bool decoded, bool destination_valid, int64_t actual, int64_t expected, std::string& error)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_legacy_claim_v1(uint32_t{decoded} | (uint32_t{destination_valid} << 1), actual, expected);
    if (result < 0 || result > 2) throw std::runtime_error("Haskell legacy claim evaluation failed");
    if (result) error = result == 1 ? "historical drivechain checkpoint witness does not match its immutable value"
                                  : "historical drivechain checkpoint destination is invalid for this network";
    return result == 0;
}

// Fine-grained reference adapters exist only in the native test target.
template <typename Result, Result fallback = 0, typename Plan, typename Value, typename... Args>
auto ReferenceReadAdmission(const Plan& plan, const std::function<Value(Args...)>& read)
{
    elements_hs_runtime_init();
    struct Context { const std::function<Value(Args...)>& read; std::exception_ptr failure; } context{read, {}};
    const auto callback = +[](void* opaque, Args... args) -> Result {
        auto& ctx = *static_cast<Context*>(opaque);
        if (ctx.failure) return fallback;
        try { return ctx.read(args...); }
        catch (...) { ctx.failure = std::current_exception(); return fallback; }
    };
    const auto result = plan(reinterpret_cast<HsFunPtr>(callback), &context);
    if (context.failure) std::rethrow_exception(context.failure);
    return result;
}
template <typename Result, Result fallback, typename Binding, typename Value, typename... Args, typename... Params>
auto ReferenceReadBoundAdmission(const Binding& binding, const std::function<Value(Args...)>& read, Params... params)
{
    return ReferenceReadAdmission<Result,fallback>([&](HsFunPtr callback, void* context) {
        return binding(params...,callback,context);
    },read);
}
template <typename Binding, typename... Params>
int ReferenceReadScalarAdmission(const Binding& binding,
    const std::function<uint64_t(uint32_t,uint64_t,uint64_t)>& read, Params... params)
{
    const std::function<int32_t(uint32_t,uint64_t,uint64_t,uint64_t*)> action =
        [&](uint32_t step, uint64_t a, uint64_t b, uint64_t* field) { *field=read(step,a,b); return 1; };
    return ReferenceReadBoundAdmission<int32_t,-1>(binding,action,params...);
}

inline bool ParentReplayTip(const std::function<bool(uint32_t)>& read)
{
    const auto code = ReferenceReadAdmission<int64_t,-1>(elements_hs_parent_replay_tip_run_v1,read);
    if (code == -2) throw std::runtime_error("Haskell parent replay tip action invalid");
    if (code < 0 || code > 1) throw std::runtime_error("Haskell parent replay tip evaluation failed");
    return code == 0;
}
inline int ReferenceCheckedStatus(int code, int maximum, const char* failure)
{
    if (code < 0 || code > maximum) throw std::runtime_error(failure);
    return code;
}
inline uint32_t RequiredPeginDepth(uint32_t configured)
{
    const std::function<int32_t(uint32_t)> read = [](uint32_t) -> int32_t {
        throw std::logic_error("confirmation minimum requested identity fact");
    };
    const auto result = ReferenceReadBoundAdmission<int32_t,-1>(elements_hs_pegin_confirmation_policy_v1,
        read, 2U, int64_t{0}, configured);
    if (result < 1 || result > UINT32_MAX) throw std::runtime_error("Haskell required pegin depth failed");
    return static_cast<uint32_t>(result);
}
inline bool HasDepositDepth(uint32_t deposit, uint32_t tip, uint32_t required)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_deposit_depth_v1(deposit, tip, required);
    return ReferenceCheckedStatus(result,1,"Haskell deposit-depth evaluation failed") == 1;
}
template <typename Binding, typename... Params>
int ReferenceReadWorkflow(const Binding& binding, const NativeWorkflow& native, Params... params)
{
    elements_hs_runtime_init();
    struct Context {
        const NativeWorkflow& native;
        std::vector<unsigned char> reply;
        std::exception_ptr failure;
    } context{native, {}, {}};
    const auto callback = +[](void* opaque, uint32_t step, uint64_t index, uint64_t size,
        unsigned char* input, uint64_t* count, unsigned char** data) -> int32_t {
        auto& ctx = *static_cast<Context*>(opaque);
        *count = 0;
        *data = nullptr;
        if (ctx.failure) return 0;
        try {
            if (size > SIZE_MAX || (size && !input)) throw std::logic_error("invalid native workflow request");
            ctx.reply = ctx.native(step, index, {input, static_cast<size_t>(size)});
            *count = ctx.reply.size();
            *data = ctx.reply.data();
            return 1;
        } catch (...) {
            ctx.failure = std::current_exception();
            return 0;
        }
    };
    const int result = binding(params..., reinterpret_cast<HsFunPtr>(callback), &context);
    if (context.failure) std::rethrow_exception(context.failure);
    return result;
}

inline uint32_t ReadCredentialBytes(uint64_t capacity, const std::function<uint64_t(uint64_t,uint64_t)>& read, uint64_t& used)
{
    return ReferenceCheckedStatus(ReferenceReadScalarAdmission(elements_hs_credential_read_v1,
        [&](uint32_t, uint64_t offset, uint64_t available) { return read(offset,available); },capacity,&used),
        2,"Haskell credential read failed");
}

inline bool AdmitPrivateCredentialFile(const std::function<int64_t(uint32_t)>& read)
{
    return ReferenceCheckedStatus(ReferenceReadBoundAdmission<int64_t,-1>(elements_hs_private_file_admission_v1,read),
        1,"Haskell private credential admission failed")==1;
}

inline bool IsRpcCredentialRecord(const std::string& text, bool rotating_cookie)
{
    elements_hs_runtime_init();
    unsigned char accepted{0};
    const auto code=elements_hs_configuration_field_v1(rotating_cookie ? 7 : 8,text.size(),
        reinterpret_cast<unsigned char*>(const_cast<char*>(text.data())),1,&accepted);
    if (code==-2) return false;
    if (code!=1 || accepted!=1) throw std::runtime_error("invalid Haskell credential record admission");
    return true;
}

inline void DepositCtipSearch(uint64_t count, const std::function<int32_t(uint32_t,uint64_t)>& action)
{
    const int code = ReferenceReadBoundAdmission<int32_t,-1>(elements_hs_deposit_ctip_search_v1,action,count);
    if (code == 1) throw std::runtime_error("deposit transaction's prior CTIP transaction is unavailable");
    if (code == 2) throw std::runtime_error("deposit transaction spends multiple slot CTIP outputs");
    if (code != 0) throw std::runtime_error("Haskell deposit CTIP search failed");
}

inline void DepositHeaders(uint64_t first, int64_t tip, const std::function<bool(uint32_t,uint64_t)>& action)
{
    const int code = ReferenceReadBoundAdmission<int32_t,-1>(elements_hs_deposit_headers_v1,action,first,tip);
    if (code == 1) throw std::runtime_error("deposit confirmation is outside the bounded v2 L1 header window");
    if (code != 0) throw std::runtime_error("Haskell deposit header build failed");
}

inline void DepositBuild(int64_t sequence, int64_t height, uint32_t flags, const std::function<bool(uint32_t)>& action)
{
    const int code = ReferenceReadBoundAdmission<int32_t,-1>(elements_hs_deposit_build_v1,action,sequence,height,flags);
    if (code == 1) throw std::runtime_error("authenticated deposit cannot form a v2 CTIP transition");
    if (code != 0) throw std::runtime_error("Haskell deposit evidence build failed");
}

inline int64_t PreviousDepositSequence(int64_t current)
{
    elements_hs_runtime_init();
    const auto previous = elements_hs_deposit_previous_sequence_v1(current);
    if (previous < 0) throw std::runtime_error("Invalid Haskell deposit sequence predecessor");
    return previous;
}

inline int ReplayMessages(uint64_t count, uint32_t height, std::array<uint16_t,4> settings, const NativeWorkflow& native)
{
    const uint64_t packed = uint64_t(settings[0]) | (uint64_t(settings[1]) << 16) |
        (uint64_t(settings[2]) << 32) | (uint64_t(settings[3]) << 48);
    const int result = ReferenceReadWorkflow(elements_hs_replay_messages_v1,native,count,height,packed);
    if (result == -2) throw std::runtime_error("Haskell M2 activation failed");
    if (result == -3) throw std::runtime_error("Haskell M3 proposal admission failed");
    if (result == -4) throw std::runtime_error("Haskell M4 workflow failed");
    return ReferenceCheckedStatus(result,0x306,"Haskell parent message workflow failed");
}

inline int ReplayTreasuryTransaction(uint64_t slots, uint64_t inputs, uint64_t outputs, uint64_t maximum,
    uint32_t threshold, bool single, const std::function<int64_t(uint32_t,uint64_t)>& action)
{
    return ReferenceCheckedStatus(ReferenceReadBoundAdmission<int64_t,-1>(elements_hs_transaction_replay_v1,action,
        slots,inputs,outputs,maximum,threshold,uint32_t(single)),0x906,"Haskell treasury transaction replay failed");
}

inline int MaintainParentReplay(ReplayMaintenance mode, uint32_t height, std::array<uint16_t,4> windows,
    uint32_t withdrawal_age, uint32_t flags, const NativeWorkflow& native)
{
    const uint64_t settings = uint64_t(windows[0]) | (uint64_t(windows[1]) << 16) |
        (uint64_t(windows[2]) << 32) | (uint64_t(windows[3]) << 48);
    return ReferenceCheckedStatus(ReferenceReadWorkflow(elements_hs_replay_maintenance_v1,native,
        static_cast<uint32_t>(mode),height,settings,withdrawal_age,flags),0x300,"Haskell parent replay maintenance failed");
}

inline std::vector<unsigned char> ActiveSlots(std::span<const unsigned char> entries)
{
    if (entries.size() > 514 || entries.size()%2 != 0) throw std::invalid_argument("invalid active slot entries");
    std::vector<unsigned char> output(entries.size()/2);
    elements_hs_runtime_init();
    const auto count = elements_hs_active_slots_v1(output.size(),const_cast<unsigned char*>(entries.data()),output.data());
    if (count < 0 || static_cast<size_t>(count) > output.size()) throw std::runtime_error("Haskell active slot selection failed");
    output.resize(count);
    return output;
}

inline int ReplayParentBlock(uint32_t height, std::array<uint16_t,4> windows, uint32_t withdrawal_age,
    uint32_t withdrawal_threshold, uint32_t treasury_opcode, bool single_m6, const NativeWorkflow& native)
{
    const uint64_t settings = uint64_t(windows[0]) | (uint64_t(windows[1]) << 16) |
        (uint64_t(windows[2]) << 32) | (uint64_t(windows[3]) << 48);
    const int result = ReferenceReadWorkflow(elements_hs_parent_block_v1,native,height,settings,withdrawal_age,
        withdrawal_threshold,treasury_opcode,uint32_t(single_m6));
    if (result == -2) throw std::runtime_error("Haskell M2 activation failed");
    if (result == -3) throw std::runtime_error("Haskell M3 proposal admission failed");
    if (result == -4) throw std::runtime_error("Haskell M4 workflow failed");
    return ReferenceCheckedStatus(result,1,"Haskell parent block replay failed");
}

inline int ReplayParentPrelude(const NativeWorkflow& native)
{
    return ReferenceCheckedStatus(ReferenceReadWorkflow(elements_hs_parent_prelude_v1,native),1,"Haskell parent prelude failed");
}

inline int M8Acceptance(uint64_t count, const std::function<int64_t(uint32_t,uint64_t)>& action)
{
    return ReferenceCheckedStatus(ReferenceReadBoundAdmission<int64_t,-1>(elements_hs_m8_acceptance_v1,
        action,count),2,"Haskell M8 acceptance failed");
}
inline int CoinbaseMessages(uint64_t count, const std::function<int64_t(uint32_t,uint64_t)>& action)
{
    return ReferenceCheckedStatus(ReferenceReadBoundAdmission<int64_t,-1>(elements_hs_coinbase_messages_v1,
        action,count),4,"Haskell coinbase message collection failed");
}
inline int ExpireProposals(uint64_t count, uint32_t height, uint32_t threshold, uint32_t max_age,
    const std::function<int64_t(uint32_t)>& action)
{
    return ReferenceCheckedStatus(ReferenceReadBoundAdmission<int64_t,-1>(elements_hs_expire_proposals_v1,
        action,count,height,threshold,max_age),2,"Haskell proposal expiry failed");
}
inline int ExpireWithdrawals(uint64_t count, uint32_t height, uint32_t max_age,
    const std::function<int64_t(uint32_t)>& action)
{
    return ReferenceCheckedStatus(ReferenceReadBoundAdmission<int64_t,-1>(elements_hs_expire_withdrawals_v1,
        action,count,height,max_age),1,"Haskell withdrawal expiry failed");
}
inline void PruneSlots(uint64_t count, const std::function<int64_t(uint32_t)>& action)
{
    ReferenceCheckedStatus(ReferenceReadBoundAdmission<int64_t,-1>(elements_hs_prune_slots_v1,
        action,count),0,"Haskell slot pruning failed");
}
inline bool BlockPublish(uint32_t flags, const std::function<int32_t(uint32_t)>& action)
{
    return ReferenceCheckedStatus(ReferenceReadBoundAdmission<int32_t,-1>(elements_hs_block_publish_v1,
        action,flags),1,"Haskell block publication failed") == 0;
}
inline bool ReferenceRuleResult(int code, std::span<const char* const> errors, std::string& error, const char* failure)
{
    ReferenceCheckedStatus(code, errors.size(), failure);
    if (code && errors[code-1]) error = errors[code-1];
    return code == 0;
}
inline bool AuthenticatedDepositResult(int32_t result, std::string& error)
{
    constexpr std::array<const char*, 8> errors{{
        "drivechain deposit transaction must contain exactly one input",
        "drivechain deposit transaction has an invalid input witness count",
        "drivechain deposit input does not match the authenticated outpoint",
        "drivechain deposit witness does not match the authenticated deposit",
        "drivechain deposit transaction must contain one credit output and at most one fee output",
        "drivechain deposit outputs must use explicit native asset values",
        "drivechain deposit destination script does not match enforcer data",
        "drivechain deposit output value and fee do not equal the authenticated deposit value",
    }};
    return ReferenceRuleResult(result, errors, error, "Haskell authenticated deposit evaluation failed");
}

inline bool AuthenticatedDeposit(uint64_t inputs, uint64_t index, uint64_t witnesses, uint32_t facts,
    int64_t claimed, int64_t witnessed, uint64_t outputs, const std::array<unsigned char, 2>& flags,
    const std::array<int64_t, 2>& amounts, std::string& error)
{
    elements_hs_runtime_init();
    return AuthenticatedDepositResult(elements_hs_authenticated_deposit_v1(inputs, index, witnesses, facts, claimed,
        witnessed, outputs, const_cast<unsigned char*>(flags.data()), const_cast<int64_t*>(amounts.data())),error);
}

inline bool DepositOutputs(uint32_t facts, int64_t value, std::span<const unsigned char> inputs,
    std::span<const unsigned char> flags, std::span<const int64_t> amounts, std::string& error)
{
    elements_hs_runtime_init();
    if (inputs.size() > std::numeric_limits<uint32_t>::max() || flags.size() != amounts.size() ||
        flags.size() > std::numeric_limits<uint32_t>::max()) throw std::length_error("Haskell deposit output shape invalid");
    const auto result = elements_hs_deposit_outputs_v1(facts, value, inputs.size(),
        const_cast<unsigned char*>(inputs.data()), flags.size(), const_cast<unsigned char*>(flags.data()),
        const_cast<int64_t*>(amounts.data()));
    constexpr std::array<const char*, 8> errors{{
        "Drivechain deposit transactions cannot mix deposit and legacy pegin inputs.",
        "Drivechain deposit transactions must contain exactly one drivechain pegin input.",
        "Drivechain deposit inputs cannot contain an asset issuance.",
        "Invalid drivechain deposit witness while checking outputs.",
        "Drivechain deposit claim script must be OP_TRUE.",
        "BIP300 deposit commits to an invalid Elements destination address.",
        "The committed deposit recipient must receive the exact explicit pegged-asset amount.",
        "Drivechain deposit transaction must contain exactly one recipient output.",
    }};
    return ReferenceRuleResult(result, errors, error, "Haskell deposit output evaluation failed");
}

inline int BmmSplitSignature(std::vector<unsigned char>& signature)
{
    elements_hs_runtime_init();
    uint64_t size{0};
    const auto result = elements_hs_bmm_split_signature_v1(signature.size(),signature.data(),&size);
    if (result < 0 || result > 255 || size > signature.size()) throw std::runtime_error("Haskell BMM signature split failed");
    signature.resize(size);
    return result;
}
inline uint32_t BmmSigHashPlan(int32_t type, uint32_t index, uint64_t count)
{
    elements_hs_runtime_init();
    return ReferenceCheckedStatus(elements_hs_bmm_sighash_plan_v1(type,index,count),15,"Haskell BMM signature hash planning failed");
}
inline bool BmmSignatureGate(bool witness, uint64_t size, uint32_t index, uint64_t inputs)
{
    elements_hs_runtime_init();
    return ReferenceCheckedStatus(elements_hs_bmm_signature_gate_v1(witness,size,index,inputs),1,"Haskell BMM signature preflight failed") == 1;
}
inline int32_t BmmStateFlow(BmmStateStep step, int32_t reply)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_bmm_state_flow_v1(static_cast<uint32_t>(step),reply);
    if (result < -1 || result > static_cast<int32_t>(BmmStateStep::SIGNATURE_MODE)) throw std::runtime_error("Haskell BMM state flow failed");
    return result;
}
inline void BmmSignatureActions(uint32_t plan, const std::function<void(uint32_t)>& action)
{
    elements_hs_runtime_init();
    std::vector<uint32_t> steps;
    const auto collect = +[](void* ctx,uint32_t step,uint32_t) -> int32_t {
        auto& values = *static_cast<std::vector<uint32_t>*>(ctx);
        if (values.size() >= 10) return 0;
        values.push_back(step);
        return 1;
    };
    steps.reserve(10);
    if (elements_hs_bmm_signature_actions_v1(plan,reinterpret_cast<HsFunPtr>(collect),&steps) != 1)
        throw std::runtime_error("Haskell BMM action plan failed");
    for (auto step : steps) action(step);
}
int M4Repeat(bool upvote, const std::function<int64_t(uint32_t)>& action);
int M3Proposal(const std::function<int64_t(uint32_t,uint64_t)>& action);
int M2Proposal(uint32_t height, uint16_t unused_age, uint16_t unused_threshold,
    uint16_t used_age, uint16_t used_threshold, const std::function<int64_t(uint32_t,uint64_t)>& action);
int M4Mode(uint32_t flags, uint64_t votes, const std::function<int64_t(uint32_t)>& action);
int ReplayUpvote(std::span<const unsigned char> hashes, std::span<const unsigned char,32> target, std::span<uint16_t> votes);
bool ReplayAlarm(std::span<uint16_t> votes);
int64_t ReplayLeading(std::span<const unsigned char> hashes, std::span<uint16_t> votes);
int ReplayExplicit(uint16_t vote, std::span<const unsigned char> hashes, std::span<uint16_t> votes);
uint64_t BmmWorkBudget(uint64_t count, const std::function<uint64_t(uint32_t,uint64_t,uint64_t)>& read);
bool BmmWorkTotal(bool saturate, uint64_t count, const std::function<uint64_t(uint64_t)>& read, uint64_t& total);
int CtipOwners(uint64_t count, uint64_t maximum, const std::function<int64_t(uint32_t)>& action);
int CtipSpends(uint64_t count, const std::function<int32_t(uint32_t,uint64_t)>& action);
int CtipOutputs(uint64_t count, uint64_t maximum, const std::function<int64_t(uint32_t,uint64_t)>& action);
int CtipReplacements(uint64_t count, const std::function<int32_t(uint32_t)>& action);
int CtipChanges(uint64_t count, const std::function<int64_t(uint32_t)>& action);
int M5Deposit(int64_t old_value, int64_t new_value, uint64_t maximum, uint64_t output, uint64_t outputs,
    uint32_t flags, const std::function<int64_t(uint32_t,uint64_t)>& action);
int M6Withdrawal(uint64_t decreases, uint64_t changes, uint64_t inputs, uint32_t threshold, bool single,
    const std::function<int64_t(uint32_t)>& action);
int32_t BmmLifecycle(BmmLifecyclePhase phase, uint32_t facts, const std::string& state_error, std::string& error);
inline int32_t ReferenceSignetResult(int32_t result, std::string& error)
{
    constexpr std::array<const char*, 6> errors{{
        "BMM parent block has no Bitcoin witness commitment",
        "BMM parent block has a malformed signet commitment script",
        "BMM parent block signet solution contains trailing data",
        "BMM parent block signet solution cannot be decoded",
        "BMM signet proof does not authenticate exactly the coinbase",
        "BMM parent block signet solution is invalid",
    }};
    if (result < -6 || result > 7) throw std::runtime_error("Haskell signet validation failed");
    if (result < 0) error = errors[-result - 1];
    return result;
}

template <typename Step, size_t Count>
inline int32_t ReferenceRunBmmFacts(uint32_t kind, Step start, const std::function<std::array<uint64_t,Count>(Step)>& action)
{
    static_assert(Count <= 4);
    const std::function<int32_t(uint32_t,uint64_t*)> read = [&](uint32_t step, uint64_t* fields) {
        const auto reply = action(static_cast<Step>(step));
        std::copy(reply.begin(),reply.end(),fields);
        return 1;
    };
    return ReferenceReadBoundAdmission<int32_t,-1>(elements_hs_bmm_proof_run_v1,read,kind,static_cast<uint32_t>(start));
}

inline int32_t ReferenceTraversalResult(int32_t result, std::string& error)
{
    if (result < -2 || result > 20) throw std::runtime_error("Haskell BMM traversal failed");
    if (result == -2 && error.empty()) error = "BMM parent header does not extend the authenticated state";
    return result;
}

inline bool RunSignetValidation(SignetStep start, const std::function<std::array<uint64_t,4>(SignetStep)>& action, std::string& error)
{
    return ReferenceSignetResult(ReferenceRunBmmFacts(0,start,action),error) == 0;
}

inline void BmmSignetActions(bool decode, const std::function<void(uint32_t)>& action)
{
    ReferenceBmmActionPlan([decode](HsFunPtr callback, void* context) {
        return elements_hs_bmm_signet_actions_v1(decode, callback, context);
    }, [&](uint32_t field, uint32_t) { action(field); });
}

inline bool ReferenceBmmProofResult(int32_t result, std::string& error)
{
    constexpr std::array<const char*, 11> errors{{
        "BMM proof envelope is invalid",
        "BMM proof entry exceeds its transaction or Merkle proof bound",
        "BMM proof entry has a malformed or non-canonical coinbase proof",
        "BMM Merkle proof does not authenticate exactly the parent coinbase",
        "BMM parent header does not extend the authenticated state",
        "BMM proof final header is not the successor of the committed L1 parent",
        "BMM successor commitment does not match the sidechain critical hash",
        "sidechain block does not commit its exact BMM proof bytes",
        "BMM proof does not extend the locally authenticated parent-chain state",
        "BMM proof contains an invalid parent-chain proof-of-work header",
        "sidechain block has no coinbase transaction",
    }};
    return ReferenceRuleResult(result, errors, error, "Haskell BMM proof evaluation failed");
}

enum class BmmCodecPhase : uint32_t { ENCODE_SIZE, DECODE_SIZE, DECODE_SHAPE, CANONICAL, ATTACH, STATE_ASSET, STATE_PUSH, STATE_DROP, STATE_END, STATE_PAYLOAD, STATE_EXCEPTION };

inline bool BmmCodec(BmmCodecPhase phase, uint32_t facts, uint64_t a, uint64_t b, std::string& error)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_bmm_codec_v1(static_cast<uint32_t>(phase), facts, a, b);
    constexpr std::array<const char*, 8> errors{{
        "serialized BMM proof exceeds its consensus size bound",
        "BMM proof is empty or exceeds its consensus size bound",
        "BMM proof is malformed or non-canonical",
        "cannot attach BMM proof without the header version bit",
        "persisted BMM state has invalid asset or value encoding",
        "persisted BMM state script is malformed",
        "persisted BMM state payload is invalid",
        "persisted BMM state payload cannot be decoded",
    }};
    if (result < 0 || result > static_cast<int32_t>(errors.size())) throw std::runtime_error("Haskell BMM codec evaluation failed");
    // The old payload-shape branch retained a preexisting diagnostic.
    if (result && (result != 7 || error.empty())) error = errors[result - 1];
    return result == 0;
}

inline bool RunBmmProofWorkflow(BmmTraversalStep start, const std::function<std::array<uint64_t,4>(uint32_t)>& read, std::string& error)
{
    const std::function<int32_t(uint32_t,uint64_t*)> action = [&](uint32_t step, uint64_t* fields) {
        const auto facts = read(step);
        std::copy(facts.begin(),facts.end(),fields);
        return 1;
    };
    const auto result = ReferenceReadBoundAdmission<int32_t,-1>(elements_hs_bmm_proof_workflow_v1,action,static_cast<uint32_t>(start));
    return result >= 101 && result <= 111 ? ReferenceBmmProofResult(result-100,error) : ReferenceTraversalResult(result,error) == 0;
}

inline bool ReferencePredicateResult(int code, const char* invalid, const char* failed)
{
    if (code == -2) throw std::runtime_error(invalid);
    return ReferenceCheckedStatus(code,1,failed) == 0;
}

inline bool ReferenceRunDepositFlow(uint32_t start, const std::function<bool(DepositVerifyStep)>& action)
{
    const std::function<bool(uint32_t)> read = [&](uint32_t step) { return action(static_cast<DepositVerifyStep>(step)); };
    return ReferencePredicateResult(ReferenceReadBoundAdmission<int64_t,-1>(elements_hs_deposit_run_v1,read,0,start),
        "Haskell deposit flow action invalid","Haskell deposit verification failed");
}

inline bool RunCheckpointLookup(const std::function<bool(DepositVerifyStep)>& action)
{
    return ReferenceRunDepositFlow(67,action);
}

inline bool RunLegacyClaim(const std::function<bool(DepositVerifyStep)>& action)
{
    return ReferenceRunDepositFlow(72,action);
}

inline void DepositTransactionFacts(const std::function<uint64_t(uint32_t)>& read)
{
    const std::function<int32_t(uint32_t,uint64_t*)> action = [&](uint32_t step, uint64_t* fields) {
        fields[0] = read(step);
        return 1;
    };
    ReferenceCheckedStatus(ReferenceReadBoundAdmission<int32_t,-1>(elements_hs_peg_read_run_v1,action,
        uint32_t{1},uint32_t{0},uint64_t{0}),0,"Haskell deposit fact projection failed");
}

inline bool ReferenceDepositStateResult(int32_t result, const std::string& decode_error, std::string& error)
{
    constexpr std::array<const char*, 11> errors{{
        "historical drivechain checkpoint cannot overwrite authenticated CTIP state",
        "", // Preserve the upstream decoding error verbatim.
        "drivechain deposit has no authenticated prior CTIP state",
        "drivechain deposit evidence is stale or does not extend the authenticated CTIP state",
        "cannot connect drivechain deposit over missing authenticated CTIP state",
        "cannot connect drivechain deposit over stale CTIP state",
        "cannot disconnect drivechain deposit without authenticated CTIP state",
        "historical drivechain checkpoint CTIP state is inconsistent during disconnect",
        "drivechain deposit CTIP state is inconsistent during disconnect",
        "historical drivechain checkpoint is not in its immutable L1 parent block",
        "drivechain deposit evidence anchor does not match sidechain block L1 parent",
    }};
    if (result < 0 || result > static_cast<int32_t>(errors.size())) throw std::runtime_error("Haskell deposit state evaluation failed");
    if (result) error = result == 2 ? decode_error : errors[result - 1];
    return result == 0;
}

int64_t BmmReplacementLimit(int64_t selected, int64_t extra);

inline int64_t BmmReplacementLimit(int64_t selected, int64_t extra)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_bmm_replacement_limit_v1(selected,extra,MAX_MONEY);
    if (result < -1 || result == 0) throw std::runtime_error("Haskell BMM replacement limit failed");
    return result;
}

int BmmSubmit(int64_t bid, int64_t maximum, const std::function<int64_t(uint32_t,uint64_t)>& action);

inline int BmmSubmit(int64_t bid, int64_t maximum, const std::function<int64_t(uint32_t,uint64_t)>& action)
{
    return ReferenceCheckedStatus(ReferenceReadBoundAdmission<int64_t,-1>(elements_hs_bmm_submit_v1,action,bid,maximum),
        2,"Haskell BMM submission failed");
}

int32_t SignetValidation(SignetStep step, uint64_t a, uint64_t b, uint64_t c, uint64_t d, std::string& error);

inline int32_t SignetValidation(SignetStep step, uint64_t a, uint64_t b, uint64_t c, uint64_t d, std::string& error)
{
    elements_hs_runtime_init();
    return ReferenceSignetResult(elements_hs_signet_validation_v1(static_cast<uint32_t>(step),a,b,c,d),error);
}

int32_t BmmTraversal(BmmTraversalStep step, uint64_t a, uint64_t b, std::string& error);

inline int32_t BmmTraversal(BmmTraversalStep step, uint64_t a, uint64_t b, std::string& error)
{
    elements_hs_runtime_init();
    return ReferenceTraversalResult(elements_hs_bmm_traversal_v1(static_cast<uint32_t>(step),a,b),error);
}

bool RunBmmTraversal(BmmTraversalStep start, const std::function<std::array<uint64_t,2>(BmmTraversalStep)>& action, std::string& error);

inline bool RunBmmTraversal(BmmTraversalStep start, const std::function<std::array<uint64_t,2>(BmmTraversalStep)>& action, std::string& error)
{
    return ReferenceTraversalResult(ReferenceRunBmmFacts(1,start,action),error) == 0;
}

bool BmmProof(BmmProofPhase phase, uint32_t facts, uint64_t a, uint64_t b, uint64_t c, std::string& error);

inline bool BmmProof(BmmProofPhase phase, uint32_t facts, uint64_t a, uint64_t b, uint64_t c, std::string& error)
{
    elements_hs_runtime_init();
    return ReferenceBmmProofResult(elements_hs_bmm_proof_v1(static_cast<uint32_t>(phase), facts, a, b, c),error);
}

bool RunDepositVerification(const std::function<bool(DepositVerifyStep)>& action, bool anchor = false);

inline bool RunDepositVerification(const std::function<bool(DepositVerifyStep)>& action, bool anchor)
{
    return ReferenceRunDepositFlow(anchor ? 11 : 0, action);
}

bool RunDepositLifecycle(const std::function<bool(DepositVerifyStep)>& action, bool disconnect);

inline bool RunDepositLifecycle(const std::function<bool(DepositVerifyStep)>& action, bool disconnect)
{
    return ReferenceRunDepositFlow(disconnect ? 27 : 19, action);
}

bool DepositState(DepositStatePhase phase, bool present, bool matches,
    const std::string& decode_error, std::string& error);

inline bool DepositState(DepositStatePhase phase, bool present, bool matches,
    const std::string& decode_error, std::string& error)
{
    elements_hs_runtime_init();
    return ReferenceDepositStateResult(elements_hs_deposit_state_v1(static_cast<uint32_t>(phase),
        DepositStateFacts(present, matches, decode_error)), decode_error, error);
}

int64_t WithdrawalPayout(int64_t burn, int64_t fee, int64_t maximum_money);

inline int64_t WithdrawalPayout(int64_t burn, int64_t fee, int64_t maximum_money)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_withdrawal_payout_v1(burn, fee, maximum_money);
    if (result < -3 || result == 0) throw std::runtime_error("Haskell withdrawal evaluation failed");
    return result;
}

std::vector<unsigned char> WithdrawalAnchorPayload(uint32_t height,
    const std::array<const unsigned char*, 4>& commitments, bool wallet = false);

inline std::vector<unsigned char> WithdrawalAnchorPayload(uint32_t height,
    const std::array<const unsigned char*, 4>& commitments, bool wallet)
{
    std::array<unsigned char, 132> input{};
    WriteLE32(input.data(), height);
    for (size_t i = 0; i < commitments.size(); ++i)
        std::copy_n(commitments[i], 32, input.begin() + 4 + 32 * i);
    std::vector<unsigned char> output;
    std::string error;
    if (!WithdrawalBytes(wallet ? WithdrawalOp::WALLET_ANCHOR : WithdrawalOp::STATE_ANCHOR, input, output, &error)) {
        if (wallet) throw std::invalid_argument(error);
        throw std::runtime_error("Haskell withdrawal anchor evaluation failed");
    }
    return output;
}

int64_t WithdrawalRpcFee(int64_t amount, int64_t fee);

inline int64_t WithdrawalRpcFee(int64_t amount, int64_t fee)
{
    std::array<unsigned char,16> input{};
    WriteLE64(input.data(), amount);
    WriteLE64(input.data()+8, fee);
    std::vector<unsigned char> output;
    std::string error;
    if (!WithdrawalBytes(WithdrawalOp::RPC_FEE, input, output, &error)) throw std::invalid_argument(error);
    return static_cast<int64_t>(ReadLE64(output.data()));
}

WithdrawalEventDecision ClassifyWithdrawalEvent(std::string_view status);

inline WithdrawalEventDecision ClassifyWithdrawalEvent(std::string_view status)
{
    std::vector<unsigned char> output;
    if (!WithdrawalBytes(WithdrawalOp::EVENT_POLICY,
            {reinterpret_cast<const unsigned char*>(status.data()), status.size()}, output, nullptr) ||
        output[0] > 2 || output[1] > 1) throw std::runtime_error("Haskell withdrawal event policy failed");
    return {output[0], output[1] != 0};
}
uint32_t CtipScript(const std::function<int32_t(uint32_t)>& read);

inline uint32_t CtipScript(const std::function<int32_t(uint32_t)>& read)
{
    const auto result = ReferenceReadAdmission<int32_t, -1>(elements_hs_ctip_script_v1, read);
    if (result < 0) throw std::runtime_error("Haskell CTIP script evaluation failed");
    return result;
}

bool PersistedCtip(uint32_t facts, int64_t amount, uint32_t script,
    EvidenceDecode decode, void* context, std::string& error);

inline bool PersistedCtip(uint32_t facts, int64_t amount, uint32_t script,
    EvidenceDecode decode, void* context, std::string& error)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_persisted_ctip_v1(facts, amount, script,
        reinterpret_cast<HsFunPtr>(decode), context);
    constexpr std::array<const char*, 4> errors{{
        "persisted drivechain CTIP state has invalid asset or value encoding",
        "persisted drivechain CTIP state script is malformed",
        "persisted drivechain CTIP state payload is invalid",
        "persisted drivechain CTIP state payload cannot be decoded",
    }};
    return ReferenceRuleResult(result, errors, error, "Haskell persisted CTIP evaluation failed");
}
inline int64_t BmmRetarget(uint32_t height, int64_t interval, int64_t target, uint32_t time, uint32_t start)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_bmm_retarget_v1(height, interval, target, time, start);
    if (result < -1) throw std::runtime_error("Haskell BMM retarget evaluation failed");
    return result;
}

inline void BmmScaleTarget(uint64_t factor, uint64_t divisor, std::span<unsigned char, 32> target,
    std::span<const unsigned char, 32> limit)
{
    elements_hs_runtime_init();
    if (elements_hs_bmm_scale_target_v1(32, factor, divisor, target.data(),
            const_cast<unsigned char*>(limit.data())) != 0) {
        throw std::runtime_error("Haskell BMM target scaling failed");
    }
}
inline bool ReferenceDepositProofResult(int32_t result, std::string& error)
{
    constexpr std::array<const char*, 7> errors{{
        "drivechain deposit outpoint is absent from the authenticated L1 transaction",
        "drivechain deposit merkle proof does not authenticate the exact L1 transaction",
        "drivechain deposit evidence contains an invalid L1 proof-of-work header",
        "drivechain deposit L1 header evidence is not a contiguous chain",
        "drivechain deposit outpoint is not the slot-24 CTIP output",
        "drivechain deposit transaction does not spend exactly one authenticated prior CTIP",
        "drivechain deposit value does not equal the authenticated CTIP increase",
    }};
    return ReferenceRuleResult(result, errors, error, "Haskell deposit proof evaluation failed");
}

inline bool DepositDestination(std::size_t count, DestinationInspect inspect, void* context, std::string& error)
{
    elements_hs_runtime_init();
    if (count > std::numeric_limits<uint32_t>::max()) throw std::length_error("Haskell destination output count too large");
    const auto result = elements_hs_deposit_destination_v2(count, reinterpret_cast<HsFunPtr>(inspect), context);
    if (result < -2 || (result >= 0 && static_cast<uint64_t>(result) >= count))
        throw std::runtime_error("Haskell destination evaluation failed");
    if (result < 0) error = result == -1 ? "deposit transaction does not commit a valid sidechain destination"
                                       : "deposit transaction contains multiple valid sidechain destinations";
    return result >= 0;
}

inline bool DepositInclusion(uint32_t facts, uint64_t matches, uint32_t headers,
    ParentHeaderCheck check_header, void* context, std::string& error)
{
    elements_hs_runtime_init();
    return ReferenceDepositProofResult(elements_hs_deposit_inclusion_v1(facts, matches, headers,
        reinterpret_cast<HsFunPtr>(check_header), context), error);
}

inline bool DepositCtip(uint32_t facts, uint64_t matches, int64_t current, int64_t previous,
    int64_t witnessed, std::string& error)
{
    elements_hs_runtime_init();
    return ReferenceDepositProofResult(elements_hs_deposit_ctip_v1(facts, matches, current, previous, witnessed), error);
}

inline bool RunDepositParsing(const std::function<bool(DepositVerifyStep)>& action)
{
    return ReferenceRunDepositFlow(35, action);
}

inline void RunCtipInputScan(const std::function<bool(DepositVerifyStep)>& action)
{
    if (!ReferenceRunDepositFlow(51, action)) throw std::runtime_error("Haskell CTIP input scan failed");
}

// Retired legacy bundle builder; no production caller remains.
struct WithdrawalBundlePlan { int64_t payout; std::vector<unsigned char> fee_script, inputs, marker;
    int32_t version; std::vector<unsigned char> outputs; };
struct WithdrawalAnchorError : std::invalid_argument { using std::invalid_argument::invalid_argument; };
std::vector<unsigned char> BuildWithdrawalBundle(int64_t amount, int64_t fee, uint64_t script_size,
    bool known_outpoint, const std::function<const std::vector<unsigned char>&(const WithdrawalBundlePlan&)>& build,
    std::span<const unsigned char> context, std::span<const unsigned char> anchor_context = {});
inline std::vector<unsigned char> BuildWithdrawalBundle(int64_t amount, int64_t fee, uint64_t script_size,
    bool known_outpoint, const std::function<const std::vector<unsigned char>&(const WithdrawalBundlePlan&)>& build)
{
    return BuildWithdrawalBundle(amount,fee,script_size,known_outpoint,build,{});
}

inline std::vector<unsigned char> BuildWithdrawalBundle(int64_t amount, int64_t fee, uint64_t script_size,
    bool known_outpoint, const std::function<const std::vector<unsigned char>&(const WithdrawalBundlePlan&)>& build,
    std::span<const unsigned char> bundle_context, std::span<const unsigned char> anchor_context)
{
    if (!build) throw std::invalid_argument("missing withdrawal construction callback");
    if (!bundle_context.empty() && bundle_context.size()!=40) throw std::invalid_argument("invalid withdrawal commitment context");
    if (!anchor_context.empty() && (anchor_context.size()!=96 || bundle_context.size()!=40))
        throw std::invalid_argument("invalid withdrawal anchor context");
    std::array<unsigned char,161> input{};
    WriteLE64(input.data(),amount); WriteLE64(input.data()+8,fee); WriteLE64(input.data()+16,script_size);
    input[24]=known_outpoint;
    std::copy(bundle_context.begin(),bundle_context.end(),input.begin()+25);
    std::copy(anchor_context.begin(),anchor_context.end(),input.begin()+65);
    std::vector<unsigned char> transport;
    std::string anchor_error;
    uint256 digest;
    const int code=ReferenceReadAdmission<int64_t,-1>([&](HsFunPtr callback,void* context) {
        if (!anchor_context.empty()) return elements_hs_wallet_bundle_v3(MAX_MONEY,input.data(),input.size(),callback,context);
        return bundle_context.empty() ? elements_hs_wallet_bundle_v1(MAX_MONEY,input.data(),callback,context) :
            elements_hs_wallet_bundle_v2(MAX_MONEY,input.data(),65,callback,context);
    },std::function<int64_t(uint32_t,uint64_t,unsigned char*,uint32_t,unsigned char**)>{
        [&](uint32_t action,uint64_t payout,unsigned char* bytes,uint32_t size,unsigned char** reply) -> int64_t {
            if (!bytes) throw std::logic_error("null withdrawal construction data");
            if (action==1) { transport.assign(bytes,bytes+size); return 0; }
            if (action==4 && !anchor_context.empty()) { anchor_error.assign(bytes,bytes+size); return 0; }
            if ((action==2 || action==3) && !anchor_context.empty() && reply) {
                if (action==2 && size==73) digest=Hash(std::span{bytes,size});
                else if (action==3 && size>1 && bytes[0]<size-1) {
                    auto hasher=TaggedHash(std::string(bytes+1,bytes+1+bytes[0]));
                    hasher.write(AsBytes(Span{bytes+1+bytes[0],size-1-bytes[0]}));
                    digest=hasher.GetSHA256();
                } else throw std::logic_error("invalid withdrawal digest input");
                *reply=digest.begin(); return 32;
            }
            const size_t plan_size=bundle_context.empty() ? 10U : 83U;
            if (action!=0 || size<5 || !reply || payout>MAX_MONEY)
                throw std::logic_error("invalid withdrawal construction action");
            const size_t layout_size=5U+bytes[4];
            if (size!=layout_size+plan_size+(anchor_context.empty() ? 0U : 39U))
                throw std::logic_error("invalid withdrawal construction action");
            auto* fields=bytes+layout_size;
            const auto& serialized=build({static_cast<int64_t>(payout),{fields,fields+10},
                {fields+10,fields+plan_size},{fields+plan_size,bytes+size},
                static_cast<int32_t>(ReadLE32(bytes)),{bytes+5,fields}});
            if (serialized.size()>std::numeric_limits<int32_t>::max()-3)
                throw std::length_error("Haskell withdrawal transport input too large");
            *reply=const_cast<unsigned char*>(serialized.data());
            return serialized.size();
        }});
    if (code==1) throw std::invalid_argument("Invalid blinded withdrawal amount, fee, payout, or outpoint");
    if (code==2 && !anchor_context.empty() && !anchor_error.empty()) throw WithdrawalAnchorError(anchor_error);
    if (code!=0) throw std::runtime_error("Haskell withdrawal bundle evaluation failed");
    return transport;
}
} // namespace drivechain::haskell
inline bool HasRequiredDrivechainDepositDepth(uint32_t deposit, uint32_t tip, uint32_t required)
{
    return drivechain::haskell::HasDepositDepth(deposit, tip, required);
}
// Retired wallet subrule adapters, retained only for differential tests.
namespace wallet {

CAmount LegacyWithdrawalAmount(CAmount payout);
CAmount ValidateNativePayout(const CScript& destination, CAmount payout);
/** Payout must already be admitted. Validate fee/total before constructing the burn. */
CAmount PrepareNativeBurn(const uint256& parent, const CScript& destination,
    CAmount payout, CAmount fee, CScript& burn);
enum class WithdrawalCheck : unsigned char { NETWORK, ACTIVATION, SUBTRACT_FEE, RELAY, LEGACY_NETWORK };
void CheckWithdrawal(WithdrawalCheck check, bool value);

struct DrivechainWithdrawalBundle {
    std::vector<unsigned char> bytes;
    std::vector<unsigned char> no_witness_bytes;
    uint256 m6id;
};

/** Decode a parent-network address or exact hex script and reject unspendable payouts. */
CScript DecodeDrivechainWithdrawalDestination(const std::string& destination);

/** Require exactly one parsed native burn matching all requested amounts. */
uint32_t FindNativeWithdrawalOutput(const CTransaction& tx, const CScript& burn_script,
    const CAsset& asset, const uint256& parent_genesis, CAmount burn, CAmount payout, CAmount fee);

/** Read the first matching legacy enforcer event; this does not authenticate it. */
std::string FindWithdrawalBundleEventStatus(const UniValue& peg_data, const std::string& m6id_hex);

/** Legacy inputless M6 codec; does not authorize a burn or broadcast.
 * Native Betanet withdrawals use drivechain::BuildNativeWithdrawalM6 instead.
 */
DrivechainWithdrawalBundle BuildDrivechainWithdrawalBundle(
    CAmount amount, CAmount mainchain_fee, const CScript& payout_script,
    const COutPoint& withdrawal_outpoint, uint32_t sidechain_block_height);

/** Build the historical slot-24 ECX-bound BIP300 M6 bytes. */
DrivechainWithdrawalBundle BuildDrivechainWithdrawalBundle(
    CAmount amount,
    CAmount mainchain_fee,
    const CScript& payout_script,
    const COutPoint& withdrawal_outpoint,
    uint32_t sidechain_block_height,
    const uint256& child_genesis,
    const uint256& previous_child_hash,
    const uint256& exchange_state_root);

} // namespace wallet
#endif
