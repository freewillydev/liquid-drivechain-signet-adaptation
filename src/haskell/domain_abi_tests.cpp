// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <haskell/domain_abi.h>
#include <iostream>
#include <limits>

extern "C" void elements_hs_runtime_init(void);
static void Require(bool condition)
{
    if (!condition) throw std::runtime_error("domain ABI test failed");
}

template <auto Function, uint32_t Operation, typename Signature, typename... Args>
static auto Raw(elements_abi::Binding<Function, Operation, Signature>, Args... args)
{
    return Function(Operation, args...);
}

int main()
{
    try {
        elements_hs_runtime_init();
        const auto& domains = elements_hs_families_v3;
        Require(domains.size() == 4);
        constexpr uint64_t CANARY{0x123456789abcdef0};
        uint32_t handlers{0};
        for (const auto& [domain, sections] : domains) {
            uint64_t result{CANARY};
            Require(domain(sections.size() << 16,0,nullptr,0,nullptr,0,nullptr,&result) == -1);
            Require(domain(UINT32_MAX,0,nullptr,0,nullptr,0,nullptr,&result) == -1);
            // Every handler rejects malformed shape before touching borrowed memory.
            for (uint32_t section = 0; section < sections.size(); ++section) {
                const auto prefix = section << 16;
                const auto count = sections[section];
                handlers += count;
                Require(domain(prefix | count,0,nullptr,0,nullptr,0,nullptr,&result) == -1);
                Require(domain(prefix | 0xffff,0,nullptr,0,nullptr,0,nullptr,&result) == -1);
                for (uint32_t operation = 0; operation < count; ++operation) {
                    Require(domain(prefix | operation,UINT32_MAX,nullptr,0,nullptr,0,nullptr,&result) == -1);
                    Require(domain(prefix | operation,0,nullptr,UINT32_MAX,nullptr,0,nullptr,&result) == -1);
                    Require(domain(prefix | operation,0,nullptr,0,nullptr,UINT32_MAX,nullptr,&result) == -1);
                    Require(domain(prefix | operation,0,nullptr,0,nullptr,0,nullptr,nullptr) == -1);
                }
            }
            Require(result == CANARY);
        }
        uint64_t result{CANARY};
        for (uint32_t version : {0U, 1U, 1U << 20, 1U << 30, 1U << 31, UINT32_MAX}) {
            constexpr uint32_t canary{0xabcdef01};
            uint32_t output[]{canary,91,92,canary};
            Require(elements_hs_bmm_header_layout_v1(version,16,2,output+1) == 0);
            Require(output[0] == canary && output[3] == canary);
            Require(output[1] == version);
            Require((output[2] & ~0x43U) == 0);
            Require(elements_hs_bmm_header_layout_v1(version,16,1,output+1) == -1);
            Require(elements_hs_bmm_header_layout_v1(version,16,2,nullptr) == -1);
        }
        uint64_t depth[]{100,105,6};
        Require(Raw(elements_hs_deposit_depth_v1,3,depth,0,nullptr,0,nullptr,&result) == 0 && result == 1);
        depth[1] = uint64_t{1} << 32;
        result = CANARY;
        Require(Raw(elements_hs_deposit_depth_v1,3,depth,0,nullptr,0,nullptr,&result) == -2 && result == CANARY);
        Require(Raw(elements_hs_deposit_depth_v1,3,nullptr,0,nullptr,0,nullptr,&result) == -1 && result == CANARY);
        uint64_t state[]{0,0xffffffff};
        Require(Raw(elements_hs_bmm_state_flow_v1,2,state,0,nullptr,0,nullptr,&result) == -2 && result == CANARY);
        // Canonical sign extension, including INT64_MIN, survives the new transport.
        for (const int64_t amount : {int64_t{-1}, std::numeric_limits<int64_t>::min(), std::numeric_limits<int64_t>::max()}) {
            uint64_t args[]{static_cast<uint64_t>(amount),0,0};
            Require(Raw(elements_hs_withdrawal_payout_v1,3,args,0,nullptr,0,nullptr,&result) == 0);
            Require(elements_hs_withdrawal_payout_v1(amount,0,0) == std::bit_cast<int64_t>(result));
        }
        Require(elements_hs_deposit_depth_v1(100,105,6) == 1);
        Require(elements_hs_deposit_depth_v1(100,104,6) == 0);
        for (uint32_t mode : {0U,1U,2U,UINT32_MAX})
            Require(elements_hs_replay_maintenance_v1(mode,0,0,0,0,nullptr,nullptr) == -1);
        unsigned char signature[]{42,1};
        Require(elements_hs_bmm_signature_workflow_v1(0,0,1,0,1,1,1,nullptr,nullptr,nullptr) == -1);
        Require(elements_hs_bmm_signature_workflow_v1(0,0,1,0,1,1,UINT64_MAX,signature,nullptr,nullptr) == -1);
        Require(elements_hs_bmm_signature_workflow_v1(3,0,1,0,1,1,2,signature,nullptr,nullptr) == -1);
        Require(elements_hs_bmm_signature_workflow_v1(0,0,1,0,1,1,2,signature,nullptr,nullptr) == -1);
        Require(elements_hs_bmm_signature_workflow_v1(2,1,0,0,1,1,0,nullptr,nullptr,nullptr) == -1);
        // Rejection before a native effect does not require its callback.
        Require(elements_hs_bmm_signature_workflow_v1(0,0,0,0,1,1,2,signature,nullptr,nullptr) == 0);
        Require(elements_hs_bmm_signature_workflow_v1(0,0,1,0,1,1,0,nullptr,nullptr,nullptr) == 0);
        for (uint32_t mode : {0U,1U,2U}) {
            for (uint32_t fault = 0; fault < 5; ++fault) {
                struct Reply { uint32_t fault; unsigned calls{}; unsigned char bytes[2]{1,2}; } reply{fault};
                auto effect = +[](void* context,uint32_t,uint64_t,uint64_t,unsigned char*,uint64_t* size,unsigned char** data) -> int32_t {
                    auto& state = *static_cast<Reply*>(context);
                    ++state.calls;
                    *size = state.fault == 1 ? UINT64_MAX : state.fault == 3 ? 2 : 1;
                    *data = state.fault == 2 ? nullptr : state.bytes;
                    if (state.fault == 4) state.bytes[0] = 2;
                    return state.fault == 0 ? 0 : 1;
                };
                Require(elements_hs_bmm_signature_workflow_v1(mode,1,1,0,1,1,2,signature,
                    reinterpret_cast<void (*)()>(effect),&reply) == -1);
                Require(reply.calls == 1);
            }
        }
        for (uint32_t upper : {0U, 1U, uint32_t{INT32_MAX}, UINT32_MAX}) {
            for (uint32_t lower : {0U, 1U, uint32_t{INT32_MAX}, UINT32_MAX}) {
                uint64_t args[]{upper, lower};
                const int64_t expected = lower <= upper ? int64_t{upper} - lower : -1;
                Require(Raw(elements_hs_replay_distance_v1,2,args,0,nullptr,0,nullptr,&result) == 0);
                Require(std::bit_cast<int64_t>(result) == expected);
                Require(elements_hs_replay_distance_v1(upper,lower) == expected);
            }
        }
        for (unsigned wide = 0; wide < 2; ++wide) {
            uint64_t args[]{0,0};
            args[wide] = uint64_t{1} << 32;
            result = CANARY;
            Require(Raw(elements_hs_replay_distance_v1,2,args,0,nullptr,0,nullptr,&result) == -2);
            Require(result == CANARY);
        }
        for (int64_t height : {INT64_MIN,int64_t{-1},int64_t{0},int64_t{4294967294},int64_t{4294967295},INT64_MAX}) {
            uint64_t args[]{std::bit_cast<uint64_t>(height)};
            Require(Raw(elements_hs_approving_parent_height_v1,1,args,0,nullptr,0,nullptr,&result) == 0);
            Require(std::bit_cast<int64_t>(result) == elements_hs_approving_parent_height_v1(height));
            for (int64_t parent : {INT64_MIN,int64_t{0},INT64_MAX}) {
                uint64_t pair[]{args[0],std::bit_cast<uint64_t>(parent)};
                Require(Raw(elements_hs_child_behind_v1,2,pair,0,nullptr,0,nullptr,&result) == 0);
                Require(result == uint64_t(height < parent));
            }
        }
        std::cout << domains.size() << " domains, " << handlers << " handlers: shape/range/null rejection, canaries, signed values and typed adapters passed\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
