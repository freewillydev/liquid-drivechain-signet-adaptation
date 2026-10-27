// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <atomic>
#include <csignal>
#include <cstdint>
#include <dlfcn.h>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>

static void Require(bool ok)
{
    if (!ok) throw std::runtime_error("Haskell dynamic-loader test failed");
}
static void SignalHandler(int) {}

int main(int argc, char** argv)
{
    try {
        Require(argc == 2);
        struct sigaction handler{}, after{};
        handler.sa_handler = SignalHandler;
        sigemptyset(&handler.sa_mask);
        Require(sigaction(SIGINT, &handler, nullptr) == 0);
        std::atomic<bool> ready{false}, ok{true};
        std::vector<std::thread> threads;
        for (unsigned i = 0; i < 8; ++i) threads.emplace_back([&] {
            while (!ready) std::this_thread::yield();
            for (unsigned round = 0; round < 20; ++round) {
                void* library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
                if (!library) { ok = false; return; }
                auto initialize = reinterpret_cast<void (*)()>(dlsym(library, "elements_hs_runtime_init"));
                using Domain = int32_t (*)(uint32_t,uint32_t,uint64_t*,uint32_t,void**,uint32_t,void (**)(),uint64_t*);
                auto depth = reinterpret_cast<Domain>(dlsym(library, "elements_hs_peg_api_v3"));
                if (!initialize || !depth || dlsym(library, "elements_hs_deposit_depth_v1") ||
                    dlsym(library, "elements_hs_deposit_evidence_api_v1") ||
                    dlsym(library, "elements_hs_peg_api_v2") ||
                    dlsym(library, "elements_hs_node_api_v2") ||
                    dlsym(library, "elements_hs_parent_api_v2") ||
                    dlsym(library, "elements_hs_bmm_api_v2") ||
                    dlsym(library, "elements_hs_exchange_api_v2") ||
                    dlsym(library, "elements_hs_usdd_api_v2")) ok = false;
                else {
                    initialize();
                    uint64_t args[]{100,105,6}, result{};
                    constexpr uint32_t DEPTH_OPERATION = (2U << 16) | 8U;
                    if (depth(DEPTH_OPERATION,3,args,0,nullptr,0,nullptr,&result) != 0 || result != 1) ok = false;
                    args[1] = 104;
                    if (depth(DEPTH_OPERATION,3,args,0,nullptr,0,nullptr,&result) != 0 || result != 0) ok = false;
                }
                if (dlclose(library) != 0) ok = false;
            }
        });
        ready = true;
        for (auto& thread : threads) thread.join();
        Require(ok);
        Require(sigaction(SIGINT, nullptr, &after) == 0 && after.sa_handler == SignalHandler);
        std::cout << "Haskell loader passed: 160 concurrent load/init/call/unload cycles; signals preserved\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
