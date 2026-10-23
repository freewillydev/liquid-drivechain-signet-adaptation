// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <atomic>
#include <csignal>
#include <cstdint>
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif
#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>

static void Require(bool ok)
{
    if (!ok) throw std::runtime_error("Haskell dynamic-loader test failed");
}
static void SignalHandler(int) {}

#ifdef _WIN32
static HMODULE Load(const char* path)
{
    return LoadLibraryExA(path, nullptr,
                         LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
}
static FARPROC Symbol(HMODULE library, const char* name) { return GetProcAddress(library, name); }
static bool Unload(HMODULE library) { return FreeLibrary(library) != 0; }
#else
static void* Load(const char* path) { return dlopen(path, RTLD_NOW | RTLD_LOCAL); }
static void* Symbol(void* library, const char* name) { return dlsym(library, name); }
static bool Unload(void* library) { return dlclose(library) == 0; }
#endif

int main(int argc, char** argv)
{
    try {
        Require(argc == 2);
#ifdef _WIN32
        Require(std::signal(SIGINT, SignalHandler) != SIG_ERR);
#else
        struct sigaction handler{}, after{};
        handler.sa_handler = SignalHandler;
        sigemptyset(&handler.sa_mask);
        Require(sigaction(SIGINT, &handler, nullptr) == 0);
#endif
        std::atomic<bool> ready{false}, ok{true};
        std::vector<std::thread> threads;
        for (unsigned i = 0; i < 8; ++i) threads.emplace_back([&] {
            while (!ready) std::this_thread::yield();
            for (unsigned round = 0; round < 20; ++round) {
                auto library = Load(argv[1]);
                if (!library) { ok = false; return; }
                auto initialize = reinterpret_cast<void (*)()>(Symbol(library, "elements_hs_runtime_init"));
                using Domain = int32_t (*)(uint32_t,uint32_t,uint64_t*,uint32_t,void**,uint32_t,void (**)(),uint64_t*);
                auto depth = reinterpret_cast<Domain>(Symbol(library, "elements_hs_deposit_evidence_api_v1"));
                if (!initialize || !depth || Symbol(library, "elements_hs_deposit_depth_v1")) ok = false;
                else {
                    initialize();
                    uint64_t args[]{100,105,6}, result{};
                    if (depth(8,3,args,0,nullptr,0,nullptr,&result) != 0 || result != 1) ok = false;
                    args[1] = 104;
                    if (depth(8,3,args,0,nullptr,0,nullptr,&result) != 0 || result != 0) ok = false;
                }
                if (!Unload(library)) ok = false;
            }
        });
        ready = true;
        for (auto& thread : threads) thread.join();
        Require(ok);
#ifdef _WIN32
        Require(std::signal(SIGINT, SignalHandler) == SignalHandler);
#else
        Require(sigaction(SIGINT, nullptr, &after) == 0 && after.sa_handler == SignalHandler);
#endif
        std::cout << "Haskell loader passed: 160 concurrent load/init/call/unload cycles; signals preserved\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
