// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#define _GNU_SOURCE
#include <Rts.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#include <pthread.h>
#endif
#include <stdlib.h>

static void runtime_defaults(void)
{
    // The embedding node owns its signals. Do not parse GHCRTS or node argv.
    RtsFlags.MiscFlags.install_signal_handlers = false;
}

static void initialize_runtime(void)
{
    // RTS workers outlive a libconsensus consumer. Keep their code and its
    // transitive runtime dependencies mapped even after that consumer dlcloses.
#ifdef _WIN32
    HMODULE self;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_PIN,
                           (LPCWSTR)&initialize_runtime, &self)) abort();
#else
    Dl_info self;
    if (!dladdr((void*)&initialize_runtime, &self) ||
        !dlopen(self.dli_fname, RTLD_NOW | RTLD_NODELETE)) abort();
#endif
    int argc = 1;
    char name[] = "elements-haskell";
    char* argv[] = {name, NULL};
    char** args = argv;
    RtsConfig config = defaultRtsConfig;
    config.rts_opts_enabled = RtsOptsIgnoreAll;
    config.rts_opts_suggestions = false;
    config.defaultsHook = runtime_defaults;
    hs_init_ghc(&argc, &args, config);
}

#ifdef _WIN32
static BOOL CALLBACK initialize_runtime_once(PINIT_ONCE once, PVOID parameter, PVOID* context)
{
    (void)once;
    (void)parameter;
    (void)context;
    initialize_runtime();
    return TRUE;
}
#endif

// Shared by every C++ adapter instance, including dynamically loaded consumers.
#ifdef _WIN32
__declspec(dllexport)
#endif
void elements_hs_runtime_init(void)
{
#ifdef _WIN32
    static INIT_ONCE once = INIT_ONCE_STATIC_INIT;
    if (!InitOnceExecuteOnce(&once, initialize_runtime_once, NULL, NULL)) abort();
#else
    static pthread_once_t once = PTHREAD_ONCE_INIT;
    if (pthread_once(&once, initialize_runtime) != 0) abort();
#endif
}
