// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <haskell/bridge.h>
#include <GrpcClient_stub.h>
#include <array>
#include <exception>
#include <stdexcept>
#ifdef _WIN32
#include <grpc/event_engine/event_engine.h>
#include <mutex>
#endif

extern "C" void elements_hs_runtime_init(void);

namespace drivechain::haskell {
#ifdef _WIN32
namespace {
// C-core's last channel can release its default event engine asynchronously.
// Keep it owned until every native request has destroyed its calls/channels,
// then join its cleanup here, before Windows enters DLL_PROCESS_DETACH. Waiting
// from a DLL destructor is unsafe because Windows has already stopped threads.
class WindowsGrpcEngine final {
    static std::mutex mutex;
    static size_t users;
public:
    WindowsGrpcEngine()
    {
        const std::lock_guard lock{mutex};
        if (users == 0) {
            namespace engine = grpc_event_engine::experimental;
            engine::SetDefaultEventEngine(engine::CreateEventEngine());
        }
        ++users;
    }
    ~WindowsGrpcEngine()
    {
        const std::lock_guard lock{mutex};
        if (--users == 0) grpc_event_engine::experimental::ShutdownDefaultEventEngine();
    }
    WindowsGrpcEngine(const WindowsGrpcEngine&) = delete;
    WindowsGrpcEngine& operator=(const WindowsGrpcEngine&) = delete;
};
std::mutex WindowsGrpcEngine::mutex;
size_t WindowsGrpcEngine::users{0};
} // namespace
#endif

GrpcResponse GrpcRequest(std::span<const std::string, 7> fields, int64_t timeout_ms,
    size_t max_output, const std::function<bool()>& should_cancel)
{
    elements_hs_runtime_init();
    struct Context {
        const std::function<bool()>& cancel;
        size_t maximum;
        std::string output;
        std::exception_ptr exception;
    } context{should_cancel, max_output, {}, {}};
    const auto cancel = +[](void* opaque) noexcept -> int {
        auto& state = *static_cast<Context*>(opaque);
        try { return state.exception || (state.cancel && state.cancel()); }
        catch (...) { state.exception = std::current_exception(); return 1; }
    };
    const auto emit = +[](void* opaque, char* bytes, size_t size) noexcept {
        auto& state = *static_cast<Context*>(opaque);
        try {
            if (size > state.maximum) throw std::runtime_error("Haskell gRPC output exceeded bound");
            state.output.assign(bytes, size);
        } catch (...) { state.exception = std::current_exception(); }
    };
    std::array<const char*, 7> pointers;
    for (size_t i = 0; i < fields.size(); ++i) {
        if (fields[i].find('\0') != std::string::npos)
            throw std::invalid_argument("NUL in enforcer request field");
        pointers[i] = fields[i].c_str();
    }
#ifdef _WIN32
    const WindowsGrpcEngine engine_lifetime;
#endif
    const int status = elements_hs_grpc_v1(pointers.data(), timeout_ms, max_output,
        reinterpret_cast<HsFunPtr>(cancel), reinterpret_cast<HsFunPtr>(emit), &context);
    if (context.exception) std::rethrow_exception(context.exception);
    return {status, std::move(context.output)};
}
} // namespace drivechain::haskell
