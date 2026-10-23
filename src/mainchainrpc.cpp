#include <mainchainrpc.h>
#include <drivechain_bmm.h>
#include <init.h>
#include <elements_drivechain_bootstrap.h>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <common/args.h>
#include <logging.h>
#include <chainparamsbase.h>
#include <consensus/merkle.h>
#include <crypto/common.h>
#include <drivechain_parent_replay.h>
#include <drivechain_parent_recovery.h>
#include <drivechain_treasury.h>
#include <haskell/bridge.h>
#include <elements_drivechain_identity.h>
#include <hash.h>
#include <primitives/block.h>
#include <primitives/bitcoin/block.h>
#include <script/script.h>
#include <signet.h>
#include <streams.h>
#include <util/signalinterrupt.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <rpc/request.h>

#include <support/events.h>

#include <rpc/client.h>

#include <event2/buffer.h>
#include <event2/keyvalq_struct.h>

#include <array>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <deque>
#include <exception>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <ranges>
#include <set>
#include <thread>
#include <tuple>
#include <vector>

namespace Bitcoin = Sidechain::Bitcoin;

namespace {

/**
 * One validation operation may spend at most two seconds in synchronous
 * parent work and replay at most two not-yet-warmed parent blocks. libevent's
 * timeval timeout is set to the exact remaining deadline for every request.
 */
static constexpr uint32_t DRIVECHAIN_LOCKED_MAX_REPLAY_STEPS{drivechain::LOCKED_MAX_REPLAY_STEPS};

struct DrivechainParentBudgetState {
    uint32_t depth{0};
    std::chrono::steady_clock::time_point deadline;
    uint32_t replay_steps_remaining{0};
    bool replay_snapshot_authenticated{false};
    bool replay_snapshot_is_explicit_target{false};
    uint32_t replay_snapshot_height{0};
    uint256 replay_snapshot_hash;
    uint64_t replay_snapshot_epoch{0};
};

thread_local DrivechainParentBudgetState g_drivechain_parent_budget;
thread_local std::optional<std::chrono::steady_clock::time_point> g_drivechain_anchor_warm_deadline;
thread_local const util::SignalInterrupt* g_drivechain_anchor_warm_interrupt{nullptr};
thread_local uint32_t g_drivechain_untrusted_parent_admission_depth{0};
std::atomic<int64_t> g_drivechain_parent_rpc_unavailable_until{0};
std::mutex g_mainchain_rpc_cookie_mutex;
std::string g_mainchain_rpc_cached_cookie;

class MainchainRPCAuthFailure : public std::runtime_error
{
public:
    explicit MainchainRPCAuthFailure(const std::string& message)
        : std::runtime_error(message) {}
};

bool DrivechainParentBudgetActive();

bool DrivechainUntrustedParentAdmissionActive()
{
    return g_drivechain_untrusted_parent_admission_depth != 0;
}

int64_t ParentSteadyClockTicks()
{
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

void MarkDrivechainParentRpcUnavailable()
{
    const int64_t retry_at = ParentSteadyClockTicks() +
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::seconds{drivechain::PARENT_RPC_BACKOFF_SECONDS}).count();
    g_drivechain_parent_rpc_unavailable_until.store(retry_at, std::memory_order_relaxed);
}

void MarkDrivechainParentRpcAvailable()
{
    g_drivechain_parent_rpc_unavailable_until.store(0, std::memory_order_relaxed);
}

void CheckDrivechainParentRpcCircuit()
{
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::PARENT_CIRCUIT,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return DrivechainParentBudgetActive();
            case 2: return ParentSteadyClockTicks() < g_drivechain_parent_rpc_unavailable_until.load(std::memory_order_relaxed);
            case 3: throw CConnectionFailed("drivechain parent RPC is in fail-fast backoff after an availability failure");
            default: throw std::logic_error("invalid parent circuit action");
            }
        });
}

bool DrivechainParentBudgetActive()
{
    return g_drivechain_parent_budget.depth != 0;
}

void CheckDrivechainParentDeadline()
{
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::PARENT_DEADLINE,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return g_drivechain_anchor_warm_deadline.has_value();
            case 2: return g_drivechain_anchor_warm_interrupt != nullptr;
            case 3: return bool(*g_drivechain_anchor_warm_interrupt);
            case 4: throw CConnectionFailed("drivechain anchor snapshot authentication interrupted");
            case 5: return std::chrono::steady_clock::now() >= *g_drivechain_anchor_warm_deadline;
            case 6: throw CConnectionFailed("drivechain anchor snapshot authentication deadline exhausted");
            case 7: return DrivechainParentBudgetActive();
            case 8: return std::chrono::steady_clock::now() >= g_drivechain_parent_budget.deadline;
            case 9: throw CConnectionFailed("drivechain parent validation work budget exhausted");
            default: throw std::logic_error("invalid parent deadline action");
            }
        });
}

std::string GetMainchainRPCCredentials()
{
    namespace hs = drivechain::haskell;
    bool private_file{false};
    std::string configured_password, credentials;
    if (hs::ParentReplayStore(hs::ReplayStoreFlow::CREDENTIAL_SOURCE, [&](uint32_t action) -> uint32_t {
        switch (action) {
        case 1: private_file = gArgs.IsArgSet("-mainchainrpccredentialfile"); return private_file;
        case 2: return gArgs.IsArgSet("-mainchainrpccookiefile");
        case 3: case 7: return gArgs.IsArgSet("-mainchainrpcuser");
        case 4: case 8: return gArgs.IsArgSet("-mainchainrpcpassword");
        case 5: throw std::runtime_error("select exactly one parent RPC authentication mechanism");
        case 6: return Params().GetConsensus().drivechain_slot.has_value();
        case 9: throw std::runtime_error("native parent RPC requires a rotating cookie or an explicit private credential file, not inline credentials");
        case 10: configured_password = gArgs.GetArg("-mainchainrpcpassword", ""); return 1;
        case 11: return !configured_password.empty();
        case 12: credentials = gArgs.GetArg("-mainchainrpcuser", "") + ":" + configured_password; return 1;
        default: throw std::logic_error("invalid credential source action");
        }
    })) return credentials;

    {
        std::unique_lock<std::mutex> lock(
            g_mainchain_rpc_cookie_mutex, std::defer_lock);
        std::string cached;
        if (hs::ParentReplayStore(hs::ReplayStoreFlow::COOKIE_CACHE, [&](uint32_t action) -> uint32_t {
            switch (action) {
            case 1: return DrivechainParentBudgetActive();
            case 2: return lock.try_lock();
            case 3: throw CConnectionFailed("mainchain RPC cookie cache is busy refreshing");
            case 4: lock.lock(); return 1;
            case 5: return !g_mainchain_rpc_cached_cookie.empty();
            case 6: cached = g_mainchain_rpc_cached_cookie; return 1;
            default: throw std::logic_error("invalid cookie cache action");
            }
        })) return cached;
    }

    // Filesystem access is forbidden once a locked validation budget exists.
    // Startup/periodic warming populates this cache outside cs_main.
    std::string loaded_cookie;
    std::string credential_error;
    hs::ParentReplayStore(hs::ReplayStoreFlow::CREDENTIAL_LOAD, [&](uint32_t action) -> uint32_t {
        switch (action) {
        case 1: return DrivechainParentBudgetActive();
        case 2: throw CConnectionFailed("mainchain RPC cookie credentials are not warmed");
        case 3: return private_file;
        case 4: return IsMainchainRPCHostAllowed(gArgs.GetArg("-mainchainrpchost", DEFAULT_RPCCONNECT), true);
        case 5: return ReadMainchainRpcCredentialFile(
            fs::PathFromString(gArgs.GetArg("-mainchainrpccredentialfile", "")), loaded_cookie, &credential_error);
        case 6: throw std::runtime_error("cannot load private loopback parent RPC credentials: " + credential_error);
        case 7: return GetMainchainAuthCookie(&loaded_cookie);
        case 8: throw std::runtime_error("cannot load the parent's private canonical rotating RPC cookie");
        case 9: {
            std::lock_guard<std::mutex> lock(g_mainchain_rpc_cookie_mutex);
            g_mainchain_rpc_cached_cookie = loaded_cookie;
            return 1;
        }
        default: throw std::logic_error("invalid credential load action");
        }
    });
    return loaded_cookie;
}

void InvalidateMainchainRPCCookie()
{
    std::lock_guard<std::mutex> lock(g_mainchain_rpc_cookie_mutex);
    g_mainchain_rpc_cached_cookie.clear();
}

bool ConsumeDrivechainReplayBudget(const uint32_t steps, std::string* error)
{
    namespace hs = drivechain::haskell;
    return hs::ParentReplayStore(hs::ReplayStoreFlow::REPLAY_BUDGET,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return DrivechainParentBudgetActive();
            case 2: CheckDrivechainParentDeadline(); return 1;
            case 3: return hs::ParentReplayRecord(hs::ReplayRecordKind::HEIGHT, 0, 0,
                steps, g_drivechain_parent_budget.replay_steps_remaining);
            case 4: return error != nullptr;
            case 5: *error = strprintf(
                "parent replay needs %u uncached blocks; locked validation permits at most %u before background warming",
                steps, g_drivechain_parent_budget.replay_steps_remaining); return 0;
            case 6: g_drivechain_parent_budget.replay_steps_remaining = hs::ReplayDistance(g_drivechain_parent_budget.replay_steps_remaining, steps); return 1;
            default: throw std::logic_error("invalid replay budget action");
            }
        });
}

void RecordDrivechainReplaySnapshot(const uint32_t height,
                                    const uint256& hash,
                                    const uint64_t epoch,
                                    const bool explicit_target)
{
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::REPLAY_SNAPSHOT,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return DrivechainParentBudgetActive();
            case 2: return ShouldReplaceDrivechainReplaySnapshot(
            g_drivechain_parent_budget.replay_snapshot_authenticated,
            g_drivechain_parent_budget.replay_snapshot_height,
            g_drivechain_parent_budget.replay_snapshot_is_explicit_target,
            explicit_target, height);
            case 3: g_drivechain_parent_budget.replay_snapshot_authenticated = true; return 1;
            case 4: g_drivechain_parent_budget.replay_snapshot_is_explicit_target = explicit_target; return 1;
            case 5: g_drivechain_parent_budget.replay_snapshot_height = height; return 1;
            case 6: g_drivechain_parent_budget.replay_snapshot_hash = hash; return 1;
            case 7: g_drivechain_parent_budget.replay_snapshot_epoch = epoch; return 1;
            default: throw std::logic_error("invalid replay snapshot action");
            }
        });
}

} // namespace

bool ShouldReplaceDrivechainReplaySnapshot(
    const bool current_authenticated,
    const uint32_t current_height,
    const bool current_explicit_target,
    const bool next_explicit_target,
    const uint32_t next_height)
{
    return drivechain::haskell::ParentReplayRecord(drivechain::haskell::ReplayRecordKind::SNAPSHOT,
        uint32_t{current_authenticated} | (uint32_t{current_explicit_target} << 1) |
        (uint32_t{next_explicit_target} << 2), 0, current_height, next_height);
}

DrivechainParentValidationBudget::DrivechainParentValidationBudget(const bool enable)
    : m_enabled(enable)
{
    const unsigned flags = (unsigned{m_enabled} << 1) | unsigned{m_enabled && g_drivechain_parent_budget.depth == 0};
    for (const auto step : drivechain::PARENT_BUDGET_ENTER_ACTIONS[flags]) {
        switch (step) {
        case 0: return;
        case 1: ++g_drivechain_parent_budget.depth; break;
        case 2: g_drivechain_parent_budget.deadline = std::chrono::steady_clock::now() + std::chrono::seconds{drivechain::LOCKED_PARENT_DEADLINE_SECONDS}; break;
        case 3: g_drivechain_parent_budget.replay_steps_remaining = DRIVECHAIN_LOCKED_MAX_REPLAY_STEPS; break;
        case 4: g_drivechain_parent_budget.replay_snapshot_authenticated = false; break;
        case 5: g_drivechain_parent_budget.replay_snapshot_is_explicit_target = false; break;
        case 6: g_drivechain_parent_budget.replay_snapshot_height = 0; break;
        case 7: g_drivechain_parent_budget.replay_snapshot_hash.SetNull(); break;
        case 8: g_drivechain_parent_budget.replay_snapshot_epoch = 0; break;
        default: std::terminate();
        }
    }
}

DrivechainParentValidationBudget::~DrivechainParentValidationBudget()
{
    const unsigned flags = (unsigned{m_enabled} << 1) | unsigned{m_enabled && g_drivechain_parent_budget.depth == 1};
    for (const auto step : drivechain::PARENT_BUDGET_EXIT_ACTIONS[flags]) {
        switch (step) {
        case 0: return;
        case 1: assert(g_drivechain_parent_budget.depth > 0); break;
        case 2: --g_drivechain_parent_budget.depth; break;
        case 3: g_drivechain_parent_budget.replay_steps_remaining = 0; break;
        case 4: g_drivechain_parent_budget.replay_snapshot_authenticated = false; break;
        case 5: g_drivechain_parent_budget.replay_snapshot_is_explicit_target = false; break;
        case 6: g_drivechain_parent_budget.replay_snapshot_hash.SetNull(); break;
        case 7: g_drivechain_parent_budget.replay_snapshot_epoch = 0; break;
        default: std::terminate();
        }
    }
}

DrivechainUntrustedParentAdmission::DrivechainUntrustedParentAdmission(
    const bool enable)
    : m_enabled(enable)
{
    for (const auto step : drivechain::PARENT_ADMISSION_ENTER_ACTIONS[unsigned{m_enabled} << 1]) {
        switch (step) {
        case 0: return;
        case 1: ++g_drivechain_untrusted_parent_admission_depth; break;
        default: std::terminate();
        }
    }
}

DrivechainUntrustedParentAdmission::~DrivechainUntrustedParentAdmission()
{
    for (const auto step : drivechain::PARENT_ADMISSION_EXIT_ACTIONS[unsigned{m_enabled} << 1]) {
        switch (step) {
        case 0: return;
        case 1: assert(g_drivechain_untrusted_parent_admission_depth > 0); break;
        case 2: --g_drivechain_untrusted_parent_admission_depth; break;
        default: std::terminate();
        }
    }
}

/** Reply structure for request_done to fill in */
struct HTTPReply
{
    int status{0};
    int error{-1};
    bool body_too_large{false};
    std::string body;
};

const char *http_errorstring(int code)
{
    switch(code) {
#if LIBEVENT_VERSION_NUMBER >= 0x02010300
    case EVREQ_HTTP_TIMEOUT:
        return "timeout reached";
    case EVREQ_HTTP_EOF:
        return "EOF reached";
    case EVREQ_HTTP_INVALID_HEADER:
        return "error while reading header, or invalid header";
    case EVREQ_HTTP_BUFFER_ERROR:
        return "error encountered while reading or writing";
    case EVREQ_HTTP_REQUEST_CANCEL:
        return "request was canceled";
    case EVREQ_HTTP_DATA_TOO_LONG:
        return "response body is larger than allowed";
#endif
    default:
        return "unknown";
    }
}

static void http_request_done(struct evhttp_request *req, void *ctx)
{
    HTTPReply *reply = static_cast<HTTPReply*>(ctx);

    if (req == nullptr) {
        /* If req is nullptr, it means an error occurred while connecting: the
         * error code will have been passed to http_error_cb.
         */
        reply->status = 0;
        return;
    }

    reply->status = evhttp_request_get_response_code(req);

    struct evbuffer *buf = evhttp_request_get_input_buffer(req);
    if (buf)
    {
        size_t size = evbuffer_get_length(buf);
        const char *data = (const char*)evbuffer_pullup(buf, size);
        if (size > drivechain::MAX_MAINCHAIN_RPC_RESPONSE_SIZE) {
            reply->body_too_large = true;
        } else if (data) {
            reply->body = std::string(data, size);
        }
        evbuffer_drain(buf, size);
    }
}

#if LIBEVENT_VERSION_NUMBER >= 0x02010300
static void http_error_cb(enum evhttp_request_error err, void *ctx)
{
    HTTPReply *reply = static_cast<HTTPReply*>(ctx);
    reply->error = err;
}
#endif

static UniValue CallMainChainRPCUncircuit(const std::string& strMethod, const UniValue& params, const std::string& endpoint)
{
    CheckDrivechainParentDeadline();
    std::string host = gArgs.GetArg("-mainchainrpchost", DEFAULT_RPCCONNECT);
    int port = gArgs.GetIntArg("-mainchainrpcport", BaseParams().MainchainRPCPort());

    // Obtain event base
    raii_event_base base = obtain_event_base();

    // Synchronously look up hostname
    raii_evhttp_connection evcon = obtain_evhttp_connection_base(base.get(), host, port);
    evhttp_connection_set_max_headers_size(
        evcon.get(), drivechain::MAX_MAINCHAIN_RPC_HEADER_SIZE);
    evhttp_connection_set_max_body_size(
        evcon.get(), drivechain::MAX_MAINCHAIN_RPC_RESPONSE_SIZE);
    namespace hs = drivechain::haskell;
    std::chrono::microseconds remaining{0};
    int64_t configured{0};
    const auto positive = [](int64_t value) {
        return hs::ParentReplayRecord(hs::ReplayRecordKind::SIGNED_POSITIVE, 0, value, 0, 0);
    };
    hs::ParentReplayStore(hs::ReplayStoreFlow::RPC_TIMEOUT, [&](uint32_t action) -> uint32_t {
        switch (action) {
        case 1: return DrivechainParentBudgetActive();
        case 2: remaining = std::chrono::duration_cast<std::chrono::microseconds>(
            g_drivechain_parent_budget.deadline - std::chrono::steady_clock::now()); return 1;
        case 3: case 8: return positive(remaining.count());
        case 4: throw CConnectionFailed("drivechain parent validation work budget exhausted");
        case 5: {
            const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(remaining);
            timeval timeout{};
            timeout.tv_sec = seconds.count();
            timeout.tv_usec = (remaining - seconds).count();
            evhttp_connection_set_timeout_tv(evcon.get(), &timeout);
            return 1;
        }
        case 6: return g_drivechain_anchor_warm_deadline.has_value();
        case 7: remaining = std::chrono::duration_cast<std::chrono::microseconds>(
            *g_drivechain_anchor_warm_deadline - std::chrono::steady_clock::now()); return 1;
        case 9: throw CConnectionFailed("drivechain anchor snapshot authentication deadline exhausted");
        case 10: configured = gArgs.GetIntArg("-mainchainrpctimeout", DEFAULT_HTTP_CLIENT_TIMEOUT); return 1;
        case 11: return positive(configured);
        case 12: return hs::ParentReplayRecord(hs::ReplayRecordKind::LESS, 0, 0, configured,
            std::chrono::ceil<std::chrono::seconds>(remaining).count());
        case 13: remaining = std::chrono::seconds{configured}; return 1;
        case 14: evhttp_connection_set_timeout(evcon.get(),
            gArgs.GetIntArg("-mainchainrpctimeout", DEFAULT_HTTP_CLIENT_TIMEOUT)); return 1;
        default: throw std::logic_error("invalid parent RPC timeout action");
        }
    });

    HTTPReply response;
    raii_evhttp_request req = obtain_evhttp_request(http_request_done, (void*)&response);
    if (req == nullptr)
        throw std::runtime_error("create http request failed");
#if LIBEVENT_VERSION_NUMBER >= 0x02010300
    evhttp_request_set_error_cb(req.get(), http_error_cb);
#endif

    // Cookie files are loaded only by startup/background calls. Locked
    // validation consumes the already-warmed credential cache in memory.
    const std::string strRPCUserColonPass = GetMainchainRPCCredentials();

    struct evkeyvalq* output_headers = evhttp_request_get_output_headers(req.get());
    assert(output_headers);
    evhttp_add_header(output_headers, "Host", host.c_str());
    evhttp_add_header(output_headers, "Connection", "close");
    evhttp_add_header(output_headers, "Authorization", (std::string("Basic ") + EncodeBase64(strRPCUserColonPass)).c_str());

    // Attach request data
    std::string strRequest = JSONRPCRequestObj(strMethod, params, 1).write() + "\n";
    struct evbuffer* output_buffer = evhttp_request_get_output_buffer(req.get());
    assert(output_buffer);
    evbuffer_add(output_buffer, strRequest.data(), strRequest.size());

    int r = evhttp_make_request(evcon.get(), req.get(), EVHTTP_REQ_POST, endpoint.c_str());
    req.release(); // ownership moved to evcon in above call
    if (r != 0) {
        throw CConnectionFailed("send http request failed");
    }

    event_base_dispatch(base.get());
    CheckDrivechainParentDeadline();

    if (response.status == 0)
        throw CConnectionFailed(strprintf("couldn't connect to server: %s (code %d)\n(make sure server is running and you are connecting to the correct RPC port)", http_errorstring(response.error), response.error));
    else if (response.status == HTTP_UNAUTHORIZED)
        throw MainchainRPCAuthFailure("incorrect mainchainrpcuser or mainchainrpcpassword (authorization failed)");
    else if (response.status >= 400 && response.status != HTTP_BAD_REQUEST && response.status != HTTP_NOT_FOUND && response.status != HTTP_INTERNAL_SERVER_ERROR)
        throw std::runtime_error(strprintf("server returned HTTP error %d", response.status));
    else if (response.body_too_large)
        throw std::runtime_error(strprintf("mainchain RPC response exceeds %u bytes", drivechain::MAX_MAINCHAIN_RPC_RESPONSE_SIZE));
    else if (response.body.empty())
        throw std::runtime_error("no response from server");

    // Parse reply
    UniValue valReply(UniValue::VSTR);
    if (!valReply.read(response.body))
        throw std::runtime_error("couldn't parse reply from server");
    CheckDrivechainParentDeadline();
    const UniValue& reply = valReply.get_obj();
    if (reply.empty())
        throw std::runtime_error("expected reply to have result, error and id properties");

    return reply;
}

static UniValue CallMainChainRPCAt(const std::string& strMethod, const UniValue& params, const std::string& endpoint)
{
    CheckDrivechainParentRpcCircuit();
    const auto call = [&] {
        UniValue reply = CallMainChainRPCUncircuit(strMethod, params, endpoint);
        MarkDrivechainParentRpcAvailable();
        return reply;
    };
    try {
        return call();
    } catch (const MainchainRPCAuthFailure&) {
        namespace hs = drivechain::haskell;
        if (hs::ParentReplayStore(hs::ReplayStoreFlow::AUTH_RETRY, [&](uint32_t action) -> uint32_t {
            switch (action) {
            case 1: return gArgs.GetArg("-mainchainrpcpassword", "").empty();
            case 2: InvalidateMainchainRPCCookie(); return 1;
            case 3: return DrivechainParentBudgetActive();
            default: throw std::logic_error("invalid parent authentication retry action");
            }
        })) {
            // Cookie rotation is repaired only outside consensus locks. The
            // retried call reloads the cookie before opening a new request.
            try {
                return call();
            } catch (...) {
                MarkDrivechainParentRpcUnavailable();
                throw;
            }
        }
        MarkDrivechainParentRpcUnavailable();
        throw;
    } catch (...) {
        MarkDrivechainParentRpcUnavailable();
        throw;
    }
}

UniValue CallMainChainRPC(const std::string& method, const UniValue& params)
{
    return CallMainChainRPCAt(method, params, "/");
}

UniValue CallMainChainWalletRPC(const std::string& wallet, const std::string& method, const UniValue& params)
{
    if (wallet.empty()) throw std::runtime_error("Set -drivechainbmmwallet to an explicitly funded parent wallet");
    char* encoded = evhttp_uriencode(wallet.data(), wallet.size(), false);
    if (!encoded) throw std::runtime_error("Cannot encode parent wallet endpoint");
    const std::string endpoint = "/wallet/" + std::string(encoded);
    free(encoded);
    return CallMainChainRPCAt(method, params, endpoint);
}

UniValue CheckDrivechainRPCReply(const std::string& method, const UniValue& reply, bool require_result)
{
    namespace hs = drivechain::haskell;
    const UniValue* result{nullptr};
    hs::ParentReplayStore(hs::ReplayStoreFlow::RPC_REPLY, [&](uint32_t action) -> uint32_t {
        switch (action) {
        case 1: return reply["error"].isNull();
        case 2: throw std::runtime_error(strprintf("%s returned error: %s", method, reply["error"].write()));
        case 3: result = &reply["result"]; return require_result && result->isNull();
        case 4: throw std::runtime_error(strprintf("%s returned no result", method));
        default: throw std::logic_error("invalid checked RPC reply action");
        }
    });
    return *result;
}

UniValue CallMainChainRPCChecked(const std::string& method, const UniValue& params)
{
    return CheckDrivechainRPCReply(method, CallMainChainRPC(method, params));
}

bool IsDrivechainSidechainSlot(const int slot)
{
    const std::optional<uint8_t>& configured = Params().GetConsensus().drivechain_slot;
    return drivechain::haskell::ParentReplayRecord(drivechain::haskell::ReplayRecordKind::CONFIGURED_SLOT,
        configured.has_value(),slot,configured.value_or(0));
}

namespace {

template <typename Status>
Status SetError(std::string* error, const Status status, const std::string& message)
{
    if (error) *error = message;
    return status;
}

bool SetError(std::string* error, const std::string& message)
{
    return SetError(error, false, message);
}

template <typename Action>
bool CatchParentError(std::string* error, Action&& action)
{
    try { return action(); }
    catch (const std::exception& exception) { return SetError(error, exception.what()); }
}

bool CheckConfiguredDrivechainSlot(const int sidechain_slot, std::string* error)
{
    const std::optional<uint8_t>& configured = Params().GetConsensus().drivechain_slot;
    namespace hs = drivechain::haskell;
    return hs::ParentReplayStore(hs::ReplayStoreFlow::CONFIGURED_SLOT, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return configured.has_value();
        case 2: return SetError(error, "this network has no configured BIP300/301 sidechain slot");
        case 3: return IsDrivechainSidechainSlot(sidechain_slot);
        case 4: return SetError(error, strprintf("drivechain sidechain slot must match configured slot %u, got %d",
                                               static_cast<unsigned int>(*configured), sidechain_slot));
        default: throw std::logic_error("invalid configured slot action");
        }
    });
}

template <typename Reset, typename Action>
bool ParentRequest(int slot, std::string* error, Reset&& reset, Action&& action)
{
    namespace hs = drivechain::haskell;
    return hs::ParentReplayStore(hs::ReplayStoreFlow::PARENT_REQUEST, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: reset(); return 1;
        case 2: return error != nullptr;
        case 3: error->clear(); return 1;
        case 4: return CheckConfiguredDrivechainSlot(slot, error);
        case 5: return CatchParentError(error, action);
        default: throw std::logic_error("invalid parent request action");
        }
    });
}

} // namespace

bool ParseDrivechainCanonicalHash(const UniValue& value, uint256& hash)
{
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::CANONICAL_HASH,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return value.isStr();
            case 2: return value.get_str().size() == drivechain::PARENT_HASH_HEX_LENGTH;
            case 3: return IsHex(value.get_str());
            case 4: hash = uint256S(value.get_str()); return 1;
            case 5: return value.get_str() == hash.GetHex();
            default: throw std::logic_error("invalid canonical hash action");
            }
        });
}

namespace {
// Callers own exception translation; warmup preserves the native RPC diagnostic.
bool ParseParentHeightInteger(const UniValue& value, uint32_t& height, std::string* error)
{
    namespace hs = drivechain::haskell;
    int64_t parsed{0};
    return hs::ParentReplayStore(hs::ReplayStoreFlow::HEIGHT_PARSE, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: parsed = value.getInt<int64_t>(); return 1;
        case 2: return hs::ParentReplayRecord(hs::ReplayRecordKind::AMOUNT, 0, parsed, 0, std::numeric_limits<uint32_t>::max());
        case 3: return SetError(error, "parent tip height is outside the supported uint32 range");
        case 4: height = static_cast<uint32_t>(parsed); return 1;
        default: throw std::logic_error("invalid parent height parse action");
        }
    });
}
} // namespace

bool ParseDrivechainParentHeight(const UniValue& value, uint32_t& height, std::string* error)
{
    namespace hs = drivechain::haskell;
    if (!hs::ParentReplayStore(hs::ReplayStoreFlow::HEIGHT_PREFLIGHT, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return value.isNum();
        case 2: return SetError(error, "parent getblockcount returned a non-numeric height");
        default: throw std::logic_error("invalid parent height preflight action");
        }
    })) return false;
    try {
        return ParseParentHeightInteger(value, height, error);
    } catch (const std::exception&) {
        return SetError(error, "parent getblockcount returned a noncanonical height");
    }
}

bool CheckDrivechainParentProofOfWork(const uint256& hash, const uint32_t n_bits, std::string* error)
{
    bool negative{false};
    bool overflow{false};
    arith_uint256 target;
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::PARENT_POW,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: target.SetCompact(n_bits, &negative, &overflow); return 1;
            case 2: return negative;
            case 3: return target == 0;
            case 4: return overflow;
            case 5: return target > UintToArith256(Params().GetConsensus().parentChainPowLimit);
            case 6: return SetError(error, "parent header has an invalid proof-of-work target");
            case 7: return UintToArith256(hash) > target;
            case 8: return SetError(error, "parent header does not satisfy its proof-of-work target");
            default: throw std::logic_error("invalid parent proof-of-work action");
            }
        });
}

arith_uint256 GetDrivechainParentBlockProof(const uint32_t n_bits)
{
    bool negative{false};
    bool overflow{false};
    arith_uint256 target, proof;
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::BLOCK_PROOF,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: target.SetCompact(n_bits, &negative, &overflow); return 1;
            case 2: return negative;
            case 3: return overflow;
            case 4: return target == 0;
            case 5: proof = 0; return 1;
            case 6: proof = (~target / (target + 1)) + 1; return 1;
            default: throw std::logic_error("invalid parent block-proof action");
            }
        });
    return proof;
}

bool CheckDrivechainParentChainwork(const uint256& parent_work, const uint256& successor_work,
    uint32_t successor_bits, std::string* error)
{
    arith_uint256 proof;
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::CHAINWORK,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: proof = GetDrivechainParentBlockProof(successor_bits); return 1;
            case 2: return proof == 0;
            case 3: return UintToArith256(successor_work) != UintToArith256(parent_work) + proof;
            case 5: return SetError(error, "parent RPC chainwork does not match the authenticated successor header");
            default: throw std::logic_error("invalid parent chainwork action");
            }
        });
}

namespace {

struct RawParentErrors {
    const char* nonhex;
    const char* trailing;
    const char* decode;
};

template <typename Object, typename Decode, typename HashError>
bool DecodeRawParent(const UniValue& raw, const uint256& hash, Object& object, std::string* error,
    const std::function<void()>& deadline, const RawParentErrors& errors, Decode&& decode, HashError&& hash_error)
{
    namespace hs = drivechain::haskell;
    if (!hs::ParentReplayStore(hs::ReplayStoreFlow::RAW_PREFLIGHT, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return raw.isStr();
        case 2: return IsHex(raw.get_str());
        case 3: return SetError(error, errors.nonhex);
        case 4: deadline(); return 1;
        default: throw std::logic_error("invalid raw-header preflight action");
        }
    })) return false;
    try {
        std::optional<DataStream> stream;
        if (!hs::ParentReplayStore(hs::ReplayStoreFlow::RAW_DECODE, [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: stream.emplace(ParseHex(raw.get_str())); return 1;
            case 2: decode(*stream); return 1;
            case 3: return !stream->empty();
            case 4: return SetError(error, errors.trailing);
            default: throw std::logic_error("invalid raw-header decode action");
            }
        })) return false;
    } catch (const std::exception& e) {
        return SetError(error, strprintf("%s%s", errors.decode, e.what()));
    }
    return hs::ParentReplayStore(hs::ReplayStoreFlow::RAW_POSTFLIGHT, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: deadline(); return 1;
        case 2: return object.GetHash() == hash;
        case 3: return CheckDrivechainParentProofOfWork(hash, object.nBits, error);
        case 4: return SetError(error, hash_error());
        default: throw std::logic_error("invalid raw-header postflight action");
        }
    });
}

} // namespace

bool DecodeDrivechainRawParentHeader(const UniValue& raw, const uint256& hash,
    Bitcoin::CBlockHeader& header, std::string* error)
{
    return DecodeRawParent(raw, hash, header, error, CheckDrivechainParentDeadline,
        {"getblockheader returned non-hex raw header data", "raw parent header has trailing bytes", "cannot decode raw parent header: "},
        [&](DataStream& stream) { stream >> header; },
        [&] { return strprintf("raw parent header hashes to %s, expected %s", header.GetHash().GetHex(), hash.GetHex()); });
}

bool DecodeDrivechainRawParentBlock(const UniValue& raw, const uint256& hash,
    Bitcoin::CBlock& block, std::string* error, const std::function<void()>& deadline)
{
    return DecodeRawParent(raw, hash, block, error, deadline,
        {"getblock returned non-hex raw block data", "raw parent block has trailing bytes", "cannot decode raw parent block: "},
        [&](DataStream& stream) { stream >> TX_WITH_WITNESS(block); },
        [] { return "raw parent block header does not match its requested hash"; });
}

namespace {

bool CheckParentChainworkStep(const VerifiedMainchainHeader& parent,
                              const VerifiedMainchainHeader& successor,
                              std::string* error)
{
    return CheckDrivechainParentChainwork(parent.chainwork, successor.chainwork, successor.header.nBits, error);
}

bool ReadRawBitcoinHeader(const uint256& hash, Bitcoin::CBlockHeader& header, std::string* error)
{
    std::optional<UniValue> params, raw;
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::RAW_REQUEST,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: params.emplace(UniValue::VARR); return 1;
            case 2: params->push_back(hash.GetHex()); return 1;
            case 3: params->push_back(false); return 1;
            case 4: raw.emplace(CallMainChainRPCChecked("getblockheader", *params)); return 1;
            case 5: return DecodeDrivechainRawParentHeader(*raw, hash, header, error);
            default: throw std::logic_error("invalid raw-header request action");
            }
        });
}

} // namespace

bool ComputeDrivechainParentMedianTimePast(const uint256& start_hash, const uint32_t start_height,
    uint64_t& median_time_past,
    const std::function<bool(const uint256&, Bitcoin::CBlockHeader&)>& read_header,
    const std::function<void()>& check_deadline)
{
    namespace hs = drivechain::haskell;
    std::vector<uint32_t> times;
    uint256 expected_hash;
    uint32_t index{0};
    uint32_t median{0};
    std::optional<Bitcoin::CBlockHeader> header;
    return hs::ParentReplayStore(hs::ReplayStoreFlow::MEDIAN_TIME, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: times.reserve(11); return 1;
        case 2: expected_hash = start_hash; return 1;
        case 3: index = 0; return 1;
        case 4: return hs::ParentReplayRecord(hs::ReplayRecordKind::MTP_SAMPLE, 0, 0, index, start_height);
        case 5: check_deadline(); return 1;
        case 6: header.emplace(); return 1;
        case 7: return read_header(expected_hash, *header);
        case 8: times.push_back(header->nTime); return 1;
        case 9: expected_hash = header->hashPrevBlock; return 1;
        case 10: header.reset(); return 1;
        case 11: ++index; return 1;
        case 12: median = hs::BmmMedian(times); return 1;
        case 13: check_deadline(); return 1;
        case 14: median_time_past = median; return 1;
        default: throw std::logic_error("invalid parent median-time action");
        }
    });
}

bool ParseDrivechainParentHeaderMetadata(const UniValue& metadata, const uint256& expected_hash,
    int min_confirmations, uint256& parsed_chainwork, int64_t& parsed_height,
    int64_t& parsed_confirmations, std::string* error)
{
    uint256 returned_hash;
    const UniValue *height{nullptr}, *confirmations{nullptr}, *chainwork{nullptr};
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::HEADER_METADATA,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return metadata.isObject();
            case 2: return SetError(error, "getblockheader result is not an object");
            case 3: return ParseDrivechainCanonicalHash(metadata.get_obj()["hash"], returned_hash);
            case 4: return returned_hash == expected_hash;
            case 5: return SetError(error, "getblockheader hash does not match requested parent block");
            case 6: height = &metadata.get_obj()["height"]; return 1;
            case 7: confirmations = &metadata.get_obj()["confirmations"]; return 1;
            case 8: chainwork = &metadata.get_obj()["chainwork"]; return 1;
            case 9: return height->isNum();
            case 10: return confirmations->isNum();
            case 11: return ParseDrivechainCanonicalHash(*chainwork, parsed_chainwork);
            case 12: return SetError(error, "getblockheader is missing canonical height, confirmations, or chainwork");
            case 13: parsed_height = height->getInt<int64_t>(); return 1;
            case 14: parsed_confirmations = confirmations->getInt<int64_t>(); return 1;
            case 15: return parsed_height < 0;
            case 16: return parsed_height > std::numeric_limits<uint32_t>::max();
            case 17: return parsed_confirmations < min_confirmations;
            case 18: return SetError(error, strprintf("parent block has %d confirmations; %d required", parsed_confirmations, min_confirmations));
            default: throw std::logic_error("invalid parent header metadata action");
            }
        });
}

bool CheckDrivechainParentPredecessor(const UniValue& previous, int64_t parsed_height,
    const Bitcoin::CBlockHeader& raw_header, const uint256& parsed_chainwork, std::string* error,
    const std::function<UniValue(const std::string&, const UniValue&)>& request)
{
    uint256 previous_hash, returned_previous_hash, previous_chainwork;
    std::optional<UniValue> params, metadata;
    const UniValue* height{nullptr};
    arith_uint256 proof;
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::HEADER_PREDECESSOR,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return parsed_height == 0;
            case 2: return previous.isNull();
            case 3: return raw_header.hashPrevBlock.IsNull();
            case 4: return UintToArith256(parsed_chainwork) == GetDrivechainParentBlockProof(raw_header.nBits);
            case 5: return SetError(error, "parent genesis unexpectedly has a predecessor");
            case 6: return SetError(error, "parent genesis chainwork does not match its authenticated header");
            case 7: return ParseDrivechainCanonicalHash(previous, previous_hash);
            case 8: return previous_hash == raw_header.hashPrevBlock;
            case 9: return SetError(error, "verbose and raw parent headers disagree about previous block");
            case 10: params.emplace(UniValue::VARR); return 1;
            case 11: params->push_back(previous_hash.GetHex()); return 1;
            case 12: params->push_back(true); return 1;
            case 13: metadata.emplace(request("getblockheader", *params)); return 1;
            case 14: return metadata->isObject();
            case 15: return SetError(error, "previous getblockheader result is not an object");
            case 16: height = &metadata->get_obj()["height"]; return 1;
            case 17: return ParseDrivechainCanonicalHash(metadata->get_obj()["hash"], returned_previous_hash);
            case 18: return returned_previous_hash == previous_hash;
            case 19: return ParseDrivechainCanonicalHash(metadata->get_obj()["chainwork"], previous_chainwork);
            case 20: return height->isNum();
            case 21: return drivechain::haskell::ParentReplayRecord(drivechain::haskell::ReplayRecordKind::SIGNED_PREDECESSOR,
                0, height->getInt<int64_t>(), static_cast<uint64_t>(parsed_height), 0);
            case 22: return SetError(error, "previous parent metadata is not canonical or contiguous");
            case 23: proof = GetDrivechainParentBlockProof(raw_header.nBits); return 1;
            case 24: return proof == 0;
            case 25: return UintToArith256(parsed_chainwork) == UintToArith256(previous_chainwork) + proof;
            case 26: return SetError(error, "parent chainwork does not match its authenticated header and predecessor");
            default: throw std::logic_error("invalid parent predecessor action");
            }
        });
}

bool CheckDrivechainParentBlockTransactions(const Bitcoin::CBlock& block,
    std::string* error, const std::function<void()>& deadline)
{
    namespace hs = drivechain::haskell;
    size_t index{0};
    bool mutated{false};
    uint256 merkle;
    std::optional<std::vector<uint256>> hashes;
    return hs::ParentReplayStore(hs::ReplayStoreFlow::BLOCK_TRANSACTIONS, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return block.vtx.empty();
        case 2: return bool(block.vtx[0]);
        case 3: return block.vtx[0]->IsCoinBase();
        case 4: return SetError(error, "raw parent block has no coinbase transaction");
        case 5: index = 1; return 1;
        case 6: case 18: return index < block.vtx.size();
        case 7: case 19: return hs::ParentReplayRecord(hs::ReplayRecordKind::PERIODIC_DEADLINE, 0, 0, index);
        case 8: case 20: case 28: deadline(); return 1;
        case 9: return bool(block.vtx[index]);
        case 10: return block.vtx[index]->IsCoinBase();
        case 11: return SetError(error, "raw parent block has a null transaction or multiple coinbases");
        case 12: case 22: ++index; return 1;
        case 14: mutated = false; return 1;
        case 15: hashes.emplace(); return 1;
        case 16: hashes->reserve(block.vtx.size()); return 1;
        case 17: index = 0; return 1;
        case 21: hashes->push_back(block.vtx[index]->GetHash()); return 1;
        case 24: merkle = ComputeMerkleRoot(std::move(*hashes), &mutated); return 1;
        case 25: return merkle != block.hashMerkleRoot;
        case 26: return mutated;
        case 27: return SetError(error, "raw parent block has an invalid or mutated transaction Merkle tree");
        default: throw std::logic_error("invalid parent block transaction action");
        }
    });
}

DrivechainParentRecoveryDeadline::DrivechainParentRecoveryDeadline(
    std::optional<std::chrono::steady_clock::time_point>& current,
    const std::function<std::chrono::steady_clock::time_point()>& now)
    : m_current(current), m_previous(current)
{
    std::chrono::steady_clock::time_point limit;
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::RECOVERY_DEADLINE,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: limit = now() + std::chrono::seconds{drivechain::PARENT_RECOVERY_SECONDS}; return 1;
            case 2: return m_previous.has_value();
            case 3: return limit < *m_previous;
            case 4: m_current = limit; return 1;
            default: throw std::logic_error("invalid parent recovery deadline action");
            }
        });
}

DrivechainParentRecoveryDeadline::~DrivechainParentRecoveryDeadline() noexcept
{
    m_current = m_previous;
}

bool CheckDrivechainParentBlockSignet(const Bitcoin::CBlock& block, std::string* error,
    const std::function<const std::vector<uint8_t>&()>& read_challenge,
    const std::function<const uint256&()>& genesis, const std::function<void()>& deadline)
{
    const std::vector<uint8_t>* bytes{nullptr};
    std::optional<CScript> challenge;
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::BLOCK_SIGNET,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: bytes = &read_challenge(); return 1;
            case 2: return bytes->empty();
            case 3: challenge.emplace(bytes->begin(), bytes->end()); return 1;
            case 4: return CheckBitcoinSignetBlockSolution(block, *challenge, genesis(), error);
            case 5: deadline(); return 1;
            default: throw std::logic_error("invalid parent block signet action");
            }
        });
}

bool VerifyDrivechainParentBlock(const uint256& hash, int min_confirmations,
    Bitcoin::CBlock& block, VerifiedMainchainHeader& verified, std::string* error,
    const std::function<bool(const uint256&, int, VerifiedMainchainHeader&, std::string*)>& read_header,
    const std::function<bool(const uint256&, Bitcoin::CBlock&, std::string*)>& read_block)
{
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::VERIFIED_BLOCK,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return read_header(hash, min_confirmations, verified, error);
            case 2: return read_block(hash, block, error);
            case 3: return block.GetBlockHeader().GetHash() == verified.header.GetHash();
            case 4: return SetError(error, "raw parent block header does not match authenticated header");
            default: throw std::logic_error("invalid verified parent block action");
            }
        });
}

bool VerifyDrivechainParentHeader(const uint256& expected_hash, int min_confirmations,
    VerifiedMainchainHeader& verified, std::string* error, const DrivechainParentHeaderSource& source)
{
    std::optional<UniValue> genesis_params, genesis, params, metadata, active_params, active_result;
    uint256 rpc_genesis, parsed_chainwork, active_hash;
    int64_t parsed_height{0}, parsed_confirmations{0};
    std::optional<Bitcoin::CBlockHeader> raw_header;
    const UniValue* previous{nullptr};
    uint64_t median_time_past{0};
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::VERIFIED_HEADER,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return min_confirmations >= 1;
            case 2: return SetError(error, "minimum parent confirmations must be positive");
            case 3: genesis_params.emplace(UniValue::VARR); return 1;
            case 4: genesis_params->push_back(0); return 1;
            case 5: genesis.emplace(source.request("getblockhash", *genesis_params)); return 1;
            case 6: return ParseDrivechainCanonicalHash(*genesis, rpc_genesis);
            case 7: return rpc_genesis == source.genesis();
            case 8: return SetError(error, strprintf("mainchain RPC genesis does not match pinned parent genesis %s", source.genesis().GetHex()));
            case 9: params.emplace(UniValue::VARR); return 1;
            case 10: params->push_back(expected_hash.GetHex()); return 1;
            case 11: params->push_back(true); return 1;
            case 12: metadata.emplace(source.request("getblockheader", *params)); return 1;
            case 13: return ParseDrivechainParentHeaderMetadata(*metadata, expected_hash, min_confirmations,
                parsed_chainwork, parsed_height, parsed_confirmations, error);
            case 14: active_params.emplace(UniValue::VARR); return 1;
            case 15: active_params->push_back(parsed_height); return 1;
            case 16: active_result.emplace(source.request("getblockhash", *active_params)); return 1;
            case 17: return ParseDrivechainCanonicalHash(*active_result, active_hash);
            case 18: return active_hash == expected_hash;
            case 19: return SetError(error, "parent block is not the active-chain block at its declared height");
            case 20: raw_header.emplace(); return 1;
            case 21: return source.raw_header(expected_hash, *raw_header, error);
            case 22: previous = &metadata->get_obj()["previousblockhash"]; return 1;
            case 23: return CheckDrivechainParentPredecessor(*previous, parsed_height, *raw_header,
                parsed_chainwork, error, source.request);
            case 24: median_time_past = 0; return 1;
            case 25: return source.median_time(expected_hash, parsed_height, median_time_past, error);
            case 26: source.deadline(); return 1;
            case 27: verified.header = *raw_header; return 1;
            case 28: verified.chainwork = parsed_chainwork; return 1;
            case 29: verified.height = static_cast<uint32_t>(parsed_height); return 1;
            case 30: verified.confirmations = parsed_confirmations; return 1;
            case 31: verified.median_time_past = median_time_past; return 1;
            case 32: return verified.chainwork.IsNull();
            case 33: return SetError(error, "parent chainwork cannot be zero");
            default: throw std::logic_error("invalid verified parent header action");
            }
        });
}

namespace {

bool ComputeVerifiedMedianTimePast(const uint256& start_hash, const uint32_t start_height,
    uint64_t& median_time_past, std::string* error)
{
    return ComputeDrivechainParentMedianTimePast(start_hash, start_height, median_time_past,
        [&](const uint256& hash, Bitcoin::CBlockHeader& header) { return ReadRawBitcoinHeader(hash, header, error); },
        [] { CheckDrivechainParentDeadline(); });
}

bool GetVerifiedActiveMainchainHeader(const uint256& expected_hash, const int min_confirmations,
                                      VerifiedMainchainHeader& verified, std::string* error)
{
    return VerifyDrivechainParentHeader(expected_hash, min_confirmations, verified, error,
        {[]() -> const uint256& { return Params().ParentGenesisBlockHash(); },
         CallMainChainRPCChecked, ReadRawBitcoinHeader, ComputeVerifiedMedianTimePast, CheckDrivechainParentDeadline});
}

bool ReadAuthenticatedRawMainchainBlock(const uint256& hash,
                                        Bitcoin::CBlock& block,
                                        std::string* error)
{
    // Bound recovery RPCs as well as polling; preserve any tighter outer budget.
    DrivechainParentRecoveryDeadline recovery_deadline(g_drivechain_anchor_warm_deadline, std::chrono::steady_clock::now);
    const UniValue raw = drivechain::FetchParentBlockBody(
        hash.GetHex(), !DrivechainParentBudgetActive(), CallMainChainRPC,
        CheckDrivechainParentDeadline,
        [] { std::this_thread::sleep_for(std::chrono::milliseconds{250}); });
    return drivechain::haskell::ParentReplayAll<3>({
        [&] { return DecodeDrivechainRawParentBlock(raw, hash, block, error, CheckDrivechainParentDeadline); },
        [&] { return CheckDrivechainParentBlockTransactions(block, error, CheckDrivechainParentDeadline); },
        [&] { return CheckDrivechainParentBlockSignet(block, error,
            []() -> const std::vector<uint8_t>& { return Params().GetConsensus().parent_signet_challenge; },
            []() -> const uint256& { return Params().ParentGenesisBlockHash(); }, CheckDrivechainParentDeadline); },
    });
}

bool ReadVerifiedMainchainBlock(const uint256& hash, const int min_confirmations,
                                Bitcoin::CBlock& block, VerifiedMainchainHeader& verified,
                                std::string* error)
{
    return VerifyDrivechainParentBlock(hash, min_confirmations, block, verified, error,
        GetVerifiedActiveMainchainHeader, ReadAuthenticatedRawMainchainBlock);
}

bool IsDrivechainTreasuryScript(const CScript& script, const int sidechain_slot)
{
    return drivechain::IsTreasuryScript(script, drivechain::FROZEN_PARENT_RULES.treasury_opcode, sidechain_slot);
}

} // namespace

bool IsExactDrivechainOpReturnAddress(const Bitcoin::CTxOut& output, const std::vector<unsigned char>& address)
{
    CScript::const_iterator pc;
    opcodetype opcode{};
    std::optional<std::vector<unsigned char>> pushed;
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::EXACT_ADDRESS,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: pc = output.scriptPubKey.begin(); return 1;
            case 2: pushed.emplace(); return 1;
            case 3: case 5: return output.scriptPubKey.GetOp(pc, opcode, *pushed);
            case 4: return opcode == OP_RETURN;
            case 6: return opcode <= OP_PUSHDATA4;
            case 7: return *pushed == address;
            case 8: return pc == output.scriptPubKey.end();
            default: throw std::logic_error("invalid exact address action");
            }
        });
}

namespace {

bool ExtractSingleOpReturnPush(const CScript& script, std::vector<unsigned char>& payload)
{
    CScript::const_iterator pc;
    opcodetype opcode{};
    std::optional<std::vector<unsigned char>> pushed;
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::SINGLE_PUSH,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: payload.clear(); return 1;
            case 2: pc = script.begin(); return 1;
            case 3: pushed.emplace(); return 1;
            case 4: case 6: return script.GetOp(pc, opcode, *pushed);
            case 5: return opcode == OP_RETURN;
            case 7: return opcode <= OP_PUSHDATA4;
            case 8: return pc == script.end();
            case 9: payload = std::move(*pushed); return 1;
            default: throw std::logic_error("invalid single-push extraction action");
            }
        });
}

enum class DrivechainParentMessageType {
    NONE = 0,
    PROPOSAL = 1,
    ACK = 2,
    WITHDRAWAL_PROPOSAL = 3,
    WITHDRAWAL_ACK = 4,
    BMM_ACCEPT = 5,
};

enum class DrivechainM4Encoding {
    NONE,
    REPEAT_PREVIOUS,
    EXPLICIT,
    LEADING_BY_50,
};

struct DrivechainParentMessage {
    DrivechainParentMessageType type{DrivechainParentMessageType::NONE};
    uint8_t slot{0};
    uint256 proposal_hash;
    DrivechainM4Encoding m4_encoding{DrivechainM4Encoding::NONE};
    std::vector<uint16_t> m4_votes;
};

struct DrivechainM8BmmRequest {
    uint8_t slot{0};
    uint256 sidechain_block_hash;
    uint256 previous_mainchain_block_hash;
};

/**
 * Parse exactly the M8 encoding recognized by the pinned enforcer's
 * M8BmmRequest::parse: the first transaction output is
 *
 *   OP_RETURN || PUSHBYTES_68 || 00bf00 || slot || h* || previous_parent
 *
 * Unlike coinbase-message parsing, the enforcer does not accept alternate push
 * opcodes for M8. A malformed lookalike is therefore an ordinary transaction,
 * not an invalid M8 request.
 */
bool ExtractDrivechainM8BmmRequest(const Bitcoin::CTransaction& transaction,
                                   DrivechainM8BmmRequest& request)
{
    static constexpr std::array<uint8_t, 3> M8_TAG{{0x00, 0xbf, 0x00}};
    static constexpr uint8_t M8_PAYLOAD_SIZE{
        M8_TAG.size() + 1 + uint256::size() + uint256::size()};
    static constexpr size_t M8_SCRIPT_SIZE{1 + 1 + M8_PAYLOAD_SIZE};

    namespace hs = drivechain::haskell;
    const CScript* script{nullptr};
    return hs::ParentReplayStore(hs::ReplayStoreFlow::M8_PARSE, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return !transaction.vout.empty();
        case 2: script = &transaction.vout[0].scriptPubKey; return 1;
        case 3: return script->size() == M8_SCRIPT_SIZE;
        case 4: return (*script)[0] == OP_RETURN;
        case 5: return (*script)[1] == M8_PAYLOAD_SIZE;
        case 6: return std::equal(M8_TAG.begin(), M8_TAG.end(), script->begin() + 2);
        case 7: request.slot = (*script)[2 + M8_TAG.size()]; return 1;
        case 8: {
            // Skip push/tag/slot, then reverse the display-order commitment.
            const auto bytes = hs::BmmCommitmentBytes(0, std::span{*script}.subspan(1, 37));
            request.sidechain_block_hash = uint256{bytes.data(), bytes.size()};
            return 1;
        }
        case 9: {
            const auto bytes = hs::BmmCommitmentBytes(1, std::span{*script}.last(32));
            request.previous_mainchain_block_hash = uint256{bytes.data(), bytes.size()};
            return 1;
        }
        default: throw std::logic_error("invalid M8 parsing action");
        }
    });
}

DrivechainParentMessage ParseDrivechainParentMessage(const CScript& script)
{
    namespace hs = drivechain::haskell;
    std::vector<unsigned char> payload;
    if (!ExtractSingleOpReturnPush(script, payload)) return {};
    auto parsed = hs::ParseParentMessage(payload);
    const auto type = static_cast<DrivechainParentMessageType>(parsed.kind);
    if (type == DrivechainParentMessageType::NONE) return {};
    if (type == DrivechainParentMessageType::WITHDRAWAL_ACK) {
        return {type, 0, {}, static_cast<DrivechainM4Encoding>(parsed.encoding), std::move(parsed.votes)};
    }
    if (type == DrivechainParentMessageType::PROPOSAL) {
        return {type, payload[4], Hash(Span{payload}.subspan(5)), DrivechainM4Encoding::NONE, {}};
    }
    // M7 carries a display-order commitment; M2/M3 carry consensus-order hashes.
    const auto bytes = hs::BmmCommitmentBytes(2, payload);
    return {type, payload[4], uint256{bytes.data(), bytes.size()}, DrivechainM4Encoding::NONE, {}};
}

bool ReadActiveMainchainHash(uint32_t height, uint256& hash, std::string* error);
bool ReadActiveMainchainHeight(uint32_t& height, std::string* error);

struct DrivechainParentReplayCache {
    bool initialized{false};
    uint64_t epoch{0};
    uint8_t slot{0};
    uint256 proposal_hash;
    uint256 checkpoint_active_proposal_hash;
    uint256 checkpoint_hash;
    uint16_t unused_proposal_max_age{0};
    uint16_t unused_activation_threshold{0};
    uint16_t used_proposal_max_age{0};
    uint16_t used_activation_threshold{0};
    uint16_t withdrawal_bundle_max_age{0};
    uint16_t withdrawal_bundle_inclusion_threshold{0};
    uint32_t replay_version{0};
    uint32_t height{0};
    uint256 hash;
    DrivechainParentReplayState state;
};

std::mutex g_drivechain_parent_replay_mutex;
DrivechainParentReplayCache g_drivechain_parent_replay_cache;
std::unique_ptr<DrivechainParentReplayStore> g_drivechain_parent_replay_store;
bool g_drivechain_parent_replay_store_rebuild_required{false};
uint64_t g_drivechain_parent_replay_epoch_counter{0};
std::atomic<uint64_t> g_drivechain_parent_replay_published_epoch{0};
using drivechain::DRIVECHAIN_PARENT_REPLAY_DB_CACHE_BYTES;

bool ReplayCacheMatchesConfiguredIdentity(
    const DrivechainParentReplayCache& cache,
    const Consensus::Params& consensus);

bool RequireConfiguredElementsProposalActive(
    const DrivechainParentReplayCache& cache,
    uint32_t target_height,
    std::string* error);

bool EnsurePinnedDrivechainParentStateThrough(uint32_t target_height,
                                              const uint256& target_hash,
                                              bool require_elements_active,
                                              std::string* error);

} // namespace

bool ExtractCanonicalDrivechainBmmCommitmentInBlock(
    const Bitcoin::CBlock& block,
    const int sidechain_slot,
    uint256& committed_sidechain_hash,
    uint32_t* output_index,
    std::string* error)
{
    committed_sidechain_hash.SetNull();
    if (output_index) *output_index = 0;
    namespace hs = drivechain::haskell;
    if (!hs::ParentReplayRecord(hs::ReplayRecordKind::AMOUNT, 0, sidechain_slot, 0, std::numeric_limits<uint8_t>::max())) {
        return SetError(error, "BIP301 M7 sidechain slot is outside the uint8 range");
    }
    if (!hs::ParentReplayAll<3>({
        [&] { return !block.vtx.empty(); }, [&] { return bool(block.vtx[0]); },
        [&] { return block.vtx[0]->IsCoinBase(); },
    })) {
        return SetError(error, "raw BMM block has no coinbase transaction");
    }

    // The pinned enforcer parses exactly OP_RETURN followed by one push, but
    // intentionally uses Script::instructions() rather than its minimal-push
    // variant. Match every push opcode it recognizes, not only PUSHBYTES_37.
    uint32_t matched_index{0};
    uint256 parsed_hash;
    const auto matches = hs::CountMatches(block.vtx[0]->vout.size(), [&](uint64_t i) {
        const CScript& script = block.vtx[0]->vout[i].scriptPubKey;
        std::vector<unsigned char> payload;
        if (!hs::ParentReplayAll<4>({
            [&] { return ExtractSingleOpReturnPush(script, payload); },
            [&] { return payload.size() == 5 + uint256::size(); },
            [&] { return hs::ParseParentMessage(payload).kind == static_cast<uint32_t>(DrivechainParentMessageType::BMM_ACCEPT); },
            [&] { return payload[4] == static_cast<uint8_t>(sidechain_slot); },
        })) return false;
        matched_index = static_cast<uint32_t>(i);
        const auto bytes = hs::BmmCommitmentBytes(0, payload);
        parsed_hash = uint256{bytes.data(), bytes.size()};
        return true;
    });

    return hs::ParentReplayStore(hs::ReplayStoreFlow::CANONICAL_MATCH, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return matches != 0;
        case 2: return matches == 1;
        case 3: committed_sidechain_hash = parsed_hash; return 1;
        case 4: return SetError(error, strprintf("BMM successor has no enforcer-recognized M7 for sidechain slot %d", sidechain_slot));
        case 5: return SetError(error, strprintf("BMM successor has %u enforcer-recognized M7 outputs for sidechain slot %d", matches, sidechain_slot));
        case 6: return output_index != nullptr;
        case 7: *output_index = matched_index; return 1;
        default: throw std::logic_error("invalid canonical match publication action");
        }
    });
}

bool MatchDrivechainBmmCommitmentInBlock(const Bitcoin::CBlock& block,
                                         const int sidechain_slot,
                                         const uint256& expected_critical_hash,
                                         uint32_t* output_index,
                                         std::string* error)
{
    uint256 committed_hash;
    // ConsensusHex carries the opaque BmmCommitment in display order. The
    // parser normalizes those bytes into the node's internal uint256 order
    // before this comparison.
    return drivechain::haskell::ParentReplayAll<2>({
        [&] { return ExtractCanonicalDrivechainBmmCommitmentInBlock(block, sidechain_slot, committed_hash, output_index, error); },
        [&] { return committed_hash == expected_critical_hash || SetError(error, strprintf(
            "BMM successor commits to critical hash %s, expected %s",
            committed_hash.GetHex(), expected_critical_hash.GetHex())); },
    });
}

bool MatchDrivechainDepositInBlock(
    const Bitcoin::CBlock& block,
    const int sidechain_slot,
    const COutPoint& outpoint,
    const CAmount value,
    const std::vector<unsigned char>& address,
    const std::map<Bitcoin::COutPoint, Bitcoin::CTxOut>& previous_outputs,
    std::string* error)
{
    // This pure matcher deliberately has no global Params dependency.  Its
    // authenticated consensus entry point checks the network's configured
    // slot before calling it.
    namespace hs = drivechain::haskell;
    const Bitcoin::CTransaction* deposit{nullptr};
    CAmount old_treasury_value{0};
    const int result = hs::DepositMatch(sidechain_slot, value, MAX_MONEY, !address.empty(), [&](uint32_t stage) -> int64_t {
        switch (stage) {
        case 1: {
            uint64_t selected{0};
            const auto match = hs::FindUniqueMatch(block.vtx.size(), [&](uint64_t i) {
                return block.vtx[i]->GetHash() == outpoint.hash;
            },selected);
            if (match == hs::MatchResult::UNIQUE) deposit = block.vtx[selected].get();
            return static_cast<int64_t>(match);
        }
        case 2: return outpoint.n < deposit->vout.size();
        case 3: return deposit->IsCoinBase();
        case 4: return IsDrivechainTreasuryScript(deposit->vout[outpoint.n].scriptPubKey, sidechain_slot);
        case 5: return hs::ParentReplayAll<2>({
            [&] { return outpoint.n + 1 < deposit->vout.size(); },
            [&] { return IsExactDrivechainOpReturnAddress(deposit->vout[outpoint.n + 1], address); }});
        case 6: return hs::CountMatches(deposit->vout.size(), [&](uint64_t i) {
            return IsDrivechainTreasuryScript(deposit->vout[i].scriptPubKey, sidechain_slot);
        });
        case 7: return hs::CountMatches(deposit->vin.size(), [&](uint64_t i) {
            const auto previous = previous_outputs.find(deposit->vin[i].prevout);
            return hs::ParentReplayAll<3>({
                [&] { return previous != previous_outputs.end(); },
                [&] { return IsDrivechainTreasuryScript(previous->second.scriptPubKey, sidechain_slot); },
                [&] { old_treasury_value = previous->second.nValue; return true; }});
        });
        case 8: return hs::TreasuryDelta(old_treasury_value, deposit->vout[outpoint.n].nValue, value, MAX_MONEY);
        default: throw std::logic_error("invalid raw deposit match stage");
        }
    });
    static constexpr const char* errors[]{
        "invalid slot, amount, or address for drivechain deposit",
        "raw parent block contains duplicate deposit txids",
        "deposit outpoint is absent from raw parent block",
        "BIP300 M5 deposit cannot be a coinbase transaction",
        "deposit outpoint is not the slot-specific BIP300 treasury output",
        "BIP300 deposit does not contain the exact following address commitment",
        "BIP300 deposit must create exactly one treasury output for the slot",
        "BIP300 deposit spends multiple treasury outputs for one slot",
        "BIP300 treasury value delta does not equal the claimed deposit amount"};
    return result == 0 || SetError(error, errors[result-1]);
}

namespace {

template <typename Project>
decltype(auto) SlotField(DrivechainParentReplayState& state, uint8_t slot, uint8_t configured_slot, Project project)
{
    return slot == configured_slot ? project(state) : project(state.other_slots[slot]);
}

uint256& SlotActiveProposal(DrivechainParentReplayState& state,
                            const uint8_t slot,
                            const uint8_t configured_slot)
{
    return SlotField(state, slot, configured_slot, [](auto& value) -> auto& { return value.active_proposal_hash; });
}

std::map<uint256, DrivechainPendingProposal>& SlotPendingProposals(
    DrivechainParentReplayState& state,
    const uint8_t slot,
    const uint8_t configured_slot)
{
    return SlotField(state, slot, configured_slot, [](auto& value) -> auto& { return value.pending_proposals; });
}

std::vector<DrivechainPendingWithdrawal>& SlotPendingWithdrawals(
    DrivechainParentReplayState& state,
    const uint8_t slot,
    const uint8_t configured_slot)
{
    return SlotField(state, slot, configured_slot, [](auto& value) -> auto& { return value.pending_withdrawals; });
}

std::optional<Bitcoin::COutPoint>& SlotCtip(DrivechainParentReplayState& state,
                                            const uint8_t slot,
                                            const uint8_t configured_slot)
{
    return SlotField(state, slot, configured_slot, [](auto& value) -> auto& { return value.ctip; });
}

CAmount& SlotCtipValue(DrivechainParentReplayState& state,
                       const uint8_t slot,
                       const uint8_t configured_slot)
{
    return SlotField(state, slot, configured_slot, [](auto& value) -> auto& { return value.ctip_value; });
}

std::vector<uint8_t> ActiveDrivechainSlots(const DrivechainParentReplayState& state,
                                           const uint8_t configured_slot)
{
    std::vector<unsigned char> entries{configured_slot, static_cast<unsigned char>(!state.active_proposal_hash.IsNull())};
    for (const auto& [slot,entry] : state.other_slots)
        entries.insert(entries.end(), {slot, static_cast<unsigned char>(!entry.active_proposal_hash.IsNull())});
    return drivechain::haskell::ActiveSlots(entries);
}

bool ExtractDrivechainTreasurySlot(const CScript& script, uint8_t& slot,
                                 drivechain::TreasuryOpcode treasury_opcode)
{
    return drivechain::ExtractTreasurySlot(script, treasury_opcode, slot);
}

auto PackM4Votes(const std::vector<DrivechainPendingWithdrawal>& pending)
{
    std::pair<std::vector<unsigned char>,std::vector<uint16_t>> packed;
    auto& [hashes,votes] = packed;
    for (const auto& entry : pending) {
        hashes.insert(hashes.end(), entry.m6id.begin(), entry.m6id.end());
        votes.push_back(entry.votes);
    }
    return packed;
}

} // namespace

bool ComputeDrivechainM6Id(const Bitcoin::CTransaction& transaction,
                           const CAmount previous_treasury_value,
                           uint256& m6id,
                           uint8_t* sidechain_slot,
                           std::string* error,
                           drivechain::TreasuryOpcode treasury_opcode)
{
    uint8_t parsed_slot{0};
    const int result = drivechain::haskell::M6Id(transaction.vout.size(),transaction.vin.size(),
        previous_treasury_value,MAX_MONEY,sidechain_slot != nullptr,[&](uint32_t step,uint64_t value) -> int64_t {
        switch (step) {
        case 1: m6id.SetNull(); return 1;
        case 2: return ExtractDrivechainTreasurySlot(transaction.vout[0].scriptPubKey, parsed_slot, treasury_opcode);
        case 3: return transaction.vout[0].nValue;
        case 4: return transaction.vout[value].nValue;
        case 5: {
            std::vector<unsigned char> fee_bytes(8);
            WriteBE64(fee_bytes.data(),value);
            Bitcoin::CMutableTransaction blinded(transaction);
            blinded.vin.clear();
            blinded.vout[0] = Bitcoin::CTxOut(0, CScript() << OP_RETURN << fee_bytes);
            m6id = blinded.GetHash();
            return 1;
        }
        case 6: *sidechain_slot = parsed_slot; return 1;
        default: throw std::logic_error("invalid M6 id action");
        }
    });
    static constexpr const char* errors[]{
        "BIP300 M6 has no replacement treasury output",
        "BIP300 M6 replacement treasury output is not vout 0",
        "BIP300 M6 must contain exactly one treasury input",
        "BIP300 M6 treasury amount is outside the money range",
        "BIP300 M6 payout total is outside the money range",
        "BIP300 M6 spends more than the previous treasury value"};
    return result == 0 || SetError(error,errors[result-1]);
}

bool ApplyDrivechainParentBlockState(
    const Bitcoin::CBlock& block,
    const uint32_t height,
    const int sidechain_slot,
    const uint256& required_active_proposal,
    const uint16_t unused_slot_proposal_max_age,
    const uint16_t unused_slot_activation_threshold,
    const uint16_t used_slot_proposal_max_age,
    const uint16_t used_slot_activation_threshold,
    const uint16_t withdrawal_bundle_max_age,
    const uint16_t withdrawal_bundle_inclusion_threshold,
    DrivechainParentReplayState& state,
    std::vector<DrivechainMintableDeposit>* deposits,
    std::string* error,
    std::vector<DrivechainSuccessfulWithdrawal>* successful_withdrawals,
    std::vector<DrivechainWithdrawalProposalIdentity>* withdrawal_proposals,
    drivechain::TreasuryOpcode treasury_opcode,
    DrivechainM6ReplayRule m6_rule)
{
    CheckDrivechainParentDeadline();
    if (deposits) deposits->clear();
    if (successful_withdrawals) successful_withdrawals->clear();
    if (withdrawal_proposals) withdrawal_proposals->clear();
    std::vector<DrivechainSuccessfulWithdrawal> derived_withdrawals;
    std::vector<DrivechainWithdrawalProposalIdentity> derived_proposals;
    const uint8_t configured_slot = static_cast<uint8_t>(sidechain_slot);
    using drivechain::haskell::ParentReplayRecord;
    using drivechain::haskell::ReplayRecordKind;
    using drivechain::haskell::ParentReplayStore;
    using drivechain::haskell::ReplayStoreFlow;
    using drivechain::haskell::ParentReplayEach;
    std::vector<DrivechainParentMessage> messages;
    std::map<uint8_t, uint256> accepted_bmm_requests;
    return ParentReplayStore(ReplayStoreFlow::BLOCK_REPLAY, [&](uint32_t stage) -> uint32_t {
        switch (stage) {
        case 1: {
            const auto valid_window = [](uint16_t max_age, uint16_t threshold) {
                return ParentReplayRecord(ReplayRecordKind::ACTIVATION_WINDOW, 0, 0, threshold, max_age);
            };
            auto other_slot = state.other_slots.begin();
            auto prior_m4 = state.previous_m4_actions.begin();
            return ParentReplayStore(ReplayStoreFlow::BLOCK_ADMISSION, [&](uint32_t step) -> uint32_t {
                switch (step) {
                case 1: return drivechain::SupportedParentReplayRules(treasury_opcode, m6_rule);
                case 2: return SetError(error, "unsupported parent-state replay rules");
                case 3: return ParentReplayRecord(ReplayRecordKind::AMOUNT, 0, sidechain_slot, 0, std::numeric_limits<uint8_t>::max());
                case 4: return !required_active_proposal.IsNull();
                case 5: return valid_window(unused_slot_proposal_max_age, unused_slot_activation_threshold);
                case 6: return valid_window(used_slot_proposal_max_age, used_slot_activation_threshold);
                case 7: return valid_window(withdrawal_bundle_max_age, withdrawal_bundle_inclusion_threshold);
                case 8: return SetError(error, "invalid slot or proposal identity for parent-state replay");
                case 9: return ParentReplayStore(ReplayStoreFlow::PROPOSAL_CONSISTENCY, [&](uint32_t action) -> uint32_t {
                    switch (action) {
                    case 1: return state.required_proposal_activated;
                    case 2: return state.active_proposal_hash != required_active_proposal;
                    case 3: return state.active_proposal_hash.IsNull();
                    case 4: return state.ctip.has_value();
                    default: throw std::logic_error("invalid proposal consistency action");
                    }
                });
                case 10: return SetError(error, "parent-state replay began with an inconsistent active proposal");
                case 11: return ParentReplayStore(ReplayStoreFlow::COINBASE_PREFLIGHT, [&](uint32_t action) -> uint32_t {
                    switch (action) {
                    case 1: return block.vtx.empty();
                    case 2: return bool(block.vtx[0]);
                    case 3: return block.vtx[0]->IsCoinBase();
                    default: throw std::logic_error("invalid coinbase preflight action");
                    }
                });
                case 12: return SetError(error, "parent-state replay block has no coinbase transaction");
                case 13: return ParentReplayRecord(ReplayRecordKind::CTIP_BALANCE, state.ctip.has_value(), state.ctip_value, 0, MAX_MONEY);
                case 14: return SetError(error, "parent-state replay began with malformed CTIP state");
                case 15: return other_slot != state.other_slots.end();
                case 16: return ParentReplayStore(ReplayStoreFlow::OTHER_SLOT_PREFLIGHT, [&](uint32_t action) -> uint32_t {
                    const auto& [slot, slot_state] = *other_slot;
                    switch (action) {
                    case 1: return slot == configured_slot;
                    case 2: return slot_state.active_proposal_hash.IsNull();
                    case 3: return slot_state.ctip.has_value();
                    case 4: return ParentReplayRecord(ReplayRecordKind::CTIP_BALANCE, slot_state.ctip.has_value(), slot_state.ctip_value, 0, MAX_MONEY);
                    default: throw std::logic_error("invalid other-slot preflight action");
                    }
                });
                case 17: return SetError(error, "parent-state replay began with malformed global slot state");
                case 18: ++other_slot; return 1;
                case 19: return prior_m4 != state.previous_m4_actions.end();
                case 20: return ParentReplayStore(ReplayStoreFlow::PRIOR_M4_PREFLIGHT, [&](uint32_t check) -> uint32_t {
                    const auto& action = prior_m4->second;
                    switch (check) {
                    case 1: return action.type == DrivechainM4ActionType::UPVOTE;
                    case 2: case 3: return action.type == DrivechainM4ActionType::ALARM;
                    case 4: return action.m6id.IsNull();
                    default: throw std::logic_error("invalid prior-M4 preflight action");
                    }
                });
                case 21: return SetError(error, strprintf("parent-state replay has malformed prior M4 action for slot %u", prior_m4->first));
                case 22: ++prior_m4; return 1;
                default: throw std::logic_error("invalid parent block admission action");
                }
            });
        }
        case 2: {
            // Parse the complete ordered coinbase message stream first. The enforcer
            // rejects duplicate M1/M2/M4/M7 messages globally, even for slots this
            // Elements chain does not use directly.
            std::set<std::pair<uint8_t, uint256>> m1_messages;
            std::set<uint8_t> m2_slots;
            std::set<uint8_t> m7_slots;
            std::optional<DrivechainParentMessage> message;
            const int result = drivechain::haskell::CoinbaseMessages(block.vtx[0]->vout.size(), [&](uint32_t action,uint64_t index) -> int64_t {
                switch (action) {
                case 1: CheckDrivechainParentDeadline(); return 1;
                case 2:
                    message.emplace(ParseDrivechainParentMessage(block.vtx[0]->vout[index].scriptPubKey));
                    return static_cast<uint32_t>(message->type);
                case 3: return m1_messages.emplace(message->slot, message->proposal_hash).second;
                case 4: return m2_slots.insert(message->slot).second;
                case 5: return m7_slots.insert(message->slot).second;
                case 6: accepted_bmm_requests.emplace(message->slot, message->proposal_hash); return 1;
                case 7: messages.push_back(std::move(*message)); return 1;
                case 8: message.reset(); return 1;
                default: throw std::logic_error("invalid coinbase collection action");
                }
            });
            static constexpr const char* errors[]{
                "parent block contains a duplicate M1 proposal message",
                "parent block contains multiple M2 ACK messages for one slot",
                "parent block contains multiple M4 withdrawal ACK messages",
                "parent block contains multiple M7 commitments for one slot"};
            return result == 0 || SetError(error,errors[result-1]);
        }
        case 3: {
            // The enforcer validates every recognized M8 after constructing the M7 map
            // for this exact block. Do this before mutating replay state so a rejected
            // block cannot leave a partially applied state in callers or tests.
            DrivechainM8BmmRequest request;
            const int result = drivechain::haskell::M8Acceptance(block.vtx.size(), [&](uint32_t action,uint64_t index) -> int64_t {
                switch (action) {
                case 1: CheckDrivechainParentDeadline(); return 1;
                case 2:
                    request = {};
                    return ExtractDrivechainM8BmmRequest(*block.vtx[index], request);
                case 3: {
                    const auto accepted = accepted_bmm_requests.find(request.slot);
                    return accepted != accepted_bmm_requests.end() && accepted->second == request.sidechain_block_hash;
                }
                case 4: return request.previous_mainchain_block_hash == block.hashPrevBlock;
                default: throw std::logic_error("invalid M8 acceptance action");
                }
            });
            if (result == 1) return SetError(error, strprintf("BIP301 M8 for slot %u was not accepted by this block's M7", request.slot));
            if (result == 2) return SetError(error, strprintf("BIP301 M8 for slot %u references an expired parent block", request.slot));
            return true;
        }
        case 4: {
            std::map<uint8_t, DrivechainM4Action> effective_m4_actions;
            if (!ParentReplayEach(messages, [&](const DrivechainParentMessage& message) {
                return ParentReplayStore(ReplayStoreFlow::MESSAGE_DISPATCH, [&](uint32_t dispatch) -> uint32_t {
                    if (dispatch == 1) { CheckDrivechainParentDeadline(); return 1; }
                    if (dispatch == 2) return static_cast<uint32_t>(message.type);
                    if (dispatch == 3) {
                        SlotPendingProposals(state, message.slot, configured_slot).try_emplace(
                            message.proposal_hash, DrivechainPendingProposal{height, 0});
                        return true;
                    }

                    if (dispatch == 4) {
                        auto& pending = SlotPendingProposals(state, message.slot, configured_slot);
                        auto proposal = pending.find(message.proposal_hash);
                        uint256* active{nullptr};
                        const int result = drivechain::haskell::M2Proposal(height,
                            unused_slot_proposal_max_age, unused_slot_activation_threshold,
                            used_slot_proposal_max_age, used_slot_activation_threshold,
                            [&](uint32_t action, uint64_t value) -> int64_t {
                            switch (action) {
                            case 1: return proposal == pending.end() ? -2 : static_cast<int64_t>(proposal->second.proposal_height);
                            case 2: return proposal->second.votes;
                            case 3:
                                proposal->second.votes = value;
                                active = &SlotActiveProposal(state, message.slot, configured_slot);
                                return !active->IsNull();
                            case 4: *active = message.proposal_hash; pending.erase(proposal); return 1;
                            case 5: return (message.slot == configured_slot ? 1 : 0) |
                                (state.required_proposal_activated ? 2 : 0) | (*active == required_active_proposal ? 4 : 0);
                            case 6:
                                state.required_proposal_activated = true;
                                state.required_activation_height = height;
                                state.required_activation_block_hash = block.GetHash(); return 1;
                            default: throw std::logic_error("invalid proposal ACK action");
                            }
                        });
                        if (result == 1) return SetError(error, "M2 proposal height is ahead of replay height");
                        if (result == 2) return SetError(error, strprintf("parent slot %d was replaced by proposal %s", sidechain_slot, active->GetHex()));
                        return true;
                    }

                    if (dispatch == 5) {
                        std::vector<DrivechainPendingWithdrawal>* pending{nullptr};
                        const int result = drivechain::haskell::M3Proposal([&](uint32_t action,uint64_t index) -> int64_t {
                            switch (action) {
                            case 1: return !SlotActiveProposal(state, message.slot, configured_slot).IsNull();
                            case 2: pending = &SlotPendingWithdrawals(state, message.slot, configured_slot); return pending->size();
                            case 3: return (*pending)[index].m6id == message.proposal_hash;
                            case 4: derived_proposals.push_back({message.slot, message.proposal_hash}); return 1;
                            case 5: pending->push_back({message.proposal_hash, height, 1}); return 1;
                            default: throw std::logic_error("invalid withdrawal proposal action");
                            }
                        });
                        if (result == 1) return SetError(error, strprintf("M3 proposes a withdrawal for inactive sidechain slot %u", message.slot));
                        if (result == 2) return SetError(error, strprintf("M3 withdrawal bundle %s is already pending for slot %u", message.proposal_hash.GetHex(), message.slot));
                        return true;
                    }

                    std::vector<uint8_t> active_slots;
                    const uint32_t flags = (message.type == DrivechainParentMessageType::WITHDRAWAL_ACK ? 1U : 0U) |
                        (message.m4_encoding == DrivechainM4Encoding::NONE ? 2U : 0U) |
                        (message.m4_encoding == DrivechainM4Encoding::EXPLICIT ? 4U : 0U) |
                        (message.m4_encoding == DrivechainM4Encoding::LEADING_BY_50 ? 8U : 0U);
                    switch (drivechain::haskell::M4Mode(flags,message.m4_votes.size(),[&](uint32_t step) -> int64_t {
                        if (step != 1) throw std::logic_error("invalid M4 mode action");
                        active_slots = ActiveDrivechainSlots(state, configured_slot);
                        return active_slots.size();
                    })) {
                    case 4: return SetError(error, "unhandled BIP300 parent coinbase message");
                    case 5: return SetError(error, "two-byte M4 contains no value requiring two-byte encoding");
                    case 6: return SetError(error, strprintf("M4 vote vector has %u entries for %u active sidechains", message.m4_votes.size(), active_slots.size()));
                    case 1:
                        return ParentReplayEach(std::views::iota(size_t{0}, active_slots.size()), [&](size_t i) {
                            const uint8_t slot = active_slots[i];
                            const uint16_t vote = message.m4_votes[i];
                            std::vector<DrivechainPendingWithdrawal>* pending{nullptr};
                            std::vector<uint16_t> votes;
                            return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::EXPLICIT_VOTE,
                                [&](uint32_t step) -> uint32_t {
                                switch (step) {
                                case 1: return vote == 0xffff;
                                case 2: {
                                    pending = &SlotPendingWithdrawals(state, slot, configured_slot);
                                    std::vector<unsigned char> hashes;
                                    std::tie(hashes,votes) = PackM4Votes(*pending);
                                    return drivechain::haskell::ReplayExplicit(vote,hashes,votes);
                                }
                                case 3:
                                case 4:
                                    for (size_t j = 0; j < pending->size(); ++j) (*pending)[j].votes = votes[j];
                                    effective_m4_actions.emplace(slot, step == 3
                                        ? DrivechainM4Action{DrivechainM4ActionType::UPVOTE,(*pending)[vote].m6id}
                                        : DrivechainM4Action{DrivechainM4ActionType::ALARM,{}});
                                    return 1;
                                case 5: return SetError(error, strprintf("M4 vote index %u is absent for sidechain slot %u", vote, slot));
                                default: throw std::logic_error("invalid explicit M4 action");
                                }
                            });
                        });
                    case 2:
                        return ParentReplayEach(active_slots, [&](const uint8_t slot) {
                            auto& pending = SlotPendingWithdrawals(state, slot, configured_slot);
                            auto [hashes,votes] = PackM4Votes(pending);
                            const auto leader = drivechain::haskell::ReplayLeading(hashes,votes);
                            if (leader < 0) return true;
                            for (size_t i = 0; i < pending.size(); ++i) pending[i].votes = votes[i];
                            effective_m4_actions.emplace(slot, DrivechainM4Action{DrivechainM4ActionType::UPVOTE, pending[leader].m6id});
                            return true;
                        });
                    case 3:
                        // Repeat only the prior block's effective actions, rebuilding the
                        // downvote/alarm set against current pending state.
                        return ParentReplayEach(state.previous_m4_actions, [&](const auto& entry) {
                            const auto& [slot, previous] = entry;
                            std::vector<DrivechainPendingWithdrawal>* pending{nullptr};
                            std::vector<uint16_t> votes;
                            const bool upvote = previous.type == DrivechainM4ActionType::UPVOTE;
                            const int result = drivechain::haskell::M4Repeat(upvote, [&](uint32_t step) -> int64_t {
                                switch (step) {
                                case 1: return !SlotActiveProposal(state, slot, configured_slot).IsNull();
                                case 2: {
                                    pending = &SlotPendingWithdrawals(state, slot, configured_slot);
                                    std::vector<unsigned char> hashes;
                                    std::tie(hashes,votes) = PackM4Votes(*pending);
                                    return drivechain::haskell::ReplayUpvote(hashes,
                                        std::span<const unsigned char,32>{previous.m6id.begin(),32},votes);
                                }
                                case 3:
                                    pending = &SlotPendingWithdrawals(state, slot, configured_slot);
                                    for (const auto& entry : *pending) votes.push_back(entry.votes);
                                    return drivechain::haskell::ReplayAlarm(votes) ? 1 : 2;
                                case 4:
                                    for (size_t i = 0; i < pending->size(); ++i) (*pending)[i].votes = votes[i];
                                    effective_m4_actions.emplace(slot, DrivechainM4Action{
                                        upvote ? DrivechainM4ActionType::UPVOTE : DrivechainM4ActionType::ALARM,
                                        upvote ? previous.m6id : uint256{}}); return 1;
                                default: throw std::logic_error("invalid repeated M4 action");
                                }
                            });
                            if (result == 1) return SetError(error, strprintf("RepeatPrevious references inactive sidechain slot %u", slot));
                            if (result == 2) return SetError(error, strprintf("M4 upvote references missing withdrawal bundle %s", previous.m6id.GetHex()));
                            return true;
                        });
                    default: throw std::logic_error("invalid selected M4 mode");
                    }
                });
            })) return false;
            // No M4 means the next RepeatPrevious repeats an empty effective action.
            state.previous_m4_actions = std::move(effective_m4_actions);
            return 1;
        }
        case 5: {
            const auto expire_proposals = [&](const uint8_t slot,
                                              std::map<uint256, DrivechainPendingProposal>& pending,
                                              const bool used) -> bool {
                const auto expire = [&](uint16_t threshold, uint16_t max_age) {
                    auto proposal = pending.begin();
                    const int result = drivechain::haskell::ExpireProposals(pending.size(),height,threshold,max_age, [&](uint32_t step) -> int64_t {
                        switch (step) {
                        case 1: return proposal->second.proposal_height;
                        case 2: return proposal->second.votes;
                        case 3: proposal = pending.erase(proposal); return 1;
                        case 4: ++proposal; return 1;
                        default: throw std::logic_error("invalid proposal expiry action");
                        }
                    });
                    if (result == 1) return SetError(error, strprintf("parent proposal height is ahead of replay height for slot %u", slot));
                    if (result == 2) return SetError(error, strprintf("parent proposal has more votes than elapsed blocks for slot %u", slot));
                    return true;
                };
                return drivechain::haskell::ParentReplayChoose({[&] { return used; },
                    [&] { return expire(used_slot_activation_threshold, used_slot_proposal_max_age); },
                    [&] { return expire(unused_slot_activation_threshold, unused_slot_proposal_max_age); }});
            };
            return drivechain::haskell::ParentReplayAll<2>({
                [&] { return expire_proposals(configured_slot, state.pending_proposals, !state.active_proposal_hash.IsNull()); },
                [&] { return ParentReplayEach(state.other_slots, [&](auto& entry) {
                    auto& [slot, slot_state] = entry;
                    return expire_proposals(slot, slot_state.pending_proposals, !slot_state.active_proposal_hash.IsNull());
                }); },
            });
        }
        case 6:
            // M6 proposals fail only after their maximum age, following M4 processing.
            return ParentReplayEach(ActiveDrivechainSlots(state, configured_slot), [&](const uint8_t slot) {
                auto& pending = SlotPendingWithdrawals(state, slot, configured_slot);
                auto withdrawal = pending.begin();
                const int result = drivechain::haskell::ExpireWithdrawals(pending.size(),height,withdrawal_bundle_max_age, [&](uint32_t step) -> int64_t {
                    switch (step) {
                    case 1: return withdrawal->proposal_height;
                    case 3: withdrawal = pending.erase(withdrawal); return 1;
                    case 4: ++withdrawal; return 1;
                    default: throw std::logic_error("invalid withdrawal expiry action");
                    }
                });
                return result == 0 || SetError(error, "M3 proposal height is ahead of replay height");
            });
        case 7: {
            const bool required_proposal_active_for_transactions = drivechain::haskell::ParentReplayAll<2>({
                [&] { return state.required_proposal_activated; },
                [&] { return state.active_proposal_hash == required_active_proposal; }});

            struct CtipChange {
                uint8_t slot;
                uint32_t output_index;
                CAmount old_value;
                CAmount new_value;
            };

            bool configured_slot_m6_applied{false};
            return ParentReplayEach(std::views::iota(size_t{1}, block.vtx.size()), [&](size_t transaction_index) {
                CheckDrivechainParentDeadline();
                const Bitcoin::CTransaction& transaction = *block.vtx[transaction_index];
                const std::vector<uint8_t> active_slots =
                    ActiveDrivechainSlots(state, configured_slot);
                std::set<uint8_t> active_set(active_slots.begin(), active_slots.end());
                std::map<Bitcoin::COutPoint, uint8_t> ctip_owner;
                std::set<uint8_t> ctip_spends;
                std::map<uint8_t, uint32_t> new_ctips;
                std::vector<CtipChange> changes;
                size_t decreases{0};
                return ParentReplayStore(ReplayStoreFlow::TRANSACTION_REPLAY, [&](uint32_t transaction_stage) -> uint32_t {
                    switch (transaction_stage) {
                    case 1: {
                        size_t owner_index{0};
                        uint8_t owner_slot{0};
                        std::optional<Bitcoin::COutPoint>* owner_ctip{nullptr};
                        CAmount* owner_value{nullptr};
                        const int result = drivechain::haskell::CtipOwners(active_slots.size(),MAX_MONEY, [&](uint32_t step) -> int64_t {
                            switch (step) {
                            case 1:
                                owner_slot = active_slots[owner_index];
                                owner_ctip = &SlotCtip(state, owner_slot, configured_slot);
                                owner_value = &SlotCtipValue(state, owner_slot, configured_slot);
                                return owner_ctip->has_value();
                            case 2: return *owner_value;
                            case 3: return ctip_owner.emplace(**owner_ctip, owner_slot).second;
                            case 4: ++owner_index; return 1;
                            default: throw std::logic_error("invalid CTIP owner action");
                            }
                        });
                        if (result == 1) return SetError(error, strprintf("malformed CTIP state for slot %u", owner_slot));
                        if (result == 2) return SetError(error, "two drivechain slots share one canonical CTIP");
                        return 1;
                    }
                    case 2: {
                        auto owner = ctip_owner.end();
                        const int result = drivechain::haskell::CtipSpends(transaction.vin.size(), [&](uint32_t step, uint64_t input_index) -> int32_t {
                            switch (step) {
                            case 1: CheckDrivechainParentDeadline(); return 1;
                            case 2: owner = ctip_owner.find(transaction.vin[input_index].prevout); return owner != ctip_owner.end();
                            case 3: return ctip_spends.insert(owner->second).second ? 1 : 2;
                            default: throw std::logic_error("invalid CTIP spend action");
                            }
                        });
                        return result == 0 || SetError(error, strprintf("parent transaction spends slot %u CTIP more than once", owner->second));
                    }
                    case 3: {
                        uint8_t output_slot{0};
                        const int result = drivechain::haskell::CtipOutputs(transaction.vout.size(),MAX_MONEY, [&](uint32_t step, uint64_t output_index) -> int64_t {
                            switch (step) {
                            case 1: CheckDrivechainParentDeadline(); return 1;
                            case 2:
                                output_slot = 0;
                                return ExtractDrivechainTreasurySlot(transaction.vout[output_index].scriptPubKey, output_slot, treasury_opcode);
                            case 3: return active_set.count(output_slot) != 0;
                            case 4: return transaction.vout[output_index].nValue;
                            case 5: return new_ctips.emplace(output_slot, static_cast<uint32_t>(output_index)).second;
                            default: throw std::logic_error("invalid CTIP output action");
                            }
                        });
                        if (result == 1) return SetError(error, strprintf("invalid treasury value for slot %u", output_slot));
                        if (result == 2) return SetError(error, strprintf("parent transaction creates multiple treasury outputs for slot %u", output_slot));
                        return 1;
                    }
                    case 4: {
                        auto replacement = ctip_owner.begin();
                        const int result = drivechain::haskell::CtipReplacements(ctip_owner.size(), [&](uint32_t step) -> int32_t {
                            switch (step) {
                            case 1: return ctip_spends.contains(replacement->second);
                            case 2: return new_ctips.count(replacement->second) != 0;
                            case 3: ++replacement; return 1;
                            default: throw std::logic_error("invalid CTIP replacement action");
                            }
                        });
                        return result == 0 || SetError(error, strprintf("parent transaction spends slot %u CTIP without replacement", replacement->second));
                    }
                    case 5: {
                        auto change_entry = new_ctips.begin();
                        std::optional<Bitcoin::COutPoint>* old_ctip{nullptr};
                        CtipChange next_change{};
                        const int result = drivechain::haskell::CtipChanges(new_ctips.size(), [&](uint32_t step) -> int64_t {
                            switch (step) {
                            case 1:
                                next_change.slot = change_entry->first;
                                next_change.output_index = change_entry->second;
                                old_ctip = &SlotCtip(state, next_change.slot, configured_slot);
                                return old_ctip->has_value();
                            case 2: return ctip_spends.contains(next_change.slot);
                            case 3: return next_change.old_value = SlotCtipValue(state, next_change.slot, configured_slot);
                            case 4: next_change.old_value = 0; return 1;
                            case 5: return next_change.new_value = transaction.vout[next_change.output_index].nValue;
                            case 6: ++decreases; return 1;
                            case 7: changes.push_back(next_change); ++change_entry; return 1;
                            default: throw std::logic_error("invalid CTIP change action");
                            }
                        });
                        if (result == 1) return SetError(error, strprintf("parent transaction creates a parallel treasury output for slot %u", next_change.slot));
                        if (result == 2) return SetError(error, strprintf("slot %u CTIP replacement has zero value delta", next_change.slot));
                        return 1;
                    }
                    case 6: return changes.empty();
                    case 7: return decreases != 0;
                    case 8: {
                        // The enforcer permits one M6 or one-or-more M5 deposits per tx,
                        // never a mixed or multi-withdrawal transition.
                        const CtipChange* change{nullptr};
                        uint256 m6id;
                        uint8_t m6_slot{0};
                        std::vector<DrivechainPendingWithdrawal>* pending{nullptr};
                        std::vector<DrivechainPendingWithdrawal>::iterator approved;
                        const int result = drivechain::haskell::M6Withdrawal(decreases,changes.size(),transaction.vin.size(),
                            withdrawal_bundle_inclusion_threshold,m6_rule == DrivechainM6ReplayRule::SINGLE_CONFIGURED_SLOT_M6,
                            [&](uint32_t step) -> int64_t {
                            switch (step) {
                            case 1: change = &changes.front(); return change->output_index;
                            case 2: return ComputeDrivechainM6Id(transaction, change->old_value, m6id, &m6_slot, error, treasury_opcode);
                            case 3: return m6_slot == change->slot;
                            case 4:
                                pending = &SlotPendingWithdrawals(state, change->slot, configured_slot);
                                approved = std::find_if(pending->begin(), pending->end(), [&](const auto& entry) { return entry.m6id == m6id; });
                                return approved != pending->end();
                            case 5: return approved->votes;
                            case 6: return change->slot == configured_slot;
                            case 7: return configured_slot_m6_applied;
                            case 8: configured_slot_m6_applied = true; return 1;
                            case 9: derived_withdrawals.push_back(DrivechainSuccessfulWithdrawal{change->slot, m6id, height, block.GetHash()}); return 1;
                            case 10: pending->erase(approved); return 1;
                            case 11: SlotCtip(state, change->slot, configured_slot) = Bitcoin::COutPoint(transaction.GetHash(), change->output_index); return 1;
                            case 12: SlotCtipValue(state, change->slot, configured_slot) = change->new_value; return 1;
                            default: throw std::logic_error("invalid M6 withdrawal action");
                            }
                        });
                        switch (result) {
                        case 0: return 1;
                        case 1: return SetError(error, "parent transaction ambiguously mixes M5 and M6 transitions");
                        case 2: return SetError(error, "BIP300 M6 must have one input and treasury vout 0");
                        case 3: return 0;
                        case 4: return SetError(error, "BIP300 M6 slot changed while deriving its blinded id");
                        case 5: return SetError(error, strprintf("BIP300 M6 %s was never proposed for slot %u", m6id.GetHex(), change->slot));
                        case 6: return SetError(error, strprintf("BIP300 M6 %s has %u votes, requiring more than %u", m6id.GetHex(), approved->votes, withdrawal_bundle_inclusion_threshold));
                        case 7: return SetError(error, strprintf("parent block contains multiple successful M6 withdrawals for configured slot %u", configured_slot));
                        default: throw std::logic_error("invalid M6 withdrawal result");
                        }
                    }
                    case 9: return ParentReplayEach(changes, [&](const CtipChange& change) {
                        std::vector<unsigned char> address;
                        const uint32_t flags = (deposits != nullptr ? 1U : 0U) |
                            (change.slot == configured_slot ? 2U : 0U) | (required_proposal_active_for_transactions ? 4U : 0U);
                        const int result = drivechain::haskell::M5Deposit(change.old_value,change.new_value,MAX_MONEY,
                            change.output_index,transaction.vout.size(),flags,[&](uint32_t step,uint64_t delta) -> int64_t {
                            switch (step) {
                            case 1: return ExtractSingleOpReturnPush(transaction.vout[change.output_index + 1].scriptPubKey, address);
                            case 2: SlotCtip(state, change.slot, configured_slot) = Bitcoin::COutPoint(transaction.GetHash(), change.output_index); return 1;
                            case 3: SlotCtipValue(state, change.slot, configured_slot) = change.new_value; return 1;
                            case 4: return address.size();
                            case 5: deposits->push_back(DrivechainMintableDeposit{*state.ctip, block.GetHash(), height, static_cast<CAmount>(delta), std::move(address)}); return 1;
                            default: throw std::logic_error("invalid M5 deposit action");
                            }
                        });
                        if (result == 1) return SetError(error, strprintf("positive CTIP replacement for slot %u has no following address", change.slot));
                        if (result == 2) return SetError(error, "parent CTIP increase is outside the money range");
                        return true;
                    });
                    default: throw std::logic_error("invalid parent transaction replay stage");
                    }
                });
            });
        }
        case 8: {
            auto slot = state.other_slots.begin();
            drivechain::haskell::PruneSlots(state.other_slots.size(), [&](uint32_t step) -> int64_t {
                switch (step) {
                case 1: return (!slot->second.active_proposal_hash.IsNull() ? 1 : 0) |
                    (!slot->second.pending_proposals.empty() ? 2 : 0) |
                    (!slot->second.pending_withdrawals.empty() ? 4 : 0) |
                    (slot->second.ctip.has_value() ? 8 : 0) |
                    (slot->second.ctip_value != 0 ? 16 : 0) |
                    (state.previous_m4_actions.count(slot->first) != 0 ? 32 : 0);
                case 2: slot = state.other_slots.erase(slot); return 1;
                case 3: ++slot; return 1;
                default: throw std::logic_error("invalid replay slot pruning action");
                }
            });
            return 1;
        }
        case 9: {
            const uint32_t flags = (state.required_proposal_activated ? 1U : 0U) |
                (state.active_proposal_hash == required_active_proposal ? 2U : 0U) |
                (successful_withdrawals != nullptr ? 4U : 0U) | (withdrawal_proposals != nullptr ? 8U : 0U);
            return drivechain::haskell::BlockPublish(flags, [&](uint32_t step) -> int32_t {
                switch (step) {
                case 1: *successful_withdrawals = std::move(derived_withdrawals); return 1;
                case 2: *withdrawal_proposals = std::move(derived_proposals); return 1;
                case 3: CheckDrivechainParentDeadline(); return 1;
                default: throw std::logic_error("invalid replay block publication action");
                }
            }) || SetError(error, "parent slot no longer has the required active proposal");
        }
        default: throw std::logic_error("invalid parent block replay stage");
        }
    });
}

bool HasRequiredDrivechainDepositDepth(const uint32_t deposit_height,
                                      const uint32_t confirmed_through_height,
                                      const uint32_t required_depth)
{
    return drivechain::haskell::HasDepositDepth(deposit_height, confirmed_through_height, required_depth);
}

static bool HasCanonicalParentCheckpoint(const Consensus::Params& consensus)
{
    return IsCanonicalDrivechainParentCheckpointIdentity(
        consensus.drivechain_parent_state_active_proposal_description,
        consensus.drivechain_parent_state_active_proposal_hash,
        consensus.drivechain_parent_state_proposal_height,
        consensus.drivechain_parent_state_proposal_block_hash,
        consensus.drivechain_parent_state_activation_height,
        consensus.drivechain_parent_state_activation_block_hash,
        consensus.drivechain_parent_state_height,
        consensus.drivechain_parent_state_ctip_txid,
        consensus.drivechain_parent_state_ctip_vout,
        consensus.drivechain_parent_state_ctip_value);
}

DrivechainDepositStatus GetConfirmedDrivechainDepositStatus(
    const uint256& mainchain_block_hash,
    const int sidechain_slot,
    const COutPoint& outpoint,
    const CAmount value,
    const std::vector<unsigned char>& address,
    std::string* error,
    const int child_height)
{
    namespace hs = drivechain::haskell;
    const Consensus::Params* config{nullptr};
    const auto positive = [](uint64_t n) { return hs::ParentReplayRecord(hs::ReplayRecordKind::POSITIVE, 0, 0, n); };
    const auto preflight = hs::ParentReplayStore(hs::ReplayStoreFlow::DEPOSIT_PREFLIGHT, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: case 5: return error != nullptr;
        case 2: error->clear(); return 1;
        case 3: return CheckConfiguredDrivechainSlot(sidechain_slot, error);
        case 4: return hs::ParentReplayRecord(hs::ReplayRecordKind::DEPOSIT, 7, value, address.size(), MAX_MONEY);
        case 6: return error->empty();
        case 7: *error = "invalid slot, amount, or address for drivechain deposit"; return 1;
        case 8: config = &Params().GetConsensus(); return 1;
        case 9: return config->drivechain_proposal_hash.has_value();
        case 10: return !config->drivechain_proposal_hash->IsNull();
        case 11: return !config->drivechain_protocol_manifest_hash.IsNull();
        case 12: return !config->drivechain_parent_state_hash.IsNull();
        case 13: return !config->drivechain_parent_state_chainwork.IsNull();
        case 14: return HasCanonicalParentCheckpoint(*config);
        case 15: return positive(config->drivechain_unused_slot_proposal_max_age);
        case 16: return positive(config->drivechain_unused_slot_activation_threshold);
        case 17: return positive(config->drivechain_used_slot_proposal_max_age);
        case 18: return positive(config->drivechain_used_slot_activation_threshold);
        case 19: return positive(config->drivechain_withdrawal_bundle_max_age);
        case 20: return positive(config->drivechain_withdrawal_bundle_inclusion_threshold);
        case 21: return config->DrivechainWithdrawalValidationEnabled();
        case 22: return config->drivechain_parent_state_replay_version == ElementsDrivechainIdentity::PARENT_REPLAY_VERSION;
        case 23: return static_cast<uint32_t>(SetError(error, DrivechainDepositStatus::UNAVAILABLE,
            "native deposits require a complete immutable parent genesis-replay identity"));
        default: throw std::logic_error("invalid deposit preflight action");
        }
    });
    if (preflight != 0) return static_cast<DrivechainDepositStatus>(preflight);
    const auto& consensus = *config;

    try {
        std::unique_lock<std::mutex> lock(
            g_drivechain_parent_replay_mutex, std::defer_lock);
        auto& cache = g_drivechain_parent_replay_cache;
        uint32_t confirmed_through_height{0}, required_depth{0};
        uint64_t snapshot_epoch{0};
        bool explicit_target{false}, needs_standalone_tip_auth{true};
        std::optional<DrivechainMintableDeposit> deposit;
        DrivechainReplayStoreReadStatus deposit_status{};
        uint256 active_cache_hash;
        const auto fail = [&](std::string message) -> uint32_t {
            if (error) *error = std::move(message);
            return 1;
        };
        // Parent RPC is selected only after exact, activated, sufficiently deep evidence.
        return static_cast<DrivechainDepositStatus>(hs::ParentReplayStore(hs::ReplayStoreFlow::CONFIRMED_DEPOSIT, [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: case 8: case 37: return DrivechainParentBudgetActive();
            case 2: return lock.try_lock();
            case 3: return fail("authenticated parent replay cache is busy warming");
            case 4: lock.lock(); return 1;
            case 5: return ReplayCacheMatchesConfiguredIdentity(cache, consensus);
            case 6: return fail("authenticated parent replay cache is not warmed");
            case 7: confirmed_through_height = cache.height; snapshot_epoch = cache.epoch; return 1;
            case 9: return g_drivechain_parent_budget.replay_snapshot_authenticated;
            case 10:
                needs_standalone_tip_auth = false;
                confirmed_through_height = g_drivechain_parent_budget.replay_snapshot_height;
                snapshot_epoch = g_drivechain_parent_budget.replay_snapshot_epoch;
                explicit_target = g_drivechain_parent_budget.replay_snapshot_is_explicit_target;
                return 1;
            case 11: return snapshot_epoch == cache.epoch;
            case 12: return fail("authenticated parent replay cache changed during validation");
            case 13: return RequireConfiguredElementsProposalActive(cache, confirmed_through_height, error);
            case 14: return bool(g_drivechain_parent_replay_store);
            case 15: return fail("persistent authenticated parent replay index is not open");
            case 16:
                deposit.emplace();
                deposit_status = g_drivechain_parent_replay_store->ReadDeposit(
                    Bitcoin::COutPoint(outpoint.hash, outpoint.n), *deposit, error);
                return 1;
            case 17: return deposit_status == DrivechainReplayStoreReadStatus::CORRUPT;
            case 18: case 35: g_drivechain_parent_replay_published_epoch.store(0, std::memory_order_release); return 1;
            case 19: cache = {}; return 1;
            case 20: g_drivechain_parent_replay_store_rebuild_required = true; return 1;
            case 21: return deposit_status == DrivechainReplayStoreReadStatus::NOT_FOUND;
            case 22: return fail(explicit_target
                ? "deposit is not a genesis-replay-derived canonical CTIP increase before the block's authenticated parent anchor"
                : "deposit is not present in the currently warmed parent replay snapshot");
            case 23: return deposit->block_hash == mainchain_block_hash;
            case 24: return deposit->value == value;
            case 25: return deposit->address == address;
            case 26: return fail("deposit does not exactly match the genesis-replay-derived canonical CTIP increase");
            case 27: return hs::ParentReplayRecord(hs::ReplayRecordKind::HEIGHT, 0, 0,
                cache.state.required_activation_height, deposit->block_height);
            case 28: return fail(strprintf("native deposit at parent height %u predates Elements proposal activation at height %u",
                deposit->block_height, cache.state.required_activation_height));
            case 29: required_depth = hs::RequiredPeginDepth(GetDrivechainPeginConfirmationDepth(Params(), child_height)); return 1;
            case 30: return HasRequiredDrivechainDepositDepth(deposit->block_height, confirmed_through_height, required_depth);
            case 31: return fail(strprintf("deposit at parent height %u does not have %u confirmations through authenticated parent height %u",
                deposit->block_height, required_depth, confirmed_through_height));
            case 32: return needs_standalone_tip_auth;
            case 33: return ReadActiveMainchainHash(cache.height, active_cache_hash, error);
            case 34: return active_cache_hash == cache.hash;
            case 36: return fail("authenticated parent replay cache is stale after a parent reorganization");
            case 38: RecordDrivechainReplaySnapshot(cache.height, cache.hash, cache.epoch, false); return 1;
            case 39: CheckDrivechainParentDeadline(); return 1;
            case 43: return explicit_target;
            default: throw std::logic_error("invalid confirmed deposit action");
            }
        }));
    } catch (const std::exception& e) {
        return SetError(error, DrivechainDepositStatus::UNAVAILABLE, e.what());
    }
}

bool ListDrivechainDepositCandidates(const std::optional<Bitcoin::COutPoint>& after,
    int child_height, std::vector<DrivechainMintableDeposit>& deposits,
    std::optional<Bitcoin::COutPoint>& next, std::string* error)
{
    deposits.clear();
    next.reset();
    std::unique_lock<std::mutex> lock(g_drivechain_parent_replay_mutex, std::try_to_lock);
    const auto& cache = g_drivechain_parent_replay_cache;
    if (!lock.owns_lock() || !ReplayCacheMatchesConfiguredIdentity(cache, Params().GetConsensus()) ||
        !g_drivechain_parent_replay_store)
        return SetError(error, "authenticated parent deposit index is unavailable");
    if (!RequireConfiguredElementsProposalActive(cache, cache.height, error)) return false;
    std::vector<DrivechainMintableDeposit> page;
    if (!g_drivechain_parent_replay_store->ListDeposits(after, 64, page, next, error)) return false;
    const auto depth = drivechain::haskell::RequiredPeginDepth(GetDrivechainPeginConfirmationDepth(Params(), child_height));
    for (auto& deposit : page) {
        if (deposit.block_height >= cache.state.required_activation_height &&
            HasRequiredDrivechainDepositDepth(deposit.block_height, cache.height, depth))
            deposits.push_back(std::move(deposit));
    }
    return true;
}

bool IsConfirmedDrivechainDeposit(const uint256& mainchain_block_hash,
                                  const int sidechain_slot,
                                  const COutPoint& outpoint,
                                  const CAmount value,
                                  const std::vector<unsigned char>& address,
                                  std::string* error,
                                  const int child_height)
{
    return GetConfirmedDrivechainDepositStatus(mainchain_block_hash, sidechain_slot,
                                                outpoint, value, address, error, child_height) ==
           DrivechainDepositStatus::VALID;
}

bool ParseDrivechainParentHeader(const UniValue& header,
                                 const uint256& expected_hash,
                                 uint64_t& median_time_past,
                                 std::string* error)
{
    namespace hs = drivechain::haskell;
    const UniValue *hash{nullptr}, *mtp{nullptr};
    median_time_past = 0;
    const auto fail = [&](const char* message) -> uint32_t { if (error) *error = message; return 0; };
    return hs::ParentReplayStore(hs::ReplayStoreFlow::HEADER_MTP, [&](uint32_t action) -> uint32_t {
        switch (action) {
        case 2: return header.isObject();
        case 3: return fail("getblockheader result is not an object");
        case 4: hash = &header.get_obj()["hash"]; return 1;
        case 5: return hash->isStr();
        case 6: return hash->get_str().size() == drivechain::PARENT_HASH_HEX_LENGTH;
        case 7: return IsHex(hash->get_str());
        case 8: return fail("getblockheader result has no canonical 32-byte hash");
        case 9: return hash->get_str() == expected_hash.GetHex();
        case 10: return uint256S(hash->get_str()) == expected_hash;
        case 11:
            if (error) *error = strprintf("getblockheader returned hash %s, expected committed parent %s", hash->get_str(), expected_hash.GetHex());
            return 0;
        case 12: mtp = &header.get_obj()["mediantime"]; return 1;
        case 13: return mtp->isNum();
        case 14: return fail("getblockheader result has no numeric mediantime");
        case 15:
            try {
                int64_t parsed{0};
                return hs::ParentReplayStore(hs::ReplayStoreFlow::HEIGHT_PARSE, [&](uint32_t step) -> uint32_t {
                    switch (step) {
                    case 1: parsed = mtp->getInt<int64_t>(); return 1;
                    case 2: return hs::ParentReplayRecord(hs::ReplayRecordKind::AMOUNT, 0, parsed, 0, UINT32_MAX);
                    case 3: return fail("getblockheader mediantime is outside the uint32 timestamp range");
                    case 4: median_time_past = static_cast<uint64_t>(parsed); return 1;
                    default: throw std::logic_error("invalid header MTP integer action");
                    }
                });
            } catch (const std::exception&) {
                return fail("getblockheader mediantime is not a canonical integer");
            }
        default: throw std::logic_error("invalid header MTP action");
        }
    });
}

bool IsCanonicalDrivechainParentCheckpointCtip(const uint256& txid, uint32_t vout, CAmount value)
{
    return drivechain::haskell::ParentReplayRecord(drivechain::haskell::ReplayRecordKind::CHECKPOINT_CTIP,
        txid.IsNull(), value, vout, MAX_MONEY);
}

bool IsCanonicalDrivechainParentCheckpointIdentity(
    const std::vector<unsigned char>& active_proposal_description,
    const std::optional<uint256>& active_proposal_hash,
    const uint32_t proposal_height,
    const uint256& proposal_block_hash,
    const uint32_t activation_height,
    const uint256& activation_block_hash,
    const uint32_t checkpoint_height,
    const uint256& ctip_txid,
    const uint32_t ctip_vout,
    const CAmount ctip_value)
{
    namespace hs = drivechain::haskell;
    return hs::ParentReplayStore(hs::ReplayStoreFlow::CHECKPOINT_IDENTITY, [&](uint32_t action) -> uint32_t {
        switch (action) {
        case 1: return IsCanonicalDrivechainParentCheckpointCtip(ctip_txid, ctip_vout, ctip_value);
        case 2: case 11: return active_proposal_description.empty();
        case 3: case 12: return active_proposal_hash.has_value();
        case 4: case 13: return active_proposal_hash->IsNull();
        case 5: return proposal_height == 0;
        case 6: case 15: return proposal_block_hash.IsNull();
        case 7: return activation_height == 0;
        case 8: case 16: return activation_block_hash.IsNull();
        case 9: return ctip_txid.IsNull();
        case 14: return Hash(active_proposal_description) == *active_proposal_hash;
        case 17: return hs::ParentReplayRecord(hs::ReplayRecordKind::LESS, 0, 0, proposal_height, activation_height);
        case 18: return hs::ParentReplayRecord(hs::ReplayRecordKind::HEIGHT, 0, 0, activation_height, checkpoint_height);
        default: throw std::logic_error("invalid checkpoint identity action");
        }
    });
}

namespace {

bool ReadActiveMainchainHash(const uint32_t height, uint256& hash, std::string* error)
{
    UniValue params(UniValue::VARR);
    params.push_back(static_cast<int64_t>(height));
    const UniValue result = CallMainChainRPCChecked("getblockhash", params);
    if (!ParseDrivechainCanonicalHash(result, hash)) {
        return SetError(error, strprintf("getblockhash(%u) returned a noncanonical hash", height));
    }
    return true;
}

bool ReadActiveMainchainHeight(uint32_t& height, std::string* error)
{
    UniValue params(UniValue::VARR);
    const UniValue result = CallMainChainRPCChecked("getblockcount", params);
    return ParseDrivechainParentHeight(result, height, error);
}

bool HasPinnedDrivechainParentState(const Consensus::Params& consensus)
{
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::PINNED_STATE,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return consensus.drivechain_slot.has_value();
            case 2: return consensus.drivechain_proposal_hash.has_value();
            case 3: return !consensus.drivechain_parent_state_hash.IsNull();
            default: throw std::logic_error("invalid pinned-state action");
            }
        });
}

bool BlockContainsExactDrivechainMessage(const Bitcoin::CBlock& block,
                                         const std::vector<unsigned char>& expected_payload,
                                         std::string* error)
{
    size_t matches{0};
    size_t index{0};
    std::optional<std::vector<unsigned char>> payload;
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::EXACT_MESSAGE,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return !block.vtx.empty();
            case 2: return bool(block.vtx[0]);
            case 3: return block.vtx[0]->IsCoinBase();
            case 4: return SetError(error, "pinned parent identity block has no coinbase transaction");
            case 5: matches = 0; return 1;
            case 6: index = 0; return 1;
            case 7: return index < block.vtx[0]->vout.size();
            case 8: payload.emplace(); return 1;
            case 9: return ExtractSingleOpReturnPush(block.vtx[0]->vout[index].scriptPubKey, *payload);
            case 10: return *payload == expected_payload;
            case 11: ++matches; return 1;
            case 12: payload.reset(); return 1;
            case 13: ++index; return 1;
            case 14: return matches == 1;
            case 15: return SetError(error, strprintf(
                "pinned parent identity block contains %u copies of its expected drivechain message", matches));
            default: throw std::logic_error("invalid exact-message action");
            }
        });
}

} // namespace

bool CheckDrivechainParentReplayMilestone(
    const Consensus::Params& consensus,
    const uint32_t height,
    const Bitcoin::CBlock& block,
    const DrivechainParentReplayState& state,
    std::string* error)
{
    namespace hs = drivechain::haskell;
    bool post_activation{false}, expects_ctip{false};
    bool checkpoint_ctip_matches{false}, checkpoint_proposal_matches{false};
    std::optional<std::vector<unsigned char>> expected;
    std::optional<decltype(state.pending_proposals)::const_iterator> proposal;
    const auto require_block_hash = [&](const uint256& hash) {
        return hs::ParentReplayStore(hs::ReplayStoreFlow::MILESTONE_HASH,
            [&](uint32_t step) -> uint32_t {
                switch (step) {
                case 1: return block.GetHash() == hash;
                case 2: return SetError(error, strprintf(
                    "authenticated parent milestone height %u hashes to %s, expected %s",
                    height, block.GetHash().GetHex(), hash.GetHex()));
                default: throw std::logic_error("invalid milestone hash action");
                }
            });
    };
    return hs::ParentReplayStore(hs::ReplayStoreFlow::MILESTONE,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: post_activation = !consensus.drivechain_parent_state_active_proposal_description.empty(); return 1;
            case 2: case 15: case 39: return post_activation;
            case 3: return height == consensus.drivechain_parent_state_proposal_height;
            case 4: return require_block_hash(consensus.drivechain_parent_state_proposal_block_hash);
            case 5: expected.emplace(drivechain::PARENT_M1_TAG.begin(), drivechain::PARENT_M1_TAG.end()); return 1;
            case 6: expected->push_back(*consensus.drivechain_slot); return 1;
            case 7: expected->insert(expected->end(), consensus.drivechain_parent_state_active_proposal_description.begin(),
                consensus.drivechain_parent_state_active_proposal_description.end()); return 1;
            case 8: return BlockContainsExactDrivechainMessage(block, *expected, error);
            case 9: proposal.emplace(state.pending_proposals.find(*consensus.drivechain_parent_state_active_proposal_hash)); return 1;
            case 10: return *proposal != state.pending_proposals.end();
            case 11: return (*proposal)->second.proposal_height == height;
            case 12: return (*proposal)->second.votes == 0;
            case 13: proposal.reset(); expected.reset(); return 1;
            case 14: return SetError(error, "authenticated parent proposal milestone did not derive the expected pending proposal state");
            case 16: return height == consensus.drivechain_parent_state_activation_height;
            case 17: return require_block_hash(consensus.drivechain_parent_state_activation_block_hash);
            case 18: expected.emplace(drivechain::PARENT_M2_TAG.begin(), drivechain::PARENT_M2_TAG.end()); return 1;
            case 19: expected->push_back(*consensus.drivechain_slot); return 1;
            case 20: expected->insert(expected->end(), consensus.drivechain_parent_state_active_proposal_hash->begin(),
                consensus.drivechain_parent_state_active_proposal_hash->end()); return 1;
            case 21: return BlockContainsExactDrivechainMessage(block, *expected, error);
            case 22: return state.active_proposal_hash == *consensus.drivechain_parent_state_active_proposal_hash;
            case 23: return state.pending_proposals.count(*consensus.drivechain_parent_state_active_proposal_hash) == 0;
            case 24: expected.reset(); return 1;
            case 26: return SetError(error, "authenticated parent activation milestone did not derive the expected active proposal state");
            case 27: return height == consensus.drivechain_parent_state_height;
            case 28: return require_block_hash(consensus.drivechain_parent_state_hash);
            case 29: expects_ctip = !consensus.drivechain_parent_state_ctip_txid.IsNull(); return 1;
            case 30: return expects_ctip;
            case 31: return state.ctip.has_value();
            case 32: return state.ctip->hash == consensus.drivechain_parent_state_ctip_txid;
            case 33: return state.ctip->n == consensus.drivechain_parent_state_ctip_vout;
            case 34: return state.ctip_value == consensus.drivechain_parent_state_ctip_value;
            case 35: return !state.ctip;
            case 36: return state.ctip_value == 0;
            case 37: checkpoint_ctip_matches = true; return 1;
            case 38: checkpoint_ctip_matches = false; return 1;
            case 40: checkpoint_proposal_matches = state.active_proposal_hash == *consensus.drivechain_parent_state_active_proposal_hash; return 1;
            case 41: checkpoint_proposal_matches = state.active_proposal_hash.IsNull(); return 1;
            case 42: return checkpoint_proposal_matches;
            case 43: return checkpoint_ctip_matches;
            case 44: return SetError(error, "authenticated parent checkpoint milestone did not derive the asserted active proposal and CTIP");
            default: throw std::logic_error("invalid replay milestone action");
            }
        });
}

uint256 DrivechainParentReplayStoreIdentity(const Consensus::Params& consensus)
{
    std::optional<HashWriter> writer;
    uint256 identity;
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::IDENTITY,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: assert(consensus.drivechain_slot.has_value()); return 1;
            case 2: assert(consensus.drivechain_proposal_hash.has_value()); return 1;
            case 3: writer.emplace(); return 1;
            case 4: *writer << std::string{drivechain::PARENT_REPLAY_STORE_DOMAIN}; return 1;
            case 5: *writer << std::string{ElementsDrivechainIdentity::BIP300301_ENFORCER_REVISION}; return 1;
            case 6: *writer << std::string{ElementsDrivechainIdentity::BIP300301_LOCAL_RULE_DOMAIN}; return 1;
            case 7: *writer << std::string{ElementsDrivechainIdentity::BIP300301_LOCAL_RULE_ID}; return 1;
            case 8: *writer << Params().HashGenesisBlock(); return 1;
            case 9: *writer << Params().ParentGenesisBlockHash(); return 1;
            case 10: *writer << consensus.parentChainPowLimit; return 1;
            case 11: *writer << consensus.parent_signet_challenge; return 1;
            case 12: *writer << consensus.pegin_min_depth; return 1;
            case 13: *writer << *consensus.drivechain_slot; return 1;
            case 14: *writer << consensus.drivechain_protocol_manifest_hash; return 1;
            case 15: *writer << consensus.drivechain_proposal_description; return 1;
            case 16: *writer << *consensus.drivechain_proposal_hash; return 1;
            case 17: *writer << consensus.drivechain_parent_state_active_proposal_description; return 1;
            case 18: *writer << consensus.drivechain_parent_state_active_proposal_hash.value_or(uint256{}); return 1;
            case 19: *writer << consensus.drivechain_parent_state_proposal_height; return 1;
            case 20: *writer << consensus.drivechain_parent_state_proposal_block_hash; return 1;
            case 21: *writer << consensus.drivechain_parent_state_activation_height; return 1;
            case 22: *writer << consensus.drivechain_parent_state_activation_block_hash; return 1;
            case 23: *writer << consensus.drivechain_parent_state_height; return 1;
            case 24: *writer << consensus.drivechain_parent_state_hash; return 1;
            case 25: *writer << consensus.drivechain_parent_state_chainwork; return 1;
            case 26: *writer << consensus.drivechain_parent_state_ctip_txid; return 1;
            case 27: *writer << consensus.drivechain_parent_state_ctip_vout; return 1;
            case 28: *writer << consensus.drivechain_parent_state_ctip_value; return 1;
            case 29: *writer << uint256S(ElementsDrivechainIdentity::PARENT_CHECKPOINT_BOOTSTRAP_STATE_COMMITMENT); return 1;
            case 30: *writer << consensus.drivechain_unused_slot_proposal_max_age; return 1;
            case 31: *writer << consensus.drivechain_unused_slot_activation_threshold; return 1;
            case 32: *writer << consensus.drivechain_used_slot_proposal_max_age; return 1;
            case 33: *writer << consensus.drivechain_used_slot_activation_threshold; return 1;
            case 34: *writer << consensus.drivechain_withdrawal_bundle_max_age; return 1;
            case 35: *writer << consensus.drivechain_withdrawal_bundle_inclusion_threshold; return 1;
            case 36: *writer << consensus.drivechain_m6_withdrawal_validation; return 1;
            case 37: *writer << consensus.drivechain_parent_state_replay_version; return 1;
            case 38: identity = writer->GetHash(); return 1;
            default: throw std::logic_error("invalid parent replay identity action");
            }
        });
    return identity;
}

void WriteDrivechainBootstrapPreimage(HashWriter& writer, const Consensus::Params& consensus,
    std::span<const ElementsDrivechainBootstrap::Slot> slots)
{
    size_t index{0};
    uint256 active, ctip_hash;
    bool has_ctip{false};
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::BOOTSTRAP_PREIMAGE,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: writer << std::string{drivechain::FROZEN_PARENT_RULES.bootstrap_domain}; return 1;
            case 2: writer << consensus.drivechain_parent_state_height; return 1;
            case 3: writer << consensus.drivechain_parent_state_hash; return 1;
            case 4: writer << consensus.drivechain_parent_state_chainwork; return 1;
            case 5: writer << static_cast<uint32_t>(slots.size()); return 1;
            case 6: index = 0; return 1;
            case 7: return index < slots.size();
            case 8: active = uint256S(slots[index].active); return 1;
            case 9: ctip_hash = uint256S(slots[index].ctip_txid); return 1;
            case 10: has_ctip = !ctip_hash.IsNull(); return 1;
            case 11: writer << slots[index].slot; return 1;
            case 12: writer << active; return 1;
            case 13: writer << has_ctip; return 1;
            case 14: return has_ctip;
            case 15: writer << ctip_hash; return 1;
            case 16: writer << slots[index].ctip_vout; return 1;
            case 17: writer << slots[index].ctip_value; return 1;
            case 18: ++index; return 1;
            default: throw std::logic_error("invalid bootstrap preimage action");
            }
        });
}

namespace {
void ConfigureDrivechainParentReplayCacheIdentity(
    DrivechainParentReplayCache& cache,
    const Consensus::Params& consensus)
{
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::CACHE_CONFIG,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: cache = {}; return 1;
            case 2: cache.initialized = true; return 1;
            case 3: cache.epoch = ++g_drivechain_parent_replay_epoch_counter; return 1;
            case 4: cache.slot = *consensus.drivechain_slot; return 1;
            case 5: cache.proposal_hash = *consensus.drivechain_proposal_hash; return 1;
            case 6: cache.checkpoint_active_proposal_hash = consensus.drivechain_parent_state_active_proposal_hash.value_or(uint256{}); return 1;
            case 7: cache.checkpoint_hash = consensus.drivechain_parent_state_hash; return 1;
            case 8: cache.unused_proposal_max_age = consensus.drivechain_unused_slot_proposal_max_age; return 1;
            case 9: cache.unused_activation_threshold = consensus.drivechain_unused_slot_activation_threshold; return 1;
            case 10: cache.used_proposal_max_age = consensus.drivechain_used_slot_proposal_max_age; return 1;
            case 11: cache.used_activation_threshold = consensus.drivechain_used_slot_activation_threshold; return 1;
            case 12: cache.withdrawal_bundle_max_age = consensus.drivechain_withdrawal_bundle_max_age; return 1;
            case 13: cache.withdrawal_bundle_inclusion_threshold = consensus.drivechain_withdrawal_bundle_inclusion_threshold; return 1;
            case 14: cache.replay_version = consensus.drivechain_parent_state_replay_version; return 1;
            default: throw std::logic_error("invalid replay cache configuration action");
            }
        });
}

bool InitializeDrivechainParentReplayCache(DrivechainParentReplayCache& cache,
                                           std::string* error,
                                           const bool force_rebuild = false)
{
    namespace hs = drivechain::haskell;
    const Consensus::Params& consensus = Params().GetConsensus();
    uint256 active_genesis;
    std::optional<Bitcoin::CBlock> checkpoint_block;
    std::optional<VerifiedMainchainHeader> checkpoint_header;
    const auto positive = [](uint64_t value) { return hs::ParentReplayRecord(hs::ReplayRecordKind::POSITIVE, 0, 0, value); };
    const auto less = [](uint64_t first, uint64_t second) { return hs::ParentReplayRecord(hs::ReplayRecordKind::LESS, 0, 0, first, second); };
    const auto preflight = hs::ParentReplayStore(hs::ReplayStoreFlow::CACHE_PREFLIGHT, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return HasPinnedDrivechainParentState(consensus);
        case 2: return !consensus.drivechain_proposal_description.empty();
        case 3: return !consensus.drivechain_proposal_hash->IsNull();
        case 4: return Hash(consensus.drivechain_proposal_description) == *consensus.drivechain_proposal_hash;
        case 5: return !consensus.drivechain_protocol_manifest_hash.IsNull();
        case 6: return HasCanonicalParentCheckpoint(consensus);
        case 7: return !consensus.drivechain_parent_state_chainwork.IsNull();
        case 8: return positive(consensus.drivechain_unused_slot_proposal_max_age);
        case 9: return positive(consensus.drivechain_unused_slot_activation_threshold);
        case 10: return less(consensus.drivechain_unused_slot_activation_threshold, consensus.drivechain_unused_slot_proposal_max_age);
        case 11: return positive(consensus.drivechain_used_slot_proposal_max_age);
        case 12: return positive(consensus.drivechain_used_slot_activation_threshold);
        case 13: return less(consensus.drivechain_used_slot_activation_threshold, consensus.drivechain_used_slot_proposal_max_age);
        case 14: return positive(consensus.drivechain_withdrawal_bundle_max_age);
        case 15: return positive(consensus.drivechain_withdrawal_bundle_inclusion_threshold);
        case 16: return less(consensus.drivechain_withdrawal_bundle_inclusion_threshold, consensus.drivechain_withdrawal_bundle_max_age);
        case 17: return consensus.DrivechainWithdrawalValidationEnabled();
        case 18: return consensus.drivechain_parent_state_replay_version == ElementsDrivechainIdentity::PARENT_REPLAY_VERSION;
        case 19: return SetError(error, "native drivechain parent launch identity is incomplete or internally inconsistent");
        case 20: return ReadActiveMainchainHash(0, active_genesis, error);
        case 21: return active_genesis == Params().ParentGenesisBlockHash();
        case 22: return SetError(error, "mainchain RPC does not serve the pinned parent genesis");
        case 23:
            checkpoint_block.emplace();
            checkpoint_header.emplace();
            return ReadVerifiedMainchainBlock(consensus.drivechain_parent_state_hash, 1, *checkpoint_block, *checkpoint_header, error);
        case 24: return checkpoint_header->height == consensus.drivechain_parent_state_height;
        case 25: return checkpoint_header->chainwork == consensus.drivechain_parent_state_chainwork;
        case 26: return SetError(error, "authenticated parent launch checkpoint height or chainwork is not pinned value");
        default: throw std::logic_error("invalid replay cache preflight action");
        }
    });
    if (preflight != 1) return preflight == 0;

    ConfigureDrivechainParentReplayCacheIdentity(cache, consensus);

    uint256 store_identity;
    {
        std::optional<DrivechainParentReplayTip> stored_tip;
        std::optional<std::string> load_error;
        DrivechainReplayStoreLoadStatus load_status{DrivechainReplayStoreLoadStatus::EMPTY};
        bool checkpoint_requires_active{false}, checkpoint_requires_ctip{false};
        if (hs::ParentReplayStore(hs::ReplayStoreFlow::CACHE_LOAD, [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return g_drivechain_parent_replay_store != nullptr;
            case 2:
                g_drivechain_parent_replay_store = std::make_unique<DrivechainParentReplayStore>(
                    gArgs.GetDataDirNet() / drivechain::PARENT_REPLAY_DIRECTORY,
                    DRIVECHAIN_PARENT_REPLAY_DB_CACHE_BYTES,
                    /*wipe=*/gArgs.GetBoolArg("-reindex", false), drivechain::FROZEN_PARENT_RULES.history);
                return 1;
            case 3: store_identity = DrivechainParentReplayStoreIdentity(consensus); return 1;
            case 4: return force_rebuild;
            case 5: return g_drivechain_parent_replay_store_rebuild_required;
            case 6:
                stored_tip.emplace();
                load_error.emplace();
                load_status = g_drivechain_parent_replay_store->Load(store_identity, *stored_tip, &*load_error);
                return static_cast<uint32_t>(load_status);
            case 7: checkpoint_requires_active = !consensus.drivechain_parent_state_active_proposal_description.empty(); return 1;
            case 8: checkpoint_requires_ctip = !consensus.drivechain_parent_state_ctip_txid.IsNull(); return 1;
            case 9: return hs::ParentReplayRecord(hs::ReplayRecordKind::HEIGHT, 0, 0, consensus.drivechain_parent_state_height, stored_tip->height);
            case 10: return checkpoint_requires_active;
            case 11: return stored_tip->state.active_proposal_hash.IsNull();
            case 12: return stored_tip->state.required_proposal_activated;
            case 13: return stored_tip->state.active_proposal_hash != cache.proposal_hash;
            case 14: return stored_tip->state.required_activation_block_hash.IsNull();
            case 15: return less(stored_tip->height, stored_tip->state.required_activation_height);
            case 16: return checkpoint_requires_ctip;
            case 17: return !stored_tip->state.ctip;
            case 18: cache.height = stored_tip->height; return 1;
            case 19: cache.hash = stored_tip->hash; return 1;
            case 20: cache.state = std::move(stored_tip->state); return 1;
            case 21: LogPrintf("Discarding derived parent replay index whose tip contradicts the immutable launch checkpoint\n"); return 1;
            case 22: return load_status == DrivechainReplayStoreLoadStatus::CORRUPT;
            case 23: return load_status == DrivechainReplayStoreLoadStatus::IDENTITY_MISMATCH;
            case 24: LogPrintf("Discarding unusable derived parent replay index and rebuilding from authenticated genesis: %s\n", *load_error); return 1;
            default: throw std::logic_error("invalid replay cache load action");
            }
        })) return true;
    }

    uint256 expected_bootstrap_commitment, ctip_hash;
    std::optional<HashWriter> bootstrap_writer;
    std::optional<DrivechainParentReplayState> bootstrap_state, genesis_state;
    std::optional<DrivechainOtherSlotReplayState> other;
    std::optional<Bitcoin::CBlock> genesis_block;
    size_t index{0};
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::CACHE_REBUILD,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return ElementsDrivechainBootstrap::ENABLED;
            case 2: expected_bootstrap_commitment = uint256S(ElementsDrivechainIdentity::PARENT_CHECKPOINT_BOOTSTRAP_STATE_COMMITMENT); return 1;
            case 3: bootstrap_writer.emplace(); return 1;
            case 4: WriteDrivechainBootstrapPreimage(*bootstrap_writer, consensus, ElementsDrivechainBootstrap::SLOTS); return 1;
            case 5: return !expected_bootstrap_commitment.IsNull();
            case 6: return bootstrap_writer->GetHash() == expected_bootstrap_commitment;
            case 7: cache = {}; return 1;
            case 8: return SetError(error, "parent replay bootstrap state does not match its identity commitment");
            case 9: bootstrap_state.emplace(); return 1;
            case 10: index = 0; return 1;
            case 11: return index < ElementsDrivechainBootstrap::SLOTS.size();
            case 12: return ElementsDrivechainBootstrap::SLOTS[index].slot != cache.slot;
            case 13: return ElementsDrivechainBootstrap::SLOTS[index].active != nullptr;
            case 14: return ElementsDrivechainBootstrap::SLOTS[index].ctip_txid != nullptr;
            case 15: cache = {}; return 1;
            case 16: return SetError(error, "parent replay bootstrap contains an invalid global slot");
            case 17: other.emplace(); return 1;
            case 18: other->active_proposal_hash = uint256S(ElementsDrivechainBootstrap::SLOTS[index].active); return 1;
            case 19: return !other->active_proposal_hash.IsNull();
            case 20: cache = {}; return 1;
            case 21: return SetError(error, "parent replay bootstrap contains a null active proposal");
            case 22: ctip_hash = uint256S(ElementsDrivechainBootstrap::SLOTS[index].ctip_txid); return 1;
            case 23: return !ctip_hash.IsNull();
            case 24: other->ctip = Bitcoin::COutPoint(ctip_hash, ElementsDrivechainBootstrap::SLOTS[index].ctip_vout); return 1;
            case 25: other->ctip_value = ElementsDrivechainBootstrap::SLOTS[index].ctip_value; return 1;
            case 26: return ElementsDrivechainBootstrap::SLOTS[index].ctip_vout == Bitcoin::COutPoint::NULL_INDEX;
            case 27: return ElementsDrivechainBootstrap::SLOTS[index].ctip_value == 0;
            case 28: cache = {}; return 1;
            case 29: return SetError(error, "parent replay bootstrap has a malformed absent CTIP");
            case 30: return bootstrap_state->other_slots.emplace(ElementsDrivechainBootstrap::SLOTS[index].slot, std::move(*other)).second;
            case 31: other.reset(); ++index; return 1;
            case 32: cache.height = consensus.drivechain_parent_state_height; return 1;
            case 33: cache.hash = consensus.drivechain_parent_state_hash; return 1;
            case 34: cache.state = std::move(*bootstrap_state); return 1;
            case 35: return g_drivechain_parent_replay_store->Reset(
                store_identity, DrivechainParentReplayTip{cache.height, cache.hash, cache.state}, error);
            case 36: cache = {}; return 0;
            case 37: g_drivechain_parent_replay_store_rebuild_required = false; return 1;
            case 38: cache = {}; return 1;
            case 39: return SetError(error, "parent replay bootstrap repeats a global slot");
            case 40: genesis_block.emplace(); return 1;
            case 41: return ReadAuthenticatedRawMainchainBlock(active_genesis, *genesis_block, error);
            case 42: return genesis_block->hashPrevBlock.IsNull();
            case 43: cache = {}; return 1;
            case 44: return SetError(error, "authenticated parent genesis unexpectedly has a predecessor");
            case 45: genesis_state.emplace(); return 1;
            case 46: return ApplyDrivechainParentBlockState(
                *genesis_block, 0, cache.slot, cache.proposal_hash,
                cache.unused_proposal_max_age, cache.unused_activation_threshold,
                cache.used_proposal_max_age, cache.used_activation_threshold,
                cache.withdrawal_bundle_max_age, cache.withdrawal_bundle_inclusion_threshold,
                *genesis_state, nullptr, error, nullptr, nullptr,
                drivechain::FROZEN_PARENT_RULES.treasury_opcode, drivechain::FROZEN_PARENT_RULES.m6);
            case 47: cache.height = 0; return 1;
            case 48: cache.hash = active_genesis; return 1;
            case 49: cache.state = std::move(*genesis_state); return 1;
            default: throw std::logic_error("invalid replay cache rebuild action");
            }
        });
}

bool ReplayCacheMatchesConfiguredIdentity(const DrivechainParentReplayCache& cache,
                                          const Consensus::Params& consensus)
{
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::CACHE_MATCH,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return cache.initialized;
            case 2: return consensus.drivechain_slot.has_value();
            case 3: return consensus.drivechain_proposal_hash.has_value();
            case 4: return cache.slot == *consensus.drivechain_slot;
            case 5: return cache.proposal_hash == *consensus.drivechain_proposal_hash;
            case 6: return cache.checkpoint_active_proposal_hash == consensus.drivechain_parent_state_active_proposal_hash.value_or(uint256{});
            case 7: return cache.checkpoint_hash == consensus.drivechain_parent_state_hash;
            case 8: return cache.unused_proposal_max_age == consensus.drivechain_unused_slot_proposal_max_age;
            case 9: return cache.unused_activation_threshold == consensus.drivechain_unused_slot_activation_threshold;
            case 10: return cache.used_proposal_max_age == consensus.drivechain_used_slot_proposal_max_age;
            case 11: return cache.used_activation_threshold == consensus.drivechain_used_slot_activation_threshold;
            case 12: return cache.withdrawal_bundle_max_age == consensus.drivechain_withdrawal_bundle_max_age;
            case 13: return cache.withdrawal_bundle_inclusion_threshold == consensus.drivechain_withdrawal_bundle_inclusion_threshold;
            case 14: return cache.replay_version == consensus.drivechain_parent_state_replay_version;
            default: throw std::logic_error("invalid replay cache identity check");
            }
        });
}

bool RequireConfiguredElementsProposalActive(
    const DrivechainParentReplayCache& cache,
    const uint32_t target_height,
    std::string* error)
{
    namespace hs = drivechain::haskell;
    return hs::ParentReplayStore(hs::ReplayStoreFlow::REQUIRED_PROPOSAL, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return cache.state.required_proposal_activated;
        case 2: return cache.state.active_proposal_hash == cache.proposal_hash;
        case 3: return hs::ParentReplayRecord(hs::ReplayRecordKind::HEIGHT, 0, 0,
            cache.state.required_activation_height, target_height);
        case 4: return SetError(error, strprintf(
            "configured Elements slot proposal is not active at parent height %u", target_height));
        default: throw std::logic_error("invalid required proposal action");
        }
    });
}

bool EnsurePinnedDrivechainParentStateThroughLocked(const uint32_t target_height,
                                                    const uint256& target_hash,
                                                    const bool require_elements_active,
                                                    DrivechainParentReplayCache& cache,
                                                    std::string* error)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    namespace hs = drivechain::haskell;
    uint256 active_checkpoint, active_cache_hash, active_target;
    uint32_t active_tip_height{0};
    bool stale_cache{false};
    const auto less = [](uint32_t first, uint32_t second) {
        return hs::ParentReplayRecord(hs::ReplayRecordKind::LESS, 0, 0, first, second);
    };
    // Locked validation may observe a cache but must never start a long rebuild.
    const auto preflight = hs::ParentReplayStore(hs::ReplayStoreFlow::REPLAY_PREFLIGHT,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return HasPinnedDrivechainParentState(consensus);
            case 2: return hs::ParentReplayRecord(hs::ReplayRecordKind::HEIGHT, 0, 0,
                consensus.drivechain_parent_state_height, target_height);
            case 3: return SetError(error, strprintf(
                "parent height %u predates native drivechain launch checkpoint %u",
                target_height, consensus.drivechain_parent_state_height));
            case 4: return ReplayCacheMatchesConfiguredIdentity(cache, consensus);
            case 5: return DrivechainParentBudgetActive();
            case 6: return SetError(error, "authenticated parent replay cache is not warmed");
            case 7: g_drivechain_parent_replay_published_epoch.store(0, std::memory_order_release); return 1;
            case 8: cache = {}; return 1;
            case 9: return InitializeDrivechainParentReplayCache(cache, error);
            case 10: return ReadActiveMainchainHash(consensus.drivechain_parent_state_height, active_checkpoint, error);
            case 11: return active_checkpoint == consensus.drivechain_parent_state_hash;
            case 12: g_drivechain_parent_replay_published_epoch.store(0, std::memory_order_release); return 1;
            case 13: return SetError(error, "active parent chain no longer contains the pinned drivechain launch checkpoint");
            case 14: return less(target_height, cache.height);
            case 15: return ReadActiveMainchainHeight(active_tip_height, error);
            case 16: stale_cache = less(active_tip_height, cache.height); return 1;
            case 17: return stale_cache;
            case 18: return ReadActiveMainchainHash(cache.height, active_cache_hash, error);
            case 19: stale_cache = active_cache_hash != cache.hash; return 1;
            case 20: return stale_cache;
            case 21: g_drivechain_parent_replay_published_epoch.store(0, std::memory_order_release); return 1;
            case 22: return DrivechainParentBudgetActive();
            case 23: return SetError(error, "authenticated parent replay cache is stale after a parent reorganization");
            case 24: cache = {}; return 1;
            // A stale derived tip must not be reloaded during reconstruction.
            case 25: return InitializeDrivechainParentReplayCache(cache, error, /*force_rebuild=*/true);
            case 26: return ReadActiveMainchainHash(target_height, active_target, error);
            case 27: return active_target == target_hash;
            case 28: return SetError(error, "requested parent replay target is not active at its claimed height");
            default: throw std::logic_error("invalid replay preflight action");
            }
        });
    if (preflight != 1) return preflight == 0;

    {
        uint32_t height{0}, replay_steps{0};
        std::optional<uint256> block_hash, committed_sidechain_hash;
        std::optional<Bitcoin::CBlock> block;
        std::optional<DrivechainParentReplayState> next_state;
        std::optional<std::vector<DrivechainMintableDeposit>> deposits;
        std::optional<std::vector<DrivechainSuccessfulWithdrawal>> successful_withdrawals;
        std::optional<std::vector<DrivechainWithdrawalProposalIdentity>> withdrawal_proposals;
        std::optional<std::pair<uint256, DrivechainReplayedBmmEdge>> replayed_edge;
        bool has_canonical_commitment{false};
        if (!hs::ParentReplayStore(hs::ReplayStoreFlow::REPLAY_ADVANCE,
            [&](uint32_t step) -> uint32_t {
                switch (step) {
                case 1: return less(cache.height, target_height);
                case 2: replay_steps = hs::ReplayDistance(target_height, cache.height); return 1;
                case 3: return ConsumeDrivechainReplayBudget(replay_steps, error);
                case 4: height = cache.height; return 1;
                case 5: return less(height, target_height);
                // Increment only below the target, never after UINT32_MAX.
                case 6: ++height; return 1;
                case 7: CheckDrivechainParentDeadline(); return 1;
                case 8: block_hash.emplace(); return 1;
                case 9: return ReadActiveMainchainHash(height, *block_hash, error);
                case 10: block.emplace(); return 1;
                case 11: return ReadAuthenticatedRawMainchainBlock(*block_hash, *block, error);
                case 12: return block->hashPrevBlock == cache.hash;
                case 13: g_drivechain_parent_replay_published_epoch.store(0, std::memory_order_release); return 1;
                case 14: return SetError(error, "authenticated parent-state replay is not a contiguous chain");
                case 15: next_state.emplace(cache.state); return 1;
                case 16: deposits.emplace(); return 1;
                case 17: successful_withdrawals.emplace(); return 1;
                case 18: withdrawal_proposals.emplace(); return 1;
                case 19: return ApplyDrivechainParentBlockState(
                    *block, height, cache.slot, cache.proposal_hash,
                    consensus.drivechain_unused_slot_proposal_max_age,
                    consensus.drivechain_unused_slot_activation_threshold,
                    consensus.drivechain_used_slot_proposal_max_age,
                    consensus.drivechain_used_slot_activation_threshold,
                    consensus.drivechain_withdrawal_bundle_max_age,
                    consensus.drivechain_withdrawal_bundle_inclusion_threshold,
                    *next_state, &*deposits, error, &*successful_withdrawals,
                    &*withdrawal_proposals, drivechain::FROZEN_PARENT_RULES.treasury_opcode,
                    drivechain::FROZEN_PARENT_RULES.m6);
                case 20: return CheckDrivechainParentReplayMilestone(consensus, height, *block, *next_state, error);
                case 21: g_drivechain_parent_replay_published_epoch.store(0, std::memory_order_release); return 0;
                case 22: CheckDrivechainParentDeadline(); return 1;
                case 23: replayed_edge.reset(); return 1;
                case 24: return less(consensus.drivechain_parent_state_height, height);
                case 25: committed_sidechain_hash.emplace(); return 1;
                case 26: has_canonical_commitment = ExtractCanonicalDrivechainBmmCommitmentInBlock(
                    *block, cache.slot, *committed_sidechain_hash, nullptr, nullptr); return 1;
                case 27:
                    replayed_edge.emplace(cache.hash, DrivechainReplayedBmmEdge{
                        *block_hash, cache.height, height, has_canonical_commitment, *committed_sidechain_hash});
                    committed_sidechain_hash.reset();
                    return 1;
                case 28: return bool(g_drivechain_parent_replay_store);
                // Durable tip and records precede every in-memory tip mutation.
                case 29: return g_drivechain_parent_replay_store->Append(
                    DrivechainParentReplayTip{cache.height, cache.hash, cache.state},
                    DrivechainParentReplayTip{height, *block_hash, *next_state},
                    *deposits, replayed_edge, *successful_withdrawals, *withdrawal_proposals, error);
                case 30: cache.state = std::move(*next_state); return 1;
                case 31: cache.height = height; return 1;
                case 32: cache.hash = *block_hash; return 1;
                case 33:
                    replayed_edge.reset();
                    withdrawal_proposals.reset();
                    successful_withdrawals.reset();
                    deposits.reset();
                    next_state.reset();
                    block.reset();
                    block_hash.reset();
                    return 1;
                default: throw std::logic_error("invalid replay advancement action");
                }
            })) return false;
    }

    // Re-read all active-chain boundaries before publishing the cache epoch.
    uint256 final_active_cache_hash;
    return hs::ParentReplayStore(hs::ReplayStoreFlow::REPLAY_PUBLISH,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return ReadActiveMainchainHash(consensus.drivechain_parent_state_height, active_checkpoint, error);
            case 2: return active_checkpoint == consensus.drivechain_parent_state_hash;
            case 3: g_drivechain_parent_replay_published_epoch.store(0, std::memory_order_release); return 1;
            case 4: return SetError(error, "parent-chain reorg raced the pinned launch checkpoint check");
            case 5: return ReadActiveMainchainHash(target_height, active_target, error);
            case 6: return active_target == target_hash;
            case 7: g_drivechain_parent_replay_published_epoch.store(0, std::memory_order_release); return 1;
            case 8: return SetError(error, "parent-chain reorg raced the replay target check");
            case 9: return ReadActiveMainchainHash(cache.height, final_active_cache_hash, error);
            case 10: return final_active_cache_hash == cache.hash;
            case 11: g_drivechain_parent_replay_published_epoch.store(0, std::memory_order_release); return 1;
            case 12: return SetError(error, "parent-chain reorg raced the replay cache tip check");
            case 13: return require_elements_active;
            case 14: return RequireConfiguredElementsProposalActive(cache, target_height, error);
            case 15: CheckDrivechainParentDeadline(); return 1;
            case 16: g_drivechain_parent_replay_published_epoch.store(cache.epoch, std::memory_order_release); return 1;
            default: throw std::logic_error("invalid replay publication action");
            }
        });
}

bool EnsurePinnedDrivechainParentStateThrough(const uint32_t target_height,
                                              const uint256& target_hash,
                                              const bool require_elements_active,
                                              std::string* error)
{
    std::unique_lock<std::mutex> lock(g_drivechain_parent_replay_mutex, std::defer_lock);
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::REPLAY_LOCK,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return DrivechainParentBudgetActive();
            case 2: return lock.try_lock();
            case 3: return SetError(error, "authenticated parent replay cache is busy warming");
            case 4: lock.lock(); return 1;
            case 5: return EnsurePinnedDrivechainParentStateThroughLocked(
                target_height, target_hash, require_elements_active, g_drivechain_parent_replay_cache, error);
            case 6: RecordDrivechainReplaySnapshot(
                target_height, target_hash, g_drivechain_parent_replay_cache.epoch,
                /*explicit_target=*/true); return 1;
            default: throw std::logic_error("invalid replay lock action");
            }
        });
}

bool GetDrivechainParentContextForHash(const uint256& parent_hash,
                                       DrivechainParentBlockContext& context,
                                       std::string* error)
{
    namespace hs = drivechain::haskell;
    struct VerifiedParent { Bitcoin::CBlock block; VerifiedMainchainHeader header; };
    std::optional<VerifiedParent> parent;
    return hs::ParentReplayStore(hs::ReplayStoreFlow::VERIFIED_PARENT_CONTEXT, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: context = {}; return 1;
        case 2: parent.emplace(); return 1;
        case 3: return ReadVerifiedMainchainBlock(parent_hash, 1, parent->block, parent->header, error);
        case 4: return EnsurePinnedDrivechainParentStateThrough(parent->header.height, parent_hash, true, error);
        case 5:
            context.parent_hash = parent_hash;
            context.parent_chainwork = parent->header.chainwork;
            context.parent_height = parent->header.height;
            context.parent_median_time_past = parent->header.median_time_past;
            return 1;
        default: throw std::logic_error("invalid verified parent context action");
        }
    });
}

struct DrivechainBmmEdgeCacheEntry {
    uint64_t replay_epoch{0};
    uint256 parent_hash;
    uint256 successor_hash;
    uint8_t slot{0};
    DrivechainBmmBlockContext context;
    bool has_canonical_commitment{false};
    uint256 committed_sidechain_hash;
    std::string rejection_reason;
};

struct DrivechainBmmNegativeParentCacheEntry {
    uint64_t replay_epoch{0};
    uint256 parent_hash;
    uint8_t slot{0};
    std::string rejection_reason;
    std::chrono::steady_clock::time_point expires;
};

std::mutex g_drivechain_bmm_edge_cache_mutex;
std::deque<DrivechainBmmEdgeCacheEntry> g_drivechain_bmm_edge_cache;
std::deque<DrivechainBmmNegativeParentCacheEntry> g_drivechain_bmm_negative_parent_cache;

void PruneDrivechainBmmCachesForEpoch(const uint64_t replay_epoch)
{
    namespace hs = drivechain::haskell;
    const auto now = std::chrono::steady_clock::now();
    const auto expired = [replay_epoch](const auto& entry, bool timeout = false) {
        return hs::ParentReplayRecord(hs::ReplayRecordKind::CACHE_EXPIRED, timeout, 0, entry.replay_epoch, replay_epoch);
    };
    std::erase_if(g_drivechain_bmm_edge_cache, [&](const auto& entry) { return expired(entry); });
    std::erase_if(g_drivechain_bmm_negative_parent_cache, [&](const auto& entry) {
        return expired(entry, entry.expires <= now);
    });
}

void CacheRejectedDrivechainParent(const uint64_t replay_epoch,
                                   const uint256& parent_hash,
                                   const uint8_t slot,
                                   const std::string& reason)
{
    g_drivechain_bmm_negative_parent_cache.push_back(
        {replay_epoch, parent_hash, slot, reason,
         std::chrono::steady_clock::now() + std::chrono::seconds{drivechain::BMM_NEGATIVE_PARENT_CACHE_SECONDS}});
    drivechain::haskell::ParentReplayAll<2>({
        [&] { return drivechain::haskell::ParentReplayRecord(drivechain::haskell::ReplayRecordKind::LESS,
            0, 0, drivechain::BMM_NEGATIVE_PARENT_CACHE_MAX, g_drivechain_bmm_negative_parent_cache.size()); },
        [&] { g_drivechain_bmm_negative_parent_cache.pop_front(); return true; }});
}

enum class DrivechainParentProbeStatus {
    ACTIVE,
    REJECTED,
    UNAVAILABLE,
};
static_assert(unsigned(DrivechainParentProbeStatus::ACTIVE) == 0 &&
              unsigned(DrivechainParentProbeStatus::REJECTED) == 1 &&
              unsigned(DrivechainParentProbeStatus::UNAVAILABLE) == 2);

DrivechainParentProbeStatus ProbeActiveDrivechainParent(
    const uint256& parent_hash,
    uint32_t& parent_height,
    std::string* error)
{
    parent_height = 0;
    UniValue params(UniValue::VARR);
    params.push_back(parent_hash.GetHex());
    params.push_back(true);
    const UniValue reply = CallMainChainRPC("getblockheader", params);
    const UniValue& rpc_error = reply["error"];
    namespace hs = drivechain::haskell;
    const UniValue* code{nullptr};
    const auto rpc_status = hs::ParentReplayStore(hs::ReplayStoreFlow::PARENT_PROBE_ERROR, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return rpc_error.isNull();
        case 2: return rpc_error.isObject();
        case 3: code = &rpc_error.get_obj()["code"]; return code->isNum();
        case 4: return code->getInt<int64_t>() == -5;
        case 5: case 7: return error != nullptr;
        case 6: *error = "committed parent hash is unknown to the authenticated parent node"; return 1;
        case 8: *error = strprintf("getblockheader returned error: %s", rpc_error.write()); return 1;
        default: throw std::logic_error("invalid parent probe error action");
        }
    });
    if (rpc_status != 0) return static_cast<DrivechainParentProbeStatus>(rpc_status);

    const UniValue& result = reply["result"];
    struct Metadata {
        uint256 returned_hash;
        const UniValue *height, *confirmations;
        int64_t parsed_height{0}, parsed_confirmations{0};
    };
    std::optional<Metadata> metadata;
    std::optional<uint256> active_hash;
    return static_cast<DrivechainParentProbeStatus>(hs::ParentReplayStore(hs::ReplayStoreFlow::PARENT_PROBE_METADATA,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return result.isObject();
            case 2: case 9: case 14: case 18: case 22: return error != nullptr;
            case 3: *error = "getblockheader returned no canonical metadata object"; return 1;
            case 4:
                metadata.emplace();
                metadata->height = &result.get_obj()["height"];
                metadata->confirmations = &result.get_obj()["confirmations"];
                return 1;
            case 5: return ParseDrivechainCanonicalHash(result.get_obj()["hash"], metadata->returned_hash);
            case 6: return metadata->returned_hash == parent_hash;
            case 7: return metadata->height->isNum();
            case 8: return metadata->confirmations->isNum();
            case 10: *error = "getblockheader returned noncanonical parent metadata"; return 1;
            case 11: metadata->parsed_height = metadata->height->getInt<int64_t>(); return 1;
            case 12: metadata->parsed_confirmations = metadata->confirmations->getInt<int64_t>(); return 1;
            case 13: return hs::ParentReplayRecord(hs::ReplayRecordKind::HEIGHT, 0, 0, 0, static_cast<uint64_t>(metadata->parsed_height));
            case 15: *error = "committed parent height is outside the supported uint32 range"; return 1;
            case 16: parent_height = static_cast<uint32_t>(metadata->parsed_height); return 1;
            case 17: return hs::ParentReplayRecord(hs::ReplayRecordKind::SIGNED_POSITIVE, 0, metadata->parsed_confirmations, 0, 0);
            case 19: *error = "committed parent block is not on the active parent chain"; return 1;
            case 20: return ReadActiveMainchainHash(parent_height, active_hash.emplace(), error);
            case 21: return *active_hash == parent_hash;
            case 23: *error = "committed parent block is not active at its declared height"; return 1;
            default: throw std::logic_error("invalid parent probe metadata action");
            }
        }));
}

bool RecheckActiveBmmEdge(const uint256& parent_hash,
                          const uint32_t parent_height,
                          const uint256& successor_hash,
                          const uint32_t successor_height,
                          std::string* error)
{
    namespace hs = drivechain::haskell;
    uint256 active_hash;
    return hs::ParentReplayStore(hs::ReplayStoreFlow::BMM_EDGE_RECHECK, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return ReadActiveMainchainHash(parent_height, active_hash, error);
        case 2: return active_hash == parent_hash;
        case 3: case 7: g_drivechain_parent_replay_published_epoch.store(0, std::memory_order_release); return 1;
        case 4: return SetError(error, "parent-chain reorg raced BIP301 validation at committed P");
        case 5: return ReadActiveMainchainHash(successor_height, active_hash, error);
        case 6: return active_hash == successor_hash;
        case 8: return SetError(error, "parent-chain reorg raced BIP301 validation at successor Q");
        default: throw std::logic_error("invalid BMM edge recheck action");
        }
    });
}

DrivechainBmmStatus GetDrivechainBmmContextForHashesStatus(
    const uint256& expected_critical_hash,
    const uint256& parent_hash,
    const int sidechain_slot,
    DrivechainBmmBlockContext& context,
    std::string* error)
{
    namespace hs = drivechain::haskell;
    std::optional<std::unique_lock<std::mutex>> cache_lock;
    uint64_t replay_epoch{0};
    const auto preflight = hs::ParentReplayStore(hs::ReplayStoreFlow::BMM_CACHE_PREFLIGHT, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: context = {}; return 1;
        case 2: cache_lock.emplace(g_drivechain_bmm_edge_cache_mutex, std::defer_lock); return 1;
        case 3: return DrivechainParentBudgetActive();
        case 4: return cache_lock->try_lock();
        case 5: return static_cast<uint32_t>(SetError(error, DrivechainBmmStatus::UNAVAILABLE, "authenticated BMM edge cache is busy"));
        case 6: cache_lock->lock(); return 1;
        case 7: replay_epoch = GetDrivechainParentReplayEpoch(); return 1;
        case 8: return hs::ParentReplayRecord(hs::ReplayRecordKind::POSITIVE, 0, 0, replay_epoch, 0);
        case 9: g_drivechain_bmm_edge_cache.clear(); return 1;
        case 10: g_drivechain_bmm_negative_parent_cache.clear(); return 1;
        case 11: return static_cast<uint32_t>(SetError(error, DrivechainBmmStatus::UNAVAILABLE, "authenticated parent replay cache is not current"));
        case 12: PruneDrivechainBmmCachesForEpoch(replay_epoch); return 1;
        default: throw std::logic_error("invalid BMM cache preflight action");
        }
    });
    if (preflight != 0) return static_cast<DrivechainBmmStatus>(preflight);

    const uint8_t slot = static_cast<uint8_t>(sidechain_slot);
    const auto matches_parent = [&](const auto& entry) {
        return hs::ParentReplayStore(hs::ReplayStoreFlow::BMM_CACHE_KEY, [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return entry.parent_hash == parent_hash;
            case 2: return entry.slot == slot;
            default: throw std::logic_error("invalid BMM cache key action");
            }
        });
    };
    decltype(g_drivechain_bmm_edge_cache)::reverse_iterator it;
    const auto cached_edge = [&] {
        // Reject nonmatching critical hashes entirely in memory. Rechecking
        // P/Q first would let arbitrary values amplify two parent RPCs.
        // Because a background-observed reorg may have made this cached edge
        // stale, this cheap result is UNAVAILABLE and never peer blame.
        uint64_t rechecked_epoch{0};
        return static_cast<DrivechainBmmStatus>(hs::ParentReplayStore(hs::ReplayStoreFlow::BMM_CACHE_HIT,
            [&](uint32_t step) -> uint32_t {
                switch (step) {
                case 1: return it->has_canonical_commitment;
                case 2: return static_cast<uint32_t>(SetError(error, DrivechainBmmStatus::UNAVAILABLE,
                    "cached parent edge has no unique enforcer-recognized M7; await a fresh authenticated edge"));
                case 3: return it->committed_sidechain_hash == expected_critical_hash;
                case 4: return static_cast<uint32_t>(SetError(error, DrivechainBmmStatus::UNAVAILABLE,
                    "expected critical hash does not match the cached enforcer-recognized M7; no parent RPC performed"));
                case 5: return RecheckActiveBmmEdge(it->parent_hash, it->context.parent_height,
                    it->successor_hash, it->context.bmm_height, error);
                case 6: rechecked_epoch = GetDrivechainParentReplayEpoch(); return 1;
                case 7: return hs::ParentReplayRecord(hs::ReplayRecordKind::POSITIVE, 0, 0, rechecked_epoch, 0);
                case 8: return !hs::ParentReplayRecord(hs::ReplayRecordKind::EPOCH_CHANGED, 0, 0, rechecked_epoch, it->replay_epoch);
                case 9: return static_cast<uint32_t>(SetError(error, DrivechainBmmStatus::UNAVAILABLE,
                    "parent replay epoch changed while rechecking cached BMM edge"));
                // Bound deposit validity by this exact Q, never a warmer replay tip.
                case 10: RecordDrivechainReplaySnapshot(it->context.bmm_height, it->successor_hash,
                    rechecked_epoch, /*explicit_target=*/true); return 1;
                case 11: context = it->context; return 1;
                default: throw std::logic_error("invalid BMM cache hit action");
                }
            }));
    };

    // Untrusted P2P cache misses may consult only the background-authenticated
    // genesis replay index. Unknown P values, edges without one unique
    // enforcer-recognized M7,
    // and wrong critical hashes return without any parent RPC. Only the exact
    // indexed commitment is allowed through to full live P/Q authentication.
    const auto admit_untrusted = [&] {
        std::unique_lock<std::mutex> replay_lock(
            g_drivechain_parent_replay_mutex, std::defer_lock);
        const DrivechainParentReplayCache* replay_cache{nullptr};
        std::optional<DrivechainReplayedBmmEdge> indexed;
        DrivechainReplayStoreReadStatus indexed_status{};
        const auto admission = hs::ParentReplayStore(hs::ReplayStoreFlow::BMM_UNTRUSTED_ADMISSION,
            [&](uint32_t step) -> uint32_t {
                switch (step) {
                case 1: return replay_lock.try_lock();
                case 2: return static_cast<uint32_t>(SetError(error, DrivechainBmmStatus::UNAVAILABLE,
                    "authenticated parent replay index is busy warming"));
                case 3: replay_cache = &g_drivechain_parent_replay_cache;
                    return ReplayCacheMatchesConfiguredIdentity(*replay_cache, Params().GetConsensus());
                case 4: return !hs::ParentReplayRecord(hs::ReplayRecordKind::EPOCH_CHANGED, 0, 0, replay_cache->epoch, replay_epoch);
                case 5: return static_cast<uint32_t>(SetError(error, DrivechainBmmStatus::UNAVAILABLE,
                    "authenticated parent replay index changed during admission"));
                case 6: return bool(g_drivechain_parent_replay_store);
                case 7: return static_cast<uint32_t>(SetError(error, DrivechainBmmStatus::UNAVAILABLE,
                    "persistent authenticated parent replay index is not open"));
                case 8: indexed_status = g_drivechain_parent_replay_store->ReadBmmEdge(parent_hash, indexed.emplace(), error); return 1;
                case 9: return indexed_status == DrivechainReplayStoreReadStatus::CORRUPT;
                case 10: case 18: g_drivechain_parent_replay_published_epoch.store(0, std::memory_order_release); return 1;
                case 11: case 19: g_drivechain_parent_replay_cache = {}; return 1;
                case 12: case 20: g_drivechain_parent_replay_store_rebuild_required = true; return 1;
                case 13: return indexed_status == DrivechainReplayStoreReadStatus::NOT_FOUND;
                case 14: return static_cast<uint32_t>(SetError(error, DrivechainBmmStatus::UNAVAILABLE,
                    "committed parent edge is not in the warmed authenticated replay index"));
                case 15: return hs::ParentReplayRecord(hs::ReplayRecordKind::HEIGHT, 0, 0, indexed->successor_height, replay_cache->height);
                case 16: return hs::ParentReplayRecord(hs::ReplayRecordKind::LESS, 0, 0, indexed->parent_height, indexed->successor_height);
                case 21: return static_cast<uint32_t>(SetError(error, DrivechainBmmStatus::UNAVAILABLE,
                    "persistent parent replay BMM edge lies beyond its durable tip"));
                case 22: return indexed->has_canonical_commitment;
                case 23: return indexed->committed_sidechain_hash == expected_critical_hash;
                case 24: return static_cast<uint32_t>(SetError(error, DrivechainBmmStatus::UNAVAILABLE,
                    "candidate does not match the warmed authenticated parent-edge M7 index"));
                default: throw std::logic_error("invalid untrusted BMM admission action");
                }
            });
        return static_cast<DrivechainBmmStatus>(admission);
    };
    decltype(g_drivechain_bmm_negative_parent_cache)::iterator rejected;
    DrivechainBmmStatus selected{DrivechainBmmStatus::UNAVAILABLE};
    if (hs::ParentReplayStore(hs::ReplayStoreFlow::BMM_CACHE_ROUTING, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: it = std::find_if(g_drivechain_bmm_edge_cache.rbegin(), g_drivechain_bmm_edge_cache.rend(), matches_parent); return 1;
        case 2: return it != g_drivechain_bmm_edge_cache.rend();
        case 3: selected = cached_edge(); return static_cast<uint32_t>(selected);
        case 4: case 6: return DrivechainUntrustedParentAdmissionActive();
        case 5: selected = admit_untrusted(); return static_cast<uint32_t>(selected);
        case 7: rejected = std::find_if(g_drivechain_bmm_negative_parent_cache.begin(),
            g_drivechain_bmm_negative_parent_cache.end(), matches_parent); return 1;
        case 8: return rejected != g_drivechain_bmm_negative_parent_cache.end();
        case 9:
            selected = SetError(error, DrivechainBmmStatus::UNAVAILABLE,
                rejected->rejection_reason + "; cached briefly without parent RPC");
            return static_cast<uint32_t>(selected);
        default: throw std::logic_error("invalid BMM cache routing action");
        }
    })) return selected;
    uint32_t probed_parent_height{0};
    const DrivechainParentProbeStatus probe_status = ProbeActiveDrivechainParent(
        parent_hash, probed_parent_height, error);
    std::optional<std::string> rejection_reason;
    const auto probe_result = hs::ParentReplayStore(hs::ReplayStoreFlow::BMM_PROBE_RESULT, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return probe_status == DrivechainParentProbeStatus::UNAVAILABLE;
        case 2: return probe_status == DrivechainParentProbeStatus::REJECTED;
        case 3: rejection_reason.emplace(error ? *error : "committed parent hash is not on the active parent chain"); return 1;
        case 4: case 7: CacheRejectedDrivechainParent(replay_epoch, parent_hash, slot, *rejection_reason); return 1;
        case 5: return hs::ParentReplayRecord(hs::ReplayRecordKind::LESS, 0, 0, probed_parent_height,
            Params().GetConsensus().drivechain_parent_state_height);
        case 6: rejection_reason.emplace(strprintf("committed parent height %u predates the Elements launch checkpoint %u",
            probed_parent_height, Params().GetConsensus().drivechain_parent_state_height)); return 1;
        case 8: return static_cast<uint32_t>(SetError(error, DrivechainBmmStatus::PARENT_REJECTED, *rejection_reason));
        default: throw std::logic_error("invalid BMM probe result action");
        }
    });
    if (probe_result != 0) return static_cast<DrivechainBmmStatus>(probe_result);

    DrivechainParentBlockContext parent_context;
    struct SuccessorData { Bitcoin::CBlock block; VerifiedMainchainHeader header; };
    std::optional<uint256> successor_hash_storage;
    std::optional<SuccessorData> successor_storage;
    std::optional<VerifiedMainchainHeader> parent;
    uint64_t successor_height{0};
    const auto preparation = hs::ParentReplayStore(hs::ReplayStoreFlow::BMM_SUCCESSOR, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return GetDrivechainParentContextForHash(parent_hash, parent_context, error);
        case 2: return hs::ApprovingParentHeight(parent_context.parent_height, successor_height);
        case 3: return static_cast<uint32_t>(SetError(error, DrivechainBmmStatus::UNAVAILABLE,
            "committed parent height has no representable successor"));
        case 4: return ReadActiveMainchainHash(static_cast<uint32_t>(successor_height), successor_hash_storage.emplace(), error);
        case 5:
            successor_storage.emplace();
            return ReadVerifiedMainchainBlock(*successor_hash_storage, 1, successor_storage->block, successor_storage->header, error);
        case 6: return EnsurePinnedDrivechainParentStateThrough(successor_storage->header.height,
            *successor_hash_storage, /* require_elements_active= */ true, error);
        case 7: return hs::ParentReplayRecord(hs::ReplayRecordKind::SUCCESSOR_HEIGHT, 0, 0,
            parent_context.parent_height, successor_storage->header.height);
        case 8: return successor_storage->header.header.hashPrevBlock == parent_hash;
        case 9: return static_cast<uint32_t>(SetError(error, DrivechainBmmStatus::UNAVAILABLE,
            strprintf("active parent block %s is not the exact successor of committed parent %s",
                successor_hash_storage->GetHex(), parent_hash.GetHex())));
        case 10:
            parent.emplace();
            parent->chainwork = parent_context.parent_chainwork;
            parent->height = parent_context.parent_height;
            return 1;
        // Authenticate continuity using the successor's raw nBits.
        case 11: return CheckParentChainworkStep(*parent, successor_storage->header, error);
        default: throw std::logic_error("invalid BMM successor action");
        }
    });
    if (preparation != 0) return static_cast<DrivechainBmmStatus>(preparation);
    const auto& successor_hash = *successor_hash_storage;
    const auto& successor_block = successor_storage->block;
    const auto& successor = successor_storage->header;

    uint256 committed_sidechain_hash;
    std::string commitment_error;
    const bool has_canonical_commitment =
        ExtractCanonicalDrivechainBmmCommitmentInBlock(
            successor_block, sidechain_slot, committed_sidechain_hash,
            nullptr, &commitment_error);

    // The M7 result is deterministic only for this exact active P -> Q edge.
    // Recheck both heights after parsing Q so a racing reorg is never mistaken
    // for either success or a parent rejection.
    uint64_t final_replay_epoch{0};
    return static_cast<DrivechainBmmStatus>(hs::ParentReplayStore(hs::ReplayStoreFlow::BMM_PUBLICATION, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return RecheckActiveBmmEdge(parent_hash, parent_context.parent_height, successor_hash, successor.height, error);
        case 2: static_cast<DrivechainParentBlockContext&>(context) = parent_context; return 1;
        case 3: case 14: return has_canonical_commitment;
        // Publish the observed M7, never the caller's candidate, even on rejection.
        case 4: context.critical_hash = committed_sidechain_hash; return 1;
        case 5: context.critical_hash = uint256{}; return 1;
        case 6:
            context.bmm_block_hash = successor_hash;
            context.bmm_chainwork = successor.chainwork;
            context.bmm_height = successor.height;
            return 1;
        case 7: final_replay_epoch = GetDrivechainParentReplayEpoch(); return 1;
        case 8: return hs::ParentReplayRecord(hs::ReplayRecordKind::POSITIVE, 0, 0, final_replay_epoch, 0);
        case 9: return !hs::ParentReplayRecord(hs::ReplayRecordKind::EPOCH_CHANGED, 0, 0, final_replay_epoch, replay_epoch);
        case 10: return static_cast<uint32_t>(SetError(error, DrivechainBmmStatus::UNAVAILABLE,
            "authenticated parent replay epoch changed during BMM validation"));
        case 11:
            g_drivechain_bmm_edge_cache.push_back(DrivechainBmmEdgeCacheEntry{
                final_replay_epoch, parent_hash, successor_hash, slot, context,
                has_canonical_commitment, committed_sidechain_hash, commitment_error});
            return 1;
        case 12: return hs::ParentReplayRecord(hs::ReplayRecordKind::LESS, 0, 0,
            drivechain::BMM_EDGE_CACHE_MAX, g_drivechain_bmm_edge_cache.size());
        case 13: g_drivechain_bmm_edge_cache.pop_front(); return 1;
        case 15: return static_cast<uint32_t>(SetError(error, DrivechainBmmStatus::PARENT_REJECTED, commitment_error));
        case 16: return committed_sidechain_hash == expected_critical_hash;
        case 17: return static_cast<uint32_t>(SetError(error, DrivechainBmmStatus::PARENT_REJECTED,
            strprintf("BMM successor commits to critical hash %s, expected %s",
                committed_sidechain_hash.GetHex(), expected_critical_hash.GetHex())));
        default: throw std::logic_error("invalid BMM publication action");
        }
    }));
}

} // namespace

bool IsDefinitiveDrivechainBmmWaitError(const std::string& error)
{
    return drivechain::haskell::BmmMessageMatches(drivechain::haskell::BmmMessageKind::DEFINITIVE_WAIT, error);
}

uint64_t GetDrivechainParentReplayEpoch()
{
    return g_drivechain_parent_replay_published_epoch.load(
        std::memory_order_acquire);
}

bool GetDrivechainSuccessfulWithdrawal(
    const int sidechain_slot,
    const uint256& m6id,
    std::optional<DrivechainSuccessfulWithdrawal>& result,
    std::string* error)
{
    return ParentRequest(sidechain_slot, error, [&] { result.reset(); }, [&]() -> bool {
        namespace hs = drivechain::haskell;
        uint32_t target_height{0};
        uint256 target_hash, active_withdrawal_hash, active_cache_hash;
        std::optional<std::lock_guard<std::mutex>> lock;
        auto& cache = g_drivechain_parent_replay_cache;
        std::optional<DrivechainSuccessfulWithdrawal> withdrawal;
        DrivechainReplayStoreReadStatus status{};
        return hs::ParentReplayStore(hs::ReplayStoreFlow::WITHDRAWAL_LOOKUP, [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return ReadActiveMainchainHeight(target_height, error);
            case 2: return ReadActiveMainchainHash(target_height, target_hash, error);
            case 3: lock.emplace(g_drivechain_parent_replay_mutex); return 1;
            case 4: return EnsurePinnedDrivechainParentStateThroughLocked(target_height, target_hash, true, cache, error);
            case 5: return bool(g_drivechain_parent_replay_store);
            case 6: return SetError(error, "persistent authenticated parent replay index is not open");
            case 7:
                withdrawal.emplace();
                status = g_drivechain_parent_replay_store->ReadSuccessfulWithdrawal(
                    static_cast<uint8_t>(sidechain_slot), m6id, *withdrawal, error);
                return 1;
            case 8: return status == DrivechainReplayStoreReadStatus::CORRUPT;
            case 9: case 16: case 29: return status == DrivechainReplayStoreReadStatus::FOUND;
            case 10: return hs::ParentReplayRecord(hs::ReplayRecordKind::LESS, 0, 0, cache.height, withdrawal->block_height);
            case 11: case 19: case 25: g_drivechain_parent_replay_published_epoch.store(0, std::memory_order_release); return 1;
            case 12: case 20: case 26: cache = {}; return 1;
            case 13: case 21: case 27: g_drivechain_parent_replay_store_rebuild_required = true; return 1;
            case 14: return error != nullptr;
            case 15: return error->empty();
            case 17: return ReadActiveMainchainHash(withdrawal->block_height, active_withdrawal_hash, error);
            case 18: return active_withdrawal_hash == withdrawal->block_hash;
            case 22: return SetError(error, "persistent successful-withdrawal record is not on the active parent chain");
            // Recheck the active tip before publishing, including a not-found result.
            case 23: return ReadActiveMainchainHash(cache.height, active_cache_hash, error);
            case 24: return active_cache_hash == cache.hash;
            case 28: return SetError(error, "parent-chain reorganization raced successful-withdrawal lookup");
            case 30: return SetError(error, "persistent authenticated parent replay successful-withdrawal index is inconsistent");
            case 31: result = std::move(*withdrawal); return 1;
            default: throw std::logic_error("invalid successful withdrawal lookup action");
            }
        });
    });
}

bool WarmDrivechainParentState(std::string* error)
{
    if (error) error->clear();
    if (!Params().GetConsensus().drivechain_slot.has_value()) return true;

    return CatchParentError(error, [&]() -> bool {
        namespace hs = drivechain::haskell;
        UniValue height_value, hash_value;
        uint32_t height{0};
        uint256 tip_hash;
        return hs::ParentReplayStore(hs::ReplayStoreFlow::WARM_PARENT, [&](uint32_t action) -> uint32_t {
            switch (action) {
            case 1: height_value = CallMainChainRPCChecked("getblockcount", UniValue(UniValue::VARR)); return 1;
            case 2: return height_value.isNum();
            case 3: return SetError(error, "parent getblockcount returned a non-numeric height");
            case 4: return ParseParentHeightInteger(height_value, height, error);
            case 5: {
                UniValue params(UniValue::VARR);
                params.push_back(static_cast<int64_t>(height));
                hash_value = CallMainChainRPCChecked("getblockhash", params);
                return 1;
            }
            case 6: return ParseDrivechainCanonicalHash(hash_value, tip_hash);
            case 7: return SetError(error, "parent getblockhash returned a noncanonical hash");
            case 8: return EnsurePinnedDrivechainParentStateThrough(height, tip_hash,
                /* require_elements_active= */ false, error);
            default: throw std::logic_error("invalid parent warmup action");
            }
        });
    });
}

bool GetDrivechainExecutionAnchor(const int slot, const uint256& hash,
    const uint32_t minimum_height, const DrivechainParentBlockContext& bid_parent,
    DrivechainParentBlockContext& anchor, std::string* error)
{
    DrivechainParentValidationBudget parent_budget{true};
    return ParentRequest(slot, error, [&] { anchor = {}; }, [&]() -> bool {
        const UniValue no_params(UniValue::VARR);
        uint256 before, after, active_anchor, active_bid;
        namespace hs = drivechain::haskell;
        std::optional<std::pair<DrivechainParentBlockContext, DrivechainParentBlockContext>> checked;
        return hs::ParentReplayStore(hs::ReplayStoreFlow::EXECUTION_ANCHOR, [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return ParseDrivechainCanonicalHash(CallMainChainRPCChecked("getbestblockhash", no_params), before);
            case 2: return SetError(error, "invalid active tip for execution anchor");
            case 3: checked.emplace(); return GetDrivechainParentContextForHash(hash, checked->first, error);
            case 4: return GetDrivechainParentContextForHash(bid_parent.parent_hash, checked->second, error);
            case 5: return hs::ParentReplayRecord(hs::ReplayRecordKind::HEIGHT, 0, 0, minimum_height, checked->first.parent_height);
            case 6: return hs::ParentReplayRecord(hs::ReplayRecordKind::HEIGHT, 0, 0, checked->first.parent_height, checked->second.parent_height);
            case 7: return !hs::ParentReplayRecord(hs::ReplayRecordKind::LESS, 0, 0, checked->second.parent_median_time_past, checked->first.parent_median_time_past);
            case 8: return checked->second.parent_height == bid_parent.parent_height;
            case 9: return checked->second.parent_median_time_past == bid_parent.parent_median_time_past;
            case 10: return SetError(error, "execution anchor outside authenticated parent interval");
            case 11: return ReadActiveMainchainHash(checked->first.parent_height, active_anchor, error);
            case 12: return ReadActiveMainchainHash(checked->second.parent_height, active_bid, error);
            case 13: return active_anchor == hash;
            case 14: return active_bid == bid_parent.parent_hash;
            case 15: return ParseDrivechainCanonicalHash(CallMainChainRPCChecked("getbestblockhash", no_params), after);
            case 16: return before == after;
            case 17: return SetError(error, "execution anchor chain changed or is not active");
            case 18: anchor = checked->first; return 1;
            default: throw std::logic_error("invalid execution anchor action");
            }
        });
    });
}

bool GetDrivechainMempoolParentContext(const int sidechain_slot,
                                      DrivechainParentBlockContext& context,
                                      std::string* error)
{
    DrivechainParentValidationBudget parent_budget{true};
    return ParentRequest(sidechain_slot, error, [&] { context = {}; }, [&]() -> bool {
        const UniValue no_params(UniValue::VARR);
        namespace hs = drivechain::haskell;
        uint256 before, after;
        std::optional<DrivechainParentBlockContext> authenticated;
        return hs::ParentReplayStore(hs::ReplayStoreFlow::MEMPOOL_CONTEXT, [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return ParseDrivechainCanonicalHash(CallMainChainRPCChecked("getbestblockhash", no_params), before);
            case 2: return SetError(error, "parent best-block hash is not canonical");
            case 3: authenticated.emplace(); return GetDrivechainParentContextForHash(before, *authenticated, error);
            case 15: return ParseDrivechainCanonicalHash(CallMainChainRPCChecked("getbestblockhash", no_params), after);
            case 16: return before == after;
            case 17: return SetError(error, "parent tip changed during mempool context authentication");
            case 18: context = *authenticated; return 1;
            default: throw std::logic_error("invalid mempool context action");
            }
        });
    });
}

bool GetDrivechainParentBlockContext(const CBlock& block,
                                     const int sidechain_slot,
                                     DrivechainParentBlockContext& context,
                                     std::string* error)
{
    namespace hs = drivechain::haskell;
    uint256 parent_hash;
    return hs::ParentReplayStore(hs::ReplayStoreFlow::BLOCK_PARENT_CONTEXT, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: context = {}; return 1;
        case 2: return CheckConfiguredDrivechainSlot(sidechain_slot, error);
        case 3: return ExtractDrivechainParentHashFromBlock(block, parent_hash, error);
        case 4:
            try { return GetDrivechainParentContextForHash(parent_hash, context, error); }
            catch (const std::exception& e) { return SetError(error, e.what()); }
        default: throw std::logic_error("invalid block parent context action");
        }
    });
}

bool GetDrivechainParentBlockContext(const CBlock& block,
                                     const int sidechain_slot,
                                     DrivechainBmmBlockContext& context,
                                     std::string* error)
{
    namespace hs = drivechain::haskell;
    std::optional<DrivechainParentBlockContext> parent_context;
    return hs::ParentReplayStore(hs::ReplayStoreFlow::EXTEND_PARENT_CONTEXT, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: context = {}; return 1;
        case 2: parent_context.emplace(); return GetDrivechainParentBlockContext(block, sidechain_slot, *parent_context, error);
        case 3: static_cast<DrivechainParentBlockContext&>(context) = *parent_context; return 1;
        default: throw std::logic_error("invalid extended parent context action");
        }
    });
}

bool GetDrivechainBmmBlockContext(const CBlock& block,
                                  const uint256& expected_critical_hash,
                                  const int sidechain_slot,
                                  DrivechainBmmBlockContext& context,
                                  std::string* error)
{
    const DrivechainBmmStatus status =
        GetDrivechainBmmBlockStatus(
            block, expected_critical_hash, sidechain_slot, context, error);
    namespace hs = drivechain::haskell;
    return hs::ParentReplayStore(hs::ReplayStoreFlow::BMM_CONTEXT_RESULT, [&](uint32_t step) -> uint32_t {
        if (step == 1) return status == DrivechainBmmStatus::VALID;
        if (step == 2) { context = {}; return 1; }
        throw std::logic_error("invalid BMM context result action");
    });
}

DrivechainBmmStatus GetDrivechainBmmBlockStatus(const CBlock& block,
                                                const uint256& expected_critical_hash,
                                                const int sidechain_slot,
                                                DrivechainBmmBlockContext& context,
                                                std::string* error)
{
    namespace hs = drivechain::haskell;
    uint256 parent_hash;
    const auto status = hs::ParentReplayStore(hs::ReplayStoreFlow::BMM_BLOCK_PREFLIGHT, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: context = {}; return 1;
        case 2: return error != nullptr;
        case 3: error->clear(); return 1;
        case 4: return CheckConfiguredDrivechainSlot(sidechain_slot, error);
        case 5: return !expected_critical_hash.IsNull();
        case 6: return static_cast<uint32_t>(SetError(error, DrivechainBmmStatus::INVALID, "BIP301 expected critical hash is null"));
        case 7: return ExtractDrivechainParentHashFromBlock(block, parent_hash, error);
        default: throw std::logic_error("invalid BMM block preflight action");
        }
    });
    if (status != 0) return static_cast<DrivechainBmmStatus>(status);
    try {
        return GetDrivechainBmmContextForHashesStatus(
            expected_critical_hash, parent_hash, sidechain_slot, context, error);
    } catch (const std::exception& e) {
        return SetError(error, DrivechainBmmStatus::UNAVAILABLE, e.what());
    }
}

DrivechainAnchorStatus IsDrivechainAnchorActive(const DrivechainAnchor& anchor,
                                                const int sidechain_slot,
                                                std::string* error)
{
    namespace hs = drivechain::haskell;
    const auto preflight = hs::ParentReplayStore(hs::ReplayStoreFlow::ANCHOR_PREFLIGHT, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return error != nullptr;
        case 2: error->clear(); return 1;
        case 3: return CheckConfiguredDrivechainSlot(sidechain_slot, error);
        case 4: return anchor.IsSane();
        case 5: return static_cast<uint32_t>(SetError(error, DrivechainAnchorStatus::UNAVAILABLE,
                              "persisted drivechain anchor is malformed"));
        default: throw std::logic_error("invalid anchor preflight action");
        }
    });
    if (preflight != 0) return static_cast<DrivechainAnchorStatus>(preflight);

    try {
        uint256 active_parent_hash, active_successor_hash;
        struct AuthenticatedBlocks {
            Bitcoin::CBlock parent_block, successor_block;
            VerifiedMainchainHeader parent, successor;
        };
        std::optional<AuthenticatedBlocks> blocks;
        // Only height/hash mismatches can signal rollback. Authentication
        // failures, including racing reorgs, remain UNAVAILABLE.
        return static_cast<DrivechainAnchorStatus>(hs::ParentReplayStore(
            hs::ReplayStoreFlow::ANCHOR_RECONCILE, [&](uint32_t step) -> uint32_t {
                switch (step) {
                case 1: return ReadActiveMainchainHash(anchor.parent_height, active_parent_hash, error);
                case 2: return active_parent_hash == anchor.parent_block_hash;
                case 3: return static_cast<uint32_t>(SetError(error, DrivechainAnchorStatus::ORPHANED,
                    strprintf("parent height %u now contains %s, persisted anchor contains %s",
                              anchor.parent_height, active_parent_hash.GetHex(), anchor.parent_block_hash.GetHex())));
                case 4: return ReadActiveMainchainHash(anchor.bmm_height, active_successor_hash, error);
                case 5: return active_successor_hash == anchor.bmm_block_hash;
                case 6: return static_cast<uint32_t>(SetError(error, DrivechainAnchorStatus::ORPHANED,
                    strprintf("parent height %u now contains %s, persisted BMM anchor contains %s",
                              anchor.bmm_height, active_successor_hash.GetHex(), anchor.bmm_block_hash.GetHex())));
                case 7:
                    blocks.emplace();
                    return ReadVerifiedMainchainBlock(anchor.parent_block_hash, 1, blocks->parent_block, blocks->parent, error);
                case 8: return ReadVerifiedMainchainBlock(anchor.bmm_block_hash, 1, blocks->successor_block, blocks->successor, error);
                case 9: return EnsurePinnedDrivechainParentStateThrough(
                    blocks->successor.height, anchor.bmm_block_hash, /* require_elements_active= */ true, error);
                case 10: return blocks->parent.height == anchor.parent_height;
                case 11: return blocks->successor.height == anchor.bmm_height;
                case 12: return blocks->successor.header.hashPrevBlock == anchor.parent_block_hash;
                case 13: return blocks->parent.chainwork == anchor.parent_chainwork;
                case 14: return blocks->successor.chainwork == anchor.bmm_chainwork;
                case 15: return blocks->parent.median_time_past == anchor.parent_median_time_past;
                case 16: return CheckParentChainworkStep(blocks->parent, blocks->successor, error);
                case 17: return error != nullptr;
                case 18: return error->empty();
                case 19: *error = "persisted drivechain anchor context disagrees with authenticated parent blocks"; return 1;
                default: throw std::logic_error("invalid anchor reconciliation action");
                }
            }));
    } catch (const std::exception& e) {
        return SetError(error, DrivechainAnchorStatus::UNAVAILABLE, e.what());
    }
}

bool DrivechainAnchorSnapshot::Matches(const int slot, const uint256& parent_tip,
                                       const uint64_t epoch) const
{
    namespace hs = drivechain::haskell;
    return hs::ParentReplayAll<3>({
        [&] { return !m_parent_tip.IsNull(); },
        [&] { return m_parent_tip == parent_tip; },
        [&] { return EpochMatches(slot, epoch); },
    });
}

bool DrivechainAnchorSnapshot::EpochMatches(const int slot, const uint64_t epoch) const
{
    namespace hs = drivechain::haskell;
    return hs::ParentReplayRecord(hs::ReplayRecordKind::ANCHOR_EPOCH, m_slot == slot, m_slot, m_epoch, epoch);
}

bool DrivechainAnchorSnapshot::Add(const DrivechainAnchor& anchor,
                                   const DrivechainAnchorStatus status)
{
    namespace hs = drivechain::haskell;
    std::vector<unsigned char> encoded;
    decltype(m_active_anchors)::iterator found;
    bool inserted{false};
    return hs::ParentReplayStore(hs::ReplayStoreFlow::SNAPSHOT_ADD, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return status == DrivechainAnchorStatus::ACTIVE;
        case 2: return anchor.IsSane();
        case 3: return !m_parent_tip.IsNull();
        case 4: return EpochMatches(m_slot, m_epoch);
        case 5: VectorWriter{encoded, 0} << anchor; return 1;
        case 6: {
            const auto result = m_active_anchors.emplace((HashWriter{} << anchor).GetHash(), encoded);
            found = result.first; inserted = result.second; return 1;
        }
        case 7: return inserted;
        case 8: return found->second == encoded;
        default: throw std::logic_error("invalid snapshot admission action");
        }
    });
}

bool DrivechainAnchorSnapshot::Contains(const DrivechainAnchor& anchor,
                                        const int slot, const uint64_t epoch) const
{
    namespace hs = drivechain::haskell;
    std::vector<unsigned char> encoded;
    decltype(m_active_anchors)::const_iterator found;
    return hs::ParentReplayStore(hs::ReplayStoreFlow::SNAPSHOT_CONTAINS, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return EpochMatches(slot, epoch);
        case 2: return anchor.IsSane();
        case 3: found = m_active_anchors.find((HashWriter{} << anchor).GetHash()); return 1;
        case 4: return found != m_active_anchors.end();
        case 5: VectorWriter{encoded, 0} << anchor; return 1;
        case 6: return found->second == encoded;
        default: throw std::logic_error("invalid snapshot lookup action");
        }
    });
}

namespace {
bool ReadDrivechainAnchorSnapshotTip(uint256& tip, std::string* error)
{
    const UniValue result = CallMainChainRPCChecked("getbestblockhash", UniValue(UniValue::VARR));
    namespace hs = drivechain::haskell;
    return hs::ParentReplayAll<2>({
        [&] { return ParseDrivechainCanonicalHash(result, tip); },
        [&] { return !tip.IsNull(); },
    }) || SetError(error, "parent getbestblockhash returned a noncanonical tip");
}
} // namespace

bool CheckDrivechainAnchorSnapshotEpoch(const DrivechainAnchorSnapshot& snapshot,
                                        const int sidechain_slot, std::string* error)
{
    namespace hs = drivechain::haskell;
    return CatchParentError(error, [&]() -> bool {
        return hs::ParentReplayStore(hs::ReplayStoreFlow::SNAPSHOT_EPOCH_FENCE, [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: CheckDrivechainParentDeadline(); return 1;
            case 2: return snapshot.EpochMatches(sidechain_slot, GetDrivechainParentReplayEpoch());
            case 3: return SetError(error, "authenticated parent generation changed during anchor snapshot use");
            default: throw std::logic_error("invalid snapshot epoch fence action");
            }
        });
    });
}

bool CheckDrivechainAnchorSnapshot(const DrivechainAnchorSnapshot& snapshot,
                                   const int sidechain_slot, std::string* error)
{
    namespace hs = drivechain::haskell;
    if (!hs::ParentReplayAll<2>({
        [&] { return CheckConfiguredDrivechainSlot(sidechain_slot, error); },
        [&] { return CheckDrivechainAnchorSnapshotEpoch(snapshot, sidechain_slot, error); },
    })) return false;
    return CatchParentError(error, [&]() -> bool {
        uint256 tip;
        // Epoch alone is insufficient: the warmer may not yet have observed
        // a reorg. Even benign extension requires a freshly authenticated set.
        return hs::ParentReplayStore(hs::ReplayStoreFlow::SNAPSHOT_TIP_FENCE, [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return ReadDrivechainAnchorSnapshotTip(tip, error);
            case 2: return snapshot.Matches(sidechain_slot, tip, GetDrivechainParentReplayEpoch());
            case 3: return SetError(error, "active parent tip changed during anchor snapshot use");
            case 4: return CheckDrivechainAnchorSnapshotEpoch(snapshot, sidechain_slot, error);
            default: throw std::logic_error("invalid snapshot tip fence action");
            }
        });
    });
}

bool WarmDrivechainAnchorSnapshot(
    const std::vector<DrivechainAnchor>& anchors, const int sidechain_slot,
    const util::SignalInterrupt& interrupt,
    std::shared_ptr<const DrivechainAnchorSnapshot>& result, std::string* error)
{
    namespace hs = drivechain::haskell;
    if (!hs::ParentReplayStore(hs::ReplayStoreFlow::SNAPSHOT_WARM_PREFLIGHT, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: result.reset(); return 1;
        case 2: return error != nullptr;
        case 3: error->clear(); return 1;
        case 4: return DrivechainParentBudgetActive();
        case 5: return g_drivechain_anchor_warm_deadline.has_value();
        case 6: return SetError(error, "bulk anchor authentication cannot run inside a parent validation budget");
        case 7: return bool(interrupt);
        case 8: return SetError(error, "drivechain anchor snapshot authentication interrupted");
        case 9: return CheckConfiguredDrivechainSlot(sidechain_slot, error);
        default: throw std::logic_error("invalid snapshot warming preflight action");
        }
    })) return false;
    struct DeadlineScope {
        explicit DeadlineScope(const util::SignalInterrupt& interrupt) {
            g_drivechain_anchor_warm_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{drivechain::ANCHOR_WARM_DEADLINE_SECONDS};
            g_drivechain_anchor_warm_interrupt = &interrupt;
        }
        ~DeadlineScope() {
            g_drivechain_anchor_warm_deadline.reset();
            g_drivechain_anchor_warm_interrupt = nullptr;
        }
    } deadline_scope{interrupt};
    return CatchParentError(error, [&]() -> bool {
        uint64_t epoch{0};
        uint256 tip;
        std::shared_ptr<DrivechainAnchorSnapshot> snapshot;
        return hs::ParentReplayStore(hs::ReplayStoreFlow::SNAPSHOT_WARM, [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: CheckDrivechainParentDeadline(); return 1;
            case 2: epoch = GetDrivechainParentReplayEpoch(); return 1;
            case 3: return hs::ParentReplayRecord(hs::ReplayRecordKind::POSITIVE, 0, 0, epoch, 0);
            case 4: return SetError(error, "anchor snapshot requires authenticated parent replay");
            case 5: return ReadDrivechainAnchorSnapshotTip(tip, error);
            case 6: snapshot = std::make_shared<DrivechainAnchorSnapshot>(sidechain_slot, tip, epoch); return 1;
            case 7: return hs::ParentReplayEach(anchors, [&](const DrivechainAnchor& anchor) {
                std::optional<std::string> anchor_error;
                return hs::ParentReplayStore(hs::ReplayStoreFlow::SNAPSHOT_WARM_ANCHOR, [&](uint32_t action) -> uint32_t {
                    switch (action) {
                    case 1: CheckDrivechainParentDeadline(); return 1;
                    case 2: return snapshot->EpochMatches(sidechain_slot, GetDrivechainParentReplayEpoch());
                    case 3: return SetError(error, "parent replay changed while authenticating anchor snapshot");
                    case 4: return snapshot->Contains(anchor, sidechain_slot, epoch);
                    case 5: return static_cast<uint32_t>(IsDrivechainAnchorActive(anchor, sidechain_slot, &anchor_error.emplace()));
                    case 6: return snapshot->Add(anchor, DrivechainAnchorStatus::ACTIVE);
                    case 7: return SetError(error, "cannot authenticate complete anchor snapshot: " + *anchor_error);
                    case 8: return SetError(error, "authenticated anchor snapshot contains malformed identity");
                    default: throw std::logic_error("invalid snapshot anchor warming action");
                    }
                });
            });
            case 8: return CheckDrivechainAnchorSnapshot(*snapshot, sidechain_slot, error);
            case 9: result = std::move(snapshot); return 1;
            default: throw std::logic_error("invalid snapshot warming action");
            }
        });
    });
}

CScript CreateDrivechainParentCommitmentScript(const uint256& parent_hash)
{
    const auto& tag = ElementsDrivechainIdentity::PARENT_COMMITMENT_TAG;
    std::vector<unsigned char> payload(tag.begin(), tag.end());
    // The child block has historically serialized its committed Bitcoin hash
    // in uint256's internal byte order.  Freeze that order explicitly here.
    payload.insert(payload.end(), parent_hash.begin(), parent_hash.end());
    return CScript() << OP_RETURN << payload;
}

bool ExtractDrivechainParentHashFromBlock(const CBlock& block, uint256& parent_hash, std::string* error)
{
    parent_hash.SetNull();
    std::string ignored_error;
    using Step = drivechain::haskell::BmmStateStep;
    return drivechain::haskell::RunBmmStateFlow(Step::PARENT_START, [&](Step step) -> int32_t {
        switch (step) {
        case Step::PARENT_COINBASE:
            return drivechain::haskell::ParentReplayAll<3>({
                [&] { return !block.vtx.empty(); },
                [&] { return bool(block.vtx[0]); },
                [&] { return block.vtx[0]->IsCoinBase(); }}) ||
                SetError(error, "block has no coinbase transaction");
        case Step::PARENT_EXTRACT:
            return drivechain::ExtractTaggedParentCommitment(block.vtx[0]->vout, parent_hash, error ? *error : ignored_error);
        default: throw std::logic_error("unexpected parent commitment extraction step");
        }
    });
}

bool IsDrivechainBmmCommitmentMined(const uint256& critical_hash, const uint256& parent_hash, const int sidechain_slot, std::string* error)
{
    namespace hs = drivechain::haskell;
    if (!hs::ParentReplayStore(hs::ReplayStoreFlow::BMM_MINED_PREFLIGHT, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return CheckConfiguredDrivechainSlot(sidechain_slot, error);
        case 2: return !critical_hash.IsNull();
        case 3: return SetError(error, "BIP301 expected critical hash is null");
        default: throw std::logic_error("invalid mined commitment preflight action");
        }
    })) return false;
    return CatchParentError(error, [&]() -> bool {
        DrivechainBmmBlockContext context;
        return GetDrivechainBmmContextForHashesStatus(
                   critical_hash, parent_hash, sidechain_slot,
                   context, error) == DrivechainBmmStatus::VALID;
    });
}

bool IsConfirmedBitcoinBlock(const uint256& hash, const int nMinConfirmationDepth, const int nbTxs)
{
    LogPrintf("Checking for confirmed bitcoin block with hash %s, mindepth %d, nbtxs %d\n", hash.ToString().c_str(), nMinConfirmationDepth, nbTxs);
    try {
        UniValue params(UniValue::VARR);
        params.push_back(hash.GetHex());
        UniValue reply = CallMainChainRPC("getblockheader", params);
        const UniValue& errval = reply.find_value("error");
        if (!errval.isNull()) {
            LogPrintf("WARNING: Got error reply from bitcoind getblockheader: %s\n", errval.write());
            return false;
        }
        const UniValue& result = reply.find_value("result");
        if (!result.isObject()) {
            LogPrintf("ERROR: bitcoind getblockheader result was malformed (not object): %s\n", result.write());
            return false;
        }

        UniValue confirmations = result.get_obj().find_value("confirmations");
        if (!confirmations.isNum() || confirmations.getInt<int64_t>() < nMinConfirmationDepth) {
            LogPrintf("Insufficient confirmations (got %s, need at least %d).\n", confirmations.write(), nMinConfirmationDepth);
            return false;
        }

        // Only perform extra test if nbTxs has been provided (non-zero).
        if (nbTxs != 0) {
            UniValue nTx = result.get_obj().find_value("nTx");
            if (!nTx.isNum() || nTx.getInt<int64_t>() != nbTxs) {
                LogPrintf("ERROR: Invalid number of transactions in merkle block for %s (got %s, need exactly %d)\n",
                        hash.GetHex(), nTx.write(), nbTxs);
                return false;
            }
        }
    } catch (CConnectionFailed&) {
        LogPrintf("WARNING: Lost connection to mainchain daemon RPC; will retry.\n");
        return false;
    } catch (...) {
        LogPrintf("WARNING: Failure connecting to mainchain daemon RPC; will retry.\n");
        return false;
    }
    return true;
}
