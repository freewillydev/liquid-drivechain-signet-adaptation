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
#include <type_traits>
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
std::atomic<uint64_t> g_drivechain_parent_replay_published_epoch{0};
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

bool DrivechainParentBudgetActive()
{
    return g_drivechain_parent_budget.depth != 0;
}

static uint32_t DrivechainParentDeadlineAction(uint32_t step)
{
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
}

void CheckDrivechainParentDeadline()
{
    static_assert(static_cast<uint32_t>(drivechain::haskell::ReplayStoreFlow::PARENT_DEADLINE) == 25);
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::PARENT_DEADLINE,
        DrivechainParentDeadlineAction);
}

struct ParentRpcCredentials {
    bool private_file{false};
    std::string configured_password, credentials, credential_error, cookie;
    std::optional<std::unique_lock<std::mutex>> cache_lock;
    RpcAuthFileReader file;
    int64_t Read(uint32_t action)
    {
        switch (action) {
        case 1: private_file = gArgs.IsArgSet("-mainchainrpccredentialfile"); return private_file;
        case 2: return gArgs.IsArgSet("-mainchainrpccookiefile");
        case 3:
        case 7: return gArgs.IsArgSet("-mainchainrpcuser");
        case 4:
        case 8: return gArgs.IsArgSet("-mainchainrpcpassword");
        case 5: throw std::runtime_error("select exactly one parent RPC authentication mechanism");
        case 6: return Params().GetConsensus().drivechain_slot.has_value();
        case 9: throw std::runtime_error("native parent RPC requires a rotating cookie or an explicit private credential file, not inline credentials");
        case 10: configured_password = gArgs.GetArg("-mainchainrpcpassword", ""); return 1;
        case 11: return !configured_password.empty();
        case 12: credentials = gArgs.GetArg("-mainchainrpcuser", "") + ":" + configured_password; return 1;
        case 20: cache_lock.emplace(g_mainchain_rpc_cookie_mutex, std::defer_lock); return 1;
        case 21: return DrivechainParentBudgetActive();
        case 22: return cache_lock->try_lock();
        case 23: throw CConnectionFailed("mainchain RPC cookie cache is busy refreshing");
        case 24: cache_lock->lock(); return 1;
        case 25: return !g_mainchain_rpc_cached_cookie.empty();
        case 26: credentials = g_mainchain_rpc_cached_cookie; return 1;
        case 27: cache_lock.reset(); return 1;
        // Haskell releases the cache lock before any permitted filesystem work.
        case 41: return DrivechainParentBudgetActive();
        case 42: throw CConnectionFailed("mainchain RPC cookie credentials are not warmed");
        case 43: return private_file;
        case 45: {
            const auto path = fs::PathFromString(gArgs.GetArg("-mainchainrpccredentialfile", ""));
            credentials.clear();
#ifdef WIN32
            credential_error = "private static parent credential files require POSIX file permissions";
            return 0;
#else
            file = MakeRpcAuthFileReader(path, credentials, &credential_error, false);
            return 1;
#endif
        }
        case 46: throw std::runtime_error("cannot load private loopback parent RPC credentials: " + credential_error);
        case 48: throw std::runtime_error("cannot load the parent's private canonical rotating RPC cookie");
        case 49: {
            std::lock_guard<std::mutex> lock(g_mainchain_rpc_cookie_mutex);
            g_mainchain_rpc_cached_cookie = credentials;
            return 1;
        }
        case 80: file = {}; return 1;
        case 81: LogPrintf("Unable to read mainchain RPC authentication cookie: %s\n", credential_error); return 1;
        case 82: credentials = cookie; return 1;
        default: throw std::logic_error("invalid parent RPC credential action");
        }
    }
};

void InvalidateMainchainRPCCookie()
{
    std::lock_guard<std::mutex> lock(g_mainchain_rpc_cookie_mutex);
    g_mainchain_rpc_cached_cookie.clear();
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

// Native resources span the Haskell-controlled preparation and transport phases.
struct ParentRpcAttempt {
    std::string host;
    raii_event_base base;
    raii_evhttp_connection evcon;
    HTTPReply response;
    raii_evhttp_request req;
    ParentRpcCredentials auth;
    std::chrono::microseconds remaining{0};
    int64_t configured{0};
    std::optional<UniValue> parsed;

    void Begin()
    {
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
        this->host = std::move(host);
        this->base = std::move(base);
        this->evcon = std::move(evcon);
    }

    int64_t Timeout(uint32_t action)
    {
        switch (action) {
        case 1: return DrivechainParentBudgetActive();
        case 2:
            remaining = std::chrono::duration_cast<std::chrono::microseconds>(
                g_drivechain_parent_budget.deadline - std::chrono::steady_clock::now());
            return 1;
        case 3:
        case 8: return remaining.count();
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
        case 7:
            remaining = std::chrono::duration_cast<std::chrono::microseconds>(
                *g_drivechain_anchor_warm_deadline - std::chrono::steady_clock::now());
            return 1;
        case 9: throw CConnectionFailed("drivechain anchor snapshot authentication deadline exhausted");
        case 10: configured = gArgs.GetIntArg("-mainchainrpctimeout", DEFAULT_HTTP_CLIENT_TIMEOUT); return 1;
        case 11: return configured;
        case 12: return std::chrono::ceil<std::chrono::seconds>(remaining).count();
        case 13: remaining = std::chrono::seconds{configured}; return 1;
        case 14:
            evhttp_connection_set_timeout(evcon.get(),
                                          gArgs.GetIntArg("-mainchainrpctimeout", DEFAULT_HTTP_CLIENT_TIMEOUT));
            return 1;
        default: throw std::logic_error("invalid parent RPC timeout action");
        }
    }

    void PrepareRequest()
    {
        raii_evhttp_request req = obtain_evhttp_request(http_request_done, (void*)&response);
        if (req == nullptr)
            throw std::runtime_error("create http request failed");
#if LIBEVENT_VERSION_NUMBER >= 0x02010300
        evhttp_request_set_error_cb(req.get(), http_error_cb);
#endif
        this->req = std::move(req);
    }

    void Send(const std::string& strMethod, const UniValue& params, const std::string& endpoint)
    {
        // Cookie files are loaded only by startup/background calls. Locked
        // validation consumes the already-warmed credential cache in memory.
        const std::string& strRPCUserColonPass = auth.credentials;

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
    }

    void ParseReply()
    {
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
        parsed.emplace(std::move(valReply));
    }

    UniValue Finish()
    {
        const UniValue& valReply = parsed.value();
        const UniValue& reply = valReply.get_obj();
        if (reply.empty())
            throw std::runtime_error("expected reply to have result, error and id properties");

        return reply;
    }
};

static int64_t ReadCheckedRpcReply(uint32_t action, const std::string& method,
    const UniValue& reply, bool require_result, const UniValue*& result)
{
    switch (action) {
    case 1: return reply["error"].isNull();
    case 2: throw std::runtime_error(strprintf("%s returned error: %s", method, reply["error"].write()));
    case 3: result = &reply["result"]; return require_result && result->isNull();
    case 4: throw std::runtime_error(strprintf("%s returned no result", method));
    default: throw std::logic_error("invalid checked RPC reply action");
    }
}

struct ParentRpcTransport {
    const std::string& strMethod;
    const UniValue& params;
    const std::string& endpoint;
    UniValue reply;
    const UniValue* result{&reply};
    std::exception_ptr failure;
    std::unique_ptr<ParentRpcAttempt> attempt;
    ParentRpcTransport(const std::string& method, const UniValue& arguments, const std::string& path)
        : strMethod(method), params(arguments), endpoint(path) {}

    int64_t Read(uint32_t step)
    {
        if (step > 200 && step < 210) return DrivechainParentDeadlineAction(step - 200);
        if (step > 300 && step < 315) return attempt->Timeout(step - 300);
        if (step > 400 && step < 483) return attempt->auth.Read(step - 400);
        switch (step) {
        case 1: return DrivechainParentBudgetActive();
        case 2: return ParentSteadyClockTicks() < g_drivechain_parent_rpc_unavailable_until.load(std::memory_order_relaxed);
        case 3: throw CConnectionFailed("drivechain parent RPC is in fail-fast backoff after an availability failure");
        case 11: attempt.reset(); return 1;
        case 12: MarkDrivechainParentRpcUnavailable(); return 1;
        case 13:
            if (!failure) throw std::logic_error("missing parent RPC failure");
            std::rethrow_exception(failure);
        case 21: return gArgs.GetArg("-mainchainrpcpassword", "").empty();
        case 22: InvalidateMainchainRPCCookie(); return 1;
        case 23: return DrivechainParentBudgetActive();
        case 31:
        case 32:
        case 33:
        case 34:
            return ReadCheckedRpcReply(step - 30, strMethod, reply, true, result);
        case 100:
            attempt = std::make_unique<ParentRpcAttempt>();
            attempt->Begin();
            return 1;
        case 101: attempt->PrepareRequest(); return 1;
        case 102: attempt->Send(strMethod, params, endpoint); return 1;
        case 103: attempt->ParseReply(); return 1;
        case 104:
            reply = attempt->Finish();
            attempt.reset();
            return 1;
        case 105: MarkDrivechainParentRpcAvailable(); return 1;
        default: throw std::logic_error("invalid parent RPC call action");
        }
    }
    std::vector<unsigned char> operator()(uint32_t step, uint64_t index, std::span<const unsigned char> input)
    {
        const bool file_effect = step >= 500 && step <= 560;
        if (!file_effect && (index != 0 || (step != 447 && !input.empty()))) throw std::logic_error("invalid parent RPC transport effect");
        // Only attempt effects have the original authentication/catch-all recovery.
        if (step < 100) {
            std::vector<unsigned char> bytes(8);
            WriteLE64(bytes.data(), static_cast<uint64_t>(Read(step)));
            return bytes;
        }
        try {
            if (step == 444) {
                auto bytes = ParentRpcHostSnapshot(gArgs.GetArg("-mainchainrpchost", DEFAULT_RPCCONNECT));
                bytes.insert(bytes.begin(), 1);
                return bytes;
            }
            if (step == 483) {
                const auto chain = gArgs.GetChainName();
                std::vector<unsigned char> bytes{1};
                bytes.insert(bytes.end(), chain.begin(), chain.end());
                return bytes;
            }
            if (step == 447) {
                const std::string cookie_file(input.begin(), input.end());
                if (cookie_file != ".cookie" && cookie_file != "regtest/.cookie")
                    throw std::logic_error("invalid parent RPC cookie default");
                if (!attempt) throw std::logic_error("missing parent RPC attempt");
                auto& auth = attempt->auth;
                auth.file = MakeRpcAuthFileReader(GetMainchainAuthCookieFile(cookie_file), auth.cookie, &auth.credential_error, true);
                std::vector<unsigned char> bytes(9, 1);
                WriteLE64(bytes.data() + 1, 1);
                return bytes;
            }
            if (file_effect) {
                if (!attempt || !attempt->auth.file) throw std::logic_error("parent RPC credential file is not open");
                auto bytes = attempt->auth.file(step - 500, index, input);
                bytes.insert(bytes.begin(), 1);
                return bytes;
            }
            std::vector<unsigned char> bytes(9, 1);
            WriteLE64(bytes.data() + 1, static_cast<uint64_t>(Read(step)));
            return bytes;
        } catch (const MainchainRPCAuthFailure&) {
            failure = std::current_exception();
            return std::vector<unsigned char>{2};
        } catch (...) {
            failure = std::current_exception();
            return std::vector<unsigned char>{0};
        }
    }
    UniValue Result(bool checked) const
    {
        if (checked) return *result;
        return reply;
    }
};

// Own request arguments and result consumers across the synchronous Haskell
// workflow. Consumers only publish JSON and construct borrowed native adapters.
struct ParentHeaderRpc {
    const std::function<UniValue(const std::string&, const UniValue&)>* hook;
    bool checked{true};
    std::string method{};
    UniValue params{};
    const std::string endpoint{"/"};
    std::function<void(UniValue)> consume{};
    std::unique_ptr<ParentRpcTransport> transport{};

    uint64_t Prepare(std::string name, UniValue arguments, std::function<void(UniValue)> publish)
    {
        if (transport) throw std::logic_error("parent header RPC request is still pending");
        if (hook) {
            publish((*hook)(name, arguments));
            return 1;
        }
        method = std::move(name);
        params = std::move(arguments);
        consume = std::move(publish);
        transport = std::make_unique<ParentRpcTransport>(method, params, endpoint);
        return 2;
    }

    template <typename Reader>
    std::vector<unsigned char> Read(uint32_t step, uint64_t index, std::span<const unsigned char> input, const Reader& read)
    {
        if (step >= 1000) {
            if (step > 1560 || !transport) throw std::logic_error("invalid parent header RPC transport action");
            return (*transport)(step-1000, index, input);
        }
        if (!input.empty() || ((step == 600 || step == 609) && index))
            throw std::logic_error("invalid parent header RPC action");
        uint64_t result;
        if (step == 600) {
            if (!transport || !consume) throw std::logic_error("missing parent header RPC result");
            consume(transport->Result(checked));
            transport.reset();
            consume = {};
            result = 1;
        } else if (step == 609) {
            throw std::runtime_error("Haskell replay store workflow failed");
        } else {
            result = read(step, index);
        }
        std::vector<unsigned char> bytes(8);
        WriteLE64(bytes.data(), result);
        return bytes;
    }
};

static UniValue CallMainChainRPCAt(const std::string& strMethod, const UniValue& params,
    const std::string& endpoint, bool checked = false)
{
    namespace hs = drivechain::haskell;
    ParentRpcTransport native{strMethod, params, endpoint};
    hs::RunReplayStore(checked ? hs::ReplayStoreWorkflow::RPC_TRANSPORT_CHECKED : hs::ReplayStoreWorkflow::RPC_TRANSPORT, std::ref(native));
    return native.Result(checked);
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
    hs::ParentReplayStore(hs::ReplayStoreFlow::RPC_REPLY, [&](uint32_t action) -> int64_t {
        return ReadCheckedRpcReply(action,method,reply,require_result,result);
    });
    return *result;
}

UniValue CallMainChainRPCChecked(const std::string& method, const UniValue& params)
{
    return CallMainChainRPCAt(method,params,"/",true);
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

namespace {
uint64_t ReadCanonicalHash(const UniValue& value, uint256& hash, uint32_t step)
{
    switch (step) {
    case 41: return value.isStr();
    case 42: return value.get_str().size();
    case 43: return IsHex(value.get_str());
    case 44: hash = uint256S(value.get_str()); return 1;
    case 45: return value.get_str() == hash.GetHex();
    default: throw std::logic_error("invalid canonical hash native action");
    }
}
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

namespace {

// These adapters retain upstream codecs/arithmetic and borrowed native objects.
// Haskell owns validation order, short circuiting and ancestor traversal.
struct ParentWorkNative {
    const uint256& hash;
    uint32_t bits;
    std::string* error;
    const uint256* parent{nullptr};
    const uint256* successor{nullptr};
    bool negative{false}, overflow{false};
    arith_uint256 target{}, proof{};

    uint64_t Read(uint32_t step, uint64_t index)
    {
        switch (step) {
        case 1: target.SetCompact(bits, &negative, &overflow); return 1;
        case 2: return negative;
        case 3: return target == 0;
        case 4: return overflow;
        case 5: return target > UintToArith256(Params().GetConsensus().parentChainPowLimit);
        case 6: return UintToArith256(hash) > target;
        case 7: proof = (~target / (target + 1)) + 1; return 1;
        case 8: proof = 0; return 1;
        case 9: return proof == 0;
        case 10: return UintToArith256(*successor) == UintToArith256(*parent) + proof;
        case 40:
            switch (index) {
            case 1: return SetError(error, "parent header has an invalid proof-of-work target");
            case 2: return SetError(error, "parent header does not satisfy its proof-of-work target");
            case 3: return SetError(error, "parent RPC chainwork does not match the authenticated successor header");
            }
        }
        throw std::logic_error("invalid parent work native action");
    }
};

struct CanonicalHashNative {
    const UniValue& value;
    uint256& hash;
    uint64_t Read(uint32_t step, uint64_t) { return ReadCanonicalHash(value,hash,step); }
};

template <typename Object>
struct RawParentNative {
    const UniValue& raw;
    const uint256& hash;
    Object& object;
    std::string* error;
    const std::function<void()>& deadline;
    const std::function<uint32_t(uint32_t)>* deadline_action{nullptr};
    ParentWorkNative work{hash, 0, error};
    static constexpr bool BLOCK = std::is_same_v<Object, Bitcoin::CBlock>;

    uint64_t Read(uint32_t step, uint64_t index)
    {
        switch (step) {
        case 20: return raw.isStr();
        case 21: return IsHex(raw.get_str());
        case 22: deadline(); return 1;
        case 23:
            try {
                DataStream stream{ParseHex(raw.get_str())};
                if constexpr (BLOCK) stream >> TX_WITH_WITNESS(object);
                else stream >> object;
                if (!stream.empty()) return SetError(error, BLOCK ? "raw parent block has trailing bytes" : "raw parent header has trailing bytes");
                work.bits = object.nBits;
                return 1;
            } catch (const std::exception& e) {
                return SetError(error, strprintf("%s%s", BLOCK ? "cannot decode raw parent block: " : "cannot decode raw parent header: ", e.what()));
            }
        case 24: return object.GetHash() == hash;
        case 36:
            if (!deadline_action) throw std::logic_error("missing raw parent deadline action");
            return (*deadline_action)(index);
        case 40:
            if (index == 4) return SetError(error, BLOCK ? "getblock returned non-hex raw block data" : "getblockheader returned non-hex raw header data");
            if (index == 5) return SetError(error, BLOCK ? std::string{"raw parent block header does not match its requested hash"} :
                strprintf("raw parent header hashes to %s, expected %s", object.GetHash().GetHex(), hash.GetHex()));
        }
        return work.Read(step,index);
    }
};

template <typename Native>
bool RunParentHeaderNative(drivechain::haskell::ParentHeaderWorkflow kind, Native& native)
{
    return drivechain::haskell::RunParentHeader(kind, 0,
        [&](uint32_t step, uint64_t index) { return native.Read(step,index); });
}

} // namespace

bool ParseDrivechainCanonicalHash(const UniValue& value, uint256& hash)
{
    CanonicalHashNative native{value,hash};
    return RunParentHeaderNative(drivechain::haskell::ParentHeaderWorkflow::HASH,native);
}

bool CheckDrivechainParentProofOfWork(const uint256& hash, const uint32_t n_bits, std::string* error)
{
    ParentWorkNative native{hash,n_bits,error};
    return RunParentHeaderNative(drivechain::haskell::ParentHeaderWorkflow::POW,native);
}

arith_uint256 GetDrivechainParentBlockProof(const uint32_t n_bits)
{
    const uint256 unused;
    ParentWorkNative native{unused,n_bits,nullptr};
    RunParentHeaderNative(drivechain::haskell::ParentHeaderWorkflow::WORK,native);
    return native.proof;
}

bool CheckDrivechainParentChainwork(const uint256& parent_work, const uint256& successor_work,
    uint32_t successor_bits, std::string* error)
{
    ParentWorkNative native{successor_work,successor_bits,error,&parent_work,&successor_work};
    return RunParentHeaderNative(drivechain::haskell::ParentHeaderWorkflow::CHAINWORK,native);
}

bool DecodeDrivechainRawParentHeader(const UniValue& raw, const uint256& hash,
    Bitcoin::CBlockHeader& header, std::string* error)
{
    const std::function<void()> deadline;
    const std::function<uint32_t(uint32_t)> action = DrivechainParentDeadlineAction;
    RawParentNative<Bitcoin::CBlockHeader> native{raw,hash,header,error,deadline,&action};
    return RunParentHeaderNative(drivechain::haskell::ParentHeaderWorkflow::RAW_DEADLINE,native);
}

bool DecodeDrivechainRawParentBlock(const UniValue& raw, const uint256& hash,
    Bitcoin::CBlock& block, std::string* error, const std::function<void()>& deadline,
    const std::function<uint32_t(uint32_t)>& deadline_action)
{
    namespace hs = drivechain::haskell;
    RawParentNative<Bitcoin::CBlock> native{raw,hash,block,error,deadline,deadline_action ? &deadline_action : nullptr};
    return RunParentHeaderNative(deadline_action ? hs::ParentHeaderWorkflow::RAW_DEADLINE : hs::ParentHeaderWorkflow::RAW,native);
}

namespace {

bool CheckParentChainworkStep(const VerifiedMainchainHeader& parent,
                              const VerifiedMainchainHeader& successor,
                              std::string* error)
{
    return CheckDrivechainParentChainwork(parent.chainwork, successor.chainwork, successor.header.nBits, error);
}

struct ParentMedianNative {
    const uint256& start_hash;
    uint64_t& median_time_past;
    const std::function<bool(const uint256&, Bitcoin::CBlockHeader&)>& read_header;
    ParentHeaderRpc* request;
    const std::function<void()>& deadline;
    std::string* error;
    const std::function<uint32_t(uint32_t)>* deadline_action{nullptr};
    uint256 expected_hash{};
    std::optional<Bitcoin::CBlockHeader> header{};
    std::optional<UniValue> raw{};
    std::optional<RawParentNative<Bitcoin::CBlockHeader>> authenticated{};

    uint64_t Read(uint32_t step, uint64_t index)
    {
        switch (step) {
        case 30: expected_hash = start_hash; return 1;
        case 31: deadline(); return 1;
        case 32: {
            header.emplace();
            if (!request) return read_header(expected_hash,*header);
            UniValue params{UniValue::VARR};
            params.push_back(expected_hash.GetHex());
            params.push_back(false);
            return request->Prepare("getblockheader", std::move(params), [this](UniValue result) {
                raw.emplace(std::move(result));
                authenticated.emplace(RawParentNative<Bitcoin::CBlockHeader>{*raw,expected_hash,*header,error,deadline,deadline_action});
            });
        }
        case 33: return header->nTime;
        case 34: expected_hash = header->hashPrevBlock; authenticated.reset(); raw.reset(); header.reset(); return 1;
        case 35: median_time_past = index; return 1;
        case 36:
            if (!deadline_action) throw std::logic_error("missing parent median deadline action");
            return (*deadline_action)(index);
        default: return authenticated->Read(step,index);
        }
    }
};

bool RunParentMedian(const uint256& start_hash, const uint32_t start_height, uint64_t& median_time_past,
    const std::function<bool(const uint256&, Bitcoin::CBlockHeader&)>& read_header,
    const std::function<UniValue(const std::string&, const UniValue&)>* request,
    const std::function<void()>& deadline, std::string* error,
    const std::function<uint32_t(uint32_t)>* deadline_action = nullptr)
{
    namespace hs = drivechain::haskell;
    ParentHeaderRpc rpc{request};
    ParentMedianNative native{start_hash,median_time_past,read_header,request ? &rpc : nullptr,deadline,error,deadline_action};
    return hs::RunParentHeader(request ? (deadline_action ? hs::ParentHeaderWorkflow::RPC_MEDIAN_DEADLINE :
        hs::ParentHeaderWorkflow::RPC_MEDIAN) : hs::ParentHeaderWorkflow::MEDIAN,
        start_height,[&](uint32_t step,uint64_t index,std::span<const unsigned char> input) {
            return rpc.Read(step,index,input,[&](uint32_t action,uint64_t argument) { return native.Read(action,argument); });
        });
}

} // namespace

bool ComputeDrivechainParentMedianTimePast(const uint256& start_hash, const uint32_t start_height,
    uint64_t& median_time_past,
    const std::function<bool(const uint256&, Bitcoin::CBlockHeader&)>& read_header,
    const std::function<void()>& check_deadline)
{
    return RunParentMedian(start_hash,start_height,median_time_past,read_header,nullptr,check_deadline,nullptr);
}

bool ComputeDrivechainRpcMedianTimePast(const uint256& start_hash, const uint32_t start_height,
    uint64_t& median_time_past, std::string* error,
    const std::function<UniValue(const std::string&, const UniValue&)>& request,
    const std::function<void()>& check_deadline,
    const std::function<uint32_t(uint32_t)>& deadline_action)
{
    return RunParentMedian(start_hash,start_height,median_time_past,{},&request,check_deadline,error,
        deadline_action ? &deadline_action : nullptr);
}

namespace {
struct ParentMetadataNative {
    const UniValue& metadata;
    const uint256& expected_hash;
    int min_confirmations;
    uint256& parsed_chainwork;
    int64_t& parsed_height;
    int64_t& parsed_confirmations;
    std::string* error;
    uint256 returned_hash{};
    const UniValue *height{nullptr}, *confirmations{nullptr}, *chainwork{nullptr};

    uint64_t Read(uint32_t step, uint64_t index)
    {
        if (step >= 41 && step <= 45) {
            if (index == 0) return ReadCanonicalHash(metadata.get_obj()["hash"],returned_hash,step);
            if (index == 1) return ReadCanonicalHash(*chainwork,parsed_chainwork,step);
        }
        switch (step) {
        case 50: return metadata.isObject();
        case 51: return returned_hash == expected_hash;
        case 52:
            height = &metadata.get_obj()["height"];
            confirmations = &metadata.get_obj()["confirmations"];
            chainwork = &metadata.get_obj()["chainwork"];
            return 1;
        case 53: return height->isNum();
        case 54: return confirmations->isNum();
        case 55: parsed_height = height->getInt<int64_t>(); return static_cast<uint64_t>(parsed_height);
        case 56: parsed_confirmations = confirmations->getInt<int64_t>(); return static_cast<uint64_t>(parsed_confirmations);
        case 57: return static_cast<uint64_t>(int64_t{min_confirmations});
        case 40:
            switch (index) {
            case 6: return SetError(error,"getblockheader result is not an object");
            case 7: return SetError(error,"getblockheader hash does not match requested parent block");
            case 8: return SetError(error,"getblockheader is missing canonical height, confirmations, or chainwork");
            case 9: return SetError(error,strprintf("parent block has %d confirmations; %d required",parsed_confirmations,min_confirmations));
            }
        }
        throw std::logic_error("invalid parent metadata native action");
    }
};

struct ParentPredecessorNative {
    const UniValue& previous;
    int64_t parsed_height;
    const Bitcoin::CBlockHeader& raw_header;
    const uint256& parsed_chainwork;
    std::string* error;
    ParentHeaderRpc& request;
    uint256 previous_hash{}, returned_previous_hash{}, previous_chainwork{};
    std::optional<UniValue> metadata{};
    const UniValue* height{nullptr};
    ParentWorkNative work{parsed_chainwork,raw_header.nBits,error,&previous_chainwork,&parsed_chainwork};

    uint64_t Read(uint32_t step, uint64_t index)
    {
        if (step >= 41 && step <= 45) {
            if (index == 2) return ReadCanonicalHash(previous,previous_hash,step);
            if (index == 3) return ReadCanonicalHash(metadata->get_obj()["hash"],returned_previous_hash,step);
            if (index == 4) return ReadCanonicalHash(metadata->get_obj()["chainwork"],previous_chainwork,step);
        }
        switch (step) {
        case 60: return static_cast<uint64_t>(parsed_height);
        case 61: return previous.isNull();
        case 62: return raw_header.hashPrevBlock.IsNull();
        case 63: return UintToArith256(parsed_chainwork) == work.proof;
        case 64: return previous_hash == raw_header.hashPrevBlock;
        case 65: {
            UniValue params{UniValue::VARR};
            params.push_back(previous_hash.GetHex());
            params.push_back(true);
            return request.Prepare("getblockheader", std::move(params), [this](UniValue result) {
                metadata.emplace(std::move(result));
            });
        }
        case 66: return metadata->isObject();
        case 67: height = &metadata->get_obj()["height"]; return 1;
        case 68: return returned_previous_hash == previous_hash;
        case 69: return height->isNum();
        case 70: return static_cast<uint64_t>(height->getInt<int64_t>());
        case 40:
            switch (index) {
            case 10: return SetError(error,"parent genesis unexpectedly has a predecessor");
            case 11: return SetError(error,"parent genesis chainwork does not match its authenticated header");
            case 12: return SetError(error,"verbose and raw parent headers disagree about previous block");
            case 13: return SetError(error,"previous getblockheader result is not an object");
            case 14: return SetError(error,"previous parent metadata is not canonical or contiguous");
            case 15: return SetError(error,"parent chainwork does not match its authenticated header and predecessor");
            }
        }
        return work.Read(step,index);
    }
};
} // namespace

bool ParseDrivechainParentHeaderMetadata(const UniValue& metadata, const uint256& expected_hash,
    int min_confirmations, uint256& parsed_chainwork, int64_t& parsed_height,
    int64_t& parsed_confirmations, std::string* error)
{
    ParentMetadataNative native{metadata,expected_hash,min_confirmations,parsed_chainwork,parsed_height,parsed_confirmations,error};
    return RunParentHeaderNative(drivechain::haskell::ParentHeaderWorkflow::METADATA,native);
}

bool CheckDrivechainParentPredecessor(const UniValue& previous, int64_t parsed_height,
    const Bitcoin::CBlockHeader& raw_header, const uint256& parsed_chainwork, std::string* error,
    const std::function<UniValue(const std::string&, const UniValue&)>& request)
{
    ParentHeaderRpc rpc{&request};
    ParentPredecessorNative native{previous,parsed_height,raw_header,parsed_chainwork,error,rpc};
    return RunParentHeaderNative(drivechain::haskell::ParentHeaderWorkflow::PREDECESSOR,native);
}

namespace {
// JSON and transport ownership only; Haskell sequences every request, deadline,
// recovery decision and authentication step.
struct ParentBodyRecoveryNative {
    const std::string hash;
    bool allow_recovery;
    const std::function<void()>& check;
    const std::function<void()>& wait;
    const std::function<uint32_t(uint32_t)>* deadline_action;
    UniValue auxiliary, header, active, peers;
    std::string method;
    UniValue block_params{UniValue::VARR};
    std::vector<UniValue>::const_iterator peer,service;
    UniValue reply;
    std::chrono::steady_clock::time_point deadline;
    int height{0};
    ParentHeaderRpc rpc;

    ParentBodyRecoveryNative(std::string expected, bool recover,
        const std::function<UniValue(const std::string&,const UniValue&)>* request,
        const std::function<void()>& check_deadline, const std::function<void()>& wait_retry,
        const std::function<uint32_t(uint32_t)>* action)
        : hash(std::move(expected)), allow_recovery(recover), check(check_deadline),
          wait(wait_retry), deadline_action(action), rpc{request,false}
    {
        block_params.push_back(hash);
        block_params.push_back(0);
    }
    ParentBodyRecoveryNative(const ParentBodyRecoveryNative&) = delete;
    ParentBodyRecoveryNative& operator=(const ParentBodyRecoveryNative&) = delete;

    uint64_t Request(const std::string& name, const UniValue& params)
    {
        return rpc.Prepare(name,params,[this,name](UniValue value) {
            auxiliary = std::move(value);
            method = name;
        });
    }
    uint64_t Read(uint32_t step, uint64_t index)
    {
        switch (step) {
        case 1: case 14: return rpc.Prepare("getblock",block_params,[this](UniValue value) { reply=std::move(value); });
        case 3: case 17: return reply["error"].isNull();
        case 4: case 18: return !reply["result"].isNull();
        case 5: throw std::runtime_error("getblock failed: "+reply["error"].write());
        case 6: return allow_recovery;
        case 7: throw std::runtime_error("pruned parent block requires recovery outside consensus locks");
        case 8: deadline=std::chrono::steady_clock::now()+std::chrono::seconds{drivechain::PARENT_RECOVERY_SECONDS}; return 1;
        case 12: return std::chrono::steady_clock::now()>=deadline;
        case 13: throw std::runtime_error("parent block recovery timed out");
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
            return Request("getblockheader",params);
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
            params.push_back(height); return Request("getblockhash",params);
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
        case 400: return Request("getpeerinfo",UniValue(UniValue::VARR));
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
            return Request("getblockfrompeer",params);
        }
        case 412: return peers.isArray();
        case 413: throw std::runtime_error("invalid parent peer response");
        case 414: peer=peers.getValues().begin(); return 1;
        case 415: peers=auxiliary["result"]; auxiliary.setNull(); return 1;
        case 417: auxiliary.setNull(); peers.setNull(); return 1;
        case 36:
            if (!deadline_action) throw std::logic_error("missing recovery deadline action");
            return (*deadline_action)(index);
        case 450: check(); return 1;
        case 460: return deadline_action != nullptr;
        default: throw std::logic_error("invalid parent recovery body action");
        }
    }
    std::vector<unsigned char> operator()(uint32_t step,uint64_t index,std::span<const unsigned char> input)
    {
        if (step < 1000 && step != 36 && index) throw std::logic_error("invalid recovery action index");
        return rpc.Read(step,index,input,[this](uint32_t action,uint64_t at) { return Read(action,at); });
    }
};

struct ParentBlockNative {
    const Bitcoin::CBlock& block;
    std::string* error;
    const std::function<void()>& deadline;
    const std::function<const std::vector<uint8_t>&()>* read_challenge{nullptr};
    const std::function<const uint256&()>* genesis{nullptr};
    bool mutated{false};
    uint256 merkle{};
    std::optional<std::vector<uint256>> hashes{};
    const std::vector<uint8_t>* bytes{nullptr};
    std::optional<CScript> challenge{};
    drivechain::haskell::NativeWorkflow signet{};

    uint64_t Read(uint32_t step, uint64_t index)
    {
        switch (step) {
        case 100: return block.vtx.size();
        case 101: return bool(block.vtx.at(index));
        case 102: return block.vtx.at(index)->IsCoinBase();
        case 103: mutated = false; hashes.emplace(); hashes->reserve(block.vtx.size()); return 1;
        case 104: hashes->push_back(block.vtx.at(index)->GetHash()); return 1;
        case 105: merkle = ComputeMerkleRoot(std::move(*hashes), &mutated); return 1;
        case 106: return merkle != block.hashMerkleRoot;
        case 107: return mutated;
        case 108: deadline(); return 1;
        case 109: bytes = &(*read_challenge)(); return 1;
        case 110: return bytes->empty();
        case 111: challenge.emplace(bytes->begin(), bytes->end()); return 1;
        case 112: signet = drivechain::haskell::PrepareParentSignet(block, *challenge, (*genesis)(), error); return 2;
        case 113: signet = {}; return 1;
        case 140:
            switch (index) {
            case 0: return SetError(error, "raw parent block has no coinbase transaction");
            case 1: return SetError(error, "raw parent block has a null transaction or multiple coinbases");
            case 2: return SetError(error, "raw parent block has an invalid or mutated transaction Merkle tree");
            }
        }
        throw std::logic_error("invalid parent block native action");
    }

    std::vector<unsigned char> ReadBytes(uint32_t step, uint64_t index, std::span<const unsigned char> input)
    {
        if (step >= 2000) {
            // A thrown callback poisons later calls, including Haskell's release action.
            try { return signet(step-2000,index,input); }
            catch (...) { signet = {}; throw; }
        }
        if (!input.empty()) throw std::logic_error("invalid parent block workflow input");
        std::vector<unsigned char> result(8);
        WriteLE64(result.data(),Read(step,index));
        return result;
    }
};
} // namespace

bool CheckDrivechainParentBlockTransactions(const Bitcoin::CBlock& block,
    std::string* error, const std::function<void()>& deadline)
{
    ParentBlockNative native{block,error,deadline};
    return RunParentHeaderNative(drivechain::haskell::ParentHeaderWorkflow::BLOCK_TRANSACTIONS,native);
}


bool CheckDrivechainParentBlockSignet(const Bitcoin::CBlock& block, std::string* error,
    const std::function<const std::vector<uint8_t>&()>& read_challenge,
    const std::function<const uint256&()>& genesis, const std::function<void()>& deadline)
{
    ParentBlockNative native{block,error,deadline,&read_challenge,&genesis};
    return drivechain::haskell::RunParentHeader(drivechain::haskell::ParentHeaderWorkflow::BLOCK_SIGNET,0,
        [&](uint32_t step,uint64_t index,std::span<const unsigned char> input) { return native.ReadBytes(step,index,input); });
}

bool AuthenticateDrivechainRawParentBlock(const UniValue& raw, const uint256& hash,
    Bitcoin::CBlock& block, std::string* error,
    const std::function<const std::vector<uint8_t>&()>& challenge,
    const std::function<const uint256&()>& genesis, const std::function<void()>& deadline,
    const std::function<uint32_t(uint32_t)>& deadline_action)
{
    namespace hs = drivechain::haskell;
    RawParentNative<Bitcoin::CBlock> decoder{raw,hash,block,error,deadline,deadline_action ? &deadline_action : nullptr};
    ParentBlockNative body{block,error,deadline,&challenge,&genesis};
    return hs::RunParentHeader(deadline_action ? hs::ParentHeaderWorkflow::BLOCK_DEADLINE : hs::ParentHeaderWorkflow::BLOCK,
        0,[&](uint32_t step,uint64_t index,std::span<const unsigned char> input) {
            if (step >= 100) return body.ReadBytes(step,index,input);
            if (!input.empty()) throw std::logic_error("invalid raw parent block workflow input");
            std::vector<unsigned char> result(8);
            WriteLE64(result.data(),decoder.Read(step,index));
            return result;
        });
}


namespace {

// Stable native ownership shared by standalone and composed header workflows.
struct ParentHeaderNative {
    const uint256& expected_hash;
    int min_confirmations;
    VerifiedMainchainHeader& verified;
    std::string* error;
    const DrivechainParentHeaderSource& source;
    bool authenticate_rpc;
    std::optional<UniValue> genesis, metadata, active_result, raw;
    uint256 rpc_genesis, parsed_chainwork, active_hash;
    int64_t parsed_height{0}, parsed_confirmations{0};
    std::optional<Bitcoin::CBlockHeader> raw_header;
    uint64_t median_time_past{0};
    std::optional<ParentMetadataNative> metadata_native;
    std::optional<ParentPredecessorNative> predecessor_native;
    std::optional<RawParentNative<Bitcoin::CBlockHeader>> raw_native;
    std::optional<ParentMedianNative> median_native;
    ParentHeaderRpc rpc{source.native_rpc ? nullptr : &source.request};
    const std::function<bool(const uint256&, Bitcoin::CBlockHeader&)> unused_reader;
    const std::function<uint32_t(uint32_t)>* deadline_action = source.deadline_action ? &source.deadline_action : nullptr;

    ParentHeaderNative(const uint256& hash, int minimum, VerifiedMainchainHeader& output,
        std::string* diagnostic, const DrivechainParentHeaderSource& input, bool authenticate)
        : expected_hash(hash), min_confirmations(minimum), verified(output), error(diagnostic),
          source(input), authenticate_rpc(authenticate) {}
    ParentHeaderNative(const ParentHeaderNative&) = delete;
    ParentHeaderNative& operator=(const ParentHeaderNative&) = delete;

    uint64_t Read(uint32_t step,uint64_t index)
    {
        if (step >= 200) return raw_native->Read(step-200,index);
        if (step >= 100) return median_native->Read(step-100,index);
        if (step >= 41 && step <= 45) {
            if (index <= 1) return metadata_native->Read(step,index);
            if (index <= 4) return predecessor_native->Read(step,index);
            if (index == 5) return ReadCanonicalHash(*genesis,rpc_genesis,step);
            if (index == 6) return ReadCanonicalHash(*active_result,active_hash,step);
            throw std::logic_error("invalid parent authentication hash index");
        }
        if (step >= 50 && step <= 56) return metadata_native->Read(step,index);
        if (step <= 10 || (step >= 60 && step <= 70)) return predecessor_native->Read(step,index);
        switch (step) {
        case 36:
            if (!deadline_action) throw std::logic_error("missing parent authentication deadline action");
            return (*deadline_action)(index);
        case 40:
            if (index <= 9) return metadata_native->Read(step,index);
            if (index <= 15) return predecessor_native->Read(step,index);
            switch (index) {
            case 16: return SetError(error,"minimum parent confirmations must be positive");
            case 17: return SetError(error,strprintf("mainchain RPC genesis does not match pinned parent genesis %s",source.genesis().GetHex()));
            case 18: return SetError(error,"parent block is not the active-chain block at its declared height");
            case 19: return SetError(error,"parent chainwork cannot be zero");
            }
            break;
        case 57: return static_cast<uint64_t>(int64_t{min_confirmations});
        case 81: {
            UniValue params{UniValue::VARR};
            params.push_back(0);
            return rpc.Prepare("getblockhash", std::move(params), [this](UniValue result) {
                genesis.emplace(std::move(result));
            });
        }
        case 82: return rpc_genesis == source.genesis();
        case 83: {
            UniValue params{UniValue::VARR};
            params.push_back(expected_hash.GetHex());
            params.push_back(true);
            return rpc.Prepare("getblockheader", std::move(params), [this](UniValue result) {
                metadata.emplace(std::move(result));
                metadata_native.emplace(*metadata,expected_hash,min_confirmations,
                    parsed_chainwork,parsed_height,parsed_confirmations,error);
            });
        }
        case 84: {
            UniValue params{UniValue::VARR};
            params.push_back(parsed_height);
            return rpc.Prepare("getblockhash", std::move(params), [this](UniValue result) {
                active_result.emplace(std::move(result));
            });
        }
        case 85: return active_hash == expected_hash;
        case 86: {
            raw_header.emplace();
            if (!authenticate_rpc) return source.raw_header(expected_hash,*raw_header,error);
            UniValue params{UniValue::VARR};
            params.push_back(expected_hash.GetHex());
            params.push_back(false);
            return rpc.Prepare("getblockheader", std::move(params), [this](UniValue result) {
                raw.emplace(std::move(result));
                raw_native.emplace(*raw,expected_hash,*raw_header,error,source.deadline,deadline_action);
            });
        }
        case 87:
            // Construct in place: work borrows the adapter's own chainwork.
            predecessor_native.emplace(metadata->get_obj()["previousblockhash"],parsed_height,
                *raw_header,parsed_chainwork,error,rpc);
            return 1;
        case 88:
            median_time_past = 0;
            if (!authenticate_rpc) return source.median_time(expected_hash,parsed_height,median_time_past,error);
            median_native.emplace(expected_hash,median_time_past,unused_reader,&rpc,source.deadline,error,deadline_action);
            return 1;
        case 89: source.deadline(); return 1;
        case 90:
            verified.header = *raw_header;
            verified.chainwork = parsed_chainwork;
            verified.height = static_cast<uint32_t>(parsed_height);
            verified.confirmations = parsed_confirmations;
            verified.median_time_past = median_time_past;
            return 1;
        case 91: return verified.chainwork.IsNull();
        }
        throw std::logic_error("invalid parent authentication native action");
    }

    std::vector<unsigned char> operator()(uint32_t step,uint64_t index,std::span<const unsigned char> input)
    {
        return rpc.Read(step,index,input,[this](uint32_t action,uint64_t at) { return Read(action,at); });
    }
};
} // namespace

bool VerifyDrivechainParentHeader(const uint256& expected_hash, int min_confirmations,
    VerifiedMainchainHeader& verified, std::string* error, const DrivechainParentHeaderSource& source,
    bool authenticate_rpc)
{
    namespace hs = drivechain::haskell;
    ParentHeaderNative native{expected_hash,min_confirmations,verified,error,source,authenticate_rpc};
    return hs::RunParentHeader(authenticate_rpc ? (source.deadline_action ? hs::ParentHeaderWorkflow::RPC_VERIFY_DEADLINE :
        hs::ParentHeaderWorkflow::RPC_VERIFY) : hs::ParentHeaderWorkflow::VERIFY,0,std::ref(native));
}

namespace {

template <typename... Fields>
std::vector<unsigned char> ParentReplayBytes(const Fields&... fields)
{
    std::vector<unsigned char> result;
    VectorWriter writer{result, 0};
    SerializeMany(writer, fields...);
    return result;
}

struct ParentNetworkNative {
    const Consensus::Params* consensus;
    const std::function<UniValue(const std::string&, const UniValue&)>* request;
    std::atomic<uint64_t>* replay_epoch;
    uint32_t height;
    uint256& active_hash;
    std::string* error;
    UniValue params{}, reply{};
    uint256 network_hash{};
    bool recover{false}, active{false};
    const std::string method{"getblockhash"}, endpoint{"/"};
    std::unique_ptr<ParentRpcTransport> transport{};

    uint64_t PrepareRequest()
    {
        if (request) {
            reply = (*request)(method, params);
            return 1;
        }
        transport = std::make_unique<ParentRpcTransport>(method, params, endpoint);
        return 2;
    }

    uint64_t Read(uint32_t step, std::span<const unsigned char> input)
    {
        switch (step) {
        case 0: return consensus->hashGenesisBlock == uint256S(ElementsDrivechainIdentity::GENESIS_HASH);
        case 1: params.setArray(); params.push_back(967680); recover = true; return 1;
        case 2: return PrepareRequest();
        case 3: return network_hash == uint256S("00000000000000030101ba5cfea54b22becc79f95dc6040beb76e01dd9d04042");
        case 4: transport.reset(); replay_epoch->store(0, std::memory_order_release); return 1;
        case 5: if (error) error->assign(input.begin(), input.end()); return 1;
        case 6:
            if (!transport) throw std::logic_error("missing parent network RPC transport");
            reply = transport->Result(true);
            transport.reset();
            return 1;
        case 7:
            recover = false;
            active = true;
            params.setArray(); params.push_back(static_cast<int64_t>(height));
            return PrepareRequest();
        case 8: return height;
        case 9: throw std::runtime_error("Haskell replay store workflow failed");
        default: return ReadCanonicalHash(reply, active ? active_hash : network_hash, step);
        }
    }

    std::vector<unsigned char> operator()(uint32_t step, uint64_t index, std::span<const unsigned char> input)
    {
        if (step < 1000 && (index || (step != 5 && !input.empty()))) throw std::logic_error("invalid parent network action");
        // Retain the original C++ std::exception boundary without poisoning the
        // outer FFI context: Haskell must still revoke the epoch and report it.
        try {
            if (step >= 1000) {
                if (step > 1560 || !transport) throw std::logic_error("invalid parent network transport action");
                auto bytes = (*transport)(step - 1000, index, input);
                bytes.insert(bytes.begin(), 1);
                return bytes;
            }
            return ParentReplayBytes(true, Read(step, input));
        }
        catch (const std::exception& e) {
            if (!recover) throw;
            recover = false;
            std::vector<unsigned char> result{0};
            const std::string_view message{e.what()};
            result.insert(result.end(), message.begin(), message.end());
            return result;
        }
    }
};

bool RunParentNetwork(ParentNetworkNative& native)
{
    return drivechain::haskell::RunReplayStore(drivechain::haskell::ReplayStoreWorkflow::PARENT_NETWORK,
        std::ref(native));
}

} // namespace

bool VerifyDrivechainParentRpcNetwork(const Consensus::Params& consensus,
    const std::function<UniValue(const std::string&, const UniValue&)>& request,
    std::atomic<uint64_t>& replay_epoch, std::string* error)
{
    uint256 unused;
    ParentNetworkNative native{&consensus, &request, &replay_epoch, 0, unused, error};
    return RunParentNetwork(native);
}

bool VerifyDrivechainParentRpcNetwork(const Consensus::Params& consensus,
    std::atomic<uint64_t>& replay_epoch, std::string* error)
{
    uint256 unused;
    ParentNetworkNative native{&consensus, nullptr, &replay_epoch, 0, unused, error};
    return RunParentNetwork(native);
}

bool CheckDrivechainParentRpcNetwork(const Consensus::Params& consensus, std::string* error)
{
    return VerifyDrivechainParentRpcNetwork(consensus, g_drivechain_parent_replay_published_epoch, error);
}

bool CheckDrivechainParentRpcNetwork(const Consensus::Params& consensus,
    const std::function<UniValue(const std::string&, const UniValue&)>& request,
    std::string* error)
{
    return VerifyDrivechainParentRpcNetwork(consensus, request,
        g_drivechain_parent_replay_published_epoch, error);
}

namespace {
struct ParentNetworkHeaderNative {
    const Consensus::Params& consensus;
    std::atomic<uint64_t>& replay_epoch;
    const uint256& expected_hash;
    int min_confirmations;
    VerifiedMainchainHeader& verified;
    std::string* error;
    const DrivechainParentHeaderSource& source;
    uint256 unused{};
    std::optional<ParentNetworkNative> network{};
    std::optional<ParentHeaderNative> header{};

    std::vector<unsigned char> operator()(uint32_t step,uint64_t index,std::span<const unsigned char> input)
    {
        if (step == 10000 || step == 10001) {
            if (!input.empty()) throw std::logic_error("invalid parent context input");
            if (step == 10000 && index == 1 && !network && !header) {
                network.emplace(&consensus,source.native_rpc ? nullptr : &source.request,
                    &replay_epoch,0,unused,error);
            } else if (step == 10000 && index == 2 && !network && !header) {
                header.emplace(expected_hash,min_confirmations,verified,error,source,true);
            } else if (step == 10001 && index == 1 && network && !header) {
                network.reset();
            } else if (step == 10001 && index == 2 && header && !network) {
                header.reset();
            } else throw std::logic_error("invalid parent context lifetime");
            return ParentReplayBytes(uint64_t{1});
        }
        if (step == 10002 && index == 0 && input.empty() && header)
            return ParentReplayBytes(uint64_t{bool(source.deadline_action)});
        if (step < 2000 && network) return (*network)(step,index,input);
        if (step >= 2000 && step < 4000 && header) return (*header)(step-2000,index,input);
        throw std::logic_error("invalid network header action");
    }
};

struct ParentRecoveryBudgetNative {
    std::optional<std::chrono::steady_clock::time_point>& current;
    const std::optional<std::chrono::steady_clock::time_point> previous;
    const std::function<std::chrono::steady_clock::time_point()>& now;
    std::chrono::steady_clock::time_point limit;
    bool initialized{false};

    ParentRecoveryBudgetNative(const DrivechainParentBodySource& source)
        : current(source.recovery_deadline), previous(current), now(source.now) {}
    ~ParentRecoveryBudgetNative() noexcept { if (initialized) current = previous; }
    ParentRecoveryBudgetNative(const ParentRecoveryBudgetNative&) = delete;
    ParentRecoveryBudgetNative& operator=(const ParentRecoveryBudgetNative&) = delete;
    uint64_t Read(uint32_t step)
    {
        switch (step) {
        case 1: limit = now() + std::chrono::seconds{drivechain::PARENT_RECOVERY_SECONDS}; return 1;
        case 2: return previous.has_value();
        case 3: return limit < *previous;
        case 4: current = limit; return 1;
        case 5: initialized = true; return 1;
        default: throw std::logic_error("invalid recovery budget action");
        }
    }
};
} // namespace

bool VerifyDrivechainNetworkHeader(const Consensus::Params& consensus, std::atomic<uint64_t>& replay_epoch,
    const uint256& expected_hash, int min_confirmations, VerifiedMainchainHeader& verified,
    std::string* error, const DrivechainParentHeaderSource& source)
{
    ParentNetworkHeaderNative native{consensus,replay_epoch,expected_hash,min_confirmations,verified,error,source};
    return drivechain::haskell::RunParentHeader(drivechain::haskell::ParentHeaderWorkflow::NETWORK_VERIFY,0,std::ref(native));
}

bool ReadDrivechainParentBlock(const Consensus::Params& consensus, std::atomic<uint64_t>& replay_epoch,
    const uint256& hash, int min_confirmations, Bitcoin::CBlock& block,
    VerifiedMainchainHeader* verified, std::string* error, const DrivechainParentBodySource& source)
{
    namespace hs = drivechain::haskell;
    VerifiedMainchainHeader unused;
    ParentNetworkHeaderNative header{consensus,replay_epoch,hash,min_confirmations,verified ? *verified : unused,error,source.header};
    // Reverse destruction order also restores the budget after a native exception
    // poisons further callbacks, so Haskell cannot perform its release effects.
    std::optional<ParentRecoveryBudgetNative> budget;
    std::optional<UniValue> raw;
    std::optional<ParentBodyRecoveryNative> recovery;
    std::optional<RawParentNative<Bitcoin::CBlock>> decoder;
    std::optional<ParentBlockNative> body;
    const auto* action = source.header.deadline_action ? &source.header.deadline_action : nullptr;
    return hs::RunParentHeader(verified ? hs::ParentHeaderWorkflow::READ_BLOCK : hs::ParentHeaderWorkflow::READ_BODY,0,
        [&](uint32_t step,uint64_t index,std::span<const unsigned char> input) {
            if ((step == 10000 || step == 10001) && index <= 2) {
                if (!verified || budget) throw std::logic_error("unexpected parent header scope");
                return header(step,index,input);
            }
            if (step == 10000 || step == 10001) {
                if (!input.empty() || header.network || header.header) throw std::logic_error("invalid parent body context");
                if (step == 10000 && index == 3 && !budget && !raw && !recovery && !body) {
                    budget.emplace(source);
                } else if (step == 10000 && index == 4 && budget && budget->initialized && !raw && !recovery && !body) {
                    recovery.emplace(hash.GetHex(),source.allow_recovery(),source.header.native_rpc ? nullptr : &source.request,
                        source.check_deadline,source.wait,action);
                } else if (step == 10000 && index == 5 && budget && budget->initialized && raw && !recovery && !body) {
                    decoder.emplace(*raw,hash,block,error,source.header.deadline,action);
                    body.emplace(block,error,source.header.deadline,&source.challenge,&source.header.genesis);
                } else if (step == 10001 && index == 5 && body && decoder && !recovery) {
                    body.reset(); decoder.reset();
                } else if (step == 10001 && index == 4 && recovery && !body) {
                    recovery.reset();
                } else if (step == 10001 && index == 3 && budget && !recovery && !body) {
                    raw.reset(); budget.reset();
                } else throw std::logic_error("invalid parent body lifetime");
                return ParentReplayBytes(uint64_t{1});
            }
            if ((step < 4000 || step == 10002) && verified && !budget) return header(step,index,input);
            if (step >= 4000 && step < 6000 && recovery) return (*recovery)(step-4000,index,input);
            if (step >= 6000 && step < 9000 && body && decoder) {
                if (step >= 6100) return body->ReadBytes(step-6000,index,input);
                if (!input.empty()) throw std::logic_error("invalid raw parent block workflow input");
                return ParentReplayBytes(decoder->Read(step-6000,index));
            }
            if (index || !input.empty()) throw std::logic_error("invalid parent body action");
            if (step > 9000 && step <= 9005 && budget) return ParentReplayBytes(budget->Read(step-9000));
            if (step == 10003 && recovery && !raw) {
                raw.emplace(recovery->reply["result"]);
                return ParentReplayBytes(uint64_t{1});
            }
            if (step == 10004 && body) return ParentReplayBytes(uint64_t{bool(action)});
            if (step == 10005 && verified && !budget)
                return ParentReplayBytes(uint64_t{block.GetBlockHeader().GetHash() == verified->header.GetHash()});
            if (step == 10006 && verified && !budget) {
                SetError(error,"raw parent block header does not match authenticated header");
                return ParentReplayBytes(uint64_t{1});
            }
            throw std::logic_error("invalid parent block action");
        });
}

namespace {

bool ReadMainchainBlock(const uint256& hash, int min_confirmations, Bitcoin::CBlock& block,
    VerifiedMainchainHeader* verified, std::string* error)
{
    const DrivechainParentHeaderSource header{
        []() -> const uint256& { return Params().ParentGenesisBlockHash(); },
        {}, {}, {}, {}, DrivechainParentDeadlineAction, true};
    return ReadDrivechainParentBlock(Params().GetConsensus(),g_drivechain_parent_replay_published_epoch,
        hash,min_confirmations,block,verified,error,
        {header,g_drivechain_anchor_warm_deadline,std::chrono::steady_clock::now,
         [] { return !DrivechainParentBudgetActive(); },{}, {},
         [] { std::this_thread::sleep_for(std::chrono::milliseconds{250}); },
         []() -> const std::vector<uint8_t>& { return Params().GetConsensus().parent_signet_challenge; }});
}

bool ReadAuthenticatedRawMainchainBlock(const uint256& hash, Bitcoin::CBlock& block, std::string* error)
{
    return ReadMainchainBlock(hash,0,block,nullptr,error);
}

bool ReadVerifiedMainchainBlock(const uint256& hash, const int min_confirmations,
                                Bitcoin::CBlock& block, VerifiedMainchainHeader& verified,
                                std::string* error)
{
    return ReadMainchainBlock(hash,min_confirmations,block,&verified,error);
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

struct NativeCoinbaseReader {
    const Bitcoin::CBlock& block;
    const CScript* script{nullptr};
    CScript::const_iterator pc{};

    std::vector<unsigned char> operator()(uint32_t step, uint64_t index)
    {
        if (step == 0) {
            if (block.vtx.empty() || !block.vtx[0] || !block.vtx[0]->IsCoinBase()) return {0};
            return ParentReplayBytes(true, uint64_t{block.vtx[0]->vout.size()});
        }
        if (step == 1) { script = &block.vtx.at(0)->vout.at(index).scriptPubKey; pc = script->begin(); }
        if (!script || (step != 1 && step != 2)) throw std::logic_error("invalid coinbase reader request");
        opcodetype opcode{};
        std::vector<unsigned char> pushed;
        const uint16_t parsed = script->GetOp(pc, opcode, pushed) ? uint16_t(opcode) : 256;
        return step == 1 ? ParentReplayBytes(parsed) : ParentReplayBytes(parsed, pc == script->end(), pushed);
    }
};

struct NativeBmmScan {
    const Bitcoin::CBlock& block;
    int slot;
    uint256& commitment;
    uint32_t* output_index;
    std::string* error;
    const uint256* expected;
    NativeCoinbaseReader reader{block};

    void Reset()
    {
        commitment.SetNull();
        if (output_index) *output_index = 0;
    }

    std::vector<unsigned char> operator()(uint32_t step, uint64_t index, std::span<const unsigned char> input)
    {
        if (!input.empty() && step != 5 && step != 6) throw std::logic_error("invalid BMM scan request");
        switch (step) {
        case 1: return ParentReplayBytes(int32_t{slot}, expected != nullptr, expected ? *expected : uint256{});
        case 2: case 3: case 4: return reader(step-2,index);
        case 5:
            if (input.size() != 32 || index > UINT32_MAX) throw std::logic_error("invalid BMM scan result");
            commitment = uint256{input.data(),input.size()};
            if (output_index) *output_index = static_cast<uint32_t>(index);
            return {};
        case 6: SetError(error, std::string(input.begin(),input.end())); return {};
        default: throw std::logic_error("invalid BMM scan effect");
        }
    }
};

bool RunNativeBmmScan(const Bitcoin::CBlock& block, int slot, uint256& commitment,
    uint32_t* output_index, std::string* error, const uint256* expected = nullptr)
{
    NativeBmmScan native{block, slot, commitment, output_index, error, expected};
    native.Reset();
    return drivechain::haskell::RunReplayStore(drivechain::haskell::ReplayStoreWorkflow::BMM,
        [&](uint32_t step, uint64_t index, std::span<const unsigned char> input) { return native(step,index,input); });
}

struct ParentScriptReader {
    const CScript& script;
    std::vector<unsigned char>& payload;
    CScript::const_iterator pc;
    opcodetype opcode{};
    std::optional<std::vector<unsigned char>> pushed;

    uint32_t Action(uint32_t step)
    {
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
    }
};

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

template <typename... Fields>
std::vector<unsigned char> ParentCacheKeyBytes(const Consensus::Params& consensus, const Fields&... fields)
{
    return ParentReplayBytes(consensus.drivechain_slot.has_value(), consensus.drivechain_slot.value_or(0),
        consensus.drivechain_proposal_hash.has_value(), consensus.drivechain_proposal_hash.value_or(uint256{}),
        consensus.drivechain_parent_state_active_proposal_hash.value_or(uint256{}), consensus.drivechain_parent_state_hash,
        consensus.drivechain_unused_slot_proposal_max_age, consensus.drivechain_unused_slot_activation_threshold,
        consensus.drivechain_used_slot_proposal_max_age, consensus.drivechain_used_slot_activation_threshold,
        consensus.drivechain_withdrawal_bundle_max_age, consensus.drivechain_withdrawal_bundle_inclusion_threshold,
        consensus.drivechain_parent_state_replay_version, fields...);
}

template <typename... Fields>
std::vector<unsigned char> ParentCacheSnapshotBytes(const DrivechainParentReplayCache& cache, const Fields&... fields)
{
    return ParentReplayBytes(cache.initialized, true, cache.slot, true, cache.proposal_hash,
        cache.checkpoint_active_proposal_hash, cache.checkpoint_hash,
        cache.unused_proposal_max_age, cache.unused_activation_threshold,
        cache.used_proposal_max_age, cache.used_activation_threshold,
        cache.withdrawal_bundle_max_age, cache.withdrawal_bundle_inclusion_threshold,
        cache.replay_version, cache.height, cache.hash, cache.state.required_proposal_activated,
        cache.state.active_proposal_hash, cache.state.required_activation_height, fields...);
}

std::mutex g_drivechain_parent_replay_mutex;
DrivechainParentReplayCache g_drivechain_parent_replay_cache;
std::unique_ptr<DrivechainParentReplayStore> g_drivechain_parent_replay_store;
bool g_drivechain_parent_replay_store_rebuild_required{false};
uint64_t g_drivechain_parent_replay_epoch_counter{0};
using drivechain::DRIVECHAIN_PARENT_REPLAY_DB_CACHE_BYTES;

bool ReplayCacheMatchesConfiguredIdentity(
    const DrivechainParentReplayCache& cache,
    const Consensus::Params& consensus);

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
    return RunNativeBmmScan(block, sidechain_slot, committed_sidechain_hash, output_index, error);
}

bool MatchDrivechainBmmCommitmentInBlock(const Bitcoin::CBlock& block,
                                         const int sidechain_slot,
                                         const uint256& expected_critical_hash,
                                         uint32_t* output_index,
                                         std::string* error)
{
    uint256 committed_hash;
    return RunNativeBmmScan(block, sidechain_slot, committed_hash, output_index, error, &expected_critical_hash);
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

bool ExtractDrivechainTreasurySlot(const CScript& script, uint8_t& slot,
                                 drivechain::TreasuryOpcode treasury_opcode)
{
    return drivechain::ExtractTreasurySlot(script, treasury_opcode, slot);
}

} // namespace

static int64_t DrivechainM6IdNativeAction(const Bitcoin::CTransaction& transaction, uint256& m6id,
    uint8_t& parsed_slot, uint8_t* sidechain_slot,
    uint32_t step, uint64_t value)
{
    switch (step) {
    case 1: m6id.SetNull(); return 1;
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
}

static bool DrivechainM6IdResult(int result, std::string* error)
{
    static constexpr const char* errors[]{
        "BIP300 M6 has no replacement treasury output",
        "BIP300 M6 replacement treasury output is not vout 0",
        "BIP300 M6 must contain exactly one treasury input",
        "BIP300 M6 treasury amount is outside the money range",
        "BIP300 M6 payout total is outside the money range",
        "BIP300 M6 spends more than the previous treasury value"};
    return result == 0 || SetError(error,errors[result-1]);
}

bool ComputeDrivechainM6Id(const Bitcoin::CTransaction& transaction,
                           const CAmount previous_treasury_value,
                           uint256& m6id,
                           uint8_t* sidechain_slot,
                           std::string* error,
                           drivechain::TreasuryOpcode treasury_opcode)
{
    uint8_t parsed_slot{0};
    return DrivechainM6IdResult(drivechain::haskell::M6Id(transaction.vout.size(),transaction.vin.size(),
        previous_treasury_value,MAX_MONEY,sidechain_slot != nullptr,[&](uint32_t step,uint64_t value) {
            if (step == 2) return int64_t(ExtractDrivechainTreasurySlot(transaction.vout[0].scriptPubKey,parsed_slot,treasury_opcode));
            return DrivechainM6IdNativeAction(transaction,m6id,parsed_slot,sidechain_slot,step,value);
        }),error);
}

namespace {
struct NativeParentBlock {
    const Bitcoin::CBlock& block;
    const uint32_t height;
    const int sidechain_slot;
    const uint256& required_active_proposal;
    const uint16_t unused_slot_proposal_max_age;
    const uint16_t unused_slot_activation_threshold;
    const uint16_t used_slot_proposal_max_age;
    const uint16_t used_slot_activation_threshold;
    const uint16_t withdrawal_bundle_max_age;
    const uint16_t withdrawal_bundle_inclusion_threshold;
    DrivechainParentReplayState& state;
    std::vector<DrivechainMintableDeposit>* deposits;
    std::string* error;
    std::vector<DrivechainSuccessfulWithdrawal>* successful_withdrawals;
    std::vector<DrivechainWithdrawalProposalIdentity>* withdrawal_proposals;
    drivechain::TreasuryOpcode treasury_opcode;
    DrivechainM6ReplayRule m6_rule;
    const uint8_t configured_slot = static_cast<uint8_t>(sidechain_slot);
    std::vector<DrivechainSuccessfulWithdrawal> derived_withdrawals;
    std::vector<DrivechainWithdrawalProposalIdentity> derived_proposals;
    std::vector<DrivechainParentMessage> messages;
    std::vector<unsigned char> payload;
    std::optional<ParentScriptReader> reader;
    static std::vector<unsigned char> words(std::initializer_list<uint64_t> values)
    {
        std::vector<unsigned char> bytes(values.size()*8);
        size_t offset{0};
        for (auto value : values) { WriteLE64(bytes.data()+offset,value); offset += 8; }
        return bytes;
    }
    std::vector<unsigned char> prelude_native(uint32_t step,uint64_t index,std::span<const unsigned char> input)
    {
        switch (step) {
        case 201:
            if (deposits) deposits->clear();
            if (successful_withdrawals) successful_withdrawals->clear();
            if (withdrawal_proposals) withdrawal_proposals->clear();
            return {};
        case 0: {
            const uint64_t flags = uint64_t(drivechain::SupportedParentReplayRules(treasury_opcode,m6_rule)) |
                (uint64_t(!required_active_proposal.IsNull()) << 1) |
                (uint64_t(state.required_proposal_activated) << 2) |
                (uint64_t(state.active_proposal_hash != required_active_proposal) << 3) |
                (uint64_t(state.active_proposal_hash.IsNull()) << 4) |
                (uint64_t(state.ctip.has_value()) << 5);
            auto bytes = words({static_cast<uint64_t>(sidechain_slot),flags,
                static_cast<uint64_t>(state.ctip_value),MAX_MONEY});
            for (uint16_t value : {unused_slot_proposal_max_age,unused_slot_activation_threshold,
                    used_slot_proposal_max_age,used_slot_activation_threshold,
                    withdrawal_bundle_max_age,withdrawal_bundle_inclusion_threshold}) {
                const auto offset = bytes.size();
                bytes.resize(offset+2);
                WriteLE16(bytes.data()+offset,value);
            }
            return bytes;
        }
        case 1: {
            const bool present = !block.vtx.empty() && bool(block.vtx[0]);
            return words({uint64_t(block.vtx.empty()) | (uint64_t(present) << 1) |
                (uint64_t(present && block.vtx[0]->IsCoinBase()) << 2)});
        }
        case 2: {
            std::vector<unsigned char> bytes;
            for (const auto& [slot,slot_state] : state.other_slots) {
                bytes.push_back(slot);
                bytes.push_back(uint8_t(slot_state.active_proposal_hash.IsNull()) |
                    (uint8_t(slot_state.ctip.has_value()) << 1));
                const auto value = words({static_cast<uint64_t>(slot_state.ctip_value)});
                bytes.insert(bytes.end(),value.begin(),value.end());
            }
            return bytes;
        }
        case 3: {
            std::vector<unsigned char> bytes;
            for (const auto& [slot,action] : state.previous_m4_actions) {
                bytes.push_back(slot);
                bytes.push_back(uint8_t(action.type == DrivechainM4ActionType::UPVOTE) |
                    (uint8_t(action.type == DrivechainM4ActionType::ALARM) << 1) |
                    (uint8_t(action.m6id.IsNull()) << 2));
            }
            return bytes;
        }
        case 10: return words({block.vtx[0]->vout.size()});
        case 11:
            reader.emplace(ParentScriptReader{block.vtx[0]->vout.at(index).scriptPubKey,payload,{}, {}, {}});
            return {};
        case 12: return words({reader.value().Action(index)});
        case 13: return payload;
        case 14: {
            const auto hash = Hash(Span{input});
            return {hash.begin(),hash.end()};
        }
        case 15: {
            if (input.size() < 35 || (input.size()-35)%2 != 0 ||
                input[0] < 1 || input[0] > 5 || input[2] > 3)
                throw std::runtime_error("invalid decoded parent message");
            DrivechainParentMessage message{static_cast<DrivechainParentMessageType>(input[0]),
                input[1],uint256{input.data()+3,32},static_cast<DrivechainM4Encoding>(input[2]),{}};
            for (size_t offset = 35; offset < input.size(); offset += 2)
                message.m4_votes.push_back(ReadLE16(input.data()+offset));
            messages.push_back(std::move(message));
            return {};
        }
        case 20: return words({block.vtx.size()});
        case 21: {
            const auto& outputs = block.vtx.at(index)->vout;
            if (outputs.empty()) return {};
            const auto& script = outputs[0].scriptPubKey;
            return {script.begin(),script.end()};
        }
        case 22: return {block.hashPrevBlock.begin(),block.hashPrevBlock.end()};
        case 30: return words({DrivechainParentDeadlineAction(index)});
        case 200:
            SetError(error,std::string(input.begin(),input.end()));
            return {};
        default: throw std::logic_error("invalid parent prelude action");
        }
    }
    struct MessageContext {
        std::map<uint8_t,DrivechainM4Action> effective_m4_actions;
        const DrivechainParentMessage* current{nullptr};
        std::map<uint256,DrivechainPendingProposal>* pending_proposals{nullptr};
        std::map<uint256,DrivechainPendingProposal>::iterator proposal;
        uint256* active{nullptr};
        std::vector<DrivechainPendingWithdrawal>* pending_withdrawals{nullptr};
        size_t active_count{0};
        uint8_t voting_slot{0};
    } message_state;
    std::vector<unsigned char> message_native(uint32_t step,uint64_t index,std::span<const unsigned char> update)
    {
        auto& [effective_m4_actions,current,pending_proposals,proposal,active,pending_withdrawals,active_count,voting_slot] = message_state;
        if (step == 1000) return words({messages.size()});
        if (step == 1001) {
            const int result = index;
            const auto fail = [&]() -> bool {
                const auto& message = *current;
                switch (result) {
                case 0x101: return SetError(error, "M2 proposal height is ahead of replay height");
                case 0x102: return SetError(error, strprintf("parent slot %d was replaced by proposal %s", sidechain_slot, active->GetHex()));
                case 0x201: return SetError(error, strprintf("M3 proposes a withdrawal for inactive sidechain slot %u", message.slot));
                case 0x202: return SetError(error, strprintf("M3 withdrawal bundle %s is already pending for slot %u", message.proposal_hash.GetHex(), message.slot));
                case 0x301: return SetError(error, "unhandled BIP300 parent coinbase message");
                case 0x302: return SetError(error, "two-byte M4 contains no value requiring two-byte encoding");
                case 0x303: return SetError(error, strprintf("M4 vote vector has %u entries for %u active sidechains", message.m4_votes.size(), active_count));
                case 0x304: {
                    size_t voting_index = !state.active_proposal_hash.IsNull() && configured_slot < voting_slot;
                    for (const auto& [slot, entry] : state.other_slots)
                        voting_index += slot < voting_slot && !entry.active_proposal_hash.IsNull();
                    return SetError(error, strprintf("M4 vote index %u is absent for sidechain slot %u", message.m4_votes.at(voting_index), voting_slot));
                }
                case 0x305: return SetError(error, strprintf("RepeatPrevious references inactive sidechain slot %u", voting_slot));
                case 0x306: return SetError(error, strprintf("M4 upvote references missing withdrawal bundle %s", state.previous_m4_actions.at(voting_slot).m6id.GetHex()));
                default: throw std::logic_error("invalid parent message workflow result");
                }
            };
            fail(); return {};
        }
        if (step == 0) {
            current = &messages.at(index);
            active_count = 0;
            voting_slot = 0;
            const auto flags = static_cast<unsigned char>(
                (current->type == DrivechainParentMessageType::WITHDRAWAL_ACK ? 1U : 0U) |
                (current->m4_encoding == DrivechainM4Encoding::NONE ? 2U : 0U) |
                (current->m4_encoding == DrivechainM4Encoding::EXPLICIT ? 4U : 0U) |
                (current->m4_encoding == DrivechainM4Encoding::LEADING_BY_50 ? 8U : 0U));
            std::vector<unsigned char> bytes{static_cast<unsigned char>(current->type), flags};
            for (uint16_t vote : current->m4_votes) {
                const auto end = bytes.size();
                bytes.resize(end+2);
                WriteLE16(bytes.data()+end, vote);
            }
            return bytes;
        }
        if (step == 40) {
            // No M4 means the next RepeatPrevious repeats an empty action.
            state.previous_m4_actions = std::move(effective_m4_actions);
            return {};
        }
        if (!current) throw std::logic_error("parent replay has no selected message");
        const auto& message = *current;
        if (step == 2) {
            SlotPendingProposals(state, message.slot, configured_slot).try_emplace(
                message.proposal_hash, DrivechainPendingProposal{height, 0});
            return {};
        }
        if (step == 3) {
            pending_proposals = &SlotPendingProposals(state, message.slot, configured_slot);
            proposal = pending_proposals->find(message.proposal_hash);
            active = nullptr;
            return {};
        }
        if (step >= 10 && step < 30) {
            const auto scalar = [&]() -> int64_t {
                switch (step) {
                case 11: return proposal == pending_proposals->end() ? -2 : static_cast<int64_t>(proposal->second.proposal_height);
                case 12: return proposal->second.votes;
                case 13:
                    proposal->second.votes = index;
                    active = &SlotActiveProposal(state, message.slot, configured_slot);
                    return !active->IsNull();
                case 14: *active = message.proposal_hash; pending_proposals->erase(proposal); return 1;
                case 15: return (message.slot == configured_slot ? 1 : 0) |
                    (state.required_proposal_activated ? 2 : 0) | (*active == required_active_proposal ? 4 : 0);
                case 16:
                    state.required_proposal_activated = true;
                    state.required_activation_height = height;
                    state.required_activation_block_hash = block.GetHash(); return 1;
                case 21: return !SlotActiveProposal(state, message.slot, configured_slot).IsNull();
                case 22: pending_withdrawals = &SlotPendingWithdrawals(state, message.slot, configured_slot); return pending_withdrawals->size();
                case 23: return (*pending_withdrawals)[index].m6id == message.proposal_hash;
                case 24: derived_proposals.push_back({message.slot, message.proposal_hash}); return 1;
                case 25: pending_withdrawals->push_back({message.proposal_hash, height, 1}); return 1;
                default: throw std::logic_error("invalid parent message action");
                }
            };
            std::vector<unsigned char> bytes(8);
            WriteLE64(bytes.data(), scalar());
            return bytes;
        }
        if (step < 30 || step > 33) throw std::logic_error("invalid parent message workflow action");
        step -= 30;
        std::vector<unsigned char> bytes;
        if (step == 0) {
            const auto append = [&](uint8_t slot, bool active) {
                bytes.insert(bytes.end(), {slot, static_cast<unsigned char>(active)});
                active_count += active;
            };
            append(configured_slot, !state.active_proposal_hash.IsNull());
            for (const auto& [slot, entry] : state.other_slots) append(slot, !entry.active_proposal_hash.IsNull());
        } else if (step == 1) {
            for (const auto& [slot, previous] : state.previous_m4_actions) {
                bytes.insert(bytes.end(), {slot, static_cast<unsigned char>(previous.type == DrivechainM4ActionType::UPVOTE)});
                bytes.insert(bytes.end(), previous.m6id.begin(), previous.m6id.end());
            }
        } else {
            if (index > 255) throw std::logic_error("invalid M4 slot");
            voting_slot = index;
            if (step == 2) {
                const bool active = !SlotActiveProposal(state, voting_slot, configured_slot).IsNull();
                bytes.push_back(active);
                if (active) {
                    for (const auto& entry : SlotPendingWithdrawals(state, voting_slot, configured_slot)) {
                        bytes.insert(bytes.end(), entry.m6id.begin(), entry.m6id.end());
                        const auto end = bytes.size();
                        bytes.resize(end+2);
                        WriteLE16(bytes.data()+end, entry.votes);
                    }
                }
            } else if (step == 3) {
                auto& pending = SlotPendingWithdrawals(state, voting_slot, configured_slot);
                if (update.size() < 33 || update[0] > 1 || (update.size()-33)/2 != pending.size() || (update.size()-33)%2)
                    throw std::logic_error("invalid M4 vote publication");
                uint256 target;
                std::copy_n(update.begin()+1, 32, target.begin());
                for (size_t i = 0; i < pending.size(); ++i) pending[i].votes = ReadLE16(update.data()+33+2*i);
                effective_m4_actions.emplace(voting_slot, DrivechainM4Action{
                    update[0] ? DrivechainM4ActionType::UPVOTE : DrivechainM4ActionType::ALARM, target});
            } else throw std::logic_error("invalid M4 workflow action");
        }
        return bytes;
    }
    static void erase_indices(auto& entries, std::span<const unsigned char> indices)
    {
        if (indices.size()%8) throw std::logic_error("invalid replay expiry indices");
        const auto size = entries.size();
        auto cursor = entries.begin();
        uint64_t consumed{0};
        for (size_t offset = 0; offset < indices.size(); offset += 8) {
            const auto index = ReadLE64(indices.data()+offset);
            if (index < consumed || index >= size) throw std::logic_error("invalid replay expiry index");
            std::advance(cursor,index-consumed);
            cursor = entries.erase(cursor);
            consumed = index+1;
        }
    }
    std::vector<unsigned char> expiry_native(uint32_t step,uint64_t slot,std::span<const unsigned char> indices)
    {
        if (step == 1000) {
            const int result = slot;
            const auto fail = [&]() -> bool {
                switch (result / 256) {
                case 0:
                    if (result == 0) return true;
                    throw std::logic_error("invalid replay expiry result");
                case 1: return SetError(error, strprintf("parent proposal height is ahead of replay height for slot %u", result%256));
                case 2: return SetError(error, strprintf("parent proposal has more votes than elapsed blocks for slot %u", result%256));
                case 3: return SetError(error, "M3 proposal height is ahead of replay height");
                default: throw std::logic_error("invalid replay expiry result");
                }
            };
            fail(); return {};
        }
        std::vector<unsigned char> rows;
        if (step == 0) {
            rows = {configured_slot,static_cast<unsigned char>(!state.active_proposal_hash.IsNull())};
            for (const auto& [number,entry] : state.other_slots)
                rows.insert(rows.end(),{number,static_cast<unsigned char>(!entry.active_proposal_hash.IsNull())});
        } else {
            if (slot > 255) throw std::logic_error("invalid replay expiry slot");
            switch (step) {
            case 1:
                for (const auto& [hash,entry] : SlotPendingProposals(state,slot,configured_slot)) {
                    const auto offset = rows.size();
                    rows.resize(offset+8);
                    WriteLE32(rows.data()+offset,entry.proposal_height);
                    WriteLE32(rows.data()+offset+4,entry.votes);
                }
                break;
            case 2: erase_indices(SlotPendingProposals(state,slot,configured_slot),indices); break;
            case 3:
                for (const auto& entry : SlotPendingWithdrawals(state,slot,configured_slot)) {
                    const auto offset = rows.size();
                    rows.resize(offset+4);
                    WriteLE32(rows.data()+offset,entry.proposal_height);
                }
                break;
            case 4: erase_indices(SlotPendingWithdrawals(state,slot,configured_slot),indices); break;
            default: throw std::logic_error("invalid replay expiry action");
            }
        }
        return rows;
    }
    struct CtipChange {
        uint8_t slot;
        uint32_t output_index;
        CAmount old_value;
        CAmount new_value;
    };
    struct TreasuryContext {
        const Bitcoin::CTransaction& transaction;
        std::vector<uint8_t> active_slots;
        std::set<uint8_t> active_set;
        std::map<Bitcoin::COutPoint,uint8_t> ctip_owner;
        std::set<uint8_t> ctip_spends;
        std::map<uint8_t,uint32_t> new_ctips;
        std::vector<CtipChange> changes;
        size_t decreases{0}, owner_index{0};
        uint8_t owner_slot{0}, output_slot{0}, m6_slot{0}, parsed_slot{0};
        std::optional<Bitcoin::COutPoint>* owner_ctip{nullptr};
        CAmount* owner_value{nullptr};
        std::map<Bitcoin::COutPoint,uint8_t>::iterator owner{ctip_owner.end()}, replacement{ctip_owner.end()};
        std::map<uint8_t,uint32_t>::iterator change_entry{new_ctips.end()};
        CtipChange next_change{};
        const CtipChange* change{nullptr};
        uint256 m6id;
        std::vector<DrivechainPendingWithdrawal>* pending{nullptr};
        std::vector<DrivechainPendingWithdrawal>::iterator approved;
        std::vector<unsigned char> address;
        std::optional<ParentScriptReader> address_reader;
        explicit TreasuryContext(const Bitcoin::CTransaction& tx) : transaction(tx) {}
    };
    std::optional<TreasuryContext> transaction_state;
    std::vector<unsigned char> treasury_native(uint32_t step,uint64_t index,std::span<const unsigned char> input)
    {
        if (step == 1000) return words({block.vtx.size(),uint64_t(state.required_proposal_activated) |
            (uint64_t(state.active_proposal_hash == required_active_proposal) << 1),MAX_MONEY});
        if (step == 1001) {
            auto& tx = transaction_state.emplace(*block.vtx.at(index));
            auto fields = words({tx.transaction.vin.size(),tx.transaction.vout.size()});
            fields.insert(fields.end(),{configured_slot,static_cast<unsigned char>(!state.active_proposal_hash.IsNull())});
            for (const auto& [slot,entry] : state.other_slots)
                fields.insert(fields.end(),{slot,static_cast<unsigned char>(!entry.active_proposal_hash.IsNull())});
            return fields;
        }
        auto& tx = transaction_state.value();
        switch (step) {
        case 1002:
            tx.active_slots.assign(input.begin(),input.end());
            tx.active_set.insert(input.begin(),input.end());
            return {};
        case 1003: {
            const auto& script = tx.transaction.vout.at(index).scriptPubKey;
            return {script.begin(),script.end()};
        }
        case 1004: case 1005:
            if (index > 255) throw std::logic_error("invalid treasury slot publication");
            (step == 1004 ? tx.output_slot : tx.parsed_slot) = index;
            return {};
        case 1006:
            tx.address_reader.emplace(ParentScriptReader{tx.transaction.vout.at(tx.change->output_index+1).scriptPubKey,
                tx.address,{}, {}, {}});
            return {};
        case 1007: return words({tx.address_reader.value().Action(index)});
        case 1008: {
            const int result = index;
            const auto fail = [&]() -> bool {
                switch (result) {
                case 0: return true;
                case 0x101: return SetError(error, strprintf("malformed CTIP state for slot %u", tx.owner_slot));
                case 0x102: return SetError(error, "two drivechain slots share one canonical CTIP");
                case 0x201: return SetError(error, strprintf("parent transaction spends slot %u CTIP more than once", tx.owner->second));
                case 0x301: return SetError(error, strprintf("invalid treasury value for slot %u", tx.output_slot));
                case 0x302: return SetError(error, strprintf("parent transaction creates multiple treasury outputs for slot %u", tx.output_slot));
                case 0x401: return SetError(error, strprintf("parent transaction spends slot %u CTIP without replacement", tx.replacement->second));
                case 0x501: return SetError(error, strprintf("parent transaction creates a parallel treasury output for slot %u", tx.next_change.slot));
                case 0x502: return SetError(error, strprintf("slot %u CTIP replacement has zero value delta", tx.next_change.slot));
                case 0x601: return SetError(error, "parent transaction ambiguously mixes M5 and M6 transitions");
                case 0x602: return SetError(error, "BIP300 M6 must have one input and treasury vout 0");
                case 0x604: return SetError(error, "BIP300 M6 slot changed while deriving its blinded id");
                case 0x605: return SetError(error, strprintf("BIP300 M6 %s was never proposed for slot %u", tx.m6id.GetHex(), tx.change->slot));
                case 0x606: return SetError(error, strprintf("BIP300 M6 %s has %u votes, requiring more than %u", tx.m6id.GetHex(), tx.approved->votes, withdrawal_bundle_inclusion_threshold));
                case 0x607: return SetError(error, strprintf("parent block contains multiple successful M6 withdrawals for configured slot %u", configured_slot));
                case 0x701: return SetError(error, strprintf("positive CTIP replacement for slot %u has no following address", tx.change->slot));
                case 0x702: return SetError(error, "parent CTIP increase is outside the money range");
                case 0x901: case 0x902: case 0x903: case 0x904: case 0x905: case 0x906:
                    return DrivechainM6IdResult(result-0x900,error);
                default: throw std::logic_error("invalid treasury transaction result");
                }
            };
            fail(); return {};
        }
        default: break;
        }
        const auto action = [&]() -> int64_t {
            if (step >= 901 && step <= 906 && step != 902)
                return DrivechainM6IdNativeAction(tx.transaction,tx.m6id,tx.parsed_slot,&tx.m6_slot,step-900,index);
            switch (step) {
            case 0:
                switch (index) {
                case 0: tx.replacement = tx.ctip_owner.begin(); return tx.ctip_owner.size();
                case 1: tx.change_entry = tx.new_ctips.begin(); return tx.new_ctips.size();
                case 2: return tx.changes.size();
                case 3: return tx.decreases;
                case 4: return tx.change->old_value;
                case 5: return tx.change->new_value;
                case 6: return tx.change->output_index;
                case 7: return (deposits != nullptr ? 1U : 0U) | (tx.change->slot == configured_slot ? 2U : 0U);
                default: throw std::logic_error("invalid treasury transaction fact");
                }
            case 101:
                tx.owner_slot = tx.active_slots[tx.owner_index];
                tx.owner_ctip = &SlotCtip(state, tx.owner_slot, configured_slot);
                tx.owner_value = &SlotCtipValue(state, tx.owner_slot, configured_slot);
                return tx.owner_ctip->has_value();
            case 102: return *tx.owner_value;
            case 103: return tx.ctip_owner.emplace(**tx.owner_ctip, tx.owner_slot).second;
            case 104: ++tx.owner_index; return 1;
            case 202: tx.owner = tx.ctip_owner.find(tx.transaction.vin[index].prevout); return tx.owner != tx.ctip_owner.end();
            case 203: return tx.ctip_spends.insert(tx.owner->second).second ? 1 : 2;
            case 303: return tx.active_set.count(tx.output_slot) != 0;
            case 304: return tx.transaction.vout[index].nValue;
            case 305: return tx.new_ctips.emplace(tx.output_slot, static_cast<uint32_t>(index)).second;
            case 401: return tx.ctip_spends.contains(tx.replacement->second);
            case 402: return tx.new_ctips.count(tx.replacement->second) != 0;
            case 403: ++tx.replacement; return 1;
            case 501:
                tx.next_change.slot = tx.change_entry->first;
                tx.next_change.output_index = tx.change_entry->second;
                return SlotCtip(state, tx.next_change.slot, configured_slot).has_value();
            case 502: return tx.ctip_spends.contains(tx.next_change.slot);
            case 503: return tx.next_change.old_value = SlotCtipValue(state, tx.next_change.slot, configured_slot);
            case 504: tx.next_change.old_value = 0; return 1;
            case 505: return tx.next_change.new_value = tx.transaction.vout[tx.next_change.output_index].nValue;
            case 506: ++tx.decreases; return 1;
            case 507: tx.changes.push_back(tx.next_change); ++tx.change_entry; return 1;
            case 601: tx.change = &tx.changes.front(); return tx.change->output_index;
            case 603: return tx.m6_slot == tx.change->slot;
            case 604:
                tx.pending = &SlotPendingWithdrawals(state, tx.change->slot, configured_slot);
                tx.approved = std::find_if(tx.pending->begin(), tx.pending->end(), [&](const auto& entry) { return entry.m6id == tx.m6id; });
                return tx.approved != tx.pending->end();
            case 605: return tx.approved->votes;
            case 606: return tx.change->slot == configured_slot;
            case 609: derived_withdrawals.push_back(DrivechainSuccessfulWithdrawal{tx.change->slot, tx.m6id, height, block.GetHash()}); return 1;
            case 610: tx.pending->erase(tx.approved); return 1;
            case 611: case 702: SlotCtip(state, tx.change->slot, configured_slot) = Bitcoin::COutPoint(tx.transaction.GetHash(), tx.change->output_index); return 1;
            case 612: case 703: SlotCtipValue(state, tx.change->slot, configured_slot) = tx.change->new_value; return 1;
            case 704: return tx.address.size();
            case 705: deposits->push_back(DrivechainMintableDeposit{*state.ctip, block.GetHash(), height, static_cast<CAmount>(index), std::move(tx.address)}); return 1;
            case 800: tx.change = &tx.changes.at(index); tx.address.clear(); return 1;
            default: throw std::logic_error("invalid treasury transaction action");
            }
        };
        return words({static_cast<uint64_t>(action())});
    }
    std::vector<unsigned char> publication_native(uint32_t step,uint64_t,std::span<const unsigned char> retired)
    {
        if (step == 1000) return words({uint64_t(state.required_proposal_activated) |
            (uint64_t(state.active_proposal_hash == required_active_proposal) << 1) |
            (uint64_t(successful_withdrawals != nullptr) << 2) | (uint64_t(withdrawal_proposals != nullptr) << 3)});
        if (step >= 21 && step <= 29)
            return {static_cast<unsigned char>(DrivechainParentDeadlineAction(step-20))};
        std::vector<unsigned char> rows;
        switch (step) {
        case 10:
            for (const auto& [slot,entry] : state.other_slots) {
                const unsigned char occupied = (!entry.active_proposal_hash.IsNull() ? 1 : 0) |
                    (!entry.pending_proposals.empty() ? 2 : 0) | (!entry.pending_withdrawals.empty() ? 4 : 0) |
                    (entry.ctip.has_value() ? 8 : 0) | (entry.ctip_value != 0 ? 16 : 0) |
                    (state.previous_m4_actions.count(slot) != 0 ? 32 : 0);
                rows.insert(rows.end(),{slot,occupied});
            }
            break;
        case 11: for (const auto slot : retired) state.other_slots.erase(slot); break;
        case 12: *successful_withdrawals = std::move(derived_withdrawals); break;
        case 13: *withdrawal_proposals = std::move(derived_proposals); break;
        default: throw std::logic_error("invalid replay publication action");
        }
        return rows;
    }

    std::vector<unsigned char> operator()(uint32_t step, uint64_t index, std::span<const unsigned char> input)
    {
        if (step == 20480) {
            if (index != 0 || !input.empty()) throw std::logic_error("invalid parent block parameters request");
            const uint64_t settings = uint64_t(unused_slot_proposal_max_age) |
                (uint64_t(unused_slot_activation_threshold) << 16) |
                (uint64_t(used_slot_proposal_max_age) << 32) |
                (uint64_t(used_slot_activation_threshold) << 48);
            return ParentReplayBytes(height, settings, uint32_t{withdrawal_bundle_max_age},
                uint32_t{withdrawal_bundle_inclusion_threshold}, static_cast<uint32_t>(treasury_opcode),
                uint32_t{m6_rule == DrivechainM6ReplayRule::SINGLE_CONFIGURED_SLOT_M6});
        }
        if (step == 20481) {
            if (!input.empty()) throw std::logic_error("invalid parent block completion request");
            switch (index) {
            case 0: case 1: return ParentReplayBytes(index == 0);
            case 3: throw std::runtime_error("Haskell M2 activation failed");
            case 4: throw std::runtime_error("Haskell M3 proposal admission failed");
            case 5: throw std::runtime_error("Haskell M4 workflow failed");
            default: throw std::runtime_error("Haskell parent block replay failed");
            }
        }
        switch (step/4096) {
        case 0: return prelude_native(step%4096,index,input);
        case 1: return message_native(step%4096,index,input);
        case 2: return expiry_native(step%4096,index,input);
        case 3: return treasury_native(step%4096,index,input);
        case 4: return publication_native(step%4096,index,input);
        default: throw std::logic_error("invalid parent block effect family");
        }
    }
};
} // namespace

DrivechainReplayEffects MakeDrivechainParentBlockEffects(
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
    auto native = std::make_shared<NativeParentBlock>(
        block, height, sidechain_slot, required_active_proposal,
        unused_slot_proposal_max_age, unused_slot_activation_threshold,
        used_slot_proposal_max_age, used_slot_activation_threshold,
        withdrawal_bundle_max_age, withdrawal_bundle_inclusion_threshold,
        state, deposits, error, successful_withdrawals, withdrawal_proposals, treasury_opcode, m6_rule);
    return [native](uint32_t step, uint64_t index, std::span<const unsigned char> input) {
        return (*native)(step,index,input);
    };
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
    const auto preflight = hs::RunReplayStore(hs::ReplayStoreWorkflow::DEPOSIT_ADMISSION,
        [&](uint32_t step, uint64_t index, std::span<const unsigned char> input) -> std::vector<unsigned char> {
        if (index != 0 || (step != 4 && !input.empty())) throw std::logic_error("invalid deposit admission request");
        switch (step) {
        case 0: if (error) error->clear(); return {};
        case 1: {
            const auto& slot = Params().GetConsensus().drivechain_slot;
            return ParentReplayBytes(slot.has_value(), slot.value_or(0), int32_t{sidechain_slot}, value, uint64_t{address.size()});
        }
        case 2:
            config = &Params().GetConsensus();
            return ParentReplayBytes(config->drivechain_proposal_hash.has_value(), config->drivechain_proposal_hash.value_or(uint256{}),
                config->drivechain_protocol_manifest_hash, config->drivechain_parent_state_hash, config->drivechain_parent_state_chainwork,
                config->drivechain_parent_state_active_proposal_description, config->drivechain_parent_state_active_proposal_hash.value_or(uint256{}),
                config->drivechain_parent_state_proposal_height, config->drivechain_parent_state_proposal_block_hash,
                config->drivechain_parent_state_activation_height, config->drivechain_parent_state_activation_block_hash,
                config->drivechain_parent_state_height, config->drivechain_parent_state_ctip_txid,
                config->drivechain_parent_state_ctip_vout, config->drivechain_parent_state_ctip_value,
                config->drivechain_unused_slot_proposal_max_age, config->drivechain_unused_slot_activation_threshold,
                config->drivechain_used_slot_proposal_max_age, config->drivechain_used_slot_activation_threshold,
                config->drivechain_withdrawal_bundle_max_age, config->drivechain_withdrawal_bundle_inclusion_threshold,
                config->drivechain_m6_withdrawal_validation, config->drivechain_parent_state_replay_version,
                uint32_t{ElementsDrivechainIdentity::PARENT_REPLAY_VERSION});
        case 3: return ParentReplayBytes(Hash(config->drivechain_parent_state_active_proposal_description));
        case 4: if (error) error->assign(input.begin(),input.end()); return {};
        default: throw std::logic_error("invalid deposit admission action");
        }
    });
    if (preflight != 0) return static_cast<DrivechainDepositStatus>(preflight);
    const auto& consensus = *config;

    try {
        std::unique_lock<std::mutex> lock(
            g_drivechain_parent_replay_mutex, std::defer_lock);
        auto& cache = g_drivechain_parent_replay_cache;
        std::optional<DrivechainMintableDeposit> deposit;
        DrivechainReplayEffects lookup;
        uint256 active_cache_hash;
        ParentNetworkNative parent{&consensus, nullptr, &g_drivechain_parent_replay_published_epoch,
            0, active_cache_hash, error};
        return static_cast<DrivechainDepositStatus>(hs::RunReplayStore(hs::ReplayStoreWorkflow::CONFIRMED_DEPOSIT,
            [&](uint32_t step, uint64_t index, std::span<const unsigned char> input) -> std::vector<unsigned char> {
            if ((step >= 200 && step <= 245) || (step >= 1200 && step <= 1760)) {
                parent.height = cache.height;
                return parent(step-200,index,input);
            }
            if (step >= 100 && step <= 143) {
                if (!lookup) throw std::logic_error("deposit lookup session not opened");
                return lookup(step-100,index,input);
            }
            if ((step != 14 && index != 0) || (step != 15 && !input.empty()))
                throw std::logic_error("invalid confirmed deposit request");
            switch (step) {
            case 0: return ParentReplayBytes(DrivechainParentBudgetActive());
            case 1: return ParentReplayBytes(lock.try_lock());
            case 2: lock.lock(); break;
            case 3: return ParentCacheSnapshotBytes(cache, cache.epoch);
            case 4:
                if (!g_drivechain_parent_budget.replay_snapshot_authenticated) return {0};
                return ParentReplayBytes(true, g_drivechain_parent_budget.replay_snapshot_height,
                    g_drivechain_parent_budget.replay_snapshot_epoch, g_drivechain_parent_budget.replay_snapshot_is_explicit_target);
            case 5: return ParentReplayBytes(bool(g_drivechain_parent_replay_store));
            case 6:
                deposit.emplace();
                lookup = g_drivechain_parent_replay_store->DepositEffects(
                    Bitcoin::COutPoint(outpoint.hash, outpoint.n), *deposit, error);
                break;
            case 7: return ParentReplayBytes(*deposit, mainchain_block_hash, value, address);
            case 8: return PeginConfirmationSnapshot(Params(), child_height);
            case 9: return ParentReplayBytes(true, active_cache_hash);
            case 10: g_drivechain_parent_replay_published_epoch.store(0, std::memory_order_release); break;
            case 11: cache = {}; break;
            case 12: g_drivechain_parent_replay_store_rebuild_required = true; break;
            case 13: RecordDrivechainReplaySnapshot(cache.height, cache.hash, cache.epoch, false); break;
            case 14:
                CheckDrivechainParentDeadline();
                if (index == 0 || index != GetDrivechainParentReplayEpoch())
                    throw std::runtime_error("authenticated parent replay epoch revoked during deposit validation");
                break;
            case 15: if (error) error->assign(input.begin(),input.end()); break;
            case 16: return ParentCacheKeyBytes(consensus);
            case 17: lookup = {}; break;
            case 18: return ParentReplayBytes(GetDrivechainParentReplayEpoch());
            default: throw std::logic_error("invalid confirmed deposit action");
            }
            return {};
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
    std::vector<DrivechainMintableDeposit> page;
    DrivechainReplayEffects scan;
    return drivechain::haskell::RunReplayStore(drivechain::haskell::ReplayStoreWorkflow::DEPOSIT_CANDIDATES,
        [&](uint32_t step, uint64_t index, std::span<const unsigned char> input) -> std::vector<unsigned char> {
        if (step >= 100 && step <= 143) {
            if (!scan) throw std::logic_error("deposit scan session not opened");
            return scan(step-100, index, input);
        }
        if ((index && step != 9 && step != 10) || (!input.empty() && step != 11))
            throw std::logic_error("invalid deposit candidates request");
        switch (step) {
        case 0: return ParentReplayBytes(lock.owns_lock());
        case 1: return ParentCacheSnapshotBytes(cache, cache.epoch);
        case 2: return ParentCacheKeyBytes(Params().GetConsensus());
        case 3: return ParentReplayBytes(bool(g_drivechain_parent_replay_store));
        case 4: return ParentReplayBytes(GetDrivechainParentReplayEpoch());
        case 5:
            scan = g_drivechain_parent_replay_store->ListDepositEffects(after, 64, page, next, error);
            return ParentReplayBytes(uint64_t{MAX_MONEY});
        case 6: scan = {}; break;
        case 7: return PeginConfirmationSnapshot(Params(), child_height);
        case 8: return ParentReplayBytes(uint64_t{page.size()});
        case 9: return ParentReplayBytes(page.at(index).block_height);
        case 10: deposits.push_back(std::move(page.at(index))); break;
        case 11: if (error) error->assign(input.begin(), input.end()); break;
        default: throw std::logic_error("invalid deposit candidates action");
        }
        return {};
    });
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
    ParentNetworkNative native{nullptr, nullptr, nullptr, height, hash, error};
    return drivechain::haskell::RunReplayStore(drivechain::haskell::ReplayStoreWorkflow::ACTIVE_HASH,
        std::ref(native));
}

bool ReadActiveMainchainHeight(uint32_t& height, std::string* error)
{
    UniValue params(UniValue::VARR);
    const UniValue result = CallMainChainRPCChecked("getblockcount", params);
    return ParseDrivechainParentHeight(result, height, error);
}

struct NativeReplayMilestone {
    const Consensus::Params& consensus;
    uint32_t height;
    const Bitcoin::CBlock& block;
    const DrivechainParentReplayState& state;
    std::string* error;
    NativeCoinbaseReader reader{block};

    std::vector<unsigned char> operator()(uint32_t step, uint64_t index, std::span<const unsigned char> input)
    {
        if (!input.empty() && step != 8) throw std::logic_error("invalid milestone request");
        switch (step) {
        case 0: return ParentReplayBytes(height, consensus.drivechain_parent_state_active_proposal_description,
            consensus.drivechain_slot.has_value(), consensus.drivechain_slot.value_or(0),
            consensus.drivechain_parent_state_active_proposal_hash.has_value(),
            consensus.drivechain_parent_state_active_proposal_hash.value_or(uint256{}),
            consensus.drivechain_parent_state_proposal_height, consensus.drivechain_parent_state_proposal_block_hash,
            consensus.drivechain_parent_state_activation_height, consensus.drivechain_parent_state_activation_block_hash,
            consensus.drivechain_parent_state_height, consensus.drivechain_parent_state_hash,
            consensus.drivechain_parent_state_ctip_txid, consensus.drivechain_parent_state_ctip_vout,
            consensus.drivechain_parent_state_ctip_value);
        case 1: return ParentReplayBytes(block.GetHash());
        case 2: case 3: case 4: return reader(step-2,index);
        case 5: {
            const auto found = state.pending_proposals.find(consensus.drivechain_parent_state_active_proposal_hash.value());
            if (found == state.pending_proposals.end()) return {0};
            return ParentReplayBytes(true, found->second);
        }
        case 6: return ParentReplayBytes(state.active_proposal_hash);
        case 7:
            return state.ctip ? ParentReplayBytes(true, *state.ctip, state.ctip_value) : ParentReplayBytes(false, state.ctip_value);
        case 8: SetError(error, std::string(input.begin(), input.end())); return {};
        default: throw std::logic_error("invalid milestone effect");
        }
    }
};

} // namespace

bool CheckDrivechainParentReplayMilestone(
    const Consensus::Params& consensus,
    const uint32_t height,
    const Bitcoin::CBlock& block,
    const DrivechainParentReplayState& state,
    std::string* error)
{
    NativeReplayMilestone native{consensus, height, block, state, error};
    return drivechain::haskell::RunReplayStore(drivechain::haskell::ReplayStoreWorkflow::MILESTONE,
        [&](uint32_t step, uint64_t index, std::span<const unsigned char> input) { return native(step,index,input); });
}

namespace {
struct NativeReplayIdentity {
    const Consensus::Params& consensus;
    std::optional<HashWriter> writer;
    uint256 identity;

    uint32_t operator()(uint32_t step)
    {
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
    }
};

struct NativeBootstrapPreimage {
    HashWriter& writer;
    const Consensus::Params& consensus;
    std::span<const ElementsDrivechainBootstrap::Slot> slots;
    size_t index{0};
    uint256 active, ctip_hash;
    bool has_ctip{false};

    uint32_t operator()(uint32_t step)
    {
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
    }
};
} // namespace

uint256 DrivechainParentReplayStoreIdentity(const Consensus::Params& consensus)
{
    NativeReplayIdentity native{consensus, {}, {}};
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::IDENTITY,
        [&](uint32_t step) { return native(step); });
    return native.identity;
}

void WriteDrivechainBootstrapPreimage(HashWriter& writer, const Consensus::Params& consensus,
    std::span<const ElementsDrivechainBootstrap::Slot> slots)
{
    NativeBootstrapPreimage native{writer, consensus, slots, 0, {}, {}, false};
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::BOOTSTRAP_PREIMAGE,
        [&](uint32_t step) { return native(step); });
}

namespace {
struct NativeCacheInitialization {
    NativeCacheInitialization(DrivechainParentReplayCache& value, std::string* diagnostic, bool force)
        : cache(value), error(diagnostic), force_rebuild(force) {}
    DrivechainParentReplayCache& cache;
    std::string* error;
    bool force_rebuild;
    const Consensus::Params& consensus{Params().GetConsensus()};
    uint256 active_genesis, store_identity, expected_bootstrap_commitment, ctip_hash;
    std::optional<Bitcoin::CBlock> checkpoint_block, genesis_block;
    std::optional<VerifiedMainchainHeader> checkpoint_header;
    NativeReplayIdentity identity{consensus, {}, {}};
    struct CachedTip {
        std::optional<DrivechainParentReplayTip> tip;
        std::optional<std::string> error;
    };
    std::optional<CachedTip> loaded;
    std::optional<HashWriter> bootstrap_writer;
    std::optional<NativeBootstrapPreimage> preimage;
    std::optional<DrivechainParentReplayState> bootstrap_state, genesis_state;
    std::optional<DrivechainOtherSlotReplayState> other;
    size_t index{0};
    std::optional<DrivechainParentReplayTip> seed;
    DrivechainReplayEffects store_effects;
    DrivechainReplayEffects block_effects;

    std::vector<unsigned char> operator()(uint32_t step, uint64_t argument, std::span<const unsigned char> input)
    {
        if (step >= 1000 && step <= 21481) {
            if (!block_effects) throw std::logic_error("genesis replay session not opened");
            return block_effects(step-1000,argument,input);
        }
        if (step >= 100 && step <= 143) {
            if (!store_effects) throw std::logic_error("replay store session not opened");
            return store_effects(step-100,argument,input);
        }
        if ((step != 10 && argument != 0) || argument > UINT32_MAX || (step != 5 && !input.empty()))
            throw std::logic_error("invalid cache initialization request");
        switch (step) {
        case 0: return ParentReplayBytes(consensus.drivechain_slot.has_value(), consensus.drivechain_slot.value_or(0),
            consensus.drivechain_proposal_hash.has_value(), consensus.drivechain_proposal_hash.value_or(uint256{}),
            consensus.drivechain_parent_state_active_proposal_hash.value_or(uint256{}), consensus.drivechain_parent_state_hash,
            consensus.drivechain_unused_slot_proposal_max_age, consensus.drivechain_unused_slot_activation_threshold,
            consensus.drivechain_used_slot_proposal_max_age, consensus.drivechain_used_slot_activation_threshold,
            consensus.drivechain_withdrawal_bundle_max_age, consensus.drivechain_withdrawal_bundle_inclusion_threshold,
            consensus.drivechain_parent_state_replay_version, consensus.drivechain_proposal_description,
            consensus.drivechain_protocol_manifest_hash, consensus.drivechain_parent_state_active_proposal_description,
            consensus.drivechain_parent_state_proposal_height, consensus.drivechain_parent_state_proposal_block_hash,
            consensus.drivechain_parent_state_activation_height, consensus.drivechain_parent_state_activation_block_hash,
            consensus.drivechain_parent_state_height, consensus.drivechain_parent_state_chainwork,
            consensus.drivechain_parent_state_ctip_txid, consensus.drivechain_parent_state_ctip_vout,
            consensus.drivechain_parent_state_ctip_value, Params().ParentGenesisBlockHash(),
            consensus.drivechain_m6_withdrawal_validation, uint32_t{ElementsDrivechainIdentity::PARENT_REPLAY_VERSION}, uint64_t{MAX_MONEY});
        case 1: return ParentReplayBytes(Hash(consensus.drivechain_proposal_description));
        case 2: return ParentReplayBytes(Hash(consensus.drivechain_parent_state_active_proposal_description));
        case 3:
            if (!ReadActiveMainchainHash(0, active_genesis, error)) return {0};
            return ParentReplayBytes(true, active_genesis);
        case 4:
            checkpoint_block.emplace();
            checkpoint_header.emplace();
            if (!ReadVerifiedMainchainBlock(consensus.drivechain_parent_state_hash, 1, *checkpoint_block, *checkpoint_header, error)) return {0};
            return ParentReplayBytes(true, checkpoint_header->height, checkpoint_header->chainwork);
        case 5: SetError(error, std::string(input.begin(), input.end())); return {};
        case 10: return ParentReplayBytes(Action(static_cast<uint32_t>(argument)));
        case 11: return ParentReplayBytes(consensus.drivechain_parent_state_height,
            consensus.drivechain_parent_state_active_proposal_description, consensus.drivechain_parent_state_ctip_txid,
            cache.proposal_hash, loaded->tip->height, loaded->tip->state.active_proposal_hash,
            loaded->tip->state.required_proposal_activated, loaded->tip->state.required_activation_block_hash,
            loaded->tip->state.required_activation_height, loaded->tip->state.ctip.has_value());
        case 12: return ParentReplayBytes(expected_bootstrap_commitment);
        case 13: return ParentReplayBytes(bootstrap_writer->GetHash());
        case 14: return ParentReplayBytes(cache.slot, uint64_t{ElementsDrivechainBootstrap::SLOTS.size()});
        case 15: {
            if (index >= ElementsDrivechainBootstrap::SLOTS.size()) throw std::logic_error("bootstrap slot index out of range");
            const auto& slot = ElementsDrivechainBootstrap::SLOTS[index];
            return ParentReplayBytes(slot.slot, slot.active != nullptr, slot.ctip_txid != nullptr);
        }
        case 16: return ParentReplayBytes(other->active_proposal_hash);
        case 17: return ParentReplayBytes(ctip_hash, ElementsDrivechainBootstrap::SLOTS[index].ctip_vout,
            ElementsDrivechainBootstrap::SLOTS[index].ctip_value);
        case 18: return ParentReplayBytes(genesis_block->hashPrevBlock);
        case 19:
            loaded->tip.emplace();
            loaded->error.emplace();
            store_effects = g_drivechain_parent_replay_store->LoadEffects(store_identity, *loaded->tip, &*loaded->error);
            return ParentReplayBytes(uint64_t{MAX_MONEY});
        case 20: store_effects = {}; return {};
        case 21:
            seed.emplace(DrivechainParentReplayTip{cache.height, cache.hash, cache.state});
            store_effects = g_drivechain_parent_replay_store->ResetEffects(store_identity, *seed, error);
            return ParentReplayBytes(uint64_t{MAX_MONEY});
        case 22: store_effects = {}; seed.reset(); return {};
        case 23:
            block_effects = MakeDrivechainParentBlockEffects(
                *genesis_block, 0, cache.slot, cache.proposal_hash,
                cache.unused_proposal_max_age, cache.unused_activation_threshold,
                cache.used_proposal_max_age, cache.used_activation_threshold,
                cache.withdrawal_bundle_max_age, cache.withdrawal_bundle_inclusion_threshold,
                *genesis_state, nullptr, error, nullptr, nullptr,
                drivechain::FROZEN_PARENT_RULES.treasury_opcode, drivechain::FROZEN_PARENT_RULES.m6);
            return block_effects(20480,0,{});
        case 24: block_effects = {}; return {};
        default: throw std::logic_error("invalid cache initialization operation");
        }
    }

    int64_t Action(uint32_t step)
    {
        if (step >= 601 && step <= 638) return identity(step - 600);
        if (step >= 701 && step <= 718) return (*preimage)(step - 700);
        switch (step) {
        case 101: cache = {}; return 1;
        case 102: cache.initialized = true; return 1;
        case 103: cache.epoch = ++g_drivechain_parent_replay_epoch_counter; return 1;
        case 104: cache.slot = *consensus.drivechain_slot; return 1;
        case 105: cache.proposal_hash = *consensus.drivechain_proposal_hash; return 1;
        case 106: cache.checkpoint_active_proposal_hash = consensus.drivechain_parent_state_active_proposal_hash.value_or(uint256{}); return 1;
        case 107: cache.checkpoint_hash = consensus.drivechain_parent_state_hash; return 1;
        case 108: cache.unused_proposal_max_age = consensus.drivechain_unused_slot_proposal_max_age; return 1;
        case 109: cache.unused_activation_threshold = consensus.drivechain_unused_slot_activation_threshold; return 1;
        case 110: cache.used_proposal_max_age = consensus.drivechain_used_slot_proposal_max_age; return 1;
        case 111: cache.used_activation_threshold = consensus.drivechain_used_slot_activation_threshold; return 1;
        case 112: cache.withdrawal_bundle_max_age = consensus.drivechain_withdrawal_bundle_max_age; return 1;
        case 113: cache.withdrawal_bundle_inclusion_threshold = consensus.drivechain_withdrawal_bundle_inclusion_threshold; return 1;
        case 114: cache.replay_version = consensus.drivechain_parent_state_replay_version; return 1;
        case 200: loaded.emplace(); return 1;
        case 201: return g_drivechain_parent_replay_store != nullptr;
        case 202:
            g_drivechain_parent_replay_store = std::make_unique<DrivechainParentReplayStore>(
                gArgs.GetDataDirNet() / drivechain::PARENT_REPLAY_DIRECTORY,
                DRIVECHAIN_PARENT_REPLAY_DB_CACHE_BYTES,
                /*wipe=*/gArgs.GetBoolArg("-reindex", false), drivechain::FROZEN_PARENT_RULES.history);
            return 1;
        case 204: return force_rebuild;
        case 205: return g_drivechain_parent_replay_store_rebuild_required;
        case 218: cache.height = loaded->tip->height; return 1;
        case 219: cache.hash = loaded->tip->hash; return 1;
        case 220: cache.state = std::move(loaded->tip->state); return 1;
        case 221: LogPrintf("Discarding derived parent replay index whose tip contradicts the immutable launch checkpoint\n"); return 1;
        case 224: LogPrintf("Discarding unusable derived parent replay index and rebuilding from authenticated genesis: %s\n", *loaded->error); return 1;
        case 250: loaded.reset(); return 1;
        case 301: return ElementsDrivechainBootstrap::ENABLED;
        case 302: expected_bootstrap_commitment = uint256S(ElementsDrivechainIdentity::PARENT_CHECKPOINT_BOOTSTRAP_STATE_COMMITMENT); return 1;
        case 303: bootstrap_writer.emplace(); return 1;
        case 307: cache = {}; return 1;
        case 309: bootstrap_state.emplace(); return 1;
        case 310: index = 0; return 1;
        case 317: other.emplace(); return 1;
        case 318: other->active_proposal_hash = uint256S(ElementsDrivechainBootstrap::SLOTS[index].active); return 1;
        case 322: ctip_hash = uint256S(ElementsDrivechainBootstrap::SLOTS[index].ctip_txid); return 1;
        case 324: other->ctip = Bitcoin::COutPoint(ctip_hash, ElementsDrivechainBootstrap::SLOTS[index].ctip_vout); return 1;
        case 325: other->ctip_value = ElementsDrivechainBootstrap::SLOTS[index].ctip_value; return 1;
        case 330: return bootstrap_state->other_slots.emplace(ElementsDrivechainBootstrap::SLOTS[index].slot, std::move(*other)).second;
        case 331: other.reset(); ++index; return 1;
        case 332: cache.height = consensus.drivechain_parent_state_height; return 1;
        case 333: cache.hash = consensus.drivechain_parent_state_hash; return 1;
        case 334: cache.state = std::move(*bootstrap_state); return 1;
        case 337: g_drivechain_parent_replay_store_rebuild_required = false; return 1;
        case 340: genesis_block.emplace(); return 1;
        case 341: return ReadAuthenticatedRawMainchainBlock(active_genesis, *genesis_block, error);
        case 345: genesis_state.emplace(); return 1;
        case 347: cache.height = 0; return 1;
        case 348: cache.hash = active_genesis; return 1;
        case 349: cache.state = std::move(*genesis_state); return 1;
        case 639: {
            const auto hash = identity.identity;
            identity.writer.reset();
            store_identity = hash;
            return 1;
        }
        case 700: preimage.emplace(NativeBootstrapPreimage{*bootstrap_writer, consensus,
            ElementsDrivechainBootstrap::SLOTS, 0, {}, {}, false}); return 1;
        case 719: preimage.reset(); return 1;
        default: throw std::logic_error("invalid replay cache initialization action");
        }
    }
};

uint32_t ReadReplayCacheIdentity(const DrivechainParentReplayCache& cache,
    const Consensus::Params& consensus,uint32_t step)
{
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
}

bool ReplayCacheMatchesConfiguredIdentity(const DrivechainParentReplayCache& cache,
                                          const Consensus::Params& consensus)
{
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::CACHE_MATCH,
        [&](uint32_t step) { return ReadReplayCacheIdentity(cache,consensus,step); });
}

bool EnsurePinnedDrivechainParentStateThroughLocked(const uint32_t target_height,
                                                    const uint256& target_hash,
                                                    const bool require_elements_active,
                                                    DrivechainParentReplayCache& cache,
                                                    std::string* error)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    if (!CheckDrivechainParentRpcNetwork(consensus, error)) return false;
    namespace hs = drivechain::haskell;
    std::optional<uint256> block_hash;
    std::optional<Bitcoin::CBlock> block;
    std::optional<DrivechainParentReplayState> next_state;
    std::optional<std::vector<DrivechainMintableDeposit>> deposits;
    std::optional<std::vector<DrivechainSuccessfulWithdrawal>> successful_withdrawals;
    std::optional<std::vector<DrivechainWithdrawalProposalIdentity>> withdrawal_proposals;
    std::optional<std::pair<uint256, DrivechainReplayedBmmEdge>> replayed_edge;
    std::optional<NativeReplayMilestone> milestone;
    uint256 bmm_commitment;
    std::optional<NativeBmmScan> bmm_scan;
    std::optional<NativeCacheInitialization> initialization;
    std::optional<DrivechainParentReplayTip> previous_tip, next_tip;
    DrivechainReplayEffects append_effects;
    DrivechainReplayEffects block_effects;
    return hs::RunReplayStore(hs::ReplayStoreWorkflow::CACHE,
        [&](uint32_t step, uint64_t index, std::span<const unsigned char> input) -> std::vector<unsigned char> {
            if (step >= 100 && step <= 108) {
                if (!milestone) throw std::logic_error("parent milestone not opened");
                return (*milestone)(step-100,index,input);
            }
            if (step >= 201 && step <= 206) {
                if (!bmm_scan) throw std::logic_error("parent BMM scan not opened");
                return (*bmm_scan)(step-200,index,input);
            }
            if ((step >= 300 && step <= 443) || (step >= 1300 && step <= 21781)) {
                if (!initialization) throw std::logic_error("parent cache initialization not opened");
                return (*initialization)(step-300,index,input);
            }
            if (step >= 500 && step <= 543) {
                if (!append_effects) throw std::logic_error("replay append session not opened");
                return append_effects(step-500,index,input);
            }
            if (step >= 30000 && step <= 50481) {
                if (!block_effects) throw std::logic_error("parent block session not opened");
                return block_effects(step-30000,index,input);
            }
            if (index > UINT32_MAX || (!input.empty() && step != 11 && step != 12 && step != 19))
                throw std::logic_error("invalid parent cache request");
            const auto height = static_cast<uint32_t>(index);
            switch (step) {
            case 0: return ParentCacheKeyBytes(consensus, consensus.drivechain_parent_state_height,
                target_height, target_hash, require_elements_active);
            case 1: return ParentCacheSnapshotBytes(cache);
            case 2: return ParentReplayBytes(DrivechainParentBudgetActive());
            case 3: return ParentReplayBytes(g_drivechain_parent_budget.replay_steps_remaining, error != nullptr);
            case 4: g_drivechain_parent_budget.replay_steps_remaining = height; break;
            case 5: return ParentReplayBytes(int64_t{DrivechainParentDeadlineAction(height)});
            case 6: g_drivechain_parent_replay_published_epoch.store(0, std::memory_order_release); break;
            case 7: cache = {}; break;
            case 8:
                if (index > 1) throw std::logic_error("invalid parent cache rebuild mode");
                initialization.emplace(NativeCacheInitialization{cache, error, index != 0});
                break;
            case 26: initialization.reset(); break;
            case 9: {
                uint256 hash;
                if (!ReadActiveMainchainHash(height, hash, error)) return {0};
                return ParentReplayBytes(true, hash);
            }
            case 10: {
                uint32_t active_height;
                if (!ReadActiveMainchainHeight(active_height, error)) return {0};
                return ParentReplayBytes(true, active_height);
            }
            case 11: SetError(error, std::string(input.begin(), input.end())); break;
            case 12:
                if (input.size() != 32) throw std::logic_error("invalid parent cache block hash");
                block_hash.emplace(input.data(), input.size());
                block.emplace();
                break;
            case 13: return ParentReplayBytes(ReadAuthenticatedRawMainchainBlock(*block_hash, *block, error));
            case 14: return ParentReplayBytes(block->hashPrevBlock);
            case 15:
                next_state.emplace(cache.state);
                deposits.emplace();
                successful_withdrawals.emplace();
                withdrawal_proposals.emplace();
                break;
            case 16:
                block_effects = MakeDrivechainParentBlockEffects(
                *block, height, cache.slot, cache.proposal_hash,
                consensus.drivechain_unused_slot_proposal_max_age, consensus.drivechain_unused_slot_activation_threshold,
                consensus.drivechain_used_slot_proposal_max_age, consensus.drivechain_used_slot_activation_threshold,
                consensus.drivechain_withdrawal_bundle_max_age, consensus.drivechain_withdrawal_bundle_inclusion_threshold,
                *next_state, &*deposits, error, &*successful_withdrawals, &*withdrawal_proposals,
                drivechain::FROZEN_PARENT_RULES.treasury_opcode, drivechain::FROZEN_PARENT_RULES.m6);
                return block_effects(20480,0,{});
            case 28: block_effects = {}; break;
            case 17:
                milestone.emplace(NativeReplayMilestone{consensus, height, *block, *next_state, error});
                return ParentReplayBytes(true);
            case 18: replayed_edge.reset(); break;
            case 19: {
                if (input.size() != 1 || input[0] > 1) throw std::logic_error("invalid replay BMM result");
                replayed_edge.emplace(cache.hash, DrivechainReplayedBmmEdge{
                    *block_hash, cache.height, height, input[0] != 0, bmm_commitment});
                break;
            }
            case 20: return ParentReplayBytes(bool(g_drivechain_parent_replay_store));
            case 21:
                previous_tip.emplace(DrivechainParentReplayTip{cache.height, cache.hash, cache.state});
                next_tip.emplace(DrivechainParentReplayTip{height, *block_hash, *next_state});
                append_effects = g_drivechain_parent_replay_store->AppendEffects(
                    *previous_tip, *next_tip, *deposits, replayed_edge, *successful_withdrawals, *withdrawal_proposals, error);
                return ParentReplayBytes(uint64_t{MAX_MONEY});
            case 27: append_effects = {}; next_tip.reset(); previous_tip.reset(); break;
            case 22:
                cache.state = std::move(*next_state);
                cache.height = height;
                cache.hash = *block_hash;
                break;
            case 23:
                bmm_scan.reset();
                milestone.reset();
                replayed_edge.reset();
                withdrawal_proposals.reset();
                successful_withdrawals.reset();
                deposits.reset();
                next_state.reset();
                block.reset();
                block_hash.reset();
                break;
            case 24: g_drivechain_parent_replay_published_epoch.store(cache.epoch, std::memory_order_release); break;
            case 25:
                bmm_scan.emplace(NativeBmmScan{*block, cache.slot, bmm_commitment, nullptr, nullptr, nullptr});
                bmm_scan->Reset();
                break;
            default: throw std::logic_error("invalid parent cache effect");
            }
            return {};
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
    if (!CheckDrivechainParentRpcNetwork(Params().GetConsensus(), error))
        return DrivechainParentProbeStatus::UNAVAILABLE;
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
    if (!CheckDrivechainParentRpcNetwork(Params().GetConsensus(), error)) return false;
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
    std::optional<std::unique_lock<std::mutex>> cache_lock, replay_lock;
    uint64_t replay_epoch{0}, rechecked_epoch{0}, final_replay_epoch{0};
    const uint8_t slot = static_cast<uint8_t>(sidechain_slot);
    DrivechainBmmEdgeCacheEntry* cached{nullptr};
    DrivechainBmmNegativeParentCacheEntry* rejected{nullptr};
    const DrivechainParentReplayCache* replay_cache{nullptr};
    const Consensus::Params* replay_consensus{nullptr};
    std::optional<DrivechainReplayedBmmEdge> indexed;
    DrivechainReplayStoreReadStatus indexed_status{};
    uint32_t probed_parent_height{0};
    std::optional<std::string> rejection_reason;
    DrivechainParentBlockContext parent_context;
    struct SuccessorData { Bitcoin::CBlock block; VerifiedMainchainHeader header; };
    std::optional<uint256> successor_hash;
    std::optional<SuccessorData> successor;
    std::optional<VerifiedMainchainHeader> parent;
    uint256 committed_sidechain_hash;
    std::string commitment_error;
    bool has_canonical_commitment{false}, prune_negative{false};
    size_t prune_write{0};
    std::chrono::steady_clock::time_point prune_time;
    const auto edge_at = [&](uint64_t index) -> DrivechainBmmEdgeCacheEntry& {
        if (index >= g_drivechain_bmm_edge_cache.size()) throw std::out_of_range("BMM cache index");
        return g_drivechain_bmm_edge_cache.at(g_drivechain_bmm_edge_cache.size()-1-index);
    };
    return static_cast<DrivechainBmmStatus>(hs::RunReplayStore(hs::ReplayStoreWorkflow::BMM_CONTEXT,
        [&](uint32_t step,uint64_t index,std::span<const unsigned char> input) -> std::vector<unsigned char> {
            if (!input.empty()) throw std::logic_error("invalid BMM context input");
            if (index && step != 0 && step != 10 && step != 11 && step != 12 && step != 13 && step != 14 &&
                step != 17 && step != 18 && step != 19 && step != 30 && step != 45 && step != 46 &&
                step != 47 && step != 51 && step != 59) throw std::logic_error("invalid BMM context index");
            const auto scalar = [](uint64_t value) { return ParentReplayBytes(value); };
            const auto report = [&](DrivechainBmmStatus status,const std::string& message) {
                return scalar(static_cast<uint32_t>(SetError(error,status,message)));
            };
            if (step == 0) {
                using S = DrivechainBmmStatus;
                switch (index) {
                case 1: return report(S::UNAVAILABLE,"authenticated BMM edge cache is busy");
                case 2: return report(S::UNAVAILABLE,"authenticated parent replay cache is not current");
                case 3: return report(S::UNAVAILABLE,"cached parent edge has no unique enforcer-recognized M7; await a fresh authenticated edge");
                case 4: return report(S::UNAVAILABLE,"expected critical hash does not match the cached enforcer-recognized M7; no parent RPC performed");
                case 5: return report(S::UNAVAILABLE,"parent replay epoch changed while rechecking cached BMM edge");
                case 6: return report(S::UNAVAILABLE,"authenticated parent replay index is busy warming");
                case 7: return report(S::UNAVAILABLE,"authenticated parent replay index changed during admission");
                case 8: return report(S::UNAVAILABLE,"persistent authenticated parent replay index is not open");
                case 9: return report(S::UNAVAILABLE,"committed parent edge is not in the warmed authenticated replay index");
                case 10: return report(S::UNAVAILABLE,"persistent parent replay BMM edge lies beyond its durable tip");
                case 11: return report(S::UNAVAILABLE,"candidate does not match the warmed authenticated parent-edge M7 index");
                case 12: return report(S::UNAVAILABLE,rejected->rejection_reason + "; cached briefly without parent RPC");
                case 14: return report(S::PARENT_REJECTED,*rejection_reason);
                case 15: return report(S::UNAVAILABLE,"committed parent height has no representable successor");
                case 16: return report(S::UNAVAILABLE,strprintf("active parent block %s is not the exact successor of committed parent %s",
                    successor_hash->GetHex(),parent_hash.GetHex()));
                case 17: return report(S::UNAVAILABLE,"authenticated parent replay epoch changed during BMM validation");
                case 18: return report(S::PARENT_REJECTED,commitment_error);
                case 19: return report(S::PARENT_REJECTED,strprintf("BMM successor commits to critical hash %s, expected %s",
                    committed_sidechain_hash.GetHex(),expected_critical_hash.GetHex()));
                default: throw std::logic_error("invalid BMM context diagnostic");
                }
            }
            const auto prune = [&](auto& entries) {
                switch (step) {
                case 10: return scalar(entries.size());
                case 11: return scalar(entries.at(index).replay_epoch);
                case 13:
                    if (index > entries.size()) throw std::out_of_range("BMM compaction index");
                    prune_write = index; break;
                case 14:
                    if (prune_write >= index) throw std::logic_error("invalid BMM compaction move");
                    entries.at(prune_write++) = std::move(entries.at(index)); break;
                case 15:
                    if (prune_write > entries.size()) throw std::out_of_range("BMM compaction end");
                    entries.erase(entries.begin()+prune_write,entries.end()); break;
                default: throw std::logic_error("invalid BMM compaction action");
                }
                return scalar(1);
            };
            if (step == 10) {
                if (index > 1) throw std::logic_error("invalid BMM cache selection");
                prune_negative = index == 1;
            }
            if (step == 10 || step == 11 || (step >= 13 && step <= 15))
                return prune_negative ? prune(g_drivechain_bmm_negative_parent_cache) : prune(g_drivechain_bmm_edge_cache);
            switch (step) {
            case 1: context = {}; break;
            case 2: cache_lock.emplace(g_drivechain_bmm_edge_cache_mutex,std::defer_lock); break;
            case 3: return scalar(DrivechainParentBudgetActive());
            case 4: return scalar(cache_lock->try_lock());
            case 5: cache_lock->lock(); break;
            case 6: replay_epoch = GetDrivechainParentReplayEpoch(); return scalar(replay_epoch);
            case 7: g_drivechain_bmm_edge_cache.clear(); break;
            case 8: g_drivechain_bmm_negative_parent_cache.clear(); break;
            case 9: prune_time = std::chrono::steady_clock::now(); break;
            case 12: return scalar(g_drivechain_bmm_negative_parent_cache.at(index).expires <= prune_time);
            case 16: return scalar(g_drivechain_bmm_edge_cache.size());
            case 17: return scalar(edge_at(index).parent_hash == parent_hash);
            case 18: return scalar(edge_at(index).slot == slot);
            case 19: cached = &edge_at(index); break;
            case 20: return scalar(cached->has_canonical_commitment);
            case 21: return scalar(cached->committed_sidechain_hash == expected_critical_hash);
            case 22: return scalar(RecheckActiveBmmEdge(cached->parent_hash,cached->context.parent_height,
                cached->successor_hash,cached->context.bmm_height,error));
            case 23: rechecked_epoch = GetDrivechainParentReplayEpoch(); return scalar(rechecked_epoch);
            case 24: return scalar(cached->replay_epoch);
            case 25: RecordDrivechainReplaySnapshot(cached->context.bmm_height,cached->successor_hash,rechecked_epoch,/*explicit_target=*/true); break;
            case 26: context = cached->context; break;
            case 27: return scalar(DrivechainUntrustedParentAdmissionActive());
            case 28: replay_lock.emplace(g_drivechain_parent_replay_mutex,std::defer_lock); break;
            case 29: return scalar(replay_lock->try_lock());
            case 30:
                if (index < 1 || index > 14) throw std::out_of_range("BMM replay identity index");
                if (index == 1) { replay_cache = &g_drivechain_parent_replay_cache; replay_consensus = &Params().GetConsensus(); }
                if (!replay_cache || !replay_consensus) throw std::logic_error("missing replay identity observation");
                return scalar(ReadReplayCacheIdentity(*replay_cache,*replay_consensus,index));
            case 31: return scalar(replay_cache->epoch);
            case 32: return scalar(bool(g_drivechain_parent_replay_store));
            case 33: indexed_status = g_drivechain_parent_replay_store->ReadBmmEdge(parent_hash,indexed.emplace(),error); break;
            case 34: return scalar(indexed_status == DrivechainReplayStoreReadStatus::CORRUPT);
            case 35: g_drivechain_parent_replay_published_epoch.store(0,std::memory_order_release); break;
            case 36: g_drivechain_parent_replay_cache = {}; break;
            case 37: g_drivechain_parent_replay_store_rebuild_required = true; break;
            case 38: return scalar(indexed->successor_height);
            case 39: return scalar(replay_cache->height);
            case 40: return scalar(indexed->parent_height);
            case 41: return scalar(indexed->has_canonical_commitment);
            case 42: return scalar(indexed->committed_sidechain_hash == expected_critical_hash);
            case 43: replay_lock.reset(); break;
            case 44: return scalar(g_drivechain_bmm_negative_parent_cache.size());
            case 45: return scalar(g_drivechain_bmm_negative_parent_cache.at(index).parent_hash == parent_hash);
            case 46: return scalar(g_drivechain_bmm_negative_parent_cache.at(index).slot == slot);
            case 47: rejected = &g_drivechain_bmm_negative_parent_cache.at(index); break;
            case 48: return scalar(static_cast<uint32_t>(ProbeActiveDrivechainParent(parent_hash,probed_parent_height,error)));
            case 49: return scalar(CheckDrivechainParentRpcNetwork(Params().GetConsensus(),error));
            case 50: rejection_reason.emplace(error ? *error : "committed parent hash is not on the active parent chain"); break;
            case 51:
                if (index > uint64_t{INT64_MAX}) throw std::out_of_range("BMM rejection duration");
                g_drivechain_bmm_negative_parent_cache.push_back({replay_epoch,parent_hash,slot,*rejection_reason,
                    std::chrono::steady_clock::now()+std::chrono::seconds{static_cast<int64_t>(index)}}); break;
            case 52: return scalar(g_drivechain_bmm_negative_parent_cache.size());
            case 53: g_drivechain_bmm_negative_parent_cache.pop_front(); break;
            case 54: return scalar(probed_parent_height);
            case 55: return scalar(Params().GetConsensus().drivechain_parent_state_height);
            case 56: rejection_reason.emplace(strprintf("committed parent height %u predates the Elements launch checkpoint %u",
                probed_parent_height,Params().GetConsensus().drivechain_parent_state_height)); break;
            case 57: return scalar(GetDrivechainParentContextForHash(parent_hash,parent_context,error));
            case 58: return scalar(parent_context.parent_height);
            case 59:
                if (index > uint64_t{UINT32_MAX}) throw std::out_of_range("BMM successor height");
                return scalar(ReadActiveMainchainHash(index,successor_hash.emplace(),error));
            case 60: successor.emplace(); return scalar(ReadVerifiedMainchainBlock(*successor_hash,1,successor->block,successor->header,error));
            case 61: return scalar(EnsurePinnedDrivechainParentStateThrough(successor->header.height,*successor_hash,/*require_elements_active=*/true,error));
            case 62: return scalar(successor->header.height);
            case 63: return scalar(successor->header.header.hashPrevBlock == parent_hash);
            case 64: parent.emplace(); parent->chainwork = parent_context.parent_chainwork; parent->height = parent_context.parent_height; break;
            case 65: return scalar(CheckParentChainworkStep(*parent,successor->header,error));
            case 66: has_canonical_commitment = ExtractCanonicalDrivechainBmmCommitmentInBlock(
                successor->block,sidechain_slot,committed_sidechain_hash,nullptr,&commitment_error); break;
            case 67: return scalar(RecheckActiveBmmEdge(parent_hash,parent_context.parent_height,*successor_hash,successor->header.height,error));
            case 68: static_cast<DrivechainParentBlockContext&>(context) = parent_context; break;
            case 69: return scalar(has_canonical_commitment);
            case 70: context.critical_hash = committed_sidechain_hash; break;
            case 71: context.critical_hash = uint256{}; break;
            case 72:
                context.bmm_block_hash = *successor_hash; context.bmm_chainwork = successor->header.chainwork;
                context.bmm_height = successor->header.height; break;
            case 73: final_replay_epoch = GetDrivechainParentReplayEpoch(); return scalar(final_replay_epoch);
            case 74: g_drivechain_bmm_edge_cache.push_back({final_replay_epoch,parent_hash,*successor_hash,slot,context,
                has_canonical_commitment,committed_sidechain_hash,commitment_error}); break;
            case 75: return scalar(g_drivechain_bmm_edge_cache.size());
            case 76: g_drivechain_bmm_edge_cache.pop_front(); break;
            case 77: return scalar(committed_sidechain_hash == expected_critical_hash);
            case 78: return scalar(indexed_status == DrivechainReplayStoreReadStatus::NOT_FOUND);
            default: throw std::logic_error("invalid BMM context action");
            }
            return scalar(1);
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
    const auto& consensus = Params().GetConsensus();
    if (!consensus.drivechain_slot.has_value()) return true;

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
                case 1:
                    return CheckDrivechainParentRpcNetwork(Params().GetConsensus(), error) &&
                        ReadActiveMainchainHash(anchor.parent_height, active_parent_hash, error);
                case 2: return active_parent_hash == anchor.parent_block_hash;
                // Final action results do not override ORPHANED; abort to the
                // enclosing UNAVAILABLE handler if identity changed meanwhile.
                case 3:
                    if (!CheckDrivechainParentRpcNetwork(Params().GetConsensus(), error))
                        throw std::runtime_error(error ? *error : "parent RPC network unavailable before anchor rollback");
                    return static_cast<uint32_t>(SetError(error, DrivechainAnchorStatus::ORPHANED,
                    strprintf("parent height %u now contains %s, persisted anchor contains %s",
                              anchor.parent_height, active_parent_hash.GetHex(), anchor.parent_block_hash.GetHex())));
                case 4: return ReadActiveMainchainHash(anchor.bmm_height, active_successor_hash, error);
                case 5: return active_successor_hash == anchor.bmm_block_hash;
                case 6:
                    if (!CheckDrivechainParentRpcNetwork(Params().GetConsensus(), error))
                        throw std::runtime_error(error ? *error : "parent RPC network unavailable before BMM rollback");
                    return static_cast<uint32_t>(SetError(error, DrivechainAnchorStatus::ORPHANED,
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
    if (!CheckDrivechainParentRpcNetwork(Params().GetConsensus(), error)) return false;
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

// Fork-specific drivechain_rpc_security adapters.
// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <init.h>
#include <chainparamsbase.h>
#include <mainchainrpc.h>
#include <drivechain_settings.h>
#include <haskell/bridge.h>
#include <haskell/rpc_security_constants.h>
#include <netbase.h>
#include <common/args.h>
#include <util/fs_helpers.h>
#include <util/strencodings.h>
#include <algorithm>
#include <array>
#include <fstream>
#include <limits>
#include <stdexcept>
#ifndef WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

struct DrivechainGrpcTLSConfig {
    std::string address;
    fs::path ca_certificate;
    fs::path client_certificate;
    fs::path client_key;
    std::string authority;
};

bool IsEnforcerHostAllowed(const std::string& host, bool allow_remote)
{
    if (IsMainchainRPCHostAllowed(host, /*native_drivechain=*/true)) return true;
    if (!allow_remote) return false;
    // Admit only IP literals or DNS names, never gRPC resolver URIs or paths.
    if (const auto ip = LookupHost(host, /*fAllowLookup=*/false)) {
        return ip->IsIPv4() || ip->IsIPv6();
    }
    if (host.empty() || host.size() > 253) return false;
    size_t label_start{0};
    for (size_t i = 0; i <= host.size(); ++i) {
        if (i == host.size() || host[i] == '.') {
            if (i == label_start || i - label_start > 63 ||
                host[label_start] == '-' || host[i - 1] == '-') return false;
            label_start = i + 1;
        } else if (!IsDigit(host[i]) && !(ToLower(host[i]) >= 'a' && ToLower(host[i]) <= 'z') && host[i] != '-') {
            return false;
        }
    }
    return true;
}

fs::path ResolveDrivechainGrpcCredentialPath(const ArgsManager& args,
                                             const std::string& argument,
                                             const std::string& fallback)
{
    fs::path path = fs::PathFromString(args.GetArg(argument, fallback));
    if (path.is_absolute()) return path;
    return fsbridge::AbsPathJoin(args.GetDataDirNet(), path);
}

DrivechainGrpcTLSConfig GetDrivechainGrpcTLSConfig(const ArgsManager& args)
{
    return {
        args.GetArg("-drivechainbmmgrpcaddr", DEFAULT_DRIVECHAIN_GRPC_ENDPOINT),
        ResolveDrivechainGrpcCredentialPath(
            args, "-drivechainbmmgrpcca", drivechain::GRPC_CA_FILE),
        ResolveDrivechainGrpcCredentialPath(
            args, "-drivechainbmmgrpccert", drivechain::GRPC_CLIENT_CERT_FILE),
        ResolveDrivechainGrpcCredentialPath(
            args, "-drivechainbmmgrpckey", drivechain::GRPC_CLIENT_KEY_FILE),
        args.GetArg("-drivechainbmmgrpcauthority", ""),
    };
}

bool ValidateReadableRegularFile(const fs::path& path,
                                 const bool private_key,
                                 std::string* error)
{
#ifndef WIN32
    struct stat metadata {}, parent_metadata {}, opened_metadata {};
    std::string native_path, native_parent;
    int descriptor=-1;
#endif
    try {
      return drivechain::haskell::AdmitTlsCredentialFile(private_key,[&](uint32_t action) -> uint64_t {
        switch (action) {
        case 1: {
            std::error_code status_error;
            const auto status = fs::symlink_status(path,status_error);
            if (status_error || !fs::is_regular_file(status)) return 0;
#ifdef WIN32
            return 2;
#else
            return 1;
#endif
        }
        case 2:
            if (error) *error = strprintf("required %s must be a non-symlink regular file: %s",
                private_key ? "mTLS client key" : "mTLS certificate",fs::PathToString(path));
            return 1;
#ifndef WIN32
        case 3:
            native_path = fs::PathToString(path);
            return lstat(native_path.c_str(),&metadata)==0 && S_ISREG(metadata.st_mode);
        case 4:
            if (error) *error = strprintf("mTLS credential must be a non-symlink regular file: %s",native_path);
            return 1;
        case 5: return metadata.st_uid;
        case 15: return geteuid();
        case 6:
            if (error) *error = strprintf("mTLS credential must be owned by the Elements process user: %s",native_path);
            return 1;
        case 7: {
            const auto parent_path = path.parent_path();
            native_parent = fs::PathToString(parent_path);
            return !parent_path.empty();
        }
        case 16: return lstat(native_parent.c_str(),&parent_metadata)==0 && S_ISDIR(parent_metadata.st_mode);
        case 17: return parent_metadata.st_uid;
        case 18: return geteuid();
        case 19: return parent_metadata.st_mode & (S_IWGRP | S_IWOTH);
        case 8:
            if (error) *error = strprintf(
                "mTLS credential directory must be owned by the Elements process user and deny group/other write access: %s",native_parent);
            return 1;
        case 9: return metadata.st_mode & (S_IRWXG | S_IRWXO);
        case 20: return metadata.st_mode & (S_IWGRP | S_IWOTH);
        case 10:
            if (error) *error = private_key
                ? strprintf("mTLS client key must deny all group and other access: %s",native_path)
                : strprintf("mTLS certificate must deny group and other write access: %s",native_path);
            return 1;
        case 11:
            descriptor=open(native_path.c_str(),O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
            return descriptor>=0;
        case 21: return fstat(descriptor,&opened_metadata)==0 && S_ISREG(opened_metadata.st_mode);
        case 22: return opened_metadata.st_uid;
        case 23: return geteuid();
        case 24: return opened_metadata.st_mode & (S_IRWXG | S_IRWXO);
        case 25: return opened_metadata.st_mode & (S_IWGRP | S_IWOTH);
        case 26: return opened_metadata.st_dev;
        case 27: return metadata.st_dev;
        case 28: return opened_metadata.st_ino;
        case 29: return metadata.st_ino;
        case 30:
            if (descriptor>=0) close(descriptor);
            descriptor=-1; return 1;
        case 12:
            if (error) *error = "mTLS credential could not be securely opened: " + native_path;
            return 1;
#else
        case 13: {
            std::ifstream input(path);
            return input.good();
        }
        case 14:
            if (error) *error = "required mTLS credential is not readable: " + fs::PathToString(path);
            return 1;
#endif
        default: throw std::logic_error("invalid credential validation action");
        }
      });
    } catch (...) {
#ifndef WIN32
        if (descriptor>=0) close(descriptor);
#endif
        throw;
    }
}

} // namespace

DrivechainGrpcStatus ClassifyDrivechainGrpcResult(const BoundedCommandResult& child,
    bool accept_duplicate, std::string& error)
{
    std::vector<unsigned char> input{2,static_cast<unsigned char>(
        child.cancelled | (child.started << 1) | (child.timed_out << 2) |
        (child.output_truncated << 3) | (!child.error.empty() << 4) |
        (child.exited << 5) | ((child.exit_code == 0) << 6)),static_cast<unsigned char>(accept_duplicate && child.exit_code == 6)};
    input.insert(input.end(),child.output.begin(),child.output.end());
    std::vector<unsigned char> output;
    if (!drivechain::haskell::WithdrawalBytes(drivechain::haskell::WithdrawalOp::SUBMISSION_POLICY,input,output,nullptr))
        throw std::runtime_error("Invalid Haskell gRPC result policy input");
    error.clear();
    switch (output.at(0)) {
    case 0: return DrivechainGrpcStatus::SUCCESS;
    case 4: error = "enforcer gRPC cancelled during shutdown"; break;
    case 5: error = strprintf("enforcer gRPC request rejected: %s",child.error); break;
    case 6: error = "enforcer gRPC exceeded its deadline"; break;
    case 7: error = "enforcer gRPC exceeded its output limit"; break;
    case 8: error = strprintf("enforcer gRPC transport failed: %s",child.error); break;
    case 9: error = "enforcer gRPC did not complete"; break;
    case 10:
        error = strprintf("enforcer gRPC status %d: %s",child.exit_code,child.output);
        return DrivechainGrpcStatus::NONZERO_EXIT;
    default: throw std::runtime_error("Invalid Haskell gRPC result policy response");
    }
    return DrivechainGrpcStatus::PROCESS_FAILURE;
}

bool ValidateDrivechainGrpcTLSConfig(const ArgsManager& args, std::string* error)
{
    if (error) error->clear();
    const DrivechainGrpcTLSConfig config = GetDrivechainGrpcTLSConfig(args);
    static constexpr const char* errors[]{
        "-drivechainbmmgrpcaddr must be a host:port endpoint without a URL scheme",
        "-drivechainbmmgrpcaddr contains whitespace, control characters, or excessive data",
        "-drivechainbmmgrpcaddr must contain a non-empty host and nonzero port",
        "-drivechainbmmgrpcaddr requires numeric loopback unless -drivechainenforcerremote=1; remote endpoints must be IP literals or DNS names",
        "-drivechainpegoutenforcer and -drivechainbmmgrpcaddr must select the same authenticated endpoint",
        "-drivechainbmmwalletaddr and -drivechainbmmgrpcaddr must select the same authenticated endpoint",
        "Connect bearer authentication is no longer supported; configure enforcer mTLS",
        "-drivechainbmmgrpcauthority contains whitespace or control characters"};
    const auto text=drivechain::haskell::AdmitGrpcText(config.address,config.authority);
    uint16_t port{0};
    std::string host;
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::GRPC_CONFIG,
        [&](uint32_t action) -> uint32_t {
        if (action>=2 && action<=16 && action%2==0) {
            if (error) *error=errors[action/2-1];
            return 1;
        }
        switch (action) {
        case 1: return text.address_shape;
        case 3: return text.address_characters;
        case 5:
            SplitHostPort(config.address,port,host);
            return !host.empty() | (!host.starts_with('-') << 1) | ((port!=0) << 2);
        case 7: return IsEnforcerHostAllowed(host, args.GetBoolArg("-drivechainenforcerremote", false));
        // Compatibility endpoints must identify the same authenticated enforcer.
        case 9: return args.IsArgSet("-drivechainpegoutenforcer");
        case 20: return args.GetArg("-drivechainpegoutenforcer","")==config.address;
        case 11: return args.IsArgSet("-drivechainbmmwalletaddr");
        case 21: return args.GetArg("-drivechainbmmwalletaddr","")==config.address;
        case 13: return !args.IsArgSet("-drivechainbmmconnectauthcookie");
        case 15: return text.authority_characters;
        case 17: return ValidateReadableRegularFile(config.ca_certificate,false,error);
        case 18: return ValidateReadableRegularFile(config.client_certificate,false,error);
        case 19: return ValidateReadableRegularFile(config.client_key,true,error);
        default: throw std::logic_error("invalid enforcer TLS configuration action");
        }
    }) != 0;
}

BoundedCommandResult RunAuthenticatedDrivechainGrpc(
    const ArgsManager& args,
    const std::string& method,
    const std::string& json_payload,
    const std::chrono::milliseconds timeout,
    const size_t max_output,
    const std::function<bool()>& should_cancel)
{
    BoundedCommandResult failure;
    std::string config_error;
    UniValue parsed_payload;
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::GRPC_REQUEST_ADMISSION,
        [&](uint32_t action) -> uint32_t {
        switch (action) {
        case 1:
            try {
                // Keep method rejection ahead of payload size/JSON validation.
                drivechain::haskell::GrpcPlan(std::array<std::string,1>{method});
                return 1;
            } catch (const std::invalid_argument&) { return 0; }
        case 2: failure.error = "refusing an unrecognized enforcer gRPC method"; return 1;
        case 11: return std::min<size_t>(method.size(),UINT32_MAX);
        case 12: return std::min<size_t>(json_payload.size(),UINT32_MAX);
        case 4: failure.error = "enforcer gRPC payload must contain 1..1048576 bytes"; return 1;
        case 5: return parsed_payload.read(json_payload) && parsed_payload.isObject();
        case 6: failure.error = "enforcer gRPC payload must be one JSON object"; return 1;
        case 7: return ValidateDrivechainGrpcTLSConfig(args, &config_error);
        case 8:
            config_error = "invalid enforcer gRPC deadline or output bound";
            return timeout.count() > 0 && timeout.count() <= 600000 && max_output > 0 && max_output <= 16777216;
        case 9: failure.error = config_error; return 1;
        case 10: break;
        default: throw std::logic_error("invalid enforcer gRPC request action");
        }
        const DrivechainGrpcTLSConfig config = GetDrivechainGrpcTLSConfig(args);
        const auto reply=drivechain::haskell::GrpcRequest(std::array<std::string,7>{
            method,json_payload,config.address,
            fs::PathToString(config.ca_certificate),fs::PathToString(config.client_certificate),
            fs::PathToString(config.client_key),config.authority}, timeout.count(), max_output, should_cancel);
        failure.started = true;
        failure.exited = true;
        failure.exit_code = reply.status;
        failure.cancelled = reply.status == -2;
        failure.timed_out = reply.status == -3;
        failure.output_truncated = reply.status == -4;
        if (reply.status < 0) failure.error = reply.output;
        else failure.output = reply.output;
        return 1;
    });
    return failure;
}

BoundedCommandResult RunAuthenticatedDrivechainGrpc(
    const std::string& method,
    const std::string& json_payload,
    const std::chrono::milliseconds timeout,
    const size_t max_output,
    const std::function<bool()>& should_cancel)
{
    return RunAuthenticatedDrivechainGrpc(
        gArgs, method, json_payload, timeout, max_output, should_cancel);
}


std::string GetDrivechainGrpcAddress(const ArgsManager& args)
{
    return GetDrivechainGrpcTLSConfig(args).address;
}

bool ValidateNativeDrivechainRpcServerConfig(const ArgsManager& args,
                                             std::string* error)
{
    if (error) error->clear();
    int64_t configured_port{0};
    std::vector<std::string> bindings;
    std::string host;
    size_t index{0};
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::RPC_SERVER,
        [&](uint32_t action) -> uint32_t {
        switch (action) {
        case 1: return args.GetBoolArg("-rest", false);
        case 2:
            if (error) *error = "unauthenticated REST is not permitted on a native drivechain node";
            return 1;
        case 3:
            configured_port = args.GetIntArg("-rpcport", BaseParams().RPCPort());
            return drivechain::haskell::DepositPreflight(0,configured_port,65535);
        case 4:
            if (error) *error = "-rpcport must be between 1 and 65535";
            return 1;
        case 5: bindings = args.GetArgs("-rpcbind"); return 1;
        case 6: return index<bindings.size();
        case 7: {
            uint16_t port = static_cast<uint16_t>(configured_port);
            SplitHostPort(bindings.at(index),port,host);
            return (port!=0) | (!host.empty() << 1);
        }
        case 10: return IsMainchainRPCHostAllowed(host, /*native_drivechain=*/true);
        case 8:
            if (error) *error = strprintf("native drivechain JSON-RPC requires a numeric IPv4 127/8 or IPv6 ::1 binding, not %s",bindings.at(index));
            return 1;
        case 9: ++index; return 1;
        default: throw std::logic_error("invalid RPC server configuration action");
        }
    }) != 0;
}

// Fork-specific drivechain_bid_wallet adapters.
// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <drivechain_bid_wallet.h>
#include <primitives/bitcoin/transaction.h>
#include <rpc/util.h>
#include <script/script.h>
#include <streams.h>
#include <util/strencodings.h>
#include <set>
#include <stdexcept>

namespace drivechain {
namespace {
namespace B = Sidechain::Bitcoin;
void Require(bool condition, const char* error)
{
    if (!condition) throw std::runtime_error(error);
}
UniValue Args(std::initializer_list<UniValue> values)
{
    UniValue result{UniValue::VARR};
    for (const auto& value : values) result.push_back(value);
    return result;
}
B::CMutableTransaction Decode(const std::string& hex)
{
    Require(hex.size() <= 200000 && IsHex(hex), "Invalid parent bid transaction encoding");
    DataStream stream{ParseHex(hex)};
    B::CMutableTransaction tx;
    stream >> TX_WITH_WITNESS(tx);
    Require(stream.empty(), "Trailing parent bid transaction data");
    return tx;
}
std::string Encode(const B::CMutableTransaction& tx)
{
    DataStream stream;
    stream << TX_WITH_WITNESS(tx);
    return HexStr(stream);
}
}
namespace {
struct LocalBidNative {
    const LocalBid& bid;
    const BidWalletIO& io;
    B::CMutableTransaction tx{}, signed_tx{};
    CScript request{}, change{};
    std::string saved{}, address{}, hex{};
    UniValue entry{}, coin{}, info{}, funded{}, signature{}, accepted{};
    std::set<B::COutPoint> seen{};
    uint256 result{}, recorded{};

    std::vector<unsigned char> operator()(uint32_t step, uint64_t index, std::span<const unsigned char> input)
    {
        if (step == 0) throw std::runtime_error(std::string(input.begin(),input.end()));
        if (step != 6 && !input.empty()) throw std::logic_error("invalid local bid workflow input");
        if (index && step != 17 && step != 20 && step != 25 && step != 28 && step != 35 &&
            step != 36 && step != 44 && step != 45) throw std::logic_error("invalid local bid workflow index");
        const auto scalar = [](int64_t value) { return ParentReplayBytes(value); };
        if (step == 1) return ParentReplayBytes(int64_t{bid.slot},uint64_t{bid.height},bid.fee,
            bid.replacement_extra,uint64_t{!bid.parent.IsNull()},uint64_t{!bid.critical.IsNull()},bid.parent,bid.critical);
        switch (step) {
        case 2: return scalar(!io.cancelled());
        case 3: return scalar(io.node("getbestblockhash",Args({})).get_str() == bid.parent.GetHex());
        case 4: return scalar(io.node("getblockheader",Args({bid.parent.GetHex()}))["height"].getInt<int64_t>());
        case 5: {
            const auto wallet = io.wallet("getwalletinfo",Args({}));
            return scalar(wallet["private_keys_enabled"].isBool() && wallet["private_keys_enabled"].get_bool());
        }
        case 6:
            Require(input.size() == 70,"invalid local bid request frame");
            request = CScript(input.begin(),input.end()); saved = io.load(); return scalar(!saved.empty());
        case 7: tx = Decode(saved); break;
        case 8: return {tx.vout.at(0).scriptPubKey.begin(),tx.vout.at(0).scriptPubKey.end()};
        case 10:
            Require(tx.vout.at(0).scriptPubKey.size() >= 32,"invalid local bid script observation");
            return scalar(std::equal(bid.parent.begin(),bid.parent.end(),tx.vout[0].scriptPubKey.end()-32));
        case 11: return scalar(tx.vout.at(0).scriptPubKey == request);
        case 12:
            recorded = B::CTransaction(tx).GetHash();
            entry = io.node("getmempoolentry",Args({recorded.GetHex()}));
            return scalar(!entry.isNull());
        case 13: return scalar(AmountFromValue(entry["fees"]["base"]));
        case 14: return scalar(AmountFromValue(io.node("getmempoolinfo",Args({}))["incrementalrelayfee"]));
        case 15: return scalar(entry["vsize"].getInt<int64_t>());
        case 16: return scalar(tx.vin.size());
        case 17: {
            const auto& prevout = tx.vin.at(index).prevout;
            coin = io.node("gettxout",Args({prevout.hash.GetHex(),prevout.n,false}));
            return scalar(coin.isNull() ? 0 : coin.isObject() ? 1 : 2);
        }
        case 18: return scalar(coin["confirmations"].getInt<int>());
        case 19: return scalar(AmountFromValue(coin["value"]));
        case 20: return scalar(seen.insert(tx.vin.at(index).prevout).second);
        case 21:
            tx = B::CMutableTransaction{};
            tx.version = 2; tx.nLockTime = bid.height; tx.vout.emplace_back(0,request);
            break;
        case 22: address = io.wallet("getrawchangeaddress",Args({"bech32"})).get_str(); break;
        case 23: info = io.wallet("getaddressinfo",Args({address})); return scalar(info["ismine"].get_bool());
        case 24: {
            const auto bytes = ParseHex(info["scriptPubKey"].get_str());
            change = CScript(bytes.begin(),bytes.end());
            return scalar(!change.empty());
        }
        case 25: {
            Require(index <= uint64_t(MAX_MONEY),"invalid local bid amount");
            tx.vout.emplace_back(index,change);
            UniValue options{UniValue::VOBJ};
            options.pushKV("changeAddress",address);
            options.pushKV("changePosition",1);
            options.pushKV("replaceable",true);
            options.pushKV("lockUnspents",false);
            options.pushKV("minconf",1);
            options.pushKV("fee_rate",1);
            options.pushKV("subtractFeeFromOutputs",Args({1}));
            funded = io.wallet("fundrawtransaction",Args({Encode(tx),options}));
            break;
        }
        case 26: tx = Decode(funded["hex"].get_str()); return scalar(funded["changepos"].getInt<int>());
        case 27: return scalar(tx.vout.size());
        case 28: return scalar(tx.vout.at(index).scriptPubKey == change);
        case 29: tx.vout.resize(2); break;
        case 30: return scalar(tx.version);
        case 31: return scalar(tx.vout.at(0).nValue);
        case 32: return scalar(tx.nLockTime);
        case 33: tx.nLockTime = bid.height; tx.vout.at(0).scriptPubKey = request; break;
        case 34: seen.clear(); break;
        case 35:
            Require(index <= uint64_t(MAX_MONEY),"invalid local bid amount");
            tx.vout.at(1).nValue = index; break;
        case 36: {
            auto& in = tx.vin.at(index);
            in.nSequence = 0xfffffffd; in.scriptSig.clear(); in.scriptWitness.SetNull(); break;
        }
        case 37: signature = io.wallet("signrawtransactionwithwallet",Args({Encode(tx)})); break;
        case 38: return scalar(signature["complete"].get_bool());
        case 39: signed_tx = Decode(signature["hex"].get_str()); break;
        case 40: return scalar(signed_tx.version == tx.version);
        case 41: return scalar(signed_tx.nLockTime == tx.nLockTime);
        case 42: return scalar(signed_tx.vout == tx.vout);
        case 43: return scalar(signed_tx.vin.size() == tx.vin.size());
        case 44: return scalar(signed_tx.vin.at(index).prevout == tx.vin.at(index).prevout);
        case 45: return scalar(signed_tx.vin.at(index).nSequence == tx.vin.at(index).nSequence);
        case 46: tx = signed_tx; break;
        case 47: return scalar(tx.vout.at(1).nValue);
        case 48: hex = Encode(tx); break;
        case 49:
            accepted = io.node("testmempoolaccept",Args({Args({hex})}));
            return scalar(accepted.isArray() && accepted.size() == 1);
        case 50: return scalar(accepted[0]["allowed"].isBool());
        case 51: return scalar(accepted[0]["allowed"].get_bool());
        case 52: {
            const auto& reason = accepted[0]["reject-reason"];
            const std::string message = reason.isStr() ? reason.get_str() : "no reason supplied";
            return {message.begin(),message.end()};
        }
        case 53: io.save(hex); break;
        case 54:
            result = B::CTransaction(tx).GetHash();
            return scalar(io.node("sendrawtransaction",Args({hex})).get_str() == result.GetHex());
        case 55: result = recorded; break;
        default: throw std::logic_error("invalid local bid workflow action");
        }
        return scalar(1);
    }
};
}

uint256 SubmitLocalBid(const LocalBid& bid, const BidWalletIO& io)
{
    LocalBidNative native{bid,io};
    const auto status = drivechain::haskell::RunReplayStore(drivechain::haskell::ReplayStoreWorkflow::LOCAL_BID, std::ref(native));
    Require(status == 1,"Haskell local bid workflow failed");
    return native.result;
}
}

// Fork-specific mainchainrpc_ecx adapters.
#include <mainchainrpc.h>
#include <haskell/bridge.h>
#include <haskell/network_defaults.h>

#include <chainparams.h>
#include <drivechain_bmm.h>
#include <drivechain_bid_wallet.h>
#include <dbwrapper.h>
#include <drivechain_peg.h>
#include <drivechain_treasury.h>
#include <init.h>
#include <logging.h>
#include <pegins.h>
#include <primitives/bitcoin/transaction.h>
#include <primitives/bitcoin/block.h>
#include <primitives/block.h>
#include <script/script.h>
#include <streams.h>
#include <common/args.h>
#include <util/strencodings.h>
#include <tinyformat.h>

#include <optional>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

bool CallAuthenticatedDrivechainJSON(
    const std::string& endpoint,
    const std::string& method,
    const UniValue& request,
    UniValue& response,
    std::string* error)
{
    namespace hs = drivechain::haskell;
    std::optional<BoundedCommandResult> result;
    return hs::ParentReplayStore(hs::ReplayStoreFlow::AUTHENTICATED_JSON, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: case 19: response = UniValue(); return 1;
        case 2: case 5: case 15: case 20: return error != nullptr;
        case 3: error->clear(); return 1;
        case 4: return endpoint == GetDrivechainGrpcAddress(gArgs);
        case 6: *error = "enforcer endpoint differs from the configured mTLS endpoint"; return 1;
        case 7: result.emplace(RunAuthenticatedDrivechainGrpc(
            method, request.write(), std::chrono::seconds{drivechain::AUTHENTICATED_GRPC_TIMEOUT_SECONDS},
            drivechain::MAX_AUTHENTICATED_GRPC_RESPONSE_SIZE)); return 1;
        case 8: return result->started;
        case 9: return result->exited;
        case 10: return result->exit_code == 0;
        case 11: return !result->timed_out;
        case 12: return !result->cancelled;
        case 13: return !result->output_truncated;
        case 14: return result->error.empty();
        case 16: *error = "authenticated enforcer request failed, timed out, or exceeded its output limit"; return 1;
        case 22: return result->error.empty();
        case 23: *error = result->error; return 1;
        case 17: return response.read(result->output);
        case 18: return response.isObject();
        case 21: *error = "authenticated enforcer returned non-object JSON"; return 1;
        default: throw std::logic_error("invalid authenticated JSON action");
        }
    });
}
UniValue BuildDrivechainBmmRequest(int sidechain_slot, uint64_t bid_sats, int64_t parent_height,
    const uint256& critical_hash, const uint256& previous_parent_hash)
{
    using Layout = drivechain::haskell::EventLayoutKind;
    const auto object = [](Layout layout, const std::vector<UniValue>& values) {
        UniValue result(UniValue::VOBJ);
        drivechain::AppendEvent(result, layout, [&](uint32_t index) { return values.at(index); });
        return result;
    };
    // uint64 wrapper values are strings in canonical protobuf JSON.
    return object(Layout::BMM_REQUEST,{UniValue(sidechain_slot),UniValue(std::to_string(bid_sats)),
        UniValue(parent_height),object(Layout::HEX,{UniValue(critical_hash.GetHex())}),
        object(Layout::HEX,{UniValue(previous_parent_hash.GetHex())})});
}

bool SubmitDrivechainBmmBid(
    const int sidechain_slot,
    const uint64_t bid_sats,
    const uint32_t parent_height,
    const uint256& critical_hash,
    const uint256& previous_parent_hash,
    uint256& request_txid,
    std::string* error,
    const std::function<bool()>& cancelled)
{
    return CatchParentError(error, [&]() -> bool {
        namespace hs = drivechain::haskell;
        static std::mutex mutex;
        static std::unique_ptr<CDBWrapper> store;
        std::optional<std::lock_guard<std::mutex>> guard;
        std::optional<std::pair<uint256,std::pair<std::string,int>>> key;
        std::string wallet;
        const Consensus::Params* consensus{nullptr};
        uint256 unused;
        std::optional<ParentNetworkNative> network;
        std::optional<drivechain::LocalBid> bid;
        std::optional<drivechain::BidWalletIO> io;
        std::optional<drivechain::LocalBidNative> local;
        const std::function<UniValue(const std::string&,const UniValue&)> node_rpc =
            [](const std::string& method, const UniValue& params) {
                const auto reply = CallMainChainRPC(method, params);
                if (method == "getmempoolentry" && reply["error"].isObject() &&
                    reply["error"]["code"].getInt<int>() == -5) return UniValue();
                return CheckDrivechainRPCReply(method, reply);
            };
        return hs::RunReplayStore(hs::ReplayStoreWorkflow::BID_SUBMISSION,
            [&](uint32_t step,uint64_t index,std::span<const unsigned char> input) -> std::vector<unsigned char> {
                if (step >= 2000 && step <= 3560 && network) return (*network)(step-2000,index,input);
                if (step >= 1000 && step <= 1055 && local) return (*local)(step-1000,index,input);
                if (step == 0 && index == 0) throw std::runtime_error(std::string(input.begin(),input.end()));
                if (index || !input.empty()) throw std::logic_error("invalid BMM submission input");
                const auto scalar = [](bool value) { return ParentReplayBytes(uint64_t{value}); };
                switch (step) {
                case 100: return ParentReplayBytes(static_cast<uint64_t>(sidechain_slot),bid_sats,
                    uint64_t{parent_height},uint64_t{!critical_hash.IsNull()},uint64_t{!previous_parent_hash.IsNull()});
                case 101: wallet = gArgs.GetArg("-drivechainbmmwallet",""); return scalar(!wallet.empty());
                case 102: return ParentRpcHostSnapshot(gArgs.GetArg("-mainchainrpchost",DEFAULT_RPCCONNECT));
                case 103: guard.emplace(mutex); break;
                case 104: return scalar(bool(store));
                case 105:
                    store = std::make_unique<CDBWrapper>(DBParams{.path = gArgs.GetDataDirNet() / "bmm-bids", .cache_bytes = 1 << 20});
                    break;
                case 106: key.emplace(Params().ParentGenesisBlockHash(),std::make_pair(wallet,sidechain_slot)); break;
                case 107: {
                    UniValue params{UniValue::VARR}; params.push_back(0);
                    return scalar(node_rpc("getblockhash",params).get_str() == Params().ParentGenesisBlockHash().GetHex());
                }
                case 108:
                    consensus = &Params().GetConsensus();
                    network.emplace(consensus,&node_rpc,&g_drivechain_parent_replay_published_epoch,0,unused,error);
                    break;
                case 109: return scalar(consensus->drivechain_slot.has_value());
                case 110: return scalar(sidechain_slot == *consensus->drivechain_slot);
                case 111: return scalar(!consensus->drivechain_parent_state_hash.IsNull());
                case 112: {
                    UniValue params{UniValue::VARR}; params.push_back(consensus->drivechain_parent_state_height);
                    return scalar(node_rpc("getblockhash",params).get_str() == consensus->drivechain_parent_state_hash.GetHex());
                }
                case 113:
                    bid.emplace(sidechain_slot,parent_height,previous_parent_hash,critical_hash,static_cast<CAmount>(bid_sats),
                        gArgs.GetIntArg("-drivechainbmmreplacementextra",0));
                    io.emplace(node_rpc,
                        [&](const std::string& method,const UniValue& params) {
                            return CheckDrivechainRPCReply(method,CallMainChainWalletRPC(wallet,method,params));
                        },
                        [&] {
                            std::string saved;
                            if (store->Exists(*key) && !store->Read(*key,saved)) throw std::runtime_error("Corrupt persisted BMM bid");
                            return saved;
                        },
                        [&](const std::string& hex) {
                            if (!store->Write(*key,hex,/*fSync=*/true)) throw std::runtime_error("Cannot persist BMM bid");
                        },cancelled);
                    local.emplace(*bid,*io);
                    break;
                case 114: {
                    const uint256 result = local->result;
                    local.reset();
                    request_txid = result;
                    break;
                }
                case 116: network.reset(); break;
                default: throw std::logic_error("invalid BMM submission action");
                }
                return scalar(true);
            });
    });
}

static UniValue CallMainChainHexRPC(const std::string& method, const UniValue& params, const char* malformed)
{
    UniValue result = CallMainChainRPCChecked(method, params);
    if (!drivechain::IsHexField(result)) throw std::runtime_error(malformed);
    return result;
}

static UniValue CallMainChainTransactionHex(bool proof, const std::string& txid,
    const std::string& block_hash, const char* malformed)
{
    UniValue params(UniValue::VARR);
    if (proof) {
        UniValue txids(UniValue::VARR);
        txids.push_back(txid);
        params.push_back(txids);
    } else {
        params.push_back(txid);
        params.push_back(false);
    }
    params.push_back(block_hash);
    return CallMainChainHexRPC(proof ? "gettxoutproof" : "getrawtransaction",params,malformed);
}

static std::string CallMainChainBlockHash(int64_t height)
{
    UniValue params(UniValue::VARR);
    params.push_back(height);
    return CallMainChainRPCChecked("getblockhash", params).get_str();
}

static const UniValue& FindField(const UniValue& obj, const std::string& lower_camel, const std::string& snake_case)
{
    return drivechain::FindField(obj.get_obj(), lower_camel, snake_case);
}

static bool GetDrivechainGrpcJSON(
    const std::string& method,
    const UniValue& request,
    UniValue& response,
    std::string* error)
{
    return CallAuthenticatedDrivechainJSON(
        GetDrivechainGrpcAddress(gArgs),
        "cusf.mainchain.v1.ValidatorService/" + method,
        request,
        response,
        error);
}

static bool GetDrivechainTwoWayPegDataAtTip(
    const int sidechain_slot,
    const uint256& mainchain_tip,
    UniValue& response,
    std::string* error)
{
    return CatchParentError(error, [&]() -> bool {
        UniValue request(UniValue::VOBJ), block_hash(UniValue::VOBJ);
        using Layout = drivechain::haskell::EventLayoutKind;
        drivechain::AppendEvent(block_hash, Layout::HEX, [&](uint32_t) { return UniValue(mainchain_tip.GetHex()); });
        drivechain::AppendEvent(request, Layout::TWO_WAY_PEG_REQUEST,
            [&](uint32_t index) { return index == 0 ? UniValue(sidechain_slot) : block_hash; });
        if (!GetDrivechainGrpcJSON("GetTwoWayPegData", request, response, error)) {
            return false;
        }

        size_t block_count{0};
        size_t event_count{0};
        const UniValue& blocks = FindField(response, "blocks", "blocks");
        if (blocks.isArray()) {
            block_count = blocks.size();
            for (const UniValue& block : blocks.getValues()) {
                if (!block.isObject()) continue;
                const UniValue& block_info = FindField(block, "blockInfo", "block_info");
                if (!block_info.isObject()) continue;
                const UniValue& events = FindField(block_info, "events", "events");
                if (events.isArray()) event_count += events.size();
            }
        }
        LogPrintf("GetTwoWayPegData returned %u blocks and %u raw events for sidechain %d\n", block_count, event_count, sidechain_slot);
        return true;
    });
}

bool GetDrivechainTwoWayPegData(const int sidechain_slot, UniValue& response, std::string* error)
{
    return CatchParentError(error, [&]() -> bool {
        UniValue no_params(UniValue::VARR);
        const uint256 mainchain_tip = uint256S(CallMainChainRPCChecked("getbestblockhash", no_params).get_str());
        return GetDrivechainTwoWayPegDataAtTip(sidechain_slot, mainchain_tip, response, error);
    });
}

static drivechain::DepositIdentity ConfiguredDepositIdentity()
{
    drivechain::DepositIdentity identity;
    identity.sidechain_slot = gArgs.GetIntArg("-drivechainbmmslot", drivechain::HISTORICAL_DEPOSIT_SLOT);
    identity.sidechain_network = gArgs.GetArg("-drivechainsidechainnetwork", drivechain::HISTORICAL_DEPOSIT_SIDECHAIN_NETWORK);
    identity.mainchain_network = gArgs.GetArg("-drivechainmainchainnetwork", drivechain::HISTORICAL_DEPOSIT_MAINCHAIN_NETWORK);
    identity.mainchain_signet_challenge = ToLower(gArgs.GetArg(
        "-drivechainmainchainsignetchallenge",
        drivechain::HISTORICAL_DEPOSIT_SIGNET_CHALLENGE));
    identity.enforcer_network = gArgs.GetArg("-drivechainenforcernetwork", drivechain::HISTORICAL_DEPOSIT_ENFORCER_NETWORK);
    identity.mainchain_genesis = Params().ParentGenesisBlockHash();
    identity.title = gArgs.GetArg("-drivechainsidechaintitle", drivechain::HISTORICAL_DEPOSIT_TITLE);
    identity.hash_id_1 = ToLower(gArgs.GetArg(
        "-drivechainsidechainhashid1",
        drivechain::HISTORICAL_DEPOSIT_HASH_ID_1));
    identity.hash_id_2 = ToLower(gArgs.GetArg(
        "-drivechainsidechainhashid2",
        drivechain::HISTORICAL_DEPOSIT_HASH_ID_2));
    return identity;
}

bool VerifyDrivechainDeposit(
    const CTransaction& tx,
    const size_t input_index,
    drivechain::AuthenticatedDeposit* authenticated_out,
    std::string* error)
{
    return CatchParentError(error, [&]() -> bool {
        namespace hs = drivechain::haskell;
        CAmount value{0};
        CScript claim_script;
        uint256 mainchain_txid, mainchain_genesis, mainchain_tip;
        UniValue mainchain_info, enforcer_chain_info, enforcer_tip, sidechains, ctip, two_way_peg_data;
        std::optional<drivechain::DepositIdentity> identity;
        drivechain::AuthenticatedDeposit authenticated;
        std::string lookup_error, verify_error;
        hs::DepositVerify(input_index, tx.vin.size(), tx.witness.vtxinwit.size(), [&](uint32_t stage) {
        switch (stage) {
        case 1:
        return GetDrivechainDepositPeginData(
                tx.witness.vtxinwit[input_index].m_pegin_witness,
                tx.vin[input_index].prevout,
                value,
                claim_script,
                mainchain_txid);
        case 2: {
        UniValue no_params(UniValue::VARR);
        mainchain_info = CallMainChainRPCChecked("getblockchaininfo", no_params);
        UniValue genesis_params(UniValue::VARR);
        genesis_params.push_back(0);
        mainchain_genesis = uint256S(CallMainChainRPCChecked("getblockhash", genesis_params).get_str());
        mainchain_tip = uint256S(mainchain_info.get_obj()["bestblockhash"].get_str());
        return true;
        }
        case 3: case 4: case 5: {
        static constexpr const char* methods[]{"GetChainInfo", "GetChainTip", "GetSidechains"};
        UniValue* replies[]{&enforcer_chain_info, &enforcer_tip, &sidechains};
        return GetDrivechainGrpcJSON(methods[stage-3], UniValue(UniValue::VOBJ), *replies[stage-3], &lookup_error);
        }
        case 6: {
        identity = ConfiguredDepositIdentity();
        UniValue ctip_request(UniValue::VOBJ);
        ctip_request.pushKV("sidechainNumber", identity->sidechain_slot);
        return GetDrivechainGrpcJSON("GetCtip", ctip_request, ctip, &lookup_error);
        }
        case 7:
        return GetDrivechainTwoWayPegDataAtTip(
                identity->sidechain_slot,
                mainchain_tip,
                two_way_peg_data,
                &lookup_error);
        case 8:
        return drivechain::AuthenticateDepositEvidence(
                mainchain_info,
                mainchain_genesis,
                enforcer_chain_info,
                enforcer_tip,
                sidechains,
                two_way_peg_data,
                ctip,
                Params().NetworkIDString(),
                *identity,
                tx.vin[input_index].prevout,
                value,
                authenticated,
                verify_error);
        case 9: {
        UniValue block_params(UniValue::VARR);
        block_params.push_back(authenticated.confirmation_block.GetHex());
        block_params.push_back(true);
        const UniValue block_header = CallMainChainRPCChecked("getblockheader", block_params);
        return drivechain::VerifyDepositBlockConfirmation(block_header, authenticated, verify_error);
        }
        case 10: {
        UniValue ctip_params(UniValue::VARR);
        ctip_params.push_back(authenticated.current_ctip.hash.GetHex());
        ctip_params.push_back(static_cast<int64_t>(authenticated.current_ctip.n));
        ctip_params.push_back(false);
        const UniValue ctip_txout = CallMainChainRPCChecked("gettxout", ctip_params);
        return drivechain::VerifyCurrentCtipOutput(ctip_txout, authenticated, verify_error);
        }
        case 11:
        return drivechain::VerifyDepositTransaction(tx, input_index, authenticated, verify_error);
        case 12:
        if (authenticated_out) {
            *authenticated_out = std::move(authenticated);
        }
        return true;
        case 13: throw std::runtime_error("transaction input is not a valid drivechain deposit witness");
        case 14: throw std::runtime_error("unable to obtain enforcer chain identity: " + lookup_error);
        case 15: throw std::runtime_error("unable to obtain current CTIP state: " + lookup_error);
        case 16: throw std::runtime_error("unable to obtain confirmed two-way-peg data: " + lookup_error);
        case 17: throw std::runtime_error(verify_error);
        default: throw std::logic_error("Invalid Haskell live deposit stage");
        }
        });
        return true;
    });
}

bool BuildDrivechainDepositEvidence(
    const drivechain::AuthenticatedDeposit& authenticated,
    DrivechainDepositEvidence& evidence,
    std::string* error)
{
    return CatchParentError(error, [&]() -> bool {
        std::optional<Sidechain::Bitcoin::CMutableTransaction> deposit_tx;
        bool fully_decoded{false};
        std::optional<std::vector<unsigned char>> previous_ctip;
        std::vector<unsigned char> candidate;
        UniValue previous_result;
        Sidechain::Bitcoin::CMutableTransaction previous_tx;
        Sidechain::Bitcoin::CBlockHeader header;
        std::exception_ptr candidate_failure;
        const auto word = [](uint64_t value) {
            std::vector<unsigned char> bytes(8);
            WriteLE64(bytes.data(),value);
            return bytes;
        };
        const auto candidate_action = [&](uint32_t step,uint64_t index) -> std::vector<unsigned char> {
            const auto& input = deposit_tx->vin.at(index);
            switch (step) {
            case 101: {
                UniValue params(UniValue::VARR);
                params.push_back(input.prevout.hash.GetHex());
                params.push_back(false);
                previous_result = CallMainChainRPCChecked("getrawtransaction",params);
                auto fields = word(previous_result.isStr());
                const auto hex = word(previous_result.isStr() && IsHex(previous_result.get_str()));
                fields.insert(fields.end(),hex.begin(),hex.end());
                return fields;
            }
            case 102: previous_ctip = candidate; return word(1);
            case 103: {
                candidate = ParseHex(previous_result.get_str());
                previous_tx = {};
                DataStream stream{candidate};
                stream >> TX_WITH_WITNESS(previous_tx);
                return word(stream.empty());
            }
            case 104: return word(input.prevout.n < previous_tx.vout.size());
            case 105: {
                const auto& script = previous_tx.vout[input.prevout.n].scriptPubKey;
                return {script.begin(),script.begin()+std::min<size_t>(script.size(),5)};
            }
            default: throw std::logic_error("invalid prior treasury native action");
            }
        };
        const uint32_t flags = unsigned{!authenticated.outpoint.hash.IsNull()} |
            (unsigned{!authenticated.confirmation_block.IsNull()} << 1);
        drivechain::haskell::ConstructDepositEvidence(authenticated.sequence_number,
            authenticated.confirmation_height,flags,authenticated.sidechain_slot,
            [&](uint32_t step,uint64_t index,std::span<const unsigned char> input) -> std::vector<unsigned char> {
                if (step >= 101 && step <= 105) {
                    try {
                        auto reply = candidate_action(step,index);
                        reply.insert(reply.begin(),0);
                        return reply;
                    } catch (const std::runtime_error& exception) {
                        candidate_failure = std::current_exception();
                        const std::string message{exception.what()};
                        std::vector<unsigned char> reply{1};
                        reply.insert(reply.end(),message.begin(),message.end());
                        return reply;
                    } catch (...) {
                        candidate_failure = std::current_exception();
                        return {2};
                    }
                }
                switch (step) {
                case 0: {
                    const UniValue raw = CallMainChainTransactionHex(false,
                        authenticated.outpoint.hash.GetHex(),authenticated.confirmation_block.GetHex(),
                        "getrawtransaction returned malformed deposit transaction hex");
                    evidence.deposit_tx = ParseHex(raw.get_str());
                    deposit_tx.emplace();
                    DataStream stream{evidence.deposit_tx};
                    stream >> TX_WITH_WITNESS(*deposit_tx);
                    fully_decoded = stream.empty();
                    return {};
                }
                case 1: return word(fully_decoded);
                case 2: return word(deposit_tx->GetHash() == authenticated.outpoint.hash);
                case 3: return word(authenticated.outpoint.n < deposit_tx->vout.size());
                case 4: {
                    const UniValue proof = CallMainChainTransactionHex(true,
                        authenticated.outpoint.hash.GetHex(),authenticated.confirmation_block.GetHex(),
                        "gettxoutproof returned malformed proof hex");
                    evidence.txout_proof = ParseHex(proof.get_str());
                    return {};
                }
                case 10: return word(deposit_tx->vin.size());
                case 11:
                    if (input.size() != 8) throw std::logic_error("invalid predecessor publication");
                    evidence.previous_ctip_tx = std::move(previous_ctip.value());
                    evidence.sequence_number = authenticated.sequence_number;
                    evidence.previous_sequence_number = static_cast<int64_t>(ReadLE64(input.data()));
                    return {};
                case 12: {
                    const UniValue info = CallMainChainRPCChecked("getblockchaininfo",UniValue(UniValue::VARR));
                    return word(static_cast<uint64_t>(info.get_obj()["blocks"].getInt<int64_t>()));
                }
                case 20: evidence.headers.clear(); return {};
                case 21: {
                    const std::string hash = CallMainChainBlockHash(static_cast<int64_t>(index));
                    UniValue params(UniValue::VARR);
                    params.push_back(hash);
                    params.push_back(false);
                    const UniValue raw = CallMainChainHexRPC("getblockheader",params,
                        "getblockheader returned malformed serialized header");
                    const auto bytes = ParseHex(raw.get_str());
                    header = {};
                    DataStream stream{bytes};
                    stream >> header;
                    return word(stream.empty());
                }
                case 22: evidence.headers.push_back(header); return {};
                case 109:
                    if (!candidate_failure) throw std::logic_error("missing prior treasury exception");
                    std::rethrow_exception(candidate_failure);
                default: throw std::logic_error("invalid deposit construction native action");
                }
            });
        return true;
    });
}

bool BuildDrivechainBmmProof(
    const drivechain::BmmL1State& previous_state,
    const int64_t parent_height,
    const uint256& parent_hash,
    const uint256& critical_hash,
    drivechain::BmmProof& proof,
    std::string* error)
{
    return CatchParentError(error, [&]() -> bool {
        std::string verify_error;
        uint256 block_hash;
        UniValue block;
        const UniValue* transactions{nullptr};
        drivechain::haskell::BmmProofBuild(previous_state.height, parent_height, [&](uint32_t stage, uint64_t height) {
        switch (stage) {
        case 1: {
        const uint256 active_anchor{uint256S(CallMainChainBlockHash(static_cast<int64_t>(previous_state.height)))};
        return active_anchor == previous_state.block_hash;
        }
        case 6:
            throw std::runtime_error(strprintf(
                "authenticated BMM anchor %s at height %u is not on the active L1 chain",
                previous_state.block_hash.GetHex(),
                previous_state.height));
        case 2: {
        const uint256 active_parent{uint256S(CallMainChainBlockHash(parent_height))};
        return active_parent == parent_hash;
        }
        case 7:
            throw std::runtime_error("sidechain parent commitment is no longer the active L1 block");
        case 3:
        proof = drivechain::BmmProof{};
        proof.previous_state = previous_state;
        return true;
        case 4: {
            block_hash = uint256S(CallMainChainBlockHash(static_cast<int64_t>(height)));

            UniValue block_params(UniValue::VARR);
            block_params.push_back(block_hash.GetHex());
            block_params.push_back(1);
            block = CallMainChainRPCChecked("getblock", block_params);
            transactions = &block.get_obj()["tx"];
            return true;
        }
        case 9: return transactions->isArray();
        case 10: return !transactions->empty();
        case 11: return (*transactions)[0].isStr();
        case 13: throw std::runtime_error("getblock returned no parent-chain coinbase txid");
        case 12: {
            const std::string coinbase_txid = (*transactions)[0].get_str();

            const UniValue raw = CallMainChainTransactionHex(false,coinbase_txid,block_hash.GetHex(),
                "getrawtransaction returned malformed coinbase hex");

            const UniValue merkle = CallMainChainTransactionHex(true,coinbase_txid,block_hash.GetHex(),
                "gettxoutproof returned malformed coinbase proof hex");
            proof.entries.push_back({
                ParseHex(raw.get_str()),
                ParseHex(merkle.get_str())});
            return true;
        }
        case 5: {
        drivechain::BmmL1State next_state;
        return drivechain::VerifyBmmProofEntries(
                proof,
                critical_hash,
                parent_hash,
                next_state,
                verify_error,
                drivechain::LayerTwoLabsBmmConsensus());
        }
        case 8:
            throw std::runtime_error(
                "constructed BMM successor proof failed self-verification: " +
                verify_error);
        default: throw std::logic_error("Invalid Haskell BMM proof build stage");
        }
        });
        return true;
    });
}

// Fork-specific haskell/grpc_bridge adapters.
// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <haskell/bridge.h>
#include <GrpcClient_stub.h>
#include <array>
#include <exception>
#include <stdexcept>

extern "C" void elements_hs_runtime_init(void);

namespace drivechain::haskell {
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
    const int status = elements_hs_grpc_v1(pointers.data(), timeout_ms, max_output,
        reinterpret_cast<HsFunPtr>(cancel), reinterpret_cast<HsFunPtr>(emit), &context);
    if (context.exception) std::rethrow_exception(context.exception);
    return {status, std::move(context.output)};
}
} // namespace drivechain::haskell
