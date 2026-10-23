// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MAINCHAINRPC_H
#define BITCOIN_MAINCHAINRPC_H

#include <drivechain_parent_rules.h>
#include <rpc/client.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <primitives/transaction.h>
#include <primitives/bitcoin/block.h>
#include <uint256.h>

#include <consensus/amount.h>
#include <serialize.h>

#include <cstdint>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <stdexcept>
#include <chrono>
#include <cstddef>
#include <functional>
#include <vector>

#include <univalue.h>

class CBlock;
class arith_uint256;

class DrivechainParentRecoveryDeadline {
    std::optional<std::chrono::steady_clock::time_point>& m_current;
    const std::optional<std::chrono::steady_clock::time_point> m_previous;
public:
    DrivechainParentRecoveryDeadline(std::optional<std::chrono::steady_clock::time_point>& current,
        const std::function<std::chrono::steady_clock::time_point()>& now);
    ~DrivechainParentRecoveryDeadline() noexcept;
    DrivechainParentRecoveryDeadline(const DrivechainParentRecoveryDeadline&) = delete;
    DrivechainParentRecoveryDeadline& operator=(const DrivechainParentRecoveryDeadline&) = delete;
};

struct VerifiedMainchainHeader {
    Sidechain::Bitcoin::CBlockHeader header;
    uint256 chainwork;
    uint32_t height{0};
    int64_t confirmations{0};
    uint64_t median_time_past{0};
};

struct DrivechainParentHeaderSource {
    std::function<const uint256&()> genesis;
    std::function<UniValue(const std::string&, const UniValue&)> request;
    std::function<bool(const uint256&, Sidechain::Bitcoin::CBlockHeader&, std::string*)> raw_header;
    std::function<bool(const uint256&, uint32_t, uint64_t&, std::string*)> median_time;
    std::function<void()> deadline;
};

bool VerifyDrivechainParentHeader(const uint256& expected_hash, int min_confirmations,
    VerifiedMainchainHeader& verified, std::string* error, const DrivechainParentHeaderSource& source);

bool CheckDrivechainParentProofOfWork(const uint256& hash, uint32_t bits, std::string* error);
arith_uint256 GetDrivechainParentBlockProof(uint32_t bits);
bool DecodeDrivechainRawParentHeader(const UniValue& raw, const uint256& hash,
    Sidechain::Bitcoin::CBlockHeader& header, std::string* error);
bool DecodeDrivechainRawParentBlock(const UniValue& raw, const uint256& hash,
    Sidechain::Bitcoin::CBlock& block, std::string* error, const std::function<void()>& deadline);
bool CheckDrivechainParentBlockTransactions(const Sidechain::Bitcoin::CBlock& block,
    std::string* error, const std::function<void()>& deadline);
/** Transaction shape must already have passed CheckDrivechainParentBlockTransactions. */
bool CheckDrivechainParentBlockSignet(const Sidechain::Bitcoin::CBlock& block, std::string* error,
    const std::function<const std::vector<uint8_t>&()>& challenge,
    const std::function<const uint256&()>& genesis, const std::function<void()>& deadline);
bool VerifyDrivechainParentBlock(const uint256& hash, int min_confirmations,
    Sidechain::Bitcoin::CBlock& block, VerifiedMainchainHeader& verified, std::string* error,
    const std::function<bool(const uint256&, int, VerifiedMainchainHeader&, std::string*)>& read_header,
    const std::function<bool(const uint256&, Sidechain::Bitcoin::CBlock&, std::string*)>& read_block);
bool ComputeDrivechainParentMedianTimePast(const uint256& start_hash, uint32_t start_height,
    uint64_t& median_time_past,
    const std::function<bool(const uint256&, Sidechain::Bitcoin::CBlockHeader&)>& read_header,
    const std::function<void()>& check_deadline);
bool CheckDrivechainParentChainwork(const uint256& parent_work, const uint256& successor_work,
    uint32_t successor_bits, std::string* error);

/** Pure parent-RPC parsing helpers; rejected canonical hashes may be decoded. */
bool ParseDrivechainCanonicalHash(const UniValue& value, uint256& hash);
bool ParseDrivechainParentHeight(const UniValue& value, uint32_t& height, std::string* error);
bool ParseDrivechainParentHeaderMetadata(const UniValue& metadata, const uint256& expected_hash,
    int min_confirmations, uint256& chainwork, int64_t& height, int64_t& confirmations, std::string* error);
/** Height must already have passed ParseDrivechainParentHeaderMetadata. */
bool CheckDrivechainParentPredecessor(const UniValue& previous, int64_t height,
    const Sidechain::Bitcoin::CBlockHeader& raw_header, const uint256& chainwork, std::string* error,
    const std::function<UniValue(const std::string&, const UniValue&)>& request);
bool IsExactDrivechainOpReturnAddress(const Sidechain::Bitcoin::CTxOut& output,
    const std::vector<unsigned char>& address);
class CTransaction;
class ArgsManager;
class HashWriter;
namespace ElementsDrivechainBootstrap {
struct Slot;
}
struct DrivechainDepositEvidence;
namespace Consensus {
struct Params;
}
namespace drivechain {
struct AuthenticatedDeposit;
struct BmmL1State;
struct BmmProof;
}
struct DrivechainAnchor;
namespace util {
class SignalInterrupt;
}

/** True only when slot is the BIP300/301 slot configured for this network. */
bool IsDrivechainSidechainSlot(int slot);

struct DrivechainParentBlockContext {
    uint256 parent_hash;
    uint256 parent_chainwork;
    uint32_t parent_height{0};
    uint64_t parent_median_time_past{0};
};

struct DrivechainBmmBlockContext : public DrivechainParentBlockContext {
    /** Exact opaque BIP301 M8/M7 value authenticated for this child block. */
    uint256 critical_hash;
    uint256 bmm_block_hash;
    uint256 bmm_chainwork;
    uint32_t bmm_height{0};
};

/** Authenticate a historical execution anchor on the same stable active chain
 * as the bidding parent. Does not replace or authenticate a BIP301 P->Q edge. */
bool GetDrivechainExecutionAnchor(int slot, const uint256& hash,
    uint32_t minimum_height, const DrivechainParentBlockContext& bid_parent,
    DrivechainParentBlockContext& anchor, std::string* error = nullptr);

enum class DrivechainAnchorStatus {
    ACTIVE,
    ORPHANED,
    UNAVAILABLE,
};

/**
 * Result of authenticating a sidechain block's BIP301 commitment.
 *
 * INVALID is reserved for immutable malformed child-block bytes.
 * PARENT_REJECTED means the authenticated current P -> Q edge does not commit
 * to the child; it is retryable because Q can be replaced by a parent reorg.
 */
enum class DrivechainBmmStatus {
    VALID,
    INVALID,
    PARENT_REJECTED,
    UNAVAILABLE,
};

/**
 * Result of validating a native BIP300 deposit against the parent chain.
 *
 * INVALID is reserved for a deterministic mismatch between the sidechain
 * claim and an already authenticated, sufficiently buried active parent
 * block.  Every failure to obtain or authenticate that parent-chain view is
 * UNAVAILABLE so a transient RPC failure or reorg cannot permanently poison
 * the sidechain block carrying the claim.
 */
enum class DrivechainDepositStatus {
    VALID,
    INVALID,
    UNAVAILABLE,
};

/**
 * True only for a canonical frozen parent-checkpoint CTIP tuple.
 *
 * A checkpoint either predates the first CTIP (null txid, UINT32_MAX vout,
 * zero value) or binds one complete positive-valued CTIP. Partial tuples are
 * invalid and must fail closed.
 */
bool IsCanonicalDrivechainParentCheckpointCtip(const uint256& txid,
                                                      const uint32_t vout,
                                                      const CAmount value);

bool IsCanonicalDrivechainParentCheckpointIdentity(
    const std::vector<unsigned char>& active_proposal_description,
    const std::optional<uint256>& active_proposal_hash,
    uint32_t proposal_height,
    const uint256& proposal_block_hash,
    uint32_t activation_height,
    const uint256& activation_block_hash,
    uint32_t checkpoint_height,
    const uint256& ctip_txid,
    uint32_t ctip_vout,
    CAmount ctip_value);

/** Pure, deterministic state used to replay the configured parent slot. */
struct DrivechainPendingProposal {
    uint32_t proposal_height{0};
    uint32_t votes{0};

    SERIALIZE_METHODS(DrivechainPendingProposal, obj)
    {
        READWRITE(obj.proposal_height, obj.votes);
    }
};

/** One M3 withdrawal proposal, in chronological (M4 index) order. */
struct DrivechainPendingWithdrawal {
    uint256 m6id;
    uint32_t proposal_height{0};
    uint16_t votes{0};

    SERIALIZE_METHODS(DrivechainPendingWithdrawal, obj)
    {
        READWRITE(obj.m6id, obj.proposal_height, obj.votes);
    }
};

enum class DrivechainM4ActionType : uint8_t {
    UPVOTE = 1,
    ALARM = 2,
};

/** Effective per-slot M4 action retained for RepeatPrevious. */
struct DrivechainM4Action {
    DrivechainM4ActionType type{DrivechainM4ActionType::ALARM};
    uint256 m6id;

    SERIALIZE_METHODS(DrivechainM4Action, obj)
    {
        uint8_t encoded_type = static_cast<uint8_t>(obj.type);
        READWRITE(encoded_type, obj.m6id);
        SER_READ(obj, obj.type = static_cast<DrivechainM4ActionType>(encoded_type));
    }
};

/** Replay state for every active or proposed parent slot other than ours. */
struct DrivechainOtherSlotReplayState {
    uint256 active_proposal_hash;
    std::map<uint256, DrivechainPendingProposal> pending_proposals;
    std::vector<DrivechainPendingWithdrawal> pending_withdrawals;
    std::optional<Sidechain::Bitcoin::COutPoint> ctip;
    CAmount ctip_value{0};

    SERIALIZE_METHODS(DrivechainOtherSlotReplayState, obj)
    {
        READWRITE(obj.active_proposal_hash,
                  obj.pending_proposals,
                  obj.pending_withdrawals);
        bool has_ctip = obj.ctip.has_value();
        READWRITE(has_ctip);
        SER_READ(obj, {
            if (has_ctip) {
                obj.ctip.emplace();
            } else {
                obj.ctip.reset();
            }
        });
        if (has_ctip) READWRITE(obj.ctip.value());
        READWRITE(obj.ctip_value);
    }
};

struct DrivechainParentReplayState {
    // The configured Elements slot remains in the top-level fields so launch
    // milestones and deposit lookups stay compact. Every other slot is kept in
    // other_slots because M4 vote indices depend on the complete active-slot
    // set, not merely on slot 24.
    uint256 active_proposal_hash;
    bool required_proposal_activated{false};
    uint32_t required_activation_height{0};
    uint256 required_activation_block_hash;
    std::map<uint256, DrivechainPendingProposal> pending_proposals;
    std::vector<DrivechainPendingWithdrawal> pending_withdrawals;
    std::optional<Sidechain::Bitcoin::COutPoint> ctip;
    CAmount ctip_value{0};
    std::map<uint8_t, DrivechainOtherSlotReplayState> other_slots;
    std::map<uint8_t, DrivechainM4Action> previous_m4_actions;

    SERIALIZE_METHODS(DrivechainParentReplayState, obj)
    {
        READWRITE(obj.active_proposal_hash,
                  obj.required_proposal_activated,
                  obj.required_activation_height,
                  obj.required_activation_block_hash,
                  obj.pending_proposals,
                  obj.pending_withdrawals);
        bool has_ctip = obj.ctip.has_value();
        READWRITE(has_ctip);
        SER_READ(obj, {
            if (has_ctip) {
                obj.ctip.emplace();
            } else {
                obj.ctip.reset();
            }
        });
        if (has_ctip) READWRITE(obj.ctip.value());
        READWRITE(obj.ctip_value,
                  obj.other_slots,
                  obj.previous_m4_actions);
    }
};

struct DrivechainMintableDeposit {
    Sidechain::Bitcoin::COutPoint outpoint;
    uint256 block_hash;
    uint32_t block_height{0};
    CAmount value{0};
    std::vector<unsigned char> address;

    SERIALIZE_METHODS(DrivechainMintableDeposit, obj)
    {
        READWRITE(obj.outpoint,
                  obj.block_hash,
                  obj.block_height,
                  obj.value,
                  obj.address);
    }
};

/** Discover mature candidates from the local authenticated index, without doing parent RPC.
 * Discovery does not authorize minting: normal transaction validation remains mandatory.
 */
bool ListDrivechainDepositCandidates(const std::optional<Sidechain::Bitcoin::COutPoint>& after,
    int child_height, std::vector<DrivechainMintableDeposit>& deposits,
    std::optional<Sidechain::Bitcoin::COutPoint>& next, std::string* error);

/** One authenticated active-parent P -> Q edge derived during replay. */
struct DrivechainReplayedBmmEdge {
    uint256 successor_hash;
    uint32_t parent_height{0};
    uint32_t successor_height{0};
    bool has_canonical_commitment{false};
    uint256 committed_sidechain_hash;

    SERIALIZE_METHODS(DrivechainReplayedBmmEdge, obj)
    {
        READWRITE(obj.successor_hash,
                  obj.parent_height,
                  obj.successor_height,
                  obj.has_canonical_commitment,
                  obj.committed_sidechain_hash);
    }
};

/** One successful BIP300 M6 derived from an authenticated active parent block. */
struct DrivechainSuccessfulWithdrawal {
    uint8_t sidechain_slot{0};
    uint256 m6id;
    uint32_t block_height{0};
    uint256 block_hash;

    SERIALIZE_METHODS(DrivechainSuccessfulWithdrawal, obj)
    {
        READWRITE(obj.sidechain_slot,
                  obj.m6id,
                  obj.block_height,
                  obj.block_hash);
    }
};

/** One fresh M3 accepted while deriving a parent-state transition. */
struct DrivechainWithdrawalProposalIdentity {
    uint8_t sidechain_slot{0};
    uint256 m6id;
};

static const bool DEFAULT_NAMED=false;
static const char DEFAULT_RPCCONNECT[] = "127.0.0.1";
static const int DEFAULT_HTTP_CLIENT_TIMEOUT=900;

//
// Exception thrown on connection error.  This error is used to determine
// when to wait if -rpcwait is given.
//
class CConnectionFailed : public std::runtime_error
{
public:

    explicit inline CConnectionFailed(const std::string& msg) :
        std::runtime_error(msg)
    {}

};

/** Result of running one direct-argv child with bounded time and output. */
struct BoundedCommandResult {
    bool started{false};
    bool exited{false};
    bool timed_out{false};
    bool cancelled{false};
    bool output_truncated{false};
    int exit_code{-1};
    std::string output;
    std::string error;
};

/** Classify process failures before exit status or caller-authorized duplicate handling. */
enum class DrivechainGrpcStatus { SUCCESS, PROCESS_FAILURE, NONZERO_EXIT };
DrivechainGrpcStatus ClassifyDrivechainGrpcResult(const BoundedCommandResult& child,
    bool accept_duplicate, std::string& error);

/** Execute argv directly, never through a shell, and always reap the child. */
BoundedCommandResult RunBoundedCommand(
    const std::vector<std::string>& argv,
    std::chrono::milliseconds timeout,
    size_t max_output,
    const std::function<bool()>& should_cancel = {});

/** Validate the mandatory CA, client certificate, and client key. */
bool ValidateDrivechainGrpcTLSConfig(
    const ArgsManager& args,
    std::string* error = nullptr);

/** Call an allowlisted enforcer method through the linked Haskell mTLS client.
 * Canonical gRPC status codes (including TLS rejection) use exit_code and output;
 * negative local failures use error. Interpret both with ClassifyDrivechainGrpcResult.
 */
BoundedCommandResult RunAuthenticatedDrivechainGrpc(
    const ArgsManager& args,
    const std::string& method,
    const std::string& json_payload,
    std::chrono::milliseconds timeout,
    size_t max_output,
    const std::function<bool()>& should_cancel = {});
BoundedCommandResult RunAuthenticatedDrivechainGrpc(
    const std::string& method,
    const std::string& json_payload,
    std::chrono::milliseconds timeout,
    size_t max_output,
    const std::function<bool()>& should_cancel = {});

std::string GetDrivechainGrpcAddress(const ArgsManager& args);

/**
 * Bound synchronous parent-chain work performed while a caller holds sidechain
 * consensus locks. Nested scopes on the same thread share one deadline and one
 * uncached-replay allowance rather than resetting the budget.
 */
class DrivechainParentValidationBudget
{
public:
    explicit DrivechainParentValidationBudget(bool enable);
    ~DrivechainParentValidationBudget();

    DrivechainParentValidationBudget(const DrivechainParentValidationBudget&) = delete;
    DrivechainParentValidationBudget& operator=(const DrivechainParentValidationBudget&) = delete;

private:
    bool m_enabled{false};
};

/**
 * Mark an untrusted P2P block-admission scope. Cache misses in this scope may
 * consult only the background-authenticated replay M7 index; local mining,
 * reindex, and ConnectTip may perform live parent discovery.
 */
class DrivechainUntrustedParentAdmission
{
public:
    explicit DrivechainUntrustedParentAdmission(bool enable);
    ~DrivechainUntrustedParentAdmission();

    DrivechainUntrustedParentAdmission(const DrivechainUntrustedParentAdmission&) = delete;
    DrivechainUntrustedParentAdmission& operator=(const DrivechainUntrustedParentAdmission&) = delete;

private:
    bool m_enabled{false};
};

UniValue CallMainChainRPC(const std::string& strMethod, const UniValue& params);
/** Same authenticated loopback transport, explicitly scoped to a parent wallet. */
UniValue CallMainChainWalletRPC(const std::string& wallet, const std::string& method, const UniValue& params);
/** Validate an RPC envelope and copy its result; errors take precedence even when null is allowed. */
UniValue CheckDrivechainRPCReply(const std::string& method, const UniValue& reply, bool require_result = true);
UniValue CallMainChainRPCChecked(const std::string& method, const UniValue& params);
/**
 * Call an allowlisted unary CUSF RPC through the bounded, authenticated gRPC transport.
 *
 * The endpoint must exactly match the configured loopback host:port (no URL
 * scheme); method is the fully-qualified service/method path without a leading
 * slash. Uses the linked Haskell gRPC client without a subprocess.
 */
bool CallAuthenticatedDrivechainJSON(
    const std::string& endpoint,
    const std::string& method,
    const UniValue& request,
    UniValue& response,
    std::string* error = nullptr);
/** Encode the shared protobuf JSON request; callers retain admission checks. */
UniValue BuildDrivechainBmmRequest(int sidechain_slot, uint64_t bid_sats, int64_t parent_height,
    const uint256& critical_hash, const uint256& previous_parent_hash);
/**
 * Fund, sign and broadcast a BIP301 M8 bid through the explicit parent RPC wallet.
 *
 * The bid is paid on the parent chain. The committed critical hash identifies
 * the Elements candidate whose policy-asset fees are collected by its
 * coinbase destination.
 */
bool SubmitDrivechainBmmBid(
    int sidechain_slot,
    uint64_t bid_sats,
    uint32_t parent_height,
    const uint256& critical_hash,
    const uint256& previous_parent_hash,
    uint256& request_txid,
    std::string* error = nullptr,
    const std::function<bool()>& cancelled = [] { return false; });
bool GetDrivechainTwoWayPegData(int sidechain_slot, UniValue& response, std::string* error = nullptr);
bool VerifyDrivechainDeposit(
    const CTransaction& tx,
    size_t input_index,
    drivechain::AuthenticatedDeposit* authenticated = nullptr,
    std::string* error = nullptr);
/** Build committed v2 SPV/CTIP evidence outside consensus validation. */
bool BuildDrivechainDepositEvidence(
    const drivechain::AuthenticatedDeposit& authenticated,
    DrivechainDepositEvidence& evidence,
    std::string* error = nullptr);
/** Build and self-verify deterministic successor/BMM proof outside consensus. */
bool BuildDrivechainBmmProof(
    const drivechain::BmmL1State& previous_state,
    int64_t parent_height,
    const uint256& parent_hash,
    const uint256& critical_hash,
    drivechain::BmmProof& proof,
    std::string* error = nullptr);

/**
 * Replay and authenticate the configured parent chain through its current tip.
 * This performs RPC and potentially substantial replay work and therefore must
 * be called only outside cs_main/mempool locks.
 */
bool WarmDrivechainParentState(std::string* error = nullptr);

/**
 * Return the current authenticated parent replay generation without RPC.
 * Zero means no replay identity is currently initialized. The value changes
 * whenever a parent reorganization forces a genesis replay rebuild.
 */
uint64_t GetDrivechainParentReplayEpoch();

/** Immutable derived-store identity; requires configured slot and proposal hash. */
uint256 DrivechainParentReplayStoreIdentity(const Consensus::Params& consensus);

/** Validate proposal, activation and checkpoint milestones without network reads. */
bool CheckDrivechainParentReplayMilestone(const Consensus::Params& consensus, uint32_t height,
    const Sidechain::Bitcoin::CBlock& block, const DrivechainParentReplayState& state, std::string* error);

/** Append the canonical bootstrap preimage using upstream typed serialization. */
void WriteDrivechainBootstrapPreimage(HashWriter& writer, const Consensus::Params& consensus,
    std::span<const ElementsDrivechainBootstrap::Slot> slots);

/**
 * Query the authenticated active-parent replay for a previously successful M6.
 *
 * A false return is an authentication, replay, or index failure and callers
 * must fail closed. A true return with an empty result means the M6 has not
 * succeeded on the current active parent chain. The derived index is rebuilt
 * from authenticated genesis whenever the parent chain reorganizes.
 */
bool GetDrivechainSuccessfulWithdrawal(
    int sidechain_slot,
    const uint256& m6id,
    std::optional<DrivechainSuccessfulWithdrawal>& result,
    std::string* error = nullptr);

/** Pure snapshot-ordering rule used by cold and cached BMM validation. */
bool ShouldReplaceDrivechainReplaySnapshot(bool current_authenticated,
                                           uint32_t current_height,
                                           bool current_explicit_target,
                                           bool next_explicit_target,
                                           uint32_t next_height);

// Verify if the block with given hash has at least the specified minimum number
// of confirmations.
// For validating merkle blocks, you can provide the nbTxs parameter to verify if
// it equals the number of transactions in the block.
bool IsConfirmedBitcoinBlock(const uint256& hash, const int nMinConfirmationDepth, const int nbTxs);

bool ExtractDrivechainParentHashFromBlock(const CBlock& block, uint256& parent_hash, std::string* error = nullptr);
/** Build the one canonical, domain-separated child coinbase P commitment. */
CScript CreateDrivechainParentCommitmentScript(const uint256& parent_hash);
bool IsDrivechainBmmCommitmentMined(const uint256& critical_hash, const uint256& parent_hash, int sidechain_slot, std::string* error = nullptr);
/** True when a fixed P -> Q edge proves that this BMM candidate cannot win. */
bool IsDefinitiveDrivechainBmmWaitError(const std::string& error);

/** Strictly parse the authenticated parent's getblockheader result. */
bool ParseDrivechainParentHeader(const UniValue& header,
                                 const uint256& expected_hash,
                                 uint64_t& median_time_past,
                                 std::string* error = nullptr);

/**
 * Authenticate the parent committed by a candidate block without requiring an
 * M7 successor that cannot exist until the candidate hash is known.
 */
bool GetDrivechainParentBlockContext(const CBlock& block,
                                     int sidechain_slot,
                                     DrivechainParentBlockContext& context,
                                     std::string* error = nullptr);

/** Authenticate a stable active parent tip for native mempool admission.
 * This is not an inclusion proof; candidate validation must authenticate its
 * own committed P again. On failure the result is cleared.
 */
bool GetDrivechainMempoolParentContext(int sidechain_slot,
                                      DrivechainParentBlockContext& context,
                                      std::string* error = nullptr);

/** Compatibility overload while validation migrates to the parent-only type. */
bool GetDrivechainParentBlockContext(const CBlock& block,
                                     int sidechain_slot,
                                     DrivechainBmmBlockContext& context,
                                     std::string* error = nullptr);

/** Validate BMM and return context for this exact derived critical hash. */
bool GetDrivechainBmmBlockContext(const CBlock& block,
                                  const uint256& expected_critical_hash,
                                  int sidechain_slot,
                                  DrivechainBmmBlockContext& context,
                                  std::string* error = nullptr);

/**
 * Status-preserving BMM validation for consensus callers.  Only INVALID may
 * be recorded as permanent block invalidity; PARENT_REJECTED and UNAVAILABLE
 * must remain reconsiderable.  Context is populated for VALID and
 * PARENT_REJECTED, identifying the exact authenticated P -> Q edge observed.
 */
DrivechainBmmStatus GetDrivechainBmmBlockStatus(const CBlock& block,
                                                const uint256& expected_critical_hash,
                                                int sidechain_slot,
                                                DrivechainBmmBlockContext& context,
                                                std::string* error = nullptr);

/**
 * Reconcile a persisted P -> Q anchor with the parent node's active chain.
 * Only a canonical active-height hash mismatch is ORPHANED.  RPC, transport,
 * decoding, or authentication failures are UNAVAILABLE and must never cause a
 * rollback.
 */
DrivechainAnchorStatus IsDrivechainAnchorActive(const DrivechainAnchor& anchor,
                                                int sidechain_slot,
                                                std::string* error = nullptr);

/**
 * Positive-only startup authentication results, bound to one exact parent tip
 * and replay generation. The complete serialized anchor is the identity, not
 * merely its P/Q hashes. Callers must freshly fence the parent tip before a
 * reconciliation pass and check its generation/deadline on every lookup.
 * This is not a replay snapshot and must never widen a child's exact Q-bound
 * deposit context. ORPHANED results are deliberately not retained here.
 */
class DrivechainAnchorSnapshot
{
    int m_slot;
    uint256 m_parent_tip;
    uint64_t m_epoch;
    std::map<uint256, std::vector<unsigned char>> m_active_anchors;

public:
    DrivechainAnchorSnapshot(int slot, const uint256& parent_tip, uint64_t epoch)
        : m_slot(slot), m_parent_tip(parent_tip), m_epoch(epoch) {}

    bool Matches(int slot, const uint256& parent_tip, uint64_t epoch) const;
    bool EpochMatches(int slot, uint64_t epoch) const;
    bool Add(const DrivechainAnchor& anchor, DrivechainAnchorStatus status);
    bool Contains(const DrivechainAnchor& anchor, int slot, uint64_t epoch) const;
    size_t Size() const { return m_active_anchors.size(); }
};

/** Authenticate a complete collection outside consensus locks, within 120s.
 * Interrupted, stale or unavailable collections are never published. */
bool WarmDrivechainAnchorSnapshot(
    const std::vector<DrivechainAnchor>& anchors, int sidechain_slot,
    const util::SignalInterrupt& interrupt,
    std::shared_ptr<const DrivechainAnchorSnapshot>& result,
    std::string* error = nullptr);

/** Fresh RPC tip fence plus generation/deadline validation before each pass. */
bool CheckDrivechainAnchorSnapshot(const DrivechainAnchorSnapshot& snapshot,
                                    int sidechain_slot, std::string* error = nullptr);

/** In-memory generation/deadline validation before every cached lookup. */
bool CheckDrivechainAnchorSnapshotEpoch(const DrivechainAnchorSnapshot& snapshot,
                                         int sidechain_slot, std::string* error = nullptr);

/** Validate exactly one M7 carrying the expected opaque critical hash. */
bool MatchDrivechainBmmCommitmentInBlock(const Sidechain::Bitcoin::CBlock& block,
                                         int sidechain_slot,
                                         const uint256& expected_critical_hash,
                                         uint32_t* output_index = nullptr,
                                         std::string* error = nullptr);

/** Parse exactly one enforcer-recognized M7 without interpreting its opaque hash. */
bool ExtractCanonicalDrivechainBmmCommitmentInBlock(
    const Sidechain::Bitcoin::CBlock& block,
    int sidechain_slot,
    uint256& committed_sidechain_hash,
    uint32_t* output_index = nullptr,
    std::string* error = nullptr);

/** Independently validate one exact BIP300 M5 transaction in a raw Bitcoin block. */
bool MatchDrivechainDepositInBlock(
    const Sidechain::Bitcoin::CBlock& block,
    int sidechain_slot,
    const COutPoint& outpoint,
    CAmount value,
    const std::vector<unsigned char>& address,
    const std::map<Sidechain::Bitcoin::COutPoint, Sidechain::Bitcoin::CTxOut>& previous_outputs,
    std::string* error = nullptr);

/**
 * Apply one already-authenticated active parent block to slot proposal/CTIP
 * state.  This function is pure so the exact replay rules can be unit tested.
 */
bool ApplyDrivechainParentBlockState(
    const Sidechain::Bitcoin::CBlock& block,
    uint32_t height,
    int sidechain_slot,
    const uint256& required_active_proposal,
    uint16_t unused_slot_proposal_max_age,
    uint16_t unused_slot_activation_threshold,
    uint16_t used_slot_proposal_max_age,
    uint16_t used_slot_activation_threshold,
    uint16_t withdrawal_bundle_max_age,
    uint16_t withdrawal_bundle_inclusion_threshold,
    DrivechainParentReplayState& state,
    std::vector<DrivechainMintableDeposit>* deposits = nullptr,
    std::string* error = nullptr,
    std::vector<DrivechainSuccessfulWithdrawal>* successful_withdrawals = nullptr,
    std::vector<DrivechainWithdrawalProposalIdentity>* withdrawal_proposals = nullptr,
    drivechain::TreasuryOpcode treasury_opcode = drivechain::TreasuryOpcode::NOP5,
    DrivechainM6ReplayRule m6_rule = DrivechainM6ReplayRule::SINGLE_CONFIGURED_SLOT_M6);

/** Derive the canonical blinded BIP300 M6 transaction id. */
bool ComputeDrivechainM6Id(const Sidechain::Bitcoin::CTransaction& transaction,
                           CAmount previous_treasury_value,
                           uint256& m6id,
                           uint8_t* sidechain_slot = nullptr,
                           std::string* error = nullptr,
                           drivechain::TreasuryOpcode treasury_opcode = drivechain::TreasuryOpcode::NOP5);

/**
 * Authenticate the containing parent block and require one exact BIP300 M5
 * deposit.  Callers in consensus validation must preserve UNAVAILABLE as a
 * retryable validation stall rather than converting it to block invalidity.
 * child_height must come from the validated child block index (active tip + 1
 * for admission), never from the witness. Unknown context retains the
 * historical confirmation depth.
 */
DrivechainDepositStatus GetConfirmedDrivechainDepositStatus(
    const uint256& mainchain_block_hash,
    int sidechain_slot,
    const COutPoint& outpoint,
    CAmount value,
    const std::vector<unsigned char>& address,
    std::string* error = nullptr,
    int child_height = -1);

/** Compatibility wrapper for non-consensus callers. */
bool IsConfirmedDrivechainDeposit(const uint256& mainchain_block_hash,
                                  int sidechain_slot,
                                  const COutPoint& outpoint,
                                  CAmount value,
                                  const std::vector<unsigned char>& address,
                                  std::string* error = nullptr,
                                  int child_height = -1);

/** Inclusive confirmations through an authenticated parent anchor; never accepts a future deposit. */
bool HasRequiredDrivechainDepositDepth(uint32_t deposit_height,
                                      uint32_t confirmed_through_height,
                                      uint32_t required_depth);

#endif // BITCOIN_MAINCHAINRPC_H
