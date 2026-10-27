// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#ifndef ELEMENTS_HASKELL_BRIDGE_H
#define ELEMENTS_HASKELL_BRIDGE_H

#include <cstdint>
#include <cstddef>
#include <array>
#include <span>
#include <string>
#include <vector>
#include <functional>
#include <iterator>
#include <initializer_list>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <utility>

class CTransaction;
class CScript;
class uint256;
namespace Sidechain::Bitcoin { class CBlock; }

namespace drivechain::haskell {
using NativeWorkflow = std::function<std::vector<unsigned char>(uint32_t, uint64_t, std::span<const unsigned char>)>;
// Owns transient Signet objects; the supplied block, challenge and genesis must outlive it.
NativeWorkflow PrepareParentSignet(const Sidechain::Bitcoin::CBlock& block,
    const CScript& challenge, const uint256& genesis, std::string* error);
enum class AuthFileMode : uint32_t { RAW, STATIC_RECORD, ROTATING_COOKIE };
bool ProductionIdentity(const std::function<bool(uint32_t)>& read, std::string* error);
bool ReadAuthFile(AuthFileMode mode, const NativeWorkflow& native);
enum class ReplayStoreWorkflow : uint32_t { CHECK_TIP, APPEND, DEPOSIT, EDGE, WITHDRAWAL, OCCURRENCE, LIST_DEPOSITS, LOAD, RESET, CACHE, MILESTONE, BMM, LOAD_SESSION, RESET_SESSION, APPEND_SESSION, DEPOSIT_ADMISSION, CONFIRMED_DEPOSIT, DEPOSIT_SESSION, SCAN_SESSION, DEPOSIT_CANDIDATES, PARENT_NETWORK, ACTIVE_HASH, CONFIRMATION_DEPTH, ALPHA_PEGIN_IDENTITY, RPC_TRANSPORT, RPC_TRANSPORT_CHECKED, RPC_HOST, LOCAL_BID, BID_SUBMISSION, BMM_CONTEXT, WALLET_WITHDRAWAL, JOURNAL_VALIDATE, JOURNAL_READ, JOURNAL_WRITE, JOURNAL_CLEAR, BMM_PROOF_REQUIRED, BMM_HEADER_POLICY, BMM_STATE_READ, BMM_STATE_EFFECTIVE, BMM_STATE_CONTEXT, STATE_STORE, STATE_RESTORE, PROOF_ENCODE, PROOF_DECODE, PROOF_ATTACH, PROOF_ENTRIES, PROOF_BLOCK, PROOF_PARENT, CHAIN_CONNECT, CHAIN_DISCONNECT, COMMITMENT };
uint32_t RunReplayStore(ReplayStoreWorkflow mode, const NativeWorkflow& native);
enum class ParentHeaderWorkflow : uint32_t { POW, WORK, CHAINWORK, RAW, MEDIAN, RPC_MEDIAN,
    HASH, METADATA, PREDECESSOR, VERIFY, RPC_VERIFY, RAW_DEADLINE, RPC_MEDIAN_DEADLINE, RPC_VERIFY_DEADLINE,
    BLOCK_TRANSACTIONS, BLOCK_SIGNET, BLOCK, BLOCK_DEADLINE,
    SIGNET_VERIFY, SIGNET_MERKLE, SIGNET_BUILD, SIGNET_DATA, SIGNET_COMMITMENT, NETWORK_VERIFY,
    READ_BODY, READ_BLOCK };
bool RunParentHeader(ParentHeaderWorkflow kind, uint32_t height,
    const std::function<uint64_t(uint32_t, uint64_t)>& native);
bool RunParentHeader(ParentHeaderWorkflow kind, uint32_t height, const NativeWorkflow& native);
enum class BitcoinSignatureWorkflow : uint32_t { BMM, PARENT, HASH };
bool RunBitcoinSignature(BitcoinSignatureWorkflow kind, int32_t hash_type, bool witness,
    uint32_t index, uint64_t inputs, uint64_t outputs, std::span<const unsigned char> signature,
    const NativeWorkflow& native);
bool MeasureWork(bool saturate, uint64_t count, const std::function<const CTransaction&(uint64_t)>& transaction,
    uint64_t& total, uint64_t* last = nullptr);
bool AnchorRule(std::span<const std::byte> encoded);
std::optional<std::array<unsigned char,80>> AnchorCheckpoint(std::span<const std::byte> encoded);
bool BmmWorkQuote(int64_t fees, uint64_t work, int64_t rate, int64_t reserve, std::array<int64_t,3>& fields);
/** RPC view: rejected quotes clear all fields; true means a positive funded bid. */
bool BmmWorkQuoteDisplay(int64_t fees, uint64_t work, int64_t rate, int64_t reserve, std::array<int64_t,3>& fields);
enum class BmmMessageKind : uint32_t { DEFINITIVE_WAIT, DUPLICATE_REQUEST };
bool BmmMessageMatches(BmmMessageKind kind, const std::string& message);
int BmmWorkBid(uint32_t hashes, int64_t height, int64_t fees, int64_t work, int64_t reserve,
    int64_t requested, const std::function<int64_t(uint32_t)>& rate, std::array<int64_t,4>& fields);
bool DepositInputLimit(bool enabled, uint64_t count, uint64_t limit,
    const std::function<uint64_t(uint32_t,uint64_t,uint64_t)>& read);
bool StartupArgs(uint32_t slot, uint32_t timeout_maximum, const std::function<uint64_t(uint32_t)>& read);
void FeeFreeSelection(int64_t age, const std::function<uint64_t(uint32_t)>& read);
enum class ConfigurationField : uint32_t { RAW_HASH, NONZERO_HASH, OUTPOINT, SPENDABLE_SCRIPT, DISPLAY_HASH, CONFIGURATION_HEX, CUSTODIAN_REGISTRY, PROPOSAL_DESCRIPTION = 9 };
enum class NetworkSelection : uint32_t { PRODUCTION, CHAIN_NAME, REGTEST_OPTION };
void ScriptCacheEncode(bool endpoint_only, std::span<const std::byte> input, std::span<unsigned char> output);
enum class CtvAction : uint8_t { IGNORE, DISCOURAGE, EMPTY_STACK, CHECK_HASH };
CtvAction CtvAdmission(uint32_t flags, uint64_t size);
uint32_t NetworkSelectionStatus(NetworkSelection kind, const std::string& text, bool elements_mode = false);
void ValidateNetworkSelection(NetworkSelection kind, const std::string& text, bool elements_mode = false);
bool RejectWalletIssueAmount(double amount);
bool MainchainCookieAtRoot(const std::string& chain);
bool AcceptAddressAlias(bool parent, bool confidential, const std::string& network, const std::string& prefix);
bool AcceptPaymentUri(bool elements_mode, bool canonical, std::string_view scheme);
std::string_view PaymentUriScheme(bool elements_mode, bool canonical, bool liquid_testnet);
// Callbacks must not reenter Haskell. Failure is {zero-based role, nonzero violation}.
std::vector<unsigned char> ParseConfigurationField(ConfigurationField kind, const std::string& text,
    const std::string& syntax_error, const std::string& value_error);
// One field admits a method; two admit method/payload; eight also build argv.
std::vector<std::string> GrpcPlan(std::span<const std::string> fields);
struct GrpcResponse { int status; std::string output; };
GrpcResponse GrpcRequest(std::span<const std::string, 7> fields, int64_t timeout_ms,
    size_t max_output, const std::function<bool()>& should_cancel);
struct GrpcTextAdmission { bool address_shape, address_characters, authority_characters; };
GrpcTextAdmission AdmitGrpcText(const std::string& address, const std::string& authority);
// Result bits: 1 = identities valid, 2 = evaluator active. Bridge failures throw.
bool AdmitTlsCredentialFile(bool private_key, const std::function<uint64_t(uint32_t)>& read);
int64_t WalletBalanceTotal(int64_t trusted, int64_t pending, int64_t immature);
/** Fresh inactive exact-inbox codecs. These do not authenticate signatures or
 * source headers. Full-width fields always use (high64, low64). */
// Internal structural codecs. They never produce a verified execution receipt.
bool FitsU32(std::span<const uint64_t> fields);
uint32_t PegEventRange(int32_t start, int32_t count, int32_t tip, int32_t& end);
int32_t PegEventStart(int32_t tip);
/** Strict fresh exact-custody codec/pin/lineage checks; no proof authentication. */

// REMOVE performs ordered mutations; a later failure does not roll back earlier steps.
// 0: valid; 1: malformed; 2: missing coin (encoding phase only).
using CustodyHash = std::function<std::array<unsigned char,32>(uint32_t, std::span<const unsigned char>)>;
// Reader supplies borrowed bytes (group 1) or scalars; no callback may reenter Haskell.
using FingerprintReader = std::function<bool(uint32_t, uint32_t, uint64_t&, const unsigned char*&)>;
// Profile 0 is BMM v4; retired and unknown profiles fail closed.
std::vector<unsigned char> BmmFingerprint(const FingerprintReader& reader, uint32_t profile = 0);
int64_t BoundedWait(int64_t value, int64_t maximum);
uint64_t BoundedAppend(uint64_t limit, uint64_t used, int64_t count);
int64_t BmmDifficultyInterval(int64_t timespan, int64_t spacing);
void BmmFixedIdentity(std::span<uint32_t, 2> fields, std::span<unsigned char, 121> payload);
void BmmCheckpointPreset(uint32_t mode, std::span<uint32_t, 16> fields,
    std::span<unsigned char, 32> block_hash);
uint32_t BmmConsensusPreset(uint32_t mode, std::span<uint64_t, 6> fields,
    std::span<unsigned char, 32> pow_limit, std::span<unsigned char, 22> challenge);
void BmmPrivateTemplate(uint32_t height, uint32_t time, uint32_t median, uint32_t slot,
    std::span<const unsigned char, 32> critical, std::span<uint32_t, 4> fields,
    std::span<unsigned char, 37> commitment);
enum class LiveEvidencePhase : uint32_t { NETWORK, CONFIRMATION, CTIP_OUTPUT, CTIP_STATE, SIDECHAIN, DEPOSITS };
bool BmmState(bool hash, int64_t interval, uint32_t height, uint32_t time, uint32_t bits,
    uint32_t start, uint32_t start_time, uint64_t count, uint32_t latest, std::string& error);
std::array<uint32_t,2> BmmHeaderLayout(uint32_t version, uint32_t flags);
bool MerkleReplacement(uint32_t mode, uint32_t index, uint32_t position, uint32_t flags);
enum class SignetStep : uint32_t { START, WITNESS, EXTRACT, BUILD, DECODE, MERKLE, COINBASE, VERIFY };
int32_t BmmActivation(uint32_t phase, uint32_t facts, int64_t height = 0, int64_t activation = 0);
void RunBmmRetarget(uint32_t height, int64_t interval, int64_t target, uint32_t time, uint32_t start,
    const NativeWorkflow& native);
uint32_t BmmMedian(std::span<const uint32_t> times);
enum class BmmProofPhase : uint32_t { ENVELOPE, BOUNDS, CANONICAL, MERKLE, EXTENSION, PARENT, CRITICAL, BLOCK_BOUNDS, BLOCK_HASH, PRIOR, MERKLE_HASH, POW_TARGET, POW_HASH, COINBASE_PRESENT };
enum class BmmTraversalStep : uint32_t {
    START, PREFLIGHT, ENTRY_BOUNDS, MERKLE, COINBASE, EXTENSION, SIGNET, ADVANCE, PARENT, COMMITMENT, CRITICAL,
    BLOCK_START, BLOCK_BOUNDS, BLOCK_HASH, BLOCK_DECODE, BLOCK_PRIOR, BLOCK_PARENT, BLOCK_ENTRIES,
    INITIALIZE_ENTRIES, PUBLISH_ENTRIES, PREPARE_ENTRY,
    PARENT_START, PARENT_COINBASE, PARENT_EXTRACT,
    VALID_STATE = 147, EXTEND_PARENT = 150, EXTEND_BITS, EXTEND_TIME,
    POW_TARGET = 154, POW_HASH, RESET_ENTRY = 200, DECODE_COINBASE,
    DECODE_MERKLE, CANONICAL_COINBASE, CANONICAL_MERKLE, COINBASE_SHAPE
};
enum class BmmLifecyclePhase : uint32_t {
    CONNECT_KIND, NATIVE_STATE, CONNECT_CHECKPOINT, INITIALIZE, REQUIRED, INCOMPLETE,
    DISCONNECT_KIND, REMOVE_CHECKPOINT, REMOVED, DISCONNECT_PROOF, LOAD_CURRENT, RESTORE
};
enum class BmmStateStep : uint32_t {
    CONNECT_START, CONNECT_KIND, NATIVE_HEADER, NATIVE_STATE, CHECKPOINT, INITIALIZE, STORE_INITIAL,
    REQUIRED, INCOMPLETE, EFFECTIVE, VERIFY, STORE_NEXT, DISCONNECT_START, DISCONNECT_KIND,
    REMOVE_CHECKPOINT, REMOVE, HAS_PROOF, DECODE_PROOF, LOAD_CURRENT, EXTRACT_PARENT, STORE_PRIOR,
    VERIFY_ENTRIES, COMPARE_CURRENT, REJECT_PRIOR,
    PRIVATE_START, PRIVATE_ENABLED, PRIVATE_VALID, PRIVATE_COINBASE, PRIVATE_HEADER,
    PRIVATE_POW, PRIVATE_NONCE, PRIVATE_ASSEMBLE, PRIVATE_VERIFY,
    READ_START, READ_PUSH, READ_DROP, READ_END, READ_MARKER, READ_STATE, READ_PAYLOAD, READ_VALID,
    ENTRY_START, ENTRY_TX, ENTRY_PROOF, ENTRY_TX_CANONICAL, ENTRY_PROOF_CANONICAL,
    PREFLIGHT_START, PREFLIGHT_ENVELOPE, PREFLIGHT_STATE,
    EXTEND_START, EXTEND_PARENT, EXTEND_DIFFICULTY, EXTEND_TIME, EXTEND_CHECK, EXTEND_POW,
    ATTACH_START, ATTACH_GATE, ATTACH_SERIALIZE, ATTACH_PUBLISH,
    CONTEXT_START, CONTEXT_VALID, CONTEXT_MEDIAN, CONTEXT_PUBLISH,
    PROOF_START, PROOF_SIZE, PROOF_DECODE, PROOF_SHAPE, PROOF_CANONICAL,
    EFFECTIVE_START, EFFECTIVE_NETWORK, EFFECTIVE_LOAD, EFFECTIVE_PUBLIC, EFFECTIVE_PUBLISH_PUBLIC,
    EFFECTIVE_PRIVATE, EFFECTIVE_PUBLISH_PRIVATE,
    ACTIVATION_START, ACTIVATION_PREFLIGHT, MODE_SELECT, MODE_PRIVATE, MODE_PUBLIC,
    CONSENSUS_START, RETARGET_START, RETARGET_SPAN, RETARGET_SCALE,
    POW_START, POW_TARGET, POW_HASH,
    EXTRACT_START, EXTRACT_SELECT, EXTRACT_FIRST, EXTRACT_SECOND, EXTRACT_PUBLISH,
    PARENT_START, PARENT_COINBASE, PARENT_EXTRACT,
    SIGNATURE_START, SIGNATURE_GATE, SIGNATURE_KEY, SIGNATURE_SPLIT, SIGNATURE_HASH, SIGNATURE_VERIFY,
    COIN_START, COIN_UNSPENT, COIN_ASSET, COIN_PEGGED, COIN_VALUE, COIN_ZERO,
    NATIVE_CHECK_START, NATIVE_CHECK_PROOF, NATIVE_CHECK_LOOKUP, NATIVE_CHECK_RESULT,
    PARENT_SIGNATURE_START, PARENT_SIGNATURE_GATE, PARENT_SIGNATURE_ENCODING, SIGNATURE_MODE
};
bool RunBmmStateFlow(BmmStateStep start, const std::function<int32_t(BmmStateStep)>& action);
enum class PegEventKind : uint32_t { LIFECYCLE, DEPOSIT_NUMBERS, STATUS };
enum class EventIdentityKind : uint32_t { BUNDLE, DEPOSIT, WITHDRAWAL, L1_DEPOSIT, L1_WITHDRAWAL };
enum class EventLayoutKind : uint32_t {
    BUNDLE, DEPOSIT, WITHDRAWAL, L1_DEPOSIT, L1_WITHDRAWAL, BUNDLE_ID, SIDECHAIN,
    SEQUENCE, TRANSACTION, ACKNOWLEDGEMENT, L1, SIDECHAIN_BLOCK, BLOCK_HASH, HEIGHT, TIMESTAMP,
    BMM_REQUEST, HEX, TWO_WAY_PEG_REQUEST
};
// Views are borrowed only for the duration of append, outside any interpreter call.
void EventFields(EventLayoutKind kind, uint32_t status,
    const std::function<void(uint32_t, std::string_view, std::optional<std::string_view>)>& append);
std::string EventIdentity(EventIdentityKind kind, const std::string& hash, uint64_t number, uint32_t status = 0);
int64_t PegEvent(PegEventKind kind, int64_t a, int64_t b, int64_t c = 0);
int64_t WithdrawalStatus(int64_t state, const std::string& status);
void WithdrawalStatusFlow(const std::function<bool(uint32_t)>& action);
void L1NormalizationFlow(const std::function<bool(uint32_t)>& action);
void SidechainEventFlow(const std::function<bool(uint32_t)>& action);
void L1LocationFlow(const std::function<bool(uint32_t)>& action);
enum class PegSchemaKind : uint32_t { TYPE, INTEGER, HEX, FIELD, NULL_DEFAULT, FALSE_BOOLEAN, GUARDED };
bool PegSchema(PegSchemaKind kind, uint64_t limit, const std::function<uint64_t(uint32_t)>& read);
void ReadWhen(bool present, const std::function<void()>& read);
uint32_t ParentReplaySchema(uint32_t rule, uint32_t unique_version, uint32_t reproposal_version);
enum class ReplayRecordKind : uint32_t { DEPOSIT = 1, EDGE, WITHDRAWAL, HEIGHT, PROPOSAL_VOTES, WITHDRAWAL_VOTES, AMOUNT, ADVANCEABLE_HEIGHT, SUCCESSOR_HEIGHT, POSITIVE, LESS, SNAPSHOT, MTP_SAMPLE, PERIODIC_DEADLINE, SIGNED_POSITIVE, CHECKPOINT_CTIP, ACTIVATION_WINDOW, CTIP_BALANCE, PROPOSAL_EXPIRED, ANCHOR_EPOCH, EPOCH_CHANGED, SIGNED_HEIGHT_WINDOW, CONFIGURED_SLOT, AMOUNT_SUM, CACHE_EXPIRED = 27, LANE_EXCEEDED, NONEMPTY_BOUNDED, CURRENT_EPOCH = 31, SIGNED_PREDECESSOR };
bool ParentReplayRecord(ReplayRecordKind kind, uint32_t flags, int64_t value = 0, uint64_t first = 0, uint64_t second = 0);
enum class OutputTotalMode { DEFERRED, AGGREGATE, PER_ASSET, REJECT };
enum class DepositRoute { FEDERATED, NATIVE, ECX, REJECT_ECX, REJECT_FEDERATED };
struct DepositRouting { DepositRoute route; uint32_t expected_stack_size; };
DepositRouting SelectDepositRoute(uint64_t count, bool legacy_marker, bool native_marker, bool configured_slot);
OutputTotalMode SelectOutputTotalMode(bool deferred, bool per_asset, bool explicit_asset);
bool RejectParentResult(bool invalid, bool unavailable);
enum class ReplayStoreFlow : uint32_t {
    READ_RECORD, LOAD, LOAD_PREFLIGHT, RESET_PREFLIGHT, RESET,
    READ_PREFLIGHT, OCCURRENCE_PREFLIGHT, DEPOSIT, EDGE, WITHDRAWAL, OCCURRENCE, APPEND, IDENTITY,
    CACHE_CONFIG, CACHE_MATCH, CACHE_PREFLIGHT, CACHE_LOAD, BOOTSTRAP_PREIMAGE, CACHE_REBUILD,
    REPLAY_PREFLIGHT, REPLAY_PUBLISH, REPLAY_ADVANCE, REPLAY_BUDGET, REPLAY_SNAPSHOT, REPLAY_LOCK,
    PARENT_DEADLINE, PARENT_CIRCUIT, MILESTONE_HASH, MILESTONE,
    EXACT_MESSAGE, PINNED_STATE, SINGLE_PUSH, EXACT_ADDRESS, CANONICAL_HASH,
    HEIGHT_PREFLIGHT, HEIGHT_PARSE, PARENT_POW, BLOCK_PROOF, CHAINWORK,
    RAW_PREFLIGHT, RAW_DECODE, RAW_POSTFLIGHT, RAW_REQUEST, MEDIAN_TIME, HEADER_METADATA, HEADER_PREDECESSOR,
    VERIFIED_HEADER, BLOCK_TRANSACTIONS, BLOCK_SIGNET, VERIFIED_BLOCK, RECOVERY_DEADLINE, SIGNET_MERKLE, PARENT_SIGNET, WARM_PARENT, RPC_REPLY, AUTH_RETRY, RPC_TIMEOUT, COOKIE_CACHE, CREDENTIAL_SOURCE, CREDENTIAL_LOAD, CHECKPOINT_IDENTITY, HEADER_MTP,
    PROPOSAL_CONSISTENCY, OTHER_SLOT_PREFLIGHT, PRIOR_M4_PREFLIGHT, COINBASE_PREFLIGHT, M8_ACCEPTANCE, COINBASE_MESSAGES, PROPOSAL_ACK,
    PROPOSAL_INSERT, WITHDRAWAL_PROPOSAL, M4_UPVOTE, M4_ALARM, M4_LEADER, M4_EXPLICIT, M4_REPEAT,
    EXPIRE_PROPOSALS, EXPIRE_WITHDRAWALS, CTIP_OWNERS, CTIP_SPENDS, CTIP_OUTPUTS, CTIP_REPLACEMENTS, CTIP_CHANGES, M5_DEPOSIT, M6_WITHDRAWAL,
    PRUNE_SLOTS, BLOCK_PUBLISH, M6_ID, M4_MODE, ACTIVE_SLOTS, EACH, MESSAGE_DISPATCH, M8_PARSE,
    CONFIRMED_DEPOSIT, DEPOSIT_PREFLIGHT, WITHDRAWAL_LOOKUP, EXECUTION_ANCHOR, MEMPOOL_CONTEXT,
    BLOCK_PARENT_CONTEXT, EXTEND_PARENT_CONTEXT, BMM_BLOCK_PREFLIGHT, BMM_CONTEXT_RESULT,
    ANCHOR_RECONCILE, SNAPSHOT_MATCH, SNAPSHOT_ADD, SNAPSHOT_CONTAINS,
    SNAPSHOT_EPOCH_FENCE, SNAPSHOT_TIP_FENCE, SNAPSHOT_WARM_ANCHOR, SNAPSHOT_WARM,
    ANCHOR_PREFLIGHT, SNAPSHOT_WARM_PREFLIGHT, VERIFIED_PARENT_CONTEXT, PARENT_PROBE_ERROR,
    PARENT_PROBE_METADATA, BMM_EDGE_RECHECK, BMM_CACHE_PREFLIGHT, BMM_CACHE_HIT, BMM_CACHE_KEY,
    BMM_UNTRUSTED_ADMISSION, BMM_PROBE_RESULT, BMM_PUBLICATION, BMM_SUCCESSOR, AUTHENTICATED_JSON,
    BMM_BID_PREFLIGHT, BMM_BID_TXID, BLOCK_ADMISSION, TRANSACTION_REPLAY, BLOCK_REPLAY, RESERVED_129, RESERVED_130, RESERVED_131, WITHDRAWAL_DESTINATION, WITHDRAWAL_BUNDLE, WITHDRAWAL_EVENT, WITHDRAWAL_SUBMISSION, WITHDRAWAL_OUTPUT, DEPOSIT_BROADCAST, DEPOSIT_SATOSHIS, DEPOSIT_SPONSORSHIP, DEPOSIT_IMPORT, DEPOSIT_NATIVE_IMPORT, DEFAULT_WALLET, WITHDRAWAL_PREFLIGHT, GRPC_CONFIG, GRPC_REQUEST, GRPC_EXECUTABLE, RPC_SERVER, CREDENTIAL, RESERVED_149, RESERVED_150, RESERVED_151, RESERVED_152, RESERVED_153, RESERVED_154, RESERVED_155
    , RESERVED_156, RESERVED_157, RESERVED_158, RESERVED_159, RESERVED_160, RESERVED_161, RESERVED_162, RESERVED_163, RESERVED_164, RESERVED_165, RESERVED_166, RESERVED_167, RESERVED_168, RESERVED_169, RESERVED_170, RESERVED_171, RESERVED_172, RESERVED_173, RESERVED_174, RESERVED_175, RESERVED_176, WITHDRAWAL_JOURNAL_READ, WITHDRAWAL_JOURNAL_WRITE, WITHDRAWAL_JOURNAL_CLEAR, WITHDRAWAL_RPC_BURN, WITHDRAWAL_RPC_CLAIM, WITHDRAWAL_RPC_VERIFY
    , RETIRED_BMM_GRPC_SUBMISSION, CHILD_MONITOR, CHILD_GRACE, CHILD_REAP, CHILD_DRAIN, RESERVED_188, RESERVED_189, RECOVERY_PEER, RECOVERY_BODY, RECOVERY_PRUNED, RECOVERY_REPLY, RECOVERY_HEADER, RECOVERY_PEER_REPLY, CREDENTIAL_FILE, GRPC_REQUEST_ADMISSION, WALLET_REFRESH, WALLET_SEND_PREFLIGHT, WALLET_SEND_RESULT, WALLET_ISSUE_PREFLIGHT, WALLET_ISSUE_RESULT, PEER_BLOCK
    , PEER_TIMER, PEER_HEADERS, PEER_DISPATCH, INDEX_DERIVED, INDEX_CONTINUITY, RESERVED_209
    , HEADER_AUTHENTICATION, PARENT_CONTEXT_ADMISSION, RESERVED_212, TEMPLATE_PARENT, TEMPLATE_ADMISSION, TEMPLATE_SELECTION, TEMPLATE_VERSION, RESERVED_217, FEE_FREE_SELECTION, CHILD_CHECKPOINT
    , CHECKPOINT_METADATA, CHECKPOINT_CLAIM, CHECKPOINT_COIN_KEY, CHECKPOINT_COIN_VALUE, RPC_BMM_AUTHENTICATION, RPC_BMM_SOURCE, RPC_BLOCK_PREPARATION, RPC_WITHDRAWAL_HISTORY, CHILD_PREFLIGHT, PERIODIC_REVERIFICATION, SYNC_PREFLIGHT, SYNC_LOOP, BID_PARENT, WALLET_COMMAND, BMM_MINED_PREFLIGHT, CONFIGURED_SLOT, BMM_CACHE_ROUTING, REQUIRED_PROPOSAL, REQUIRED_PAIR, CONFIGURED_BID, PARSED_BID, FUNDED_SUBMISSION, COMMITMENT_PROBE, SUCCESSOR_PROBE, TEMPLATE_CREATION, REWARD_WALLET
    , RESERVED_246, RESERVED_247, REQUIRED_QUAD, RESERVED_249, RESERVED_250, RESERVED_251, RESERVED_252, RESERVED_253, RESERVED_254, RESERVED_255, PARENT_REQUEST, BUNDLE_EVENT_CHECK, BUNDLE_EVENT_CLEAR, RESERVED_259, PARENT_REPORT, RESERVED_261, RESERVED_262
    , RESERVED_263, PEER_REQUEST, PEER_SYNC, RESERVED_266, FEE_FREE_DEPOSIT, NATIVE_DEPOSIT_ADMISSION, RESERVED_269, NATIVE_WITHDRAWAL_SUBMISSION, RESERVED_271, RESERVED_272, CREDENTIAL_RECORD, RESERVED_274, PEER_BLOCK_DISPATCH, RESERVED_276, MEMPOOL_WITNESS, PRELIMINARY_WITNESS, CANONICAL_MATCH, EXPLICIT_VOTE, PARENT_CONTEXT, BLOCK_DEPOSIT_PREFLIGHT
    , BRANCH_REPLAY, RECOVERY_ANCESTOR, RECOVERY_ADMISSION, EPHEMERAL_HEADER, CONNECTION_ANCHOR, CONNECTION_STATE, RESERVED_289, RESERVED_290, STARTUP_PARENT, RESERVED_292, RESERVED_293, REQUIRED_PAIR_ERRORS, RESERVED_295, CONNECTION_CONTEXT, SNAPSHOT_PREPARE, ANCHOR_CACHE, ANCHOR_PUBLISH, ANCHOR_DISCONNECT, CANDIDATE_ADMISSION, SNAPSHOT_BACKLOG, ANCHOR_REPLACEMENT, RECONCILIATION_GATE, ANCHOR_ORDER, ANCHOR_COLLECT
    , PRODUCTION_ROUTING, BLOCK_PREPARATION, BLOCK_ACCEPTANCE, MEMPOOL_SWEEP_PREFLIGHT, PARENT_RPC_HOST
    , FULL_BLOCK_PREFLIGHT, BLOCK_ANCHOR_ADMISSION, BLOCK_ANCHOR_PUBLICATION
    , STARTUP_PARENT_LOAD, STARTUP_PARENT_VERIFY, STARTUP_BUNDLE
    , CONTEXTUAL_HEADER, CONTEXTUAL_OUTPUTS, CANDIDATE_SELF_CHECK
    , BRANCH_CHOICE, STARTUP_RECONCILE, RESERVED_323
    , FINAL_BMM, BMM_FAILURE, RESERVED_326, BLOCK_REPLAY_COMPOSED, BLOCK_REPLAY_PRELUDE
    , RPC_CREDENTIALS_COMPOSED, RPC_TIMEOUT_COMPOSED
    , RPC_CALL, RPC_CALL_CHECKED
    , CACHE_INITIALIZE, RECOVERY_COMPOSED
};
uint32_t ParentReplayStore(ReplayStoreFlow kind, const std::function<int64_t(uint32_t)>& action);
// Condition, true branch, false branch; only the selected branch is evaluated.
bool ParentReplayChoose(const std::array<std::function<bool()>,3>& actions);
// Bind lazy facts; Haskell owns their order, short-circuiting and acceptance.
template <size_t N>
bool ParentReplayAll(const std::array<std::function<bool()>, N>& facts)
{
    static_assert(N >= 2 && N <= 4);
    constexpr ReplayStoreFlow flows[]{ReplayStoreFlow::REQUIRED_PAIR,
        ReplayStoreFlow::REQUIRED_PROPOSAL, ReplayStoreFlow::REQUIRED_QUAD};
    return ParentReplayStore(flows[N - 2], [&](uint32_t step) -> uint32_t {
        if (step == N + 1) return 0;
        if (step == 0 || step > N) throw std::logic_error("invalid required fact action");
        return facts[step - 1]();
    });
}
bool BmmReplacementBid(const std::string& message, int64_t current, int64_t maximum, int64_t& replacement);
int64_t BmmSelectedBid(int64_t configured, int64_t fees);
uint32_t PeerRejectionStrikes(bool complete, bool same_edge, uint32_t count);
uint32_t NextExtraNonce(bool same_parent, uint32_t current);
int32_t NextBlockHeight(bool present, int32_t height);
uint64_t NextBondContextHeight(int32_t height);
bool ApprovingParentHeight(int64_t parent, uint64_t& successor);
int BmmRewardAddress(const std::function<bool(uint32_t)>& read);
bool BmmWait(const std::function<int32_t(uint32_t)>& action);
bool BmmProduction(bool ecx, const std::function<bool(uint32_t)>& action);
bool BmmSyncTick(int64_t parent, int64_t child, const std::function<bool(uint32_t)>& action);
void BmmProofBuild(uint64_t previous, int64_t parent, const std::function<bool(uint32_t,uint64_t)>& action);
void ConstructDepositEvidence(int64_t sequence, int64_t height, uint32_t flags, int32_t slot, const NativeWorkflow& native);
void DepositVerify(uint64_t index, uint64_t inputs, uint64_t witnesses, const std::function<bool(uint32_t)>& action);
bool FeeAsset(const std::optional<std::string>& configured, bool canonical,
    std::span<const unsigned char,32> pegged, std::span<unsigned char,32> output, std::string* error);
// Callbacks run synchronously; false admission/action stops before advancement.
template <typename Condition, typename Action, typename Advance>
bool ParentReplayWhile(Condition&& condition, Action&& action, Advance&& advance)
{
    return ParentReplayStore(ReplayStoreFlow::EACH, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return bool(condition());
        case 2: return bool(action());
        case 3: advance(); return 1;
        default: throw std::logic_error("invalid replay traversal action");
        }
    });
}
// Like a short-circuiting range-for; the action must not invalidate its iterators.
template <typename Range, typename Action>
bool ParentReplayEach(Range&& range, Action&& action)
{
    auto entry = std::begin(range);
    const auto end = std::end(range);
    return ParentReplayWhile([&] { return entry != end; },
        [&] { return bool(action(*entry)); }, [&] { ++entry; });
}
using PegFields = int32_t (*)(void*, uint32_t, int64_t*);
bool LiveEvidence(LiveEvidencePhase phase, PegFields read, void* context,
    const std::string& parse_error, std::string& error);
bool DepositPreflight(uint32_t rule, int64_t amount, int64_t bound);
// 0: confirmed broadcast, 1: mempool broadcast, 2: fatal CTIP lookup failure.
bool DepositMessageMatches(uint32_t kind, const std::string& message);
bool TreasuryDelta(int64_t previous, int64_t current, int64_t claimed, int64_t maximum);
uint64_t CountMatches(uint64_t count, const std::function<bool(uint64_t)>& matches);
enum class MatchResult { UNIQUE, MISSING, DUPLICATE };
MatchResult FindUniqueMatch(uint64_t count, const std::function<bool(uint64_t)>& matches, uint64_t& index);
int DepositMatch(int64_t slot, int64_t amount, int64_t bound, bool has_address, const std::function<int64_t(uint32_t)>& fact);
enum class ReplayMaintenance : uint32_t { BEFORE_TREASURY, AFTER_TREASURY };
int M6Id(uint64_t outputs, uint64_t inputs, int64_t previous, int64_t maximum, bool has_slot,
    const std::function<int64_t(uint32_t,uint64_t)>& action);
using DestinationInspect = int32_t (*)(void*, uint32_t, uint32_t);
enum class DepositStatePhase : uint32_t {
    CHECK_CHECKPOINT, CHECK_PRIOR, CONNECT_PRIOR, DISCONNECT_PRESENT,
    DISCONNECT_CHECKPOINT, DISCONNECT_CURRENT, CHECK_CHECKPOINT_ANCHOR, CHECK_ANCHOR,
};
enum class DepositVerifyStep : uint32_t {
    CHECKPOINT = 1, CHECKPOINT_STATE, BUILD_CHECKPOINT, VERIFY_CHECKPOINT,
    HAS_WITNESS, LEGACY_WITNESS, REJECT_LEGACY, PARSE, PRIOR_STATE, VERIFY,
    ANCHOR_START, ANCHOR_CHECKPOINT, CHECKPOINT_ANCHOR, ANCHOR_HAS_WITNESS,
    ANCHOR_LEGACY_WITNESS, PARSE_ANCHOR, CHECK_ANCHOR, REJECT_ANCHOR,
    CONNECT_START, CONNECT_CHECKPOINT, CONNECT_BUILD, CONNECT_VERIFY, CONNECT_PUBLISH_CHECKPOINT,
    CONNECT_PARSE, CONNECT_PRIOR, CONNECT_PUBLISH_NEXT,
    DISCONNECT_START, DISCONNECT_PRESENT, DISCONNECT_CHECKPOINT, DISCONNECT_CHECK,
    DISCONNECT_REMOVE, DISCONNECT_PARSE, DISCONNECT_CURRENT, DISCONNECT_RESTORE,
    PARSE_START, INPUT_BOUNDS, WITNESS_BOUNDS, REJECT_INDEX, READ_EVIDENCE,
    DECODE_DEPOSIT, DECODE_PREVIOUS, DECODE_PROOF, REJECT_ENCODING, INCLUSION,
    SET_ANCHOR, FIND_PREVIOUS, READ_WITNESS, CTIP, DESTINATION, PUBLISH_PARSED,
    SCAN_START, SCAN_BOUNDS, SCAN_HASH, SCAN_OUTPUT_BOUNDS, SCAN_SCRIPT,
    SCAN_MATCH, SCAN_ADVANCE, SCAN_PRESENT, SCAN_VALUE, SCAN_EMPTY,
    AUTH_START, AUTH_NETWORK, AUTH_IDENTITY, AUTH_DEPOSIT, AUTH_CTIP, AUTH_PUBLISH,
    LOOKUP_START, LOOKUP_INPUT, LOOKUP_WITNESS, LOOKUP_MATCH, LOOKUP_PUBLISH,
    CLAIM_START, CLAIM_WITNESS, CLAIM_DESTINATION, CLAIM_VERIFY, CLAIM_PUBLISH,
    CTIP_READ_START, CTIP_READ_PRESENT, CTIP_READ_DECODE, CTIP_READ_ERROR_TARGET, CTIP_READ_ERROR, CTIP_READ_PUBLISH,
};
enum class DepositWorkflow : uint32_t { VERIFY = 0, ANCHOR = 11, CONNECT = 19, DISCONNECT = 27 };
uint32_t DepositStateFacts(bool present, bool matches, const std::string& decode_error);
bool RunDepositStateWorkflow(DepositWorkflow kind, const std::function<uint32_t(DepositVerifyStep)>& action,
    const std::string& decode_error, std::string& error);
bool RunDepositAuthentication(const std::function<bool(DepositVerifyStep)>& action);
bool RunCtipRead(const std::function<bool(DepositVerifyStep)>& action);
using TransactionHash = int32_t (*)(const unsigned char*, uint32_t, unsigned char*);
using EvidenceDecode = int32_t (*)(void*, int64_t*);
enum class DepositClaimWorkflow : uint32_t { CHECKPOINT, LEGACY, TRANSACTION };
bool RunDepositClaim(DepositClaimWorkflow kind, uint64_t inputs, uint64_t index, uint64_t witnesses,
    uint64_t outputs, std::span<const std::vector<unsigned char>> stack, const unsigned char* asset,
    const unsigned char* genesis, const unsigned char* prevout, TransactionHash hash_transaction,
    const NativeWorkflow& native, std::string& error);
bool ReadPersistedCtip(uint32_t facts, int64_t amount, const std::function<int32_t(uint32_t)>& read,
    EvidenceDecode decode, void* context, std::string& error);
using ParentHeaderCheck = int32_t (*)(void*, uint32_t);
bool ParseDeterministicDeposit(uint64_t inputs, uint64_t index, uint64_t witnesses,
    std::span<const std::vector<unsigned char>> stack, const unsigned char* asset,
    const unsigned char* genesis, const unsigned char* prevout, TransactionHash hash_transaction,
    EvidenceDecode decode, void* context, const NativeWorkflow& native, std::string& error);
// Callbacks are synchronous upstream codec adapters; no pointer may escape.
bool DepositEvidence(std::span<const std::vector<unsigned char>> stack, const unsigned char* prevout,
    TransactionHash hash_transaction, EvidenceDecode decode, void* context, std::string& error);
// 0 invalid, 1 historical v1, 2 native, 3 deterministic v2. Modes: 0 all,
// 1 historical/deterministic only, 2 native only. Value is unchanged on rejection.
int32_t DepositWitness(std::span<const std::vector<unsigned char>> stack, uint32_t mode,
    const unsigned char* asset, const unsigned char* genesis, const unsigned char* prevout,
    TransactionHash hash_transaction, int64_t& value);
enum class NativeRecipient : uint32_t { DECODE, ENCODE, CONSTRUCT };
bool RunNativeRecipient(NativeRecipient kind, int64_t amount, std::string_view source, const NativeWorkflow& native);
bool CheckNativeDeposit(const CTransaction& tx, uint64_t index, bool canonical,
    const unsigned char* asset, const unsigned char* genesis, TransactionHash hash_transaction,
    const NativeWorkflow& native, std::string& error);
// -1 means invalid script; 0..255 is the decoded slot.
int32_t TreasurySlot(uint32_t script, uint32_t opcode);
bool TreasuryMatches(std::span<const unsigned char> script, uint32_t opcode, int32_t expected);
// Positive payout, or -1 (burn), -2 (fee), -3 (burn <= fee).
enum class WithdrawalOp : uint32_t {
    BUILD_SCRIPT = 1, PARSE_SCRIPT, BUILD_REFERENCE, PARSE_REFERENCE, LEGACY_FRAME,
    DECODE_FEE, ENCODE_FEE, BUILD_OUTPUT, PARSE_OUTPUT, BUILD_M6, PARSE_M6, RESERVED_12, STATE_ANCHOR, WALLET_BUNDLE, WALLET_ANCHOR, STATE_MARKER, WALLET_TRANSPORT, RPC_FEE, EVENT_POLICY, BUNDLE_ADMISSION, NATIVE_AMOUNT, PARENT_DUST, NATIVE_GUARD, NATIVE_GUARD_RESULT, INPUTS_COMMITMENT, NATIVE_PAYOUT, NATIVE_BURN_PLAN, NATIVE_OUTPUT_SELECTION,
    JOURNAL_ADMISSION, PARENT_POLICY, RPC_ADMISSION, SUBMISSION_POLICY, PROOF_BOUNDS, JOURNAL_LEGACY, JOURNAL_IDENTITY,
};
std::vector<unsigned char> WithdrawalTransport(std::span<const unsigned char> transaction, bool strip_marker = false);
struct WithdrawalEventDecision { uint8_t rejection; bool clear; };
struct WithdrawalBundleAdmission { bool begin; bool clear; };
WithdrawalBundleAdmission AdmitWithdrawalBundle(bool busy, const unsigned char* current, const unsigned char* requested);
bool WithdrawalBytes(WithdrawalOp op, std::span<const unsigned char> input,
                     std::vector<unsigned char>& output, std::string* error);
} // namespace drivechain::haskell
#endif
