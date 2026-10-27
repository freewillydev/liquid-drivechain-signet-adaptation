// Copyright (c) 2017-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_check.h>

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <consensus/validation.h>

bool CheckTransaction(const CTransaction& tx, TxValidationState& state)
{
    // Basic checks that don't depend on any context
    if (tx.vin.empty())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vin-empty");
    if (tx.vout.empty())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-empty");
    // Size limits (this doesn't take the witness into account, as that hasn't been checked for malleability)
    if (::GetSerializeSize(TX_NO_WITNESS(tx)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-oversize");
    }

    // Check for negative or overflow output values (see CVE-2010-5139)
    CAmount nValueOutExplicit = 0;
    for (const auto& txout : tx.vout)
    {
        if (!txout.nValue.IsValid())
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-amount-invalid");
        if (!txout.nValue.IsExplicit())
            continue;
        if (txout.nValue.GetAmount() < 0)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-negative");
        if (txout.nValue.GetAmount() > MAX_MONEY)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-toolarge");
        nValueOutExplicit += txout.nValue.GetAmount();
        if (!MoneyRange(nValueOutExplicit))
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-txouttotal-toolarge");
    }

    // Check for duplicate inputs (see CVE-2018-17144)
    // While Consensus::CheckTxInputs does check if all inputs of a tx are available, and UpdateCoins marks all inputs
    // of a tx as spent, it does not check if the tx has duplicate inputs.
    // Failure to run this check will result in either a crash or an inflation bug, depending on the implementation of
    // the underlying coins database.
    std::set<COutPoint> vInOutPoints;
    for (const auto& txin : tx.vin) {
        if (!vInOutPoints.insert(txin.prevout).second)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-inputs-duplicate");
    }

    if (tx.IsCoinBase())
    {
        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-cb-length");

        for (unsigned int i = 0; i < tx.vout.size(); i++) {
            if (tx.vout[i].IsFee()) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-cb-fee");
            }
        }
    }
    else
    {
        for (const auto& txin : tx.vin)
            if (txin.prevout.IsNull())
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-prevout-null");
    }

    return true;
}

// Fork-specific drivechain_withdrawal adapters.
// Copyright (c) 2026 The Elements developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <drivechain_withdrawal.h>
#include <crypto/common.h>
#include <haskell/bridge.h>
#include <hash.h>
#include <primitives/txwitness.h>
#include <span.h>
#include <streams.h>

#include <algorithm>
#include <exception>
#include <limits>
#include <utility>

namespace drivechain {
namespace {

using Bytes = std::vector<unsigned char>;
using haskell::WithdrawalBytes;
using haskell::WithdrawalOp;

static_assert(NATIVE_WITHDRAWAL_MAX_DESTINATION_SIZE == 128);
static_assert(NATIVE_WITHDRAWAL_M6_REFERENCE_SIZE == 74);
static_assert(NATIVE_WITHDRAWAL_MAX_M6_LEGACY_SIZE == 251);
static_assert(Sidechain::Bitcoin::CTransaction::CURRENT_VERSION == 2);

Bytes Context(const uint256& genesis, uint8_t slot, const uint256& txid, uint32_t vout)
{
    Bytes input(69);
    std::copy(genesis.begin(), genesis.end(), input.begin());
    input[32] = slot;
    std::copy(txid.begin(), txid.end(), input.begin() + 33);
    WriteBE32(input.data() + 65, vout);
    return input;
}

void AppendAmount(Bytes& input, CAmount value)
{
    const auto offset = input.size();
    input.resize(offset + 8);
    WriteLE64(input.data() + offset, static_cast<uint64_t>(value));
}

void FillM6(NativeWithdrawalM6& m6, const Sidechain::Bitcoin::CMutableTransaction& tx,
            const NativeWithdrawalCommitment& reference, CAmount fee, CAmount burn, Bytes legacy)
{
    m6.blinded_transaction = tx;
    m6.burn_commitment = reference;
    m6.parent_fee = fee;
    m6.payout_amount = tx.vout[2].nValue;
    m6.burn_amount = burn;
    m6.destination = tx.vout[2].scriptPubKey;
    m6.legacy_serialization = std::move(legacy);
    m6.m6id = Hash(m6.legacy_serialization);
}

} // namespace

bool BuildNativeWithdrawalScript(const uint256& parent_genesis,
                                 const CScript& destination, CAmount parent_fee,
                                 CScript& script, std::string* error)
{
    script.clear();
    Bytes input(parent_genesis.begin(), parent_genesis.end()), result;
    AppendAmount(input, parent_fee);
    input.insert(input.end(), destination.begin(), destination.end());
    if (!WithdrawalBytes(WithdrawalOp::BUILD_SCRIPT, input, result, error)) return false;
    script.assign(result.begin(), result.end());
    return true;
}

bool ParseNativeWithdrawalScript(const CScript& script, const uint256& parent_genesis,
                                 CScript& destination, CAmount& parent_fee, std::string* error)
{
    destination.clear();
    parent_fee = 0;
    Bytes input(parent_genesis.begin(), parent_genesis.end()), result;
    input.insert(input.end(), script.begin(), script.end());
    if (!WithdrawalBytes(WithdrawalOp::PARSE_SCRIPT, input, result, error)) return false;
    parent_fee = static_cast<CAmount>(ReadLE64(result.data()));
    destination.assign(result.begin() + 8, result.end());
    return true;
}

bool BuildNativeWithdrawalOutput(const CAsset& pegged_asset, const uint256& parent_genesis,
                                 const CScript& destination, CAmount burn_amount,
                                 CAmount parent_fee, CTxOut& output, std::string* error)
{
    output.SetNull();
    Bytes input(pegged_asset.begin(), pegged_asset.end()), result;
    input.insert(input.end(), parent_genesis.begin(), parent_genesis.end());
    AppendAmount(input, burn_amount);
    AppendAmount(input, parent_fee);
    input.insert(input.end(), destination.begin(), destination.end());
    if (!WithdrawalBytes(WithdrawalOp::BUILD_OUTPUT, input, result, error)) return false;
    output = CTxOut(pegged_asset, burn_amount, CScript(result.begin(), result.end()));
    return true;
}

bool ParseNativeWithdrawalOutput(const CTxOut& output, const CTxOutWitness* witness,
                                 const CAsset& pegged_asset, const uint256& parent_genesis,
                                 NativeWithdrawal& withdrawal, std::string* error)
{
    withdrawal = {};
    const CAsset asset = output.nAsset.IsExplicit() ? output.nAsset.GetAsset() : CAsset{};
    const CAmount amount = output.nValue.IsExplicit() ? output.nValue.GetAmount() : 0;
    Bytes input(pegged_asset.begin(), pegged_asset.end()), result;
    input.insert(input.end(), asset.begin(), asset.end());
    for (bool flag : {output.nAsset.IsExplicit(), output.nValue.IsExplicit(),
                      output.nNonce.IsNull(), !witness || witness->IsNull()}) input.push_back(flag);
    AppendAmount(input, amount);
    input.insert(input.end(), parent_genesis.begin(), parent_genesis.end());
    input.insert(input.end(), output.scriptPubKey.begin(), output.scriptPubKey.end());
    if (!WithdrawalBytes(WithdrawalOp::PARSE_OUTPUT, input, result, error)) return false;
    withdrawal.parent_genesis = parent_genesis;
    withdrawal.burn_amount = amount;
    withdrawal.parent_fee = static_cast<CAmount>(ReadLE64(result.data()));
    withdrawal.payout_amount = static_cast<CAmount>(ReadLE64(result.data() + 8));
    withdrawal.destination.assign(result.begin() + 16, result.end());
    return true;
}

NativeWithdrawalCommitment ComputeNativeWithdrawalM6Commitment(
    const uint256& genesis, uint8_t slot, const uint256& txid, uint32_t vout)
{
    Bytes result;
    WithdrawalBytes(WithdrawalOp::BUILD_REFERENCE, Context(genesis, slot, txid, vout), result, nullptr);
    NativeWithdrawalCommitment commitment;
    std::copy(result.begin(), result.end(), commitment.begin());
    return commitment;
}

bool ParseNativeWithdrawalM6Commitment(const CScript& script, uint256& genesis,
                                      uint8_t& slot, uint256& txid, uint32_t& vout,
                                      std::string* error)
{
    genesis.SetNull();
    slot = 0;
    txid.SetNull();
    vout = std::numeric_limits<uint32_t>::max();
    Bytes result;
    if (!WithdrawalBytes(WithdrawalOp::PARSE_REFERENCE, script, result, error)) return false;
    std::copy_n(result.begin(), 32, genesis.begin());
    slot = result[32];
    std::copy_n(result.begin() + 33, 32, txid.begin());
    vout = ReadBE32(result.data() + 65);
    return true;
}

Bytes SerializeNativeWithdrawalM6Legacy(const Sidechain::Bitcoin::CMutableTransaction& tx)
{
    DataStream stream;
    stream << TX_NO_WITNESS(tx);
    const auto bytes = MakeUCharSpan(stream);
    return {bytes.begin(), bytes.end()};
}

bool DeserializeNativeWithdrawalM6Legacy(const Bytes& bytes,
                                         Sidechain::Bitcoin::CMutableTransaction& tx,
                                         std::string* error)
{
    tx = {};
    Bytes result;
    // Reject unbounded counts and lengths before upstream allocation.
    if (!WithdrawalBytes(WithdrawalOp::LEGACY_FRAME, bytes, result, error)) return false;
    try {
        DataStream stream{bytes};
        stream >> TX_NO_WITNESS(tx);
        if (stream.empty()) return true;
        if (error) *error = "blinded M6 legacy serialization has trailing bytes";
    } catch (const std::exception& exception) {
        if (error) *error = std::string{"invalid blinded M6 legacy serialization: "} + exception.what();
    }
    tx = {};
    return false;
}

uint256 ComputeNativeWithdrawalM6Id(const Sidechain::Bitcoin::CMutableTransaction& tx)
{
    return Hash(SerializeNativeWithdrawalM6Legacy(tx));
}

bool BuildNativeWithdrawalM6(const uint256& genesis, uint8_t slot, const uint256& txid,
                             uint32_t vout, const NativeWithdrawal& withdrawal,
                             NativeWithdrawalM6& m6, std::string* error)
{
    m6 = {};
    Bytes input = Context(genesis, slot, txid, vout), result;
    AppendAmount(input, withdrawal.burn_amount);
    AppendAmount(input, withdrawal.parent_fee);
    AppendAmount(input, withdrawal.payout_amount);
    input.insert(input.end(), withdrawal.destination.begin(), withdrawal.destination.end());
    if (!WithdrawalBytes(WithdrawalOp::BUILD_M6, input, result, error)) return false;
    Sidechain::Bitcoin::CMutableTransaction tx;
    if (!DeserializeNativeWithdrawalM6Legacy(result, tx, error)) return false;
    FillM6(m6, tx, ComputeNativeWithdrawalM6Commitment(genesis, slot, txid, vout),
        withdrawal.parent_fee, withdrawal.burn_amount, std::move(result));
    return true;
}

bool ParseNativeWithdrawalM6(const Sidechain::Bitcoin::CMutableTransaction& tx,
                             const uint256& genesis, uint8_t slot, const uint256& txid,
                             uint32_t vout, NativeWithdrawalM6& m6, std::string* error)
{
    m6 = {};
    Bytes input = Context(genesis, slot, txid, vout), result;
    Bytes legacy = SerializeNativeWithdrawalM6Legacy(tx);
    input.insert(input.end(), legacy.begin(), legacy.end());
    if (!WithdrawalBytes(WithdrawalOp::PARSE_M6, input, result, error)) return false;
    FillM6(m6, tx, ComputeNativeWithdrawalM6Commitment(genesis, slot, txid, vout),
           static_cast<CAmount>(ReadLE64(result.data())), static_cast<CAmount>(ReadLE64(result.data()+8)), std::move(legacy));
    return true;
}

} // namespace drivechain

// Fork-specific haskell/bridge adapters.
// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <haskell/bridge.h>
#include <consensus/amount.h>
#include <consensus/params.h>
#include <consensus/consensus.h>
#include <crypto/common.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <util/moneystr.h>

#include <haskell/domain_abi.h>

#include <array>
#include <algorithm>
#include <limits>
#include <memory>
#include <stdexcept>
#include <utility>
#include <exception>

extern "C" void elements_hs_runtime_init(void);

namespace {
bool ParameterGate(uint32_t mode, int64_t first, int64_t second)
{
    elements_hs_runtime_init();
    const int result = elements_hs_parameter_gate_v1(mode, first, second);
    if (result < 0 || result > 1) throw std::runtime_error("Haskell parameter gate failed");
    return result == 1;
}
}

bool Consensus::Params::DrivechainWithdrawalValidationEnabled() const
{
    return ParameterGate(1, drivechain_slot.has_value(), drivechain_m6_withdrawal_validation);
}

namespace drivechain::haskell {
void ScriptCacheEncode(bool endpoint_only, std::span<const std::byte> input, std::span<unsigned char> output)
{
    elements_hs_runtime_init();
    if (elements_hs_script_cache_encode_v1(endpoint_only,input.size(),
        reinterpret_cast<unsigned char*>(const_cast<std::byte*>(input.data())),output.size(),output.data()) != 0)
        throw std::runtime_error("Haskell script cache encoding failed");
}

namespace {
int CheckedStatus(int code, int maximum, const char* failure)
{
    if (code < 0 || code > maximum) throw std::runtime_error(failure);
    return code;
}
}

static int ReadExportRange(uint32_t mode, int32_t start, int32_t count, int32_t activation,
    int32_t tip, int32_t& end)
{
    elements_hs_runtime_init();
    return elements_hs_export_range_v1(mode,start,count,activation,tip,&end);
}

uint32_t PegEventRange(int32_t start, int32_t count, int32_t tip, int32_t& end)
{
    return CheckedStatus(ReadExportRange(2,start,count,0,tip,end),2,"Haskell peg-event range validation failed");
}

int32_t PegEventStart(int32_t tip)
{
    int32_t start{};
    CheckedStatus(ReadExportRange(3,0,0,0,tip,start),0,"Haskell peg-event start selection failed");
    return start;
}

bool ApprovingParentHeight(int64_t parent, uint64_t& successor)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_approving_parent_height_v1(parent);
    if (result == -1) return false;
    if (result < 1 || result > UINT32_MAX) throw std::runtime_error("Haskell approving parent height failed");
    successor = result;
    return true;
}

int64_t BoundedWait(int64_t value, int64_t maximum)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_bounded_wait_v1(value, maximum);
    if (result < 1 || result > maximum) throw std::runtime_error("Haskell wait interval bounds failed");
    return result;
}

uint64_t BoundedAppend(uint64_t limit, uint64_t used, int64_t count)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_bounded_append_v1(limit, used, count);
    if (result < 0 || result > count) throw std::runtime_error("Haskell output append bounds failed");
    return result;
}

bool FitsU32(std::span<const uint64_t> fields)
{
    elements_hs_runtime_init();
    return CheckedStatus(elements_hs_unsigned32_fields_v1(fields.size(), const_cast<uint64_t*>(fields.data())),
        1, "Haskell unsigned field bounds failed") != 0;
}

bool AnchorRule(std::span<const std::byte> encoded)
{
    elements_hs_runtime_init();
    if (encoded.size()!=145 && encoded.size()!=290 && encoded.size()!=294 && encoded.size()!=439)
        throw std::invalid_argument("Invalid anchor framing");
    const auto result = elements_hs_anchor_rule_v1(encoded.size(),
        reinterpret_cast<unsigned char*>(const_cast<std::byte*>(encoded.data())));
    return CheckedStatus(result,1,"Haskell anchor evaluation failed") == 1;
}

uint32_t PeerRejectionStrikes(bool complete, bool same_edge, uint32_t count)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_peer_strikes_v1(complete | (same_edge << 1), count);
    if (result < 0 || result > UINT32_MAX) throw std::runtime_error("Haskell peer strike evaluation failed");
    return result;
}

uint32_t NextExtraNonce(bool same_parent, uint32_t current)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_extra_nonce_v1(same_parent, current);
    if (result < 0 || result > UINT32_MAX) throw std::runtime_error("Haskell extra nonce evaluation failed");
    return result;
}

int32_t NextBlockHeight(bool present, int32_t height)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_next_block_height_v1(present, height);
    if (result < INT32_MIN || result > INT32_MAX) throw std::runtime_error("Haskell next block height evaluation failed");
    return result;
}

uint64_t NextBondContextHeight(int32_t height)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_next_block_height_v1(2, height);
    if (result < int64_t{INT32_MIN} + 1 || result > int64_t{INT32_MAX} + 1)
        throw std::runtime_error("Haskell bond context height evaluation failed");
    return static_cast<uint64_t>(result);
}

int64_t BmmSelectedBid(int64_t configured, int64_t fees)
{
    elements_hs_runtime_init();
    return elements_hs_bmm_selected_bid_v1(configured,fees,MAX_MONEY);
}

bool BmmWorkQuote(int64_t fees, uint64_t work, int64_t rate, int64_t reserve, std::array<int64_t,3>& fields)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_bmm_work_quote_v1(fees,work,rate,reserve,MAX_MONEY,fields.data());
    return CheckedStatus(result,1,"Haskell BMM work quote evaluation failed") == 1;
}

bool BmmWorkQuoteDisplay(int64_t fees, uint64_t work, int64_t rate, int64_t reserve, std::array<int64_t,3>& fields)
{
    elements_hs_runtime_init();
    return CheckedStatus(elements_hs_bmm_work_quote_display_v1(fees,work,rate,reserve,MAX_MONEY,fields.data()),
        1,"Haskell work quote display failed") == 1;
}

bool BmmMessageMatches(BmmMessageKind kind, const std::string& message)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_bmm_message_v1(static_cast<uint32_t>(kind), message.size(),
        reinterpret_cast<unsigned char*>(const_cast<char*>(message.data())));
    return CheckedStatus(result,1,kind == BmmMessageKind::DEFINITIVE_WAIT ?
        "Haskell BMM wait error classification failed" : "Haskell BMM duplicate request classification failed") == 1;
}

bool FeeAsset(const std::optional<std::string>& configured, bool canonical,
    std::span<const unsigned char,32> pegged, std::span<unsigned char,32> output, std::string* error)
{
    elements_hs_runtime_init();
    if (error) error->clear();
    const int code = elements_hs_fee_asset_v1(bool(configured) | (canonical << 1),configured ? configured->size() : 0,
        configured ? reinterpret_cast<unsigned char*>(const_cast<char*>(configured->data())) : nullptr,
        const_cast<unsigned char*>(pegged.data()),output.data());
    CheckedStatus(code,2,"Haskell fee asset resolution failed");
    if (code && error) *error = code == 1 ? "-feeasset must be exactly 64 hexadecimal characters" :
        "-feeasset must equal the immutable Elements pegged asset";
    return code == 0;
}

bool BmmReplacementBid(const std::string& message, int64_t current, int64_t maximum, int64_t& replacement)
{
    elements_hs_runtime_init();
    if (message.size() > UINT32_MAX) return false;
    const auto parser = +[](unsigned char* input, uint32_t size) -> int64_t {
        try { return ParseMoney(std::string(reinterpret_cast<const char*>(input),size)).value_or(-1); }
        catch (...) { return -1; }
    };
    const auto result = elements_hs_bmm_replacement_v1(current,maximum,MAX_MONEY,
        reinterpret_cast<unsigned char*>(const_cast<char*>(message.data())),message.size(),reinterpret_cast<HsFunPtr>(parser));
    if (result == -2) throw std::runtime_error("Haskell BMM replacement evaluation failed");
    if (result < 0) return false;
    replacement = result;
    return true;
}

namespace {
constexpr std::array<std::string_view,4> PAYMENT_URI_SCHEMES{"bitcoin","elements","liquidnetwork","liquidtestnet"};
int32_t PaymentUriPolicy(uint32_t flags, uint32_t scheme)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_payment_uri_v1(flags,scheme);
    return CheckedStatus(result,scheme == 4 ? 3 : 1,"Haskell payment URI policy failed");
}
}

bool AcceptPaymentUri(bool elements_mode, bool canonical, std::string_view scheme)
{
    const auto found = std::find(PAYMENT_URI_SCHEMES.begin(),PAYMENT_URI_SCHEMES.end(),scheme);
    const uint32_t code = found == PAYMENT_URI_SCHEMES.end() ? 5 : found - PAYMENT_URI_SCHEMES.begin();
    return PaymentUriPolicy(uint32_t(elements_mode) | (uint32_t(canonical) << 1),code) == 1;
}

std::string_view PaymentUriScheme(bool elements_mode, bool canonical, bool liquid_testnet)
{
    return PAYMENT_URI_SCHEMES.at(PaymentUriPolicy(uint32_t(elements_mode) |
        (uint32_t(canonical) << 1) | (uint32_t(liquid_testnet) << 2),4));
}

bool AcceptAddressAlias(bool parent, bool confidential, const std::string& network, const std::string& prefix)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_address_alias_v1(uint32_t(parent) | (uint32_t(confidential) << 1),
        network.size(), reinterpret_cast<unsigned char*>(const_cast<char*>(network.data())),
        prefix.size(), reinterpret_cast<unsigned char*>(const_cast<char*>(prefix.data())));
    return CheckedStatus(result,1,"Haskell address alias validation failed") == 1;
}

bool RejectWalletIssueAmount(double amount)
{
    elements_hs_runtime_init();
    return CheckedStatus(elements_hs_wallet_issue_amount_v1(&amount),1,"Haskell issuance amount evaluation failed") == 1;
}

uint32_t NetworkSelectionStatus(NetworkSelection kind, const std::string& text, bool elements_mode)
{
    if (static_cast<uint32_t>(kind) > 2) throw std::runtime_error("Haskell network selection evaluation failed");
    elements_hs_runtime_init();
    const auto code = elements_hs_network_selection_v1(static_cast<uint32_t>(kind), elements_mode, text.size(),
        reinterpret_cast<unsigned char*>(const_cast<char*>(text.data())));
    return CheckedStatus(code,5,"Haskell network selection evaluation failed");
}

void ValidateNetworkSelection(NetworkSelection kind, const std::string& text, bool elements_mode)
{
    const auto code = NetworkSelectionStatus(kind, text, elements_mode);
    static constexpr const char* errors[]{
        "This program only supports the canonical -chain=elements production network",
        "The pre-launch 'usdd' chain identity is unsupported; use -chain=elements",
        "-con_elementsmode is not supported with -chain=regtest; use -chain=elementsregtest for Elements/ECX testing",
        "the Simplicity deployment is not supported with -chain=regtest; use an Elements-mode chain",
        "the dynafed deployment is not supported with -chain=regtest; use an Elements-mode chain"};
    if (code) throw std::runtime_error(errors[code - 1]);
}

bool MainchainCookieAtRoot(const std::string& chain)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_network_selection_v1(3,0,chain.size(),
        reinterpret_cast<unsigned char*>(const_cast<char*>(chain.data())));
    return CheckedStatus(result,1,"Haskell mainchain cookie selection failed") == 1;
}

CtvAction CtvAdmission(uint32_t flags, uint64_t size)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_ctv_admission_v1(flags, size);
    return static_cast<CtvAction>(CheckedStatus(result,3,"Haskell CTV admission failed"));
}

std::vector<unsigned char> ParseConfigurationField(ConfigurationField kind, const std::string& text,
    const std::string& syntax_error, const std::string& value_error)
{
    elements_hs_runtime_init();
    const bool variable = kind==ConfigurationField::SPENDABLE_SCRIPT || kind==ConfigurationField::CONFIGURATION_HEX;
    const bool proposal = kind==ConfigurationField::PROPOSAL_DESCRIPTION;
    const size_t capacity = proposal ? std::min<size_t>(text.size(),65526)+10 : variable
        ? std::max<size_t>(1,std::min<size_t>(kind==ConfigurationField::SPENDABLE_SCRIPT ? 10000 : 65536,text.size()/2))
        : kind==ConfigurationField::CUSTODIAN_REGISTRY ? 325 : kind==ConfigurationField::OUTPOINT ? 36 : 32;
    std::vector<unsigned char> output(capacity);
    const auto result=elements_hs_configuration_field_v1(static_cast<uint32_t>(kind),text.size(),
        reinterpret_cast<unsigned char*>(const_cast<char*>(text.data())),output.size(),output.data());
    if (result==-2) throw std::runtime_error(syntax_error);
    if (result==-3) throw std::runtime_error(value_error);
    if (result<=0 || static_cast<size_t>(result)>output.size() ||
        (!variable && static_cast<size_t>(result)!=capacity))
        throw std::runtime_error("Haskell configuration parser failed");
    output.resize(result);
    return output;
}

GrpcTextAdmission AdmitGrpcText(const std::string& address, const std::string& authority)
{
    elements_hs_runtime_init();
    const auto mask=elements_hs_grpc_text_v1(address.size(),
        reinterpret_cast<unsigned char*>(const_cast<char*>(address.data())),authority.size(),
        reinterpret_cast<unsigned char*>(const_cast<char*>(authority.data())));
    CheckedStatus(mask,7,"invalid Haskell gRPC text admission");
    return {bool(mask&1),bool(mask&2),bool(mask&4)};
}

std::vector<std::string> GrpcPlan(std::span<const std::string> fields)
{
    if (fields.size()!=1 && fields.size()!=2) throw std::invalid_argument("invalid gRPC planner field count");
    std::array<unsigned char*,8> pointers{};
    std::array<uint32_t,8> lengths{};
    uint64_t capacity{256};
    for (size_t i=0; i<fields.size(); ++i) {
        if (capacity>INT32_MAX-4 || fields[i].size()>INT32_MAX-capacity-4) throw std::length_error("gRPC planner input too large");
        capacity+=fields[i].size()+4;
        pointers[i]=reinterpret_cast<unsigned char*>(const_cast<char*>(fields[i].data()));
        lengths[i]=fields[i].size();
    }
    std::vector<unsigned char> reply(capacity);
    elements_hs_runtime_init();
    const auto size=elements_hs_grpc_plan_v1(fields.size(),pointers.data(),lengths.data(),reply.data(),reply.size());
    if (size<1 || size>static_cast<int64_t>(reply.size()) || reply[0]>1)
        throw std::runtime_error("invalid gRPC planner reply");
    if (reply[0]) throw std::invalid_argument(std::string(reply.begin()+1,reply.begin()+size));
    std::vector<std::string> args;
    for (size_t offset=1; offset<static_cast<size_t>(size);) {
        if (size-offset<4) throw std::runtime_error("truncated gRPC planner length");
        const auto length=ReadLE32(reply.data()+offset);
        offset+=4;
        if (length>size-offset) throw std::runtime_error("truncated gRPC planner argument");
        args.emplace_back(reinterpret_cast<const char*>(reply.data()+offset),length);
        offset+=length;
    }
    if ((fields.size()<8 && !args.empty()) || (fields.size()==8 && args.size()!=(fields[6].empty() ? 11U : 13U)))
        throw std::runtime_error("invalid gRPC planner argument count");
    return args;
}

namespace {
template <typename Result, Result fallback = 0, typename Plan, typename Value, typename... Args>
auto ReadAdmission(const Plan& plan, const std::function<Value(Args...)>& read)
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
auto ReadBoundAdmission(const Binding& binding, const std::function<Value(Args...)>& read, Params... params)
{
    return ReadAdmission<Result,fallback>([&](HsFunPtr callback, void* context) {
        return binding(params...,callback,context);
    },read);
}

template <typename Binding, typename... Args, typename... Params>
void RequireAdmission(const Binding& binding, const std::function<bool(Args...)>& action,
    const char* rejected, const char* failure, Params... params)
{
    const int code = ReadBoundAdmission<int32_t,-1>(binding,action,params...);
    if (code == 1) throw std::runtime_error(rejected);
    if (code != 0) throw std::runtime_error(failure);
}
using NativeDigestEffect = std::function<int32_t(uint32_t, uint64_t, unsigned char*, unsigned char*)>;

bool WorkflowResult(int code, std::span<const char* const> errors, std::string& error, const char* failure)
{
    if (code < 0 || static_cast<size_t>(code) > errors.size()) throw std::runtime_error(failure);
    if (code && errors[code-1]) error = errors[code-1];
    return code == 0;
}

template <typename Binding, typename... Params>
int ReadWorkflow(const Binding& binding, const NativeWorkflow& native, Params... params)
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
}

bool ProductionIdentity(const std::function<bool(uint32_t)>& read, std::string* error)
{
    const int code = CheckedStatus(ReadAdmission<int32_t>(elements_hs_production_identity_v1, read),
        32, "Haskell production identity validation failed");
    static constexpr const char* fields[]{
        "network id",
        "data directory",
        "RPC port",
        "parent RPC port",
        "onion target port",
        "P2P port",
        "P2P message-magic derivation",
        "local enforcer-rule derivation",
        "P2P message magic",
        "P2PKH prefix",
        "P2SH prefix",
        "WIF prefix",
        "extended public key prefix",
        "extended secret key prefix",
        "blinded address prefix",
        "parent P2PKH prefix",
        "parent P2SH prefix",
        "bech32/blech32 namespaces",
        "Elements/parent/slot mode",
        "runtime Elements/header/signed-block codecs",
        "parent-chain identity",
        "signed-block/genesis mode",
        "child genesis/asset identity",
        "peer seeds/genesis checkpoint",
        "Elements M1 proposal identity",
        "historical parent proposal milestones",
        "parent replay checkpoint assertions",
        "parent replay identity",
        "reserved identity field",
        "reserved identity field",
        "Taproot/Simplicity activation",
        "issuance/policy identity",
    };
    if (code && error) *error = std::string("Elements production identity mismatch: ") + fields[code-1];
    return code == 0;
}

bool ReadAuthFile(AuthFileMode mode, const NativeWorkflow& native)
{
    return CheckedStatus(ReadWorkflow(elements_hs_auth_file_v1,native,static_cast<uint32_t>(mode)),
        1,"Haskell credential file workflow failed")==1;
}

uint32_t RunReplayStore(ReplayStoreWorkflow mode, const NativeWorkflow& native)
{
    return CheckedStatus(ReadWorkflow(elements_hs_replay_store_v1,native,static_cast<uint32_t>(mode),uint64_t{MAX_MONEY}),
        mode == ReplayStoreWorkflow::LOAD || mode == ReplayStoreWorkflow::LOAD_SESSION ||
            mode == ReplayStoreWorkflow::BMM_CONTEXT ? 3 :
            (mode >= ReplayStoreWorkflow::DEPOSIT && mode <= ReplayStoreWorkflow::OCCURRENCE) ||
                (mode >= ReplayStoreWorkflow::DEPOSIT_ADMISSION && mode <= ReplayStoreWorkflow::DEPOSIT_SESSION) ? 2 : 1,
        "Haskell replay store workflow failed");
}

bool RunBitcoinSignature(BitcoinSignatureWorkflow kind, int32_t hash_type, bool witness,
    uint32_t index, uint64_t inputs, uint64_t outputs, std::span<const unsigned char> signature,
    const NativeWorkflow& native)
{
    const int result = ReadWorkflow(elements_hs_bmm_signature_workflow_v1,native,
        static_cast<uint32_t>(kind),hash_type,uint32_t(witness),index,inputs,outputs,
        uint64_t(signature.size()),const_cast<unsigned char*>(signature.data()));
    return CheckedStatus(result,1,"Haskell Bitcoin signature workflow failed") == 1;
}

bool RunParentHeader(ParentHeaderWorkflow kind, uint32_t height,
    const std::function<uint64_t(uint32_t, uint64_t)>& native)
{
    return RunParentHeader(kind, height,
        [&](uint32_t step, uint64_t index, std::span<const unsigned char> input) {
            if (!input.empty()) throw std::logic_error("invalid parent header workflow input");
            std::vector<unsigned char> bytes(8);
            WriteLE64(bytes.data(), native(step,index));
            return bytes;
        });
}

bool RunParentHeader(ParentHeaderWorkflow kind, uint32_t height, const NativeWorkflow& native)
{
    const auto result = ReadWorkflow(elements_hs_parent_header_v1, native, static_cast<uint32_t>(kind), height);
    return CheckedStatus(result,1,"Haskell parent header workflow failed") == 1;
}

bool MeasureWork(bool saturate, uint64_t count, const std::function<const CTransaction&(uint64_t)>& transaction,
    uint64_t& total, uint64_t* last)
{
    const NativeWorkflow native = [&](uint32_t step, uint64_t index, std::span<const unsigned char> input) {
        std::vector<unsigned char> bytes;
        if (step == 0) {
            const auto& witnesses = transaction(index).witness.vtxinwit;
            for (const auto& witness : witnesses) {
                const auto& stack = witness.scriptWitness.stack;
                const auto tag = [&](size_t back) -> uint64_t {
                    return stack.size() < back || stack[stack.size()-back].empty() ? 256 : stack[stack.size()-back][0];
                };
                const std::array<uint64_t,5> fields{stack.size(), tag(1), tag(2),
                    stack.size() < 2 ? 0 : stack[stack.size()-2].size(),
                    stack.size() < 3 ? 0 : stack[stack.size()-3].size()};
                const auto offset = bytes.size();
                bytes.resize(offset+40);
                for (size_t i = 0; i < fields.size(); ++i) WriteLE64(bytes.data()+offset+8*i, fields[i]);
            }
        } else if (step == 1 && input.size() == 8) {
            const auto& stack = transaction(ReadLE64(input.data())).witness.vtxinwit.at(index).scriptWitness.stack;
            bytes.resize(8);
            WriteLE64(bytes.data(), ::GetSerializeSize(stack));
        } else throw std::logic_error("invalid work measurement action");
        return bytes;
    };
    std::array<uint64_t,2> fields{};
    const auto code = CheckedStatus(ReadWorkflow(elements_hs_bmm_work_measurement_v1, native,
        uint32_t(saturate), count, total, fields.data()), 1, "Haskell work measurement failed");
    total = fields[0];
    if (last) *last = fields[1];
    return code == 0;
}

std::optional<std::array<unsigned char,80>> AnchorCheckpoint(std::span<const std::byte> encoded)
{
    if (encoded.size()!=145) throw std::invalid_argument("Invalid checkpoint anchor framing");
    elements_hs_runtime_init();
    std::array<unsigned char,80> output{};
    const auto code=elements_hs_anchor_checkpoint_v1(encoded.size(),
        reinterpret_cast<unsigned char*>(const_cast<std::byte*>(encoded.data())),output.data());
    return CheckedStatus(code,1,"Haskell anchor checkpoint failed")==0 ? std::make_optional(output) : std::nullopt;
}

int BmmRewardAddress(const std::function<bool(uint32_t)>& read)
{
    const int code = ReadAdmission<int32_t,-1>(elements_hs_bmm_reward_address_v1,read);
    return CheckedStatus(code,5,"Haskell BMM reward admission failed");
}

bool BmmWait(const std::function<int32_t(uint32_t)>& action)
{
    const int code = ReadAdmission<int32_t,-1>(elements_hs_bmm_wait_v1,action);
    return CheckedStatus(code,1,"Haskell BMM wait failed") == 1;
}

bool BmmProduction(bool ecx, const std::function<bool(uint32_t)>& action)
{
    const int code = ReadAdmission<int32_t,-1>([&](HsFunPtr callback,void* context) {
        return ecx ? elements_hs_bmm_ecx_production_v1(callback,context) : elements_hs_bmm_native_production_v1(callback,context);
    },action);
    return CheckedStatus(code,ecx ? 14 : 10,ecx ?
        "Haskell ECX BMM production failed" : "Haskell native BMM production failed") == 0;
}

bool BmmSyncTick(int64_t parent, int64_t child, const std::function<bool(uint32_t)>& action)
{
    const int code = ReadBoundAdmission<int32_t,-1>(elements_hs_bmm_sync_heights_v1,action,parent,child);
    return CheckedStatus(code,5,"Haskell BMM sync tick failed") == 0;
}

void BmmProofBuild(uint64_t previous, int64_t parent, const std::function<bool(uint32_t,uint64_t)>& action)
{
    RequireAdmission(elements_hs_bmm_proof_build_v1,action,
        "BMM successor is outside the bounded parent-header window","Haskell BMM proof build failed",previous,parent);
}

MatchResult FindUniqueMatch(uint64_t count, const std::function<bool(uint64_t)>& matches, uint64_t& index)
{
    uint64_t selected{0};
    const std::function<int32_t(uint32_t,uint64_t)> action = [&](uint32_t stage, uint64_t candidate) {
        if (stage == 1) return int32_t{matches(candidate)};
        if (stage == 2) selected = candidate;
        return int32_t{1};
    };
    const auto result = ReadBoundAdmission<int32_t,-1>(elements_hs_deposit_ctip_search_v1,action,count);
    CheckedStatus(result,2,"Haskell unique match scan failed");
    if (result == 0) index = selected;
    return static_cast<MatchResult>(result);
}

void ConstructDepositEvidence(int64_t sequence, int64_t height, uint32_t flags, int32_t slot, const NativeWorkflow& native)
{
    static constexpr const char* errors[]{
        "authenticated deposit cannot form a v2 CTIP transition",
        "L1 deposit transaction does not contain the authenticated outpoint",
        "deposit transaction's prior CTIP transaction is unavailable",
        "deposit transaction spends multiple slot CTIP outputs",
        "deposit confirmation is outside the bounded v2 L1 header window",
        "serialized L1 header contains trailing data"};
    const int code = CheckedStatus(ReadWorkflow(elements_hs_deposit_construction_v1,native,
        sequence,height,flags,slot),std::size(errors),"Haskell deposit reconstruction failed");
    if (code) throw std::runtime_error(errors[code-1]);
}

void DepositVerify(uint64_t index, uint64_t inputs, uint64_t witnesses, const std::function<bool(uint32_t)>& action)
{
    RequireAdmission(elements_hs_deposit_verify_v1,action,
        "drivechain deposit input or witness index is out of range","Haskell live deposit verification failed",index,inputs,witnesses);
}

int64_t WalletBalanceTotal(int64_t trusted, int64_t pending, int64_t immature)
{
    elements_hs_runtime_init();
    return elements_hs_wallet_balance_v1(trusted, pending, immature);
}

std::vector<unsigned char> BmmFingerprint(const FingerprintReader& reader, uint32_t profile)
{
    elements_hs_runtime_init();
    struct Context {
        const FingerprintReader& reader;
        std::vector<unsigned char> bytes;
        std::exception_ptr failure;
    } context{reader, {}, {}};
    const auto read = +[](void* opaque, uint32_t group, uint32_t index, uint64_t* value, unsigned char** bytes) -> int32_t {
        auto& ctx = *static_cast<Context*>(opaque);
        try {
            const unsigned char* borrowed{nullptr};
            const bool ok = ctx.reader(group, index, *value, borrowed);
            *bytes = const_cast<unsigned char*>(borrowed);
            return ok;
        } catch (...) { ctx.failure = std::current_exception(); return 0; }
    };
    const auto write = +[](void* opaque, unsigned char* bytes, uint64_t size) -> int32_t {
        auto& ctx = *static_cast<Context*>(opaque);
        try {
            if (size > ctx.bytes.max_size()) throw std::length_error("BMM fingerprint too large");
            ctx.bytes.assign(bytes, bytes + size);
            return 1;
        } catch (...) { ctx.failure = std::current_exception(); return 0; }
    };
    const auto result = elements_hs_fingerprint_v2(profile, reinterpret_cast<HsFunPtr>(read), reinterpret_cast<HsFunPtr>(write), &context);
    if (context.failure) std::rethrow_exception(context.failure);
    if (result != 1) throw std::runtime_error("Haskell BMM fingerprint failed");
    return std::move(context.bytes);
}

namespace {
struct BorrowedStack {
    std::vector<uint32_t> sizes;
    std::vector<unsigned char*> fields;
    explicit BorrowedStack(std::span<const std::vector<unsigned char>> stack)
    {
        if (stack.size() > std::numeric_limits<uint32_t>::max()) throw std::length_error("Haskell deposit stack too large");
        for (const auto& item : stack) {
            if (item.size() > std::numeric_limits<uint32_t>::max()) throw std::length_error("Haskell deposit field too large");
            sizes.push_back(item.size());
            fields.push_back(const_cast<unsigned char*>(item.data()));
        }
    }
};

bool DepositProofResult(int32_t result, std::string& error)
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
    return WorkflowResult(result, errors, error, "Haskell deposit proof evaluation failed");
}
} // namespace

bool BmmState(bool hash, int64_t interval, uint32_t height, uint32_t time, uint32_t bits,
    uint32_t start, uint32_t start_time, uint64_t count, uint32_t latest, std::string& error)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_bmm_state_v1(hash, interval, height, time, bits, start, start_time, count, latest);
    if (result < 0 || result > 1) throw std::runtime_error("Haskell BMM state evaluation failed");
    if (result) error = "BMM parent-chain state is malformed";
    return result == 0;
}

int32_t BmmActivation(uint32_t phase, uint32_t facts, int64_t height, int64_t activation)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_bmm_activation_v1(phase, facts, height, activation);
    if (result == -2) throw std::runtime_error("-ecxprivatebmmcheckpoint requires an explicit -ecxprivatebmmactivationheight");
    if (result == -3) throw std::runtime_error("invalid -ecxprivatebmmactivationheight");
    if (result < 0 || result > 2) throw std::runtime_error("Haskell BMM activation evaluation failed");
    return result;
}

void RunBmmRetarget(uint32_t height, int64_t interval, int64_t target, uint32_t time, uint32_t start,
    const NativeWorkflow& native)
{
    const int result = ReadWorkflow(elements_hs_bmm_retarget_workflow_v1, native, height, interval, target, time, start);
    if (result == -2) throw std::runtime_error("Haskell BMM retarget evaluation failed");
    if (result == -3) throw std::runtime_error("Haskell BMM target scaling failed");
    if (result != 0) throw std::runtime_error("Haskell BMM state flow failed");
}

uint32_t BmmMedian(std::span<const uint32_t> times)
{
    elements_hs_runtime_init();
    if (times.size() > std::numeric_limits<uint32_t>::max()) throw std::length_error("BMM median history too large");
    const auto result = elements_hs_bmm_median_v1(times.size(), const_cast<uint32_t*>(times.data()));
    if (result < 0 || result > std::numeric_limits<uint32_t>::max()) throw std::runtime_error("Haskell BMM median evaluation failed");
    return result;
}

bool RunBmmStateFlow(BmmStateStep start, const std::function<int32_t(BmmStateStep)>& action)
{
    static_assert(static_cast<uint32_t>(BmmStateStep::SIGNATURE_MODE) == 114);
    const std::function<int32_t(uint32_t)> read = [&](uint32_t step) { return action(static_cast<BmmStateStep>(step)); };
    return CheckedStatus(ReadBoundAdmission<int64_t,INT64_MIN>(elements_hs_bmm_state_run_v1,read,
        static_cast<uint32_t>(start)),1,"Haskell BMM state flow failed") == 0;
}

void EventFields(EventLayoutKind kind, uint32_t status,
    const std::function<void(uint32_t, std::string_view, std::optional<std::string_view>)>& append)
{
    elements_hs_runtime_init();
    for (uint32_t index = 0;; ++index) {
        std::array<char, 32> key{}, value{};
        std::array<uint32_t, 2> sizes{};
        const auto result = elements_hs_event_layout_v1(static_cast<uint32_t>(kind), index, status,
            reinterpret_cast<unsigned char*>(key.data()), reinterpret_cast<unsigned char*>(value.data()), key.size(), sizes.data());
        if (result == 0) return;
        if ((result != 1 && result != 2 && result != 257 && result != 258) ||
            sizes[0] > key.size() || sizes[1] > value.size()) throw std::runtime_error("Haskell event layout evaluation failed");
        append(index, std::string_view(key.data(), sizes[0]), (result & 255) == 2 ?
            std::optional<std::string_view>{std::string_view(value.data(), sizes[1])} : std::nullopt);
        if (result & 256) return;
    }
}

std::string EventIdentity(EventIdentityKind kind, const std::string& hash, uint64_t number, uint32_t status)
{
    if (hash.size() > 64) throw std::length_error("Haskell event identity hash exceeds bounds");
    elements_hs_runtime_init();
    std::array<char, 128> output{};
    const auto size = elements_hs_event_identity_v1(static_cast<uint32_t>(kind),
        reinterpret_cast<unsigned char*>(const_cast<char*>(hash.data())), hash.size(), number, status,
        reinterpret_cast<unsigned char*>(output.data()), output.size());
    if (size < 0 || static_cast<size_t>(size) > output.size()) throw std::runtime_error("Haskell event identity evaluation failed");
    return {output.data(), static_cast<size_t>(size)};
}

static int64_t PegEventResult(int64_t result)
{
    constexpr std::array<const char*, 5> errors{{
        "withdrawal bundle event must contain exactly one lifecycle state",
        "withdrawal bundle lifecycle state must be an object",
        "deposit contains an invalid negative or zero numeric field",
        "normalized withdrawal event has an unknown lifecycle status",
        "withdrawal bundle has conflicting succeeded and failed events",
    }};
    if (result < -5 || result > 3) throw std::runtime_error("Haskell peg event evaluation failed");
    if (result < 0) throw std::runtime_error(errors[-result - 1]);
    return result;
}

int64_t PegEvent(PegEventKind kind, int64_t a, int64_t b, int64_t c)
{
    elements_hs_runtime_init();
    return PegEventResult(elements_hs_peg_event_v1(static_cast<uint32_t>(kind), a, b, c));
}

int64_t WithdrawalStatus(int64_t state, const std::string& status)
{
    if (status.size() > UINT32_MAX) throw std::runtime_error("withdrawal status exceeds FFI bounds");
    elements_hs_runtime_init();
    return PegEventResult(elements_hs_withdrawal_status_v1(state,
        reinterpret_cast<unsigned char*>(const_cast<char*>(status.data())), static_cast<uint32_t>(status.size())));
}

bool LiveEvidence(LiveEvidencePhase phase, PegFields read, void* context,
    const std::string& parse_error, std::string& error)
{
    elements_hs_runtime_init();
    const std::function<int32_t(uint32_t,int64_t*)> reader = [&](uint32_t step, int64_t* fields) {
        return read ? read(context, step, fields) : -2;
    };
    const int32_t result = ReadBoundAdmission<int32_t,-2>(elements_hs_live_evidence_v3,
        reader, static_cast<uint32_t>(phase));
    constexpr std::array<const char*, 37> errors{{
        "configured sidechain slot is out of range",
        "sidechain network does not match the configured identity",
        "mainchain genesis does not match the configured network",
        "mainchain blockchain info is missing",
        "mainchain network does not match the configured network",
        "mainchain signet challenge does not match the configured network",
        "mainchain is not fully synchronized",
        "enforcer network does not match the configured mainchain",
        "enforcer tip is not synchronized with the canonical mainchain tip",
        "mainchain deposit block header is missing",
        "mainchain deposit block is no longer confirmed",
        "mainchain deposit block height changed",
        "mainchain deposit block hash is missing or malformed",
        "mainchain deposit block hash changed",
        "current CTIP outpoint is not unspent on the canonical mainchain",
        "current CTIP outpoint is not confirmed",
        "current CTIP value does not match the enforcer",
        "CTIP state contains an invalid value or sequence",
        "CTIP sequence predates the confirmed deposit",
        "CTIP outpoint does not match the deposit at the same sequence",
        "sidechain entry must be an object",
        "enforcer returned duplicate sidechain slot",
        "expected sidechain slot is not active",
        "sidechain activation height is not active at the enforcer tip",
        "sidechain declaration identity does not match the configured slot",
        "GetTwoWayPegData block must be an object",
        "GetTwoWayPegData events must be an array",
        "GetTwoWayPegData event must be an object",
        "deposit event must be an object",
        "duplicate confirmed deposit event for outpoint",
        "confirmed deposit value does not match the sidechain claim",
        "deposit sequence number is negative",
        "confirmed deposit address is not valid for this sidechain network",
        "confirmed deposit outpoint is absent from canonical two-way-peg data",
        "deposit vout is out of range",
        "deposit address is empty",
        "deposit address contains non-printable bytes",
    }};
    if (result < -1 || result > static_cast<int32_t>(errors.size()) || (result == -1 && parse_error.empty()))
        throw std::runtime_error("Haskell live evidence evaluation failed");
    if (result) error = result == -1 ? parse_error : errors[result - 1];
    return result == 0;
}

static bool LegacyClaimResult(int32_t result, std::string& error)
{
    if (result < 0 || result > 2) throw std::runtime_error("Haskell legacy claim evaluation failed");
    if (result) error = result == 1 ? "historical drivechain checkpoint witness does not match its immutable value"
                                  : "historical drivechain checkpoint destination is invalid for this network";
    return result == 0;
}

uint64_t CountMatches(uint64_t count, const std::function<bool(uint64_t)>& matches)
{
    const std::function<bool(uint32_t,uint64_t)> read = [&](uint32_t, uint64_t index) { return matches(index); };
    const auto result = ReadBoundAdmission<int32_t,-1>(elements_hs_count_matches_v1,read,count);
    if (result < 0) throw std::runtime_error("Haskell match scan failed");
    return result;
}

int DepositMatch(int64_t slot, int64_t amount, int64_t bound, bool has_address, const std::function<int64_t(uint32_t)>& fact)
{
    return CheckedStatus(ReadBoundAdmission<int64_t,-1>(elements_hs_deposit_match_v1,fact,slot,amount,bound,has_address),
        9,"Haskell raw deposit match failed");
}

int M6Id(uint64_t outputs, uint64_t inputs, int64_t previous, int64_t maximum, bool has_slot,
    const std::function<int64_t(uint32_t,uint64_t)>& action)
{
    return CheckedStatus(ReadBoundAdmission<int64_t,-1>(elements_hs_m6_id_v1,action,outputs,inputs,previous,maximum,has_slot),
        6,"Haskell M6 id preparation failed");
}

bool TreasuryDelta(int64_t previous, int64_t current, int64_t claimed, int64_t maximum)
{
    elements_hs_runtime_init();
    return CheckedStatus(elements_hs_treasury_delta_v1(previous,current,claimed,maximum),1,
        "Haskell treasury delta failed") == 1;
}

bool DepositPreflight(uint32_t rule, int64_t amount, int64_t bound)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_deposit_preflight_v1(rule, amount, bound);
    if (result != 0 && result != 1) throw std::runtime_error("Invalid Haskell deposit preflight result");
    return result == 1;
}

bool DepositMessageMatches(uint32_t kind, const std::string& message)
{
    elements_hs_runtime_init();
    return CheckedStatus(elements_hs_deposit_broadcast_message_v1(kind, message.size(),
        reinterpret_cast<unsigned char*>(const_cast<char*>(message.data()))),1,
        "Invalid Haskell deposit message result") == 1;
}

static bool PredicateResult(int code, const char* invalid, const char* failed)
{
    if (code == -2) throw std::runtime_error(invalid);
    return CheckedStatus(code,1,failed) == 0;
}

static bool RunDepositFlow(uint32_t start, const std::function<bool(DepositVerifyStep)>& action)
{
    const std::function<bool(uint32_t)> read = [&](uint32_t step) { return action(static_cast<DepositVerifyStep>(step)); };
    return PredicateResult(ReadBoundAdmission<int64_t,-1>(elements_hs_deposit_run_v1,read,0,start),
        "Haskell deposit flow action invalid","Haskell deposit verification failed");
}

uint32_t ParentReplayStore(ReplayStoreFlow kind, const std::function<int64_t(uint32_t)>& action)
{
    return CheckedStatus(ReadBoundAdmission<int64_t,-1>(elements_hs_parent_replay_run_v1,
        action,static_cast<uint32_t>(kind)),3,"Haskell parent replay store evaluation failed");
}

bool ParentReplayChoose(const std::array<std::function<bool()>,3>& actions)
{
    return ParentReplayStore(ReplayStoreFlow::BRANCH_CHOICE, [&](uint32_t step) -> uint32_t {
        if (step < 1 || step > actions.size()) throw std::logic_error("invalid branch choice action");
        return actions[step-1]();
    });
}

static void RunPegFlow(uint32_t kind, const std::function<bool(uint32_t)>& action)
{
    if (!PredicateResult(ReadBoundAdmission<int64_t,-1>(elements_hs_deposit_run_v1,action,kind,0),
        "Haskell peg event action invalid","Haskell peg event flow failed"))
        throw std::runtime_error("Haskell peg event flow failed");
}

int BmmWorkBid(uint32_t hashes, int64_t height, int64_t fees, int64_t work, int64_t reserve,
    int64_t requested, const std::function<int64_t(uint32_t)>& rate, std::array<int64_t,4>& fields)
{
    std::array<int64_t,4> result{};
    const int code = CheckedStatus(ReadBoundAdmission<int64_t,-1>(elements_hs_bmm_work_bid_v1,
        rate,hashes,height,fees,work,reserve,requested,MAX_MONEY,result.data()),5,"Haskell BMM work bid failed");
    fields = result;
    return code;
}

void WithdrawalStatusFlow(const std::function<bool(uint32_t)>& action)
{
    RunPegFlow(1, action);
}

void L1NormalizationFlow(const std::function<bool(uint32_t)>& action)
{
    RunPegFlow(2, action);
}

void SidechainEventFlow(const std::function<bool(uint32_t)>& action)
{
    RunPegFlow(3, action);
}

void L1LocationFlow(const std::function<bool(uint32_t)>& action)
{
    RunPegFlow(4, action);
}

static int32_t RunPegRead(uint32_t mode, uint32_t kind, uint64_t limit, const std::function<uint64_t(uint32_t)>& read)
{
    const std::function<int32_t(uint32_t,uint64_t*)> action = [&](uint32_t step, uint64_t* fields) {
        fields[0] = read(step);
        return 1;
    };
    return ReadBoundAdmission<int32_t,-1>(elements_hs_peg_read_run_v1,action,mode,kind,limit);
}

bool PegSchema(PegSchemaKind kind, uint64_t limit, const std::function<uint64_t(uint32_t)>& read)
{
    return CheckedStatus(RunPegRead(0,static_cast<uint32_t>(kind),limit,read),1,"Haskell peg schema evaluation failed") == 0;
}

void ReadWhen(bool present, const std::function<void()>& read)
{
    PegSchema(PegSchemaKind::GUARDED, 0, [&](uint32_t step) -> uint64_t {
        if (step == 1) return present;
        read();
        return 1;
    });
}

static int64_t ReadReplayRecord(uint32_t kind, uint32_t flags, int64_t value, uint64_t first, uint64_t second)
{
    elements_hs_runtime_init();
    return elements_hs_parent_replay_record_v1(kind,flags,value,first,second);
}

uint32_t ParentReplaySchema(uint32_t rule, uint32_t unique_version, uint32_t reproposal_version)
{
    const auto version = ReadReplayRecord(0, rule, 0, unique_version, reproposal_version);
    if (version < 0) throw std::invalid_argument("unknown parent replay withdrawal history rule");
    return version;
}

bool ParentReplayRecord(ReplayRecordKind kind, uint32_t flags, int64_t value, uint64_t first, uint64_t second)
{
    const auto result = ReadReplayRecord(static_cast<uint32_t>(kind), flags, value, first, second);
    if (result < 0 || result > 1) throw std::runtime_error("Haskell parent replay record evaluation failed");
    return result == 1;
}

OutputTotalMode SelectOutputTotalMode(bool deferred, bool per_asset, bool explicit_asset)
{
    return static_cast<OutputTotalMode>(CheckedStatus(ReadReplayRecord(
        25, deferred | (per_asset << 1) | (explicit_asset << 2), 0, 0, 0), 3, "Haskell output total mode failed"));
}

DepositRouting SelectDepositRoute(uint64_t count, bool legacy_marker, bool native_marker, bool configured_slot)
{
    const auto plan = CheckedStatus(ReadReplayRecord(
        30, legacy_marker | (native_marker << 1) | (configured_slot << 2), 0, count, 0), 0xb04, "Haskell deposit routing failed");
    if ((plan & 255) > 4) throw std::runtime_error("Invalid Haskell deposit route");
    return {static_cast<DepositRoute>(plan & 255),static_cast<uint32_t>(plan >> 8)};
}

bool RejectParentResult(bool invalid, bool unavailable)
{
    return CheckedStatus(ReadReplayRecord(26, invalid | (unavailable << 1), 0, 0, 0),
        1, "Haskell parent result admission failed") == 1;
}

bool RunDepositAuthentication(const std::function<bool(DepositVerifyStep)>& action)
{
    return RunDepositFlow(61, action);
}

bool RunCtipRead(const std::function<bool(DepositVerifyStep)>& action)
{
    return RunDepositFlow(77, action);
}

static bool DepositStateResult(int32_t result, const std::string& decode_error, std::string& error)
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

uint32_t DepositStateFacts(bool present, bool matches, const std::string& decode_error)
{
    return uint32_t{present} | (uint32_t{!decode_error.empty()} << 1) | (uint32_t{matches} << 2);
}

bool RunDepositStateWorkflow(DepositWorkflow kind, const std::function<uint32_t(DepositVerifyStep)>& action,
    const std::string& decode_error, std::string& error)
{
    const std::function<int64_t(uint32_t)> read = [&](uint32_t step) -> int64_t {
        if (step >= 83 && step <= 93) {
            DepositStateResult(step-82, decode_error, error);
            return 1;
        }
        return action(static_cast<DepositVerifyStep>(step));
    };
    return PredicateResult(ReadBoundAdmission<int64_t,-1>(elements_hs_deposit_run_v1, read,
        uint32_t{5}, static_cast<uint32_t>(kind)), "Haskell deposit action invalid", "Haskell deposit state workflow failed");
}

bool ReadPersistedCtip(uint32_t facts, int64_t amount, const std::function<int32_t(uint32_t)>& read,
    EvidenceDecode decode, void* context, std::string& error)
{
    const auto result = ReadAdmission<int32_t,-1>([&](HsFunPtr callback, void* cursor) {
        return elements_hs_persisted_ctip_workflow_v1(facts,amount,callback,cursor,reinterpret_cast<HsFunPtr>(decode),context);
    },read);
    constexpr std::array<const char*,4> errors{{
        "persisted drivechain CTIP state has invalid asset or value encoding",
        "persisted drivechain CTIP state script is malformed",
        "persisted drivechain CTIP state payload is invalid",
        "persisted drivechain CTIP state payload cannot be decoded"}};
    return WorkflowResult(result,errors,error,"Haskell persisted CTIP workflow failed");
}

static bool DepositEvidenceResult(int32_t result, std::string& error)
{
    constexpr std::array<const char*, 6> errors{{
        "drivechain deposit witness does not contain deterministic v2 evidence",
        "drivechain deposit evidence field is empty or exceeds its consensus bound",
        "drivechain deposit transaction encoding or txid is invalid",
        "drivechain deposit sequence or header encoding is non-canonical",
        "drivechain deposit sequence transition is invalid",
        "drivechain deposit header chain length is invalid",
    }};
    return WorkflowResult(result, errors, error, "Haskell deposit evidence evaluation failed");
}

bool DepositEvidence(std::span<const std::vector<unsigned char>> stack, const unsigned char* prevout,
    TransactionHash hash_transaction, EvidenceDecode decode, void* context, std::string& error)
{
    elements_hs_runtime_init();
    BorrowedStack borrowed{stack};
    return DepositEvidenceResult(elements_hs_deposit_evidence_v1(MAX_BLOCK_SERIALIZED_SIZE, stack.size(),
        borrowed.sizes.data(), borrowed.fields.data(), const_cast<unsigned char*>(prevout),
        reinterpret_cast<HsFunPtr>(hash_transaction), reinterpret_cast<HsFunPtr>(decode), context),error);
}

bool ParseDeterministicDeposit(uint64_t inputs, uint64_t index, uint64_t witnesses,
    std::span<const std::vector<unsigned char>> stack, const unsigned char* asset,
    const unsigned char* genesis, const unsigned char* prevout, TransactionHash hash_transaction,
    EvidenceDecode decode, void* context, const NativeWorkflow& native, std::string& error)
{
    BorrowedStack borrowed{stack};
    const auto result = ReadWorkflow(elements_hs_deposit_parsing_v1,native,inputs,index,witnesses,
        MAX_MONEY,MAX_BLOCK_SERIALIZED_SIZE,static_cast<uint32_t>(stack.size()),
        borrowed.sizes.data(),borrowed.fields.data(),const_cast<unsigned char*>(asset),
        const_cast<unsigned char*>(genesis),const_cast<unsigned char*>(prevout),
        reinterpret_cast<HsFunPtr>(hash_transaction),reinterpret_cast<HsFunPtr>(decode),context);
    if (result == -2) return DepositEvidenceResult(-1,error);
    if (result == -3) return DepositProofResult(-1,error);
    if (result == -4) throw std::runtime_error("Haskell destination evaluation failed");
    if (result == -5) throw std::runtime_error("Haskell deposit witness evaluation failed");
    if (result > 0x100 && result <= 0x106) return DepositEvidenceResult(result-0x100,error);
    if (result > 0x200 && result <= 0x207) return DepositProofResult(result-0x200,error);
    if (result == 0x301 || result == 0x302) {
        error = result == 0x301 ? "deposit transaction does not commit a valid sidechain destination"
            : "deposit transaction contains multiple valid sidechain destinations";
        return false;
    }
    constexpr const char* errors[]{"drivechain deposit input index is out of range",
        "drivechain deposit evidence contains malformed transaction or merkle proof data"};
    return WorkflowResult(result,errors,error,"Haskell deposit parsing failed");
}

static bool AuthenticatedDepositResult(int32_t result, std::string& error)
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
    return WorkflowResult(result, errors, error, "Haskell authenticated deposit evaluation failed");
}

bool RunDepositClaim(DepositClaimWorkflow kind, uint64_t inputs, uint64_t index, uint64_t witnesses,
    uint64_t outputs, std::span<const std::vector<unsigned char>> stack, const unsigned char* asset,
    const unsigned char* genesis, const unsigned char* prevout, TransactionHash hash_transaction,
    const NativeWorkflow& native, std::string& error)
{
    BorrowedStack borrowed{stack};
    const auto result = ReadWorkflow(elements_hs_deposit_claim_v1,native,static_cast<uint32_t>(kind),
        inputs,index,witnesses,outputs,MAX_MONEY,MAX_BLOCK_SERIALIZED_SIZE,static_cast<uint32_t>(stack.size()),
        borrowed.sizes.data(),borrowed.fields.data(),const_cast<unsigned char*>(asset),
        const_cast<unsigned char*>(genesis),const_cast<unsigned char*>(prevout),reinterpret_cast<HsFunPtr>(hash_transaction));
    if (result == -5) throw std::runtime_error("Haskell deposit witness evaluation failed");
    switch (kind) {
    case DepositClaimWorkflow::CHECKPOINT:
        if (result < 0 || result > 1) throw std::runtime_error("Haskell checkpoint lookup failed");
        return result == 0;
    case DepositClaimWorkflow::LEGACY: return LegacyClaimResult(result,error);
    case DepositClaimWorkflow::TRANSACTION: return AuthenticatedDepositResult(result,error);
    default: throw std::logic_error("invalid deposit claim workflow");
    }
}

int32_t DepositWitness(std::span<const std::vector<unsigned char>> stack, uint32_t mode,
    const unsigned char* asset, const unsigned char* genesis, const unsigned char* prevout,
    TransactionHash hash_transaction, int64_t& value)
{
    elements_hs_runtime_init();
    BorrowedStack borrowed{stack};
    const auto result = elements_hs_deposit_witness_v1(MAX_MONEY, MAX_BLOCK_SERIALIZED_SIZE, mode,
        stack.size(), borrowed.sizes.data(), borrowed.fields.data(), const_cast<unsigned char*>(asset),
        const_cast<unsigned char*>(genesis), const_cast<unsigned char*>(prevout),
        reinterpret_cast<HsFunPtr>(hash_transaction), &value);
    if (result < 0 || result > 3) throw std::runtime_error("Haskell deposit witness evaluation failed");
    return result;
}

static bool DepositOutputsResult(int32_t result, std::string& error)
{
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
    return WorkflowResult(result, errors, error, "Haskell deposit output evaluation failed");
}

bool RunNativeRecipient(NativeRecipient kind, int64_t amount, std::string_view source, const NativeWorkflow& native)
{
    const auto result = ReadWorkflow(elements_hs_native_recipient_v1,native,static_cast<uint32_t>(kind),
        MAX_MONEY,amount,source.size(),reinterpret_cast<unsigned char*>(const_cast<char*>(source.data())));
    if (result < 0 || result > 3) throw std::runtime_error("Haskell native deposit recipient failed");
    if (kind == NativeRecipient::CONSTRUCT && result)
        throw std::invalid_argument("invalid native deposit destination or value");
    if (kind == NativeRecipient::ENCODE && result)
        throw std::invalid_argument(result == 2 ? "drivechain deposit destination exceeds 128 bytes"
            : "invalid drivechain deposit address or fee");
    return result == 0;
}

bool CheckNativeDeposit(const CTransaction& tx, uint64_t index, bool canonical,
    const unsigned char* asset, const unsigned char* genesis, TransactionHash hash_transaction,
    const NativeWorkflow& native, std::string& error)
{
    std::vector<uint64_t> offsets{0};
    std::vector<uint32_t> sizes;
    std::vector<unsigned char*> fields, prevouts;
    // Only pointer/length metadata crosses here; witness parsing stays lazy.
    for (size_t i = 0; i < std::min(tx.vin.size(),tx.witness.vtxinwit.size()); ++i) {
        BorrowedStack stack{tx.witness.vtxinwit[i].m_pegin_witness.stack};
        sizes.insert(sizes.end(),stack.sizes.begin(),stack.sizes.end());
        fields.insert(fields.end(),stack.fields.begin(),stack.fields.end());
        offsets.push_back(sizes.size());
        prevouts.push_back(const_cast<unsigned char*>(tx.vin[i].prevout.hash.ToUint256().begin()));
    }
    const auto result = ReadWorkflow(elements_hs_native_outputs_v1,native,uint32_t{canonical},
        tx.vin.size(),index,tx.witness.vtxinwit.size(),tx.vout.size(),MAX_MONEY,MAX_BLOCK_SERIALIZED_SIZE,
        offsets.data(),sizes.data(),fields.data(),prevouts.data(),const_cast<unsigned char*>(asset),
        const_cast<unsigned char*>(genesis),reinterpret_cast<HsFunPtr>(hash_transaction));
    if (result == -5) throw std::runtime_error("Haskell deposit witness evaluation failed");
    if (result > 0x100 && result <= 0x108) return DepositOutputsResult(result-0x100,error);
    if (result > 0x200 && result <= 0x208) return AuthenticatedDepositResult(result-0x200,error);
    if (canonical && result == 3) return false;
    constexpr const char* errors[]{"Drivechain deposit input or witness index is out of range.",
        "Committed Elements fee must be less than the authenticated deposit value."};
    return WorkflowResult(result,errors,error,"Haskell native deposit output workflow failed");
}

int32_t TreasurySlot(uint32_t script, uint32_t opcode)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_treasury_slot_v1(script, opcode);
    if (result < -1 || result > 255) throw std::runtime_error("Haskell treasury evaluation failed");
    return result;
}

bool TreasuryMatches(std::span<const unsigned char> script, uint32_t opcode, int32_t expected)
{
    elements_hs_runtime_init();
    return CheckedStatus(elements_hs_treasury_match_v1(expected,opcode,script.size(),
        const_cast<unsigned char*>(script.data())),1,"Haskell treasury matching failed") == 1;
}

bool WithdrawalBytes(WithdrawalOp op, std::span<const unsigned char> input,
                     std::vector<unsigned char>& output, std::string* error)
{
    elements_hs_runtime_init();
    output.clear();
    if (error) error->clear();
    if (op == WithdrawalOp::WALLET_TRANSPORT || op == WithdrawalOp::JOURNAL_LEGACY) {
        output = WithdrawalTransport(input, op == WithdrawalOp::JOURNAL_LEGACY);
        return true;
    }
    if (input.size() > std::numeric_limits<uint32_t>::max()) throw std::length_error("Haskell withdrawal input too large");
    std::array<unsigned char, 256> reply{};
    const auto size = elements_hs_withdrawal_bytes_v1(static_cast<uint32_t>(op), MAX_MONEY,
        const_cast<unsigned char*>(input.data()), input.size(), reply.data(), reply.size());
    if (size < 1 || size > static_cast<int32_t>(reply.size()) || reply[0] > 1)
        throw std::runtime_error("Haskell withdrawal byte evaluation failed");
    if (reply[0]) {
        if (error) error->assign(reply.begin() + 1, reply.begin() + size);
        return false;
    }
    constexpr std::array<std::pair<int, int>, 35> lengths{{
        {45, 173}, {9, 136}, {74, 74}, {69, 69}, {0, 0}, {8, 8}, {8, 8},
        {45, 173}, {17, 144}, {124, 251}, {16, 16}, {0, 60}, {134, 134}, {18, 18}, {134, 134}, {39, 39},
        {0, 0}, {8, 8}, {2, 2}, {2, 2}, {8, 8}, {8, 8}, {0, 0}, {4, 255}, {73, 73}, {12, 12}, {4, 185}, {8, 128}, {0, 0}, {9, 9}, {4, 255}, {1, 1}, {4, 255}, {0, 0}, {0, 0},
    }};
    const auto command = static_cast<uint32_t>(op) - 1;
    if (command >= lengths.size() || size - 1 < lengths[command].first || size - 1 > lengths[command].second)
        throw std::runtime_error("Haskell withdrawal reply has invalid length");
    output.assign(reply.begin() + 1, reply.begin() + size);
    return true;
}

std::vector<unsigned char> WithdrawalTransport(std::span<const unsigned char> transaction, bool strip_marker)
{
    elements_hs_runtime_init();
    if (transaction.size() > std::numeric_limits<int32_t>::max() - 3)
        throw std::length_error("Haskell withdrawal transport input too large");
    std::vector<unsigned char> reply(transaction.size() + 3);
    const auto size = elements_hs_withdrawal_bytes_v1(static_cast<uint32_t>(strip_marker ? WithdrawalOp::JOURNAL_LEGACY : WithdrawalOp::WALLET_TRANSPORT), MAX_MONEY,
        const_cast<unsigned char*>(transaction.data()), transaction.size(), reply.data(), reply.size());
    if (size < 1 || size != static_cast<int32_t>(reply.size()) - (strip_marker ? 4 : 0) || reply[0] != 0)
        throw std::runtime_error("Haskell withdrawal transport evaluation failed");
    reply.resize(size);
    reply.erase(reply.begin());
    return reply;
}

WithdrawalBundleAdmission AdmitWithdrawalBundle(bool busy, const unsigned char* current, const unsigned char* requested)
{
    std::array<unsigned char,65> input{};
    input[0] = busy;
    std::copy_n(current, 32, input.begin() + 1);
    std::copy_n(requested, 32, input.begin() + 33);
    std::vector<unsigned char> output;
    if (!WithdrawalBytes(WithdrawalOp::BUNDLE_ADMISSION, input, output, nullptr) ||
        output[0] > 1 || output[1] > 1) throw std::runtime_error("Haskell withdrawal bundle admission failed");
    return {output[0] != 0, output[1] != 0};
}
template <typename Binding, typename... Params>
static int ReadScalarAdmission(const Binding& binding,
    const std::function<uint64_t(uint32_t,uint64_t,uint64_t)>& read, Params... params)
{
    const std::function<int32_t(uint32_t,uint64_t,uint64_t,uint64_t*)> action =
        [&](uint32_t step, uint64_t a, uint64_t b, uint64_t* field) { *field=read(step,a,b); return 1; };
    return ReadBoundAdmission<int32_t,-1>(binding,action,params...);
}

bool StartupArgs(uint32_t slot, uint32_t timeout_maximum, const std::function<uint64_t(uint32_t)>& read)
{
    return CheckedStatus(ReadScalarAdmission(elements_hs_startup_args_v1,
        [&](uint32_t step, uint64_t, uint64_t) { return read(step); }, slot,
        uint64_t{MAX_MONEY}, uint64_t{timeout_maximum}), 1, "Haskell startup admission failed")==0;
}

std::array<uint32_t,2> BmmHeaderLayout(uint32_t version, uint32_t flags)
{
    elements_hs_runtime_init();
    std::array<uint32_t,2> layout{};
    constexpr uint32_t allowed_fields{0x143U}; // withdrawal, BMM, dynafed, critical hash
    if (elements_hs_bmm_header_layout_v1(version,flags,layout.size(),layout.data()) != 0 ||
        (layout[1] & ~allowed_fields) != 0)
        throw std::runtime_error("Haskell header layout failed");
    return layout;
}

void BmmFixedIdentity(std::span<uint32_t, 2> fields, std::span<unsigned char, 121> payload)
{
    elements_hs_runtime_init();
    if (elements_hs_bmm_identity_v1(fields.data(), payload.data()) != 0)
        throw std::runtime_error("Haskell BMM fixed identity failed");
}

void FeeFreeSelection(int64_t age, const std::function<uint64_t(uint32_t)>& read)
{
    if (ReadScalarAdmission(elements_hs_fee_free_selection_v1,
        [&](uint32_t step, uint64_t, uint64_t) { return read(step); }, age)!=1)
        throw std::runtime_error("Haskell fee-free selection failed");
}

bool DepositInputLimit(bool enabled, uint64_t count, uint64_t limit,
    const std::function<uint64_t(uint32_t,uint64_t,uint64_t)>& read)
{
    return CheckedStatus(ReadScalarAdmission(elements_hs_deposit_input_limit_v1,
        read,uint32_t{enabled},count,limit),1,"Haskell deposit input limit failed") == 1;
}

bool MerkleReplacement(uint32_t mode, uint32_t index, uint32_t position, uint32_t flags)
{
    elements_hs_runtime_init();
    const int result = elements_hs_merkle_replacement_v1(mode,index,position,flags);
    if (result < 0 || result > 1) throw std::runtime_error("Haskell Merkle replacement failed");
    return result == 1;
}

void BmmCheckpointPreset(uint32_t mode, std::span<uint32_t, 16> fields,
    std::span<unsigned char, 32> block_hash)
{
    elements_hs_runtime_init();
    if (elements_hs_bmm_checkpoint_v1(mode, fields.data(), block_hash.data()) != 0)
        throw std::runtime_error("Haskell BMM checkpoint failed");
}

int64_t BmmDifficultyInterval(int64_t timespan, int64_t spacing)
{
    elements_hs_runtime_init();
    int64_t interval{0};
    if (elements_hs_bmm_interval_v1(timespan, spacing, &interval) != 0)
        throw std::runtime_error("Haskell difficulty interval failed");
    return interval;
}

void BmmPrivateTemplate(uint32_t height, uint32_t time, uint32_t median, uint32_t slot,
    std::span<const unsigned char, 32> critical, std::span<uint32_t, 4> fields,
    std::span<unsigned char, 37> commitment)
{
    elements_hs_runtime_init();
    if (elements_hs_bmm_private_template_v1(height, time, median, slot,
            const_cast<unsigned char*>(critical.data()), fields.data(), commitment.data()) != 0)
        throw std::runtime_error("Haskell private BMM template failed");
}

uint32_t BmmConsensusPreset(uint32_t mode, std::span<uint64_t, 6> fields,
    std::span<unsigned char, 32> pow_limit, std::span<unsigned char, 22> challenge)
{
    elements_hs_runtime_init();
    const auto size = elements_hs_bmm_preset_v1(mode, fields.data(), pow_limit.data(), challenge.data());
    if (size < 0 || size > 22) throw std::runtime_error("Haskell BMM preset failed");
    return size;
}

bool AdmitTlsCredentialFile(bool private_key, const std::function<uint64_t(uint32_t)>& read)
{
    return CheckedStatus(ReadScalarAdmission(elements_hs_tls_file_admission_v1,
        [&](uint32_t step,uint64_t,uint64_t) { return read(step); },static_cast<uint32_t>(private_key)),
        1,"Haskell mTLS credential admission failed") == 1;
}

} // namespace drivechain::haskell
