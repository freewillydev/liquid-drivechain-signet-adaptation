// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <haskell/bridge.h>
#include <haskell/domain_abi.h>
#include <haskell/simplicity_ffi.h>
#include <crypto/common.h>

#include <atomic>
#include <algorithm>
#include <csignal>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <tuple>
#include <vector>

namespace hs = drivechain::haskell;

static void Require(bool ok)
{
    if (!ok) throw std::runtime_error("Haskell runtime/ABI test failed");
}

static void CheckOptionalEnvironment()
{
    for (uint32_t kind=0; kind<7; ++kind) {
        for (uint32_t present : {0U,1U,2U,255U,UINT32_MAX}) {
            for (uint32_t fields=0; fields<=256; ++fields) {
                bool expected=false;
                if (present<=1) switch (kind) {
                case 0: expected=fields==(present ? 1U : 0U); break;
                case 1: expected=fields==(present ? 7U : 0U); break;
                case 2: expected=fields==(present ? 255U : 0U); break;
                case 3: expected=present ? fields==5 || fields==7 : fields==0; break;
                case 4: expected=present ? fields==7 : fields==0 || fields==4; break;
                case 5: expected=present ? fields==13 || fields==15 : fields==0; break;
                }
                Require(elements_haskell_optional_environment(kind,present,fields)==expected);
            }
        }
    }
}

static void CheckWideArithmetic()
{
    // hi, lo, multiplier, divisor hi/lo, expected hi/lo, accepted.
    const uint64_t cases[][8] = {
        {0,0,0,0,1,0,0,1},
        {0,7,3,0,2,0,10,1},
        {1,0,1,0,2,0,UINT64_C(1) << 63,1},
        {UINT64_MAX,UINT64_MAX,UINT64_MAX,UINT64_MAX,UINT64_MAX,0,UINT64_MAX,1},
        {UINT64_MAX,UINT64_MAX,1,0,1,UINT64_MAX,UINT64_MAX,1},
        {UINT64_MAX,UINT64_MAX,2,0,1,0,0,0},
        {0,0,0,0,0,0,0,0},
    };
    for (const auto& row : cases) {
        uint64_t output[]{91,92,93,94};
        Require(elements_haskell_muldiv128(row[0],row[1],row[2],row[3],row[4],output+1,output+2) == bool(row[7]));
        Require(output[0] == 91 && output[3] == 94);
        Require(output[1] == (row[7] ? row[5] : 92));
        Require(output[2] == (row[7] ? row[6] : 93));
        Require(!elements_haskell_muldiv128(row[0],row[1],row[2],row[3],row[4],nullptr,output));
        Require(!elements_haskell_muldiv128(row[0],row[1],row[2],row[3],row[4],output,nullptr));
        Require(output[0] == 91);
    }
}

static void CheckCanonicalActivation()
{
    std::array<unsigned char,364> input{};
    input[3]=1;
    for (size_t i=0; i<10; ++i) input[4+32*i]=static_cast<unsigned char>(i+1);
    for (size_t offset=324; offset<364; offset+=8) input[offset+7]=1;
    Require(elements_haskell_canonical_activation(input.data(),input.size()));
    for (const auto& pair : {std::pair{4,36},std::pair{4,100},std::pair{36,100}}) {
        auto aliased=input;
        std::copy_n(input.data()+pair.first,32,aliased.data()+pair.second);
        Require(!elements_haskell_canonical_activation(aliased.data(),aliased.size()));
    }
    for (size_t offset=324; offset<364; offset+=8) {
        auto zero=input;
        zero[offset+7]=0;
        Require(!elements_haskell_canonical_activation(zero.data(),zero.size()));
    }
    Require(!elements_haskell_canonical_activation(nullptr,364));
    Require(!elements_haskell_canonical_activation(input.data(),363));
    Require(!elements_haskell_canonical_activation(input.data(),365));
}

static uint32_t verifier_version{1}, verifier_status{0};
static std::vector<int> verifier_calls;
extern "C" uint32_t TestRustVersion() { verifier_calls.push_back(1); return verifier_version; }
extern "C" uint32_t TestRustVerify(uint32_t abi, const unsigned char* annex, size_t size,
    const unsigned char* program, size_t program_size, const unsigned char* digest, size_t digest_size)
{
    verifier_calls.push_back(2);
    if (abi != 1 || size != 3 || annex[0] != 0x50 || program_size != 32 || digest_size != 32 ||
        program[0] != 17 || digest[0] != 29) return 2;
    return verifier_status;
}

extern "C" uint32_t TestRustIdentity(unsigned char* output, size_t size)
{
    verifier_calls.push_back(3);
    if (size != 32) return 2;
    std::fill_n(output, size, 7);
    return verifier_status;
}

static void CheckRustStartup()
{
    std::array<unsigned char,32> expected;
    expected.fill(7);
    for (bool active : {false,true}) {
        for (uint32_t version : {0U,1U,UINT32_MAX}) {
            for (uint32_t status : {0U,1U,4U,UINT32_MAX}) {
                verifier_version=version; verifier_status=status; verifier_calls.clear();
                std::string error="stale";
                Require(hs::VerifierIdentity(active,1,1,expected,TestRustVersion,TestRustVersion,
                    TestRustIdentity,&error)==(!active || (version==1 && status==0)));
                Require(verifier_calls==(active ? (version==1 ? std::vector<int>{1,1,3} :
                    std::vector<int>{1}) : std::vector<int>{}));
                Require(error.empty()==(!active || (version==1 && status==0)));
            }
        }
    }
    verifier_calls.clear();
    Require(!hs::VerifierIdentity(true,1,1,expected,nullptr,TestRustVersion,TestRustIdentity,nullptr));
    Require(!hs::VerifierIdentity(true,1,1,expected,TestRustVersion,nullptr,TestRustIdentity,nullptr));
    Require(!hs::VerifierIdentity(true,1,1,expected,TestRustVersion,TestRustVersion,nullptr,nullptr));
    expected.fill(0);
    Require(!hs::VerifierIdentity(true,1,1,expected,TestRustVersion,TestRustVersion,TestRustIdentity,nullptr));
    Require(verifier_calls.empty());
}

static void CheckRustVerifier()
{
    const std::array<unsigned char,3> annex{0x50,1,2};
    const std::array<unsigned char,32> program{17}, digest{29};
    for (uint32_t version : {0U,1U,2U}) {
        for (uint32_t status : {0U,1U,2U,3U,4U,UINT32_MAX}) {
            verifier_version = version; verifier_status = status; verifier_calls.clear();
            Require(hs::VerifyJournal(TestRustVersion,TestRustVerify,annex,program,digest) ==
                (version != 1 ? 2 : status == 0 ? 0 : 1));
            Require(verifier_calls == (version == 1 ? std::vector<int>{1,2} : std::vector<int>{1}));
        }
    }
    verifier_calls.clear();
    Require(hs::VerifyJournal(TestRustVersion,TestRustVerify,annex,{},digest) == 1);
    Require(hs::VerifyJournal(TestRustVersion,TestRustVerify,annex,program,{}) == 1);
    Require(hs::VerifyJournal(nullptr,TestRustVerify,annex,program,digest) == 2);
    Require(hs::VerifyJournal(TestRustVersion,nullptr,annex,program,digest) == 2);
    Require(verifier_calls.empty());
}

extern "C" bool TestRustGroth16(void* context, const unsigned char* proof, size_t size,
    const uint32_t* program, const unsigned char* digest)
{
    verifier_calls.push_back(3);
    return context == nullptr && size == 2 && proof[0] == 7 && program[7] == 43 && digest[31] == 99;
}

static void CheckRustGroth16()
{
    const std::array<unsigned char,2> proof{7,8};
    std::array<uint32_t,8> program{};
    std::array<unsigned char,32> digest{};
    program[7] = 43; digest[31] = 99;
    verifier_calls.clear();
    Require(hs::VerifyGroth16(TestRustGroth16,nullptr,proof.data(),proof.size(),program.data(),digest.data()));
    digest[31] = 0;
    Require(!hs::VerifyGroth16(TestRustGroth16,nullptr,proof.data(),proof.size(),program.data(),digest.data()));
    Require(verifier_calls == std::vector<int>({3,3}));
    verifier_calls.clear();
    Require(!hs::VerifyGroth16(TestRustGroth16,&digest,proof.data(),proof.size(),program.data(),digest.data()));
    Require(!hs::VerifyGroth16(nullptr,nullptr,proof.data(),proof.size(),program.data(),digest.data()));
    Require(!hs::VerifyGroth16(TestRustGroth16,nullptr,nullptr,proof.size(),program.data(),digest.data()));
    Require(!hs::VerifyGroth16(TestRustGroth16,nullptr,proof.data(),proof.size(),nullptr,digest.data()));
    Require(!hs::VerifyGroth16(TestRustGroth16,nullptr,proof.data(),proof.size(),program.data(),nullptr));
    Require(verifier_calls.empty());
}

extern "C" bool TestRustCustody(const unsigned char* bundle, size_t bundle_size,
    const unsigned char* registry, size_t registry_size, const unsigned char* receipts, size_t count)
{
    verifier_calls.push_back(4);
    return bundle_size == 2 && bundle[1] == 29 && registry_size == 3 && registry[2] == 53 &&
        count == 3 && receipts[413] == 99;
}

static void CheckRustCustody()
{
    const std::array<unsigned char,2> bundle{17,29};
    const std::array<unsigned char,3> registry{31,41,53};
    std::array<unsigned char,414> receipts{};
    receipts.back() = 99;
    verifier_calls.clear();
    Require(hs::VerifyCustody(TestRustCustody,bundle,registry,receipts,3));
    receipts.back() = 0;
    Require(!hs::VerifyCustody(TestRustCustody,bundle,registry,receipts,3));
    Require(verifier_calls == std::vector<int>({4,4}));
    verifier_calls.clear();
    Require(!hs::VerifyCustody(TestRustCustody,bundle,registry,receipts,UINT64_MAX));
    Require(!hs::VerifyCustody(TestRustCustody,bundle,registry,receipts,2));
    Require(!hs::VerifyCustody(TestRustCustody,bundle,registry,std::span{receipts}.first(413),3));
    Require(!hs::VerifyCustody(nullptr,bundle,registry,receipts,3));
    Require(verifier_calls.empty());
}

extern "C" bool TestReadJetAnnex(const void* context, const unsigned char** bytes, size_t* size)
{
    verifier_calls.push_back(5);
    const int mode = *static_cast<const int*>(context);
    static const unsigned char good[]{0x50,1,2}, bad[]{0x51,1,2};
    if (mode == 0) return false;
    if (mode == 5) return true; // A reader that publishes nothing must fail closed.
    *bytes = mode == 1 ? nullptr : mode == 3 ? bad : good;
    *size = mode == 2 ? 0 : 3;
    return true;
}

static void CheckRustJet()
{
    const std::array<unsigned char,32> program{17}, digest{29};
    for (uint32_t version : {0U,1U,2U}) for (int mode = 0; mode <= 5; ++mode) {
        for (uint32_t status : {0U,1U,4U,UINT32_MAX}) {
            verifier_calls.clear(); verifier_version = version; verifier_status = status;
            Require(elements_haskell_verify_jet(TestRustVersion,TestRustVerify,TestReadJetAnnex,&mode,
                program.data(),digest.data()) == (version == 1 && mode == 4 && status == 0));
            Require(verifier_calls == (version != 1 ? std::vector<int>{1} :
                mode != 4 ? std::vector<int>{1,5} : std::vector<int>{1,5,2}));
        }
    }
    verifier_calls.clear();
    Require(!elements_haskell_verify_jet(TestRustVersion,TestRustVerify,nullptr,nullptr,program.data(),digest.data()));
    Require(!elements_haskell_verify_jet(TestRustVersion,TestRustVerify,TestReadJetAnnex,nullptr,nullptr,digest.data()));
    Require(!elements_haskell_verify_jet(nullptr,TestRustVerify,TestReadJetAnnex,nullptr,program.data(),digest.data()));
    Require(!elements_haskell_verify_jet(TestRustVersion,nullptr,TestReadJetAnnex,nullptr,program.data(),digest.data()));
    Require(verifier_calls.empty());
}

static void CheckStatusAdapters()
{
    const std::vector<std::pair<std::function<void()>,const char*>> invalid{
        {[] { hs::AdmitStandardness(static_cast<hs::StandardnessGate>(3),0); }, "Haskell standardness gate failed"},
        {[] { hs::ContextPresence(1,0); }, "Haskell context presence evaluation failed"},
        {[] { hs::CtvAdmission(32,0); }, "Haskell CTV admission failed"},
        {[] { hs::TaprootWitnessPolicy(false,false,0,257,0,0); }, "Haskell Taproot witness policy failed"},
        {[] { hs::BmmMessageMatches(static_cast<hs::BmmMessageKind>(2),""); }, "Haskell BMM duplicate request classification failed"},
    };
    for (const auto& [call,message] : invalid) {
        bool failed{false};
        try { call(); }
        catch (const std::runtime_error& error) { failed=true; Require(std::string(error.what())==message); }
        Require(failed);
    }
    Require(!hs::AdmitStandardness(hs::StandardnessGate::ANNEX_NETWORK,0));
    Require(hs::AdmitStandardness(hs::StandardnessGate::ANNEX_NETWORK,7));
    Require(hs::ContextPresence(0,2)==0 && hs::ContextPresence(2,2)==1 && hs::ContextPresence(1,2)==2);
    Require(hs::TaprootWitnessPolicy(false,false,2,0xc4,0,0)==1);
    Require(!hs::TransactionWeight(false,1,2,400000,1500000));
    Require(!hs::BondMarkerPolicy(false,{}));
}

static void IdentityProfiles()
{
    for (const size_t size : {52, 53, 100, 65526}) {
        const std::string payload(size, '\0');
        std::vector<unsigned char> expected{0,8,'E','l','e','m','e','n','t','s'};
        expected.insert(expected.end(), payload.begin(), payload.end());
        Require(hs::ParseConfigurationField(hs::ConfigurationField::PROPOSAL_DESCRIPTION,
            payload, "proposal syntax", "proposal value") == expected);
    }
    for (const size_t size : {0, 51, 65527}) {
        bool rejected = false;
        try { hs::ParseConfigurationField(hs::ConfigurationField::PROPOSAL_DESCRIPTION,
            std::string(size, 'x'), "proposal syntax", "proposal value"); }
        catch (const std::runtime_error& e) { rejected = std::string(e.what()) == "proposal syntax"; }
        Require(rejected);
    }
    for (bool availability : {false,true}) {
        std::vector<unsigned char> expected(availability ? 32 : 16,3);
        std::vector<unsigned char> valid(availability ? 71 : 178,2);
        if (availability) { valid[0]=1; std::copy(expected.begin(),expected.end(),valid.begin()+1); valid[65]=3; valid[66]=5; WriteBE32(valid.data()+67,16777216); }
        else { valid[0]=5; valid[1]=3; std::copy(expected.begin(),expected.end(),valid.begin()+34); }
        const auto check=[&](const std::vector<unsigned char>& bytes) {
            const auto nonzero=[&](size_t offset) { return std::any_of(bytes.begin()+offset,bytes.begin()+offset+32,[](auto b) { return b!=0; }); };
            const bool accepted=availability ? bytes[0]==1 && nonzero(1) && nonzero(33) &&
                std::equal(expected.begin(),expected.end(),bytes.begin()+1) && bytes[65]==3 && bytes[66]==5 && ReadBE32(bytes.data()+67)==16777216 :
                (bytes[0]==5 || bytes[0]==6) && bytes[1]==3 && std::equal(expected.begin(),expected.end(),bytes.begin()+34) &&
                nonzero(2) && nonzero(50) && nonzero(82) && nonzero(114) && nonzero(146);
            std::vector<unsigned char> output(availability ? 64 : 161,0xa5);
            const int actual=elements_hs_exchange_frozen_profile_v1(availability ? 5 : 4,0,bytes.size(),
                const_cast<unsigned char*>(bytes.data()),expected.data(),output.data());
            Require(actual==(accepted ? 0 : 1));
            std::vector<unsigned char> wanted(output.size(),0xa5);
            if (accepted && availability) std::copy_n(bytes.begin()+1,64,wanted.begin());
            if (accepted && !availability) { wanted[0]=bytes[0]; std::copy_n(bytes.begin()+2,32,wanted.begin()+1); std::copy_n(bytes.begin()+50,128,wanted.begin()+33); }
            Require(output==wanted);
        };
        check(valid);
        for (size_t offset=0;offset<valid.size();++offset) for (unsigned byte : {0U,1U,3U,5U,6U,255U}) { auto bytes=valid; bytes[offset]=byte; check(bytes); }
        const std::vector<size_t> offsets=availability ? std::vector<size_t>{1,33} : std::vector<size_t>{2,50,82,114,146};
        for (size_t offset : offsets) { auto bytes=valid; std::fill_n(bytes.begin()+offset,32,0); check(bytes); }
        expected[0]^=1; check(valid);
    }
}

static void MatcherAccumulatorProfiles()
{
    for (bool matcher : {false,true}) {
        std::vector<unsigned char> valid(matcher ? 85 : 100,1);
        if (matcher) { WriteBE64(valid.data()+41,0); WriteBE32(valid.data()+81,6); }
        else { std::fill_n(valid.begin()+32,32,2); WriteBE32(valid.data()+96,64); }
        const auto check=[&](const std::vector<unsigned char>& bytes) {
            for (bool signer : {false,true}) {
                const auto nonzero=[&](size_t offset) { return std::any_of(bytes.begin()+offset,bytes.begin()+offset+32,[](auto b) { return b!=0; }); };
                const bool accepted=matcher ? bytes[0]==1 && signer && ReadBE64(bytes.data()+41)!=UINT64_MAX && nonzero(49) && ReadBE32(bytes.data()+81)==6 :
                    nonzero(0) && nonzero(32) && nonzero(64) && !std::equal(bytes.begin(),bytes.begin()+32,bytes.begin()+32) &&
                    ReadBE32(bytes.data()+96)>0 && ReadBE32(bytes.data()+96)<=64;
                std::vector<unsigned char> output(matcher ? 32 : 96,0xa5);
                const int actual=elements_hs_exchange_frozen_profile_v1(matcher ? 6 : 7,matcher && signer,bytes.size(),
                    const_cast<unsigned char*>(bytes.data()),nullptr,output.data());
                Require(actual==(accepted ? 0 : 1));
                std::vector<unsigned char> wanted(output.size(),0xa5);
                if (accepted) std::copy_n(bytes.begin()+(matcher ? 49 : 0),output.size(),wanted.begin());
                Require(output==wanted);
            }
        };
        check(valid);
        for (size_t offset=0;offset<valid.size();++offset) for (unsigned byte : {0U,1U,6U,64U,65U,255U}) { auto bytes=valid; bytes[offset]=byte; check(bytes); }
        for (size_t offset : matcher ? std::vector<size_t>{49} : std::vector<size_t>{0,32,64}) {
            auto bytes=valid; std::fill_n(bytes.begin()+offset,32,0); check(bytes);
        }
        auto bytes=valid;
        if (matcher) std::fill_n(bytes.begin()+41,8,255);
        else std::copy_n(bytes.begin(),32,bytes.begin()+32);
        check(bytes);
    }
}

static void SignalHandler(int) {}

// Prior production runner: an independent oracle for command framing and order.
static uint32_t ReferenceStore(uint32_t flow, const std::function<uint32_t(uint32_t)>& action)
{
    auto command = elements_hs_parent_replay_store_v2(flow, 0, 0);
    const int32_t maximum = elements_hs_parent_replay_store_v2(flow, UINT32_MAX, 0);
    if (maximum < 1 || maximum > 255) throw std::runtime_error("Haskell parent replay store evaluation failed");
    while (command > 0) {
        const auto step = static_cast<uint32_t>(command) & 255;
        const auto status = (static_cast<uint32_t>(command) >> 8) & 255;
        const bool terminal = command & 65536;
        const bool committing = command & 131072;
        const uint32_t flags = terminal ? 65536 : committing ? 131072 : 0;
        if (step < 1 || step > static_cast<uint32_t>(maximum) || status > 3 ||
            (terminal && committing) || command != static_cast<int32_t>(step + flags + (flags ? status * 256 : 0))) break;
        const auto result = action(step);
        if (terminal || (committing && result == 1)) return status;
        command = elements_hs_parent_replay_store_v2(flow, step, result);
    }
    if (command >= -13 && command <= -10) return -10 - command;
    throw std::runtime_error("Haskell parent replay store evaluation failed");
}

static void CheckStoreRunner()
{
    static_assert(static_cast<uint32_t>(hs::ReplayStoreFlow::CHILD_DRAIN) == 187);
    constexpr uint32_t last = static_cast<uint32_t>(hs::ReplayStoreFlow::BOND_TREE);
    for (uint32_t kind = 0; kind <= last; ++kind) for (uint32_t seed = 0; seed < 32; ++seed) {
        const auto run = [&](bool reference) {
            const auto owner = std::this_thread::get_id();
            std::vector<uint32_t> trace;
            uint32_t status{0};
            std::string failure;
            const auto action = [&](uint32_t step) -> uint32_t {
                Require(std::this_thread::get_id() == owner);
                trace.push_back(step);
                // Bound generated loops only; the production runner has no new limit.
                if (trace.size() == 128 || (seed >= 16 && trace.size() == seed-15))
                    throw std::logic_error("store callback sentinel");
                Require(hs::WithdrawalPayout(100,10,1000) == 90);
                Require(hs::ParentReplayStore(static_cast<hs::ReplayStoreFlow>(0),
                    [](uint32_t) { return 0U; }) <= 3);
                switch (seed % 8) {
                case 0: return 0;
                case 1: return 1;
                case 2: return UINT32_MAX;
                case 3: return 2;
                default: return (step*7 + trace.size()*13 + seed) % (seed % 8 == 4 ? 2 : 5);
                }
            };
            try { status = reference ? ReferenceStore(kind,action) :
                hs::ParentReplayStore(static_cast<hs::ReplayStoreFlow>(kind),action); }
            catch (const std::logic_error& e) { failure = std::string("logic:") + e.what(); }
            catch (const std::runtime_error& e) { failure = std::string("runtime:") + e.what(); }
            return std::tuple{status,trace,failure};
        };
        Require(run(false) == run(true));
    }
    for (const uint32_t kind : {129U,183U,198U,199U,200U,last+1,UINT32_MAX}) {
        bool called{false}, failed{false};
        try { hs::ParentReplayStore(static_cast<hs::ReplayStoreFlow>(kind),
            [&](uint32_t) { called = true; return 1U; }); }
        catch (const std::runtime_error&) { failed = true; }
        Require(failed && !called);
    }
    std::cout << "Store runner: " << (last+1)*32 << " legacy trace/exception comparisons, nested reentry, invalid kinds passed\n";
}

static bool ReferencePredicate(uint32_t kind, const std::function<bool(uint32_t)>& action)
{
    static constexpr uint32_t starts[]{0,11,19,27,35,51,61,67,72,77};
    static constexpr uint32_t bounds[]{51,17,34,27,6};
    const bool peg = kind > 10;
    const auto maximum = kind < 10 ? 82 : bounds[kind-10];
    const char* invalid = kind < 10 ? "Haskell deposit flow action invalid" :
        peg ? "Haskell peg event action invalid" : "Haskell parent replay tip action invalid";
    const char* failure = kind < 10 ? "Haskell deposit verification failed" :
        peg ? "Haskell peg event flow failed" : "Haskell parent replay tip evaluation failed";
    const auto next = [&](uint32_t phase, uint32_t result) -> int64_t {
        if (kind < 10) return elements_hs_deposit_verification_v1(phase,result);
        switch (kind) {
        case 10: return elements_hs_parent_replay_tip_v1(phase,result);
        case 11: return elements_hs_withdrawal_status_flow_v1(phase,result);
        case 12: return elements_hs_l1_normalization_v1(phase,result);
        case 13: return elements_hs_sidechain_events_v1(phase,result);
        case 14: return elements_hs_l1_location_v1(phase,result);
        default: throw std::logic_error("invalid predicate test kind");
        }
    };
    int64_t step = next(kind < 10 ? starts[kind] : 0,0);
    while (step > 0) {
        const bool terminal = (step & 256) != 0;
        step &= ~256;
        if (step < 1 || step > maximum) throw std::runtime_error(invalid);
        const bool result = action(step);
        if (terminal) {
            if (peg && !result) throw std::runtime_error(failure);
            return result;
        }
        step = next(step,result);
    }
    if (peg || step < -1) throw std::runtime_error(failure);
    return step == 0;
}

static bool RunPredicateCase(uint32_t kind, const std::function<bool(uint32_t)>& action)
{
    const auto deposit = [&](hs::DepositVerifyStep step) { return action(static_cast<uint32_t>(step)); };
    switch (kind) {
    case 0: case 1: return hs::RunDepositVerification(deposit,kind==1);
    case 2: case 3: return hs::RunDepositLifecycle(deposit,kind==3);
    case 4: return hs::RunDepositParsing(deposit);
    case 5: hs::RunCtipInputScan(deposit); return true;
    case 6: return hs::RunDepositAuthentication(deposit);
    case 7: return hs::RunCheckpointLookup(deposit);
    case 8: return hs::RunLegacyClaim(deposit);
    case 9: return hs::RunCtipRead(deposit);
    case 10: return hs::ParentReplayTip(action);
    case 11: hs::WithdrawalStatusFlow(action); return true;
    case 12: hs::L1NormalizationFlow(action); return true;
    case 13: hs::SidechainEventFlow(action); return true;
    case 14: hs::L1LocationFlow(action); return true;
    default: throw std::logic_error("invalid predicate test kind");
    }
}

static void CheckPredicateRunner()
{
    for (uint32_t kind = 0; kind < 15; ++kind) for (uint32_t seed = 0; seed < 64; ++seed) {
        const auto run = [&](bool reference) {
            const auto owner = std::this_thread::get_id();
            std::vector<uint32_t> trace;
            bool accepted{false};
            std::string failure;
            const auto action = [&](uint32_t step) -> bool {
                Require(std::this_thread::get_id() == owner);
                trace.push_back(step);
                if (trace.size() == 128 || (seed >= 32 && trace.size() == seed-31))
                    throw std::logic_error("predicate callback sentinel");
                Require(hs::WithdrawalPayout(100,10,1000) == 90);
                Require(!hs::ParentReplayTip([&](uint32_t) {
                    Require(std::this_thread::get_id() == owner);
                    return false;
                }));
                if (seed % 32 < 2) return (seed % 32) != 0;
                return ((step*1103515245U + uint32_t(trace.size())*12345U) >> (seed % 30)) & 1U;
            };
            try {
                accepted = reference ? ReferencePredicate(kind,action) : RunPredicateCase(kind,action);
                if (reference && kind == 5 && !accepted) throw std::runtime_error("Haskell CTIP input scan failed");
            } catch (const std::logic_error& e) { failure = std::string("logic:") + e.what(); }
            catch (const std::runtime_error& e) { failure = std::string("runtime:") + e.what(); }
            return std::tuple{accepted,trace,failure};
        };
        Require(run(false) == run(true));
    }
    std::cout << "Predicate runner: 960 legacy trace/exception comparisons and nested reentry passed\n";
}

static void CheckBmmStateRunner()
{
    using Step = hs::BmmStateStep;
    for (uint32_t start = 0; start <= 116; ++start) for (uint32_t seed = 0; seed < 64; ++seed) {
        const auto run = [&](bool reference) {
            const auto owner = std::this_thread::get_id();
            std::vector<uint32_t> trace;
            bool accepted{false};
            std::string failure;
            const auto action = [&](Step current) -> int32_t {
                Require(std::this_thread::get_id() == owner);
                const auto step = static_cast<uint32_t>(current);
                trace.push_back(step);
                if (trace.size() == 128 || (seed >= 32 && trace.size() == seed-31))
                    throw std::logic_error("BMM callback sentinel");
                Require(hs::WithdrawalPayout(100,10,1000) == 90);
                Require(!hs::RunBmmStateFlow(Step::COIN_START,[&](Step) {
                    Require(std::this_thread::get_id() == owner);
                    return 0;
                }));
                static constexpr int32_t replies[]{INT32_MIN,-7,-3,-2,-1,0,1,2,INT32_MAX};
                if (seed % 32 < std::size(replies)) return replies[seed % 32];
                const bool alternate = seed % 2;
                switch (step) {
                case 1: case 13: return alternate ? 1 : 2;
                case 3: case 15: case 110: return 0;
                case 4: case 71: return alternate ? 3 : 4;
                case 5: case 18: case 73: return 5;
                case 7: case 22: return 6;
                case 8: return 7;
                case 14: return 3;
                case 16: return 4;
                case 23: return -7;
                case 29: return trace.size() < seed % 32 ? 0 : 1;
                case 70: case 76: return 2;
                default: return 1;
                }
            };
            try {
                if (reference) {
                    auto phase = hs::BmmStateFlow(static_cast<Step>(start),0);
                    while (phase > 0) {
                        const auto current = static_cast<Step>(phase);
                        phase = hs::BmmStateFlow(current,action(current));
                    }
                    accepted = phase == 0;
                } else accepted = hs::RunBmmStateFlow(static_cast<Step>(start),action);
            } catch (const std::logic_error& e) { failure = std::string("logic:") + e.what(); }
            catch (const std::runtime_error& e) { failure = std::string("runtime:") + e.what(); }
            return std::tuple{accepted,trace,failure};
        };
        Require(run(false) == run(true));
    }
    bool called{false}, failed{false};
    try { hs::RunBmmStateFlow(static_cast<Step>(UINT32_MAX),[&](Step) { called = true; return 1; }); }
    catch (const std::runtime_error&) { failed = true; }
    Require(failed && !called);
    std::cout << "BMM runner: 7488 legacy signed trace/exception comparisons and nested reentry passed\n";
}

static void CheckBmmProofRunner()
{
    for (uint32_t kind = 0; kind < 2; ++kind) for (uint32_t start = 0; start < (kind ? 23U : 10U); ++start)
    for (uint32_t seed = 0; seed < 64; ++seed) {
        const auto run = [&](bool reference) {
            const auto owner = std::this_thread::get_id();
            std::vector<uint32_t> trace;
            uint64_t index{0}, writes{0};
            std::string error = seed % 2 ? "prior diagnostic" : "", failure;
            bool accepted{false};
            const auto action = [&](uint32_t step) {
                Require(std::this_thread::get_id() == owner);
                trace.push_back(step);
                if (trace.size() == 128 || (seed >= 32 && trace.size() == seed - 31))
                    throw std::logic_error("proof callback sentinel");
                Require(hs::WithdrawalPayout(100,10,1000) == 90);
                Require(!hs::RunBmmStateFlow(hs::BmmStateStep::COIN_START,[](auto) { return 0; }));
                writes += kind == 1 && step == 19;
                static constexpr uint64_t replies[]{0,1,2,3,UINT64_C(1)<<63,UINT64_MAX};
                if (seed % 32 < std::size(replies)) {
                    const auto value = replies[seed % 32];
                    return std::array<uint64_t,4>{value,value,value,value};
                }
                if (!kind) return step == 4 ? std::array<uint64_t,4>{seed % 3,0,0,0} :
                    step == 5 ? std::array<uint64_t,4>{1,1,1,0} : std::array<uint64_t,4>{1,0,0,0};
                if (step == 7) return std::array<uint64_t,4>{index++,seed % 5 + 1,0,0};
                return std::array<uint64_t,4>{step == 19 ? 0U : 1U,step == 5 ? seed % 2 : 0,0,0};
            };
            try {
                if (reference) {
                    auto phase = kind ? hs::BmmTraversal(static_cast<hs::BmmTraversalStep>(start),0,0,error) :
                        hs::SignetValidation(static_cast<hs::SignetStep>(start),0,0,0,0,error);
                    while (phase > 0) {
                        const auto fields = action(phase);
                        if (kind && phase == 19) { phase = 0; break; }
                        phase = kind ? hs::BmmTraversal(static_cast<hs::BmmTraversalStep>(phase),fields[0],fields[1],error) :
                            hs::SignetValidation(static_cast<hs::SignetStep>(phase),fields[0],fields[1],fields[2],fields[3],error);
                    }
                    accepted = phase == 0;
                } else if (kind) {
                    accepted = hs::RunBmmTraversal(static_cast<hs::BmmTraversalStep>(start),[&](auto step) {
                        const auto fields = action(static_cast<uint32_t>(step));
                        return std::array<uint64_t,2>{fields[0],fields[1]};
                    },error);
                } else accepted = hs::RunSignetValidation(static_cast<hs::SignetStep>(start),[&](auto step) {
                    return action(static_cast<uint32_t>(step));
                },error);
            } catch (const std::logic_error& e) { failure = std::string("logic:") + e.what(); }
            catch (const std::runtime_error& e) { failure = std::string("runtime:") + e.what(); }
            return std::tuple{accepted,trace,writes,error,failure};
        };
        Require(run(false) == run(true));
    }
    std::cout << "BMM proof runner: 2112 legacy unsigned traces, diagnostics, publication and exception comparisons passed\n";
}

static void CheckPegReadRunner()
{
    for (uint32_t kind = 0; kind < 9; ++kind) for (uint32_t seed = 0; seed < 128; ++seed) {
        const bool projection = kind == 8;
        const uint64_t limit = seed % 3 ? UINT64_MAX : 0;
        const auto run = [&](bool reference) {
            const auto owner = std::this_thread::get_id();
            std::vector<uint32_t> trace;
            bool accepted{false};
            std::string failure;
            const std::function<uint64_t(uint32_t)> action = [&](uint32_t step) {
                Require(std::this_thread::get_id() == owner);
                trace.push_back(step);
                if (seed >= 64 && trace.size() == seed % 16 + 1) throw std::logic_error("peg read sentinel");
                Require(hs::WithdrawalPayout(100,10,1000) == 90);
                hs::ReadWhen(false,[] { throw std::logic_error("guarded read forced"); });
                static constexpr uint64_t values[]{0,1,2,UINT64_MAX,UINT64_C(1)<<63,15};
                if (seed % 64 < std::size(values)) return values[seed % 64];
                if (projection) {
                    if (step == 2) return uint64_t{0};
                    if (step == 4) return uint64_t{15};
                    if (step == 7 || step == 9) return uint64_t{seed % 3};
                }
                if (kind == 2 && step == 3) return limit * 2;
                return uint64_t{1};
            };
            try {
                if (reference) {
                    int64_t phase = projection ? elements_hs_deposit_projection_v1(0,0) : elements_hs_peg_schema_v1(kind,0,0,limit);
                    while (phase > 0) {
                        const bool terminal = !projection && (phase & 256);
                        if (!projection) phase &= ~256;
                        if (phase < 1 || phase > (projection ? 10 : 5)) break;
                        const auto value = action(phase);
                        if (terminal) { phase = value == 1 ? 0 : -1; break; }
                        phase = projection ? elements_hs_deposit_projection_v1(phase,value) : elements_hs_peg_schema_v1(kind,phase,value,limit);
                    }
                    if (phase < (projection ? 0 : -1) || phase > 0)
                        throw std::runtime_error(projection ? "Haskell deposit fact projection failed" : "Haskell peg schema evaluation failed");
                    accepted = phase == 0;
                } else if (projection) {
                    hs::DepositTransactionFacts(action);
                    accepted = true;
                } else accepted = hs::PegSchema(static_cast<hs::PegSchemaKind>(kind),limit,action);
            } catch (const std::logic_error& e) { failure = std::string("logic:") + e.what(); }
            catch (const std::runtime_error& e) { failure = std::string("runtime:") + e.what(); }
            return std::tuple{accepted,trace,failure};
        };
        Require(run(false) == run(true));
    }
    std::cout << "Peg read runner: 1152 unsigned/terminal/exception traces and guarded nested reentry passed\n";
}

static bool CheckLiveSelection(hs::LiveEvidencePhase phase, uint32_t expected)
{
    std::array<uint32_t, 2> state{0, expected};
    const auto read = +[](void* context, uint32_t step, int64_t* fields) -> int32_t {
        auto& state = *static_cast<std::array<uint32_t, 2>*>(context);
        const uint32_t call = state[0]++;
        const uint32_t expected_step = state[1] == 11 && call == 8 ? 9 : state[1] == 11 && call == 9 ? 8 : call;
        if (step != expected_step) return -1;
        std::fill_n(fields, 4, step == 9 ? 65 : 1);
        return 1;
    };
    std::string error;
    return hs::LiveEvidence(phase, read, &state, {}, error) && state[0] == expected;
}

static int32_t TestTransactionHash(const unsigned char* bytes, uint32_t size, unsigned char* hash)
{
    if (size != 32) return 0;
    std::copy_n(bytes, 32, hash);
    return 1;
}

static bool CheckDepositCallback(uint32_t header_count = 3)
{
    std::vector<std::vector<unsigned char>> fields(11);
    fields[0] = {100,0,0,0,0,0,0,0};
    fields[1].assign(32, 1);
    fields[2].assign(32, 2);
    fields[3] = {0x51};
    const std::string marker = "drivechain-deposit-v2";
    fields[4].assign(marker.begin(), marker.end());
    fields[5].assign(32, 3);
    int64_t value{-123};
    uint32_t checked{0};
    const auto header = +[](void* state, uint32_t index) -> int32_t {
        auto& next = *static_cast<uint32_t*>(state);
        return index == next++ ? 3 : -1;
    };
    std::string error;
    const auto decode_ctip = +[](void*, int64_t* fields) -> int32_t {
        fields[0] = 100;
        fields[1] = 0;
        return 15;
    };
    uint32_t inspected{0};
    const auto inspect = +[](void* state, uint32_t index, uint32_t action) -> int32_t {
        ++*static_cast<uint32_t*>(state);
        if (index == 0) return action == 0 ? 106 : action == 1 ? 43 | (3 << 9) : 1;
        return action <= 1 ? 0 : -1;
    };
    std::vector<unsigned char> checkpoint;
    const auto live_fields = +[](void*, uint32_t step, int64_t* fields) -> int32_t {
        if (step == 0) { std::fill_n(fields, 4, 0); return 1; }
        if (step != 1) return -1;
        fields[0] = 100; fields[1] = 8; fields[2] = 8; fields[3] = 1;
        return 1;
    };
    return hs::DepositWitness(fields, 0, fields[1].data(), fields[2].data(), fields[5].data(),
               TestTransactionHash, value) == 3 && value == 100 &&
        hs::DepositInclusion(15, 1, header_count, header, &checked, error) && checked == header_count &&
        hs::DepositCtip(3, 1, 200, 100, 100, error) &&
        hs::PersistedCtip(31, 0, 71 | (117 << 9), decode_ctip, nullptr, error) &&
        hs::DepositState(hs::DepositStatePhase::CONNECT_PRIOR, true, true, {}, error) &&
        hs::LegacyClaim(true, true, 2000, 2000, error) &&
        !hs::LegacyCheckpoint(true, fields[1].data(), fields[2].data(), 0, checkpoint) && checkpoint.empty() &&
        hs::DepositDestination(2, inspect, &inspected, error) && inspected == 6 &&
        hs::LiveEvidence(hs::LiveEvidencePhase::CTIP_STATE, live_fields, nullptr, {}, error) &&
        CheckLiveSelection(hs::LiveEvidencePhase::SIDECHAIN, 7) &&
        CheckLiveSelection(hs::LiveEvidencePhase::DEPOSITS, 11) &&
        hs::PegEvent(hs::PegEventKind::LIFECYCLE, 4, 4) == 2 &&
        hs::PegEvent(hs::PegEventKind::DEPOSIT_NUMBERS, INT64_MAX, 1, 0) == 0 &&
        hs::BmmState(true, 2016, 4031, 1, 1, 2016, 1, 11, 1, error) &&
        hs::BmmHeader(2, error) == 6 && hs::BmmHeader(2 | 16 | 32 | 64 | 256, error) == 0 &&
        hs::BmmProof(hs::BmmProofPhase::MERKLE, 1, 1, 1, 0, error) &&
        hs::BmmProof(hs::BmmProofPhase::CANONICAL, 31, 1, 0, 0, error);
}

void CheckAnchorReentry()
{
    std::array<std::byte,145> anchor{};
    for (size_t offset : {0,1,33,65,133}) anchor[offset] = std::byte{1};
    anchor[97] = std::byte{2};
    const auto owner = std::this_thread::get_id();
    std::vector<uint32_t> seen;
    std::string error;
    Require(hs::ExchangeGenesisInitialization(0,[&](uint32_t step) {
        Require(std::this_thread::get_id()==owner);
        seen.push_back(step);
        return hs::AnchorRule(anchor);
    },error));
    Require(seen==std::vector<uint32_t>({0,1,2,3,4,19}));
    anchor[0] = std::byte{0};
    seen.clear();
    Require(!hs::ExchangeGenesisInitialization(0,[&](uint32_t step) {
        seen.push_back(step);
        return hs::AnchorRule(anchor);
    },error));
    Require(seen==std::vector<uint32_t>({0}));
}

int main()
{
    try {
#ifdef _WIN32
        Require(std::signal(SIGINT, SignalHandler) != SIG_ERR);
#else
        struct sigaction handler{}, before{}, after{};
        handler.sa_handler = SignalHandler;
        sigemptyset(&handler.sa_mask);
        Require(sigaction(SIGINT, &handler, nullptr) == 0);
        Require(sigaction(SIGINT, nullptr, &before) == 0);
#endif
        // Concurrent first entry also exercises the one-time RTS initializer.
        std::atomic<bool> ready{false}, ok{true};
        std::vector<std::thread> workers;
        for (unsigned t = 0; t < 8; ++t) workers.emplace_back([&] {
            while (!ready.load()) std::this_thread::yield();
            try {
                for (unsigned i = 0; i < 10000; ++i) {
                    if (!hs::HasDepositDepth(i, i + 5, 6) ||
                        hs::TreasurySlot(0x511801b7, 0xb7) != 24 ||
                        hs::WithdrawalPayout(100, 10, 1000) != 90) ok = false;
                    if (i < 100) {
                        const auto owner = std::this_thread::get_id();
                        if (hs::ParentReplayStore(static_cast<hs::ReplayStoreFlow>(0),[&](uint32_t) {
                            Require(std::this_thread::get_id() == owner);
                            Require(hs::WithdrawalPayout(100,10,1000) == 90);
                            return 0U;
                        }) > 3) ok = false;
                        if (hs::ParentReplayTip([&](uint32_t) {
                            Require(std::this_thread::get_id() == owner);
                            Require(hs::WithdrawalPayout(100,10,1000) == 90);
                            return false;
                        })) ok = false;
                        if (hs::RunBmmStateFlow(hs::BmmStateStep::COIN_START,[&](hs::BmmStateStep) {
                            Require(std::this_thread::get_id() == owner);
                            Require(hs::WithdrawalPayout(100,10,1000) == 90);
                            return 0;
                        })) ok = false;
                        std::string proof_error;
                        if (hs::RunSignetValidation(hs::SignetStep::START,[](auto) {
                            return std::array<uint64_t,4>{};
                        },proof_error) || proof_error != "BMM parent block has no Bitcoin witness commitment") ok = false;
                        if (!CheckDepositCallback()) ok = false;
                        std::vector<unsigned char> input(41, 0), script, parsed;
                        input[0] = 1;
                        input[32] = 10;
                        input[40] = 0x51;
                        if (!hs::WithdrawalBytes(hs::WithdrawalOp::BUILD_SCRIPT, input, script, nullptr)) ok = false;
                        input.resize(32);
                        input.insert(input.end(), script.begin(), script.end());
                        if (!hs::WithdrawalBytes(hs::WithdrawalOp::PARSE_SCRIPT, input, parsed, nullptr) ||
                            parsed != std::vector<unsigned char>({10,0,0,0,0,0,0,0,0x51})) ok = false;
                    }
                }
            } catch (...) { ok = false; }
        });
        ready = true;
        for (auto& worker : workers) worker.join();
        Require(ok);
#ifdef _WIN32
        Require(std::signal(SIGINT, SignalHandler) == SignalHandler);
#else
        Require(sigaction(SIGINT, nullptr, &after) == 0);
        Require(before.sa_handler == after.sa_handler);
#endif
        CheckStatusAdapters();
        CheckWideArithmetic();
        CheckOptionalEnvironment();
        CheckCanonicalActivation();
        CheckRustVerifier();
        CheckRustStartup();
        CheckRustGroth16();
        CheckRustCustody();
        CheckRustJet();
        CheckStoreRunner();
        CheckPredicateRunner();
        CheckBmmStateRunner();
        CheckBmmProofRunner();
        CheckPegReadRunner();
        CheckAnchorReentry();

        Require(!hs::HasDepositDepth(1000, 1004, 6));
        Require(hs::TreasurySlot(0x511800b7, 0xb7) == -1);
        Require(hs::WithdrawalPayout(10, 10, 1000) == -3);
        std::vector<unsigned char> output{1};
        std::string error;
        Require(!hs::WithdrawalBytes(hs::WithdrawalOp::LEGACY_FRAME, {}, output, &error));
        Require(output.empty() && !error.empty());
        bool fault = false;
        try { hs::WithdrawalBytes(static_cast<hs::WithdrawalOp>(0), {}, output, nullptr); }
        catch (const std::runtime_error&) { fault = true; }
        Require(fault);
        Require(hs::DepositOutputs(14, 100, std::vector<unsigned char>{3,0},
            std::vector<unsigned char>{7,0}, std::vector<int64_t>{100,99}, error));
        Require(!hs::DepositOutputs(14, 100, std::vector<unsigned char>{3},
            std::vector<unsigned char>{15}, std::vector<int64_t>{100}, error));
        Require(error == "The committed deposit recipient must receive the exact explicit pegged-asset amount.");
        Require(CheckDepositCallback(2017));
        Require(!hs::DepositState(hs::DepositStatePhase::CHECK_PRIOR, false, false, "decode failed", error));
        Require(error == "decode failed");
        Require(!hs::DepositState(hs::DepositStatePhase::CHECK_CHECKPOINT, true, true, "ignored", error));
        Require(error == "historical drivechain checkpoint cannot overwrite authenticated CTIP state");
        const auto unchanged = error;
        Require(hs::DepositState(hs::DepositStatePhase::CHECK_PRIOR, true, true, {}, error));
        Require(error == unchanged);
        fault = false;
        try { hs::DepositState(static_cast<hs::DepositStatePhase>(8), true, true, {}, error); }
        catch (const std::runtime_error&) { fault = true; }
        Require(fault && error == unchanged);
        const auto failed_fields = +[](void*, uint32_t, int64_t*) -> int32_t { return 0; };
        Require(!hs::LiveEvidence(hs::LiveEvidencePhase::NETWORK, failed_fields, nullptr, "parser failure", error));
        Require(error == "parser failure");
        fault = false;
        try { hs::LiveEvidence(hs::LiveEvidencePhase::NETWORK, failed_fields, nullptr, {}, error); }
        catch (const std::runtime_error&) { fault = true; }
        Require(fault);
        fault = false;
        try { hs::LiveEvidence(static_cast<hs::LiveEvidencePhase>(UINT32_MAX), nullptr, nullptr, {}, error); }
        catch (const std::runtime_error&) { fault = true; }
        Require(fault);
        Require(!hs::LegacyClaim(false, false, 2000, 2000, error));
        for (const auto& [kind, expected] : std::vector<std::pair<hs::PegEventKind, std::string>>{
            {static_cast<hs::PegEventKind>(UINT32_MAX), "Haskell peg event evaluation failed"},
            {hs::PegEventKind::STATUS, "withdrawal bundle has conflicting succeeded and failed events"}}) {
            fault = false;
            try { hs::PegEvent(kind, 2, 2); }
            catch (const std::runtime_error& failure) { fault = failure.what() == expected; }
            Require(fault);
        }
        Require(error == "historical drivechain checkpoint witness does not match its immutable value");
        Require(!hs::LegacyClaim(true, false, 2000, 2000, error));
        Require(error == "historical drivechain checkpoint destination is invalid for this network");
        Require(!hs::DepositDestination(0, nullptr, nullptr, error));
        Require(error == "deposit transaction does not commit a valid sidechain destination");
        fault = false;
        try { hs::DepositDestination(1, +[](void*, uint32_t, uint32_t) -> int32_t { return -1; }, nullptr, error); }
        catch (const std::runtime_error&) { fault = true; }
        Require(fault);
        fault = false;
        try { hs::DepositInclusion(15, 1, 1, +[](void*, uint32_t) -> int32_t { return -1; }, nullptr, error); }
        catch (const std::runtime_error&) { fault = true; }
        Require(fault);
        IdentityProfiles();
        MatcherAccumulatorProfiles();
        for (bool deferred : {false,true}) for (bool per_asset : {false,true}) for (bool explicit_asset : {false,true}) {
            const auto expected = deferred ? hs::OutputTotalMode::DEFERRED : !per_asset ? hs::OutputTotalMode::AGGREGATE :
                explicit_asset ? hs::OutputTotalMode::PER_ASSET : hs::OutputTotalMode::REJECT;
            Require(hs::SelectOutputTotalMode(deferred,per_asset,explicit_asset) == expected);
        }
        for (bool invalid : {false,true}) for (bool unavailable : {false,true})
            Require(hs::RejectParentResult(invalid,unavailable) == (invalid && !unavailable));
        std::cout << "Haskell FFI passed: 8 concurrent callers, first initialization, signal ownership, rejection ABI, four frozen profiles\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
