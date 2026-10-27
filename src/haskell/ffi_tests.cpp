// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <test/util/haskell_reference.h>
#include <haskell/bridge.h>
#include <haskell/domain_abi.h>
#include <haskell/simplicity_ffi.h>
#include <crypto/common.h>
#include <uint256.h>
#include <primitives/transaction.h>

#include <atomic>
#include <algorithm>
#include <csignal>
#include <exception>
#include <iostream>
#include <map>
#include <stdexcept>
#include <thread>
#include <tuple>
#include <vector>

namespace hs = drivechain::haskell;

static void Require(bool ok)
{
    if (!ok) throw std::runtime_error("Haskell runtime/ABI test failed");
}

static void CheckParentHeaders()
{
    const std::vector<uint32_t> expected{30,31,32,20,21,22,23,22,24,1,2,3,4,5,6,33,34,31,35};
    for (int failure = -1; failure < static_cast<int>(expected.size()); ++failure) {
        std::vector<uint32_t> seen;
        bool caught{false};
        try {
            Require(hs::RunParentHeader(hs::ParentHeaderWorkflow::RPC_MEDIAN,0,
                [&](uint32_t step,uint64_t) -> uint64_t {
                    seen.push_back(step);
                    if (static_cast<int>(seen.size()) == failure+1) throw std::logic_error("parent header original failure");
                    return step >= 2 && step <= 6 ? 0 : 1;
                }));
        } catch (const std::logic_error& e) {
            caught = std::string(e.what()) == "parent header original failure";
        }
        Require(caught == (failure >= 0));
        const auto end = failure < 0 ? expected.size() : static_cast<size_t>(failure+1);
        Require(seen == std::vector<uint32_t>(expected.begin(),expected.begin()+end));
    }
    using Event = std::pair<uint32_t,uint64_t>;
    for (bool native_deadlines : {false,true}) {
        std::vector<Event> complete;
        for (int failure = -1; failure < static_cast<int>(complete.size()); ++failure) {
            std::vector<Event> seen;
            bool caught{false};
            try {
                Require(hs::RunParentHeader(native_deadlines ? hs::ParentHeaderWorkflow::RPC_VERIFY_DEADLINE :
                    hs::ParentHeaderWorkflow::RPC_VERIFY,0,
                    [&](uint32_t step,uint64_t index) -> uint64_t {
                        seen.emplace_back(step,index);
                        if (static_cast<int>(seen.size()) == failure+1)
                            throw std::logic_error("parent authentication original failure");
                        if (step >= 200) step -= 200;
                        else if (step >= 100) step -= 100;
                        if (step == 36) return 0;
                        if (step == 42) return 64;
                        if (step == 55 || step == 60) return 10;
                        if (step == 56 || step == 57) return 6;
                        if (step == 70) return 9;
                        if ((step >= 2 && step <= 6) || step == 9 || step == 91) return 0;
                        return 1;
                    }));
            } catch (const std::logic_error& e) {
                caught = std::string(e.what()) == "parent authentication original failure";
            }
            if (failure == -1) {
                complete = seen;
                Require(complete.back() == Event{91,0});
                Require(std::count(complete.begin(),complete.end(),Event{132,0}) == 11);
                Require(std::count(complete.begin(),complete.end(),Event{136,1}) == (native_deadlines ? 34 : 0));
            }
            Require(caught == (failure >= 0));
            const auto end = failure < 0 ? complete.size() : static_cast<size_t>(failure+1);
            Require(seen == std::vector<Event>(complete.begin(),complete.begin()+end));
        }
    }
}

static void CheckNativeDeposits()
{
    const auto word = [](uint64_t value) {
        std::vector<unsigned char> bytes(8);
        WriteLE64(bytes.data(),value);
        return bytes;
    };
    const std::vector<uint32_t> construction{1,2,3,5,6,7,8,9};
    const std::vector<uint32_t> outputs{10,10,1,2,3,10,20};
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint(Txid::FromUint256(uint256{}),0));
    tx.vin[0].m_is_pegin = true;
    tx.vout.resize(1);
    tx.witness.vtxinwit.resize(1);
    const std::string marker = "drivechain-deposit-v2", address = "address";
    tx.witness.vtxinwit[0].m_pegin_witness.stack = {word(100),std::vector<unsigned char>(32),
        std::vector<unsigned char>(32),{81},{marker.begin(),marker.end()},
        std::vector<unsigned char>(32),std::vector<unsigned char>(32),{address.begin(),address.end()}};
    const CTransaction view(tx);
    const uint256 zero{};
    for (bool build : {false,true}) {
        const auto& expected = build ? construction : outputs;
        for (int failure = -1; failure < static_cast<int>(expected.size()); ++failure) {
            std::vector<uint32_t> seen;
            bool caught{false};
            try {
                const hs::NativeWorkflow native = [&](uint32_t step,uint64_t,std::span<const unsigned char>) {
                    seen.push_back(step);
                    if (static_cast<int>(seen.size()) == failure+1)
                        throw std::logic_error("native deposit original failure");
                    if (step == 2) return word(1);
                    if (step == 10) return word(7);
                    if (step == 20) {
                        auto bytes = word(7 | (23 << 8));
                        const auto value = word(100);
                        bytes.insert(bytes.end(),value.begin(),value.end());
                        return bytes;
                    }
                    return std::vector<unsigned char>{};
                };
                std::string error;
                const bool ok = build ? hs::RunNativeRecipient(hs::NativeRecipient::CONSTRUCT,100,"dcfee1:1:address",native)
                    : hs::CheckNativeDeposit(view,0,true,zero.begin(),zero.begin(),nullptr,native,error);
                Require(ok);
            } catch (const std::logic_error& e) {
                caught = std::string(e.what()) == "native deposit original failure";
            }
            Require(caught == (failure >= 0));
            const auto end = failure < 0 ? expected.size() : static_cast<size_t>(failure+1);
            Require(seen == std::vector<uint32_t>(expected.begin(),expected.begin()+end));
        }
    }
}

static void CheckParentPrelude()
{
    const std::vector<std::pair<uint32_t,uint64_t>> expected{{0,0},{1,0},{2,0},{3,0},{10,0},
        {30,1},{30,7},{11,0},{12,1},{12,2},{12,3},{12,4},{12,5},{12,6},{12,7},{12,8},{12,9},
        {13,0},{15,0},{20,0},{30,1},{30,7},{21,1},{22,0}};
    for (int failure = -1; failure < static_cast<int>(expected.size()); ++failure) {
        std::vector<std::pair<uint32_t,uint64_t>> seen;
        bool caught{false};
        try {
            Require(hs::ReplayParentPrelude([&](uint32_t step,uint64_t index,std::span<const unsigned char> input) {
                seen.emplace_back(step,index);
                if (static_cast<int>(seen.size()) == failure+1) throw std::logic_error("prelude native effect failed");
                std::vector<unsigned char> result;
                const auto word = [](uint64_t value) {
                    std::vector<unsigned char> bytes(8);
                    WriteLE64(bytes.data(),value);
                    return bytes;
                };
                if (step == 0) {
                    result.resize(44);
                    WriteLE64(result.data(),24);
                    WriteLE64(result.data()+8,19);
                    WriteLE64(result.data()+24,MAX_MONEY);
                    for (size_t i = 32; i < 44; i += 4) { WriteLE16(result.data()+i,10); WriteLE16(result.data()+i+2,5); }
                    return result;
                }
                if (step == 1) return word(6);
                if (step == 10 || step == 12) return word(1);
                if (step == 20) return word(2);
                if (step == 30) return word(0);
                if (step == 22) return std::vector<unsigned char>(32,42);
                if (step == 13 || step == 21) {
                    result = step == 13 ? std::vector<unsigned char>{0xd1,0x61,0x73,0x68,24} :
                        std::vector<unsigned char>{106,68,0,191,0,24};
                    for (unsigned char i = 1; i <= 32; ++i) result.push_back(i);
                    if (step == 21) result.insert(result.end(),32,42);
                    return result;
                }
                if (step == 15) {
                    Require(input.size() == 35 && input[0] == 5 && input[1] == 24 && input[2] == 0);
                    for (size_t i = 0; i < 32; ++i) Require(input[3+i] == 32-i);
                }
                return result;
            }) == 0);
        } catch (const std::logic_error& error) {
            caught = std::string(error.what()) == "prelude native effect failed";
        }
        Require(caught == (failure >= 0));
        Require(seen == std::vector<std::pair<uint32_t,uint64_t>>(expected.begin(),
            failure < 0 ? expected.end() : expected.begin()+failure+1));
    }
    Require(elements_hs_parent_prelude_v1(nullptr,nullptr) == -1);
    bool rejected{false};
    try { hs::ReplayParentPrelude([](auto,auto,auto) { return std::vector<unsigned char>{1}; }); }
    catch (const std::runtime_error&) { rejected = true; }
    Require(rejected);
}

static void CheckParentBlock()
{
    using Call = std::pair<uint32_t,uint64_t>;
    const std::vector<Call> expected{{30,1},{30,7},{201,0},{0,0},{1,0},{2,0},{3,0},{10,0},{20,0},
        {5096,0},{4136,0},{8192,0},{8193,24},{13288,0},{17384,0},{16394,0},{16395,0},
        {16396,0},{16397,0},{16405,0},{16411,0}};
    for (int failure = -1; failure < static_cast<int>(expected.size()); ++failure) {
        std::vector<Call> seen;
        bool caught{false};
        try {
            Require(hs::ReplayParentBlock(100,{10,5,10,5},10,5,0xb7,false,
                [&](uint32_t step,uint64_t index,std::span<const unsigned char> input) {
                    seen.emplace_back(step,index);
                    if (static_cast<int>(seen.size()) == failure+1)
                        throw std::logic_error("parent block native effect failed");
                    const auto words = [](std::initializer_list<uint64_t> values) {
                        std::vector<unsigned char> bytes(values.size()*8);
                        size_t offset{0};
                        for (const auto value : values) { WriteLE64(bytes.data()+offset,value); offset += 8; }
                        return bytes;
                    };
                    switch (step) {
                    case 0: {
                        auto bytes = words({24,19,0,MAX_MONEY});
                        bytes.resize(44);
                        for (size_t i = 32; i < 44; i += 4) { WriteLE16(bytes.data()+i,10); WriteLE16(bytes.data()+i+2,5); }
                        return bytes;
                    }
                    case 1: return words({6});
                    case 10: case 30: case 5096: return words({0});
                    case 20: return words({1});
                    case 8192: return std::vector<unsigned char>{24,0};
                    case 13288: return words({1,0,MAX_MONEY});
                    case 17384: return words({12});
                    case 16394: return std::vector<unsigned char>{42,0,43,1};
                    case 16395: Require(input.size() == 1 && input[0] == 42); break;
                    case 16405: case 16411: return std::vector<unsigned char>{0};
                    case 201: case 2: case 3: case 4136: case 8193: case 16396: case 16397: break;
                    default: throw std::runtime_error("unexpected parent block callback");
                    }
                    return std::vector<unsigned char>{};
                }) == 0);
        } catch (const std::logic_error& error) {
            caught = std::string(error.what()) == "parent block native effect failed";
        }
        Require(caught == (failure >= 0));
        Require(seen == std::vector<Call>(expected.begin(),failure < 0 ? expected.end() : expected.begin()+failure+1));
    }
    Require(elements_hs_parent_block_v1(100,0,10,5,0xb7,0,nullptr,nullptr) == -1);
    bool rejected{false};
    try { hs::ReplayParentBlock(100,{10,5,10,5},10,5,0xb7,false,
        [](auto,auto,auto) { return std::vector<unsigned char>{1}; }); }
    catch (const std::runtime_error&) { rejected = true; }
    Require(rejected);
}

static void CheckDepositConstruction()
{
    using Call = std::pair<uint32_t,uint64_t>;
    const std::vector<Call> expected{{0,0},{1,0},{2,0},{3,0},{4,0},{10,0},
        {101,0},{103,0},{104,0},{105,0},{101,1},{103,1},{104,1},{105,1},{102,1},
        {11,0},{12,0},{20,0},{21,10},{22,0},{21,11},{22,0}};
    const auto word = [](uint64_t value) {
        std::vector<unsigned char> bytes(8);
        WriteLE64(bytes.data(),value);
        return bytes;
    };
    const auto reply = [&](uint32_t step,uint64_t index,std::span<const unsigned char> input) {
        if (step == 11) Require(input.size() == 8 && ReadLE64(input.data()) == 6);
        else Require(input.empty());
        if (step >= 101 && step <= 105) {
            auto body = word(1);
            if (step == 101) {
                const auto hex = word(1);
                body.insert(body.end(),hex.begin(),hex.end());
            }
            if (step == 105) body = {static_cast<unsigned char>(index == 0 ? 0xb7 : 0xb4),1,24,0x51};
            body.insert(body.begin(),0);
            return body;
        }
        switch (step) {
        case 0: case 4: case 11: case 20: case 22: return std::vector<unsigned char>{};
        case 1: case 2: case 3: case 21: return word(1);
        case 10: return word(2);
        case 12: return word(11);
        default: throw std::logic_error("unexpected construction callback");
        }
    };
    for (int failure = -1; failure < static_cast<int>(expected.size()); ++failure) {
        std::vector<Call> seen;
        bool caught{false};
        try {
            hs::ConstructDepositEvidence(7,10,3,24,[&](uint32_t step,uint64_t index,std::span<const unsigned char> input) {
                seen.emplace_back(step,index);
                if (static_cast<int>(seen.size()) == failure+1)
                    throw std::logic_error("deposit native effect failed");
                return reply(step,index,input);
            });
        } catch (const std::logic_error& error) {
            caught = std::string(error.what()) == "deposit native effect failed";
        }
        Require(caught == (failure >= 0));
        Require(seen == std::vector<Call>(expected.begin(),failure < 0 ? expected.end() : expected.begin()+failure+1));
    }
    Require(elements_hs_deposit_construction_v1(7,10,3,24,nullptr,nullptr) == -1);
    for (int slot : {-1,256}) {
        bool rejected{false};
        try { hs::ConstructDepositEvidence(7,10,3,slot,reply); }
        catch (const std::runtime_error& error) {
            rejected = std::string(error.what()) == "deposit transaction's prior CTIP transaction is unavailable";
        }
        Require(rejected);
    }
    bool rejected{false};
    try { hs::ConstructDepositEvidence(0,10,3,24,[](auto,auto,auto) -> std::vector<unsigned char> {
        throw std::logic_error("preflight must not call native code");
    }); }
    catch (const std::runtime_error& error) {
        rejected = std::string(error.what()) == "authenticated deposit cannot form a v2 CTIP transition";
    }
    Require(rejected);
    rejected = false;
    try { hs::ConstructDepositEvidence(7,10,3,24,[](auto,auto,auto) { return std::vector<unsigned char>{1}; }); }
    catch (const std::runtime_error& error) { rejected = std::string(error.what()) == "Haskell deposit reconstruction failed"; }
    Require(rejected);
    std::vector<Call> seen;
    rejected = false;
    try { hs::ConstructDepositEvidence(7,10,3,24,[&](uint32_t step,uint64_t index,std::span<const unsigned char> input) {
        seen.emplace_back(step,index);
        if (step == 101) {
            const std::string message{"prefix multiple slot CTIP suffix"};
            std::vector<unsigned char> bytes{1};
            bytes.insert(bytes.end(),message.begin(),message.end());
            return bytes;
        }
        if (step == 109) throw std::runtime_error("original fatal candidate exception");
        return reply(step,index,input);
    }); }
    catch (const std::runtime_error& error) { rejected = std::string(error.what()) == "original fatal candidate exception"; }
    Require(rejected && seen.back() == Call{109,0} && seen.size() == 8);
}

static void CheckDeterministicParsing()
{
    const auto word = [](uint64_t value) {
        std::vector<unsigned char> bytes(8);
        WriteLE64(bytes.data(),value);
        return bytes;
    };
    const std::vector<unsigned char> asset(32,3), genesis(32,4), txid(32,5);
    const std::string marker{"drivechain-deposit-v2"};
    const std::vector<std::vector<unsigned char>> stack{word(100),asset,genesis,{81},
        {marker.begin(),marker.end()},txid,{1},{1},word(1),word(0),{1}};
    const auto hash = +[](const unsigned char* bytes,uint32_t size,unsigned char* output) -> int32_t {
        if (size != 32) return 0;
        std::copy_n(bytes,32,output);
        return 1;
    };
    const auto decode = +[](void*,int64_t* output) -> int32_t {
        output[0] = 1; output[1] = 0; output[2] = 2;
        return 1;
    };
    using Call = std::pair<uint32_t,uint64_t>;
    const std::vector<Call> expected{{0,0},{1,0},{2,0},{3,0},{4,0},{5,0},{5,1},{6,0},{7,0},
        {8,0},{9,0},{10,0},{11,0},{8,1},{12,0},{13,0},{14,0},{15,0},{16,0},
        {20,0},{21,0},{20,1},{21,1},{22,1},{23,1},{24,0}};
    for (int failure = -1; failure < static_cast<int>(expected.size()); ++failure) {
        std::vector<Call> seen;
        bool caught{false};
        std::string error{"unchanged"};
        try {
            Require(hs::ParseDeterministicDeposit(1,0,1,stack,asset.data(),genesis.data(),txid.data(),hash,decode,nullptr,
                [&](uint32_t step,uint64_t index,std::span<const unsigned char> input) {
                    seen.emplace_back(step,index);
                    if (static_cast<int>(seen.size()) == failure+1)
                        throw std::logic_error("original parsing effect failure");
                    if (step == 13) Require(input.size() == 8 && ReadLE64(input.data()) == 100);
                    else Require(input.empty());
                    switch (step) {
                    case 0: case 6: case 11: case 13: case 24: return std::vector<unsigned char>{};
                    case 1: case 2: case 3: case 9: case 22: case 23: return word(1);
                    case 4: {
                        auto result = word(15);
                        for (auto value : {1U,2U}) {
                            const auto bytes = word(value);
                            result.insert(result.end(),bytes.begin(),bytes.end());
                        }
                        return result;
                    }
                    case 5: return word(3);
                    case 7: case 16: return word(2);
                    case 8: return word(index == 0);
                    case 10: case 14: return std::vector<unsigned char>{0xb4,1,24,0x51};
                    case 12: return word(100);
                    case 15: return word(200);
                    case 20: return word(index == 0 ? 0 : 106);
                    case 21: return word(1+512+1024);
                    default: throw std::logic_error("unexpected parsing native action");
                    }
                },error));
        } catch (const std::logic_error& exception) {
            caught = std::string(exception.what()) == "original parsing effect failure";
        }
        Require(caught == (failure >= 0));
        Require(seen == std::vector<Call>(expected.begin(),failure < 0 ? expected.end() : expected.begin()+failure+1));
        Require(error == "unchanged");
    }
    std::string error;
    const hs::NativeWorkflow forbidden = [](auto,auto,auto) -> std::vector<unsigned char> {
        throw std::logic_error("out-of-range parser touched native code");
    };
    Require(!hs::ParseDeterministicDeposit(0,0,0,{},nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,forbidden,error));
    Require(error == "drivechain deposit input index is out of range");
}

static void CheckDepositClaims()
{
    const auto word = [](uint64_t value) {
        std::vector<unsigned char> bytes(8);
        WriteLE64(bytes.data(),value);
        return bytes;
    };
    const std::vector<unsigned char> asset(32,3), genesis(32,4), txid(32,5);
    const std::string marker{"drivechain-deposit-v1"};
    const std::vector<std::vector<unsigned char>> stack{word(100),asset,genesis,{81},
        {marker.begin(),marker.end()},txid};
    const auto identity = uint256S("feed724d3382997ae6500d8185353e116d557a4f299b58e8f722c1aa400ab730");
    const auto previous = uint256S("7de4aeb747a54bbe6b590d2038f445b9dc995217fb1b4e524c4129cdd0f06bea");
    std::vector<unsigned char> record;
    Require(hs::LegacyCheckpoint(true,identity.begin(),previous.begin(),0,record));
    const std::vector<std::vector<uint32_t>> traces{{0,1},{10,11,12},{20,21,22,22,23}};
    for (uint32_t mode = 0; mode < 3; ++mode) {
        const auto& expected = traces[mode];
        for (int failure = -1; failure < static_cast<int>(expected.size()); ++failure) {
            std::vector<uint32_t> seen;
            bool caught{false};
            std::string error{"unchanged"};
            try {
                Require(hs::RunDepositClaim(static_cast<hs::DepositClaimWorkflow>(mode),1,0,1,2,
                    stack,asset.data(),genesis.data(),txid.data(),nullptr,
                    [&](uint32_t step,uint64_t index,std::span<const unsigned char> input) {
                        seen.push_back(step);
                        if (static_cast<int>(seen.size()) == failure+1) throw std::logic_error("original claim exception");
                        if (step == 1) Require(std::vector<unsigned char>(input.begin(),input.end()) == record);
                        else if (step == 21) Require(input.size() == 1 && input[0] == 1);
                        else Require(input.empty());
                        switch (step) {
                        case 0: {
                            std::vector<unsigned char> row(identity.begin(),identity.end());
                            row.insert(row.end(),previous.begin(),previous.end());
                            row.resize(68);
                            return row;
                        }
                        case 1: case 12: return std::vector<unsigned char>{};
                        case 10: return word(1);
                        case 11: case 23: return word(100);
                        case 20: return word(15);
                        case 21: return word(3);
                        case 22: {
                            auto row = word(index == 0 ? 23 : 15);
                            const auto amount = word(index == 0 ? 90 : 10);
                            row.insert(row.end(),amount.begin(),amount.end());
                            return row;
                        }
                        default: throw std::logic_error("unexpected claim native action");
                        }
                    },error));
            } catch (const std::logic_error& exception) {
                caught = std::string(exception.what()) == "original claim exception";
            }
            Require(caught == (failure >= 0));
            Require(seen == std::vector<uint32_t>(expected.begin(),failure < 0 ? expected.end() : expected.begin()+failure+1));
            Require(error == "unchanged");
        }
    }
    const hs::NativeWorkflow forbidden = [](auto,auto,auto) -> std::vector<unsigned char> {
        throw std::logic_error("missing claim input touched native code");
    };
    std::string error{"unchanged"};
    Require(!hs::RunDepositClaim(hs::DepositClaimWorkflow::CHECKPOINT,0,0,0,0,{},
        nullptr,nullptr,nullptr,nullptr,forbidden,error));
    Require(error == "unchanged");
    Require(elements_hs_deposit_claim_v1(99,0,0,0,0,MAX_MONEY,4000000,0,
        nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr) == -1);
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

static void CheckStatusAdapters()
{
    const std::vector<std::pair<std::function<void()>,const char*>> invalid{
        {[] { hs::CtvAdmission(32,0); }, "Haskell CTV admission failed"},
        {[] { hs::BmmMessageMatches(static_cast<hs::BmmMessageKind>(2),""); }, "Haskell BMM duplicate request classification failed"},
    };
    for (const auto& [call,message] : invalid) {
        bool failed{false};
        try { call(); }
        catch (const std::runtime_error& error) { failed=true; Require(std::string(error.what())==message); }
        Require(failed);
    }
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
    constexpr uint32_t last = static_cast<uint32_t>(hs::ReplayStoreFlow::BLOCK_REPLAY_PRELUDE);
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
    static_assert(static_cast<uint32_t>(hs::ReplayStoreFlow::RECOVERY_COMPOSED) == 334);
    std::vector<uint32_t> recovery;
    Require(hs::ParentReplayStore(hs::ReplayStoreFlow::RECOVERY_COMPOSED,[&](uint32_t step) {
        recovery.push_back(step);
        return step == 101 ? 0 : 1;
    }) == 0);
    Require(recovery == std::vector<uint32_t>({1,101,3,4}));
    for (const uint32_t kind : {129U,183U,198U,199U,200U,
            static_cast<uint32_t>(hs::ReplayStoreFlow::RECOVERY_COMPOSED)+1,UINT32_MAX}) {
        bool called{false}, failed{false};
        try { hs::ParentReplayStore(static_cast<hs::ReplayStoreFlow>(kind),
            [&](uint32_t) { called = true; return 1U; }); }
        catch (const std::runtime_error&) { failed = true; }
        Require(failed && !called);
    }
    std::cout << "Store runner: " << (last+1)*32 << " legacy trace/exception comparisons, nested reentry, invalid kinds passed\n";
}

static void CheckRpcPreparation()
{
    static_assert(static_cast<uint32_t>(hs::ReplayStoreFlow::RPC_CREDENTIALS_COMPOSED) == 329);
    static_assert(static_cast<uint32_t>(hs::ReplayStoreFlow::RPC_TIMEOUT_COMPOSED) == 330);
    for (auto kind : {hs::ReplayStoreFlow::READ_RECORD,hs::ReplayStoreFlow::PARENT_DEADLINE,
            hs::ReplayStoreFlow::RPC_TIMEOUT,hs::ReplayStoreFlow::CREDENTIAL_SOURCE,
            hs::ReplayStoreFlow::RPC_CREDENTIALS_COMPOSED,hs::ReplayStoreFlow::RPC_TIMEOUT_COMPOSED}) {
        for (int64_t bad : {int64_t{-1},INT64_MIN,int64_t{UINT32_MAX}+1,INT64_MAX}) {
            unsigned calls{0};
            bool rejected{false};
            try { hs::ParentReplayStore(kind,[&](uint32_t) { ++calls; return bad; }); }
            catch (const std::runtime_error&) { rejected = true; }
            Require(rejected && calls == 1);
        }
    }
    for (uint32_t flags = 0; flags < 4096; ++flags) {
        const auto run = [&](bool reference, int fault) {
            std::vector<uint32_t> trace;
            std::string credential, cached = "cached-cookie", error;
            bool held{false};
            uint32_t status{0};
            const auto flag = [&](unsigned bit) { return (flags >> bit) & 1; };
            const auto action = [&](uint32_t step) -> int64_t {
                trace.push_back(step);
                if (int(trace.size()) == fault+1) throw std::logic_error("credential fault");
                switch (step) {
                case 1: case 43: return flag(0);
                case 2: return flag(1);
                case 3: case 7: return flag(2);
                case 4: case 8: return flag(3);
                case 6: return flag(4);
                case 11: return flag(5);
                case 21: case 41: return flag(6);
                case 25: Require(held); return flag(7);
                case 22: held = flag(8); return held;
                case 24: held = true; return 1;
                case 26: Require(held); credential = cached; return 1;
                case 27: held = false; return 1;
                case 44: Require(!held); return flag(9);
                case 45: Require(!held); credential = "private-file"; return flag(10);
                case 47: Require(!held); credential = "rotating-cookie"; return flag(11);
                case 49: Require(!held); cached = credential; return 1;
                case 12: credential = "inline"; return 1;
                case 5: case 9: case 23: case 42: case 46: case 48:
                    throw std::runtime_error("credential rejection " + std::to_string(step));
                default: return 1;
                }
            };
            try {
                if (reference) {
                    const auto source = ReferenceStore(58,action);
                    if (!source) {
                        action(20);
                        const auto cached_result = ReferenceStore(57,[&](uint32_t s) { return action(20+s); });
                        action(27);
                        if (!cached_result) ReferenceStore(59,[&](uint32_t s) { return action(40+s); });
                    }
                    status = 1;
                } else {
                    status = hs::ParentReplayStore(hs::ReplayStoreFlow::RPC_CREDENTIALS_COMPOSED,action);
                }
            } catch (const std::logic_error& e) { error = std::string("logic:") + e.what(); }
            catch (const std::runtime_error& e) { error = std::string("runtime:") + e.what(); }
            return std::tuple{status,trace,credential,cached,error,held};
        };
        const auto expected = run(true,-1);
        if (run(false,-1) != expected)
            throw std::runtime_error("credential state mismatch " + std::to_string(flags));
        for (int fault = 0; fault < int(std::get<1>(expected).size()); ++fault) {
            if (run(false,fault) != run(true,fault))
                throw std::runtime_error("credential fault mismatch " + std::to_string(flags) + ":" + std::to_string(fault));
        }
    }
    const std::vector<int64_t> values{INT64_MIN,-1000001,-1,0,1,999999,1000000,1000001,INT64_MAX};
    for (bool budget : {false,true}) for (bool warm : {false,true})
    for (int64_t remaining : values) for (int64_t configured : values) {
        const auto run = [&](bool reference, int fault) {
            std::vector<uint32_t> trace;
            std::string error;
            uint32_t status{0};
            int64_t selected{remaining};
            const auto seconds = remaining / 1000000 + (remaining % 1000000 > 0);
            const auto action = [&](uint32_t step) -> int64_t {
                trace.push_back(step);
                if (int(trace.size()) == fault+1) throw std::logic_error("timeout fault");
                switch (step) {
                case 1: return budget;
                case 6: return warm;
                case 3: case 8: return reference ? remaining>0 : remaining;
                case 11: return reference ? configured>0 : configured;
                case 12: return reference ? configured<seconds : seconds;
                case 13: selected = configured; return 1;
                case 4: case 9: throw std::runtime_error("expired " + std::to_string(step));
                default: return 1;
                }
            };
            try {
                status = reference ? ReferenceStore(56,action) :
                    hs::ParentReplayStore(hs::ReplayStoreFlow::RPC_TIMEOUT_COMPOSED,action);
            } catch (const std::logic_error& e) { error = std::string("logic:") + e.what(); }
            catch (const std::runtime_error& e) { error = std::string("runtime:") + e.what(); }
            return std::tuple{status,trace,selected,error};
        };
        const auto expected = run(true,-1);
        Require(run(false,-1) == expected);
        for (int fault = 0; fault < int(std::get<1>(expected).size()); ++fault)
            Require(run(false,fault) == run(true,fault));
    }
    std::cout << "RPC preparation: 4096 credential states and 324 signed timeout scenarios, every callback fault passed\n";
}

static void CheckRpcCall()
{
    static_assert(static_cast<uint32_t>(hs::ReplayStoreFlow::RPC_CALL) == 331);
    static_assert(static_cast<uint32_t>(hs::ReplayStoreFlow::RPC_CALL_CHECKED) == 332);
    struct AuthFailure : std::runtime_error { using std::runtime_error::runtime_error; };
    for (unsigned flags=0;flags<64;++flags) for (unsigned first=0;first<4;++first)
    for (unsigned second=0;second<4;++second) {
        const bool budget=flags&1, circuit=flags&2, password=flags&4,
            checked=flags&8, reply_error=flags&16, missing=flags&32;
        const auto run = [&](bool reference,int fault) {
            std::vector<uint32_t> trace;
            std::string error, published;
            unsigned attempts{0}, available{0}, unavailable{0}, invalidated{0};
            std::exception_ptr failure;
            const auto action = [&](uint32_t step) -> int64_t {
                trace.push_back(step);
                if (step!=10 && int(trace.size())==fault+1) throw std::logic_error("RPC effect fault");
                switch (step) {
                case 1: case 23: return budget;
                case 2: return circuit;
                case 3: throw std::runtime_error("circuit open");
                case 10: {
                    const auto attempt = [&]() -> int64_t {
                        if (int(trace.size())==fault+1) throw std::logic_error("RPC effect fault");
                        Require(attempts<2);
                        const unsigned outcome = attempts++==0 ? first : second;
                        const std::string message = "request " + std::to_string(attempts);
                        if (outcome==1) throw AuthFailure(message);
                        if (outcome==2) throw std::runtime_error(message);
                        if (outcome==3) throw std::logic_error(message);
                        ++available;
                        return 0;
                    };
                    if (reference) return attempt();
                    try { return attempt(); }
                    catch (const AuthFailure&) { failure=std::current_exception(); return 1; }
                    catch (...) { failure=std::current_exception(); return 2; }
                }
                case 12: ++unavailable; return 1;
                case 13: Require(bool(failure)); std::rethrow_exception(failure);
                case 21: return !password;
                case 22: ++invalidated; return 1;
                case 31: return !reply_error;
                case 32: throw std::runtime_error("reply error");
                case 33: return missing;
                case 34: throw std::runtime_error("missing result");
                default: throw std::logic_error("unexpected RPC effect");
                }
            };
            try {
                if (reference) {
                    ReferenceStore(26,action);
                    const auto reject = [&]() {
                        failure=std::current_exception();
                        action(12);
                        action(13);
                    };
                    try { action(10); }
                    catch (const AuthFailure&) {
                        if (ReferenceStore(55,[&](uint32_t step) { return action(step+20); })) {
                            try { action(10); } catch (...) { reject(); }
                        } else reject();
                    } catch (...) { reject(); }
                    if (checked) ReferenceStore(54,[&](uint32_t step) { return action(step+30); });
                } else {
                    hs::ParentReplayStore(checked ? hs::ReplayStoreFlow::RPC_CALL_CHECKED :
                        hs::ReplayStoreFlow::RPC_CALL,action);
                }
                published=checked ? "result" : "raw reply";
            } catch (const AuthFailure& ex) { error=std::string("auth:")+ex.what(); }
            catch (const std::logic_error& ex) { error=std::string("logic:")+ex.what(); }
            catch (const std::runtime_error& ex) { error=std::string("runtime:")+ex.what(); }
            return std::tuple{trace,error,published,attempts,available,unavailable,invalidated};
        };
        const auto expected=run(true,-1);
        Require(run(false,-1)==expected);
        for (int fault=0;fault<int(std::get<0>(expected).size());++fault) {
            Require(run(false,fault)==run(true,fault));
        }
    }
    for (int64_t bad : {INT64_MIN,int64_t{-1},int64_t{3},int64_t{UINT32_MAX}+1,INT64_MAX}) {
        std::vector<uint32_t> trace;
        bool rejected{false};
        try { hs::ParentReplayStore(hs::ReplayStoreFlow::RPC_CALL_CHECKED,[&](uint32_t step) {
            trace.push_back(step); return step==10 ? bad : int64_t{0};
        }); } catch (const std::runtime_error&) { rejected=true; }
        Require(rejected && trace==std::vector<uint32_t>({1,10}));
    }
    std::cout << "RPC lifecycle: 1024 states, retained native exception types, retry bounds, effect faults and publication passed\n";
}

static void CheckReplayCacheInitialization()
{
    static_assert(static_cast<uint32_t>(hs::ReplayStoreFlow::CACHE_INITIALIZE) == 333);
    using Facts = std::map<uint32_t,int64_t>;
    const Facts base{{8,10},{9,5},{11,10},{12,5},{14,10},{15,5},
        {27,5},{28,10},{29,5},{30,10},{31,5},{32,10},
        {204,0},{205,0},{206,1},{209,100},{210,0},{211,0},{212,0},
        {213,0},{214,0},{215,100},{216,0},{217,0},{225,50},{226,60},
        {326,1},{327,1}};
    std::vector<Facts> fixtures;
    for (unsigned flags=0;flags<128;++flags) for (int status=0;status<4;++status) {
        auto values=base;
        values[206]=status;
        values[201]=bool(flags&1);
        values[204]=bool(flags&2);
        values[205]=bool(flags&4);
        values[210]=bool(flags&8);
        values[212]=bool(flags&16);
        values[216]=bool(flags&32);
        values[301]=bool(flags&64);
        fixtures.push_back(std::move(values));
    }
    for (unsigned route=0;route<3;++route) {
        auto values=base;
        values[204]=route!=0;
        values[301]=route==1;
        // Reach both the loaded-state consistency branches and both CTIP encodings.
        values[210]=values[212]=values[216]=1;
        fixtures.push_back(values);
        for (uint32_t step : {1,2,3,4,5,6,7,17,18,20,21,23,24,25,201,204,205,
                              210,211,212,213,214,216,217,301,305,306,312,313,314,
                              319,323,326,327,330,335,341,342,346,714}) {
            auto changed=values;
            changed[step]=!changed.contains(step) || changed[step]!=0 ? 0 : 1;
            fixtures.push_back(std::move(changed));
        }
        for (uint32_t step : {8,9,11,12,14,15,27,28,29,30,31,32,209,215,225,226})
        for (int64_t value : {int64_t{0},int64_t{5},int64_t{10},int64_t{UINT32_MAX}}) {
            auto changed=values;
            changed[step]=value;
            fixtures.push_back(std::move(changed));
        }
    }
    const auto run = [&](const Facts& facts,bool reference,int fault,unsigned* entries=nullptr) {
        if (entries) *entries=0;
        const auto store = [&](uint32_t kind,const std::function<int64_t(uint32_t)>& effect) {
            if (entries) ++*entries;
            return ReferenceStore(kind,effect);
        };
        std::vector<uint32_t> trace, mutations;
        std::string error;
        uint32_t status{99}, slot{0}, preimage_slot{0};
        bool loaded{false}, identity{false}, preimage{false};
        const auto action = [&](uint32_t step) -> int64_t {
            trace.push_back(step);
            if (int(trace.size())==fault+1) throw std::logic_error("cache effect fault");
            if (step==200) loaded=true;
            if (step==250) loaded=false;
            if (step==603) identity=true;
            if (step==639) identity=false;
            if (step==700) preimage=true;
            if (step==719) preimage=false;
            if (step==310) slot=0;
            if (step==331) ++slot;
            if (step==706) preimage_slot=0;
            if (step==718) ++preimage_slot;
            if (step>=101) mutations.push_back(step);
            if (step==311) return slot<2;
            if (step==707) return preimage_slot<2;
            if (step==222) return facts.at(206)==2;
            if (step==223) return facts.at(206)==3;
            if (step==19 || step==22 || step==26 || step==308 || step==316 ||
                step==321 || step==329 || step==336 || step==339 || step==344) return 0;
            const auto found=facts.find(step);
            return found==facts.end() ? 1 : found->second;
        };
        try {
            if (!reference) {
                if (entries) ++*entries;
                status=hs::ParentReplayStore(hs::ReplayStoreFlow::CACHE_INITIALIZE,action);
            } else {
                const auto preflight=store(15,[&](uint32_t step) -> int64_t {
                    if (step==8 || step==9 || step==11 || step==12 || step==14 || step==15) {
                        if (entries) ++*entries;
                        return action(step)>0;
                    }
                    if (step==10 || step==13 || step==16) {
                        if (entries) ++*entries;
                        const uint32_t offset=step==10 ? 27 : step==13 ? 29 : 31;
                        const auto first=action(offset);
                        return first<action(offset+1);
                    }
                    return action(step);
                });
                if (preflight!=1) status=preflight==0;
                else {
                    store(13,[&](uint32_t step) { return action(100+step); });
                    action(200);
                    const auto found=store(16,[&](uint32_t step) -> int64_t {
                        if (step==3) {
                            store(12,[&](uint32_t field) { return action(600+field); });
                            return action(639);
                        }
                        if (step==9) {
                            if (entries) ++*entries;
                            const auto checkpoint=action(225);
                            return checkpoint<=action(209);
                        }
                        if (step==15) {
                            if (entries) ++*entries;
                            const auto height=action(215);
                            return height<action(226);
                        }
                        return action(200+step);
                    });
                    action(250);
                    if (found) status=1;
                    else status=store(18,[&](uint32_t step) -> int64_t {
                        if (step==4) {
                            action(700);
                            store(17,[&](uint32_t field) { return action(700+field); });
                            return action(719);
                        }
                        return action(300+step);
                    });
                }
            }
        } catch (const std::logic_error& ex) { error=std::string("logic:")+ex.what(); }
        catch (const std::runtime_error&) { error="runtime"; }
        return std::tuple{status,trace,mutations,error,loaded,identity,preimage};
    };
    for (const auto& facts : fixtures) {
        const auto expected=run(facts,true,-1);
        Require(run(facts,false,-1)==expected);
        for (int fault=0;fault<int(std::get<1>(expected).size());++fault)
            Require(run(facts,false,fault)==run(facts,true,fault));
    }
    for (int64_t bad : {INT64_MIN,int64_t{-1},int64_t{UINT32_MAX}+1,INT64_MAX}) {
        auto facts=base;
        facts[8]=bad;
        const auto result=run(facts,false,-1);
        Require(std::get<3>(result)=="runtime" &&
            std::get<1>(result)==std::vector<uint32_t>({1,2,3,4,5,6,7,8}));
    }
    for (uint32_t step : {200,639,250,700,719}) {
        auto facts=base;
        facts[204]=1;
        const auto complete=std::get<1>(run(facts,false,-1));
        const auto end=std::find(complete.begin(),complete.end(),step);
        Require(end!=complete.end());
        facts[step]=0;
        const auto result=run(facts,false,-1);
        Require(std::get<3>(result)=="runtime" &&
            std::get<1>(result)==std::vector<uint32_t>(complete.begin(),end+1));
    }
    for (bool rebuild : {false,true}) {
        auto facts=base;
        facts[204]=rebuild;
        unsigned old_entries{0}, new_entries{0};
        Require(run(facts,true,-1,&old_entries)==run(facts,false,-1,&new_entries));
        Require(old_entries==(rebuild ? 15U : 14U) && new_entries==1);
    }
    std::cout << "Replay cache: " << fixtures.size()
        << " legacy state comparisons, every effect fault, scoped cleanup and invalid fields passed\n";
}

static void CheckAuthFile()
{
    const std::vector<std::string> records{"","u:p","u:p\r\n","__cookie__:"+std::string(64,'a'),
        "\n\n",std::string(4096,'a'),std::string(4097,'a'),"u:read-failure"};
    for (uint32_t flags=0;flags<256;++flags) for (uint32_t mode=0;mode<3;++mode)
    for (size_t record_index=0;record_index<records.size();++record_index) {
        const auto run = [&](bool reference,int fault) {
            using Event=std::tuple<uint32_t,uint64_t,uint64_t>;
            std::vector<Event> trace;
            std::string record,error;
            std::array<char,4097> bytes{};
            bool opened{false},closed{false},accepted{false};
            unsigned reads{0};
            const auto flag = [&](uint32_t bit) { return bool(flags&bit); };
            const auto effect = [&](uint32_t step,uint64_t index,std::span<const unsigned char> input) {
                const uint64_t available=input.empty() ? 0 : ReadLE64(input.data());
                trace.emplace_back(step,index,available);
                if (int(trace.size())==fault+1) throw std::logic_error("auth file effect fault");
                if (step==50) return std::vector<unsigned char>(record.begin(),record.end());
                const auto scalar = [&]() -> uint64_t {
                    switch (step) {
                    case 1: return flag(1);
                    case 3: return flag(128);
                    case 4: opened=flag(2); return opened;
                    case 31: return flag(4);
                    case 38: case 14: return flag(8);
                    case 33: return 100;
                    case 34: return flag(16) ? 100 : 101;
                    case 36: return flag(32) ? 0 : 16;
                    case 9: closed=true; return 1;
                    case 11: Require(index<=bytes.size()); record.assign(bytes.data(),index); return 1;
                    case 12: return flag(64);
                    case 13: return flag(2);
                    case 16: opened=flag(4); return opened;
                    case 18: record=records[record_index].substr(0,4097); return 1;
                    case 19: return record_index==7;
                    case 20: return record.size();
                    case 23: case 25: return record.empty() ? 256 : static_cast<unsigned char>(record.back());
                    case 24: case 26: record.pop_back(); return 1;
                    case 40: {
                        Require(input.size()==8 && index<=bytes.size() && available==bytes.size()-index);
                        if (record_index==3 && reads++==0) return UINT64_MAX;
                        if (record_index==7) return UINT64_MAX-1;
                        const auto& source=records[record_index];
                        Require(index<=source.size());
                        const auto count=std::min<uint64_t>(available,
                            std::min<uint64_t>(source.size()-index,index==0 ? 2 : 4097));
                        std::copy_n(source.data()+index,count,bytes.data()+index);
                        return count;
                    }
                    case 22: case 60: record.clear(); break;
                    case 8: case 32: case 35: case 37: closed=true; break;
                    case 2: case 5: case 10: case 15: case 17: break;
                    default: throw std::logic_error("unexpected auth file effect");
                    }
                    error=std::to_string(step);
                    return 1;
                };
                std::vector<unsigned char> output(8);
                WriteLE64(output.data(),scalar());
                return output;
            };
            const auto scalar = [&](uint32_t step,uint64_t index=0) {
                const auto bytes=effect(step,index,{});
                Require(bytes.size()==8);
                return ReadLE64(bytes.data());
            };
            try {
                if (reference) {
                    uint64_t used{0};
                    uint32_t read_status{0};
                    const auto file=ReferenceStore(196,[&](uint32_t step) -> uint32_t {
                        switch (step) {
                        case 6: return hs::AdmitPrivateCredentialFile([&](uint32_t action) -> int64_t {
                            if (action==1) return hs::ParentReplayAll<2>({
                                [&] { return scalar(31); }, [&] { return scalar(38); }});
                            return scalar(action+30);
                        });
                        case 7:
                            read_status=hs::ReadCredentialBytes(4097,[&](uint64_t offset,uint64_t available) {
                                std::array<unsigned char,8> request;
                                WriteLE64(request.data(),available);
                                return ReadLE64(effect(40,offset,request).data());
                            },used);
                            return read_status;
                        case 9: scalar(9); return read_status;
                        case 11: return scalar(11,used);
                        default: return scalar(step);
                        }
                    });
                    accepted=mode==0 ? file : ReferenceStore(273,[&](uint32_t step) -> uint32_t {
                        if (step==1) return file;
                        if (step==2) {
                            const auto bytes=effect(50,0,{});
                            return hs::IsRpcCredentialRecord(std::string(bytes.begin(),bytes.end()),mode==2);
                        }
                        return scalar(60);
                    });
                } else accepted=hs::ReadAuthFile(static_cast<hs::AuthFileMode>(mode),effect);
            } catch (const std::logic_error& ex) { error=std::string("logic:")+ex.what(); }
            catch (const std::runtime_error& ex) { error=std::string("runtime:")+ex.what(); }
            // The native descriptor guard closes on both normal and exceptional exit.
            if (opened) closed=true;
            return std::tuple{accepted,trace,record,error,closed};
        };
        const auto expected=run(true,-1);
        if (run(false,-1)!=expected) throw std::runtime_error("auth file state mismatch");
        for (int fault=0;fault<int(std::get<1>(expected).size());++fault)
            if (run(false,fault)!=run(true,fault)) throw std::runtime_error("auth file fault mismatch");
    }
    for (uint32_t mode : {3U,UINT32_MAX}) {
        bool called{false},rejected{false};
        try { hs::ReadAuthFile(static_cast<hs::AuthFileMode>(mode),[&](auto,auto,auto) {
            called=true; return std::vector<unsigned char>{};
        }); } catch (const std::runtime_error&) { rejected=true; }
        Require(rejected && !called);
    }
    for (size_t size : {0U,1U,7U,9U}) {
        unsigned calls{0};
        bool rejected{false};
        try { hs::ReadAuthFile(hs::AuthFileMode::RAW,[&](auto,auto,auto) {
            ++calls; return std::vector<unsigned char>(size);
        }); } catch (const std::runtime_error&) { rejected=true; }
        Require(rejected && calls==1);
    }
    std::cout << "Auth file: 6144 legacy state comparisons, every effect fault, read bounds and invalid requests passed\n";
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
    struct State {
        uint32_t calls, expected;
        std::thread::id thread;
    } state{0, expected, std::this_thread::get_id()};
    const auto read = +[](void* context, uint32_t step, int64_t* fields) -> int32_t {
        auto& state = *static_cast<State*>(context);
        if (std::this_thread::get_id() != state.thread) return -1;
        const uint32_t call = state.calls++;
        const uint32_t expected_step = state.expected == 11 && call == 8 ? 9 : state.expected == 11 && call == 9 ? 8 : call;
        if (step != expected_step) return -1;
        if (!std::all_of(fields, fields + 4, [](int64_t value) { return value == 0; })) return -1;
        // The synchronous callback may reenter a different Haskell domain.
        if (!hs::HasDepositDepth(10, 15, 6)) return -1;
        std::fill_n(fields, 4, step == 9 ? 65 : 1);
        return 1;
    };
    std::string error;
    return hs::LiveEvidence(phase, read, &state, {}, error) && state.calls == expected;
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

static void CheckBmmHeaderPolicy()
{
    for (const bool checking : {false, true}) for (const bool private_mode : {false, true})
    for (const bool present : {false, true}) for (const int64_t activation : {-1, 99, 100, INT32_MAX})
    for (const uint32_t flags : {0U, 1U, 2U, 3U}) for (const uint32_t facts : {0U, 17U, 6U, 2U, 18U, 50U, 146U}) {
        const auto mode = checking ? hs::ReplayStoreWorkflow::BMM_HEADER_POLICY : hs::ReplayStoreWorkflow::BMM_PROOF_REQUIRED;
        std::vector<uint32_t> trace;
        std::string expected_error, actual_error, expected_exception, actual_exception;
        int expected = -1, actual = -1;
        const auto required = [&] {
            if (hs::BmmActivation(0, flags) != 2) return 0;
            return private_mode ? hs::BmmActivation(1, present, 98, activation) : hs::BmmActivation(2, 1);
        };
        try {
            if (!checking) expected = required();
            else {
                int code = hs::BmmHeader(facts, expected_error);
                if (code == 6) code = hs::BmmHeader(facts | (required() << 6) | 256, expected_error);
                expected = code == 0;
            }
        } catch (const std::runtime_error& e) { expected_exception = e.what(); }
        const auto native = [&](uint32_t step, uint64_t index, std::span<const unsigned char> input) {
            trace.push_back(step);
            Require(index == 0 && (input.empty() || step == 0 || step == 11));
            if (step == 0) throw std::runtime_error(std::string(input.begin(), input.end()));
            std::vector<unsigned char> bytes(step == 3 ? 24 : 8);
            switch (step) {
            case 1: WriteLE64(bytes.data(), flags); break;
            case 2: WriteLE64(bytes.data(), private_mode); break;
            case 3:
                WriteLE64(bytes.data(), present); WriteLE64(bytes.data()+8, 98);
                WriteLE64(bytes.data()+16, activation); break;
            case 4: WriteLE64(bytes.data(), 1); break;
            case 10: WriteLE64(bytes.data(), facts); break;
            case 11: actual_error.assign(input.begin(), input.end()); WriteLE64(bytes.data(), 1); break;
            default: throw std::runtime_error("unexpected header policy callback");
            }
            return bytes;
        };
        try { actual = hs::RunReplayStore(mode, native); }
        catch (const std::runtime_error& e) { actual_exception = e.what(); }
        Require(expected == actual && expected_error == actual_error && expected_exception == actual_exception);
        const auto complete_trace = trace;
        for (size_t fault = 0; fault < complete_trace.size(); ++fault) {
            trace.clear();
            bool caught = false;
            try {
                hs::RunReplayStore(mode, [&](uint32_t step, uint64_t index, std::span<const unsigned char> input) {
                    if (trace.size() == fault) { trace.push_back(step); throw std::runtime_error("header native fault"); }
                    return native(step, index, input);
                });
            } catch (const std::runtime_error& e) { caught = std::string(e.what()) == "header native fault"; }
            Require(caught && trace == std::vector<uint32_t>(complete_trace.begin(), complete_trace.begin()+fault+1));
        }
    }
}


int main()
{
    CheckBmmHeaderPolicy();
    try {
        struct sigaction handler{}, before{}, after{};
        handler.sa_handler = SignalHandler;
        sigemptyset(&handler.sa_mask);
        Require(sigaction(SIGINT, &handler, nullptr) == 0);
        Require(sigaction(SIGINT, nullptr, &before) == 0);
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
        Require(sigaction(SIGINT, nullptr, &after) == 0);
        Require(before.sa_handler == after.sa_handler);
        CheckStatusAdapters();
        CheckOptionalEnvironment();
        CheckStoreRunner();
        CheckPredicateRunner();
        CheckBmmStateRunner();
        CheckBmmProofRunner();
        CheckPegReadRunner();
        CheckParentPrelude();
        CheckParentBlock();
        CheckDepositConstruction();
        CheckDeterministicParsing();
        CheckDepositClaims();
        CheckNativeDeposits();
        CheckParentHeaders();
        CheckRpcPreparation();
        CheckRpcCall();
        CheckAuthFile();
        CheckReplayCacheInitialization();

        for (int failure = -1; failure < 18; ++failure) {
            std::vector<uint32_t> seen;
            unsigned int crossings{0};
            bool caught{false};
            const std::vector<uint32_t> expected{0,1,2,100,101,102,200,201,202,203,204,205,206,207,208,209,210,3};
            try {
                Require(hs::RunBitcoinSignature(hs::BitcoinSignatureWorkflow::PARENT,0,true,0,1,1,
                    std::array<unsigned char,3>{42,43,1},
                    [&](uint32_t step,uint64_t value,std::span<const unsigned char> bytes) -> std::vector<unsigned char> {
                        ++crossings;
                        const auto effect = [&](uint32_t action) {
                            seen.push_back(action);
                            if (static_cast<int>(seen.size()) == failure+1) throw std::logic_error("signature native effect failed");
                        };
                        if (step == 4) {
                            for (const auto action : bytes) effect(action);
                            return {};
                        }
                        effect(step);
                        if (step == 2) Require(value == 1 && bytes.size() == 2 && bytes[0] == 42 && bytes[1] == 43);
                        return step == 0 || step == 1 || step == 3 ? std::vector<unsigned char>{1} : std::vector<unsigned char>{};
                    }));
            } catch (const std::logic_error& error) {
                caught = std::string(error.what()) == "signature native effect failed";
            }
            Require(caught == (failure >= 0));
            Require(seen == std::vector<uint32_t>(expected.begin(),failure < 0 ? expected.end() : expected.begin()+failure+1));
            Require(crossings == (failure < 0 || failure == 17 ? 5U : failure < 3 ? failure+1U : 4U));
        }

        for (bool publication : {false,true}) {
            const std::vector<std::pair<uint32_t,uint64_t>> expected = publication ?
                std::vector<std::pair<uint32_t,uint64_t>>{{10,0},{11,0},{12,0},{13,0},{21,0},{27,0}} :
                std::vector<std::pair<uint32_t,uint64_t>>{{0,0},{1,24},{2,24},{1,0},{2,0},{3,0},{4,0},{3,24},{4,24}};
            for (int fault = -1; fault < static_cast<int>(expected.size()); ++fault) {
                std::vector<std::pair<uint32_t,uint64_t>> seen;
                bool caught{false};
                try {
                    Require(hs::MaintainParentReplay(publication ? hs::ReplayMaintenance::AFTER_TREASURY :
                        hs::ReplayMaintenance::BEFORE_TREASURY,100,{10,5,20,15},12,15,
                        [&](uint32_t step,uint64_t slot,std::span<const unsigned char> payload) -> std::vector<unsigned char> {
                            seen.emplace_back(step,slot);
                            if (static_cast<int>(seen.size()) == fault+1) throw std::logic_error("maintenance effect failed");
                            if (step == 0) return {24,1,0,1};
                            if (step == 1) return std::vector<unsigned char>(8,0);
                            if (step == 3) return std::vector<unsigned char>(4,0);
                            if (step == 10) return {5,0,9,1};
                            if (step == 21 || step == 27) return {0};
                            if (step == 11) Require(payload.size() == 1 && payload[0] == 5);
                            if (step == 2 || step == 4) Require(payload.size() == 8 && ReadLE64(payload.data()) == 0);
                            return {};
                        }) == 0);
                } catch (const std::logic_error& error) {
                    caught = std::string(error.what()) == "maintenance effect failed";
                }
                Require(caught == (fault >= 0));
                Require(seen == std::vector<std::pair<uint32_t,uint64_t>>(expected.begin(),
                    fault < 0 ? expected.end() : expected.begin()+fault+1));
            }
        }

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
        uint32_t live_calls = 0;
        const auto throwing_fields = +[](void* context, uint32_t, int64_t*) -> int32_t {
            ++*static_cast<uint32_t*>(context);
            throw std::logic_error("live evidence callback failure");
        };
        try { hs::LiveEvidence(hs::LiveEvidencePhase::NETWORK, throwing_fields, &live_calls, {}, error); }
        catch (const std::logic_error& failure) { fault = std::string{failure.what()} == "live evidence callback failure"; }
        Require(fault && live_calls == 1);
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
