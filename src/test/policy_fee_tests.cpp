// Copyright (c) 2020-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/haskell_reference.h>
#include <consensus/amount.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <crypto/sha256.h>
#include <haskell/bridge.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <limits>
#include <set>
#include <vector>

namespace drivechain::haskell {
uint64_t BmmWorkBudget(uint64_t count, const std::function<uint64_t(uint32_t,uint64_t,uint64_t)>& read)
{
    uint64_t result{0};
    ReferenceCheckedStatus(ReferenceReadScalarAdmission(elements_hs_bmm_work_budget_v1,read,count,&result),
        0,"Haskell work budget evaluation failed");
    return result;
}

bool BmmWorkTotal(bool saturate, uint64_t count, const std::function<uint64_t(uint64_t)>& read, uint64_t& total)
{
    return ReferenceCheckedStatus(ReferenceReadScalarAdmission(elements_hs_bmm_work_total_v1,
        [&](uint32_t, uint64_t index, uint64_t) { return read(index); },
        static_cast<uint32_t>(saturate),count,total,&total),1,"Haskell work total evaluation failed") == 0;
}
}

BOOST_AUTO_TEST_SUITE(policy_fee_tests)






BOOST_AUTO_TEST_CASE(FeeRounder)
{
    FastRandomContext rng{/*fDeterministic=*/true};
    FeeFilterRounder fee_rounder{CFeeRate{1000}, rng};

    // check that 1000 rounds to 974 or 1071
    std::set<CAmount> results;
    while (results.size() < 2) {
        results.emplace(fee_rounder.round(1000));
    }
    BOOST_CHECK_EQUAL(*results.begin(), 974);
    BOOST_CHECK_EQUAL(*++results.begin(), 1071);

    // check that negative amounts rounds to 0
    BOOST_CHECK_EQUAL(fee_rounder.round(-0), 0);
    BOOST_CHECK_EQUAL(fee_rounder.round(-1), 0);

    // check that MAX_MONEY rounds to 9170997
    BOOST_CHECK_EQUAL(fee_rounder.round(MAX_MONEY), 9170997);
}

BOOST_AUTO_TEST_CASE(bmm_work_fee_quote)
{
    BmmWorkFeeQuote quote;
    BOOST_REQUIRE(CalculateBmmWorkFeeQuote(20'000, 1'500'000, 1'000, 500, quote));
    BOOST_CHECK_EQUAL(quote.verification_fee, 1'500);
    BOOST_CHECK_EQUAL(quote.producer_reserve, 500);
    BOOST_CHECK_EQUAL(quote.bid, 18'000);

    BOOST_REQUIRE(CalculateBmmWorkFeeQuote(10, 1, 1, 0, quote));
    BOOST_CHECK_EQUAL(quote.verification_fee, 1);
    BOOST_CHECK_EQUAL(quote.bid, 9);

    BOOST_CHECK(!CalculateBmmWorkFeeQuote(1'000, 2'000'000, 1'000, 0, quote));
    BOOST_CHECK(!CalculateBmmWorkFeeQuote(-1, 0, 0, 0, quote));
    BOOST_CHECK(!CalculateBmmWorkFeeQuote(
        MAX_MONEY,
        std::numeric_limits<uint64_t>::max(),
        MAX_MONEY,
        0,
        quote));
}

BOOST_AUTO_TEST_CASE(bmm_work_fee_quote_legacy_parity)
{
    // Frozen pre-migration rule, including partial results on insufficient funds.
    const auto legacy = [](CAmount fees, uint64_t work, CAmount rate, CAmount reserve, BmmWorkFeeQuote& quote) {
        quote = {};
        if (!MoneyRange(fees) || !MoneyRange(rate) || !MoneyRange(reserve)) return false;
        const uint64_t unsigned_rate = static_cast<uint64_t>(rate);
        if (unsigned_rate && work > (UINT64_MAX - 999999) / unsigned_rate) return false;
        const uint64_t priced = (work * unsigned_rate + 999999) / 1000000;
        if (priced > static_cast<uint64_t>(MAX_MONEY)) return false;
        quote.verification_fee = priced;
        quote.producer_reserve = reserve;
        if (quote.verification_fee > fees || reserve > fees - quote.verification_fee) return false;
        quote.bid = fees - quote.verification_fee - reserve;
        return MoneyRange(quote.bid);
    };
    FastRandomContext rng{/*fDeterministic=*/true};
    const std::array<CAmount,9> amounts{INT64_MIN,-1,0,1,1000,MAX_MONEY-1,MAX_MONEY,MAX_MONEY+1,INT64_MAX};
    const std::array<uint64_t,7> weights{0,1,999999,1000000,1000001,UINT64_MAX-999999,UINT64_MAX};
    const auto check = [&](CAmount fees, uint64_t work, CAmount rate, CAmount reserve) {
        BmmWorkFeeQuote expected{17,18,19}, actual{17,18,19};
        const bool accepted = legacy(fees,work,rate,reserve,expected);
        BOOST_CHECK_EQUAL(CalculateBmmWorkFeeQuote(fees,work,rate,reserve,actual),accepted);
        BOOST_CHECK_EQUAL(actual.verification_fee,expected.verification_fee);
        BOOST_CHECK_EQUAL(actual.producer_reserve,expected.producer_reserve);
        BOOST_CHECK_EQUAL(actual.bid,expected.bid);
        std::array<int64_t,3> display{17,18,19};
        BOOST_CHECK_EQUAL(drivechain::haskell::BmmWorkQuoteDisplay(fees,work,rate,reserve,display),accepted && expected.bid>0);
        BOOST_CHECK_EQUAL(display[0],accepted ? expected.verification_fee : 0);
        BOOST_CHECK_EQUAL(display[1],accepted ? expected.producer_reserve : 0);
        BOOST_CHECK_EQUAL(display[2],accepted ? expected.bid : 0);
        // The producer must stop at the quote gate, before submission or proof
        // acquisition, for every unfunded or zero-bid boundary above.
        std::vector<uint32_t> stages;
        std::array<int64_t,3> production{17,18,19};
        const bool produced = drivechain::haskell::BmmProduction(true, [&](uint32_t stage) {
            stages.push_back(stage);
            if (stage == 16) return drivechain::haskell::BmmWorkQuoteDisplay(fees,work,rate,reserve,production);
            if (stage == 10) {
                BOOST_CHECK_EQUAL(production[0], expected.verification_fee);
                BOOST_CHECK_EQUAL(production[1], expected.producer_reserve);
                BOOST_CHECK_EQUAL(production[2], expected.bid);
            }
            return true;
        });
        BOOST_CHECK_EQUAL(produced, accepted && expected.bid > 0);
        const std::vector<uint32_t> expected_stages = produced ?
            std::vector<uint32_t>{1,19,2,20,3,15,4,5,6,16,7,8,9,17,10,18,11,12,13,14} :
            std::vector<uint32_t>{1,19,2,20,3,15,4,5,6,16,116};
        BOOST_CHECK(stages == expected_stages);
    };
    for (const auto fees : amounts)
        for (const auto rate : amounts)
            for (const auto reserve : amounts)
                for (const auto work : weights) check(fees,work,rate,reserve);
    for (int i=0; i<10000; ++i) {
        const auto rate = static_cast<CAmount>(rng.randrange(MAX_MONEY+1));
        const auto boundary = rate ? (UINT64_MAX-999999)/rate : UINT64_MAX;
        check(static_cast<CAmount>(rng.randrange(MAX_MONEY+1)),rng.rand64(),rate,0);
        check(MAX_MONEY,boundary,rate,1);
        if (boundary != UINT64_MAX) check(MAX_MONEY,boundary+1,rate,1);
    }
}

BOOST_AUTO_TEST_CASE(simplicity_work_budget_legacy_parity)
{
    const auto legacy = [](const CTransaction& tx) {
        uint64_t total{0};
        for (const auto& witness : tx.witness.vtxinwit) {
            const auto& stack = witness.scriptWitness.stack;
            if (stack.size() < 4) continue;
            size_t control = stack.size()-1;
            if (!stack[control].empty() && stack[control][0] == 0x50) --control;
            if (control < 1 || stack[control].empty() ||
                (stack[control][0] & 0xfe) != 0xbe || stack[control-1].size() != 32) continue;
            const uint64_t budget = static_cast<uint64_t>(GetSerializeSize(stack)) + 50;
            if (budget > UINT64_MAX/1000 || total > UINT64_MAX-budget*1000) return UINT64_MAX;
            total += budget*1000;
        }
        return total;
    };
    FastRandomContext rng{/*fDeterministic=*/true};
    const std::array<size_t,7> sizes{0,1,31,32,33,252,253};
    const std::array<unsigned char,6> tags{0,0x50,0xbd,0xbe,0xbf,0xff};
    for (int trial=0; trial<5000; ++trial) {
        CMutableTransaction tx;
        tx.witness.vtxinwit.resize(rng.randrange(8));
        tx.vin.resize(tx.witness.vtxinwit.size());
        for (auto& witness : tx.witness.vtxinwit) {
            auto& stack = witness.scriptWitness.stack;
            stack.resize(rng.randrange(8));
            for (auto& item : stack) item.assign(sizes[rng.randrange(sizes.size())],tags[rng.randrange(tags.size())]);
        }
        const CTransaction immutable(tx);
        BOOST_CHECK_EQUAL(GetSimplicityValidationMilliweight(immutable),legacy(immutable));
    }
    // Callback failures must rethrow the original exception, not become saturation.
    BOOST_CHECK_EXCEPTION(drivechain::haskell::BmmWorkBudget(1,[](uint32_t, uint64_t, uint64_t) -> uint64_t {
        throw std::logic_error("work read fault");
    }), std::logic_error, [](const auto& error) { return std::string(error.what()) == "work read fault"; });
}

BOOST_AUTO_TEST_CASE(bmm_whole_candidate_measurement)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.witness.vtxinwit.resize(1);
    tx.witness.vtxinwit[0].scriptWitness.stack = {{0}, {0}, std::vector<unsigned char>(32), {0xbe}};
    const CTransaction immutable{tx};
    const auto work = uint64_t(GetSerializeSize(tx.witness.vtxinwit[0].scriptWitness.stack)+50)*1000;
    for (const bool saturate : {false, true}) {
        uint64_t total{UINT64_MAX-1}, last{0};
        std::vector<uint64_t> reads;
        const bool accepted = drivechain::haskell::MeasureWork(saturate, 3,
            [&](uint64_t index) -> const CTransaction& { reads.push_back(index); return immutable; }, total, &last);
        BOOST_CHECK_EQUAL(accepted, saturate);
        BOOST_CHECK_EQUAL(total, saturate ? UINT64_MAX : UINT64_MAX-1);
        BOOST_CHECK_EQUAL(last, work);
        BOOST_CHECK(reads == (saturate ? std::vector<uint64_t>{0,0,1,1,2,2} : std::vector<uint64_t>{0,0}));
    }
    uint64_t total{UINT64_MAX-1};
    BOOST_CHECK_EQUAL(GetSimplicityValidationMilliweight(immutable, &total), work);
    BOOST_CHECK_EQUAL(total, UINT64_MAX);
    total = 7;
    BOOST_CHECK_EXCEPTION(drivechain::haskell::MeasureWork(false, 3,
        [&](uint64_t index) -> const CTransaction& {
            if (index == 1) throw std::logic_error("whole candidate read fault");
            return immutable;
        }, total), std::logic_error, [](const auto& error) { return std::string(error.what()) == "whole candidate read fault"; });
    BOOST_CHECK_EQUAL(total, 7U);
    BOOST_CHECK(drivechain::haskell::MeasureWork(false, 0,
        [](uint64_t) -> const CTransaction& { throw std::logic_error("empty candidate read"); }, total));
    BOOST_CHECK_EQUAL(total, 7U);
}

BOOST_AUTO_TEST_CASE(bmm_work_total_modes)
{
    for (bool saturate : {false,true}) {
        uint64_t amount = UINT64_MAX-1;
        std::vector<uint64_t> seen;
        const bool accepted = drivechain::haskell::BmmWorkTotal(saturate,3,[&](uint64_t index) {
            seen.push_back(index);
            // The former production path nested a witness-budget entry here.
            BOOST_CHECK_EQUAL(drivechain::haskell::BmmWorkBudget(0,[](uint32_t,uint64_t,uint64_t) {
                throw std::logic_error("empty budget read"); return uint64_t{0};
            }),0U);
            return uint64_t{1};
        },amount);
        BOOST_CHECK_EQUAL(accepted,saturate);
        BOOST_CHECK_EQUAL(amount,UINT64_MAX);
        BOOST_CHECK_EQUAL(seen.size(),saturate ? 3U : 2U);
        for (size_t i=0; i<seen.size(); ++i) BOOST_CHECK_EQUAL(seen[i],i);
    }
    uint64_t amount{7};
    BOOST_CHECK_EXCEPTION(drivechain::haskell::BmmWorkTotal(false,3,[](uint64_t index) -> uint64_t {
        if (index == 1) throw std::logic_error("total read fault");
        return 1;
    },amount),std::logic_error,[](const auto& error) { return std::string(error.what()) == "total read fault"; });
    BOOST_CHECK_EQUAL(amount,7U);
    BOOST_CHECK(drivechain::haskell::BmmWorkTotal(false,0,[](uint64_t) -> uint64_t {
        throw std::logic_error("empty total read");
    },amount));
    BOOST_CHECK_EQUAL(amount,7U);
}

BOOST_AUTO_TEST_SUITE_END()
