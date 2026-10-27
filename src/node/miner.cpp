// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/miner.h>

#include <addresstype.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <common/args.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <deploymentstatus.h>
#include <drivechain_bmm.h>
#include <node/drivechain_withdrawal_bundle.h>
#include <pegins.h>
#include <logging.h>
#include <mainchainrpc.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <pow.h>
#include <primitives/transaction.h>
#include <util/moneystr.h>
#include <util/signalinterrupt.h>
#include <util/time.h>
#include <validation.h>

#include <dynafed.h>

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <haskell/bridge.h>
#include <utility>

namespace node {

bool AppendOpTrueBlockWitness(CBlockHeader& block)
{
    const CScript op_true(OP_TRUE);
    if (block.m_dynafed_params.m_current.m_signblockscript != GetScriptForDestination(WitnessV0ScriptHash(op_true))) return false;
    block.m_signblock_witness.stack.emplace_back(op_true.begin(), op_true.end());
    return true;
}

bool SearchBlockNonce(CBlock& block, uint64_t& max_tries, const Consensus::Params& consensus,
                      const util::SignalInterrupt& interrupt)
{
    while (max_tries > 0 && block.nNonce < std::numeric_limits<uint32_t>::max() &&
           !CheckProofOfWork(block.GetHash(), block.nBits, consensus) && !interrupt) {
        ++block.nNonce;
        --max_tries;
    }
    return max_tries != 0 && !interrupt;
}

namespace {
GlobalMutex g_current_drivechain_withdrawal_bundle_mutex;
uint256 g_current_drivechain_withdrawal_bundle_hash GUARDED_BY(g_current_drivechain_withdrawal_bundle_mutex);
std::optional<DrivechainWithdrawalBundleEnvelope> g_current_drivechain_withdrawal_bundle_envelope GUARDED_BY(g_current_drivechain_withdrawal_bundle_mutex);
bool g_drivechain_withdrawal_bundle_creation_in_progress GUARDED_BY(g_current_drivechain_withdrawal_bundle_mutex) = false;
} // namespace

uint256 GetCurrentDrivechainWithdrawalBundleHash()
{
    LOCK(g_current_drivechain_withdrawal_bundle_mutex);
    return g_current_drivechain_withdrawal_bundle_hash;
}

std::optional<DrivechainWithdrawalBundleEnvelope> GetCurrentDrivechainWithdrawalBundleEnvelope()
{
    LOCK(g_current_drivechain_withdrawal_bundle_mutex);
    return g_current_drivechain_withdrawal_bundle_envelope;
}

void RestoreCurrentDrivechainWithdrawalBundleHash(const uint256& bundle_hash)
{
    LOCK(g_current_drivechain_withdrawal_bundle_mutex);
    g_current_drivechain_withdrawal_bundle_hash = bundle_hash;
    g_current_drivechain_withdrawal_bundle_envelope.reset();
    g_drivechain_withdrawal_bundle_creation_in_progress = false;
}

bool TryBeginDrivechainWithdrawalBundleCreation(uint256& current_bundle_hash, bool& creation_in_progress)
{
    LOCK(g_current_drivechain_withdrawal_bundle_mutex);
    current_bundle_hash = g_current_drivechain_withdrawal_bundle_hash;
    creation_in_progress = g_drivechain_withdrawal_bundle_creation_in_progress;
    if (!drivechain::haskell::AdmitWithdrawalBundle(creation_in_progress,
            current_bundle_hash.begin(), current_bundle_hash.begin()).begin) {
        return false;
    }
    g_drivechain_withdrawal_bundle_creation_in_progress = true;
    return true;
}

void CompleteDrivechainWithdrawalBundleCreation(const uint256& bundle_hash)
{
    RestoreCurrentDrivechainWithdrawalBundleHash(bundle_hash);
}

void CompleteDrivechainWithdrawalBundleCreation(
    const uint256& bundle_hash,
    DrivechainWithdrawalBundleEnvelope envelope)
{
    LOCK(g_current_drivechain_withdrawal_bundle_mutex);
    g_current_drivechain_withdrawal_bundle_hash = bundle_hash;
    g_current_drivechain_withdrawal_bundle_envelope = std::move(envelope);
    g_drivechain_withdrawal_bundle_creation_in_progress = false;
}

void AbortDrivechainWithdrawalBundleCreation()
{
    LOCK(g_current_drivechain_withdrawal_bundle_mutex);
    g_drivechain_withdrawal_bundle_creation_in_progress = false;
}

bool ClearCurrentDrivechainWithdrawalBundleHash(const uint256& bundle_hash)
{
    LOCK(g_current_drivechain_withdrawal_bundle_mutex);
    if (!drivechain::haskell::AdmitWithdrawalBundle(g_drivechain_withdrawal_bundle_creation_in_progress,
            g_current_drivechain_withdrawal_bundle_hash.begin(), bundle_hash.begin()).clear) {
        return false;
    }
    g_current_drivechain_withdrawal_bundle_hash.SetNull();
    g_current_drivechain_withdrawal_bundle_envelope.reset();
    return true;
}

void ResetChallenge(CBlockHeader& block, const CBlockIndex& indexLast, const Consensus::Params& params)
{
    block.proof.challenge = indexLast.get_proof().challenge;
}

void ResetProof(CBlockHeader& block)
{
    block.proof.solution.clear();
}

int64_t GetMinimumTime(const CBlockIndex* pindexPrev, const int64_t difficulty_adjustment_interval)
{
    int64_t min_time{pindexPrev->GetMedianTimePast() + 1};
    // Height of block to be mined.
    const int height{pindexPrev->nHeight + 1};
    // Account for BIP94 timewarp rule on all networks. This makes future
    // activation safer.
    if (height % difficulty_adjustment_interval == 0) {
        min_time = std::max<int64_t>(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP);
    }
    return min_time;
}

int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime{std::max<int64_t>(GetMinimumTime(pindexPrev, consensusParams.DifficultyAdjustmentInterval()),
                                       TicksSinceEpoch<std::chrono::seconds>(NodeClock::now()))};

    if (nOldTime < nNewTime) {
        pblock->nTime = nNewTime;
    }

    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks) {
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);
    }

    return nNewTime - nOldTime;
}

void IncrementExtraNonce(CBlock* pblock, const CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    nExtraNonce = drivechain::haskell::NextExtraNonce(hashPrevBlock == pblock->hashPrevBlock, nExtraNonce);
    hashPrevBlock = pblock->hashPrevBlock;
    unsigned int nHeight = pindexPrev->nHeight + 1; // Height first in coinbase required for block.version=2
    CMutableTransaction txCoinbase(*pblock->vtx[0]);
    txCoinbase.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce));
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
}

void RegenerateCommitments(CBlock& block, ChainstateManager& chainman)
{
    CMutableTransaction tx{*block.vtx.at(0)};
    tx.vout.erase(tx.vout.begin() + GetWitnessCommitmentIndex(block));
    tx.witness.vtxoutwit.erase(tx.witness.vtxoutwit.begin() + GetWitnessCommitmentIndex(block));
    block.vtx.at(0) = MakeTransactionRef(tx);

    const CBlockIndex* prev_block = WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock));
    chainman.GenerateCoinbaseCommitment(block, prev_block);

    block.hashMerkleRoot = BlockMerkleRoot(block);
    if (chainman.GetConsensus().utreexo) {
        LOCK(cs_main);
        utreexo::Prepare(block, prev_block, chainman.ActiveChainstate().CoinsTip(),
            chainman.GetParams(), *chainman.m_blockman.m_block_tree_db);
    }
}

static BlockAssembler::Options ClampOptions(BlockAssembler::Options options)
{
    Assert(options.block_reserved_weight <= MAX_BLOCK_WEIGHT);
    Assert(options.block_reserved_weight >= MINIMUM_BLOCK_RESERVED_WEIGHT);
    Assert(options.coinbase_output_max_additional_sigops <= MAX_BLOCK_SIGOPS_COST);
    // Limit weight to between block_reserved_weight and MAX_BLOCK_WEIGHT for sanity:
    // block_reserved_weight can safely exceed -blockmaxweight, but the rest of the block template will be empty.
    options.nBlockMaxWeight = std::clamp<size_t>(options.nBlockMaxWeight, options.block_reserved_weight, MAX_BLOCK_WEIGHT);
    return options;
}

BlockAssembler::BlockAssembler(Chainstate& chainstate, const CTxMemPool* mempool, const Options& options)
    : chainparams{chainstate.m_chainman.GetParams()},
      m_mempool{options.use_mempool ? mempool : nullptr},
      m_chainstate{chainstate},
      m_options{ClampOptions(options)}
{
}

void ApplyArgsManOptions(const ArgsManager& args, BlockAssembler::Options& options)
{
    // Block resource limits
    options.nBlockMaxWeight = args.GetIntArg("-blockmaxweight", options.nBlockMaxWeight);
    if (const auto blockmintxfee{args.GetArg("-blockmintxfee")}) {
        if (const auto parsed{ParseMoney(*blockmintxfee)}) options.blockMinFeeRate = CFeeRate{*parsed};
    }
    options.print_modified_fee = args.GetBoolArg("-printpriority", options.print_modified_fee);
    options.block_reserved_weight = args.GetIntArg("-blockreservedweight", options.block_reserved_weight);
}

void BlockAssembler::resetBlock()
{
    inBlock.clear();

    // Reserve space for fixed-size block header, txs count, and coinbase tx.
    nBlockWeight = m_options.block_reserved_weight;
    if (chainparams.GetConsensus().utreexo) {
        // Reserve the largest canonical root vector before selecting transactions.
        nBlockWeight += (8 + 1 + 63 * 32) * WITNESS_SCALE_FACTOR;
    }
    nBlockSigOpsCost = m_options.coinbase_output_max_additional_sigops;

    // These counters do not include coinbase tx
    nBlockTx = 0;
    nFees = 0;
}

std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewBlock()
{
    auto authenticated_parent_height = m_options.authenticated_parent_height;
    DrivechainParentValidationBudget parent_budget{
        chainparams.GetConsensus().drivechain_slot.has_value()};
    const auto& min_tx_age = m_options.min_tx_age;
    const auto& proposed_entry = m_options.proposed_entry;
    const auto& commit_scripts = m_options.commit_scripts;
    assert(min_tx_age >= std::chrono::seconds(0));
    const auto time_start{SteadyClock::now()};

    resetBlock();

    pblocktemplate.reset(new CBlockTemplate());
    CBlock* const pblock = &pblocktemplate->block; // pointer for convenience


    // Add dummy coinbase tx as first transaction
    pblock->vtx.emplace_back();
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOpsCost.push_back(-1); // updated at end

    LOCK(::cs_main);
    CBlockIndex* pindexPrev = m_chainstate.m_chain.Tip();
    assert(pindexPrev != nullptr);
    nHeight = pindexPrev->nHeight + 1;
    m_include_drivechain_pegins =
        m_chainstate.IsDrivechainMempoolCurrentForMining();

    pblock->nVersion = m_chainstate.m_chainman.m_versionbitscache.ComputeBlockVersion(pindexPrev, chainparams.GetConsensus());
    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainparams.MineBlocksOnDemand()) {
        pblock->nVersion = gArgs.GetIntArg("-blockversion", pblock->nVersion);
    }
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::TEMPLATE_VERSION,
        [&](uint32_t step) EXCLUSIVE_LOCKS_REQUIRED(cs_main) -> uint32_t {
            switch (step) {
            case 1: return chainparams.GetConsensus().elements_mode;
            case 2: return drivechain::BmmProofRequiredAfter(pindexPrev);
            case 3: pblock->nVersion |= CBlockHeader::BMM_PROOF_HF_MASK; return 1;
            default: throw std::runtime_error("Unknown template version action");
            }
        });

    pblock->nTime = TicksSinceEpoch<std::chrono::seconds>(NodeClock::now());
    m_lock_time_cutoff = pindexPrev->GetMedianTimePast();

    // ELEMENTS:
    if (drivechain::haskell::ParentReplayAll<2>({[&] { return chainparams.GetConsensus().elements_mode; },
        [&] { return DeploymentActiveAfter(pindexPrev, m_chainstate.m_chainman, Consensus::DEPLOYMENT_DYNA_FED); }})) {
        const DynaFedParamEntry current_params = ComputeNextBlockCurrentParameters(m_chainstate.m_chain.Tip(), chainparams.GetConsensus());
        const DynaFedParams block_params(current_params, proposed_entry);
        pblock->m_dynafed_params = block_params;
        nBlockWeight += ::GetSerializeSize(block_params) * WITNESS_SCALE_FACTOR;
        nBlockWeight += current_params.m_signblock_witness_limit; // Note witness discount
        assert(pblock->proof.IsNull());

    } else if (g_signed_blocks) {
        // Old style signed blocks
        // Pad block weight by block proof fields (including upper-bound of signature)
        nBlockWeight += chainparams.GetConsensus().signblockscript.size() * WITNESS_SCALE_FACTOR;
        nBlockWeight += chainparams.GetConsensus().max_block_signature_size * WITNESS_SCALE_FACTOR;
        ResetProof(*pblock);
        ResetChallenge(*pblock, *pindexPrev, chainparams.GetConsensus());
    }

    // Select against the same authenticated P that the final coinbase names.
    // A mempool entry may have been admitted before the parent tip advanced.
    std::optional<DrivechainParentBlockContext> selection;
    std::string selection_error;
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::TEMPLATE_SELECTION,
        [&](uint32_t step) EXCLUSIVE_LOCKS_REQUIRED(cs_main) -> uint32_t {
            switch (step) {
            case 1: m_candidate_parent.reset(); return 1;
            case 2: return chainparams.GetConsensus().drivechain_slot.has_value();
            case 3: {
                CMutableTransaction commitment_coinbase;
                commitment_coinbase.vin.resize(1);
                commitment_coinbase.vin[0].prevout.SetNull();
                for (const auto& script : commit_scripts) commitment_coinbase.vout.emplace_back(policyAsset, 0, script);
                CBlock commitment_block;
                commitment_block.vtx.push_back(MakeTransactionRef(std::move(commitment_coinbase)));
                selection.emplace();
                return GetDrivechainParentBlockContext(commitment_block,
                    chainparams.GetConsensus().drivechain_slot.value(), *selection, &selection_error);
            }
            case 4: m_candidate_parent = selection.value(); return 1;
            case 5: throw std::runtime_error("CreateNewBlock(): " + selection_error);
            default: throw std::runtime_error("Unknown template selection action");
            }
        });

    int nPackagesSelected = 0;
    int nDescendantsUpdated = 0;
    if (m_mempool) {
        addPackageTxs(nPackagesSelected, nDescendantsUpdated, min_tx_age);
    }

    const auto time_1{SteadyClock::now()};

    m_last_block_num_txs = nBlockTx;
    m_last_block_weight = nBlockWeight;

    // Create coinbase transaction.
    CMutableTransaction coinbaseTx;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].scriptPubKey = m_options.coinbase_output_script;
    coinbaseTx.vout[0].nAsset = policyAsset;
    coinbaseTx.vout[0].nValue = nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus());
    if (g_con_elementsmode) {
        if(chainparams.GetConsensus().subsidy_asset != policyAsset) {
            // Only claim the subsidy if it's the same as the policy asset.
            coinbaseTx.vout[0].nValue = nFees;
        }
        // 0-value outputs must be unspendable
        if (coinbaseTx.vout[0].nValue.GetAmount() == 0) {
            coinbaseTx.vout[0].scriptPubKey = CScript() << OP_RETURN;
        }
    }
    coinbaseTx.vin[0].scriptSig = CScript() << nHeight << OP_0;
    uint256 withdrawal_bundle_hash;
if (chainparams.GetConsensus().elements_mode && chainparams.GetConsensus().has_parent_chain) {
    withdrawal_bundle_hash = GetCurrentDrivechainWithdrawalBundleHash();
}
    // Non-consensus commitment output before finishing coinbase transaction
    if (!commit_scripts.empty()) {
        for (const auto& commit_script: commit_scripts) {
            coinbaseTx.vout.insert(std::prev(coinbaseTx.vout.end()), CTxOut(policyAsset, 0, commit_script));
        }
    }
    pblock->vtx[0] = MakeTransactionRef(std::move(coinbaseTx));
    pblocktemplate->vchCoinbaseCommitment = m_chainstate.m_chainman.GenerateCoinbaseCommitment(*pblock, pindexPrev);
    pblocktemplate->vTxFees[0] = -nFees;

    LogPrintf("CreateNewBlock(): block weight: %u txs: %u fees: %ld sigops %d\n", GetBlockWeight(*pblock), nBlockTx, nFees, nBlockSigOpsCost);

    // Fill in header
    pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
    pblock->hashWithdrawalBundle = withdrawal_bundle_hash;
if (authenticated_parent_height && m_candidate_parent &&
    *authenticated_parent_height != m_candidate_parent->parent_height) {
    throw std::runtime_error("CreateNewBlock(): supplied parent height disagrees with authenticated candidate P");
}
    UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev);
    pblock->nBits          = g_signed_blocks ? 0 : GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus());
    if (g_con_blockheightinheader) {
        pblock->block_height = nHeight;
    }
    pblock->nNonce         = 0;
    pblocktemplate->vTxSigOpsCost[0] = WITNESS_SCALE_FACTOR * GetLegacySigOpCount(*pblock->vtx[0]);
    utreexo::Prepare(*pblock, pindexPrev, m_chainstate.CoinsTip(), chainparams,
        *m_chainstate.m_blockman.m_block_tree_db);

    BlockValidationState state;
    // The replay cache can publish a replacement generation without taking
    // cs_main or the mempool lock. Never return a template containing a peg-in
    // if that publication raced assembly; the next template fences deposits
    // until the mempool sweep completes.
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::TEMPLATE_ADMISSION,
        [&](uint32_t step) EXCLUSIVE_LOCKS_REQUIRED(cs_main) -> uint32_t {
            switch (step) {
            case 1: return m_include_drivechain_pegins;
            case 2: return m_chainstate.IsDrivechainMempoolCurrentForMining();
            case 3: return !drivechain::haskell::ParentReplayEach(pblock->vtx, [](const CTransactionRef& tx) {
                return drivechain::haskell::ParentReplayEach(tx->vin, [](const CTxIn& input) { return !input.m_is_pegin; });
            });
            case 4: throw std::runtime_error("authenticated parent replay changed during block assembly");
            case 5: return m_options.test_block_validity;
            case 6: return chainparams.GetConsensus().drivechain_slot.has_value();
            case 7: return TestBlockCandidateValidity(state, chainparams, m_chainstate, *pblock, pindexPrev, false, false);
            case 8: throw std::runtime_error(strprintf("CreateNewBlock: TestBlockCandidateValidity failed: %s", state.ToString()));
            default: throw std::runtime_error("Unknown template admission action");
            }
        });
    const auto time_2{SteadyClock::now()};

    LogDebug(BCLog::BENCH, "CreateNewBlock() packages: %.2fms (%d packages, %d updated descendants), validity: %.2fms (total %.2fms)\n",
             Ticks<MillisecondsDouble>(time_1 - time_start), nPackagesSelected, nDescendantsUpdated,
             Ticks<MillisecondsDouble>(time_2 - time_1),
             Ticks<MillisecondsDouble>(time_2 - time_start));

    return std::move(pblocktemplate);
}

void BlockAssembler::onlyUnconfirmed(CTxMemPool::setEntries& testSet)
{
    for (CTxMemPool::setEntries::iterator iit = testSet.begin(); iit != testSet.end(); ) {
        // Only test txs not already in the block
        if (inBlock.count((*iit)->GetSharedTx()->GetHash())) {
            testSet.erase(iit++);
        } else {
            iit++;
        }
    }
}

bool BlockAssembler::TestPackage(uint64_t packageSize, int64_t packageSigOpsCost) const
{
    // TODO: switch to weight-based accounting for packages instead of vsize-based accounting.
    if (nBlockWeight + WITNESS_SCALE_FACTOR * packageSize >= m_options.nBlockMaxWeight) {
        return false;
    }
    if (nBlockSigOpsCost + packageSigOpsCost >= MAX_BLOCK_SIGOPS_COST) {
        return false;
    }
    return true;
}

// Perform transaction-level checks before adding to block:
// - transaction finality (locktime)
bool BlockAssembler::TestPackageTransactions(const CTxMemPool& mempool, const CTxMemPool::setEntries& package) const
{
    for (const auto& entry : package) {
        const auto& tx = entry->GetTx();
        if (!m_include_drivechain_pegins && std::any_of(tx.vin.begin(), tx.vin.end(),
                [](const CTxIn& input) { return input.m_is_pegin; })) return false;
        if (!IsFinalTx(tx, nHeight, m_lock_time_cutoff)) return false;
        if (m_candidate_parent && !CheckNativeCandidateTransactionScripts(tx, m_chainstate,
                mempool, pblocktemplate->block, *m_candidate_parent)) return false;
    }
    return true;
}

void BlockAssembler::AddToBlock(CTxMemPool::txiter iter)
{
    pblocktemplate->block.vtx.emplace_back(iter->GetSharedTx());
    pblocktemplate->vTxFees.push_back(iter->GetFee());
    pblocktemplate->vTxSigOpsCost.push_back(iter->GetSigOpCost());
    nBlockWeight += iter->GetTxWeight();
    ++nBlockTx;
    nBlockSigOpsCost += iter->GetSigOpCost();
    nFees += iter->GetFee();
    inBlock.insert(iter->GetSharedTx()->GetHash());

    if (m_options.print_modified_fee) {
        LogPrintf("fee rate %s txid %s\n",
                  CFeeRate(iter->GetModifiedFee(), iter->GetTxSize()).ToString(),
                  iter->GetTx().GetHash().ToString());
    }
}

/** Add descendants of given transactions to mapModifiedTx with ancestor
 * state updated assuming given transactions are inBlock. Returns number
 * of updated descendants. */
static int UpdatePackagesForAdded(const CTxMemPool& mempool,
                                  const CTxMemPool::setEntries& alreadyAdded,
                                  indexed_modified_transaction_set& mapModifiedTx) EXCLUSIVE_LOCKS_REQUIRED(mempool.cs)
{
    AssertLockHeld(mempool.cs);

    int nDescendantsUpdated = 0;
    for (CTxMemPool::txiter it : alreadyAdded) {
        CTxMemPool::setEntries descendants;
        mempool.CalculateDescendants(it, descendants);
        // Insert all descendants (not yet in block) into the modified set
        for (CTxMemPool::txiter desc : descendants) {
            if (alreadyAdded.count(desc)) {
                continue;
            }
            ++nDescendantsUpdated;
            modtxiter mit = mapModifiedTx.find(desc);
            if (mit == mapModifiedTx.end()) {
                CTxMemPoolModifiedEntry modEntry(desc);
                mit = mapModifiedTx.insert(modEntry).first;
            }
            mapModifiedTx.modify(mit, update_for_parent_inclusion(it));
        }
    }
    return nDescendantsUpdated;
}

void BlockAssembler::SortForBlock(const CTxMemPool::setEntries& package, std::vector<CTxMemPool::txiter>& sortedEntries)
{
    // Sort package by ancestor count
    // If a transaction A depends on transaction B, then A's ancestor count
    // must be greater than B's.  So this is sufficient to validly order the
    // transactions for block inclusion.
    sortedEntries.clear();
    sortedEntries.insert(sortedEntries.begin(), package.begin(), package.end());
    std::sort(sortedEntries.begin(), sortedEntries.end(), CompareTxIterByAncestorCount());
}

// This transaction selection algorithm orders the mempool based
// on feerate of a transaction including all unconfirmed ancestors.
// Since we don't remove transactions from the mempool as we select them
// for block inclusion, we need an alternate method of updating the feerate
// of a transaction with its not-yet-selected ancestors as we go.
// This is accomplished by walking the in-mempool descendants of selected
// transactions and storing a temporary modified state in mapModifiedTxs.
// Each time through the loop, we compare the best transaction in
// mapModifiedTxs with the next transaction in the mempool to decide what
// transaction package to work on next.
void BlockAssembler::addPackageTxs(int& nPackagesSelected, int& nDescendantsUpdated, std::chrono::seconds min_tx_age)
{
    const auto& mempool{*Assert(m_mempool)};
    LOCK(mempool.cs);

    // A native BIP300 deposit gives the sidechain its entire backing value to
    // one committed recipient, so its one-input/one-output canonical form has
    // no room to pay an Elements fee. Include only that exact standalone form
    // before ordinary feerate selection. Requiring no mempool parents or
    // children prevents this exception from subsidizing any package.
    CTxMemPool::txiter free_iter;
    std::optional<CTxMemPool::setEntries> singleton;
    drivechain::haskell::FeeFreeSelection(min_tx_age.count(),
        [&](uint32_t step) EXCLUSIVE_LOCKS_REQUIRED(cs_main, mempool.cs) -> uint64_t {
            switch (step) {
            case 1: return chainparams.GetConsensus().drivechain_slot.has_value();
            case 2: free_iter=mempool.mapTx.begin(); return 1;
            case 3: return free_iter!=mempool.mapTx.end();
            case 4: return static_cast<uint64_t>(free_iter->GetFee());
            case 5: return free_iter->GetCountWithAncestors();
            case 6: return free_iter->GetCountWithDescendants();
            case 7: return free_iter->GetMemPoolParentsConst().size();
            case 8: return free_iter->GetMemPoolChildrenConst().size();
            case 9: return IsCanonicalFeeFreeDrivechainDeposit(free_iter->GetTx());
            case 11: return static_cast<uint64_t>(free_iter->GetTime().count());
            case 17: return static_cast<uint64_t>(GetTime<std::chrono::seconds>().count());
            case 12:
                singleton.emplace(CTxMemPool::setEntries{free_iter});
                return TestPackage(free_iter->GetTxSize(),free_iter->GetSigOpCost());
            case 13: return TestPackageTransactions(mempool, singleton.value());
            case 14: AddToBlock(free_iter); return 1;
            case 15: ++nPackagesSelected; return 1;
            case 16: singleton.reset(); ++free_iter; return 1;
            default: throw std::runtime_error("Unknown fee-free selection action");
            }
        });

    // mapModifiedTx will store sorted packages after they are modified
    // because some of their txs are already in the block
    indexed_modified_transaction_set mapModifiedTx;
    // Keep track of entries that failed inclusion, to avoid duplicate work
    std::set<Txid> failedTx;

    CTxMemPool::indexed_transaction_set::index<confidential_score>::type::iterator mi = mempool.mapTx.get<confidential_score>().begin();
    CTxMemPool::txiter iter;

    // Limit the number of attempts to add transactions to the block when it is
    // close to full; this is just a simple heuristic to finish quickly if the
    // mempool has a lot of entries.
    const int64_t MAX_CONSECUTIVE_FAILURES = 1000;
    int64_t nConsecutiveFailed = 0;

    while (mi != mempool.mapTx.get<confidential_score>().end() || !mapModifiedTx.empty()) {
        // First try to find a new transaction in mapTx to evaluate.
        //
        // Skip entries in mapTx that are already in a block or are present
        // in mapModifiedTx (which implies that the mapTx ancestor state is
        // stale due to ancestor inclusion in the block)
        // Also skip transactions that we've already failed to add. This can happen if
        // we consider a transaction in mapModifiedTx and it fails: we can then
        // potentially consider it again while walking mapTx.  It's currently
        // guaranteed to fail again, but as a belt-and-suspenders check we put it in
        // failedTx and avoid re-evaluation, since the re-evaluation would be using
        // cached size/sigops/fee values that are not actually correct.
        /** Return true if given transaction from mapTx has already been evaluated,
         * or if the transaction's cached data in mapTx is incorrect. */
        if (mi != mempool.mapTx.get<confidential_score>().end()) {
            auto it = mempool.mapTx.project<0>(mi);
            assert(it != mempool.mapTx.end());
            if (mapModifiedTx.count(it) || inBlock.count(it->GetSharedTx()->GetHash()) || failedTx.count(it->GetSharedTx()->GetHash())) {
                ++mi;
                continue;
            }
        }

        // Now that mi is not stale, determine which transaction to evaluate:
        // the next entry from mapTx, or the best from mapModifiedTx?
        bool fUsingModified = false;

        modconftxscoreiter modit = mapModifiedTx.get<confidential_score>().begin();
        if (mi == mempool.mapTx.get<confidential_score>().end()) {
            // We're out of entries in mapTx; use the entry from mapModifiedTx
            iter = modit->iter;
            fUsingModified = true;
        } else {
            // Try to compare the mapTx entry to the mapModifiedTx entry
            iter = mempool.mapTx.project<0>(mi);
            if (modit != mapModifiedTx.get<confidential_score>().end() &&
                    CompareTxMemPoolEntryByAncestorFee()(*modit, CTxMemPoolModifiedEntry(iter))) {
                // The best entry in mapModifiedTx has higher score
                // than the one from mapTx.
                // Switch which transaction (package) to consider
                iter = modit->iter;
                fUsingModified = true;
            } else {
                // Either no entry in mapModifiedTx, or it's worse than mapTx.
                // Increment mi for the next loop iteration.
                ++mi;
            }
        }

        // Skip transactions that are under X seconds in mempool
        // min_tx_age value of 0 is considered "inactive", in case of mocktime
        if (min_tx_age > std::chrono::seconds(0) && iter->GetTime() > GetTime<std::chrono::seconds>() - min_tx_age) {
            continue;
        }

        // We skip mapTx entries that are inBlock, and mapModifiedTx shouldn't
        // contain anything that is inBlock.
        assert(!inBlock.count(iter->GetSharedTx()->GetHash()));

        uint64_t packageSize = iter->GetSizeWithAncestors();
        CAmount packageFees = iter->GetModFeesWithAncestors();
        int64_t packageSigOpsCost = iter->GetSigOpCostWithAncestors();
        uint64_t discountSize = iter->GetDiscountSizeWithAncestors();
        if (fUsingModified) {
            packageSize = modit->nSizeWithAncestors;
            packageFees = modit->nModFeesWithAncestors;
            packageSigOpsCost = modit->nSigOpCostWithAncestors;
            discountSize = modit->discountSizeWithAncestors;
        }

        if (packageFees < m_options.blockMinFeeRate.GetFee(packageSize)) {
            if (Params().GetAcceptDiscountCT()) {
                if (packageFees < m_options.blockMinFeeRate.GetFee(discountSize)) {
                    return;
                }
            } else {
                // Everything else we might consider has a lower fee rate
                return;
            }
        }

        if (!TestPackage(packageSize, packageSigOpsCost)) {
            if (fUsingModified) {
                // Since we always look at the best entry in mapModifiedTx,
                // we must erase failed entries so that we can consider the
                // next best entry on the next loop iteration
                mapModifiedTx.get<confidential_score>().erase(modit);
                failedTx.insert(iter->GetSharedTx()->GetHash());
            }

            ++nConsecutiveFailed;

            if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES && nBlockWeight >
                    m_options.nBlockMaxWeight - m_options.block_reserved_weight) {
                // Give up if we're close to full and haven't succeeded in a while
                break;
            }
            continue;
        }

        auto ancestors{mempool.AssumeCalculateMemPoolAncestors(__func__, *iter, CTxMemPool::Limits::NoLimits(), /*fSearchForParents=*/false)};

        onlyUnconfirmed(ancestors);
        ancestors.insert(iter);

        // Test if all tx's are Final
        if (!TestPackageTransactions(mempool, ancestors)) {
            if (fUsingModified) {
                mapModifiedTx.get<confidential_score>().erase(modit);
                failedTx.insert(iter->GetSharedTx()->GetHash());
            }
            continue;
        }

        // This transaction will make it in; reset the failed counter.
        nConsecutiveFailed = 0;

        // Package can be added. Sort the entries in a valid order.
        std::vector<CTxMemPool::txiter> sortedEntries;
        SortForBlock(ancestors, sortedEntries);

for (const auto& entry : sortedEntries) {
    AddToBlock(entry);
    mapModifiedTx.erase(entry);
}

        ++nPackagesSelected;
        pblocktemplate->m_package_feerates.emplace_back(packageFees, static_cast<int32_t>(packageSize));

        // Update transactions that depend on each of these
        nDescendantsUpdated += UpdatePackagesForAdded(mempool, ancestors, mapModifiedTx);
    }
}
} // namespace node
