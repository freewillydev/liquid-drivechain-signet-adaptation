// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/blockchain.h>

#include <blockfilter.h>
#include <chain.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <clientversion.h>
#include <coins.h>
#include <common/args.h>
#include <consensus/amount.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <crypto/common.h>
#include <deploymentinfo.h>
#include <deploymentstatus.h>
#include <drivechain_bmm.h>
#include <haskell/bmm_constants.h>
#include <drivechain_peg.h>
#include <ecx_exchange_state.h>
#include <drivechain_withdrawal.h>
#include <flatfile.h>
#include <hash.h>
#include <haskell/bridge.h>
#include <index/blockfilterindex.h>
#include <index/coinstatsindex.h>
#include <init.h>
#include <interfaces/mining.h>
#include <kernel/coinstats.h>
#include <logging/timer.h>
#include <mainchainrpc.h>
#include <net.h>
#include <net_processing.h>
#include <node/blockstorage.h>
#include <node/context.h>
#include <node/transaction.h>
#include <node/utxo_snapshot.h>
#include <node/warnings.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <serialize.h>
#include <streams.h>
#include <sync.h>
#include <txdb.h>
#include <txmempool.h>
#include <undo.h>
#include <univalue.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/moneystr.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/translation.h>
#include <usdd_withdrawal_accumulator.h>
#include <validation.h>
#include <validationinterface.h>
#include <versionbits.h>
#include <pegins.h>
#include <dynafed.h>

#include <stdint.h>

#include <chrono>
#include <condition_variable>
#include <algorithm>
#include <array>
#include <iterator>
#include <memory>
#include <mutex>
#include <string>
#include <optional>
#include <ranges>
#include <vector>

using kernel::CCoinsStats;
using kernel::CoinStatsHashType;

using interfaces::Mining;
using node::BlockManager;
using node::NodeContext;
using node::SnapshotMetadata;
using util::MakeUnorderedList;

std::tuple<std::unique_ptr<CCoinsViewCursor>, CCoinsStats, const CBlockIndex*>
PrepareUTXOSnapshot(
    Chainstate& chainstate,
    const std::function<void()>& interruption_point = {})
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

static std::mutex g_usdd_withdrawal_proof_mutex;

UniValue EcxWideNumberToJSON(std::span<const unsigned char,16> bytes, bool signed_value)
{
    UniValue number;
    number.setNumStr(drivechain::haskell::WideDecimal(bytes,signed_value));
    return number;
}

UniValue WriteUTXOSnapshot(
    Chainstate& chainstate,
    CCoinsViewCursor* pcursor,
    CCoinsStats* maybe_stats,
    const CBlockIndex* tip,
    AutoFile& afile,
    const fs::path& path,
    const fs::path& temppath,
    const std::function<void()>& interruption_point = {});

/* Calculate the difficulty for a given block index.
 */
double GetDifficulty(const CBlockIndex& blockindex)
{
    int nShift = (blockindex.nBits >> 24) & 0xff;
    double dDiff =
        (double)0x0000ffff / (double)(blockindex.nBits & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}

UniValue paramEntryToJSON(const DynaFedParamEntry& entry)
{
    UniValue result(UniValue::VOBJ);

    // set the type
    if (entry.m_serialize_type == 0) {
        result.pushKV("type", "null");
    } else if (entry.m_serialize_type == 1) {
        result.pushKV("type", "compact");
    } else if (entry.m_serialize_type == 2) {
        result.pushKV("type", "full");
    }

    // nothing more to do for null
    if (entry.m_serialize_type == 0) {
        return result;
    }

    // fields all params have
    result.pushKV("root", entry.CalculateRoot().GetHex());
    result.pushKV("signblockscript", HexStr(entry.m_signblockscript));
    result.pushKV("max_block_witness", (uint64_t)entry.m_signblock_witness_limit);

    // add the extra root which is stored for compact and calculated for full
    if (entry.m_serialize_type == 1) {
        // compact
        result.pushKV("extra_root", entry.m_elided_root.GetHex());
    } else if (entry.m_serialize_type == 2) {
        // full
        result.pushKV("extra_root", entry.CalculateExtraRoot().GetHex());
    }

    // some extra fields only present on full params
    if (entry.m_serialize_type == 2) {
        result.pushKV("fedpeg_program", HexStr(entry.m_fedpeg_program));
        result.pushKV("fedpegscript", HexStr(entry.m_fedpegscript));
        UniValue result_extension(UniValue::VARR);
        for (auto& item : entry.m_extension_space) {
            result_extension.push_back(HexStr(item));
        }
        result.pushKV("extension_space", result_extension);
    }

    return result;
}

UniValue dynaParamsToJSON(const DynaFedParams& dynafed_params)
{
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("current", paramEntryToJSON(dynafed_params.m_current));
    ret.pushKV("proposed", paramEntryToJSON(dynafed_params.m_proposed));
    return ret;
}

static int ComputeNextBlockAndDepth(const CBlockIndex& tip, const CBlockIndex& blockindex, const CBlockIndex*& next)
{
    next = tip.GetAncestor(blockindex.nHeight + 1);
    if (next && next->pprev == &blockindex) {
        return tip.nHeight - blockindex.nHeight + 1;
    }
    next = nullptr;
    return &blockindex == &tip ? 1 : -1;
}

static const CBlockIndex* ParseHashOrHeight(const UniValue& param, ChainstateManager& chainman)
{
    LOCK(::cs_main);
    CChain& active_chain = chainman.ActiveChain();

    if (param.isNum()) {
        const int height{param.getInt<int>()};
        if (height < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Target block height %d is negative", height));
        }
        const int current_tip{active_chain.Height()};
        if (height > current_tip) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Target block height %d after current tip %d", height, current_tip));
        }

        return active_chain[height];
    } else {
        const uint256 hash{ParseHashV(param, "hash_or_height")};
        const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(hash);

        if (!pindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }

        return pindex;
    }
}

UniValue blockheaderToJSON(const CBlockIndex& tip, const CBlockIndex& blockindex_, const uint256 pow_limit)
{
    // Serialize passed information without accessing chain state of the active chain!
    AssertLockNotHeld(cs_main); // For performance reasons

    CBlockIndex tmpBlockIndexFull;
    const CBlockIndex* blockindex;
    {
        LOCK(cs_main);
        blockindex = blockindex_.untrim_to(&tmpBlockIndexFull);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("hash", blockindex->GetBlockHash().GetHex());
    const CBlockIndex* pnext;
    int confirmations = ComputeNextBlockAndDepth(tip, blockindex_, pnext);
    result.pushKV("confirmations", confirmations);
    result.pushKV("height", blockindex->nHeight);
    result.pushKV("version", blockindex->nVersion);
    result.pushKV("versionHex", strprintf("%08x", blockindex->nVersion));
    result.pushKV("merkleroot", blockindex->hashMerkleRoot.GetHex());
    if (Params().GetConsensus().utreexo && blockindex->nHeight > 0) {
        UniValue accumulator(UniValue::VOBJ), roots(UniValue::VARR);
        for (const auto& root : blockindex->utreexo.roots) roots.push_back(root.GetHex());
        accumulator.pushKV("leaves", blockindex->utreexo.leaves);
        accumulator.pushKV("roots", std::move(roots));
        result.pushKV("utreexo", std::move(accumulator));
    }
    if (Params().GetConsensus().elements_mode) {
        result.pushKV("withdrawalbundlehash", blockindex->hashWithdrawalBundle.GetHex());
        result.pushKV("bmmproofhash", blockindex->hashBmmProof.GetHex());
        result.pushKV("exchangestateroot", blockindex->hashExchangeStateRoot.GetHex());
        result.pushKV("forcedinboxroot", blockindex->hashForcedInboxRoot.GetHex());
        result.pushKV("depositinboxroot", blockindex->hashDepositInboxRoot.GetHex());
        result.pushKV("ecxparentheight", static_cast<uint64_t>(blockindex->ecxParentHeight));
        result.pushKV("forcedprocessedcursor", blockindex->forcedProcessedCursor);
        result.pushKV("depositprocessedcursor", blockindex->depositProcessedCursor);
        result.pushKV(
            "sourcebacklogoldestparentheight",
            blockindex->sourceBacklogOldestParentHeight);
    }
    result.pushKV("time", (int64_t)blockindex->nTime);
    result.pushKV("mediantime", (int64_t)blockindex->GetMedianTimePast());
    if (!g_signed_blocks) {
        result.pushKV("nonce", (uint64_t)blockindex->nNonce);
        result.pushKV("bits", strprintf("%08x", blockindex->nBits));
        result.pushKV("difficulty", GetDifficulty(*blockindex));
        result.pushKV("chainwork", blockindex->nChainWork.GetHex());
    } else {
        if (!blockindex->is_dynafed_block()) {
            if (blockindex->trimmed()) {
                result.pushKV("signblock_witness_asm", "<trimmed>");
                result.pushKV("signblock_witness_hex", "<trimmed>");
                result.pushKV("signblock_challenge", "<trimmed>");
                result.pushKV("warning", "Fields missing due to -trim_headers flag.");
            } else {
                result.pushKV("signblock_witness_asm", ScriptToAsmStr(blockindex->get_proof().solution));
                result.pushKV("signblock_witness_hex", HexStr(blockindex->get_proof().solution));
                result.pushKV("signblock_challenge", HexStr(blockindex->get_proof().challenge));
            }
        } else {
            if (blockindex->trimmed()) {
                result.pushKV("signblock_witness_hex", "<trimmed>");
                result.pushKV("dynamic_parameters", "<trimmed>");
                result.pushKV("warning", "Fields missing due to -trim_headers flag.");
            } else {
                result.pushKV("signblock_witness_hex", EncodeHexScriptWitness(blockindex->signblock_witness()));
                result.pushKV("dynamic_parameters", dynaParamsToJSON(blockindex->dynafed_params()));
            }
        }
    }
    result.pushKV("nTx", (uint64_t)blockindex->nTx);
    if (blockindex_.pprev)
        result.pushKV("previousblockhash", blockindex->pprev->GetBlockHash().GetHex());
    if (pnext)
        result.pushKV("nextblockhash", pnext->GetBlockHash().GetHex());
    return result;
}

UniValue blockToJSON(BlockManager& blockman, const CBlock& block, const CBlockIndex& tip, const CBlockIndex& blockindex, TxVerbosity verbosity, const uint256 pow_limit)
{
    UniValue result = blockheaderToJSON(tip, blockindex, pow_limit);

    result.pushKV("strippedsize", (int)::GetSerializeSize(TX_NO_WITNESS(block)));
    result.pushKV("size", (int)::GetSerializeSize(TX_WITH_WITNESS(block)));
    result.pushKV("weight", (int)::GetBlockWeight(block));
    UniValue txs(UniValue::VARR);

    switch (verbosity) {
        case TxVerbosity::SHOW_TXID:
            for (const CTransactionRef& tx : block.vtx) {
                txs.push_back(tx->GetHash().GetHex());
            }
            break;

        case TxVerbosity::SHOW_DETAILS:
        case TxVerbosity::SHOW_DETAILS_AND_PREVOUT:
            CBlockUndo blockUndo;
            const bool is_not_pruned{WITH_LOCK(::cs_main, return !blockman.IsBlockPruned(blockindex))};
            bool have_undo{is_not_pruned && WITH_LOCK(::cs_main, return blockindex.nStatus & BLOCK_HAVE_UNDO)};
            if (have_undo && !blockman.ReadBlockUndo(blockUndo, blockindex)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Undo data expected but can't be read. This could be due to disk corruption or a conflict with a pruning event.");
            }
            for (size_t i = 0; i < block.vtx.size(); ++i) {
                const CTransactionRef& tx = block.vtx.at(i);
                // coinbase transaction (i.e. i == 0) doesn't have undo data
                const CTxUndo* txundo = (have_undo && i > 0) ? &blockUndo.vtxundo.at(i - 1) : nullptr;
                UniValue objTx(UniValue::VOBJ);
                TxToUniv(*tx, /*block_hash=*/uint256(), /*entry=*/objTx, /*include_hex=*/true, txundo, verbosity);
                txs.push_back(std::move(objTx));
            }
            break;
    }

    result.pushKV("tx", std::move(txs));

    return result;
}

static RPCHelpMan getblockcount()
{
    return RPCHelpMan{"getblockcount",
                "\nReturns the height of the most-work fully-validated chain.\n"
                "The genesis block has height 0.\n",
                {},
                RPCResult{
                    RPCResult::Type::NUM, "", "The current block count"},
                RPCExamples{
                    HelpExampleCli("getblockcount", "")
            + HelpExampleRpc("getblockcount", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    return chainman.ActiveChain().Height();
},
    };
}

static RPCHelpMan getbestblockhash()
{
    return RPCHelpMan{"getbestblockhash",
                "\nReturns the hash of the best (tip) block in the most-work fully-validated chain.\n",
                {},
                RPCResult{
                    RPCResult::Type::STR_HEX, "", "the block hash, hex-encoded"},
                RPCExamples{
                    HelpExampleCli("getbestblockhash", "")
            + HelpExampleRpc("getbestblockhash", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    return chainman.ActiveChain().Tip()->GetBlockHash().GetHex();
},
    };
}

static RPCHelpMan waitfornewblock()
{
    return RPCHelpMan{"waitfornewblock",
                "\nWaits for any new block and returns useful info about it.\n"
                "\nReturns the current block on timeout or exit.\n"
                "\nMake sure to use no RPC timeout (bitcoin-cli -rpcclienttimeout=0)",
                {
                    {"timeout", RPCArg::Type::NUM, RPCArg::Default{0}, "Time in milliseconds to wait for a response. 0 indicates no timeout."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hash", "The blockhash"},
                        {RPCResult::Type::NUM, "height", "Block height"},
                    }},
                RPCExamples{
                    HelpExampleCli("waitfornewblock", "1000")
            + HelpExampleRpc("waitfornewblock", "1000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    int timeout = 0;
    if (!request.params[0].isNull())
        timeout = request.params[0].getInt<int>();
    if (timeout < 0) throw JSONRPCError(RPC_MISC_ERROR, "Negative timeout");

    NodeContext& node = EnsureAnyNodeContext(request.context);
    Mining& miner = EnsureMining(node);

    auto block{CHECK_NONFATAL(miner.getTip()).value()};
    if (IsRPCRunning()) {
        block = timeout ? miner.waitTipChanged(block.hash, std::chrono::milliseconds(timeout)) : miner.waitTipChanged(block.hash);
    }

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("hash", block.hash.GetHex());
    ret.pushKV("height", block.height);
    return ret;
},
    };
}

static RPCHelpMan waitforblock()
{
    return RPCHelpMan{"waitforblock",
                "\nWaits for a specific new block and returns useful info about it.\n"
                "\nReturns the current block on timeout or exit.\n"
                "\nMake sure to use no RPC timeout (bitcoin-cli -rpcclienttimeout=0)",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Block hash to wait for."},
                    {"timeout", RPCArg::Type::NUM, RPCArg::Default{0}, "Time in milliseconds to wait for a response. 0 indicates no timeout."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hash", "The blockhash"},
                        {RPCResult::Type::NUM, "height", "Block height"},
                    }},
                RPCExamples{
                    HelpExampleCli("waitforblock", "\"0000000000079f8ef3d2c688c244eb7a4570b24c9ed7b4a8c619eb02596f8862\" 1000")
            + HelpExampleRpc("waitforblock", "\"0000000000079f8ef3d2c688c244eb7a4570b24c9ed7b4a8c619eb02596f8862\", 1000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    int timeout = 0;

    uint256 hash(ParseHashV(request.params[0], "blockhash"));

    if (!request.params[1].isNull())
        timeout = request.params[1].getInt<int>();
    if (timeout < 0) throw JSONRPCError(RPC_MISC_ERROR, "Negative timeout");

    NodeContext& node = EnsureAnyNodeContext(request.context);
    Mining& miner = EnsureMining(node);

    auto block{CHECK_NONFATAL(miner.getTip()).value()};
    const auto deadline{std::chrono::steady_clock::now() + 1ms * timeout};
    while (IsRPCRunning() && block.hash != hash) {
        if (timeout) {
            auto now{std::chrono::steady_clock::now()};
            if (now >= deadline) break;
            const MillisecondsDouble remaining{deadline - now};
            block = miner.waitTipChanged(block.hash, remaining);
        } else {
            block = miner.waitTipChanged(block.hash);
        }
    }

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("hash", block.hash.GetHex());
    ret.pushKV("height", block.height);
    return ret;
},
    };
}

static RPCHelpMan waitforblockheight()
{
    return RPCHelpMan{"waitforblockheight",
                "\nWaits for (at least) block height and returns the height and hash\n"
                "of the current tip.\n"
                "\nReturns the current block on timeout or exit.\n"
                "\nMake sure to use no RPC timeout (bitcoin-cli -rpcclienttimeout=0)",
                {
                    {"height", RPCArg::Type::NUM, RPCArg::Optional::NO, "Block height to wait for."},
                    {"timeout", RPCArg::Type::NUM, RPCArg::Default{0}, "Time in milliseconds to wait for a response. 0 indicates no timeout."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hash", "The blockhash"},
                        {RPCResult::Type::NUM, "height", "Block height"},
                    }},
                RPCExamples{
                    HelpExampleCli("waitforblockheight", "100 1000")
            + HelpExampleRpc("waitforblockheight", "100, 1000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    int timeout = 0;

    int height = request.params[0].getInt<int>();

    if (!request.params[1].isNull())
        timeout = request.params[1].getInt<int>();
    if (timeout < 0) throw JSONRPCError(RPC_MISC_ERROR, "Negative timeout");

    NodeContext& node = EnsureAnyNodeContext(request.context);
    Mining& miner = EnsureMining(node);

    auto block{CHECK_NONFATAL(miner.getTip()).value()};
    const auto deadline{std::chrono::steady_clock::now() + 1ms * timeout};

    while (IsRPCRunning() && block.height < height) {
        if (timeout) {
            auto now{std::chrono::steady_clock::now()};
            if (now >= deadline) break;
            const MillisecondsDouble remaining{deadline - now};
            block = miner.waitTipChanged(block.hash, remaining);
        } else {
            block = miner.waitTipChanged(block.hash);
        }
    }

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("hash", block.hash.GetHex());
    ret.pushKV("height", block.height);
    return ret;
},
    };
}

static RPCHelpMan syncwithvalidationinterfacequeue()
{
    return RPCHelpMan{"syncwithvalidationinterfacequeue",
                "\nWaits for the validation interface queue to catch up on everything that was there when we entered this function.\n",
                {},
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("syncwithvalidationinterfacequeue","")
            + HelpExampleRpc("syncwithvalidationinterfacequeue","")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    CHECK_NONFATAL(node.validation_signals)->SyncWithValidationInterfaceQueue();
    return UniValue::VNULL;
},
    };
}

static RPCHelpMan getdifficulty()
{
    return RPCHelpMan{"getdifficulty",
                "\nReturns the proof-of-work difficulty as a multiple of the minimum difficulty.\n",
                {},
                RPCResult{
                    RPCResult::Type::NUM, "", "the proof-of-work difficulty as a multiple of the minimum difficulty."},
                RPCExamples{
                    HelpExampleCli("getdifficulty", "")
            + HelpExampleRpc("getdifficulty", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    return GetDifficulty(*CHECK_NONFATAL(chainman.ActiveChain().Tip()));
},
    };
}

static RPCHelpMan getblockfrompeer()
{
    return RPCHelpMan{
        "getblockfrompeer",
        "Attempt to fetch block from a given peer.\n\n"
        "We must have the header for this block, e.g. using submitheader.\n"
        "The block will not have any undo data which can limit the usage of the block data in a context where the undo data is needed.\n"
        "Subsequent calls for the same block may cause the response from the previous peer to be ignored.\n"
        "Peers generally ignore requests for a stale block that they never fully verified, or one that is more than a month old.\n"
        "When a peer does not respond with a block, we will disconnect.\n"
        "Note: The block could be re-pruned as soon as it is received.\n\n"
        "Returns an empty JSON object if the request was successfully scheduled.",
        {
            {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The block hash to try to fetch"},
            {"peer_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "The peer to fetch it from (see getpeerinfo for peer IDs)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", /*optional=*/false, "", {}},
        RPCExamples{
            HelpExampleCli("getblockfrompeer", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\" 0")
            + HelpExampleRpc("getblockfrompeer", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\" 0")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    PeerManager& peerman = EnsurePeerman(node);

    const uint256& block_hash{ParseHashV(request.params[0], "blockhash")};
    const NodeId peer_id{request.params[1].getInt<int64_t>()};

    const CBlockIndex* const index = WITH_LOCK(cs_main, return chainman.m_blockman.LookupBlockIndex(block_hash););

    if (!index) {
        throw JSONRPCError(RPC_MISC_ERROR, "Block header missing");
    }

    // Fetching blocks before the node has syncing past their height can prevent block files from
    // being pruned, so we avoid it if the node is in prune mode.
    if (chainman.m_blockman.IsPruneMode() && index->nHeight > WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip()->nHeight)) {
        throw JSONRPCError(RPC_MISC_ERROR, "In prune mode, only blocks that the node has already synced previously can be fetched from a peer");
    }

    const bool block_has_data = WITH_LOCK(::cs_main, return index->nStatus & BLOCK_HAVE_DATA);
    if (block_has_data) {
        throw JSONRPCError(RPC_MISC_ERROR, "Block already downloaded");
    }

    if (const auto err{peerman.FetchBlock(peer_id, *index)}) {
        throw JSONRPCError(RPC_MISC_ERROR, err.value());
    }
    return UniValue::VOBJ;
},
    };
}

static RPCHelpMan getblockhash()
{
    return RPCHelpMan{"getblockhash",
                "\nReturns hash of block in best-block-chain at height provided.\n",
                {
                    {"height", RPCArg::Type::NUM, RPCArg::Optional::NO, "The height index"},
                },
                RPCResult{
                    RPCResult::Type::STR_HEX, "", "The block hash"},
                RPCExamples{
                    HelpExampleCli("getblockhash", "1000")
            + HelpExampleRpc("getblockhash", "1000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    const CChain& active_chain = chainman.ActiveChain();

    int nHeight = request.params[0].getInt<int>();
    if (nHeight < 0 || nHeight > active_chain.Height())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");

    const CBlockIndex* pblockindex = active_chain[nHeight];
    return pblockindex->GetBlockHash().GetHex();
},
    };
}

static RPCHelpMan getblockheader()
{
    return RPCHelpMan{"getblockheader",
                "\nIf verbose is false, returns a string that is serialized, hex-encoded data for blockheader 'hash'.\n"
                "If verbose is true, returns an Object with information about blockheader <hash>.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The block hash"},
                    {"verbose", RPCArg::Type::BOOL, RPCArg::Default{true}, "true for a json object, false for the hex-encoded data"},
                },
                {
                    RPCResult{"for verbose = true",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "hash", "the block hash (same as provided)"},
                            {RPCResult::Type::NUM, "confirmations", "The number of confirmations, or -1 if the block is not on the main chain"},
                            {RPCResult::Type::NUM, "height", "The block height or index"},
                            {RPCResult::Type::NUM, "version", "The block version"},
                            {RPCResult::Type::STR_HEX, "versionHex", "The block version formatted in hexadecimal"},
                            {RPCResult::Type::STR_HEX, "merkleroot", "The merkle root"},
                            {RPCResult::Type::STR_HEX, "withdrawalbundlehash", "The current drivechain withdrawal bundle hash committed by this block header"},
                            {RPCResult::Type::STR_HEX, "bmmproofhash", "The BMM proof commitment appended by the existing header extension"},
                            {RPCResult::Type::STR_HEX, "exchangestateroot", "The append-only ECX state singleton root, or zero before activation"},
                            {RPCResult::Type::NUM_TIME, "time", "The block time expressed in " + UNIX_EPOCH_TIME},
                            {RPCResult::Type::NUM_TIME, "mediantime", "The median block time expressed in " + UNIX_EPOCH_TIME},
                            {RPCResult::Type::NUM, "nonce", /*optional=*/true, "The nonce"},
                            {RPCResult::Type::STR_HEX, "bits", /*optional=*/true, "The bits"},
                            {RPCResult::Type::NUM, "difficulty", /*optional=*/true, "The difficulty"},
                            {RPCResult::Type::STR_HEX, "chainwork", /*optional=*/true, "Expected number of hashes required to produce the current chain"},
                            {RPCResult::Type::NUM, "nTx", "The number of transactions in the block"},
                            {RPCResult::Type::STR, "signblock_witness_asm", /*optional=*/true, "ASM of sign block witness data"},
                            {RPCResult::Type::STR_HEX, "signblock_witness_hex", /*optional=*/true, "Hex of sign block witness data"},
                            {RPCResult::Type::STR_HEX, "signblock_challenge", /*optional=*/true, "Hex of sign block challenge"},
                            {RPCResult::Type::STR, "warning", /*optional=*/true, "Warning message if block was not loaded cleanly"},
                            {RPCResult::Type::OBJ, "dynamic_parameters", /*optional=*/true, "Dynamic federation parameters in the block, if any",
                            {
                                {RPCResult::Type::OBJ, "current", "enforced dynamic federation parameters",
                                {
                                    {RPCResult::Type::STR_HEX, "root", /*optional=*/true, "parameter root"},
                                    {RPCResult::Type::STR_HEX, "signblockscript", /*optional=*/true, "signblock script as hex"},
                                    {RPCResult::Type::NUM, "max_block_witness", /*optional=*/true, "maximum serialized size of the block witness stack"},
                                    {RPCResult::Type::STR_HEX, "extra_root", /*optional=*/true, "extra root"},
                                    {RPCResult::Type::STR_HEX, "fedpeg_program", /*optional=*/true, "fedpeg program scriptPubKey in hex"},
                                    {RPCResult::Type::STR_HEX, "fedpegscript", /*optional=*/true, "fedpeg script in hex"},
                                    {RPCResult::Type::ARR, "extension_space", /*optional=*/true, "extension space as hex strings",
                                    {
                                        {RPCResult::Type::ELISION, "", ""}
                                    }}
                                }},
                                {RPCResult::Type::OBJ, "proposed", "Proposed parameters. Unenforced. Must be published in full",
                                {
                                    {RPCResult::Type::ELISION, "", "same entries as \"current\""}
                                }},
                            }},
                            {RPCResult::Type::OBJ, "utreexo", /*optional=*/true, "Post-block accumulator on the isolated Utreexo test chain",
                            {
                                {RPCResult::Type::NUM, "leaves", "Cumulative leaf count, including spent leaves"},
                                {RPCResult::Type::ARR, "roots", "Forest roots in commitment order",
                                {{RPCResult::Type::STR_HEX, "", "Root hash"}}},
                            }},
                            {RPCResult::Type::STR_HEX, "previousblockhash", /*optional=*/true, "The hash of the previous block (if available)"},
                            {RPCResult::Type::STR_HEX, "nextblockhash", /*optional=*/true, "The hash of the next block (if available)"},
                        }},
                    RPCResult{"for verbose=false",
                        RPCResult::Type::STR_HEX, "", "A string that is serialized, hex-encoded data for block 'hash'"},
                },
                RPCExamples{
                    HelpExampleCli("getblockheader", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
            + HelpExampleRpc("getblockheader", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    uint256 hash(ParseHashV(request.params[0], "hash"));

    bool fVerbose = true;
    if (!request.params[1].isNull())
        fVerbose = request.params[1].get_bool();

    CBlockIndex* pblockindex;
    const CBlockIndex* tip;
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    {
        LOCK(cs_main);
        pblockindex = chainman.m_blockman.LookupBlockIndex(hash);
        tip = chainman.ActiveChain().Tip();
    }

    if (!pblockindex) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
    }

    if (!fVerbose)
    {
        LOCK(cs_main);
        DataStream ssBlock{};
        CBlockIndex tmpBlockIndexFull;
        const CBlockIndex* pblockindexfull=pblockindex->untrim_to(&tmpBlockIndexFull);
        ssBlock << TX_WITH_WITNESS(pblockindexfull->GetBlockHeader());
        std::string strHex = HexStr(ssBlock);
        return strHex;
    }

    return blockheaderToJSON(*tip, *pblockindex, chainman.GetConsensus().powLimit);
},
    };
}

void CheckBlockDataAvailability(BlockManager& blockman, const CBlockIndex& blockindex, bool check_for_undo)
{
    AssertLockHeld(cs_main);
    uint32_t flag = check_for_undo ? BLOCK_HAVE_UNDO : BLOCK_HAVE_DATA;
    if (!(blockindex.nStatus & flag)) {
        if (blockman.IsBlockPruned(blockindex)) {
            throw JSONRPCError(RPC_MISC_ERROR, strprintf("%s not available (pruned data)", check_for_undo ? "Undo data" : "Block"));
        }
        if (check_for_undo) {
            throw JSONRPCError(RPC_MISC_ERROR, "Undo data not available");
        }
        throw JSONRPCError(RPC_MISC_ERROR, "Block not available (not fully downloaded)");
    }
}

static CBlock GetBlockChecked(BlockManager& blockman, const CBlockIndex& blockindex)
{
    CBlock block;
    {
        LOCK(cs_main);
        CheckBlockDataAvailability(blockman, blockindex, /*check_for_undo=*/false);
    }

    if (!blockman.ReadBlock(block, blockindex)) {
        // Block not found on disk. This shouldn't normally happen unless the block was
        // pruned right after we released the lock above.
        throw JSONRPCError(RPC_MISC_ERROR, "Block not found on disk");
    }

    return block;
}

static std::vector<uint8_t> GetRawBlockChecked(BlockManager& blockman, const CBlockIndex& blockindex)
{
    std::vector<uint8_t> data{};
    FlatFilePos pos{};
    {
        LOCK(cs_main);
        CheckBlockDataAvailability(blockman, blockindex, /*check_for_undo=*/false);
        pos = blockindex.GetBlockPos();
    }

    if (!blockman.ReadRawBlock(data, pos)) {
        // Block not found on disk. This shouldn't normally happen unless the block was
        // pruned right after we released the lock above.
        throw JSONRPCError(RPC_MISC_ERROR, "Block not found on disk");
    }

    return data;
}

static CBlockUndo GetUndoChecked(BlockManager& blockman, const CBlockIndex& blockindex)
{
    CBlockUndo blockUndo;

    // The Genesis block does not have undo data
    if (blockindex.nHeight == 0) return blockUndo;

    {
        LOCK(cs_main);
        CheckBlockDataAvailability(blockman, blockindex, /*check_for_undo=*/true);
    }

    if (!blockman.ReadBlockUndo(blockUndo, blockindex)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Can't read undo data from disk");
    }

    return blockUndo;
}

const RPCResult getblock_vin{
    RPCResult::Type::ARR, "vin", "",
    {
        {RPCResult::Type::OBJ, "", "",
        {
            {RPCResult::Type::ELISION, "", "The same output as verbosity = 2"},
            {RPCResult::Type::OBJ, "prevout", "(Only if undo information is available)",
            {
                {RPCResult::Type::BOOL, "generated", "Coinbase or not"},
                {RPCResult::Type::NUM, "height", "The height of the prevout"},
                {RPCResult::Type::STR_AMOUNT, "value", "The value in " + CURRENCY_UNIT},
                {RPCResult::Type::OBJ, "scriptPubKey", "",
                {
                    {RPCResult::Type::STR, "asm", "Disassembly of the output script"},
                    {RPCResult::Type::STR, "desc", "Inferred descriptor for the output"},
                    {RPCResult::Type::STR_HEX, "hex", "The raw output script bytes, hex-encoded"},
                    {RPCResult::Type::STR, "address", /*optional=*/true, "The Bitcoin address (only if a well-defined address exists)"},
                    {RPCResult::Type::STR, "type", "The type (one of: " + GetAllOutputTypes() + ")"},
                }},
            }},
        }},
    }
};

static RPCHelpMan getblock()
{
    return RPCHelpMan{"getblock",
                "\nIf verbosity is 0, returns a string that is serialized, hex-encoded data for block 'hash'.\n"
                "If verbosity is 1, returns an Object with information about block <hash>.\n"
                "If verbosity is 2, returns an Object with information about block <hash> and information about each transaction.\n"
                "If verbosity is 3, returns an Object with information about block <hash> and information about each transaction, including prevout information for inputs (only for unpruned blocks in the current best chain).\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The block hash"},
                    {"verbosity|verbose", RPCArg::Type::NUM, RPCArg::Default{1}, "0 for hex-encoded data, 1 for a JSON object, 2 for JSON object with transaction data, and 3 for JSON object with transaction data including prevout information for inputs",
                     RPCArgOptions{.skip_type_check = true}},
                },
                {
                    RPCResult{"for verbosity = 0",
                RPCResult::Type::STR_HEX, "", "A string that is serialized, hex-encoded data for block 'hash'"},
                    RPCResult{"for verbosity = 1",
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "hash", "the block hash (same as provided)"},
                    {RPCResult::Type::NUM, "confirmations", "The number of confirmations, or -1 if the block is not on the main chain"},
                    {RPCResult::Type::NUM, "size", "The block size"},
                    {RPCResult::Type::NUM, "strippedsize", "The block size excluding witness data"},
                    {RPCResult::Type::NUM, "weight", "The block weight as defined in BIP 141"},
                    {RPCResult::Type::NUM, "height", "The block height or index"},
                    {RPCResult::Type::NUM, "version", "The block version"},
                    {RPCResult::Type::STR_HEX, "versionHex", "The block version formatted in hexadecimal"},
                    {RPCResult::Type::STR_HEX, "merkleroot", "The merkle root"},
                    {RPCResult::Type::STR_HEX, "withdrawalbundlehash", "The current drivechain withdrawal bundle hash committed by this block header"},
                    {RPCResult::Type::STR_HEX, "bmmproofhash", "The BMM proof commitment appended by the existing header extension"},
                    {RPCResult::Type::STR_HEX, "exchangestateroot", "The append-only ECX state singleton root, or zero before activation"},
                    {RPCResult::Type::ARR, "tx", "The transaction ids",
                        {{RPCResult::Type::STR_HEX, "", "The transaction id"}}},
                    {RPCResult::Type::NUM_TIME, "time",       "The block time expressed in " + UNIX_EPOCH_TIME},
                    {RPCResult::Type::NUM_TIME, "mediantime", "The median block time expressed in " + UNIX_EPOCH_TIME},
                    {RPCResult::Type::NUM, "nonce", /*optional=*/true, "The nonce"},
                    {RPCResult::Type::STR_HEX, "bits", /*optional=*/true, "The bits"},
                    {RPCResult::Type::NUM, "difficulty", /*optional=*/true, "The difficulty"},
                    {RPCResult::Type::STR_HEX, "chainwork", /*optional=*/true, "Expected number of hashes required to produce the chain up to this block"},
                    {RPCResult::Type::NUM, "nTx", "The number of transactions in the block"},
                    {RPCResult::Type::STR, "signblock_witness_asm", /*optional=*/true, "ASM of sign block witness data"},
                    {RPCResult::Type::STR_HEX, "signblock_witness_hex", /*optional=*/true, "Hex of sign block witness data"},
                    {RPCResult::Type::STR_HEX, "signblock_challenge", /*optional=*/true, "Hex of sign block challenge"},
                    {RPCResult::Type::STR, "warning", /*optional=*/true, "Warning message if block was not loaded cleanly"},
                    {RPCResult::Type::OBJ, "dynamic_parameters", /*optional=*/true, "Dynamic federation parameters in the block, if any",
                    {
                        {RPCResult::Type::OBJ, "current", "enforced dynamic federation parameters. The signblockscript is published for each block, while others are published only at epoch start",
                        {
                            {RPCResult::Type::STR, "type", "one of \"null\", \"compact\", \"full\""},
                            {RPCResult::Type::STR_HEX, "root", /*optional=*/true, "parameter root"},
                            {RPCResult::Type::STR_HEX, "signblockscript", /*optional=*/true, "signblock script as hex"},
                            {RPCResult::Type::NUM, "max_block_witness", /*optional=*/true, "maximum serialized size of the block witness stack"},
                            {RPCResult::Type::STR_HEX, "extra_root", /*optional=*/true, "extra root"},
                            {RPCResult::Type::STR_HEX, "fedpeg_program", /*optional=*/true, "fedpeg program scriptPubKey in hex"},
                            {RPCResult::Type::STR_HEX, "fedpegscript", /*optional=*/true, "fedpeg script in hex"},
                            {RPCResult::Type::ARR, "extension_space", /*optional=*/true, "extension space as hex strings",
                            {
                                {RPCResult::Type::ELISION, "", ""}
                            }},
                        }},
                        {RPCResult::Type::OBJ, "proposed", "Proposed parameters. Unenforced. Must be published in full",
                        {
                            {RPCResult::Type::ELISION, "", "same entries as \"current\""}
                        }},
                    }},
                    {RPCResult::Type::OBJ, "utreexo", /*optional=*/true, "Post-block accumulator on the isolated Utreexo test chain",
                    {
                        {RPCResult::Type::NUM, "leaves", "Cumulative leaf count, including spent leaves"},
                        {RPCResult::Type::ARR, "roots", "Forest roots in commitment order",
                        {{RPCResult::Type::STR_HEX, "", "Root hash"}}},
                    }},
                    {RPCResult::Type::STR_HEX, "previousblockhash", /*optional=*/true, "The hash of the previous block (if available)"},
                    {RPCResult::Type::STR_HEX, "nextblockhash", /*optional=*/true, "The hash of the next block (if available)"},
                }},
                    RPCResult{"for verbosity = 2",
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::ELISION, "", "Same output as verbosity = 1"},
                    {RPCResult::Type::ARR, "tx", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::ELISION, "", "The transactions in the format of the getrawtransaction RPC. Different from verbosity = 1 \"tx\" result"},
                            {RPCResult::Type::NUM, "fee", "The transaction fee in " + CURRENCY_UNIT + ", omitted if block undo data is not available"},
                        }},
                    }},
                }},
                    RPCResult{"for verbosity = 3",
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::ELISION, "", "Same output as verbosity = 2"},
                    {RPCResult::Type::ARR, "tx", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            getblock_vin,
                        }},
                    }},
                }},
        },
                RPCExamples{
                    HelpExampleCli("getblock", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
            + HelpExampleRpc("getblock", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    uint256 hash(ParseHashV(request.params[0], "blockhash"));

    int verbosity{ParseVerbosity(request.params[1], /*default_verbosity=*/1, /*allow_bool=*/true)};

    const CBlockIndex* pblockindex;
    const CBlockIndex* tip;
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    {
        LOCK(cs_main);
        pblockindex = chainman.m_blockman.LookupBlockIndex(hash);
        tip = chainman.ActiveChain().Tip();

        if (!pblockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
    }

    const std::vector<uint8_t> block_data{GetRawBlockChecked(chainman.m_blockman, *pblockindex)};

    if (verbosity <= 0) {
        return HexStr(block_data);
    }

    DataStream block_stream{block_data};
    CBlock block{};
    block_stream >> TX_WITH_WITNESS(block);

    TxVerbosity tx_verbosity;
    if (verbosity == 1) {
        tx_verbosity = TxVerbosity::SHOW_TXID;
    } else if (verbosity == 2) {
        tx_verbosity = TxVerbosity::SHOW_DETAILS;
    } else {
        tx_verbosity = TxVerbosity::SHOW_DETAILS_AND_PREVOUT;
    }

    return blockToJSON(chainman.m_blockman, block, *tip, *pblockindex, tx_verbosity, chainman.GetConsensus().powLimit);
},
    };
}

//! Return height of highest block that has been pruned, or std::nullopt if no blocks have been pruned
std::optional<int> GetPruneHeight(const BlockManager& blockman, const CChain& chain) {
    AssertLockHeld(::cs_main);

    // Search for the last block missing block data or undo data. Don't let the
    // search consider the genesis block, because the genesis block does not
    // have undo data, but should not be considered pruned.
    const CBlockIndex* first_block{chain[1]};
    const CBlockIndex* chain_tip{chain.Tip()};

    // If there are no blocks after the genesis block, or no blocks at all, nothing is pruned.
    if (!first_block || !chain_tip) return std::nullopt;

    // If the chain tip is pruned, everything is pruned.
    if (!((chain_tip->nStatus & BLOCK_HAVE_MASK) == BLOCK_HAVE_MASK)) return chain_tip->nHeight;

    const auto& first_unpruned{*CHECK_NONFATAL(blockman.GetFirstBlock(*chain_tip, /*status_mask=*/BLOCK_HAVE_MASK, first_block))};
    if (&first_unpruned == first_block) {
        // All blocks between first_block and chain_tip have data, so nothing is pruned.
        return std::nullopt;
    }

    // Block before the first unpruned block is the last pruned block.
    return CHECK_NONFATAL(first_unpruned.pprev)->nHeight;
}

static RPCHelpMan pruneblockchain()
{
    return RPCHelpMan{"pruneblockchain", "",
                {
                    {"height", RPCArg::Type::NUM, RPCArg::Optional::NO, "The block height to prune up to. May be set to a discrete height, or to a " + UNIX_EPOCH_TIME + "\n"
            "                  to prune blocks whose block time is at least 2 hours older than the provided timestamp."},
                },
                RPCResult{
                    RPCResult::Type::NUM, "", "Height of the last block pruned"},
                RPCExamples{
                    HelpExampleCli("pruneblockchain", "1000")
            + HelpExampleRpc("pruneblockchain", "1000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    if (!chainman.m_blockman.IsPruneMode()) {
        throw JSONRPCError(RPC_MISC_ERROR, "Cannot prune blocks because node is not in prune mode.");
    }

    LOCK(cs_main);
    Chainstate& active_chainstate = chainman.ActiveChainstate();
    CChain& active_chain = active_chainstate.m_chain;

    int heightParam = request.params[0].getInt<int>();
    if (heightParam < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative block height.");
    }

    // Height value more than a billion is too high to be a block height, and
    // too low to be a block time (corresponds to timestamp from Sep 2001).
    if (heightParam > 1000000000) {
        // Add a 2 hour buffer to include blocks which might have had old timestamps
        const CBlockIndex* pindex = active_chain.FindEarliestAtLeast(heightParam - TIMESTAMP_WINDOW, 0);
        if (!pindex) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Could not find block with at least the specified timestamp.");
        }
        heightParam = pindex->nHeight;
    }

    unsigned int height = (unsigned int) heightParam;
    unsigned int chainHeight = (unsigned int) active_chain.Height();
    if (chainHeight < chainman.GetParams().PruneAfterHeight()) {
        throw JSONRPCError(RPC_MISC_ERROR, "Blockchain is too short for pruning.");
    } else if (height > chainHeight) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Blockchain is shorter than the attempted prune height.");
    } else if (height > chainHeight - MIN_BLOCKS_TO_KEEP) {
        LogDebug(BCLog::RPC, "Attempt to prune blocks close to the tip.  Retaining the minimum number of blocks.\n");
        height = chainHeight - MIN_BLOCKS_TO_KEEP;
    }

    PruneBlockFilesManual(active_chainstate, height);
    return GetPruneHeight(chainman.m_blockman, active_chain).value_or(-1);
},
    };
}

CoinStatsHashType ParseHashType(const std::string& hash_type_input)
{
    if (hash_type_input == "hash_serialized_3") {
        return CoinStatsHashType::HASH_SERIALIZED;
    } else if (hash_type_input == "muhash") {
        return CoinStatsHashType::MUHASH;
    } else if (hash_type_input == "none") {
        return CoinStatsHashType::NONE;
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("'%s' is not a valid hash_type", hash_type_input));
    }
}

/**
 * Calculate statistics about the unspent transaction output set
 *
 * @param[in] index_requested Signals if the coinstatsindex should be used (when available).
 */
static std::optional<kernel::CCoinsStats> GetUTXOStats(CCoinsView* view, node::BlockManager& blockman,
                                                       kernel::CoinStatsHashType hash_type,
                                                       const std::function<void()>& interruption_point = {},
                                                       const CBlockIndex* pindex = nullptr,
                                                       bool index_requested = true)
{
    // Use CoinStatsIndex if it is requested and available and a hash_type of Muhash or None was requested
    if ((hash_type == kernel::CoinStatsHashType::MUHASH || hash_type == kernel::CoinStatsHashType::NONE) && g_coin_stats_index && index_requested) {
        if (pindex) {
            return g_coin_stats_index->LookUpStats(*pindex);
        } else {
            CBlockIndex& block_index = *CHECK_NONFATAL(WITH_LOCK(::cs_main, return blockman.LookupBlockIndex(view->GetBestBlock())));
            return g_coin_stats_index->LookUpStats(block_index);
        }
    }

    // If the coinstats index isn't requested or is otherwise not usable, the
    // pindex should either be null or equal to the view's best block. This is
    // because without the coinstats index we can only get coinstats about the
    // best block.
    CHECK_NONFATAL(!pindex || pindex->GetBlockHash() == view->GetBestBlock());

    return kernel::ComputeUTXOStats(hash_type, view, blockman, interruption_point);
}

static RPCHelpMan gettxoutsetinfo()
{
    return RPCHelpMan{"gettxoutsetinfo",
                "\nReturns statistics about the unspent transaction output set.\n"
                "Note this call may take some time if you are not using coinstatsindex.\n",
                {
                    {"hash_type", RPCArg::Type::STR, RPCArg::Default{"hash_serialized_3"}, "Which UTXO set hash should be calculated. Options: 'hash_serialized_3' (the legacy algorithm), 'muhash', 'none'."},
                    {"hash_or_height", RPCArg::Type::NUM, RPCArg::DefaultHint{"the current best block"}, "The block hash or height of the target height (only available with coinstatsindex).",
                     RPCArgOptions{
                         .skip_type_check = true,
                         .type_str = {"", "string or numeric"},
                     }},
                    {"use_index", RPCArg::Type::BOOL, RPCArg::Default{true}, "Use coinstatsindex, if available."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "height", "The block height (index) of the returned statistics"},
                        {RPCResult::Type::STR_HEX, "bestblock", "The hash of the block at which these statistics are calculated"},
                        {RPCResult::Type::NUM, "txouts", "The number of unspent transaction outputs"},
                        {RPCResult::Type::NUM, "bogosize", "Database-independent, meaningless metric indicating the UTXO set size"},
                        {RPCResult::Type::STR_HEX, "hash_serialized_3", /*optional=*/true, "The serialized hash (only present if 'hash_serialized_3' hash_type is chosen)"},
                        {RPCResult::Type::STR_HEX, "muhash", /*optional=*/true, "The serialized hash (only present if 'muhash' hash_type is chosen)"},
                        {RPCResult::Type::NUM, "transactions", /*optional=*/true, "The number of transactions with unspent outputs (not available when coinstatsindex is used)"},
                        {RPCResult::Type::NUM, "disk_size", /*optional=*/true, "The estimated size of the chainstate on disk (not available when coinstatsindex is used)"},
                        {RPCResult::Type::STR_AMOUNT, "total_amount", "The total amount of coins in the UTXO set"},
                        {RPCResult::Type::STR_AMOUNT, "total_unspendable_amount", /*optional=*/true, "The total amount of coins permanently excluded from the UTXO set (only available if coinstatsindex is used)"},
                        {RPCResult::Type::OBJ, "block_info", /*optional=*/true, "Info on amounts in the block at this block height (only available if coinstatsindex is used)",
                        {
                            {RPCResult::Type::STR_AMOUNT, "prevout_spent", "Total amount of all prevouts spent in this block"},
                            {RPCResult::Type::STR_AMOUNT, "coinbase", "Coinbase subsidy amount of this block"},
                            {RPCResult::Type::STR_AMOUNT, "new_outputs_ex_coinbase", "Total amount of new outputs created by this block"},
                            {RPCResult::Type::STR_AMOUNT, "unspendable", "Total amount of unspendable outputs created in this block"},
                            {RPCResult::Type::OBJ, "unspendables", "Detailed view of the unspendable categories",
                            {
                                {RPCResult::Type::STR_AMOUNT, "genesis_block", "The unspendable amount of the Genesis block subsidy"},
                                {RPCResult::Type::STR_AMOUNT, "bip30", "Transactions overridden by duplicates (no longer possible with BIP30)"},
                                {RPCResult::Type::STR_AMOUNT, "scripts", "Amounts sent to scripts that are unspendable (for example OP_RETURN outputs)"},
                                {RPCResult::Type::STR_AMOUNT, "unclaimed_rewards", "Fee rewards that miners did not claim in their coinbase transaction"},
                            }}
                        }},
                    }},
                RPCExamples{
                    HelpExampleCli("gettxoutsetinfo", "") +
                    HelpExampleCli("gettxoutsetinfo", R"("none")") +
                    HelpExampleCli("gettxoutsetinfo", R"("none" 1000)") +
                    HelpExampleCli("gettxoutsetinfo", R"("none" '"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09"')") +
                    HelpExampleCli("-named gettxoutsetinfo", R"(hash_type='muhash' use_index='false')") +
                    HelpExampleRpc("gettxoutsetinfo", "") +
                    HelpExampleRpc("gettxoutsetinfo", R"("none")") +
                    HelpExampleRpc("gettxoutsetinfo", R"("none", 1000)") +
                    HelpExampleRpc("gettxoutsetinfo", R"("none", "00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09")")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue ret(UniValue::VOBJ);

    const CBlockIndex* pindex{nullptr};
    const CoinStatsHashType hash_type{request.params[0].isNull() ? CoinStatsHashType::HASH_SERIALIZED : ParseHashType(request.params[0].get_str())};
    bool index_requested = request.params[2].isNull() || request.params[2].get_bool();

    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    Chainstate& active_chainstate = chainman.ActiveChainstate();
    active_chainstate.ForceFlushStateToDisk();

    CCoinsView* coins_view;
    BlockManager* blockman;
    {
        LOCK(::cs_main);
        coins_view = &active_chainstate.CoinsDB();
        blockman = &active_chainstate.m_blockman;
        pindex = blockman->LookupBlockIndex(coins_view->GetBestBlock());
    }

    if (!request.params[1].isNull()) {
        if (!g_coin_stats_index) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Querying specific block heights requires coinstatsindex");
        }

        if (hash_type == CoinStatsHashType::HASH_SERIALIZED) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "hash_serialized_3 hash type cannot be queried for a specific block");
        }

        if (!index_requested) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot set use_index to false when querying for a specific block");
        }
        pindex = ParseHashOrHeight(request.params[1], chainman);
    }

    if (index_requested && g_coin_stats_index) {
        if (!g_coin_stats_index->BlockUntilSyncedToCurrentChain()) {
            const IndexSummary summary{g_coin_stats_index->GetSummary()};

            // If a specific block was requested and the index has already synced past that height, we can return the
            // data already even though the index is not fully synced yet.
            if (pindex->nHeight > summary.best_block_height) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Unable to get data because coinstatsindex is still syncing. Current height: %d", summary.best_block_height));
            }
        }
    }

    const std::optional<CCoinsStats> maybe_stats = GetUTXOStats(coins_view, *blockman, hash_type, node.rpc_interruption_point, pindex, index_requested);
    if (maybe_stats.has_value()) {
        const CCoinsStats& stats = maybe_stats.value();
        ret.pushKV("height", (int64_t)stats.nHeight);
        ret.pushKV("bestblock", stats.hashBlock.GetHex());
        ret.pushKV("txouts", (int64_t)stats.nTransactionOutputs);
        ret.pushKV("bogosize", (int64_t)stats.nBogoSize);
        if (hash_type == CoinStatsHashType::HASH_SERIALIZED) {
            ret.pushKV("hash_serialized_3", stats.hashSerialized.GetHex());
        }
        if (hash_type == CoinStatsHashType::MUHASH) {
            ret.pushKV("muhash", stats.hashSerialized.GetHex());
        }
        CHECK_NONFATAL(stats.total_amount.has_value());
        ret.pushKV("total_amount", ValueFromAmount(stats.total_amount.value()));
        if (!stats.index_used) {
            ret.pushKV("transactions", static_cast<int64_t>(stats.nTransactions));
            ret.pushKV("disk_size", stats.nDiskSize);
        } else {
            ret.pushKV("total_unspendable_amount", ValueFromAmount(stats.total_unspendable_amount));

            CCoinsStats prev_stats{};
            if (pindex->nHeight > 0) {
                const std::optional<CCoinsStats> maybe_prev_stats = GetUTXOStats(coins_view, *blockman, hash_type, node.rpc_interruption_point, pindex->pprev, index_requested);
                if (!maybe_prev_stats) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read UTXO set");
                }
                prev_stats = maybe_prev_stats.value();
            }

            UniValue block_info(UniValue::VOBJ);
            block_info.pushKV("prevout_spent", ValueFromAmount(stats.total_prevout_spent_amount - prev_stats.total_prevout_spent_amount));
            block_info.pushKV("coinbase", ValueFromAmount(stats.total_coinbase_amount - prev_stats.total_coinbase_amount));
            block_info.pushKV("new_outputs_ex_coinbase", ValueFromAmount(stats.total_new_outputs_ex_coinbase_amount - prev_stats.total_new_outputs_ex_coinbase_amount));
            block_info.pushKV("unspendable", ValueFromAmount(stats.total_unspendable_amount - prev_stats.total_unspendable_amount));

            UniValue unspendables(UniValue::VOBJ);
            unspendables.pushKV("genesis_block", ValueFromAmount(stats.total_unspendables_genesis_block - prev_stats.total_unspendables_genesis_block));
            unspendables.pushKV("bip30", ValueFromAmount(stats.total_unspendables_bip30 - prev_stats.total_unspendables_bip30));
            unspendables.pushKV("scripts", ValueFromAmount(stats.total_unspendables_scripts - prev_stats.total_unspendables_scripts));
            unspendables.pushKV("unclaimed_rewards", ValueFromAmount(stats.total_unspendables_unclaimed_rewards - prev_stats.total_unspendables_unclaimed_rewards));
            block_info.pushKV("unspendables", std::move(unspendables));

            ret.pushKV("block_info", std::move(block_info));
        }
    } else {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read UTXO set");
    }
    return ret;
},
    };
}

static RPCHelpMan gettxout()
{
    return RPCHelpMan{"gettxout",
        "\nReturns details about an unspent transaction output.\n",
        {
            {"txid", RPCArg::Type::STR, RPCArg::Optional::NO, "The transaction id"},
            {"n", RPCArg::Type::NUM, RPCArg::Optional::NO, "vout number"},
            {"include_mempool", RPCArg::Type::BOOL, RPCArg::Default{true}, "Whether to include the mempool. Note that an unspent output that is spent in the mempool won't appear."},
        },
        {
            RPCResult{"If the UTXO was not found", RPCResult::Type::NONE, "", ""},
            RPCResult{"Otherwise", RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR_HEX, "bestblock", "The hash of the block at the tip of the chain"},
                {RPCResult::Type::NUM, "confirmations", "The number of confirmations"},
                {RPCResult::Type::STR_AMOUNT, "value", /*optional=*/true, "The transaction value in " + CURRENCY_UNIT},
                {RPCResult::Type::STR_HEX, "valuecommitment", /*optional=*/true, "Hex-encoded value commitment"},
                {RPCResult::Type::STR_HEX, "asset", /*optional=*/true, "Explicit asset id"},
                {RPCResult::Type::STR_HEX, "assetcommitment", /*optional=*/true, "Hex-encoded asset commitment"},
                {RPCResult::Type::STR_HEX, "commitmentnonce", /*optional=*/true, "Output nonce / commitment field"},
                {RPCResult::Type::OBJ, "scriptPubKey", "", {
                    {RPCResult::Type::STR, "asm", "Disassembly of the output script"},
                    {RPCResult::Type::STR, "desc", "Inferred descriptor for the output"},
                    {RPCResult::Type::STR_HEX, "hex", "The raw output script bytes, hex-encoded"},
                    {RPCResult::Type::STR, "type", "The type, eg pubkeyhash"},
                    {RPCResult::Type::STR, "address", /*optional=*/true, "The Bitcoin address (only if a well-defined address exists)"},
                }},
                {RPCResult::Type::BOOL, "coinbase", "Coinbase or not"},
            }},
        },
        RPCExamples{
            "\nGet unspent transactions\n"
            + HelpExampleCli("listunspent", "") +
            "\nView the details\n"
            + HelpExampleCli("gettxout", "\"txid\" 1") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("gettxout", "\"txid\", 1")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    LOCK(cs_main);

    UniValue ret(UniValue::VOBJ);

    auto hash{Txid::FromUint256(ParseHashV(request.params[0], "txid"))};
    COutPoint out{hash, request.params[1].getInt<uint32_t>()};
    bool fMempool = true;
    if (!request.params[2].isNull())
        fMempool = request.params[2].get_bool();

    Chainstate& active_chainstate = chainman.ActiveChainstate();
    CCoinsViewCache* coins_view = &active_chainstate.CoinsTip();

    std::optional<Coin> coin;
    if (fMempool) {
        const CTxMemPool& mempool = EnsureMemPool(node);
        LOCK(mempool.cs);
        CCoinsViewMemPool view(coins_view, mempool);
        if (!mempool.isSpent(out)) coin = view.GetCoin(out);
    } else {
        coin = coins_view->GetCoin(out);
    }
    if (!coin) return UniValue::VNULL;

    const CBlockIndex* pindex = active_chainstate.m_blockman.LookupBlockIndex(coins_view->GetBestBlock());
    ret.pushKV("bestblock", pindex->GetBlockHash().GetHex());
    if (coin->nHeight == MEMPOOL_HEIGHT) {
        ret.pushKV("confirmations", 0);
    } else {
        ret.pushKV("confirmations", (int64_t)(pindex->nHeight - coin->nHeight + 1));
    }
    if (coin->out.nValue.IsExplicit()) {
        ret.pushKV("value", ValueFromAmount(coin->out.nValue.GetAmount()));
    } else {
        ret.pushKV("valuecommitment", coin->out.nValue.GetHex());
    }
    if (g_con_elementsmode) {
        if (coin->out.nAsset.IsExplicit()) {
            ret.pushKV("asset", coin->out.nAsset.GetAsset().GetHex());
        } else {
            ret.pushKV("assetcommitment", coin->out.nAsset.GetHex());
        }

        ret.pushKV("commitmentnonce", coin->out.nNonce.GetHex());
    }
    UniValue o(UniValue::VOBJ);
    ScriptToUniv(coin->out.scriptPubKey, /*out=*/o, /*include_hex=*/true, /*include_address=*/true);
    ret.pushKV("scriptPubKey", std::move(o));
    ret.pushKV("coinbase", (bool)coin->fCoinBase);

    return ret;
},
    };
}

static RPCHelpMan getecxstateutxoroot()
{
    return RPCHelpMan{"getecxstateutxoroot",
        "Compute the exact consensus ECX header root for an existing unspent output.\n"
        "This is intended for freezing an activated-regtest genesis singleton.\n",
        {
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The singleton transaction id"},
            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The singleton output index"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "root", "ECX/header-state/v1 root in display hex"},
            {RPCResult::Type::BOOL, "eligible", "Whether the output has the required explicit asset/value, null nonce and P2TR shape"},
            {RPCResult::Type::NUM, "height", "UTXO creation height"},
        }},
        RPCExamples{
            HelpExampleCli("getecxstateutxoroot", "\"txid\" 0") +
            HelpExampleRpc("getecxstateutxoroot", "\"txid\", 0")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (!drivechain::haskell::ExchangeAvailable(drivechain::haskell::Availability::RPC,
            [](uint32_t) { return Params().GetConsensus().elements_mode; })) {
        throw JSONRPCError(
            RPC_MISC_ERROR,
            "ECX state is unavailable outside an Elements-mode chain");
    }
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    LOCK(cs_main);

    const uint256 txid{ParseHashV(request.params[0], "txid")};
    const int vout = request.params[1].getInt<int>();
    COutPoint outpoint;
    std::optional<Coin> coin;
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::REQUIRED_PAIR_ERRORS,
        [&](uint32_t step) EXCLUSIVE_LOCKS_REQUIRED(cs_main) -> uint32_t {
        switch (step) {
        case 1: return vout >= 0;
        case 2: throw JSONRPCError(RPC_INVALID_PARAMETER, "vout must be nonnegative");
        case 3:
            outpoint = COutPoint{Txid::FromUint256(txid), static_cast<uint32_t>(vout)};
            coin = chainman.ActiveChainstate().CoinsTip().GetCoin(outpoint);
            return coin.has_value();
        case 4: throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "ECX singleton UTXO not found");
        default: throw std::logic_error("invalid ECX UTXO admission action");
        }
    });

    UniValue result(UniValue::VOBJ);
    result.pushKV(
        "root",
        ecx::ComputeStateUtxoRoot(
            Params().GetConsensus().hashGenesisBlock,
            outpoint,
            coin->out).GetHex());
    result.pushKV("eligible", ecx::IsStateAuthorityOutput(coin->out));
    result.pushKV("height", static_cast<uint64_t>(coin->nHeight));
    return result;
},
    };
}

static RPCHelpMan getecxconsensuscontext()
{
    return RPCHelpMan{"getecxconsensuscontext",
        "Return the fail-closed ECX source heads and authenticated BMM clock "
        "used for mempool and next-block Simplicity execution.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::NUM, "sidechainheight", "Active sidechain height"},
            {RPCResult::Type::STR_HEX, "sidechainblockhash", "Active sidechain block hash"},
            {RPCResult::Type::STR_HEX, "exchangestateroot", "Active ECX singleton root"},
            {RPCResult::Type::OBJ, "forcedinbox", "Consensus forced-action source head", {
                {RPCResult::Type::STR_HEX, "headroot", "Append-only forced inbox root"},
                {RPCResult::Type::NUM, "entrycount", "Number of forced actions committed through this head"},
                {RPCResult::Type::NUM, "nextindex", "Index assigned to the next forced action"},
                {RPCResult::Type::NUM, "processedcursor", "First unprocessed forced-action index"},
            }},
            {RPCResult::Type::OBJ, "depositinbox", "Consensus confidential-deposit source head", {
                {RPCResult::Type::STR_HEX, "headroot", "Append-only deposit inbox root"},
                {RPCResult::Type::NUM, "entrycount", "Number of deposits committed through this head"},
                {RPCResult::Type::NUM, "nextindex", "Index assigned to the next deposit"},
                {RPCResult::Type::NUM, "processedcursor", "First unprocessed deposit index"},
            }},
            {RPCResult::Type::OBJ, "bmm", "Authenticated prior-parent context", {
                {RPCResult::Type::BOOL, "authenticated", "Whether the context was derived from verified BMM state rather than the explicit regtest clock"},
                {RPCResult::Type::NUM, "parentheight", "BMM-authenticated parent height"},
                {RPCResult::Type::NUM, "parentmtp", "BMM-authenticated parent median time past"},
                {RPCResult::Type::STR_HEX, "parentblockhash", "BMM-authenticated parent block hash"},
            }},
            {RPCResult::Type::NUM, "sourceparentheight", "Approval height committed by the active ECX header"},
            {RPCResult::Type::OBJ, "capital", /*optional=*/true, "Verified V2 public capital projection (present only for a frozen V2 deployment)", {
                {RPCResult::Type::NUM, "version", "Capital projection version"},
                {RPCResult::Type::STR_HEX, "exchangestateroot", "Root selecting this exact projection"},
                {RPCResult::Type::STR_HEX, "configurationhash", "Frozen V2 configuration"},
                {RPCResult::Type::STR_HEX, "bondassetid", "Verified fixed-supply bond asset"},
                {RPCResult::Type::STR_HEX, "bonddeploymentcommitment", "Verified deployment envelope"},
                {RPCResult::Type::STR_HEX, "transitionprogramid", "Frozen SP1 transition program"},
                {RPCResult::Type::STR_HEX, "transitioncmr", "Frozen Simplicity transition CMR"},
                {RPCResult::Type::NUM, "insurancereservequoteunits", "Public aggregate insurance reserve"},
                {RPCResult::Type::NUM, "outstandingbondunits", "Public outstanding share atoms"},
                {RPCResult::Type::NUM, "navquoteunitsperbond", "Execution-time NAV per whole share"},
                {RPCResult::Type::NUM, "deficitquoteunits", "Worst full-range portfolio deficit"},
                {RPCResult::Type::NUM, "targetreservequoteunits", "Ceiling of 125% deficit coverage"},
                {RPCResult::Type::NUM, "coveragebps", "Public coverage ratio"},
                {RPCResult::Type::STR, "mode", "Normal, ReduceOnly, or Recovery"},
                {RPCResult::Type::NUM, "fundingepoch", "Last deterministic funding epoch"},
                {RPCResult::Type::STR_HEX, "redemptionqueueroot", "FIFO redemption queue root"},
                {RPCResult::Type::NUM, "redemptionhead", "FIFO head"},
                {RPCResult::Type::NUM, "redemptiontail", "FIFO tail"},
                {RPCResult::Type::NUM, "queuedredemptionbondunits", "Public queued share aggregate"},
                {RPCResult::Type::NUM, "legacyfeepoolquoteunits", "Always zero in V2"},
            }},
        }},
        RPCExamples{
            HelpExampleCli("getecxconsensuscontext", "") +
            HelpExampleRpc("getecxconsensuscontext", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (!drivechain::haskell::ExchangeAvailable(drivechain::haskell::Availability::RPC,
            [](uint32_t) { return Params().GetConsensus().elements_mode; })) {
        throw JSONRPCError(
            RPC_MISC_ERROR,
            "ECX consensus context is unavailable outside an Elements-mode chain");
    }
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    const CBlockIndex* tip{chainman.ActiveChain().Tip()};
    std::string context_error;
    ecx::ExchangeConsensusSnapshot exchange;
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::REQUIRED_PAIR_ERRORS,
        [&](uint32_t step) EXCLUSIVE_LOCKS_REQUIRED(cs_main) -> uint32_t {
        switch (step) {
        case 1: return tip != nullptr;
        case 2: throw JSONRPCError(RPC_MISC_ERROR, "active sidechain tip is unavailable");
        case 3: return ecx::GetExchangeConsensusSnapshot(
            chainman.ActiveChainstate().CoinsTip(), tip, exchange, context_error);
        case 4: throw JSONRPCError(RPC_MISC_ERROR, context_error);
        default: throw std::logic_error("invalid ECX context admission action");
        }
    });
    drivechain::BmmParentContext bmm;
    bool bmm_authenticated{true};
    drivechain::BmmL1State bmm_state;
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::PARENT_REPORT,
        [&](uint32_t step) EXCLUSIVE_LOCKS_REQUIRED(cs_main) -> uint32_t {
        switch (step) {
        case 1: return Params().GetConsensus().drivechain_slot.has_value();
        // Report authenticated P, not its M7 inclusion Q or the mempool parent.
        case 2: return GetPriorActiveBmmParentCheckpoint(tip, Params().GetConsensus()).has_value();
        case 3: throw JSONRPCError(
                RPC_MISC_ERROR,
                "active native ECX tip has no authenticated parent checkpoint");
        case 4: {
        const DrivechainAnchor& anchor{*tip->m_drivechain_anchor};
        bmm.block_hash = anchor.parent_block_hash;
        bmm.height = anchor.parent_height;
        bmm.median_time_past = anchor.parent_median_time_past;
        return 1;
        }
        case 5: return drivechain::GetEffectiveBmmState(chainman.ActiveChainstate().CoinsTip(),tip,bmm_state,context_error);
        case 6: return drivechain::GetBmmParentContext(bmm_state,bmm,context_error);
        case 7: throw JSONRPCError(RPC_MISC_ERROR,context_error);
        case 8: return Params().NetworkIDString() == "elementsregtest";
        case 9: return tip->ecxParentHeight;
        case 10: throw JSONRPCError(
                RPC_MISC_ERROR,
                "active ECX regtest tip has no synthetic parent height");
        case 11:
        bmm.block_hash.SetNull();
        bmm.height = tip->ecxParentHeight;
        bmm.median_time_past = tip->GetMedianTimePast();
        bmm_authenticated = false;
        return 1;
        case 12: return tip->ecxParentHeight;
        case 13: return tip->ecxParentHeight == bmm.height;
        case 14: throw JSONRPCError(
            RPC_MISC_ERROR,
            "active ECX header approval height disagrees with BMM chainstate");
        default: throw std::logic_error("invalid parent report action");
        }
    });

    const auto inbox_json = [](const uint256& root, uint64_t count, uint64_t cursor) {
        UniValue inbox(UniValue::VOBJ);
        inbox.pushKV("headroot",root.GetHex());
        inbox.pushKV("entrycount",count);
        inbox.pushKV("nextindex",count);
        inbox.pushKV("processedcursor",cursor);
        return inbox;
    };
    UniValue parent(UniValue::VOBJ);
    parent.pushKV("authenticated", bmm_authenticated);
    parent.pushKV("parentheight", bmm.height);
    parent.pushKV("parentmtp", bmm.median_time_past);
    parent.pushKV("parentblockhash", bmm.block_hash.GetHex());

    UniValue result(UniValue::VOBJ);
    result.pushKV("sidechainheight", static_cast<uint64_t>(tip->nHeight));
    result.pushKV("sidechainblockhash", tip->GetBlockHash().GetHex());
    result.pushKV("exchangestateroot", exchange.exchange_state_root.GetHex());
    result.pushKV("forcedinbox", inbox_json(exchange.forced_inbox_root,exchange.forced_entry_count,exchange.forced_processed_cursor));
    result.pushKV("depositinbox", inbox_json(exchange.deposit_inbox_root,exchange.deposit_entry_count,exchange.deposit_processed_cursor));
    result.pushKV("bmm", parent);
    result.pushKV("sourceparentheight", static_cast<uint64_t>(tip->ecxParentHeight));
    result.pushKV(
        "sourcebacklogoldestparentheight",
        exchange.source_backlog_oldest_parent_height);
    const ecx::ExchangeConsensus& frozen{ecx::LayerTwoLabsExchangeConsensus()};
    static_assert(ecx::BOND_V2_CAPITAL_SNAPSHOT_VERSION == 4);
    if (drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::CAPITAL_REPORT,
        [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return frozen.bond_v2.activation_enabled;
        case 2: return tip->ecxBondV2Capital.has_value();
        case 3: throw JSONRPCError(
                RPC_MISC_ERROR,
                "active ECX V2 tip has no fully verified capital projection");
        default: break;
        }
        const ecx::BondV2CapitalSnapshot& capital{*tip->ecxBondV2Capital};
        switch (step) {
            case 4: return capital.version;
            case 5: return drivechain::haskell::ExchangeCarryIdentity(capital.proof_profile,
                std::array<const unsigned char*,15>{
                    capital.configuration_hash.begin(),capital.transition_program_id.begin(),capital.transition_cmr.begin(),
                    capital.exchange_state_root.begin(),capital.bond_asset_id.begin(),capital.bond_deployment_commitment.begin(),
                    frozen.bond_v2.configuration_hash.begin(),frozen.bond_v2.transition_program_id.begin(),frozen.bond_v2.transition_cmr.begin(),
                    frozen.bond_v2.incremental_successor_configuration_hash.begin(),frozen.bond_v2.incremental_successor_program_id.begin(),
                    frozen.bond_v2.incremental_successor_transition_cmr.begin(),exchange.exchange_state_root.begin(),
                    frozen.bond_v2.bond_asset_id.begin(),frozen.bond_v2.bond_deployment_commitment.begin()});
            case 6: return capital.bond_inventory_covenant_hash == frozen.bond_v2.inventory_covenant_script_sha256;
            case 7: return capital.capital_mode;
            case 8: return capital.oracle_mode;
            case 9: return capital.operationally_safe;
            case 10: return capital.legacy_fee_pool == std::array<unsigned char,16>{};
            case 11: throw JSONRPCError(
                RPC_MISC_ERROR,
                "active ECX V2 capital projection is not root/frozen-identity bound");
            default: throw std::logic_error("invalid capital report action");
            }
        })) {
        const ecx::BondV2CapitalSnapshot& capital{*tip->ecxBondV2Capital};
        UniValue capital_json(UniValue::VOBJ);
        capital_json.pushKV("version", capital.version);
        capital_json.pushKV(
            "proofprofile", capital.proof_profile == 0 ? "finite-v18" : "incremental-successor");
        capital_json.pushKV("exchangestateroot", capital.exchange_state_root.GetHex());
        capital_json.pushKV("configurationhash", capital.configuration_hash.GetHex());
        capital_json.pushKV(
            "bondactionconfigurationhash", frozen.bond_v2.configuration_hash.GetHex());
        capital_json.pushKV("bondassetid", capital.bond_asset_id.GetHex());
        capital_json.pushKV(
            "bonddeploymentcommitment",
            capital.bond_deployment_commitment.GetHex());
        capital_json.pushKV("transitionprogramid", capital.transition_program_id.GetHex());
        capital_json.pushKV("transitioncmr", capital.transition_cmr.GetHex());
        capital_json.pushKV("covenantstatehash", capital.covenant_state_hash.GetHex());
        capital_json.pushKV("bondstateroot", capital.bond_state_root.GetHex());
        capital_json.pushKV("fundingstateroot", capital.funding_state_root.GetHex());
        capital_json.pushKV(
            "bondinventorycovenanthash", capital.bond_inventory_covenant_hash.GetHex());
        capital_json.pushKV("insurancereservequoteunits", EcxWideNumberToJSON(capital.insurance_reserve));
        capital_json.pushKV("issuedbondunits", capital.issued_share_atoms);
        capital_json.pushKV("outstandingbondunits", capital.outstanding_share_atoms);
        capital_json.pushKV("inventorybondunits", capital.inventory_share_atoms);
        capital_json.pushKV("navquoteunitsperbond", EcxWideNumberToJSON(capital.nav_per_whole_share));
        capital_json.pushKV("deficitquoteunits", EcxWideNumberToJSON(capital.full_bound_deficit));
        capital_json.pushKV("targetreservequoteunits", EcxWideNumberToJSON(capital.target_reserve));
        capital_json.pushKV("coveragebps", EcxWideNumberToJSON(capital.coverage_bps));
        capital_json.pushKV("controlledquoteunits", EcxWideNumberToJSON(capital.controlled_usdd_atoms));
        capital_json.pushKV("mode", drivechain::ECX_CAPITAL_MODES.at(capital.capital_mode));
        capital_json.pushKV("minimumauthenticatedprice", capital.minimum_authenticated_price);
        capital_json.pushKV("maximumauthenticatedprice", capital.maximum_authenticated_price);
        capital_json.pushKV("fundingepoch", capital.funding_epoch);
        capital_json.pushKV("fundingrateppm", capital.funding_rate_ppm);
        capital_json.pushKV(
            "globalfundingindexnumerator", EcxWideNumberToJSON(capital.global_funding_index_numerator,true));
        capital_json.pushKV("redemptionqueueroot", capital.redemption_queue_root.GetHex());
        capital_json.pushKV("redemptionhead", EcxWideNumberToJSON(capital.redemption_head.bytes));
        capital_json.pushKV("redemptiontail", EcxWideNumberToJSON(capital.redemption_tail.bytes));
        capital_json.pushKV(
            "queuedredemptionbondunits",
            capital.queued_redemption_share_atoms);
        UniValue oracle_json(UniValue::VOBJ);
        oracle_json.pushKV("certificatehash", capital.oracle_certificate_hash.GetHex());
        oracle_json.pushKV(
            "validthroughparentmtp", capital.oracle_valid_through_parent_mtp);
        oracle_json.pushKV("mode", drivechain::ECX_ORACLE_MODES.at(capital.oracle_mode));
        capital_json.pushKV("oracle", oracle_json);
        capital_json.pushKV(
            "encryptedavailabilityroot", capital.encrypted_availability_root.GetHex());
        UniValue bond_inbox_json(UniValue::VOBJ);
        bond_inbox_json.pushKV("headroot", capital.bond_inbox_head_root.GetHex());
        bond_inbox_json.pushKV("entrycount", EcxWideNumberToJSON(capital.bond_inbox_entry_count.bytes));
        bond_inbox_json.pushKV("processedroot", capital.bond_inbox_processed_root.GetHex());
        bond_inbox_json.pushKV(
            "processedcursor", EcxWideNumberToJSON(capital.bond_inbox_processed_cursor.bytes));
        bond_inbox_json.pushKV("outcomeroot", capital.bond_inbox_outcome_root.GetHex());
        bond_inbox_json.pushKV(
            "outcomecount", EcxWideNumberToJSON(capital.bond_inbox_outcome_count.bytes));
        bond_inbox_json.pushKV(
            "nodeverifiedsourceheadroot", capital.node_bond_inbox_head_root.GetHex());
        bond_inbox_json.pushKV(
            "nodeverifiedsourceentrycount", EcxWideNumberToJSON(capital.node_bond_inbox_entry_count.bytes));
        capital_json.pushKV("bondinbox", bond_inbox_json);
        UniValue execution_json(UniValue::VOBJ);
        execution_json.pushKV(
            "receiptbatchroot", capital.matcher_execution_receipt_batch_root.GetHex());
        execution_json.pushKV(
            "previoussequence", EcxWideNumberToJSON(capital.previous_matcher_execution_sequence.bytes));
        execution_json.pushKV("sequence", EcxWideNumberToJSON(capital.matcher_execution_sequence.bytes));
        capital_json.pushKV("matcherexecution", execution_json);
        capital_json.pushKV(
            "lasttransitionsidechainheight", capital.last_transition_sidechain_height);
        capital_json.pushKV("operationallysafe", capital.operationally_safe == 1);
        capital_json.pushKV("legacyfeepoolquoteunits", EcxWideNumberToJSON(capital.legacy_fee_pool));
        result.pushKV("capital", capital_json);
    }
    return result;
},
    };
}


static RPCHelpMan getecxbondinboxentries()
{
    return RPCHelpMan{"getecxbondinboxentries",
        "Reconstruct a bounded range of exact node-verified bond-inbox source "
        "entries from active-chain archival blocks. The returned finite "
        "700-byte or incremental-successor 708-byte records and "
        "witness-bearing source transactions are derived by the "
        "same parser used by consensus; producer-supplied projections are "
        "never accepted. The call fails if a block was pruned or the active "
        "chain changes while it is being read.\n",
        {
            {"start_height", RPCArg::Type::NUM, RPCArg::Optional::NO,
                "First active sidechain height to scan (at or after V2 activation)"},
            {"block_count", RPCArg::Type::NUM, RPCArg::Default{drivechain::BOND_EXPORT_DEFAULT_BLOCKS},
                "Number of active blocks to scan, 1..64; output stops before "
                "a block that would exceed eight returned entries"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::NUM, "schema_version", "Exact export schema, currently 4"},
            {RPCResult::Type::STR_HEX, "configurationhash", "Frozen V18 configuration"},
            {RPCResult::Type::NUM, "activationheight", "First height accepted by this frozen source lane"},
            {RPCResult::Type::STR_HEX, "capturedtiphash", "Active tip used for this reconstruction"},
            {RPCResult::Type::NUM, "capturedtipheight", "Captured active-tip height"},
            {RPCResult::Type::NUM, "startheight", "First reconstructed block"},
            {RPCResult::Type::NUM, "endheight", "Last reconstructed block, inclusive"},
            {RPCResult::Type::NUM, "nextheight", "Next block for a bounded continuation"},
            {RPCResult::Type::BOOL, "truncated", "Whether another block remains in the requested range"},
            {RPCResult::Type::STR_HEX, "endingheadroot", "Reconstructed node source head"},
            {RPCResult::Type::NUM, "endingentrycount", "Reconstructed node source count"},
            {RPCResult::Type::ARR, "entries", "Exact source entries", {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::NUM, "entryindex", "Canonical append index"},
                    {RPCResult::Type::NUM, "sidechainheight", "Containing active block height"},
                    {RPCResult::Type::NUM, "observedparentheight", "Authenticated observed parent height"},
                    {RPCResult::Type::NUM, "processdeadlineparentheight", "Exact ExpiredUnavailable boundary, observed parent height plus six"},
                    {RPCResult::Type::NUM, "refundnotbeforeparentheight", "Signed enqueue refund boundary, or zero for non-enqueue markers"},
                    {RPCResult::Type::NUM, "markerkind", "Canonical marker kind, 0..3"},
                    {RPCResult::Type::STR_HEX, "actionid", "Authenticated marker action identifier"},
                    {RPCResult::Type::NUM, "transactionindex", "Transaction index in the block"},
                    {RPCResult::Type::NUM, "markervout", "Exact marker output index"},
                    {RPCResult::Type::STR_HEX, "txid", "Source txid in display order"},
                    {RPCResult::Type::STR_HEX, "wtxid", "Source wtxid in display order"},
                    {RPCResult::Type::STR_HEX, "canonicalentryhex", "Exact canonical entry: 700 bytes for finite-v18 or 708 bytes for incremental-successor"},
                    {RPCResult::Type::STR_HEX, "sourcetransactionhex", "Exact witness-bearing transaction serialization"},
                }},
            }},
        }},
        RPCExamples{
            HelpExampleCli("getecxbondinboxentries", "100 1") +
            HelpExampleRpc("getecxbondinboxentries", "100, 1")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    const ecx::ExchangeConsensus& frozen{ecx::LayerTwoLabsExchangeConsensus()};
    if (!drivechain::haskell::ParentReplayAll<3>({
        [&] { return Params().GetConsensus().elements_mode; },
        [&] { return frozen.bond_v2.activation_enabled; },
        [&] { return frozen.bond_v2.identities_frozen; },
    })) {
        throw JSONRPCError(
            RPC_MISC_ERROR,
            "frozen ECX bond V2 source export is unavailable");
    }
    const int start_height{request.params[0].getInt<int>()};
    const int block_count{
        request.params[1].isNull() ? drivechain::BOND_EXPORT_DEFAULT_BLOCKS : request.params[1].getInt<int>()};
    int32_t requested_end{0};
    if (drivechain::haskell::ExchangeExportRange(start_height, block_count,
            frozen.activation_height, std::nullopt, requested_end)) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "start_height must be at/after V2 activation and block_count must be 1..64");
    }

    uint256 captured_tip_hash;
    int captured_tip_height{0};
    ecx::BondV2CapitalSnapshot working;
    std::vector<std::pair<const CBlockIndex*, ecx::BondV2CapitalSnapshot>> blocks;
    const auto has_projection = [](const CBlockIndex* index) {
        return drivechain::haskell::ParentReplayAll<2>({
            [&] { return index != nullptr; },
            [&] { return index->ecxBondV2Capital.has_value(); },
        });
    };
    {
        LOCK(cs_main);
        const CBlockIndex* tip{chainman.ActiveChain().Tip()};
        if (drivechain::haskell::ExchangeExportRange(start_height, block_count,
                frozen.activation_height, tip ? tip->nHeight : -1, requested_end)) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER, "start_height is beyond the active tip");
        }
        captured_tip_hash = tip->GetBlockHash();
        captured_tip_height = tip->nHeight;
        const CBlockIndex* previous{nullptr};
        drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::EXPORT_INITIALIZE,
            [&](uint32_t step) EXCLUSIVE_LOCKS_REQUIRED(cs_main) -> uint32_t {
            switch (step) {
            case 1: return start_height == frozen.activation_height;
            case 2:
                working.bond_inbox_head_root = ecx::BondInboxGenesisHead(frozen);
                working.node_bond_inbox_head_root = working.bond_inbox_head_root;
                return 1;
            case 3:
                previous = chainman.ActiveChain()[start_height - 1];
                return has_projection(previous);
            case 4: throw JSONRPCError(
                    RPC_MISC_ERROR,
                    "predecessor lacks a verified bond-inbox projection");
            case 5: working = *previous->ecxBondV2Capital; return 1;
            default: throw std::logic_error("invalid bond-inbox initialization action");
            }
        });
        const std::function<bool(int64_t)> capture = [&](int64_t height) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
            AssertLockHeld(cs_main);
            const CBlockIndex* index{chainman.ActiveChain()[static_cast<int>(height)]};
            if (!has_projection(index)) {
                throw JSONRPCError(
                    RPC_MISC_ERROR,
                    strprintf("height %d lacks a verified bond-inbox projection", height));
            }
            blocks.emplace_back(index, *index->ecxBondV2Capital);
            return true;
        };
        drivechain::haskell::ParentReplayEach(
            std::views::iota(int64_t{start_height}, int64_t{requested_end} + 1), capture);
    }

    std::vector<ecx::BondInboxSourceExport> exported;
    int end_height{start_height - 1};
    const bool truncated{!drivechain::haskell::ParentReplayEach(blocks, [&](const auto& entry) {
        const auto& [index, expected] = entry;
        CBlock block;
        if (!chainman.m_blockman.ReadBlock(block, *index)) {
            throw JSONRPCError(
                RPC_MISC_ERROR,
                strprintf("archival block unavailable at height %d", index->nHeight));
        }
        ecx::BondV2CapitalSnapshot candidate{working};
        std::vector<ecx::BondInboxSourceExport> block_entries;
        std::string error;
        drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::EXPORT_RECONSTRUCT,
            [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return expected.proof_profile;
            case 2: return working.proof_profile;
            case 3:
                candidate.proof_profile = 1;
                candidate.bond_inbox_head_root = ecx::IncrementalSuccessorBondInboxGenesisHead(frozen);
                candidate.node_bond_inbox_head_root = candidate.bond_inbox_head_root;
                candidate.bond_inbox_entry_count = 0;
                candidate.node_bond_inbox_entry_count = 0;
                return true;
            case 4: case 5: {
                const auto append_sources = step == 5
                    ? ecx::AppendIncrementalSuccessorBondInboxSourcesForBlock : ecx::AppendBondInboxSourcesForBlock;
                return append_sources(block, static_cast<uint64_t>(index->nHeight),
                    static_cast<uint64_t>(index->ecxParentHeight), candidate, error, frozen, &block_entries);
            }
            case 6: return candidate.node_bond_inbox_head_root == expected.node_bond_inbox_head_root;
            case 7: return candidate.node_bond_inbox_entry_count == expected.node_bond_inbox_entry_count;
            case 8:
                throw JSONRPCError(RPC_MISC_ERROR, "archival source reconstruction disagrees with the verified block index");
            case 9: throw JSONRPCError(RPC_MISC_ERROR, error);
            default: throw std::logic_error("invalid bond-inbox reconstruction action");
            }
        });
        if (drivechain::haskell::ParentReplayAll<2>({
            [&] { return !exported.empty(); },
            [&] { return drivechain::haskell::ParentReplayRecord(
                drivechain::haskell::ReplayRecordKind::LANE_EXCEEDED, drivechain::BOND_EXPORT_ENTRY_LIMIT, 0,
                exported.size(), block_entries.size()); },
        })) {
            return false;
        }
        exported.insert(
            exported.end(),
            std::make_move_iterator(block_entries.begin()),
            std::make_move_iterator(block_entries.end()));
        working = expected;
        end_height = index->nHeight;
        return true;
    })};

    {
        LOCK(cs_main);
        const CBlockIndex* tip{chainman.ActiveChain().Tip()};
        if (!drivechain::haskell::ParentReplayAll<3>({
            [&] { return tip != nullptr; },
            [&] { return tip->GetBlockHash() == captured_tip_hash; },
            [&] { return tip->nHeight == captured_tip_height; },
        })) {
            throw JSONRPCError(
                RPC_MISC_ERROR,
                "active chain changed while reconstructing bond-inbox entries");
        }
        const std::function<bool(const std::pair<const CBlockIndex*, ecx::BondV2CapitalSnapshot>&)> check_range =
            [&](const auto& entry) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
            AssertLockHeld(cs_main);
            const auto* index = entry.first;
            return bool(drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::EXPORT_RECHECK,
                [&](uint32_t step) EXCLUSIVE_LOCKS_REQUIRED(cs_main) -> uint32_t {
                switch (step) {
                case 1: return index->nHeight <= end_height;
                case 2: return chainman.ActiveChain()[index->nHeight] == index;
                case 3: throw JSONRPCError(
                    RPC_MISC_ERROR,
                    "bond-inbox export range was reorganized during reconstruction");
                default: throw std::logic_error("invalid bond-inbox recheck action");
                }
            }));
        };
        drivechain::haskell::ParentReplayEach(blocks, check_range);
    }

    UniValue entries(UniValue::VARR);
    for (const auto& entry : exported) {
        UniValue object(UniValue::VOBJ);
        object.pushKV("proofprofile", static_cast<uint64_t>(entry.proof_profile));
        object.pushKV("entryindex", EcxWideNumberToJSON(entry.entry_index_u128.bytes));
        object.pushKV("sidechainheight", entry.sidechain_height);
        object.pushKV("observedparentheight", entry.observed_parent_height);
        object.pushKV(
            "processdeadlineparentheight",
            entry.process_deadline_parent_height);
        object.pushKV(
            "refundnotbeforeparentheight",
            entry.refund_not_before_parent_height);
        object.pushKV("markerkind", static_cast<uint64_t>(entry.marker_kind));
        object.pushKV("actionid", entry.action_id.GetHex());
        object.pushKV(
            "transactionindex",
            static_cast<uint64_t>(entry.source_transaction_index));
        object.pushKV("markervout", static_cast<uint64_t>(entry.marker_vout));
        object.pushKV("txid", entry.source_txid.GetHex());
        object.pushKV("wtxid", entry.source_wtxid.GetHex());
        object.pushKV("canonicalentryhex", HexStr(entry.canonical_entry));
        object.pushKV("sourcetransactionhex", HexStr(entry.source_transaction));
        entries.push_back(object);
    }
    UniValue result(UniValue::VOBJ);
    result.pushKV("schema_version", 4);
    result.pushKV("configurationhash", frozen.bond_v2.configuration_hash.GetHex());
    result.pushKV("activationheight", frozen.activation_height);
    result.pushKV("capturedtiphash", captured_tip_hash.GetHex());
    result.pushKV("capturedtipheight", captured_tip_height);
    result.pushKV("startheight", start_height);
    result.pushKV("endheight", end_height);
    result.pushKV("nextheight", int64_t{end_height} + 1);
    result.pushKV("truncated", truncated);
    result.pushKV("endingheadroot", working.node_bond_inbox_head_root.GetHex());
    result.pushKV(
        "endingentrycount", EcxWideNumberToJSON(working.node_bond_inbox_entry_count.bytes));
    result.pushKV("entries", entries);
    return result;
},
    };
}

static RPCHelpMan verifychain()
{
    return RPCHelpMan{"verifychain",
                "\nVerifies blockchain database.\n",
                {
                    {"checklevel", RPCArg::Type::NUM, RPCArg::DefaultHint{strprintf("%d, range=0-4", DEFAULT_CHECKLEVEL)},
                        strprintf("How thorough the block verification is:\n%s", MakeUnorderedList(CHECKLEVEL_DOC))},
                    {"nblocks", RPCArg::Type::NUM, RPCArg::DefaultHint{strprintf("%d, 0=all", DEFAULT_CHECKBLOCKS)}, "The number of blocks to check."},
                },
                RPCResult{
                    RPCResult::Type::BOOL, "", "Verification finished successfully. If false, check debug.log for reason."},
                RPCExamples{
                    HelpExampleCli("verifychain", "")
            + HelpExampleRpc("verifychain", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const int check_level{request.params[0].isNull() ? DEFAULT_CHECKLEVEL : request.params[0].getInt<int>()};
    const int check_depth{request.params[1].isNull() ? DEFAULT_CHECKBLOCKS : request.params[1].getInt<int>()};

    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);

    Chainstate& active_chainstate = chainman.ActiveChainstate();
    return CVerifyDB(chainman.GetNotifications()).VerifyDB(
               active_chainstate, chainman.GetParams().GetConsensus(), active_chainstate.CoinsTip(), check_level, check_depth) == VerifyDBResult::SUCCESS;
},
    };
}

static void SoftForkDescPushBack(const CBlockIndex* blockindex, UniValue& softforks, const ChainstateManager& chainman, Consensus::BuriedDeployment dep)
{
    // For buried deployments.

    if (!DeploymentEnabled(chainman, dep)) return;

    UniValue rv(UniValue::VOBJ);
    rv.pushKV("type", "buried");
    // getdeploymentinfo reports the softfork as active from when the chain height is
    // one below the activation height
    rv.pushKV("active", DeploymentActiveAfter(blockindex, chainman, dep));
    rv.pushKV("height", chainman.GetConsensus().DeploymentHeight(dep));
    softforks.pushKV(DeploymentName(dep), std::move(rv));
}

static void SoftForkDescPushBack(const CBlockIndex* blockindex, UniValue& softforks, const ChainstateManager& chainman, Consensus::DeploymentPos id)
{
    // For BIP9 deployments.

    if (!DeploymentEnabled(chainman, id)) return;
    if (blockindex == nullptr) return;

    auto get_state_name = [](const ThresholdState state) -> std::string {
        switch (state) {
        case ThresholdState::DEFINED: return "defined";
        case ThresholdState::STARTED: return "started";
        case ThresholdState::LOCKED_IN: return "locked_in";
        case ThresholdState::ACTIVE: return "active";
        case ThresholdState::FAILED: return "failed";
        }
        return "invalid";
    };

    UniValue bip9(UniValue::VOBJ);

    const ThresholdState next_state = chainman.m_versionbitscache.State(blockindex, chainman.GetConsensus(), id);
    const ThresholdState current_state = chainman.m_versionbitscache.State(blockindex->pprev, chainman.GetConsensus(), id);

    const bool has_signal = (ThresholdState::STARTED == current_state || ThresholdState::LOCKED_IN == current_state);

    // BIP9 parameters
    if (has_signal) {
        bip9.pushKV("bit", chainman.GetConsensus().vDeployments[id].bit);
    }
    bip9.pushKV("start_time", chainman.GetConsensus().vDeployments[id].nStartTime);
    bip9.pushKV("timeout", chainman.GetConsensus().vDeployments[id].nTimeout);
    bip9.pushKV("min_activation_height", chainman.GetConsensus().vDeployments[id].min_activation_height);

    // BIP9 status
    bip9.pushKV("status", get_state_name(current_state));
    bip9.pushKV("since", chainman.m_versionbitscache.StateSinceHeight(blockindex->pprev, chainman.GetConsensus(), id));
    bip9.pushKV("status_next", get_state_name(next_state));

    // BIP9 signalling status, if applicable
    if (has_signal) {
        UniValue statsUV(UniValue::VOBJ);
        std::vector<bool> signals;
        BIP9Stats statsStruct = chainman.m_versionbitscache.Statistics(blockindex, chainman.GetConsensus(), id, &signals);
        statsUV.pushKV("period", statsStruct.period);
        statsUV.pushKV("elapsed", statsStruct.elapsed);
        statsUV.pushKV("count", statsStruct.count);
        if (ThresholdState::LOCKED_IN != current_state) {
            statsUV.pushKV("threshold", statsStruct.threshold);
            statsUV.pushKV("possible", statsStruct.possible);
        }
        bip9.pushKV("statistics", std::move(statsUV));

        std::string sig;
        sig.reserve(signals.size());
        for (const bool s : signals) {
            sig.push_back(s ? '#' : '-');
        }
        bip9.pushKV("signalling", sig);
    }

    UniValue rv(UniValue::VOBJ);
    rv.pushKV("type", "bip9");
    if (ThresholdState::ACTIVE == next_state) {
        rv.pushKV("height", chainman.m_versionbitscache.StateSinceHeight(blockindex, chainman.GetConsensus(), id));
    }
    rv.pushKV("active", ThresholdState::ACTIVE == next_state);
    rv.pushKV("bip9", std::move(bip9));

    softforks.pushKV(DeploymentName(id), std::move(rv));
}

// used by rest.cpp:rest_chaininfo, so cannot be static
RPCHelpMan getblockchaininfo()
{
    return RPCHelpMan{"getblockchaininfo",
        "Returns an object containing various state info regarding blockchain processing.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "chain", "current network name (always elements in production)"},
                {RPCResult::Type::NUM, "blocks", "the height of the most-work fully-validated chain. The genesis block has height 0"},
                {RPCResult::Type::NUM, "headers", "the current number of headers we have validated"},
                {RPCResult::Type::STR, "bestblockhash", "the hash of the currently best block"},
                {RPCResult::Type::STR_HEX, "bits", /*optional=*/true, "nBits: compact representation of the block difficulty target"},
                {RPCResult::Type::STR_HEX, "target", /*optional=*/true, "The difficulty target"},
                {RPCResult::Type::NUM, "difficulty", /*optional=*/true, "the current difficulty"},
                {RPCResult::Type::NUM_TIME, "time", "The block time expressed in " + UNIX_EPOCH_TIME},
                {RPCResult::Type::NUM_TIME, "mediantime", "The median block time expressed in " + UNIX_EPOCH_TIME},
                {RPCResult::Type::NUM, "verificationprogress", "estimate of verification progress [0..1]"},
                {RPCResult::Type::BOOL, "initialblockdownload", "(debug information) estimate of whether this node is in Initial Block Download mode"},
                {RPCResult::Type::STR_HEX, "chainwork", /*optional=*/true, "total amount of work in active chain, in hexadecimal"},
                {RPCResult::Type::NUM, "size_on_disk", "the estimated size of the block and undo files on disk"},
                {RPCResult::Type::BOOL, "pruned", "if the blocks are subject to pruning"},
                {RPCResult::Type::BOOL, "trim_headers", "whether header trimming is enabled (-trim-headers)"},
                {RPCResult::Type::STR_HEX, "current_params_root", /*optional=*/true, "the root of the currently active dynafed params"},
                {RPCResult::Type::STR_HEX, "current_fedpeg_program", /*optional=*/true, "The fedpeg program enforced on the next block"},
                {RPCResult::Type::STR_HEX, "current_fedpeg_script", /*optional=*/true, "The fedpeg script enforced on the next block"},
                {RPCResult::Type::STR, "current_signblock_asm", /*optional=*/true, "ASM of sign block challenge data enforced on the next block"},
                {RPCResult::Type::STR_HEX, "current_signblock_hex", /*optional=*/true, "Hex of sign block challenge data enforced on the next block"},
                {RPCResult::Type::NUM, "max_block_witness", /*optional=*/true, "maximum sized block witness serialized size for the next block"},
                {RPCResult::Type::NUM, "epoch_length", /*optional=*/true, "length of dynamic federations epoch, or signaling period"},
                {RPCResult::Type::NUM, "total_valid_epochs", /*optional=*/true, "number of epochs a given fedpegscript is valid for, defined per chain"},
                {RPCResult::Type::NUM, "epoch_age", /*optional=*/true, "number of blocks into a dynamic federation epoch chain tip is. This number is between 0 to epoch_length-1"},
                {RPCResult::Type::ARR, "extension_space", /*optional=*/true, "array of extension fields in dynamic blockheader",
                {
                    {RPCResult::Type::ELISION, "", ""}
                }},
                {RPCResult::Type::NUM, "pruneheight", /*optional=*/true, "lowest-height complete block stored (only present if pruning is enabled)"},
                {RPCResult::Type::BOOL, "automatic_pruning", /*optional=*/true, "whether automatic pruning is enabled (only present if pruning is enabled)"},
                {RPCResult::Type::NUM, "prune_target_size", /*optional=*/true, "the target size used by pruning (only present if automatic pruning is enabled)"},
                (IsDeprecatedRPCEnabled("warnings") ?
                    RPCResult{RPCResult::Type::STR, "warnings", "any network and blockchain warnings (DEPRECATED)"} :
                    RPCResult{RPCResult::Type::ARR, "warnings", "any network and blockchain warnings (run with `-deprecatedrpc=warnings` to return the latest warning as a single string)",
                    {
                        {RPCResult::Type::STR, "", "warning"},
                    }
                    }
                ),
            }},
        RPCExamples{
            HelpExampleCli("getblockchaininfo", "")
            + HelpExampleRpc("getblockchaininfo", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    Chainstate& active_chainstate = chainman.ActiveChainstate();

    const CChainParams& chainparams = chainman.GetParams();
    const CBlockIndex& tip{*CHECK_NONFATAL(active_chainstate.m_chain.Tip())};
    CHECK_NONFATAL(&tip);
    const int height{tip.nHeight};

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("chain", chainparams.GetChainTypeString());
    obj.pushKV("blocks", height);
    obj.pushKV("headers", chainman.m_best_header ? chainman.m_best_header->nHeight : -1);
    obj.pushKV("bestblockhash", tip.GetBlockHash().GetHex());
    if (!g_signed_blocks) {
    obj.pushKV("bits", strprintf("%08x", tip.nBits));
    obj.pushKV("target", GetTarget(tip, chainman.GetConsensus().powLimit).GetHex());
    obj.pushKV("difficulty", GetDifficulty(tip));
    }
    obj.pushKV("time", tip.GetBlockTime());
    obj.pushKV("mediantime", tip.GetMedianTimePast());
    obj.pushKV("verificationprogress", chainman.GuessVerificationProgress(&tip));
    obj.pushKV("initialblockdownload", chainman.IsInitialBlockDownload());
    if (!g_signed_blocks) {
        obj.pushKV("chainwork", tip.nChainWork.GetHex());
    }
    obj.pushKV("size_on_disk", chainman.m_blockman.CalculateCurrentUsage());
    obj.pushKV("pruned", chainman.m_blockman.IsPruneMode());
    obj.pushKV("trim_headers", node::fTrimHeaders); // ELEMENTS
    if (g_signed_blocks) {
        if (!DeploymentActiveAfter(&tip, chainman, Consensus::DEPLOYMENT_DYNA_FED)) {
            CScript sign_block_script = chainparams.GetConsensus().signblockscript;
            obj.pushKV("current_signblock_asm", ScriptToAsmStr(sign_block_script));
            obj.pushKV("current_signblock_hex", HexStr(sign_block_script));
            obj.pushKV("max_block_witness", (uint64_t)chainparams.GetConsensus().max_block_signature_size);
            UniValue arr(UniValue::VARR);
            for (const auto& extension : chainparams.GetConsensus().first_extension_space) {
                arr.push_back(HexStr(extension));
            }
            obj.pushKV("extension_space", arr);
        } else {
            const DynaFedParamEntry entry = ComputeNextBlockFullCurrentParameters(&tip, chainparams.GetConsensus());
            obj.pushKV("current_params_root", entry.CalculateRoot().GetHex());
            obj.pushKV("current_signblock_asm", ScriptToAsmStr(entry.m_signblockscript));
            obj.pushKV("current_signblock_hex", HexStr(entry.m_signblockscript));
            obj.pushKV("max_block_witness", (uint64_t)entry.m_signblock_witness_limit);
            obj.pushKV("current_fedpeg_program", HexStr(entry.m_fedpeg_program));
            obj.pushKV("current_fedpeg_script", HexStr(entry.m_fedpegscript));
            UniValue arr(UniValue::VARR);
            for (const auto& extension : entry.m_extension_space) {
                arr.push_back(HexStr(extension));
            }
            obj.pushKV("extension_space", arr);
            obj.pushKV("epoch_length", (uint64_t)chainparams.GetConsensus().dynamic_epoch_length);
            obj.pushKV("total_valid_epochs", (uint64_t)chainparams.GetConsensus().total_valid_epochs);
            obj.pushKV("epoch_age", (uint64_t)(tip.nHeight % chainparams.GetConsensus().dynamic_epoch_length));
        }
    }

    if (chainman.m_blockman.IsPruneMode()) {
        const auto prune_height{GetPruneHeight(chainman.m_blockman, active_chainstate.m_chain)};
        obj.pushKV("pruneheight", prune_height ? prune_height.value() + 1 : 0);

        const bool automatic_pruning{chainman.m_blockman.GetPruneTarget() != BlockManager::PRUNE_TARGET_MANUAL};
        obj.pushKV("automatic_pruning",  automatic_pruning);
        if (automatic_pruning) {
            obj.pushKV("prune_target_size", chainman.m_blockman.GetPruneTarget());
        }
    }
    if (chainman.GetParams().GetChainTypeMeta().chain_type == ChainType::SIGNET) {
        const std::vector<uint8_t>& signet_challenge =
            chainman.GetParams().GetConsensus().signet_challenge;
        obj.pushKV("signet_challenge", HexStr(signet_challenge));
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    obj.pushKV("warnings", node::GetWarningsForRpc(*CHECK_NONFATAL(node.warnings), IsDeprecatedRPCEnabled("warnings")));
    return obj;
},
    };
}

namespace {
const std::vector<RPCResult> RPCHelpForDeployment{
    {RPCResult::Type::STR, "type", "one of \"buried\", \"bip9\""},
    {RPCResult::Type::NUM, "height", /*optional=*/true, "height of the first block which the rules are or will be enforced (only for \"buried\" type, or \"bip9\" type with \"active\" status)"},
    {RPCResult::Type::BOOL, "active", "true if the rules are enforced for the mempool and the next block"},
    {RPCResult::Type::OBJ, "bip9", /*optional=*/true, "status of bip9 softforks (only for \"bip9\" type)",
    {
        {RPCResult::Type::NUM, "bit", /*optional=*/true, "the bit (0-28) in the block version field used to signal this softfork (only for \"started\" and \"locked_in\" status)"},
        {RPCResult::Type::NUM_TIME, "start_time", "the minimum median time past of a block at which the bit gains its meaning"},
        {RPCResult::Type::NUM_TIME, "timeout", "the median time past of a block at which the deployment is considered failed if not yet locked in"},
        {RPCResult::Type::NUM, "min_activation_height", "minimum height of blocks for which the rules may be enforced"},
        {RPCResult::Type::STR, "status", "status of deployment at specified block (one of \"defined\", \"started\", \"locked_in\", \"active\", \"failed\")"},
        {RPCResult::Type::NUM, "since", "height of the first block to which the status applies"},
        {RPCResult::Type::STR, "status_next", "status of deployment at the next block"},
        {RPCResult::Type::OBJ, "statistics", /*optional=*/true, "numeric statistics about signalling for a softfork (only for \"started\" and \"locked_in\" status)",
        {
            {RPCResult::Type::NUM, "period", "the length in blocks of the signalling period"},
            {RPCResult::Type::NUM, "threshold", /*optional=*/true, "the number of blocks with the version bit set required to activate the feature (only for \"started\" status)"},
            {RPCResult::Type::NUM, "elapsed", "the number of blocks elapsed since the beginning of the current period"},
            {RPCResult::Type::NUM, "count", "the number of blocks with the version bit set in the current period"},
            {RPCResult::Type::BOOL, "possible", /*optional=*/true, "returns false if there are not enough blocks left in this period to pass activation threshold (only for \"started\" status)"},
        }},
        {RPCResult::Type::STR, "signalling", /*optional=*/true, "indicates blocks that signalled with a # and blocks that did not with a -"},
    }},
};

UniValue DeploymentInfo(const CBlockIndex* blockindex, const ChainstateManager& chainman)
{
    UniValue softforks(UniValue::VOBJ);
    SoftForkDescPushBack(blockindex, softforks, chainman, Consensus::DEPLOYMENT_HEIGHTINCB);
    SoftForkDescPushBack(blockindex, softforks, chainman, Consensus::DEPLOYMENT_DERSIG);
    SoftForkDescPushBack(blockindex, softforks, chainman, Consensus::DEPLOYMENT_CLTV);
    SoftForkDescPushBack(blockindex, softforks, chainman, Consensus::DEPLOYMENT_CSV);
    SoftForkDescPushBack(blockindex, softforks, chainman, Consensus::DEPLOYMENT_SEGWIT);
    SoftForkDescPushBack(blockindex, softforks, chainman, Consensus::DEPLOYMENT_DYNA_FED);
    SoftForkDescPushBack(blockindex, softforks, chainman, Consensus::DEPLOYMENT_TESTDUMMY);
    SoftForkDescPushBack(blockindex, softforks, chainman, Consensus::DEPLOYMENT_TAPROOT);
    SoftForkDescPushBack(blockindex, softforks, chainman, Consensus::DEPLOYMENT_SIMPLICITY);
    return softforks;
}
} // anon namespace

RPCHelpMan getdeploymentinfo()
{
    return RPCHelpMan{"getdeploymentinfo",
        "Returns an object containing various state info regarding deployments of consensus changes.",
        {
            {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Default{"hash of current chain tip"}, "The block hash at which to query deployment state"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR, "hash", "requested block hash (or tip)"},
                {RPCResult::Type::NUM, "height", "requested block height (or tip)"},
                {RPCResult::Type::OBJ_DYN, "deployments", "", {
                    {RPCResult::Type::OBJ, "xxxx", "name of the deployment", RPCHelpForDeployment}
                }},
            }
        },
        RPCExamples{ HelpExampleCli("getdeploymentinfo", "") + HelpExampleRpc("getdeploymentinfo", "") },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const ChainstateManager& chainman = EnsureAnyChainman(request.context);
            LOCK(cs_main);
            const Chainstate& active_chainstate = chainman.ActiveChainstate();

            const CBlockIndex* blockindex;
            if (request.params[0].isNull()) {
                blockindex = CHECK_NONFATAL(active_chainstate.m_chain.Tip());
            } else {
                const uint256 hash(ParseHashV(request.params[0], "blockhash"));
                blockindex = chainman.m_blockman.LookupBlockIndex(hash);
                if (!blockindex) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
                }
            }

            UniValue deploymentinfo(UniValue::VOBJ);
            deploymentinfo.pushKV("hash", blockindex->GetBlockHash().ToString());
            deploymentinfo.pushKV("height", blockindex->nHeight);
            deploymentinfo.pushKV("deployments", DeploymentInfo(blockindex, chainman));
            return deploymentinfo;
        },
    };
}

/** Comparison function for sorting the getchaintips heads.  */
struct CompareBlocksByHeight
{
    bool operator()(const CBlockIndex* a, const CBlockIndex* b) const
    {
        /* Make sure that unequal blocks with the same height do not compare
           equal. Use the pointers themselves to make a distinction. */

        if (a->nHeight != b->nHeight)
          return (a->nHeight > b->nHeight);

        return a < b;
    }
};

static RPCHelpMan getalphacheckpointevidence()
{
    return RPCHelpMan{"getalphacheckpointevidence",
        "Capture raw checkpoint evidence at an exact active tip, including spent claims and source-block witnesses.\n"
        "This flushes the coins cache and holds cs_main while taking the snapshot. It does not qualify a proof\n"
        "or authenticate external configuration. Limited to 10,000 headers, 100,000 coins and 64 MiB raw evidence.\n",
        {{"expectedblock", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Required exact active-chain tip"}},
        RPCResult{RPCResult::Type::OBJ, "", "Versioned raw checkpoint evidence",
            {{RPCResult::Type::ELISION, "", "Exact block, coin, claim, withdrawal and optional capital/anchor records"}}},
        RPCExamples{HelpExampleCli("getalphacheckpointevidence", "\"blockhash\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    const uint256 expected = ParseHashV(request.params[0], "expectedblock");
    LOCK(cs_main);
    CChain& active = chainman.ActiveChain();
    const CBlockIndex* tip = active.Tip();
    using drivechain::haskell::ParentReplayAll;
    if (!ParentReplayAll<3>({[&] { return tip != nullptr; },
        [&] { return tip->GetBlockHash() == expected; }, [&] { return !expected.IsNull(); }})) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Checkpoint tip changed or is unavailable");
    }
    const auto check_limit = [](uint64_t used, uint64_t added, uint32_t limit, const char* message) {
        if (drivechain::haskell::ParentReplayRecord(
                drivechain::haskell::ReplayRecordKind::LANE_EXCEEDED, limit, 0, used, added))
            throw JSONRPCError(RPC_MISC_ERROR, message);
    };
    check_limit(tip->nHeight, 1, drivechain::CHECKPOINT_HEADER_LIMIT, "Checkpoint header limit exceeded");
    if (!ParentReplayAll<2>({[&] { return tip->m_usdd_withdrawal_accumulator.has_value(); },
        [&] { return tip->m_usdd_withdrawal_accumulator->IsSane(); }})) {
        throw JSONRPCError(RPC_MISC_ERROR, "Checkpoint withdrawal state unavailable or invalid");
    }
    auto sources = node::PrepareChildCheckpointSources(chainman);
    auto& cursor = sources.coins;
    size_t raw_bytes{0};
    auto encode = [&](const auto& value) {
        DataStream bytes{};
        bytes << value;
        check_limit(raw_bytes, bytes.size(), drivechain::CHECKPOINT_BYTE_LIMIT, "Checkpoint evidence size limit exceeded");
        raw_bytes += bytes.size();
        return HexStr(bytes);
    };
    UniValue result(UniValue::VOBJ), headers(UniValue::VARR), coins(UniValue::VARR),
        spent(UniValue::VARR), blocks(UniValue::VARR);
    result.pushKV("version", 1);
    result.pushKV("proof_ready", false);
    result.pushKV("network", Params().NetworkIDString());
    result.pushKV("genesis", active.Genesis()->GetBlockHash().GetHex());
    result.pushKV("blockhash", expected.GetHex());
    result.pushKV("height", tip->nHeight);
    for (int height = 0; height <= tip->nHeight; ++height) {
        node.rpc_interruption_point();
        CBlockIndex full;
        const CBlockIndex* index = chainman.m_blockman.m_block_tree_db->RegenerateFullIndex(active[height], &full);
        headers.push_back(encode(TX_WITH_WITNESS(index->GetBlockHeader())));
    }
    for (; sources.spent_claims->Valid(); sources.spent_claims->Next()) {
        node.rpc_interruption_point();
        check_limit(spent.size(), 1, drivechain::CHECKPOINT_ENTRY_LIMIT, "Checkpoint claim limit exceeded");
        spent.push_back(encode(sources.spent_claims->GetKey()));
    }
    // The coin database omits output witnesses. Retain the original blocks,
    // including all transaction witnesses, and cross-check every exported coin.
    std::map<int, CBlock> source_blocks;
    for (; cursor->Valid(); cursor->Next()) {
        node.rpc_interruption_point();
        check_limit(coins.size(), 1, drivechain::CHECKPOINT_ENTRY_LIMIT, "Checkpoint coin limit exceeded");
        COutPoint outpoint;
        Coin coin;
        if (!ParentReplayAll<4>({[&] { return cursor->GetKey(outpoint); },
            [&] { return cursor->GetValue(coin); }, [&] { return !coin.IsSpent(); },
            [&] { return coin.nHeight <= uint32_t(tip->nHeight); }})) {
            throw JSONRPCError(RPC_MISC_ERROR, "Unreadable or inconsistent checkpoint coin");
        }
        const int height = coin.nHeight;
        auto [it, inserted] = source_blocks.try_emplace(height);
        if (inserted) {
            if (!ParentReplayAll<2>({[&] { return chainman.m_blockman.ReadBlock(it->second, *active[height]); },
                [&] { return it->second.GetHash() == active[height]->GetBlockHash(); }})) {
                throw JSONRPCError(RPC_MISC_ERROR, "Checkpoint coin source block unavailable or mismatched");
            }
            UniValue block(UniValue::VOBJ);
            block.pushKV("height", height);
            block.pushKV("block", encode(TX_WITH_WITNESS(it->second)));
            blocks.push_back(std::move(block));
        }
        const auto& transactions = it->second.vtx;
        auto tx = std::find_if(transactions.begin(), transactions.end(), [&](const auto& candidate) {
            return candidate->GetHash() == outpoint.hash;
        });
        if (!ParentReplayAll<4>({[&] { return tx != transactions.end(); },
            [&] { return outpoint.n < (*tx)->vout.size(); },
            [&] { return (*tx)->vout[outpoint.n] == coin.out; },
            [&] { return (*tx)->IsCoinBase() == coin.IsCoinBase(); }})) {
            throw JSONRPCError(RPC_MISC_ERROR, "Checkpoint coin does not match its original transaction");
        }
        UniValue item(UniValue::VOBJ);
        item.pushKV("outpoint", encode(outpoint));
        item.pushKV("height", height);
        item.pushKV("coinbase", coin.IsCoinBase());
        item.pushKV("output", encode(coin.out));
        coins.push_back(std::move(item));
    }
    result.pushKV("headers", std::move(headers));
    result.pushKV("coins", std::move(coins));
    result.pushKV("spent_claim_keys", std::move(spent));
    result.pushKV("coin_source_blocks", std::move(blocks));
    const auto& accumulator = sources.withdrawals;
    UniValue withdrawals(UniValue::VOBJ), frontier(UniValue::VARR);
    withdrawals.pushKV("count", accumulator.count);
    withdrawals.pushKV("root", HexStr(accumulator.root));
    for (const auto& entry : accumulator.frontier) frontier.push_back(HexStr(entry));
    withdrawals.pushKV("frontier", std::move(frontier));
    result.pushKV("withdrawals", std::move(withdrawals));
    result.pushKV("capital_snapshot", tip->ecxBondV2Capital ? UniValue(encode(*tip->ecxBondV2Capital)) : UniValue());
    result.pushKV("drivechain_anchor", tip->m_drivechain_anchor ? UniValue(encode(*tip->m_drivechain_anchor)) : UniValue());
    return result;
        }};
}

static RPCHelpMan getchaintips()
{
    return RPCHelpMan{"getchaintips",
                "Return information about all known tips in the block tree,"
                " including the main chain as well as orphaned branches.\n",
                {},
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {{RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::NUM, "height", "height of the chain tip"},
                            {RPCResult::Type::STR_HEX, "hash", "block hash of the tip"},
                            {RPCResult::Type::NUM, "branchlen", "zero for main chain, otherwise length of branch connecting the tip to the main chain"},
                            {RPCResult::Type::STR, "status", "status of the chain, \"active\" for the main chain\n"
            "Possible values for status:\n"
            "1.  \"invalid\"               This branch contains at least one invalid block\n"
            "2.  \"headers-only\"          Not all blocks for this branch are available, but the headers are valid\n"
            "3.  \"valid-headers\"         All blocks are available for this branch, but they were never fully validated\n"
            "4.  \"valid-fork\"            This branch is not part of the active chain, but is fully validated\n"
            "5.  \"active\"                This is the tip of the active main chain, which is certainly valid"},
                        }}}},
                RPCExamples{
                    HelpExampleCli("getchaintips", "")
            + HelpExampleRpc("getchaintips", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    CChain& active_chain = chainman.ActiveChain();

    /*
     * Idea: The set of chain tips is the active chain tip, plus orphan blocks which do not have another orphan building off of them.
     * Algorithm:
     *  - Make one pass through BlockIndex(), picking out the orphan blocks, and also storing a set of the orphan block's pprev pointers.
     *  - Iterate through the orphan blocks. If the block isn't pointed to by another orphan, it is a chain tip.
     *  - Add the active chain tip
     */
    std::set<const CBlockIndex*, CompareBlocksByHeight> setTips;
    std::set<const CBlockIndex*> setOrphans;
    std::set<const CBlockIndex*> setPrevs;

    for (const auto& [_, block_index] : chainman.BlockIndex()) {
        if (!active_chain.Contains(&block_index)) {
            setOrphans.insert(&block_index);
            setPrevs.insert(block_index.pprev);
        }
    }

    for (std::set<const CBlockIndex*>::iterator it = setOrphans.begin(); it != setOrphans.end(); ++it) {
        if (setPrevs.erase(*it) == 0) {
            setTips.insert(*it);
        }
    }

    // Always report the currently active tip.
    setTips.insert(active_chain.Tip());

    /* Construct the output array.  */
    UniValue res(UniValue::VARR);
    for (const CBlockIndex* block : setTips) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("height", block->nHeight);
        obj.pushKV("hash", block->phashBlock->GetHex());

        const int branchLen = block->nHeight - active_chain.FindFork(block)->nHeight;
        obj.pushKV("branchlen", branchLen);

        std::string status;
        if (active_chain.Contains(block)) {
            // This block is part of the currently active chain.
            status = "active";
        } else if (block->nStatus & BLOCK_FAILED_MASK) {
            // This block or one of its ancestors is invalid.
            status = "invalid";
        } else if (!block->HaveNumChainTxs()) {
            // This block cannot be connected because full block data for it or one of its parents is missing.
            status = "headers-only";
        } else if (block->IsValid(BLOCK_VALID_SCRIPTS)) {
            // This block is fully validated, but no longer part of the active chain. It was probably the active block once, but was reorganized.
            status = "valid-fork";
        } else if (block->IsValid(BLOCK_VALID_TREE)) {
            // The headers for this block are valid, but it has not been validated. It was probably never part of the most-work chain.
            status = "valid-headers";
        } else {
            // No clue.
            status = "unknown";
        }
        obj.pushKV("status", status);

        res.push_back(std::move(obj));
    }

    return res;
},
    };
}

static RPCHelpMan preciousblock()
{
    return RPCHelpMan{"preciousblock",
                "\nTreats a block as if it were received before others with the same work.\n"
                "\nA later preciousblock call can override the effect of an earlier one.\n"
                "\nThe effects of preciousblock are not retained across restarts.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hash of the block to mark as precious"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("preciousblock", "\"blockhash\"")
            + HelpExampleRpc("preciousblock", "\"blockhash\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    uint256 hash(ParseHashV(request.params[0], "blockhash"));
    CBlockIndex* pblockindex;

    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    {
        LOCK(cs_main);
        pblockindex = chainman.m_blockman.LookupBlockIndex(hash);
        if (!pblockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
    }

    BlockValidationState state;
    chainman.ActiveChainstate().PreciousBlock(state, pblockindex);

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.ToString());
    }

    return UniValue::VNULL;
},
    };
}

void InvalidateBlock(ChainstateManager& chainman, const uint256 block_hash) {
    BlockValidationState state;
    CBlockIndex* pblockindex;
    {
        LOCK(chainman.GetMutex());
        pblockindex = chainman.m_blockman.LookupBlockIndex(block_hash);
        if (!pblockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
    }
    chainman.ActiveChainstate().InvalidateBlock(state, pblockindex);

    if (state.IsValid()) {
        chainman.ActiveChainstate().ActivateBestChain(state);
    }

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.ToString());
    }
}

static RPCHelpMan invalidateblock()
{
    return RPCHelpMan{"invalidateblock",
                "\nPermanently marks a block as invalid, as if it violated a consensus rule.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hash of the block to mark as invalid"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("invalidateblock", "\"blockhash\"")
            + HelpExampleRpc("invalidateblock", "\"blockhash\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    uint256 hash(ParseHashV(request.params[0], "blockhash"));

    InvalidateBlock(chainman, hash);

    return UniValue::VNULL;
},
    };
}

void ReconsiderBlock(ChainstateManager& chainman, uint256 block_hash) {
    {
        LOCK(chainman.GetMutex());
        CBlockIndex* pblockindex = chainman.m_blockman.LookupBlockIndex(block_hash);
        if (!pblockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }

        chainman.ActiveChainstate().ResetBlockFailureFlags(pblockindex);
        chainman.RecalculateBestHeader();
    }

    BlockValidationState state;
    chainman.ActiveChainstate().ActivateBestChain(state);

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.ToString());
    }
}

static RPCHelpMan reconsiderblock()
{
    return RPCHelpMan{"reconsiderblock",
                "\nRemoves invalidity status of a block, its ancestors and its descendants, reconsider them for activation.\n"
                "This can be used to undo the effects of invalidateblock.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hash of the block to reconsider"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("reconsiderblock", "\"blockhash\"")
            + HelpExampleRpc("reconsiderblock", "\"blockhash\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    uint256 hash(ParseHashV(request.params[0], "blockhash"));

    ReconsiderBlock(chainman, hash);

    return UniValue::VNULL;
},
    };
}

static RPCHelpMan getchaintxstats()
{
    return RPCHelpMan{"getchaintxstats",
                "\nCompute statistics about the total number and rate of transactions in the chain.\n",
                {
                    {"nblocks", RPCArg::Type::NUM, RPCArg::DefaultHint{"one month"}, "Size of the window in number of blocks"},
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::DefaultHint{"chain tip"}, "The hash of the block that ends the window."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM_TIME, "time", "The timestamp for the final block in the window, expressed in " + UNIX_EPOCH_TIME},
                        {RPCResult::Type::NUM, "txcount", /*optional=*/true,
                         "The total number of transactions in the chain up to that point, if known. "
                         "It may be unknown when using assumeutxo."},
                        {RPCResult::Type::STR_HEX, "window_final_block_hash", "The hash of the final block in the window"},
                        {RPCResult::Type::NUM, "window_final_block_height", "The height of the final block in the window."},
                        {RPCResult::Type::NUM, "window_block_count", "Size of the window in number of blocks"},
                        {RPCResult::Type::NUM, "window_interval", /*optional=*/true, "The elapsed time in the window in seconds. Only returned if \"window_block_count\" is > 0"},
                        {RPCResult::Type::NUM, "window_tx_count", /*optional=*/true,
                         "The number of transactions in the window. "
                         "Only returned if \"window_block_count\" is > 0 and if txcount exists for the start and end of the window."},
                        {RPCResult::Type::NUM, "txrate", /*optional=*/true,
                         "The average rate of transactions per second in the window. "
                         "Only returned if \"window_interval\" is > 0 and if window_tx_count exists."},
                    }},
                RPCExamples{
                    HelpExampleCli("getchaintxstats", "")
            + HelpExampleRpc("getchaintxstats", "2016")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    const CBlockIndex* pindex;
    int blockcount = 30 * 24 * 60 * 60 / chainman.GetParams().GetConsensus().nPowTargetSpacing; // By default: 1 month

    if (request.params[1].isNull()) {
        LOCK(cs_main);
        pindex = chainman.ActiveChain().Tip();
    } else {
        uint256 hash(ParseHashV(request.params[1], "blockhash"));
        LOCK(cs_main);
        pindex = chainman.m_blockman.LookupBlockIndex(hash);
        if (!pindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
        if (!chainman.ActiveChain().Contains(pindex)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Block is not in main chain");
        }
    }

    CHECK_NONFATAL(pindex != nullptr);

    if (request.params[0].isNull()) {
        blockcount = std::max(0, std::min(blockcount, pindex->nHeight - 1));
    } else {
        blockcount = request.params[0].getInt<int>();

        if (blockcount < 0 || (blockcount > 0 && blockcount >= pindex->nHeight)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid block count: should be between 0 and the block's height - 1");
        }
    }

    const CBlockIndex& past_block{*CHECK_NONFATAL(pindex->GetAncestor(pindex->nHeight - blockcount))};
    const int64_t nTimeDiff{pindex->GetMedianTimePast() - past_block.GetMedianTimePast()};

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("time", (int64_t)pindex->nTime);
    if (pindex->m_chain_tx_count) {
        ret.pushKV("txcount", pindex->m_chain_tx_count);
    }
    ret.pushKV("window_final_block_hash", pindex->GetBlockHash().GetHex());
    ret.pushKV("window_final_block_height", pindex->nHeight);
    ret.pushKV("window_block_count", blockcount);
    if (blockcount > 0) {
        ret.pushKV("window_interval", nTimeDiff);
        if (pindex->m_chain_tx_count != 0 && past_block.m_chain_tx_count != 0) {
            const auto window_tx_count = pindex->m_chain_tx_count - past_block.m_chain_tx_count;
            ret.pushKV("window_tx_count", window_tx_count);
            if (nTimeDiff > 0) {
                ret.pushKV("txrate", double(window_tx_count) / nTimeDiff);
            }
        }
    }

    return ret;
},
    };
}

template<typename T>
static T CalculateTruncatedMedian(std::vector<T>& scores)
{
    size_t size = scores.size();
    if (size == 0) {
        return 0;
    }

    std::sort(scores.begin(), scores.end());
    if (size % 2 == 0) {
        return (scores[size / 2 - 1] + scores[size / 2]) / 2;
    } else {
        return scores[size / 2];
    }
}

void CalculatePercentilesByWeight(CAmount result[NUM_GETBLOCKSTATS_PERCENTILES], std::vector<std::pair<CAmount, int64_t>>& scores, int64_t total_weight)
{
    if (scores.empty()) {
        return;
    }

    std::sort(scores.begin(), scores.end());

    // 10th, 25th, 50th, 75th, and 90th percentile weight units.
    const double weights[NUM_GETBLOCKSTATS_PERCENTILES] = {
        total_weight / 10.0, total_weight / 4.0, total_weight / 2.0, (total_weight * 3.0) / 4.0, (total_weight * 9.0) / 10.0
    };

    int64_t next_percentile_index = 0;
    int64_t cumulative_weight = 0;
    for (const auto& element : scores) {
        cumulative_weight += element.second;
        while (next_percentile_index < NUM_GETBLOCKSTATS_PERCENTILES && cumulative_weight >= weights[next_percentile_index]) {
            result[next_percentile_index] = element.first;
            ++next_percentile_index;
        }
    }

    // Fill any remaining percentiles with the last value.
    for (int64_t i = next_percentile_index; i < NUM_GETBLOCKSTATS_PERCENTILES; i++) {
        result[i] = scores.back().first;
    }
}

template<typename T>
static inline bool SetHasKeys(const std::set<T>& set) {return false;}
template<typename T, typename Tk, typename... Args>
static inline bool SetHasKeys(const std::set<T>& set, const Tk& key, const Args&... args)
{
    return (set.count(key) != 0) || SetHasKeys(set, args...);
}

// outpoint (needed for the utxo index) + nHeight + fCoinBase
static constexpr size_t PER_UTXO_OVERHEAD = sizeof(COutPoint) + sizeof(uint32_t) + sizeof(bool);

static RPCHelpMan getblockstats()
{
    return RPCHelpMan{"getblockstats",
                "\nCompute per block statistics for a given window. All amounts are in satoshis.\n"
                "It won't work for some heights with pruning.\n",
                {
                    {"hash_or_height", RPCArg::Type::NUM, RPCArg::Optional::NO, "The block hash or height of the target block",
                     RPCArgOptions{
                         .skip_type_check = true,
                         .type_str = {"", "string or numeric"},
                     }},
                    {"stats", RPCArg::Type::ARR, RPCArg::DefaultHint{"all values"}, "Values to plot (see result below)",
                        {
                            {"height", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Selected statistic"},
                            {"time", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Selected statistic"},
                        },
                        RPCArgOptions{.oneline_description="stats"}},
                },
                RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "avgfee", /*optional=*/true, "Average fee in the block"},
                {RPCResult::Type::NUM, "avgfeerate", /*optional=*/true, "Average feerate (in satoshis per virtual byte)"},
                {RPCResult::Type::NUM, "avgtxsize", /*optional=*/true, "Average transaction size"},
                {RPCResult::Type::STR_HEX, "blockhash", /*optional=*/true, "The block hash (to check for potential reorgs)"},
                {RPCResult::Type::ARR_FIXED, "feerate_percentiles", /*optional=*/true, "Feerates at the 10th, 25th, 50th, 75th, and 90th percentile weight unit (in satoshis per virtual byte)",
                {
                    {RPCResult::Type::NUM, "10th_percentile_feerate", "The 10th percentile feerate"},
                    {RPCResult::Type::NUM, "25th_percentile_feerate", "The 25th percentile feerate"},
                    {RPCResult::Type::NUM, "50th_percentile_feerate", "The 50th percentile feerate"},
                    {RPCResult::Type::NUM, "75th_percentile_feerate", "The 75th percentile feerate"},
                    {RPCResult::Type::NUM, "90th_percentile_feerate", "The 90th percentile feerate"},
                }},
                {RPCResult::Type::NUM, "height", /*optional=*/true, "The height of the block"},
                {RPCResult::Type::NUM, "ins", /*optional=*/true, "The number of inputs (excluding coinbase)"},
                {RPCResult::Type::NUM, "maxfee", /*optional=*/true, "Maximum fee in the block"},
                {RPCResult::Type::NUM, "maxfeerate", /*optional=*/true, "Maximum feerate (in satoshis per virtual byte)"},
                {RPCResult::Type::NUM, "maxtxsize", /*optional=*/true, "Maximum transaction size"},
                {RPCResult::Type::NUM, "medianfee", /*optional=*/true, "Truncated median fee in the block"},
                {RPCResult::Type::NUM, "mediantime", /*optional=*/true, "The block median time past"},
                {RPCResult::Type::NUM, "mediantxsize", /*optional=*/true, "Truncated median transaction size"},
                {RPCResult::Type::NUM, "minfee", /*optional=*/true, "Minimum fee in the block"},
                {RPCResult::Type::NUM, "minfeerate", /*optional=*/true, "Minimum feerate (in satoshis per virtual byte)"},
                {RPCResult::Type::NUM, "mintxsize", /*optional=*/true, "Minimum transaction size"},
                {RPCResult::Type::NUM, "outs", /*optional=*/true, "The number of outputs"},
                {RPCResult::Type::NUM, "subsidy", /*optional=*/true, "The block subsidy"},
                {RPCResult::Type::NUM, "swtotal_size", /*optional=*/true, "Total size of all segwit transactions"},
                {RPCResult::Type::NUM, "swtotal_weight", /*optional=*/true, "Total weight of all segwit transactions"},
                {RPCResult::Type::NUM, "swtxs", /*optional=*/true, "The number of segwit transactions"},
                {RPCResult::Type::NUM, "time", /*optional=*/true, "The block time"},
                {RPCResult::Type::NUM, "total_out", /*optional=*/true, "Total amount in all outputs (excluding coinbase and thus reward [ie subsidy + totalfee])"},
                {RPCResult::Type::NUM, "total_size", /*optional=*/true, "Total size of all non-coinbase transactions"},
                {RPCResult::Type::NUM, "total_weight", /*optional=*/true, "Total weight of all non-coinbase transactions"},
                {RPCResult::Type::NUM, "totalfee", /*optional=*/true, "The fee total"},
                {RPCResult::Type::NUM, "txs", /*optional=*/true, "The number of transactions (including coinbase)"},
                {RPCResult::Type::NUM, "utxo_increase", /*optional=*/true, "The increase/decrease in the number of unspent outputs (not discounting op_return and similar)"},
                {RPCResult::Type::NUM, "utxo_size_inc", /*optional=*/true, "The increase/decrease in size for the utxo index (not discounting op_return and similar)"},
                {RPCResult::Type::NUM, "utxo_increase_actual", /*optional=*/true, "The increase/decrease in the number of unspent outputs, not counting unspendables"},
                {RPCResult::Type::NUM, "utxo_size_inc_actual", /*optional=*/true, "The increase/decrease in size for the utxo index, not counting unspendables"},
            }},
                RPCExamples{
                    HelpExampleCli("getblockstats", R"('"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09"' '["minfeerate","avgfeerate"]')") +
                    HelpExampleCli("getblockstats", R"(1000 '["minfeerate","avgfeerate"]')") +
                    HelpExampleRpc("getblockstats", R"("00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09", ["minfeerate","avgfeerate"])") +
                    HelpExampleRpc("getblockstats", R"(1000, ["minfeerate","avgfeerate"])")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    const CBlockIndex& pindex{*CHECK_NONFATAL(ParseHashOrHeight(request.params[0], chainman))};

    std::set<std::string> stats;
    if (!request.params[1].isNull()) {
        const UniValue stats_univalue = request.params[1].get_array();
        for (unsigned int i = 0; i < stats_univalue.size(); i++) {
            const std::string stat = stats_univalue[i].get_str();
            stats.insert(stat);
        }
    }

    // ELEMENTS:
    const CAsset asset = policyAsset; // TODO Make configurable

    const CBlock& block = GetBlockChecked(chainman.m_blockman, pindex);
    const CBlockUndo& blockUndo = GetUndoChecked(chainman.m_blockman, pindex);

    const bool do_all = stats.size() == 0; // Calculate everything if nothing selected (default)
    const bool do_mediantxsize = do_all || stats.count("mediantxsize") != 0;
    const bool do_medianfee = do_all || stats.count("medianfee") != 0;
    const bool do_feerate_percentiles = do_all || stats.count("feerate_percentiles") != 0;
    const bool loop_inputs = do_all || do_medianfee || do_feerate_percentiles ||
        SetHasKeys(stats, "utxo_increase", "utxo_increase_actual", "utxo_size_inc", "utxo_size_inc_actual", "totalfee", "avgfee", "avgfeerate", "minfee", "maxfee", "minfeerate", "maxfeerate");
    const bool loop_outputs = do_all || loop_inputs || stats.count("total_out");
    const bool do_calculate_size = do_mediantxsize ||
        SetHasKeys(stats, "total_size", "avgtxsize", "mintxsize", "maxtxsize", "swtotal_size");
    const bool do_calculate_weight = do_all || SetHasKeys(stats, "total_weight", "avgfeerate", "swtotal_weight", "avgfeerate", "feerate_percentiles", "minfeerate", "maxfeerate");
    const bool do_calculate_sw = do_all || SetHasKeys(stats, "swtxs", "swtotal_size", "swtotal_weight");

    CAmount maxfee = 0;
    CAmount maxfeerate = 0;
    CAmount minfee = MAX_MONEY;
    CAmount minfeerate = MAX_MONEY;
    CAmount total_out = 0;
    CAmount totalfee = 0;
    int64_t inputs = 0;
    int64_t maxtxsize = 0;
    int64_t mintxsize = MAX_BLOCK_SERIALIZED_SIZE;
    int64_t outputs = 0;
    int64_t swtotal_size = 0;
    int64_t swtotal_weight = 0;
    int64_t swtxs = 0;
    int64_t total_size = 0;
    int64_t total_weight = 0;
    int64_t utxos = 0;
    int64_t utxo_size_inc = 0;
    int64_t utxo_size_inc_actual = 0;
    std::vector<CAmount> fee_array;
    std::vector<std::pair<CAmount, int64_t>> feerate_array;
    std::vector<int64_t> txsize_array;

    for (size_t i = 0; i < block.vtx.size(); ++i) {
        const auto& tx = block.vtx.at(i);
        outputs += tx->vout.size();

        CAmount tx_total_out = 0;
        // ELEMENTS:
        CAmount elements_txfee = 0;
        if (g_con_elementsmode) {
            if (loop_outputs) {
                for (const CTxOut& out : tx->vout) {
                    if (out.IsFee() && out.nAsset.GetAsset() == asset) {
                        elements_txfee += out.nValue.GetAmount();
                    }
                    if (out.nValue.IsExplicit() && out.nAsset.IsExplicit() && out.nAsset.GetAsset() == asset) {
                        tx_total_out += out.nValue.GetAmount();
                    }
                    size_t out_size = GetSerializeSize(out) + PER_UTXO_OVERHEAD;
                    utxo_size_inc += out_size;

                    // The Genesis block and the repeated BIP30 block coinbases don't change the UTXO
                    // set counts, so they have to be excluded from the statistics
                    if (pindex.nHeight == 0 || (IsBIP30Repeat(pindex) && tx->IsCoinBase())) continue;
                    // Skip unspendable outputs since they are not included in the UTXO set
                    if (out.scriptPubKey.IsUnspendable()) continue;

                    ++utxos;
                    utxo_size_inc_actual += out_size;
                }
            }
        } else {
            if (loop_outputs) {
                for (const CTxOut& out : tx->vout) {
                    tx_total_out += out.nValue.GetAmount();

                    size_t out_size = GetSerializeSize(out) + PER_UTXO_OVERHEAD;
                    utxo_size_inc += out_size;

                    // The Genesis block and the repeated BIP30 block coinbases don't change the UTXO
                    // set counts, so they have to be excluded from the statistics
                    if (pindex.nHeight == 0 || (IsBIP30Repeat(pindex) && tx->IsCoinBase())) continue;
                    // Skip unspendable outputs since they are not included in the UTXO set
                    if (out.scriptPubKey.IsUnspendable()) continue;

                    ++utxos;
                    utxo_size_inc_actual += out_size;
                }
            }
        }

        if (tx->IsCoinBase()) {
            continue;
        }

        inputs += tx->vin.size(); // Don't count coinbase's fake input
        total_out += tx_total_out; // Don't count coinbase reward

        int64_t tx_size = 0;
        if (do_calculate_size) {

            tx_size = tx->GetTotalSize();
            if (do_mediantxsize) {
                txsize_array.push_back(tx_size);
            }
            maxtxsize = std::max(maxtxsize, tx_size);
            mintxsize = std::min(mintxsize, tx_size);
            total_size += tx_size;
        }

        int64_t weight = 0;
        if (do_calculate_weight) {
            weight = GetTransactionWeight(*tx);
            total_weight += weight;
        }

        if (do_calculate_sw && tx->HasWitness()) {
            ++swtxs;
            swtotal_size += tx_size;
            swtotal_weight += weight;
        }

        if (loop_inputs) {
            CAmount tx_total_in = 0;
            const auto& txundo = blockUndo.vtxundo.at(i - 1);
            for (const Coin& coin: txundo.vprevout) {
                const CTxOut& prevoutput = coin.out;

                tx_total_in += g_con_elementsmode ? 0 : prevoutput.nValue.GetAmount();
                size_t prevout_size = GetSerializeSize(prevoutput) + PER_UTXO_OVERHEAD;
                utxo_size_inc -= prevout_size;
                utxo_size_inc_actual -= prevout_size;
            }

            CAmount txfee = g_con_elementsmode ? elements_txfee : (tx_total_in - tx_total_out);
            CHECK_NONFATAL(MoneyRange(txfee));
            if (do_medianfee) {
                fee_array.push_back(txfee);
            }
            maxfee = std::max(maxfee, txfee);
            minfee = std::min(minfee, txfee);
            totalfee += txfee;

            // New feerate uses satoshis per virtual byte instead of per serialized byte
            CAmount feerate = weight ? (txfee * WITNESS_SCALE_FACTOR) / weight : 0;
            if (do_feerate_percentiles) {
                feerate_array.emplace_back(feerate, weight);
            }
            maxfeerate = std::max(maxfeerate, feerate);
            minfeerate = std::min(minfeerate, feerate);
        }
    }

    CAmount feerate_percentiles[NUM_GETBLOCKSTATS_PERCENTILES] = { 0 };
    CalculatePercentilesByWeight(feerate_percentiles, feerate_array, total_weight);

    UniValue feerates_res(UniValue::VARR);
    for (int64_t i = 0; i < NUM_GETBLOCKSTATS_PERCENTILES; i++) {
        feerates_res.push_back(feerate_percentiles[i]);
    }

    UniValue ret_all(UniValue::VOBJ);
    ret_all.pushKV("avgfee", (block.vtx.size() > 1) ? totalfee / (block.vtx.size() - 1) : 0);
    ret_all.pushKV("avgfeerate", total_weight ? (totalfee * WITNESS_SCALE_FACTOR) / total_weight : 0); // Unit: sat/vbyte
    ret_all.pushKV("avgtxsize", (block.vtx.size() > 1) ? total_size / (block.vtx.size() - 1) : 0);
    ret_all.pushKV("blockhash", pindex.GetBlockHash().GetHex());
    ret_all.pushKV("feerate_percentiles", std::move(feerates_res));
    ret_all.pushKV("height", (int64_t)pindex.nHeight);
    ret_all.pushKV("ins", inputs);
    ret_all.pushKV("maxfee", maxfee);
    ret_all.pushKV("maxfeerate", maxfeerate);
    ret_all.pushKV("maxtxsize", maxtxsize);
    ret_all.pushKV("medianfee", CalculateTruncatedMedian(fee_array));
    ret_all.pushKV("mediantime", pindex.GetMedianTimePast());
    ret_all.pushKV("mediantxsize", CalculateTruncatedMedian(txsize_array));
    ret_all.pushKV("minfee", (minfee == MAX_MONEY) ? 0 : minfee);
    ret_all.pushKV("minfeerate", (minfeerate == MAX_MONEY) ? 0 : minfeerate);
    ret_all.pushKV("mintxsize", mintxsize == MAX_BLOCK_SERIALIZED_SIZE ? 0 : mintxsize);
    ret_all.pushKV("outs", outputs);
    ret_all.pushKV("subsidy", GetBlockSubsidy(pindex.nHeight, chainman.GetParams().GetConsensus()));
    ret_all.pushKV("swtotal_size", swtotal_size);
    ret_all.pushKV("swtotal_weight", swtotal_weight);
    ret_all.pushKV("swtxs", swtxs);
    ret_all.pushKV("time", pindex.GetBlockTime());
    ret_all.pushKV("total_out", total_out);
    ret_all.pushKV("total_size", total_size);
    ret_all.pushKV("total_weight", total_weight);
    ret_all.pushKV("totalfee", totalfee);
    ret_all.pushKV("txs", (int64_t)block.vtx.size());
    ret_all.pushKV("utxo_increase", outputs - inputs);
    ret_all.pushKV("utxo_size_inc", utxo_size_inc);
    ret_all.pushKV("utxo_increase_actual", utxos - inputs);
    ret_all.pushKV("utxo_size_inc_actual", utxo_size_inc_actual);

    if (do_all) {
        return ret_all;
    }

    UniValue ret(UniValue::VOBJ);
    for (const std::string& stat : stats) {
        const UniValue& value = ret_all[stat];
        if (value.isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid selected statistic '%s'", stat));
        }
        ret.pushKV(stat, value);
    }
    return ret;
},
    };
}

namespace {
//! Search for a given set of pubkey scripts
bool FindScriptPubKey(std::atomic<int>& scan_progress, const std::atomic<bool>& should_abort, int64_t& count, CCoinsViewCursor* cursor, const std::set<CScript>& needles, std::map<COutPoint, Coin>& out_results, std::function<void()>& interruption_point)
{
    scan_progress = 0;
    count = 0;
    while (cursor->Valid()) {
        COutPoint key;
        Coin coin;
        if (!cursor->GetKey(key) || !cursor->GetValue(coin)) return false;
        if (++count % 8192 == 0) {
            interruption_point();
            if (should_abort) {
                // allow to abort the scan via the abort reference
                return false;
            }
        }
        if (count % 256 == 0) {
            // update progress reference every 256 item
            uint32_t high = 0x100 * *UCharCast(key.hash.begin()) + *(UCharCast(key.hash.begin()) + 1);
            scan_progress = (int)(high * 100.0 / 65536.0 + 0.5);
        }
        if (needles.count(coin.out.scriptPubKey)) {
            out_results.emplace(key, coin);
        }
        cursor->Next();
    }
    scan_progress = 100;
    return true;
}
} // namespace

/** RAII object to prevent concurrency issue when scanning the txout set */
static std::atomic<int> g_scan_progress;
static std::atomic<bool> g_scan_in_progress;
static std::atomic<bool> g_should_abort_scan;
class CoinsViewScanReserver
{
private:
    bool m_could_reserve{false};
public:
    explicit CoinsViewScanReserver() = default;

    bool reserve() {
        CHECK_NONFATAL(!m_could_reserve);
        if (g_scan_in_progress.exchange(true)) {
            return false;
        }
        CHECK_NONFATAL(g_scan_progress == 0);
        m_could_reserve = true;
        return true;
    }

    ~CoinsViewScanReserver() {
        if (m_could_reserve) {
            g_scan_in_progress = false;
            g_scan_progress = 0;
        }
    }
};

static const auto scan_action_arg_desc = RPCArg{
    "action", RPCArg::Type::STR, RPCArg::Optional::NO, "The action to execute\n"
        "\"start\" for starting a scan\n"
        "\"abort\" for aborting the current scan (returns true when abort was successful)\n"
        "\"status\" for progress report (in %) of the current scan"
};

static const auto scan_objects_arg_desc = RPCArg{
    "scanobjects", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Array of scan objects. Required for \"start\" action\n"
        "Every scan object is either a string descriptor or an object:",
    {
        {"descriptor", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "An output descriptor"},
        {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "An object with output descriptor and metadata",
            {
                {"desc", RPCArg::Type::STR, RPCArg::Optional::NO, "An output descriptor"},
                {"range", RPCArg::Type::RANGE, RPCArg::Default{1000}, "The range of HD chain indexes to explore (either end or [begin,end])"},
            }},
    },
    RPCArgOptions{.oneline_description="[scanobjects,...]"},
};

static const auto scan_result_abort = RPCResult{
    "when action=='abort'", RPCResult::Type::BOOL, "success",
    "True if scan will be aborted (not necessarily before this RPC returns), or false if there is no scan to abort"
};
static const auto scan_result_status_none = RPCResult{
    "when action=='status' and no scan is in progress - possibly already completed", RPCResult::Type::NONE, "", ""
};
static const auto scan_result_status_some = RPCResult{
    "when action=='status' and a scan is currently in progress", RPCResult::Type::OBJ, "", "",
    {{RPCResult::Type::NUM, "progress", "Approximate percent complete"},}
};


static RPCHelpMan scantxoutset()
{
    // raw() descriptor corresponding to mainnet address 12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S
    const std::string EXAMPLE_DESCRIPTOR_RAW = "raw(76a91411b366edfc0a8b66feebae5c2e25a7b6a5d1cf3188ac)#fm24fxxy";

    return RPCHelpMan{"scantxoutset",
        "\nScans the unspent transaction output set for entries that match certain output descriptors.\n"
        "Examples of output descriptors are:\n"
        "    addr(<address>)                      Outputs whose output script corresponds to the specified address (does not include P2PK)\n"
        "    raw(<hex script>)                    Outputs whose output script equals the specified hex-encoded bytes\n"
        "    combo(<pubkey>)                      P2PK, P2PKH, P2WPKH, and P2SH-P2WPKH outputs for the given pubkey\n"
        "    pkh(<pubkey>)                        P2PKH outputs for the given pubkey\n"
        "    sh(multi(<n>,<pubkey>,<pubkey>,...)) P2SH-multisig outputs for the given threshold and pubkeys\n"
        "    tr(<pubkey>)                         P2TR\n"
        "    tr(<pubkey>,{pk(<pubkey>)})          P2TR with single fallback pubkey in tapscript\n"
        "    rawtr(<pubkey>)                      P2TR with the specified key as output key rather than inner\n"
        "    wsh(and_v(v:pk(<pubkey>),after(2)))  P2WSH miniscript with mandatory pubkey and a timelock\n"
        "\nIn the above, <pubkey> either refers to a fixed public key in hexadecimal notation, or to an xpub/xprv optionally followed by one\n"
        "or more path elements separated by \"/\", and optionally ending in \"/*\" (unhardened), or \"/*'\" or \"/*h\" (hardened) to specify all\n"
        "unhardened or hardened child keys.\n"
        "In the latter case, a range needs to be specified by below if different from 1000.\n"
        "For more information on output descriptors, see the documentation in the doc/descriptors.md file.\n",
        {
            scan_action_arg_desc,
            scan_objects_arg_desc,
        },
        {
            RPCResult{"when action=='start'; only returns after scan completes", RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::BOOL, "success", "Whether the scan was completed"},
                {RPCResult::Type::NUM, "txouts", "The number of unspent transaction outputs scanned"},
                {RPCResult::Type::NUM, "height", "The block height at which the scan was done"},
                {RPCResult::Type::STR_HEX, "bestblock", "The hash of the block at the tip of the chain"},
                {RPCResult::Type::ARR, "unspents", "",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
                        {RPCResult::Type::NUM, "vout", "The vout value"},
                        {RPCResult::Type::STR_HEX, "scriptPubKey", "The output script"},
                        {RPCResult::Type::STR, "desc", "A specialized descriptor for the matched output script"},
                        {RPCResult::Type::STR_AMOUNT, "amount", "The total amount in " + CURRENCY_UNIT + " of the unspent output"},
                        {RPCResult::Type::STR_HEX, "asset", /*optional=*/true,  "The asset ID"},
                        {RPCResult::Type::BOOL, "coinbase", "Whether this is a coinbase output"},
                        {RPCResult::Type::NUM, "height", "Height of the unspent transaction output"},
                        {RPCResult::Type::STR_HEX, "blockhash", "Blockhash of the unspent transaction output"},
                        {RPCResult::Type::NUM, "confirmations", "Number of confirmations of the unspent transaction output when the scan was done"},
                    }},
                }},
                {RPCResult::Type::STR_AMOUNT, "total_unblinded_bitcoin_amount", /*optional=*/true, "The total amount of all found unspent unblinded outputs in " + CURRENCY_UNIT},
                {RPCResult::Type::STR_AMOUNT, "total_amount", /*optional=*/true, "The total amount of all found unspent outputs in " + CURRENCY_UNIT},
            }},
            scan_result_abort,
            scan_result_status_some,
            scan_result_status_none,
        },
        RPCExamples{
            HelpExampleCli("scantxoutset", "start \'[\"" + EXAMPLE_DESCRIPTOR_RAW + "\"]\'") +
            HelpExampleCli("scantxoutset", "status") +
            HelpExampleCli("scantxoutset", "abort") +
            HelpExampleRpc("scantxoutset", "\"start\", [\"" + EXAMPLE_DESCRIPTOR_RAW + "\"]") +
            HelpExampleRpc("scantxoutset", "\"status\"") +
            HelpExampleRpc("scantxoutset", "\"abort\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue result(UniValue::VOBJ);
    const auto action{self.Arg<std::string>("action")};
    if (action == "status") {
        CoinsViewScanReserver reserver;
        if (reserver.reserve()) {
            // no scan in progress
            return UniValue::VNULL;
        }
        result.pushKV("progress", g_scan_progress.load());
        return result;
    } else if (action == "abort") {
        CoinsViewScanReserver reserver;
        if (reserver.reserve()) {
            // reserve was possible which means no scan was running
            return false;
        }
        // set the abort flag
        g_should_abort_scan = true;
        return true;
    } else if (action == "start") {
        CoinsViewScanReserver reserver;
        if (!reserver.reserve()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Scan already in progress, use action \"abort\" or \"status\"");
        }

        if (request.params[1].isNull()) {
            throw JSONRPCError(RPC_MISC_ERROR, "scanobjects argument is required for the start action");
        }

        std::set<CScript> needles;
        std::map<CScript, std::string> descriptors;
        CAmount total_in = 0;

        // loop through the scan objects
        for (const UniValue& scanobject : request.params[1].get_array().getValues()) {
            FlatSigningProvider provider;
            auto scripts = EvalDescriptorStringOrObject(scanobject, provider);
            for (CScript& script : scripts) {
                std::string inferred = InferDescriptor(script, provider)->ToString();
                needles.emplace(script);
                descriptors.emplace(std::move(script), std::move(inferred));
            }
        }

        // Scan the unspent transaction output set for inputs
        UniValue unspents(UniValue::VARR);
        std::vector<CTxOut> input_txos;
        std::map<COutPoint, Coin> coins;
        g_should_abort_scan = false;
        int64_t count = 0;
        std::unique_ptr<CCoinsViewCursor> pcursor;
        const CBlockIndex* tip;
        NodeContext& node = EnsureAnyNodeContext(request.context);
        {
            ChainstateManager& chainman = EnsureChainman(node);
            LOCK(cs_main);
            Chainstate& active_chainstate = chainman.ActiveChainstate();
            active_chainstate.ForceFlushStateToDisk();
            pcursor = CHECK_NONFATAL(active_chainstate.CoinsDB().Cursor());
            tip = CHECK_NONFATAL(active_chainstate.m_chain.Tip());
        }
        bool res = FindScriptPubKey(g_scan_progress, g_should_abort_scan, count, pcursor.get(), needles, coins, node.rpc_interruption_point);
        result.pushKV("success", res);
        result.pushKV("txouts", count);
        result.pushKV("height", tip->nHeight);
        result.pushKV("bestblock", tip->GetBlockHash().GetHex());

        if (!g_con_elementsmode) {
            for (const auto& it : coins) {
                const COutPoint& outpoint = it.first;
                const Coin& coin = it.second;
                const CTxOut& txo = coin.out;
                const CBlockIndex& coinb_block{*CHECK_NONFATAL(tip->GetAncestor(coin.nHeight))};
                input_txos.push_back(txo);
                total_in += txo.nValue.GetAmount();

                UniValue unspent(UniValue::VOBJ);
                unspent.pushKV("txid", outpoint.hash.GetHex());
                unspent.pushKV("vout", outpoint.n);
                unspent.pushKV("scriptPubKey", HexStr(txo.scriptPubKey));
                unspent.pushKV("desc", descriptors[txo.scriptPubKey]);
                unspent.pushKV("amount", ValueFromAmount(txo.nValue.GetAmount()));
                unspent.pushKV("coinbase", coin.IsCoinBase());
                unspent.pushKV("height", coin.nHeight);
                unspent.pushKV("blockhash", coinb_block.GetBlockHash().GetHex());
                unspent.pushKV("confirmations", tip->nHeight - coin.nHeight + 1);

                unspents.push_back(unspent);
            }
            result.pushKV("unspents", unspents);
            result.pushKV("total_amount", ValueFromAmount(total_in));
        } else {
            CAmount total_in_explicit_parent = 0;
            for (const auto& it : coins) {
                const COutPoint& outpoint = it.first;
                const Coin& coin = it.second;
                const CTxOut& txo = coin.out;
                const CBlockIndex& coinb_block{*CHECK_NONFATAL(tip->GetAncestor(coin.nHeight))};
                input_txos.push_back(txo);
                if (txo.nValue.IsExplicit() && txo.nAsset.IsExplicit() && txo.nAsset.GetAsset() == Params().GetConsensus().pegged_asset) {
                    total_in_explicit_parent += txo.nValue.GetAmount();
                }

                UniValue unspent(UniValue::VOBJ);
                unspent.pushKV("txid", outpoint.hash.GetHex());
                unspent.pushKV("vout", outpoint.n);
                unspent.pushKV("scriptPubKey", HexStr(txo.scriptPubKey));
                unspent.pushKV("desc", descriptors[txo.scriptPubKey]);
                if (txo.nValue.IsExplicit()) {
                    unspent.pushKV("amount", ValueFromAmount(txo.nValue.GetAmount()));
                } else {
                    unspent.pushKV("amountcommitment", HexStr(txo.nValue.vchCommitment));
                }
                if (txo.nAsset.IsExplicit()) {
                    unspent.pushKV("asset", txo.nAsset.GetAsset().GetHex());
                } else {
                    unspent.pushKV("assetcommitment", HexStr(txo.nAsset.vchCommitment));
                }
                unspent.pushKV("coinbase", coin.IsCoinBase());
                unspent.pushKV("height", coin.nHeight);
                unspent.pushKV("blockhash", coinb_block.GetBlockHash().GetHex());
                unspent.pushKV("confirmations", tip->nHeight - coin.nHeight + 1);

                unspents.push_back(unspent);
            }
            result.pushKV("unspents", unspents);
            result.pushKV("total_unblinded_bitcoin_amount", ValueFromAmount(total_in_explicit_parent));
        }
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid action '%s'", action));
    }
    return result;
},
    };
}

/** RAII object to prevent concurrency issue when scanning blockfilters */
static std::atomic<int> g_scanfilter_progress;
static std::atomic<int> g_scanfilter_progress_height;
static std::atomic<bool> g_scanfilter_in_progress;
static std::atomic<bool> g_scanfilter_should_abort_scan;
class BlockFiltersScanReserver
{
private:
    bool m_could_reserve{false};
public:
    explicit BlockFiltersScanReserver() = default;

    bool reserve() {
        CHECK_NONFATAL(!m_could_reserve);
        if (g_scanfilter_in_progress.exchange(true)) {
            return false;
        }
        m_could_reserve = true;
        return true;
    }

    ~BlockFiltersScanReserver() {
        if (m_could_reserve) {
            g_scanfilter_in_progress = false;
        }
    }
};

static bool CheckBlockFilterMatches(BlockManager& blockman, const CBlockIndex& blockindex, const GCSFilter::ElementSet& needles)
{
    const CBlock block{GetBlockChecked(blockman, blockindex)};
    const CBlockUndo block_undo{GetUndoChecked(blockman, blockindex)};

    // Check if any of the outputs match the scriptPubKey
    for (const auto& tx : block.vtx) {
        if (std::any_of(tx->vout.cbegin(), tx->vout.cend(), [&](const auto& txout) {
                return needles.count(std::vector<unsigned char>(txout.scriptPubKey.begin(), txout.scriptPubKey.end())) != 0;
            })) {
            return true;
        }
    }
    // Check if any of the inputs match the scriptPubKey
    for (const auto& txundo : block_undo.vtxundo) {
        if (std::any_of(txundo.vprevout.cbegin(), txundo.vprevout.cend(), [&](const auto& coin) {
                return needles.count(std::vector<unsigned char>(coin.out.scriptPubKey.begin(), coin.out.scriptPubKey.end())) != 0;
            })) {
            return true;
        }
    }

    return false;
}

static RPCHelpMan scanblocks()
{
    return RPCHelpMan{"scanblocks",
        "\nReturn relevant blockhashes for given descriptors (requires blockfilterindex).\n"
        "This call may take several minutes. Make sure to use no RPC timeout (bitcoin-cli -rpcclienttimeout=0)",
        {
            scan_action_arg_desc,
            scan_objects_arg_desc,
            RPCArg{"start_height", RPCArg::Type::NUM, RPCArg::Default{0}, "Height to start to scan from"},
            RPCArg{"stop_height", RPCArg::Type::NUM, RPCArg::DefaultHint{"chain tip"}, "Height to stop to scan"},
            RPCArg{"filtertype", RPCArg::Type::STR, RPCArg::Default{BlockFilterTypeName(BlockFilterType::BASIC)}, "The type name of the filter"},
            RPCArg{"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "",
                {
                    {"filter_false_positives", RPCArg::Type::BOOL, RPCArg::Default{false}, "Filter false positives (slower and may fail on pruned nodes). Otherwise they may occur at a rate of 1/M"},
                },
                RPCArgOptions{.oneline_description="options"}},
        },
        {
            scan_result_status_none,
            RPCResult{"When action=='start'; only returns after scan completes", RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::NUM, "from_height", "The height we started the scan from"},
                {RPCResult::Type::NUM, "to_height", "The height we ended the scan at"},
                {RPCResult::Type::ARR, "relevant_blocks", "Blocks that may have matched a scanobject.", {
                    {RPCResult::Type::STR_HEX, "blockhash", "A relevant blockhash"},
                }},
                {RPCResult::Type::BOOL, "completed", "true if the scan process was not aborted"}
            }},
            RPCResult{"when action=='status' and a scan is currently in progress", RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::NUM, "progress", "Approximate percent complete"},
                    {RPCResult::Type::NUM, "current_height", "Height of the block currently being scanned"},
                },
            },
            scan_result_abort,
        },
        RPCExamples{
            HelpExampleCli("scanblocks", "start '[\"addr(bcrt1q4u4nsgk6ug0sqz7r3rj9tykjxrsl0yy4d0wwte)\"]' 300000") +
            HelpExampleCli("scanblocks", "start '[\"addr(bcrt1q4u4nsgk6ug0sqz7r3rj9tykjxrsl0yy4d0wwte)\"]' 100 150 basic") +
            HelpExampleCli("scanblocks", "status") +
            HelpExampleRpc("scanblocks", "\"start\", [\"addr(bcrt1q4u4nsgk6ug0sqz7r3rj9tykjxrsl0yy4d0wwte)\"], 300000") +
            HelpExampleRpc("scanblocks", "\"start\", [\"addr(bcrt1q4u4nsgk6ug0sqz7r3rj9tykjxrsl0yy4d0wwte)\"], 100, 150, \"basic\"") +
            HelpExampleRpc("scanblocks", "\"status\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue ret(UniValue::VOBJ);
    if (request.params[0].get_str() == "status") {
        BlockFiltersScanReserver reserver;
        if (reserver.reserve()) {
            // no scan in progress
            return NullUniValue;
        }
        ret.pushKV("progress", g_scanfilter_progress.load());
        ret.pushKV("current_height", g_scanfilter_progress_height.load());
        return ret;
    } else if (request.params[0].get_str() == "abort") {
        BlockFiltersScanReserver reserver;
        if (reserver.reserve()) {
            // reserve was possible which means no scan was running
            return false;
        }
        // set the abort flag
        g_scanfilter_should_abort_scan = true;
        return true;
    } else if (request.params[0].get_str() == "start") {
        BlockFiltersScanReserver reserver;
        if (!reserver.reserve()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Scan already in progress, use action \"abort\" or \"status\"");
        }
        const std::string filtertype_name{request.params[4].isNull() ? "basic" : request.params[4].get_str()};

        BlockFilterType filtertype;
        if (!BlockFilterTypeByName(filtertype_name, filtertype)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown filtertype");
        }

        UniValue options{request.params[5].isNull() ? UniValue::VOBJ : request.params[5]};
        bool filter_false_positives{options.exists("filter_false_positives") ? options["filter_false_positives"].get_bool() : false};

        BlockFilterIndex* index = GetBlockFilterIndex(filtertype);
        if (!index) {
            throw JSONRPCError(RPC_MISC_ERROR, "Index is not enabled for filtertype " + filtertype_name);
        }

        NodeContext& node = EnsureAnyNodeContext(request.context);
        ChainstateManager& chainman = EnsureChainman(node);

        // set the start-height
        const CBlockIndex* start_index = nullptr;
        const CBlockIndex* stop_block = nullptr;
        {
            LOCK(cs_main);
            CChain& active_chain = chainman.ActiveChain();
            start_index = active_chain.Genesis();
            stop_block = active_chain.Tip(); // If no stop block is provided, stop at the chain tip.
            if (!request.params[2].isNull()) {
                start_index = active_chain[request.params[2].getInt<int>()];
                if (!start_index) {
                    throw JSONRPCError(RPC_MISC_ERROR, "Invalid start_height");
                }
            }
            if (!request.params[3].isNull()) {
                stop_block = active_chain[request.params[3].getInt<int>()];
                if (!stop_block || stop_block->nHeight < start_index->nHeight) {
                    throw JSONRPCError(RPC_MISC_ERROR, "Invalid stop_height");
                }
            }
        }
        CHECK_NONFATAL(start_index);
        CHECK_NONFATAL(stop_block);

        // loop through the scan objects, add scripts to the needle_set
        GCSFilter::ElementSet needle_set;
        for (const UniValue& scanobject : request.params[1].get_array().getValues()) {
            FlatSigningProvider provider;
            std::vector<CScript> scripts = EvalDescriptorStringOrObject(scanobject, provider);
            for (const CScript& script : scripts) {
                needle_set.emplace(script.begin(), script.end());
            }
        }
        UniValue blocks(UniValue::VARR);
        const int amount_per_chunk = 10000;
        std::vector<BlockFilter> filters;
        int start_block_height = start_index->nHeight; // for progress reporting
        const int total_blocks_to_process = stop_block->nHeight - start_block_height;

        g_scanfilter_should_abort_scan = false;
        g_scanfilter_progress = 0;
        g_scanfilter_progress_height = start_block_height;
        bool completed = true;

        const CBlockIndex* end_range = nullptr;
        do {
            node.rpc_interruption_point(); // allow a clean shutdown
            if (g_scanfilter_should_abort_scan) {
                completed = false;
                break;
            }

            // split the lookup range in chunks if we are deeper than 'amount_per_chunk' blocks from the stopping block
            int start_block = !end_range ? start_index->nHeight : start_index->nHeight + 1; // to not include the previous round 'end_range' block
            end_range = (start_block + amount_per_chunk < stop_block->nHeight) ?
                    WITH_LOCK(::cs_main, return chainman.ActiveChain()[start_block + amount_per_chunk]) :
                    stop_block;

            if (index->LookupFilterRange(start_block, end_range, filters)) {
                for (const BlockFilter& filter : filters) {
                    // compare the elements-set with each filter
                    if (filter.GetFilter().MatchAny(needle_set)) {
                        if (filter_false_positives) {
                            // Double check the filter matches by scanning the block
                            const CBlockIndex& blockindex = *CHECK_NONFATAL(WITH_LOCK(cs_main, return chainman.m_blockman.LookupBlockIndex(filter.GetBlockHash())));

                            if (!CheckBlockFilterMatches(chainman.m_blockman, blockindex, needle_set)) {
                                continue;
                            }
                        }

                        blocks.push_back(filter.GetBlockHash().GetHex());
                    }
                }
            }
            start_index = end_range;

            // update progress
            int blocks_processed = end_range->nHeight - start_block_height;
            if (total_blocks_to_process > 0) { // avoid division by zero
                g_scanfilter_progress = (int)(100.0 / total_blocks_to_process * blocks_processed);
            } else {
                g_scanfilter_progress = 100;
            }
            g_scanfilter_progress_height = end_range->nHeight;

        // Finish if we reached the stop block
        } while (start_index != stop_block);

        ret.pushKV("from_height", start_block_height);
        ret.pushKV("to_height", start_index->nHeight); // start_index is always the last scanned block here
        ret.pushKV("relevant_blocks", std::move(blocks));
        ret.pushKV("completed", completed);
    }
    else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid action '%s'", request.params[0].get_str()));
    }
    return ret;
},
    };
}

static RPCHelpMan getdescriptoractivity()
{
    return RPCHelpMan{"getdescriptoractivity",
        "\nGet spend and receive activity associated with a set of descriptors for a set of blocks. "
        "This command pairs well with the `relevant_blocks` output of `scanblocks()`.\n"
        "This call may take several minutes. If you encounter timeouts, try specifying no RPC timeout (bitcoin-cli -rpcclienttimeout=0)",
        {
            RPCArg{"blockhashes", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "The list of blockhashes to examine for activity. Order doesn't matter. Must be along main chain or an error is thrown.\n", {
                {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "A valid blockhash"},
            }},
            scan_objects_arg_desc,
            {"include_mempool", RPCArg::Type::BOOL, RPCArg::Default{true}, "Whether to include unconfirmed activity"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::ARR, "activity", "events", {
                    {RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::STR, "type", "always 'spend'"},
                        {RPCResult::Type::STR_AMOUNT, "amount", "The total amount in " + CURRENCY_UNIT + " of the spent output"},
                        {RPCResult::Type::STR_HEX, "blockhash", /*optional=*/true, "The blockhash this spend appears in (omitted if unconfirmed)"},
                        {RPCResult::Type::NUM, "height", /*optional=*/true, "Height of the spend (omitted if unconfirmed)"},
                        {RPCResult::Type::STR_HEX, "spend_txid", "The txid of the spending transaction"},
                        {RPCResult::Type::NUM, "spend_vin", "The vin of the spend"},
                        {RPCResult::Type::STR_HEX, "prevout_txid", "The txid of the prevout"},
                        {RPCResult::Type::NUM, "prevout_vout", "The vout of the prevout"},
                        {RPCResult::Type::OBJ, "prevout_spk", "", ScriptPubKeyDoc()},
                    }},
                    {RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::STR, "type", "always 'receive'"},
                        {RPCResult::Type::STR_AMOUNT, "amount", "The total amount in " + CURRENCY_UNIT + " of the new output"},
                        {RPCResult::Type::STR_HEX, "blockhash", /*optional=*/true, "The block that this receive is in (omitted if unconfirmed)"},
                        {RPCResult::Type::NUM, "height", /*optional=*/true, "The height of the receive (omitted if unconfirmed)"},
                        {RPCResult::Type::STR_HEX, "txid", "The txid of the receiving transaction"},
                        {RPCResult::Type::NUM, "vout", "The vout of the receiving output"},
                        {RPCResult::Type::OBJ, "output_spk", "", ScriptPubKeyDoc()},
                    }},
                    // TODO is the skip_type_check avoidable with a heterogeneous ARR?
                }, /*skip_type_check=*/true},
            },
        },
        RPCExamples{
            HelpExampleCli("getdescriptoractivity", "'[\"000000000000000000001347062c12fded7c528943c8ce133987e2e2f5a840ee\"]' '[\"addr(bc1qzl6nsgqzu89a66l50cvwapnkw5shh23zarqkw9)\"]'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue ret(UniValue::VOBJ);
    UniValue activity(UniValue::VARR);
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);

    struct CompareByHeightAscending {
        bool operator()(const CBlockIndex* a, const CBlockIndex* b) const {
            return a->nHeight < b->nHeight;
        }
    };

    std::set<const CBlockIndex*, CompareByHeightAscending> blockindexes_sorted;

    {
        // Validate all given blockhashes, and ensure blocks are along a single chain.
        LOCK(::cs_main);
        for (const UniValue& blockhash : request.params[0].get_array().getValues()) {
            uint256 bhash = ParseHashV(blockhash, "blockhash");
            CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(bhash);
            if (!pindex) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
            }
            if (!chainman.ActiveChain().Contains(pindex)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Block is not in main chain");
            }
            blockindexes_sorted.insert(pindex);
        }
    }

    std::set<CScript> scripts_to_watch;

    // Determine scripts to watch.
    for (const UniValue& scanobject : request.params[1].get_array().getValues()) {
        FlatSigningProvider provider;
        std::vector<CScript> scripts = EvalDescriptorStringOrObject(scanobject, provider);

        for (const CScript& script : scripts) {
            scripts_to_watch.insert(script);
        }
    }

    const auto AddSpend = [&](
            const CScript& spk,
            const CConfidentialValue& val,
            const CTransactionRef& tx,
            int vin,
            const CTxIn& txin,
            const CBlockIndex* index
            ) {
        UniValue event(UniValue::VOBJ);
        UniValue spkUv(UniValue::VOBJ);
        ScriptToUniv(spk, /*out=*/spkUv, /*include_hex=*/true, /*include_address=*/true);

        event.pushKV("type", "spend");
        if (val.IsExplicit()) {
            event.pushKV("amount", ValueFromAmount(val.GetAmount()));
        } else {
            event.pushKV("amountcommitment", HexStr(val.vchCommitment));
        }
        if (index) {
            event.pushKV("blockhash", index->GetBlockHash().ToString());
            event.pushKV("height", index->nHeight);
        }
        event.pushKV("spend_txid", tx->GetHash().ToString());
        event.pushKV("spend_vin", vin);
        event.pushKV("prevout_txid", txin.prevout.hash.ToString());
        event.pushKV("prevout_vout", txin.prevout.n);
        event.pushKV("prevout_spk", spkUv);

        return event;
    };

    const auto AddReceive = [&](const CTxOut& txout, const CBlockIndex* index, int vout, const CTransactionRef& tx) {
        UniValue event(UniValue::VOBJ);
        UniValue spkUv(UniValue::VOBJ);
        ScriptToUniv(txout.scriptPubKey, /*out=*/spkUv, /*include_hex=*/true, /*include_address=*/true);

        event.pushKV("type", "receive");
        if (txout.nValue.IsExplicit()) {
            event.pushKV("amount", ValueFromAmount(txout.nValue.GetAmount()));
        } else {
            event.pushKV("amountcommitment", HexStr(txout.nValue.vchCommitment));
        }
        if (index) {
            event.pushKV("blockhash", index->GetBlockHash().ToString());
            event.pushKV("height", index->nHeight);
        }
        event.pushKV("txid", tx->GetHash().ToString());
        event.pushKV("vout", vout);
        event.pushKV("output_spk", spkUv);

        return event;
    };

    BlockManager* blockman;
    Chainstate& active_chainstate = chainman.ActiveChainstate();
    {
        LOCK(::cs_main);
        blockman = CHECK_NONFATAL(&active_chainstate.m_blockman);
    }

    for (const CBlockIndex* blockindex : blockindexes_sorted) {
        const CBlock block{GetBlockChecked(chainman.m_blockman, *blockindex)};
        const CBlockUndo block_undo{GetUndoChecked(*blockman, *blockindex)};

        for (size_t i = 0; i < block.vtx.size(); ++i) {
            const auto& tx = block.vtx.at(i);

            if (!tx->IsCoinBase()) {
                // skip coinbase; spends can't happen there.
                const auto& txundo = block_undo.vtxundo.at(i - 1);

                for (size_t vin_idx = 0; vin_idx < tx->vin.size(); ++vin_idx) {
                    const auto& coin = txundo.vprevout.at(vin_idx);
                    const auto& txin = tx->vin.at(vin_idx);
                    if (scripts_to_watch.contains(coin.out.scriptPubKey)) {
                        activity.push_back(AddSpend(
                                    coin.out.scriptPubKey, coin.out.nValue, tx, vin_idx, txin, blockindex));
                    }
                }
            }

            for (size_t vout_idx = 0; vout_idx < tx->vout.size(); ++vout_idx) {
                const auto& vout = tx->vout.at(vout_idx);
                if (scripts_to_watch.contains(vout.scriptPubKey)) {
                    activity.push_back(AddReceive(vout, blockindex, vout_idx, tx));
                }
            }
        }
    }

    bool search_mempool = true;
    if (!request.params[2].isNull()) {
        search_mempool = request.params[2].get_bool();
    }

    if (search_mempool) {
        const CTxMemPool& mempool = EnsureMemPool(node);
        LOCK(::cs_main);
        LOCK(mempool.cs);
        const CCoinsViewCache& coins_view = &active_chainstate.CoinsTip();

        for (const CTxMemPoolEntry& e : mempool.entryAll()) {
            const auto& tx = e.GetSharedTx();

            for (size_t vin_idx = 0; vin_idx < tx->vin.size(); ++vin_idx) {
                CScript scriptPubKey;
                CConfidentialValue value;
                const auto& txin = tx->vin.at(vin_idx);
                std::optional<Coin> coin = coins_view.GetCoin(txin.prevout);

                // Check if the previous output is in the chain
                if (!coin) {
                    // If not found in the chain, check the mempool. Likely, this is a
                    // child transaction of another transaction in the mempool.
                    CTransactionRef prev_tx = CHECK_NONFATAL(mempool.get(txin.prevout.hash));

                    if (txin.prevout.n >= prev_tx->vout.size()) {
                        throw std::runtime_error("Invalid output index");
                    }
                    const CTxOut& out = prev_tx->vout[txin.prevout.n];
                    scriptPubKey = out.scriptPubKey;
                    value = out.nValue;
                } else {
                    // Coin found in the chain
                    const CTxOut& out = coin->out;
                    scriptPubKey = out.scriptPubKey;
                    value = out.nValue;
                }

                if (scripts_to_watch.contains(scriptPubKey)) {
                    UniValue event(UniValue::VOBJ);
                    activity.push_back(AddSpend(
                                scriptPubKey, value, tx, vin_idx, txin, nullptr));
                }
            }

            for (size_t vout_idx = 0; vout_idx < tx->vout.size(); ++vout_idx) {
                const auto& vout = tx->vout.at(vout_idx);
                if (scripts_to_watch.contains(vout.scriptPubKey)) {
                    activity.push_back(AddReceive(vout, nullptr, vout_idx, tx));
                }
            }
        }
    }

    ret.pushKV("activity", activity);
    return ret;
},
    };
}

static RPCHelpMan getblockfilter()
{
    return RPCHelpMan{"getblockfilter",
                "\nRetrieve a BIP 157 content filter for a particular block.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hash of the block"},
                    {"filtertype", RPCArg::Type::STR, RPCArg::Default{BlockFilterTypeName(BlockFilterType::BASIC)}, "The type name of the filter"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "filter", "the hex-encoded filter data"},
                        {RPCResult::Type::STR_HEX, "header", "the hex-encoded filter header"},
                    }},
                RPCExamples{
                    HelpExampleCli("getblockfilter", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\" \"basic\"") +
                    HelpExampleRpc("getblockfilter", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\", \"basic\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    uint256 block_hash = ParseHashV(request.params[0], "blockhash");
    std::string filtertype_name = BlockFilterTypeName(BlockFilterType::BASIC);
    if (!request.params[1].isNull()) {
        filtertype_name = request.params[1].get_str();
    }

    BlockFilterType filtertype;
    if (!BlockFilterTypeByName(filtertype_name, filtertype)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown filtertype");
    }

    BlockFilterIndex* index = GetBlockFilterIndex(filtertype);
    if (!index) {
        throw JSONRPCError(RPC_MISC_ERROR, "Index is not enabled for filtertype " + filtertype_name);
    }

    const CBlockIndex* block_index;
    bool block_was_connected;
    {
        ChainstateManager& chainman = EnsureAnyChainman(request.context);
        LOCK(cs_main);
        block_index = chainman.m_blockman.LookupBlockIndex(block_hash);
        if (!block_index) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
        block_was_connected = block_index->IsValid(BLOCK_VALID_SCRIPTS);
    }

    bool index_ready = index->BlockUntilSyncedToCurrentChain();

    BlockFilter filter;
    uint256 filter_header;
    if (!index->LookupFilter(block_index, filter) ||
        !index->LookupFilterHeader(block_index, filter_header)) {
        int err_code;
        std::string errmsg = "Filter not found.";

        if (!block_was_connected) {
            err_code = RPC_INVALID_ADDRESS_OR_KEY;
            errmsg += " Block was not connected to active chain.";
        } else if (!index_ready) {
            err_code = RPC_MISC_ERROR;
            errmsg += " Block filters are still in the process of being indexed.";
        } else {
            err_code = RPC_INTERNAL_ERROR;
            errmsg += " This error is unexpected and indicates index corruption.";
        }

        throw JSONRPCError(err_code, errmsg);
    }

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("filter", HexStr(filter.GetEncodedFilter()));
    ret.pushKV("header", filter_header.GetHex());
    return ret;
},
    };
}

/**
 * RAII class that disables the network in its constructor and enables it in its
 * destructor.
 */
class NetworkDisable
{
    CConnman& m_connman;
public:
    NetworkDisable(CConnman& connman) : m_connman(connman) {
        m_connman.SetNetworkActive(false);
        if (m_connman.GetNetworkActive()) {
            throw JSONRPCError(RPC_MISC_ERROR, "Network activity could not be suspended.");
        }
    };
    ~NetworkDisable() {
        m_connman.SetNetworkActive(true);
    };
};

/**
 * RAII class that temporarily rolls back the local chain in it's constructor
 * and rolls it forward again in it's destructor.
 */
class TemporaryRollback
{
    ChainstateManager& m_chainman;
    const CBlockIndex& m_invalidate_index;
public:
    TemporaryRollback(ChainstateManager& chainman, const CBlockIndex& index) : m_chainman(chainman), m_invalidate_index(index) {
        InvalidateBlock(m_chainman, m_invalidate_index.GetBlockHash());
    };
    ~TemporaryRollback() {
        ReconsiderBlock(m_chainman, m_invalidate_index.GetBlockHash());
    };
};

/**
 * Serialize the UTXO set to a file for loading elsewhere.
 *
 * @see SnapshotMetadata
 */
static RPCHelpMan dumptxoutset()
{
    return RPCHelpMan{
        "dumptxoutset",
        "Write the serialized UTXO set to a file. This can be used in loadtxoutset afterwards if this snapshot height is supported in the chainparams as well.\n\n"
        "Unless the \"latest\" type is requested, the node will roll back to the requested height and network activity will be suspended during this process. "
        "Because of this it is discouraged to interact with the node in any other way during the execution of this call to avoid inconsistent results and race conditions, particularly RPCs that interact with blockstorage.\n\n"
        "This call may take several minutes. Make sure to use no RPC timeout (bitcoin-cli -rpcclienttimeout=0)",
        {
            {"path", RPCArg::Type::STR, RPCArg::Optional::NO, "Path to the output file. If relative, will be prefixed by datadir."},
            {"type", RPCArg::Type::STR, RPCArg::Default(""), "The type of snapshot to create. Can be \"latest\" to create a snapshot of the current UTXO set or \"rollback\" to temporarily roll back the state of the node to a historical block before creating the snapshot of a historical UTXO set. This parameter can be omitted if a separate \"rollback\" named parameter is specified indicating the height or hash of a specific historical block. If \"rollback\" is specified and separate \"rollback\" named parameter is not specified, this will roll back to the latest valid snapshot block that can currently be loaded with loadtxoutset."},
            {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "",
                {
                    {"rollback", RPCArg::Type::NUM, RPCArg::Optional::OMITTED,
                        "Height or hash of the block to roll back to before creating the snapshot. Note: The further this number is from the tip, the longer this process will take. Consider setting a higher -rpcclienttimeout value in this case.",
                    RPCArgOptions{.skip_type_check = true, .type_str = {"", "string or numeric"}}},
                },
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::NUM, "coins_written", "the number of coins written in the snapshot"},
                    {RPCResult::Type::STR_HEX, "base_hash", "the hash of the base of the snapshot"},
                    {RPCResult::Type::NUM, "base_height", "the height of the base of the snapshot"},
                    {RPCResult::Type::STR, "path", "the absolute path that the snapshot was written to"},
                    {RPCResult::Type::STR_HEX, "txoutset_hash", "the hash of the UTXO set contents"},
                    {RPCResult::Type::NUM, "nchaintx", "the number of transactions in the chain up to and including the base block"},
                }
        },
        RPCExamples{
            HelpExampleCli("-rpcclienttimeout=0 dumptxoutset", "utxo.dat latest") +
            HelpExampleCli("-rpcclienttimeout=0 dumptxoutset", "utxo.dat rollback") +
            HelpExampleCli("-rpcclienttimeout=0 -named dumptxoutset", R"(utxo.dat rollback=853456)")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    const CBlockIndex* tip{WITH_LOCK(::cs_main, return node.chainman->ActiveChain().Tip())};
    const CBlockIndex* target_index{nullptr};
    const std::string snapshot_type{self.Arg<std::string>("type")};
    const UniValue options{request.params[2].isNull() ? UniValue::VOBJ : request.params[2]};
    if (options.exists("rollback")) {
        if (!snapshot_type.empty() && snapshot_type != "rollback") {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid snapshot type \"%s\" specified with rollback option", snapshot_type));
        }
        target_index = ParseHashOrHeight(options["rollback"], *node.chainman);
    } else if (snapshot_type == "rollback") {
        auto snapshot_heights = node.chainman->GetParams().GetAvailableSnapshotHeights();
        CHECK_NONFATAL(snapshot_heights.size() > 0);
        auto max_height = std::max_element(snapshot_heights.begin(), snapshot_heights.end());
        target_index = ParseHashOrHeight(*max_height, *node.chainman);
    } else if (snapshot_type == "latest") {
        target_index = tip;
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid snapshot type \"%s\" specified. Please specify \"rollback\" or \"latest\"", snapshot_type));
    }

    const ArgsManager& args{EnsureAnyArgsman(request.context)};
    const fs::path path = fsbridge::AbsPathJoin(args.GetDataDirNet(), fs::u8path(request.params[0].get_str()));
    // Write to a temporary path and then move into `path` on completion
    // to avoid confusion due to an interruption.
    const fs::path temppath = fsbridge::AbsPathJoin(args.GetDataDirNet(), fs::u8path(request.params[0].get_str() + ".incomplete"));

    if (fs::exists(path)) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            path.utf8string() + " already exists. If you are sure this is what you want, "
            "move it out of the way first");
    }

    FILE* file{fsbridge::fopen(temppath, "wb")};
    AutoFile afile{file};
    if (afile.IsNull()) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "Couldn't open file " + temppath.utf8string() + " for writing.");
    }

    CConnman& connman = EnsureConnman(node);
    const CBlockIndex* invalidate_index{nullptr};
    std::optional<NetworkDisable> disable_network;
    std::optional<TemporaryRollback> temporary_rollback;

    // If the user wants to dump the txoutset of the current tip, we don't have
    // to roll back at all
    if (target_index != tip) {
        // If the node is running in pruned mode we ensure all necessary block
        // data is available before starting to roll back.
        if (node.chainman->m_blockman.IsPruneMode()) {
            LOCK(node.chainman->GetMutex());
            const CBlockIndex* current_tip{node.chainman->ActiveChain().Tip()};
            const CBlockIndex* first_block{node.chainman->m_blockman.GetFirstBlock(*current_tip, /*status_mask=*/BLOCK_HAVE_MASK)};
            if (first_block->nHeight > target_index->nHeight) {
                throw JSONRPCError(RPC_MISC_ERROR, "Could not roll back to requested height since necessary block data is already pruned.");
            }
        }

        // Suspend network activity for the duration of the process when we are
        // rolling back the chain to get a utxo set from a past height. We do
        // this so we don't punish peers that send us that send us data that
        // seems wrong in this temporary state. For example a normal new block
        // would be classified as a block connecting an invalid block.
        // Skip if the network is already disabled because this
        // automatically re-enables the network activity at the end of the
        // process which may not be what the user wants.
        if (connman.GetNetworkActive()) {
            disable_network.emplace(connman);
        }

        invalidate_index = WITH_LOCK(::cs_main, return node.chainman->ActiveChain().Next(target_index));
        temporary_rollback.emplace(*node.chainman, *invalidate_index);
    }

    Chainstate* chainstate;
    std::unique_ptr<CCoinsViewCursor> cursor;
    CCoinsStats stats;
    {
        // Lock the chainstate before calling PrepareUtxoSnapshot, to be able
        // to get a UTXO database cursor while the chain is pointing at the
        // target block. After that, release the lock while calling
        // WriteUTXOSnapshot. The cursor will remain valid and be used by
        // WriteUTXOSnapshot to write a consistent snapshot even if the
        // chainstate changes.
        LOCK(node.chainman->GetMutex());
        chainstate = &node.chainman->ActiveChainstate();
        // In case there is any issue with a block being read from disk we need
        // to stop here, otherwise the dump could still be created for the wrong
        // height.
        // The new tip could also not be the target block if we have a stale
        // sister block of invalidate_index. This block (or a descendant) would
        // be activated as the new tip and we would not get to new_tip_index.
        if (target_index != chainstate->m_chain.Tip()) {
            LogWarning("dumptxoutset failed to roll back to requested height, reverting to tip.\n");
            throw JSONRPCError(RPC_MISC_ERROR, "Could not roll back to requested height.");
        } else {
            std::tie(cursor, stats, tip) = PrepareUTXOSnapshot(*chainstate, node.rpc_interruption_point);
        }
    }

    UniValue result = WriteUTXOSnapshot(*chainstate, cursor.get(), &stats, tip, afile, path, temppath, node.rpc_interruption_point);
    fs::rename(temppath, path);

    result.pushKV("path", path.utf8string());
    return result;
},
    };
}

std::tuple<std::unique_ptr<CCoinsViewCursor>, CCoinsStats, const CBlockIndex*>
PrepareUTXOSnapshot(
    Chainstate& chainstate,
    const std::function<void()>& interruption_point)
{
    std::unique_ptr<CCoinsViewCursor> pcursor;
    std::optional<CCoinsStats> maybe_stats;
    const CBlockIndex* tip;

    {
        // We need to lock cs_main to ensure that the coinsdb isn't written to
        // between (i) flushing coins cache to disk (coinsdb), (ii) getting stats
        // based upon the coinsdb, and (iii) constructing a cursor to the
        // coinsdb for use in WriteUTXOSnapshot.
        //
        // Cursors returned by leveldb iterate over snapshots, so the contents
        // of the pcursor will not be affected by simultaneous writes during
        // use below this block.
        //
        // See discussion here:
        //   https://github.com/bitcoin/bitcoin/pull/15606#discussion_r274479369
        //
        AssertLockHeld(::cs_main);

        chainstate.ForceFlushStateToDisk();

        maybe_stats = GetUTXOStats(&chainstate.CoinsDB(), chainstate.m_blockman, CoinStatsHashType::HASH_SERIALIZED, interruption_point);
        if (!maybe_stats) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read UTXO set");
        }

        pcursor = chainstate.CoinsDB().Cursor();
        tip = CHECK_NONFATAL(chainstate.m_blockman.LookupBlockIndex(maybe_stats->hashBlock));
    }

    return {std::move(pcursor), *CHECK_NONFATAL(maybe_stats), tip};
}

UniValue WriteUTXOSnapshot(
    Chainstate& chainstate,
    CCoinsViewCursor* pcursor,
    CCoinsStats* maybe_stats,
    const CBlockIndex* tip,
    AutoFile& afile,
    const fs::path& path,
    const fs::path& temppath,
    const std::function<void()>& interruption_point)
{
    LOG_TIME_SECONDS(strprintf("writing UTXO snapshot at height %s (%s) to file %s (via %s)",
        tip->nHeight, tip->GetBlockHash().ToString(),
        fs::PathToString(path), fs::PathToString(temppath)));

    SnapshotMetadata metadata{chainstate.m_chainman.GetParams().MessageStart(), tip->GetBlockHash(), maybe_stats->coins_count};

    afile << metadata;

    COutPoint key;
    Txid last_hash;
    Coin coin;
    unsigned int iter{0};
    size_t written_coins_count{0};
    std::vector<std::pair<uint32_t, Coin>> coins;

    // To reduce space the serialization format of the snapshot avoids
    // duplication of tx hashes. The code takes advantage of the guarantee by
    // leveldb that keys are lexicographically sorted.
    // In the coins vector we collect all coins that belong to a certain tx hash
    // (key.hash) and when we have them all (key.hash != last_hash) we write
    // them to file using the below lambda function.
    // See also https://github.com/bitcoin/bitcoin/issues/25675
    auto write_coins_to_file = [&](AutoFile& afile, const Txid& last_hash, const std::vector<std::pair<uint32_t, Coin>>& coins, size_t& written_coins_count) {
        afile << last_hash;
        WriteCompactSize(afile, coins.size());
        for (const auto& [n, coin] : coins) {
            WriteCompactSize(afile, n);
            afile << coin;
            ++written_coins_count;
        }
    };

    pcursor->GetKey(key);
    last_hash = key.hash;
    while (pcursor->Valid()) {
        if (iter % 5000 == 0) interruption_point();
        ++iter;
        if (pcursor->GetKey(key) && pcursor->GetValue(coin)) {
            if (key.hash != last_hash) {
                write_coins_to_file(afile, last_hash, coins, written_coins_count);
                last_hash = key.hash;
                coins.clear();
            }
            coins.emplace_back(key.n, coin);
        }
        pcursor->Next();
    }

    if (!coins.empty()) {
        write_coins_to_file(afile, last_hash, coins, written_coins_count);
    }

    CHECK_NONFATAL(written_coins_count == maybe_stats->coins_count);

    afile.fclose();

    UniValue result(UniValue::VOBJ);
    result.pushKV("coins_written", written_coins_count);
    result.pushKV("base_hash", tip->GetBlockHash().ToString());
    result.pushKV("base_height", tip->nHeight);
    result.pushKV("path", path.utf8string());
    result.pushKV("txoutset_hash", maybe_stats->hashSerialized.ToString());
    result.pushKV("nchaintx", tip->m_chain_tx_count);
    return result;
}

UniValue CreateUTXOSnapshot(
    node::NodeContext& node,
    Chainstate& chainstate,
    AutoFile& afile,
    const fs::path& path,
    const fs::path& tmppath)
{
    auto [cursor, stats, tip]{WITH_LOCK(::cs_main, return PrepareUTXOSnapshot(chainstate, node.rpc_interruption_point))};
    return WriteUTXOSnapshot(chainstate, cursor.get(), &stats, tip, afile, path, tmppath, node.rpc_interruption_point);
}

static RPCHelpMan loadtxoutset()
{
    return RPCHelpMan{
        "loadtxoutset",
        "Load the serialized UTXO set from a file.\n"
        "Once this snapshot is loaded, its contents will be "
        "deserialized into a second chainstate data structure, which is then used to sync to "
        "the network's tip. "
        "Meanwhile, the original chainstate will complete the initial block download process in "
        "the background, eventually validating up to the block that the snapshot is based upon.\n\n"

        "The result is a usable bitcoind instance that is current with the network tip in a "
        "matter of minutes rather than hours. UTXO snapshot are typically obtained from "
        "third-party sources (HTTP, torrent, etc.) which is reasonable since their "
        "contents are always checked by hash.\n\n"

        "You can find more information on this process in the `assumeutxo` design "
        "document (<https://github.com/bitcoin/bitcoin/blob/master/doc/design/assumeutxo.md>).",
        {
            {"path",
                RPCArg::Type::STR,
                RPCArg::Optional::NO,
                "path to the snapshot file. If relative, will be prefixed by datadir."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::NUM, "coins_loaded", "the number of coins loaded from the snapshot"},
                    {RPCResult::Type::STR_HEX, "tip_hash", "the hash of the base of the snapshot"},
                    {RPCResult::Type::NUM, "base_height", "the height of the base of the snapshot"},
                    {RPCResult::Type::STR, "path", "the absolute path that the snapshot was loaded from"},
                }
        },
        RPCExamples{
            HelpExampleCli("-rpcclienttimeout=0 loadtxoutset", "utxo.dat")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    const fs::path path{AbsPathForConfigVal(EnsureArgsman(node), fs::u8path(self.Arg<std::string>("path")))};

    FILE* file{fsbridge::fopen(path, "rb")};
    AutoFile afile{file};
    if (afile.IsNull()) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "Couldn't open file " + path.utf8string() + " for reading.");
    }

    SnapshotMetadata metadata{chainman.GetParams().MessageStart()};
    try {
        afile >> metadata;
    } catch (const std::ios_base::failure& e) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("Unable to parse metadata: %s", e.what()));
    }

    auto activation_result{chainman.ActivateSnapshot(afile, metadata, false)};
    if (!activation_result) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Unable to load UTXO snapshot: %s. (%s)", util::ErrorString(activation_result).original, path.utf8string()));
    }

    // Because we can't provide historical blocks during tip or background sync.
    // Update local services to reflect we are a limited peer until we are fully sync.
    node.connman->RemoveLocalServices(NODE_NETWORK);
    // Setting the limited state is usually redundant because the node can always
    // provide the last 288 blocks, but it doesn't hurt to set it.
    node.connman->AddLocalServices(NODE_NETWORK_LIMITED);

    CBlockIndex& snapshot_index{*CHECK_NONFATAL(*activation_result)};

    UniValue result(UniValue::VOBJ);
    result.pushKV("coins_loaded", metadata.m_coins_count);
    result.pushKV("tip_hash", snapshot_index.GetBlockHash().ToString());
    result.pushKV("base_height", snapshot_index.nHeight);
    result.pushKV("path", fs::PathToString(path));
    return result;
},
    };
}

const std::vector<RPCResult> RPCHelpForChainstate{
    {RPCResult::Type::NUM, "blocks", "number of blocks in this chainstate"},
    {RPCResult::Type::STR_HEX, "bestblockhash", "blockhash of the tip"},
    {RPCResult::Type::STR_HEX, "bits", /*optional=*/true, "nBits: compact representation of the block difficulty target"},
    {RPCResult::Type::STR_HEX, "target", /*optional=*/true, "The difficulty target"},
    {RPCResult::Type::NUM, "difficulty", /*optional=*/true, "difficulty of the tip"},
    {RPCResult::Type::NUM, "verificationprogress", "progress towards the network tip"},
    {RPCResult::Type::STR_HEX, "snapshot_blockhash", /*optional=*/true, "the base block of the snapshot this chainstate is based on, if any"},
    {RPCResult::Type::NUM, "coins_db_cache_bytes", "size of the coinsdb cache"},
    {RPCResult::Type::NUM, "coins_tip_cache_bytes", "size of the coinstip cache"},
    {RPCResult::Type::BOOL, "validated", "whether the chainstate is fully validated. True if all blocks in the chainstate were validated, false if the chain is based on a snapshot and the snapshot has not yet been validated."},
};

static RPCHelpMan getchainstates()
{
return RPCHelpMan{
        "getchainstates",
        "\nReturn information about chainstates.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::NUM, "headers", "the number of headers seen so far"},
                {RPCResult::Type::ARR, "chainstates", "list of the chainstates ordered by work, with the most-work (active) chainstate last", {{RPCResult::Type::OBJ, "", "", RPCHelpForChainstate},}},
            }
        },
        RPCExamples{
            HelpExampleCli("getchainstates", "")
    + HelpExampleRpc("getchainstates", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    LOCK(cs_main);
    UniValue obj(UniValue::VOBJ);

    ChainstateManager& chainman = EnsureAnyChainman(request.context);

    auto make_chain_data = [&](const Chainstate& cs, bool validated) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        AssertLockHeld(::cs_main);
        UniValue data(UniValue::VOBJ);
        if (!cs.m_chain.Tip()) {
            return data;
        }
        const CChain& chain = cs.m_chain;
        const CBlockIndex* tip = chain.Tip();

        data.pushKV("blocks",                (int)chain.Height());
        data.pushKV("bestblockhash",         tip->GetBlockHash().GetHex());
        data.pushKV("bits", strprintf("%08x", tip->nBits));
        // ELEMENTS: avoid dividing by 0
        if (tip->nBits > 0) {
            data.pushKV("difficulty",            (double)GetDifficulty(*tip));
            data.pushKV("target", GetTarget(*tip, chainman.GetConsensus().powLimit).GetHex());
        }
        data.pushKV("verificationprogress", chainman.GuessVerificationProgress(tip));
        data.pushKV("coins_db_cache_bytes",  cs.m_coinsdb_cache_size_bytes);
        data.pushKV("coins_tip_cache_bytes", cs.m_coinstip_cache_size_bytes);
        if (cs.m_from_snapshot_blockhash) {
            data.pushKV("snapshot_blockhash", cs.m_from_snapshot_blockhash->ToString());
        }
        data.pushKV("validated", validated);
        return data;
    };

    obj.pushKV("headers", chainman.m_best_header ? chainman.m_best_header->nHeight : -1);

    const auto& chainstates = chainman.GetAll();
    UniValue obj_chainstates{UniValue::VARR};
    for (Chainstate* cs : chainstates) {
      obj_chainstates.push_back(make_chain_data(*cs, !cs->m_from_snapshot_blockhash || chainstates.size() == 1));
    }
    obj.pushKV("chainstates", std::move(obj_chainstates));
    return obj;
}
    };
}


//
// ELEMENTS:

namespace {

UniValue FetchDrivechainL1PegEvents(int sidechain_id)
{
    UniValue response(UniValue::VOBJ);
    std::string error;
    if (!GetDrivechainTwoWayPegData(sidechain_id, response, &error)) {
        throw JSONRPCError(RPC_MISC_ERROR, strprintf("GetTwoWayPegData failed: %s", error));
    }
    return drivechain::NormalizeL1PegEvents(response, sidechain_id);
}

} // namespace

static RPCHelpMan getdrivechaindepositdestination()
{
    return RPCHelpMan{"getdrivechaindepositdestination",
        "Encode the recipient and exact Elements fee to commit in an L1 M5 deposit.\n"
        "This does not create or broadcast a transaction. The parent transaction fee is separate.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Recipient Elements address."},
            {"deposit_fee_sats", RPCArg::Type::NUM, RPCArg::Default{0}, "Exact Elements fee deducted from the deposit, in integer satoshis. The deposit must exceed this amount."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR, "destination", "Opaque destination for the enforcer's CreateDepositTransaction address field."},
            {RPCResult::Type::STR, "bitwindow_address", "Slot-prefixed destination for BitWindow's generic deposit-address parser."},
            {RPCResult::Type::STR_HEX, "destination_hex", "Exact M5 destination bytes."},
            {RPCResult::Type::NUM, "deposit_fee_sats", "Elements fee committed by these bytes."},
            {RPCResult::Type::NUM, "sidechain_slot", "Configured sidechain slot."},
        }},
        RPCExamples{HelpExampleCli("getdrivechaindepositdestination", "\"<elements-address>\" 1000")},
        [&](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            const auto slot = Params().GetConsensus().drivechain_slot;
            if (!slot) throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Native BIP300 deposits are not enabled on this network");
            const auto& fee_value = request.params[1];
            CAmount fee{0};
            if (!fee_value.isNull() && (!fee_value.isNum() || !ParseInt64(fee_value.getValStr(), &fee)))
                throw JSONRPCError(RPC_INVALID_PARAMETER, "deposit_fee_sats must be an integer");
            std::string destination;
            try { destination = EncodeDrivechainDepositDestination(request.params[0].get_str(), fee); }
            catch (const std::invalid_argument& e) { throw JSONRPCError(RPC_INVALID_PARAMETER, e.what()); }
            UniValue result(UniValue::VOBJ);
            result.pushKV("destination", destination);
            result.pushKV("bitwindow_address", strprintf("s%u_%s", *slot, destination));
            result.pushKV("destination_hex", HexStr(std::vector<unsigned char>(destination.begin(), destination.end())));
            result.pushKV("deposit_fee_sats", fee);
            result.pushKV("sidechain_slot", *slot);
            return result;
        }};
}

static RPCHelpMan getdrivechainpegevents()
{
    return RPCHelpMan{"getdrivechainpegevents",
                "Returns versioned BIP300 deposit, withdrawal, bundle, and acknowledgement events.\n"
                "Sidechain events are reconstructed from active-chain consensus data and therefore follow reorgs.\n"
                "Set include_l1 to query and normalize CUSF GetTwoWayPegData from the configured enforcer.\n",
                {
                    {"start_height", RPCArg::Type::NUM, RPCArg::DefaultHint{"tip - 999"}, "First sidechain height to scan."},
                    {"count", RPCArg::Type::NUM, RPCArg::Default{drivechain::PEG_EVENT_DEFAULT_COUNT}, "Number of sidechain blocks to scan (1-10000)."},
                    {"include_l1", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include normalized L1 CUSF lifecycle events."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "Versioned drivechain event response.",
                    {
                        {RPCResult::Type::NUM, "schema_version", "Event contract version."},
                        {RPCResult::Type::NUM, "sidechain_id", "BIP300 sidechain slot."},
                        {RPCResult::Type::OBJ, "sidechain_tip", "Active sidechain tip.",
                            {
                                {RPCResult::Type::STR_HEX, "hash", "Sidechain tip hash."},
                                {RPCResult::Type::NUM, "height", "Sidechain tip height."},
                            }},
                        {RPCResult::Type::OBJ, "range", "Scanned sidechain range.",
                            {
                                {RPCResult::Type::NUM, "start_height", "First scanned height."},
                                {RPCResult::Type::NUM, "end_height", "Last scanned height."},
                            }},
                        {RPCResult::Type::ARR, "events", "Normalized events in deterministic chain order.",
                            {{RPCResult::Type::OBJ, "", "Deposit, withdrawal, bundle commitment, or L1 lifecycle event.",
                                {
                                    {RPCResult::Type::STR, "event_id", "Stable event identity."},
                                    {RPCResult::Type::STR, "source", "Event source: sidechain or l1."},
                                    {RPCResult::Type::STR, "kind", "Event kind."},
                                    {RPCResult::Type::STR, "status", "Lifecycle status."},
                                    {RPCResult::Type::NUM, "sidechain_id", /*optional=*/true, "BIP300 sidechain slot."},
                                    {RPCResult::Type::STR_HEX, "sidechain_txid", /*optional=*/true, "Sidechain transaction id."},
                                    {RPCResult::Type::NUM, "vin", /*optional=*/true, "Sidechain transaction input index."},
                                    {RPCResult::Type::NUM, "vout", /*optional=*/true, "Sidechain transaction output index."},
                                    {RPCResult::Type::STR_HEX, "mainchain_txid", /*optional=*/true, "Mainchain transaction id."},
                                    {RPCResult::Type::NUM, "mainchain_vout", /*optional=*/true, "Mainchain output index."},
                                    {RPCResult::Type::STR_HEX, "m6id", /*optional=*/true, "Withdrawal bundle id."},
                                    {RPCResult::Type::NUM, "value_sats", /*optional=*/true, "Explicit value in satoshis."},
                                    {RPCResult::Type::STR_HEX, "asset", /*optional=*/true, "Elements asset id."},
                                    {RPCResult::Type::STR_HEX, "claim_script", /*optional=*/true, "Drivechain deposit claim script."},
                                    {RPCResult::Type::STR_HEX, "address_hex", /*optional=*/true, "Enforcer deposit address bytes."},
                                    {RPCResult::Type::NUM, "sequence_number", /*optional=*/true, "Enforcer sequence number."},
                                    {RPCResult::Type::STR, "acknowledgement", /*optional=*/true, "Bundle acknowledgement state."},
                                    {RPCResult::Type::STR_HEX, "mainchain_transaction", /*optional=*/true, "Final mainchain transaction."},
                                    {RPCResult::Type::STR_HEX, "mainchain_genesis_hash", /*optional=*/true, "Parent-chain genesis hash."},
                                    {RPCResult::Type::STR_HEX, "mainchain_script", /*optional=*/true, "Parent-chain destination script."},
                                    {RPCResult::Type::OBJ, "sidechain", /*optional=*/true, "Sidechain block location.",
                                        {
                                            {RPCResult::Type::STR_HEX, "block_hash", "Sidechain block hash."},
                                            {RPCResult::Type::NUM, "height", "Sidechain block height."},
                                        }},
                                    {RPCResult::Type::OBJ, "l1", /*optional=*/true, "Mainchain block location.",
                                        {
                                            {RPCResult::Type::STR_HEX, "block_hash", "Mainchain block hash."},
                                            {RPCResult::Type::NUM, "height", "Mainchain block height."},
                                            {RPCResult::Type::NUM, "timestamp", /*optional=*/true, "Mainchain block timestamp."},
                                        }},
                                }}}},
                    }},
                RPCExamples{
                    HelpExampleCli("getdrivechainpegevents", "0 1000 true")
                    + HelpExampleRpc("getdrivechainpegevents", "0, 1000, true")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto& consensus = Params().GetConsensus();
    if (!drivechain::haskell::ParentReplayAll<2>({[&] { return consensus.elements_mode; },
        [&] { return consensus.has_parent_chain; }})) {
        throw JSONRPCError(
            RPC_MISC_ERROR,
            "getdrivechainpegevents is unavailable outside an Elements parent-chain configuration");
    }
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    const int sidechain_id = gArgs.GetIntArg("-drivechainbmmslot", drivechain::DRIVECHAIN_SIDECHAIN_SLOT);
    if (!drivechain::haskell::ParentReplayRecord(drivechain::haskell::ReplayRecordKind::AMOUNT,
            0,sidechain_id,0,INT32_MAX)) throw JSONRPCError(RPC_INVALID_PARAMETER, "-drivechainbmmslot must be non-negative");

    int tip_height;
    uint256 tip_hash;
    std::vector<const CBlockIndex*> blocks;
    int start_height;
    int end_height;
    {
        LOCK(cs_main);
        const CBlockIndex* tip = chainman.ActiveChain().Tip();
        if (!drivechain::haskell::ExchangeAvailable(drivechain::haskell::Availability::RPC,
                [&](uint32_t) { return tip != nullptr; })) throw JSONRPCError(RPC_MISC_ERROR, "Sidechain tip is unavailable");
        tip_height = tip->nHeight;
        tip_hash = tip->GetBlockHash();

        start_height = request.params[0].isNull() ? drivechain::haskell::PegEventStart(tip_height) : request.params[0].getInt<int>();
        const int count = request.params[1].isNull() ? drivechain::PEG_EVENT_DEFAULT_COUNT : request.params[1].getInt<int>();
        const auto range = drivechain::haskell::PegEventRange(start_height,count,tip_height,end_height);
        if (range == 1) throw JSONRPCError(RPC_INVALID_PARAMETER, "start_height is outside the active sidechain");
        if (range == 2) throw JSONRPCError(RPC_INVALID_PARAMETER, "count must be between 1 and 10000");
        blocks.reserve(end_height - start_height + 1);
        for (int64_t height = start_height; height <= end_height; ++height) {
            blocks.push_back(chainman.ActiveChain()[static_cast<int>(height)]);
        }
    }

    UniValue events(UniValue::VARR);
    drivechain::haskell::ParentReplayEach(blocks, [&](const CBlockIndex* block_index) {
        CBlock block;
        if (!chainman.m_blockman.ReadBlock(block, *block_index)) {
            throw JSONRPCError(RPC_MISC_ERROR, strprintf("Block not available at height %d", block_index->nHeight));
        }
        const uint256 previous_bundle_hash = block_index->pprev == nullptr ? uint256::ZERO : block_index->pprev->hashWithdrawalBundle;
        const UniValue block_events = drivechain::ExtractSidechainPegEvents(block, block_index->nHeight, previous_bundle_hash);
        events.push_backV(block_events.getValues());
        return true;
    });

    const bool include_l1 = request.params[2].isNull() ? false : request.params[2].get_bool();
    drivechain::haskell::ParentReplayAll<2>({[&] { return include_l1; }, [&] {
        const UniValue l1_events = FetchDrivechainL1PegEvents(sidechain_id);
        events.push_backV(l1_events.getValues());
        return true;
    }});

    UniValue tip(UniValue::VOBJ);
    tip.pushKV("hash", tip_hash.GetHex());
    tip.pushKV("height", tip_height);
    UniValue range(UniValue::VOBJ);
    range.pushKV("start_height", start_height);
    range.pushKV("end_height", end_height);

    UniValue result(UniValue::VOBJ);
    result.pushKV("schema_version", drivechain::PEG_EVENT_SCHEMA_VERSION);
    result.pushKV("sidechain_id", sidechain_id);
    result.pushKV("sidechain_tip", tip);
    result.pushKV("range", range);
    result.pushKV("events", events);
    return result;
},
    };
}

static RPCHelpMan getsidechaininfo()
{
    return RPCHelpMan{"getsidechaininfo",
                "Returns an object containing various state info regarding sidechain functionality.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "fedpegscript", "The fedpegscript from genesis block"},
                        {RPCResult::Type::ARR, "current_fedpeg_programs", "The currently-enforced fedpegscript scriptPubKeys in hex. Prior to a transition this may be P2SH scriptpubkey, otherwise it will be a native segwit script. Results are paired in-order with current_fedpegscripts",
                            {{RPCResult::Type::STR_HEX, "", "active fedpegscript scriptPubKeys"}}},
                        {RPCResult::Type::ARR, "current_fedpegscripts", "The currently-enforced fedpegscripts in hex. Peg-ins for any entries on this list are honored by consensus and policy. Newest first. Two total entries are possible",
                            {{RPCResult::Type::STR_HEX, "", "active fedpegscript"}}},
                        {RPCResult::Type::STR_HEX, "pegged_asset", "Pegged asset type"},
                        {RPCResult::Type::STR_HEX, "fee_asset", "The asset used for transaction fees and relay policy"},
                        {RPCResult::Type::STR, "min_peg_diff", "The minimum difficulty parent chain header target. Peg-in headers that have less work will be rejected as an anti-Dos measure"},
                        {RPCResult::Type::STR_HEX, "parent_blockhash", "The parent genesis blockhash as source of pegged-in funds"},
                        {RPCResult::Type::BOOL, "parent_chain_has_pow", "Whether parent chain has pow or signed blocks"},
                        {RPCResult::Type::STR, "parent_chain_signblockscript_asm", /*optional=*/true, "If the parent chain has signed blocks, its signblockscript in ASM"},
                        {RPCResult::Type::STR_HEX, "parent_chain_signblockscript_hex", /*optional=*/true, "If the parent chain has signed blocks, its signblockscript in hex"},
                        {RPCResult::Type::STR_HEX, "parent_pegged_asset", /*optional=*/true, "If the parent chain has Confidential Assets, the asset id of the pegged asset in that chain"},
                        {RPCResult::Type::NUM, "pegin_confirmation_depth", "The mainchain confirmations required for a peg-in in the next child block (mempool admission)"},
                        {RPCResult::Type::NUM, "pegin_confirmation_depth_historical", "The original depth committed by the genesis/protocol identity"},
                        {RPCResult::Type::NUM, "pegin_confirmation_depth_current_block", "The depth required by the current child block's consensus rules"},
                        {RPCResult::Type::NUM, "pegin_confirmation_depth_validation_height", "The next child block height used for pegin_confirmation_depth"},
                        {RPCResult::Type::NUM, "pegin_confirmation_depth_activation_height", /*optional=*/true, "Child height of the fixed Alpha one-confirmation upgrade"},
                        {RPCResult::Type::NUM, "pegin_confirmation_depth_after_activation", /*optional=*/true, "Required depth at and after the fixed Alpha upgrade"},
                        {RPCResult::Type::BOOL, "enforce_pak", "If peg-out authorization is being enforced"},
                        {RPCResult::Type::STR, "pegin_min_amount", /*optional=*/true, "minimum peg-in amount enforced by consensus"},
                        {RPCResult::Type::NUM, "pegin_min_height", /*optional=*/true, "block height from which the minimum peg-in amount applies"},
                        {RPCResult::Type::BOOL, "pegin_min_active", /*optional=*/true, "whether the minimum peg-in rule is active at the current tip"},
                        {RPCResult::Type::STR, "pegin_subsidy_threshold", /*optional=*/true, "peg-in subsidy threshold amount"},
                        {RPCResult::Type::NUM, "pegin_subsidy_height", /*optional=*/true, "block height from which the peg-in subsidy rule applies"},
                        {RPCResult::Type::BOOL, "pegin_subsidy_active", /*optional=*/true, "whether the peg-in subsidy rule is active at the current tip"},
                    }},
                RPCExamples{
                    HelpExampleCli("getsidechaininfo", "")
                    + HelpExampleRpc("getsidechaininfo", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    LOCK(cs_main);

    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    const Consensus::Params& consensus = Params().GetConsensus();
    const uint256& parent_blockhash = Params().ParentGenesisBlockHash();

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("fedpegscript", HexStr(consensus.fedpegScript));
    // We use mempool_validation as true to show what is enforced for *next* block
    std::vector<std::pair<CScript, CScript>> fedpegscripts = GetValidFedpegScripts(chainman.ActiveChain().Tip(), consensus, true /* nextblock_validation */);
    UniValue fedpeg_prog_entries(UniValue::VARR);
    UniValue fedpeg_entries(UniValue::VARR);
    for (const auto& scripts : fedpegscripts) {
        fedpeg_prog_entries.push_back(HexStr(scripts.first));
        fedpeg_entries.push_back(HexStr(scripts.second));
    }
    obj.pushKV("current_fedpeg_programs", fedpeg_prog_entries);
    obj.pushKV("current_fedpegscripts", fedpeg_entries);
    obj.pushKV("pegged_asset", consensus.pegged_asset.GetHex());
    obj.pushKV("fee_asset", policyAsset.GetHex());
    obj.pushKV("min_peg_diff", consensus.parentChainPowLimit.GetHex());
    obj.pushKV("parent_blockhash", parent_blockhash.GetHex());
    obj.pushKV("parent_chain_has_pow", consensus.ParentChainHasPow());
    obj.pushKV("enforce_pak", Params().GetEnforcePak());
    const int child_tip_height = chainman.ActiveChain().Height();
    const int validation_height = drivechain::haskell::NextBlockHeight(true, child_tip_height);
    obj.pushKV("pegin_confirmation_depth", (uint64_t)GetDrivechainPeginConfirmationDepth(Params(), validation_height));
    obj.pushKV("pegin_confirmation_depth_historical", (uint64_t)consensus.pegin_min_depth);
    obj.pushKV("pegin_confirmation_depth_current_block", (uint64_t)GetDrivechainPeginConfirmationDepth(Params(), child_tip_height));
    obj.pushKV("pegin_confirmation_depth_validation_height", validation_height);
    if (HasAlphaPeginOneConfirmationUpgrade(Params())) {
        obj.pushKV("pegin_confirmation_depth_activation_height", ALPHA_PEGIN_ONE_CONFIRMATION_HEIGHT);
        obj.pushKV("pegin_confirmation_depth_after_activation", 1);
    }
    if (!consensus.ParentChainHasPow()) {
        obj.pushKV("parent_chain_signblockscript_asm", ScriptToAsmStr(consensus.parent_chain_signblockscript));
        obj.pushKV("parent_chain_signblockscript_hex", HexStr(consensus.parent_chain_signblockscript));
        obj.pushKV("parent_pegged_asset", consensus.parent_pegged_asset.GetHex());
    }

    PeginMinimum pegin_minimum = Params().GetPeginMinimum();
    if (pegin_minimum.amount > 0) {
        obj.pushKV("pegin_min_amount", FormatMoney(pegin_minimum.amount));
    }
    if (pegin_minimum.height < std::numeric_limits<int>::max()) {
        obj.pushKV("pegin_min_height", pegin_minimum.height);
        obj.pushKV("pegin_min_active", chainman.ActiveTip()->nHeight >= pegin_minimum.height);
    }

    PeginSubsidy pegin_subsidy = Params().GetPeginSubsidy();
    if (pegin_subsidy.threshold > 0) {
        obj.pushKV("pegin_subsidy_threshold", FormatMoney(pegin_subsidy.threshold));
    }
    if (pegin_subsidy.height < std::numeric_limits<int>::max()) {
        obj.pushKV("pegin_subsidy_height", pegin_subsidy.height);
        obj.pushKV("pegin_subsidy_active", chainman.ActiveTip()->nHeight >= pegin_subsidy.height);
    }

    return obj;
},
    };
}

namespace {

struct AuthenticatedNativeWithdrawal
{
    uint256 txid;
    uint32_t vout{0};
    uint256 block_hash;
    int block_height{0};
    int confirmations{0};
    drivechain::NativeWithdrawal withdrawal;
    drivechain::NativeWithdrawalM6 m6;
    std::optional<DrivechainSuccessfulWithdrawal> successful_parent_withdrawal;
};

std::pair<bool, CAmount> NativeWithdrawalParentPolicy(const CScript& script)
{
    static_assert(static_cast<int>(TxoutType::PUBKEY) == 2 && static_cast<int>(TxoutType::PUBKEYHASH) == 3 &&
        static_cast<int>(TxoutType::SCRIPTHASH) == 4 && static_cast<int>(TxoutType::MULTISIG) == 5 &&
        static_cast<int>(TxoutType::WITNESS_V0_SCRIPTHASH) == 7 && static_cast<int>(TxoutType::WITNESS_V0_KEYHASH) == 8 &&
        static_cast<int>(TxoutType::WITNESS_V1_TAPROOT) == 9 && DUST_RELAY_TX_FEE_BITCOIN == 3000);
    TxoutType type{TxoutType::NONSTANDARD};
    std::array<unsigned char, 10> facts{};
    facts[4] = IsStandard(script, std::nullopt, type);
    WriteLE32(facts.data(), static_cast<uint32_t>(type));
    int witness_version{0};
    std::vector<unsigned char> witness_program;
    facts[9] = script.IsWitnessProgram(witness_version, witness_program);
    WriteLE32(facts.data() + 5, static_cast<uint32_t>(::GetSerializeSize(Sidechain::Bitcoin::CTxOut(0, script))));
    std::vector<unsigned char> policy;
    if (!drivechain::haskell::WithdrawalBytes(drivechain::haskell::WithdrawalOp::PARENT_POLICY, facts, policy, nullptr))
        throw std::runtime_error("Haskell withdrawal parent policy failed");
    return {policy[0] == 1, static_cast<CAmount>(ReadLE64(policy.data() + 1))};
}

enum class WithdrawalAdmission : uint8_t { OPTIONS, INITIAL, BEFORE_REPLAY, AFTER_REPLAY };

void CheckWithdrawalPolicy(drivechain::haskell::WithdrawalOp op, std::span<const unsigned char> input)
{
    std::vector<unsigned char> result;
    if (!drivechain::haskell::WithdrawalBytes(op,input,result,nullptr))
        throw std::runtime_error("Haskell withdrawal RPC admission failed");
    const auto code = static_cast<int32_t>(ReadLE32(result.data()));
    if (code) throw JSONRPCError(code,std::string(result.begin()+4,result.end()));
}

int CheckWithdrawalAdmission(WithdrawalAdmission stage, uint8_t flags, int depth, int required)
{
    std::array<unsigned char,10> input{static_cast<uint8_t>(stage),flags};
    WriteLE32(input.data()+2,depth);
    WriteLE32(input.data()+6,required);
    CheckWithdrawalPolicy(drivechain::haskell::WithdrawalOp::RPC_ADMISSION,input);
    return depth;
}

void CheckWithdrawalProofBounds(uint8_t stage, uint64_t index, uint64_t count = 0)
{
    std::array<unsigned char,17> input{stage};
    WriteLE64(input.data()+1,index);
    WriteLE64(input.data()+9,count);
    CheckWithdrawalPolicy(drivechain::haskell::WithdrawalOp::PROOF_BOUNDS,input);
}

int RecheckWithdrawalAnchor(ChainstateManager& chainman, const CBlockIndex& index,
                           const uint256& hash, WithdrawalAdmission stage, int required)
{
    LOCK(cs_main);
    const auto& active = chainman.ActiveChain();
    const bool anchored = drivechain::haskell::ParentReplayAll<2>({
        [&] { return active.Contains(&index); }, [&] { return index.GetBlockHash() == hash; },
    });
    return CheckWithdrawalAdmission(stage,anchored,anchored ? active.Height()-index.nHeight+1 : 0,required);
}

AuthenticatedNativeWithdrawal LoadNativeWithdrawal(
    ChainstateManager& chainman,
    const uint256& txid,
    const uint32_t vout,
    const uint256& block_hash,
    const int min_confirmations)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    CheckWithdrawalAdmission(WithdrawalAdmission::OPTIONS,consensus.DrivechainWithdrawalValidationEnabled(),0,min_confirmations);

    const CBlockIndex* block_index{nullptr};
    int confirmations{0};
    {
        LOCK(cs_main);
        block_index = chainman.m_blockman.LookupBlockIndex(block_hash);
        const CChain& active = chainman.ActiveChain();
        const bool anchored = drivechain::haskell::ParentReplayAll<2>({
            [&] { return block_index != nullptr; }, [&] { return active.Contains(block_index); }});
        const bool available = drivechain::haskell::ParentReplayAll<2>({
            [&] { return block_index != nullptr; },
            [&]() EXCLUSIVE_LOCKS_REQUIRED(cs_main) { return (block_index->nStatus & BLOCK_HAVE_DATA) != 0; }});
        confirmations = CheckWithdrawalAdmission(WithdrawalAdmission::INITIAL,anchored | (available << 1),
            anchored ? active.Height()-block_index->nHeight+1 : 0,min_confirmations);
    }

    CBlock block;
    if (!chainman.m_blockman.ReadBlock(block, *block_index)) {
        throw JSONRPCError(RPC_MISC_ERROR,
                           "Unable to read the confirming Elements block");
    }
    BlockValidationState block_state;
    if (!CheckBlock(block, block_state, consensus,
                    /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/true)) {
        throw JSONRPCError(
            RPC_VERIFY_ERROR,
            strprintf("Confirming Elements block body failed context-free validation: %s",
                      block_state.ToString()));
    }
    CTransactionRef transaction;
    // A native V1 withdrawal is exactly one canonical parent-genesis peg-out
    // output in its transaction. Its explicit pegged-asset value is destroyed
    // by ordinary Elements consensus because OP_RETURN is never added to the
    // UTXO set. Nothing in this RPC can turn the burn back into a spendable
    // output.
    std::optional<uint32_t> canonical_vout;
    drivechain::NativeWithdrawal withdrawal, parsed;
    size_t candidate_index{0};
    uint32_t output_index{0};
    CAmount parent_dust{0};
    std::string parse_error;
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::WITHDRAWAL_RPC_BURN,
        [&](uint32_t action) -> uint32_t {
        switch (action) {
        case 1: return candidate_index < block.vtx.size();
        case 2: {
            const auto& candidate = block.vtx.at(candidate_index);
            return drivechain::haskell::ParentReplayAll<2>({
                [&] { return bool(candidate); }, [&] { return candidate->GetHash() == txid; }});
        }
        case 3: return bool{transaction};
        case 4: throw JSONRPCError(RPC_INTERNAL_ERROR,"Confirming block contains the withdrawal txid more than once");
        case 5: transaction = block.vtx.at(candidate_index); break;
        case 6: ++candidate_index; break;
        case 7: return bool{transaction};
        case 8: throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,"Withdrawal transaction is not in the specified confirming block");
        case 9: return vout < transaction->vout.size();
        case 10: throw JSONRPCError(RPC_INVALID_PARAMETER,"Withdrawal vout is outside the transaction");
        case 11: return output_index < transaction->vout.size();
        case 12: return transaction->vout.at(output_index).scriptPubKey.IsPegoutScript(Params().ParentGenesisBlockHash());
        case 13: {
            parsed = {};
            parse_error.clear();
            const auto* witness = output_index < transaction->witness.vtxoutwit.size() ?
                &transaction->witness.vtxoutwit[output_index] : nullptr;
            return drivechain::ParseNativeWithdrawalOutput(transaction->vout.at(output_index),witness,
                consensus.pegged_asset,Params().ParentGenesisBlockHash(),parsed,&parse_error);
        }
        case 14: throw JSONRPCError(RPC_VERIFY_ERROR,strprintf("Malformed native withdrawal output %u: %s",output_index,parse_error));
        case 15: return canonical_vout.has_value();
        case 16: throw JSONRPCError(RPC_VERIFY_ERROR,"Native withdrawal V1 permits exactly one withdrawal burn per Elements transaction");
        case 17: canonical_vout = output_index; withdrawal = std::move(parsed); break;
        case 18: ++output_index; break;
        case 19: return canonical_vout == vout;
        case 20: throw JSONRPCError(RPC_VERIFY_ERROR,"Requested outpoint is not the transaction's sole canonical native withdrawal burn");
        case 21: return transaction->vout.at(vout).scriptPubKey.IsUnspendable();
        case 22: throw JSONRPCError(RPC_INTERNAL_ERROR,"Canonical native withdrawal output is unexpectedly spendable");
        case 23: {
            const auto policy = NativeWithdrawalParentPolicy(withdrawal.destination);
            parent_dust = policy.second;
            return policy.first;
        }
        case 24: throw JSONRPCError(RPC_VERIFY_ERROR,"Native withdrawal Bitcoin destination is not a recognized, currently spendable standard script");
        case 25: return withdrawal.payout_amount >= parent_dust;
        case 26: throw JSONRPCError(RPC_VERIFY_ERROR,"Native withdrawal Bitcoin payout is dust for its destination");
        default: throw std::logic_error("Invalid Haskell withdrawal burn scan action");
        }
        return 1;
    });

    drivechain::NativeWithdrawalM6 m6, reparsed_m6;
    std::string m6_error, parent_error;
    AuthenticatedNativeWithdrawal result;
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::WITHDRAWAL_RPC_CLAIM,
        [&](uint32_t action) -> uint32_t {
        switch (action) {
        case 1: return drivechain::BuildNativeWithdrawalM6(consensus.hashGenesisBlock,
            *consensus.drivechain_slot,txid,vout,withdrawal,m6,&m6_error);
        case 2: throw JSONRPCError(RPC_VERIFY_ERROR,m6_error);
        case 3: return drivechain::ParseNativeWithdrawalM6(m6.blinded_transaction,consensus.hashGenesisBlock,
            *consensus.drivechain_slot,txid,vout,reparsed_m6,&m6_error);
        case 4: return reparsed_m6.m6id == m6.m6id;
        case 5: return reparsed_m6.legacy_serialization == m6.legacy_serialization;
        case 6: throw JSONRPCError(RPC_INTERNAL_ERROR,m6_error.empty() ?
            "Internally generated native withdrawal M6 failed canonical round-trip" : m6_error);
        // Both checks are required: parent replay may be slow on a cold node.
        case 7: confirmations = RecheckWithdrawalAnchor(chainman,*block_index,block_hash,WithdrawalAdmission::BEFORE_REPLAY,min_confirmations); break;
        case 8:
            result.txid = txid;
            result.vout = vout;
            result.block_hash = block_hash;
            result.block_height = block_index->nHeight;
            result.confirmations = confirmations;
            result.withdrawal = std::move(withdrawal);
            result.m6 = std::move(m6);
            break;
        case 9: return GetDrivechainSuccessfulWithdrawal(*consensus.drivechain_slot,result.m6.m6id,
            result.successful_parent_withdrawal,&parent_error);
        case 10: throw JSONRPCError(RPC_MISC_ERROR,strprintf(
            "Unable to authenticate completed BIP300 withdrawals on the active parent chain: %s",parent_error));
        case 11: result.confirmations = RecheckWithdrawalAnchor(chainman,*block_index,block_hash,WithdrawalAdmission::AFTER_REPLAY,min_confirmations); break;
        default: throw std::logic_error("Invalid Haskell withdrawal claim action");
        }
        return 1;
    });
    return result;
}

UniValue NativeWithdrawalToJSON(const AuthenticatedNativeWithdrawal& claim)
{
    UniValue result(UniValue::VOBJ);
    result.pushKV("txid", claim.txid.GetHex());
    result.pushKV("vout", static_cast<uint64_t>(claim.vout));
    result.pushKV("blockhash", claim.block_hash.GetHex());
    result.pushKV("blockheight", claim.block_height);
    result.pushKV("confirmations", claim.confirmations);
    result.pushKV("burn_amount", ValueFromAmount(claim.withdrawal.burn_amount));
    result.pushKV("payout_amount", ValueFromAmount(claim.withdrawal.payout_amount));
    result.pushKV("mainchain_fee", ValueFromAmount(claim.withdrawal.parent_fee));
    result.pushKV("bitcoin_script_pub_key", HexStr(claim.withdrawal.destination));
    result.pushKV("burn_commitment", HexStr(claim.m6.burn_commitment));
    result.pushKV("m6id", claim.m6.m6id.GetHex());
    result.pushKV("blinded_m6", HexStr(claim.m6.legacy_serialization));
    result.pushKV("burn_is_unspendable", true);
    const bool paid = claim.successful_parent_withdrawal.has_value();
    result.pushKV("paid_on_parent_chain", paid);
    if (paid) {
        result.pushKV(
            "parent_payment_blockhash",
            claim.successful_parent_withdrawal->block_hash.GetHex());
        result.pushKV(
            "parent_payment_blockheight",
            static_cast<uint64_t>(
                claim.successful_parent_withdrawal->block_height));
    }
    result.pushKV(
        "conservation",
        "burn_amount = payout_amount + mainchain_fee");
    return result;
}

[[noreturn]] void ThrowPaidNativeWithdrawal(const AuthenticatedNativeWithdrawal& claim)
{
    const auto& payment = claim.successful_parent_withdrawal.value();
    throw JSONRPCError(
        RPC_VERIFY_ALREADY_IN_UTXO_SET,
        strprintf("Native withdrawal M6 %s was already paid in parent block %s at height %u",
                  claim.m6.m6id.GetHex(),
                  payment.block_hash.GetHex(), payment.block_height));
}

uint32_t ParseWithdrawalVout(const UniValue& value)
{
    const int64_t parsed = value.getInt<int64_t>();
    if (!drivechain::haskell::ParentReplayRecord(drivechain::haskell::ReplayRecordKind::AMOUNT,
            0, parsed, 0, std::numeric_limits<uint32_t>::max() - 1)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "vout is outside the canonical uint32 range");
    }
    return static_cast<uint32_t>(parsed);
}

} // namespace

static RPCHelpMan getdrivechainwithdrawalbundle()
{
    return RPCHelpMan{"getdrivechainwithdrawalbundle",
                "Authenticates a confirmed native pegged-asset burn and deterministically derives its blinded BIP300 M6. This call does not submit anything.\n",
                {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Elements burn transaction id"},
                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Canonical burn output index"},
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Active-chain block containing the burn"},
                    {"minconfirmations", RPCArg::Type::NUM, RPCArg::Default{drivechain::WITHDRAWAL_READ_CONFIRMATIONS}, "Required active Elements confirmations"},
                },
                RPCResult{RPCResult::Type::OBJ, "", "Authenticated burn and exact blinded M6"},
                RPCExamples{
                    HelpExampleCli("getdrivechainwithdrawalbundle", "\"<txid>\" 0 \"<blockhash>\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    const int min_confirmations = request.params[3].isNull()
        ? drivechain::WITHDRAWAL_READ_CONFIRMATIONS
        : request.params[3].getInt<int>();
    return NativeWithdrawalToJSON(LoadNativeWithdrawal(
        chainman,
        ParseHashV(request.params[0], "txid"),
        ParseWithdrawalVout(request.params[1]),
        ParseHashV(request.params[2], "blockhash"),
        min_confirmations));
},
    };
}

static RPCHelpMan submitdrivechainwithdrawal()
{
    return RPCHelpMan{"submitdrivechainwithdrawal",
                "Authenticates a confirmed native pegged-asset burn, derives its unique blinded M6, and submits it idempotently to the configured BIP300 enforcer.\n",
                {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Elements burn transaction id"},
                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Canonical burn output index"},
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Active-chain block containing the burn"},
                    {"minconfirmations", RPCArg::Type::NUM, RPCArg::Default{drivechain::WITHDRAWAL_SUBMIT_CONFIRMATIONS}, "Required active Elements confirmations before proposing the M6"},
                },
                RPCResult{RPCResult::Type::OBJ, "", "Authenticated burn, exact blinded M6, and enforcer submission result"},
                RPCExamples{
                    HelpExampleCli("submitdrivechainwithdrawal", "\"<txid>\" 0 \"<blockhash>\" 6")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    const int min_confirmations = request.params[3].isNull()
        ? drivechain::WITHDRAWAL_SUBMIT_CONFIRMATIONS
        : request.params[3].getInt<int>();
    AuthenticatedNativeWithdrawal claim = LoadNativeWithdrawal(
        chainman,
        ParseHashV(request.params[0], "txid"),
        ParseWithdrawalVout(request.params[1]),
        ParseHashV(request.params[2], "blockhash"),
        min_confirmations);
    std::string response;
    std::string submission_error;
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::REQUIRED_PAIR_ERRORS,
        [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return !claim.successful_parent_withdrawal.has_value();
        case 2: ThrowPaidNativeWithdrawal(claim);
        case 3: return SubmitDrivechainWithdrawalBundle(EnsureAnyNodeContext(request.context),
            *Params().GetConsensus().drivechain_slot, claim.m6.legacy_serialization, &response, &submission_error);
        case 4: throw JSONRPCError(RPC_MISC_ERROR, submission_error);
        default: throw std::logic_error("invalid withdrawal submission action");
        }
    });

    UniValue result = NativeWithdrawalToJSON(claim);
    result.pushKV("submitted", true);
    result.pushKV("enforcer_response", response);
    result.pushKV(
        "security_model",
        "burn authenticated by this Elements node; M6 authorization follows BIP300 miner voting");
    return result;
},
    };
}

static RPCHelpMan verifydrivechainwithdrawalbundle()
{
    return RPCHelpMan{"verifydrivechainwithdrawalbundle",
                "Verifies that an externally proposed blinded BIP300 M6 is the unique canonical bundle for a confirmed native pegged-asset burn. This call does not submit anything.\n"
                "Miners and operators can use this RPC to reject fabricated or altered native withdrawal proposals before voting.\n",
                {
                    {"blinded_m6", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact legacy zero-input blinded M6 serialization"},
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Active Elements block containing the burn referenced by the M6"},
                    {"minconfirmations", RPCArg::Type::NUM, RPCArg::Default{drivechain::WITHDRAWAL_SUBMIT_CONFIRMATIONS}, "Required active Elements confirmations"},
                },
                RPCResult{RPCResult::Type::OBJ, "", "Verified burn and exact blinded M6"},
                RPCExamples{
                    HelpExampleCli("verifydrivechainwithdrawalbundle", "\"<blinded_m6_hex>\" \"<blockhash>\" 6")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::string encoded = request.params[0].get_str();
    std::vector<unsigned char> serialized;
    Sidechain::Bitcoin::CMutableTransaction proposed;
    std::string parse_error;
    uint256 referenced_genesis;
    uint8_t referenced_slot{0};
    uint256 burn_txid;
    uint32_t burn_vout{0};
    const Consensus::Params& consensus = Params().GetConsensus();
    drivechain::NativeWithdrawalM6 structurally_valid;
    AuthenticatedNativeWithdrawal claim;
    UniValue result;
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::WITHDRAWAL_RPC_VERIFY,
        [&](uint32_t action) -> uint32_t {
        switch (action) {
        case 1: return IsHex(encoded);
        case 2: throw JSONRPCError(RPC_DESERIALIZATION_ERROR,"blinded_m6 must be canonical hexadecimal");
        case 3:
            serialized = ParseHex(encoded);
            return drivechain::haskell::ParentReplayRecord(drivechain::haskell::ReplayRecordKind::NONEMPTY_BOUNDED,
                0,0,serialized.size(),drivechain::NATIVE_WITHDRAWAL_MAX_M6_LEGACY_SIZE);
        case 4: throw JSONRPCError(RPC_DESERIALIZATION_ERROR,"blinded_m6 exceeds the canonical native-withdrawal serialization bound");
        case 5: return drivechain::DeserializeNativeWithdrawalM6Legacy(serialized,proposed,&parse_error);
        case 6: throw JSONRPCError(RPC_DESERIALIZATION_ERROR,parse_error);
        // The shared legacy decoder requires exactly three outputs before this action.
        case 7: return drivechain::ParseNativeWithdrawalM6Commitment(proposed.vout.at(1).scriptPubKey,
            referenced_genesis,referenced_slot,burn_txid,burn_vout,&parse_error);
        case 8: throw JSONRPCError(RPC_VERIFY_ERROR,parse_error);
        case 9: return drivechain::haskell::ParentReplayAll<3>({
            [&] { return consensus.drivechain_slot.has_value(); },
            [&] { return referenced_genesis == consensus.hashGenesisBlock; },
            [&] { return referenced_slot == static_cast<uint8_t>(*consensus.drivechain_slot); }});
        case 10: throw JSONRPCError(RPC_VERIFY_ERROR,"blinded M6 references a different Elements chain or sidechain slot");
        case 11: return drivechain::ParseNativeWithdrawalM6(proposed,referenced_genesis,referenced_slot,
            burn_txid,burn_vout,structurally_valid,&parse_error);
        case 12: {
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            const int min_confirmations = request.params[2].isNull()
                ? drivechain::WITHDRAWAL_SUBMIT_CONFIRMATIONS : request.params[2].getInt<int>();
            claim = LoadNativeWithdrawal(chainman,burn_txid,burn_vout,
                ParseHashV(request.params[1],"blockhash"),min_confirmations);
            break;
        }
        case 13: return claim.m6.legacy_serialization == serialized;
        case 14: return claim.m6.m6id == drivechain::ComputeNativeWithdrawalM6Id(proposed);
        case 15: throw JSONRPCError(RPC_VERIFY_ERROR,
            "blinded M6 payout, fee, reference, or canonical encoding does not match the confirmed Elements burn");
        case 16: return !claim.successful_parent_withdrawal.has_value();
        case 17:
            result = NativeWithdrawalToJSON(claim);
            result.pushKV("valid",true);
            result.pushKV("security_model",
                "verified against the active Elements chain; BIP300 payout still requires miner approval");
            break;
        case 18: ThrowPaidNativeWithdrawal(claim);
        default: throw std::logic_error("Invalid Haskell withdrawal verification action");
        }
        return 1;
    });
    return result;
},
    };
}

static const CBlockIndex* ReadWithdrawalAccumulator(ChainstateManager& chainman, const UniValue& hash,
    usdd::WithdrawalAccumulatorState& accumulator) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    const CChain& active = chainman.ActiveChain();
    const auto* index = hash.isNull() ? active.Tip() : chainman.m_blockman.LookupBlockIndex(ParseHashV(hash, "blockhash"));
    AssertLockHeld(cs_main);
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::REQUIRED_PAIR_ERRORS,
        [&](uint32_t step) EXCLUSIVE_LOCKS_REQUIRED(cs_main) -> uint32_t {
        switch (step) {
        case 1: return drivechain::haskell::ParentReplayAll<2>({
            [&] { return index != nullptr; },
            [&]() EXCLUSIVE_LOCKS_REQUIRED(cs_main) { return active.Contains(index); }});
        case 2: throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,"Block is not in the active chain");
        case 3: return index->m_usdd_withdrawal_accumulator.has_value();
        case 4: throw JSONRPCError(RPC_INTERNAL_ERROR,"Withdrawal accumulator unavailable; reindex required");
        default: throw std::logic_error("invalid withdrawal accumulator admission action");
        }
    });
    accumulator = *index->m_usdd_withdrawal_accumulator;
    return index;
}

static RPCHelpMan getusddwithdrawalaccumulator()
{
    return RPCHelpMan{"getusddwithdrawalaccumulator",
                "Returns the deterministic canonical Ethereum-withdrawal accumulator at an active-chain block.\n"
                "This generic index binds each leaf's actual asset and vault but is not, by itself, an authorizing\n"
                "USDD root. The immutable external deployment manifest and vault must enforce their exact IDs.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::DefaultHint{"chain tip"}, "Optional active-chain block hash"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "blockhash", "Block whose derived state is returned"},
                        {RPCResult::Type::NUM, "height", "Block height"},
                        {RPCResult::Type::NUM, "count", "Cumulative canonical withdrawal-leaf count"},
                        {RPCResult::Type::STR_HEX, "root", "Depth-64 SHA-256 sparse-Merkle root"},
                        {RPCResult::Type::BOOL, "authorizing", "Always false: the node cannot authenticate an external USDD deployment"},
                        {RPCResult::Type::STR, "scope", "Exact scope of the generic accumulator"},
                    }},
                RPCExamples{
                    HelpExampleCli("getusddwithdrawalaccumulator", "")
                    + HelpExampleRpc("getusddwithdrawalaccumulator", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    const CBlockIndex* blockindex{nullptr};
    usdd::WithdrawalAccumulatorState accumulator;
    {
        LOCK(cs_main);
        blockindex = ReadWithdrawalAccumulator(chainman, request.params[0], accumulator);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("blockhash", blockindex->GetBlockHash().GetHex());
    result.pushKV("height", blockindex->nHeight);
    result.pushKV("count", accumulator.count);
    result.pushKV("root", HexStr(accumulator.root));
    result.pushKV("authorizing", false);
    result.pushKV("scope", "generic exact USDD-v1-shaped burns; leaf binds actual asset and vault");
    return result;
},
    };
}

static RPCHelpMan getusddwithdrawalproof()
{
    return RPCHelpMan{"getusddwithdrawalproof",
                "Reconstructs a canonical withdrawal inclusion proof from retained active-chain blocks.\n"
                "Proof reconstruction requires unpruned blocks containing withdrawals, is single-flight,\n"
                "and is limited to 10,000 leaves and a ten-second work budget per call.\n",
                {
                    {"index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Zero-based cumulative claim index"},
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::DefaultHint{"chain tip"}, "Optional active-chain block hash"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "Withdrawal claim and bottom-up 64-sibling branch",
                    {
                        {RPCResult::Type::NUM, "index", "Claim index"},
                        {RPCResult::Type::STR_HEX, "root", "Accumulator root"},
                        {RPCResult::Type::NUM, "count", "Accumulator leaf count"},
                        {RPCResult::Type::STR_HEX, "leaf", "Canonical Solidity-compatible leaf"},
                        {RPCResult::Type::STR_HEX, "burn_id", "Canonical burn identity"},
                        {RPCResult::Type::STR_HEX, "txid", "Elements burn transaction ID in display order"},
                        {RPCResult::Type::NUM, "vout", "Burn output index"},
                        {RPCResult::Type::STR_HEX, "asset", "Explicit burned asset ID"},
                        {RPCResult::Type::STR_HEX, "vault_id", "Vault ID from the burn payload"},
                        {RPCResult::Type::STR_HEX, "recipient", "Fixed Ethereum recipient"},
                        {RPCResult::Type::NUM, "amount_usdt_micro", "Six-decimal USDT amount"},
                        {RPCResult::Type::ARR, "siblings", "64 sibling hashes, bottom-up",
                            {{RPCResult::Type::STR_HEX, "hash", "Sibling hash"}}},
                        {RPCResult::Type::BOOL, "authorizing", "Always false: the node cannot authenticate an external USDD deployment"},
                    }},
                RPCExamples{
                    HelpExampleCli("getusddwithdrawalproof", "0")
                    + HelpExampleRpc("getusddwithdrawalproof", "0")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const int64_t requested_index = request.params[0].getInt<int64_t>();
    CheckWithdrawalProofBounds(0, static_cast<uint64_t>(requested_index));
    const uint64_t index = static_cast<uint64_t>(requested_index);
    std::unique_lock<std::mutex> proof_lock(
        g_usdd_withdrawal_proof_mutex, std::defer_lock);
    if (!proof_lock.try_lock()) {
        throw JSONRPCError(
            RPC_MISC_ERROR, "A withdrawal-proof reconstruction is already running");
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{drivechain::WITHDRAWAL_PROOF_SECONDS};
    const auto interruption_point = [&] {
        RpcInterruptionPoint();
        if (std::chrono::steady_clock::now() >= deadline) {
            throw JSONRPCError(
                RPC_MISC_ERROR, "Withdrawal-proof reconstruction work budget exhausted");
        }
    };

    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    const CBlockIndex* target{nullptr};
    usdd::WithdrawalAccumulatorState accumulator;
    std::vector<const CBlockIndex*> blocks_with_withdrawals;
    {
        LOCK(cs_main);
        const CChain& active = chainman.ActiveChain();
        target = ReadWithdrawalAccumulator(chainman, request.params[1], accumulator);
        CheckWithdrawalProofBounds(1,index,accumulator.count);
        uint64_t prior_count{0};
        int height{1};
        const CBlockIndex* cursor{nullptr};
        const auto status = drivechain::haskell::ParentReplayStore(
            drivechain::haskell::ReplayStoreFlow::RPC_WITHDRAWAL_HISTORY,
            [&](uint32_t step) EXCLUSIVE_LOCKS_REQUIRED(cs_main) -> uint32_t {
                switch (step) {
                case 1: return height <= target->nHeight;
                case 2:
                    if (height % drivechain::WITHDRAWAL_PROOF_INTERRUPT_INTERVAL == 0) interruption_point();
                    cursor = active[height];
                    return 1;
                case 3: return cursor->m_usdd_withdrawal_accumulator.has_value();
                case 4: return cursor->m_usdd_withdrawal_accumulator->count >= prior_count;
                case 5: return cursor->m_usdd_withdrawal_accumulator->count != prior_count;
                case 6: blocks_with_withdrawals.push_back(cursor); return 1;
                case 7: prior_count = cursor->m_usdd_withdrawal_accumulator->count; ++height; return 1;
                default: throw std::logic_error("invalid withdrawal history scan action");
                }
            });
        if (status == 1) throw JSONRPCError(RPC_INTERNAL_ERROR, "Discontinuous withdrawal accumulator; reindex required");
        if (status == 2) throw JSONRPCError(RPC_INTERNAL_ERROR, "Nonmonotonic withdrawal accumulator; reindex required");
    }

    std::vector<usdd::EthereumWithdrawalClaim> claims;
    claims.reserve(static_cast<size_t>(accumulator.count));
    drivechain::haskell::ParentReplayEach(blocks_with_withdrawals, [&](const CBlockIndex* blockindex) {
        interruption_point();
        CBlock block;
        if (!chainman.m_blockman.ReadBlock(block, *blockindex)) {
            throw JSONRPCError(RPC_MISC_ERROR,
                "A withdrawal-containing block is pruned or unreadable; use an archival node or indexer");
        }
        std::vector<usdd::EthereumWithdrawalClaim> appended;
        std::string extraction_error;
        if (!usdd::ExtractEthereumWithdrawals(
                block, Params().GetConsensus().hashGenesisBlock,
                claims.size(), appended, &extraction_error)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, extraction_error);
        }
        claims.insert(claims.end(), appended.begin(), appended.end());
        return true;
    });
    interruption_point();
    usdd::WithdrawalInclusionProof proof;
    usdd::WithdrawalHash reconstructed_root;
    std::string proof_error;
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::RPC_WITHDRAWAL_PROOF,
        [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return claims.size() == accumulator.count;
        case 2: throw JSONRPCError(RPC_INTERNAL_ERROR, "Reconstructed withdrawal count disagrees with the persisted accumulator");
        case 3: return usdd::BuildWithdrawalInclusionProof(claims, index, proof, reconstructed_root, &proof_error);
        case 4: return reconstructed_root == accumulator.root;
        case 5: return !proof_error.empty();
        case 6: throw JSONRPCError(RPC_INTERNAL_ERROR, proof_error);
        case 7: throw JSONRPCError(RPC_INTERNAL_ERROR, "Reconstructed withdrawal root mismatch");
        default: throw std::logic_error("invalid withdrawal proof action");
        }
    });

    UniValue siblings(UniValue::VARR);
    for (const auto& sibling : proof.siblings) siblings.push_back(HexStr(sibling));
    UniValue result(UniValue::VOBJ);
    result.pushKV("index", index);
    result.pushKV("root", HexStr(accumulator.root));
    result.pushKV("count", accumulator.count);
    result.pushKV("leaf", HexStr(proof.claim.leaf));
    result.pushKV("burn_id", HexStr(proof.claim.burn_id));
    result.pushKV("txid", HexStr(proof.claim.burn_txid_display));
    result.pushKV("vout", static_cast<uint64_t>(proof.claim.burn_vout));
    result.pushKV("asset", HexStr(proof.claim.asset_id));
    result.pushKV("vault_id", HexStr(proof.claim.vault_id));
    result.pushKV("recipient", HexStr(proof.claim.recipient));
    result.pushKV("amount_usdt_micro", proof.claim.amount_usdt_micro);
    result.pushKV("siblings", siblings);
    result.pushKV("authorizing", false);
    return result;
},
    };
}

// END ELEMENTS
//

void RegisterBlockchainRPCCommands(CRPCTable &t)
{
    static const CRPCCommand commands[] =
    {
        {"blockchain", &getblockchaininfo},
        {"blockchain", &getchaintxstats},
        {"blockchain", &getblockstats},
        {"blockchain", &getbestblockhash},
        {"blockchain", &getblockcount},
        {"blockchain", &getblock},
        {"blockchain", &getblockfrompeer},
        {"blockchain", &getblockhash},
        {"blockchain", &getblockheader},
        {"blockchain", &getchaintips},
        {"blockchain", &getalphacheckpointevidence},
        {"blockchain", &getdifficulty},
        {"blockchain", &getdeploymentinfo},
        {"blockchain", &gettxout},
        {"blockchain", &gettxoutsetinfo},
        {"blockchain", &pruneblockchain},
        {"blockchain", &verifychain},
        {"blockchain", &preciousblock},
        {"blockchain", &scantxoutset},
        {"blockchain", &scanblocks},
        {"blockchain", &getdescriptoractivity},
        {"blockchain", &getblockfilter},
        {"blockchain", &getecxstateutxoroot},
        {"blockchain", &getecxconsensuscontext},
        {"blockchain", &getecxbondinboxentries},
        {"blockchain", &getdrivechainpegevents},
        {"blockchain", &getdrivechaindepositdestination},
        {"blockchain", &getdrivechainwithdrawalbundle},
        {"blockchain", &verifydrivechainwithdrawalbundle},
        {"blockchain", &submitdrivechainwithdrawal},
        {"blockchain", &getusddwithdrawalaccumulator},
        {"blockchain", &getusddwithdrawalproof},
        {"blockchain", &getsidechaininfo}, // ELEMENTS
        {"blockchain", &dumptxoutset},
        {"blockchain", &loadtxoutset},
        {"blockchain", &getchainstates},
        {"hidden", &invalidateblock},
        {"hidden", &reconsiderblock},
        {"hidden", &waitfornewblock},
        {"hidden", &waitforblock},
        {"hidden", &waitforblockheight},
        {"hidden", &syncwithvalidationinterfacequeue},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
