// Copyright (c) 2026 The Elements developers
// Distributed under the MIT software license, see the accompanying file COPYING.
#ifndef BITCOIN_NODE_DRIVECHAIN_DEPOSITS_H
#define BITCOIN_NODE_DRIVECHAIN_DEPOSITS_H

#include <primitives/bitcoin/transaction.h>
#include <optional>

namespace node {
struct NodeContext;
/** One bounded pass; cursor wraps so new, immature and reorged deposits are retried. */
void AutoImportDrivechainDeposits(NodeContext& node,
    std::optional<Sidechain::Bitcoin::COutPoint>& cursor);
}
#endif
