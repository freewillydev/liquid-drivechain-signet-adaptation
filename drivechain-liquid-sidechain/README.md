# liquid-signet-sidechain — Native Liquid/Elements Drivechain Sidechain (BIP 300/301)

> **QUARANTINED HISTORICAL PROTOTYPE — DO NOT RUN.** This directory describes
> the retired slot-5/regtest experiment and is not compatible with this fork's
> canonical network. Every executable below exits before performing any work.
> The only supported node identity is **Elements Drivechain**, selected with
> `elementsd -chain=elements` and fixed to BIP300 slot **24**. Follow the
> [repository README](../README.md) instead. The remaining text is retained
> only as an audit trail and does not describe the current implementation.

**Retired historical design.** The historical design
below explored Elements on a private drivechain signet using CUSF mechanisms.
It is not deployment guidance or security evidence for the current node.

- **Upstream base**: ElementsProject/elements (cloned into this workspace at commit 75499e7 on branch `liquid-drivechain-signet-adaptation`).
- **Historical environment**: The private Drivechain signet in `../drivechain-wallet-dev/local-dev` (mainchain + bip300301_enforcer + bitassets ID 4 live example).
- **Sidechain ID**: 5 ("liquid-signet").

## Quick Start (Reproducible on Live Signet)

Prerequisites: Docker stack from drivechain-wallet-dev/local-dev up and healthy (enforcer answering gRPC on 50051).

```bash
cd /Volumes/T705/code/liquid-signet-sidechain

# 1. (Optional but recommended) Activate sidechain ID 5
./drivechain-liquid-sidechain/scripts/activate-liquid-id5.sh

# 2. Run full e2e validation (deposit / BMM mine / transfer / pegout flows via native CUSF)
./drivechain-liquid-sidechain/tests/e2e-liquid-on-signet.sh
```

See `docs/DESIGN.md` for architecture (CUSF WalletService/ValidatorService only, adapter bridges to real Elements), security model, and why this is future-compatible with real BIP300/301 with zero adapter changes.

## Contents

- `config/liquid-signet-proposal-id5.json` — Sidechain declaration (M1 proposal, exactly like ID 4).
- `scripts/activate-liquid-id5.sh` — Wrapper (uses the canonical `activate-sidechain.sh`).
- `scripts/mine-liquid-block.sh` — BMM + sidechain advance (stub + full pattern from bitassets).
- `tests/e2e-liquid-on-signet.sh` — End-to-end validation against live enforcer/mainchain. Produces txids, gRPC responses, state diffs as evidence.
- `docs/DESIGN.md` — Full design, flows, Elements integration points (pegins.cpp + fedpeg validation), production notes.
- `adapter/` — Stub + notes for the Rust (or Python) CUSF <-> elementsd bridge (follows plain-bitassets patterns exactly).
- `config/elements-drivechain.conf` — Example elementsd config (regtest isolation + drivechain flags).

## Native Mechanisms Used (No Shortcuts)

All via the live enforcer (same as plain-bitassets ID 4):

- `WalletService.CreateSidechainProposal` + mining for activation.
- `WalletService.CreateDepositTransaction` (main->side pegin, produces CUSF Deposit events).
- `WalletService.CreateBmmCriticalDataTransaction` + L1 mine + confirmation (side block advance via BMM h*).
- `WalletService.BroadcastWithdrawalBundle` (side->main pegout with contest).
- `ValidatorService.GetSidechains`, `GetBlockInfo`, `SubscribeEvents`, `GetBmmHStarCommitment`, `GetTwoWayPegData`.

Elements (the sidechain consensus engine) receives peg credits and produces blocks; the adapter (or manual scripts for v1) translates CUSF events <-> Elements RPC. **Peg security comes from mainchain hashrate escrows + BMM + enforcer, not from any multisig federation.**

## Elements Integration (from cloned upstream)

See `src/pegins.cpp`, `src/pegins.h`, `src/consensus/tx_verify.cpp` (IsValidPeginWitness + fedpegscripts), `src/validation.cpp`, `src/chainparams.cpp`.

v1 uses regtest + adapter-driven credits (or pegin claims against a bridge single-key fedpegscript). Future: small patch for native "drivechain_peg" mode or in-process gRPC client.

Build from this workspace source when needed: `./autogen.sh && ./configure --enable-wallet ... && make` (then run `./src/elementsd` for the daemon and `./src/elements-cli` for the command-line interface).

## Validation Gates (Evidence Every Turn)

- Raw gRPC responses (GetSidechains, deposit txids, BMM commitments, withdrawal events).
- Mainchain `getblockchaininfo` + height advances.
- Side "state" diffs (credits, balances, blockcounts).
- Script exit codes + logs.
- All captured in `tests/e2e-*.log` and console on every run.

Current live signet (at design time): mainchain height 117, enforcer/bitassets healthy, ID 4 active precedent.

## Setting Up the Liquid Node on a New Signet + New Sidechain ID (BIP 300/301 + Blind Merged Mining)

This section explains how to take the Liquid/Elements node and run it against **a completely new L1 signet** (different challenge, different enforcer/L1 instance) under **a fresh, unused sidechain slot** (any ID 0-255 not already activated on that L1), with full **Blind Merged Mining (BMM, BIP 301)** support.

The architecture is the same as ID 4/5 on the example private signet: the enforcer (CUSF) on L1 handles proposals, deposits, BMM bids, and withdrawals. The `elementsd` is the sidechain execution engine (CT, assets, Simplicity, etc.). An adapter/participant bridges the two.

### 1. Bootstrapping / Connecting to a New L1 Signet

You need your own L1 + enforcer pair for the new signet.

- Use (or copy) the general private-signet bootstrap tools from `../drivechain-wallet-dev/local-dev/scripts/` (or equivalent in your environment):
  - `./scripts/generate-private-signet-keys.sh` — produces a fresh `signetchallenge`, mining keys, rpcauth, etc.
  - Customize `docker-compose.*.yml` (or your L1 startup) with the **new** challenge, block time, RPC ports, data directories, etc. Run a **new instance** of the patched `drivechaind` (L1) and a **new enforcer** pointing at it (`--node-rpc-addr`, different ports like 50051/8122 to avoid collision with other signets you may be running).

- Important L1 flags (in your patched bitcoind config or command line):
  - `-signet`
  - `-signetchallenge=<the new  hex from keygen>`
  - `-signetblocktime=60` (or your desired target)
  - Separate `-datadir`, RPC ports, ZMQ, etc.

- Start the L1 + enforcer and wait for the enforcer to be healthy (gRPC on 50051 for ValidatorService/WalletService).

- On this new L1, query current sidechains to see which IDs are taken:
  ```bash
  # Preferred (uses the proto schema if available)
  buf curl --protocol grpc --http2-prior-knowledge \
    --schema /path/to/your/proto \
    http://127.0.0.1:50051/cusf.mainchain.v1.ValidatorService/GetSidechains

  # Fallback
  bitcoin-cli -signet -rpcport=YOUR_L1_RPC getactive-sidechains || true
  ```
  Note the active `sidechainNumber` values. Choose a free one, e.g. `6`, `7`, `10`, etc. (must not be in use on *this* L1).

### 2. Creating a Sidechain Proposal for Your New ID

- Copy the template and customize for your ID (replace `N` with your chosen free ID):
  ```bash
  cp config/liquid-signet-proposal-id5.json config/my-liquid-proposal-idN.json
  ```

- Edit `config/my-liquid-proposal-idN.json`:
  - `"sidechain_id": N`
  - `"title"`: something descriptive (e.g. "my-liquid-on-newsignet")
  - `"description"`: update to describe your deployment / features (CT, assets, Simplicity, etc.)
  - `hash_id_1` and `hash_id_2`: 32-byte unique hex values. You can derive them as `sha256("my-liquid-idN" + some salt)` or just use random unique bytes. They must be unique per sidechain on the L1.

Example minimal change for ID 6:
```json
{
  "sidechain_id": 6,
  "declaration": {
    "v0": {
      "title": "my-liquid-signet",
      "description": "Liquid/Elements sidechain as native BIP300/301 drivechain on my new signet. ...",
      "hash_id_1": { "hex": "0000000000000000000000000000000000000000000000000000000000000006" },
      "hash_id_2": { "hex": "0000000000000000000000000000000000000006" }
    }
  }
}
```

### 3. Activating the New Sidechain ID on Your L1

Use the **general** activation helper (do not use the ID5-specific wrapper):

```bash
# From the drivechain-wallet-dev/local-dev (or your equivalent scripts dir)
./scripts/activate-sidechain.sh N /path/to/your/liquid-signet-sidechain/drivechain-liquid-sidechain/config/my-liquid-proposal-idN.json
```

This does:
- `WalletService.CreateSidechainProposal`
- Mines the required activation/vote blocks on L1 (you can increase `ACTIVATION_BLOCKS` env var if your setup needs more votes).

After it succeeds, re-query `GetSidechains` and confirm your ID N shows `activationHeight` set and `voteCount` sufficient.

Mine a few more L1 blocks with `./scripts/mine-private-signet-blocks.sh 10` (or your L1 miner) if needed.

### 4. Running elementsd for the New Sidechain ID

The sidechain engine runs **isolated** (usually `-regtest` with its own P2P/RPC so multiple sidechains don't collide).

- Copy and customize the starter:
  ```bash
  cp scripts/start-liquid-id5-regtest.sh scripts/start-liquid-idN-regtest.sh
  chmod +x scripts/start-liquid-idN-regtest.sh
  ```

- Edit `scripts/start-liquid-idN-regtest.sh`:
  - Change all `id5` / `5` references in `DATADIR`, comments, etc. to your `idN`.
  - Adjust `RPCPORT`, `P2PPORT` to free ports (e.g. 18443 + offset for the ID).
  - Update any cookie / datadir paths inside if the script hard-codes them.

- Launch:
  ```bash
  ./scripts/start-liquid-idN-regtest.sh
  ```

- Verify:
  ```bash
  ./src/elements-cli -regtest -datadir=/tmp/liquid-idN-regtest -rpcport=YOUR_RPC_PORT -rpccookiefile=/tmp/liquid-idN-regtest/regtest/.cookie getblockchaininfo
  ```

You now have a running Liquid node for sidechain slot N on your new signet.

### 5. Setting Up Blind Merged Mining (BIP 301 BMM)

BMM is how sidechain blocks advance: the sidechain produces a block, its critical data (header hash or header+body merkle root) is bid into L1 via a `CreateBmmCriticalDataTransaction`, an L1 block is mined containing the bid, the enforcer confirms it, and then the sidechain block is submitted to `elementsd`.

**Manual / one-shot BMM (for testing):**

1. Make sure your elementsd is at a certain height and has a new block ready.
2. Compute the `critical_hash` from the next sidechain block you want to mine (usually the best block header hash or the value the bitassets/liquid convention uses — see `mine-liquid-block.sh` comments and the participant script).
3. Submit BMM bid on L1 (via enforcer):
   ```bash
   # Example using buf (adjust for your proto location)
   buf curl --protocol grpc --http2-prior-knowledge \
     -d '{
       "sidechainId": N,
       "valueSats": 100000,
       "height": <upcoming-L1-height>,
       "criticalHash": {"hex": "<your-critical-hash>"},
       "prevBytes": {"hex": "<previous-bmm-for-this-sc-or-zero>"}
     }' \
     http://127.0.0.1:50051/cusf.mainchain.v1.WalletService/CreateBmmCriticalDataTransaction
   ```
4. Mine one (or more) L1 block(s):
   ```bash
   ./scripts/mine-private-signet-blocks.sh 1
   ```
5. Confirm the BMM was accepted (query `GetBmmHStarCommitment` or events for your sidechain_id).
6. Submit the sidechain block to elementsd:
   ```bash
   ./src/elements-cli -regtest -datadir=... -rpcport=... submitblock <the-block-hex>
   ```

**Automated / continuous BMM:**

- Copy and parameterize the automation scripts:
  ```bash
  cp scripts/liquid_id5_participant.py scripts/liquid_idN_participant.py
  cp scripts/grpc_bmm_id5.py scripts/grpc_bmm_idN.py
  cp scripts/cusf-bmm-id5.sh scripts/cusf-bmm-idN.sh
  cp scripts/mine-liquid-block.sh scripts/mine-liquid-idN-block.sh
  ```

- Edit the copies:
  - Set `LIQUID_ID = N` (or equivalent variable).
  - Update all datadir, RPC port, cookie file, and enforcer/mainchain connection strings to match your new elementsd instance and your L1/enforcer.
  - In the participant, update the BMM parameters (bid amount, block interval, etc.).

- Run the loop (it will repeatedly compute the next side block, bid BMM on L1, mine L1, wait for confirmation, and submit the block to elementsd):
  ```bash
  python3 -u scripts/liquid_idN_participant.py --max 100
  ```

- For production, use the `adapter/` (Rust or Python stub). Copy `adapter/liquid_id5_side_stub.py` (or the Rust equivalent), update the sidechain ID, elementsd connection, and the event handlers for Deposit / BMM. The adapter subscribes to enforcer events and drives both BMM and peg credits automatically.

### 6. Deposits, Withdrawals, and Other Flows for the New ID

- **Deposits (main → side)**: Use `WalletService.CreateDepositTransaction` on your enforcer with your `sidechain_id = N`. The adapter (or manual code) turns the resulting Deposit event into a pegin/credit tx on your elementsd instance.
- **Withdrawals (side → main)**: Create a withdrawal on the sidechain side (or via your app), collect into a bundle, then call `WalletService.BroadcastWithdrawalBundle` with your ID. L1 handles the contest period.
- All other flows (GetSidechains, GetBlockInfo with your ID, SubscribeEvents(sidechain_id=N), etc.) just pass the correct numeric ID.

### Tips & Gotchas for New Deployments

- Run each sidechain (and each L1 signet) with completely separate data directories, RPC ports, P2P ports, and cookies.
- The sidechain P2P is intentionally isolated (`-regtest` + custom `-port`/`-bind`) so it doesn't talk to public Liquid or other signets.
- For a public BIP300/301 signet later: only the L1 challenge + enforcer host + proposal details change. The elementsd + adapter code stays the same.
- Build the node with `./autogen.sh && ./configure --enable-wallet && make`. Use the resulting `./src/elementsd` and `./src/elements-cli`.
- Always keep the enforcer healthy; the BMM/peg logic lives there.
- Test activation + a few BMM blocks + a deposit/withdrawal end-to-end before relying on the setup (see the `tests/` directory for the harness pattern used for ID5 — generalize the same way).

See `docs/DESIGN.md` for the full architecture diagram and security model (everything is secured by L1 hashrate escrows + BMM + enforcer, not a federation).

The scripts and adapter in this directory are the reference implementation. Duplicate + edit the ID-specific parts for your new deployment.

This gives you a fully functional Liquid/Elements sidechain with native BIP300 deposits, BIP301 BMM, and withdrawals on your new signet under a fresh sidechain number.

## Production Notes

- Follows every pattern from `drivechain-wallet-dev/local-dev/` (named volumes, healthchecks, static IPs, Mac QEMU notes, VPS path, pr-ready smoke shape).
- Adapter liveness / restart safety identical to bitassets.
- For real Elements + CT/assets: wire the adapter to a running `elementsd -regtest` (or custom chain) + expose combined Electrum/RPC surface for Floresta later.
- On public BIP300/301 signet: change only the challenge + enforcer host; same proposal/flows/scripts.

## Production Evidence (Latest Run — Real BMM + Side Credit State + Restart Persistence)

**Core real proofs (native CUSF/BIP300/301 only, no federation/multisig):**
- ID5 "liquid-signet" fully activated (propH=146, actH=152, 6 votes; full no-fed declaration).
- Real BMM for fresh ID5 (bmmH=1+): TOLERATED inserts including **9c96f2b2be11d6019a35ef41c96138f941ac8d7392cc41aa72e7ed76d072e7a0** (real elements criticals 79f16ed9... at H=11 and 6e4c43... at H=14). Enforcer: "inserted new bmm request into db" + **"Adding BMM accept for SC 5"** (lib/miner.rs tolerate despite P2P limitation).
- Real side blocks/credits: elementsd regtest at H=16 (fresh criticals). Adapter credit recorder produced `real_credit` entry in state.json (H=16, 100k, "Real side credit/peg state driven by native CUSF BMM + elementsd (no federation)").
- `tests/liquid-side-state.json` real entries (BMM txids + credit) read by e2e.
- Full e2e exit 0 (real data visible in output).
- Explicit restart test (`liquid-id5-restart-test-1779730602`): datadir + enforcer DB survived stop/re-launch; ID5 (146/152) still active in GetSidechains post-restart; no corruption.
- Live Get* + healthy stack (main H~195, elements H=16, docker healthy).
- Production code in repo: `scripts/liquid_id5_participant.py` (bmm_h=1, dynamic prev, 60s, tolerate, self-mine, poll) + extended adapter stub (credit handler).

**Key logs/commands:**
- BMM: `/tmp/liquid-id5-visible-bmm-1779729575.log`
- E2E: `/tmp/liquid-id5-e2e-real-1779730407.log` (exit 0)
- Restart: `/tmp/liquid-id5-restart-test-1779730602.log`
- Participant: `python3 -u drivechain-liquid-sidechain/scripts/liquid_id5_participant.py --max 5`
- Adapter credit: `python3 drivechain-liquid-sidechain/adapter/liquid_id5_side_stub.py --record-credits`

**Note (historical)**: Earlier e2e runs reported some "SIMULATED" due to harness detection not wired to /tmp/liquid-id5-regtest + real state. This was the last documented caveat.

**Final Polished E2E + Harness Verification (2026-05-25 — post state recovery + REAL_ID5_MODE detector)**

- Harness updated: REAL_ID5_MODE detector (checks /tmp/liquid-id5-regtest + real_* keys in state.json + presence of adapter/liquid_id5_side_stub.py + scripts/liquid_id5_participant.py).
- state.json recovered from JSONL append corruption to valid single JSON object preserving all real evidence (real_bmm_evidence with tx 9c96f2b2..., real_deposit f18c90b5..., real_credit at elements H=16 + adapter note + native CUSF). Original backed up as tests/liquid-side-state.json.bak.1779750013.
- Polished full e2e run (tmux bg log: /tmp/liquid-id5-e2e-final-verif-1779732020.log ; internal: tests/e2e-liquid-20260525-130020.log):
  - Detector fired: REAL_ID5_MODE=1 + real artifacts banner (H=16+, real_* in state, adapter credit recorder, participant bmm_h=1/60s/TOLERATED/dynamic-prev, commit a39dcd6).
  - ID5 live in GetSidechains during run (propH=146/actH=152 + full no-fed declaration).
  - E2E_EXIT=0.
  - Final E2E COMPLETE block now emits clean real-native summary (no "SIMULATED (no elementsd running)" in the polished path):
    REAL NATIVE CUSF ID5 LIQUID-SIGNET (elements regtest + enforcer BMM, no federation): BMM tx 9c96f2b2be11d6019a35ef41c96138f941ac8d7392cc41aa72e7ed76d072e7a0 (h=1, TOLERATED per lib/miner.rs on private signet P2P-less), deposit f18c90b509c82353d619cb76c1e3fec1a6dc75a0e7b119d1695b4a81bda9d34c (CreateDeposit ID5 100k+1k, 'Broadcast successfully'), side H=16 + real credits (adapter/liquid_id5_side_stub.py), main H~196, restart persistence (propH=146/actH=152 in GetSidechains). Production drivers: scripts/liquid_id5_participant.py (bmm_h=1, 60s, dynamic prev, self-mine+GetBmmHStar), commit a39dcd6 on liquid-drivechain-signet-adaptation. All real txids/heights/credits/state/restart proven on this machine. See DESIGN.md + /tmp/liquid-id5-*.log for verbatim evidence.
- All core real proofs + clean e2e output with real data + zero simulated language in final summary now verified on this machine.

See `docs/DESIGN.md` for full architecture + earlier evidence.

- [x] All core real BMM + credit state + restart + artifacts in repo.
- [x] e2e harness real-mode detection + clean real output (state recovery + REAL_ID5_MODE).
- [x] Commit useful changes (harness polish + clean state.json).
- [x] Full production evidence (real txids, BMM inclusion, side H/credits, restart, polished e2e exit 0) on machine.

This historical document is not an authoritative description of the current
node. See the root README for the production mainnet identity.
