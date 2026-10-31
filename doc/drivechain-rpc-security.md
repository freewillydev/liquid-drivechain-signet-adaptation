# Secure native Drivechain RPC setup

The current network is `-chain=elements`, data subdirectory `elements-native-v1`,
the production identity targeting mainnet slot 24. It requires its own proposal activation.
See the [generated identity table](drivechain-network-identity.md) and
[identity and peg operations](drivechain-peg-operations.md).

## Parent and wallet RPC

Run the fully validating parent on the same trusted host, with `txindex`
enabled and RPC bound only to loopback. The native default port is 28532:

```ini
mainchainrpchost=127.0.0.1
mainchainrpcport=28532
mainchainrpccookiefile=/absolute/path/to/parent-bitcoin/.cookie
drivechainl1blocksync=0
```

Do not configure `mainchainrpcuser` or `mainchainrpcpassword`. On POSIX the
rotating cookie must be a regular non-symlink file owned by the Elements user,
mode 0600, containing the canonical `__cookie__:` plus 64 hex characters.
The native default cookie location is the parent data directory's `.cookie` file.
The inherited `contrib/assets_tutorial` uses isolated tutorial chains and random
inline credentials. Its tests do not define the native `-chain=elements` policy;
do not copy tutorial authentication settings into a native deployment.
DNS names (including `localhost`), LAN addresses and inline parent credentials
are rejected. An explicit `mainchainrpccredentialfile` is also supported for a
trusted same-host bridge: it must be an owner-only, non-symlink private file
containing `user:password`, and cannot be combined with cookie or inline
credential options. Prefer the rotating cookie for direct parent access.
Verify the frozen parent checkpoint before using funds.

Elements' own authenticated JSON-RPC defaults to port 7071 and is restricted to
numeric loopback (IPv4 127/8 or IPv6 ::1). Use its generated cookie. Local
`rpcauth`/static credentials remain supported for existing clients. Native
`rest=1` is rejected because that listener bypasses RPC authentication.
Do not expose either HTTP listener on a LAN/public interface.

These local HTTP connections are authenticated but **not encrypted**. They
rely on trusted same-host isolation. Remote wallet access needs a separately
authenticated TLS tunnel/proxy with a narrow allowlist; never expose raw RPC.
This configuration does not protect against compromise of the host/user.

## Local BMM funding

Elements constructs the BIP301 M8 request as output zero of a normal parent
transaction. It funds and signs through an **explicit existing Bitcoin Core
wallet**, then uses parent `testmempoolaccept` and `sendrawtransaction`. It does
not request coins or signatures from an enforcer wallet, create/load a wallet,
or fall back to the parent's default wallet.

```ini
# Keep production disabled until the wallet, chain and spending policy are checked.
drivechainl1blocksync=0
drivechainbmmwallet=elements-bids
drivechainbmmbid=250
drivechainbmmreplacementextra=0
```

The named wallet must be loaded, unlocked for signing when necessary, and have
confirmed funds. Restrict it to the bid budget; do not select a savings wallet.
The configured bid is a minimum per-candidate transaction fee, not a total
spending cap: candidate fees can raise it under the existing pricing policy.
The fee is selected before signing; no fee-estimator adjustment can silently
raise it. Funding requires confirmed inputs and at least 1,000 sats of change.
The parent genesis and configured fork checkpoint, slot, current parent hash/height, funding outputs, and signed
transaction are checked before broadcast.

Signed requests are synchronously journaled in `bmm-bids/` under the network
data directory, scoped by parent genesis, wallet and slot. Keep this directory
across restarts. Lost replies retry the identical transaction; a different
candidate for the same parent is refused. An unmined stale request reuses its
inputs when possible, replacing it only within the selected fee plus the
explicit replacement allowance. A rejected replacement waits for a later
attempt; it does not silently fund another conflicting bid. Do not share one
bid wallet across independent producers.

Mempool acceptance is not block acceptance. A compatible miner must include
the matching M7 commitment and M8 request. Elements still independently checks
the authenticated parent evidence. The parent can advance between the last
tip check and broadcast; no remote RPC sequence can make those atomic.

## Miner enforcer mutual TLS

Withdrawal proposals and optional enforcer queries use the authenticated unary
gRPC path. BMM funding/broadcast does not use gRPC. Withdrawal submission calls
the wallet-free `cusf.mainchain.v1.BlockProducerService/ProposeWithdrawalBundle`,
not the deprecated wallet-service alias. The miner operates the enforcer;
Elements needs only its endpoint and credentials, not a local enforcer daemon.
Submission is not approval: the genuine BIP300 vote and mined M6 remain required.
There is
no plaintext ConnectJSON fallback, bearer-cookie alternative, or PATH search.

The Haskell client is linked into the node and uses the gRPC C core directly.
No grpcurl executable, subprocess, shell, or server reflection is needed.
Remove the obsolete `drivechainbmmgrpcurl` setting from existing configurations.
Requests use generated bindings for the pinned enforcer protocol. Transport
retries are disabled; application retry policy remains with the caller.

If the enforcer serves plaintext gRPC, bind it to `127.0.0.1:50051` and use
the bundled mTLS proxy on `127.0.0.1:55051`. The proxy-to-enforcer hop is
plaintext on the trusted host; this is not end-to-end TLS inside the enforcer.
Do not forward that plaintext listener to another host or an untrusted network.

```sh
contrib/drivechain-mtls/generate-certs.sh /absolute/path/to/enforcer-tls /offline/issuer-ca elements-node-01
contrib/drivechain-mtls/run-mtls-proxy.sh /absolute/path/to/enforcer-tls 127.0.0.1:55051 127.0.0.1:50051 elements-node-01
```

Install HAProxy (`brew install haproxy` on macOS). The helper verifies client
certificates and the exact configured client identity, requires TLS 1.2 or later, and
negotiates HTTP/2 using ALPN `h2`. A TLS tunnel without ALPN is not compatible
with the gRPC C core, even if a grpcurl probe succeeds. The old
`run-stunnel-proxy.sh` name delegates to this helper for compatibility.

Configure absolute paths (relative credential paths resolve under the network
data directory):

```ini
drivechainbmmgrpcaddr=127.0.0.1:55051
drivechainbmmgrpcca=/absolute/path/to/elements-native-v1/enforcer-tls/ca.pem
drivechainbmmgrpccert=/absolute/path/to/elements-native-v1/enforcer-tls/elements-client.pem
drivechainbmmgrpckey=/absolute/path/to/elements-native-v1/enforcer-tls/elements-client-key.pem
drivechainbmmgrpcauthority=enforcer.local
```

On POSIX, credential files and their immediate directory must be owned by the
Elements user and not group/other writable; files must not be symlinks. The
client private key requires mode 0600. Numeric loopback is the default endpoint
policy. For a miner-operated remote endpoint, explicitly set
`drivechainenforcerremote=1`, use its IP or DNS name in `drivechainbmmgrpcaddr`,
and install the miner-issued client credentials and trusted CA. Set
`drivechainbmmgrpcauthority` to the server certificate's authenticated DNS name.
Remote opt-in does not relax mTLS, allow plaintext, or permit remote parent
wallet HTTP. An optional deprecated `drivechainbmmwalletaddr` must exactly
match it; `drivechainbmmconnectauthcookie` is unsupported.
The overall Haskell migration still requires a native macOS/Linux toolchain;
Windows packaging is not qualified. This transport change does not change that.
The configured authority is used for TLS server-name verification as well as
the request authority, including when connecting to a numeric loopback endpoint.

Run isolated transport regression tests (no live enforcer or funds):

```sh
cmake --build build --target haskell_grpc_probe -j1
python3 src/haskell/test/grpc_transport.py build/bin/haskell_grpc_probe /path/to/temporary-directory build/bin/elements-functional-test-node
```

Tests require Python grpcio/protobuf, protoc, bash, openssl, and HAProxy. The build needs
Cabal and gRPC C-core development libraries; Haskell dependency sources are pinned
in `src/haskell/GrpcDependencies.cmake`. Match native dependency deployment targets
to the intended release OS; locally installed libraries are not portable releases.
Missing/wrong client credentials must fail the TLS handshake. No plaintext or
insecure-certificate fallback is provided.

The generator's optional client identity is a lowercase DNS label. Its default
is `elements-client` for existing installations; filenames remain unchanged.
Use a separate key/identity for each operator and an exact identity allowlist
at the miner endpoint. The helper allows one identity, not per-method access
control or certificate revocation. A holder of an allowed certificate **and
private key** receives that identity's endpoint access. Do not share the key
among operators. CA compromise permits impersonation regardless of CN naming.

Daemon startup re-executes the node after detaching, retaining the initialization
pipe for `-daemonwait`. Configuration parsing already uses the threaded Haskell
runtime; using that runtime after a raw fork loses its worker threads and can
hang the first asynchronous gRPC request. The optional test-node argument above
checks daemon startup, read-only enforcer queries, and shutdown with isolated
fixtures. No live transactions are created.

## Production and rotation

Automatic `drivechainl1blocksync` defaults **off**. A named parent wallet does not
enable spending; `drivechainl1blocksync=1` is a separate explicit opt-in. The bid
is `max(configured bid, selected candidate fees)` and the replacement allowance
is per transaction, **not a lifetime spending cap**. Use only a dedicated wallet
with a finite authorized balance and no automatic refill. Disabling the bidder
cannot cancel transactions already in the parent mempool. Explicit manual bid
RPCs still spend when requested. Keep the bidder off during read-only setup.

The fresh child requires a matching parent proposal; see its
[network identity](drivechain-network-identity.md). An operator option cannot
substitute for proposal activation. Enforcer calls fail closed at use when credentials
are invalid; this is not a guarantee of a startup TLS probe.
A native `sendtomainchain` burn can be created without an available enforcer,
so verify the submission path before burning coins. Explicit bundle submission
returns an error on transport failure; creating a burn is not successful
submission or payment, and a later endpoint outage cannot undo a burn.

For withdrawal-service startup and recurring monitoring, install Python grpcio
and openssl and run the read-only preflight under the credential owner:

```sh
python3 contrib/drivechain-mtls/check_enforcer_tls.py \
  /absolute/path/to/enforcer-tls 127.0.0.1:55051 enforcer.local
```

Configure the deployment supervisor to require exit 0 before enabling withdrawal
workflows, and its monitoring system to run this hourly and alert on exit 1
(failure) or 2 (rotation due within 14 days). `--remote` is required for a remote
miner endpoint. This authenticates a bounded, read-only `GetChainInfo` request;
it does not propose a bundle, spend funds or treat the reply as consensus data.
It checks local CA/client expiry and the server certificate if present locally.
The remote server certificate is authenticated by gRPC at each probe; advance
expiry monitoring of an unprovided remote server certificate is the miner's
responsibility. A successful probe is only point-in-time readiness, not a
guarantee that a later withdrawal can be submitted or mined.

The helper is an operator integration point, **not automatically installed as
a system service or a mandatory node startup gate**. Nodes doing validation,
deposits or native BMM must remain usable without the optional enforcer.

The helper issues a 365-day CA and 90-day server/client certificates and refuses
to overwrite existing credentials. The CA key and serial are written to the
separate non-nested CA directory (default: `<credential-directory>-ca`), never
the runtime directory. Generate on the issuer host and deploy only runtime
credentials; a separate directory on the same host is not offline protection.
The proxy refuses to start if `ca-key.pem` remains in its runtime directory.
For old installations, preserve and move that key to secure offline storage
before restarting the proxy; do not delete the issuer key. Monitor expiry:

```sh
openssl x509 -checkend 1209600 -noout -in /absolute/path/to/enforcer-tls/elements-client.pem
openssl x509 -checkend 1209600 -noout -in /absolute/path/to/enforcer-tls/server.pem
```

Rotate using a newly issued private directory. Stop block production/Elements
and the proxy, switch both configurations to the new matching credentials,
start the proxy, verify authentication, then restart Elements. Do not delete
working credentials before verification. Stop the foreground proxy with its
supervisor or Ctrl-C.

Check listeners with `lsof -nP -iTCP -sTCP:LISTEN`: ports 28532, 7065, 50051
and 55051 must not listen publicly. No environment variables may bypass
withdrawal event verification or silently select another fee/slot/endpoint.
The legacy ECX-only `drivechainpegoutmainfeesats` option is deprecated and unused
now that its unsafe burn-and-submit path is disabled. It never sets the native
`sendtomainchain` RPC's explicit coin-denominated `mainchainfee` argument.
