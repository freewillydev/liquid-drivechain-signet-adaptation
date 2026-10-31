# Upstream integration (2026-09-02)

This is a history-preserving merge, not a replacement of the fork with upstream
or an `ours` merge that only changes Git ancestry.

- Fork parent: `e90b9afee34d3e805ee2a6b3fac910683f0dc007`.
- ElementsProject/elements master: `4ddaefc8ccfdd9db3053b633092c28285da081e4`.
- Shared ancestor: `27c2fb6b7de404908f9ef2eb5c98c9989d1ab8e4`.
- Imported upstream history: 15,093 commits, moving from the 23.99 to the 28.99
  development line. This is not a tagged upstream release.

## Compatibility boundaries

The frozen native identity, slot 24, parent checkpoint, verifier identity,
authenticated parent replay, deposit uniqueness, withdrawal burn/M6 checks,
CTV and mTLS policy are retained. Installed binaries still accept only
`-chain=elements`. Upstream's other networks are not supported production modes.
No live node, wallet, chain directory or released binary was replaced during
this integration.

Important adaptations include:

- Port fork node, wallet, consensus, tests and verifier dependencies into
  upstream's CMake build. Preserve the public `libelementsconsensus` C ABI,
  shared/static installations and relocatable pkg-config metadata.
- Adapt stream, chain-type, mempool, startup, logging and script APIs while
  retaining the fork's validation rules. Preserve null-tip startup handling
  and exclude unauthenticated Drivechain headers when rebuilding best-header
  state.
- Explicitly retain the original block-header hash preimage after upstream
  removed `SER_GETHASH`. Withdrawal/BMM commitments, ECX fields, parent height
  and replay cursors must not disappear from the hash. Proof solutions and
  witnesses must not enter it. Regression vectors compare hash, BMM critical
  hash and serialized bytes against the pre-merge implementation across 1,024
  combinations of header modes and fields.
- Keep private standard-regtest and alternate-identity functional executables
  separate from production binaries. Their test-only startup allowance is
  never installed or compiled into the shared production node library.
- Retain the Qt asset/LWK dialog sources and canonical Elements URI prefix
  in the optional GUI build. Historical LWK helper workflows remain
  quarantined; compilation does not make them supported native workflows.
- Retain ECX benchmark registration with upstream's priority-based API when
  the real ECX verifier archive is supplied. The archive is required for
  those benchmarks; it is never replaced with a test cryptography stub.

## Build

Use CMake 3.22+, a C++20 compiler, and the platform dependencies described in
the upstream build documents. Autotools and the old hand-maintained MSVC
project files have been removed upstream. Do not reuse an Autotools build
directory. The inherited dependency recipes are not themselves evidence of
a validated fork release.

Current Alpha configuration from the repository root (replace the absolute paths).
The three compiler definitions below match the running Alpha release: omitting
them does not reproduce its frozen catalogue and activation profile.

```sh
cmake -S . -B /absolute/path/to/build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  '-DCMAKE_CXX_FLAGS=-DECX_SIMPLICITY_CATALOGUE_FROZEN=1 -DECX_PRODUCTION_ACTIVATION_PROFILE_FROZEN=1 -DECX_SIMPLICITY_CATALOGUE_SHA256_HEX=\"bc981c9ba6665d16d95fea6a329b5c7317eefe520ffc3b12722d76fad270af1f\"' \
  -DBUILD_GUI=OFF -DBUILD_TESTS=ON \
  -DUSDD_SP1_VERIFIER_ARCHIVE=/absolute/path/to/libusdd_sp1_verifier.a \
  -DECX_SP1_VERIFIER_ARCHIVE=/absolute/path/to/libecx_sp1_verifier.a
cmake --build /absolute/path/to/build --parallel 1
/absolute/path/to/build/bin/test_elements --log_level=error --report_level=detailed
python3 test/functional/test_runner.py \
  --configfile=/absolute/path/to/build/test/config.ini
```

The USDD archive must match the pinned semantic identity. ECX needs its
separate SP1 6.3.1 Groth16 **and custody** entry points; the USDD archive is not
a substitute. Missing verifiers retain fail-closed runtime checks and do not
constitute a supported cryptographic configuration. CMake checks the specified
archives' link ABIs; startup and tests check identity and behavior.

On macOS, also set `CMAKE_OSX_DEPLOYMENT_TARGET` explicitly to match the
archives (the local USDD archive targets 11.0). The archive checker rejects
objects with a mismatched or missing deployment target. Platform Rust link
dependencies can be specified with `USDD_SP1_VERIFIER_NATIVE_LIBS` and
`ECX_SP1_VERIFIER_SYSTEM_LIBS`; Windows requires explicit values. These are
CMake semicolon-separated library lists.

Wallets use SQLite descriptors by default. Legacy Berkeley DB wallets/tests
require `-DWITH_BDB=ON` and a compatible BDB dependency. The optional Qt 5 GUI
uses `-DBUILD_GUI=ON`; `CMAKE_PREFIX_PATH` may be needed for Qt discovery.
Enable its tests with `-DBUILD_GUI_TESTS=ON` and benchmarks with
`-DBUILD_BENCH=ON`. Without the ECX archive, CMake explicitly reports that
the additional ECX jet benchmarks are not built.
Keep `TMPDIR`, build output and caches on a volume with enough space. The
validation build used `nice -n 10` and one worker. Do not overwrite an active
installation or point test executables at real chain/wallet data. Preserve
backups before a later deployment; newer upstream database or wallet formats
must not be assumed downgrade-compatible.

## Local validation

Validation used macOS arm64, an isolated build, the pinned native USDD verifier,
SQLite descriptor wallets and disposable test data. It created no public
transactions and did not change the active node's configuration.

- Daemon, CLI, transaction/utility/wallet tools, private functional executables,
  unit binary, optional Qt GUI/tests, benchmark binary and shared/static
  consensus library built successfully.
- Full unit suite: **816 of 817 passed** (including one with warnings).
  The remaining test,
  `ecx_exchange_state_tests/incremental_successor_accepts_real_rust_crypto_source_vector`,
  aborts because the separate ECX custody verifier is absent. This same test
  failed before the merge; it has not been disabled or weakened. The final
  run passed 19,723,202 of 19,723,203 assertions.
- Native first-deposit, CTIP/replay, authorized M6, withdrawal, startup and
  BMM/header regression fixtures passed within that suite. Header compatibility
  vectors were generated with the pre-merge C++ implementation, not inferred
  from the new implementation alone.
- `feature_standard_regtest_ecx_isolation.py`, `wallet_basic.py`, `wallet_send.py` and
  `feature_ecx_withdrawal_guard.py` passed with descriptor wallets. The
  withdrawal rejection fixture uses real owner-only TLS credentials and an
  explicit trusted grpcurl executable; it does not bypass transport preflight.
- Seven mTLS/helper tests passed, including actual TLS authentication and
  forwarding, wrong/missing identities and endpoint/credential rejection.
- Shared and static C consumer probes passed after component installation,
  including API version, valid transactions and malformed-input errors.
  pkg-config metadata is relocatable; the static probe has no build-tree
  libelementsconsensus dylib dependency.
- Headless Qt option, URI and nested-RPC tests passed with
  `QT_QPA_PLATFORM=minimal`. The application, wallet and address-book GUI
  test bodies are skipped on macOS in that mode, so this is not a pass for
  interactive wallet coverage. The suite now retains disposable data and
  QSettings paths even when individual test fixtures restore global state.
- The benchmark binary passed `-sanity-check -priority-level=high`.
  Both additional ECX benchmark translation units passed native C/C++ syntax
  checks, but their linking/execution requires the absent ECX archive.

Local logs and disposable fixtures are under
`/Volumes/T705/elements-upstream-build-20260902/`; they are not release artifacts
and are not committed, particularly wallet data and private TLS credentials.

## Remaining validation limits

- Link the separate ECX custody verifier and rerun the full suite before
  claiming it is green. The private identity/catalogue functional test was
  skipped because its fixture catalogue is not enabled in this build.
- The inherited `feature_confidential_transactions.py` reached its legacy
  `dumpwallet` step and failed on a descriptor-only build. Its earlier proof
  checks ran, but the full test is **not** a pass. Run it with the required
  legacy wallet dependency/configuration.
- The historical ECX positive-withdrawal functional fixture uses an obsolete
  HTTP mock and was not run as proof of the current mTLS path. It needs a real
  authenticated gRPC fixture; native deposit/M6 unit coverage is not a substitute
  for that test or deployed-miner payment.
- No current Windows/Linux release, portable macOS package, live parent-enforcer
  lifecycle, or hosted CI run was validated. Local Homebrew libraries emit
  deployment-target warnings, so the local executable is not a portable release.
- Inherited CI/dependency scripts still contain historical Autotools paths and
  do not supply this fork's verifier archives. Historical release recipes are
  intentionally pinned to older source. They require a separate current-source
  integration before release use; their presence is not a passing CI claim.

The [security remediation release gates](security-report-remediation.md) still
apply. Upstream synchronization and release validation are separate processes.
