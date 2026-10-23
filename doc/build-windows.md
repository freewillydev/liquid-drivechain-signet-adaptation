WINDOWS BUILD NOTES
====================

## This fork: native Haskell qualification build

The current fork requires a native GHC toolchain. The historical upstream
cross-compilation and MSVC instructions below do **not** qualify the migrated
node. The opt-in `ELEMENTS_EXPERIMENTAL_WINDOWS_HASKELL=ON` path targets native
x86-64 MinGW/UCRT builds; it does not remove production identity or activation
gates. The release is command-line only (`BUILD_GUI=OFF`).

The Windows qualification toolchain uses GHC 9.6.7, cabal-install 3.16.1.0,
the UCRT64 GCC toolchain, and the Boost **1.81.0** headers/checksum pinned in
`depends/packages/boost.mk`. Select `Boost_INCLUDE_DIR` explicitly and use
`Boost_NO_SYSTEM_PATHS=ON`; a newer package-manager Boost is not a substitute.
Build both real Rust verifier archives from their authenticated source packets
with the pinned native Windows Rust toolchain. Supply their native import/system
libraries from `cargo rustc -- --print native-static-libs`, and retain the
USDD semantic-identity check. Never substitute empty or verifier-disabled archives.

Required CMake selections, in addition to the ordinary native Ninja release build:

- `ELEMENTS_EXPERIMENTAL_WINDOWS_HASKELL=ON`
- `ELEMENTS_GHC`, `ELEMENTS_GHC_PKG`, and `ELEMENTS_CABAL`: absolute tool paths
- `CMAKE_PREFIX_PATH`: the native UCRT dependency prefix
- `ELEMENTS_WINDOWS_RUNTIME_DIRS`: explicit, reviewed DLL search directories
- `USDD_SP1_VERIFIER_ARCHIVE` and `USDD_SP1_VERIFIER_NATIVE_LIBS`
- `ECX_SP1_VERIFIER_ARCHIVE` and `ECX_SP1_VERIFIER_SYSTEM_LIBS`

The Windows GHC distribution supplies static Haskell packages. These are embedded
in one `libelements_haskell.dll`, with exports derived from the existing foreign
declarations. Its runtime is initialized once, ignores `GHCRTS`, leaves signal
ownership with the caller, and stays pinned while runtime threads can reference
it. Do not copy a second runtime into each C++ consumer.
Use Windows PE relocations for this DLL, without the Unix `-fPIC` flag. The
native callback tests catch incorrect relative jump-table entries from that
combination in GHC 9.6.7. The Windows gRPC adapter also owns the shared event
engine while requests are active and drains it after the last request, before
Windows loader teardown; concurrent and repeated-request tests cover that path.

Use `contrib/devtools/bundle_windows_runtime.cmake` to collect actual PE imports
into a **new** directory. It requires `ROOT_BINARIES`, `SEARCH_DIRECTORIES`,
`OUTPUT_DIRECTORY`, and an absolute `OBJDUMP`; it rejects unresolved/conflicting
dependencies, non-PE inputs, and output-directory reuse. Include the Haskell DLL
among the root inputs. Test the resulting bundle after removing development
directories from `PATH`, including from a directory containing spaces.
`test_bundle_windows_runtime.py` covers the bundler's positive and negative cases.
Distribute dependency notices and exact source/build provenance with the bundle.

Qualification includes the native verifier tests and verification of existing
proof fixtures (not proof generation), Haskell property/ABI/loader tests, node
unit tests, and isolated mTLS/lifecycle tests. The property-test C++ reference
uses GHC's bundled Clang/libc++; its `mingw/bin` must be available to that test
process for `libc++.dll` and `libunwind.dll`. This is a test-tool requirement,
not a runtime dependency to impose on node users.

On Windows, run the node in the foreground; Unix `-daemon`/`-daemonwait` behavior
is not supported. `grpc_transport.py --direct-only` tests native direct mTLS and,
with the functional test node, startup/restart/shutdown. It explicitly does not
qualify HAProxy: retain a separate full proxy-client test where HAProxy is run.
Test-only node binaries and private proof/TLS fixtures must never enter a release.

For credential and parent-RPC limitations, see
[Drivechain RPC security](drivechain-rpc-security.md). Successful platform tests
do not authorize a new network, consensus identity, proof, or transaction.

## Historical upstream instructions

Below are some notes on how to build Bitcoin Core for Windows.

The options known to work for building Bitcoin Core on Windows are:

* On Linux, using the [Mingw-w64](https://www.mingw-w64.org/) cross compiler tool chain.
* On Windows, using [Windows Subsystem for Linux (WSL)](https://learn.microsoft.com/en-us/windows/wsl/about) and Mingw-w64.
* On Windows, using [Microsoft Visual Studio](https://visualstudio.microsoft.com). See [`build-windows-msvc.md`](./build-windows-msvc.md).

Other options which may work, but which have not been extensively tested are (please contribute instructions):

* On Windows, using a POSIX compatibility layer application such as [cygwin](https://www.cygwin.com/) or [msys2](https://www.msys2.org/).

The instructions below work on Ubuntu and Debian. Make sure the distribution's `g++-mingw-w64-x86-64-posix`
package meets the minimum required `g++` version specified in [dependencies.md](dependencies.md).

Installing Windows Subsystem for Linux
---------------------------------------

Follow the upstream installation instructions, available [here](https://learn.microsoft.com/en-us/windows/wsl/install).

Cross-compilation for Ubuntu and Windows Subsystem for Linux
------------------------------------------------------------

The steps below can be performed on Ubuntu or WSL. The depends system
will also work on other Linux distributions, however the commands for
installing the toolchain will be different.

See [README.md](../depends/README.md) in the depends directory for which
dependencies to install and [dependencies.md](dependencies.md) for a complete overview.

If you want to build the Windows installer using the `deploy` build target, you will need [NSIS](https://nsis.sourceforge.io/Main_Page):

    apt install nsis


Acquire the source in the usual way:

    git clone https://github.com/bitcoin/bitcoin.git
    cd bitcoin

Note that for WSL the Bitcoin Core source path MUST be somewhere in the default mount file system, for
example /usr/src/bitcoin, AND not under /mnt/d/. If this is not the case the dependency autoconf scripts will fail.
This means you cannot use a directory that is located directly on the host Windows file system to perform the build.

Build using:

    gmake -C depends HOST=x86_64-w64-mingw32  # Use "-j N" for N parallel jobs.
    cmake -B build --toolchain depends/x86_64-w64-mingw32/toolchain.cmake
    cmake --build build     # Use "-j N" for N parallel jobs.

## Depends system

For further documentation on the depends system see [README.md](../depends/README.md) in the depends directory.

Installation
-------------

After building using the Windows subsystem it can be useful to copy the compiled
executables to a directory on the Windows drive in the same directory structure
as they appear in the release `.zip` archive. This can be done in the following
way. This will install to `c:\workspace\bitcoin`, for example:
```shell
cmake --install build --prefix /mnt/c/workspace/bitcoin
```

Note that due to the presence of debug information, the binaries may be very large,
if you do not need the debug information, you can prune it during install by calling:
```shell
cmake --install build --prefix /mnt/c/workspace/bitcoin --strip
```

You can also create an installer using:
```shell
cmake --build build --target deploy
```
