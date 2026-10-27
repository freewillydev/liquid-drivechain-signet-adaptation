# Elements · Blue Current

A Haskell/Monomer wallet based on the selected Blue Current design. Home fills the window; Receive opens a blue panel, Send and review open amber panels, and wallet tools stay charcoal. Small windows show one action at a time with a fixed Back toolbar.

## Run

On macOS, open **Elements Blue Current.app** on Apple Silicon with macOS 26 or later. The Windows preview includes `Start Blue Current.cmd` and `bin/elements-blue-current.exe`; the Linux preview includes an `Elements Blue Current` launcher (Ubuntu 24.04 x86_64 qualified). Standalone developer previews without a managed node profile first use an interactive demo; demo payments move no funds. The combined node bundle instead requires its managed connection profile. After saving a standalone connection, subsequent launches reconnect to that node and remember the selected wallet. Use Wallets → Connection settings to change the node or return to demo.

When macOS asks, allow the app access to the drive holding your node. Rebuilt ad hoc previews may ask again.

The local macOS bundle includes fonts, SDL2 and GLEW; its deployment target follows the minimum version required by those compiled libraries. It has a local ad hoc signature and does not require Homebrew at runtime. It has not been notarized for public distribution or tested on another Mac. The combined release also contains the Elements node and matching `elements-cli`; standalone developer previews require those separately.

The macOS/Linux source builds use GHC 9.6.7; Windows was verified with GHC 9.10.3. All use Cabal, SDL2 and GLEW. Linux additionally needs ATK 2.50+ and the AT-SPI bridge development libraries (`libatk1.0-dev libatk-bridge2.0-dev` on Ubuntu). Monomer is pinned to commit `5c6239365e3a37686b6547bc91c29270ae5487c6` with NanoVG's `stb_truetype` backend.

```sh
./run-preview.command --demo
./run-preview.command --demo --window=320x400 --pane=send
./run-preview.command --live --elements-cli /path/elements-cli --chain elementsregtest --datadir /explicit/node/folder --rpcport 12345 --wallet my-wallet
```

`BLUE_CURRENT_GHC` selects a compiler; `BLUE_CURRENT_BUILD_ROOT` moves build caches to a spacious drive. `BLUE_CURRENT_PROFILE_DIR` isolates settings for tests. There is no dependency on the older UI's POSIX-specific core, and the subpackage is self-contained.

## Wallet behavior

- Connection settings include the CLI path, chain, node data folder and RPC port. The app uses existing node authentication and saves no RPC password. Settings and the selected live or demo wallet survive restart.
- Balances and activity refresh every 15 seconds on Home, Receive and submitted-payment screens. Refresh runs in the background without locking navigation. Editing and review are not interrupted by automatic polling. Loading, disconnected, malformed-response, pending and conflicted states have explicit feedback.
- Receive generates a real confidential address and a QR encoding that exact string. Copy copies the full address. Demo QR codes explicitly encode a non-payment value.
- Send validates decimal amounts with integer satoshis and checks the recipient against the selected node. The node funds and signs a PSBT before review. Review shows the complete recipient, wallet, exact network fee and total. Confirmation broadcasts those exact signed bytes. A repeated submission has the same transaction ID and cannot create another payment. If acceptance remains uncertain, the same review is retained and the transaction ID is shown for reconciliation.
- Only the node's `bitcoin` asset is presented as L-ECX. Coin selection uses the actual asset ID from `dumpassetlabels`; other assets are not summed into the wallet balance or activity.
- Wallet tools create descriptor wallets, load existing wallets, back up the current wallet and recover a backup into a new wallet. Backup paths refer to the node's computer. Backups contain private wallet information and need secure storage. No seed phrase, password reset, external signer or wallet-encryption interface is provided.
- Errors appear once in the active screen as a red card with a heading, warning icon, readable dark text and a dismiss button. Common exception wrappers are removed.
- Home and panels scroll independently. The header rearranges at narrow widths, balances fit their actual digit count, compact activity rows stack, and short windows use tighter vertical spacing so primary actions stay visible. The entire Send and Receive tile responds to clicks, including empty corners. Changing panels resets the panel scroll position. The macOS window enforces a minimum content size of 320×400.
- Tab and Shift-Tab navigate controls; focusing an offscreen field scrolls it into view. Escape returns home. Native accessibility exposes buttons, editable fields, selected wallet, balances, full addresses, payment details, activity and status on all three platforms: NSAccessibility on macOS, UI Automation on Windows, and ATK/AT-SPI on Linux. Names, values, enabled states, focus and changing screens are exposed; native notifications report changes and errors. Assistive actions use the normal application handlers and confirmation guards. Requests for controls hidden or disabled after navigation are rejected. Windows was exercised with NVDA 2026.2 and Linux with Orca 46.1; both generated wallet-field speech in isolated test profiles. These checks validate speech generation and accessible operation, not a formal accessibility audit or physical braille hardware. Mac VoiceOver has not had a formal audit.

## Tests and packaging

```sh
cabal test wallet-behavior --test-show-details=direct
python3 scripts/test-regtest.py --elements-bin /path/to/element/bin --work-parent /path/to/test/scratch -- cabal test live-wallet --test-show-details=direct
python3 scripts/package-macos.py /path/to/built/elements-blue-current
python3 scripts/package-portable.py /path/to/binary --platform linux --output /new/bundle/folder
python3 scripts/package-portable.py C:/path/elements-blue-current.exe --platform windows --library-dir C:/SDL/bin --library-dir C:/msys64/mingw64/bin --output C:/new/bundle
```

The regtest harness creates a fresh isolated node with test funds, picks an unused RPC port, runs the wallet suite, and stops only its own node. The integration suite checks address generation, exact reviewed versus actual fee, signed submission, idempotent retry, pending and confirmed activity, mining, recipient credit, backup and recovery. Tests passed against official Elements 23.3.4 on macOS ARM64, Linux x86_64 and native Windows x86_64. Production funds were not used.

The imported node integration was additionally checked on macOS against this
fork's functional-test node: payment/backup/recovery, packaged node lifecycle,
and bundle policy tests pass. Earlier Windows/Linux results predate the latest
resize, branding and submission-reconciliation changes; their final release
bundles still require qualification. These checks do not qualify live consensus
or a production-chain release.

The behavior suite checks decimal precision, invalid fees, insufficient funds, malformed data, CLI string/null handling, asset isolation, review guards, QR dimensions/quiet zone, demo isolation and persisted settings. Native UI checks include wide windows and 320×400, 360×640, 400×720 and 800×600 layouts, accessibility actions/value entry, fixed navigation and focus scrolling.

`ci/platforms.yml` provides a proposed macOS/Linux/Windows build matrix. Install it at the repository root as `.github/workflows/blue-current.yml` to run it. It has not been dispatched. Native Windows builds and behavior tests passed with GHC 9.10.3 using the verified official SDL 2.32.10 MinGW SDK and AMD Radeon RX 5600 XT. Windows renders on SDL's main thread; resizing repaints when the drag finishes. GDI captures of the hardware surface were black, so visual checks used the app's actual OpenGL front buffer in the logged-in Windows desktop. Home, Receive and Send were inspected at 320×400, 400×720, 800×600, 1280×820 and 1920×1080, together with review, submitted, backup and red-error screens. Native pointer messages at both empty corners of each main tile opened the correct panel; Mac pointer checks also passed.

Windows UI Automation clients exercised roles, full values, Unicode editing, focus, exact totals, demo submission, disabled controls and focus/structure/value notifications. An isolated portable NVDA 2026.2 installation generated the corresponding field names, roles and values. Linux builds and behavior tests passed with GHC 9.6.7 on Ubuntu 24.04 under WSL. A separate AT-SPI client exercised the same flow over a private accessibility bus, including stale-control rejection, disabled-field protection and native notifications. Orca 46.1 generated wallet field speech on that private desktop. Speech generation was recorded without desktop audio output; no personal screen-reader profile was changed.

Linux visual layouts were inspected at the same five sizes using a private X11 display. The software renderer fell back to rendering on the main thread. Linux needs the desktop's standard AT-SPI bus/registry service for screen-reader discovery (normally supplied with Orca/GNOME). Windows requires the system UI Automation service. The default macOS GHC 9.14.1 toolchain is unqualified.

Blue Current is the only frontend in this product bundle. Older OpenGL/Bloomberg
frontends are not included. Inherited upstream Qt sources remain for maintenance,
but cannot be built together with the bundled wallet and are never packaged with it.

From the node repository, configure with `-DBUILD_BLUE_CURRENT=ON -DBUILD_GUI=OFF`
and build normally. `BLUE_CURRENT_CABAL`, `ELEMENTS_GHC`,
`BLUE_CURRENT_BUILD_DIR`, and `BLUE_CURRENT_STORE_DIR` select the tools/caches.
Headless node builds retain the default `BUILD_BLUE_CURRENT=OFF`.
Installation places the wallet next to the node/CLI and its assets under
`share/elements-blue-current`. Portable releases use the packaging scripts below.

Font licensing is in `assets/FONT-LICENSE.txt`. The macOS packaging script copies the installed graphics-library licenses into the bundle.

The shared Elements mark is `assets/elements-logo.png`, the unchanged transparent
artwork supplied for this wallet. It appears beside ELEMENTS in every header and
as the native window icon. Platform packages use the same mark for the macOS app
and Dock icon, Windows executable and shortcut, and Linux application-menu icon.
To regenerate ICO/ICNS containers after replacing the master, run
`python3 scripts/build-branding.py` with Pillow installed. Windows packaging uses
PowerShell on native Windows or through WSL to embed icon resources before any
release signing. On Linux, run the bundle's `python3 install-desktop.py` after
placing it in its final folder to add its application-menu entry.

Windows QA can opt in to framebuffer capture by setting `BLUE_CURRENT_CAPTURE_REQUEST` to a request-file path. Write the desired BMP output path into that file; the application consumes the request on its own window thread and captures only its own OpenGL surface. This diagnostic is inactive unless the environment variable is set.

## Managed node and Bitwindow integration

A managed installation accepts `--node-profile PATH`, or discovers the bundled
`node-profile.json`. Profiles pin child genesis, native asset, Bitcoin parent
identity and fork height. Every wallet operation verifies the selected network.
`--check-node-profile PATH` performs a headless connection/lifecycle check.

Bitwindow installs a single wallet/node/CLI bundle and creates a private attached
profile (`startNode: false`). It owns the daemon; the wallet leaves attached nodes
running. Standalone managed profiles may opt into daemon startup, in which case
the wallet stops only its owned child on exit.

The BTC to ECX production sidechain at Bitcoin block 973,728 is not finalized.
`release/production-identity.pending.json` therefore refuses activation; do not
substitute historical Alpha/Betanet hashes. `scripts/bundle-node-macos.py` and
`scripts/combine-release.py` assemble portable, pinned release inputs without
changing consensus. Production readiness also requires qualified node releases
and a parent catalog selecting the correct fork.

The Elements wallet has its own backup. It is independent of Bitwindow's starter
seed; use Backup & recovery before relying on that wallet for funds.
