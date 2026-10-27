#!/bin/sh
set -eu
PROJECT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$PROJECT_DIR"
SELECTED_GHC="${BLUE_CURRENT_GHC:-}"
if [ -z "$SELECTED_GHC" ]; then
  if [ -x "$HOME/.ghcup/ghc/9.6.7/bin/ghc" ]; then
    SELECTED_GHC="$HOME/.ghcup/ghc/9.6.7/bin/ghc"
  elif command -v ghc-9.6.7 >/dev/null 2>&1; then
    SELECTED_GHC="$(command -v ghc-9.6.7)"
  else
    echo 'Install GHC 9.6.7 or set BLUE_CURRENT_GHC to its executable.' >&2
    exit 1
  fi
fi
BUILD_ROOT="${BLUE_CURRENT_BUILD_ROOT:-$PROJECT_DIR/build/cache}"
mkdir -p "$BUILD_ROOT/tmp"
export TMPDIR="$BUILD_ROOT/tmp"
exec cabal --store-dir="$BUILD_ROOT/store" run exe:elements-blue-current \
  --with-compiler="$SELECTED_GHC" --builddir="$BUILD_ROOT/app-dist" -- "$@"
