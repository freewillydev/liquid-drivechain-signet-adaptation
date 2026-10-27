#!/usr/bin/env python3
"""Build the sole wallet frontend; keep Cabal caches in the selected build tree."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cabal', default='cabal')
    parser.add_argument('--ghc', default='ghc')
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--store-dir', default='')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    command = [args.cabal]
    if args.store_dir:
        command.append('--store-dir=' + args.store_dir)
    options = ['--project-file=' + str(root / 'cabal.project'),
               '--builddir=' + str(args.build_dir.resolve()),
               '--with-compiler=' + args.ghc]
    subprocess.run([*command, 'build', 'exe:elements-blue-current', *options, '-j1'], check=True)
    binary = subprocess.check_output(
        [*command, 'list-bin', 'exe:elements-blue-current', *options], text=True).strip()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    staging = args.output.with_suffix('.next')
    shutil.copy2(binary, staging)
    os.replace(staging, args.output)


if __name__ == '__main__':
    main()
