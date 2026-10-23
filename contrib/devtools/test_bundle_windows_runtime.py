#!/usr/bin/env python3
"""Native PE bundling regressions; creates only isolated compiler fixtures."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cmake", required=True)
    parser.add_argument("--cc", required=True)
    parser.add_argument("--objdump", required=True)
    parser.add_argument("--temporary-root", type=Path, required=True)
    args = parser.parse_args()
    if os.name != "nt":
        raise SystemExit("These tests require native Windows")
    script = Path(__file__).with_name("bundle_windows_runtime.cmake").resolve()
    temporary_root = args.temporary_root.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="pe-bundle-test-", dir=temporary_root) as temporary:
        root = Path(temporary).resolve(strict=True)
        assert root.parent == temporary_root
        first, second, missing = (root / name for name in ("first", "second", "missing"))
        for directory, value in ((first, 42), (second, 43)):
            directory.mkdir()
            (directory / "dep.c").write_text(f"__declspec(dllexport) int value(void) {{ return {value}; }}\n")
            (directory / "main.c").write_text(
                "__declspec(dllimport) int value(void); int main(void) { return value() == 42 ? 0 : 1; }\n")
            subprocess.run([args.cc, "-shared", "dep.c", "-o", "dep.dll", "-Wl,--out-implib,dep.a"],
                           cwd=directory, check=True, capture_output=True)
            subprocess.run([args.cc, "main.c", "dep.a", "-o", "app.exe"],
                           cwd=directory, check=True, capture_output=True)
        missing.mkdir()
        shutil.copyfile(first / "app.exe", missing / "app.exe")

        def bundle(inputs, search, output, succeeds):
            result = subprocess.run([args.cmake,
                "-DROOT_BINARIES=" + ";".join(path.as_posix() for path in inputs),
                "-DSEARCH_DIRECTORIES=" + search.as_posix(),
                "-DOUTPUT_DIRECTORY=" + output.as_posix(),
                "-DOBJDUMP=" + Path(args.objdump).as_posix(), "-P", str(script)],
                capture_output=True, text=True, timeout=30)
            assert (result.returncode == 0) == succeeds, (result.returncode, result.stdout, result.stderr)
            return result

        good = root / "good"
        bundle([first / "app.exe"], first, good, True)
        assert {path.name for path in good.iterdir()} == {"app.exe", "dep.dll", "SHA256SUMS"}
        environment = dict(os.environ, PATH=str(Path(os.environ["SystemRoot"]) / "System32"))
        subprocess.run([str(good / "app.exe")], cwd=missing, env=environment, check=True, timeout=10)
        print("PASS exact DLL closure and relocation without build PATH")
        before = (good / "SHA256SUMS").read_bytes()
        bundle([first / "app.exe"], first, good, False)
        assert (good / "SHA256SUMS").read_bytes() == before
        print("PASS existing bundle cannot be overwritten")
        absent = root / "absent"
        result = bundle([missing / "app.exe"], missing, absent, False)
        assert "dep.dll" in result.stderr and not absent.exists(), result.stderr
        print("PASS unresolved dependency fails before writing output")
        conflicting = root / "conflicting"
        result = bundle([first / "app.exe", second / "app.exe"], first, conflicting, False)
        assert "dep.dll" in result.stderr and not conflicting.exists(), result.stderr
        print("PASS conflicting dependency fails before writing output")
        invalid = root / "invalid"
        bundle([first / "main.c"], first, invalid, False)
        assert not invalid.exists()
        print("PASS non-PE input rejected")


if __name__ == "__main__":
    main()
