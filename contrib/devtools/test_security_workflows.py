#!/usr/bin/env python3
"""Keep mutable action and test-data refs out of security CI."""

from pathlib import Path
import os
import re
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class WorkflowTests(unittest.TestCase):
    def test_security_helper_scripts_exist(self):
        text = (ROOT / ".github/workflows/drivechain-security.yml").read_text()
        commands = [shlex.split(line) for line in text.splitlines()
                    if line.lstrip().startswith(("python3 ", "/usr/bin/python3 "))]
        self.assertTrue(commands, "security workflow has no helper checks")
        for command in commands:
            with self.subTest(script=command[1]):
                script = ROOT / command[1]
                self.assertEqual(script.suffix, ".py")
                self.assertTrue(script.is_file(), "CI references a missing helper")

    def test_actions_are_sha_pinned(self):
        for path in (ROOT / ".github/workflows").glob("*.yml"):
            text = path.read_text()
            for action in re.findall(r"uses:\s*([^\s#]+)", text):
                with self.subTest(path=path, action=action):
                    self.assertRegex(action, r"^[\w/-]+@[0-9a-f]{40}$")
            self.assertRegex(text, r"(?m)^permissions:\n  contents: read$")

    def test_test_assets_are_pinned(self):
        revision = (ROOT / "ci/qa-assets-revision").read_text().strip()
        self.assertRegex(revision, r"^[0-9a-f]{40}$")
        for name in ("ci/test/03_test_script.sh", ".github/workflows/ci.yml"):
            text = (ROOT / name).read_text()
            self.assertIn("ci/qa-assets-revision", text)
            self.assertNotIn("qa-assets/raw/master", text)
            self.assertNotIn("git clone --depth=1 https://github.com/ElementsProject/qa-assets", text)
        script = (ROOT / "ci/test/03_test_script.sh").read_text()
        unit_download = script.split('elif [ "$RUN_UNIT_TESTS"', 1)[1].split('\nfi', 1)[0]
        self.assertIn("qa-assets/${QA_ASSETS_REVISION}/unit_test_data/", unit_download)
        self.assertNotIn("git ", unit_download)

    def test_test_assets_do_not_trust_cached_git_or_output_paths(self):
        script = (ROOT / "ci/test/03_test_script.sh").read_text()
        setup = script[script.index("QA_ASSETS_REVISION="):script.index('\nif [ "$USE_BUSY_BOX"')]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            upstream, cached, source = (root / name for name in ("upstream", "cached", "source"))
            (source / "ci").mkdir(parents=True)

            def git(*args):
                return subprocess.check_output(["git", *map(str, args)], text=True,
                                               stderr=subprocess.DEVNULL).strip()

            git("init", upstream)
            (upstream / "test-corpus").write_text("pinned corpus")
            git("-C", upstream, "add", "test-corpus")
            git("-C", upstream, "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                "-c", "commit.gpgsign=false", "commit", "-m", "Fixture")
            revision = git("-C", upstream, "rev-parse", "HEAD")
            (source / "ci/qa-assets-revision").write_text(revision + "\n")
            git("clone", upstream, cached)
            marker, sentinel = root / "hook-ran", root / "sentinel"
            hook = cached / ".git/hooks/post-checkout"
            hook.write_text('#!/bin/sh\nprintf ran > "$HOOK_MARKER"\n')
            hook.chmod(0o700)
            sentinel.write_text("unchanged")
            (cached / "unit_test_data").mkdir()
            (cached / "unit_test_data/script_assets_test.json").symlink_to(sentinel)
            (cached / ".git/info/exclude").write_text("unit_test_data/\n")
            env = dict(os.environ, BASE_ROOT_DIR=str(source), BASE_SCRATCH_DIR=str(root),
                       DIR_QA_ASSETS=str(cached), CI_RETRY_EXE="", HOOK_MARKER=str(marker),
                       GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0=f"url.{upstream.as_uri()}.insteadOf",
                       GIT_CONFIG_VALUE_0="https://github.com/ElementsProject/qa-assets",
                       RUN_UNIT_TESTS_SEQUENTIAL="false")
            # Replace only the network download; retain its normal file-write
            # behavior, including following an unsafe cached symlink.
            download = '''curl() {
  while [ "$#" -gt 0 ]; do
    if [ "$1" = -o ]; then printf 'pinned unit data' > "$2"; return; fi
    shift
  done
  return 1
}
'''
            for fuzz in (True, False):
                with self.subTest(fuzz=fuzz):
                    marker.unlink(missing_ok=True)
                    env.update(RUN_FUZZ_TESTS=str(fuzz).lower(), RUN_UNIT_TESTS=str(not fuzz).lower())
                    result = subprocess.run(["bash", "-c", "set -e\n" + download + setup +
                                             '\nprintf "%s\\n" "$DIR_QA_ASSETS"'],
                                            env=env, capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertFalse(marker.exists(), "cached Git hook executed")
                    self.assertEqual(sentinel.read_text(), "unchanged")
                    actual = Path(result.stdout.splitlines()[-1])
                    self.assertNotEqual(actual, cached)
                    if fuzz:
                        self.assertEqual((actual / "test-corpus").read_text(), "pinned corpus")
                    else:
                        self.assertEqual((actual / "unit_test_data/script_assets_test.json").read_text(),
                                         "pinned unit data")


if __name__ == "__main__":
    unittest.main()
