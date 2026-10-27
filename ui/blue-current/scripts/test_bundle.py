#!/usr/bin/env python3
import tempfile
import unittest
from pathlib import Path
from bundle_policy import validate_inputs


class BundlePolicyTest(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.wallet, self.node = self.root / 'wallet', self.root / 'node'
        for name in ['wallet/bin/elements-blue-current', 'node/bin/elementsd',
                     'node/bin/elements-cli', 'wallet/Resources/assets/elements-logo.png']:
            self.put(name)

    def put(self, name):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'fixture')

    def test_single_wallet(self):
        validate_inputs(self.wallet, self.node, 'linux')

    def test_qt_refused(self):
        self.put('node/bin/elements-qt')
        with self.assertRaisesRegex(ValueError, 'Legacy frontend'):
            validate_inputs(self.wallet, self.node, 'linux')

    def test_other_frontend_refused(self):
        self.put('wallet/bin/other-wallet')
        with self.assertRaisesRegex(ValueError, 'Unexpected executable'):
            validate_inputs(self.wallet, self.node, 'linux')

    def test_missing_cli_refused(self):
        (self.node / 'bin/elements-cli').unlink()
        with self.assertRaisesRegex(ValueError, 'Missing bundled'):
            validate_inputs(self.wallet, self.node, 'linux')

    def test_external_link_refused(self):
        (self.wallet / 'outside').symlink_to(self.node, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'escapes'):
            validate_inputs(self.wallet, self.node, 'linux')

    def test_internal_library_link(self):
        self.put('wallet/lib/libSDL.so.1')
        (self.wallet / 'lib/libSDL.so').symlink_to('libSDL.so.1')
        validate_inputs(self.wallet, self.node, 'linux')


if __name__ == '__main__':
    unittest.main()
