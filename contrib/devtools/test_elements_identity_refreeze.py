#!/usr/bin/env python3
"""Independent serialization and isolation checks for the fresh child chain."""

import re
import tempfile
import unittest
from pathlib import Path

from elements_identity_refreeze import (
    Header, IDENTITY_HEADER, assert_current, betanet_bootstrap_commitment,
    calculate_fresh, hash256, indexer_bindings,
)


def replace_field(header, name, value):
    pattern = rf"(inline constexpr [^;{{}}]+\s+{re.escape(name)}(?:\[\])?\s*\{{)[^{{}};]*(\}};)"
    encoded = f'"{value}"' if isinstance(value, str) else str(value).lower()
    header.text, count = re.subn(pattern, lambda m: m[1] + encoded + m[2], header.text, count=1)
    if count != 1:
        raise AssertionError(f"fixture field not found: {name}")


class GeneratedResourceHeaderTests(unittest.TestCase):
    def test_bootstrap_requires_explicit_directory(self):
        with self.assertRaisesRegex(ValueError, "explicit generated include directory"):
            Header(IDENTITY_HEADER.with_name("elements_drivechain_bootstrap.h"))

    def test_missing_generated_bootstrap_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                Header(IDENTITY_HEADER.with_name("elements_drivechain_bootstrap.h"), Path(directory))

    def test_resources_and_missing_include(self):
        header = Header(IDENTITY_HEADER)
        self.assertEqual(header.integer("CONSENSUS_MAX_BLOCK_WEIGHT"), 4_000_000)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.h"
            path.write_text("#include <haskell/resource_constants.h>\n", encoding="utf-8")
            with self.assertRaises(FileNotFoundError):
                Header(path)


class FreshIdentityTests(unittest.TestCase):
    def setUp(self):
        self.header = Header(IDENTITY_HEADER)

    def test_frozen_identity_and_distinct_namespace(self):
        result = calculate_fresh(self.header)
        self.assertEqual(result, calculate_fresh(Header(IDENTITY_HEADER)))
        assert_current(self.header, result)
        self.assertEqual(result.genesis_hash, "fe05f7c76cfb50ef4f5594c761df25581e95a9946a64bc9d8f567235ffa485c9")
        self.assertEqual(result.proposal_hash, "a9980eaa8bb6893d4baea100f484000b4f72e4640fc0d9f3ebf8a2f29ae63460")
        self.assertEqual(result.pegged_asset, "2e69819685c22252a706f69ce67ab9ab36a633b91e61f6ee69216d6e1c7e90d3")
        self.assertEqual(result.data_dir, "elements-native-v1")
        self.assertEqual(result.p2p_message_start, "97b20d51")
        self.assertEqual(result.p2p_message_start, hash256(result.p2p_magic_domain.encode())[:4].hex())
        self.assertTrue(result.parent_activation_required)
        self.assertFalse(result.future_parent_milestones_committed)
        self.assertIn(b"native BIP300/301", bytes.fromhex(result.proposal_description_hex))

    def test_live_profile_and_old_namespaces_rejected(self):
        for name, value in (
            ("BETANET_EXISTING_ELEMENTS_TEST_PROFILE", True),
            ("DATA_DIR", "elements-betanet-slot24-v1"),
            ("P2P_MAGIC_DOMAIN", "ecash-elements-drivechain-betanet-slot24-p2p-v1"),
        ):
            with self.subTest(name=name):
                header = Header(IDENTITY_HEADER)
                replace_field(header, name, value)
                with self.assertRaises(ValueError):
                    calculate_fresh(header)

    def test_noncanonical_parent_state_rejected(self):
        for name, value in (
            ("HISTORICAL_PROPOSAL_DESCRIPTION_HEX", "00"),
            ("HISTORICAL_PROPOSAL_HASH", "11" * 32),
            ("HISTORICAL_ACTIVATION_HEIGHT", 1),
            ("PARENT_CHECKPOINT_HEIGHT", 967680),
            ("PARENT_CHECKPOINT_CHAINWORK", "00" * 32),
            ("PARENT_CHECKPOINT_CTIP_TXID", "11" * 32),
            ("PARENT_CHECKPOINT_CTIP_VOUT", 0),
            ("PARENT_CHECKPOINT_CTIP_VALUE", 1),
            ("PARENT_CHECKPOINT_BOOTSTRAP_STATE_COMMITMENT", "00" * 32),
        ):
            with self.subTest(name=name):
                header = Header(IDENTITY_HEADER)
                replace_field(header, name, value)
                with self.assertRaises(ValueError):
                    calculate_fresh(header)

    def test_unfrozen_rules_cannot_export_bindings(self):
        for name, value in (
            ("MAINCHAIN_RPC_PORT", 18302), ("PEGIN_MIN_DEPTH", 1),
            ("SIDECHAIN_SLOT", 130), ("PARENT_REPLAY_VERSION", 4),
            ("BIP300301_ENFORCER_REVISION", "00" * 20),
            ("PUBKEY_ADDRESS_PREFIX", 1), ("BECH32_HRP", "wrong"),
            ("GENESIS_HASH", "00" * 32), ("PEGGED_ASSET", "00" * 32),
            ("IDENTITY_COMMITMENT", "00" * 32),
        ):
            with self.subTest(name=name):
                header = Header(IDENTITY_HEADER)
                replace_field(header, name, value)
                with self.assertRaises(ValueError):
                    indexer_bindings(header)

    def test_checkpoint_changes_rebind_every_child_identity(self):
        original = calculate_fresh(self.header)
        replace_field(self.header, "PARENT_CHECKPOINT_HASH", "44" * 32)
        with self.assertRaisesRegex(ValueError, "bootstrap commitment mismatch"):
            calculate_fresh(self.header)
        replace_field(self.header, "PARENT_CHECKPOINT_BOOTSTRAP_STATE_COMMITMENT",
                      betanet_bootstrap_commitment(self.header))
        changed = calculate_fresh(self.header)
        for field in ("genesis_hash", "pegged_asset", "proposal_hash", "identity_commitment"):
            self.assertNotEqual(getattr(original, field), getattr(changed, field))
        with self.assertRaises(ValueError):
            assert_current(self.header, changed)

    def test_indexer_bindings(self):
        bindings = indexer_bindings(self.header)
        self.assertEqual(bindings["network"], "native-fresh")
        self.assertEqual(bindings["sidechain_slot"], 24)
        self.assertEqual(bindings["rpc_port"], 7071)
        self.assertEqual(bindings["p2p_port"], 7072)
        self.assertEqual(bindings["p2p_magic_u32_le"].to_bytes(4, "little").hex(), "97b20d51")
        self.assertEqual(bindings["native_asset"], self.header.string("PEGGED_ASSET"))
        self.assertEqual(bindings["bech32_hrp"], self.header.string("BECH32_HRP"))
        self.assertEqual(bindings["blech32_hrp"], self.header.string("BLECH32_HRP"))


if __name__ == "__main__":
    unittest.main()
