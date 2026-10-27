#!/usr/bin/env python3
"""Independently derive the fresh native-only child identity. Never activates a node."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import struct
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
IDENTITY_HEADER = ROOT / "src" / "elements_drivechain_identity.h"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash256(data: bytes) -> bytes:
    return sha256(sha256(data))


def display_hash(raw_internal: bytes) -> str:
    if len(raw_internal) != 32:
        raise ValueError("uint256 must contain 32 bytes")
    return raw_internal[::-1].hex()


def uint256_from_display(value: str) -> bytes:
    raw = bytes.fromhex(value)
    if len(raw) != 32:
        raise ValueError(f"uint256 display value has {len(raw)} bytes")
    return raw[::-1]


def compact_size(value: int) -> bytes:
    if value < 0:
        raise ValueError("CompactSize cannot encode a negative integer")
    if value < 253:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", value)
    if value <= 0xFFFFFFFFFFFFFFFF:
        return b"\xff" + struct.pack("<Q", value)
    raise ValueError("CompactSize integer exceeds uint64")


class HashWriter:
    """Minimal SER_GETHASH, version-zero writer used by chainparams.cpp."""

    def __init__(self) -> None:
        self.data = bytearray()

    def raw(self, value: bytes) -> "HashWriter":
        self.data.extend(value)
        return self

    def vector(self, value: bytes) -> "HashWriter":
        self.data.extend(compact_size(len(value)))
        self.data.extend(value)
        return self

    def string(self, value: str) -> "HashWriter":
        return self.vector(value.encode("utf-8"))

    def boolean(self, value: bool) -> "HashWriter":
        return self.u8(1 if value else 0)

    def u8(self, value: int) -> "HashWriter":
        self.data.extend(struct.pack("<B", value))
        return self

    def u16(self, value: int) -> "HashWriter":
        self.data.extend(struct.pack("<H", value))
        return self

    def u32(self, value: int) -> "HashWriter":
        self.data.extend(struct.pack("<I", value))
        return self

    def i32(self, value: int) -> "HashWriter":
        self.data.extend(struct.pack("<i", value))
        return self

    def u64(self, value: int) -> "HashWriter":
        self.data.extend(struct.pack("<Q", value))
        return self

    def i64(self, value: int) -> "HashWriter":
        self.data.extend(struct.pack("<q", value))
        return self

    def uint256(self, display: str) -> "HashWriter":
        self.data.extend(uint256_from_display(display))
        return self

    def digest(self) -> bytes:
        return hash256(bytes(self.data))


def _strip_integer_suffixes(expression: str) -> str:
    expression = expression.replace("'", "")
    return re.sub(r"(?<=\d)(?:ULL|LLU|UL|LU|LL|U|L)\b", "", expression)


def _safe_integer_expression(expression: str) -> int:
    expression = _strip_integer_suffixes(expression.strip())
    if expression == "std::numeric_limits<int64_t>::max()":
        return (1 << 63) - 1
    tree = ast.parse(expression, mode="eval")

    def evaluate(node: ast.AST) -> int:
        if isinstance(node, ast.Expression):
            return evaluate(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            return -evaluate(node.operand)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
            return evaluate(node.left) * evaluate(node.right)
        raise ValueError(f"unsupported integer expression: {expression}")

    return evaluate(tree)


class Header:
    def __init__(self, path: Path, generated_include_dir: Path | None = None) -> None:
        self.path = path
        self.generated_include_dir = generated_include_dir
        self.text = path.read_text(encoding="utf-8")
        # Only current identities include the Haskell-generated resource table.
        # Resolve beside the supplied header, never from a different checkout.
        if re.search(r"^#include <haskell/resource_constants.h>$", self.text, re.MULTILINE):
            self.text += "\n" + (path.parent / "haskell/resource_constants.h").read_text(encoding="utf-8")
        if re.search(r"^#include <haskell/bootstrap_constants.h>$", self.text, re.MULTILINE):
            if generated_include_dir is None:
                raise ValueError("bootstrap constants require an explicit generated include directory")
            self.text += "\n" + (generated_include_dir / "haskell/bootstrap_constants.h").read_text(encoding="utf-8")

    def string(self, name: str) -> str:
        match = re.search(
            rf"inline constexpr char\s+{re.escape(name)}\[\]\s*\{{(.*?)\}};",
            self.text,
            re.DOTALL,
        )
        if not match:
            raise ValueError(f"missing char constant {name}")
        literals = re.findall(r'"(?:[^"\\]|\\.)*"', match.group(1))
        if not literals:
            raise ValueError(f"char constant {name} has no string literal")
        return "".join(ast.literal_eval(item) for item in literals)

    def integer(self, name: str) -> int:
        match = re.search(
            rf"inline constexpr [^;{{}}]+\s+{re.escape(name)}\s*\{{([^{{}};]+)\}};",
            self.text,
        )
        if not match:
            raise ValueError(f"missing integer constant {name}")
        return _safe_integer_expression(match.group(1))

    def boolean(self, name: str) -> bool:
        match = re.search(
            rf"inline constexpr bool\s+{re.escape(name)}\s*\{{(true|false)\}};",
            self.text,
        )
        if not match:
            raise ValueError(f"missing boolean constant {name}")
        return match.group(1) == "true"

    def array(self, name: str) -> bytes:
        match = re.search(
            rf"inline constexpr std::array<[^>]+>\s+{re.escape(name)}\s*\{{\{{(.*?)\}}\}};",
            self.text,
            re.DOTALL,
        )
        if not match:
            raise ValueError(f"missing byte-array constant {name}")
        values: list[int] = []
        for token in match.group(1).split(","):
            token = token.strip()
            if not token:
                continue
            if token.startswith("'"):
                decoded = ast.literal_eval(token)
                if not isinstance(decoded, str) or len(decoded) != 1:
                    raise ValueError(f"invalid character in {name}: {token}")
                values.append(ord(decoded))
            else:
                values.append(_safe_integer_expression(token))
        return bytes(values)


@dataclass(frozen=True)
class IdentityResult:
    mode: str
    protocol_manifest_hash: str
    proposal_description_hex: str
    proposal_hash: str
    identity_commitment: str
    pegged_asset: str
    genesis_merkle_root: str
    genesis_hash: str
    p2p_magic_domain: str
    p2p_message_start: str
    data_dir: str
    parent_replay_version: int
    annex_feature_version: int
    parent_activation_required: bool
    future_parent_milestones_committed: bool
    m1_payload_hex: str
    m2_payload_hex: str
    used_slot_m2_votes_required: int
    used_slot_proposal_max_age: int


def add_common_protocol_fields(
    writer: HashWriter,
    header: Header,
    *,
    p2p_domain: str,
    annex_feature_version: int,
    include_network_namespaces: bool,
) -> None:
    if include_network_namespaces:
        message_start = hash256(p2p_domain.encode("ascii"))[:4]
        writer.string(header.string("NETWORK_ID"))
        writer.string(p2p_domain)
        writer.vector(message_start)
        writer.u16(header.integer("P2P_PORT"))
        writer.u16(header.integer("RPC_PORT"))
        writer.u16(header.integer("MAINCHAIN_RPC_PORT"))
        writer.u16(header.integer("ONION_TARGET_PORT"))
        writer.string(header.string("DATA_DIR"))
    else:
        writer.string(p2p_domain)

    writer.string(header.array("PARENT_COMMITMENT_TAG").decode("ascii"))
    writer.u8(header.integer("PUBKEY_ADDRESS_PREFIX"))
    writer.u8(header.integer("SCRIPT_ADDRESS_PREFIX"))
    writer.u8(header.integer("BLINDED_ADDRESS_PREFIX"))
    writer.u8(header.integer("SECRET_KEY_PREFIX"))
    writer.vector(header.array("EXT_PUBLIC_KEY_PREFIX"))
    writer.vector(header.array("EXT_SECRET_KEY_PREFIX"))
    writer.string(header.string("BECH32_HRP"))
    writer.string(header.string("BLECH32_HRP"))
    writer.boolean(True)  # elements_mode
    writer.boolean(True)  # has_parent_chain
    writer.boolean(True)  # connect_genesis_outputs
    writer.i64(0)  # genesis_subsidy / CAmount
    writer.string(header.string("GENESIS_STYLE"))
    writer.vector(bytes([header.integer("SIGNBLOCK_CHALLENGE_OPCODE")]))
    writer.u32(header.integer("MAX_BLOCK_SIGNATURE_SIZE"))
    writer.boolean(True)  # drivechain_m6_withdrawal_validation
    writer.u32(annex_feature_version)


def add_native_rules(writer: HashWriter, header: Header) -> None:
    writer.string("current_bmm_parent_mtp")
    writer.u16(header.integer("CURRENT_BMM_PARENT_MTP_JET_CATALOGUE_ITEM"))
    writer.vector(header.array("CURRENT_BMM_PARENT_MTP_JET_ENCODING"))
    writer.vector(header.array("CURRENT_BMM_PARENT_MTP_JET_CMR"))
    writer.u64(header.integer("CURRENT_BMM_PARENT_MTP_JET_COST_MWU"))
    writer.u32(header.integer("CONSENSUS_MAX_BLOCK_SERIALIZED_SIZE"))
    writer.u32(header.integer("CONSENSUS_MAX_BLOCK_WEIGHT"))
    writer.string(header.string("BIP300301_ENFORCER_REVISION"))
    writer.string(header.string("BIP300301_LOCAL_RULE_DOMAIN"))
    writer.string(header.string("BIP300301_LOCAL_RULE_ID"))


def add_deployment_fields(writer: HashWriter, header: Header) -> None:
    for deployment_bit in (
        header.integer("TAPROOT_DEPLOYMENT_BIT"),
        header.integer("SIMPLICITY_DEPLOYMENT_BIT"),
    ):
        writer.i32(deployment_bit)
        writer.i64(header.integer("DEPLOYMENT_ALWAYS_ACTIVE"))
        writer.i64(header.integer("DEPLOYMENT_NO_TIMEOUT"))
        writer.i32(header.integer("DEPLOYMENT_MIN_ACTIVATION_HEIGHT"))


def add_parent_identity_fields(writer: HashWriter, header: Header) -> None:
    writer.uint256(header.string("PARENT_GENESIS"))
    writer.uint256(header.string("PARENT_POW_LIMIT"))
    writer.vector(bytes.fromhex(header.string("PARENT_SIGNET_CHALLENGE")))
    writer.u8(header.integer("SIDECHAIN_SLOT"))


def add_historical_parent_fields(
    writer: HashWriter, header: Header, *, include_bootstrap: bool = False
) -> None:
    """Commit only milestones that predate and do not depend on this proposal."""
    writer.vector(bytes.fromhex(header.string("HISTORICAL_PROPOSAL_DESCRIPTION_HEX")))
    writer.uint256(header.string("HISTORICAL_PROPOSAL_HASH"))
    writer.u32(header.integer("HISTORICAL_PROPOSAL_HEIGHT"))
    writer.uint256(header.string("HISTORICAL_PROPOSAL_BLOCK_HASH"))
    writer.u32(header.integer("HISTORICAL_ACTIVATION_HEIGHT"))
    writer.uint256(header.string("HISTORICAL_ACTIVATION_BLOCK_HASH"))
    writer.u32(header.integer("PARENT_CHECKPOINT_HEIGHT"))
    writer.uint256(header.string("PARENT_CHECKPOINT_HASH"))
    writer.uint256(header.string("PARENT_CHECKPOINT_CHAINWORK"))
    writer.uint256(header.string("PARENT_CHECKPOINT_CTIP_TXID"))
    writer.u32(header.integer("PARENT_CHECKPOINT_CTIP_VOUT"))
    writer.i64(header.integer("PARENT_CHECKPOINT_CTIP_VALUE"))
    if include_bootstrap:
        writer.uint256(header.string("PARENT_CHECKPOINT_BOOTSTRAP_STATE_COMMITMENT"))


def add_replay_fields(writer: HashWriter, header: Header) -> None:
    writer.u32(header.integer("PEGIN_MIN_DEPTH"))
    writer.u16(header.integer("UNUSED_PROPOSAL_MAX_AGE"))
    writer.u16(header.integer("UNUSED_ACTIVATION_THRESHOLD"))
    writer.u16(header.integer("USED_PROPOSAL_MAX_AGE"))
    writer.u16(header.integer("USED_ACTIVATION_THRESHOLD"))
    writer.u16(header.integer("WITHDRAWAL_BUNDLE_MAX_AGE"))
    writer.u16(header.integer("WITHDRAWAL_BUNDLE_INCLUSION_THRESHOLD"))
    writer.u32(header.integer("PARENT_REPLAY_VERSION"))


def proposal(
    manifest_digest: bytes,
    *,
    source_domain: str,
    text: str,
) -> tuple[bytes, bytes]:
    title = b"Elements"
    if len(title) > 255:
        raise ValueError("proposal title exceeds the one-byte BIP300 field")
    source_id = hashlib.new(
        "ripemd160", sha256(source_domain.encode("ascii") + manifest_digest)
    ).digest()
    description = b"\x00" + bytes([len(title)]) + title + text.encode("ascii")
    description += manifest_digest + source_id
    return description, hash256(description)


def identity_commitment(
    header: Header,
    manifest_digest: bytes,
    proposal_description: bytes,
    proposal_digest: bytes,
    *,
    include_bootstrap: bool = False,
) -> bytes:
    writer = HashWriter().string("ELEMENTS_DRIVECHAIN_NETWORK_V13")
    add_common_protocol_fields(
        writer,
        header,
        p2p_domain=header.string("P2P_MAGIC_DOMAIN"),
        annex_feature_version=header.integer("ANNEX_FEATURE_VERSION"),
        include_network_namespaces=True,
    )
    add_native_rules(writer, header)
    add_deployment_fields(writer, header)
    writer.vector(commit_to_arguments(header))
    add_parent_identity_fields(writer, header)
    writer.u32(header.integer("PEGIN_MIN_DEPTH"))
    writer.raw(manifest_digest)
    writer.vector(proposal_description)
    writer.raw(proposal_digest)
    add_historical_parent_fields(writer, header, include_bootstrap=include_bootstrap)
    writer.u16(header.integer("UNUSED_PROPOSAL_MAX_AGE"))
    writer.u16(header.integer("UNUSED_ACTIVATION_THRESHOLD"))
    writer.u16(header.integer("USED_PROPOSAL_MAX_AGE"))
    writer.u16(header.integer("USED_ACTIVATION_THRESHOLD"))
    writer.u16(header.integer("WITHDRAWAL_BUNDLE_MAX_AGE"))
    writer.u16(header.integer("WITHDRAWAL_BUNDLE_INCLUSION_THRESHOLD"))
    writer.u32(header.integer("PARENT_REPLAY_VERSION"))
    return writer.digest()


def commit_to_arguments(header: Header) -> bytes:
    # CommitToArguments hashes unframed ASCII network ID and script hex.
    return sha256(
        header.string("NETWORK_ID").encode("ascii")
        + b"6a"  # fedpegScript = OP_RETURN
        + bytes([header.integer("SIGNBLOCK_CHALLENGE_OPCODE")]).hex().encode("ascii")
    )


# SHA-256 initial state and round constants, used for Elements' unpadded
# 64-byte fast-Merkle compression function.
_SHA256_IV = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)
_SHA256_K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1,
    0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786,
    0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147,
    0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
    0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A,
    0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)


def _rotr(value: int, shift: int) -> int:
    return ((value >> shift) | (value << (32 - shift))) & 0xFFFFFFFF


def sha256_midstate_64(block: bytes) -> bytes:
    if len(block) != 64:
        raise ValueError("fast-Merkle parent requires exactly 64 bytes")
    words = list(struct.unpack(">16I", block)) + [0] * 48
    for index in range(16, 64):
        x = words[index - 15]
        y = words[index - 2]
        s0 = _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)
        s1 = _rotr(y, 17) ^ _rotr(y, 19) ^ (y >> 10)
        words[index] = (
            words[index - 16] + s0 + words[index - 7] + s1
        ) & 0xFFFFFFFF

    a, b, c, d, e, f, g, h = _SHA256_IV
    for index in range(64):
        sigma1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        choice = (e & f) ^ ((~e) & g)
        temp1 = (h + sigma1 + choice + _SHA256_K[index] + words[index]) & 0xFFFFFFFF
        sigma0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        majority = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (sigma0 + majority) & 0xFFFFFFFF
        h, g, f, e, d, c, b, a = (
            g,
            f,
            e,
            (d + temp1) & 0xFFFFFFFF,
            c,
            b,
            a,
            (temp1 + temp2) & 0xFFFFFFFF,
        )
    state = tuple(
        (initial + value) & 0xFFFFFFFF
        for initial, value in zip(_SHA256_IV, (a, b, c, d, e, f, g, h))
    )
    return struct.pack(">8I", *state)


def fast_merkle_two(left: bytes, right: bytes) -> bytes:
    if len(left) != 32 or len(right) != 32:
        raise ValueError("fast-Merkle leaves must be uint256 values")
    return sha256_midstate_64(left + right)


def derive_pegged_asset(identity_digest: bytes, parent_genesis_display: str) -> bytes:
    parent_genesis = uint256_from_display(parent_genesis_display)
    prevout_hash = hash256(identity_digest + struct.pack("<I", 0))
    entropy = fast_merkle_two(prevout_hash, parent_genesis)
    return fast_merkle_two(entropy, bytes(32))


def genesis(identity_digest: bytes, header: Header) -> tuple[bytes, bytes]:
    # CMutableTransaction, Elements serialization, no witness.
    script_sig = b"\x20" + identity_digest
    tx = bytearray()
    tx.extend(struct.pack("<i", 1))
    tx.extend(b"\x00")  # Elements witness flags
    tx.extend(b"\x01")  # vin count
    tx.extend(bytes(32) + b"\xff\xff\xff\xff")
    tx.extend(compact_size(len(script_sig)) + script_sig)
    tx.extend(b"\xff\xff\xff\xff")
    tx.extend(b"\x01")  # vout count
    tx.extend(b"\x01" + bytes(32))  # explicit null CAsset
    tx.extend(b"\x01" + bytes(8))  # explicit zero CAmount, big-endian
    tx.extend(b"\x00")  # null nonce
    tx.extend(b"\x01\x6a")  # OP_RETURN
    tx.extend(bytes(4))  # locktime
    merkle_root = hash256(bytes(tx))

    block_header = bytearray()
    block_header.extend(struct.pack("<i", header.integer("GENESIS_VERSION")))
    block_header.extend(bytes(32))
    block_header.extend(merkle_root)
    block_header.extend(struct.pack("<I", header.integer("GENESIS_TIME")))
    block_header.extend(struct.pack("<I", 0))  # block_height
    block_header.extend(b"\x01" + bytes([header.integer("SIGNBLOCK_CHALLENGE_OPCODE")]))
    return merkle_root, hash256(bytes(block_header))


BETANET_BOOTSTRAP_DOMAIN = "ELEMENTS_BETANET_PARENT_REPLAY_BOOTSTRAP_V1"


def betanet_bootstrap_commitment(header: Header) -> str:
    """Empty BIP300 state immediately before activation; not an RPC attestation."""
    writer = HashWriter().string(BETANET_BOOTSTRAP_DOMAIN)
    writer.u32(header.integer("PARENT_CHECKPOINT_HEIGHT"))
    writer.uint256(header.string("PARENT_CHECKPOINT_HASH"))
    writer.uint256(header.string("PARENT_CHECKPOINT_CHAINWORK"))
    writer.u32(0)
    return display_hash(writer.digest())


def calculate_fresh(header: Header) -> IdentityResult:
    if header.boolean("BETANET_EXISTING_ELEMENTS_TEST_PROFILE"):
        raise ValueError("fresh chain cannot reuse the live Betanet proposal")
    if header.string("DATA_DIR") != "elements-native-v1":
        raise ValueError("fresh child data directory is required")
    if header.string("P2P_MAGIC_DOMAIN") != "ecash-elements-native-slot24-p2p-v1":
        raise ValueError("fresh child P2P namespace is required")
    if header.string("PARENT_CHECKPOINT_BOOTSTRAP_STATE_COMMITMENT") != betanet_bootstrap_commitment(header):
        raise ValueError("parent bootstrap commitment mismatch")
    zero_hash = "00" * 32
    preactivation_checkpoint_is_canonical = (
        header.string("HISTORICAL_PROPOSAL_DESCRIPTION_HEX") == ""
        and header.string("HISTORICAL_PROPOSAL_HASH") == zero_hash
        and header.integer("HISTORICAL_PROPOSAL_HEIGHT") == 0
        and header.string("HISTORICAL_PROPOSAL_BLOCK_HASH") == zero_hash
        and header.integer("HISTORICAL_ACTIVATION_HEIGHT") == 0
        and header.string("HISTORICAL_ACTIVATION_BLOCK_HASH") == zero_hash
        and header.integer("PARENT_CHECKPOINT_HEIGHT") == 967679
        and header.string("PARENT_CHECKPOINT_HASH") != header.string("PARENT_GENESIS")
        and header.string("PARENT_CHECKPOINT_CHAINWORK") != zero_hash
        and header.string("PARENT_CHECKPOINT_CTIP_TXID") == zero_hash
        and header.integer("PARENT_CHECKPOINT_CTIP_VOUT") == 0xFFFFFFFF
        and header.integer("PARENT_CHECKPOINT_CTIP_VALUE") == 0
    )
    if not preactivation_checkpoint_is_canonical:
        raise ValueError("canonical pre-activation checkpoint is absent")

    manifest = HashWriter().string("ELEMENTS_DRIVECHAIN_PROTOCOL_MANIFEST_V13")
    add_common_protocol_fields(
        manifest, header, p2p_domain=header.string("P2P_MAGIC_DOMAIN"),
        annex_feature_version=header.integer("ANNEX_FEATURE_VERSION"),
        include_network_namespaces=True,
    )
    add_native_rules(manifest, header)
    add_deployment_fields(manifest, header)
    add_parent_identity_fields(manifest, header)
    add_historical_parent_fields(manifest, header, include_bootstrap=True)
    add_replay_fields(manifest, header)
    manifest_digest = manifest.digest()
    description, proposal_digest = proposal(
        manifest_digest,
        source_domain="ELEMENTS_DRIVECHAIN_PROTOCOL_SOURCE_V13",
        text=header.string("PROPOSAL_TEXT"),
    )
    identity_digest = identity_commitment(
        header, manifest_digest, description, proposal_digest, include_bootstrap=True
    )
    pegged = derive_pegged_asset(identity_digest, header.string("PARENT_GENESIS"))
    merkle, genesis_digest = genesis(identity_digest, header)
    return IdentityResult(
        mode="fresh-native-v1",
        protocol_manifest_hash=display_hash(manifest_digest),
        proposal_description_hex=description.hex(),
        proposal_hash=display_hash(proposal_digest),
        identity_commitment=display_hash(identity_digest),
        pegged_asset=display_hash(pegged),
        genesis_merkle_root=display_hash(merkle),
        genesis_hash=display_hash(genesis_digest),
        p2p_magic_domain=header.string("P2P_MAGIC_DOMAIN"),
        p2p_message_start=hash256(header.string("P2P_MAGIC_DOMAIN").encode("ascii"))[:4].hex(),
        data_dir=header.string("DATA_DIR"),
        parent_replay_version=header.integer("PARENT_REPLAY_VERSION"),
        annex_feature_version=header.integer("ANNEX_FEATURE_VERSION"),
        parent_activation_required=True,
        future_parent_milestones_committed=False,
        m1_payload_hex=(bytes.fromhex("d5e0c4af") + bytes([header.integer("SIDECHAIN_SLOT")]) + description).hex(),
        m2_payload_hex=(bytes.fromhex("d6e1c5df") + bytes([header.integer("SIDECHAIN_SLOT")]) + proposal_digest).hex(),
        used_slot_m2_votes_required=header.integer("USED_ACTIVATION_THRESHOLD") + 1,
        used_slot_proposal_max_age=header.integer("USED_PROPOSAL_MAX_AGE"),
    )


def assert_current(header: Header, result: IdentityResult) -> None:
    expected = {
        "protocol_manifest_hash": header.string("PROTOCOL_MANIFEST_HASH"),
        "proposal_description_hex": header.string("PROPOSAL_DESCRIPTION_HEX"),
        "proposal_hash": header.string("PROPOSAL_HASH"),
        "identity_commitment": header.string("IDENTITY_COMMITMENT"),
        "pegged_asset": header.string("PEGGED_ASSET"),
        "genesis_merkle_root": header.string("GENESIS_MERKLE_ROOT"),
        "genesis_hash": header.string("GENESIS_HASH"),
        "p2p_message_start": header.array("P2P_MESSAGE_START").hex(),
    }
    mismatches = {
        field: {"computed": getattr(result, field), "header": expected_value}
        for field, expected_value in expected.items()
        if getattr(result, field) != expected_value
    }
    derived_magic = hash256(result.p2p_magic_domain.encode("ascii"))[:4].hex()
    if derived_magic != result.p2p_message_start:
        mismatches["derived_p2p_message_start"] = {
            "computed": derived_magic,
            "result": result.p2p_message_start,
        }
    if mismatches:
        raise ValueError(
            "independent identity audit failed:\n" + json.dumps(mismatches, indent=2)
        )


def indexer_bindings(header: Header) -> dict:
    """Export audited fresh-chain bindings, not evidence of activation."""
    result = calculate_fresh(header)
    assert_current(header, result)
    return {
        "schema": "elements-indexer-bindings-v1",
        "network": "native-fresh",
        "identity_commitment": result.identity_commitment,
        "genesis_hash": result.genesis_hash,
        "native_asset": result.pegged_asset,
        "p2p_message_start": result.p2p_message_start,
        "p2p_magic_u32_le": int.from_bytes(bytes.fromhex(result.p2p_message_start), "little"),
        "data_dir": result.data_dir,
        "rpc_port": header.integer("RPC_PORT"),
        "p2p_port": header.integer("P2P_PORT"),
        "pubkey_address_prefix": header.integer("PUBKEY_ADDRESS_PREFIX"),
        "script_address_prefix": header.integer("SCRIPT_ADDRESS_PREFIX"),
        "blinded_address_prefix": header.integer("BLINDED_ADDRESS_PREFIX"),
        "bech32_hrp": header.string("BECH32_HRP"),
        "blech32_hrp": header.string("BLECH32_HRP"),
        "sidechain_slot": header.integer("SIDECHAIN_SLOT"),
        "parent_checkpoint_height": header.integer("PARENT_CHECKPOINT_HEIGHT"),
        "parent_checkpoint_hash": header.string("PARENT_CHECKPOINT_HASH"),
        "parent_replay_version": result.parent_replay_version,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--header",
        type=Path,
        default=IDENTITY_HEADER,
        help="identity header to audit (default: repository source)",
    )
    parser.add_argument(
        "--candidate",
        action="store_true",
        help="print the independently calculated candidate without comparing derived header fields",
    )
    parser.add_argument(
        "--indexer-bindings", action="store_true",
        help="export audited fresh-chain consumer bindings (no --candidate)",
    )
    parser.add_argument("--generated-include-dir", type=Path,
                        help="build src directory containing haskell/bootstrap_constants.h")
    args = parser.parse_args()
    if args.indexer_bindings and args.candidate:
        parser.error("--indexer-bindings forbids --candidate")

    try:
        header = Header(args.header, args.generated_include_dir)
        result = calculate_fresh(header)
        if not args.candidate:
            assert_current(header, result)
        output = indexer_bindings(header) if args.indexer_bindings else asdict(result)
    except (OSError, ValueError, struct.error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
