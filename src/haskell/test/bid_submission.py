"""Isolated native BMM submission tests, with synthetic unsigned Bitcoin data.

This is transport/journal qualification, not a mined bid or valid signature test.
Only a fresh loopback HTTP listener and temporary native-test datadir are used.
"""
import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import threading


def check(binary, directory, mode, expected_error):
    data = directory / mode
    data.mkdir()
    credential = data / "parent.auth"
    credential.write_text("fixture:fixture\n")
    credential.chmod(0o600)
    identity = (Path(__file__).resolve().parents[2] / "elements_drivechain_identity.h").read_text()

    def constant(name):
        return re.search(r"\b" + name + r'\[\]\{\s*"([0-9a-f]{64})"', identity)[1]

    parent_hash = "112233".zfill(64)
    network_hash = "00000000000000030101ba5cfea54b22becc79f95dc6040beb76e01dd9d04042"
    calls, failures, broadcasts = [], [], []
    pending = [None]
    change = "0014" + "07" * 20
    funded_count = [0]

    class Parent(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            method, params = request["method"], request["params"]
            calls.append((self.path, method, params))
            if self.headers.get("Authorization") != "Basic " + base64.b64encode(b"fixture:fixture").decode():
                failures.append("authentication differs")
            wallet = method in ("getwalletinfo", "getrawchangeaddress", "getaddressinfo",
                                "fundrawtransaction", "signrawtransactionwithwallet")
            if self.path != ("/wallet/fixture-bid-wallet" if wallet else "/"):
                failures.append("wrong endpoint: " + self.path)
            result, error = None, None
            if method == "getblockhash":
                values = {0: constant("PARENT_GENESIS"), 967680: network_hash,
                          967679: constant("PARENT_CHECKPOINT_HASH")}
                result = values[params[0]]
                if params[0] == {"genesis": 0, "network": 967680, "checkpoint": 967679}.get(mode):
                    result = "11" * 32
                if mode == "network-error" and params == [967680]:
                    result, error = None, dict(code=-8, message="network fixture offline")
            elif method == "getbestblockhash":
                result = parent_hash
            elif method == "getblockheader":
                assert params == [parent_hash]
                result = dict(height=973958)
            elif method == "getwalletinfo":
                result = dict(private_keys_enabled=mode != "signing")
            elif method == "getrawchangeaddress":
                result = "fixture-change"
            elif method == "getaddressinfo":
                result = dict(ismine=mode != "ownership", scriptPubKey=change)
            elif method == "fundrawtransaction":
                funded_count[0] += 1
                assert params[1] == dict(changeAddress="fixture-change", changePosition=1,
                    replaceable=True, lockUnspents=False, minconf=1, fee_rate=1, subtractFeeFromOutputs=[1])
                raw = bytes.fromhex(params[0])
                assert raw[:6] == b"\x02\x00\x00\x00\x00\x02"
                # The fixture adds one confirmed input, retaining the two native
                # outputs. Haskell must replace the change value and sequence.
                vin = bytes.fromhex("1234".zfill(64))[::-1] + struct.pack("<I", 0) + b"\x00" + b"\xff" * 4
                result = dict(hex=(raw[:4] + b"\x01" + vin + raw[5:]).hex(), changepos=-1)
            elif method == "gettxout":
                assert params == ["1234".zfill(64), 0, False]
                result = dict(confirmations=0 if mode == "unconfirmed" else 6, value=0.001)
            elif method == "signrawtransactionwithwallet":
                result = dict(hex=params[0], complete=mode != "signature")
            elif method == "testmempoolaccept":
                result = [dict(allowed=mode != "mempool", **{"reject-reason": "fixture rejection"})]
            elif method == "sendrawtransaction":
                broadcasts.append(params[0])
                raw = bytes.fromhex(params[0])
                pending[0] = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()
                result = "11" * 32 if mode == "txid" else pending[0]
                if mode == "retry" and len(broadcasts) == 1:
                    pending[0], result, error = None, None, dict(code=-28, message="fixture ambiguous broadcast")
            elif method == "getmempoolentry":
                if pending[0] is None:
                    error = dict(code=-5, message="not found")
                else:
                    assert params == [pending[0]]
                    result = dict(vsize=170, fees=dict(base=0.0000025))
            else:
                failures.append("unexpected request: " + method)
            body = json.dumps(dict(result=result, error=error, id=request["id"])).encode()
            self.send_response(500 if error else 200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    parent = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Parent)
    worker = threading.Thread(target=parent.serve_forever)
    worker.start()
    env = dict(os.environ, ELEMENTS_TEST_BID_RPC_PORT=str(parent.server_port),
               ELEMENTS_TEST_BID_MODE=mode, ELEMENTS_TEST_BID_ERROR=expected_error,
               ELEMENTS_TEST_BID_CREDENTIAL=str(credential.resolve()))
    try:
        with (data / "test.log").open("w") as log:
            result = subprocess.run([str(binary), "--run_test=bmm_submission_tests/bmm_submission_native_http",
                "--report_level=detailed"], env=env, stdout=log, stderr=subprocess.STDOUT, timeout=60)
        (data / "requests.json").write_text(json.dumps(calls, indent=2) + "\n")
        assert result.returncode == 0, (data / "test.log").read_text()[-6000:]
        assert not failures, failures
        if mode in ("wallet", "host"):
            assert not calls, calls
        last_method = {"genesis": "getblockhash", "network": "getblockhash", "network-error": "getblockhash",
            "checkpoint": "getblockhash", "slot": "getblockhash", "cancel": "getblockhash",
            "signing": "getwalletinfo", "ownership": "getaddressinfo", "unconfirmed": "gettxout",
            "signature": "signrawtransactionwithwallet", "mempool": "testmempoolaccept", "txid": "sendrawtransaction"}
        if mode in last_method:
            assert calls[-1][1] == last_method[mode], calls
        if mode in ("genesis", "network", "network-error", "checkpoint", "slot", "cancel"):
            assert all(endpoint == "/" for endpoint, _, _ in calls), calls
        if mode in ("success", "retry"):
            assert funded_count[0] == 1
            assert len(broadcasts) == (2 if mode == "retry" else 1)
            assert len(set(broadcasts)) == 1
        elif mode != "txid":
            assert not broadcasts
        print("PASS bid-submission-" + mode, flush=True)
    finally:
        parent.shutdown()
        parent.server_close()
        worker.join()


if __name__ == "__main__":
    binary, directory = map(Path, sys.argv[1:])
    directory.mkdir()
    for mode, error in {
        "success": "", "retry": "fixture ambiguous broadcast", "wallet": "explicitly funded parent wallet",
        "host": "numeric loopback", "genesis": "wrong genesis", "network": "post-fork block",
        "network-error": "cannot verify mainnet parent", "checkpoint": "wrong fork checkpoint",
        "slot": "differs from the selected chain", "cancel": "submission cancelled",
        "signing": "signing parent wallet", "ownership": "not wallet-owned", "unconfirmed": "not confirmed",
        "signature": "Incomplete BMM signature", "mempool": "fixture rejection", "txid": "different BMM transaction ID",
    }.items():
        check(binary, directory, mode, error)
    print("PASS all isolated BMM submission cases; listeners stopped", flush=True)
