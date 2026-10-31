"""Exercise the native parent HTTP client with isolated, synthetic credentials."""
import base64
import hashlib
import http.server
import json
import os
import pathlib
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request


def unused_port():
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


def check(binary, directory, mode):
    data = directory / mode
    data.mkdir()
    credential_file = data / "parent.auth"
    environment = dict(os.environ)
    if mode in ("cookie-default", "cookie-relative"):
        home = data / "home"
        environment["HOME"] = str(home)
        parent_data = home / ("Library/Application Support/Bitcoin" if sys.platform == "darwin" else ".bitcoin")
        credential_file = parent_data / "regtest/.cookie"
        credential_file.parent.mkdir(parents=True)
    rotating = "__cookie__:" + "a" * 64
    updated = "__cookie__:" + "b" * 64
    cookie_auth = mode in ("cookie", "cache", "rotate", "cookie401", "cookie401-parse", "cookie-invalid", "cookie-missing",
                          "cookie-default", "cookie-relative")
    initial = rotating if cookie_auth else "fixture:fixture"
    credential_file.write_text(initial + "\n")
    credential_file.chmod(0o644 if mode == "unsafe" else 0o600)
    if mode in ("private-invalid", "cookie-invalid"):
        credential_file.write_text("not:a:credential\n")
    elif mode == "private-large":
        credential_file.write_text("a" * 4097)
    elif mode == "cookie-missing":
        credential_file.unlink()
    elif mode == "private-symlink":
        target = data / "real.auth"
        credential_file.rename(target)
        credential_file.symlink_to(target)
    elif mode == "private-directory":
        credential_file.unlink()
        credential_file.mkdir(mode=0o700)
    expected = [initial]
    calls = []
    failures = []
    genesis = "11" * 32
    rejected_messages = {
        "unsafe": ["permissions must deny all group and other access"],
        "conflict": ["mutually exclusive", "select exactly one parent RPC authentication mechanism"],
        "timeout": ["timeout reached"],
        "inline401": ["authorization failed"],
        "cookie401": ["authorization failed"],
        "cookie401-parse": ["couldn't parse reply from server"],
        "http503": ["server returned HTTP error 503"],
        "malformed": ["couldn't parse reply from server"],
        "empty": ["no response from server"],
        "private-invalid": ["parent credential file must contain one bounded username:password record"],
        "cookie-invalid": ["mainchain RPC cookie is not a canonical rotating Bitcoin Core cookie"],
        "private-large": ["mainchain RPC cookie file is unexpectedly large"],
        "cookie-missing": ["cannot securely open mainchain RPC cookie"],
        "private-symlink": ["cannot securely open mainchain RPC cookie"],
        "private-directory": ["mainchain RPC cookie is not a regular file"],
        "private-hostname": ["Static parent RPC credential files require a numeric-loopback endpoint"],
    }

    class Parent(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            method = request["method"]
            authorized = self.headers.get("Authorization") == (
                "Basic " + base64.b64encode(expected[0].encode()).decode())
            calls.append((method, authorized))
            if mode in ("inline401", "cookie401", "cookie401-parse", "http503", "malformed", "empty"):
                status, body = 200, b"not JSON"
                if mode in ("inline401", "cookie401") or (mode == "cookie401-parse" and len(calls) == 1):
                    status, body = 401, b""
                elif mode == "http503":
                    status = 503
                elif mode == "empty":
                    body = b""
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if not authorized:
                if mode != "rotate":
                    failures.append("unexpected authentication failure")
                self.send_response(401)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if method == "getnetworkinfo":
                result = {"version": 300000, "subversion": "/Satoshi:30.0/"}
                if mode == "cache":
                    credential_file.unlink()
                elif mode == "rotate":
                    credential_file.write_text(updated + "\n")
                    expected[0] = updated
                elif mode == "timeout":
                    time.sleep(2)
            elif method == "getblockhash" and request["params"] == [0]:
                result = genesis
            else:
                failures.append("unexpected parent method")
                result = None
            body = json.dumps({"result": result, "error": None, "id": request["id"]}).encode()
            try:
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                assert mode == "timeout"

        def log_message(self, *args):
            pass

    parent = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Parent)
    worker = threading.Thread(target=parent.serve_forever)
    worker.start()
    port = unused_port()
    args = [str(binary), f"-datadir={data}", "-chain=elementsregtest", "-server=1",
        "-listen=0", "-dnsseed=0", "-fixedseeds=0", "-disablewallet=1",
        "-drivechainl1blocksync=0", "-validatepegin=1", "-dbcache=16", "-par=1",
        f"-rpcport={port}", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
        "-mainchainrpchost=127.0.0.1", f"-mainchainrpcport={parent.server_port}",
        f"-parentgenesisblockhash={genesis}", "-printtoconsole=0"]
    if mode in ("inline", "timeout", "inline401", "http503", "malformed", "empty"):
        args += ["-mainchainrpcuser=fixture", "-mainchainrpcpassword=fixture"]
    elif mode == "cookie-default":
        pass
    elif mode == "cookie-relative":
        args += ["-mainchainrpccookiefile=regtest/.cookie"]
    elif cookie_auth:
        args += [f"-mainchainrpccookiefile={credential_file}"]
    else:
        args += [f"-mainchainrpccredentialfile={credential_file}"]
    if mode == "conflict":
        args += [f"-mainchainrpccookiefile={credential_file}"]
    if mode == "timeout":
        args += ["-mainchainrpctimeout=1"]
    if mode == "private-hostname":
        args[args.index("-mainchainrpchost=127.0.0.1")] = "-mainchainrpchost=localhost"

    def rpc(method):
        cookie = (data / "elementsregtest/.cookie").read_bytes().strip()
        req = urllib.request.Request(f"http://127.0.0.1:{port}/",
            data=json.dumps({"id": 1, "method": method, "params": []}).encode(),
            headers={"Authorization": "Basic " + base64.b64encode(cookie).decode()})
        try:
            with urllib.request.urlopen(req, timeout=3) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            return json.load(error)

    process = None
    try:
        with (data / "console.log").open("w") as output:
            process = subprocess.Popen(args, stdout=output, stderr=subprocess.STDOUT, env=environment)
            rejected = mode in rejected_messages
            if rejected:
                assert process.wait(timeout=30) != 0
                debug = data / "elementsregtest/debug.log"
                log = (data / "console.log").read_text() + (debug.read_text() if debug.exists() else "")
                messages = rejected_messages[mode]
                assert any(message in log for message in messages), log[-6000:]
                expected_calls = 0 if mode in ("unsafe", "conflict", "private-invalid", "cookie-invalid",
                    "private-large", "cookie-missing", "private-symlink", "private-directory", "private-hostname") else (
                    2 if mode in ("cookie401", "cookie401-parse") else 1)
                assert calls == [("getnetworkinfo", True)] * expected_calls, calls
            else:
                for _ in range(200):
                    if process.poll() is not None:
                        raise AssertionError((data / "console.log").read_text())
                    try:
                        reply = rpc("getblockcount")
                        if reply["error"] is None:
                            assert reply["result"] == 0
                            break
                    except (OSError, ValueError):
                        pass
                    time.sleep(0.1)
                else:
                    raise AssertionError("isolated node did not finish initialization")
                if mode == "rotate":
                    assert calls == [("getnetworkinfo", True), ("getblockhash", False),
                                     ("getblockhash", True)], calls
                else:
                    assert calls == [("getnetworkinfo", True), ("getblockhash", True)], calls
                assert rpc("stop")["error"] is None
                assert process.wait(timeout=15) == 0
            assert not failures, failures
            print("PASS", mode, flush=True)
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        parent.shutdown()
        parent.server_close()
        worker.join()


def check_network(binary, directory, mode):
    data = directory / ("network-" + mode)
    data.mkdir()
    correct = "00000000000000030101ba5cfea54b22becc79f95dc6040beb76e01dd9d04042"
    cookie = data / "parent.auth"
    old_cookie, new_cookie = "__cookie__:" + "a" * 64, "__cookie__:" + "b" * 64
    cookie.write_text(old_cookie + "\n")
    cookie.chmod(0o600)
    calls, failures = [], []
    expected_error = {
        "match": "", "wrong": "post-fork block", "upper": "post-fork block",
        "rpc-error": "getblockhash returned error", "null-result": "getblockhash returned no result",
        "malformed-json": "couldn't parse reply", "unauthorized": "authorization failed",
        "cookie-rotate": "", "cookie-denied": "authorization failed", "timeout": "timeout reached",
    }[mode]

    class Parent(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            calls.append(request)
            expected_auth = (new_cookie if len(calls) > 1 else old_cookie) if mode.startswith("cookie-") else "fixture:fixture"
            if self.headers.get("Authorization") != "Basic " + base64.b64encode(expected_auth.encode()).decode():
                failures.append("unexpected authentication")
            if request["method"] != "getblockhash" or request["params"] != [967680]:
                failures.append("unexpected parent request")
            if mode == "timeout":
                time.sleep(2)
            unauthorized = mode in ("unauthorized", "cookie-denied") or (mode == "cookie-rotate" and len(calls) == 1)
            if unauthorized:
                if mode.startswith("cookie-"):
                    cookie.write_text(new_cookie + "\n")
                body, status = b"", 401
            elif mode == "malformed-json":
                body, status = b"invalid", 200
            else:
                result = correct if mode not in ("wrong", "upper") else ("0" * 64 if mode == "wrong" else correct.upper())
                body = json.dumps(dict(result=None if mode in ("rpc-error", "null-result") else result,
                    error={"code": -8, "message": "fixture"} if mode == "rpc-error" else None, id=request["id"])).encode()
                status = 500 if mode == "rpc-error" else 200
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *args):
            pass

    parent = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Parent)
    worker = threading.Thread(target=parent.serve_forever)
    worker.start()
    env = dict(os.environ, ELEMENTS_TEST_PARENT_RPC_PORT=str(parent.server_port),
        ELEMENTS_TEST_PARENT_RPC_ERROR=expected_error)
    env.pop("ELEMENTS_TEST_PARENT_RPC_COOKIE", None)
    if mode.startswith("cookie-"):
        env["ELEMENTS_TEST_PARENT_RPC_COOKIE"] = str(cookie)
    try:
        with (data / "test.log").open("w") as log:
            result = subprocess.run([str(binary),
                "--run_test=drivechain_network_safety_tests/parent_network_native_http_transport",
                "--report_level=detailed"], env=env, stdout=log, stderr=subprocess.STDOUT, timeout=30)
        assert result.returncode == 0, (data / "test.log").read_text()[-6000:]
        assert len(calls) == (2 if mode.startswith("cookie-") else 1), calls
        assert not failures, failures
        print("PASS network-" + mode, flush=True)
    finally:
        parent.shutdown()
        parent.server_close()
        worker.join()


def check_header(binary, directory, mode, composed=False, block=False, body_only=False):
    label = ("body-" if body_only else "complete-block-" if block else "network-header-" if composed else "header-") + mode
    data = directory / label
    data.mkdir()
    # Offline synthetic headers, never submitted to a chain or a mining RPC.
    headers, hashes = [], []
    previous = bytes(32)
    coinbase = (struct.pack("<I", 1) + b"\x01" + bytes(32) + b"\xff"*4 + b"\x01\x00" +
                b"\xff"*4 + b"\x01" + struct.pack("<Q", 50) + b"\x01\x51" + bytes(4))
    merkle = hashlib.sha256(hashlib.sha256(coinbase).digest()).digest()
    for height in range(3):
        root = merkle if block and height == 2 and mode != "body-merkle" else bytes(32)
        prefix = struct.pack("<I", 1) + previous + root + struct.pack("<II", 1000+height, 0x207fffff)
        for nonce in range(1000):
            raw = prefix + struct.pack("<I", nonce)
            digest = hashlib.sha256(hashlib.sha256(raw).digest()).digest()
            if int.from_bytes(digest, "little") <= 0x7fffff << (8*29):
                break
        else:
            raise AssertionError("synthetic header nonce search exhausted")
        headers.append(raw.hex())
        hashes.append(digest[::-1].hex())
        previous = digest
    expected_error = {
        "match": "", "wrong-genesis": "genesis does not match", "inactive": "not the active-chain block",
        "raw-trailing": "trailing bytes", "raw-short": "cannot decode raw parent header",
        "wrong-raw": "raw parent header hashes", "predecessor-height": "not canonical or contiguous",
        "ancestor-trailing": "trailing bytes", "rpc-error": "getblockheader returned error",
        "cookie-rotate": "", "cookie-cache": "", "timeout": "timeout reached",
        "identity-wrong": "does not serve the mainnet parent post-fork block",
        "identity-upper": "does not serve the mainnet parent post-fork block",
        "identity-null": "cannot verify mainnet parent RPC identity: getblockhash returned no result",
        "identity-error": "cannot verify mainnet parent RPC identity",
        "identity-unauthorized": "cannot verify mainnet parent RPC identity",
        "identity-timeout": "cannot verify mainnet parent RPC identity",
        "pruned": "", "body-trailing": "trailing bytes", "body-short": "cannot decode raw parent block",
        "body-merkle": "invalid or mutated transaction Merkle tree", "body-rpc-error": "getblock failed:",
        "body-timeout": "timeout reached", "recovery-nopeer": "no parent peer offers full block service",
        "recovery-inactive": "pruned parent block is not active", "recovery-height": "height changed during recovery",
        "cookie-body-rotate": "", "cookie-body-cache": "",
    }[mode]
    raw_block = headers[2] + "01" + coinbase.hex()
    recovering = mode in ("pruned", "recovery-nopeer", "recovery-inactive", "recovery-height", "cookie-body-cache")
    body_calls = [0]
    cookie = data / "parent.cookie"
    old_cookie, new_cookie = "__cookie__:" + "a"*64, "__cookie__:" + "b"*64
    cookie.write_text(old_cookie + "\n")
    cookie.chmod(0o600)
    authorized_cookie = [old_cookie]
    rotated = [False]
    calls, failures = [], []

    class Parent(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            method, params = request["method"], request["params"]
            calls.append((method, params))
            expected = authorized_cookie[0] if mode.startswith("cookie-") else "fixture:fixture"
            if self.headers.get("Authorization") != "Basic " + base64.b64encode(expected.encode()).decode():
                failures.append("unexpected authentication")
            status, error = 200, None
            if composed and method == "getblockhash" and params == [967680]:
                result = "00000000000000030101ba5cfea54b22becc79f95dc6040beb76e01dd9d04042"
                if mode == "identity-wrong":
                    result = "00"*32
                elif mode == "identity-upper":
                    result = result.upper()
                elif mode == "identity-null":
                    result = None
                elif mode == "identity-error":
                    result, error, status = None, dict(code=-8, message="fixture identity"), 500
                elif mode == "identity-unauthorized":
                    status = 401
                elif mode == "identity-timeout":
                    time.sleep(2)
            elif method == "getblockhash" and (params in ([0], [2]) or (block and mode == "recovery-height" and params == [1])):
                result = hashes[2 if mode == "recovery-height" and params == [1] else params[0]]
                if (mode == "wrong-genesis" and params == [0]) or (mode == "inactive" and params == [2]):
                    result = "00"*32
            elif method == "getblockheader" and len(params) == 2 and params[0] in hashes:
                height = hashes.index(params[0])
                if params[1] is True:
                    result = dict(hash=hashes[height], height=height, confirmations=6,
                        chainwork=f"{2*(height+1):064x}", previousblockhash=hashes[max(0, height-1)])
                    if mode == "predecessor-height" and height == 1:
                        result["height"] = 0
                    if block and height == 2 and body_calls[0]:
                        if mode == "recovery-inactive":
                            result["confirmations"] = 0
                        if mode == "recovery-height" and body_calls[0] >= 3:
                            result["height"] = 1
                elif params[1] is False:
                    result = headers[height]
                    if mode == "raw-trailing" or (mode == "ancestor-trailing" and height == 1):
                        result += "00"
                    elif mode == "raw-short":
                        result = result[:100]
                    elif mode == "wrong-raw":
                        result = headers[0]
                    if mode == "timeout" and height == 1:
                        time.sleep(2)
                else:
                    failures.append("invalid header verbosity")
                    result = None
                if mode == "rpc-error":
                    result, error, status = None, dict(code=-8, message="fixture"), 500
            elif block and method == "getblock" and params == [hashes[2], 0]:
                body_calls[0] += 1
                result = raw_block
                if recovering and body_calls[0] <= 2:
                    result, error, status = None, dict(code=-1, message="Block not available (pruned data)"), 500
                elif mode == "body-trailing":
                    result += "00"
                elif mode == "body-short":
                    result = result[:100]
                elif mode == "body-rpc-error":
                    result, error, status = None, dict(code=-8, message="fixture"), 500
                elif mode == "body-timeout":
                    time.sleep(2)
            elif block and method == "getpeerinfo" and params == []:
                result = [dict(id=1, servicesnames=["NETWORK_LIMITED" if mode == "recovery-nopeer" else "NETWORK"])]
            elif block and method == "getblockfrompeer" and params == [hashes[2], 1]:
                result = {}
            else:
                failures.append("unexpected RPC request")
                result = None
            if (mode == "cookie-cache" and len(calls) == 1) or (mode == "cookie-body-cache" and method == "getblock" and body_calls[0] == 1):
                cookie.unlink()
            if ((mode == "cookie-rotate" and len(calls) == 4) or
                (mode == "cookie-body-rotate" and method == "getblock")) and not rotated[0]:
                cookie.write_text(new_cookie + "\n")
                authorized_cookie[0], rotated[0] = new_cookie, True
                status = 401
            body = b"" if status == 401 else json.dumps(dict(result=result, error=error, id=request["id"])).encode()
            try:
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                assert mode in ("timeout", "identity-timeout", "body-timeout")

        def log_message(self, *args):
            pass

    parent = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Parent)
    worker = threading.Thread(target=parent.serve_forever)
    worker.start()
    env = dict(os.environ, ELEMENTS_TEST_HEADER_RPC_PORT=str(parent.server_port),
        ELEMENTS_TEST_HEADER_HASH=hashes[2], ELEMENTS_TEST_HEADER_GENESIS=hashes[0],
        ELEMENTS_TEST_HEADER_ERROR=expected_error)
    env.pop("ELEMENTS_TEST_HEADER_COOKIE", None)
    env.pop("ELEMENTS_TEST_NETWORK_HEADER", None)
    env.pop("ELEMENTS_TEST_NETWORK_REVOKED", None)
    env.pop("ELEMENTS_TEST_PARENT_BODY", None)
    env.pop("ELEMENTS_TEST_BODY_HEADER_PUBLISHED", None)
    if block:
        env["ELEMENTS_TEST_PARENT_BODY"] = "raw" if body_only else "full"
        if not body_only and not mode.startswith("identity-"):
            env["ELEMENTS_TEST_BODY_HEADER_PUBLISHED"] = "1"
    if composed:
        env["ELEMENTS_TEST_NETWORK_HEADER"] = "1"
        if mode.startswith("identity-"):
            env["ELEMENTS_TEST_NETWORK_REVOKED"] = "1"
    if mode.startswith("cookie-"):
        env["ELEMENTS_TEST_HEADER_COOKIE"] = str(cookie)
    try:
        with (data / "test.log").open("w") as log:
            result = subprocess.run([str(binary), "--run_test=pegin_witness_tests/parent_header_native_http_transport",
                "--report_level=detailed"], env=env, stdout=log, stderr=subprocess.STDOUT, timeout=30)
        assert result.returncode == 0, (data / "test.log").read_text()[-6000:]
        if not expected_error and not block:
            assert len(calls) == (9 if mode == "cookie-rotate" else 8) + int(composed), calls
            assert calls[-1] == ("getblockheader", [hashes[0], False]), calls
        if composed:
            assert calls[0] == ("getblockhash", [967680]), calls
            if mode.startswith("identity-"):
                assert len(calls) == 1, calls
        if block and not mode.startswith("identity-"):
            assert any(method == "getblock" for method, _ in calls), calls
            if body_only:
                assert calls[0] == ("getblock", [hashes[2], 0]), calls
                assert all(params != [967680] for _, params in calls), calls
            if not expected_error:
                assert body_calls[0] == (3 if recovering else 2 if mode == "cookie-body-rotate" else 1), calls
                if recovering:
                    assert ("getblockfrompeer", [hashes[2], 1]) in calls, calls
        assert calls and not failures, failures
        print("PASS " + label, flush=True)
    finally:
        parent.shutdown()
        parent.server_close()
        worker.join()


if __name__ == "__main__":
    binary = pathlib.Path(sys.argv[1]).resolve(strict=True)
    directory = pathlib.Path(sys.argv[2]).resolve()
    directory.mkdir(exist_ok=False)
    for mode in ("inline", "private", "cookie", "cache", "rotate", "unsafe", "conflict", "timeout",
                 "inline401", "cookie401", "cookie401-parse", "http503", "malformed", "empty",
                 "private-invalid", "cookie-invalid", "private-large", "cookie-missing", "private-symlink", "private-directory",
                 "private-hostname", "cookie-default", "cookie-relative"):
        check(binary, directory, mode)
    if len(sys.argv) > 3:
        unit_tests = pathlib.Path(sys.argv[3]).resolve(strict=True)
        for mode in ("match", "wrong", "upper", "rpc-error", "null-result", "malformed-json",
                     "unauthorized", "cookie-rotate", "cookie-denied", "timeout"):
            check_network(unit_tests, directory, mode)
        for mode in ("match", "wrong-genesis", "inactive", "raw-trailing", "raw-short", "wrong-raw",
                     "predecessor-height", "ancestor-trailing", "rpc-error", "cookie-rotate", "cookie-cache", "timeout"):
            check_header(unit_tests, directory, mode)
            check_header(unit_tests, directory, mode, composed=True)
        for mode in ("identity-wrong", "identity-upper", "identity-null", "identity-error",
                     "identity-unauthorized", "identity-timeout"):
            check_header(unit_tests, directory, mode, composed=True)
        for mode in ("match", "pruned", "body-trailing", "body-short", "body-merkle", "body-rpc-error",
                     "body-timeout", "recovery-nopeer", "recovery-inactive", "recovery-height",
                     "cookie-body-rotate", "cookie-body-cache"):
            check_header(unit_tests, directory, mode, composed=True, block=True)
            check_header(unit_tests, directory, mode, block=True, body_only=True)
        for mode in ("identity-wrong", "identity-null", "identity-error"):
            check_header(unit_tests, directory, mode, composed=True, block=True)
    print("PASS all isolated native parent HTTP preparation cases; nodes stopped", flush=True)
