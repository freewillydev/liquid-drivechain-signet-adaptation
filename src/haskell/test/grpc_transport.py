#!/usr/bin/env python3
"""Exercise the actual C++/Haskell client ABI against the official enforcer schema."""
import concurrent.futures
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import time
import grpc
from google.protobuf import json_format

root = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(root / "test/functional"))
from test_framework.enforcer_protocol import load_protocol
from grpc_daemon import check_daemon, unused_port

probe, temporary_root = sys.argv[1:3]
node = sys.argv[3] if len(sys.argv) > 3 else None
cases = [
    ("ValidatorService", "GetChainInfo", {}, {"network": "NETWORK_SIGNET"}),
    ("ValidatorService", "GetChainTip", {}, {"blockHeaderInfo": {
        "blockHash": {"hex": "11" * 32}, "height": 123, "timestamp": "9007199254740993"}}),
    ("ValidatorService", "GetCtip", {"sidechainNumber": 24}, {"ctip": {
        "txid": {"hex": "22" * 32}, "vout": 1, "value": "9007199254740993", "sequenceNumber": "42"}}),
    ("ValidatorService", "GetSidechains", {}, {"sidechains": [{"sidechainNumber": 24,
        "description": {"hex": "aabb"}, "activationHeight": 100}]}),
    ("ValidatorService", "GetTwoWayPegData", {"sidechainId": 24, "endBlockHash": {"hex": "33" * 32}},
        {"blocks": [{"blockHeaderInfo": {"blockHash": {"hex": "33" * 32}, "height": 123},
         "blockInfo": {"events": [{"deposit": {"sequenceNumber": "3",
         "outpoint": {"txid": {"hex": "44" * 32}, "vout": 1},
         "output": {"address": {"hex": "abcd"}, "valueSats": "1000"}}},
         {"withdrawalBundle": {"m6id": {"hex": "99" * 32}, "event": {"submitted": {}}}}]}}]}),
    ("WalletService", "CreateBmmCriticalDataTransaction", {"sidechainId": 24, "valueSats": "100",
        "height": 123, "criticalHash": {"hex": "55" * 32}, "prevBytes": {"hex": "66" * 32}},
        {"txid": {"hex": "77" * 32}}),
    ("WalletService", "BroadcastWithdrawalBundle", {"sidechainId": 24, "transaction": "AAEC"}, {}),
    ("BlockProducerService", "ProposeWithdrawalBundle", {"sidechainId": 24, "transaction": "AAEC"}, {}),
]

with tempfile.TemporaryDirectory(prefix="direct-grpc-", dir=temporary_root) as directory:
    certs = pathlib.Path(directory) / "tls"
    subprocess.run(["bash", str(root / "contrib/drivechain-mtls/generate-certs.sh"), str(certs)],
                   check=True, capture_output=True)
    # A DNS-only certificate ensures authority controls TLS verification, not
    # merely the HTTP/2 header. All connections still use numeric loopback.
    subprocess.run(["openssl", "req", "-new", "-key", str(certs / "server-key.pem"),
                    "-out", str(certs / "dns.csr"), "-subj", "/CN=enforcer.local",
                    "-addext", "subjectAltName=DNS:enforcer.local"], check=True, capture_output=True)
    subprocess.run(["openssl", "x509", "-req", "-in", str(certs / "dns.csr"),
                    "-CA", str(certs / "ca.pem"), "-CAkey", str(certs / "ca-key.pem"),
                    "-set_serial", "42", "-days", "1", "-copy_extensions", "copy",
                    "-out", str(certs / "server.pem")], check=True, capture_output=True)
    messages = load_protocol(directory)
    calls = []
    behavior = "valid"

    def handler(service, method, expected, response):
        request_type, response_type = messages(service, method)
        expected_message = json_format.ParseDict(expected, request_type())
        response_message = json_format.ParseDict(response, response_type())
        def invoke(wire, context):
            if "x509_common_name" in context.auth_context():
                assert context.auth_context()["x509_common_name"] == [b"elements-client"]
            assert request_type.FromString(wire) == expected_message
            calls.append(method)
            if behavior in ("deadline", "cancel"):
                while context.is_active():
                    time.sleep(0.005)
                return b""
            if behavior == "oversized":
                return b"x" * 65537
            if behavior == "malformed":
                return b"\x0a\xff"
            if behavior == "duplicate":
                context.abort(grpc.StatusCode.ALREADY_EXISTS, "bundle exists")
            if behavior == "fake-duplicate":
                context.abort(grpc.StatusCode.PERMISSION_DENIED, "AlreadyExists")
            return response_message.SerializeToString()
        return grpc.unary_unary_rpc_method_handler(invoke)

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        server = grpc.server(executor)
        for service, method, request, response in cases:
            server.add_generic_rpc_handlers((grpc.method_handlers_generic_handler(
                "cusf.mainchain.v1." + service, {method: handler(service, method, request, response)}),))
        credentials = grpc.ssl_server_credentials([
            ((certs / "server-key.pem").read_bytes(), (certs / "server.pem").read_bytes())],
            root_certificates=(certs / "ca.pem").read_bytes(), require_client_auth=True)
        port = server.add_secure_port("127.0.0.1:0", credentials)
        plaintext_port = server.add_insecure_port("127.0.0.1:0")
        assert port
        server.start()
        def run(service, method, request, mode="valid"):
            result = subprocess.run([probe, f"127.0.0.1:{port}", str(certs),
                "cusf.mainchain.v1." + service + "/" + method, json.dumps(request), mode],
                capture_output=True, text=True, timeout=10)
            assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
            status, output = result.stdout.split("\n", 1)
            return int(status), output.strip()
        try:
            for service, method, request, response in cases:
                before = len(calls)
                status, output = run(service, method, request)
                assert status == 0, (method, status, output)
                _, response_type = messages(service, method)
                assert json_format.Parse(output, response_type()) == json_format.ParseDict(response, response_type())
                assert len(calls) == before + 1
                print("PASS official-schema", method, flush=True)
            # TLS must not silently fall back when the endpoint is plaintext.
            secure_port = port
            before = len(calls)
            try:
                port = plaintext_port
                status, output = run("ValidatorService", "GetChainInfo", {})
                assert status == 14 and output, (status, output)
                assert len(calls) == before
            finally:
                port = secure_port
            print("PASS plaintext endpoint rejected with diagnostic", flush=True)
            for behavior, expected in [("oversized", 8), ("malformed", -1), ("duplicate", 6),
                                       ("fake-duplicate", 7), ("deadline", -3), ("cancel", -2)]:
                started = time.monotonic()
                status, output = run("ValidatorService", "GetChainInfo", {}, behavior)
                assert status == expected, (behavior, status, output)
                assert time.monotonic() - started < 5
                print("PASS", behavior, flush=True)
            behavior = "valid"
            if node:
                check_daemon(node, directory, certs, port, calls)
            # Qualify the shipped HTTP/2 proxy, not just direct gRPC TLS.
            secure_port = port
            port = unused_port()
            with tempfile.TemporaryFile() as proxy_log:
                proxy = subprocess.Popen(["bash", str(root / "contrib/drivechain-mtls/run-mtls-proxy.sh"),
                    str(certs), f"127.0.0.1:{port}", f"127.0.0.1:{plaintext_port}"],
                    stdout=proxy_log, stderr=proxy_log)
                try:
                    for _ in range(100):
                        try:
                            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                                break
                        except OSError:
                            assert proxy.poll() is None, "HTTP/2 proxy exited"
                            time.sleep(0.05)
                    for service, method, request, response in cases:
                        before = len(calls)
                        status, output = run(service, method, request)
                        assert status == 0, (method, status, output)
                        assert len(calls) == before + 1
                    if node:
                        proxy_directory = pathlib.Path(directory) / "proxied"
                        proxy_directory.mkdir()
                        check_daemon(node, proxy_directory, certs, port, calls)
                    print("PASS authenticated HTTP/2 proxy: all allowed methods", flush=True)
                finally:
                    proxy.terminate()
                    proxy.wait(timeout=10)
                    port = secure_port
            before = len(calls)
            status, output = run("ValidatorService", "GetChainInfo", {}, "wrong-authority")
            assert status == 14 and output, (status, output)
            assert len(calls) == before
            assert run("ValidatorService", "Stop", {})[0] == -1
            assert len(calls) == before
            assert run("ValidatorService", "GetChainInfo", {"ignored": 1})[0] == -1
            assert run("ValidatorService", "GetCtip", {"sidechainNumber": 24, "sidechain_number": 25})[0] == -1
            assert len(calls) == before
            other = pathlib.Path(directory) / "other"
            subprocess.run(["bash", str(root / "contrib/drivechain-mtls/generate-certs.sh"), str(other)],
                           check=True, capture_output=True)
            ca = (certs / "ca.pem").read_bytes()
            (certs / "ca.pem").write_bytes((other / "ca.pem").read_bytes())
            status, output = run("ValidatorService", "GetChainInfo", {})
            assert status != 0 and output, (status, output)
            assert len(calls) == before
            (certs / "ca.pem").write_bytes(ca)
            (certs / "elements-client.pem").write_bytes((other / "elements-client.pem").read_bytes())
            (certs / "elements-client-key.pem").write_bytes((other / "elements-client-key.pem").read_bytes())
            status, output = run("ValidatorService", "GetChainInfo", {})
            assert status != 0 and output, (status, output)
            assert len(calls) == before
            (certs / "ca.pem").write_text("not a PEM certificate")
            (certs / "elements-client.pem").write_text("not a PEM certificate")
            (certs / "elements-client-key.pem").write_text("not a PEM key")
            status, output = run("ValidatorService", "GetChainInfo", {})
            assert status != 0 and output, (status, output)
            assert len(calls) == before
            print("PASS authority and method rejection", flush=True)
        finally:
            server.stop(0).wait()
