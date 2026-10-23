"""Daemon lifecycle regression using only isolated parent/enforcer fixtures."""
import base64
import http.server
import json
import os
import pathlib
import signal
import socket
import subprocess
import tempfile
import threading
import time
import urllib.request
import urllib.error


def unused_port():
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


def check_windows_process(args, rpc, calls, occupied_port):
    """Windows has no fork/daemon mode: qualify the actual foreground process."""
    for iteration in range(2):
        with tempfile.TemporaryFile() as log:
            process = subprocess.Popen(args, stdout=log, stderr=log)
            try:
                for _ in range(200):
                    if process.poll() is not None:
                        log.seek(0)
                        raise AssertionError(("node exited before RPC readiness", process.returncode,
                                              log.read().decode(errors="replace")))
                    try:
                        assert rpc("getblockcount") == 0
                        break
                    except (OSError, ValueError):
                        time.sleep(0.1)
                else:
                    raise AssertionError("Windows node RPC did not become ready")
                before = len(calls)
                result = rpc("getdrivechainpegevents", [0, 1, True])
                assert result["sidechain_id"] == 24, result
                assert calls[before:] == ["GetTwoWayPegData"], calls[before:]
                rpc("stop")
                assert process.wait(timeout=20) == 0, "Windows node shutdown failed"
                print("PASS Windows", "startup" if iteration == 0 else "restart",
                      "nested gRPC and clean shutdown", flush=True)
            finally:
                # Only reap the process created by this fixture, never a PID
                # recovered from an unrelated runtime or a mutable pid file.
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
    failed = subprocess.run(args + [f"-rpcport={occupied_port}"],
                            capture_output=True, text=True, timeout=20)
    assert failed.returncode != 0, "failed Windows initialization reported success"
    assert "bind" in (failed.stdout + failed.stderr).lower(), (failed.stdout, failed.stderr)
    print("PASS Windows initialization failure propagation", flush=True)


def check_daemon(binary, directory, certs, enforcer_port, calls):
    invalid = subprocess.run([str(binary), "-version"],
        env=dict(os.environ, ELEMENTS_DAEMON_PIPE="-1"), capture_output=True, timeout=5)
    if os.name == "nt":
        # This POSIX-only handoff must not acquire meaning on Windows.
        assert invalid.returncode == 0, (invalid.stdout, invalid.stderr)
    else:
        assert invalid.returncode != 0 and b"Invalid daemon initialization pipe" in invalid.stderr
    class Parent(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            assert self.headers["Authorization"] == "Basic " + base64.b64encode(b"fixture:fixture").decode()
            result = "33" * 32 if request["method"] == "getbestblockhash" else None
            body = json.dumps({"result": result, "error": None, "id": request["id"]}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    parent = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Parent)
    worker = threading.Thread(target=parent.serve_forever)
    worker.start()
    try:
        for mode in ((None,) if os.name == "nt" else ("-daemonwait", "-daemon")):
            data = pathlib.Path(directory) / (mode[1:] if mode else "foreground-windows")
            data.mkdir()
            pidfile = data / "node.pid"
            port = unused_port()
            args = [str(binary), f"-datadir={data}", "-chain=elementsregtest",
                f"-pid={pidfile}", "-listen=0", "-connect=0", "-dnsseed=0", "-fixedseeds=0",
                "-disablewallet=1", "-drivechainl1blocksync=0", "-validatepegin=0", "-dbcache=16", "-par=1",
                f"-rpcport={port}", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
                "-mainchainrpchost=127.0.0.1", f"-mainchainrpcport={parent.server_port}",
                "-mainchainrpcuser=fixture", "-mainchainrpcpassword=fixture",
                f"-drivechainbmmgrpcaddr=127.0.0.1:{enforcer_port}",
                "-drivechainbmmgrpcauthority=enforcer.local",
                f"-drivechainbmmgrpcca={certs / 'ca.pem'}",
                f"-drivechainbmmgrpccert={certs / 'elements-client.pem'}",
                f"-drivechainbmmgrpckey={certs / 'elements-client-key.pem'}"]
            if mode:
                args.append(mode)

            def rpc(method, params=None):
                cookie = (data / "elementsregtest/.cookie").read_bytes().strip()
                request = urllib.request.Request(f"http://127.0.0.1:{port}/",
                    data=json.dumps({"id": 1, "method": method, "params": params or []}).encode(),
                    headers={"Authorization": "Basic " + base64.b64encode(cookie).decode()})
                try:
                    with urllib.request.urlopen(request, timeout=5) as response:
                        reply = json.load(response)
                except urllib.error.HTTPError as error:
                    reply = json.load(error)
                if reply["error"] is not None and reply["error"].get("code") == -28:
                    raise ValueError("node RPC is still warming up")
                assert reply["error"] is None, reply
                return reply["result"]

            if os.name == "nt":
                check_windows_process(args, rpc, calls, parent.server_port)
                continue

            try:
                started = subprocess.run(args, capture_output=True, text=True, timeout=20)
                logs = "\n".join(path.read_text()[-6000:] for path in data.glob("*/debug.log"))
                assert started.returncode == 0, (started.stdout, started.stderr, logs)
                for _ in range(100):
                    try:
                        assert rpc("getblockcount") == 0
                        break
                    except (OSError, ValueError):
                        time.sleep(0.1)
                else:
                    raise AssertionError("daemon RPC did not become ready")
                before = len(calls)
                result = rpc("getdrivechainpegevents", [0, 1, True])
                assert result["sidechain_id"] == 24, result
                assert calls[before:] == ["GetTwoWayPegData"], calls[before:]
                rpc("stop")
                for _ in range(100):
                    if not pidfile.exists():
                        break
                    time.sleep(0.1)
                assert not pidfile.exists(), "daemon shutdown hung"
                print("PASS", mode, "nested gRPC and clean shutdown", flush=True)
                if mode == "-daemonwait":
                    # A post-fork initialization error must reach the waiting parent.
                    failed = subprocess.run(args + [f"-rpcport={parent.server_port}"],
                        capture_output=True, text=True, timeout=20)
                    assert failed.returncode != 0, "failed daemon initialization reported success"
                    for _ in range(100):
                        if not pidfile.exists():
                            break
                        time.sleep(0.1)
                    assert not pidfile.exists(), "failed daemon did not finish shutdown"
                    print("PASS daemonwait initialization failure propagation", flush=True)
            finally:
                if pidfile.exists():
                    pid = int(pidfile.read_text())
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
    finally:
        parent.shutdown()
        parent.server_close()
        worker.join()
