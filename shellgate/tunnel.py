from __future__ import annotations

import re
import shutil
import socket
import subprocess
import threading
import time

ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
PINGGY_URL_RE = re.compile(r"tcp://([a-zA-Z0-9.-]+):([0-9]+)")


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def detect_local_ip(iface: str | None = None) -> str:
    """Detect the preferred local/VPN IPv4 address for reverse-shell callbacks."""
    candidates = [iface] if iface else ["tun0", "tap0", "eth1", "eth0", "tailscale0"]
    if shutil.which("ip"):
        for dev in candidates:
            if not dev:
                continue
            try:
                out = subprocess.check_output(
                    ["ip", "-4", "-o", "addr", "show", dev],
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=2,
                )
                m = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/", out)
                if m:
                    return m.group(1)
            except (subprocess.SubprocessError, OSError):
                continue

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            ip = s.getsockname()[0]
            if ip and not ip.startswith("127."):
                return ip
    except OSError:
        pass
    return "127.0.0.1"


class TunnelManager:
    """Manages callback endpoint resolution via local interface or Pinggy SSH TCP tunnel."""

    def __init__(self, local_port: int, mode: str = "local", iface: str | None = None, host_override: str | None = None):
        if mode not in ("local", "pinggy"):
            raise ValueError(f"Unsupported tunnel mode: {mode}")
        self.local_port = local_port
        self.mode = mode
        self.iface = iface
        self.host_override = host_override
        self.host: str | None = None
        self.port: int | None = None
        self.error: str | None = None
        self._proc: subprocess.Popen[str] | None = None
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str | None:
        if self.host and self.port:
            return f"tcp://{self.host}:{self.port}"
        return None

    def start(self, wait_seconds: float = 0.0) -> None:
        if self.mode == "local":
            self.host = self.host_override or detect_local_ip(self.iface)
            self.port = self.local_port
            return

        if not shutil.which("ssh"):
            self.error = "'ssh' binary not found in PATH"
            return

        self._thread = threading.Thread(target=self._run_pinggy, daemon=True)
        self._thread.start()
        if wait_seconds > 0:
            deadline = time.monotonic() + wait_seconds
            while time.monotonic() < deadline and not self.url and not self.error and not self._stop_event.is_set():
                time.sleep(0.1)

    def _run_pinggy(self) -> None:
        cmd = [
            "ssh",
            "-p",
            "443",
            f"-R0:localhost:{self.local_port}",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ServerAliveInterval=30",
            "-o",
            "ConnectTimeout=10",
            "-T",
            "tcp@free.pinggy.io",
        ]
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            assert self._proc.stdout is not None
            while not self._stop_event.is_set():
                line = self._proc.stdout.readline()
                if not line:
                    break
                clean = strip_ansi(line).strip()
                if not self.host:
                    m = PINGGY_URL_RE.search(clean)
                    if m:
                        self.host = m.group(1)
                        self.port = int(m.group(2))
        except OSError as exc:
            self.error = str(exc)

    def stop(self) -> None:
        self._stop_event.set()
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()
