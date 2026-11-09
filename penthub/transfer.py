from __future__ import annotations

import base64
import hashlib
import os
import re
import shlex
import time
from collections.abc import Callable

from penthub.listener import Session, drain_socket, recv_until

SHA256_RE = re.compile(r"\b([0-9a-fA-F]{64})\b")
NON_B64_RE = re.compile(r"[^a-zA-Z0-9+/=]")
UNSAFE_WIN_CHARS_RE = re.compile(r'[\r\n&|><^"]')


def quote_posix(path: str) -> str:
    return shlex.quote(path)


def quote_ps_single(path: str) -> str:
    if "\r" in path or "\n" in path:
        raise ValueError("Path cannot contain newline characters")
    return "'" + path.replace("'", "''") + "'"


def validate_win_cmd_path(path: str) -> str:
    if not path or UNSAFE_WIN_CHARS_RE.search(path):
        raise ValueError(f"Unsafe characters in Windows target path: {path!r}")
    return path


def upload_file(
    session: Session,
    local_path: str,
    remote_path: str,
    chunk_size: int = 1000,
    timeout: float = 15.0,
    verify_hash: bool = True,
    on_progress: Callable[[int, int], None] | None = None,
) -> tuple[bool, str]:
    """Upload a local file via chunked Base64 and verify SHA-256 integrity."""
    if not os.path.isfile(local_path):
        return False, f"Local file not found: {local_path}"

    with open(local_path, "rb") as fh:
        raw = fh.read()
    local_sha = hashlib.sha256(raw).hexdigest()
    b64_str = base64.b64encode(raw).decode("ascii")

    with session.io_lock:
        if not session.alive:
            return False, "Session is closed"
        sock = session.conn
        target_os = session.os
        drain_socket(sock, idle_timeout=0.15, total_timeout=0.4)

        try:
            if target_os == "windows":
                safe_remote = validate_win_cmd_path(remote_path)
                b64_remote = f"{safe_remote}.b64"
                sock.sendall(f'del /f /q "{safe_remote}" "{b64_remote}" 2>nul\n'.encode())
            else:
                q_remote = quote_posix(remote_path)
                q_b64 = quote_posix(f"{remote_path}.b64")
                sock.sendall(f"rm -f {q_remote} {q_b64}\n".encode())
            time.sleep(0.2)

            chunks = [b64_str[i : i + chunk_size] for i in range(0, len(b64_str), chunk_size)] or [""]
            total = len(chunks)
            for idx, chunk in enumerate(chunks, start=1):
                if target_os == "windows":
                    if chunk:
                        sock.sendall(f'echo {chunk}>>"{b64_remote}"\n'.encode())
                    else:
                        sock.sendall(f'type nul > "{b64_remote}"\n'.encode())
                else:
                    sock.sendall(f"printf '%s' '{chunk}' >> {q_b64}\n".encode())
                if on_progress:
                    on_progress(idx, total)
                time.sleep(0.01)

            if target_os == "windows":
                decode_cmd = (
                    f'certutil -f -decode "{b64_remote}" "{safe_remote}" >nul && '
                    f'del /f /q "{b64_remote}" && '
                    f'echo __PH_UP_^S__ && certutil -hashfile "{safe_remote}" SHA256 && echo __PH_UP_^E__\n'
                )
            elif target_os == "mac":
                decode_cmd = (
                    f"base64 -D -i {q_b64} -o {q_remote} && rm -f {q_b64} && "
                    f"printf '__PH_UP_''S__\\n' && shasum -a 256 {q_remote} && printf '__PH_UP_''E__\\n'\n"
                )
            else:
                decode_cmd = (
                    f"base64 -d {q_b64} > {q_remote} && rm -f {q_b64} && "
                    f"printf '__PH_UP_''S__\\n' && (sha256sum {q_remote} 2>/dev/null || shasum -a 256 {q_remote} 2>/dev/null || echo NO_HASH) && printf '__PH_UP_''E__\\n'\n"
                )

            sock.sendall(decode_cmd.encode())
            raw_resp, found = recv_until(sock, b"__PH_UP_E__", activity_timeout=timeout)
        except (OSError, ValueError) as exc:
            return False, f"Upload error: {exc}"

    if not found:
        return False, "Upload decode confirmation marker timed out"

    text = raw_resp.decode(errors="ignore")
    block = text.rsplit("__PH_UP_S__", 1)[-1].split("__PH_UP_E__", 1)[0] if "__PH_UP_S__" in text else text
    if verify_hash:
        match = SHA256_RE.search(block)
        if match:
            remote_sha = match.group(1).lower()
            if remote_sha != local_sha:
                return False, f"SHA-256 mismatch! local={local_sha} remote={remote_sha}"
            return True, f"Uploaded {len(raw)} bytes (SHA-256 verified: {local_sha[:16]}...)"
        if "NO_HASH" in block:
            return True, f"Uploaded {len(raw)} bytes (sha256 tool unavailable on target; local={local_sha[:16]}...)"
        return False, f"Remote hash missing in response: {block.strip()}"
    return True, f"Uploaded {len(raw)} bytes (local SHA-256: {local_sha[:16]}...)"


def download_file(
    session: Session,
    remote_path: str,
    local_save_path: str,
    timeout: float = 30.0,
    on_bytes: Callable[[int], None] | None = None,
) -> tuple[bool, str]:
    """Download a remote file via framed Base64 stream and compute SHA-256."""
    start_marker = "---START_B64---"
    end_marker = "---END_B64---"

    with session.io_lock:
        if not session.alive:
            return False, "Session is closed"
        sock = session.conn
        target_os = session.os
        drain_socket(sock, idle_timeout=0.15, total_timeout=0.4)

        try:
            if target_os == "windows":
                ps_path = quote_ps_single(remote_path)
                ps_cmd = f"$b=[System.IO.File]::ReadAllBytes({ps_path});[System.Convert]::ToBase64String($b)"
                cmd = f'echo ---START_^B64--- && powershell -NoP -Command "{ps_cmd}" && echo ---END_^B64---\n'
            elif target_os == "mac":
                q_remote = quote_posix(remote_path)
                cmd = f"printf '\\n---START_''B64---\\n'; base64 -i {q_remote}; printf '\\n---END_''B64---\\n'\n"
            else:
                q_remote = quote_posix(remote_path)
                cmd = f"printf '\\n---START_''B64---\\n'; (base64 -w0 {q_remote} 2>/dev/null || base64 {q_remote}); printf '\\n---END_''B64---\\n'\n"

            sock.sendall(cmd.encode())
            raw_resp, found = recv_until(
                sock,
                end_marker.encode("ascii"),
                activity_timeout=timeout,
                on_chunk=on_bytes,
            )
        except (OSError, ValueError) as exc:
            return False, f"Download error: {exc}"

    full_text = raw_resp.decode(errors="ignore")
    if not found or start_marker not in full_text or end_marker not in full_text:
        return False, "Incomplete transfer: framing markers not received before timeout"

    raw_b64 = full_text.rsplit(start_marker, 1)[-1].split(end_marker, 1)[0]
    clean_b64 = NON_B64_RE.sub("", raw_b64)
    try:
        data = base64.b64decode(clean_b64, validate=True)
    except Exception as exc:
        return False, f"Base64 decode failed: {exc}"

    parent = os.path.dirname(os.path.abspath(local_save_path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(local_save_path, "wb") as fh:
        fh.write(data)
    sha = hashlib.sha256(data).hexdigest()
    return True, f"Saved {local_save_path} ({len(data)} bytes, SHA-256: {sha[:16]}...)"
