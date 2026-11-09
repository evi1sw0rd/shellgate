from __future__ import annotations

import functools
import http.server
import os
import threading
from email.parser import BytesParser
from email.policy import default


class _StagingHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def do_POST(self) -> None:
        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            self.send_error(400, "Expected multipart/form-data")
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400, "Invalid Content-Length")
            return
        if length <= 0 or length > 100 * 1024 * 1024:
            self.send_error(400, "Invalid or oversized body")
            return

        body = self.rfile.read(length)
        raw_msg = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode() + body
        msg = BytesParser(policy=default).parsebytes(raw_msg)
        if not msg.is_multipart():
            self.send_error(400, "Invalid multipart payload")
            return

        upload_dir = os.path.join(self.directory, "uploads")
        os.makedirs(upload_dir, exist_ok=True)
        saved: list[str] = []

        for part in msg.iter_parts():
            filename = part.get_filename()
            if not filename:
                continue
            safe_name = os.path.basename(filename)
            if not safe_name or safe_name in (".", ".."):
                continue
            payload = part.get_payload(decode=True) or b""
            dest = os.path.join(upload_dir, safe_name)
            with open(dest, "wb") as fh:
                fh.write(payload)
            saved.append(safe_name)

        if not saved:
            self.send_error(400, "No valid file parts found")
            return

        self.send_response(200)
        self.end_headers()
        self.wfile.write((f"Uploaded: {', '.join(saved)}\n").encode())


class StagingServer:
    """Optional Python 3.13+ safe HTTP staging server for payload/tool delivery."""

    def __init__(self, directory: str = "./srv", bind_host: str = "0.0.0.0", port: int = 8080):
        self.directory = os.path.abspath(directory)
        self.bind_host = bind_host
        self.port = port
        self._httpd: http.server.ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> int:
        os.makedirs(self.directory, exist_ok=True)
        handler = functools.partial(_StagingHandler, directory=self.directory)
        self._httpd = http.server.ThreadingHTTPServer((self.bind_host, self.port), handler)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self.port

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
