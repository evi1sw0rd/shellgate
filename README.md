# ShellGate

**ShellGate** is a zero-dependency Python 3 multi-session reverse-shell listener, tunnel gate, and integrity-verified file transfer hub built for authorized penetration testing, Red Team engagements, and CTF labs (Hack The Box, OSCP).

## Key Features

- **Zero External Dependencies:** Pure Python 3.10+ standard library (`socket`, `select`, `threading`, `http.server`, `hashlib`, `base64`, `shlex`).
- **Dual Endpoint Modes:**
  - `--mode local`: Auto-detects VPN/interface IP (`tun0`, `tap0`, `eth1`, `eth0`, `tailscale0`) or uses `--iface` / `--host`.
  - `--mode pinggy`: Automatically establishes an SSH TCP reverse tunnel (`tcp@free.pinggy.io:443`) with clean teardown on exit.
- **Race-Free Session Fingerprinting:** Marker-framed OS (`linux`, `mac`, `windows`), user, and hostname detection protected by per-session `threading.Lock`.
- **Integrity-Verified File Transfer:**
  - `:upload <local> <remote>`: Chunked Base64 upload with OS-aware command quoting (`shlex.quote` on POSIX, validated paths on Windows) and automatic **SHA-256 verification** on target.
  - `:download <remote> <local>`: Framed Base64 stream download with activity timeout, whitespace sanitization, and local SHA-256 computation.
- **Cross-Platform Payload Generator:** Generates Bash TCP, `sh`/`mkfifo`, Python 3 PTY, traditional `nc`, UTF-16LE Base64-encoded PowerShell, and optional HTTP staging one-liners.
- **Optional Python 3.13+ HTTP Staging Server (`--http-port`):** Serves local tools from `--srv-dir` and accepts multipart file uploads (`email.parser.BytesParser`, no deprecated `cgi`) with `os.path.basename` path-traversal sanitization.

## Installation

```bash
# Editable install (recommended for Kali / dev)
pip install -e . --break-system-packages

# Or run directly without installing
python3 -m shellgate --help
```

## Usage

```bash
# HTB / VPN local listener on tun0:8888
shellgate --mode local --iface tun0 --port 8888

# Public callback via Pinggy SSH tunnel
shellgate --mode pinggy --port 8888

# Local listener + HTTP staging server on port 8080 serving ./srv
shellgate --mode local --port 8888 --http-port 8080 --srv-dir ./srv
```

### Interactive Session Commands

| Command | Description |
| :--- | :--- |
| `:upload <local> <remote>` | Upload file via Base64 chunks and verify remote SHA-256 |
| `:download <remote> <local>` | Download file via framed Base64 stream |
| `:pty` | Send Python 3 / `script` PTY stabilization command (POSIX) |
| `:check` | Run quick host triage (`id; uname -a; ip a` / `whoami & ipconfig`) |
| `:info` | Print session metadata |
| `:rename <alias>` | Assign a friendly alias to the session |
| `:kill` | Close the active session |
| `:back` | Return to the main menu |

## Running Tests

```bash
python3 -m unittest discover -s tests -v
```

## Disclaimer

For **authorized security testing, education, and CTF lab use only**. Always obtain explicit written permission before testing any system you do not own.
