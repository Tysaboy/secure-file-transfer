#!/usr/bin/env python3
"""
server.py — Secure File Transfer Server (custom TCP protocol)

Features:
- Challenge–response authentication: sha256(challenge + secret)
- Commands: pwd, ls, cd, cat, sha256, download, upload
- File transfers use Base64 payloads terminated by sentinel '---'
"""

from __future__ import annotations

import os
import secrets as sec
import socket
import threading
import subprocess
import shlex
from pathlib import Path
from typing import Tuple

from common import (
    SENTINEL,
    get_secret,
    recv_line,
    send_line,
    sha256_bytes,
    sha256_file,
    recv_b64_payload,
    send_b64_payload,
    iter_b64_lines_from_file,
    write_file_from_b64_lines,
)

def auth_handshake(conn: socket.socket, secret: str) -> bool:
    challenge = sec.token_hex(16)  # per-connection random
    send_line(conn, f"CHALLENGE {challenge}")
    try:
        resp = recv_line(conn)
    except Exception:
        return False

    if not resp.startswith("RESPONSE "):
        send_line(conn, "ERR expected RESPONSE")
        return False

    client_hex = resp.split(" ", 1)[1].strip()
    expected = sha256_bytes((challenge + secret).encode("utf-8"))
    if client_hex.lower() != expected.lower():
        send_line(conn, "ERR auth_failed")
        return False

    send_line(conn, "OK")
    return True

def safe_join(base: Path, user_path: str) -> Path:
    """
    Minimal path resolution. For a lab assignment we don't sandbox to a root.
    We do normalize to avoid weirdness.
    """
    p = (base / user_path).expanduser()
    return p.resolve()

def handle_client(conn: socket.socket, addr: Tuple[str, int], secret: str) -> None:
    # per-client working directory
    cwd = Path.cwd().resolve()
    try:
        if not auth_handshake(conn, secret):
            conn.close()
            return

        while True:
            try:
                line = recv_line(conn)
            except ConnectionError:
                break
            except Exception as e:
                send_line(conn, f"ERR {type(e).__name__}: {e}")
                continue

            line = line.strip()
            if not line:
                continue
            if line.lower() in ("quit", "exit"):
                send_line(conn, "OK bye")
                break

            # Split into command + rest preserving spaces for filenames
            parts = line.split(" ", 1)
            cmd = parts[0].lower()
            rest = parts[1] if len(parts) == 2 else ""

            try:
                if cmd == "pwd":
                    send_line(conn, f"OK {cwd}")

                elif cmd == "cd":
                    if not rest:
                        send_line(conn, "ERR usage: cd <directory>")
                        continue
                    new_dir = safe_join(cwd, rest)
                    if not new_dir.exists() or not new_dir.is_dir():
                        send_line(conn, "ERR directory_not_found")
                        continue
                    cwd = new_dir
                    send_line(conn, f"OK {cwd}")

                elif cmd == "ls":
                    # For familiarity, we forward to /bin/ls without shell (still a lab).
                    # Allow options like -l -a and optional path.
                    args = []
                    if rest:
                        # Use shlex split so quotes work: ls "My Folder"
                        args = shlex.split(rest)
                    proc = subprocess.run(
                        ["ls", *args],
                        cwd=str(cwd),
                        capture_output=True,
                        text=True,
                    )
                    if proc.returncode != 0:
                        send_line(conn, f"ERR {proc.stderr.strip() or 'ls_failed'}")
                    else:
                        send_line(conn, "OK")
                        # send output as lines + sentinel
                        for out_line in proc.stdout.splitlines():
                            send_line(conn, out_line)
                        send_line(conn, SENTINEL)

                elif cmd == "sha256":
                    if not rest:
                        send_line(conn, "ERR usage: sha256 <file>")
                        continue
                    path = safe_join(cwd, rest)
                    if not path.exists() or not path.is_file():
                        send_line(conn, "ERR file_not_found")
                        continue
                    digest = sha256_file(str(path))
                    send_line(conn, f"OK {digest}")

                elif cmd == "cat":
                    if not rest:
                        send_line(conn, "ERR usage: cat <file>")
                        continue
                    path = safe_join(cwd, rest)
                    if not path.exists() or not path.is_file():
                        send_line(conn, "ERR file_not_found")
                        continue
                    send_line(conn, "OK")
                    # transmit as base64 payload so binary files won't break protocol
                    send_b64_payload(conn, iter_b64_lines_from_file(str(path)))

                elif cmd == "download":
                    if not rest:
                        send_line(conn, "ERR usage: download <file>")
                        continue
                    path = safe_join(cwd, rest)
                    if not path.exists() or not path.is_file():
                        send_line(conn, "ERR file_not_found")
                        continue
                    send_line(conn, "OK")
                    send_b64_payload(conn, iter_b64_lines_from_file(str(path)))

                elif cmd == "upload":
                    if not rest:
                        send_line(conn, "ERR usage: upload <file>")
                        continue
                    # server writes file into cwd; rest is target filename (can include spaces)
                    target = safe_join(cwd, rest)
                    # ensure parent exists
                    if not target.parent.exists():
                        send_line(conn, "ERR invalid_path")
                        # still need to drain payload? For simplicity, we don't request payload.
                        continue

                    send_line(conn, "OK READY")
                    b64_lines = recv_b64_payload(conn)
                    try:
                        write_file_from_b64_lines(str(target), b64_lines)
                    except Exception as e:
                        send_line(conn, f"ERR decode_failed: {e}")
                        continue
                    send_line(conn, "OK uploaded")

                else:
                    send_line(conn, "ERR unknown_command")

            except PermissionError:
                send_line(conn, "ERR permission_denied")
            except Exception as e:
                send_line(conn, f"ERR {type(e).__name__}: {e}")

    finally:
        try:
            conn.close()
        except Exception:
            pass

def main() -> None:
    import sys

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <port>")
        raise SystemExit(2)

    secret = get_secret()

    port = int(sys.argv[1])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(25)
    print(f"[server] listening on 0.0.0.0:{port}")

    try:
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr, secret), daemon=True)
            t.start()
    finally:
        s.close()

if __name__ == "__main__":
    main()
