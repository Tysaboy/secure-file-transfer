#!/usr/bin/env python3
"""
client.py — Secure File Transfer Client (custom TCP protocol)

Interactive client supporting:
- pwd, ls, cd, cat, sha256, download, upload
- smart sync for download/upload using SHA256 (skip if identical)
"""

from __future__ import annotations

import os
import socket
import sys
from pathlib import Path
from typing import Optional

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

def do_handshake(sock: socket.socket, secret: str) -> None:
    line = recv_line(sock)
    if not line.startswith("CHALLENGE "):
        raise RuntimeError("Protocol error: expected CHALLENGE")
    challenge = line.split(" ", 1)[1].strip()
    digest = sha256_bytes((challenge + secret).encode("utf-8"))
    send_line(sock, f"RESPONSE {digest}")
    ok = recv_line(sock)
    if ok != "OK":
        raise RuntimeError(f"Authentication failed: {ok}")

def read_ok_payload(sock: socket.socket) -> list[str]:
    """
    For commands like ls that return OK then multiple lines until sentinel.
    """
    first = recv_line(sock)
    if not first.startswith("OK"):
        raise RuntimeError(first)
    lines: list[str] = []
    while True:
        line = recv_line(sock)
        if line == SENTINEL:
            break
        lines.append(line)
    return lines

def cmd_sha256(sock: socket.socket, remote_path: str) -> Optional[str]:
    send_line(sock, f"sha256 {remote_path}")
    resp = recv_line(sock)
    if resp.startswith("OK "):
        return resp.split(" ", 1)[1].strip()
    return None

def cmd_download(sock: socket.socket, remote_path: str, local_path: Optional[str] = None) -> None:
    # smart sync: compare hashes
    remote_hash = cmd_sha256(sock, remote_path)
    if remote_hash is None:
        print("ERR: remote file not found or sha256 failed")
        return

    lp = Path(local_path if local_path else Path(remote_path).name)
    if lp.exists() and lp.is_file():
        try:
            local_hash = sha256_file(str(lp))
            if local_hash == remote_hash:
                print("[skip] download: local file matches remote (sha256)")
                return
        except Exception:
            pass

    send_line(sock, f"download {remote_path}")
    resp = recv_line(sock)
    if resp != "OK":
        print(resp)
        return

    b64_lines = recv_b64_payload(sock)
    try:
        write_file_from_b64_lines(str(lp), b64_lines)
    except Exception as e:
        print(f"ERR decode_failed: {e}")
        return

    # verify
    try:
        post_hash = sha256_file(str(lp))
        if post_hash != remote_hash:
            print("WARN: sha256 mismatch after download")
        else:
            print(f"OK downloaded -> {lp}")
    except Exception:
        print(f"OK downloaded -> {lp}")

def cmd_upload(sock: socket.socket, local_path: str, remote_name: Optional[str] = None) -> None:
    lp = Path(local_path)
    if not lp.exists() or not lp.is_file():
        print("ERR: local file not found")
        return

    local_hash = sha256_file(str(lp))
    remote_target = remote_name if remote_name else lp.name

    remote_hash = cmd_sha256(sock, remote_target)
    if remote_hash is not None and remote_hash == local_hash:
        print("[skip] upload: remote file matches local (sha256)")
        return

    send_line(sock, f"upload {remote_target}")
    resp = recv_line(sock)
    if not resp.startswith("OK"):
        print(resp)
        return

    send_b64_payload(sock, iter_b64_lines_from_file(str(lp)))
    final = recv_line(sock)
    if final.startswith("OK"):
        print(f"OK uploaded -> {remote_target}")
    else:
        print(final)

def interactive(host: str, port: int) -> None:
    secret = get_secret()
    with socket.create_connection((host, port), timeout=10) as sock:
        do_handshake(sock, secret)
        print("[client] authenticated. Type 'help' for commands, 'exit' to quit.")
        while True:
            try:
                raw = input("sft> ").strip()
            except (EOFError, KeyboardInterrupt):
                raw = "exit"

            if not raw:
                continue
            if raw.lower() in ("exit", "quit"):
                send_line(sock, "exit")
                try:
                    print(recv_line(sock))
                except Exception:
                    pass
                break
            if raw.lower() == "help":
                print("Commands: pwd, ls [opts], cd <dir>, cat <file>, sha256 <file>, download <file> [local], upload <local> [remote]")
                continue

            parts = raw.split(" ", 1)
            cmd = parts[0].lower()
            rest = parts[1] if len(parts) == 2 else ""

            try:
                if cmd in ("pwd",):
                    send_line(sock, "pwd")
                    print(recv_line(sock))

                elif cmd == "cd":
                    send_line(sock, raw)
                    print(recv_line(sock))

                elif cmd == "ls":
                    send_line(sock, raw)
                    lines = read_ok_payload(sock)
                    print("\n".join(lines))

                elif cmd == "sha256":
                    send_line(sock, raw)
                    print(recv_line(sock))

                elif cmd == "cat":
                    send_line(sock, raw)
                    resp = recv_line(sock)
                    if resp != "OK":
                        print(resp)
                        continue
                    b64_lines = recv_b64_payload(sock)
                    # decode to stdout as bytes (best-effort)
                    import base64
                    data = b"".join(base64.b64decode(line.encode("ascii")) for line in b64_lines if line)
                    try:
                        print(data.decode("utf-8", errors="replace"))
                    except Exception:
                        print(data)

                elif cmd == "download":
                    if not rest:
                        print("usage: download <remote_path> [local_path]")
                        continue
                    args = rest.split(" ", 1)
                    remote = args[0]
                    local = args[1].strip() if len(args) == 2 else None
                    cmd_download(sock, remote, local)

                elif cmd == "upload":
                    if not rest:
                        print("usage: upload <local_path> [remote_name]")
                        continue
                    args = rest.split(" ", 1)
                    local = args[0]
                    remote = args[1].strip() if len(args) == 2 else None
                    cmd_upload(sock, local, remote)

                else:
                    # allow raw passthrough for experimentation
                    send_line(sock, raw)
                    print(recv_line(sock))

            except Exception as e:
                print(f"ERR: {e}")

def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <host> <port>")
        raise SystemExit(2)
    host = sys.argv[1]
    port = int(sys.argv[2])
    interactive(host, port)

if __name__ == "__main__":
    main()
