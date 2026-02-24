#!/usr/bin/env python3
"""
common.py — shared helpers for Secure File Transfer (custom TCP line protocol)

Protocol summary (high level):
- Lines are UTF-8 text terminated by '\n'
- File payloads are transmitted as Base64 lines and terminated by a sentinel line: ---
"""

from __future__ import annotations

import base64
import hashlib
import os
import socket
from typing import Iterable, Optional

SENTINEL = "---"

def get_secret(env_var: str = "SECRET526") -> str:
    secret = os.environ.get(env_var)
    if not secret:
        raise RuntimeError(f"{env_var} is not set. Example: export {env_var}='my_secret'")
    return secret

def sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()

def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def send_line(sock: socket.socket, line: str) -> None:
    if "\n" in line:
        # Keep protocol framing simple: one logical message per line.
        line = line.replace("\n", "\\n")
    sock.sendall((line + "\n").encode("utf-8"))

def recv_line(sock: socket.socket, max_bytes: int = 1024 * 1024) -> str:
    """
    Read until '\n'. This is intentionally simple for a lab protocol.
    """
    buf = bytearray()
    while True:
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("Connection closed")
        buf += chunk
        if buf.endswith(b"\n"):
            break
        if len(buf) > max_bytes:
            raise ValueError("Line too long")
    return buf[:-1].decode("utf-8", errors="replace")

def iter_b64_lines_from_file(path: str, line_len: int = 76) -> Iterable[str]:
    """
    Stream file as base64 text lines. Avoid loading full file into memory.
    """
    # We'll encode in chunks then wrap at fixed length.
    enc = base64.b64encode
    with open(path, "rb") as f:
        pending = b""
        while True:
            data = f.read(57 * 1024)  # multiple of 3-ish; not required
            if not data:
                break
            pending += data
            # Encode pending; but to avoid re-encoding everything, encode this chunk directly.
            b64 = enc(pending).decode("ascii")
            pending = b""
            for i in range(0, len(b64), line_len):
                yield b64[i:i+line_len]
    if pending:
        b64 = enc(pending).decode("ascii")
        for i in range(0, len(b64), line_len):
            yield b64[i:i+line_len]

def write_file_from_b64_lines(path: str, lines: Iterable[str]) -> None:
    """
    Decode base64 lines into a file.
    """
    # Collect and decode incrementally.
    decoder = base64.b64decode
    with open(path, "wb") as f:
        for line in lines:
            if not line:
                continue
            f.write(decoder(line.encode("ascii"), validate=True))

def recv_b64_payload(sock: socket.socket) -> list[str]:
    """
    Receive Base64 lines until SENTINEL. Returns the list of lines.
    """
    out: list[str] = []
    while True:
        line = recv_line(sock)
        if line == SENTINEL:
            break
        out.append(line)
    return out

def send_b64_payload(sock: socket.socket, b64_lines: Iterable[str]) -> None:
    for line in b64_lines:
        send_line(sock, line)
    send_line(sock, SENTINEL)
