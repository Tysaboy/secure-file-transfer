# Secure File Transfer System (Custom TCP Protocol)

A client--server file transfer system using a custom line-based protocol
over TCP sockets, featuring: - Challenge--response authentication using
SHA256 - Integrity verification (SHA256) and smart sync (skip redundant
transfers) - Remote filesystem commands and Base64 file transfer framing

> Educational project. No TLS. Not secure against advanced MITM.

------------------------------------------------------------------------

## Features

### Authentication (Challenge--Response)

On connect: 1. Server sends a random challenge. 2. Client replies with
sha256(challenge + secret). 3. Server verifies locally and accepts or
rejects.

The secret is never sent over the network, and the per-connection random
challenge mitigates replay attacks.

### Commands

After authentication, the client supports: - pwd - ls \[options\] - cd
`<directory>`{=html} - cat `<file>`{=html} - sha256 `<file>`{=html} -
download `<file>`{=html} - upload `<file>`{=html}

### File Transfer Framing

File contents are Base64-encoded for safe transmission over an ASCII
line-based protocol.

## Transfers end with a sentinel line:

### Smart Sync

Before upload/download: - Compare local and remote SHA256 - Skip
transfer if hashes match - Otherwise transfer and verify integrity

------------------------------------------------------------------------

## Repository Structure

secure-file-transfer/ ├── src/ │ ├── server.py │ ├── client.py │ └──
common.py ├── protocol/ │ └── PROTOCOL.md ├── demo/ │ └── demo.md └──
docs/

------------------------------------------------------------------------

## Run

### Server

``` bash
export SECRET526="your_shared_secret"
python3 src/server.py 22222
```

### Client

``` bash
export SECRET526="your_shared_secret"
python3 src/client.py localhost 22222
```

------------------------------------------------------------------------

## Security Notes

-   Protects the shared secret from being transmitted directly.
-   Random challenge reduces replay attacks.
-   SHA256 used for integrity and sync decisions.
-   No TLS: vulnerable to man-in-the-middle attacks.
-   No perfect forward secrecy.

------------------------------------------------------------------------

## Author

Gildas Yegnon\
University of Calgary\
CompTIA Security+
