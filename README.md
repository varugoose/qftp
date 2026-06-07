# QFTP — QUIC File Transfer Protocol (Part 3 Implementation)

QFTP is a stateful, download-only, authenticated, resumable file-transfer
protocol that runs on top of QUIC (RFC 9000). This repository is the Phase 3
reference implementation of the protocol specified in Phase 2: a command-line
**server** and **client** that speak QFTP over a QUIC connection.

The QUIC transport (handshake, TLS 1.3, stream multiplexing, loss recovery) is
provided by the third-party `aioquic` library. Everything that defines QFTP —
the 12-byte common header, all 13 message types, message serialization and
parsing, and the six-state protocol DFA — is hand-written and lives in the
`qftp/` package. No third-party code touches the "kernel" of the protocol.

---

## Requirements

- Python 3.10+
- A Linux-based environment (tested on **WSL2 / Ubuntu**)
- `openssl` on the PATH (for generating a local TLS certificate)

All Python dependencies are installed into a local virtualenv by `make install`.

---

## Build and Run

The project is driven entirely through the `Makefile`:

```bash
make install      # create .venv and install aioquic + pytest
make certs        # generate a self-signed TLS cert for the server
make server       # start the server (terminal 1)
make client FILE=<filename>   # run the client (terminal 2)
make test         # run the PDU / DFA unit tests
make clean        # tear everything down
```

### Server

```bash
make server PORT=4433 FILES=server_files
```

The server serves files from the `FILES` directory (default `server_files/`).

### Client

```bash
make client HOST=127.0.0.1 PORT=4433 QUSER=bob QPASS=bobpass FILE=hello.txt
```

Run the client with no `FILE` to list the available files instead of
downloading one.

To resume an interrupted download, re-run the same command with `RESUME=1`:

```bash
make client FILE=sample.bin RESUME=1
```

If a partial copy of the file already exists in the download directory, the
client reports how many bytes it already has, requests only the remaining bytes
from that offset (using the negotiated `CAP_RESUME` capability), reassembles the
file, and verifies the full-file SHA-256.

---

## Configuration

Per the assignment, no connection configuration is hard-coded into the program
logic; it is supplied via command-line arguments (wired through the Makefile
variables above).

| Setting | Where | Default |
|---|---|---|
| Server **port** | hard-coded default, overridable via `--port` | **4433** |
| Server hostname/IP (client side) | `--host` | `127.0.0.1` |
| Served-files directory (server side) | `--files` | `server_files` |
| Username / password (client side) | `QUSER` / `QPASS` (`--username` / `--password`) | `bob` / `bobpass` |

**Hardcoded port:** the server binds to port **4433** by default and the client
defaults to the same value, as required by the assignment. Both can be
overridden on the command line for flexibility.

---

## Protocol State Machine (DFA)

Both endpoints implement and enforce the six-state QFTP DFA from Phase 2:

```
INIT -> HANDSHAKING -> AUTHENTICATING -> READY <-> TRANSFERRING
                                           |
                                           +-> CLOSED  (CLOSE or ERROR from any state)
```

Any message received in a state where it is not valid causes the receiver to
send an `ERROR` (`ERR_UNEXPECTED_MESSAGE`) and transition to `CLOSED`, closing
both QUIC streams and the connection (Section 3.5 of the Phase 2 spec).

Two unidirectional QUIC streams are used: a **control stream** for all messages
except `DATA_CHUNK`, and a **data stream** that carries only `DATA_CHUNK`
messages during an active transfer.

---

## Project Layout

```
qftp-impl/
├── Makefile             # build / run / test entry point
├── requirements.txt     # aioquic, pytest
├── README.md            # this file
├── qftp/                # the protocol implementation (hand-written kernel)
│   ├── constants.py     # version, message types, states, status/error codes
│   ├── pdu.py           # serialize/deserialize the header + all 13 PDUs
│   ├── dfa.py           # state machine + transition enforcement
│   ├── server.py        # QFTP server over aioquic
│   └── client.py        # QFTP client over aioquic
├── tests/
│   ├── test_pdu.py      # round-trip + wire-size tests (21 tests)
│   └── test_dfa.py      # state-machine transition tests (17 tests)
├── integration_test.py  # in-process end-to-end client/server test
└── server_files/        # sample files the server offers
```

---

## Implementation Status

- [x] Project scaffold, Makefile, dependency setup
- [x] Common header + all 13 PDUs (`qftp/pdu.py`)
- [x] PDU unit tests — round-trip + Section 2.5 size verification (21 passing)
- [x] DFA state machine and transition enforcement (`qftp/dfa.py`, 17 tests)
- [x] Server: QUIC setup, two-stream handling, auth, listing, chunked transfer
- [x] Client: QUIC connect, auth, listing, download, SHA-256 verification
- [x] End-to-end integration test (list, download, auth failure, missing file)
- [x] Resumable transfers via `start_offset` / `CAP_RESUME` (auto-resume of a
      partial download; verified end-to-end)

---

## Notes for Grading

- **Kernel:** `aioquic` supplies QUIC only. All QFTP framing, serialization,
  parsing, and state logic in `qftp/` is original.
- **DFA enforcement** is implemented on both the client and the server.
- Enum *values* for auth status, error, and abort codes in `qftp/constants.py`
  have been verified against the Phase 2 enum figures (Sections 2.4.4, 2.4.12,
  2.4.11).
