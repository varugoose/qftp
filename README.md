# QFTP — QUIC File Transfer Protocol (Phase 3 Implementation)

CS 544 Computer Networks — Term Project Part 3
Ryan Varughese — Professor Brian Mitchell

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

## What Implementation Taught Me About the Design

Software design is a feedback loop: building the protocol surfaced gaps and
ambiguities in the Phase 2 specification that were not visible on paper. This
section documents the design changes the implementation forced, and the
decisions it validated.

### 1. Stream directionality: the data stream cannot be client-opened

The Phase 2 spec described QFTP as running over *two unidirectional streams,
both opened by the client* — one for control, one for data. Implementing this
immediately exposed a contradiction: a client-opened unidirectional QUIC stream
can only carry bytes from client to server, yet almost every QFTP reply travels
server-to-client (HELLO_ACK, AUTH_RESPONSE, FILE_METADATA, and every
DATA_CHUNK). With both streams unidirectional and client-owned, the server would
have had no way to answer.

The implementation resolves this with two changes:

* The **control stream is a client-opened *bidirectional* stream.** Control is
  inherently a two-way conversation (request/response), so a bidirectional
  stream is the natural fit, and the client still initiates it by sending HELLO.
* The **data stream is a *server-opened* unidirectional stream.** Bulk file data
  only ever flows server-to-client, which is exactly what a server-initiated
  unidirectional stream expresses. The server opens it when a transfer begins.

This preserves the design's real intent — keeping bulk data off the control
stream so a long transfer cannot head-of-line-block control messages — while
correcting the ownership/direction model to something QUIC can actually express.
Phase 2's "two streams, control vs. data" idea was sound; only the directionality
labels were wrong.

### 2. TRANSFER_COMPLETE is bounded by byte count, not message arrival

The Phase 2 DFA treats `TRANSFERRING --recv TRANSFER_COMPLETE--> READY` as a
clean transition, implicitly assuming TRANSFER_COMPLETE is the last thing the
client sees. Once control and data live on *separate* QUIC streams (see #1),
that assumption breaks: QUIC multiplexes streams independently, so the small
TRANSFER_COMPLETE message on the control stream can arrive *before* the final
bulk DATA_CHUNK on the data stream. A literal DFA would move to READY on
TRANSFER_COMPLETE and then reject the late DATA_CHUNK as an illegal transition.

The fix is a small but important refinement to the protocol's completion
semantics: **the end of a transfer is defined by having received all promised
bytes, not by the arrival of the TRANSFER_COMPLETE message.** The client buffers
the TRANSFER_COMPLETE and defers the state transition until its received byte
count reaches the `bytes_sent` value the message carried. All DATA_CHUNK
self-loops therefore occur (validly) while still in TRANSFERRING, and the single
transition to READY fires last. The `bytes_sent` field in TRANSFER_COMPLETE,
which looked redundant in Phase 2 (the client could already count bytes), turns
out to be exactly the value needed to make this robust.

### 3. Keeping enum values in lockstep with the spec

While writing `constants.py`, I reconciled the AuthStatus, ErrorCode, and
AbortReason enums against the figures in Phase 2 Sections 2.4.4, 2.4.12, and
2.4.11. This caught a discrepancy in the error-code set: the ordering and the
use of `ERR_INTERNAL = 0x00FF` as a high-valued sentinel (rather than the next
sequential value) had to be reflected exactly in code. Minor on its own, but a
concrete reminder that the wire-level constants are part of the contract — a
client and server that disagree on a single integer will misinterpret every
error.

### 4. Decisions the implementation validated

Not every lesson was a correction. Two Phase 2 choices proved their worth:

* **The 12-byte header with an explicit `payload_len`.** QUIC delivers a stream
  as an undifferentiated sequence of bytes, so the receiver must re-frame
  individual messages itself. The `payload_len` field makes this trivial — read
  the header, read exactly that many more bytes — and is the foundation of the
  `FrameBuffer` reassembly logic. A delimiter-based design would have been far
  more fragile.
* **Splitting HANDSHAKING and AUTHENTICATING into distinct states.** Keeping the
  version handshake separate from the credential exchange kept both the server
  and client transition logic clean; the auth-retry loop lives entirely within
  AUTHENTICATING without ever entangling version negotiation.

---

## Where to Find Each Requirement

- **Kernel:** `aioquic` supplies QUIC only. All QFTP framing, serialization,
  parsing, and state logic in `qftp/` is original.
- **DFA enforcement** is implemented on both the client and the server.
- Enum *values* for auth status, error, and abort codes in `qftp/constants.py`
  have been verified against the Phase 2 enum figures (Sections 2.4.4, 2.4.12,
  2.4.11).
