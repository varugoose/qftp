"""
QFTP client.

Connects to a QFTP server over QUIC and drives a full session: handshake,
authentication, then either listing the available files or downloading one and
verifying its SHA-256 against the server-supplied checksum.

The protocol logic lives entirely in this client -- the command-line user never
types QFTP message names. They give a host, credentials, and optionally a
filename; the client translates that into the HELLO / AUTH / LIST / FILE_REQUEST
message flow and enforces the DFA on every step.

Two-stream handling
-------------------
All control messages travel on the client-opened bidirectional control stream.
DATA_CHUNK bytes arrive on the server-opened unidirectional data stream. Because
those are different QUIC streams, the small TRANSFER_COMPLETE message can arrive
before the last bulk data chunk. The client therefore defers the
TRANSFER_COMPLETE state transition until every byte has been received, so the
DATA_CHUNK self-loops all occur (validly) before the final transition to READY.

Run via:  make client HOST=localhost FILE=hello.txt USER=bob PASS=bobpass
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import os
import ssl
from typing import Optional

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived

from . import pdu
from .constants import (
    MAX_VERSION,
    MIN_VERSION,
    AuthStatus,
    Capability,
    MsgType,
    State,
)
from .dfa import InvalidTransition, ProtocolStateMachine, Role


class QftpClientProtocol(QuicConnectionProtocol):
    """Per-connection QFTP client logic."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dfa = ProtocolStateMachine(Role.CLIENT)
        self._buffers = {}
        self._seq = 0
        self.control_stream_id: Optional[int] = None
        # All parsed inbound messages land here in arrival order.
        self._inbox: "asyncio.Queue" = asyncio.Queue()

    # ----- send helpers ---------------------------------------------------- #
    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def _send_control(self, message: pdu.Message) -> None:
        if self.control_stream_id is None:
            self.control_stream_id = self._quic.get_next_available_stream_id(
                is_unidirectional=False)
        data = message.encode(self._next_seq(), version=MAX_VERSION)
        self._quic.send_stream_data(self.control_stream_id, data)
        self.transmit()

    # ----- receive --------------------------------------------------------- #
    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, StreamDataReceived):
            buf = self._buffers.setdefault(event.stream_id, pdu.FrameBuffer())
            buf.feed(event.data)
            for header, message in buf.messages():
                self._inbox.put_nowait(message)

    async def _next_message(self) -> pdu.Message:
        return await self._inbox.get()

    # ----- session driver -------------------------------------------------- #
    async def run_session(self, username: str, password: str,
                          filename: Optional[str], out_dir: str,
                          start_offset: int = 0, resume: bool = False) -> int:
        """
        Run one full QFTP session. Returns a process-style exit code
        (0 = success, non-zero = failure).
        """
        # 1. Handshake.
        self.dfa.on_send(MsgType.HELLO)
        self._send_control(pdu.Hello(
            min_version=MIN_VERSION, max_version=MAX_VERSION,
            capabilities=Capability.CAP_RESUME))

        msg = await self._next_message()
        if isinstance(msg, pdu.Error):
            self.dfa.on_recv(MsgType.ERROR)
            print(f"Server refused connection: {msg.message}")
            return 1
        self.dfa.on_recv(MsgType.HELLO_ACK)
        resume_ok = bool(msg.capabilities & Capability.CAP_RESUME)

        # 2. Authenticate (single attempt with the supplied credentials).
        self.dfa.on_send(MsgType.AUTH_REQUEST)
        self._send_control(pdu.AuthRequest(username=username, password=password))
        msg = await self._next_message()
        if isinstance(msg, pdu.Error):
            self.dfa.on_recv(MsgType.ERROR)
            print(f"Error during authentication: {msg.message}")
            return 1
        self.dfa.on_recv(MsgType.AUTH_RESPONSE, auth_status=msg.status,
                         attempts_remaining=msg.attempts_remaining)
        if msg.status != AuthStatus.AUTH_OK:
            print(f"Authentication failed (status={AuthStatus(msg.status).name}).")
            if not self.dfa.is_closed:
                self.dfa.on_send(MsgType.CLOSE)
                self._send_control(pdu.Close())
            return 1
        print(f"Authenticated as {username}.")

        # 3a. No filename -> list the catalog.
        if not filename:
            self.dfa.on_send(MsgType.LIST_REQUEST)
            self._send_control(pdu.ListRequest())
            msg = await self._next_message()
            if isinstance(msg, pdu.Error):
                self.dfa.on_recv(MsgType.ERROR)
                print(f"Error: {msg.message}")
                return 1
            self.dfa.on_recv(MsgType.LIST_RESPONSE)
            print(f"\n{len(msg.entries)} file(s) available:")
            for e in msg.entries:
                print(f"  {e.filename:<30} {e.file_size:>12} bytes")
            self.dfa.on_send(MsgType.CLOSE)
            self._send_control(pdu.Close())
            return 0

        # 3b. Filename -> download it.
        return await self._download(filename, out_dir, start_offset,
                                    resume_ok, resume)

    async def _download(self, filename: str, out_dir: str,
                        start_offset: int, resume_ok: bool,
                        resume: bool) -> int:
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, filename)

        # Decide where to start. An explicit --offset wins; otherwise, if
        # --resume is set and the server negotiated CAP_RESUME and a partial
        # file already exists, continue from its current size.
        effective_offset = start_offset
        if resume and effective_offset == 0:
            if not resume_ok:
                print("Resume requested, but the server did not negotiate "
                      "CAP_RESUME; downloading from the start.")
            elif os.path.exists(out_path):
                effective_offset = os.path.getsize(out_path)
                if effective_offset:
                    print(f"Found {effective_offset} bytes already downloaded; "
                          f"resuming from there.")

        self.dfa.on_send(MsgType.FILE_REQUEST)
        self._send_control(pdu.FileRequest(
            filename=filename, start_offset=effective_offset))

        msg = await self._next_message()
        if isinstance(msg, pdu.Error):
            self.dfa.on_recv(MsgType.ERROR)
            print(f"Could not start download: {msg.message}")
            return 1
        self.dfa.on_recv(MsgType.FILE_METADATA)
        meta = msg
        if effective_offset:
            print(f"Downloading {filename}: {meta.transfer_size} more bytes "
                  f"(total {meta.total_size}).")
        else:
            print(f"Downloading {filename}: {meta.transfer_size} bytes "
                  f"(total {meta.total_size}).")

        # Open keeping existing bytes when resuming, else truncate fresh.
        mode = "r+b" if (effective_offset and os.path.exists(out_path)) else "wb"
        received = 0
        complete: Optional[pdu.TransferComplete] = None

        with open(out_path, mode) as out:
            while True:
                msg = await self._next_message()
                if isinstance(msg, pdu.DataChunk):
                    self.dfa.on_recv(MsgType.DATA_CHUNK)  # self-loop
                    out.seek(msg.offset)
                    out.write(msg.data)
                    received += len(msg.data)
                elif isinstance(msg, pdu.TransferComplete):
                    complete = msg  # defer the transition until data drains
                elif isinstance(msg, pdu.Abort):
                    self.dfa.on_recv(MsgType.ABORT)
                    print("Server aborted the transfer.")
                    return 1
                elif isinstance(msg, pdu.Error):
                    self.dfa.on_recv(MsgType.ERROR)
                    print(f"Transfer error: {msg.message}")
                    return 1
                # Done once we have TRANSFER_COMPLETE and all promised bytes.
                if complete is not None and received >= complete.bytes_sent:
                    self.dfa.on_recv(MsgType.TRANSFER_COMPLETE)
                    break

        # Verify the full file against the server's SHA-256.
        digest = hashlib.sha256()
        with open(out_path, "rb") as f:
            for block in iter(lambda: f.read(1 << 16), b""):
                digest.update(block)
        if digest.digest() == meta.sha256:
            print(f"Download complete: {out_path} (SHA-256 verified).")
            rc = 0
        else:
            print("Download FAILED: checksum mismatch.")
            rc = 1

        self.dfa.on_send(MsgType.CLOSE)
        self._send_control(pdu.Close())
        return rc


async def run_client(host: str, port: int, cert: Optional[str],
                     username: str, password: str, filename: Optional[str],
                     out_dir: str, insecure: bool, start_offset: int,
                     resume: bool) -> int:
    config = QuicConfiguration(is_client=True, alpn_protocols=["qftp"])
    if insecure:
        config.verify_mode = ssl.CERT_NONE
    elif cert:
        config.load_verify_locations(cert)

    async with connect(host, port, configuration=config,
                       create_protocol=QftpClientProtocol) as client:
        return await client.run_session(username, password, filename,
                                        out_dir, start_offset, resume)


def main() -> None:
    parser = argparse.ArgumentParser(description="QFTP client")
    parser.add_argument("--host", default="localhost",
                        help="server hostname or IP")
    parser.add_argument("--port", type=int, default=4433)
    parser.add_argument("--cert", default="certs/cert.pem",
                        help="server certificate to trust")
    parser.add_argument("--insecure", action="store_true",
                        help="skip TLS certificate verification")
    parser.add_argument("--username", default="bob")
    parser.add_argument("--password", default="bobpass")
    parser.add_argument("--file", default=None,
                        help="file to download; omit to list available files")
    parser.add_argument("--out", default="downloads",
                        help="directory to save downloads into")
    parser.add_argument("--offset", type=int, default=0,
                        help="explicit resume byte offset (requires CAP_RESUME)")
    parser.add_argument("--resume", action="store_true",
                        help="auto-resume a partial download in --out")
    args = parser.parse_args()

    rc = asyncio.run(run_client(
        args.host, args.port, args.cert, args.username, args.password,
        args.file, args.out, args.insecure, args.offset, args.resume))
    raise SystemExit(rc)


if __name__ == "__main__":
    main()
