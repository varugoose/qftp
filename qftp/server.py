"""
QFTP server.

Implements the server half of QFTP on top of aioquic. Responsibilities:

* Accept QUIC connections (TLS 1.3, ALPN "qftp").
* Speak QFTP on two streams: a client-opened **bidirectional control stream**
  for every message except DATA_CHUNK, and a **server-opened unidirectional
  data stream** that carries DATA_CHUNK bytes during a transfer.
* Enforce the six-state DFA on every message via ``ProtocolStateMachine``.
* Authenticate the client (hardcoded demo credentials), list files, and serve
  files in chunks with a full-file SHA-256 in FILE_METADATA.

Stream-directionality note (implementation feedback to the Phase 2 spec)
------------------------------------------------------------------------
The Phase 2 spec described both streams as "unidirectional, opened by the
client". A client-opened unidirectional stream can only carry client->server
bytes, which cannot work for server replies (HELLO_ACK, DATA_CHUNK, ...).
Implementation resolved this as: the control stream is a client-opened
*bidirectional* stream (both directions), and the data stream is a *server*-
opened unidirectional stream (server->client only, the exact QUIC primitive for
one-way bulk data). This preserves the design's real goal -- separating control
and bulk data onto different streams to avoid head-of-line blocking.

Run via:  make server PORT=4433 FILES=server_files
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import os
import time
from typing import Dict, Optional

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, QuicEvent, StreamDataReceived

from . import pdu
from .constants import (
    MAX_VERSION,
    MIN_VERSION,
    DEFAULT_AUTH_MAX_ATTEMPTS,
    DEFAULT_MAX_CHUNK_SIZE,
    AbortReason,
    AuthStatus,
    Capability,
    ErrorCode,
    MsgType,
    State,
)
from .dfa import InvalidTransition, ProtocolStateMachine, Role

# Hardcoded demo credentials (Section 5.3.1 permits this for the reference
# implementation). A real deployment would use salted password hashes.
CREDENTIALS = {
    "bob": "bobpass",
    "admin": "adminpass",
}

# Capabilities this server supports.
SERVER_CAPABILITIES = Capability.CAP_RESUME


class QftpServerProtocol(QuicConnectionProtocol):
    """Per-connection QFTP server logic. One instance exists per client."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dfa = ProtocolStateMachine(Role.SERVER)
        self._buffers: Dict[int, pdu.FrameBuffer] = {}
        self._seq = 0

        self.control_stream_id: Optional[int] = None
        self.data_stream_id: Optional[int] = None

        # Session state (application bookkeeping, not part of the DFA).
        self.username: Optional[str] = None
        self.attempts_remaining = DEFAULT_AUTH_MAX_ATTEMPTS
        self.negotiated_caps = 0
        self.max_chunk_size = DEFAULT_MAX_CHUNK_SIZE
        self._abort = False  # set when a transfer should stop early

        # Configured at serve() time and attached to each protocol instance.
        self.files_dir: str = getattr(self, "files_dir", "server_files")

    # ----- low-level send helpers ----------------------------------------- #
    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def _send(self, message: pdu.Message, stream_id: int,
              end_stream: bool = False) -> None:
        """Encode and transmit one message on the given stream."""
        data = message.encode(self._next_seq(), version=MAX_VERSION)
        self._quic.send_stream_data(stream_id, data, end_stream)
        self.transmit()

    def _send_control(self, message: pdu.Message) -> None:
        assert self.control_stream_id is not None
        self._send(message, self.control_stream_id)

    def _fail(self, code: int, text: str) -> None:
        """Send an ERROR (which the DFA treats as fatal) and close."""
        try:
            self.dfa.on_send(MsgType.ERROR)
        except InvalidTransition:
            pass
        if self.control_stream_id is not None:
            self._send_control(pdu.Error(error_code=code, message=text))
        self.close()

    # ----- event entry point ---------------------------------------------- #
    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, StreamDataReceived):
            buf = self._buffers.setdefault(event.stream_id, pdu.FrameBuffer())
            buf.feed(event.data)
            try:
                for header, message in buf.messages():
                    self._on_message(event.stream_id, header, message)
            except pdu.PDUError:
                self._fail(ErrorCode.ERR_MALFORMED_MESSAGE,
                           "could not parse message")
        elif isinstance(event, ConnectionTerminated):
            self._abort = True

    # ----- message handling ------------------------------------------------ #
    def _on_message(self, stream_id: int, header: pdu.Header,
                    message: pdu.Message) -> None:
        # The control stream is whichever stream the first HELLO arrives on.
        if self.control_stream_id is None and isinstance(message, pdu.Hello):
            self.control_stream_id = stream_id

        # Validate the transition before acting on the message (Section 3.5).
        try:
            self.dfa.on_recv(message.MSG_TYPE)
        except InvalidTransition:
            self._fail(ErrorCode.ERR_UNEXPECTED_MESSAGE,
                       f"unexpected {MsgType(message.MSG_TYPE).name}")
            return

        if isinstance(message, pdu.Hello):
            self._handle_hello(message)
        elif isinstance(message, pdu.AuthRequest):
            self._handle_auth(message)
        elif isinstance(message, pdu.ListRequest):
            self._handle_list()
        elif isinstance(message, pdu.FileRequest):
            self._handle_file_request(message)
        elif isinstance(message, pdu.Abort):
            self._abort = True  # transfer task will notice and stop
        elif isinstance(message, pdu.Close):
            self.close()
        # ERROR already drove us to CLOSED via the DFA; nothing more to do.

    def _handle_hello(self, msg: pdu.Hello) -> None:
        # Negotiate a version: the highest the server supports within the
        # client's [min, max] range.
        if msg.min_version > MAX_VERSION or msg.max_version < MIN_VERSION:
            self._fail(ErrorCode.ERR_VERSION_MISMATCH, "no common version")
            return
        agreed = min(MAX_VERSION, msg.max_version)
        self.negotiated_caps = msg.capabilities & SERVER_CAPABILITIES

        self.dfa.on_send(MsgType.HELLO_ACK)
        self._send_control(pdu.HelloAck(
            agreed_version=agreed,
            capabilities=self.negotiated_caps,
            max_chunk_size=self.max_chunk_size,
        ))

    def _handle_auth(self, msg: pdu.AuthRequest) -> None:
        ok = CREDENTIALS.get(msg.username) == msg.password
        if ok:
            self.username = msg.username
            self.dfa.on_send(MsgType.AUTH_RESPONSE, auth_status=AuthStatus.AUTH_OK)
            self._send_control(pdu.AuthResponse(
                status=AuthStatus.AUTH_OK,
                attempts_remaining=self.attempts_remaining,
            ))
            return

        self.attempts_remaining -= 1
        if self.attempts_remaining > 0:
            self.dfa.on_send(MsgType.AUTH_RESPONSE,
                             auth_status=AuthStatus.AUTH_BAD_CREDENTIALS,
                             attempts_remaining=self.attempts_remaining)
            self._send_control(pdu.AuthResponse(
                status=AuthStatus.AUTH_BAD_CREDENTIALS,
                attempts_remaining=self.attempts_remaining,
            ))
        else:
            self.dfa.on_send(MsgType.AUTH_RESPONSE,
                             auth_status=AuthStatus.AUTH_LOCKED_OUT,
                             attempts_remaining=0)
            self._send_control(pdu.AuthResponse(
                status=AuthStatus.AUTH_LOCKED_OUT, attempts_remaining=0))
            self.close()

    def _handle_list(self) -> None:
        entries = []
        for name in sorted(os.listdir(self.files_dir)):
            path = os.path.join(self.files_dir, name)
            if os.path.isfile(path):
                st = os.stat(path)
                entries.append(pdu.FileEntry(
                    filename=name, file_size=st.st_size,
                    mtime=int(st.st_mtime)))
        self.dfa.on_send(MsgType.LIST_RESPONSE)
        self._send_control(pdu.ListResponse(entries=entries))

    def _handle_file_request(self, msg: pdu.FileRequest) -> None:
        # Reject path traversal: only plain filenames in the served directory.
        if msg.filename != os.path.basename(msg.filename):
            self._fail(ErrorCode.ERR_PERMISSION_DENIED, "invalid filename")
            return
        path = os.path.join(self.files_dir, msg.filename)
        if not os.path.isfile(path):
            self._fail(ErrorCode.ERR_FILE_NOT_FOUND, "no such file")
            return
        if msg.start_offset and not (self.negotiated_caps & Capability.CAP_RESUME):
            self._fail(ErrorCode.ERR_CAPABILITY_NOT_NEGOTIATED,
                       "resume not negotiated")
            return

        total_size = os.path.getsize(path)
        if msg.start_offset > total_size:
            self._fail(ErrorCode.ERR_OFFSET_OUT_OF_RANGE, "offset past EOF")
            return

        # Kick off the transfer as a background task so we don't block the loop.
        self._abort = False
        asyncio.ensure_future(self._send_file(path, msg.start_offset, total_size))

    async def _send_file(self, path: str, start_offset: int,
                         total_size: int) -> None:
        # Full-file SHA-256 (over the entire file, not just the sent portion).
        digest = hashlib.sha256()
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(1 << 16), b""):
                digest.update(block)
        mtime = int(os.path.getmtime(path))
        transfer_size = total_size - start_offset

        # FILE_METADATA goes on the control stream.
        self.dfa.on_send(MsgType.FILE_METADATA)
        self._send_control(pdu.FileMetadata(
            total_size=total_size,
            transfer_size=transfer_size,
            modified_time=mtime,
            sha256=digest.digest(),
        ))

        # Open the server->client unidirectional data stream for DATA_CHUNK.
        self.data_stream_id = self._quic.get_next_available_stream_id(
            is_unidirectional=True)

        sent = 0
        offset = start_offset
        with open(path, "rb") as f:
            f.seek(start_offset)
            while offset < total_size:
                if self._abort:
                    return  # aborted: DFA already returned to READY on recv ABORT
                chunk = f.read(self.max_chunk_size)
                if not chunk:
                    break
                self.dfa.on_send(MsgType.DATA_CHUNK)
                last = (offset + len(chunk)) >= total_size
                self._send(pdu.DataChunk(offset=offset, data=chunk),
                           self.data_stream_id, end_stream=last)
                offset += len(chunk)
                sent += len(chunk)
                await asyncio.sleep(0)  # yield to the event loop

        # TRANSFER_COMPLETE on the control stream ends the transfer.
        self.dfa.on_send(MsgType.TRANSFER_COMPLETE)
        self._send_control(pdu.TransferComplete(bytes_sent=sent))


async def run_server(host: str, port: int, files_dir: str,
                     cert: str, key: str) -> None:
    config = QuicConfiguration(is_client=False, alpn_protocols=["qftp"])
    config.load_cert_chain(cert, key)

    def create_protocol(*args, **kwargs):
        protocol = QftpServerProtocol(*args, **kwargs)
        protocol.files_dir = files_dir
        return protocol

    await serve(host, port, configuration=config,
                create_protocol=create_protocol)
    print(f"QFTP server listening on {host}:{port}, serving '{files_dir}'")
    await asyncio.Future()  # run forever


def main() -> None:
    parser = argparse.ArgumentParser(description="QFTP server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=4433)
    parser.add_argument("--files", default="server_files")
    parser.add_argument("--cert", default="certs/cert.pem")
    parser.add_argument("--key", default="certs/key.pem")
    args = parser.parse_args()

    try:
        asyncio.run(run_server(args.host, args.port, args.files,
                               args.cert, args.key))
    except KeyboardInterrupt:
        print("\nServer stopped.")


if __name__ == "__main__":
    main()
