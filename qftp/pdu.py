"""
QFTP PDU (Protocol Data Unit) definitions: serialization and parsing.

This is the hand-written "kernel" of QFTP. Every byte that crosses the wire is
packed and unpacked here, on top of Python's ``struct`` module. No third-party
library touches message framing, field layout, or parsing -- only QUIC's
transport (handled by aioquic elsewhere) sits underneath.

Wire conventions (Section 2.1)
------------------------------
* All multi-byte integers are big-endian (network byte order).
* Strings are length-prefixed UTF-8 with a 2-byte (u16) length and no NUL
  terminator.
* Timestamps are 64-bit Unix epoch seconds (UTC).
* Checksums are raw 32-byte SHA-256 digests.

Common header (12 bytes, Section 2.2)
-------------------------------------
    version      u8    protocol version
    msg_type     u8    one of MsgType
    flags        u16   reserved in v1 (senders set 0, receivers ignore)
    sequence     u32   monotonically increasing per-endpoint sequence number
    payload_len  u32   number of payload bytes that follow the header

A receiver reads exactly ``HEADER_SIZE + payload_len`` bytes per message.

Usage
-----
Encoding:   ``data = Hello(min_version=1, max_version=1, capabilities=1).encode(seq)``
Decoding:   ``msg = decode_message(data)``  -> a dataclass instance

The encode/decode split keeps each message type self-describing while a single
``decode_message`` entry point handles header parsing and dispatch.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import ClassVar, List, Tuple

from .constants import HEADER_SIZE, MsgType


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #
class PDUError(Exception):
    """Raised when a buffer cannot be parsed into a valid QFTP message."""


# --------------------------------------------------------------------------- #
# Common header
# --------------------------------------------------------------------------- #
# struct format for the 12-byte header: >BBHII
#   >  big-endian
#   B  version (u8)
#   B  msg_type (u8)
#   H  flags (u16)
#   I  sequence (u32)
#   I  payload_len (u32)
_HEADER_FMT = ">BBHII"
assert struct.calcsize(_HEADER_FMT) == HEADER_SIZE


@dataclass
class Header:
    """The 12-byte common header prepended to every QFTP message."""

    version: int
    msg_type: int
    sequence: int
    payload_len: int
    flags: int = 0  # reserved in v1

    def pack(self) -> bytes:
        return struct.pack(
            _HEADER_FMT,
            self.version,
            self.msg_type,
            self.flags,
            self.sequence,
            self.payload_len,
        )

    @classmethod
    def unpack(cls, buf: bytes) -> "Header":
        if len(buf) < HEADER_SIZE:
            raise PDUError(
                f"buffer too short for header: {len(buf)} < {HEADER_SIZE}"
            )
        version, msg_type, flags, sequence, payload_len = struct.unpack(
            _HEADER_FMT, buf[:HEADER_SIZE]
        )
        return cls(
            version=version,
            msg_type=msg_type,
            sequence=sequence,
            payload_len=payload_len,
            flags=flags,
        )


# --------------------------------------------------------------------------- #
# String helper: u16-length-prefixed UTF-8
# --------------------------------------------------------------------------- #
def _pack_string(s: str) -> bytes:
    """Encode a string as u16 length prefix followed by its UTF-8 bytes."""
    raw = s.encode("utf-8")
    if len(raw) > 0xFFFF:
        raise PDUError(f"string too long to encode: {len(raw)} bytes")
    return struct.pack(">H", len(raw)) + raw


def _unpack_string(buf: bytes, offset: int) -> Tuple[str, int]:
    """
    Decode a length-prefixed string starting at ``offset``.

    Returns the decoded string and the offset immediately past it.
    """
    if offset + 2 > len(buf):
        raise PDUError("truncated string length prefix")
    (length,) = struct.unpack_from(">H", buf, offset)
    offset += 2
    if offset + length > len(buf):
        raise PDUError("truncated string body")
    s = buf[offset:offset + length].decode("utf-8")
    return s, offset + length


# --------------------------------------------------------------------------- #
# Base class for messages
# --------------------------------------------------------------------------- #
@dataclass
class Message:
    """
    Base class for all QFTP messages.

    Subclasses set the ``MSG_TYPE`` class variable and implement
    ``_pack_payload`` / ``_unpack_payload``. ``encode`` frames the payload with
    a correct header; ``decode_message`` (module level) dispatches on msg_type.
    """

    MSG_TYPE: ClassVar[int]

    def _pack_payload(self) -> bytes:  # pragma: no cover - overridden
        raise NotImplementedError

    @classmethod
    def _unpack_payload(cls, payload: bytes) -> "Message":  # pragma: no cover
        raise NotImplementedError

    def encode(self, sequence: int, version: int = 1, flags: int = 0) -> bytes:
        """Serialize this message (header + payload) into bytes for the wire."""
        payload = self._pack_payload()
        header = Header(
            version=version,
            msg_type=self.MSG_TYPE,
            sequence=sequence,
            payload_len=len(payload),
            flags=flags,
        )
        return header.pack() + payload


# --------------------------------------------------------------------------- #
# 2.4.1 HELLO (0x01) - Client -> Server        payload: 6 bytes
#   min_version u8, max_version u8, capabilities u16, reserved u16
# --------------------------------------------------------------------------- #
@dataclass
class Hello(Message):
    MSG_TYPE: ClassVar[int] = MsgType.HELLO
    min_version: int
    max_version: int
    capabilities: int

    def _pack_payload(self) -> bytes:
        return struct.pack(
            ">BBHH", self.min_version, self.max_version, self.capabilities, 0
        )

    @classmethod
    def _unpack_payload(cls, payload: bytes) -> "Hello":
        min_v, max_v, caps, _reserved = struct.unpack(">BBHH", payload)
        return cls(min_version=min_v, max_version=max_v, capabilities=caps)


# --------------------------------------------------------------------------- #
# 2.4.2 HELLO_ACK (0x02) - Server -> Client    payload: 8 bytes
#   agreed_version u8, reserved u8, capabilities u16, max_chunk_size u32
# --------------------------------------------------------------------------- #
@dataclass
class HelloAck(Message):
    MSG_TYPE: ClassVar[int] = MsgType.HELLO_ACK
    agreed_version: int
    capabilities: int
    max_chunk_size: int

    def _pack_payload(self) -> bytes:
        return struct.pack(
            ">BBHI", self.agreed_version, 0, self.capabilities, self.max_chunk_size
        )

    @classmethod
    def _unpack_payload(cls, payload: bytes) -> "HelloAck":
        agreed, _reserved, caps, chunk = struct.unpack(">BBHI", payload)
        return cls(agreed_version=agreed, capabilities=caps, max_chunk_size=chunk)


# --------------------------------------------------------------------------- #
# 2.4.3 AUTH_REQUEST (0x03) - Client -> Server   payload: 4+ bytes
#   string(username), string(password)
# --------------------------------------------------------------------------- #
@dataclass
class AuthRequest(Message):
    MSG_TYPE: ClassVar[int] = MsgType.AUTH_REQUEST
    username: str
    password: str

    def _pack_payload(self) -> bytes:
        return _pack_string(self.username) + _pack_string(self.password)

    @classmethod
    def _unpack_payload(cls, payload: bytes) -> "AuthRequest":
        username, off = _unpack_string(payload, 0)
        password, _ = _unpack_string(payload, off)
        return cls(username=username, password=password)


# --------------------------------------------------------------------------- #
# 2.4.4 AUTH_RESPONSE (0x04) - Server -> Client   payload: 4 bytes
#   status u8, attempts_remaining u8, reserved u16
# --------------------------------------------------------------------------- #
@dataclass
class AuthResponse(Message):
    MSG_TYPE: ClassVar[int] = MsgType.AUTH_RESPONSE
    status: int
    attempts_remaining: int

    def _pack_payload(self) -> bytes:
        return struct.pack(">BBH", self.status, self.attempts_remaining, 0)

    @classmethod
    def _unpack_payload(cls, payload: bytes) -> "AuthResponse":
        status, attempts, _reserved = struct.unpack(">BBH", payload)
        return cls(status=status, attempts_remaining=attempts)


# --------------------------------------------------------------------------- #
# 2.4.5 LIST_REQUEST (0x05) - Client -> Server    payload: 0 bytes
# --------------------------------------------------------------------------- #
@dataclass
class ListRequest(Message):
    MSG_TYPE: ClassVar[int] = MsgType.LIST_REQUEST

    def _pack_payload(self) -> bytes:
        return b""

    @classmethod
    def _unpack_payload(cls, payload: bytes) -> "ListRequest":
        return cls()


# --------------------------------------------------------------------------- #
# 2.4.6 LIST_RESPONSE (0x06) - Server -> Client    payload: 4+ bytes
#   entry_count u32, then per entry:
#     file_size u64, mtime u64, string(filename)
# --------------------------------------------------------------------------- #
@dataclass
class FileEntry:
    """A single file in a LIST_RESPONSE catalog."""
    filename: str
    file_size: int
    mtime: int


@dataclass
class ListResponse(Message):
    MSG_TYPE: ClassVar[int] = MsgType.LIST_RESPONSE
    entries: List[FileEntry] = field(default_factory=list)

    def _pack_payload(self) -> bytes:
        out = struct.pack(">I", len(self.entries))
        for e in self.entries:
            out += struct.pack(">QQ", e.file_size, e.mtime)
            out += _pack_string(e.filename)
        return out

    @classmethod
    def _unpack_payload(cls, payload: bytes) -> "ListResponse":
        (count,) = struct.unpack_from(">I", payload, 0)
        offset = 4
        entries: List[FileEntry] = []
        for _ in range(count):
            file_size, mtime = struct.unpack_from(">QQ", payload, offset)
            offset += 16
            filename, offset = _unpack_string(payload, offset)
            entries.append(
                FileEntry(filename=filename, file_size=file_size, mtime=mtime)
            )
        return cls(entries=entries)


# --------------------------------------------------------------------------- #
# 2.4.7 FILE_REQUEST (0x07) - Client -> Server    payload: 10+ bytes
#   start_offset u64, string(filename)
# --------------------------------------------------------------------------- #
@dataclass
class FileRequest(Message):
    MSG_TYPE: ClassVar[int] = MsgType.FILE_REQUEST
    filename: str
    start_offset: int = 0

    def _pack_payload(self) -> bytes:
        return struct.pack(">Q", self.start_offset) + _pack_string(self.filename)

    @classmethod
    def _unpack_payload(cls, payload: bytes) -> "FileRequest":
        (start_offset,) = struct.unpack_from(">Q", payload, 0)
        filename, _ = _unpack_string(payload, 8)
        return cls(filename=filename, start_offset=start_offset)


# --------------------------------------------------------------------------- #
# 2.4.8 FILE_METADATA (0x08) - Server -> Client    payload: 56 bytes
#   total_size u64, transfer_size u64, modified_time u64, sha256 32 bytes
# --------------------------------------------------------------------------- #
@dataclass
class FileMetadata(Message):
    MSG_TYPE: ClassVar[int] = MsgType.FILE_METADATA
    total_size: int        # total file size in bytes
    transfer_size: int     # bytes the server will send (total_size - start_offset)
    modified_time: int     # Unix epoch seconds, UTC
    sha256: bytes          # SHA-256 of the FULL file (not the partial transfer)

    def _pack_payload(self) -> bytes:
        if len(self.sha256) != 32:
            raise PDUError(f"sha256 must be 32 bytes, got {len(self.sha256)}")
        return struct.pack(
            ">QQQ32s",
            self.total_size,
            self.transfer_size,
            self.modified_time,
            self.sha256,
        )

    @classmethod
    def _unpack_payload(cls, payload: bytes) -> "FileMetadata":
        total, transfer, mtime, digest = struct.unpack(">QQQ32s", payload)
        return cls(
            total_size=total,
            transfer_size=transfer,
            modified_time=mtime,
            sha256=digest,
        )


# --------------------------------------------------------------------------- #
# 2.4.9 DATA_CHUNK (0x09) - Server -> Client    payload: 12+ bytes  (DATA STREAM)
#   offset u64, chunk_len u32, data[chunk_len]
# --------------------------------------------------------------------------- #
@dataclass
class DataChunk(Message):
    MSG_TYPE: ClassVar[int] = MsgType.DATA_CHUNK
    offset: int
    data: bytes

    def _pack_payload(self) -> bytes:
        return struct.pack(">QI", self.offset, len(self.data)) + self.data

    @classmethod
    def _unpack_payload(cls, payload: bytes) -> "DataChunk":
        offset, chunk_len = struct.unpack_from(">QI", payload, 0)
        data = payload[12:12 + chunk_len]
        if len(data) != chunk_len:
            raise PDUError(
                f"DATA_CHUNK truncated: declared {chunk_len}, got {len(data)}"
            )
        return cls(offset=offset, data=data)


# --------------------------------------------------------------------------- #
# 2.4.10 TRANSFER_COMPLETE (0x0A) - Server -> Client    payload: 8 bytes
#   bytes_sent u64
# --------------------------------------------------------------------------- #
@dataclass
class TransferComplete(Message):
    MSG_TYPE: ClassVar[int] = MsgType.TRANSFER_COMPLETE
    bytes_sent: int

    def _pack_payload(self) -> bytes:
        return struct.pack(">Q", self.bytes_sent)

    @classmethod
    def _unpack_payload(cls, payload: bytes) -> "TransferComplete":
        (bytes_sent,) = struct.unpack(">Q", payload)
        return cls(bytes_sent=bytes_sent)


# --------------------------------------------------------------------------- #
# 2.4.11 ABORT (0x0B) - Either Direction    payload: 4 bytes
#   reason u8, reserved 3 bytes
# --------------------------------------------------------------------------- #
@dataclass
class Abort(Message):
    MSG_TYPE: ClassVar[int] = MsgType.ABORT
    reason: int

    def _pack_payload(self) -> bytes:
        # reason (1 byte) + 3 reserved bytes set to zero
        return struct.pack(">B3x", self.reason)

    @classmethod
    def _unpack_payload(cls, payload: bytes) -> "Abort":
        (reason,) = struct.unpack(">B3x", payload)
        return cls(reason=reason)


# --------------------------------------------------------------------------- #
# 2.4.12 ERROR (0x0C) - Either Direction    payload: 6+ bytes
#   error_code u16, reserved u16, string(message)
# --------------------------------------------------------------------------- #
@dataclass
class Error(Message):
    MSG_TYPE: ClassVar[int] = MsgType.ERROR
    error_code: int
    message: str = ""

    def _pack_payload(self) -> bytes:
        return struct.pack(">HH", self.error_code, 0) + _pack_string(self.message)

    @classmethod
    def _unpack_payload(cls, payload: bytes) -> "Error":
        error_code, _reserved = struct.unpack_from(">HH", payload, 0)
        message, _ = _unpack_string(payload, 4)
        return cls(error_code=error_code, message=message)


# --------------------------------------------------------------------------- #
# 2.4.13 CLOSE (0x0D) - Either Direction    payload: 0 bytes
# --------------------------------------------------------------------------- #
@dataclass
class Close(Message):
    MSG_TYPE: ClassVar[int] = MsgType.CLOSE

    def _pack_payload(self) -> bytes:
        return b""

    @classmethod
    def _unpack_payload(cls, payload: bytes) -> "Close":
        return cls()


# --------------------------------------------------------------------------- #
# Dispatch table + top-level decode
# --------------------------------------------------------------------------- #
# Maps each message type code to the class that parses its payload.
_DISPATCH = {
    MsgType.HELLO: Hello,
    MsgType.HELLO_ACK: HelloAck,
    MsgType.AUTH_REQUEST: AuthRequest,
    MsgType.AUTH_RESPONSE: AuthResponse,
    MsgType.LIST_REQUEST: ListRequest,
    MsgType.LIST_RESPONSE: ListResponse,
    MsgType.FILE_REQUEST: FileRequest,
    MsgType.FILE_METADATA: FileMetadata,
    MsgType.DATA_CHUNK: DataChunk,
    MsgType.TRANSFER_COMPLETE: TransferComplete,
    MsgType.ABORT: Abort,
    MsgType.ERROR: Error,
    MsgType.CLOSE: Close,
}


def decode_message(buf: bytes) -> Tuple[Header, Message]:
    """
    Parse a complete framed message from ``buf``.

    ``buf`` must contain exactly one message: a 12-byte header followed by
    ``payload_len`` payload bytes. Returns the parsed ``Header`` and the
    corresponding ``Message`` subclass instance.

    Raises ``PDUError`` on any framing or parsing problem, including an
    unrecognized message type (the caller is responsible for turning that into
    an ERROR / ERR_UNEXPECTED_MESSAGE per the DFA rules in Section 3.5).
    """
    header = Header.unpack(buf)
    expected_len = HEADER_SIZE + header.payload_len
    if len(buf) < expected_len:
        raise PDUError(
            f"incomplete message: have {len(buf)} bytes, "
            f"need {expected_len} (payload_len={header.payload_len})"
        )
    payload = buf[HEADER_SIZE:expected_len]

    try:
        msg_type = MsgType(header.msg_type)
    except ValueError:
        raise PDUError(f"unrecognized msg_type 0x{header.msg_type:02X}")

    cls = _DISPATCH[msg_type]
    message = cls._unpack_payload(payload)
    return header, message


# --------------------------------------------------------------------------- #
# Stream framing
# --------------------------------------------------------------------------- #
class FrameBuffer:
    """
    Reassembles a byte stream into complete QFTP messages.

    QUIC delivers stream data as an ordered byte stream, not as discrete
    messages: a single read may contain several messages, a partial message, or
    a message split across reads. ``FrameBuffer`` accumulates incoming bytes and
    yields each complete (header, message) pair as soon as enough bytes for it
    have arrived, leaving any partial trailing message buffered for next time.

    Typical use inside a stream-data event handler::

        buf.feed(event.data)
        for header, message in buf.messages():
            handle(header, message)
    """

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, data: bytes) -> None:
        """Append newly received bytes to the buffer."""
        self._buf.extend(data)

    def messages(self):
        """Yield each complete (Header, Message) currently buffered."""
        while True:
            if len(self._buf) < HEADER_SIZE:
                return
            header = Header.unpack(self._buf)
            total = HEADER_SIZE + header.payload_len
            if len(self._buf) < total:
                return  # wait for the rest of this message
            frame = bytes(self._buf[:total])
            del self._buf[:total]
            yield decode_message(frame)
