"""
PDU round-trip and wire-size tests.

These tests serve two purposes:

1. Correctness -- every message encodes and decodes back to an equal value.
2. Spec consistency -- the encoded byte sizes are asserted against the
   Section 2.5 "Size Summary" table from the Phase 2 specification. This is the
   automated check that keeps the implementation honest about PDU size math,
   the exact failure mode the design review flagged.

Run with:  make test   (or)   python -m pytest tests/ -v
"""

import os
import sys

# Allow running the tests from the repo root without installing the package.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from qftp import pdu
from qftp.constants import (
    HEADER_SIZE,
    MsgType,
    AuthStatus,
    ErrorCode,
    AbortReason,
    Capability,
    DEFAULT_MAX_CHUNK_SIZE,
)


def _roundtrip(message, sequence=1):
    """Encode a message, decode it back, and return (header, decoded, raw)."""
    raw = message.encode(sequence)
    header, decoded = pdu.decode_message(raw)
    return header, decoded, raw


# --------------------------------------------------------------------------- #
# Header
# --------------------------------------------------------------------------- #
def test_header_round_trip_and_size():
    h = pdu.Header(version=1, msg_type=MsgType.HELLO, sequence=42, payload_len=6)
    packed = h.pack()
    assert len(packed) == HEADER_SIZE
    back = pdu.Header.unpack(packed)
    assert back.version == 1
    assert back.msg_type == MsgType.HELLO
    assert back.sequence == 42
    assert back.payload_len == 6
    assert back.flags == 0


# --------------------------------------------------------------------------- #
# Per-message round trips with exact size assertions (Section 2.5)
# --------------------------------------------------------------------------- #
def test_hello():
    msg = pdu.Hello(min_version=1, max_version=1, capabilities=Capability.CAP_RESUME)
    header, decoded, raw = _roundtrip(msg)
    assert len(raw) == 18                       # spec: 18 bytes
    assert header.msg_type == MsgType.HELLO
    assert decoded == msg


def test_hello_ack():
    msg = pdu.HelloAck(
        agreed_version=1,
        capabilities=Capability.CAP_RESUME,
        max_chunk_size=DEFAULT_MAX_CHUNK_SIZE,
    )
    header, decoded, raw = _roundtrip(msg)
    assert len(raw) == 20                       # spec: 20 bytes
    assert decoded == msg


def test_auth_request():
    msg = pdu.AuthRequest(username="bob", password="bobpass")
    header, decoded, raw = _roundtrip(msg)
    # 12 header + 4 fixed (two u16 length prefixes) + len("bob") + len("bobpass")
    assert len(raw) == 12 + 4 + 3 + 7
    assert decoded == msg


def test_auth_response():
    msg = pdu.AuthResponse(status=AuthStatus.AUTH_OK, attempts_remaining=3)
    header, decoded, raw = _roundtrip(msg)
    assert len(raw) == 16                       # spec: 16 bytes
    assert decoded == msg


def test_list_request():
    msg = pdu.ListRequest()
    header, decoded, raw = _roundtrip(msg)
    assert len(raw) == 12                        # spec: 12 bytes (header only)
    assert decoded == msg


def test_list_response():
    entries = [
        pdu.FileEntry(filename="a.txt", file_size=100, mtime=1_700_000_000),
        pdu.FileEntry(filename="big.bin", file_size=2**40, mtime=1_700_000_500),
    ]
    msg = pdu.ListResponse(entries=entries)
    header, decoded, raw = _roundtrip(msg)
    # 12 header + 4 entry_count + per entry (18 fixed + filename bytes)
    expected = 12 + 4 + (18 + 5) + (18 + 7)
    assert len(raw) == expected
    assert decoded == msg
    assert decoded.entries[1].file_size == 2**40


def test_file_request_with_offset():
    msg = pdu.FileRequest(filename="dataset.csv", start_offset=4096)
    header, decoded, raw = _roundtrip(msg)
    # 12 header + 10 fixed (u64 offset + u16 len) + filename bytes
    assert len(raw) == 12 + 10 + len("dataset.csv")
    assert decoded == msg
    assert decoded.start_offset == 4096


def test_file_metadata():
    digest = bytes(range(32))
    msg = pdu.FileMetadata(
        total_size=10_000,
        transfer_size=5_904,
        modified_time=1_700_000_000,
        sha256=digest,
    )
    header, decoded, raw = _roundtrip(msg)
    assert len(raw) == 68                        # spec: 68 bytes
    assert decoded == msg
    assert decoded.sha256 == digest


def test_data_chunk():
    payload = os.urandom(1024)
    msg = pdu.DataChunk(offset=2048, data=payload)
    header, decoded, raw = _roundtrip(msg)
    # 12 header + 12 fixed (u64 offset + u32 chunk_len) + data
    assert len(raw) == 12 + 12 + len(payload)
    assert decoded == msg
    assert decoded.data == payload


def test_transfer_complete():
    msg = pdu.TransferComplete(bytes_sent=123_456)
    header, decoded, raw = _roundtrip(msg)
    assert len(raw) == 20                        # spec: 20 bytes
    assert decoded == msg


def test_abort():
    msg = pdu.Abort(reason=AbortReason.ABORT_USER_REQUEST)
    header, decoded, raw = _roundtrip(msg)
    assert len(raw) == 16                         # spec: 16 bytes
    assert decoded == msg


def test_error():
    msg = pdu.Error(error_code=ErrorCode.ERR_FILE_NOT_FOUND, message="no such file")
    header, decoded, raw = _roundtrip(msg)
    # 12 header + 4 fixed (u16 code + u16 reserved) + 2 (msg len) + message bytes
    assert len(raw) == 12 + 4 + 2 + len("no such file")
    assert decoded == msg


def test_close():
    msg = pdu.Close()
    header, decoded, raw = _roundtrip(msg)
    assert len(raw) == 12                         # spec: 12 bytes (header only)
    assert decoded == msg


# --------------------------------------------------------------------------- #
# Framing / error handling
# --------------------------------------------------------------------------- #
def test_unicode_strings_round_trip():
    msg = pdu.AuthRequest(username="ryan", password="pa$$wörd_\u00fc")
    _, decoded, _ = _roundtrip(msg)
    assert decoded == msg


def test_truncated_header_raises():
    try:
        pdu.Header.unpack(b"\x01\x02\x03")
        assert False, "expected PDUError"
    except pdu.PDUError:
        pass


def test_incomplete_payload_raises():
    raw = pdu.Hello(min_version=1, max_version=1, capabilities=0).encode(1)
    truncated = raw[:-2]
    try:
        pdu.decode_message(truncated)
        assert False, "expected PDUError"
    except pdu.PDUError:
        pass


def test_unknown_msg_type_raises():
    # Build a header with an out-of-range msg_type (0xEE) and empty payload.
    bad = pdu.Header(version=1, msg_type=0xEE, sequence=1, payload_len=0).pack()
    try:
        pdu.decode_message(bad)
        assert False, "expected PDUError"
    except pdu.PDUError:
        pass


def test_sequence_and_version_preserved():
    raw = pdu.Close().encode(sequence=999, version=1)
    header, _ = pdu.decode_message(raw)
    assert header.sequence == 999
    assert header.version == 1


# --------------------------------------------------------------------------- #
# FrameBuffer: stream reassembly
# --------------------------------------------------------------------------- #
def test_framebuffer_splits_concatenated_messages():
    a = pdu.Hello(min_version=1, max_version=1, capabilities=0).encode(1)
    b = pdu.Close().encode(2)
    c = pdu.AuthRequest(username="bob", password="x").encode(3)
    buf = pdu.FrameBuffer()
    buf.feed(a + b + c)
    msgs = [m for _, m in buf.messages()]
    assert len(msgs) == 3
    assert isinstance(msgs[0], pdu.Hello)
    assert isinstance(msgs[1], pdu.Close)
    assert isinstance(msgs[2], pdu.AuthRequest)


def test_framebuffer_handles_partial_then_completed_message():
    raw = pdu.TransferComplete(bytes_sent=42).encode(7)
    buf = pdu.FrameBuffer()
    buf.feed(raw[:5])                 # only part of the header arrives
    assert [m for _, m in buf.messages()] == []
    buf.feed(raw[5:])                 # the rest arrives
    msgs = [m for _, m in buf.messages()]
    assert len(msgs) == 1
    assert msgs[0].bytes_sent == 42
