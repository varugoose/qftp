"""
QFTP protocol constants.

This module centralizes every magic number defined by the QFTP wire protocol:
the protocol version, message type codes, capability bits, DFA states, and the
enumerations carried inside individual PDUs (auth status, error codes, abort
reasons).

NOTE ON ENUM VALUES
-------------------
The numeric values for AuthStatus, ErrorCode, and AbortReason below have been
verified against the enum figures in the QFTP Phase 2 specification (Sections
2.4.4, 2.4.12, and 2.4.11 respectively). The wire format itself is independent
of these values -- the PDU layer simply packs whatever value is in the field --
but keeping these in sync with the written spec ensures the implementation and
the design document tell the same story.
"""

from enum import IntEnum


# --------------------------------------------------------------------------- #
# Protocol version
# --------------------------------------------------------------------------- #
# v1 of QFTP. Advertised as a [min_version, max_version] range in HELLO and
# echoed as the agreed version in HELLO_ACK.
PROTOCOL_VERSION = 1
MIN_VERSION = 1
MAX_VERSION = 1


# --------------------------------------------------------------------------- #
# Message type codes (8-bit msg_type field in the common header)
# --------------------------------------------------------------------------- #
# Codes 0x01-0x0D are allocated by v1. 0x0E-0xFF are reserved for future
# message types (Section 4.5).
class MsgType(IntEnum):
    HELLO = 0x01              # Client -> Server  : open session, advertise caps
    HELLO_ACK = 0x02          # Server -> Client  : confirm session, agreed caps
    AUTH_REQUEST = 0x03       # Client -> Server  : submit credentials
    AUTH_RESPONSE = 0x04      # Server -> Client  : auth result
    LIST_REQUEST = 0x05       # Client -> Server  : ask for file catalog
    LIST_RESPONSE = 0x06      # Server -> Client  : file catalog
    FILE_REQUEST = 0x07       # Client -> Server  : request a file (opt. offset)
    FILE_METADATA = 0x08      # Server -> Client  : size + checksum before xfer
    DATA_CHUNK = 0x09         # Server -> Client  : a slice of file bytes (DATA)
    TRANSFER_COMPLETE = 0x0A  # Server -> Client  : end of a successful transfer
    ABORT = 0x0B              # Either            : cancel in-progress transfer
    ERROR = 0x0C              # Either            : fatal error, connection ends
    CLOSE = 0x0D              # Either            : graceful session shutdown


# --------------------------------------------------------------------------- #
# Capability flags (16-bit bitmap in HELLO / HELLO_ACK)
# --------------------------------------------------------------------------- #
# Negotiated by bitwise-AND of client and server advertised capabilities.
class Capability(IntEnum):
    CAP_RESUME = 0x0001       # resumable downloads via non-zero start_offset
    # 0x0002 - 0x8000 reserved (CAP_COMPRESSION, CAP_PER_CHUNK_INTEGRITY, ...)


# --------------------------------------------------------------------------- #
# DFA states (Section 3.1)
# --------------------------------------------------------------------------- #
# Each endpoint maintains its own state. HANDSHAKING and AUTHENTICATING are kept
# deliberately distinct rather than collapsed, to avoid conflating the version
# handshake with the credential exchange.
class State(IntEnum):
    INIT = 0
    HANDSHAKING = 1
    AUTHENTICATING = 2
    READY = 3
    TRANSFERRING = 4
    CLOSED = 5


# --------------------------------------------------------------------------- #
# Authentication status (status field of AUTH_RESPONSE)
# --------------------------------------------------------------------------- #
class AuthStatus(IntEnum):
    AUTH_OK = 0x00              # credentials accepted
    AUTH_BAD_CREDENTIALS = 0x01  # wrong user/pass; attempts_remaining > 0 -> retry
    AUTH_LOCKED_OUT = 0x02       # retry limit exhausted; attempts_remaining == 0
    AUTH_SERVER_ERROR = 0x03     # server-side failure verifying credentials


# --------------------------------------------------------------------------- #
# Error codes (16-bit error_code field of ERROR)
# --------------------------------------------------------------------------- #
class ErrorCode(IntEnum):
    ERR_VERSION_MISMATCH = 0x0001           # no mutually supported version
    ERR_MALFORMED_MESSAGE = 0x0002          # could not parse a received PDU
    ERR_UNEXPECTED_MESSAGE = 0x0003         # message invalid for current DFA state
    ERR_CAPABILITY_NOT_NEGOTIATED = 0x0004  # used a feature that wasn't negotiated
    ERR_AUTH_REQUIRED = 0x0005              # file op attempted before authentication
    ERR_FILE_NOT_FOUND = 0x0006             # requested file does not exist
    ERR_PERMISSION_DENIED = 0x0007          # authenticated but not authorized
    ERR_OFFSET_OUT_OF_RANGE = 0x0008        # start_offset beyond end of file
    ERR_INTERNAL = 0x00FF                   # generic server-side failure


# --------------------------------------------------------------------------- #
# Abort reasons (reason field of ABORT)
# --------------------------------------------------------------------------- #
class AbortReason(IntEnum):
    ABORT_USER_REQUEST = 0x00    # user/client chose to cancel the transfer
    ABORT_TIMEOUT = 0x01         # cancelled due to a timeout (e.g. idle transfer)
    ABORT_RESOURCE_LIMIT = 0x02  # cancelled due to a server resource limit


# --------------------------------------------------------------------------- #
# Sizing / framing constants
# --------------------------------------------------------------------------- #
HEADER_SIZE = 12               # bytes in the common header

# Recommended data-chunk size advertised in HELLO_ACK.max_chunk_size.
# Section 2.4.2 recommends 64 KB (between 16 KB and 1 MB).
DEFAULT_MAX_CHUNK_SIZE = 65536
MIN_MAX_CHUNK_SIZE = 16384
MAX_MAX_CHUNK_SIZE = 1048576

# Default per-session authentication attempt budget (Section 1.4 / 5.3.2).
DEFAULT_AUTH_MAX_ATTEMPTS = 3
