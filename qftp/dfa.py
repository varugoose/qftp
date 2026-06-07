"""
QFTP protocol state machine (DFA).

This module implements the six-state deterministic finite automaton from
Section 3 of the Phase 2 specification, for BOTH endpoints. It is deliberately
pure logic: it knows nothing about QUIC, sockets, or asyncio. Given the current
state, a direction (send/recv), and a message type, it either returns the new
state or raises :class:`InvalidTransition`. This separation lets every legal and
illegal transition be unit-tested in isolation, before any networking exists.

The six states (Section 3.1)::

    INIT -> HANDSHAKING -> AUTHENTICATING -> READY <-> TRANSFERRING
                                              |
                                              +--> CLOSED

How the server/client use it
----------------------------
* Before sending a message, call :meth:`on_send` -- it confirms the send is
  legal in the current state and advances the state.
* After parsing a received message, call :meth:`on_recv` -- likewise.
* If either raises :class:`InvalidTransition`, the caller follows Section 3.5:
  send an ERROR (ERR_UNEXPECTED_MESSAGE) and move to CLOSED.

Conditional and universal rules
-------------------------------
* AUTH_RESPONSE is conditional: the next state depends on the auth status and
  the number of attempts remaining (Section 3.2 / 3.3). Pass ``auth_status`` and
  ``attempts_remaining`` for that message.
* ERROR and CLOSE are universal: per the "any state" rows of the client table
  (Section 3.2), either of them -- in either direction -- drives the endpoint to
  CLOSED from any active state. This implementation applies that universally to
  both roles, which also gives the server graceful handling of a client CLOSE
  during a transfer (a small, deliberate generalization of the server table in
  Section 3.3, where CLOSE was only listed in READY).
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, Optional, Tuple

from .constants import State, MsgType, AuthStatus


class Role(Enum):
    """Which side of the conversation an endpoint is on."""
    CLIENT = "client"
    SERVER = "server"


class Direction(Enum):
    """Whether the message is being sent by, or received by, this endpoint."""
    SEND = "send"
    RECV = "recv"


class InvalidTransition(Exception):
    """
    Raised when a message is not valid for the current state.

    Per Section 3.5, the endpoint that detects this MUST send an ERROR with code
    ERR_UNEXPECTED_MESSAGE and transition to CLOSED. The attributes are exposed
    so callers can log precisely what went wrong.
    """

    def __init__(self, role: Role, state: State, direction: Direction,
                 msg_type: int):
        self.role = role
        self.state = state
        self.direction = direction
        self.msg_type = msg_type
        try:
            name = MsgType(msg_type).name
        except ValueError:
            name = f"0x{msg_type:02X}"
        super().__init__(
            f"{role.value}: illegal to {direction.value} {name} "
            f"while in state {state.name}"
        )


# --------------------------------------------------------------------------- #
# Static transition tables (the rows of Sections 3.2 and 3.3 that do not
# depend on message contents). Keyed by (state, direction, msg_type).
# ERROR, CLOSE, and AUTH_RESPONSE are handled separately below.
# --------------------------------------------------------------------------- #
_Key = Tuple[State, Direction, MsgType]

_CLIENT_TABLE: Dict[_Key, State] = {
    (State.INIT,           Direction.SEND, MsgType.HELLO):             State.HANDSHAKING,
    (State.HANDSHAKING,    Direction.RECV, MsgType.HELLO_ACK):         State.AUTHENTICATING,
    (State.AUTHENTICATING, Direction.SEND, MsgType.AUTH_REQUEST):      State.AUTHENTICATING,
    (State.READY,          Direction.SEND, MsgType.LIST_REQUEST):      State.READY,
    (State.READY,          Direction.RECV, MsgType.LIST_RESPONSE):     State.READY,
    (State.READY,          Direction.SEND, MsgType.FILE_REQUEST):      State.TRANSFERRING,
    (State.TRANSFERRING,   Direction.RECV, MsgType.FILE_METADATA):     State.TRANSFERRING,
    (State.TRANSFERRING,   Direction.RECV, MsgType.DATA_CHUNK):        State.TRANSFERRING,
    (State.TRANSFERRING,   Direction.RECV, MsgType.TRANSFER_COMPLETE): State.READY,
    (State.TRANSFERRING,   Direction.SEND, MsgType.ABORT):             State.READY,
    (State.TRANSFERRING,   Direction.RECV, MsgType.ABORT):             State.READY,
}

_SERVER_TABLE: Dict[_Key, State] = {
    (State.INIT,           Direction.RECV, MsgType.HELLO):             State.HANDSHAKING,
    (State.HANDSHAKING,    Direction.SEND, MsgType.HELLO_ACK):         State.AUTHENTICATING,
    (State.AUTHENTICATING, Direction.RECV, MsgType.AUTH_REQUEST):      State.AUTHENTICATING,
    (State.READY,          Direction.RECV, MsgType.LIST_REQUEST):      State.READY,
    (State.READY,          Direction.SEND, MsgType.LIST_RESPONSE):     State.READY,
    (State.READY,          Direction.RECV, MsgType.FILE_REQUEST):      State.TRANSFERRING,
    (State.TRANSFERRING,   Direction.SEND, MsgType.FILE_METADATA):     State.TRANSFERRING,
    (State.TRANSFERRING,   Direction.SEND, MsgType.DATA_CHUNK):        State.TRANSFERRING,
    (State.TRANSFERRING,   Direction.SEND, MsgType.TRANSFER_COMPLETE): State.READY,
    (State.TRANSFERRING,   Direction.SEND, MsgType.ABORT):             State.READY,
    (State.TRANSFERRING,   Direction.RECV, MsgType.ABORT):             State.READY,
}

_TABLES = {Role.CLIENT: _CLIENT_TABLE, Role.SERVER: _SERVER_TABLE}


def auth_response_next_state(status: int,
                             attempts_remaining: Optional[int]) -> State:
    """
    Compute the state after an AUTH_RESPONSE, per Sections 3.2 / 3.3.

    * AUTH_OK                  -> READY
    * AUTH_BAD_CREDENTIALS     -> AUTHENTICATING if attempts remain, else CLOSED
    * AUTH_LOCKED_OUT          -> CLOSED
    * AUTH_SERVER_ERROR        -> AUTHENTICATING (transient; attempts unchanged)
    * any unrecognized status  -> CLOSED (treated as fatal, Section 4.6)
    """
    if status == AuthStatus.AUTH_OK:
        return State.READY
    if status == AuthStatus.AUTH_BAD_CREDENTIALS:
        if attempts_remaining is not None and attempts_remaining > 0:
            return State.AUTHENTICATING
        return State.CLOSED
    if status == AuthStatus.AUTH_LOCKED_OUT:
        return State.CLOSED
    if status == AuthStatus.AUTH_SERVER_ERROR:
        return State.AUTHENTICATING
    return State.CLOSED


class ProtocolStateMachine:
    """
    Tracks and enforces the QFTP DFA for a single endpoint.

    Create one per connection, passing the endpoint's :class:`Role`. It starts
    in :attr:`State.INIT`. Call :meth:`on_send` / :meth:`on_recv` around every
    message; both advance the state or raise :class:`InvalidTransition`.
    """

    def __init__(self, role: Role):
        self.role = role
        self.state = State.INIT

    @property
    def is_closed(self) -> bool:
        """True once the machine has reached the terminal CLOSED state."""
        return self.state == State.CLOSED

    def on_send(self, msg_type: int, *, auth_status: Optional[int] = None,
                attempts_remaining: Optional[int] = None) -> State:
        """Validate and apply the transition for sending ``msg_type``."""
        return self._transition(Direction.SEND, msg_type,
                                 auth_status, attempts_remaining)

    def on_recv(self, msg_type: int, *, auth_status: Optional[int] = None,
                attempts_remaining: Optional[int] = None) -> State:
        """Validate and apply the transition for receiving ``msg_type``."""
        return self._transition(Direction.RECV, msg_type,
                                 auth_status, attempts_remaining)

    # ----------------------------------------------------------------------- #
    # Internal
    # ----------------------------------------------------------------------- #
    def _transition(self, direction: Direction, msg_type: int,
                    auth_status: Optional[int],
                    attempts_remaining: Optional[int]) -> State:
        # Normalize the message type.
        try:
            mt = MsgType(msg_type)
        except ValueError:
            # Unknown message type is never valid (Section 4.5 / 3.5).
            raise InvalidTransition(self.role, self.state, direction, msg_type)

        # CLOSED is terminal: nothing is legal once we are there.
        if self.state == State.CLOSED:
            raise InvalidTransition(self.role, self.state, direction, mt)

        # Universal rule: ERROR or CLOSE in either direction ends the session.
        if mt in (MsgType.ERROR, MsgType.CLOSE):
            self.state = State.CLOSED
            return self.state

        # Conditional rule: AUTH_RESPONSE depends on the status/attempts.
        if mt == MsgType.AUTH_RESPONSE:
            expected_dir = (Direction.RECV if self.role == Role.CLIENT
                            else Direction.SEND)
            if self.state != State.AUTHENTICATING or direction != expected_dir:
                raise InvalidTransition(self.role, self.state, direction, mt)
            if auth_status is None:
                raise ValueError(
                    "auth_status is required to evaluate an AUTH_RESPONSE "
                    "transition"
                )
            self.state = auth_response_next_state(auth_status, attempts_remaining)
            return self.state

        # Everything else: consult the static table for this role.
        next_state = _TABLES[self.role].get((self.state, direction, mt))
        if next_state is None:
            raise InvalidTransition(self.role, self.state, direction, mt)
        self.state = next_state
        return self.state
