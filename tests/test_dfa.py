"""
DFA / state-machine tests.

These exercise both the legal transitions (the happy paths a real session
follows) and -- just as important for the rubric's DFA-validation points -- the
illegal ones that must be rejected. The state machine is pure logic, so these
tests run instantly with no networking.

Run with:  make test   (or)   python -m pytest tests/test_dfa.py -v
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from qftp.dfa import (
    ProtocolStateMachine,
    Role,
    InvalidTransition,
)
from qftp.constants import State, MsgType, AuthStatus


# --------------------------------------------------------------------------- #
# Happy paths
# --------------------------------------------------------------------------- #
def test_client_full_session_happy_path():
    m = ProtocolStateMachine(Role.CLIENT)
    assert m.state == State.INIT
    assert m.on_send(MsgType.HELLO) == State.HANDSHAKING
    assert m.on_recv(MsgType.HELLO_ACK) == State.AUTHENTICATING
    assert m.on_send(MsgType.AUTH_REQUEST) == State.AUTHENTICATING
    assert m.on_recv(MsgType.AUTH_RESPONSE,
                     auth_status=AuthStatus.AUTH_OK) == State.READY
    # list, then request a file
    assert m.on_send(MsgType.LIST_REQUEST) == State.READY
    assert m.on_recv(MsgType.LIST_RESPONSE) == State.READY
    assert m.on_send(MsgType.FILE_REQUEST) == State.TRANSFERRING
    assert m.on_recv(MsgType.FILE_METADATA) == State.TRANSFERRING
    assert m.on_recv(MsgType.DATA_CHUNK) == State.TRANSFERRING
    assert m.on_recv(MsgType.DATA_CHUNK) == State.TRANSFERRING
    assert m.on_recv(MsgType.TRANSFER_COMPLETE) == State.READY
    assert m.on_send(MsgType.CLOSE) == State.CLOSED
    assert m.is_closed


def test_server_full_session_happy_path():
    m = ProtocolStateMachine(Role.SERVER)
    assert m.on_recv(MsgType.HELLO) == State.HANDSHAKING
    assert m.on_send(MsgType.HELLO_ACK) == State.AUTHENTICATING
    assert m.on_recv(MsgType.AUTH_REQUEST) == State.AUTHENTICATING
    assert m.on_send(MsgType.AUTH_RESPONSE,
                     auth_status=AuthStatus.AUTH_OK) == State.READY
    assert m.on_recv(MsgType.LIST_REQUEST) == State.READY
    assert m.on_send(MsgType.LIST_RESPONSE) == State.READY
    assert m.on_recv(MsgType.FILE_REQUEST) == State.TRANSFERRING
    assert m.on_send(MsgType.FILE_METADATA) == State.TRANSFERRING
    assert m.on_send(MsgType.DATA_CHUNK) == State.TRANSFERRING
    assert m.on_send(MsgType.TRANSFER_COMPLETE) == State.READY
    assert m.on_recv(MsgType.CLOSE) == State.CLOSED


# --------------------------------------------------------------------------- #
# Authentication branches
# --------------------------------------------------------------------------- #
def test_auth_retry_then_success():
    m = ProtocolStateMachine(Role.CLIENT)
    m.on_send(MsgType.HELLO)
    m.on_recv(MsgType.HELLO_ACK)
    m.on_send(MsgType.AUTH_REQUEST)
    # wrong password, but attempts remain -> stay in AUTHENTICATING
    assert m.on_recv(MsgType.AUTH_RESPONSE,
                     auth_status=AuthStatus.AUTH_BAD_CREDENTIALS,
                     attempts_remaining=2) == State.AUTHENTICATING
    # retry
    m.on_send(MsgType.AUTH_REQUEST)
    assert m.on_recv(MsgType.AUTH_RESPONSE,
                     auth_status=AuthStatus.AUTH_OK) == State.READY


def test_auth_locked_out_closes():
    m = ProtocolStateMachine(Role.CLIENT)
    m.on_send(MsgType.HELLO)
    m.on_recv(MsgType.HELLO_ACK)
    m.on_send(MsgType.AUTH_REQUEST)
    assert m.on_recv(MsgType.AUTH_RESPONSE,
                     auth_status=AuthStatus.AUTH_LOCKED_OUT,
                     attempts_remaining=0) == State.CLOSED


def test_auth_bad_credentials_no_attempts_left_closes():
    m = ProtocolStateMachine(Role.CLIENT)
    m.on_send(MsgType.HELLO)
    m.on_recv(MsgType.HELLO_ACK)
    m.on_send(MsgType.AUTH_REQUEST)
    assert m.on_recv(MsgType.AUTH_RESPONSE,
                     auth_status=AuthStatus.AUTH_BAD_CREDENTIALS,
                     attempts_remaining=0) == State.CLOSED


def test_auth_response_without_status_is_an_error():
    m = ProtocolStateMachine(Role.CLIENT)
    m.on_send(MsgType.HELLO)
    m.on_recv(MsgType.HELLO_ACK)
    m.on_send(MsgType.AUTH_REQUEST)
    with pytest.raises(ValueError):
        m.on_recv(MsgType.AUTH_RESPONSE)  # missing auth_status


# --------------------------------------------------------------------------- #
# Abort returns to READY without closing the session
# --------------------------------------------------------------------------- #
def test_client_abort_returns_to_ready():
    m = ProtocolStateMachine(Role.CLIENT)
    m.on_send(MsgType.HELLO)
    m.on_recv(MsgType.HELLO_ACK)
    m.on_send(MsgType.AUTH_REQUEST)
    m.on_recv(MsgType.AUTH_RESPONSE, auth_status=AuthStatus.AUTH_OK)
    m.on_send(MsgType.FILE_REQUEST)
    m.on_recv(MsgType.FILE_METADATA)
    m.on_recv(MsgType.DATA_CHUNK)
    assert m.on_send(MsgType.ABORT) == State.READY
    # session continues: can request another file
    assert m.on_send(MsgType.FILE_REQUEST) == State.TRANSFERRING


def test_server_abort_returns_to_ready():
    m = ProtocolStateMachine(Role.SERVER)
    m.on_recv(MsgType.HELLO)
    m.on_send(MsgType.HELLO_ACK)
    m.on_recv(MsgType.AUTH_REQUEST)
    m.on_send(MsgType.AUTH_RESPONSE, auth_status=AuthStatus.AUTH_OK)
    m.on_recv(MsgType.FILE_REQUEST)
    m.on_send(MsgType.FILE_METADATA)
    assert m.on_recv(MsgType.ABORT) == State.READY


# --------------------------------------------------------------------------- #
# Universal CLOSE / ERROR rules
# --------------------------------------------------------------------------- #
def test_recv_close_from_ready_closes():
    m = ProtocolStateMachine(Role.CLIENT)
    m.on_send(MsgType.HELLO)
    m.on_recv(MsgType.HELLO_ACK)
    m.on_send(MsgType.AUTH_REQUEST)
    m.on_recv(MsgType.AUTH_RESPONSE, auth_status=AuthStatus.AUTH_OK)
    assert m.on_recv(MsgType.CLOSE) == State.CLOSED


def test_recv_error_during_transfer_closes():
    m = ProtocolStateMachine(Role.CLIENT)
    m.on_send(MsgType.HELLO)
    m.on_recv(MsgType.HELLO_ACK)
    m.on_send(MsgType.AUTH_REQUEST)
    m.on_recv(MsgType.AUTH_RESPONSE, auth_status=AuthStatus.AUTH_OK)
    m.on_send(MsgType.FILE_REQUEST)
    assert m.on_recv(MsgType.ERROR) == State.CLOSED


def test_send_error_from_any_state_closes():
    m = ProtocolStateMachine(Role.SERVER)
    m.on_recv(MsgType.HELLO)  # now in HANDSHAKING
    assert m.on_send(MsgType.ERROR) == State.CLOSED


# --------------------------------------------------------------------------- #
# Illegal transitions (the core of DFA validation)
# --------------------------------------------------------------------------- #
def test_file_request_before_auth_rejected():
    m = ProtocolStateMachine(Role.CLIENT)
    m.on_send(MsgType.HELLO)
    m.on_recv(MsgType.HELLO_ACK)            # in AUTHENTICATING
    with pytest.raises(InvalidTransition):
        m.on_send(MsgType.FILE_REQUEST)     # not allowed before READY


def test_data_chunk_in_ready_rejected():
    m = ProtocolStateMachine(Role.CLIENT)
    m.on_send(MsgType.HELLO)
    m.on_recv(MsgType.HELLO_ACK)
    m.on_send(MsgType.AUTH_REQUEST)
    m.on_recv(MsgType.AUTH_RESPONSE, auth_status=AuthStatus.AUTH_OK)  # READY
    with pytest.raises(InvalidTransition):
        m.on_recv(MsgType.DATA_CHUNK)       # data only valid while TRANSFERRING


def test_second_hello_after_handshake_rejected():
    m = ProtocolStateMachine(Role.CLIENT)
    m.on_send(MsgType.HELLO)
    m.on_recv(MsgType.HELLO_ACK)            # AUTHENTICATING
    with pytest.raises(InvalidTransition):
        m.on_send(MsgType.HELLO)            # handshake already done


def test_hello_in_wrong_direction_rejected():
    # A client should SEND hello, not receive it.
    m = ProtocolStateMachine(Role.CLIENT)
    with pytest.raises(InvalidTransition):
        m.on_recv(MsgType.HELLO)


def test_no_transitions_allowed_after_closed():
    m = ProtocolStateMachine(Role.CLIENT)
    m.on_send(MsgType.HELLO)
    m.on_recv(MsgType.HELLO_ACK)
    m.on_send(MsgType.AUTH_REQUEST)
    m.on_recv(MsgType.AUTH_RESPONSE, auth_status=AuthStatus.AUTH_OK)
    m.on_send(MsgType.CLOSE)                # CLOSED
    assert m.is_closed
    with pytest.raises(InvalidTransition):
        m.on_send(MsgType.LIST_REQUEST)


def test_unknown_message_type_rejected():
    m = ProtocolStateMachine(Role.CLIENT)
    with pytest.raises(InvalidTransition):
        m.on_recv(0xEE)                     # not a defined message type
