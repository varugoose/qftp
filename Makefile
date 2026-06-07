# =========================================================================== #
# QFTP -- QUIC File Transfer Protocol (Phase 3 implementation)
#
# This Makefile is the single documented entry point for building and running
# the project on a Linux-based system (Tux, macOS, or WSL2/Ubuntu).
#
#   make install   create a virtualenv and install dependencies
#   make certs     generate a self-signed TLS certificate for QUIC
#   make server    run the QFTP server   (see 'make help' for arguments)
#   make client    run the QFTP client
#   make test      run the PDU / DFA unit test suite
#   make clean     remove the virtualenv, certs, and Python caches
# =========================================================================== #

VENV    := .venv
PY      := $(VENV)/bin/python
PIP     := $(VENV)/bin/pip
CERTDIR := certs

# ---- Default configuration (override on the command line) ------------------ #
# Example:  make server PORT=4433 FILES=server_files
#           make client HOST=127.0.0.1 FILE=hello.txt QUSER=bob QPASS=bobpass
HOST  ?= 127.0.0.1
PORT  ?= 4433
FILES ?= server_files
QUSER ?= bob
QPASS ?= bobpass
FILE  ?=

.PHONY: help install certs server client test integration clean

help:
	@echo "QFTP make targets:"
	@echo "  make install   - set up virtualenv and install dependencies"
	@echo "  make certs     - generate a self-signed TLS cert for QUIC"
	@echo "  make server    - run the server (PORT, FILES)"
	@echo "  make client    - run the client (HOST, PORT, FILE, QUSER, QPASS)"
	@echo "  make test      - run the unit test suite"
	@echo "  make integration - run the in-process end-to-end test"
	@echo "  make clean     - remove venv, certs, and caches"

install:
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	@echo "Install complete. Next: 'make certs' then 'make server' / 'make client'."

# Generate a self-signed certificate + key for the server. QUIC mandates TLS,
# so the server needs a cert; the client trusts it explicitly for local testing.
certs:
	@mkdir -p $(CERTDIR)
	openssl req -x509 -newkey rsa:2048 -nodes \
		-keyout $(CERTDIR)/key.pem -out $(CERTDIR)/cert.pem \
		-days 365 -subj "/CN=localhost" \
		-addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
	@echo "Wrote $(CERTDIR)/cert.pem and $(CERTDIR)/key.pem"

server:
	$(PY) -m qftp.server --port $(PORT) --files $(FILES) \
		--cert $(CERTDIR)/cert.pem --key $(CERTDIR)/key.pem

client:
	$(PY) -m qftp.client --host $(HOST) --port $(PORT) \
		--cert $(CERTDIR)/cert.pem --username $(QUSER) --password $(QPASS) \
		$(if $(FILE),--file $(FILE),) $(if $(RESUME),--resume,)

test:
	$(PY) -m pytest tests/ -v

# End-to-end test: runs a real client/server session in-process (no sockets),
# exercising the handshake, DFA, transfer, and checksum verification.
integration:
	$(PY) integration_test.py

clean:
	rm -rf $(VENV) $(CERTDIR) .pytest_cache
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@echo "Cleaned."
