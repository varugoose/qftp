"""
In-process end-to-end integration test.

This wires a real QftpServerProtocol and QftpClientProtocol together by pumping
QUIC datagrams between them directly in memory, with no UDP sockets. That makes
it a genuine end-to-end exercise of the QUIC handshake, the two-stream design,
the DFA, authentication, and chunked transfer + SHA-256 verification -- while
sidestepping the sandbox's lack of IPv6 sockets. On a normal machine you would
instead run `make server` and `make client` over real UDP.
"""

import asyncio
import hashlib
import os
import tempfile

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

import sys
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from qftp.server import QftpServerProtocol
from qftp.client import QftpClientProtocol


CLIENT_ADDR = ("127.0.0.1", 50000)
SERVER_ADDR = ("127.0.0.1", 4433)


class Wire:
    """
    A fake datagram transport that hands datagrams straight to the peer.

    Datagrams sent before the peer is attached are queued, so the client's very
    first packet can be inspected (to extract the connection ID the server needs)
    before the server protocol exists.
    """

    def __init__(self, loop, src_addr):
        self.loop = loop
        self.src_addr = src_addr
        self.peer = None
        self.queue = []

    def sendto(self, data, addr=None):
        if self.peer is None:
            self.queue.append(data)
        else:
            self.loop.call_soon(self.peer.datagram_received, data, self.src_addr)

    def flush(self):
        for data in self.queue:
            self.loop.call_soon(self.peer.datagram_received, data, self.src_addr)
        self.queue.clear()

    def close(self):
        pass

    def get_extra_info(self, name, default=None):
        return default


def make_cert(tmp):
    """Generate a throwaway self-signed cert/key for the test."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    cert_path = os.path.join(tmp, "cert.pem")
    key_path = os.path.join(tmp, "key.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
    return cert_path, key_path


async def scenario(files_dir, filename, username="bob", password="bobpass",
                   resume=False, out_dir=None):
    loop = asyncio.get_event_loop()
    tmp = tempfile.mkdtemp()
    cert_path, key_path = make_cert(tmp)

    # --- client side: start it first so we can read its initial packet ---
    client_config = QuicConfiguration(is_client=True, alpn_protocols=["qftp"])
    client_config.load_verify_locations(cert_path)
    client_quic = QuicConnection(configuration=client_config)
    client = QftpClientProtocol(client_quic)

    client_wire = Wire(loop, CLIENT_ADDR)
    client.connection_made(client_wire)
    client_quic.connect(SERVER_ADDR, now=loop.time())
    client.transmit()  # queues the Initial packet(s) in client_wire

    # The server needs the destination connection ID from the client's first
    # packet (this is what aioquic's serve() does under the hood).
    from aioquic.buffer import Buffer
    from aioquic.quic.packet import pull_quic_header
    header = pull_quic_header(Buffer(data=client_wire.queue[0]),
                              host_cid_length=8)
    dcid = header.destination_cid

    # --- server side ---
    server_config = QuicConfiguration(is_client=False, alpn_protocols=["qftp"])
    server_config.load_cert_chain(cert_path, key_path)
    server_quic = QuicConnection(configuration=server_config,
                                 original_destination_connection_id=dcid)
    server = QftpServerProtocol(server_quic)
    server.files_dir = files_dir

    server_wire = Wire(loop, SERVER_ADDR)
    server.connection_made(server_wire)

    # --- cross-wire and release the buffered handshake packets ---
    client_wire.peer = server
    server_wire.peer = client
    client_wire.flush()

    if out_dir is None:
        out_dir = os.path.join(tmp, "downloads")
    rc = await asyncio.wait_for(
        client.run_session(username, password, filename, out_dir,
                           resume=resume),
        timeout=10,
    )
    return rc, out_dir


def main():
    files_dir = os.path.join(os.path.dirname(__file__), "server_files")

    # 1. Listing
    rc, _ = asyncio.run(scenario(files_dir, None))
    assert rc == 0, "listing failed"
    print("[PASS] list catalog\n")

    # 2. Text file download + checksum
    rc, out_dir = asyncio.run(scenario(files_dir, "hello.txt"))
    assert rc == 0, "hello.txt download failed"
    with open(os.path.join(files_dir, "hello.txt"), "rb") as a, \
         open(os.path.join(out_dir, "hello.txt"), "rb") as b:
        assert a.read() == b.read(), "hello.txt content mismatch"
    print("[PASS] download hello.txt, bytes identical\n")

    # 3. Multi-chunk binary download + checksum
    rc, out_dir = asyncio.run(scenario(files_dir, "sample.bin"))
    assert rc == 0, "sample.bin download failed"
    h1 = hashlib.sha256(open(os.path.join(files_dir, "sample.bin"), "rb").read()).hexdigest()
    h2 = hashlib.sha256(open(os.path.join(out_dir, "sample.bin"), "rb").read()).hexdigest()
    assert h1 == h2, "sample.bin checksum mismatch"
    print(f"[PASS] download sample.bin, SHA-256 match ({h1[:16]}...)\n")

    # 4. Bad password is rejected
    rc, _ = asyncio.run(scenario(files_dir, "hello.txt", password="wrong"))
    assert rc == 1, "bad password should fail"
    print("[PASS] wrong password rejected\n")

    # 5. Missing file is rejected
    rc, _ = asyncio.run(scenario(files_dir, "does_not_exist.txt"))
    assert rc == 1, "missing file should fail"
    print("[PASS] missing file rejected\n")

    # 6. Resume a partial download: pre-seed the first 70000 bytes of
    #    sample.bin, then resume and confirm the assembled file is correct.
    resume_dir = tempfile.mkdtemp()
    full = open(os.path.join(files_dir, "sample.bin"), "rb").read()
    partial_len = 70000
    with open(os.path.join(resume_dir, "sample.bin"), "wb") as f:
        f.write(full[:partial_len])
    rc, out_dir = asyncio.run(
        scenario(files_dir, "sample.bin", resume=True, out_dir=resume_dir))
    assert rc == 0, "resume failed"
    resumed = open(os.path.join(out_dir, "sample.bin"), "rb").read()
    assert resumed == full, "resumed file does not match original"
    assert len(resumed) == len(full)
    print(f"[PASS] resume from {partial_len} bytes, full file reassembled "
          f"and verified\n")

    print("ALL END-TO-END SCENARIOS PASSED")


if __name__ == "__main__":
    main()
