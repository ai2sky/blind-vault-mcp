"""A loopback HTTPS front for Vaultwarden on the LAN.

bw only talks HTTPS, and the public URL goes through a Cloudflare tunnel that
stalls on large responses (a sync of a big vault never completes). This proxy
terminates TLS on 127.0.0.1 with a throwaway self-signed certificate and passes
the bytes to Vaultwarden's plain HTTP port on the LAN. bw trusts the certificate
through NODE_EXTRA_CA_CERTS; nothing else does.
"""

from __future__ import annotations

import datetime
import ipaddress
import socket
import ssl
import threading
import urllib.parse
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def make_cert(directory: Path) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vw-vault loopback")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(key, hashes.SHA256()))
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    cert_path, key_path = directory / "loopback.crt", directory / "loopback.key"
    key_path.touch(mode=0o600)
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


class LanProxy:
    def __init__(self, upstream: str, port: int, directory: Path):
        parts = urllib.parse.urlsplit(upstream)
        self.upstream = (parts.hostname or "", parts.port or 80)
        self.cert, key = make_cert(directory)
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(self.cert, key)
        key.unlink()  # loaded into the context; not needed on disk
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(32)
        self.url = f"https://127.0.0.1:{port}"

    def start(self) -> None:
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            tls = self.ctx.wrap_socket(conn, server_side=True)
            up = socket.create_connection(self.upstream, timeout=30)
        except (OSError, ssl.SSLError):
            conn.close()
            return
        up.settimeout(None)

        def pump(src, dst):
            try:
                while data := src.recv(65536):
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                for s in (src, dst):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        threading.Thread(target=pump, args=(up, tls), daemon=True).start()
        pump(tls, up)
