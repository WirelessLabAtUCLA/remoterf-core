from __future__ import annotations

import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from remoteRF_server.server.cert_provider import (
    CERT_NAME,
    start_cert_provider,
    stop_cert_provider,
)


class CertificateProviderTests(unittest.TestCase):
    def test_bootstrap_serves_ca_certificate(self):
        ca_pem = (
            b"-----BEGIN CERTIFICATE-----\n"
            b"local-test-ca\n"
            b"-----END CERTIFICATE-----\n"
        )
        leaf_pem = (
            b"-----BEGIN CERTIFICATE-----\n"
            b"local-test-leaf\n"
            b"-----END CERTIFICATE-----\n"
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            cert_dir = Path(temp_dir)
            (cert_dir / "ca.crt").write_bytes(ca_pem)
            (cert_dir / "server.crt").write_bytes(leaf_pem)

            with patch.dict(
                os.environ,
                {"REMOTERF_CERT_DIR": str(cert_dir)},
            ):
                server, _thread = start_cert_provider(
                    host="127.0.0.1",
                    port=0,
                )
                try:
                    with socket.create_connection(
                        server.server_address,
                        timeout=2.0,
                    ) as client:
                        client.sendall(b"RAW\n")
                        client.shutdown(socket.SHUT_WR)
                        served = b""
                        while True:
                            chunk = client.recv(4096)
                            if not chunk:
                                break
                            served += chunk
                finally:
                    stop_cert_provider(server)

        self.assertEqual(CERT_NAME, "ca.crt")
        self.assertEqual(served, ca_pem)
        self.assertNotEqual(served, leaf_pem)


if __name__ == "__main__":
    unittest.main()
