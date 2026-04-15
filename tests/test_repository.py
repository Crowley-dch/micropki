import pytest
import threading
import time
import requests
from pathlib import Path
import tempfile

from micropki.repository import start_server
from micropki.database import CertificateDatabase


class TestRepository:

    @pytest.fixture
    def server(self):
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name

        with tempfile.TemporaryDirectory() as cert_dir:
            db = CertificateDatabase(db_path)
            db.init_schema()

            cert_data = {
                'serial_hex': '2A7F',
                'subject': 'CN=Test Cert',
                'issuer': 'CN=Test CA',
                'not_before': '2026-01-01T00:00:00',
                'not_after': '2027-01-01T00:00:00',
                'cert_pem': '-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
                'status': 'valid'
            }
            db.insert_certificate(cert_data)

            server_thread = threading.Thread(
                target=start_server,
                kwargs={
                    'host': '127.0.0.1',
                    'port': 8888,
                    'db_path': db_path,
                    'cert_dir': cert_dir
                },
                daemon=True
            )
            server_thread.start()
            time.sleep(1)

            yield {'db_path': db_path, 'cert_dir': cert_dir}

            db.close()
            Path(db_path).unlink(missing_ok=True)

    def test_health_endpoint(self, server):
        response = requests.get("http://localhost:8888/health")
        assert response.status_code == 200
        assert response.json()['status'] == 'ok'

    def test_get_certificate(self, server):
        response = requests.get("http://localhost:8888/certificate/2A7F")
        assert response.status_code == 200
        assert "BEGIN CERTIFICATE" in response.text

    def test_get_certificate_not_found(self, server):
        response = requests.get("http://localhost:8888/certificate/FFFF")
        assert response.status_code == 404

    def test_get_certificate_invalid_serial(self, server):
        response = requests.get("http://localhost:8888/certificate/invalid")
        assert response.status_code == 400

    def test_crl_endpoint(self, server):
        response = requests.get("http://localhost:8888/crl")
        assert response.status_code == 501

    def test_root_endpoint(self, server):
        response = requests.get("http://localhost:8888/")
        assert response.status_code == 200
        assert 'endpoints' in response.json()