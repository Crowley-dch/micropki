import pytest
import tempfile
import os
from datetime import datetime

from micropki.database import CertificateDatabase


class TestCertificateDatabase:

    @pytest.fixture
    def db(self):
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name

        db = CertificateDatabase(db_path)
        db.init_schema()

        yield db

        db.close()
        os.unlink(db_path)

    def test_init_schema(self, db):
        conn = db._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='certificates'"
        )
        assert cursor.fetchone() is not None

    def test_insert_certificate(self, db):
        cert_data = {
            'serial_hex': '2A7F',
            'subject': 'CN=Test',
            'issuer': 'CN=CA',
            'not_before': '2026-01-01T00:00:00',
            'not_after': '2027-01-01T00:00:00',
            'cert_pem': 'test_pem',
            'status': 'valid'
        }

        result = db.insert_certificate(cert_data)
        assert result is True

    def test_insert_duplicate_serial(self, db):
        cert_data = {
            'serial_hex': '2A7F',
            'subject': 'CN=Test',
            'issuer': 'CN=CA',
            'not_before': '2026-01-01T00:00:00',
            'not_after': '2027-01-01T00:00:00',
            'cert_pem': 'test_pem',
            'status': 'valid'
        }

        db.insert_certificate(cert_data)
        result = db.insert_certificate(cert_data)
        assert result is False

    def test_get_certificate_by_serial(self, db):
        cert_data = {
            'serial_hex': '2A7F',
            'subject': 'CN=Test',
            'issuer': 'CN=CA',
            'not_before': '2026-01-01T00:00:00',
            'not_after': '2027-01-01T00:00:00',
            'cert_pem': 'test_pem',
            'status': 'valid'
        }
        db.insert_certificate(cert_data)

        cert = db.get_certificate_by_serial('2A7F')
        assert cert is not None
        assert cert['serial_hex'] == '2A7F'
        assert cert['subject'] == 'CN=Test'

    def test_list_certificates(self, db):
        for i in range(3):
            cert_data = {
                'serial_hex': f'00{i}',
                'subject': f'CN=Test{i}',
                'issuer': 'CN=CA',
                'not_before': '2026-01-01T00:00:00',
                'not_after': '2027-01-01T00:00:00',
                'cert_pem': 'test_pem',
                'status': 'valid'
            }
            db.insert_certificate(cert_data)

        certs = db.list_certificates()
        assert len(certs) == 3

    def test_update_status(self, db):
        cert_data = {
            'serial_hex': '2A7F',
            'subject': 'CN=Test',
            'issuer': 'CN=CA',
            'not_before': '2026-01-01T00:00:00',
            'not_after': '2027-01-01T00:00:00',
            'cert_pem': 'test_pem',
            'status': 'valid'
        }
        db.insert_certificate(cert_data)

        result = db.update_status('2A7F', 'revoked', 'key compromise')
        assert result is True

        cert = db.get_certificate_by_serial('2A7F')
        assert cert['status'] == 'revoked'
        assert cert['revocation_reason'] == 'key compromise'

    def test_count_certificates(self, db):
        for i in range(5):
            cert_data = {
                'serial_hex': f'00{i}',
                'subject': f'CN=Test{i}',
                'issuer': 'CN=CA',
                'not_before': '2026-01-01T00:00:00',
                'not_after': '2027-01-01T00:00:00',
                'cert_pem': 'test_pem',
                'status': 'valid'
            }
            db.insert_certificate(cert_data)

        count = db.count_certificates()
        assert count == 5