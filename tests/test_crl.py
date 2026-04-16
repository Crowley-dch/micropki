import pytest
import tempfile
import os
from pathlib import Path
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

from micropki.crl import CRLGenerator
from micropki.database import CertificateDatabase
from micropki.crypto_utils import generate_key, encrypt_private_key
from micropki.certificates import create_self_signed_certificate


class TestCRL:

    @pytest.fixture
    def ca_setup(self):
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name

        db = CertificateDatabase(db_path)
        db.init_schema()

        key = generate_key('rsa', 4096)
        cert = create_self_signed_certificate(
            private_key=key,
            subject_dn="/CN=Test CA",
            validity_days=365,
            key_type='rsa'
        )

        yield {
            'db': db,
            'ca_cert': cert,
            'ca_key': key,
            'db_path': db_path
        }

        db.close()
        os.unlink(db_path)

    def test_generate_empty_crl(self, ca_setup):
        """Тест генерации пустого CRL"""
        generator = CRLGenerator(
            ca_setup['ca_cert'],
            ca_setup['ca_key'],
            ca_setup['db']
        )

        crl, crl_number, next_update = generator.generate_crl(next_update_days=7)

        assert crl is not None
        assert crl_number == 1
        # Проверяем, что CRL подписан (имеет signature)
        assert crl.signature is not None

    def test_crl_number_increments(self, ca_setup):

        generator = CRLGenerator(
            ca_setup['ca_cert'],
            ca_setup['ca_key'],
            ca_setup['db']
        )

        crl1, num1, _ = generator.generate_crl()

        generator.save_crl_number(str(ca_setup['ca_cert'].subject), num1,
                                  datetime.now(timezone.utc) + timedelta(days=7), "test")

        crl2, num2, _ = generator.generate_crl()

        assert num2 == num1 + 1

    def test_crl_format(self, ca_setup):
        generator = CRLGenerator(
            ca_setup['ca_cert'],
            ca_setup['ca_key'],
            ca_setup['db']
        )

        crl, _, _ = generator.generate_crl()

        crl_pem = crl.public_bytes(serialization.Encoding.PEM)

        assert crl_pem.startswith(b'-----BEGIN X509 CRL-----')
        assert crl_pem.endswith(b'-----END X509 CRL-----\n')

    def test_crl_has_aki_extension(self, ca_setup):
        generator = CRLGenerator(
            ca_setup['ca_cert'],
            ca_setup['ca_key'],
            ca_setup['db']
        )

        crl, _, _ = generator.generate_crl()

        try:
            aki = crl.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
            assert aki is not None
        except x509.ExtensionNotFound:
            assert False, "AKI extension not found"

    def test_crl_has_crl_number(self, ca_setup):
        generator = CRLGenerator(
            ca_setup['ca_cert'],
            ca_setup['ca_key'],
            ca_setup['db']
        )

        crl, crl_number, _ = generator.generate_crl()

        ext = crl.extensions.get_extension_for_class(x509.CRLNumber)
        assert ext.value.crl_number == crl_number

    def test_crl_number_increments(self, ca_setup):
        generator = CRLGenerator(
            ca_setup['ca_cert'],
            ca_setup['ca_key'],
            ca_setup['db']
        )

        crl1, num1, _ = generator.generate_crl()
        crl2, num2, _ = generator.generate_crl()

        assert num2 == num1 + 1

    def test_crl_with_revoked_certificate(self, ca_setup):
        db = ca_setup['db']

        from datetime import datetime
        cert_data = {
            'serial_hex': '2A7F',
            'subject': 'CN=Test Cert',
            'issuer': str(ca_setup['ca_cert'].subject),
            'not_before': '2026-01-01T00:00:00',
            'not_after': '2027-01-01T00:00:00',
            'cert_pem': 'test',
            'status': 'revoked',
            'revocation_reason': 'keyCompromise',
            'revocation_date': datetime.now().isoformat()
        }
        db.insert_certificate(cert_data)

        generator = CRLGenerator(
            ca_setup['ca_cert'],
            ca_setup['ca_key'],
            db
        )

        crl, _, _ = generator.generate_crl()

        revoked_certs = list(crl)
        assert len(revoked_certs) >= 1

        found = False
        for rc in revoked_certs:
            if rc.serial_number == 0x2A7F:
                found = True
                break
        assert found

    def test_save_crl_to_file(self, ca_setup, tmp_path):
        generator = CRLGenerator(
            ca_setup['ca_cert'],
            ca_setup['ca_key'],
            ca_setup['db']
        )

        crl, _, _ = generator.generate_crl()

        crl_path = tmp_path / 'test.crl.pem'
        generator.save_crl(crl, crl_path, 'test')

        assert crl_path.exists()
        assert crl_path.stat().st_size > 0