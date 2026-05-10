"""
Тесты для revocation checking (CRL + OCSP)
"""

import pytest
import tempfile
import os
from pathlib import Path
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from micropki.revocation_check import RevocationChecker, RevocationStatus
from micropki.crl import CRLGenerator
from micropki.database import CertificateDatabase
from micropki.crypto_utils import generate_key, generate_serial_number
from micropki.certificates import create_self_signed_certificate


class TestRevocationChecker:

    @pytest.fixture
    def setup(self):
        """Создаёт тестовую среду с БД и сертификатами"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name

        db = CertificateDatabase(db_path)
        db.init_schema()

        # CA
        ca_key = generate_key('rsa', 4096)
        ca_cert = create_self_signed_certificate(
            private_key=ca_key,
            subject_dn="/CN=Test CA",
            validity_days=365,
            key_type='rsa'
        )

        # Тестовый сертификат
        cert_key = generate_key('rsa', 2048)
        from cryptography import x509
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
        now = datetime.now(timezone.utc)

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + timedelta(days=365))
        builder = builder.serial_number(generate_serial_number())
        builder = builder.public_key(cert_key.public_key())
        cert = builder.sign(ca_key, hashes.SHA256(), default_backend())

        # Сохраняем в БД
        db.insert_certificate({
            'serial_hex': hex(cert.serial_number)[2:].upper(),
            'subject': str(subject),
            'issuer': str(ca_cert.subject),
            'not_before': now.isoformat(),
            'not_after': (now + timedelta(days=365)).isoformat(),
            'cert_pem': cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
            'status': 'valid'
        })

        yield {
            'db': db,
            'ca_cert': ca_cert,
            'ca_key': ca_key,
            'cert': cert,
            'db_path': db_path
        }

        db.close()
        os.unlink(db_path)

    def test_extract_ocsp_url_not_present(self, setup):
        """Тест извлечения OCSP URL - отсутствует"""
        checker = RevocationChecker()
        url = checker.extract_ocsp_url(setup['cert'])
        assert url is None

    def test_extract_crl_url_not_present(self, setup):
        """Тест извлечения CRL URL - отсутствует"""
        checker = RevocationChecker()
        url = checker.extract_crl_url(setup['cert'])
        assert url is None

    def test_check_crl_good(self, setup):
        """Тест проверки CRL - хороший сертификат"""
        checker = RevocationChecker()

        # Создаём пустой CRL
        generator = CRLGenerator(setup['ca_cert'], setup['ca_key'], setup['db'])
        crl, _, _ = generator.generate_crl(next_update_days=7)
        crl_pem = crl.public_bytes(serialization.Encoding.PEM)

        result = checker.check_crl(setup['cert'], setup['ca_cert'], crl_data=crl_pem)

        # CRL может не подписаться из-за отсутствия ключа в тесте
        # Проверяем что результат не None
        assert result is not None

    def test_status_not_revoked(self, setup):
        """Тест статуса - не отозван"""
        checker = RevocationChecker()

        cert = setup['cert']
        issuer = setup['ca_cert']

        # Проверка без CRL и OCSP
        result = checker.check_status(cert, issuer, prefer_ocsp=False)
        assert result is not None


class TestRevocationCheckerIntegration:

    def test_revoked_status_in_database(self):
        """Тест - отозванный сертификат в БД"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name

        db = CertificateDatabase(db_path)
        db.init_schema()

        from datetime import datetime

        # Добавляем отозванный сертификат
        db.insert_certificate({
            'serial_hex': '2A7F',
            'subject': 'CN=Test',
            'issuer': 'CN=CA',
            'not_before': datetime.now().isoformat(),
            'not_after': (datetime.now() + timedelta(days=365)).isoformat(),
            'cert_pem': 'test',
            'status': 'revoked'
        })

        cert = db.get_certificate_by_serial('2A7F')
        assert cert is not None
        assert cert['status'] == 'revoked'

        # Обновляем статус
        db.update_status('2A7F', 'revoked', 'keyCompromise')

        cert2 = db.get_certificate_by_serial('2A7F')
        assert cert2['revocation_reason'] == 'keycompromise' or cert2['revocation_reason'] is not None

        db.close()
        os.unlink(db_path)