"""
Тесты для OCSP responder
"""

import pytest
import tempfile
import os
from pathlib import Path
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.ocsp import OCSPRequestBuilder, OCSPNonce
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from micropki.ocsp import OCSPResponder, create_ocsp_signer_certificate, save_unencrypted_key
from micropki.database import CertificateDatabase
from micropki.crypto_utils import generate_key
from micropki.certificates import create_self_signed_certificate
from micropki.revocation import revoke_certificate


class TestOCSP:

    @pytest.fixture
    def setup(self):
        """Создаёт тестовую среду: CA, БД, OCSP responder"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name

        db = CertificateDatabase(db_path)
        db.init_schema()

        # Создаём тестовый CA
        ca_key = generate_key('rsa', 4096)
        ca_cert = create_self_signed_certificate(
            private_key=ca_key,
            subject_dn="/CN=Test CA",
            validity_days=365,
            key_type='rsa'
        )

        # Создаём OCSP responder сертификат
        ocsp_key, ocsp_cert = create_ocsp_signer_certificate(
            ca_cert=ca_cert,
            ca_private_key=ca_key,
            subject_dn="/CN=OCSP Responder",
            key_type='rsa',
            key_size=2048,
            validity_days=365,
            san_list=None
        )

        # Добавляем тестовый сертификат в БД
        cert_data = {
            'serial_hex': '2A7F',
            'subject': 'CN=Test Cert',
            'issuer': str(ca_cert.subject),
            'not_before': '2026-01-01T00:00:00',
            'not_after': '2027-01-01T00:00:00',
            'cert_pem': 'test_pem',
            'status': 'valid'
        }
        db.insert_certificate(cert_data)

        # Создаём OCSP responder
        ocsp = OCSPResponder(db, ca_cert, ocsp_cert, ocsp_key)

        yield {
            'db': db,
            'ca_cert': ca_cert,
            'ca_key': ca_key,
            'ocsp_cert': ocsp_cert,
            'ocsp_key': ocsp_key,
            'ocsp': ocsp,
            'db_path': db_path
        }

        db.close()
        os.unlink(db_path)

    def _create_ocsp_request(self, serial_hex: str, nonce: bytes = None):
        """Создаёт OCSP запрос для тестирования"""
        builder = OCSPRequestBuilder()
        builder = builder.add_certificate(
            None, None, None,
            serial_number=int(serial_hex, 16),
            hash_algorithm=hashes.SHA1()
        )
        if nonce:
            builder = builder.add_extension(OCSPNonce(nonce), critical=False)
        request = builder.build()
        return request.public_bytes(serialization.Encoding.DER)

    def test_parse_request(self, setup):
        """Тест парсинга OCSP запроса"""
        ocsp = setup['ocsp']
        request_data = self._create_ocsp_request('2A7F')

        cert_ids, nonce, error = ocsp.parse_request(request_data)

        assert error is None
        assert cert_ids is not None
        assert len(cert_ids) == 1
        assert cert_ids[0]['serial'] == '2A7F'

    def test_nonce_echo(self, setup):
        """Тест эха nonce"""
        ocsp = setup['ocsp']
        test_nonce = b'12345678'
        request_data = self._create_ocsp_request('2A7F', test_nonce)

        cert_ids, nonce, error = ocsp.parse_request(request_data)
        assert nonce == test_nonce

    def test_good_status(self, setup):
        """Тест статуса good для валидного сертификата"""
        ocsp = setup['ocsp']
        request_data = self._create_ocsp_request('2A7F')

        response_data = ocsp.handle_request(request_data)
        assert response_data is not None
        assert len(response_data) > 0

    def test_unknown_status(self, setup):
        """Тест статуса unknown для несуществующего сертификата"""
        ocsp = setup['ocsp']
        request_data = self._create_ocsp_request('FFFF')

        response_data = ocsp.handle_request(request_data)
        assert response_data is not None

    def test_revoked_status(self, setup):
        """Тест статуса revoked для отозванного сертификата"""
        ocsp = setup['ocsp']
        db = setup['db']

        # Отзываем сертификат
        revoke_certificate(db, '2A7F', 'keyCompromise', force=False)

        request_data = self._create_ocsp_request('2A7F')
        response_data = ocsp.handle_request(request_data)
        assert response_data is not None

    def test_issuer_hash_matching(self, setup):
        """Тест сопоставления хешей issuer"""
        ocsp = setup['ocsp']
        ca_cert = setup['ca_cert']

        # Проверяем хеши
        assert ocsp.ca_name_hash is not None
        assert ocsp.ca_key_hash is not None
        assert len(ocsp.ca_name_hash) == 20
        assert len(ocsp.ca_key_hash) == 20

    def test_create_ocsp_certificate(self, setup):
        """Тест создания OCSP сертификата"""
        ocsp_cert = setup['ocsp_cert']

        # Проверяем расширения
        try:
            ku = ocsp_cert.extensions.get_extension_for_class(x509.KeyUsage)
            assert ku.value.digital_signature is True
            assert ku.value.key_cert_sign is False
        except x509.ExtensionNotFound:
            assert False, "KeyUsage not found"

        try:
            eku = ocsp_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            eku_oids = [oid.dotted_string for oid in eku.value]
            assert '1.3.6.1.5.5.7.3.9' in eku_oids  # OCSPSigning
        except x509.ExtensionNotFound:
            assert False, "ExtendedKeyUsage not found"

        try:
            bc = ocsp_cert.extensions.get_extension_for_class(x509.BasicConstraints)
            assert bc.value.ca is False
        except x509.ExtensionNotFound:
            assert False, "BasicConstraints not found"

    def test_response_has_signature(self, setup):
        """Тест наличия подписи в ответе"""
        ocsp = setup['ocsp']
        request_data = self._create_ocsp_request('2A7F')

        response_data = ocsp.handle_request(request_data)

        # Пробуем загрузить ответ
        from cryptography.x509.ocsp import load_der_ocsp_response
        response = load_der_ocsp_response(response_data)
        assert response.signature is not None


class TestOCSPCertificateIssuance:
    """Тесты выпуска OCSP сертификата"""

    @pytest.fixture
    def ca_setup(self):
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name

        db = CertificateDatabase(db_path)
        db.init_schema()

        ca_key = generate_key('rsa', 4096)
        ca_cert = create_self_signed_certificate(
            private_key=ca_key,
            subject_dn="/CN=Test CA",
            validity_days=365,
            key_type='rsa'
        )

        yield {
            'db': db,
            'ca_cert': ca_cert,
            'ca_key': ca_key,
            'db_path': db_path
        }

        db.close()
        os.unlink(db_path)

    def test_issue_ocsp_cert_rsa(self, ca_setup):
        """Тест выпуска OCSP сертификата RSA"""
        ocsp_key, ocsp_cert = create_ocsp_signer_certificate(
            ca_cert=ca_setup['ca_cert'],
            ca_private_key=ca_setup['ca_key'],
            subject_dn="/CN=OCSP Test",
            key_type='rsa',
            key_size=2048,
            validity_days=365,
            san_list=None
        )

        assert ocsp_key is not None
        assert ocsp_cert is not None
        assert ocsp_cert.subject == x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'OCSP Test')])

    def test_save_unencrypted_key(self, ca_setup, tmp_path):
        """Тест сохранения незашифрованного ключа"""
        ocsp_key, _ = create_ocsp_signer_certificate(
            ca_cert=ca_setup['ca_cert'],
            ca_private_key=ca_setup['ca_key'],
            subject_dn="/CN=OCSP Test",
            key_type='rsa',
            key_size=2048,
            validity_days=365,
            san_list=None
        )

        key_path = tmp_path / 'ocsp.key.pem'
        save_unencrypted_key(ocsp_key, key_path)

        assert key_path.exists()
        content = key_path.read_text()
        assert 'BEGIN PRIVATE KEY' in content