import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from pathlib import Path
from micropki.certificates import (
    create_self_signed_certificate,
    cert_to_pem
)
from micropki.crypto_utils import generate_key


class TestCertificates:

    def setup_method(self):
        self.rsa_key = generate_key('rsa', 4096)
        self.ecc_key = generate_key('ecc', 384)

    def test_openssl_compatibility(self):
        """Тест совместимости с OpenSSL"""
        import subprocess
        import tempfile

        # Проверяем, доступен ли OpenSSL
        try:
            subprocess.run(['openssl', 'version'], capture_output=True, check=True)
        except (subprocess.SubprocessError, FileNotFoundError):
            pytest.skip("OpenSSL не установлен, пропускаем тест")

        # Создаем тестовый сертификат
        key = generate_key('rsa', 4096)
        cert = create_self_signed_certificate(
            private_key=key,
            subject_dn="/CN=OpenSSL Test",
            validity_days=365,
            key_type='rsa'
        )

        # Сохраняем во временный файл
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False) as f:
            pem_data = cert_to_pem(cert)
            f.write(pem_data)
            cert_file = f.name

        try:
            # Проверяем через OpenSSL
            result = subprocess.run(
                ['openssl', 'x509', '-in', cert_file, '-text', '-noout'],
                capture_output=True,
                text=True
            )

            assert result.returncode == 0
            assert "OpenSSL Test" in result.stdout

            # Проверяем самоподписанность
            verify_result = subprocess.run(
                ['openssl', 'verify', '-CAfile', cert_file, cert_file],
                capture_output=True,
                text=True
            )

            assert verify_result.returncode == 0
            assert "OK" in verify_result.stdout

        finally:
            # Очистка
            import os
            try:
                os.unlink(cert_file)
            except:
                pass
    def test_create_rsa_certificate(self):
        cert = create_self_signed_certificate(
            private_key=self.rsa_key,
            subject_dn="/CN=Test CA",
            validity_days=365,
            key_type='rsa'
        )

        assert cert is not None
        assert cert.subject == cert.issuer
        assert cert.version == x509.Version.v3

    def test_create_ecc_certificate(self):
        cert = create_self_signed_certificate(
            private_key=self.ecc_key,
            subject_dn="/CN=Test ECC CA",
            validity_days=365,
            key_type='ecc'
        )

        assert cert is not None
        assert cert.signature_hash_algorithm.name == hashes.SHA384().name

    def test_basic_constraints(self):
        cert = create_self_signed_certificate(
            private_key=self.rsa_key,
            subject_dn="/CN=Test",
            validity_days=365,
            key_type='rsa'
        )

        ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert ext.critical is True
        assert ext.value.ca is True

    def test_key_certificate_match(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        import os

        key = generate_key('rsa', 4096)
        cert = create_self_signed_certificate(
            private_key=key,
            subject_dn="/CN=Test Match",
            validity_days=365,
            key_type='rsa'
        )

        test_message = b"Test message for signature"

        signature = key.sign(
            test_message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        public_key = cert.public_key()

        try:
            public_key.verify(
                signature,
                test_message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            assert True
        except Exception as e:
            assert False, f"Верификация не удалась: {e}"
    def test_key_usage(self):
        cert = create_self_signed_certificate(
            private_key=self.rsa_key,
            subject_dn="/CN=Test",
            validity_days=365,
            key_type='rsa'
        )

        ext = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ext.critical is True
        assert ext.value.key_cert_sign is True
        assert ext.value.crl_sign is True

    def test_ski_aki_extensions(self):
        cert = create_self_signed_certificate(
            private_key=self.rsa_key,
            subject_dn="/CN=Test",
            validity_days=365,
            key_type='rsa'
        )

        ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)

        assert ski.value.digest == aki.value.key_identifier

    def test_cert_to_pem(self):
        cert = create_self_signed_certificate(
            private_key=self.rsa_key,
            subject_dn="/CN=Test",
            validity_days=365,
            key_type='rsa'
        )

        pem = cert_to_pem(cert)
        assert pem.startswith(b"-----BEGIN CERTIFICATE-----")
        assert pem.endswith(b"-----END CERTIFICATE-----\n")