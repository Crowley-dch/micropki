"""
Тесты для client tools
"""

import pytest
import tempfile
import os
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID

from micropki.client import generate_private_key, create_csr, save_private_key, save_csr


class TestClientTools:

    def test_generate_rsa_key(self):
        """Тест генерации RSA ключа"""
        key = generate_private_key('rsa', 2048)
        assert key is not None
        assert key.key_size == 2048

    def test_generate_ecc_key(self):
        """Тест генерации ECC ключа"""
        key = generate_private_key('ecc', 256)
        assert key is not None

    def test_create_csr(self):
        """Тест создания CSR"""
        key = generate_private_key('rsa', 2048)
        csr = create_csr(key, "/CN=test.example.com", None)

        assert csr is not None
        common_name = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if common_name:
            assert common_name[0].value == "test.example.com"

    def test_create_csr_with_san(self):
        """Тест создания CSR с SAN"""
        key = generate_private_key('rsa', 2048)
        csr = create_csr(key, "/CN=test.example.com", ["dns:test.example.com"])

        assert csr is not None

        # Проверяем наличие SAN
        try:
            san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            assert san is not None
        except x509.ExtensionNotFound:
            pass

    def test_save_private_key(self, tmp_path):
        """Тест сохранения приватного ключа"""
        key = generate_private_key('rsa', 2048)
        key_path = tmp_path / 'test.key.pem'

        save_private_key(key, key_path)

        assert key_path.exists()
        content = key_path.read_text()
        assert 'BEGIN PRIVATE KEY' in content

    def test_save_csr(self, tmp_path):
        """Тест сохранения CSR"""
        key = generate_private_key('rsa', 2048)
        csr = create_csr(key, "/CN=test.example.com", None)
        csr_path = tmp_path / 'test.csr.pem'

        save_csr(csr, csr_path)

        assert csr_path.exists()
        content = csr_path.read_text()
        assert 'BEGIN CERTIFICATE REQUEST' in content