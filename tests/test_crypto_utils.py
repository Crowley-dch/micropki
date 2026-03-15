import pytest
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from micropki.crypto_utils import (
    generate_rsa_key,
    generate_ecc_key,
    generate_key,
    encrypt_private_key,
    calculate_ski,
    parse_dn_string,
    generate_serial_number
)


class TestCryptoUtils:

    def test_generate_rsa_key(self):
        key = generate_rsa_key(4096)
        assert key is not None
        assert key.key_size == 4096

        from cryptography.hazmat.primitives.asymmetric import rsa
        assert isinstance(key, rsa.RSAPrivateKey)

    def test_generate_rsa_key_wrong_size(self):
        with pytest.raises(ValueError, match="Для RSA допустим только размер 4096"):
            generate_rsa_key(2048)

    def test_generate_ecc_key(self):
        key = generate_ecc_key(384)
        assert key is not None

        from cryptography.hazmat.primitives.asymmetric import ec
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert isinstance(key.curve, ec.SECP384R1)

    def test_generate_ecc_key_wrong_size(self):
        with pytest.raises(ValueError, match="Для ECC допустима только кривая P-384"):
            generate_ecc_key(256)

    def test_generate_key_rsa(self):
        key = generate_key('rsa', 4096)
        from cryptography.hazmat.primitives.asymmetric import rsa
        assert isinstance(key, rsa.RSAPrivateKey)

    def test_generate_key_ecc(self):
        key = generate_key('ecc', 384)
        from cryptography.hazmat.primitives.asymmetric import ec
        assert isinstance(key, ec.EllipticCurvePrivateKey)

    def test_encrypt_private_key(self):
        key = generate_rsa_key(4096)
        passphrase = b"test-password"

        encrypted = encrypt_private_key(key, passphrase)

        assert encrypted is not None
        assert b"-----BEGIN ENCRYPTED PRIVATE KEY-----" in encrypted

        # Проверяем, что можно расшифровать
        decrypted = serialization.load_pem_private_key(
            encrypted, passphrase, default_backend()
        )
        assert decrypted is not None

    def test_calculate_ski(self):
        key = generate_rsa_key(4096)
        ski = calculate_ski(key.public_key())

        assert len(ski) == 20  # SHA-1

    def test_parse_dn_string_slash_format(self):
        dn = "/CN=Test CA/O=MicroPKI/C=US"
        result = parse_dn_string(dn)

        assert len(result) == 3
        assert result[0].value == 'Test CA'
        assert result[1].value == 'MicroPKI'
        assert result[2].value == 'US'

    def test_parse_dn_string_comma_format(self):
        dn = "CN=Test CA,O=MicroPKI,C=US"
        result = parse_dn_string(dn)

        assert len(result) == 3
        assert result[0].value == 'Test CA'

    def test_generate_serial_number(self):
        serial = generate_serial_number()
        assert serial > 0

        # Проверяем лимит в 159 бит
        max_serial = (1 << 159) - 1
        assert serial <= max_serial