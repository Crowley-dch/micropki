import pytest
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from micropki.csr import generate_intermediate_csr, sign_csr_with_ca
from micropki.crypto_utils import generate_key, encrypt_private_key
from micropki.certificates import create_self_signed_certificate


class TestCSR:

    def test_generate_intermediate_csr(self):
        private_key, csr, csr_pem = generate_intermediate_csr(
            subject_dn="/CN=Test Intermediate CA",
            key_type="rsa",
            key_size=4096,
            pathlen=0
        )

        assert private_key is not None
        assert csr is not None
        assert csr_pem is not None
        assert b"BEGIN CERTIFICATE REQUEST" in csr_pem

        has_basic = False
        for ext in csr.extensions:
            if ext.oid == ExtensionOID.BASIC_CONSTRAINTS:
                has_basic = True
                assert ext.value.ca is True
                break
        assert has_basic

    def test_sign_csr_with_ca(self):
        root_key = generate_key('rsa', 4096)
        root_cert = create_self_signed_certificate(
            private_key=root_key,
            subject_dn="/CN=Root CA",
            validity_days=365,
            key_type='rsa'
        )

        inter_key, csr, _ = generate_intermediate_csr(
            subject_dn="/CN=Intermediate CA",
            key_type="rsa",
            key_size=4096,
            pathlen=0
        )

        cert = sign_csr_with_ca(
            csr=csr,
            ca_private_key=root_key,
            ca_cert=root_cert,
            validity_days=365,
            key_type='rsa',
            is_intermediate=True,
            pathlen=0
        )

        assert cert is not None
        assert cert.subject == csr.subject
        assert cert.issuer == root_cert.subject