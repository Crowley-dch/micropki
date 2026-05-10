"""
OCSP Responder - RFC 6960
"""

from cryptography import x509
from cryptography.x509.ocsp import (
    OCSPRequestBuilder,
    OCSPResponseBuilder,
    OCSPResponseStatus,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, Dict, Any
import logging

from .revocation import get_reason_code


class OCSPResponder:
    """OCSP responder для проверки статуса сертификатов"""

    def __init__(self, db, ca_cert: x509.Certificate,
                 responder_cert: x509.Certificate, responder_key):
        self.db = db
        self.ca_cert = ca_cert
        self.responder_cert = responder_cert
        self.responder_key = responder_key

        # Предвычисляем хеши CA для быстрого поиска
        self.ca_name_hash = self._hash_name(ca_cert.subject)
        self.ca_key_hash = self._hash_key(ca_cert.public_key())

        self.logger = logging.getLogger('micropki.ocsp')

    def _hash_name(self, name: x509.Name) -> bytes:
        """SHA-1 хеш DN"""
        name_der = name.public_bytes()
        digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
        digest.update(name_der)
        return digest.finalize()

    def _hash_key(self, public_key) -> bytes:
        """SHA-1 хеш публичного ключа"""
        key_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
        digest.update(key_der)
        return digest.finalize()

    def _get_certificate_status(self, serial_hex: str) -> Tuple[str, Optional[str], Optional[str]]:
        """Получает статус сертификата из БД"""
        cert = self.db.get_certificate_by_serial(serial_hex)

        if not cert:
            return 'unknown', None, None

        if cert['status'] == 'valid':
            return 'good', None, None
        elif cert['status'] == 'revoked':
            reason = cert.get('revocation_reason', 'unspecified')
            rev_date = cert.get('revocation_date')
            return 'revoked', reason, rev_date
        else:
            return 'good', None, None

    def parse_request(self, request_data: bytes) -> Tuple[Optional[list], Optional[bytes], Optional[str]]:

        try:
            ocsp_request = x509.ocsp.load_der_ocsp_request(request_data)

            cert_ids = []
            for req in ocsp_request:
                cert_ids.append({
                    'serial': hex(req.serial_number)[2:].upper(),
                    'issuer_name_hash': req.issuer_name_hash,
                    'issuer_key_hash': req.issuer_key_hash,
                    'hash_algorithm': req.hash_algorithm
                })

            # Извлекаем nonce
            nonce = None
            for ext in ocsp_request.extensions:
                if ext.oid.dotted_string == '1.3.6.1.5.5.7.48.1.2':
                    nonce = ext.value
                    break

            return cert_ids, nonce, None

        except Exception as e:
            return None, None, f"Failed to parse OCSP request: {e}"

    def build_response(self, cert_ids: list, nonce: Optional[bytes]) -> bytes:

        builder = OCSPResponseBuilder()
        builder = builder.add_responder_id(
            x509.ocsp.OCSPResponderKeyHash(self.responder_key.public_key())
        )
        builder = builder.produced_at(datetime.now(timezone.utc))

        for cert_id in cert_ids:
            serial_hex = cert_id['serial']

            # Проверяем соответствие issuer
            if cert_id['issuer_name_hash'] != self.ca_name_hash or \
                    cert_id['issuer_key_hash'] != self.ca_key_hash:
                status = 'unknown'
                reason = None
                rev_date = None
            else:
                status, reason, rev_date = self._get_certificate_status(serial_hex)

            # Создаём single response
            if status == 'good':
                single_response = builder.certificate_status(
                    x509.ocsp.OCSPCertStatus.good,
                    x509.ocsp.OCSPCertStatus.good,
                    serial_number=int(serial_hex, 16),
                    revocation_time=None,
                    revocation_reason=None
                )

            elif status == 'revoked':
                rev_dt = datetime.fromisoformat(rev_date) if rev_date else datetime.now(timezone.utc)
                reason_code = get_reason_code(reason) if reason else 0
                single_response = builder.certificate_status(
                    x509.ocsp.OCSPCertStatus.revoked,
                    x509.ocsp.OCSPCertStatus.revoked,
                    serial_number=int(serial_hex, 16),
                    revocation_time=rev_dt,
                    revocation_reason=reason_code
                )
            else:
                single_response = builder.certificate_status(
                    x509.ocsp.OCSPCertStatus.unknown,
                    x509.ocsp.OCSPCertStatus.unknown,
                    serial_number=int(serial_hex, 16),
                    revocation_time=None,
                    revocation_reason=None
                )

            builder = builder.single_response(single_response)

        if nonce:
            builder = builder.add_extension(
                x509.ocsp.OCSPNonce(nonce),
                critical=False
            )

        # Подписываем ответ
        response = builder.build(
            private_key=self.responder_key,
            algorithm=self._get_signature_algorithm(),
            cert_time=datetime.now(timezone.utc),
            responder_certificate=self.responder_cert
        )

        return response.public_bytes(serialization.Encoding.DER)

    def _get_signature_algorithm(self):
        if isinstance(self.responder_key, rsa.RSAPrivateKey):
            return hashes.SHA256()
        else:
            return hashes.SHA384()

    def handle_request(self, request_data: bytes) -> bytes:
        cert_ids, nonce, error = self.parse_request(request_data)

        if error:
            builder = OCSPResponseBuilder()
            builder = builder.responder_id(
                x509.ocsp.OCSPResponderKeyHash(self.responder_key.public_key())
            )
            response = builder.build(
                private_key=self.responder_key,
                algorithm=self._get_signature_algorithm(),
                cert_time=datetime.now(timezone.utc),
                responder_certificate=self.responder_cert
            )
            return response.public_bytes(serialization.Encoding.DER)

        return self.build_response(cert_ids, nonce)


def create_ocsp_signer_certificate(
        ca_cert: x509.Certificate,
        ca_private_key,
        subject_dn: str,
        key_type: str,
        key_size: int,
        validity_days: int,
        san_list: list = None
) -> Tuple[Any, x509.Certificate]:

    from .crypto_utils import generate_key, parse_dn_string, calculate_ski
    from .san_utils import create_san_extension, parse_san_list

    private_key = generate_key(key_type, key_size)
    public_key = private_key.public_key()

    name_attributes = parse_dn_string(subject_dn)
    subject = x509.Name(name_attributes)

    import time
    import os
    serial = (int(time.time()) << 32) | int.from_bytes(os.urandom(4), 'big')

    now = datetime.now(timezone.utc)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + timedelta(days=validity_days))
    builder = builder.serial_number(serial)
    builder = builder.public_key(public_key)

    ski = calculate_ski(public_key)
    builder = builder.add_extension(x509.SubjectKeyIdentifier(ski), critical=False)

    ca_ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski.value),
        critical=False
    )

    builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)

    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )


    from cryptography.x509.oid import ExtendedKeyUsageOID
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),
        critical=False
    )

    if san_list:
        san_dict = parse_san_list(san_list)
        if any(san_dict.values()):
            san_ext = create_san_extension(san_dict)
            builder = builder.add_extension(san_ext, critical=False)

    if isinstance(ca_private_key, rsa.RSAPrivateKey):
        sig_algo = hashes.SHA256()
    else:
        sig_algo = hashes.SHA384()

    certificate = builder.sign(
        private_key=ca_private_key,
        algorithm=sig_algo,
        backend=default_backend()
    )

    return private_key, certificate


def save_unencrypted_key(private_key, output_path):
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    output_path.write_bytes(key_pem)
    output_path.chmod(0o600)