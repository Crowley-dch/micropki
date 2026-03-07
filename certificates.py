from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import datetime

from .crypto_utils import calculate_ski, generate_serial_number, parse_dn_string


def create_self_signed_certificate(
        private_key,
        subject_dn: str,
        validity_days: int,
        key_type: str
):

    print(f"Создание самоподписанного сертификата для: {subject_dn}")

    name_attributes = parse_dn_string(subject_dn)
    subject = x509.Name(name_attributes)
    issuer = subject  # самоподписанный

    public_key = private_key.public_key()

    ski = calculate_ski(public_key)

    serial_number = generate_serial_number()

    now = datetime.datetime.now(datetime.timezone.utc)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + datetime.timedelta(days=validity_days))
    builder = builder.serial_number(serial_number)
    builder = builder.public_key(public_key)


    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    )

    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,  # опционально, но добавим
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )

    builder = builder.add_extension(
        x509.SubjectKeyIdentifier(ski),
        critical=False
    )

    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            x509.SubjectKeyIdentifier(ski)
        ),
        critical=False
    )

    if key_type == 'rsa':
        signature_algorithm = hashes.SHA256()
    elif key_type == 'ecc':
        signature_algorithm = hashes.SHA384()
    else:
        raise ValueError(f"Неподдерживаемый тип ключа: {key_type}")

    certificate = builder.sign(
        private_key=private_key,
        algorithm=signature_algorithm,
        backend=default_backend()
    )

    print(f"Сертификат создан. Серийный номер: {hex(serial_number)}")
    return certificate


def cert_to_pem(certificate):

    return certificate.public_bytes(encoding=serialization.Encoding.PEM)


if __name__ == '__main__':
    from .crypto_utils import generate_key

    print("Тестирование certificates.py")

    test_key = generate_key('rsa', 4096)

    cert = create_self_signed_certificate(
        private_key=test_key,
        subject_dn="/CN=Test CA/O=MicroPKI/C=US",
        validity_days=365,
        key_type='rsa'
    )

    pem_cert = cert_to_pem(cert)
    print(f"Сертификат в PEM формате ({len(pem_cert)} байт):")
    print(pem_cert.decode('utf-8')[:200] + "...")