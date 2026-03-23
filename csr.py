from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from pathlib import Path
from typing import Optional, Tuple, Any

from .crypto_utils import generate_key, parse_dn_string, calculate_ski
from .templates import TemplateFactory, apply_template_to_builder
from .san_utils import create_san_extension, parse_san_list, validate_san_for_template


def generate_intermediate_csr(
        subject_dn: str,
        key_type: str,
        key_size: int,
        pathlen: int = 0
) -> Tuple[Any, Any, bytes]:

    print(f"Генерация CSR для Intermediate CA")
    print(f"  Subject: {subject_dn}")
    print(f"  Key type: {key_type}, size: {key_size}")
    print(f"  Path length constraint: {pathlen}")

    private_key = generate_key(key_type, key_size)

    name_attributes = parse_dn_string(subject_dn)
    subject = x509.Name(name_attributes)

    csr_builder = x509.CertificateSigningRequestBuilder()
    csr_builder = csr_builder.subject_name(subject)

    basic_constraints = x509.BasicConstraints(ca=True, path_length=pathlen)
    csr_builder = csr_builder.add_extension(
        basic_constraints,
        critical=True
    )
    key_usage = x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False
    )
    csr_builder = csr_builder.add_extension(
        key_usage,
        critical=True
    )

    csr = csr_builder.sign(
        private_key,
        hashes.SHA256() if key_type == 'rsa' else hashes.SHA384(),
        default_backend()
    )

    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    print(f" CSR успешно создан")
    return private_key, csr, csr_pem


def sign_csr_with_ca(
        csr: x509.CertificateSigningRequest,
        ca_private_key: Any,
        ca_cert: x509.Certificate,
        validity_days: int,
        key_type: str,
        is_intermediate: bool = True,
        pathlen: int = 0
) -> x509.Certificate:

    from datetime import datetime, timedelta, timezone

    print(f"Подпись CSR с помощью CA: {ca_cert.subject}")

    public_key = csr.public_key()

    subject = csr.subject

    from .crypto_utils import generate_serial_number
    serial_number = generate_serial_number()

    now = datetime.now(timezone.utc)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + timedelta(days=validity_days))
    builder = builder.serial_number(serial_number)
    builder = builder.public_key(public_key)

    ski = calculate_ski(public_key)
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier(ski),
        critical=False
    )

    aki = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(aki.value),
        critical=False
    )

    if is_intermediate:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=pathlen),
            critical=True
        )
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
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
    else:
        pass

    if key_type == 'rsa':
        signature_algorithm = hashes.SHA256()
    else:
        signature_algorithm = hashes.SHA384()

    certificate = builder.sign(
        private_key=ca_private_key,
        algorithm=signature_algorithm,
        backend=default_backend()
    )

    print(f" Сертификат подписан. Серийный номер: {hex(serial_number)}")
    return certificate


def sign_end_entity_certificate(
        csr: x509.CertificateSigningRequest,
        ca_private_key: Any,
        ca_cert: x509.Certificate,
        template_name: str,
        san_list: list,
        validity_days: int,
        key_type: str
) -> x509.Certificate:

    from datetime import datetime, timedelta, timezone
    from .crypto_utils import generate_serial_number

    print(f"Подпись конечного сертификата (шаблон: {template_name})")

    public_key = csr.public_key()

    subject = csr.subject

    san_dict = parse_san_list(san_list) if san_list else {'dns': [], 'ip': [], 'email': [], 'uri': []}

    validate_san_for_template(san_dict, template_name)

    template = TemplateFactory.get_template(template_name)

    if template.requires_san() and not san_dict.get('dns') and not san_dict.get('ip'):
        raise ValueError(f"Шаблон {template_name} требует хотя бы один DNS или IP SAN")

    san_extension = None
    if any(san_dict.values()):
        san_extension = create_san_extension(san_dict)

    serial_number = generate_serial_number()

    now = datetime.now(timezone.utc)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + timedelta(days=validity_days))
    builder = builder.serial_number(serial_number)
    builder = builder.public_key(public_key)

    ski = calculate_ski(public_key)
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier(ski),
        critical=False
    )

    aki = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(aki.value),
        critical=False
    )

    builder = apply_template_to_builder(builder, template, san_extension)

    if key_type == 'rsa':
        signature_algorithm = hashes.SHA256()
    else:
        signature_algorithm = hashes.SHA384()

    certificate = builder.sign(
        private_key=ca_private_key,
        algorithm=signature_algorithm,
        backend=default_backend()
    )

    print(f"Сертификат подписан. Серийный номер: {hex(serial_number)}")
    return certificate


def load_csr_from_file(csr_path: Path) -> x509.CertificateSigningRequest:

    with open(csr_path, 'rb') as f:
        csr_data = f.read()

    csr = x509.load_pem_x509_csr(csr_data, default_backend())
    return csr


def save_csr(csr_pem: bytes, output_path: Path):

    output_path.write_bytes(csr_pem)
    print(f"CSR сохранен: {output_path}")


if __name__ == '__main__':
    print("Тестирование csr.py")

    print("\n--- Тест 1: Генерация Intermediate CSR ---")
    private_key, csr, csr_pem = generate_intermediate_csr(
        subject_dn="/CN=Intermediate CA,O=MicroPKI",
        key_type="rsa",
        key_size=4096,
        pathlen=0
    )
    print(f"CSR создан, длина: {len(csr_pem)} байт")
    print(csr_pem.decode('utf-8')[:200] + "...")

    extensions = csr.extensions
    has_basic = False
    for ext in extensions:
        if ext.oid == ExtensionOID.BASIC_CONSTRAINTS:
            has_basic = True
            print(f"  Basic Constraints в CSR: {ext.value}")
            break
    print(f"  Basic Constraints присутствует: {has_basic}")

    print("\n Тесты пройдены успешно!")