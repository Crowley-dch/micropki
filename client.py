import argparse
import sys
import os
from pathlib import Path
import logging
import json
from datetime import datetime
from typing import Optional, List, Dict, Any
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

from .validation import PathValidator, ValidationStatus
from .revocation_check import RevocationChecker, RevocationStatus, check_certificate_status
from .logger import setup_logger


def generate_private_key(key_type: str, key_size: int):
    """Генерирует приватный ключ"""
    if key_type == 'rsa':
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
    else:  # ecc
        curves = {256: ec.SECP256R1(), 384: ec.SECP384R1()}
        curve = curves.get(key_size, ec.SECP256R1())
        return ec.generate_private_key(curve, default_backend())


def create_csr(private_key, subject_dn: str, san_list: list = None) -> x509.CertificateSigningRequest:
    """Создаёт CSR из приватного ключа"""
    from .crypto_utils import parse_dn_string
    from .san_utils import create_san_extension, parse_san_list

    name_attributes = parse_dn_string(subject_dn)
    subject = x509.Name(name_attributes)

    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(subject)

    if san_list:
        san_dict = parse_san_list(san_list)
        if any(san_dict.values()):
            san_ext = create_san_extension(san_dict)
            builder = builder.add_extension(san_ext, critical=False)

    csr = builder.sign(private_key, hashes.SHA256(), default_backend())
    return csr


def save_private_key(private_key, path: Path):
    """Сохраняет приватный ключ незашифрованным"""
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    path.write_bytes(key_pem)
    path.chmod(0o600)


def save_csr(csr: x509.CertificateSigningRequest, path: Path):
    """Сохраняет CSR в PEM"""
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    path.write_bytes(csr_pem)


def request_certificate(csr_path: Path, template: str, ca_url: str,
                        api_key: str = None) -> bytes:
    """Отправляет CSR в CA и получает сертификат"""
    import requests

    csr_data = csr_path.read_bytes()

    url = f"{ca_url.rstrip('/')}/request-cert"
    params = {'template': template}

    headers = {'Content-Type': 'application/x-pem-file'}
    if api_key:
        headers['X-API-Key'] = api_key

    response = requests.post(url, params=params, data=csr_data, headers=headers, timeout=30)

    if response.status_code != 201:
        raise Exception(f"Certificate request failed: HTTP {response.status_code}\n{response.text}")

    return response.content


def validate_certificate(cert_path: Path, trusted_paths: List[str],
                         untrusted_paths: List[str],
                         check_revocation: bool = False,
                         ocsp_url: str = None,
                         crl_url: str = None,
                         validation_time: datetime = None) -> dict:
    """Проверяет сертификат и возвращает результат"""
    from .validation import PathValidator
    from .revocation_check import RevocationChecker

    with open(cert_path, 'rb') as f:
        leaf = x509.load_pem_x509_certificate(f.read())

    untrusted = []
    for path in untrusted_paths:
        with open(path, 'rb') as f:
            untrusted.append(x509.load_pem_x509_certificate(f.read()))

    trusted = []
    for path in trusted_paths:
        with open(path, 'rb') as f:
            trusted.append(x509.load_pem_x509_certificate(f.read()))

    validator = PathValidator(validation_time)
    result = validator.validate_chain(leaf, untrusted, trusted)

    output = {
        'overall_status': result.overall_status.value,
        'steps': [{'name': s.name, 'status': s.status.value, 'message': s.message} for s in result.steps],
        'chain_length': len(result.chain),
        'revocation': None
    }

    if check_revocation and result.overall_status == ValidationStatus.PASS:
        issuer = result.chain[1] if len(result.chain) > 1 else None
        if issuer:
            checker = RevocationChecker()
            rev_result = checker.check_status(leaf, issuer, ocsp_url, None, crl_url)
            output['revocation'] = {
                'status': rev_result.status.value,
                'method': rev_result.method,
                'message': rev_result.message,
                'revocation_date': rev_result.revocation_date,
                'revocation_reason': rev_result.revocation_reason
            }

    return output


def add_client_commands(subparsers):
    """Добавляет client подкоманды в парсер"""

    # client gen-csr
    gen_csr_parser = subparsers.add_parser(
        'gen-csr',
        aliases=['client gen-csr'],
        help="Generate private key and CSR"
    )
    gen_csr_parser.add_argument('--subject', required=True)
    gen_csr_parser.add_argument('--key-type', default='rsa', choices=['rsa', 'ecc'])
    gen_csr_parser.add_argument('--key-size', type=int, default=2048)
    gen_csr_parser.add_argument('--san', action='append', dest='san_list')
    gen_csr_parser.add_argument('--out-key', default='./key.pem')
    gen_csr_parser.add_argument('--out-csr', default='./request.csr.pem')
    gen_csr_parser.add_argument('--log-file')

    # client request-cert
    request_cert_parser = subparsers.add_parser(
        'request-cert',
        aliases=['client request-cert'],
        help="Submit CSR to CA and get certificate"
    )
    request_cert_parser.add_argument('--csr', required=True)
    request_cert_parser.add_argument('--template', required=True, choices=['server', 'client', 'code_signing'])
    request_cert_parser.add_argument('--ca-url', required=True)
    request_cert_parser.add_argument('--api-key')
    request_cert_parser.add_argument('--out-cert', default='./cert.pem')
    request_cert_parser.add_argument('--log-file')

    # client validate
    validate_parser = subparsers.add_parser(
        'validate',
        aliases=['client validate'],
        help="Validate certificate chain"
    )
    validate_parser.add_argument('--cert', required=True)
    validate_parser.add_argument('--untrusted', action='append', default=[])
    validate_parser.add_argument('--trusted', action='append', default=['./pki/certs/ca.cert.pem'])
    validate_parser.add_argument('--crl')
    validate_parser.add_argument('--ocsp')
    validate_parser.add_argument('--mode', default='full', choices=['chain', 'full'])
    validate_parser.add_argument('--format', default='text', choices=['text', 'json'])
    validate_parser.add_argument('--log-file')

    # client check-status
    check_status_parser = subparsers.add_parser(
        'check-status',
        aliases=['client check-status'],
        help="Check certificate revocation status"
    )
    check_status_parser.add_argument('--cert', required=True)
    check_status_parser.add_argument('--ca-cert', required=True)
    check_status_parser.add_argument('--crl')
    check_status_parser.add_argument('--ocsp-url')
    check_status_parser.add_argument('--log-file')


def handle_gen_csr(args, logger):
    logger.info(f"Generating {args.key_type} key ({args.key_size} bits)")

    private_key = generate_private_key(args.key_type, args.key_size)
    csr = create_csr(private_key, args.subject, args.san_list)

    key_path = Path(args.out_key)
    csr_path = Path(args.out_csr)

    save_private_key(private_key, key_path)
    save_csr(csr, csr_path)

    print(f"\n Private key saved: {key_path}")
    print(f" CSR saved: {csr_path}")
    print(f" Private key is UNENCRYPTED")
    print(f"\nTo request a certificate:")
    print(f"  micropki client request-cert --csr {csr_path} --template server --ca-url http://localhost:8080")

    return 0


def handle_request_cert(args, logger):
    """Обработчик client request-cert"""
    logger.info(f"Requesting certificate for {args.csr} using template {args.template}")

    csr_path = Path(args.csr)
    if not csr_path.exists():
        print(f" CSR file not found: {csr_path}", file=sys.stderr)
        return 1

    try:
        cert_pem = request_certificate(csr_path, args.template, args.ca_url, args.api_key)
        cert_path = Path(args.out_cert)
        cert_path.write_bytes(cert_pem)

        print(f"\n Certificate saved: {cert_path}")

        # Показываем информацию о сертификате
        cert = x509.load_pem_x509_certificate(cert_pem)
        print(f"   Subject: {cert.subject}")
        print(f"   Serial: {hex(cert.serial_number)}")
        print(f"   Valid: {cert.not_valid_before_utc} - {cert.not_valid_after_utc}")

        return 0
    except Exception as e:
        logger.error(f"Certificate request failed: {e}")
        print(f" {e}", file=sys.stderr)
        return 1


def handle_validate(args, logger):
    logger.info(f"Validating certificate: {args.cert}")

    check_revocation = (args.mode == 'full')

    result = validate_certificate(
        cert_path=Path(args.cert),
        trusted_paths=args.trusted,
        untrusted_paths=args.untrusted,
        check_revocation=check_revocation,
        ocsp_url=args.ocsp,
        crl_url=args.crl
    )

    if args.format == 'json':
        print(json.dumps(result, indent=2))
    else:
        print(f"CERTIFICATE VALIDATION RESULT")
        print(f"Overall status: {' PASS' if result['overall_status'] == 'pass' else '❌ FAIL'}")
        print(f"Chain length: {result['chain_length']}")
        print(f"\nValidation steps:")
        for step in result['steps']:
            status_icon = '' if step['status'] == 'pass' else '❌' if step['status'] == 'fail' else '⚠️'
            print(f"  {status_icon} {step['name']}: {step['message']}")

        if result.get('revocation'):
            rev = result['revocation']
            status_icon = '✅' if rev['status'] == 'good' else '❌' if rev['status'] == 'revoked' else '⚠️'
            print(f"\nRevocation status: {status_icon} {rev['status'].upper()}")
            print(f"  Method: {rev['method']}")
            print(f"  {rev['message']}")
            if rev.get('revocation_date'):
                print(f"  Revocation date: {rev['revocation_date']}")
            if rev.get('revocation_reason'):
                print(f"  Reason: {rev['revocation_reason']}")

    return 0 if result['overall_status'] == 'pass' else 1


def handle_check_status(args, logger):
    logger.info(f"Checking revocation status: {args.cert}")

    result = check_certificate_status(
        cert_path=args.cert,
        issuer_path=args.ca_cert,
        ocsp_url=args.ocsp_url,
        crl_url=args.crl
    )

    print(f"REVOCATION STATUS")

    status_icon = '' if result.status == RevocationStatus.GOOD else '❌' if result.status == RevocationStatus.REVOKED else '⚠️'
    print(f"Status: {status_icon} {result.status.value.upper()}")
    print(f"Method: {result.method}")
    print(f"Message: {result.message}")

    if result.revocation_date:
        print(f"Revocation date: {result.revocation_date}")
    if result.revocation_reason:
        print(f"Reason: {result.revocation_reason}")

    return 0 if result.status in [RevocationStatus.GOOD, RevocationStatus.UNKNOWN] else 1