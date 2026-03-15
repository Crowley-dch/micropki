import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
from pathlib import Path

def generate_rsa_key(key_size: int = 4096):
    if key_size != 4096:
        raise ValueError(f"Для RSA допустим только размер 4096, получено: {key_size}")

    print(f"Генерация RSA ключа {key_size} бит...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    return private_key


def generate_ecc_key(key_size: int = 384):
    if key_size != 384:
        raise ValueError(f"Для ECC допустима только кривая P-384 (key_size=384), получено: {key_size}")

    print("Генерация ECC ключа на кривой P-384...")
    private_key = ec.generate_private_key(
        curve=ec.SECP384R1(),
        backend=default_backend()
    )
    return private_key


def generate_key(key_type: str, key_size: int):

    if key_type == 'rsa':
        return generate_rsa_key(key_size)
    elif key_type == 'ecc':
        return generate_ecc_key(key_size)
    else:
        raise ValueError(f"Неподдерживаемый тип ключа: {key_type}")


def encrypt_private_key(private_key, passphrase: bytes):

    print("Шифрование приватного ключа...")

    # Для RSA и ECC ключей используем одинаковый метод
    encrypted_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
    )

    return encrypted_key


def calculate_ski(public_key):

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    digest.update(public_bytes)
    ski = digest.finalize()

    return ski


def parse_dn_string(dn_string: str):

    attributes = []

    dn_string = dn_string.strip()

    if dn_string.startswith('/'):

        parts = dn_string[1:].split('/')
    else:
        parts = dn_string.split(',')

    for part in parts:
        part = part.strip()
        if not part:
            continue

        if '=' not in part:
            raise ValueError(f"Некорректный компонент DN (нет знака '='): {part}")

        key, value = part.split('=', 1)
        key = key.strip().upper()
        value = value.strip()

        oid_map = {
            'CN': NameOID.COMMON_NAME,
            'O': NameOID.ORGANIZATION_NAME,
            'OU': NameOID.ORGANIZATIONAL_UNIT_NAME,
            'C': NameOID.COUNTRY_NAME,
            'ST': NameOID.STATE_OR_PROVINCE_NAME,
            'L': NameOID.LOCALITY_NAME,
            'E': NameOID.EMAIL_ADDRESS,
            'EMAILADDRESS': NameOID.EMAIL_ADDRESS,
            'DC': NameOID.DOMAIN_COMPONENT,
        }

        if key not in oid_map:
            raise ValueError(f"Неподдерживаемый компонент DN: {key}")

        attributes.append(x509.NameAttribute(oid_map[key], value))

    if not attributes:
        raise ValueError("DN не содержит атрибутов")

    return attributes


def load_encrypted_private_key(key_path: Path, passphrase: bytes):

    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.backends import default_backend

    print(f"Загрузка зашифрованного ключа из: {key_path}")

    encrypted_key = key_path.read_bytes()

    private_key = load_pem_private_key(
        encrypted_key,
        password=passphrase,
        backend=default_backend()
    )

    print("Ключ успешно расшифрован")
    return private_key

def generate_serial_number():

    random_bytes = os.urandom(19)
    serial = int.from_bytes(random_bytes, byteorder='big')
    return serial


if __name__ == '__main__':
    print("Тестирование crypto_utils.py")

    rsa_key = generate_rsa_key(4096)
    print(f"RSA ключ сгенерирован: {type(rsa_key)}")

    ecc_key = generate_ecc_key(384)
    print(f"ECC ключ сгенерирован: {type(ecc_key)}")

    passphrase = b"test-password"
    encrypted = encrypt_private_key(rsa_key, passphrase)
    print(f"Ключ зашифрован: {len(encrypted)} байт")

    dn1 = parse_dn_string("/CN=Test CA/O=MicroPKI/C=US")
    print(f"DN1 распарсен: {dn1}")

    dn2 = parse_dn_string("CN=Test CA,O=MicroPKI,C=US")
    print(f"DN2 распарсен: {dn2}")

    serial = generate_serial_number()
    print(f"Серийный номер: {serial}")