import argparse
import sys
import os
from pathlib import Path
import subprocess
from .logger import setup_logger, get_logger
from .ca import CertificateAuthority
from .crypto_utils import load_encrypted_private_key,parse_dn_string
import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509

def validate_key_type(value):
    if value not in ['rsa', 'ecc']:
        raise argparse.ArgumentTypeError(f"Тип ключа должен быть 'rsa' или 'ecc', получено: {value}")
    return value


def validate_pathlen(value):
    try:
        pathlen = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Path length должен быть числом, получено: {value}")

    if pathlen < 0:
        raise argparse.ArgumentTypeError(f"Path length должен быть >= 0, получено: {pathlen}")
    return pathlen


def validate_template(value):
    valid_templates = ['server', 'client', 'code_signing']
    if value not in valid_templates:
        raise argparse.ArgumentTypeError(
            f"Шаблон должен быть одним из: {', '.join(valid_templates)}, получено: {value}"
        )
    return value
def validate_key_size(value):
    try:
        size = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Размер ключа должен быть числом, получено: {value}")

    if size <= 0:
        raise argparse.ArgumentTypeError(f"Размер ключа должен быть положительным, получено: {size}")
    return size


def validate_key_size_with_type(size, key_type):
    if key_type == 'rsa' and size != 4096:
        raise ValueError(f"Для RSA ключа размер должен быть 4096 бит, получено: {size}")
    elif key_type == 'ecc' and size != 384:
        raise ValueError(f"Для ECC ключа размер должен быть 384 бит, получено: {size}")
    return True


def validate_validity_days(value):
    try:
        days = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Срок действия должен быть числом, получено: {value}")

    if days <= 0:
        raise argparse.ArgumentTypeError(f"Срок действия должен быть положительным, получено: {days}")
    return days


def validate_passphrase_file(value):
    path = Path(value)
    if not path.exists():
        raise argparse.ArgumentTypeError(f"Файл с паролем не существует: {value}")
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"Указанный путь не является файлом: {value}")

    try:
        with open(path, 'rb') as f:
            pass
    except Exception as e:
        raise argparse.ArgumentTypeError(f"Не удается прочитать файл с паролем: {e}")

    return path


def validate_out_dir(value):
    path = Path(value)

    if not path.exists():
        try:
            parent = path.parent
            if parent != path and not parent.exists():
                raise argparse.ArgumentTypeError(f"Родительская директория не существует: {parent}")
            if parent.exists() and not os.access(parent, os.W_OK):
                raise argparse.ArgumentTypeError(f"Нет прав на запись в родительскую директорию: {parent}")
        except PermissionError:
            raise argparse.ArgumentTypeError(f"Нет прав на создание директории: {value}")
    else:
        if not path.is_dir():
            raise argparse.ArgumentTypeError(f"Указанный путь существует, но это не директория: {value}")
        if not os.access(path, os.W_OK):
            raise argparse.ArgumentTypeError(f"Нет прав на запись в директорию: {value}")

    return path


def validate_cert_file(value):
    path = Path(value)
    if not path.exists():
        raise argparse.ArgumentTypeError(f"Файл сертификата не существует: {value}")
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"Указанный путь не является файлом: {value}")
    return path


def read_passphrase(passphrase_file: Path) -> bytes:
    with open(passphrase_file, 'rb') as f:
        passphrase = f.read().strip()
    return passphrase


def create_parser():
    parser = argparse.ArgumentParser(
        description="MicroPKI - инструмент для создания инфраструктуры открытых ключей",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  micropki ca init --subject "/CN=My Root CA" --key-type rsa --key-size 4096 --passphrase-file pass.txt --out-dir ./pki
  micropki ca init --subject "CN=ECC Root CA,O=Demo" --key-type ecc --key-size 384 --passphrase-file pass.txt
  micropki ca verify --cert ./pki/certs/ca.cert.pem
  micropki key test --key ./pki/private/ca.key.pem --cert ./pki/certs/ca.cert.pem --passphrase-file pass.txt
        """
    )
    subparsers = parser.add_subparsers(
        title="команды",
        dest="command",
        required=True,
        help="Доступные команды"
    )
    issue_intermediate_parser = subparsers.add_parser(
        'issue-intermediate',
        aliases=['issue intermediate', 'ca issue-intermediate', 'ca issue intermediate'],
        help="Создать промежуточный CA",
        description="Генерирует CSR для Intermediate CA и подписывает его корневым CA"
    )

    issue_intermediate_parser.add_argument(
        '--root-cert',
        type=validate_cert_file,
        required=True,
        help="Путь к сертификату корневого CA (PEM)"
    )

    issue_intermediate_parser.add_argument(
        '--root-key',
        type=validate_cert_file,
        required=True,
        help="Путь к зашифрованному ключу корневого CA (PEM)"
    )

    issue_intermediate_parser.add_argument(
        '--root-pass-file',
        type=validate_passphrase_file,
        required=True,
        help="Файл с паролем для расшифровки ключа корневого CA"
    )

    issue_intermediate_parser.add_argument(
        '--subject',
        required=True,
        help="Distinguished Name для Intermediate CA (например, 'CN=Intermediate CA,O=MicroPKI')"
    )

    issue_intermediate_parser.add_argument(
        '--key-type',
        type=validate_key_type,
        default='rsa',
        choices=['rsa', 'ecc'],
        help="Тип ключа: rsa или ecc (по умолчанию: rsa)"
    )

    issue_intermediate_parser.add_argument(
        '--key-size',
        type=validate_key_size,
        required=True,
        help="Размер ключа (4096 для RSA, 384 для ECC)"
    )

    issue_intermediate_parser.add_argument(
        '--passphrase-file',
        type=validate_passphrase_file,
        required=True,
        help="Файл с паролем для шифрования ключа Intermediate CA"
    )

    issue_intermediate_parser.add_argument(
        '--out-dir',
        type=validate_out_dir,
        default='./pki',
        help="Директория для вывода (по умолчанию: ./pki)"
    )

    issue_intermediate_parser.add_argument(
        '--validity-days',
        type=validate_validity_days,
        default=1825,
        help="Срок действия в днях (по умолчанию: 1825 ≈ 5 лет)"
    )

    issue_intermediate_parser.add_argument(
        '--pathlen',
        type=validate_pathlen,
        default=0,
        help="Ограничение длины пути (pathLenConstraint, по умолчанию: 0)"
    )

    issue_intermediate_parser.add_argument(
        '--log-file',
        help="Путь к файлу лога"
    )

    issue_intermediate_parser.add_argument(
        '--force',
        action='store_true',
        help="Принудительно перезаписывать существующие файлы"
    )

    # Команда 'issue-cert'
    issue_cert_parser = subparsers.add_parser(
        'issue-cert',
        aliases=['issue cert', 'ca issue-cert', 'ca issue cert'],
        help="Выпустить конечный сертификат",
        description="Выпускает сертификат для сервера, клиента или подписи кода"
    )

    issue_cert_parser.add_argument(
        '--ca-cert',
        type=validate_cert_file,
        required=True,
        help="Путь к сертификату CA (корневому или промежуточному)"
    )

    issue_cert_parser.add_argument(
        '--ca-key',
        type=validate_cert_file,
        required=True,
        help="Путь к зашифрованному ключу CA"
    )

    issue_cert_parser.add_argument(
        '--ca-pass-file',
        type=validate_passphrase_file,
        required=True,
        help="Файл с паролем для расшифровки ключа CA"
    )

    issue_cert_parser.add_argument(
        '--template',
        type=validate_template,
        required=True,
        choices=['server', 'client', 'code_signing'],
        help="Шаблон сертификата: server, client, code_signing"
    )

    issue_cert_parser.add_argument(
        '--subject',
        required=True,
        help="Distinguished Name для сертификата (например, 'CN=example.com,O=MicroPKI')"
    )

    issue_cert_parser.add_argument(
        '--san',
        action='append',
        dest='san_list',
        help="Subject Alternative Name (можно указывать несколько раз). "
             "Форматы: dns:example.com, ip:192.168.1.1, email:user@example.com, uri:https://example.com"
    )

    issue_cert_parser.add_argument(
        '--out-dir',
        type=validate_out_dir,
        default='./pki/certs',
        help="Директория для вывода (по умолчанию: ./pki/certs)"
    )

    issue_cert_parser.add_argument(
        '--validity-days',
        type=validate_validity_days,
        default=365,
        help="Срок действия в днях (по умолчанию: 365)"
    )

    issue_cert_parser.add_argument(
        '--csr',
        type=validate_cert_file,
        help="Путь к внешнему CSR (опционально, если не указан - генерируется новый ключ)"
    )

    issue_cert_parser.add_argument(
        '--log-file',
        help="Путь к файлу лога"
    )

    issue_cert_parser.add_argument(
        '--force',
        action='store_true',
        help="Принудительно перезаписывать существующие файлы"
    )
    chain_verify_parser = subparsers.add_parser(
        'chain-verify',
        aliases=['chain verify'],
        help="Проверить цепочку сертификатов"
    )
    chain_verify_parser.add_argument('--leaf', type=validate_cert_file, required=True)
    chain_verify_parser.add_argument('--intermediate', type=validate_cert_file, required=True)
    chain_verify_parser.add_argument('--root', type=validate_cert_file, required=True)
    chain_verify_parser.add_argument('--log-file')
    # Команда ca-init
    ca_init_parser = subparsers.add_parser(
        'ca-init',
        aliases=['ca init'],
        help="Инициализировать корневой центр сертификации",
        description="Создает самоподписанный корневой сертификат CA"
    )

    ca_init_parser.add_argument(
        '--subject',
        required=True,
        help="Distinguished Name (например, '/CN=My Root CA' или 'CN=My Root CA,O=Demo')"
    )

    ca_init_parser.add_argument(
        '--key-type',
        type=validate_key_type,
        default='rsa',
        choices=['rsa', 'ecc'],
        help="Тип ключа: rsa или ecc (по умолчанию: rsa)"
    )

    ca_init_parser.add_argument(
        '--key-size',
        type=validate_key_size,
        required=True,
        help="Размер ключа в битах (4096 для RSA, 384 для ECC)"
    )

    ca_init_parser.add_argument(
        '--passphrase-file',
        type=validate_passphrase_file,
        required=True,
        help="Путь к файлу с паролем для шифрования ключа"
    )

    ca_init_parser.add_argument(
        '--out-dir',
        type=validate_out_dir,
        default='./pki',
        help="Директория для вывода файлов (по умолчанию: ./pki)"
    )

    ca_init_parser.add_argument(
        '--validity-days',
        type=validate_validity_days,
        default=3650,
        help="Срок действия сертификата в днях (по умолчанию: 3650)"
    )

    ca_init_parser.add_argument(
        '--log-file',
        help="Путь к файлу лога (если не указан, лог пишется в stderr)"
    )

    ca_init_parser.add_argument(
        '--force',
        action='store_true',
        help="Принудительно перезаписывать существующие файлы"
    )

    # Команда ca-verify
    ca_verify_parser = subparsers.add_parser(
        'ca-verify',
        aliases=['ca verify'],
        help="Проверить сертификат CA",
        description="Проверяет самоподписанный сертификат CA"
    )

    ca_verify_parser.add_argument(
        '--cert',
        type=validate_cert_file,
        required=True,
        help="Путь к файлу сертификата для проверки"
    )

    ca_verify_parser.add_argument(
        '--log-file',
        help="Путь к файлу лога (если не указан, лог пишется в stderr)"
    )

    # Команда key-test
    key_test_parser = subparsers.add_parser(
        'key-test',
        aliases=['key test'],
        help="Проверить соответствие ключа и сертификата",
        description="Проверяет, что приватный ключ соответствует сертификату"
    )

    key_test_parser.add_argument(
        '--key',
        type=validate_cert_file,
        required=True,
        help="Путь к файлу с зашифрованным приватным ключом"
    )

    key_test_parser.add_argument(
        '--cert',
        type=validate_cert_file,
        required=True,
        help="Путь к файлу сертификата"
    )

    key_test_parser.add_argument(
        '--passphrase-file',
        type=validate_passphrase_file,
        required=True,
        help="Путь к файлу с паролем для расшифровки ключа"
    )

    key_test_parser.add_argument(
        '--log-file',
        help="Путь к файлу лога (если не указан, лог пишется в stderr)"
    )

    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()

    logger = setup_logger(getattr(args, 'log_file', None))

    try:
        if args.command in ['ca-init', 'ca init']:
            try:
                validate_key_size_with_type(args.key_size, args.key_type)
            except ValueError as e:
                logger.error(str(e))
                print(f" Ошибка: {e}", file=sys.stderr)
                return 1

            try:
                passphrase = read_passphrase(args.passphrase_file)
                logger.info(f"Пароль прочитан из файла: {args.passphrase_file}")
            except Exception as e:
                logger.error(f"Ошибка чтения файла с паролем: {e}")
                print(f" Ошибка: Не удалось прочитать файл с паролем - {e}", file=sys.stderr)
                return 1

            try:
                ca = CertificateAuthority(
                    out_dir=str(args.out_dir),
                    log_file=args.log_file
                )

                ca.create_directories()

                files = ca.init_root_ca(
                    subject=args.subject,
                    key_type=args.key_type,
                    key_size=args.key_size,
                    passphrase=passphrase,
                    validity_days=args.validity_days,
                    force=args.force
                )

                print("\n Корневой CA успешно создан!")
                print(f" Директория: {args.out_dir}")
                print(f" Приватный ключ: {files['key_path']}")
                print(f" Сертификат: {files['cert_path']}")
                print(f" Политика: {files['policy_path']}")

                return 0

            except FileExistsError as e:
                logger.error(str(e))
                print(f"\n Ошибка: {e}", file=sys.stderr)
                return 1

            except Exception as e:
                logger.error(f"Ошибка при создании CA: {e}")
                print(f"\n Ошибка: {e}", file=sys.stderr)
                return 1

        elif args.command in ['ca-verify', 'ca verify']:
            cert_path = args.cert
            logger.info(f"Проверка сертификата: {cert_path}")

            try:
                # Проверяем через OpenSSL
                result = subprocess.run(
                    ['openssl', 'x509', '-in', str(cert_path), '-text', '-noout'],
                    capture_output=True,
                    text=True
                )

                if result.returncode != 0:
                    logger.error(f"Ошибка при чтении сертификата: {result.stderr}")
                    print(f" Ошибка при чтении сертификата", file=sys.stderr)
                    return 1

                print("\n Содержимое сертификата:")
                print(result.stdout)

                verify_result = subprocess.run(
                    ['openssl', 'verify', '-CAfile', str(cert_path), str(cert_path)],
                    capture_output=True,
                    text=True
                )

                if verify_result.returncode == 0 and "OK" in verify_result.stdout:
                    print(" Сертификат самоподписанный и валидный")
                    logger.info("Сертификат успешно проверен")
                    return 0
                else:
                    print(" Сертификат не прошел проверку")
                    logger.error(f"Ошибка проверки: {verify_result.stderr}")
                    return 1

            except FileNotFoundError:
                logger.error("OpenSSL не найден. Убедитесь, что OpenSSL установлен")
                print(" OpenSSL не найден. Убедитесь, что OpenSSL установлен", file=sys.stderr)
                return 1

            except Exception as e:
                logger.error(f"Ошибка при проверке сертификата: {e}")
                print(f" Ошибка: {e}", file=sys.stderr)
                return 1

        # Команда: key-test
        elif args.command in ['key-test', 'key test']:
            logger.info("Проверка соответствия ключа и сертификата")

            try:
                # Читаем пароль
                passphrase = read_passphrase(args.passphrase_file)

                # Загружаем ключ
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import padding
                from cryptography import x509
                from .crypto_utils import load_encrypted_private_key, encrypt_private_key

                # Загружаем сертификат
                with open(args.cert, 'rb') as f:
                    cert_data = f.read()
                cert = x509.load_pem_x509_certificate(cert_data)

                # Загружаем и расшифровываем ключ
                private_key = load_encrypted_private_key(args.key, passphrase)

                # Тестовое сообщение
                test_message = b"MicroPKI test message for key verification"

                # Подписываем приватным ключом
                signature = private_key.sign(
                    test_message,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )

                # Проверяем публичным ключом из сертификата
                cert.public_key().verify(
                    signature,
                    test_message,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )

                print("\n Ключ соответствует сертификату!")
                print(f" Ключ: {args.key}")
                print(f" Сертификат: {args.cert}")
                logger.info("Ключ успешно проверен на соответствие сертификату")
                return 0

            except Exception as e:
                logger.error(f"Ошибка при проверке ключа: {e}")
                print(f"\n Ключ НЕ соответствует сертификату: {e}", file=sys.stderr)
                return 1
        elif args.command in ['issue-intermediate', 'issue intermediate', 'ca issue-intermediate',
                              'ca issue intermediate']:
            from .crypto_utils import load_encrypted_private_key, encrypt_private_key, parse_dn_string
            from .certificates import cert_to_pem
            from .csr import generate_intermediate_csr, sign_csr_with_ca, load_csr_from_file
            from cryptography import x509
            import datetime
            from cryptography.hazmat.backends import default_backend

            logger.info(" СОЗДАНИЕ ПРОМЕЖУТОЧНОГО CA ")

            try:
                logger.info("Загрузка корневого CA")
                with open(args.root_cert, 'rb') as f:
                    root_cert_data = f.read()
                root_cert = x509.load_pem_x509_certificate(root_cert_data)

                root_passphrase = read_passphrase(args.root_pass_file)
                root_key = load_encrypted_private_key(args.root_key, root_passphrase)
                logger.info(f"Корневой CA загружен: {root_cert.subject}")

                basic_constraints = root_cert.extensions.get_extension_for_class(x509.BasicConstraints)
                if not basic_constraints.value.ca:
                    raise ValueError("Указанный сертификат не является CA")

                logger.info("Генерация ключа и CSR для Intermediate CA")
                intermediate_key, csr, csr_pem = generate_intermediate_csr(
                    subject_dn=args.subject,
                    key_type=args.key_type,
                    key_size=args.key_size,
                    pathlen=args.pathlen
                )

                csr_dir = Path(args.out_dir) / 'csrs'
                csr_dir.mkdir(parents=True, exist_ok=True)
                csr_path = csr_dir / 'intermediate.csr.pem'
                csr_path.write_bytes(csr_pem)
                logger.info(f"CSR сохранен: {csr_path}")

                logger.info("Подпись CSR корневым CA")
                intermediate_cert = sign_csr_with_ca(
                    csr=csr,
                    ca_private_key=root_key,
                    ca_cert=root_cert,
                    validity_days=args.validity_days,
                    key_type=args.key_type,
                    is_intermediate=True,
                    pathlen=args.pathlen
                )

                private_dir = Path(args.out_dir) / 'private'
                private_dir.mkdir(parents=True, exist_ok=True)

                intermediate_key_path = private_dir / 'intermediate.key.pem'
                if intermediate_key_path.exists() and not args.force:
                    raise FileExistsError(f"Файл уже существует: {intermediate_key_path}. Используйте --force")

                intermediate_passphrase = read_passphrase(args.passphrase_file)
                encrypted_key = encrypt_private_key(intermediate_key, intermediate_passphrase)
                intermediate_key_path.write_bytes(encrypted_key)

                try:
                    os.chmod(intermediate_key_path, 0o600)
                except Exception:
                    pass
                logger.info(f"Ключ Intermediate CA сохранен: {intermediate_key_path}")

                # 8. Сохраняем сертификат Intermediate CA
                certs_dir = Path(args.out_dir) / 'certs'
                certs_dir.mkdir(parents=True, exist_ok=True)

                cert_path = certs_dir / 'intermediate.cert.pem'
                if cert_path.exists() and not args.force:
                    raise FileExistsError(f"Файл уже существует: {cert_path}. Используйте --force")

                cert_pem = cert_to_pem(intermediate_cert)
                cert_path.write_bytes(cert_pem)
                logger.info(f"Сертификат Intermediate CA сохранен: {cert_path}")

                policy_path = Path(args.out_dir) / 'policy.txt'
                if policy_path.exists():
                    with open(policy_path, 'a', encoding='utf-8') as f:
                        f.write(f"\n\n--- INTERMEDIATE CA ---\n")
                        f.write(f"Subject: {args.subject}\n")
                        f.write(f"Serial Number: {hex(intermediate_cert.serial_number)}\n")
                        f.write(
                            f"Validity: {intermediate_cert.not_valid_before} - {intermediate_cert.not_valid_after}\n")
                        f.write(f"Key: {args.key_type.upper()}-{args.key_size}\n")
                        f.write(f"Path Length: {args.pathlen}\n")
                        f.write(f"Issuer: {root_cert.subject}\n")
                        f.write(f"Created: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    logger.info(f"policy.txt обновлен: {policy_path}")

                print("\n Промежуточный CA успешно создан!")
                print(f" Директория: {args.out_dir}")
                print(f" Приватный ключ: {intermediate_key_path}")
                print(f" Сертификат: {cert_path}")
                print(f" CSR: {csr_path}")

                return 0

            except FileExistsError as e:
                logger.error(str(e))
                print(f"\n Ошибка: {e}", file=sys.stderr)
                return 1
            except Exception as e:
                logger.error(f"Ошибка при создании Intermediate CA: {e}")
                print(f"\n Ошибка: {e}", file=sys.stderr)
                return 1

        elif args.command in ['chain-verify', 'chain verify']:
            from .chain import validate_full_chain
            is_valid = validate_full_chain(args.leaf, args.intermediate, args.root)
            return 0 if is_valid else 1

        elif args.command in ['issue-cert', 'issue cert', 'ca issue-cert', 'ca issue cert']:
            from .crypto_utils import load_encrypted_private_key, generate_key, encrypt_private_key, parse_dn_string
            from .certificates import cert_to_pem
            from .csr import sign_end_entity_certificate, load_csr_from_file
            from .templates import TemplateFactory
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import hashes
            import datetime

            logger.info(" ВЫПУСК КОНЕЧНОГО СЕРТИФИКАТА ")

            try:
                logger.info("Загрузка CA")
                with open(args.ca_cert, 'rb') as f:
                    ca_cert_data = f.read()
                ca_cert = x509.load_pem_x509_certificate(ca_cert_data)

                ca_passphrase = read_passphrase(args.ca_pass_file)
                ca_key = load_encrypted_private_key(args.ca_key, ca_passphrase)
                logger.info(f"CA загружен: {ca_cert.subject}")

                ca_key_type = 'rsa' if 'RSA' in str(type(ca_key)) else 'ecc'

                template = TemplateFactory.get_template(args.template)
                logger.info(f"Шаблон: {args.template}")

                if args.csr:
                    logger.info(f"Загрузка внешнего CSR: {args.csr}")
                    csr = load_csr_from_file(args.csr)
                    # Извлекаем subject из CSR
                    subject = csr.subject
                    private_key = None
                    key_path = None
                else:
                    logger.info("Генерация новой ключевой пары")
                    if args.template == 'server':
                        key_size = 2048
                    else:
                        key_size = 2048  # Стандарт
                    private_key = generate_key('rsa', key_size)  # Для простоты используем RSA
                    subject = x509.Name(parse_dn_string(args.subject))

                    from cryptography.x509 import CertificateSigningRequestBuilder
                    csr_builder = CertificateSigningRequestBuilder()
                    csr_builder = csr_builder.subject_name(subject)
                    csr = csr_builder.sign(private_key, hashes.SHA256(), default_backend())

                san_list = args.san_list if hasattr(args, 'san_list') and args.san_list else []

                logger.info(f"Подпись сертификата (действителен {args.validity_days} дней)")
                certificate = sign_end_entity_certificate(
                    csr=csr,
                    ca_private_key=ca_key,
                    ca_cert=ca_cert,
                    template_name=args.template,
                    san_list=san_list,
                    validity_days=args.validity_days,
                    key_type=ca_key_type
                )

                common_name = None
                for attr in subject:
                    if attr.oid._name == 'commonName':
                        common_name = attr.value
                        break
                if not common_name:
                    common_name = f"cert_{hex(certificate.serial_number)[2:]}"

                common_name = common_name.replace('*', 'star').replace(' ', '_').replace('/', '_')

                certs_dir = Path(args.out_dir)
                certs_dir.mkdir(parents=True, exist_ok=True)

                cert_path = certs_dir / f"{common_name}.cert.pem"
                if cert_path.exists() and not args.force:
                    raise FileExistsError(f"Файл уже существует: {cert_path}. Используйте --force")

                cert_pem = cert_to_pem(certificate)
                cert_path.write_bytes(cert_pem)
                logger.info(f"Сертификат сохранен: {cert_path}")

                # 10. Сохраняем приватный ключ (если сгенерирован)
                if private_key and not args.csr:
                    key_path = certs_dir / f"{common_name}.key.pem"
                    if key_path.exists() and not args.force:
                        raise FileExistsError(f"Файл уже существует: {key_path}. Используйте --force")

                    # Сохраняем незашифрованный ключ
                    unencrypted_key = private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                    key_path.write_bytes(unencrypted_key)

                    # Устанавливаем права 600
                    try:
                        os.chmod(key_path, 0o600)
                    except Exception:
                        pass

                    logger.warning(f" Приватный ключ сохранен НЕЗАШИФРОВАННЫМ: {key_path}")
                    print(f"\n ВНИМАНИЕ: Приватный ключ сохранен НЕЗАШИФРОВАННЫМ: {key_path}")

                # 11. Выводим информацию
                print("\n Сертификат успешно выпущен!")
                print(f" Директория: {args.out_dir}")
                print(f" Шаблон: {args.template}")
                print(f" Subject: {subject}")
                if san_list:
                    print(f" SAN: {', '.join(san_list)}")
                print(f" Сертификат: {cert_path}")
                if key_path:
                    print(f" Приватный ключ: {key_path}")
                print(f" Действителен до: {certificate.not_valid_after}")

                return 0

            except FileExistsError as e:
                logger.error(str(e))
                print(f"\n Ошибка: {e}", file=sys.stderr)
                return 1
            except ValueError as e:
                logger.error(str(e))
                print(f"\n Ошибка валидации: {e}", file=sys.stderr)
                return 1
            except Exception as e:
                logger.error(f"Ошибка при выпуске сертификата: {e}")
                print(f"\n Ошибка: {e}", file=sys.stderr)
                return 1
        else:
            logger.error(f"Неизвестная команда: {args.command}")
            print(f" Ошибка: Неизвестная команда '{args.command}'. Используйте 'ca init', 'ca verify' или 'key test'",
                  file=sys.stderr)
            return 1

    except KeyboardInterrupt:
        logger.info("Операция прервана пользователем")
        print("\nОперация прервана", file=sys.stderr)
        return 1

    except Exception as e:
        logger.error(f"Необработанная ошибка: {e}")
        print(f"\n Непредвиденная ошибка: {e}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())