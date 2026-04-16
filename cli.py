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

def validate_db_path(value):
    path = Path(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    return str(path)

def validate_serial(value):
    try:
        int(value, 16)
        return value.upper()
    except ValueError:
        raise argparse.ArgumentTypeError(f"Неверный формат серийного номера: {value}. Ожидается hex строка")

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

def validate_reason(value):
    valid_reasons = [
        'unspecified', 'keyCompromise', 'cACompromise', 'affiliationChanged',
        'superseded', 'cessationOfOperation', 'certificateHold',
        'removeFromCRL', 'privilegeWithdrawn', 'aACompromise'
    ]
    if value not in valid_reasons:
        raise argparse.ArgumentTypeError(
            f"Причина отзыва должна быть одной из: {', '.join(valid_reasons)}, получено: {value}"
        )
    return value
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
    # Команда 'db init'
    db_init_parser = subparsers.add_parser(
        'db-init',
        aliases=['db init'],
        help="Инициализировать базу данных сертификатов"
    )
    db_init_parser.add_argument(
        '--db-path',
        type=validate_db_path,
        default='./pki/micropki.db',
        help="Путь к SQLite базе данных (по умолчанию: ./pki/micropki.db)"
    )
    db_init_parser.add_argument('--log-file')

    # Команда 'ca list-certs'
    list_certs_parser = subparsers.add_parser(
        'list-certs',
        aliases=['ca list-certs'],
        help="Список сертификатов в базе данных"
    )
    list_certs_parser.add_argument(
        '--status',
        choices=['valid', 'revoked', 'expired'],
        help="Фильтр по статусу"
    )
    list_certs_parser.add_argument(
        '--format',
        choices=['table', 'json', 'csv'],
        default='table',
        help="Формат вывода (по умолчанию: table)"
    )
    list_certs_parser.add_argument(
        '--db-path',
        type=validate_db_path,
        default='./pki/micropki.db',
        help="Путь к SQLite базе данных"
    )
    list_certs_parser.add_argument('--log-file')

    # Команда 'ca show-cert'
    show_cert_parser = subparsers.add_parser(
        'show-cert',
        aliases=['ca show-cert'],
        help="Показать сертификат по серийному номеру"
    )
    show_cert_parser.add_argument(
        'serial',
        type=validate_serial,
        help="Серийный номер сертификата (hex)"
    )
    show_cert_parser.add_argument(
        '--db-path',
        type=validate_db_path,
        default='./pki/micropki.db',
        help="Путь к SQLite базе данных"
    )
    show_cert_parser.add_argument('--log-file')

    # Команда 'repo serve'
    repo_serve_parser = subparsers.add_parser(
        'repo-serve',
        aliases=['repo serve'],
        help="Запустить HTTP репозиторий сервер"
    )
    repo_serve_parser.add_argument(
        '--host',
        default='127.0.0.1',
        help="Адрес для привязки (по умолчанию: 127.0.0.1)"
    )
    repo_serve_parser.add_argument(
        '--port',
        type=int,
        default=8080,
        help="Порт для привязки (по умолчанию: 8080)"
    )
    repo_serve_parser.add_argument(
        '--db-path',
        type=validate_db_path,
        default='./pki/micropki.db',
        help="Путь к SQLite базе данных"
    )
    repo_serve_parser.add_argument(
        '--cert-dir',
        type=validate_out_dir,
        default='./pki/certs',
        help="Директория с сертификатами (по умолчанию: ./pki/certs)"
    )
    # Команда 'revoke'
    revoke_parser = subparsers.add_parser(
        'revoke',
        aliases=['ca revoke'],
        help="Отозвать сертификат",
        description="Отзывает выпущенный сертификат по серийному номеру"
    )
    revoke_parser.add_argument('serial', type=validate_serial, help="Серийный номер сертификата (hex)")
    revoke_parser.add_argument('--reason', type=validate_reason, default='unspecified',
                               help="Причина отзыва (по умолчанию: unspecified)")
    revoke_parser.add_argument('--db-path', type=validate_db_path, default='./pki/micropki.db',
                               help="Путь к SQLite базе данных")
    revoke_parser.add_argument('--force', action='store_true',
                               help="Принудительно без подтверждения")
    revoke_parser.add_argument('--log-file')

    # Команда 'gen-crl'
    gen_crl_parser = subparsers.add_parser(
        'gen-crl',
        aliases=['ca gen-crl'],
        help="Сгенерировать CRL",
        description="Генерирует CRL (Certificate Revocation List) для указанного CA"
    )
    gen_crl_parser.add_argument('--ca', required=True, choices=['root', 'intermediate'],
                                help="Тип CA: root или intermediate")
    gen_crl_parser.add_argument('--next-update', type=int, default=7,
                                help="Дней до следующего обновления CRL (по умолчанию: 7)")
    gen_crl_parser.add_argument('--out-file', type=str,
                                help="Путь для сохранения CRL (опционально)")
    gen_crl_parser.add_argument('--db-path', type=validate_db_path, default='./pki/micropki.db')
    gen_crl_parser.add_argument('--out-dir', type=validate_out_dir, default='./pki')
    gen_crl_parser.add_argument('--log-file')
    repo_serve_parser.add_argument('--log-file')

    return parser


def main():
    import sys
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
                    log_file=args.log_file,
                    db_path=getattr(args, 'db_path', None)
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

        elif args.command in ['key-test', 'key test']:
            logger.info("Проверка соответствия ключа и сертификата")

            try:
                passphrase = read_passphrase(args.passphrase_file)

                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import padding
                from cryptography import x509
                from .crypto_utils import load_encrypted_private_key

                with open(args.cert, 'rb') as f:
                    cert_data = f.read()
                cert = x509.load_pem_x509_certificate(cert_data)

                private_key = load_encrypted_private_key(args.key, passphrase)

                test_message = b"MicroPKI test message for key verification"

                signature = private_key.sign(
                    test_message,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )

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
            from .csr import generate_intermediate_csr, sign_csr_with_ca
            from cryptography import x509
            import datetime
            from cryptography.hazmat.backends import default_backend

            logger.info("=== СОЗДАНИЕ ПРОМЕЖУТОЧНОГО CA ===")

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
            from .crypto_utils import load_encrypted_private_key, generate_key, parse_dn_string
            from .certificates import cert_to_pem
            from .csr import sign_end_entity_certificate, load_csr_from_file
            from .templates import TemplateFactory
            from cryptography import x509
            from cryptography.x509 import CertificateSigningRequestBuilder
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import hashes
            import datetime

            logger.info("=== ВЫПУСК КОНЕЧНОГО СЕРТИФИКАТА ===")

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
                    subject = csr.subject
                    private_key = None
                    key_path = None
                else:
                    logger.info("Генерация новой ключевой пары")
                    private_key = generate_key('rsa', 2048)
                    subject = x509.Name(parse_dn_string(args.subject))
                    csr_builder = CertificateSigningRequestBuilder().subject_name(subject)
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

                if private_key and not args.csr:
                    key_path = certs_dir / f"{common_name}.key.pem"
                    if key_path.exists() and not args.force:
                        raise FileExistsError(f"Файл уже существует: {key_path}. Используйте --force")

                    unencrypted_key = private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                    key_path.write_bytes(unencrypted_key)

                    try:
                        os.chmod(key_path, 0o600)
                    except Exception:
                        pass

                    logger.warning(f"Приватный ключ сохранен НЕЗАШИФРОВАННЫМ: {key_path}")
                    print(f"\n ВНИМАНИЕ: Приватный ключ сохранен НЕЗАШИФРОВАННЫМ: {key_path}")

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
                print(f"\nОшибка: {e}", file=sys.stderr)
                return 1


        elif args.command in ['db-init', 'db init']:
            from .database import CertificateDatabase
            logger.info(f"Инициализация базы данных: {args.db_path}")
            db = CertificateDatabase(args.db_path)
            if db.init_schema():
                print(f" База данных инициализирована: {args.db_path}")
                logger.info(f"База данных успешно создана: {args.db_path}")
            else:
                print(f" Ошибка инициализации базы данных")
                return 1
            return 0

        # Команда: list-certs
        elif args.command in ['list-certs', 'ca list-certs']:
            from .database import CertificateDatabase
            import json
            import csv
            import sys

            logger.info(f"Запрос списка сертификатов (статус: {args.status})")
            db = CertificateDatabase(args.db_path)
            certs = db.list_certificates(status=args.status)

            if args.format == 'json':
                output = [{'serial': c['serial_hex'], 'subject': c['subject'], 'issuer': c['issuer'], 'not_before': c['not_before'], 'not_after': c['not_after'], 'status': c['status']} for c in certs]
                print(json.dumps(output, indent=2))
            elif args.format == 'csv':
                writer = csv.writer(sys.stdout)
                writer.writerow(['serial', 'subject', 'issuer', 'not_before', 'not_after', 'status'])
                for cert in certs:
                    writer.writerow([cert['serial_hex'], cert['subject'], cert['issuer'], cert['not_before'][:10], cert['not_after'][:10], cert['status']])
            else:
                print("\n" + "=" * 100)
                print(f"{'Serial':<20} {'Subject':<35} {'Status':<10} {'Expires':<20}")
                print("=" * 100)
                for cert in certs:
                    serial = cert['serial_hex'][:18] + "..." if len(cert['serial_hex']) > 20 else cert['serial_hex']
                    subject = cert['subject'][:32] + "..." if len(cert['subject']) > 35 else cert['subject']
                    expires = cert['not_after'][:10] if cert['not_after'] else 'N/A'
                    print(f"{serial:<20} {subject:<35} {cert['status']:<10} {expires:<20}")
                print("=" * 100)
                print(f"Всего: {len(certs)} сертификатов")
            return 0
        # Команда: revoke
        elif args.command in ['revoke', 'ca revoke']:
            from .database import CertificateDatabase
            from .revocation import revoke_certificate

            logger.info(f"Отзыв сертификата: {args.serial}, причина: {args.reason}")

            db = CertificateDatabase(args.db_path)

            try:
                success = revoke_certificate(db, args.serial, args.reason, args.force)
                if success:
                    print(f"✅ Сертификат {args.serial} успешно отозван")
                    logger.info(f"Сертификат отозван: {args.serial}, причина: {args.reason}")
                else:
                    print(f"❌ Не удалось отозвать сертификат {args.serial}")
                    return 1
            except ValueError as e:
                logger.error(str(e))
                print(f"❌ Ошибка: {e}", file=sys.stderr)
                return 1
            except Exception as e:
                logger.error(f"Ошибка при отзыве: {e}")
                print(f"❌ Ошибка: {e}", file=sys.stderr)
                return 1
            return 0

        # Команда: gen-crl
        elif args.command in ['gen-crl', 'ca gen-crl']:
            from .database import CertificateDatabase
            from .crl import generate_crl_for_ca
            from .crypto_utils import read_passphrase_from_file

            logger.info(f"Генерация CRL для CA: {args.ca}")

            db = CertificateDatabase(args.db_path)
            out_dir = Path(args.out_dir)

            # Определяем пути к сертификатам и ключам
            if args.ca == 'root':
                cert_path = out_dir / 'certs' / 'ca.cert.pem'
                key_path = out_dir / 'private' / 'ca.key.pem'
                passphrase_file = out_dir / 'private' / 'ca.pass'  # может быть в другом месте
                ca_name = 'root'
            else:  # intermediate
                cert_path = out_dir / 'certs' / 'intermediate.cert.pem'
                key_path = out_dir / 'private' / 'intermediate.key.pem'
                passphrase_file = out_dir / 'private' / 'intermediate.pass'
                ca_name = 'intermediate'

            # Проверяем существование файлов
            if not cert_path.exists():
                print(f"❌ Сертификат не найден: {cert_path}", file=sys.stderr)
                return 1

            if not key_path.exists():
                print(f"❌ Ключ не найден: {key_path}", file=sys.stderr)
                return 1

            # Запрашиваем пароль (упрощённо - читаем из файла или спрашиваем)
            try:
                # Пробуем прочитать из файла
                with open(passphrase_file, 'rb') as f:
                    ca_passphrase = f.read().strip()
            except FileNotFoundError:
                # Если файла нет, запрашиваем ввод
                import getpass
                ca_passphrase = getpass.getpass(f"Введите пароль для {args.ca} CA: ").encode()

            try:
                crl_path = generate_crl_for_ca(
                    db=db,
                    ca_cert_path=cert_path,
                    ca_key_path=key_path,
                    ca_passphrase=ca_passphrase,
                    ca_name=ca_name,
                    out_dir=out_dir,
                    next_update_days=args.next_update
                )
                print(f" CRL сгенерирован: {crl_path}")
                logger.info(f"CRL сгенерирован для {args.ca}: {crl_path}")
            except Exception as e:
                logger.error(f"Ошибка генерации CRL: {e}")
                print(f" Ошибка: {e}", file=sys.stderr)
                return 1
            return 0
        # Команда: show-cert
        elif args.command in ['show-cert', 'ca show-cert']:
            from .database import CertificateDatabase
            logger.info(f"Поиск сертификата по серийному номеру: {args.serial}")
            db = CertificateDatabase(args.db_path)
            cert = db.get_certificate_by_serial(args.serial)
            if cert:
                print(cert['cert_pem'])
                logger.info(f"Сертификат найден: {cert['subject']}")
            else:
                print(f" Сертификат с серийным номером {args.serial} не найден", file=sys.stderr)
                return 1
            return 0

        # Команда: repo serve
        elif args.command in ['repo-serve', 'repo serve']:
            from .repository import start_server
            logger.info(f"Запуск HTTP репозиторий сервера: {args.host}:{args.port}")
            print(f" Запуск HTTP сервера на http://{args.host}:{args.port}")
            print("   Нажмите Ctrl+C для остановки")
            start_server(
                host=args.host,
                port=args.port,
                db_path=args.db_path,
                cert_dir=args.cert_dir,
                log_file=args.log_file
            )
            return 0

        else:
            logger.error(f"Неизвестная команда: {args.command}")
            print(f" Ошибка: Неизвестная команда '{args.command}'. Доступные команды: ca-init, ca-verify, key-test, issue-intermediate, issue-cert, chain-verify, db-init, list-certs, show-cert, repo-serve", file=sys.stderr)
            return 1

    except KeyboardInterrupt:
        logger.info("Операция прервана пользователем")
        print("\n Операция прервана", file=sys.stderr)
        return 1

    except Exception as e:
        logger.error(f"Необработанная ошибка: {e}")
        print(f"\n Непредвиденная ошибка: {e}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())