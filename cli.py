import argparse
import sys
import os
from pathlib import Path
import subprocess
from .logger import setup_logger, get_logger
from .ca import CertificateAuthority
from .crypto_utils import load_encrypted_private_key


def validate_key_type(value):
    if value not in ['rsa', 'ecc']:
        raise argparse.ArgumentTypeError(f"Тип ключа должен быть 'rsa' или 'ecc', получено: {value}")
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

    # Настраиваем логирование
    logger = setup_logger(getattr(args, 'log_file', None))

    try:
        # Команда: ca-init
        if args.command in ['ca-init', 'ca init']:
            # Дополнительная проверка размера ключа в зависимости от типа
            try:
                validate_key_size_with_type(args.key_size, args.key_type)
            except ValueError as e:
                logger.error(str(e))
                print(f" Ошибка: {e}", file=sys.stderr)
                return 1

            # Читаем пароль из файла
            try:
                passphrase = read_passphrase(args.passphrase_file)
                logger.info(f"Пароль прочитан из файла: {args.passphrase_file}")
            except Exception as e:
                logger.error(f"Ошибка чтения файла с паролем: {e}")
                print(f" Ошибка: Не удалось прочитать файл с паролем - {e}", file=sys.stderr)
                return 1

            # Создаем CA и инициализируем
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

                # Выводим информацию об успехе
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

        # Команда: ca-verify
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
                print(f"\n❌ Ключ НЕ соответствует сертификату: {e}", file=sys.stderr)
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