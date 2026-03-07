import os
from pathlib import Path
import datetime

from .crypto_utils import generate_key, encrypt_private_key
from .certificates import create_self_signed_certificate, cert_to_pem
from .logger import get_logger


class CertificateAuthority:

    def __init__(self, out_dir: str, log_file: str = None):

        self.out_dir = Path(out_dir)
        self.logger = get_logger()

        self.private_dir = self.out_dir / 'private'
        self.certs_dir = self.out_dir / 'certs'

        self.logger.info(f"Инициализация CA в директории: {out_dir}")

    def create_directories(self):

        self.logger.info("Создание структуры директорий")

        self.private_dir.mkdir(parents=True, exist_ok=True)
        self.certs_dir.mkdir(parents=True, exist_ok=True)

        try:
            os.chmod(self.private_dir, 0o700)
            self.logger.info(f"Установлены права 700 на {self.private_dir}")
        except Exception as e:
            self.logger.warning(f"Не удалось установить права на директорию: {e}")

        self.logger.info(f"Директории созданы: {self.out_dir}")

    def init_root_ca(
            self,
            subject: str,
            key_type: str,
            key_size: int,
            passphrase: bytes,
            validity_days: int
    ):

        self.logger.info(f"ИНИЦИАЛИЗАЦИЯ КОРНЕВОГО CA ")
        self.logger.info(f"Subject: {subject}")
        self.logger.info(f"Тип ключа: {key_type}")
        self.logger.info(f"Размер ключа: {key_size}")
        self.logger.info(f"Срок действия: {validity_days} дней")

        self.logger.info("ШАГ 1: Генерация ключевой пары")
        try:
            private_key = generate_key(key_type, key_size)
            self.logger.info("Ключевая пара успешно сгенерирована")
        except Exception as e:
            self.logger.error(f"Ошибка генерации ключа: {e}")
            raise

        self.logger.info("ШАГ 2: Создание самоподписанного сертификата")
        try:
            certificate = create_self_signed_certificate(
                private_key=private_key,
                subject_dn=subject,
                validity_days=validity_days,
                key_type=key_type
            )
            self.logger.info("Сертификат успешно создан")
        except Exception as e:
            self.logger.error(f"Ошибка создания сертификата: {e}")
            raise

        self.logger.info("ШАГ 3: Шифрование и сохранение приватного ключа")
        key_path = self.private_dir / 'ca.key.pem'
        try:
            encrypted_key = encrypt_private_key(private_key, passphrase)
            key_path.write_bytes(encrypted_key)

            try:
                os.chmod(key_path, 0o600)
                self.logger.info(f"Установлены права 600 на {key_path}")
            except Exception as e:
                self.logger.warning(f"Не удалось установить права на ключ: {e}")

            self.logger.info(f"Приватный ключ сохранен: {key_path}")
        except Exception as e:
            self.logger.error(f"Ошибка сохранения ключа: {e}")
            raise

        self.logger.info("ШАГ 4: Сохранение сертификата")
        cert_path = self.certs_dir / 'ca.cert.pem'
        try:
            pem_cert = cert_to_pem(certificate)
            cert_path.write_bytes(pem_cert)
            self.logger.info(f"Сертификат сохранен: {cert_path}")
        except Exception as e:
            self.logger.error(f"Ошибка сохранения сертификата: {e}")
            raise

        self.logger.info("ШАГ 5: Создание документа политики")
        policy_path = self.out_dir / 'policy.txt'
        try:
            self._create_policy_file(
                policy_path,
                subject,
                certificate.serial_number,
                certificate.not_valid_before,
                certificate.not_valid_after,
                key_type,
                key_size
            )
            self.logger.info(f"Документ сохранен: {policy_path}")
        except Exception as e:
            self.logger.error(f"Ошибка создания policy.txt: {e}")
            raise

        self.logger.info(f"=== ИНИЦИАЛИЗАЦИЯ CA УСПЕШНО ЗАВЕРШЕНА ===")

        return {
            'key_path': str(key_path),
            'cert_path': str(cert_path),
            'policy_path': str(policy_path)
        }

    def _create_policy_file(
            self,
            policy_path: Path,
            subject: str,
            serial_number: int,
            not_before: datetime.datetime,
            not_after: datetime.datetime,
            key_type: str,
            key_size: int
    ):
        """
        Создает файл политики CA

        Args:
            policy_path: путь для сохранения
            subject: DN субъекта
            serial_number: серийный номер сертификата
            not_before: дата начала действия
            not_after: дата окончания действия
            key_type: тип ключа
            key_size: размер ключа
        """
        content = f"""CERTIFICATE POLICY DOCUMENT
==========================

CA Name (Subject DN): {subject}
Certificate Serial Number (hex): {hex(serial_number)}

Validity Period:
  Not Before: {not_before.strftime('%Y-%m-%d %H:%M:%S UTC')}
  Not After:  {not_after.strftime('%Y-%m-%d %H:%M:%S UTC')}

Key Algorithm: {key_type.upper()}
Key Size: {key_size} bits

Purpose: Root CA for MicroPKI demonstration
Policy Version: 1.0
Creation Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

---
This is a self-signed root certificate authority.
All private keys are stored encrypted with AES-256.
"""
        policy_path.write_text(content, encoding='utf-8')


if __name__ == '__main__':
    from .logger import setup_logger

    logger = setup_logger()

    ca = CertificateAuthority(out_dir='./test_pki')

    ca.create_directories()

    test_passphrase = b"test-passphrase"

    print("\n=== Тест RSA CA ===")
    files = ca.init_root_ca(
        subject="/CN=Test Root CA/O=MicroPKI/C=US",
        key_type="rsa",
        key_size=4096,
        passphrase=test_passphrase,
        validity_days=365
    )
    print(f"Созданы файлы: {files}")

    # Проверяем, что файлы существуют
    for path in files.values():
        if Path(path).exists():
            print(f"✓ {path} создан")
        else:
            print(f"✗ {path} НЕ создан")