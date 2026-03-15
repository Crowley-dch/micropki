# MicroPKI
## 🔧 Требования

- **Python** ≥ 3.8
- **OpenSSL** (для команды `ca-verify`) - опционально
- **Зависимости Python**:
  - `cryptography` ≥ 41.0.0
  - `pytest` ≥ 7.0.0 (для тестов)
## Установка и настройка

1. Клонируйте репозиторий:
   ```bash
   git clone <url-репозитория>
   cd micro-pki
   ```
2. Создание виртуального окружения
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```
3. Установка зависимостей
```bash
pip install -r requirements.txt
```

### Создайте файл с паролем
```bash
echo "my-secret-password" > passphrase.txt
```
### Создайте корневой CA (RSA)
```bash
python -m micropki.cli ca-init --subject "/CN=My Root CA" --key-type rsa --key-size 4096 --passphrase-file passphrase.txt --out-dir ./pki
```
### Проверьте сертификат
```bash
python -m micropki.cli ca-verify --cert ./pki/certs/ca.cert.pem
```
### Проверьте соответствие ключа и сертификата
```bash
python -m micropki.cli key-test --key ./pki/private/ca.key.pem --cert ./pki/certs/ca.cert.pem --passphrase-file passphrase.txt
```

## Команды
1. Создание корневого CA (RSA)
```bash
python -m micropki.cli ca-init --subject "/CN=My Root CA" --key-type rsa --key-size 4096 --passphrase-file passphrase.txt --out-dir ./pki --validity-days 3650
```
Создает CA с RSA ключом 4096 бит, сертификатом на 10 лет.

2. Создание корневого CA (ECC)
```bash
python -m micropki.cli ca-init --subject "CN=ECC Root CA,O=Demo,C=US" --key-type ecc --key-size 384 --passphrase-file passphrase.txt --out-dir ./pki-ecc
```
Создает CA с ECC ключом на кривой P-384.

3. Принудительная перезапись
```bash
python -m micropki.cli ca-init --subject "/CN=Test CA" --key-type rsa --key-size 4096 --passphrase-file passphrase.txt --force
```
Перезаписывает существующие файлы (если они уже есть).

4. Логирование в файл
```bash
python -m micropki.cli ca-init --subject "/CN=Test CA" --key-type rsa --key-size 4096 --passphrase-file passphrase.txt --log-file ./ca-init.log
```
Сохраняет логи в файл вместо консоли.

5. Проверка сертификата
```bash
python -m micropki.cli ca-verify --cert ./pki/certs/ca.cert.pem
```
Показывает содержимое сертификата и проверяет его валидность.

6. Проверка соответствия ключа и сертификата
```bash
python -m micropki.cli key-test --key ./pki/private/ca.key.pem --cert ./pki/certs/ca.cert.pem --passphrase-file passphrase.txt
```
Проверяет, что приватный ключ соответствует сертификату.

7. Справка
```bash
python -m micropki.cli --help
python -m micropki.cli ca-init --help
python -m micropki.cli ca-verify --help
python -m micropki.cli key-test --help
```

## Описание файлов
```text
cli.py
Парсер командной строки. Обрабатывает аргументы, валидирует входные данные, вызывает соответствующие функции.
```
```text
ca.py
Класс CertificateAuthority - основная логика создания CA. Управляет директориями, файлами, правами доступа.
```
```text
certificates.py
Создание самоподписанных X.509 v3 сертификатов с расширениями:

BasicConstraints (CA=TRUE, критическое)

KeyUsage (keyCertSign, cRLSign, критическое)

SubjectKeyIdentifier (SKI)

AuthorityKeyIdentifier (AKI)
```
```text
crypto_utils.py
Криптографические функции:

Генерация RSA и ECC ключей

Шифрование ключей (PKCS#8, AES-256)

Загрузка зашифрованных ключей

Парсинг Distinguished Name

Вычисление SKI

Генерация серийных номеров
```

## Тестирование

Запуск всех тестов
```bash
pytest tests/ -v
```

Запуск конкретного теста
```bash
pytest tests/test_crypto_utils.py -v
pytest tests/test_certificates.py::TestCertificates::test_create_rsa_certificate -v
```