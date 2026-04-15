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
### Инициализация базы данных
```bash
python -m micropki.cli db-init --db-path ./pki/micropki.db
```
### Запуск HTTP репозиторий сервера
```bash
python -m micropki.cli repo-serve --host 127.0.0.1 --port 8080 --db-path ./pki/micropki.db --cert-dir ./pki/certs
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
8. С оздание промежуточного СА
```bash
python -m micropki.cli issue-intermediate --root-cert ./pki/certs/ca.cert.pem --root-key ./pki/private/ca.key.pem --root-pass-file passphrase.txt --subject "CN=Intermediate CA,O=MicroPKI" --key-type rsa --key-size 4096 --passphrase-file passphrase.txt --out-dir ./pki --validity-days 1825 --pathlen 0
```
Создает Intermediate CA, подписанный корневым CA, с ограничением пути pathlen.
9. Выпуск сертификата сервера
```bash
python -m micropki.cli issue-cert --ca-cert ./pki/certs/intermediate.cert.pem --ca-key ./pki/private/intermediate.key.pem --ca-pass-file passphrase.txt --template server --subject "CN=example.com" --san dns:example.com --san dns:www.example.com --out-dir ./pki/certs --validity-days 365
```
Выпускает сертификат для TLS/HTTPS. Требует хотя бы один DNS или IP SAN.

10. Выпуск клиентского сертификата
```bash
python -m micropki.cli issue-cert --ca-cert ./pki/certs/intermediate.cert.pem --ca-key ./pki/private/intermediate.key.pem --ca-pass-file passphrase.txt --template client --subject "CN=Alice Smith,EMAIL=alice@example.com" --san email:alice@example.com --out-dir ./pki/certs
```
Выпускает сертификат для аутентификации клиентов. Поддерживает email SAN.

11. Выпуск сертификата подписи кода
```bash
python -m micropki.cli issue-cert --ca-cert ./pki/certs/intermediate.cert.pem --ca-key ./pki/private/intermediate.key.pem --ca-pass-file passphrase.txt --template code_signing --subject "CN=MicroPKI Code Signer" --out-dir ./pki/certs
```
Выпускает сертификат для подписи кода. Не требует SAN.

12. Проверка цепочки сертификатов
```bash
python -m micropki.cli chain-verify --leaf ./pki/certs/example.com.cert.pem --intermediate ./pki/certs/intermediate.cert.pem --root ./pki/certs/ca.cert.pem
```
Проверяет цепочку leaf → intermediate → root: подписи, сроки действия, Basic Constraints, Key Usage.
13. Инициализация базы данных
```bash
python -m micropki.cli db-init --db-path ./pki/micropki.db
```
Создает SQLite базу данных и необходимые таблицы для хранения сертификатов.
14. Список сертификатов
```bash
python -m micropki.cli list-certs
python -m micropki.cli list-certs --status valid
python -m micropki.cli list-certs --format json
python -m micropki.cli list-certs --format csv
```
Выводит список всех сертификатов из базы данных. Поддерживает фильтрацию по статусу и форматы вывода (table, json, csv).
15. Показать сертификат по серийному номеру
```bash
python -m micropki.cli show-cert 2A7F
```
16. Запуск HTTP репозиторий сервера
```bash
python -m micropki.cli repo-serve --host 127.0.0.1 --port 8080 --db-path ./pki/micropki.db --cert-dir ./pki/certs
```

### SAN форматы
 - dns:example.com - DNS имя

 - ip:192.168.1.1 - IP адрес

 - email:user@example.com - Email адрес

 - uri:https://example.com - URI
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
```text
csr.py 
Работа с Certificate Signing Requests:
- generate_intermediate_csr() - генерация CSR для Intermediate CA
- sign_csr_with_ca() - подпись CSR корневым/промежуточным CA
- sign_end_entity_certificate() - подпись конечного сертификата с шаблоном
- load_csr_from_file() - загрузка CSR из файла
```
```text
templates.py
Шаблоны сертификатов:
- ServerTemplate - для TLS/HTTPS (EKU: serverAuth, требует DNS/IP SAN)
- ClientTemplate - для аутентификации (EKU: clientAuth, поддерживает email SAN)
- CodeSigningTemplate - для подписи кода (EKU: codeSigning, без SAN)
- TemplateFactory - фабрика для получения шаблонов по имени
```
```text
san_utils.py
Утилиты для Subject Alternative Names:
- parse_san_string() - парсинг строки "type:value"
- parse_san_list() - парсинг списка SAN
- create_san_extension() - создание расширения SAN
- validate_san_for_template() - валидация SAN для шаблона
```
```text
chain.py 
Проверка цепочки сертификатов:
- ChainValidator - класс для валидации цепочки (подписи, сроки, BC, KU)
- validate_full_chain() - проверка leaf → intermediate → root
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