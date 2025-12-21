# CryptoCore (final)

## Установка (Windows)
```bash
git clone https://github.com/desolatttte1212/CryptoCore.git
python3 -m venv venv
source venv/bin/activate
pip install -e .
cryptocore --help
```
## Финальная структура проекта
```bash
cryptocore/
├── docs/                          # Документация
│   ├── API.md                     # Полное API всех публичных функций
│   ├── USERGUIDE.md               # Руководство пользователя CLI
│   └── DEVELOPMENT.md             # Инструкция для разработчиков
├── tests/                         # Тестовая система
│   ├── unit/                      # Модульные тесты (по компонентам)
│   ├── integration/               # Интеграционные тесты (CLI, end-to-end)
│   ├── vectors/                   # Официальные тестовые векторы (NIST, RFC)
│   └── run_tests.py               # Единая точка запуска всех тестов
├── src/                           # Исходный код библиотеки
│   ├── __init__.py                # Инициализация пакета
│   ├── __main__.py                # Точка входа (CLI)
│   ├── cli_parser.py              # Парсер командной строки
│   ├── aead/                      # Authenticated Encryption (GCM, Encrypt-then-MAC)
│   ├── hash/                      # Хеш-функции (SHA-256, SHA3-256)
│   ├── kdf/                       # Key Derivation (PBKDF2, HKDF)
│   ├── mac/                       # MAC-функции (HMAC, CMAC)
│   ├── modes/                     # Режимы шифрования (ECB, CBC, CFB, OFB, CTR, GCM)
│   ├── csprng.py                  # Криптографически безопасный ГСЧ
│   └── file_io.py                 # Утилиты для работы с файлами
├── CHANGELOG.md                   # История изменений по спринтам
├── CONTRIBUTING.md                # Гайдлайны для контрибьюторов
├── SECURITY.md                    # Политика безопасности и отчёты об уязвимостях
└── requirements.txt               # Зависимости с фиксированными версиями
```

## Общая структура команд

```bash
cryptocore <command> [options]
```
Доступные команды:

dgst — вычисление хешей и MAC
crypto — шифрование и дешифрование
derive — генерация ключей из паролей
## Команда derive — генерация ключей
Генерирует криптографический ключ из пароля с использованием PBKDF2-HMAC-SHA256.
```bash
cryptocore derive --password <пароль> [опции]
```
### Пример использования
1. Базовая генерация ключа (соль генерируется)
```bash
cryptocore derive --password "MySecureP@ss123!" --iterations 200000 --length 32
> a1b2c3d4...e5f6g7h8 i9j0k1l2...m3n4o5p6
Первое значение — 32-байтный ключ (64 hex символа)
Второе — 16-байтная соль (32 hex символа)
```
2. Генерация с фиксированной солью (для воспроизводимости)
```bash
cryptocore derive --password "app_secret" --salt a1b2c3d4e5f601234567890123456789 --length 16
> 5f4dcc3b5aa765d61d8327deb882cf99 a1b2c3d4e5f601234567890123456789
```
3. Сохранение ключа в файл (для использования в шифровании)
```bash
$ cryptocore derive --password "master_key" --output encryption.key --length 32
$ ls -l encryption.key
# Размер файла: 32 байта (сырой ключ)
# Использование ключа для шифрования
KEY=$(xxd -p encryption.key)
cryptocore crypto --algorithm aes --mode gcm --encrypt --key $KEY --input data.txt --output data.enc
```
## Команда crypto — шифрование и дешифрование
Поддерживает все режимы AES: ECB, CBC, CFB, OFB, CTR, GCM.
```bash
cryptocore crypto --algorithm aes --mode <режим> --[encrypt|decrypt] [опции]
```
### Режимы и особенности
GCM (рекомендуется)
Аутентифицированное шифрование (конфиденциальность + целостность)
Поддерживает дополнительные аутентифицированные данные (AAD)

```bash
# Шифрование с AAD
cryptocore crypto --algorithm aes --mode gcm --encrypt --key 00112233445566778899aabbccddeeff --input database.sql --output database.enc --aad "database_v3.2"

# Дешифрование (AAD должен совпадать!)
cryptocore crypto --algorithm aes --mode gcm --decrypt --key 00112233445566778899aabbccddeeff --input database.enc --output database_decrypted.sql --aad "database_v3.2"
```
### CBC, CFB, OFB
Требуют IV (инициализирующий вектор)
CBC использует padding, остальные — нет
```bash
# Шифрование CBC
cryptocore crypto --algorithm aes --mode cbc --encrypt --key 00112233445566778899aabbccddeeff --input secret.txt --output secret.enc

# Дешифрование CBC (IV читается из файла)
cryptocore crypto --algorithm aes --mode cbc --decrypt --key 00112233445566778899aabbccddeeff --input secret.enc --output secret.txt
```
### ECB
```bash
cryptocore crypto --algorithm aes --mode ecb --encrypt --key 00112233445566778899aabbccddeeff --input single_block.bin --output single_block.enc
```
## Команда dgst — хеширование и MAC
Вычисляет хеши, HMAC и AES-CMAC.

Синтаксис
```bash
# SHA-256
cryptocore dgst --algorithm sha256 --input document.pdf
> a1b2c3d4... document.pdf

# Сохранение в файл
cryptocore dgst --algorithm sha256 --input data.bin --output checksum.sha256
```
HMAC (аутентификация)

```bash
# Генерация HMAC
cryptocore dgst --algorithm sha256 --hmac --key a1b2c3d4... --input config.json
> e5f6a7b8... config.json

# Проверка HMAC
cryptocore dgst --algorithm sha256 --hmac --key a1b2c3d4... --input config.json --verify expected.hmac
> [OK] Verification successful
```



