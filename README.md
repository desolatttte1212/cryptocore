# CryptoCore

Инструмент для шифрования и дешифрования AES-128 в режиме ECB

## Установка (Windows)
```bash
git clone https://github.com/desolatttte1212/CryptoCore.git
python3 -m venv venv
source venv/bin/activate
pip install -e .
cryptocore --help
```
## Спринт 1. Выполненные требования
STR-1
Репозиторий создан на GitHub: https://github.com/desolatttte1212/CryptoCore

Ветка для разработки: m1

Полная история коммитов доступна

STR-2
README.md содержит:
Название проекта и описание

Инструкции по сборке и установке

Примеры использования CLI

STR-3
setup.py - конфигурация Python пакета

requirements.txt - зависимости (pycryptodome)

Установка через pip install -e .

STR-4 Структура проекта
```bash
CryptoCore/
├── src/
│   ├── __init__.py
│   ├── cli_parser.py
│   ├── file_io.py
│   └── modes/
│       ├── __init__.py
│       └── ecb.py
├── tests/
│   ├── __init__.py
│   └── test_cryptocore.py
├── setup.py
├── README.md
├── requirements.txt
└── run_tests.py
```
CLI-1
Установка через pip install -e .

Доступна команда cryptocore в командной строке

Проверено: cryptocore --help работает корректно

CLI-2
--algorithm ALGORITHM (только aes)

--mode MODE (только ecb)

--encrypt или --decrypt (обязательно один)

--key KEY (16-байтный ключ)

--input INPUT_FILE (путь к файлу)

--output OUTPUT_FILE (путь для результата)

CLI-3
Ключ принимается в hex-формате: 00112233445566778899aabbccddeeff

Автоматическая конвертация в bytes

Валидация длины (ровно 16 байт)

CLI-4
Проверка обязательных аргументов

Взаимоисключающие флаги (--encrypt/--decrypt)

Проверка существования входного файла

Валидация формата ключа

Четкие сообщения об ошибках в stderr

CLI-5
Шифрование: input.txt → input.txt.enc

Дешифрование: file.enc → file.dec

Автоматическое удаление расширений .enc, .crypt, .aes

CRY-1
Реализован AES-128 (128-битный блок, 128-битный ключ)

Используется 16-байтный ключ

Блочный размер: 16 байт

CRY-2
Используется pycryptodome библиотека

Crypto.Cipher.AES для криптографических примитивов

AES.new(key, AES.MODE_ECB) для создания шифра

CRY-3
Самостоятельная реализация логики ECB режима

Разбивка на блоки по 16 байт

Обработка каждого блока независимо

Вызов AES примитивов для каждого блока

CRY-4 Шифрование:
Добавление паддинга до кратного 16 байтам

padding_length = block_size - (len(data) % block_size)

Заполнение байтами со значением длины паддинга

Дешифрование:

Валидация паддинга после расшифрования

Проверка корректности байтов паддинга

Удаление паддинга из данных

CRY-5
Все файлы обрабатываются как бинарные потоки

Использование 'rb' и 'wb' режимов

Поддержка любых типов файлов

IO-1
read_file() функция читает весь файл в память

Поддержка больших файлов (в пределах доступной памяти)

Бинарное чтение: open(file_path, 'rb')

IO-2
write_file() функция записывает все данные

Автоматическое создание директорий если нужно

Бинарная запись: open(file_path, 'wb')

IO-3
Проверка существования входного файла

Обработка ошибок чтения/записи

Информативные сообщения об ошибках в stderr

Ненулевой код выхода при ошибках

Тесты
```bash
python -m unittest tests.test_cryptocore -v

```

## Примеры использования
Шифрование:
```bash
bash
cryptocore --algorithm aes --mode ecb --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input plaintext.txt --output ciphertext.bin
```

Дешифрование:
```bash
bash
cryptocore --algorithm aes --mode ecb --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input ciphertext.bin --output decrypted.txt
  ```
Тестирование полного цикла:
```bash
bash
# Создайте тестовый файл
echo "Hello, CryptoCore!" > test_input.txt

# Зашифруйте
cryptocore --algorithm aes --mode ecb --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input test_input.txt --output test_encrypted.bin

# Расшифруйте
cryptocore --algorithm aes --mode ecb --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input test_encrypted.bin --output test_decrypted.txt

# Проверьте результат
diff test_input.txt test_decrypted.txt
```
