# CryptoCore
## Установка(Windows)
```bash
git clone -b m2 https://github.com/ksesha-kr/CryptoCore.git
cd CryptoCore
python -m venv venv
venv\Scripts\activate
pip install -e .
cryptocore --help
```
## Спринт 2. Выполненные требования

### STR-1
- Существующая кодовая база расширена без потери функциональности
- Все тесты спринта 1 продолжают работать
- Сохранена обратная совместимость с режимом ECB

### STR-2
- Добавлена документация по новым режимам работы (CBC, CFB, OFB, CTR)
- Примеры использования с обработкой IV
- Инструкции по тестированию интероперабельности с OpenSSL
- Обновлен README.md с примерами для всех режимов

### STR-3
- Новая структура модулей в `src/modes/`:
  - `cbc.py` - реализация Cipher Block Chaining
  - `cfb.py` - реализация Cipher Feedback
  - `ofb.py` - реализация Output Feedback
  - `ctr.py` - реализация Counter mode
  - `base_mode.py` - базовый абстрактный класс

### CLI-1
- Поддержка новых режимов: `cbc`, `cfb`, `ofb`, `ctr`
- Совместимость с существующим режимом `ecb`
- Валидация аргументов командной строки

### CLI-2
- **Шифрование**: IV генерируется автоматически, флаг `--iv` игнорируется с предупреждением
- **Дешифрование**: IV передается через `--iv` или читается из файла
- Автоматическое определение источника IV

### CLI-3
- Проверка что `--iv` используется только при дешифровании
- Валидация формата IV (16-байтная hex-строка)
- Четкие сообщения об ошибках при неверном использовании

### CRY-1
- Используется AES-128 из pycryptodome
- Сохранена вся функциональность спринта 1
- Криптографические примитивы не реализованы с нуля

### CRY-2
- **CBC**: Реализована цепочка блоков с XOR между блоками
- **CFB**: Реализован как поточный шифр (128-битные сегменты)
- **OFB**: Реализован генератор ключевого потока, независимый от данных
- **CTR**: Реализован счетчик с инкрементом для каждого блока

### CRY-3
- **CBC**: Требует паддинг PKCS#7, блочный режим
- **CFB**: Не требует паддинга, обработка частичных блоков, поточный режим
- **OFB**: Не требует паддинга, симметричное шифрование/дешифрование
- **CTR**: Не требует паддинга, счетчик на основе nonce

### CRY-4
- **С паддингом**: ECB, CBC (используют PKCS#7)
- **Без паддинга**: CFB, OFB, CTR (поточные режимы)
- Автоматическое определение необходимости паддинга по режиму

### IV-1
- Используется `os.urandom(16)` для генерации криптографически стойкого IV
- CSPRNG (Cryptographically Secure Pseudorandom Number Generator)

### IV-2
- Формат файла при шифровании: `<16-байтный IV><данные шифротекста>`
- IV записывается в начало файла перед шифрованными данными

### IV-3
- Если указан `--iv` - используется переданное значение
- Если `--iv` не указан - IV читается из первых 16 байт файла
- Гибкое управление источником IV

### IV-4
- Все режимы используют 16-байтный IV
- Для CTR: 8 байт nonce + 8 байт счетчик (little-endian)
- Единообразная обработка для всех режимов

### IO-1
- IV записывается в начало выходного файла перед данными при шифровании
- Автоматическое форматирование выходного файла

### IO-2
- Автоматическое чтение IV из файла если не указан явно
- Прозрачная обработка для пользователя

### IO-3
- Проверка что файл содержит минимум 16 байт для извлечения IV
- Четкие сообщения об ошибках при коротких файлах

### TEST-1: Round-trip tests for all new modes
- Шифрование → дешифрование = исходные данные для всех 4 режимов
- Тестирование различных размеров данных
- Проверка обработки частичных блоков

### TEST-2: Interoperability CryptoCore → OpenSSL
- Шифрование CryptoCore, дешифрование OpenSSL
- Подтверждение корректности формата данных
- Проверка совместимости форматов файлов

### TEST-3: Interoperability OpenSSL → CryptoCore
- Шифрование OpenSSL, дешифрование CryptoCore
- Подтверждение совместимости реализаций
- Тестирование с явным указанием IV

### TEST-4: Test scripts provided
- Комплексные тесты для всех режимов
- Скрипты проверки интероперабельности
- Unit-тесты для каждого компонента

## Использование

### Базовые команды

**Шифрование (IV генерируется автоматически)**
```bash
cryptocore --algorithm aes --mode cbc --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input plaintext.txt \
  --output ciphertext.bin
  ```
  **Дешифрование с IV из файла**

```bash
cryptocore --algorithm aes --mode cbc --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input ciphertext.bin \
  --output decrypted.txt
```
**Дешифрование с указанием IV**

```bash
cryptocore --algorithm aes --mode cbc --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --iv 00112233445566778899aabbccddeeff \
  --input ciphertext.bin \
  --output decrypted.txt
  ```
## Примеры для каждого режима
**CBC Mode - Шифрование с паддингом**

```bash
cryptocore --algorithm aes --mode cbc --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input document.txt \
  --output document.cbc.enc
  ```
**CFB Mode - Поточный шифр без паддинга**

```bash
cryptocore --algorithm aes --mode cfb --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input image.jpg \
  --output image.cfb.enc
  ```
**OFB Mode - Генератор ключевого потока**

```bash
cryptocore --algorithm aes --mode ofb --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input data.bin \
  --output data.ofb.enc
  ```
**CTR Mode - Режим счетчика**

```bash
cryptocore --algorithm aes --mode ctr --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input message.txt \
  --output message.ctr.enc
  ```
## Тестирование
**Запуск всех тестов**
```bash
python -m unittest discover tests/ -v
```
**Тестирование интероперабельности с OpenSSL**
```bash
CryptoCore → OpenSSL
```
**Шифруем CryptoCore:**

```bash
cryptocore --algorithm aes --mode cbc --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input test.txt --output test.enc
```
**Извлекаем IV и данные:**

```bash
dd if=test.enc of=iv.bin bs=16 count=1
dd if=test.enc of=ciphertext.bin bs=16 skip=1
```
**Дешифруем OpenSSL:**

```bash
openssl enc -aes-128-cbc -d \
  -K 000102030405060708090A0B0C0D0E0F \
  -iv $(xxd -p iv.bin | tr -d '\n') \
  -in ciphertext.bin -out decrypted.txt
OpenSSL → CryptoCore
```
**Шифруем OpenSSL:**

```bash
openssl enc -aes-128-cbc \
  -K 000102030405060708090A0B0C0D0E0F \
  -iv 00112233445566778899AABBCCDDEEFF \
  -in test.txt -out openssl.enc
  ```
**Дешифруем CryptoCore:**

```bash
cryptocore --algorithm aes --mode cbc --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --iv 00112233445566778899aabbccddeeff \
  --input openssl.enc --output decrypted.txt
  ```
**Обработка IV**
Шифрование

```python
iv = os.urandom(16)
ciphertext = mode.encrypt(plaintext, iv)
write_file_with_iv(output_file, iv, ciphertext)
Дешифрование
```
```python
if args.iv:
    iv = bytes.fromhex(args.iv)
else:
    iv, ciphertext = read_file_with_iv(input_file)
plaintext = mode.decrypt(ciphertext, iv)
```
