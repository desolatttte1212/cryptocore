# CryptoCore
## Key Derivation
### Команда derive
Генерирует ключ с помощью PBKDF2-HMAC-SHA256.

Синтаксис
```bash
cryptocore derive --password <пароль> [опции]
```
## Пример использования
### 1. Базовая генерация ключа (соль генерируется)
```bash
cryptocore derive --password "MySecureP@ss123!" --iterations 200000 --length 32
> a1b2c3d4...e5f6g7h8 i9j0k1l2...m3n4o5p6
Первое значение — 32-байтный ключ (64 hex символа)
Второе — 16-байтная соль (32 hex символа)
```
### 2. Генерация с фиксированной солью (для воспроизводимости)
```bash
cryptocore derive --password "app_secret" --salt a1b2c3d4e5f601234567890123456789 --length 16
> 5f4dcc3b5aa765d61d8327deb882cf99 a1b2c3d4e5f601234567890123456789
```
### 3. Сохранение ключа в файл (для использования в шифровании)
```bash
$ cryptocore derive --password "master_key" --output encryption.key --length 32
$ ls -l encryption.key
# Размер файла: 32 байта (сырой ключ)
```
### Иерархия ключей (Key Hierarchy)
Из одного мастер-ключа можно получить несколько детерминированных ключей для разных целей:

encryption — ключ шифрования
authentication — ключ для HMAC
user_123 — ключ для конкретного пользователя

### Тестирование
```bash
 python -m pytest tests/test_pbkdf2/ -v
  python -m pytest tests -v  
 ```

