### Шифрование с GCM
```bash
Шифрование с дополнительными данными (AAD)
cryptocore crypto --algorithm aes --mode gcm --encrypt --key 00112233445566778899aabbccddeeff --input secret.txt --output secret.bin --aad aabbccddeeff

Расшифровка (тот же AAD!)
cryptocore crypto --algorithm aes --mode gcm --decrypt --key 00112233445566778899aabbccddeeff --input secret.bin --output recovered.txt --aad aabbccddeeff
```
### Encrypt-then-MAC
```bash
Требуется 32-байтный ключ: 16 байт — AES, 16 байт — HMAC
cryptocore crypto --algorithm aes --mode etm --encrypt --key $(openssl rand -hex 32) --input data.txt --output data.etm  --aad "metadata"
  ```
  ### Тесты
  ```bash
  python -m pytest tests/gcm_tests 

  python -m pytest tests/test_encrypt_then_mac.py  

  python -m pytest tests/ -v  
 ```
