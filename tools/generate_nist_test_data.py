import os
import sys
import argparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from src.csprng import generate_random_bytes
except ImportError:
    print("Ошибка: не удалось импортировать модуль 'csprng'.", file=sys.stderr)
    print("Убедитесь, что запускаете скрипт из корневой директории проекта, или установите пакет командой 'pip install -e .'", file=sys.stderr)
    sys.exit(1)


def generate_random_file(filepath, total_bytes):
    chunk_size = 65536

    with open(filepath, 'wb') as f:
        written = 0
        while written < total_bytes:
            to_write = min(chunk_size, total_bytes - written)
            data = generate_random_bytes(to_write)
            f.write(data)
            written += to_write


def main():
    parser = argparse.ArgumentParser(
        description="Генератор случайных данных для NIST STS с использованием CSPRNG из CryptoCore"
    )
    parser.add_argument(
        '--size-mb', type=int, default=10,
        help='Размер выходного файла в мегабайтах (по умолчанию: 10 МБ = 80 000 000 бит)'
    )
    parser.add_argument(
        '--output', type=str, default='nist_test_data.bin',
        help='Имя выходного файла (по умолчанию: nist_test_data.bin)'
    )

    args = parser.parse_args()

    if args.size_mb <= 0:
        print("Ошибка: размер должен быть положительным числом.", file=sys.stderr)
        sys.exit(1)

    total_bytes = args.size_mb * 1024 * 1024
    total_bits = total_bytes * 8

    print("🔍 CryptoCore — Генератор тестовых данных для NIST STS")
    print("=" * 50)
    print(f"• Выходной файл: {os.path.abspath(args.output)}")
    print(f"• Размер: {args.size_mb} МБ ({total_bytes} байт, {total_bits} бит)")
    print()

    try:
        generate_random_file(args.output, total_bytes)
        print("✅ Случайные данные успешно сгенерированы!")
        print()
    except Exception as e:
        print(f"❌ Не удалось сгенерировать файл: {e}", file=sys.stderr)
        sys.exit(1)

    print("📋 Инструкции по запуску NIST STS (с сайта https://csrc.nist.gov):")
    print("-" * 65)
    print("1. Скачайте NIST STS:")
    print("   https://csrc.nist.gov/projects/random-bit-generation/documentation-and-software")
    print()
    print("2. Распакуйте и соберите (Linux/macOS):")
    print("   tar -xzf sts-2.1.2.tar.gz && cd sts-2.1.2 && make")
    print()
    print(f"3. Запустите набор тестов с {total_bits} битами:")
    if os.name == 'nt':
        print(f"   sts-2.1.2.exe {total_bits}")
    else:
        print(f"   ./assess {total_bits}")
    print()
    print("4. При запросе укажите полный путь к вашему файлу:")
    print(f"   {os.path.abspath(args.output)}")
    print()
    print("5. Используйте параметры по умолчанию для всех тестов.")
    print()
    print("6. Результаты будут сохранены в:")
    print("   experiments/AlgorithmTesting/finalAnalysisReport.txt")
    print("   (подробные результаты по каждому тесту: experiments/AlgorithmTesting/*/results.txt)")
    print()
    print("✅ Критерии успеха (в соответствии с NIST SP 800-22):")
    print("   - Большинство тестов проходят (p-значение ≥ 0.01)")
    print("   - Равномерное распределение p-значений по всем тестам")


if __name__ == '__main__':
    main()