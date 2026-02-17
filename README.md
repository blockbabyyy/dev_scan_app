# DevScan

Инструмент глубокого поиска файловых сигнатур внутри произвольных контейнеров: папок, ZIP-архивов, бинарных склеек (BIN) и дампов трафика (PCAP).

## Возможности

- **Три движка сканирования**: [Hyperscan](https://github.com/intel/hyperscan) (по умолчанию), [RE2](https://github.com/google/re2), [Boost.Regex](https://www.boost.org/doc/libs/release/libs/regex/)
- **21 тип файлов** из коробки (PDF, ZIP, RAR4/5, PNG, JPG, GIF, BMP, MKV, MP3, OLE, DOC, XLS, PPT, DOCX, XLSX, PPTX, JSON, HTML, XML, EMAIL)
- **Коррекция коллизий** — DOCX/XLSX/PPTX автоматически вычитаются из ZIP, DOC/XLS/PPT из OLE
- **Конфигурируемые сигнатуры** — добавляйте свои типы через `signatures.json`
- **Экспорт результатов** — отчёты в JSON и TXT (`crash_report/report.json`, `crash_report/report.txt`)
- **Логирование** — лог-файл в `crash_report/devscan_YYYYMMDD_HHMMSS.log`
- **Бенчмарки** — сравнение производительности движков на сгенерированных датасетах

## Структура проекта

```
DevScan/
├── include/
│   ├── Scaner.h            # Интерфейс Scanner + движки (Boost, RE2, Hyperscan)
│   ├── ConfigLoader.h      # Загрузка сигнатур из JSON
│   ├── TypeMap.h            # Маппинг расширений -> имён типов
│   ├── Logger.h             # Логгер (crash_report/)
│   ├── ReportWriter.h       # Экспорт результатов (JSON/TXT)
│   └── generator/
│       └── Generator.h      # Генератор тестовых датасетов
├── src/
│   ├── Scaner.cpp           # Реализации движков
│   ├── cli/
│   │   └── main_cli.cpp     # CLI-приложение
│   └── generator/
│       └── Generator.cpp    # Реализация генератора
├── tests/
│   ├── ScanerTests.cpp      # Юнит-тесты (12 тестов, 3 движка x 4 кейса)
│   ├── IntegrationTests.cpp # Интеграционные тесты (Folder, ZIP, BIN, PCAP)
│   └── Benchmarks.cpp       # Бенчмарки производительности
├── signatures.json          # База сигнатур
└── CMakeLists.txt
```

## Требования

- C++17
- [CMake](https://cmake.org/) >= 3.21
- [vcpkg](https://vcpkg.io/)

### Зависимости (vcpkg)

```bash
vcpkg install hyperscan re2 boost-regex boost-iostreams nlohmann-json gtest benchmark
```

## Сборка

```bash
mkdir build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=<путь_к_vcpkg>/scripts/buildsystems/vcpkg.cmake
cmake --build . --config Release
```

Будут собраны три таргета:

| Таргет | Описание |
|---|---|
| `DevScanApp` | CLI-приложение |
| `DevScanTests` | Юнит- и интеграционные тесты (GTest) |
| `DevScanBenchmarks` | Бенчмарки (Google Benchmark) |

## Использование

### Базовый запуск

```bash
DevScanApp.exe <путь_к_папке_или_файлу>
```

### С параметрами

```bash
DevScanApp.exe C:/data -c my_sigs.json -e re2
```

| Опция | Описание |
|---|---|
| `-c, --config <file>` | Путь к файлу сигнатур (по умолчанию: `signatures.json`) |
| `-e, --engine <type>` | Движок: `hs` (Hyperscan), `re2`, `boost` |

### Вывод

После сканирования программа:
1. Выводит таблицу результатов в stdout
2. Сохраняет `crash_report/report.json` и `crash_report/report.txt`
3. Пишет лог в `crash_report/devscan_YYYYMMDD_HHMMSS.log`

Пример вывода:

```
[Info] Сканирование: C:/data движком Hyperscan...

--- РЕЗУЛЬТАТЫ СКАНЕРА ---
Тип файла       | Найдено
--------------------------
PDF             | 10
ZIP             | 5
DOC             | 3
--------------------------
Всего файлов обработано: 150

[Отчёты] crash_report/report.json, crash_report/report.txt
[Лог]    crash_report/devscan_20260217_143052.log
```

### Формат report.json

```json
{
  "scan_target": "C:/data",
  "engine": "Hyperscan",
  "total_files_processed": 150,
  "detections": {
    "PDF": 10,
    "ZIP": 5,
    "DOC": 3
  }
}
```

## Сигнатуры

Сигнатуры хранятся в `signatures.json`. Каждая запись содержит:

| Поле | Тип | Описание |
|---|---|---|
| `name` | string | Имя типа (например, `"PDF"`) |
| `type` | string | `"binary"` или `"text"` |
| `hex_head` | string | Magic bytes начала файла (HEX) |
| `hex_tail` | string | Magic bytes конца файла (HEX, опционально) |
| `pattern` | string | Regex-паттерн для текстовых сигнатур |
| `text_pattern` | string | Дополнительный текстовый якорь для бинарных сигнатур |
| `deduct_from` | string | Тип-родитель для вычитания коллизий (опционально) |

### Пример: бинарная сигнатура

```json
{
  "name": "MY_FORMAT",
  "type": "binary",
  "hex_head": "4D5A",
  "hex_tail": "00000000",
  "deduct_from": "ZIP"
}
```

### Пример: текстовая сигнатура

```json
{
  "name": "LOG_ERROR",
  "type": "text",
  "pattern": "Error:\\s\\d+"
}
```

### Механизм вычитания (deduct_from)

Некоторые форматы являются подмножествами других (DOCX это ZIP с определённой структурой, DOC это OLE). Поле `deduct_from` автоматически корректирует счётчик родительского типа:

```
ZIP: 15  (до коррекции)
DOCX: 5, XLSX: 3, PPTX: 2  (deduct_from: ZIP)
ZIP: 5   (после коррекции: 15 - 5 - 3 - 2 = 5)
```

## Тесты

```bash
# Запуск всех тестов
./DevScanTests

# Через CTest
ctest --test-dir build
```

### Набор тестов (16 тестов)

**Юнит-тесты** (12 = 3 движка x 4 кейса):
- `Detection_PDF` — детекция PDF по head + tail
- `Detection_ZIP` — детекция ZIP по head
- `Office_Vs_Zip_No_Deduction` — DOCX внутри ZIP без вычитания
- `Empty_Data` — пустой ввод

**Интеграционные тесты** (4):
- `Folder_Scan_With_Generator` — генерация папки с 50 файлами, проверка всех типов
- `Zip_Archive_Internal_Scan` — генерация ZIP-архива, детекция ZIP-структуры
- `Bin_Concat_Scan` — генерация бинарной склейки (30 файлов), проверка всех типов
- `Pcap_Dump_Scan` — генерация PCAP-дампа (30 файлов), проверка всех типов

## Бенчмарки

```bash
./DevScanBenchmarks
```

Сравнивает производительность Hyperscan, RE2 и Boost.Regex на сгенерированных датасетах разных режимов (FOLDER, BIN, PCAP).

## Логирование

Логгер автоматически инициализируется при запуске `DevScanApp`. Все события пишутся в файл `crash_report/devscan_YYYYMMDD_HHMMSS.log`:

| Уровень | Файл | stderr |
|---|---|---|
| `INFO` | да | нет |
| `WARN` | да | да |
| `ERROR` | да | да |

Формат строки лога:

```
[2026-02-17 14:30:52] [INFO] DevScan запущен
[2026-02-17 14:30:52] [INFO] Загрузка конфигурации: signatures.json
[2026-02-17 14:30:52] [WARN] Пропуск файла C:/data/locked.bin: permission denied
[2026-02-17 14:30:53] [INFO] Сканирование завершено. Файлов обработано: 150
```

## Лицензия

MIT
