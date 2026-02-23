# DevScan

Инструмент глубокого поиска файловых сигнатур внутри произвольных контейнеров: папок, ZIP-архивов, бинарных склеек (BIN) и дампов трафика (PCAP).

## Возможности

- **Три движка сканирования**: [Hyperscan](https://github.com/intel/hyperscan) (по умолчанию), [RE2](https://github.com/google/re2), [Boost.Regex](https://www.boost.org/doc/libs/release/libs/regex/)
- **27 типов файлов** из коробки (PDF, ZIP, RAR4/5, PNG, JPG, GIF, BMP, MKV, MP3, OLE, DOC, XLS, PPT, DOCX, XLSX, PPTX, JSON, HTML, XML, EMAIL, 7Z, GZIP, PE, SQLITE, FLAC, WAV)
- **Коррекция коллизий** — DOCX/XLSX/PPTX автоматически вычитаются из ZIP, DOC/XLS/PPT из OLE
- **Конфигурируемые сигнатуры** — добавляйте свои типы через `signatures.json` или интерактивным визардом `--add-sig`
- **Экспорт результатов** — отчёты в JSON и TXT (`crash_report/report.json`, `crash_report/report.txt`)
- **Логирование** — лог-файл в `crash_report/devscan_YYYYMMDD_HHMMSS.log`
- **Многопоточность** — по умолчанию используются все ядра процессора
- **Бенчмарки** — сравнение производительности движков на сгенерированных датасетах

## Структура проекта

```
DevScan/
├── include/
│   ├── Scanner.h           # Интерфейс Scanner + движки (Boost, RE2, Hyperscan)
│   ├── ConfigLoader.h      # Загрузка сигнатур из JSON
│   ├── TypeMap.h           # build_ext_to_type / build_type_to_ext (по сигнатурам)
│   ├── Logger.h            # Логгер (crash_report/)
│   ├── ReportWriter.h      # Экспорт результатов (JSON/TXT)
│   └── generator/
│       └── Generator.h     # Генератор тестовых датасетов
├── src/
│   ├── Scanner.cpp         # Реализации движков + apply_deduction
│   ├── cli/
│   │   └── main_cli.cpp    # CLI-приложение
│   └── generator/
│       └── Generator.cpp   # Реализация генератора
├── tests/
│   ├── ScannerTests.cpp    # Юнит-тесты (45 тестов)
│   ├── IntegrationTests.cpp# Интеграционные тесты (Folder, ZIP, BIN, PCAP)
│   └── Benchmarks.cpp      # Бенчмарки производительности
├── signatures.json         # База сигнатур
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

> `signatures.json` автоматически копируется в build-директорию при каждом изменении.

## Использование

### Справка

```bash
DevScanApp.exe --help
DevScanApp.exe --version
```

### Базовый запуск

```bash
DevScanApp.exe <путь_к_папке_или_файлу>
```

### Все опции

```bash
DevScanApp.exe C:/data -e re2 -j 8 --output-json report.json
```

| Опция | Описание |
|---|---|
| `-c, --config <file>` | Путь к файлу сигнатур (по умолчанию: `signatures.json`) |
| `-e, --engine <type>` | Движок: `hs` (Hyperscan, по умолчанию), `re2`, `boost` |
| `-j, --threads <N>` | Количество потоков (по умолчанию: число ядер CPU) |
| `-m, --max-filesize <MB>` | Максимальный размер файла в МБ (по умолчанию: 512) |
| `--output-json <path>` | Сохранить JSON-отчёт по указанному пути |
| `--output-txt <path>` | Сохранить TXT-отчёт по указанному пути |
| `--no-report` | Не генерировать отчёты |
| `--add-sig` | Интерактивный визард для добавления новой сигнатуры |

### Вывод

После сканирования программа:
1. Выводит таблицу результатов в stdout
2. Сохраняет `crash_report/report.json` и `crash_report/report.txt` (если не указано `--no-report`)
3. Пишет лог в `crash_report/devscan_YYYYMMDD_HHMMSS.log`

Пример вывода:

```
[Info] Scanning: C:/data (150 files, 8 threads, engine: Hyperscan)

--- SCAN RESULTS ---
Type            | Count
--------------------------
PDF             | 10
ZIP             | 5
DOC             | 3
--------------------------
Files processed: 150  (1.23s)
[Reports] crash_report/report.json, crash_report/report.txt
[Log]     crash_report/devscan_20260223_143052.log
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

Сигнатуры хранятся в `signatures.json` — единственный источник истины для сканера, генератора и маппинга расширений. Каждая запись:

| Поле | Тип | Описание |
|---|---|---|
| `name` | string | Имя типа (например, `"PDF"`) |
| `type` | string | `"binary"` или `"text"` |
| `extensions` | array | Расширения файлов (например, `[".pdf"]`, `[".exe", ".dll"]`, `[]`) |
| `hex_head` | string | Magic bytes начала файла (HEX) |
| `hex_tail` | string | Magic bytes конца файла (HEX, опционально) |
| `text_pattern` | string | Дополнительный regex-якорь для бинарных сигнатур |
| `pattern` | string | Regex-паттерн для текстовых сигнатур (`type: "text"`) |
| `deduct_from` | string | Тип-родитель для вычитания коллизий (опционально) |

### Пример: бинарная сигнатура

```json
{
  "name": "MY_FORMAT",
  "type": "binary",
  "extensions": [".myf"],
  "hex_head": "4D5A",
  "hex_tail": "00000000"
}
```

### Пример: текстовая сигнатура

```json
{
  "name": "LOG_ERROR",
  "type": "text",
  "extensions": [".log"],
  "pattern": "Error:\\s\\d+"
}
```

### Добавление сигнатуры через визард

```bash
DevScanApp.exe --add-sig
# или с нестандартным конфигом:
DevScanApp.exe --add-sig -c my_sigs.json
```

Визард проведёт по шагам:
1. Ввод имени типа
2. Выбор типа (`binary` / `text`)
3. Путь к sample-файлу для авто-определения magic bytes (или ввод HEX вручную)
4. Опциональное чтение tail-байт из того же файла
5. Regex-якорь для уточнения (опционально)
6. Список расширений через запятую
7. `deduct_from` (опционально)
8. Превью JSON → подтверждение → запись в файл

### Механизм вычитания (deduct_from)

Некоторые форматы являются подмножествами других (DOCX — это ZIP с определённой структурой, DOC — это OLE с маркером `WordDocument`). Поле `deduct_from` автоматически корректирует счётчик родительского типа:

```
ZIP: 15  → после коррекции: 15 - 5(DOCX) - 3(XLSX) - 2(PPTX) = 5
```

> Вычитание однопроходное (плоское). Транзитивные цепочки не поддерживаются.

## Тесты

```bash
# Запуск всех тестов
./DevScanTests

# Через CTest
ctest --test-dir build
```

### Набор тестов (45 тестов)

**ScannerTest** — типизированные тесты, запускаются на всех трёх движках (3 × 7 = 21):

| Тест | Описание |
|---|---|
| `Detection_PDF` | Детекция PDF по head + tail |
| `Detection_ZIP` | Детекция ZIP по head |
| `Office_ZIP_And_DOCX_Both_Detected` | DOCX и ZIP одновременно детектируются до вычитания |
| `Empty_Data` | Пустой буфер не даёт совпадений |
| `Single_Byte` | Один байт не даёт совпадений |
| `All_Zeros` | Буфер из нулей не даёт ложных срабатываний |
| `Multiple_PDF_In_Same_Buffer` | Несколько PDF в одном буфере считаются корректно |

**FalsePositiveTest** — тесты на ложные срабатывания, все движки (3 × 3 = 9):

| Тест | Описание |
|---|---|
| `BMP_No_FP_On_Plain_BM` | "BM" без нулевых байт не детектируется как BMP |
| `Email_No_FP_On_Lone_From` | Одиночный "From:" без заголовков не даёт EMAIL |
| `Email_Positive_With_Headers` | Полноценные заголовки детектируются как EMAIL |

**DeductionTest** (2):
- `DOCX_Deducted_From_ZIP` — вычитание DOCX из ZIP корректно
- `Deduction_Does_Not_Go_Negative` — вычитание не уходит в отрицательные значения

**ConfigLoaderTest** (9): загрузка валидных/невалидных конфигов, обработка ошибок.

**IntegrationTest** (4):
- `Folder_Scan_With_Generator` — генерация папки с 50 файлами, проверка всех типов
- `Zip_Archive_Internal_Scan` — генерация ZIP-архива, детекция ZIP-структуры
- `Bin_Concat_Scan` — генерация бинарной склейки (30 файлов), проверка всех типов
- `Pcap_Dump_Scan` — генерация PCAP-дампа (30 файлов), проверка всех типов

## Бенчмарки

```bash
./DevScanBenchmarks
```

Запускает сравнение Hyperscan, RE2 и Boost.Regex на датасете из 50 файлов (mix=0.2) в режимах 1 и 8 потоков. Перед бенчмарком выводится таблица точности детекции по каждому движку.

## Архитектура

### Иерархия Scanner

```
Scanner (abstract)
├── BoostScanner   — Boost.Regex, однопоточный
├── Re2Scanner     — Google RE2, двухфазный (Set-filter + счёт)
└── HsScanner      — Intel Hyperscan, BLOCK-mode
                     ⚠ не потокобезопасен: каждый поток создаёт свой экземпляр
```

Создание движка:
```cpp
auto scanner = Scanner::create(EngineType::HYPERSCAN);
scanner->prepare(sigs);
scanner->scan(data, size, stats);
apply_deduction(stats, sigs); // из Scanner.h
```

### Формат ScanStats

```cpp
struct ScanStats {
    std::map<std::string, int> counts;   // тип -> количество
    int total_files_processed = 0;
};
```

## Логирование

| Уровень | Файл | stderr |
|---|---|---|
| `INFO` | да | нет |
| `WARN` | да | да |
| `ERROR` | да | да |

Формат строки лога:

```
[2026-02-23 14:30:52] [INFO] DevScan started
[2026-02-23 14:30:52] [INFO] Loading config: signatures.json
[2026-02-23 14:30:52] [WARN] Skipped: C:/data/locked.bin: permission denied
[2026-02-23 14:30:53] [INFO] Scan complete. Files: 150, time: 1.23s
```

## Лицензия

MIT
