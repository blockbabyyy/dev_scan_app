#pragma once
// Scanner.h — главный заголовок для сканера сигнатур
// Здесь определяются основные структуры и классы для поиска файловых сигнатур
//
// Что такое файловая сигнатура?
// Это уникальная последовательность байт в начале/конце файла (magic bytes).
// Например, PDF всегда начинается с "%PDF" (в hex: 25 50 44 46).
//
// Архитектура:
// Scanner (абстрактный класс) — определяет интерфейс для всех движков
// ├── BoostScanner   — использует Boost.Regex, медленный но надёжный
// ├── Re2Scanner     — Google RE2, быстрый, безопасный (no backtracking)
// └── HsScanner      — Intel Hyperscan, самый быстрый (SIMD инструкции)

#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <boost/regex.hpp>

// Forward declarations — чтобы не включать тяжёлые заголовки
// Это ускоряет компиляцию и уменьшает зависимости
namespace re2 { class RE2; }
struct hs_database;  // Внутренняя структура Hyperscan (opaque pointer)
struct hs_scratch;   // Рабочая память для Hyperscan

// Типы сигнатур: бинарные (PDF, ZIP) или текстовые (JSON, HTML)
enum class SignatureType { BINARY, TEXT };

// Доступные движки сканирования
// Hyperscan — дефолтный выбор (лучшая производительность)
enum class EngineType { BOOST, RE2, HYPERSCAN };

// Определение одной сигнатуры
// Пример из signatures.json:
// {
//   "name": "PDF",
//   "type": "binary",
//   "hex_head": "25504446",
//   "hex_tail": "2525454F46",
//   "priority": 5,
//   "min_file_size": 64
// }
struct SignatureDefinition {
    std::string name;                    // Имя типа (например, "PDF")
    std::string hex_head;                // Magic bytes начала файла (hex строка)
    std::string hex_tail;                // Magic bytes конца файла (опционально)
    std::string text_pattern;            // Regex для текстовых сигнатур или доп. паттерн
    SignatureType type = SignatureType::BINARY;  // Тип сигнатуры
    
    // Механизм вычитания коллизий
    // Пример: DOCX — это ZIP с определённой структурой
    // Если найден DOCX, вычитаем 1 из счётчика ZIP
    std::string deduct_from;
    
    std::vector<std::string> extensions;  // Расширения файлов (.pdf, .docx)
    int priority = 0;                     // Приоритет (выше = проверяется первым)
                                          // Нужно для разрешения конфликтов (RAR4 vs RAR5)
    int min_file_size = 0;                // Минимальный размер файла для детекции
                                          // Защита от ложных срабатываний на маленьких файлах
    
    // Взаимоисключающие сигнатуры
    // Пример: RAR4 exclusive_with ["RAR5"]
    // RAR5 включает заголовок RAR4, поэтому если найден RAR5, RAR4 не показываем
    std::vector<std::string> exclusive_with;
};

// Статистика сканирования одного файла или группы файлов
// Хранит количество найденных сигнатур каждого типа
struct ScanStats {
    std::map<std::string, int> counts;         // Основные детекции (тип -> количество)
    std::set<std::string> detected_types;      // Track which types were detected (for single-match-per-file)
    std::map<std::string, int> embedded_counts;  // Вложенные детекции (внутри контейнеров)
    int total_files_processed = 0;             // Сколько файлов обработано

    // Добавляет детекцию только один раз на файл
    // Это предотвращает множественные срабатывания на одну сигнатуру в большом файле
    // Пример: внутри DOCX может быть 10 вхождений "word/document.xml",
    // но мы считаем это как ОДИН файл DOCX
    bool add_once(const std::string& name) {
        if (detected_types.count(name)) return false;  // Уже было
        detected_types.insert(name);
        counts[name]++;
        return true;
    }

    // Legacy метод (для обратной совместимости, не используется в новом коде)
    void add(const std::string& name) { counts[name]++; }

    // Полный сброс статистики
    void reset() { counts.clear(); detected_types.clear(); embedded_counts.clear(); total_files_processed = 0; }

    // Сброс состояния перед сканированием нового файла
    // detected_types очищается, но counts сохраняется (для агрегации по всем файлам)
    void reset_file_state() { detected_types.clear(); }

    // Оператор сложения — объединяет статистику из нескольких потоков
    // Каждый поток сканирует свою пачку файлов, потом результаты мерджатся
    ScanStats& operator+=(const ScanStats& other) {
        for (const auto& [name, count] : other.counts) counts[name] += count;
        for (const auto& [name, count] : other.embedded_counts) embedded_counts[name] += count;
        for (const auto& t : other.detected_types) detected_types.insert(t);
        total_files_processed += other.total_files_processed;
        return *this;
    }
};

// Функции постобработки результатов
// Вызываются после сканирования всех файлов для коррекции счётчиков

// 1. Вычитание коллизий
// Пример: если найдено 5 DOCX и 15 ZIP, после apply_deduction будет 5 DOCX и 10 ZIP
void apply_deduction(ScanStats& stats, const std::vector<SignatureDefinition>& sigs);

// 2. Иерархия контейнеров
// ZIP-производные (DOCX/XLSX/PPTX) вычитаются из общего счётчика ZIP
void apply_container_hierarchy(ScanStats& stats);

// 3. Фильтрация ложных срабатываний внутри контейнеров
// Если файл — контейнер (DOCX/PPTX), то PNG/JPG внутри него считаем вложенными
void apply_container_false_positive_filter(ScanStats& stats);

// 4. Взаимоисключающие сигнатуры
// RAR4 vs RAR5: если оба найдены, оставляем только один по приоритету
void apply_exclusive_filter(ScanStats& stats, const std::vector<SignatureDefinition>& sigs);

// Базовый класс сканера (интерфейс)
// Используется полиморфизм для переключения между движками
class Scanner {
public:
    virtual ~Scanner() = default;
    
    // Подготовка движка — компиляция паттернов
    // Вызывается один раз перед сканированием группы файлов
    virtual void prepare(const std::vector<SignatureDefinition>& sigs) = 0;
    
    // Сканирование данных
    // data: указатель на данные файла (memory-mapped)
    // size: размер данных в байтах
    // stats: структура для записи результатов
    virtual void scan(const char* data, size_t size, ScanStats& stats) = 0;
    
    // Название движка для вывода в отчёте
    virtual std::string name() const = 0;
    
    // Фабричный метод для создания нужного движка
    // Пример: auto scanner = Scanner::create(EngineType::HYPERSCAN);
    static std::unique_ptr<Scanner> create(EngineType type);
};

// Boost.Scanner — использует Boost.Regex
// Плюсы: простая отладка, хорошие сообщения об ошибках
// Минусы: медленный (backtracking regex), нет оптимизаций
class BoostScanner : public Scanner {
public:
    void prepare(const std::vector<SignatureDefinition>& sigs) override;
    void scan(const char* data, size_t size, ScanStats& stats) override;
    std::string name() const override;
private:
    // Пары (скомпилированный regex, имя сигнатуры)
    std::vector<std::pair<boost::regex, std::string>> m_regexes;
};

// RE2::Set не может быть forward declared — используем type-erased deleter
// Это позволяет хранить RE2::Set в unique_ptr без включения заголовка re2/set.h
struct Re2SetDeleter { void operator()(void* p) const noexcept; };

// Google RE2 Scanner
// Плюсы: быстрый, безопасный (no catastrophic backtracking)
// Минусы: менее гибкий regex (нет lookbehind)
//
// Алгоритм работы (two-phase):
// 1. RE2::Set — быстрый фильтр "какие паттерны вообще совпали?"
// 2. Индивидуальные regex — подсчёт количества совпадений для каждого
class Re2Scanner : public Scanner {
public:
    Re2Scanner();           // Конструктор (re2::RE2 должен быть complete типом)
    ~Re2Scanner() override; // Деструктор (освобождает память)
    void prepare(const std::vector<SignatureDefinition>& sigs) override;
    void scan(const char* data, size_t size, ScanStats& stats) override;
    std::string name() const override;
private:
    std::unique_ptr<void, Re2SetDeleter> m_set;  // RE2::Set для фильтра
    std::vector<std::string> m_sig_names;         // Имена сигнатур по ID
    std::vector<std::pair<std::unique_ptr<re2::RE2>, std::string>> m_regexes;  // Индивидуальные regex
};

// Intel Hyperscan Scanner
// Плюсы: самый быстрый (использует SIMD, аппаратные ускорители)
// Минусы: сложная сборка, большие бинарники
//
// ВАЖНО: HsScanner НЕ потокобезопасен!
// hs_scratch — рабочая память, не может использоваться несколькими потоками одновременно
// Решение: каждый поток создаёт свой экземпляр HsScanner
// В main_cli.cpp это реализовано через лямбду scan_chunk
class HsScanner : public Scanner {
public:
    HsScanner();
    ~HsScanner() override;
    void prepare(const std::vector<SignatureDefinition>& sigs) override;
    void scan(const char* data, size_t size, ScanStats& stats) override;
    std::string name() const override;
private:
    hs_database* db = nullptr;       // Скомпилированная база паттернов
    hs_scratch* scratch = nullptr;   // Рабочая память (per-thread!)
    std::vector<std::string> m_sig_names;  // Имена сигнатур по ID
    std::vector<std::string> m_temp_patterns;  // Хранение строк паттернов (чтобы не удалились)
};
