#include <benchmark/benchmark.h>
#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <memory>
#include <thread>
#include <iomanip>
#include <map>
#include <algorithm>
#include <mutex>
#include <cstring>

#include "Scaner.h"
#include "generator/Generator.h"

namespace fs = std::filesystem;

// ============================================================================
// ГЛОБАЛЬНЫЕ ДАННЫЕ
// ============================================================================
struct FileEntry {
    std::string name;
    std::string content;
    std::string extension;
};

static std::vector<FileEntry> g_files;
static size_t g_total_bytes = 0;
static GenStats g_expected_stats;

// Для сбора результатов из бенчмарков
static std::mutex g_stats_mutex;
static std::map<std::string, ScanStats> g_benchmark_results;

enum class Strategy {
    CleanStress, // Стратегия 2: Verify Clean -> Benchmark Stress
    Pragmatic    // Стратегия 3: Verify Stress (Pragmatic) -> Benchmark Stress
};

Strategy g_current_strategy = Strategy::CleanStress; // Default

// ============================================================================
// ХЕЛПЕРЫ
// ============================================================================

void update_expected_stats(const std::string& ext) {
    if (ext == ".pdf") g_expected_stats.pdf++;
    else if (ext == ".zip") g_expected_stats.zip++;
    else if (ext == ".rar") g_expected_stats.rar++;
    else if (ext == ".doc") g_expected_stats.doc++;
    else if (ext == ".xls") g_expected_stats.xls++;
    else if (ext == ".ppt") g_expected_stats.ppt++;
    else if (ext == ".docx") g_expected_stats.docx++;
    else if (ext == ".xlsx") g_expected_stats.xlsx++;
    else if (ext == ".pptx") g_expected_stats.pptx++;
    else if (ext == ".png") g_expected_stats.png++;
    else if (ext == ".jpg") g_expected_stats.jpg++;
    else if (ext == ".gif") g_expected_stats.gif++;
    else if (ext == ".bmp") g_expected_stats.bmp++;
    else if (ext == ".mkv") g_expected_stats.mkv++;
    else if (ext == ".mp3") g_expected_stats.mp3++;
    else if (ext == ".json") g_expected_stats.json++;
    else if (ext == ".html") g_expected_stats.html++;
    else if (ext == ".xml") g_expected_stats.xml++;
    else if (ext == ".eml") g_expected_stats.eml++;
    g_expected_stats.total_files++;
}

// Подсчет количества разных найденных типов (для строгого режима)
int CountDistinctTypes(const ScanStats& st) {
    int cnt = 0;
    if (st.pdf > 0) cnt++;
    if (st.zip > 0) cnt++;
    if (st.rar > 0) cnt++;
    if (st.doc > 0) cnt++;
    if (st.xls > 0) cnt++;
    if (st.ppt > 0) cnt++;
    if (st.docx > 0) cnt++;
    if (st.xlsx > 0) cnt++;
    if (st.pptx > 0) cnt++;
    if (st.png > 0) cnt++;
    if (st.jpg > 0) cnt++;
    if (st.gif > 0) cnt++;
    if (st.bmp > 0) cnt++;
    if (st.mkv > 0) cnt++;
    if (st.mp3 > 0) cnt++;
    if (st.json > 0) cnt++;
    if (st.html > 0) cnt++;
    if (st.xml > 0) cnt++;
    if (st.eml > 0) cnt++;
    return cnt;
}

// ============================================================================
// ПОДГОТОВКА ДАННЫХ
// ============================================================================

void LoadDataset(const fs::path& folder, double mix_ratio) {
    const int GEN_COUNT = 50;

    // Перегенерируем данные каждый раз
    if (fs::exists(folder)) fs::remove_all(folder);

    std::cout << "[Setup] Generating dataset in " << folder << " (Mix: " << mix_ratio << ")...\n";
    DataSetGenerator gen;
    gen.generate_count(folder, GEN_COUNT, OutputMode::FOLDER, mix_ratio);

    std::cout << "[Setup] Loading files into RAM...\n";
    g_files.clear();
    g_total_bytes = 0;
    g_expected_stats.reset();

    for (const auto& entry : fs::directory_iterator(folder)) {
        if (entry.is_regular_file()) {
            std::ifstream f(entry.path(), std::ios::binary | std::ios::ate);
            if (!f) continue;
            auto size = f.tellg();
            std::string str(size, '\0');
            f.seekg(0);
            f.read(&str[0], size);

            FileEntry fe;
            fe.name = entry.path().filename().string();
            fe.content = std::move(str);
            fe.extension = entry.path().extension().string();
            std::transform(fe.extension.begin(), fe.extension.end(), fe.extension.begin(), ::tolower);

            g_total_bytes += size;
            update_expected_stats(fe.extension);
            g_files.push_back(std::move(fe));
        }
    }
    std::cout << "[Setup] Loaded " << g_files.size() << " files, "
        << (g_total_bytes / 1024 / 1024) << " MB.\n";
}

// ============================================================================
// ВЕРИФИКАЦИЯ
// ============================================================================

bool IsCorrectDetection(const std::string& ext, const ScanStats& st, bool strict_mode) {
    bool found_target = false;

    if (ext == ".pdf") found_target = st.pdf > 0;
    else if (ext == ".zip") found_target = st.zip > 0;
    else if (ext == ".rar") found_target = st.rar > 0;
    else if (ext == ".doc") found_target = st.doc > 0;
    else if (ext == ".xls") found_target = st.xls > 0;
    else if (ext == ".ppt") found_target = st.ppt > 0;
    else if (ext == ".docx") found_target = st.docx > 0;
    else if (ext == ".xlsx") found_target = st.xlsx > 0;
    else if (ext == ".pptx") found_target = st.pptx > 0;
    else if (ext == ".png") found_target = st.png > 0;
    else if (ext == ".jpg") found_target = st.jpg > 0;
    else if (ext == ".gif") found_target = st.gif > 0;
    else if (ext == ".bmp") found_target = st.bmp > 0;
    else if (ext == ".mkv") found_target = st.mkv > 0;
    else if (ext == ".mp3") found_target = st.mp3 > 0;
    else if (ext == ".json") found_target = st.json > 0;
    else if (ext == ".html") found_target = st.html > 0;
    else if (ext == ".xml") found_target = st.xml > 0;
    else if (ext == ".eml") found_target = st.eml > 0;

    if (!found_target) return false;

    // Строгий режим: проверяем, что не найдено лишних типов
    if (strict_mode) {
        if (CountDistinctTypes(st) > 1) return false;
    }

    return true;
}

void UpdateMatchedStats(GenStats& matched, const std::string& ext) {
    if (ext == ".pdf") matched.pdf++;
    else if (ext == ".zip") matched.zip++;
    else if (ext == ".rar") matched.rar++;
    else if (ext == ".doc") matched.doc++;
    else if (ext == ".xls") matched.xls++;
    else if (ext == ".ppt") matched.ppt++;
    else if (ext == ".docx") matched.docx++;
    else if (ext == ".xlsx") matched.xlsx++;
    else if (ext == ".pptx") matched.pptx++;
    else if (ext == ".png") matched.png++;
    else if (ext == ".jpg") matched.jpg++;
    else if (ext == ".gif") matched.gif++;
    else if (ext == ".bmp") matched.bmp++;
    else if (ext == ".mkv") matched.mkv++;
    else if (ext == ".mp3") matched.mp3++;
    else if (ext == ".json") matched.json++;
    else if (ext == ".html") matched.html++;
    else if (ext == ".xml") matched.xml++;
    else if (ext == ".eml") matched.eml++;
}

void PrintVerificationTable(const std::string& engine_name, const GenStats& matched, bool strict) {
    auto row = [&](const std::string& n, int exp, int act) {
        std::string status = (act == exp) ? "OK" : (act < exp ? "MISS" : "FP?");
        std::cout << "| " << std::left << std::setw(12) << n
            << " | " << std::setw(6) << exp
            << " | " << std::setw(6) << act
            << " | " << status << "\n";
        };

    std::cout << "\n--- Accuracy (" << (strict ? "Strict" : "Pragmatic") << "): " << engine_name << " ---\n";
    std::cout << "| TYPE         | GEN    | MATCH  | STATUS\n";
    std::cout << "|--------------|--------|--------|-------\n";
    row("PDF", g_expected_stats.pdf, matched.pdf);
    row("ZIP", g_expected_stats.zip, matched.zip);
    row("DOCX", g_expected_stats.docx, matched.docx);
    row("JPG", g_expected_stats.jpg, matched.jpg);
    row("JSON", g_expected_stats.json, matched.json);
    row("XML", g_expected_stats.xml, matched.xml);

    int total_matched = matched.pdf + matched.zip + matched.rar +
        matched.doc + matched.xls + matched.ppt +
        matched.docx + matched.xlsx + matched.pptx +
        matched.png + matched.jpg + matched.gif + matched.bmp +
        matched.mkv + matched.mp3 +
        matched.json + matched.html + matched.xml + matched.eml;

    std::cout << "|--------------|--------|--------|-------\n";
    row("TOTAL ACCURACY", g_expected_stats.total_files, total_matched);
    std::cout << "------------------------------------------\n";
}

void VerifyAll(bool strict) {
    std::cout << "\n[Verify] Running " << (strict ? "STRICT" : "PRAGMATIC") << " accuracy verification...\n";

    auto check_engine = [&](std::unique_ptr<Scanner> s) {
        s->prepare();
        GenStats matched_stats;

        for (const auto& file : g_files) {
            ScanStats st;
            s->scan(file.content.data(), file.content.size(), st);

            if (IsCorrectDetection(file.extension, st, strict)) {
                UpdateMatchedStats(matched_stats, file.extension);
            }
        }
        PrintVerificationTable(s->name(), matched_stats, strict);
        };

    check_engine(std::make_unique<StdScanner>(true)); // Opt
    check_engine(std::make_unique<Re2Scanner>());
    check_engine(std::make_unique<BoostScanner>(true)); // Opt
    check_engine(std::make_unique<HsScanner>());
}

// ============================================================================
// BENCHMARK (Скорость)
// ============================================================================

template <typename ScannerT, bool PreCheck = false>
void BM_Scan(benchmark::State& state) {
    std::unique_ptr<Scanner> scanner;
    if constexpr (std::is_same_v<ScannerT, StdScanner> || std::is_same_v<ScannerT, BoostScanner>) {
        scanner = std::make_unique<ScannerT>(PreCheck);
    }
    else {
        scanner = std::make_unique<ScannerT>();
    }
    scanner->prepare();

    size_t total_files = g_files.size();
    size_t batch_size = (total_files + state.threads() - 1) / state.threads();
    size_t start_idx = state.thread_index() * batch_size;
    size_t end_idx = std::min(start_idx + batch_size, total_files);

    ScanStats stats; // Dummy stats

    for (auto _ : state) {
        for (size_t i = start_idx; i < end_idx; ++i) {
            scanner->scan(g_files[i].content.data(), g_files[i].content.size(), stats);
        }
    }

    size_t bytes_processed = 0;
    for (size_t i = start_idx; i < end_idx; ++i) bytes_processed += g_files[i].content.size();
    state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * bytes_processed);

    // Сбор результатов (опционально, для общей таблицы)
    ScanStats thread_stats; // Если нужно собрать статистику по потокам
    // ... логика сбора статистики, если нужна таблица в конце ...
    // В данном примере таблица печатается отдельно через VerifyAll,
    // а бенчмарк выводит только скорость.
}

BENCHMARK_TEMPLATE(BM_Scan, StdScanner, false)->Name("Std_Raw")->Unit(benchmark::kMillisecond)->Threads(1)->Threads(16);
BENCHMARK_TEMPLATE(BM_Scan, StdScanner, true)->Name("Std_Opt")->Unit(benchmark::kMillisecond)->Threads(1)->Threads(16);
BENCHMARK_TEMPLATE(BM_Scan, Re2Scanner)->Name("RE2")->Unit(benchmark::kMillisecond)->Threads(1)->Threads(16);
BENCHMARK_TEMPLATE(BM_Scan, BoostScanner, false)->Name("Boost_Raw")->Unit(benchmark::kMillisecond)->Threads(1)->Threads(16);
BENCHMARK_TEMPLATE(BM_Scan, BoostScanner, true)->Name("Boost_Opt")->Unit(benchmark::kMillisecond)->Threads(1)->Threads(16);
BENCHMARK_TEMPLATE(BM_Scan, HsScanner)->Name("Hyperscan")->Unit(benchmark::kMillisecond)->Threads(1)->Threads(16);

// ============================================================================
// MAIN (Интерактивный)
// ============================================================================

void print_help() {
    std::cout << "Usage: Benchmarks.exe [google-benchmark-options] [--strategy=STRAT]\n"
        << "Strategies:\n"
        << "  clean_stress (Default): \n"
        << "      1. Generate CLEAN data (mix=0.0). Verify Strict accuracy.\n"
        << "      2. Generate STRESS data (mix=0.2). Run Benchmarks.\n"
        << "  pragmatic: \n"
        << "      1. Generate STRESS data (mix=0.2).\n"
        << "      2. Verify Pragmatic accuracy (ignore extra detections).\n"
        << "      3. Run Benchmarks.\n\n";
}

int main(int argc, char** argv) {
    bool strategy_selected = false;

    // 1. Парсинг аргументов
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--help") {
            print_help();
            return 0;
        }
        if (std::string(argv[i]) == "--strategy=clean_stress") {
            g_current_strategy = Strategy::CleanStress;
            strategy_selected = true;
        }
        else if (std::string(argv[i]) == "--strategy=pragmatic") {
            g_current_strategy = Strategy::Pragmatic;
            strategy_selected = true;
        }
    }

    // 2. Интерактивное меню (если стратегия не выбрана через аргументы)
    if (!strategy_selected) {
        std::cout << "-------------------------------------------------------------\n";
        std::cout << "No strategy specified. Select execution mode:\n";
        std::cout << "  1. Clean -> Stress (Strict Verify on clean data -> Benchmark) [Default]\n";
        std::cout << "  2. Pragmatic (Strict Verify on stress data, lenient on noise -> Benchmark)\n";
        std::cout << "Enter choice [1/2]: ";

        std::string input;
        std::getline(std::cin, input);

        if (input == "2") {
            g_current_strategy = Strategy::Pragmatic;
        }
        else {
            g_current_strategy = Strategy::CleanStress;
            std::cout << "Selected: Clean -> Stress\n";
        }
        std::cout << "-------------------------------------------------------------\n\n";
    }

    Scanner::SilentMode = true;

    // 3. Выполнение выбранной стратегии
    if (g_current_strategy == Strategy::CleanStress) {
        std::cout << ">>> STRATEGY 2: Clean Verification -> Stress Benchmark\n";

        // Этап 1: Чистые данные для проверки точности
        LoadDataset("bench_data_clean", 0.0);
        VerifyAll(true); // Строгая проверка

        // Этап 2: Грязные данные для замера скорости
        std::cout << "\n>>> Switching to STRESS data for Benchmarking...\n";
        LoadDataset("bench_data_stress", 0.2);
    }
    else {
        std::cout << ">>> STRATEGY 3: Pragmatic Verification -> Stress Benchmark\n";

        // Один этап: Грязные данные, но мягкая проверка
        LoadDataset("bench_data_stress", 0.2);
        VerifyAll(false); // Прагматичная проверка
    }

    // 4. Запуск бенчмарков
    std::cout << "\n[Benchmark] Running performance tests...\n";
    ::benchmark::Initialize(&argc, argv);
    if (::benchmark::ReportUnrecognizedArguments(argc, argv)) return 1;
    ::benchmark::RunSpecifiedBenchmarks();

    return 0;
}
