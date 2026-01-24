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

#include "Scaner.h"
#include "generator/Generator.h"

namespace fs = std::filesystem;

// ============================================================================
// ГЛОБАЛЬНЫЕ ДАННЫЕ
// ============================================================================
static std::vector<std::string> g_file_contents;
static size_t g_total_bytes = 0;
static GenStats g_expected_stats;

// Для сбора результатов из бенчмарков без повторного запуска
static std::mutex g_stats_mutex;
static std::map<std::string, ScanStats> g_benchmark_results;

// ============================================================================
// ПОДГОТОВКА ДАННЫХ
// ============================================================================
void update_expected_stats(const fs::path& path) {
    std::string ext = path.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

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

void PrepareDataset() {
    const int GEN_COUNT = 50;
    const fs::path GEN_DIR = "bench_data";

    if (!fs::exists(GEN_DIR) || fs::is_empty(GEN_DIR)) {
        std::cout << "[Setup] Generating dataset in " << GEN_DIR << "...\n";
        DataSetGenerator gen;
        gen.generate_count(GEN_DIR, GEN_COUNT, OutputMode::FOLDER, 0.2);
    }

    std::cout << "[Setup] Loading files into RAM...\n";
    g_file_contents.clear();
    g_total_bytes = 0;
    g_expected_stats.reset();

    for (const auto& entry : fs::directory_iterator(GEN_DIR)) {
        if (entry.is_regular_file()) {
            std::ifstream f(entry.path(), std::ios::binary | std::ios::ate);
            if (!f) continue;
            auto size = f.tellg();
            std::string str(size, '\0');
            f.seekg(0);
            f.read(&str[0], size);

            g_file_contents.push_back(std::move(str));
            g_total_bytes += size;

            update_expected_stats(entry.path());
        }
    }
    std::cout << "[Setup] Loaded " << g_file_contents.size() << " files, "
        << (g_total_bytes / 1024 / 1024) << " MB.\n";
}

// ============================================================================
// BENCHMARK (Шаблон)
// ============================================================================

template <typename ScannerT, bool PreCheck = false>
void BM_Scan(benchmark::State& state) {
    // 1. Инициализация движка (для каждого потока свой экземпляр)
    std::unique_ptr<Scanner> scanner;
    if constexpr (std::is_same_v<ScannerT, StdScanner> || std::is_same_v<ScannerT, BoostScanner>) {
        scanner = std::make_unique<ScannerT>(PreCheck);
    }
    else {
        scanner = std::make_unique<ScannerT>();
    }
    scanner->prepare();

    // 2. Разделение нагрузки (Split Workload)
    // g_file_contents - это вектор ПОЛНЫХ файлов. Мы делим не байты, а индексы файлов.
    // Сигнатуры не рвутся, так как каждый поток обрабатывает свои файлы целиком.
    size_t total_files = g_file_contents.size();
    size_t batch_size = (total_files + state.threads() - 1) / state.threads();
    size_t start_idx = state.thread_index() * batch_size;
    size_t end_idx = std::min(start_idx + batch_size, total_files);

    // Локальная статистика потока (накапливает результаты за ВСЕ итерации)
    ScanStats thread_accumulated_stats;

    // 3. Цикл измерений
    for (auto _ : state) {
        // Проходим по своей части файлов
        for (size_t i = start_idx; i < end_idx; ++i) {
            // Сканируем в thread_accumulated_stats (накапливаем)
            scanner->scan(g_file_contents[i].data(), g_file_contents[i].size(), thread_accumulated_stats);
        }
    }

    // 4. Сохранение результатов
    // Метрика пропускной способности для Google Benchmark
    size_t bytes_processed_by_thread = 0;
    for (size_t i = start_idx; i < end_idx; ++i) {
        bytes_processed_by_thread += g_file_contents[i].size();
    }
    state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * bytes_processed_by_thread);

    // Сохранение детальной статистики для таблицы (под мьютексом)
    {
        std::lock_guard<std::mutex> lock(g_stats_mutex);
        // Имя бенчмарка уникально для комбинации параметров (включая кол-во потоков)
        g_benchmark_results[state.name()] += thread_accumulated_stats;
    }
}

// Регистрация тестов

// Std::Regex
BENCHMARK_TEMPLATE(BM_Scan, StdScanner, false)->Name("Std_Raw")->Unit(benchmark::kMillisecond)->Threads(1)->Threads(16);
BENCHMARK_TEMPLATE(BM_Scan, StdScanner, true)->Name("Std_Opt")->Unit(benchmark::kMillisecond)->Threads(1)->Threads(16);

// Google RE2
BENCHMARK_TEMPLATE(BM_Scan, Re2Scanner)->Name("RE2")->Unit(benchmark::kMillisecond)->Threads(1)->Threads(16);

// Boost.Regex
BENCHMARK_TEMPLATE(BM_Scan, BoostScanner, false)->Name("Boost_Raw")->Unit(benchmark::kMillisecond)->Threads(1)->Threads(16);
BENCHMARK_TEMPLATE(BM_Scan, BoostScanner, true)->Name("Boost_Opt")->Unit(benchmark::kMillisecond)->Threads(1)->Threads(16);

// Hyperscan
BENCHMARK_TEMPLATE(BM_Scan, HsScanner)->Name("Hyperscan")->Unit(benchmark::kMillisecond)->Threads(1)->Threads(16);


// ============================================================================
// ВЫВОД РЕЗУЛЬТАТОВ
// ============================================================================
void PrintResultsTable() {
    std::cout << "\n\n==========================================================\n";
    std::cout << "                VERIFICATION TABLE\n";
    std::cout << "==========================================================\n";

    // Перебираем все выполненные бенчмарки
    for (auto& [name, raw_stats] : g_benchmark_results) {

        // НОРМАЛИЗАЦИЯ
        // Бенчмарк мог выполняться 1000 раз. Нам нужно привести цифры к 1 прогону.
        // Используем total_files как базу.
        // Если expected=50, а found=5000, значит было 100 итераций.

        if (g_expected_stats.total_files == 0) continue;

        // Вычисляем коэффициент масштабирования (сколько раз прогнали тест)
        // Берем по total_files, но для надежности можно брать среднее или просто делить.
        // Тут хитрость: raw_stats содержит сумму (total_files * iterations).
        // scale = raw_stats.total_files / g_expected_stats.total_files.

        long long scale = 1;
        if (raw_stats.total_files > 0) {
            scale = raw_stats.total_files / g_expected_stats.total_files;
        }
        if (scale == 0) scale = 1; // Защита от деления на 0, если ничего не нашли

        // Лямбда для вывода строки
        auto row = [&](const std::string& type, int exp, int act_total) {
            // Нормализуем значение
            int act = act_total / scale;

            std::string status = (act == exp) ? "OK" : (act < exp ? "MISS" : "FP");
            std::cout << "| " << std::left << std::setw(35) << name.substr(0, 34)
                << " | " << std::setw(6) << type
                << " | " << std::setw(6) << exp
                << " | " << std::setw(6) << act
                << " | " << status << "\n";
            };

        std::cout << "\n--- Result: " << name << " (Avg of " << scale << " iter) ---\n";
        std::cout << "| BENCHMARK                           | TYPE   | EXP    | ACT    | STATUS\n";
        std::cout << "|-------------------------------------|--------|--------|--------|-------\n";

        row("PDF", g_expected_stats.pdf, raw_stats.pdf);
        row("ZIP", g_expected_stats.zip, raw_stats.zip);
        row("DOCX", g_expected_stats.docx, raw_stats.docx);
        row("JPG", g_expected_stats.jpg, raw_stats.jpg);
        row("JSON", g_expected_stats.json, raw_stats.json);

        // Подсчет общего итога
        int act_sum = raw_stats.pdf + raw_stats.zip + raw_stats.rar +
            raw_stats.doc + raw_stats.xls + raw_stats.ppt +
            raw_stats.docx + raw_stats.xlsx + raw_stats.pptx +
            raw_stats.png + raw_stats.jpg + raw_stats.gif + raw_stats.bmp +
            raw_stats.mkv + raw_stats.mp3 +
            raw_stats.json + raw_stats.html + raw_stats.xml + raw_stats.eml;

        row("TOTAL", g_expected_stats.total_files, act_sum);
        std::cout << "-------------------------------------------------------------------------\n";
    }
}

int main(int argc, char** argv) {
    // 1. Подготовка
    PrepareDataset();

    // 2. Включение Silent Mode
    Scanner::SilentMode = true;

    // 3. Запуск тестов
    ::benchmark::Initialize(&argc, argv);
    if (::benchmark::ReportUnrecognizedArguments(argc, argv)) return 1;
    ::benchmark::RunSpecifiedBenchmarks();

    // 4. Вывод таблицы результатов
    PrintResultsTable();

    return 0;
}
