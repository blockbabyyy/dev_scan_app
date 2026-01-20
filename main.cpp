#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <sstream>
#include <filesystem>

#include <re2/re2.h>
#include <boost/regex.hpp>
#include <boost/algorithm/string/replace.hpp> // ??? ????????????? ???????????? ? boost
#include <regex>
#include <hs/hs.h> // Hyperscan
#include "Signatures.h"
#include "Scaner.h"
//#include "generator/Generator.h"
#include "benchmark/benchmark.h"

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib") // На случай, если CMake не подхватит
#endif


namespace fs = std::filesystem;


// Глобальный датасет (в RAM), чтобы исключить диск из замеров
struct InMemoryFile {
    std::vector<char> content;
};
static std::vector<InMemoryFile> g_dataset;
static size_t g_totalBytes = 0;

// ==========================================
// 3. [NEW] ПРОСТАЯ ТАБЛИЦА СРАВНЕНИЯ
// ==========================================

void PrintTableRow(const std::string& cat, int gen, int scan) {
    int diff = scan - gen;
    std::cout << "| " << std::left << std::setw(22) << cat
        << " | " << std::right << std::setw(10) << gen
        << " | " << std::setw(10) << scan
        << " | " << std::setw(10) << diff << " |" << std::endl;
}

void PrintSeparator() {
    std::cout << "+------------------------+------------+------------+------------+" << std::endl;
}

template <class ScannerType>
void VerifyAccuracy(const GenStats& gen) {
    ScannerType scanner;
    scanner.prepare();
    ScanStats scan;

    std::cout << "\n>>> Accuracy Check: " << scanner.name() << " <<<\n";

    // Прогон в 1 поток для точности
    for (const auto& file : g_dataset) {
        scanner.scan(file.content.data(), file.content.size(), scan);
    }

    PrintSeparator();
    std::cout << "| Category               | Generated  | Detected   | Diff       |" << std::endl;
    PrintSeparator();

    // 1. Документы
    int scan_ole = scan.doc + scan.xls + scan.ppt + scan.ole;
    int scan_xml = scan.docx + scan.xlsx + scan.pptx;

    PrintTableRow("PDF", gen.pdf, scan.pdf);
    PrintTableRow("Old Office (OLE)", gen.office_ole, scan_ole);
    PrintTableRow("New Office (XML)", gen.office_xml, scan_xml);

    // 2. Архивы
    PrintTableRow("Pure ZIP", gen.zip, scan.zip);
    PrintTableRow("RAR", gen.rar, scan.rar);

    // 3. Медиа
    PrintTableRow("PNG", gen.png, scan.png);
    PrintTableRow("JPG", gen.jpg, scan.jpg);
    PrintTableRow("GIF", gen.gif, scan.gif);
    PrintTableRow("BMP", gen.bmp, scan.bmp);
    PrintTableRow("MKV", gen.mkv, scan.mkv);
    PrintTableRow("MP3", gen.mp3, scan.mp3);

    // 4. Текст
    PrintTableRow("HTML", gen.html, scan.html);
    PrintTableRow("XML", gen.xml, scan.xml);
    PrintTableRow("JSON", gen.json, scan.json);
    PrintTableRow("EML", gen.eml, scan.eml);

    PrintSeparator();
    // Итого
    // (txt считаем за "ожидаемые неизвестные")
    PrintTableRow("Unknown / TXT", gen.txt, scan.unknown);
    PrintSeparator();
    std::cout << std::endl;
}

// ==========================================
// 4. GOOGLE BENCHMARK FUNCTION
// ==========================================

/*
template <class ScannerType>
void BM_ScanEngine(benchmark::State& state) {
    // 1. Setup (выполняется для каждого потока)
    ScannerType scanner;
    scanner.prepare(); // Alloc scratch for Hyperscan

    if (g_dataset.empty()) {
        state.SkipWithError("Dataset is empty!");
        return;
    }

    // Расчет нагрузки для потока (Data Parallelism)
    size_t total_files = g_dataset.size();
    size_t num_threads = state.threads();
    size_t thread_idx = state.thread_index();

    // Делим файлы поровну между потоками
    size_t chunk_size = total_files / num_threads;
    size_t start = thread_idx * chunk_size;
    size_t end = (thread_idx == num_threads - 1) ? total_files : (start + chunk_size);

    // Считаем объем данных, который обработает ЭТОТ поток за одну итерацию
    size_t batch_bytes = 0;
    for (size_t i = start; i < end; ++i) {
        batch_bytes += g_dataset[i].content.size();
    }

    // 2. Loop (Замер времени)
    for (auto _ : state) {
        ScanStats stats; // Легкая структура на стеке

        // Сканируем свой кусок
        for (size_t i = start; i < end; ++i) {
            scanner.scan(g_dataset[i].content.data(), g_dataset[i].content.size(), stats);
        }

        // Защита от оптимизации
        benchmark::DoNotOptimize(stats);
    }

    // 3. Metrics (MB/s)
    // GBenchmark автоматически замерит время. Мы добавляем пропускную способность.
    state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * batch_bytes);
}
*/

template <class ScannerType>
void BM_ScanEngine(benchmark::State& state) {
    if (g_dataset.empty()) {
        state.SkipWithError("Dataset is empty!");
        return;
    }

    // 1. ЗАМЕР ПАМЯТИ ДО СОЗДАНИЯ СКАНЕРА
    // Снимаем показания до того, как движок выделил память под свои базы
    size_t mem_before = GetMemoryUsage();

    // 2. ИНИЦИАЛИЗАЦИЯ (Scanner Setup)
    // Здесь Hyperscan компилирует базу, RE2 строит автоматы и т.д.
    ScannerType scanner;
    scanner.prepare();

    // 3. ЗАМЕР ПАМЯТИ ПОСЛЕ
    size_t mem_after = GetMemoryUsage();

    // Считаем разницу. Это и есть "вес" самого сканера в RAM.
    double ram_overhead_mb = 0.0;
    if (mem_after > mem_before) {
        ram_overhead_mb = (double)(mem_after - mem_before) / (1024.0 * 1024.0);
    }

    // --- (Далее стандартная логика Data Parallelism) ---
    size_t total_files = g_dataset.size();
    size_t num_threads = state.threads();
    size_t thread_idx = state.thread_index();
    size_t chunk = total_files / num_threads;
    size_t start = thread_idx * chunk;
    size_t end = (thread_idx == num_threads - 1) ? total_files : start + chunk;

    size_t bytes = 0;
    for (size_t i = start; i < end; ++i) bytes += g_dataset[i].content.size();

    // 4. ЦИКЛ ЗАМЕРА СКОРОСТИ
    for (auto _ : state) {
        ScanStats stats;
        for (size_t i = start; i < end; ++i) {
            scanner.scan(g_dataset[i].content.data(), g_dataset[i].content.size(), stats);
        }
        benchmark::DoNotOptimize(stats);
    }

    // 5. ЗАПИСЬ РЕЗУЛЬТАТОВ
    state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * bytes);

    // Добавляем пользовательский счетчик RAM
    // benchmark::Counter::kAvgThreads - усреднит значение по потокам (так как каждый поток выделил память под свой сканер)
    state.counters["RAM (MB)"] = benchmark::Counter(ram_overhead_mb, benchmark::Counter::kAvgThreads);
}

size_t GetMemoryUsage() {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS_EX pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
        // PrivateUsage (Commit Charge) - это "честная" память, выделенная процессом,
        // включая ту, что может быть сброшена в swap. Самый точный показатель утечек и аллокаций.
        return pmc.PrivateUsage;
    }
#endif
    return 0;
}

std::string pretty_format(DataSetGenerator::ContainerType type) {
    if (type == DataSetGenerator::ContainerType::FOLDER) return "Folder";
    else if (type == DataSetGenerator::ContainerType::ZIP) return "ZIP Archive";
    else if (type == DataSetGenerator::ContainerType::PCAP) return "PCAP";
    else return "Unknown";
}
// вынести Сканер в отдельный файл.
int main(int argc, char** argv) {

    StdScanner std_scanner;
    Re2Scanner re2_scanner;
	BoostScanner boost_scanner;
	HsScanner hs_scanner;

    std::string directory = R"(C:\projects\dev_scan_app\input)";
    ScanStats stats_std, stats_re2, stats_boost, stats_hs;

	GenStats gen_stats;
    
    DataSetGenerator::ContainerType type = DataSetGenerator::ContainerType::PCAP;
	size_t gen_size_mb = 40;
    /*
    try {
        // Проверки пути
        if (!fs::exists(directory) || !fs::is_directory(directory)) {
            std::cerr << "Папка не найдена: " << directory << std::endl;
            return 1;
        }
       
        bool is_gen_required = fs::is_empty(directory);
        
        if (is_gen_required) {
            std::cout << "Input directory is empty. Generating dataset..." << std::endl;
            DataSetGenerator generator;
            // Генерируем 200 МБ файлов в папку
            gen_stats = generator.generate(directory, 400, DataSetGenerator::ContainerType::FOLDER);
            gen_stats.print();
        }

		hs_scanner.prepare(); // подготовка Hyperscan

        for (const auto& entry : fs::directory_iterator(directory)) {
            if (fs::is_regular_file(entry)) {


                std::ifstream file(entry.path(), std::ios::binary | std::ios::ate);
                if (!file) continue;


                size_t size = file.tellg();
                if (size == 0) continue; 

                std::vector<char> buffer(size);
                file.seekg(0);
                file.read(buffer.data(), size);


                std_scanner.scan(buffer.data(), buffer.size(), stats_std);
                re2_scanner.scan(buffer.data(), buffer.size(), stats_re2);
				boost_scanner.scan(buffer.data(), buffer.size(), stats_boost);
				hs_scanner.scan(buffer.data(), buffer.size(), stats_hs);

            }
        }

        std::cout << "===== Results =====" << std::endl;
		stats_std.print(std_scanner.name());
		stats_re2.print(re2_scanner.name());
		stats_boost.print(boost_scanner.name());
		stats_hs.print(hs_scanner.name());
        

    }
    catch (const std::exception& ex) {
        std::cerr << "Ошибка: " << ex.what() << std::endl;
        return 1;
    }
    */

    try {
        // 1. ГЕНЕРАЦИЯ
        GenStats gen_stats;
        if (!fs::exists(directory)) fs::create_directories(directory);

        if (fs::is_empty(directory)) {
            std::cout << "[Main] Generating dataset "<< gen_size_mb <<" " <<pretty_format(type) << " type" << "...\n";
            DataSetGenerator generator;
            gen_stats = generator.generate(directory, gen_size_mb, type);
        }
        else {
            std::cout << "[Main] Files exist. Skipping generation.\n";
            // Внимание: Если файлы старые, таблица точности будет пустой или неверной,
            // так как gen_stats пуст. Для теста лучше удалить папку input.
        }

        // 2. ЗАГРУЗКА
        std::cout << "[Main] Loading to RAM...\n";
        g_totalBytes = 0;
        for (const auto& entry : fs::directory_iterator(directory)) {
            if (fs::is_regular_file(entry)) {
                std::ifstream file(entry.path(), std::ios::binary | std::ios::ate);
                if (!file) continue;
                size_t s = file.tellg();
                if (s == 0) continue;
                InMemoryFile mem;
                mem.content.resize(s);
                file.seekg(0);
                file.read(mem.content.data(), s);
                g_dataset.push_back(std::move(mem));
                g_totalBytes += s;
            }
        }
        std::cout << "Loaded " << g_dataset.size() << " files (" << g_totalBytes / 1024 / 1024 << " MB).\n";

        // 3. ПРОВЕРКА ТОЧНОСТИ (Только если есть с чем сравнивать)
        if (gen_stats.total_files > 0) {
            VerifyAccuracy<StdScanner>(gen_stats);
            VerifyAccuracy<BoostScanner>(gen_stats);
            VerifyAccuracy<Re2Scanner>(gen_stats);
            VerifyAccuracy<HsScanner>(gen_stats);
        }

        // 4. ЗАПУСК ТЕСТОВ
        std::cout << "\n[Main] Starting Benchmark...\n";

        // Single Thread
        benchmark::RegisterBenchmark("Std::Regex (ST)", BM_ScanEngine<StdScanner>)
            ->Unit(benchmark::kMillisecond)->MinTime(1.0);
        benchmark::RegisterBenchmark("Boost.Regex (ST)", BM_ScanEngine<BoostScanner>)
            ->Unit(benchmark::kMillisecond)->MinTime(1.0);
        benchmark::RegisterBenchmark("Google RE2 (ST)", BM_ScanEngine<Re2Scanner>)
            ->Unit(benchmark::kMillisecond)->MinTime(1.0);
        benchmark::RegisterBenchmark("Hyperscan (ST)", BM_ScanEngine<HsScanner>)
            ->Unit(benchmark::kMillisecond)->MinTime(1.0);

        // Multi Thread (Ryzen 7 7700 = 16 threads)
        int threads = 16;
        benchmark::RegisterBenchmark("Std::Regex (MT)", BM_ScanEngine<StdScanner>)
            ->Threads(threads)->Unit(benchmark::kMillisecond)->MinTime(2.0);
        benchmark::RegisterBenchmark("Boost.Regex (MT)", BM_ScanEngine<BoostScanner>)
            ->Threads(threads)->Unit(benchmark::kMillisecond)->MinTime(2.0);
        benchmark::RegisterBenchmark("Google RE2 (MT)", BM_ScanEngine<Re2Scanner>)
            ->Threads(threads)->Unit(benchmark::kMillisecond)->MinTime(2.0);
        benchmark::RegisterBenchmark("Hyperscan (MT)", BM_ScanEngine<HsScanner>)
            ->Threads(threads)->Unit(benchmark::kMillisecond)->MinTime(2.0);

        benchmark::Initialize(&argc, argv);
        benchmark::RunSpecifiedBenchmarks();

        g_dataset.clear();

    }
    catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }
    

    return 0;
}