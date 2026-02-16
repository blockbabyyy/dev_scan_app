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

// Конфиг сигнатур для бенчмарка — hex-строки, как в signatures.json
const std::vector<SignatureDefinition> BENCH_SIGS = {
    { "PDF", "25504446", "2525454F46", "", SignatureType::BINARY },
    { "ZIP", "504B0304", "504B0506", "", SignatureType::BINARY },
    { "RAR4", "526172211A0700", "", "", SignatureType::BINARY },
    { "RAR5", "526172211A070100", "", "", SignatureType::BINARY },
    { "PNG", "89504E470D0A1A0A", "49454E44AE426082", "", SignatureType::BINARY },
    { "JPG", "FFD8FF", "FFD9", "", SignatureType::BINARY },
    { "GIF", "47494638", "003B", "", SignatureType::BINARY },
    { "BMP", "424D", "", "", SignatureType::BINARY },
    { "MKV", "1A45DFA3", "", "", SignatureType::BINARY },
    { "MP3", "494433", "", "", SignatureType::BINARY },

    // Office (OLE)
    { "DOC", "D0CF11E0A1B11AE1", "", "WordDocument", SignatureType::BINARY, "OLE" },
    { "XLS", "D0CF11E0A1B11AE1", "", "Workbook", SignatureType::BINARY, "OLE" },
    { "PPT", "D0CF11E0A1B11AE1", "", "PowerPoint Document", SignatureType::BINARY, "OLE" },

    // Office (OOXML)
    { "DOCX", "504B0304", "", "word/document.xml", SignatureType::BINARY, "ZIP" },
    { "XLSX", "504B0304", "", "xl/workbook.xml", SignatureType::BINARY, "ZIP" },
    { "PPTX", "504B0304", "", "ppt/presentation.xml", SignatureType::BINARY, "ZIP" },

    { "JSON", "", "", "\\{\\s*\"[^\"]+\"\\s*:", SignatureType::TEXT },
    { "HTML", "", "", "<html.*?</html>", SignatureType::TEXT },
    { "XML",  "", "", "<\\?xml", SignatureType::TEXT },
    { "EMAIL",  "", "", "From:\\s", SignatureType::TEXT }
};

struct FileEntry {
    std::string name;
    std::string content;
    std::string extension;
};

static std::vector<FileEntry> g_files;
static size_t g_total_bytes = 0;
static GenStats g_expected_stats;

void update_expected_stats(const std::string& ext) {
    if (ext == ".pdf") g_expected_stats.add("PDF");
    else if (ext == ".zip") g_expected_stats.add("ZIP");
    else if (ext == ".rar") g_expected_stats.add("RAR4");
    else if (ext == ".doc") g_expected_stats.add("DOC");
    else if (ext == ".xls") g_expected_stats.add("XLS");
    else if (ext == ".ppt") g_expected_stats.add("PPT");
    else if (ext == ".docx") g_expected_stats.add("DOCX");
    else if (ext == ".xlsx") g_expected_stats.add("XLSX");
    else if (ext == ".pptx") g_expected_stats.add("PPTX");
    else if (ext == ".png") g_expected_stats.add("PNG");
    else if (ext == ".jpg") g_expected_stats.add("JPG");
    else if (ext == ".gif") g_expected_stats.add("GIF");
    else if (ext == ".bmp") g_expected_stats.add("BMP");
    else if (ext == ".mkv") g_expected_stats.add("MKV");
    else if (ext == ".mp3") g_expected_stats.add("MP3");
    else if (ext == ".json") g_expected_stats.add("JSON");
    else if (ext == ".html") g_expected_stats.add("HTML");
    else if (ext == ".xml") g_expected_stats.add("XML");
    else if (ext == ".eml") g_expected_stats.add("EMAIL");
    g_expected_stats.total_files_processed++;
}

int GetStat(const ScanStats& st, const std::string& key) {
    if (st.counts.count(key)) return st.counts.at(key);
    return 0;
}

int CountDistinctTypes(const ScanStats& st) {
    return (int)st.counts.size();
}

void LoadDataset(const fs::path& folder, double mix_ratio) {
    const int GEN_COUNT = 50;
    if (fs::exists(folder)) fs::remove_all(folder);

    std::cout << "[Setup] Generating dataset in " << folder << " (Mix: " << mix_ratio << ")...\n";
    DataSetGenerator gen;
    gen.generate_count(folder, GEN_COUNT, OutputMode::FOLDER, mix_ratio);

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

bool IsCorrectDetection(const std::string& ext, const ScanStats& st, bool strict_mode) {
    std::string key;
    if (ext == ".pdf") key = "PDF";
    else if (ext == ".zip") key = "ZIP";
    else if (ext == ".rar") key = "RAR4";
    else if (ext == ".doc") key = "DOC";
    else if (ext == ".xls") key = "XLS";
    else if (ext == ".ppt") key = "PPT";
    else if (ext == ".docx") key = "DOCX";
    else if (ext == ".xlsx") key = "XLSX";
    else if (ext == ".pptx") key = "PPTX";
    else if (ext == ".png") key = "PNG";
    else if (ext == ".jpg") key = "JPG";
    else if (ext == ".gif") key = "GIF";
    else if (ext == ".bmp") key = "BMP";
    else if (ext == ".mkv") key = "MKV";
    else if (ext == ".mp3") key = "MP3";
    else if (ext == ".json") key = "JSON";
    else if (ext == ".html") key = "HTML";
    else if (ext == ".xml") key = "XML";
    else if (ext == ".eml") key = "EMAIL";

    if (key.empty()) return false;

    // Проверка, что целевой тип найден
    if (GetStat(st, key) == 0) return false;

    // Строгий режим: не должно быть других типов
    if (strict_mode) {
        // Исключение: DOCX внутри ZIP и т.д. (здесь мы проверяем сырой выхлоп движка)
        // Для бенчмарка упростим: если mix=0.0 (clean), то должно быть ровно 1 совпадение.
        if (st.counts.size() > 1) {
            // Разрешаем коллизии для Office форматов, так как они детектятся как ZIP + DOCX
            if (key == "DOCX" || key == "XLSX" || key == "PPTX") return true;
            return false;
        }
    }
    return true;
}

void UpdateMatchedStats(GenStats& matched, const std::string& ext) {
    // Просто дублируем логику update_expected_stats
    if (ext == ".pdf") matched.add("PDF");
    else if (ext == ".zip") matched.add("ZIP");
    else if (ext == ".rar") matched.add("RAR4");
    else if (ext == ".doc") matched.add("DOC");
    else if (ext == ".xls") matched.add("XLS");
    else if (ext == ".ppt") matched.add("PPT");
    else if (ext == ".docx") matched.add("DOCX");
    else if (ext == ".xlsx") matched.add("XLSX");
    else if (ext == ".pptx") matched.add("PPTX");
    else if (ext == ".png") matched.add("PNG");
    else if (ext == ".jpg") matched.add("JPG");
    else if (ext == ".gif") matched.add("GIF");
    else if (ext == ".bmp") matched.add("BMP");
    else if (ext == ".mkv") matched.add("MKV");
    else if (ext == ".mp3") matched.add("MP3");
    else if (ext == ".json") matched.add("JSON");
    else if (ext == ".html") matched.add("HTML");
    else if (ext == ".xml") matched.add("XML");
    else if (ext == ".eml") matched.add("EMAIL");
}

void PrintVerificationTable(const std::string& engine_name, const GenStats& matched, bool strict) {
    auto row = [&](const std::string& n, int exp, int act) {
        std::string status = (act == exp) ? "OK" : (act < exp ? "MISS" : "FP?");
        std::cout << "| " << std::left << std::setw(12) << n
            << " | " << std::setw(6) << exp
            << " | " << std::setw(6) << act
            << " | " << status << "\n";
        };

    std::cout << "\n--- Accuracy: " << engine_name << " ---\n";
    std::cout << "| TYPE         | GEN    | MATCH  | STATUS\n";
    std::cout << "|--------------|--------|--------|-------\n";

    // Выводим только основные типы
    std::vector<std::string> keys = { "PDF", "ZIP", "DOCX", "JPG", "JSON", "XML" };
    for (const auto& k : keys) {
        row(k, GetStat(g_expected_stats, k), GetStat(matched, k));
    }
    std::cout << "------------------------------------------\n";
}

void VerifyAll(bool strict) {
    std::cout << "\n[Verify] Running verification...\n";

    auto check_engine = [&](std::unique_ptr<Scanner> s) {
        s->prepare(BENCH_SIGS); // ! Важно: передаем сигнатуры
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

    check_engine(std::make_unique<Re2Scanner>());
    check_engine(std::make_unique<BoostScanner>());
    check_engine(std::make_unique<HsScanner>());
}

template <typename ScannerT>
void BM_Scan(benchmark::State& state) {
    auto scanner = std::make_unique<ScannerT>();
    scanner->prepare(BENCH_SIGS);

    size_t total_files = g_files.size();
    size_t batch_size = (total_files + state.threads() - 1) / state.threads();
    size_t start_idx = state.thread_index() * batch_size;
    size_t end_idx = std::min(start_idx + batch_size, total_files);

    ScanStats stats;

    for (auto _ : state) {
        for (size_t i = start_idx; i < end_idx; ++i) {
            scanner->scan(g_files[i].content.data(), g_files[i].content.size(), stats);
        }
    }

    size_t bytes_processed = 0;
    for (size_t i = start_idx; i < end_idx; ++i) bytes_processed += g_files[i].content.size();
    state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * bytes_processed);
}

BENCHMARK_TEMPLATE(BM_Scan, Re2Scanner)->Name("RE2")->Unit(benchmark::kMillisecond)->Threads(1)->Threads(8);
BENCHMARK_TEMPLATE(BM_Scan, BoostScanner)->Name("Boost")->Unit(benchmark::kMillisecond)->Threads(1)->Threads(8);
BENCHMARK_TEMPLATE(BM_Scan, HsScanner)->Name("Hyperscan")->Unit(benchmark::kMillisecond)->Threads(1)->Threads(8);

int main(int argc, char** argv) {
    // SilentMode removed — field no longer exists in Scanner

    std::cout << ">>> Preparing Benchmark Data (Mix=0.2)...\n";
    LoadDataset("bench_data_stress", 0.2);

    VerifyAll(false); // Проверяем точность перед запуском

    std::cout << "\n[Benchmark] Running performance tests...\n";
    ::benchmark::Initialize(&argc, argv);
    if (::benchmark::ReportUnrecognizedArguments(argc, argv)) return 1;
    ::benchmark::RunSpecifiedBenchmarks();

    return 0;
}
