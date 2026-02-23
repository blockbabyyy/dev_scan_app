#include <benchmark/benchmark.h>
#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>
#include <memory>
#include <iomanip>
#include <map>
#include <algorithm>

#include "Scanner.h"
#include "ConfigLoader.h"
#include "TypeMap.h"
#include "generator/Generator.h"

namespace fs = std::filesystem;

// Сигнатуры загружаются из JSON — единый источник истины
static std::vector<SignatureDefinition> g_sigs;

struct FileEntry {
    std::string name;
    std::string content;
    std::string extension;
};

static std::vector<FileEntry> g_files;
static size_t g_total_bytes = 0;
static GenStats g_expected_stats;

int GetStat(const ScanStats& st, const std::string& key) {
    auto it = st.counts.find(key);
    return (it != st.counts.end()) ? it->second : 0;
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

            std::string type = ext_to_type(fe.extension);
            if (!type.empty()) g_expected_stats.add(type);
            g_expected_stats.total_files_processed++;

            g_files.push_back(std::move(fe));
        }
    }
    std::cout << "[Setup] Loaded " << g_files.size() << " files, "
        << (g_total_bytes / 1024 / 1024) << " MB.\n";
}

bool IsCorrectDetection(const std::string& ext, const ScanStats& st, bool strict_mode) {
    std::string key = ext_to_type(ext);
    if (key.empty()) return false;
    if (GetStat(st, key) == 0) return false;

    if (strict_mode && st.counts.size() > 1) {
        // Разрешаем коллизии для Office форматов (детектятся как ZIP + DOCX)
        if (key == "DOCX" || key == "XLSX" || key == "PPTX") return true;
        return false;
    }
    return true;
}

void PrintVerificationTable(const std::string& engine_name, const GenStats& matched) {
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

    for (const auto& [key, count] : g_expected_stats.counts) {
        row(key, count, GetStat(matched, key));
    }
    std::cout << "------------------------------------------\n";
}

void VerifyAll(bool strict) {
    std::cout << "\n[Verify] Running verification...\n";

    auto check_engine = [&](std::unique_ptr<Scanner> s) {
        s->prepare(g_sigs);
        GenStats matched_stats;

        for (const auto& file : g_files) {
            ScanStats st;
            s->scan(file.content.data(), file.content.size(), st);

            if (IsCorrectDetection(file.extension, st, strict)) {
                std::string type = ext_to_type(file.extension);
                if (!type.empty()) matched_stats.add(type);
            }
        }
        PrintVerificationTable(s->name(), matched_stats);
        };

    check_engine(std::make_unique<Re2Scanner>());
    check_engine(std::make_unique<BoostScanner>());
    check_engine(std::make_unique<HsScanner>());
}

template <typename ScannerT>
void BM_Scan(benchmark::State& state) {
    auto scanner = std::make_unique<ScannerT>();
    scanner->prepare(g_sigs);

    size_t total_files = g_files.size();
    size_t batch_size = (total_files + state.threads() - 1) / state.threads();
    size_t start_idx = state.thread_index() * batch_size;
    size_t end_idx = std::min(start_idx + batch_size, total_files);

    for (auto _ : state) {
        ScanStats stats;
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
    g_sigs = ConfigLoader::load("signatures.json");
    if (g_sigs.empty()) {
        std::cerr << "[Fatal] Failed to load signatures.json\n";
        return 1;
    }

    std::cout << ">>> Preparing Benchmark Data (Mix=0.2)...\n";
    LoadDataset("bench_data_stress", 0.2);

    VerifyAll(false);

    std::cout << "\n[Benchmark] Running performance tests...\n";
    ::benchmark::Initialize(&argc, argv);
    if (::benchmark::ReportUnrecognizedArguments(argc, argv)) return 1;
    ::benchmark::RunSpecifiedBenchmarks();

    return 0;
}
