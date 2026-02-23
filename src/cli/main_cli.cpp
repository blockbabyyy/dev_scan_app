#include <iostream>
#include <filesystem>
#include <vector>
#include <string>
#include <iomanip>
#include <thread>
#include <future>
#include <atomic>
#include <chrono>
#include <boost/iostreams/device/mapped_file.hpp>
#include "Scanner.h"
#include "ConfigLoader.h"
#include "Logger.h"
#include "ReportWriter.h"

namespace fs = std::filesystem;

static constexpr size_t DEFAULT_MAX_FILESIZE_MB = 512;

void print_ui_help() {
    std::cout << "\n"
        << "==================================================================\n"
        << "              DEV SCANNER TOOL\n"
        << "==================================================================\n\n"
        << "  DevScanApp.exe <path> [options]\n\n"
        << "OPTIONS:\n"
        << "  -c, --config <file>        Signatures file (default: signatures.json)\n"
        << "  -e, --engine <type>        Engine: hs (Hyperscan), re2, boost\n"
        << "  -j, --threads <N>          Thread count (default: CPU cores)\n"
        << "  -m, --max-filesize <MB>    Max file size in MB (default: 512)\n"
        << "  --output-json <path>       Export JSON report to path\n"
        << "  --output-txt <path>        Export TXT report to path\n"
        << "  --no-report                Skip report generation\n"
        << "==================================================================\n";
}

void apply_deduction(ScanStats& stats, const std::vector<SignatureDefinition>& sigs) {
    for (const auto& def : sigs) {
        if (!def.deduct_from.empty()) {
            const std::string& child = def.name;
            const std::string& parent = def.deduct_from;
            if (stats.counts.count(child) && stats.counts.count(parent)) {
                int child_count = stats.counts[child];
                stats.counts[parent] = std::max(0, stats.counts[parent] - child_count);
            }
        }
    }
}

int main(int argc, char* argv[]) {
    Logger::init();
    Logger::info("DevScan started");

    if (argc < 2) {
        print_ui_help();
        return 0;
    }

    std::string target_path = argv[1];
    std::string config_path = "signatures.json";
    EngineType engine_choice = EngineType::HYPERSCAN;
    unsigned int num_threads = std::thread::hardware_concurrency();
    if (num_threads == 0) num_threads = 4;
    size_t max_filesize = DEFAULT_MAX_FILESIZE_MB * 1024 * 1024;
    std::string output_json;
    std::string output_txt;
    bool no_report = false;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "-c" || arg == "--config") && i + 1 < argc) {
            config_path = argv[++i];
        }
        else if ((arg == "-e" || arg == "--engine") && i + 1 < argc) {
            std::string e = argv[++i];
            if (e == "re2") engine_choice = EngineType::RE2;
            else if (e == "boost") engine_choice = EngineType::BOOST;
        }
        else if ((arg == "-j" || arg == "--threads") && i + 1 < argc) {
            num_threads = static_cast<unsigned int>(std::stoi(argv[++i]));
            if (num_threads == 0) num_threads = 1;
        }
        else if ((arg == "-m" || arg == "--max-filesize") && i + 1 < argc) {
            max_filesize = static_cast<size_t>(std::stoi(argv[++i])) * 1024 * 1024;
        }
        else if (arg == "--output-json" && i + 1 < argc) {
            output_json = argv[++i];
        }
        else if (arg == "--output-txt" && i + 1 < argc) {
            output_txt = argv[++i];
        }
        else if (arg == "--no-report") {
            no_report = true;
        }
    }

    Logger::info("Loading config: " + config_path);
    auto sigs = ConfigLoader::load(config_path);
    if (sigs.empty()) {
        Logger::error("Failed to load signatures from " + config_path);
        return 1;
    }
    Logger::info("Signatures loaded: " + std::to_string(sigs.size()));

    // Collect file paths
    std::vector<fs::path> file_paths;
    try {
        if (fs::is_directory(target_path)) {
            auto opts = fs::directory_options::skip_permission_denied;
            for (auto const& entry : fs::recursive_directory_iterator(target_path, opts)) {
                if (entry.is_regular_file() && !entry.is_symlink())
                    file_paths.push_back(entry.path());
            }
        }
        else if (fs::exists(target_path)) {
            file_paths.push_back(target_path);
        }
    }
    catch (const std::exception& e) {
        Logger::error("Directory traversal error: " + std::string(e.what()));
    }

    auto engine_name_str = Scanner::create(engine_choice)->name();
    std::cerr << "[Info] Scanning: " << target_path << " (" << file_paths.size()
              << " files, " << num_threads << " threads, engine: " << engine_name_str << ")\n";
    Logger::info("Scan started: " + target_path + " (" + std::to_string(file_paths.size())
                 + " files, " + std::to_string(num_threads) + " threads)");

    // Progress tracking
    std::atomic<size_t> processed{0};
    size_t total_files = file_paths.size();

    // Split files into chunks for threads
    if (num_threads > total_files && total_files > 0) num_threads = static_cast<unsigned int>(total_files);
    if (num_threads == 0) num_threads = 1;

    auto scan_chunk = [&](size_t start, size_t end) -> ScanStats {
        auto scanner = Scanner::create(engine_choice);
        scanner->prepare(sigs);
        ScanStats local;

        for (size_t i = start; i < end; ++i) {
            try {
                auto fsize = fs::file_size(file_paths[i]);
                if (fsize == 0) {
                    processed++;
                    continue;
                }
                if (fsize > max_filesize) {
                    Logger::warn("Skipped (too large): " + file_paths[i].string()
                                 + " (" + std::to_string(fsize / 1024 / 1024) + " MB)");
                    processed++;
                    continue;
                }
                boost::iostreams::mapped_file_source mmap(file_paths[i].string());
                if (mmap.is_open()) {
                    scanner->scan(mmap.data(), mmap.size(), local);
                    local.total_files_processed++;
                }
            }
            catch (const std::exception& e) {
                Logger::warn("Skipped: " + file_paths[i].string() + ": " + e.what());
            }
            processed++;
        }
        return local;
    };

    // Launch threads
    auto t_start = std::chrono::high_resolution_clock::now();
    std::vector<std::future<ScanStats>> futures;
    size_t chunk_size = (total_files + num_threads - 1) / num_threads;

    for (unsigned int t = 0; t < num_threads; ++t) {
        size_t start = t * chunk_size;
        size_t end = std::min(start + chunk_size, total_files);
        if (start >= total_files) break;
        futures.push_back(std::async(std::launch::async, scan_chunk, start, end));
    }

    // Progress indicator (print to stderr every 500ms)
    if (total_files > 10) {
        while (true) {
            bool all_done = true;
            for (auto& f : futures) {
                if (f.wait_for(std::chrono::milliseconds(500)) != std::future_status::ready) {
                    all_done = false;
                    break;
                }
            }
            size_t p = processed.load();
            std::cerr << "\r[" << p << "/" << total_files << "] "
                      << (total_files > 0 ? (p * 100 / total_files) : 100) << "%   " << std::flush;
            if (all_done) break;
        }
        std::cerr << "\r[" << total_files << "/" << total_files << "] 100%   \n";
    }

    // Merge results
    ScanStats results;
    for (auto& f : futures) results += f.get();

    auto t_end = std::chrono::high_resolution_clock::now();
    double elapsed = std::chrono::duration<double>(t_end - t_start).count();

    apply_deduction(results, sigs);
    Logger::info("Scan complete. Files: " + std::to_string(results.total_files_processed)
                 + ", time: " + std::to_string(elapsed) + "s");

    // Results table
    std::cout << "\n--- SCAN RESULTS ---\n";
    std::cout << std::left << std::setw(15) << "Type" << " | " << "Count\n";
    std::cout << "--------------------------\n";
    for (auto const& [name, count] : results.counts) {
        if (count > 0)
            std::cout << std::left << std::setw(15) << name << " | " << count << "\n";
    }
    std::cout << "--------------------------\n";
    std::cout << "Files processed: " << results.total_files_processed
              << "  (" << std::fixed << std::setprecision(2) << elapsed << "s)\n";

    // Reports
    if (!no_report) {
        std::string json_path = output_json.empty() ? "crash_report/report.json" : output_json;
        std::string txt_path  = output_txt.empty()  ? "crash_report/report.txt"  : output_txt;

        fs::create_directories(fs::path(json_path).parent_path());
        fs::create_directories(fs::path(txt_path).parent_path());

        ReportWriter::write_json(json_path, results, target_path, engine_name_str);
        ReportWriter::write_txt(txt_path, results, target_path, engine_name_str);
        Logger::info("Reports saved: " + json_path + ", " + txt_path);
        std::cout << "[Reports] " << json_path << ", " << txt_path << "\n";
    }

    std::cout << "[Log]     " << Logger::path() << "\n";
    return 0;
}
