#include <iostream>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <set>
#include <vector>
#include <string>
#include <iomanip>
#include <thread>
#include <future>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <boost/iostreams/device/mapped_file.hpp>
#include <nlohmann/json.hpp>
#include "Scanner.h"
#include "ConfigLoader.h"
#include "Logger.h"
#include "ReportWriter.h"

namespace fs = std::filesystem;

static constexpr size_t DEFAULT_MAX_FILESIZE_MB = 512;

// ---------------------------------------------------------------------------
// --add-sig wizard
// ---------------------------------------------------------------------------

static void print_hexdump(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; i += 16) {
        std::printf("  %04X  ", static_cast<unsigned>(i));
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < len) std::printf("%02X ", data[i + j]);
            else              std::printf("   ");
            if (j == 7)       std::printf(" ");
        }
        std::printf(" ");
        for (size_t j = 0; j < 16 && i + j < len; ++j)
            std::putchar(std::isprint(static_cast<unsigned char>(data[i + j])) ? data[i + j] : '.');
        std::putchar('\n');
    }
}

static int run_add_sig_wizard(const std::string& config_path) {
    // 1. Load existing JSON (or start fresh)
    nlohmann::json arr = nlohmann::json::array();
    {
        std::ifstream f(config_path);
        if (f.is_open()) {
            try {
                f >> arr;
            } catch (const std::exception& ex) {
                std::cerr << "Error: failed to parse " << config_path << ": " << ex.what() << "\n";
                return 1;
            }
            if (!arr.is_array()) {
                std::cerr << "Error: " << config_path << " root must be an array []\n";
                return 1;
            }
        }
        // If file doesn't exist yet, arr stays as empty array — we'll create it.
    }

    // 2. Collect existing names for duplicate check
    std::set<std::string> existing_names;
    for (const auto& e : arr)
        if (e.contains("name"))
            existing_names.insert(e["name"].get<std::string>());

    std::cout << "\n=== Add Signature Wizard ===\n\n";

    // 3. Name
    std::string sig_name;
    while (true) {
        std::cout << "Signature name (e.g. MYFORMAT): ";
        std::getline(std::cin, sig_name);
        if (sig_name.empty()) { std::cout << "  Name cannot be empty.\n"; continue; }
        if (existing_names.count(sig_name)) {
            std::cout << "  Name '" << sig_name << "' already exists. Choose another.\n";
            continue;
        }
        break;
    }

    // 4. Type
    std::string type_input;
    std::cout << "Type [binary/text] (default: binary): ";
    std::getline(std::cin, type_input);
    bool is_binary = (type_input != "text");

    std::string hex_head, hex_tail, text_pattern;

    if (is_binary) {
        // 5. Sample file for auto hex detection
        std::string sample_path;
        std::cout << "Sample file path (Enter to skip): ";
        std::getline(std::cin, sample_path);

        if (!sample_path.empty()) {
            std::ifstream sf(sample_path, std::ios::binary);
            if (!sf.is_open()) {
                std::cout << "  Warning: cannot open '" << sample_path << "'\n";
            } else {
                unsigned char buf[16] = {};
                sf.read(reinterpret_cast<char*>(buf), 16);
                size_t read_count = static_cast<size_t>(sf.gcount());

                std::cout << "First " << read_count << " bytes:\n";
                print_hexdump(buf, read_count);

                // How many bytes to use as header
                std::string nbytes_str;
                std::cout << "Bytes to use as header (1-" << read_count << "): ";
                std::getline(std::cin, nbytes_str);
                int nbytes = 0;
                try { nbytes = std::stoi(nbytes_str); } catch (...) {}
                if (nbytes < 1) nbytes = 1;
                if (nbytes > static_cast<int>(read_count)) nbytes = static_cast<int>(read_count);

                std::ostringstream hs;
                hs << std::uppercase << std::hex << std::setfill('0');
                for (int i = 0; i < nbytes; ++i)
                    hs << std::setw(2) << static_cast<int>(buf[i]);
                hex_head = hs.str();
                std::cout << "  hex_head: " << hex_head << "\n";

                // Optional tail
                std::string tail_choice;
                std::cout << "Read tail bytes from file? [y/N]: ";
                std::getline(std::cin, tail_choice);
                if (tail_choice == "y" || tail_choice == "Y") {
                    std::string ntail_str;
                    std::cout << "How many bytes from the end (1-16): ";
                    std::getline(std::cin, ntail_str);
                    int ntail = 0;
                    try { ntail = std::stoi(ntail_str); } catch (...) {}
                    if (ntail < 1) ntail = 1;
                    if (ntail > 16) ntail = 16;

                    sf.clear();
                    sf.seekg(0, std::ios::end);
                    std::streamoff fsize = sf.tellg();
                    if (fsize >= ntail) {
                        sf.seekg(-ntail, std::ios::end);
                        unsigned char tbuf[16] = {};
                        sf.read(reinterpret_cast<char*>(tbuf), ntail);
                        size_t tread = static_cast<size_t>(sf.gcount());
                        std::cout << "Last " << tread << " bytes:\n";
                        print_hexdump(tbuf, tread);
                        std::ostringstream ts;
                        ts << std::uppercase << std::hex << std::setfill('0');
                        for (size_t i = 0; i < tread; ++i)
                            ts << std::setw(2) << static_cast<int>(tbuf[i]);
                        hex_tail = ts.str();
                        std::cout << "  hex_tail: " << hex_tail << "\n";
                    }
                }
            }
        } else {
            // Manual hex entry
            std::cout << "Enter hex_head manually (e.g. 25504446, Enter to skip): ";
            std::getline(std::cin, hex_head);
        }

        // Optional text_pattern
        std::cout << "Text pattern / regex substring for refinement (Enter to skip): ";
        std::getline(std::cin, text_pattern);
    } else {
        // 6. Text type — regex pattern
        std::cout << "Regex pattern: ";
        std::getline(std::cin, text_pattern);
    }

    // 7. Extensions
    std::string ext_str;
    std::cout << "Extensions comma-separated (e.g. .myf,.myfmt, Enter for none): ";
    std::getline(std::cin, ext_str);
    std::vector<std::string> extensions;
    if (!ext_str.empty()) {
        std::istringstream iss(ext_str);
        std::string token;
        while (std::getline(iss, token, ',')) {
            // trim whitespace
            auto b = token.find_first_not_of(" \t");
            auto e = token.find_last_not_of(" \t");
            if (b != std::string::npos)
                extensions.push_back(token.substr(b, e - b + 1));
        }
    }

    // 8. deduct_from
    std::string deduct_from;
    std::cout << "Deduct from (existing name, Enter to skip): ";
    std::getline(std::cin, deduct_from);

    // 9. Build JSON object
    nlohmann::json new_sig;
    new_sig["name"] = sig_name;
    new_sig["type"] = is_binary ? "binary" : "text";
    new_sig["extensions"] = extensions;
    if (!hex_head.empty())    new_sig["hex_head"] = hex_head;
    if (!hex_tail.empty())    new_sig["hex_tail"] = hex_tail;
    if (!text_pattern.empty()) {
        if (is_binary) new_sig["text_pattern"] = text_pattern;
        else           new_sig["pattern"]       = text_pattern;
    }
    if (!deduct_from.empty()) new_sig["deduct_from"] = deduct_from;

    // Preview
    std::cout << "\nPreview:\n" << new_sig.dump(4) << "\n\n";

    // Confirm
    std::string confirm;
    std::cout << "Append to " << config_path << "? [y/N]: ";
    std::getline(std::cin, confirm);
    if (confirm != "y" && confirm != "Y") {
        std::cout << "Cancelled.\n";
        return 0;
    }

    arr.push_back(new_sig);

    std::ofstream out(config_path);
    if (!out.is_open()) {
        std::cerr << "Error: cannot write to " << config_path << "\n";
        return 1;
    }
    out << arr.dump(4) << "\n";
    std::cout << "Saved to " << config_path << "\n";
    return 0;
}

// ---------------------------------------------------------------------------

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
        << "  --add-sig                  Interactive wizard to add a new signature\n"
        << "==================================================================\n";
}


int main(int argc, char* argv[]) {
    Logger::init();
    Logger::info("DevScan started");

    if (argc < 2) {
        print_ui_help();
        return 0;
    }

    // Handle -h/--help/--version/--add-sig before treating argv[1] as a path
    {
        std::string first = argv[1];
        if (first == "-h" || first == "--help") {
            print_ui_help();
            return 0;
        }
        if (first == "--version") {
            std::cout << "DevScan 1.0.0\n";
            return 0;
        }
        if (first == "--add-sig") {
            std::string cfg = "signatures.json";
            for (int i = 2; i + 1 < argc; ++i)
                if (std::string(argv[i]) == "-c" || std::string(argv[i]) == "--config")
                    cfg = argv[i + 1];
            return run_add_sig_wizard(cfg);
        }
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
            max_filesize = std::stoull(argv[++i]) * 1024 * 1024;
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
