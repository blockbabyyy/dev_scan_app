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
#include <algorithm>
#include <ctime>
#include <functional>
#include <zip.h>  // libzip for ZIP extraction
#ifdef _WIN32
#include <io.h>   // _dup, _fileno
#endif
#include <boost/iostreams/device/mapped_file.hpp>
#include <nlohmann/json.hpp>
#include "Scanner.h"
#include "ConfigLoader.h"
#include "Logger.h"
#include "ReportWriter.h"

namespace fs = std::filesystem;

static constexpr size_t DEFAULT_MAX_FILESIZE_MB = 512;

// ---------------------------------------------------------------------------
// ZIP extraction helper
// ---------------------------------------------------------------------------

// FIX to-do #3: open ZIP directly without loading the whole file into RAM.
// On Windows, zip_open() uses the current system codepage for the path, which
// breaks for UTF-8 filenames. We work around this by opening the file with
// _wfopen_s (wide char, always correct), duplicating the fd, and handing the
// dup to zip_fdopen so libzip owns it.
static zip_t* open_zip_path(const fs::path& path, int* errcode) {
#ifdef _WIN32
    FILE* fp = nullptr;
    if (_wfopen_s(&fp, path.wstring().c_str(), L"rb") != 0 || !fp) {
        *errcode = ZIP_ER_OPEN;
        return nullptr;
    }
    int fd = _dup(_fileno(fp));
    fclose(fp);
    if (fd < 0) { *errcode = ZIP_ER_OPEN; return nullptr; }
    return zip_fdopen(fd, ZIP_RDONLY, errcode);
#else
    return zip_open(path.c_str(), ZIP_RDONLY, errcode);
#endif
}

static std::string detect_office_format(const fs::path& path) {
    int errcode = 0;
    zip_t* archive = open_zip_path(path, &errcode);
    if (!archive) {
        if (errcode != 0) {
            zip_error_t ze; zip_error_init_with_code(&ze, errcode);
            Logger::warn("Failed to open ZIP: " + path.filename().string()
                         + " - " + zip_error_strerror(&ze));
            zip_error_fini(&ze);
        }
        return "";
    }

    zip_int64_t num_entries = zip_get_num_entries(archive, 0);
    std::set<std::string> entries;
    for (zip_int64_t i = 0; i < num_entries; ++i) {
        const char* name = zip_get_name(archive, i, ZIP_FL_ENC_RAW);
        if (name) entries.insert(name);
    }
    zip_close(archive);

    if (entries.count("word/document.xml"))   return "DOCX";
    if (entries.count("xl/workbook.xml"))     return "XLSX";
    if (entries.count("ppt/presentation.xml")) return "PPTX";
    return "";
}

static std::vector<fs::path> extract_zip_entries(const fs::path& zip_path,
                                                  const fs::path& temp_dir,
                                                  int max_entries, size_t max_size) {
    std::vector<fs::path> extracted;

    int errcode = 0;
    zip_t* archive = open_zip_path(zip_path, &errcode);
    if (!archive) return extracted;

    zip_int64_t num_entries = zip_get_num_entries(archive, 0);
    if (num_entries > max_entries) {
        zip_close(archive);
        return extracted;
    }

    size_t total_size = 0;
    for (zip_int64_t i = 0; i < num_entries; ++i) {
        const char* name = zip_get_name(archive, i, ZIP_FL_ENC_RAW);
        if (!name) continue;
        std::string name_str(name);
        if (name_str.empty() || name_str.back() == '/') continue;

        zip_stat_t stat;
        if (zip_stat_index(archive, i, 0, &stat) != 0) continue;
        if (total_size + stat.size > max_size) break;

        zip_file_t* zf = zip_fopen_index(archive, i, 0);
        if (!zf) continue;

        std::vector<char> entry_buf(stat.size);
        zip_int64_t bytes_read = zip_fread(zf, entry_buf.data(), stat.size);
        zip_fclose(zf);
        if (bytes_read != static_cast<zip_int64_t>(stat.size)) continue;

        fs::path out_path = temp_dir / name_str;
        fs::create_directories(out_path.parent_path());

        std::ofstream out(out_path.wstring(), std::ios::binary);
        if (out.is_open()) {
            out.write(entry_buf.data(), static_cast<std::streamsize>(entry_buf.size()));
            out.close();
            extracted.push_back(out_path);
            total_size += stat.size;
        }
    }

    zip_close(archive);
    return extracted;
}

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
        << "  --no-extract               Don't extract archives (default: auto-extract ZIP/7Z/RAR)\n"
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
    bool extract_containers = true;  // По умолчанию извлекаем архивы

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
        else if (arg == "--no-extract") {  // Отключение извлечения
            extract_containers = false;
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
    std::vector<fs::path> temp_dirs;  // Track temp directories for cleanup
    auto opts = fs::directory_options::skip_permission_denied;
    
    try {
        if (fs::is_directory(target_path)) {
            for (auto const& entry : fs::recursive_directory_iterator(target_path, opts)) {
                if (entry.is_regular_file() && !entry.is_symlink())
                    file_paths.push_back(entry.path());
            }
        }
        else if (fs::exists(target_path)) {
            file_paths.push_back(target_path);
            
            // Если файл — архив (ZIP/7Z/RAR), извлекаем его содержимое
            // По умолчанию извлечение включено, можно отключить через --no-extract
            if (extract_containers) {
                std::string ext = fs::path(target_path).extension().string();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

                // CROSS-PLATFORM FIX: Используем libzip вместо PowerShell для кроссплатформенности
                // PowerShell работает только на Windows, libzip работает на Windows/Linux/macOS
                if (ext == ".zip") {
                    // Создаём временную папку для распаковки
                    std::string temp_dir = fs::temp_directory_path().string() + "/devscan_extract_" + std::to_string(std::time(nullptr));
                    fs::create_directories(temp_dir);
                    temp_dirs.push_back(temp_dir);

                    // Используем libzip для извлечения
                    auto extracted = extract_zip_entries(target_path, temp_dir, MAX_CONTAINER_ENTRIES, MAX_UNCOMPRESSED_SIZE);
                    
                    if (!extracted.empty()) {
                        Logger::info("Extracted ZIP to: " + temp_dir + " (" + std::to_string(extracted.size()) + " files)");
                        for (const auto& f : extracted) {
                            file_paths.push_back(f);
                        }
                    }
                }
                // NOTE: 7Z и RAR требуют внешних утилит (7-Zip), которые могут быть недоступны на Linux
                // Для полной кроссплатформенности рекомендуется использовать только ZIP
            }
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

    // Simple scan function (no recursion - recursion handled inline)
    auto scan_chunk = [&](size_t start, size_t end) -> ScanStats {
        // FIX to-do #1: per-file PCAP detection — two scanner instances per thread.
        // scanner_anchored is used for all regular files (anchored=true).
        // scanner_unanchored is used for binary streams (.pcap) where signatures
        // can appear anywhere, not just at the file start (anchored=false).
        auto scanner_anchored = Scanner::create(engine_choice);
        scanner_anchored->prepare(sigs, true);
        std::unique_ptr<Scanner> scanner_unanchored;  // lazy init — only if .pcap found
        ScanStats local;
        // FIX to-do #5: store extraction_root explicitly so relative paths
        // are computed via fs::relative, not by searching "devscan_" in string.
        struct QEntry { fs::path path; int depth; fs::path root; };
        std::vector<QEntry> scan_queue;

        for (size_t i = start; i < end; ++i) {
            scan_queue.clear();
            scan_queue.push_back({file_paths[i], 0, {}});

            while (!scan_queue.empty()) {
                auto [curr_path, depth, extraction_root] = scan_queue.back();
                scan_queue.pop_back();

                if (depth > MAX_CONTAINER_DEPTH) continue;

                try {
                    auto fsize = fs::file_size(curr_path);
                    if (fsize == 0 || fsize > max_filesize) continue;
                }
                catch (const fs::filesystem_error& e) {
                    Logger::warn("Cannot access file: " + curr_path.string() + " - " + e.what());
                    continue;
                }

                try {

                    // FIX to-do #5: compute relative path from extraction_root directly
                    // instead of searching for "devscan_" substring in the absolute path.
                    std::string relative_path;
                    if (depth > 0 && !extraction_root.empty()) {
                        std::error_code ec;
                        fs::path rel = fs::relative(curr_path, extraction_root, ec);
                        if (!ec) {
                            relative_path = rel.generic_string();  // forward slashes
                        } else {
                            relative_path = curr_path.filename().string();
                        }
                    }

                    std::string file_ext = curr_path.extension().string();
                    std::transform(file_ext.begin(), file_ext.end(), file_ext.begin(), ::tolower);

                    if (depth > 0 && !relative_path.empty()) {
                        // Skip Office Open XML system files (internal structure, not content)
                        if (is_office_system_file(relative_path)) continue;

                        // Skip EMF/BIN/RELS by extension (docProps thumbnails, printer settings)
                        if (file_ext == ".emf" || file_ext == ".bin" || file_ext == ".rels") continue;

                        // Skip XML files from known Office subdirectories
                        if (file_ext == ".xml" &&
                            (relative_path.find("word/")      == 0 ||
                             relative_path.find("xl/")        == 0 ||
                             relative_path.find("ppt/")       == 0 ||
                             relative_path.find("docProps/")  == 0 ||
                             relative_path.find("customXml/") == 0 ||
                             relative_path.find("[Content_Types]") == 0)) {
                            continue;
                        }
                    } else if (depth > 0) {
                        // Fallback when extraction_root unavailable: skip by extension only
                        if (file_ext == ".emf" || file_ext == ".bin" || file_ext == ".rels") continue;
                    }

                    boost::iostreams::mapped_file_source mmap(curr_path.string());
                    if (!mmap.is_open()) continue;

                    // FIX to-do #1: per-file binary-stream detection.
                    // .pcap files are binary streams — scan unanchored, count every occurrence.
                    std::string curr_ext = curr_path.extension().string();
                    std::transform(curr_ext.begin(), curr_ext.end(), curr_ext.begin(), ::tolower);
                    bool is_binary_stream = (curr_ext == ".pcap");
                    if (is_binary_stream && !scanner_unanchored) {
                        // Hyperscan reports every end-of-match position for patterns
                        // with a tail (e.g. GIF8.*?; → every ';' after any 'GIF8').
                        // RE2 uses FindAndConsume which gives correct non-overlapping
                        // counts identical to Python re.findall.
                        EngineType pcap_engine = (engine_choice == EngineType::HYPERSCAN)
                                                 ? EngineType::RE2 : engine_choice;
                        scanner_unanchored = Scanner::create(pcap_engine);
                        scanner_unanchored->prepare(sigs, false);
                    }
                    Scanner* active_scanner = is_binary_stream
                        ? scanner_unanchored.get()
                        : scanner_anchored.get();

                    ScanStats file_stats;
                    file_stats.reset_file_state();
                    active_scanner->scan(mmap.data(), mmap.size(), file_stats, is_binary_stream);
                    file_stats.total_files_processed++;
                    local.total_files_processed++;

                    bool is_embedded = (depth > 0);

                    // Move counts to appropriate location
                    if (is_embedded) {
                        for (const auto& [name, count] : file_stats.counts) {
                            local.embedded_counts[name] += count;
                        }
                    } else {
                        for (const auto& [name, count] : file_stats.counts) {
                            local.counts[name] += count;
                        }
                    }

                    mmap.close();

                    // Check if this is a ZIP-based container
                    std::string ext = curr_path.extension().string();
                    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

                    bool is_container = (ext == ".zip" || ext == ".docx" || ext == ".xlsx" ||
                                         ext == ".pptx" || ext == ".epub");

                    if (is_container && extract_containers && depth < MAX_CONTAINER_DEPTH) {
                        std::string office_type = detect_office_format(curr_path);
                        if (!office_type.empty() || ext == ".zip") {
                            fs::path temp_dir = fs::temp_directory_path() /
                                               ("devscan_" + std::to_string(depth) + "_" +
                                                std::to_string(std::time(nullptr)));
                            fs::create_directories(temp_dir);
                            temp_dirs.push_back(temp_dir);

                            auto extracted = extract_zip_entries(curr_path, temp_dir,
                                                                  MAX_CONTAINER_ENTRIES,
                                                                  MAX_UNCOMPRESSED_SIZE);

                            if (!extracted.empty()) {
                                Logger::info("Extracted " + (office_type.empty() ? "ZIP" : office_type) +
                                            " " + curr_path.filename().string() + ": " +
                                            std::to_string(extracted.size()) + " entries");

                                for (const auto& entry : extracted) {
                                    scan_queue.push_back({entry, depth + 1, temp_dir});
                                }
                            }
                        }
                    }
                }
                catch (const fs::filesystem_error& e) {
                    Logger::warn("Filesystem error: " + curr_path.string() + " - " + e.what());
                }
                catch (const std::exception& e) {
                    Logger::warn("Skipped: " + curr_path.string() + ": " + e.what());
                }
            }
            // FIX to-do #7: increment once per file_paths[i], not per scan_queue entry
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
    // apply_container_hierarchy removed: deduct_from in signatures.json already handles
    // DOCX/XLSX/PPTX -> ZIP deduction; calling both caused double-subtraction (to-do #2)
    apply_exclusive_filter(results, sigs);  // Handle mutually exclusive signatures (RAR4/RAR5)
    Logger::info("Scan complete. Files: " + std::to_string(results.total_files_processed)
                 + ", time: " + std::to_string(elapsed) + "s");

    // Results table with new format: "found X type (Y embedded)"
    std::cout << "\n--- SCAN RESULTS ---\n";
    
    // Combine standalone and embedded counts for display
    std::map<std::string, std::pair<int, int>> all_detections;  // type -> (standalone, embedded)
    
    for (const auto& [name, count] : results.counts) {
        if (count > 0) {
            all_detections[name].first = count;
        }
    }
    for (const auto& [name, count] : results.embedded_counts) {
        if (count > 0) {
            all_detections[name].second = count;
        }
    }
    
    // Print results in new format
    for (const auto& [name, counts] : all_detections) {
        int standalone = counts.first;
        int embedded = counts.second;
        int total = standalone + embedded;
        
        if (embedded > 0) {
            std::cout << "found " << total << " " << name << " (" << embedded << " embedded)\n";
        } else {
            std::cout << "found " << total << " " << name << "\n";
        }
    }
    
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
    
    // Cleanup temp directories
    for (const auto& td : temp_dirs) {
        try {
            fs::remove_all(td);
        } catch (...) {}
    }
    
    return 0;
}
