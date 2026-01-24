#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <cstring>
#include <algorithm>
#include <numeric>

#include "Scaner.h"
#include "generator/Generator.h"

namespace fs = std::filesystem;

std::string read_file(const fs::path& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return "";
    auto size = f.tellg();
    if (size <= 0) return "";
    std::string str(size, '\0');
    f.seekg(0);
    f.read(&str[0], size);
    return str;
}

// [FIX] Подсчет количества РАЗНЫХ типов (категорий), а не суммы совпадений
int count_distinct_types(const ScanStats& st) {
    int types = 0;
    if (st.pdf > 0) types++;
    if (st.zip > 0) types++;
    if (st.rar > 0) types++;
    if (st.doc > 0) types++;
    if (st.xls > 0) types++;
    if (st.ppt > 0) types++;
    if (st.docx > 0) types++;
    if (st.xlsx > 0) types++;
    if (st.pptx > 0) types++;
    if (st.png > 0) types++;
    if (st.jpg > 0) types++;
    if (st.gif > 0) types++;
    if (st.bmp > 0) types++;
    if (st.mkv > 0) types++;
    if (st.mp3 > 0) types++;
    if (st.json > 0) types++;
    if (st.html > 0) types++;
    if (st.xml > 0) types++;
    if (st.eml > 0) types++;
    return types;
}

// Хелпер для нормализации (если нашли 15 json вхождений в файле, считаем как 1 файл)
ScanStats normalize_stats(const ScanStats& st) {
    ScanStats n = st;
    if (n.pdf > 1) n.pdf = 1;
    if (n.zip > 1) n.zip = 1;
    if (n.rar > 1) n.rar = 1;
    if (n.doc > 1) n.doc = 1;
    if (n.xls > 1) n.xls = 1;
    if (n.ppt > 1) n.ppt = 1;
    if (n.docx > 1) n.docx = 1;
    if (n.xlsx > 1) n.xlsx = 1;
    if (n.pptx > 1) n.pptx = 1;
    if (n.png > 1) n.png = 1;
    if (n.jpg > 1) n.jpg = 1;
    if (n.gif > 1) n.gif = 1;
    if (n.bmp > 1) n.bmp = 1;
    if (n.mkv > 1) n.mkv = 1;
    if (n.mp3 > 1) n.mp3 = 1;
    if (n.json > 1) n.json = 1;
    if (n.html > 1) n.html = 1;
    if (n.xml > 1) n.xml = 1;
    if (n.eml > 1) n.eml = 1;
    return n;
}

// Хелпер для суммы "файлов найдено" (для таблицы)
int sum_files_found(const ScanStats& st) {
    return st.pdf + st.zip + st.rar +
        st.doc + st.xls + st.ppt +
        st.docx + st.xlsx + st.pptx +
        st.png + st.jpg + st.gif + st.bmp +
        st.mkv + st.mp3 +
        st.json + st.html + st.xml + st.eml;
}

void save_debug_sample(const std::string& reason, const std::string& engine_name,
    const std::string& original_filename, const std::string& data) {

    fs::create_directories("debug_samples");

    // [FIX] Санитизация имени: заменяем двоеточия (std::regex -> std_regex)
    std::string safe_engine = engine_name;
    std::replace(safe_engine.begin(), safe_engine.end(), ' ', '_');
    std::replace(safe_engine.begin(), safe_engine.end(), '.', '_');
    std::replace(safe_engine.begin(), safe_engine.end(), ':', '_'); // <--- ВАЖНО

    std::string filename = safe_engine + "_" + reason + "_" + original_filename;
    fs::path out_path = fs::path("debug_samples") / filename;

    std::ofstream f(out_path, std::ios::binary);
    f.write(data.data(), data.size());

    std::cout << "    [SAVED] " << reason << " sample saved to: " << out_path.string() << "\n";
}

bool is_expected_type(const std::string& ext, const ScanStats& st) {
    if (ext == ".pdf") return st.pdf > 0;
    if (ext == ".zip") return st.zip > 0;
    if (ext == ".rar") return st.rar > 0;
    if (ext == ".doc") return st.doc > 0;
    if (ext == ".xls") return st.xls > 0;
    if (ext == ".ppt") return st.ppt > 0;
    if (ext == ".docx") return st.docx > 0;
    if (ext == ".xlsx") return st.xlsx > 0;
    if (ext == ".pptx") return st.pptx > 0;
    if (ext == ".png") return st.png > 0;
    if (ext == ".jpg") return st.jpg > 0;
    if (ext == ".gif") return st.gif > 0;
    if (ext == ".bmp") return st.bmp > 0;
    if (ext == ".mkv") return st.mkv > 0;
    if (ext == ".mp3") return st.mp3 > 0;
    if (ext == ".json") return st.json > 0;
    if (ext == ".html") return st.html > 0;
    if (ext == ".xml")  return st.xml > 0;
    if (ext == ".eml")  return st.eml > 0;
    return false;
}

void run_benchmark(Scanner* scanner, const fs::path& target, bool is_folder, const GenStats& expected) {
    ScanStats actual;
    size_t total_bytes = 0;

    std::cout << "\n>>> Scanning with " << scanner->name() << "..." << std::endl;
    auto start = std::chrono::high_resolution_clock::now();

    if (is_folder) {
        for (const auto& entry : fs::directory_iterator(target)) {
            if (entry.is_regular_file()) {
                std::string data = read_file(entry.path());
                if (data.empty()) continue;

                size_t fsize = data.size();
                total_bytes += fsize;

                ScanStats file_stats;
                scanner->scan(data.data(), fsize, file_stats);

                // [FIX] Нормализуем перед сложением (15 matches -> 1 file)
                ScanStats normalized = normalize_stats(file_stats);
                actual += normalized;

                // --- АНАЛИЗ ОШИБОК ---
                std::string ext = entry.path().extension().string();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                std::string fname = entry.path().filename().string();

                int distinct_types = count_distinct_types(file_stats);

                // 1. MISS
                if (distinct_types == 0) {
                    std::cout << "[DEBUG] MISS: " << fname << " (" << (fsize / 1024) << " KB)\n";
                    save_debug_sample("MISS", scanner->name(), fname, data);
                }
                // 2. FP / MULTI (Нашли больше одного РАЗНОГО типа)
                else if (distinct_types > 1) {
                    std::cout << "[DEBUG] FP/MULTI: " << fname << " found " << distinct_types << " distinct types!\n";
                    save_debug_sample("FP_MULTI", scanner->name(), fname, data);
                }
                // 3. WRONG TYPE
                else if (!is_expected_type(ext, file_stats)) {
                    std::cout << "[DEBUG] WRONG TYPE: " << fname << " (Expected " << ext << ")\n";
                    save_debug_sample("WRONG_TYPE", scanner->name(), fname, data);
                }
            }
        }
    }
    else {
        // Stream mode
        std::string data = read_file(target);
        total_bytes += data.size();
        if (!data.empty()) {
            scanner->scan(data.data(), total_bytes, actual);
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff = end - start;
    double mb = total_bytes / (1024.0 * 1024.0);

    std::cout << " Time:  " << std::fixed << std::setprecision(3) << diff.count() << " sec ("
        << (diff.count() > 0 ? mb / diff.count() : 0.0) << " MB/s)\n";
    std::cout << " Size:  " << mb << " MB\n";

    auto row = [&](const std::string& n, int exp, int act) {
        std::string status = (act == exp) ? "OK" : (act < exp ? "MISS" : "FP");
        std::cout << "| " << std::left << std::setw(12) << n
            << " | " << std::setw(6) << exp
            << " | " << std::setw(6) << act
            << " | " << status << "\n";
        };

    std::cout << "------------------------------------------\n";
    std::cout << "| TYPE         | GEN    | FOUND  | STATUS\n";
    std::cout << "|--------------|--------|--------|-------\n";
    row("PDF", expected.pdf, actual.pdf);
    row("ZIP", expected.zip, actual.zip);
    row("RAR", expected.rar, actual.rar);
    std::cout << "|--------------|--------|--------|-------\n";
    row("DOC", expected.doc, actual.doc);
    row("XLS", expected.xls, actual.xls);
    row("PPT", expected.ppt, actual.ppt);
    std::cout << "|--------------|--------|--------|-------\n";
    row("DOCX", expected.docx, actual.docx);
    row("XLSX", expected.xlsx, actual.xlsx);
    row("PPTX", expected.pptx, actual.pptx);
    std::cout << "|--------------|--------|--------|-------\n";
    row("PNG", expected.png, actual.png);
    row("JPG", expected.jpg, actual.jpg);
    row("GIF", expected.gif, actual.gif);
    row("BMP", expected.bmp, actual.bmp);
    std::cout << "|--------------|--------|--------|-------\n";
    row("MKV", expected.mkv, actual.mkv);
    row("MP3", expected.mp3, actual.mp3);
    std::cout << "|--------------|--------|--------|-------\n";
    row("JSON", expected.json, actual.json);
    row("HTML", expected.html, actual.html);
    row("XML", expected.xml, actual.xml);
    row("EML", expected.eml, actual.eml);
    std::cout << "|--------------|--------|--------|-------\n";

    // [FIX] Суммируем найденные файлы, а не все совпадения
    row("TOTAL MATCH", expected.total_files, sum_files_found(actual));
    std::cout << "------------------------------------------\n";
}

void print_usage() {
    std::cout << "Usage: ScanerApp [mode] [amount] [mix]\n";
    std::cout << "  mode: folder, bin, pcap, zip\n";
    std::cout << "  amount: number of files (e.g. 1000) OR size in MB (e.g. 100mb)\n";
    std::cout << "  mix: 0.0 - 1.0 (probability of gluing files)\n";
    std::cout << "Example: ScanerApp zip 500mb 0.2\n";
}

int main(int argc, char* argv[]) {
    std::string amount_str = "50";
    double mix = 0.0;
    OutputMode mode = OutputMode::FOLDER;

    std::string out_base_name = "dataset";
    fs::path out_path;

    if (argc > 1) {
        std::string m = argv[1];
        std::transform(m.begin(), m.end(), m.begin(), ::tolower);

        if (m == "bin") mode = OutputMode::BIN;
        else if (m == "pcap") mode = OutputMode::PCAP;
        else if (m == "zip") mode = OutputMode::ZIP;
        else if (m == "folder") mode = OutputMode::FOLDER;
        else { print_usage(); return 1; }
    }
    if (argc > 2) amount_str = argv[2];
    if (argc > 3) mix = std::stod(argv[3]);

    if (mode == OutputMode::FOLDER) out_path = out_base_name + "_dir";
    else if (mode == OutputMode::ZIP) out_path = out_base_name + ".zip";
    else if (mode == OutputMode::PCAP) out_path = out_base_name + ".pcap";
    else out_path = out_base_name + ".bin";

    bool use_mb = false;
    int limit_val = 0;
    size_t mb_pos = amount_str.find("mb");
    if (mb_pos == std::string::npos) mb_pos = amount_str.find("MB");

    if (mb_pos != std::string::npos) {
        use_mb = true;
        limit_val = std::stoi(amount_str.substr(0, mb_pos));
    }
    else {
        limit_val = std::stoi(amount_str);
    }

    std::cout << "=== Regex Benchmark Tool ===\n";
    std::cout << "Mode:      " << (mode == OutputMode::FOLDER ? "FOLDER" : "STREAM") << "\n";
    std::cout << "Output:    " << fs::absolute(out_path) << "\n\n";

    // 1. Generate
    DataSetGenerator gen;
    GenStats expected;
    if (use_mb) expected = gen.generate_size(out_path, limit_val, mode, mix);
    else expected = gen.generate_count(out_path, limit_val, mode, mix);

    // Вывод статистики
    std::cout << "Generated Breakdown:\n";
    auto print_stat = [](const char* name, int count) {
        if (count > 0) std::cout << "  " << std::left << std::setw(6) << name << ": " << count << "\n";
        };
    print_stat("PDF", expected.pdf); print_stat("ZIP", expected.zip);
    print_stat("DOC", expected.doc); print_stat("XLS", expected.xls);
    print_stat("DOCX", expected.docx); print_stat("XLSX", expected.xlsx); print_stat("PPTX", expected.pptx);
    print_stat("JSON", expected.json); print_stat("XML", expected.xml);
    print_stat("PNG", expected.png); print_stat("JPG", expected.jpg);
    print_stat("MKV", expected.mkv); print_stat("MP3", expected.mp3);
    std::cout << "  TOTAL:  " << expected.total_files << " files\n";

    // 2. Engines
    std::vector<std::unique_ptr<Scanner>> scanners;
    scanners.push_back(std::make_unique<StdScanner>(false));
    scanners.push_back(std::make_unique<BoostScanner>(false));

    scanners.push_back(std::make_unique<Re2Scanner>());
    auto hs = std::make_unique<HsScanner>();
    hs->prepare();
    scanners.push_back(std::move(hs));

    // 3. Run
    for (const auto& s : scanners) {
        run_benchmark(s.get(), out_path, mode == OutputMode::FOLDER, expected);
    }

    return 0;
}
