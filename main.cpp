#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <cstring>

#include "Scaner.h"
#include "generator/Generator.h"

namespace fs = std::filesystem;

// Чтение всего файла в память
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

void run_benchmark(Scanner* scanner, const fs::path& target, bool is_folder, const GenStats& expected) {
    ScanStats actual;
    size_t total_bytes = 0;

    std::cout << "\n>>> Scanning with " << scanner->name() << "..." << std::endl;
    auto start = std::chrono::high_resolution_clock::now();

    if (is_folder) {
        for (const auto& entry : fs::directory_iterator(target)) {
            if (entry.is_regular_file()) {
                std::string data = read_file(entry.path());
                total_bytes += data.size();
                scanner->scan(data.data(), data.size(), actual);
            }
        }
    }
    else {
        // Один большой файл (BIN, PCAP, ZIP)
        std::string data = read_file(target);
        total_bytes += data.size();
        if (!data.empty()) {
            scanner->scan(data.data(), data.size(), actual);
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff = end - start;
    double mb = total_bytes / (1024.0 * 1024.0);

    // Вывод
    std::cout << " Time:  " << diff.count() << " sec (" << (mb / diff.count()) << " MB/s)\n";
    std::cout << " Size:  " << mb << " MB\n";

    auto row = [&](const std::string& n, int exp, int act) {
        std::cout << " " << std::left << std::setw(12) << n << " | Exp:" << std::setw(5) << exp
            << " | Act:" << std::setw(5) << act
            << " | " << (act == exp ? "OK" : (act > exp ? "FP" : "MISS")) << "\n";
        };

    std::cout << "------------------------------------------\n";
    row("PDF", expected.pdf, actual.pdf);
    row("ZIP", expected.zip, actual.zip);
    row("RAR", expected.rar, actual.rar);
    row("Office(OLE)", expected.doc + expected.xls + expected.ppt,
        actual.doc + actual.xls + actual.ppt);
    row("Office(XML)", expected.docx + expected.xlsx + expected.pptx,
        actual.docx + actual.xlsx + actual.pptx);
    row("Media", expected.mkv + expected.mp3 + expected.png + expected.jpg + expected.gif + expected.bmp,
        actual.mkv + actual.mp3 + actual.png + actual.jpg + actual.gif + actual.bmp);
    row("Text", expected.json + expected.html + expected.xml + expected.eml,
        actual.json + actual.html + actual.xml + actual.eml);
    std::cout << "------------------------------------------\n";
}

void print_usage() {
    std::cout << "Usage: ScanerApp [mode] [count] [mix_ratio]\n";
    std::cout << "  mode: folder, bin, pcap, zip\n";
    std::cout << "  count: number of files (default 1000)\n";
    std::cout << "  mix: 0.0 - 1.0 (default 0.0)\n";
}

int main(int argc, char* argv[]) {
    int count = 1000;
    double mix = 0.0;
    OutputMode mode = OutputMode::FOLDER;
    fs::path out_path = "dataset"; // папка по умолчанию

    if (argc > 1) {
        std::string m = argv[1];
        if (m == "bin") { mode = OutputMode::BIN; out_path = "dataset.bin"; }
        else if (m == "pcap") { mode = OutputMode::PCAP; out_path = "dataset.pcap"; }
        else if (m == "zip") { mode = OutputMode::ZIP; out_path = "dataset.zip"; }
        else if (m == "folder") { mode = OutputMode::FOLDER; out_path = "dataset_dir"; }
        else { print_usage(); return 1; }
    }
    if (argc > 2) count = std::stoi(argv[2]);
    if (argc > 3) mix = std::stod(argv[3]);

    // 1. Generate
    DataSetGenerator gen;
    GenStats expected = gen.generate(out_path, count, mode, mix);

    // 2. Prepare Engines
    std::vector<std::unique_ptr<Scanner>> scanners;
    scanners.push_back(std::make_unique<StdScanner>());
    scanners.push_back(std::make_unique<BoostScanner>());
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