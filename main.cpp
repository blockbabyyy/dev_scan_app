#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <cstring>
#include <algorithm> // для transform

#include "Scaner.h"
#include "generator/Generator.h"

namespace fs = std::filesystem;

// Хелпер для чтения файла целиком в память
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

// Запуск бенчмарка для одного движка
void run_benchmark(Scanner* scanner, const fs::path& target, bool is_folder, const GenStats& expected) {
    ScanStats actual;
    size_t total_bytes = 0;

    std::cout << "\n>>> Scanning with " << scanner->name() << "..." << std::endl;

    // Замер времени (только сканирование, без чтения диска если возможно, 
    // но здесь мы включаем чтение, чтобы эмулировать реальную работу)
    auto start = std::chrono::high_resolution_clock::now();

    if (is_folder) {
        for (const auto& entry : fs::directory_iterator(target)) {
            if (entry.is_regular_file()) {
                std::string data = read_file(entry.path());
                if (data.empty()) continue;
                total_bytes += data.size();
                scanner->scan(data.data(), data.size(), actual);
            }
        }
    }
    else {
        // Режим контейнера (ZIP, PCAP, BIN) - сканируем один большой файл
        std::string data = read_file(target);
        total_bytes += data.size();
        if (!data.empty()) {
            scanner->scan(data.data(), data.size(), actual);
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff = end - start;
    double mb = total_bytes / (1024.0 * 1024.0);

    // --- Вывод результатов ---
    std::cout << " Time:  " << std::fixed << std::setprecision(3) << diff.count() << " sec ("
        << (diff.count() > 0 ? mb / diff.count() : 0.0) << " MB/s)\n";
    std::cout << " Size:  " << mb << " MB\n";

    // Таблица сравнения
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
    row("Office(OLE)", expected.doc + expected.xls + expected.ppt,
        actual.doc + actual.xls + actual.ppt);
    row("Office(XML)", expected.docx + expected.xlsx + expected.pptx,
        actual.docx + actual.xlsx + actual.pptx);
    row("Images", expected.png + expected.jpg + expected.gif + expected.bmp,
        actual.png + actual.jpg + actual.gif + actual.bmp);
    row("Media", expected.mkv + expected.mp3,
        actual.mkv + actual.mp3);
    row("Text", expected.json + expected.html + expected.xml + expected.eml,
        actual.json + actual.html + actual.xml + actual.eml);
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
    // Дефолтные настройки
    std::string amount_str = "10";
    double mix = 0.0;
    OutputMode mode = OutputMode::FOLDER;

    // Базовое имя выходного ресурса
    std::string out_base_name = "dataset";
    fs::path out_path;

    // Парсинг аргументов
    if (argc > 1) {
        std::string m = argv[1];
        // Приводим к нижнему регистру для удобства
        std::transform(m.begin(), m.end(), m.begin(), ::tolower);

        if (m == "bin") mode = OutputMode::BIN;
        else if (m == "pcap") mode = OutputMode::PCAP;
        else if (m == "zip") mode = OutputMode::ZIP;
        else if (m == "folder") mode = OutputMode::FOLDER;
        else { print_usage(); return 1; }
    }
    if (argc > 2) amount_str = argv[2];
    if (argc > 3) mix = std::stod(argv[3]);

    // [FIX] Автоматически добавляем расширение, если юзер не указал
    // А то сгенерится dataset.bin, а мы хотели ZIP
    if (mode == OutputMode::FOLDER) {
        out_path = out_base_name + "_dir";
    }
    else if (mode == OutputMode::ZIP) {
        out_path = out_base_name + ".zip";
    }
    else if (mode == OutputMode::PCAP) {
        out_path = out_base_name + ".pcap";
    }
    else {
        out_path = out_base_name + ".bin";
    }

    // Определение лимита (файлы или мегабайты)
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

    // Инфо о запуске
    std::cout << "=== Regex Benchmark Tool ===\n";
    std::cout << "Mode:      " << (mode == OutputMode::FOLDER ? "FOLDER" :
        (mode == OutputMode::ZIP ? "ZIP (Store)" :
            (mode == OutputMode::PCAP ? "PCAP Stream" : "BIN Stream"))) << "\n";
    std::cout << "Target:    " << limit_val << (use_mb ? " MB" : " Files") << "\n";
    std::cout << "Mix Ratio: " << mix << "\n";
    std::cout << "Output:    " << fs::absolute(out_path) << "\n\n";

    // Генерация
    DataSetGenerator gen;
    GenStats expected;

    if (use_mb) {
        expected = gen.generate_size(out_path, limit_val, mode, mix);
    }
    else {
        expected = gen.generate_count(out_path, limit_val, mode, mix);
    }
    
    std::cout << "Generated Info:\n";
    std::cout << "  Archives: " << (expected.pdf + expected.zip + expected.rar) << "\n";
    std::cout << "  Office:   " << (expected.doc + expected.xls + expected.ppt + expected.docx + expected.xlsx + expected.pptx) << "\n";
    std::cout << "  Media:    " << (expected.png + expected.jpg + expected.gif + expected.bmp + expected.mkv + expected.mp3) << "\n";
    std::cout << "  Total:    " << expected.total_files << " files\n";

    // Инициализация движков
    std::vector<std::unique_ptr<Scanner>> scanners;

    // Можно закомментировать ненужные для ускорения отладки
    scanners.push_back(std::make_unique<StdScanner>());
    //scanners.push_back(std::make_unique<BoostScanner>());
    scanners.push_back(std::make_unique<Re2Scanner>());

    auto hs = std::make_unique<HsScanner>();
    hs->prepare();
    //scanners.push_back(std::move(hs));

    // Запуск тестов
    for (const auto& s : scanners) {
        run_benchmark(s.get(), out_path, mode == OutputMode::FOLDER, expected);
    }

    return 0;
}
