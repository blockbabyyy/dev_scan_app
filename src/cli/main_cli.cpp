#include <iostream>
#include <filesystem>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <boost/iostreams/device/mapped_file.hpp>
#include "Scaner.h"

namespace fs = std::filesystem;
using json = nlohmann::json;

// Функция вывода HELP интерфейса
void print_ui_help() {
    std::cout << "\n"
        << "==================================================================\n"
        << "              DEV SCANNER TOOL - ПОЛЬЗОВАТЕЛЬСКОЕ РУКОВОДСТВО     \n"
        << "==================================================================\n\n"
        << "ПРОГРАММА ПРЕДНАЗНАЧЕНА ДЛЯ ГЛУБОКОГО ПОИСКА СИГНАТУР В ФАЙЛАХ.\n\n"
        << "КАК ИСПОЛЬЗОВАТЬ:\n"
        << "  DevScanApp.exe <путь_к_папке_или_файлу> [опции]\n\n"
        << "ОПЦИИ:\n"
        << "  -c, --config <file>   Путь к файлу сигнатур (по умолчанию: signatures.json)\n"
        << "  -e, --engine <type>   Движок: hs (Hyperscan), re2, boost\n\n"
        << "ИНСТРУКЦИЯ ПО ДОБАВЛЕНИЮ СИГНАТУР В JSON:\n"
        << "  Вы можете расширить базу поиска, редактируя 'signatures.json'.\n"
        << "  Пример нового блока для бинарного файла:\n"
        << "  {\n"
        << "    \"name\": \"MY_EXE\",\n"
        << "    \"type\": \"binary\",\n"
        << "    \"hex_head\": \"4D5A\",        // Magic bytes (HEX)\n"
        << "    \"deduct_from\": \"CONTAINER\" // Опционально: вычесть из родителя\n"
        << "  }\n\n"
        << "  Пример для текстового паттерна:\n"
        << "  { \"name\": \"LOG_ERR\", \"type\": \"text\", \"pattern\": \"Error: \\\\d+\" }\n"
        << "==================================================================\n";
}

// Загрузка конфигурации
std::vector<SignatureDefinition> load_signatures(const std::string& path) {
    std::vector<SignatureDefinition> sigs;
    std::ifstream f(path);
    if (!f.is_open()) {
        std::cerr << "[Error] Не удалось найти файл конфигурации: " << path << "\n";
        return sigs;
    }

    try {
        json j;
        f >> j;
        for (auto& item : j) {
            SignatureDefinition def;
            def.name = item.at("name").get<std::string>();
            std::string type = item.value("type", "binary");
            def.type = (type == "text") ? SignatureType::TEXT : SignatureType::BINARY;

            if (def.type == SignatureType::BINARY) {
                def.hex_head = item.value("hex_head", "");
                def.hex_tail = item.value("hex_tail", "");
                def.text_pattern = item.value("text_pattern", "");
            }
            else {
                def.text_pattern = item.at("pattern").get<std::string>();
            }
            def.deduct_from = item.value("deduct_from", "");
            sigs.push_back(def);
        }
    }
    catch (const std::exception& e) {
        std::cerr << "[Error] Ошибка парсинга JSON: " << e.what() << "\n";
    }
    return sigs;
}

// Логика вычитания DOCX из ZIP и т.д.
void apply_deduction(ScanStats& stats, const std::vector<SignatureDefinition>& sigs) {
    for (const auto& def : sigs) {
        if (!def.deduct_from.empty()) {
            std::string child = def.name;
            std::string parent = def.deduct_from;
            if (stats.counts.count(child) && stats.counts.count(parent)) {
                int child_count = stats.counts[child];
                stats.counts[parent] = std::max(0, stats.counts[parent] - child_count);
            }
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_ui_help();
        return 0;
    }

    std::string target_path = argv[1];
    std::string config_path = "signatures.json";
    EngineType engine_choice = EngineType::HYPERSCAN;

    // Простейший парсинг аргументов
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "-c" || arg == "--config") && i + 1 < argc) config_path = argv[++i];
        if ((arg == "-e" || arg == "--engine") && i + 1 < argc) {
            std::string e = argv[++i];
            if (e == "re2") engine_choice = EngineType::RE2;
            else if (e == "boost") engine_choice = EngineType::BOOST;
        }
    }

    auto sigs = load_signatures(config_path);
    if (sigs.empty()) return 1;

    auto scanner = Scanner::create(engine_choice);
    scanner->prepare(sigs);

    ScanStats results;
    std::cout << "[Info] Сканирование: " << target_path << " движком " << scanner->name() << "...\n";

    try {
        if (fs::is_directory(target_path)) {
            for (auto const& entry : fs::recursive_directory_iterator(target_path)) {
                if (entry.is_regular_file()) {
                    boost::iostreams::mapped_file_source mmap(entry.path().string());
                    if (mmap.is_open()) {
                        scanner->scan(mmap.data(), mmap.size(), results);
                        results.total_files_processed++;
                    }
                }
            }
        }
        else if (fs::exists(target_path)) {
            boost::iostreams::mapped_file_source mmap(target_path);
            if (mmap.is_open()) {
                scanner->scan(mmap.data(), mmap.size(), results);
                results.total_files_processed = 1;
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << "[Fatal] Ошибка доступа к файлам: " << e.what() << "\n";
    }

    apply_deduction(results, sigs);

    // Вывод итоговой таблицы
    std::cout << "\n--- РЕЗУЛЬТАТЫ СКАНЕРА ---\n";
    std::cout << std::left << std::setw(15) << "Тип файла" << " | " << "Найдено\n";
    std::cout << "--------------------------\n";
    for (auto const& [name, count] : results.counts) {
        if (count > 0) {
            std::cout << std::left << std::setw(15) << name << " | " << count << "\n";
        }
    }
    std::cout << "--------------------------\n";
    std::cout << "Всего файлов обработано: " << results.total_files_processed << "\n";

    return 0;
}
