#pragma once
#include <string>
#include <fstream>
#include <iomanip>
#include <nlohmann/json.hpp>
#include "Scanner.h"

class ReportWriter {
public:
    static void write_json(const std::string& path,
                           const ScanStats& results,
                           const std::string& target,
                           const std::string& engine_name)
    {
        nlohmann::json j;
        j["scan_target"] = target;
        j["engine"] = engine_name;
        j["total_files_processed"] = results.total_files_processed;

        nlohmann::json det = nlohmann::json::object();
        for (const auto& [name, count] : results.counts) {
            if (count > 0) det[name] = count;
        }
        j["detections"] = det;

        std::ofstream f(path, std::ios::out | std::ios::trunc);
        if (f.is_open()) f << j.dump(2) << "\n";
    }

    static void write_txt(const std::string& path,
                          const ScanStats& results,
                          const std::string& target,
                          const std::string& engine_name)
    {
        std::ofstream f(path, std::ios::out | std::ios::trunc);
        if (!f.is_open()) return;

        f << "--- РЕЗУЛЬТАТЫ СКАНЕРА ---\n";
        // Use a wider format for alignment on Cyrillic labels
        f << "Цель:   " << target << "\n";
        f << "Движок: " << engine_name << "\n";
        f << "--------------------------\n";
        f << std::left << std::setw(15) << "Тип файла" << " | " << "Найдено\n";
        f << "--------------------------\n";
        for (const auto& [name, count] : results.counts) {
            if (count > 0)
                f << std::left << std::setw(15) << name << " | " << count << "\n";
        }
        f << "--------------------------\n";
        f << "Всего файлов обработано: " << results.total_files_processed << "\n";
    }
};
