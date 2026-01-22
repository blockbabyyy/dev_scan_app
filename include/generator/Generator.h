#pragma once
#include <string>
#include <vector>
#include <map>
#include <filesystem>
#include <fstream>
#include <random> 
#include "Scaner.h"

// Используем ScanStats как GenStats для единообразия
using GenStats = ScanStats;

enum class OutputMode {
    FOLDER, // Папка с файлами
    BIN,    // Бинарная склейка (Blob)
    PCAP,   // Дамп трафика (файлы как payload пакетов)
    ZIP     // ZIP-архив без сжатия (Store)
};

class DataSetGenerator {
public:
    struct FileType {
        std::string extension;
        std::string head;
        std::string middle;
        std::string tail;
        bool is_text;
    };

    DataSetGenerator();

    // Генерация заданного количества файлов
    GenStats generate_count(const std::filesystem::path& output_path, int count, OutputMode mode, double mix_ratio = 0.0);

    // Генерация заданного объема данных (в МБ)
    GenStats generate_size(const std::filesystem::path& output_path, int size_mb, OutputMode mode, double mix_ratio = 0.0);

private:
    std::map<std::string, FileType> types;
    std::vector<std::string> extensions;
    std::vector<std::string> dictionary; // Словарь для реалистичного текста

    // Создание контента одного файла (или склейки)
    std::pair<std::string, std::string> create_payload(std::mt19937& rng, bool is_mixed);

    // Заполнение мусором (с ловушками или словами)
    void fill_complex(std::stringstream& ss, size_t count, bool is_text, std::mt19937& rng);

    // Выбор реалистичного размера в зависимости от типа
    size_t get_realistic_size(const std::string& ext, std::mt19937& rng);

    // Универсальный метод записи (limit_type: 0 = count, 1 = bytes)
    void write_generic(const std::filesystem::path& path, size_t limit, int limit_type, OutputMode mode, double mix_ratio, GenStats& stats);

    uint32_t calculate_crc32(const std::string& data);
    void update_stats(const std::string& ext, GenStats& stats);
};