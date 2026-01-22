#pragma once
#include <string>
#include <vector>
#include <map>
#include <filesystem>
#include <fstream>
#include <random> 
#include "Scaner.h"

using GenStats = ScanStats;

enum class OutputMode {
    FOLDER, // Отдельные файлы
    BIN,    // Один сплошной файл (конкатенация)
    PCAP,   // Дамп трафика (файлы внутри пакетов)
    ZIP     // Архив без сжатия (Store)
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

    // Главный метод
    GenStats generate(const std::filesystem::path& output_path, int count, OutputMode mode, double mix_ratio = 0.0);

private:
    std::map<std::string, FileType> types;
    std::vector<std::string> extensions;

    // Генерирует "чистый" контент файла в память (PDF, DOC, JPG...)
    // Возвращает пару {расширение, данные}
    std::pair<std::string, std::string> create_payload(std::mt19937& rng, bool is_mixed);

    // Хелпер заполнения
    void fill_safe(std::stringstream& ss, size_t count, bool is_text);

    // Реализации упаковщиков
    void write_as_folder(const std::filesystem::path& dir, int count, double mix_ratio, GenStats& stats);
    void write_as_bin(const std::filesystem::path& file, int count, double mix_ratio, GenStats& stats);
    void write_as_pcap(const std::filesystem::path& file, int count, double mix_ratio, GenStats& stats);
    void write_as_zip(const std::filesystem::path& file, int count, double mix_ratio, GenStats& stats);

    // Для ZIP CRC32
    uint32_t calculate_crc32(const std::string& data);

    // Обновление статистики
    void update_stats(const std::string& ext, GenStats& stats);
};