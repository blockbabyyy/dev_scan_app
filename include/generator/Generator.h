#pragma once
#include <string>
#include <vector>
#include <map>
#include <filesystem>
#include <fstream>
#include <random>
#include "Scanner.h"

using GenStats = ScanStats;

enum class OutputMode {
    FOLDER, // Папка с файлами
    BIN,    // Бинарная склейка
    PCAP,   // Эмуляция дампа трафика (файлы как payload пакетов)
    ZIP     // ZIP-архив без сжатия (Store)
};

class DataSetGenerator {
public:
    // config_path — путь к signatures.json для синхронизации сигнатур
    explicit DataSetGenerator(const std::string& config_path = "signatures.json");

    // seed=0 — random_device, иначе фиксированный seed
    GenStats generate_count(const std::filesystem::path& output_path, int count, OutputMode mode, double mix_ratio = 0.0, uint32_t seed = 0);
    GenStats generate_size(const std::filesystem::path& output_path, int size_mb, OutputMode mode, double mix_ratio = 0.0, uint32_t seed = 0);

private:
    struct FileType {
        std::string extension;
        std::string head;
        std::string middle;
        std::string tail;
        bool is_text;
    };

    std::map<std::string, FileType> types;
    std::vector<std::string> extensions;
    std::vector<std::string> dictionary;

    void load_signatures(const std::string& config_path);
    void add_text_templates();

    std::pair<std::string, std::string> create_payload(std::mt19937& rng, bool is_mixed);
    void fill_complex(std::stringstream& ss, size_t count, bool is_text, std::mt19937& rng);
    size_t get_realistic_size(const std::string& ext, std::mt19937& rng);
    void write_generic(const std::filesystem::path& path, size_t limit, int limit_type, OutputMode mode, double mix_ratio, GenStats& stats, uint32_t seed);

    uint32_t calculate_crc32(const std::string& data);
    void update_stats(const std::string& ext, GenStats& stats);
};
