#pragma once
#include <string>
#include <vector>
#include <random>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include "Signatures.h"

namespace fs = std::filesystem;

struct GenStats {
    size_t total_files = 0;
    size_t total_bytes = 0;
    size_t pdf = 0, doc = 0, xls = 0, ppt = 0, ole = 0;
    size_t docx = 0, xlsx = 0, pptx = 0, zip = 0, rar = 0;
    size_t png = 0, jpg = 0, gif = 0, bmp = 0, mkv = 0, mp3 = 0;
    size_t html = 0, xml = 0, json = 0, eml = 0, txt = 0;

    size_t office_ole = 0;
    size_t office_xml = 0;
};

enum class ContainerType { FOLDER, ZIP, PCAP, BIN };

class DataSetGenerator {
public:
    struct FileType {
        std::string extension;
        std::string signature; // Header
        bool is_text;
        std::string footer;    // <--- NEW: Footer for carving validation
    };

    DataSetGenerator();
    GenStats generate(const std::string& output_path, size_t total_size_mb, ContainerType type);

public:
    // Generates a single file content into stream
    void generate_content(std::ostream& out, size_t size, const FileType& type);


private:
    std::vector<FileType> file_types;
    static const std::vector<std::string> dictionary;

    std::mt19937 rng;

   

    // Methods per container
    void generate_folder(const std::string& dir, size_t totalBytes, GenStats& stats);
    void generate_zip(const std::string& filename, size_t totalBytes, GenStats& stats);
    void generate_pcap(const std::string& filename, size_t totalBytes, GenStats& stats);
    void generate_bin(const std::string& filename, size_t totalBytes, GenStats& stats);

    // Content fillers
    void fill_text(std::ostream& out, size_t size);
    void fill_json(std::ostream& out, size_t size);
    void fill_email(std::ostream& out, size_t size);
    void fill_binary(std::ostream& out, size_t size, const std::string& signatureToAvoid);

    void fill_ole(std::ostream& out, size_t size, const std::string& marker);
    void fill_openxml(std::ostream& out, size_t size, const std::string& marker);

    void update_stats(GenStats& stats, const std::string& ext);
    uint32_t calculate_CRC32(const char* data, size_t length);
    struct ZipEntry { std::string name; uint32_t crc32; uint32_t size; uint32_t offset; };
};