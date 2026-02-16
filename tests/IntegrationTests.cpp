#include <gtest/gtest.h>
#include <filesystem>
#include <vector>
#include <string>
#include <map>
#include <algorithm>

#include "Scaner.h"
#include "generator/Generator.h"
#include <boost/iostreams/device/mapped_file.hpp>

namespace fs = std::filesystem;

// [FIX] Синхронизировано с Signatures.h и Generator.cpp
const std::vector<SignatureDefinition> INTEGRATION_SIGS = {
    { "PDF", "25504446", "2525454F46", "", SignatureType::BINARY },
    { "ZIP", "504B0304", "", "", SignatureType::BINARY },
    { "RAR4", "526172211A0700", "", "", SignatureType::BINARY },
    { "RAR5", "526172211A070100", "", "", SignatureType::BINARY },
    { "PNG", "89504E470D0A1A0A", "49454E44AE426082", "", SignatureType::BINARY },
    { "JPG", "FFD8FF", "FFD9", "", SignatureType::BINARY },
    { "GIF", "47494638", "003B", "", SignatureType::BINARY },
    { "BMP", "424D", "", "", SignatureType::BINARY },
    { "MKV", "1A45DFA3", "", "", SignatureType::BINARY },
    { "MP3", "494433", "", "", SignatureType::BINARY },
    { "DOC", "D0CF11E0A1B11AE1", "", "WordDocument", SignatureType::BINARY, "OLE" },
    { "XLS", "D0CF11E0A1B11AE1", "", "Workbook", SignatureType::BINARY, "OLE" },
    { "PPT", "D0CF11E0A1B11AE1", "", "PowerPoint Document", SignatureType::BINARY, "OLE" },
    { "DOCX", "504B0304", "", "word/document.xml", SignatureType::BINARY, "ZIP" },
    { "XLSX", "504B0304", "", "xl/workbook.xml", SignatureType::BINARY, "ZIP" },
    { "PPTX", "504B0304", "", "ppt/presentation.xml", SignatureType::BINARY, "ZIP" },
    { "JSON", "", "", "\\{\\s*\"[^\"]+\"\\s*:", SignatureType::TEXT },
    { "HTML", "", "", "<html.*?</html>", SignatureType::TEXT },
    { "XML",  "", "", "<\\?xml", SignatureType::TEXT },
    { "EMAIL", "", "", "From:\\s", SignatureType::TEXT }
};

class IntegrationTest : public ::testing::Test {
protected:
    fs::path temp_dir;
    std::unique_ptr<Scanner> scanner;

    void SetUp() override {
        scanner = Scanner::create(EngineType::HYPERSCAN);
        scanner->prepare(INTEGRATION_SIGS);
        std::random_device rd;
        temp_dir = fs::temp_directory_path() / ("devscan_int_" + std::to_string(rd()));
        fs::create_directories(temp_dir);
    }

    void TearDown() override { fs::remove_all(temp_dir); }

    int GetCount(const ScanStats& stats, const std::string& name) {
        auto it = stats.counts.find(name);
        return (it != stats.counts.end()) ? it->second : 0;
    }

    // [FIX] Корректная обработка путей: и папок, и одиночных файлов
    ScanStats ScanPath(const fs::path& path) {
        ScanStats stats;
        auto scan_file = [&](const fs::path& p) {
            try {
                boost::iostreams::mapped_file_source mmap(p.string());
                if (mmap.is_open()) scanner->scan(mmap.data(), mmap.size(), stats);
            }
            catch (...) {}
            };

        if (fs::is_directory(path)) {
            for (const auto& entry : fs::recursive_directory_iterator(path))
                if (entry.is_regular_file()) scan_file(entry.path());
        }
        else if (fs::exists(path)) {
            scan_file(path);
        }
        return stats;
    }
};

TEST_F(IntegrationTest, Folder_Scan_With_Generator) {
    DataSetGenerator gen;
    GenStats expected = gen.generate_count(temp_dir, 50, OutputMode::FOLDER, 0.0);
    ScanStats actual = ScanPath(temp_dir);

    // Вывод отладочного отчета
    std::cout << "--- Scan Report ---\n";
    for (auto const& [name, count] : actual.counts) std::cout << name << ": " << count << "\n";

    for (auto const& [ext, count] : expected.counts) {
        if (count == 0) continue;
        std::string type_name = ext.substr(ext[0] == '.' ? 1 : 0);
        std::transform(type_name.begin(), type_name.end(), type_name.begin(), ::toupper);

        if (type_name == "RAR") {
            int found_rar = GetCount(actual, "RAR4") + GetCount(actual, "RAR5") + GetCount(actual, "RAR");
            EXPECT_GE(found_rar, 1) << "RAR was not detected";
        }
        else {
            if (type_name == "EML") type_name = "EMAIL";
            EXPECT_GE(GetCount(actual, type_name), 1) << "Not found: " << type_name << " (ext: " << ext << ")";
        }
    }
}

TEST_F(IntegrationTest, Zip_Archive_Internal_Scan) {
    DataSetGenerator gen;
    fs::path zip_path = temp_dir / "internal_test.zip";
    gen.generate_count(zip_path, 20, OutputMode::ZIP, 0.0);
    ScanStats actual = ScanPath(zip_path);
    // [FIX] Теперь ZIP-архив воспринимается как файл и сканируется корректно
    EXPECT_GE(GetCount(actual, "ZIP"), 20);
}
