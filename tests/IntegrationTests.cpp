#include <gtest/gtest.h>
#include <filesystem>
#include <vector>
#include <string>
#include <map>
#include <algorithm>

#include "Scaner.h"
#include "ConfigLoader.h"
#include "TypeMap.h"
#include "generator/Generator.h"
#include <boost/iostreams/device/mapped_file.hpp>

namespace fs = std::filesystem;

class IntegrationTest : public ::testing::Test {
protected:
    fs::path temp_dir;
    std::unique_ptr<Scanner> scanner;
    std::vector<SignatureDefinition> sigs;

    void SetUp() override {
        sigs = ConfigLoader::load("signatures.json");
        ASSERT_FALSE(sigs.empty()) << "Failed to load signatures.json";
        scanner = Scanner::create(EngineType::HYPERSCAN);
        scanner->prepare(sigs);
        std::random_device rd;
        temp_dir = fs::temp_directory_path() / ("devscan_int_" + std::to_string(rd()));
        fs::create_directories(temp_dir);
    }

    void TearDown() override { fs::remove_all(temp_dir); }

    int GetCount(const ScanStats& stats, const std::string& name) {
        auto it = stats.counts.find(name);
        return (it != stats.counts.end()) ? it->second : 0;
    }

    ScanStats ScanPath(const fs::path& path) {
        ScanStats stats;
        auto scan_file = [&](const fs::path& p) {
            try {
                if (fs::file_size(p) == 0) return;
                boost::iostreams::mapped_file_source mmap(p.string());
                if (mmap.is_open()) scanner->scan(mmap.data(), mmap.size(), stats);
            }
            catch (...) {}
            };

        if (fs::is_directory(path)) {
            auto opts = fs::directory_options::skip_permission_denied;
            for (const auto& entry : fs::recursive_directory_iterator(path, opts))
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

    for (auto const& [type_name, count] : expected.counts) {
        if (count == 0) continue;
        EXPECT_GE(GetCount(actual, type_name), 1)
            << "Not found: " << type_name;
    }
}

TEST_F(IntegrationTest, Zip_Archive_Internal_Scan) {
    DataSetGenerator gen;
    fs::path zip_path = temp_dir / "internal_test.zip";
    gen.generate_count(zip_path, 20, OutputMode::ZIP, 0.0);
    ScanStats actual = ScanPath(zip_path);
    // ZIP-паттерн с head+tail (PK0304...PK0506) — считает ZIP-структуры, не записи
    EXPECT_GE(GetCount(actual, "ZIP"), 1) << "ZIP archive not detected at all";
}

TEST_F(IntegrationTest, Bin_Concat_Scan) {
    DataSetGenerator gen;
    fs::path bin_path = temp_dir / "concat_test.bin";
    GenStats expected = gen.generate_count(bin_path, 30, OutputMode::BIN, 0.0);
    ScanStats actual = ScanPath(bin_path);

    std::cout << "--- BIN Scan Report ---\n";
    for (auto const& [name, count] : actual.counts) std::cout << name << ": " << count << "\n";

    for (auto const& [type_name, count] : expected.counts) {
        if (count == 0) continue;
        EXPECT_GE(GetCount(actual, type_name), 1)
            << "Not found in BIN: " << type_name;
    }
}

TEST_F(IntegrationTest, Pcap_Dump_Scan) {
    DataSetGenerator gen;
    fs::path pcap_path = temp_dir / "dump_test.pcap";
    GenStats expected = gen.generate_count(pcap_path, 30, OutputMode::PCAP, 0.0);
    ScanStats actual = ScanPath(pcap_path);

    std::cout << "--- PCAP Scan Report ---\n";
    for (auto const& [name, count] : actual.counts) std::cout << name << ": " << count << "\n";

    for (auto const& [type_name, count] : expected.counts) {
        if (count == 0) continue;
        EXPECT_GE(GetCount(actual, type_name), 1)
            << "Not found in PCAP: " << type_name;
    }
}
