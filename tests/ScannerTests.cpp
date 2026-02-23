#include <gtest/gtest.h>
#include <vector>
#include <string>
#include <map>
#include <algorithm>
#include <fstream>
#include <filesystem>

#include "Scanner.h"
#include "ConfigLoader.h"

// ==========================================
// 1. СИГНАТУРЫ ДЛЯ ТЕСТОВ
// ==========================================
static const std::vector<SignatureDefinition> TEST_SIGS = {
    { "PDF", "25504446", "2525454F46", "", SignatureType::BINARY },
    { "ZIP", "504B0304", "", "", SignatureType::BINARY },
    { "DOCX", "504B0304", "", "word/document.xml", SignatureType::BINARY, "ZIP" }
};

// ==========================================
// 2. ФИКСТУРА (ШАБЛОННАЯ)
// ==========================================
template <typename T>
class ScannerTest : public ::testing::Test {
protected:
    static T scanner;

    static void SetUpTestSuite() {
        scanner.prepare(TEST_SIGS);
    }

    int GetCount(const ScanStats& stats, const std::string& name) {
        auto it = stats.counts.find(name);
        return (it != stats.counts.end()) ? it->second : 0;
    }

    void RunVerify(const std::string& data, const std::string& type_name, int expected_count) {
        ScanStats stats;
        scanner.scan(data.data(), data.size(), stats);
        EXPECT_EQ(GetCount(stats, type_name), expected_count) << "Engine: " << scanner.name();
    }
};

template <typename T>
T ScannerTest<T>::scanner;

using ScannerTypes = ::testing::Types<Re2Scanner, BoostScanner, HsScanner>;
TYPED_TEST_SUITE(ScannerTest, ScannerTypes);

// ==========================================
// 3. БАЗОВЫЕ ТЕСТЫ ДЕТЕКЦИИ
// ==========================================

TYPED_TEST(ScannerTest, Detection_PDF) {
    std::string data = "\x25\x50\x44\x46_some_binary_data_\x25\x25\x45\x4F\x46";
    this->RunVerify(data, "PDF", 1);
}

TYPED_TEST(ScannerTest, Detection_ZIP) {
    std::string data = "\x50\x4B\x03\x04_content_";
    this->RunVerify(data, "ZIP", 1);
}

TYPED_TEST(ScannerTest, Office_ZIP_And_DOCX_Both_Detected) {
    std::string data = "\x50\x4B\x03\x04...word/document.xml...";
    ScanStats stats;
    this->scanner.scan(data.data(), data.size(), stats);
    EXPECT_GE(this->GetCount(stats, "ZIP"), 1);
    EXPECT_EQ(this->GetCount(stats, "DOCX"), 1);
}

TYPED_TEST(ScannerTest, Empty_Data) {
    std::string data = "";
    ScanStats stats;
    this->scanner.scan(data.data(), data.size(), stats);
    EXPECT_EQ(stats.counts.size(), 0u);
}

// ==========================================
// 4. EDGE CASES
// ==========================================

TYPED_TEST(ScannerTest, Single_Byte) {
    std::string data = "\x00";
    ScanStats stats;
    this->scanner.scan(data.data(), data.size(), stats);
    EXPECT_EQ(stats.counts.size(), 0u);
}

TYPED_TEST(ScannerTest, All_Zeros) {
    std::string data(4096, '\0');
    ScanStats stats;
    this->scanner.scan(data.data(), data.size(), stats);
    EXPECT_EQ(this->GetCount(stats, "PDF"), 0);
    EXPECT_EQ(this->GetCount(stats, "ZIP"), 0);
}

TYPED_TEST(ScannerTest, Multiple_PDF_In_Same_Buffer) {
    std::string pdf1 = "\x25\x50\x44\x46_data1_\x25\x25\x45\x4F\x46";
    std::string pdf2 = "\x25\x50\x44\x46_data2_\x25\x25\x45\x4F\x46";
    std::string data = pdf1 + std::string(100, '\xCC') + pdf2;
    ScanStats stats;
    this->scanner.scan(data.data(), data.size(), stats);
    EXPECT_GE(this->GetCount(stats, "PDF"), 2) << "Engine: " << this->scanner.name();
}

// ==========================================
// 5. FALSE POSITIVE ТЕСТЫ (full signatures.json)
// ==========================================

template <typename T>
class FalsePositiveTest : public ::testing::Test {
protected:
    static T scanner;

    static void SetUpTestSuite() {
        auto sigs = ConfigLoader::load("signatures.json");
        scanner.prepare(sigs);
    }

    int GetCount(const ScanStats& stats, const std::string& name) {
        auto it = stats.counts.find(name);
        return (it != stats.counts.end()) ? it->second : 0;
    }
};

template <typename T>
T FalsePositiveTest<T>::scanner;

using FPScannerTypes = ::testing::Types<Re2Scanner, BoostScanner, HsScanner>;
TYPED_TEST_SUITE(FalsePositiveTest, FPScannerTypes);

TYPED_TEST(FalsePositiveTest, BMP_No_FP_On_Plain_BM) {
    // "BM" without the reserved zero bytes should NOT match BMP
    std::string data = "BM some random text with BM appearing again";
    ScanStats stats;
    this->scanner.scan(data.data(), data.size(), stats);
    EXPECT_EQ(this->GetCount(stats, "BMP"), 0) << "BMP false positive on plain text with 'BM'";
}

TYPED_TEST(FalsePositiveTest, Email_No_FP_On_Lone_From) {
    // "From: " without a follow-up header should NOT match EMAIL
    std::string data = "This log says From: admin performed an action.";
    ScanStats stats;
    this->scanner.scan(data.data(), data.size(), stats);
    EXPECT_EQ(this->GetCount(stats, "EMAIL"), 0) << "EMAIL false positive on lone 'From:'";
}

TYPED_TEST(FalsePositiveTest, Email_Positive_With_Headers) {
    std::string data = "From: user@example.com\nTo: other@example.com\nBody text";
    ScanStats stats;
    this->scanner.scan(data.data(), data.size(), stats);
    EXPECT_GE(this->GetCount(stats, "EMAIL"), 1) << "EMAIL not detected with proper headers";
}

// ==========================================
// 6. DEDUCTION LOGIC
// ==========================================

TEST(DeductionTest, DOCX_Deducted_From_ZIP) {
    ScanStats stats;
    stats.counts["ZIP"] = 5;
    stats.counts["DOCX"] = 3;

    std::vector<SignatureDefinition> sigs = {
        { "DOCX", "504B0304", "", "word/document.xml", SignatureType::BINARY, "ZIP" }
    };

    apply_deduction(stats, sigs);

    EXPECT_EQ(stats.counts["ZIP"], 2);  // 5 - 3 = 2
    EXPECT_EQ(stats.counts["DOCX"], 3); // untouched
}

TEST(DeductionTest, Deduction_Does_Not_Go_Negative) {
    ScanStats stats;
    stats.counts["OLE"] = 1;
    stats.counts["DOC"] = 3;

    std::vector<SignatureDefinition> sigs = {
        { "DOC", "D0CF11E0A1B11AE1", "", "WordDocument", SignatureType::BINARY, "OLE" }
    };

    apply_deduction(stats, sigs);

    EXPECT_EQ(stats.counts["OLE"], 0); // max(0, 1-3) = 0
}

// ==========================================
// 7. CONFIGLOADER ТЕСТЫ
// ==========================================

class ConfigLoaderTest : public ::testing::Test {
protected:
    std::filesystem::path temp_file;

    void TearDown() override {
        if (!temp_file.empty()) std::filesystem::remove(temp_file);
    }

    void WriteTemp(const std::string& content) {
        temp_file = std::filesystem::temp_directory_path() / "devscan_test_config.json";
        std::ofstream f(temp_file);
        f << content;
    }
};

TEST_F(ConfigLoaderTest, Valid_File) {
    WriteTemp(R"([{"name": "TEST", "type": "binary", "hex_head": "AABB"}])");
    auto sigs = ConfigLoader::load(temp_file.string());
    ASSERT_EQ(sigs.size(), 1u);
    EXPECT_EQ(sigs[0].name, "TEST");
    EXPECT_EQ(sigs[0].hex_head, "AABB");
}

TEST_F(ConfigLoaderTest, Invalid_JSON) {
    WriteTemp("{broken json");
    auto sigs = ConfigLoader::load(temp_file.string());
    EXPECT_TRUE(sigs.empty());
}

TEST_F(ConfigLoaderTest, Not_An_Array) {
    WriteTemp(R"({"name": "TEST"})");
    auto sigs = ConfigLoader::load(temp_file.string());
    EXPECT_TRUE(sigs.empty());
}

TEST_F(ConfigLoaderTest, Missing_Name_Skipped) {
    WriteTemp(R"([{"type": "binary", "hex_head": "AABB"}, {"name": "OK", "hex_head": "CC"}])");
    auto sigs = ConfigLoader::load(temp_file.string());
    ASSERT_EQ(sigs.size(), 1u);
    EXPECT_EQ(sigs[0].name, "OK");
}

TEST_F(ConfigLoaderTest, Odd_Hex_Cleared) {
    WriteTemp(R"([{"name": "BAD", "type": "binary", "hex_head": "ABC"}])");
    auto sigs = ConfigLoader::load(temp_file.string());
    ASSERT_EQ(sigs.size(), 1u);
    EXPECT_TRUE(sigs[0].hex_head.empty()); // odd length → cleared
}

TEST_F(ConfigLoaderTest, Nonexistent_File) {
    auto sigs = ConfigLoader::load("this_file_does_not_exist_12345.json");
    EXPECT_TRUE(sigs.empty());
}

TEST_F(ConfigLoaderTest, Empty_Array) {
    WriteTemp("[]");
    auto sigs = ConfigLoader::load(temp_file.string());
    EXPECT_TRUE(sigs.empty());
}

TEST_F(ConfigLoaderTest, Text_Without_Pattern_Warns) {
    WriteTemp(R"([{"name": "NOPATTERN", "type": "text"}])");
    auto sigs = ConfigLoader::load(temp_file.string());
    ASSERT_EQ(sigs.size(), 1u);
    EXPECT_TRUE(sigs[0].text_pattern.empty());
}

TEST_F(ConfigLoaderTest, Deduct_From_Invalid_Ref) {
    // Should load but print warning about invalid deduct_from reference
    WriteTemp(R"([{"name": "A", "type": "binary", "hex_head": "FF", "deduct_from": "NONEXISTENT"}])");
    auto sigs = ConfigLoader::load(temp_file.string());
    ASSERT_EQ(sigs.size(), 1u);
    EXPECT_EQ(sigs[0].deduct_from, "NONEXISTENT");
}
