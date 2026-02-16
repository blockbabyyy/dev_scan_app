#include <gtest/gtest.h>
#include <vector>
#include <string>
#include <map>
#include <algorithm>

#include "Scaner.h"

// ==========================================
// 1. СИГНАТУРЫ ДЛЯ ТЕСТОВ
// ==========================================
static const std::vector<SignatureDefinition> TEST_SIGS = {
    { "PDF", "25504446", "2525454F46", "", SignatureType::BINARY },
    // Для ZIP в юнит-тестах используем только заголовок для максимальной надежности
    { "ZIP", "504B0304", "", "", SignatureType::BINARY },
    { "DOCX", "504B0304", "", "word/document.xml", SignatureType::BINARY, "ZIP" }
};

// ==========================================
// 2. ФИКСУТРА ТЕСТА (ШАБЛОННАЯ)
// ==========================================
template <typename T>
class ScannerTest : public ::testing::Test {
protected:
    T scanner;

    void SetUp() override {
        // Загружаем тестовые сигнатуры в движок
        scanner.prepare(TEST_SIGS);
    }

    // Безопасный доступ к мапе результатов
    int GetCount(const ScanStats& stats, const std::string& name) {
        auto it = stats.counts.find(name);
        return (it != stats.counts.end()) ? it->second : 0;
    }

    // Хелпер для запуска сканирования и проверки результата
    void RunVerify(const std::string& data, const std::string& type_name, int expected_count) {
        ScanStats stats;
        scanner.scan(data.data(), data.size(), stats);
        EXPECT_EQ(GetCount(stats, type_name), expected_count) << "Engine: " << scanner.name();
    }
};

// Регистрируем список движков для прогона тестов
using ScannerTypes = ::testing::Types<Re2Scanner, BoostScanner, HsScanner>;
TYPED_TEST_SUITE(ScannerTest, ScannerTypes);

// ==========================================
// 3. ТЕСТЫ
// ==========================================

// Тест детекции PDF (Заголовок + Хвост)
TYPED_TEST(ScannerTest, Detection_PDF) {
    std::string data = "\x25\x50\x44\x46_some_binary_data_\x25\x25\x45\x4F\x46";
    this->RunVerify(data, "PDF", 1);
}

// Тест детекции ZIP (Только заголовок)
TYPED_TEST(ScannerTest, Detection_ZIP) {
    std::string data = "\x50\x4B\x03\x04_content_";
    this->RunVerify(data, "ZIP", 1);
}

// Проверка нахождения DOCX внутри ZIP-структуры (без вычитания)
TYPED_TEST(ScannerTest, Office_Vs_Zip_No_Deduction) {
    std::string data = "\x50\x4B\x03\x04...word/document.xml...";
    ScanStats stats;
    this->scanner.scan(data.data(), data.size(), stats);

    // Должны найти и ZIP (по заголовку), и DOCX (по якорю внутри)
    EXPECT_GE(this->GetCount(stats, "ZIP"), 1);
    EXPECT_EQ(this->GetCount(stats, "DOCX"), 1);
}

// Тест корректной обработки пустого ввода
TYPED_TEST(ScannerTest, Empty_Data) {
    std::string data = "";
    ScanStats stats;
    this->scanner.scan(data.data(), data.size(), stats);
    EXPECT_EQ(stats.counts.size(), 0);
}
