#include <gtest/gtest.h>
#include <vector>
#include <string>
#include <sstream>
#include <chrono>
#include <map>
#include <iomanip>
#include <random>

#include "Scaner.h"
#include "Signatures.h"

// ==========================================
// 1. ИНФРАСТРУКТУРА ТЕСТОВ
// ==========================================

class TestDataFactory {
public:
    struct TypeInfo {
        std::string head;
        std::string middle;
        std::string tail;
        bool is_text;
    };

    TestDataFactory() {
        // [FIX] Используем константы из Signatures.h, чтобы тесты всегда соответствовали логике
        types[".zip"] = { Sig::Bin::ZIP_HEAD, "", Sig::Bin::ZIP_TAIL, false };
        types[".rar4"] = { Sig::Bin::RAR4, "", "", false };
        types[".rar5"] = { Sig::Bin::RAR5, "", "", false };
        types[".png"] = { Sig::Bin::PNG_HEAD, "", Sig::Bin::PNG_TAIL, false };
        types[".jpg"] = { Sig::Bin::JPG_HEAD, "", Sig::Bin::JPG_TAIL, false };
        types[".gif"] = { Sig::Bin::GIF_HEAD, "", Sig::Bin::GIF_TAIL, false };

        // BMP
        types[".bmp"] = { std::string("\x42\x4D\x36\x00\x0C\x00\x00\x00", 8), "", "", false };

        types[".mkv"] = { Sig::Bin::MKV, "", "", false };
        types[".mp3"] = { Sig::Bin::MP3, "", "", false };

        // Office
        types[".doc"] = { Sig::Bin::OLE, Sig::Bin::OLE_WORD, "", false };
        types[".xls"] = { Sig::Bin::OLE, Sig::Bin::OLE_XL,   "", false };
        types[".ppt"] = { Sig::Bin::OLE, Sig::Bin::OLE_PPT,  "", false };

        // [BATTLE MODE] Важно: middle - это теперь длинный XML якорь
        types[".docx"] = { Sig::Bin::ZIP_HEAD, Sig::Bin::XML_WORD, Sig::Bin::ZIP_TAIL, false };
        types[".xlsx"] = { Sig::Bin::ZIP_HEAD, Sig::Bin::XML_XL,   Sig::Bin::ZIP_TAIL, false };
        types[".pptx"] = { Sig::Bin::ZIP_HEAD, Sig::Bin::XML_PPT,  Sig::Bin::ZIP_TAIL, false };

        // Text
        types[".pdf"] = { Sig::Bin::PDF_HEAD, "", Sig::Bin::PDF_TAIL, false };
        types[".json"] = { "{ \"k\": ", "", " }", true };
        types[".html"] = { "<html><body>", "", "</body></html>", true };
        types[".xml"] = { "<?xml version=\"1.0\"?>", "", "", true };
        types[".eml"] = { "From: me@test.com", "", "", true };
    }

    // Стандартный метод (фиксированный размер)
    std::string Make(const std::string& ext, size_t size = 1024) {
        return GenerateContent(ext, size);
    }

    // [NEW] Метод для реалистичных (рандомных) размеров
    // Возвращает пару {контент, размер}
    std::pair<std::string, size_t> MakeRealistic(const std::string& ext, std::mt19937& rng) {
        size_t size = GetRealisticSize(ext, rng);
        return { GenerateContent(ext, size), size };
    }

    // [NEW] Метод для инъекции контента (проверка на коллизии)
    std::string MakeWithContent(const std::string& ext, const std::string& injected) {
        if (types.find(ext) == types.end()) return "";
        const auto& t = types[ext];
        std::stringstream ss;
        ss << t.head;
        // Вставляем ловушку до маркера
        ss << " ...text... " << injected << " ...text... ";
        ss << t.middle;
        ss << t.tail;
        return ss.str();
    }

    std::string MakeGarbage(size_t size) {
        return std::string(size, '\xAA');
    }

private:
    std::map<std::string, TypeInfo> types;

    // Логика размеров (копия из Generator.cpp)
    size_t GetRealisticSize(const std::string& ext, std::mt19937& rng) {
        std::uniform_int_distribution<int> chance(0, 100);
        int c = chance(rng);
        bool is_text = types[ext].is_text;

        if (is_text) {
            std::uniform_int_distribution<size_t> d(1024, 200 * 1024);
            return d(rng);
        }
        else if (ext == ".mkv" || ext == ".mp3") {
            // Медиа (5-50 МБ)
            std::uniform_int_distribution<size_t> d(5 * 1024 * 1024, 50 * 1024 * 1024);
            return d(rng);
        }
        else {
            // Бинарники
            if (c < 50) { std::uniform_int_distribution<size_t> d(10 * 1024, 500 * 1024); return d(rng); }
            else if (c < 90) { std::uniform_int_distribution<size_t> d(500 * 1024, 5 * 1024 * 1024); return d(rng); }
            else { std::uniform_int_distribution<size_t> d(5 * 1024 * 1024, 20 * 1024 * 1024); return d(rng); }
        }
    }

    std::string GenerateContent(const std::string& ext, size_t size) {
        if (types.find(ext) == types.end()) return "";
        const auto& t = types[ext];
        std::stringstream ss;

        ss << t.head;
        size_t overhead = t.head.size() + t.middle.size() + t.tail.size();
        size_t body_total = (size > overhead) ? size - overhead : 0;

        size_t pre_marker = std::min((size_t)50, body_total);
        size_t post_marker = body_total - pre_marker;

        auto fill = [&](size_t n) {
            if (t.is_text) {
                if (ext == ".json") ss << "\"v\""; else ss << std::string(n, ' ');
            }
            else {
                for (size_t i = 0; i < n; ++i) ss.put((char)0xCC);
            }
            };

        fill(pre_marker);
        ss << t.middle;
        fill(post_marker);
        ss << t.tail;

        return ss.str();
    }
};

// Фикстура
template <typename T>
class ScannerTest : public ::testing::Test {
protected:
    T scanner;
    TestDataFactory factory;

    void SetUp() override { scanner.prepare(); }

    void PrintFailureDetails(const std::string& test_name, const ScanStats& exp, const ScanStats& act, double ms) {
        std::cout << "\n=== FAIL: " << test_name << " [" << scanner.name() << "] (" << ms << " ms) ===\n";
        auto row = [&](const std::string& l, int e, int a) {
            if (e != a) std::cout << " -> " << std::left << std::setw(10) << l << " Exp:" << e << " Act:" << a << "\n";
            };
        row("PDF", exp.pdf, act.pdf); row("ZIP", exp.zip, act.zip); row("RAR", exp.rar, act.rar);
        row("DOC", exp.doc, act.doc); row("XLS", exp.xls, act.xls); row("PPT", exp.ppt, act.ppt);
        row("DOCX", exp.docx, act.docx); row("XLSX", exp.xlsx, act.xlsx); row("PPTX", exp.pptx, act.pptx);
        row("PNG", exp.png, act.png); row("JPG", exp.jpg, act.jpg); row("GIF", exp.gif, act.gif); row("BMP", exp.bmp, act.bmp);
        row("MKV", exp.mkv, act.mkv); row("MP3", exp.mp3, act.mp3);
        row("JSON", exp.json, act.json); row("HTML", exp.html, act.html); row("XML", exp.xml, act.xml); row("EML", exp.eml, act.eml);
        std::cout << "--------------------------------\n";
    }

    void RunVerify(const std::string& test_name, const std::string& data, const ScanStats& expected) {
        ScanStats actual;
        auto start = std::chrono::high_resolution_clock::now();
        scanner.scan(data.data(), data.size(), actual);
        auto ms = std::chrono::duration<double, std::milli>(std::chrono::high_resolution_clock::now() - start).count();

        bool failed = false;
        if (actual.pdf != expected.pdf) failed = true;
        if (actual.zip != expected.zip) failed = true;
        if (actual.rar != expected.rar) failed = true;
        if (actual.doc != expected.doc) failed = true;
        if (actual.xls != expected.xls) failed = true;
        if (actual.ppt != expected.ppt) failed = true;
        if (actual.docx != expected.docx) failed = true;
        if (actual.xlsx != expected.xlsx) failed = true;
        if (actual.pptx != expected.pptx) failed = true;
        if (actual.png != expected.png) failed = true;
        if (actual.jpg != expected.jpg) failed = true;
        if (actual.gif != expected.gif) failed = true;
        if (actual.bmp != expected.bmp) failed = true;
        if (actual.mkv != expected.mkv) failed = true;
        if (actual.mp3 != expected.mp3) failed = true;
        if (actual.json != expected.json) failed = true;
        if (actual.html != expected.html) failed = true;
        if (actual.xml != expected.xml) failed = true;
        if (actual.eml != expected.eml) failed = true;

        if (failed) {
            PrintFailureDetails(test_name, expected, actual, ms);
            FAIL() << "Mismatch in stats";
        }
    }
};

using ScannerTypes = ::testing::Types<StdScanner, Re2Scanner, BoostScanner, HsScanner>;
TYPED_TEST_SUITE(ScannerTest, ScannerTypes);

// --- Tests ---

TYPED_TEST(ScannerTest, Base_AllTypes) {
    ScanStats expected;
    std::string data;
    data += this->factory.Make(".pdf", 2048); expected.pdf++;
    data += this->factory.Make(".zip", 2048); expected.zip++;
    data += this->factory.Make(".png", 1024); expected.png++;
    data += this->factory.Make(".bmp", 1024); expected.bmp++;
    data += this->factory.Make(".gif", 1024); expected.gif++;
    data += this->factory.Make(".mp3", 1024); expected.mp3++;
    data += this->factory.Make(".json", 512) + "\n"; expected.json++;
    data += this->factory.Make(".eml", 512) + "\n";  expected.eml++;
    this->RunVerify("Base_AllTypes", data, expected);
}

TYPED_TEST(ScannerTest, Office_Suite_Fixed) {
    ScanStats expected;
    std::string data;
    data += this->factory.Make(".doc", 2048); expected.doc++;
    data += this->factory.Make(".xls", 2048); expected.xls++;
    data += this->factory.Make(".docx", 2048); expected.docx++;
    // Ожидаем ZIP=0, так как DOCX не считается ZIP-ом
    expected.zip = 0;
    this->RunVerify("Office_Suite_Fixed", data, expected);
}

TYPED_TEST(ScannerTest, Trap_Partial) {
    std::string data;
    data += "BM_fake";
    data += "PK_fake";
    data += Sig::Bin::GIF_HEAD + this->factory.MakeGarbage(100);
    ScanStats expected;
    this->RunVerify("Trap_Partial", data, expected);
}

// [NEW] Тест с реалистичными размерами (Battle Mode Check)
// Проверяет, что якоря находят файлы, а математика st.zip -= office работает.
TYPED_TEST(ScannerTest, Office_Vs_Zip_Realistic) {
    std::mt19937 rng(42);
    std::string data;
    ScanStats expected;

    // 1. Настоящий ZIP (рандомный размер)
    auto [zip_c, zip_s] = this->factory.MakeRealistic(".zip", rng);
    data += zip_c; expected.zip++;

    // 2. Офис (рандомный размер)
    auto [docx_c, docx_s] = this->factory.MakeRealistic(".docx", rng);
    data += docx_c; expected.docx++;
    auto [xlsx_c, xlsx_s] = this->factory.MakeRealistic(".xlsx", rng);
    data += xlsx_c; expected.xlsx++;
    auto [pptx_c, pptx_s] = this->factory.MakeRealistic(".pptx", rng);
    data += pptx_c; expected.pptx++;

    this->RunVerify("Office_Vs_Zip_Realistic", data, expected);
}

// [NEW] Тест на коллизии (Anchor Collision)
// Проверяет, что сканер ищет "word/document.xml", а не просто "word/".
TYPED_TEST(ScannerTest, Office_Anchor_Collision) {
    std::string data;
    // Вставляем обманку "word/" в контент
    data += this->factory.MakeWithContent(".docx", "this is a fake word/ path in text");

    ScanStats expected;
    expected.docx = 1; // Должен найтись только 1 раз (как структура), а не 2

    this->RunVerify("Office_Anchor_Collision", data, expected);
}
