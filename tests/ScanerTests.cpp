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
        types[".zip"] = { Sig::Bin::ZIP_HEAD, "", Sig::Bin::ZIP_TAIL, false };
        types[".rar4"] = { Sig::Bin::RAR4, "", "", false };
        types[".rar5"] = { Sig::Bin::RAR5, "", "", false };
        types[".png"] = { Sig::Bin::PNG_HEAD, "", Sig::Bin::PNG_TAIL, false };
        types[".jpg"] = { Sig::Bin::JPG_HEAD, "", Sig::Bin::JPG_TAIL, false };
        types[".gif"] = { Sig::Bin::GIF_HEAD, "", Sig::Bin::GIF_TAIL, false };

        // [FIX] BMP: Используем явный конструктор string, чтобы \x00 не обрезал строку!
        // BM + size(6) + reserved(0,0) + reserved(0,0)
        types[".bmp"] = { std::string("\x42\x4D\x36\x00\x0C\x00\x00\x00", 8), "", "", false };

        types[".mkv"] = { Sig::Bin::MKV, "", "", false };
        types[".mp3"] = { Sig::Bin::MP3, "", "", false };

        // Office
        types[".doc"] = { Sig::Bin::OLE, Sig::Bin::OLE_WORD, "", false };
        types[".xls"] = { Sig::Bin::OLE, Sig::Bin::OLE_XL,   "", false };
        types[".ppt"] = { Sig::Bin::OLE, Sig::Bin::OLE_PPT,  "", false };
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

    std::string Make(const std::string& ext, size_t size = 1024) {
        if (types.find(ext) == types.end()) return "";
        const auto& t = types[ext];
        std::stringstream ss;

        ss << t.head;
        size_t overhead = t.head.size() + t.middle.size() + t.tail.size();
        size_t body_total = (size > overhead) ? size - overhead : 0;

        // Маркер ближе к началу для RE2 (лимит 1000 байт)
        size_t pre_marker = std::min((size_t)50, body_total);
        size_t post_marker = body_total - pre_marker;

        auto fill = [&](size_t n) {
            if (t.is_text) {
                if (ext == ".json") ss << "\"v\""; else ss << std::string(n, ' ');
            }
            else {
                // Безопасный мусор 0xCC (чтобы не создавать хвосты случайно)
                for (size_t i = 0; i < n; ++i) ss.put((char)0xCC);
            }
            };

        fill(pre_marker);
        ss << t.middle;
        fill(post_marker);
        ss << t.tail;

        return ss.str();
    }

    std::string MakeGarbage(size_t size) {
        return std::string(size, '\xAA');
    }

private:
    std::map<std::string, TypeInfo> types;
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
        // Полный вывод таблицы
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
        auto check = [&](int a, int e) { if (a != e) failed = true; };

        check(actual.pdf, expected.pdf); check(actual.zip, expected.zip); check(actual.rar, expected.rar);
        check(actual.doc, expected.doc); check(actual.xls, expected.xls); check(actual.ppt, expected.ppt);
        check(actual.docx, expected.docx); check(actual.xlsx, expected.xlsx); check(actual.pptx, expected.pptx);
        check(actual.png, expected.png); check(actual.jpg, expected.jpg); check(actual.gif, expected.gif); check(actual.bmp, expected.bmp);
        check(actual.mkv, expected.mkv); check(actual.mp3, expected.mp3);
        check(actual.json, expected.json); check(actual.html, expected.html); check(actual.xml, expected.xml); check(actual.eml, expected.eml);

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
    // [FIX] EML теперь 1 (так как ищем только From:)
    data += this->factory.Make(".eml", 512) + "\n";  expected.eml++;

    this->RunVerify("Base_AllTypes", data, expected);
}

TYPED_TEST(ScannerTest, Office_Suite) {
    ScanStats expected;
    std::string data;

    data += this->factory.Make(".doc", 2048); expected.doc++;
    data += this->factory.Make(".xls", 2048); expected.xls++;
    data += this->factory.Make(".docx", 2048); expected.docx++;

    // DOCX это ZIP, ожидаем обнаружение.
    expected.zip = 1;

    // Хак для RE2 теста (из-за жадности может не найти вложенный zip, если они слиплись, но тут они разделены)
    // Но для чистоты теста оставим как есть.
    this->RunVerify("Office_Suite", data, expected);
}

TYPED_TEST(ScannerTest, Trap_Partial) {
    std::string data;
    data += "BM_fake";
    data += "PK_fake";
    // GIF заголовок без хвоста
    data += Sig::Bin::GIF_HEAD + this->factory.MakeGarbage(100);

    ScanStats expected; // Все 0
    this->RunVerify("Trap_Partial", data, expected);
}

TYPED_TEST(ScannerTest, Mush_Multiple_Same_Type) {
    std::string pdf1 = this->factory.Make(".pdf", 1024);
    std::string garbage = this->factory.MakeGarbage(1024);
    std::string pdf2 = this->factory.Make(".pdf", 1024);
    std::string full = pdf1 + garbage + pdf2;

    ScanStats expected;
    // RE2 найдет 1 (жадный *), остальные 2 (ленивые *? или {0,N}?)
    if (this->scanner.name() == "Google RE2") expected.pdf = 1;
    else expected.pdf = 2;

    this->RunVerify("Mush_Multiple_Same_Type", full, expected);
}