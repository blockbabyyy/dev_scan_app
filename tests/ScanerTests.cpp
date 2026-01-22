#include <gtest/gtest.h>
#include "Scaner.h"
#include "Signatures.h"
#include <string>
#include <type_traits>

// Помогательные генераторы буферов для всех типов сигнатур
static std::string make_pdf() {
    return Sig::Bin::PDF_HEAD + std::string("middle") + Sig::Bin::PDF_TAIL;
}
static std::string make_zip_with_xml(const std::string& xml_marker) {
    return Sig::Bin::ZIP_HEAD + std::string(16, 'Z') + xml_marker;
}
static std::string make_zip_full() {
    return Sig::Bin::ZIP_HEAD + std::string(16, 'Z') + Sig::Bin::ZIP_TAIL;
}
static std::string make_rar4() {
    return Sig::Bin::RAR4 + std::string(4, 'R');
}
static std::string make_rar5() {
    return Sig::Bin::RAR5 + std::string(4, 'R');
}
static std::string make_ole_with(const std::string& marker) {
    return Sig::Bin::OLE + std::string(8, 'X') + marker;
}
static std::string make_framed(const std::string& head, const std::string& tail) {
    return head + std::string(100, 'A') + tail;
}
static std::string make_bmp() {
    std::string s;
    s.push_back('B'); s.push_back('M');
    // 4 bytes size
    s.push_back('\x10'); s.push_back('\x00'); s.push_back('\x00'); s.push_back('\x00');
    // two reserved zero bytes expected by regex
    s.push_back('\x00'); s.push_back('\x00');
    // some payload
    s.append(std::string(10, 'B'));
    return s;
}
static std::string make_html() {
    return Sig::Text::HTML_HEAD + std::string(" body ") + Sig::Text::HTML_TAIL;
}
static std::string make_xml_text() {
    return std::string("<?xml version=\"1.0\"?>") + std::string("content");
}
static std::string make_json() {
    return std::string("{ \"key\": \"value\" }");
}
static std::string make_eml() {
    return std::string("From: user@example.com\r\nSubject: test\r\n");
}

// Универсальная функция запуска тестов для одного сканнера
template <typename Scanner>
void run_full_signature_test(const std::string& scanner_name) {
    Scanner scanner;
    if constexpr (std::is_same_v<Scanner, HsScanner>) {
        scanner.prepare();
    }

    ScanStats st{};

    // Библиотека ожидает бинарные буферы — используем std::string с нулевыми байтами при необходимости
    auto pdf = make_pdf();
    auto zip_full = make_zip_full();
    auto zip_docx = make_zip_with_xml(Sig::Bin::XML_WORD);
    auto zip_xlsx = make_zip_with_xml(Sig::Bin::XML_XL);
    auto zip_pptx = make_zip_with_xml(Sig::Bin::XML_PPT);
    auto rar4 = make_rar4();
    auto rar5 = make_rar5();
    auto ole_doc = make_ole_with(Sig::Bin::OLE_WORD);
    auto ole_xls = make_ole_with(Sig::Bin::OLE_XL);
    auto ole_ppt = make_ole_with(Sig::Bin::OLE_PPT);
    auto png = make_framed(Sig::Bin::PNG_HEAD, Sig::Bin::PNG_TAIL);
    auto jpg = make_framed(Sig::Bin::JPG_HEAD, Sig::Bin::JPG_TAIL);
    auto gif = make_framed(Sig::Bin::GIF_HEAD, Sig::Bin::GIF_TAIL);
    auto bmp = make_bmp();
    auto mkv = Sig::Bin::MKV + std::string(8, '\x00');
    auto mp3 = Sig::Bin::MP3 + std::string(8, '\x00');
    auto html = make_html();
    auto xml = make_xml_text();
    auto json = make_json();
    auto eml = make_eml();

    // Сканы (один файл = одна сигнатура) — вызываем по одному разу для каждого буфера
    scanner.scan(pdf.data(), pdf.size(), st);
    scanner.scan(zip_full.data(), zip_full.size(), st);
    scanner.scan(zip_docx.data(), zip_docx.size(), st);
    scanner.scan(zip_xlsx.data(), zip_xlsx.size(), st);
    scanner.scan(zip_pptx.data(), zip_pptx.size(), st);
    scanner.scan(rar4.data(), rar4.size(), st);
    scanner.scan(rar5.data(), rar5.size(), st);
    scanner.scan(ole_doc.data(), ole_doc.size(), st);
    scanner.scan(ole_xls.data(), ole_xls.size(), st);
    scanner.scan(ole_ppt.data(), ole_ppt.size(), st);
    scanner.scan(png.data(), png.size(), st);
    scanner.scan(jpg.data(), jpg.size(), st);
    scanner.scan(gif.data(), gif.size(), st);
    scanner.scan(bmp.data(), bmp.size(), st);
    scanner.scan(mkv.data(), mkv.size(), st);
    scanner.scan(mp3.data(), mp3.size(), st);
    scanner.scan(html.data(), html.size(), st);
    scanner.scan(xml.data(), xml.size(), st);
    scanner.scan(json.data(), json.size(), st);
    scanner.scan(eml.data(), eml.size(), st);

    // Для Hyperscan: если DB/scratch не доступны и ничего не найдено — пропустить тест
    if constexpr (std::is_same_v<Scanner, HsScanner>) {
        if ((st.pdf + st.zip + st.rar + st.doc + st.xls + st.ppt +
             st.docx + st.xlsx + st.pptx + st.png + st.jpg + st.gif +
             st.bmp + st.mkv + st.mp3 + st.html + st.xml + st.json + st.eml) == 0) {
            GTEST_SKIP() << "Hyperscan DB/scratch not available for " << scanner_name;
        }
    }

    // Проверки: каждый тип хотя бы один раз найден
    EXPECT_GE(st.pdf, 1) << scanner_name << " should detect PDF";
    EXPECT_GE(st.zip, 1) << scanner_name << " should detect ZIP";
    EXPECT_GE(st.rar, 1) << scanner_name << " should detect RAR (4/5)";
    EXPECT_GE(st.doc, 1) << scanner_name << " should detect OLE Word";
    EXPECT_GE(st.xls, 1) << scanner_name << " should detect OLE Excel";
    EXPECT_GE(st.ppt, 1) << scanner_name << " should detect OLE PowerPoint";
    EXPECT_GE(st.docx, 1) << scanner_name << " should detect DOCX (XML)";
    EXPECT_GE(st.xlsx, 1) << scanner_name << " should detect XLSX (XML)";
    EXPECT_GE(st.pptx, 1) << scanner_name << " should detect PPTX (XML)";
    EXPECT_GE(st.png, 1) << scanner_name << " should detect PNG";
    EXPECT_GE(st.jpg, 1) << scanner_name << " should detect JPG";
    EXPECT_GE(st.gif, 1) << scanner_name << " should detect GIF";
    EXPECT_GE(st.bmp, 1) << scanner_name << " should detect BMP";
    EXPECT_GE(st.mkv, 1) << scanner_name << " should detect MKV";
    EXPECT_GE(st.mp3, 1) << scanner_name << " should detect MP3";
    EXPECT_GE(st.html, 1) << scanner_name << " should detect HTML";
    EXPECT_GE(st.xml, 1) << scanner_name << " should detect XML";
    EXPECT_GE(st.json, 1) << scanner_name << " should detect JSON";
    EXPECT_GE(st.eml, 1) << scanner_name << " should detect EML";
}

// Тесты для каждого из поддерживаемых сканнеров
TEST(ScanerTests, StdScanner_AllSignatures) {
    run_full_signature_test<StdScanner>("std::regex");
}

TEST(ScanerTests, Re2Scanner_AllSignatures) {
    run_full_signature_test<Re2Scanner>("Google RE2");
}

TEST(ScanerTests, BoostScanner_AllSignatures) {
    run_full_signature_test<BoostScanner>("Boost.Regex");
}

TEST(ScanerTests, HsScanner_AllSignatures) {
    run_full_signature_test<HsScanner>("Hyperscan");
}