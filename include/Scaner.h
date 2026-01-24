#pragma once
#include <string>
#include <vector>
#include <memory>
#include <regex>
#include <iostream>
#include <boost/regex.hpp>

namespace re2 { class RE2; }
struct hs_database;
struct hs_scratch;

// Статистика (без изменений)
struct ScanStats {
    int total_files = 0;
    int pdf = 0, zip = 0, rar = 0;
    int png = 0, jpg = 0, gif = 0, bmp = 0;
    int mkv = 0, mp3 = 0;
    int doc = 0, xls = 0, ppt = 0;
    int docx = 0, xlsx = 0, pptx = 0;
    int html = 0, xml = 0, json = 0, eml = 0;
    int ole = 0, unknown = 0;

    void reset() { *this = ScanStats(); }

    ScanStats& operator+=(const ScanStats& other) {
        total_files += other.total_files;
        pdf += other.pdf; zip += other.zip; rar += other.rar;
        png += other.png; jpg += other.jpg; gif += other.gif; bmp += other.bmp;
        mkv += other.mkv; mp3 += other.mp3;
        doc += other.doc; xls += other.xls; ppt += other.ppt;
        docx += other.docx; xlsx += other.xlsx; pptx += other.pptx;
        html += other.html; xml += other.xml; json += other.json; eml += other.eml;
        ole += other.ole; unknown += other.unknown;
        return *this;
    }
};

using GenStats = ScanStats;

class Scanner {
public:
    virtual ~Scanner() = default;
    virtual void prepare() {}
    virtual void scan(const char* data, size_t size, ScanStats& stats) = 0;
    virtual std::string name() const = 0;
};

// 1. std::regex (с опциональным pre_check)
class StdScanner : public Scanner {
public:
    StdScanner(bool use_pre_check = true); // [UPDATED]
    ~StdScanner() override;
    std::string name() const override;
    void scan(const char* data, size_t size, ScanStats& stats) override;

private:
    bool m_use_pre_check; // [NEW]
    std::regex r_pdf, r_zip, r_rar4, r_rar5;
    std::regex r_png, r_jpg, r_gif, r_bmp;
    std::regex r_mkv, r_mp3;
    std::regex r_doc, r_xls, r_ppt;
    std::regex r_docx, r_xlsx, r_pptx;
    std::regex r_html, r_xml, r_json, r_eml;
};

// 2. Google RE2 (без изменений)
class Re2Scanner : public Scanner {
public:
    Re2Scanner();
    ~Re2Scanner() override;
    std::string name() const override;
    void scan(const char* data, size_t size, ScanStats& stats) override;

private:
    std::unique_ptr<re2::RE2> r_pdf, r_zip;
    std::unique_ptr<re2::RE2> r_rar4, r_rar5;
    std::unique_ptr<re2::RE2> r_png, r_jpg, r_gif, r_bmp;
    std::unique_ptr<re2::RE2> r_mkv, r_mp3;
    std::unique_ptr<re2::RE2> r_doc, r_xls, r_ppt;
    std::unique_ptr<re2::RE2> r_docx, r_xlsx, r_pptx;
    std::unique_ptr<re2::RE2> r_html, r_xml, r_json, r_eml;
};

// 3. Boost.Regex (с опциональным pre_check)
class BoostScanner : public Scanner {
public:
    BoostScanner(bool use_pre_check = true); // [UPDATED]
    ~BoostScanner() override;
    std::string name() const override;
    void scan(const char* data, size_t size, ScanStats& stats) override;

private:
    bool m_use_pre_check; // [NEW]
    boost::regex r_pdf, r_zip;
    boost::regex r_rar4, r_rar5;
    boost::regex r_png, r_jpg, r_gif, r_bmp;
    boost::regex r_mkv, r_mp3;
    boost::regex r_doc, r_xls, r_ppt;
    boost::regex r_docx, r_xlsx, r_pptx;
    boost::regex r_html, r_xml, r_json, r_eml;
};

// 4. Intel Hyperscan (без изменений)
class HsScanner : public Scanner {
public:
    HsScanner();
    ~HsScanner() override;
    void prepare() override;
    std::string name() const override;
    void scan(const char* data, size_t size, ScanStats& stats) override;

private:
    hs_database* db = nullptr;
    hs_scratch* scratch = nullptr;
    enum {
        ID_DOC = 1, ID_XLS, ID_PPT,
        ID_DOCX, ID_XLSX, ID_PPTX,
        ID_ZIP, ID_PDF, ID_RAR,
        ID_PNG, ID_JPG, ID_GIF, ID_BMP,
        ID_MKV, ID_MP3,
        ID_HTML, ID_XML, ID_JSON, ID_EML
    };
};
