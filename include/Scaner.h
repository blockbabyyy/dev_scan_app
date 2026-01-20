#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <iomanip>
#include <regex>

// Подключаем Boost в хедере, так как объекты используются по значению
#include <boost/regex.hpp>
#include <generator/Generator.h>

// Предварительные объявления, чтобы не перегружать хедер
namespace re2 { class RE2; }
struct hs_database;
struct hs_scratch;
typedef struct hs_database hs_database_t;
typedef struct hs_scratch hs_scratch_t;

// Структура для сбора статистики
struct ScanStats {
    int pdf = 0;
    // Old Office
    int doc = 0; int xls = 0; int ppt = 0; int ole = 0;
    // New Office
    int docx = 0; int xlsx = 0; int pptx = 0; int zip = 0;

    int rar = 0;
    int png = 0; int jpg = 0; int gif = 0; int bmp = 0; int mkv = 0; int mp3 = 0;
    int html = 0; int xml = 0; int json = 0; int eml = 0;
    int unknown = 0;

    // Оператор объединения результатов (реализация в cpp для чистоты, или inline если критично)
    ScanStats& operator+=(const ScanStats& other);

    // Вывод результатов
    void print(const std::string& engine_name) const;
};

// Функция сравнения
void compare_stats(const GenStats& gen, const ScanStats& scan, const std::string& engine_name);

// Абстрактный интерфейс сканера
class Scanner {
public:
    virtual ~Scanner() = default;
    virtual void prepare() {}
    virtual void scan(const char* data, size_t size, ScanStats& stats) = 0;
    virtual std::string name() const = 0;
};

// Реализация на std::regex
class StdScanner : public Scanner {
public:
    StdScanner();
    std::string name() const override;
    void scan(const char* d, size_t s, ScanStats& st) override;

private:
    std::regex r_pdf, r_zip, r_rar4, r_rar5;
    std::regex r_png, r_jpg, r_gif, r_bmp, r_mkv, r_mp3;
    std::regex r_html, r_xml, r_json, r_eml;
    std::regex r_doc, r_xls, r_ppt;
    std::regex r_docx, r_xlsx, r_pptx;
};

// Реализация на Google RE2
class Re2Scanner : public Scanner {
public:
    Re2Scanner();
    ~Re2Scanner() override; // Деструктор нужен, так как используется unique_ptr с неполным типом в хедере
    std::string name() const override;
    void scan(const char* d, size_t s, ScanStats& st) override;

private:
    // PIMPL idiom через unique_ptr позволяет не инклюдить <re2/re2.h> в хедер
    std::unique_ptr<re2::RE2> r_doc, r_xls, r_ppt, r_ole_gen;
    std::unique_ptr<re2::RE2> r_docx, r_xlsx, r_pptx, r_zip_gen;
    std::unique_ptr<re2::RE2> r_pdf, r_rar4, r_rar5;
    std::unique_ptr<re2::RE2> r_png, r_jpg, r_gif, r_bmp, r_mkv, r_mp3;
    std::unique_ptr<re2::RE2> r_html, r_xml, r_json, r_eml;
};

// Реализация на Boost.Regex
class BoostScanner : public Scanner {
public:
    BoostScanner();
    std::string name() const override;
    void scan(const char* d, size_t s, ScanStats& st) override;

private:
    boost::regex r_doc, r_xls, r_ppt, r_ole_gen;
    boost::regex r_docx, r_xlsx, r_pptx, r_zip_gen;
    boost::regex r_pdf, r_rar4, r_rar5;
    boost::regex r_png, r_jpg, r_gif, r_bmp, r_mkv, r_mp3;
    boost::regex r_html, r_xml, r_json, r_eml;
};

// Реализация на Intel Hyperscan
class HsScanner : public Scanner {
public:
    HsScanner();
    ~HsScanner() override;

    void prepare() override;
    std::string name() const override;
    void scan(const char* data, size_t size, ScanStats& stats) override;

private:
    hs_database_t* db = nullptr;
    hs_scratch_t* scratch = nullptr;

    // Внутренние ID паттернов
    enum {
        ID_PDF = 1, ID_OLE, ID_ZIP, ID_RAR,
        ID_DOC, ID_XLS, ID_PPT,
        ID_DOCX, ID_XLSX, ID_PPTX,
        ID_PNG, ID_JPG, ID_GIF, ID_BMP, ID_MKV, ID_MP3,
        ID_HTML, ID_XML, ID_JSON, ID_EML
    };
};