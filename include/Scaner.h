#pragma once
#include <string>
#include <vector>
#include <memory>
#include <regex>
#include <iostream>

// Подключаем Boost (нужен для определения членов класса BoostScanner)
#include <boost/regex.hpp>

// Forward declarations для сторонних библиотек, чтобы не тянуть их хедеры сюда,
// если не обязательно (хотя для unique_ptr RE2 нужен полный тип в cpp, здесь достаточно forward decl,
// но проще подключить в cpp, а здесь использовать указатели).
namespace re2 { class RE2; }
struct hs_database;
struct hs_scratch;

// ==========================================
// Структура статистики
// ==========================================
struct ScanStats {
    // Общие счетчики
    int total_files = 0;

    // Архивы
    int pdf = 0;
    int zip = 0;
    int rar = 0;

    // Картинки
    int png = 0;
    int jpg = 0;
    int gif = 0;
    int bmp = 0;

    // Медиа
    int mkv = 0;
    int mp3 = 0;

    // Office Legacy (OLE)
    int doc = 0;
    int xls = 0;
    int ppt = 0;

    // Office OpenXML (XML inside ZIP)
    int docx = 0;
    int xlsx = 0;
    int pptx = 0;

    // Текст
    int html = 0;
    int xml = 0;
    int json = 0;
    int eml = 0;

    // Служебные
    int ole = 0;     // Просто контейнер OLE (без уточнения типа)
    int unknown = 0; // Не распознано

    // Метод для суммирования результатов (нужен для многопоточности или агрегации)
    ScanStats& operator+=(const ScanStats& other);

    // Метод для красивого вывода
    void print(const std::string& name) const;

    // Сброс
    void reset() { *this = ScanStats(); }
};

// GenStats — это то же самое, что ScanStats (статистика генератора)
using GenStats = ScanStats;

// ==========================================
// Базовый интерфейс Сканера
// ==========================================
class Scanner {
public:
    virtual ~Scanner() = default;

    // Подготовка (нужна для Hyperscan для аллокации scratch memory)
    virtual void prepare() {}

    // Основной метод сканирования
    virtual void scan(const char* data, size_t size, ScanStats& stats) = 0;

    // Имя движка
    virtual std::string name() const = 0;
};

// ==========================================
// Реализации сканеров
// ==========================================

// 1. std::regex
class StdScanner : public Scanner {
public:
    StdScanner();
    std::string name() const override;
    void scan(const char* data, size_t size, ScanStats& stats) override;

private:
    std::regex r_pdf, r_zip, r_rar4, r_rar5;
    std::regex r_png, r_jpg, r_gif, r_bmp;
    std::regex r_mkv, r_mp3;
    std::regex r_doc, r_xls, r_ppt;       // OLE
    std::regex r_docx, r_xlsx, r_pptx;    // XML markers
    std::regex r_html, r_xml, r_json, r_eml;
};

// 2. Google RE2
class Re2Scanner : public Scanner {
public:
    Re2Scanner();
    ~Re2Scanner() override;
    std::string name() const override;
    void scan(const char* data, size_t size, ScanStats& stats) override;

private:
    // Используем unique_ptr, чтобы не инклюдить re2.h в хедер
    std::unique_ptr<re2::RE2> r_pdf, r_zip_gen;
    std::unique_ptr<re2::RE2> r_rar4, r_rar5;
    std::unique_ptr<re2::RE2> r_png, r_jpg, r_gif, r_bmp;
    std::unique_ptr<re2::RE2> r_mkv, r_mp3;
    std::unique_ptr<re2::RE2> r_doc, r_xls, r_ppt;
    std::unique_ptr<re2::RE2> r_docx, r_xlsx, r_pptx;
    std::unique_ptr<re2::RE2> r_html, r_xml, r_json, r_eml;
};

// 3. Boost.Regex
class BoostScanner : public Scanner {
public:
    BoostScanner();
    std::string name() const override;
    void scan(const char* data, size_t size, ScanStats& stats) override;

private:
    boost::regex r_pdf, r_zip_gen;
    boost::regex r_rar4, r_rar5;
    boost::regex r_png, r_jpg, r_gif, r_bmp;
    boost::regex r_mkv, r_mp3;
    boost::regex r_doc, r_xls, r_ppt;
    boost::regex r_docx, r_xlsx, r_pptx;
    boost::regex r_html, r_xml, r_json, r_eml;
};

// 4. Intel Hyperscan
class HsScanner : public Scanner {
public:
    HsScanner();
    ~HsScanner() override;

    void prepare() override; // Alloc scratch
    std::string name() const override;
    void scan(const char* data, size_t size, ScanStats& stats) override;

private:
    struct hs_database* db = nullptr;
    struct hs_scratch* scratch = nullptr;

    // ID для Hyperscan (enum для switch-case в callback)
    enum {
        ID_DOC = 1, ID_XLS, ID_PPT,
        ID_DOCX, ID_XLSX, ID_PPTX,
        ID_ZIP, ID_PDF, ID_RAR,
        ID_PNG, ID_JPG, ID_GIF, ID_BMP,
        ID_MKV, ID_MP3,
        ID_HTML, ID_XML, ID_JSON, ID_EML
    };
};