#include <re2/re2.h>
#include <hs/hs.h>
#include <string_view>
#include <iostream>
#include <exception>
#include <iomanip>
#include <vector>
#include <algorithm>

#include "Scaner.h"
#include "Signatures.h"

// ==========================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// ==========================================

// Быстрая пред-проверка (Pre-check).
// Используется ТОЛЬКО в StdScanner для оптимизации.
// Проверяет наличие подстрок head и tail перед запуском тяжелой регулярки.
inline bool pre_check(const char* data, size_t size, const std::string& head, const std::string& tail = "") {
    if (head.empty()) {
        return true;
    }

    std::string_view sv(data, size);
    size_t head_pos = sv.find(head);

    if (head_pos == std::string_view::npos) {
        return false;
    }

    if (!tail.empty()) {
        // Ищем хвост строго после заголовка
        if (sv.find(tail, head_pos + 1) == std::string_view::npos) {
            return false;
        }
    }
    return true;
}

// Пост-коррекция счетчиков.
// Так как DOCX/XLSX/PPTX технически являются ZIP-архивами,
// сканеры могут находить ZIP-сигнатуры внутри них.
// Мы вычитаем количество офисных файлов из ZIP, чтобы получить "чистые" архивы.
inline void fix_counters(ScanStats& st) {
    int office_xml = 0;
    office_xml += st.docx;
    office_xml += st.xlsx;
    office_xml += st.pptx;

    if (st.zip >= office_xml) {
        st.zip -= office_xml;
    }
    else {
        // Защита от отрицательных значений (если вдруг regex ошибся)
        st.zip = 0;
    }
}

// ==========================================
// StdScanner
// ==========================================
// Использует std::regex. Самый медленный, требует pre_check.

StdScanner::StdScanner() {
    auto f = std::regex::optimize;
    auto fi = std::regex::optimize | std::regex::icase;

    auto safe_compile = [&](std::regex& target, const std::string& pat, auto flags, const char* name) {
        try {
            target.assign(pat, flags);
        }
        catch (const std::regex_error& e) {
            std::cerr << "[StdScanner] Error compiling " << name << ": " << e.what() << "\n";
        }
        };

    // Компиляция сигнатур
    safe_compile(r_doc, Sig::complex<Sig::Engine::STD>(Sig::Bin::OLE, Sig::Bin::OLE_WORD), f, "DOC");
    safe_compile(r_xls, Sig::complex<Sig::Engine::STD>(Sig::Bin::OLE, Sig::Bin::OLE_XL), f, "XLS");
    safe_compile(r_ppt, Sig::complex<Sig::Engine::STD>(Sig::Bin::OLE, Sig::Bin::OLE_PPT), f, "PPT");

    safe_compile(r_docx, Sig::complex<Sig::Engine::STD>(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_WORD), f, "DOCX");
    safe_compile(r_xlsx, Sig::complex<Sig::Engine::STD>(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_XL), f, "XLSX");
    safe_compile(r_pptx, Sig::complex<Sig::Engine::STD>(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_PPT), f, "PPTX");

    // Для ZIP ищем только EOCD (хвост)
    safe_compile(r_zip, Sig::framed<Sig::Engine::STD>(Sig::Bin::ZIP_HEAD, Sig::Bin::ZIP_TAIL), f, "ZIP");

    safe_compile(r_pdf, Sig::framed<Sig::Engine::STD>(Sig::Bin::PDF_HEAD, Sig::Bin::PDF_TAIL), f, "PDF");

    safe_compile(r_png, Sig::framed<Sig::Engine::STD>(Sig::Bin::PNG_HEAD, Sig::Bin::PNG_TAIL), f, "PNG");
    safe_compile(r_jpg, Sig::framed<Sig::Engine::STD>(Sig::Bin::JPG_HEAD, Sig::Bin::JPG_TAIL), f, "JPG");
    safe_compile(r_gif, Sig::framed<Sig::Engine::STD>(Sig::Bin::GIF_HEAD, Sig::Bin::GIF_TAIL), f, "GIF");

    safe_compile(r_rar4, Sig::raw_to_hex(Sig::Bin::RAR4), f, "RAR4");
    safe_compile(r_rar5, Sig::raw_to_hex(Sig::Bin::RAR5), f, "RAR5");
    safe_compile(r_bmp, Sig::Bin::BMP_HEAD, f, "BMP");

    safe_compile(r_mkv, Sig::raw_to_hex(Sig::Bin::MKV), f, "MKV");
    safe_compile(r_mp3, Sig::raw_to_hex(Sig::Bin::MP3), f, "MP3");

    safe_compile(r_html, Sig::framed_text<Sig::Engine::STD>(Sig::Text::HTML_HEAD, Sig::Text::HTML_TAIL), fi, "HTML");
    safe_compile(r_xml, Sig::Text::XML, fi, "XML");
    safe_compile(r_json, Sig::framed_text<Sig::Engine::STD>(Sig::Text::JSON_HEAD, Sig::Text::JSON_TAIL), f, "JSON");
    safe_compile(r_eml, Sig::Text::EML, fi, "EML");
}

StdScanner::~StdScanner() = default;

std::string StdScanner::name() const { return "std::regex"; }

void StdScanner::scan(const char* d, size_t s, ScanStats& st) {
    auto run_check = [&](const std::string& label, const std::regex& re, int& counter,
        const std::string& head_check = "", const std::string& tail_check = "") {

            // 1. Быстрая проверка (Optimization)
            if (!pre_check(d, s, head_check, tail_check)) {
                return;
            }

            std::cout << "\r[StdScanner] Scanning: " << std::left << std::setw(10) << label
                << " | Found: " << counter << std::flush;

            const char* start = d;
            const char* end = d + s;
            std::cmatch m;

            try {
                if (re.mark_count() == 0 && std::string(start, std::min((size_t)1, s)).empty()) return;

                while (start < end && std::regex_search(start, end, m, re)) {
                    counter++;
                    std::cout << "\r[StdScanner] Scanning: " << std::left << std::setw(10) << label
                        << " | Found: " << counter << std::flush;

                    auto shift = std::max((std::ptrdiff_t)1, m.length());
                    start += m.position() + shift;
                }
            }
            catch (...) {}
        };

    // Запуск сканирования с pre_check аргументами
    run_check("DOC", r_doc, st.doc, Sig::Bin::OLE, Sig::Bin::OLE_WORD);
    run_check("XLS", r_xls, st.xls, Sig::Bin::OLE, Sig::Bin::OLE_XL);
    run_check("PPT", r_ppt, st.ppt, Sig::Bin::OLE, Sig::Bin::OLE_PPT);

    run_check("DOCX", r_docx, st.docx, Sig::Bin::ZIP_HEAD, Sig::Bin::XML_WORD);
    run_check("XLSX", r_xlsx, st.xlsx, Sig::Bin::ZIP_HEAD, Sig::Bin::XML_XL);
    run_check("PPTX", r_pptx, st.pptx, Sig::Bin::ZIP_HEAD, Sig::Bin::XML_PPT);

    // Для ZIP проверяем только EOCD
    run_check("ZIP", r_zip, st.zip, "", Sig::Bin::ZIP_TAIL);

    run_check("PDF", r_pdf, st.pdf, Sig::Bin::PDF_HEAD, Sig::Bin::PDF_TAIL);
    run_check("RAR4", r_rar4, st.rar, Sig::Bin::RAR4);
    run_check("RAR5", r_rar5, st.rar, Sig::Bin::RAR5);

    run_check("PNG", r_png, st.png, Sig::Bin::PNG_HEAD, Sig::Bin::PNG_TAIL);
    run_check("JPG", r_jpg, st.jpg, Sig::Bin::JPG_HEAD, Sig::Bin::JPG_TAIL);
    run_check("GIF", r_gif, st.gif, Sig::Bin::GIF_HEAD, Sig::Bin::GIF_TAIL);
    run_check("BMP", r_bmp, st.bmp, "BM");

    run_check("MKV", r_mkv, st.mkv, Sig::Bin::MKV);
    run_check("MP3", r_mp3, st.mp3, Sig::Bin::MP3);

    run_check("HTML", r_html, st.html, "<html", "</html>");
    run_check("XML", r_xml, st.xml, "<?xml");
    run_check("JSON", r_json, st.json, "{", "}");
    run_check("EML", r_eml, st.eml, "From:");

    // Финальная коррекция категорий
    fix_counters(st);

    std::cout << "\r[StdScanner] Done.                                           \n";
}

// ==========================================
// Re2Scanner
// ==========================================
// Использует Google RE2. Работает БЕЗ pre_check (честный бенчмарк).

// ==========================================
// Re2Scanner
// ==========================================
Re2Scanner::Re2Scanner() {
    auto compile = [&](std::unique_ptr<re2::RE2>& target, const std::string& pat) {
        re2::RE2::Options opt;

        // [FIX] Критически важно для бинарных файлов!
        // По умолчанию RE2 ожидает UTF-8 и точка (.) не матчит "битые" байты.
        // EncodingLatin1 заставляет RE2 работать с сырыми байтами.
        opt.set_encoding(re2::RE2::Options::EncodingLatin1);

        opt.set_dot_nl(true);           // Точка матчит \n
        opt.set_case_sensitive(false);  // Регистронезависимость

        target = std::make_unique<re2::RE2>(pat, opt);

        if (!target->ok()) {
            std::cerr << "\n[Re2Scanner] Error compiling regex: " << target->error()
                << " | Pattern: " << pat.substr(0, 50) << "...\n";
        }
        };

    // Дальше код без изменений
    compile(r_doc, Sig::complex<Sig::Engine::RE2>(Sig::Bin::OLE, Sig::Bin::OLE_WORD));
    compile(r_xls, Sig::complex<Sig::Engine::RE2>(Sig::Bin::OLE, Sig::Bin::OLE_XL));
    compile(r_ppt, Sig::complex<Sig::Engine::RE2>(Sig::Bin::OLE, Sig::Bin::OLE_PPT));

    compile(r_docx, Sig::complex<Sig::Engine::RE2>(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_WORD));
    compile(r_xlsx, Sig::complex<Sig::Engine::RE2>(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_XL));
    compile(r_pptx, Sig::complex<Sig::Engine::RE2>(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_PPT));

    compile(r_zip, Sig::framed<Sig::Engine::RE2>(Sig::Bin::ZIP_HEAD, Sig::Bin::ZIP_TAIL));
    compile(r_pdf, Sig::framed<Sig::Engine::RE2>(Sig::Bin::PDF_HEAD, Sig::Bin::PDF_TAIL));

    compile(r_png, Sig::framed<Sig::Engine::RE2>(Sig::Bin::PNG_HEAD, Sig::Bin::PNG_TAIL));
    compile(r_jpg, Sig::framed<Sig::Engine::RE2>(Sig::Bin::JPG_HEAD, Sig::Bin::JPG_TAIL));
    compile(r_gif, Sig::framed<Sig::Engine::RE2>(Sig::Bin::GIF_HEAD, Sig::Bin::GIF_TAIL));

    compile(r_rar4, Sig::raw_to_hex(Sig::Bin::RAR4));
    compile(r_rar5, Sig::raw_to_hex(Sig::Bin::RAR5));
    compile(r_bmp, Sig::Bin::BMP_HEAD);

    compile(r_mkv, Sig::raw_to_hex(Sig::Bin::MKV));
    compile(r_mp3, Sig::raw_to_hex(Sig::Bin::MP3));

    compile(r_html, Sig::framed_text<Sig::Engine::RE2>(Sig::Text::HTML_HEAD, Sig::Text::HTML_TAIL));
    compile(r_xml, Sig::Text::XML);
    compile(r_json, Sig::framed_text<Sig::Engine::RE2>(Sig::Text::JSON_HEAD, Sig::Text::JSON_TAIL));
    compile(r_eml, Sig::Text::EML);
}

Re2Scanner::~Re2Scanner() = default;
std::string Re2Scanner::name() const { return "Google RE2"; }

void Re2Scanner::scan(const char* data, size_t size, ScanStats& stats) {
    // Чистый RE2 без pre_check
    auto run = [&](const std::unique_ptr<re2::RE2>& re, int& cnt) {
        re2::StringPiece input(data, size);
        while (re2::RE2::FindAndConsume(&input, *re)) {
            cnt++;
        }
        };

    run(r_doc, stats.doc); run(r_xls, stats.xls); run(r_ppt, stats.ppt);
    run(r_docx, stats.docx); run(r_xlsx, stats.xlsx); run(r_pptx, stats.pptx);
    run(r_zip, stats.zip); run(r_pdf, stats.pdf);
    run(r_png, stats.png); run(r_jpg, stats.jpg); run(r_gif, stats.gif);
    run(r_rar4, stats.rar); run(r_rar5, stats.rar); run(r_bmp, stats.bmp);
    run(r_mkv, stats.mkv); run(r_mp3, stats.mp3);
    run(r_html, stats.html); run(r_xml, stats.xml); run(r_json, stats.json); run(r_eml, stats.eml);

    fix_counters(stats);
}

// ==========================================
// BoostScanner
// ==========================================
// Использует Boost.Regex. Работает БЕЗ pre_check.

BoostScanner::BoostScanner() {
    auto f = boost::regex::optimize;
    auto fi = boost::regex::optimize | boost::regex::icase;

    r_doc.assign(Sig::complex<Sig::Engine::BOOST>(Sig::Bin::OLE, Sig::Bin::OLE_WORD), f);
    r_xls.assign(Sig::complex<Sig::Engine::BOOST>(Sig::Bin::OLE, Sig::Bin::OLE_XL), f);
    r_ppt.assign(Sig::complex<Sig::Engine::BOOST>(Sig::Bin::OLE, Sig::Bin::OLE_PPT), f);

    r_docx.assign(Sig::complex<Sig::Engine::BOOST>(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_WORD), f);
    r_xlsx.assign(Sig::complex<Sig::Engine::BOOST>(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_XL), f);
    r_pptx.assign(Sig::complex<Sig::Engine::BOOST>(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_PPT), f);

    r_zip.assign(Sig::framed<Sig::Engine::BOOST>(Sig::Bin::ZIP_HEAD, Sig::Bin::ZIP_TAIL), f);
    r_pdf.assign(Sig::framed<Sig::Engine::BOOST>(Sig::Bin::PDF_HEAD, Sig::Bin::PDF_TAIL), f);

    r_png.assign(Sig::framed<Sig::Engine::BOOST>(Sig::Bin::PNG_HEAD, Sig::Bin::PNG_TAIL), f);
    r_jpg.assign(Sig::framed<Sig::Engine::BOOST>(Sig::Bin::JPG_HEAD, Sig::Bin::JPG_TAIL), f);
    r_gif.assign(Sig::framed<Sig::Engine::BOOST>(Sig::Bin::GIF_HEAD, Sig::Bin::GIF_TAIL), f);

    r_rar4.assign(Sig::raw_to_hex(Sig::Bin::RAR4), f);
    r_rar5.assign(Sig::raw_to_hex(Sig::Bin::RAR5), f);
    r_bmp.assign(Sig::Bin::BMP_HEAD, f);

    r_mkv.assign(Sig::raw_to_hex(Sig::Bin::MKV), f);
    r_mp3.assign(Sig::raw_to_hex(Sig::Bin::MP3), f);

    r_html.assign(Sig::framed_text<Sig::Engine::BOOST>(Sig::Text::HTML_HEAD, Sig::Text::HTML_TAIL), fi);
    r_xml.assign(Sig::Text::XML, fi);
    r_json.assign(Sig::framed_text<Sig::Engine::BOOST>(Sig::Text::JSON_HEAD, Sig::Text::JSON_TAIL), f);
    r_eml.assign(Sig::Text::EML, fi);
}

BoostScanner::~BoostScanner() = default;

std::string BoostScanner::name() const { return "Boost.Regex"; }

void BoostScanner::scan(const char* data, size_t size, ScanStats& stats) {
    // Чистый запуск Boost
    auto run = [&](const boost::regex& re, int& cnt) {
        boost::cmatch m;
        const char* start = data;
        const char* end = data + size;
        while (boost::regex_search(start, end, m, re)) {
            cnt++;
            start += m.position() + std::max((std::ptrdiff_t)1, m.length());
        }
        };

    run(r_doc, stats.doc);
    run(r_xls, stats.xls);
    run(r_ppt, stats.ppt);

    run(r_docx, stats.docx);
    run(r_xlsx, stats.xlsx);
    run(r_pptx, stats.pptx);

    run(r_zip, stats.zip);
    run(r_pdf, stats.pdf);

    run(r_png, stats.png);
    run(r_jpg, stats.jpg);
    run(r_gif, stats.gif);
    run(r_rar4, stats.rar);
    run(r_rar5, stats.rar);
    run(r_bmp, stats.bmp);

    run(r_mkv, stats.mkv);
    run(r_mp3, stats.mp3);

    run(r_html, stats.html);
    run(r_xml, stats.xml);
    run(r_json, stats.json);
    run(r_eml, stats.eml);

    // Финальная коррекция категорий
    fix_counters(stats);
}

// ==========================================
// HsScanner
// ==========================================
// Использует Intel Hyperscan. Самый быстрый и мощный.

HsScanner::HsScanner() {
    // Используем Sig::complex<Sig::Engine::HS> -> это дает полные сигнатуры (Head.*?Tail)
    // HS может позволить себе сложные паттерны без потери скорости.
    std::string p_doc = Sig::complex<Sig::Engine::HS>(Sig::Bin::OLE, Sig::Bin::OLE_WORD);
    std::string p_xls = Sig::complex<Sig::Engine::HS>(Sig::Bin::OLE, Sig::Bin::OLE_XL);
    std::string p_ppt = Sig::complex<Sig::Engine::HS>(Sig::Bin::OLE, Sig::Bin::OLE_PPT);

    // Для OpenXML: Head(ZIP) ... Anchor(XML)
    std::string p_docx = Sig::complex<Sig::Engine::HS>(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_WORD);
    std::string p_xlsx = Sig::complex<Sig::Engine::HS>(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_XL);
    std::string p_pptx = Sig::complex<Sig::Engine::HS>(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_PPT);

    std::string p_zip = Sig::framed<Sig::Engine::HS>(Sig::Bin::ZIP_HEAD, Sig::Bin::ZIP_TAIL);
    std::string p_pdf = Sig::framed<Sig::Engine::HS>(Sig::Bin::PDF_HEAD, Sig::Bin::PDF_TAIL);

    std::string p_png = Sig::framed<Sig::Engine::HS>(Sig::Bin::PNG_HEAD, Sig::Bin::PNG_TAIL);
    std::string p_jpg = Sig::framed<Sig::Engine::HS>(Sig::Bin::JPG_HEAD, Sig::Bin::JPG_TAIL);
    std::string p_gif = Sig::framed<Sig::Engine::HS>(Sig::Bin::GIF_HEAD, Sig::Bin::GIF_TAIL);

    std::string p_rar4 = Sig::raw_to_hex(Sig::Bin::RAR4);
    std::string p_rar5 = Sig::raw_to_hex(Sig::Bin::RAR5);
    std::string p_bmp = Sig::Bin::BMP_HEAD;
    std::string p_mkv = Sig::raw_to_hex(Sig::Bin::MKV);
    std::string p_mp3 = Sig::raw_to_hex(Sig::Bin::MP3);

    std::string p_html = Sig::framed_text<Sig::Engine::HS>(Sig::Text::HTML_HEAD, Sig::Text::HTML_TAIL);
    std::string p_xml = Sig::Text::XML;
    std::string p_json = Sig::framed_text<Sig::Engine::HS>(Sig::Text::JSON_HEAD, Sig::Text::JSON_TAIL);
    std::string p_eml = Sig::Text::EML;

    const char* exprs[] = {
        p_doc.c_str(), p_xls.c_str(), p_ppt.c_str(),
        p_docx.c_str(), p_xlsx.c_str(), p_pptx.c_str(), p_zip.c_str(),
        p_pdf.c_str(), p_rar4.c_str(), p_rar5.c_str(),
        p_png.c_str(), p_jpg.c_str(), p_gif.c_str(), p_bmp.c_str(), p_mkv.c_str(), p_mp3.c_str(),
        p_html.c_str(), p_xml.c_str(), p_json.c_str(), p_eml.c_str()
    };
    unsigned int ids[] = {
        ID_DOC, ID_XLS, ID_PPT,
        ID_DOCX, ID_XLSX, ID_PPTX, ID_ZIP,
        ID_PDF, ID_RAR, ID_RAR,
        ID_PNG, ID_JPG, ID_GIF, ID_BMP, ID_MKV, ID_MP3,
        ID_HTML, ID_XML, ID_JSON, ID_EML
    };

    // Флаги: DOTALL (точка включает \n), CASELESS (регистронезависимо), UTF8
    std::vector<unsigned int> flags;
    for (int i = 0; i < 16; ++i) flags.push_back(HS_FLAG_DOTALL);
    flags.push_back(HS_FLAG_DOTALL | HS_FLAG_CASELESS | HS_FLAG_UTF8);
    flags.push_back(HS_FLAG_DOTALL | HS_FLAG_CASELESS | HS_FLAG_UTF8);
    flags.push_back(HS_FLAG_DOTALL | HS_FLAG_UTF8);
    flags.push_back(HS_FLAG_DOTALL | HS_FLAG_CASELESS | HS_FLAG_UTF8);

    hs_compile_error_t* err;
    if (hs_compile_multi(exprs, flags.data(), ids, 20, HS_MODE_BLOCK, nullptr, &db, &err) != HS_SUCCESS) {
        std::cerr << "[HsScanner] HS Error: " << err->message << std::endl;
        hs_free_compile_error(err);
    }
}

HsScanner::~HsScanner() {
    if (scratch) hs_free_scratch(scratch);
    if (db) hs_free_database(db);
}
void HsScanner::prepare() {
    if (db && !scratch) hs_alloc_scratch(db, &scratch);
}
std::string HsScanner::name() const { return "Hyperscan"; }

// Контекст для callback'а Hyperscan
struct HsContext {
    ScanStats* stats;
    unsigned long long last_offset[32] = { 0 };
};

void HsScanner::scan(const char* data, size_t size, ScanStats& stats) {
    if (!db || !scratch) return;

    HsContext ctx;
    ctx.stats = &stats;

    // Callback функция, вызываемая при совпадении
    auto on_match = [](unsigned int id, unsigned long long from, unsigned long long to, unsigned int flags, void* ptr) -> int {
        HsContext* c = static_cast<HsContext*>(ptr);

        // Защита от дребезга (Debounce):
        // Игнорируем совпадения того же типа на дистанции < 512 байт.
        if (id < 32) {
            unsigned long long last = c->last_offset[id];
            if (last != 0 && to < last + 512) {
                return 0;
            }
            c->last_offset[id] = to;
        }

        ScanStats* st = c->stats;
        switch (id) {
        case ID_DOC: st->doc++; break; case ID_XLS: st->xls++; break; case ID_PPT: st->ppt++; break;
        case ID_DOCX: st->docx++; break; case ID_XLSX: st->xlsx++; break; case ID_PPTX: st->pptx++; break;
        case ID_ZIP: st->zip++; break; case ID_PDF: st->pdf++; break; case ID_RAR: st->rar++; break;
        case ID_PNG: st->png++; break; case ID_JPG: st->jpg++; break; case ID_GIF: st->gif++; break;
        case ID_BMP: st->bmp++; break; case ID_MKV: st->mkv++; break; case ID_MP3: st->mp3++; break;
        case ID_HTML: st->html++; break; case ID_XML: st->xml++; break; case ID_JSON: st->json++; break;
        case ID_EML: st->eml++; break; default: st->unknown++; break;
        }
        return 0;
        };

    hs_scan(db, data, size, 0, scratch, on_match, &ctx);

    // Финальная коррекция категорий
    fix_counters(stats);
}
