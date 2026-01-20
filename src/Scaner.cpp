#include <re2/re2.h>
#include <hs/hs.h>

#include "Scaner.h"
#include "Signatures.h" 

ScanStats& ScanStats::operator+=(const ScanStats& other) {
    pdf += other.pdf;
    doc += other.doc; 
    xls += other.xls; 
    ppt += other.ppt; 
    ole += other.ole;
    docx += other.docx; 
    xlsx += other.xlsx; 
    pptx += other.pptx; 
    zip += other.zip;
    rar += other.rar;
    png += other.png; 
    jpg += other.jpg; 
    gif += other.gif; 
    bmp += other.bmp; 
    mkv += other.mkv; 
    mp3 += other.mp3;
    html += other.html; 
    xml += other.xml; 
    json += other.json; 
    eml += other.eml;
    unknown += other.unknown;

    return *this;
}

void ScanStats::print(const std::string& engine_name) const {
    std::cout << "===== " << engine_name << " Results =====" << std::endl;
    std::cout << "[Docs (Old)]\n"
        << "  DOC: " << doc << " | XLS: " << xls << " | PPT: " << ppt
        << " | Generic OLE: " << ole << "\n";
    std::cout << "[Docs (OpenXML)]\n"
        << "  DOCX: " << docx << " | XLSX: " << xlsx << " | PPTX: " << pptx << "\n";
    std::cout << "[Archives]\n"
        << " ZIP: " << zip << " | PDF: " << pdf << " | RAR: " << rar << "\n";
    std::cout << "[Media]\n"
        << "  PNG: " << png << " | JPG: " << jpg << " | GIF: " << gif
        << " | BMP: " << bmp << " | MKV: " << mkv << " | MP3: " << mp3 << "\n";
    std::cout << "[Text]\n"
        << "  HTML: " << html << " | XML: " << xml
        << " | JSON: " << json << " | EML: " << eml << "\n";
    std::cout << "[Other]\n  Unknown: " << unknown << std::endl;
    std::cout << "========================================" << std::endl;
}


void compare_stats(const GenStats& gen, const ScanStats& scan, const std::string& engine_name) {
    std::cout << "\n>>> COMPARISON REPORT (" << engine_name << ") <<<\n";

    auto check = [](const std::string& label, int expected, int actual) {
        std::cout << std::left << std::setw(20) << label
            << " Generated: " << std::setw(5) << expected
            << " Found: " << std::setw(5) << actual;
        if (expected == actual) std::cout << " [OK]";
        else std::cout << " [MISMATCH] (" << (actual - expected) << ")";
        std::cout << std::endl;
        };

    check("PDF", gen.pdf, scan.pdf);

    int scan_ole_total = scan.doc + scan.xls + scan.ppt + scan.ole;
    check("Old Office (OLE)", gen.office_ole, scan_ole_total);

    int scan_xml_total = scan.docx + scan.xlsx + scan.pptx;
    check("New Office (XML)", gen.office_xml, scan_xml_total);

    check("Pure ZIP", gen.zip, scan.zip);
    check("RAR", gen.rar, scan.rar);

    check("PNG", gen.png, scan.png);
    check("JPG", gen.jpg, scan.jpg);
    check("GIF", gen.gif, scan.gif);
    check("BMP", gen.bmp, scan.bmp);
    check("MKV", gen.mkv, scan.mkv);
    check("MP3", gen.mp3, scan.mp3);

    check("HTML", gen.html, scan.html);
    check("XML", gen.xml, scan.xml);
    check("JSON", gen.json, scan.json);
    check("EML", gen.eml, scan.eml);

    std::cout << "--------------------------------------------------\n";
    std::cout << "Total Generated: " << gen.total_files << "\n";
    std::cout << "Total Unknown (scanned): " << scan.unknown << " (Expected ~" << gen.txt << " txt files)\n";
    std::cout << "==================================================\n";
}

// ==========================================
// StdScanner
// ==========================================

StdScanner::StdScanner() {
    auto f = std::regex::optimize;
    auto fi = std::regex::optimize | std::regex::icase;

    r_doc.assign(Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_WORD), f);
    r_xls.assign(Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_XL), f);
    r_ppt.assign(Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_PPT), f);

    r_docx.assign(Sig::complex(Sig::Bin::ZIP, Sig::Bin::XML_WORD), f);
    r_xlsx.assign(Sig::complex(Sig::Bin::ZIP, Sig::Bin::XML_XL), f);
    r_pptx.assign(Sig::complex(Sig::Bin::ZIP, Sig::Bin::XML_PPT), f);

    r_pdf.assign("^" + Sig::raw_to_hex(Sig::Bin::PDF), f);
    r_zip.assign("^" + Sig::raw_to_hex(Sig::Bin::ZIP), f);
    r_rar4.assign("^" + Sig::raw_to_hex(Sig::Bin::RAR4), f);
    r_rar5.assign("^" + Sig::raw_to_hex(Sig::Bin::RAR5), f);

    r_png.assign("^" + Sig::raw_to_hex(Sig::Bin::PNG), f);
    r_jpg.assign("^" + Sig::raw_to_hex(Sig::Bin::JPG), f);
    r_gif.assign("^" + Sig::raw_to_hex(Sig::Bin::GIF), f);
    r_bmp.assign("^" + Sig::raw_to_hex(Sig::Bin::BMP), f);
    r_mkv.assign("^" + Sig::raw_to_hex(Sig::Bin::MKV), f);
    r_mp3.assign("^" + Sig::raw_to_hex(Sig::Bin::MP3), f);

    r_html.assign("^" + Sig::raw_to_hex(Sig::Text::HTML), fi);
    r_xml.assign("^" + Sig::raw_to_hex(Sig::Text::XML), fi);
    r_json.assign("^" + Sig::raw_to_hex(Sig::Text::JSON), f);
    r_eml.assign("^" + Sig::raw_to_hex(Sig::Text::EML), fi);
}

std::string StdScanner::name() const { return "std::regex"; }

void StdScanner::scan(const char* d, size_t s, ScanStats& st) {
    std::cmatch m; auto end = d + s;
    // std::regex_search может быть медленным для бинарных данных, но такова реализация
    if (std::regex_search(d, end, m, r_doc))  st.doc++;
    else if (std::regex_search(d, end, m, r_xls))  st.xls++;
    else if (std::regex_search(d, end, m, r_ppt))  st.ppt++;

    else if (std::regex_search(d, end, m, r_docx)) st.docx++;
    else if (std::regex_search(d, end, m, r_xlsx)) st.xlsx++;
    else if (std::regex_search(d, end, m, r_pptx)) st.pptx++;

    else if (std::regex_search(d, end, m, r_zip)) st.zip++;
    else if (std::regex_search(d, end, m, r_pdf)) st.pdf++;
    else if (std::regex_search(d, end, m, r_rar4) || std::regex_search(d, end, m, r_rar5)) st.rar++;
    else if (std::regex_search(d, end, m, r_png)) st.png++;
    else if (std::regex_search(d, end, m, r_jpg)) st.jpg++;
    else if (std::regex_search(d, end, m, r_gif)) st.gif++;
    else if (std::regex_search(d, end, m, r_bmp)) st.bmp++;
    else if (std::regex_search(d, end, m, r_mkv)) st.mkv++;
    else if (std::regex_search(d, end, m, r_mp3)) st.mp3++;
    else if (std::regex_search(d, end, m, r_html)) st.html++;
    else if (std::regex_search(d, end, m, r_xml)) st.xml++;
    else if (std::regex_search(d, end, m, r_json)) st.json++;
    else if (std::regex_search(d, end, m, r_eml)) st.eml++;
    else st.unknown++;
}

// ==========================================
// Re2Scanner
// ==========================================

Re2Scanner::Re2Scanner() {
    re2::RE2::Options ob;
    ob.set_encoding(re2::RE2::Options::EncodingLatin1);
    ob.set_log_errors(false);
    ob.set_dot_nl(true);

    re2::RE2::Options ot = ob;
    ot.set_case_sensitive(false);

    // Используем std::make_unique для создания объектов RE2 в куче
    r_doc = std::make_unique<re2::RE2>("^" + Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_WORD), ob);
    r_xls = std::make_unique<re2::RE2>("^" + Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_XL), ob);
    r_ppt = std::make_unique<re2::RE2>("^" + Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_PPT), ob);
    r_ole_gen = std::make_unique<re2::RE2>("^" + Sig::raw_to_hex(Sig::Bin::OLE), ob);

    r_docx = std::make_unique<re2::RE2>("^" + Sig::complex(Sig::Bin::ZIP, Sig::Bin::XML_WORD), ob);
    r_xlsx = std::make_unique<re2::RE2>("^" + Sig::complex(Sig::Bin::ZIP, Sig::Bin::XML_XL), ob);
    r_pptx = std::make_unique<re2::RE2>("^" + Sig::complex(Sig::Bin::ZIP, Sig::Bin::XML_PPT), ob);
    r_zip_gen = std::make_unique<re2::RE2>("^" + Sig::raw_to_hex(Sig::Bin::ZIP), ob);

    r_pdf = std::make_unique<re2::RE2>("^" + Sig::raw_to_hex(Sig::Bin::PDF), ob);
    r_rar4 = std::make_unique<re2::RE2>("^" + Sig::raw_to_hex(Sig::Bin::RAR4), ob);
    r_rar5 = std::make_unique<re2::RE2>("^" + Sig::raw_to_hex(Sig::Bin::RAR5), ob);

    r_png = std::make_unique<re2::RE2>("^" + Sig::raw_to_hex(Sig::Bin::PNG), ob);
    r_jpg = std::make_unique<re2::RE2>("^" + Sig::raw_to_hex(Sig::Bin::JPG), ob);
    r_gif = std::make_unique<re2::RE2>("^" + Sig::raw_to_hex(Sig::Bin::GIF), ob);
    r_bmp = std::make_unique<re2::RE2>("^" + Sig::raw_to_hex(Sig::Bin::BMP), ob);
    r_mkv = std::make_unique<re2::RE2>("^" + Sig::raw_to_hex(Sig::Bin::MKV), ob);
    r_mp3 = std::make_unique<re2::RE2>("^" + Sig::raw_to_hex(Sig::Bin::MP3), ob);

    r_html = std::make_unique<re2::RE2>("^" + Sig::Text::HTML, ot);
    r_xml = std::make_unique<re2::RE2>("^" + Sig::Text::XML, ot);
    r_json = std::make_unique<re2::RE2>("^" + Sig::Text::JSON, ob);
    r_eml = std::make_unique<re2::RE2>("^" + Sig::Text::EML, ot);
}


Re2Scanner::~Re2Scanner() = default;

std::string Re2Scanner::name() const { return "Google RE2"; }

void Re2Scanner::scan(const char* d, size_t s, ScanStats& st) {
    re2::StringPiece p(d, s);
    // Используем *r_ptr для разыменования unique_ptr
    if (re2::RE2::PartialMatch(p, *r_doc)) st.doc++;
    else if (re2::RE2::PartialMatch(p, *r_xls)) st.xls++;
    else if (re2::RE2::PartialMatch(p, *r_ppt)) st.ppt++;
    else if (re2::RE2::PartialMatch(p, *r_ole_gen)) st.ole++;

    else if (re2::RE2::PartialMatch(p, *r_docx)) st.docx++;
    else if (re2::RE2::PartialMatch(p, *r_xlsx)) st.xlsx++;
    else if (re2::RE2::PartialMatch(p, *r_pptx)) st.pptx++;
    else if (re2::RE2::PartialMatch(p, *r_zip_gen)) st.zip++;

    else if (re2::RE2::PartialMatch(p, *r_pdf)) st.pdf++;
    else if (re2::RE2::PartialMatch(p, *r_rar4) || re2::RE2::PartialMatch(p, *r_rar5)) st.rar++;
    else if (re2::RE2::PartialMatch(p, *r_png)) st.png++;
    else if (re2::RE2::PartialMatch(p, *r_jpg)) st.jpg++;
    else if (re2::RE2::PartialMatch(p, *r_gif)) st.gif++;
    else if (re2::RE2::PartialMatch(p, *r_bmp)) st.bmp++;
    else if (re2::RE2::PartialMatch(p, *r_mkv)) st.mkv++;
    else if (re2::RE2::PartialMatch(p, *r_mp3)) st.mp3++;
    else if (re2::RE2::PartialMatch(p, *r_html)) st.html++;
    else if (re2::RE2::PartialMatch(p, *r_xml)) st.xml++;
    else if (re2::RE2::PartialMatch(p, *r_json)) st.json++;
    else if (re2::RE2::PartialMatch(p, *r_eml)) st.eml++;
    else st.unknown++;
}

// ==========================================
// BoostScanner
// ==========================================

BoostScanner::BoostScanner() {
    auto flags_bin = boost::regex::perl;
    auto flags_text = boost::regex::perl | boost::regex::icase;

    r_doc.assign("\\A" + Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_WORD), flags_bin);
    r_xls.assign("\\A" + Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_XL), flags_bin);
    r_ppt.assign("\\A" + Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_PPT), flags_bin);
    r_ole_gen.assign("\\A" + Sig::raw_to_hex(Sig::Bin::OLE), flags_bin);

    r_docx.assign("\\A" + Sig::complex(Sig::Bin::ZIP, Sig::Bin::XML_WORD), flags_bin);
    r_xlsx.assign("\\A" + Sig::complex(Sig::Bin::ZIP, Sig::Bin::XML_XL), flags_bin);
    r_pptx.assign("\\A" + Sig::complex(Sig::Bin::ZIP, Sig::Bin::XML_PPT), flags_bin);
    r_zip_gen.assign("\\A" + Sig::raw_to_hex(Sig::Bin::ZIP), flags_bin);

    r_pdf.assign("\\A" + Sig::raw_to_hex(Sig::Bin::PDF), flags_bin);
    r_rar4.assign("\\A" + Sig::raw_to_hex(Sig::Bin::RAR4), flags_bin);
    r_rar5.assign("\\A" + Sig::raw_to_hex(Sig::Bin::RAR5), flags_bin);

    r_png.assign("\\A" + Sig::raw_to_hex(Sig::Bin::PNG), flags_bin);
    r_jpg.assign("\\A" + Sig::raw_to_hex(Sig::Bin::JPG), flags_bin);
    r_gif.assign("\\A" + Sig::raw_to_hex(Sig::Bin::GIF), flags_bin);
    r_bmp.assign("\\A" + Sig::raw_to_hex(Sig::Bin::BMP), flags_bin);
    r_mkv.assign("\\A" + Sig::raw_to_hex(Sig::Bin::MKV), flags_bin);
    r_mp3.assign("\\A" + Sig::raw_to_hex(Sig::Bin::MP3), flags_bin);

    r_html.assign("\\A" + Sig::Text::HTML, flags_text);
    r_xml.assign("\\A" + Sig::Text::XML, flags_text);
    r_json.assign("\\A" + Sig::Text::JSON, flags_bin);
    r_eml.assign("\\A" + Sig::Text::EML, flags_text);
}

std::string BoostScanner::name() const { return "Boost.Regex"; }

void BoostScanner::scan(const char* d, size_t s, ScanStats& st) {
    // Boost regex_search принимает итераторы
    if (boost::regex_search(d, d + s, r_doc)) st.doc++;
    else if (boost::regex_search(d, d + s, r_xls)) st.xls++;
    else if (boost::regex_search(d, d + s, r_ppt)) st.ppt++;
    else if (boost::regex_search(d, d + s, r_ole_gen)) st.ole++;

    else if (boost::regex_search(d, d + s, r_docx)) st.docx++;
    else if (boost::regex_search(d, d + s, r_xlsx)) st.xlsx++;
    else if (boost::regex_search(d, d + s, r_pptx)) st.pptx++;
    else if (boost::regex_search(d, d + s, r_zip_gen)) st.zip++;

    else if (boost::regex_search(d, d + s, r_pdf)) st.pdf++;
    else if (boost::regex_search(d, d + s, r_rar4) || boost::regex_search(d, d + s, r_rar5)) st.rar++;
    else if (boost::regex_search(d, d + s, r_png)) st.png++;
    else if (boost::regex_search(d, d + s, r_jpg)) st.jpg++;
    else if (boost::regex_search(d, d + s, r_gif)) st.gif++;
    else if (boost::regex_search(d, d + s, r_bmp)) st.bmp++;
    else if (boost::regex_search(d, d + s, r_mkv)) st.mkv++;
    else if (boost::regex_search(d, d + s, r_mp3)) st.mp3++;
    else if (boost::regex_search(d, d + s, r_html)) st.html++;
    else if (boost::regex_search(d, d + s, r_xml)) st.xml++;
    else if (boost::regex_search(d, d + s, r_json)) st.json++;
    else if (boost::regex_search(d, d + s, r_eml)) st.eml++;
    else st.unknown++;
}

// ==========================================
// HsScanner (Hyperscan)
// ==========================================

HsScanner::HsScanner() {
    // Подготовка паттернов
    std::string p_doc = "^" + Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_WORD);
    std::string p_xls = "^" + Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_XL);
    std::string p_ppt = "^" + Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_PPT);
    std::string p_ole = "^" + Sig::raw_to_hex(Sig::Bin::OLE);

    std::string p_docx = "^" + Sig::complex(Sig::Bin::ZIP, Sig::Bin::XML_WORD);
    std::string p_xlsx = "^" + Sig::complex(Sig::Bin::ZIP, Sig::Bin::XML_XL);
    std::string p_pptx = "^" + Sig::complex(Sig::Bin::ZIP, Sig::Bin::XML_PPT);
    std::string p_zip = "^" + Sig::raw_to_hex(Sig::Bin::ZIP);

    std::string p_pdf = "^" + Sig::raw_to_hex(Sig::Bin::PDF);
    std::string p_rar4 = "^" + Sig::raw_to_hex(Sig::Bin::RAR4);
    std::string p_rar5 = "^" + Sig::raw_to_hex(Sig::Bin::RAR5);

    std::string p_png = "^" + Sig::raw_to_hex(Sig::Bin::PNG);
    std::string p_jpg = "^" + Sig::raw_to_hex(Sig::Bin::JPG);
    std::string p_gif = "^" + Sig::raw_to_hex(Sig::Bin::GIF);
    std::string p_bmp = "^" + Sig::raw_to_hex(Sig::Bin::BMP);
    std::string p_mkv = "^" + Sig::raw_to_hex(Sig::Bin::MKV);
    std::string p_mp3 = "^" + Sig::raw_to_hex(Sig::Bin::MP3);

    std::string p_html = "^" + Sig::Text::HTML;
    std::string p_xml = "^" + Sig::Text::XML;
    std::string p_json = "^" + Sig::Text::JSON;
    std::string p_eml = "^" + Sig::Text::EML;

    const char* exprs[] = {
        p_doc.c_str(), p_xls.c_str(), p_ppt.c_str(), p_ole.c_str(),
        p_docx.c_str(), p_xlsx.c_str(), p_pptx.c_str(), p_zip.c_str(),
        p_pdf.c_str(), p_rar4.c_str(), p_rar5.c_str(),
        p_png.c_str(), p_jpg.c_str(), p_gif.c_str(), p_bmp.c_str(), p_mkv.c_str(), p_mp3.c_str(),
        p_html.c_str(), p_xml.c_str(), p_json.c_str(), p_eml.c_str()
    };

    unsigned int ids[] = {
        ID_DOC, ID_XLS, ID_PPT, ID_OLE,
        ID_DOCX, ID_XLSX, ID_PPTX, ID_ZIP,
        ID_PDF, ID_RAR, ID_RAR,
        ID_PNG, ID_JPG, ID_GIF, ID_BMP, ID_MKV, ID_MP3,
        ID_HTML, ID_XML, ID_JSON, ID_EML
    };

    std::vector<unsigned int> flags;

    for (int i = 0; i < 17; ++i) flags.push_back(HS_FLAG_DOTALL); // Бинарные
    flags.push_back(HS_FLAG_DOTALL | HS_FLAG_CASELESS | HS_FLAG_UTF8); // HTML
    flags.push_back(HS_FLAG_DOTALL | HS_FLAG_CASELESS | HS_FLAG_UTF8); // XML
    flags.push_back(HS_FLAG_DOTALL | HS_FLAG_UTF8);                    // JSON
    flags.push_back(HS_FLAG_DOTALL | HS_FLAG_CASELESS | HS_FLAG_UTF8); // EML

    hs_compile_error_t* err;
    if (hs_compile_multi(exprs, flags.data(), ids, 21, HS_MODE_BLOCK, nullptr, &db, &err) != HS_SUCCESS) {
        std::cerr << "HS Error: " << err->message << std::endl;
        hs_free_compile_error(err);
    }
}

HsScanner::~HsScanner() {
    // Важно освободить ресурсы C-библиотеки
    if (scratch) hs_free_scratch(scratch);
    if (db) hs_free_database(db);
}

void HsScanner::prepare() {
    if (db && !scratch) {
        hs_alloc_scratch(db, &scratch); // выделяем память для сканирования один раз
    }
}

std::string HsScanner::name() const { return "Hyperscan"; }

void HsScanner::scan(const char* data, size_t size, ScanStats& stats) {
    if (!db || !scratch) return;

    int best_id = 0;

    // Лямбда для обратного вызова Hyperscan
    auto on_match = [](unsigned int id, unsigned long long, unsigned long long, unsigned int, void* ctx) -> int {
        int* current = static_cast<int*>(ctx);
        // Приоритезация: если нашли специфичный формат (например, DOCX), перезаписываем общий (ZIP)
        bool is_specific = (id == ID_DOC || id == ID_XLS || id == ID_PPT ||
            id == ID_DOCX || id == ID_XLSX || id == ID_PPTX);

        if (*current == 0) *current = id;
        else if (is_specific) *current = id;

        return 0; // 0 - продолжить поиск
        };

    hs_scan(db, data, size, 0, scratch, on_match, &best_id);

    switch (best_id) {
        case ID_DOC: stats.doc++; break;
        case ID_XLS: stats.xls++; break;
        case ID_PPT: stats.ppt++; break;
        case ID_OLE: stats.ole++; break;

        case ID_DOCX: stats.docx++; break;
        case ID_XLSX: stats.xlsx++; break;
        case ID_PPTX: stats.pptx++; break;
        case ID_ZIP: stats.zip++; break;

        case ID_PDF:  stats.pdf++; break;
        case ID_RAR:  stats.rar++; break;
        case ID_PNG:  stats.png++; break;
        case ID_JPG:  stats.jpg++; break;
        case ID_GIF:  stats.gif++; break;
        case ID_BMP:  stats.bmp++; break;
        case ID_MKV:  stats.mkv++; break;
        case ID_MP3:  stats.mp3++; break;
        case ID_HTML: stats.html++; break;
        case ID_XML:  stats.xml++; break;
        case ID_JSON: stats.json++; break;
        case ID_EML:  stats.eml++; break;
        default:      stats.unknown++; break;
    }
}