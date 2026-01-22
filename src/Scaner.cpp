#include <re2/re2.h>
#include <hs/hs.h>
#include <string_view>
#include "Scaner.h"
#include "Signatures.h" 

// --- ScanStats ---
ScanStats& ScanStats::operator+=(const ScanStats& other) {
    pdf += other.pdf; doc += other.doc; xls += other.xls; ppt += other.ppt; ole += other.ole;
    docx += other.docx; xlsx += other.xlsx; pptx += other.pptx; zip += other.zip;
    rar += other.rar; png += other.png; jpg += other.jpg; gif += other.gif; bmp += other.bmp;
    mkv += other.mkv; mp3 += other.mp3;
    html += other.html; xml += other.xml; json += other.json; eml += other.eml;
    unknown += other.unknown;
    return *this;
}

void ScanStats::print(const std::string& name) const {
    std::cout << "===== " << name << " Results =====" << std::endl;
    std::cout << "PDF: " << pdf << " | ZIP: " << zip << " | RAR: " << rar << "\n";
    std::cout << "Office: " << (doc + xls + ppt) << " (OLE) | " << (docx + xlsx + pptx) << " (XML)\n";
    std::cout << "Images: " << (png + jpg + gif + bmp) << " | Media: " << (mkv + mp3) << "\n";
    std::cout << "Text: HTML=" << html << " XML=" << xml << " JSON=" << json << " EML=" << eml << "\n";
    std::cout << "========================================" << std::endl;
}

void compare_stats(const GenStats& gen, const ScanStats& scan, const std::string& name) {
    std::cout << "\n>>> Check: " << name << " <<<\n";
    std::cout << "Total Gen: " << gen.total_files << "\n";
}

// --- Helpers ---
inline bool has_sig(const char* data, size_t size, const std::string& signature) {
    if (signature.empty()) return true;
    std::string_view sv(data, size);
    return sv.find(signature) != std::string_view::npos;
}

// Regex Counters
template<typename SearchFunc>
int count_matches_std(const char* data, size_t size, const std::regex& re, SearchFunc searcher) {
    int count = 0;
    const char* start = data;
    const char* end = data + size;
    std::cmatch m;
    try {
        while (start < end && searcher(start, end, m, re)) {
            count++;
            auto shift = std::max((std::ptrdiff_t)1, m.length());
            start += m.position() + shift;
        }
    }
    catch (...) {}
    return count;
}

template<typename SearchFunc>
int count_matches_boost(const char* data, size_t size, const boost::regex& re, SearchFunc searcher) {
    int count = 0;
    const char* start = data;
    const char* end = data + size;
    boost::cmatch m;
    while (start < end && searcher(start, end, m, re)) {
        count++;
        auto shift = std::max((std::ptrdiff_t)1, m.length());
        start += m.position() + shift;
    }
    return count;
}

int count_re2(const char* data, size_t size, re2::RE2* re) {
    int count = 0;
    re2::StringPiece input(data, size);
    while (re2::RE2::FindAndConsume(&input, *re)) count++;
    return count;
}

// ==========================================
// StdScanner
// ==========================================
StdScanner::StdScanner() {
    auto f = std::regex::optimize;
    auto fi = std::regex::optimize | std::regex::icase;

    // OLE & XML
    r_doc.assign(Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_WORD), f);
    r_xls.assign(Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_XL), f);
    r_ppt.assign(Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_PPT), f);
    r_docx.assign(Sig::complex(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_WORD), f);
    r_xlsx.assign(Sig::complex(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_XL), f);
    r_pptx.assign(Sig::complex(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_PPT), f);

    // Framed (is_hs = false)
    r_zip.assign(Sig::framed(Sig::Bin::ZIP_HEAD, Sig::Bin::ZIP_TAIL, false), f);
    r_pdf.assign(Sig::framed(Sig::Bin::PDF_HEAD, Sig::Bin::PDF_TAIL, false), f);

    r_png.assign(Sig::framed(Sig::Bin::PNG_HEAD, Sig::Bin::PNG_TAIL, false), f);
    r_jpg.assign(Sig::framed(Sig::Bin::JPG_HEAD, Sig::Bin::JPG_TAIL, false), f);
    r_gif.assign(Sig::framed(Sig::Bin::GIF_HEAD, Sig::Bin::GIF_TAIL, false), f);

    r_html.assign(Sig::framed_text(Sig::Text::HTML_HEAD, Sig::Text::HTML_TAIL, false), fi);
    r_json.assign(Sig::framed_text(Sig::Text::JSON_HEAD, Sig::Text::JSON_TAIL, false), f);

    // Simple
    r_rar4.assign(Sig::raw_to_hex(Sig::Bin::RAR4), f);
    r_rar5.assign(Sig::raw_to_hex(Sig::Bin::RAR5), f);
    // BMP теперь Regex, а не Hex, т.к. там есть точки
    r_bmp.assign(Sig::Bin::BMP_HEAD, f);
    r_mkv.assign(Sig::raw_to_hex(Sig::Bin::MKV), f);
    r_mp3.assign(Sig::raw_to_hex(Sig::Bin::MP3), f);
    r_xml.assign(Sig::Text::XML, fi);
    r_eml.assign(Sig::Text::EML, fi);
}
std::string StdScanner::name() const { return "std::regex"; }

void StdScanner::scan(const char* d, size_t s, ScanStats& st) {
    auto searcher = [](const char* start, const char* end, std::cmatch& m, const std::regex& re) {
        return std::regex_search(start, end, m, re);
        };
    if (has_sig(d, s, Sig::Bin::OLE)) {
        st.doc += count_matches_std(d, s, r_doc, searcher);
        st.xls += count_matches_std(d, s, r_xls, searcher);
        st.ppt += count_matches_std(d, s, r_ppt, searcher);
    }
    if (has_sig(d, s, Sig::Bin::ZIP_HEAD)) {
        st.docx += count_matches_std(d, s, r_docx, searcher);
        st.xlsx += count_matches_std(d, s, r_xlsx, searcher);
        st.pptx += count_matches_std(d, s, r_pptx, searcher);
        st.zip += count_matches_std(d, s, r_zip, searcher);
    }
    if (has_sig(d, s, Sig::Bin::PDF_HEAD)) st.pdf += count_matches_std(d, s, r_pdf, searcher);
    if (has_sig(d, s, Sig::Bin::RAR4)) st.rar += count_matches_std(d, s, r_rar4, searcher);
    if (has_sig(d, s, Sig::Bin::RAR5)) st.rar += count_matches_std(d, s, r_rar5, searcher);

    if (has_sig(d, s, Sig::Bin::PNG_HEAD)) st.png += count_matches_std(d, s, r_png, searcher);
    if (has_sig(d, s, Sig::Bin::JPG_HEAD)) st.jpg += count_matches_std(d, s, r_jpg, searcher);
    if (has_sig(d, s, Sig::Bin::GIF_HEAD)) st.gif += count_matches_std(d, s, r_gif, searcher);
    // BMP без префильтра, т.к. сигнатура теперь сложнее (regex)
    st.bmp += count_matches_std(d, s, r_bmp, searcher);

    if (has_sig(d, s, Sig::Bin::MKV)) st.mkv += count_matches_std(d, s, r_mkv, searcher);
    if (has_sig(d, s, Sig::Bin::MP3)) st.mp3 += count_matches_std(d, s, r_mp3, searcher);

    st.html += count_matches_std(d, s, r_html, searcher);
    st.xml += count_matches_std(d, s, r_xml, searcher);
    st.json += count_matches_std(d, s, r_json, searcher);
    st.eml += count_matches_std(d, s, r_eml, searcher);
}

// ==========================================
// Re2Scanner
// ==========================================
Re2Scanner::Re2Scanner() {
    re2::RE2::Options ob;
    ob.set_encoding(re2::RE2::Options::EncodingLatin1);
    ob.set_log_errors(false);
    ob.set_dot_nl(true);
    // ВАЖНО: Увеличиваем лимит памяти до 64 МБ, иначе поиск с гэпом 4МБ может падать
    ob.set_max_mem(64 << 20);

    re2::RE2::Options ot = ob; ot.set_case_sensitive(false);

    r_doc = std::make_unique<re2::RE2>(Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_WORD), ob);
    r_xls = std::make_unique<re2::RE2>(Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_XL), ob);
    r_ppt = std::make_unique<re2::RE2>(Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_PPT), ob);
    r_docx = std::make_unique<re2::RE2>(Sig::complex(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_WORD), ob);
    r_xlsx = std::make_unique<re2::RE2>(Sig::complex(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_XL), ob);
    r_pptx = std::make_unique<re2::RE2>(Sig::complex(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_PPT), ob);

    // is_hs = false
    r_zip_gen = std::make_unique<re2::RE2>(Sig::framed(Sig::Bin::ZIP_HEAD, Sig::Bin::ZIP_TAIL, false), ob);
    r_pdf = std::make_unique<re2::RE2>(Sig::framed(Sig::Bin::PDF_HEAD, Sig::Bin::PDF_TAIL, false), ob);
    r_rar4 = std::make_unique<re2::RE2>(Sig::raw_to_hex(Sig::Bin::RAR4), ob);
    r_rar5 = std::make_unique<re2::RE2>(Sig::raw_to_hex(Sig::Bin::RAR5), ob);
    r_png = std::make_unique<re2::RE2>(Sig::framed(Sig::Bin::PNG_HEAD, Sig::Bin::PNG_TAIL, false), ob);
    r_jpg = std::make_unique<re2::RE2>(Sig::framed(Sig::Bin::JPG_HEAD, Sig::Bin::JPG_TAIL, false), ob);
    r_gif = std::make_unique<re2::RE2>(Sig::framed(Sig::Bin::GIF_HEAD, Sig::Bin::GIF_TAIL, false), ob);

    r_bmp = std::make_unique<re2::RE2>(Sig::Bin::BMP_HEAD, ob);
    r_mkv = std::make_unique<re2::RE2>(Sig::raw_to_hex(Sig::Bin::MKV), ob);
    r_mp3 = std::make_unique<re2::RE2>(Sig::raw_to_hex(Sig::Bin::MP3), ob);

    r_html = std::make_unique<re2::RE2>(Sig::framed_text(Sig::Text::HTML_HEAD, Sig::Text::HTML_TAIL, false), ot);
    r_xml = std::make_unique<re2::RE2>(Sig::Text::XML, ot);
    r_json = std::make_unique<re2::RE2>(Sig::framed_text(Sig::Text::JSON_HEAD, Sig::Text::JSON_TAIL, false), ob);
    r_eml = std::make_unique<re2::RE2>(Sig::Text::EML, ot);
}
Re2Scanner::~Re2Scanner() = default;
std::string Re2Scanner::name() const { return "Google RE2"; }

void Re2Scanner::scan(const char* d, size_t s, ScanStats& st) {
    if (has_sig(d, s, Sig::Bin::OLE)) {
        st.doc += count_re2(d, s, r_doc.get());
        st.xls += count_re2(d, s, r_xls.get());
        st.ppt += count_re2(d, s, r_ppt.get());
    }
    if (has_sig(d, s, Sig::Bin::ZIP_HEAD)) {
        st.docx += count_re2(d, s, r_docx.get());
        st.xlsx += count_re2(d, s, r_xlsx.get());
        st.pptx += count_re2(d, s, r_pptx.get());
        st.zip += count_re2(d, s, r_zip_gen.get());
    }
    if (has_sig(d, s, Sig::Bin::PDF_HEAD)) st.pdf += count_re2(d, s, r_pdf.get());
    if (has_sig(d, s, Sig::Bin::RAR4)) st.rar += count_re2(d, s, r_rar4.get());
    if (has_sig(d, s, Sig::Bin::RAR5)) st.rar += count_re2(d, s, r_rar5.get());

    if (has_sig(d, s, Sig::Bin::PNG_HEAD)) st.png += count_re2(d, s, r_png.get());
    if (has_sig(d, s, Sig::Bin::JPG_HEAD)) st.jpg += count_re2(d, s, r_jpg.get());
    if (has_sig(d, s, Sig::Bin::GIF_HEAD)) st.gif += count_re2(d, s, r_gif.get());

    st.bmp += count_re2(d, s, r_bmp.get());
    if (has_sig(d, s, Sig::Bin::MKV)) st.mkv += count_re2(d, s, r_mkv.get());
    if (has_sig(d, s, Sig::Bin::MP3)) st.mp3 += count_re2(d, s, r_mp3.get());

    st.html += count_re2(d, s, r_html.get());
    st.xml += count_re2(d, s, r_xml.get());
    st.json += count_re2(d, s, r_json.get());
    st.eml += count_re2(d, s, r_eml.get());
}

// ==========================================
// BoostScanner
// ==========================================
BoostScanner::BoostScanner() {
    auto flags_bin = boost::regex::perl;
    auto flags_text = boost::regex::perl | boost::regex::icase;

    r_doc.assign(Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_WORD), flags_bin);
    r_xls.assign(Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_XL), flags_bin);
    r_ppt.assign(Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_PPT), flags_bin);
    r_docx.assign(Sig::complex(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_WORD), flags_bin);
    r_xlsx.assign(Sig::complex(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_XL), flags_bin);
    r_pptx.assign(Sig::complex(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_PPT), flags_bin);

    // is_hs = false
    r_zip_gen.assign(Sig::framed(Sig::Bin::ZIP_HEAD, Sig::Bin::ZIP_TAIL, false), flags_bin);
    r_pdf.assign(Sig::framed(Sig::Bin::PDF_HEAD, Sig::Bin::PDF_TAIL, false), flags_bin);
    r_rar4.assign(Sig::raw_to_hex(Sig::Bin::RAR4), flags_bin);
    r_rar5.assign(Sig::raw_to_hex(Sig::Bin::RAR5), flags_bin);

    r_png.assign(Sig::framed(Sig::Bin::PNG_HEAD, Sig::Bin::PNG_TAIL, false), flags_bin);
    r_jpg.assign(Sig::framed(Sig::Bin::JPG_HEAD, Sig::Bin::JPG_TAIL, false), flags_bin);
    r_gif.assign(Sig::framed(Sig::Bin::GIF_HEAD, Sig::Bin::GIF_TAIL, false), flags_bin);

    r_bmp.assign(Sig::Bin::BMP_HEAD, flags_bin);
    r_mkv.assign(Sig::raw_to_hex(Sig::Bin::MKV), flags_bin);
    r_mp3.assign(Sig::raw_to_hex(Sig::Bin::MP3), flags_bin);

    r_html.assign(Sig::framed_text(Sig::Text::HTML_HEAD, Sig::Text::HTML_TAIL, false), flags_text);
    r_xml.assign(Sig::Text::XML, flags_text);
    r_json.assign(Sig::framed_text(Sig::Text::JSON_HEAD, Sig::Text::JSON_TAIL, false), flags_bin);
    r_eml.assign(Sig::Text::EML, flags_text);
}
std::string BoostScanner::name() const { return "Boost.Regex"; }

void BoostScanner::scan(const char* d, size_t s, ScanStats& st) {
    auto searcher = [](const char* start, const char* end, boost::cmatch& m, const boost::regex& re) {
        return boost::regex_search(start, end, m, re);
        };
    if (has_sig(d, s, Sig::Bin::OLE)) {
        st.doc += count_matches_boost(d, s, r_doc, searcher);
        st.xls += count_matches_boost(d, s, r_xls, searcher);
        st.ppt += count_matches_boost(d, s, r_ppt, searcher);
    }
    if (has_sig(d, s, Sig::Bin::ZIP_HEAD)) {
        st.docx += count_matches_boost(d, s, r_docx, searcher);
        st.xlsx += count_matches_boost(d, s, r_xlsx, searcher);
        st.pptx += count_matches_boost(d, s, r_pptx, searcher);
        st.zip += count_matches_boost(d, s, r_zip_gen, searcher);
    }
    if (has_sig(d, s, Sig::Bin::PDF_HEAD)) st.pdf += count_matches_boost(d, s, r_pdf, searcher);
    if (has_sig(d, s, Sig::Bin::RAR4)) st.rar += count_matches_boost(d, s, r_rar4, searcher);
    if (has_sig(d, s, Sig::Bin::RAR5)) st.rar += count_matches_boost(d, s, r_rar5, searcher);

    if (has_sig(d, s, Sig::Bin::PNG_HEAD)) st.png += count_matches_boost(d, s, r_png, searcher);
    if (has_sig(d, s, Sig::Bin::JPG_HEAD)) st.jpg += count_matches_boost(d, s, r_jpg, searcher);
    if (has_sig(d, s, Sig::Bin::GIF_HEAD)) st.gif += count_matches_boost(d, s, r_gif, searcher);

    st.bmp += count_matches_boost(d, s, r_bmp, searcher);
    if (has_sig(d, s, Sig::Bin::MKV)) st.mkv += count_matches_boost(d, s, r_mkv, searcher);
    if (has_sig(d, s, Sig::Bin::MP3)) st.mp3 += count_matches_boost(d, s, r_mp3, searcher);

    st.html += count_matches_boost(d, s, r_html, searcher);
    st.xml += count_matches_boost(d, s, r_xml, searcher);
    st.json += count_matches_boost(d, s, r_json, searcher);
    st.eml += count_matches_boost(d, s, r_eml, searcher);
}

// ==========================================
// HsScanner
// ==========================================
HsScanner::HsScanner() {
    std::string p_doc = Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_WORD);
    std::string p_xls = Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_XL);
    std::string p_ppt = Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_PPT);
    std::string p_docx = Sig::complex(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_WORD);
    std::string p_xlsx = Sig::complex(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_XL);
    std::string p_pptx = Sig::complex(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_PPT);

    // is_hs = true (чистый regex)
    std::string p_zip = Sig::framed(Sig::Bin::ZIP_HEAD, Sig::Bin::ZIP_TAIL, true);
    std::string p_pdf = Sig::framed(Sig::Bin::PDF_HEAD, Sig::Bin::PDF_TAIL, true);
    std::string p_rar4 = Sig::raw_to_hex(Sig::Bin::RAR4);
    std::string p_rar5 = Sig::raw_to_hex(Sig::Bin::RAR5);

    std::string p_png = Sig::framed(Sig::Bin::PNG_HEAD, Sig::Bin::PNG_TAIL, true);
    std::string p_jpg = Sig::framed(Sig::Bin::JPG_HEAD, Sig::Bin::JPG_TAIL, true);
    std::string p_gif = Sig::framed(Sig::Bin::GIF_HEAD, Sig::Bin::GIF_TAIL, true);

    std::string p_bmp = Sig::Bin::BMP_HEAD;
    std::string p_mkv = Sig::raw_to_hex(Sig::Bin::MKV);
    std::string p_mp3 = Sig::raw_to_hex(Sig::Bin::MP3);

    std::string p_html = Sig::framed_text(Sig::Text::HTML_HEAD, Sig::Text::HTML_TAIL, true);
    std::string p_xml = Sig::Text::XML;
    std::string p_json = Sig::framed_text(Sig::Text::JSON_HEAD, Sig::Text::JSON_TAIL, true);
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

    std::vector<unsigned int> flags;
    for (int i = 0; i < 16; ++i) flags.push_back(HS_FLAG_DOTALL);
    flags.push_back(HS_FLAG_DOTALL | HS_FLAG_CASELESS | HS_FLAG_UTF8);
    flags.push_back(HS_FLAG_DOTALL | HS_FLAG_CASELESS | HS_FLAG_UTF8);
    flags.push_back(HS_FLAG_DOTALL | HS_FLAG_UTF8);
    flags.push_back(HS_FLAG_DOTALL | HS_FLAG_CASELESS | HS_FLAG_UTF8);

    hs_compile_error_t* err;
    if (hs_compile_multi(exprs, flags.data(), ids, 20, HS_MODE_BLOCK, nullptr, &db, &err) != HS_SUCCESS) {
        std::cerr << "HS Error: " << err->message << std::endl;
        hs_free_compile_error(err);
    }
}
HsScanner::~HsScanner() { if (scratch) hs_free_scratch(scratch); if (db) hs_free_database(db); }
void HsScanner::prepare() { if (db && !scratch) hs_alloc_scratch(db, &scratch); }
std::string HsScanner::name() const { return "Hyperscan"; }

void HsScanner::scan(const char* data, size_t size, ScanStats& stats) {
    if (!db || !scratch) return;
    auto on_match = [](unsigned int id, unsigned long long from, unsigned long long to, unsigned int flags, void* ctx) -> int {
        ScanStats* st = static_cast<ScanStats*>(ctx);
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
    hs_scan(db, data, size, 0, scratch, on_match, &stats);
}