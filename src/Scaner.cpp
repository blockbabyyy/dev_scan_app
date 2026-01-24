#include <re2/re2.h>
#include <hs/hs.h>
#include <string_view>
#include <iostream>
#include <exception>
#include <algorithm> 

#include "Scaner.h"
#include "Signatures.h" 

// ... (ScanStats и Helpers без изменений) ...
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
inline bool has_sig(const char* data, size_t size, const std::string& signature) {
    if (signature.empty()) return true;
    std::string_view sv(data, size);
    return sv.find(signature) != std::string_view::npos;
}

template<typename SearchFunc>
int count_matches_std(const char* data, size_t size, const std::regex& re, SearchFunc searcher) {
    int count = 0;
    const char* start = data;
    const char* end = data + size;
    std::cmatch m;
    try {
        if (re.mark_count() == 0 && std::string(start, std::min((size_t)1, size)).empty()) return 0;
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
    try {
        if (re.empty()) return 0;
        while (start < end && searcher(start, end, m, re)) {
            count++;
            auto shift = std::max((std::ptrdiff_t)1, m.length());
            start += m.position() + shift;
        }
    }
    catch (...) {}
    return count;
}
int count_re2(const char* data, size_t size, re2::RE2* re) {
    if (!re || !re->ok()) return 0;
    int count = 0;
    re2::StringPiece input(data, size);
    while (re2::RE2::FindAndConsume(&input, *re)) count++;
    return count;
}

inline bool pre_check(const char* data, size_t size, const std::string& head, const std::string& tail = "") {
    if (head.empty()) return true;
    std::string_view sv(data, size);
    size_t head_pos = sv.find(head);
    if (head_pos == std::string_view::npos) return false;
    if (!tail.empty()) {
        if (sv.find(tail, head_pos + 1) == std::string_view::npos) return false;
    }
    return true;
}

// ==========================================
// StdScanner
// ==========================================
StdScanner::StdScanner() {
    auto f = std::regex::optimize;
    auto fi = std::regex::optimize | std::regex::icase;
    auto safe_compile = [&](std::regex& target, const std::string& pat, auto flags, const char* name) {
        try { target.assign(pat, flags); }
        catch (const std::regex_error& e) { std::cerr << "[StdScanner] Error compiling " << name << ": " << e.what() << "\n"; }
        };

    // [FIX] Используем Engine::STD
    safe_compile(r_doc, Sig::complex<Sig::Engine::STD>(Sig::Bin::OLE, Sig::Bin::OLE_WORD), f, "DOC");
    safe_compile(r_xls, Sig::complex<Sig::Engine::STD>(Sig::Bin::OLE, Sig::Bin::OLE_XL), f, "XLS");
    safe_compile(r_ppt, Sig::complex<Sig::Engine::STD>(Sig::Bin::OLE, Sig::Bin::OLE_PPT), f, "PPT");

    safe_compile(r_docx, Sig::complex<Sig::Engine::STD>(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_WORD), f, "DOCX");
    safe_compile(r_xlsx, Sig::complex<Sig::Engine::STD>(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_XL), f, "XLSX");
    safe_compile(r_pptx, Sig::complex<Sig::Engine::STD>(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_PPT), f, "PPTX");

    safe_compile(r_zip, Sig::framed<Sig::Engine::STD>(Sig::Bin::ZIP_HEAD, Sig::Bin::ZIP_TAIL), f, "ZIP");
    safe_compile(r_pdf, Sig::framed<Sig::Engine::STD>(Sig::Bin::PDF_HEAD, Sig::Bin::PDF_TAIL), f, "PDF");
    safe_compile(r_png, Sig::framed<Sig::Engine::STD>(Sig::Bin::PNG_HEAD, Sig::Bin::PNG_TAIL), f, "PNG");
    safe_compile(r_jpg, Sig::framed<Sig::Engine::STD>(Sig::Bin::JPG_HEAD, Sig::Bin::JPG_TAIL), f, "JPG");
    safe_compile(r_gif, Sig::framed<Sig::Engine::STD>(Sig::Bin::GIF_HEAD, Sig::Bin::GIF_TAIL), f, "GIF");

    safe_compile(r_html, Sig::framed_text<Sig::Engine::STD>(Sig::Text::HTML_HEAD, Sig::Text::HTML_TAIL), fi, "HTML");
    safe_compile(r_json, Sig::framed_text<Sig::Engine::STD>(Sig::Text::JSON_HEAD, Sig::Text::JSON_TAIL), f, "JSON");

    safe_compile(r_rar4, Sig::raw_to_hex(Sig::Bin::RAR4), f, "RAR4");
    safe_compile(r_rar5, Sig::raw_to_hex(Sig::Bin::RAR5), f, "RAR5");
    safe_compile(r_bmp, Sig::Bin::BMP_HEAD, f, "BMP");
    safe_compile(r_mkv, Sig::raw_to_hex(Sig::Bin::MKV), f, "MKV");
    safe_compile(r_mp3, Sig::raw_to_hex(Sig::Bin::MP3), f, "MP3");
    safe_compile(r_xml, Sig::Text::XML, fi, "XML");
    safe_compile(r_eml, Sig::Text::EML, fi, "EML");
}
std::string StdScanner::name() const { return "std::regex"; }
void StdScanner::scan(const char* d, size_t s, ScanStats& st) {
    // Лямбда для поиска с выводом статуса
    auto run_check = [&](const std::string& label, const std::regex& re, int& counter, const std::string& sig_check = "") {
        // 1. Быстрая проверка сигнатуры (Pre-filter)
        if (!sig_check.empty() && !has_sig(d, s, sig_check)) {
            return; // Пропускаем, если нет сигнатуры
        }

        // 2. Вывод статуса (перезаписываемая строка)
        std::cout << "\r[StdScanner] Scanning: " << std::left << std::setw(10) << label
            << " | Found so far: " << counter << std::flush;

        // 3. Поиск регуляркой
        const char* start = d;
        const char* end = d + s;
        std::cmatch m;

        try {
            // Проверка на пустую/битую регулярку
            if (re.mark_count() == 0 && std::string(start, std::min((size_t)1, s)).empty()) return;

            while (start < end && std::regex_search(start, end, m, re)) {
                counter++;
                // Обновляем счетчик в реальном времени
                std::cout << "\r[StdScanner] Scanning: " << std::left << std::setw(10) << label
                    << " | Found so far: " << counter << std::flush;

                auto shift = std::max((std::ptrdiff_t)1, m.length());
                start += m.position() + shift;
            }
        }
        catch (const std::exception& e) {
            std::cerr << "\n[Error] Regex failed for " << label << ": " << e.what() << "\n";
        }
        };

    // --- ЗАПУСК ПРОВЕРОК ---

    // OLE Группа
    run_check("DOC (OLE)", r_doc, st.doc, Sig::Bin::OLE);
    run_check("XLS (OLE)", r_xls, st.xls, Sig::Bin::OLE);
    run_check("PPT (OLE)", r_ppt, st.ppt, Sig::Bin::OLE);

    // ZIP / Office XML Группа
    // Сначала ищем просто ZIP хедер, если есть - копаем глубже
    if (has_sig(d, s, Sig::Bin::ZIP_HEAD)) {
        run_check("DOCX", r_docx, st.docx);
        run_check("XLSX", r_xlsx, st.xlsx);
        run_check("PPTX", r_pptx, st.pptx);
        run_check("ZIP", r_zip, st.zip);
    }

    run_check("PDF", r_pdf, st.pdf, Sig::Bin::PDF_HEAD);
    run_check("RAR4", r_rar4, st.rar, Sig::Bin::RAR4);
    run_check("RAR5", r_rar5, st.rar, Sig::Bin::RAR5);

    run_check("PNG", r_png, st.png, Sig::Bin::PNG_HEAD);
    run_check("JPG", r_jpg, st.jpg, Sig::Bin::JPG_HEAD);
    run_check("GIF", r_gif, st.gif, Sig::Bin::GIF_HEAD);

    run_check("BMP", r_bmp, st.bmp, Sig::Bin::BMP_HEAD.substr(0, 2)); // Проверяем только "BM"

    run_check("MKV", r_mkv, st.mkv, Sig::Bin::MKV);
    run_check("MP3", r_mp3, st.mp3, Sig::Bin::MP3);

    // Текстовые файлы (самые опасные для зависания из-за обилия текста)
    run_check("HTML", r_html, st.html, "<html");
    run_check("XML", r_xml, st.xml, "<?xml");
    run_check("JSON", r_json, st.json, "{");
    run_check("EML", r_eml, st.eml, "From:");

    // Очистка строки статуса после завершения
    std::cout << "\r[StdScanner] Done.                                           \n";
}

// ==========================================
// Re2Scanner
// ==========================================
Re2Scanner::Re2Scanner() {
    re2::RE2::Options ob;
    ob.set_encoding(re2::RE2::Options::EncodingLatin1);
    ob.set_log_errors(true);
    ob.set_dot_nl(true);
    ob.set_max_mem(64 << 20);
    re2::RE2::Options ot = ob; ot.set_case_sensitive(false);

    auto compile = [&](const std::string& pat, const re2::RE2::Options& opt, const char* name) {
        auto re = std::make_unique<re2::RE2>(pat, opt);
        if (!re->ok()) {
            std::cerr << "[Re2Scanner] Error compiling " << name << ": " << re->error() << "\n";
            std::cerr << " -> Pattern: " << pat.substr(0, 50) << "...\n";
        }
        return re;
        };

    // [FIX] Используем Engine::RE2 (лимит 1000)
    r_doc = compile(Sig::complex<Sig::Engine::RE2>(Sig::Bin::OLE, Sig::Bin::OLE_WORD), ob, "DOC");
    r_xls = compile(Sig::complex<Sig::Engine::RE2>(Sig::Bin::OLE, Sig::Bin::OLE_XL), ob, "XLS");
    r_ppt = compile(Sig::complex<Sig::Engine::RE2>(Sig::Bin::OLE, Sig::Bin::OLE_PPT), ob, "PPT");
    r_docx = compile(Sig::complex<Sig::Engine::RE2>(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_WORD), ob, "DOCX");
    r_xlsx = compile(Sig::complex<Sig::Engine::RE2>(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_XL), ob, "XLSX");
    r_pptx = compile(Sig::complex<Sig::Engine::RE2>(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_PPT), ob, "PPTX");

    r_zip_gen = compile(Sig::framed<Sig::Engine::RE2>(Sig::Bin::ZIP_HEAD, Sig::Bin::ZIP_TAIL), ob, "ZIP");
    r_pdf = compile(Sig::framed<Sig::Engine::RE2>(Sig::Bin::PDF_HEAD, Sig::Bin::PDF_TAIL), ob, "PDF");
    r_png = compile(Sig::framed<Sig::Engine::RE2>(Sig::Bin::PNG_HEAD, Sig::Bin::PNG_TAIL), ob, "PNG");
    r_jpg = compile(Sig::framed<Sig::Engine::RE2>(Sig::Bin::JPG_HEAD, Sig::Bin::JPG_TAIL), ob, "JPG");
    r_gif = compile(Sig::framed<Sig::Engine::RE2>(Sig::Bin::GIF_HEAD, Sig::Bin::GIF_TAIL), ob, "GIF");

    r_rar4 = compile(Sig::raw_to_hex(Sig::Bin::RAR4), ob, "RAR4");
    r_rar5 = compile(Sig::raw_to_hex(Sig::Bin::RAR5), ob, "RAR5");
    r_bmp = compile(Sig::Bin::BMP_HEAD, ob, "BMP");
    r_mkv = compile(Sig::raw_to_hex(Sig::Bin::MKV), ob, "MKV");
    r_mp3 = compile(Sig::raw_to_hex(Sig::Bin::MP3), ob, "MP3");

    r_html = compile(Sig::framed_text<Sig::Engine::RE2>(Sig::Text::HTML_HEAD, Sig::Text::HTML_TAIL), ot, "HTML");
    r_xml = compile(Sig::Text::XML, ot, "XML");
    r_json = compile(Sig::framed_text<Sig::Engine::RE2>(Sig::Text::JSON_HEAD, Sig::Text::JSON_TAIL), ob, "JSON");
    r_eml = compile(Sig::Text::EML, ot, "EML");
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
    auto safe_compile = [&](boost::regex& target, const std::string& pat, auto flags, const char* name) {
        try { target.assign(pat, flags); }
        catch (const boost::regex_error& e) { std::cerr << "[BoostScanner] Error compiling " << name << ": " << e.what() << "\n"; }
        };

    // [FIX] Используем Engine::BOOST
    safe_compile(r_doc, Sig::complex<Sig::Engine::BOOST>(Sig::Bin::OLE, Sig::Bin::OLE_WORD), flags_bin, "DOC");
    safe_compile(r_xls, Sig::complex<Sig::Engine::BOOST>(Sig::Bin::OLE, Sig::Bin::OLE_XL), flags_bin, "XLS");
    safe_compile(r_ppt, Sig::complex<Sig::Engine::BOOST>(Sig::Bin::OLE, Sig::Bin::OLE_PPT), flags_bin, "PPT");
    safe_compile(r_docx, Sig::complex<Sig::Engine::BOOST>(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_WORD), flags_bin, "DOCX");
    safe_compile(r_xlsx, Sig::complex<Sig::Engine::BOOST>(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_XL), flags_bin, "XLSX");
    safe_compile(r_pptx, Sig::complex<Sig::Engine::BOOST>(Sig::Bin::ZIP_HEAD, Sig::Bin::XML_PPT), flags_bin, "PPTX");

    safe_compile(r_zip_gen, Sig::framed<Sig::Engine::BOOST>(Sig::Bin::ZIP_HEAD, Sig::Bin::ZIP_TAIL), flags_bin, "ZIP");
    safe_compile(r_pdf, Sig::framed<Sig::Engine::BOOST>(Sig::Bin::PDF_HEAD, Sig::Bin::PDF_TAIL), flags_bin, "PDF");
    safe_compile(r_png, Sig::framed<Sig::Engine::BOOST>(Sig::Bin::PNG_HEAD, Sig::Bin::PNG_TAIL), flags_bin, "PNG");
    safe_compile(r_jpg, Sig::framed<Sig::Engine::BOOST>(Sig::Bin::JPG_HEAD, Sig::Bin::JPG_TAIL), flags_bin, "JPG");
    safe_compile(r_gif, Sig::framed<Sig::Engine::BOOST>(Sig::Bin::GIF_HEAD, Sig::Bin::GIF_TAIL), flags_bin, "GIF");

    safe_compile(r_rar4, Sig::raw_to_hex(Sig::Bin::RAR4), flags_bin, "RAR4");
    safe_compile(r_rar5, Sig::raw_to_hex(Sig::Bin::RAR5), flags_bin, "RAR5");
    safe_compile(r_bmp, Sig::Bin::BMP_HEAD, flags_bin, "BMP");
    safe_compile(r_mkv, Sig::raw_to_hex(Sig::Bin::MKV), flags_bin, "MKV");
    safe_compile(r_mp3, Sig::raw_to_hex(Sig::Bin::MP3), flags_bin, "MP3");
    safe_compile(r_html, Sig::framed_text<Sig::Engine::BOOST>(Sig::Text::HTML_HEAD, Sig::Text::HTML_TAIL), flags_text, "HTML");
    safe_compile(r_xml, Sig::Text::XML, flags_text, "XML");
    safe_compile(r_json, Sig::framed_text<Sig::Engine::BOOST>(Sig::Text::JSON_HEAD, Sig::Text::JSON_TAIL), flags_bin, "JSON");
    safe_compile(r_eml, Sig::Text::EML, flags_text, "EML");
}

std::string BoostScanner::name() const { return "Boost.Regex"; }

void BoostScanner::scan(const char* d, size_t s, ScanStats& st) {
    auto searcher = [](const char* start, const char* end, boost::cmatch& m, const boost::regex& re) { return boost::regex_search(start, end, m, re); };
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
    // Сигнатуры
    std::string p_doc = Sig::complex<Sig::Engine::HS>(Sig::Bin::OLE, Sig::Bin::OLE_WORD);
    std::string p_xls = Sig::complex<Sig::Engine::HS>(Sig::Bin::OLE, Sig::Bin::OLE_XL);
    std::string p_ppt = Sig::complex<Sig::Engine::HS>(Sig::Bin::OLE, Sig::Bin::OLE_PPT);
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

    std::vector<unsigned int> flags;
    // Используем DOTALL для бинарных данных
    for (int i = 0; i < 16; ++i) flags.push_back(HS_FLAG_DOTALL);
    flags.push_back(HS_FLAG_DOTALL | HS_FLAG_CASELESS | HS_FLAG_UTF8); // HTML
    flags.push_back(HS_FLAG_DOTALL | HS_FLAG_CASELESS | HS_FLAG_UTF8); // XML
    flags.push_back(HS_FLAG_DOTALL | HS_FLAG_UTF8);                    // JSON
    flags.push_back(HS_FLAG_DOTALL | HS_FLAG_CASELESS | HS_FLAG_UTF8); // EML

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

// Контекст для хранения состояния между вызовами (защита от дребезга)
struct HsContext {
    ScanStats* stats;
    unsigned long long last_offset[32] = { 0 }; // Смещение последнего совпадения для каждого id
};

void HsScanner::scan(const char* data, size_t size, ScanStats& stats) {
    if (!db || !scratch) return;

    HsContext ctx;
    ctx.stats = &stats;


    auto on_match = [](unsigned int id, unsigned long long from, unsigned long long to, unsigned int flags, void* ptr) -> int {
        HsContext* c = static_cast<HsContext*>(ptr);

        // DEBOUNCE LOGIC (Защита от дребезга)
        // Если для этого ID новое совпадение найдено слишком близко к предыдущему (например, < 512 байт),
        // считаем это частью того же файла и игнорируем.
        // Это позволяет считать поток файлов (BIN/ZIP), но подавляет множественные срабатывания внутри одного файла.

        // 0 - особый случай (начало), но to всегда > 0.
        // Используем 512 байт как "мертвую зону". В генераторе файлы > 1KB.
        if (id < 32) {
            unsigned long long last = c->last_offset[id];

            // Если это не первое совпадение И дистанция меньше порога -> пропускаем
            if (last != 0 && to < last + 512) {
                return 0;
            }
            c->last_offset[id] = to; // Обновляем позицию
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
}