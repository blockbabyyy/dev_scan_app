#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <re2/re2.h>
#include <boost/regex.hpp>
#include <boost/algorithm/string/replace.hpp> // ??? ????????????? ???????????? ? boost
#include <regex>
#include <hs/hs.h> // Hyperscan
#include "Signatures.h"
#include "generator/Generator.h"



namespace fs = std::filesystem;

// Статистика
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

    void print(const std::string& engine_name) const {
        std::cout << "===== " << engine_name << " Results =====" << std::endl;
        std::cout << "[Docs (Old)]\n"
            << "  DOC: " << doc << " | XLS: " << xls << " | PPT: " << ppt
            << " | Generic OLE: " << ole << "\n";
        std::cout << "[Docs (OpenXML)]\n"
            << "  DOCX: " << docx << " | XLSX: " << xlsx << " | PPTX: " << pptx<< "\n";
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
};

// Интерфейс 
class Scanner {
    public:
        virtual ~Scanner() = default;

        // Метод для подготовки (pre-allocation памяти для HS)
        virtual void prepare() {}

        // Основной метод сканирования
        virtual void scan(const char* data, size_t size, ScanStats& stats) = 0;

        // Имя для вывода в консоль
        virtual std::string name() const = 0;
};


class StdScanner : public Scanner {
    public:
        StdScanner() {
            auto f = std::regex::optimize;
            auto fi = std::regex::optimize | std::regex::icase;


            // DOC: ^OLE + .* + WordDocument
            r_doc.assign(Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_WORD), f);
            r_xls.assign(Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_XL), f);
            r_ppt.assign(Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_PPT), f);

            // DOCX: ^ZIP + .* + word/
            r_docx.assign(Sig::complex(Sig::Bin::ZIP, Sig::Bin::XML_WORD), f);
            r_xlsx.assign(Sig::complex(Sig::Bin::ZIP, Sig::Bin::XML_XL), f);
            r_pptx.assign(Sig::complex(Sig::Bin::ZIP, Sig::Bin::XML_PPT), f);

            // Бинарные: ^ + байты
            r_pdf.assign("^" + Sig::raw_to_hex(Sig::Bin::PDF), f);
            //r_ole.assign("^" + Sig::Bin::OLE, f);
            r_zip.assign("^" + Sig::raw_to_hex(Sig::Bin::ZIP), f);
            r_rar4.assign("^" + Sig::raw_to_hex(Sig::Bin::RAR4), f);
            r_rar5.assign("^" + Sig::raw_to_hex(Sig::Bin::RAR5), f);

            r_png.assign("^" + Sig::raw_to_hex(Sig::Bin::PNG), f);
            r_jpg.assign("^" + Sig::raw_to_hex(Sig::Bin::JPG), f);
            r_gif.assign("^" + Sig::raw_to_hex(Sig::Bin::GIF), f);
            r_bmp.assign("^" + Sig::raw_to_hex(Sig::Bin::BMP), f);
            r_mkv.assign("^" + Sig::raw_to_hex(Sig::Bin::MKV), f);
            r_mp3.assign("^" + Sig::raw_to_hex(Sig::Bin::MP3), f);

            // Текстовые: ^ + паттерн
            r_html.assign("^" + Sig::raw_to_hex(Sig::Text::HTML), fi);
            r_xml.assign("^" + Sig::raw_to_hex(Sig::Text::XML), fi);
            r_json.assign("^" + Sig::raw_to_hex(Sig::Text::JSON), f);
            r_eml.assign("^" + Sig::raw_to_hex(Sig::Text::EML), fi);

        }

        std::string name() const override { return "std::regex"; }
        void scan(const char* d, size_t s, ScanStats& st) override {
            std::cmatch m; auto end = d + s;
            if (std::regex_search(d, end, m, r_doc))  st.doc++;
            else if (std::regex_search(d, end, m, r_xls))  st.xls++;
            else if (std::regex_search(d, end, m, r_ppt))  st.ppt++;

            else if (std::regex_search(d, end, m, r_docx)) st.docx++;
            else if (std::regex_search(d, end, m, r_xlsx)) st.xlsx++;
            else if (std::regex_search(d, end, m, r_pptx)) st.pptx++;

            else if (std::regex_search(d, end, m, r_zip)) st.zip++;
            else if (std::regex_search(d, end, m, r_pdf)) st.pdf++;
            //else if (std::regex_search(d, end, m, r_ole)) st.office_ole++;
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
    private:
        std::regex r_pdf, /*r_ole,*/ r_zip, r_rar4, r_rar5;
        std::regex r_png, r_jpg, r_gif, r_bmp, r_mkv, r_mp3;
        std::regex r_html, r_xml, r_json, r_eml;
        std::regex r_doc, r_xls, r_ppt;
        std::regex r_docx, r_xlsx, r_pptx;
        
		
};

class Re2Scanner : public Scanner {
    public:
        Re2Scanner() {
            re2::RE2::Options ob; 
            ob.set_encoding(re2::RE2::Options::EncodingLatin1); 
            ob.set_log_errors(false);
            ob.set_dot_nl(true);

			// Текстовые - нечувствительны к регистру
            re2::RE2::Options ot = ob; 
            ot.set_case_sensitive(false);

            r_doc = std::make_unique<re2::RE2>("^" + Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_WORD), ob);
            r_xls = std::make_unique<re2::RE2>("^" + Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_XL), ob);
            r_ppt = std::make_unique<re2::RE2>("^" + Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_PPT), ob);
            r_ole_gen = std::make_unique<re2::RE2>("^" + Sig::raw_to_hex(Sig::Bin::OLE), ob);

            r_docx = std::make_unique<re2::RE2>("^" + Sig::complex(Sig::Bin::ZIP, Sig::Bin::XML_WORD), ob);
            r_xlsx = std::make_unique<re2::RE2>("^" + Sig::complex(Sig::Bin::ZIP, Sig::Bin::XML_XL), ob);
            r_pptx = std::make_unique<re2::RE2>("^" + Sig::complex(Sig::Bin::ZIP, Sig::Bin::XML_PPT), ob);
            r_zip_gen = std::make_unique<re2::RE2>("^" + Sig::raw_to_hex(Sig::Bin::ZIP), ob);

            // ... Инициализация остальных такая же, как в StdScanner, только через make_unique
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

        std::string name() const override { return "Google RE2"; }
        void scan(const char* d, size_t s, ScanStats& st) override {
            re2::StringPiece p(d, s);
            if (RE2::PartialMatch(p, *r_doc)) st.doc++;
            else if (RE2::PartialMatch(p, *r_xls)) st.xls++;
            else if (RE2::PartialMatch(p, *r_ppt)) st.ppt++;
            else if (RE2::PartialMatch(p, *r_ole_gen)) st.ole++;

            else if (RE2::PartialMatch(p, *r_docx)) st.docx++;
            else if (RE2::PartialMatch(p, *r_xlsx)) st.xlsx++;
            else if (RE2::PartialMatch(p, *r_pptx)) st.pptx++;
            else if (RE2::PartialMatch(p, *r_zip_gen)) st.zip++;

            else if (RE2::PartialMatch(p, *r_pdf)) st.pdf++;
            else if (RE2::PartialMatch(p, *r_rar4) || RE2::PartialMatch(p, *r_rar5)) st.rar++;
            else if (RE2::PartialMatch(p, *r_png)) st.png++;
            else if (RE2::PartialMatch(p, *r_jpg)) st.jpg++;
            else if (RE2::PartialMatch(p, *r_gif)) st.gif++;
            else if (RE2::PartialMatch(p, *r_bmp)) st.bmp++;
            else if (RE2::PartialMatch(p, *r_mkv)) st.mkv++;
            else if (RE2::PartialMatch(p, *r_mp3)) st.mp3++;
            else if (RE2::PartialMatch(p, *r_html)) st.html++;
            else if (RE2::PartialMatch(p, *r_xml)) st.xml++;
            else if (RE2::PartialMatch(p, *r_json)) st.json++;
            else if (RE2::PartialMatch(p, *r_eml)) st.eml++;
            else st.unknown++;
        }
    private:
        //объекты класса re2::RE2 некопируемые + можно инициализировать отложенно
        std::unique_ptr<re2::RE2> r_doc, r_xls, r_ppt, r_ole_gen;
        std::unique_ptr<re2::RE2> r_docx, r_xlsx, r_pptx, r_zip_gen;
        std::unique_ptr<re2::RE2> r_pdf, r_rar4, r_rar5;
        std::unique_ptr<re2::RE2> r_png, r_jpg, r_gif, r_bmp, r_mkv, r_mp3;
        std::unique_ptr<re2::RE2> r_html, r_xml, r_json, r_eml;

};

class BoostScanner : public Scanner {
    public:
        BoostScanner() {
			auto flags_bin = boost::regex::perl; // Бинарные - чувствительны к регистру
			auto flags_text = boost::regex::perl | boost::regex::icase; // Текстовые - нечувствительны к регистру

            r_doc.assign("\\A" + Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_WORD), flags_bin);
            r_xls.assign("\\A" + Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_XL), flags_bin);
            r_ppt.assign("\\A" + Sig::complex(Sig::Bin::OLE, Sig::Bin::OLE_PPT), flags_bin);
            r_ole_gen.assign("\\A" + Sig::raw_to_hex(Sig::Bin::OLE), flags_bin);

            r_docx.assign("\\A" + Sig::complex(Sig::Bin::ZIP, Sig::Bin::XML_WORD), flags_bin);
            r_xlsx.assign("\\A" + Sig::complex(Sig::Bin::ZIP, Sig::Bin::XML_XL), flags_bin);
            r_pptx.assign("\\A" + Sig::complex(Sig::Bin::ZIP, Sig::Bin::XML_PPT), flags_bin);
            r_zip_gen.assign("\\A" + Sig::raw_to_hex(Sig::Bin::ZIP), flags_bin);

            // Остальное
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

        std::string name() const override { return "Boost.Regex"; }
        void scan(const char* d, size_t s, ScanStats& st) override {
            // Boost корректно работает с указателями
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
    private:
        boost::regex r_doc, r_xls, r_ppt, r_ole_gen;
        boost::regex r_docx, r_xlsx, r_pptx, r_zip_gen;
        boost::regex r_pdf, r_rar4, r_rar5;
        boost::regex r_png, r_jpg, r_gif, r_bmp, r_mkv, r_mp3;
        boost::regex r_html, r_xml, r_json, r_eml;
};


class HsScanner : public Scanner {
    public:
        
        HsScanner() {
            // Подготовка паттернов (нужно добавить ^ вручную для каждого)
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

        ~HsScanner() {
            if (scratch) hs_free_scratch(scratch);
            if (db) hs_free_database(db);
        }

        void prepare() override {
            if (db && !scratch) {
				hs_alloc_scratch(db, &scratch); // выделяем память для сканирования
            }
        }

        std::string name() const override { return "Hyperscan"; }

        void scan(const char* data, size_t size, ScanStats& stats) override {
            if (!db || !scratch) return;

            // Логика приоритетов для Hyperscan
            // Так как HS находит все совпадения, вводим конкуренцию
            // ID_DOCX круче ID_ZIP.
            int best_id = 0;

            auto on_match = [](unsigned int id, unsigned long long, unsigned long long, unsigned int, void* ctx) {
                int* current = static_cast<int*>(ctx);
                // Если нашли специфичный формат, перезаписываем общий
                // Если нашли общий, а уже записан специфичный - не трогаем
                bool is_specific = (id == ID_DOC || id == ID_XLS || id == ID_PPT ||
                    id == ID_DOCX || id == ID_XLSX || id == ID_PPTX);

                if (*current == 0) *current = id;
                else if (is_specific) *current = id;

                return 0; // Ищем дальше, вдруг найдется более специфичный маркер
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

    private:
        hs_database_t* db = nullptr;
        hs_scratch_t* scratch = nullptr;

        // Внутренние ID для Hyperscan callback
        enum {
            ID_PDF = 1, ID_OLE, ID_ZIP, ID_RAR,
            ID_DOC, ID_XLS, ID_PPT,       
            ID_DOCX, ID_XLSX, ID_PPTX,
            ID_PNG, ID_JPG, ID_GIF, ID_BMP, ID_MKV, ID_MP3,
            ID_HTML, ID_XML, ID_JSON, ID_EML
        };

};

int main() {

    StdScanner std_scanner;
    Re2Scanner re2_scanner;
	BoostScanner boost_scanner;
	HsScanner hs_scanner;

    std::string directory = R"(C:\projects\dev_scan_app\input)";
    ScanStats stats_std, stats_re2, stats_boost, stats_hs;

	GenStats gen_stats;

    try {
        // Проверки пути
        if (!fs::exists(directory) || !fs::is_directory(directory)) {
            std::cerr << "Папка не найдена: " << directory << std::endl;
            return 1;
        }
       
        bool is_gen_required = fs::is_empty(directory);
        
        if (is_gen_required) {
            std::cout << "Input directory is empty. Generating dataset..." << std::endl;
            DataSetGenerator generator;
            // Генерируем 200 МБ файлов в папку
            gen_stats = generator.generate(directory, 400, DataSetGenerator::ContainerType::FOLDER);
            gen_stats.print();
        }

		hs_scanner.prepare(); // подготовка Hyperscan

        for (const auto& entry : fs::directory_iterator(directory)) {
            if (fs::is_regular_file(entry)) {


                std::ifstream file(entry.path(), std::ios::binary | std::ios::ate);
                if (!file) continue;


                size_t size = file.tellg();
                if (size == 0) continue; 

                std::vector<char> buffer(size);
                file.seekg(0);
                file.read(buffer.data(), size);


                std_scanner.scan(buffer.data(), buffer.size(), stats_std);
                re2_scanner.scan(buffer.data(), buffer.size(), stats_re2);
				boost_scanner.scan(buffer.data(), buffer.size(), stats_boost);
				hs_scanner.scan(buffer.data(), buffer.size(), stats_hs);

            }
        }

        std::cout << "===== Results =====" << std::endl;
		stats_std.print(std_scanner.name());
		stats_re2.print(re2_scanner.name());
		stats_boost.print(boost_scanner.name());
		stats_hs.print(hs_scanner.name());
        

    }
    catch (const std::exception& ex) {
        std::cerr << "Ошибка: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}