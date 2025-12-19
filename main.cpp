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
    // Документы и Архивы
    int pdf = 0;
    int office_ole = 0;
    int zip_docx = 0; // ZIP + DOCX/XLSX/PPTX
    int rar = 0;

    // Медиа
    int png = 0;
    int jpg = 0;
    int gif = 0;
    int bmp = 0;
    int mkv = 0;
    int mp3 = 0;

    // Текст
    int html = 0;
    int xml = 0;
    int json = 0;
    int eml = 0;

    int unknown = 0;

    void print(const std::string& engine_name) const {
        std::cout << "===== " << engine_name << " Results =====" << std::endl;

        std::cout << "[Docs & Archives]" << std::endl;
        std::cout << "  PDF: " << pdf << " | OLE: " << office_ole
            << " | ZIP: " << zip_docx << " | RAR: " << rar << std::endl;

        std::cout << "[Media]" << std::endl;
        std::cout << "  PNG: " << png << " | JPG: " << jpg << " | GIF: " << gif
            << " | BMP: " << bmp << " | MKV: " << mkv << " | MP3: " << mp3 << std::endl;

        std::cout << "[Text/Code]" << std::endl;
        std::cout << "  HTML: " << html << " | XML: " << xml
            << " | JSON: " << json << " | EML: " << eml << std::endl;

        std::cout << "[Other]" << std::endl;
        std::cout << "  Unknown: " << unknown << std::endl;
		std::cout << "-------------------------------" << std::endl;
        std::cout << "  Total Files: " << (pdf + office_ole + zip_docx + rar +
            png + jpg + gif + bmp + mkv + mp3 +
			html + xml + json + eml + unknown) << std::endl;
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
            auto f_icase = std::regex::optimize | std::regex::icase;
            // Компиляция
            pdf.assign("^" + Sig::Bin::PDF, f);
		    office_old.assign("^" + Sig::Bin::OLE, f);
            zip.assign("^" + Sig::Bin::ZIP, f);
		    rar4.assign("^" + Sig::Bin::RAR4, f);
		    rar5.assign("^" + Sig::Bin::RAR5, f);

            png.assign("^" + Sig::Bin::PNG, f);
			jpg.assign("^" + Sig::Bin::JPG, f);
			gif.assign("^" + Sig::Bin::GIF, f);
			bmp.assign("^" + Sig::Bin::BMP, f);
			mkv.assign("^" + Sig::Bin::MKV, f);
            mp3.assign("^" + Sig::Bin::MP3, f);
            
            
			html.assign(Sig::Text::HTML, f_icase);
			xml.assign(Sig::Text::XML, f_icase);
            json.assign(Sig::Text::JSON, f_icase);
			eml.assign(Sig::Text::EML, f_icase);
            
        }

        std::string name() const override { return "std::regex"; }

        void scan(const char* data, size_t size, ScanStats& stats) override {
            std::cmatch m;
            
            if (std::regex_search(data, data + size, m, pdf)) stats.pdf++;
            else if (std::regex_search(data, data + size, m, office_old)) stats.office_ole++;
            else if (std::regex_search(data, data + size, m, zip)) stats.zip_docx++;
            else if (std::regex_search(data, data + size, m, rar4) ||
                     std::regex_search(data, data + size, m, rar5)) stats.rar++;
            else if (std::regex_search(data, data + size, m, png)) stats.png++;
            else if (std::regex_search(data, data + size, m, jpg)) stats.jpg++;
            else if (std::regex_search(data, data + size, m, gif)) stats.gif++;
            else if (std::regex_search(data, data + size, m, bmp)) stats.bmp++;
            else if (std::regex_search(data, data + size, m, mkv)) stats.mkv++;
            else if (std::regex_search(data, data + size, m, mp3)) stats.mp3++;
            else if (std::regex_search(data, data + size, m, mp3)) stats.mp3++;
       
            else if (std::regex_search(data, data + size, m, html)) stats.html++;
            else if (std::regex_search(data, data + size, m, xml)) stats.xml++;
			else if (std::regex_search(data, data + size, m, json)) stats.json++;
			else if (std::regex_search(data, data + size, m, eml)) stats.eml++;
      
			else stats.unknown++;
            
        }
    private:
        std::regex pdf, office_old, zip, rar4, rar5, png, jpg, gif, bmp, mkv, mp3, html, xml, json, eml;

        
		
};

class Re2Scanner : public Scanner {
    public:
        Re2Scanner() {
            // Опции для бинарников
            re2::RE2::Options options;
            options.set_encoding(re2::RE2::Options::EncodingLatin1);
            options.set_log_errors(false);

			// Опции для текстовых (регистронезависимые)
            re2::RE2::Options opt_text = options;
            opt_text.set_case_sensitive(false);
            // Компиляция
            pdf = std::make_unique<re2::RE2>("^" + Sig::Bin::PDF, options);
            office_old = std::make_unique<re2::RE2>("^" + Sig::Bin::OLE, options);
            zip = std::make_unique<re2::RE2>("^" + Sig::Bin::ZIP, options);
            rar4 = std::make_unique<re2::RE2>("^" + Sig::Bin::RAR4, options);
            rar5 = std::make_unique<re2::RE2>("^" + Sig::Bin::RAR4, options);

            png = std::make_unique<re2::RE2>("^" + Sig::Bin::PNG, options);
            jpg = std::make_unique<re2::RE2>("^" + Sig::Bin::JPG, options);
            gif = std::make_unique<re2::RE2>("^" + Sig::Bin::GIF, options);
            bmp = std::make_unique<re2::RE2>("^" + Sig::Bin::BMP, options);
            mkv = std::make_unique<re2::RE2>("^" + Sig::Bin::MKV, options);
            mp3 = std::make_unique<re2::RE2>("^" + Sig::Bin::MP3, options);

            // 4. Инициализация ТЕКСТОВЫХ паттернов (уже содержат ^)
            // HTML и XML и EML ищем без учета регистра (opt_text)
            html = std::make_unique<re2::RE2>(Sig::Text::HTML, opt_text);
            xml = std::make_unique<re2::RE2>(Sig::Text::XML, opt_text);
            eml = std::make_unique<re2::RE2>(Sig::Text::EML, opt_text);

            // JSON обычно чувствителен к регистру (хотя для { это не важно), используем opt_bin
            json = std::make_unique<re2::RE2>(Sig::Text::JSON, options);

        }

        std::string name() const override { return "Google RE2"; }

        void scan(const char* data, size_t size, ScanStats& stats) override {
            // RE2 требует StringPiece (легкая обертка)
            re2::StringPiece piece(data, size);

            // Проверки
            if (RE2::PartialMatch(piece, *pdf)) stats.pdf++;
            else if (RE2::PartialMatch(piece, *office_old)) stats.office_ole++;
            else if (RE2::PartialMatch(piece, *zip)) stats.zip_docx++;
            else if (RE2::PartialMatch(piece, *rar4) || RE2::PartialMatch(piece, *rar5)) stats.rar++;
            else if (RE2::PartialMatch(piece, *png)) stats.png++;
            else if (RE2::PartialMatch(piece, *jpg)) stats.jpg++;
            else if (RE2::PartialMatch(piece, *gif)) stats.gif++;
            else if (RE2::PartialMatch(piece, *bmp)) stats.bmp++;
            else if (RE2::PartialMatch(piece, *mkv)) stats.mkv++;
            else if (RE2::PartialMatch(piece, *mp3)) stats.mp3++;

            // Текст
            else if (RE2::PartialMatch(piece, *html)) stats.html++;
            else if (RE2::PartialMatch(piece, *xml)) stats.xml++;
			else if (RE2::PartialMatch(piece, *json)) stats.json++;
            else if (RE2::PartialMatch(piece, *eml)) stats.eml++;
            else stats.unknown++;
        }
    private:
        //объекты класса re2::RE2 некопируемые + можно инициализировать отложенно
        std::unique_ptr<re2::RE2> pdf, office_old, zip, rar4, rar5, png, jpg, gif, bmp, mkv, mp3, html, xml, json, eml;

};

class BoostScanner : public Scanner {
    public:
        BoostScanner() {
            // Boost по умолчанию хорошо оптимизирован
            pdf.assign("^" + Sig::Bin::PDF);
            office_old.assign("^" + Sig::Bin::OLE);
            zip.assign("^" + Sig::Bin::ZIP);
            rar4.assign("^" + Sig::Bin::RAR4);
            rar5.assign("^" + Sig::Bin::RAR5);

            png.assign("^" + Sig::Bin::PNG);
            jpg.assign("^" + Sig::Bin::JPG);
            gif.assign("^" + Sig::Bin::GIF);
            bmp.assign("^" + Sig::Bin::BMP);
            mkv.assign("^" + Sig::Bin::MKV);
            mp3.assign("^" + Sig::Bin::MP3);


            html.assign(Sig::Text::HTML);
            xml.assign(Sig::Text::XML);
            json.assign(Sig::Text::JSON);
            eml.assign(Sig::Text::EML);
        }

        std::string name() const override { return "Boost.Regex"; }

        void scan(const char* data, size_t size, ScanStats& stats) override {
            // Boost тоже умеет работать с диапазоном итераторов (const char*)
            if (boost::regex_search(data, data + size, pdf)) stats.pdf++;
            else if (boost::regex_search(data, data + size, office_old)) stats.office_ole++;
            else if (boost::regex_search(data, data + size, rar4) ||
                boost::regex_search(data, data + size, rar5)) stats.rar++;
            else if (boost::regex_search(data, data + size, png)) stats.png++;
            else if (boost::regex_search(data, data + size, jpg)) stats.jpg++;
            else if (boost::regex_search(data, data + size, gif)) stats.gif++;
            else if (boost::regex_search(data, data + size, bmp)) stats.bmp++;
            else if (boost::regex_search(data, data + size, mkv)) stats.mkv++;
            else if (boost::regex_search(data, data + size, mp3)) stats.mp3++;

            // Текст
            else if (boost::regex_search(data, data + size, html)) stats.html++;
            else if (boost::regex_search(data, data + size, xml)) stats.xml++;
            else if (boost::regex_search(data, data + size, json)) stats.json++;
            else if (boost::regex_search(data, data + size, eml)) stats.eml++;
            else stats.unknown++;
        }
    private:
        boost::regex pdf, office_old, zip, rar4, rar5, png, jpg, gif, bmp, mkv, mp3, html, xml, json, eml;;
};

/* Перенесена в Signature.h
// Вспомогательная функция: превращает сырые байты в безопасный regex "\xHH"
std::string raw_to_hex(const std::string& raw) {
    std::ostringstream ss;
    ss << "^"; // Сразу добавляем якорь начала
    for (unsigned char c : raw) {
        // Каждый байт превращаем в \xHH
        ss << "\\x" << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }
    return ss.str();
}
*/
class HsScanner : public Scanner {
    public:
        
        HsScanner() {
            // Подготовка паттернов (нужно добавить ^ вручную для каждого)
            std::string p_pdf = Sig::raw_to_hex(Sig::Bin::PDF);
            std::string p_office_old = Sig::raw_to_hex(Sig::Bin::OLE);
            std::string p_zip = Sig::raw_to_hex(Sig::Bin::ZIP);
            std::string p_rar4= Sig::raw_to_hex(Sig::Bin::RAR4);
            std::string p_rar5 = Sig::raw_to_hex(Sig::Bin::RAR5);

            std::string p_png = Sig::raw_to_hex(Sig::Bin::PNG);
            std::string p_jpg = Sig::raw_to_hex(Sig::Bin::JPG);
            std::string p_gif = Sig::raw_to_hex(Sig::Bin::GIF);
            std::string p_bmp = Sig::raw_to_hex(Sig::Bin::BMP);
            std::string p_mkv = Sig::raw_to_hex(Sig::Bin::MKV);
            std::string p_mp3 = Sig::raw_to_hex(Sig::Bin::MP3);

            const char* expressions[] = {
                // Бинарные
                p_pdf.c_str(), p_office_old.c_str(), p_zip.c_str(), p_rar4.c_str(), p_rar5.c_str(),
                p_png.c_str(), p_jpg.c_str(), p_gif.c_str(), p_bmp.c_str(), p_mkv.c_str(), p_mp3.c_str(),
                // Текстовые (берем напрямую из Signatures.h)
                Sig::Text::HTML.c_str(), Sig::Text::XML.c_str(),
                Sig::Text::JSON.c_str(), Sig::Text::EML.c_str()
            };
            unsigned int ids[] = {
             ID_PDF, ID_OLE, ID_ZIP, ID_RAR4, ID_RAR5,  // внутренние id для HS
             ID_PNG, ID_JPG, ID_GIF, ID_BMP, ID_MKV, ID_MP3,
             ID_HTML, ID_XML, ID_JSON, ID_EML
            };
            std::vector<unsigned int> flags;
            // Для первых 10 (бинарных) ставим стандартные флаги
            for (int i = 0; i < 10; ++i) {
                flags.push_back(HS_FLAG_DOTALL);
            }
            // Для текстовых:
            // HTML, XML, EML - игнорируем регистр (CASELESS)
            flags.push_back(HS_FLAG_DOTALL | HS_FLAG_CASELESS); // HTML
            flags.push_back(HS_FLAG_DOTALL | HS_FLAG_CASELESS); // XML
            flags.push_back(HS_FLAG_DOTALL);                    // JSON (скобки не имеют регистра)
            flags.push_back(HS_FLAG_DOTALL | HS_FLAG_CASELESS); // EML
			

            hs_compile_error_t* compile_err;
            // Компилируем сразу все паттерны в одну базу
            if (hs_compile_multi(expressions, flags.data(), ids, 5, HS_MODE_BLOCK, nullptr, &db, &compile_err) != HS_SUCCESS) {
                std::cerr << "HS Compile Error: " << compile_err->message << std::endl;
                hs_free_compile_error(compile_err);
                db = nullptr;
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

            if (!db) {
                std::cerr << "[Error] Hyperscan DB not compiled!" << std::endl;
                return;
            }
            if (!scratch) {

                throw std::runtime_error("[Error] Hyperscan scratch space not allocated! Call prepare()!");
            }

			//if (!db || !scratch) return; // база не скомпилирована или память не выделена

            int found_id = 0; 

            // Лямбда функция обратного вызова
            auto on_match = [](unsigned int id, unsigned long long from, unsigned long long to,
                unsigned int flags, void* context) -> int {
                    int* found_ptr = static_cast<int*>(context);
                    *found_ptr = id;
                    return 1; // возврат 1, чтобы остановить сканирование после первого совпадения
                };

            hs_scan(db, data, size, 0, scratch, on_match, &found_id);

			if (found_id == 0) {
                stats.unknown++;
               
            }
            else if (found_id == ID_PDF) stats.pdf++;
            else if (found_id == ID_OLE) stats.office_ole++;
            else if (found_id == ID_ZIP) stats.zip_docx++;
            else if (found_id == ID_RAR4 || found_id == ID_RAR5) stats.rar++;
            else if (found_id == ID_PNG) stats.png++;
            else if (found_id == ID_JPG) stats.jpg++;
            else if (found_id == ID_GIF) stats.gif++;
            else if (found_id == ID_BMP) stats.bmp++;
            else if (found_id == ID_MKV) stats.mkv++;
            else if (found_id == ID_MP3) stats.mp3++;
            else if (found_id == ID_HTML) stats.html++;
            else if (found_id == ID_XML) stats.xml++;
            else if (found_id == ID_JSON) stats.json++;
			else if (found_id == ID_EML) stats.eml++;
            else stats.unknown++;
        }

    private:
        hs_database_t* db = nullptr;
        hs_scratch_t* scratch = nullptr;

        // Внутренние ID для Hyperscan callback
        enum {
            ID_PDF = 1, ID_OLE, ID_ZIP, ID_RAR4, ID_RAR5,
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