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

#include "generator/Generator.h"



namespace fs = std::filesystem;

// (magic bytes)
const std::string sig_pdf("\x25\x50\x44\x46", 4);
//const std::string sig_pdf = "\x25\x50\x44\x46";                         // %PDF
const std::string sig_doc = "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1";     // DOC (Old Office)
const std::string sig_png = "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A";     // PNG
const std::string sig_rar4 = "\x52\x61\x72\x21\x1A\x07\x00";          // RAR 4
const std::string sig_rar5 = "\x52\x61\x72\x21\x1A\x07\x01\x00";     // RAR 5


// Статистика
struct ScanStats {
    int pdf = 0;
    int doc = 0;
    int png = 0;
    int rar = 0;
    int other = 0;

    void print(const std::string& engine_name) const {
        std::cout << "===== " << engine_name << " Results =====" << std::endl;
        std::cout << "PDF: " << pdf << "\nDOC: " << doc << "\nPNG: " << png
            << "\nRAR: " << rar << "\nOther: " << other << "\nTotal: " << pdf+doc+png+rar+other << std::endl;
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
            // Компиляция
            pdf.assign("^" + sig_pdf, std::regex::optimize);
		    doc.assign("^" + sig_doc, std::regex::optimize);
		    png.assign("^" + sig_png, std::regex::optimize);
		    rar4.assign("^" + sig_rar4, std::regex::optimize);
		    rar5.assign("^" + sig_rar5, std::regex::optimize);
       
        }

        std::string name() const override { return "std::regex"; }

        void scan(const char* data, size_t size, ScanStats& stats) override {
            std::cmatch m;
            
            if (std::regex_search(data, data + size, m, pdf)) stats.pdf++;
            else if (std::regex_search(data, data + size, m, doc)) stats.doc++;
            else if (std::regex_search(data, data + size, m, png)) stats.png++;
            else if (std::regex_search(data, data + size, m, rar4) ||
                     std::regex_search(data, data + size, m, rar5)) stats.rar++;
			else stats.other++;
            
        }
    private:
        std::regex pdf, doc, png, rar4, rar5;
		
};

class Re2Scanner : public Scanner {
    public:
        Re2Scanner() {
            // Опции
            re2::RE2::Options options;
            options.set_encoding(re2::RE2::Options::EncodingLatin1);
            options.set_log_errors(false);
            // Компиляция
            std::string p_pdf = "^" + sig_pdf;
            std::string p_doc = "^" + sig_doc;
            std::string p_png = "^" + sig_png;
            std::string p_rar4 = "^" + sig_rar4;
            std::string p_rar5 = "^" + sig_rar5;


            pdf = std::make_unique<re2::RE2>(p_pdf, options);
            doc = std::make_unique<re2::RE2>(p_doc, options);
            png = std::make_unique<re2::RE2>(p_png, options);
            rar4 = std::make_unique<re2::RE2>(p_rar4, options);
            rar5 = std::make_unique<re2::RE2>(p_rar5, options);
        }

        std::string name() const override { return "Google RE2"; }

        void scan(const char* data, size_t size, ScanStats& stats) override {
            // RE2 требует StringPiece (легкая обертка)
            re2::StringPiece piece(data, size);

            if (RE2::PartialMatch(piece, *pdf)) stats.pdf++;
            else if (RE2::PartialMatch(piece, *doc)) stats.doc++;
            else if (RE2::PartialMatch(piece, *png)) stats.png++;
            else if (RE2::PartialMatch(piece, *rar4) ||
                RE2::PartialMatch(piece, *rar5)) stats.rar++;
            else stats.other++;
        }
    private:
        //объекты класса re2::RE2 некопируемые + можно инициализировать отложенно
        std::unique_ptr<re2::RE2> pdf, doc, png, rar4, rar5;

};

class BoostScanner : public Scanner {
    public:
        BoostScanner() {
            // Boost по умолчанию хорошо оптимизирован
            pdf.assign("^" + sig_pdf);
            doc.assign("^" + sig_doc);
            png.assign("^" + sig_png);
            rar4.assign("^" + sig_rar4);
            rar5.assign("^" + sig_rar5);
        }

        std::string name() const override { return "Boost.Regex"; }

        void scan(const char* data, size_t size, ScanStats& stats) override {
            // Boost тоже умеет работать с диапазоном итераторов (const char*)
            if (boost::regex_search(data, data + size, pdf)) stats.pdf++;
            else if (boost::regex_search(data, data + size, doc)) stats.doc++;
            else if (boost::regex_search(data, data + size, png)) stats.png++;
            else if (boost::regex_search(data, data + size, rar4) ||
                boost::regex_search(data, data + size, rar5)) stats.rar++;
            else stats.other++;
        }
    private:
        boost::regex pdf, doc, png, rar4, rar5;
};


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

class HsScanner : public Scanner {
    public:
        HsScanner() {
            // Подготовка паттернов (нужно добавить ^ вручную для каждого)
            std::string p_pdf = raw_to_hex(sig_pdf);
            std::string p_doc = raw_to_hex(sig_doc);
            std::string p_png = raw_to_hex(sig_png);
            std::string p_rar4 = raw_to_hex(sig_rar4);
            std::string p_rar5 = raw_to_hex(sig_rar5);

            const char* expressions[] = {
                p_pdf.c_str(), p_doc.c_str(), p_png.c_str(), p_rar4.c_str(), p_rar5.c_str()
            };
            unsigned int ids[] = { ID_PDF, ID_DOC, ID_PNG, ID_RAR4, ID_RAR5 }; // внутренние id для HS
			unsigned int flags[] = { HS_FLAG_DOTALL, HS_FLAG_DOTALL, HS_FLAG_DOTALL, HS_FLAG_DOTALL, HS_FLAG_DOTALL }; //флаги

            hs_compile_error_t* compile_err;
            // Компилируем сразу все паттерны в одну базу
            if (hs_compile_multi(expressions, flags, ids, 5, HS_MODE_BLOCK, nullptr, &db, &compile_err) != HS_SUCCESS) {
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

            if (found_id == ID_PDF) stats.pdf++;
            else if (found_id == ID_DOC) stats.doc++;
            else if (found_id == ID_PNG) stats.png++;
            else if (found_id == ID_RAR4 || found_id == ID_RAR5) stats.rar++;
            else stats.other++;
        }

    private:
        hs_database_t* db = nullptr;
        hs_scratch_t* scratch = nullptr;

        // Внутренние ID для Hyperscan callback
        enum { ID_PDF = 1, ID_DOC, ID_PNG, ID_RAR4, ID_RAR5 };

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