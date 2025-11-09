#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#include <re2/re2.h>
#include <boost/regex.hpp>
#include <boost/algorithm/string/replace.hpp> // для экранирования спецсимволов в boost
#include <regex>
#include <hs/hs.h> // Hyperscan

namespace fs = std::filesystem;

// Сигнатуры для проверки (magic bytes)
const std::string pdf_header = "%PDF";
const std::string doc_header = "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1";
const std::string png_header = "\x89PNG\r\n\x1A\n";
const std::string rar4_header = "\x52\x61\x72\x21\x1A\x07\x00";
const std::string rar5_header = "\x52\x61\x72\x21\x1A\x07\x01\x00";

// RE2 (Google)
bool check_file_signature_re2(const std::string& file_path, const std::string& signature, size_t size, re2::RE2::Options& opt) {
    re2::RE2 regex("^" + signature, opt); // ^ - обязательно начало файла
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Ошибка открытия файла (RE2): " << file_path << std::endl;
        return false;
    }

    std::vector<char> buffer(size);
    file.read(buffer.data(), size);
    file.close();

    re2::StringPiece data(buffer.data(), size);
    return RE2::PartialMatch(data, regex);
}

// Boost.Regex: тут надо экранировать спецсимволы вручную, т.к. escape нет
bool check_file_signature_boost(const std::string& file_path, const std::string& signature, size_t size) {
    // Экранирую все спецсимволы boost-овским replace_all (см. доку boost::regex)
    std::string escaped_sig = signature;
    boost::replace_all(escaped_sig, "\\", "\\\\");
    boost::replace_all(escaped_sig, "^", "\\^");
    boost::replace_all(escaped_sig, ".", "\\.");
    boost::replace_all(escaped_sig, "$", "\\$");
    boost::replace_all(escaped_sig, "|", "\\|");
    boost::replace_all(escaped_sig, "(", "\\(");
    boost::replace_all(escaped_sig, ")", "\\)");
    boost::replace_all(escaped_sig, "[", "\\[");
    boost::replace_all(escaped_sig, "]", "\\]");
    boost::replace_all(escaped_sig, "*", "\\*");
    boost::replace_all(escaped_sig, "+", "\\+");
    boost::replace_all(escaped_sig, "?", "\\?");
    boost::replace_all(escaped_sig, "{", "\\{");
    boost::replace_all(escaped_sig, "}", "\\}");

    boost::regex regex("^" + escaped_sig, boost::regex::perl | boost::regex::nosubs);

    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Ошибка открытия файла (Boost.Regex): " << file_path << std::endl;
        return false;
    }

    std::vector<char> buffer(size);
    file.read(buffer.data(), size);
    file.close();

    std::string data(buffer.data(), size);
    return boost::regex_search(data, regex);
}

// std::regex: почти то же самое, что и boost, но другой синтаксис
bool check_file_signature_std(const std::string& file_path, const std::string& signature, size_t size) {
    // Экранирую спецсимволы вручную (см. ECMAScript синтаксис)
    std::string escaped_sig = signature;
    std::string specials = R"(\^.$|()[]*+?{})";
    for (char c : specials) {
        std::string s(1, c);
        std::string r = "\\" + s;
        size_t pos = 0;
        while ((pos = escaped_sig.find(s, pos)) != std::string::npos) {
            escaped_sig.replace(pos, 1, r);
            pos += r.size();
        }
    }

    std::regex regex("^" + escaped_sig, std::regex::ECMAScript);

    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Ошибка открытия файла (std::regex): " << file_path << std::endl;
        return false;
    }

    std::vector<char> buffer(size);
    file.read(buffer.data(), size);
    file.close();

    std::string data(buffer.data(), size);
    return std::regex_search(data, regex);
}

bool check_file_signature_hs(const std::string& file_path, const std::string& signature, size_t size) {
    hs_database_t* database = nullptr; // Указатель на скомпилированную базу данных регулярных выражений
    hs_compile_error_t* compile_err; // Указатель на ошибку компиляции
    hs_scratch_t* scratch = nullptr; // Указатель на область памяти для выполнения поиска

    std::string pattern = "^" + signature; // ^ - обязательно начало файла
    if (hs_compile(pattern.c_str(), HS_FLAG_DOTALL, HS_MODE_BLOCK, nullptr, &database, &compile_err) != HS_SUCCESS) {
        std::cerr << "Ошибка компиляции шаблона Hyperscan: " << compile_err->message << std::endl;
        hs_free_compile_error(compile_err);
        return false;
    }

    if (hs_alloc_scratch(database, &scratch) != HS_SUCCESS) {
        std::cerr << "Ошибка выделения памяти для Hyperscan." << std::endl;
        hs_free_database(database);
        return false;
    }

    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Ошибка открытия файла (Hyperscan): " << file_path << std::endl;
        hs_free_scratch(scratch);
        hs_free_database(database);
        return false;
	}
    std::vector<char> buffer(size);
	file.read(buffer.data(), size);
    file.close();
    
    bool matched = false;

	// hs_scan требует callback-функцию для обработки совпадений
    auto on_match = [](unsigned int id,                     // номер совпавшего шаблона
		               unsigned long long from,             // смещение начала совпадения
		               unsigned long long to,              // смещение конца совпадения
		               unsigned int flags,                  // флаги совпадения
                       void* context) -> int {
        bool* matched_ptr = static_cast<bool*>(context);
        *matched_ptr = true;
        return 0; // Продолжаем поиск
    };

    if (hs_scan(database, buffer.data(), size, 0, scratch, on_match, &matched) != HS_SUCCESS) {
        std::cerr << "Ошибка сканирования файла Hyperscan." << std::endl;
    }
    hs_free_scratch(scratch);
    hs_free_database(database);
	return matched;

}
// Основная функция подсчёта файлов по сигнатурам для всех трёх regex-движков
void count_files(const std::string& directory, re2::RE2::Options& opt) {
    // Счётчики для каждого движка
    int pdf_count_re2 = 0, docx_count_re2 = 0, png_count_re2 = 0, rar_count_re2 = 0, other_count_re2 = 0;
    int pdf_count_boost = 0, docx_count_boost = 0, png_count_boost = 0, rar_count_boost = 0, other_count_boost = 0;
    int pdf_count_std = 0, docx_count_std = 0, png_count_std = 0, rar_count_std = 0, other_count_std = 0;
    int pdf_count_hs = 0, docx_count_hs = 0, png_count_hs = 0, rar_count_hs = 0, other_count_hs = 0;

    try {
        for (const auto& entry : fs::directory_iterator(directory)) {
            if (fs::is_regular_file(entry)) {
                const std::string file_path = entry.path().string();

                // std::regex
                bool matched_std = false;
                if (check_file_signature_std(file_path, pdf_header, 4)) { pdf_count_std++; matched_std = true; }
                else if (check_file_signature_std(file_path, doc_header, 8)) { docx_count_std++; matched_std = true; }
                else if (check_file_signature_std(file_path, png_header, 8)) { png_count_std++; matched_std = true; }
                else if (check_file_signature_std(file_path, rar4_header, 7) ||
                         check_file_signature_std(file_path, rar5_header, 8)) {
                    rar_count_std++; matched_std = true;
                }
                else { other_count_std++; }

            }
        }
        for (const auto& entry : fs::directory_iterator(directory)) {
            if (fs::is_regular_file(entry)) {
                const std::string file_path = entry.path().string();

                // RE2
                bool matched_re2 = false;
                if (check_file_signature_re2(file_path, pdf_header, 4, opt)) { pdf_count_re2++; matched_re2 = true; }
                else if (check_file_signature_re2(file_path, doc_header, 8, opt)) { docx_count_re2++; matched_re2 = true; }
                else if (check_file_signature_re2(file_path, png_header, 8, opt)) { png_count_re2++; matched_re2 = true; }
                else if (check_file_signature_re2(file_path, rar4_header, 7, opt) ||
                    check_file_signature_re2(file_path, rar5_header, 8, opt)) {
                    rar_count_re2++; matched_re2 = true;
                }
                else { other_count_re2++; }
            }
        }
        for (const auto& entry : fs::directory_iterator(directory)) {
            if (fs::is_regular_file(entry)) {
                const std::string file_path = entry.path().string();

                // Boost.Regex
                bool matched_boost = false;
                if (check_file_signature_boost(file_path, pdf_header, 4)) { pdf_count_boost++; matched_boost = true; }
                else if (check_file_signature_boost(file_path, doc_header, 8)) { docx_count_boost++; matched_boost = true; }
                else if (check_file_signature_boost(file_path, png_header, 8)) { png_count_boost++; matched_boost = true; }
                else if (check_file_signature_boost(file_path, rar4_header, 7) ||
                    check_file_signature_boost(file_path, rar5_header, 8)) {
                    rar_count_boost++; matched_boost = true;
                }
                else { other_count_boost++; }
            }
        }
        for (const auto& entry : fs::directory_iterator(directory)) {
            if (fs::is_regular_file(entry)) {
                const std::string file_path = entry.path().string();

                // hyperscan
                bool matched_hs= false;
                if (check_file_signature_boost(file_path, pdf_header, 4)) { pdf_count_hs++; matched_hs = true; }
                else if (check_file_signature_hs(file_path, doc_header, 8)) { docx_count_hs++; matched_hs = true; }
                else if (check_file_signature_hs(file_path, png_header, 8)) { png_count_hs++; matched_hs = true; }
                else if (check_file_signature_hs(file_path, rar4_header, 7) ||
                    check_file_signature_hs(file_path, rar5_header, 8)) {
                    rar_count_hs++; matched_hs = true;
                }
                else { other_count_hs++; }
            }
        }

    }
    catch (const fs::filesystem_error& ex) {
        std::cerr << "Ошибка файловой системы: " << ex.what() << std::endl;
    }

    // Выводим результаты для каждого движка отдельно
    std::cout << "===== RE2 Results =====" << std::endl;
    std::cout << "PDF: " << pdf_count_re2 << "\nDOC: " << docx_count_re2 << "\nPNG: " << png_count_re2
        << "\nRAR: " << rar_count_re2 << "\nOther: " << other_count_re2 << std::endl;

    std::cout << "===== Boost.Regex Results =====" << std::endl;
    std::cout << "PDF: " << pdf_count_boost << "\nDOC: " << docx_count_boost << "\nPNG: " << png_count_boost
        << "\nRAR: " << rar_count_boost << "\nOther: " << other_count_boost << std::endl;

    std::cout << "===== std::regex Results =====" << std::endl;
    std::cout << "PDF: " << pdf_count_std << "\nDOC: " << docx_count_std << "\nPNG: " << png_count_std
        << "\nRAR: " << rar_count_std << "\nOther: " << other_count_std << std::endl;

    std::cout << "===== std::HyperScan Results =====" << std::endl;
    std::cout << "PDF: " << pdf_count_hs << "\nDOC: " << docx_count_hs << "\nPNG: " << png_count_hs
        << "\nRAR: " << rar_count_hs << "\nOther: " << other_count_hs << std::endl;
}

int main() {
    re2::RE2::Options options;
    options.set_encoding(re2::RE2::Options::EncodingLatin1);
    std::string directory = R"(C:\projects\test_auto\data)"; // путь к папке с файлами для теста

    try {
        if (!fs::exists(directory)) {
            std::cerr << "Директория не существует: " << directory << std::endl;
            return 1;
        }
        if (!fs::is_directory(directory)) {
            std::cerr << "Путь не является директорией: " << directory << std::endl;
            return 1;
        }
        count_files(directory, options);
    }
    catch (const std::exception& ex) {
        std::cerr << "Ошибка: " << ex.what() << std::endl;
        return 1;
    }
    return 0;
}
