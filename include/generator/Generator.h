#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <random>

namespace fs = std::filesystem;


struct GenStats {
    // Документы
    int pdf = 0;
    int office_ole = 0; // .doc, .xls, .ppt (Старые)
    int office_xml = 0; // .docx, .xlsx, .pptx (Новые)

    // Архивы
    int zip = 0;        // Чистые .zip
    int rar = 0;

    // Медиа
    int png = 0;
    int jpg = 0;
    int gif = 0;
    int bmp = 0;
    int mkv = 0;        // Matroska container
    int mp3 = 0;

    // Текст / Данные
    int html = 0;
    int xml = 0;
    int json = 0;
    int eml = 0;
    int txt = 0;

    int total_files = 0;
    size_t total_bytes = 0;

    void print() const {
        std::cout << "===== GENERATION REPORT (Ground Truth) =====" << std::endl;
        std::cout << "--- DOCS ---" << std::endl;
        std::cout << "PDF: " << pdf << " | Office OLE (doc/xls/ppt): " << office_ole
            << " | Office XML (docx/xlsx/pptx): " << office_xml << std::endl;

        std::cout << "--- ARCHIVES ---" << std::endl;
        std::cout << "ZIP: " << zip << " | RAR: " << rar << std::endl;

        std::cout << "--- MEDIA ---" << std::endl;
        std::cout << "PNG: " << png << " | JPG: " << jpg << " | GIF: " << gif
            << " | BMP: " << bmp << " | MKV: " << mkv << " | MP3: " << mp3 << std::endl;

        std::cout << "--- TEXT/DATA ---" << std::endl;
        std::cout << "HTML: " << html << " | XML: " << xml << " | JSON: " << json
            << " | EML: " << eml << " | TXT: " << txt << std::endl;

        std::cout << "----------------" << std::endl;
        std::cout << "Total Files: " << total_files
            << " | Total Size: " << (total_bytes / 1024 / 1024) << " MB" << std::endl;
        std::cout << "============================================" << std::endl;
    }
};


class DataSetGenerator {
    public:
        enum class ContainerType {
            BIN,
            ZIP,
            PCAP,
            FOLDER

        };

        DataSetGenerator();

        GenStats generate(const std::string& output_path, size_t total_size_mb,
		    ContainerType container_type = ContainerType::BIN);

    private:
        struct FileType {
            std::string extension;
            std::string signature;
            bool is_text; // true = использовать словарь, false = бинарный шум
		};

        struct ZipEntry {
            std::string name;
            uint32_t crc32;
            uint32_t size;
            uint32_t offset;
        };

        std::vector<FileType> file_types;
		std::mt19937 rng;

		// Словарь для текстовых файлов
		static const std::vector<std::string> dictionary;

		// Внутренние методы генерации контента
		void generate_content(std::ostream& out, size_t size, const FileType& type);


		void generate_folder(const std::string& dir, size_t total_bytes, GenStats& stats);
		void generate_zip(const std::string& dir, size_t total_bytes, GenStats& stats);
		void generate_bin(const std::string& filepath, size_t total_bytes, GenStats& stats);
		void generate_pcap(const std::string& filepath, size_t total_bytes, GenStats& stats);

		uint32_t calculate_CRC32(const char* data, size_t length); // Для ZIP

        // Стратегии заполенения
        void fill_binary(std::ostream& out, size_t size, const std::string& signature);
		void fill_text(std::ostream& out, size_t size);
		void fill_email(std::ostream& out, size_t size);
		void fill_json(std::ostream& out, size_t size);
		void fill_ole(std::ostream& out, size_t size, const std::string& marker);
		void fill_openxml(std::ostream& out, size_t size, const std::string& marker);

        void update_stats(GenStats& stats, const std::string& ext);
};
