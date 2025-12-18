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
    int pdf = 0;
    int doc = 0;      // Old Office (OLE2)
    int zip = 0;      // ZIP + DOCX + XLSX
    int png = 0;
    int rar = 0;
    int other = 0;    // txt, html, xml, json, eml, bmp, jpg...
    int total_files = 0;
    size_t total_bytes = 0;

    void print() const {
        std::cout << "===== GENERATION REPORT =====" << std::endl;
        std::cout << "PDF: " << pdf << " | DOC: " << doc << " | ZIP/DOCX: " << zip
            << " | PNG: " << png << " | RAR: " << rar
            << " | Other: " << other << std::endl;
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

        std::vector<FileType> file_types;
		std::mt19937 rng;

		// Словарь для текстовых файлов
		static const std::vector<std::string> dictionary;

		// Внутренние методы генерации контента
		void generate_content(std::ostream& out, size_t size, const FileType& type);


		void generate_folder(const std::string& dir, size_t total_bytes, GenStats& stats);


        // Стратегии заполенения
        void fill_binary(std::ostream& out, size_t size, const std::string& signature);
		void fill_text(std::ostream& out, size_t size);
		void fill_email(std::ostream& out, size_t size);
		void fill_json(std::ostream& out, size_t size);

        void update_stats(GenStats& stats, const std::string& ext);
};



/*
class UnstructuredFileGenerator {
public:
    struct Stats {
        std::map<std::string, int> fileCount;
    };

    enum class ContainerType {
        BIN,
        ZIP,
        PCAP
    };

    // Конструктор с параметрами
    explicit UnstructuredFileGenerator(uint64_t targetSizeMB = 400,
        ContainerType containerType = ContainerType::BIN);

    // Основной метод генерации
    bool generate(const std::string& outputPath);

    // Получение статистики
    Stats getStats() const;

    // Получение пути к контейнеру
    std::string getContainerPath() const;

private:
    struct FileSignature {
        std::string extension;
        std::vector<uint8_t> signature;
    };

    uint64_t targetSize;
    uint64_t currentSize;
    ContainerType containerType;
    std::string outputPath;
    fs::path tempDir;
    std::vector<FileSignature> signatures;
    Stats stats;
    std::mt19937 rng;

    // Инициализация сигнатур
    void initializeSignatures();

    // Генерация файлов
    void generateFiles();

    // Создание контейнера
    void createContainer();

    // Создание бинарного контейнера
    void createBinContainer();

    // Создание ZIP контейнера
    void createZipContainer();

    // Создание PCAP контейнера
    void createPcapContainer();

    // Очистка временных файлов
    void cleanup();

    // Вспомогательные функции для ZIP
    uint32_t calculateCRC32(const std::vector<uint8_t>& data);
};

*/