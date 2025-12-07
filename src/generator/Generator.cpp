#include "generator/Generator.h"
#include <fstream>
#include <chrono>
#include <iostream>

UnstructuredFileGenerator::UnstructuredFileGenerator(uint64_t targetSizeMB,
    ContainerType containerType)
    : targetSize(targetSizeMB * 1024 * 1024),
    currentSize(0),
    containerType(containerType) {
    initializeSignatures();
}

bool UnstructuredFileGenerator::generate(const std::string& outputPath) {
    this->outputPath = outputPath;
    tempDir = fs::temp_directory_path() / ("ufg_" +
        std::to_string(std::chrono::high_resolution_clock::now().time_since_epoch().count()));

    if (!fs::create_directories(tempDir)) {
        return false;
    }

    try {
        generateFiles();
        createContainer();
        cleanup();
        return true;        
    }
    catch (...) {
        cleanup();
        return false;
    }
}

UnstructuredFileGenerator::Stats UnstructuredFileGenerator::getStats() const {
    return stats;
}

std::string UnstructuredFileGenerator::getContainerPath() const {
    return outputPath;
}

void UnstructuredFileGenerator::initializeSignatures() {
    // Инициализация генератора случайных чисел
    rng.seed(std::chrono::high_resolution_clock::now().time_since_epoch().count());

    // Текстовые форматы
    signatures.push_back({ "txt", {0x54, 0x65, 0x78, 0x74, 0x20, 0x46, 0x69, 0x6C, 0x65} }); // "Text File"

    // XML и HTML
    signatures.push_back({ "xml", {0x3C, 0x3F, 0x78, 0x6D, 0x6C, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x3D} }); // "<?xml version="
    signatures.push_back({ "html", {0x3C, 0x21, 0x44, 0x4F, 0x43, 0x54, 0x59, 0x50, 0x45, 0x20, 0x68, 0x74, 0x6D, 0x6C, 0x3E} }); // "<!DOCTYPE html>"

    // Изображения
    signatures.push_back({ "png", {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A} });
    signatures.push_back({ "jpg", {0xFF, 0xD8, 0xFF, 0xE0} });
    signatures.push_back({ "gif", {0x47, 0x49, 0x46, 0x38, 0x39, 0x61} });
    signatures.push_back({ "bmp", {0x42, 0x4D} });

    // Аудио
    signatures.push_back({ "wav", {0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x41, 0x56, 0x45} });
    signatures.push_back({ "mp3", {0x49, 0x44, 0x33} }); // ID3 tag

    // Видео
    signatures.push_back({ "mp4", {0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70, 0x6D, 0x70, 0x34, 0x32} });
    signatures.push_back({ "mkv", {0x1A, 0x45, 0xDF, 0xA3} });

    // Документы Office (новые форматы)
    signatures.push_back({ "docx", {0x50, 0x4B, 0x03, 0x04} });
    signatures.push_back({ "xlsx", {0x50, 0x4B, 0x03, 0x04} });
    signatures.push_back({ "pptx", {0x50, 0x4B, 0x03, 0x04} });

    // Документы Office (старые форматы)
    signatures.push_back({ "doc", {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1} });
    signatures.push_back({ "ppt", {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1} });
}

void UnstructuredFileGenerator::generateFiles() {
    // Используем допустимые типы для uniform_int_distribution на MSVC:
    // индексы и байты генерируем как int, затем явно приводим к нужному типу
    std::uniform_int_distribution<int> signatureDist(0, static_cast<int>(signatures.size() - 1));
    std::uniform_int_distribution<uint32_t> sizeDist(20, 1024 * 10); // 20 байт - 10KB

    while (currentSize < targetSize) {
        // Выбираем случайную сигнатуру
        int indexInt = signatureDist(rng);
        size_t index = static_cast<size_t>(indexInt);
        const auto& sig = signatures[index];

        // Генерируем случайный размер файла
        uint32_t fileSize = sig.signature.size() + sizeDist(rng);

        // Создаем файл
        std::string filename = "file_" + std::to_string(stats.fileCount.size()) + "." + sig.extension;
        fs::path filePath = tempDir / filename;

        std::ofstream file(filePath, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Failed to create file: " + filePath.string());
        }

        // Записываем сигнатуру
        file.write(reinterpret_cast<const char*>(sig.signature.data()), sig.signature.size());

        // Записываем случайные данные
        std::vector<uint8_t> randomData(fileSize - sig.signature.size());
        std::uniform_int_distribution<int> byteDist(0, 255);
        for (auto& byte : randomData) {
            byte = static_cast<uint8_t>(byteDist(rng));
        }
        file.write(reinterpret_cast<const char*>(randomData.data()), randomData.size());

        file.close();

        // Обновляем статистику
        stats.fileCount[sig.extension]++;
        currentSize += fileSize;
    }
}

void UnstructuredFileGenerator::createContainer() {
    switch (containerType) {
    case ContainerType::BIN:
        createBinContainer();
        break;
    case ContainerType::ZIP:
        createZipContainer();
        break;
    case ContainerType::PCAP:
        createPcapContainer();
        break;
    }
}

void UnstructuredFileGenerator::createBinContainer() {
    std::ofstream container(outputPath, std::ios::binary);
    if (!container) {
        throw std::runtime_error("Failed to create container file");
    }

    for (const auto& entry : fs::directory_iterator(tempDir)) {
        if (entry.is_regular_file()) {
            std::ifstream file(entry.path(), std::ios::binary);
            if (file) {
                container << file.rdbuf();
            }
        }
    }
}

void UnstructuredFileGenerator::createZipContainer() {
    std::ofstream container(outputPath, std::ios::binary);
    if (!container) {
        throw std::runtime_error("Failed to create ZIP container file");
    }

    // Записываем сигнатуру ZIP файла
    const uint8_t zipHeader[] = { 0x50, 0x4B, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    container.write(reinterpret_cast<const char*>(zipHeader), sizeof(zipHeader));

    for (const auto& entry : fs::directory_iterator(tempDir)) {
        if (entry.is_regular_file()) {
            // Local file header
            const uint8_t localHeader[] = {
                0x50, 0x4B, 0x03, 0x04, // Signature
                0x0A, 0x00,             // Version needed
                0x00, 0x00,             // General purpose bit flag
                0x00, 0x00,             // Compression method (STORED)
                0x00, 0x00,             // Last mod file time
                0x00, 0x00,             // Last mod file date
                0x00, 0x00, 0x00, 0x00, // CRC32 (не проверяется для STORED)
                0x00, 0x00, 0x00, 0x00, // Compressed size
                0x00, 0x00, 0x00, 0x00, // Uncompressed size
                0x00, 0x00,             // File name length
                0x00, 0x00              // Extra field length
            };

            container.write(reinterpret_cast<const char*>(localHeader), sizeof(localHeader));

            // Имя файла
            std::string fileName = entry.path().filename().string();
            uint16_t fileNameLength = static_cast<uint16_t>(fileName.length());
            container.write(reinterpret_cast<const char*>(&fileNameLength), sizeof(fileNameLength) - 1);
            container.write(fileName.c_str(), fileName.length());

            // Размер файла
            uint32_t fileSize = static_cast<uint32_t>(fs::file_size(entry.path()));
            container.seekp(-8, std::ios::cur); // Перемещаемся к месту записи размеров
            container.write(reinterpret_cast<const char*>(&fileSize), sizeof(fileSize)); // Compressed size
            container.write(reinterpret_cast<const char*>(&fileSize), sizeof(fileSize)); // Uncompressed size
            container.seekp(0, std::ios::end); // Возвращаемся в конец

            // Содержимое файла
            std::ifstream file(entry.path(), std::ios::binary);
            if (file) {
                container << file.rdbuf();
            }
        }
    }
}

void UnstructuredFileGenerator::createPcapContainer() {
    std::ofstream container(outputPath, std::ios::binary);
    if (!container) {
        throw std::runtime_error("Failed to create PCAP container file");
    }

    // Global Header PCAP
    const uint8_t globalHeader[] = {
        0xD4, 0xC3, 0xB2, 0xA1, // Magic number
        0x02, 0x00, 0x04, 0x00, // Major, Minor version
        0x00, 0x00, 0x00, 0x00, // TZ offset
        0x00, 0x00, 0x00, 0x00, // Timestamp accuracy
        0xFF, 0xFF, 0x00, 0x00, // Snapshot length
        0x01, 0x00, 0x00, 0x00  // Link-layer header type (Ethernet)
    };
    container.write(reinterpret_cast<const char*>(globalHeader), sizeof(globalHeader));

    for (const auto& entry : fs::directory_iterator(tempDir)) {
        if (entry.is_regular_file()) {
            uint32_t fileSize = fs::file_size(entry.path());

            // Packet header
            const uint8_t packetHeader[] = {
                0x00, 0x00, 0x00, 0x00, // Timestamp seconds
                0x00, 0x00, 0x00, 0x00, // Timestamp microseconds
                0x00, 0x00, 0x00, 0x00, // Captured packet length
                0x00, 0x00, 0x00, 0x00  // Original packet length
            };

            container.write(reinterpret_cast<const char*>(packetHeader), sizeof(packetHeader));

            // Записываем размер в заголовок пакета
            container.seekp(-8, std::ios::cur);
            container.write(reinterpret_cast<const char*>(&fileSize), sizeof(fileSize)); // Captured length
            container.write(reinterpret_cast<const char*>(&fileSize), sizeof(fileSize)); // Original length
            container.seekp(0, std::ios::end);

            // Содержимое файла как payload
            std::ifstream file(entry.path(), std::ios::binary);
            if (file) {
                container << file.rdbuf();
            }
        }
    }
}

void UnstructuredFileGenerator::cleanup() {
    if (fs::exists(tempDir)) {
        fs::remove_all(tempDir);
    }
}
