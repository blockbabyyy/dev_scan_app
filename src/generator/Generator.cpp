#include "generator/Generator.h"
#include "Signatures.h"
#include <fstream>
#include <chrono>
#include <iostream>
#include <cstring>
#include <sstream>

// Словарь для текстовых файлов
const std::vector<std::string> DataSetGenerator::dictionary = {
    // HTML/XML тэги
    "<div>", "<span>", "class=", "id=", "href=", "<html>", "<body>", "<script>",
    "<?xml", "<root>", "<item>", "version=", "encoding=", "UTF-8",
    // общие слова
    "lorem", "ipsum", "dolor", "sit", "amet", "consectetur", "adipiscing", "elit",
    "the", "and", "is", "in", "at", "of", "to", "for", "with", "on",
    // Ключевые слова кода
    "function", "return", "var", "const", "if", "else", "for", "while",
    // Обманки
    "%PDF-", "PK", "Rar!", "PNG", "JFIF", "Exif", // Ловушки в тексте
    "user@example.com", "admin@localhost", "http://", "https://"
};


void DataSetGenerator::update_stats(GenStats& stats, const std::string& ext) {
    stats.total_files++;

    if (ext == ".pdf") stats.pdf++;
    else if (ext == ".doc" || ext == ".xls" || ext == ".ppt") stats.office_ole++;
    else if (ext == ".docx" || ext == ".xlsx" || ext == ".pptx") stats.office_xml++;
    else if (ext == ".zip") stats.zip++;
    else if (ext == ".rar") stats.rar++;
    else if (ext == ".png") stats.png++;
    else if (ext == ".jpg") stats.jpg++;
    else if (ext == ".gif") stats.gif++;
    else if (ext == ".bmp") stats.bmp++;
    else if (ext == ".mkv") stats.mkv++;
    else if (ext == ".mp3") stats.mp3++;
    else if (ext == ".html") stats.html++;
    else if (ext == ".xml") stats.xml++;
    else if (ext == ".json") stats.json++;
    else if (ext == ".eml") stats.eml++;
    else if (ext == ".txt") stats.txt++;
}

// Простая таблица CRC32 для ZIP
static uint32_t crc32_table[256];
static bool crc_initialized = false;

static void init_crc32() {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) c = (c & 1) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
        crc32_table[i] = c;
    }
    crc_initialized = true;
}

uint32_t DataSetGenerator::calculate_CRC32(const char* data, size_t length) {
    if (!crc_initialized) init_crc32();
    uint32_t c = 0xFFFFFFFF;
    for (size_t i = 0; i < length; ++i) {
        c = crc32_table[(c ^ (uint8_t)data[i]) & 0xFF] ^ (c >> 8);
    }
    return c ^ 0xFFFFFFFF;
}

DataSetGenerator::DataSetGenerator() {
    std::random_device rd;
    rng.seed(rd());

    // Инициализация поддерживаемых типов
    // --- TEXT ---
    file_types.push_back({ ".txt",  "", true }); // 
    file_types.push_back({ ".html", "<html>", true }); // Добавим явную сигнатуру для простоты regex
    file_types.push_back({ ".xml",  "<?xml", true });
    file_types.push_back({ ".json", "{", true });      // JSON начинается с {
    file_types.push_back({ ".eml",  "", true });  // EML начинается с заголовка

    // --- DOCS ---
    file_types.push_back({ ".pdf",  Sig::Bin::PDF, false });
	// OLE (Old Office) - одна сигнатура на всех // ToDo: нужны более комплексные сигнатуры для старых офисов
    file_types.push_back({ ".doc",  Sig::Bin::OLE, false });
    file_types.push_back({ ".xls",  Sig::Bin::OLE, false });
    file_types.push_back({ ".ppt",  Sig::Bin::OLE, false });
	// ZIP-based (New Office) // ToDo: нужны более комплексные сигнатуры для новых офисов
    file_types.push_back({ ".docx", Sig::Bin::ZIP, false });
    file_types.push_back({ ".xlsx", Sig::Bin::ZIP, false });
    file_types.push_back({ ".pptx", Sig::Bin::ZIP, false });

    // --- MEDIA ---
    file_types.push_back({ ".png",  Sig::Bin::PNG, false });
    file_types.push_back({ ".jpg",  Sig::Bin::JPG, false });
    file_types.push_back({ ".gif",  Sig::Bin::GIF, false });
    file_types.push_back({ ".bmp",  Sig::Bin::BMP, false });
    file_types.push_back({ ".mkv",  Sig::Bin::MKV, false });
    file_types.push_back({ ".mp3",  Sig::Bin::MP3, false });

    // --- ARCHIVES ---
    file_types.push_back({ ".zip",  Sig::Bin::ZIP, false });
    file_types.push_back({ ".rar",  Sig::Bin::RAR4, false });
	file_types.push_back({ ".rar",  Sig::Bin::RAR5, false });
};

GenStats DataSetGenerator::generate(const std::string& output_path, size_t total_size_mb,
    ContainerType type) {

    size_t target_size_bytes = total_size_mb * 1024 * 1024;
    GenStats stats;

    switch (type) {
        case ContainerType::FOLDER: generate_folder(output_path, target_size_bytes, stats); break;
        case ContainerType::ZIP: generate_zip(output_path, target_size_bytes, stats); break;
        case ContainerType::PCAP: generate_pcap(output_path, target_size_bytes, stats); break;
        case ContainerType::BIN: generate_bin(output_path, target_size_bytes, stats); break;
    }
    
    stats.total_bytes = target_size_bytes;
    return stats;
};


void DataSetGenerator::generate_content(std::ostream& out, size_t size, const FileType& type) {
    // 1. Пишем сигнатуру (если есть)
    if (!type.signature.empty()) {
        out.write(type.signature.data(), type.signature.size());
    }

    size_t remaining = (size > type.signature.size()) ? (size - type.signature.size()) : 0;
    if (remaining == 0) return;

    // 2. Заполняем тело
    if (type.is_text) {
        if (type.extension == ".json") fill_json(out, remaining);
        else if (type.extension == ".eml") fill_email(out, remaining);
        else fill_text(out, remaining);
    }
    else if (type.extension == ".doc") fill_ole(out, remaining, Sig::Bin::OLE_WORD);
    else if (type.extension == ".xls") fill_ole(out, remaining, Sig::Bin::OLE_XL);
    else if (type.extension == ".ppt") fill_ole(out, remaining, Sig::Bin::OLE_PPT);

    else if (type.extension == ".docx") fill_openxml(out, remaining, Sig::Bin::XML_WORD);
    else if (type.extension == ".xlsx") fill_openxml(out, remaining, Sig::Bin::XML_XL);
    else if (type.extension == ".pptx") fill_openxml(out, remaining, Sig::Bin::XML_PPT);
    else {
        fill_binary(out, remaining, type.signature);
    }
}

// Генераторы контейнеров
void DataSetGenerator::generate_folder(const std::string& dir, size_t totalBytes, GenStats& stats) {

    if (!fs::exists(dir)) fs::create_directories(dir);
    size_t currentBytes = 0;
    int index = 0;
    std::uniform_int_distribution<int> typeDist(0, file_types.size() - 1);
    std::discrete_distribution<> sizeDist({ 70, 20, 10 });

    while (currentBytes < totalBytes) {
        const auto& ftype = file_types[typeDist(rng)];

        // Размер
        size_t fsize = 0;
        int cat = sizeDist(rng);
        if (cat == 0) fsize = std::uniform_int_distribution<size_t>(1024, 100 * 1024)(rng);
        else if (cat == 1) fsize = std::uniform_int_distribution<size_t>(100 * 1024, 5 * 1024 * 1024)(rng);
        else fsize = std::uniform_int_distribution<size_t>(5 * 1024 * 1024, 25 * 1024 * 1024)(rng);

        if (currentBytes + fsize > totalBytes + (10 * 1024 * 1024)) fsize = (totalBytes > currentBytes) ? totalBytes - currentBytes : 1024;
        if (fsize == 0) fsize = 1024;

        std::string fname = dir + "/file_" + std::to_string(index++) + ftype.extension;
        std::ofstream ofs(fname, std::ios::binary);
        if (ofs) {
            generate_content(ofs, fsize, ftype);
            update_stats(stats, ftype.extension); // <-- Считаем файл
            currentBytes += fsize;
        }

        // Прогресс
        if (index % 50 == 0) std::cout << "\rGenerating: " << (currentBytes / 1024 / 1024) << " MB" << std::flush;
    }
    std::cout << std::endl;
}

void DataSetGenerator::generate_zip(const std::string& filename, size_t total_bytes, GenStats& stats) {
    std::ofstream zip(filename, std::ios::binary);
    size_t current_bytes = 0;
    int index = 0;
    std::vector<DataSetGenerator::ZipEntry> entries;
    std::uniform_int_distribution<int> type_dist(0, file_types.size() - 1);

    std::cout << "[ZIP] Generating uncompresased archive: " << filename << std::endl;

    while (current_bytes < total_bytes) {
        const auto& ftype = file_types[type_dist(rng)];
        size_t fsize = std::uniform_int_distribution<size_t>(100, 200 * 1024)(rng); // Небольшие файлы для ZIP
        std::string fname = "file_" + std::to_string(index++) + ftype.extension;

        // Генерируем контент в память, чтобы посчитать CRC32
        std::stringstream buffer;
        generate_content(buffer, fsize, ftype);
		update_stats(stats, ftype.extension);

        std::string data = buffer.str();
        uint32_t crc = calculate_CRC32(data.data(), data.size());

        // Сохраняем метаданные
        ZipEntry entry;
        entry.name = fname;
        entry.crc32 = crc;
        entry.size = (uint32_t)data.size();
        entry.offset = (uint32_t)zip.tellp();
        entries.push_back(entry);

        // Пишем Local File Header
        // Сигнутура (0x04034b50)
        uint32_t sig = 0x04034b50; zip.write((char*)&sig, 4);
        uint16_t ver = 20; zip.write((char*)&ver, 2); // версия
        uint16_t flg = 0;  zip.write((char*)&flg, 2); // флаги
        uint16_t meth = 0; zip.write((char*)&meth, 2); // метод (0 = хранение)
        uint16_t time = 0; zip.write((char*)&time, 2); // время
        uint16_t date = 0; zip.write((char*)&date, 2); // дата
        zip.write((char*)&entry.crc32, 4);
        zip.write((char*)&entry.size, 4); // размер сжатого (если да)
        zip.write((char*)&entry.size, 4); // несжатого
        uint16_t name_len = (uint16_t)fname.size(); // длина имени
        zip.write((char*)&name_len, 2);
        uint16_t extra_len = 0; // длина доп. поля
        zip.write((char*)&extra_len, 2);
        zip.write(fname.c_str(), fname.size());

        // Пишем данные
        zip.write(data.data(), data.size());

        current_bytes += data.size();
    }

    // Пишем Central Directory
    uint32_t cd_start = (uint32_t)zip.tellp();
    for (const auto& e : entries) {
        uint32_t sig = 0x02014b50; zip.write((char*)&sig, 4);
        uint16_t ver = 20; zip.write((char*)&ver, 2);
        zip.write((char*)&ver, 2); // 
        uint16_t flg = 0; zip.write((char*)&flg, 2);
        uint16_t meth = 0; zip.write((char*)&meth, 2);
        uint32_t dummy = 0; zip.write((char*)&dummy, 4);
        zip.write((char*)&e.crc32, 4);
        zip.write((char*)&e.size, 4);
        zip.write((char*)&e.size, 4);
        uint16_t nameLen = (uint16_t)e.name.size(); zip.write((char*)&nameLen, 2);
        uint16_t extra = 0; zip.write((char*)&extra, 2);
        zip.write((char*)&extra, 2); // Comment len
        zip.write((char*)&extra, 2); // Disk start
        zip.write((char*)&extra, 2); // Internal attr
        uint32_t extAttr = 0; zip.write((char*)&extAttr, 4);
        zip.write((char*)&e.offset, 4); // Local header offset
        zip.write(e.name.c_str(), e.name.size());
    }
    uint32_t cd_size = (uint32_t)zip.tellp() - cd_start;

    // End of Central Directory Record
    uint32_t cd_sig_end = 0x06054b50; zip.write((char*)&cd_sig_end, 4);
    uint16_t disk = 0; zip.write((char*)&disk, 2);
    zip.write((char*)&disk, 2);
    uint16_t entries_num = (uint16_t)entries.size();
    zip.write((char*)&entries_num, 2); // Entries on this disk
    zip.write((char*)&entries_num, 2); // Total entries
    zip.write((char*)&cd_size, 4);
    zip.write((char*)&cd_start, 4);
    uint16_t comment_len = 0; zip.write((char*)&comment_len, 2);
}

void DataSetGenerator::generate_pcap(const std::string& filename, size_t total_bytes, GenStats& stats) {
    std::ofstream pcap(filename, std::ios::binary);

    // Global Header
    uint32_t magic = 0xa1b2c3d4; pcap.write((char*)&magic, 4);
    uint16_t verMaj = 2; pcap.write((char*)&verMaj, 2);
    uint16_t verMin = 4; pcap.write((char*)&verMin, 2);
    uint32_t zone = 0; pcap.write((char*)&zone, 4);
    uint32_t sigfigs = 0; pcap.write((char*)&sigfigs, 4);
    uint32_t snaplen = 65535; pcap.write((char*)&snaplen, 4);
    uint32_t linktype = 1; // Ethernet
    pcap.write((char*)&linktype, 4);

    size_t currentBytes = 0;
    std::uniform_int_distribution<int> typeDist(0, file_types.size() - 1);

    std::cout << "[PCAP] Generating network traffic dump: " << filename << std::endl;

    while (currentBytes < total_bytes) {
        const auto& ftype = file_types[typeDist(rng)];
        // В PCAP пакеты обычно небольшие, разобьем "файл" на 1-2 пакета или запишем целиком (jumbo frame style)
        // Для теста регулярок лучше писать целиком как payload, чтобы сигнатура была непрерывной
        size_t fsize = std::uniform_int_distribution<size_t>(64, 1500)(rng);

        std::stringstream buffer;
        generate_content(buffer, fsize, ftype);
		update_stats(stats, ftype.extension);
        std::string payload = buffer.str();

        // Packet Header
        uint32_t ts_sec = 0x657755AA; // Fake timestamp
        uint32_t ts_usec = 0;
        uint32_t incl_len = (uint32_t)payload.size(); // +14 байт Ethernet header если надо, но для regex неважно
        uint32_t orig_len = incl_len;

        pcap.write((char*)&ts_sec, 4);
        pcap.write((char*)&ts_usec, 4);
        pcap.write((char*)&incl_len, 4);
        pcap.write((char*)&orig_len, 4);

        // Payload (наш сгенерированный файл)
        pcap.write(payload.data(), payload.size());

        currentBytes += payload.size();
    }
}

void DataSetGenerator::generate_bin(const std::string& filename, size_t totalBytes, GenStats& stats) {
    std::ofstream bin(filename, std::ios::binary);
    size_t currentBytes = 0;
    std::uniform_int_distribution<int> typeDist(0, file_types.size() - 1);

    std::cout << "[BIN] Generating custom binary dump: " << filename << std::endl;

    while (currentBytes < totalBytes) {
        const auto& ftype = file_types[typeDist(rng)];
        size_t fsize = std::uniform_int_distribution<size_t>(1024, 1024 * 1024)(rng);

        std::stringstream buffer;
        generate_content(buffer, fsize, ftype);
		update_stats(stats, ftype.extension);
        std::string data = buffer.str();

        // Проприетарный заголовок: [MAGIC 4B][TYPE 4B][SIZE 8B]
        uint32_t magic = 0xDEADBEEF;
        uint32_t type = 1;
        uint64_t size = data.size();

        bin.write((char*)&magic, 4);
        bin.write((char*)&type, 4);
        bin.write((char*)&size, 8);
        bin.write(data.data(), data.size());

        currentBytes += data.size();
    }
}


// Стратегии заполнения
void DataSetGenerator::fill_text(std::ostream& out, size_t size) {
    std::uniform_int_distribution<int> wordIdx(0, dictionary.size() - 1);
    std::string buffer;
    buffer.reserve(4096);

    while (size > 0) {
        const std::string& word = dictionary[wordIdx(rng)];

        // Формируем кусок
        std::string chunk = word + " ";

        // Если кусок больше, чем осталось места - обрезаем его
        if (chunk.size() > size) {
            chunk.resize(size);
        }

        buffer += chunk;

        // Сбрасываем буфер на диск, если он заполнился или если это финал
        if (buffer.size() >= 4096 || buffer.size() == size) {
            out.write(buffer.data(), buffer.size());

            // Защита от переполнения:
            if (size >= buffer.size()) {
                size -= buffer.size();
            }
            else {
                size = 0; // На всякий случай, хотя логика выше должна предотвратить
            }

            buffer.clear();
        }
    }
}

void DataSetGenerator::fill_json(std::ostream& out, size_t size) {
    out << "{\"data\": [";
    size_t written = 10;

    // Генерируем псевдо-JSON
    while (size > written + 2) {
        std::string val = "\"" + dictionary[std::uniform_int_distribution<int>(0, dictionary.size() - 1)(rng)] + "\",";
        if (val.size() > size - written - 2) break;
        out.write(val.data(), val.size());
        written += val.size();
    }
    out << "]}";
}

void DataSetGenerator::fill_email(std::ostream& out, size_t size) {
    std::string header =
        "Date: Mon, 16 Dec 2024 10:00:00 +0000\r\n"
        "From: generator <test@domain.com>\r\n"
        "To: user <user@local.host>\r\n"
        "Subject: Automated Test Data\r\n"
        "MIME-Version: 1.0\r\n\r\n";

    out.write(header.data(), std::min(size, header.size()));
    size_t remaining = (size > header.size()) ? size - header.size() : 0;

    fill_text(out, remaining); // Тело письма - просто текст
}

void DataSetGenerator::fill_binary(std::ostream& out, size_t size, const std::string& signatureToAvoid) {
    // Буфер 4КБ
    std::vector<char> buffer(4096);
    std::uniform_int_distribution<int> byteDist(0, 255);

    // Генерируем 1 блок шума
    for (auto& b : buffer) b = static_cast<char>(byteDist(rng));

    // Иногда вставляем байты, похожие на сигнатуру PDF или ZIP, но битые
    if (buffer.size() > 10) {
        buffer[10] = 0x50; buffer[11] = 0x4B; buffer[12] = 0x00; buffer[13] = 0x00; // Fake ZIP
        buffer[50] = 0x25; buffer[51] = 0x50; buffer[52] = 0x44; buffer[53] = 0x46; // Fake PDF
    }

    size_t totalWritten = 0;
    while (totalWritten < size) {
        size_t toWrite = std::min(size - totalWritten, buffer.size());

        // Немного меняем буфер каждый раз (XOR), чтобы не был идеальный копипаст (против дедупликации)
        buffer[totalWritten % 256] ^= 0xFF;

        out.write(buffer.data(), toWrite);
        totalWritten += toWrite;
    }
}

void DataSetGenerator::fill_ole(std::ostream& out, size_t size, const std::string& marker) {
    std::vector<char> buffer(512, 0);
    // Заполним мусором
    for (auto& c : buffer) c = rng() % 255;

    // Вставляем маркер (например, "WordDocument") в случайное место заголовка
    size_t pos = 100 + (rng() % 200);
    if (pos + marker.size() < buffer.size()) {
        std::memcpy(&buffer[pos], marker.data(), marker.size());
    }

    size_t toWrite = std::min(size, buffer.size());
    out.write(buffer.data(), toWrite);

    if (size > toWrite) {
        fill_binary(out, size - toWrite, ""); // Остальное добиваем шумом
    }
}
void DataSetGenerator::fill_openxml(std::ostream& out, size_t size, const std::string& marker) {
    std::string internalFileName = marker + "core.xml"; // например word/core.xml

    // Local File Header Signature
    uint32_t sig = 0x04034b50;
    out.write((char*)&sig, 4);

    // Min version (20), Flags (0), Method (0 - Store)
    char headerPart[] = {
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, // Ver, Flags, Method
        0x00, 0x00, 0x00, 0x00,             // Time, Date
        0x00, 0x00, 0x00, 0x00,             // CRC32
        0x00, 0x00, 0x00, 0x00,             // Comp Size
        0x00, 0x00, 0x00, 0x00              // Uncomp Size
    };
    out.write(headerPart, sizeof(headerPart));

    uint16_t nameLen = (uint16_t)internalFileName.size();
    uint16_t extraLen = 0;
    out.write((char*)&nameLen, 2);
    out.write((char*)&extraLen, 2);

    // Имя файла (САМОЕ ВАЖНОЕ ДЛЯ ДЕТЕКЦИИ)
    out.write(internalFileName.data(), internalFileName.size());

    // Данные файла
    size_t headerSize = 4 + sizeof(headerPart) + 4 + internalFileName.size();
    size_t remaining = (size > headerSize) ? size - headerSize : 0;

    // Добиваем файл шумом (имитация содержимого XML и других файлов в архиве)
    fill_binary(out, remaining, "");
};

/*
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
    std::uniform_int_distribution<size_t> signatureDist(0, signatures.size() - 1);
    std::uniform_int_distribution<int> sizeDist(20, 1024 * 10); // 20 байт - 10KB

    while (currentSize < targetSize) {
        // Выбираем случайную сигнатуру
        size_t index = signatureDist(rng);
        const auto& sig = signatures[index];

        // Генерируем случайный размер файла (минимум сигнатура + 20 байт)
        uint32_t minSize = static_cast<uint32_t>(sig.signature.size() + 20);
        uint32_t fileSize = std::max(minSize, minSize + static_cast<uint32_t>(sizeDist(rng)));

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

// Простая реализация CRC32 для ZIP
uint32_t UnstructuredFileGenerator::calculateCRC32(const std::vector<uint8_t>& data) {
    static uint32_t table[256];
    static bool initialized = false;

    if (!initialized) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t crc = i;
            for (int j = 0; j < 8; j++) {
                if (crc & 1) {
                    crc = (crc >> 1) ^ 0xEDB88320;
                }
                else {
                    crc >>= 1;
                }
            }
            table[i] = crc;
        }
        initialized = true;
    }

    uint32_t crc = 0xFFFFFFFF;
    for (const auto& byte : data) {
        crc = (crc >> 8) ^ table[(crc & 0xFF) ^ byte];
    }
    return crc ^ 0xFFFFFFFF;
}

struct ZipEntryInfo {
    std::string fileName;
    uint32_t crc32;
    uint32_t compressedSize;
    uint32_t uncompressedSize;
    uint32_t localHeaderOffset;
    uint16_t fileNameLength;
};

void UnstructuredFileGenerator::createZipContainer() {
    std::ofstream container(outputPath, std::ios::binary);
    if (!container) {
        throw std::runtime_error("Failed to create ZIP container file");
    }

    std::vector<ZipEntryInfo> entries;
    uint32_t offset = 0;

    // Создаем каждый файл как отдельную запись в ZIP
    for (const auto& entry : fs::directory_iterator(tempDir)) {
        if (entry.is_regular_file()) {
            // Читаем содержимое файла
            std::ifstream file(entry.path(), std::ios::binary | std::ios::ate);
            if (!file) continue;

            std::streamsize fileSize = file.tellg();
            file.seekg(0, std::ios::beg);

            std::vector<uint8_t> fileData(fileSize);
            file.read(reinterpret_cast<char*>(fileData.data()), fileSize);
            file.close();

            // Вычисляем CRC32
            uint32_t crc32 = calculateCRC32(fileData);

            // Имя файла в ZIP
            std::string fileName = entry.path().filename().string();

            // Сохраняем информацию для центральной директории
            ZipEntryInfo entryInfo;
            entryInfo.fileName = fileName;
            entryInfo.crc32 = crc32;
            entryInfo.compressedSize = static_cast<uint32_t>(fileSize);
            entryInfo.uncompressedSize = static_cast<uint32_t>(fileSize);
            entryInfo.localHeaderOffset = offset;
            entryInfo.fileNameLength = static_cast<uint16_t>(fileName.length());

            entries.push_back(entryInfo);

            // Local file header
            std::vector<uint8_t> localHeader;

            // Signature
            localHeader.insert(localHeader.end(), { 0x50, 0x4B, 0x03, 0x04 });

            // Version needed to extract (2.0)
            localHeader.insert(localHeader.end(), { 0x14, 0x00 });

            // General purpose bit flag (0)
            localHeader.insert(localHeader.end(), { 0x00, 0x00 });

            // Compression method (0 = STORED)
            localHeader.insert(localHeader.end(), { 0x00, 0x00 });

            // Last mod file time (00:00:00)
            localHeader.insert(localHeader.end(), { 0x00, 0x00 });

            // Last mod file date (01.01.1980)
            localHeader.insert(localHeader.end(), { 0x21, 0x00 });

            // CRC-32
            for (size_t i = 0; i < sizeof(uint32_t); ++i) {
                localHeader.push_back(reinterpret_cast<const uint8_t*>(&crc32)[i]);
            }

            // Compressed size
            uint32_t compressedSize = static_cast<uint32_t>(fileSize);
            for (size_t i = 0; i < sizeof(uint32_t); ++i) {
                localHeader.push_back(reinterpret_cast<const uint8_t*>(&compressedSize)[i]);
            }

            // Uncompressed size
            uint32_t uncompressedSize = static_cast<uint32_t>(fileSize);
            for (size_t i = 0; i < sizeof(uint32_t); ++i) {
                localHeader.push_back(reinterpret_cast<const uint8_t*>(&uncompressedSize)[i]);
            }

            // File name length
            uint16_t fileNameLength = static_cast<uint16_t>(fileName.length());
            for (size_t i = 0; i < sizeof(uint16_t); ++i) {
                localHeader.push_back(reinterpret_cast<const uint8_t*>(&fileNameLength)[i]);
            }

            // Extra field length (0)
            localHeader.insert(localHeader.end(), { 0x00, 0x00 });

            // Write local header
            container.write(reinterpret_cast<const char*>(localHeader.data()), localHeader.size());
            offset += static_cast<uint32_t>(localHeader.size());

            // Write file name
            container.write(fileName.c_str(), fileName.length());
            offset += static_cast<uint32_t>(fileName.length());

            // Write file data
            container.write(reinterpret_cast<const char*>(fileData.data()), fileData.size());
            offset += static_cast<uint32_t>(fileData.size());
        }
    }

    // Записываем центральную директорию
    uint32_t centralDirStart = offset;
    uint32_t centralDirSize = 0;

    for (const auto& entry : entries) {
        std::vector<uint8_t> centralHeader;

        // Signature
        centralHeader.insert(centralHeader.end(), { 0x50, 0x4B, 0x01, 0x02 });

        // Version made by
        centralHeader.insert(centralHeader.end(), { 0x14, 0x00 });

        // Version needed to extract
        centralHeader.insert(centralHeader.end(), { 0x14, 0x00 });

        // General purpose bit flag
        centralHeader.insert(centralHeader.end(), { 0x00, 0x00 });

        // Compression method
        centralHeader.insert(centralHeader.end(), { 0x00, 0x00 });

        // Last mod file time
        centralHeader.insert(centralHeader.end(), { 0x00, 0x00 });

        // Last mod file date
        centralHeader.insert(centralHeader.end(), { 0x21, 0x00 });

        // CRC-32
        for (size_t i = 0; i < sizeof(uint32_t); ++i) {
            centralHeader.push_back(reinterpret_cast<const uint8_t*>(&entry.crc32)[i]);
        }

        // Compressed size
        for (size_t i = 0; i < sizeof(uint32_t); ++i) {
            centralHeader.push_back(reinterpret_cast<const uint8_t*>(&entry.compressedSize)[i]);
        }

        // Uncompressed size
        for (size_t i = 0; i < sizeof(uint32_t); ++i) {
            centralHeader.push_back(reinterpret_cast<const uint8_t*>(&entry.uncompressedSize)[i]);
        }

        // File name length
        for (size_t i = 0; i < sizeof(uint16_t); ++i) {
            centralHeader.push_back(reinterpret_cast<const uint8_t*>(&entry.fileNameLength)[i]);
        }

        // Extra field length
        centralHeader.insert(centralHeader.end(), { 0x00, 0x00 });

        // File comment length
        centralHeader.insert(centralHeader.end(), { 0x00, 0x00 });

        // Disk number start
        centralHeader.insert(centralHeader.end(), { 0x00, 0x00 });

        // Internal file attributes
        centralHeader.insert(centralHeader.end(), { 0x00, 0x00 });

        // External file attributes
        centralHeader.insert(centralHeader.end(), { 0x00, 0x00, 0x00, 0x00 });

        // Relative offset of local header
        for (size_t i = 0; i < sizeof(uint32_t); ++i) {
            centralHeader.push_back(reinterpret_cast<const uint8_t*>(&entry.localHeaderOffset)[i]);
        }

        // Write central directory header
        container.write(reinterpret_cast<const char*>(centralHeader.data()), centralHeader.size());

        // Write file name
        container.write(entry.fileName.c_str(), entry.fileName.length());

        centralDirSize += static_cast<uint32_t>(centralHeader.size() + entry.fileName.length());
    }

    // End of central directory record
    std::vector<uint8_t> endRecord;

    // Signature
    endRecord.insert(endRecord.end(), { 0x50, 0x4B, 0x05, 0x06 });

    // Number of this disk
    endRecord.insert(endRecord.end(), { 0x00, 0x00 });

    // Number of the disk with the start of the central directory
    endRecord.insert(endRecord.end(), { 0x00, 0x00 });

    // Total number of entries in the central directory on this disk
    uint16_t entryCount = static_cast<uint16_t>(entries.size());
    for (size_t i = 0; i < sizeof(uint16_t); ++i) {
        endRecord.push_back(reinterpret_cast<const uint8_t*>(&entryCount)[i]);
    }

    // Total number of entries in the central directory
    for (size_t i = 0; i < sizeof(uint16_t); ++i) {
        endRecord.push_back(reinterpret_cast<const uint8_t*>(&entryCount)[i]);
    }

    // Size of the central directory
    for (size_t i = 0; i < sizeof(uint32_t); ++i) {
        endRecord.push_back(reinterpret_cast<const uint8_t*>(&centralDirSize)[i]);
    }

    // Offset of start of central directory
    for (size_t i = 0; i < sizeof(uint32_t); ++i) {
        endRecord.push_back(reinterpret_cast<const uint8_t*>(&centralDirStart)[i]);
    }

    // ZIP file comment length
    endRecord.insert(endRecord.end(), { 0x00, 0x00 });

    // Write end of central directory record
    container.write(reinterpret_cast<const char*>(endRecord.data()), endRecord.size());
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

    uint32_t packetCounter = 0;
    for (const auto& entry : fs::directory_iterator(tempDir)) {
        if (entry.is_regular_file()) {
            uint32_t fileSize = static_cast<uint32_t>(fs::file_size(entry.path()));

            // Packet header
            std::vector<uint8_t> packetHeader;

            // Timestamp seconds
            uint32_t ts_sec = packetCounter;
            for (size_t i = 0; i < sizeof(uint32_t); ++i) {
                packetHeader.push_back(reinterpret_cast<const uint8_t*>(&ts_sec)[i]);
            }

            // Timestamp microseconds
            uint32_t ts_usec = 0;
            for (size_t i = 0; i < sizeof(uint32_t); ++i) {
                packetHeader.push_back(reinterpret_cast<const uint8_t*>(&ts_usec)[i]);
            }

            // Captured packet length
            for (size_t i = 0; i < sizeof(uint32_t); ++i) {
                packetHeader.push_back(reinterpret_cast<const uint8_t*>(&fileSize)[i]);
            }

            // Original packet length
            for (size_t i = 0; i < sizeof(uint32_t); ++i) {
                packetHeader.push_back(reinterpret_cast<const uint8_t*>(&fileSize)[i]);
            }

            // Write packet header
            container.write(reinterpret_cast<const char*>(packetHeader.data()), packetHeader.size());

            // Содержимое файла как payload
            std::ifstream file(entry.path(), std::ios::binary);
            if (file) {
                container << file.rdbuf();
            }

            packetCounter++;
        }
    }
}

void UnstructuredFileGenerator::cleanup() {
    if (fs::exists(tempDir)) {
        fs::remove_all(tempDir);
    }
}
*/