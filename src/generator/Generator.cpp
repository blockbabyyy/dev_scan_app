#include "generator/Generator.h"
#include <vector>

// Словарь
const std::vector<std::string> DataSetGenerator::dictionary = {
    "lorem", "ipsum", "dolor", "sit", "amet", "consectetur", "adipiscing", "elit",
    "the", "and", "is", "in", "at", "of", "to", "for", "with", "on",
    "function", "return", "var", "const", "if", "else", "for", "while",
    // Ловушки
    "%PDF-", "PK", "Rar!", "PNG", "JFIF", "Exif",
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

// CRC32 Table Init
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
    // Можно развернуть цикл для скорости, но компилятор с -O2 сам справится
    for (size_t i = 0; i < length; ++i) c = crc32_table[(c ^ (uint8_t)data[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFF;
}

DataSetGenerator::DataSetGenerator() {
    std::random_device rd;
    rng.seed(rd());

    // --- TEXT ---
    file_types.push_back({ ".txt",  "", true, "" });
    file_types.push_back({ ".html", "", true, "" });
    file_types.push_back({ ".xml",  "<?xml", true, "" });
    file_types.push_back({ ".json", "", true, "" });
    file_types.push_back({ ".eml",  "", true, "" });

    // --- DOCS ---
    file_types.push_back({ ".pdf",  Sig::Bin::PDF_HEAD, false, Sig::Bin::PDF_TAIL });
    file_types.push_back({ ".doc",  Sig::Bin::OLE, false, "" });
    file_types.push_back({ ".xls",  Sig::Bin::OLE, false, "" });
    file_types.push_back({ ".ppt",  Sig::Bin::OLE, false, "" });
    file_types.push_back({ ".docx", "", false, "" });
    file_types.push_back({ ".xlsx", "", false, "" });
    file_types.push_back({ ".pptx", "", false, "" });

    // --- MEDIA ---
    file_types.push_back({ ".png",  Sig::Bin::PNG_HEAD, false, Sig::Bin::PNG_TAIL });
    file_types.push_back({ ".jpg",  Sig::Bin::JPG_HEAD, false, Sig::Bin::JPG_TAIL });
    file_types.push_back({ ".gif",  Sig::Bin::GIF_HEAD, false, Sig::Bin::GIF_TAIL });
    file_types.push_back({ ".bmp",  Sig::Bin::BMP_HEAD, false, "" });
    file_types.push_back({ ".mkv",  Sig::Bin::MKV, false, "" });
    file_types.push_back({ ".mp3",  Sig::Bin::MP3, false, "" });

    // --- ARCHIVES ---
    file_types.push_back({ ".zip",  Sig::Bin::ZIP_HEAD, false, Sig::Bin::ZIP_TAIL });
    file_types.push_back({ ".rar",  Sig::Bin::RAR4, false, "" });
    file_types.push_back({ ".rar",  Sig::Bin::RAR5, false, "" });
};

GenStats DataSetGenerator::generate(const std::string& output_path, size_t total_size_mb, ContainerType type) {
    size_t target_size_bytes = total_size_mb * 1024 * 1024;
    GenStats stats;
    fs::path final_path = output_path;

    if (type != ContainerType::FOLDER) {
        if (!fs::exists(final_path.parent_path()) && final_path.has_parent_path()) {
            fs::create_directories(final_path.parent_path());
        }
        else if (!final_path.has_parent_path()) {
            fs::create_directories(final_path); // если передан просто путь папки
        }

        std::string filename = "dataset";
        if (type == ContainerType::ZIP) filename += ".zip";
        else if (type == ContainerType::PCAP) filename += ".pcap";
        else if (type == ContainerType::BIN) filename += ".bin";

        // Если output_path была папкой, добавляем имя файла
        if (fs::is_directory(final_path) || !final_path.has_extension()) {
            final_path /= filename;
        }
    }

    std::string path_str = final_path.string();
    std::cout << "Starting generation: " << total_size_mb << " MB -> " << path_str << std::endl;

    switch (type) {
    case ContainerType::FOLDER: generate_folder(path_str, target_size_bytes, stats); break;
    case ContainerType::ZIP:    generate_zip(path_str, target_size_bytes, stats); break;
    case ContainerType::PCAP:   generate_pcap(path_str, target_size_bytes, stats); break;
    case ContainerType::BIN:    generate_bin(path_str, target_size_bytes, stats); break;
    }
    stats.total_bytes = target_size_bytes;
    std::cout << "\nGeneration complete." << std::endl;
    return stats;
};

void DataSetGenerator::generate_content(std::ostream& out, size_t size, const FileType& type) {
    if (!type.signature.empty()) {
        out.write(type.signature.data(), type.signature.size());
    }

    size_t header_len = type.signature.size();
    size_t footer_len = type.footer.size();
    size_t body_size = 0;

    if (size > header_len + footer_len) {
        body_size = size - header_len - footer_len;
    }

    if (type.is_text) {
        if (type.extension == ".json") fill_json(out, body_size);
        else if (type.extension == ".eml") fill_email(out, body_size);
        else if (type.extension == ".html") {
            out << "<html><head></head><body>";
            fill_text(out, (body_size > 40) ? body_size - 40 : 0);
            out << "</body>";
        }
        else fill_text(out, body_size);
    }
    else if (type.extension == ".docx") fill_openxml(out, body_size, Sig::Bin::XML_WORD);
    else if (type.extension == ".xlsx") fill_openxml(out, body_size, Sig::Bin::XML_XL);
    else if (type.extension == ".pptx") fill_openxml(out, body_size, Sig::Bin::XML_PPT);
    else if (type.extension == ".doc") fill_ole(out, body_size, Sig::Bin::OLE_WORD);
    else if (type.extension == ".xls") fill_ole(out, body_size, Sig::Bin::OLE_XL);
    else if (type.extension == ".ppt") fill_ole(out, body_size, Sig::Bin::OLE_PPT);
    else {
        fill_binary(out, body_size, type.signature);
    }

    if (!type.footer.empty()) {
        out.write(type.footer.data(), type.footer.size());
    }
    else if (type.extension == ".html") {
        out << "</html>";
    }
}

void DataSetGenerator::generate_folder(const std::string& dir, size_t totalBytes, GenStats& stats) {
    if (!fs::exists(dir)) fs::create_directories(dir);
    size_t currentBytes = 0;
    size_t lastLogBytes = 0;
    int index = 0;

    std::uniform_int_distribution<int> typeDist(0, file_types.size() - 1);
    std::discrete_distribution<> sizeDist({ 70, 20, 10 });

    while (currentBytes < totalBytes) {
        const auto& ftype = file_types[typeDist(rng)];
        size_t fsize = 0;
        int cat = sizeDist(rng);

        // Размеры файлов
        if (cat == 0) fsize = std::uniform_int_distribution<size_t>(512, 50 * 1024)(rng);
        else if (cat == 1) fsize = std::uniform_int_distribution<size_t>(50 * 1024, 1 * 1024 * 1024)(rng);
        else fsize = std::uniform_int_distribution<size_t>(1 * 1024 * 1024, 10 * 1024 * 1024)(rng);

        // Корректировка конца
        if (currentBytes + fsize > totalBytes + (5 * 1024 * 1024)) fsize = (totalBytes > currentBytes) ? totalBytes - currentBytes : 512;
        if (fsize == 0) fsize = 512;

        std::string fname = dir + "/file_" + std::to_string(index++) + ftype.extension;
        std::ofstream ofs(fname, std::ios::binary);
        if (ofs) {
            generate_content(ofs, fsize, ftype);
            update_stats(stats, ftype.extension);
            currentBytes += fsize;
        }

        // Лог только раз в ~10МБ
        if (currentBytes - lastLogBytes > 10 * 1024 * 1024) {
            std::cout << "\r[FOLDER] Generated: " << (currentBytes / 1024 / 1024) << " MB" << std::flush;
            lastLogBytes = currentBytes;
        }
    }
    std::cout << std::endl;
}

void DataSetGenerator::generate_zip(const std::string& filename, size_t total_bytes, GenStats& stats) {
    std::ofstream zip(filename, std::ios::binary);
    size_t current_bytes = 0;
    size_t lastLogBytes = 0;
    int index = 0;
    std::vector<DataSetGenerator::ZipEntry> entries;
    std::uniform_int_distribution<int> type_dist(0, file_types.size() - 1);

    // Резервируем память под вектор записей, чтобы не было реаллокаций
    entries.reserve(total_bytes / 50000);

    std::cout << "[ZIP] Generating: " << filename << std::endl;
    while (current_bytes < total_bytes) {
        const auto& ftype = file_types[type_dist(rng)];
        // Ограничиваем размер файла внутри ZIP до 20 МБ, чтобы не забивать RAM stringstream-ом
        size_t fsize = std::uniform_int_distribution<size_t>(100, 20 * 1024 * 1024)(rng);

        std::string fname = "f" + std::to_string(index++) + ftype.extension;

        std::stringstream buffer;
        generate_content(buffer, fsize, ftype);
        update_stats(stats, ftype.extension);
        std::string data = buffer.str();
        uint32_t crc = calculate_CRC32(data.data(), data.size());

        ZipEntry entry = { fname, crc, (uint32_t)data.size(), (uint32_t)zip.tellp() };
        entries.push_back(entry);

        // Local Header
        uint32_t sig = 0x04034b50; zip.write((char*)&sig, 4);
        uint16_t dummy = 0;
        zip.write((char*)&dummy, 2); zip.write((char*)&dummy, 2); zip.write((char*)&dummy, 2);
        zip.write((char*)&dummy, 2); zip.write((char*)&dummy, 2);
        zip.write((char*)&entry.crc32, 4);
        zip.write((char*)&entry.size, 4); zip.write((char*)&entry.size, 4);
        uint16_t nlen = fname.size(); zip.write((char*)&nlen, 2);
        zip.write((char*)&dummy, 2);
        zip.write(fname.c_str(), nlen);
        zip.write(data.data(), data.size());

        current_bytes += data.size();

        if (current_bytes - lastLogBytes > 10 * 1024 * 1024) {
            std::cout << "\r[ZIP] Generated: " << (current_bytes / 1024 / 1024) << " MB" << std::flush;
            lastLogBytes = current_bytes;
        }
    }

    // Central Directory
    uint32_t cd_start = (uint32_t)zip.tellp();
    for (const auto& e : entries) {
        uint32_t sig = 0x02014b50; zip.write((char*)&sig, 4);
        uint16_t ver = 20; zip.write((char*)&ver, 2); zip.write((char*)&ver, 2);
        uint16_t zero = 0; zip.write((char*)&zero, 2); zip.write((char*)&zero, 2);
        uint32_t zero32 = 0; zip.write((char*)&zero32, 4);
        zip.write((char*)&e.crc32, 4); zip.write((char*)&e.size, 4); zip.write((char*)&e.size, 4);
        uint16_t nameLen = (uint16_t)e.name.size(); zip.write((char*)&nameLen, 2);
        zip.write((char*)&zero, 2); zip.write((char*)&zero, 2); zip.write((char*)&zero, 2);
        zip.write((char*)&zero, 2); zip.write((char*)&zero32, 4); zip.write((char*)&e.offset, 4);
        zip.write(e.name.c_str(), e.name.size());
    }
    uint32_t cd_size = (uint32_t)zip.tellp() - cd_start;

    // EOCD
    uint32_t cd_sig_end = 0x06054b50; zip.write((char*)&cd_sig_end, 4);
    uint16_t disk = 0; zip.write((char*)&disk, 2); zip.write((char*)&disk, 2);
    uint16_t entries_num = (uint16_t)entries.size();
    zip.write((char*)&entries_num, 2); zip.write((char*)&entries_num, 2);
    zip.write((char*)&cd_size, 4); zip.write((char*)&cd_start, 4);
    uint16_t comment_len = 0; zip.write((char*)&comment_len, 2);
    std::cout << std::endl;
}

void DataSetGenerator::generate_pcap(const std::string& filename, size_t total_bytes, GenStats& stats) {
    std::ofstream pcap(filename, std::ios::binary);
    uint32_t magic = 0xa1b2c3d4; pcap.write((char*)&magic, 4);
    char glob[] = { 0,2, 0,4, 0,0,0,0, 0,0,0,0, (char)0xFF,(char)0xFF,0,0, 1,0,0,0 };
    pcap.write(glob, 20);

    size_t currentBytes = 0;
    size_t lastLogBytes = 0;
    std::uniform_int_distribution<int> typeDist(0, file_types.size() - 1);

    std::cout << "[PCAP] Generating: " << filename << std::endl;

    while (currentBytes < total_bytes) {
        const auto& ftype = file_types[typeDist(rng)];
        size_t fsize = std::uniform_int_distribution<size_t>(64, 1400)(rng);

        std::stringstream buffer;
        generate_content(buffer, fsize, ftype);
        update_stats(stats, ftype.extension);
        std::string payload = buffer.str();

        uint32_t ts = 0x55AA55AA;
        uint32_t len = payload.size();
        pcap.write((char*)&ts, 4); pcap.write((char*)&ts, 4);
        pcap.write((char*)&len, 4); pcap.write((char*)&len, 4);
        pcap.write(payload.data(), len);
        currentBytes += len;

        if (currentBytes - lastLogBytes > 10 * 1024 * 1024) {
            std::cout << "\r[PCAP] Generated: " << (currentBytes / 1024 / 1024) << " MB" << std::flush;
            lastLogBytes = currentBytes;
        }
    }
    std::cout << std::endl;
}

void DataSetGenerator::generate_bin(const std::string& filename, size_t totalBytes, GenStats& stats) {
    std::ofstream bin(filename, std::ios::binary);
    size_t currentBytes = 0;
    size_t lastLogBytes = 0;
    std::uniform_int_distribution<int> typeDist(0, file_types.size() - 1);
    std::cout << "[BIN] Generating: " << filename << std::endl;

    while (currentBytes < totalBytes) {
        const auto& ftype = file_types[typeDist(rng)];
        // Ограничиваем размер 50 МБ для сохранения RAM
        size_t fsize = std::uniform_int_distribution<size_t>(1024, 50 * 1024 * 1024)(rng);

        std::stringstream buffer;
        generate_content(buffer, fsize, ftype);
        update_stats(stats, ftype.extension);
        std::string data = buffer.str();

        uint32_t magic = 0xDEADBEEF; uint64_t sz = data.size();
        bin.write((char*)&magic, 4); bin.write((char*)&sz, 8);
        bin.write(data.data(), sz);
        currentBytes += sz;

        if (currentBytes - lastLogBytes > 10 * 1024 * 1024) {
            std::cout << "\r[BIN] Generated: " << (currentBytes / 1024 / 1024) << " MB" << std::flush;
            lastLogBytes = currentBytes;
        }
    }
    std::cout << std::endl;
}

void DataSetGenerator::fill_text(std::ostream& out, size_t size) {
    // Оптимизация: Буфер 64KB и генерация блоками, без частых string alloc
    const size_t BUF_SIZE = 65536;
    std::vector<char> buffer;
    buffer.reserve(BUF_SIZE);

    std::uniform_int_distribution<int> wordIdx(0, dictionary.size() - 1);

    while (size > 0) {
        // Заполняем буфер в памяти
        while (buffer.size() < BUF_SIZE && buffer.size() < size) {
            const std::string& w = dictionary[wordIdx(rng)];
            // Простая вставка
            for (char c : w) buffer.push_back(c);
            buffer.push_back(' ');
        }

        // Если сгенерировали больше чем надо (из-за длины слова)
        size_t to_write = std::min(size, buffer.size());
        out.write(buffer.data(), to_write);

        size -= to_write;
        buffer.clear();
    }
}

void DataSetGenerator::fill_json(std::ostream& out, size_t size) {
    out << "{\"data\": [";
    size_t written = 10;
    while (size > written + 5) {
        std::string val = "\"" + dictionary[std::uniform_int_distribution<int>(0, dictionary.size() - 1)(rng)] + "\",";
        // Проверка, чтобы не вылезти за размер
        if (val.size() > size - written - 5) break;
        out.write(val.data(), val.size());
        written += val.size();
    }
    out << "]}";
}

void DataSetGenerator::fill_email(std::ostream& out, size_t size) {
    std::string h = "Date: Mon, 01 Jan 2025\r\nFrom: <gen>\r\nSubject: Test\r\n\r\n";
    size_t hlen = std::min(size, h.size());
    out.write(h.data(), hlen);
    if (size > hlen) fill_text(out, size - hlen);
}

void DataSetGenerator::fill_binary(std::ostream& out, size_t size, const std::string& signatureToAvoid) {
    // Буфер увеличен до 64 KB для скорости записи
    std::vector<char> buffer(65536);
    std::uniform_int_distribution<int> bdist(0, 255);

    // Инициализируем 1 раз
    for (auto& b : buffer) b = (char)bdist(rng);

    // Вставляем ловушки
    if (buffer.size() > 60) {
        buffer[10] = 0x50; buffer[11] = 0x4B; buffer[12] = 0x03; buffer[13] = 0x04;
        buffer[50] = 0x25; buffer[51] = 0x50; buffer[52] = 0x44; buffer[53] = 0x46;
    }

    size_t written = 0;
    while (written < size) {
        size_t n = std::min(size - written, buffer.size());

        // Легкая мутация для предотвращения дедупликации, но быстрая
        buffer[written % 1024] ^= 0xAA;

        out.write(buffer.data(), n);
        written += n;
    }
}

void DataSetGenerator::fill_ole(std::ostream& out, size_t size, const std::string& marker) {
    std::vector<char> b(4096, 0); // Чуть больше буфер
    for (auto& c : b) c = rng() % 255;

    if (marker.size() + 100 < b.size()) std::memcpy(&b[100], marker.data(), marker.size());

    size_t toWrite = std::min(size, b.size());
    out.write(b.data(), toWrite);
    if (size > toWrite) fill_binary(out, size - toWrite, "");
}

void DataSetGenerator::fill_openxml(std::ostream& out, size_t size, const std::string& marker) {
    std::string name = marker + "core.xml";
    uint32_t sig = 0x04034b50; out.write((char*)&sig, 4);
    char garbage[26] = { 0 };
    out.write(garbage, 22);
    uint16_t n = name.size(); out.write((char*)&n, 2);
    out.write(garbage, 2);
    out.write(name.data(), n);

    size_t head = 30 + n;
    if (size > head) fill_binary(out, size - head, "");
}