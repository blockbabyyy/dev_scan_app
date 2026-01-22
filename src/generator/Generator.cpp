#include "generator/Generator.h"
#include "Signatures.h"
#include <iostream>
#include <sstream>
#include <random>
#include <ctime>
#include <iomanip>

// Таблица CRC32 (генерируется на лету или хардкод, тут упрощенно)
static uint32_t crc32_table[256];
static bool crc_initialized = false;

void init_crc32() {
    if (crc_initialized) return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) {
            c = (c & 1) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
        }
        crc32_table[i] = c;
    }
    crc_initialized = true;
}

DataSetGenerator::DataSetGenerator() {
    init_crc32();
    // Те же типы, что и в тестах (безопасные и с маркерами)
    types[".zip"] = { ".zip", Sig::Bin::ZIP_HEAD, "", Sig::Bin::ZIP_TAIL, false };
    types[".rar"] = { ".rar", Sig::Bin::RAR4, "", "", false };
    types[".png"] = { ".png", Sig::Bin::PNG_HEAD, "", Sig::Bin::PNG_TAIL, false };
    types[".jpg"] = { ".jpg", Sig::Bin::JPG_HEAD, "", Sig::Bin::JPG_TAIL, false };
    types[".gif"] = { ".gif", Sig::Bin::GIF_HEAD, "", std::string("\x00\x3B", 2), false };
    types[".bmp"] = { ".bmp", std::string("\x42\x4D\x36\x00\x0C\x00\x00\x00", 8), "", "", false };
    types[".mkv"] = { ".mkv", Sig::Bin::MKV, "", "", false };
    types[".mp3"] = { ".mp3", Sig::Bin::MP3, "", "", false };
    types[".doc"] = { ".doc", Sig::Bin::OLE, Sig::Bin::OLE_WORD, "", false };
    types[".xls"] = { ".xls", Sig::Bin::OLE, Sig::Bin::OLE_XL,   "", false };
    types[".ppt"] = { ".ppt", Sig::Bin::OLE, Sig::Bin::OLE_PPT,  "", false };
    types[".docx"] = { ".docx", Sig::Bin::ZIP_HEAD, Sig::Bin::XML_WORD, Sig::Bin::ZIP_TAIL, false };
    types[".xlsx"] = { ".xlsx", Sig::Bin::ZIP_HEAD, Sig::Bin::XML_XL,   Sig::Bin::ZIP_TAIL, false };
    types[".pptx"] = { ".pptx", Sig::Bin::ZIP_HEAD, Sig::Bin::XML_PPT,  Sig::Bin::ZIP_TAIL, false };
    types[".pdf"] = { ".pdf", Sig::Bin::PDF_HEAD, "", Sig::Bin::PDF_TAIL, false };
    types[".json"] = { ".json", "{ \"k\": ", "", " }", true };
    types[".html"] = { ".html", "<html><body>", "", "</body></html>", true };
    types[".xml"] = { ".xml", "<?xml version=\"1.0\"?>", "", "", true };
    types[".eml"] = { ".eml", "From: user@loc", "", "", true };

    for (const auto& kv : types) extensions.push_back(kv.first);
}

// --- Payload Generation ---
void DataSetGenerator::fill_safe(std::stringstream& ss, size_t count, bool is_text) {
    if (count == 0) return;
    if (is_text) {
        for (size_t i = 0; i < count; ++i) ss.put(' ');
    }
    else {
        // 0xCC - безопасный наполнитель
        for (size_t i = 0; i < count; ++i) ss.put((char)0xCC);
    }
}

std::pair<std::string, std::string> DataSetGenerator::create_payload(std::mt19937& rng, bool is_mixed) {
    std::uniform_int_distribution<size_t> dist_idx(0, extensions.size() - 1);
    std::uniform_int_distribution<size_t> dist_size(512, 4096);

    std::stringstream ss;
    std::string primary_ext;

    int parts = is_mixed ? (2 + (rng() % 2)) : 1;

    for (int p = 0; p < parts; ++p) {
        if (p > 0) fill_safe(ss, 64, false); // Gap between mixed files

        std::string ext = extensions[dist_idx(rng)];
        if (p == 0) primary_ext = ext; // Считаем тип по первому файлу (условно)

        const auto& t = types[ext];
        size_t total_size = dist_size(rng);

        ss << t.head;
        size_t overhead = t.head.size() + t.middle.size() + t.tail.size();
        size_t body = (total_size > overhead) ? total_size - overhead : 0;

        // Маркер ближе к началу (для RE2)
        size_t pre_marker = std::min((size_t)50, body);
        size_t post_marker = body - pre_marker;

        fill_safe(ss, pre_marker, t.is_text);
        ss << t.middle;
        fill_safe(ss, post_marker, t.is_text);
        ss << t.tail;
    }
    return { primary_ext, ss.str() };
}

void DataSetGenerator::update_stats(const std::string& ext, GenStats& stats) {
    if (ext == ".pdf") stats.pdf++;
    else if (ext == ".zip") stats.zip++;
    else if (ext == ".rar") stats.rar++;
    else if (ext == ".png") stats.png++;
    else if (ext == ".jpg") stats.jpg++;
    else if (ext == ".gif") stats.gif++;
    else if (ext == ".bmp") stats.bmp++;
    else if (ext == ".mkv") stats.mkv++;
    else if (ext == ".mp3") stats.mp3++;
    else if (ext == ".doc") stats.doc++;
    else if (ext == ".xls") stats.xls++;
    else if (ext == ".ppt") stats.ppt++;
    else if (ext == ".docx") { stats.docx++; stats.zip++; }
    else if (ext == ".xlsx") { stats.xlsx++; stats.zip++; }
    else if (ext == ".pptx") { stats.pptx++; stats.zip++; }
    else if (ext == ".json") stats.json++;
    else if (ext == ".html") stats.html++;
    else if (ext == ".xml") stats.xml++;
    else if (ext == ".eml") stats.eml++;
    stats.total_files++;
}

// --- WRITE MODES ---

void DataSetGenerator::write_as_folder(const std::filesystem::path& dir, int count, double mix_ratio, GenStats& stats) {
    std::filesystem::create_directories(dir);
    std::mt19937 rng(std::random_device{}());
    std::uniform_real_distribution<double> dist_mix(0.0, 1.0);

    for (int i = 0; i < count; ++i) {
        bool is_mixed = dist_mix(rng) < mix_ratio;

        // ext - это расширение основного (первого) файла в цепочке
        auto [ext, data] = create_payload(rng, is_mixed);

        // [FIX] Используем реальное расширение вместо .bin
        // Если файл смешанный (например PDF+ZIP), он получит расширение первого (PDF).
        std::string fname = "file_" + std::to_string(i) + ext;

        std::ofstream f(dir / fname, std::ios::binary);
        f << data;

        // Статистику обновляем как и раньше
        update_stats(ext, stats);
    }
}

void DataSetGenerator::write_as_bin(const std::filesystem::path& file, int count, double mix_ratio, GenStats& stats) {
    std::ofstream f(file, std::ios::binary);
    std::mt19937 rng(std::random_device{}());
    std::uniform_real_distribution<double> dist_mix(0.0, 1.0);

    for (int i = 0; i < count; ++i) {
        bool is_mixed = dist_mix(rng) < mix_ratio;
        auto [ext, data] = create_payload(rng, is_mixed);
        f << data;
        update_stats(ext, stats);
    }
}

// Простая структура PCAP Header
struct PcapGlobalHeader {
    uint32_t magic = 0xa1b2c3d4;
    uint16_t version_major = 2;
    uint16_t version_minor = 4;
    int32_t  thiszone = 0;
    uint32_t sigfigs = 0;
    uint32_t snaplen = 65535;
    uint32_t network = 1; // Ethernet
};

struct PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

void DataSetGenerator::write_as_pcap(const std::filesystem::path& file, int count, double mix_ratio, GenStats& stats) {
    std::ofstream f(file, std::ios::binary);
    std::mt19937 rng(std::random_device{}());
    std::uniform_real_distribution<double> dist_mix(0.0, 1.0);

    PcapGlobalHeader gh;
    f.write((char*)&gh, sizeof(gh));

    uint32_t timestamp = (uint32_t)std::time(nullptr);

    for (int i = 0; i < count; ++i) {
        bool is_mixed = dist_mix(rng) < mix_ratio;
        auto [ext, data] = create_payload(rng, is_mixed);
        update_stats(ext, stats);

        PcapPacketHeader ph;
        ph.ts_sec = timestamp + i;
        ph.ts_usec = 0;
        ph.incl_len = (uint32_t)data.size();
        ph.orig_len = (uint32_t)data.size();

        f.write((char*)&ph, sizeof(ph));
        f.write(data.data(), data.size());
    }
}

// Helpers for ZIP
uint32_t DataSetGenerator::calculate_crc32(const std::string& data) {
    uint32_t crc = 0xFFFFFFFF;
    for (unsigned char c : data) {
        crc = crc32_table[(crc ^ c) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

// ZIP Structures (Packed)
#pragma pack(push, 1)
struct ZipLocalHeader {
    uint32_t sig = 0x04034b50;
    uint16_t version = 20;
    uint16_t flags = 0;
    uint16_t compression = 0; // Store
    uint16_t time = 0;
    uint16_t date = 0;
    uint32_t crc32 = 0;
    uint32_t comp_size = 0;
    uint32_t uncomp_size = 0;
    uint16_t name_len = 0;
    uint16_t extra_len = 0;
};
struct ZipDirHeader {
    uint32_t sig = 0x02014b50;
    uint16_t ver_made = 20;
    uint16_t ver_need = 20;
    uint16_t flags = 0;
    uint16_t compression = 0;
    uint16_t time = 0;
    uint16_t date = 0;
    uint32_t crc32 = 0;
    uint32_t comp_size = 0;
    uint32_t uncomp_size = 0;
    uint16_t name_len = 0;
    uint16_t extra_len = 0;
    uint16_t comment_len = 0;
    uint16_t disk_start = 0;
    uint16_t int_attr = 0;
    uint32_t ext_attr = 0;
    uint32_t local_offset = 0;
};
struct ZipEOCD {
    uint32_t sig = 0x06054b50;
    uint16_t disk_num = 0;
    uint16_t disk_dir_start = 0;
    uint16_t num_dir_this = 0;
    uint16_t num_dir_total = 0;
    uint32_t size_dir = 0;
    uint32_t offset_dir = 0;
    uint16_t comment_len = 0;
};
#pragma pack(pop)

void DataSetGenerator::write_as_zip(const std::filesystem::path& file, int count, double mix_ratio, GenStats& stats) {
    std::ofstream f(file, std::ios::binary);
    if (!f.is_open()) {
        std::cerr << "Error: Cannot create ZIP file at " << file << std::endl;
        return;
    }

    std::mt19937 rng(std::random_device{}());
    std::uniform_real_distribution<double> dist_mix(0.0, 1.0);

    // Храним информацию о каждом добавленном файле для Central Directory
    struct Entry {
        uint32_t offset;
        uint32_t crc;
        uint32_t size;
        std::string name;
    };
    std::vector<Entry> entries;

    // 1. Пишем Local File Headers + Data
    for (int i = 0; i < count; ++i) {
        bool is_mixed = dist_mix(rng) < mix_ratio;

        // Получаем расширение и данные
        auto [ext, data] = create_payload(rng, is_mixed);
        update_stats(ext, stats);

        // Формируем имя файла внутри архива с правильным расширением
        std::string fname = "file_" + std::to_string(i) + ext;

        uint32_t offset = (uint32_t)f.tellp();
        uint32_t crc = calculate_crc32(data);

        ZipLocalHeader lh;
        lh.crc32 = crc;
        lh.comp_size = (uint32_t)data.size();
        lh.uncomp_size = (uint32_t)data.size();
        lh.name_len = (uint16_t)fname.size();

        // Записываем структуру заголовка
        f.write((char*)&lh, sizeof(lh));
        // Записываем имя файла
        f.write(fname.data(), fname.size());
        // Записываем данные файла (Payload)
        f.write(data.data(), data.size());

        // Сохраняем метаданные для CD
        entries.push_back({ offset, crc, (uint32_t)data.size(), fname });
    }

    // 2. Пишем Central Directory
    uint32_t cd_start = (uint32_t)f.tellp();
    for (const auto& e : entries) {
        ZipDirHeader dh;
        dh.crc32 = e.crc;
        dh.comp_size = e.size;
        dh.uncomp_size = e.size;
        dh.name_len = (uint16_t)e.name.size();
        dh.local_offset = e.offset;

        f.write((char*)&dh, sizeof(dh));
        f.write(e.name.data(), e.name.size());
    }

    // Вычисляем размер Central Directory
    uint32_t cd_size = (uint32_t)f.tellp() - cd_start;

    // 3. Пишем End of Central Directory (EOCD)
    ZipEOCD eocd;
    eocd.num_dir_this = (uint16_t)entries.size();
    eocd.num_dir_total = (uint16_t)entries.size();
    eocd.size_dir = cd_size;
    eocd.offset_dir = cd_start;

    f.write((char*)&eocd, sizeof(eocd));
}

GenStats DataSetGenerator::generate(const std::filesystem::path& path, int count, OutputMode mode, double mix_ratio) {
    GenStats stats;
    std::cout << "[Generator] Mode: ";
    switch (mode) {
    case OutputMode::FOLDER: std::cout << "FOLDER"; break;
    case OutputMode::BIN: std::cout << "BIN (Concatenation)"; break;
    case OutputMode::PCAP: std::cout << "PCAP"; break;
    case OutputMode::ZIP: std::cout << "ZIP (No Compression)"; break;
    }
    std::cout << ", Files: " << count << ", Mix: " << mix_ratio << "\n";

    if (mode == OutputMode::FOLDER) {
        write_as_folder(path, count, mix_ratio, stats);
    }
    else {
        // Для остальных режимов путь - это файл, а не папка.
        // Убедимся, что родительская папка существует
        if (path.has_parent_path()) {
            std::filesystem::create_directories(path.parent_path());
        }
        if (mode == OutputMode::BIN) write_as_bin(path, count, mix_ratio, stats);
        else if (mode == OutputMode::PCAP) write_as_pcap(path, count, mix_ratio, stats);
        else if (mode == OutputMode::ZIP) write_as_zip(path, count, mix_ratio, stats);
    }

    return stats;
}