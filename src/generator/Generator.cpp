#include "generator/Generator.h"
#include "Signatures.h"
#include <iostream>
#include <sstream>
#include <random>
#include <ctime>
#include <iomanip>

// --- CRC32 Utils ---
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

// [FIX] Ловушки теперь "битые" (Corrupted), чтобы не вызывать False Positives
const std::vector<std::string> TRAPS_BIN = {
    "\x50\x4B\xFF\xFF",     // PK.. (Bad Version) - похоже на ZIP, но не ZIP
    "\x25\x50\x44\x5F",     // %PD_ (Broken PDF Header)
    "\x47\x49\x46\x39",     // GIF9 (Not GIF8)
    "\xFF\xD8\x00\x00",     // JPG Marker prefix without valid subtype
    "WordDoc_ment",         // [FIX] Broken OLE Marker (was "WordDocument")
    "Workbuuk",             // Broken Excel
    "PowerPoint Fakument"   // Broken PPT
};

const std::vector<std::string> TRAPS_TEXT = {
    "<hmtl fake='yes'>",    // [FIX] Typo in tag name (hmtl instead of html)
    "{\"fake_json\"; 1}",   // [FIX] Semicolon instead of colon
    "Subject- Fake",        // [FIX] Dash instead of colon
    "%PDF-1.4-fake",        // Broken version
    "PK\x03\x04_fake_text", // Text looking like binary signature
    "GIF89a_fake"
};

DataSetGenerator::DataSetGenerator() {
    init_crc32();

    // Инициализация типов (без изменений)
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

    // Словарь для текста
    dictionary = {
        "lorem", "ipsum", "dolor", "sit", "amet", "consectetur", "adipiscing", "elit",
        "function", "var", "const", "return", "if", "else", "for", "while",
        "class", "public", "private", "protected", "import", "include",
        "http://example.com", "user@domain.org", "127.0.0.1", "path/to/file",
        "debug", "error", "info", "warning", "trace", "fatal"
    };
}

size_t DataSetGenerator::get_realistic_size(const std::string& ext, std::mt19937& rng) {
    std::uniform_int_distribution<int> chance(0, 100);
    int c = chance(rng);

    if (types[ext].is_text) {
        // Текст: 1 КБ - 200 КБ
        std::uniform_int_distribution<size_t> d(1024, 200 * 1024);
        return d(rng);
    }
    else if (ext == ".mkv" || ext == ".mp3") {
        // Медиа: 5 МБ - 50 МБ
        std::uniform_int_distribution<size_t> d(5 * 1024 * 1024, 50 * 1024 * 1024);
        return d(rng);
    }
    else {
        // Бинарники
        if (c < 50) { // 50% мелких (10KB - 500KB)
            std::uniform_int_distribution<size_t> d(10 * 1024, 500 * 1024);
            return d(rng);
        }
        else if (c < 90) { // 40% средних (500KB - 5MB)
            std::uniform_int_distribution<size_t> d(500 * 1024, 5 * 1024 * 1024);
            return d(rng);
        }
        else { // 10% крупных (5MB - 20MB)
            std::uniform_int_distribution<size_t> d(5 * 1024 * 1024, 20 * 1024 * 1024);
            return d(rng);
        }
    }
}

void DataSetGenerator::fill_complex(std::stringstream& ss, size_t count, bool is_text, std::mt19937& rng) {
    if (count == 0) return;
    size_t written = 0;

    if (is_text) {
        std::uniform_int_distribution<size_t> dict_idx(0, dictionary.size() - 1);
        std::uniform_int_distribution<int> trap_chance(0, 100);

        while (written < count) {
            if (trap_chance(rng) < 2 && written + 30 < count) {
                // Вставка текстовой ловушки
                std::uniform_int_distribution<size_t> t_idx(0, TRAPS_TEXT.size() - 1);
                std::string trap = TRAPS_TEXT[t_idx(rng)];
                ss << trap << " ";
                written += trap.size() + 1;
            }
            else {
                std::string word = dictionary[dict_idx(rng)];
                if (written + word.size() + 1 <= count) {
                    ss << word << " ";
                    written += word.size() + 1;
                }
                else {
                    while (written < count) { ss.put(' '); written++; }
                }
            }
        }
    }
    else {
        std::uniform_int_distribution<int> trap_chance(0, 100);
        while (written < count) {
            if (trap_chance(rng) < 2 && written + 20 < count) {
                // Вставка бинарной ловушки
                std::uniform_int_distribution<size_t> t_idx(0, TRAPS_BIN.size() - 1);
                std::string trap = TRAPS_BIN[t_idx(rng)];
                ss.write(trap.data(), trap.size());
                written += trap.size();
            }
            else {
                ss.put((char)0xCC);
                written++;
            }
        }
    }
}

std::pair<std::string, std::string> DataSetGenerator::create_payload(std::mt19937& rng, bool is_mixed) {
    std::uniform_int_distribution<size_t> dist_idx(0, extensions.size() - 1);
    std::stringstream ss;
    std::string primary_ext;

    int parts = is_mixed ? (2 + (rng() % 2)) : 1;

    for (int p = 0; p < parts; ++p) {
        if (p > 0) fill_complex(ss, 128, false, rng);

        std::string ext = extensions[dist_idx(rng)];
        if (p == 0) primary_ext = ext;

        const auto& t = types[ext];
        size_t total_size = get_realistic_size(ext, rng);

        ss << t.head;
        size_t overhead = t.head.size() + t.middle.size() + t.tail.size();
        if (total_size < overhead + 100) total_size = overhead + 100;

        size_t body = total_size - overhead;
        size_t pre_marker = std::min((size_t)50, body);
        size_t post_marker = body - pre_marker;

        fill_complex(ss, pre_marker, t.is_text, rng);
        ss << t.middle;
        fill_complex(ss, post_marker, t.is_text, rng);
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

uint32_t DataSetGenerator::calculate_crc32(const std::string& data) {
    uint32_t crc = 0xFFFFFFFF;
    for (unsigned char c : data) {
        crc = crc32_table[(crc ^ c) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

#pragma pack(push, 1)
struct PcapGlobalHeader { uint32_t magic = 0xa1b2c3d4; uint16_t vm = 2; uint16_t vn = 4; int32_t tz = 0; uint32_t sf = 0; uint32_t sl = 65535; uint32_t net = 1; };
struct PcapPacketHeader { uint32_t ts_sec; uint32_t ts_usec; uint32_t incl; uint32_t orig; };
struct ZipLocalHeader { uint32_t sig = 0x04034b50; uint16_t ver = 20; uint16_t fl = 0; uint16_t comp = 0; uint16_t tm = 0; uint16_t dt = 0; uint32_t crc32 = 0; uint32_t comp_size = 0; uint32_t uncomp_size = 0; uint16_t name_len = 0; uint16_t extra_len = 0; };
struct ZipDirHeader { uint32_t sig = 0x02014b50; uint16_t ver_made = 20; uint16_t ver_need = 20; uint16_t fl = 0; uint16_t comp = 0; uint16_t tm = 0; uint16_t dt = 0; uint32_t crc32 = 0; uint32_t comp_size = 0; uint32_t uncomp_size = 0; uint16_t name_len = 0; uint16_t extra_len = 0; uint16_t comment_len = 0; uint16_t disk_start = 0; uint16_t int_attr = 0; uint32_t ext_attr = 0; uint32_t local_offset = 0; };
struct ZipEOCD { uint32_t sig = 0x06054b50; uint16_t disk_num = 0; uint16_t disk_dir_start = 0; uint16_t num_dir_this = 0; uint16_t num_dir_total = 0; uint32_t size_dir = 0; uint32_t offset_dir = 0; uint16_t comment_len = 0; };
#pragma pack(pop)

void DataSetGenerator::write_generic(const std::filesystem::path& path, size_t limit, int limit_type, OutputMode mode, double mix_ratio, GenStats& stats) {
    if (mode == OutputMode::FOLDER) {
        if (std::filesystem::exists(path)) std::filesystem::remove_all(path);
        std::filesystem::create_directories(path);
    }
    else {
        if (path.has_parent_path()) std::filesystem::create_directories(path.parent_path());
    }

    std::ofstream f;
    if (mode != OutputMode::FOLDER) {
        f.open(path, std::ios::binary);
        if (mode == OutputMode::PCAP) {
            PcapGlobalHeader gh; f.write((char*)&gh, sizeof(gh));
        }
    }

    std::mt19937 rng(std::random_device{}());
    std::uniform_real_distribution<double> dist_mix(0.0, 1.0);

    struct ZipEntry { uint32_t off; uint32_t crc; uint32_t sz; std::string name; };
    std::vector<ZipEntry> zip_entries;

    size_t current_count = 0;
    size_t current_bytes = 0;
    uint32_t timestamp = (uint32_t)std::time(nullptr);

    while (true) {
        if (limit_type == 0 && current_count >= limit) break;
        if (limit_type == 1 && current_bytes >= limit) break;

        bool is_mixed = dist_mix(rng) < mix_ratio;
        auto [ext, data] = create_payload(rng, is_mixed);
        update_stats(ext, stats);

        std::string fname = "file_" + std::to_string(current_count) + ext;

        if (mode == OutputMode::FOLDER) {
            std::ofstream sub(path / fname, std::ios::binary);
            sub << data;
        }
        else if (mode == OutputMode::BIN) {
            f << data;
        }
        else if (mode == OutputMode::PCAP) {
            PcapPacketHeader ph;
            ph.ts_sec = timestamp + (uint32_t)current_count;
            ph.ts_usec = 0;
            ph.incl = (uint32_t)data.size();
            ph.orig = (uint32_t)data.size();
            f.write((char*)&ph, sizeof(ph));
            f.write(data.data(), data.size());
        }
        else if (mode == OutputMode::ZIP) {
            uint32_t off = (uint32_t)f.tellp();
            uint32_t crc = calculate_crc32(data);
            ZipLocalHeader lh;
            lh.crc32 = crc;
            lh.comp_size = (uint32_t)data.size();
            lh.uncomp_size = (uint32_t)data.size();
            lh.name_len = (uint16_t)fname.size();
            f.write((char*)&lh, sizeof(lh));
            f.write(fname.data(), fname.size());
            f.write(data.data(), data.size());
            zip_entries.push_back({ off, crc, (uint32_t)data.size(), fname });
        }

        current_count++;
        current_bytes += data.size();

        if (current_count % 20 == 0) {
            std::cout << "\rGenerating: " << current_count << " files | "
                << (current_bytes / 1024 / 1024) << " MB" << std::flush;
        }
    }

    if (mode == OutputMode::ZIP) {
        uint32_t cd_start = (uint32_t)f.tellp();
        for (const auto& e : zip_entries) {
            ZipDirHeader dh;
            dh.crc32 = e.crc; dh.comp_size = e.sz; dh.uncomp_size = e.sz;
            dh.name_len = (uint16_t)e.name.size(); dh.local_offset = e.off;
            f.write((char*)&dh, sizeof(dh));
            f.write(e.name.data(), e.name.size());
        }
        uint32_t cd_size = (uint32_t)f.tellp() - cd_start;
        ZipEOCD eocd;
        eocd.num_dir_this = (uint16_t)zip_entries.size();
        eocd.num_dir_total = (uint16_t)zip_entries.size();
        eocd.size_dir = cd_size; eocd.offset_dir = cd_start;
        f.write((char*)&eocd, sizeof(eocd));
    }

    std::cout << "\n[Generator] Done. Total: " << current_count << " files, "
        << (current_bytes / 1024 / 1024) << " MB.\n";
}

GenStats DataSetGenerator::generate_count(const std::filesystem::path& path, int count, OutputMode mode, double mix) {
    GenStats stats;
    write_generic(path, count, 0, mode, mix, stats);
    return stats;
}

GenStats DataSetGenerator::generate_size(const std::filesystem::path& path, int size_mb, OutputMode mode, double mix) {
    GenStats stats;
    size_t limit_bytes = (size_t)size_mb * 1024 * 1024;
    write_generic(path, limit_bytes, 1, mode, mix, stats);
    return stats;
}