#include "generator/Generator.h"
#include "TypeMap.h"
#include "ConfigLoader.h"
#include <iostream>
#include <sstream>
#include <random>
#include <ctime>
#include <iomanip>
#include <mutex>

// --- CRC32 ---
static uint32_t crc32_table[256];
static std::once_flag crc_init_flag;

static void init_crc32() {
    std::call_once(crc_init_flag, [] {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int j = 0; j < 8; j++) {
                c = (c & 1) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
            }
            crc32_table[i] = c;
        }
    });
}

// Ловушки (false-positive bait)
static const std::vector<std::string> TRAPS_BIN = {
    "\x50\x4B\xFF\xFF",
    "\x25\x50\x44\x5F",
    "\x47\x49\x46\x39",
    "\xFF\xD8\x00\x00",
    "WordDoc_ment",
    "Workbuuk",
    "PowerPoint Fakument"
};

static const std::vector<std::string> TRAPS_TEXT = {
    "<hmtl fake='yes'>",
    "{\"fake_json\"; 1}",
    "Subject- Fake",
    "%PDF-1.4-fake",
    "PK\x03\x04_fake_text",
    "GIF89a_fake"
};

// Конвертация hex-строки из signatures.json в бинарные байты
static std::string hex_to_bytes(const std::string& hex) {
    std::string result;
    result.reserve(hex.length() / 2);
    for (size_t i = 0; i + 1 < hex.length(); i += 2) {
        unsigned int byte;
        if (std::sscanf(hex.c_str() + i, "%2x", &byte) == 1) {
            result.push_back(static_cast<char>(byte));
        }
    }
    return result;
}

DataSetGenerator::DataSetGenerator(const std::string& config_path) {
    init_crc32();
    load_signatures(config_path);
    add_text_templates();

    for (const auto& [ext, _] : types) extensions.push_back(ext);

    dictionary = {
        "lorem", "ipsum", "dolor", "sit", "amet", "consectetur", "adipiscing", "elit",
        "function", "var", "const", "return", "if", "else", "for", "while",
        "class", "public", "private", "protected", "import", "include",
        "http://example.com", "user@domain.org", "127.0.0.1", "path/to/file",
        "debug", "error", "info", "warning", "trace", "fatal"
    };
}

void DataSetGenerator::load_signatures(const std::string& config_path) {
    auto sigs = ConfigLoader::load(config_path);
    auto& type_ext = type_to_ext_map();

    for (const auto& sig : sigs) {
        if (sig.type == SignatureType::TEXT) continue; // текстовые шаблоны добавляем вручную

        auto it = type_ext.find(sig.name);
        if (it == type_ext.end()) continue; // нет расширения — пропускаем (OLE, RAR5 без .rar5)

        const std::string& ext = it->second;

        FileType ft;
        ft.extension = ext;
        ft.head = hex_to_bytes(sig.hex_head);
        ft.middle = sig.text_pattern; // "WordDocument", "word/document.xml", etc.
        ft.tail = hex_to_bytes(sig.hex_tail);
        ft.is_text = false;

        // Спецкейсы: BMP нуждается в полном 14-байтном заголовке
        if (sig.name == "BMP") {
            ft.head = std::string("\x42\x4D\x36\x00\x0C\x00\x00\x00\x00\x00\x36\x00\x00\x00", 14);
            ft.middle.clear(); // text_pattern в BMP — для сканера, не для генератора
        }
        // GIF: tail в hex — 003B, но нужен бинарный \x00\x3B
        // (hex_to_bytes уже правильно конвертирует)

        types[ext] = ft;
    }
}

void DataSetGenerator::add_text_templates() {
    // Текстовые типы нельзя строить из regex-паттернов — нужен структурный шаблон
    types[".json"] = { ".json", "{ \"k\": ", "", " }", true };
    types[".html"] = { ".html", "<html><body>", "", "</body></html>", true };
    types[".xml"]  = { ".xml", "<?xml version=\"1.0\"?>", "", "", true };
    types[".eml"]  = { ".eml", "From: user@local\nTo: dest@local\nSubject: test\n\n", "", "", true };
}

size_t DataSetGenerator::get_realistic_size(const std::string& ext, std::mt19937& rng) {
    std::uniform_int_distribution<int> chance(0, 100);
    int c = chance(rng);

    auto it = types.find(ext);
    if (it == types.end()) {
        std::uniform_int_distribution<size_t> d(10 * 1024, 100 * 1024);
        return d(rng);
    }

    if (it->second.is_text) {
        std::uniform_int_distribution<size_t> d(1024, 200 * 1024);
        return d(rng);
    }
    else if (ext == ".mkv" || ext == ".mp3") {
        std::uniform_int_distribution<size_t> d(1 * 1024 * 1024, 5 * 1024 * 1024);
        return d(rng);
    }
    else {
        if (c < 50) {
            std::uniform_int_distribution<size_t> d(10 * 1024, 100 * 1024);
            return d(rng);
        }
        else if (c < 90) {
            std::uniform_int_distribution<size_t> d(100 * 1024, 1 * 1024 * 1024);
            return d(rng);
        }
        else {
            std::uniform_int_distribution<size_t> d(1 * 1024 * 1024, 5 * 1024 * 1024);
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
        std::uniform_int_distribution<int> byte_dist(0, 255);
        while (written < count) {
            if (trap_chance(rng) < 2 && written + 20 < count) {
                std::uniform_int_distribution<size_t> t_idx(0, TRAPS_BIN.size() - 1);
                std::string trap = TRAPS_BIN[t_idx(rng)];
                ss.write(trap.data(), trap.size());
                written += trap.size();
            }
            else {
                ss.put(static_cast<char>(byte_dist(rng)));
                written++;
            }
        }
    }
}

std::pair<std::string, std::string> DataSetGenerator::create_payload(std::mt19937& rng, bool is_mixed) {
    std::uniform_int_distribution<size_t> dist_idx(0, extensions.size() - 1);
    std::stringstream ss;
    std::string primary_ext;

    int parts = is_mixed ? (2 + static_cast<int>(rng() % 2)) : 1;

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
        size_t pre_marker = std::min(static_cast<size_t>(50), body);
        size_t post_marker = body - pre_marker;

        fill_complex(ss, pre_marker, t.is_text, rng);
        ss << t.middle;
        fill_complex(ss, post_marker, t.is_text, rng);
        ss << t.tail;
    }
    return { primary_ext, ss.str() };
}

void DataSetGenerator::update_stats(const std::string& ext, GenStats& stats) {
    std::string type = ext_to_type(ext);
    if (!type.empty()) stats.add(type);
    stats.total_files_processed++;
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

void DataSetGenerator::write_generic(const std::filesystem::path& path, size_t limit, int limit_type, OutputMode mode, double mix_ratio, GenStats& stats, uint32_t seed) {
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
            PcapGlobalHeader gh;
            f.write(reinterpret_cast<const char*>(&gh), sizeof(gh));
        }
    }

    std::mt19937 rng(seed ? seed : std::random_device{}());
    std::uniform_real_distribution<double> dist_mix(0.0, 1.0);

    struct ZipEntry { uint32_t off; uint32_t crc; uint32_t sz; std::string name; };
    std::vector<ZipEntry> zip_entries;

    size_t current_count = 0;
    size_t current_bytes = 0;
    uint32_t timestamp = static_cast<uint32_t>(std::time(nullptr));

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
            ph.ts_sec = timestamp + static_cast<uint32_t>(current_count);
            ph.ts_usec = 0;
            ph.incl = static_cast<uint32_t>(data.size());
            ph.orig = static_cast<uint32_t>(data.size());
            f.write(reinterpret_cast<const char*>(&ph), sizeof(ph));
            f.write(data.data(), data.size());
        }
        else if (mode == OutputMode::ZIP) {
            uint32_t off = static_cast<uint32_t>(f.tellp());
            uint32_t crc = calculate_crc32(data);
            ZipLocalHeader lh;
            lh.crc32 = crc;
            lh.comp_size = static_cast<uint32_t>(data.size());
            lh.uncomp_size = static_cast<uint32_t>(data.size());
            lh.name_len = static_cast<uint16_t>(fname.size());
            f.write(reinterpret_cast<const char*>(&lh), sizeof(lh));
            f.write(fname.data(), fname.size());
            f.write(data.data(), data.size());
            zip_entries.push_back({ off, crc, static_cast<uint32_t>(data.size()), fname });
        }

        current_count++;
        current_bytes += data.size();
    }

    if (mode == OutputMode::ZIP) {
        uint32_t cd_start = static_cast<uint32_t>(f.tellp());
        for (const auto& e : zip_entries) {
            ZipDirHeader dh;
            dh.crc32 = e.crc;
            dh.comp_size = e.sz;
            dh.uncomp_size = e.sz;
            dh.name_len = static_cast<uint16_t>(e.name.size());
            dh.local_offset = e.off;
            f.write(reinterpret_cast<const char*>(&dh), sizeof(dh));
            f.write(e.name.data(), e.name.size());
        }
        uint32_t cd_size = static_cast<uint32_t>(f.tellp()) - cd_start;
        ZipEOCD eocd;
        eocd.num_dir_this = static_cast<uint16_t>(zip_entries.size());
        eocd.num_dir_total = static_cast<uint16_t>(zip_entries.size());
        eocd.size_dir = cd_size;
        eocd.offset_dir = cd_start;
        f.write(reinterpret_cast<const char*>(&eocd), sizeof(eocd));
    }
}

GenStats DataSetGenerator::generate_count(const std::filesystem::path& path, int count, OutputMode mode, double mix, uint32_t seed) {
    GenStats stats;
    write_generic(path, count, 0, mode, mix, stats, seed);
    return stats;
}

GenStats DataSetGenerator::generate_size(const std::filesystem::path& path, int size_mb, OutputMode mode, double mix, uint32_t seed) {
    GenStats stats;
    size_t limit_bytes = static_cast<size_t>(size_mb) * 1024 * 1024;
    write_generic(path, limit_bytes, 1, mode, mix, stats, seed);
    return stats;
}
