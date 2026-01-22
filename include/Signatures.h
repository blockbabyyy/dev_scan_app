#pragma once
#include <string>
#include <sstream>
#include <iomanip>

namespace Sig {
    namespace Bin {
        const std::string PDF_HEAD = "\x25\x50\x44\x46";
        const std::string PDF_TAIL = "\x25\x25\x45\x4F\x46"; // %%EOF

        const std::string ZIP_HEAD = "\x50\x4B\x03\x04";
        const std::string ZIP_TAIL = "\x50\x4B\x05\x06";

        const std::string OLE = "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1";

        const std::string RAR4("\x52\x61\x72\x21\x1A\x07\x00", 7);
        const std::string RAR5("\x52\x61\x72\x21\x1A\x07\x01\x00", 8);

        const std::string PNG_HEAD = "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A";
        const std::string PNG_TAIL = "\x49\x45\x4E\x44\xAE\x42\x60\x82";

        const std::string JPG_HEAD = "\xFF\xD8\xFF";
        const std::string JPG_TAIL = "\xFF\xD9";

        const std::string GIF_HEAD = "\x47\x49\x46\x38";
        const std::string GIF_TAIL = "\x00\x3B";

        // BMP: BM + 4 bytes size + 2 bytes reserved (00 00) + 2 bytes reserved (00 00)
        // Упростим: BM + 4 любых + \x00\x00
        // Это отсечет 99% мусора
        const std::string BMP_HEAD = "\x42\x4D.{4}\\x00\\x00";

        const std::string MKV = "\x1A\x45\xDF\xA3";
        const std::string MP3 = "\x49\x44\x33";

        const std::string OLE_WORD = "WordDocument";
        const std::string OLE_XL = "Workbook";
        const std::string OLE_PPT = "PowerPoint Document";

        const std::string XML_WORD = "word/";
        const std::string XML_XL = "xl/";
        const std::string XML_PPT = "ppt/";
    }

    namespace Text {
        const std::string HTML_HEAD = "<html";
        const std::string HTML_TAIL = "</html>";
        const std::string XML = "<\\?xml";
        const std::string JSON_HEAD = "\\{\\s*\"";
        const std::string JSON_TAIL = "\\}";
        const std::string EML = "(?:Date|From|Received|Subject):\\s";
    }

    inline std::string raw_to_hex(const std::string& raw) {
        std::ostringstream ss;
        for (unsigned char c : raw) {
            ss << "\\x" << std::hex << std::setw(2) << std::setfill('0') << (int)c;
        }
        return ss.str();
    }

    // [\s\S] - универсальная "точка", работающая везде.
    const std::string ANY = "[\\s\\S]";

    // Лимит для Std/Boost/RE2 (4MB), чтобы не переполнять стек.
    const std::string LIMIT_STD = "{0,4194304}";

    inline std::string complex(const std::string& head_raw, const std::string& marker_raw) {
        return raw_to_hex(head_raw) + ANY + "{0,1024}" + raw_to_hex(marker_raw);
    }

    // is_hs = true -> генерируем регулярку для Hyperscan (без лимитов)
    // is_hs = false -> генерируем регулярку с лимитом для Std/RE2
    inline std::string framed(const std::string& head_raw, const std::string& tail_raw, bool is_hs) {
        if (is_hs) {
            // Hyperscan: используем .*? (ленивый), флаг DOTALL включается в API
            return raw_to_hex(head_raw) + ".*?" + raw_to_hex(tail_raw);
        }
        else {
            // Std/Boost/RE2: используем [\s\S]{0,N}? (ленивый с лимитом)
            return raw_to_hex(head_raw) + ANY + LIMIT_STD + "?" + raw_to_hex(tail_raw);
        }
    }

    inline std::string framed_text(const std::string& head, const std::string& tail, bool is_hs) {
        if (is_hs) {
            return head + ".*?" + tail;
        }
        else {
            return head + ANY + LIMIT_STD + "?" + tail;
        }
    }
}