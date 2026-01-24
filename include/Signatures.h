#pragma once
#include <string>
#include <sstream>
#include <iomanip>

namespace Sig {
    enum class Engine { STD, BOOST, RE2, HS };

    namespace Bin {
        const std::string PDF_HEAD = "\x25\x50\x44\x46";
        const std::string PDF_TAIL = "\x25\x25\x45\x4F\x46";

        const std::string ZIP_HEAD = "\x50\x4B\x03\x04";
        const std::string ZIP_TAIL = "\x50\x4B\x05\x06";

        const std::string OLE = "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1";
        const std::string OLE_WORD = "WordDocument";
        const std::string OLE_XL = "Workbook";
        const std::string OLE_PPT = "PowerPoint Document";

        const std::string XML_WORD = "word/document.xml";
        const std::string XML_XL = "xl/workbook.xml";
        const std::string XML_PPT = "ppt/presentation.xml";

        const std::string RAR4("\x52\x61\x72\x21\x1A\x07\x00", 7);
        const std::string RAR5("\x52\x61\x72\x21\x1A\x07\x01\x00", 8);
        const std::string PNG_HEAD = "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A";
        const std::string PNG_TAIL = "\x49\x45\x4E\x44\xAE\x42\x60\x82";
        const std::string JPG_HEAD = "\xFF\xD8\xFF";
        const std::string JPG_TAIL = "\xFF\xD9";
        const std::string GIF_HEAD = "\x47\x49\x46\x38";
        const std::string GIF_TAIL("\x00\x3B", 2);
        const std::string BMP_HEAD = "\x42\x4D[\\s\\S]{4}\\x00\\x00"; // BMP оставляем как есть, это короткий паттерн

        const std::string MKV = "\x1A\x45\xDF\xA3";
        const std::string MP3 = "\x49\x44\x33";
    }

    namespace Text {
        const std::string HTML_HEAD = "<html";
        const std::string HTML_TAIL = "</html>";
        const std::string XML = "<\\?xml";
        const std::string JSON_HEAD = "\\{\\s*\"[^\"]+\"\\s*:";
        const std::string JSON_TAIL = "\\}";
        const std::string EML = "From:\\s";
    }

    inline std::string raw_to_hex(const std::string& raw) {
        std::ostringstream ss;
        for (unsigned char c : raw) {
            ss << "\\x" << std::hex << std::setw(2) << std::setfill('0') << (int)c;
        }
        return ss.str();
    }

    const std::string ANY = "[\\s\\S]";
    const std::string LIMIT_STD = "{0,10000000}";

    // --- ЛОГИКА ГЕНЕРАЦИИ ---

    template <Engine E>
    std::string complex(const std::string& head_raw, const std::string& marker_raw) {
        if constexpr (E == Engine::HS) {
            return raw_to_hex(head_raw) + ".*?" + raw_to_hex(marker_raw);
        }

        // Для OLE (Старый офис) нужен заголовок + маркер
        if (head_raw == Bin::OLE) {
            std::string mid;
            // [FIX] Для RE2 используем точку (.) вместо ANY ([\s\S]), 
            // так как set_dot_nl(true) включен, а [\s\S]*? может сбоить.
            if constexpr (E == Engine::RE2) mid = ".*?";
            else mid = ANY + "{0,50000}";

            return raw_to_hex(head_raw) + mid + raw_to_hex(marker_raw);
        }

        // Для Нового офиса (DOCX) только якорь
        return raw_to_hex(marker_raw);
    }

    template <Engine E>
    std::string framed(const std::string& head_raw, const std::string& tail_raw) {
        if (head_raw == Bin::ZIP_HEAD && E != Engine::HS) {
            return raw_to_hex(tail_raw);
        }

        std::string head = raw_to_hex(head_raw);
        std::string tail = raw_to_hex(tail_raw);

        if constexpr (E == Engine::HS) {
            return head + ".*?" + tail;
        }
        else if constexpr (E == Engine::RE2) {
            // [FIX] RE2: используем точку (.) с ленивым квантификатором *?
            return head + ".*?" + tail;
        }
        else {
            return head + ANY + LIMIT_STD + "?" + tail;
        }
    }

    template <Engine E>
    std::string framed_text(const std::string& head, const std::string& tail) {
        if constexpr (E == Engine::HS) return head + ".*?" + tail;
        else if constexpr (E == Engine::RE2) return head + ".*?" + tail; // [FIX] точка вместо ANY
        else return head + ANY + LIMIT_STD + "?" + tail;
    }
}
