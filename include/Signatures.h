#pragma once
#include <string>
#include <sstream>
#include <iomanip>

namespace Sig {
    namespace Bin {
        const std::string PDF = "\x25\x50\x44\x46";
        const std::string OLE = "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1";
        const std::string ZIP = "\x50\x4B\x03\x04";
        const std::string RAR4("\x52\x61\x72\x21\x1A\x07\x00", 7);
        const std::string RAR5("\x52\x61\x72\x21\x1A\x07\x01\x00", 8);

        const std::string PNG = "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A";
        const std::string JPG = "\xFF\xD8\xFF";
        const std::string GIF = "\x47\x49\x46\x38";
        const std::string BMP = "\x42\x4D";
        const std::string MKV = "\x1A\x45\xDF\xA3";
        const std::string MP3 = "\x49\x44\x33";


        //вторичные сигнатуры для разделения офисных файлов
        const std::string OLE_WORD = "WordDocument";
        const std::string OLE_XL = "Workbook";
        const std::string OLE_PPT = "PowerPoint Document";

        // OpenXML Markers (Internal ZIP paths)
        const std::string XML_WORD = "word/";
        const std::string XML_XL = "xl/";
        const std::string XML_PPT = "ppt/";


    }

    namespace Text {
        // Убрали ^ из начала, добавим в коде
        // HTML: <html или <!DOCTYPE html
        const std::string HTML = "\\s*(?:<!DOCTYPE\\s+html|<html)";
        // XML: <?xml
        const std::string XML = "\\s*<\\?xml";
        // JSON: { или [
        const std::string JSON = "\\s*(?:\\{|\\[)";
        // EML: Упростили. Просто ищем валидный заголовок в начале.
        const std::string EML = "(?:Date|From|Received|Subject):\\s";
    }

    inline std::string raw_to_hex(const std::string& raw) {
        std::ostringstream ss;
        for (unsigned char c : raw) {
            ss << "\\x" << std::hex << std::setw(2) << std::setfill('0') << (int)c;
        }
        return ss.str();
    }

	// Комплексная сигнатура: заголовок + любые символы + контент
    inline std::string complex(const std::string& head_raw, const std::string& marker_raw) {
        
        std::string pattern = raw_to_hex(head_raw);
        pattern += ".*";
        pattern += raw_to_hex(marker_raw);

        return pattern;
    }
}