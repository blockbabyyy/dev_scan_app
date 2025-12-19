#pragma once
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

namespace Sig {
        
       
    // 1. БИНАРНЫЕ СИГНАТУРЫ
    namespace Bin {
        // Документы
        const std::string PDF = "\x25\x50\x44\x46";                         // %PDF
        const std::string OLE = "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1";     // DOC, XLS, PPT (Old)
        const std::string ZIP = "\x50\x4B\x03\x04";                         // ZIP, DOCX, XLSX

        // Архивы (RAR4 содержит null byte, поэтому задаем через конструктор длины)
        const std::string RAR4("\x52\x61\x72\x21\x1A\x07\x00", 7);
        const std::string RAR5("\x52\x61\x72\x21\x1A\x07\x01\x00", 8);

        // Медиа
        const std::string PNG = "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A";
        const std::string JPG = "\xFF\xD8\xFF";
        const std::string GIF = "\x47\x49\x46\x38"; // GIF8
        const std::string BMP = "\x42\x4D";         // BM
        const std::string MKV = "\x1A\x45\xDF\xA3"; // Matroska / WebM
        const std::string MP3 = "\x49\x44\x33";     // ID3v2 container
    }

    // 2. СЛОЖНЫЕ РЕГУЛЯРНЫЕ ВЫРАЖЕНИЯ (Regex)    
    namespace Text {
        // HTML: Пробелы, DOCTYPE или <html (регистронезависимо)
        const std::string HTML = "^\\s*(?:<!DOCTYPE\\s+html|<html)"; 

        // XML: Пробелы, <?xml
        const std::string XML = "^\\s*<\\?xml";

        // JSON: { или [
        const std::string JSON = "^\\s*(?:\\{|\\[)";

        // EML: Заголовки почты
        const std::string EML = "^(Date:|From:|Received:|Return-Path:|Subject:|To:)\\s";
    }


    // Превращает сырые байты в HEX-regex для Hyperscan/Regex (например: "^\x25\x50...")
    inline std::string raw_to_hex(const std::string& raw) {
        std::ostringstream ss;
        ss << "^"; // Добавляем якорь начала
        for (unsigned char c : raw) {
            ss << "\\x" << std::hex << std::setw(2) << std::setfill('0') << (int)c;
        }
        return ss.str();
    }
}