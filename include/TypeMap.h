#pragma once
#include <string>
#include <unordered_map>

// Единственный источник маппинга расширение -> имя типа для всего проекта.
inline const std::unordered_map<std::string, std::string>& ext_to_type_map() {
    static const std::unordered_map<std::string, std::string> m = {
        {".pdf",  "PDF"},
        {".zip",  "ZIP"},
        {".rar",  "RAR4"},
        {".rar5", "RAR5"},
        {".doc",  "DOC"},
        {".xls",  "XLS"},
        {".ppt",  "PPT"},
        {".docx", "DOCX"},
        {".xlsx", "XLSX"},
        {".pptx", "PPTX"},
        {".png",  "PNG"},
        {".jpg",  "JPG"},
        {".gif",  "GIF"},
        {".bmp",  "BMP"},
        {".mkv",  "MKV"},
        {".mp3",  "MP3"},
        {".json", "JSON"},
        {".html", "HTML"},
        {".xml",  "XML"},
        {".eml",  "EMAIL"},
        {".7z",   "7Z"},
        {".gz",   "GZIP"},
        {".exe",  "PE"},
        {".dll",  "PE"},
        {".sqlite", "SQLITE"},
        {".db",   "SQLITE"},
        {".flac", "FLAC"},
        {".wav",  "WAV"}
    };
    return m;
}

inline std::string ext_to_type(const std::string& ext) {
    auto& m = ext_to_type_map();
    auto it = m.find(ext);
    return (it != m.end()) ? it->second : "";
}

// Обратный маппинг: имя типа -> расширение
inline const std::unordered_map<std::string, std::string>& type_to_ext_map() {
    static const std::unordered_map<std::string, std::string> m = [] {
        std::unordered_map<std::string, std::string> result;
        for (const auto& [ext, name] : ext_to_type_map()) {
            result.emplace(name, ext);
        }
        return result;
    }();
    return m;
}
