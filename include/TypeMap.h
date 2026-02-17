#pragma once
#include <string>
#include <unordered_map>

// Единственный источник маппинга расширение -> имя типа для всего проекта.
// Используется в Generator::update_stats(), IntegrationTests, Benchmarks.
inline const std::unordered_map<std::string, std::string>& ext_to_type_map() {
    static const std::unordered_map<std::string, std::string> m = {
        {".pdf",  "PDF"},
        {".zip",  "ZIP"},
        {".rar",  "RAR4"},
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
        {".eml",  "EMAIL"}
    };
    return m;
}

inline std::string ext_to_type(const std::string& ext) {
    auto& m = ext_to_type_map();
    auto it = m.find(ext);
    return (it != m.end()) ? it->second : "";
}
