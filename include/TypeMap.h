#pragma once
#include <string>
#include <unordered_map>
#include <vector>
#include "Scanner.h"

// Build extension -> type name map from loaded signatures.
inline std::unordered_map<std::string, std::string>
build_ext_to_type(const std::vector<SignatureDefinition>& sigs) {
    std::unordered_map<std::string, std::string> m;
    for (const auto& s : sigs)
        for (const auto& ext : s.extensions)
            m.emplace(ext, s.name);
    return m;
}

// Build type name -> primary extension map (first extension wins).
inline std::unordered_map<std::string, std::string>
build_type_to_ext(const std::vector<SignatureDefinition>& sigs) {
    std::unordered_map<std::string, std::string> m;
    for (const auto& s : sigs)
        if (!s.extensions.empty())
            m.emplace(s.name, s.extensions[0]);
    return m;
}
