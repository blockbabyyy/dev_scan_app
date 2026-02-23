#pragma once

#include <vector>
#include <string>
#include <set>
#include <fstream>
#include <iostream>
#include <cctype>
#include <nlohmann/json.hpp>
#include "Scanner.h"

class ConfigLoader {
public:
    static std::vector<SignatureDefinition> load(const std::string& filepath) {
        std::vector<SignatureDefinition> sigs;
        std::ifstream f(filepath);

        if (!f.is_open()) {
            std::cerr << "[ConfigLoader] Warning: Could not open " << filepath << "\n";
            return sigs;
        }

        try {
            nlohmann::json j;
            f >> j;

            if (!j.is_array()) {
                std::cerr << "[ConfigLoader] Error: Root must be an array []\n";
                return sigs;
            }

            for (size_t idx = 0; idx < j.size(); ++idx) {
                const auto& item = j[idx];
                SignatureDefinition def;

                if (!item.contains("name")) {
                    std::cerr << "[ConfigLoader] Warning: entry #" << idx << " has no 'name', skipped\n";
                    continue;
                }
                def.name = item["name"].get<std::string>();

                std::string type_str = item.value("type", "binary");
                if (type_str == "text") {
                    def.type = SignatureType::TEXT;
                    if (item.contains("pattern")) {
                        def.text_pattern = item["pattern"].get<std::string>();
                    } else {
                        std::cerr << "[ConfigLoader] Warning: '" << def.name
                                  << "' is text but has no 'pattern'\n";
                    }
                }
                else {
                    def.type = SignatureType::BINARY;
                    if (item.contains("hex_head")) def.hex_head = item["hex_head"].get<std::string>();
                    if (item.contains("hex_tail")) def.hex_tail = item["hex_tail"].get<std::string>();
                    if (item.contains("text_pattern")) def.text_pattern = item["text_pattern"].get<std::string>();

                    if (!validate_hex(def.hex_head, def.name, "hex_head")) def.hex_head.clear();
                    if (!validate_hex(def.hex_tail, def.name, "hex_tail")) def.hex_tail.clear();

                    if (def.hex_head.empty() && def.hex_tail.empty() && def.text_pattern.empty()) {
                        std::cerr << "[ConfigLoader] Warning: '" << def.name
                                  << "' is binary but has no hex_head, hex_tail, or text_pattern\n";
                    }
                }

                if (item.contains("extensions")) {
                    for (const auto& e : item["extensions"])
                        def.extensions.push_back(e.get<std::string>());
                }

                if (item.contains("deduct_from")) {
                    def.deduct_from = item["deduct_from"].get<std::string>();
                }

                sigs.push_back(def);
            }

            // Check for duplicate names
            std::set<std::string> names;
            for (const auto& s : sigs) {
                if (!names.insert(s.name).second) {
                    std::cerr << "[ConfigLoader] Warning: duplicate signature name '"
                              << s.name << "'\n";
                }
            }
            // Validate deduct_from references
            for (const auto& s : sigs) {
                if (!s.deduct_from.empty() && names.find(s.deduct_from) == names.end()) {
                    std::cerr << "[ConfigLoader] Warning: '" << s.name
                              << "' references deduct_from '" << s.deduct_from
                              << "' which does not exist\n";
                }
            }
        }
        catch (const std::exception& e) {
            std::cerr << "[ConfigLoader] JSON Error: " << e.what() << "\n";
        }
        return sigs;
    }

private:
    static bool validate_hex(const std::string& hex, const std::string& sig_name, const char* field) {
        if (hex.empty()) return true;
        if (hex.length() % 2 != 0) {
            std::cerr << "[ConfigLoader] Warning: '" << sig_name << "' " << field
                      << " has odd length (" << hex.length() << ")\n";
            return false;
        }
        for (size_t i = 0; i < hex.length(); ++i) {
            if (!std::isxdigit(static_cast<unsigned char>(hex[i]))) {
                std::cerr << "[ConfigLoader] Warning: '" << sig_name << "' " << field
                          << " has non-hex char at pos " << i << "\n";
                return false;
            }
        }
        return true;
    }
};
