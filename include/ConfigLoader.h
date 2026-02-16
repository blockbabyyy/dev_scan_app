#pragma once

#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include "Scaner.h"

using json = nlohmann::json;

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
            json j;
            f >> j;

            if (!j.is_array()) {
                std::cerr << "[ConfigLoader] Error: Root must be an array []\n";
                return sigs;
            }

            for (const auto& item : j) {
                SignatureDefinition def;

                if (!item.contains("name")) continue;
                def.name = item["name"].get<std::string>();

                std::string type_str = item.value("type", "binary");
                if (type_str == "text") {
                    def.type = SignatureType::TEXT;
                    if (item.contains("pattern")) def.text_pattern = item["pattern"].get<std::string>();
                }
                else {
                    def.type = SignatureType::BINARY;
                    if (item.contains("hex_head")) def.hex_head = item["hex_head"].get<std::string>();
                    if (item.contains("hex_tail")) def.hex_tail = item["hex_tail"].get<std::string>();
                }

                // [ВАЖНО] Читаем поле для коррекции коллизий
                if (item.contains("deduct_from")) {
                    def.deduct_from = item["deduct_from"].get<std::string>();
                }

                sigs.push_back(def);
            }
        }
        catch (const std::exception& e) {
            std::cerr << "[ConfigLoader] JSON Error: " << e.what() << "\n";
        }
        return sigs;
    }
};
