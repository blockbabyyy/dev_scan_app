#include "Scanner.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <re2/re2.h>
#include <re2/set.h>
#include <hs/hs.h>

namespace {
    std::string hex_to_regex_str(const std::string& hex) {
        if (hex.empty()) return "";
        if (hex.length() % 2 != 0) {
            std::cerr << "[Scanner] Warning: odd-length hex string '" << hex
                      << "', last nibble dropped\n";
        }
        std::ostringstream ss;
        for (size_t i = 0; i + 1 < hex.length(); i += 2) {
            char c1 = hex[i], c2 = hex[i + 1];
            if (!std::isxdigit(static_cast<unsigned char>(c1)) ||
                !std::isxdigit(static_cast<unsigned char>(c2))) {
                std::cerr << "[Scanner] Warning: non-hex chars at pos " << i
                          << " in '" << hex << "'\n";
            }
            ss << "\\x" << c1 << c2;
        }
        return ss.str();
    }

    std::string build_pattern(const SignatureDefinition& def) {
        if (def.type == SignatureType::TEXT) return def.text_pattern;

        std::string head = hex_to_regex_str(def.hex_head);
        std::string tail = hex_to_regex_str(def.hex_tail);

        // text_pattern может быть hex строкой (для UTF-16LE паттернов OLE)
        // или обычным regex паттерном
        std::string pattern;
        if (!def.text_pattern.empty()) {
            // Проверяем, является ли text_pattern hex строкой (только 0-9A-Fa-F)
            bool is_hex = true;
            for (char c : def.text_pattern) {
                if (!std::isxdigit(static_cast<unsigned char>(c))) {
                    is_hex = false;
                    break;
                }
            }
            if (is_hex && def.text_pattern.length() % 2 == 0) {
                pattern = hex_to_regex_str(def.text_pattern);
            } else {
                pattern = def.text_pattern;
            }
        }

        // Для бинарных сигнатур с hex_head — привязка к началу файла
        // Это предотвращает ложные срабатывания когда сигнатура найдена в середине файла
        if (!head.empty() && !tail.empty()) return "^" + head + ".*?" + tail;
        if (!head.empty() && !pattern.empty()) return "^" + head + ".*?" + pattern;
        if (!head.empty()) return "^" + head;

        // Fallback: head пуст, но есть pattern или tail
        if (!pattern.empty()) return pattern;
        if (!tail.empty()) return tail;

        return "";
    }
}

// NOTE: deduction is single-pass (flat). Transitive chains (A deducts B, B deducts C)
// are not supported — if such chains are added to signatures.json, a topological-sort
// pass will be required here.
void apply_deduction(ScanStats& stats, const std::vector<SignatureDefinition>& sigs) {
    for (const auto& def : sigs) {
        if (!def.deduct_from.empty()) {
            const std::string& child = def.name;
            const std::string& parent = def.deduct_from;
            if (stats.counts.count(child) && stats.counts.count(parent)) {
                int child_count = stats.counts[child];
                stats.counts[parent] = std::max(0, stats.counts[parent] - child_count);
            }
        }
    }
}

// Apply container hierarchy: if ZIP-derived format detected, reduce ZIP count
void apply_container_hierarchy(ScanStats& stats) {
    // DOCX/XLSX/PPTX are ZIP containers — subtract them from ZIP count
    const std::vector<std::string> zip_derivatives = {"DOCX", "XLSX", "PPTX"};
    int zip_derived_count = 0;
    for (const auto& deriv : zip_derivatives) {
        if (stats.counts.count(deriv)) {
            zip_derived_count += stats.counts[deriv];
        }
    }
    if (zip_derived_count > 0 && stats.counts.count("ZIP")) {
        stats.counts["ZIP"] = std::max(0, stats.counts["ZIP"] - zip_derived_count);
    }
}

// Move detections from recursive container scanning to embedded_counts
// This function is called after all containers have been recursively scanned
// The containers_to_scan queue is populated during initial scanning when a container is detected
void apply_embedded_detection_filter(ScanStats& stats) {
    // This function is now a no-op because embedded_counts are populated directly
    // during recursive container scanning in main_cli.cpp
    // The old heuristic-based approach (apply_container_false_positive_filter) has been removed
}

// Handle mutually exclusive signatures (e.g., RAR4 vs RAR5)
// If RAR5 is detected, RAR4 should not be counted (RAR5 includes RAR4 header)
void apply_exclusive_filter(ScanStats& stats, const std::vector<SignatureDefinition>& sigs) {
    for (const auto& def : sigs) {
        if (def.exclusive_with.empty()) continue;
        
        const std::string& name = def.name;
        if (!stats.counts.count(name)) continue;
        
        // Check if any exclusive signature is also detected
        for (const auto& exclusive : def.exclusive_with) {
            if (stats.counts.count(exclusive)) {
                // This signature is exclusive with another detected one
                // Keep the one with higher priority
                int this_priority = def.priority;
                int other_priority = 0;
                for (const auto& s : sigs) {
                    if (s.name == exclusive) {
                        other_priority = s.priority;
                        break;
                    }
                }
                
                if (this_priority < other_priority) {
                    // Remove this one, keep the other
                    stats.counts.erase(name);
                } else {
                    // Remove the other one
                    stats.counts.erase(exclusive);
                }
            }
        }
    }
}

std::unique_ptr<Scanner> Scanner::create(EngineType type) {
    switch (type) {
    case EngineType::BOOST: return std::make_unique<BoostScanner>();
    case EngineType::RE2:   return std::make_unique<Re2Scanner>();
    case EngineType::HYPERSCAN: return std::make_unique<HsScanner>();
    default: return std::make_unique<HsScanner>();
    }
}

// === Boost ===
std::string BoostScanner::name() const { return "Boost.Regex"; }
void BoostScanner::prepare(const std::vector<SignatureDefinition>& sigs) {
    m_regexes.clear();
    
    // Sort signatures by priority (higher first) for correct matching order
    std::vector<SignatureDefinition> sorted_sigs = sigs;
    std::sort(sorted_sigs.begin(), sorted_sigs.end(), 
        [](const auto& a, const auto& b) { return a.priority > b.priority; });
    
    for (const auto& s : sorted_sigs) {
        std::string pat = build_pattern(s);
        if (pat.empty()) continue;
        try {
            auto flags = boost::regex::optimize | boost::regex::mod_s;
            if (s.type == SignatureType::TEXT) flags |= boost::regex::icase;
            m_regexes.emplace_back(boost::regex(pat, flags), s.name);
        }
        catch (const std::exception& e) {
            std::cerr << "[BoostScanner] Failed to compile pattern for '"
                      << s.name << "': " << e.what() << "\n";
        }
    }
}
void BoostScanner::scan(const char* data, size_t size, ScanStats& stats) {
    const char* end = data + size;
    for (const auto& [re, name] : m_regexes) {
        boost::cmatch m;
        const char* cur = data;
        while (cur < end && boost::regex_search(cur, end, m, re)) {
            stats.add_once(name);  // Use add_once to prevent multiple counts per file
            cur += m.position() + std::max(static_cast<std::ptrdiff_t>(1), m.length());
        }
    }
}

// === RE2 (two-phase: Set filter → individual count) ===
void Re2SetDeleter::operator()(void* p) const noexcept {
    delete static_cast<re2::RE2::Set*>(p);
}

Re2Scanner::Re2Scanner() = default;  // re2::RE2 is complete here
Re2Scanner::~Re2Scanner() = default;

std::string Re2Scanner::name() const { return "Google RE2"; }

void Re2Scanner::prepare(const std::vector<SignatureDefinition>& sigs) {
    m_set.reset();
    m_sig_names.clear();
    m_regexes.clear();

    // Sort signatures by priority (higher first) for correct matching order
    std::vector<SignatureDefinition> sorted_sigs = sigs;
    std::sort(sorted_sigs.begin(), sorted_sigs.end(), 
        [](const auto& a, const auto& b) { return a.priority > b.priority; });

    // Build individual regexes (for phase 2 counting)
    for (const auto& s : sorted_sigs) {
        std::string pat = build_pattern(s);
        if (pat.empty()) continue;

        re2::RE2::Options opt;
        opt.set_encoding(re2::RE2::Options::EncodingLatin1);
        opt.set_dot_nl(true);
        if (s.type == SignatureType::TEXT) opt.set_case_sensitive(false);
        auto re = std::make_unique<re2::RE2>(pat, opt);
        if (re->ok()) {
            m_regexes.emplace_back(std::move(re), s.name);
            m_sig_names.push_back(s.name);
        }
    }

    // Build RE2::Set (for phase 1 filtering)
    re2::RE2::Options set_opt;
    set_opt.set_encoding(re2::RE2::Options::EncodingLatin1);
    set_opt.set_dot_nl(true);
    std::unique_ptr<void, Re2SetDeleter> new_set(new re2::RE2::Set(set_opt, re2::RE2::UNANCHORED));
    auto* raw = static_cast<re2::RE2::Set*>(new_set.get());

    for (const auto& [re, sig_name] : m_regexes) {
        std::string err;
        raw->Add(re->pattern(), &err);
    }
    if (raw->Compile()) {
        m_set = std::move(new_set);
    }
}

void Re2Scanner::scan(const char* data, size_t size, ScanStats& stats) {
    auto* set = static_cast<re2::RE2::Set*>(m_set.get());
    if (!set) {
        // Fallback: no set compiled, scan all individually
        for (const auto& [re, name] : m_regexes) {
            re2::StringPiece input(data, size);
            while (re2::RE2::FindAndConsume(&input, *re)) stats.add_once(name);
        }
        return;
    }

    // Phase 1: fast filter — which patterns match at all?
    std::vector<int> matched_ids;
    set->Match(re2::StringPiece(data, size), &matched_ids);

    // Phase 2: count matches only for patterns that were found
    for (int id : matched_ids) {
        const auto& [re, name] = m_regexes[id];
        re2::StringPiece input(data, size);
        while (re2::RE2::FindAndConsume(&input, *re)) stats.add_once(name);
    }
}

// === Hyperscan ===
HsScanner::HsScanner() = default;
HsScanner::~HsScanner() {
    if (scratch) hs_free_scratch(scratch);
    if (db) hs_free_database(db);
}
std::string HsScanner::name() const { return "Hyperscan"; }
void HsScanner::prepare(const std::vector<SignatureDefinition>& sigs) {
    if (scratch) { hs_free_scratch(scratch); scratch = nullptr; }
    if (db) { hs_free_database(db); db = nullptr; }
    m_temp_patterns.clear(); m_sig_names.clear();
    m_temp_patterns.reserve(sigs.size());

    // Sort signatures by priority (higher first) for correct matching order
    std::vector<SignatureDefinition> sorted_sigs = sigs;
    std::sort(sorted_sigs.begin(), sorted_sigs.end(), 
        [](const auto& a, const auto& b) { return a.priority > b.priority; });

    std::vector<const char*> exprs;
    std::vector<unsigned int> flags, ids;

    for (size_t i = 0; i < sorted_sigs.size(); ++i) {
        std::string pat = build_pattern(sorted_sigs[i]);
        if (pat.empty()) continue;
        m_temp_patterns.push_back(pat);
        m_sig_names.push_back(sorted_sigs[i].name);
        exprs.push_back(m_temp_patterns.back().c_str());
        ids.push_back(static_cast<unsigned int>(m_sig_names.size() - 1));
        flags.push_back(HS_FLAG_DOTALL | (sorted_sigs[i].type == SignatureType::TEXT ? HS_FLAG_CASELESS : 0));
    }

    if (exprs.empty()) return;
    hs_compile_error_t* err;
    if (hs_compile_multi(exprs.data(), flags.data(), ids.data(), static_cast<unsigned int>(exprs.size()), HS_MODE_BLOCK, nullptr, &db, &err) != HS_SUCCESS) {
        std::cerr << "[Scanner] HS Compile Error: " << err->message << std::endl;
        hs_free_compile_error(err);
    }
    else {
        hs_alloc_scratch(db, &scratch);
    }
}
void HsScanner::scan(const char* data, size_t size, ScanStats& stats) {
    if (!db || !scratch) return;
    // ASSERT: this method must not be called concurrently on the same instance (scratch is not thread-safe).
    struct Ctx { ScanStats* s; const std::vector<std::string>* n; } ctx = { &stats, &m_sig_names };
    auto on_match = [](unsigned int id, unsigned long long, unsigned long long, unsigned int, void* ptr) -> int {
        auto* c = static_cast<Ctx*>(ptr);
        if (id < c->n->size()) c->s->add_once((*c->n)[id]);  // Use add_once to prevent multiple counts
        return 0;
    };
    hs_scan(db, data, size, 0, scratch, on_match, &ctx);
}
