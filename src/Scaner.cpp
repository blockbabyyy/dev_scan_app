#include "Scaner.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <re2/re2.h>
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

        if (!head.empty() && !tail.empty()) return head + ".*?" + tail;
        if (!head.empty() && !def.text_pattern.empty()) return head + ".*?" + def.text_pattern;

        return head;
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
    for (const auto& s : sigs) {
        try {
            auto flags = boost::regex::optimize | boost::regex::mod_s;
            if (s.type == SignatureType::TEXT) flags |= boost::regex::icase;
            m_regexes.emplace_back(boost::regex(build_pattern(s), flags), s.name);
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
            stats.add(name);
            cur += m.position() + std::max((std::ptrdiff_t)1, m.length());
        }
    }
}

// === RE2 ===
Re2Scanner::Re2Scanner() = default;
Re2Scanner::~Re2Scanner() = default;
std::string Re2Scanner::name() const { return "Google RE2"; }
void Re2Scanner::prepare(const std::vector<SignatureDefinition>& sigs) {
    m_regexes.clear();
    re2::RE2::Options opt;
    opt.set_encoding(re2::RE2::Options::EncodingLatin1);
    opt.set_dot_nl(true);
    for (const auto& s : sigs) {
        auto re = std::make_unique<re2::RE2>(build_pattern(s), opt);
        if (re->ok()) m_regexes.emplace_back(std::move(re), s.name);
    }
}
void Re2Scanner::scan(const char* data, size_t size, ScanStats& stats) {
    for (const auto& [re, name] : m_regexes) {
        re2::StringPiece input(data, size);
        while (re2::RE2::FindAndConsume(&input, *re)) stats.add(name);
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

    std::vector<const char*> exprs;
    std::vector<unsigned int> flags, ids;

    for (size_t i = 0; i < sigs.size(); ++i) {
        m_temp_patterns.push_back(build_pattern(sigs[i]));
        m_sig_names.push_back(sigs[i].name);
        exprs.push_back(m_temp_patterns.back().c_str());
        ids.push_back((unsigned int)i);
        flags.push_back(HS_FLAG_DOTALL | (sigs[i].type == SignatureType::TEXT ? HS_FLAG_CASELESS : 0));
    }

    if (exprs.empty()) return;
    hs_compile_error_t* err;
    if (hs_compile_multi(exprs.data(), flags.data(), ids.data(), (unsigned int)exprs.size(), HS_MODE_BLOCK, nullptr, &db, &err) != HS_SUCCESS) {
        std::cerr << "[Scanner] HS Compile Error: " << err->message << std::endl;
        hs_free_compile_error(err);
    }
    else {
        hs_alloc_scratch(db, &scratch);
    }
}
void HsScanner::scan(const char* data, size_t size, ScanStats& stats) {
    if (!db || !scratch) return;
    struct Ctx { ScanStats* s; const std::vector<std::string>* n; } ctx = { &stats, &m_sig_names };
    auto on_match = [](unsigned int id, unsigned long long, unsigned long long, unsigned int, void* ptr) -> int {
        Ctx* c = (Ctx*)ptr;
        if (id < c->n->size()) c->s->add((*c->n)[id]);
        return 0;
        };
    hs_scan(db, data, size, 0, scratch, on_match, &ctx);
}
