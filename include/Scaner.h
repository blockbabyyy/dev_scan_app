#pragma once
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <boost/regex.hpp>

namespace re2 { class RE2; }
struct hs_database;
struct hs_scratch;

enum class SignatureType { BINARY, TEXT };
enum class EngineType { BOOST, RE2, HYPERSCAN };

struct SignatureDefinition {
    std::string name;
    std::string hex_head;
    std::string hex_tail;
    std::string text_pattern;
    SignatureType type = SignatureType::BINARY;
    std::string deduct_from; // Для логики вычитания коллизий
};

struct ScanStats {
    std::map<std::string, int> counts;
    int total_files_processed = 0;

    void add(const std::string& name) { counts[name]++; }
    void reset() { counts.clear(); total_files_processed = 0; }

    ScanStats& operator+=(const ScanStats& other) {
        for (const auto& [name, count] : other.counts) counts[name] += count;
        total_files_processed += other.total_files_processed;
        return *this;
    }
};

class Scanner {
public:
    virtual ~Scanner() = default;
    virtual void prepare(const std::vector<SignatureDefinition>& sigs) = 0;
    virtual void scan(const char* data, size_t size, ScanStats& stats) = 0;
    virtual std::string name() const = 0;
    static std::unique_ptr<Scanner> create(EngineType type);
};

// Реализации (Boost, RE2, Hs) определяются в Scaner.cpp
class BoostScanner : public Scanner {
public:
    void prepare(const std::vector<SignatureDefinition>& sigs) override;
    void scan(const char* data, size_t size, ScanStats& stats) override;
    std::string name() const override;
private:
    std::vector<std::pair<boost::regex, std::string>> m_regexes;
};

class Re2Scanner : public Scanner {
public:
    Re2Scanner();
    ~Re2Scanner() override;
    void prepare(const std::vector<SignatureDefinition>& sigs) override;
    void scan(const char* data, size_t size, ScanStats& stats) override;
    std::string name() const override;
private:
    std::vector<std::pair<std::unique_ptr<re2::RE2>, std::string>> m_regexes;
};

class HsScanner : public Scanner {
public:
    HsScanner();
    ~HsScanner() override;
    void prepare(const std::vector<SignatureDefinition>& sigs) override;
    void scan(const char* data, size_t size, ScanStats& stats) override;
    std::string name() const override;
private:
    hs_database* db = nullptr;
    hs_scratch* scratch = nullptr;
    std::vector<std::string> m_sig_names;
    std::vector<std::string> m_temp_patterns;
};
