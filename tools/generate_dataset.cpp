#include <filesystem>
#include <fstream>
#include <vector>
#include <random>
#include <string>
#include <iostream>

namespace fs = std::filesystem;

static std::vector<uint8_t> make_random(size_t n, std::mt19937 &rng) {
    std::vector<uint8_t> v(n);
    std::uniform_int_distribution<int> d(0, 255);
    for (size_t i = 0; i < n; ++i) v[i] = static_cast<uint8_t>(d(rng));
    return v;
}

static bool write_file(const fs::path &p, const std::vector<uint8_t> &data) {
    std::ofstream os(p, std::ios::binary);
    if (!os) return false;
    os.write(reinterpret_cast<const char*>(data.data()), data.size());
    return !!os;
}

int main(int argc, char** argv) {
    fs::path out_dir = (argc > 1) ? fs::path(argv[1]) : fs::path("test_data");
    size_t files_per_type = (argc > 2) ? std::stoul(argv[2]) : 10;
    fs::create_directories(out_dir);

    std::random_device rd;
    std::mt19937 rng(static_cast<uint32_t>(rd()));

    // define signatures
    const std::vector<std::pair<std::string, std::vector<uint8_t>>> types = {
        { "pdf", { '%','P','D','F' } },
        { "doc", { 0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1 } }, // OLE (DOC)
        { "png", { 0x89,'P','N','G',0x0D,0x0A,0x1A,0x0A } },
        { "rar4",{ 'R','a','r','!','\x1A','\x07','\x00' } },
        { "rar5",{ 'R','a','r','!','\x1A','\x07','\x01','\x00' } },
        { "txt", { 'H','e','l','l','o' } }
    };

    size_t counter = 0;
    for (const auto &t : types) {
        for (size_t i = 0; i < files_per_type; ++i) {
            size_t total_size = 512 + (rng() % 4096); // 512 .. ~4608
            std::vector<uint8_t> data;
            data.insert(data.end(), t.second.begin(), t.second.end());
            if (data.size() < total_size) {
                auto tail = make_random(total_size - data.size(), rng);
                data.insert(data.end(), tail.begin(), tail.end());
            }
            fs::path p = out_dir / (t.first + "_" + std::to_string(i) + ".bin");
            if (!write_file(p, data)) {
                std::cerr << "Не удалось записать файл: " << p.string() << "\n";
            } else {
                ++counter;
            }
        }
    }

    // несколько полностью случайных бинарников
    for (size_t i = 0; i < files_per_type; ++i) {
        size_t total_size = 256 + (rng() % 8192);
        auto data = make_random(total_size, rng);
        fs::path p = out_dir / ("rand_" + std::to_string(i) + ".bin");
        if (!write_file(p, data)) std::cerr << "Не удалось записать файл: " << p.string() << "\n";
        else ++counter;
    }

    std::cout << "Сгенерировано файлов: " << counter << ", в папке: " << out_dir << std::endl;
    std::cout << "Запустите вашу программу (RegexBench) на этой папке для проверки распознавания.\n";
    return 0;
}