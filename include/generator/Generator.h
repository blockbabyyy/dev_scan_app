#include <string>
#include <map>
#include <cstdint>
#include <vector>
#include <random>
#include <filesystem>

namespace fs = std::filesystem;

class UnstructuredFileGenerator {
public:
    struct Stats {
        std::map<std::string, int> fileCount;
    };

    enum class ContainerType {
        BIN,
        ZIP,
        PCAP
    };

    // Конструктор с параметрами
    explicit UnstructuredFileGenerator(uint64_t targetSizeMB = 400,
        ContainerType containerType = ContainerType::BIN);

    // Основной метод генерации
    bool generate(const std::string& outputPath);

    // Получение статистики
    Stats getStats() const;

    // Получение пути к контейнеру
    std::string getContainerPath() const;

private:
    struct FileSignature {
        std::string extension;
        std::vector<uint8_t> signature;
    };

    uint64_t targetSize;
    uint64_t currentSize;
    ContainerType containerType;
    std::string outputPath;
    fs::path tempDir;
    std::vector<FileSignature> signatures;
    Stats stats;
    std::mt19937 rng;

    // Инициализация сигнатур
    void initializeSignatures();

    // Генерация файлов
    void generateFiles();

    // Создание контейнера
    void createContainer();

    // Создание бинарного контейнера
    void createBinContainer();

    // Создание ZIP контейнера
    void createZipContainer();

    // Создание PCAP контейнера
    void createPcapContainer();

    // Очистка временных файлов
    void cleanup();
};

