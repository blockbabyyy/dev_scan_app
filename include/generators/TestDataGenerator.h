#pragma once

#include <vector>
#include <cstdint>
#include <random>
#include <unordered_map>
#include <FileType.h>

namespace generator {

	class TestDataGenerator {
	public:
		// Генерация случайных бинарных данных заданного размера
		struct Config {
			uint32_t seed = 42; // Начальное значение для генератора случайных чисел
			size_t min_file_size = 512; // Размер файла в байтах
			size_t max_file_size = 64*1024; // Максимальный размер файла в байтах
			double noise_ratio = 0.05; // Доля "шума" в файле (от 0 до 1)
		};

		explicit TestDataGenerator(const Config& config);

		std::vector<uint8_t> generateFileData(FileType file_type);
		std::vector<uint8_t> generateRandomData(size_t size);

		struct Stats {
			size_t total_files_generated = 0;
			size_t total_bytes_generated = 0;
			std::unordered_map<FileType, size_t> files_per_type;
			std::unordered_map<FileType, size_t> bytes_per_type;
		};

		const Stats& getStats() const { return stats_; }
		void resetStats() { stats_ = Stats(); }
	private:
		Config config_;
		std::mt19937 rng_;
		Stats stats_;
		
		filetype::FileType selectRandomFileType(); // Случайный выбор типа файла
		size_t getRandomFileSize(); // Случайный размер файла в заданном диапазоне
		void updateStats(FileType file_type, size_t file_size);
	};
}