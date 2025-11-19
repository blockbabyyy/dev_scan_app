#pragma once
namespace filetype {
#include <string>
#include <vector>

	enum class FileType {
		// Текстовые файлы
		TXT, CSV, JSON, XML, HTML,
		// Изображения
		JPEG, PNG, GIF, BMP, TIFF,
		// Аудио
		MP3, WAV, FLAC, AAC,
		// Видео
		MP4, AVI, MKV, MOV,
		// Документы
		PDF, DOC, DOCX, PPT, XLSX, PPTX,
		// Email
		EML, MSG,
	}

	std::string getFileExtension(FileType file_type);
	
	std::vector<unit8_t> getFileSignature(FileType type);
}