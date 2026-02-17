#pragma once
#include <string>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

class Logger {
public:
    static Logger& instance() {
        static Logger inst;
        return inst;
    }

    static void init() { instance().do_init(); }
    static void info(const std::string& msg)  { instance().log("INFO",  msg, false); }
    static void warn(const std::string& msg)  { instance().log("WARN",  msg, true);  }
    static void error(const std::string& msg) { instance().log("ERROR", msg, true);  }
    static std::string path() { return instance().m_path; }

private:
    std::ofstream m_file;
    std::string m_path;

    Logger() = default;
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    static std::string timestamp() {
        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        std::tm tm_buf{};
#ifdef _WIN32
        localtime_s(&tm_buf, &t);
#else
        localtime_r(&t, &tm_buf);
#endif
        std::ostringstream ss;
        ss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }

    static std::string file_timestamp() {
        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        std::tm tm_buf{};
#ifdef _WIN32
        localtime_s(&tm_buf, &t);
#else
        localtime_r(&t, &tm_buf);
#endif
        std::ostringstream ss;
        ss << std::put_time(&tm_buf, "%Y%m%d_%H%M%S");
        return ss.str();
    }

    void do_init() {
        namespace fs = std::filesystem;
        fs::path dir = "crash_report";
        fs::create_directories(dir);
        std::string filename = "devscan_" + file_timestamp() + ".log";
        m_path = (dir / filename).string();
        m_file.open(m_path, std::ios::out | std::ios::trunc);
    }

    void log(const char* level, const std::string& msg, bool also_stderr) {
        std::string line = "[" + timestamp() + "] [" + level + "] " + msg;
        if (m_file.is_open()) {
            m_file << line << "\n";
            m_file.flush();
        }
        if (also_stderr) {
            std::cerr << line << "\n";
        }
    }
};
