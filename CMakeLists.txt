cmake_minimum_required(VERSION 3.21)

# === 1. VCPKG PREAMBLE ===
if(POLICY CMP0167)
    cmake_policy(SET CMP0167 OLD)
endif()

# Настройки VCPKG
set(VCPKG_ROOT "C:/vcpkg" CACHE STRING "Path to vcpkg root")
set(VCPKG_DEFAULT_TRIPLET "x64-windows" CACHE STRING "Target triplet")

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
endif()

project(DevScan)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# === 2. ЗАВИСИМОСТИ ===
find_package(re2 CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS regex iostreams)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(Threads REQUIRED)
find_package(GTest CONFIG REQUIRED) # Добавили GTest

# Hyperscan (ручной поиск)
find_path(HYPERSCAN_INCLUDE_DIR NAMES hs/hs.h
    PATHS "${CMAKE_BINARY_DIR}/vcpkg_installed/${VCPKG_DEFAULT_TRIPLET}/include"
          "${VCPKG_ROOT}/installed/${VCPKG_DEFAULT_TRIPLET}/include"
    NO_DEFAULT_PATH
)
find_library(HYPERSCAN_LIBRARY NAMES hs
    PATHS "${CMAKE_BINARY_DIR}/vcpkg_installed/${VCPKG_DEFAULT_TRIPLET}/lib"
          "${VCPKG_ROOT}/installed/${VCPKG_DEFAULT_TRIPLET}/lib"
    NO_DEFAULT_PATH
)

if(NOT HYPERSCAN_INCLUDE_DIR OR NOT HYPERSCAN_LIBRARY)
    message(FATAL_ERROR "Hyperscan library not found!")
endif()

# === 3. БИБЛИОТЕКА (CORE) ===
add_library(DevScanCore STATIC
    src/Scaner.cpp
)

target_include_directories(DevScanCore PUBLIC 
    "${CMAKE_SOURCE_DIR}/include"
)
target_include_directories(DevScanCore PRIVATE 
    "${HYPERSCAN_INCLUDE_DIR}"
)

target_link_libraries(DevScanCore PUBLIC
    re2::re2
    Boost::regex
    nlohmann_json::nlohmann_json
    ${HYPERSCAN_LIBRARY}
)

# === 4. ПРИЛОЖЕНИЕ (CLI) ===
add_executable(DevScanApp src/cli/main_cli.cpp)

target_link_libraries(DevScanApp PRIVATE
    DevScanCore
    Boost::iostreams
    Threads::Threads
)

configure_file(signatures.json signatures.json COPYONLY)

# === 5. ТЕСТЫ (TESTS) ===
enable_testing()

add_executable(DevScanTests
    tests/ScanerTests.cpp
    tests/IntegrationTests.cpp     
    src/generator/Generator.cpp    
)

# Подключаем заголовки ядра
target_include_directories(DevScanTests PRIVATE
    "${CMAKE_SOURCE_DIR}/include"
    "${CMAKE_SOURCE_DIR}/include/generator"
)

# Линкуем с ядром и GTest
target_link_libraries(DevScanTests PRIVATE
    DevScanCore
    GTest::gtest
    GTest::gtest_main
    Boost::iostreams
)

# Регистрация тестов в CTest
include(GoogleTest)
gtest_discover_tests(DevScanTests)
