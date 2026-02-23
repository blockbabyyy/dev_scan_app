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

# === OUTPUT STRUCTURE ===
# Все бинарники и DLL-зависимости -> bin/
# Статические библиотеки         -> lib/
# PDB-символы                    -> pdb/
# .ilk (инкрементальная линковка) -> убраны через /INCREMENTAL:NO
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY                "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE        "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY                "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE        "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/lib")

if(MSVC)
    # Отключаем инкрементальную линковку — убирает .ilk-файлы
    add_link_options(/INCREMENTAL:NO)
endif()

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
    src/Scanner.cpp
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

# === 5. ТЕСТЫ (TESTS) ===
enable_testing()

add_executable(DevScanTests
    tests/ScannerTests.cpp
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
gtest_discover_tests(DevScanTests
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# === 6. БЕНЧМАРКИ (BENCHMARKS) ===
find_package(benchmark CONFIG REQUIRED)

add_executable(DevScanBenchmarks
    tests/Benchmarks.cpp
    src/generator/Generator.cpp
)

target_include_directories(DevScanBenchmarks PRIVATE
    "${CMAKE_SOURCE_DIR}/include"
    "${CMAKE_SOURCE_DIR}/include/generator"
)

target_link_libraries(DevScanBenchmarks PRIVATE
    DevScanCore
    benchmark::benchmark
    Boost::iostreams
)

# === 7. PDB → pdb/ ===
set_target_properties(DevScanApp DevScanTests DevScanBenchmarks
    PROPERTIES PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/pdb"
)

# === 8. КОПИРОВАНИЕ signatures.json ===
# Копируем в bin/ (рядом с .exe для тестов и запуска из bin/)
# и в корень build/ (для запуска через ./bin/... из корня build)
add_custom_command(
    OUTPUT  "${CMAKE_BINARY_DIR}/bin/signatures.json"
            "${CMAKE_BINARY_DIR}/signatures.json"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "${CMAKE_SOURCE_DIR}/signatures.json"
            "${CMAKE_BINARY_DIR}/bin/signatures.json"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "${CMAKE_SOURCE_DIR}/signatures.json"
            "${CMAKE_BINARY_DIR}/signatures.json"
    DEPENDS "${CMAKE_SOURCE_DIR}/signatures.json"
    COMMENT "Copying signatures.json to bin/ and build root"
)
add_custom_target(copy_signatures ALL
    DEPENDS "${CMAKE_BINARY_DIR}/bin/signatures.json"
            "${CMAKE_BINARY_DIR}/signatures.json"
)
add_dependencies(DevScanApp        copy_signatures)
add_dependencies(DevScanTests      copy_signatures)
add_dependencies(DevScanBenchmarks copy_signatures)
