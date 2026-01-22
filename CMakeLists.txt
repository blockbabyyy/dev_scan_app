cmake_minimum_required(VERSION 3.21)

# ==============================================================================
# 1. НАСТРОЙКА VCPKG И ПОЛИТИК
# ==============================================================================
# Подавляем Warning по поводу FindBoost (CMP0167)
if(POLICY CMP0167)
    cmake_policy(SET CMP0167 OLD)
endif()

set(VCPKG_ROOT "C:/vcpkg" CACHE STRING "Path to vcpkg root directory" FORCE)
set(VCPKG_DEFAULT_TRIPLET "x64-windows" CACHE STRING "vcpkg triplet" FORCE)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "Vcpkg toolchain file" FORCE)
endif()

# ==============================================================================
# 2. ИНИЦИАЛИЗАЦИЯ ПРОЕКТА
# ==============================================================================
project(RegexBench)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ==============================================================================
# 3. ПОИСК БИБЛИОТЕК
# ==============================================================================

# --- Hyperscan (Особый случай) ---
# ВНИМАНИЕ: При Manifest Mode vcpkg ставит библиотеки в build/vcpkg_installed.
# Если Hyperscan нет в vcpkg.json, он будет искаться в глобальном каталоге.
find_path(HYPERSCAN_INCLUDE_DIR
    NAMES hs/hs.h
    # Сначала ищем в локальной папке сборки (если добавлен в манифест)
    PATHS "${CMAKE_BINARY_DIR}/vcpkg_installed/${VCPKG_DEFAULT_TRIPLET}/include"
    # Потом в глобальной (как запасной вариант)
    "${VCPKG_ROOT}/installed/${VCPKG_DEFAULT_TRIPLET}/include"
    NO_DEFAULT_PATH
)

find_library(HYPERSCAN_LIBRARY
    NAMES hs
    PATHS "${CMAKE_BINARY_DIR}/vcpkg_installed/${VCPKG_DEFAULT_TRIPLET}/lib"
    "${VCPKG_ROOT}/installed/${VCPKG_DEFAULT_TRIPLET}/lib"
    NO_DEFAULT_PATH
)

if(NOT HYPERSCAN_INCLUDE_DIR OR NOT HYPERSCAN_LIBRARY)
    message(FATAL_ERROR "Hyperscan не найден! Проверьте пути.")
endif()

# --- Остальные библиотеки (через Config Mode) ---
find_package(absl CONFIG REQUIRED)
find_package(re2 CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS regex)
find_package(benchmark CONFIG REQUIRED)

# ТЕПЕРЬ GTest ищем через CONFIG (так как он будет в vcpkg.json)
find_package(GTest CONFIG REQUIRED)

enable_testing()

# ==============================================================================
# 4. ФАЙЛЫ ПРОЕКТА
# ==============================================================================

set(SOURCES
    main.cpp
    src/generator/Generator.cpp
    src/Scaner.cpp
)

set(HEADERS
    include/generator/Generator.h
    include/Signatures.h
    include/Scaner.h
)

# ==============================================================================
# 5. СБОРКА И ЛИНКОВКА
# ==============================================================================

# Основное приложение
add_executable(RegexBench ${SOURCES} ${HEADERS})

target_include_directories(RegexBench PRIVATE
    "${CMAKE_SOURCE_DIR}/include"
    "${HYPERSCAN_INCLUDE_DIR}"
)

target_link_libraries(RegexBench PRIVATE
    re2::re2
    Boost::regex
    benchmark::benchmark
    benchmark::benchmark_main
    ${HYPERSCAN_LIBRARY}
    Psapi
    absl::base
)

# --- Тесты ---
add_executable(RegexBenchTests
    tests/ScanerTests.cpp
    src/Scaner.cpp 
)

target_include_directories(RegexBenchTests PRIVATE
    "${CMAKE_SOURCE_DIR}/include"
    "${HYPERSCAN_INCLUDE_DIR}"
)

target_link_libraries(RegexBenchTests PRIVATE
    re2::re2
    Boost::regex
    ${HYPERSCAN_LIBRARY}
    # В CONFIG режиме цели называются GTest::gtest и GTest::gtest_main
    GTest::gtest
    GTest::gtest_main 
)

include(GoogleTest)
gtest_discover_tests(RegexBenchTests)