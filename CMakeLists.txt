cmake_minimum_required(VERSION 3.21)

# ==============================================================================
# 1. НАСТРОЙКИ VCPKG
# ==============================================================================
# Убираем надоедливый варнинг про FindBoost
if(POLICY CMP0167)
    cmake_policy(SET CMP0167 OLD)
endif()

set(VCPKG_ROOT "C:/vcpkg" CACHE STRING "Путь до vcpkg" FORCE)
set(VCPKG_DEFAULT_TRIPLET "x64-windows" CACHE STRING "Архитектура по дефолту" FORCE)

# Подключаем тулчейн vcpkg, если он еще не задан
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "Vcpkg toolchain" FORCE)
endif()

# ==============================================================================
# 2. ПРОЕКТ
# ==============================================================================
project(RegexBench)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ==============================================================================
# 3. ПОИСК БИБЛИОТЕК
# ==============================================================================

# --- Hyperscan (Тут пришлось повозиться) ---
# Hyperscan ставится кривовато в vcpkg (нет нормального конфига), ищем вручную.
find_path(HYPERSCAN_INCLUDE_DIR
    NAMES hs/hs.h
    # Сначала смотрим в локальной папке билда (если манифест режим)
    PATHS "${CMAKE_BINARY_DIR}/vcpkg_installed/${VCPKG_DEFAULT_TRIPLET}/include"
    # На всякий случай смотрим в глобальной папке vcpkg
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
    message(FATAL_ERROR "Hyperscan не нашелся! Проверь пути в CMakeLists.")
endif()

# --- Остальное ищется нормально через конфиги ---
find_package(absl CONFIG REQUIRED)
find_package(re2 CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS regex)
find_package(benchmark CONFIG REQUIRED)
find_package(GTest CONFIG REQUIRED)

enable_testing()

# ==============================================================================
# 4. ФАЙЛЫ
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
# 5. СБОРКА
# ==============================================================================

# Основная программа
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
    src/generator/Generator.cpp
)

target_include_directories(RegexBenchTests PRIVATE
    "${CMAKE_SOURCE_DIR}/include"
    "${HYPERSCAN_INCLUDE_DIR}"
)

target_link_libraries(RegexBenchTests PRIVATE
    re2::re2
    Boost::regex
    ${HYPERSCAN_LIBRARY}
    GTest::gtest
    GTest::gtest_main 
)

include(GoogleTest)
gtest_discover_tests(RegexBenchTests)


add_executable(Benchmarks tests/Benchmarks.cpp src/Scaner.cpp src/generator/Generator.cpp)
# Подключаем папки include
target_include_directories(Benchmarks PRIVATE 
    ${CMAKE_SOURCE_DIR}/include 
    ${CMAKE_SOURCE_DIR}/src
)

# Линкуем библиотеки (те же, что и для main app)
target_link_libraries(Benchmarks PRIVATE
    re2::re2
    Boost::regex
    benchmark::benchmark
    benchmark::benchmark_main
    ${HYPERSCAN_LIBRARY}
    Psapi
    absl::base
)
