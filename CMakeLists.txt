cmake_minimum_required(VERSION 3.21)

# ==============================================================================
# 1. НАСТРОЙКА VCPKG (ЭТО ДОЛЖНО БЫТЬ ДО КОМАНДЫ project() !!!)
# ==============================================================================

# Укажите ваш путь к vcpkg
set(VCPKG_ROOT "C:/vcpkg" CACHE STRING "Path to vcpkg root directory" FORCE)
set(VCPKG_DEFAULT_TRIPLET "x64-windows" CACHE STRING "vcpkg triplet" FORCE)

# Подключаем тулчейн vcpkg ПЕРЕД инициализацией проекта
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

# Hyperscan (Ручной поиск, т.к. официального конфига может не быть)
find_path(HYPERSCAN_INCLUDE_DIR
    NAMES hs/hs.h
    PATHS "${VCPKG_ROOT}/installed/${VCPKG_DEFAULT_TRIPLET}/include"
    NO_DEFAULT_PATH
)

find_library(HYPERSCAN_LIBRARY
    NAMES hs
    PATHS "${VCPKG_ROOT}/installed/${VCPKG_DEFAULT_TRIPLET}/lib"
    NO_DEFAULT_PATH
)

if(NOT HYPERSCAN_INCLUDE_DIR OR NOT HYPERSCAN_LIBRARY)
    message(FATAL_ERROR "Hyperscan не найден! Проверьте путь: ${VCPKG_ROOT}/installed/${VCPKG_DEFAULT_TRIPLET}")
endif()

# Остальные библиотеки через vcpkg
find_package(absl CONFIG REQUIRED) # Нужен для RE2
find_package(RE2 CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS regex)
find_package(benchmark CONFIG REQUIRED)

# ==============================================================================
# 4. ФАЙЛЫ ПРОЕКТА
# ==============================================================================

set(SOURCES
    main.cpp
    src/generator/Generator.cpp
)

set(HEADERS
    include/generator/Generator.h
    include/Signatures.h 
)

# ==============================================================================
# 5. СБОРКА И ЛИНКОВКА
# ==============================================================================

add_executable(RegexBench ${SOURCES} ${HEADERS})

# Подключаем папки заголовков
target_include_directories(RegexBench PRIVATE
    "${CMAKE_SOURCE_DIR}/include"  # Чтобы работало #include "Signatures.h"
    "${HYPERSCAN_INCLUDE_DIR}"     # Чтобы работало #include <hs/hs.h>
)

# Линкуем библиотеки
target_link_libraries(RegexBench PRIVATE
    re2::re2
    Boost::regex
    benchmark::benchmark
    benchmark::benchmark_main
    ${HYPERSCAN_LIBRARY}
    # absl::absl  <-- Обычно подтягивается автоматически через RE2, но если будут ошибки линковки, раскомментируйте
)