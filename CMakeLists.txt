cmake_minimum_required(VERSION 3.21)
project(RegexBench)

# --- Укажите путь к vcpkg ВРУЧНУЮ ---
# Замените C:/vcpkg на ваш реальный путь к директории vcpkg
set(VCPKG_ROOT "C:/vcpkg" CACHE STRING "Path to vcpkg root directory" FORCE)

# --- Укажите триплет (опционально, но рекомендуется для ясности) ---
# Замените x64-windows, если вы используете другой (например, x86-windows, x64-windows-static)
set(VCPKG_DEFAULT_TRIPLET "x64-windows" CACHE STRING "vcpkg triplet (e.g., x64-windows)" FORCE)

# Указываем toolchain vcpkg до project(), используя заданный путь
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  set(CMAKE_TOOLCHAIN_FILE "${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
      CACHE STRING "Vcpkg toolchain file")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Поиск Hyperscan ---
# Используем переменные VCPKG_ROOT и VCPKG_DEFAULT_TRIPLET, заданные выше
find_path(HYPERSCAN_INCLUDE_DIR
    NAMES hs/hs.h  # hs.h находится внутри поддиректории hs/
    PATHS ${VCPKG_ROOT}/installed/${VCPKG_DEFAULT_TRIPLET}/include # Используем переменные
    NO_DEFAULT_PATH # Искать ТОЛЬКО в указанных PATHS
)

find_library(HYPERSCAN_LIBRARY
    NAMES hs # Имя библиотеки hs.lib
    PATHS ${VCPKG_ROOT}/installed/${VCPKG_DEFAULT_TRIPLET}/lib # Используем переменные
    NO_DEFAULT_PATH # Искать ТОЛЬКО в указанных PATHS
)

# Проверка, что оба компонента найдены
if(NOT HYPERSCAN_INCLUDE_DIR OR NOT HYPERSCAN_LIBRARY)
  message(FATAL_ERROR "Hyperscan headers или library не найдены. Убедитесь, что пакет hyperscan установлен через vcpkg в ${VCPKG_ROOT}/installed/${VCPKG_DEFAULT_TRIPLET}/ и используйте #include <hs/hs.h>.")
endif()

# Подключаем библиотеки через vcpkg/ find_package
find_package(absl CONFIG REQUIRED)
find_package(RE2 CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS regex)
find_package(benchmark CONFIG REQUIRED)

# Исполняемый файл
add_executable(RegexBench main.cpp)

# Подключаем *корневую* директорию заголовков vcpkg (например, C:/vcpkg/installed/x64-windows/include)
# Это позволяет использовать #include <hs/hs.h> в вашем C++ коде
target_include_directories(RegexBench PRIVATE ${HYPERSCAN_INCLUDE_DIR})

# Линковка
target_link_libraries(RegexBench PRIVATE
    #absl::absl
    re2::re2
    Boost::regex
    ${HYPERSCAN_LIBRARY} # Линкуем найденную библиотеку Hyperscan
    benchmark::benchmark
    benchmark::benchmark_main
)