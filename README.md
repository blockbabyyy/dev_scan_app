# RegexBench

This is alpha version of app which aim is to find files of any types inside diffirent types of containers.

Now, the programm is for debugging of regex libraries. 

To-do:
- add generator unstructured dataset (files of any types in some container);
- benchmark of libraries;
- transition to the beta version (console app complians with all OOP rules).

## Features

*   Benchmarks multiple regex engines: std::regex, [RE2](https://github.com/google/re2), [Boost.Regex](https://www.boost.org/doc/libs/release/libs/regex/), and [Hyperscan](https://github.com/intel/hyperscan).
*   Uses [Google Benchmark](https://github.com/google/benchmark) for standardized performance measurement.
*   Configured with CMake for cross-platform building.

## Prerequisites

*   A C++ compiler supporting C++17 or later.
*   [CMake](https://cmake.org/) version 3.21 or higher.
*   [vcpkg](https://vcpkg.io/en/getting-started.html) as the C++ package manager.

### Installing vcpkg

If you haven't installed `vcpkg` yet, please follow the official [Getting Started Guide](https://vcpkg.io/en/getting-started.html). This typically involves cloning the repository and running the bootstrap script.

## Dependencies

This project relies on the following libraries, managed by `vcpkg`:

*   `benchmark`
*   `boost-regex`
*   `re2`
*   `hyperscan` (See manual installation step below)

If you're going to use other package managers of diffirent ways, follow giudes for each library.
### Installing Dependencies via vcpkg

1.  **Install `hyperscan` manually:** `vcpkg` does not currently provide a pre-built `hyperscan` package in its default registry. You need to install it manually using the port provided in the `vcpkg` repository.
    *   Navigate to your `vcpkg` installation directory.
    *   Run the following command, replacing `<your-triplet>` (e.g., `x64-windows`, `x64-linux`) with your target platform triplet:
        ```bash
        ./vcpkg install hyperscan[tools]:<your-triplet>
        ```
        *Example for Windows x64:*
        ```cmd
        vcpkg install hyperscan[tools]:x64-windows
        ```
        or jsut
        ```cmd
        vcpkg install hyperscan
        ```
    *   **Note:** The `[tools]` feature is often required for Hyperscan. Adjust the command based on your specific needs or if the port definition changes.

2.  **Install other dependencies:** After installing `hyperscan`, install the remaining dependencies using `vcpkg`:
    ```bash
    ./vcpkg install benchmark boost-regex re2 --triplet <your-triplet>
    ```

## Building the Project

1.  **Configure `CMakeLists.txt`:**
    *   Open the `CMakeLists.txt` file in this project's root directory.
    *   Locate the lines setting `VCPKG_ROOT` and `VCPKG_DEFAULT_TRIPLET`.
    *   Manually update the `VCPKG_ROOT` variable to point to the absolute path of your `vcpkg` installation directory (e.g., `/path/to/vcpkg` on Linux/macOS or `C:\path\to\vcpkg` on Windows).
    *   Ensure the `VCPKG_DEFAULT_TRIPLET` matches the triplet you used when installing the dependencies via `vcpkg` (e.g., `x64-windows`).

2.  **Create a build directory:**
    ```bash
    mkdir build
    cd build
    ```

3.  **Configure the project with CMake:**
    ```bash
    cmake .. -DCMAKE_TOOLCHAIN_FILE=<path_to_your_vcpkg>/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=<your_triplet>
    ```
    Replace `<path_to_your_vcpkg>` with the path to your `vcpkg` directory and `<your_triplet>` with your specific triplet (e.g., `x64-windows`).

    *Alternatively,* if you have set the `VCPKG_ROOT` and `VCPKG_DEFAULT_TRIPLET` correctly in the `CMakeLists.txt`, the toolchain file should be found automatically, and you might only need:
    ```bash
    cmake ..
    ```

4.  **Build the executable:**
    ```bash
    cmake --build . --config Release
    # Or simply: make (on Unix-like systems)
    # Or: msbuild RegexBench.sln /p:Configuration=Release (on Windows with MSBuild)
    ```

## Running the Benchmarks

Execute the generated binary (e.g., `./RegexBench` on Unix-like systems or `RegexBench.exe` on Windows) to run the benchmarks.
