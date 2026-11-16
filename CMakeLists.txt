cmake_minimum_required(VERSION 3.28)

project(linko-server
  VERSION 0.1.0
  DESCRIPTION "Linko server: signaling and messaging for the Linko messenger"
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# The shared core comes in as a submodule pinned to a tag. Adding it first
# means the warning flags below (set at this directory scope) do not reach
# core's own targets - they carry their own warnings-as-errors settings.
# The submodule also provides gtest/gtest_main (FetchContent, ADR-0002) and
# nlohmann_json, which linko_core links PUBLIC, so the server reuses them
# without a second copy in vcpkg.json.
add_subdirectory(external/linko-core)

# Vendored third-party sources (see vendor/qrcodegen/README.md): the
# target is created before the warnings-as-errors block below takes
# effect, so upstream code is not held to our lint rules.
add_library(vendor_qrcodegen STATIC vendor/qrcodegen/qrcodegen.cpp)
target_include_directories(vendor_qrcodegen SYSTEM PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/vendor/qrcodegen)

# Warnings are errors on every compiler (CLAUDE.md, design spec 7).
if(MSVC)
  add_compile_options(/W4 /WX)
else()
  add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

# Server dependencies (ADR-0003): Boost.Beast/Asio, OpenSSL, SQLite3. On
# Windows the vcpkg toolchain (CMakePresets "windows") makes these
# find_package calls resolve against the manifest; on macOS the "macos"
# preset passes Homebrew prefix hints via CMAKE_PREFIX_PATH.
find_package(Boost 1.92 REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

# The server library: all logic lives here so the coverage gate (spec 7:
# >= 80 % of server logic) has a single target to measure. The executable
# only wires the CLI entry point.
add_library(server_lib STATIC src/cli.cpp src/config.cpp src/log.cpp
                           src/messaging.cpp
                           src/store.cpp src/crypto.cpp src/throttle.cpp
                           src/wire.cpp src/call_registry.cpp src/ws/hub.cpp src/ws/session.cpp
                           src/http/router.cpp src/http/listener.cpp
                           src/http/register_handler.cpp
                           src/http/users_handler.cpp
                           src/http/turn_handler.cpp
                           src/http/files_handler.cpp
                           src/file_store.cpp src/cleanup.cpp)
target_include_directories(server_lib
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_link_libraries(server_lib
  PUBLIC linko_core Boost::system OpenSSL::SSL OpenSSL::Crypto
         SQLite::SQLite3 vendor_qrcodegen)

add_executable(linko-server src/main.cpp)
target_link_libraries(linko-server PRIVATE server_lib)

enable_testing()
add_subdirectory(tests)
