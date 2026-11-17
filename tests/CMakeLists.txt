# GoogleTest suites for the linko-server. The gtest/gtest_main targets come
# from the linko-core submodule (FetchContent, ADR-0002); server tests link
# server_lib so every suite covers exactly the measured library.
include(GoogleTest)

# linko_add_test(<name> <sources...>)
#
# Creates a GoogleTest executable <name> from <sources>, links it against
# server_lib and gtest_main, and registers every TEST it contains with CTest.
function(linko_add_test name)
  add_executable(${name} ${ARGN})
  # Windows OpenSSL uplink: test executables load certificates through
  # OpenSSL FILE* paths, so each must export OPENSSL_Applink exactly like
  # the server executable (see the root CMakeLists.txt and
  # vendor/applink/README.md).
  if(MSVC)
    set(LINKO_APPLINK_C ${CMAKE_SOURCE_DIR}/vendor/applink/applink.c)
    target_sources(${name} PRIVATE ${LINKO_APPLINK_C})
    set_source_files_properties(${LINKO_APPLINK_C} PROPERTIES COMPILE_OPTIONS "/W0")
  endif()
  target_link_libraries(${name} PRIVATE server_lib gtest_main)
  gtest_discover_tests(${name})
endfunction()

# Test target names carry the server_ prefix: the core submodule defines
# its own suites (smoke, envelope, ...) in the same CMake tree and target
# names must not collide (CMP0002).
linko_add_test(server_smoke test_smoke.cpp)
linko_add_test(server_config test_config.cpp)
linko_add_test(server_store test_store.cpp)
linko_add_test(server_crypto test_crypto.cpp)
linko_add_test(server_cert test_cert.cpp)
linko_add_test(server_cli test_cli.cpp)
linko_add_test(server_http test_http.cpp)
linko_add_test(server_ws test_ws.cpp)
linko_add_test(server_call_registry test_call_registry.cpp)
linko_add_test(server_turn_users test_turn_users.cpp)
linko_add_test(server_messaging test_messaging.cpp)
linko_add_test(server_files test_files.cpp)
linko_add_test(server_reports test_reports.cpp)
# The crypto and CLI suites include the header-only test_cert helper.
target_include_directories(server_crypto PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(server_cert PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(server_cli PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(server_http PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(server_ws PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(server_call_registry PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(server_turn_users PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(server_messaging PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(server_files PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(server_reports PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
# The config suite loads the committed example file by absolute path.
target_compile_definitions(server_config PRIVATE LINKO_REPO_ROOT="${CMAKE_SOURCE_DIR}")
