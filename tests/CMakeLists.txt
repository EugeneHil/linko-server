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
  target_link_libraries(${name} PRIVATE server_lib gtest_main)
  gtest_discover_tests(${name})
endfunction()

# Test target names carry the server_ prefix: the core submodule defines
# its own suites (smoke, envelope, ...) in the same CMake tree and target
# names must not collide (CMP0002).
linko_add_test(server_smoke test_smoke.cpp)
