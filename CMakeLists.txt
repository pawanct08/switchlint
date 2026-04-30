cmake_minimum_required(VERSION 3.18)
project(switchlint CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ─── Dependencies via FetchContent ──────────────────────────────────────────
include(FetchContent)

# yaml-cpp
FetchContent_Declare(
    yaml-cpp
    GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
    GIT_TAG        master
)
set(YAML_CPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_TOOLS  OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(yaml-cpp)

# nlohmann/json (header-only)
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
)
set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(nlohmann_json)

# GoogleTest
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.14.0
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# ─── Core library ────────────────────────────────────────────────────────────
add_library(switchlint_core STATIC
    src/topology/graph.cpp
    src/topology/path_resolver.cpp
    src/parser/yaml_parser.cpp
    src/rules/rule_registry.cpp
    src/rules/builtin_rules.cpp
    src/rules/vlan_membership.cpp
    src/rules/vlan_tagging.cpp
    src/rules/multicast_group.cpp
    src/rules/tsn_cbs.cpp
    src/rules/tsn_tas.cpp
    src/rules/firewall_coverage.cpp
    src/rules/bandwidth_oversubscription.cpp
    src/rules/someip_collision.cpp
    src/rules/redundancy.cpp
    src/rules/hop_count.cpp
    src/rules/orphan_detection.cpp
    src/report/text_reporter.cpp
    src/report/json_reporter.cpp
)

target_include_directories(switchlint_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src          # allows tests to include src/parser/...
)

target_link_libraries(switchlint_core PUBLIC
    yaml-cpp::yaml-cpp
    nlohmann_json::nlohmann_json
)

# Windows: link Winsock for inet_pton
if(WIN32)
    target_link_libraries(switchlint_core PUBLIC ws2_32)
endif()

# ─── CLI executable ──────────────────────────────────────────────────────────
add_executable(switchlint src/cli/main.cpp)
target_link_libraries(switchlint PRIVATE switchlint_core)

# ─── Tests ───────────────────────────────────────────────────────────────────
enable_testing()

add_executable(switchlint_tests
    tests/rules/test_vlan.cpp
    tests/rules/test_tsn.cpp
    tests/rules/test_firewall.cpp
)

target_include_directories(switchlint_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(switchlint_tests PRIVATE
    switchlint_core
    GTest::gtest_main
)

# Pass fixture path so tests can load YAML files without hard-coded paths
target_compile_definitions(switchlint_tests PRIVATE
    FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures"
)

include(GoogleTest)
gtest_discover_tests(switchlint_tests)
