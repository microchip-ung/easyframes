project (ef)

cmake_minimum_required(VERSION 3.5)

#find_package(Catch2 REQUIRED)
#target_link_libraries(tests Catch2::Catch2)

add_definitions(-Wall)

add_library(libef STATIC ef.c ef-parse-bytes.c ef-buf.c)

add_executable(ef main.c)
target_link_libraries(ef libef pcap)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(ef-tests ef-tests.cxx test-ef-parse-bytes.cxx)
target_link_libraries(ef-tests libef)

include(CTest)
add_test(xx ./ef-tests)
#include(Catch)
#catch_discover_tests(ef-tests)

