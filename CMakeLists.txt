project(easyframes)

cmake_minimum_required(VERSION 3.4)

add_definitions(-Wall)
include_directories(src)

add_library(libef STATIC
    src/ef.c
    src/ef-parse-bytes.c
    src/ef-buf.c
    src/ef-eth.c
    src/ef-vlan.c
    src/ef-arp.c
    src/ef-ipv4.c
    src/ef-udp.c
    src/ef-payload.c
)

add_executable(ef src/main.c)
target_link_libraries(ef libef pcap)

install(TARGETS ef DESTINATION bin)

# TEST ONLY
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(ef-tests test/ef-tests.cxx test/test-ef-parse-bytes.cxx)
target_link_libraries(ef-tests libef)

include(CTest)
add_test(ef-tests ./ef-tests)

