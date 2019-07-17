project(easyframes)

cmake_minimum_required(VERSION 2.4)

add_definitions(-Wall)
include_directories(src)


set(_LIBPCAP "")
FIND_PATH(PCAP_INCLUDE_DIR NAMES pcap/pcap.h)
FIND_LIBRARY(PCAP_LIBRARY NAMES pcap)

if (PCAP_LIBRARY)
    add_definitions(-DHAS_LIBPCAP)
    include_directories(${PCAP_INCLUDE_DIR})
    set(_LIBPCAP ${PCAP_LIBRARY})
endif()

add_library(libef STATIC
    src/ef.c
    src/main.c  # TODO, rename to ef-args.c
    src/ef-parse-bytes.c
    src/ef-exec.c
    src/ef-buf.c
    src/ef-ifh.c
    src/ef-eth.c
    src/ef-vlan.c
    src/ef-arp.c
    src/ef-ipv4.c
    src/ef-ipv6.c
    src/ef-icmp.c
    src/ef-igmp.c
    src/ef-udp.c
    src/ef-payload.c
    src/ef-padding.c
    src/ef-oam.c
    src/ef-ts.c
)

target_link_libraries(libef ${_LIBPCAP})

add_executable(ef src/mainmain.c) # todo, rename to main.c
target_link_libraries(ef libef ${_LIBPCAP})

add_executable(er src/er.c)

add_executable(base64decode src/base64decode.c)

install(TARGETS ef er base64decode DESTINATION bin)

# TEST ONLY
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(ef-tests
    test/ef-test.cxx
    test/ef-tests.cxx
    test/test-ef-parse-bytes.cxx
    test/ifh-ignore.cxx
)

target_link_libraries(ef-tests libef)

include(CTest)
add_test(ef-tests ./ef-tests)
add_test(parser-tests.rb ${CMAKE_CURRENT_SOURCE_DIR}/test/parser-tests.rb)

