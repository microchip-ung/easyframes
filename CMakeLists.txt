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
    src/ef-args.c
    src/ef-arp.c
    src/ef-buf.c
    src/ef-capture.c
    src/ef-eth.c
    src/ef-exec.c
    src/ef-icmp.c
    src/ef-ifh.c
    src/ef-igmp.c
    src/ef-ipv4.c
    src/ef-ipv6.c
    src/ef-oam.c
    src/ef-mrp.c
    src/ef-opcua.c
    src/ef-padding.c
    src/ef-parse-bytes.c
    src/ef-payload.c
    src/ef-profinet.c
    src/ef-ptp.c
    src/ef-udp.c
    src/ef-vlan.c
)

target_link_libraries(libef ${_LIBPCAP})

add_executable(ef src/main.c) # todo, rename to main.c
target_link_libraries(ef libef ${_LIBPCAP})

add_executable(base64decode src/base64decode.c)

install(TARGETS ef base64decode DESTINATION bin)
