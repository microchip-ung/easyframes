project(easyframes C)

cmake_minimum_required(VERSION 2.8.12)

add_definitions(-Wall)
include_directories(src)


set(_LIBPCAP "")
find_package(PkgConfig)
pkg_check_modules(PCAP libpcap)
if (PCAP_FOUND)
    add_definitions(-DHAS_LIBPCAP)
    include_directories(${PCAP_INCLUDE_DIRS})
    set(_LIBPCAP ${PCAP_LIBRARIES})
else()
    FIND_PATH(PCAP_INCLUDE_DIR NAMES pcap/pcap.h)
    FIND_LIBRARY(PCAP_LIBRARY NAMES pcap)

    if (PCAP_LIBRARY)
        add_definitions(-DHAS_LIBPCAP)
        include_directories(${PCAP_INCLUDE_DIR})
        set(_LIBPCAP ${PCAP_LIBRARY})
    endif()
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

# Appends the cmake/modules path to MAKE_MODULE_PATH variable.
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules ${CMAKE_MODULE_PATH})

#
# Make a version file containing the current version from git.
#
include(GetGitRevisionDescription)
git_describe(VERSION --tags --dirty=-dirty)

#parse the version information into pieces.
string(REGEX REPLACE "^v([0-9]+)\\..*" "\\1" VERSION_MAJOR "${VERSION}")
string(REGEX REPLACE "^v[0-9]+\\.([0-9]+).*" "\\1" VERSION_MINOR "${VERSION}")
set(VERSION_SHORT "${VERSION_MAJOR}.${VERSION_MINOR}")

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules/version.c.in
                ${CMAKE_CURRENT_BINARY_DIR}/version.c)
set(version_file "${CMAKE_CURRENT_BINARY_DIR}/version.c")

add_executable(ef src/main.c ${version_file}) # todo, rename to main.c
target_link_libraries(ef libef ${_LIBPCAP})

install(TARGETS ef DESTINATION bin)
