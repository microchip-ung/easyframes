project(easyframes)

cmake_minimum_required(VERSION 3.6)

add_definitions(-D_DEFAULT_SOURCE -D__DEFAULT_SOURCE -D__FAVOR_BSD
    -DHAVE_NET_ETHERNET_H -Werror -Wall)

add_executable(ef
               src/ef-arp.c
               src/ef-dns.c
               src/ef-eth.c
               src/ef-fileio.c
               src/ef-functions.c
               src/ef-icmp.c
               src/ef-igmp.c
               src/ef-ip.c
               src/ef-printout.c
               src/ef-raw.c
               src/ef-rip.c
               src/ef-tcp.c
               src/ef-udp.c
               src/ef.c
)

target_link_libraries(ef net-1.0)

install (TARGETS ef DESTINATION bin)

