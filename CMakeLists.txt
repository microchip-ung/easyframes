project(nemesis)

cmake_minimum_required(VERSION 3.7)

add_definitions(-D_DEFAULT_SOURCE -D__DEFAULT_SOURCE -D__FAVOR_BSD
    -DHAVE_NET_ETHERNET_H -Werror -Wall)

add_executable(nemesis
               src/nemesis-arp.c
               src/nemesis-dns.c
               src/nemesis-ethernet.c
               src/nemesis-fileio.c
               src/nemesis-functions.c
               src/nemesis-icmp.c
               src/nemesis-igmp.c
               src/nemesis-ip.c
               src/nemesis-printout.c
               src/nemesis-rip.c
               src/nemesis-tcp.c
               src/nemesis-udp.c
               src/nemesis-raw.c
               src/nemesis.c
)

target_link_libraries(nemesis net-1.0)

install (TARGETS nemesis DESTINATION bin)

