/*
 * Easy Frames Project
 * Copyright (C) 2002, 2003 Jeff Nathan <jeff@snort.org>
 * Copyright (C) 2017 Microsemi <allan.nielsen@microsemi.com>
 *
 * ef.c (main)
 */

#include "ef.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char **avtmp, *avval;
    extern int optind;

    avtmp = argv;
    avval = strrchr(*avtmp, '/');

    if (avval++ == NULL) avval = *avtmp;

    if (!strncmp(avval, "ef-arp", 11)) {
        ef_arp(argc, argv);
    } else if (argc > 1 && !strncmp(argv[1], "arp", 3)) {
        argv += optind;
        argc -= optind;
        ef_arp(argc, argv);
    } else if (!strncmp(avval, "ef-dns", 11)) {
        ef_dns(argc, argv);
    } else if (argc > 1 && !strncmp(argv[1], "dns", 3)) {
        argv += optind;
        argc -= optind;
        ef_dns(argc, argv);
    } else if (!strncmp(avval, "ef-eth", 16)) {
        ef_eth(argc, argv);
    } else if (argc > 1 && !strncmp(argv[1], "eth", 8)) {
        argv += optind;
        argc -= optind;
        ef_eth(argc, argv);
    } else if (!strncmp(avval, "ef-icmp", 12)) {
        ef_icmp(argc, argv);
    } else if (argc > 1 && !strncmp(argv[1], "icmp", 4)) {
        argv += optind;
        argc -= optind;
        ef_icmp(argc, argv);
    } else if (!strncmp(avval, "ef-igmp", 12)) {
        ef_igmp(argc, argv);
    } else if (argc > 1 && !strncmp(argv[1], "igmp", 4)) {
        argv += optind;
        argc -= optind;
        ef_igmp(argc, argv);
    } else if (!strncmp(avval, "ef-ip", 10)) {
        ef_ip(argc, argv);
    } else if (argc > 1 && !strncmp(argv[1], "ip", 2)) {
        argv += optind;
        argc -= optind;
        ef_ip(argc, argv);
    } else if (!strncmp(avval, "ef-rip", 11)) {
        ef_rip(argc, argv);
    } else if (argc > 1 && !strncmp(argv[1], "rip", 3)) {
        argv += optind;
        argc -= optind;
        ef_rip(argc, argv);
    } else if (!strncmp(avval, "ef-tcp", 11)) {
        ef_tcp(argc, argv);
    } else if (argc > 1 && !strncmp(argv[1], "tcp", 3)) {
        argv += optind;
        argc -= optind;
        ef_tcp(argc, argv);
    } else if (!strncmp(avval, "ef-udp", 11)) {
        ef_udp(argc, argv);
    } else if (argc > 1 && !strncmp(argv[1], "udp", 3)) {
        argv += optind;
        argc -= optind;
        ef_udp(argc, argv);
    } else if (!strncmp(avval, "ef-raw", 11)) {
        ef_raw(argc, argv);
    } else if (argc > 1 && !strncmp(argv[1], "raw", 3)) {
        argv += optind;
        argc -= optind;
        ef_raw(argc, argv);
    } else
        ef_usage(argv[0]);

    /* NOTREACHED */
    exit(0);
}

void ef_usage(char *arg) {
    printf("EF (easyframes) Usage:\n  %s [mode] [options]\n\n", arg);
    printf("EF modes:\n"
           "  arp\n"
           "  dns\n"
           "  eth\n"
           "  icmp\n"
           "  igmp\n"
           "  ip\n"
           "  raw\n"
           "  rip\n"
           "  tcp\n"
           "  udp\n\n");
    printf("EF options: \n"
           "  To display options, specify a mode with the option \"help\".\n");
    putchar('\n');
    exit(1);
}
