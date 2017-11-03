/*
 * Easy Frames Project
 * Copyright (C) 1999, 2000, 2001 Mark Grimes <mark@stateful.net>
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 * Copyright (C) 2017 Microsemi <allan.nielsen@microsemi.com>
 *
 * ef-igmp.c (IGMP Packet Injector)
 *
 */

#include "ef.h"

static ETHERhdr etherhdr;
static IPhdr iphdr;
static IGMPhdr igmphdr;
static FileData pd, ipod;
static int got_payload;
static int got_group, got_type, got_code;
static char *payloadfile = NULL;   /* payload file name */
static char *ipoptionsfile = NULL; /* IP options file name */
static char *device = NULL;        /* Ethernet device */

static void igmp_cmdline(int, char **);
static int igmp_exit(int);
static void igmp_initdata(void);
static void igmp_usage(char *);
static void igmp_validatedata(void);
static void igmp_verbose(void);

int buildigmp(ETHERhdr *eth, IPhdr *ip, IGMPhdr *igmp, FileData *pd,
              FileData *ipod, char *device) {
    int n;
    u_int32_t igmp_packetlen = 0, igmp_meta_packetlen = 0;
    static int sockfd = -1;
    static u_int8_t *pkt;
    struct libnet_link_int *l2 = NULL;
    u_int8_t link_offset = 0;
    int sockbuff = IP_MAXPACKET;

    if (pd->file_mem == NULL) pd->file_s = 0;
    if (ipod->file_mem == NULL) ipod->file_s = 0;

    if (got_link) /* data link layer transport */
    {
        if ((l2 = libnet_open_link_interface(device, errbuf)) == NULL) {
            ef_device_failure(INJECTION_LINK, (const char *)device);
            return -1;
        }
        link_offset = LIBNET_ETH_H;
    } else {
        if ((sockfd = libnet_open_raw_sock(IPPROTO_RAW)) < 0) {
            ef_device_failure(INJECTION_RAW, (const char *)NULL);
            return -1;
        }
        if ((setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (const void *)&sockbuff,
                        sizeof(sockbuff))) < 0) {
            fprintf(stderr, "ERROR: setsockopt() failed.\n");
            return -1;
        }
    }

    igmp_packetlen = link_offset + LIBNET_IP_H + LIBNET_IGMP_H + pd->file_s +
                     ipod->file_s;

    igmp_meta_packetlen = igmp_packetlen - (link_offset + LIBNET_IP_H);

#ifdef DEBUG
    printf("DEBUG: IGMP packet length %u.\n", igmp_packetlen);
    printf("DEBUG: IP   options size  %u.\n", ipod->file_s);
    printf("DEBUG: IGMP payload size  %u.\n", pd->file_s);
#endif

    if (libnet_init_packet(igmp_packetlen, &pkt) == -1) {
        fprintf(stderr, "ERROR: Unable to allocate packet memory.\n");
        return -1;
    }

    if (got_link)
        libnet_build_ethernet(eth->ether_dhost, eth->ether_shost, ETHERTYPE_IP,
                              NULL, 0, pkt);

    libnet_build_ip(igmp_meta_packetlen, ip->ip_tos, ip->ip_id, ip->ip_off,
                    ip->ip_ttl, ip->ip_p, ip->ip_src.s_addr, ip->ip_dst.s_addr,
                    NULL, 0, pkt + link_offset);

    libnet_build_igmp(igmp->igmp_type, igmp->igmp_code, igmp->igmp_group.s_addr,
                      pd->file_mem, pd->file_s, pkt + link_offset + LIBNET_IP_H);

    if (got_ipoptions) {
        if ((libnet_insert_ipo((struct ipoption *)ipod->file_mem, ipod->file_s,
                               pkt + link_offset)) == -1) {
            fprintf(stderr,
                    "ERROR: Unable to add IP options, discarding "
                    "them.\n");
        }
    }

    if (got_link)
        libnet_do_checksum(pkt + LIBNET_ETH_H, IPPROTO_IP,
                           LIBNET_IP_H + ipod->file_s);

    libnet_do_checksum(pkt + link_offset, IPPROTO_IGMP,
                       LIBNET_IGMP_H + pd->file_s + ipod->file_s);

    if (got_link)
        n = libnet_write_link_layer(l2, device, pkt, igmp_packetlen);
    else
        n = libnet_write_ip(sockfd, pkt, igmp_packetlen);

    if (verbose == 2) ef_hexdump(pkt, igmp_packetlen, HEX_ASCII_DECODE);
    if (verbose == 3) ef_hexdump(pkt, igmp_packetlen, HEX_RAW_DECODE);

    if (n != igmp_packetlen) {
        fprintf(stderr,
                "ERROR: Incomplete packet injection.  Only wrote "
                "%d bytes.\n",
                n);
    } else {
        if (verbose) {
            if (got_link)
                printf("Wrote %d byte IGMP packet through linktype %s.\n", n,
                       ef_lookup_linktype(l2->linktype));
            else
                printf("Wrote %d byte IGMP packet.\n", n);
        }
    }
    libnet_destroy_packet(&pkt);
    if (got_link)
        libnet_close_link_interface(l2);
    else
        libnet_close_raw_sock(sockfd);
    return n;
}

void ef_igmp(int argc, char **argv) {
    if (argc > 1 && !strncmp(argv[1], "help", 4)) igmp_usage(argv[0]);

    if (ef_seedrand() < 0)
        fprintf(stderr, "ERROR: Unable to seed random number generator.\n");

    igmp_initdata();
    igmp_cmdline(argc, argv);
    igmp_validatedata();
    igmp_verbose();

    if (got_payload) {
        if (builddatafromfile(
                    ((got_link == 1) ? IGMP_LINKBUFFSIZE : IGMP_RAWBUFFSIZE), &pd,
                    (const char *)payloadfile, (const u_int32_t)PAYLOADMODE) < 0)
            igmp_exit(1);
    }

    if (got_ipoptions) {
        if (builddatafromfile(OPTIONSBUFFSIZE, &ipod, (const char *)ipoptionsfile,
                              (const u_int32_t)OPTIONSMODE) < 0)
            igmp_exit(1);
    }

    if (buildigmp(&etherhdr, &iphdr, &igmphdr, &pd, &ipod, device) < 0) {
        puts("\nIGMP Injection Failure");
        igmp_exit(1);
    } else {
        puts("\nIGMP Packet Injected");
        igmp_exit(0);
    }
}

static void igmp_initdata(void) {
    /* defaults */
    etherhdr.ether_type = ETHERTYPE_IP;    /* Ethernet type IP */
    memset(etherhdr.ether_shost, 0, 6);    /* Ethernet source address */
    memset(etherhdr.ether_dhost, 0xff, 6); /* Ethernet destination address */
    memset(&iphdr.ip_src.s_addr, 0, 4);    /* IP source address */
    memset(&iphdr.ip_dst.s_addr, 0, 4);    /* IP destination address */
    iphdr.ip_tos = 0;                      /* IP type of service */
    iphdr.ip_id = (u_int16_t)libnet_get_prand(PRu16); /* IP ID */
    iphdr.ip_p = IPPROTO_IGMP;                        /* IP protocol IGMP */
    iphdr.ip_off = 0;              /* IP fragmentation offset */
    iphdr.ip_ttl = 1;              /* IP TTL - set to 1 purposely */
    igmphdr.igmp_type = 0;         /* IGMP type */
    igmphdr.igmp_code = 0;         /* IGMP code */
    igmphdr.igmp_group.s_addr = 0; /* IGMP group IP address */
    pd.file_mem = NULL;
    pd.file_s = 0;
    ipod.file_mem = NULL;
    ipod.file_s = 0;
    return;
}

static void igmp_validatedata(void) {
    struct sockaddr_in sin;

    /* validation tests */
    if (iphdr.ip_src.s_addr == 0)
        iphdr.ip_src.s_addr = (u_int32_t)libnet_get_prand(PRu32);

    /* if the user has supplied a source hardware addess but not a device
     * try to select a device automatically
     */
    if (memcmp(etherhdr.ether_shost, zero, 6) && !got_link && !device) {
        if (libnet_select_device(&sin, &device, (char *)&errbuf) < 0) {
            fprintf(stderr,
                    "ERROR: Device not specified and unable to "
                    "automatically select a device.\n");
            igmp_exit(1);
        } else {
#ifdef DEBUG
            printf("DEBUG: automatically selected device: "
                   "       %s\n",
                   device);
#endif
            got_link = 1;
        }
    }

    /* if a device was specified and the user has not specified a source
     * hardware address, try to determine the source address automatically
     */
    if (got_link) {
        if ((ef_check_link(&etherhdr, device)) < 0) {
            fprintf(stderr,
                    "ERROR: Cannot retrieve hardware address of "
                    "%s.\n",
                    device);
            igmp_exit(1);
        }
    }

    /* Attempt to send valid packets if the user hasn't decided to craft an
     * anomolous packet
     */
    if (!got_type) igmphdr.igmp_type = IGMP_V1_MEMBERSHIP_REPORT;
    if (!got_code) igmphdr.igmp_code = 0;
    if (!got_group) {
        ef_name_resolve("224.0.0.1",
                             (u_int32_t *)&igmphdr.igmp_group.s_addr);
        ef_name_resolve("224.0.0.1", (u_int32_t *)&iphdr.ip_dst.s_addr);
    }
    return;
}

static void igmp_usage(char *arg) {
    printf("IGMP usage:\n  %s [-v (verbose)] [options]\n\n", arg);
    printf("IGMP options: \n"
           "  -p <IGMP type>\n"
           "  -c <IGMP code (unused field)>\n"
           "  -i <IGMP group IP address>\n"
           "  -P <Payload file>\n\n");
    printf("IP options: \n"
           "  -S <Source IP address>\n"
           "  -D <Destination IP address>\n"
           "  -I <IP ID>\n"
           "  -T <IP TTL>\n"
           "  -t <IP TOS>\n"
           "  -F <IP fragmentation options>\n"
           "     -F[D],[M],[R],[offset]\n"
           "  -O <IP options file>\n\n");
    printf("Data Link Options: \n"
           "  -d <Ethernet device name>\n"
           "  -H <Source MAC address>\n"
           "  -M <Destination MAC address>\n");
    putchar('\n');
    igmp_exit(1);
}

static void igmp_cmdline(int argc, char **argv) {
    int opt, i;
    u_int32_t addr_tmp[6];
    char *igmp_options;
    extern char *optarg;
    extern int optind;

#if defined(ENABLE_PCAPOUTPUT)
    igmp_options = "c:d:D:F:H:i:I:M:O:p:P:S:t:T:vW?";
#else
    igmp_options = "c:d:D:F:H:i:I:M:O:p:P:S:t:T:v?";
#endif

    while ((opt = getopt(argc, argv, igmp_options)) != -1) {
        switch (opt) {
        case 'c': /* IGMP code */
            igmphdr.igmp_code = xgetint8(optarg);
            got_code = 1;
            break;
        case 'd': /* Ethernet device */
            if (strlen(optarg) < 256) {
                device = strdup(optarg);
                got_link = 1;
            } else {
                fprintf(stderr, "ERROR: device %s > 256 characters.\n", optarg);
                igmp_exit(1);
            }
            break;
        case 'D': /* destination IP address */
            if ((ef_name_resolve(optarg,
                                      (u_int32_t *)&iphdr.ip_dst.s_addr)) < 0) {
                fprintf(stderr,
                        "ERROR: Invalid destination IP address: "
                        "\"%s\".\n",
                        optarg);
                igmp_exit(1);
            }
            break;
        case 'F': /* IP fragmentation options */
            if (parsefragoptions(&iphdr, optarg) < 0) igmp_exit(1);
            break;
        case 'H': /* Ethernet source address */
            memset(addr_tmp, 0, sizeof(addr_tmp));
            sscanf(optarg, "%02X:%02X:%02X:%02X:%02X:%02X", &addr_tmp[0],
                   &addr_tmp[1], &addr_tmp[2], &addr_tmp[3], &addr_tmp[4],
                   &addr_tmp[5]);
            for (i = 0; i < 6; i++)
                etherhdr.ether_shost[i] = (u_int8_t)addr_tmp[i];
            break;
        case 'i': /* IGMP group address */
            if ((ef_name_resolve(
                        optarg, (u_int32_t *)&igmphdr.igmp_group.s_addr)) < 0) {
                fprintf(stderr,
                        "ERROR: Invalid IGMP group address: \"%s\"."
                        "\n",
                        optarg);
                igmp_exit(1);
            }
            got_group = 1;
            break;
        case 'I': /* IP ID */
            iphdr.ip_id = xgetint16(optarg);
            break;
        case 'M': /* Ethernet destination address */
            memset(addr_tmp, 0, sizeof(addr_tmp));
            sscanf(optarg, "%02X:%02X:%02X:%02X:%02X:%02X", &addr_tmp[0],
                   &addr_tmp[1], &addr_tmp[2], &addr_tmp[3], &addr_tmp[4],
                   &addr_tmp[5]);
            for (i = 0; i < 6; i++)
                etherhdr.ether_dhost[i] = (u_int8_t)addr_tmp[i];
            break;
        case 'O': /* IP options file */
            if (strlen(optarg) < 256) {
                ipoptionsfile = strdup(optarg);
                got_ipoptions = 1;
            } else {
                fprintf(stderr,
                        "ERROR: IP options file %s > 256 "
                        "characters.\n",
                        optarg);
                igmp_exit(1);
            }
            break;
        case 'p': /* IGMP type */
            igmphdr.igmp_type = xgetint8(optarg);
            got_type = 1;
            break;
        case 'P': /* payload file */
            if (strlen(optarg) < 256) {
                payloadfile = strdup(optarg);
                got_payload = 1;
            } else {
                fprintf(stderr,
                        "ERROR: payload file %s > 256 "
                        "characters.\n",
                        optarg);
                igmp_exit(1);
            }
            break;
        case 'S': /* source IP address */
            if ((ef_name_resolve(optarg,
                                      (u_int32_t *)&iphdr.ip_src.s_addr)) < 0) {
                fprintf(stderr,
                        "ERROR: Invalid source IP address: \"%s\"."
                        "\n",
                        optarg);
                igmp_exit(1);
            }
            break;
        case 't': /* IP type of service */
            iphdr.ip_tos = xgetint8(optarg);
            break;
        case 'T': /* IP time to live */
            iphdr.ip_ttl = xgetint8(optarg);
            break;
        case 'v':
            verbose++;
            break;
        case '?': /* FALLTHROUTH */
        default:
            igmp_usage(argv[0]);
            break;
        }
    }
    argc -= optind;
    argv += optind;
    return;
}

static int igmp_exit(int code) {
    if (got_payload) free(pd.file_mem);

    if (got_ipoptions) free(ipod.file_mem);

    if (device != NULL) free(device);

    if (ipoptionsfile != NULL) free(ipoptionsfile);

    if (payloadfile != NULL) free(payloadfile);

    exit(code);
}

static void igmp_verbose(void) {
    if (verbose) {
        if (got_link) ef_printeth(&etherhdr);

        ef_printip(&iphdr);
        printf("         [IGMP Type] %hu\n", igmphdr.igmp_type);
        printf("         [IGMP Code] %hu\n", igmphdr.igmp_code);
        printf("[IGMP group address] %s\n", inet_ntoa(igmphdr.igmp_group));
    }
    return;
}