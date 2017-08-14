/*
 * $Id: nemesis-tcp.c,v 1.2 2004/10/07 01:20:56 jnathan Exp $
 *
 * THE NEMESIS PROJECT
 * Copyright (C) 1999, 2000 Mark Grimes <mark@stateful.net>
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-tcp.c (TCP Packet Injector)
 *
 */

#include "nemesis.h"

static ETHERhdr etherhdr;
static IPhdr iphdr;
static TCPhdr tcphdr;
static FileData pd, ipod, tcpod;
static int got_payload;
static char *payloadfile = NULL;    /* payload file name */
static char *ipoptionsfile = NULL;  /* IP options file name */
static char *tcpoptionsfile = NULL; /* IP options file name */
static char *device = NULL;         /* Ethernet device */

static void tcp_cmdline(int, char **);
static int tcp_exit(int);
static void tcp_initdata(void);
static void tcp_usage(char *);
static void tcp_validatedata(void);
static void tcp_verbose(void);

int buildtcp(ETHERhdr *eth, IPhdr *ip, TCPhdr *tcp, FileData *pd,
             FileData *ipod, FileData *tcpod, char *device) {
    int n;
    u_int32_t tcp_packetlen = 0, tcp_meta_packetlen = 0;
    static u_int8_t *pkt;
    static int sockfd = -1;
    struct libnet_link_int *l2 = NULL;
    u_int8_t link_offset = 0;
    int sockbuff = IP_MAXPACKET;

    if (pd->file_mem == NULL) pd->file_s = 0;
    if (ipod->file_mem == NULL) ipod->file_s = 0;
    if (tcpod->file_mem == NULL) tcpod->file_s = 0;

    if (got_link) /* data link layer transport */
    {
        if ((l2 = libnet_open_link_interface(device, errbuf)) == NULL) {
            nemesis_device_failure(INJECTION_LINK, (const char *)device);
            return -1;
        }
        link_offset = LIBNET_ETH_H;
    } else {
        if ((sockfd = libnet_open_raw_sock(IPPROTO_RAW)) < 0) {
            nemesis_device_failure(INJECTION_RAW, (const char *)NULL);
            return -1;
        }
        if ((setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (const void *)&sockbuff,
                        sizeof(sockbuff))) < 0) {
            fprintf(stderr, "ERROR: setsockopt() failed.\n");
            return -1;
        }
    }

    tcp_packetlen = link_offset + LIBNET_IP_H + LIBNET_TCP_H + pd->file_s +
                    ipod->file_s + tcpod->file_s;

    tcp_meta_packetlen = tcp_packetlen - (link_offset + LIBNET_IP_H);

#ifdef DEBUG
    printf("DEBUG: TCP packet length %u.\n", tcp_packetlen);
    printf("DEBUG: IP  options size  %u.\n", ipod->file_s);
    printf("DEBUG: TCP options size  %u.\n", tcpod->file_s);
    printf("DEBUG: TCP payload size  %u.\n", pd->file_s);
#endif

    if (libnet_init_packet(tcp_packetlen, &pkt) == -1) {
        fprintf(stderr, "ERROR: Unable to allocate packet memory.\n");
        return -1;
    }

    if (got_link)
        libnet_build_ethernet(eth->ether_dhost, eth->ether_shost, ETHERTYPE_IP,
                              NULL, 0, pkt);

    libnet_build_ip(tcp_meta_packetlen, ip->ip_tos, ip->ip_id, ip->ip_off,
                    ip->ip_ttl, ip->ip_p, ip->ip_src.s_addr, ip->ip_dst.s_addr,
                    NULL, 0, pkt + link_offset);

    libnet_build_tcp(tcp->th_sport, tcp->th_dport, tcp->th_seq, tcp->th_ack,
                     tcp->th_flags, tcp->th_win, tcp->th_urp, pd->file_mem,
                     pd->file_s, pkt + link_offset + LIBNET_IP_H);

    if (got_ipoptions) {
        if ((libnet_insert_ipo((struct ipoption *)ipod->file_mem, ipod->file_s,
                               pkt + link_offset)) == -1) {
            fprintf(stderr,
                    "ERROR: Unable to add IP options, discarding "
                    "them.\n");
        }
    }

    if (got_tcpoptions) {
        if ((libnet_insert_tcpo((struct tcpoption *)tcpod->file_mem,
                                tcpod->file_s, pkt + link_offset)) == -1) {
            fprintf(stderr,
                    "ERROR: Unable to add TCP options, discarding "
                    "them.\n");
        }
    }

    if (got_link)
        libnet_do_checksum(pkt + LIBNET_ETH_H, IPPROTO_IP,
                           LIBNET_IP_H + ipod->file_s);

    libnet_do_checksum(pkt + link_offset, IPPROTO_TCP,
                       LIBNET_TCP_H + pd->file_s + tcpod->file_s);

    if (got_link)
        n = libnet_write_link_layer(l2, device, pkt, tcp_packetlen);
    else
        n = libnet_write_ip(sockfd, pkt, tcp_packetlen);

    if (verbose == 2) nemesis_hexdump(pkt, tcp_packetlen, HEX_ASCII_DECODE);
    if (verbose == 3) nemesis_hexdump(pkt, tcp_packetlen, HEX_RAW_DECODE);

    if (n != tcp_packetlen) {
        fprintf(stderr,
                "ERROR: Incomplete packet injection.  Only wrote "
                "%d bytes.\n",
                n);
    } else {
        if (verbose) {
            if (got_link)
                printf("Wrote %d byte TCP packet through linktype %s.\n", n,
                       nemesis_lookup_linktype(l2->linktype));
            else
                printf("Wrote %d byte TCP packet.\n", n);
        }
    }
    libnet_destroy_packet(&pkt);
    if (got_link)
        libnet_close_link_interface(l2);
    else
        libnet_close_raw_sock(sockfd);
    return n;
}

void nemesis_tcp(int argc, char **argv) {
    if (argc > 1 && !strncmp(argv[1], "help", 4)) tcp_usage(argv[0]);

    if (nemesis_seedrand() < 0)
        fprintf(stderr, "ERROR: Unable to seed random number generator.\n");

    tcp_initdata();
    tcp_cmdline(argc, argv);
    tcp_validatedata();
    tcp_verbose();

    if (got_payload) {
        if (builddatafromfile(
                    ((got_link == 1) ? TCP_LINKBUFFSIZE : TCP_RAWBUFFSIZE), &pd,
                    (const char *)payloadfile, (const u_int32_t)PAYLOADMODE) < 0)
            tcp_exit(1);
    }

    if (got_ipoptions) {
        if (builddatafromfile(OPTIONSBUFFSIZE, &ipod, (const char *)ipoptionsfile,
                              (const u_int32_t)OPTIONSMODE) < 0)
            tcp_exit(1);
    }

    if (got_tcpoptions) {
        if (builddatafromfile(OPTIONSBUFFSIZE, &tcpod,
                              (const char *)tcpoptionsfile,
                              (const u_int32_t)OPTIONSMODE) < 0)
            tcp_exit(1);
    }

    if (buildtcp(&etherhdr, &iphdr, &tcphdr, &pd, &ipod, &tcpod, device) < 0) {
        puts("\nTCP Injection Failure");
        tcp_exit(1);
    } else {
        puts("\nTCP Packet Injected");
        tcp_exit(0);
    }
}

static void tcp_initdata(void) {
    /* defaults */
    etherhdr.ether_type = ETHERTYPE_IP;    /* Ethernet type IP */
    memset(etherhdr.ether_shost, 0, 6);    /* Ethernet source address */
    memset(etherhdr.ether_dhost, 0xff, 6); /* Ethernet destination address */
    memset(&iphdr.ip_src.s_addr, 0, 4);    /* IP source address */
    memset(&iphdr.ip_dst.s_addr, 0, 4);    /* IP destination address */
    iphdr.ip_tos = 0;                      /* IP type of service */
    iphdr.ip_id = (u_int16_t)libnet_get_prand(PRu16); /* IP ID */
    iphdr.ip_p = IPPROTO_TCP;                         /* IP protocol TCP */
    iphdr.ip_off = 0;   /* IP fragmentation offset */
    iphdr.ip_ttl = 255; /* IP TTL */
    tcphdr.th_sport = (u_int16_t)libnet_get_prand(PRu16);
    /* TCP source port */
    tcphdr.th_dport = (u_int16_t)libnet_get_prand(PRu16);
    /* TCP destination port */
    tcphdr.th_seq = (u_int32_t)libnet_get_prand(PRu32);
    /* randomize sequence number */
    tcphdr.th_ack = (u_int32_t)libnet_get_prand(PRu32);
    /* randomize ack number */
    tcphdr.th_flags |= TH_SYN; /* TCP flags */
    tcphdr.th_win = 4096;      /* TCP window size */
    pd.file_mem = NULL;
    pd.file_s = 0;
    ipod.file_mem = NULL;
    ipod.file_s = 0;
    tcpod.file_mem = NULL;
    tcpod.file_s = 0;
    return;
}

static void tcp_validatedata(void) {
    struct sockaddr_in sin;

    /* validation tests */
    if (iphdr.ip_src.s_addr == 0)
        iphdr.ip_src.s_addr = (u_int32_t)libnet_get_prand(PRu32);
    if (iphdr.ip_dst.s_addr == 0)
        iphdr.ip_dst.s_addr = (u_int32_t)libnet_get_prand(PRu32);

    /* if the user has supplied a source hardware addess but not a device
     * try to select a device automatically
     */
    if (memcmp(etherhdr.ether_shost, zero, 6) && !got_link && !device) {
        if (libnet_select_device(&sin, &device, (char *)&errbuf) < 0) {
            fprintf(stderr,
                    "ERROR: Device not specified and unable to "
                    "automatically select a device.\n");
            tcp_exit(1);
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
        if ((nemesis_check_link(&etherhdr, device)) < 0) {
            fprintf(stderr, "ERROR: cannot retrieve hardware address of %s.\n",
                    device);
            tcp_exit(1);
        }
    }

    return;
}

static void tcp_usage(char *arg) {
    printf("TCP usage:\n  %s [-v (verbose)] [options]\n\n", arg);
    printf("TCP options: \n"
           "  -x <Source port>\n"
           "  -y <Destination port>\n"
           "  -f <TCP flags>\n"
           "     -fS (SYN), -fA (ACK), -fR (RST), -fP (PSH), -fF (FIN),"
           " -fU (URG)\n"
           "     -fE (ECE), -fC (CWR)\n"
           "  -w <Window size>\n"
           "  -s <SEQ number>\n"
           "  -a <ACK number>\n"
           "  -u <Urgent pointer offset>\n"
           "  -o <TCP options file>\n"
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
    tcp_exit(1);
}

static void tcp_cmdline(int argc, char **argv) {
    int opt, i, flag;
    u_int32_t addr_tmp[6];
    char *tcp_options;
    char *p, c;
    extern char *optarg;
    extern int optind;

#if defined(ENABLE_PCAPOUTPUT)
    tcp_options = "a:d:D:f:F:H:I:M:o:O:P:s:S:t:T:u:w:x:y:vW?";
#else
    tcp_options = "a:d:D:f:F:H:I:M:o:O:P:s:S:t:T:u:w:x:y:v?";
#endif

    while ((opt = getopt(argc, argv, tcp_options)) != -1) {
        switch (opt) {
        case 'a': /* ACK window */
            tcphdr.th_ack = xgetint32(optarg);
            break;
        case 'd': /* Ethernet device */
            if (strlen(optarg) < 256) {
                device = strdup(optarg);
                got_link = 1;
            } else {
                fprintf(stderr, "ERROR: device %s > 256 characters.\n", optarg);
                tcp_exit(1);
            }
            break;
        case 'D': /* destination IP address */
            if ((nemesis_name_resolve(optarg,
                                      (u_int32_t *)&iphdr.ip_dst.s_addr)) < 0) {
                fprintf(stderr,
                        "ERROR: Invalid destination IP address: "
                        "\"%s\".\n",
                        optarg);
                tcp_exit(1);
            }
            break;
        case 'f': /* TCP flags */
            p = optarg;
            tcphdr.th_flags = 0;
            while (*p != '\0') {
                c = *p;
                flag = strchr(validtcpflags, c) - validtcpflags;
                if (flag < 0 || flag > 8) {
                    printf("ERROR: Invalid TCP flag: %c.\n", c);
                    tcp_exit(1);
                }
                if (flag == 8)
                    break;
                else {
                    tcphdr.th_flags |= 1 << flag;
                    p++;
                }
            }
            break;
        case 'F': /* IP fragmentation options */
            if (parsefragoptions(&iphdr, optarg) < 0) tcp_exit(1);
            break;
        case 'H': /* Ethernet source address */
            memset(addr_tmp, 0, sizeof(addr_tmp));
            sscanf(optarg, "%02X:%02X:%02X:%02X:%02X:%02X", &addr_tmp[0],
                   &addr_tmp[1], &addr_tmp[2], &addr_tmp[3], &addr_tmp[4],
                   &addr_tmp[5]);
            for (i = 0; i < 6; i++)
                etherhdr.ether_shost[i] = (u_int8_t)addr_tmp[i];
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
        case 'o': /* TCP options file */
            if (strlen(optarg) < 256) {
                tcpoptionsfile = strdup(optarg);
                got_tcpoptions = 1;
            } else {
                fprintf(stderr,
                        "ERROR: TCP options file %s > 256 "
                        "characters.\n",
                        optarg);
                tcp_exit(1);
            }
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
                tcp_exit(1);
            }
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
                tcp_exit(1);
            }
            break;
        case 's': /* TCP sequence number */
            tcphdr.th_seq = xgetint32(optarg);
            break;
        case 'S': /* source IP address */
            if ((nemesis_name_resolve(optarg,
                                      (u_int32_t *)&iphdr.ip_src.s_addr)) < 0) {
                fprintf(stderr,
                        "ERROR: Invalid source IP address: \"%s\"."
                        "\n",
                        optarg);
                tcp_exit(1);
            }
            break;
        case 't': /* IP type of service */
            iphdr.ip_tos = xgetint8(optarg);
            break;
        case 'T': /* IP time to live */
            iphdr.ip_ttl = xgetint8(optarg);
            break;
        case 'u': /* TCP urgent pointer */
            tcphdr.th_urp = xgetint16(optarg);
            break;
        case 'v':
            verbose++;
            break;
        case 'w': /* TCP window size */
            tcphdr.th_win = xgetint16(optarg);
            break;
        case 'x': /* TCP source port */
            tcphdr.th_sport = xgetint16(optarg);
            break;
        case 'y': /* TCP destination port */
            tcphdr.th_dport = xgetint16(optarg);
            break;
        case '?': /* FALLTHROUGH */
        default:
            tcp_usage(argv[0]);
            break;
        }
    }
    argc -= optind;
    argv += optind;
    return;
}

static int tcp_exit(int code) {
    if (got_payload) free(pd.file_mem);

    if (got_ipoptions) free(ipod.file_mem);

    if (got_tcpoptions) free(tcpod.file_mem);

    if (device != NULL) free(device);

    if (tcpoptionsfile != NULL) free(tcpoptionsfile);

    if (ipoptionsfile != NULL) free(ipoptionsfile);

    if (payloadfile != NULL) free(payloadfile);

    exit(code);
}

static void tcp_verbose(void) {
    if (verbose) {
        if (got_link) nemesis_printeth(&etherhdr);

        nemesis_printip(&iphdr);
        nemesis_printtcp(&tcphdr);
    }
    return;
}
