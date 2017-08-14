/*
 * Easy Frames Project
 * Copyright (C) 1999, 2000, 2001 Mark Grimes <mark@stateful.net>
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 * Copyright (C) 2017 Microsemi <allan.nielsen@microsemi.com>
 *
 * ef-dns.c (DNS Packet Injector)
 *
 */

#include "ef.h"

static int state; /* default to UDP */
static ETHERhdr etherhdr;
static IPhdr iphdr;
static TCPhdr tcphdr;
static UDPhdr udphdr;
static DNShdr dnshdr;
static FileData pd, ipod, tcpod;
static int got_payload;
static char *payloadfile = NULL;    /* payload file name */
static char *ipoptionsfile = NULL;  /* TCP options file name */
static char *tcpoptionsfile = NULL; /* IP options file name */
static char *device = NULL;         /* Ethernet device */

static void dns_cmdline(int, char **);
static int dns_exit(int);
static void dns_initdata(void);
static void dns_usage(char *);
static void dns_validatedata(void);
static void dns_verbose(void);

int builddns(ETHERhdr *eth, IPhdr *ip, TCPhdr *tcp, UDPhdr *udp, DNShdr *dns,
             FileData *pd, FileData *ipod, FileData *tcpod, char *device) {
    int n;
    u_int32_t dns_packetlen = 0, dns_meta_packetlen = 0;
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

    dns_packetlen =
            link_offset + LIBNET_IP_H + LIBNET_DNS_H + pd->file_s + ipod->file_s;

    if (state == 0) /* UDP */
        dns_packetlen += LIBNET_UDP_H;
    else /* TCP */
        dns_packetlen += LIBNET_TCP_H + tcpod->file_s;

    dns_meta_packetlen = dns_packetlen - (link_offset + LIBNET_IP_H);

#ifdef DEBUG
    printf("DEBUG: DNS packet length %u.\n", dns_packetlen);
    printf("DEBUG: IP  options size  %u.\n", ipod->file_s);
    printf("DEBUG: TCP options size  %u.\n", tcpod->file_s);
    printf("DEBUG: DNS payload size  %u.\n", pd->file_s);
#endif

    if (libnet_init_packet(dns_packetlen, &pkt) == -1) {
        fprintf(stderr, "ERROR: Unable to allocate packet memory.\n");
        return -1;
    }

    if (got_link)
        libnet_build_ethernet(eth->ether_dhost, eth->ether_shost, ETHERTYPE_IP,
                              NULL, 0, pkt);

    libnet_build_ip(dns_meta_packetlen, ip->ip_tos, ip->ip_id, ip->ip_off,
                    ip->ip_ttl, ip->ip_p, ip->ip_src.s_addr, ip->ip_dst.s_addr,
                    NULL, 0, pkt + link_offset);

    if (state == 0) {
        libnet_build_udp(udp->uh_sport, udp->uh_dport, NULL, 0,
                         pkt + link_offset + LIBNET_IP_H);
    } else {
        libnet_build_tcp(tcp->th_sport, tcp->th_dport, tcp->th_seq, tcp->th_ack,
                         tcp->th_flags, tcp->th_win, tcp->th_urp, NULL, 0,
                         pkt + link_offset + LIBNET_IP_H);
    }

    libnet_build_dns(dns->id, dns->flags, dns->num_q, dns->num_answ_rr,
                     dns->num_auth_rr, dns->num_addi_rr, pd->file_mem, pd->file_s,
                     pkt + link_offset + LIBNET_IP_H +
                             ((state == 0) ? LIBNET_UDP_H : LIBNET_TCP_H));

    if (got_ipoptions) {
        if ((libnet_insert_ipo((struct ipoption *)ipod->file_mem, ipod->file_s,
                               pkt + link_offset)) == -1) {
            fprintf(stderr,
                    "ERROR: Unable to add IP options, discarding "
                    "them.\n");
        }
    }

    if (state == 1) {
        if (got_tcpoptions) {
            if ((libnet_insert_tcpo((struct tcpoption *)tcpod->file_mem,
                                    tcpod->file_s, pkt + link_offset)) == -1) {
                fprintf(stderr,
                        "ERROR: Unable to add TCP options, discarding "
                        "them.\n");
            }
        }
    }

    if (got_link)
        libnet_do_checksum(pkt + LIBNET_ETH_H, IPPROTO_IP,
                           LIBNET_IP_H + ipod->file_s);

    libnet_do_checksum(pkt + link_offset,
                       ((state == 0) ? IPPROTO_UDP : IPPROTO_TCP),
                       ((state == 0) ? LIBNET_UDP_H : LIBNET_TCP_H) +
                               LIBNET_DNS_H + pd->file_s + ipod->file_s +
                               ((state == 0) ? 0 : tcpod->file_s));

    if (got_link)
        n = libnet_write_link_layer(l2, device, pkt, dns_packetlen);
    else
        n = libnet_write_ip(sockfd, pkt, dns_packetlen);

    if (verbose == 2) ef_hexdump(pkt, dns_packetlen, HEX_ASCII_DECODE);
    if (verbose == 3) ef_hexdump(pkt, dns_packetlen, HEX_RAW_DECODE);

    if (n != dns_packetlen) {
        fprintf(stderr,
                "ERROR: Incomplete packet injection.  Only wrote %d "
                "bytes.\n",
                n);
    } else {
        if (verbose) {
            if (got_link) {
                printf("Wrote %d byte DNS (%s) packet through "
                       "linktype %s.\n",
                       n, ((state == 0) ? "UDP" : "TCP"),
                       ef_lookup_linktype(l2->linktype));
            } else {
                printf("Wrote %d byte DNS (%s) packet\n", n,
                       ((state == 1) ? "UDP" : "TCP"));
            }
        }
    }
    libnet_destroy_packet(&pkt);
    if (got_link)
        libnet_close_link_interface(l2);
    else
        libnet_close_raw_sock(sockfd);
    return n;
}

void ef_dns(int argc, char **argv) {
    if (argc > 1 && !strncmp(argv[1], "help", 4)) dns_usage(argv[0]);

    if (ef_seedrand() < 0)
        fprintf(stderr, "ERROR: Unable to seed random number generator.\n");

    dns_initdata();
    dns_cmdline(argc, argv);
    dns_validatedata();
    dns_verbose();

    if (got_payload) {
        if (state) {
            if (builddatafromfile(((got_link == 1) ? DNSTCP_LINKBUFFSIZE
                                                   : DNSTCP_RAWBUFFSIZE),
                                  &pd, (const char *)payloadfile,
                                  (const u_int32_t)PAYLOADMODE) < 0)
                dns_exit(1);
        } else {
            if (builddatafromfile(((got_link == 1) ? DNSUDP_LINKBUFFSIZE
                                                   : DNSUDP_RAWBUFFSIZE),
                                  &pd, (const char *)payloadfile,
                                  (const u_int32_t)PAYLOADMODE) < 0)
                dns_exit(1);
        }
    }

    if (got_ipoptions) {
        if (builddatafromfile(OPTIONSBUFFSIZE, &ipod, (const char *)ipoptionsfile,
                              (const u_int32_t)OPTIONSMODE) < 0)
            dns_exit(1);
    }

    if (state && got_tcpoptions) {
        if (builddatafromfile(OPTIONSBUFFSIZE, &tcpod,
                              (const char *)tcpoptionsfile,
                              (const u_int32_t)OPTIONSMODE) < 0)
            dns_exit(1);
    }

    if (builddns(&etherhdr, &iphdr, &tcphdr, &udphdr, &dnshdr, &pd, &ipod,
                 &tcpod, device) < 0) {
        puts("\nDNS Injection Failure");
        dns_exit(1);
    } else {
        puts("\nDNS Packet Injected");
        dns_exit(0);
    }
}

static void dns_initdata(void) {
    /* defaults */
    etherhdr.ether_type = ETHERTYPE_IP;    /* Ethernet type IP */
    memset(etherhdr.ether_shost, 0, 6);    /* Ethernet source address */
    memset(etherhdr.ether_dhost, 0xff, 6); /* Ethernet destination address */
    memset(&iphdr.ip_src.s_addr, 0, 4);    /* IP source address */
    memset(&iphdr.ip_dst.s_addr, 0, 4);    /* IP destination address */
    iphdr.ip_tos = IPTOS_LOWDELAY;         /* IP type of service */
    iphdr.ip_id = (u_int16_t)libnet_get_prand(PRu16); /* IP ID */
    iphdr.ip_p = IPPROTO_UDP;
    iphdr.ip_off = 0;   /* IP fragmentation offset */
    iphdr.ip_ttl = 255; /* IP TTL */
    tcphdr.th_sport = (u_int16_t)libnet_get_prand(PRu16);
    /* TCP source port */
    tcphdr.th_dport = 53; /* TCP destination port */
    tcphdr.th_seq = (u_int32_t)libnet_get_prand(PRu32);
    /* randomize sequence number */
    tcphdr.th_ack = (u_int32_t)libnet_get_prand(PRu32);
    /* randomize ack number */
    tcphdr.th_flags = 0;  /* TCP flags */
    tcphdr.th_win = 4096; /* TCP window size */
    udphdr.uh_sport = (u_int16_t)libnet_get_prand(PRu16);
    /* UDP source port */
    udphdr.uh_dport = 53; /* UDP destination port */
    pd.file_mem = NULL;
    pd.file_s = 0;
    ipod.file_mem = NULL;
    ipod.file_s = 0;
    tcpod.file_mem = NULL;
    tcpod.file_s = 0;
    return;
}

static void dns_validatedata(void) {
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
            dns_exit(1);
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
            fprintf(stderr, "ERROR: cannot retrieve hardware address of %s.\n",
                    device);
            dns_exit(1);
        }
    }

    /* Attempt to send valid packets if the user hasn't decided to craft an
     * anomolous packet
     */
    if (state && tcphdr.th_flags == 0) tcphdr.th_flags |= TH_SYN;
    return;
}

static void dns_usage(char *arg) {
    printf("DNS usage:\n  %s [-v (verbose)] [options]\n\n", arg);
    printf("DNS options: \n"
           "  -i <DNS ID>\n"
           "  -g <DNS flags>\n"
           "  -q <# of Questions>\n"
           "  -W <# of Answer RRs>\n"
           "  -A <# of Authority RRs>\n"
           "  -r <# of Additional RRs>\n"
           "  -P <Payload file>\n"
           "  -k (Enable TCP transport)\n\n");
    printf("TCP options (with -k): \n"
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
           "  -o <TCP options file>\n\n");
    printf("UDP options (without -k): \n"
           "  -x <Source port>\n"
           "  -y <Destination port>\n\n");
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
    dns_exit(1);
}

static void dns_cmdline(int argc, char **argv) {
    int opt, i, flag;
    u_int32_t addr_tmp[6];
    char *dns_options;
    char *p, c;
    extern char *optarg;
    extern int optind;

#if defined(ENABLE_PCAPOUTPUT)
    dns_options = "a:A:b:d:D:f:F:g:H:i:I:M:o:O:P:q:r:s:S:t:T:u:w:W:x:y:kv?";
#else
    dns_options = "a:A:b:d:D:f:F:g:H:i:I:M:o:O:P:q:r:s:S:t:T:u:w:x:y:kv?";
#endif

    while ((opt = getopt(argc, argv, dns_options)) != -1) {
        switch (opt) {
        case 'a': /* ACK window */
            tcphdr.th_ack = xgetint32(optarg);
            break;
        case 'A': /* number of authoritative resource records */
            dnshdr.num_auth_rr = xgetint16(optarg);
            break;
        case 'b': /* number of answers */
            dnshdr.num_answ_rr = xgetint16(optarg);
            break;
        case 'd': /* Ethernet device */
            if (strlen(optarg) < 256) {
                device = strdup(optarg);
                got_link = 1;
            } else {
                fprintf(stderr, "ERROR: device %s > 256 characters.\n", optarg);
                dns_exit(1);
            }
            break;
        case 'D': /* destination IP address */
            if ((ef_name_resolve(optarg,
                                      (u_int32_t *)&iphdr.ip_dst.s_addr)) < 0) {
                fprintf(stderr,
                        "ERROR: Invalid destination IP address: "
                        "\"%s\".\n",
                        optarg);
                dns_exit(1);
            }
            break;
        case 'f': /* TCP flags */
            p = optarg;
            while (*p != '\0') {
                c = *p;
                flag = strchr(validtcpflags, c) - validtcpflags;
                if (flag < 0 || flag > 7) {
                    printf("ERROR: Invalid TCP flag: %c.\n", c);
                    dns_exit(1);
                } else {
                    tcphdr.th_flags |= 1 << flag;
                    p++;
                }
            }
            break;
        case 'F': /* IP fragmentation options */
            if (parsefragoptions(&iphdr, optarg) < 0) dns_exit(1);
            break;
        case 'g': /* DNS flags */
            dnshdr.flags = xgetint16(optarg);
            break;
        case 'H': /* Ethernet source address */
            memset(addr_tmp, 0, sizeof(addr_tmp));
            sscanf(optarg, "%02X:%02X:%02X:%02X:%02X:%02X", &addr_tmp[0],
                   &addr_tmp[1], &addr_tmp[2], &addr_tmp[3], &addr_tmp[4],
                   &addr_tmp[5]);
            for (i = 0; i < 6; i++)
                etherhdr.ether_shost[i] = (u_int8_t)addr_tmp[i];
            break;
        case 'i': /* DNS ID */
            dnshdr.id = xgetint16(optarg);
            break;
        case 'I': /* IP ID */
            iphdr.ip_id = xgetint16(optarg);
            break;
        case 'k': /* use TCP */
            iphdr.ip_tos = 0;
            iphdr.ip_p = IPPROTO_TCP;
            state = 1;
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
                dns_exit(1);
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
                dns_exit(1);
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
                dns_exit(1);
            }
            break;
        case 'q': /* number of questions */
            dnshdr.num_q = xgetint16(optarg);
            break;
        case 'r': /* number of additional resource records */
            dnshdr.num_addi_rr = xgetint16(optarg);
            break;
        case 's': /* TCP sequence number */
            tcphdr.th_seq = xgetint32(optarg);
            break;
        case 'S': /* source IP address */
            if ((ef_name_resolve(optarg,
                                      (u_int32_t *)&iphdr.ip_src.s_addr)) < 0) {
                fprintf(stderr,
                        "ERROR: Invalid source IP address: \"%s\"."
                        "\n",
                        optarg);
                dns_exit(1);
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

        case 'x': /* TCP/UDP source port */
            tcphdr.th_sport = xgetint16(optarg);
            udphdr.uh_sport = xgetint16(optarg);
            break;
        case 'y': /* TCP/UDP destination port */
            tcphdr.th_dport = xgetint16(optarg);
            udphdr.uh_dport = xgetint16(optarg);
            break;
        case '?': /* FALLTHROUGH */
        default:
            dns_usage(argv[0]);
            break;
        }
    }
    argc -= optind;
    argv += optind;
    return;
}

static int dns_exit(int code) {
    if (got_payload) free(pd.file_mem);

    if (got_ipoptions) free(ipod.file_mem);

    if (got_tcpoptions) free(tcpod.file_mem);

    if (device != NULL) free(device);

    if (tcpoptionsfile != NULL) free(tcpoptionsfile);

    if (ipoptionsfile != NULL) free(ipoptionsfile);

    if (payloadfile != NULL)
        ;
    free(payloadfile);

    exit(code);
}

static void dns_verbose(void) {
    if (verbose) {
        if (got_link) ef_printeth(&etherhdr);

        ef_printip(&iphdr);

        if (state)
            ef_printtcp(&tcphdr);
        else
            ef_printudp(&udphdr);

        printf("   [DNS # Questions] %hu\n", dnshdr.num_q);
        printf("  [DNS # Answer RRs] %hu\n", dnshdr.num_answ_rr);
        printf("    [DNS # Auth RRs] %hu\n", dnshdr.num_auth_rr);
        printf("  [DNS # Addtnl RRs] %hu\n\n", dnshdr.num_addi_rr);
    }
    return;
}
