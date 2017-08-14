/*
 * Easy Frames Project
 * Copyright (C) 2002, 2003 Jeff Nathan <jeff@snort.org>
 * Copyright (C) 2017 Microsemi <allan.nielsen@microsemi.com>
 *
 * ef-ethernet.c (Ethernet Packet Injector)
 *
 */

#include "ef.h"

static ETHERhdr etherhdr;
static char *device = NULL; /* Ethernet device */

static int cnt = 1;
static int frame_size = 0;
#define MAX_FRAME 4096
static u_int8_t payload[MAX_FRAME];
static int payload_size;

static void ethernet_cmdline(int, char **);
static int ethernet_exit(int);
static void ethernet_initdata(void);
static void ethernet_usage(char *);
static void ethernet_validatedata(void);
static void ethernet_verbose(void);

static int build_ether(ETHERhdr *eth, char *device) {
    int n;
    static u_int8_t *pkt;
    char *ethertype;
    struct libnet_link_int *l2 = NULL;


    if ((l2 = libnet_open_link_interface(device, errbuf)) == NULL) {
        ef_device_failure(INJECTION_LINK, (const char *)device);
        return -1;
    }

    if (libnet_init_packet(frame_size, &pkt) == -1) {
        fprintf(stderr, "ERROR: Unable to allocate packet memory.\n");
        exit(1);
    }

    libnet_build_ethernet(eth->ether_dhost, eth->ether_shost, eth->ether_type,
                          payload, frame_size - LIBNET_ETH_H, pkt);

    if (cnt > 1) {
        printf("CNT: %d\n", cnt);
    }

    for (int i = 0; i < cnt; ++i) {
        n = libnet_write_link_layer(l2, device, pkt, frame_size);
    }
#ifdef DEBUG
    printf("DEBUG: frame_size is %u.\n", frame_size);
#endif
    if (verbose == 2) ef_hexdump(pkt, frame_size, HEX_ASCII_DECODE);
    if (verbose == 3) ef_hexdump(pkt, frame_size, HEX_RAW_DECODE);

    switch (eth->ether_type) {
    case ETHERTYPE_IP:
        ethertype = "IP";
        break;
    case ETHERTYPE_ARP:
        ethertype = "ARP";
        break;
    case ETHERTYPE_REVARP:
        ethertype = "REVARP";
        break;
    case ETHERTYPE_8021Q:
        ethertype = "802.1q";
        break;
    case ETHERTYPE_IPV6:
        ethertype = "IPV6";
        break;
    default:
        ethertype = NULL;
        break;
    }

    if (verbose) {
        if (ethertype != NULL)
            printf("Wrote %d byte Ethernet type %s packet through linktype "
                   "%s.\n",
                   n, ethertype, ef_lookup_linktype(l2->linktype));
        else
            printf("Wrote %d byte Ethernet type %hu packet through linktype "
                   "%s.\n",
                   n, eth->ether_type, ef_lookup_linktype(l2->linktype));
    }
    libnet_destroy_packet(&pkt);
    if (l2 != NULL) libnet_close_link_interface(l2);
    return (n);
}

void ef_ethernet(int argc, char **argv) {
    if (argc > 1 && !strncmp(argv[1], "help", 4)) ethernet_usage(argv[0]);

    ethernet_initdata();
    ethernet_cmdline(argc, argv);
    ethernet_validatedata();
    ethernet_verbose();

    if (build_ether(&etherhdr, device) < 0) {
        puts("\nEthernet Injection Failure");
        ethernet_exit(1);
    } else {
        puts("\nEthernet Packet Injected");
        ethernet_exit(0);
    }
}

static void ethernet_initdata(void) {
    /* defaults */
    etherhdr.ether_type = ETHERTYPE_IP;    /* Ethernet type IP */
    memset(etherhdr.ether_shost, 0, 6);    /* Ethernet source address */
    memset(etherhdr.ether_dhost, 0xff, 6); /* Ethernet destination address */
    return;
}

static void ethernet_validatedata(void) {
    struct sockaddr_in sin;

    /* validation tests */
    if (device == NULL) {
        if (libnet_select_device(&sin, &device, (char *)&errbuf) < 0) {
            fprintf(stderr,
                    "ERROR: Device not specified and unable to "
                    "automatically select a device.\n");
            ethernet_exit(1);
        } else {
#ifdef DEBUG
            printf("DEBUG: automatically selected device: "
                   "       %s\n",
                   device);
#endif
        }
    }

    /* Determine if there's a source hardware address set */
    if ((ef_check_link(&etherhdr, device)) < 0) {
        fprintf(stderr, "ERROR: Cannot retrieve hardware address of %s.\n",
                device);
        ethernet_exit(1);
    }

    if (payload_size && !frame_size) {
        frame_size = payload_size + LIBNET_ETH_H;
        if (frame_size < 64) frame_size = 64;
    }

    if (!frame_size) {
        frame_size = 64;
    }

    return;
}

static void ethernet_usage(char *arg) {
    printf("Ethernet Usage:\n  %s [-v (verbose)] [options]\n\n", arg);
    printf("Ethernet Options: \n"
           "  -c <Repeat count>\n"
           "  -d <Ethernet device name>\n"
           "  -H <Source MAC address>\n"
           "  -M <Destination MAC address>\n"
           "  -S <Frame size>\n"
           "  -P <payload (hex string)>\n"
           "  -T <Ethernet frame type (defaults to IP)>\n");
    putchar('\n');
    ethernet_exit(1);
}

static void ethernet_cmdline(int argc, char **argv) {
    int opt, i;
    u_int32_t addr_tmp[6];
    char *ethernet_options;
    extern char *optarg;
    extern int optind;

    ethernet_options = "d:H:M:P:S:T:c:v?";

    while ((opt = getopt(argc, argv, ethernet_options)) != -1) {
        switch (opt) {
        case 'd': /* Ethernet device */
            if (strlen(optarg) < 256)
                device = optarg;
            else {
                fprintf(stderr, "ERROR: device %s > 256 characters.\n", optarg);
                ethernet_exit(1);
            }
            break;

        case 'H': /* Ethernet source address */
            memset(addr_tmp, 0, sizeof(addr_tmp));
            sscanf(optarg, "%02X:%02X:%02X:%02X:%02X:%02X", &addr_tmp[0],
                   &addr_tmp[1], &addr_tmp[2], &addr_tmp[3], &addr_tmp[4],
                   &addr_tmp[5]);
            for (i = 0; i < 6; i++)
                etherhdr.ether_shost[i] = (u_int8_t)addr_tmp[i];
            break;

        case 'M': /* Ethernet destination address */
            memset(addr_tmp, 0, sizeof(addr_tmp));
            sscanf(optarg, "%02X:%02X:%02X:%02X:%02X:%02X", &addr_tmp[0],
                   &addr_tmp[1], &addr_tmp[2], &addr_tmp[3], &addr_tmp[4],
                   &addr_tmp[5]);
            for (i = 0; i < 6; i++)
                etherhdr.ether_dhost[i] = (u_int8_t)addr_tmp[i];
            break;

        case 'S': /* Payload size */
            frame_size = atoi(optarg);

            if (frame_size < 64 || frame_size > MAX_FRAME) {
                fprintf(stderr, "ERROR: invalid frame size: %d\n", frame_size);
                ethernet_exit(1);
            }
            break;

        case 'P':  // Payload
            payload_size = parse_hex_string(optarg, payload, MAX_FRAME);
            if (payload_size < 0) {
                fprintf(stderr, "ERROR: invalid hex string\n");
                ethernet_exit(1);
            }
            break;

        case 'C': // CNT
            cnt = atoi(optarg);
            if (cnt < 0 || cnt > 2000000000) {
                fprintf(stderr, "ERROR: invalid count\n");
                ethernet_exit(1);
            }
            break;

        case 'T':
            etherhdr.ether_type = xgetint16(optarg);
            break;

        case 'v':
            verbose++;
            break;

        case '?': /* FALLTHROUGH */
        default:
            ethernet_usage(argv[0]);
            break;
        }
    }
    argc -= optind;
    argv += optind;
    return;
}

static int ethernet_exit(int code) {
    exit(code);
}

static void ethernet_verbose(void) {
    if (verbose) ef_printeth(&etherhdr);
    return;
}

