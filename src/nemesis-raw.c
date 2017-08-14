/*
 * $Id: nemesis-ethernet.c,v 1.1.1.1 2003/10/31 21:29:36 jnathan Exp $
 *
 * THE NEMESIS PROJECT
 * Copyright (C) 2002, 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-ethernet.c (Ethernet Packet Injector)
 *
 */

#include "nemesis.h"

static ETHERhdr etherhdr;
static char *device = NULL; /* Ethernet device */

static int cnt = 1;
static int frame_size = 0;
#define MAX_FRAME 4096
static u_int8_t payload[MAX_FRAME];
static int payload_size;

static void raw_cmdline(int, char **);
static void raw_usage(char *);
static void raw_validatedata(void);

static int build_raw(ETHERhdr *eth, char *device) {
    int n;
    struct libnet_link_int *l2 = NULL;

    if ((l2 = libnet_open_link_interface(device, errbuf)) == NULL) {
        nemesis_device_failure(INJECTION_LINK, (const char *)device);
        return -1;
    }

    for (int i = 0; i < cnt; ++i) {
        n = libnet_write_link_layer(l2, device, payload, payload_size);
    }

#ifdef DEBUG
    printf("DEBUG: payload_size is %u.\n", payload_size);
#endif
    if (verbose == 2) nemesis_hexdump(payload, payload_size, HEX_ASCII_DECODE);
    if (verbose == 3) nemesis_hexdump(payload, payload_size, HEX_RAW_DECODE);

    if (verbose) {
        printf("Wrote %d byte Ethernet type %hu packet through linktype %s.\n",
               n, eth->ether_type, nemesis_lookup_linktype(l2->linktype));
    }

    if (l2 != NULL) libnet_close_link_interface(l2);
    return n;
}

void nemesis_raw(int argc, char **argv) {
    if (argc > 1 && !strncmp(argv[1], "help", 4)) raw_usage(argv[0]);

    raw_cmdline(argc, argv);
    raw_validatedata();

    if (build_raw(&etherhdr, device) < 0) {
        puts("\nEthernet Injection Failure");
        exit(1);
    } else {
        puts("\nEthernet Packet Injected");
        exit(0);
    }
}

static void raw_validatedata(void) {
    struct sockaddr_in sin;

    /* validation tests */
    if (device == NULL) {
        if (libnet_select_device(&sin, &device, (char *)&errbuf) < 0) {
            fprintf(stderr,
                    "ERROR: Device not specified and unable to "
                    "automatically select a device.\n");
            exit(1);
        } else {
            printf("DEBUG: automatically selected device: %s\n", device);
        }
    }

    if (payload_size && !frame_size) {
        frame_size = payload_size + LIBNET_ETH_H;
        if (frame_size < 64) frame_size = 64;
    }

    if (!frame_size) {
        frame_size = 64;
    }

    if (cnt < 0 || cnt > 2000000000) {
        fprintf(stderr, "ERROR: invalid count\n");
        exit(1);
    }

    return;
}

static void raw_usage(char *arg) {
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
    exit(1);
}

static void raw_cmdline(int argc, char **argv) {
    int opt;
    char *raw_options;
    extern char *optarg;
    extern int optind;

    raw_options = "d:P:S:c:v?";

    while ((opt = getopt(argc, argv, raw_options)) != -1) {
        switch (opt) {
        case 'd': /* Ethernet device */
            if (strlen(optarg) < 256)
                device = optarg;
            else {
                fprintf(stderr, "ERROR: device %s > 256 characters.\n", optarg);
                exit(1);
            }
            break;

        case 'S': /* Payload size */
            frame_size = atoi(optarg);
            if (frame_size < 64 || frame_size > MAX_FRAME) {
                fprintf(stderr, "ERROR: invalid frame size: %d\n", frame_size);
                exit(1);
            }
            break;

        case 'P':  // Payload
            payload_size = parse_hex_string(optarg, payload, MAX_FRAME);
            if (payload_size < 0) {
                fprintf(stderr, "ERROR: invalid hex string\n");
                exit(1);
            }
            break;

        case 'C':  // CNT
            cnt = atoi(optarg);
            break;

        case 'v':
            verbose++;
            break;

        case '?': /* FALLTHROUGH */
        default:
            raw_usage(argv[0]);
            break;
        }
    }
    argc -= optind;
    argv += optind;
    return;
}