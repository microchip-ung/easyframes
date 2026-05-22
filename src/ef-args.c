#include "ef.h"

#include <sys/time.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <getopt.h>

int argc_frame(int argc, const char *argv[], frame_t *f) {
    int i, j, res, offset;
    hdr_t *h;

    offset = 0;
    frame_reset(f);

    i = 0;
    while (i < argc) {
        //po("%d, i=%d/%d %s\n", __LINE__, i, argc, argv[i]);

        if (strcmp(argv[i], "help") == 0) {
            po("Specify a frame by using one or more of the following headers:\n");
            hdr_help(hdr_tmpls, HDR_TMPL_SIZE, 2, 0);
            return -1;
        }

        h = 0;
        for (j = 0; j < HDR_TMPL_SIZE; ++j) {
            if (hdr_tmpls[j] && strcmp(argv[i], hdr_tmpls[j]->name) == 0) {
                h = hdr_tmpls[j];
                i++;
                break;
            }
        }

        if (!h) {
            // Only overwrite if hdr_parse_fields didn't already set context
            if (!PARSE_ERR_CTX.token) {
                PARSE_ERR_CTX.token = argv[i];
                PARSE_ERR_CTX.hdr_name = NULL;
                PARSE_ERR_CTX.fields = NULL;
                PARSE_ERR_CTX.fields_size = 0;
            }
            return i;
        }

        h = frame_clone_and_push_hdr(f, h);
        if (!h) {
            po("ERROR: frame_clone_and_push_hdr() failed\n");
            return -1;
        }

        //po("Parsing hdr: %s: %p\n", h->name, h);
        //po("%d, i=%d/%d %s\n", __LINE__, i, argc, argv[i]);
        res = h->parser(f, h, offset, argc - i, argv + i);
        if (res < 0) {
            return res;
        }

        offset += h->size;
        i += res;
        //po("%d, i=%d/%d %s\n", __LINE__, i, argc, argv[i]);
    }

    return i;
}

void cmd_destruct(cmd_t *c) {
    if (c->name)
        free(c->name);

    if (c->arg0)
        free(c->arg0);

    if (c->frame)
        frame_free(c->frame);

    if (c->frame_buf)
        bfree(c->frame_buf);

    if (c->frame_mask_buf)
        bfree(c->frame_mask_buf);

    if (c->mmsg)
        free(c->mmsg);
    if (c->miov)
        free(c->miov);

    memset(c, 0, sizeof(*c));
}

void print_version() {
    po("ef version: %s\n", gGIT_VERSION);
}

void print_help() {
    po("Usage: ef [options] <command> args [<command> args]...\n");
    po("\n");
    po("The ef (easy frame) tool allow to easily transmit frames, and\n");
    po("optionally specify what frames it expect to receive.\n");
    po("\n");
    po("Options:\n");
    po("  -v                    Print version.\n");
    po("  -h                    Top level help message.\n");
    po("  -p                    No pad. Skip padding frames to 60 bytes,\n");
    po("     allowing runt frames to be sent or matched as-is.\n");
    po("  -Q                    Set PACKET_QDISC_BYPASS on all sockets.\n");
    po("     Skips the Linux qdisc layer entirely, reducing TX CPU cost.\n");
    po("  -r                    Use PACKET_TX_RING (TPACKET_V2) for TX.\n");
    po("     Per-cmd mmap ring; one atomic store per frame plus a periodic\n");
    po("     send() kick. Off by default; the env var EF_TX_RING=1 has the\n");
    po("     same effect as -r.\n");
    po("  -x                    Force AF_XDP zero-copy TX. Loads an\n");
    po("     XDP_PASS program on the iface (or reuses one already there)\n");
    po("     and binds an xsk socket in XDP_ZEROCOPY mode. Fails hard if\n");
    po("     the driver does not support ZC, so the run is never silently\n");
    po("     demoted. Mutually exclusive with -r.\n");
    po("  -m                    Batch TX with sendmmsg in the rate path.\n");
    po("     Sends up to 'burst' frames per syscall using a pre-built\n");
    po("     mmsghdr vector. Requires a 'rate ...' on the tx command\n");
    po("     (use 'rate <high>G' as a near-unlimited rate to opt in).\n");
    po("     Same effect via env: EF_USE_SENDMMSG=1.\n");
    po("  --ignore-link-down    On the PACKET_TX_RING path (-r), retry\n");
    po("     silently when send() returns ENETDOWN instead of treating it\n");
    po("     as fatal. Useful for tests that toggle the link mid-run.\n");
    po("  -t <timeout-in-ms>    Wall-clock deadline. Default 100ms.\n");
    po("     RX: the tool always listens for the full timeout period\n");
    po("     so we can verify that no unexpected frames arrive.\n");
    po("     TX:\n");
    po("       'rep N' (with or without 'rate'): runs to completion,\n");
    po("         ignoring -t. Explicit rep is the user contract.\n");
    po("       'rate ...' with no rep: stops at -t.\n");
    po("       no rep, no rate: a single frame is sent and the loop\n");
    po("         exits as soon as RX (if any) is satisfied.\n");
    po("\n");
    po("  -c <if>,[<snaplen>],[<sync>],[<file>],[cnt]\n");
    po("     Use tcpdump to capture traffic on an interface while the\n");
    po("     test is running. If file is not specified, then it will\n");
    po("     default to './<if>.pcap'\n");
    po("     tcpdump will be invoked with the following options:\n");
    po("     tcpdump -i <if> [-s <snaplen>] [-j <sync>] -w <file> -c <cnt>\n");
    po("\n");
    po("\n");
    po("Valid commands:\n");
    po("  tx: Transmit a frame on a interface. Syntax:\n");
    po("  tx <interface> [rep <N>] [rate <pps>] [burst <N>] FRAME | help\n");
    po("\n");
    po("  rx: Specify a frame which is expected to be received. If no \n");
    po("      frame is specified, then the expectation is that no\n");
    po("      frames are received on the interface. Syntax:\n");
    po("  rx <interface> [FRAME] | help\n");
    po("\n");
    po("  hex: Print a frame on stdout as a hex string. Syntax:\n");
    po("  hex FRAME\n");
    po("\n");
    po("  name: Specify a frame, and provide a name (alias) for it.\n");
    po("        This alias can be used other places instead of the\n");
    po("        complete frame specification. Syntax:\n");
    po("  name <name> FRAME-SPEC | help\n");
    po("\n");
    po("  pcap: Write a frame to a pcap file (appending if the file\n");
    po("  exists already). Syntax:\n");
    po("  pcap <file> FRAME | help\n");
    po("\n");
    po("Where FRAME is either a frame specification of a named frame.\n");
    po("Syntax: FRAME ::= FRAME-SPEC | name <name>\n");
    po("\n");
    po("FRAME-SPEC is a textual specification of a frame.\n");
    po("Syntax: FRAME-SPEC ::= [HDR-NAME [<HDR-FIELD> <HDR-FIELD-VAL>]...]...\n");
    po("        HDR-NAME ::= eth|stag|ctag|arp|ipv4|udp\n");
    po("\n");
    po("Examples:\n");
    po("  ef tx eth0 eth dmac ::1 smac ::2 stag vid 0x100 ipv4 dip 1 udp\n");
    po("\n");
    po("  ef name f1 eth dmac ff:ff:ff:ff:ff:ff smac ::1\\\n");
    po("     rx eth0 name f1\\\n");
    po("     tx eth1 name f1\n");
    po("\n");
    po("A complete header or a given field in a header can be ignored by\n");
    po("using the 'ign' or 'ignore' flag.\n");
    po("Example:\n");
    po("  To ignore the ipv4 header completly:\n");
    po("  ef hex eth dmac 1::2 smac 3::4 ipv4 ign udp\n");
    po("\n");
    po("  To ignore the ipv4 everything in the ipv4 header except the sip:\n");
    po("  ef hex eth dmac 1::2 smac 3::4 ipv4 ign sip 1.2.3.4 udp\n");
    po("\n");
    po("  To ignore the sip field in ipv4:\n");
    po("  ef hex eth dmac 1::2 smac 3::4 ipv4 sip ign udp\n");
    po("\n");
    po("A frame can be repeated to utilize up to line speed bandwith (>512 byte frames)\n");
    po("using the 'rep' or 'repeat' flag.\n");
    po("Example:\n");
    po("   Send a frame 1 million times:\n");
    po("   ef tx eth0 rep 1000000 eth dmac ::1 smac ::2\n");
    po("   Note that the repeat flag must follow the tx <interface> key-word\n");
    po("   Results must be viewed through the PC or DUT interface counters, i.e. outside of 'ef'\n");
    po("\n");
    po("TX rate limiting:\n");
    po("   'rate <pps>' limits TX to the given packets per second.\n");
    po("   'rate <N>K|M|G' limits TX to the given wire rate in Kbps/Mbps/Gbps.\n");
    po("   Wire rate includes preamble, SFD, FCS and IFG (24 bytes overhead).\n");
    po("   'rate' without 'rep' implies infinite repeat, bounded by -t timeout.\n");
    po("   'rep', 'rate' and 'burst' can appear in any order.\n");
    po("   'burst <N>' overrides the token-bucket burst size (default: 10%%\n");
    po("   of pps, clamped to [1, 1024]). Useful at low rates where the\n");
    po("   default burst would send an unwanted packet storm.\n");
    po("Examples:\n");
    po("   ef -t 5000 tx eth0 rate 1000 eth dmac ::1 smac ::2\n");
    po("   ef tx eth0 rep 500 rate 100 eth dmac ::1 smac ::2\n");
    po("   ef -t 5000 tx eth0 rate 1G eth dmac ::1 smac ::2\n");
    po("   ef -t 5000 tx eth0 rate 100M eth dmac ::1 smac ::2\n");
    po("\n");
}

int argc_cmd(int argc, const char *argv[], cmd_t *c) {
    int i = 0, res;

    if (i >= argc)
        return 0;

    //po("%d, i=%d/%d %s\n", __LINE__, i, argc, argv[i]);

    if (strcmp(argv[i], "name") == 0) {
        c->type = CMD_TYPE_NAME;
#ifdef HAS_LIBPCAP
    } else if (strcmp(argv[i], "pcap") == 0) {
        c->type = CMD_TYPE_PCAP;
#endif
    } else if (strcmp(argv[i], "hex") == 0) {
        c->type = CMD_TYPE_HEX;
    } else if (strcmp(argv[i], "rx") == 0) {
        c->type = CMD_TYPE_RX;
    } else if (strcmp(argv[i], "tx") == 0) {
        c->type = CMD_TYPE_TX;
    } else if (strcmp(argv[i], "help") == 0) {
        print_help();
        return -1;
    } else {
        return 0;
    }

    i += 1;
    if (i >= argc)
        return 0;

//    po("%d, i=%d/%d %s\n", __LINE__, i, argc, argv[i]);
    switch (c->type) {
        case CMD_TYPE_NAME:
            c->name = strdup(argv[i]);
            i += 1;
            break;

        case CMD_TYPE_HEX: /* fallthrough */
            break;

#ifdef HAS_LIBPCAP
        case CMD_TYPE_PCAP: /* fallthrough */
#endif
        case CMD_TYPE_RX: /* fallthrough */
        case CMD_TYPE_TX: /* fallthrough */
            c->arg0 = strdup(argv[i]);
            i += 1;
            break;

        default:
            ;
    }

    if (c->type == CMD_TYPE_TX) {
        int rep_given = 0, kw;

        c->repeat = 1;
        c->rate_pps = 0;
        c->rate_bps = 0;
        c->rate_burst = 0;

        for (kw = 0; kw < 3 && i < argc; kw++) {
            if (strcmp(argv[i], "rep") == 0 ||
                strcmp(argv[i], "repeat") == 0) {
                if (i + 1 >= argc)
                    break;
                c->repeat = atoi(argv[i + 1]);
                rep_given = 1;
                i += 2;
            } else if (strcmp(argv[i], "rate") == 0) {
                if (i + 1 >= argc)
                    break;

                const char *val = argv[i + 1];
                char *end;
                unsigned long long num = strtoull(val, &end, 10);

                if (end != val && (*end == 'K' || *end == 'k')) {
                    c->rate_bps = num * 1000ULL;
                } else if (end != val && (*end == 'M' || *end == 'm')) {
                    c->rate_bps = num * 1000000ULL;
                } else if (end != val && (*end == 'G' || *end == 'g')) {
                    c->rate_bps = num * 1000000000ULL;
                } else {
                    c->rate_pps = (uint32_t)num;
                }

                i += 2;
            } else if (strcmp(argv[i], "burst") == 0) {
                if (i + 1 >= argc)
                    break;
                c->rate_burst = atoi(argv[i + 1]);
                i += 2;
            } else {
                break;
            }
        }

        // rate without rep implies infinite repeat
        if ((c->rate_pps > 0 || c->rate_bps > 0) && !rep_given)
            c->repeat = UINT32_MAX;
        c->rep_explicit = rep_given;
    }

    //po("%d, i=%d/%d %s\n", __LINE__, i, argc, argv[i]);
    if (i + 1 < argc && strcmp(argv[i], "name") == 0 &&
        c->type != CMD_TYPE_NAME) {
        c->name = strdup(argv[i + 1]);
        i += 2;
        //po("%d, assign name: %s\n", __LINE__, c->name);
        return i;
    }

    //po("%d, i=%d/%d %s\n", __LINE__, i, argc, argv[i]);
    // start parsing the frame
    c->frame = frame_alloc();
    res = argc_frame(argc - i, argv + i, c->frame);

    if (res == 0 && c->type == CMD_TYPE_RX) {
        // RX can have empty frame (meaning nothing)
        frame_free(c->frame);
        c->frame = 0;
        //po("%d, i=%d/%d %s\n", __LINE__, i, argc, argv[i]);
        return i;
    }

    if (res <= 0) {
        cmd_destruct(c);
        //po("%d, i=%d/%d %s\n", __LINE__, i, argc, argv[i]);
        return res;
    }

    if (c->frame) {
        c->frame_buf = frame_to_buf(c->frame);
        if (!c->frame_buf) {
            cmd_destruct(c);
            return -1;
        }

        if (c->frame->has_mask)
            c->frame_mask_buf = frame_mask_to_buf(c->frame);
    }

    i += res;
    //po("%d, i=%d/%d %s\n", __LINE__, i, argc, argv[i]);

    return i;
}

static int is_known_hdr(const char *name)
{
    int j;

    for (j = 0; j < HDR_TMPL_SIZE; j++)
        if (hdr_tmpls[j] && hdr_tmpls[j]->name &&
            strcmp(name, hdr_tmpls[j]->name) == 0)
            return 1;
    return 0;
}

static void print_parse_error(int argc, const char *argv[], int err_idx)
{
    int j, col;
    const char *tok = PARSE_ERR_CTX.token ? PARSE_ERR_CTX.token : argv[err_idx];

    // Find the actual argv position of the error token.  PARSE_ERR_CTX.token
    // is a pointer into a sub-array of argv, so pointer comparison works.
    int tok_idx = err_idx;
    if (PARSE_ERR_CTX.token) {
        for (j = 0; j < argc; j++) {
            if (argv[j] == PARSE_ERR_CTX.token) {
                tok_idx = j;
                break;
            }
        }
    }

    // Error headline
    if (PARSE_ERR_CTX.hdr_name && !is_known_hdr(tok)) {
        pe("error: '%s' is not a field of '%s' or a recognized header\n",
           tok, PARSE_ERR_CTX.hdr_name);
    } else if (PARSE_ERR_CTX.hdr_name) {
        pe("error: '%s' is not a field of '%s'\n",
           tok, PARSE_ERR_CTX.hdr_name);
    } else if (PARSE_ERR_CTX.token) {
        pe("error: '%s' is not a recognized header or command\n", tok);
    } else {
        pe("error: unexpected token '%s'\n", tok);
    }

    // Show the full command with a caret pointing to the bad token
    pe("  ");
    for (j = 0; j < argc; j++)
        pe("%s ", argv[j]);
    pe("\n");

    // Compute column offset of the error token
    col = 2; // leading "  "
    for (j = 0; j < tok_idx; j++)
        col += strlen(argv[j]) + 1;

    pe("%*s", col, "");
    for (j = 0; j < (int)strlen(tok); j++)
        pe("^");
    pe("\n");

    // Hint: list available fields
    if (PARSE_ERR_CTX.hdr_name && PARSE_ERR_CTX.fields) {
        pe("  valid fields for '%s':", PARSE_ERR_CTX.hdr_name);
        for (j = 0; j < PARSE_ERR_CTX.fields_size; j++) {
            if (PARSE_ERR_CTX.fields[j].bit_width == 0)
                continue;
            pe(" %s", PARSE_ERR_CTX.fields[j].name);
        }
        pe("\n");
    }
}

int argc_cmds(int argc, const char *argv[]) {
    struct timeval tv_now, tv_left, tv_begin, tv_end;

    int res, i = 0, cmd_idx = 0;
    cmd_t cmds[100] = {};

    memset(&PARSE_ERR_CTX, 0, sizeof(PARSE_ERR_CTX));

    while (i < argc && cmd_idx < 100) {
        //po("%d, cmd[%d]\n", __LINE__, cmd_idx);
        res = argc_cmd(argc - i, argv + i, &cmds[cmd_idx]);

        if (res > 0) {
            i += res;
            cmd_idx ++;

        } else if (res == 0) {
            break;

        } else {
            goto err;

        }
    }

    if (i != argc) {
        print_parse_error(argc, argv, i);
        goto err;
    }

    capture_all_start();

    tv_left.tv_sec = TIME_OUT_MS / 1000;
    tv_left.tv_usec = (TIME_OUT_MS - (tv_left.tv_sec * 1000)) * 1000;
    gettimeofday(&tv_begin, 0);
    timeradd(&tv_begin, &tv_left, &tv_end);

    res = exec_cmds(cmd_idx, cmds);

    // exec_cmds may return faster than TIME_OUT_MS if no rx interafces are
    // specified. We need to sleep the the deceired time if we are capturing
    // interfaces.
    gettimeofday(&tv_now, 0);
    if (capture_cnt() > 0 && timercmp(&tv_now, &tv_end, <)) {
        timersub(&tv_end, &tv_now, &tv_left);
        sleep(tv_left.tv_sec);
        usleep(tv_left.tv_usec);
    }

    capture_all_stop();

    for (i = 0; i < cmd_idx; ++i) {
        cmd_destruct(&cmds[i]);
    }

    return res;

err:
    for (i = 0; i < cmd_idx; ++i) {
        cmd_destruct(&cmds[i]);
    }

    return -1;
}

int NO_PAD = 0;
int TIME_OUT_MS = 100;
int QDISC_BYPASS = 0;
int TX_RING = 0;
int MMSG_TX = 0;
int TX_XDP = 0;
int IGNORE_LINK_DOWN = 0;
parse_err_ctx_t PARSE_ERR_CTX;

int main_(int argc, const char *argv[]) {
    static const struct option long_opts[] = {
        { "ignore-link-down", no_argument, NULL, 1 },
        { NULL,               0,           NULL, 0 },
    };
    int opt;

    while ((opt = getopt_long(argc, (char * const*)argv, "pQvhrxmt:c:",
                              long_opts, NULL)) != -1) {
        switch (opt) {
            case 1:  // --ignore-link-down
                IGNORE_LINK_DOWN = 1;
                break;

            case 'Q':
                QDISC_BYPASS = 1;
                break;

            case 'x':
                TX_XDP = 1;
                break;

            case 'r':
                TX_RING = 1;
                break;

            case 'm':
                MMSG_TX = 1;
                break;

            case 'p':
                NO_PAD = 1;
                break;

            case 'v':
                print_version();
                return 0;

            case 'h':
                print_help();
                return -1;

            case 't':
                TIME_OUT_MS = atoi(optarg);
                break;

            case 'c':
                if (capture_add(optarg)) {
                    po("ERROR adding capture interface\n");
                    return -1;
                }
                break;

            default: /* '?' */
                print_help();
                return -1;
        }
    }

    if (TX_XDP && TX_RING) {
        pe("error: -x is mutually exclusive with -r\n");
        return -1;
    }

    return argc_cmds(argc - optind, argv + optind);
}

