#include "ef.h"

#include <sys/time.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int argc_frame(int argc, const char *argv[], frame_t *f) {
    int i, j, res;
    hdr_t *h;

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
            //po("ERROR: Invalid parameter: %s\n", argv[i]);
            //return -1;
            return i;
        }

        h = frame_clone_and_push_hdr(f, h);
        if (!h) {
            po("ERROR: frame_clone_and_push_hdr() failed\n");
            return -1;
        }

        //po("Parsing hdr: %s: %p\n", h->name, h);
        //po("%d, i=%d/%d %s\n", __LINE__, i, argc, argv[i]);
        res = h->parser(f, h, argc - i, argv + i);
        if (res < 0) {
            return res;
        }

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

    memset(c, 0, sizeof(*c));
}


void print_help() {
    po("Usage: ef [options] <command> args [<command> args]...\n");
    po("\n");
    po("The ef (easy frame) tool allow to easily transmit frames, and\n");
    po("optionally specify what frames it expect to receive.\n");
    po("\n");
    po("Options:\n");
    po("  -h                    Top level help message.\n");
    po("  -t <timeout-in-ms>    When listening on an interface (rx),\n");
    po("     When listening on an interface (rx), the tool will always\n");
    po("     listen during the entire timeout period. This is needed,\n");
    po("     as we must also check that no frames are received during\n");
    po("     the test.  Default is 100ms.\n");
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
    po("  tx <interface> FRAME | help\n");
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
        c->repeat = 1;
        if (strcmp(argv[i], "rep") == 0 || strcmp(argv[i], "repeat") == 0) {
            c->repeat = atoi(argv[i+1]);
            i += 2;
        }
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

        if (c->frame->has_mask)
            c->frame_mask_buf = frame_mask_to_buf(c->frame);
    }

    i += res;
    //po("%d, i=%d/%d %s\n", __LINE__, i, argc, argv[i]);

    return i;
}

int argc_cmds(int argc, const char *argv[]) {
    struct timeval tv_now, tv_left, tv_begin, tv_end;

    int res, i = 0, cmd_idx = 0;
    cmd_t cmds[100] = {};

    while (i < argc && cmd_idx < 100) {
        //po("%d, cmd[%d]\n", __LINE__, cmd_idx);
        res = argc_cmd(argc - i, argv + i, &cmds[cmd_idx]);

        if (res > 0) {
            i += res;
            cmd_idx ++;

        } else if (res == 0) {
            break;

        } else {
            return -1;

        }
    }

    if (i != argc) {
        po("Parse error! %d %d %d\n", i, argc, cmd_idx);
        return -1;
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
}

int TIME_OUT_MS = 100;

int main_(int argc, const char *argv[]) {
    int opt;

    while ((opt = getopt(argc, (char * const*)argv, "ht:c:")) != -1) {
        switch (opt) {
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

    return argc_cmds(argc - optind, argv + optind);
}

