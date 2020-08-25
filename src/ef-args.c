#include "ef.h"

#include <sys/time.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

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

    if (c->stream_name)
        free(c->stream_name);

    if (c->frame)
        frame_free(c->frame);

    if (c->frame_buf)
        bfree(c->frame_buf);

    if (c->frame_mask_buf)
        bfree(c->frame_mask_buf);

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
    po("  tx <interface> [rep <cnt>] FRAME | help\n");
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
    po("  stream: Specify a name of the sequence, followed by a sequence of\n");
    po("          named frames. The stream name can be used with the 'tx'\n");
    po("          command to send a sequence of frames. Syntax:\n");
    po("  stream <stream-name> <named-frame>...\n");
    po("\n");
    po("  pcap: Write a frame to a pcap file (appending if the file\n");
    po("  exists already). Syntax:\n");
    po("  pcap <file> FRAME | help\n");
    po("\n");
    po("Where FRAME is either a frame specification of a named frame.\n");
    po("Syntax: FRAME ::= FRAME-SPEC | name <frane-name | stream-name>\n");
    po("\n");
    po("FRAME-SPEC is a textual specification of a frame.\n");
    po("Syntax: FRAME-SPEC ::= [HDR-NAME [<HDR-FIELD> <HDR-FIELD-VAL>]...]...\n");
    po("        HDR-NAME ::= eth|stag|ctag|arp|ipv4|udp\n");
    po("\n");
    po("Examples:\n");
    po("  # Send a UDP frame on eth0, with the specified ethernet, vlan, ip\n");
    po("  # and UDP header\n");
    po("  $ ef tx eth0 eth dmac ::1 smac ::2 stag vid 0x100 ipv4 dip 1 udp\n");
    po("\n");
    po("  # Send a frame on eth1, and expect to receive it again on eth0\n");
    po("  $ ef name f1 eth dmac ff:ff:ff:ff:ff:ff smac ::1\\\n");
    po("     rx eth0 name f1\\\n");
    po("     tx eth1 name f1\n");
    po("\n");
    po("  # Send frame f1 twice and f2 once on eth1\n");
    po("  $ ef name f1 eth dmac ff:ff:ff:ff:ff:ff smac ::1\\\n");
    po("     name f2 eth dmac ::1 smac ::2\\\n");
    po("     stream s1 f1 f1 f2\\\n");
    po("     tx eth1 name s1\n");
    po("\n");
    po("  # Send 300 frames on eth1. It will be a repeated sequence of: f1,\n");
    po("  # f1, f2, f1, f1, f2....\n");
    po("  $ ef name f1 eth dmac ff:ff:ff:ff:ff:ff smac ::1\\\n");
    po("     name f2 eth dmac ::1 smac ::2\\\n");
    po("     stream s1 f1 f1 f2\\\n");
    po("     tx eth1 rep 100 name s1\n");
    po("\n");
    po("A complete header or a given field in a header can be ignored by\n");
    po("using the 'ign' or 'ignore' flag.\n");
    po("Example:\n");
    po("  # To ignore the ipv4 header completly:\n");
    po("  $ ef hex eth dmac 1::2 smac 3::4 ipv4 ign udp\n");
    po("\n");
    po("  # To ignore the ipv4 everything in the ipv4 header except the sip:\n");
    po("  $ ef hex eth dmac 1::2 smac 3::4 ipv4 ign sip 1.2.3.4 udp\n");
    po("\n");
    po("  # To ignore the sip field in ipv4:\n");
    po("  $ ef hex eth dmac 1::2 smac 3::4 ipv4 sip ign udp\n");
    po("\n");
    po("A frame can be repeated to utilize up to line speed bandwith (>512 byte frames)\n");
    po("using the 'rep' or 'repeat' flag.\n");
    po("Example:\n");
    po("   # Send a frame 1 million times:\n");
    po("   $ ef tx eth0 rep 1000000 eth dmac ::1 smac ::2\n");
    po("   Note that the repeat flag must follow the tx <interface> key-word\n");
    po("   Results must be viewed through the PC or DUT interface counters, i.e. outside of 'ef'\n");
    po("\n");
}

int argc_stream(int argc, const char *argv[], cmd_t *stream_start, cmd_t *c) {
    int i = 0;

    if (i >= argc)
        return 0;

    if (strcmp(argv[i], "stream") == 0 ||
        strcmp(argv[i], "name") == 0 ||
        strcmp(argv[i], "pcap") == 0 ||
        strcmp(argv[i], "hex") == 0 ||
        strcmp(argv[i], "rx") == 0 ||
        strcmp(argv[i], "tx") == 0 ||
        strcmp(argv[i], "end") == 0) {
        return 0;
    } else if (strcmp(argv[i], "help") == 0) {
        print_help();
        return -1;
    } else {
        c->type = CMD_TYPE_STREAM;
        c->name = strdup(argv[i]);
        c->stream_name = strdup(stream_start->stream_name);
        i += 1;
        //po("%d, i=%d/%d %s\n", __LINE__, i, argc, argv[i]);
        return i;
    }
}

int argc_cmd(int argc, const char *argv[], cmd_t *c) {
    int i = 0, res;

    if (i >= argc)
        return 0;

    //po("%d, i=%d/%d %s\n", __LINE__, i, argc, argv[i]);

    if (strcmp(argv[i], "stream") == 0) {
        c->type = CMD_TYPE_STREAM;
        if (argc < 3) {
            return -1;
        }
    } else if (strcmp(argv[i], "name") == 0) {
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

    c->stream_cnt = 1;

    i += 1;
    if (i >= argc)
        return 0;

    //po("%d, i=%d/%d %s\n", __LINE__, i, argc, argv[i]);
    switch (c->type) {
        case CMD_TYPE_NAME:
            c->name = strdup(argv[i]);
            i += 1;
            break;

        case CMD_TYPE_HEX:
            break;

        case CMD_TYPE_STREAM:
            c->stream_name = strdup(argv[i]);
            i += 1;
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

    //po("%d, i=%d/%d %s\n", __LINE__, i, argc, argv[i]);
    if (c->type == CMD_TYPE_STREAM && i + 1 <= argc) {
        c->name = strdup(argv[i]);
        i += 1;
        //po("%d, i=%d/%d %s\n", __LINE__, i, argc, argv[i]);
        return i;
    }

    if (c->type == CMD_TYPE_TX) {
        c->repeat = 1;
        if (strcmp(argv[i], "rep") == 0 || strcmp(argv[i], "repeat") == 0) {
            c->repeat = atoi(argv[i+1]);
            i += 2;
        }

        c->repeat_left = c->repeat;
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

static int copy_cmd_by_name(const char *name, int cnt, cmd_t *cmds, cmd_t *dst) {
    int i;

    for (i = 0; i < cnt; i++) {
        if (cmds[i].type != CMD_TYPE_NAME)
            continue;

        if (!cmds[i].frame_buf || !cmds[i].name)
            continue;

        if (strcmp(cmds[i].name, name) != 0)
            continue;

        dst->frame = frame_clone(cmds[i].frame);
        dst->frame_buf = bclone(cmds[i].frame_buf);
        dst->frame_mask_buf = bclone(cmds[i].frame_mask_buf);
        return 0;
    }

    return -1;
}

static int expand_name_stream(cmd_t *cmds, int idx, int length) {
    int i, j;
    cmd_t *cur = &cmds[idx];

    if (cur->type == CMD_TYPE_NAME)
        return 1;

    if (!cur->name)
        return 1;

    // Try see if we match a named frame
    if (copy_cmd_by_name(cur->name, idx, cmds, cur) == 0) {
        return 1;
    }

    // Streams are not allowed to point to streams (at least not now)
    if (cur->type == CMD_TYPE_STREAM) {
        return -1;
    }

    // RX are not allowed to point to streams (at least not now)
    if (cur->type == CMD_TYPE_RX) {
        return -1;
    }

    // Try see if we match a named stream
    for (i = 0; i < idx; i++) {
        if (cmds[i].type != CMD_TYPE_STREAM)
            continue;

        if (!cmds[i].stream_name)
            continue;

        if (strcmp(cmds[i].stream_name, cur->name) != 0)
            continue;

        //po("matching stream of length: %d\n", cmds[i].stream_cnt);
        if (idx + cmds[i].stream_cnt >= length) {
            po("ERROR: Running out of cmd buffers! (%d >= %d)\n",
               idx + cmds[i].stream_cnt, length);
            return -1;
        }

        free(cur->name);
        cur->name = 0;

        for (j = 0; j < cmds[i].stream_cnt; ++j) {
            if (j > 0) {
                memcpy(&cmds[idx + j], &cmds[idx], sizeof(cmds[0]));

                if (cmds[idx].arg0)
                    cmds[idx + j].arg0 = strdup(cmds[idx].arg0);
            }

            cmds[idx + j].name = strdup(cmds[i + j].name);
            cmds[idx + j].stream_name = strdup(cmds[i + j].stream_name);
            cmds[idx + j].stream_ridx = cmds[i + j].stream_ridx;
            cmds[idx + j].stream_cnt = cmds[i + j].stream_cnt;
            cmds[idx + j].frame = frame_clone(cmds[i + j].frame);
            cmds[idx + j].frame_buf = bclone(cmds[i + j].frame_buf);
            cmds[idx + j].frame_mask_buf = bclone(cmds[i + j].frame_mask_buf);

            cmds[idx + j].repeat = cmds[idx + j].repeat * cmds[idx + j].stream_cnt;
            cmds[idx + j].repeat_left = cmds[idx + j].repeat;
        }
        return cmds[i].stream_cnt;
    }

    return -1;
}

int argc_cmds(int argc, const char *argv[]) {
    struct timeval tv_now, tv_left, tv_begin, tv_end;

    int res, j, i = 0, cmd_idx = 0;
#define CMDS_CNT 1024
    cmd_t cmds[CMDS_CNT] = {};
    cmd_t *stream_start = 0;

    while (i < argc && cmd_idx < CMDS_CNT) {
        res = 0;

        //po("%d, %d cmd[%d] %s\n", __LINE__, i, cmd_idx, argv[i]);
        if (stream_start) {
            //po("%d, %d cmd[%d] %s\n", __LINE__, i, cmd_idx, argv[i]);
            res = argc_stream(argc - i, argv + i, stream_start, &cmds[cmd_idx]);
            if (res > 0) {
                stream_start->stream_cnt++;
                cmds[cmd_idx].stream_cnt = stream_start->stream_cnt;

                cmd_t *itr = stream_start;
                while (itr != &cmds[cmd_idx]) {
                    itr->stream_cnt = stream_start->stream_cnt;
                    itr->stream_ridx++;
                    //po("%d, %s/%s(%d)\n", __LINE__, itr->arg0, itr->name, itr->stream_ridx);
                    itr++;
                }
            } else {
                //po("end of stream\n");
                stream_start = 0;
            }
        }

        //po("%d, %d cmd[%d] %s\n", __LINE__, i, cmd_idx, argv[i]);
        if (res <= 0) {
            //po("%d, %d cmd[%d] %s\n", __LINE__, i, cmd_idx, argv[i]);
            res = argc_cmd(argc - i, argv + i, &cmds[cmd_idx]);
        }

        if (res > 0) {
            if (!stream_start && cmds[cmd_idx].type == CMD_TYPE_STREAM) {
                stream_start = &cmds[cmd_idx];
                //po("Start of stream\n");
            }
            //po("i=%d, res=%d\n", i, res);
            i += res;

            res = expand_name_stream(cmds, cmd_idx, CMDS_CNT);
            if (res > 0) {
                cmd_idx += res;
            } else {
                po("Error: invalid name: %s\n", cmds[cmd_idx].name);
                break;
            }

        } else if (res == 0) {
            break;
        } else {
            return -1;
        }
    }

    if (i != argc) {
        po("Parse error! %d %d %d\n", i, argc, cmd_idx);
        po("ARGS:\n");
        for (j = 0; j < argc; j++) {
            po("%2d  %s", j, argv[j]);
            if (j == i) {
                po("  <------ UNEXPECTED\n");
            } else {
                po("\n");
            }
        }

        for (i = 0; i < cmd_idx; ++i) {
            cmd_destruct(&cmds[i]);
        }
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

    while ((opt = getopt(argc, (char * const*)argv, "vht:c:")) != -1) {
        switch (opt) {
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

    return argc_cmds(argc - optind, argv + optind);
}

