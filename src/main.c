#include "ef.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int argc_frame(int argc, const char *argv[], frame_t *f) {
    int i, j, res;
    hdr_t *h;

    frame_reset(f);

    i = 0;
    while (i < argc) {
        //printf("%d, i=%d/%d %s\n", __LINE__, i, argc, argv[i]);

        if (strcmp(argv[i], "help") == 0) {
            printf("Specify a frame by using one or more of the following headers:\n");
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
            //printf("ERROR: Invalid parameter: %s\n", argv[i]);
            //return -1;
            return i;
        }

        h = frame_clone_and_push_hdr(f, h);
        if (!h) {
            printf("ERROR: frame_clone_and_push_hdr() failed\n");
            return -1;
        }

        //printf("Parsing hdr: %s: %p\n", h->name, h);
        //printf("%d, i=%d/%d %s\n", __LINE__, i, argc, argv[i]);
        res = h->parser(h, argc - i, argv + i);
        if (res < 0) {
            return res;
        }

        i += res;
        //printf("%d, i=%d/%d %s\n", __LINE__, i, argc, argv[i]);
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

    memset(c, 0, sizeof(*c));
}


void print_help() {
    printf("Usage: ef [options] <command> args [<command> args]...\n");
    printf("\n");
    printf("The ef (easy frame) tool allow to easily transmit frames, and\n");
    printf("optionally specify what frames it expect to receive.\n");
    printf("\n");
    printf("Options:\n");
    printf("  -h                    Top level help message.\n");
    printf("  -t <timeout-in-ms>    When listening on an interface (rx),\n");
    printf("                        the tool will always listen during the\n");
    printf("                        entire timeout period. This is needed,\n");
    printf("                        as we must also check that no frames\n");
    printf("                        are received during the test.\n");
    printf("                        Default is 100ms.\n");
    printf("\n");
    printf("Valid commands:\n");
    printf("  tx: Transmit a frame on a interface. Syntax:\n");
    printf("  tx <interface> FRAME | help\n");
    printf("\n");
    printf("  rx: Specify a frame which is expected to be received. If no \n");
    printf("      frame is specified, then the expectation is that no\n");
    printf("      frames are received on the interface. Syntax:\n");
    printf("  rx <interface> [FRAME] | help\n");
    printf("\n");
    printf("  hex: Print a frame on stdout as a hex string. Syntax:\n");
    printf("  hex FRAME\n");
    printf("\n");
    printf("  name: Specify a frame, and provide a name (alias) for it.\n");
    printf("        This alias can be used other places instead of the\n");
    printf("        complete frame specification. Syntax:\n");
    printf("  name <name> FRAME-SPEC | help\n");
    printf("\n");
    printf("  pcap: Write a frame to a pcap file (appending if the file\n");
    printf("  exists already). Syntax:\n");
    printf("  pcap <file> FRAME | help\n");
    printf("\n");
    printf("Where FRAME is either a frame specification of a named frame.\n");
    printf("Syntax: FRAME ::= FRAME-SPEC | name <name>\n");
    printf("\n");
    printf("FRAME-SPEC is a textual specification of a frame.\n");
    printf("Syntax: FRAME-SPEC ::= [HDR-NAME [<HDR-FIELD> <HDR-FIELD-VAL>]...]...\n");
    printf("        HDR-NAME ::= eth|stag|ctag|arp|ipv4|udp\n");
    printf("\n");
    printf("Examples:\n");
    printf("  ef tx eth0 eth dmac ::1 smac ::2 stag vid 0x100 ipv4 dip 1 udp\n");
    printf("\n");
    printf("  ef name f1 eth dmac ff:ff:ff:ff:ff:ff smac ::1\\\n");
    printf("     rx eth0 name f1\\\n");
    printf("     tx eth1 name f1\n");
    printf("\n");
}

int argc_cmd(int argc, const char *argv[], cmd_t *c) {
    int i = 0, res;

    if (i >= argc)
        return 0;

    //printf("%d, i=%d/%d %s\n", __LINE__, i, argc, argv[i]);

    if (strcmp(argv[i], "name") == 0) {
        c->type = CMD_TYPE_NAME;
    } else if (strcmp(argv[i], "pcap") == 0) {
        c->type = CMD_TYPE_PCAP;
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

    //printf("%d, i=%d/%d %s\n", __LINE__, i, argc, argv[i]);
    switch (c->type) {
        case CMD_TYPE_NAME:
            c->name = strdup(argv[i]);
            i += 1;
            break;

        case CMD_TYPE_HEX: /* fallthrough */
            break;

        case CMD_TYPE_PCAP: /* fallthrough */
        case CMD_TYPE_RX: /* fallthrough */
        case CMD_TYPE_TX: /* fallthrough */
            c->arg0 = strdup(argv[i]);
            i += 1;
            break;

        default:
            ;
    }

    //printf("%d, i=%d/%d %s\n", __LINE__, i, argc, argv[i]);
    if (i + 1 < argc && strcmp(argv[i], "name") == 0 &&
        c->type != CMD_TYPE_NAME) {
        c->name = strdup(argv[i + 1]);
        i += 2;
        //printf("%d, assign name: %s\n", __LINE__, c->name);
        return i;
    }

    //printf("%d, i=%d/%d %s\n", __LINE__, i, argc, argv[i]);
    // start parsing the frame
    c->frame = frame_alloc();
    res = argc_frame(argc - i, argv + i, c->frame);

    if (res == 0 && c->type == CMD_TYPE_RX) {
        // RX can have empty frame (meaning nothing)
        frame_free(c->frame);
        c->frame = 0;
        //printf("%d, i=%d/%d %s\n", __LINE__, i, argc, argv[i]);
        return i;
    }

    if (res <= 0) {
        cmd_destruct(c);
        //printf("%d, i=%d/%d %s\n", __LINE__, i, argc, argv[i]);
        return res;
    }

    if (c->frame) {
        c->frame_buf = frame_to_buf(c->frame);
    }

    i += res;
    //printf("%d, i=%d/%d %s\n", __LINE__, i, argc, argv[i]);

    return i;
}

int argc_cmds(int argc, const char *argv[]) {
    int res, i = 0, cmd_idx = 0;
    cmd_t cmds[100] = {};

    while (i < argc && cmd_idx < 100) {
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
        printf("Parse error! %d %d %d\n", i, argc, cmd_idx);
        return -1;
    }

    res = exec_cmds(cmd_idx, cmds);

    for (i = 0; i < cmd_idx; ++i) {
        cmd_destruct(&cmds[i]);
    }

    return res;
}

int TIME_OUT_MS = 100;

int main(int argc, const char *argv[]) {
    int opt;

    while ((opt = getopt(argc, (char * const*)argv, "ht:")) != -1) {
        switch (opt) {
            case 'h':
                print_help();
                return -1;

            case 't':
                TIME_OUT_MS = atoi(optarg);
                break;

            default: /* '?' */
                print_help();
                return -1;
        }
    }

    return argc_cmds(argc - optind, argv + optind);
}

