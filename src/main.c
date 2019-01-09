#include "ef.h"

#include <stdio.h>

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
        res = hdr_parse_fields(h, argc - i, argv + i);
        if (res < 0) {
            printf("%s:%d Error parsing fields\n", __FILE__, __LINE__);
            return -1;
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

int argc_cmd(int argc, const char *argv[], cmd_t *c) {
    int i = 0, res;

    if (i >= argc)
        return 0;

    //printf("%d, i=%d/%d %s\n", __LINE__, i, argc, argv[i]);

    if (strcmp(argv[i], "name") == 0) {
        c->type = CMD_TYPE_NAME;
    } else if (strcmp(argv[i], "pcap") == 0) {
        c->type = CMD_TYPE_PCAP;
    } else if (strcmp(argv[i], "hexstr") == 0) {
        c->type = CMD_TYPE_HEX;
    } else if (strcmp(argv[i], "rx") == 0) {
        c->type = CMD_TYPE_RX;
    } else if (strcmp(argv[i], "tx") == 0) {
        c->type = CMD_TYPE_TX;
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
        return 0;
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
        //printf("%d i: %d\n", __LINE__, i);
        res = argc_cmd(argc - i, argv + i, &cmds[cmd_idx]);
        //printf("%d res: %d\n", __LINE__, res);
        if (res > 0) {
            i += res;
            cmd_idx ++;
        } else {
            break;
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

int main(int argc, const char *argv[]) {
    return argc_cmds(argc - 1, argv + 1);
}

