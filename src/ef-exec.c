#include "ef.h"

#include <stdio.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <pcap/pcap.h>
#include <assert.h>

#ifndef MAX
#define MAX(a, b) (a > b ? a : b)
#endif

int raw_socket(const char *name) {
    int s, res;
    struct sockaddr_ll sa = {};

    if (!name)
        return -1;

    s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s < 0) {
        printf("%s:%d socket error: %m\n", __FILE__, __LINE__);
        return -1;
    }

    sa.sll_family = PF_PACKET;
    sa.sll_ifindex = if_nametoindex(name);
    sa.sll_protocol = htons(ETH_P_ALL);

    res = bind(s, (struct sockaddr*)&sa, sizeof(sa));
    if (res < 0) {
        printf("%s:%d bind error: %m\n", __FILE__, __LINE__);
        close(s);
        return -1;
    }

    return s;
}

int add_cmd_to_resource(cmd_t *c, int res_max, int res_valid,
                        cmd_socket_t *resources) {

    int i;
    cmd_t *cmd_ptr;

    switch (c->type) {
        case CMD_TYPE_RX:
        case CMD_TYPE_TX:
            break;
        default:
            return -1;
    }

    for (i = 0; i < res_valid; ++i) {
        if (!resources[i].cmd)
            continue;

        if (strcmp(c->arg0, resources[i].cmd->arg0) != 0)
            continue;

        // we have a match - append it to the list
        cmd_ptr = resources[i].cmd;
        while (cmd_ptr->next)
            cmd_ptr = cmd_ptr->next;
        cmd_ptr->next = c;

        return 0;
    }

    // No match, create a new entry
    assert(res_valid < res_max);
    resources[res_valid].cmd = c;
    resources[res_valid].fd = -1;
    // printf("%s at resource %d\n", resources[res_valid].cmd->arg0, res_valid);

    return 1;
}

int rfds_wfds_fill(cmd_socket_t *resources, int res_valid, fd_set *rfds,
                   fd_set *wfds) {
    cmd_t *cmd_ptr;
    int i, fd_set_cnt, fd_max;

    fd_max = 0;
    fd_set_cnt = 0;

    FD_ZERO(rfds);
    FD_ZERO(wfds);

    for (i = 0; i < res_valid; i++) {
        resources[i].has_rx = 0;
        resources[i].has_tx = 0;

        cmd_ptr = resources[i].cmd;
        while (cmd_ptr) {
            // We must listen even if done, as we need to confirm that no other
            // frames are receiwed
            if (cmd_ptr->type == CMD_TYPE_RX)
                resources[i].has_rx = 1;

            // Only TX is not done
            if (cmd_ptr->type == CMD_TYPE_TX && cmd_ptr->done == 0)
                resources[i].has_tx = 1;

            cmd_ptr = cmd_ptr->next;
        }

        if (resources[i].has_rx) {
            FD_SET(resources[i].fd, rfds);
            fd_max = MAX(resources[i].fd, fd_max);
            fd_set_cnt++;
        }

        if (resources[i].has_tx) {
            FD_SET(resources[i].fd, wfds);
            fd_max = MAX(resources[i].fd, fd_max);
            fd_set_cnt++;
        }
    }

    if (fd_set_cnt)
        return fd_max;

    return -1;
}

int rfds_wfds_process(cmd_socket_t *resources, int res_valid, fd_set *rfds,
                      fd_set *wfds) {
    int i, res, match;
    buf_t *b;
    cmd_t *cmd_ptr;

    for (i = 0; i < res_valid; i++) {
        if (!FD_ISSET(resources[i].fd, rfds))
            continue;

        // read the frame, and try to match it
        b = balloc(32 * 1024);
        res = recv(resources[i].fd, b->data, b->size, 0);
        if (res > 0) {
            b->size = res;

            // Try to match the frame agains expected frames
            match = 0;
            for (cmd_ptr = resources[i].cmd; cmd_ptr; cmd_ptr = cmd_ptr->next) {

                if (!cmd_ptr->frame_buf)
                    continue;

                if (cmd_ptr->done)
                    continue;

                if (bequal(b, cmd_ptr->frame_buf)) {
                    match = 1;
                    cmd_ptr->done = 1;
                    break;
                }
            }

            if (match) {
                dprintf(1, "RX-OK  %16s: ", resources[i].cmd->arg0);
                if (resources[i].cmd->name) {
                    dprintf(1, "name %s", resources[i].cmd->name);
                } else {
                    print_hex_str(1, b->data, res);
                }
                dprintf(1, "\n");
            } else {
                resources[i].rx_err_cnt ++;
                dprintf(2, "RX-ERR %16s: ", resources[i].cmd->arg0);
                print_hex_str(2, b->data, res);
                dprintf(2, "\n");
            }

        }

        bfree(b);
    }

    for (i = 0; i < res_valid; i++) {
        if (!FD_ISSET(resources[i].fd, wfds))
            continue;

        // TX the first not "done" frame.
        for (cmd_ptr = resources[i].cmd; cmd_ptr; cmd_ptr = cmd_ptr->next) {
            if (cmd_ptr->type != CMD_TYPE_TX)
                continue;

            if (cmd_ptr->done)
                continue;

            b = cmd_ptr->frame_buf;
            res = send(resources[i].fd, b->data, b->size, 0);
            if (res == b->size) {
                dprintf(1, "TX     %16s: ", cmd_ptr->arg0);
                if (cmd_ptr->name) {
                    dprintf(1, "name %s", cmd_ptr->name);
                } else {
                    print_hex_str(1, b->data, b->size);
                }
                dprintf(1, "\n");

                cmd_ptr->done = 1;
            }

            break;
        }
    }

    return 0;
}

buf_t *frame_by_name(const char *name, int cnt, cmd_t *cmds) {
    int i;

    for (i = 0; i < cnt; i++) {
        if (cmds[i].type != CMD_TYPE_NAME)
            continue;

        if (!cmds[i].frame_buf || !cmds[i].name)
            continue;

        return bclone(cmds[i].frame_buf);
    }

    return 0;
}

int pcap_append(cmd_t *c) {
    struct pcap_pkthdr pkt;
    struct stat statbuf;

    pcap_t *pcap;
    pcap_dumper_t *pcapfile;

    pcap = pcap_open_dead(DLT_EN10MB, 65535);
    if (!pcap) {
        fprintf(stderr, "Error from pcap_open_dead(): %s\n", pcap_geterr(pcap));
        return -1;
    }

    if (stat(c->arg0, &statbuf) == 0) {
        pcapfile = pcap_dump_open_append(pcap, c->arg0);
    } else {
        pcapfile = pcap_dump_open(pcap, c->arg0);
    }

    if (!pcapfile) {
        fprintf(stderr, "Error from pcap_dump_open(): %s\n", pcap_geterr(pcap));
        return -1;
    }

    memset(&pkt, 0, sizeof(pkt));
    pkt.caplen = c->frame_buf->size;
    pkt.len = c->frame_buf->size;
    pcap_dump((u_char *)pcapfile, &pkt, c->frame_buf->data);

    pcap_dump_close(pcapfile);
    pcap_close(pcap);

    return 0;
}

int exec_cmds(int cnt, cmd_t *cmds) {
    struct timeval tv;
    int i, res, fd_max, err = 0;
    int res_valid = 0;
    cmd_socket_t resources[100] = {};
    fd_set rfds, wfds;
    cmd_t *cmd_ptr;

    // Print inventory of named frames
    for (i = 0; i < cnt; i++) {
        if (cmds[i].type != CMD_TYPE_NAME)
            continue;

        if (cmds[i].frame_buf && cmds[i].name) {
            dprintf(1, "NAME:  %16s: ", cmds[i].name);
            print_hex_str(1, cmds[i].frame_buf->data, cmds[i].frame_buf->size);
            dprintf(1, "\n");
        }
    }

    // Pair named frames
    for (i = 0; i < cnt; i++) {
        if (cmds[i].type == CMD_TYPE_NAME)
            continue;

        if (!cmds[i].name)
            continue;

        if (cmds[i].frame_buf)
            continue;

        cmds[i].frame_buf = frame_by_name(cmds[i].name, cnt, cmds);
        if (!cmds[i].frame_buf) {
            dprintf(2, "No frame in inventory called %s\n", cmds[i].name);
            err ++;
        }
    }

    if (err)
        return err;

    for (i = 0; i < cnt; i++) {
        if (cmds[i].type != CMD_TYPE_PCAP)
            continue;

        pcap_append(&cmds[i]);
    }

    // Handle HEX strings
    for (i = 0; i < cnt; i++) {
        if (cmds[i].type != CMD_TYPE_HEX)
            continue;

        if (cmds[i].frame_buf) {
            print_hex_str(1, cmds[i].frame_buf->data, cmds[i].frame_buf->size);
            dprintf(1, "\n");
        }
    }

    // Handle all PCAP


    // Map all commands to resources
    for (i = 0; i < cnt; i++) {
        res = add_cmd_to_resource(&cmds[i], 100, res_valid, resources);
        if (res > 0)
            res_valid += res;
    }

    // Open all resources
    for (i = 0; i < res_valid; i++) {
        resources[i].fd = raw_socket(resources[i].cmd->arg0);

        if (resources[i].fd < 0)
            return -1;
    }

    // TODO, hard-coded
    tv.tv_sec = 0;
    tv.tv_usec = 100000;

    while (1) {
        fd_max = rfds_wfds_fill(resources, res_valid, &rfds, &wfds);
        if (fd_max < 0) {
            break;
        }

        res = select(fd_max + 1, &rfds, &wfds, 0, &tv);
        if (res == 0) {
            break;
        } else if (res < 0) {
            break;
        }

        rfds_wfds_process(resources, res_valid, &rfds, &wfds);
    }

    // close resources
    for (i = 0; i < res_valid; i++) {
        if (resources[i].fd >= 0) {
            close(resources[i].fd);
            resources[i].fd = -1;
        }
    }

    // check results
    for (i = 0; i < res_valid; i++) {
        err += resources[i].rx_err_cnt;

        for (cmd_ptr = resources[i].cmd; cmd_ptr; cmd_ptr = cmd_ptr->next) {
            if (cmd_ptr->type != CMD_TYPE_RX)
                continue;

            if (!cmd_ptr->frame_buf)
                continue;

            if (cmd_ptr->done)
                continue;

            dprintf(2, "NO-RX  %16s: ", cmd_ptr->arg0);
            print_hex_str(2, cmd_ptr->frame_buf->data,
                          cmd_ptr->frame_buf->size);
            dprintf(2, "\n");

            err++;
        }
    }

    return err;
}
