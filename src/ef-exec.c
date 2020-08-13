#include "ef.h"

#include <time.h>
#include <poll.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#ifdef HAS_LIBPCAP
#include <pcap/pcap.h>
#endif
#include <assert.h>
#include <sys/time.h>

#ifndef MAX
#define MAX(a, b) (a > b ? a : b)
#endif

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

static clock_t SEND_TIME = 0;
static clock_t POLL_TIME = 0;
static const uint32_t block_size = 16 * 1024 * 1024;
static const uint32_t frame_size = 2048;
static const uint32_t block_count = 16;

static const uint32_t frame_count = (block_size * block_count) / frame_size;

int setup_ring1(int fd, tpacket_ring *ring, int direction) {
    int res;
    //int one = 1;

    memset(&ring->req, 0, sizeof(ring->req));
    ring->req.tp_block_size = block_size;
    ring->req.tp_frame_size = frame_size;
    ring->req.tp_block_nr = block_count;
    ring->req.tp_frame_nr = (block_size * block_count) / frame_size;

    res = setsockopt(fd, SOL_PACKET, direction, &ring->req, sizeof(ring->req));
    if (res == -1) {
        po("%s:%d Failed to set PACKET_?X_RING: %m\n", __FILE__, __LINE__);
        return -1;
    }

    //setsockopt(fd, SOL_PACKET, PACKET_QDISC_BYPASS, &one, sizeof(one));
    //if (res == -1) {
    //    po("%s:%d Failed to set PACKET_QDISC_BYPASS: %m\n", __FILE__, __LINE__);
    //    return -1;
    //}

    return 0;
}

int setup_ring2(int fd, tpacket_ring *ring) {
    int i;

    ring->blocks = malloc(ring->req.tp_block_nr * sizeof(*ring->blocks));
    if (!ring->blocks) {
        po("%s:%d Failed to malloc: %m\n", __FILE__, __LINE__);
        return -1;
    }

    for (i = 0; i < ring->req.tp_block_nr; ++i) {
        ring->blocks[i].iov_base = ring->map + (i * ring->req.tp_block_size);
        ring->blocks[i].iov_len = ring->req.tp_block_size;
    }

    return 0;
}

int ring_wait_for_init(tpacket_ring *ring) {
    int i, loop;

    printf("Check that ring is being initialized\n");
    for (i = 0; i < ring->req.tp_frame_nr; ++i) {
        struct tpacket3_hdr * hdr;
        hdr = ((struct tpacket3_hdr *)(ring->map + (frame_size * i)));

        loop = 1;
        do {
            switch((volatile uint32_t)hdr->tp_status) {
                case TP_STATUS_AVAILABLE:
                    loop = 0;
                    break;

                case TP_STATUS_WRONG_FORMAT:
                    printf("An error has occured during transfer\n");
                    return -1;

                default:
                    usleep(0);
                    break;
            }
        } while (loop);
    }

    printf("ring setup ok\n");
    return 0;
}


int raw_socket(cmd_socket_t *cmd_socket) {
    int s, res, val, ifidx;
    struct sockaddr_ll sa = {};
    struct packet_mreq mr = {};

    const char *name = cmd_socket->cmd->arg0;

    if (!name) {
        po("%s:%d itnerface name missing\n", __FILE__, __LINE__);
        return -1;
    }

    s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s < 0) {
        po("%s:%d socket error: %m\n", __FILE__, __LINE__);
        return -1;
    }

    val = TPACKET_V3;
    res = setsockopt(s, SOL_PACKET, PACKET_VERSION, &val, sizeof(val));
    if (res == -1) {
        po("%s:%d Failed to enable TPACKET_V3: %m\n", __FILE__, __LINE__);
        close(s);
        return -1;
    }

    setup_ring1(s, &cmd_socket->rx_ring, PACKET_RX_RING);
    setup_ring1(s, &cmd_socket->tx_ring, PACKET_TX_RING);

    cmd_socket->map = mmap(NULL, 2 * block_size * block_count,
                           PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, s,
                           0);
    if (cmd_socket->map == MAP_FAILED) {
        po("%s:%d Failed to mmap: %m\n", __FILE__, __LINE__);
        return -1;
    }

    cmd_socket->rx_ring.map = cmd_socket->map;
    cmd_socket->tx_ring.map = cmd_socket->map + (block_size * block_count);

    setup_ring2(s, &cmd_socket->rx_ring);
    setup_ring2(s, &cmd_socket->tx_ring);
    ring_wait_for_init(&cmd_socket->tx_ring);

    ifidx = if_nametoindex(name);
    mr.mr_ifindex = ifidx;
    mr.mr_type = PACKET_MR_PROMISC;
    res = setsockopt(s, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));
    if (res == -1) {
        po("%s:%d Failed to set PROMISC: %m\n", __FILE__, __LINE__);
        close(s);
        return -1;
    }

    val = 1;
    res = setsockopt(s, SOL_PACKET, PACKET_AUXDATA, &val, sizeof(val));
    if (res == -1) {
        po("%s:%d Failed to enable AUXDATA: %m\n", __FILE__, __LINE__);
        close(s);
        return -1;
    }

#if 0
    // Make sure that the socket is empty before started.
    //
    // Warning: I have no idea why this is needed, but otherwise I see that the
    // test is failing on Ubuntu 18.04
    //
    // TODO: This does not seem to be needed, if we uses a RX ring buffer
    // instead (atleast that seems to work for libpcap)
    for (int i = 0; i < 10000; ++i) {
        struct msghdr msg = { 0 };
        int res = recvmsg(s, &msg, MSG_DONTWAIT);
        if (res < 0)
            break;
    }
#endif


    sa.sll_family = PF_PACKET;
    sa.sll_ifindex = if_nametoindex(name);
    sa.sll_protocol = htons(ETH_P_ALL);

    res = bind(s, (struct sockaddr*)&sa, sizeof(sa));
    if (res < 0) {
        po("%s:%d bind error: %m\n", __FILE__, __LINE__);
        close(s);
        return -1;
    }

    cmd_socket->fd = s;
    return 0;
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
    // po("%s at resource %d\n", resources[res_valid].cmd->arg0, res_valid);

    return 1;
}

int timeval_to_ms(const struct timeval *tv) {
    return (tv->tv_sec * 1000) + (tv->tv_usec / 1000);
}

int rfds_wfds_fill(cmd_socket_t *resources, int res_valid, struct pollfd *pfd,
                   int *tx_pending) {
    cmd_t *cmd_ptr;
    int i, max_index = -1;

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

        pfd[i].events = 0;
        if (resources[i].has_rx) {
            pfd[i].events |= POLLIN;
        }

        if (resources[i].has_tx) {
            pfd[i].events |= POLLOUT;
            *tx_pending = 1;
        }

        if (resources[i].has_rx || resources[i].has_tx) {
            pfd[i].fd = resources[i].fd;
            max_index = i;
        } else {
            pfd[i].fd = -1;
        }
    }

    return max_index;
}

int rfds_wfds_process(cmd_socket_t *resources, int res_valid,
                      struct pollfd *pfds) {
    int i, res, match, old_size;
    buf_t *b;
    cmd_t *cmd_ptr;

    uint8_t cbuf[sizeof(struct cmsghdr) + sizeof(struct tpacket_auxdata) +
            sizeof(size_t)] = {};

    for (i = 0; i < res_valid; i++) {
        struct iovec iov = {};
        struct msghdr msg = {};

        if (!(pfds[i].revents & POLLIN))
            continue;

        // read the frame, and try to match it
        b = balloc(32 * 1024);

        iov.iov_base = b->data;
        iov.iov_len = b->size;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf;
        msg.msg_controllen = sizeof(cbuf);

        res = recvmsg(resources[i].fd, &msg, 0);
        if (res > 0) {
            old_size = b->size;
            b->size = res;

            // We need to get the vlan ID from AUX data
            if (msg.msg_controllen >= sizeof(struct cmsghdr) &&
                res + 4 < old_size) {
                struct cmsghdr* cmsg = (struct cmsghdr*)cbuf;

                if ((cmsg->cmsg_level == SOL_PACKET) &&
                    (cmsg->cmsg_type == PACKET_AUXDATA)) {

                    struct tpacket_auxdata* aux =
                            (struct tpacket_auxdata*)CMSG_DATA(cmsg);

                    if (aux->tp_status & TP_STATUS_VLAN_VALID) {
                        uint16_t tci = htons(aux->tp_vlan_tci);

                        // make room and re-add the vlan tag
                        memmove(b->data + 16, b->data + 12, res - 12);
#ifdef TP_STATUS_VLAN_TPID_VALID
                        uint16_t tpid = htons(aux->tp_vlan_tpid);
                        memcpy(b->data + 12, &tpid, sizeof(tpid));
#else
                        {
                            uint8_t eth_p_8021q[2] = {0x81, 0x00};
                            memcpy(b->data + 12, eth_p_8021q,
                                   sizeof(eth_p_8021q));
                        }
#endif
                        memcpy(b->data + 14, &tci, sizeof(tci));
                        b->size += 4;
                    }
                }
            }

            // Try to match the frame agains expected frames
            match = 0;
            for (cmd_ptr = resources[i].cmd; cmd_ptr; cmd_ptr = cmd_ptr->next) {

                if (!cmd_ptr->frame_buf)
                    continue;

                if (cmd_ptr->done)
                    continue;

                if (bequal_mask(b, cmd_ptr->frame_buf, cmd_ptr->frame_mask_buf,
                                cmd_ptr->frame->padding_len)) {
                    match = 1;
                    cmd_ptr->done = 1;
                    break;
                }
            }

            if (match) {
                po("RX-OK  %16s: ", cmd_ptr->arg0);
                if (cmd_ptr->name) {
                    po("name %s", cmd_ptr->name);
                } else {
                    print_hex_str(1, b->data, b->size);
                    if (cmd_ptr->frame_mask_buf) {
                        po("RX-OK MASK:              ");
                        print_hex_str(1, cmd_ptr->frame_mask_buf->data,
                                      cmd_ptr->frame_mask_buf->size);
                        po("\n");
                    }
                }
                po("\n");
            } else {
                resources[i].rx_err_cnt ++;
                pe("RX-ERR %16s: ", resources[i].cmd->arg0);
                print_hex_str(2, b->data, b->size);
                pe("\n");
            }

        }

        bfree(b);
    }

    //printf("line: %d\n", __LINE__);

    //printf("line: %d\n", __LINE__);
    for (i = 0; i < res_valid; i++) {
        //printf("line: %d\n", __LINE__);
        if (!(pfds[i].revents & POLLOUT))
            continue;

        // TX the first not "done" frame.
        for (cmd_ptr = resources[i].cmd; cmd_ptr; cmd_ptr = cmd_ptr->next) {
            //printf("line: %d\n", __LINE__);
            if (cmd_ptr->type != CMD_TYPE_TX)
                continue;

            if (cmd_ptr->done)
                continue;

            b = cmd_ptr->frame_buf;
            int ready = 0;

            if (!cmd_ptr->ring_buffer_initialized) {
                //printf("filling buffers: %d\n", __LINE__);
                int j, k;
                struct tpacket3_hdr *hdr;
                uint8_t *pdu;

                cmd_ptr->ring_buffer_initialized = 1;
                for (k = 0; k < frame_count; k++) {
                    hdr = ((struct tpacket3_hdr *)
                           (resources[i].tx_ring.map + (frame_size * k)));
                    pdu = ((uint8_t *) hdr) + (sizeof *hdr);
                    switch((volatile uint32_t)hdr->tp_status) {
                        case TP_STATUS_AVAILABLE:
                            for (j = 0; j < b->size; j++) {
                                pdu[j] = b->data[j];
                            }
                            hdr->tp_len = b->size;
                            break;

                        case TP_STATUS_WRONG_FORMAT:
                            printf("An error has occured during transfer\n");
                            break;

                        default:
                            printf("not ready\n");
                            break;
                    }
                }
            } else {
                //printf("sending frames: %d\n", __LINE__);
                // TODO, get the ring_buffer_initialized out of fast path

                int k;
                struct tpacket3_hdr *hdr;

                int limit = frame_count;
                if (limit > cmd_ptr->repeat_left) {
                    limit = cmd_ptr->repeat_left;
                }

                if (cmd_ptr->tx_ts_start == 0) {
                    cmd_ptr->tx_ts_start = clock();
                }

                for (k = 0; k < limit; k++) {
                    hdr = ((struct tpacket3_hdr *)
                           (resources[i].tx_ring.map + (frame_size * cmd_ptr->ring_idx)));

                    uint32_t status = (volatile uint32_t)hdr->tp_status;
                    if (status == TP_STATUS_AVAILABLE) {
                        hdr->tp_status = TP_STATUS_SEND_REQUEST;
                        ready++;

                        cmd_ptr->ring_idx++;
                        if (cmd_ptr->ring_idx >= frame_count)
                            cmd_ptr->ring_idx = 0;

                    } else if (status == TP_STATUS_SEND_REQUEST) {
                        //printf("send_request ring_idx=%d\n", ring_idx);
                        break;

                    } else if (status == TP_STATUS_SENDING) {
                        //printf("sending\n");
                        break;

                    } else if (status == TP_STATUS_WRONG_FORMAT) {
                        //printf("Wrong header\n");
                        break;

                    } else if (status == TP_STATUS_WRONG_FORMAT) {
                        //printf("unknown %d\n", hdr->tp_status);
                        break;
                    }
                }

                //usleep(500000);
                {
                    clock_t a = clock();
                    res = send(resources[i].fd, 0, 0, MSG_DONTWAIT);
                    clock_t b = clock();
                    SEND_TIME += b - a;
                }
                //res = send(resources[i].fd, 0, 0, 0);

                if (res < 0) {
                    //printf("ERR: %d / %m (%d)\n", res, errno);
                    //usleep(100000);
                }

                //int no_frames = res / b->size;
                int no_frames = ready;
                if (no_frames > cmd_ptr->repeat_left) {
                    cmd_ptr->repeat_left = 0;
                    printf("no match: %d %d\n", no_frames, cmd_ptr->repeat_left);
                } else {
                    cmd_ptr->repeat_left -= no_frames;
                }

                //printf("Send2 return: no-frames=%8d ready=%8d left=%8d res=%d\n", no_frames, ready, cmd_ptr->repeat_left, res);

                if (res == 0 && cmd_ptr->repeat_left == 0) {
                    cmd_ptr->tx_ts_end = clock();

                    double bits_per_frame = (cmd_ptr->frame_buf->size + 20) * 8;
                    double t_us = (double)((cmd_ptr->tx_ts_end - cmd_ptr->tx_ts_start) / (CLOCKS_PER_SEC / 1000000));
                    double mbps = ((double)cmd_ptr->repeat * bits_per_frame) / t_us;
                    double mfps = (double)cmd_ptr->repeat / t_us;

                    po("TX     %16s: ", cmd_ptr->arg0);
                    if (cmd_ptr->name) {
                        po("name %s", cmd_ptr->name);
                    } else {
                        print_hex_str(1, b->data, b->size);
                    }
                    po(" time=%8.0f mbps=%3.3f mfsp=%3.3f\n", t_us, mbps, mfps);
                    cmd_ptr->done = 1;
                }

            }

            //printf("out-of-loop\n");

            // Only process 1 command per resource
            break;
        }
    }

    return 0;
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

#ifdef HAS_LIBPCAP
int pcap_append(cmd_t *c) {
    struct pcap_pkthdr pkt;
    struct stat statbuf;

    pcap_t *pcap;
    pcap_dumper_t *pcapfile;

    pcap = pcap_open_dead(DLT_EN10MB, 65535);
    if (!pcap) {
        pe("Error from pcap_open_dead(): %s\n", pcap_geterr(pcap));
        return -1;
    }

    if (stat(c->arg0, &statbuf) == 0) {
        pcapfile = pcap_dump_open_append(pcap, c->arg0);
    } else {
        pcapfile = pcap_dump_open(pcap, c->arg0);
    }

    if (!pcapfile) {
        pe("Error from pcap_dump_open(): %s\n", pcap_geterr(pcap));
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
#endif

int exec_cmds(int cnt, cmd_t *cmds) {
    struct timeval tv_now, tv_left, tv_begin, tv_end;
    int i, res, idx_max, err = 0, tx_pending = 0;
    int res_valid = 0;
    cmd_socket_t resources[100] = {};
    struct pollfd pfds[100] = {};
    cmd_t *cmd_ptr;

    // Print inventory of named frames
    for (i = 0; i < cnt; i++) {
        if (cmds[i].type != CMD_TYPE_NAME)
            continue;

        if (cmds[i].frame_buf && cmds[i].name) {
            po("NAME:  %16s: ", cmds[i].name);
            print_hex_str(1, cmds[i].frame_buf->data, cmds[i].frame_buf->size);
            po("\n");

            if (cmds[i].frame_mask_buf) {
                po("NAME MASK:               ");
                print_hex_str(1, cmds[i].frame_mask_buf->data,
                              cmds[i].frame_mask_buf->size);
                po("\n");
            }
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

        if (copy_cmd_by_name(cmds[i].name, cnt, cmds, &cmds[i]) != 0) {
            pe("No frame in inventory called %s\n", cmds[i].name);
            err ++;
        }
    }

    if (err)
        return err;

#ifdef HAS_LIBPCAP
    for (i = 0; i < cnt; i++) {
        if (cmds[i].type != CMD_TYPE_PCAP)
            continue;

        pcap_append(&cmds[i]);
    }
#endif

    // Handle HEX strings
    for (i = 0; i < cnt; i++) {
        if (cmds[i].type != CMD_TYPE_HEX)
            continue;

        if (cmds[i].frame_mask_buf && cmds[i].frame_buf) {
            po("DATA: ");
            print_hex_str(1, cmds[i].frame_buf->data, cmds[i].frame_buf->size);
            po("\nMASK: ");
            print_hex_str(1, cmds[i].frame_mask_buf->data,
                          cmds[i].frame_buf->size);
            po("\n");
        } else if (cmds[i].frame_buf) {
            print_hex_str(1, cmds[i].frame_buf->data, cmds[i].frame_buf->size);
            po("\n");
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
        raw_socket(&resources[i]);
        if (resources[i].fd < 0) {
            printf("Failed to open raw socket for %i/%s\n", i,
                   resources[i].cmd->arg0);
            return -1;
        }
    }

    int timer_started = 0;
    timerclear(&tv_now);
    timerclear(&tv_end);
    timerclear(&tv_left);
    timerclear(&tv_begin);
    tv_left.tv_sec = TIME_OUT_MS / 1000;
    tv_left.tv_usec = (TIME_OUT_MS - (tv_left.tv_sec * 1000)) * 1000;

    clock_t before = clock();
    while (1) {
        tx_pending = 0;
        idx_max = rfds_wfds_fill(resources, res_valid, pfds, &tx_pending);
        //printf("line: %d idx_max = %d, tx_pending = %d\n", __LINE__, idx_max,
        //       tx_pending);
        if (idx_max < 0) {
            break;
        }

        if (tx_pending) {
            clock_t a = clock();
            res = poll(pfds, idx_max + 1, -1);
            clock_t b = clock();
            POLL_TIME += b - a;
        } else {
            if (!timer_started) {
                gettimeofday(&tv_begin, 0);
                timeradd(&tv_begin, &tv_left, &tv_end);
                timer_started = 1;
            }

            clock_t a = clock();
            res = poll(pfds, idx_max + 1, timeval_to_ms(&tv_left));
            clock_t b = clock();
            POLL_TIME += b - a;

            gettimeofday(&tv_now, 0);
            if (timercmp(&tv_now, &tv_end, >)) {
                //printf("time is out\n");
                break;
            }
            timersub(&tv_end, &tv_now, &tv_left);
        }

        //printf("poll res: %d\n", res);


        if (res == 0) {
            //printf("no file descriptors ready\n");
            break;
        } else if (res < 0) {
            break;
        }

        rfds_wfds_process(resources, res_valid, pfds);
    }
    clock_t after = clock();

    double t_total, r_other, r_send, r_poll;
    t_total = after - before;
    r_send = SEND_TIME / t_total;
    r_poll = POLL_TIME / t_total;
    r_other = 1 - r_send - r_poll;

    printf("Total=%ld send=%ld poll=%ld send+poll=%ld ratio(other/send/poll)=%2.2f/%2.2f/%2.2f\n",
           after-before, SEND_TIME, POLL_TIME, SEND_TIME + POLL_TIME,
           r_other, r_send, r_poll);

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

            pe("NO-RX  %16s: ", cmd_ptr->arg0);
            if (cmd_ptr->name) {
                pe("name %s", cmd_ptr->name);
            } else {
                print_hex_str(2, cmd_ptr->frame_buf->data,
                              cmd_ptr->frame_buf->size);
                pe("\n");
                if (cmd_ptr->frame_mask_buf) {
                    pe("NO-RX MASK:              ");
                    print_hex_str(2, cmd_ptr->frame_mask_buf->data,
                                  cmd_ptr->frame_mask_buf->size);
                    pe("\n");
                }
            }

            pe("\n");

            err++;
        }
    }

    return err;
}
