#define _GNU_SOURCE
#include "ef.h"

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
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

int raw_socket(const char *name) {
    int i, s, res, val, ifidx;
    struct sockaddr_ll sa = {};
    struct packet_mreq mr = {};

    if (!name)
        return -1;

    s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s < 0) {
        po("%s:%d socket error: %m\n", __FILE__, __LINE__);
        return -1;
    }

    ifidx = if_nametoindex(name);

    sa.sll_family = PF_PACKET;
    sa.sll_ifindex = if_nametoindex(name);
    sa.sll_protocol = htons(ETH_P_ALL);

    res = bind(s, (struct sockaddr*)&sa, sizeof(sa));
    if (res < 0) {
        po("%s:%d bind error: %m\n", __FILE__, __LINE__);
        close(s);
        return -1;
    }

    mr.mr_ifindex = ifidx;
    mr.mr_type = PACKET_MR_PROMISC;
    res = setsockopt(s, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));
    if (res == -1) {
        po("%s:%d Failed to set PROMISC: %m\n", __FILE__, __LINE__);
        close(s);
        return -1;
    }

    val = 1;
    setsockopt(s, SOL_PACKET, PACKET_AUXDATA, &val, sizeof(val));
    if (res == -1) {
        po("%s:%d Failed to enable AUXDATA: %m\n", __FILE__, __LINE__);
        close(s);
        return -1;
    }

    if (QDISC_BYPASS) {
        val = 1;
        if (setsockopt(s, SOL_PACKET, PACKET_QDISC_BYPASS,
                       &val, sizeof(val)) < 0) {
            po("%s:%d PACKET_QDISC_BYPASS not supported on %s: %m\n",
               __FILE__, __LINE__, name);
        }
    }

    // Make sure that the socket is empty before started.
    //
    // Warning: I have no idea why this is needed, but otherwise I see that the
    // test is failing on Ubuntu 18.04
    //
    // TODO: This does not seem to be needed, if we uses a RX ring buffer
    // instead (atleast that seems to work for libpcap)
    for (i = 0; i < 10000; ++i) {
        struct msghdr msg = { 0 };
        int res = recvmsg(s, &msg, MSG_DONTWAIT);
        if (res < 0)
            break;
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
    // po("%s at resource %d\n", resources[res_valid].cmd->arg0, res_valid);

    return 1;
}

// Returns the number of pfd entries with a non-zero events mask, or
// -1 if no resource has anything to wait for.
int pfds_fill(cmd_socket_t *resources, int res_valid, struct pollfd *pfds,
              int has_rate) {
    cmd_t *cmd_ptr;
    int i, active = 0;

    for (i = 0; i < res_valid; i++) {
        short events = 0;

        resources[i].has_rx = 0;
        resources[i].has_tx = 0;

        cmd_ptr = resources[i].cmd;
        while (cmd_ptr) {
            if (cmd_ptr->type == CMD_TYPE_RX)
                resources[i].has_rx = 1;
            if (cmd_ptr->type == CMD_TYPE_TX && cmd_ptr->done == 0)
                resources[i].has_tx = resources[i].has_tx || !has_rate || rate_can_send(cmd_ptr);
            cmd_ptr = cmd_ptr->next;
        }

        if (resources[i].has_rx)
            events |= POLLIN;
        if (resources[i].has_tx)
            events |= POLLOUT;

        pfds[i].fd = resources[i].fd;
        pfds[i].events = events;
        pfds[i].revents = 0;

        if (events)
            active++;
    }

    return active ? active : -1;
}

int send_ready_pfds(cmd_socket_t *resources, int res_valid,
                    struct pollfd *pfds) {
    int i, res, tx_done;
    cmd_t *cmd_ptr;
    buf_t *b;

    while (1) {
        tx_done = 1;
        for (i = 0; i < res_valid; i++) {
            if (!(pfds[i].revents & POLLOUT))
                continue;

            // TX the first not "done" frame.
            for (cmd_ptr = resources[i].cmd; cmd_ptr; cmd_ptr = cmd_ptr->next) {
                if (cmd_ptr->type != CMD_TYPE_TX)
                    continue;

                if (cmd_ptr->done)
                    continue;

                b = cmd_ptr->frame_buf;
                res = send(resources[i].fd, b->data, b->size, 0);
                cmd_ptr->repeat--;

                if (cmd_ptr->repeat > 0) {
                    tx_done = 0;
                }

                if ((size_t)res == b->size && cmd_ptr->repeat == 0) {
                    po("TX     %16s: ", cmd_ptr->arg0);
                    if (cmd_ptr->name) {
                        po("name %s", cmd_ptr->name);
                    } else {
                        print_hex_str(1, b->data, b->size);
                    }
                    po("\n");
                    cmd_ptr->done = 1;
                }
                break;
            }
        }
        if (tx_done > 0)
            break;
    }

    return 0;
}


int send_rate_ready_pfds(cmd_socket_t *resources, int res_valid,
                         struct pollfd *pfds) {
    int i, res;
    cmd_t *cmd_ptr;
    buf_t *b;


    for (i = 0; i < res_valid; i++) {
        if (!(pfds[i].revents & POLLOUT))
            continue;

        for (cmd_ptr = resources[i].cmd; cmd_ptr; cmd_ptr = cmd_ptr->next) {
            if (cmd_ptr->type != CMD_TYPE_TX)
                continue;

            if (cmd_ptr->done)
                continue;

            if (!rate_can_send(cmd_ptr))
                continue;

            if (MMSG_TX && cmd_ptr->mmsg) {
                // Batch up to rate_burst_available (or full burst when
                // rate is unlimited) into a single sendmmsg syscall.
                int avail = rate_burst_available(cmd_ptr);
                int sent;

                if (avail <= 0)
                    continue;
                if ((uint32_t)avail > cmd_ptr->repeat)
                    avail = cmd_ptr->repeat;

                // MSG_DONTWAIT: sendmmsg returns the number of fully-sent
                // messages (0..avail). -1 + EAGAIN/EWOULDBLOCK means none
                // could be sent without blocking; we'll come back next
                // ppoll wake. Same non-blocking property as the txring
                // kick.
                sent = sendmmsg(resources[i].fd, cmd_ptr->mmsg, avail,
                                MSG_DONTWAIT);
                if (sent < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK ||
                        errno == EINTR  || errno == ENOBUFS)
                        break;
                    pe("TX-ERR %16s: sendmmsg: %m\n", cmd_ptr->arg0);
                    cmd_ptr->done = 1;
                    resources[i].tx_err_cnt++;
                    break;
                }
                if (sent == 0)
                    break;

                rate_consume_n(cmd_ptr, sent);
                cmd_ptr->repeat -= sent;

                if (cmd_ptr->repeat == 0) {
                    b = cmd_ptr->frame_buf;
                    po("TX     %16s: ", cmd_ptr->arg0);
                    if (cmd_ptr->name) {
                        po("name %s", cmd_ptr->name);
                    } else {
                        print_hex_str(1, b->data, b->size);
                    }
                    po("\n");
                    cmd_ptr->done = 1;
                }
                break;
            }

            b = cmd_ptr->frame_buf;
            res = send(resources[i].fd, b->data, b->size, 0);
            if (res < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK ||
                    errno == EINTR  || errno == ENOBUFS)
                    break;
                pe("TX-ERR %16s: send: %m\n", cmd_ptr->arg0);
                cmd_ptr->done = 1;
                resources[i].tx_err_cnt++;
                break;
            }
            if ((size_t)res != b->size)
                break;

            rate_consume(cmd_ptr);
            cmd_ptr->repeat--;

            if (cmd_ptr->repeat == 0) {
                po("TX     %16s: ", cmd_ptr->arg0);
                if (cmd_ptr->name) {
                    po("name %s", cmd_ptr->name);
                } else {
                    print_hex_str(1, b->data, b->size);
                }
                po("\n");
                cmd_ptr->done = 1;
            }
            break;
        }
    }

    return 0;
}

int send_txring_ready_pfds(cmd_socket_t *resources, int res_valid,
                           struct pollfd *pfds) {
    cmd_t *cmd_ptr;
    buf_t *b;
    int    i;

    for (i = 0; i < res_valid; i++) {
        if (!(pfds[i].revents & POLLOUT))
            continue;

        for (cmd_ptr = resources[i].cmd; cmd_ptr; cmd_ptr = cmd_ptr->next) {
            int    submitted;
            int    budget;
            size_t in_flight;

            if (cmd_ptr->type != CMD_TYPE_TX)
                continue;
            if (cmd_ptr->done)
                continue;
            if (!cmd_ptr->txring_map)
                continue;

            // Budget uses unsigned math so rate-without-rep
            // (repeat = UINT32_MAX) does not wrap to -1.
            if (cmd_ptr->repeat > 0) {
                if (cmd_ptr->rate_pps > 0)
                    budget = rate_burst_available(cmd_ptr);
                else
                    budget = (int)cmd_ptr->txring_frame_nr;
                if (budget > 0) {
                    if ((uint32_t)budget > cmd_ptr->repeat)
                        budget = (int)cmd_ptr->repeat;
                    submitted = txring_send(cmd_ptr, resources[i].fd, budget);
                    if (submitted < 0) {
                        cmd_ptr->done = 1;
                        resources[i].tx_err_cnt++;
                        break;
                    }
                    if (submitted > 0) {
                        if (cmd_ptr->rate_pps > 0)
                            rate_consume_n(cmd_ptr, submitted);
                        cmd_ptr->repeat -= (uint32_t)submitted;
                    }
                }
            }

            // Done only when the kernel has drained every slot we ever
            // flipped, not just when repeat hits zero. Kick periodically
            // while waiting; ppoll wakes us when something drains.
            in_flight = txring_unsent(cmd_ptr);
            if (cmd_ptr->repeat == 0) {
                if (in_flight == 0) {
                    b = cmd_ptr->frame_buf;
                    po("TX     %16s: ", cmd_ptr->arg0);
                    if (cmd_ptr->name)
                        po("name %s", cmd_ptr->name);
                    else
                        print_hex_str(1, b->data, b->size);
                    po("\n");
                    cmd_ptr->done = 1;
                } else {
                    txring_kick(resources[i].fd);
                }
            }
            break;
        }
    }

    return 0;
}

int pfds_process(cmd_socket_t *resources, int res_valid, struct pollfd *pfds,
                 int has_rate) {
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
                        po("\nRX-OK MASK:              ");
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

    if (TX_RING)
        return send_txring_ready_pfds(resources, res_valid, pfds);
    if (has_rate)
        return send_rate_ready_pfds(resources, res_valid, pfds);
    return send_ready_pfds(resources, res_valid, pfds);
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

// Returns 1 if we are past ts_end, 0 otherwise. On return ts_left is
// ts_end - ts_now, or zero if past.
static int update_timeleft(struct timespec *ts_now, struct timespec *ts_end,
                           struct timespec *ts_left)
{
    clock_gettime(CLOCK_MONOTONIC, ts_now);
    if (ts_less(ts_end, ts_now)) {
        ts_clear(ts_left);
        return 1;
    }
    ts_sub(ts_end, ts_now, ts_left);
    return 0;
}

// Sleep until the shorter of ts_pace and ts_left elapses, using
// CLOCK_MONOTONIC + TIMER_ABSTIME so we don't drift across iterations.
static void wait_for_tokens(const struct timespec *ts_pace,
                            const struct timespec *ts_left) {
    const struct timespec *ts = ts_pace;
    struct timespec ts_dl;

    if (ts_isset(ts_left) && ts_less(ts_left, ts))
        ts = ts_left;

    clock_gettime(CLOCK_MONOTONIC, &ts_dl);
    ts_add(&ts_dl, ts, &ts_dl);
    clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts_dl, NULL);
}

// True if any TX cmd still owes an explicit-rep contract.
static int explicit_rep_pending(int cnt, const cmd_t *cmds)
{
    int i;
    for (i = 0; i < cnt; i++) {
        if (cmds[i].type != CMD_TYPE_TX)
            continue;
        if (cmds[i].done)
            continue;
        if (!cmds[i].rep_explicit)
            continue;
        return 1;
    }
    return 0;
}

int exec_cmds(int cnt, cmd_t *cmds) {
    struct timespec ts_now, ts_left, ts_begin, ts_end;
    int i, res, npfds, err = 0;
    int res_valid = 0;
    int has_rate = 0;
    cmd_socket_t resources[100] = {};
    struct pollfd pfds[100];
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

    // Convert wire-rate bps to pps now that frame_buf is resolved.
    for (i = 0; i < cnt; i++) {
        if (cmds[i].rate_bps > 0 && cmds[i].frame_buf)
            cmds[i].rate_pps = rate_bps_to_pps(cmds[i].rate_bps,
                                               cmds[i].frame_buf->size);
    }

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
        resources[i].fd = raw_socket(resources[i].cmd->arg0);

        if (resources[i].fd < 0)
            return -1;
    }

    // EF_USE_SENDMMSG=1 enables the sendmmsg batched TX path, same as
    // -m. Must be evaluated before rate_init so the mmsg/miov vectors
    // get allocated for rate-limited cmds.
    if (!MMSG_TX) {
        const char *env = getenv("EF_USE_SENDMMSG");
        if (env && *env && strcmp(env, "0") != 0)
            MMSG_TX = 1;
    }

    // Initialize the rate path for any TX cmd that has explicit rate, or
    // any TX cmd at all when -m is set.
    for (i = 0; i < cnt; i++) {
        if (cmds[i].type != CMD_TYPE_TX)
            continue;
        if (cmds[i].rate_pps > 0 || MMSG_TX) {
            has_rate = 1;
            rate_init(&cmds[i]);
        }
    }

    // EF_TX_RING=1 enables PACKET_TX_RING, same as -r. Off by default;
    // there is no auto-pick based on rep count.
    if (!TX_RING) {
        const char *env = getenv("EF_TX_RING");
        if (env && *env && strcmp(env, "0") != 0)
            TX_RING = 1;
    }

    if (TX_RING) {
        for (i = 0; i < res_valid; i++) {
            cmd_t *cp;
            for (cp = resources[i].cmd; cp; cp = cp->next) {
                if (cp->type != CMD_TYPE_TX)
                    continue;
                if (txring_init(cp, resources[i].fd) < 0)
                    return -1;
            }
        }
    }

    ts_clear(&ts_now);
    ts_clear(&ts_end);
    ts_clear(&ts_left);
    ts_clear(&ts_begin);

    ts_left.tv_sec  = TIME_OUT_MS / 1000;
    ts_left.tv_nsec = (long)(TIME_OUT_MS % 1000) * 1000000L;

    clock_gettime(CLOCK_MONOTONIC, &ts_begin);
    ts_add(&ts_begin, &ts_left, &ts_end);
    int tx_pending = 0;
    while (1) {
        struct timespec ts_pace;
        ts_clear(&ts_pace);

        if (has_rate) {
            tx_pending = rate_refill_cmds(cnt, cmds, &ts_pace);
            if (!tx_pending)
                has_rate = 0; // fall back to non-ratelimited logic
        }

        npfds = pfds_fill(resources, res_valid, pfds, has_rate);
        if (npfds < 0) {
            if (!tx_pending)
                break;
            wait_for_tokens(&ts_pace, &ts_left);
            if (update_timeleft(&ts_now, &ts_end, &ts_left)) {
                // -t is a hard cap unless we still owe explicit-rep frames.
                if (!explicit_rep_pending(cnt, cmds))
                    break;
            }
            continue;
        }

        struct timespec ts_to;
        if (ts_isset(&ts_pace)) {
            ts_to = ts_pace;
            if (ts_isset(&ts_left) && ts_less(&ts_left, &ts_to))
                ts_to = ts_left;
        } else if (ts_isset(&ts_left)) {
            ts_to = ts_left;
        } else {
            ts_to.tv_sec  = 0;
            ts_to.tv_nsec = 250000;
        }

        res = ppoll(pfds, res_valid, &ts_to, NULL);
        if (update_timeleft(&ts_now, &ts_end, &ts_left)) {
            if (!explicit_rep_pending(cnt, cmds))
                break;
        }

        if (res == 0) {
            if (tx_pending || explicit_rep_pending(cnt, cmds))
                continue;
            break;
        } else if (res < 0) {
            break;
        }

        pfds_process(resources, res_valid, pfds, has_rate);
    }

    // close resources. munmap any TX rings before closing the socket
    // since the mapping is owned by the socket lifetime.
    if (TX_RING) {
        for (i = 0; i < res_valid; i++) {
            cmd_t *cp;
            for (cp = resources[i].cmd; cp; cp = cp->next)
                if (cp->type == CMD_TYPE_TX)
                    txring_close(cp);
        }
    }
    for (i = 0; i < res_valid; i++) {
        if (resources[i].fd >= 0) {
            close(resources[i].fd);
            resources[i].fd = -1;
        }
    }

    // check results
    for (i = 0; i < res_valid; i++) {
        err += resources[i].rx_err_cnt;
        err += resources[i].tx_err_cnt;

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
