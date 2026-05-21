#include "ef.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/ethtool.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>

// PACKET_TX_RING TPACKET_V2 slot layout (kernel reads tx data from here):
//   [ tpacket2_hdr | pad | frame data ]
//                         ^ TPACKET_ALIGN(sizeof(tpacket2_hdr))
// TPACKET2_HDRLEN includes sizeof(sockaddr_ll) which is only used on the
// RX path; on TX the kernel reads frame data at hdrlen - sizeof(sockaddr_ll).
#define FRAME_DATA_OFF       (TPACKET2_HDRLEN - sizeof(struct sockaddr_ll))
#define TXRING_TARGET_FRAMES 1024  // fallback when ETHTOOL_GRINGPARAM fails

static inline struct tpacket2_hdr *slot_hdr(cmd_t *c, size_t idx) {
    return (struct tpacket2_hdr *)((char *)c->txring_map +
                                   idx * c->txring_frame_size);
}

static size_t next_pow2(size_t x) {
    size_t p = 64;
    while (p < x)
        p <<= 1;
    return p;
}

static size_t nic_tx_ring_pending(int fd, const char *ifname) {
    struct ethtool_ringparam erp = {};
    struct ifreq             ifr = {};

    erp.cmd = ETHTOOL_GRINGPARAM;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_data = (caddr_t)&erp;
    if (ioctl(fd, SIOCETHTOOL, &ifr) < 0)
        return 0;
    return erp.tx_pending;
}

static size_t target_frames_from_env(size_t fallback) {
    const char *env = getenv("EF_TXRING_FRAMES");
    long        n;

    if (!env || !*env)
        return fallback;
    n = strtol(env, NULL, 10);
    if (n < 2 || n > (1L << 20) || (n & (n - 1)) != 0) {
        pe("EF_TXRING_FRAMES=%s invalid (need power of 2 in [2, 1M]); using %zu\n",
           env, fallback);
        return fallback;
    }
    return (size_t)n;
}

int txring_init(cmd_t *c, int fd) {
    struct tpacket_req req = {};
    size_t             frame_size, block_size, frames_per_block, block_nr;
    size_t             target_frames, nic_depth;
    long               page_size;
    int                ver;
    size_t             i;

    if (!c->frame_buf)
        return -1;

    // Match the NIC tx ring depth (rounded to a power of two for
    // PACKET_TX_RING). Going larger just shifts the queue into the
    // qdisc; going smaller starves the kernel pipeline.
    nic_depth     = nic_tx_ring_pending(fd, c->arg0);
    target_frames = nic_depth < 2 ? TXRING_TARGET_FRAMES
                                  : next_pow2(nic_depth);
    target_frames = target_frames_from_env(target_frames);

    frame_size = next_pow2(FRAME_DATA_OFF + c->frame_buf->size);

    // block_size is a multiple of both frame_size and page_size. For
    // frame_size <= page_size both are powers of two so page_size
    // works; for jumbos use frame_size directly.
    page_size  = sysconf(_SC_PAGESIZE);
    block_size = frame_size > (size_t)page_size ? frame_size
                                                : (size_t)page_size;
    frames_per_block = block_size / frame_size;
    block_nr         = (target_frames + frames_per_block - 1) /
                       frames_per_block;

    ver = TPACKET_V2;
    if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver)) < 0) {
        pe("txring: PACKET_VERSION: %m\n");
        return -1;
    }

    req.tp_block_size = block_size;
    req.tp_block_nr   = block_nr;
    req.tp_frame_size = frame_size;
    req.tp_frame_nr   = frames_per_block * block_nr;
    if (setsockopt(fd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req)) < 0) {
        pe("txring: PACKET_TX_RING (frame=%zu block=%zu nr=%u): %m\n",
           frame_size, block_size, req.tp_block_nr);
        return -1;
    }

    if ((req.tp_frame_nr & (req.tp_frame_nr - 1)) != 0) {
        pe("txring: frame_nr=%u must be a power of 2\n", req.tp_frame_nr);
        return -1;
    }

    c->txring_map_len    = (size_t)req.tp_block_size * req.tp_block_nr;
    c->txring_frame_size = req.tp_frame_size;
    c->txring_frame_nr   = req.tp_frame_nr;
    c->txring_mask       = req.tp_frame_nr - 1;
    c->txring_map = mmap(NULL, c->txring_map_len, PROT_READ | PROT_WRITE,
                         MAP_SHARED, fd, 0);
    if (c->txring_map == MAP_FAILED) {
        pe("txring: mmap: %m\n");
        c->txring_map = NULL;
        return -1;
    }

    // Prewrite the static frame into every slot; the hot path only
    // flips tp_status.
    for (i = 0; i < c->txring_frame_nr; i++) {
        struct tpacket2_hdr *h = slot_hdr(c, i);
        memcpy((char *)h + FRAME_DATA_OFF, c->frame_buf->data,
               c->frame_buf->size);
        h->tp_len = c->frame_buf->size;
    }

    c->txring_head = 0;
    return 0;
}

// Flip up to 'budget' AVAILABLE slots into SEND_REQUEST and kick the
// kernel. Returns the number flipped. qdisc-rejected slots come back
// as SEND_REQUEST so a future kick retries them.
int txring_send(cmd_t *c, int fd, int budget) {
    struct tpacket2_hdr *h;
    size_t               head, mask;
    int                  filled = 0;
    uint32_t             st;

    if (!c->txring_map || budget <= 0)
        return 0;

    head = c->txring_head;
    mask = c->txring_mask;

    // tp_status is shared with the kernel (which may run on a different
    // core), so plain loads/stores are not safe: the compiler could fuse
    // or reorder them, and without barriers a CPU could observe the new
    // status before the slot contents the kernel just wrote.
    //   ACQUIRE on the load pairs with the kernel's release when it sets
    //   AVAILABLE - guarantees that any frame metadata the kernel touched
    //   is visible to us before we read the status.
    //   RELEASE on the store pairs with the kernel's acquire when it
    //   picks up SEND_REQUEST - guarantees the prewritten frame bytes
    //   are visible to the kernel before it sees the new status.
    while (filled < budget) {
        h  = slot_hdr(c, head);
        st = __atomic_load_n(&h->tp_status, __ATOMIC_ACQUIRE);
        if (st != TP_STATUS_AVAILABLE)
            break;
        __atomic_store_n(&h->tp_status, TP_STATUS_SEND_REQUEST,
                         __ATOMIC_RELEASE);
        head = (head + 1) & mask;
        filled++;
    }

    c->txring_head = head;

    if (filled > 0) {
        int n = send(fd, NULL, 0, MSG_DONTWAIT);
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
            errno != EINTR && errno != ENOBUFS &&
            !(IGNORE_LINK_DOWN && errno == ENETDOWN)) {
            pe("TX-ERR %16s: send (txring): %m\n", c->arg0);
            return -1;
        }
    }

    return filled;
}

// Slots in SEND_REQUEST are kernel-owned (queued or retrying);
// AVAILABLE means drained.
size_t txring_unsent(const cmd_t *c) {
    struct tpacket2_hdr *h;
    size_t               i, unsent = 0;

    if (!c->txring_map)
        return 0;
    for (i = 0; i < c->txring_frame_nr; i++) {
        h = (struct tpacket2_hdr *)((char *)c->txring_map +
                                    i * c->txring_frame_size);
        if (__atomic_load_n(&h->tp_status, __ATOMIC_ACQUIRE)
            != TP_STATUS_AVAILABLE)
            unsent++;
    }
    return unsent;
}

// The kernel retries SEND_REQUEST slots only when we call send().
void txring_kick(int fd) {
    (void)send(fd, NULL, 0, MSG_DONTWAIT);
}

void txring_close(cmd_t *c) {
    size_t unsent;

    if (c->txring_map && c->txring_map != MAP_FAILED) {
        unsent = txring_unsent(c);
        if (unsent > 0)
            pe("TX-DROP %16s: %zu frames in flight at exit\n",
               c->arg0, unsent);
        munmap(c->txring_map, c->txring_map_len);
        c->txring_map = NULL;
    }
}
