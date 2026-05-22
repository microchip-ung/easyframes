// XDP_PGOFF_TX_RING (0x80000000) and XDP_UMEM_PGOFF_COMPLETION_RING
// (0x180000000) overflow 32-bit off_t. Force 64-bit mmap offsets so
// 32-bit builds (BeagleBone armv7l) don't truncate them. Must come
// before any system header.
#define _FILE_OFFSET_BITS 64

#include "ef.h"
#include "ef-xdp.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/rtnetlink.h>

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

// Older kernel headers (pre 5.18) don't define BPF_F_XDP_HAS_FRAGS.
// load_xdp_pass falls back to loading without the flag if the first
// attempt fails, so a bogus value is safe at compile time.
#ifndef BPF_F_XDP_HAS_FRAGS
#define BPF_F_XDP_HAS_FRAGS (1U << 5)
#endif

// Ring depth for both TX and completion. 2048 is comfortably above
// what most NICs surface to a single queue and large enough that the
// fill loop amortizes the producer-store + kick across many slots.
#define EF_XDP_RING_SIZE   2048

// All TX descriptors point at UMEM slot 0 (ef tx commands have one
// immutable frame), so the UMEM only needs enough slots that the
// kernel accepts the bind. The XDP_UMEM_REG validation requires
// len >= chunk_size, plus a couple slots of headroom for the kernel's
// bookkeeping.
#define EF_XDP_NUM_FRAMES  64

// XDP_UMEM_MIN_CHUNK_SIZE in the kernel.
#define EF_XDP_MIN_CHUNK   2048

typedef struct {
    uint32_t *producer;
    uint32_t *consumer;
    uint32_t *flags;
    void     *descs;
    void     *map;
    size_t    map_size;
    uint32_t  size;
    uint32_t  mask;
} ef_xdp_ring_t;

struct ef_xdp {
    int            fd;          // AF_XDP socket
    int            ifindex;
    int            queue_id;
    void          *umem;
    size_t         umem_size;
    uint32_t       chunk_size;
    size_t         frame_len;
    ef_xdp_ring_t  tx;
    ef_xdp_ring_t  comp;
    uint64_t       tx_submitted;
    uint64_t       tx_completed;
    int            prog_fd;     // -1 if we did not attach
    int            attached;    // 1 if we netlink-attached the prog
};

// XDP_PASS bytecode. Drivers that gate the xsk fast path on "an XDP
// program is loaded" (mlx5 and friends) accept this minimal pair.
//   r0 = 2 (XDP_PASS); exit
static const struct bpf_insn xdp_pass_prog[] = {
    { .code = 0xb7, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 2 },
    { .code = 0x95, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 },
};

static uint32_t next_pow2_u32(uint32_t v) {
    if (v == 0)
        return 1;
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    return v + 1;
}

// Pick the smallest pow2 chunk size that fits both the frame and the
// iface MTU. The kernel's ZC bind path validates that an MTU-sized RX
// frame fits in one chunk, even on a TX-only socket. Capped at
// PAGE_SIZE per XDP_UMEM_REG rules: if MTU > PAGE_SIZE the iface needs
// XDP_USE_SG (multi-buffer ZC) which we do not emit, so callers will
// fail the open in that case.
static uint32_t chunk_size_for(size_t frame_len, uint32_t mtu) {
    long     page      = sysconf(_SC_PAGESIZE);
    uint32_t chunk_max = page > 0 ? (uint32_t)page : 4096;
    uint32_t want      = frame_len > EF_XDP_MIN_CHUNK ? (uint32_t)frame_len
                                                     : EF_XDP_MIN_CHUNK;
    uint32_t chunk;

    if (mtu > want)
        want = mtu;
    chunk = next_pow2_u32(want);
    if (chunk > chunk_max)
        return 0;
    return chunk;
}

static uint32_t iface_mtu(const char *ifname) {
    struct ifreq ifr = {};
    uint32_t     mtu = 0;
    int          s;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        return 0;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFMTU, &ifr) == 0 && ifr.ifr_mtu > 0)
        mtu = (uint32_t)ifr.ifr_mtu;
    close(s);
    return mtu;
}

// Returns 1 if any XDP program is attached to ifindex, 0 otherwise.
// Gates the "reuse the attached program" fast path so we do not pay
// the ~500ms driver channel reset that comes with attaching a fresh
// program on mlx5.
static int iface_has_xdp(int ifindex) {
    struct {
        struct nlmsghdr  nh;
        struct ifinfomsg ifi;
    }                 req     = {};
    struct nlmsghdr  *rh;
    struct ifinfomsg *rifi;
    struct rtattr    *rta;
    struct rtattr    *inner;
    char              buf[8192];
    ssize_t           n;
    int               s;
    int               attrlen;
    int               inner_len;

    req.nh.nlmsg_type  = RTM_GETLINK;
    req.nh.nlmsg_flags = NLM_F_REQUEST;
    req.nh.nlmsg_seq   = 1;
    req.nh.nlmsg_len   = sizeof(req);
    req.ifi.ifi_family = AF_UNSPEC;
    req.ifi.ifi_index  = ifindex;

    s = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (s < 0)
        return 0;
    if (send(s, &req, sizeof(req), 0) < 0) {
        close(s);
        return 0;
    }
    n = recv(s, buf, sizeof(buf), 0);
    close(s);
    if (n < (ssize_t)sizeof(struct nlmsghdr))
        return 0;

    rh = (struct nlmsghdr *)buf;
    if (rh->nlmsg_type != RTM_NEWLINK)
        return 0;

    rifi    = NLMSG_DATA(rh);
    attrlen = rh->nlmsg_len - NLMSG_SPACE(sizeof(*rifi));
    rta     = (struct rtattr *)((char *)rifi + NLMSG_ALIGN(sizeof(*rifi)));

    for (; RTA_OK(rta, attrlen); rta = RTA_NEXT(rta, attrlen)) {
        if (rta->rta_type != IFLA_XDP)
            continue;
        inner_len = RTA_PAYLOAD(rta);
        inner     = (struct rtattr *)RTA_DATA(rta);
        for (; RTA_OK(inner, inner_len); inner = RTA_NEXT(inner, inner_len)) {
            if (inner->rta_type == IFLA_XDP_ATTACHED) {
                uint8_t mode = *(uint8_t *)RTA_DATA(inner);
                return mode != XDP_ATTACHED_NONE;
            }
        }
    }
    return 0;
}

// BPF_PROG_LOAD with two attempts: first with BPF_F_XDP_HAS_FRAGS so
// the prog is accepted at any MTU (5.18+), then a plain load for
// older kernels. expected_attach_type must be BPF_XDP - without it,
// the kernel rejects XDP programs.
static int load_xdp_pass(void) {
    union bpf_attr attr;
    char           log[1024] = {};
    int            fd;

    memset(&attr, 0, sizeof(attr));
    attr.prog_type            = BPF_PROG_TYPE_XDP;
    attr.expected_attach_type = BPF_XDP;
    attr.insn_cnt   = sizeof(xdp_pass_prog) / sizeof(xdp_pass_prog[0]);
    attr.insns      = (uint64_t)(uintptr_t)xdp_pass_prog;
    attr.license    = (uint64_t)(uintptr_t)"GPL";
    attr.prog_flags = BPF_F_XDP_HAS_FRAGS;
    attr.log_buf    = (uint64_t)(uintptr_t)log;
    attr.log_size   = sizeof(log);
    attr.log_level  = 1;

    fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    if (fd >= 0)
        return fd;

    memset(&attr, 0, sizeof(attr));
    memset(log,   0, sizeof(log));
    attr.prog_type            = BPF_PROG_TYPE_XDP;
    attr.expected_attach_type = BPF_XDP;
    attr.insn_cnt = sizeof(xdp_pass_prog) / sizeof(xdp_pass_prog[0]);
    attr.insns    = (uint64_t)(uintptr_t)xdp_pass_prog;
    attr.license  = (uint64_t)(uintptr_t)"GPL";
    attr.log_buf  = (uint64_t)(uintptr_t)log;
    attr.log_size = sizeof(log);

    fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    if (fd < 0)
        pe("xdp: BPF_PROG_LOAD: %m (log: %s)\n", log[0] ? log : "(empty)");
    return fd;
}

// RTM_SETLINK with IFLA_XDP { IFLA_XDP_FD, IFLA_XDP_FLAGS }. prog_fd
// < 0 detaches. Returns 0 on success.
static int netlink_xdp_set(int ifindex, int prog_fd, uint32_t flags) {
    char                buf[256] = {};
    struct nlmsghdr    *nh       = (struct nlmsghdr *)buf;
    struct ifinfomsg   *ifi;
    struct rtattr      *xdp_attr;
    struct rtattr      *ifd;
    struct rtattr      *iflags;
    char                reply[1024];
    struct nlmsgerr    *err;
    ssize_t             n;
    int                 s;

    nh->nlmsg_type  = RTM_SETLINK;
    nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nh->nlmsg_seq   = 1;
    nh->nlmsg_len   = NLMSG_LENGTH(sizeof(*ifi));

    ifi             = NLMSG_DATA(nh);
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_index  = ifindex;

    xdp_attr           = (struct rtattr *)((char *)nh + NLMSG_ALIGN(nh->nlmsg_len));
    xdp_attr->rta_type = IFLA_XDP;
    xdp_attr->rta_len  = RTA_LENGTH(0);
    nh->nlmsg_len      = NLMSG_ALIGN(nh->nlmsg_len) + RTA_ALIGN(xdp_attr->rta_len);

    ifd                       = (struct rtattr *)((char *)nh + NLMSG_ALIGN(nh->nlmsg_len));
    ifd->rta_type             = IFLA_XDP_FD;
    ifd->rta_len              = RTA_LENGTH(sizeof(int));
    *(int *)RTA_DATA(ifd)     = prog_fd;
    nh->nlmsg_len             = NLMSG_ALIGN(nh->nlmsg_len) + RTA_ALIGN(ifd->rta_len);
    xdp_attr->rta_len        += RTA_ALIGN(ifd->rta_len);

    iflags                       = (struct rtattr *)((char *)nh + NLMSG_ALIGN(nh->nlmsg_len));
    iflags->rta_type             = IFLA_XDP_FLAGS;
    iflags->rta_len              = RTA_LENGTH(sizeof(uint32_t));
    *(uint32_t *)RTA_DATA(iflags) = flags;
    nh->nlmsg_len                = NLMSG_ALIGN(nh->nlmsg_len) + RTA_ALIGN(iflags->rta_len);
    xdp_attr->rta_len           += RTA_ALIGN(iflags->rta_len);

    s = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (s < 0) {
        pe("xdp: netlink socket: %m\n");
        return -1;
    }
    if (send(s, nh, nh->nlmsg_len, 0) < 0) {
        pe("xdp: netlink send: %m\n");
        close(s);
        return -1;
    }

    n = recv(s, reply, sizeof(reply), 0);
    close(s);
    if (n < (ssize_t)sizeof(struct nlmsghdr)) {
        pe("xdp: netlink short reply: %zd\n", n);
        return -1;
    }
    if (((struct nlmsghdr *)reply)->nlmsg_type != NLMSG_ERROR)
        return 0;
    err = NLMSG_DATA((struct nlmsghdr *)reply);
    if (err->error == 0)
        return 0;
    pe("xdp: netlink RTM_SETLINK: %s\n", strerror(-err->error));
    return -1;
}

static int setup_rings(ef_xdp_t *xs) {
    uint32_t r       = EF_XDP_RING_SIZE;
    uint32_t r_small = 64;

    // RX and fill rings are unused but the kernel rejects bind() unless
    // they are configured to at least a token size.
    if (setsockopt(xs->fd, SOL_XDP, XDP_RX_RING, &r_small, sizeof(r_small)) < 0 ||
        setsockopt(xs->fd, SOL_XDP, XDP_UMEM_FILL_RING, &r_small, sizeof(r_small)) < 0) {
        pe("xdp: setsockopt(XDP_{RX,FILL}_RING): %m\n");
        return -1;
    }
    if (setsockopt(xs->fd, SOL_XDP, XDP_TX_RING, &r, sizeof(r)) < 0 ||
        setsockopt(xs->fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &r, sizeof(r)) < 0) {
        pe("xdp: setsockopt(XDP_{TX,COMPLETION}_RING): %m\n");
        return -1;
    }
    return 0;
}

static int mmap_rings(ef_xdp_t *xs) {
    struct xdp_mmap_offsets off;
    socklen_t               optlen = sizeof(off);

    if (getsockopt(xs->fd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen) < 0) {
        pe("xdp: XDP_MMAP_OFFSETS: %m\n");
        return -1;
    }

    xs->tx.size     = EF_XDP_RING_SIZE;
    xs->tx.mask     = EF_XDP_RING_SIZE - 1;
    xs->tx.map_size = off.tx.desc +
                      (size_t)EF_XDP_RING_SIZE * sizeof(struct xdp_desc);
    xs->tx.map      = mmap(NULL, xs->tx.map_size,
                           PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_POPULATE,
                           xs->fd, XDP_PGOFF_TX_RING);
    if (xs->tx.map == MAP_FAILED) {
        pe("xdp: mmap tx ring: %m\n");
        return -1;
    }
    xs->tx.producer = (uint32_t *)((char *)xs->tx.map + off.tx.producer);
    xs->tx.consumer = (uint32_t *)((char *)xs->tx.map + off.tx.consumer);
    xs->tx.flags    = (uint32_t *)((char *)xs->tx.map + off.tx.flags);
    xs->tx.descs    =             (char *)xs->tx.map + off.tx.desc;

    xs->comp.size     = EF_XDP_RING_SIZE;
    xs->comp.mask     = EF_XDP_RING_SIZE - 1;
    xs->comp.map_size = off.cr.desc + (size_t)EF_XDP_RING_SIZE * sizeof(uint64_t);
    xs->comp.map      = mmap(NULL, xs->comp.map_size,
                             PROT_READ | PROT_WRITE,
                             MAP_SHARED | MAP_POPULATE,
                             xs->fd, XDP_UMEM_PGOFF_COMPLETION_RING);
    if (xs->comp.map == MAP_FAILED) {
        pe("xdp: mmap completion ring: %m\n");
        return -1;
    }
    xs->comp.producer = (uint32_t *)((char *)xs->comp.map + off.cr.producer);
    xs->comp.consumer = (uint32_t *)((char *)xs->comp.map + off.cr.consumer);
    xs->comp.flags    = (uint32_t *)((char *)xs->comp.map + off.cr.flags);
    return 0;
}

// mlx5 (and some other drivers) lets bind() succeed before the channel
// reset finishes, returning ENETDOWN from every sendto() until ~500ms
// later. Retry with 10ms backoff. Any other errno (or a successful
// kick) means the data path is live.
static int probe_kick(int fd) {
    int     tries = 200;
    ssize_t rc;

    while (tries-- > 0) {
        rc = sendto(fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
        if (rc >= 0)
            return 1;
        if (errno != ENETDOWN)
            return 1;  // any other errno means the path is live
        usleep(10000);
    }
    return 0;
}

static int try_bind_zc(int fd, int ifindex, int queue_id) {
    struct sockaddr_xdp sxdp = {
        .sxdp_family   = AF_XDP,
        .sxdp_ifindex  = ifindex,
        .sxdp_queue_id = queue_id,
        .sxdp_flags    = XDP_USE_NEED_WAKEUP | XDP_ZEROCOPY,
    };
    return bind(fd, (struct sockaddr *)&sxdp, sizeof(sxdp));
}

// Drain the completion ring into tx_completed. Acquire-load on the
// producer pairs with the kernel's release when it finishes a frame.
static void drain_completions(ef_xdp_t *xs) {
    uint32_t prod  = __atomic_load_n(xs->comp.producer, __ATOMIC_ACQUIRE);
    uint32_t cons  = __atomic_load_n(xs->comp.consumer, __ATOMIC_RELAXED);
    uint32_t avail = prod - cons;

    if (avail == 0 || avail > xs->comp.size)
        return;  // bogus avail means the producer has wrapped past us
    __atomic_store_n(xs->comp.consumer, prod, __ATOMIC_RELEASE);
    xs->tx_completed += avail;
}

int xdp_init(cmd_t *c, const char *ifname) {
    ef_xdp_t           *xs;
    struct xdp_umem_reg umem_reg;
    uint32_t            mtu;
    int                 prog_fd;
    int                 rc;

    if (!c->frame_buf || c->frame_buf->size == 0)
        return -1;

    xs = calloc(1, sizeof(*xs));
    if (!xs)
        return -1;
    xs->fd       = -1;
    xs->prog_fd  = -1;
    xs->queue_id = 0;

    xs->ifindex = if_nametoindex(ifname);
    if (xs->ifindex == 0) {
        pe("xdp: if_nametoindex(%s): %m\n", ifname);
        goto err;
    }

    mtu = iface_mtu(ifname);
    xs->chunk_size = chunk_size_for(c->frame_buf->size, mtu);
    if (xs->chunk_size == 0) {
        pe("xdp: %s MTU %u exceeds PAGE_SIZE; ZC requires XDP_USE_SG "
           "which this backend does not emit\n", ifname, mtu);
        goto err;
    }
    xs->umem_size = (size_t)xs->chunk_size * EF_XDP_NUM_FRAMES;

    xs->fd = socket(AF_XDP, SOCK_RAW, 0);
    if (xs->fd < 0) {
        pe("xdp: socket(AF_XDP): %m\n");
        goto err;
    }

    xs->umem = mmap(NULL, xs->umem_size,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (xs->umem == MAP_FAILED) {
        pe("xdp: mmap UMEM (%zu B): %m\n", xs->umem_size);
        xs->umem = NULL;
        goto err;
    }

    umem_reg = (struct xdp_umem_reg){
        .addr       = (uint64_t)(uintptr_t)xs->umem,
        .len        = xs->umem_size,
        .chunk_size = xs->chunk_size,
        .headroom   = 0,
    };
    if (setsockopt(xs->fd, SOL_XDP, XDP_UMEM_REG, &umem_reg, sizeof(umem_reg)) < 0) {
        pe("xdp: XDP_UMEM_REG: %m\n");
        goto err;
    }

    if (setup_rings(xs) < 0)
        goto err;
    if (mmap_rings(xs) < 0)
        goto err;

    // Try the bind without attaching our own program first: if the
    // iface already has one (from a prior ef run that didn't detach,
    // or from another tool) we save the ~500ms channel-reset cost.
    if (iface_has_xdp(xs->ifindex)) {
        rc = try_bind_zc(xs->fd, xs->ifindex, xs->queue_id);
        if (rc == 0 && probe_kick(xs->fd))
            goto bound;
    }

    // Fresh attach. The kernel takes a reference on the prog at attach
    // time so we keep the fd open for the lifetime of the socket and
    // close it together at xdp_close().
    prog_fd = load_xdp_pass();
    if (prog_fd < 0)
        goto err;
    if (netlink_xdp_set(xs->ifindex, prog_fd, XDP_FLAGS_DRV_MODE) < 0) {
        close(prog_fd);
        goto err;
    }
    xs->prog_fd  = prog_fd;
    xs->attached = 1;

    rc = try_bind_zc(xs->fd, xs->ifindex, xs->queue_id);
    if (rc < 0) {
        pe("xdp: ZC bind on %s queue %d: %m\n", ifname, xs->queue_id);
        goto err;
    }
    if (!probe_kick(xs->fd)) {
        pe("xdp: data path stayed down on %s queue %d after bind\n",
           ifname, xs->queue_id);
        goto err;
    }

bound:
    memcpy(xs->umem, c->frame_buf->data, c->frame_buf->size);
    xs->frame_len = c->frame_buf->size;
    c->xdp        = xs;
    return 0;

err:
    if (xs->attached)
        netlink_xdp_set(xs->ifindex, -1, XDP_FLAGS_DRV_MODE);
    if (xs->prog_fd >= 0)
        close(xs->prog_fd);
    if (xs->tx.map && xs->tx.map != MAP_FAILED)
        munmap(xs->tx.map, xs->tx.map_size);
    if (xs->comp.map && xs->comp.map != MAP_FAILED)
        munmap(xs->comp.map, xs->comp.map_size);
    if (xs->umem && xs->umem != MAP_FAILED)
        munmap(xs->umem, xs->umem_size);
    if (xs->fd >= 0)
        close(xs->fd);
    free(xs);
    return -1;
}

// Submit up to 'budget' descriptors and kick the kernel. Returns the
// number submitted. Mirrors txring_send: the caller decrements its
// rep counter by the return value, and combines that with xdp_unsent
// to drive the completion check.
//
// The atomic discipline matches PACKET_TX_RING. tx.consumer is owned
// by the kernel: ACQUIRE-load ensures we see its prior writes (slot
// release) before computing free space. tx.producer is ours: relaxed
// load is fine, but the store must be RELEASE so the kernel cannot
// observe an advanced producer with stale descriptor bytes (the
// TPACKET_V3 footgun).
//
// NEED_WAKEUP gates the kick: under ZC, the driver napi runs in the
// background and the flag goes high only when it has parked. Skipping
// the kick when napi is live saves syscalls on the fast path. When
// the ring is FULL we kick unconditionally - napi can settle with
// NEED_WAKEUP unset right after draining the last batch (mlx5 at
// near-peak rate does this), and a missed kick stalls indefinitely.
int xdp_send(cmd_t *c, int budget) {
    ef_xdp_t        *xs = c->xdp;
    struct xdp_desc *descs;
    uint32_t         prod, cons, in_use, free_slots, flags;
    int              i;

    if (!xs || budget <= 0)
        return 0;

    drain_completions(xs);

    prod       = __atomic_load_n(xs->tx.producer, __ATOMIC_RELAXED);
    cons       = __atomic_load_n(xs->tx.consumer, __ATOMIC_ACQUIRE);
    in_use     = prod - cons;
    free_slots = xs->tx.size - in_use;

    if (free_slots == 0) {
        // Ring full and napi may have parked; kick unconditionally.
        (void)sendto(xs->fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
        return 0;
    }

    if ((uint32_t)budget > free_slots)
        budget = (int)free_slots;

    descs = (struct xdp_desc *)xs->tx.descs;
    for (i = 0; i < budget; i++) {
        struct xdp_desc *d = &descs[(prod + i) & xs->tx.mask];
        d->addr    = 0;
        d->len     = (uint32_t)xs->frame_len;
        d->options = 0;
    }

    __atomic_store_n(xs->tx.producer, prod + (uint32_t)budget,
                     __ATOMIC_RELEASE);
    xs->tx_submitted += (uint64_t)budget;

    flags = __atomic_load_n(xs->tx.flags, __ATOMIC_RELAXED);
    if (flags & XDP_RING_NEED_WAKEUP) {
        int n = sendto(xs->fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
            errno != EINTR && errno != ENOBUFS) {
            pe("TX-ERR %16s: sendto (xdp): %m\n", c->arg0);
            return -1;
        }
    }

    return budget;
}

// Count outstanding TX (submitted but not yet completed). Drains the
// completion ring first so the count reflects the latest kernel view.
size_t xdp_unsent(const cmd_t *c) {
    ef_xdp_t *xs = c->xdp;
    if (!xs)
        return 0;
    // const-correctness: completions are kernel side-effects; touching
    // tx_completed via the drain is not a logical mutation of c.
    drain_completions((ef_xdp_t *)xs);
    return (size_t)(xs->tx_submitted - xs->tx_completed);
}

// Idempotent kick. Always issues the syscall - the main loop calls
// this during the drain phase where napi has typically parked and
// the NEED_WAKEUP flag is up; checking the flag would be redundant.
void xdp_kick(cmd_t *c) {
    if (c->xdp && c->xdp->fd >= 0)
        (void)sendto(c->xdp->fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
}

int xdp_socket_fd(const cmd_t *c) {
    return c->xdp ? c->xdp->fd : -1;
}

int xdp_install_iface(const char *ifname) {
    int ifindex = if_nametoindex(ifname);
    int prog_fd;
    int rc;

    if (ifindex == 0) {
        pe("xdp-install: if_nametoindex(%s): %m\n", ifname);
        return -1;
    }
    if (iface_has_xdp(ifindex)) {
        pe("xdp-install: %s already has an XDP program attached\n", ifname);
        return 0;  // idempotent: nothing to do
    }
    prog_fd = load_xdp_pass();
    if (prog_fd < 0)
        return -1;
    rc = netlink_xdp_set(ifindex, prog_fd, XDP_FLAGS_DRV_MODE);
    // The kernel takes a reference on the program at attach time, so
    // we can close the local fd right away. The program stays alive
    // until detached.
    close(prog_fd);
    return rc;
}

int xdp_uninstall_iface(const char *ifname) {
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        pe("xdp-uninstall: if_nametoindex(%s): %m\n", ifname);
        return -1;
    }
    return netlink_xdp_set(ifindex, -1, XDP_FLAGS_DRV_MODE);
}

void xdp_close(cmd_t *c) {
    ef_xdp_t *xs = c->xdp;
    if (!xs)
        return;

    drain_completions(xs);
    if (xs->tx_submitted != xs->tx_completed)
        pe("TX-DROP %16s: %llu xdp descriptors in flight at exit\n",
           c->arg0,
           (unsigned long long)(xs->tx_submitted - xs->tx_completed));

    if (xs->tx.map && xs->tx.map != MAP_FAILED)
        munmap(xs->tx.map, xs->tx.map_size);
    if (xs->comp.map && xs->comp.map != MAP_FAILED)
        munmap(xs->comp.map, xs->comp.map_size);
    if (xs->umem && xs->umem != MAP_FAILED)
        munmap(xs->umem, xs->umem_size);
    if (xs->fd >= 0)
        close(xs->fd);

    if (xs->attached)
        netlink_xdp_set(xs->ifindex, -1, XDP_FLAGS_DRV_MODE);
    if (xs->prog_fd >= 0)
        close(xs->prog_fd);

    free(xs);
    c->xdp = NULL;
}
