#include "ef.h"

#include <time.h>
#include <sys/time.h>

#define RATE_MILLIPKT    1000LL
#define NSEC_PER_SEC     1000000000LL

/* Ethernet wire overhead: preamble(7) + SFD(1) + FCS(4) + IFG(12) */
#define ETH_WIRE_OVERHEAD 24

static int clamp(int v, int lo, int hi)
{
    return v < lo ? lo : (v > hi ? hi : v);
}

void rate_init(cmd_t *c)
{
    int i, burst;

    // Auto-compute burst: 10% of pps, clamped to [1, RATE_BURST].
    if (c->rate_burst > 0)
        burst = clamp(c->rate_burst, 1, RATE_BURST);
    else if (c->rate_pps > 0)
        burst = clamp((int)(c->rate_pps / 10), 1, RATE_BURST);
    else
        burst = RATE_BURST;

    c->rate_burst = burst;
    c->tb_rate = (int64_t)c->rate_pps * RATE_MILLIPKT;
    c->tb_max  = (int64_t)burst * RATE_MILLIPKT;
    c->tb_tokens = c->tb_max;
    clock_gettime(CLOCK_MONOTONIC, &c->tb_last);

    // Pre-fill sendmmsg vector — all entries point to the same frame buffer.
    // Caller varies vlen at send time.
    if (c->frame_buf) {
        for (i = 0; i < burst; i++) {
            c->miov[i].iov_base = c->frame_buf->data;
            c->miov[i].iov_len  = c->frame_buf->size;
            c->mmsg[i].msg_hdr.msg_iov    = &c->miov[i];
            c->mmsg[i].msg_hdr.msg_iovlen = 1;
        }
    }
}

void rate_refill(cmd_t *c, struct timespec *now)
{
    int64_t sec, nsec, add;

    if (c->rate_pps == 0)
        return;

    sec  = now->tv_sec  - c->tb_last.tv_sec;
    nsec = now->tv_nsec - c->tb_last.tv_nsec;
    if (nsec < 0) {
        sec  -= 1;
        nsec += NSEC_PER_SEC;
    }

    if (sec < 0)
        return;

    /* sec * tb_rate + (nsec * rate_pps) / 1e6  — split to avoid overflow */
    add = sec * c->tb_rate +
          (nsec * (int64_t)c->rate_pps) / (NSEC_PER_SEC / RATE_MILLIPKT);

    if (add <= 0)
        return;

    c->tb_tokens += add;
    if (c->tb_tokens > c->tb_max)
        c->tb_tokens = c->tb_max;
    c->tb_last = *now;
}

int rate_can_send(cmd_t *c)
{
    if (c->rate_pps == 0)
        return 1;
    return c->tb_tokens >= RATE_MILLIPKT;
}

int rate_burst_available(cmd_t *c)
{
    int avail;

    if (c->rate_pps == 0)
        return c->rate_burst > 0 ? c->rate_burst : RATE_BURST;

    avail = (int)(c->tb_tokens / RATE_MILLIPKT);
    if (avail > c->rate_burst)
        avail = c->rate_burst;
    return avail;
}

void rate_consume(cmd_t *c)
{
    if (c->rate_pps == 0)
        return;
    c->tb_tokens -= RATE_MILLIPKT;
}

void rate_consume_n(cmd_t *c, int n)
{
    if (c->rate_pps == 0)
        return;
    c->tb_tokens -= (int64_t)n * RATE_MILLIPKT;
}

int64_t rate_ns_until_token(cmd_t *c)
{
    int64_t deficit;

    if (c->rate_pps == 0)
        return 0;

    if (c->tb_tokens >= RATE_MILLIPKT)
        return 0;

    deficit = RATE_MILLIPKT - c->tb_tokens;
    return (deficit * NSEC_PER_SEC) / c->tb_rate;
}

uint32_t rate_bps_to_pps(uint64_t bps, size_t frame_len)
{
    uint64_t wire_bits = (uint64_t)(frame_len + ETH_WIRE_OVERHEAD) * 8;
    uint64_t pps = bps / wire_bits;

    return pps > 0 ? (uint32_t)pps : 1;
}

int rate_refill_cmds(int cnt, cmd_t *cmds, struct timeval *tv_left)
{
        int64_t min_wait_ns = -1;
        struct timespec ts_now;
        int tx_pending = 0;

        clock_gettime(CLOCK_MONOTONIC, &ts_now);

        // Refill all rate-limited buckets and compute min wait
        for (int i = 0; i < cnt; i++) {
                if (cmds[i].type != CMD_TYPE_TX || cmds[i].done)
                        continue;

                tx_pending = 1;

                if (cmds[i].rate_pps > 0) {
                        rate_refill(&cmds[i], &ts_now);
                        int64_t w = rate_ns_until_token(&cmds[i]);
                        if (min_wait_ns < 0 || w < min_wait_ns)
                                min_wait_ns = w;
                } else {
                        min_wait_ns = 0;
                }
        }

        // Set select timeout to pacing interval when waiting for tokens
        if (min_wait_ns > 0) {
                struct timeval tv_pace;
                tv_pace.tv_sec = min_wait_ns / 1000000000LL;
                tv_pace.tv_usec = (min_wait_ns % 1000000000LL) / 1000;
                // Use the shorter of pacing and remaining timeout.
                // After timeout expires tv_left is ~0, so always use
                // the pacing interval to avoid a busy-loop.
                if (!timerisset(tv_left) || timercmp(&tv_pace, tv_left, <))
                        *tv_left = tv_pace;
        }

        return tx_pending;
}
