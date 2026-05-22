#ifndef EF_XDP_H
#define EF_XDP_H

#include <stddef.h>
#include <stdint.h>

// AF_XDP zero-copy TX backend, modelled on the PACKET_TX_RING path:
// one mmap'd ring per cmd, atomic producer/consumer indices shared
// with the kernel, single sendto() kick to nudge the napi when it
// has parked. ZC only - if the bind cannot land in zero-copy mode
// the open fails. The send() / sendmmsg() and PACKET_TX_RING paths
// still cover everything else.
struct cmd;
typedef struct ef_xdp ef_xdp_t;

int    xdp_init(struct cmd *c, const char *ifname);
int    xdp_send(struct cmd *c, int budget);
void   xdp_kick(struct cmd *c);
size_t xdp_unsent(const struct cmd *c);
void   xdp_close(struct cmd *c);

int    xdp_socket_fd(const struct cmd *c);

#endif // EF_XDP_H
