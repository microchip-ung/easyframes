#include "ef.h"

#include <pcap/pcap.h>

extern hdr_t HDR_ETH;
extern hdr_t HDR_VLAN;
extern hdr_t HDR_ARP;
extern hdr_t HDR_IPV4;


int argc_frame(int argc, const char *argv[], frame_t *f) {
    int i, res;
    hdr_t *h;

    frame_reset(f);

    i = 0;
    while (i < argc) {
        if (strcmp(argv[i], "eth") == 0) {
            h = &HDR_ETH;

        } else if (strcmp(argv[i], "vlan") == 0) {
            h = &HDR_VLAN;

        } else if (strcmp(argv[i], "arp") == 0) {
            h = &HDR_ARP;

        } else if (strcmp(argv[i], "ipv4") == 0) {
            h = &HDR_IPV4;

        } else {
            return i;

        }

        h = frame_clone_and_push_hdr(f, h);
        printf("Parsing hdr: %s: %p\n", h->name, h);

        i += 1;
        if (i >= argc)
            return i;

        res = hdr_parse_fields(h, argc - i, argv + i);
        if (res <= 0) {
            printf("err\n");
            return -1;
        }

        i += res;
    }

    return i;
}

int main(int argc, const char *argv[]) {
    struct pcap_pkthdr pkt;
    init_frame_data_all();
    buf_t *buf;

    pcap_t *pcap;
    pcap_dumper_t *pcapfile;

    pcap = pcap_open_dead(DLT_EN10MB, 65535);
    if (!pcap) {
        fprintf(stderr, "Error from pcap_open_dead(): %s\n", pcap_geterr(pcap));
        return -1;
    }

    pcapfile = pcap_dump_open(pcap, "/tmp/xx.pcap");
    if (!pcapfile) {
        fprintf(stderr, "Error from pcap_dump_open(): %s\n", pcap_geterr(pcap));
        return -1;
    }

    frame_t frame = {};

    argc_frame(argc - 1, argv + 1, &frame);
    buf = frame_to_buf(&frame);

    memset(&pkt, 0, sizeof(pkt));
    pkt.caplen = buf->size;
    pkt.len = buf->size;
    pcap_dump((u_char *)pcapfile, &pkt, buf->data);

    pcap_dump_close(pcapfile);
    pcap_close(pcap);

    frame_reset(&frame);
    uninit_frame_data_all();

    return 0;
}

