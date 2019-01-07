#include "ef.h"

#include <pcap/pcap.h>


int argc_frame(int argc, const char *argv[], frame_t *f) {
    int i, j, res;
    hdr_t *h;

    frame_reset(f);

    i = 0;
    while (i < argc) {
        h = 0;
        for (j = 0; j < HDR_TMPL_SIZE; ++j) {
            if (hdr_tmpls[j] && strcmp(argv[i], hdr_tmpls[j]->name) == 0) {
                h = hdr_tmpls[j];
                break;
            }
        }

        if (!h)
            return i;

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

    return 0;
}

