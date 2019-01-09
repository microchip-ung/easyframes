#include "ef.h"

#include <pcap/pcap.h>


int argc_frame(int argc, const char *argv[], frame_t *f) {
    int i, j, res;
    hdr_t *h;

    frame_reset(f);

    i = 0;
    while (i < argc) {

        if (strcmp(argv[i], "help") == 0) {
            printf("Specify a frame by using one or more of the following headers:\n");
            hdr_help(hdr_tmpls, HDR_TMPL_SIZE, 2, 0);
            return -1;
        }

        h = 0;
        for (j = 0; j < HDR_TMPL_SIZE; ++j) {
            if (hdr_tmpls[j] && strcmp(argv[i], hdr_tmpls[j]->name) == 0) {
                h = hdr_tmpls[j];
                break;
            }
        }

        if (!h) {
            printf("ERROR: Invalid parameter: %s\n", argv[i]);
            return -1;
        }

        i += 1;
        if (i >= argc) {
            printf("ERROR: Missing argument to %s\n", argv[i - 1]);
            return -1;
        }

        h = frame_clone_and_push_hdr(f, h);
        if (!h) {
            printf("ERROR: frame_clone_and_push_hdr() failed\n");
            return -1;
        }

        printf("Parsing hdr: %s: %p\n", h->name, h);
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
    int res;

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

    res = argc_frame(argc - 1, argv + 1, &frame);
    if (res < 0) {
        return -1;
    }
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

