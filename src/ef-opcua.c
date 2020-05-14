#include <stdio.h>
#include "ef.h"

// Little-endian parser
static buf_t *opc_parse_uint16(hdr_t *hdr, int hdr_offset, const char *s, int bytes) {
    buf_t *b = parse_bytes(s, 2);
    uint8_t tmp;

    if (b) {
        tmp = b->data[0];
        b->data[0] = b->data[1];
        b->data[1] = tmp;
    }
    return b;
}

static field_t OPC_UA_FIELDS[] = {
    { .name = "flags-flags1",
      .help = "UADPFlags: ExtendedFlags1 enabled",
      .bit_width =  1 },
    { .name = "flags-pl-hdr",
      .help = "UADPFlags: PayloadHeader disabled",
      .bit_width =  1 },
    { .name = "flags-grp-hdr",
      .help = "UADPFlags: GroupHeader enabled",
      .bit_width =  1 },
    { .name = "flags-pub-id",
      .help = "UADPFlags: PublisherId enabled",
      .bit_width =  1 },
    { .name = "version",
      .help = "UADPVersion",
      .bit_width =  4 },
    { .name = "flags1-flags2",
      .help = "ExtendedFlags1: ExtendedFlags2 disabled",
      .bit_width =  1 },
    { .name = "flags1-pico-seconds",
      .help = "ExtendedFlags1: PicoSeconds disabled",
      .bit_width =  1 },
    { .name = "flags1-timestamp",
      .help = "ExtendedFlags1: Timestamp disabled",
      .bit_width =  1 },
    { .name = "flags1-security",
      .help = "ExtendedFlags1: Security disabled",
      .bit_width =  1 },
    { .name = "flags1-dsc-id",
      .help = "ExtendedFlags1: DataSetClassId disabled",
      .bit_width =  1 },
    { .name = "flags1-pub-id-type",
      .help = "ExtendedFlags1: PublisherId type",
      .bit_width =  3 },
    { .name = "pub-id",
      .help = "PublisherId (little-endian)",
      .bit_width =  16,
      .parser = opc_parse_uint16 },
    { .name = "gflags-rsvd",
      .help = "GroupFlags: Reserved",
      .bit_width =  4 },
    { .name = "gflags-seq-num",
      .help = "GroupFlags: SequenceNumber enabled",
      .bit_width =  1 },
    { .name = "gflags-nm-num",
      .help = "GroupFlags: NetworkMessageNumber enabled",
      .bit_width =  1 },
    { .name = "gflags-gversion",
      .help = "GroupFlags: GroupVersion enabled",
      .bit_width =  1 },
    { .name = "gflags-wg-id",
      .help = "GroupFlags: WriterGroupId enabled",
      .bit_width =  1 },
    { .name = "wg-id",
      .help = "WriterGroupId (little-endian)",
      .bit_width =  16,
      .parser = opc_parse_uint16 },
    { .name = "gversion",
      .help = "GroupVersion",
      .bit_width =  32 },
    { .name = "nm-num",
      .help = "NetworkMessageNumber",
      .bit_width =  16 },
    { .name = "seq-num",
      .help = "SequenceNumber",
      .bit_width =  16 },
};

static hdr_t HDR_OPC_UA = {
    .name = "opc-ua",
    .help = "OPC UA PubSub",
    .type = 0xB62C,
    .fields = OPC_UA_FIELDS,
    .fields_size = sizeof(OPC_UA_FIELDS) / sizeof(OPC_UA_FIELDS[0]),
    .parser = hdr_parse_fields,
};

void opcua_init() {
    def_offset(&HDR_OPC_UA);
    def_val(&HDR_OPC_UA, "version", "1");
    def_val(&HDR_OPC_UA, "flags-pub-id", "1");
    def_val(&HDR_OPC_UA, "flags-grp-hdr", "1");
    def_val(&HDR_OPC_UA, "flags-flags1", "1");
    def_val(&HDR_OPC_UA, "flags1-pub-id-type", "1");
    def_val(&HDR_OPC_UA, "flags1-flags2", "1"); 
    def_val(&HDR_OPC_UA, "gflags-wg-id", "1");
    def_val(&HDR_OPC_UA, "gflags-gversion", "1");
    def_val(&HDR_OPC_UA, "gflags-nm-num", "1");
    def_val(&HDR_OPC_UA, "gflags-seq-num", "1");
    hdr_tmpls[HDR_TMPL_OPC_UA] =  &HDR_OPC_UA;
}

void opcua_uninit() {
    uninit_frame_data(&HDR_OPC_UA);
    hdr_tmpls[HDR_TMPL_OPC_UA] = 0;
}

