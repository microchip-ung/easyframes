/*
 * Easy Frames Project
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 * Copyright (C) 2017 Microsemi <allan.nielsen@microsemi.com>
 *
 * ef.h
 *
 */

#ifndef __NEMESIS_H__
#define __NEMESIS_H__

#include <endian.h>
#include <time.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define LIBNET_LIL_ENDIAN 1
#elif __BYTE_ORDER == __BIG_ENDIAN
#define LIBNET_BIG_ENDIAN 1
#endif

#include <libnet-1.0.h>

#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY 0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT 0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY 0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST 0x02
#endif
#ifndef TH_ECE
#define TH_ECE 0x40
#endif
#ifndef TH_CWR
#define TH_CWR 0x80
#endif

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif

#define STPUTC(c) putchar(c);
#define STPUTS(s)                  \
    {                              \
        const char *p;             \
        p = s;                     \
        while (*p) STPUTC(*(p++)); \
    }

#define ARPBUFFSIZE 1472

#define DNSTCP_RAWBUFFSIZE 65403 /* plan for IP and TCP options */
#define DNSTCP_LINKBUFFSIZE 1368 /* link-layer version of above */
#define DNSUDP_RAWBUFFSIZE 65455 /* plan for IP options */
#define DNSUDP_LINKBUFFSIZE 1420 /* link-layer version of above */

#define ETHERBUFFSIZE 1500 /* max frame size */

#define ICMP_RAWBUFFSIZE                                                \
    65399                      /* plan for IP options & max ICMP header \
                                  len */
#define ICMP_LINKBUFFSIZE 1364 /* link-layer version of above */

#define IGMP_RAWBUFFSIZE 65467 /* plan for IP options */
#define IGMP_LINKBUFFSIZE 1432 /* link-layer version of above */

#define IP_RAWBUFFSIZE 65475 /* plan for IP options */
#define IP_LINKBUFFSIZE 1440 /* link-layer version of above */

#define RIP_RAWBUFFSIZE                                               \
    65451                     /* plan for IP options & max RIP header \
                                 len */
#define RIP_LINKBUFFSIZE 1416 /* link-layer version of above */

#define TCP_RAWBUFFSIZE 65415 /* plan for IP and TCP options */
#define TCP_LINKBUFFSIZE 1380 /* link-layer version of above */

#define UDP_RAWBUFFSIZE 65467 /* plan for IP options */
#define UDP_LINKBUFFSIZE 1432 /* link-layer version of above */

#define FP_MAX_ARGS 4 /* number of IP fragment parsing tokens */
#define ERRBUFFSIZE 256
#define WINERRBUFFSIZE 1024

#define HEX_ASCII_DECODE 0x02
#define HEX_RAW_DECODE 0x04

#define INJECTION_RAW 0x02
#define INJECTION_LINK 0x04

#define PAYLOADMODE 0
#define OPTIONSMODE 1
#define OPTIONSBUFFSIZE 40

#ifndef ETHERTYPE_8021Q
#define ETHERTYPE_8021Q 0x8100 /* IEEE 802.1Q VLAN tagging */
#endif

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86DD /* IPv6 protocol */
#endif

#ifndef ETHERTYPE_PPOEDISC
#define ETHERTYPE_PPPOEDISC 0x8863 /* PPP Over Ethernet Discovery Stage */
#endif

#ifndef ETHERTYPE_PPPOE
#define ETHERTYPE_PPPOE 0x8864 /* PPP Over Ethernet Session Stage */
#endif

typedef struct libnet_arp_hdr ARPhdr;
typedef struct libnet_as_lsa_hdr ASLSAhdr;
typedef struct libnet_auth_hdr AUTHhdr;
typedef struct libnet_dbd_hdr DBDhdr;
typedef struct libnet_dns_hdr DNShdr;
typedef struct libnet_ethernet_hdr ETHERhdr;
typedef struct libnet_icmp_hdr ICMPhdr;
typedef struct libnet_igmp_hdr IGMPhdr;
typedef struct libnet_ip_hdr IPhdr;
typedef struct libnet_lsa_hdr LSAhdr;
typedef struct libnet_lsr_hdr LSRhdr;
typedef struct libnet_lsu_hdr LSUhdr;
typedef struct libnet_net_lsa_hdr NETLSAhdr;
typedef struct libnet_rip_hdr RIPhdr;
typedef struct libnet_rtr_lsa_hdr RTRLSAhdr;
typedef struct libnet_sum_lsa_hdr SUMLSAhdr;
typedef struct libnet_tcp_hdr TCPhdr;
typedef struct libnet_udp_hdr UDPhdr;
typedef struct libnet_vrrp_hdr VRRPhdr;

extern char zero[ETHER_ADDR_LEN];
extern char one[ETHER_ADDR_LEN];
extern char errbuf[ERRBUFFSIZE];
extern char *pcap_outfile;
extern char *validtcpflags;
extern const char *version;
extern int verbose;
extern int got_link;
extern int got_ipoptions;
extern int got_tcpoptions;

typedef struct _FileData {
    int32_t file_s;     /* file size */
    u_int8_t *file_mem; /* pointer to file memory */
} FileData;

/* support functions */
u_int32_t xgetint32(const char *);
u_int16_t xgetint16(const char *);
u_int8_t xgetint8(const char *);
// int gmt2local(time_t);
int ef_name_resolve(char *, u_int32_t *);
int ef_check_link(ETHERhdr *, char *);
int ef_getdev(int, char **);
char *ef_lookup_linktype(int);
int ef_seedrand(void);
int parsefragoptions(IPhdr *, char *);
int parse_hex_string(const char *, u_int8_t *, int);

/* file I/O functions */
int builddatafromfile(const size_t, FileData *, const char *, const u_int32_t);

/* printout functions */
void ef_hexdump(u_int8_t *, u_int32_t, int);
void ef_device_failure(int, const char *);
void ef_maketitle(char *, const char *, const char *);
void ef_printeth(ETHERhdr *);
void ef_printarp(ARPhdr *);
void ef_printip(IPhdr *);
void ef_printtcp(TCPhdr *);
void ef_printudp(UDPhdr *);
void ef_printicmp(ICMPhdr *, int);
void ef_printrip(RIPhdr *);
void ef_printtitle(const char *);
void ef_usage(char *);

/* injection functions */
void ef_arp(int, char **);
void ef_dns(int, char **);
void ef_eth(int, char **);
void ef_icmp(int, char **);
void ef_igmp(int, char **);
void ef_ip(int, char **);
void ef_rip(int, char **);
void ef_tcp(int, char **);
void ef_udp(int, char **);
void ef_raw(int, char **);

#endif /* __NEMESIS_H__ */
