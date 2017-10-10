/*
 * Easy Frames Project
 * Copyright (C) 2002, 2003 Jeff Nathan <jeff@snort.org>
 * Copyright (C) 2017 Microsemi <allan.nielsen@microsemi.com>
 *
 * ef-functions.c (ef utility functions)
 *
 */

#include <errno.h>
#include <limits.h>
#include <math.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include "ef.h"

char zero[ETHER_ADDR_LEN];
char one[ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
char errbuf[ERRBUFFSIZE];          /* all-purpose error buffer */
char *validtcpflags = "FSRPAUEC-"; /* TCP flag index */
int verbose;                       /* verbosity */
int got_link;
int got_ipoptions;
int got_tcpoptions;


/**
 * Convert user supplied string to a u_int32_t or exit on invalid data.
 *
 * @param str string to be converted
 *
 * @returns u_int32_t conversion of input string
 */
u_int32_t xgetint32(const char *str) {
    char *endp;
    u_long val;

    val = strtoul(str, &endp, 0);
    if (val > UINT_MAX || str == endp || *endp) {
        fprintf(stderr,
                "ERROR: Argument %s must be a positive integer between "
                "0 and %u.\n",
                str, UINT_MAX);
        exit(1);
    } else
        return (u_int32_t)val;
}

/**
 * Convert user supplied string to a u_int16_t or exit on invalid data.
 *
 * @param str string to be converted
 *
 * @return u_int16_t conversion of input string
 */
u_int16_t xgetint16(const char *str) {
    char *endp;
    u_long val;

    val = strtoul(str, &endp, 0);
    if (val > USHRT_MAX || str == endp || *endp) {
        fprintf(stderr,
                "ERROR: Argument %s must be a positive integer between "
                "0 and %hu.\n",
                str, USHRT_MAX);
        exit(1);
    } else
        return (u_int16_t)val;
}

/**
 * Convert user supplied string to a u_int8_t or exit on invalid data.
 *
 * @param str string to be converted
 *
 * @return u_int8_t conversion of input string
 */
u_int8_t xgetint8(const char *str) {
    char *endp;
    u_long val;

    val = strtoul(str, &endp, 0);
    if (val > UCHAR_MAX || str == endp || *endp) {
        fprintf(stderr,
                "ERROR: Argument %s must be a positive integer between "
                "0 and %u.\n",
                str, UCHAR_MAX);
        exit(1);
    } else
        return (u_int8_t)val;
}


/**
 * Parses a string to set the fragmentation options in an IP header
 *
 * @param iph pointer to an IPhdr structure
 * @param str string to be parsed
 *
 * @note Optimized by Marty Roesch <roesch@sourcefire.com>.
 *
 * @return 0 on sucess, -1 on failure
 **/
int parsefragoptions(IPhdr *iph, char *str) {
    int reserved = 0, dont = 0, more = 0, offset = 0;
    int i, argcount = 0;
    u_int8_t error = 0;
    char *orig = NULL;       /* original input string */
    char *toks[FP_MAX_ARGS]; /* break all args down into option sets */
    char **ap;
    u_int16_t frag_offset = 0;

    orig = strdup(str);

    for (ap = toks;
         ap < &toks[FP_MAX_ARGS] && (*ap = strsep(&str, " ,")) != NULL;) {
        if (**ap != '\0') {
            ap++;
            argcount++;
        }
    }
    *ap = NULL;

    for (i = 0; i < argcount; i++) {
        if (toks[i][0] == 'D') {
            if (!dont)
                dont++;
            else {
                error++;
                break;
            }
        } else if (toks[i][0] == 'M') {
            if (!more)
                more++;
            else {
                error++;
                break;
            }
        } else if (toks[i][0] == 'R') {
            if (!reserved)
                reserved++;
            else {
                error++;
                break;
            }
        } else if (isdigit((int)toks[i][0])) {
            if (!offset) {
                offset++;
                frag_offset = xgetint16(toks[i]);
            } else {
                error++;
                break;
            }
        } else {
            error++;
            break;
        }
    }

    if (error > 0) {
        fprintf(stderr,
                "ERROR: Invalid IP fragmentation options "
                "specification: %s.\n",
                orig);

        if (orig != NULL) free(orig);

        return -1;
    }

    if (frag_offset > 8189) {
        fprintf(stderr,
                "ERROR: Fragmentation offset %hu must be a positive "
                "integer between 0 and 8189.\n",
                frag_offset);

        if (orig != NULL) free(orig);

        return -1;
    }

    iph->ip_off = (frag_offset & IP_OFFMASK) |
                  ((reserved == 1 ? IP_RF : 0) | (dont == 1 ? IP_DF : 0) |
                   (more == 1 ? IP_MF : 0));

    if (orig != NULL) free(orig);

    return 0;
}


/**
 *
 * Convert a hostname or IP address, supplied in ASCII format, to an u_int32_t
 * in network byte order.
 *
 * @param hostname host name or IP address in ASCII
 * @param address u_int32_t pointer to hold converted IP
 *
 * @return 0 on sucess, -1 on failure
 */
int ef_name_resolve(char *hostname, u_int32_t *address) {
    struct in_addr saddr;
    struct hostent *hp = NULL;
    extern int h_errno;

    if (address == NULL || hostname == NULL) return -1;

    if ((inet_aton(hostname, &saddr)) < 1) {
        if ((hp = gethostbyname(hostname)) == NULL) {
            fprintf(stderr,
                    "ERROR: Unable to resolve supplied hostname: "
                    "%s. %s\n",
                    hostname, hstrerror(h_errno));
            return -1;
        }
        /* Do not blindly disregard the size of the address returned */
        if (hp->h_length != 4) {
            fprintf(stderr,
                    "ERROR: ef_name_resolve() received a non IPv4 "
                    "address.\n");
            return -1;
        }
        memcpy((u_int32_t *)address, hp->h_addr, 4);
        return 0;
    } else {
        if (!memcmp(&saddr.s_addr, zero, 4)) return -1;

        memcpy((u_int32_t *)address, &saddr.s_addr, 4);
        return 0;
    }
}


/**
 * Determine if a source Ethernet address has been specified and fill in the
 * ETHERhdr structure if necessary.
 *
 * @param eth ETHERhdr pointer containing the source Ethernet address
 * @param device char pointer containing the Ethernet device name
 *
 * @return 0 on sucess, -1 on failure
 */
int ef_check_link(ETHERhdr *eth, char *device) {
    int i;
    struct ether_addr *e = NULL;
    struct libnet_link_int l2;

    memset(&l2, 0, sizeof(struct libnet_link_int));
#ifdef DEBUG
    printf("DEBUG: determining if device %s\n       has a hardware address "
           "assigned.\n",
           device);
#endif
    if (!memcmp(eth->ether_shost, zero, 6)) {
        memset(&l2, 0, sizeof(l2));
        if ((e = libnet_get_hwaddr(&l2, device, errbuf)) == NULL) return -1;

        for (i = 0; i < 6; i++) eth->ether_shost[i] = e->ether_addr_octet[i];

        return 0;
    } else
        return 0;
}


/**
 * Lookup and return the string associated with each link type.
 *
 * @param linktype integer represntation of linktype
 *
 * @return char * containing the appropriate linktype or Unknown on a failed
 *         match.
 */
char *ef_lookup_linktype(int linktype) {
    char *dlt;

    switch (linktype) {
    case 0:
        dlt = "DLT_NULL";
        break;
    case 1:
        dlt = "DLT_EN10MB";
        break;
    case 2:
        dlt = "DLT_EN3MB";
        break;
    case 3:
        dlt = "DLT_AX25";
        break;
    case 4:
        dlt = "DLT_PRONET";
        break;
    case 5:
        dlt = "DLT_CHAOS";
        break;
    case 6:
        dlt = "DLT_IEEE802";
        break;
    case 7:
        dlt = "DLT_ARCNET";
        break;
    case 8:
        dlt = "DLT_SLIP";
        break;
    case 9:
        dlt = "DLT_PPP";
        break;
    case 10:
        dlt = "DLT_FDDI";
        break;
    case 11:
        dlt = "DLT_ATM_RFC1483";
        break;
    case 12:
        dlt = "DLT_LOOP";
        break;
    case 13:
        dlt = "DLT_ENC";
        break;
    case 14:
        dlt = "DLT_RAW";
        break;
    case 15:
        dlt = "DLT_SLIP_BSDOS";
        break;
    case 16:
        dlt = "DLT_PPP_BSDOS";
        break;
    default:
        dlt = "UNKNOWN";
    }
    return dlt;
}


/**
 * Seed the random number generator
 *
 * @return 0 on success, -1 on failure
 */
int ef_seedrand(void) {
    srandom(time(NULL));
    return 0;
}

int parse_hex_string(const char *in, u_int8_t *out, int out_max) {
    u_int8_t val;
    int first_nibble = 0;
    int out_cnt = 0;

    for (int i = 0; i < strlen(in); ++i) {
        char c = in[i];
        u_int8_t nibble = 0;

        if (c >= '0' && c <= '9') {
            nibble = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            nibble = (c - 'a') + 10;
        } else if (c >= 'A' && c <= 'F') {
            nibble = (c - 'A') + 10;
        } else if (c == ' ' || c == '\n' || c == '\r' || c == '\t' ||
                   c == '.' || c == ':') {
            if (first_nibble) return -1;
            continue;
        } else {
            return -1;
        }

        if (first_nibble) {
            if (out_cnt >= out_max) return -1;

            val |= nibble;
            first_nibble = 0;
            *out++ = val;
            out_cnt++;
            val = 0;

        } else {
            first_nibble = 1;
            val = nibble;
            val <<= 4;
        }
    }

    return out_cnt;
}


