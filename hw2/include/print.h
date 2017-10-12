#ifndef PRINT_H
#define PRINT_H
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netinet/udp.h>

#define IPV4 0x0800
#define TYPE_ICMP 1
#define TYPE_TCP 6
#define TYPE_UDP 17

#define ETH_ALEN 6

#define ETH_SIZE (sizeof(struct eth_hdr))

struct eth_hdr
{
    unsigned char h_dest[ETH_ALEN];
    unsigned char h_source[ETH_ALEN];
    uint16_t h_proto ;
}__attribute__((packed));

struct ip_hdr {
//#if defined(__LITTLE_ENDIAN_BITFIELD)
    uint8_t    ihl:4, version:4;
//#elif defined (__BIG_ENDIAN_BITFIELD)
//    uint8_t    version:4, ihl:4;
//#endif
    uint8_t     tos;
    uint16_t    tot_len;
    uint16_t    id;
    uint16_t    frag_off;
    uint8_t     ttl;
    uint8_t     protocol;
    uint16_t    check;
    uint32_t    saddr;
    uint32_t    daddr;
};

struct tcp_hdr {
    uint16_t    source;
    uint16_t    dest;
    uint32_t    seq;
    uint32_t    ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
    uint16_t    res1:4, doff:4,
                fin:1, syn:1,
                rst:1, psh:1,
                ack:1, urg:1,
                ece:1, cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
    uint16_t    doff:4, res1:4,
                cwr:1, ece:1,
                urg:1, ack:1,
                psh:1, rst:1,
                syn:1, fin:1;
#else
    uint16_t    res1:4, doff:4,
                fin:1, syn:1,
                rst:1, psh:1,
                ack:1, urg:1,
                ece:1, cwr:1;
#endif
    uint16_t    window;
    uint16_t    check;
    uint16_t    urg_ptr;
};

void print_timestamp(struct timeval ts);
void print_eth(const u_char *packet, size_t length);
size_t print_tcp(const u_char* packet, size_t length);
size_t print_udp(const u_char* packet, size_t length);
size_t print_icmp(const u_char* packet, size_t length);
size_t print_other(const u_char* packet, size_t length);
void print_payload(const u_char* packet, size_t length);
void print_output(const u_char* packet, size_t length, size_t hdr_len);
#endif
