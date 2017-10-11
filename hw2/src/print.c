/*
#include <pcap/pcap.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <arpa/inet.h>


#include <netinet/ip_icmp.h>

#include <netinet/tcp.h>
*/
#include "print.h"

#define MAC_FMT  "%02x:%02x:%02x:%02x:%02x:%02x "
//
//  source MAC -> destination MAC type & len
//  1st Header -> ethernet
void print_eth(const u_char *packet, size_t length) {
    struct eth_hdr *hdr = (struct eth_hdr*)packet;
    // Source MAC
    printf(MAC_FMT, hdr->h_source[0], hdr->h_source[1], hdr->h_source[2],
           hdr->h_source[3], hdr->h_source[4], hdr->h_source[5]);
    // ->
    printf("-> ");
    // Destination MAC
    printf(MAC_FMT, hdr->h_dest[0], hdr->h_dest[1], hdr->h_dest[2],
           hdr->h_dest[3], hdr->h_dest[4], hdr->h_dest[5]);
    
    printf("type 0x%x ", ntohs(hdr->h_proto));       // Ethernet Type
    printf("len %zu\n", length);                     // Packet Length
}

//
//  
//  2nd & 3rd -> IP, TCP
void print_tcp(const u_char* packet, size_t length) {
    size_t hdrlen, payloadlen;
    // IP Layer
    struct ip_hdr *iph = (struct ip_hdr*)(packet + ETH_SIZE);
    size_t iphdrlen = (iph -> ihl) * 4;
    
    // TCP Layer
    struct tcp_hdr *tcph = (struct tcp_hdr*)(packet + iphdrlen + ETH_SIZE);
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iph->daddr), dst_ip, INET_ADDRSTRLEN);
    printf("%s:%u -> %s:%u TCP\n", src_ip, tcph->source,dst_ip, tcph->dest);
    
    // Total - Header Length -> Payload
    hdrlen = ETH_SIZE + iphdrlen + tcph->doff * 4;
    payloadlen = length - hdrlen;
    if (payloadlen > 0) {
        print_payload(packet + hdrlen, payloadlen);
    }
}

void print_udp(const u_char* packet, size_t length) {
    // IP Layer
    struct ip_hdr *iph = (struct ip_hdr*)(packet + ETH_SIZE);
    size_t iphdrlen = (iph -> ihl) * 4;
    size_t payloadlen, hdrlen;

    // UDP Layer
    struct udphdr *udph = (struct udphdr*)(packet + iphdrlen  + ETH_SIZE);
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iph->daddr), dst_ip, INET_ADDRSTRLEN);
    printf("%s:%u > %s:%u UDP\n", src_ip, udph->uh_sport, dst_ip, udph->uh_dport);
    
    // Payload
    hdrlen = ETH_SIZE + iphdrlen + sizeof(struct udphdr);
    payloadlen = length - hdrlen;
    if (payloadlen > 0) {
        print_payload(packet + hdrlen, payloadlen);
    }
}

void print_icmp(const u_char* packet, size_t length) {
    // IP Layer
    struct ip_hdr *iph = (struct ip_hdr*)(packet + ETH_SIZE);
    size_t iphdrlen = (iph -> ihl) * 4;
    size_t hdrlen, payloadlen;
    
    // Transport Layer
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iph->daddr), dst_ip, INET_ADDRSTRLEN);
    printf("%s > %s ICMP\n", src_ip, dst_ip);
    
    // Payload
    hdrlen = ETH_SIZE + iphdrlen + 8;//sizeof(struct icmp);
    payloadlen = length - hdrlen;
    if (payloadlen > 0) {
        print_payload(packet + hdrlen, payloadlen);
    }
}

void print_payload_row(u_char *buffer, size_t count) {
    int i;
    
    for (i = 0; i < count; ++i) {
        printf("%02x ", buffer[i]);
    }
    
    while(i < 16){
        printf("   ");
        ++i;
    }
    
    printf("  ");
    
    for (i = 0; i < count; ++i) {
        char c = buffer[i];
        if (c < ' ' || c > '~') {
            c = '.';
        }
        printf("%c", c);
    }
    printf("\n");
}

//
//
//
void print_payload(const u_char* packet, size_t length) {
    int i;
    size_t count = 0;
    u_char buffer[16];
    for (i = 0; i < length; ++i) {
        if (count == 16) {
            print_payload_row(buffer, count);
            count = 0;
        }
        buffer[count] = packet[i];
        count++;
    }

    if (count > 0)
        print_payload_row(buffer, count);
}

// Print Time Stamp
void print_timestamp(time_t ts){
    char buffer[64];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S ", localtime(&ts));
    printf("%s", buffer);
}
