#include "print.h"

#define MAC_FMT  "%02x:%02x:%02x:%02x:%02x:%02x "

static char header_buffer[256];

//
//  source MAC -> destination MAC type & len
//  1st Header -> ethernet
void print_eth(const u_char *packet, size_t length) {
    struct eth_hdr *hdr = (struct eth_hdr*)packet;
    char src_MAC[20], dst_MAC[20];
    // Source MAC
    sprintf(src_MAC, MAC_FMT, hdr->h_source[0], hdr->h_source[1], hdr->h_source[2],
           hdr->h_source[3], hdr->h_source[4], hdr->h_source[5]);
    // Destination MAC
    sprintf(dst_MAC, MAC_FMT, hdr->h_dest[0], hdr->h_dest[1], hdr->h_dest[2],
           hdr->h_dest[3], hdr->h_dest[4], hdr->h_dest[5]);
    
    sprintf(header_buffer, "%s%s -> %s type 0x%x len %zu\n",
            header_buffer, src_MAC, dst_MAC,ntohs(hdr->h_proto), length);
}

//
//  
//  2nd & 3rd -> IP, TCP
size_t print_tcp(const u_char* packet, size_t length) {
    size_t hdrlen;
    // IP Layer
    struct ip_hdr *iph = (struct ip_hdr*)(packet + ETH_SIZE);
    size_t iphdrlen = (iph -> ihl) * 4;
    
    // TCP Layer
    struct tcp_hdr *tcph = (struct tcp_hdr*)(packet + iphdrlen + ETH_SIZE);
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iph->daddr), dst_ip, INET_ADDRSTRLEN);
    sprintf(header_buffer, "%s%s:%u -> %s:%u TCP\n",
            header_buffer, src_ip, tcph->source,dst_ip, tcph->dest);
    
    // Total - Header Length -> Payload
    hdrlen = ETH_SIZE + iphdrlen + tcph->doff * 4;
    return hdrlen;
}

size_t print_udp(const u_char* packet, size_t length) {
    // IP Layer
    struct ip_hdr *iph = (struct ip_hdr*)(packet + ETH_SIZE);
    size_t iphdrlen = (iph -> ihl) * 4;
    size_t hdrlen = ETH_SIZE + iphdrlen + sizeof(struct udphdr);

    // UDP Layer
    struct udphdr *udph = (struct udphdr*)(packet + iphdrlen  + ETH_SIZE);
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iph->daddr), dst_ip, INET_ADDRSTRLEN);
    sprintf(header_buffer, "%s%s:%u -> %s:%u UDP\n",
            header_buffer, src_ip, udph->uh_sport, dst_ip, udph->uh_dport);

    return hdrlen;
}

size_t print_icmp(const u_char* packet, size_t length) {
    // IP Layer
    struct ip_hdr *iph = (struct ip_hdr*)(packet + ETH_SIZE);
    size_t iphdrlen = (iph -> ihl) * 4;
    size_t hdrlen = ETH_SIZE + iphdrlen + 8;
    
    // Transport Layer
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iph->daddr), dst_ip, INET_ADDRSTRLEN);
    sprintf(header_buffer, "%s%s -> %s ICMP\n",
            header_buffer, src_ip, dst_ip);

    return hdrlen;
}

size_t print_other(const u_char* packet, size_t length) {
    // IP Layer
    struct ip_hdr *iph = (struct ip_hdr*)(packet + ETH_SIZE);
    size_t iphdrlen = (iph -> ihl) * 4;
    size_t hdrlen = ETH_SIZE + iphdrlen;
    
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iph->daddr), dst_ip, INET_ADDRSTRLEN);
    sprintf(header_buffer, "%s%s -> %s OTHER\n",
            header_buffer, src_ip, dst_ip);
    return hdrlen;
}

void print_output(const u_char* packet, size_t length, size_t hdr_len){
    printf("%s", header_buffer);
    size_t payload_len = length - hdr_len;
    if (payload_len > 0) {
        print_payload(packet + hdr_len, payload_len);
    }
    printf("\n");
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
void print_timestamp(struct timeval ts){
    char buffer[256];
    time_t t = (time_t)((int) ts.tv_sec);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", localtime(&t));
    sprintf(header_buffer, "%s.%06d ", buffer, (int) ts.tv_usec);
}
