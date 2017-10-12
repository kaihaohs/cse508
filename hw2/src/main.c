#include <stdio.h>
#include "mydump.h"
#include "debug.h"
#include "print.h"

// Pcap Handle
static pcap_t *handle = NULL;

// Each Packet
static void parse_packets(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);

int main(int argc, char *argv[]) {
    // 1 Parse Argument -> program_state
    parse_args(argc, argv);
    
    // 2 Handle
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net = 0;
    bpf_u_int32 mask = 0;
    
    if(program_state -> inputfile){     // 2.1 Input File
        if ((handle = pcap_open_offline(program_state -> inputfile, errbuf)) == NULL) {
            error("Unable to read the offline dump file %s", program_state -> inputfile);
            return EXIT_FAILURE;
        }
    }else{                              // 2.2 Input Interface
        if (program_state -> interface == NULL) {
            program_state -> interface = pcap_lookupdev(errbuf);
            if (program_state -> interface == NULL) {
                printf("Unable to find the default device: %s\n", errbuf);
                return EXIT_FAILURE;
            }
        }

        if (pcap_lookupnet(program_state -> interface, &net, &mask, errbuf) == -1) {
            printf("Unable to get the netmask: %s\n", errbuf);
            net = mask = 0;
        }
        
        if((handle = pcap_open_live(program_state -> interface, BUFSIZ, 1, 1000, errbuf))== NULL) {
            printf("Unable to open the device %s: %s\n", program_state->interface, errbuf);
            return EXIT_FAILURE;
        }
    }
    
    // 3 Filter
    if (program_state -> expression != NULL) {
        // 3.1 Compile
        struct bpf_program filter;
        if (pcap_compile(handle, &filter, program_state -> expression, 0, net) == -1) {
            error("Unable to parse the filter %s: %s\n", program_state -> expression, pcap_geterr(handle));
            return EXIT_FAILURE;
        }
        // 3.2 Apply
        if (pcap_setfilter(handle, &filter) == -1) {
            error("Unable to apply the filter %s: %s\n", program_state -> expression, pcap_geterr(handle));
            return EXIT_FAILURE;
        }
    }
    
    // 4 Loop Anlysis
    pcap_loop(handle, -1, parse_packets, (u_char*)program_state);
    
    // 5 Free & Close
    free(program_state);
    pcap_close(handle);
    return EXIT_SUCCESS;
}

static void parse_packets(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // 1 Time stamp
    struct timeval ts = pkthdr -> ts;
    print_timestamp(ts);
    
    // 2 MAC
    print_eth(packet, pkthdr->caplen);
    
    // 3 IP & Payload
    struct eth_hdr *peth = (struct eth_hdr *)packet;
    size_t hdr_len = 0;
    
    if (ntohs(peth -> h_proto) == IPV4) {
    
        struct ip_hdr *pip = (struct ip_hdr*)(packet + ETH_SIZE);
        switch (pip -> protocol) {
            case TYPE_ICMP:
                hdr_len = print_icmp(packet, pkthdr->caplen);
                break;
            case TYPE_UDP:
                hdr_len = print_udp(packet, pkthdr->caplen);
                break;
            case TYPE_TCP:
                hdr_len = print_tcp(packet, pkthdr->caplen);
                break;
            default:
                hdr_len = print_other(packet, pkthdr->caplen);
                break;
        }
    } else {return;/* Other Packets (IPv6)*/}
    
    // Search string in the payload
    if(program_state -> string){
        if(hdr_len && pkthdr->caplen > hdr_len
           &&strstr((char *)(packet + hdr_len), program_state -> string)){
            print_output(packet, pkthdr->caplen, hdr_len);
        }
    }else{
        print_output(packet, pkthdr->caplen, hdr_len);
    }
}
