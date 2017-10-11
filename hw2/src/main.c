#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <pcap/pcap.h>
#include "mydump.h"
#include "debug.h"
#include "print.h"

static pcap_t *handle = NULL;
static void callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);

int main(int argc, char *argv[]) {
    // 1 Parse Argument -> program_state
    parse_args(argc, argv);
    
    // 2
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net = 0;
    bpf_u_int32 mask = 0;
    
    if(program_state -> inputfile){     // Input File
        if ((handle = pcap_open_offline(program_state -> inputfile, errbuf)) == NULL) {
            error("Unable to read the offline dump file %s", program_state -> inputfile);
            return EXIT_FAILURE;
        }
    }else{
        if (program_state -> interface) {// Interface
            if (pcap_lookupnet(program_state -> interface, &net, &mask, errbuf) == -1) {
                printf("Error getting ip and mask! Error message: %s\n", errbuf);
                net = mask = 0;
            }

            if((handle = pcap_open_live(program_state -> interface, BUFSIZ, 1, 1000, errbuf))== NULL) {
                printf("Error opening live! Error message: %s\n", errbuf);
                return EXIT_FAILURE;
            }
        }else{ // Null File & Interface
            program_state -> interface = pcap_lookupdev(errbuf);
            if (program_state -> interface == NULL) {
                printf("Error finding default device! Error message: %s\n", errbuf);
                return EXIT_FAILURE;
            }
        }
        
        if ((handle = pcap_open_live(program_state -> interface, BUFSIZ, 1, 1000, errbuf)) == NULL) {
            error("%s\n", errbuf);
            return EXIT_FAILURE;
        }
    }
    
    // Filter
    if (program_state -> expression != NULL) {
        // 1 Compile
        struct bpf_program filter;
        if (pcap_compile(handle, &filter, program_state -> expression, 0, net) == -1) {
            error("Couldn't parse the filter %s: %s\n", program_state -> expression, pcap_geterr(handle));
            return EXIT_FAILURE;
        }
        // 2 Apply 
        if (pcap_setfilter(handle, &filter) == -1) {
            error("Couldn't apply the filter %s: %s\n", program_state -> expression, pcap_geterr(handle));
            return EXIT_FAILURE;
        }
    }
    
    pcap_loop(handle, -1, callback, (u_char*)program_state -> searchstring);
    free(program_state);
    pcap_close(handle);
    return EXIT_SUCCESS;
}

static void callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // 1 Time stamp
    print_timestamp(pkthdr -> ts.tv_sec);
    
    struct eth_hdr *peth = (struct eth_hdr *)packet;
    // 2 MAC & IP & Payload
    if (ntohs(peth -> h_proto) == IPV4) {

        struct ip_hdr *pip = (struct ip_hdr*)(packet + ETH_SIZE);
        switch (pip -> protocol) {
            case TYPE_ICMP:
                print_eth(packet, pkthdr->caplen);
                print_icmp(packet, pkthdr->caplen);
                break;
            case TYPE_UDP:
                print_eth(packet, pkthdr->caplen);
                print_udp(packet, pkthdr->caplen);
                break;
            case TYPE_TCP:
                print_eth(packet, pkthdr->caplen);
                print_tcp(packet, pkthdr->caplen);
                break;
            default:
                //printother(packet, pkthdr->caplen);
                break;
        }
    } else {
        print_eth(packet, pkthdr->caplen);
        printf("OTHER PACKET\n");
        //print_payload(packet + ETH_SIZE, pkthdr->caplen - ETH_SIZE);
    }
    
    printf("\n");
}


