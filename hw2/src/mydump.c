#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <ifaddrs.h>
#include <time.h>
#include <signal.h>
/*
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <linux/if.h>*/

#include "mydump.h"
#include "debug.h"
/*
static void sniffinterface(pcap_t *handle, char *searchstring);
static bool interfaceexists(const char *interface);
static void callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
static void printeth(const u_char *packet, size_t length);
static size_t printip(const u_char *packet, size_t length, char *srcip, char *destip);
static void printudp(const u_char* packet, size_t length);
static void printtcp(const u_char* packet, size_t length);
static void printicmp(const u_char* packet, size_t length);
static void printother(const u_char* packet, size_t length);
static void printpayload(const u_char* packet, size_t length);
static bool searchpacket(const u_char *packet, size_t length, char *search);*/

// static p

//static pcap_t *handle = NULL;
/*
void exithandler(int dummy) {
    if (handle != NULL) {
        pcap_breakloop(handle);
    }
}*/

int main(int argc, char *argv[]) {
    // 1 Parse Argument -> program_state
    parse_args(argc, argv);
    
    free(program_state);
    return EXIT_SUCCESS;
}
/*
    // Set up to capture
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 mask = 0;    The netmask of our sniffing device *
    bpf_u_int32 net = 0;     The IP of our sniffing device *
    struct bpf_program filter;
    // Zero out the struct
    memset(&filter, 0, sizeof(struct bpf_program));

    // Figure out to read the file or read the interface
    if (inputfile == NULL) {
        if (interface == NULL) {
            // No interface provided; just pick one
            if ((interface = pcap_lookupdev(errbuf)) == NULL) {
                error("%s\n", errbuf);
                return EXIT_FAILURE;
            } else {
                info("Bounded to the default interface %s\n", interface);
            }
        } else {
            // User provided an interface, see if it exists
            if (!interfaceexists(interface)) {
                error("The interface %s does not exist.\n", interface);
                return EXIT_FAILURE;
            }
        }

        // Collect information about the ipaddress and netmask
        if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
            error("%s\n", errbuf);
            net = mask = 0;
        }

        // Create a handle for the live interface
        if ((handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf)) == NULL) {
            error("%s\n", errbuf);
            return EXIT_FAILURE;
        }
    } else {
        // User gave us an input file. Try to open it.
        if ((handle = pcap_open_offline(inputfile, errbuf)) == NULL) {
            error("Unable to read the offline dump %s: %s\n", inputfile, errbuf);
            return EXIT_FAILURE;
        }
    }

    // If theres a filter, make compile the filter and apply it
    if (expression != NULL) {
        // Compile the filter
        if (pcap_compile(handle, &filter, expression, 0, net) == -1) {
            error("Couldn't parse the filter %s: %s\n", expression, pcap_geterr(handle));
            return EXIT_FAILURE;
        }
        // Apply the filter
        if (pcap_setfilter(handle, &filter) == -1) {
            error("Couldn't apply the filter %s: %s\n", expression, pcap_geterr(handle));
            return EXIT_FAILURE;
        }
    }

    // Start sniffing
    sniffinterface(handle, searchstring);

    // Close the session
    printf("\n");
    if (inputfile != NULL) {
        info("Ending parsing of input file %s...\n", inputfile);
    } else {
        info("Ending listening session on %s...\n", interface);
    }
    pcap_close(handle);*/


/*
static void sniffinterface(pcap_t *handle, char *searchstring) {
    if (handle == NULL)
        return;
    // We got this far, set up the signal handler
    signal(SIGINT, exithandler);

    // Now start reading the handle
    pcap_loop(handle, -1, callback, (u_char*)searchstring);
}

static bool interfaceexists(const char *interface) {
    bool exists = false;
    if (interface != NULL) {
        struct ifaddrs *ifaddrs, *ifa;

        // Try to get list of interfaces
        if (getifaddrs(&ifaddrs) == -1) {
            perror("getifaddrs");
            return exists;
        }

        // Iterate through the devices
        for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
            if (strcmp(ifa->ifa_name, interface) == 0 && CHECK_FLAG(ifa->ifa_flags, IFF_UP)) {
                exists = true;
                break;
            }
        }

        // We are done; free the list
        freeifaddrs(ifaddrs);
    }
    return exists;
}

static void callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    if (args != NULL) {
        if (!searchpacket(packet, pkthdr->len, (char*)args)) {
            // Didn't find the search string, exit
            return;
        }
    }
    // source and destination IP
    // address and port, protocol (TCP, UDP, ICMP, OTHER), and the raw content of the
    // application-layer packet payload
    // Extract the time stamp
    char buffer[256];
    time_t ts = pkthdr->ts.tv_sec;
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S%P", localtime(&ts));
    printf("%s ", buffer);
    // Check to see if we have a ipv4 packet
    struct ethhdr *ehdr = (struct ethhdr *)packet;
    if (ntohs(ehdr->h_proto) == IPV4) {
        struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
        // Figure out protocol sensitive information
        switch (iph->protocol) {
            case TYPE_ICMP:
                printicmp(packet, pkthdr->caplen);
                break;
            case TYPE_UDP:
                printudp(packet, pkthdr->caplen);
                break;
            case TYPE_TCP:
                printtcp(packet, pkthdr->caplen);
                break;
            default:
                printother(packet, pkthdr->caplen);
                break;
        }
    } else {
        // We have something else like arp, etc.
        printeth(packet, pkthdr->caplen);
        // Print a OTHER and a newline
        printf("OTHER\n");
        // Print whatever is left
        printpayload(packet + sizeof(struct ethhdr), pkthdr->caplen - sizeof(struct ethhdr));
    }
    // Make a gap for the next packet
    printf("\n");
}

static void printeth(const u_char *packet, size_t length) {
    // source and destination MAC address
    struct ethhdr *hdr = (struct ethhdr*)packet;
    // Print out the source mac address
    printf("%02x:%02x:%02x:%02x:%02x:%02x ",
        hdr->h_source[0],
        hdr->h_source[1],
        hdr->h_source[2],
        hdr->h_source[3],
        hdr->h_source[4],
        hdr->h_source[5]);
    // Print out the destination mac address
    printf("> %02x:%02x:%02x:%02x:%02x:%02x ",
        hdr->h_dest[0],
        hdr->h_dest[1],
        hdr->h_dest[2],
        hdr->h_dest[3],
        hdr->h_dest[4],
        hdr->h_dest[5]);
    // Print out the ethernet type
    printf("0x%04x ", ntohs(hdr->h_proto));
    // Print out the packet length
    printf("%5zu", length);
    // Print out a newline to force rest of output on next line
    printf("\n");
}
*/

