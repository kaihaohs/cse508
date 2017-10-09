#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "mydump.h"
#include "debug.h"

void* Calloc(size_t nmemb, size_t size);

state_t *program_state;

// Parse Argument - Main
void parse_args(int argc, char *argv[])
{
    char opt;
    program_state = Calloc(1, sizeof(state_t));
    
    while ((opt = getopt(argc, argv, "hi:r:s:")) != -1) {
        switch (opt) {
            case 'i':
                program_state -> interface = optarg;
                break;
            case 'r':
                program_state -> inputfile = optarg;
                break;
            case 's':
                program_state -> searchstring = optarg;
                break;
            case 'h':
                USAGE(argv[0], stdout, EXIT_SUCCESS);
                break;
            default:
                USAGE(argv[0], stderr, EXIT_FAILURE);
                break;
        }
    }

    if (program_state -> interface != NULL && program_state -> inputfile != NULL) {
        error("Interface and input file are provided at the same time!\n");
        USAGE(argv[0], stderr, EXIT_FAILURE);
    }

    if ( optind == argc - 1) {
        program_state -> expression = argv[optind];
    } else if (optind != argc) {
        error("Too many expression are provided!\n");
        USAGE(argv[0], stderr, EXIT_FAILURE);
    }
    
    debug("Search String: %s\n", program_state -> searchstring);
    debug("BPF Expression: %s\n", program_state -> expression);
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


