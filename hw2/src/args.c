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
                program_state -> string = optarg;
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
    
    debug("Match String: %s\n", program_state -> string);
    debug("BPF Expression: %s\n", program_state -> expression);
}


void* Calloc(size_t nmemb, size_t size)
{
    void* ret;
    if ((ret = calloc(nmemb, size)) == NULL) {
        perror("Out of Memory");
        exit(EXIT_FAILURE);
    }
    return ret;
}

