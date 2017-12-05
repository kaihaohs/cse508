//
//  args.c
//  hw3
//
//  Created by Kaihao Li on 2017/11/11.
//  Copyright © 2017 Kaihao Li. All rights reserved.
//

#include "debug.h"
#include "args.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

state_t * p_state;

void error_exit(){free(p_state); exit(EXIT_FAILURE);}

void init_key(char *keyfile){
    // 1 keyfile
    if (keyfile == NULL) {
        error("No Specific key file !\n");
        error_exit();
    }
    
    struct stat st;
    memset(&st, 0, sizeof(struct stat));
    if (stat(keyfile, &st) < 0) {
        error("Key %s does not exist!\n", keyfile);
        error_exit();
    }
    
    // 2 Read file
    p_state->key.value = malloc(st.st_size);
    p_state->key.size = st.st_size;
    
    int keyfd;
    if ((keyfd = open(keyfile, 0)) < 0) {
        error("Unable to open the key %s\n", keyfile);
        error_exit();
    }
    
    if (read(keyfd, p_state->key.value, p_state->key.size) != p_state->key.size) {
        error("Unable to read the key %s.\n", keyfile);
        error_exit();
    }
    
    if (keyfd != STDIN_FILENO)
        close(keyfd);
    
    // 3 Init AES ctr Key
    if (AES_set_encrypt_key(p_state->key.value, 128, &(p_state->key.aeskey)) < 0) {
        error("Could not set encryption key.\n");
    }
}

void parse_args(int argc, char **argv){
    char * error = NULL;
    p_state = calloc(1, sizeof(state_t));
    int opt;
    
    // 1 Parse Argument
    while((opt = getopt(argc, argv, "l:k:")) != -1) {
        switch(opt) {
            case 'l':
                p_state->proxy_port = (unsigned short) strtoul(optarg, &error, 10);
                if (*error != '\0') {
                    error("Invalid proxy port [%s]\n", optarg);
                    error_exit();
                }
                p_state->is_server = true;
                break;
            case 'k':
                p_state->keyfile = optarg;
                break;
            default:
                HELP();
                error_exit();
        }
    }
    
    // 2 Key File
    init_key(p_state->keyfile);
    
    // 3 Check Host & Port
    char* hostname= NULL;
    int port = 0;
    if (optind < argc && (argc - optind) == 2) {
        hostname = argv[optind];
        error = NULL;
        port = (unsigned short) strtoul(argv[optind + 1], &error, 10);
        if (*error != '\0') {
            error("Invalid port [%s]\n", argv[optind + 1]);
            error_exit();
        }
    } else {
        error("Incorrect positional arguments provided.\n");
        error_exit();
    }
    
    // 4 Init Socket
    p_state->dest.sin_addr.s_addr = ((struct in_addr *)(gethostbyname(hostname)->h_addr))->s_addr;
    //inet_addr(gethostbyname(hostname));
    p_state->dest.sin_family = AF_INET;
    p_state->dest.sin_port = htons(port);
}
