//
//  args.c
//  hw3
//
//  Created by Kaihao Li on 2017/11/9.
//  Copyright © 2017 Kaihao Li. All rights reserved.
//

#include <stdio.h>
#include "pbproxy.h"

state_t * pg_state;

void error_exit(){free(pg_state); exit(EXIT_FAILURE);}

void
parse_args(int argc, char **argv){
    // 1 Parse Argument
    pg_state = calloc(1, sizeof(state_t));
    char opt;
    while ((opt = getopt(argc, argv, "l:k:")) != -1) {
        switch(opt) {
            case 'l':
                pg_state->is_server = true;
                pg_state->str_src_port = optarg;
                break;
            case 'k':
                pg_state->str_key = optarg;
                break;
            case '?':
                fprintf(stderr, "pbproxy : Error arguments\n");
                error_exit();
                break;
            default:
                fprintf(stderr, "pbproxy : Error arguments\n");
                error_exit();
        }
    }
    
    // 2 Check positional argument
    if(!pg_state->str_key){
        fprintf(stderr, "[pbproxy] Invalid key file!\n");
        error_exit();
    }
    
    // 3 Set port
    if (optind == argc - 2) {
        pg_state->str_dst = argv[optind];
        pg_state->str_dst_port = argv[optind+1];
    } else{
        fprintf(stderr, "[pbproxy] Invalid destination and port arguments!\n");
        error_exit();
    }
    
    // 4
    pg_state->key = read_file(pg_state->str_key);
    //unsigned const char *key = read_file(pg_state->str_key);
    if (!pg_state->key) {
        fprintf(stderr, "read key file failed!\n");
        error_exit();
    }
    if ((pg_state->host = gethostbyname(pg_state->str_dst)) == 0) {
        fprintf(stderr, "No such host!\n");
        error_exit();
    }
    
    pg_state->dst_port = atoi(pg_state->str_dst_port);
}
