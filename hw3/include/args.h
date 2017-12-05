//
//  args.h
//  hw3
//
//  Created by Kaihao Li on 2017/11/11.
//  Copyright © 2017 Kaihao Li. All rights reserved.
//

#ifndef args_h
#define args_h

#include <stdio.h>
#include "pbproxy.h"
#include "encrypt.h"

typedef struct
{
    int proxy_port;
    boolean is_server;
    char* keyfile;
    encryption_key_t key;
    struct sockaddr_in dest;
} state_t;

void parse_args(int argc, char **argv);

#endif /* args_h */
