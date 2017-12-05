//
//  server.h
//  hw3
//
//  Created by Kaihao Li on 2017/11/12.
//  Copyright © 2017 Kaihao Li. All rights reserved.
//

#ifndef server_h
#define server_h

#include "encrypt.h"
#include <sys/select.h>
#include <sys/socket.h>
#include <arpa/inet.h>

void
run_server(struct sockaddr_in dest, int proxyport, encryption_key_t *key);
#endif /* server_h */
