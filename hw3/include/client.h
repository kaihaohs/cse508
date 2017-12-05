//
//  client.h
//  hw3
//
//  Created by Kaihao Li on 2017/11/12.
//  Copyright © 2017 Kaihao Li. All rights reserved.
//


#ifndef client_h
#define client_h

#include "encrypt.h"
#include <sys/select.h>
#include <sys/socket.h>
#include <arpa/inet.h>

void
run_client(struct sockaddr_in dest, encryption_key_t *key);
#endif /* client_h */
