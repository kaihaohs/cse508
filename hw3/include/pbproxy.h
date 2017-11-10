//
//  pbproxy.h
//  hw3
//
//  Created by Kaihao Li on 2017/11/9.
//  Copyright © 2017 Kaihao Li. All rights reserved.
//

#ifndef pbproxy_h
#define pbproxy_h
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>

typedef enum { false, true } boolean;

typedef struct
{
    boolean is_server;
    char* str_src_port;
    char* str_key;
    char* str_dst;
    char* str_dst_port;
    const unsigned char* key;
    int src_port;
    int dst_port;
    struct hostent *host;
} state_t;

#define BUF_SIZE 4096

typedef struct {
    int sock;
    struct sockaddr address;
    struct sockaddr_in sshaddr;
    uint addr_len;
    const u_char *key;
} connection_t;

typedef struct {
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned int num;
    unsigned char ecount[AES_BLOCK_SIZE];
}ctr_encrypt_t;

state_t * pg_state;

void parse_args(int argc, char **argv);
void error_exit(void);
int run_client(void);
int run_server(void);
void print_client(void);
void print_server(void);
void
init_ctr(ctr_encrypt_t* state, const unsigned char iv[8]);
char* read_file(const char* filename);
#endif /* pbproxy_h */
