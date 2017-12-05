#ifndef PBPROXY_H
#define PBPROXY_H

#define BUFFER_SIZE 1024

#define HELP() do { \
    printf("pbproxy [-l port] -k keyfile destination port\n\n" \
    "-l  Reverse-proxy mode: listen for inbound connections on <port> and relay\n"\
    "    them to <destination>:<port>\n\n"\
    "-k  Use the symmetric key contained in <keyfile> (as a hexadecimal string)\n"); \
} while(0)

typedef enum { false, true } boolean;

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/rand.h>

#endif
