//
//  server.c
//  hw3
//
//  Created by Kaihao Li on 2017/11/12.
//  Copyright © 2017 Kaihao Li. All rights reserved.
//

#include "server.h"
#include "pbproxy.h"
#include "debug.h"
#include "encrypt.h"

//#include <pthread.h>

static int connect_dest(struct sockaddr_in dest) {
    int destfd;
    
    if ((destfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        error("Unable to create a socket\n");
        return -1;
    }
    
    if (connect(destfd, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        error("Unable to connect\n");
        return -1;
    }
    
    return destfd;
}

static void close_all(int in_fd, int out_fd){
    //info("[Thread] Exit & close!\n");
    if (in_fd != STDIN_FILENO)
        close(in_fd);
    close(out_fd);
}

// Relay traffic
static void server_proxy(int in_fd, int out_fd, encryption_key_t *key,
                  counter_state_t *instate, counter_state_t *outstate) {
    unsigned char buffer[BUFFER_SIZE];
    ssize_t bytes_read, bytes_written;
    fd_set rset;
    
    while (1) {
        
        // Reset Socket
        FD_ZERO(&rset);
        FD_SET(in_fd, &rset);
        FD_SET(out_fd, &rset);
        
        int max_fd = in_fd > out_fd ? in_fd + 1 : out_fd + 1;
        
        // Wait
        if (select(max_fd, &rset, NULL, NULL, NULL) < 0) {
            error("select failed\n");
            close_all(in_fd, out_fd);
            return;
        }
        
        // With Client
        if (FD_ISSET(in_fd, &rset)) {
            // Read
            if ((bytes_read = read(in_fd, buffer, BUFFER_SIZE)) < 1) {
                error("[Input] %ld bytes \n", bytes_read);
                close_all(in_fd, out_fd);
                return;
            }
            
            // Encrypt and write data to destination
            if ((bytes_written = write_encrypted(out_fd, key, instate, buffer, bytes_read)) <= 0)
            {
                error("[Error] Incorrect Keys!\n");
                close_all(in_fd, out_fd);
                return;
            }
        }
        
        // With SSHD
        if (FD_ISSET(out_fd, &rset)) {
            if ((bytes_read = read(out_fd, buffer, BUFFER_SIZE)) < 1) {
                close_all(in_fd, out_fd);
                return;
            }
            
            if ((bytes_written = write_decrypted(in_fd, key, outstate, buffer, bytes_read)) <= 0)
            {
                error("[Relay] receive decrypted data!\n");
                close_all(in_fd, out_fd);
                return;
            }
        }
    }
    close_all(in_fd, out_fd);
    return;
}

static int setupserver(int proxyport) {
    struct sockaddr_in server;
    int server_sock;
    
    if ((server_sock = socket(AF_INET , SOCK_STREAM , 0)) < 0) {
        error("Unable to open socket");
        return -1;
    }
    
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(proxyport);
    
    // Set address reuse
    int optval = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);
    
    // Create the server socket
    if(bind(server_sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        error("Unable to bind the port.");
        return -1;
    }
    
    listen(server_sock, 127);
    
    return server_sock;
}

void server_process(int fd, struct sockaddr_in dest, encryption_key_t *key) {
    info("[Thread %d ] Start!\n", fd);
    
    // Init IVs
    unsigned char clientiv[AES_BLOCK_SIZE];
    unsigned char serveriv[AES_BLOCK_SIZE];
    memset(clientiv, 0, AES_BLOCK_SIZE);
    memset(serveriv, 0, AES_BLOCK_SIZE);
    
    if(!RAND_bytes(serveriv, AES_BLOCK_SIZE)) {
        error("Could not create random bytes for iv.\n");
        info("[Thread %d ] Exit!\n", fd);
        exit(EXIT_FAILURE);
    }
    
    // Exchange IV
    memset(serveriv + 8, 0, 8);
    write(fd, serveriv, AES_BLOCK_SIZE);
    read(fd, clientiv, AES_BLOCK_SIZE);
    
    //
    int destfd = connect_dest(dest);
    
    counter_state_t client_state, server_state;
    init_counter(&client_state, clientiv);
    init_counter(&server_state, serveriv);
    
    // Relay
    server_proxy(destfd, fd, key, &server_state, &client_state);
    
    info("[Thread %d ] Exit!\n", fd);
    exit(EXIT_SUCCESS);
}

void
run_server(struct sockaddr_in dest, int proxyport, encryption_key_t *key) {
    struct sockaddr_in client;
    int proxyclientfd;
    int addrlen = 0;
    
    int proxyfd = setupserver(proxyport);
    if (proxyfd < 0)
        return;
    
    // Begin listening for connections
    while(1) {
        // Wait for a connection
        if ((proxyclientfd = accept(proxyfd, (struct sockaddr*)&client, (socklen_t*)&addrlen)) < 0) {
            error("Failed to create a connection with the client\n");
            continue;
        }
        pid_t pid = fork();
        if(pid == 0){
            server_process(proxyclientfd, dest, key);
        }
    }
}


