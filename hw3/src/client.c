//
//  client.c
//  hw3
//
//  Created by Kaihao Li on 2017/11/12.
//  Copyright © 2017 Kaihao Li. All rights reserved.
//
#include "client.h"
#include "pbproxy.h"
#include "debug.h"
#include "encrypt.h"

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

static void close_out(int out_fd){
    info("Exit & close out!\n");
    close(out_fd);
}

// Relay traffic
static void client_proxy(int in_fd, int out_fd, encryption_key_t *key,
                  counter_state_t *instate, counter_state_t *outstate) {
    
    unsigned char buffer[BUFFER_SIZE];
    ssize_t bytes_read, bytes_written;
    fd_set rset;
    
    while (1) {
        
        // Reset Socket
        FD_ZERO(&rset);
        FD_SET(in_fd, &rset);
        FD_SET(out_fd, &rset);
        
        int max = in_fd > out_fd ? in_fd + 1 : out_fd + 1;
        
        // Wait
        if (select(max, &rset, NULL, NULL, NULL) < 0) {
            error("select failed\n");
            close_out(out_fd);
            return;
        }
        
        // With Terminal
        if (FD_ISSET(in_fd, &rset)) {
            // Read
            if ((bytes_read = read(in_fd, buffer, BUFFER_SIZE)) < 1) {
                close_out(out_fd);
                return;
            }
            
            // Encrypt and write data to destination
            if ((bytes_written = write_encrypted(out_fd, key, instate, buffer, bytes_read)) <= 0)
            {
                error("[Relay] send decrypted data!\n");
                close_out(out_fd);
                return;
            }
        }
        
        // With Server
        if (FD_ISSET(out_fd, &rset)) {
            if ((bytes_read = read(out_fd, buffer, BUFFER_SIZE)) < 1) {
                error("[Rev] %ld bytes \n", bytes_read);
                close_out(out_fd);
                return;
            }
            
            // Encrypt and write data to destination
            if ((bytes_written = write_decrypted(STDOUT_FILENO, key, outstate, buffer, bytes_read)) <= 0) {
                error("[Relay] receive decrypted data!\n");
                close_out( out_fd);
                return;
            }
        }
    }
    close_out(out_fd);
    return;
}

void
run_client(struct sockaddr_in dest, encryption_key_t *key) {
    
    // 1 Connect to Dest
    int destfd = connect_dest(dest);
    if(destfd < 0)
        return;
    
    // 2 Init IVs
    unsigned char client_iv[AES_BLOCK_SIZE];
    unsigned char server_iv[AES_BLOCK_SIZE];
    memset(client_iv, 0, AES_BLOCK_SIZE);
    memset(server_iv, 0, AES_BLOCK_SIZE);
    
    if(!RAND_bytes(client_iv, AES_BLOCK_SIZE)) {
        error("Could not create random bytes for iv.\n");
        return;
    }
    
    // 3 Exchange IVs
    memset(client_iv + 8, 0, 8);
    write(destfd, client_iv, AES_BLOCK_SIZE);    // Send IV to the server
    read(destfd, server_iv, AES_BLOCK_SIZE);     // Wait for the server's IV
    
    // 4 Initialize counter states
    counter_state_t client_state, server_state;
    init_counter(&client_state, client_iv);
    init_counter(&server_state, server_iv);
    
    // 5 Start the relay proxy
    client_proxy(STDIN_FILENO, destfd, key, &client_state, &server_state);
}
