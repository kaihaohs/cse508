//
//  server.c
//  hw3n
//
//  Created by Kaihao Li on 2017/11/10.
//  Copyright © 2017 Kaihao Li. All rights reserved.
//

#include "pbproxy.h"
#include "debug.h"

extern state_t * pg_state;

int do_connect_sshd(connection_t *conn){
    int ssh_fd;
    ssh_fd = socket(AF_INET, SOCK_STREAM, 0);
    
    if (connect(ssh_fd, (struct sockaddr *)&conn->sshaddr, sizeof(conn->sshaddr)) == -1) {
        fprintf(stderr, "[Error] Connect to ssh failed!\n");
        pthread_exit(0);
    }
    fprintf(stderr, "[-] Establish Connection to sshd!\n");
    return ssh_fd;
}

void* server_process(void* ptr) {
    if (!ptr) pthread_exit(0);
    
    debug("[-] New thread started\n");
    
    connection_t *conn = (connection_t *)ptr;
    unsigned char buffer[256];
    int ssh_fd, n;
    boolean ssh_done = false;
    
    memset(buffer, '\0', sizeof(buffer));
    // 1 Connect to sshd
    ssh_fd = do_connect_sshd(conn);
    
    // 2 Setting
    int flags;
    flags = fcntl(conn->sock, F_GETFL);
    if (flags == -1) {
        printf("[Error] Read sock 1 flag error! -> Exit\n");
        close(conn->sock);
        close(ssh_fd);
        free(conn);
        pthread_exit(0);
    }
    
    // 3 Flags
    fcntl(conn->sock, F_SETFL, flags | O_NONBLOCK);
    
    flags = fcntl(ssh_fd, F_GETFL);
    if (flags == -1) {
        printf("[Error] Read ssh_fd flag error!\n");
        pthread_exit(0);
    }
    fcntl(ssh_fd, F_SETFL, flags | O_NONBLOCK);
    
    ctr_encrypt_t state;
    AES_KEY aes_key;
    unsigned char iv[8];
    
    if (AES_set_encrypt_key(conn->key, 128, &aes_key) < 0) {
        fprintf(stderr, "[Error] Set encryption key error!\n");
        error_exit();
    }
    
    while (1) {
        // Read Message From Client
        while ((n = read(conn->sock, buffer, 256)) > 0) {
            if (n < 8) {
                printf("[Error] Incorrect Package\n");
                close(conn->sock);
                close(ssh_fd);
                free(conn);
                pthread_exit(0);
            }
            
            memcpy(iv, buffer, 8);
            //n = n - 8;
            n = strlen(buffer + 8);
            
            unsigned char* decryption = malloc(n * sizeof(u_char));
            init_ctr(&state, iv);
            
            AES_ctr128_encrypt(buffer + 8, decryption, n, &aes_key, state.ivec, state.ecount, &(state.num));
            write(ssh_fd, decryption, n);
            fprintf(stderr, "[Relay to SSHD] Message (%d bytes)\n", n);
            free(decryption);
            memset(buffer, '\0', sizeof(buffer));
            if (n + 8 < 256)
                break;
        };
        
        // Read Message from SSHD
        while ((n = read(ssh_fd, buffer, 256)) >= 0) {
            if (n > 0) {
                if(!RAND_bytes(iv, 8)) {
                    fprintf(stderr, "[Error] Init IVs.\n");
                    pthread_exit(0);
                }
                char *tmp = (char*)malloc(n + 8);
                memcpy(tmp, iv, 8);
                
                unsigned char* encryption = malloc( n * sizeof(u_char));
                init_ctr(&state, iv);
                AES_ctr128_encrypt(buffer, encryption, n, &aes_key, state.ivec, state.ecount, &(state.num));
                memcpy(tmp+8, encryption, n);
                free(encryption);
                fprintf(stderr, "[Relay to Client] Message (%d bytes)\n", n);
                write(conn->sock, tmp, n + 8);
                
                free(tmp);
                memset(buffer, '\0', sizeof(buffer));
            }
            
            if (ssh_done == false && n == 0)
                ssh_done = true;
            
            if (n < 256) break;
        }
        if (ssh_done)   break;
    }
    
    printf("[-] exit thread and close connection\n");
    close(conn->sock);
    close(ssh_fd);
    free(conn);
    pthread_exit(0);
}

int do_listen(){
    int listen_fd;
    struct sockaddr_in serv_addr;
    int listen_port = atoi(pg_state->str_src_port);
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htons(INADDR_ANY);
    serv_addr.sin_port = htons(listen_port);
    
    bind(listen_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    
    if (listen(listen_fd, 5) < 0) {
        fprintf(stderr, "[Error] Listen failed!\n");
        error_exit();
    };
    return listen_fd;
}

int run_server(){
    connection_t *connection;
    pthread_t thread;
    
    // 1 Listen Receice Port
    int listen_fd = do_listen();
    
    // 2 Init sshd socket Info
    struct sockaddr_in ssh_addr;
    ssh_addr.sin_family = AF_INET;
    ssh_addr.sin_port = htons(pg_state->dst_port);
    ssh_addr.sin_addr.s_addr = ((struct in_addr *)(pg_state->host->h_addr))->s_addr;
    
    while (1) {
        // 3 Thread
        connection = (connection_t *)malloc(sizeof(connection_t));
        connection->sock = accept(listen_fd, &connection->address, &connection->addr_len);
        if (connection->sock > 0) {
            connection->sshaddr = ssh_addr;
            connection->key = pg_state->key;
            pthread_create(&thread, 0, server_process, (void*)connection);
            pthread_detach(thread);
        } else {
            free(connection);
        }
    }
}

void print_server(){
    fprintf(stderr, "< Init pbproxy as [server] >\n\
            [key] %s\n\
            [from host] localhost(this machine)\n\
            [from port] %s\n\
            [to host] %s\n\
            [to port] %s\n"\
            ,pg_state->str_key, //pg_state->str_src,
            pg_state->str_src_port,
            pg_state->str_dst,
            pg_state->str_dst_port);
}
