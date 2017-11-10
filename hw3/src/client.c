//
//  client.c
//  hw3
//
//  Created by Kaihao Li on 2017/11/9.
//  Copyright © 2017 Kaihao Li. All rights reserved.
//

#include "pbproxy.h"

extern state_t * pg_state;

/**
 *  Connect to the Server Port
 **/
int do_connect(){
    int sockfd, portno;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    
    // 1 Create a socket point
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "[ERROR] open socket");
        error_exit();
    }
    
    // 2 Get Host Info
    server = pg_state->host;//gethostbyname("localhost");
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    portno = pg_state->dst_port;    //2223
    serv_addr.sin_port = htons(portno);
    
    // 3 Now connect to the server
    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        fprintf(stderr, "[ERROR] connect to %s:%d",
                pg_state->str_dst, portno);
        error_exit();
    }
    
    return sockfd;
}

int run_client(){
    int sockfd;
    char buffer[256];
    
    // 1 Connect the Server
    sockfd = do_connect();
    
    fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
    fcntl(sockfd, F_SETFL, O_NONBLOCK);
    
    // 2 Init Encryption
    ctr_encrypt_t state;
    unsigned char iv[8];
    AES_KEY aes_key;
    
    if (AES_set_encrypt_key(pg_state->key, 128, &aes_key) < 0) {
        fprintf(stderr, "[ERROR] Init encryption key!\n");
        error_exit();
    }
    
    unsigned long n;
    int num;
    while(1) {
        while((num = read(STDIN_FILENO, buffer, 256) > 0)){
            if(!RAND_bytes(iv, 8)) {
                fprintf(stderr, "[Error] Generate random IV!\n");
                error_exit();
            }
            n = strlen(buffer);
            char *tmp = (char*)malloc(n + 8);
            memcpy(tmp, iv, 8);
            
            // Encrypt Read Info
            unsigned char * encryption = malloc(n * sizeof(u_char));
            init_ctr(&state, iv);
            AES_ctr128_encrypt(buffer, encryption, n, &aes_key, state.ivec, state.ecount, &(state.num));
            memcpy(tmp + 8, encryption, n);
            free(encryption);
            
            // Write to socket handler
            fprintf(stderr, "Sent %lu bytes encrypted message!\n", n);
            write(sockfd, tmp, n + 8);
            free(tmp);
        }
        
        while ((num = read(sockfd, buffer, 256)) > 0) {
            printf("%d\n",num);
            if (num < 8) {
                fprintf(stderr, "[Error] Packet length is too short!\n");
                close(sockfd);
                error_exit();
            }
            n = num - 8;
            memcpy(iv, buffer, 8);
            
            unsigned char decryption[num];
            init_ctr(&state, iv);
            
            AES_ctr128_encrypt(buffer+8, decryption, n, &aes_key, state.ivec, state.ecount, &(state.num));
            
            write(STDOUT_FILENO, decryption, n);
            if (num < 256)
                break;
        }
    }
    return 0;
}

void print_client(){
    fprintf(stderr, "< Init pbproxy as [client] >\n\
    [key] %s\n\
    [server host] %s\n\
    [server port] %s\n"\
    ,pg_state->str_key,
    pg_state->str_dst,
    pg_state->str_dst_port);
}
