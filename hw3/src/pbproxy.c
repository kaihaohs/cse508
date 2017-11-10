//
//  pbproxy.c
//  hw3
//
//  Created by Kaihao Li on 2017/11/9.
//  Copyright © 2017 Kaihao Li. All rights reserved.
//
#include "pbproxy.h"

int main(int argc, char *argv[]) {
    // 1 Parse Argument -> program state
    parse_args(argc, argv);
    
    // 2 Run Server or Client
    if(pg_state->is_server){
        print_server();
        run_server();
    }else{
        print_client();
        run_client();
    }
    exit(EXIT_SUCCESS);
}

void
init_ctr(ctr_encrypt_t* state, const unsigned char iv[8]) {
    // aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the first call.
    state->num = 0;
    memset(state->ecount, 0, AES_BLOCK_SIZE);
    
    // Initialise counter in 'ivec' to 0
    memset(state->ivec + 8, 0, 8);
    
    // Copy IV into 'ivec'
    memcpy(state->ivec, iv, 8);
}

char* read_file(const char* filename) {
    char *buffer = 0;
    long length;
    FILE *f = fopen (filename, "rb");
    
    if (f) {
        fseek (f, 0, SEEK_END);
        length = ftell (f);
        fseek (f, 0, SEEK_SET);
        buffer = malloc (length);
        if (buffer)
            fread (buffer, 1, length, f);
        fclose (f);
    } else
        return 0;
    
    return buffer;
}

/*
void test(){
    char buffer[BUF_SIZE];
    int sockfd;
    int port = 2223;
    struct sockaddr_in serv_addr, ssh_addr;
    
    // 1 Create a socket point
    if((sockfd = socket(AF_INET, SOCK_STREAM, 0) < 0)){
        fprintf(stderr, "Create socket error!");
        error_exit();
    }
    
    // 2 Get Host Address
    struct hostent *server;
    server = gethostbyname("localhost");//argv[1]);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }
    
    // 3 Setting
    bzero((char *) &serv_addr, sizeof(serv_addr));
    //bzero(&serv_addr, sizeof(ssh_addr));
    serv_addr.sin_family = AF_INET;                 // IP
    //pg_state->dst_port); // Server Port
    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    //serv_addr.sin_addr.s_addr = ((struct in_addr *)(pg_state->host->h_addr));//->s_addr;
    serv_addr.sin_port = htons(port);
    
    
    // 3 Connect to Server
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
        fprintf(stderr, "Connection failed!\n");
        error_exit();
    }
    
    
    
    fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
     fcntl(sockfd, F_SETFL, O_NONBLOCK);
     
     ctr_encrypt_t state;
     unsigned char iv[8];
     AES_KEY aes_key;
     
     if (AES_set_encrypt_key(pg_state->key, 128, &aes_key) < 0) {
     fprintf(stderr, "Set encryption key error!\n");
     error_exit();
     }
     long n;
     while(1) {
     // Read from the Terminal or Standard Input
     while ((n = read(STDIN_FILENO, buffer, BUF_SIZE)) > 0) {
     if(!RAND_bytes(iv, 8)) {
     fprintf(stderr, "Error generating random bytes.\n");
     exit(1);
     }
     char *tmp = (char*)malloc(n + 8);
     memcpy(tmp, iv, 8);
     
     unsigned char encryption[n];
     init_ctr(&state, iv);
     AES_ctr128_encrypt(buffer, encryption, n, &aes_key, state.ivec, state.ecount, &(state.num));
     memcpy(tmp+8, encryption, n);
     //fprintf(stderr, "Then %d bytes encrypted message\n", n);
     write(sockfd, tmp, n + 8);
     //write(sockfd, "lalalala", 8);
     free(tmp);
     if (n < BUF_SIZE)
     break;
     }
     }
}*/
