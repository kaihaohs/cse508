//
//  pbproxy.c
//  hw3
//
//  Created by Kaihao Li on 2017/11/9.
//  Copyright © 2017 Kaihao Li. All rights reserved.
//

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>

#define BUF_SIZE 4096

typedef enum { false, true } boolean;

typedef struct
{
    boolean is_server;
    char* str_src_port;
    char* str_key;
    char* str_dst;
    char* str_dst_port;
    const char* key;
    int src_port;
    int dst_port;
    struct hostent *host;
} state_t;

typedef struct {
    int sock;
    struct sockaddr address;
    struct sockaddr_in sshaddr;
    int addr_len;
    const u_char *key;
} connection_t;

typedef struct {
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned int num;
    unsigned char ecount[AES_BLOCK_SIZE];
}ctr_encrypt_t;

state_t * pg_state;
void parse_args(int argc, char **argv);
void error_exit(){free(pg_state); exit(EXIT_FAILURE);}

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

void
parse_args(int argc, char **argv){
    // 1 Parse Argument
    pg_state = calloc(1, sizeof(state_t));
    char opt;
    while ((opt = getopt(argc, argv, "l:k:")) != -1) {
        switch(opt) {
            case 'l':
                pg_state->is_server = true;
                pg_state->str_src_port = optarg;
                break;
            case 'k':
                pg_state->str_key = optarg;
                break;
            case '?':
                fprintf(stderr, "pbproxy : Error arguments\n");
                error_exit();
                break;
            default:
                fprintf(stderr, "pbproxy : Error arguments\n");
                error_exit();
        }
    }
    
    // 2 Check positional argument
    if(!pg_state->str_key){
        fprintf(stderr, "[pbproxy] Invalid key file!\n");
        error_exit();
    }
    
    // 3 Set port
    if (optind == argc - 2) {
        pg_state->str_dst = argv[optind];
        pg_state->str_dst_port = argv[optind+1];
    } else{
        fprintf(stderr, "[pbproxy] Invalid destination and port arguments!\n");
        error_exit();
    }
    
    // 4
    pg_state->key = read_file(pg_state->str_key);
    //unsigned const char *key = read_file(pg_state->str_key);
     if (!pg_state->key) {
         fprintf(stderr, "read key file failed!\n");
         error_exit();
     }
    if ((pg_state->host = gethostbyname(pg_state->str_dst)) == 0) {
        fprintf(stderr, "Resovle Destination Error!\n");
        error_exit();
    }
    //int dst_port = (int)strtol(str_dst_port, NULL, 10);
    pg_state->dst_port = atoi(pg_state->str_dst_port);
}

void run_client(){
    char buffer[BUF_SIZE];
    int sockfd;
    
    // 1 Init Server
    struct sockaddr_in serv_addr, ssh_addr;
    bzero(&serv_addr, sizeof(serv_addr));
    bzero(&serv_addr, sizeof(ssh_addr));
    serv_addr.sin_family = AF_INET;                 // IP
    serv_addr.sin_port = htons(pg_state->dst_port); // Server Port
    serv_addr.sin_addr.s_addr = ((struct in_addr *)(pg_state->host->h_addr))->s_addr;
    
    // 2 Create sockfd
    if((sockfd = socket(AF_INET, SOCK_STREAM, 0) < 0)){
        fprintf(stderr, "Create socket error!");
        error_exit();
    }
    
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
            //fprintf(stderr, "Then %d bytes encrypted message\n", n);*/
            write(sockfd, tmp, n + 8);
            //write(sockfd, "lalalala", 8);
            free(tmp);
            if (n < BUF_SIZE)
                break;
        }
    }
}
int main(int argc, char *argv[]) {
    // 1 Parse Argument -> program state
    parse_args(argc, argv);
    
    // 2 Run Server or Client
    if(pg_state->is_server){
        //run_server();
    }else{
        run_client();
    }
    
    exit(EXIT_SUCCESS);
}
