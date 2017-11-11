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
    free(pg_state);
    exit(EXIT_SUCCESS);
}

/*
 *  Helper Functions
 */
void
init_ctr(ctr_encrypt_t* state, const unsigned char iv[8]) {
    // aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the first call.
    state->num = 0;
    memset(state->ecount, 0, AES_BLOCK_SIZE);
    memset(state->ivec + 8, 0, 8);      // Initialise counter in 'ivec' to 0
    memcpy(state->ivec, iv, 8);          // Copy IV into 'ivec'
}

char* read_file(const char* filename) {
    char *buffer = 0;
    long length;
    FILE * file = fopen(filename, "rb");
    
    if (!file) return 0;
    
    fseek (file, 0, SEEK_END);
    length = ftell (file);
    fseek (file, 0, SEEK_SET);
    buffer = malloc (length);
    if (buffer)
        fread (buffer, 1, length, file);
    fclose (file);
    return buffer;
}
