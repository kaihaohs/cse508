#ifndef ENCRYPT_H
#define ENCRYPT_H
#include <sys/types.h>
#include <openssl/aes.h>

typedef struct{
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned int num;
    unsigned char ecount[AES_BLOCK_SIZE];
}counter_state_t;

typedef struct{
    unsigned char *value;
    size_t size;
    AES_KEY aeskey;
}encryption_key_t;


void init_counter(counter_state_t *state, const unsigned char iv[16]);

ssize_t write_encrypted(int writefd, encryption_key_t *key, counter_state_t *state,
                        unsigned char *buffer, size_t size);
ssize_t write_decrypted(int writefd, encryption_key_t *key, counter_state_t *state,
                        unsigned char *buffer, size_t size);
#endif
