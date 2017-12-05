#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/aes.h>
#include "encrypt.h"
#include "debug.h"

void init_counter(counter_state_t *state, const unsigned char iv[16]) {
    memset(state, 0, sizeof(counter_state_t));
    /* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the first call. */
    state->num = 0;
    memset(state->ecount, 0, AES_BLOCK_SIZE);
    /* Copy IV into 'ivec' */
    memcpy(state->ivec, iv, AES_BLOCK_SIZE);
}

ssize_t write_encrypted(int writefd, encryption_key_t *key, counter_state_t *state,
                        unsigned char *buffer, size_t size) {
    ssize_t bytes_written = 0;
    unsigned char *outbuff = calloc(0, size * sizeof(unsigned char));
    // Encrypt
    AES_ctr128_encrypt(buffer, outbuff, size, &(key->aeskey), state->ivec,
                       state->ecount, &(state->num));

    // Write the socket
    if ((bytes_written = write(writefd, outbuff, size)) != size) {
        free(outbuff);
        return 0;
    }
    free(outbuff);
    return bytes_written;
}

ssize_t write_decrypted(int writefd, encryption_key_t *key, counter_state_t *state,
                        unsigned char *buffer, size_t size) {
    ssize_t bytes_written = 0;
    unsigned char *outbuff = calloc(0, size * sizeof(unsigned char));

    // Decrypt
    AES_ctr128_encrypt(buffer, outbuff, size, &(key->aeskey), state->ivec,
                       state->ecount, &(state->num));

    // Write the socket
    if ((bytes_written = write(writefd, outbuff, size)) != size) {
        error("bytes_witten: %ld, outsize: %ld\n", bytes_written, size);
        free(outbuff);
        return 0;
    }
    free(outbuff);
    return bytes_written;
}
