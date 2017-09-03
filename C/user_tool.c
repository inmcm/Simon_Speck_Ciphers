//
// Created by Calvin McCoy on 9/2/17.
//

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef __APPLE__
#include <fcntl.h>
#endif

#include "Simon.h"
#include "Speck.h"

/* Usage
 $ ./user encrypt/decrypt cipher mode keyfile file

*/
void print_hex(uint8_t *data, uint64_t data_len);


int main(int argc, char *argv[]) {
    int i;
    printf("Hello!\n");
    for (i=0; i < argc; i++) {
        printf("arg%d: %s\n", i, argv[i]);
    }

    static const uint16_t key_size_bits = 64;
    static const uint16_t block_size_bits = 32;
    static const uint8_t  block_size = block_size_bits >> 3;

    FILE *key_fd;
    key_fd = fopen(argv[4],"rb");
    fseek(key_fd, 0L, SEEK_END);
    size_t key_file_size = (size_t)ftell(key_fd);
    size_t  key_size = key_size_bits >> 3;
    printf("Key File Size (Bits): %zu\n", key_file_size*8);
    if (key_size > key_file_size) {
        fprintf(stderr, "Insufficient Key Bytes! Found:%zu  Need %zu\n", key_file_size, key_size);
        return -1;
    }

    rewind(key_fd);
    uint8_t *key_buffer = malloc((size_t)key_size);
    fread(key_buffer, 1, key_size, key_fd);
    print_hex(key_buffer, key_size);
    fclose(key_fd);



    FILE *in_fd;
    in_fd = fopen(argv[5],"rb");
    fseek(in_fd, 0L, SEEK_END);
    size_t input_size = (size_t)ftell(in_fd);
    printf("File Size: %zX\n", input_size);
    rewind(in_fd);
    uint8_t *working_buffer = malloc((size_t)input_size);
    fread(working_buffer, 1, input_size, in_fd);
    fclose(in_fd);
    print_hex(working_buffer, 64);


    Simon_Cipher my_simon_cipher;
    int result = Simon_Init(&my_simon_cipher, Simon_64_32, ECB, key_buffer, NULL, NULL);
    if (result) {
        fprintf(stderr, "Failed to Init Cipher\n");
        return result;
    }

    uint8_t *backup_buffer = working_buffer;
    for(int block=0; block < input_size / block_size; block++){
        printf("Encrypting Block %d\n", block);
        Simon_Encrypt(my_simon_cipher, working_buffer, working_buffer);
        working_buffer += block_size;
    }

    print_hex(backup_buffer, input_size);


    working_buffer = backup_buffer;
    for(int block=0; block < input_size / block_size; block++){
        printf("Decrypting Block %d\n", block);
        Simon_Decrypt(my_simon_cipher, working_buffer, working_buffer);
        working_buffer += block_size;
    }

    print_hex(backup_buffer, input_size);

    FILE *out_fd;
    out_fd = fopen("outputext.txt","wb");
    fwrite(backup_buffer, 1, input_size, out_fd);
    fclose(out_fd);

    /* Free ALl Buffers */
    free(key_buffer);
    free(backup_buffer);
    printf("All done!\n");
    return  0;
}


void print_hex(uint8_t *data, uint64_t data_len) {
    uint64_t line_limit = (data_len % 16) > 0 ? 1 : 0;
    line_limit += data_len >> 4;
    uint64_t element = 0;
    for (uint64_t line=0; line<line_limit; line++) {
        printf("%04X   ", line);
        uint8_t element_limit = data_len-element >= 16 ? 16 : data_len-element;
        for (uint8_t element_cnt=0; element_cnt < element_limit; element_cnt++) {
            printf("%02X ", data[element++]);
        }
        printf("\n");
    }
    printf("\n");
}