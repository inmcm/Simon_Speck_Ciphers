//
// Created by Calvin McCoy on 9/2/17.
//

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "string.h"
#ifdef __APPLE__
#include <fcntl.h>
#endif

#include "cipher_constants.h"
#include "simon.h"
#include "speck.h"


/* Usage
 $ ./user simon_256_128 ECB -e keyfile input output

*/
void print_hex(uint8_t *data, uint64_t data_len);


#define SIMON 0
#define SPECK 1
#define ENCRYPT 0
#define DECRYPT 1

const static struct {
    const char *str;
    uint8_t     index;
    uint8_t     cipher;
} valid_cfgs [] = {
        {"simon_64_32", 0, SIMON},
        {"simon_72_48", 1, SIMON},
        {"simon_96_48", 2, SIMON},
        {"simon_96_64", 3, SIMON},
        {"simon_128_64", 4, SIMON},
        {"simon_96_96", 5, SIMON},
        {"simon_144_96", 6, SIMON},
        {"simon_128_128", 7, SIMON},
        {"simon_192_128", 8, SIMON},
        {"simon_256_128", 9, SIMON},
        {"speck_64_32", 0, SPECK},
        {"speck_72_48", 1, SPECK},
        {"speck_96_48", 2, SPECK},
        {"speck_96_64", 3, SPECK},
        {"speck_128_64", 4, SPECK},
        {"speck_96_96", 5, SPECK},
        {"speck_144_96", 6, SPECK},
        {"speck_128_128", 7, SPECK},
        {"speck_192_128", 8, SPECK},
        {"speck_256_128", 9, SPECK}
};


int main(int argc, char *argv[]) {
    int i;
    printf("Hello!\n");
    for (i=0; i < argc; i++) {
        printf("arg%d: %s\n", i, argv[i]);
    }

    uint8_t cfg_index = 255;
    uint8_t cfg_cipher;
    uint8_t cfg_dir;



    for (int j = 0;  j < sizeof (valid_cfgs) / sizeof (valid_cfgs[0]);  ++j) {
        if (!strcmp(argv[1], valid_cfgs[j].str))
            cfg_index = valid_cfgs[j].index;
            cfg_cipher = valid_cfgs[j].cipher;
    }
    if (255 == cfg_index) {
        fprintf(stderr, "Not a Valid Simon/Speck Cipher Configuration");
        return -1;
    }

    const uint16_t key_size_bits = key_sizes[cfg_index];
    const uint8_t block_size_bits = block_sizes[cfg_index];
    const uint8_t  block_size = block_size_bits >> 3;


    // Set Cipher Direction: -e -> Encrypt, -d -> Decrypt
    if (!strncmp(argv[3], "-e", 2)) cfg_dir = ENCRYPT;
    else if (!strncmp(argv[3], "-d", 2)) cfg_dir = DECRYPT;
    else {
        fprintf(stderr, "Can Only Encrypt or Decrypt");
        return -1;
    }

   // Read In Key Bytes
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
    fclose(key_fd);


    // Read in Input Data to Allocated Array
    FILE *in_fd;
    in_fd = fopen(argv[5],"rb");
    fseek(in_fd, 0L, SEEK_END);
    size_t input_size = (size_t)ftell(in_fd);
    printf("File Size: %zX\n", input_size);
    rewind(in_fd);
    uint8_t *working_buffer = malloc((size_t)input_size);
    fread(working_buffer, 1, input_size, in_fd);
    fclose(in_fd);



    Simon_Cipher my_simon_cipher;
    int result = Simon_Init(&my_simon_cipher, Simon_256_128, ECB, key_buffer, NULL, NULL);
    if (result) {
        fprintf(stderr, "Failed to Init Cipher\n");
        return result;
    }

    uint8_t *backup_buffer = working_buffer;
    for(int block=0; block < input_size / block_size; block++){
//        printf("Encrypting Block %d\n", block);
        Simon_Encrypt(my_simon_cipher, working_buffer, working_buffer);
        working_buffer += block_size;
    }

//    print_hex(backup_buffer, input_size);


    working_buffer = backup_buffer;
    for(int block=0; block < input_size / block_size; block++){
//        printf("Decrypting Block %d\n", block);
        Simon_Decrypt(my_simon_cipher, working_buffer, working_buffer);
        working_buffer += block_size;
    }

//    print_hex(backup_buffer, input_size);

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
