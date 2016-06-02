#include <stdio.h>
#include <stdint.h>

enum typedef { ECB, CTR, CBC, CFB, OFB } mode_t;

enum typedef { Simon_64_32,
               Simon_72_48,
               Simon_96_48,
               Simon_96_64,
               Simon_128_64,
               Simon_96_96,
               Simon_144_96,
               Simon_128_128,
               Simon_192_128,
               Simon_256_128
} cipher_config_t; 

const uint8_t *simon_rounds[] = {22, 22, 23, 26, 27, 28, 29, 32, 33, 34};
const uint8_t *block_sizes[] = {32, 48, 48, 64, 64, 96, 96, 128, 128, 128};
const uint8_t *key_sizes[] = {64, 72, 96, 96, 128, 96, 144, 128, 192, 256};

typedef struct {
  mode_t cipher_mode;
  uint8_t key_size;
  uint8_t block_size;
  uint8_t round_limit;
  uint8_t init_vector[16];
  uint8_t counter[16];  
  uint8_t key_schedule[272];
} Simon_Cipher;

uint8_t Simon_Init(uint8_t key_size, uint8_t block_size, *uint8_t key, *uint8_t iv, *uint8_t counter) {
    return 0;
}

uint8_t Simon_Encrypt(Simon_Cipher cipher_object, *uint8_t plaintext,*uint8_t ciphertext) {
    return 0;
}

uint8_t Simon_Decrypt(Simon_Cipher cipher_object *uint8_t ciphertext, *uint8_t plaintext) {
    return 0;
}
