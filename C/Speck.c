#include <stdio.h>
#include <stdint.h>

enum typedef { ECB, CTR, CBC, CFB, OFB } mode_t;

enum typedef { Speck_64_32,
               Speck_72_48,
               Speck_96_48,
               Speck_96_64,
               Speck_128_64,
               Speck_96_96,
               Speck_144_96,
               Speck_128_128,
               Speck_192_128,
               Speck_256_128
} cipher_config_t; 

const uint8_t *speck_rounds[] = {22, 22, 23, 26, 27, 28, 29, 32, 33, 34};
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
} Speck_Cipher;

uint8_t Speck_Init(cipher_config_t c_mode, *uint8_t key, *uint8_t iv, *uint8_t counter) {
    return 0;
}

uint8_t Speck_Encrypt(Speck_Cipher cipher_object, *uint8_t plaintext,*uint8_t ciphertext) {
    return 0;
}

uint8_t Speck_Decrypt(Speck_Cipher cipher_object *uint8_t ciphertext, *uint8_t plaintext) {
    return 0;
}
