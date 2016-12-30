#ifndef SPECK_H
#define SPECK_H

// enum speck_mode_t { ECB, CTR, CBC, CFB, OFB };
// const uint8_t speck_block_sizes[] = {32, 48, 48, 64, 64, 96, 96, 128, 128, 128};
// const uint16_t speck_key_sizes[] = {64, 72, 96, 96, 128, 96, 144, 128, 192, 256};

#ifndef CIPHER_CONSTANTS
#define CIPHER_CONSTANTS
enum mode_t { ECB, CTR, CBC, CFB, OFB };
#endif

enum speck_cipher_config_t { Speck_64_32,
               Speck_72_48,
               Speck_96_48,
               Speck_96_64,
               Speck_128_64,
               Speck_96_96,
               Speck_144_96,
               Speck_128_128,
               Speck_192_128,
               Speck_256_128
} ; 

typedef struct {
    enum speck_cipher_config_t cipher_cfg;
    uint8_t key_size;
    uint8_t block_size;
    uint8_t round_limit;
    uint8_t init_vector[16];
    uint8_t counter[16];  
    uint8_t key_schedule[576];
    uint8_t alpha;
    uint8_t beta;
} Speck_Cipher;

typedef struct _bitword24_t{
  uint32_t data: 24;
} bitword24_t;

typedef struct _bytes3_t{
        uint8_t data[3];
} bytes3_t;

typedef struct _bitword48_t{
  uint64_t data: 48;
} bitword48_t;

typedef struct _bytes6_t{
        uint8_t data[6];
} bytes6_t;


uint8_t Speck_Init(Speck_Cipher *cipher_object, enum speck_cipher_config_t cipher_cfg, enum mode_t c_mode, void *key, uint8_t *iv, uint8_t *counter);

uint8_t Speck_Encrypt(Speck_Cipher cipher_object, void *plaintext, void *ciphertext);

uint8_t Speck_Decrypt(Speck_Cipher cipher_object, uint8_t *ciphertext, uint8_t *plaintext);

void Speck_Encrypt_32(uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext);
void Speck_Encrypt_48(uint8_t round_limit, uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext);
void Speck_Encrypt_64(uint8_t round_limit, uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext);
void Speck_Encrypt_96(uint8_t round_limit, uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext);
void Speck_Encrypt_128(uint8_t round_limit, uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext);

#endif