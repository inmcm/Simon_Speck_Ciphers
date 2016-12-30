#ifndef SIMON_H
#define SIMON_H

#ifndef CIPHER_CONSTANTS
#define CIPHER_CONSTANTS
enum mode_t { ECB, CTR, CBC, CFB, OFB };
#endif

enum simon_cipher_config_t { Simon_64_32,
                       Simon_72_48,
                       Simon_96_48,
                       Simon_96_64,
                       Simon_128_64,
                       Simon_96_96,
                       Simon_144_96,
                       Simon_128_128,
                       Simon_192_128,
                       Simon_256_128
}; 

typedef struct {
  enum simon_cipher_config_t cipher_cfg;
  uint8_t key_size;
  uint8_t block_size;
  uint8_t round_limit;
  uint8_t init_vector[16];
  uint8_t counter[16];  
  uint8_t key_schedule[576];
  uint8_t z_seq;
} Simon_Cipher;

typedef struct _bword_24{
  uint32_t data: 24;
} bword_24;

typedef struct _bword_48{
  uint64_t data: 48;
} bword_48;

uint8_t Simon_Init(Simon_Cipher *cipher_object, enum simon_cipher_config_t cipher_cfg, enum mode_t c_mode, void *key, uint8_t *iv, uint8_t *counter);

uint8_t Simon_Encrypt(Simon_Cipher cipher_object, void *plaintext, void *ciphertext);

void Simon_Encrypt_32(uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext);
void Simon_Encrypt_48(uint8_t round_limit, uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext);
void Simon_Encrypt_64(uint8_t round_limit, uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext);
void Simon_Encrypt_96(uint8_t round_limit, uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext);
void Simon_Encrypt_128(uint8_t round_limit, uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext);

uint8_t Simon_Decrypt(Simon_Cipher cipher_object, void *ciphertext, void *plaintext);
void Simon_Decrypt_32(uint8_t *key_schedule, uint8_t *ciphertext, uint8_t *plaintext);
void Simon_Decrypt_48(uint8_t round_limit, uint8_t *key_schedule, uint8_t *ciphertext, uint8_t *plaintext);
void Simon_Decrypt_64(uint8_t round_limit, uint8_t *key_schedule, uint8_t *ciphertext, uint8_t *plaintext);
void Simon_Decrypt_96(uint8_t round_limit, uint8_t *key_schedule, uint8_t *ciphertext, uint8_t *plaintext);
void Simon_Decrypt_128(uint8_t round_limit, uint8_t *key_schedule, uint8_t *ciphertext, uint8_t *plaintext);

#endif