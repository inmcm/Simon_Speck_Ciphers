// cipher_constants.h
#ifndef CIPHER_CONSTANTS_H
#define CIPHER_CONSTANTS_H

enum mode_t { ECB, CTR, CBC, CFB, OFB };

static const uint8_t block_sizes[] = {32, 48, 48, 64, 64, 96, 96, 128, 128, 128};

static const uint16_t key_sizes[] = {64, 72, 96, 96, 128, 96, 144, 128, 192, 256};

enum cipher_config_t {
    cfg_64_32,
    cfg_72_48,
    cfg_96_48,
    cfg_96_64,
    cfg_128_64,
    cfg_96_96,
    cfg_144_96,
    cfg_128_128,
    cfg_192_128,
    cfg_256_128
} ;

typedef struct {
    enum cipher_config_t cipher_cfg;
    void (*encryptPtr)(const uint8_t, const uint8_t *, const uint8_t *, uint8_t *);
    void (*decryptPtr)(const uint8_t, const uint8_t *, const uint8_t *, uint8_t *);
    uint16_t key_size;
    uint8_t block_size;
    uint8_t round_limit;
    uint8_t init_vector[16];
    uint8_t counter[16];
    uint8_t key_schedule[576];
    uint8_t alpha;
    uint8_t beta;
    uint8_t z_seq;
} SimSpk_Cipher;

#endif