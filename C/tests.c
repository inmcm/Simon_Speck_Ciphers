// Simon Tests 
#include <stdio.h>
#include <stdint.h>
#include "Simon.h"
#include "Speck.h"

// Function Prototypes
void cipher_compare(const void *source, void *target, size_t n);

// Global Fail count
int fail_count = 0;


void cipher_compare(const void *source, void *target, size_t n) {
    for(size_t i=0; i < n; i++) {
        uint8_t * src_bytes = (uint8_t *)source;
        uint8_t * trg_bytes = (uint8_t *)target;
        printf("Byte %02d: %02x - %02x",i, src_bytes[i], trg_bytes[i]);
        if (src_bytes[i] != trg_bytes[i]) {
            printf("  FAIL\n");
            fail_count++;
        }
        else printf("\n");
    }
}

int main(void){

    // Create reusable cipher objects for each algorithm type
    Simon_Cipher my_simon_cipher;
    Speck_Cipher my_speck_cipher;

    // Create generic tmp variables
    uint8_t ciphertext_buffer[16];
    uint32_t result;

    // Initialize IV and Counter Values for Use with Block Modes
    uint8_t my_IV[] = {0x32,0x14,0x76,0x58};
    uint8_t my_counter[] = {0x2F,0x3D,0x5C,0x7B};

    printf("***********************************\n");
    printf("******* Simon Cipher Tests ********\n");
    printf("***********************************\n");

    // Simon 64/32 Test
    // Key: 1918 1110 0908 0100 Plaintext: 6565 6877 Ciphertext: c69b e9bb
    printf("**** Test Simon 64/32 ****\n");
    uint8_t simon64_32_key[] = {0x00, 0x01, 0x08, 0x09, 0x10, 0x11, 0x18, 0x19};
    uint8_t simon64_32_plain[] = {0x77, 0x68, 0x65, 0x65};
    uint8_t simon64_32_cipher[] = {0xBB,0xE9, 0x9B, 0xC6};
    result = Simon_Init(&my_simon_cipher, Simon_64_32, ECB, simon64_32_key, my_IV, my_counter);

    printf("Encryption Test:\n");
    Simon_Encrypt(my_simon_cipher, &simon64_32_plain, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &simon64_32_cipher, sizeof(simon64_32_cipher));

    printf("Decryption Test:\n");
    Simon_Decrypt(my_simon_cipher, &simon64_32_cipher, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &simon64_32_plain, sizeof(simon64_32_plain));

    printf("\n");


    // Simon 72/48 Test
    // Key: 121110 0a0908 020100 Plaintext: 612067 6e696c Ciphertext: dae5ac 292cac
    printf("**** Test Simon 72/48 ****\n");
    uint8_t simon72_48_key[] = {0x00, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x10, 0x11, 0x12};
    uint8_t simon72_48_plain[] = {0x6c, 0x69, 0x6E, 0x67, 0x20, 0x61};
    uint8_t simon72_48_cipher[] = {0xAC, 0x2C, 0x29, 0xAC, 0xE5, 0xda};
    result = Simon_Init(&my_simon_cipher, Simon_72_48, ECB, simon72_48_key, my_IV, my_counter);

    printf("Encryption Test:\n");
    Simon_Encrypt(my_simon_cipher, &simon72_48_plain, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &simon72_48_cipher, sizeof(simon72_48_cipher));

    printf("Decryption Test:\n");
    Simon_Decrypt(my_simon_cipher, &simon72_48_cipher, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &simon72_48_plain, sizeof(simon72_48_plain));
    printf("\n");


    // Simon 96/48 Test
    // Key: 1a1918 121110 0a0908 020100 Plaintext: 726963 20646e Ciphertext: 6e06a5 acf156
    printf("**** Test Simon 96/48 ****\n");
    uint8_t simon96_48_key[] = {0x00, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x10, 0x11, 0x12, 0x18, 0x19, 0x1a};
    uint8_t simon96_48_plain[] = {0x6e, 0x64, 0x20, 0x63, 0x69, 0x72};
    uint8_t simon96_48_cipher[] = {0x56, 0xf1, 0xac, 0xa5, 0x06, 0x6e};
    result = Simon_Init(&my_simon_cipher, Simon_96_48, ECB, simon96_48_key, my_IV, my_counter);

    printf("Encryption Test:\n");
    Simon_Encrypt(my_simon_cipher, &simon96_48_plain, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &simon96_48_cipher, sizeof(simon96_48_cipher));

    printf("Decryption Test:\n");
    Simon_Decrypt(my_simon_cipher, &simon96_48_cipher, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &simon96_48_plain, sizeof(simon96_48_plain));

    printf("\n");


    // Simon 96/64 Test
    // Key: 13121110 0b0a0908 03020100 Plaintext: 6f722067 6e696c63 Ciphertext: 5ca2e27f 111a8fc8
    printf("**** Test Simon 96/64 ****\n");
    uint8_t simon96_64_key[] = {0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0A, 0x0B, 0x10, 0x11, 0x12, 0x13};
    uint8_t simon96_64_plain[] = {0x63, 0x6c, 0x69, 0x6e, 0x67, 0x20, 0x72, 0x6f};
    uint8_t simon96_64_cipher[] = {0xc8, 0x8f, 0x1a, 0x11, 0x7f, 0xe2, 0xa2, 0x5c};
    result = Simon_Init(&my_simon_cipher, Simon_96_64, ECB, simon96_64_key, my_IV, my_counter);

    printf("Encryption Test:\n");
    Simon_Encrypt(my_simon_cipher, &simon96_64_plain, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &simon96_64_cipher, sizeof(simon96_64_cipher));

    printf("Decryption Test:\n");
    Simon_Decrypt(my_simon_cipher, &simon96_64_cipher, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &simon96_64_plain, sizeof(simon96_64_plain));

    printf("\n");


    // Simon 128/64 Test
    // Key: 1b1a1918 13121110 0b0a0908 03020100 Plaintext: 656b696c 20646e75 Ciphertext: 44c8fc20 b9dfa07a
    printf("**** Test Simon 128/64 ****\n");
    uint8_t simon128_64_key[] = {0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0A, 0x0B, 0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1A, 0x1B};
    uint8_t simon128_64_plain[] = {0x75, 0x6e, 0x64, 0x20, 0x6c, 0x69, 0x6b, 0x65};
    uint8_t simon128_64_cipher[] = {0x7a, 0xa0, 0xdf, 0xb9, 0x20, 0xfc, 0xc8, 0x44};
    result = Simon_Init(&my_simon_cipher, Simon_128_64, ECB, simon128_64_key, my_IV, my_counter);
    printf("Encryption Test:\n");
    Simon_Encrypt(my_simon_cipher, &simon128_64_plain, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &simon128_64_cipher, sizeof(simon128_64_cipher));

    printf("Decryption Test:\n");
    Simon_Decrypt(my_simon_cipher, &simon128_64_cipher, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &simon128_64_plain, sizeof(simon128_64_plain));

    printf("\n");


    // Simon 96/96 Test
    // Key: 0d0c0b0a0908 050403020100 Plaintext: 2072616c6c69 702065687420 Ciphertext: 602807a462b4 69063d8ff082
    printf("**** Test Simon 96/96 ****\n");
    uint8_t simon96_96_key[] = {0x00, 0x01, 0x02, 0x03,0x04,0x05, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D};
    uint8_t simon96_96_plain[] = {0x20, 0x74, 0x68, 0x65, 0x20, 0x70, 0x69, 0x6c, 0x6c, 0x61, 0x72, 0x20};
    uint8_t simon96_96_cipher[] = {0x82, 0xf0, 0x8f, 0x3d, 0x06, 0x69, 0xb4, 0x62, 0xa4, 0x07, 0x28, 0x60};
    result = Simon_Init(&my_simon_cipher, Simon_96_96, ECB, simon96_96_key, my_IV, my_counter);
    printf("Encryption Test:\n");
    Simon_Encrypt(my_simon_cipher, &simon96_96_plain, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &simon96_96_cipher, sizeof(simon96_96_cipher));

    printf("Decryption Test:\n");
    Simon_Decrypt(my_simon_cipher, &simon96_96_cipher, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &simon96_96_plain, sizeof(simon96_96_plain));

    printf("\n");


    // Simon 144/96 Test
    // Key: 151413121110 0d0c0b0a0908 050403020100 Plaintext: 746168742074 73756420666f Ciphertext: ecad1c6c451e 3f59c5db1ae9
    printf("**** Test Simon 144/96 ****\n");
    uint8_t simon144_96_key[] = {0x00, 0x01, 0x02, 0x03,0x04,0x05, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15};
    uint8_t simon144_96_plain[] = {0x6f, 0x66, 0x20, 0x64, 0x75, 0x73, 0x74, 0x20, 0x74, 0x68, 0x61, 0x74};
    uint8_t simon144_96_cipher[] = {0xe9, 0x1a, 0xdb, 0xc5, 0x59, 0x3f, 0x1e, 0x45, 0x6c, 0x1c, 0xad, 0xec};
    result = Simon_Init(&my_simon_cipher, Simon_144_96, ECB, simon144_96_key, my_IV, my_counter);
    printf("Encryption Test:\n");
    Simon_Encrypt(my_simon_cipher, &simon144_96_plain, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &simon144_96_cipher, sizeof(simon144_96_cipher));

    printf("Decryption Test:\n");
    Simon_Decrypt(my_simon_cipher, &simon144_96_cipher, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &simon144_96_plain, sizeof(simon144_96_plain));

    printf("\n");


    // Simon 128/128 Test
    // Key: 0f0e0d0c0b0a0908 0706050403020100 Plaintext: 6373656420737265 6c6c657661727420 Ciphertext: 49681b1e1e54fe3f 65aa832af84e0bbc
    printf("**** Test Simon 128/128 ****\n");
    uint8_t simon128_128_key[] = {0x00, 0x01, 0x02, 0x03,0x04, 0x05, 0x06,0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    uint8_t simon128_128_plain[] = {0x20, 0x74, 0x72, 0x61, 0x76, 0x65, 0x6c, 0x6c, 0x65, 0x72, 0x73, 0x20, 0x64, 0x65, 0x73, 0x63};
    uint8_t simon128_128_cipher[] = {0xbc, 0x0b, 0x4e, 0xf8, 0x2a, 0x83, 0xaa, 0x65, 0x3f, 0xfe, 0x54, 0x1e, 0x1e, 0x1b, 0x68, 0x49};
    result = Simon_Init(&my_simon_cipher, Simon_128_128, ECB, simon128_128_key, my_IV, my_counter);
    printf("Encryption Test:\n");
    Simon_Encrypt(my_simon_cipher, &simon128_128_plain, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &simon128_128_cipher, sizeof(simon128_128_cipher));

    printf("Decryption Test:\n");
    Simon_Decrypt(my_simon_cipher, &simon128_128_cipher, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &simon128_128_plain, sizeof(simon128_128_plain));

    printf("\n");


    // Simon 192/128 Test
    // Key: 1716151413121110 0f0e0d0c0b0a0908 0706050403020100 Plaintext: 206572656874206e 6568772065626972 Ciphertext: c4ac61effcdc0d4f 6c9c8d6e2597b85b
    printf("**** Test Simon 192/128 ****\n");
    uint8_t simon192_128_key[] = {0x00, 0x01, 0x02, 0x03,0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
    uint8_t simon192_128_plain[] = {0x72, 0x69, 0x62, 0x65, 0x20, 0x77, 0x68, 0x65, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x72, 0x65, 0x20};
    uint8_t simon192_128_cipher[] = {0x5b, 0xb8, 0x97, 0x25, 0x6e, 0x8d, 0x9c, 0x6c, 0x4f, 0x0d, 0xdc, 0xfc, 0xef, 0x61, 0xac, 0xc4};
    result = Simon_Init(&my_simon_cipher, Simon_192_128, ECB, simon192_128_key, my_IV, my_counter);
    printf("Encryption Test:\n");
    Simon_Encrypt(my_simon_cipher, &simon192_128_plain, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &simon192_128_cipher, sizeof(simon192_128_cipher));

    printf("Decryption Test:\n");
    Simon_Decrypt(my_simon_cipher, &simon192_128_cipher, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &simon192_128_plain, sizeof(simon192_128_plain));

    printf("\n");


    // Simon 256/128 Test
    // Key: 1f1e1d1c1b1a1918 1716151413121110 0f0e0d0c0b0a0908 0706050403020100 Plaintext: 74206e69206d6f6f 6d69732061207369 Ciphertext: 8d2b5579afc8a3a0 3bf72a87efe7b868
    printf("**** Test Simon 256/128 ****\n");
    uint8_t simon256_128_key[] = {0x00, 0x01, 0x02, 0x03,0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1d, 0x1e, 0x1f};
    uint8_t simon256_128_plain[] = {0x69, 0x73, 0x20, 0x61, 0x20, 0x73, 0x69, 0x6d, 0x6f, 0x6f, 0x6d, 0x20, 0x69, 0x6e, 0x20, 0x74};
    uint8_t simon256_128_cipher[] = {0x68, 0xb8, 0xe7, 0xef, 0x87, 0x2a, 0xf7, 0x3b, 0xa0, 0xa3, 0xc8, 0xaf, 0x79, 0x55, 0x2b, 0x8d};
    result = Simon_Init(&my_simon_cipher, Simon_256_128, ECB, simon256_128_key, my_IV, my_counter);
    printf("Encryption Test:\n");
    Simon_Encrypt(my_simon_cipher, &simon256_128_plain, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &simon256_128_cipher, sizeof(simon256_128_cipher));

    printf("Decryption Test:\n");
    Simon_Decrypt(my_simon_cipher, &simon256_128_cipher, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &simon256_128_plain, sizeof(simon256_128_plain));

    printf("\n");

    printf("***********************************\n");
    printf("******* Speck Cipher Tests ********\n");
    printf("***********************************\n");

    printf("**** Test Speck 64/32 ****\n");
    uint8_t speck64_32_key[] = {0x00, 0x01, 0x08, 0x09, 0x10, 0x11, 0x18, 0x19};
    uint8_t speck64_32_plain[] = {0x4c, 0x69, 0x74, 0x65};
    uint8_t speck64_32_cipher[] = {0xf2, 0x42, 0x68, 0xa8};
    result = Speck_Init(&my_speck_cipher, Speck_64_32, ECB, speck64_32_key, my_IV, my_counter);
    Speck_Encrypt(my_speck_cipher, &speck64_32_plain, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &speck64_32_cipher, sizeof(speck64_32_cipher));

    printf("\n");

    printf("**** Test Speck 72/48 ****\n");
    uint8_t speck72_48_key[] = {0x00, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x10, 0x11, 0x12};
    uint8_t speck72_48_plain[] = {0x72, 0x61, 0x6c, 0x6c, 0x79, 0x20};
    uint8_t speck72_48_cipher[] = {0xdc, 0x5a, 0x38, 0xa5, 0x49, 0xc0};
    result = Speck_Init(&my_speck_cipher, Speck_72_48, ECB, speck72_48_key, my_IV, my_counter);
    Speck_Encrypt(my_speck_cipher, &speck72_48_plain, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &speck72_48_cipher, sizeof(speck72_48_cipher));

    printf("\n");

    printf("**** Test Speck 96/48 ****\n");
    uint8_t speck96_48_key[] = {0X00,0X01,0X02,0X08,0X09,0X0A,0X10,0X11,0X12,0X18,0X19,0X1A};
    uint8_t speck96_48_plain[] = {0X74, 0X68, 0X69, 0X73, 0X20, 0X6D};
    uint8_t speck96_48_cipher[] = {0X5D, 0X44, 0XB6, 0X10, 0X5E, 0X73};
    result = Speck_Init(&my_speck_cipher, Speck_96_48, ECB, speck96_48_key, my_IV, my_counter);
    Speck_Encrypt(my_speck_cipher, &speck96_48_plain, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &speck96_48_cipher, sizeof(speck96_48_cipher));

    printf("\n");

    printf("**** Test Speck 96/64 ****\n");
    uint8_t speck96_64_key[] = {0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0A, 0x0b, 0x10, 0x11, 0x12, 0x13};
    uint8_t speck96_64_plain[] = {0X65, 0X61, 0X6E, 0X73, 0X20, 0X46, 0X61, 0X74};
    uint8_t speck96_64_cipher[] = {0X6c, 0X94, 0X75, 0X41, 0XEC, 0X52, 0X79, 0X9F};
    result = Speck_Init(&my_speck_cipher, Speck_96_64, ECB, speck96_64_key, my_IV, my_counter);
    Speck_Encrypt(my_speck_cipher, &speck96_64_plain, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &speck96_64_cipher, sizeof(speck96_64_cipher));

    printf("\n");

    printf("**** Test Speck 128/64 ****\n");
    uint8_t speck128_64_key[] = {0x00,0x01,0x02,0x03,0x08,0x09,0x0a,0x0b,0x10,0x11,0x12,0x13,0x18,0x19,0x1a,0x1b};
    uint8_t speck128_64_plain[] = {0X2D,0X43,0X75,0X74,0X74,0X65,0X72,0X3B};
    uint8_t speck128_64_cipher[] = {0X8B,0X02,0X4E,0X45,0X48,0XA5,0X6F,0X8C};
    result = Speck_Init(&my_speck_cipher, Speck_128_64, ECB, speck128_64_key, my_IV, my_counter);
    Speck_Encrypt(my_speck_cipher, &speck128_64_plain, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &speck128_64_cipher, sizeof(speck128_64_cipher));

    printf("\n");

    printf("**** Test Speck 96/96 ****\n");
    uint8_t speck96_96_key[] = {0X00, 0X01, 0X02, 0X03, 0X04, 0X05, 0X08, 0X09, 0X0A, 0X0B, 0X0C, 0X0D};
    uint8_t speck96_96_plain[] = {0X20, 0X75, 0X73, 0X61, 0X67, 0X65, 0X2C, 0X20, 0X68, 0X6F, 0X77, 0X65};
    uint8_t speck96_96_cipher[] = {0XAA, 0X79, 0X8F, 0XDE, 0XBD, 0X62, 0X78, 0X71, 0XAB, 0X09, 0X4D, 0X9E};
    result = Speck_Init(&my_speck_cipher, Speck_96_96, ECB, speck96_96_key, my_IV, my_counter);
    Speck_Encrypt(my_speck_cipher, &speck96_96_plain, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &speck96_96_cipher, sizeof(speck96_96_cipher));

    printf("\n");

    printf("**** Test Speck 144/96 ****\n");
    uint8_t speck144_96_key[] = {0X00, 0X01, 0X02, 0X03, 0X04, 0X05, 0X08, 0X09, 0X0A, 0X0B, 0X0C, 0X0D, 0X10, 0X11, 0X12, 0X13, 0X14, 0X15};
    uint8_t speck144_96_plain[] = {0X76, 0X65, 0X72, 0X2C, 0X20, 0X69, 0X6E, 0X20, 0X74, 0X69, 0X6D, 0X65};
    uint8_t speck144_96_cipher[] = {0XE6, 0X2E, 0X25, 0X40, 0XE4, 0X7A, 0X8A, 0X22, 0X72, 0X10, 0XF3, 0X2B};
    result = Speck_Init(&my_speck_cipher, Speck_144_96, ECB, speck144_96_key, my_IV, my_counter);
    Speck_Encrypt(my_speck_cipher, &speck144_96_plain, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &speck144_96_cipher, sizeof(speck144_96_cipher));

    printf("\n");

    printf("**** Test Speck 128/128 ****\n");
    uint8_t speck128_128_key[] = {0X00, 0X01, 0X02, 0X03, 0X04, 0X05, 0X06, 0X07, 0X08, 0X09, 0X0A, 0X0B, 0X0C, 0X0D, 0X0E, 0X0F};
    uint8_t speck128_128_plain[] = {0X20, 0X6D, 0X61, 0X64, 0X65, 0X20, 0X69, 0X74, 0X20, 0X65, 0X71, 0X75, 0X69, 0X76, 0X61, 0X6C};
    uint8_t speck128_128_cipher[] = {0X18, 0X0D, 0X57, 0X5C, 0XDF, 0XFE, 0X60, 0X78, 0X65, 0X32, 0X78, 0X79, 0X51, 0X98, 0X5D, 0XA6};
    result = Speck_Init(&my_speck_cipher, Speck_128_128, ECB, speck128_128_key, my_IV, my_counter);
    Speck_Encrypt(my_speck_cipher, &speck128_128_plain, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &speck128_128_cipher, sizeof(speck128_128_cipher));

    printf("\n");

    printf("**** Test Speck 192/128 ****\n");
    uint8_t speck192_128_key[] = {0X00, 0X01, 0X02, 0X03, 0X04, 0X05, 0X06, 0X07, 0X08, 0X09, 0X0A, 0X0B, 0X0C, 0X0D, 0X0E, 0X0F, 0X10, 0X11, 0X12, 0X13, 0X14, 0X15, 0X16, 0X17};
    uint8_t speck192_128_plain[] = {0X65, 0X6E, 0X74, 0X20, 0X74, 0X6F, 0X20, 0X43, 0X68, 0X69, 0X65, 0X66, 0X20, 0X48, 0X61, 0X72};
    uint8_t speck192_128_cipher[] = {0X86, 0X18, 0X3C, 0XE0, 0X5D, 0X18, 0XBC, 0XF9, 0X66, 0X55, 0X13, 0X13, 0X3A, 0XCF, 0XE4, 0X1B};
    result = Speck_Init(&my_speck_cipher, Speck_192_128, ECB, speck192_128_key, my_IV, my_counter);
    Speck_Encrypt(my_speck_cipher, &speck192_128_plain, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &speck192_128_cipher, sizeof(speck192_128_cipher));

    printf("\n");

    printf("**** Test Speck 256/128 ****\n");
    uint8_t speck256_128_key[] = {0X00, 0X01, 0X02, 0X03, 0X04, 0X05, 0X06, 0X07, 0X08, 0X09, 0X0A, 0X0B, 0X0C, 0X0D, 0X0E, 0X0F, 0X10, 0X11, 0X12, 0X13, 0X14, 0X15, 0X16, 0X17, 0X18, 0X19, 0X1A, 0X1B, 0X1C, 0X1D, 0X1E, 0X1F};
    uint8_t speck256_128_plain[] = {0X70, 0X6F, 0X6F, 0X6E, 0X65, 0X72, 0X2E, 0X20, 0X49, 0X6E, 0X20, 0X74, 0X68, 0X6F, 0X73, 0X65};
    uint8_t speck256_128_cipher[] = {0X43, 0X8F, 0X18, 0X9C, 0X8D, 0XB4, 0XEE, 0X4E, 0X3E, 0XF5, 0XC0, 0X05, 0X04, 0X01, 0X09, 0X41};
    result = Speck_Init(&my_speck_cipher, Speck_256_128, ECB, speck256_128_key, my_IV, my_counter);
    Speck_Encrypt(my_speck_cipher, &speck256_128_plain, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &speck256_128_cipher, sizeof(speck256_128_cipher));

    printf("\n");

    printf("Total Fail Count: %d\n", fail_count);

    return fail_count;
}
