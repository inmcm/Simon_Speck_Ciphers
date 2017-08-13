#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "Speck.h"


#define rotate_left(x,n) (((x) >> (word_size - (n))) | ((x) << (n)))
#define rotate_right(x,n) (((x) << (word_size - (n))) | ((x) >> (n)))

const uint8_t speck_rounds[] = {22, 22, 23, 26, 27, 28, 29, 32, 33, 34};
const uint8_t speck_block_sizes[] = {32, 48, 48, 64, 64, 96, 96, 128, 128, 128};
const uint16_t speck_key_sizes[] = {64, 72, 96, 96, 128, 96, 144, 128, 192, 256};

uint8_t Speck_Init(Speck_Cipher *cipher_object, enum speck_cipher_config_t cipher_cfg, enum mode_t c_mode, void *key, uint8_t *iv, uint8_t *counter) {

    if (cipher_cfg > Speck_256_128 || cipher_cfg < Speck_64_32) {
        return 1;
    }
    
    cipher_object->block_size = speck_block_sizes[cipher_cfg];
    cipher_object->key_size = speck_key_sizes[cipher_cfg];
    cipher_object->round_limit = speck_rounds[cipher_cfg];
    cipher_object->cipher_cfg = cipher_cfg;
    
    uint8_t word_size = speck_block_sizes[cipher_cfg] >> 1;
    uint8_t word_bytes = word_size >> 3;
    uint16_t key_words =  speck_key_sizes[cipher_cfg] / word_size;
    uint64_t sub_keys[4] = {};
    uint64_t mod_mask = ULLONG_MAX >> (64 - word_size);
    
    if (cipher_cfg == Speck_64_32) {
        cipher_object->alpha = 7;
        cipher_object->beta = 2;
    }
    else {
        cipher_object->alpha = 8;
        cipher_object->beta = 3;
    }

    // Setup
    for(int i = 0; i < key_words; i++) {
        memcpy(&sub_keys[i], key + (word_bytes * i), word_bytes);
    }
     
    // Store First Key Schedule Entry
    memcpy(cipher_object->key_schedule, &sub_keys[0], word_bytes);

    uint64_t tmp,tmp2;
    for (uint64_t i = 0; i < speck_rounds[cipher_cfg] - 1; i++) {

        // Run Speck Cipher Round Function
        // tmp = ((rotate_right(sub_keys[1],cipher_object->alpha) + sub_keys[0]) ^ i) & mod_mask;
        tmp = (rotate_right(sub_keys[1],cipher_object->alpha)) & mod_mask;
        // printf("Check rotate: %04x %04x\n",sub_keys[1], tmp);
        tmp = (tmp + sub_keys[0]) & mod_mask;
        // printf("Check Add: %04x\n",tmp);
        tmp= tmp ^ i;
        // printf("New X: %x\n",tmp);
        // sub_keys[0] = ((rotate_left(sub_keys[0],cipher_object->beta)) ^ tmp) & mod_mask;
        tmp2 = (rotate_left(sub_keys[0],cipher_object->beta)) & mod_mask;
        // printf("Check rotate: %04x %04x\n",sub_keys[0], tmp2);
        tmp2 = tmp2 ^ tmp;
        // printf("New Y: %04x\n",tmp2);
        sub_keys[0] = tmp2;
        // printf("\n");
        
        // Shift Key Schedule Subword
        if (key_words != 2) {
            // Shift Sub Words
            for(int j = 1; j < (key_words - 1); j++){
                sub_keys[j] = sub_keys[j+1];
            }
        }
        sub_keys[key_words - 1] = tmp;

        // printf("Subkeys 3:%04x  2:%04x  1:%04x  0:%04x  \n",sub_keys[3],sub_keys[2],sub_keys[1],sub_keys[0]);

        // Append sub key to key schedule
        memcpy(cipher_object->key_schedule + (word_bytes * (i+1)), &sub_keys[0], word_bytes);   
    }
    return 0;
}


uint8_t Speck_Encrypt(Speck_Cipher cipher_object, void *plaintext, void *ciphertext) {
    if (cipher_object.cipher_cfg == Speck_64_32) {
        Speck_Encrypt_32(cipher_object.key_schedule, plaintext, ciphertext);
    }
    
    else if(cipher_object.cipher_cfg <= Speck_96_48) {
        Speck_Encrypt_48(cipher_object.round_limit, cipher_object.key_schedule, plaintext, ciphertext);
    }
    
    else if(cipher_object.cipher_cfg <= Speck_128_64) {
        Speck_Encrypt_64(cipher_object.round_limit, cipher_object.key_schedule, plaintext, ciphertext);
    }
    
    else if(cipher_object.cipher_cfg <= Speck_144_96) {
        Speck_Encrypt_96(cipher_object.round_limit, cipher_object.key_schedule, plaintext, ciphertext);
    }

    else if(cipher_object.cipher_cfg <= Speck_256_128) {
        Speck_Encrypt_128(cipher_object.round_limit, cipher_object.key_schedule, plaintext, ciphertext);
    }
    
    else return 1;

    return 0;;
}

void Speck_Encrypt_32(uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext) {
    
    const uint8_t word_size = 16;
    uint16_t y_word = *(uint16_t *)plaintext;
    uint16_t x_word = *(((uint16_t *)plaintext) + 1);
    uint16_t *round_key_ptr = (uint16_t *)key_schedule;
    uint16_t * word_ptr = (uint16_t *)ciphertext;

    for(uint8_t i = 0; i < 22; i++) {  // Block size 32 has only one round number option
        x_word = ((rotate_right(x_word, 7)) + y_word) ^ *(round_key_ptr + i);
        y_word = (rotate_left(y_word, 2)) ^ x_word;
    }
    // Assemble Ciphertext Output Array   
    *word_ptr = y_word;
    word_ptr += 1;
    *word_ptr = x_word;
    return;
}


void Speck_Encrypt_48(uint8_t round_limit, uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext){
   
    const uint8_t word_size = 24;

    bytes3_t *threeBytePtr = (bytes3_t *)plaintext;
    uint32_t y_word = (*(bitword24_t *)threeBytePtr).data;
    uint32_t x_word = (*(bitword24_t *)(threeBytePtr + 1)).data;
    threeBytePtr = (bytes3_t *)key_schedule;
    uint32_t round_key;

    for(uint8_t i = 0; i < round_limit; i++) {  
        round_key = (*(bitword24_t *)(threeBytePtr + i)).data;
        x_word = (((rotate_right(x_word, 8)) + y_word) ^ round_key) & 0x00FFFFFF;
        y_word = ((rotate_left(y_word, 3)) ^ x_word) & 0x00FFFFFF;
    }
    // Assemble Ciphertext Output Array
    threeBytePtr = (bytes3_t *)ciphertext; 
    *threeBytePtr = *(bytes3_t *)&y_word;
    threeBytePtr += 1;
    *threeBytePtr = *(bytes3_t *)&x_word;
    return;
}
void Speck_Encrypt_64(uint8_t round_limit, uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext){
    
    const uint8_t word_size = 32;
    uint32_t y_word = *(uint32_t *)plaintext;
    uint32_t x_word = *(((uint32_t *)plaintext) + 1);
    uint32_t *round_key_ptr = (uint32_t *)key_schedule;
    uint32_t * word_ptr = (uint32_t *)ciphertext;

    for(uint8_t i = 0; i < round_limit; i++) { 
        x_word = ((rotate_right(x_word, 8)) + y_word) ^ *(round_key_ptr + i);
        y_word = (rotate_left(y_word, 3)) ^ x_word;
    }
    // Assemble Ciphertext Output Array   
    *word_ptr = y_word;
    word_ptr += 1;
    *word_ptr = x_word;
    return;
}
void Speck_Encrypt_96(uint8_t round_limit, uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext){
    const uint8_t word_size = 48;

    bytes6_t *threeBytePtr = (bytes6_t *)plaintext;
    uint64_t y_word = (*(bitword48_t *)threeBytePtr).data;
    uint64_t x_word = (*(bitword48_t *)(threeBytePtr + 1)).data;
    threeBytePtr = (bytes6_t *)key_schedule;
    uint64_t round_key;

    for(uint8_t i = 0; i < round_limit; i++) {  
        round_key = (*(bitword48_t *)(threeBytePtr + i)).data;
        x_word = (((rotate_right(x_word, 8)) + y_word) ^ round_key) & 0x00FFFFFFFFFFFF;
        y_word = ((rotate_left(y_word, 3)) ^ x_word) & 0x00FFFFFFFFFFFF;
    }
    // Assemble Ciphertext Output Array
    threeBytePtr = (bytes6_t *)ciphertext; 
    *threeBytePtr = *(bytes6_t *)&y_word;
    threeBytePtr += 1;
    *threeBytePtr = *(bytes6_t *)&x_word;
}
void Speck_Encrypt_128(uint8_t round_limit, uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext){
    const uint8_t word_size = 64;
    uint64_t y_word = *(uint64_t *)plaintext;
    uint64_t x_word = *(((uint64_t *)plaintext) + 1);
    uint64_t *round_key_ptr = (uint64_t *)key_schedule;
    uint64_t * word_ptr = (uint64_t *)ciphertext;

    for(uint8_t i = 0; i < round_limit; i++) { 
        x_word = ((rotate_right(x_word, 8)) + y_word) ^ *(round_key_ptr + i);
        y_word = (rotate_left(y_word, 3)) ^ x_word;
    }
    // Assemble Ciphertext Output Array   
    *word_ptr = y_word;
    // word_ptr += 1;
    // *word_ptr = x_word;
    *(word_ptr + 1) = x_word;
}

uint8_t Speck_Decrypt(Speck_Cipher cipher_object, uint8_t *ciphertext, uint8_t *plaintext) {
    return 0;
}


// int main(void){
//     // uint8_t word_size = 32;
//     // uint32_t p = 0xFF340000;
//     // uint32_t x,y;
//     // uint32_t n = 0x00005600;
//     // uint8_t alpha = 8;
//     // uint8_t beta = 3;
//     // uint32_t k = 0xCACACACA;

//     // uint32_t output;
//     // printf("Before: %x, %x\n",output,p);
//     // output = rotate_left(p,alpha);
//     // printf("After: %x, %x\n",output,p);

//     // printf("Before: %x, %x\n",output, p);
//     // output = rotate_right(p,alpha);
//     // printf("After: %x, %x\n",output, p);

    
//     // x = 10;
//     // y = 20;
//     // printf("%#010x  %#010x  %#010x\n", x, y, k);
//     // x = (rotate_right(x,alpha) + y) ^ k;
//     // y = (rotate_left(y,beta)) ^ x;
//     // printf("%#010x  %#010x  %#010x\n", x, y, k);

//     Speck_Cipher my_cipher = *(Speck_Cipher *)malloc(sizeof(Speck_Cipher));

//     uint8_t ciphertext_buffer[16];
//     uint8_t my_IV[] = {0x32,0x14,0x76,0x58};
//     uint8_t my_counter[] = {0x2F,0x3D,0x5C,0x7B};
//     uint32_t result;

//     printf("Test Speck 64/32\n");
//     uint8_t speck64_32_key[] = {0x00, 0x01, 0x08, 0x09, 0x10, 0x11, 0x18, 0x19};
//     uint8_t speck64_32_plain[] = {0x4c, 0x69, 0x74, 0x65};
//     uint8_t speck64_32_cipher[] = {0xf2, 0x42, 0x68, 0xa8};
//     result = Speck_Init(&my_cipher, Speck_64_32, ECB, speck64_32_key, my_IV, my_counter);
//     Speck_Encrypt(my_cipher, &speck64_32_plain, &ciphertext_buffer);
//     for(int i=0; i < 4; i++) {
//         printf("Ciphertext Byte %02d: %02x - %02x",i,ciphertext_buffer[i],speck64_32_cipher[i]);
//         if (ciphertext_buffer[i] != speck64_32_cipher[i]) printf("  FAIL\n");
//         else printf("\n");
//     } 
//     printf("\n");

//     printf("Test Speck 72/48\n");
//     uint8_t speck72_48_key[] = {0x00, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x10, 0x11, 0x12};
//     uint8_t speck72_48_plain[] = {0x72, 0x61, 0x6c, 0x6c, 0x79, 0x20};
//     uint8_t speck72_48_cipher[] = {0xdc, 0x5a, 0x38, 0xa5, 0x49, 0xc0};
//     result = Speck_Init(&my_cipher, Speck_72_48, ECB, speck72_48_key, my_IV, my_counter);
//     Speck_Encrypt(my_cipher, &speck72_48_plain, &ciphertext_buffer);
//     for(int i=0; i < 6; i++) {
//         printf("Ciphertext Byte %02d: %02x - %02x",i,ciphertext_buffer[i],speck72_48_cipher[i]);
//         if (ciphertext_buffer[i] != speck72_48_cipher[i]) printf("  FAIL\n");
//         else printf("\n");
//     } 
//     printf("\n");

//     printf("Test Speck 96/48\n");
//     uint8_t speck96_48_key[] = {0X00,0X01,0X02,0X08,0X09,0X0A,0X10,0X11,0X12,0X18,0X19,0X1A};
//     uint8_t speck96_48_plain[] = {0X74, 0X68, 0X69, 0X73, 0X20, 0X6D};
//     uint8_t speck96_48_cipher[] = {0X5D, 0X44, 0XB6, 0X10, 0X5E, 0X73};
//     result = Speck_Init(&my_cipher, Speck_96_48, ECB, speck96_48_key, my_IV, my_counter);
//     Speck_Encrypt(my_cipher, &speck96_48_plain, &ciphertext_buffer);
//     for(int i=0; i < 6; i++) {
//         printf("Ciphertext Byte %02d: %02x - %02x",i,ciphertext_buffer[i],speck96_48_cipher[i]);
//         if (ciphertext_buffer[i] != speck96_48_cipher[i]) printf("  FAIL\n");
//         else printf("\n");
//     }
//     printf("\n");

//     printf("Test Speck 96/64\n");
//     uint8_t speck96_64_key[] = {0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0A, 0x0b, 0x10, 0x11, 0x12, 0x13};
//     uint8_t speck96_64_plain[] = {0X65, 0X61, 0X6E, 0X73, 0X20, 0X46, 0X61, 0X74};
//     uint8_t speck96_64_cipher[] = {0X6c, 0X94, 0X75, 0X41, 0XEC, 0X52, 0X79, 0X9F};
//     result = Speck_Init(&my_cipher, Speck_96_64, ECB, speck96_64_key, my_IV, my_counter);
//     Speck_Encrypt(my_cipher, &speck96_64_plain, &ciphertext_buffer);
//     for(int i=0; i < 8; i++) {
//         printf("Ciphertext Byte %02d: %02x - %02x",i,ciphertext_buffer[i],speck96_64_cipher[i]);
//         if (ciphertext_buffer[i] != speck96_64_cipher[i]) printf("  FAIL\n");
//         else printf("\n");
//     }
//     printf("\n");

//     printf("Test Speck 128/64\n");
//     uint8_t speck128_64_key[] = {0x00,0x01,0x02,0x03,0x08,0x09,0x0a,0x0b,0x10,0x11,0x12,0x13,0x18,0x19,0x1a,0x1b};
//     uint8_t speck128_64_plain[] = {0X2D,0X43,0X75,0X74,0X74,0X65,0X72,0X3B};
//     uint8_t speck128_64_cipher[] = {0X8B,0X02,0X4E,0X45,0X48,0XA5,0X6F,0X8C};
//     result = Speck_Init(&my_cipher, Speck_128_64, ECB, speck128_64_key, my_IV, my_counter);
//     Speck_Encrypt(my_cipher, &speck128_64_plain, &ciphertext_buffer);
//     for(int i=0; i < 8; i++) {
//         printf("Ciphertext Byte %02d: %02x - %02x",i,ciphertext_buffer[i],speck128_64_cipher[i]);
//         if (ciphertext_buffer[i] != speck128_64_cipher[i]) printf("  FAIL\n");
//         else printf("\n");
//     }
//     printf("\n");

//     printf("Test Speck 96/96\n");
//     uint8_t speck96_96_key[] = {0X00, 0X01, 0X02, 0X03, 0X04, 0X05, 0X08, 0X09, 0X0A, 0X0B, 0X0C, 0X0D};
//     uint8_t speck96_96_plain[] = {0X20, 0X75, 0X73, 0X61, 0X67, 0X65, 0X2C, 0X20, 0X68, 0X6F, 0X77, 0X65};
//     uint8_t speck96_96_cipher[] = {0XAA, 0X79, 0X8F, 0XDE, 0XBD, 0X62, 0X78, 0X71, 0XAB, 0X09, 0X4D, 0X9E};
//     result = Speck_Init(&my_cipher, Speck_96_96, ECB, speck96_96_key, my_IV, my_counter);
//     Speck_Encrypt(my_cipher, &speck96_96_plain, &ciphertext_buffer);
//     for(int i=0; i < 12; i++) {
//         printf("Ciphertext Byte %02d: %02x - %02x",i,ciphertext_buffer[i],speck96_96_cipher[i]);
//         if (ciphertext_buffer[i] != speck96_96_cipher[i]) printf("  FAIL\n");
//         else printf("\n");
//     }
//     printf("\n");

//     printf("Test Speck 144/96\n");
//     uint8_t speck144_96_key[] = {0X00, 0X01, 0X02, 0X03, 0X04, 0X05, 0X08, 0X09, 0X0A, 0X0B, 0X0C, 0X0D, 0X10, 0X11, 0X12, 0X13, 0X14, 0X15};
//     uint8_t speck144_96_plain[] = {0X76, 0X65, 0X72, 0X2C, 0X20, 0X69, 0X6E, 0X20, 0X74, 0X69, 0X6D, 0X65};
//     uint8_t speck144_96_cipher[] = {0XE6, 0X2E, 0X25, 0X40, 0XE4, 0X7A, 0X8A, 0X22, 0X72, 0X10, 0XF3, 0X2B};
//     result = Speck_Init(&my_cipher, Speck_144_96, ECB, speck144_96_key, my_IV, my_counter);
//     Speck_Encrypt(my_cipher, &speck144_96_plain, &ciphertext_buffer);
//     for(int i=0; i < 12; i++) {
//         printf("Ciphertext Byte %02d: %02x - %02x",i,ciphertext_buffer[i],speck144_96_cipher[i]);
//         if (ciphertext_buffer[i] != speck144_96_cipher[i]) printf("  FAIL\n");
//         else printf("\n");
//     }
//     printf("\n");

//     printf("Test Speck 128/128\n");
//     uint8_t speck128_128_key[] = {0X00, 0X01, 0X02, 0X03, 0X04, 0X05, 0X06, 0X07, 0X08, 0X09, 0X0A, 0X0B, 0X0C, 0X0D, 0X0E, 0X0F};
//     uint8_t speck128_128_plain[] = {0X20, 0X6D, 0X61, 0X64, 0X65, 0X20, 0X69, 0X74, 0X20, 0X65, 0X71, 0X75, 0X69, 0X76, 0X61, 0X6C};
//     uint8_t speck128_128_cipher[] = {0X18, 0X0D, 0X57, 0X5C, 0XDF, 0XFE, 0X60, 0X78, 0X65, 0X32, 0X78, 0X79, 0X51, 0X98, 0X5D, 0XA6};
//     result = Speck_Init(&my_cipher, Speck_128_128, ECB, speck128_128_key, my_IV, my_counter);
//     Speck_Encrypt(my_cipher, &speck128_128_plain, &ciphertext_buffer);
//     for(int i=0; i < 16; i++) {
//         printf("Ciphertext Byte %02d: %02x - %02x",i,ciphertext_buffer[i],speck128_128_cipher[i]);
//         if (ciphertext_buffer[i] != speck128_128_cipher[i]) printf("  FAIL\n");
//         else printf("\n");
//     }
//     printf("\n");

//     printf("Test Speck 192/128\n");
//     uint8_t speck192_128_key[] = {0X00, 0X01, 0X02, 0X03, 0X04, 0X05, 0X06, 0X07, 0X08, 0X09, 0X0A, 0X0B, 0X0C, 0X0D, 0X0E, 0X0F, 0X10, 0X11, 0X12, 0X13, 0X14, 0X15, 0X16, 0X17};
//     uint8_t speck192_128_plain[] = {0X65, 0X6E, 0X74, 0X20, 0X74, 0X6F, 0X20, 0X43, 0X68, 0X69, 0X65, 0X66, 0X20, 0X48, 0X61, 0X72};
//     uint8_t speck192_128_cipher[] = {0X86, 0X18, 0X3C, 0XE0, 0X5D, 0X18, 0XBC, 0XF9, 0X66, 0X55, 0X13, 0X13, 0X3A, 0XCF, 0XE4, 0X1B};
//     result = Speck_Init(&my_cipher, Speck_192_128, ECB, speck192_128_key, my_IV, my_counter);
//     Speck_Encrypt(my_cipher, &speck192_128_plain, &ciphertext_buffer);
//     for(int i=0; i < 16; i++) {
//         printf("Ciphertext Byte %02d: %02x - %02x",i,ciphertext_buffer[i],speck192_128_cipher[i]);
//         if (ciphertext_buffer[i] != speck192_128_cipher[i]) printf("  FAIL\n");
//         else printf("\n");
//     }
//     printf("\n");

//     printf("Test Speck 256/128\n");
//     uint8_t speck256_128_key[] = {0X00, 0X01, 0X02, 0X03, 0X04, 0X05, 0X06, 0X07, 0X08, 0X09, 0X0A, 0X0B, 0X0C, 0X0D, 0X0E, 0X0F, 0X10, 0X11, 0X12, 0X13, 0X14, 0X15, 0X16, 0X17, 0X18, 0X19, 0X1A, 0X1B, 0X1C, 0X1D, 0X1E, 0X1F};
//     uint8_t speck256_128_plain[] = {0X70, 0X6F, 0X6F, 0X6E, 0X65, 0X72, 0X2E, 0X20, 0X49, 0X6E, 0X20, 0X74, 0X68, 0X6F, 0X73, 0X65};
//     uint8_t speck256_128_cipher[] = {0X43, 0X8F, 0X18, 0X9C, 0X8D, 0XB4, 0XEE, 0X4E, 0X3E, 0XF5, 0XC0, 0X05, 0X04, 0X01, 0X09, 0X41};
//     result = Speck_Init(&my_cipher, Speck_256_128, ECB, speck256_128_key, my_IV, my_counter);
//     Speck_Encrypt(my_cipher, &speck256_128_plain, &ciphertext_buffer);
//     for(int i=0; i < 16; i++) {
//         printf("Ciphertext Byte %02d: %02x - %02x",i,ciphertext_buffer[i],speck256_128_cipher[i]);
//         if (ciphertext_buffer[i] != speck256_128_cipher[i]) printf("  FAIL\n");
//         else printf("\n");
//     }
//     printf("\n");

//     printf("FINISH!!\n");

// }