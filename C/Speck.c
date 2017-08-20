/*
 * Speck.c
 * Implementation of NSA Speck Block Cipher
 * Copyright 2017 Michael Calvin McCoy
 * calvin.mccoy@gmail.com
 *  # The MIT License (MIT) - see LICENSE.md see LICENSE.md
*/

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
        tmp = (rotate_right(sub_keys[1],cipher_object->alpha)) & mod_mask;
        tmp = (tmp + sub_keys[0]) & mod_mask;
        tmp= tmp ^ i;
        tmp2 = (rotate_left(sub_keys[0],cipher_object->beta)) & mod_mask;
        tmp2 = tmp2 ^ tmp;
        sub_keys[0] = tmp2;

        // Shift Key Schedule Subword
        if (key_words != 2) {
            // Shift Sub Words
            for(int j = 1; j < (key_words - 1); j++){
                sub_keys[j] = sub_keys[j+1];
            }
        }
        sub_keys[key_words - 1] = tmp;

        // Append sub key to key schedule
        memcpy(cipher_object->key_schedule + (word_bytes * (i+1)), &sub_keys[0], word_bytes);   
    }
    return 0;
}


uint8_t Speck_Encrypt(Speck_Cipher cipher_object, const void *plaintext, void *ciphertext) {
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

void Speck_Encrypt_32(const uint8_t *key_schedule, const uint8_t *plaintext, uint8_t *ciphertext) {

    const uint8_t word_size = 16;
    uint16_t *y_word = (uint16_t *)ciphertext;
    uint16_t *x_word = ((uint16_t *)ciphertext) + 1;
    uint16_t *round_key_ptr = (uint16_t *)key_schedule;

    *y_word = *(uint16_t *)plaintext;
    *x_word = *(((uint16_t *)plaintext) + 1);

    for(uint8_t i = 0; i < 22; i++) {  // Block size 32 has only one round number option
        *x_word = ((rotate_right(*x_word, 7)) + *y_word) ^ *(round_key_ptr + i);
        *y_word = (rotate_left(*y_word, 2)) ^ *x_word;
    }
}


void Speck_Encrypt_48(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *plaintext,
                      uint8_t *ciphertext){
   
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
}

void Speck_Encrypt_64(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *plaintext,
                      uint8_t *ciphertext) {

    const uint8_t word_size = 32;
    uint32_t *y_word = (uint32_t *)ciphertext;
    uint32_t *x_word = ((uint32_t *)ciphertext) + 1;
    uint32_t *round_key_ptr = (uint32_t *)key_schedule;

    *y_word = *(uint32_t *)plaintext;
    *x_word = *(((uint32_t *)plaintext) + 1);

    for(uint8_t i = 0; i < round_limit; i++) { 
        *x_word = ((rotate_right(*x_word, 8)) + *y_word) ^ *(round_key_ptr + i);
        *y_word = (rotate_left(*y_word, 3)) ^ *x_word;
    }
}

void Speck_Encrypt_96(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *plaintext,
                      uint8_t *ciphertext){
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

void Speck_Encrypt_128(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *plaintext,
                       uint8_t *ciphertext){

    const uint8_t word_size = 64;
    uint64_t *y_word = (uint64_t *)ciphertext;
    uint64_t *x_word = ((uint64_t *)ciphertext) + 1;
    uint64_t *round_key_ptr = (uint64_t *)key_schedule;

    *y_word = *(uint64_t *)plaintext;
    *x_word = *(((uint64_t *)plaintext) + 1);

    for(uint8_t i = 0; i < round_limit; i++) { 
        *x_word = ((rotate_right(*x_word, 8)) + *y_word) ^ *(round_key_ptr + i);
        *y_word = (rotate_left(*y_word, 3)) ^ *x_word;
    }
}

uint8_t Speck_Decrypt(Speck_Cipher cipher_object, void *ciphertext, void *plaintext) {
    if (cipher_object.cipher_cfg == Speck_64_32) {
        Speck_Decrypt_32(cipher_object.key_schedule, ciphertext, plaintext);
    }

    else if(cipher_object.cipher_cfg <= Speck_96_48) {
        Speck_Decrypt_48(cipher_object.round_limit, cipher_object.key_schedule, ciphertext, plaintext);
    }

    else if(cipher_object.cipher_cfg <= Speck_128_64) {
        Speck_Decrypt_64(cipher_object.round_limit, cipher_object.key_schedule, ciphertext, plaintext);
    }

    else if(cipher_object.cipher_cfg <= Speck_144_96) {
        Speck_Decrypt_96(cipher_object.round_limit, cipher_object.key_schedule, ciphertext, plaintext);
    }

    else if(cipher_object.cipher_cfg <= Speck_256_128) {
        Speck_Decrypt_128(cipher_object.round_limit, cipher_object.key_schedule, ciphertext, plaintext);
    }

    else return 1;

    return 0;
}

void Speck_Decrypt_32(const uint8_t *key_schedule, const uint8_t *ciphertext, uint8_t *plaintext) {

    const uint8_t word_size = 16;
    uint16_t *y_word = (uint16_t *)plaintext;
    uint16_t *x_word = ((uint16_t *)plaintext) + 1;
    uint16_t *round_key_ptr = (uint16_t *)key_schedule;

    *y_word = *(uint16_t *)ciphertext;
    *x_word = *(((uint16_t *)ciphertext) + 1);

    for(int8_t i = 21; i >=0; i--) {  // Block size 32 has only one round number option
        *y_word = rotate_right((*y_word ^ *x_word), 2);
        *x_word = rotate_left((uint16_t)((*x_word ^ *(round_key_ptr + i)) - *y_word), 7);
    }
}

void Speck_Decrypt_48(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *ciphertext,
                      uint8_t *plaintext) {

    const uint8_t word_size = 24;

    bytes3_t *threeBytePtr = (bytes3_t *)ciphertext;
    uint32_t y_word = (*(bitword24_t *)threeBytePtr).data;
    uint32_t x_word = (*(bitword24_t *)(threeBytePtr + 1)).data;
    threeBytePtr = (bytes3_t *)key_schedule;
    uint32_t round_key;

    for(int8_t i = round_limit - 1; i >=0; i--) {
        round_key = (*(bitword24_t *)(threeBytePtr + i)).data;
        y_word = (rotate_right((y_word ^ x_word), 3)) & 0x00FFFFFF;
        x_word = (rotate_left(((((x_word ^ round_key)) - y_word) & 0x00FFFFFF), 8)) & 0x00FFFFFF;
    }

    // Assemble Plaintext Output Array
    threeBytePtr = (bytes3_t *)plaintext;
    *threeBytePtr = *(bytes3_t *)&y_word;
    threeBytePtr += 1;
    *threeBytePtr = *(bytes3_t *)&x_word;
}

void Speck_Decrypt_64(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *ciphertext,
                      uint8_t *plaintext) {

    const uint8_t word_size = 32;
    uint32_t *y_word = (uint32_t *)plaintext;
    uint32_t *x_word = ((uint32_t *)plaintext) + 1;
    uint32_t *round_key_ptr = (uint32_t *)key_schedule;

    *y_word = *(uint32_t *)ciphertext;
    *x_word = *(((uint32_t *)ciphertext) + 1);

    for(int8_t i = round_limit - 1; i >=0; i--) {
        *y_word = rotate_right((*y_word ^ *x_word), 3);
        *x_word = rotate_left((uint32_t)((*x_word ^ *(round_key_ptr + i)) - *y_word), 8);
    }
}

void Speck_Decrypt_96(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *ciphertext,
                      uint8_t *plaintext) {
    const uint8_t word_size = 48;

    bytes6_t *sixBytePtr = (bytes6_t *)ciphertext;
    uint64_t y_word = (*(bitword48_t *)sixBytePtr).data;
    uint64_t x_word = (*(bitword48_t *)(sixBytePtr + 1)).data;
    sixBytePtr = (bytes6_t *)key_schedule;
    uint64_t round_key;

    for(int8_t i = round_limit - 1; i >=0; i--) {
        round_key = (*(bitword48_t *)(sixBytePtr + i)).data;
        y_word = (rotate_right((y_word ^ x_word), 3)) & 0x00FFFFFFFFFFFF;
        x_word = (rotate_left(((((x_word ^ round_key)) - y_word) & 0x00FFFFFFFFFFFF), 8)) & 0x00FFFFFFFFFFFF;
    }

    // Assemble Plaintext Output Array
    sixBytePtr = (bytes6_t *)plaintext;
    *sixBytePtr = *(bytes6_t *)&y_word;
    sixBytePtr += 1;
    *sixBytePtr = *(bytes6_t *)&x_word;
}

void Speck_Decrypt_128(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *ciphertext,
                       uint8_t *plaintext) {

    const uint8_t word_size = 64;
    uint64_t *y_word = (uint64_t *)plaintext;
    uint64_t *x_word = ((uint64_t *)plaintext) + 1;
    uint64_t *round_key_ptr = (uint64_t *)key_schedule;

    *y_word = *(uint64_t *)ciphertext;
    *x_word = *(((uint64_t *)ciphertext) + 1);

    for(int8_t i = round_limit - 1; i >=0; i--) {
        *y_word = rotate_right((*y_word ^ *x_word), 3);
        *x_word = rotate_left((uint64_t)((*x_word ^ *(round_key_ptr + i)) - *y_word), 8);
    }
}
