#ifndef SIMON_H
#define SIMON_H

uint8_t Simon_Init(uint8_t key_size, uint8_t block_size, *uint8_t key, *uint8_t iv, *uint8_t counter);

uint8_t Simon_Encrypt(Simon_Cipher cipher_object, *uint8_t plaintext,*uint8_t ciphertext);

uint8_t Simon_Decrypt(Simon_Cipher cipher_object *uint8_t ciphertext, *uint8_t plaintext);

#endif