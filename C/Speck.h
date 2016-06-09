#ifndef SPECK_H
#define SPECK_H

uint8_t Speck_Init(cipher_config_t c_mode, *uint8_t key, *uint8_t iv, *uint8_t counter);

uint8_t Speck_Encrypt(Speck_Cipher cipher_object, *uint8_t plaintext,*uint8_t ciphertext);

uint8_t Speck_Decrypt(Speck_Cipher cipher_object, *uint8_t ciphertext, *uint8_t plaintext);

#endif