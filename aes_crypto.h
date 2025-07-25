// aes_crypto.h

#pragma once

#include <Arduino.h>

#define KEY_SIZE 16
#define BLOCK_SIZE 16

void generation_Key(char* key_gen);
size_t applyPadding(const char* input, size_t inputLen, uint8_t* output);
void encrypt(uint8_t* input, size_t len, char* key, uint8_t* output);
void decrypt(uint8_t* input, size_t len, char* key, uint8_t* output);
void printHex(const uint8_t* data, size_t len);
