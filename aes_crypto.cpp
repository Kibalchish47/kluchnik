// aes_crypto.cpp

#include "aes_crypto.h"
#include <mbedtls/aes.h>

void generation_Key(char* key_gen) {
    const char charset[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
        "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ ";
    const int charSet_size = sizeof(charset) - 1;
    for (int i = 0; i < KEY_SIZE; i++) {
        key_gen[i] = charset[random(charSet_size)];
    }
    key_gen[KEY_SIZE] = '\0';
}

size_t applyPadding(const char* input, size_t inputLen, uint8_t* output) {
    size_t paddedLen = ((inputLen / BLOCK_SIZE) + 1) * BLOCK_SIZE;
    memcpy(output, input, inputLen);
    uint8_t padValue = paddedLen - inputLen;
    for (size_t i = inputLen; i < paddedLen; i++) {
        output[i] = padValue;
    }
    return paddedLen;
}

void encrypt(uint8_t* input, size_t len, char* key, uint8_t* output) {
    unsigned char iv[BLOCK_SIZE] = { 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, (const unsigned char*)key, KEY_SIZE * 8);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, len, iv, input, output);
    mbedtls_aes_free(&aes);
}

void decrypt(uint8_t* input, size_t len, char* key, uint8_t* output) {
    unsigned char iv[BLOCK_SIZE] = { 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, (const unsigned char*)key, KEY_SIZE * 8);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, len, iv, input, output);
    mbedtls_aes_free(&aes);
}

void printHex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (data[i] < 16) Serial.print('0');
        Serial.print(data[i], HEX);
        Serial.print(' ');
    }
    Serial.println();
}
