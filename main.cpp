#include <Arduino.h>
#include "aes_crypto.h"

void setup() {
    Serial.begin(9600);
    delay(1000);
    randomSeed(analogRead(0));

    Serial.println("Введите строку и нажмите Enter:");

    while (Serial.available() == 0) delay(10);

    String inputString = Serial.readStringUntil('\n');
    inputString.trim();
	Serial.println(inputString);
    size_t inputLen = inputString.length();
    uint8_t paddedInput[64];
    size_t paddedLen = applyPadding(inputString.c_str(), inputLen, paddedInput);

    char key[KEY_SIZE + 1];
    generation_Key(key);
    Serial.print("Ключ: ");
    Serial.println(key);

    uint8_t encrypted[64];
    uint8_t decrypted[64];

    encrypt(paddedInput, paddedLen, key, encrypted);
    decrypt(encrypted, paddedLen, key, decrypted);

    Serial.println("Зашифровано (HEX):");
    printHex(encrypted, paddedLen);

    uint8_t padLen = decrypted[paddedLen - 1];
    if (padLen > 0 && padLen <= BLOCK_SIZE) {
        Serial.println("Расшифровка (без паддинга):");
        for (size_t i = 0; i < paddedLen - padLen; i++) {
            Serial.print((char)decrypted[i]);
        }
        Serial.println();
    } else {
        Serial.println("Ошибка паддинга!");
    }
}

void loop() {}


