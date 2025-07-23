/*******************************************************************
 * True Random Number Generator (TRNG) v2.4 - EXPERIMENTAL
 *
 * !!! WARNING: FOR EDUCATIONAL PURPOSES ONLY !!!
 * This version replaces the standard AESLib library with a custom,
 * by-hand implementation of the AES-128 (ECB) algorithm.
 * DO NOT USE THIS CODE IN A PRODUCTION ENVIRONMENT.
 * Custom crypto is notoriously difficult to get right and secure.
 *******************************************************************/

// --- Core Libraries ---
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include "I2Cdev.h"
#include "MPU6050.h"
// #include "AESLib.h" // AESLib is intentionally removed for this experiment

// --- Networking Libraries ---
#include <WiFi.h>

// --- Pin Definitions ---
#define BUTTON_UP     13
#define BUTTON_DOWN   12
#define BUTTON_SELECT 14
#define GATE_CONTROL_PIN 27
#define COUNTER_RESET_PIN 26
const int counterPins[8] = {4, 5, 15, 16, 17, 18, 19, 23};

// --- Display & MPU Setup ---
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 32
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, -1);
MPU6050 mpu;

// --- TCP and Networking ---
#define TCP_PORT 80
WiFiServer server(TCP_PORT);
const char* ap_ssid = "Kluchnik";
const char* ap_password = "password";

// --- Main Menu Configuration ---
const int MENU_ITEMS_COUNT = 4;
const char* menuItems[MENU_ITEMS_COUNT] = {
  "Generate Password",
  "Set Length",
  "Set Complexity",
  "About"
};

// --- State Variables ---
int8_t selector = 0;
int8_t top_line_index = 0;
long lastDebounceTime = 0;
long debounceDelay = 200;

// --- Password Generation Settings ---
int passwordLength = 16;
enum Complexity {
  NUMBERS_ONLY, LOWERCASE_ONLY, UPPERCASE_ONLY,
  LOWER_UPPER, LOWER_UPPER_NUM, ALL_CHARS
};
int complexityLevel = ALL_CHARS;
const char* complexityNames[] = {
  "Numbers", "Lowercase", "Uppercase", "Letters", "Alphanumeric", "All Symbols"
};

// --- Cryptography ---
uint8_t encryptionKey[] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
byte generatedKey[16];


/*========================================================================*/
/* CUSTOM AES-128 IMPLEMENTATION (EXPERIMENTAL)                           */
/*========================================================================*/
namespace CustomAES {

// --- S-box and Rcon tables for AES-128 ---
const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const uint8_t Rcon[11] = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

// --- Helper Functions ---
void keyExpansion(const uint8_t* key, uint8_t* roundKeys) {
    memcpy(roundKeys, key, 16);
    for (int i = 1; i < 11; ++i) {
        uint8_t* prev = roundKeys + (i - 1) * 16;
        uint8_t* curr = roundKeys + i * 16;
        uint8_t temp[4];

        memcpy(temp, prev + 12, 4); // Last column of previous key

        // RotWord
        uint8_t t = temp[0];
        temp[0] = temp[1];
        temp[1] = temp[2];
        temp[2] = temp[3];
        temp[3] = t;

        // SubWord
        for (int j = 0; j < 4; ++j) {
            temp[j] = sbox[temp[j]];
        }

        // Rcon
        temp[0] ^= Rcon[i];

        for (int j = 0; j < 4; ++j) {
            curr[j] = prev[j] ^ temp[j];
        }
        for (int j = 4; j < 16; ++j) {
            curr[j] = prev[j] ^ curr[j - 4];
        }
    }
}

void addRoundKey(uint8_t* state, const uint8_t* roundKey) {
    for (int i = 0; i < 16; ++i) {
        state[i] ^= roundKey[i];
    }
}

void subBytes(uint8_t* state) {
    for (int i = 0; i < 16; ++i) {
        state[i] = sbox[state[i]];
    }
}

void shiftRows(uint8_t* state) {
    uint8_t temp;
    // Row 1
    temp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = temp;
    // Row 2
    temp = state[2]; state[2] = state[10]; state[10] = temp;
    temp = state[6]; state[6] = state[14]; state[14] = temp;
    // Row 3
    temp = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = temp;
}

uint8_t xtime(uint8_t x) {
    return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

void mixColumns(uint8_t* state) {
    uint8_t t, Tmp, Tm;
    for (int i = 0; i < 4; ++i) {
        t = state[i * 4 + 0] ^ state[i * 4 + 1] ^ state[i * 4 + 2] ^ state[i * 4 + 3];
        Tmp = state[i * 4 + 0] ^ state[i * 4 + 1]; Tmp = xtime(Tmp); state[i * 4 + 0] ^= Tmp ^ t;
        Tmp = state[i * 4 + 1] ^ state[i * 4 + 2]; Tmp = xtime(Tmp); state[i * 4 + 1] ^= Tmp ^ t;
        Tmp = state[i * 4 + 2] ^ state[i * 4 + 3]; Tmp = xtime(Tmp); state[i * 4 + 2] ^= Tmp ^ t;
        Tmp = state[i * 4 + 3] ^ state[i * 4 + 0]; Tmp = xtime(Tmp); state[i * 4 + 3] ^= Tmp ^ t;
    }
}

// --- Main Encryption Function ---
void encrypt(uint8_t* data, const uint8_t* key) {
    uint8_t roundKeys[176];
    keyExpansion(key, roundKeys);

    addRoundKey(data, roundKeys);

    for (int i = 1; i < 10; ++i) {
        subBytes(data);
        shiftRows(data);
        mixColumns(data);
        addRoundKey(data, roundKeys + i * 16);
    }

    subBytes(data);
    shiftRows(data);
    addRoundKey(data, roundKeys + 10 * 16);
}

} // namespace CustomAES


/*========================================================================*/
/* SETUP                                                                  */
/*========================================================================*/
void setup() {
  Serial.begin(115200);
  Wire.begin();

  pinMode(BUTTON_UP, INPUT_PULLUP);
  pinMode(BUTTON_DOWN, INPUT_PULLUP);
  pinMode(BUTTON_SELECT, INPUT_PULLUP);
  pinMode(GATE_CONTROL_PIN, OUTPUT);
  pinMode(COUNTER_RESET_PIN, OUTPUT);
  digitalWrite(GATE_CONTROL_PIN, LOW);

  for (int i = 0; i < 8; i++) {
    pinMode(counterPins[i], INPUT);
  }

  if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    Serial.println(F("SSD1306 allocation failed"));
    for (;;);
  }

  mpu.initialize();
  if (!mpu.testConnection()) {
    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(WHITE);
    display.setCursor(0, 0);
    display.println("MPU6050 Failed!");
    display.display();
    for (;;);
  }

  wifiInitAP();

  display.clearDisplay();
  display.display();
}

/*========================================================================*/
/* MAIN LOOP                                                              */
/*========================================================================*/
void loop() {
  handleLocalInput(); 
  handleRemoteClient(); // Временно отключаем сеть
  drawMenu();
  delay(10); // Небольшая задержка для стабильности
}

/*========================================================================*/
/* MENU & INPUT HANDLING                                                  */
/*========================================================================*/
void do_action_up() {
  selector--;
  if (selector < 0) selector = MENU_ITEMS_COUNT - 1;
  if (selector < top_line_index) top_line_index = selector;
}
void do_action_down() {
  selector++;
  if (selector >= MENU_ITEMS_COUNT) selector = 0;
  if (selector >= top_line_index + 3) top_line_index = selector - 2;
}

void handleLocalInput() {
  if ((millis() - lastDebounceTime) < debounceDelay) return;

  if (digitalRead(BUTTON_UP) == LOW) {
    do_action_up();
    lastDebounceTime = millis();
  }
  if (digitalRead(BUTTON_DOWN) == LOW) {
    do_action_down();
    lastDebounceTime = millis();
  }
  if (digitalRead(BUTTON_SELECT) == LOW) {
    performAction();
    lastDebounceTime = millis();
  }
}

void drawMenu() {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(WHITE);

  for (int i = 0; i < 3; i++) {
    int item_index = top_line_index + i;
    if (item_index < MENU_ITEMS_COUNT) {
      display.setCursor(10, i * 10);
      display.print(menuItems[item_index]);
    }
  }

  int selector_y_pos = (selector - top_line_index) * 10;
  display.setCursor(0, selector_y_pos);
  display.print(">");
  display.display();
}

void performAction() {
  switch (selector) {
    case 0:
      display.clearDisplay();
      display.setCursor(10, 12);
      display.print("Use PC app to gen.");
      display.display();
      delay(2000);
      break;
    case 1:
      chooseLength();
      break;
    case 2:
      chooseComplexity();
      break;
    case 3:
      displayAbout();
      break;
  }
}

/*========================================================================*/
/* CORE TRNG & CRYPTO LOGIC                                               */
/*========================================================================*/
byte readCounter() {
  byte value = 0;
  for (int i = 0; i < 8; i++) {
    if (digitalRead(counterPins[i]) == HIGH) {
      value |= (1 << i);
    }
  }
  return value;
}

byte generateRandomByte() {
  int16_t ax, ay, az, gx, gy, gz;
  digitalWrite(COUNTER_RESET_PIN, HIGH);
  delayMicroseconds(10);
  digitalWrite(COUNTER_RESET_PIN, LOW);

  unsigned long startTime = millis();
  while (millis() - startTime < 200) {
    mpu.getMotion6(&ax, &ay, &az, &gx, &gy, &gz);
    long motionEnergy = abs(ax) + abs(ay) + abs(az) + abs(gx) + abs(gy) + abs(gz);
    unsigned long gateTime = (motionEnergy % 100) + 10;
    digitalWrite(GATE_CONTROL_PIN, HIGH);
    delayMicroseconds(gateTime);
    digitalWrite(GATE_CONTROL_PIN, LOW);
    delayMicroseconds(10);
  }
  return readCounter();
}

void runPasswordGeneration(WiFiClient client) {
  display.clearDisplay();
  display.setCursor(10, 5);
  display.print("Shaking device to");
  display.setCursor(25, 15);
  display.print("gather entropy...");
  display.display();

  for (int i = 0; i < 16; i++) {
    generatedKey[i] = generateRandomByte();
  }
  
  // --- Using the custom AES implementation ---
  CustomAES::encrypt(generatedKey, encryptionKey);
  
  sendToPC(client, generatedKey);
  
  display.clearDisplay();
  display.setCursor(35, 12);
  display.print("Data sent!");
  display.display();
  delay(2000);
}

void sendToPC(WiFiClient client, byte* dataToSend) {
  String payload = "LEN:" + String(passwordLength) +
                   ",COMPLEX:" + String(complexityLevel) +
                   ",KEY:";
  
  char hexBuffer[3];
  for (int i = 0; i < 16; i++) {
    sprintf(hexBuffer, "%02X", dataToSend[i]);
    payload += hexBuffer;
  }
  payload += "\n";
  
  client.print(payload);
}

/*========================================================================*/
/* NETWORKING FUNCTIONS                                                   */
/*========================================================================*/
void wifiInitAP() {
  WiFi.softAP(ap_ssid, ap_password);
  IPAddress IP = WiFi.softAPIP();
  Serial.print("AP IP address: ");
  Serial.println(IP);
  display.clearDisplay();
  display.setCursor(0,0);
  display.println("AP: Kluchnik");
  display.setCursor(0,10);
  display.println(IP);
  display.display();
  server.begin();
}

void handleRemoteClient() {
  WiFiClient client = server.available();
  if (client) {
    Serial.println("Client connected!");
    String currentLine = "";
    while (client.connected()) {
      if (client.available()) {
        char c = client.read();
        if (c == '\n') {
          if (currentLine.startsWith("GET_DATA")) {
            runPasswordGeneration(client);
          } else if (currentLine.startsWith("CMD_UP")) {
            do_action_up();
          } else if (currentLine.startsWith("CMD_DOWN")) {
            do_action_down();
          } else if (currentLine.startsWith("CMD_SELECT")) {
            performAction();
          }
          currentLine = "";
          break;
        } else if (c != '\r') {
          currentLine += c;
        }
      }
    }
    client.stop();
    Serial.println("Client disconnected.");
  }
}

/*========================================================================*/
/* ADVANCED UI FUNCTIONS                                                  */
/*========================================================================*/
// NOTE: These functions remain unchanged from the previous version.
void chooseLength() {
  bool setting = true;
  while (setting) {
    if ((millis() - lastDebounceTime) > debounceDelay) {
      if (digitalRead(BUTTON_UP) == LOW) {
        passwordLength++;
        if (passwordLength > 64) passwordLength = 64;
        lastDebounceTime = millis();
      }
      if (digitalRead(BUTTON_DOWN) == LOW) {
        passwordLength--;
        if (passwordLength < 8) passwordLength = 8;
        lastDebounceTime = millis();
      }
      if (digitalRead(BUTTON_SELECT) == LOW) {
        setting = false;
        lastDebounceTime = millis();
      }
    }
    display.clearDisplay();
    display.setCursor(0, 0);
    display.print("Set Length (8-64)");
    display.setCursor(0, 12);
    display.print("Up/Down=+1/-1 Sel=OK");
    display.setTextSize(2);
    display.setCursor(50, 16);
    display.print(passwordLength);
    display.setTextSize(1);
    display.display();
  }
  delay(200);
}

void chooseComplexity() {
  bool setting = true;
  int tempSelector = complexityLevel;
  int numComplexityLevels = sizeof(complexityNames) / sizeof(char*);

  while (setting) {
    if ((millis() - lastDebounceTime) > debounceDelay) {
      if (digitalRead(BUTTON_UP) == LOW) {
        tempSelector--;
        if (tempSelector < 0) tempSelector = numComplexityLevels - 1;
        lastDebounceTime = millis();
      }
      if (digitalRead(BUTTON_DOWN) == LOW) {
        tempSelector++;
        if (tempSelector >= numComplexityLevels) tempSelector = 0;
        lastDebounceTime = millis();
      }
      if (digitalRead(BUTTON_SELECT) == LOW) {
        complexityLevel = tempSelector;
        setting = false;
        lastDebounceTime = millis();
      }
    }
    display.clearDisplay();
    display.setCursor(0, 0);
    display.print("Set Complexity");
    display.setCursor(0, 12);
    display.print("Up/Down=Change Sel=OK");
    display.setTextSize(1);
    display.setCursor(20, 22);
    display.print(complexityNames[tempSelector]);
    display.display();
  }
  delay(200);
}

void displayAbout() {
  const int aboutPagesCount = 4;
  const char* aboutTitles[] = {"< Back", "Generate", "Set Length", "Set Complexity"};
  int aboutSelector = 1;
  bool inAboutMenu = true;

  while(inAboutMenu) {
    if ((millis() - lastDebounceTime) > debounceDelay) {
      if (digitalRead(BUTTON_UP) == LOW) {
        aboutSelector--;
        if (aboutSelector < 0) aboutSelector = aboutPagesCount - 1;
        lastDebounceTime = millis();
      }
      if (digitalRead(BUTTON_DOWN) == LOW) {
        aboutSelector++;
        if (aboutSelector >= aboutPagesCount) aboutSelector = 0;
        lastDebounceTime = millis();
      }
      if (digitalRead(BUTTON_SELECT) == LOW) {
        if (aboutSelector == 0) {
          inAboutMenu = false;
        } else {
          display.clearDisplay();
          display.setCursor(0,0);
          display.print(aboutTitles[aboutSelector]);
          display.drawFastHLine(0, 9, 128, WHITE);
          
          switch(aboutSelector) {
            case 1:
              display.setCursor(0,12); display.print("Use PC app to gen.");
              display.setCursor(0,22); display.print("Shake the device.");
              break;
            case 2:
              display.setCursor(0,12); display.print("Up/Down to change.");
              display.setCursor(0,22); display.print("Select to save.");
              break;
            case 3:
              display.setCursor(0,12); display.print("Select from a list");
              display.setCursor(0,22); display.print("of char sets.");
              break;
          }
          display.display();
          delay(500);
          while(digitalRead(BUTTON_SELECT) == HIGH);
        }
        lastDebounceTime = millis();
      }
    }
    
    display.clearDisplay();
    display.setCursor(0,0);
    display.print("-- About --");
    display.setCursor(0, 12 + (aboutSelector*8));
    display.print(">");
    display.setCursor(10, 12); display.print(aboutTitles[0]);
    display.setCursor(10, 20); display.print(aboutTitles[1]);
    display.display();
  }
  delay(200);
}
