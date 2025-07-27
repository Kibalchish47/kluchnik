
/*========================================================================*/
/* SETUP                                                                  */
/*========================================================================*/
void setup();

/*========================================================================*/
/* MAIN LOOP                                                              */
/*========================================================================*/
void loop();

/*========================================================================*/
/* CRYPTOGRAPHY HELPER FUNCTIONS                                          */
/*========================================================================*/

/**
 * @brief Applies PKCS7 padding to the input data.
 * @param input The data to pad.
 * @param inputLen The length of the input data.
 * @param output Buffer to store the padded data.
 * @return The new length of the data after padding.
 */
size_t applyPadding(const uint8_t* input, size_t inputLen, uint8_t* output);

/**
 * @brief Encrypts data using AES-128-CBC with mbedtls.
 * @param input The plaintext data to encrypt.
 * @param len The length of the plaintext data.
 * @param key The 16-byte encryption key.
 * @param iv The 16-byte initialization vector.
 * @param output Buffer to store the ciphertext.
 */
void encrypt_cbc(uint8_t* input, size_t len, const uint8_t* key, uint8_t* iv_local, uint8_t* output) {
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, key, KEY_SIZE * 8);
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, len, iv_local, input, output);
  mbedtls_aes_free(&aes);
}


/*========================================================================*/
/* CORE TRNG & NETWORKING LOGIC                                           */
/*========================================================================*/


/* On call, read data from counter */
byte readCounter() {
  byte value = 0;
  for (int i = 0; i < 8; i++) {
    if (digitalRead(counterPins[i]) == HIGH) {
      value |= (1 << i);
    }
  }
  return value;
}


/* Using the readCounter() function, read a byte after a randomised amount of time. */
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

  // 1. Generate 16 random bytes
  for (int i = 0; i < 16; i++) {
    generatedKey[i] = generateRandomByte();
  }
  
  // 2. Pad the data. Since input is 16 bytes, output will be 32 bytes.
  uint8_t paddedData[32];
  size_t paddedLen = applyPadding(generatedKey, KEY_SIZE, paddedData);

  // 3. Encrypt the padded data
  uint8_t encryptedData[32];
  uint8_t iv_copy[BLOCK_SIZE]; // mbedtls modifies the IV, so we use a copy
  memcpy(iv_copy, iv, BLOCK_SIZE);
  encrypt_cbc(paddedData, paddedLen, encryptionKey, iv_copy, encryptedData);
  
  // 4. Send the encrypted data to the PC
  sendToPC(client, encryptedData, paddedLen);
  
  display.clearDisplay();
  display.setCursor(35, 12);
  display.print("Data sent!");
  display.display();
  delay(2000);
}

void sendToPC(WiFiClient client, byte* dataToSend, size_t len) {
  String payload = "LEN:" + String(passwordLength) +
                   ",COMPLEX:" + String(complexityLevel) +
                   ",KEY:";
  
  char hexBuffer[3];
  for (size_t i = 0; i < len; i++) {
    sprintf(hexBuffer, "%02X", dataToSend[i]);
    payload += hexBuffer;
  }
  payload += "\n";
  
  client.print(payload);
}

void wifiInitAP() {
  WiFi.softAP(AP_SSID, AP_PASSWORD);
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
      // Add a timeout to prevent blocking forever
      unsigned long timeout = millis();
      while(!client.available() && millis() - timeout < 1000) {
        // Wait for data or timeout
      }
      if(!client.available()) {
        break; // No data received, disconnect
      }
      
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
    client.stop();
    Serial.println("Client disconnected.");
  }
}

// --- UI AND MENU FUNCTIONS (UNCHANGED) ---
// ... (The code for handleLocalInput, drawMenu, performAction, chooseLength, etc. is omitted for brevity but should be included here)
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
  if (digitalRead(BUTTON_UP) == LOW) { do_action_up(); lastDebounceTime = millis(); }
  if (digitalRead(BUTTON_DOWN) == LOW) { do_action_down(); lastDebounceTime = millis(); }
  if (digitalRead(BUTTON_SELECT) == LOW) { performAction(); lastDebounceTime = millis(); }
}

void drawMenu() {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SH110X_WHITE);
  for (int i = 0; i < 3; i++) {
    int item_index = top_line_index + i;
    if (item_index < MENU_ITEMS_COUNT) {
      display.setCursor(10, 5 + i * 10);
      display.print(menuItems[item_index]);
    }
  }
  int selector_y_pos = 5 + (selector - top_line_index) * 10;
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
    case 1: chooseLength(); break;
    case 2: chooseComplexity(); break;
    case 3: displayAbout(); break;
  }
}
void chooseLength() {
  bool setting = true;
  while (setting) {
    if ((millis() - lastDebounceTime) > debounceDelay) {
      if (digitalRead(BUTTON_UP) == LOW) { passwordLength++; if (passwordLength > 64) passwordLength = 64; lastDebounceTime = millis(); 
      if (digitalRead(BUTTON_DOWN) == LOW) { passwordLength--; if (passwordLength < 8) passwordLength = 8; lastDebounceTime = millis(); }
      if (digitalRead(BUTTON_SELECT) == LOW) { setting = false; lastDebounceTime = millis(); }
    }
    display.clearDisplay();
    display.setCursor(0, 0); display.print("Set Length (8-64)");
    display.setCursor(0, 12); display.print("Up/Down=+1/-1 Sel=OK");
    display.setTextSize(2); display.setCursor(50, 25); display.print(passwordLength);
    display.setTextSize(1); display.display();
  }
  delay(200);
}
void chooseComplexity() {
  bool setting = true;
  int tempSelector = complexityLevel;
  int numComplexityLevels = sizeof(complexityNames) / sizeof(char*);
  while (setting) {
    if ((millis() - lastDebounceTime) > debounceDelay) {
      if (digitalRead(BUTTON_UP) == LOW) { tempSelector--; if (tempSelector < 0) tempSelector = numComplexityLevels - 1; lastDebounceTime = millis(); }
      if (digitalRead(BUTTON_DOWN) == LOW) { tempSelector++; if (tempSelector >= numComplexityLevels) tempSelector = 0; lastDebounceTime = millis(); }
      if (digitalRead(BUTTON_SELECT) == LOW) { complexityLevel = tempSelector; setting = false; lastDebounceTime = millis(); }
    }
    display.clearDisplay();
    display.setCursor(0, 0); display.print("Set Complexity");
    display.setCursor(0, 12); display.print("Up/Down=Change Sel=OK");
    display.setTextSize(1); display.setCursor(20, 25); display.print(complexityNames[tempSelector]);
    display.display();
  }zyy
  delay(200);
}
void displayAbout() {
  display.clearDisplay();
  display.setCursor(0, 0);
  display.print("TRNG v2.5");
  display.setCursor(0, 10);
  display.print("mbedtls AES-CBC");
  display.setCursor(0, 20);
  display.print("Press Select...");
  display.display();
  delay(500);
  while(digitalRead(BUTTON_SELECT) == HIGH);
}
