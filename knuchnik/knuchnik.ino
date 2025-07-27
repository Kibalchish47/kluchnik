/*******************************************************************
 * True Random Number Generator (TRNG) v2.5 - mbedtls AES-CBC
 *
 * This version replaces simple AES libraries with the robust,
 * standard mbedtls library included with the ESP-IDF.
 * It uses the more secure AES-128-CBC mode with PKCS7 padding.
 *******************************************************************/

// --- Core Libraries ---
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SH110X.h> // Using SH110X for 1.3" OLED
#include "I2Cdev.h"
#include "MPU6050.h"

// --- Cryptography Library ---
#include <mbedtls/aes.h>

// --- Networking Libraries ---
#include <WiFi.h>
#include "tcp.ino"

#define BUTTON_UP     13
#define BUTTON_DOWN   12
#define BUTTON_SELECT 14
#define GATE_CONTROL_PIN 27
#define COUNTER_RESET_PIN 26
const int counterPins[8] = {4, 5, 15, 16, 17, 18, 19, 23};

// --- Display & MPU Setup ---
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET    -1
Adafruit_SH1106G display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);
MPU6050 mpu;

// --- Main Menu Configuration ---
const int MENU_ITEMS_COUNT = 4;
const char* menuItems[MENU_ITEMS_COUNT] = {
  "Generate Password", "Set Length", "Set Complexity", "About"
};

// --- State Variables ---
int8_t selector = 0;
int8_t top_line_index = 0;
long lastDebounceTime = 0;
long debounceDelay = 200;

// --- Networking variables & conditions ---
static bool ap_enabled = false;
esp_netif_ip_info_t ip_info;

// --- Password Generation Settings ---
static int passwordLength = 16;
enum Complexity {
  NUMBERS_ONLY, LOWERCASE_ONLY, UPPERCASE_ONLY,
  LOWER_UPPER, LOWER_UPPER_NUM, ALL_CHARS
};
static uint8_t complexityLevel = ALL_CHARS;
const char* complexityNames[] = {
  "Numbers", "Lowercase", "Uppercase", "Letters", "Alphanumeric", "All Symbols"
};

// --- Cryptography ---
#define KEY_SIZE 16
#define BLOCK_SIZE 16
// This is the fixed key used to encrypt the random data
const unsigned char encryptionKey[KEY_SIZE] = {
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
};
// This is the fixed IV for CBC mode. MUST match the one in the Rust app.
const unsigned char iv[BLOCK_SIZE] = {
    0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
byte generatedKey[KEY_SIZE];

/* FUNCTION DEFINITION */
void  setup();
void    loop();
size_t applyPadding(const uint8_t*, size_t, uint8_t*);
void encrypt_cbc(uint8_t*, size_t, const uint8_t*, uint8_t*, uint8_t*);
byte readCounter();
byte generateRandomByte();
void runPasswordGeneration(WiFiClient);
void sendToPC(WiFiClient, byte*, size_t);
void handleRemoteClient();
void do_action_up();
void do_action_down();
void handleLocalInput();
void drawMenu();
void performAction();
void chooseLength();
void chooseComplexity();
void displayAbout();
void tcpSendMessage(char*);
esp_err_t wifiInitAP(void);
static void wifi_event_handler(void*, esp_event_base_t, int32_t, void*);


/*========================================================================*/
/* SETUP                                                                  */
/*========================================================================*/
void setup() {
  Serial.begin(115200);
  Wire.begin(); // Default I2C pins for ESP32 are 21 (SDA), 22 (SCL)

  pinMode(BUTTON_UP, INPUT_PULLUP);
  pinMode(BUTTON_DOWN, INPUT_PULLUP);
  pinMode(BUTTON_SELECT, INPUT_PULLUP);
  pinMode(GATE_CONTROL_PIN, OUTPUT);
  pinMode(COUNTER_RESET_PIN, OUTPUT);
  digitalWrite(GATE_CONTROL_PIN, LOW);

  for (int i = 0; i < 8; i++) {
    pinMode(counterPins[i], INPUT);
  }

  if (!display.begin(0x3C, true)) {
    Serial.println(F("SH1106 allocation failed"));
    for (;;);
  }

  mpu.initialize();
  if (!mpu.testConnection()) {
    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(SH110X_WHITE);
    display.setCursor(0, 0);
    display.println("MPU6050 Failed!");
    display.display();
    for (;;);
  }

  if (!wifiInitAP()) {
    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(SH110X_WHITE);
    display.setCursor(0, 0);
    display.println("WiFi Init Failed!");
    display.display();
    for (;;);
  }
  display.clearDisplay();
  display.display();
}

/*========================================================================*/
/* MAIN LOOP                                                              */
/*========================================================================*/
void loop() {
  handleLocalInput();
  handleRemoteClient();
  drawMenu();
}

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
size_t applyPadding(const uint8_t* input, size_t inputLen, uint8_t* output) {
  size_t paddedLen = ((inputLen / BLOCK_SIZE) + 1) * BLOCK_SIZE;
  memcpy(output, input, inputLen);
  uint8_t padValue = paddedLen - inputLen;
  for (size_t i = inputLen; i < paddedLen; i++) {
    output[i] = padValue;
  }
  return paddedLen;
}

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

/*void wifiInitAP() {
  WiFi.softAP(AP_SSID, AP_PASSWD);
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
}*/
void handleRemoteClient() {
  /*WiFiClient client = server.available();
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
  }*/
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
  }
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


esp_err_t wifiInitAP(void)
{
  // Initialising access point with needed configs
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  esp_netif_t* p_netif = esp_netif_create_default_wifi_ap();
  esp_netif_config_t netif_cfg = ESP_NETIF_DEFAULT_WIFI_AP();
  esp_netif_t* wifi_netif = esp_netif_new(&netif_cfg);
  ESP_LOGI(TAG, "%p", eth_netif);
  
  ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));
  
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg)); 

  // Get IP address of ESP32
  //esp_netif_t * p_netif = esp_netif_create_default_wifi_ap();
  esp_netif_ip_info_t if_info;
  ESP_ERROR_CHECK(esp_netif_get_ip_info(p_netif, &if_info));
  ESP_LOGI(TAG, "ESP32 IP:" IPSTR, IP2STR(&if_info.ip));

  wifi_config_t wifi_config = {
    .ap = {
      .ssid = AP_SSID,
      .password = AP_PASSWD,
      .ssid_len = strlen(AP_SSID),
      .channel = WIFI_CHANNEL_1,
      .authmode = WIFI_AUTH_WPA2_PSK,
      .max_connection = 1,
    },
  };

  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
  ESP_ERROR_CHECK(esp_wifi_start());
  return ESP_OK;
}

static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                                    int32_t event_id, void* event_data)
{
    if (event_id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t* event = (wifi_event_ap_staconnected_t*) event_data;
        ESP_LOGI(TAG, "station "MACSTR" join, AID=%d",
                 MAC2STR(event->mac), event->aid);
    } else if (event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        wifi_event_ap_stadisconnected_t* event = (wifi_event_ap_stadisconnected_t*) event_data;
        ESP_LOGI(TAG, "station "MACSTR" leave, AID=%d",
                 MAC2STR(event->mac), event->aid);
    }
}
  
void tcpSendMessage(char* msg)
{

  // Creating socket for TCP connection
  int16_t sock = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in server_addr {
    .sin_family = AF_INET,
    .sin_port = htons(TCP_PORT),
  };
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

  bind(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
  listen(sock, 1);

  while(1) {
     struct sockaddr_in client_addr;
     socklen_t addr_len = sizeof(client_addr);
     // on each iteration, create a new client with new socket address
     int8_t client = accept(sock, (struct sockaddr*)&client_addr, &addr_len);

     // recieve messages from client
     send(client, msg, strlen(msg), 0);

     close(client);
     delay(50);
  }
}

/*void tcpSendBytes(byte msg[MAX_LEN_TCP_MSG])
{

}*/
