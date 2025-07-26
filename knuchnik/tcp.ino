/*******************************************************************
 *
*******************************************************************/

// --- networking libraries ---
#include "esp_wifi.h"
#include "esp_netif.h"

// --- misc libraries ---
#include <string.h>
#include "lwip/sockets.h"


// --- Display & MPU Setup ---
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 32

// --- TCP and networking ---
#define SERVER_PORT 80
#define TCP_PORT 3333
#define MAX_CLIENTS 1 /* maximum of 1 connection by TCP */

// --- Networking config ---
#define AP_SSID "Kluchnik"
#define AP_PASSWD "password"

/* TODO *
 * Make interface from SD card to ESP
 * Read specific files (plaintext?):
   - Wifi password file
   - User's symmetric AES key
   - password keys (encrypted with user's AES key)
 * TCP interface
   - ESP creates a hotspot point (no security)
   - user connects to point
   - ESP sends data through TCP
 */

