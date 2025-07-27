# **Hardware TRNG "Kluchnik" — ESP32 Firmware**

This is the firmware repository for the "Kluchnik" hardware True Random Number Generator (TRNG). The firmware is written in C++ using the Arduino framework and is designed for the ESP32 Dev Kit C board.

## **⚙️ How it Works**
The device generates true random numbers by using two sources of physical entropy:
- **Chaotic Motion:** A 6-axis MPU-6050 sensor reads acceleration and rotation data that occurs when the user shakes the device. This data is unpredictable and serves as the basis for randomness generation.
- **Generator Jitter**: An external high-frequency oscillator (~100 kHz) creates a stream of pulses.

The ESP32 firmware uses the data from the MPU-6050 to open a digital "gate" for random intervals of time, allowing a random number of pulses to pass through to an 8-bit hardware counter. The final value on the counter is a single, truly random byte.

The generated 128-bit key is encrypted on the device using **AES-128-CBC** (`mbedtls`) and is transmitted over Wi-Fi to the desktop application.

## **🔌 Hardware Components**
To build the device, you will need:
- ESP32 Dev Kit C board
- MPU-6050 sensor (accelerometer + gyroscope)
- 1.3" I2C OLED display (128x64, SH1106 driver)
- 3x tactile push-buttons
- External Circuitry:
  - Clock pulse generator (~100 kHz)
  - Digital gate (e.g., a 74HC08 AND logic gate)
  - 8-bit counter (e.g., 74HC590)

## **Pinout (ESP32 Pins)**
| Component           | ESP32 Pin |
|:-------------------:|:---------:|
| **I2C (OLED, MPU)** |           |
| SDA                 | GPIO 21   |
| SCL                 | GPIO 22   |
| **Buttons**         |           |
| Up                  | GPIO 13   |
| Down                | GPIO 12   |
| Select              | GPIO 14   |
| **TRNG Circuit**    |           |
| Gate Control        | GPIO 27   |
| Counter Reset       | GPIO 26   |
| Read D0-D7          | GPIO 4, 5, 15, 16, 17, 18, 19, 23 |

## **🛠️ Build and Flash**

### **1. Development Environment**

It is recommended to use **PlatformIO** with Visual Studio Code for convenient library management and building. The **Arduino IDE** can also be used.

### **2. Library Installation**
Ensure you have the following libraries installed:
- `Adafruit GFX Library`
- `Adafruit BusIO`
- `Adafruit SH110X`
- `Adafruit MPU6050`
- `I2Cdev`

The `mbedtls` library is already included in the ESP32 toolchain for Arduino.

### **3. Wi-Fi Configuration**

Before flashing, you can change the name and password of the Wi-Fi access point that the device creates. Open the main `.ino` file and modify these lines:const char* ap_ssid = "Kluchnik";
const char* ap_password = "password";

### **4. Flashing**
1. Connect the ESP32 to your computer.
2. Select the correct COM port in your development environment.
3. Click "Upload".

After a successful flash, the device will create a Wi-Fi access point with the specified name. The OLED display will show the device's IP address (usually `192.168.4.1`).
