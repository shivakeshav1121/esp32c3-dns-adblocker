// Copy this file to "secrets.h" (same folder) and fill in your values.
// secrets.h is git-ignored so your Wi-Fi password never gets published.
#pragma once

const char* WIFI_SSID = "YOUR_2.4GHZ_WIFI_NAME";   // ESP32-C3 supports 2.4 GHz only
const char* WIFI_PASS = "YOUR_WIFI_PASSWORD";

// Protects the web page's update/upload buttons (HTTP Basic Auth). Use a real password.
const char* WEB_USER = "admin";
const char* WEB_PASS = "CHANGE_ME";
