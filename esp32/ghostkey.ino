#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <ESP32Servo.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include "mbedtls/md.h"
#include "mbedtls/aes.h"
#include "esp_system.h"

// ============================================================
// WIFI
// ============================================================

const char* WIFI_SSID = "NARZO";
const char* WIFI_PASSWORD = "aahilhere";

// IMPORTANT:
// Replace this with the IP address of the laptop running Flask.
const char* SERVER = "http://10.188.102.195:5000";

// ============================================================
// NODE 1 IDENTITY
// ============================================================

const char* DEVICE_ID = "READER_001";
const char* DEVICE_SECRET = "reader_secret_001";

// ============================================================
// AES-128-CBC SHARED KEY
// ============================================================
// This MUST match AES_KEY_HEX in security.py ("3fae1baf5e3d4c2c9be2f1a6c88f3ac0")
// and AES_KEY_HEX in app.js. It encrypts every HTTP body this
// node sends/receives, on top of the HMAC auth below - a basic
// shared-key scheme, not a full TLS replacement.
// ============================================================

const uint8_t AES_KEY[16] = {
  0x3f, 0xae, 0x1b, 0xaf, 0x5e, 0x3d, 0x4c, 0x2c,
  0x9b, 0xe2, 0xf1, 0xa6, 0xc8, 0x8f, 0x3a, 0xc0
};

// ============================================================
// PINS
// ============================================================

#define SERVO_PIN 18
#define BUZZER_PIN 25

// OLED
#define OLED_SDA 21
#define OLED_SCL 22

// ============================================================
// OLED
// ============================================================

#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64

Adafruit_SSD1306 display(
  SCREEN_WIDTH,
  SCREEN_HEIGHT,
  &Wire,
  -1
);

// ============================================================
// SERVO
// ============================================================

Servo lockServo;

#define LOCKED_ANGLE 0
#define UNLOCKED_ANGLE 90

// ============================================================
// OLED FUNCTIONS
// ============================================================

void oledClear() {

  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
}

void oledMessage(String line1, String line2 = "", String line3 = "") {

  oledClear();

  display.setTextSize(1);

  display.println(line1);

  if (line2 != "") {
    display.println();
    display.println(line2);
  }

  if (line3 != "") {
    display.println();
    display.println(line3);
  }

  display.display();
}


void oledLarge(String message) {

  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);

  display.setTextSize(2);
  display.setCursor(0, 10);

  display.println(message);

  display.display();
}


// ============================================================
// SERVO FUNCTIONS
// ============================================================

void lockDoor() {

  lockServo.write(LOCKED_ANGLE);

  Serial.println("SERVO: LOCKED");
}


void unlockDoor() {

  lockServo.write(UNLOCKED_ANGLE);

  Serial.println("SERVO: UNLOCKED");
}


// ============================================================
// BUZZER
// ============================================================

void beep() {

  digitalWrite(BUZZER_PIN, HIGH);
  delay(150);
  digitalWrite(BUZZER_PIN, LOW);
}


void deniedBeep() {

  for (int i = 0; i < 3; i++) {

    digitalWrite(BUZZER_PIN, HIGH);
    delay(100);

    digitalWrite(BUZZER_PIN, LOW);
    delay(100);
  }
}


// ============================================================
// HMAC SHA256
// ============================================================

String hmacSHA256(String secret, String message) {

  byte hmacResult[32];

  const mbedtls_md_info_t* mdInfo =
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

  mbedtls_md_context_t ctx;

  mbedtls_md_init(&ctx);

  mbedtls_md_setup(&ctx, mdInfo, 1);

  mbedtls_md_hmac_starts(
      &ctx,
      (const unsigned char*)secret.c_str(),
      secret.length()
  );

  mbedtls_md_hmac_update(
      &ctx,
      (const unsigned char*)message.c_str(),
      message.length()
  );

  mbedtls_md_hmac_finish(
      &ctx,
      hmacResult
  );

  mbedtls_md_free(&ctx);

  String output = "";

  for (int i = 0; i < 32; i++) {

    if (hmacResult[i] < 16) {
      output += "0";
    }

    output += String(hmacResult[i], HEX);
  }

  return output;
}


// ============================================================
// AES-128-CBC HELPERS
// ============================================================

String bytesToHex(const uint8_t* data, size_t len) {

  String out = "";

  for (size_t i = 0; i < len; i++) {

    if (data[i] < 16) {
      out += "0";
    }

    out += String(data[i], HEX);
  }

  return out;
}


size_t hexToBytes(const String &hex, uint8_t* out, size_t maxLen) {

  size_t len = hex.length() / 2;

  if (len > maxLen) {
    len = maxLen;
  }

  for (size_t i = 0; i < len; i++) {

    String byteStr = hex.substring(i * 2, i * 2 + 2);

    out[i] = (uint8_t) strtol(byteStr.c_str(), NULL, 16);
  }

  return len;
}


// Encrypt a plaintext string. Fills ivHexOut / dataHexOut with
// hex strings ready to drop straight into the outgoing JSON.
bool aesEncrypt(String plaintext, String &ivHexOut, String &dataHexOut) {

  size_t inLen = plaintext.length();

  // PKCS7 padding - always adds at least 1 byte, up to 16
  size_t padLen = 16 - (inLen % 16);
  size_t totalLen = inLen + padLen;

  uint8_t* buf = (uint8_t*) malloc(totalLen);

  if (!buf) {
    return false;
  }

  memcpy(buf, plaintext.c_str(), inLen);

  for (size_t i = inLen; i < totalLen; i++) {
    buf[i] = (uint8_t) padLen;
  }

  uint8_t iv[16];
  esp_fill_random(iv, 16);

  // mbedtls_aes_crypt_cbc mutates the IV buffer it's given, so
  // hand it a scratch copy and keep the original for the output.
  uint8_t ivWorking[16];
  memcpy(ivWorking, iv, 16);

  uint8_t* outBuf = (uint8_t*) malloc(totalLen);

  if (!outBuf) {
    free(buf);
    return false;
  }

  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_enc(&ctx, AES_KEY, 128);

  mbedtls_aes_crypt_cbc(
    &ctx,
    MBEDTLS_AES_ENCRYPT,
    totalLen,
    ivWorking,
    buf,
    outBuf
  );

  mbedtls_aes_free(&ctx);

  ivHexOut = bytesToHex(iv, 16);
  dataHexOut = bytesToHex(outBuf, totalLen);

  free(buf);
  free(outBuf);

  return true;
}


// Decrypt {ivHex, dataHex} back into a plaintext string.
bool aesDecrypt(String ivHex, String dataHex, String &plaintextOut) {

  uint8_t iv[16];
  hexToBytes(ivHex, iv, 16);

  size_t dataLen = dataHex.length() / 2;

  if (dataLen == 0 || dataLen % 16 != 0) {
    return false;
  }

  uint8_t* cipherBuf = (uint8_t*) malloc(dataLen);
  uint8_t* outBuf = (uint8_t*) malloc(dataLen);

  if (!cipherBuf || !outBuf) {
    if (cipherBuf) free(cipherBuf);
    if (outBuf) free(outBuf);
    return false;
  }

  hexToBytes(dataHex, cipherBuf, dataLen);

  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_dec(&ctx, AES_KEY, 128);

  mbedtls_aes_crypt_cbc(
    &ctx,
    MBEDTLS_AES_DECRYPT,
    dataLen,
    iv,
    cipherBuf,
    outBuf
  );

  mbedtls_aes_free(&ctx);

  // Strip PKCS7 padding
  uint8_t padLen = outBuf[dataLen - 1];
  size_t plainLen = dataLen;

  if (padLen > 0 && padLen <= 16 && padLen <= dataLen) {
    plainLen = dataLen - padLen;
  }

  char* strBuf = (char*) malloc(plainLen + 1);

  if (!strBuf) {
    free(cipherBuf);
    free(outBuf);
    return false;
  }

  memcpy(strBuf, outBuf, plainLen);
  strBuf[plainLen] = '\0';

  plaintextOut = String(strBuf);

  free(cipherBuf);
  free(outBuf);
  free(strBuf);

  return true;
}


// ============================================================
// CARD SECRETS
// ============================================================

String getCardSecret(String cardID) {

  if (cardID == "CARD_001") {
    return "card_secret_001";
  }

  if (cardID == "CARD_002") {
    return "card_secret_002";
  }

  if (cardID == "CARD_999") {
    return "unknown_secret";
  }

  return "";
}


// ============================================================
// GET CHALLENGE
// ============================================================

bool getChallenge(String &nonce) {

  HTTPClient http;

  String url = String(SERVER) + "/api/challenge";

  Serial.println();
  Serial.println("REQUESTING CHALLENGE");
  Serial.println(url);

  oledMessage(
    "GHOST KEY",
    "REQUESTING",
    "CHALLENGE..."
  );

  http.begin(url);

  int httpCode = http.GET();

  Serial.print("HTTP STATUS: ");
  Serial.println(httpCode);

  if (httpCode <= 0) {

    Serial.print("HTTP ERROR: ");
    Serial.println(http.errorToString(httpCode));

    oledMessage(
      "SERVER ERROR",
      "NO CONNECTION",
      "HTTP " + String(httpCode)
    );

    http.end();

    return false;
  }

  String response = http.getString();

  Serial.println("SERVER RESPONSE (ENCRYPTED):");
  Serial.println(response);

  // ----------------------------------------------------------
  // Response is {"iv": "...", "data": "..."} - decrypt first
  // ----------------------------------------------------------

  DynamicJsonDocument envelope(1024);

  DeserializationError envError =
      deserializeJson(envelope, response);

  if (envError || !envelope["iv"] || !envelope["data"]) {

    Serial.println("ENVELOPE PARSE ERROR");

    oledMessage(
      "SERVER ERROR",
      "BAD ENVELOPE"
    );

    http.end();

    return false;
  }

  String plaintext;

  if (!aesDecrypt(
        envelope["iv"].as<String>(),
        envelope["data"].as<String>(),
        plaintext
      )) {

    Serial.println("DECRYPTION FAILED");

    oledMessage(
      "SERVER ERROR",
      "DECRYPT FAIL"
    );

    http.end();

    return false;
  }

  Serial.println("DECRYPTED:");
  Serial.println(plaintext);

  DynamicJsonDocument doc(2048);

  DeserializationError error =
      deserializeJson(doc, plaintext);

  if (error) {

    Serial.println("JSON PARSE ERROR");

    oledMessage(
      "SERVER ERROR",
      "BAD RESPONSE"
    );

    http.end();

    return false;
  }

  if (!doc["nonce"]) {

    Serial.println("NO NONCE RECEIVED");

    oledMessage(
      "SERVER ERROR",
      "NO CHALLENGE"
    );

    http.end();

    return false;
  }

  nonce = doc["nonce"].as<String>();

  Serial.print("CHALLENGE NONCE: ");
  Serial.println(nonce);

  http.end();

  return true;
}


// ============================================================
// SEND ACCESS REQUEST
// ============================================================

bool sendAccess(
  String cardID,
  String nonce,
  String deviceHMAC,
  String credentialHMAC
) {

  HTTPClient http;

  String url = String(SERVER) + "/api/access";

  Serial.println();
  Serial.println("SENDING ACCESS REQUEST");
  Serial.println(url);

  oledMessage(
    "VERIFYING",
    cardID,
    "PLEASE WAIT..."
  );

  http.begin(url);

  http.addHeader(
    "Content-Type",
    "application/json"
  );

  // ----------------------------------------------------------
  // Build the plaintext body, then AES-encrypt it before
  // it ever touches the network.
  // ----------------------------------------------------------

  DynamicJsonDocument doc(2048);

  doc["credential_id"] = cardID;
  doc["device_id"] = DEVICE_ID;
  doc["nonce"] = nonce;
  doc["device_hmac"] = deviceHMAC;
  doc["credential_hmac"] = credentialHMAC;

  String plaintextBody;

  serializeJson(doc, plaintextBody);

  String ivHex, dataHex;

  if (!aesEncrypt(plaintextBody, ivHex, dataHex)) {

    Serial.println("ENCRYPTION FAILED");

    oledMessage(
      "LOCAL ERROR",
      "ENCRYPT FAIL"
    );

    http.end();

    lockDoor();

    return false;
  }

  DynamicJsonDocument envelopeOut(2048);

  envelopeOut["iv"] = ivHex;
  envelopeOut["data"] = dataHex;

  String requestBody;

  serializeJson(envelopeOut, requestBody);

  int httpCode =
      http.POST(requestBody);

  Serial.print("HTTP STATUS: ");
  Serial.println(httpCode);

  String response = http.getString();

  Serial.println("SERVER RESPONSE (ENCRYPTED):");
  Serial.println(response);

  if (httpCode <= 0) {

    Serial.print("HTTP ERROR: ");
    Serial.println(http.errorToString(httpCode));

    oledMessage(
      "SERVER ERROR",
      "CONNECTION",
      "FAILED"
    );

    http.end();

    lockDoor();

    return false;
  }

  // ----------------------------------------------------------
  // Decrypt the response envelope
  // ----------------------------------------------------------

  DynamicJsonDocument responseEnvelope(2048);

  DeserializationError envError =
      deserializeJson(responseEnvelope, response);

  if (envError || !responseEnvelope["iv"] || !responseEnvelope["data"]) {

    Serial.println("RESPONSE ENVELOPE ERROR");

    oledMessage(
      "SERVER ERROR",
      "BAD ENVELOPE"
    );

    http.end();

    lockDoor();

    return false;
  }

  String plaintextResponse;

  if (!aesDecrypt(
        responseEnvelope["iv"].as<String>(),
        responseEnvelope["data"].as<String>(),
        plaintextResponse
      )) {

    Serial.println("RESPONSE DECRYPTION FAILED");

    oledMessage(
      "SERVER ERROR",
      "DECRYPT FAIL"
    );

    http.end();

    lockDoor();

    return false;
  }

  Serial.println("DECRYPTED RESPONSE:");
  Serial.println(plaintextResponse);

  DynamicJsonDocument responseDoc(4096);

  DeserializationError error =
      deserializeJson(
        responseDoc,
        plaintextResponse
      );

  if (error) {

    Serial.println("RESPONSE JSON ERROR");

    oledMessage(
      "SERVER ERROR",
      "BAD RESPONSE"
    );

    http.end();

    lockDoor();

    return false;
  }

  String decision =
      responseDoc["decision"] | "BLOCK";

  String reason =
      responseDoc["reason"] | "Unknown";

  int riskScore =
      responseDoc["risk_score"] | 0;

  String riskLevel =
      responseDoc["risk_level"] | "UNKNOWN";

  Serial.print("DECISION: ");
  Serial.println(decision);

  Serial.print("RISK: ");
  Serial.println(riskScore);

  Serial.print("LEVEL: ");
  Serial.println(riskLevel);

  Serial.print("REASON: ");
  Serial.println(reason);

  // ========================================================
  // ACCESS ALLOWED
  // ========================================================

  if (decision == "ALLOW") {

    Serial.println();
    Serial.println("ACCESS GRANTED");

    oledLarge("ACCESS");

    delay(800);

    oledMessage(
      "ACCESS GRANTED",
      cardID,
      "RISK: " + String(riskScore)
    );

    beep();

    unlockDoor();

    delay(5000);

    lockDoor();

    oledMessage(
      "GHOST KEY",
      "DOOR LOCKED"
    );
  }

  // ========================================================
  // ACCESS BLOCKED
  // ========================================================

  else {

    Serial.println();
    Serial.println("ACCESS DENIED");

    oledLarge("DENIED");

    delay(1000);

    oledMessage(
      "ACCESS DENIED",
      cardID,
      "RISK: " + String(riskScore)
    );

    deniedBeep();

    lockDoor();

    delay(2500);

    oledMessage(
      "GHOST KEY",
      "SYSTEM READY"
    );
  }

  http.end();

  return decision == "ALLOW";
}


// ============================================================
// NORMAL ACCESS
// ============================================================

void normalAccess(String cardID) {

  Serial.println();
  Serial.println("================================");
  Serial.println("CARD DETECTED");
  Serial.println(cardID);
  Serial.println("================================");

  oledMessage(
    "CARD DETECTED",
    cardID,
    "READING..."
  );

  String cardSecret =
      getCardSecret(cardID);

  if (cardSecret == "") {

    Serial.println("UNKNOWN CARD");

    oledMessage(
      "UNKNOWN CARD",
      cardID
    );

    deniedBeep();

    lockDoor();

    return;
  }

  String nonce;

  if (!getChallenge(nonce)) {

    Serial.println("NO CHALLENGE");

    oledMessage(
      "AUTH ERROR",
      "NO CHALLENGE"
    );

    lockDoor();

    return;
  }

  // ========================================================
  // CREATE HMACs
  // ========================================================

  String deviceMessage =
      nonce + "|" + DEVICE_ID;

  String credentialMessage =
      nonce + "|" + cardID;

  String deviceHMAC =
      hmacSHA256(
        DEVICE_SECRET,
        deviceMessage
      );

  String credentialHMAC =
      hmacSHA256(
        cardSecret,
        credentialMessage
      );

  // ========================================================
  // SEND TO SERVER (encrypted)
  // ========================================================

  sendAccess(
    cardID,
    nonce,
    deviceHMAC,
    credentialHMAC
  );
}


// ============================================================
// SIMULATED PN532
// ============================================================

String getSimulatedCard(char command) {

  if (command == '1') {
    return "CARD_001";
  }

  if (command == '2') {
    return "CARD_002";
  }

  if (command == '9') {
    return "CARD_999";
  }

  return "";
}


// ============================================================
// WIFI
// ============================================================

void connectWiFi() {

  Serial.println();
  Serial.println("CONNECTING TO WIFI");

  oledMessage(
    "GHOST KEY",
    "CONNECTING",
    "TO WIFI..."
  );

  WiFi.begin(
    WIFI_SSID,
    WIFI_PASSWORD
  );

  int attempts = 0;

  while (
    WiFi.status() != WL_CONNECTED &&
    attempts < 30
  ) {

    delay(500);

    Serial.print(".");

    attempts++;
  }

  Serial.println();

  if (WiFi.status() == WL_CONNECTED) {

    Serial.println("WIFI CONNECTED");

    Serial.print("ESP32 IP: ");
    Serial.println(WiFi.localIP());

    oledMessage(
      "WIFI CONNECTED",
      WiFi.localIP().toString(),
      "NODE 1 READY"
    );

    delay(1500);
  }

  else {

    Serial.println("WIFI FAILED");

    oledMessage(
      "WIFI FAILED",
      "CHECK NETWORK"
    );

    lockDoor();
  }
}


// ============================================================
// SETUP
// ============================================================

void setup() {

  Serial.begin(115200);

  delay(1000);

  // ----------------------------------------------------------
  // Pins
  // ----------------------------------------------------------

  pinMode(
    BUZZER_PIN,
    OUTPUT
  );

  digitalWrite(
    BUZZER_PIN,
    LOW
  );

  // ----------------------------------------------------------
  // Servo
  // ----------------------------------------------------------

  lockServo.attach(
    SERVO_PIN
  );

  lockDoor();

  // ----------------------------------------------------------
  // OLED
  // ----------------------------------------------------------

  Wire.begin(
    OLED_SDA,
    OLED_SCL
  );

  if (!display.begin(
        SSD1306_SWITCHCAPVCC,
        0x3C
      )) {

    Serial.println(
      "OLED NOT FOUND"
    );

  } else {

    Serial.println(
      "OLED INITIALIZED"
    );

    oledLarge("GHOST");

    delay(1000);

    oledMessage(
      "GHOST KEY",
      "NODE 1",
      "READER_001"
    );

    delay(1500);
  }

  // ----------------------------------------------------------
  // WiFi
  // ----------------------------------------------------------

  connectWiFi();

  // ----------------------------------------------------------
  // Serial menu
  // ----------------------------------------------------------

  Serial.println();
  Serial.println("=================================");
  Serial.println("       GHOST KEY NODE 1");
  Serial.println("=================================");
  Serial.println("READER_001");
  Serial.println("CHENNAI LAB A");
  Serial.println("AES-128-CBC ENCRYPTION: ON");
  Serial.println();
  Serial.println("SIMULATED PN532 COMMANDS:");
  Serial.println("1 = CARD_001");
  Serial.println("2 = CARD_002");
  Serial.println("9 = CARD_999");
  Serial.println("=================================");

  oledMessage(
    "GHOST KEY",
    "NODE 1 READY",
    "SCAN CARD"
  );
}


// ============================================================
// LOOP
// ============================================================

void loop() {

  // ----------------------------------------------------------
  // WiFi monitoring
  // ----------------------------------------------------------

  if (
    WiFi.status() != WL_CONNECTED
  ) {

    Serial.println(
      "WIFI DISCONNECTED"
    );

    oledMessage(
      "WIFI LOST",
      "SYSTEM LOCKED"
    );

    lockDoor();

    connectWiFi();

    return;
  }

  // ----------------------------------------------------------
  // Serial Monitor simulated PN532
  // ----------------------------------------------------------

  if (Serial.available()) {

    char command =
        Serial.read();

    // CARD_001
    if (command == '1') {

      normalAccess(
        "CARD_001"
      );
    }

    // CARD_002
    else if (command == '2') {

      normalAccess(
        "CARD_002"
      );
    }

    // CARD_999
    else if (command == '9') {

      normalAccess(
        "CARD_999"
      );
    }
  }

  delay(20);
}
