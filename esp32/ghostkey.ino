#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <ESP32Servo.h>
#include "mbedtls/md.h"

// ======================================================
// WIFI SETTINGS
// ======================================================

const char* WIFI_SSID = "NARZO";
const char* WIFI_PASSWORD = "aahilhere";

// IMPORTANT:
// Replace this with your computer's LAN IPv4 address.
// Example:
// http://192.168.1.105:5000

const char* SERVER = "http://10.188.102.24:5000";

// ======================================================
// DEVICE SETTINGS
// ======================================================

const char* DEVICE_ID = "READER_001";
const char* DEVICE_SECRET = "reader_secret_001";

// ======================================================
// PINS
// ======================================================

#define OLED_SDA 21
#define OLED_SCL 22

#define SERVO_PIN 18
#define BUZZER_PIN 25
#define LED_PIN 26

// ======================================================
// OLED
// ======================================================

#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64

Adafruit_SSD1306 display(
  SCREEN_WIDTH,
  SCREEN_HEIGHT,
  &Wire,
  -1
);

// ======================================================
// SERVO
// ======================================================

Servo doorServo;

#define LOCK_ANGLE 0
#define UNLOCK_ANGLE 90

// ======================================================
// CARD SECRETS
// ======================================================

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

// ======================================================
// HMAC-SHA256
// ======================================================

String calculateHMAC(String secret, String message) {

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

// ======================================================
// OLED DISPLAY
// ======================================================

void showScreen(String line1, String line2, String line3 = "") {

  display.clearDisplay();

  display.setTextColor(SSD1306_WHITE);

  display.setTextSize(2);

  display.setCursor(0, 0);
  display.println(line1);

  display.setCursor(0, 24);
  display.println(line2);

  if (line3 != "") {

    display.setTextSize(1);

    display.setCursor(0, 50);
    display.println(line3);
  }

  display.display();
}

// ======================================================
// BUZZER
// ======================================================

void beep() {

  digitalWrite(BUZZER_PIN, HIGH);
  delay(150);
  digitalWrite(BUZZER_PIN, LOW);
}

// ======================================================
// DENIED BUZZER
// ======================================================

void deniedBeep() {

  for (int i = 0; i < 3; i++) {

    digitalWrite(BUZZER_PIN, HIGH);
    delay(120);

    digitalWrite(BUZZER_PIN, LOW);
    delay(120);
  }
}

// ======================================================
// SERVO
// ======================================================

void lockDoor() {

  doorServo.write(LOCK_ANGLE);

  Serial.println("DOOR: LOCKED");
}

void unlockDoor() {

  doorServo.write(UNLOCK_ANGLE);

  Serial.println("DOOR: UNLOCKED");
}

// ======================================================
// SIMULATED PN532
// ======================================================

String simulatePN532() {

  if (Serial.available()) {

    String input = Serial.readStringUntil('\n');

    input.trim();

    if (input == "1") {
      return "CARD_001";
    }

    if (input == "2") {
      return "CARD_002";
    }

    if (input == "9") {
      return "CARD_999";
    }
  }

  return "";
}

// ======================================================
// GET CHALLENGE FROM SERVER
// ======================================================

String getChallenge() {

  HTTPClient http;

  String url = String(SERVER) + "/api/challenge";

  Serial.println();
  Serial.println("================================");
  Serial.println("REQUESTING CHALLENGE");
  Serial.println("================================");

  Serial.print("URL: ");
  Serial.println(url);

  http.begin(url);

  http.addHeader(
    "Content-Type",
    "application/json"
  );

  String payload =
    "{\"device_id\":\"" +
    String(DEVICE_ID) +
    "\"}";

  Serial.print("Payload: ");
  Serial.println(payload);

  int httpResponseCode = http.POST(payload);

  // ==================================================
  // TEMPORARY DEBUGGING
  // ==================================================

  Serial.print("HTTP status: ");
  Serial.println(httpResponseCode);

  if (httpResponseCode > 0) {

    String response = http.getString();

    Serial.println("--------------------------------");
    Serial.println("SERVER RESPONSE:");
    Serial.println(response);
    Serial.println("--------------------------------");

    DynamicJsonDocument doc(2048);

    DeserializationError error =
      deserializeJson(doc, response);

    if (error) {

      Serial.print("JSON parsing error: ");
      Serial.println(error.c_str());

      http.end();

      return "";
    }

    String nonce =
      doc["nonce"].as<String>();

    Serial.print("NONCE RECEIVED: ");
    Serial.println(nonce);

    http.end();

    return nonce;
  }

  // ==================================================
  // HTTP ERROR
  // ==================================================

  Serial.print("Challenge HTTP error: ");
  Serial.println(httpResponseCode);

  Serial.println("Possible causes:");
  Serial.println("1. Server unreachable");
  Serial.println("2. Wrong SERVER IP");
  Serial.println("3. Wrong port");
  Serial.println("4. WiFi problem");
  Serial.println("5. Firewall blocking port 5000");

  http.end();

  return "";
}

// ======================================================
// SEND AUTHENTICATION REQUEST
// ======================================================

bool authenticateCard(String cardID) {

  // Always start locked
  lockDoor();

  Serial.println();
  Serial.println("================================");
  Serial.println("AUTHENTICATION START");
  Serial.println("================================");

  Serial.print("CARD: ");
  Serial.println(cardID);

  // ==================================================
  // GET CHALLENGE
  // ==================================================

  String nonce = getChallenge();

  if (nonce == "") {

    Serial.println("FAILED TO GET CHALLENGE");

    showScreen(
      "SERVER",
      "ERROR",
      "Door remains locked"
    );

    digitalWrite(LED_PIN, LOW);

    return false;
  }

  // ==================================================
  // CARD SECRET
  // ==================================================

  String cardSecret =
    getCardSecret(cardID);

  if (cardSecret == "") {

    Serial.println("UNKNOWN CARD SECRET");

    showScreen(
      "CARD",
      "UNKNOWN"
    );

    deniedBeep();

    digitalWrite(LED_PIN, LOW);

    return false;
  }

  // ==================================================
  // DEVICE HMAC
  // ==================================================

  String deviceMessage =
    nonce + "|" + String(DEVICE_ID);

  String deviceHMAC =
    calculateHMAC(
      DEVICE_SECRET,
      deviceMessage
    );

  Serial.println();
  Serial.println("DEVICE HMAC:");
  Serial.println(deviceHMAC);

  // ==================================================
  // CARD HMAC
  // ==================================================

  String cardMessage =
    nonce + "|" + cardID;

  String cardHMAC =
    calculateHMAC(
      cardSecret,
      cardMessage
    );

  Serial.println();
  Serial.println("CARD HMAC:");
  Serial.println(cardHMAC);

  // ==================================================
  // SEND ACCESS REQUEST
  // ==================================================

  HTTPClient http;

  String url =
    String(SERVER) + "/api/access";

  Serial.println();
  Serial.println("================================");
  Serial.println("SENDING ACCESS REQUEST");
  Serial.println("================================");

  Serial.print("URL: ");
  Serial.println(url);

  http.begin(url);

  http.addHeader(
    "Content-Type",
    "application/json"
  );

  String payload =
    "{"
    "\"device_id\":\"" + String(DEVICE_ID) + "\","
    "\"credential_id\":\"" + cardID + "\","
    "\"nonce\":\"" + nonce + "\","
    "\"device_hmac\":\"" + deviceHMAC + "\","
    "\"credential_hmac\":\"" + cardHMAC + "\""
    "}";

  Serial.println("ACCESS PAYLOAD:");
  Serial.println(payload);

  int httpResponseCode =
    http.POST(payload);

  // ==================================================
  // DEBUG ACCESS RESPONSE
  // ==================================================

  Serial.print("ACCESS HTTP STATUS: ");
  Serial.println(httpResponseCode);

  if (httpResponseCode > 0) {

    String response =
      http.getString();

    Serial.println("--------------------------------");
    Serial.println("ACCESS SERVER RESPONSE:");
    Serial.println(response);
    Serial.println("--------------------------------");

    DynamicJsonDocument doc(4096);

    DeserializationError error =
      deserializeJson(doc, response);

    if (error) {

      Serial.print("ACCESS JSON ERROR: ");
      Serial.println(error.c_str());

      http.end();

      return false;
    }

    String decision =
      doc["decision"].as<String>();

    String riskLevel =
      doc["risk_level"].as<String>();

    int riskScore =
      doc["risk_score"] | 0;

    String reason =
      doc["reason"].as<String>();

    Serial.println();
    Serial.println("========== RESULT ==========");

    Serial.print("DECISION: ");
    Serial.println(decision);

    Serial.print("RISK LEVEL: ");
    Serial.println(riskLevel);

    Serial.print("RISK SCORE: ");
    Serial.println(riskScore);

    Serial.print("REASON: ");
    Serial.println(reason);

    Serial.println("============================");

    // ==================================================
    // ACCESS GRANTED
    // ==================================================

    if (decision == "ALLOW") {

      Serial.println();
      Serial.println("ACCESS GRANTED!");

      showScreen(
        "ACCESS",
        "GRANTED",
        "Door unlocked"
      );

      digitalWrite(
        LED_PIN,
        HIGH
      );

      beep();

      unlockDoor();

      delay(5000);

      lockDoor();

      digitalWrite(
        LED_PIN,
        LOW
      );

      showScreen(
        "DOOR",
        "LOCKED"
      );

      http.end();

      return true;
    }

    // ==================================================
    // ACCESS DENIED
    // ==================================================

    else {

      Serial.println();
      Serial.println("ACCESS DENIED!");

      showScreen(
        "ACCESS",
        "DENIED",
        riskLevel
      );

      digitalWrite(
        LED_PIN,
        LOW
      );

      deniedBeep();

      lockDoor();

      delay(2000);

      showScreen(
        "DOOR",
        "LOCKED"
      );

      http.end();

      return false;
    }
  }

  // ==================================================
  // ACCESS HTTP ERROR
  // ==================================================

  Serial.print(
    "Access HTTP error: "
  );

  Serial.println(
    httpResponseCode
  );

  lockDoor();

  http.end();

  return false;
}

// ======================================================
// WIFI CONNECTION
// ======================================================

void connectWiFi() {

  Serial.println();
  Serial.println("Connecting to WiFi...");

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

    Serial.println("WiFi connected!");

    Serial.print("ESP32 IP: ");
    Serial.println(
      WiFi.localIP()
    );

    Serial.print("Server: ");
    Serial.println(SERVER);

    showScreen(
      "GHOST",
      "KEY",
      "WiFi Connected"
    );

  } else {

    Serial.println(
      "WiFi connection FAILED!"
    );

    showScreen(
      "WIFI",
      "ERROR"
    );
  }
}

// ======================================================
// SETUP
// ======================================================

void setup() {

  Serial.begin(115200);

  delay(1000);

  Serial.println();
  Serial.println();
  Serial.println("================================");
  Serial.println("        GHOST KEY");
  Serial.println("================================");

  // ==================================================
  // GPIO
  // ==================================================

  pinMode(
    BUZZER_PIN,
    OUTPUT
  );

  pinMode(
    LED_PIN,
    OUTPUT
  );

  digitalWrite(
    BUZZER_PIN,
    LOW
  );

  digitalWrite(
    LED_PIN,
    LOW
  );

  // ==================================================
  // OLED
  // ==================================================

  Wire.begin(
    OLED_SDA,
    OLED_SCL
  );

  if (
    !display.begin(
      SSD1306_SWITCHCAPVCC,
      0x3C
    )
  ) {

    Serial.println(
      "OLED initialization failed!"
    );

  } else {

    Serial.println(
      "OLED initialized!"
    );

    showScreen(
      "GHOST",
      "KEY",
      "Starting..."
    );
  }

  // ==================================================
  // SERVO
  // ==================================================

  doorServo.attach(
    SERVO_PIN
  );

  lockDoor();

  // ==================================================
  // WIFI
  // ==================================================

  connectWiFi();

  // ==================================================
  // SERIAL MENU
  // ==================================================

  Serial.println();
  Serial.println("================================");
  Serial.println("       SIMULATED PN532");
  Serial.println("================================");
  Serial.println();
  Serial.println("1 = CARD_001");
  Serial.println("2 = CARD_002");
  Serial.println("9 = CARD_999");
  Serial.println();
  Serial.println("================================");
  Serial.println();
}

// ======================================================
// LOOP
// ======================================================

void loop() {

  // ==================================================
  // CHECK WIFI
  // ==================================================

  if (
    WiFi.status() != WL_CONNECTED
  ) {

    Serial.println(
      "WiFi disconnected!"
    );

    lockDoor();

    digitalWrite(
      LED_PIN,
      LOW
    );

    connectWiFi();
  }

  // ==================================================
  // SIMULATED CARD
  // ==================================================

  String cardID =
    simulatePN532();

  if (cardID != "") {

    Serial.println();
    Serial.println(
      "SIMULATED PN532:"
    );

    Serial.println(cardID);

    showScreen(
      "CARD",
      cardID
    );

    delay(500);

    authenticateCard(
      cardID
    );

    Serial.println();
    Serial.println("Ready for next card...");
    Serial.println();
  }

  delay(50);
}
