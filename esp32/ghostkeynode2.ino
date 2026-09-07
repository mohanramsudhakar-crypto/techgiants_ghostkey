#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <ESP32Servo.h>
#include "mbedtls/md.h"
#include "mbedtls/aes.h"
#include "esp_system.h"


// ============================================================
// WIFI / SERVER
// ============================================================

const char* WIFI_SSID = "NARZO";
const char* WIFI_PASSWORD = "aahilhere";

const char* SERVER = "http://10.188.102.195:5000";


// ============================================================
// NODE 2 IDENTITY
// ============================================================

const char* DEVICE_ID = "READER_002";
const char* DEVICE_SECRET = "reader_secret_002";


// ============================================================
// AES-128-CBC SHARED KEY
// ============================================================
// Must match AES_KEY_HEX in security.py ("3fae1baf5e3d4c2c9be2f1a6c88f3ac0")
// and AES_KEY_HEX in app.js.
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


// ============================================================
// SERVO
// ============================================================

Servo lockServo;

// Change these if your physical lock mechanism needs
// different positions.

#define LOCKED_ANGLE 0
#define UNLOCKED_ANGLE 90


// ============================================================
// SERVO FUNCTIONS
// ============================================================

void lockDoor()
{
    Serial.println("SERVO: LOCKING");

    lockServo.write(LOCKED_ANGLE);

    delay(500);

    Serial.println("SERVO: LOCKED");
}


void unlockDoor()
{
    Serial.println("SERVO: UNLOCKING");

    lockServo.write(UNLOCKED_ANGLE);

    delay(500);

    Serial.println("SERVO: UNLOCKED");
}


// ============================================================
// BUZZER
// ============================================================

void beep()
{
    digitalWrite(BUZZER_PIN, HIGH);
    delay(150);
    digitalWrite(BUZZER_PIN, LOW);
}


void deniedBeep()
{
    for (int i = 0; i < 3; i++)
    {
        digitalWrite(BUZZER_PIN, HIGH);
        delay(100);

        digitalWrite(BUZZER_PIN, LOW);
        delay(100);
    }
}


// ============================================================
// HMAC-SHA256
// ============================================================

String hmacSHA256(String secret, String message)
{
    byte hmacResult[32];

    const mbedtls_md_info_t* mdInfo =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_context_t ctx;

    mbedtls_md_init(&ctx);

    mbedtls_md_setup(
        &ctx,
        mdInfo,
        1
    );

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

    for (int i = 0; i < 32; i++)
    {
        if (hmacResult[i] < 16)
        {
            output += "0";
        }

        output += String(
            hmacResult[i],
            HEX
        );
    }

    return output;
}


// ============================================================
// AES-128-CBC HELPERS
// ============================================================

String bytesToHex(const uint8_t* data, size_t len)
{
    String out = "";

    for (size_t i = 0; i < len; i++)
    {
        if (data[i] < 16)
        {
            out += "0";
        }

        out += String(data[i], HEX);
    }

    return out;
}


size_t hexToBytes(const String &hex, uint8_t* out, size_t maxLen)
{
    size_t len = hex.length() / 2;

    if (len > maxLen)
    {
        len = maxLen;
    }

    for (size_t i = 0; i < len; i++)
    {
        String byteStr = hex.substring(i * 2, i * 2 + 2);

        out[i] = (uint8_t) strtol(byteStr.c_str(), NULL, 16);
    }

    return len;
}


bool aesEncrypt(String plaintext, String &ivHexOut, String &dataHexOut)
{
    size_t inLen = plaintext.length();

    size_t padLen = 16 - (inLen % 16);
    size_t totalLen = inLen + padLen;

    uint8_t* buf = (uint8_t*) malloc(totalLen);

    if (!buf)
    {
        return false;
    }

    memcpy(buf, plaintext.c_str(), inLen);

    for (size_t i = inLen; i < totalLen; i++)
    {
        buf[i] = (uint8_t) padLen;
    }

    uint8_t iv[16];
    esp_fill_random(iv, 16);

    uint8_t ivWorking[16];
    memcpy(ivWorking, iv, 16);

    uint8_t* outBuf = (uint8_t*) malloc(totalLen);

    if (!outBuf)
    {
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


bool aesDecrypt(String ivHex, String dataHex, String &plaintextOut)
{
    uint8_t iv[16];
    hexToBytes(ivHex, iv, 16);

    size_t dataLen = dataHex.length() / 2;

    if (dataLen == 0 || dataLen % 16 != 0)
    {
        return false;
    }

    uint8_t* cipherBuf = (uint8_t*) malloc(dataLen);
    uint8_t* outBuf = (uint8_t*) malloc(dataLen);

    if (!cipherBuf || !outBuf)
    {
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

    uint8_t padLen = outBuf[dataLen - 1];
    size_t plainLen = dataLen;

    if (padLen > 0 && padLen <= 16 && padLen <= dataLen)
    {
        plainLen = dataLen - padLen;
    }

    char* strBuf = (char*) malloc(plainLen + 1);

    if (!strBuf)
    {
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
// CARD SECRET
// ============================================================

String getCardSecret(String cardID)
{
    if (cardID == "CARD_001")
    {
        return "card_secret_001";
    }

    if (cardID == "CARD_002")
    {
        return "card_secret_002";
    }

    if (cardID == "CARD_999")
    {
        return "unknown_secret";
    }

    return "";
}


// ============================================================
// GET CHALLENGE
// ============================================================

bool getChallenge(String &nonce)
{
    HTTPClient http;

    String url =
        String(SERVER)
        + "/api/challenge";


    Serial.println();
    Serial.println("REQUESTING CHALLENGE");

    Serial.println(url);


    http.begin(url);

    int httpCode =
        http.GET();


    Serial.print(
        "HTTP STATUS: "
    );

    Serial.println(httpCode);


    if (httpCode <= 0)
    {
        Serial.print(
            "HTTP ERROR: "
        );

        Serial.println(
            http.errorToString(httpCode)
        );

        http.end();

        return false;
    }


    String response =
        http.getString();


    Serial.println(
        "SERVER RESPONSE (ENCRYPTED):"
    );

    Serial.println(response);


    // --------------------------------------------------------
    // Decrypt the {"iv":..., "data":...} envelope
    // --------------------------------------------------------

    DynamicJsonDocument envelope(1024);

    DeserializationError envError =
        deserializeJson(envelope, response);

    if (envError || !envelope["iv"] || !envelope["data"])
    {
        Serial.println("ENVELOPE PARSE ERROR");

        http.end();

        return false;
    }

    String plaintext;

    if (!aesDecrypt(
            envelope["iv"].as<String>(),
            envelope["data"].as<String>(),
            plaintext
        ))
    {
        Serial.println("DECRYPTION FAILED");

        http.end();

        return false;
    }

    Serial.println("DECRYPTED:");
    Serial.println(plaintext);


    DynamicJsonDocument doc(2048);

    DeserializationError error =
        deserializeJson(
            doc,
            plaintext
        );


    if (error)
    {
        Serial.println(
            "JSON PARSE ERROR"
        );

        http.end();

        return false;
    }


    if (!doc["nonce"])
    {
        Serial.println(
            "NO NONCE RECEIVED"
        );

        http.end();

        return false;
    }


    nonce =
        doc["nonce"].as<String>();


    Serial.print(
        "CHALLENGE NONCE: "
    );

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
)
{
    HTTPClient http;

    String url =
        String(SERVER)
        + "/api/access";


    Serial.println();
    Serial.println(
        "SENDING ACCESS REQUEST"
    );

    Serial.println(url);


    http.begin(url);

    http.addHeader(
        "Content-Type",
        "application/json"
    );


    // ----------------------------------------------------------
    // Build the plaintext body, then AES-encrypt it
    // ----------------------------------------------------------

    DynamicJsonDocument doc(2048);


    doc["credential_id"] =
        cardID;

    doc["device_id"] =
        DEVICE_ID;

    doc["nonce"] =
        nonce;

    doc["device_hmac"] =
        deviceHMAC;

    doc["credential_hmac"] =
        credentialHMAC;


    String plaintextBody;

    serializeJson(
        doc,
        plaintextBody
    );

    String ivHex, dataHex;

    if (!aesEncrypt(plaintextBody, ivHex, dataHex))
    {
        Serial.println("ENCRYPTION FAILED");

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


    Serial.print(
        "HTTP STATUS: "
    );

    Serial.println(httpCode);


    String response =
        http.getString();


    Serial.println(
        "SERVER RESPONSE (ENCRYPTED):"
    );

    Serial.println(response);


    if (httpCode <= 0)
    {
        Serial.print(
            "HTTP ERROR: "
        );

        Serial.println(
            http.errorToString(httpCode)
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

    if (envError || !responseEnvelope["iv"] || !responseEnvelope["data"])
    {
        Serial.println("RESPONSE ENVELOPE ERROR");

        http.end();

        lockDoor();

        return false;
    }

    String plaintextResponse;

    if (!aesDecrypt(
            responseEnvelope["iv"].as<String>(),
            responseEnvelope["data"].as<String>(),
            plaintextResponse
        ))
    {
        Serial.println("RESPONSE DECRYPTION FAILED");

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


    if (error)
    {
        Serial.println(
            "RESPONSE JSON ERROR"
        );

        http.end();

        lockDoor();

        return false;
    }


    String decision =
        responseDoc["decision"]
        | "BLOCK";


    String reason =
        responseDoc["reason"]
        | "Unknown";


    int riskScore =
        responseDoc["risk_score"]
        | 0;


    String riskLevel =
        responseDoc["risk_level"]
        | "UNKNOWN";


    Serial.println();
    Serial.println(
        "================================"
    );

    Serial.print(
        "DECISION: "
    );

    Serial.println(decision);


    Serial.print(
        "RISK: "
    );

    Serial.println(riskScore);


    Serial.print(
        "LEVEL: "
    );

    Serial.println(riskLevel);


    Serial.print(
        "REASON: "
    );

    Serial.println(reason);


    Serial.println(
        "================================"
    );


    // ========================================================
    // ACCESS GRANTED
    // ========================================================

    if (decision == "ALLOW")
    {
        Serial.println();
        Serial.println(
            "ACCESS GRANTED"
        );


        beep();


        // ----------------------------------------------------
        // SERVO UNLOCK
        // ----------------------------------------------------

        unlockDoor();


        // Keep door unlocked for 5 seconds
        delay(5000);


        // ----------------------------------------------------
        // SERVO LOCK
        // ----------------------------------------------------

        lockDoor();
    }


    // ========================================================
    // ACCESS DENIED
    // ========================================================

    else
    {
        Serial.println();
        Serial.println(
            "ACCESS DENIED"
        );


        deniedBeep();


        // ----------------------------------------------------
        // Make absolutely sure the door stays locked
        // ----------------------------------------------------

        lockDoor();


        delay(2500);
    }


    http.end();

    return decision == "ALLOW";
}


// ============================================================
// NORMAL ACCESS
// ============================================================

void normalAccess(String cardID)
{
    Serial.println();
    Serial.println(
        "================================"
    );

    Serial.println(
        "CARD DETECTED"
    );

    Serial.println(cardID);

    Serial.println(
        "================================"
    );


    String cardSecret =
        getCardSecret(cardID);


    // ========================================================
    // UNKNOWN CARD
    // ========================================================

    if (cardSecret == "")
    {
        Serial.println(
            "UNKNOWN CARD"
        );

        deniedBeep();

        lockDoor();

        return;
    }


    // ========================================================
    // REQUEST CHALLENGE
    // ========================================================

    String nonce;


    if (!getChallenge(nonce))
    {
        Serial.println(
            "NO CHALLENGE"
        );

        lockDoor();

        return;
    }


    // ========================================================
    // CREATE HMAC
    // ========================================================

    String deviceMessage =
        nonce
        + "|"
        + DEVICE_ID;


    String credentialMessage =
        nonce
        + "|"
        + cardID;


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
// REPLAY ATTACK DEMO
// ============================================================
// Note: each call to sendAccess() still produces a *different*
// ciphertext (fresh random IV) even though it's the exact same
// plaintext nonce/HMAC being replayed - that's expected and
// correct. The server decrypts both requests, sees the same
// nonce used twice, and blocks the second one. AES encryption
// hides the traffic; it doesn't (and isn't meant to) replace
// the nonce-based replay check.
// ============================================================

void replayAttackDemo()
{
    Serial.println();
    Serial.println(
        "================================"
    );

    Serial.println(
        "REPLAY ATTACK DEMO"
    );

    Serial.println(
        "================================"
    );


    String cardID =
        "CARD_002";


    String cardSecret =
        getCardSecret(cardID);


    // ========================================================
    // GET ONE CHALLENGE
    // ========================================================

    String nonce;


    if (!getChallenge(nonce))
    {
        Serial.println(
            "NO CHALLENGE"
        );

        return;
    }


    // ========================================================
    // CREATE VALID HMAC
    // ========================================================

    String deviceMessage =
        nonce
        + "|"
        + DEVICE_ID;


    String credentialMessage =
        nonce
        + "|"
        + cardID;


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
    // FIRST REQUEST
    // ========================================================

    Serial.println();
    Serial.println(
        "FIRST REQUEST"
    );

    Serial.println(
        "Expected: ALLOW"
    );


    sendAccess(
        cardID,
        nonce,
        deviceHMAC,
        credentialHMAC
    );


    delay(1000);


    // ========================================================
    // SECOND REQUEST
    // SAME NONCE
    // SAME HMAC
    //
    // This should be detected as replay.
    // ========================================================

    Serial.println();
    Serial.println(
        "SECOND REQUEST"
    );

    Serial.println(
        "Expected: BLOCK"
    );

    Serial.println(
        "Replay attack should be detected."
    );


    sendAccess(
        cardID,
        nonce,
        deviceHMAC,
        credentialHMAC
    );
}


// ============================================================
// WIFI CONNECTION
// ============================================================

void connectWiFi()
{
    Serial.println();
    Serial.println(
        "CONNECTING TO WIFI"
    );


    WiFi.begin(
        WIFI_SSID,
        WIFI_PASSWORD
    );


    int attempts = 0;


    while (
        WiFi.status() != WL_CONNECTED
        &&
        attempts < 30
    )
    {
        delay(500);

        Serial.print(".");

        attempts++;
    }


    Serial.println();


    if (WiFi.status() == WL_CONNECTED)
    {
        Serial.println(
            "WIFI CONNECTED"
        );


        Serial.print(
            "ESP32 IP: "
        );

        Serial.println(
            WiFi.localIP()
        );
    }


    else
    {
        Serial.println(
            "WIFI FAILED"
        );

        lockDoor();
    }
}


// ============================================================
// SETUP
// ============================================================

void setup()
{
    Serial.begin(115200);

    delay(1000);


    // ========================================================
    // BUZZER
    // ========================================================

    pinMode(
        BUZZER_PIN,
        OUTPUT
    );

    digitalWrite(
        BUZZER_PIN,
        LOW
    );


    // ========================================================
    // SERVO
    // ========================================================

    Serial.println();
    Serial.println(
        "INITIALIZING SERVO..."
    );


    // Attach servo to GPIO 18
    lockServo.attach(
        SERVO_PIN,
        500,
        2400
    );


    delay(300);


    // IMPORTANT:
    // Start in locked position
    lockServo.write(
        LOCKED_ANGLE
    );


    delay(700);


    Serial.println(
        "SERVO INITIALIZED"
    );

    Serial.print(
        "SERVO PIN: "
    );

    Serial.println(SERVO_PIN);

    Serial.print(
        "LOCK ANGLE: "
    );

    Serial.println(
        LOCKED_ANGLE
    );

    Serial.print(
        "UNLOCK ANGLE: "
    );

    Serial.println(
        UNLOCKED_ANGLE
    );


    Serial.println(
        "SERVO: LOCKED"
    );


    // ========================================================
    // WIFI
    // ========================================================

    connectWiFi();


    // ========================================================
    // STARTUP INFORMATION
    // ========================================================

    Serial.println();
    Serial.println(
        "================================="
    );

    Serial.println(
        "       GHOST KEY NODE 2"
    );

    Serial.println(
        "================================="
    );

    Serial.println(
        "READER_002"
    );

    Serial.println(
        "CHENNAI LAB B"
    );

    Serial.println(
        "AES-128-CBC ENCRYPTION: ON"
    );

    Serial.println();


    Serial.println(
        "SIMULATED PN532 COMMANDS:"
    );

    Serial.println(
        "1 = CARD_001"
    );

    Serial.println(
        "2 = CARD_002"
    );

    Serial.println(
        "9 = CARD_999"
    );

    Serial.println(
        "R = REPLAY ATTACK DEMO"
    );


    Serial.println(
        "================================="
    );

    Serial.println(
        "SYSTEM READY"
    );
}


// ============================================================
// LOOP
// ============================================================

void loop()
{
    // ========================================================
    // WIFI CHECK
    // ========================================================

    if (
        WiFi.status()
        != WL_CONNECTED
    )
    {
        Serial.println(
            "WIFI DISCONNECTED"
        );


        // Fail closed
        lockDoor();


        connectWiFi();


        return;
    }


    // ========================================================
    // SERIAL CARD SIMULATION
    // ========================================================

    if (Serial.available())
    {
        char command =
            Serial.read();


        // ----------------------------------------------------
        // CARD 001
        // ----------------------------------------------------

        if (command == '1')
        {
            normalAccess(
                "CARD_001"
            );
        }


        // ----------------------------------------------------
        // CARD 002
        // ----------------------------------------------------

        else if (command == '2')
        {
            normalAccess(
                "CARD_002"
            );
        }


        // ----------------------------------------------------
        // UNAUTHORIZED CARD
        // ----------------------------------------------------

        else if (command == '9')
        {
            normalAccess(
                "CARD_999"
            );
        }


        // ----------------------------------------------------
        // REPLAY DEMO
        // ----------------------------------------------------

        else if (
            command == 'R'
            ||
            command == 'r'
        )
        {
            replayAttackDemo();
        }
    }


    delay(20);
}
