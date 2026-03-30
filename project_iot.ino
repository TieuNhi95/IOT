#include <WiFi.h>
#include <HTTPClient.h>
#include "mbedtls/md.h"
#include "time.h"
#include <ArduinoJson.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <DHT.h>

const char* ntpServer = "pool.ntp.org";
const long gmtOffset_sec = 7 * 3600;  // GMT+7 (Hà Nội)
const int daylightOffset_sec = 0;

const char* ssid = "P1618";
const char* password = "vietanh123";

String client_id = "urrenqp399tccxaf74fn";
String secret    = "9083786ad5f34eb4984ee4a3bcc5e242";

String access_token = "";
const char* deviceId = "eb07ac76f06a6a95b0etk4";

#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64

#define DHTPIN 15
#define DHTTYPE DHT11

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, -1);
DHT dht(DHTPIN, DHTTYPE);


float temperature;
float humidity;

bool fanState = false;
bool mistState = false;

unsigned long lastSensorRead = 0;
unsigned long lastVentilation = 0;
unsigned long mistStopTime = 0;

const int sensorInterval = 5000;
const int ventilationInterval = 900000;
const int ventilationDuration = 60000;
const int fanAfterMist = 120000;

// ===== SHA256 =====
String sha256(String data) {
  byte shaResult[32];
  mbedtls_md_context_t ctx;

  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
  mbedtls_md_starts(&ctx);
  mbedtls_md_update(&ctx, (const unsigned char*)data.c_str(), data.length());
  mbedtls_md_finish(&ctx, shaResult);
  mbedtls_md_free(&ctx);

  char output[65];
  for (int i = 0; i < 32; i++) sprintf(output + i * 2, "%02x", shaResult[i]);

  return String(output);
}

String hmac_sha256(String message, String key) {
  unsigned char output[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
  mbedtls_md_hmac_starts(&ctx, (const unsigned char*)key.c_str(), key.length());
  mbedtls_md_hmac_update(&ctx, (const unsigned char*)message.c_str(), message.length());
  mbedtls_md_hmac_finish(&ctx, output);
  mbedtls_md_free(&ctx);

  String hexStr = "";
  for(int i=0;i<32;i++){
    if(output[i]<16) hexStr += "0";
    hexStr += String(output[i], HEX);
  }
  hexStr.toUpperCase();
  return hexStr;
}

// ===== BUILD SIGN =====
String buildSign(int64_t timestamp) {

  String method = "GET";

  // body rỗng
  String bodyHash = sha256("");

  String url = "/v1.0/token?grant_type=1";

  String stringToSign =
      method + "\n" +
      bodyHash + "\n" +
      "\n" +
      url;

  Serial.println("stringToSign:");
  Serial.println(stringToSign);

  String signStr = client_id + String(timestamp) + stringToSign;

  return hmac_sha256(signStr, secret);
}

void initTime() {
   // Cấu hình NTP
  configTime(gmtOffset_sec, daylightOffset_sec, ntpServer);

  // Chờ sync thời gian (kiểm tra nếu timestamp < 2021 thì chưa sync)
  Serial.print("Waiting for NTP time");
  time_t now = time(nullptr);
  while (now < 1609459200) { // 01/01/2021
    delay(500);
    Serial.print(".");
    now = time(nullptr);
  }
}

void initWifi() {
  Serial.println("\nWiFi start");
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("\nWiFi connected");
}

int64_t getTimestamp(){
  return (int64_t)time(nullptr) * 1000;
}

String buildStringToSign(String method, String body) {
  // SHA256 hash body
  unsigned char output[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
  mbedtls_md_starts(&ctx);
  mbedtls_md_update(&ctx, (const unsigned char*)body.c_str(), body.length());
  mbedtls_md_finish(&ctx, output);
  mbedtls_md_free(&ctx);

  String bodyHash = "";
  for(int i=0;i<32;i++){
    if(output[i]<16) bodyHash += "0";
    bodyHash += String(output[i], HEX);
  }
  bodyHash.toLowerCase();  // Tuya dùng lowercase cho hash body

  String url = "/v1.0/devices/" + String(deviceId) + "/commands";

  String stringToSign = method + "\n" + bodyHash + "\n\n" + url;
  return stringToSign;
}

// ==== Tạo sign final ====
String calcSignToken(String clientId, String accessToken, String secret, int64_t timestamp, String body) {
  String str = clientId + accessToken + String(timestamp) + buildStringToSign("POST", body);
  return hmac_sha256(str, secret);
}

// ===== GET TOKEN =====
void getToken() {

  HTTPClient http;

  int64_t timestamp = getTimestamp();
  // Serial.println("timestamp:");
  // Serial.print(timestamp);
  String sign = buildSign(timestamp);

  String url = "https://openapi.tuyaus.com/v1.0/token?grant_type=1";

  http.begin(url);
  http.addHeader("client_id", client_id);
  http.addHeader("sign", sign);
  http.addHeader("t", String(timestamp));
  http.addHeader("sign_method", "HMAC-SHA256");

  int httpCode = http.GET();

  // Serial.println("HTTP Code: " + String(httpCode));

  if (httpCode > 0) {
    String payload = http.getString();
    Serial.println(payload);

    DynamicJsonDocument doc(512);
    DeserializationError error = deserializeJson(doc, payload);

    if (error) {
     Serial.print("deserializeJson() failed: ");
     Serial.println(error.c_str());
     http.end();
     return;
    }
    
    access_token = doc["result"]["access_token"].as<String>();

    Serial.println("ACCESS TOKEN:");
    Serial.print(access_token);
  }

  http.end();
}

void sendCommand(bool sw1, bool sw2) {
  fanState = sw1;
  mistState = sw2;
  String body = "{\"commands\":[{\"code\":\"switch_1\",\"value\":" + String(sw1?"true":"false") + "},{\"code\":\"switch_2\",\"value\":" + String(sw2?"true":"false") + "}]}";

  int64_t timestamp = getTimestamp();
  String sign = calcSignToken(client_id, access_token, secret, timestamp, body);

  HTTPClient http;
  http.begin("https://openapi.tuyaus.com/v1.0/devices/" + String(deviceId) + "/commands");
  http.addHeader("client_id", client_id);
  http.addHeader("access_token", access_token);
  http.addHeader("sign", sign);
  http.addHeader("t", String(timestamp));
  http.addHeader("sign_method", "HMAC-SHA256");
  http.addHeader("Content-Type", "application/json");

  int httpResponseCode = http.POST(body);
  Serial.print("HTTP Response code: ");
  Serial.println(httpResponseCode);

  if(httpResponseCode > 0){
    String resp = http.getString();
    Serial.println(resp);
    DynamicJsonDocument doc(512);
    DeserializationError error = deserializeJson(doc, resp);

    if (error) {
      Serial.print("deserializeJson() failed: ");
      Serial.println(error.c_str());
      http.end();
      return;
    }

    // Lấy code
    int code = doc["code"];
    bool success = doc["success"];
      if(!success && code == 1010){
        http.end();
        getToken();
        sendCommand(sw1,sw2);
      }else{
        Serial.println("Success");
      }
  } else {
    Serial.println("Error sending command");
  }
  http.end();
}

void setup() {
  Serial.begin(115200);

  dht.begin();

  Wire.begin(21,22);
  display.begin(SSD1306_SWITCHCAPVCC, 0x3C);
 
  initWifi();

  initTime();

  getToken();

}

void loop() {


  unsigned long now = millis();

  if(now - lastSensorRead > sensorInterval){

    lastSensorRead = now;

    temperature = dht.readTemperature();
    humidity = dht.readHumidity();

    Serial.print("Temp: ");
    Serial.print(temperature);
    Serial.print("  Hum: ");
    Serial.println(humidity);

    // ===== PHUN SƯƠNG =====

    if(humidity <= 75 && !mistState){
      sendCommand(true, true);
    }

    if(humidity >= 85 && mistState){
      sendCommand(fanState,false);
      mistStopTime = now;
    }

    // ===== QUẠT DO NHIỆT =====

    if(temperature >= 28){
      sendCommand(true,mistState);
    }

    if(temperature <= 26 && !mistState){
      sendCommand(false,mistState);
    }

  }

  // ===== QUẠT SAU PHUN =====

  if(!mistState && mistStopTime != 0){
    if(now - mistStopTime < fanAfterMist){
      sendCommand(true,mistState);
    } else {
      mistStopTime = 0;
    }
  }

  // ===== THÔNG GIÓ ĐỊNH KỲ =====

  if(now - lastVentilation > ventilationInterval){
    lastVentilation = now;
    sendCommand(true,mistState);
  }

  if(now - lastVentilation > ventilationDuration && !mistState){
    if(temperature < 28){
      sendCommand(false,mistState);
    }
  }

  // ===== OLED =====

  display.clearDisplay();
  display.setTextSize(2);
  display.setTextColor(WHITE);

  display.setCursor(0,0);
  display.print("T ");
  display.print(temperature,1);
  display.print("C");

  display.setCursor(0,22);
  display.print("H ");
  display.print(humidity,0);
  display.print("%");

  display.setTextSize(1);

  display.setCursor(0,48);
  display.print("FAN: ");
  display.print(fanState ? "ON" : "OFF");

  display.setCursor(70,48);
  display.print("MIST: ");
  display.print(mistState ? "ON" : "OFF");

  display.display();

}