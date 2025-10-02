#include <Arduino.h>
#include <WiFi.h>
#include <MQTT.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <Update.h>
#include <esp_ota_ops.h>
#include <esp_partition.h>
#include <mbedtls/aes.h>
#include <mbedtls/base64.h>

// !!!PLEASE READ!!! YOU WILL BE GIVEN A NUMBER for smart-dorm-XXX WITH EACH MICROCONTROLLER CHECKOUT
// USE THIS IN `host` after you uncomment it. For independent testing, select a value rand(999,999999)
//const char* host = "smart-dorm-XXX";

// This network will be live at the event. If you wish to not use it for any reason, you may swap.
const char ssid[] = "cyber360sc24";
const char pass[] = "864FsP@rkCh2llF215";

const char* serverCA = R"EOF(-----BEGIN CERTIFICATE-----
MIIDgTCCAmmgAwIBAgIUG/oiPJDtGh5HqWjx6ROQy6bf0XAwDQYJKoZIhvcNAQEL
BQAwUDESMBAGA1UECAwJU0QgQ291bnR5MRMwEQYDVQQHDApTcGFya1ZpbGxlMRMw
EQYDVQQKDApTcGFya0NoYWxsMRAwDgYDVQQDDAdzcGFya0NBMB4XDTI1MTAwMjEx
NTUxN1oXDTMwMTAwMjExNTUxN1owUDESMBAGA1UECAwJU0QgQ291bnR5MRMwEQYD
VQQHDApTcGFya1ZpbGxlMRMwEQYDVQQKDApTcGFya0NoYWxsMRAwDgYDVQQDDAdz
cGFya0NBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjlMz69QQpzLi
QrZMQ3vJhyOu3AmkwScNG/MLjONdCx25/rUR3dqTi4qbID/ysf5dEmIjNc4bbP9j
LN1RRkDFlDGI7jgyMoGP+Jgns9qMjO2izrNvGXynYAPk/XkeB0sZRcOrGLG2+KNW
ePXMpKXMNAAPYwQDP7vwv+ERpu/btsbOLT777gmPw8fv3CvkZsVtxsy8ogOYK3Lj
HAgaIFGurio0T51OlibsseUVunklYfMsJKDfZ49Jm6SJV9ls/JIWTbHiofl0bfKc
Wxdx4aXCPK+R0dhb2V060/zgFmowE4ISZTS460feuUTTCUgAgSG/NKtcMOXTXYdT
3ACDT5clOwIDAQABo1MwUTAdBgNVHQ4EFgQU1QNXyonrw69X+ZT3rYjU3yCSEdAw
HwYDVR0jBBgwFoAU1QNXyonrw69X+ZT3rYjU3yCSEdAwDwYDVR0TAQH/BAUwAwEB
/zANBgkqhkiG9w0BAQsFAAOCAQEAULUMNwMrq9fuJZ8IHurKM03qRt3bGyqH2reC
p/2WPAPD6cJT5ZPmcZ3w6PU75i+ObuJz0vPEO+0DJp5UrYZ6EluT9ktNKrPJFrmJ
ktWa6qk/tzxKGiGRZPgPpn2wUdpv1gSLE/SwxeQfxIeET2RdVdNiOeJOdybV8qvY
TIbyOBEvncrnWZv7MlD6Tjrue+sJhe5W3ErX/xTxFSMFQp1VX91d3jjV6Ivc7Y10
UG1mtbF4bqB+cHtWM0zE9QwkFHPS18+3OqpjYwqSVedkhTGPIM9+ZXvjIOoir3qJ
+Y3GjVUzhWZM6DOts74pIpPSbRooAClWD2pd9K6fQgZ/KjNWtw==
-----END CERTIFICATE-----)EOF";

const char* clientCert = R"KEY(-----BEGIN CERTIFICATE-----
MIIDPzCCAicCFBzZNDpiM8J3g6J5my9QnSYcTkrkMA0GCSqGSIb3DQEBCwUAMFAx
EjAQBgNVBAgMCVNEIENvdW50eTETMBEGA1UEBwwKU3BhcmtWaWxsZTETMBEGA1UE
CgwKU3BhcmtDaGFsbDEQMA4GA1UEAwwHc3BhcmtDQTAeFw0yNTEwMDIxMjA1MDha
Fw0yNjA5MjcxMjA1MDhaMGgxCzAJBgNVBAYTAkFTMRIwEAYDVQQIDAlTRCBDb3Vu
dHkxEzARBgNVBAcMClNwYXJrVmlsbGUxFzAVBgNVBAoMDlNwYXJrQ2hhbGwgTHRk
MRcwFQYDVQQDDA5zbWFydC1kb3JtLTEwMTCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBALuiCSPeqeeS1wgn3h5zwwzH3vugG6hBLeYeIt4xPItgRTgI4tCo
KCi1FTOWr+q90w2A4cAKgYBHY0QB1nj/XDZa71ddNCOOw5qbErzOVygZutVvicaO
lZQFPGM/fT4jUfVijVhQ3DnOlAyiQ8Nbr8lUudQIGgOSqFMQUHcCUPbUesqSlD/7
WJoaRz+tdtZ4fl5pdZQTxpM0kZVnIEo66WEaKvexqVBDF+qpDHvn5XIVJxSOA9u4
LCId023AE93xmIP5TY+lGkIDyhvkUbd7I3+dRVEd9sGmoWAtcN02Ak2NgCH4wuAj
aIVeZc4qqLx1F7e/4w8ScPxmTZkM5kbJqXkCAwEAATANBgkqhkiG9w0BAQsFAAOC
AQEAS0M6uSQOTmuqQc+Yo8As+P/ekAsgmVkIoOdmzEwcJN4H+K0ZpmEKWd/9b7N0
36BIKaGkfQrHKZThlT+5ue8CV0PRi3pzx/QRJHX1bxOk3ALOiCPv1yeAn2EFWAA1
bsBtPc+1X0dhOEo/l0/0cUH6ZrE7mS7hsovLG2oOZ3FHB5TfVcxcfhqo3F864wyz
bSxJRfnd1i0qXQ4zryY8oppRK1WjZ6Do6SSCcJhWf79VTOs53cVBlvoHh5il1kOa
u/4ywQVa+Q6b/+dSYp1zR7yqIM46pdyCFhPK4uRAvG6yZFGc3a8hLWLntroVn+PM
39xNSqpLXUVeXI9xkVh/odr1SA==
-----END CERTIFICATE-----)KEY";

const char* clientKey = R"KEY(-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7ogkj3qnnktcI
J94ec8MMx977oBuoQS3mHiLeMTyLYEU4COLQqCgotRUzlq/qvdMNgOHACoGAR2NE
AdZ4/1w2Wu9XXTQjjsOamxK8zlcoGbrVb4nGjpWUBTxjP30+I1H1Yo1YUNw5zpQM
okPDW6/JVLnUCBoDkqhTEFB3AlD21HrKkpQ/+1iaGkc/rXbWeH5eaXWUE8aTNJGV
ZyBKOulhGir3salQQxfqqQx75+VyFScUjgPbuCwiHdNtwBPd8ZiD+U2PpRpCA8ob
5FG3eyN/nUVRHfbBpqFgLXDdNgJNjYAh+MLgI2iFXmXOKqi8dRe3v+MPEnD8Zk2Z
DOZGyal5AgMBAAECggEAK477FLjvFBu+cD4DHmos5IVs8ljRut6Ax4yE9zSSc9/C
SfckIqD7C7I4LQ0FI1d0jMy3+8Nkm3FXLdVIYzgTAepb6FnyjfOpXLW15J95U82f
VkfJwg7dUiriAT9etaNw9iiuHAvPiFr4+zLbTNm25iQVbNABrAUqrvfZWjtvLNGy
ujLyKzZSE1W3+RDwp+CtBE20m4VEuNQ2/gCGelnDx0kptpBF/iJry4Km4br6D51Y
k6asaZcJfZmawTVre9AcVi7l2loXwtJ1EMNuEJyakdxdJfkFB16LvC13GHw2KcQZ
eOGWBPNAyHLMvHJSg/cXMhxhUnVL9ERAHKoF6Rg5NQKBgQDcFe7rTK1KQQqHx4Pi
5kIFAbzAbW36TvEvR+8zwm/a4nuaNsY1xJTQSQ5qKCUypEQh64Kz1VnTZ3Mr3emx
2yhlETWUMEvWcNkKJ4Twn7bgfk/CWEIp7RvkWVUE1Tg1QYjFVGmsc9oD2m3P/jIK
3zRqWf2MFLx/LKMX0mKTXUMvPQKBgQDaQGRE3EuKNUZ+4YSKn7KKY/6baUpY0LsB
YRmr7YZ6joEi3qB45vPUE903uuvDLbyOXdHppzu6saeOhfHftDBFuJCL1P2rO62e
VghdYtnvaZfvL1szXhiPwplAWMCsMJCnSOUcE3bd3l0mWK8h678qnBHpoFNSNneO
hQCkRiGG7QKBgQDHFxxDROC5/C5fd6+p0SvFxbWOyS8ksMbjQ4pyYyC2fAzeC1Cw
kP0hkgT1KQ3FSu3LVXWt4oFYiQuZkix2VM+s5a13OV1RRlJAKlHLLl/LotfZ8ecg
cDq8DceoEI3BN2BXSa4yb7a3p5+Q+N0iEpoi3vdLAfMmhCWhRhMgRcyh7QKBgDux
ovsmmc6qdaacfgkAVu/9G5VcPgZ+yLc+3KumosKAmZd09sU6vfQCnt3wVS2kI894
n8JdiDuu/ZpAzoAWI6HeMkLctakRAJKvC0inkd4mrnSwKiypjuQ7IHl2DPTLr7Th
fjCorjlO6YFkfjoz5ax81XVl8YQp+5dSj3Ne7yqdAoGABamE1FXL8GDGDBrgJkg0
xfw8oEmW0Vtpe0Flu8jt4/5U8zvoeHzT2w4Pm6W2BTA8Rj0EgNGLqxzIakPWHLQI
KX/3z73z9Hbl97W7iuhd2/l/BWNlldl32n2i/PuxCA17er8vq1BQ+0nlxbjwBtrQ
qkLFGKoicJod/qqQXD5214E=
-----END PRIVATE KEY-----)KEY";
const char* defURL = "http://107.173.236.249:9668/ota-update.bin";

// For token generation and trusted pairing
static bool paired = false;
static uint32_t expectedToken = 0;

// Connect to the network
WiFiClientSecure net;
MQTTClient client;
String baseTopic;
unsigned long lastTelemetryMs = 0;
const unsigned long telemetryIntervalMs = 10000;


void handleSerialCommands() {
  if (!Serial.available()) return;
  String cmd = Serial.readStringUntil('\n');
  cmd.trim();
  // Test connection status if any issues
  if (cmd.equalsIgnoreCase("debug")) {
    Serial.println();
    Serial.println(F("[DEBUG]"));
    Serial.println(F("server ca: ")); Serial.println(serverCA);
    Serial.println(F("client cert: ")); Serial.println(clientCert);
    Serial.println(F("client key:"));
    Serial.println(clientKey);
    Serial.println();
    Serial.println("WiFi connected!");
    Serial.println("MQTT connected!");
    // Test powerful server-side encryption when needed. EX: enc:{"PII":"top secret"}
  } else if (cmd.startsWith("enc:")) {
    encryptWithServer(cmd.substring(4));
    Serial.println("[ENC] requested");
  } else if (cmd.length() > 0) {
    Serial.print(F("[DEBUG] Unknown command: "));
    Serial.println(cmd);
  }
}

bool otaUpdateFromUrl(const String& urlParam) {
  String url = urlParam.length() ? urlParam : String(defURL);
  log("[OTA] Requested URL: " + url);
  logToBroker("[OTA] Requested URL: " + url);

  HTTPClient http;

  if (url.startsWith("https://")) {
    WiFiClientSecure httpsClient;
    httpsClient.setInsecure();
    if (!http.begin(httpsClient, url)) {
      Serial.println(F("[OTA] http.begin() failed (https)"));
      return false;
    }
  } else {
    WiFiClient httpClient;
    if (!http.begin(httpClient, url)) {
      Serial.println(F("[OTA] http.begin() failed (http)"));
      return false;
    }
  }

  const int httpCode = http.GET();
  if (httpCode != HTTP_CODE_OK) {
    Serial.print(F("[OTA] HTTP error: "));
    Serial.println(httpCode);
    http.end();
    return false;
  }

  // Check size to ensure no tampering has been done to our update
  int contentLength = http.getSize();
  if (contentLength > 0) {
    Serial.print(F("[OTA] Content-Length: "));
    Serial.println(contentLength);
  } else {
    Serial.println(F("[OTA] Content-Length unknown (chunked)"));
  }



  // Query OTA slot and print details
  const esp_partition_t* next = esp_ota_get_next_update_partition(nullptr);
  if (!next) {
    Serial.println(F("[OTA] No OTA partition found (check Partition Scheme: must support OTA)"));
    http.end();
    return false;
  }
  Serial.printf("[OTA] Next OTA partition addr=0x%08x size=%u bytes\n", next->address, next->size);
  // Ensure size is valid range for update and do signature checks next
  if (contentLength > 0 && (uint32_t)contentLength > next->size) {
    Serial.println(F("[OTA] Image too large for OTA partition — aborting"));
    http.end();
    return false;
  }

  WiFiClient& stream = http.getStream();

  // Begin with the partition’s size (or UPDATE_SIZE_UNKNOWN for chunked only after signature check)
  size_t maxSize = (contentLength > 0) ? contentLength : (size_t)UPDATE_SIZE_UNKNOWN;
  if (!Update.begin(maxSize)) {
    Serial.print(F("[OTA] Update.begin failed: "));
    Update.printError(Serial);
    http.end();
    return false;
  }
  // Start writing will doing sig and len checks along the way for verification
  Serial.println(F("[OTA] Writing..."));
  size_t written = Update.writeStream(stream);
  // Sig and/or size mismatch, bad file
  if (contentLength > 0 && written != (size_t)contentLength) {
    Serial.print(F("[OTA] Written length mismatch: wrote "));
    Serial.print(written);
    Serial.print(F("/"));
    Serial.println(contentLength);
  }
  // Tampered binary, not signed by admins or length off
  if (!Update.end()) {
    Serial.print(F("[OTA] Update.end failed: "));
    Update.printError(Serial);
    http.end();
    return false;
  }
  // Length/Format of bin not correct or internal signature check has failed
  if (!Update.isFinished()) {
    Serial.println(F("[OTA] Update not finished"));
    http.end();
    return false;
  }

  Serial.println(F("[OTA] Update successful, rebooting..."));
  http.end();
  delay(250);
  ESP.restart();
  return true;
}

// Callback for message recieved
void messageReceived(String &topic, String &payload) {
  log("Message incoming on topic: " + topic);
  // Do ota update
  if (topic == baseTopic+"/update") {
    String url = payload;
    url.trim();
    if (url.length() == 0) {
      Serial.println(F("[OTA] Empty URL payload. Using Default"));
    }
    otaUpdateFromUrl(url);
  } else if (topic == baseTopic+"/send_data") { // Confirm receive
      Serial.println(F("Sensor Data Received by Broker"));
  } else if (topic == (baseTopic + "/pair")) {  // This should be called on boot or when secure token exchange is needed for critical data
      if (payload == "request") {
        expectedToken = genToken();  // generate the token and send it for pairing
        client.publish(baseTopic + "/pair_token", String(expectedToken));
        Serial.println("[PAIR] issued token");
      }
  } else if (topic == (baseTopic + "/pair_confirm")) {
      // check for token tampering
      if ((uint32_t)payload.toInt() == expectedToken) {
        paired = true;
        client.publish(baseTopic + "/pair_status", "OK");
        Serial.println("[PAIR] success");
      } else {
        client.publish(baseTopic + "/pair_status", "FAIL");
        Serial.println("[PAIR] failed");
      }
  } else if (topic == (baseTopic + "/note_cipher")) { // Recieve back server-sided encryption cipher, used for sensitive data when powerful crypto is required.
      Serial.println("[ENC] ct_b64=" + payload);
      client.publish(baseTopic + "/secure_store", payload);
  }
}

// Generate random pair token
static uint32_t genToken() {
  return (uint32_t)(100000 + (rand() % 900000));
}

// These would typically be real sensors connected to the GPIO pins, however given timeline, potential wiring issues, & scope, these are your "sensors".
void publishTelemetry() {
  // "Fetch" sensor data
  float temperature = 18.0 + (random(0, 140) / 10.0f); // 18.0..31.9 °C
  int   humidity    = random(30, 71);                  // 30..70 %
  int   occupancy   = random(0, 2);                    // 0/1
  int   respiration = random(10, 23);                  // 10..22 bpm
  int   soundDB     = random(30, 66);                  // 30..65 dB

  // Build JSON
  String payload = "{";
  payload += "\"temperature\":" + String(temperature, 1) + ",";
  payload += "\"humidity\":"    + String(humidity)      + ",";
  payload += "\"occupancy\":"   + String(occupancy)     + ",";
  payload += "\"respiration\":" + String(respiration)   + ",";
  payload += "\"soundDB\":"     + String(soundDB);
  payload += "}";

  client.publish(baseTopic + "/send_data", payload);
  Serial.println("[TX] " + baseTopic + "/send_data " + payload);
}

// Log important/critical events so admins and SOC can monitor
void logToBroker(const String& s) {
  char buf[512];                       // Using "live buf" approach to conserve space avoid taking size up in extremely limited SRAM
  snprintf(buf, sizeof(buf), s.c_str()); // Avoid allocating extra space on stack and directly print the buf to our pub stream to avoid using precious SRAM
  client.publish(baseTopic + "/logstream", buf);
}

// Efficient memory logging to keep logs in flash and out of limited SRAM
void log(const String& s) {
  Serial.printf(s.c_str());
  Serial.print("\n");
}

// For mission-critical sensitive data, handle encryption server sided before logging/storing. This allows much more advanced encryption than what an ESP32 can handle.
inline void encryptWithServer(const String& pt) {
  client.publish(baseTopic + "/note_plain", pt);
}

void setup() {
  Serial.begin(115200);
  delay(50);

  baseTopic = String("/smart_dorm/") + host;

  // Connect to the WiFi
  WiFi.begin(ssid, pass);

  Serial.print("Checking wifi...");
  while (WiFi.status() != WL_CONNECTED) {
    Serial.print(".");
    delay(1000);
  }
  Serial.println("WiFi connected!");

  // Configure WiFiClientSecure with the required certs
  net.setCACert(serverCA);
  net.setCertificate(clientCert);
  net.setPrivateKey(clientKey);

  // Set a timeout for our WiFiClient so it doesn't hang on disconnect
  net.setTimeout(5);

  // Start the mqtt client
  client.begin("107.173.236.249", 8883, net);

  // Set the mqtt client message callback
  client.onMessage(messageReceived);

  // Connect to the mqtt broker
  while (!client.connect(host, "user", "pass")) {
    Serial.print(".");
    delay(1000);
  }

  Serial.println("connected!");

  // Subscribe to the relevant topics
  client.subscribe(baseTopic + "/#");
}

void loop() {
  // Run the mqtt client loop (handles recived messages - runs keep alive)
  client.loop();

  handleSerialCommands();

  // Check that client is still connected - if not reconnect
  if (!client.connected()) {
    while (!client.connect(host, "user", "pass")) {
      Serial.print(".");
      delay(1000);
   }
    Serial.println("Reconnected to MQTT Broker!");
    client.subscribe(baseTopic + "/#");
  }

  const unsigned long now = millis();
  if (now - lastTelemetryMs >= telemetryIntervalMs) {
    lastTelemetryMs = now;
    publishTelemetry();
  }
}
