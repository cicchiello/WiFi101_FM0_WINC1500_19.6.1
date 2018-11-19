/*

 This example connects to an network using WPA2 Enterprise authentication and MSCHAPV2
 
 Then it prints the  MAC address of the Wifi shield,
 the IP address obtained, and other network details.

 Circuit:
 * WiFi shield attached

 created 13 July 2010
 by dlf (Metodo2 srl)
 modified 31 May 2012
 by Tom Igoe
 */
#include <SPI.h>
#include <WiFi101.h>

#include "arduino_secrets.h" 
///////please enter your sensitive data in the Secret tab/arduino_secrets.h
static const char *MAIN_WLAN_SSID = SECRET_SSID;
static const char *MAIN_WLAN_802_1X_USR_NAME = SECRET_USER_NAME;
static const char *MAIN_WLAN_802_1X_PWD = SECRET_PWD;

static tstrAuth1xMschap2 mschapv2_credential;
static tstrNetworkId networkId;

int status = WL_IDLE_STATUS;     // the Wifi radio's status

void setup() {
#ifdef ADAFRUIT_FEATHER_M0
  WiFi.setPins(8,7,4,2);
#endif

  //Initialize serial and wait for port to open:
  Serial.begin(9600);
  while (!Serial) {
    ; // wait for serial port to connect. Needed for native USB port only
  }

  networkId.pu8Bssid = NULL;
  networkId.pu8Ssid = (uint8 *)MAIN_WLAN_SSID;
  networkId.u8SsidLen = strlen(MAIN_WLAN_SSID);
  networkId.enuChannel = M2M_WIFI_CH_ALL;

  mschapv2_credential.pu8Domain = NULL;
  //mschapv2_credential.u16DomainLen = strlen(mschapv2_credential.pu8Domain);
  mschapv2_credential.pu8UserName = (uint8 *)MAIN_WLAN_802_1X_USR_NAME;
  mschapv2_credential.pu8Password = (uint8 *)MAIN_WLAN_802_1X_PWD;
  mschapv2_credential.u16UserNameLen = strlen(MAIN_WLAN_802_1X_USR_NAME);
  mschapv2_credential.u16PasswordLen = strlen(MAIN_WLAN_802_1X_PWD);
  mschapv2_credential.bUnencryptedUserName = false;
  mschapv2_credential.bPrependDomain = true;

  // check for the presence of the shield:
  if (WiFi.status() == WL_NO_SHIELD) {
    Serial.println("WiFi shield not present");
    // don't continue:
    while (true);
  }

  // attempt to connect to WiFi network:
  while ( WiFi.status() != WL_CONNECTED) {
    Serial.print("Attempting to connect to WPA2 Enterprise with MSCHAPv2 SSID: ");
    Serial.println((const char*)networkId.pu8Ssid);
    Serial.print("Using second phase user: ");
    Serial.println((const char*)mschapv2_credential.pu8UserName);
    Serial.print("Using second phase pswd: ");
    Serial.println((const char*)mschapv2_credential.pu8Password);
    status = WiFi.begin(&networkId, &mschapv2_credential);

    // wait 10 seconds for connection:
    delay(10000);
  }

  // you're connected now, so print out the data:
  Serial.print("You're connected to the network");
  printCurrentNet();
  printWiFiData();

}

void loop() {
  // check the network connection once every 10 seconds:
  delay(10000);
  printCurrentNet();
}

void printWiFiData() {
  // print your WiFi shield's IP address:
  IPAddress ip = WiFi.localIP();
  Serial.print("IP Address: ");
  Serial.println(ip);
  Serial.println(ip);

  // print your MAC address:
  byte mac[6];
  WiFi.macAddress(mac);
  Serial.print("MAC address: ");
  Serial.print(mac[5], HEX);
  Serial.print(":");
  Serial.print(mac[4], HEX);
  Serial.print(":");
  Serial.print(mac[3], HEX);
  Serial.print(":");
  Serial.print(mac[2], HEX);
  Serial.print(":");
  Serial.print(mac[1], HEX);
  Serial.print(":");
  Serial.println(mac[0], HEX);

}

void printCurrentNet() {
  // print the SSID of the network you're attached to:
  Serial.print("SSID: ");
  Serial.println(WiFi.SSID());

  // print the MAC address of the router you're attached to:
  byte bssid[6];
  WiFi.BSSID(bssid);
  Serial.print("BSSID: ");
  Serial.print(bssid[5], HEX);
  Serial.print(":");
  Serial.print(bssid[4], HEX);
  Serial.print(":");
  Serial.print(bssid[3], HEX);
  Serial.print(":");
  Serial.print(bssid[2], HEX);
  Serial.print(":");
  Serial.print(bssid[1], HEX);
  Serial.print(":");
  Serial.println(bssid[0], HEX);

  // print the received signal strength:
  long rssi = WiFi.RSSI();
  Serial.print("signal strength (RSSI):");
  Serial.println(rssi);

  // print the encryption type:
  byte encryption = WiFi.encryptionType();
  Serial.print("Encryption Type:");
  Serial.println(encryption, HEX);
  Serial.println();
}

