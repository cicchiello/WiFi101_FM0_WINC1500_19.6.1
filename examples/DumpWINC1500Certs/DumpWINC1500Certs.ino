/*
  DumpWINC1500Certs.ini for WiFi101 / WINC1500.
  
  Copyright (c) 2018 JFCEnterprises LLC.  All right reserved.

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include <WiFi101.h>
#include <utility/DumpCerts.h>


void setup() {
#ifdef ADAFRUIT_FEATHER_M0
  WiFi.setPins(8,7,4,2);
#endif

  // Initialize serial
  Serial.begin(9600);
  while (!Serial) {
    ; // wait for serial port to connect. Needed for native USB port only
  }

  /* Initialize the BSP. */
  nm_bsp_init();
  
  if(0 != m2m_wifi_download_mode()) {
    Serial.println("Unable to initialize bus, Press RESET button to try again.");
    while(1);
  }
}


void loop() {
  uint8 *buffer = CertificateFlashBufferSingleton();
  int shouldContinue = dumpRootCerts(buffer);
  if (!shouldContinue) {
     Serial.println("Done");
     while (1) {}
  }
}

