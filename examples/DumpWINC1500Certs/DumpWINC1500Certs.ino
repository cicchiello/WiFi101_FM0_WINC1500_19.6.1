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
#include <CertUtils.h>
#include <root_tls_cert.h>
#include <crypto.h>


void setup() {
#ifdef ADAFRUIT_FEATHER_M0
  WiFi.setPins(8,7,4,2);
#endif

  // Initialize serial
  Serial.begin(9600);
  while (!Serial) {
    ; // wait for serial port to connect. Needed for native USB port only
  }

  Serial.println("in setup");

  /* Initialize the BSP. */
  nm_bsp_init();
  
  if(0 != m2m_wifi_download_mode()) {
    Serial.println("Unable to initialize bus, Press RESET button to try again.");
    while(1);
  }
}



typedef enum dumpStateEnum {
  DUMP_INIT = 0,
  DUMP_NEXT,
  DUMP_DONE
} DumpState;

DumpState dstate = DUMP_INIT;


struct {
  uint32 forceAlignment;  // forces gau8CertMem to start on 4-byte alignment
  uint8_t gau8CertMem[M2M_TLS_SERVER_FLASH_SIZE];
} CertificateMemory;


void dumpNibble(uint8 n)
{
  char c;
  if (n > 9) c = 'A' + (n-10);
  else c = '0' + n;
  
  Serial.print(c);
}

void dumpByte(uint8 b)
{
  uint8 h = (b >> 4) & 0x0f;
  uint8 l = (b) & 0x0f;
  dumpNibble(h);
  dumpNibble(l);
}

void dumpWord(uint8 w)
{
  uint8 h = (w >> 8) & 0xff;
  uint8 l = (w) & 0xff;
  dumpByte(h);
  dumpByte(l);
}

void dumpRootCertEntry(const tstrRootCertEntryHeader *entry, uint8 idx)
{
  Serial.println();
//Serial.print("Address: "); Serial.println((uint32)((void*)entry));
  
  const tstrRootCertEntryHeader *pstrEntryHdr = entry;
  const tstrRootCertPubKeyInfo *pstrKey = &pstrEntryHdr->strPubKey;
  Serial.print("dumpRootCertEntry: dumping a ");
  Serial.print(pstrKey->u32PubKeyType == ROOT_CERT_PUBKEY_RSA ? "RSA" : "ECDSA");
  Serial.println(" public key");

  Serial.print("---begin cert #"); Serial.println(idx);
  const tstrRootCertRsaKeyInfo *info = &pstrKey->strRsaKeyInfo;
  uint16 nSz = info->u16NSz;
  uint16 eSz = info->u16ESz;
  Serial.print("dumpRootCertEntry: nSz: "); Serial.println(nSz);
  Serial.print("dumpRootCertEntry: eSz: "); Serial.println(eSz);
  uint16 tSz = WORD_ALIGN(nSz) + WORD_ALIGN(eSz);
  for (int i = 0; i < tSz; ) {
      dumpWord(i);
      Serial.print("   ");
      int j;
      for (j = 0; (j + i < tSz) && (j < 16); j++) {
      	  uint8 b = ((uint8*)entry)[i*16 + j];
	  Serial.print(" ");
	  dumpByte(b);
      }
      i += 16;
      Serial.println();
  }
  
  Serial.println("---end");
  Serial.println();
}


void dumpRootCerts(const uint8 *certMem)
{
  static uint8 idx = 0;
  static uint32 nStoredCerts = 0;
  
  const tstrRootCertFlashHeader *pstrRootFlashHdr = (const tstrRootCertFlashHeader*)((const void *)certMem);
    
  switch (dstate) {
  case DUMP_INIT: {
    memset((void*)certMem, 0, M2M_TLS_ROOTCER_FLASH_SIZE);
    programmer_read_root_cert(certMem);
    nStoredCerts = pstrRootFlashHdr->u32nCerts;
    Serial.print("There are "); Serial.print(nStoredCerts); Serial.println(" Root Certificates");

    dstate = (nStoredCerts == 0) ? DUMP_DONE : DUMP_NEXT;
    idx = 0;
  }
    break;
  case DUMP_NEXT: {
    uint32 offset = sizeof(tstrRootCertFlashHeader);
    for (uint8 i = 0; i < idx; i++) {
      const tstrRootCertEntryHeader *pstrEntryHdr = (const tstrRootCertEntryHeader*)((const void *)&certMem[offset]);
      const tstrRootCertPubKeyInfo *pstrKey = &pstrEntryHdr->strPubKey;
      offset += sizeof(tstrRootCertEntryHeader);
      offset += (pstrKey->u32PubKeyType == ROOT_CERT_PUBKEY_RSA) ? 
                   (WORD_ALIGN(pstrKey->strRsaKeyInfo.u16NSz) + WORD_ALIGN(pstrKey->strRsaKeyInfo.u16ESz)) :
		   (WORD_ALIGN(pstrKey->strEcsdaKeyInfo.u16KeySz) * 2);
    }

    dumpRootCertEntry((const tstrRootCertEntryHeader*)((const void*)&certMem[offset]), idx);

    idx++;
    if (idx == nStoredCerts) {
      // done dumping
      dstate = DUMP_DONE;
    }
  }
    break;
    
  case DUMP_DONE: {
    Serial.println("Done dumping");
    while (1) {}
  }
    break;
    
  default:
    break;
  }
}

void loop() {
  dumpRootCerts(&CertificateMemory.gau8CertMem[0]);
}

