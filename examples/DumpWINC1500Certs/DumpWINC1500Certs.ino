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

  //Serial.println("in setup");

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
  if (n > 9) c = 'a' + (n-10);
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

void dumpWord(uint16 w)
{
  uint8 h = (w & 0xff00) >> 8;
  uint8 l = w & 0x00ff;
  dumpByte(h);
  dumpByte(l);
}

void dumpBuffer(const uint8 *ptr, const uint16 len)
{
  for (int i = 0; i < len; ) {
      Serial.print("0000");
      dumpWord(i);
      Serial.print(":");
      for (int j = 0; (j + i < len) && (j < 16); ) {
	  Serial.print(" ");
	  dumpByte(ptr[i + j]);
	  j++;
	  if (j + i < len) {
	    dumpByte(ptr[i + j]);
	    j++;
	  }
      }
      i += 16;
      Serial.println();
  }
}


void dumpDate(const tstrSystemTime *d)
{
  Serial.print(d->u8Month);
  Serial.print(" ");
  Serial.print(d->u8Day);
  Serial.print(" ");
  Serial.print(d->u16Year);
}


void dumpRootCert(const tstrRootCertEntryHeader *entry, uint8 idx)
{
  Serial.println();
  
  Serial.print("dumpRootCert: certificate #"); Serial.println(idx);
  
  const uint8 *pNameHash = &entry->au8SHA1NameHash[0];
  Serial.println("dumpRootCert: Name Hash:");
  dumpBuffer(pNameHash, CRYPTO_SHA1_DIGEST_SIZE);
  Serial.println();

  Serial.println("dumpRootCert: Validity");
  Serial.print("dumpRootCert:   Not Before: ");
  dumpDate(&entry->strStartDate);
  Serial.println();
  Serial.print("dumpRootCert:   Not After: ");
  dumpDate(&entry->strExpDate);
  Serial.println();
  Serial.println();


  const tstrRootCertPubKeyInfo *pubKey = &entry->strPubKey;
  bool isRSA = pubKey->u32PubKeyType == ROOT_CERT_PUBKEY_RSA;
  
  Serial.print("dumpRootCert: pubKey type is "); Serial.println(isRSA ? "RSA" : "ECDSA");
  const uint8 *keyMem = (const uint8 *) (((const void*)entry) + sizeof(tstrRootCertEntryHeader));
  if (isRSA) {
    const tstrRootCertRsaKeyInfo *info = &pubKey->strRsaKeyInfo;
    uint16 nSz = info->u16NSz;
    uint16 eSz = info->u16ESz;
    Serial.print("dumpRootCert: nSz: "); Serial.println(nSz);
    Serial.print("dumpRootCert: eSz: "); Serial.println(eSz);

    Serial.println("---begin pubkey"); 
    dumpBuffer(keyMem-1, nSz+1);
    Serial.println("---end");

    uint8 exponent2 = keyMem[nSz];
    uint8 exponent1 = keyMem[nSz+1];
    uint8 exponent0 = keyMem[nSz+2];
    uint32 exponent = (exponent2 << 16) + (exponent1 << 8) + exponent0;
    Serial.print("dumpRootCert: PubKey Exponent: "); Serial.println(exponent);
    
  } else {
    uint16 keyMemSz = 0;
    const tstrRootCertEcdsaKeyInfo *info = &pubKey->strEcsdaKeyInfo;
    uint16 curveID = info->u16CurveID;
    uint16 keySz = info->u16KeySz;
    Serial.print("dumpRootCert: CurveID: "); Serial.println(curveID);
    keyMemSz = keySz * 2;

    Serial.println("---begin key"); 
    dumpBuffer(keyMem, keyMemSz);
    Serial.println("---end");
  }

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

    dumpRootCert((const tstrRootCertEntryHeader *)((const void*)&certMem[offset]), idx);

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

