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



typedef struct{
	uint8	au8StartPattern[ROOT_CERT_FLASH_START_PATTERN_LENGTH];
	uint32	u32nCerts;
} RootCertFlashHeader;


typedef struct{
	uint8   timebuf[21];
} SystemTimeV0;


typedef struct{
	uint16	u16Year;
	uint8	u8Month;
	uint8	u8Day;
	uint8	u8Hour;
	uint8	u8Minute;
	uint8	u8Second;
	uint8	__PAD8__;
} SystemTimeV1;


typedef struct{
	uint32	u32PubKeyType;
	union{
		tstrRootCertRsaKeyInfo		strRsaKeyInfo;
		tstrRootCertEcdsaKeyInfo	strEcsdaKeyInfo;
	};
} RootCertPubKeyInfoV0;


typedef struct{
	uint32	u32PubKeyType;
	union{
		tstrRootCertRsaKeyInfo		strRsaKeyInfo;
		tstrRootCertEcdsaKeyInfo	strEcsdaKeyInfo;
	};
} RootCertPubKeyInfoV1;


typedef struct{
	uint8				au8SHA1NameHash[CRYPTO_SHA1_DIGEST_SIZE];
	uint16				modulusLen;
	uint16				exponentLen;
	SystemTimeV0			strStartDate;
	SystemTimeV0			strExpDate;
} RootCertEntryHeaderV0;


typedef struct{
	uint8				au8SHA1NameHash[CRYPTO_SHA1_DIGEST_SIZE];
	SystemTimeV1			strStartDate;
	SystemTimeV1			strExpDate;
	RootCertPubKeyInfoV1		strPubKey;
} RootCertEntryHeaderV1;



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
  DUMP_NEXTV0,
  DUMP_NEXTV1,
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


void dumpDateV0(const SystemTimeV0 *d)
{
  dumpBuffer((uint8*)d, 21); // can't make out what this is yet...
}


void dumpDateV1(const SystemTimeV1 *d)
{
  Serial.print(d->u8Month);
  Serial.print(" ");
  Serial.print(d->u8Day);
  Serial.print(" ");
  Serial.print(d->u16Year);
}


void dumpRootCertV0(const RootCertEntryHeaderV0 *entry, uint8 idx)
{
  Serial.println();
  
  Serial.print("dumpRootCertV0: certificate #"); Serial.println(idx);
  
  const uint8 *pNameHash = &entry->au8SHA1NameHash[0];
  Serial.println("dumpRootCertV0: Name Hash:");
  dumpBuffer(pNameHash, CRYPTO_SHA1_DIGEST_SIZE);
  Serial.println();

  Serial.println("dumpRootCertV0: Validity");
  Serial.println("dumpRootCertV0:   Not Before: ");
  Serial.println("---begin date"); 
  dumpDateV0(&entry->strStartDate);
  Serial.println("---end");
  Serial.println();
  Serial.println("dumpRootCertV0:   Not After: ");
  Serial.println("---begin date"); 
  dumpDateV0(&entry->strExpDate);
  Serial.println("---end");
  Serial.println();
  Serial.println();

  uint8 *mod = (uint8*) entry + sizeof(RootCertEntryHeaderV0);

  Serial.print("DumpRootCertV0: pubkey len: "); Serial.println(entry->modulusLen);
  Serial.println("---begin pubkey"); 
  dumpBuffer(mod, entry->modulusLen);
  Serial.println("---end");

  uint8 *exp = mod + entry->modulusLen;
  uint8 exponent2 = exp[0];
  uint8 exponent1 = exp[1];
  uint8 exponent0 = exp[2];
  uint32 exponent = (exponent2 << 16) + (exponent1 << 8) + exponent0;
  
  Serial.print("DumpRootCertV0: exponent len: "); Serial.println(entry->exponentLen);
  Serial.print("dumpRootCertV1: PubKey Exponent: "); Serial.println(exponent);
}


void dumpRootCertV1(const RootCertEntryHeaderV1 *entry, uint8 idx)
{
  Serial.println();
  
  Serial.print("dumpRootCertV1: certificate #"); Serial.println(idx);
  
  const uint8 *pNameHash = &entry->au8SHA1NameHash[0];
  Serial.println("dumpRootCertV1: Name Hash:");
  dumpBuffer(pNameHash, CRYPTO_SHA1_DIGEST_SIZE);
  Serial.println();

  Serial.println("dumpRootCertV1: Validity");
  Serial.print("dumpRootCertV1:   Not Before: ");
  dumpDateV1(&entry->strStartDate);
  Serial.println();
  Serial.print("dumpRootCertV1:   Not After: ");
  dumpDateV1(&entry->strExpDate);
  Serial.println();
  Serial.println();


  const RootCertPubKeyInfoV1 *pubKey = &entry->strPubKey;
  bool isRSA = pubKey->u32PubKeyType == ROOT_CERT_PUBKEY_RSA;
  
  Serial.print("dumpRootCertV1: pubKey type is "); Serial.println(isRSA ? "RSA" : "ECDSA");
  const uint8 *keyMem = (const uint8 *) (((const void*)entry) + sizeof(RootCertEntryHeaderV1));
  if (isRSA) {
    const tstrRootCertRsaKeyInfo *info = &pubKey->strRsaKeyInfo;
    uint16 nSz = info->u16NSz;
    uint16 eSz = info->u16ESz;
    Serial.print("dumpRootCertV1: nSz: "); Serial.println(nSz);
    Serial.print("dumpRootCertV1: eSz: "); Serial.println(eSz);

    Serial.println("---begin pubkey"); 
    dumpBuffer(keyMem-1, nSz+1);
    Serial.println("---end");

    uint8 exponent2 = keyMem[nSz];
    uint8 exponent1 = keyMem[nSz+1];
    uint8 exponent0 = keyMem[nSz+2];
    uint32 exponent = (exponent2 << 16) + (exponent1 << 8) + exponent0;
    Serial.print("dumpRootCertV1: PubKey Exponent: "); Serial.println(exponent);
    
  } else {
    uint16 keyMemSz = 0;
    const tstrRootCertEcdsaKeyInfo *info = &pubKey->strEcsdaKeyInfo;
    uint16 curveID = info->u16CurveID;
    uint16 keySz = info->u16KeySz;
    Serial.print("dumpRootCertV1: CurveID: "); Serial.println(curveID);
    keyMemSz = keySz * 2;

    Serial.println("---begin key"); 
    dumpBuffer(keyMem, keyMemSz);
    Serial.println("---end");
  }

  Serial.println();
}


static uint8 V0[] = ROOT_CERT_FLASH_START_PATTERN_V0;
static uint8 V1[] = ROOT_CERT_FLASH_START_PATTERN;

static int schemaVersion = -1;

void dumpRootCerts(const uint8 *certMem)
{
  static uint8 idx = 0;
  static uint32 nStoredCerts = 0;
  
  const RootCertFlashHeader *rootFlashHdr = (const RootCertFlashHeader*)((const void *)certMem);
    
  switch (dstate) {
  case DUMP_INIT: {
    memset((void*)certMem, 0, M2M_TLS_ROOTCER_FLASH_SIZE);
    programmer_read_root_cert(certMem);
    
    if (memcmp(&rootFlashHdr->au8StartPattern[0], V0, ROOT_CERT_FLASH_START_PATTERN_LENGTH) == 0) {
      schemaVersion = 0;
      Serial.println("Root Certificate header version 0 detected");
    } else if (memcmp(&rootFlashHdr->au8StartPattern[0], V1, ROOT_CERT_FLASH_START_PATTERN_LENGTH) == 0) {
      Serial.println("Root Certificate header version 1 detected");
      schemaVersion = 1;
    } else {
      Serial.println("Unrecognized Root Certification header version");
    }
    Serial.println();
    
    nStoredCerts = rootFlashHdr->u32nCerts;
    Serial.print("There are "); Serial.print(nStoredCerts); Serial.println(" Root Certificates");
    dstate = (nStoredCerts == 0) ? DUMP_DONE : (schemaVersion == 0 ? DUMP_NEXTV0 : DUMP_NEXTV1);
    idx = 0;
  }
    break;
    
  case DUMP_NEXTV0: {
    uint32 offset = sizeof(RootCertFlashHeader);
    for (uint8 i = 0; i < idx; i++) {
      const RootCertEntryHeaderV0 *pstrEntryHdr = (const RootCertEntryHeaderV0*)((const void *)&certMem[offset]);
      uint16 modulusLen = pstrEntryHdr->modulusLen;
      uint16 exponentLen = pstrEntryHdr->exponentLen;
      offset += sizeof(RootCertEntryHeaderV0);
      offset += modulusLen + exponentLen;
      while (offset % 4 != 0)
        offset++;
    }

    dumpRootCertV0((const RootCertEntryHeaderV0 *)((const void*)&certMem[offset]), idx);

    idx++;
    if (idx == nStoredCerts) {
      // done dumping
      dstate = DUMP_DONE;
    }
  }
    break;
    
  case DUMP_NEXTV1: {
    uint32 offset = sizeof(RootCertFlashHeader);
    for (uint8 i = 0; i < idx; i++) {
      const RootCertEntryHeaderV1 *pstrEntryHdr = (const RootCertEntryHeaderV1*)((const void *)&certMem[offset]);
      const RootCertPubKeyInfoV1 *pstrKey = &pstrEntryHdr->strPubKey;
      offset += sizeof(RootCertEntryHeaderV1);
      offset += (pstrKey->u32PubKeyType == ROOT_CERT_PUBKEY_RSA) ? 
                   (WORD_ALIGN(pstrKey->strRsaKeyInfo.u16NSz) + WORD_ALIGN(pstrKey->strRsaKeyInfo.u16ESz)) :
		   (WORD_ALIGN(pstrKey->strEcsdaKeyInfo.u16KeySz) * 2);
    }

    dumpRootCertV1((const RootCertEntryHeaderV1 *)((const void*)&certMem[offset]), idx);

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

