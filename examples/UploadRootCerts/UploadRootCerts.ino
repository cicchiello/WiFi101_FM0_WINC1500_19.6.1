/*
  UploadRootCerts.ini for WiFi101 / WINC1500.
    - remove all existing root certificates
    - upload a list of root certificates using V1-style encoding
    - each root certificate will include encoding for
         - 20 character namehash
         - valid from date
	 - valid to date
	 - pubkey type (hardcoded RSA for now)
	 - modulus len
	 - exponent len
	 - modulus (pubkey)
	 - exponent

  For a given DER-encoded certificate file (say, cert.cer), do:
     > openssl x509 -in NMA_Root.cer -inform der -text -noout
  To determine most of the details needed for the above list.


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
#include "utility/DumpCerts.h"
#include "utility/programmer.h"
#include "utility/certificate.h"


/*
   if TESTRUN is defined, no changes will be made to the WINC1500 -- to provide
   the means to see a dry run of the image preparation.  When you think you're ready
   to change the flash for real, comment the line, compile, upload and run!
*/
//#define TESTRUN 1


/*
   Include a header file for each root certificate that includes the following function:
      const Certificate *<uniqueRootCertName>_getCertificate();

   The pointer to the returned Certificate must remain valid throughout the life of
   the sketch.

   The associated .cpp file should be placed in the 
*/
#include "utility/certs/NMA_Root_winc1500cert.h"
#include "utility/certs/GlobalSign_winc1500cert.h"
#include "utility/certs/ziggo_winc1500cert.h"


// returns 0 on failure; len of image on success
int prepare_certificate_entry_image(uint8 *entry_image, const Certificate *certificate)
{
  uint16 len = sizeof(tstrRootCertEntryHeader);
  tstrRootCertEntryHeader *entryHdr = (tstrRootCertEntryHeader*)entry_image;
  uint8 *keyBuff = &entry_image[sizeof(tstrRootCertEntryHeader)];

  /* Clear out the Certificate Entry Header */
  m2m_memset((uint8*)entryHdr, 0, len);

  /* Write Root Certificate Entry Header */
  m2m_memcpy(entryHdr->au8SHA1NameHash, (uint8*) certificate->nameHash, CRYPTO_SHA1_DIGEST_SIZE); 
  entryHdr->strStartDate = certificate->validFrom;  // Cert. Start Date
  entryHdr->strExpDate = certificate->validUntil;   // Cert. Expiration Date

  /* Write the certificate public key */
  if(certificate->pubKeyType == X509_CERT_PUBKEY_RSA)
  {
    /* RSA Public Key */
    const tstrRSAPubKey *key = &certificate->pubkey;

    entryHdr->strPubKey.u32PubKeyType		= ROOT_CERT_PUBKEY_RSA;
    entryHdr->strPubKey.strRsaKeyInfo.u16NSz	= key->u16NSize;
    entryHdr->strPubKey.strRsaKeyInfo.u16ESz	= key->u16ESize;

    /* N */
    m2m_memcpy(keyBuff, key->pu8N, key->u16NSize);
    keyBuff += key->u16NSize;

    /* E */
    m2m_memcpy(keyBuff, key->pu8E, key->u16ESize);
    len += WORD_ALIGN(key->u16ESize) + WORD_ALIGN(key->u16NSize);
  }
  else if(certificate->pubKeyType == X509_CERT_PUBKEY_ECDSA)
  {
    Serial.println("Unimplemented: CertKeyType == X509_CERT_PUBKEY_ECDSA");
    return 0;
  }

  return len;
}


  
// returns 0 on failure; len of flash image on success
int prepare_flash_image(uint8 *flash_image, const Certificate *certificates[])
{
  uint16 len = sizeof(tstrRootCertFlashHeader);
  tstrRootCertFlashHeader *flashHdr = (tstrRootCertFlashHeader*)((void *)flash_image);
  uint8 startPattern[] = ROOT_CERT_FLASH_START_PATTERN;
  
  memset(flash_image, 0, M2M_TLS_ROOTCER_FLASH_SIZE);

  int i = 0;
  for (i = 0; certificates[i]; i++) {}
  const int numCertificates = i;
  
  flashHdr->u32nCerts = numCertificates;
  m2m_memcpy(flashHdr->au8StartPattern, startPattern, ROOT_CERT_FLASH_START_PATTERN_LENGTH);

  for (int icert = 0; icert < numCertificates; icert++)
  {
    uint8 *entryBuff = &flash_image[len];
    tstrRootCertEntryHeader *entryHdr	= (tstrRootCertEntryHeader*)entryBuff;
    int entryLen = prepare_certificate_entry_image((uint8*) entryHdr, certificates[icert]);
    if (entryLen > 0) {
      entryHdr = (tstrRootCertEntryHeader*) (((uint8*)entryHdr) + entryLen);
      len += entryLen;
    } else {
      return 0;
    } 
  }

  return (len > M2M_TLS_ROOTCER_FLASH_SIZE) ? 0 : len;
}



static uint8 *buffer = 0;

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

  /* Setup Certificate array */
  const Certificate *certificates[] = {
    NMA_Root_getCertificate(),
    GlobalSign_getCertificate(),
    ziggo_getCertificate(),
    0 // make sure there's one extra entry of 0
  };

  /* Prepare the flash buffer */
  buffer = CertificateFlashBufferSingleton();
  int ret = prepare_flash_image(buffer, (const Certificate**) &certificates);
  if (ret <= 0) {
    Serial.println("ERROR: detected error in prepare_flash_image");
    while (1) {}
  }

#ifndef TESTRUN
  Serial.println("Here's a dump of the image that will be written");
#else
  Serial.println("Here's a dump of the image that would be written");
#endif
}


void loop() {
  int dumpShouldContinue = dumpRootCerts(buffer);
  if (!dumpShouldContinue) {
    Serial.println("Dump is done");

#ifndef TESTRUN
    /* Erase memory */
    Serial.println("Erasing the WINC1500 root certificate area of its flash");
    int ret = programmer_erase_root_cert();
    if(M2M_SUCCESS != ret) {
      Serial.println("ERROR: detected error during erase");
      Serial.print("INFO: ret == "); Serial.println(ret);
      while (1) {}
    }

    /* Write */
    Serial.println("Writing the Root Certificate(s) to WINC1500 flash...");
    ret = programmer_write_root_cert(buffer);
    if(M2M_SUCCESS != ret) {
      Serial.println("ERROR: detected error during write");
      Serial.print("INFO: ret == "); Serial.println(ret);
      while (1) {}
    }
  
    Serial.println("--- Root Certificate(s) written! ---");
#else     
    Serial.println("Skipping erase and write steps because this is a test run");
#endif

    Serial.println("UploadRootCerts is Done");
    while (1) {}
  }
}

