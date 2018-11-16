#ifndef _INCLUDED_CERTIFICATE_H
#define _INCLUDED_CERTIFICATE_H

#include "driver/include/m2m_types.h"
#include "utility/crypto.h"

typedef struct strCertificate {
  uint8 nameHash[CRYPTO_SHA1_DIGEST_SIZE];
  tstrSystemTime validFrom;
  tstrSystemTime validUntil;
  uint32         pubKeyType;
  tstrRSAPubKey  pubkey;
} Certificate;

#endif
