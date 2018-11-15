#ifndef _INCLUDED_DUMP_CERTS
#define _INCLUDED_DUMP_CERTS

#include "driver/include/m2m_types.h"

uint8 *CertificateFlashBufferSingleton();

int dumpRootCerts(const uint8 *certMem);

#endif
