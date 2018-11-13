/**
 * \file
 *
 * \brief Header file for cryptographic algorithms.
 *
 * Copyright (c) 2017-2018 Microchip Technology Inc. and its subsidiaries.
 *
 * \asf_license_start
 *
 * \page License
 *
 * Subject to your compliance with these terms, you may use Microchip
 * software and any derivatives exclusively with Microchip products.
 * It is your responsibility to comply with third party license terms applicable
 * to your use of third party software (including open source software) that
 * may accompany Microchip software.
 *
 * THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES,
 * WHETHER EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE,
 * INCLUDING ANY IMPLIED WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY,
 * AND FITNESS FOR A PARTICULAR PURPOSE. IN NO EVENT WILL MICROCHIP BE
 * LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE, INCIDENTAL OR CONSEQUENTIAL
 * LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND WHATSOEVER RELATED TO THE
 * SOFTWARE, HOWEVER CAUSED, EVEN IF MICROCHIP HAS BEEN ADVISED OF THE
 * POSSIBILITY OR THE DAMAGES ARE FORESEEABLE.  TO THE FULLEST EXTENT
 * ALLOWED BY LAW, MICROCHIP'S TOTAL LIABILITY ON ALL CLAIMS IN ANY WAY
 * RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF FEES, IF ANY,
 * THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS SOFTWARE.
 *
 * \asf_license_stop
 *
 */

#ifndef __CRYPTO_API_H__
#define __CRYPTO_API_H__

/*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
INCLUDES
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*/

#include "common/include/nm_common.h"
#include "driver/include/m2m_types.h"

/*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
MACROS
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*/

#define CRYPTO_SHA1_DIGEST_SIZE			(20)
#define ECC_POINT_MAX					(72)

/*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
DATA TYPES
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*/

/*!
@enum\
	tenuCertPubKeyType
*/
typedef enum{
	X509_CERT_PUBKEY_RSA	= 1,
	X509_CERT_PUBKEY_ECDSA	= 2
}tenuCertPubKeyType;


/*!
@struct	\
	tstrRsaPrivateKey
*/
typedef struct{
	uint16	u16NSize;
	uint16	u16eSize;
	uint16	u16dSize;
	uint16	u16PSize;
	uint16	u16QSize;
	uint16	u16dPSize;
	uint16	u16dQSize;
	uint16	u16QInvSize;
	uint32	u32Version;
	uint8	*pu8N;
	uint8	*pu8e;
	uint8	*pu8d;
	uint8	*pu8p;
	uint8	*pu8q;
	uint8	*pu8dP;
	uint8	*pu8dQ;
	uint8	*pu8QInv;
}tstrRsaPrivateKey;


/*!
@struct	\
	tstrASN1RsaPrivateKey

@brief	RSA Private Key Elements

	The structure contains the elements of the RSA Private key as decoded from
	the supplied private key file (PEM Format).
*/
typedef struct{
	tstrRsaPrivateKey	strRsaPrivKey;
	uint8				*pu8AllocPtr;
	uint16				u16KeyBufSz;
}tstrASN1RSAPrivateKey;


/*!
@struct	\
	tstrRSAPubKey
*/
typedef struct{
	uint16	u16NSize;
	uint16	u16ESize;
	uint8	*pu8N;
	uint8	*pu8E;
}tstrRSAPubKey;


/*!
@struct	\
	tstrECDSAPubKey
*/
typedef struct{
	uint16	u16CurveID;
	uint16	u16EcPointSz;
	uint8	au8EcPoint[ECC_POINT_MAX * 2];
}tstrECDSAPubKey;


/*!
@struct	\
	tstrX509CertPublicKey
*/
typedef struct{
	tenuCertPubKeyType	enuCertKeyType;
	union{
		tstrRSAPubKey	strRsaPub;
		tstrECDSAPubKey	strEcdsaPub;
	};
}tstrX509CertPublicKey;


/*!
@struct	\
	tstrX520Name

@brief
*/
typedef struct{
	char	acCmnName[64];
	uint8	au8NameSHA1[20];
}tstrX509Name;


/*!
@struct	\
	txtrX509CertInfo
*/
typedef struct{
	uint8					u8SerialNumberLength;
	uint8					au8SerialNo[64];
	tstrX509Name			strIssuer;
	tstrSystemTime			strExpiryDate;
	tstrSystemTime			strStartDate;
	tstrX509Name			strSubject;
	tstrX509CertPublicKey	strPubKey;
	void					*pvPrivate;
}txtrX509CertInfo;


/*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
MACROS
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*/

#define ROOT_CERT_FLASH_START_PATTERN_LENGTH		16

#define ROOT_CERT_FLASH_EMPTY_PATTERN \
{\
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF	\
}
	
/* tstrRootCertEntryHeader Format used in 19.4.x */
#define ROOT_CERT_FLASH_START_PATTERN_V0	\
{\
	0x01, 0xF1, 0x02, 0xF2, 0x03, 0xF3, 0x04, 0xF4,	\
	0x05, 0xF5, 0x06, 0xF6, 0x07, 0xF7, 0x08, 0xF8	\
}

/* tstrRootCertEntryHeader Format used in 19.5.x */
#define ROOT_CERT_FLASH_START_PATTERN	\
{\
	0x11, 0xF1, 0x12, 0xF2, 0x13, 0xF3, 0x14, 0xF4, \
	0x15, 0xF5, 0x16, 0xF6, 0x17, 0xF7, 0x18, 0xF8	\
}

/*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
DATA TYPES
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*/

typedef struct{
	uint8	au8StartPattern[ROOT_CERT_FLASH_START_PATTERN_LENGTH];
	uint32	u32nCerts;
}tstrRootCertFlashHeader;

typedef enum{
	ROOT_CERT_PUBKEY_RSA		= 1,
	ROOT_CERT_PUBKEY_ECDSA		= 2
}tenuRootCertPubKeyType;

typedef struct{
	uint16	u16NSz;
	uint16	u16ESz;
}tstrRootCertRsaKeyInfo;

typedef struct{
	uint16	u16CurveID;
	uint16	u16KeySz;
}tstrRootCertEcdsaKeyInfo;

typedef struct{
	uint32	u32PubKeyType;
	union{
		tstrRootCertRsaKeyInfo		strRsaKeyInfo;
		tstrRootCertEcdsaKeyInfo	strEcsdaKeyInfo;
	};
}tstrRootCertPubKeyInfo;


/*!
@struct
	tstrRootCertEntryHeader

@brief
	Header of a root certificate entry in flash.
*/	
typedef struct{
	uint8					au8SHA1NameHash[CRYPTO_SHA1_DIGEST_SIZE];
	tstrSystemTime			strStartDate;
	tstrSystemTime			strExpDate;
	tstrRootCertPubKeyInfo	strPubKey;
}tstrRootCertEntryHeader;


/*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
FUNCTION PROTOTYPES
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*/

sint8 CryptoX509CertDecode(uint8 *pu8X509CertBuf, uint16 u16X509CertBuffer, txtrX509CertInfo *pstrCert, uint8 bDumpCert);
void CryptoX509DeleteContext(txtrX509CertInfo *pstrCert);
sint8 CryptoDecodeRsaPrivKey(uint8 *pu8RsaKeyFile, uint32 u32KeySize, tstrASN1RSAPrivateKey *pstrRsaPrivKey);
#endif /* __CRYPTO_API_H__ */
