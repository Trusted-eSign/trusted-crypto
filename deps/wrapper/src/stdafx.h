#pragma once

//#include "targetver.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#ifdef _WIN32                 //added 
#include <tchar.h>
#include <windows.h>
#include <wincrypt.h>

#include "WinCryptEx.h"

#define HCRYPT_NULL NULL
#else // !_WIN32
#ifdef __x86_64__
#define SIZEOF_VOID_P 8
#else // !__x86_64__
#define SIZEOF_VOID_P 4
#endif

#ifdef CPROCSP
#undef HAVE_CONFIG_H // CSP headers includes myconfig.h if HAVE_CONFIG_H is defined
#include <cpcsp/WinCryptEx.h>
#include <cpcsp/CSP_WinDef.h>
#define CSP_BOOL BOOL
#endif

#define HCRYPT_NULL 0
#endif                          //added

#if defined(_WIN32) || (!defined(_WIN32) && defined(CPROCSP))
	#define CSP_ENABLE
#endif

#ifndef INT32_MAX
#  define INT32_MAX __MAXINT__(int32_t)
#endif
#ifndef UINT32_MAX
#  define UINT32_MAX __MAXUINT__(uint32_t)
#endif

#  define __MAXUINT__(T) ((T) -1)
#  define __MAXINT__(T) ((T) ((((T) 1) << ((sizeof(T) * CHAR_BIT) - 1)) ^ __MAXUINT__(T)))
#  define __MININT__(T) (-__MAXINT__(T) - 1)

#define X509_NAME_wincrypt X509_NAME
#undef X509_NAME

#undef X509_EXTENSIONS
#undef X509_CERT_PAIR 
#undef PKCS7_ISSUER_AND_SERIAL
#undef PKCS7_SIGNER_INFO
#undef OCSP_REQUEST
#undef OCSP_RESPONSE

#ifndef _countof
#define _countof(array) (sizeof(array)/sizeof(array[0]))
#endif
