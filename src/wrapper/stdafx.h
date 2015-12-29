// stdafx.h: ���������� ���� ��� ����������� ��������� ���������� ������
// ��� ���������� ������ ��� ����������� �������, ������� ����� ������������, ��
// �� ����� ����������
//

#pragma once

//#include "targetver.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32                 //added 
#include <tchar.h>
#include <windows.h>
#include <wincrypt.h>

#define HCRYPT_NULL NULL
#else // !_WIN32
#ifdef __x86_64__
#define SIZEOF_VOID_P 8
#else // !__x86_64__
#define SIZEOF_VOID_P 4
#endif

#undef HAVE_CONFIG_H // CSP headers includes myconfig.h if HAVE_CONFIG_H is defined
//#include <cpcsp/WinCryptEx.h>

#define HCRYPT_NULL 0
#endif                          //added

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
