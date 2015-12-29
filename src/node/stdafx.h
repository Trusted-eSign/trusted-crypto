// stdafx.h: ���������� ���� ��� ����������� ��������� ���������� ������
// ��� ���������� ������ ��� ����������� �������, ������� ����� ������������, ��
// �� ����� ����������
//

#pragma once

//#include "targetver.h"

#include <stdio.h>

//��������� �������� �������
#ifdef _WIN32
	#include <tchar.h>
	#include <windows.h>
	#include <wincrypt.h>
#else // !_WIN32
	#ifdef __x86_64__
		#define SIZEOF_VOID_P 8
	#else // !__x86_64__
		#define SIZEOF_VOID_P 4
	#endif

	#undef HAVE_CONFIG_H // CSP headers includes myconfig.h if HAVE_CONFIG_H is defined
	//#include <cpcsp/WinCryptEx.h>
#endif // !_WIN32

#define X509_NAME_wincrypt X509_NAME
#undef X509_NAME

#undef X509_EXTENSIONS
#undef X509_CERT_PAIR
#undef PKCS7_ISSUER_AND_SERIAL
#undef PKCS7_SIGNER_INFO
#undef OCSP_REQUEST
#undef OCSP_RESPONSE

// TODO: ���������� ����� ������ �� �������������� ���������, ����������� ��� ���������
