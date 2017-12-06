#include "../stdafx.h"

#include "wrapper/utils/csp.h"

bool Csp::isGost2001CSPAvailable() {
	LOGGER_FN();

	try {
#ifdef CSP_ENABLE
		static HCRYPTPROV hCryptProv = 0;
		bool res;

		res = CryptAcquireContext(
			&hCryptProv,
			NULL,
			NULL,
			PROV_GOST_2001_DH,
			CRYPT_VERIFYCONTEXT);

		if (hCryptProv) {
			if (!CryptReleaseContext(hCryptProv, 0)) {
				THROW_EXCEPTION(0, Csp, NULL, "CryptReleaseContext. Error: %d", GetLastError());
			}
		}

		hCryptProv = 0;

		return res;
#else
		THROW_EXCEPTION(0, Csp, NULL, "Only if defined CSP_ENABLE");
#endif
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Csp, e, "Error check GOST 2001 provaider");
	}
}

bool Csp::isGost2012_256CSPAvailable() {
	LOGGER_FN();

	try {
#ifdef CSP_ENABLE
		static HCRYPTPROV hCryptProv = 0;
		bool res;

		res = CryptAcquireContext(
			&hCryptProv,
			NULL,
			NULL,
			PROV_GOST_2012_256,
			CRYPT_VERIFYCONTEXT);

		if (hCryptProv) {
			if (!CryptReleaseContext(hCryptProv, 0)) {
				THROW_EXCEPTION(0, Csp, NULL, "CryptReleaseContext. Error: %d", GetLastError());
			}
		}

		hCryptProv = 0;

		return res;
#else
		THROW_EXCEPTION(0, Csp, NULL, "Only if defined CSP_ENABLE");
#endif
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Csp, e, "Error check GOST 2001 provaider");
	}
}

bool Csp::isGost2012_512CSPAvailable() {
	LOGGER_FN();

	try {
#ifdef CSP_ENABLE
		static HCRYPTPROV hCryptProv = 0;
		bool res;

		res = CryptAcquireContext(
			&hCryptProv,
			NULL,
			NULL,
			PROV_GOST_2012_512,
			CRYPT_VERIFYCONTEXT);

		if (hCryptProv) {
			if (!CryptReleaseContext(hCryptProv, 0)) {
				THROW_EXCEPTION(0, Csp, NULL, "CryptReleaseContext. Error: %d", GetLastError());
			}
		}

		hCryptProv = 0;

		return res;
#else
		THROW_EXCEPTION(0, Csp, NULL, "Only if defined CSP_ENABLE");
#endif
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Csp, e, "Error check GOST 2001 provaider");
	}
}

bool Csp::checkCPCSPLicense() {
	LOGGER_FN();

	try {
#ifdef CSP_ENABLE
		static HCRYPTPROV hCryptProv = 0;
		DWORD cbData = 0;
		bool res = false;

		if (!isGost2001CSPAvailable()) {
			THROW_EXCEPTION(0, Key, NULL, "GOST 2001 provaider not available");
		}

		if (!CryptAcquireContext(
			&hCryptProv,
			NULL,
			NULL,
			PROV_GOST_2001_DH,
			CRYPT_VERIFYCONTEXT))
		{
			THROW_EXCEPTION(0, Key, NULL, "CryptAcquireContext. Error: %d", GetLastError());
		}

		res = CryptGetProvParam(
			hCryptProv,
			PP_LICENSE,
			NULL,
			&cbData,
			0);

		if (hCryptProv) {
			if (!CryptReleaseContext(hCryptProv, 0)) {
				THROW_EXCEPTION(0, Csp, NULL, "CryptReleaseContext. Error: %d", GetLastError());
			}
		}

		hCryptProv = 0;

		return res;
#else
		THROW_EXCEPTION(0, Csp, NULL, "Only if defined CSP_ENABLE");
#endif
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Csp, e, "Error check cpcsp license");
	}
}

Handle<std::string> Csp::getCPCSPLicense() {
	LOGGER_FN();

	try {
#ifdef CSP_ENABLE
		static HCRYPTPROV hCryptProv = 0;
		DWORD cbData = 0;
		LPBYTE pbData;
		Handle<std::string> license;

		if (!isGost2001CSPAvailable()) {
			THROW_EXCEPTION(0, Key, NULL, "GOST 2001 provaider not available");
		}

		if (!CryptAcquireContext(
			&hCryptProv,
			NULL,
			NULL,
			PROV_GOST_2001_DH,
			CRYPT_VERIFYCONTEXT))
		{
			THROW_EXCEPTION(0, Key, NULL, "CryptAcquireContext. Error: %d", GetLastError());
		}

		if (!CryptGetProvParam(
			hCryptProv,
			PP_LICENSE,
			NULL,
			&cbData,
			0))
		{
			THROW_EXCEPTION(0, Key, NULL, "CryptGetProvParam. Error: %d", GetLastError());
		}

		pbData = (LPBYTE)malloc(cbData);

		if (!CryptGetProvParam(
			hCryptProv,
			PP_LICENSE,
			pbData,
			&cbData,
			0))
		{
			THROW_EXCEPTION(0, Key, NULL, "CryptGetProvParam. Error: %d", GetLastError());
		}

		license = new std::string((char *)pbData);

		if (hCryptProv) {
			if (!CryptReleaseContext(hCryptProv, 0)) {
				THROW_EXCEPTION(0, Csp, NULL, "CryptReleaseContext. Error: %d", GetLastError());
			}
		}

		hCryptProv = 0;

		if (pbData) {
			free((BYTE*)pbData);
		}

		return license;
#else
		THROW_EXCEPTION(0, Csp, NULL, "Only if defined CSP_ENABLE");
#endif
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Csp, e, "Error check cpcsp license");
	}
}
