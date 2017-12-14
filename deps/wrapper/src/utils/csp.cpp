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
		LPBYTE pbData;
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

		res = CryptGetProvParam(
			hCryptProv,
			PP_LICENSE,
			pbData,
			&cbData,
			0);

		if (hCryptProv) {
			if (!CryptReleaseContext(hCryptProv, 0)) {
				THROW_EXCEPTION(0, Csp, NULL, "CryptReleaseContext. Error: %d", GetLastError());
			}
		}

		hCryptProv = 0;

		if (pbData) {
			free((BYTE*)pbData);
		}

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
			THROW_EXCEPTION(0, Csp, NULL, "CryptAcquireContext. Error: %d", GetLastError());
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
		THROW_EXCEPTION(0, Csp, e, "Error get cpcsp license");
	}
}

std::vector<ProviderProps> Csp::enumProviders() {
	LOGGER_FN();

	try {
#ifdef CSP_ENABLE
		std::vector<ProviderProps> res;
		DWORD dwIndex = 0;
		DWORD dwType;
		DWORD cbName;
		LPTSTR pszName;

		while (CryptEnumProviders(dwIndex, NULL, 0, &dwType, NULL, &cbName))
		{
			if (!cbName)
				break;

			pszName = (LPTSTR)malloc(cbName);

			if (!CryptEnumProviders(dwIndex++, NULL, NULL, &dwType, pszName, &cbName)) {
				THROW_EXCEPTION(0, Csp, NULL, "CryptEnumProviders. Error: %d", GetLastError());
			}

			res.push_back({ dwType, new std::string(pszName) });

			if (pszName) {
				free(pszName);
			}
		}

		return res;
#else
		THROW_EXCEPTION(0, Csp, NULL, "Only if defined CSP_ENABLE");
#endif
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Csp, e, "Error enum providers");
	}
}

std::vector<Handle<std::string>> Csp::enumContainers(int provType) {
	LOGGER_FN();

	try {
#ifdef CSP_ENABLE
		std::vector<Handle<std::string>> res;
		std::vector<ProviderProps> providers;
		HCRYPTPROV hProv = 0;
		DWORD dwIndex = 0;
		DWORD dwType;
		LPTSTR pszName;
		DWORD dwFlags = CRYPT_FIRST;
		char* pszContainerName = NULL;
		BYTE* pbData = NULL;
		DWORD cbName;
		DWORD dwCount = 1;

		if (!provType) {
			providers = this->enumProviders();
		}
		else {
			providers.push_back({ provType, NULL });
		}

		if (!providers.size()) {
			THROW_EXCEPTION(0, Csp, NULL, "Empty providers list");
		}

		for (int i = 0; i < providers.size(); i++) {
			ProviderProps provider = providers[i];
			
			if (!CryptAcquireContext(
				&hProv,
				NULL,
				!provider.name.isEmpty() && provider.name->length() ? (LPCSTR)provider.name->c_str() : NULL,
				provider.type,
				CRYPT_VERIFYCONTEXT))
			{
				THROW_EXCEPTION(0, Csp, NULL, "CryptAcquireContext. Error: %d", GetLastError());
			}

			while (CryptGetProvParam(hProv, PP_ENUMCONTAINERS, NULL, &cbName, dwFlags))
			{
				if (cbName == 0)
					break;

				pbData = (BYTE*)malloc(cbName);

				if (!pbData) {
					THROW_EXCEPTION(0, Csp, NULL, "malloc failure");
				}

				if (!CryptGetProvParam(hProv, PP_ENUMCONTAINERS, pbData, &cbName, dwFlags | CRYPT_FQCN)) {
					free((void*)pbData);
					break;
				}

				pszContainerName = (char*)pbData;
				res.push_back(new std::string(pszContainerName));

				pszContainerName = NULL;
				free((void*)pbData);

				dwFlags = CRYPT_NEXT;
			}

			if (hProv) {
				if (!CryptReleaseContext(hProv, 0)) {
					THROW_EXCEPTION(0, Csp, NULL, "CryptReleaseContext. Error: %d", GetLastError());
				}
			}
		}

		return res;
#else
		THROW_EXCEPTION(0, Csp, NULL, "Only if defined CSP_ENABLE");
#endif
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Csp, e, "Error enum containers");
	}
}
