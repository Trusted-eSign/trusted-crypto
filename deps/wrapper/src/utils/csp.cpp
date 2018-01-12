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
				THROW_EXCEPTION(0, Csp, NULL, "CryptReleaseContext. Error: 0x%08x", GetLastError());
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
				THROW_EXCEPTION(0, Csp, NULL, "CryptReleaseContext. Error: 0x%08x", GetLastError());
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
				THROW_EXCEPTION(0, Csp, NULL, "CryptReleaseContext. Error: 0x%08x", GetLastError());
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
			THROW_EXCEPTION(0, Key, NULL, "CryptAcquireContext. Error: 0x%08x", GetLastError());
		}

		if (!CryptGetProvParam(
			hCryptProv,
			PP_LICENSE,
			NULL,
			&cbData,
			0))
		{
			THROW_EXCEPTION(0, Key, NULL, "CryptGetProvParam. Error: 0x%08x", GetLastError());
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
				THROW_EXCEPTION(0, Csp, NULL, "CryptReleaseContext. Error: 0x%08x", GetLastError());
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
			THROW_EXCEPTION(0, Csp, NULL, "CryptAcquireContext. Error: 0x%08x", GetLastError());
		}

		if (!CryptGetProvParam(
			hCryptProv,
			PP_LICENSE,
			NULL,
			&cbData,
			0))
		{
			THROW_EXCEPTION(0, Key, NULL, "CryptGetProvParam. Error: 0x%08x", GetLastError());
		}

		pbData = (LPBYTE)malloc(cbData);

		if (!CryptGetProvParam(
			hCryptProv,
			PP_LICENSE,
			pbData,
			&cbData,
			0))
		{
			THROW_EXCEPTION(0, Key, NULL, "CryptGetProvParam. Error: 0x%08x", GetLastError());
		}

		license = new std::string((char *)pbData);

		if (hCryptProv) {
			if (!CryptReleaseContext(hCryptProv, 0)) {
				THROW_EXCEPTION(0, Csp, NULL, "CryptReleaseContext. Error: 0x%08x", GetLastError());
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

Handle<std::string> Csp::getCPCSPVersion() {
	LOGGER_FN();

	try {
#ifdef CSP_ENABLE
		static HCRYPTPROV hCryptProv = 0;
		DWORD cbData = 0;
		DWORD pbData;
		Handle <std::string> res;

		if (!isGost2001CSPAvailable()) {
			THROW_EXCEPTION(0, Key, NULL, "GOST 2001 provaider not available");
		}

		if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_GOST_2001_DH, CRYPT_VERIFYCONTEXT)){
			THROW_EXCEPTION(0, Csp, NULL, "CryptAcquireContext. Error: 0x%08x", GetLastError());
		}

		if (!CryptGetProvParam(
			hCryptProv,
			PP_VERSION,
			NULL,
			&cbData,
			0))
		{
			THROW_EXCEPTION(0, Key, NULL, "CryptGetProvParam. Error: 0x%08x", GetLastError());
		}

		pbData = (DWORD)malloc(cbData);

		if (!CryptGetProvParam(
			hCryptProv,
			PP_VERSION,
			(BYTE *)pbData,
			&cbData,
			0))
		{
			THROW_EXCEPTION(0, Key, NULL, "CryptGetProvParam. Error: 0x%08x", GetLastError());
		}

		res = new std::string((char *)pbData);

		if (hCryptProv) {
			if (!CryptReleaseContext(hCryptProv, 0)) {
				THROW_EXCEPTION(0, Csp, NULL, "CryptReleaseContext. Error: 0x%08x", GetLastError());
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
		THROW_EXCEPTION(0, Csp, e, "Error get cpcsp version");
	}
}

Handle<std::string> Csp::getCPCSPVersionPKZI() {
	LOGGER_FN();

	try {
#ifdef CSP_ENABLE
		static HCRYPTPROV hCryptProv = 0;
		PROV_PP_VERSION_EX *exVersion = NULL;
		DWORD cbData = 0;
		LPBYTE pbData;
		Handle<std::string> res;

		if (!isGost2001CSPAvailable()) {
			THROW_EXCEPTION(0, Key, NULL, "GOST 2001 provaider not available");
		}

		if (!CryptAcquireContext(&hCryptProv, NULL,	NULL, PROV_GOST_2001_DH, CRYPT_VERIFYCONTEXT)){
			THROW_EXCEPTION(0, Csp, NULL, "CryptAcquireContext. Error: 0x%08x", GetLastError());
		}

		if (!CryptGetProvParam(
			hCryptProv,
			PP_VERSION_EX,
			NULL,
			&cbData,
			0))
		{
			THROW_EXCEPTION(0, Key, NULL, "CryptGetProvParam. Error: 0x%08x", GetLastError());
		}

		pbData = (LPBYTE)malloc(cbData);

		if (!CryptGetProvParam(
			hCryptProv,
			PP_VERSION_EX,
			pbData,
			&cbData,
			0))
		{
			THROW_EXCEPTION(0, Key, NULL, "CryptGetProvParam. Error: 0x%08x", GetLastError());
		}

		exVersion = (PROV_PP_VERSION_EX *)pbData;
		res = new std::string(std::to_string(exVersion->PKZI_Build));

		if (hCryptProv) {
			if (!CryptReleaseContext(hCryptProv, 0)) {
				THROW_EXCEPTION(0, Csp, NULL, "CryptReleaseContext. Error: 0x%08x", GetLastError());
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
		THROW_EXCEPTION(0, Csp, e, "Error get cpcsp version");
	}
}

Handle<std::string> Csp::getCPCSPVersionSKZI() {
	LOGGER_FN();

	try {
#ifdef CSP_ENABLE
		static HCRYPTPROV hCryptProv = 0;
		PROV_PP_VERSION_EX *exVersion = NULL;
		DWORD cbData = 0;
		LPBYTE pbData;
		Handle<std::string> res;

		if (!isGost2001CSPAvailable()) {
			THROW_EXCEPTION(0, Key, NULL, "GOST 2001 provaider not available");
		}

		if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_GOST_2001_DH, CRYPT_VERIFYCONTEXT)){
			THROW_EXCEPTION(0, Csp, NULL, "CryptAcquireContext. Error: 0x%08x", GetLastError());
		}

		if (!CryptGetProvParam(
			hCryptProv,
			PP_VERSION_EX,
			NULL,
			&cbData,
			0))
		{
			THROW_EXCEPTION(0, Key, NULL, "CryptGetProvParam. Error: 0x%08x", GetLastError());
		}

		pbData = (LPBYTE)malloc(cbData);

		if (!CryptGetProvParam(
			hCryptProv,
			PP_VERSION_EX,
			pbData,
			&cbData,
			0))
		{
			THROW_EXCEPTION(0, Key, NULL, "CryptGetProvParam. Error: 0x%08x", GetLastError());
		}

		exVersion = (PROV_PP_VERSION_EX *)pbData;
		res = new std::string(std::to_string(exVersion->SKZI_Build));

		if (hCryptProv) {
			if (!CryptReleaseContext(hCryptProv, 0)) {
				THROW_EXCEPTION(0, Csp, NULL, "CryptReleaseContext. Error: 0x%08x", GetLastError());
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
		THROW_EXCEPTION(0, Csp, e, "Error get cpcsp version");
	}
}

Handle<std::string> Csp::getCPCSPSecurityLvl() {
	LOGGER_FN();

	try {
#ifdef CSP_ENABLE
		std::vector<std::string> secureLvl = { { "KC1" }, { "KC2" }, { "KC3" }, { "KB1" }, { "KB2" }, { "KA1" } };
		static HCRYPTPROV hCryptProv = 0;
		Handle<std::string> version;
		DWORD dwVersion[20];
		DWORD dwDataLength = (DWORD)sizeof(dwVersion);

		if (!isGost2001CSPAvailable()) {
			THROW_EXCEPTION(0, Key, NULL, "GOST 2001 provaider not available");
		}

		if (!CryptAcquireContext(&hCryptProv, NULL,	NULL, PROV_GOST_2001_DH, CRYPT_VERIFYCONTEXT)){
			THROW_EXCEPTION(0, Csp, NULL, "CryptAcquireContext. Error: 0x%08x", GetLastError());
		}

		if (!CryptGetProvParam(hCryptProv, PP_SECURITY_LEVEL, (BYTE*)&dwVersion, &dwDataLength, 0)){
			THROW_EXCEPTION(0, Key, NULL, "CryptGetProvParam. Error: 0x%08x", GetLastError());
		}

		version = new std::string(secureLvl[dwVersion[0] - 1]);

		if (hCryptProv) {
			if (!CryptReleaseContext(hCryptProv, 0)) {
				THROW_EXCEPTION(0, Csp, NULL, "CryptReleaseContext. Error: 0x%08x", GetLastError());
			}
		}

		hCryptProv = 0;

		return version;
#else
		THROW_EXCEPTION(0, Csp, NULL, "Only if defined CSP_ENABLE");
#endif
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Csp, e, "Error get cpcsp version");
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
				THROW_EXCEPTION(0, Csp, NULL, "CryptEnumProviders. Error: 0x%08x", GetLastError());
			}

			res.push_back({ (int)dwType, new std::string(pszName) });

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

std::vector<Handle<std::string>> Csp::enumContainers(int provType, Handle<std::string> provName) {
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
			providers.push_back({ provType, provName });
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
				THROW_EXCEPTION(0, Csp, NULL, "CryptAcquireContext. Error: 0x%08x", GetLastError());
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
					THROW_EXCEPTION(0, Csp, NULL, "CryptReleaseContext. Error: 0x%08x", GetLastError());
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

Handle<Certificate> Csp::getCertifiacteFromContainer(Handle<std::string> contName, int provType, Handle<std::string> provName) {
	LOGGER_FN();

#ifdef CSP_ENABLE
	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;
	BYTE* pbCertificate = NULL;
#endif

	try {
#ifdef CSP_ENABLE
		DWORD cbName;
		DWORD dwKeySpec;
		PCCERT_CONTEXT pCertContext;
		HCERTSTORE hCertStore = HCRYPT_NULL;
		X509 *hcert = NULL;
		const unsigned char *p;

		if (contName.isEmpty()) {
			THROW_EXCEPTION(0, Csp, NULL, "container name epmty");
		}

		if (!provType) {
			THROW_EXCEPTION(0, Csp, NULL, "provider type not set");
		}

		if (!CryptAcquireContext(
			&hProv,
			contName->c_str(),
			!provName.isEmpty() && provName->length() ? (LPCSTR)provName->c_str() : NULL,
			provType,
			0))
		{
			THROW_EXCEPTION(0, Csp, NULL, "CryptAcquireContext. Error: 0x%08x", GetLastError());
		}

		if (!CryptGetUserKey(hProv, AT_SIGNATURE, &hKey)) {
			CryptDestroyKey(hKey);

			if (!CryptGetUserKey(hProv, AT_KEYEXCHANGE, &hKey)) {
				THROW_EXCEPTION(0, Csp, NULL, "CryptGetUserKey. Error: 0x%08x", GetLastError());
			}
			else {
				dwKeySpec = AT_KEYEXCHANGE;
			}
		}
		else {
			dwKeySpec = AT_SIGNATURE;
		}

		if (!CryptGetKeyParam(hKey, KP_CERTIFICATE, NULL, &cbName, 0)) {
			DWORD ee = GetLastError();
			THROW_EXCEPTION(0, Csp, NULL, "CryptGetKeyParam. Error: 0x%08x", GetLastError());
		}

		pbCertificate = (BYTE*)malloc(cbName);

		if (!CryptGetKeyParam(hKey, KP_CERTIFICATE, pbCertificate, &cbName, 0)) {
			THROW_EXCEPTION(0, Csp, NULL, "CryptGetKeyParam. Error: 0x%08x", GetLastError());
		}

		if ((pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, pbCertificate, cbName)) == NULL) {
			THROW_EXCEPTION(0, Csp, NULL, "CertCreateCertificateContext. Error: 0x%08x", GetLastError());
		}

		if (pCertContext) {
			p = pCertContext->pbCertEncoded;

			LOGGER_OPENSSL(d2i_X509);
			if (!(hcert = d2i_X509(NULL, &p, pCertContext->cbCertEncoded))) {
				THROW_OPENSSL_EXCEPTION(0, Csp, NULL, "'d2i_X509' Error decode len bytes");
			}
		} else {
			THROW_EXCEPTION(0, Csp, NULL, "Cannot find certificate in store");
		}

		free(pbCertificate);

		if (hKey) {
			CryptDestroyKey(hKey);
			hKey = NULL;
		}

		if (hProv) {
			if (!CryptReleaseContext(hProv, 0)) {
				THROW_EXCEPTION(0, Csp, NULL, "CryptReleaseContext. Error: 0x%08x", GetLastError());
			}

			hProv = NULL;
		}

		return new Certificate(hcert);
#else
		THROW_EXCEPTION(0, Csp, NULL, "Only if defined CSP_ENABLE");
#endif
	}
	catch (Handle<Exception> e){
#ifdef CSP_ENABLE
		free(pbCertificate);

		if (hKey) {
			CryptDestroyKey(hKey);
			hKey = NULL;
		}

		if (hProv) {
			if (!CryptReleaseContext(hProv, 0)) {
				THROW_EXCEPTION(0, Csp, NULL, "CryptReleaseContext. Error: 0x%08x", GetLastError());
			}

			hProv = NULL;
		}
#endif

		THROW_EXCEPTION(0, Csp, e, "Error get certificate from container");
	}
}

void Csp::installCertifiacteFromContainer(Handle<std::string> contName, int provType, Handle<std::string> provName) {
	LOGGER_FN();

#ifdef CSP_ENABLE
	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;
	BYTE* pbCertificate = NULL;
#endif

	try {
#ifdef CSP_ENABLE
		DWORD cbName;
		DWORD dwKeySpec;
		PCCERT_CONTEXT pCertContext;
		HCERTSTORE hCertStore = HCRYPT_NULL;
		CRYPT_KEY_PROV_INFO pKeyInfo = { 0 };

		if (contName.isEmpty()) {
			THROW_EXCEPTION(0, Csp, NULL, "container name epmty");
		}

		if (!provType) {
			THROW_EXCEPTION(0, Csp, NULL, "provider type not set");
		}

		if (!CryptAcquireContext(
			&hProv,
			contName->c_str(),
			!provName.isEmpty() && provName->length() ? (LPCSTR)provName->c_str() : NULL,
			provType,
			0))
		{
			THROW_EXCEPTION(0, Csp, NULL, "CryptAcquireContext. Error: 0x%08x", GetLastError());
		}

		if (!CryptGetUserKey(hProv, AT_SIGNATURE, &hKey)) {
			CryptDestroyKey(hKey);

			if (!CryptGetUserKey(hProv, AT_KEYEXCHANGE, &hKey)) {
				THROW_EXCEPTION(0, Csp, NULL, "CryptGetUserKey. Error: 0x%08x", GetLastError());
			}
			else {
				dwKeySpec = AT_KEYEXCHANGE;
			}
		}
		else {
			dwKeySpec = AT_SIGNATURE;
		}

		if (!CryptGetKeyParam(hKey, KP_CERTIFICATE, NULL, &cbName, 0)) {
			DWORD ee = GetLastError();
			THROW_EXCEPTION(0, Csp, NULL, "CryptGetKeyParam. Error: 0x%08x", GetLastError());
		}

		pbCertificate = (BYTE*)malloc(cbName);

		if (!CryptGetKeyParam(hKey, KP_CERTIFICATE, pbCertificate, &cbName, 0)) {
			THROW_EXCEPTION(0, Csp, NULL, "CryptGetKeyParam. Error: 0x%08x", GetLastError());
		}

		if ((pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, pbCertificate, cbName)) == NULL) {
			THROW_EXCEPTION(0, Csp, NULL, "CertCreateCertificateContext. Error: 0x%08x", GetLastError());
		}

		size_t value_len = strlen(contName->c_str());
		size_t wide_string_len = MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, (LPCSTR)contName->c_str(), value_len, NULL, 0);

		wchar_t* wide_buf = (wchar_t*)LocalAlloc(LMEM_ZEROINIT, (wide_string_len + 1) * sizeof(wchar_t));
		wide_string_len = MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, (LPCSTR)contName->c_str(), value_len, (LPWSTR)wide_buf, wide_string_len);

		pKeyInfo.dwKeySpec = dwKeySpec;
		pKeyInfo.dwProvType = provType;
		pKeyInfo.pwszContainerName = wide_buf;
		pKeyInfo.pwszProvName = !provName.isEmpty() && provName->length() ? (LPWSTR)provName->c_str() : NULL;

		if (!CertSetCertificateContextProperty(
			pCertContext,
			CERT_KEY_PROV_INFO_PROP_ID,
			CERT_STORE_NO_CRYPT_RELEASE_FLAG,
			&pKeyInfo
			))
		{
			THROW_EXCEPTION(0, Csp, NULL, "CertSetCertificateContextProperty: Code: %d", GetLastError());
		};

		if (HCRYPT_NULL == (hCertStore = CertOpenStore(
			CERT_STORE_PROV_SYSTEM,
			X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			HCRYPT_NULL,
			CERT_SYSTEM_STORE_CURRENT_USER,
			L"MY")))
		{
			THROW_EXCEPTION(0, Csp, NULL, "CertOpenStore failed: Code: %d", GetLastError());
		}

		if (!CertAddCertificateContextToStore(
			hCertStore,
			pCertContext,
			CERT_STORE_ADD_REPLACE_EXISTING,
			NULL
			))
		{
			THROW_EXCEPTION(0, Csp, NULL, "CertAddCertificateContextToStore failed. Code: %d", GetLastError())
		}

		if (pCertContext) {
			CertFreeCertificateContext(pCertContext);
			pCertContext = HCRYPT_NULL;
		}

		if (hCertStore) {
			CertCloseStore(hCertStore, 0);
			hCertStore = HCRYPT_NULL;
		}

		free(pbCertificate);

		if (hKey) {
			CryptDestroyKey(hKey);
			hKey = NULL;
		}

		if (hProv) {
			if (!CryptReleaseContext(hProv, 0)) {
				THROW_EXCEPTION(0, Csp, NULL, "CryptReleaseContext. Error: 0x%08x", GetLastError());
			}

			hProv = NULL;
		}

		return;
#else
		THROW_EXCEPTION(0, Csp, NULL, "Only if defined CSP_ENABLE");
#endif
	}
	catch (Handle<Exception> e){
#ifdef CSP_ENABLE
		free(pbCertificate);

		if (hKey) {
			CryptDestroyKey(hKey);
			hKey = NULL;
		}

		if (hProv) {
			if (!CryptReleaseContext(hProv, 0)) {
				THROW_EXCEPTION(0, Csp, NULL, "CryptReleaseContext. Error: 0x%08x", GetLastError());
			}

			hProv = NULL;
		}
#endif

		THROW_EXCEPTION(0, Csp, e, "Error install certificate from container");
	}
}

void Csp::deleteContainer(Handle<std::string> contName, int provType, Handle<std::string> provName) {
	LOGGER_FN();

#ifdef CSP_ENABLE
	HCRYPTPROV hProv = NULL;
#endif

	try {
#ifdef CSP_ENABLE
		if (contName.isEmpty()) {
			THROW_EXCEPTION(0, Csp, NULL, "container name epmty");
		}

		if (!provType) {
			THROW_EXCEPTION(0, Csp, NULL, "provider type not set");
		}

		if (!CryptAcquireContext(
			&hProv,
			contName->c_str(),
			!provName.isEmpty() && provName->length() ? (LPCSTR)provName->c_str() : NULL,
			provType,
			CRYPT_DELETEKEYSET))
		{
			THROW_EXCEPTION(0, Csp, NULL, "CryptAcquireContext. Error: 0x%08x", GetLastError());
		}

		hProv = NULL;

		return;
#else
		THROW_EXCEPTION(0, Csp, NULL, "Only if defined CSP_ENABLE");
#endif
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Csp, e, "Error install certificate from container");
	}
}

Handle<std::string> Csp::getContainerNameByCertificate(Handle<Certificate> cert, Handle<std::string> category){
	LOGGER_FN();

#ifdef CSP_ENABLE
	PCCERT_CONTEXT pCertContext = HCRYPT_NULL;
	PCCERT_CONTEXT pCertFound = HCRYPT_NULL;
	HCERTSTORE hCertStore = HCRYPT_NULL;
	HCRYPTPROV hCryptProv = HCRYPT_NULL;
	HCRYPTKEY hPublicKey = HCRYPT_NULL;
	LPBYTE pbContainerName = HCRYPT_NULL;
	LPBYTE pbFPCert = HCRYPT_NULL;
#endif

	try {
#ifdef CSP_ENABLE
		DWORD cbFPCert;
		DWORD cbContainerName;
		DWORD dwFlags;
		DWORD cbData = 0;
		Handle<std::string> res = new std::string("");

		std::wstring wCategory = std::wstring(category->begin(), category->end());

		pCertContext = createCertificateContext(cert);

		if (HCRYPT_NULL == (hCertStore = CertOpenStore(
			CERT_STORE_PROV_SYSTEM,
			X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			HCRYPT_NULL,
			CERT_SYSTEM_STORE_CURRENT_USER,
			wCategory.c_str())))
		{
			THROW_EXCEPTION(0, Csp, NULL, "CertOpenStore failed: %s Code: %d", category->c_str(), GetLastError());
		}

		if (!findExistingCertificate(pCertFound, hCertStore, pCertContext)) {
			THROW_EXCEPTION(0, Csp, NULL, "Cannot find existing certificate");
		}

		if (!CryptAcquireContext(
			&hCryptProv,
			NULL,
			NULL,
			PROV_GOST_2001_DH,
			CRYPT_VERIFYCONTEXT))
		{
			THROW_EXCEPTION(0, Csp, NULL, "CryptAcquireContext. Error: 0x%08x", GetLastError());
		}

		if (!CryptImportPublicKeyInfo(
			hCryptProv,
			pCertFound->dwCertEncodingType,
			&pCertFound->pCertInfo->SubjectPublicKeyInfo,
			&hPublicKey))
		{
			THROW_EXCEPTION(0, Csp, NULL, "Error during CryptImportPublicKeyInfo. Error: 0x%08x", GetLastError());
		}

		if (!CryptGetKeyParam(hPublicKey, KP_FP, NULL, &cbFPCert, 0))
		{
			THROW_EXCEPTION(0, Csp, NULL, "CryptGetKeyParam. Error: 0x%08x", GetLastError());
		}

		pbFPCert = (LPBYTE)malloc(cbFPCert);

		if (!pbFPCert) {
			THROW_EXCEPTION(0, Csp, NULL, "Fail to allocate memory");
		}

		if (!CryptGetKeyParam(hPublicKey, KP_FP, pbFPCert, &cbFPCert, 0))
		{
			THROW_EXCEPTION(0, Csp, NULL, "CryptGetKeyParam. Error: 0x%08x", GetLastError());
		}


		if (!CryptGetProvParam(hCryptProv, PP_ENUMCONTAINERS, NULL, &cbContainerName, CRYPT_FIRST))
		{
			THROW_EXCEPTION(0, Csp, NULL, "CryptGetProvParam. Error: 0x%08x", GetLastError());
		}

		pbContainerName = (LPBYTE)malloc(cbContainerName);

		if (!pbContainerName) {
			THROW_EXCEPTION(0, Csp, NULL, "Fail to allocate memory");
		}

		dwFlags = CRYPT_FIRST;

		while (CryptGetProvParam(hCryptProv, PP_ENUMCONTAINERS, pbContainerName, &cbContainerName, dwFlags | CRYPT_FQCN))
		{
			if (cmpCertAndContFP((LPCSTR)pbContainerName, pbFPCert, cbFPCert)) {
				res = new std::string((char*)pbContainerName);
				break;
			}

			dwFlags = CRYPT_NEXT;
		}

		if (pCertContext) {
			CertFreeCertificateContext(pCertContext);
			pCertContext = HCRYPT_NULL;
		}

		if (pCertFound) {
			CertFreeCertificateContext(pCertFound);
			pCertFound = HCRYPT_NULL;
		}

		if (pbContainerName) {
			free(pbContainerName);
		}

		if (pbFPCert) {
			free(pbFPCert);
		}

		if (hCertStore) {
			CertCloseStore(hCertStore, 0);
			hCertStore = HCRYPT_NULL;
		}

		if (hPublicKey)
		{
			if (!CryptDestroyKey(hPublicKey))
			{
				THROW_EXCEPTION(0, Csp, NULL, "CryptDestroyKey. Error: 0x%08x", GetLastError());
			}
		}

		if (hCryptProv) {
			if (!CryptReleaseContext(hCryptProv, 0)) {
				THROW_EXCEPTION(0, Csp, NULL, "CryptReleaseContext. Error: 0x%08x", GetLastError());
			}
		}

		return res;

#else
		THROW_EXCEPTION(0, Csp, NULL, "Only if defined CSP_ENABLE");
#endif
	}
	catch (Handle<Exception> e) {
#ifdef CSP_ENABLE
		if (pCertContext) {
			CertFreeCertificateContext(pCertContext);
			pCertContext = HCRYPT_NULL;
		}

		if (pCertFound) {
			CertFreeCertificateContext(pCertFound);
			pCertFound = HCRYPT_NULL;
		}

		if (pbContainerName) {
			free(pbContainerName);
		}

		if (pbFPCert) {
			free(pbFPCert);
		}

		if (hCertStore) {
			CertCloseStore(hCertStore, 0);
			hCertStore = HCRYPT_NULL;
		}

		if (hPublicKey)
		{
			if (!CryptDestroyKey(hPublicKey))
			{
				THROW_EXCEPTION(0, Csp, NULL, "CryptDestroyKey. Error: 0x%08x", GetLastError());
			}
		}

		if (hCryptProv) {
			if (!CryptReleaseContext(hCryptProv, 0)) {
				THROW_EXCEPTION(0, Csp, NULL, "CryptReleaseContext. Error: 0x%08x", GetLastError());
			}
		}
#endif

		THROW_EXCEPTION(0, Csp, e, "Error delete contaiener");
	}
}

#ifdef CSP_ENABLE

PCCERT_CONTEXT Csp::createCertificateContext(Handle<Certificate> cert) {
	LOGGER_FN();

	try {
		PCCERT_CONTEXT pCertContext = HCRYPT_NULL;
		unsigned char *pData = NULL, *p = NULL;
		int iData;

		if (cert->isEmpty()) {
			THROW_OPENSSL_EXCEPTION(0, Csp, NULL, "cert cannot be empty");
		}

		LOGGER_OPENSSL(i2d_X509);
		if ((iData = i2d_X509(cert->internal(), NULL)) <= 0) {
			THROW_OPENSSL_EXCEPTION(0, Csp, NULL, "Error i2d_X509");
		}

		LOGGER_OPENSSL(OPENSSL_malloc);
		if (NULL == (pData = (unsigned char*)OPENSSL_malloc(iData))) {
			THROW_OPENSSL_EXCEPTION(0, Csp, NULL, "Error malloc");
		}

		p = pData;
		LOGGER_OPENSSL(i2d_X509);
		if ((iData = i2d_X509(cert->internal(), &p)) <= 0) {
			THROW_OPENSSL_EXCEPTION(0, Csp, NULL, "Error i2d_X509");
		}

		LOGGER_TRACE("CertCreateCertificateContext");
		if (NULL == (pCertContext = CertCreateCertificateContext(
			X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pData, iData))) {
			THROW_EXCEPTION(0, Csp, NULL, "CertCreateCertificateContext() failed");
		}

		OPENSSL_free(pData);

		return pCertContext;
	}
	catch (Handle<Exception> e) {
		THROW_EXCEPTION(0, Csp, e, "Error create cert context from X509");
	}
}

bool Csp::findExistingCertificate(
	OUT PCCERT_CONTEXT &pOutCertContext,
	IN HCERTSTORE hCertStore,
	IN PCCERT_CONTEXT pCertContext,
	IN DWORD dwFindFlags,
	IN DWORD dwCertEncodingType
	) {

	LOGGER_FN();

	bool res = false;

	try {
		if (!hCertStore) {
			THROW_EXCEPTION(0, Csp, NULL, "certificate store cannot be empty");
		}

		if (!pCertContext) {
			THROW_EXCEPTION(0, Csp, NULL, "certificate context cannot be empty");
		}

		LOGGER_TRACE("CertFindCertificateInStore");
		pOutCertContext = CertFindCertificateInStore(
			hCertStore,
			dwCertEncodingType,
			dwFindFlags,
			CERT_FIND_EXISTING,
			pCertContext,
			NULL
			);

		if (pOutCertContext) {
			res = true;
		}

		return res;
	}
	catch (Handle<Exception> e) {
		THROW_EXCEPTION(0, Csp, e, "Error find certificate in store. Code: %d", GetLastError());
	}
}

CRYPT_KEY_PROV_INFO * Csp::getCertificateContextProperty(
	IN PCCERT_CONTEXT pCertContext,
	IN DWORD dwPropId) {

	LOGGER_FN();

	try {
		DWORD dwSize = 0;

		LOGGER_TRACE("CertGetCertificateContextProperty");
		if (!CertGetCertificateContextProperty(pCertContext, dwPropId, NULL, &dwSize)) {
			THROW_EXCEPTION(0, Csp, NULL, "CertGetCertificateContextProperty(NULL) failed. Code: %d", GetLastError());
		}

		CRYPT_KEY_PROV_INFO *pinfo = (CRYPT_KEY_PROV_INFO *)malloc(dwSize);

		LOGGER_TRACE("CertGetCertificateContextProperty");
		if (!CertGetCertificateContextProperty(pCertContext, dwPropId, pinfo, &dwSize))
		{
			LOGGER_OPENSSL(OPENSSL_free);
			OPENSSL_free(pinfo);
			THROW_EXCEPTION(0, Csp, NULL, "CertGetCertificateContextProperty(NULL) failed. Code: %d", GetLastError());
		}

		return pinfo;
	}
	catch (Handle<Exception> e) {
		THROW_EXCEPTION(0, Csp, e, "Error get certificate context property");
	}
}

bool Csp::cmpCertAndContFP(LPCSTR szContainerName, LPBYTE pbFPCert, DWORD cbFPCert) {
	LOGGER_FN();

	try {
		HCRYPTPROV hProvCont = HCRYPT_NULL;
		LPBYTE pbFPCont;
		DWORD cbFPCont;
		BOOL result = FALSE;

		if (!CryptAcquireContext(
			&hProvCont,
			szContainerName,
			NULL,
			PROV_GOST_2012_256,
			CRYPT_VERIFYCONTEXT))
		{
			THROW_EXCEPTION(0, Csp, NULL, "CryptAcquireContext. Error: 0x%08x", GetLastError());
		}

		cbFPCont = cbFPCert;
		pbFPCont = (LPBYTE)malloc(cbFPCont);

		if (CryptGetProvParam(hProvCont, PP_SIGNATURE_KEY_FP, pbFPCont, &cbFPCont, 0)) {
			if (!memcmp(pbFPCont, pbFPCert, cbFPCert)) {
				result = TRUE;
				goto Done;
			}
		}

		if (CryptGetProvParam(hProvCont, PP_EXCHANGE_KEY_FP, pbFPCont, &cbFPCont, 0)) {
			if (!memcmp(pbFPCont, pbFPCert, cbFPCert)) {
				result = TRUE;
				goto Done;
			}
		}

	Done:
		if (pbFPCont) {
			free(pbFPCont);
		}

		if (hProvCont)
		{
			if (!CryptReleaseContext(hProvCont, 0))
			{
				THROW_EXCEPTION(0, Csp, NULL, "CryptReleaseContext. Error: 0x%08x", GetLastError());
			}
		}

		return result;
	}
	catch (Handle<Exception> e) {
		THROW_EXCEPTION(0, Csp, e, "Error compare cert and container FP");
	}
}

#endif //CSP_ENABLE
