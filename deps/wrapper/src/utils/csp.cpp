#include "../stdafx.h"

#include "wrapper/utils/csp.h"

#ifdef CSP_ENABLE

bool Csp::isGost2001CSPAvailable() {
	LOGGER_FN();

	try {
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
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Csp, e, "Error check GOST 2001 provaider");
	}
}

bool Csp::isGost2012_256CSPAvailable() {
	LOGGER_FN();

	try {
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
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Csp, e, "Error check GOST 2001 provaider");
	}
}

bool Csp::isGost2012_512CSPAvailable() {
	LOGGER_FN();

	try {
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
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Csp, e, "Error check GOST 2001 provaider");
	}
}

bool Csp::checkCPCSPLicense() {
	LOGGER_FN();

	static HCRYPTPROV hCryptProv = 0;
	LPBYTE pbData;

	try {
		DWORD cbData = 0;
		bool res = false;

		if (!isGost2001CSPAvailable()) {
			THROW_EXCEPTION(0, Csp, NULL, "GOST 2001 provaider not available");
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
			THROW_EXCEPTION(0, Csp, NULL, "CryptGetProvParam. Error: 0x%08x", GetLastError());
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
	}
	catch (Handle<Exception> e){
		if (hCryptProv) {
			CryptReleaseContext(hCryptProv, 0);
			hCryptProv = 0;
		}

		if (pbData) {
			free((BYTE*)pbData);
		}

		THROW_EXCEPTION(0, Csp, e, "Error check cpcsp license");
	}
}

Handle<std::string> Csp::getCPCSPLicense() {
	LOGGER_FN();

	static HCRYPTPROV hCryptProv = 0;
	LPBYTE pbData;

	try {
		DWORD cbData = 0;
		Handle<std::string> license;

		if (!isGost2001CSPAvailable()) {
			THROW_EXCEPTION(0, Csp, NULL, "GOST 2001 provaider not available");
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
			THROW_EXCEPTION(0, Csp, NULL, "CryptGetProvParam. Error: 0x%08x", GetLastError());
		}

		pbData = (LPBYTE)malloc(cbData);

		if (!CryptGetProvParam(
			hCryptProv,
			PP_LICENSE,
			pbData,
			&cbData,
			0))
		{
			THROW_EXCEPTION(0, Csp, NULL, "CryptGetProvParam. Error: 0x%08x", GetLastError());
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
	}
	catch (Handle<Exception> e){
		if (hCryptProv) {
			CryptReleaseContext(hCryptProv, 0);
			hCryptProv = 0;
		}

		if (pbData) {
			free((BYTE*)pbData);
		}

		THROW_EXCEPTION(0, Csp, e, "Error get cpcsp license");
	}
}

Handle<std::string> Csp::getCPCSPVersion() {
	LOGGER_FN();

	static HCRYPTPROV hCryptProv = 0;

	try {
		DWORD pbData = 0;
		DWORD cbData = (DWORD)sizeof(pbData);

		Handle <std::string> res;

		if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_GOST_2001_DH, CRYPT_VERIFYCONTEXT)){
			THROW_EXCEPTION(0, Csp, NULL, "CryptAcquireContext. Error: 0x%08x", GetLastError());
		}

		if (!CryptGetProvParam(
			hCryptProv,
			PP_VERSION,
			(BYTE*)&pbData,
			&cbData,
			0))
		{
			THROW_EXCEPTION(0, Csp, NULL, "CryptGetProvParam. Error: 0x%08x", GetLastError());
		}

		res = new std::string(std::to_string(((pbData >> 8) & 0xFF)) + "." + std::to_string((0xFF & pbData)));

		if (hCryptProv) {
			if (!CryptReleaseContext(hCryptProv, 0)) {
				THROW_EXCEPTION(0, Csp, NULL, "CryptReleaseContext. Error: 0x%08x", GetLastError());
			}
		}

		hCryptProv = 0;

		return res;
	}
	catch (Handle<Exception> e){
		if (hCryptProv) {
			CryptReleaseContext(hCryptProv, 0);
			hCryptProv = 0;
		}

		THROW_EXCEPTION(0, Csp, e, "Error get cpcsp version");
	}
}

Handle<std::string> Csp::getCPCSPVersionPKZI() {
	LOGGER_FN();

	static HCRYPTPROV hCryptProv = 0;
	LPBYTE pbData;

	try {
		PROV_PP_VERSION_EX *exVersion = NULL;
		DWORD cbData = 0;
		Handle<std::string> res;

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
			THROW_EXCEPTION(0, Csp, NULL, "CryptGetProvParam. Error: 0x%08x", GetLastError());
		}

		pbData = (LPBYTE)malloc(cbData);

		if (!CryptGetProvParam(
			hCryptProv,
			PP_VERSION_EX,
			pbData,
			&cbData,
			0))
		{
			THROW_EXCEPTION(0, Csp, NULL, "CryptGetProvParam. Error: 0x%08x", GetLastError());
		}

		exVersion = (PROV_PP_VERSION_EX *)pbData;
		if (exVersion) {
			res = new std::string(std::to_string(exVersion->PKZI_Build));
		}

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
	}
	catch (Handle<Exception> e){
		if (hCryptProv) {
			CryptReleaseContext(hCryptProv, 0);
			hCryptProv = 0;
		}

		if (pbData) {
			free((BYTE*)pbData);
		}

		THROW_EXCEPTION(0, Csp, e, "Error get cpcsp version");
	}
}

Handle<std::string> Csp::getCPCSPVersionSKZI() {
	LOGGER_FN();

	static HCRYPTPROV hCryptProv = 0;
	LPBYTE pbData;

	try {
		PROV_PP_VERSION_EX *exVersion = NULL;
		DWORD cbData = 0;
		Handle<std::string> res;

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
			THROW_EXCEPTION(0, Csp, NULL, "CryptGetProvParam. Error: 0x%08x", GetLastError());
		}

		pbData = (LPBYTE)malloc(cbData);

		if (!CryptGetProvParam(
			hCryptProv,
			PP_VERSION_EX,
			pbData,
			&cbData,
			0))
		{
			THROW_EXCEPTION(0, Csp, NULL, "CryptGetProvParam. Error: 0x%08x", GetLastError());
		}

		exVersion = (PROV_PP_VERSION_EX *)pbData;
		if (exVersion) {
			res = new std::string(std::to_string(exVersion->SKZI_Build));
		}

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
	}
	catch (Handle<Exception> e){
		if (hCryptProv) {
			CryptReleaseContext(hCryptProv, 0);
			hCryptProv = 0;
		}

		if (pbData) {
			free((BYTE*)pbData);
		}

		THROW_EXCEPTION(0, Csp, e, "Error get cpcsp version");
	}
}

Handle<std::string> Csp::getCPCSPSecurityLvl() {
	LOGGER_FN();

	static HCRYPTPROV hCryptProv = 0;

	try {
		std::vector<std::string> secureLvl = { { "KC1" }, { "KC2" }, { "KC3" }, { "KB1" }, { "KB2" }, { "KA1" } };
		Handle<std::string> version;
		DWORD dwVersion[20];
		DWORD dwDataLength = (DWORD)sizeof(dwVersion);

		if (!isGost2001CSPAvailable()) {
			THROW_EXCEPTION(0, Csp, NULL, "GOST 2001 provaider not available");
		}

		if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_GOST_2001_DH, CRYPT_VERIFYCONTEXT)){
			THROW_EXCEPTION(0, Csp, NULL, "CryptAcquireContext. Error: 0x%08x", GetLastError());
		}

		if (!CryptGetProvParam(hCryptProv, PP_SECURITY_LEVEL, (BYTE*)&dwVersion, &dwDataLength, 0)){
			THROW_EXCEPTION(0, Csp, NULL, "CryptGetProvParam. Error: 0x%08x", GetLastError());
		}

		version = new std::string(secureLvl[dwVersion[0] - 1]);

		if (hCryptProv) {
			if (!CryptReleaseContext(hCryptProv, 0)) {
				THROW_EXCEPTION(0, Csp, NULL, "CryptReleaseContext. Error: 0x%08x", GetLastError());
			}
		}

		hCryptProv = 0;

		return version;
	}
	catch (Handle<Exception> e){
		if (hCryptProv) {
			CryptReleaseContext(hCryptProv, 0);
			hCryptProv = 0;
		}

		THROW_EXCEPTION(0, Csp, e, "Error get cpcsp version");
	}
}

std::vector<ProviderProps> Csp::enumProviders() {
	LOGGER_FN();

	LPTSTR pszName;

	try {
		std::vector<ProviderProps> res;
		DWORD dwIndex = 0;
		DWORD dwType;
		DWORD cbName;

		while (CryptEnumProviders(dwIndex, NULL, 0, &dwType, NULL, &cbName))
		{
			if (!cbName)
				break;

			pszName = (LPTSTR)malloc(cbName);

			if (!CryptEnumProviders(dwIndex++, NULL, NULL, &dwType, pszName, &cbName)) {
				THROW_EXCEPTION(0, Csp, NULL, "CryptEnumProviders. Error: 0x%08x", GetLastError());
			}

			res.push_back({ (int)dwType, new std::string(pszName) });

			free(pszName);
		}

		return res;
	}
	catch (Handle<Exception> e){
		if (pszName) {
			free(pszName);
		}

		THROW_EXCEPTION(0, Csp, e, "Error enum providers");
	}
}

std::vector<Handle<ContainerName>> Csp::enumContainers(int provType, Handle<std::string> provName) {
	LOGGER_FN();

	try {
		std::vector<Handle<ContainerName>> res;
		std::vector<ProviderProps> providers;
		HCRYPTPROV hProv = 0;
		HCRYPTPROV hProvCont = 0;
		DWORD dwIndex = 0;
		DWORD dwType;
		LPTSTR pszName;
		DWORD dwFlags = CRYPT_FIRST;
		char* pszContainerName = NULL;
		char* containerName = NULL;
		BYTE* pbData = NULL;
		DWORD cbName;
		WCHAR wzContName[MAX_PATH];
		DWORD cbData = 0;

		if (!provType) {
			providers = this->enumProviders();
		}
		else {
			providers.push_back({ provType, provName });
		}

		if (!providers.size()) {
			THROW_EXCEPTION(0, Csp, NULL, "Empty providers list");
		}

		for (size_t i = 0; i < providers.size(); i++) {
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

				Handle<ContainerName> item = new ContainerName();

				pbData = (BYTE*)malloc(cbName);

				if (!pbData) {
					THROW_EXCEPTION(0, Csp, NULL, "malloc failure");
				}

				if (!CryptGetProvParam(hProv, PP_ENUMCONTAINERS, pbData, &cbName, dwFlags | CRYPT_UNIQUE)) {
					free((void*)pbData);
					pbData = NULL;
					break;
				}

				pszContainerName = (char*)pbData;
				item->unique = new std::string(pszContainerName);

				if (!CryptAcquireContext(
					&hProvCont,
					pszContainerName,
					NULL,
					provider.type,
					CRYPT_VERIFYCONTEXT))
				{
					THROW_EXCEPTION(0, Csp, NULL, "CryptAcquireContext. Error: 0x%08x", GetLastError());
				}

				if (!CryptGetProvParam(hProvCont, PP_FQCN, NULL, &cbData, 0)){
					THROW_EXCEPTION(0, Csp, NULL, "CryptGetProvParam. Error: 0x%08x", GetLastError());
				}

				pbData = (LPBYTE)malloc(cbData);

				if (!CryptGetProvParam(hProvCont, PP_FQCN, pbData, &cbData, 0)){
					THROW_EXCEPTION(0, Csp, NULL, "CryptGetProvParam. Error: 0x%08x", GetLastError());
				}

				item->fqcnA = new std::string((char*)pbData);

				if (mbstowcs(wzContName, (char*)pbData, MAX_PATH) <= 0) {
					THROW_EXCEPTION(0, Csp, NULL, "mbstowcs failed");
				}

				item->fqcnW = new std::wstring(wzContName);

				if (!CryptGetProvParam(hProvCont, PP_CONTAINER, NULL, &cbData, 0)){
					THROW_EXCEPTION(0, Csp, NULL, "CryptGetProvParam. Error: 0x%08x", GetLastError());
				}

				pbData = (LPBYTE)malloc(cbData);

				if (!CryptGetProvParam(hProvCont, PP_CONTAINER, pbData, &cbData, 0)){
					THROW_EXCEPTION(0, Csp, NULL, "CryptGetProvParam. Error: 0x%08x", GetLastError());
				}

				containerName = (char *)pbData;

				size_t value_len = strlen(containerName);
				size_t wide_string_len = MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, (LPCSTR)containerName, value_len, NULL, 0);
				if (!wide_string_len) {
					THROW_EXCEPTION(0, Csp, NULL, "MultiByteToWideChar() failed");
				}

				wchar_t* wide_buf = (wchar_t*)LocalAlloc(LMEM_ZEROINIT, (wide_string_len + 1) * sizeof(wchar_t));
				wide_string_len = MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, (LPCSTR)containerName, value_len, (LPWSTR)wide_buf, wide_string_len);

				if (!wide_string_len) {
					LocalFree(wide_buf);
					THROW_EXCEPTION(0, Csp, NULL, "MultiByteToWideChar() failed");
				}

				item->container = new std::wstring(wide_buf);

				res.push_back(item);

				pszContainerName = NULL;
				free((void*)pbData);

				dwFlags = CRYPT_NEXT;
			}

			if (hProv) {
				if (!CryptReleaseContext(hProv, 0)) {
					THROW_EXCEPTION(0, Csp, NULL, "CryptReleaseContext. Error: 0x%08x", GetLastError());
				}
			}

			if (hProvCont) {
				if (!CryptReleaseContext(hProvCont, 0)) {
					THROW_EXCEPTION(0, Csp, NULL, "CryptReleaseContext. Error: 0x%08x", GetLastError());
				}
			}

			if (pbData) {
				free((BYTE*)pbData);
			}
		}

		return res;
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Csp, e, "Error enum containers");
	}
}

Handle<Certificate> Csp::getCertificateFromContainer(Handle<std::string> contName, int provType, Handle<std::string> provName) {
	LOGGER_FN();

	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;
	BYTE* pbCertificate = NULL;

	try {
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

		p = pCertContext->pbCertEncoded;

		LOGGER_OPENSSL(d2i_X509);
		if (!(hcert = d2i_X509(NULL, &p, pCertContext->cbCertEncoded))) {
			THROW_OPENSSL_EXCEPTION(0, Csp, NULL, "'d2i_X509' Error decode len bytes");
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
	}
	catch (Handle<Exception> e){
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

		THROW_EXCEPTION(0, Csp, e, "Error get certificate from container");
	}
}

void Csp::installCertificateFromContainer(Handle<std::string> contName, int provType, Handle<std::string> provName) {
	LOGGER_FN();

	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;
	BYTE* pbCertificate = NULL;

	try {
		DWORD cbName;
		DWORD dwKeySpec, dwSize;
		PCCERT_CONTEXT pCertContext;
		HCERTSTORE hCertStore = HCRYPT_NULL;
		CRYPT_KEY_PROV_INFO pKeyInfo = { 0 };
		DWORD dwNewProvType = 0;
		ALG_ID dwAlgId = 0;
		WCHAR wzContName[MAX_PATH];

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

		if (mbstowcs(wzContName, contName->c_str(), MAX_PATH) <= 0) {
			THROW_EXCEPTION(0, Csp, NULL, "mbstowcs failed");
		}

		dwSize = sizeof(dwAlgId);
		if (!CryptGetKeyParam(hKey, KP_ALGID, (LPBYTE)&dwAlgId, &dwSize, 0)) {
			THROW_EXCEPTION(0, Csp, NULL, "CryptGetKeyParam. Error: 0x%08x", GetLastError());
		}

		switch (dwAlgId) {
		case CALG_GR3410EL:
		case CALG_DH_EL_SF:
			dwNewProvType = PROV_GOST_2001_DH;
			break;

#if defined(PROV_GOST_2012_256)
		case CALG_GR3410_12_256:
		case CALG_DH_GR3410_12_256_SF:
			dwNewProvType = PROV_GOST_2012_256;
			break;

		case CALG_GR3410_12_512:
		case CALG_DH_GR3410_12_512_SF:
			dwNewProvType = PROV_GOST_2012_512;
			break;
#endif // PROV_GOST_2012_256

#if defined(CALG_ECDSA) && defined(CALG_ECDH)
		case CALG_ECDSA:
		case CALG_ECDH:
			dwNewProvType = PROV_EC_ECDSA_FULL;
			break;
#endif // defined(CALG_ECDSA) && defined(CALG_ECDH)

#if defined(CALG_RSA_SIGN) && defined(CALG_RSA_KEYX)
		case CALG_RSA_SIGN:
		case CALG_RSA_KEYX:
			dwNewProvType = PROV_RSA_AES;
			break;
#endif // defined(CALG_ECDSA) && defined(CALG_ECDH)

		default:
			THROW_EXCEPTION(0, Csp, NULL, "Unsupported container key type", GetLastError());
			break;
		}

		pKeyInfo.dwKeySpec = dwKeySpec;
		pKeyInfo.dwProvType = dwNewProvType;
		pKeyInfo.pwszContainerName = wzContName;
		pKeyInfo.pwszProvName = (LPWSTR)provTypeToProvNameW(dwNewProvType);

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

		CertFreeCertificateContext(pCertContext);
		pCertContext = HCRYPT_NULL;

		CertCloseStore(hCertStore, 0);
		hCertStore = HCRYPT_NULL;

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
	}
	catch (Handle<Exception> e){
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

		THROW_EXCEPTION(0, Csp, e, "Error install certificate from container");
	}
}

void Csp::installCertificateToContainer(Handle<Certificate> cert, Handle<std::string> contName, int provType, Handle<std::string> provName) {
	LOGGER_FN();

	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;

	try {
		DWORD dwKeySpec;
		PCCERT_CONTEXT pCertContext;

		if (contName.isEmpty()) {
			THROW_EXCEPTION(0, Csp, NULL, "container name epmty");
		}

		if (!provType) {
			THROW_EXCEPTION(0, Csp, NULL, "provider type not set");
		}

		if (cert.isEmpty()) {
			THROW_EXCEPTION(0, Csp, NULL, "cert empty");
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

		pCertContext = createCertificateContext(cert);

		if (!CryptSetKeyParam(hKey, KP_CERTIFICATE, pCertContext->pbCertEncoded, 0)) {
			DWORD ee = GetLastError();
			THROW_EXCEPTION(0, Csp, NULL, "CryptSetKeyParam. Error: 0x%08x", GetLastError());
		}

		CertFreeCertificateContext(pCertContext);
		pCertContext = HCRYPT_NULL;

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
	}
	catch (Handle<Exception> e){
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

		THROW_EXCEPTION(0, Csp, e, "Error install certificate from container");
	}
}

void Csp::deleteContainer(Handle<std::string> contName, int provType, Handle<std::string> provName) {
	LOGGER_FN();

	HCRYPTPROV hProv = NULL;

	try {
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
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Csp, e, "Error install certificate from container");
	}
}

Handle<std::string> Csp::getContainerNameByCertificate(Handle<Certificate> cert, Handle<std::string> category){
	LOGGER_FN();

	PCCERT_CONTEXT pCertContext = HCRYPT_NULL;
	HCRYPTPROV hCryptProv = HCRYPT_NULL;
	HCRYPTKEY hPublicKey = HCRYPT_NULL;
	LPBYTE pbContainerName = HCRYPT_NULL;
	LPBYTE pbFPCert = HCRYPT_NULL;

	try {
		DWORD cbFPCert;
		DWORD cbContainerName;
		DWORD dwFlags;
		DWORD cbData = 0;
		Handle<std::string> res = new std::string("");

		std::wstring wCategory = std::wstring(category->begin(), category->end());

		pCertContext = createCertificateContext(cert);

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
			pCertContext->dwCertEncodingType,
			&pCertContext->pCertInfo->SubjectPublicKeyInfo,
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

		free(pbContainerName);
		free(pbFPCert);

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
	}
	catch (Handle<Exception> e) {
		if (pCertContext) {
			CertFreeCertificateContext(pCertContext);
			pCertContext = HCRYPT_NULL;
		}

		free(pbContainerName);
		free(pbFPCert);

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

		THROW_EXCEPTION(0, Csp, e, "Error get containerName by Certificate");
	}
}

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

Handle<CertificateCollection> Csp::buildChain(Handle<Certificate> cert){
	LOGGER_FN();

	try{
		Handle<CertificateCollection> chain = new CertificateCollection();

		PCCERT_CONTEXT pCertCtx = createCertificateContext(cert);

		CERT_CHAIN_PARA chainPara;
		PCCERT_CHAIN_CONTEXT pChainContext = NULL;

		memset(&chainPara, 0, sizeof(chainPara));
		chainPara.cbSize = sizeof(chainPara);

		if (!CertGetCertificateChain(
			NULL,
			pCertCtx,
			NULL,
			NULL,
			&chainPara,
			CERT_CHAIN_CACHE_END_CERT | CERT_CHAIN_REVOCATION_CHECK_CHAIN,
			NULL,
			&pChainContext)) {

			if (pChainContext) {
				CertFreeCertificateChain(pChainContext);
			}

			chain->push(cert);

			return chain;
		}

		PCERT_SIMPLE_CHAIN first_chain = pChainContext->rgpChain[0];
		DWORD num_elements = first_chain->cElement;
		PCERT_CHAIN_ELEMENT *element = first_chain->rgpElement;

		X509 *xcert = NULL;
		const unsigned char *p;

		for (DWORD i = 0; i < num_elements; ++i) {
			PCCERT_CONTEXT pCertContext = element[i]->pCertContext;

			if (pCertContext){
				p = pCertContext->pbCertEncoded;

				LOGGER_OPENSSL(d2i_X509);
				if (!(xcert = d2i_X509(NULL, &p, pCertContext->cbCertEncoded))) {
					THROW_OPENSSL_EXCEPTION(0, Csp, NULL, "'d2i_X509' Error decode len bytes");
				}

				chain->push(new Certificate(xcert));
			}
		}

		if (pCertCtx) {
			CertFreeCertificateContext(pCertCtx);
		}

		if (pChainContext) {
			CertFreeCertificateChain(pChainContext);
		}

		return chain;
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Csp, e, "Error build chain (certificate collection)");
	}
}

bool Csp::verifyCertificateChain(Handle<Certificate> cert){
	LOGGER_FN();

	try{
		CERT_CHAIN_POLICY_PARA policyPara;
		CERT_CHAIN_POLICY_STATUS policyStatus;

		CERT_CHAIN_PARA	 chainPara;
		PCCERT_CHAIN_CONTEXT pChainContext = NULL;
		bool bResult = false;

		PCCERT_CONTEXT pCertCtx = createCertificateContext(cert);

		memset(&chainPara, 0, sizeof(chainPara));
		chainPara.cbSize = sizeof(chainPara);

		if (!CertGetCertificateChain(
			NULL,
			pCertCtx,
			NULL,
			NULL,
			&chainPara,
			CERT_CHAIN_CACHE_END_CERT | CERT_CHAIN_REVOCATION_CHECK_CHAIN,
			NULL,
			&pChainContext)) {
			goto Finish;
		}

		memset(&policyPara, 0, sizeof(policyPara));
		policyPara.cbSize = sizeof(policyPara);

		memset(&policyStatus, 0, sizeof(policyStatus));
		policyStatus.cbSize = sizeof(policyStatus);

		if (!CertVerifyCertificateChainPolicy(
			CERT_CHAIN_POLICY_BASE,
			pChainContext,
			&policyPara,
			&policyStatus)) {
			goto Finish;
		}

		if (policyStatus.dwError) {
			goto Finish;
		}

		bResult = true;

	Finish:
		if (pChainContext) {
			CertFreeCertificateChain(pChainContext);
		}

		if (pCertCtx) {
			CertFreeCertificateContext(pCertCtx);
		}

		return bResult;
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Csp, e, "Error verify chain (provider store)");
	}
}

bool Csp::isHaveExportablePrivateKey(Handle<Certificate> cert) {
	LOGGER_FN();

	HCERTSTORE hTempStore = HCRYPT_NULL;
	HCERTSTORE hCertStore = HCRYPT_NULL;
	PCCERT_CONTEXT pCertFound = HCRYPT_NULL;
	PCCERT_CONTEXT pCertContext = HCRYPT_NULL;

	try {
		bool res = false;

		if (HCRYPT_NULL == (hCertStore = CertOpenStore(
			CERT_STORE_PROV_SYSTEM,
			X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			HCRYPT_NULL,
			CERT_SYSTEM_STORE_CURRENT_USER,
			L"MY")))
		{
			THROW_EXCEPTION(0, ProviderMicrosoft, NULL, "CertOpenStore failed");
		}

		pCertContext = createCertificateContext(cert);

		if (!findExistingCertificate(pCertFound, hCertStore, pCertContext)) {
			THROW_EXCEPTION(0, ProviderMicrosoft, NULL, "Cannot find existing certificate");
		}

		if (!(hTempStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, NULL, CERT_STORE_CREATE_NEW_FLAG, NULL))) {
			THROW_EXCEPTION(0, Csp, NULL, "CertOpenStore failed");
		}

		if (CertAddCertificateContextToStore(hTempStore, pCertFound, CERT_STORE_ADD_NEW, NULL)) {
			CRYPT_DATA_BLOB bDataBlob = { 0, NULL };
			if (PFXExportCertStoreEx(hTempStore, &bDataBlob, NULL, NULL, EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY)) {
				bDataBlob.pbData = (BYTE *)malloc(bDataBlob.cbData);

				if (PFXExportCertStoreEx(hTempStore, &bDataBlob, NULL, NULL, EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY)) {
					res = true;
				}

				if (bDataBlob.pbData) {
					free((BYTE*)bDataBlob.pbData);
				}
			}
		}

		if (pCertFound) {
			CertFreeCertificateContext(pCertFound);
			pCertFound = HCRYPT_NULL;
		}

		if (pCertContext) {
			CertFreeCertificateContext(pCertContext);
			pCertContext = HCRYPT_NULL;
		}

		if (hTempStore) {
			CertCloseStore(hTempStore, 0);
			hTempStore = HCRYPT_NULL;
		}

		if (hCertStore) {
			CertCloseStore(hCertStore, 0);
			hCertStore = HCRYPT_NULL;
		}

		return res;
	}
	catch (Handle<Exception> e) {
		if (pCertFound) {
			CertFreeCertificateContext(pCertFound);
		}

		if (pCertContext) {
			CertFreeCertificateContext(pCertContext);
		}

		if (hTempStore) {
			CertCloseStore(hTempStore, 0);
			hTempStore = HCRYPT_NULL;
		}

		if (hCertStore) {
			CertCloseStore(hCertStore, 0);
			hCertStore = HCRYPT_NULL;
		}

		return false;
	}
}

Handle<Pkcs12> Csp::certToPkcs12(Handle<Certificate> cert, bool exportPrivateKey, Handle<std::string> password) {
	LOGGER_FN();

	HCERTSTORE hTempStore = HCRYPT_NULL;
	HCERTSTORE hCertStore = HCRYPT_NULL;
	PCCERT_CONTEXT pCertFound = HCRYPT_NULL;
	PCCERT_CONTEXT pCertContext = HCRYPT_NULL;

	try {
		DWORD dwFlags = NULL;
		PKCS12 *p12 = NULL;
		Handle<Pkcs12> resP12;
		WCHAR wPassword[MAX_PATH];

		if (exportPrivateKey) {
			dwFlags = EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY;
		}

		if (!password.isEmpty()) {
			if (mbstowcs(wPassword, password->c_str(), MAX_PATH) <= 0) {
				THROW_EXCEPTION(0, Csp, NULL, "mbstowcs failed");
			}
		}

		if (HCRYPT_NULL == (hCertStore = CertOpenStore(
			CERT_STORE_PROV_SYSTEM,
			X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			HCRYPT_NULL,
			CERT_SYSTEM_STORE_CURRENT_USER,
			L"MY")))
		{
			THROW_EXCEPTION(0, ProviderMicrosoft, NULL, "CertOpenStore failed");
		}

		pCertContext = createCertificateContext(cert);

		if (!findExistingCertificate(pCertFound, hCertStore, pCertContext)) {
			THROW_EXCEPTION(0, ProviderMicrosoft, NULL, "Cannot find existing certificate");
		}

		if (!(hTempStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, NULL, CERT_STORE_CREATE_NEW_FLAG, NULL))) {
			THROW_EXCEPTION(0, Csp, NULL, "CertOpenStore failed");
		}

		if (CertAddCertificateContextToStore(hTempStore, pCertFound, CERT_STORE_ADD_NEW, NULL)) {
			CRYPT_DATA_BLOB bDataBlob = { 0, NULL };
			if (PFXExportCertStoreEx(hTempStore, &bDataBlob, wPassword, NULL, dwFlags)) {
				bDataBlob.pbData = (BYTE *)malloc(bDataBlob.cbData);

				if (PFXExportCertStoreEx(hTempStore, &bDataBlob, wPassword, NULL, dwFlags)) {
					const unsigned char *p = bDataBlob.pbData;

					LOGGER_OPENSSL(d2i_PKCS12);
					p12 = d2i_PKCS12(NULL, &p, bDataBlob.cbData);
					resP12 = new Pkcs12(p12);
				}

				if (bDataBlob.pbData) {
					free((BYTE*)bDataBlob.pbData);
				}
			}
		}

		if (pCertFound) {
			CertFreeCertificateContext(pCertFound);
			pCertFound = HCRYPT_NULL;
		}

		if (pCertContext) {
			CertFreeCertificateContext(pCertContext);
			pCertContext = HCRYPT_NULL;
		}

		if (hTempStore) {
			CertCloseStore(hTempStore, 0);
			hTempStore = HCRYPT_NULL;
		}

		if (hCertStore) {
			CertCloseStore(hCertStore, 0);
			hCertStore = HCRYPT_NULL;
		}

		return resP12;
	}
	catch (Handle<Exception> e) {
		if (pCertFound) {
			CertFreeCertificateContext(pCertFound);
		}

		if (pCertContext) {
			CertFreeCertificateContext(pCertContext);
		}

		if (hTempStore) {
			CertCloseStore(hTempStore, 0);
			hTempStore = HCRYPT_NULL;
		}

		if (hCertStore) {
			CertCloseStore(hCertStore, 0);
			hCertStore = HCRYPT_NULL;
		}

		THROW_EXCEPTION(0, Csp, e, "Error create pkcs12 by certificate");
	}
}

void Csp::importPkcs12(Handle<Pkcs12> p12, Handle<std::string> password) {
	LOGGER_FN();

	HCERTSTORE hCertStore = HCRYPT_NULL;
	HCERTSTORE hImportCertStore = HCRYPT_NULL;
	PCCERT_CONTEXT pCertContext = HCRYPT_NULL;

	try {
		CRYPT_DATA_BLOB bDataBlob = { 0, NULL };
		WCHAR wPassword[MAX_PATH];
		DWORD dwSize = 0;
		unsigned char *pData = NULL, *p = NULL;
		const unsigned char *pCert;
		int iData;
		X509 *xcert = NULL;
		wchar_t *storeName = L"MY";

		if (p12->isEmpty()) {
			THROW_OPENSSL_EXCEPTION(0, Csp, NULL, "p12 cannot be empty");
		}

		if (!password.isEmpty()) {
			if (mbstowcs(wPassword, password->c_str(), MAX_PATH) <= 0) {
				THROW_EXCEPTION(0, Csp, NULL, "mbstowcs failed");
			}
		}

		LOGGER_OPENSSL(i2d_PKCS12);
		if ((iData = i2d_PKCS12(p12->internal(), NULL)) <= 0) {
			THROW_OPENSSL_EXCEPTION(0, Csp, NULL, "Error i2d_PKCS12");
		}

		LOGGER_OPENSSL(OPENSSL_malloc);
		if (NULL == (pData = (unsigned char*)OPENSSL_malloc(iData))) {
			THROW_OPENSSL_EXCEPTION(0, Csp, NULL, "Error malloc");
		}

		p = pData;
		LOGGER_OPENSSL(i2d_PKCS12);
		if ((iData = i2d_PKCS12(p12->internal(), &p)) <= 0) {
			THROW_OPENSSL_EXCEPTION(0, Csp, NULL, "Error i2d_PKCS12");
		}

		bDataBlob.cbData = iData;
		bDataBlob.pbData = pData;

		if (!(hImportCertStore = PFXImportCertStore(&bDataBlob, wPassword, CRYPT_USER_KEYSET | PKCS12_ALLOW_OVERWRITE_KEY))) {
			THROW_EXCEPTION(0, Csp, NULL, "PFXImportCertStore failed. Code: %d", GetLastError());
		}

		while (pCertContext = CertEnumCertificatesInStore(hImportCertStore, pCertContext)) {
			pCert = pCertContext->pbCertEncoded;

			LOGGER_OPENSSL(d2i_X509);
			if (!(xcert = d2i_X509(NULL, &pCert, pCertContext->cbCertEncoded))) {
				THROW_OPENSSL_EXCEPTION(0, Csp, NULL, "'d2i_X509' Error decode len bytes");
			}

			Handle<Certificate> hcert = new Certificate(xcert);

			if (CertGetCertificateContextProperty(pCertContext,
				CERT_KEY_PROV_INFO_PROP_ID,
				NULL,
				&dwSize)
				)
			{
				storeName = L"MY";
			}
			else if (hcert->isCA()) {
#ifndef OPENSSL_SYS_WINDOWS
				continue;
#endif
				if (hcert->isSelfSigned()) {
					storeName = L"ROOT";
				}
				else {
					storeName = L"CA";
				}
			}
			else {
				storeName = L"AddressBook";
			}

			if (HCRYPT_NULL == (hCertStore = CertOpenStore(
				CERT_STORE_PROV_SYSTEM,
				X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
				HCRYPT_NULL,
				CERT_SYSTEM_STORE_CURRENT_USER,
				storeName)))
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

			CertCloseStore(hCertStore, 0);
			hCertStore = HCRYPT_NULL;
		}

		OPENSSL_free(pData);

		CertFreeCertificateContext(pCertContext);
		pCertContext = HCRYPT_NULL;

		if (hImportCertStore) {
			CertCloseStore(hImportCertStore, 0);
			hImportCertStore = HCRYPT_NULL;
		}
	}
	catch (Handle<Exception> e) {
		if (pCertContext) {
			CertFreeCertificateContext(pCertContext);
		}

		if (hImportCertStore) {
			CertCloseStore(hImportCertStore, 0);
			hImportCertStore = HCRYPT_NULL;
		}

		if (hCertStore) {
			CertCloseStore(hCertStore, 0);
			hCertStore = HCRYPT_NULL;
		}

		THROW_EXCEPTION(0, Csp, e, "Error import pfx");
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

		if (!pbFPCert) {
			THROW_EXCEPTION(0, Csp, NULL, "pbFPCert cannot be null pointer");
		}

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
			if (pbFPCont && !memcmp(pbFPCont, pbFPCert, cbFPCert)) {
				result = TRUE;
				goto Done;
			}
		}

		if (CryptGetProvParam(hProvCont, PP_EXCHANGE_KEY_FP, pbFPCont, &cbFPCont, 0)) {
			if (pbFPCont && !memcmp(pbFPCont, pbFPCert, cbFPCert)) {
				result = TRUE;
				goto Done;
			}
		}

	Done:
		free(pbFPCont);

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

LPCWSTR Csp::provTypeToProvNameW(DWORD dwProvType) {
	LOGGER_FN();

	switch (dwProvType) {
	case PROV_GOST_2001_DH:
		return CP_GR3410_2001_PROV_W;

#ifdef PROV_GOST_2012_256
	case PROV_GOST_2012_256:
		return CAT_L(CP_GR3410_2012_PROV_A);

	case PROV_GOST_2012_512:
		return CAT_L(CP_GR3410_2012_STRONG_PROV_A);
#endif // PROV_GOST_2012_256

	default:
		return NULL;
	}
}

#if defined(CPCSP_VER) && (CPCSP_VER >= 50000)
static void add_single_param_to_param_list(const BYTE * param, size_t param_length, TContainerParamType param_type, std::list<CRYPT_CONTAINER_PARAM*> & param_list) {
	LOGGER_FN();

	CRYPT_CONTAINER_PARAM * contParam;
	DWORD param_len = static_cast<DWORD>(param_length);
	contParam = reinterpret_cast<CRYPT_CONTAINER_PARAM *>(new BYTE[offsetof(CRYPT_CONTAINER_PARAM, pbData) + param_len]);
	contParam->param_type = param_type;
	contParam->cbData = param_len;

	std::copy(param, param + param_length, reinterpret_cast<BYTE*>(contParam->pbData));

	param_list.push_back(contParam);
}

static std::list <CRYPT_CONTAINER_PARAM*> create_container_params(
	const std::string & szAuthURL,
	const std::string & szRestURL,
	const PCCERT_CONTEXT pCertContext,
	unsigned certificate_id,
	bool isLM
	)
{
	LOGGER_FN();

	std::list<CRYPT_CONTAINER_PARAM*> param_list;

	add_single_param_to_param_list(reinterpret_cast<const BYTE*>(szAuthURL.c_str()), szAuthURL.length() + 1, TContainerParamType_AuthServer, param_list);
	add_single_param_to_param_list(reinterpret_cast<const BYTE*>(szRestURL.c_str()), szRestURL.length() + 1, TContainerParamType_SignServer, param_list);
	add_single_param_to_param_list(pCertContext->pbCertEncoded, pCertContext->cbCertEncoded, TContainerParamType_Certificate, param_list);

	DWORD cert_id = static_cast<DWORD>(certificate_id);
	add_single_param_to_param_list(reinterpret_cast<const BYTE*>(&cert_id), sizeof(DWORD), TContainerParamType_CertificateID, param_list);

	return param_list;
}

static void destroy_container_params(std::list<CRYPT_CONTAINER_PARAM*> contParams)
{
	LOGGER_FN();

	for (std::list<CRYPT_CONTAINER_PARAM*>::iterator it = contParams.begin(); it != contParams.end(); ++it) {
		CRYPT_CONTAINER_PARAM* param = *it;
		delete[] param;
	}
}

static void destroy_key_prov_params(CRYPT_KEY_PROV_PARAM * provParams)
{
	LOGGER_FN();

	if (!provParams)
		return;
	delete[](provParams);
}

static void create_key_prov_params(const std::list<CRYPT_CONTAINER_PARAM*> & contParams, CRYPT_KEY_PROV_PARAM ** provParamsOut, DWORD * provParamsCount)
{
	LOGGER_FN();

	CRYPT_KEY_PROV_PARAM * provParams = new CRYPT_KEY_PROV_PARAM[contParams.size()];

	DWORD paramNum = 0;
	for (std::list<CRYPT_CONTAINER_PARAM*>::const_iterator it = contParams.begin(); it != contParams.end(); ++it) {
		CRYPT_CONTAINER_PARAM* param = *it;
		provParams[paramNum].dwParam = PP_CONTAINER_PARAM;
		provParams[paramNum].dwFlags = 0;
		provParams[paramNum].cbData = offsetof(CRYPT_CONTAINER_PARAM, pbData) + param->cbData;
		provParams[paramNum].pbData = (LPBYTE)param;
		paramNum++;
	}
	*provParamsOut = provParams;
	*provParamsCount = paramNum;
}

static bool hasCloudReader(const WCHAR * provName, DWORD dwProvType)
{
	LOGGER_FN();

	HCRYPTPROV hProv;
	bool res = false;
	if (!CryptAcquireContextW(&hProv, NULL, provName, dwProvType, CRYPT_VERIFYCONTEXT)) {
		return res;
	}
	DWORD dwMaxLen = 0;
	DWORD dwFlags = CRYPT_FIRST;
	if (!CryptGetProvParam(hProv, PP_ENUMREADERS, NULL, &dwMaxLen, dwFlags)) {
		CryptReleaseContext(hProv, 0);
		return res;
	}

	std::vector<BYTE> reader_info;
	reader_info.resize(dwMaxLen);
	DWORD dwLen = dwMaxLen;
	while (CryptGetProvParam(hProv, PP_ENUMREADERS, &reader_info[0], &dwLen, dwFlags)) {
		dwLen = dwMaxLen;
		dwFlags &= ~CRYPT_FIRST;
		const char * reader_str = (const char*)&reader_info[0];
		reader_str += (std::string(reader_str).length() + 1);
		std::string reader_name = reader_str;
		if (reader_name == "CLOUD") {
			res = true;
			break;
		}
	}
	CryptReleaseContext(hProv, 0);
	return res;
}

#define MAX_PROVIDER_NAME_LEN 260
static std::wstring GetProviderWithCloud(DWORD dwProvType)
{
	LOGGER_FN();

	DWORD dwIndex = 0;
	DWORD dwInnerType = 0;
	WCHAR provName[MAX_PROVIDER_NAME_LEN + 1];
	DWORD dwProvNameSize = sizeof(provName);
	std::wstring res = std::wstring();
	while (CryptEnumProvidersW(dwIndex++, NULL, 0, &dwInnerType, provName, &dwProvNameSize)) {
		dwProvNameSize = sizeof(provName);
		if ((dwInnerType == dwProvType) && hasCloudReader(provName, dwProvType)) {
			res = std::wstring(provName);
			break;
		}
	}
	return res;
}

static void getProviderByOID(const std::string & szPubKeyOID, DWORD * dwProvType, std::wstring & provider_name)
{
	LOGGER_FN();

	std::wstring def_prov;
	if (szPubKeyOID == szOID_CP_GOST_R3410EL) {
		*dwProvType = PROV_GOST_2001_DH;
		def_prov = CP_GR3410_2001_PROV_W;
	}
	else if (szPubKeyOID == szOID_CP_GOST_R3410_12_256) {
		*dwProvType = PROV_GOST_2012_256;
		def_prov = CAT_L(CP_GR3410_2012_PROV_A);
	}
	else if (szPubKeyOID == szOID_CP_GOST_R3410_12_512) {
		*dwProvType = PROV_GOST_2012_512;
		def_prov = CAT_L(CP_GR3410_2012_STRONG_PROV_A);
	}
	else if (szPubKeyOID == szOID_RSA_RSA) {
		*dwProvType = PROV_RSA_AES;
		def_prov = CAT_L(CP_RSA_AES_ENH_PROV_A);
	}
	else if (szPubKeyOID == szOID_ECC_PUBLIC_KEY) {
		*dwProvType = PROV_EC_ECDSA_FULL;
		def_prov = CAT_L(CP_ECDSA_AES_PROV_A);
	}
	else {
		*dwProvType = PROV_GOST_2001_DH;
		def_prov = CP_GR3410_2001_PROV_W;
	}
	provider_name = GetProviderWithCloud(*dwProvType);
	if (provider_name.empty())
		provider_name = def_prov;
}

static DWORD set_certificate_to_store_internal(
	const PCCERT_CONTEXT pCertContext,
	const std::string & contName,
	const std::list<CRYPT_CONTAINER_PARAM*> & contParams,
	bool isLM
	)
{
	LOGGER_FN();

	DWORD err = ERROR_SUCCESS;
	CRYPT_KEY_PROV_INFO	stProvInfo;
	WCHAR wzContName[MAX_CONTAINER_NAME_LEN];
	mbstowcs(wzContName, ("CLOUD\\\\" + contName).c_str(), MAX_CONTAINER_NAME_LEN);
	stProvInfo.pwszContainerName = wzContName;
	stProvInfo.dwFlags = isLM ? CRYPT_MACHINE_KEYSET : 0;
	stProvInfo.dwKeySpec = AT_KEYEXCHANGE;
	if (!pCertContext || !pCertContext->pCertInfo) {
		THROW_EXCEPTION(0, Csp, NULL, "The certificate context is not inited");
	}

	std::wstring provider_name;
	getProviderByOID(pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, &stProvInfo.dwProvType, provider_name);
	stProvInfo.pwszProvName = (LPWSTR)provider_name.c_str();

	CRYPT_KEY_PROV_PARAM * rgProvParam = NULL;
	DWORD cProvParam = 0;
	if (contParams.size())
		create_key_prov_params(contParams, &rgProvParam, &cProvParam);
	stProvInfo.cProvParam = cProvParam;
	stProvInfo.rgProvParam = rgProvParam;
	if (!CertSetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, 0, &stProvInfo)) {
		destroy_key_prov_params(rgProvParam);
		return GetLastError();
	}
	destroy_key_prov_params(rgProvParam);

	HCERTSTORE hStore = HCRYPT_NULL;

	DWORD dwFlags = 0;
	if (isLM) {
		dwFlags |= CERT_SYSTEM_STORE_LOCAL_MACHINE;
	}
	else {
		dwFlags |= CERT_SYSTEM_STORE_CURRENT_USER;
	}

	dwFlags |= CERT_STORE_OPEN_EXISTING_FLAG;

	hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, dwFlags, L"My");

	if (!hStore)
		return GetLastError();

	if (!CertAddCertificateContextToStore(hStore, pCertContext, CERT_STORE_ADD_REPLACE_EXISTING, NULL)) {
		if (hStore) {
			CertCloseStore(hStore, 0);
			hStore = HCRYPT_NULL;
		}

		return GetLastError();
	}

	if (hStore) {
		CertCloseStore(hStore, 0);
		hStore = HCRYPT_NULL;
	}

	return err;
}

void Csp::installCertificateFromCloud(
	Handle<Certificate> hcert,
	const std::string & szAuthURL,
	const std::string & szRestURL,
	unsigned certificate_id,
	bool isLM
	)
{
	LOGGER_FN();

	PCCERT_CONTEXT pCertContext = HCRYPT_NULL;
	std::list<CRYPT_CONTAINER_PARAM*> contParams;

	try {
		const std::string contName = Csp::formContainerNameForDSS(szRestURL, certificate_id);
		pCertContext = createCertificateContext(hcert);
		contParams = create_container_params(szAuthURL, szRestURL, pCertContext, certificate_id, isLM);
		DWORD err = set_certificate_to_store_internal(pCertContext, contName, contParams, isLM);

		destroy_container_params(contParams);

		if (pCertContext) {
			CertFreeCertificateContext(pCertContext);
			pCertContext = HCRYPT_NULL;
		}

		if (err) {
			THROW_EXCEPTION(0, Csp, NULL, "set_certificate_to_store_internal return code: 0x%08x", err);
		}
	}
	catch (Handle<Exception> e) {
		if (pCertContext) {
			CertFreeCertificateContext(pCertContext);
			pCertContext = HCRYPT_NULL;
		}

		destroy_container_params(contParams);

		THROW_EXCEPTION(0, Csp, e, "Error install certificate from cloud");
	}

	return;
}

static unsigned get_random_seed(const std::string & server_name, unsigned cert_id)
{
	return std::accumulate(server_name.begin(), server_name.end(), 0) + cert_id;
}

static const std::string get_random_uuid(unsigned seed)
{
	std::string uuid = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx";
	const char * hex = "0123456789abcdef";
	srand(seed);
	for (std::string::iterator it = uuid.begin(); it != uuid.end(); ++it) {
		size_t num = rand() % 16;
		switch (*it) {
		case '-':
		case '4':
			break;
		case 'y':
			num &= (0x03 | 0x08);
		case 'x':
			*it = hex[num];
			break;
		}
	}
	return uuid;
}

std::string Csp::formContainerNameForDSS(const std::string & restPath, unsigned certificateID)
{
	return "DSS-" + get_random_uuid(get_random_seed(restPath, certificateID));
}

#endif // defined(CPCSP_VER) && (CPCSP_VER >= 50000)

#endif //CSP_ENABLE

ContainerName::ContainerName(){
	LOGGER_FN();

	unique = new std::string("");
	container = new std::wstring((wchar_t *) "");
	fqcnA = new std::string("");
	fqcnW = new std::wstring((wchar_t *) "");
}