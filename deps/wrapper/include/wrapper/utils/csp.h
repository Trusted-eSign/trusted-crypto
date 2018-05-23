#ifndef UTIL_CSP_INCLUDED
#define UTIL_CSP_INCLUDED

#include <vector>
#include <sstream>

#include "../common/common.h"
#include "../pki/cert.h"
#include "../pki/pkcs12.h"

struct ProviderProps {
	int type;
	Handle<std::string> name;
};

class ContainerName {
public:
	ContainerName();
	~ContainerName(){};
public:
	Handle<std::string> unique; //CRYPT_UNIQUE
	Handle<std::wstring> container; //PP_CONTAINER
	Handle<std::string> fqcnA; //PP_FQCN
	Handle<std::wstring> fqcnW; //PP_FQCN with mbstowcs
};

class Csp {
public:
	Csp(){};
	~Csp(){};

	bool isGost2001CSPAvailable();
	bool isGost2012_256CSPAvailable();
	bool isGost2012_512CSPAvailable();

	bool checkCPCSPLicense();
	Handle<std::string> getCPCSPLicense();
	Handle<std::string> getCPCSPVersion();
	Handle<std::string> getCPCSPVersionPKZI();
	Handle<std::string> getCPCSPVersionSKZI();
	Handle<std::string> getCPCSPSecurityLvl();

	std::vector<ProviderProps> enumProviders();
	std::vector<Handle<ContainerName>> enumContainers(int provType, Handle<std::string> provName);
	Handle<Certificate> getCertifiacteFromContainer(Handle<std::string> contName, int provType, Handle<std::string> provName);
	Handle<std::string> getContainerNameByCertificate(Handle<Certificate> cert, Handle<std::string> category);
	void installCertifiacteFromContainer(Handle<std::string> contName, int provType, Handle<std::string> provName);
	void installCertifiacteToContainer(Handle<Certificate> cert, Handle<std::string> contName, int provType, Handle<std::string> provName);
	void deleteContainer(Handle<std::string> contName, int provType, Handle<std::string> provName);

	static Handle<CertificateCollection> buildChain(Handle<Certificate> cert);
	static bool verifyCertificateChain(Handle<Certificate> cert);

	bool isHaveExportablePrivateKey(Handle<Certificate> cert);
	Handle<Pkcs12> certToPkcs12(Handle<Certificate> cert, bool exportPrivateKey, Handle<std::string> password);
	void importPkcs12(Handle<Pkcs12> p12, Handle<std::string> password);

#ifdef CSP_ENABLE
	PCCERT_CONTEXT static createCertificateContext(Handle<Certificate> cert);

	bool static findExistingCertificate(
		OUT PCCERT_CONTEXT &pOutCertContext,
		IN HCERTSTORE hCertStore,
		IN PCCERT_CONTEXT pCertContext,
		IN DWORD dwFindFlags = 0,
		IN DWORD dwCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
		);

private:
	bool static cmpCertAndContFP(LPCSTR szContainerName, LPBYTE pbFPCert, DWORD cbFPCert);

	CRYPT_KEY_PROV_INFO static * getCertificateContextProperty(
		IN PCCERT_CONTEXT pCertContext,
		IN DWORD dwPropId
		);

	LPCWSTR provTypeToProvNameW(DWORD dwProvType);
#endif //CSP_ENABLE
};

#endif //!UTIL_CSP_INCLUDED 
