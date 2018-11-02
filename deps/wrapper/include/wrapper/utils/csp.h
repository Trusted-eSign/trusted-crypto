#ifndef UTIL_CSP_INCLUDED
#define UTIL_CSP_INCLUDED

#include <vector>
#include <sstream>
#include <list>
#include <iterator>
#include <numeric>

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

#ifdef CSP_ENABLE
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
	Handle<Certificate> getCertificateFromContainer(Handle<std::string> contName, int provType, Handle<std::string> provName);
	Handle<std::string> getContainerNameByCertificate(Handle<Certificate> cert, Handle<std::string> category);
	void installCertificateFromCloud(
		Handle<Certificate> hcert,
		const std::string & szAuthURL,
		const std::string & szRestURL,
		unsigned certificate_id,
		bool isLM = false
		);
	void installCertificateFromContainer(Handle<std::string> contName, int provType, Handle<std::string> provName);
	void installCertificateToContainer(Handle<Certificate> cert, Handle<std::string> contName, int provType, Handle<std::string> provName);
	void deleteContainer(Handle<std::string> contName, int provType, Handle<std::string> provName);

	static Handle<CertificateCollection> buildChain(Handle<Certificate> cert);
	static bool verifyCertificateChain(Handle<Certificate> cert);

	bool isHaveExportablePrivateKey(Handle<Certificate> cert);
	Handle<Pkcs12> certToPkcs12(Handle<Certificate> cert, bool exportPrivateKey, Handle<std::string> password);
	void importPkcs12(Handle<Pkcs12> p12, Handle<std::string> password);

	PCCERT_CONTEXT static createCertificateContext(Handle<Certificate> cert);
	PCCRL_CONTEXT static createCrlContext(Handle<CRL> crl);

	bool static findExistingCertificate(
		OUT PCCERT_CONTEXT &pOutCertContext,
		IN HCERTSTORE hCertStore,
		IN PCCERT_CONTEXT pCertContext,
		IN DWORD dwFindFlags = 0,
		IN DWORD dwCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
		);

	bool static findExistingCrl(
		OUT PCCRL_CONTEXT &pOutCrlContext,
		IN HCERTSTORE hCertStore,
		IN PCCRL_CONTEXT pCrlContext,
		IN DWORD dwFindFlags = 0,
		IN DWORD dwCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
		);

	LPCWSTR static provTypeToProvNameW(DWORD dwProvType);

private:
	bool static cmpCertAndContFP(LPCSTR szContainerName, LPBYTE pbFPCert, DWORD cbFPCert);

	CRYPT_KEY_PROV_INFO static * getCertificateContextProperty(
		IN PCCERT_CONTEXT pCertContext,
		IN DWORD dwPropId
		);

	static std::string formContainerNameForDSS(const std::string & restPath, unsigned certificateID);
#endif //CSP_ENABLE
};

#endif //!UTIL_CSP_INCLUDED
