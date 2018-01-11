#ifndef UTIL_CSP_INCLUDED
#define UTIL_CSP_INCLUDED

#include <vector>
#include <sstream>

#include "../common/common.h"
#include "../pki/cert.h"

struct ProviderProps {
	int type;
	Handle<std::string> name;
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
	Handle<std::string> getCPCSPSecurityLvl();

	std::vector<ProviderProps> enumProviders();
	std::vector<Handle<std::string>> enumContainers(int provType, Handle<std::string> provName);
	Handle<Certificate> getCertifiacteFromContainer(Handle<std::string> contName, int provType, Handle<std::string> provName);
	Handle<std::string> getContainerNameByCertificate(Handle<Certificate> cert, Handle<std::string> category);
	void installCertifiacteFromContainer(Handle<std::string> contName, int provType, Handle<std::string> provName);

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
};

#endif //!UTIL_CSP_INCLUDED 
