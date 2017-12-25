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

	std::vector<ProviderProps> enumProviders();
	std::vector<Handle<std::string>> enumContainers(int provType, Handle<std::string> provName);
	Handle<Certificate> getCertifiacteFromContainer(Handle<std::string> contName, int provType, Handle<std::string> provName);
	void installCertifiacteFromContainer(Handle<std::string> contName, int provType, Handle<std::string> provName);
};

#endif //!UTIL_CSP_INCLUDED 
