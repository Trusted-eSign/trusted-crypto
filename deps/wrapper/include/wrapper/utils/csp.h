#ifndef UTIL_CSP_INCLUDED
#define UTIL_CSP_INCLUDED

#include <vector>

#include "../common/common.h"

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

	std::vector<ProviderProps> enumProviders();
	std::vector<Handle<std::string>> enumContainers(int provType = NULL);
};

#endif //!UTIL_CSP_INCLUDED 
