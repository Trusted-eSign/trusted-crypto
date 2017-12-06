#ifndef UTIL_CSP_INCLUDED
#define UTIL_CSP_INCLUDED

#include "../common/common.h"

class Csp {
public:
	Csp(){};
	~Csp(){};

	bool isGost2001CSPAvailable();
	bool isGost2012_256CSPAvailable();
	bool isGost2012_512CSPAvailable();

	bool checkCPCSPLicense();
	Handle<std::string> getCPCSPLicense();
};

#endif //!UTIL_CSP_INCLUDED 
