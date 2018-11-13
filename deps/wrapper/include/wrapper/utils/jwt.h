#ifndef UTIL_JWT_INCLUDED
#define UTIL_JWT_INCLUDED

#ifndef JWT_NO_LICENSE
	#include <openssl/ctlicense.h>
#endif

#include "../common/common.h"

class Jwt {
public:
	Jwt(){};
	~Jwt(){};

	bool addLicense(Handle<std::string> lic);
	bool deleteLicense(Handle<std::string> lic);
	int checkLicense();
	int checkLicense(Handle<std::string> lic);
	int checkTrialLicense();
	int getExpirationTime(Handle<std::string> lic);
	int getTrialExpirationTime();
	int createTrialLicense();
};

#endif //!UTIL_JWT_INCLUDED 
