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

	bool checkLicense();
	bool checkLicense(Handle<std::string> lic);
};

#endif //!UTIL_JWT_INCLUDED 
