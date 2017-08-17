#include "../stdafx.h"

#include "wrapper/utils/jwt.h"

int Jwt::checkLicense() {
	LOGGER_FN();

	try{
#ifndef JWT_NO_LICENSE

		int res = 0;

		CTLICENSE_OPERATION noOperationDemand = { false, false, false, false, false, false, false };

		if (!ctlicense_check_store(&noOperationDemand)) {
			res = -1;
		}

		return res;
#else
		THROW_EXCEPTION(0, Jwt, NULL, "Only if undefined JWT_NO_LICENSE");
#endif
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Jwt, e, "Error check license");
	}
}

int Jwt::checkLicense(Handle<std::string> lic) {
	LOGGER_FN();

	try{
		int errorCode;
		int res = 0;

#ifndef JWT_NO_LICENSE
		CTLICENSE_OPERATION noOperationDemand = { false, false, false, false, false, false, false };

		if (!ctlicense_check_str((char *)lic->c_str(), &noOperationDemand, &errorCode)) {
			res = errorCode;
		}

		return res;
#else
		THROW_EXCEPTION(0, Jwt, NULL, "Only if undefined JWT_NO_LICENSE");
#endif
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Jwt, e, "Error check license");
	}
}
