#include "../stdafx.h"

#include "wrapper/utils/jwt.h"

bool Jwt::checkLicense() {
	LOGGER_FN();

	try{
#ifndef JWT_NO_LICENSE

		CTLICENSE_OPERATION noOperationDemand = { false, false, false, false, false, false, false };

		if (!ctlicense_check_store(&noOperationDemand)) {
			THROW_EXCEPTION(0, Jwt, NULL, "No valid jwt license in store ");
		}

		return true;
#else
		THROW_EXCEPTION(0, Jwt, NULL, "Only if undefined JWT_NO_LICENSE");
#endif
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Jwt, e, "Error check license");
	}
}

bool Jwt::checkLicense(Handle<std::string> lic) {
	LOGGER_FN();

	try{
		int errorCode;

#ifndef JWT_NO_LICENSE
		CTLICENSE_OPERATION noOperationDemand = { false, false, false, false, false, false, false };

		if (!ctlicense_check_str((char *)lic->c_str(), &noOperationDemand, &errorCode)) {
			THROW_EXCEPTION(0, Jwt, NULL, "verify jwt license failed(error code %d)", errorCode);
		}

		return true;
#else
		THROW_EXCEPTION(0, Jwt, NULL, "Only if undefined JWT_NO_LICENSE");
#endif
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Jwt, e, "Error check license");
	}
}
