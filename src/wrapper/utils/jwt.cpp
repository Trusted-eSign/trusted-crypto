#include "../stdafx.h"

#include "jwt.h"

bool Jwt::checkLicense() {
	LOGGER_FN();

	try{
		int errorCode;

#ifndef OPENSSL_NO_CTGOSTCP
		if (!jwtdlVerifyLicenseFile(&errorCode)) {
			THROW_EXCEPTION(0, Jwt, NULL, "jwtdlVerifyLicenseFile() failed(error code %d)", errorCode);
		}

		return true;
#else
		THROW_EXCEPTION(0, Jwt, NULL, "Only if defined CTGSOTCP");
#endif
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Jwt, e, "Error check license");
	}
}
