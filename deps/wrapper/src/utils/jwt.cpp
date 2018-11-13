#include "../stdafx.h"

#include "wrapper/utils/jwt.h"

bool Jwt::addLicense(Handle<std::string> lic) {
	LOGGER_FN();

	try{
		int errorCode;

#ifndef JWT_NO_LICENSE
		return ctlicense_add_str((char *)lic->c_str(), &errorCode);
#else
		THROW_EXCEPTION(0, Jwt, NULL, "Only if undefined JWT_NO_LICENSE");
#endif
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Jwt, e, "Error check license");
	}
}

bool Jwt::deleteLicense(Handle<std::string> lic) {
	LOGGER_FN();

	try{
#ifndef JWT_NO_LICENSE
		return ctlicense_delete((char *)lic->c_str());
#else
		THROW_EXCEPTION(0, Jwt, NULL, "Only if undefined JWT_NO_LICENSE");
#endif
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Jwt, e, "Error check license");
	}
}

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

int Jwt::getExpirationTime(Handle<std::string> lic) {
	LOGGER_FN();

	try {
		int errorCode;
		int res = 0;

#ifndef JWT_NO_LICENSE
		res = getExpTime((char *)lic->c_str(), &errorCode);
		if (errorCode != 900) res = errorCode;
		return res;
#else
		THROW_EXCEPTION(0, Jwt, NULL, "Only if undefined JWT_NO_LICENSE");
#endif
	}
	catch (Handle<Exception> e) {
		THROW_EXCEPTION(0, Jwt, e, "Error check license");
	}
}

int Jwt::getTrialExpirationTime() {
	LOGGER_FN();

	try {
		int errorCode;
		int res = 0;

#ifndef JWT_NO_LICENSE
		res = getTrialExpTime(&errorCode);
		if (errorCode != 900) res = errorCode;
		return res;
#else
		THROW_EXCEPTION(0, Jwt, NULL, "Only if undefined JWT_NO_LICENSE");
#endif
	}
	catch (Handle<Exception> e) {
		THROW_EXCEPTION(0, Jwt, e, "Error check license");
	}
}

int Jwt::checkTrialLicense() {
	LOGGER_FN();

	try {
		int errorCode;
		int res = 0;

#ifndef JWT_NO_LICENSE
		res = ctlic_validateTrial(&errorCode);
		if (errorCode != 900) res = errorCode;
		return res;
#else
		THROW_EXCEPTION(0, Jwt, NULL, "Only if undefined JWT_NO_LICENSE");
#endif
	}
	catch (Handle<Exception> e) {
		THROW_EXCEPTION(0, Jwt, e, "Error check license");
	}
}

int Jwt::createTrialLicense() {
	LOGGER_FN();

	try {
		int errorCode;
		int res = 0;

#ifndef JWT_NO_LICENSE
		res = ctlic_generateTrial(&errorCode);
		if (errorCode != 900) res = errorCode;
		return res;
#else
		THROW_EXCEPTION(0, Jwt, NULL, "Don't create trial license");
#endif
	}
	catch (Handle<Exception> e) {
		THROW_EXCEPTION(0, Jwt, e, "Error create trial license");
	}
}


