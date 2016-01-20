#include "../stdafx.h"

#include "x509_name.h"

Handle<std::string> X509Name::toString(){
	LOGGER_FN();

	LOGGER_OPENSSL("X509_NAME_oneline_ex");
	std::string text = X509_NAME_oneline_ex(this->internal());

	return new std::string(text);
}