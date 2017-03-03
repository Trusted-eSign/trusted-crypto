#include "../stdafx.h"

#include "wrapper/cms/signer_id.h"

void SignerId::setIssuerName(Handle<std::string> name){
	LOGGER_FN();

	this->issuerName = name;
}

Handle<std::string> SignerId::getIssuerName(){
	LOGGER_FN();

	if (!this->issuerName.isEmpty()) {
		return this->issuerName;
	}
	else {
		THROW_EXCEPTION(0, SignerId, NULL, "Issuer name is empty");
	}

	return this->issuerName;
}

void SignerId::setSerialNumber(Handle<std::string> value){
	LOGGER_FN();

	this->serialNumber = value;
}

Handle<std::string> SignerId::getSerialNumber(){
	LOGGER_FN();

	if (!this->serialNumber.isEmpty()) {
		return this->serialNumber;
	}
	else {
		THROW_EXCEPTION(0, SignerId, NULL, "Serial number is empty");
	}
}

void SignerId::setKeyId(Handle<std::string> value){
	LOGGER_FN();

	this->keyid = value;
}

Handle<std::string> SignerId::getKeyId(){
	LOGGER_FN();

	if (!this->keyid.isEmpty()) {
		return this->keyid;
	}
	else {
		THROW_EXCEPTION(0, SignerId, NULL, "KeyId is empty");
	}
}
