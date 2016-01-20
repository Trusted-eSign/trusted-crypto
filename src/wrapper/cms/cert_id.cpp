#include "../stdafx.h"

#include "cert_id.h"

void CertificateId::setIssuerName(Handle<X509Name> value){
	LOGGER_FN();

	this->issuerName = value;
}

Handle<X509Name> CertificateId::getIssuerName(){
	LOGGER_FN();

	return this->issuerName;
}

void CertificateId::setSerialNumber(Handle<std::string> value){
	LOGGER_FN();

	this->serialNumber = value;
}

Handle<std::string> CertificateId::getSerialNumber(){
	LOGGER_FN();

	return this->serialNumber;
}

void CertificateId::setKeyId(Handle<std::string> value){
	LOGGER_FN();

	this->keyid = value;
}

Handle<std::string> CertificateId::getKeyId(){
	LOGGER_FN();

	return this->keyid;
}