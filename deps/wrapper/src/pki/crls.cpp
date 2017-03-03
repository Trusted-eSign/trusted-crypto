#include "../stdafx.h"

#include "wrapper/pki/crls.h"

void CrlCollection::push(Handle<CRL> crl) {
	LOGGER_FN();

	if (this->isEmpty()){
		LOGGER_OPENSSL("sk_X509_CRL_new_null");
		this->setData(sk_X509_CRL_new_null());
	}

	Handle<CRL> crlcpy = crl->duplicate();

	LOGGER_OPENSSL("sk_X509_CRL_push");
	sk_X509_CRL_push(this->internal(), crlcpy->internal());

	crlcpy->setParent(this->handle());
}

int CrlCollection::length() {
	LOGGER_FN();

	if (this->isEmpty()) {
		return 0;
	}		

	LOGGER_OPENSSL("sk_X509_CRL_num");
	return sk_X509_CRL_num(this->internal());
}

Handle<CRL> CrlCollection::items(int index) {
	LOGGER_FN();

	LOGGER_OPENSSL("sk_X509_CRL_value");
	X509_CRL *crl = sk_X509_CRL_value(this->internal(), index);

	if (!crl){
		THROW_OPENSSL_EXCEPTION(0, CrlCollection, NULL, "Has no item by index %d", index);
	}

	return new CRL(crl, this->handle());
}

void CrlCollection::pop(){
	LOGGER_FN();

	LOGGER_OPENSSL("sk_X509_CRL_value");
	sk_X509_CRL_pop(this->internal());	
}

void CrlCollection::removeAt(int index){
	LOGGER_FN();

	LOGGER_OPENSSL("sk_X509_CRL_delete");
	sk_X509_CRL_delete(this->internal(), index);
}
