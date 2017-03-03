#include "../stdafx.h"

#include "wrapper/pki/revokeds.h"

void RevokedCollection::push(Handle<Revoked> rv) {
	LOGGER_FN();

	if (this->isEmpty()){
		LOGGER_OPENSSL("sk_X509_REVOKED_new_null");
		this->setData(sk_X509_REVOKED_new_null());
	}
	Handle<Revoked> rvcpy = rv->duplicate();

	LOGGER_OPENSSL("sk_X509_REVOKED_push");
	sk_X509_REVOKED_push(this->internal(), rvcpy->internal());

	rvcpy->setParent(this->handle());
}

int RevokedCollection::length() {
	LOGGER_FN();

	if (this->isEmpty())
		return 0;

	LOGGER_OPENSSL("sk_X509_REVOKED_num");
	return sk_X509_REVOKED_num(this->internal());
}

Handle<Revoked> RevokedCollection::items(int index) {
	LOGGER_FN();

	LOGGER_OPENSSL("sk_X509_REVOKED_value");
	X509_REVOKED *rv = sk_X509_REVOKED_value(this->internal(), index);

	if (!rv){
		THROW_OPENSSL_EXCEPTION(0, RevokedCollection, NULL, "Has no item by index %d", index);
	}

	return (new Revoked(rv, this->handle()))->duplicate();
}

void RevokedCollection::pop(){
	LOGGER_FN();

	LOGGER_OPENSSL("sk_X509_REVOKED_value");
	sk_X509_REVOKED_pop(this->internal());	
}

void RevokedCollection::removeAt(int index){
	LOGGER_FN();

	LOGGER_OPENSSL("sk_X509_REVOKED_delete");
	sk_X509_REVOKED_delete(this->internal(), index);
}
