#include "../stdafx.h"

#include "certs.h"

void CertificateCollection::push(Handle<Certificate> cert) {
	LOGGER_FN();

	if (this->isEmpty()){
		LOGGER_OPENSSL("sk_X509_new_null");
		this->setData(sk_X509_new_null());
	}
	Handle<Certificate> certcpy = cert->duplicate();
	X509* text = certcpy->internal();

	LOGGER_OPENSSL("sk_X509_push");
	sk_X509_push(this->internal(), certcpy->internal());

	certcpy->setParent(this->handle());
}

int CertificateCollection::length() {
	LOGGER_FN();

	if (this->isEmpty())
		return 0;

	LOGGER_OPENSSL("sk_X509_num");
	return sk_X509_num(this->internal());
}

Handle<Certificate> CertificateCollection::items(int index) {
	LOGGER_FN();

	LOGGER_OPENSSL("sk_X509_value");
	X509 *cert = sk_X509_value(this->internal(), index);

	if (!cert){
		THROW_OPENSSL_EXCEPTION(0, CertificateCollection, NULL, "Has no item by index %d", index);
	}

	return new Certificate(cert, this->handle());
}
