#include "stdafx.h"

#include "certs.h"

void CertificateCollection::push(Handle<Certificate> &cert) {
	if (this->isEmpty()){
		this->setData(sk_X509_new_null());
	}
	Handle<Certificate> certcpy = cert->duplicate();
	X509* text = certcpy->internal();
	sk_X509_push(this->internal(), certcpy->internal());
	certcpy->setParent(this->handle());
}

int CertificateCollection::length() {
	if (this->isEmpty())
		return 0;
	return sk_X509_num(this->internal());
}

Handle<Certificate> CertificateCollection::items(int index) {
	X509 *cert = sk_X509_value(this->internal(), index);
	if (!cert) return NULL;
	//X509 *dcert = X509_dup(cert);
	return new Certificate(cert, this->handle());
}
