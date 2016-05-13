#include "../stdafx.h"

#include "pkcs12.h"

void Pkcs12::read(Handle<Bio> in){
	LOGGER_FN();

	if (in.isEmpty()) {
		THROW_EXCEPTION(0, Pkcs12, NULL, "Parameter %d cann't be NULL", 1);
	}	

	PKCS12 *p12 = NULL;

	in->reset();

	LOGGER_OPENSSL(d2i_PKCS12_bio);
	p12 = d2i_PKCS12_bio(in->internal(), NULL);
	if (!p12) {
		THROW_EXCEPTION(0, Pkcs12, NULL, "Can not read PKCS12 data from BIO");
	}

	this->setData(p12);
}

void Pkcs12::write(Handle<Bio> out){
	LOGGER_FN();

	if (out.isEmpty()) {
		THROW_EXCEPTION(0, Pkcs12, NULL, "Parameter %d is NULL", 1);
	}
		
	LOGGER_OPENSSL(i2d_PKCS12_bio);
	if (i2d_PKCS12_bio(out->internal(), this->internal()) < 1){
		THROW_OPENSSL_EXCEPTION(0, Pkcs12, NULL, "i2d_PKCS12_bio", NULL);
	}		
}

Handle<Pkcs12> Pkcs12::create(Handle<Certificate> cert, Handle<Key> key, Handle<CertificateCollection> ca, char *pass, char *name){
	LOGGER_FN();

	try{
		PKCS12 *p12 = NULL;

		LOGGER_OPENSSL(PKCS12_create);
		p12 = PKCS12_create(pass, name, key->internal(), cert->internal(), NULL, 0, 0, 0, 0, 0);
		if (!p12) {
			THROW_OPENSSL_EXCEPTION(0, Pkcs12, NULL, "Error creating PKCS#12 structure");
		}

		return new Pkcs12(p12, this->handle());
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Pkcs12, e, "Error create pkcs12");
	}
}

Handle<Certificate> Pkcs12::getCertificate(const char *pass) {
	LOGGER_FN();

	try{
		EVP_PKEY *pkey;
		X509 *hcert;
		STACK_OF(X509) *ca = NULL;

		if (!PKCS12_parse(this->internal(), pass, &pkey, &hcert, &ca)) {
			THROW_OPENSSL_EXCEPTION(0, Pkcs12, NULL, "Error parsing PKCS12", NULL);
		}

		if (hcert){
			return new Certificate(hcert);
		}
		else {
			THROW_EXCEPTION(0, Pkcs12, NULL, "Cannot get certificate", 1);
		}
		
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Pkcs12, e, "Error get certificate from pkcs12");
	}
}

Handle<Key> Pkcs12::getKey(const char *pass) {
	LOGGER_FN();

	try{
		EVP_PKEY *pkey;
		X509 *hcert;
		STACK_OF(X509) *ca = NULL;

		if (!PKCS12_parse(this->internal(), pass, &pkey, &hcert, &ca)) {
			THROW_OPENSSL_EXCEPTION(0, Pkcs12, NULL, "Error parsing PKCS12", NULL);
		}

		if (pkey) {
			return new Key(pkey);
		}
		else {
			THROW_EXCEPTION(0, Pkcs12, NULL, "Cannot get key", 1);
		}
		
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Pkcs12, e, "Error get key from pkcs12");
	}
}

Handle<CertificateCollection> Pkcs12::getCACertificates(const char *pass) {
	LOGGER_FN();

	try{
		EVP_PKEY *pkey;
		X509 *hcert;
		STACK_OF(X509) *ca = NULL;

		if (!PKCS12_parse(this->internal(), pass, &pkey, &hcert, &ca)) {
			THROW_OPENSSL_EXCEPTION(0, Pkcs12, NULL, "Error parsing PKCS12", NULL);
		}

		if (ca){
			return new CertificateCollection(ca);
		}
		else {
			return new CertificateCollection();
		}

	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Pkcs12, e, "Error get ca from pkcs12");
	}
}