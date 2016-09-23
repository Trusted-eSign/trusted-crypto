#ifndef CMS_PKI_PKCS12_H_INCLUDED
#define  CMS_PKI_PKCS12_H_INCLUDED

#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>

#include "../common/common.h"

class CTWRAPPER_API Pkcs12;

#include "pki.h"
#include "key.h"

SSLOBJECT_free(PKCS12, PKCS12_free);

class Pkcs12 : public SSLObject < PKCS12 > {
public:
	//constructor
	SSLOBJECT_new(Pkcs12, PKCS12){}
	SSLOBJECT_new_null(Pkcs12, PKCS12, PKCS12_new){}

	//properties
	Handle<Certificate> getCertificate(const char *pass);
	Handle<Key> getKey(const char *pass);
	Handle<CertificateCollection> getCACertificates(const char *pass);

	//Methods
	void read(Handle<Bio> in);
	void write(Handle<Bio> out);
	Handle<Pkcs12> create(Handle<Certificate> cert, Handle<Key> key, Handle<CertificateCollection> ca, char *pass, char *name);
};

#endif //!CMS_PKI_PKCS12_H_INCLUDED
