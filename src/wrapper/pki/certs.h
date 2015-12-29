#ifndef CMS_PKI_CERTS_H_INCLUDED
#define  CMS_PKI_CERTS_H_INCLUDED

#include <openssl/crypto.h>

#include "../common/common.h"

class CTWRAPPER_API CertificateCollection;

#include "pki.h"
#include "cert.h"

SSLOBJECT_free(stack_st_X509, sk_X509_free)

class CertificateCollection: public SSLObject<stack_st_X509> {
public:
	SSLOBJECT_new(CertificateCollection, stack_st_X509){}
	SSLOBJECT_new_null(CertificateCollection, stack_st_X509, sk_X509_new_null){}

	//methods
	void push(Handle<Certificate>&);
	int length();
	Handle<Certificate> items(int index);
};

#endif //!CMS_PKI_CERTS_H_INCLUDED
