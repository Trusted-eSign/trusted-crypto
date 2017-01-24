#ifndef CMS_PKI_REVOKED_H_INCLUDED
#define  CMS_PKI_REVOKED_H_INCLUDED

#include <openssl/x509v3.h>
#include <openssl/pem.h>

#include "../common/common.h"

class CTWRAPPER_API RevokedCertificate;

SSLOBJECT_free(X509_REVOKED, X509_REVOKED_free);

class Revoked : public SSLObject < X509_REVOKED > {
public:
	SSLOBJECT_new(Revoked, X509_REVOKED){}
	SSLOBJECT_new_null(Revoked, X509_REVOKED, X509_REVOKED_new){}

	Handle<Revoked> duplicate();

	//Properties
public:
	Handle<std::string> getSerialNumber();
	Handle<std::string> getRevocationDate();
	int getReason();
};

#endif //!CMS_PKI_REVOKED_H_INCLUDED
