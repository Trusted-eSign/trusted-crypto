#ifndef CMS_PKI_CERTREG_H_INCLUDED
#define  CMS_PKI_CERTREG_H_INCLUDED

#include <openssl/x509v3.h>

#include "../common/common.h"

class CTWRAPPER_API CertificationRequest;

#include "pki.h"
#include "cert_request_info.h"

SSLOBJECT_free(X509_REQ, X509_REQ_free)

class CertificationRequest : public SSLObject < X509_REQ > {
public:
	//Constructor
	SSLOBJECT_new(CertificationRequest, X509_REQ){}
	SSLOBJECT_new_null(CertificationRequest, X509_REQ, X509_REQ_new){}

	CertificationRequest(Handle<CertificationRequestInfo> csrinfo);

	//Methods
	void read(Handle<Bio> in, DataFormat::DATA_FORMAT format);
	void sign(Handle<Key> key, const char* digest);
	bool verify();

	//Properties
	Handle<std::string> getPEMString();
};

#endif