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

	void read(Handle<Bio> in, DataFormat::DATA_FORMAT format);
	void write(Handle<Bio> out, DataFormat::DATA_FORMAT format);
	Handle<CertificationRequest> duplicate();

	void setSubject(Handle<std::string> x509Name);
	void setPublicKey(Handle<Key> key);
	void setVersion(long version);

	Handle<std::string> getSubject();
	Handle<Key> getPublicKey();
	long getVersion();

	void sign(Handle<Key> key, const char* digest);
	bool verify();

	Handle<Certificate> toCertificate(int days, Handle<Key> key);

	Handle<std::string> getPEMString();
};

#endif