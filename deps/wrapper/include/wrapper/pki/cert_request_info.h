#ifndef CMS_PKI_CERTREGINFO_H_INCLUDED
#define  CMS_PKI_CERTREGINFO_H_INCLUDED

#include <openssl/x509v3.h>

#include "../common/common.h"

class CTWRAPPER_API CertificationRequestInfo;

#include "pki.h"

SSLOBJECT_free(X509_REQ_INFO, X509_REQ_INFO_free)

class CertificationRequestInfo : public SSLObject < X509_REQ_INFO > {
public:
	//Constructor
	SSLOBJECT_new(CertificationRequestInfo, X509_REQ_INFO){}
	SSLOBJECT_new_null(CertificationRequestInfo, X509_REQ_INFO, X509_REQ_INFO_new){}

	//Methods
	void setSubject(Handle<std::string> x509Name);
	void setSubjectPublicKey(Handle<Key> key);
	void setVersion(long version);

	Handle<std::string> getSubject();
	Handle<Key> getPublicKey();
	long getVersion();
};

#endif