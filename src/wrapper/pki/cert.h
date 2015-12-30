#ifndef CMS_PKI_CERT_H_INCLUDED
#define  CMS_PKI_CERT_H_INCLUDED

#include <openssl/x509v3.h>
#include <openssl/pem.h>

#include "../common/common.h"

class CTWRAPPER_API Certificate;

#include "pki.h"
#include "key.h"


SSLOBJECT_free(X509, X509_free);

class Certificate: public SSLObject<X509> {
public:
	SSLOBJECT_new(Certificate, X509){}
	SSLOBJECT_new_null(Certificate, X509, X509_new){}

	void load(std::string filename);
	void read(Handle<Bio> in);
	void write(Handle<Bio> out);
	Handle<Key> publicKey();
	Handle<Certificate> duplicate();
	int compare(Handle<Certificate> cert);

	Handle<std::string> subjectFriendlyName();
	Handle<std::string> issuerFriendlyName();
	Handle<std::string> subjectName();
	Handle<std::string> issuerName();
	Handle<std::string> serialNumber();
    int type();
    int keyUsage();
	long version();

	Handle<std::string> notAfter();
	Handle<std::string> notBefore();
    Handle<std::string> thumbprint();
protected:
	static Handle<std::string> GetCommonName(X509_NAME *a);
};

char *i2t_X509_NAME_CN(X509_NAME *a, char* buf, int len);

#endif //!CMS_PKI_CERT_H_INCLUDED
