#include <openssl/x509v3.h>

#include "../common/common.h"

class CTWRAPPER_API CSR;

#include "pki.h"

SSLOBJECT_free(X509_REQ, X509_REQ_free)

class CSR : public SSLObject < X509_REQ > {
public:
	//Constructor
	SSLOBJECT_new(CSR, X509_REQ){}
	SSLOBJECT_new_null(CSR, X509_REQ, X509_REQ_new){}

	CSR(Handle<std::string> x509Name, Handle<Key> key, const char* digest);

	void sign(Handle<Key> key, const char* digest);
	bool verify();
	void write(Handle<Bio> out, DataFormat::DATA_FORMAT format);

	void setSubject(Handle<std::string> x509Name);
	void setSubjectPublicKey(Handle<Key> key);

	Handle<std::string> getEncoded();
};
