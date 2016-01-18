#ifndef CMS_PKI_ALG_H_INCLUDED
#define  CMS_PKI_ALG_H_INCLUDED

#include <openssl/x509.h>

#include "../common/common.h"

class CTWRAPPER_API Algorithm;

#include "pki.h"
#include "oid.h"

SSLOBJECT_free(X509_ALGOR, X509_ALGOR_free)

class Algorithm : public SSLObject < X509_ALGOR > {
public:
	//Constructor
	SSLOBJECT_new(Algorithm, X509_ALGOR){}
	SSLOBJECT_new_null(Algorithm, X509_ALGOR, X509_ALGOR_new){}
	Algorithm(const char* alg_name);
	Algorithm(Handle<OID> alg_oid);

	//Properties
	Handle<OID> getTypeId();
	Handle<std::string> getName();

	//Methods
	Handle<Algorithm> duplicate();
	bool isDigest();

protected:
	void init(const char*alg_name);
};

#endif  //!CMS_PKI_ALG_H_INCLUDED
