#ifndef CMS_PKI_CRL_H_INCLUDED
#define  CMS_PKI_CRL_H_INCLUDED

#include <openssl/x509v3.h>
#include <openssl/pem.h>

#include "../common/common.h"

#define ERROR_CRL_BAD_INPUT_DATA "Input data is not CRL"
#define ERROR_CRL_BAD_DIR_INPUT_DATA "Input data is not binary CRL format"
#define ERROR_CRL_BAD_PEM_INPUT_DATA "Input data is not PEM CRL format"

class CTWRAPPER_API CRL;
class CTWRAPPER_API RevokedCertificate;

#include "pki.h"

SSLOBJECT_free(X509_CRL, X509_CRL_free);

class CRL : public SSLObject < X509_CRL > {
public:
	SSLOBJECT_new(CRL, X509_CRL){}
	SSLOBJECT_new_null(CRL, X509_CRL, X509_CRL_new){}

	//Methods
	void read(Handle<Bio> in, DataFormat::DATA_FORMAT format);
	void write(Handle<Bio> out, DataFormat::DATA_FORMAT format);
	int equals(Handle<CRL> crl);
	Handle<CRL> duplicate();
	Handle<std::string> hash(const EVP_MD *md);
	Handle<std::string> hash(Handle<std::string> algorithm);

	//Handle<RevokedCertificate> getCertificate(Handle<Certificate> cert);
	//Handle<RevokedCertificate> getCertificate(Handle<std::string> serial);
	
	//Properties
	Handle<std::string> getThumbprint();
	Handle<std::string> getEncoded();
	Handle<std::string> getThisUpdate();
	Handle<std::string> getNextUpdate();
	Handle<std::string> getSigAlgName();
	long getVersion();
public:
	Handle<std::string> issuerName();
};


SSLOBJECT_free(X509_REVOKED, X509_REVOKED_free);
class RevokedCertificate : public SSLObject < X509_REVOKED > {
public:
	SSLOBJECT_new(RevokedCertificate, X509_REVOKED){}
	SSLOBJECT_new_null(RevokedCertificate, X509_REVOKED, X509_REVOKED_new){}

	//Properties
public:
	Handle<std::string> revocationDate();
	int reason();
};

#endif //!CMS_PKI_CRL_H_INCLUDED
