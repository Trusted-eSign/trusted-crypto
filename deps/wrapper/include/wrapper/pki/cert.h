#ifndef CMS_PKI_CERT_H_INCLUDED
#define  CMS_PKI_CERT_H_INCLUDED

#include <vector>

#include <openssl/x509v3.h>
#include <openssl/pem.h>

#include "../common/common.h"

class CTWRAPPER_API Certificate;

#include "pki.h"
#include "key.h"
#include "exts.h"
#include "cert_request.h"

#define SERIAL_RAND_BITS 64

SSLOBJECT_free(X509, X509_free);

class Certificate : public SSLObject < X509 > {
public:
	//constructor
	SSLOBJECT_new(Certificate, X509){}
	SSLOBJECT_new_null(Certificate, X509, X509_new){}

	Certificate(Handle<CertificationRequest> csr);

	//properties
	long getVersion();
	Handle<std::string> getSerialNumber();
	Handle<std::string> getNotBefore();
	Handle<std::string> getNotAfter();
	Handle<std::string> getIssuerFriendlyName();
	Handle<std::string> getIssuerName();
	Handle<std::string> getSubjectFriendlyName();
	Handle<std::string> getSubjectName();
	Handle<std::string> getThumbprint();
	Handle<std::string> getPublicKeyAlgorithm();
	Handle<std::string> getSignatureAlgorithm();
	Handle<std::string> getSignatureDigestAlgorithm();
	Handle<std::string> getOrganizationName();
	Handle<Key> getPublicKey();
	std::vector<std::string> getOCSPUrls();
	std::vector<std::string> getCAIssuersUrls();
	Handle<ExtensionCollection> getExtensions();
	int getType();
	int getKeyUsage();
	bool isSelfSigned();
	bool isCA();

	void setSubject(Handle<std::string> x509Name);
	void setIssuer(Handle<std::string> x509Name);
	void setVersion(long version);
	void setExtensions(Handle<ExtensionCollection> exts);
	void setNotBefore(Handle<std::string> notBefore);
	void setNotAfter(Handle<std::string> notAfter);
	void setSerialNumber(Handle<std::string> serial);

	//Methods
	void read(Handle<Bio> in, DataFormat::DATA_FORMAT format);
	void write(Handle<Bio> out, DataFormat::DATA_FORMAT format);
	Handle<Certificate> duplicate();
	int compare(Handle<Certificate> cert);
	bool equals(Handle<Certificate> cert);
	Handle<std::string> hash(Handle<std::string> algorithm);
	Handle<std::string> hash(const EVP_MD *md);
	void sign(Handle<Key> key, const char* digest);

protected:
	static Handle<std::string> GetCommonName(X509_NAME *a);
};

char *i2t_X509_NAME_CN(X509_NAME *a, char* buf, int len);

#endif //!CMS_PKI_CERT_H_INCLUDED
