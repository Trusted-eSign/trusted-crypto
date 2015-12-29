#ifndef CMS_PKI_CHAIN_H_INCLUDED
#define  CMS_PKI_CHAIN_H_INCLUDED

//#include <openssl/x509v3.h>
//
//#include "../common/common.h"
//
//#define ERROR_CRL_BAD_INPUT_DATA "Input data is not CRL"
//#define ERROR_CRL_BAD_DIR_INPUT_DATA "Input data is not binary CRL format"
//#define ERROR_CRL_BAD_PEM_INPUT_DATA "Input data is not PEM CRL format"
//
//class CTWRAPPER_API CRL;
//class CTWRAPPER_API RevokedCertificate;
//
//#include "pki.h"
//
//SSLOBJECT_free(X509_CRL, X509_CRL_free);
//
//class CRL : public SSLObject < X509_CRL > {
//public:
//	SSLOBJECT_new(CRL, X509_CRL){}
//	SSLOBJECT_new_null(CRL, X509_CRL, X509_CRL_new){}
//
//	void read(Handle<Bio> in, DataFormat format);
//	void write(Handle<Bio> out, DataFormat format);
//	Handle<CRL> duplicate();
//
//	Handle<RevokedCertificate> getCertificate(Handle<Certificate> cert);
//	Handle<RevokedCertificate> getCertificate(Handle<std::string> serial);
//
//	//Properties
//public:
//	int version();
//	Handle<std::string> issuerName();
//	Handle<std::string> lastUpdate();
//	Handle<std::string> nextUpdate();
//};
//
//
//SSLOBJECT_free(X509_REVOKED, X509_REVOKED_free);
//class RevokedCertificate : public SSLObject < X509_REVOKED > {
//public:
//	SSLOBJECT_new(RevokedCertificate, X509_REVOKED){}
//	SSLOBJECT_new_null(RevokedCertificate, X509_REVOKED, X509_REVOKED_new){}
//
//	//Properties
//public:
//	Handle<std::string> revocationDate();
//	int reason();
//};

#endif //!CMS_PKI_CHAIN_H_INCLUDED
