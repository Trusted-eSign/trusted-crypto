#ifndef CMS_CERT_ID_H_INCLUDED
#define CMS_CERT_ID_H_INCLUDED

#include "../common/common.h"

class CTWRAPPER_API CertificateId;

#include "common.h"

class CertificateId {
public:
	//Constructor
	CertificateId(){};
	~CertificateId(){};

	//Properties
	void setIssuerName(Handle<X509Name> value);
	Handle<X509Name> getIssuerName();
	void setSerialNumber(Handle<std::string> value);
	Handle<std::string> getSerialNumber();
	void setKeyId(Handle<std::string> value);
	Handle<std::string> getKeyId();

	//Methods


protected:
	Handle<X509Name> issuerName;
	Handle<std::string> serialNumber;
	Handle<std::string> keyid;
};

#endif  // !CMS_CERT_ID_H_INCLUDED

