#ifndef CMS_SIGNER_ID_H_INCLUDED
#define CMS_SIGNER_ID_H_INCLUDED

#include "../common/common.h"

class CTWRAPPER_API SignerId;

#include "common.h"

class SignerId {
public:
	//Constructor
	SignerId(){};
	~SignerId(){};

	//Properties
	void setIssuerName(Handle<std::string> name);
	Handle<std::string> getIssuerName();
	void setSerialNumber(Handle<std::string> value);
	Handle<std::string> getSerialNumber();
	void setKeyId(Handle<std::string> value);
	Handle<std::string> getKeyId();
protected:
	Handle<std::string> issuerName;
	Handle<std::string> serialNumber;
	Handle<std::string> keyid;
};

#endif  // !CMS_SIGNER_ID_H_INCLUDED

