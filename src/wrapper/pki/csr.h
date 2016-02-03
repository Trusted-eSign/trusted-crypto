#ifndef CMS_PKI_CSR_H_INCLUDED
#define  CMS_PKI_CSR_H_INCLUDED

#include <openssl/x509v3.h>

#include "../common/common.h"

class CTWRAPPER_API CSR;

#include "pki.h"

class CSR{
public:
	X509_REQ *req;
public:
	
	CSR(Handle<std::string> x509Name, Handle<Key> key, const char* digest);

	void write(Handle<Bio> out, DataFormat::DATA_FORMAT format);

	Handle<std::string> getEncodedHEX();
};

#endif