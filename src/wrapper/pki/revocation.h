#ifndef PKI_REVOCATION_H_INCLUDED
#define PKI_REVOCATION_H_INCLUDED

#include "../common/common.h"
#include "../store/pkistore.h"
#include "../store/provider_system.h"

class CTWRAPPER_API CRL;

#include "crl.h"
#include "cert.h"

class Revocation{
public:

	//Methods
	void write(Handle<Bio> out, DataFormat::DATA_FORMAT format);
	
	//Properties
	Handle<CRL> getCRL(Handle<Certificate> cert, Handle<Provider_System> prvSys);

protected:
	Handle<CRL> hcrl;

	const char* getCRLDistPoint(Handle<Certificate> cert);
	//int getCrlLocal(Handle<CRL> &crl, Handle<Certificate> cert, Handle<Provider_System> prvSys);

private:
	int findCRLLocal(Handle<CRL> &crl, Handle<Certificate> x);
	Handle<CRL> downloadCRL(const char* crlURL);
};

#endif //!PKI_REVOCATION_H_INCLUDED
