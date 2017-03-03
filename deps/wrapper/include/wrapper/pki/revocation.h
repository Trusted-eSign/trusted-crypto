#ifndef PKI_REVOCATION_H_INCLUDED
#define PKI_REVOCATION_H_INCLUDED

#include "../common/common.h"
#include "../store/pkistore.h"

class CTWRAPPER_API CRL;

#include "crl.h"
#include "cert.h"
#include "../store/pkistore.h"

class Revocation{
public:	
	Handle<CRL> getCrlLocal(Handle<Certificate> cert, Handle<PkiStore> pkiStore);
	bool checkCrlTime(Handle<CRL> crl);
	std::vector<std::string> getCrlDistPoints(Handle<Certificate> cert);
};

#endif //!PKI_REVOCATION_H_INCLUDED
