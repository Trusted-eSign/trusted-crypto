#ifndef PKI_REVOCATION_H_INCLUDED
#define PKI_REVOCATION_H_INCLUDED

#include "../common/common.h"
#include "../store/pkistore.h"

class CTWRAPPER_API CRL;

#include "crl.h"
#include "cert.h"

class Revocation{
public:	
	boolean getCrlLocal(Handle<CRL> &outCrl, Handle<Certificate> cert, Handle<PkiStore> pkiStore);
	boolean checkCrlTime(Handle<CRL> crl);
	std::vector<std::string> getCrlDistPoints(Handle<Certificate> cert);
};

#endif //!PKI_REVOCATION_H_INCLUDED
