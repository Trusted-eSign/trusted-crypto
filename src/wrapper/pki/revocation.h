#ifndef PKI_REVOCATION_H_INCLUDED
#define PKI_REVOCATION_H_INCLUDED

#include "../common/common.h"
#include "../store/pkistore.h"

class CTWRAPPER_API CRL;

#include "crl.h"
#include "cert.h"

class Revocation{
public:	
	Handle<CRL> getCRL(Handle<Certificate> cert, Handle<PkiStore> pkiStore);
protected:
	boolean getCrlLocal(Handle<CRL> &outCrl, Handle<Certificate> cert, Handle<PkiStore> pkiStore);
};

#endif //!PKI_REVOCATION_H_INCLUDED
