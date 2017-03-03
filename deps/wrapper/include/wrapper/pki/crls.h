#ifndef CMS_PKI_CRLS_H_INCLUDED
#define  CMS_PKI_CRLS_H_INCLUDED

#include "../common/common.h"

class CTWRAPPER_API CrlCollection;

#include "crl.h"

SSLOBJECT_free(stack_st_X509_CRL, sk_X509_CRL_free)

class CrlCollection : public SSLObject < stack_st_X509_CRL > {
public:
	SSLOBJECT_new(CrlCollection, stack_st_X509_CRL){}
	SSLOBJECT_new_null(CrlCollection, stack_st_X509_CRL, sk_X509_CRL_new_null){}

	//methods
	void push(Handle<CRL> crl);
	void pop();
	void removeAt(int index);
	int length();
	Handle<CRL> items(int index);
};

#endif //!CMS_PKI_CRLS_H_INCLUDED
