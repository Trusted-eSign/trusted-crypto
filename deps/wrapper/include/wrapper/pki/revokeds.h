#ifndef PKI_REVOKEDS_H_INCLUDED
#define  PKI_REVOKEDS_H_INCLUDED

#include <openssl/crypto.h>

#include "../common/common.h"

#include "revoked.h"

class CTWRAPPER_API RevokedCollection;

SSLOBJECT_free(stack_st_X509_REVOKED, sk_X509_REVOKED_free)

class RevokedCollection : public SSLObject < stack_st_X509_REVOKED > {
public:
	SSLOBJECT_new(RevokedCollection, stack_st_X509_REVOKED){}
	SSLOBJECT_new_null(RevokedCollection, stack_st_X509_REVOKED, sk_X509_REVOKED_new_null){}

	//methods
	void push(Handle<Revoked> r);
	void pop();
	void removeAt(int index);
	int length();
	Handle<Revoked> items(int index);
};

#endif //!PKI_REVOKEDS_H_INCLUDED
