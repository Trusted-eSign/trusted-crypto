#ifndef CMS_PKI_ALGS_H_INCLUDED
#define  CMS_PKI_ALGS_H_INCLUDED

#include <openssl/x509.h>

#include "../common/common.h"

class CTWRAPPER_API AlgorithmCollection;

#include "pki.h"

SSLOBJECT_free(stack_st_X509_ALGOR, sk_X509_ALGOR_free)

class AlgorithmCollection :public SSLObject<stack_st_X509_ALGOR> {
public:
	SSLOBJECT_new(AlgorithmCollection, stack_st_X509_ALGOR){}
	SSLOBJECT_new_null(AlgorithmCollection, stack_st_X509_ALGOR, sk_X509_ALGOR_new_null){}

	void push(Handle<Algorithm>item);
	void pop();
	void removeAt(int index);

public:
	int length();
	Handle<Algorithm> items(int index);
};

#endif //!CMS_PKI_ALGS_H_INCLUDED
