#ifndef CMS_PKI_ATTRS_H_INCLUDED
#define  CMS_PKI_ATTRS_H_INCLUDED

#include <openssl/x509.h>

#include "../common/common.h"

class CTWRAPPER_API AttributeCollection;

#include "pki.h"
#include "oid.h"
#include "attr.h"

SSLOBJECT_free(stack_st_X509_ATTRIBUTE, sk_X509_ATTRIBUTE_free)

class AttributeCollection: public SSLObject<stack_st_X509_ATTRIBUTE> {
public:
	SSLOBJECT_new(AttributeCollection, stack_st_X509_ATTRIBUTE){}
	SSLOBJECT_new_null(AttributeCollection, stack_st_X509_ATTRIBUTE, sk_X509_ATTRIBUTE_new_null){}
	AttributeCollection(stack_st_X509_ATTRIBUTE** data, Handle<SObject> parent = NULL);

	void push(Handle<Attribute> attr); //void push(Handle<Attribute> &attr);
	void pop();
	Handle<Attribute> items(int index);
	Handle<Attribute> items(Handle<OID> oid);
	Handle<Attribute> items(const std::string &txtOID); 
	Handle<Attribute> items(const char* oid);
	Handle<AttributeCollection> duplicate();
	int length();

protected:

protected:
	stack_st_X509_ATTRIBUTE **data__;
};

#endif //!CMS_PKI_ATTRS_H_INCLUDED
