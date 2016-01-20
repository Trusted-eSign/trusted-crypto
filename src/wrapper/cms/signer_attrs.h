#ifndef CMS_SIGNER_ATTR_COLLECTION_H_INCLUDED
#define CMS_SIGNER_ATTR_COLLECTION_H_INCLUDED

#include "common.h"

#include "signer.h"

class CTWRAPPER_API SignerAttributeCollection;

class SignerAttributeCollection {
public:
	//Constructor
	SignerAttributeCollection(Handle<Signer> signer, bool signed_attr);
	~SignerAttributeCollection(){}

	//Properties
	int length();

	//Methods
	Handle<Attribute> items(int index, int location);
	Handle<Attribute> items(int index);
	Handle<Attribute> items(Handle<OID>, int location);
	Handle<Attribute> items(Handle<OID>);
	void push(Handle<Attribute> attr);
	void removeAt(int index);

protected:
	Handle<Signer> signer;
	bool signed_attr;
};

#endif  //!CMS_SIGNER_ATTR_COLLECTION_H_INCLUDED

