#ifndef CMS_PKI_ATTR_VALS_H_INCLUDED
#define  CMS_PKI_ATTR_VALS_H_INCLUDED

#include "../common/common.h"

class CTWRAPPER_API AttributeValueCollection;

#include "pki.h"
#include "attr.h"

class AttributeValueCollection {
public:
	AttributeValueCollection(Handle<Attribute>data);
	~AttributeValueCollection();

	void push(std::string &val);
	void push(void *val);
	void set(int index, std::string val);
	void set(int index, void *val);
	void pop();
	void removeAt(int index);
	Handle<std::string> items(int index);
protected:
	void init();
	//-----Properties-----
public:
	int length(); //get
protected:
	Handle<Attribute> data_;
	STACK_OF(ASN1_TYPE) *set_;
};

#endif //  comment this --->  CMS_PKI_ATTR_VALS_H_INCLUDED
