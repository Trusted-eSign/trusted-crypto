#include "stdafx.h"

#include "attrs.h"

AttributeCollection::AttributeCollection(stack_st_X509_ATTRIBUTE **data, Handle<SObject> parent)
	:SSLObject<stack_st_X509_ATTRIBUTE>(sk_X509_ATTRIBUTE_new_null(), &so_stack_st_X509_ATTRIBUTE_free, parent)
{
	LOGGER_FN();

	if (parent.isEmpty())
		THROW_EXCEPTION(0, AttributeCollection, NULL, "Parameter 2 can not be NULL");

	this->data__ = data;
	if (data)
		this->setData((*data));
}

void AttributeCollection::push(Handle<Attribute>attr) {
	LOGGER_FN();

	if (this->data__ != NULL)
		if (!(*this->data__)){
			(*this->data__) = sk_X509_ATTRIBUTE_new_null();
			this->setData((*this->data__));
		}
	LOGGER_OPENSSL(X509_ATTRIBUTE_dup);
	X509_ATTRIBUTE *_attr = X509_ATTRIBUTE_dup(attr->internal());
	if (!_attr) THROW_EXCEPTION(0, AttributeCollection, NULL, "X509_ATTRIBUTE_dup");
	
	LOGGER_OPENSSL(sk_X509_ATTRIBUTE_push);
	sk_X509_ATTRIBUTE_push(this->internal(), _attr);
}

void AttributeCollection::pop() {
	LOGGER_FN();

	LOGGER_OPENSSL(sk_X509_ATTRIBUTE_pop);
	sk_X509_ATTRIBUTE_pop(this->internal());
}

Handle<Attribute> AttributeCollection::items(int index) {
	LOGGER_FN();

	LOGGER_OPENSSL(sk_X509_ATTRIBUTE_value);
	X509_ATTRIBUTE *res = sk_X509_ATTRIBUTE_value(this->internal(), index);
	return new Attribute(res, this->handle());
}

Handle<Attribute> AttributeCollection::items(Handle<OID>oid) {
	LOGGER_FN();

	LOGGER_OPENSSL(X509at_get_attr_by_OBJ);
	int index = X509at_get_attr_by_OBJ(this->internal(), oid->internal(), -1);
	if (index < 0)
		return NULL;
	return this->items(index);
}

Handle<Attribute> AttributeCollection::items(const std::string &txtOID) {
	LOGGER_FN();

	Handle<OID> oid = NULL;
	try{
		 oid = new OID(txtOID);
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, AttributeCollection, e, "Can not create OID");
	}
	return this->items(oid);
}

Handle<Attribute> AttributeCollection::items(const char* oid) {
	LOGGER_FN();

	Handle<OID> hoid = NULL;
	try{
		hoid = new OID(std::string(oid));
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, AttributeCollection, e, "Can not create OID");
	}
	return this->items(hoid);
}

int AttributeCollection::length() {
	LOGGER_FN();

	if (this->isEmpty())
		return 0;
	LOGGER_OPENSSL(sk_X509_ATTRIBUTE_num);
	int res = sk_X509_ATTRIBUTE_num(this->internal());
	return res;
}

Handle<AttributeCollection> AttributeCollection::duplicate() {
	LOGGER_FN();

	LOGGER_OPENSSL(sk_X509_ATTRIBUTE_dup);
	STACK_OF(X509_ATTRIBUTE) *_copy = sk_X509_ATTRIBUTE_dup(this->internal());
	if (!_copy)
		THROW_EXCEPTION(0, AttributeCollection, NULL, "sk_X509_ATTRIBUTE_dup");
	
	Handle<AttributeCollection> res = new AttributeCollection(_copy);
	return res;
}
