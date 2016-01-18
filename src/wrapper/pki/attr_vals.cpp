#include "../stdafx.h"

#include "attr_vals.h"

AttributeValueCollection::AttributeValueCollection(Handle<Attribute> data) {
	LOGGER_FN();

	this->init();
	this->data_ = data;
	this->set_ = data->internal()->value.set;
	if (this->set_ == NULL) {
		LOGGER_OPENSSL(sk_ASN1_TYPE_new_null);
		this->set_ = sk_ASN1_TYPE_new_null();
		data->internal()->single = 0;
	}
}

AttributeValueCollection::~AttributeValueCollection() {
	LOGGER_FN();
}

void AttributeValueCollection::init() {
	LOGGER_FN();

	this->data_ = NULL;
	this->set_ = NULL;
}

int AttributeValueCollection::length() {
	LOGGER_FN();

	LOGGER_OPENSSL(sk_ASN1_TYPE_num);
	return sk_ASN1_TYPE_num(this->set_);
}

void AttributeValueCollection::push(std::string &val) {
	LOGGER_FN();

	const unsigned char* _val = (const unsigned char*) val.c_str();
	LOGGER_OPENSSL(d2i_ASN1_TYPE);
	ASN1_TYPE *t = d2i_ASN1_TYPE(NULL, &_val, val.length());
	if (t->type != this->data_->getAsnType())
		THROW_EXCEPTION(0, AttributeValueCollection, NULL, "Parameter 1 isn't ASN1 binary");
	sk_ASN1_TYPE_push(this->set_, t);
}

void AttributeValueCollection::push(void *val) {
	LOGGER_FN();
	LOGGER_OPENSSL(ASN1_TYPE_new);
	ASN1_TYPE *_type = ASN1_TYPE_new();
	LOGGER_OPENSSL(ASN1_TYPE_set1);
	ASN1_TYPE_set1(_type, this->data_->getAsnType(), val);
	LOGGER_OPENSSL(sk_ASN1_TYPE_push);
	sk_ASN1_TYPE_push(this->set_, _type);
}

void AttributeValueCollection::pop() {
	LOGGER_FN();

	LOGGER_OPENSSL(sk_ASN1_TYPE_pop);
	sk_ASN1_TYPE_pop(this->set_);
}

void AttributeValueCollection::removeAt(int index) {
	LOGGER_FN();

	LOGGER_OPENSSL(sk_ASN1_TYPE_delete);
	sk_ASN1_TYPE_delete(this->set_, index);
}

Handle<std::string> AttributeValueCollection::items(int index) {
	LOGGER_FN();

	LOGGER_OPENSSL(sk_ASN1_TYPE_value);
	ASN1_TYPE *_type = sk_ASN1_TYPE_value(this->set_, index);
	if (!_type)
		THROW_EXCEPTION(0, AttributeValueCollection, NULL, "OPENSSL:sk_ASN1_TYPE_value");
	
	LOGGER_OPENSSL(i2d_ASN1_TYPE);
	int len = i2d_ASN1_TYPE(_type, NULL);
	unsigned char *out = NULL;
	
	LOGGER_OPENSSL(i2d_ASN1_TYPE);
	i2d_ASN1_TYPE(_type, &out);

	Handle<std::string> res = new std::string((char *) out, len);
	
	return res; 
}

void AttributeValueCollection::set(int index, std::string val){
	LOGGER_FN();

	const unsigned char* _val = (const unsigned char*)val.c_str();
	LOGGER_OPENSSL(d2i_ASN1_TYPE);
	ASN1_TYPE *t = d2i_ASN1_TYPE(NULL, &_val, val.length());
	
	if (!sk_ASN1_TYPE_set(this->set_, index, t)){
		THROW_EXCEPTION(0, AttributeValueCollection, NULL, "sk_ASN1_TYPE_set");
	}
}

void AttributeValueCollection::set(int index, void *val){
	LOGGER_FN();

	LOGGER_OPENSSL(ASN1_TYPE_new);
	ASN1_TYPE *_type = ASN1_TYPE_new();
	
	LOGGER_OPENSSL(sk_ASN1_TYPE_set);
	if (!sk_ASN1_TYPE_set(this->set_, index, _type))
		THROW_EXCEPTION(0, AttributeValueCollection, NULL, "sk_ASN1_TYPE_set");
}
