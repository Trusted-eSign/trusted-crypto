#include "stdafx.h"

#include "attr.h"

Attribute::Attribute(Handle<OID> oid, int asnType)
	:SSLObject<X509_ATTRIBUTE>(X509_ATTRIBUTE_new(), &so_X509_ATTRIBUTE_free)
{
	LOGGER_FN();

	LOGGER_OPENSSL(X509_ATTRIBUTE_create_by_txt);
	X509_ATTRIBUTE *attr =  X509_ATTRIBUTE_create_by_txt(NULL, oid->toString()->c_str(), 0, NULL, -1);
	if (!attr)
		THROW_EXCEPTION(0, Attribute, NULL, "X509_ATTRIBUTE_create_by_txt");
	this->setData(attr);
	this->asnType_ = asnType;
}

Attribute::Attribute(const std::string& oid, int asnType)
	:SSLObject<X509_ATTRIBUTE>(X509_ATTRIBUTE_new(), &so_X509_ATTRIBUTE_free)
{
	LOGGER_FN();

	LOGGER_OPENSSL(X509_ATTRIBUTE_create_by_txt);
	X509_ATTRIBUTE *attr = X509_ATTRIBUTE_create_by_txt(NULL, oid.c_str(), 0, NULL, -1);
	if (!attr)
		THROW_EXCEPTION(0, Attribute, NULL, "X509_ATTRIBUTE_create_by_txt");
	this->setData(attr);
	this->asnType_ = asnType;
}

Handle<std::string> Attribute::toString() {
	LOGGER_FN();

	unsigned char *_out = NULL;
	LOGGER_OPENSSL(i2d_X509_ATTRIBUTE);
	int len = i2d_X509_ATTRIBUTE(this->internal(), &_out);
	std::string *res = new std::string((char *)_out, len);
	OPENSSL_free(_out);
	return res;
}

Handle<OID> Attribute::typeId() {
	LOGGER_FN();

	if (this->internal() && this->internal()->object) {
		Handle<OID> res = new OID(this->internal()->object, false);
		return res;
	}
	return NULL;
}

void Attribute::typeId(Handle<OID> &oid) {
	LOGGER_FN();

	LOGGER_OPENSSL(X509_ATTRIBUTE_set1_object);
	if (!X509_ATTRIBUTE_set1_object(this->internal(), oid->internal())) {
		THROW_EXCEPTION(0, Attribute, NULL, "X509_ATTRIBUTE_set1_object");
	}
}

void Attribute::typeId(std::string oid) {
	LOGGER_FN();

	try {
		Handle<OID> _oid = new OID(oid);
		this->typeId(_oid);
	}
	catch (Handle<Exception> e) {
		THROW_EXCEPTION(0, Attribute, e, "No comment");
	}
}

Handle<AttributeValueCollection> Attribute::values() {
	LOGGER_FN();

	return new AttributeValueCollection(this);
}

Handle<std::string> Attribute::values(int index) {
	LOGGER_FN();

	Handle<std::string> res = new std::string(this->values()->items(index));
	return res;
}

int Attribute::asnType() {
	LOGGER_FN();

	return this->asnType_;
}

void Attribute::asnType(int val) {
	LOGGER_FN();

	this->asnType_ = val;
}
