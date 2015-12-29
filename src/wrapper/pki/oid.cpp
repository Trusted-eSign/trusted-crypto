#include "stdafx.h"

#include <openssl/objects.h>

#include "oid.h"

OID::OID(const std::string& val)
	: SSLObject<ASN1_OBJECT>(ASN1_OBJECT_new(), &so_ASN1_OBJECT_free)
{
	ASN1_OBJECT *obj = OBJ_txt2obj(val.c_str(), 0);
	if (obj) {
		this->setData(obj);
	} else {
		THROW_EXCEPTION(0, OID, NULL, "Wrong OID text value");
	}
}

int OID::toNID() {
	return OBJ_obj2nid(this->internal());
}

Handle<std::string> OID::toString() {
	char buf[100];
	LOGGER_OPENSSL(OBJ_obj2txt);
	int bufLen = 0;
	if ((bufLen = OBJ_obj2txt(buf, 100, this->internal(), 1)) <= 0)
		THROW_OPENSSL_EXCEPTION(0, Algorithm, NULL, "OBJ_obj2txt");
	std::string *res = new std::string(buf, bufLen);
	return res;
}
