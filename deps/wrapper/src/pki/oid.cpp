#include "../stdafx.h"

#include <openssl/objects.h>

#include "wrapper/pki/oid.h"

OID::OID(const std::string& val)
	: SSLObject<ASN1_OBJECT>(ASN1_OBJECT_new(), &so_ASN1_OBJECT_free)
{
	LOGGER_FN();

	if (!strcmp(val.c_str(), "1.2.643.100.111")) {
		int nid;
		nid = OBJ_create("1.2.643.100.111", "subjectSignTool", "subjectSignTool");
		X509V3_EXT_add_alias(nid, NULL);
	}
	else if (!strcmp(val.c_str(), "1.2.643.100.112")) {
		int nid;
		nid = OBJ_create("1.2.643.100.112", "issuerSignTool", "issuerSignTool");
		X509V3_EXT_add_alias(nid, NULL);
	}

	ASN1_OBJECT *obj = OBJ_txt2obj(val.c_str(), 0);
	if (obj) {
		this->setData(obj);
	}
	else {
		THROW_EXCEPTION(0, OID, NULL, "Wrong OID text value");
	}
}

int OID::toNid() {
	LOGGER_FN();

	return OBJ_obj2nid(this->internal());
}

Handle<std::string> OID::toString() {
	LOGGER_FN();

	char buf[100];
	LOGGER_OPENSSL(OBJ_obj2txt);
	int bufLen = 0;
	if ((bufLen = OBJ_obj2txt(buf, 100, this->internal(), 1)) <= 0)
		THROW_OPENSSL_EXCEPTION(0, Algorithm, NULL, "OBJ_obj2txt");
	std::string *res = new std::string(buf, bufLen);
	return res;
}

Handle<std::string> OID::getLongName(){
	LOGGER_FN();

	const char *buf;
	LOGGER_OPENSSL(OBJ_nid2ln);
	buf = OBJ_nid2ln(this->toNid());
	if (!buf)
		THROW_OPENSSL_EXCEPTION(0, Algorithm, NULL, "OBJ_nid2ln");
	std::string *res = new std::string(buf);
	return res;
}

Handle<std::string> OID::getShortName(){
	LOGGER_FN();

	const char *buf;
	LOGGER_OPENSSL(OBJ_nid2sn);
	buf = OBJ_nid2sn(this->toNid());
	if (!buf)
		THROW_OPENSSL_EXCEPTION(0, Algorithm, NULL, "OBJ_nid2sn");
	std::string *res = new std::string(buf);
	return res;
}

Handle<std::string> OID::getValue(){
	LOGGER_FN();

	return this->toString();
}