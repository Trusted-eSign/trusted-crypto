#include "../stdafx.h"
#include "alg.h"

Algorithm::Algorithm(const char* alg_name)
	:SSLObject<X509_ALGOR>(X509_ALGOR_new(), &so_X509_ALGOR_free){
	LOGGER_FN();
	try{
		init(alg_name);

	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Algorithm, e, "Can not init Algorithm");
	}
}

Algorithm::Algorithm(Handle<OID> alg_oid)
	:SSLObject<X509_ALGOR>(X509_ALGOR_new(), &so_X509_ALGOR_free){
	LOGGER_FN();

	if (alg_oid.isEmpty())
		THROW_EXCEPTION(0, Algorithm, NULL, "Parameter %d can not be NULL", 1);

	try{
		Handle<std::string> sn = alg_oid->getShortName();
		init(sn->c_str());
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Algorithm, e, "Can not init Algorithm");
	}
}

Handle<Algorithm> Algorithm::duplicate() {
	LOGGER_FN();

	LOGGER_OPENSSL(X509_ALGOR_dup);
	X509_ALGOR *_alg = X509_ALGOR_dup(this->internal());
	if (!_alg) THROW_OPENSSL_EXCEPTION(0, Algorithm, NULL, "X509_ALGOR_dup");
	return new Algorithm(_alg);
}

Handle<OID> Algorithm::getTypeId() {
	LOGGER_FN();

	return new OID(this->internal()->algorithm, this->handle());
}

Handle<std::string> Algorithm::getName() {
	LOGGER_FN();


	X509_ALGOR* alg = this->internal();
	char buf[100];
	LOGGER_OPENSSL(OBJ_obj2txt);
	int bufLen = 0;
	if ((bufLen = OBJ_obj2txt(buf, 100, alg->algorithm, 0)) <= 0)
		THROW_OPENSSL_EXCEPTION(0, Algorithm, NULL, "OBJ_obj2txt");
	std::string *res = new std::string(buf, bufLen);
	return res;
}

void Algorithm::init(const char*alg_name){
	LOGGER_FN();

	LOGGER_OPENSSL(OBJ_sn2nid);
	int nid = OBJ_sn2nid(alg_name);
	if (!nid)
		THROW_EXCEPTION(0, Algorithm, NULL, "Unknown algorithm name '%s'", alg_name);

	LOGGER_OPENSSL(OBJ_nid2obj);
	ASN1_OBJECT *obj = OBJ_nid2obj(nid);
	if (!obj){
		THROW_EXCEPTION(0, Algorithm, NULL, "OBJ_nid2obj(%d)", nid);
	}

	LOGGER_OPENSSL(X509_ALGOR_set0);
	if (!X509_ALGOR_set0(this->internal(), obj, V_ASN1_UNDEF, 0)){
		THROW_EXCEPTION(0, Algorithm, NULL, "X509_ALGOR_set0");
	}
}

bool Algorithm::isDigest(){
	LOGGER_FN();

	LOGGER_OPENSSL(EVP_get_digestbynid);
	const EVP_MD *md = EVP_get_digestbynid(this->getTypeId()->toNid());
	if (md){
		return true;
	}
	return false;
}
