#include "../stdafx.h"

#include "revoked.h"

Handle<std::string> Revoked::getRevocationDate()
{
	LOGGER_FN();

	ASN1_TIME *time = this->internal()->revocationDate;
	LOGGER_OPENSSL(ASN1_TIME_to_generalizedtime);
	ASN1_GENERALIZEDTIME *gtime = ASN1_TIME_to_generalizedtime(time, NULL);
	Handle<Bio> out = new Bio(BIO_TYPE_MEM, "");
	LOGGER_OPENSSL(ASN1_GENERALIZEDTIME_print);
	ASN1_GENERALIZEDTIME_print(out->internal(), gtime);
	LOGGER_OPENSSL(ASN1_GENERALIZEDTIME_free);
	ASN1_GENERALIZEDTIME_free(gtime);
	return out->read();
}

Handle<std::string> Revoked::getSerialNumber() {
	LOGGER_FN();

	LOGGER_OPENSSL(BIO_new);
	BIO * bioSerial = BIO_new(BIO_s_mem());
	LOGGER_OPENSSL(i2a_ASN1_INTEGER);
	if (i2a_ASN1_INTEGER(bioSerial, this->internal()->serialNumber) < 0){
		THROW_OPENSSL_EXCEPTION(0, Revoked, NULL, "i2a_ASN1_INTEGER", NULL);
	}

	int contlen;
	char * cont;
	LOGGER_OPENSSL(BIO_get_mem_data);
	contlen = BIO_get_mem_data(bioSerial, &cont);

	Handle<std::string> sn_str = new std::string(cont, contlen);

	BIO_free(bioSerial);

	return sn_str;
}

Handle<std::string> Revoked::getReason()
{
	LOGGER_FN();

	Handle<Bio> out = new Bio(BIO_TYPE_MEM, "");
	STACK_OF(X509_EXTENSION) *exts = this->internal()->extensions;
	LOGGER_OPENSSL(sk_X509_EXTENSION_num);
	for (int i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
		X509_EXTENSION *ex;
		LOGGER_OPENSSL(sk_X509_EXTENSION_value);
        ex = sk_X509_EXTENSION_value(exts, i);
		LOGGER_OPENSSL(X509V3_EXT_print);
		X509V3_EXT_print(out->internal(), ex, NULL, 0);
	}
	
	return out->read();
}

Handle<Revoked> Revoked::duplicate(){
	LOGGER_FN();

	X509_REVOKED *r = NULL;
	LOGGER_OPENSSL(X509_REVOKED_dup);
	r = X509_REVOKED_dup(this->internal());
	if (!r)
		THROW_EXCEPTION(1, Revoked, NULL, "X509_REVOKED_dup");
	return new Revoked(r);
}
