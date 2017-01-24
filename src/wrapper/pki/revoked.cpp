#include "../stdafx.h"

#include "revoked.h"

Handle<std::string> Revoked::revocationDate()
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

int Revoked::reason()
{
	LOGGER_FN();

	return this->internal()->reason;
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
