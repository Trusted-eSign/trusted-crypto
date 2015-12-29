#include "../stdafx.h"

//#include <openssl/ctgostcp.h>
//#include <openssl/ctcrypto.h>

#include "crl.h"

void CRL::read(Handle<Bio> in, DataFormat::DATA_FORMAT format) {
	LOGGER_FN();

	if (in.isEmpty())
		THROW_EXCEPTION(0, CRL, NULL, ERROR_PARAMETER_NULL, 1);
	X509_CRL *crl = NULL;
	switch (format){
	case DataFormat::BASE64:
		LOGGER_OPENSSL("PEM_read_bio_X509_CRL");
		crl = PEM_read_bio_X509_CRL(in->internal(), NULL, NULL, NULL);
		if (!crl)
			THROW_EXCEPTION(0, CRL, NULL, ERROR_CRL_BAD_PEM_INPUT_DATA);
		break;
	case DataFormat::DER:
		LOGGER_OPENSSL("d2i_X509_CRL_bio");
		crl = d2i_X509_CRL_bio(in->internal(), NULL);
		if (!crl)
			THROW_EXCEPTION(0, CRL, NULL, ERROR_CRL_BAD_DIR_INPUT_DATA);
		break;
	default:
		THROW_EXCEPTION(0, CRL, NULL, ERROR_DATA_FORMAT_UNKNOWN_FORMAT, format);
	}
	this->setData(crl);
}

void CRL::write(Handle<Bio> out, DataFormat::DATA_FORMAT format) {
	LOGGER_FN();

	if (out.isEmpty())
		THROW_EXCEPTION(0, CRL, NULL, ERROR_PARAMETER_NULL, 1);
	switch (format){
	case DataFormat::DER:
		LOGGER_OPENSSL(i2d_X509_CRL_bio);
		if (!i2d_X509_CRL_bio(out->internal(), this->internal()))
			THROW_EXCEPTION(1, CRL, NULL, "i2d_X509_CRL_bio");
		break;
	case DataFormat::BASE64:
		LOGGER_OPENSSL(PEM_write_bio_X509_CRL);
		if (!PEM_write_bio_X509_CRL(out->internal(), this->internal()))
			THROW_EXCEPTION(1, CRL, NULL, "PEM_write_bio_X509_CRL");
		break;
	}
	out->flush();
}

Handle<CRL> CRL::duplicate()
{
	LOGGER_FN();

	X509_CRL *crl = NULL;
	LOGGER_OPENSSL(X509_CRL_dup);
	crl = X509_CRL_dup(this->internal());
	if (!crl)
		THROW_EXCEPTION(1, CRL, NULL, "X509_CRL_dup");
	return new CRL(crl);
}

int CRL::version()
{
	LOGGER_FN();
	
	return X509_CRL_get_version(this->internal());
}

Handle<std::string> CRL::issuerName()
{
	LOGGER_FN();
	

	LOGGER_OPENSSL(X509_CRL_get_issuer);
	X509_NAME *name = X509_CRL_get_issuer(this->internal());
	if (!name)
		THROW_EXCEPTION(1, CRL, NULL, "X509_NAME is NULL");

	LOGGER_OPENSSL(X509_NAME_oneline);
	char *str_name = X509_NAME_oneline(name, NULL, 0);
	if (!str_name)
		THROW_EXCEPTION(1, CRL, NULL, "X509_NAME_oneline");

	Handle<std::string> res = new std::string(str_name);
	OPENSSL_free(str_name);

	return res;
}

Handle<std::string> CRL::nextUpdate(){
	LOGGER_FN();

	LOGGER_OPENSSL(X509_CRL_get_nextUpdate);
	ASN1_TIME *time = X509_CRL_get_nextUpdate(this->internal());
	return ASN1_TIME_toString(time);
}

Handle<std::string> CRL::lastUpdate(){
	LOGGER_FN();

	LOGGER_OPENSSL(X509_CRL_get_lastUpdate);
	ASN1_TIME *time = X509_CRL_get_lastUpdate(this->internal());
	return ASN1_TIME_toString(time);
}

/*
Handle<RevokedCertificate> CRL::getCertificate(Handle<Certificate> cert)
{
	LOGGER_FN();

	if (cert.isEmpty())
		THROW_EXCEPTION(0, CRL, NULL, ERROR_PARAMETER_NULL, 1);
	X509_REVOKED *rc = NULL;
	LOGGER_OPENSSL(X509_CRL_get0_by_cert);
	if (X509_CRL_get0_by_cert(this->internal(), &rc, cert->internal())){
		return new RevokedCertificate(rc, this->handle());
	}
	else{
		return NULL;
	}
}
*/

Handle<std::string> RevokedCertificate::revocationDate()
{
	LOGGER_FN();

	ASN1_TIME *time = this->internal()->revocationDate;
	return ASN1_TIME_toString(time);
}

int RevokedCertificate::reason()
{
	LOGGER_FN();

	return this->internal()->reason;
}
