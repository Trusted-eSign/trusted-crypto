#include "../stdafx.h"

#include "cert.h"

void Certificate::load(std::string filename) {
	LOGGER_FN();

	LOGGER_OPENSSL(BIO_new_file);
	BIO* in = BIO_new_file(filename.c_str(), "rb");
	if (in) {
		//read PEM
		LOGGER_OPENSSL(PEM_read_bio_X509);
		X509 *cert = PEM_read_bio_X509(in, NULL, NULL, NULL);
		if (!cert) {
			//read DER
			LOGGER_OPENSSL(BIO_seek);
			BIO_seek(in, 0);
			LOGGER_OPENSSL(d2i_X509_bio);
			cert = d2i_X509_bio(in, NULL);
		}

		if (!cert) {
			throw 1;
		}
		this->setData(cert);
	}
	LOGGER_OPENSSL(BIO_free);
	BIO_free(in);
}

Handle<Key> Certificate::publicKey() {
	LOGGER_FN();

	if (!this->isEmpty()) {
		LOGGER_OPENSSL(X509_get_pubkey);
		EVP_PKEY *key = X509_get_pubkey(this->internal());
		if (!key)
			THROW_EXCEPTION(0, Certificate, NULL, "X509_get_pubkey");;
		return new Key(key, this->handle());
	}
	return NULL;
}

Handle<Certificate> Certificate::duplicate(){
	LOGGER_FN();

	X509 *cert = NULL;
	LOGGER_OPENSSL(X509_dup);
	cert = X509_dup(this->internal());
	if (!cert)
		THROW_EXCEPTION(1, Certificate, NULL, "X509_dup");
	return new Certificate(cert);
}

void Certificate::read(Handle<Bio> in){
	LOGGER_FN();

	if (in.isEmpty())
		THROW_EXCEPTION(0, Certificate, NULL, "Parameter %d cann't be NULL", 1);
	//read PEM
	X509 *cert = NULL;
 
	in->reset();

	switch (in->type()){
	case BIO_TYPE_FILE:
		in->reset();
		LOGGER_OPENSSL(PEM_read_bio_X509);
		cert = PEM_read_bio_X509(in->internal(), NULL, NULL, NULL);
		if (!cert) {
			//read DER
			in->reset();
			LOGGER_OPENSSL(d2i_X509_bio);
			cert = d2i_X509_bio(in->internal(), NULL);
		}
		break;
	case BIO_TYPE_MEM:
		LOGGER_OPENSSL(d2i_X509_bio);
		cert = d2i_X509_bio(in->internal(), NULL);
		break;
	default:
		THROW_EXCEPTION(0, Certificate, NULL, "Unknown BIO type '%d'", in->type());
	}

	if (!cert) {
		THROW_EXCEPTION(0, Certificate, NULL, "Wrong data");
	}

	this->setData(cert);
}

void Certificate::write(Handle<Bio> out){
	LOGGER_FN();

	if (out.isEmpty())
		THROW_EXCEPTION(0, Certificate, NULL, "Parameter %d is NULL", 1);

	LOGGER_OPENSSL(i2d_X509_bio);
	if (i2d_X509_bio(out->internal(), this->internal())<=0)
		THROW_EXCEPTION(0, Certificate, NULL, "i2d_X509_bio");
}

Handle<std::string> Certificate::subjectFriendlyName()
{
	LOGGER_FN();

	LOGGER_OPENSSL(X509_get_subject_name);
	return GetCommonName(X509_get_subject_name(this->internal()));
}

Handle<std::string> Certificate::issuerFriendlyName()
{
	LOGGER_FN();

	LOGGER_OPENSSL(X509_get_issuer_name);
	return GetCommonName(X509_get_issuer_name(this->internal()));
}

Handle<std::string> Certificate::GetCommonName(X509_NAME *a){
	LOGGER_FN();

	Handle<std::string> name = new std::string("");
	if (a == NULL)
		THROW_EXCEPTION(0, Certificate, NULL, "Parameter 1 can not be NULL");

	int nid = NID_commonName;
	LOGGER_OPENSSL(X509_NAME_get_index_by_NID);
	int index = X509_NAME_get_index_by_NID(a, nid, -1);
	if (index >= 0) {
		LOGGER_OPENSSL(X509_NAME_get_entry);
		X509_NAME_ENTRY *issuerNameCommonName = X509_NAME_get_entry(a, index);

		if (issuerNameCommonName) {
			LOGGER_OPENSSL(X509_NAME_ENTRY_get_data);
			ASN1_STRING *issuerCNASN1 = X509_NAME_ENTRY_get_data(issuerNameCommonName);

			if (issuerCNASN1 != NULL) {
				unsigned char *utf = NULL;
				LOGGER_OPENSSL(ASN1_STRING_to_UTF8);
				ASN1_STRING_to_UTF8(&utf, issuerCNASN1);
				name = new std::string((char *)utf);
				OPENSSL_free(utf);
			}
		}
	}
	else {
		return new std::string("No common name");
	}


	return name;
}

Handle<std::string> Certificate::subjectName()
{
	LOGGER_FN();

	LOGGER_OPENSSL(X509_get_subject_name);
	X509_NAME *name = X509_get_subject_name(this->internal());
	if (!name)
		THROW_EXCEPTION(0, Certificate, NULL, "X509_NAME is NULL");

	LOGGER_OPENSSL(X509_NAME_oneline_ex);
	std::string str_name = X509_NAME_oneline_ex(name);
	//if (!str_name)
	//	THROW_EXCEPTION(0, Certificate, NULL, "X509_NAME_oneline_ex");

	Handle<std::string> res = new std::string(str_name.c_str(), str_name.length());
	//OPENSSL_free(str_name);

	return res;
}

Handle<std::string> Certificate::issuerName()
{
	LOGGER_FN();

	LOGGER_OPENSSL(X509_get_issuer_name);
	X509_NAME *name = X509_get_issuer_name(this->internal());
	if (!name)
		THROW_EXCEPTION(0, Certificate, NULL, "X509_NAME is NULL");

	LOGGER_OPENSSL(X509_NAME_oneline_ex);
	std::string str_name = X509_NAME_oneline_ex(name);
	//if (!str_name)
	//	THROW_EXCEPTION(0, Certificate, NULL, "X509_NAME_oneline_ex");

	Handle<std::string> res = new std::string(str_name.c_str(), str_name.length());
	//OPENSSL_free(str_name);

	return res;
}

Handle<std::string> Certificate::notAfter()
{
	LOGGER_FN();

	LOGGER_OPENSSL(X509_get_notAfter);
	ASN1_TIME *time = X509_get_notAfter(this->internal());
	LOGGER_OPENSSL(ASN1_TIME_to_generalizedtime);
	ASN1_GENERALIZEDTIME *gtime = ASN1_TIME_to_generalizedtime(time, NULL);
	Handle<Bio> out = new Bio(BIO_TYPE_MEM, "");
	LOGGER_OPENSSL(ASN1_GENERALIZEDTIME_print);
	ASN1_GENERALIZEDTIME_print(out->internal(), gtime);
	LOGGER_OPENSSL(ASN1_GENERALIZEDTIME_free);
	ASN1_GENERALIZEDTIME_free(gtime);
	return out->read();
}

Handle<std::string> Certificate::notBefore()
{
	LOGGER_FN();

	LOGGER_OPENSSL(X509_get_notBefore);
	ASN1_TIME *time = X509_get_notBefore(this->internal());
	LOGGER_OPENSSL(ASN1_TIME_to_generalizedtime);
	ASN1_GENERALIZEDTIME *gtime = ASN1_TIME_to_generalizedtime(time, NULL);
	Handle<Bio> out = new Bio(BIO_TYPE_MEM, "");
	LOGGER_OPENSSL(ASN1_GENERALIZEDTIME_print);
	ASN1_GENERALIZEDTIME_print(out->internal(), gtime);
	LOGGER_OPENSSL(ASN1_GENERALIZEDTIME_free);
	ASN1_GENERALIZEDTIME_free(gtime);
	return out->read();
}

Handle<std::string> Certificate::serialNumber()
{
	LOGGER_FN();

	LOGGER_OPENSSL(X509_get_serialNumber);
	ASN1_INTEGER *sn = X509_get_serialNumber(this->internal());
	unsigned char* out = NULL;
	LOGGER_OPENSSL(i2d_ASN1_INTEGER);
	int out_len = i2d_ASN1_INTEGER(sn, &out);

	Handle<std::string> res = new std::string((char *)out, out_len);
    
	LOGGER_OPENSSL(OPENSSL_free);
	OPENSSL_free(out);
	return res;
}

int Certificate::compare(Handle<Certificate> cert){
	LOGGER_FN();

	LOGGER_OPENSSL(X509_cmp);
	int res = X509_cmp(this->internal(), cert->internal());

	return res;
}

Handle<std::string> Certificate::thumbprint()
{
    LOGGER_FN();
    
    LOGGER_OPENSSL(EVP_sha1);
    const EVP_MD *md = EVP_sha1();
    
    unsigned char hash[20] = {0};
     
    LOGGER_OPENSSL(X509_digest);
    if (!X509_digest(this->internal(), md, hash, NULL)){
        THROW_OPENSSL_EXCEPTION(0, Certificate, NULL, "X509_digest");
    }
    
	Handle<std::string> res = new std::string((char *)hash, 20);
    
    return res;
}

long Certificate::version(){
    LOGGER_FN();

	LOGGER_OPENSSL(X509_get_version);
	long res = X509_get_version(this->internal());

	return res;   
}

int Certificate::type(){
    LOGGER_FN();
    
    LOGGER_OPENSSL(X509_get_pubkey);
    EVP_PKEY *pk = X509_get_pubkey(this->internal());
    
    return pk->type;
}

int Certificate::keyUsage(){
    LOGGER_FN();
    
    LOGGER_OPENSSL(X509_check_purpose);
    X509_check_purpose(this->internal(), -1, -1);
    if (this->internal()->ex_flags & EXFLAG_KUSAGE)
        return this->internal()->ex_kusage;
    
    return UINT32_MAX;
}