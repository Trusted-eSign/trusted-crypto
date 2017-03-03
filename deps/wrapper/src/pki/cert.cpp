#include "../stdafx.h"

#include "wrapper/pki/cert.h"

Handle<Key> Certificate::getPublicKey() {
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

void Certificate::read(Handle<Bio> in, DataFormat::DATA_FORMAT format){
	LOGGER_FN();

	if (in.isEmpty())
		THROW_EXCEPTION(0, Certificate, NULL, "Parameter %d cann't be NULL", 1);

	X509 *cert = NULL;

	in->reset();

	switch (format){
	case DataFormat::DER:
		LOGGER_OPENSSL(d2i_X509_bio);
		cert = d2i_X509_bio(in->internal(), NULL);
		break;
	case DataFormat::BASE64:
		LOGGER_OPENSSL(PEM_read_bio_X509);
		cert = PEM_read_bio_X509(in->internal(), NULL, NULL, NULL);
		break;
	default:
		THROW_EXCEPTION(0, Certificate, NULL, ERROR_DATA_FORMAT_UNKNOWN_FORMAT, format);
	}

	if (!cert) {
		THROW_EXCEPTION(0, Certificate, NULL, "Can not read X509 data from BIO");
	}

	this->setData(cert);
}

void Certificate::write(Handle<Bio> out, DataFormat::DATA_FORMAT format){
	LOGGER_FN();

	if (out.isEmpty())
		THROW_EXCEPTION(0, Certificate, NULL, "Parameter %d is NULL", 1);

	switch (format){
	case DataFormat::DER:
		LOGGER_OPENSSL(i2d_X509_bio);
		if (i2d_X509_bio(out->internal(), this->internal()) < 1)
			THROW_OPENSSL_EXCEPTION(0, Certificate, NULL, "i2d_X509_bio", NULL);
		break;
	case DataFormat::BASE64:
		LOGGER_OPENSSL(PEM_write_bio_X509);
		if (PEM_write_bio_X509(out->internal(), this->internal()) < 1)
			THROW_OPENSSL_EXCEPTION(0, Certificate, NULL, "PEM_write_bio_X509", NULL);
		break;
	default:
		THROW_EXCEPTION(0, Certificate, NULL, ERROR_DATA_FORMAT_UNKNOWN_FORMAT, format);
	}
}

#include <openssl/cms.h>

Handle<std::string> Certificate::getSubjectFriendlyName()
{
	LOGGER_FN();

	LOGGER_OPENSSL(X509_get_subject_name);
	return GetCommonName(X509_get_subject_name(this->internal()));
}

Handle<std::string> Certificate::getIssuerFriendlyName()
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

Handle<std::string> Certificate::getSubjectName()
{
	LOGGER_FN();

	LOGGER_OPENSSL(X509_get_subject_name);
	X509_NAME *name = X509_get_subject_name(this->internal());
	if (!name)
		THROW_EXCEPTION(0, Certificate, NULL, "X509_NAME is NULL");

	LOGGER_OPENSSL(X509_NAME_oneline_ex);
	std::string str_name = X509_NAME_oneline_ex(name);

	Handle<std::string> res = new std::string(str_name.c_str(), str_name.length());

	return res;
}

Handle<std::string> Certificate::getIssuerName()
{
	LOGGER_FN();

	LOGGER_OPENSSL(X509_get_issuer_name);
	X509_NAME *name = X509_get_issuer_name(this->internal());
	if (!name)
		THROW_EXCEPTION(0, Certificate, NULL, "X509_NAME is NULL");

	LOGGER_OPENSSL(X509_NAME_oneline_ex);
	std::string str_name = X509_NAME_oneline_ex(name);

	Handle<std::string> res = new std::string(str_name.c_str(), str_name.length());

	return res;
}

Handle<std::string> Certificate::getNotAfter()
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

Handle<std::string> Certificate::getNotBefore()
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

Handle<std::string> Certificate::getSerialNumber()
{
	LOGGER_FN();

	LOGGER_OPENSSL(BIO_new);
	BIO * bioSerial = BIO_new(BIO_s_mem());
	LOGGER_OPENSSL(i2a_ASN1_INTEGER);
	if (i2a_ASN1_INTEGER(bioSerial, X509_get_serialNumber(this->internal())) < 0){
		THROW_OPENSSL_EXCEPTION(0, Certificate, NULL, "i2a_ASN1_INTEGER", NULL);
	}

	int contlen;
	char * cont;
	LOGGER_OPENSSL(BIO_get_mem_data);
	contlen = BIO_get_mem_data(bioSerial, &cont);

	Handle<std::string> res = new std::string(cont, contlen);

	BIO_free(bioSerial);

	return res;
}

Handle<std::string> Certificate::getSignatureAlgorithm() {
	LOGGER_FN();

	LOGGER_OPENSSL(X509_get_signature_nid);
	int sig_nid = X509_get_signature_nid(this->internal());
	if (!sig_nid){
		THROW_OPENSSL_EXCEPTION(0, Certificate, NULL, "Unknown signature nid");
	}

	LOGGER_OPENSSL(OBJ_nid2ln);
	return new std::string(OBJ_nid2ln(sig_nid));
}

Handle<std::string> Certificate::getSignatureDigest() {
	LOGGER_FN();

	int signature_nid = 0, md_nid = 0;
	const EVP_MD *type;

	LOGGER_OPENSSL("X509_get_signature_nid");
	signature_nid = X509_get_signature_nid(this->internal());
	if (!signature_nid){
		THROW_OPENSSL_EXCEPTION(0, SignedData, NULL, "Unknown signature nid");
	}

	LOGGER_OPENSSL("OBJ_find_sigid_algs");
	if (!OBJ_find_sigid_algs(signature_nid, &md_nid, NULL)) {
		THROW_OPENSSL_EXCEPTION(0, SignedData, NULL, "Error find sigid algs");
	}

	if (!md_nid){
		THROW_OPENSSL_EXCEPTION(0, SignedData, NULL, "Unknown digest name");
	}

	return new std::string(OBJ_nid2sn(md_nid));
}

Handle<std::string> Certificate::getOrganizationName(){
	LOGGER_FN();

	X509_NAME * a = NULL;
	Handle<std::string> organizationName = new std::string("");
	if ((a = X509_get_subject_name(this->internal())) == NULL) {
		THROW_OPENSSL_EXCEPTION(0, Certificate, NULL, "Cannot get subject name");
	}		

	int nid = NID_organizationName;
	LOGGER_OPENSSL(X509_NAME_get_index_by_NID);
	int index = X509_NAME_get_index_by_NID(a, nid, -1);
	if (index >= 0) {
		LOGGER_OPENSSL(X509_NAME_get_entry);
		X509_NAME_ENTRY *subjectNameOrganizationName = X509_NAME_get_entry(a, index);

		if (subjectNameOrganizationName) {
			LOGGER_OPENSSL(X509_NAME_ENTRY_get_data);
			ASN1_STRING *organizationCNASN1 = X509_NAME_ENTRY_get_data(subjectNameOrganizationName);

			if (organizationCNASN1 != NULL) {
				unsigned char *utf = NULL;
				LOGGER_OPENSSL(ASN1_STRING_to_UTF8);
				ASN1_STRING_to_UTF8(&utf, organizationCNASN1);
				organizationName = new std::string((char *)utf);
				OPENSSL_free(utf);
			}
		}
	}
	else {
		return new std::string("");
	}

	return organizationName;
}

int Certificate::compare(Handle<Certificate> cert){
	LOGGER_FN();

	LOGGER_OPENSSL(X509_cmp);
	int res = X509_cmp(this->internal(), cert->internal());

	return res;
}

Handle<std::string> Certificate::getThumbprint()
{
	LOGGER_FN();

	return this->hash(EVP_sha1());
}

long Certificate::getVersion(){
	LOGGER_FN();

	LOGGER_OPENSSL(X509_get_version);
	long res = X509_get_version(this->internal());

	return res;
}

int Certificate::getType(){
	LOGGER_FN();

	LOGGER_OPENSSL(X509_get_pubkey);
	EVP_PKEY *pk = X509_get_pubkey(this->internal());
	if (!pk)
		THROW_OPENSSL_EXCEPTION(0, Certificate, NULL, "X509_get_pubkey", NULL);

	return pk->type;
}

int Certificate::getKeyUsage(){
	LOGGER_FN();

	LOGGER_OPENSSL(X509_check_purpose);
	X509_check_purpose(this->internal(), -1, -1);
	if (this->internal()->ex_flags & EXFLAG_KUSAGE)
		return this->internal()->ex_kusage;

	return UINT32_MAX;
}

bool Certificate::equals(Handle<Certificate> cert){
	LOGGER_FN();

	Handle<std::string> cert1 = this->getThumbprint();
	Handle<std::string> cert2 = cert->getThumbprint();

	if (cert1->compare(*cert2) == 0){
		return true;
	}
	return false;
}

Handle<std::string> Certificate::hash(Handle<std::string> algorithm){
	LOGGER_FN();

	LOGGER_OPENSSL(EVP_get_digestbyname);
	const EVP_MD *md = EVP_get_digestbyname(algorithm->c_str());
	if (!md) {
		THROW_OPENSSL_EXCEPTION(0, Certificate, NULL, "EVP_get_digestbyname");
	}

	return this->hash(md);
}

Handle<std::string> Certificate::hash(const EVP_MD *md) {
	LOGGER_FN();

	unsigned char hash[EVP_MAX_MD_SIZE] = { 0 };
	unsigned int hashlen = 0;

	LOGGER_OPENSSL(X509_digest);
	if (!X509_digest(this->internal(), md, hash, &hashlen)) {
		THROW_OPENSSL_EXCEPTION(0, Certificate, NULL, "X509_digest");
	}

	Handle<std::string> res = new std::string((char *)hash, hashlen);

	return res;
}