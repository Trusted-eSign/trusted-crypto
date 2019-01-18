#include "../stdafx.h"

#include "wrapper/pki/cert_request.h"
#include "wrapper/pki/key.h"

CertificationRequest::CertificationRequest(Handle<CertificationRequestInfo> csrinfo) :SSLObject<X509_REQ>(X509_REQ_new(), &so_X509_REQ_free){
	LOGGER_FN();

	try{
		if (csrinfo->isEmpty()){
			THROW_EXCEPTION(0, CertificationRequest, NULL, "X509_REQ_info empty");
		}

		this->internal()->req_info = csrinfo->internal();		
	}
	catch (Handle<Exception> &e){
		THROW_EXCEPTION(0, CertificationRequest, e, "Error create certification request");
	}
}

void CertificationRequest::sign(Handle<Key> key, const char* digest){
	LOGGER_FN();

	try{
		const EVP_MD *md_alg = NULL;
		int md_type = 0;

		if (key.isEmpty()) {
			THROW_EXCEPTION(0, CertificationRequest, NULL, "Empty key");
		}

		if (!digest) {
			LOGGER_OPENSSL(EVP_PKEY_get_default_digest_nid);
			if (EVP_PKEY_get_default_digest_nid(key->internal(), &md_type) <= 0) {
				THROW_OPENSSL_EXCEPTION(0, CertificationRequest, NULL, "default digest for key type not found");
			}

			LOGGER_OPENSSL(EVP_get_digestbynid);
			md_alg = EVP_get_digestbynid(md_type);
		}
		else {
			LOGGER_OPENSSL(EVP_get_digestbyname);
			md_alg = EVP_get_digestbyname(digest);
		}

		if (!md_alg){
			THROW_EXCEPTION(0, CertificationRequest, NULL, "Can not get digest by name");
		}

		LOGGER_OPENSSL(X509_REQ_sign);
		if (!X509_REQ_sign(this->internal(), key->internal(), md_alg)){
			THROW_OPENSSL_EXCEPTION(0, CertificationRequest, NULL, "X509_REQ_sign 'Error sign X509_REQ'");
		}

	}
	catch (Handle<Exception> &e){
		THROW_EXCEPTION(0, CertificationRequest, e, "Error sign csr");
	}
}

bool CertificationRequest::verify(){
	EVP_PKEY *pkey = NULL;
	int res = 0;

	pkey = X509_REQ_get_pubkey(this->internal());
	if (!pkey){
		THROW_EXCEPTION(0, CertificationRequest, NULL, "X509_REQ_get_pubkey");
	}

	int i = X509_REQ_verify(this->internal(), pkey);
	EVP_PKEY_free(pkey);
	pkey = NULL;

	if (i < 0){
		THROW_EXCEPTION(0, CertificationRequest, NULL, "Verify failure");
	}
	else if (i == 0){
		THROW_EXCEPTION(0, CertificationRequest, NULL, "Verify failure");
	}
	else{
		res = 1;
	}

	return res;
}

Handle<std::string> CertificationRequest::getPEMString(){
	LOGGER_FN();

	try{
		LOGGER_OPENSSL(BIO_new);
		BIO * bio_out = BIO_new(BIO_s_mem());

		LOGGER_OPENSSL(PEM_write_bio_X509_REQ);
		if (!PEM_write_bio_X509_REQ(bio_out, this->internal())){
			THROW_OPENSSL_EXCEPTION(0, CertificationRequest, NULL, "PEM_write_bio_X509_REQ");
		}
		BUF_MEM *bio_buf;
		LOGGER_OPENSSL(BIO_get_mem_ptr);
		BIO_get_mem_ptr(bio_out, &bio_buf);
		Handle<std::string> res = new std::string(bio_buf->data, bio_buf->length);
		LOGGER_OPENSSL(BIO_free);
		BIO_free(bio_out);

		return res;
	}
	catch (Handle<Exception> &e){
		THROW_EXCEPTION(0, CertificationRequest, e, "Error get pem CSR");
	}
}

Handle<CertificationRequest> CertificationRequest::duplicate(){
	LOGGER_FN();

	X509_REQ *req = NULL;

	LOGGER_OPENSSL(X509_REQ_dup);
	req = X509_REQ_dup(this->internal());
	if (!req) {
		THROW_EXCEPTION(0, CertificationRequest, NULL, "X509_REQ_dup");
	}

	return new CertificationRequest(req);
}

void CertificationRequest::read(Handle<Bio> in, DataFormat::DATA_FORMAT format){
	LOGGER_FN();

	if (in.isEmpty())
		THROW_EXCEPTION(0, CertificationRequest, NULL, "Parameter %d cann't be NULL", 1);

	X509_REQ *req = NULL;

	in->reset();

	switch (format){
	case DataFormat::DER:
		LOGGER_OPENSSL(d2i_X509_REQ_bio);
		req = d2i_X509_REQ_bio(in->internal(), NULL);
		break;
	case DataFormat::BASE64:
		LOGGER_OPENSSL(PEM_read_bio_X509);
		req = PEM_read_bio_X509_REQ(in->internal(), NULL, NULL, NULL);
		break;
	default:
		THROW_EXCEPTION(0, CertificationRequest, NULL, ERROR_DATA_FORMAT_UNKNOWN_FORMAT, format);
	}

	if (!req) {
		THROW_EXCEPTION(0, CertificationRequest, NULL, "Can not read X509_REQ data from BIO");
	}

	this->setData(req);
}

void CertificationRequest::write(Handle<Bio> out, DataFormat::DATA_FORMAT format){
	LOGGER_FN();

	if (out.isEmpty()) {
		THROW_EXCEPTION(0, Certificate, NULL, "CertificationRequest is NULL");
	}

	switch (format){
	case DataFormat::DER:
		LOGGER_OPENSSL(i2d_X509_REQ_bio);
		if (i2d_X509_REQ_bio(out->internal(), this->internal()) < 1)
			THROW_OPENSSL_EXCEPTION(0, CertificationRequest, NULL, "i2d_X509_REQ_bio", NULL);
		break;
	case DataFormat::BASE64:
		LOGGER_OPENSSL(PEM_write_bio_X509_REQ);
		if (PEM_write_bio_X509_REQ(out->internal(), this->internal()) < 1)
			THROW_OPENSSL_EXCEPTION(0, CertificationRequest, NULL, "CertificationRequest", NULL);
		break;
	default:
		THROW_EXCEPTION(0, CertificationRequest, NULL, ERROR_DATA_FORMAT_UNKNOWN_FORMAT, format);
	}
}

void CertificationRequest::setSubject(Handle<std::string> xName) {
	LOGGER_FN();

	try{
		if (xName.isEmpty()){
			THROW_EXCEPTION(0, CertificationRequest, NULL, "Parameter 1 can not be NULL");
		}

		LOGGER_OPENSSL(X509_NAME_new);
		X509_NAME *name = X509_NAME_new();

		std::string strName = xName->c_str();
		strName = strName + "/";

		std::string sl = "/";
		std::string eq = "=";

		size_t pos = 0, posInBuf = 0;

		std::string buf, field, param;

		while ((pos = strName.find(sl)) != std::string::npos)  {
			buf = strName.substr(0, pos);
			if (buf.length() > 0){
				posInBuf = buf.find(eq);
				field = buf.substr(0, posInBuf);
				param = buf.substr(posInBuf + 1, buf.length());

				LOGGER_OPENSSL(X509_NAME_add_entry_by_txt);
				if (!X509_NAME_add_entry_by_txt(name, field.c_str(), MBSTRING_UTF8, (const unsigned char *)param.c_str(), -1, -1, 0)){
					THROW_OPENSSL_EXCEPTION(0, CertificationRequest, NULL, "X509_NAME_add_entry_by_txt 'Unable add param to X509_NAME'");
				}
			}
			strName.erase(0, pos + sl.length());
		}

		LOGGER_OPENSSL(X509_NAME_dup);
		if (!X509_REQ_set_subject_name(this->internal(), name)) {
			X509_NAME_free(name);

			THROW_OPENSSL_EXCEPTION(0, CertificationRequest, NULL, "X509_REQ_set_subject_name 'Error set subject name'");
		}

		if (name){
			LOGGER_OPENSSL(X509_NAME_free);
			X509_NAME_free(name);
		}
	}
	catch (Handle<Exception> &e){
		THROW_EXCEPTION(0, CertificationRequest, e, "Error set subject to X509_REQ_info");
	}
}

void CertificationRequest::setPublicKey(Handle<Key> key){
	LOGGER_FN();

	if (key.isEmpty()){
		THROW_EXCEPTION(0, CertificationRequest, NULL, "Key is empty");
	}

	LOGGER_OPENSSL(X509_REQ_set_pubkey);
	if (!X509_REQ_set_pubkey(this->internal(), key->internal())) {
		THROW_OPENSSL_EXCEPTION(0, CertificationRequest, NULL, "X509_REQ_set_pubkey");
	}
}

void CertificationRequest::setVersion(long version){
	LOGGER_FN();

	LOGGER_OPENSSL(X509_REQ_set_version);
	if (!X509_REQ_set_version(this->internal(), version)) {
		THROW_OPENSSL_EXCEPTION(0, CertificationRequest, NULL, "X509_REQ_set_version");
	}
}

void CertificationRequest::setExtensions(Handle<ExtensionCollection> exts) {
	LOGGER_FN();

	try {
		if (exts.isEmpty()) {
			THROW_EXCEPTION(0, CertificationRequest, NULL, "Extensions is empty");
		}

		if (this->internal()->req_info->attributes) {
			LOGGER_OPENSSL(sk_X509_ATTRIBUTE_new_null);
			if (!(this->internal()->req_info->attributes = sk_X509_ATTRIBUTE_new_null())) {
				THROW_OPENSSL_EXCEPTION(0, CertificationRequest, NULL, "sk_X509_ATTRIBUTE_new_null");
			}
		}

		LOGGER_OPENSSL(X509_REQ_add_extensions);
		if (!X509_REQ_add_extensions(this->internal(), exts->internal())) {
			THROW_OPENSSL_EXCEPTION(0, CertificationRequest, NULL, "Error add extensions");
		}

		return;
	}
	catch (Handle<Exception> &e) {
		THROW_EXCEPTION(0, CertificationRequest, e, "Error set extensions");
	}
}

Handle<std::string> CertificationRequest::getSubject() {
	LOGGER_FN();

	LOGGER_OPENSSL(X509_REQ_get_subject_name);
	X509_NAME *name = X509_REQ_get_subject_name(this->internal());
	if (!name) {
		THROW_EXCEPTION(0, CertificationRequest, NULL, "X509_REQ_INFO subject is NULL");
	}

	LOGGER_OPENSSL(X509_NAME_oneline_ex);
	std::string str_name = X509_NAME_oneline_ex(name);

	Handle<std::string> res = new std::string(str_name.c_str(), str_name.length());

	return res;
}

long CertificationRequest::getVersion() {
	LOGGER_FN();

	LOGGER_OPENSSL(X509_REQ_get_version);
	long res = X509_REQ_get_version(this->internal());

	return res;
}

Handle<Key> CertificationRequest::getPublicKey() {
	LOGGER_FN();

	EVP_PKEY *epkey = NULL;
	
	LOGGER_OPENSSL(X509_REQ_get_pubkey);
	epkey = X509_REQ_get_pubkey(this->internal());

	if (!epkey) {
		THROW_OPENSSL_EXCEPTION(0, CertificationRequest, NULL, "X509_REQ_get_pubkey");
	}

	return new Key(epkey);
}

Handle<ExtensionCollection> CertificationRequest::getExtensions() {
	LOGGER_FN();

	X509_EXTENSIONS *exts = NULL;

	LOGGER_OPENSSL(X509_REQ_get_extensions);
	exts = X509_REQ_get_extensions(this->internal());

	return new ExtensionCollection(exts);
}

Handle<Certificate> CertificationRequest::toCertificate(int days, Handle<Key> key) {
	LOGGER_FN();

	X509 *res = NULL;

	if (days <= 0) {
		THROW_EXCEPTION(0, CertificationRequest, NULL, "Days can not be <= 0");
	}

	if (key->isEmpty()) {
		THROW_EXCEPTION(0, CertificationRequest, NULL, "Key can not be empty");
	}

	LOGGER_OPENSSL(X509_REQ_to_X509);
	if ( !(res = X509_REQ_to_X509(this->internal(), days, key->internal())) ) {
		THROW_OPENSSL_EXCEPTION(0, CertificationRequest, NULL, "X509_REQ_to_X509");
	}

	return new Certificate(res);
}
