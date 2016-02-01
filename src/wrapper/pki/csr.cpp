#include "../stdafx.h"

#include "csr.h"
#include "key.h"

CSR::CSR(Handle<std::string> x509Name, Handle<Key> key, const char* digest)	:SSLObject<X509_REQ>(X509_REQ_new(), &so_X509_REQ_free){
	LOGGER_FN();

	try{
		LOGGER_OPENSSL(X509_REQ_new);
		X509_REQ *req = X509_REQ_new();
		if (!req){
			THROW_EXCEPTION(0, CSR, NULL, "X509_REQ_new");
		}

		/* version 1 */
		LOGGER_OPENSSL(X509_REQ_set_version);
		if (!X509_REQ_set_version(req, 0L)){
			THROW_OPENSSL_EXCEPTION(0, CSR, NULL, "X509_REQ_set_version", NULL);
		};

		this->setSubject(x509Name);
		this->setSubjectPublicKey(key);
		this->sign(key, digest);

		if (!this->verify()){
			THROW_EXCEPTION(0, CSR, NULL, "CSR verify failure");
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, CSR, e, "Error create csr");
	}	
}

void CSR::setSubject(Handle<std::string> xName) {
	LOGGER_FN();

	try{
		if (xName->length() == NULL){
			THROW_EXCEPTION(0, CSR, NULL, "Parameter 1 can not be NULL");
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
				if (!X509_NAME_add_entry_by_txt(name, field.c_str(), MBSTRING_ASC, (const unsigned char *)param.c_str(), -1, -1, 0)){
					THROW_OPENSSL_EXCEPTION(0, CSR, NULL, "X509_NAME_add_entry_by_txt 'Unable add param to X509_NAME'");
				}
			}
			strName.erase(0, pos + sl.length());
		}

		LOGGER_OPENSSL(X509_REQ_set_subject_name);
		if (!X509_REQ_set_subject_name(this->internal(), name)){
			LOGGER_OPENSSL(X509_NAME_free);
			X509_NAME_free(name);
			THROW_OPENSSL_EXCEPTION(0, CSR, NULL, "X509_REQ_set_subject_name 'Unable set subject name to X509_REQ'");
		}

	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, CSR, e, "Error set subject to X509_REQ");
	}	
}

void CSR::setSubjectPublicKey(Handle<Key> key){
	LOGGER_FN();

	if (!X509_REQ_set_pubkey(this->internal(), key->internal())){
		THROW_OPENSSL_EXCEPTION(0, CSR, NULL, "X509_REQ_set_pubkey 'Unable set pubkey to X509_REQ'");
	}

}

void CSR::sign(Handle<Key> key, const char* digest){
	LOGGER_FN();

	try{
		const EVP_MD *md_alg = NULL;

		LOGGER_OPENSSL(EVP_get_digestbyname);
		md_alg = EVP_get_digestbyname(digest);
		if (!md_alg){
			THROW_EXCEPTION(0, CSR, NULL, "Can not get digest by name");
		}

		LOGGER_OPENSSL(X509_REQ_sign);
		if (!X509_REQ_sign(this->internal(), key->internal(), md_alg)){
			THROW_OPENSSL_EXCEPTION(0, CSR, NULL, "X509_REQ_sign 'Error sign X509_REQ'");
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, CSR, e, "Error sign csr");
	}	
}

bool CSR::verify(){
	EVP_PKEY *pkey = NULL;
	int res = 0;

	pkey = X509_REQ_get_pubkey(this->internal());
	if (!pkey){
		THROW_EXCEPTION(0, CSR, NULL, "X509_REQ_get_pubkey");
	}

	int i = X509_REQ_verify(this->internal(), pkey);
	EVP_PKEY_free(pkey);
	pkey = NULL;

	if (i < 0){
		THROW_EXCEPTION(0, CSR, NULL, "Verify failure");
	}
	else if (i == 0){
		THROW_EXCEPTION(0, CSR, NULL, "Verify failure");
	}
	else{
		res = 1;
	}
		
	return res;
}

void CSR::write(Handle<Bio> out, DataFormat::DATA_FORMAT format){
	LOGGER_FN();

	if (out.isEmpty()){
		THROW_EXCEPTION(0, SignedData, NULL, "Parameter %d is NULL", 1);
	}
		
	switch (format){

	case DataFormat::DER:
		LOGGER_OPENSSL(i2d_X509_REQ_bio);
		if (i2d_X509_REQ_bio(out->internal(), this->internal()) < 1){
			THROW_OPENSSL_EXCEPTION(0, CSR, NULL, "i2d_X509_REQ_bio", NULL);
		}			
		break;

	case DataFormat::BASE64:
		LOGGER_OPENSSL(PEM_write_bio_X509_REQ);
		if (PEM_write_bio_X509_REQ(out->internal(), this->internal()) < 1){
			THROW_OPENSSL_EXCEPTION(0, CSR, NULL, "PEM_write_bio_X509_REQ", NULL);
		}			
		break;

	default:
		THROW_EXCEPTION(0, CSR, NULL, ERROR_DATA_FORMAT_UNKNOWN_FORMAT, format);
	}
}

Handle<std::string> CSR::getEncoded(){
	LOGGER_FN();

	try{
		LOGGER_OPENSSL(BIO_new);
		BIO * bio_out = BIO_new(BIO_s_mem());

		LOGGER_OPENSSL(PEM_write_bio_X509_REQ);
		if (!PEM_write_bio_X509_REQ(bio_out, this->internal())){
			THROW_OPENSSL_EXCEPTION(0, CSR, NULL, "PEM_write_bio_X509_REQ");
		}
		BUF_MEM *bio_buf;
		LOGGER_OPENSSL(BIO_get_mem_ptr);
		BIO_get_mem_ptr(bio_out, &bio_buf);
		Handle<std::string> res = new std::string(bio_buf->data, bio_buf->length);
		LOGGER_OPENSSL(BIO_free);
		BIO_free(bio_out);

		return res;
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, CSR, e, "Error get encoded CSR");
	}
}