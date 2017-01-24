#include "../stdafx.h"

#include "cert_request.h"
#include "key.h"

CertificationRequest::CertificationRequest(Handle<CertificationRequestInfo> csrinfo) :SSLObject<X509_REQ>(X509_REQ_new(), &so_X509_REQ_free){
	LOGGER_FN();

	try{
		if (csrinfo->isEmpty()){
			THROW_EXCEPTION(0, CertificationRequest, NULL, "X509_REQ_info empty");
		}

		this->internal()->req_info = csrinfo->internal();		
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, CertificationRequest, e, "Error create certification request");
	}
}

void CertificationRequest::sign(Handle<Key> key, const char* digest){
	LOGGER_FN();

	try{
		const EVP_MD *md_alg = NULL;

		LOGGER_OPENSSL(EVP_get_digestbyname);
		md_alg = EVP_get_digestbyname(digest);
		if (!md_alg){
			THROW_EXCEPTION(0, CertificationRequest, NULL, "Can not get digest by name");
		}

		LOGGER_OPENSSL(X509_REQ_sign);
		if (!X509_REQ_sign(this->internal(), key->internal(), md_alg)){
			THROW_OPENSSL_EXCEPTION(0, CertificationRequest, NULL, "X509_REQ_sign 'Error sign X509_REQ'");
		}

	}
	catch (Handle<Exception> e){
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
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, CertificationRequest, e, "Error get pem CSR");
	}
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