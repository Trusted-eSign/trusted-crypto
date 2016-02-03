#include "../stdafx.h"

#include "csr.h"
#include "key.h"
#include "certRegInfo.h"
#include "certReg.h"

CSR::CSR(Handle<std::string> x509Name, Handle<Key> key, const char* digest){
	LOGGER_FN();

	try{
		Handle<CertificationRequestInfo> csrinfo;
		Handle<CertificationRequest> csrreq;

		csrinfo = new CertificationRequestInfo();
		csrinfo->setVersion(0L); /*Version 1*/
		csrinfo->setSubject(x509Name);
		csrinfo->setSubjectPublicKey(key);
		
		csrreq = new CertificationRequest(csrinfo);
		csrinfo->setParent(csrreq->handle());
		csrreq->sign(key, digest);
		if (!csrreq->verify()){
			THROW_EXCEPTION(0, CSR, NULL, "Error verify X509_REQ");
		}
		
		LOGGER_OPENSSL(X509_REQ_dup);
		req = X509_REQ_dup(csrreq->internal());
		if (!req){
			THROW_EXCEPTION(0, CSR, NULL, "Error dup X509_REQ");
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, CSR, e, "Error create csr");
	}
}

void CSR::write(Handle<Bio> out, DataFormat::DATA_FORMAT format){
	LOGGER_FN();

	if (req == NULL){
		THROW_EXCEPTION(0, CSR, NULL, "X509_REQ is NULL", 1);
	}
	if (out.isEmpty()){
		THROW_EXCEPTION(0, CSR, NULL, "Parameter %d is NULL", 1);
	}
		
	switch (format){

	case DataFormat::DER:
		LOGGER_OPENSSL(i2d_X509_REQ_bio);
		if (i2d_X509_REQ_bio(out->internal(), req) < 1){
			THROW_OPENSSL_EXCEPTION(0, CSR, NULL, "i2d_X509_REQ_bio", NULL);
		}			
		break;

	case DataFormat::BASE64:
		LOGGER_OPENSSL(PEM_write_bio_X509_REQ);
		if (PEM_write_bio_X509_REQ(out->internal(), req) < 1){
			THROW_OPENSSL_EXCEPTION(0, CSR, NULL, "PEM_write_bio_X509_REQ", NULL);
		}			
		break;

	default:
		THROW_EXCEPTION(0, CSR, NULL, ERROR_DATA_FORMAT_UNKNOWN_FORMAT, format);
	}
}

Handle<std::string> CSR::getEncodedHEX(){
	LOGGER_FN();

	try{
		LOGGER_OPENSSL(BIO_new);
		BIO * bio_out = BIO_new(BIO_s_mem());

		LOGGER_OPENSSL(PEM_write_bio_X509_REQ);
		if (!PEM_write_bio_X509_REQ(bio_out, req)){
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