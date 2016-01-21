#include "../stdafx.h"

#include "signed_data.h"

Handle<CertificateCollection> SignedData::certificates(){
	LOGGER_FN();

	STACK_OF(X509) *certs;

	LOGGER_OPENSSL(CMS_get1_certs);
	certs = CMS_get1_certs(this->internal());

	if (!certs){
		THROW_OPENSSL_EXCEPTION(0, SignedData, NULL, "CMS_get1_certs");
	}

	return new CertificateCollection(certs);
}

Handle<Certificate> SignedData::certificates(int index){
	LOGGER_FN();

	return this->certificates()->items(index);
}

Handle<SignerCollection> SignedData::signers(){
	LOGGER_FN();

	stack_st_CMS_SignerInfo *signers_ = CMS_get0_SignerInfos(this->internal());

	if (!signers_){
		THROW_OPENSSL_EXCEPTION(0, SignedData, NULL, "Has no signers");
	}

	return new SignerCollection(signers_, this->handle());
}

Handle<Signer> SignedData::signers(int index){
	LOGGER_FN();

	return this->signers()->items(index);
}

bool SignedData::isDetached(){
	LOGGER_FN();

	LOGGER_OPENSSL(CMS_is_detached);
	int res = CMS_is_detached(this->internal());

	if (res == -1){
		THROW_OPENSSL_EXCEPTION(0, SignedData, NULL, "CMS_is_detached");
	}

	return res == 1;
}

void SignedData::read(Handle<Bio> in, DataFormat::DATA_FORMAT format){
	if (in.isEmpty())
		THROW_EXCEPTION(0, SignedData, NULL, "Parameter %d cann't be NULL", 1);

	CMS_ContentInfo *ci = NULL;

	in->reset();

	switch (format){
	case DataFormat::DER:
		LOGGER_OPENSSL("d2i_CMS_bio");
		ci = d2i_CMS_bio(in->internal(), NULL);
		break;
	case DataFormat::BASE64:
		LOGGER_OPENSSL("SMIME_read_CMS");
		ci = SMIME_read_CMS(in->internal(), NULL);
		break;
	default:
		THROW_EXCEPTION(0, SignedData, NULL, ERROR_DATA_FORMAT_UNKNOWN_FORMAT, format);
	}

	if (!ci) {
		puts(OpenSSL::printErrors()->c_str());
		THROW_EXCEPTION(0, SignedData, NULL, "Can not read CMS signed data from BIO");
	}

	this->setData(ci);
}

void SignedData::write(Handle<Bio> out, DataFormat::DATA_FORMAT format){
	LOGGER_FN();

	if (out.isEmpty())
		THROW_EXCEPTION(0, SignedData, NULL, "Parameter %d is NULL", 1);

	switch (format){
	case DataFormat::DER:
		LOGGER_OPENSSL("i2d_X509_bio");
		//TODO: i2d_CMS_bio_stream
		if (i2d_CMS_bio(out->internal(), this->internal()) < 1)
			THROW_OPENSSL_EXCEPTION(0, SignedData, NULL, "i2d_X509_bio", NULL);
		break;
	case DataFormat::BASE64:
		THROW_EXCEPTION(0, SignedData, NULL, "Method is not implemented yet");
		/*
		LOGGER_OPENSSL(PEM_read_bio_X509);
		if (PEM_write_bio_CMS_stream(out->internal(), this->internal()) < 1)
			THROW_OPENSSL_EXCEPTION(0, SignedData, NULL, "PEM_write_bio_X509", NULL);
		break;
		*/
	default:
		THROW_EXCEPTION(0, SignedData, NULL, ERROR_DATA_FORMAT_UNKNOWN_FORMAT, format);
	}
}