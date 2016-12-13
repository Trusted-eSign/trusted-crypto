#include "../stdafx.h"

#include "signed_data.h"

Handle<CertificateCollection> SignedData::certificates(){
	LOGGER_FN();

	STACK_OF(X509) *certs;

	LOGGER_OPENSSL(CMS_get1_certs);
	certs = CMS_get1_certs(this->internal());

	return new CertificateCollection(certs);
}

Handle<Certificate> SignedData::certificates(int index){
	LOGGER_FN();

	return this->certificates()->items(index);
}

Handle<SignerCollection> SignedData::signers(){
	LOGGER_FN();

	stack_st_CMS_SignerInfo *signers_ = CMS_get0_SignerInfos(this->internal());

	return new SignerCollection(signers_, this->handle());
}

Handle<Signer> SignedData::signers(int index){
	LOGGER_FN();

	return this->signers()->items(index);
}

bool SignedData::isDetached(){
	LOGGER_FN();

	LOGGER_OPENSSL("CMS_is_detached");
	int res = CMS_is_detached(this->internal());

	if (res == -1){
		THROW_OPENSSL_EXCEPTION(0, SignedData, NULL, "CMS_is_detached");
	}

	return res == 1;
}

void SignedData::read(Handle<Bio> in, DataFormat::DATA_FORMAT format){
	LOGGER_FN();

	try{
		if (in.isEmpty()){
			THROW_EXCEPTION(0, SignedData, NULL, "Parameter %d cann't be NULL", 1);
		}

		CMS_ContentInfo *ci = NULL;

		in->reset();

		switch (format){
		case DataFormat::DER:
			LOGGER_OPENSSL(d2i_CMS_bio);
			ci = d2i_CMS_bio(in->internal(), NULL);
			if (ci == NULL){
				THROW_OPENSSL_EXCEPTION(0, SignedData, NULL, "d2i_CMS_bio");
			}

			LOGGER_OPENSSL(CMS_is_detached);
			if (ci && !CMS_is_detached(ci)){
				LOGGER_INFO("Get content from DER file");

				LOGGER_OPENSSL(CMS_get0_content);
				ASN1_OCTET_STRING *asn = (*CMS_get0_content(ci));
				if (asn == NULL){
					THROW_EXCEPTION(0, SignedData, NULL, "CMS_get0_content");
				}

				LOGGER_OPENSSL(BIO_new_mem_buf);
				Handle<Bio> content = new Bio(BIO_new_mem_buf(asn->data, asn->length));
				if (content->internal() == NULL){
					THROW_EXCEPTION(0, SignedData, NULL, "Error set content cms to BIO");
				}

				this->setContent(content);
			}

			break;
		case DataFormat::BASE64:
		{
			LOGGER_OPENSSL("PEM_read_bio_CMS");
			if ((ci = PEM_read_bio_CMS(in->internal(), NULL, NULL, NULL)) == NULL){
				THROW_OPENSSL_EXCEPTION(0, SignedData, NULL, "PEM_read_bio_CMS");
			};

			LOGGER_OPENSSL(CMS_is_detached);
			if (ci && !CMS_is_detached(ci)){
				LOGGER_INFO("Get content from DER file");

				ASN1_OCTET_STRING *asn = (*CMS_get0_content(ci));
				if (asn == NULL){
					THROW_EXCEPTION(0, SignedData, NULL, "CMS_get0_content");
				}

				Handle<Bio> content = new Bio(BIO_new_mem_buf(asn->data, asn->length));
				if (content->internal() == NULL){
					THROW_EXCEPTION(0, SignedData, NULL, "Error set content cms to BIO");
				}

				this->setContent(content);
			}

			break;
		}
		default:
			THROW_EXCEPTION(0, SignedData, NULL, ERROR_DATA_FORMAT_UNKNOWN_FORMAT, format);
		}

		if (!ci) {
			puts(OpenSSL::printErrors()->c_str());
			THROW_EXCEPTION(0, SignedData, NULL, "Can not read CMS signed data from BIO");
		}

		this->setData(ci);
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, SignedData, e, "Error read cms");
	}
}

void SignedData::write(Handle<Bio> out, DataFormat::DATA_FORMAT format){
	LOGGER_FN();

	if (out.isEmpty())
		THROW_EXCEPTION(0, SignedData, NULL, "Parameter %d is NULL", 1);

	switch (format){
	case DataFormat::DER:

		LOGGER_OPENSSL("i2d_CMS_bio");
		if (i2d_CMS_bio(out->internal(), this->internal()) < 1)
			THROW_OPENSSL_EXCEPTION(0, SignedData, NULL, "i2d_CMS_bio", NULL);

		// LOGGER_OPENSSL("i2d_CMS_bio_stream");
		// if (i2d_CMS_bio_stream(out->internal(), this->internal(), this->content->internal(), flags) < 1)
		//   THROW_OPENSSL_EXCEPTION(0, SignedData, NULL, "i2d_CMS_bio_stream", NULL);

		break;
	case DataFormat::BASE64:
		LOGGER_OPENSSL("PEM_write_bio_CMS");
		if (PEM_write_bio_CMS(out->internal(), this->internal()) < 1)
			THROW_OPENSSL_EXCEPTION(0, SignedData, NULL, "PEM_write_bio_CMS", NULL);

		// LOGGER_OPENSSL("PEM_write_bio_CMS_stream");
		// if (PEM_write_bio_CMS_stream(out->internal(), this->internal(), this->content->internal(), flags) < 1)
		//   THROW_OPENSSL_EXCEPTION(0, SignedData, NULL, "PEM_write_bio_CMS_stream", NULL);

		break;

	default:
		THROW_EXCEPTION(0, SignedData, NULL, ERROR_DATA_FORMAT_UNKNOWN_FORMAT, format);
	}
}

Handle<Signer> SignedData::createSigner(Handle<Certificate> cert, Handle<Key> pkey){
	LOGGER_FN();

	int def_nid;
	LOGGER_OPENSSL("EVP_PKEY_get_default_digest_nid");
	if (EVP_PKEY_get_default_digest_nid(pkey->internal(), &def_nid) <= 0) {
		THROW_OPENSSL_EXCEPTION(0, SignedData, NULL, "Unknown digest name");
	}
	LOGGER_OPENSSL("EVP_PKEY_get_default_digest_nid");
	const EVP_MD *md = EVP_get_digestbynid(def_nid);
	if (md == NULL) {
		THROW_OPENSSL_EXCEPTION(0, SignedData, NULL, "No default digest");
	}

	LOGGER_OPENSSL("CMS_add1_signer");
	CMS_SignerInfo *signer = CMS_add1_signer(this->internal(), cert->internal(), pkey->internal(), md, flags);
	if (!signer){
		THROW_OPENSSL_EXCEPTION(0, SignedData, NULL, "CMS_add1_signer");
	}

	return new Signer(signer, this->handle());
}

void SignedData::addCertificate(Handle<Certificate> cert){
	LOGGER_FN();

	Handle<Certificate> cert_copy = cert->duplicate();

	LOGGER_OPENSSL("CMS_add0_cert");
	if (CMS_add0_cert(this->internal(), cert_copy->internal()) < 1){
		THROW_EXCEPTION(0, SignedData, NULL, "Certificate already present");
	}

	cert_copy->setParent(this->handle());
}

void SignedData::setContent(Handle<Bio> value){
	LOGGER_FN();

	this->content = value;
}

Handle<Bio> SignedData::getContent(){
	LOGGER_FN();

	this->content->reset();
	return this->content;
}

bool SignedData::verify(Handle<CertificateCollection> certs){
	LOGGER_FN();
	int res;

	try {
		stack_st_X509 *pCerts = NULL;
		if (!certs.isEmpty()){
			pCerts = certs->internal();
		}

		// Сдвиг курсора на начало
		content->reset();

		X509_STORE *store = X509_STORE_new();

		LOGGER_OPENSSL("CMS_verify");
		res = CMS_verify(this->internal(), pCerts, store, content->internal(), NULL, flags);
		LOGGER_OPENSSL("X509_STORE_free");
		X509_STORE_free(store);
		
		return res == 1;
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, SignedData, e, "Error CMS verify");
	}
}

Handle<SignedData> SignedData::sign(Handle<Certificate> cert, Handle<Key> pkey, Handle<CertificateCollection> certs, Handle<Bio> content, unsigned int flags){
	LOGGER_FN();

	LOGGER_OPENSSL("CMS_sign");
	CMS_ContentInfo *res = CMS_sign(cert->internal(), pkey->internal(), certs->internal(), content->internal(), flags);
	if (!res){
		THROW_OPENSSL_EXCEPTION(0, SignedData, NULL, "CMS_sign");
	}

	Handle<SignedData> sd = new SignedData(res);
	sd->flags = flags;

	return sd;
}

void SignedData::sign(){
	LOGGER_FN();

	if (!(flags & CMS_DETACHED)){
		CMS_set_detached(this->internal(), 0);
	}

	flags |= CMS_BINARY; /*Don't translate message to text*/

	LOGGER_OPENSSL("CMS_final");
	if (CMS_final(this->internal(), this->content->internal(), NULL, flags) < 1){
		THROW_OPENSSL_EXCEPTION(0, SignedData, NULL, "CMS_final");
	}
}

int SignedData::getFlags(){
	LOGGER_FN();

	return this->flags;
}

void SignedData::setFlags(int v){
	LOGGER_FN();

	this->flags = v;
}

void SignedData::addFlag(int v){
	LOGGER_FN();

	this->flags |= v;
}
void SignedData::removeFlags(int v){
	LOGGER_FN();

	this->flags ^= v;
}
