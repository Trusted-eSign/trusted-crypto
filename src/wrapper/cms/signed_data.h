#ifndef CMS_SIGNED_DATA_H_INCLUDED
#define  CMS_SIGNED_DATA_H_INCLUDED

#include "common.h"

SSLOBJECT_free(CMS_ContentInfo, CMS_ContentInfo_free);

class SignedData : public SSLObject < CMS_ContentInfo > {
public:
	//Constructor
	SSLOBJECT_new(SignedData, CMS_ContentInfo){
		if (CMS_SignedData_init(this->internal()) < 1){
			THROW_OPENSSL_EXCEPTION(0, SignedData, NULL, "CMS_SignedData_init");
		}
	}
	SSLOBJECT_new_null(SignedData, CMS_ContentInfo, CMS_ContentInfo_new){
		LOGGER_FN();

		LOGGER_OPENSSL("CMS_SignedData_init");
		CMS_SignedData_init(this->internal());
	}

	// Properties
	void setContent(Handle<Bio> value);
	Handle<Bio> getContent();

	// Methods
	Handle<CertificateCollection> certificates();
	Handle<Certificate> certificates(int index);
	Handle<SignerCollection> signers();
	Handle<Signer> signers(int index);
	bool isDetached();
	void read(Handle<Bio> in, DataFormat::DATA_FORMAT format);
	void write(Handle<Bio> out, DataFormat::DATA_FORMAT format);
	void addCertificate(Handle<Certificate> cert);
	bool verify(Handle<CertificateCollection> certs, int flags);

	static Handle<SignedData> sign(Handle<Certificate> cert, Handle<Key> pkey, Handle<CertificateCollection> certs, Handle<Bio> content, unsigned int flags); // Подписывает данные и формирует новый CMS пакет
	void sign();

	Handle<Signer> createSigner(Handle<Certificate> cert, Handle<Key> pkey, Handle<std::string> digestname, unsigned int flags);

protected:
	Handle<Bio> content;
};

#endif  //!CMS_SIGNED_DATA_H_INCLUDED