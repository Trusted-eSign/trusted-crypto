#ifndef CMS_SIGNED_DATA_H_INCLUDED
#define  CMS_SIGNED_DATA_H_INCLUDED

#include "common.h"

SSLOBJECT_free(CMS_ContentInfo, CMS_ContentInfo_free);

class SignedData : public SSLObject < CMS_ContentInfo > {
public:
	//Constructor
	//Has no constructor
	SSLOBJECT_new(SignedData, CMS_ContentInfo){}
	SSLOBJECT_new_null(SignedData, CMS_ContentInfo, CMS_ContentInfo_new){}

	//Properties

	//Methods
	Handle<CertificateCollection> certificates();
	Handle<Certificate> certificates(int index);
	Handle<SignerCollection> signers();
	Handle<Signer> signers(int index);
	bool isDetached();
	void read(Handle<Bio> in, DataFormat::DATA_FORMAT format);
	void write(Handle<Bio> out, DataFormat::DATA_FORMAT format);

};

#endif  //!CMS_SIGNED_DATA_H_INCLUDED