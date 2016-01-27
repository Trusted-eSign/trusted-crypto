#include "../stdafx.h"

#include "signers.h"

int SignerCollection::length(){
	LOGGER_FN();

	LOGGER_OPENSSL("sk_CMS_SignerInfo_num");
	int res = sk_CMS_SignerInfo_num(this->internal());

	return (res == -1) ? 0 : res;
}

Handle<Signer> SignerCollection::items(int index){
	LOGGER_FN();

	LOGGER_OPENSSL("sk_CMS_SignerInfo_value");
	CMS_SignerInfo *si = sk_CMS_SignerInfo_value(this->internal(), index);
	if (!si){
		THROW_OPENSSL_EXCEPTION(0, SignerCollection, NULL, "sk_CMS_SignerInfo_value");
	}

	return new Signer(si, this->handle());
}