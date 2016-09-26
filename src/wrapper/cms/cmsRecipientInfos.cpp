#include "../stdafx.h"

#include "cmsRecipientInfos.h"

void CmsRecipientInfoCollection::push(Handle<CmsRecipientInfo> ri) {
	LOGGER_FN();

	if (this->isEmpty()){
		LOGGER_OPENSSL("sk_CMS_RecipientInfo_new_null");
		this->setData(sk_CMS_RecipientInfo_new_null());
	}

	LOGGER_OPENSSL("sk_CMS_RecipientInfo_push");
	sk_CMS_RecipientInfo_push(this->internal(), ri->ri);
}

int CmsRecipientInfoCollection::length() {
	LOGGER_FN();

	if (this->isEmpty()) {
		return 0;
	}		

	LOGGER_OPENSSL("sk_CMS_RecipientInfo_num");
	return sk_CMS_RecipientInfo_num(this->internal());
}

Handle<CmsRecipientInfo> CmsRecipientInfoCollection::items(int index) {
	LOGGER_FN();

	LOGGER_OPENSSL("sk_CMS_RecipientInfo_value");
	CMS_RecipientInfo *ri = sk_CMS_RecipientInfo_value(this->internal(), index);

	if (!ri){
		THROW_OPENSSL_EXCEPTION(0, CmsRecipientInfoCollection, NULL, "Has no item by index %d", index);
	}

	Handle<CmsRecipientInfo> cmsRecInfo = new CmsRecipientInfo();
	cmsRecInfo->ri = ri;

	return cmsRecInfo;
}

void CmsRecipientInfoCollection::pop(){
	LOGGER_FN();

	LOGGER_OPENSSL("sk_CMS_RecipientInfo_pop");
	sk_CMS_RecipientInfo_pop(this->internal());
}

void CmsRecipientInfoCollection::removeAt(int index){
	LOGGER_FN();

	LOGGER_OPENSSL("sk_CMS_RecipientInfo_delete");
	sk_CMS_RecipientInfo_delete(this->internal(), index);
}
