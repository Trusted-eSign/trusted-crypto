#ifndef CMS_PKI_CMSRECIPIENTINFOS_H_INCLUDED
#define  CMS_PKI_CMSRECIPIENTINFOS_H_INCLUDED

#include "../common/common.h"

class CTWRAPPER_API CmsRecipientInfoCollection;

#include "cmsRecipientInfo.h"

DECLARE_STACK_OF(CMS_RecipientInfo)

SSLOBJECT_free(stack_st_CMS_RecipientInfo, sk_CMS_RecipientInfo_free)

class CmsRecipientInfoCollection : public SSLObject < stack_st_CMS_RecipientInfo > {
public:
	SSLOBJECT_new(CmsRecipientInfoCollection, stack_st_CMS_RecipientInfo){}
	SSLOBJECT_new_null(CmsRecipientInfoCollection, stack_st_CMS_RecipientInfo, sk_CMS_RecipientInfo_new_null){}

	//methods
	void push(Handle<CmsRecipientInfo> ri);
	void pop();
	void removeAt(int index);
	int length();
	Handle<CmsRecipientInfo> items(int index);
};

#endif //!CMS_PKI_CMSRECIPIENTINFOS_H_INCLUDED
