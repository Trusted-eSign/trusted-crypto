#ifndef PKI_WCMSRECIPIENTINFO_H_INCLUDED
#define  PKI_WCMSRECIPIENTINFO_H_INCLUDED

#include "../../wrapper/cms/cmsRecipientInfo.h"

#include <nan.h>
#include "../utils/wrap.h"
#include "../helper.h"

WRAP_CLASS(CmsRecipientInfo){
public:
	WCmsRecipientInfo(){};
	~WCmsRecipientInfo(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);
	
	//Properties
	static NAN_METHOD(GetIssuerName);
	static NAN_METHOD(GetSerialNumber);

	//Methods
	static NAN_METHOD(KtriCertCmp);

	WRAP_NEW_INSTANCE(CmsRecipientInfo);
};

#endif //PKI_WCMSRECIPIENTINFO_H_INCLUDED
