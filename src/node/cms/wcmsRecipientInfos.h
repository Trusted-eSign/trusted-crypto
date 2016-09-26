#ifndef PKI_WCMSRECIPIENTINFOS_H_INCLUDED
#define  PKI_WCMSRECIPIENTINFOS_H_INCLUDED

#include "../../wrapper/cms/cmsRecipientInfos.h"

#include <nan.h>
#include "../utils/wrap.h"
#include "../helper.h"

WRAP_CLASS(CmsRecipientInfoCollection) {
public:
	WCmsRecipientInfoCollection(){};
	~WCmsRecipientInfoCollection(){};

	WRAP_NEW_INSTANCE(CmsRecipientInfoCollection);

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	static NAN_METHOD(Items);
	static NAN_METHOD(Push);
	static NAN_METHOD(Pop);
	static NAN_METHOD(RemoveAt);
	static NAN_METHOD(Length);
};

#endif //PKI_WCMSRECIPIENTINFOS_H_INCLUDED
