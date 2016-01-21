#ifndef CMS_W_SIGNER_ATTRS_H_INCLUDED
#define CMS_W_SIGNER_ATTRS_H_INCLUDED

#include "../../wrapper/cms/common.h"

#include <nan.h>
#include "../utils/wrap.h"
#include "../helper.h"

WRAP_CLASS(SignerAttributeCollection)
{
public:
	WSignerAttributeCollection(){};
	~WSignerAttributeCollection(){};

	static const char* className;

	WRAP_NEW_INSTANCE(SignerAttributeCollection);

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	// Properties
	static NAN_METHOD(Length);

	// Methods
	static NAN_METHOD(Push);
	static NAN_METHOD(RemoveAt);
	static NAN_METHOD(Items);
	
};

#endif // !CMS_W_SIGNER_ATTRS_H_INCLUDED