#ifndef CMS_W_SIGNED_DATA_H_INCLUDED
#define  CMS_W_SIGNED_DATA_H_INCLUDED

#include "../../wrapper/cms/common.h"

#include <nan.h>
#include "../utils/wrap.h"
#include "../helper.h"

WRAP_CLASS(SignedData)
{
public:
	WSignedData(){};
	~WSignedData(){};

	static const char* className;

	WRAP_NEW_INSTANCE(SignedData);

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	// Properties
	static NAN_METHOD(Load);
	static NAN_METHOD(Import);
	static NAN_METHOD(GetCertificates);
	static NAN_METHOD(GetSigners);
};

#endif //!CMS_W_SIGNED_DATA_H_INCLUDED