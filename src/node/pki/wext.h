#ifndef PKI_WEXT_H_INCLUDED
#define  PKI_WEXT_H_INCLUDED

#include <wrapper/pki/ext.h>

#include <nan.h>
#include "../utils/wrap.h"
#include "../helper.h"

class WExtension : public Wrapper < Extension > {
public:
	WExtension(){};
	~WExtension(){};

	static const char* className;

	WRAP_NEW_INSTANCE(Extension);

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	static NAN_METHOD(GetTypeId);
	static NAN_METHOD(SetTypeId);
	static NAN_METHOD(GetCritical);
	static NAN_METHOD(SetCritical);
};

#endif //PKI_WEXT_H_INCLUDED
