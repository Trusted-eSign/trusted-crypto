#ifndef PKI_WOID_H_INCLUDED
#define  PKI_WOID_H_INCLUDED

#include "../../wrapper/pki/oid.h"

#include <nan.h>
#include "../helper.h"

#define CLASS_NAME_OID "OID"

class WOID: public node::ObjectWrap
{
public:
	WOID(){};
	~WOID(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	// Properties
	static NAN_METHOD(GetLongName);
	static NAN_METHOD(GetShortName);
	static NAN_METHOD(GetValue);

	// Methods

	Handle<OID> data_;

	static inline Nan::Persistent<v8::Function> & constructor() {
		static Nan::Persistent<v8::Function> my_constructor;
		return my_constructor;
	}
};

#endif //PKI_WOID_H_INCLUDED