#ifndef PKI_WATTR_VALS_H_INCLUDED
#define  PKI_WATTR_VALS_H_INCLUDED

#include "../../wrapper/pki/attr_vals.h"

#include <nan.h>
#include "../utils/wrap.h"
#include "../helper.h"

WRAP_CLASS(AttributeValueCollection){
public:
	WAttributeValueCollection(){};
	~WAttributeValueCollection(){};

	static v8::Local<v8::Object> NewInstance(v8::Local<v8::Object> attribute);

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	static NAN_METHOD(Push);
	static NAN_METHOD(Pop);
	static NAN_METHOD(RemoveAt);

	static NAN_METHOD(Items);
	static NAN_METHOD(Length);

};

#endif //PKI_WATTR_VALS_H_INCLUDED