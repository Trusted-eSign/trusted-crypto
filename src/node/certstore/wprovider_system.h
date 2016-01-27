//#ifndef PKI_WCERT_H_INCLUDED
//#define  PKI_WCERT_H_INCLUDED

#include "../../wrapper/certstore/provider_system.h"

#include <node.h>
#include <v8.h>
#include <node_object_wrap.h>
#include <nan.h>
#include "../helper.h"

class WProviderSystem : public node::ObjectWrap
{
public:
	WProviderSystem(){};
	~WProviderSystem(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	static NAN_METHOD(fillingCache);
	static NAN_METHOD(readJson);

	Handle<ProviderSystem> data_;
	
	static inline Nan::Persistent<v8::Function> & constructor() {
		static Nan::Persistent<v8::Function> my_constructor;
		return my_constructor;
	}
};

//#endif //PKI_WCERT_H_INCLUDED
