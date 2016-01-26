//#ifndef PKI_WCERT_H_INCLUDED
//#define  PKI_WCERT_H_INCLUDED

#include "../../wrapper/certstore/certstore.h"

#include <node.h>
#include <v8.h>
#include <node_object_wrap.h>
#include <nan.h>
#include "../helper.h"

class WCertStore : public node::ObjectWrap
{
public:
	WCertStore(){};
	~WCertStore(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);
	
	static NAN_METHOD(addCertStore);
	static NAN_METHOD(removeCertStore);
	static NAN_METHOD(createCache);
	static NAN_METHOD(addCacheSection);

	static NAN_METHOD(getCertStore);
	static NAN_METHOD(getPrvTypePresent);

	Handle<CertStore> data_;
	
	static inline Nan::Persistent<v8::Function> & constructor() {
		static Nan::Persistent<v8::Function> my_constructor;
		return my_constructor;
	}
};

//#endif //PKI_WCERT_H_INCLUDED
