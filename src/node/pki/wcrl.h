#ifndef PKI_WCRL_H_INCLUDED
#define  PKI_WCRL_H_INCLUDED

#include "../../wrapper/pki/crl.h"

#include <node.h>
#include <v8.h>
#include <node_object_wrap.h>
#include <nan.h>
#include "../helper.h"

class WCRL: public node::ObjectWrap
{
public:
	WCRL(){};
	~WCRL(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	static NAN_METHOD(Load);
	static NAN_METHOD(Import);

	static NAN_METHOD(Save);
	static NAN_METHOD(Export);

	static NAN_METHOD(GetVersion);
	static NAN_METHOD(GetIssuerName);
	static NAN_METHOD(GetLastUpdate);
	static NAN_METHOD(GetNextUpdate);
	static NAN_METHOD(GetCertificate);

	Handle<CRL> data_;
	
	static inline Nan::Persistent<v8::Function> & constructor() {
		static Nan::Persistent<v8::Function> my_constructor;
		return my_constructor;
	}
};

#endif //PKI_WCRL_H_INCLUDED
