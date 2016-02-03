#ifndef PKI_WCERTREQ_H_INCLUDED
#define PKI_WCERTREQ_H_INCLUDED

#include "../../wrapper/pki/certReg.h"

#include <node.h>
#include <v8.h>
#include <node_object_wrap.h>
#include <nan.h>
#include "../helper.h"

class WCertificationRequest : public node::ObjectWrap{
public:
	WCertificationRequest(){};
	~WCertificationRequest(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	static NAN_METHOD(Sign);
	static NAN_METHOD(GetPEMString);

	Handle<CertificationRequest> data_;

	static inline Nan::Persistent<v8::Function> & constructor() {
		static Nan::Persistent<v8::Function> my_constructor;
		return my_constructor;
	}
};

#endif //PKI_WCERTREQ_H_INCLUDED
