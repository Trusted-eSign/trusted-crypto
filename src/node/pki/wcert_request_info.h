#ifndef PKI_WCERTREQINFO_H_INCLUDED
#define PKI_WCERTREQINFO_H_INCLUDED

#include "../../wrapper/pki/cert_request_info.h"

#include <nan.h>
#include "../helper.h"

class WCertificationRequestInfo : public node::ObjectWrap{
public:
	WCertificationRequestInfo(){};
	~WCertificationRequestInfo(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	static NAN_METHOD(SetSubject);
	static NAN_METHOD(SetSubjectPublicKey);
	static NAN_METHOD(SetVersion);

	Handle<CertificationRequestInfo> data_;

	static inline Nan::Persistent<v8::Function> & constructor() {
		static Nan::Persistent<v8::Function> my_constructor;
		return my_constructor;
	}
};

#endif //PKI_WCERTREQINFO_H_INCLUDED
