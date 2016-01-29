//#ifndef CMS_PKI_CSR_H_INCLUDED
//#define CMS_PKI_CSR_H_INCLUDED

#include "../../wrapper/pki/certRegInfo.h"

#include <node.h>
#include <v8.h>
#include <node_object_wrap.h>
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

	Handle<CertificationRequestInfo> data_;

	static inline Nan::Persistent<v8::Function> & constructor() {
		static Nan::Persistent<v8::Function> my_constructor;
		return my_constructor;
	}
};

//#endif //CMS_PKI_CSR_H_INCLUDED
