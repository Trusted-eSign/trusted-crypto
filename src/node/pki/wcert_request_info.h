#ifndef PKI_WCERTREQINFO_H_INCLUDED
#define PKI_WCERTREQINFO_H_INCLUDED

#include <wrapper/pki/cert_request_info.h>

#include <nan.h>
#include "../utils/wrap.h"
#include "../helper.h"

WRAP_CLASS(CertificationRequestInfo) {
public:
	WCertificationRequestInfo(){};
	~WCertificationRequestInfo(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	static NAN_METHOD(SetSubject);
	static NAN_METHOD(SetPublicKey);
	static NAN_METHOD(SetVersion);

	static NAN_METHOD(GetSubject);
	static NAN_METHOD(GetPublicKey);
	static NAN_METHOD(GetVersion);

	WRAP_NEW_INSTANCE(CertificationRequestInfo);
};

#endif //PKI_WCERTREQINFO_H_INCLUDED
