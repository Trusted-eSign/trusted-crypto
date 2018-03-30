#ifndef PKI_WCERTREQ_H_INCLUDED
#define PKI_WCERTREQ_H_INCLUDED

#include <wrapper/pki/cert_request.h>

#include <nan.h>
#include "../utils/wrap.h"
#include "../helper.h"

WRAP_CLASS(CertificationRequest){
public:
	WCertificationRequest(){};
	~WCertificationRequest(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	static NAN_METHOD(Load);
	static NAN_METHOD(Save);

	static NAN_METHOD(SetSubject);
	static NAN_METHOD(SetPublicKey);
	static NAN_METHOD(SetVersion);
	static NAN_METHOD(SetExtensions);

	static NAN_METHOD(GetSubject);
	static NAN_METHOD(GetPublicKey);
	static NAN_METHOD(GetVersion);
	static NAN_METHOD(GetExtensions);

	static NAN_METHOD(Sign);
	static NAN_METHOD(Verify);

	static NAN_METHOD(ToCertificate);

	static NAN_METHOD(GetPEMString);

	WRAP_NEW_INSTANCE(CertificationRequest);
};

#endif //PKI_WCERTREQ_H_INCLUDED
