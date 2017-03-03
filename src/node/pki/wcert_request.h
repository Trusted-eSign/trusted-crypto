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
	static NAN_METHOD(Sign);
	static NAN_METHOD(GetPEMString);

	WRAP_NEW_INSTANCE(CertificationRequest);
};

#endif //PKI_WCERTREQ_H_INCLUDED
