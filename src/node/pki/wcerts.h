#ifndef PKI_WCERTS_H_INCLUDED
#define  PKI_WCERTS_H_INCLUDED

#include <wrapper/pki/certs.h>

#include <nan.h>
#include "../utils/wrap.h"
#include "../helper.h"

class WCertificateCollection : public Wrapper < CertificateCollection >
{
public:
	WCertificateCollection(){};
	~WCertificateCollection(){};

	WRAP_NEW_INSTANCE(CertificateCollection);

	static const char* className;

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	static NAN_METHOD(Items);
	static NAN_METHOD(Push);
	static NAN_METHOD(Pop);
	static NAN_METHOD(RemoveAt);
	static NAN_METHOD(Length);
};

#endif //PKI_WCERTS_H_INCLUDED