#ifndef CMS_W_SIGNER_H_INCLUDED
#define CMS_W_SIGNER_H_INCLUDED

#include <wrapper/cms/common.h>

#include <nan.h>
#include "../utils/wrap.h"
#include "../helper.h"

WRAP_CLASS(Signer)
{
public:
	WSigner(){};
	~WSigner(){};

	static const char* className;

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	// Properties
	static NAN_METHOD(SetCertificate);
	static NAN_METHOD(GetCertificate);
	static NAN_METHOD(GetSignature);
	static NAN_METHOD(GetSignatureAlgorithm);
	static NAN_METHOD(GetDigestAlgorithm);
	static NAN_METHOD(GetSignerId);
	static NAN_METHOD(GetSigningTime);

	// Methods
	static NAN_METHOD(GetSignedAttributes);
	static NAN_METHOD(GetUnsignedAttributes);
	static NAN_METHOD(Verify);
	static NAN_METHOD(VerifyContent);

	WRAP_NEW_INSTANCE(Signer);
};

#endif // !CMS_W_SIGNER_H_INCLUDED