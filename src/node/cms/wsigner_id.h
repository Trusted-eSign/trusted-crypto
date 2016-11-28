#ifndef PKI_WSIGNERID_H_INCLUDED
#define  PKI_WSIGNERID_H_INCLUDED

#include "../../wrapper/cms/signer_id.h"

#include <nan.h>
#include "../utils/wrap.h"
#include "../helper.h"

WRAP_CLASS(SignerId){
public:
	WSignerId(){};
	~WSignerId(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);
	
	static NAN_METHOD(GetIssuerName);
	static NAN_METHOD(GetSerialNumber);
	static NAN_METHOD(GetKeyId);

	WRAP_NEW_INSTANCE(SignerId);
};

#endif //PKI_WSIGNERID_H_INCLUDED
