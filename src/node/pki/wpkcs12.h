#ifndef PKI_WPKCS12_H_INCLUDED
#define  PKI_WPKCS12_H_INCLUDED

#include "../../wrapper/pki/pkcs12.h"

#include <nan.h>
#include "../utils/wrap.h"
#include "../helper.h"

WRAP_CLASS(Pkcs12){
public:
	WPkcs12(){};
	~WPkcs12(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);
	
	//Properties
	static NAN_METHOD(GetCertificate);
	static NAN_METHOD(GetKey);
	static NAN_METHOD(GetCACertificates);

	//Methods
	static NAN_METHOD(Load);
	static NAN_METHOD(Save);

	WRAP_NEW_INSTANCE(Pkcs12);
};

#endif //PKI_WPKCS12_H_INCLUDED
