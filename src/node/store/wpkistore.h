#ifndef WPKISTORE_H_INCLUDED
#define WPKISTORE_H_INCLUDED

#include <wrapper/store/pkistore.h>

#include <nan.h>
#include "../utils/wrap.h"
#include "../helper.h"

WRAP_CLASS(PkiStore){
public:
	WPkiStore(){};
	~WPkiStore(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);
	
	static NAN_METHOD(AddProvider);
	static NAN_METHOD(AddCert);
	static NAN_METHOD(AddCrl);
	static NAN_METHOD(AddCsr);
	static NAN_METHOD(AddKey);
	static NAN_METHOD(DeleteCert);
	static NAN_METHOD(DeleteCrl);
	static NAN_METHOD(Find);
	static NAN_METHOD(FindKey);
	static NAN_METHOD(GetItem);
	static NAN_METHOD(GetCerts);
};

WRAP_CLASS(Provider){
public:
	WProvider(){};
	~WProvider(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	WRAP_NEW_INSTANCE(Provider);
};

WRAP_CLASS(Filter){
public:
	WFilter(){};
	~WFilter(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	static NAN_METHOD(SetType);
	static NAN_METHOD(SetProvider);
	static NAN_METHOD(SetCategory);
	static NAN_METHOD(SetHash);
	static NAN_METHOD(SetSubjectName);
	static NAN_METHOD(SetSubjectFriendlyName);
	static NAN_METHOD(SetIssuerName);
	static NAN_METHOD(SetIssuerFriendlyName);
	static NAN_METHOD(SetSerial);
	static NAN_METHOD(SetIsValid);
};

WRAP_CLASS(PkiItem){
public:
	WPkiItem(){};
	~WPkiItem(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);	

	static NAN_METHOD(SetFormat);
	static NAN_METHOD(SetType);
	static NAN_METHOD(SetProvider);
	static NAN_METHOD(SetCategory);
	static NAN_METHOD(SetURI);
	static NAN_METHOD(SetHash);
	static NAN_METHOD(SetSubjectName);
	static NAN_METHOD(SetSubjectFriendlyName);
	static NAN_METHOD(SetIssuerName);
	static NAN_METHOD(SetIssuerFriendlyName);
	static NAN_METHOD(SetSerial);
	static NAN_METHOD(SetNotBefore);
	static NAN_METHOD(SetNotAfter);
	static NAN_METHOD(SetLastUpdate);
	static NAN_METHOD(SetNextUpdate);
	static NAN_METHOD(SetKey);
	static NAN_METHOD(SetKeyEncrypted);
	static NAN_METHOD(SetOrganizationName);
	static NAN_METHOD(SetSignatureAlgorithm);
	static NAN_METHOD(SetSignatureDigestAlgorithm);
	static NAN_METHOD(SetPublicKeyAlgorithm);
	static NAN_METHOD(SetAuthorityKeyid);
	static NAN_METHOD(SetCrlNumber);
};

#endif //WPKISTORE_H_INCLUDED
