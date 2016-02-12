#ifndef CMS_PKI_WCIPHER_H_INCLUDED
#define CMS_PKI_WCIPHER_H_INCLUDED

#include "../../wrapper/pki/cipher.h"

#include <node.h>
#include <v8.h>
#include <node_object_wrap.h>
#include <nan.h>
#include "../helper.h"

class WCipher : public node::ObjectWrap{
public:
	WCipher(){};
	~WCipher(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	static NAN_METHOD(SetCryptoMethod);
	
	static NAN_METHOD(Encrypt);
	static NAN_METHOD(Decrypt);

	static NAN_METHOD(AddRecipientsCerts);
	static NAN_METHOD(SetPrivKey);
	static NAN_METHOD(SetRecipientCert);

	static NAN_METHOD(SetDigest);
	static NAN_METHOD(SetSalt);
	static NAN_METHOD(SetPass);
	static NAN_METHOD(SetIV);
	static NAN_METHOD(SetKey);

	static NAN_METHOD(GetSalt);
	static NAN_METHOD(GetIV);
	static NAN_METHOD(GetKey);

	static NAN_METHOD(GetAlgorithm);
	static NAN_METHOD(GetMode);
	static NAN_METHOD(GetDigestAlgorithm);

	Handle<Cipher> data_;

	static inline Nan::Persistent<v8::Function> & constructor() {
		static Nan::Persistent<v8::Function> my_constructor;
		return my_constructor;
	}
};

#endif //CMS_PKI_WCIPHER_H_INCLUDED
