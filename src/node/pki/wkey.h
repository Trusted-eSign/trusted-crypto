#ifndef WKEY_H_INCLUDED
#define WKEY_H_INCLUDED

#include "../../wrapper/pki/key.h"

#include <nan.h>
#include "../utils/wrap.h"
#include "../helper.h"

WRAP_CLASS(Key){
public:
	WKey(){};
	~WKey(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	static NAN_METHOD(Generate);
	static NAN_METHOD(Compare);
	static NAN_METHOD(Duplicate);

	static NAN_METHOD(ReadPrivateKey);
	static NAN_METHOD(WritePrivateKey);

	static NAN_METHOD(ReadPublicKey);
	static NAN_METHOD(WritePublicKey);

	WRAP_NEW_INSTANCE(Key);
};

#endif //WKEY_H_INCLUDED
