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

	static NAN_METHOD(keypairGenerate);
	static NAN_METHOD(keypairGenerateMemory);
	static NAN_METHOD(keypairGenerateBIO);

	static NAN_METHOD(privkeyLoad);	
	static NAN_METHOD(privkeyLoadMemory);
	//static NAN_METHOD(privkeyLoadBIO);

	static NAN_METHOD(pubkeyLoad);
	static NAN_METHOD(pubkeyLoadMemory);
	//static NAN_METHOD(pubkeyLoadBIO);

	static NAN_METHOD(privkeySave);
	static NAN_METHOD(privkeySaveBIO);
	static NAN_METHOD(privkeySaveMemory);

	static NAN_METHOD(pubkeySave);
	static NAN_METHOD(pubkeySaveBIO);
	static NAN_METHOD(pubkeySaveMemory);

	WRAP_NEW_INSTANCE(Key);
};

#endif //WKEY_H_INCLUDED
