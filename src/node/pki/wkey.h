//#ifndef PKI_WKEY_H_INCLUDED
//#define  PKI_WKEY_H_INCLUDED

#include "../../wrapper/pki/key.h"

#include <node.h>
#include <v8.h>
#include <node_object_wrap.h>
#include <nan.h>
#include "../helper.h"

class WKey : public node::ObjectWrap
{
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

	Handle<Key> data_;

	static inline Nan::Persistent<v8::Function> & constructor() {
		static Nan::Persistent<v8::Function> my_constructor;
		return my_constructor;
	}
};

//#endif //PKI_WKEY_H_INCLUDED
