#ifndef PKI_WCHAIN_H_INCLUDED
#define PKI_WCHAIN_H_INCLUDED

#include "../../wrapper/pki/chain.h"

#include <node.h>
#include <v8.h>
#include <node_object_wrap.h>
#include <nan.h>
#include "../helper.h"

class WChain : public node::ObjectWrap{
public:
	WChain(){};
	~WChain(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	static NAN_METHOD(BuildChain);
	static NAN_METHOD(VerifyChain);

	Handle<Chain> data_;

	static inline Nan::Persistent<v8::Function> & constructor() {
		static Nan::Persistent<v8::Function> my_constructor;
		return my_constructor;
	}
};

#endif //PKI_WCHAIN_H_INCLUDED
