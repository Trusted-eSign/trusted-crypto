#ifndef PKI_WKEY_H_INCLUDED
#define  PKI_WKEY_H_INCLUDED

#include "../../wrapper/pki/cert.h"

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
	static NAN_METHOD(Load);
	static NAN_METHOD(Import);

	Handle<Key> data_;
};

#endif //PKI_WKEY_H_INCLUDED
