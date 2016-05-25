#ifndef PKI_WCHAIN_H_INCLUDED
#define PKI_WCHAIN_H_INCLUDED

#include "../../wrapper/pki/chain.h"

#include <nan.h>
#include "../utils/wrap.h"
#include "../helper.h"

WRAP_CLASS(Chain) {
public:
	WChain(){};
	~WChain(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	static NAN_METHOD(BuildChain);
	static NAN_METHOD(VerifyChain);
};

#endif //PKI_WCHAIN_H_INCLUDED
