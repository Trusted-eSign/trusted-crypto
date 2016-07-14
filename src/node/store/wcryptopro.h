#ifndef WCRYPTOPRO_H_INCLUDED
#define WCRYPTOPRO_H_INCLUDED

#include "../../wrapper/store/provider_cryptopro.h"

#include <nan.h>
#include "../utils/wrap.h"
#include "../helper.h"

#include "../pki/wcert.h"
#include "../pki/wkey.h"

WRAP_CLASS(ProviderCryptopro){
public:
	WProviderCryptopro(){};
	~WProviderCryptopro(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);
	static NAN_METHOD(GetKey);
};

#endif //WCRYPTOPRO_H_INCLUDED
