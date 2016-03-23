#ifndef WMICROSOFT_H_INCLUDED
#define WMICROSOFT_H_INCLUDED

#include "../../wrapper/store/provider_microsoft.h"

#include <nan.h>
#include "../utils/wrap.h"
#include "../helper.h"

WRAP_CLASS(ProviderMicrosoft){
public:
	WProviderMicrosoft(){};
	~WProviderMicrosoft(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);
};

#endif //WMICROSOFT_H_INCLUDED
