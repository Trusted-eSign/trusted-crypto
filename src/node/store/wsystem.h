#ifndef WSYSTEM_H_INCLUDED
#define WSYSTEM_H_INCLUDED

#include "../../wrapper/store/provider_system.h"

#include <nan.h>
#include "../utils/wrap.h"
#include "../helper.h"

WRAP_CLASS(Provider_System){
public:
	WProvider_System(){};
	~WProvider_System(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);
	static NAN_METHOD(ObjectToPkiItem);
};

#endif //PKI_WCERT_H_INCLUDED
