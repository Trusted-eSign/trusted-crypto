#ifndef UTIL_WSLOT_INCLUDED
#define UTIL_WSLOT_INCLUDED

#include <nan.h>
#include "../utils/wrap.h"
#include "../helper.h"

#include "../../wrapper/pkcs11/slot.h"

WRAP_CLASS(Slot){
public:
	WSlot(){};
	~WSlot(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	static NAN_METHOD(FindToken);
};

#endif //!UTIL_WSLOT_INCLUDED 
