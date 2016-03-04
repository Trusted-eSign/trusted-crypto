#ifndef WCSR_H_INCLUDED
#define WCSR_H_INCLUDED

#include "../../wrapper/pki/csr.h"

#include <nan.h>
#include "../utils/wrap.h"
#include "../helper.h"

WRAP_CLASS(CSR){
public:
	WCSR(){};
	~WCSR(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	static NAN_METHOD(Save);
	static NAN_METHOD(GetEncodedHEX);

	WRAP_NEW_INSTANCE(CSR);
};

#endif //WCSR_H_INCLUDED
