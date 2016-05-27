#ifndef PKI_WREVOCATION_H_INCLUDED
#define PKI_WREVOCATION_H_INCLUDED

#include "../../wrapper/pki/revocation.h"

#include <nan.h>
#include "../utils/wrap.h"

WRAP_CLASS(Revocation) {
public:
	WRevocation(){};
	~WRevocation(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	static NAN_METHOD(GetCrlLocal);	
	static NAN_METHOD(GetCrlDistPoints);
	static NAN_METHOD(CheckCrlTime);
};

#endif
